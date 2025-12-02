use std::ffi::CString;
use std::ptr::NonNull;
use std::sync::OnceLock;

use super::{sys, Error, Result};

/// Global process-level RefData. Can only be set once.
static PROCESS_REF_DATA: OnceLock<RefData> = OnceLock::new();

/// A key handle returned when registering a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyHandle(pub(crate) u8);

impl KeyHandle {
    pub fn index(&self) -> u8 {
        self.0
    }
}

/// Builder for process-level configuration.
/// Collects key names and settings, then initializes the global state.
pub struct ProcessConfigBuilder {
    keys: Vec<String>,
    max_record_size: u64,
}

impl ProcessConfigBuilder {
    pub fn new(max_record_size: u64) -> Self {
        Self {
            keys: Vec::new(),
            max_record_size,
        }
    }

    pub fn register_key(&mut self, name: &str) -> Result<KeyHandle> {
        let index = self.keys.len();
        if self.keys.len() > 255 {
            return Err(Error::TooManyKeys);
        }
        self.keys.push(name.to_string());
        Ok(KeyHandle(index as u8))
    }

    /// Initialize the process-global configuration. Can only be called once.
    /// Consumes the builder and creates the C structures.
    pub fn init(self) -> Result<()> {
        // can't setup twice
        if PROCESS_REF_DATA.get().is_some() {
            return Err(Error::AlreadyInitialized);
        }

        // Calculate buffer size needed: sum of (1 + len) for each key
        let buffer_size: usize = self.keys.iter().map(|k| 1 + k.len()).sum();

        assert!(!self.keys.is_empty());

        // Build the C key table
        let key_table_ptr = unsafe { sys::custom_labels_v2_key_table_new(buffer_size) };
        if key_table_ptr.is_null() {
            panic!("failed to allocate key table");
        }

        let mut key_table_ptr = key_table_ptr;
        for name in &self.keys {
            let c_name = CString::new(name.as_str()).map_err(|_| Error::KeyNameNullByte)?;
            let result = unsafe {
                sys::custom_labels_v2_key_table_register(&mut key_table_ptr, c_name.as_ptr())
            };
            if result < 0 {
                unsafe { sys::custom_labels_v2_key_table_free(key_table_ptr) };
                return Err(Error::KeyRegistration(name.clone()));
            }
        }

        // Build the C ref_data
        let ref_data_ptr = unsafe {
            sys::custom_labels_v2_ref_data_new(key_table_ptr, self.max_record_size)
        };
        if ref_data_ptr.is_null() {
            unsafe { sys::custom_labels_v2_key_table_free(key_table_ptr) };
            panic!("failed to allocate ref data");
        }

        let ref_data = RefData {
            raw: NonNull::new(ref_data_ptr).unwrap(),
            _key_table: NonNull::new(key_table_ptr).unwrap(),
        };

        PROCESS_REF_DATA
            .set(ref_data)
            .map_err(|_| Error::AlreadyInitialized)
    }
}

/// Internal holder for the C structures.
struct RefData {
    raw: NonNull<sys::custom_labels_v2_ref_data_t>,
    _key_table: NonNull<sys::custom_labels_v2_key_table_t>,
}

unsafe impl Send for RefData {}
unsafe impl Sync for RefData {}

impl RefData {
    fn as_ptr(&self) -> *const sys::custom_labels_v2_ref_data_t {
        self.raw.as_ptr()
    }
}

impl Drop for RefData {
    fn drop(&mut self) {
        unsafe {
            sys::custom_labels_v2_ref_data_free(self.raw.as_ptr());
            sys::custom_labels_v2_key_table_free(self._key_table.as_ptr());
        }
    }
}

/// Get the raw pointer to the process-global RefData.
/// Used internally to set up thread TLs.
pub(crate) fn get_process_ref_data_ptr() -> *const sys::custom_labels_v2_ref_data_t {
    PROCESS_REF_DATA
        .get()
        .map(|r| r.as_ptr())
        .unwrap_or(std::ptr::null())
}
