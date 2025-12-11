use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("key name contains null byte")]
    KeyNameNullByte,
    #[error("failed to register key '{0}'")]
    KeyRegistration(String),
    #[error("too many keys (max 256)")]
    TooManyKeys,
    #[error("attribute value too long ({0} bytes, max 255)")]
    ValueTooLong(usize),
    #[error("failed to set attribute")]
    SetAttribute,
    #[error("process already initialized")]
    AlreadyInitialized,
}

pub type Result<T> = std::result::Result<T, Error>;