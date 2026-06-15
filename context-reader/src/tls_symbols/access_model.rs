//! TLS access model classification.
//!
//! Determines *how* a TLS symbol is accessed by inspecting the relocations that
//! reference it. ELF defines several TLS access models:
//!
//! - **Static TLS** — the symbol lives in the main executable's own TLS block
//!   and resolves to a fixed offset from the thread pointer at link time. No
//!   dynamic TLS relocation is involved.
//! - **TLSDESC** (TLS Descriptor) — the GOT holds a `{resolver, arg}` pair.
//!   Modern, low-overhead, supports `dlopen`. Default on aarch64; opt-in on
//!   x86_64 via `-mtls-dialect=gnu2`.
//! - **General Dynamic (GD)** — runtime call to `__tls_get_addr(module, offset)`.
//!   Default on x86_64.
//! - **Local Dynamic (LD)** — like GD but for module-local symbols.
//! - **Initial Exec (IE)** — TP-relative offset stored in GOT. Cheap but
//!   unsuitable for `dlopen`'d libraries.
//! - **Local Exec (LE)** — TP-relative offset baked into code. Only valid in
//!   the main executable.
//!
//! Our spec only permits **TLSDESC** (for shared libraries) and **Static TLS**
//! (for main executables / statically-linked binaries). This module classifies
//! a given symbol's access model so callers can enforce that policy.
//!
//! The classifier is pure: it reads the ELF file on disk and does not touch
//! the target process.

use anyhow::{Context, Result};
use goblin::elf::Elf;
use std::fs;
use std::path::Path;
use tracing::debug;

// ---- Relocation type constants (subset relevant to TLS) ---------------------
//
// Names follow the psABI documents. We hard-code the numeric values because
// goblin exposes them as bare `u32` and not as named constants for every
// architecture's TLS relocs.

// x86_64
const R_X86_64_DTPMOD64: u32 = 16;
const R_X86_64_DTPOFF64: u32 = 17;
const R_X86_64_TPOFF64: u32 = 18;
const R_X86_64_TLSGD: u32 = 19;
const R_X86_64_TLSLD: u32 = 20;
const R_X86_64_DTPOFF32: u32 = 21;
const R_X86_64_GOTTPOFF: u32 = 22;
const R_X86_64_TPOFF32: u32 = 23;
const R_X86_64_TLSDESC: u32 = 36;
// R_X86_64_TLSDESC_CALL (35) is intentionally not matched: it's a code-site
// reloc that always travels alongside the real GOT-slot R_X86_64_TLSDESC
// reloc, so detecting it on its own would only yield a TlsDesc with no
// usable got_offset. Match the GOT-slot reloc and TLSDESC_CALL is implied.

// aarch64. Only the dynamic-relocation types are listed: code-site TLS
// relocations in the 512–559 range (TLSGD/TLSLD/TLSIE/TLSLE) are resolved
// at link time and never appear in `.rela.dyn` / `.rela.plt` of a finished
// shared library, so the classifier has no use for them.
const R_AARCH64_TLS_DTPMOD64: u32 = 1028;
const R_AARCH64_TLS_DTPREL64: u32 = 1029;
const R_AARCH64_TLS_TPREL64: u32 = 1030;
const R_AARCH64_TLSDESC: u32 = 1031;

// ELF machine types we care about
const EM_X86_64: u16 = 62;
const EM_AARCH64: u16 = 183;

// ---- Public types ----------------------------------------------------------

/// The TLS access model used for a particular symbol.
///
/// Determined by inspecting which relocation types reference the symbol.
/// Variants are ordered roughly by spec-compliance: the first two are the
/// only ones our spec permits.
#[derive(Debug, Clone)]
pub enum TlsAccessModel {
    /// Symbol is in the main executable's own TLS block — link-time
    /// resolved to a fixed TP-relative offset. No dynamic TLS reloc.
    ///
    /// Applies to both PIE and non-PIE executables and to fully statically
    /// linked binaries.
    StaticTls,

    /// TLSDESC access: GOT entry holds `{resolver, arg}` populated by the
    /// loader. `got_offset` is the file offset of the GOT entry; `addend`
    /// is the reloc's addend (usually the symbol's TLS-block offset).
    TlsDesc { got_offset: usize, addend: i64 },

    /// General Dynamic: runtime call to `__tls_get_addr(module, offset)`.
    /// Default on x86_64. **NOT** spec-compliant.
    GeneralDynamic { reloc_type: u32 },

    /// Local Dynamic. Module-local variant of GD. **NOT** spec-compliant.
    LocalDynamic { reloc_type: u32 },

    /// Initial Exec: TP-relative offset stored in GOT at load time.
    /// Unusable from `dlopen`'d libraries. **NOT** spec-compliant from a
    /// shared library.
    InitialExec { reloc_type: u32 },

    /// Local Exec: TP-relative offset baked into code. Only meaningful in
    /// the main executable. Appearing in a shared library indicates a
    /// corrupt build.
    LocalExec { reloc_type: u32 },

    /// No dynamic TLS relocation references this symbol, and the symbol is
    /// not in the main executable's own TLS block. Indicates a likely
    /// misconfiguration (declared but never used? wrong binary?).
    Unknown,
}

impl TlsAccessModel {
    /// True iff the spec permits this access model.
    pub fn is_compliant(&self) -> bool {
        matches!(self, Self::StaticTls | Self::TlsDesc { .. })
    }

    /// Short human-readable name suitable for diagnostics.
    pub fn name(&self) -> &'static str {
        match self {
            Self::StaticTls => "Static TLS",
            Self::TlsDesc { .. } => "TLSDESC",
            Self::GeneralDynamic { .. } => "General Dynamic (GD)",
            Self::LocalDynamic { .. } => "Local Dynamic (LD)",
            Self::InitialExec { .. } => "Initial Exec (IE)",
            Self::LocalExec { .. } => "Local Exec (LE)",
            Self::Unknown => "unknown / no TLS relocation",
        }
    }

    /// Suggested remediation for non-compliant models. Returned as a static
    /// string so callers can plug it into error messages.
    pub fn remediation_hint(&self) -> Option<&'static str> {
        match self {
            Self::StaticTls | Self::TlsDesc { .. } => None,
            Self::GeneralDynamic { .. } => Some(
                "rebuild the binary with `-mtls-dialect=gnu2` (gcc/clang) so the \
                 compiler emits TLSDESC instead of General Dynamic",
            ),
            Self::LocalDynamic { .. } => Some(
                "the symbol appears to use Local Dynamic access; ensure it is \
                 declared with default visibility and rebuild with \
                 `-mtls-dialect=gnu2`",
            ),
            Self::InitialExec { .. } => Some(
                "the symbol uses Initial Exec, which prevents the library from \
                 being `dlopen`'d; remove `-ftls-model=initial-exec` and rebuild \
                 with the default (or `-mtls-dialect=gnu2` for TLSDESC)",
            ),
            Self::LocalExec { .. } => Some(
                "Local Exec relocation in a shared library indicates a corrupt \
                 build; rebuild from clean sources",
            ),
            Self::Unknown => Some(
                "no TLS relocation references this symbol and it is not in the \
                 main executable's TLS; check that the symbol is actually used \
                 and that you are pointing at the correct binary",
            ),
        }
    }
}

// ---- Classifier ------------------------------------------------------------

/// Classify the TLS access model used for `symbol_name` in the ELF binary
/// at `path`.
///
/// `is_main_executable` controls the Static-TLS detection: if true and no
/// dynamic TLS relocation references the symbol, we treat it as Static TLS
/// (the symbol's TLS-relative offset is resolved at link time). For
/// statically-linked executables there are no dynamic relocations at all
/// and this is the only reasonable classification.
///
/// # Caller contract
///
/// `symbol_name` should refer to an `STT_TLS` symbol. The classifier itself
/// does not enforce this — it matches relocations by symbol-table index, not
/// by symbol type — so passing a non-TLS symbol may yield spurious results
/// if some TLS reloc happens to share the index. All in-tree callers filter
/// to `STT_TLS` before calling.
pub fn classify(
    path: &Path,
    symbol_name: &str,
    is_main_executable: bool,
) -> Result<TlsAccessModel> {
    let buffer = fs::read(path).context("Failed to read binary")?;
    let elf = Elf::parse(&buffer).context("Failed to parse ELF")?;
    classify_with_elf(&elf, symbol_name, is_main_executable, Some(path))
}

/// Like [`classify`], but operates on an already-parsed [`Elf`].
///
/// Useful when the caller is iterating many symbols in the same binary and
/// wants to avoid reading and parsing the file once per call. The `path`
/// argument is purely for debug-log decoration; pass `None` if unavailable.
pub fn classify_with_elf(
    elf: &Elf,
    symbol_name: &str,
    is_main_executable: bool,
    path: Option<&Path>,
) -> Result<TlsAccessModel> {
    // Find the symbol's index in .dynsym. If the symbol isn't in .dynsym at
    // all, no dynamic reloc can reference it by index — which means either
    // it's static-TLS in a main exe, or it isn't a usable export.
    let dynsym_index = elf.dynsyms.iter().position(|sym| {
        elf.dynstrtab
            .get_at(sym.st_name)
            .map(|n| n == symbol_name)
            .unwrap_or(false)
    });

    let machine = elf.header.e_machine;

    if let Some(idx) = dynsym_index {
        if let Some(mut model) = scan_relocations_for(elf, idx, machine) {
            // Local Exec and Initial Exec in the main executable both resolve
            // to a fixed TP-relative offset — LE at link time, IE at load time
            // — with no `__tls_get_addr` call and no DTV involvement. They are
            // simply the two on-disk encodings of "Static TLS in the main
            // executable" that the spec permits. Collapse both to StaticTls
            // here so callers only have to special-case one variant.
            //
            // In a shared library LE and IE remain non-compliant: LE in a .so
            // indicates a corrupt build, and IE prevents the library from
            // being `dlopen`'d.
            if is_main_executable
                && matches!(
                    model,
                    TlsAccessModel::LocalExec { .. } | TlsAccessModel::InitialExec { .. }
                )
            {
                debug!(
                    "Promoting {} to Static TLS for main executable {:?} (symbol {:?})",
                    model.name(),
                    path,
                    symbol_name
                );
                model = TlsAccessModel::StaticTls;
            }
            debug!(
                "Classified TLS access model for {:?} in {:?}: {}",
                symbol_name,
                path,
                model.name()
            );
            return Ok(model);
        }
    }

    // No dynamic TLS relocation references the symbol.
    //
    // For the main executable / statically-linked binaries, that's expected:
    // the symbol's offset is resolved at link time into a TP-relative
    // address (effectively Local Exec / Static TLS).
    //
    // For a shared library, it means the symbol is declared but unused —
    // which is suspicious. We classify as Unknown so the caller can decide
    // whether to bail or warn.
    if is_main_executable {
        debug!(
            "Classified TLS access model for {:?} in {:?}: Static TLS (main executable, no dynamic reloc)",
            symbol_name, path
        );
        Ok(TlsAccessModel::StaticTls)
    } else {
        debug!(
            "Classified TLS access model for {:?} in {:?}: Unknown (no TLS relocs reference it)",
            symbol_name, path
        );
        Ok(TlsAccessModel::Unknown)
    }
}

/// Scan all relocation tables and find the most-specific TLS access model
/// referencing the given symbol index.
///
/// Precedence (highest wins, per agreement: any TLSDESC reloc → accept):
/// 1. TLSDESC
/// 2. General Dynamic (DTPMOD + DTPOFF pair)
/// 3. Local Dynamic
/// 4. Initial Exec
/// 5. Local Exec
fn scan_relocations_for(elf: &Elf, sym_idx: usize, machine: u16) -> Option<TlsAccessModel> {
    // Collect candidate access models from each reloc that references the
    // symbol. We walk pltrelocs, dynrels, and shdr_relocs to cover every
    // reloc section the ELF might carry.

    let mut best: Option<TlsAccessModel> = None;

    let mut consider = |r_type: u32, r_offset: u64, r_addend: i64| {
        let candidate = match (machine, r_type) {
            // ----- TLSDESC (highest precedence) -----
            (EM_X86_64, R_X86_64_TLSDESC) | (EM_AARCH64, R_AARCH64_TLSDESC) => {
                Some(TlsAccessModel::TlsDesc {
                    got_offset: r_offset as usize,
                    addend: r_addend,
                })
            }

            // ----- General Dynamic -----
            (EM_X86_64, R_X86_64_DTPMOD64)
            | (EM_X86_64, R_X86_64_DTPOFF64)
            | (EM_X86_64, R_X86_64_TLSGD)
            | (EM_AARCH64, R_AARCH64_TLS_DTPMOD64)
            | (EM_AARCH64, R_AARCH64_TLS_DTPREL64) => {
                Some(TlsAccessModel::GeneralDynamic { reloc_type: r_type })
            }

            // ----- Local Dynamic -----
            (EM_X86_64, R_X86_64_TLSLD) | (EM_X86_64, R_X86_64_DTPOFF32) => {
                Some(TlsAccessModel::LocalDynamic { reloc_type: r_type })
            }

            // ----- Initial Exec -----
            (EM_X86_64, R_X86_64_GOTTPOFF) | (EM_AARCH64, R_AARCH64_TLS_TPREL64) => {
                Some(TlsAccessModel::InitialExec { reloc_type: r_type })
            }

            // ----- Local Exec -----
            (EM_X86_64, R_X86_64_TPOFF32) | (EM_X86_64, R_X86_64_TPOFF64) => {
                Some(TlsAccessModel::LocalExec { reloc_type: r_type })
            }

            _ => None,
        };

        if let Some(cand) = candidate {
            best = Some(merge_best(best.take(), cand));
        }
    };

    for r in elf.pltrelocs.iter() {
        if r.r_sym == sym_idx {
            consider(r.r_type, r.r_offset, r.r_addend.unwrap_or(0));
        }
    }
    for r in elf.dynrels.iter() {
        if r.r_sym == sym_idx {
            consider(r.r_type, r.r_offset, r.r_addend.unwrap_or(0));
        }
    }
    for (_, relocs) in elf.shdr_relocs.iter() {
        for r in relocs.iter() {
            if r.r_sym == sym_idx {
                consider(r.r_type, r.r_offset, r.r_addend.unwrap_or(0));
            }
        }
    }

    best
}

/// Merge two candidate classifications, keeping the most-specific one.
///
/// TLSDESC always wins; otherwise we keep the first non-trivial one. (We
/// don't try to rank GD vs IE etc. — any of them is non-compliant and the
/// caller just needs to know which.)
fn merge_best(existing: Option<TlsAccessModel>, candidate: TlsAccessModel) -> TlsAccessModel {
    use TlsAccessModel::*;
    match (&existing, &candidate) {
        (Some(TlsDesc { .. }), _) => existing.unwrap(),
        (_, TlsDesc { .. }) => candidate,
        (Some(_), _) => existing.unwrap(),
        (None, _) => candidate,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Smoke test the variant API.
    #[test]
    fn compliance_predicate() {
        assert!(TlsAccessModel::StaticTls.is_compliant());
        assert!(TlsAccessModel::TlsDesc {
            got_offset: 0x1000,
            addend: 0
        }
        .is_compliant());
        assert!(!TlsAccessModel::GeneralDynamic {
            reloc_type: R_X86_64_DTPMOD64
        }
        .is_compliant());
        assert!(!TlsAccessModel::InitialExec {
            reloc_type: R_X86_64_GOTTPOFF
        }
        .is_compliant());
        assert!(!TlsAccessModel::Unknown.is_compliant());
    }

    #[test]
    fn remediation_hints_present_for_noncompliant() {
        let noncompliant = [
            TlsAccessModel::GeneralDynamic { reloc_type: 0 },
            TlsAccessModel::LocalDynamic { reloc_type: 0 },
            TlsAccessModel::InitialExec { reloc_type: 0 },
            TlsAccessModel::LocalExec { reloc_type: 0 },
            TlsAccessModel::Unknown,
        ];
        for m in &noncompliant {
            assert!(
                m.remediation_hint().is_some(),
                "missing hint for {}",
                m.name()
            );
        }
        assert!(TlsAccessModel::StaticTls.remediation_hint().is_none());
    }
}
