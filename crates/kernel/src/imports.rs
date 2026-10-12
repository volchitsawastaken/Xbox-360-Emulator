//! Import-thunk resolution and kernel export dispatch.
//!
//! Record format facts ported from the BSD-licensed Xenia
//! `xex_module.cc` (`SetupLibraryImports`) plus `xex2_info.h`
//! (`xex2_import_library`: size, digest, id, versions, name index,
//! count, then `count` guest-virtual record addresses at +0x28):
//! - each record address points at a guest slot holding a record value:
//!   top byte = kind (0 = variable, 1 = thunk), low 16 = export ordinal
//! - variable slots are patched with the backing-store address
//! - thunk slots (16 bytes) are rewritten to `sc; blr; nop; nop`
//!   (reference words `0x44000042, 0x4E800020, 0x60000000 x2`);
//!   the boot runner traps the `sc` and dispatches here by
//!   `thunk_addr = pc_after_sc - 4`
//!
//! Ordinal/name facts come from `ordinals.rs` (diagnostics only).
//! Dispatch handlers below are original implementations against
//! `Memory`/`Kernel` state. Unimplemented imports are explicit
//! `Unsupported` errors with call counts, never fake success.

use std::collections::HashMap;
use x360_common::{EmuError, Result};
use x360_memory::Memory;

use super::ordinals;
use super::Kernel;

/// Thunk rewrite words (reference `SetupLibraryImports` thunk path).
pub const THUNK_SC: u32 = 0x4400_0042;
pub const THUNK_BLR: u32 = 0x4E80_0020;
pub const THUNK_NOP: u32 = 0x6000_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportKind {
    Variable,
    Function,
}

#[derive(Debug, Clone)]
pub struct ResolvedImport {
    pub lib: String,
    pub ordinal: u16,
    pub kind: ImportKind,
    pub thunk_addr: u32,
}

/// How an `apply` run went, for logs and tests.
#[derive(Debug, Clone, Default)]
pub struct ApplyStats {
    pub functions: usize,
    pub variables: usize,
}

/// Registered import thunks: `thunk_addr -> ResolvedImport`.
#[derive(Debug, Default)]
pub struct ImportTable {
    imports: HashMap<u32, ResolvedImport>,
    /// Per-(lib, ordinal) call counts for unimplemented-import reports.
    pub unimplemented_calls: HashMap<(String, u16), u64>,
    /// Per-(lib, ordinal) call counts for implemented imports (frequency).
    pub implemented_calls: HashMap<(String, u16), u64>,
}

impl ImportTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.imports.len()
    }

    pub fn is_empty(&self) -> bool {
        self.imports.is_empty()
    }

    pub fn get(&self, thunk_addr: u32) -> Option<&ResolvedImport> {
        self.imports.get(&thunk_addr)
    }

    /// Name for diagnostics (`None` when the ordinal is unknown).
    pub fn name_of(lib: &str, ordinal: u16) -> Option<&'static str> {
        ordinals::kernel_export_name(lib, ordinal)
    }
}

/// Walk every record address, decode its guest slot, and patch.
///
/// `libs` is `(library_name, record_addresses)`. Variables get a
/// zeroed 32-byte backing store from the kernel heap and the slot is
/// rewritten with its address. Functions are rewritten to the
/// `sc; blr; nop; nop` trap sequence and registered in `table`.
/// Unknown record kinds are explicit errors.
pub fn apply(
    mem: &mut Memory,
    kernel: &mut Kernel,
    table: &mut ImportTable,
    libs: &[(&str, &[u32])],
) -> Result<ApplyStats> {
    let mut stats = ApplyStats::default();
    for (lib, records) in libs {
        for &addr in *records {
            let slot = mem.read_u32(addr).map_err(|e| {
                EmuError::InvalidExecutable(format!("import slot {:08x}: {}", addr, e))
            })?;
            let kind_byte = (slot >> 24) as u8;
            let ordinal = (slot & 0xFFFF) as u16;
            match kind_byte {
                0 => {
                    // Variable: real backing store, slot points at it.
                    let backing = kernel.alloc_mem(32, 4)?;
                    mem.write_bytes(backing, &[0u8; 32])?;
                    mem.write_u32(addr, backing)?;
                    table.imports.insert(
                        addr,
                        ResolvedImport {
                            lib: (*lib).to_string(),
                            ordinal,
                            kind: ImportKind::Variable,
                            thunk_addr: addr,
                        },
                    );
                    stats.variables += 1;
                }
                1 => {
                    // Thunk: 16-byte trap rewrite.
                    mem.write_u32(addr, THUNK_SC)?;
                    mem.write_u32(addr.wrapping_add(4), THUNK_BLR)?;
                    mem.write_u32(addr.wrapping_add(8), THUNK_NOP)?;
                    mem.write_u32(addr.wrapping_add(12), THUNK_NOP)?;
                    table.imports.insert(
                        addr,
                        ResolvedImport {
                            lib: (*lib).to_string(),
                            ordinal,
                            kind: ImportKind::Function,
                            thunk_addr: addr,
                        },
                    );
                    stats.functions += 1;
                }
                other => {
                    return Err(EmuError::InvalidExecutable(format!(
                        "import slot {:08x} in {} has unknown kind {} (slot {:08x})",
                        addr, lib, other, slot
                    )));
                }
            }
        }
    }
    log::info!(
        "imports: resolved {} functions + {} variables",
        stats.functions,
        stats.variables
    );
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Kernel;

    fn slot_value(kind: u8, ordinal: u16) -> u32 {
        ((kind as u32) << 24) | (ordinal as u32)
    }

    #[test]
    fn thunk_rewrite_traps_and_registers() {
        let mut mem = Memory::new();
        let mut kernel = Kernel::new();
        let mut table = ImportTable::new();
        let t0 = 0x8200_1000;
        mem.write_u32(t0, slot_value(1, 0x12E)).unwrap();
        mem.write_u32(t0 + 4, 0x1111_1111).unwrap();
        mem.write_u32(t0 + 8, 0x2222_2222).unwrap();
        mem.write_u32(t0 + 12, 0x3333_3333).unwrap();
        let stats = apply(
            &mut mem,
            &mut kernel,
            &mut table,
            &[("xboxkrnl.exe", &[t0])],
        )
        .unwrap();
        assert_eq!(stats.functions, 1);
        assert_eq!(mem.read_u32(t0).unwrap(), THUNK_SC);
        assert_eq!(mem.read_u32(t0 + 4).unwrap(), THUNK_BLR);
        let r = table.get(t0).unwrap();
        assert_eq!(r.ordinal, 0x12E);
        assert_eq!(
            ImportTable::name_of("xboxkrnl.exe", 0x12E),
            Some("RtlInitializeCriticalSection")
        );
    }

    #[test]
    fn variable_gets_backing_store() {
        let mut mem = Memory::new();
        let mut kernel = Kernel::new();
        let mut table = ImportTable::new();
        let v0 = 0x8200_2000;
        mem.write_u32(v0, slot_value(0, 0x156)).unwrap();
        apply(
            &mut mem,
            &mut kernel,
            &mut table,
            &[("xboxkrnl.exe", &[v0])],
        )
        .unwrap();
        let backing = mem.read_u32(v0).unwrap();
        assert_ne!(backing, 0);
        assert_eq!(mem.read_bytes(backing, 4).unwrap(), &[0, 0, 0, 0]);
    }

    #[test]
    fn bad_kind_rejected() {
        let mut mem = Memory::new();
        let mut kernel = Kernel::new();
        let mut table = ImportTable::new();
        let t0 = 0x8200_3000;
        mem.write_u32(t0, slot_value(7, 1)).unwrap();
        assert!(apply(
            &mut mem,
            &mut kernel,
            &mut table,
            &[("xboxkrnl.exe", &[t0])]
        )
        .is_err());
    }

    #[test]
    fn ordinal_names_known() {
        assert_eq!(
            ImportTable::name_of("xboxkrnl.exe", 0xCC),
            Some("NtAllocateVirtualMemory")
        );
        assert_eq!(
            ImportTable::name_of("xam.xex", 0x282),
            Some("XamGetSystemVersion")
        );
        assert_eq!(ImportTable::name_of("xboxkrnl.exe", 0xFFFF), None);
    }
}
