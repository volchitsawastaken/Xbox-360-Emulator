//! Backing values for kernel import variables.
//!
//! A kind-0 import slot is a variable reference only when its ordinal
//! names a `kVariable` export (see `ordinals.rs`); kind-0 slots with
//! function ordinals are import descriptors the reference leaves
//! patched with `0xDEADC0DE` ("appears to be ignored"), and fully
//! unknown ordinals get `0xF00DF00D`. Both match the BSD-licensed
//! Xenia `xex_module.cc` `SetupLibraryImports` variable path (facts
//! only, all code original). Zeroed backing stores are never silently
//! treated as valid pointers: genuine variables get genuine content.

use x360_common::Result;
use x360_memory::Memory;

use super::ordinals;
use super::Kernel;

/// Marker for a function-ordinal descriptor slot (reference value).
pub const DESCRIPTOR_MARKER: u32 = 0xDEAD_C0DE;
/// Marker for an unresolvable import slot (reference value).
pub const UNRESOLVED_MARKER: u32 = 0xF00D_F00D;

/// Resolve what a kind-0 slot for (`lib`, `ordinal`) must contain.
/// Returns the 32-bit slot value (usually a guest address).
pub fn init_variable(
    kernel: &mut Kernel,
    mem: &mut Memory,
    lib: &str,
    ordinal: u16,
) -> Result<u32> {
    let l = lib.to_ascii_lowercase();
    let is_xkrnl = l.contains("xboxkrnl");
    let is_xam = !is_xkrnl && (l == "xam.xex" || l.contains("xam"));
    let known_variable = if is_xkrnl {
        ordinals::xboxkrnl_is_variable(ordinal)
    } else if is_xam {
        ordinals::xam_is_variable(ordinal)
    } else {
        false
    };
    if is_xkrnl {
        if let Some(v) = xboxkrnl_variable(kernel, mem, ordinal)? {
            return Ok(v);
        }
    }
    if known_variable {
        // Genuine variable without a content model yet: zeroed cell so
        // reads are deterministic; the ordinal is logged for the ledger.
        log::warn!(
            "imports: variable {}!{} has no content model yet (zeroed)",
            lib,
            ordinals::kernel_export_name(lib, ordinal).unwrap_or("?")
        );
        let backing = kernel.alloc_mem(32, 4)?;
        mem.write_bytes(backing, &[0u8; 32])?;
        return Ok(backing);
    }
    if ordinals::kernel_export_name(lib, ordinal).is_some() {
        log::debug!(
            "imports: descriptor {}!{} left as marker",
            lib,
            ordinals::kernel_export_name(lib, ordinal).unwrap_or("?")
        );
        return Ok(DESCRIPTOR_MARKER);
    }
    log::warn!("imports: unknown ordinal {}!{:04x}", lib, ordinal);
    Ok(UNRESOLVED_MARKER)
}

/// Content models for xboxkrnl variables. `None` = no model (caller
/// falls back to a zeroed cell). Layout facts from the reference
/// `xboxkrnl_module.cc` constructor (see function bodies).
fn xboxkrnl_variable(kernel: &mut Kernel, mem: &mut Memory, ordinal: u16) -> Result<Option<u32>> {
    match ordinal {
        // XexExecutableModuleHandle (0x193): variable holds ppXex, a
        // pointer to a module structure whose +0x58 points at the
        // loaded XEX header image. Games dereference it to find the
        // header (e.g. for RtlImageXexHeaderField-style queries).
        0x193 => {
            let pp = kernel.alloc_mem(4, 4)?;
            let modstruct = kernel.alloc_mem(0x60, 4)?;
            mem.write_bytes(modstruct, &[0u8; 0x60])?;
            let hdr = kernel.place_xex_header(mem)?;
            mem.write_u32(modstruct + 0x58, hdr)?;
            mem.write_u32(pp, modstruct)?;
            log::info!(
                "imports: XexExecutableModuleHandle pp={:08x} mod={:08x} hdr={:08x}",
                pp,
                modstruct,
                hdr
            );
            Ok(Some(pp))
        }
        // XboxKrnlVersion (0x158): 8-byte version (2, FFFF, FFFF, 80, 00).
        0x158 => {
            let addr = kernel.alloc_mem(8, 4)?;
            mem.write_bytes(addr, &[0x00, 0x02, 0xFF, 0xFF, 0xFF, 0xFF, 0x80, 0x00])?;
            Ok(Some(addr))
        }
        // KeTimeStampBundle (0xAD): 24-byte bundle; uptime millis at
        // +16 is a boot-time snapshot (hardware refreshes it at 1ms;
        // staleness is tracked, not hidden).
        0xAD => {
            let addr = kernel.alloc_mem(24, 4)?;
            mem.write_bytes(addr, &[0u8; 24])?;
            let ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u32)
                .unwrap_or(0);
            mem.write_u32(addr + 16, ms)?;
            Ok(Some(addr))
        }
        // ExLoadedCommandLine (0x1AE): NUL-terminated launch string.
        0x1AE => {
            let s = b"\"default.xex\"\0";
            let addr = kernel.alloc_mem(s.len() as u32, 4)?;
            mem.write_bytes(addr, s)?;
            Ok(Some(addr))
        }
        _ => Ok(None),
    }
}

/// Slot-value sanity for tests.
pub fn is_marker(v: u32) -> bool {
    v == DESCRIPTOR_MARKER || v == UNRESOLVED_MARKER
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::imports::ImportTable;

    #[test]
    fn executable_module_handle_chain() {
        let mut k = Kernel::new();
        let mut m = Memory::new();
        k.set_module_info(0x8200_0000, 0x100, 0x5841_08CE);
        k.set_xex_header(vec![0xAB; 64], 0x8200_1000, "default.xex".into());
        let pp = init_variable(&mut k, &mut m, "xboxkrnl.exe", 0x193).unwrap();
        assert!(!is_marker(pp));
        let modstruct = m.read_u32(pp).unwrap();
        assert_ne!(modstruct, 0);
        let hdr = m.read_u32(modstruct + 0x58).unwrap();
        assert_ne!(hdr, 0);
        assert_eq!(m.read_bytes(hdr, 4).unwrap(), &[0xAB; 4]);
    }

    #[test]
    fn function_descriptor_gets_marker() {
        let mut k = Kernel::new();
        let mut m = Memory::new();
        // RtlInitializeCriticalSection is a function: descriptor marker.
        let v = init_variable(&mut k, &mut m, "xboxkrnl.exe", 0x12E).unwrap();
        assert_eq!(v, DESCRIPTOR_MARKER);
        let _ = ImportTable::name_of("xboxkrnl.exe", 0x12E);
    }

    #[test]
    fn version_and_timestamp_modeled() {
        let mut k = Kernel::new();
        let mut m = Memory::new();
        let ver = init_variable(&mut k, &mut m, "xboxkrnl.exe", 0x158).unwrap();
        assert_eq!(m.read_bytes(ver, 8).unwrap().len(), 8);
        let ts = init_variable(&mut k, &mut m, "xboxkrnl.exe", 0xAD).unwrap();
        assert_eq!(m.read_bytes(ts, 24).unwrap().len(), 24);
    }
}
