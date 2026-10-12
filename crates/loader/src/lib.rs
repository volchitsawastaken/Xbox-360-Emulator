//! XEX executable loading. Validates, never claims boot from load.

use x360_common::{EmuError, Result};
use x360_memory::Memory;

pub const XEX2_MAGIC: u32 = 0x5845_5832; // "XEX2"

#[derive(Debug, Clone)]
pub struct XexHeader {
    pub magic: u32,
    pub module_flags: u32,
    pub header_size: u32,
    pub security_offset: u32,
    pub header_count: u32,
}

#[derive(Debug, Clone)]
pub struct XexInfo {
    pub entry_point: u32,
    pub base_address: u32,
    pub size: usize,
}

/// Parse XEX2 header directory. Returns entry point for the kernel.
pub fn parse_xex(image: &[u8]) -> Result<(XexHeader, XexInfo)> {
    if image.len() < 24 {
        return Err(EmuError::InvalidExecutable(
            "file too small for XEX2".into(),
        ));
    }
    let magic = u32::from_be_bytes([image[0], image[1], image[2], image[3]]);
    if magic != XEX2_MAGIC {
        return Err(EmuError::InvalidExecutable(format!(
            "bad magic {:08x}, expected XEX2",
            magic
        )));
    }
    let module_flags = u32::from_be_bytes([image[4], image[5], image[6], image[7]]);
    let header_size = u32::from_be_bytes([image[8], image[9], image[10], image[11]]);
    let _reserved = u32::from_be_bytes([image[12], image[13], image[14], image[15]]);
    let security_offset = u32::from_be_bytes([image[16], image[17], image[18], image[19]]);
    let header_count = u32::from_be_bytes([image[20], image[21], image[22], image[23]]);

    if header_count > 64 {
        return Err(EmuError::InvalidExecutable(format!(
            "header_count {} unreasonable",
            header_count
        )));
    }
    if (header_size as usize) > image.len() {
        return Err(EmuError::InvalidExecutable("header_size OOB".into()));
    }
    if (security_offset as usize) > image.len() {
        log::warn!("xex: security_offset OOB (tracked, retail needs validation)");
    }
    if module_flags == 0 {
        log::debug!("xex: module_flags zero (homebrew?)");
    }

    // Walk directory entries (key: u32, offset: u32, size: u32).
    let mut entry_point: Option<u32> = None;
    let mut base_address: u32 = 0x8200_0000;
    for i in 0..header_count {
        let off = 24 + (i as usize) * 12;
        if off + 12 > image.len() {
            return Err(EmuError::InvalidExecutable("directory truncated".into()));
        }
        let key = u32::from_be_bytes([image[off], image[off + 1], image[off + 2], image[off + 3]]);
        let val_off = u32::from_be_bytes([
            image[off + 4],
            image[off + 5],
            image[off + 6],
            image[off + 7],
        ]) as usize;
        let val_size = u32::from_be_bytes([
            image[off + 8],
            image[off + 9],
            image[off + 10],
            image[off + 11],
        ]) as usize;
        if val_off
            .checked_add(val_size)
            .map(|end| end > image.len())
            .unwrap_or(true)
        {
            return Err(EmuError::InvalidExecutable(format!(
                "dir key {:08x} OOB (off {} size {})",
                key, val_off, val_size
            )));
        }
        match key {
            0x0001_0000 => {
                // Entry point
                if val_off + 4 > image.len() {
                    return Err(EmuError::InvalidExecutable("entry point OOB".into()));
                }
                entry_point = Some(u32::from_be_bytes([
                    image[val_off],
                    image[val_off + 1],
                    image[val_off + 2],
                    image[val_off + 3],
                ]));
            }
            0x0000_0001 => {
                // Base reference (simplified)
                if val_off + 8 <= image.len() {
                    base_address = u32::from_be_bytes([
                        image[val_off + 4],
                        image[val_off + 5],
                        image[val_off + 6],
                        image[val_off + 7],
                    ]);
                }
            }
            _ => {
                log::debug!("xex: unhandled dir key {:08x} (tracked)", key);
            }
        }
    }

    let entry = entry_point
        .ok_or_else(|| EmuError::InvalidExecutable("no entry point directory entry".into()))?;

    if entry == 0 {
        return Err(EmuError::InvalidExecutable("entry point is zero".into()));
    }

    Ok((
        XexHeader {
            magic,
            module_flags,
            header_size,
            security_offset,
            header_count,
        },
        XexInfo {
            entry_point: entry,
            base_address,
            size: image.len(),
        },
    ))
}

/// Load raw code bytes at guest address. Used by tests and homebrew path.
pub fn load_bytes_to_guest(mem: &mut Memory, addr: u32, data: &[u8]) -> Result<()> {
    mem.write_bytes(addr, data)?;
    log::info!("loader: placed {} bytes at {:08x}", data.len(), addr);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_xex(entry: u32) -> Vec<u8> {
        let mut v = vec![0u8; 64];
        v[0..4].copy_from_slice(b"XEX2");
        v[8..12].copy_from_slice(&24u32.to_be_bytes());
        v[20..24].copy_from_slice(&1u32.to_be_bytes());
        // dir[0]: key=entry, off=48, size=4
        v[24..28].copy_from_slice(&0x0001_0000u32.to_be_bytes());
        v[28..32].copy_from_slice(&48u32.to_be_bytes());
        v[32..36].copy_from_slice(&4u32.to_be_bytes());
        v[48..52].copy_from_slice(&entry.to_be_bytes());
        v
    }

    #[test]
    fn parses_minimal() {
        let img = minimal_xex(0x8200_1000);
        let (_, info) = parse_xex(&img).unwrap();
        assert_eq!(info.entry_point, 0x8200_1000);
    }

    #[test]
    fn bad_magic_rejected() {
        let mut img = minimal_xex(0x8200_1000);
        img[0] = b'Y';
        assert!(parse_xex(&img).is_err());
    }

    #[test]
    fn missing_entry_rejected() {
        let mut v = vec![0u8; 32];
        v[0..4].copy_from_slice(b"XEX2");
        v[20..24].copy_from_slice(&0u32.to_be_bytes());
        assert!(parse_xex(&v).is_err());
    }
}
