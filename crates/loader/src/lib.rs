//! XEX executable loading. Validates, never claims boot from load.
//!
//! Header model cross-checked against the BSD-licensed Xenia project's
//! `xex2_info.h` (clean-room format research) plus public Free60 notes:
//! - magic `XEX2` (retail) or `XEX1` (early)
//! - fixed header, then `header_count` directory entries of 8 bytes:
//!   key:u32 BE, value-or-offset:u32 BE
//! - key low byte selects storage: `0x00`/`0x01` = value inline,
//!   anything else = value is an offset to sized data (first u32 = size)
//! - entry point key `0x00010100`, image base `0x00010201`,
//!   stack size `0x00020200`, execution info `0x00040006`
//! - optional security header at `security_offset` carries image size
//!   (+0x04) and load address (+0x110)

use x360_common::{EmuError, Result};
use x360_memory::Memory;

pub const XEX2_MAGIC: u32 = 0x5845_5832; // "XEX2"
pub const XEX1_MAGIC: u32 = 0x5845_5831; // "XEX1"

// Directory keys (format facts, see module docs).
pub const KEY_ENTRY_POINT: u32 = 0x0001_0100;
pub const KEY_IMAGE_BASE_ADDRESS: u32 = 0x0001_0201;
pub const KEY_ORIGINAL_BASE_ADDRESS: u32 = 0x0001_0001;
pub const KEY_DEFAULT_STACK_SIZE: u32 = 0x0002_0200;
pub const KEY_EXECUTION_INFO: u32 = 0x0004_0006;
pub const KEY_IMPORT_LIBRARIES: u32 = 0x0001_03FF;
pub const KEY_SYSTEM_FLAGS: u32 = 0x0003_0000;

pub const DEFAULT_BASE_ADDRESS: u32 = 0x8200_0000;

#[derive(Debug, Clone)]
pub struct XexHeader {
    pub magic: u32,
    pub module_flags: u32,
    pub header_size: u32,
    pub security_offset: u32,
    pub header_count: u32,
}

/// One validated directory entry.
#[derive(Debug, Clone, Copy)]
pub struct XexDir {
    pub key: u32,
    pub data: XexDirData,
}

#[derive(Debug, Clone, Copy)]
pub enum XexDirData {
    /// Value stored inline in the entry (`key & 0xFF` is `0x00`/`0x01`).
    Inline(u32),
    /// Data at image offset with a leading size word.
    AtOffset { offset: u32, size: u32 },
}

#[derive(Debug, Clone)]
pub struct XexInfo {
    pub entry_point: u32,
    pub base_address: u32,
    pub stack_size: Option<u32>,
    pub title_id: Option<u32>,
    pub is_dll: bool,
    pub size: usize,
    /// Validated directory table for later stages (relocations, imports).
    pub dirs: Vec<XexDir>,
}

fn read_u32(image: &[u8], off: usize) -> Result<u32> {
    if off + 4 > image.len() {
        return Err(EmuError::InvalidExecutable("field OOB".into()));
    }
    Ok(u32::from_be_bytes([
        image[off],
        image[off + 1],
        image[off + 2],
        image[off + 3],
    ]))
}

/// Parse XEX1/XEX2 header directory. Returns entry point for the kernel.
pub fn parse_xex(image: &[u8]) -> Result<(XexHeader, XexInfo)> {
    if image.len() < 24 {
        return Err(EmuError::InvalidExecutable("file too small for XEX".into()));
    }
    let magic = read_u32(image, 0)?;
    if magic != XEX2_MAGIC && magic != XEX1_MAGIC {
        return Err(EmuError::InvalidExecutable(format!(
            "bad magic {:08x}, expected XEX2/XEX1",
            magic
        )));
    }
    let module_flags = read_u32(image, 4)?;
    let header_size = read_u32(image, 8)?;
    let security_offset = read_u32(image, 16)?;
    let header_count = read_u32(image, 20)?;

    if header_count > 64 {
        return Err(EmuError::InvalidExecutable(format!(
            "header_count {} unreasonable",
            header_count
        )));
    }
    if (header_size as usize) > image.len() {
        return Err(EmuError::InvalidExecutable("header_size OOB".into()));
    }

    // Optional security header: image size (+0x04), load address (+0x110).
    let mut sec_image_size: Option<u32> = None;
    let mut sec_load_address: Option<u32> = None;
    if security_offset != 0 {
        if (security_offset as usize) > image.len() {
            log::warn!("xex: security_offset OOB (tracked)");
        } else if (security_offset as usize) + 0x114 <= image.len() {
            sec_image_size = Some(read_u32(image, security_offset as usize + 4)?);
            sec_load_address = Some(read_u32(image, security_offset as usize + 0x110)?);
        } else {
            log::debug!("xex: security header truncated (tracked)");
        }
    }
    let _ = sec_image_size;

    let mut entry_point: Option<u32> = None;
    let mut image_base: Option<u32> = None;
    let mut original_base: Option<u32> = None;
    let mut stack_size: Option<u32> = None;
    let mut title_id: Option<u32> = None;
    let mut dirs = Vec::new();

    for i in 0..header_count {
        let off = 24 + (i as usize) * 8;
        if off + 8 > image.len() {
            return Err(EmuError::InvalidExecutable("directory truncated".into()));
        }
        let key = read_u32(image, off)?;
        let value = read_u32(image, off + 4)?;
        match key & 0xFF {
            0x00 | 0x01 => {
                dirs.push(XexDir {
                    key,
                    data: XexDirData::Inline(value),
                });
                match key {
                    KEY_ENTRY_POINT => entry_point = Some(value),
                    KEY_IMAGE_BASE_ADDRESS => image_base = Some(value),
                    KEY_ORIGINAL_BASE_ADDRESS => original_base = Some(value),
                    KEY_DEFAULT_STACK_SIZE => stack_size = Some(value),
                    _ => {
                        log::debug!("xex: inline key {:08x}={:08x} (tracked)", key, value);
                    }
                }
            }
            _ => {
                let data_off = value as usize;
                if data_off >= image.len() {
                    return Err(EmuError::InvalidExecutable(format!(
                        "dir key {:08x} offset OOB",
                        key
                    )));
                }
                let size = if data_off + 4 <= image.len() {
                    read_u32(image, data_off)?
                } else {
                    0
                };
                if (data_off as u64) + (size as u64) > image.len() as u64 {
                    return Err(EmuError::InvalidExecutable(format!(
                        "dir key {:08x} data OOB (off {} size {})",
                        key, data_off, size
                    )));
                }
                dirs.push(XexDir {
                    key,
                    data: XexDirData::AtOffset {
                        offset: value,
                        size,
                    },
                });
                // Known offset-keyed structures with fixed layouts.
                if key == KEY_EXECUTION_INFO {
                    // media_id +0x00, version +0x04, base_version +0x08,
                    // title_id +0x0C, platform/exec-table/disc +0x10..13.
                    if size >= 0x18 {
                        title_id = Some(read_u32(image, data_off + 0x0C)?);
                    } else {
                        log::warn!("xex: execution info truncated (tracked)");
                    }
                } else {
                    log::debug!("xex: offset key {:08x} (tracked)", key);
                }
            }
        }
    }

    let entry = entry_point
        .ok_or_else(|| EmuError::InvalidExecutable("no entry point directory entry".into()))?;
    if entry == 0 {
        return Err(EmuError::InvalidExecutable("entry point is zero".into()));
    }

    let base = image_base
        .or(original_base)
        .or(sec_load_address)
        .unwrap_or(DEFAULT_BASE_ADDRESS);

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
            base_address: base,
            stack_size,
            title_id,
            is_dll: module_flags & 0x08 != 0,
            size: image.len(),
            dirs,
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

    /// Minimal image using the real 8-byte entry model.
    fn minimal_xex(entry: u32) -> Vec<u8> {
        let mut v = vec![0u8; 32];
        v[0..4].copy_from_slice(b"XEX2");
        v[8..12].copy_from_slice(&32u32.to_be_bytes()); // header_size
        v[20..24].copy_from_slice(&1u32.to_be_bytes()); // count
        v[24..28].copy_from_slice(&KEY_ENTRY_POINT.to_be_bytes());
        v[28..32].copy_from_slice(&entry.to_be_bytes());
        v
    }

    #[test]
    fn parses_minimal() {
        let img = minimal_xex(0x8200_1000);
        let (_, info) = parse_xex(&img).unwrap();
        assert_eq!(info.entry_point, 0x8200_1000);
        assert_eq!(info.base_address, DEFAULT_BASE_ADDRESS);
        assert_eq!(info.dirs.len(), 1);
        assert_eq!(info.dirs[0].key, KEY_ENTRY_POINT);
        assert!(matches!(info.dirs[0].data, XexDirData::Inline(0x8200_1000)));
    }

    #[test]
    fn accepts_xex1() {
        let mut img = minimal_xex(0x8200_1000);
        img[0..4].copy_from_slice(b"XEX1");
        assert!(parse_xex(&img).is_ok());
    }

    #[test]
    fn stack_size_and_base_keys() {
        let mut v = vec![0u8; 24 + 8 * 3];
        v[0..4].copy_from_slice(b"XEX2");
        v[8..12].copy_from_slice(&(24 + 24u32).to_be_bytes());
        v[20..24].copy_from_slice(&3u32.to_be_bytes());
        v[24..28].copy_from_slice(&KEY_ENTRY_POINT.to_be_bytes());
        v[28..32].copy_from_slice(&0x8200_1000u32.to_be_bytes());
        v[32..36].copy_from_slice(&KEY_IMAGE_BASE_ADDRESS.to_be_bytes());
        v[36..40].copy_from_slice(&0x8200_0000u32.to_be_bytes());
        v[40..44].copy_from_slice(&KEY_DEFAULT_STACK_SIZE.to_be_bytes());
        v[44..48].copy_from_slice(&0x10000u32.to_be_bytes());
        let (_, info) = parse_xex(&v).unwrap();
        assert_eq!(info.base_address, 0x8200_0000);
        assert_eq!(info.stack_size, Some(0x10000));
    }

    #[test]
    fn execution_info_title_id() {
        // dir entry points at an 0x18-byte execution info struct.
        let data_off = 24 + 16u32;
        let total = (data_off + 0x18) as usize;
        let mut v = vec![0u8; total];
        v[0..4].copy_from_slice(b"XEX2");
        v[8..12].copy_from_slice(&(24 + 8u32).to_be_bytes());
        v[20..24].copy_from_slice(&2u32.to_be_bytes());
        v[24..28].copy_from_slice(&KEY_ENTRY_POINT.to_be_bytes());
        v[28..32].copy_from_slice(&0x8200_1000u32.to_be_bytes());
        v[32..36].copy_from_slice(&KEY_EXECUTION_INFO.to_be_bytes());
        v[36..40].copy_from_slice(&data_off.to_be_bytes());
        v[data_off as usize..data_off as usize + 4].copy_from_slice(&0x18u32.to_be_bytes());
        v[(data_off + 0x0C) as usize..(data_off + 0x10) as usize]
            .copy_from_slice(&0x1234_ABCDu32.to_be_bytes());
        let (_, info) = parse_xex(&v).unwrap();
        assert_eq!(info.title_id, Some(0x1234_ABCD));
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

    #[test]
    fn offset_oob_rejected() {
        let mut v = vec![0u8; 32];
        v[0..4].copy_from_slice(b"XEX2");
        v[20..24].copy_from_slice(&1u32.to_be_bytes());
        v[24..28].copy_from_slice(&KEY_IMPORT_LIBRARIES.to_be_bytes());
        v[28..32].copy_from_slice(&0xFFFFu32.to_be_bytes());
        assert!(parse_xex(&v).is_err());
    }
}
