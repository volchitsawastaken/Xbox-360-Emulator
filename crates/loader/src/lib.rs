//! XEX executable loading. Validates, never claims boot from load.
//!
//! Header model cross-checked against the BSD-licensed Xenia project's
//! `xex2_info.h` (clean-room format research) plus public Free60 notes:
//! - magic `XEX2` (retail) or `XEX1` (early)
//! - fixed header, then `header_count` directory entries of 8 bytes:
//!   key:u32 BE, value-or-offset:u32 BE
//! - key low byte selects storage: `0x00`/`0x01` = value inline,
//!   anything else = value is an offset to sized data (first u32 = size
//!   for size-prefixed tables; fixed-size structs start directly)
//! - entry point key `0x00010100`, image base `0x00010201`,
//!   stack size `0x00020200`, execution info `0x00040006`
//! - optional security header at `security_offset` carries image size
//!   (+0x04), image flags (+0x10C), load address (+0x110),
//!   export table (+0x160), page descriptor count (+0x180),
//!   then page descriptors at +0x184 (each 0x18 bytes:
//!   value:u32 BE then 20-byte digest), per `xex2_security_info` and
//!   `xex2_page_descriptor` in the reference header; descriptor value
//!   low 4 bits are the section kind (1/2/3), high 28 bits page count
//! - TLS info key `0x00020104` is a fixed 0x10-byte struct
//!   (`xex2_opt_tls_info`: slot_count, raw_data_address, data_size,
//!   raw_data_size); static libraries key `0x000200FF` is size-prefixed
//!   (`xex2_opt_static_libraries`: size then 0x10-byte entries with
//!   8-byte names), count = (size-4)/0x10
//! - directory walk structure follows the `Load`/`ReadImage` flow in the
//!   reference `xex_module.cc` (lookup by key, offset from header base,
//!   per-key struct decode); import resolution is intentionally not
//!   performed here, static names are recorded only.

use x360_common::{EmuError, Result};
use x360_memory::Memory;

pub mod image;

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
pub const KEY_TLS_INFO: u32 = 0x0002_0104;
pub const KEY_STATIC_LIBRARIES: u32 = 0x0002_00FF;
// Documented size-prefixed structures (first word = total size).
pub const KEY_RESOURCE_INFO: u32 = 0x0000_02FF;
pub const KEY_FILE_FORMAT_INFO: u32 = 0x0000_03FF;
pub const KEY_BOUNDING_PATH: u32 = 0x0000_80FF;
pub const KEY_ORIGINAL_PE_NAME: u32 = 0x0001_83FF;
pub const KEY_MULTIDISC_MEDIA_IDS: u32 = 0x0004_06FF;
pub const KEY_ALTERNATE_TITLE_IDS: u32 = 0x0004_07FF;

/// Encryption types from the file-format-info structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XexEncryption {
    None,
    Normal,
    Unknown(u16),
}

/// Compression types from the file-format-info structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XexCompression {
    None,
    Basic,
    Normal,
    Delta,
    Unknown(u16),
}

pub const DEFAULT_BASE_ADDRESS: u32 = 0x8200_0000;

// Security header field offsets from `security_offset` (reference
// `xex2_security_info` layout facts).
const SEC_IMAGE_SIZE_OFF: usize = 0x04;
const SEC_IMAGE_FLAGS_OFF: usize = 0x10C;
const SEC_LOAD_ADDRESS_OFF: usize = 0x110;
const SEC_EXPORT_TABLE_OFF: usize = 0x160;
const SEC_PAGE_COUNT_OFF: usize = 0x180;
const SEC_FIXED_SIZE: usize = 0x184;
const SEC_AES_KEY_OFF: usize = 0x150;
const PAGE_DESCRIPTOR_SIZE: usize = 0x18;
const TLS_INFO_SIZE: usize = 0x10;
const STATIC_LIB_ENTRY_SIZE: usize = 0x10;
const EXECUTION_INFO_SIZE: usize = 0x18;

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

/// Section kind from a page descriptor value (low 4 bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionKind {
    Code,
    Data,
    ReadOnlyData,
}

/// One decoded page descriptor (digest bytes are validated in-bounds
/// but not retained).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageDescriptor {
    pub section_kind: SectionKind,
    pub page_count: u32,
}

/// Decoded TLS header (`xex2_opt_tls_info` layout facts).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsInfo {
    pub slot_count: u32,
    pub raw_data_address: u32,
    pub data_size: u32,
    pub raw_data_size: u32,
}

/// One recorded static library name (`xex2_opt_static_library`
/// layout facts: 8-byte name, versions/approval recorded nowhere;
/// import resolution is out of scope for the loader).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticLib {
    pub name: String,
}

/// One XEX resource descriptor (`xex2_resource` layout facts: 8-byte
/// name, BE address, BE size; count = (size - 4) / 16). The address
/// is served to the guest as-is (reference `UserModule::GetSection`
/// returns `res.address` directly); what backs it in guest memory is
/// load-time work, not loader work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XexResource {
    /// Raw 8-byte name (NUL-padded; compare trims trailing NULs).
    pub name: [u8; 8],
    pub address: u32,
    pub size: u32,
}

/// Parse the `RESOURCE_INFO` body at `data_off` (reference
/// `xex2_opt_resource_info` + `xex2_resource`). A non-multiple body
/// is an explicit error, never silently truncated.
pub(crate) fn parse_resources(image: &[u8], data_off: usize) -> Result<Vec<XexResource>> {
    if data_off + 4 > image.len() {
        return Err(EmuError::InvalidExecutable("resource info OOB".into()));
    }
    let size = read_u32(image, data_off)? as usize;
    if size < 4 || !(size - 4).is_multiple_of(16) {
        return Err(EmuError::InvalidExecutable(format!(
            "resource info bad size {}",
            size
        )));
    }
    if data_off + size > image.len() {
        return Err(EmuError::InvalidExecutable(format!(
            "resource info OOB (off {} size {})",
            data_off, size
        )));
    }
    let mut out = Vec::new();
    for i in 0..(size - 4) / 16 {
        let ent = data_off + 4 + i * 16;
        let mut name = [0u8; 8];
        name.copy_from_slice(&image[ent..ent + 8]);
        out.push(XexResource {
            name,
            address: read_u32(image, ent + 8)?,
            size: read_u32(image, ent + 12)?,
        });
    }
    Ok(out)
}

/// One import library from `IMPORT_LIBRARIES` (`xex2_import_library`
/// layout facts: size-prefixed entries after a padded string table;
/// each entry carries name index, id, versions, import count, then
/// `count` guest-virtual record addresses at +0x28. Record patching
/// itself is load-time work in `image::apply_imports`.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportLibrary {
    pub name: String,
    pub id: u32,
    pub version: u32,
    pub min_version: u32,
    pub import_count: u16,
    /// Guest-virtual record addresses (`import_table` in the reference).
    pub records: Vec<u32>,
}

#[derive(Debug, Clone)]
pub struct XexInfo {
    /// None for data-only modules (no executable entry). Booting one is
    /// an explicit error at load-to-execute time, not at parse time.
    pub entry_point: Option<u32>,
    pub base_address: u32,
    pub stack_size: Option<u32>,
    pub title_id: Option<u32>,
    pub is_dll: bool,
    pub size: usize,
    /// Validated directory table for later stages (relocations, imports).
    pub dirs: Vec<XexDir>,
    /// Security `image_size` (+0x04); `None` when the security header
    /// is absent or truncated. Added field, defaults to `None`.
    pub image_size: Option<u32>,
    /// Security `image_flags` (+0x10C); `None` when absent/truncated.
    /// Added field, defaults to `None`.
    pub image_flags: Option<u32>,
    /// Security `export_table` (+0x160); `None` when absent/truncated.
    /// Added field, defaults to `None`.
    pub export_table: Option<u32>,
    /// Security `page_descriptor_count` (+0x180); `None` when the
    /// security header is absent or truncated. Added field, defaults
    /// to `None`. A present-but-OOB count is an explicit error, never
    /// silently clamped.
    pub page_descriptor_count: Option<u32>,
    /// Decoded page descriptors; empty when the security header is
    /// absent or truncated. Added field, defaults to empty.
    pub page_descriptors: Vec<PageDescriptor>,
    /// Decoded TLS header when key `0x00020104` is present. Added
    /// field, defaults to `None`.
    pub tls_info: Option<TlsInfo>,
    /// Recorded static library names when key `0x000200FF` is present.
    /// Added field, defaults to empty. No import resolution performed.
    pub static_libs: Vec<StaticLib>,
    /// Import libraries when key `0x000103FF` is present. Names, ids,
    /// versions, and import counts only; record patching is load-time.
    pub import_libs: Vec<ImportLibrary>,
    /// File-format info when key `0x000003FF` is present: encryption and
    /// compression of the image body. Absent = unknown, never assumed.
    pub format_info: Option<FormatInfo>,
    /// Wrapped image AES key from security (+0x150), unwrapped with the
    /// public retail key for `enc=Normal` bodies. Absent when the
    /// security header is missing or truncated.
    pub aes_key: Option<[u8; 16]>,
    /// Resource descriptors when key `0x000002FF` is present. Served
    /// as-is by `XexGetModuleSection`; empty when absent.
    pub resources: Vec<XexResource>,
}

/// File-format info (`xex2_opt_file_format_info` layout facts:
/// size u32, encryption u16, compression u16).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormatInfo {
    pub encryption: XexEncryption,
    pub compression: XexCompression,
}

pub(crate) fn read_u32(image: &[u8], off: usize) -> Result<u32> {
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

struct SecurityParsed {
    image_size: Option<u32>,
    image_flags: Option<u32>,
    load_address: Option<u32>,
    export_table: Option<u32>,
    page_count: Option<u32>,
    pages: Vec<PageDescriptor>,
    aes_key: Option<[u8; 16]>,
}

fn empty_security() -> SecurityParsed {
    SecurityParsed {
        image_size: None,
        image_flags: None,
        load_address: None,
        export_table: None,
        page_count: None,
        pages: Vec::new(),
        aes_key: None,
    }
}

fn parse_security(image: &[u8], security_offset: u32) -> Result<SecurityParsed> {
    if security_offset == 0 {
        return Ok(empty_security());
    }
    let base = security_offset as usize;
    if base >= image.len() {
        log::warn!("xex: security_offset OOB (tracked)");
        return Ok(empty_security());
    }
    if base + SEC_FIXED_SIZE > image.len() {
        log::debug!("xex: security header truncated (tracked)");
        return Ok(empty_security());
    }
    let image_size = Some(read_u32(image, base + SEC_IMAGE_SIZE_OFF)?);
    let image_flags = Some(read_u32(image, base + SEC_IMAGE_FLAGS_OFF)?);
    let load_address = Some(read_u32(image, base + SEC_LOAD_ADDRESS_OFF)?);
    let export_table = Some(read_u32(image, base + SEC_EXPORT_TABLE_OFF)?);
    let page_count = read_u32(image, base + SEC_PAGE_COUNT_OFF)?;
    let array_off = base + SEC_FIXED_SIZE;
    let needed = (u64::from(page_count))
        .checked_mul(PAGE_DESCRIPTOR_SIZE as u64)
        .ok_or_else(|| EmuError::InvalidExecutable("page count overflow".into()))?;
    if (array_off as u64) + needed > image.len() as u64 {
        return Err(EmuError::InvalidExecutable(format!(
            "page descriptor array OOB (off {} count {} size {})",
            array_off, page_count, needed
        )));
    }
    let mut descs = Vec::new();
    for i in 0..page_count {
        let off = array_off + (i as usize) * PAGE_DESCRIPTOR_SIZE;
        let value = read_u32(image, off)?;
        let info = value & 0xF;
        let pages = value >> 4;
        let kind = match info {
            1 => SectionKind::Code,
            2 => SectionKind::Data,
            3 => SectionKind::ReadOnlyData,
            _ => {
                return Err(EmuError::InvalidExecutable(format!(
                    "unknown page descriptor kind {} at index {}",
                    info, i
                )));
            }
        };
        descs.push(PageDescriptor {
            section_kind: kind,
            page_count: pages,
        });
    }
    Ok(SecurityParsed {
        image_size,
        image_flags,
        load_address,
        export_table,
        page_count: Some(page_count),
        pages: descs,
        // Wrapped image key at +0x150 (16 bytes); absent when truncated.
        aes_key: if base + SEC_AES_KEY_OFF + 16 <= image.len() {
            let mut key = [0u8; 16];
            key.copy_from_slice(&image[base + SEC_AES_KEY_OFF..base + SEC_AES_KEY_OFF + 16]);
            Some(key)
        } else {
            None
        },
    })
}

fn parse_tls(image: &[u8], data_off: usize) -> Result<TlsInfo> {
    if data_off + TLS_INFO_SIZE > image.len() {
        return Err(EmuError::InvalidExecutable("tls info truncated".into()));
    }
    Ok(TlsInfo {
        slot_count: read_u32(image, data_off)?,
        raw_data_address: read_u32(image, data_off + 4)?,
        data_size: read_u32(image, data_off + 8)?,
        raw_data_size: read_u32(image, data_off + 12)?,
    })
}

/// File-format info needs 8 bytes: size u32, encryption u16,
/// compression u16. Unknown codes are recorded, never guessed.
fn parse_format_info(image: &[u8], data_off: usize) -> Result<(u32, FormatInfo)> {
    if data_off + 8 > image.len() {
        return Err(EmuError::InvalidExecutable(
            "file format info truncated".into(),
        ));
    }
    let size = read_u32(image, data_off)?;
    let raw = read_u32(image, data_off + 4)?;
    let encryption = match (raw >> 16) as u16 {
        0 => XexEncryption::None,
        1 => XexEncryption::Normal,
        other => XexEncryption::Unknown(other),
    };
    let compression = match (raw & 0xFFFF) as u16 {
        0 => XexCompression::None,
        1 => XexCompression::Basic,
        2 => XexCompression::Normal,
        3 => XexCompression::Delta,
        other => XexCompression::Unknown(other),
    };
    Ok((
        size,
        FormatInfo {
            encryption,
            compression,
        },
    ))
}

fn parse_static_libs(image: &[u8], data_off: usize) -> Result<(u32, Vec<StaticLib>)> {
    if data_off + 4 > image.len() {
        return Err(EmuError::InvalidExecutable(
            "static libraries truncated".into(),
        ));
    }
    let size = read_u32(image, data_off)?;
    if size < 4 {
        return Err(EmuError::InvalidExecutable(format!(
            "static libraries size {} too small",
            size
        )));
    }
    if (size - 4) % (STATIC_LIB_ENTRY_SIZE as u32) != 0 {
        return Err(EmuError::InvalidExecutable(format!(
            "static libraries size {} malformed",
            size
        )));
    }
    if (data_off as u64) + (u64::from(size)) > image.len() as u64 {
        return Err(EmuError::InvalidExecutable(format!(
            "static libraries data OOB (off {} size {})",
            data_off, size
        )));
    }
    let count = (size - 4) / (STATIC_LIB_ENTRY_SIZE as u32);
    let mut libs = Vec::new();
    for l in 0..count {
        let ent = data_off + 4 + (l as usize) * STATIC_LIB_ENTRY_SIZE;
        if ent + STATIC_LIB_ENTRY_SIZE > image.len() {
            return Err(EmuError::InvalidExecutable(format!(
                "static library {} truncated",
                l
            )));
        }
        let raw = &image[ent..ent + 8];
        let end = raw.iter().position(|&b| b == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&raw[..end]).into_owned();
        libs.push(StaticLib { name });
    }
    Ok((size, libs))
}

/// Parse the import-libraries table (`xex2_opt_import_libraries` layout
/// facts: outer size, string table (size, count, NUL strings padded to
/// 4), then size-prefixed library entries with name index, id,
/// versions, and import count). Record patching is load-time work and
/// explicitly out of scope here.
fn parse_import_libraries(image: &[u8], data_off: usize) -> Result<(u32, Vec<ImportLibrary>)> {
    if data_off + 12 > image.len() {
        return Err(EmuError::InvalidExecutable(
            "import libraries truncated".into(),
        ));
    }
    let size = read_u32(image, data_off)?;
    if size < 12 {
        return Err(EmuError::InvalidExecutable(format!(
            "import libraries size {} too small",
            size
        )));
    }
    if (data_off as u64) + (size as u64) > image.len() as u64 {
        return Err(EmuError::InvalidExecutable(format!(
            "import libraries data OOB (off {} size {})",
            data_off, size
        )));
    }
    let str_size = read_u32(image, data_off + 4)? as usize;
    let str_count = read_u32(image, data_off + 8)? as usize;
    if str_count > 64 {
        return Err(EmuError::InvalidExecutable(format!(
            "import string count {} unreasonable",
            str_count
        )));
    }
    if 12 + str_size > size as usize {
        return Err(EmuError::InvalidExecutable(
            "import string table overruns payload".into(),
        ));
    }
    // Collect NUL-terminated, 4-padded strings.
    let mut names = Vec::new();
    let mut pos = data_off + 12;
    let str_end = data_off + 12 + str_size;
    while names.len() < str_count {
        if pos >= str_end {
            return Err(EmuError::InvalidExecutable(
                "import string table truncated".into(),
            ));
        }
        let rel = &image[pos..str_end];
        let len = rel
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| EmuError::InvalidExecutable("import string unterminated".into()))?;
        names.push(String::from_utf8_lossy(&rel[..len]).into_owned());
        pos += len + 1;
        pos += (4 - (pos % 4)) % 4;
    }
    // Library entries follow the 12-byte table header + strings.
    let mut libs = Vec::new();
    let mut off = data_off + 12 + str_size;
    let end = data_off + size as usize;
    while off < end {
        if off + 4 > end {
            return Err(EmuError::InvalidExecutable(
                "import library entry truncated".into(),
            ));
        }
        let lib_size = read_u32(image, off)? as usize;
        if lib_size == 0 {
            break;
        }
        if lib_size < 0x28 || off + lib_size > end {
            return Err(EmuError::InvalidExecutable(format!(
                "import library size {} OOB",
                lib_size
            )));
        }
        let id = read_u32(image, off + 0x18)?;
        let version = read_u32(image, off + 0x1C)?;
        let min_version = read_u32(image, off + 0x20)?;
        let name_index = u16::from_be_bytes([image[off + 0x24], image[off + 0x25]]) as usize;
        let count = u16::from_be_bytes([image[off + 0x26], image[off + 0x27]]);
        if (name_index & 0xFF) >= names.len() {
            return Err(EmuError::InvalidExecutable(format!(
                "import name index {} OOB ({} strings)",
                name_index,
                names.len()
            )));
        }
        if count > 20000 {
            return Err(EmuError::InvalidExecutable(format!(
                "import count {} unreasonable",
                count
            )));
        }
        let need = 0x28usize
            .checked_add(count as usize * 4)
            .ok_or_else(|| EmuError::InvalidExecutable("import size overflow".into()))?;
        if lib_size < need || off + need > end {
            return Err(EmuError::InvalidExecutable(format!(
                "import library size {} too small for {} records",
                lib_size, count
            )));
        }
        let mut records = Vec::with_capacity(count as usize);
        for i in 0..count as usize {
            records.push(read_u32(image, off + 0x28 + i * 4)?);
        }
        libs.push(ImportLibrary {
            name: names[name_index & 0xFF].clone(),
            id,
            version,
            min_version,
            import_count: count,
            records,
        });
        off += lib_size;
    }
    Ok((size, libs))
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

    // Security header: image size/flags/export/page descriptors plus
    // load-address fallback. Absent or truncated headers yield Nones;
    // a present header with an OOB page count is an explicit error.
    let sec = parse_security(image, security_offset)?;

    let mut entry_point: Option<u32> = None;
    let mut image_base: Option<u32> = None;
    let mut original_base: Option<u32> = None;
    let mut stack_size: Option<u32> = None;
    let mut title_id: Option<u32> = None;
    let mut tls_info: Option<TlsInfo> = None;
    let mut format_info: Option<FormatInfo> = None;
    let mut static_libs: Vec<StaticLib> = Vec::new();
    let mut import_libs: Vec<ImportLibrary> = Vec::new();
    let mut resources: Vec<XexResource> = Vec::new();
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
                // Known fixed layouts first (retail structures).
                if key == KEY_EXECUTION_INFO {
                    // media_id +0x00, version +0x04, base_version +0x08,
                    // title_id +0x0C, platform/exec-table/disc +0x10..13.
                    if data_off + EXECUTION_INFO_SIZE > image.len() {
                        log::warn!("xex: execution info truncated (tracked)");
                        dirs.push(XexDir {
                            key,
                            data: XexDirData::AtOffset {
                                offset: value,
                                size: 0,
                            },
                        });
                    } else {
                        dirs.push(XexDir {
                            key,
                            data: XexDirData::AtOffset {
                                offset: value,
                                size: EXECUTION_INFO_SIZE as u32,
                            },
                        });
                        title_id = Some(read_u32(image, data_off + 0x0C)?);
                    }
                } else if key == KEY_TLS_INFO {
                    let info = parse_tls(image, data_off)?;
                    dirs.push(XexDir {
                        key,
                        data: XexDirData::AtOffset {
                            offset: value,
                            size: TLS_INFO_SIZE as u32,
                        },
                    });
                    tls_info = Some(info);
                } else if key == KEY_STATIC_LIBRARIES {
                    let (size, mut libs) = parse_static_libs(image, data_off)?;
                    dirs.push(XexDir {
                        key,
                        data: XexDirData::AtOffset {
                            offset: value,
                            size,
                        },
                    });
                    static_libs.append(&mut libs);
                } else if key == KEY_IMPORT_LIBRARIES {
                    let (size, mut libs) = parse_import_libraries(image, data_off)?;
                    dirs.push(XexDir {
                        key,
                        data: XexDirData::AtOffset {
                            offset: value,
                            size,
                        },
                    });
                    import_libs.append(&mut libs);
                } else if key == KEY_FILE_FORMAT_INFO {
                    let (size, info) = parse_format_info(image, data_off)?;
                    if (data_off as u64) + (size as u64) > image.len() as u64 {
                        return Err(EmuError::InvalidExecutable(format!(
                            "file format info OOB (off {} size {})",
                            data_off, size
                        )));
                    }
                    dirs.push(XexDir {
                        key,
                        data: XexDirData::AtOffset {
                            offset: value,
                            size,
                        },
                    });
                    format_info = Some(info);
                } else if key == KEY_RESOURCE_INFO {
                    let entries = parse_resources(image, data_off)?;
                    let size = read_u32(image, data_off)? as u32;
                    dirs.push(XexDir {
                        key,
                        data: XexDirData::AtOffset {
                            offset: value,
                            size,
                        },
                    });
                    resources = entries;
                } else {
                    // Only these keys are documented size-prefixed (first
                    // word = total size). Anything else (timestamps,
                    // version pairs, logo blobs) must not be misread as a
                    // size, so it is recorded with unverified length.
                    const SIZE_PREFIXED: [u32; 6] = [
                        KEY_BOUNDING_PATH,
                        KEY_ORIGINAL_PE_NAME,
                        KEY_IMPORT_LIBRARIES,
                        KEY_FILE_FORMAT_INFO,
                        KEY_MULTIDISC_MEDIA_IDS,
                        KEY_ALTERNATE_TITLE_IDS,
                    ];
                    if SIZE_PREFIXED.contains(&key) {
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
                    } else {
                        dirs.push(XexDir {
                            key,
                            data: XexDirData::AtOffset {
                                offset: value,
                                size: 0,
                            },
                        });
                    }
                    log::debug!("xex: offset key {:08x} (tracked)", key);
                }
            }
        }
    }

    if entry_point == Some(0) {
        return Err(EmuError::InvalidExecutable("entry point is zero".into()));
    }

    let base = image_base
        .or(original_base)
        .or(sec.load_address)
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
            entry_point,
            base_address: base,
            stack_size,
            title_id,
            is_dll: module_flags & 0x08 != 0,
            size: image.len(),
            dirs,
            image_size: sec.image_size,
            image_flags: sec.image_flags,
            export_table: sec.export_table,
            page_descriptor_count: sec.page_count,
            page_descriptors: sec.pages,
            tls_info,
            static_libs,
            format_info,
            import_libs,
            aes_key: sec.aes_key,
            resources,
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

    fn put_u32(v: &mut [u8], off: usize, val: u32) {
        v[off..off + 4].copy_from_slice(&val.to_be_bytes());
    }

    /// Image with a security header at 0x100 holding the given page
    /// descriptor values (already-encoded value words).
    fn security_image(page_values: &[u32]) -> Vec<u8> {
        let sec_base = 0x100usize;
        let total = sec_base + SEC_FIXED_SIZE + page_values.len() * PAGE_DESCRIPTOR_SIZE;
        let mut v = vec![0u8; total.max(0x200)];
        v[0..4].copy_from_slice(b"XEX2");
        put_u32(&mut v, 8, 32);
        put_u32(&mut v, 16, sec_base as u32);
        put_u32(&mut v, 20, 1);
        put_u32(&mut v, 24, KEY_ENTRY_POINT);
        put_u32(&mut v, 28, 0x8200_1000);
        put_u32(&mut v, sec_base + SEC_IMAGE_SIZE_OFF, 0x0012_0000);
        put_u32(&mut v, sec_base + SEC_IMAGE_FLAGS_OFF, 0x0000_0400);
        put_u32(&mut v, sec_base + SEC_LOAD_ADDRESS_OFF, 0x8200_0000);
        put_u32(&mut v, sec_base + SEC_EXPORT_TABLE_OFF, 0x0000_9000);
        put_u32(
            &mut v,
            sec_base + SEC_PAGE_COUNT_OFF,
            page_values.len() as u32,
        );
        for (i, w) in page_values.iter().enumerate() {
            put_u32(
                &mut v,
                sec_base + SEC_FIXED_SIZE + i * PAGE_DESCRIPTOR_SIZE,
                *w,
            );
        }
        v
    }

    /// Directory image with one entry-point plus one offset entry whose
    /// payload bytes are provided.
    fn dir_image_with_payload(key: u32, payload: &[u8]) -> Vec<u8> {
        let data_off = (24 + 16) as u32;
        let total = (data_off as usize) + payload.len();
        let mut v = vec![0u8; total];
        v[0..4].copy_from_slice(b"XEX2");
        put_u32(&mut v, 8, 24 + 16);
        put_u32(&mut v, 20, 2);
        put_u32(&mut v, 24, KEY_ENTRY_POINT);
        put_u32(&mut v, 28, 0x8200_1000);
        put_u32(&mut v, 32, key);
        put_u32(&mut v, 36, data_off);
        v[(data_off as usize)..].copy_from_slice(payload);
        v
    }

    #[test]
    fn parses_minimal() {
        let img = minimal_xex(0x8200_1000);
        let (_, info) = parse_xex(&img).unwrap();
        assert_eq!(info.entry_point, Some(0x8200_1000));
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

    fn put_u16(v: &mut [u8], off: usize, x: u16) {
        v[off..off + 2].copy_from_slice(&x.to_be_bytes());
    }

    /// Synthetic import table: 2 strings, 2 libraries (3 + 1 imports).
    /// Entry sizes follow the real layout: 0x28 + count * 4.
    fn import_payload() -> Vec<u8> {
        let mut strings = b"xboxkrnl.exe\0".to_vec();
        while !strings.len().is_multiple_of(4) {
            strings.push(0);
        }
        strings.extend_from_slice(b"xam.xex\0");
        let sizes = [0x28 + 3 * 4, 0x28 + 4];
        let mut p = vec![0u8; 12 + strings.len() + sizes[0] + sizes[1]];
        let total_len = p.len() as u32;
        put_u32(&mut p, 0, total_len);
        put_u32(&mut p, 4, strings.len() as u32);
        put_u32(&mut p, 8, 2);
        p[12..12 + strings.len()].copy_from_slice(&strings);
        let mut off = 12 + strings.len();
        for (n, (idx, count)) in [(0u16, 3u16), (1u16, 1u16)].iter().enumerate() {
            put_u32(&mut p, off, sizes[n] as u32);
            put_u32(&mut p, off + 0x18, 1); // id
            put_u32(&mut p, off + 0x1C, 2); // version
            put_u32(&mut p, off + 0x20, 1); // min version
            put_u16(&mut p, off + 0x24, *idx);
            put_u16(&mut p, off + 0x26, *count);
            for i in 0..*count as usize {
                put_u32(
                    &mut p,
                    off + 0x28 + i * 4,
                    0xDEAD_0000 + *idx as u32 * 0x100 + i as u32,
                );
            }
            off += sizes[n];
        }
        p
    }

    #[test]
    fn import_libraries_parsed() {
        let img = dir_image_with_payload(KEY_IMPORT_LIBRARIES, &import_payload());
        let (_, info) = parse_xex(&img).unwrap();
        assert_eq!(info.import_libs.len(), 2);
        assert_eq!(info.import_libs[0].name, "xboxkrnl.exe");
        assert_eq!(info.import_libs[0].import_count, 3);
        assert_eq!(info.import_libs[0].id, 1);
        assert_eq!(info.import_libs[0].records.len(), 3);
        assert_eq!(info.import_libs[0].records[0], 0xDEAD_0000);
        assert_eq!(info.import_libs[1].name, "xam.xex");
        assert_eq!(info.import_libs[1].import_count, 1);
        assert_eq!(info.import_libs[1].records, vec![0xDEAD_0100]);
    }

    #[test]
    fn import_short_table_rejected() {
        // Declares 3 records but sizes the entry for 1.
        let mut payload = import_payload();
        put_u32(&mut payload, 12 + 24, 0x28 + 4);
        let img = dir_image_with_payload(KEY_IMPORT_LIBRARIES, &payload);
        assert!(parse_xex(&img).is_err());
    }

    #[test]
    fn import_bad_name_index_rejected() {
        let mut payload = import_payload();
        put_u16(&mut payload, 12 + 16 + 8 + 0x24, 9); // first lib, bad index
        let img = dir_image_with_payload(KEY_IMPORT_LIBRARIES, &payload);
        assert!(parse_xex(&img).is_err());
    }

    #[test]
    fn import_truncated_rejected() {
        let img = dir_image_with_payload(KEY_IMPORT_LIBRARIES, &[0u8; 6]);
        assert!(parse_xex(&img).is_err());
    }

    /// Retail rank: import surface of every `.xex` in `$X360_FW_DIR`,
    /// smallest first. Skipped when unset. Firmware never enters git.
    #[test]
    fn retail_import_rank() {
        let dir = match std::env::var("X360_FW_DIR") {
            Ok(d) => d,
            Err(_) => return,
        };
        let mut names: Vec<_> = std::fs::read_dir(&dir)
            .expect("X360_FW_DIR unreadable")
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().map(|x| x == "xex").unwrap_or(false))
            .collect();
        names.sort();
        assert!(!names.is_empty(), "no .xex in $X360_FW_DIR");
        let mut rows: Vec<(String, usize, usize)> = Vec::new();
        for path in &names {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            let file = std::fs::read(path).expect("read xex");
            let (_, info) = parse_xex(&file).expect("retail header parses");
            let total: usize = info
                .import_libs
                .iter()
                .map(|l| l.import_count as usize)
                .sum();
            let detail: Vec<String> = info
                .import_libs
                .iter()
                .map(|l| format!("{}:{}", l.name, l.import_count))
                .collect();
            println!("{}: {} imports [{}]", name, total, detail.join(" "));
            rows.push((name, total, info.import_libs.len()));
        }
        rows.sort_by_key(|r| r.1);
        println!("--- smallest import surface first ---");
        for (name, total, libs) in &rows {
            println!("{}: {} imports in {} libs", name, total, libs);
        }
        assert!(!rows.is_empty());
    }

    #[test]
    fn missing_entry_parses_as_data_module() {
        let mut v = vec![0u8; 32];
        v[0..4].copy_from_slice(b"XEX2");
        v[20..24].copy_from_slice(&0u32.to_be_bytes());
        let (_, info) = parse_xex(&v).unwrap();
        assert_eq!(info.entry_point, None);
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

    #[test]
    fn format_info_encryption_kinds() {
        // size=8, encryption=1 (normal), compression=2 (normal).
        let payload = [0u8, 0, 0, 8, 0, 1, 0, 2];
        let img = dir_image_with_payload(KEY_FILE_FORMAT_INFO, &payload);
        let (_, info) = parse_xex(&img).unwrap();
        let fmt = info.format_info.expect("format info parsed");
        assert_eq!(fmt.encryption, XexEncryption::Normal);
        assert_eq!(fmt.compression, XexCompression::Normal);
    }

    #[test]
    fn format_info_truncated_rejected() {
        let img = dir_image_with_payload(KEY_FILE_FORMAT_INFO, &[0u8; 4]);
        assert!(parse_xex(&img).is_err());
    }

    /// Retail validation: parse every `.xex` in `$X360_FW_DIR`.
    /// Skipped when unset (CI, clean machines). Firmware never enters git.
    #[test]
    fn retail_headers_parse() {
        let dir = match std::env::var("X360_FW_DIR") {
            Ok(d) => d,
            Err(_) => return,
        };
        let mut names: Vec<_> = std::fs::read_dir(&dir)
            .expect("X360_FW_DIR unreadable")
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().map(|x| x == "xex").unwrap_or(false))
            .collect();
        names.sort();
        assert!(!names.is_empty(), "no .xex in $X360_FW_DIR");
        for path in &names {
            let bytes = std::fs::read(path).expect("read xex");
            match parse_xex(&bytes) {
                Ok((_, info)) => println!(
                    "{}: entry={} base={:08x} title={:?} stack={:?} dll={} enc={:?} comp={:?}",
                    path.file_name().unwrap().to_string_lossy(),
                    info.entry_point
                        .map(|e| format!("{:08x}", e))
                        .unwrap_or_else(|| "none(data)".into()),
                    info.base_address,
                    info.title_id.map(|t| format!("{:08x}", t)),
                    info.stack_size,
                    info.is_dll,
                    info.format_info.map(|f| format!("{:?}", f.encryption)),
                    info.format_info.map(|f| format!("{:?}", f.compression)),
                ),
                Err(e) => panic!(
                    "{}: rejected: {}",
                    path.file_name().unwrap().to_string_lossy(),
                    e
                ),
            }
        }
    }

    #[test]
    fn absent_security_yields_nones() {
        let img = minimal_xex(0x8200_1000);
        let (_, info) = parse_xex(&img).unwrap();
        assert_eq!(info.image_size, None);
        assert_eq!(info.image_flags, None);
        assert_eq!(info.export_table, None);
        assert_eq!(info.page_descriptor_count, None);
        assert!(info.page_descriptors.is_empty());
        assert_eq!(info.tls_info, None);
        assert!(info.static_libs.is_empty());
    }

    #[test]
    fn security_fields_and_pages() {
        let code = (2u32 << 4) | 1;
        let data = (4u32 << 4) | 2;
        let ro = (1u32 << 4) | 3;
        let img = security_image(&[code, data, ro]);
        let (_, info) = parse_xex(&img).unwrap();
        assert_eq!(info.image_size, Some(0x0012_0000));
        assert_eq!(info.image_flags, Some(0x0000_0400));
        assert_eq!(info.export_table, Some(0x0000_9000));
        assert_eq!(info.page_descriptor_count, Some(3));
        assert_eq!(info.page_descriptors.len(), 3);
        assert_eq!(info.page_descriptors[0].section_kind, SectionKind::Code);
        assert_eq!(info.page_descriptors[0].page_count, 2);
        assert_eq!(info.page_descriptors[1].section_kind, SectionKind::Data);
        assert_eq!(info.page_descriptors[1].page_count, 4);
        assert_eq!(
            info.page_descriptors[2].section_kind,
            SectionKind::ReadOnlyData
        );
        assert_eq!(info.page_descriptors[2].page_count, 1);
        assert_eq!(info.base_address, 0x8200_0000);
    }

    #[test]
    fn security_page_count_oob_rejected() {
        let mut img = security_image(&[(1u32 << 4) | 1]);
        let sec_base = 0x100usize;
        put_u32(&mut img, sec_base + SEC_PAGE_COUNT_OFF, 64);
        let err = parse_xex(&img).unwrap_err();
        assert!(matches!(err, EmuError::InvalidExecutable(_)));
    }

    #[test]
    fn page_descriptor_unknown_kind_rejected() {
        let bad = (1u32 << 4) | 7;
        let img = security_image(&[bad]);
        let err = parse_xex(&img).unwrap_err();
        assert!(matches!(err, EmuError::InvalidExecutable(_)));
    }

    #[test]
    fn page_descriptor_zero_kind_rejected() {
        let bad = 1u32 << 4;
        let img = security_image(&[bad]);
        assert!(parse_xex(&img).is_err());
    }

    #[test]
    fn tls_info_parsed() {
        let mut payload = vec![0u8; TLS_INFO_SIZE];
        put_u32(&mut payload, 0, 64);
        put_u32(&mut payload, 4, 0x8200_2000);
        put_u32(&mut payload, 8, 0x100);
        put_u32(&mut payload, 12, 0x80);
        let img = dir_image_with_payload(KEY_TLS_INFO, &payload);
        let (_, info) = parse_xex(&img).unwrap();
        let tls = info.tls_info.expect("tls present");
        assert_eq!(tls.slot_count, 64);
        assert_eq!(tls.raw_data_address, 0x8200_2000);
        assert_eq!(tls.data_size, 0x100);
        assert_eq!(tls.raw_data_size, 0x80);
    }

    #[test]
    fn tls_truncated_rejected() {
        let payload = vec![0u8; 8];
        let img = dir_image_with_payload(KEY_TLS_INFO, &payload);
        let err = parse_xex(&img).unwrap_err();
        assert!(matches!(err, EmuError::InvalidExecutable(_)));
    }

    #[test]
    fn static_libs_parsed() {
        let mut payload = vec![0u8; 4 + 2 * STATIC_LIB_ENTRY_SIZE];
        put_u32(&mut payload, 0, (4 + 2 * STATIC_LIB_ENTRY_SIZE) as u32);
        payload[4..7].copy_from_slice(b"xam");
        payload[4 + STATIC_LIB_ENTRY_SIZE..4 + STATIC_LIB_ENTRY_SIZE + 8]
            .copy_from_slice(b"xboxkrnl");
        let img = dir_image_with_payload(KEY_STATIC_LIBRARIES, &payload);
        let (_, info) = parse_xex(&img).unwrap();
        assert_eq!(info.static_libs.len(), 2);
        assert_eq!(info.static_libs[0].name, "xam");
        assert_eq!(info.static_libs[1].name, "xboxkrnl");
    }

    #[test]
    fn static_libs_malformed_size_rejected() {
        let mut payload = vec![0u8; 8];
        put_u32(&mut payload, 0, 5);
        let img = dir_image_with_payload(KEY_STATIC_LIBRARIES, &payload);
        assert!(parse_xex(&img).is_err());
    }

    #[test]
    fn static_libs_oob_rejected() {
        let mut payload = vec![0u8; 4];
        put_u32(&mut payload, 0, 0x100);
        let img = dir_image_with_payload(KEY_STATIC_LIBRARIES, &payload);
        let err = parse_xex(&img).unwrap_err();
        assert!(matches!(err, EmuError::InvalidExecutable(_)));
    }

    #[test]
    fn resources_parsed() {
        // size 20 = one 16-byte entry: name + BE address + BE size.
        let mut payload = vec![0u8; 20];
        put_u32(&mut payload, 0, 20);
        payload[4..12].copy_from_slice(b"SHADR\x00\x00\x00");
        put_u32(&mut payload, 12, 0x8200_4000);
        put_u32(&mut payload, 16, 0x1000);
        let img = dir_image_with_payload(KEY_RESOURCE_INFO, &payload);
        let (_, info) = parse_xex(&img).unwrap();
        assert_eq!(info.resources.len(), 1);
        assert_eq!(&info.resources[0].name, b"SHADR\x00\x00\x00");
        assert_eq!(info.resources[0].address, 0x8200_4000);
        assert_eq!(info.resources[0].size, 0x1000);
    }

    #[test]
    fn resources_malformed_size_rejected() {
        // 10 is not 4 + 16k.
        let mut payload = vec![0u8; 10];
        put_u32(&mut payload, 0, 10);
        let img = dir_image_with_payload(KEY_RESOURCE_INFO, &payload);
        assert!(parse_xex(&img).is_err());
    }

    #[test]
    fn resources_oob_rejected() {
        let mut payload = vec![0u8; 4];
        put_u32(&mut payload, 0, 0x100);
        let img = dir_image_with_payload(KEY_RESOURCE_INFO, &payload);
        let err = parse_xex(&img).unwrap_err();
        assert!(matches!(err, EmuError::InvalidExecutable(_)));
    }

    #[test]
    fn resources_empty_table_ok() {
        // size 4 = zero entries: valid, yields no resources.
        let mut payload = vec![0u8; 4];
        put_u32(&mut payload, 0, 4);
        let img = dir_image_with_payload(KEY_RESOURCE_INFO, &payload);
        let (_, info) = parse_xex(&img).unwrap();
        assert!(info.resources.is_empty());
    }

    #[test]
    fn resources_zero_size_rejected() {
        let mut payload = vec![0u8; 4];
        put_u32(&mut payload, 0, 0);
        let img = dir_image_with_payload(KEY_RESOURCE_INFO, &payload);
        assert!(parse_xex(&img).is_err());
    }

    #[test]
    fn resources_truncated_entry_rejected() {
        // Claims one entry (size 20) but only half the bytes are present.
        let mut payload = vec![0u8; 12];
        put_u32(&mut payload, 0, 20);
        payload[4..8].copy_from_slice(b"SHAD");
        let img = dir_image_with_payload(KEY_RESOURCE_INFO, &payload);
        assert!(parse_xex(&img).is_err());
    }

    #[test]
    fn resources_xex1_accepted() {
        let mut payload = vec![0u8; 20];
        put_u32(&mut payload, 0, 20);
        payload[4..12].copy_from_slice(b"SHADR\x00\x00\x00");
        put_u32(&mut payload, 12, 0x8200_4000);
        put_u32(&mut payload, 16, 0x1000);
        let mut img = dir_image_with_payload(KEY_RESOURCE_INFO, &payload);
        img[0..4].copy_from_slice(b"XEX1");
        let (_, info) = parse_xex(&img).unwrap();
        assert_eq!(info.resources.len(), 1);
        assert_eq!(info.resources[0].address, 0x8200_4000);
    }

    #[test]
    fn header_edges_rejected_or_tolerated() {
        // File too small for any XEX.
        assert!(parse_xex(&[0u8; 16]).is_err());
        // Absurd directory count.
        let mut img = minimal_xex(0x8200_1000);
        put_u32(&mut img, 20, 65);
        assert!(parse_xex(&img).is_err());
        // header_size past EOF.
        let mut img = minimal_xex(0x8200_1000);
        put_u32(&mut img, 8, 0x1000);
        assert!(parse_xex(&img).is_err());
        // Zero entry point is never a valid executable entry.
        assert!(parse_xex(&minimal_xex(0)).is_err());
        // Directory truncated mid-entry.
        let mut img = vec![0u8; 28];
        img[0..4].copy_from_slice(b"XEX2");
        put_u32(&mut img, 8, 32);
        put_u32(&mut img, 20, 2);
        put_u32(&mut img, 24, KEY_ENTRY_POINT);
        assert!(parse_xex(&img).is_err());
    }

    #[test]
    fn security_oob_and_truncated_tolerated() {
        // OOB offset: tracked, yields Nones rather than a hard error.
        let mut img = minimal_xex(0x8200_1000);
        put_u32(&mut img, 16, 0x5000);
        let (_, info) = parse_xex(&img).unwrap();
        assert_eq!(info.image_size, None);
        assert!(info.page_descriptors.is_empty());
        // Truncated header (nonzero but short of the fixed size): same.
        let mut img = vec![0u8; 0x110];
        img[0..4].copy_from_slice(b"XEX2");
        put_u32(&mut img, 8, 32);
        put_u32(&mut img, 16, 0x100);
        put_u32(&mut img, 20, 1);
        put_u32(&mut img, 24, KEY_ENTRY_POINT);
        put_u32(&mut img, 28, 0x8200_1000);
        let (_, info) = parse_xex(&img).unwrap();
        assert_eq!(info.image_size, None);
    }

    #[test]
    fn execution_info_truncated_tolerated() {
        // Payload shorter than 0x18 bytes: tracked with size 0, no title.
        let img = dir_image_with_payload(KEY_EXECUTION_INFO, &[0u8; 8]);
        let (_, info) = parse_xex(&img).unwrap();
        assert_eq!(info.title_id, None);
        assert!(info.dirs.iter().any(|d| d.key == KEY_EXECUTION_INFO));
    }

    #[test]
    fn static_libs_empty_table_ok() {
        let mut payload = vec![0u8; 4];
        put_u32(&mut payload, 0, 4);
        let img = dir_image_with_payload(KEY_STATIC_LIBRARIES, &payload);
        let (_, info) = parse_xex(&img).unwrap();
        assert!(info.static_libs.is_empty());
    }

    #[test]
    fn format_info_oob_rejected() {
        // Declared size runs past EOF.
        let mut payload = vec![0u8; 8];
        put_u32(&mut payload, 0, 0x100);
        put_u32(&mut payload, 4, 0x0001_0002);
        let img = dir_image_with_payload(KEY_FILE_FORMAT_INFO, &payload);
        assert!(parse_xex(&img).is_err());
    }
}
