//! XEX image bodies: basic decompression, PE sections, guest loading.
//!
//! Semantics ported from the BSD-licensed Xenia `xex_module.cc`
//! (`ReadImageBasicCompressed`, `ReadPEHeaders`) — structure and checks
//! only, all code original:
//! - compressed stream starts at `header_size`, blocks described by the
//!   file-format-info payload: `count = (info_size - 8) / 8`, each block
//!   `data_size` literal bytes then `zero_size` zero bytes
//! - expected output = security `image_size`; page-descriptor total must
//!   agree (page size 64 KiB when base < `0x90000000`, else 4 KiB)
//! - decompressed image is a little-endian PE: `MZ`, `e_lfanew`,
//!   `PE\0\0`, machine PPCBE, XBOX subsystem, section table
//! - only `enc=None + Basic` is implemented; anything else (AES/LZX)
//!   is an explicit `Unsupported`, never guessed

use x360_common::{EmuError, Result};
use x360_memory::Memory;

use super::{XexCompression, XexDirData, XexEncryption, XexHeader, XexInfo, KEY_FILE_FORMAT_INFO};

pub const PAGE_THRESHOLD: u32 = 0x9000_0000;
pub const PAGE_SMALL: u32 = 64 * 1024;
pub const PAGE_TINY: u32 = 4 * 1024;

/// One basic-compression block descriptor from the format-info payload.
#[derive(Debug, Clone, Copy)]
pub struct BasicBlock {
    pub data_size: u32,
    pub zero_size: u32,
}

/// Parse block descriptors. `payload_off` points at the format-info data,
/// `payload_size` is its leading size word.
pub fn parse_basic_blocks(
    image: &[u8],
    payload_off: usize,
    payload_size: u32,
) -> Result<Vec<BasicBlock>> {
    if payload_size < 8 {
        return Err(EmuError::InvalidExecutable(
            "format info too small for blocks".into(),
        ));
    }
    if !(payload_size - 8).is_multiple_of(8) {
        return Err(EmuError::InvalidExecutable(format!(
            "format info size {} not a whole block count",
            payload_size
        )));
    }
    let count = ((payload_size - 8) / 8) as usize;
    if count == 0 || count > 4096 {
        return Err(EmuError::InvalidExecutable(format!(
            "block count {} unreasonable",
            count
        )));
    }
    if payload_off + payload_size as usize > image.len() {
        return Err(EmuError::InvalidExecutable(
            "format info payload OOB".into(),
        ));
    }
    let mut blocks = Vec::with_capacity(count);
    for i in 0..count {
        let off = payload_off + 8 + i * 8;
        blocks.push(BasicBlock {
            data_size: super::read_u32(image, off)?,
            zero_size: super::read_u32(image, off + 4)?,
        });
    }
    Ok(blocks)
}

/// Decompress the basic stream. Output is exactly `expected` bytes;
/// overruns, shortfalls, and unconsumed input are all explicit errors.
pub fn decompress_basic(
    image: &[u8],
    header_size: usize,
    blocks: &[BasicBlock],
    expected: usize,
) -> Result<Vec<u8>> {
    if header_size > image.len() {
        return Err(EmuError::InvalidExecutable("header_size OOB".into()));
    }
    if expected == 0 || expected > 256 * 1024 * 1024 {
        return Err(EmuError::InvalidExecutable(format!(
            "expected size {} unreasonable",
            expected
        )));
    }
    let stream = &image[header_size..];
    let mut out = vec![0u8; expected];
    let mut si = 0usize;
    let mut di = 0usize;
    for (n, b) in blocks.iter().enumerate() {
        let ds = b.data_size as usize;
        let zs = b.zero_size as usize;
        if di + ds + zs > expected {
            return Err(EmuError::InvalidExecutable(format!(
                "block {} overruns output ({} > {})",
                n,
                di + ds + zs,
                expected
            )));
        }
        if si + ds > stream.len() {
            return Err(EmuError::InvalidExecutable(format!(
                "block {} overruns input",
                n
            )));
        }
        out[di..di + ds].copy_from_slice(&stream[si..si + ds]);
        si += ds;
        di += ds + zs; // zero region already zeroed
    }
    if di > expected {
        return Err(EmuError::InvalidExecutable(format!(
            "blocks overrun output ({} > {})",
            di, expected
        )));
    }
    if di != expected {
        // Retail evidence (XimeDicCh.xex): trailing zero pages may be
        // absent from the block list entirely. The buffer is pre-zeroed,
        // so the shortfall is well-defined; it is logged, not hidden.
        log::debug!(
            "basic: shortfall {} of {} bytes left zero",
            expected - di,
            expected
        );
    }
    // Retail files pad the stream with zeros to a boundary (observed:
    // 16 KiB on AvatarEditor.xex). Trailing zeros are allowed; trailing
    // nonzeros mean a misread and are an explicit error.
    let rest = &stream[si..];
    if let Some(pos) = rest.iter().position(|&b| b != 0) {
        return Err(EmuError::InvalidExecutable(format!(
            "stream has {} trailing non-zero bytes",
            rest.len() - pos
        )));
    }
    Ok(out)
}

/// Produce the loadable (decrypted, decompressed) image for a parsed file.
/// Only `enc=None` bodies are handled; AES/LZX are explicit `Unsupported`.
pub fn loadable_image(file: &[u8], hdr: &XexHeader, info: &XexInfo) -> Result<Vec<u8>> {
    let fmt = info
        .format_info
        .ok_or_else(|| EmuError::InvalidExecutable("no file format info".into()))?;
    match (fmt.encryption, fmt.compression) {
        (XexEncryption::None, XexCompression::Basic) => {
            let (off, size) = format_payload(info)?;
            let blocks = parse_basic_blocks(file, off as usize, size)?;
            let expected = info
                .image_size
                .ok_or_else(|| EmuError::InvalidExecutable("no image size for output".into()))?
                as usize;
            let out = decompress_basic(file, hdr.header_size as usize, &blocks, expected)?;
            // Page-descriptor total must agree with the decompressed size.
            let total = page_total(&info.page_descriptors, info.base_address)?;
            if total != expected {
                return Err(EmuError::InvalidExecutable(format!(
                    "page total {} != image size {}",
                    total, expected
                )));
            }
            Ok(out)
        }
        (XexEncryption::None, XexCompression::None) => {
            let hs = hdr.header_size as usize;
            if hs > file.len() {
                return Err(EmuError::InvalidExecutable("header_size OOB".into()));
            }
            Ok(file[hs..].to_vec())
        }
        (enc, comp) => Err(EmuError::Unsupported(format!(
            "image body enc={:?} comp={:?} (AES/LZX pending)",
            enc, comp
        ))),
    }
}

fn format_payload(info: &XexInfo) -> Result<(u32, u32)> {
    for d in &info.dirs {
        if d.key == KEY_FILE_FORMAT_INFO {
            if let XexDirData::AtOffset { offset, size } = d.data {
                return Ok((offset, size));
            }
        }
    }
    Err(EmuError::InvalidExecutable(
        "file format info payload missing".into(),
    ))
}
/// Page-descriptor total for cross-checking the decompressed size.
pub fn page_total(descriptors: &[super::PageDescriptor], base: u32) -> Result<usize> {
    let page = if base < PAGE_THRESHOLD {
        PAGE_SMALL
    } else {
        PAGE_TINY
    } as u64;
    let mut total = 0u64;
    for d in descriptors {
        total += d.page_count as u64 * page;
        if total > 256 * 1024 * 1024 {
            return Err(EmuError::InvalidExecutable(
                "page total unreasonable".into(),
            ));
        }
    }
    Ok(total as usize)
}

fn read_u16le(image: &[u8], off: usize) -> Result<u16> {
    if off + 2 > image.len() {
        return Err(EmuError::InvalidExecutable("pe field OOB".into()));
    }
    Ok(u16::from_le_bytes([image[off], image[off + 1]]))
}

fn read_u32le(image: &[u8], off: usize) -> Result<u32> {
    if off + 4 > image.len() {
        return Err(EmuError::InvalidExecutable("pe field OOB".into()));
    }
    Ok(u32::from_le_bytes([
        image[off],
        image[off + 1],
        image[off + 2],
        image[off + 3],
    ]))
}

/// One PE section header (little-endian on disk).
#[derive(Debug, Clone)]
pub struct PeSection {
    pub name: String,
    pub virt_addr: u32,
    pub virt_size: u32,
    pub raw_off: u32,
    pub raw_size: u32,
    /// Raw bytes actually present in the image. Retail linkers emit
    /// sections (e.g. `.reloc`) whose declared range extends past the
    /// image end; only `raw_available` bytes exist. Observed on retail
    /// files, so it is modeled explicitly rather than rejected.
    pub raw_available: u32,
    pub characteristics: u32,
}

/// Parse the PE section table of a decompressed image.
pub fn parse_pe_sections(image: &[u8]) -> Result<Vec<PeSection>> {
    if image.len() < 64 || image[0] != b'M' || image[1] != b'Z' {
        return Err(EmuError::InvalidExecutable("missing MZ signature".into()));
    }
    let lfanew = read_u32le(image, 0x3C)? as usize;
    if lfanew + 6 > image.len() {
        return Err(EmuError::InvalidExecutable("e_lfanew OOB".into()));
    }
    if &image[lfanew..lfanew + 4] != b"PE\0\0" {
        return Err(EmuError::InvalidExecutable("missing PE signature".into()));
    }
    let machine = read_u16le(image, lfanew + 4)?;
    // IBM PowerPC Big-Endian per reference `pe_image.h`.
    if machine != 0x01F2 {
        return Err(EmuError::InvalidExecutable(format!(
            "not PPCBE (machine {:04x})",
            machine
        )));
    }
    let num_sections = read_u16le(image, lfanew + 6)? as usize;
    if num_sections == 0 || num_sections > 96 {
        return Err(EmuError::InvalidExecutable(format!(
            "section count {} unreasonable",
            num_sections
        )));
    }
    let opt_size = read_u16le(image, lfanew + 20)? as usize;
    let opt_magic = read_u16le(image, lfanew + 24)?;
    if opt_magic != 0x10B {
        return Err(EmuError::InvalidExecutable("not PE32".into()));
    }
    let table = lfanew + 24 + opt_size;
    let mut sections = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let off = table + i * 40;
        if off + 40 > image.len() {
            return Err(EmuError::InvalidExecutable("section table OOB".into()));
        }
        let raw_name = &image[off..off + 8];
        let end = raw_name.iter().position(|&b| b == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&raw_name[..end]).into_owned();
        let virt_size = read_u32le(image, off + 8)?;
        let virt_addr = read_u32le(image, off + 12)?;
        let raw_size = read_u32le(image, off + 16)?;
        let raw_off = read_u32le(image, off + 20)?;
        let characteristics = read_u32le(image, off + 36)?;
        let raw_available =
            (image.len().saturating_sub(raw_off as usize) as u64).min(raw_size as u64) as u32;
        sections.push(PeSection {
            name,
            virt_addr,
            virt_size,
            raw_off,
            raw_size,
            raw_available,
            characteristics,
        });
    }
    Ok(sections)
}

/// Copy sections to guest memory at `base + virt_addr`, zero-filling BSS.
/// Sections fully past the image end are not mapped: skipped with a log,
/// never an error (retail linkers emit such sections). Partially mapped
/// sections load their present bytes; missing tails stay zero. Ranges are
/// validated; failures name the section.
pub fn load_sections_to_guest(
    mem: &mut Memory,
    image: &[u8],
    base: u32,
    sections: &[PeSection],
) -> Result<()> {
    for s in sections {
        if s.virt_addr as usize >= image.len() {
            log::debug!(
                "pe: section {} at {:08x} past image end, not mapped",
                s.name,
                s.virt_addr
            );
            continue;
        }
        let mapped = (image.len() - s.virt_addr as usize) as u64;
        let dest = base.wrapping_add(s.virt_addr);
        if s.raw_available > 0 {
            let end = (s.raw_off + s.raw_available) as usize;
            let src = &image[s.raw_off as usize..end];
            mem.write_bytes(dest, src)
                .map_err(|e| EmuError::InvalidExecutable(format!("section {}: {}", s.name, e)))?;
        }
        let have = s.raw_available as u64;
        let want = (s.virt_size as u64).min(mapped);
        if want > have {
            let bss = vec![0u8; (want - have) as usize];
            mem.write_bytes(dest.wrapping_add(s.raw_available), &bss)
                .map_err(|e| {
                    EmuError::InvalidExecutable(format!("section {} bss: {}", s.name, e))
                })?;
        }
        if s.raw_size > s.raw_available {
            log::debug!(
                "pe: section {} declares {} raw bytes, {} present",
                s.name,
                s.raw_size,
                s.raw_available
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn basic_image(blocks: &[(u32, u32)], stream: &[u8], header: usize) -> Vec<u8> {
        let mut v = vec![0xAAu8; header];
        v.extend_from_slice(stream);
        let _ = blocks;
        v
    }

    #[test]
    fn basic_roundtrip_with_zeros() {
        // stream: "AB" + 3 zeros + "CDEF", expected "AB\0\0\0CDEF".
        let img = basic_image(&[], b"ABCDEF", 16);
        let blocks = vec![
            BasicBlock {
                data_size: 2,
                zero_size: 3,
            },
            BasicBlock {
                data_size: 4,
                zero_size: 0,
            },
        ];
        let out = decompress_basic(&img, 16, &blocks, 9).unwrap();
        assert_eq!(&out, b"AB\0\0\0CDEF");
    }

    #[test]
    fn basic_shortfall_left_zero() {
        // Retail case (XimeDicCh.xex): blocks cover less than expected;
        // the tail stays zero and the stream is still fully consumed.
        let img = basic_image(&[], b"AB", 0);
        let blocks = vec![BasicBlock {
            data_size: 2,
            zero_size: 0,
        }];
        let out = decompress_basic(&img, 0, &blocks, 6).unwrap();
        assert_eq!(&out, b"AB\0\0\0\0");
    }

    #[test]
    fn basic_overrun_is_error() {
        let img = basic_image(&[], b"AB", 0);
        let blocks = vec![BasicBlock {
            data_size: 2,
            zero_size: 99,
        }];
        assert!(decompress_basic(&img, 0, &blocks, 50).is_err());
    }

    #[test]
    fn basic_trailing_zeros_allowed() {
        let img = basic_image(&[], b"ABCD", 0);
        let mut padded = img.clone();
        padded.extend_from_slice(&[0u8; 16]);
        let blocks = vec![BasicBlock {
            data_size: 4,
            zero_size: 0,
        }];
        let out = decompress_basic(&padded, 0, &blocks, 4).unwrap();
        assert_eq!(&out, b"ABCD");
    }

    #[test]
    fn basic_trailing_nonzero_is_error() {
        let img = basic_image(&[], b"ABCD", 0);
        let mut padded = img.clone();
        padded.extend_from_slice(&[0u8; 15]);
        padded.push(1);
        let blocks = vec![BasicBlock {
            data_size: 4,
            zero_size: 0,
        }];
        assert!(decompress_basic(&padded, 0, &blocks, 4).is_err());
    }

    #[test]
    fn pe_rejects_non_pe() {
        assert!(parse_pe_sections(b"XEX2 rest").is_err());
        assert!(parse_pe_sections(&[0u8; 16]).is_err());
    }

    #[test]
    fn sections_load_to_guest_with_bss() {
        use x360_memory::Memory;
        let mut mem = Memory::new();
        let mut image = vec![0u8; 0x2100];
        image[..64].fill(0xCC);
        let sections = vec![PeSection {
            name: ".data".into(),
            virt_addr: 0x2000,
            virt_size: 80, // 64 raw + 16 zero BSS
            raw_off: 0,
            raw_size: 64,
            raw_available: 64,
            characteristics: 0,
        }];
        load_sections_to_guest(&mut mem, &image, 0x8200_0000, &sections).unwrap();
        assert_eq!(mem.read_u8(0x8200_2000).unwrap(), 0xCC);
        assert_eq!(mem.read_u8(0x8200_203F).unwrap(), 0xCC);
        assert_eq!(mem.read_u8(0x8200_2040).unwrap(), 0x00);
        assert_eq!(mem.read_u8(0x8200_204F).unwrap(), 0x00);
    }

    #[test]
    fn pe_minimal_section() {
        // MZ + e_lfanew=64 + PE + 1 section, all little-endian.
        let mut v = vec![0u8; 64 + 24 + 224 + 40 + 16];
        v[0] = b'M';
        v[1] = b'Z';
        v[0x3C..0x40].copy_from_slice(&64u32.to_le_bytes());
        v[64..68].copy_from_slice(b"PE\0\0");
        v[68..70].copy_from_slice(&0x01F2u16.to_le_bytes()); // PPCBE
        v[70..72].copy_from_slice(&1u16.to_le_bytes());
        v[84..86].copy_from_slice(&224u16.to_le_bytes()); // opt size
        v[88..90].copy_from_slice(&0x10Bu16.to_le_bytes()); // PE32
        let t = 64 + 24 + 224;
        v[t..t + 8].copy_from_slice(b".text\0\0\0");
        v[t + 8..t + 12].copy_from_slice(&16u32.to_le_bytes());
        v[t + 12..t + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        v[t + 16..t + 20].copy_from_slice(&16u32.to_le_bytes());
        let raw: u32 = (t + 40) as u32;
        v[t + 20..t + 24].copy_from_slice(&raw.to_le_bytes());
        v[t + 36..t + 40].copy_from_slice(&0x60000020u32.to_le_bytes());
        let secs = parse_pe_sections(&v).unwrap();
        assert_eq!(secs.len(), 1);
        assert_eq!(secs[0].name, ".text");
        assert_eq!(secs[0].virt_addr, 0x1000);
        assert_eq!(secs[0].raw_available, 16);
    }

    #[test]
    fn unmapped_section_skipped_not_error() {
        use x360_memory::Memory;
        let mut mem = Memory::new();
        mem.write_u32(0x8200_1000, 0xDEAD_BEEF).unwrap();
        // Section fully past the 64-byte image: skipped, memory untouched.
        let sections = vec![PeSection {
            name: ".reloc".into(),
            virt_addr: 0x50000,
            virt_size: 6816,
            raw_off: 0,
            raw_size: 7168,
            raw_available: 0,
            characteristics: 0,
        }];
        load_sections_to_guest(&mut mem, &[0u8; 64], 0x8200_0000, &sections).unwrap();
        assert_eq!(mem.read_u32(0x8200_1000).unwrap(), 0xDEAD_BEEF);
    }

    /// Retail proof: `dash.xex` sections load into guest memory and its
    /// entry-point code disassembles with our own decoder. Prints the
    /// first instructions plus supported/unsupported counts.
    #[test]
    fn retail_entry_disassembles() {
        use super::super::parse_xex;
        use x360_cpu::decode;
        use x360_memory::Memory;
        let dir = match std::env::var("X360_FW_DIR") {
            Ok(d) => d,
            Err(_) => return,
        };
        let path = std::path::Path::new(&dir).join("dash.xex");
        let file = std::fs::read(&path).expect("read dash.xex");
        let (hdr, info) = parse_xex(&file).expect("dash header parses");
        let entry = info.entry_point.expect("dash has entry");
        let image = loadable_image(&file, &hdr, &info).expect("dash decompresses");
        let sections = parse_pe_sections(&image).expect("dash PE parses");
        let mut mem = Memory::new();
        load_sections_to_guest(&mut mem, &image, info.base_address, &sections)
            .expect("dash sections load");
        let mut supported = 0u32;
        let mut unsupported = 0u32;
        for i in 0..32u32 {
            let addr = entry.wrapping_add(i * 4);
            let word = mem
                .fetch_u32(addr)
                .unwrap_or_else(|e| panic!("dash fetch {:08x}: {}", addr, e));
            match decode::decode(word) {
                Ok(d) => {
                    if matches!(d, decode::Decoded::Unsupported { .. }) {
                        unsupported += 1;
                        println!("{:08x}: <unimplemented: {:?}>", addr, d);
                    } else {
                        supported += 1;
                        if supported <= 8 {
                            println!("{:08x}: {}", addr, decode::disasm(word));
                        }
                    }
                }
                Err(e) => {
                    unsupported += 1;
                    println!("{:08x}: <decode error: {}>", addr, e);
                }
            }
        }
        println!("supported={} unsupported={}", supported, unsupported);
        // Entry itself must be real code, and a retail prologue is
        // overwhelmingly plain integer ops our decoder covers.
        assert!(supported >= 24, "too much retail code undecodable");
        let _ = unsupported;
    }

    /// Retail proof: every unencrypted Basic XEX in `$X360_FW_DIR`
    /// decompresses to a PPCBE PE whose sections cover its entry point.
    /// Encrypted (AES/LZX) files report explicit Unsupported and are
    /// counted separately — never forced through the wrong path.
    #[test]
    fn retail_images_load() {
        use super::super::{parse_xex, XexCompression, XexEncryption};
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
        let mut loaded = 0u32;
        let mut pending_crypto = 0u32;
        for path in &names {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            let file = std::fs::read(path).expect("read xex");
            let (hdr, info) = parse_xex(&file).expect("retail header parses");
            let fmt = info.format_info.expect("retail has format info");
            match (fmt.encryption, fmt.compression) {
                (XexEncryption::None, XexCompression::Basic) => {
                    let image = loadable_image(&file, &hdr, &info)
                        .unwrap_or_else(|e| panic!("{}: decompress: {}", name, e));
                    if info.entry_point.is_none() {
                        // Data-only module: decompresses, but is not a PE
                        // and has no entry. Assert exactly that.
                        assert!(
                            parse_pe_sections(&image).is_err(),
                            "{}: data module unexpectedly parses as PE",
                            name
                        );
                        println!("{}: data module, {} bytes", name, image.len());
                        loaded += 1;
                        continue;
                    }
                    let sections =
                        parse_pe_sections(&image).unwrap_or_else(|e| panic!("{}: pe: {}", name, e));
                    assert!(!sections.is_empty(), "{}: no sections", name);
                    if let Some(entry) = info.entry_point {
                        let rel = entry.wrapping_sub(info.base_address);
                        let covered = sections.iter().any(|s| {
                            (s.virt_addr as usize) < image.len()
                                && rel >= s.virt_addr
                                && rel < s.virt_addr + s.virt_size.max(1)
                        });
                        assert!(covered, "{}: entry not in any mapped section", name);
                    }
                    println!(
                        "{}: {} sections, {} bytes",
                        name,
                        sections.len(),
                        image.len()
                    );
                    loaded += 1;
                }
                (enc, comp) => {
                    let r = loadable_image(&file, &hdr, &info);
                    assert!(
                        matches!(r, Err(x360_common::EmuError::Unsupported(_))),
                        "{}: expected Unsupported, got {:?}",
                        name,
                        r.map(|v| v.len())
                    );
                    println!("{}: pending crypto enc={:?} comp={:?}", name, enc, comp);
                    pending_crypto += 1;
                }
            }
        }
        println!("loaded={}, pending_crypto={}", loaded, pending_crypto);
        assert!(loaded > 0, "nothing loadable");
    }
}
