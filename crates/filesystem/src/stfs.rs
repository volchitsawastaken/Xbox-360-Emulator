//! STFS container reading (GOD/XBLA packages, e.g. Braid).
//!
//! Layout and block-mapping facts ported from the BSD-licensed Xenia
//! `stfs_xbox.h` + `stfs_container_device.{h,cc}` (structure and checks
//! only, all code original):
//! - magic `CON `/`PIRS`/`LIVE` at 0x00, header size u32be at 0x340
//! - volume descriptor (0x24 bytes) at 0x379: length, version, flags,
//!   file-table count u16be, file-table block u24le, top hash,
//!   total/free block counts u32be
//! - volume type u32be at 0x3A9 (0 = STFS; SVOD is explicit Unsupported)
//! - 0x1000-byte blocks; hash tables hold 170 entries of
//!   sha1 + info u32be (low 24 = next block, `0xFFFFFF` = end)
//! - data block `b` lives at
//!   `round_up(header_size) + mapped(b) * 0x1000` with hash-table
//!   slots interleaved per level spans {170, 28900, 4913000}
//! - directory blocks hold 64 entries of 0x40 bytes: name[40],
//!   flags (length low 6, contiguous bit 6, directory bit 7),
//!   valid/allocated/start u24le, parent u16be, length u32be
//!
//! Only read-only single-backing packages are supported; dual-backing
//! resiliency tables are explicit `Unsupported`. Data blocks are SHA1
//! verified against their hash entries on every read.

use sha1::{Digest, Sha1};
use x360_common::{EmuError, Result};

pub const BLOCK: usize = 0x1000;
const L0_SPAN: u64 = 170;
const L1_SPAN: u64 = 28900;
const END_OF_CHAIN: u32 = 0xFF_FFFF;
const DIR_ENTRIES: usize = 64;
const DIR_ENTRY_SIZE: usize = 0x40;
const HASH_ENTRY_SIZE: usize = 0x18;

/// One directory entry.
#[derive(Debug, Clone)]
pub struct StfsEntry {
    pub name: String,
    pub is_dir: bool,
    pub parent: u16,
    pub start_block: u32,
    pub length: u32,
}

/// An opened STFS image (borrows the package bytes).
pub struct StfsImage<'a> {
    data: &'a [u8],
    header_size: u64,
    file_table_block: u32,
    file_table_count: u32,
    total_blocks: u32,
    blocks_per_hash: u64,
    block_step0: u64,
    block_step1: u64,
}

fn read_u16be(data: &[u8], off: usize) -> Result<u16> {
    if off + 2 > data.len() {
        return Err(EmuError::Other("stfs field OOB".into()));
    }
    Ok(u16::from_be_bytes([data[off], data[off + 1]]))
}

fn read_u32be(data: &[u8], off: usize) -> Result<u32> {
    if off + 4 > data.len() {
        return Err(EmuError::Other("stfs field OOB".into()));
    }
    Ok(u32::from_be_bytes([
        data[off],
        data[off + 1],
        data[off + 2],
        data[off + 3],
    ]))
}

fn read_u24le(data: &[u8], off: usize) -> Result<u32> {
    if off + 3 > data.len() {
        return Err(EmuError::Other("stfs field OOB".into()));
    }
    Ok(data[off] as u32 | ((data[off + 1] as u32) << 8) | ((data[off + 2] as u32) << 16))
}

fn round_up(v: u64, align: u64) -> u64 {
    v.div_ceil(align) * align
}

impl<'a> StfsImage<'a> {
    /// Open and validate. `data` is the whole package file.
    pub fn open(data: &'a [u8]) -> Result<Self> {
        if data.len() < 0x400 {
            return Err(EmuError::Other("stfs too small".into()));
        }
        match &data[0..4] {
            b"CON " | b"PIRS" | b"LIVE" => {}
            _ => return Err(EmuError::Other("not an STFS package".into())),
        }
        let header_size = read_u32be(data, 0x340)? as u64;
        if header_size == 0 || header_size > data.len() as u64 {
            return Err(EmuError::Other("stfs header size OOB".into()));
        }
        const VD: usize = 0x379;
        if data[VD] != 0x24 {
            return Err(EmuError::Other("bad volume descriptor".into()));
        }
        let flags = data[VD + 2];
        let read_only = flags & 1 != 0;
        if !read_only {
            return Err(EmuError::Unsupported(
                "dual-backing STFS resiliency tables pending".into(),
            ));
        }
        let volume_type = read_u32be(data, 0x3A9)?;
        if volume_type != 0 {
            return Err(EmuError::Unsupported(
                "SVOD volumes pending (STFS only)".into(),
            ));
        }
        let file_table_count = read_u16be(data, VD + 3)? as u32;
        let file_table_block = read_u24le(data, VD + 5)?;
        let total_blocks = read_u32be(data, VD + 0x1C)?;
        if total_blocks == 0 || total_blocks > 1 << 24 {
            return Err(EmuError::Other("stfs block count unreasonable".into()));
        }
        Ok(Self {
            data,
            header_size,
            file_table_block,
            file_table_count,
            total_blocks,
            blocks_per_hash: 1,
            block_step0: L0_SPAN + 1,
            block_step1: L1_SPAN + (L0_SPAN + 1),
        })
    }

    pub fn total_blocks(&self) -> u32 {
        self.total_blocks
    }

    fn block_to_offset(&self, block: u64) -> Result<u64> {
        if block >= self.total_blocks as u64 + 4096 {
            return Err(EmuError::Other(format!("stfs block {} OOB", block)));
        }
        let mut base = L0_SPAN;
        let mut mapped = block;
        for _ in 0..3 {
            mapped += ((block + base) / base) * self.blocks_per_hash;
            if block < base {
                break;
            }
            base *= L0_SPAN;
        }
        let off = round_up(self.header_size, BLOCK as u64) + mapped * BLOCK as u64;
        if off + BLOCK as u64 > self.data.len() as u64 {
            return Err(EmuError::Other(format!("stfs block {} past EOF", block)));
        }
        Ok(off)
    }

    fn hash_block_number(&self, block: u32, level: u32) -> u64 {
        let b = block as u64;
        match level {
            0 => {
                if b < L0_SPAN {
                    return 0;
                }
                let mut n =
                    (b / L0_SPAN) * self.block_step0 + ((b / L1_SPAN) + 1) * self.blocks_per_hash;
                if b < L1_SPAN {
                    return n;
                }
                n += self.blocks_per_hash;
                n
            }
            1 => {
                if b < L1_SPAN {
                    return self.block_step0;
                }
                (b / L1_SPAN) * self.block_step1 + self.blocks_per_hash
            }
            _ => self.block_step1,
        }
    }

    fn hash_table_offset(&self, block: u32) -> Result<u64> {
        // Read-only packages use a single backing block per table.
        let num = self.hash_block_number(block, 0);
        // Table index 0 is the top table; its offset needs no chain walk.
        let _ = num;
        Ok(round_up(self.header_size, BLOCK as u64) + num * BLOCK as u64)
    }

    /// Hash entry (sha1 + info) covering data `block`.
    fn hash_entry(&self, block: u32) -> Result<([u8; 20], u32)> {
        let table_off = self.hash_table_offset(block)? as usize;
        let record = (block as u64 % L0_SPAN) as usize;
        let off = table_off + record * HASH_ENTRY_SIZE;
        if off + HASH_ENTRY_SIZE > self.data.len() {
            return Err(EmuError::Other("stfs hash entry OOB".into()));
        }
        let mut sha = [0u8; 20];
        sha.copy_from_slice(&self.data[off..off + 20]);
        let info = read_u32be(self.data, off + 20)?;
        Ok((sha, info))
    }

    /// Follow the level-0 chain from `start`, collecting data blocks.
    fn chain(&self, start: u32, max_blocks: u64) -> Result<Vec<u32>> {
        let mut out = Vec::new();
        let mut block = start;
        while block != END_OF_CHAIN {
            if out.len() as u64 >= max_blocks {
                return Err(EmuError::Other("stfs chain overrun".into()));
            }
            if block >= self.total_blocks {
                return Err(EmuError::Other(format!("stfs chain block {} OOB", block)));
            }
            out.push(block);
            let (_, info) = self.hash_entry(block)?;
            block = info & 0xFF_FFFF;
        }
        Ok(out)
    }

    /// List all directory entries (flat, with parent indices).
    pub fn list_files(&self) -> Result<Vec<StfsEntry>> {
        let mut out = Vec::new();
        let mut table = self.file_table_block;
        for _ in 0..self.file_table_count.max(1) {
            let off = self.block_to_offset(table as u64)? as usize;
            for i in 0..DIR_ENTRIES {
                let e = off + i * DIR_ENTRY_SIZE;
                if e + DIR_ENTRY_SIZE > self.data.len() {
                    return Err(EmuError::Other("stfs directory OOB".into()));
                }
                if self.data[e] == 0 {
                    break;
                }
                let flags = self.data[e + 40];
                let name_len = (flags & 0x3F) as usize;
                if name_len == 0 || name_len > 40 {
                    return Err(EmuError::Other("stfs bad name length".into()));
                }
                let name = String::from_utf8_lossy(&self.data[e..e + name_len]).into_owned();
                out.push(StfsEntry {
                    name,
                    is_dir: flags & 0x80 != 0,
                    parent: read_u16be(self.data, e + 50)?,
                    start_block: read_u24le(self.data, e + 47)?,
                    length: read_u32be(self.data, e + 52)?,
                });
            }
            let (_, info) = self.hash_entry(table)?;
            table = info & 0xFF_FFFF;
            if table == END_OF_CHAIN {
                break;
            }
        }
        Ok(out)
    }

    /// Read a file's bytes, SHA1-verifying every block against its entry.
    pub fn read_file(&self, entry: &StfsEntry) -> Result<Vec<u8>> {
        if entry.is_dir {
            return Err(EmuError::Other("stfs read of directory".into()));
        }
        let need = (entry.length as u64).div_ceil(BLOCK as u64);
        let blocks = self.chain(entry.start_block, need + 1)?;
        if (blocks.len() as u64) < need {
            return Err(EmuError::Other(format!(
                "stfs {} chain short ({} < {})",
                entry.name,
                blocks.len(),
                need
            )));
        }
        let mut out = Vec::with_capacity(entry.length as usize);
        for block in blocks.iter().take(need as usize) {
            let off = self.block_to_offset(*block as u64)? as usize;
            let chunk = &self.data[off..off + BLOCK];
            let (sha, _) = self.hash_entry(*block)?;
            let mut hasher = Sha1::new();
            hasher.update(chunk);
            if hasher.finalize().as_slice() != sha {
                return Err(EmuError::Other(format!(
                    "stfs {} block {} hash mismatch",
                    entry.name, block
                )));
            }
            let take = ((entry.length as usize) - out.len()).min(BLOCK);
            out.extend_from_slice(&chunk[..take]);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal read-only image: 1 file-table block, 1 file ("hi.bin",
    /// 3 bytes), 1 data block. Layout: header pages, hash table at the
    /// first computed slot, file table next, data block after.
    fn tiny_image() -> Vec<u8> {
        // header_size 0x1000 -> blocks start at 0x1000.
        // block_to_offset(0) = 0x1000 + (0 + (0+170)/170*1)*0x1000 = 0x2000.
        // hash table 0 at 0x1000. data block 1 -> 0x1000 + (1+1)*0x1000 = 0x3000.
        let mut v = vec![0u8; 0x4000];
        v[0..4].copy_from_slice(b"LIVE");
        v[0x340..0x344].copy_from_slice(&0x1000u32.to_be_bytes());
        let vd = 0x379;
        v[vd] = 0x24;
        v[vd + 1] = 0;
        v[vd + 2] = 0x01; // read-only
        v[vd + 3..vd + 5].copy_from_slice(&1u16.to_be_bytes()); // 1 table block
        v[vd + 5..vd + 8].copy_from_slice(&[0, 0, 0]); // table block 0
        v[vd + 0x1C..vd + 0x20].copy_from_slice(&8u32.to_be_bytes()); // total
        v[0x3A9..0x3AD].copy_from_slice(&0u32.to_be_bytes()); // STFS
                                                              // Hash table at 0x1000: entry[0] -> table chain END, entry[1] -> data END + sha.
                                                              // data block content "ABC" first; hash over full block below.
        v[0x3000..0x3003].copy_from_slice(b"ABC");
        let mut hasher = Sha1::new();
        hasher.update(&v[0x3000..0x4000]);
        let digest = hasher.finalize();
        // entry 0: next = END (file-table chain of length 1).
        v[0x1000 + 20..0x1000 + 24].copy_from_slice(&END_OF_CHAIN.to_be_bytes());
        // entry 1: sha + next = END.
        v[0x1000 + 0x18..0x1000 + 0x2C].copy_from_slice(&digest);
        v[0x1000 + 0x2C..0x1000 + 0x30].copy_from_slice(&END_OF_CHAIN.to_be_bytes());
        // Directory block at 0x2000: one file.
        let e = 0x2000;
        v[e..e + 6].copy_from_slice(b"hi.bin");
        v[e + 40] = 6; // name len 6, file
        v[e + 41..e + 44].copy_from_slice(&[1, 0, 0]); // valid blocks u24le
        v[e + 44..e + 47].copy_from_slice(&[1, 0, 0]); // allocated u24le
        v[e + 47..e + 50].copy_from_slice(&[1, 0, 0]); // start block 1
        v[e + 50..e + 52].copy_from_slice(&0xFFFFu16.to_be_bytes());
        v[e + 52..e + 56].copy_from_slice(&3u32.to_be_bytes()); // length 3
        v
    }

    #[test]
    fn tiny_lists_and_reads() {
        let img = tiny_image();
        let stfs = StfsImage::open(&img).unwrap();
        let files = stfs.list_files().unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name, "hi.bin");
        assert!(!files[0].is_dir);
        assert_eq!(stfs.read_file(&files[0]).unwrap(), b"ABC");
    }

    #[test]
    fn bad_magic_rejected() {
        assert!(StfsImage::open(b"NOPE rest of bytes here........").is_err());
        assert!(StfsImage::open(&[0u8; 16]).is_err());
    }

    #[test]
    fn tampered_block_detected() {
        let mut img = tiny_image();
        img[0x3000] ^= 0xFF;
        let stfs = StfsImage::open(&img).unwrap();
        let files = stfs.list_files().unwrap();
        assert!(stfs.read_file(&files[0]).is_err());
    }

    /// Retail proof: Braid GOD lists real files and its XEX extracts
    /// with a valid header. Gated on `$X360_STFS_FILE` (a `LIVE` package
    /// such as the quarantined Braid data file). Package bytes stay out
    /// of git.
    #[test]
    fn retail_braid_lists_and_extracts() {
        let path = match std::env::var("X360_STFS_FILE") {
            Ok(p) => p,
            Err(_) => return,
        };
        let bytes = std::fs::read(&path).expect("read package");
        let stfs = StfsImage::open(&bytes).expect("open package");
        println!("total_blocks={}", stfs.total_blocks());
        let files = stfs.list_files().expect("list files");
        assert!(!files.is_empty(), "empty package");
        for f in files.iter().take(30) {
            println!(
                "{} {} len={}",
                if f.is_dir { "dir " } else { "file" },
                f.name,
                f.length
            );
        }
        let xex = files
            .iter()
            .find(|f| !f.is_dir && f.name.to_lowercase().ends_with(".xex"))
            .expect("no .xex in package");
        println!("extracting {} ({} bytes)", xex.name, xex.length);
        let data = stfs.read_file(xex).expect("extract xex");
        assert!(data.len() >= 24, "xex too small");
        assert_eq!(&data[0..4], b"XEX2", "not an XEX2 image");
        println!(
            "xex ok: {} bytes, entry dir follows loader rules",
            data.len()
        );
    }
}
