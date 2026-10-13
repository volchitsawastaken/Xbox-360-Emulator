//! 512 MB unified guest memory with regions and permissions.
//!
//! Guest map:
//! - `0x00000000..0x20000000` physical DRAM (512 MB)
//! - `0x80000000..0xA0000000` cached mirror of DRAM
//! - `0xC0000000..0xE0000000` uncached mirror of DRAM
//! - `0x7FFF0000..0x80000000` MMIO guard (always denied, reachable)
//!
//! M4 semantics: all DRAM is RWX; `Perm` is honored for the MMIO guard
//! deny message and will be enforced per-region in M6 (write-protect,
//! code pages). `fetch_u32` exists so EXEC faults are distinguishable
//! in traces once enforcement lands.

use x360_common::{EmuError, Result};

/// Total unified memory: 512 MiB.
pub const MEM_SIZE: usize = 512 * 1024 * 1024;
/// Guest physical base.
pub const PHYS_BASE: u32 = 0x0000_0000;
/// Cached virtual mirror base.
pub const VIRT_BASE: u32 = 0x8000_0000;
/// Uncached mirror base.
pub const UNCACHED_BASE: u32 = 0xC000_0000;
/// MMIO guard window.
pub const MMIO_BASE: u32 = 0x7FFF_0000;
pub const MMIO_SIZE: u32 = 0x0001_0000;

bitflags::bitflags! {
    /// Access permissions per region.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Perm: u8 {
        const READ = 0b001;
        const WRITE = 0b010;
        const EXEC = 0b100;
    }
}

/// Guest memory.
pub struct Memory {
    data: Vec<u8>,
}

impl Memory {
    pub fn new() -> Self {
        Self {
            data: vec![0; MEM_SIZE],
        }
    }

    /// Translate guest address to DRAM offset.
    /// Returns Err for MMIO (permission denied) and unmapped/OOB.
    fn translate(&self, addr: u32, size: usize, need: Perm) -> Result<usize> {
        let end = (addr as u64)
            .checked_add(size as u64)
            .ok_or_else(|| EmuError::MemoryFault {
                addr,
                size,
                kind: "overflow".into(),
            })?;

        // MMIO guard is reachable and always denied for direct access.
        // Any overlap with the window is denied (not just fully inside).
        let mmio_end = MMIO_BASE as u64 + MMIO_SIZE as u64;
        if (addr as u64) < mmio_end && end > MMIO_BASE as u64 {
            return Err(EmuError::MemoryFault {
                addr,
                size,
                kind: format!("permission denied in mmio-guard (need {:?})", need),
            });
        }

        // DRAM mirrors.
        let dram_end = MEM_SIZE as u64;
        if end <= dram_end {
            return Ok(addr as usize);
        }
        let v_base = VIRT_BASE as u64;
        let v_end = v_base + dram_end;
        if (addr as u64) >= v_base && end <= v_end {
            return Ok((addr - VIRT_BASE) as usize);
        }
        let u_base = UNCACHED_BASE as u64;
        let u_end = u_base + dram_end;
        if (addr as u64) >= u_base && end <= u_end {
            return Ok((addr - UNCACHED_BASE) as usize);
        }

        Err(EmuError::MemoryFault {
            addr,
            size,
            kind: "out-of-range (512MB unified + mirrors)".into(),
        })
    }

    fn check_align(addr: u32, align: u32) -> Result<()> {
        if !addr.is_multiple_of(align) {
            return Err(EmuError::AlignmentFault { addr });
        }
        Ok(())
    }

    pub fn read_u8(&self, addr: u32) -> Result<u8> {
        let off = self.translate(addr, 1, Perm::READ)?;
        Ok(self.data[off])
    }

    pub fn write_u8(&mut self, addr: u32, v: u8) -> Result<()> {
        let off = self.translate(addr, 1, Perm::WRITE)?;
        self.data[off] = v;
        Ok(())
    }

    pub fn read_u32(&self, addr: u32) -> Result<u32> {
        Self::check_align(addr, 4)?;
        let off = self.translate(addr, 4, Perm::READ)?;
        Ok(u32::from_be_bytes([
            self.data[off],
            self.data[off + 1],
            self.data[off + 2],
            self.data[off + 3],
        ]))
    }

    /// Instruction fetch requires EXEC permission (DRAM is READ|WRITE|EXEC).
    pub fn fetch_u32(&self, addr: u32) -> Result<u32> {
        Self::check_align(addr, 4)?;
        let off = self.translate(addr, 4, Perm::EXEC)?;
        Ok(u32::from_be_bytes([
            self.data[off],
            self.data[off + 1],
            self.data[off + 2],
            self.data[off + 3],
        ]))
    }

    pub fn write_u32(&mut self, addr: u32, v: u32) -> Result<()> {
        Self::check_align(addr, 4)?;
        let off = self.translate(addr, 4, Perm::WRITE)?;
        self.data[off..off + 4].copy_from_slice(&v.to_be_bytes());
        Ok(())
    }

    /// 64-bit big-endian access for `ld/std` (PPC64 GPRs). Deliberately
    /// permissive on alignment: retail Braid stores dwords to 4-aligned
    /// addresses (396-byte stride array, field at +24), which shipped
    /// hardware tolerates and the reference's `uint32_t` memory never
    /// faults on. Wild addresses still fault at translation (unmapped).
    pub fn read_u64(&self, addr: u32) -> Result<u64> {
        let off = self.translate(addr, 8, Perm::READ)?;
        Ok(u64::from_be_bytes([
            self.data[off],
            self.data[off + 1],
            self.data[off + 2],
            self.data[off + 3],
            self.data[off + 4],
            self.data[off + 5],
            self.data[off + 6],
            self.data[off + 7],
        ]))
    }

    pub fn write_u64(&mut self, addr: u32, v: u64) -> Result<()> {
        let off = self.translate(addr, 8, Perm::WRITE)?;
        self.data[off..off + 8].copy_from_slice(&v.to_be_bytes());
        Ok(())
    }

    pub fn read_bytes(&self, addr: u32, len: usize) -> Result<&[u8]> {
        let off = self.translate(addr, len, Perm::READ)?;
        Ok(&self.data[off..off + len])
    }

    pub fn write_bytes(&mut self, addr: u32, src: &[u8]) -> Result<()> {
        let off = self.translate(addr, src.len(), Perm::WRITE)?;
        self.data[off..off + src.len()].copy_from_slice(src);
        Ok(())
    }

    /// Host pointer for fast paths. Requires WRITE since it hands out `*mut`.
    /// Isolated unsafe boundary, documented.
    pub fn host_ptr(&mut self, addr: u32, len: usize) -> Result<*mut u8> {
        let off = self.translate(addr, len, Perm::WRITE)?;
        // SAFETY: bounds checked above, pointer valid for self lifetime.
        Ok(unsafe { self.data.as_mut_ptr().add(off) })
    }
}

impl Default for Memory {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_be() {
        let mut m = Memory::new();
        m.write_u32(0x1000, 0xDEAD_BEEF).unwrap();
        assert_eq!(m.read_u32(0x1000).unwrap(), 0xDEAD_BEEF);
    }

    #[test]
    fn mirrors_alias() {
        let mut m = Memory::new();
        m.write_u32(0x1000, 0x1234_5678).unwrap();
        assert_eq!(m.read_u32(VIRT_BASE + 0x1000).unwrap(), 0x1234_5678);
        assert_eq!(m.read_u32(UNCACHED_BASE + 0x1000).unwrap(), 0x1234_5678);
        assert_eq!(m.fetch_u32(VIRT_BASE + 0x1000).unwrap(), 0x1234_5678);
    }

    #[test]
    fn high_entry_addresses_work() {
        let mut m = Memory::new();
        m.write_u32(0x8200_1000, 0x6000_0000).unwrap();
        assert_eq!(m.fetch_u32(0x8200_1000).unwrap(), 0x6000_0000);
    }

    #[test]
    fn oob_is_error_not_wrap() {
        let m = Memory::new();
        let r = m.read_u32(0xFFFF_FFFC);
        assert!(r.is_err());
    }

    #[test]
    fn misaligned_is_error() {
        let m = Memory::new();
        assert!(m.read_u32(0x1001).is_err());
    }

    #[test]
    fn u64_roundtrip_be() {
        let mut m = Memory::new();
        m.write_u64(0x2000, 0x1122_3344_5566_7788).unwrap();
        assert_eq!(m.read_u64(0x2000).unwrap(), 0x1122_3344_5566_7788);
        assert_eq!(m.read_u32(0x2000).unwrap(), 0x1122_3344);
        assert_eq!(m.read_u32(0x2004).unwrap(), 0x5566_7788);
    }

    #[test]
    fn u64_four_aligned_roundtrips() {
        // Retail Braid `std` to 4-aligned addresses must work.
        let mut m = Memory::new();
        m.write_u64(0x2004, 0x1122_3344_5566_7788).unwrap();
        assert_eq!(m.read_u64(0x2004).unwrap(), 0x1122_3344_5566_7788);
    }

    #[test]
    fn mmio_guard_denies() {
        let m = Memory::new();
        assert!(m.read_u32(MMIO_BASE).is_err());
        let mut m2 = Memory::new();
        assert!(m2.write_u8(MMIO_BASE, 1).is_err());
    }

    #[test]
    fn spanning_mmio_is_denied() {
        let m = Memory::new();
        // 8-byte read starting 4 bytes before MMIO must not succeed.
        assert!(m.read_bytes(MMIO_BASE - 4, 8).is_err());
    }

    #[test]
    fn host_ptr_roundtrip() {
        let mut m = Memory::new();
        let ptr = m.host_ptr(0x2000, 4).unwrap();
        // SAFETY: pointer from host_ptr, bounds checked, test-only.
        unsafe {
            std::ptr::write_bytes(ptr, 0xAB, 4);
        }
        assert_eq!(m.read_bytes(0x2000, 4).unwrap(), &[0xAB; 4]);
    }
}
