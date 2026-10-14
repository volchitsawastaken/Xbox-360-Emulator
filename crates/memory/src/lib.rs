//! 512 MB unified guest memory with regions and permissions.
//!
//! Guest map (reference `memory.cc`):
//! - `0x00000000..0x20000000` physical DRAM (512 MB)
//! - `0x80000000..0xA0000000` cached mirror of DRAM
//! - `0xC0000000..0xE0000000` uncached mirror of DRAM
//! - `0x7FC80000..0x80000000` MMIO (3.5 MB, real backing bytes;
//!   EXEC denied — games never execute it)
//! - `0x7F000000..0x7FC80000` GPU writeback/XPS (12.5 MB, zeroed
//!   backing; the GPU fills it on real hardware, reads see zeros
//!   until the GPU backend lands)
//!
//! M4 semantics: all DRAM is RWX; `Perm` is honored for the MMIO
//! EXEC denial and will be enforced per-region in M6 (write-protect,
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
/// MMIO window (reference `memory.cc`: 0x7FC80000-0x7FFFFFFF).
pub const MMIO_BASE: u32 = 0x7FC8_0000;
pub const MMIO_SIZE: usize = 0x0038_0000;
/// GPU writeback/XPS window (reference: 0x7F000000-0x7FC7FFFF).
pub const WB_BASE: u32 = 0x7F00_0000;
pub const WB_SIZE: usize = 0x00C8_0000;

bitflags::bitflags! {
    /// Access permissions per region.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Perm: u8 {
        const READ = 0b001;
        const WRITE = 0b010;
        const EXEC = 0b100;
    }
}

/// Backing location for a translated access.
#[derive(Debug, Clone, Copy)]
enum Loc {
    Dram(usize),
    Mmio(usize),
    Wb(usize),
}

/// Guest memory.
pub struct Memory {
    data: Vec<u8>,
    mmio: Vec<u8>,
    wb: Vec<u8>,
}

impl Memory {
    pub fn new() -> Self {
        Self {
            data: vec![0; MEM_SIZE],
            mmio: vec![0; MMIO_SIZE],
            wb: vec![0; WB_SIZE],
        }
    }

    /// Translate guest address to backing store. MMIO/writeback route
    /// to their own bytes; EXEC inside them is denied (genuine: the
    /// reference never executes MMIO either).
    fn translate(&self, addr: u32, size: usize, need: Perm) -> Result<Loc> {
        let end = (addr as u64)
            .checked_add(size as u64)
            .ok_or_else(|| EmuError::MemoryFault {
                addr,
                size,
                kind: "overflow".into(),
            })?;

        // MMIO + writeback windows route to their own backing.
        // EXEC inside them is denied (reference never executes MMIO).
        let mm_end = MMIO_BASE as u64 + MMIO_SIZE as u64;
        if (addr as u64) >= MMIO_BASE as u64 && end <= mm_end {
            if need.contains(Perm::EXEC) {
                return Err(EmuError::MemoryFault {
                    addr,
                    size,
                    kind: "exec denied in mmio window".into(),
                });
            }
            return Ok(Loc::Mmio((addr - MMIO_BASE) as usize));
        }
        let wb_end = WB_BASE as u64 + WB_SIZE as u64;
        if (addr as u64) >= WB_BASE as u64 && end <= wb_end {
            if need.contains(Perm::EXEC) {
                return Err(EmuError::MemoryFault {
                    addr,
                    size,
                    kind: "exec denied in writeback window".into(),
                });
            }
            return Ok(Loc::Wb((addr - WB_BASE) as usize));
        }

        // DRAM mirrors.
        let dram_end = MEM_SIZE as u64;
        if end <= dram_end {
            return Ok(Loc::Dram(addr as usize));
        }
        let v_base = VIRT_BASE as u64;
        let v_end = v_base + dram_end;
        if (addr as u64) >= v_base && end <= v_end {
            return Ok(Loc::Dram((addr - VIRT_BASE) as usize));
        }
        let u_base = UNCACHED_BASE as u64;
        let u_end = u_base + dram_end;
        if (addr as u64) >= u_base && end <= u_end {
            return Ok(Loc::Dram((addr - UNCACHED_BASE) as usize));
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
        Ok(self.slice(addr, 1, Perm::READ)?[0])
    }

    pub fn write_u8(&mut self, addr: u32, v: u8) -> Result<()> {
        self.slice_mut(addr, 1, Perm::WRITE)?[0] = v;
        Ok(())
    }

    pub fn read_u32(&self, addr: u32) -> Result<u32> {
        Self::check_align(addr, 4)?;
        let b = self.slice(addr, 4, Perm::READ)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Instruction fetch requires EXEC permission (DRAM is READ|WRITE|EXEC).
    pub fn fetch_u32(&self, addr: u32) -> Result<u32> {
        Self::check_align(addr, 4)?;
        let b = self.slice(addr, 4, Perm::EXEC)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn write_u32(&mut self, addr: u32, v: u32) -> Result<()> {
        Self::check_align(addr, 4)?;
        self.slice_mut(addr, 4, Perm::WRITE)?
            .copy_from_slice(&v.to_be_bytes());
        Ok(())
    }

    /// 64-bit big-endian access for `ld/std` (PPC64 GPRs). Deliberately
    /// permissive on alignment: retail Braid stores dwords to 4-aligned
    /// addresses (396-byte stride array, field at +24), which shipped
    /// hardware tolerates and the reference's `uint32_t` memory never
    /// faults on. Wild addresses still fault at translation (unmapped).
    pub fn read_u64(&self, addr: u32) -> Result<u64> {
        let b = self.slice(addr, 8, Perm::READ)?;
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    pub fn write_u64(&mut self, addr: u32, v: u64) -> Result<()> {
        self.slice_mut(addr, 8, Perm::WRITE)?
            .copy_from_slice(&v.to_be_bytes());
        Ok(())
    }

    pub fn read_bytes(&self, addr: u32, len: usize) -> Result<&[u8]> {
        self.slice(addr, len, Perm::READ)
    }

    pub fn write_bytes(&mut self, addr: u32, src: &[u8]) -> Result<()> {
        let len = src.len();
        self.slice_mut(addr, len, Perm::WRITE)?.copy_from_slice(src);
        Ok(())
    }

    /// Guest physical address for a virtual address (reference
    /// `MmGetPhysicalAddress`): mirrors collapse to DRAM, physical
    /// addresses pass through, anything else maps to 0 (never a
    /// fabricated pointer).
    pub fn to_physical(&self, addr: u32) -> u32 {
        if (addr as u64) < MEM_SIZE as u64 {
            return addr;
        }
        if addr >= VIRT_BASE && (addr - VIRT_BASE) < MEM_SIZE as u32 {
            return addr - VIRT_BASE;
        }
        if addr >= UNCACHED_BASE && (addr - UNCACHED_BASE) < MEM_SIZE as u32 {
            return addr - UNCACHED_BASE;
        }
        0
    }

    /// Host pointer for fast paths. Requires WRITE since it hands out `*mut`.
    /// Isolated unsafe boundary, documented. DRAM only: MMIO has no
    /// stable host image yet (GPU backend will own it).
    pub fn host_ptr(&mut self, addr: u32, len: usize) -> Result<*mut u8> {
        match self.translate(addr, len, Perm::WRITE)? {
            Loc::Dram(off) => {
                // SAFETY: bounds checked above, pointer valid for self lifetime.
                Ok(unsafe { self.data.as_mut_ptr().add(off) })
            }
            Loc::Mmio(_) | Loc::Wb(_) => Err(EmuError::MemoryFault {
                addr,
                size: len,
                kind: "host_ptr denied outside DRAM".into(),
            }),
        }
    }

    fn slice(&self, addr: u32, len: usize, need: Perm) -> Result<&[u8]> {
        match self.translate(addr, len, need)? {
            Loc::Dram(off) => Ok(&self.data[off..off + len]),
            Loc::Mmio(off) => Ok(&self.mmio[off..off + len]),
            Loc::Wb(off) => Ok(&self.wb[off..off + len]),
        }
    }

    fn slice_mut(&mut self, addr: u32, len: usize, need: Perm) -> Result<&mut [u8]> {
        match self.translate(addr, len, need)? {
            Loc::Dram(off) => Ok(&mut self.data[off..off + len]),
            Loc::Mmio(off) => Ok(&mut self.mmio[off..off + len]),
            Loc::Wb(off) => Ok(&mut self.wb[off..off + len]),
        }
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
    fn physical_collapses_mirrors() {
        let m = Memory::new();
        assert_eq!(m.to_physical(0x0011_5000), 0x0011_5000);
        assert_eq!(m.to_physical(0x8211_5000), 0x0211_5000);
        assert_eq!(m.to_physical(0xC211_5000), 0x0211_5000);
        assert_eq!(m.to_physical(0xFFFF_0000), 0);
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
    fn mmio_window_roundtrips() {
        // Reference map: 0x7FC80000+ is MMIO with real storage.
        let mut m = Memory::new();
        m.write_u32(0x7FC8_0714, 0xDEAD_BEEF).unwrap();
        assert_eq!(m.read_u32(0x7FC8_0714).unwrap(), 0xDEAD_BEEF);
        // Reads see last-written values (zeros initially).
        assert_eq!(m.read_u32(0x7FC8_0000).unwrap(), 0);
        // EXEC inside MMIO is denied.
        assert!(m.fetch_u32(0x7FC8_0714).is_err());
        // Writeback window is zeroed storage too.
        m.write_u32(0x7F00_0010, 0x1234_5678).unwrap();
        assert_eq!(m.read_u32(0x7F00_0010).unwrap(), 0x1234_5678);
        // Between DRAM top and 0x7F000000 is still unmapped.
        assert!(m.read_u32(0x4000_0000).is_err());
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
