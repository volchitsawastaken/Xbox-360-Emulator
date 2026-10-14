//! PM4 ring / indirect-buffer executor: CPU-visible side effects.
//!
//! Reference (facts only; logic below is original):
//! - `src/xenia/gpu/xenos.h` — packet framing (`type = word >> 30`),
//!   type-3 `opcode = (word >> 8) & 0x7F`, `count = ((word >> 16) &
//!   0x3FFF) + 1`, `GpuSwap`/`Endian` table, opcode numbers.
//! - `src/xenia/gpu/pm4_command_processor_implement.h` — `ExecutePacket`
//!   (words 0/`0xBAADF00D` skipped, type-2 NOP), `ExecutePacketType0`
//!   (`base = word & 0x7FFF`, bit 15 = write-one, `count + 1` values),
//!   `ExecutePacketType1` (two reg/value pairs), `ExecuteIndirectBuffer`
//!   (`[list_ptr, list_length & 0xFFFFF]`, length in dwords),
//!   `ExecutePacketType3_MEM_WRITE` (`[addr, data...]`, per-word
//!   `GpuSwap(addr & 3)`, `addr += 4`), `ExecutePacketType3_EVENT_WRITE`
//!   (`[initiator]`, count 1 = flag only), `ExecutePacketType3_*_SHD/EXT`
//!   (`[initiator, address, value]`, `> 0x1FFFFFFF` remap through
//!   writeback base/size), `ExecutePacketType3_REG_RMW/REG_TO_MEM`,
//!   `ExecutePacketType3_WAIT_REG_MEM/COND_WRITE` (`MatchValueAndRef`),
//!   `ExecutePacketType3_INTERRUPT` (`[cpu_mask]`).
//! - `src/xenia/gpu/command_processor.cc` — worker loop (consume
//!   `[read, write)`, publish read index to the writeback pointer),
//!   `InitializeRingBuffer` (zero `1 << (size_log2 + 3)` bytes),
//!   register indices (`WRITEBACK_START 0x0A04`, `WRITEBACK_SIZE 0x0A05`,
//!   `VGT_EVENT_INITIATOR 0x21F9`, `RB_SAMPLE_COUNT_ADDR 0x2325`).
//! - `src/xenia/gpu/register_table.inc` — the register index facts above.
//!
//! Scope: memory/register effects the guest CPU can observe. Draw and
//! pipeline-state packets are length-skipped and counted (there is no
//! draw backend yet); unmatched waits, malformed framing, and exotic
//! endianness are explicit errors, never silent mis-execution.
//! Interrupts are recorded pending; delivery needs a safe
//! guest-reentry point and is still pending.

use std::collections::HashSet;
use x360_common::{EmuError, Result};
use x360_memory::Memory;

use crate::Kernel;

/// Type-3 opcodes with CPU-visible effects (reference `xenos.h`).
const OP_IB: u32 = 0x3F;
const OP_IB_PFD: u32 = 0x37;
const OP_MEM_WRITE: u32 = 0x3D;
const OP_EVENT_WRITE: u32 = 0x46;
const OP_EVENT_WRITE_SHD: u32 = 0x58;
const OP_EVENT_WRITE_EXT: u32 = 0x5A;
const OP_EVENT_WRITE_ZPD: u32 = 0x5B;
const OP_REG_RMW: u32 = 0x21;
const OP_REG_TO_MEM: u32 = 0x3E;
const OP_WAIT_REG_MEM: u32 = 0x3C;
const OP_COND_WRITE: u32 = 0x45;
const OP_INTERRUPT: u32 = 0x54;
const OP_NOP: u32 = 0x10;
const OP_ME_INIT: u32 = 0x48;

/// Register indices with executor-visible roles (reference
/// `register_table.inc`).
const REG_WRITEBACK_START: u32 = 0x0A04;
const REG_WRITEBACK_SIZE: u32 = 0x0A05;
const REG_VGT_EVENT_INITIATOR: u32 = 0x21F9;
const REG_RB_SAMPLE_COUNT_ADDR: u32 = 0x2325;

/// Maximum IB nesting (reference recurses; real streams nest shallowly).
const MAX_IB_DEPTH: u32 = 8;
/// Runaway guard per pump call (packets, not steps).
const MAX_PACKETS: u64 = 1_000_000;

/// Per-batch execution stats (tests + TEMP forensics).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct GpuExecStats {
    pub packets: u64,
    pub mem_writes: u64,
    pub reg_writes: u64,
    pub ib_entered: u64,
    /// Draw/state packets length-skipped (no draw backend yet).
    pub skipped_packets: u64,
    pub interrupts: u32,
}

/// `GpuSwap` (reference `xenos.h` `GpuSwapInline`).
fn gpu_swap(value: u32, endianness: u32) -> Result<u32> {
    match endianness {
        0 => Ok(value),
        1 => Ok(((value << 8) & 0xFF00_FF00) | ((value >> 8) & 0x00FF_00FF)),
        2 => Ok(value.swap_bytes()),
        3 => Ok(((value >> 16) & 0xFFFF) | (value << 16)),
        _ => Err(EmuError::Unsupported(format!(
            "PM4 bad endianness {}",
            endianness
        ))),
    }
}

/// `MatchValueAndRef` (reference `pm4_command_processor_implement.h`).
fn match_value_and_ref(value: u32, reference: u32, wait_info: u32) -> bool {
    let flags = (((value < reference) as u32) << 1)
        | (((value <= reference) as u32) << 2)
        | (((value == reference) as u32) << 3)
        | (((value != reference) as u32) << 4)
        | (((value >= reference) as u32) << 5)
        | (((value > reference) as u32) << 6)
        | (1 << 7);
    ((flags >> (wait_info & 7)) & 1) != 0
}

impl Kernel {
    /// Execute ring dwords `[start_dw, end_dw)`; `ring_dw` is the ring
    /// size in dwords for wraparound. Returns batch stats.
    pub fn gpu_exec_ring(
        &mut self,
        mem: &mut Memory,
        ring_base: u32,
        start_dw: u32,
        end_dw: u32,
        ring_dw: u32,
    ) -> Result<GpuExecStats> {
        if ring_dw == 0 {
            return Err(EmuError::Other("PM4 empty ring".into()));
        }
        let total = (end_dw.wrapping_sub(start_dw)) % ring_dw;
        // Linearize the (small, rare) batch; IBs recurse the same way.
        if total as u64 > MAX_PACKETS {
            return Err(EmuError::Other(format!("PM4 batch {} too large", total)));
        }
        let mut words = Vec::with_capacity(total as usize);
        for i in 0..total {
            let addr = ring_base.wrapping_add(((start_dw + i) % ring_dw) * 4);
            words.push(
                mem.read_u32(addr)
                    .map_err(|e| EmuError::Other(format!("PM4 ring read {:08x}: {}", addr, e)))?,
            );
        }
        let mut st = GpuExecStats::default();
        let mut seen_opcodes = HashSet::new();
        self.gpu_exec_linear(mem, &words, 0, &mut st, &mut seen_opcodes)?;
        Ok(st)
    }

    /// Execute a linear word slice (ring batch or indirect buffer).
    fn gpu_exec_linear(
        &mut self,
        mem: &mut Memory,
        words: &[u32],
        depth: u32,
        st: &mut GpuExecStats,
        seen_opcodes: &mut HashSet<u32>,
    ) -> Result<()> {
        if depth > MAX_IB_DEPTH {
            return Err(EmuError::Unsupported("PM4 IB nesting too deep".into()));
        }
        let mut c = 0usize;
        while c < words.len() {
            if st.packets >= MAX_PACKETS {
                return Err(EmuError::Other("PM4 packet cap exceeded".into()));
            }
            let w = words[c];
            st.packets += 1;
            // Reference `ExecutePacket`: 0 and 0xBAADF00D are skipped.
            if w == 0 || w == 0xBAAD_F00D {
                c += 1;
                continue;
            }
            match w >> 30 {
                // Type-2: single-dword NOP.
                2 => c += 1,
                // Type-1: two (reg11, value) pairs.
                1 => {
                    let r1 = w & 0x7FF;
                    let r2 = (w >> 11) & 0x7FF;
                    let (v1, v2) = (get(words, c + 1)?, get(words, c + 2)?);
                    self.vd_regs.insert(r1, v1);
                    self.vd_regs.insert(r2, v2);
                    st.reg_writes += 2;
                    c += 3;
                }
                // Type-0: count+1 values from base_index.
                0 => {
                    let base = w & 0x7FFF;
                    let one = (w >> 15) & 1;
                    let n = (((w >> 16) & 0x3FFF) + 1) as usize;
                    if one == 0 {
                        for k in 0..n {
                            self.vd_regs.insert(base + k as u32, get(words, c + 1 + k)?);
                        }
                        st.reg_writes += n as u64;
                    } else {
                        // Repeated write of one register; last wins.
                        let mut last = 0;
                        for k in 0..n {
                            last = get(words, c + 1 + k)?;
                        }
                        self.vd_regs.insert(base, last);
                        st.reg_writes += 1;
                    }
                    c += 1 + n;
                }
                // Type-3.
                _ => {
                    let opcode = (w >> 8) & 0x7F;
                    let cnt = (((w >> 16) & 0x3FFF) + 1) as usize;
                    if w & 1 != 0 {
                        return Err(EmuError::Unsupported(format!(
                            "PM4 predicated packet {:08x}",
                            w
                        )));
                    }
                    c = self.gpu_exec_type3(mem, words, c, opcode, cnt, depth, st, seen_opcodes)?;
                }
            }
        }
        Ok(())
    }

    /// Execute one type-3 packet at `c`; returns the next cursor.
    #[allow(clippy::too_many_arguments)]
    fn gpu_exec_type3(
        &mut self,
        mem: &mut Memory,
        words: &[u32],
        c: usize,
        opcode: u32,
        cnt: usize,
        depth: u32,
        st: &mut GpuExecStats,
        seen_opcodes: &mut HashSet<u32>,
    ) -> Result<usize> {
        // Payload availability (reference overflow-checks the same way).
        if c + cnt >= words.len() {
            return Err(EmuError::Other(format!(
                "PM4 truncated packet op {:02x} cnt {}",
                opcode, cnt
            )));
        }
        let p = |i: usize| words[c + 1 + i];
        match opcode {
            OP_NOP | OP_ME_INIT => Ok(c + 1 + cnt),
            OP_IB | OP_IB_PFD => {
                if cnt < 2 {
                    return Err(EmuError::Other("PM4 short IB packet".into()));
                }
                let base = p(0);
                let len = (p(1) & 0xF_FFFF) as usize;
                if base as u64 >= x360_memory::MEM_SIZE as u64 {
                    return Err(EmuError::Unsupported(format!(
                        "PM4 IB outside DRAM {:08x}",
                        base
                    )));
                }
                if len as u64 > MAX_PACKETS {
                    return Err(EmuError::Other(format!("PM4 IB len {} too large", len)));
                }
                let mut ib = Vec::with_capacity(len);
                for k in 0..len {
                    ib.push(
                        mem.read_u32(base.wrapping_add(k as u32 * 4))
                            .map_err(|e| EmuError::Other(format!("PM4 IB read: {}", e)))?,
                    );
                }
                st.ib_entered += 1;
                self.gpu_exec_linear(mem, &ib, depth + 1, st, seen_opcodes)?;
                // Reference consumes exactly [ptr, len]; extras (cnt > 2)
                // would parse as packets there too, so mirror that.
                Ok(c + 3)
            }
            OP_MEM_WRITE => {
                let mut addr = p(0);
                for i in 0..cnt - 1 {
                    let a = addr & !3;
                    let v = gpu_swap(p(1 + i), addr & 3)?;
                    mem.write_u32(a, v)
                        .map_err(|e| EmuError::Other(format!("PM4 MEM_WRITE {:08x}: {}", a, e)))?;
                    st.mem_writes += 1;
                    addr = addr.wrapping_add(4);
                }
                Ok(c + 1 + cnt)
            }
            OP_EVENT_WRITE => {
                if cnt != 1 {
                    return Err(EmuError::Unsupported(format!(
                        "PM4 EVENT_WRITE with address cnt {}",
                        cnt
                    )));
                }
                self.vd_regs.insert(REG_VGT_EVENT_INITIATOR, p(0) & 0x3F);
                Ok(c + 1 + cnt)
            }
            OP_EVENT_WRITE_SHD => {
                if cnt < 3 {
                    return Err(EmuError::Other("PM4 short EVENT_WRITE_SHD".into()));
                }
                let init = p(0);
                let mut addr = p(1);
                let value = p(2);
                self.vd_regs.insert(REG_VGT_EVENT_INITIATOR, init & 0x3F);
                if (init >> 31) & 1 != 0 {
                    return Err(EmuError::Unsupported(
                        "PM4 EVENT_WRITE_SHD counter source".into(),
                    ));
                }
                // Reference writeback-window remap for high addresses.
                if addr > 0x1FFF_FFFF {
                    let base = self.vd_regs.get(&REG_WRITEBACK_START).copied().unwrap_or(0);
                    let size = self.vd_regs.get(&REG_WRITEBACK_SIZE).copied().unwrap_or(0);
                    let off = addr.wrapping_sub(base);
                    if base != 0 && off < size {
                        addr = 0x7F00_0000 + off;
                    } else {
                        return Err(EmuError::Unsupported(format!(
                            "PM4 SHD outside writeback {:08x}",
                            addr
                        )));
                    }
                }
                let a = addr & !3;
                let v = gpu_swap(value, addr & 3)?;
                mem.write_u32(a, v)
                    .map_err(|e| EmuError::Other(format!("PM4 SHD {:08x}: {}", a, e)))?;
                st.mem_writes += 1;
                Ok(c + 1 + cnt)
            }
            OP_EVENT_WRITE_EXT => {
                if cnt < 2 {
                    return Err(EmuError::Other("PM4 short EVENT_WRITE_EXT".into()));
                }
                let init = p(0);
                let addr = p(1);
                self.vd_regs.insert(REG_VGT_EVENT_INITIATOR, init & 0x3F);
                // Reference asserts k8in16 and writes six halfwords
                // (full-screen extent fallback).
                if addr & 3 != 1 {
                    return Err(EmuError::Unsupported(format!(
                        "PM4 EXT bad alignment {:08x}",
                        addr
                    )));
                }
                let extents: [u16; 6] = [
                    (0u16 >> 3).swap_bytes(),
                    ((xenos_max_wh() >> 3) as u16).swap_bytes(),
                    (0u16 >> 3).swap_bytes(),
                    ((xenos_max_wh() >> 3) as u16).swap_bytes(),
                    0u16.swap_bytes(),
                    1u16.swap_bytes(),
                ];
                let mut bytes = [0u8; 12];
                for (i, e) in extents.iter().enumerate() {
                    bytes[2 * i] = (e & 0xFF) as u8;
                    bytes[2 * i + 1] = (e >> 8) as u8;
                }
                mem.write_bytes(addr, &bytes)
                    .map_err(|e| EmuError::Other(format!("PM4 EXT {:08x}: {}", addr, e)))?;
                st.mem_writes += 1;
                Ok(c + 1 + cnt)
            }
            OP_EVENT_WRITE_ZPD => {
                if cnt < 1 {
                    return Err(EmuError::Other("PM4 short EVENT_WRITE_ZPD".into()));
                }
                self.vd_regs.insert(REG_VGT_EVENT_INITIATOR, p(0) & 0x3F);
                let report = self
                    .vd_regs
                    .get(&REG_RB_SAMPLE_COUNT_ADDR)
                    .copied()
                    .unwrap_or(0);
                if report != 0 {
                    return Err(EmuError::Unsupported(
                        "PM4 occlusion-query report path".into(),
                    ));
                }
                Ok(c + 1 + cnt)
            }
            OP_REG_RMW => {
                if cnt < 3 {
                    return Err(EmuError::Other("PM4 short REG_RMW".into()));
                }
                let info = p(0);
                let reg = info & 0x1FFF;
                let mut v = self.vd_regs.get(&reg).copied().unwrap_or(0);
                if (info >> 31) & 1 != 0 {
                    v &= self.vd_regs.get(&(p(1) & 0x1FFF)).copied().unwrap_or(0);
                } else {
                    v &= p(1);
                }
                if (info >> 30) & 1 != 0 {
                    v |= self.vd_regs.get(&(p(2) & 0x1FFF)).copied().unwrap_or(0);
                } else {
                    v |= p(2);
                }
                self.vd_regs.insert(reg, v);
                st.reg_writes += 1;
                Ok(c + 1 + cnt)
            }
            OP_REG_TO_MEM => {
                if cnt < 2 {
                    return Err(EmuError::Other("PM4 short REG_TO_MEM".into()));
                }
                let reg = p(0);
                if reg >= 0x1_0000 {
                    return Err(EmuError::Unsupported(format!("PM4 bad reg {:08x}", reg)));
                }
                let v = self.vd_regs.get(&reg).copied().unwrap_or(0);
                let addr = p(1);
                let a = addr & !3;
                let w = gpu_swap(v, addr & 3)?;
                mem.write_u32(a, w)
                    .map_err(|e| EmuError::Other(format!("PM4 REG_TO_MEM {:08x}: {}", a, e)))?;
                st.mem_writes += 1;
                Ok(c + 1 + cnt)
            }
            OP_WAIT_REG_MEM => {
                if cnt < 5 {
                    return Err(EmuError::Other("PM4 short WAIT_REG_MEM".into()));
                }
                let info = p(0);
                let poll = p(1);
                let reference = p(2);
                let mask = p(3);
                let value = if info & 0x10 != 0 {
                    let a = poll & !3;
                    let raw = mem
                        .read_u32(a)
                        .map_err(|e| EmuError::Other(format!("PM4 WAIT read {:08x}: {}", a, e)))?;
                    gpu_swap(raw, poll & 3)?
                } else {
                    self.vd_regs.get(&poll).copied().unwrap_or(0)
                };
                if !match_value_and_ref(value & mask, reference, info) {
                    return Err(EmuError::Unsupported(format!(
                        "PM4 WAIT unsatisfied (op {:02x} val {:08x} ref {:08x} mask {:08x})",
                        opcode, value, reference, mask
                    )));
                }
                Ok(c + 1 + cnt)
            }
            OP_COND_WRITE => {
                if cnt < 6 {
                    return Err(EmuError::Other("PM4 short COND_WRITE".into()));
                }
                let info = p(0);
                let poll = p(1);
                let reference = p(2);
                let mask = p(3);
                let waddr = p(4);
                let wdata = p(5);
                let value = if info & 0x10 != 0 {
                    let a = poll & !3;
                    let raw = mem
                        .read_u32(a)
                        .map_err(|e| EmuError::Other(format!("PM4 COND read {:08x}: {}", a, e)))?;
                    gpu_swap(raw, poll & 3)?
                } else {
                    self.vd_regs.get(&poll).copied().unwrap_or(0)
                };
                if match_value_and_ref(value & mask, reference, info) {
                    if info & 0x100 != 0 {
                        let a = waddr & !3;
                        let w = gpu_swap(wdata, waddr & 3)?;
                        mem.write_u32(a, w)
                            .map_err(|e| EmuError::Other(format!("PM4 COND {:08x}: {}", a, e)))?;
                        st.mem_writes += 1;
                    } else {
                        self.vd_regs.insert(waddr, wdata);
                        st.reg_writes += 1;
                    }
                }
                Ok(c + 1 + cnt)
            }
            OP_INTERRUPT => {
                if cnt < 1 {
                    return Err(EmuError::Other("PM4 short INTERRUPT".into()));
                }
                if p(0) != 0 {
                    // Reference dispatches the guest graphics-interrupt
                    // callback per set bit; delivery needs a safe
                    // reentry point, so record it explicitly pending.
                    self.vd_irq_pending += 1;
                    st.interrupts += 1;
                }
                // Reference consumes exactly the mask word.
                Ok(c + 2)
            }
            _ => {
                // Draw / pipeline-state packets: length-skipped and
                // counted (no draw backend yet), first sighting logged.
                if seen_opcodes.insert(opcode) {
                    log::warn!("kernel: PM4 op {:02x} skipped (no draw backend)", opcode);
                }
                st.skipped_packets += 1;
                Ok(c + 1 + cnt)
            }
        }
    }
}

fn get(words: &[u32], i: usize) -> Result<u32> {
    words
        .get(i)
        .copied()
        .ok_or_else(|| EmuError::Other(format!("PM4 truncated at word {}", i)))
}

/// Reference `xenos::kTexture2DCubeMaxWidthHeight` (8192).
fn xenos_max_wh() -> u32 {
    8192
}

#[cfg(test)]
mod tests {
    use super::*;
    use x360_memory::Memory;

    fn kernel() -> Kernel {
        Kernel::new()
    }

    /// Type-3 header builder: (count-1) | opcode<<8, top bits 11.
    fn t3(op: u32, cnt: usize) -> u32 {
        0xC000_0000 | (((cnt - 1) as u32) << 16) | (op << 8)
    }

    #[test]
    fn mem_write_and_reg_roundtrip() {
        let mut k = kernel();
        let mut m = Memory::new();
        // Type-0 reg write, REG_RMW, REG_TO_MEM, MEM_WRITE.
        let words = vec![
            0x0000_0A31,
            0x0100_0000,                             // reg[0xA31] = 0x01000000
            (0xC000_0000 | (2 << 16) | (0x21 << 8)), // REG_RMW cnt 3
            0x0000_0A31,
            0xFFFF_FFFF,
            0x0000_0001,                             // reg |= 1
            (0xC000_0000 | (1 << 16) | (0x3E << 8)), // REG_TO_MEM cnt 2
            0x0000_0A31,
            0x0100_7000,                             // -> [0x01007000]
            (0xC000_0000 | (2 << 16) | (0x3D << 8)), // MEM_WRITE cnt 3
            0x0100_7010,
            0xDEAD_BEEF,
            0x1234_5678,
        ];
        let mut st = GpuExecStats::default();
        let mut seen = HashSet::new();
        k.gpu_exec_linear(&mut m, &words, 0, &mut st, &mut seen)
            .unwrap();
        assert_eq!(k.vd_regs.get(&0xA31), Some(&0x0100_0001));
        assert_eq!(m.read_u32(0x0100_7000).unwrap(), 0x0100_0001);
        assert_eq!(m.read_u32(0x0100_7010).unwrap(), 0xDEAD_BEEF);
        assert_eq!(m.read_u32(0x0100_7014).unwrap(), 0x1234_5678);
        assert_eq!(st.mem_writes, 3);
        let _ = t3(0x10, 1);
    }

    #[test]
    fn ib_nesting_and_wait() {
        let mut k = kernel();
        let mut m = Memory::new();
        // IB body at 0x01008000: WAIT on reg (satisfied) + MEM_WRITE.
        m.write_u32(0x0100_8000, 0xC004_3C00).unwrap(); // WAIT cnt 5
        m.write_u32(0x0100_8004, 0x0000_0003).unwrap(); // info: reg, == test
        m.write_u32(0x0100_8008, 0x0000_0A31).unwrap(); // reg 0xA31
        m.write_u32(0x0100_800C, 0x0100_0000).unwrap(); // ref
        m.write_u32(0x0100_8010, 0xFFFF_FFFF).unwrap(); // mask
        m.write_u32(0x0100_8014, 0x0000_0008).unwrap(); // wait iters (ignored)
        m.write_u32(0x0100_8018, 0xC001_3D00).unwrap(); // MEM_WRITE cnt 2
        m.write_u32(0x0100_801C, 0x0100_9000).unwrap();
        m.write_u32(0x0100_8020, 0x0000_00AB).unwrap();
        let words = vec![
            0x0000_0A31,
            0x0100_0000, // reg[0xA31] = ref (WAIT passes)
            0xC001_3F00,
            0x0100_8000,
            0x0000_0009, // IB len 9
        ];
        let mut st = GpuExecStats::default();
        let mut seen = HashSet::new();
        k.gpu_exec_linear(&mut m, &words, 0, &mut st, &mut seen)
            .unwrap();
        assert_eq!(st.ib_entered, 1);
        assert_eq!(m.read_u32(0x0100_9000).unwrap(), 0xAB);
    }

    #[test]
    fn wait_unsatisfied_is_explicit() {
        let mut k = kernel();
        let mut m = Memory::new();
        let words = vec![
            0xC004_3C00,
            0x0000_0003,
            0x0000_0A31,
            0x1111_1111,
            0xFFFF_FFFF,
            0x8,
        ];
        let mut st = GpuExecStats::default();
        let mut seen = HashSet::new();
        let e = k.gpu_exec_linear(&mut m, &words, 0, &mut st, &mut seen);
        assert!(e.is_err());
    }

    #[test]
    fn draws_skip_by_length() {
        let mut k = kernel();
        let mut m = Memory::new();
        // Unknown type-3 (e.g. draw 0x22) with 2 payload words.
        let words = vec![0xC001_2200, 0xAAAAAAAA, 0xBBBBBBBB, 0x0000_0A31, 0x42];
        let mut st = GpuExecStats::default();
        let mut seen = HashSet::new();
        k.gpu_exec_linear(&mut m, &words, 0, &mut st, &mut seen)
            .unwrap();
        assert_eq!(st.skipped_packets, 1);
        assert_eq!(k.vd_regs.get(&0xA31), Some(&0x42));
    }
}
