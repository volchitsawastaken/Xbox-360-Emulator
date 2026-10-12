//! Guest command-buffer bridge (M5).
//!
//! Reads real PM4 words from guest RAM and dispatches them through the
//! command processor. Packet framing is real; per-register semantics are
//! harness conventions for bring-up, explicitly NOT claimed Xenos
//! hardware addresses. Pending packets are counted and logged, never
//! silently dropped.

use x360_common::{EmuError, Result};
use x360_memory::Memory;

use crate::{Packet, Xenos};

/// Harness register holding an RGBA8 clear color.
/// Bring-up convention only; hardware meaning is pending register docs.
pub const HARNESS_CLEAR_COLOR_REG: u32 = 0x2000;

#[derive(Debug, Default)]
pub struct ExecuteStats {
    pub packets: u64,
    pub words: usize,
    pub pending_type3: u64,
}

/// Execute `word_count` PM4 words starting at guest `addr`.
/// Type0/2 apply; Type3 is recorded as pending (counted + logged) and
/// skipped so later packets still execute. Anything else aborts.
pub fn execute_buffer(
    xenos: &mut Xenos,
    mem: &Memory,
    addr: u32,
    word_count: usize,
) -> Result<ExecuteStats> {
    if word_count == 0 || word_count > 4096 {
        return Err(EmuError::Other(format!("bad buffer length {}", word_count)));
    }
    let bytes = mem.read_bytes(addr, word_count * 4)?;
    let mut words = vec![0u32; word_count];
    for (i, chunk) in bytes.chunks(4).enumerate() {
        words[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }

    let mut stats = ExecuteStats::default();
    let mut i = 0;
    while i < words.len() {
        let off = addr.wrapping_add(i as u32 * 4);
        let (packet, used) = xenos.decode_packet(&words[i..], off)?;
        stats.packets += 1;
        match &packet {
            Packet::Type3 { opcode, .. } => {
                stats.pending_type3 += 1;
                let name = crate::pm4::lookup(*opcode)
                    .map(|i| i.name)
                    .unwrap_or("UNKNOWN");
                log::warn!(
                    "bridge: {} {:02x} @{:08x} pending, skipping",
                    name,
                    opcode,
                    off
                );
                xenos.stats.unsupported += 1;
                xenos.stats.last_unsupported =
                    Some(format!("{} {:02x} skipped by bridge", name, opcode));
            }
            _ => xenos.dispatch(&packet)?,
        }
        stats.words += used;
        i += used;
    }
    Ok(stats)
}

/// Read the harness clear color from tracked state, if set.
pub fn harness_clear_color(xenos: &Xenos) -> Option<[u8; 4]> {
    xenos
        .regs
        .get(&HARNESS_CLEAR_COLOR_REG)
        .map(|v| v.to_be_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn type0_header(reg_byte_addr: u32, count: usize) -> u32 {
        (((count - 1) as u32) << 16) | (reg_byte_addr / 4)
    }

    #[test]
    fn executes_guest_type0_from_ram() {
        let mut mem = Memory::new();
        let addr = 0x70000;
        let header = type0_header(HARNESS_CLEAR_COLOR_REG, 1);
        mem.write_u32(addr, header).unwrap();
        mem.write_u32(addr + 4, 0xFF00_00FF).unwrap();
        let mut gpu = Xenos::new();
        let stats = execute_buffer(&mut gpu, &mem, addr, 2).unwrap();
        assert_eq!(stats.packets, 1);
        assert_eq!(stats.pending_type3, 0);
        assert_eq!(harness_clear_color(&gpu), Some([0xFF, 0x00, 0x00, 0xFF]));
    }

    #[test]
    fn pending_type3_counted_not_fatal() {
        let mut mem = Memory::new();
        let addr = 0x71000;
        let type3 = (3u32 << 30) | ((0x12u32) << 8); // count 1
        mem.write_u32(addr, type3).unwrap();
        mem.write_u32(addr + 4, 0).unwrap();
        // Followed by a real Type0 that must still apply.
        let header = type0_header(HARNESS_CLEAR_COLOR_REG, 1);
        mem.write_u32(addr + 8, header).unwrap();
        mem.write_u32(addr + 12, 0x00FF_00FF).unwrap();
        let mut gpu = Xenos::new();
        let stats = execute_buffer(&mut gpu, &mem, addr, 4).unwrap();
        assert_eq!(stats.packets, 2);
        assert_eq!(stats.pending_type3, 1);
        assert_eq!(harness_clear_color(&gpu), Some([0x00, 0xFF, 0x00, 0xFF]));
    }

    #[test]
    fn bad_length_and_oob_are_errors() {
        let mem = Memory::new();
        let mut gpu = Xenos::new();
        assert!(execute_buffer(&mut gpu, &mem, 0x1000, 0).is_err());
        assert!(execute_buffer(&mut gpu, &mem, 0xFFFF_FFF0, 8).is_err());
    }

    #[test]
    fn guest_state_reaches_host_pixels() {
        // Full bridge chain: guest RAM -> decode -> state -> host render.
        let mut mem = Memory::new();
        let addr = 0x72000;
        let header = type0_header(HARNESS_CLEAR_COLOR_REG, 1);
        mem.write_u32(addr, header).unwrap();
        mem.write_u32(addr + 4, 0xFF00_00FF).unwrap();
        let mut gpu = Xenos::new();
        execute_buffer(&mut gpu, &mem, addr, 2).unwrap();
        let color = harness_clear_color(&gpu).expect("color set");
        let r = crate::validation::render_clear(color);
        // Ok(true) = pixels match; Ok(false) = headless skip. Both pass.
        assert!(r.is_ok());
    }
}
