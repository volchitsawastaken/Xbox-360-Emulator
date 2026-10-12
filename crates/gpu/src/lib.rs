//! Xenos command processor and resource tracking.
//!
//! Pipeline: ringbuffer -> packet decode -> state -> resources -> wgpu.
//! Unsupported packets/shaders are explicit errors with diagnostics.
//! No draw is claimed without a real encoder (M5+).

use std::collections::HashMap;
use x360_common::{EmuError, Result};

pub mod validation;

/// Packet classes (PM4-style).
#[derive(Debug, Clone)]
pub enum Packet {
    Type0 { reg: u32, values: Vec<u32> },
    Type2 { nop_count: u32 },
    Type3 { opcode: u8, payload: Vec<u32> },
    Unknown { word: u32, offset: u32 },
}

#[derive(Debug, Default)]
pub struct GpuStats {
    pub decoded: u64,
    pub unsupported: u64,
    pub draws: u64,
    pub last_unsupported: Option<String>,
}

/// Minimal Xenos state.
pub struct Xenos {
    pub stats: GpuStats,
    /// Type0 register file (byte addr -> value). Real state application.
    pub regs: HashMap<u32, u32>,
    shader_cache: HashMap<u64, ShaderInfo>,
}

#[derive(Debug, Clone)]
pub struct ShaderInfo {
    pub hash: u64,
    pub size: usize,
    pub translated: bool,
}

impl Xenos {
    pub fn new() -> Self {
        Self {
            stats: GpuStats::default(),
            regs: HashMap::new(),
            shader_cache: HashMap::new(),
        }
    }

    /// Decode one packet from a real ringbuffer slice.
    /// `words[0]` is the header, following words are payload.
    /// Copies real payload values, never synthesizes zeros.
    pub fn decode_packet(&mut self, words: &[u32], offset: u32) -> Result<(Packet, usize)> {
        if words.is_empty() {
            return Err(EmuError::UnimplementedGpuPacket("empty ringbuffer".into()));
        }
        let word = words[0];
        let ptype = (word >> 30) & 0x3;
        match ptype {
            0 => {
                let count = (((word >> 16) & 0x3FFF) + 1) as usize;
                let reg = (word & 0xFFFF) * 4;
                if words.len() < 1 + count {
                    return Err(EmuError::UnimplementedGpuPacket(format!(
                        "type0 truncated: need {} have {}",
                        count,
                        words.len() - 1
                    )));
                }
                let values = words[1..1 + count].to_vec();
                self.stats.decoded += 1;
                Ok((Packet::Type0 { reg, values }, 1 + count))
            }
            2 => {
                self.stats.decoded += 1;
                Ok((
                    Packet::Type2 {
                        nop_count: word & 0x3FFF_FFFF,
                    },
                    1,
                ))
            }
            3 => {
                let opcode = ((word >> 8) & 0xFF) as u8;
                let count = (((word >> 16) & 0x3FFF) + 1) as usize;
                if words.len() < 1 + count {
                    return Err(EmuError::UnimplementedGpuPacket(format!(
                        "type3 truncated: need {} have {}",
                        count,
                        words.len() - 1
                    )));
                }
                let payload = words[1..1 + count].to_vec();
                self.stats.decoded += 1;
                Ok((Packet::Type3 { opcode, payload }, 1 + count))
            }
            _ => {
                let msg = format!("packet-type1 word={:08x} off={}", word, offset);
                self.stats.unsupported += 1;
                self.stats.last_unsupported = Some(msg.clone());
                Err(EmuError::UnimplementedGpuPacket(msg))
            }
        }
    }

    /// Legacy single-word decode (header only). Payload must follow via
    /// decode_packet for real use; this entry reports truncation explicitly.
    pub fn decode_header(&mut self, word: u32, offset: u32) -> Result<Packet> {
        let ptype = (word >> 30) & 0x3;
        match ptype {
            0 | 3 => Err(EmuError::UnimplementedGpuPacket(format!(
                "header-only decode needs payload word={:08x} off={} (use decode_packet)",
                word, offset
            ))),
            2 => {
                self.stats.decoded += 1;
                Ok(Packet::Type2 {
                    nop_count: word & 0x3FFF_FFFF,
                })
            }
            _ => {
                let msg = format!("packet-type1 word={:08x} off={}", word, offset);
                self.stats.unsupported += 1;
                self.stats.last_unsupported = Some(msg.clone());
                Err(EmuError::UnimplementedGpuPacket(msg))
            }
        }
    }

    /// Dispatch a decoded packet.
    /// - Type0 applies register state (real work).
    /// - Type2 nop succeeds.
    /// - Type3 always reports pending-M5 until a real wgpu encoder exists.
    pub fn dispatch(&mut self, p: &Packet) -> Result<()> {
        match p {
            Packet::Type0 { reg, values } => {
                for (i, v) in values.iter().enumerate() {
                    self.regs.insert(reg + i as u32 * 4, *v);
                }
                Ok(())
            }
            Packet::Type2 { .. } => Ok(()),
            Packet::Type3 { opcode, payload } => {
                let msg = format!(
                    "type3 opcode={:02x} len={} pending-M5 (no encoder yet)",
                    opcode,
                    payload.len()
                );
                self.stats.unsupported += 1;
                self.stats.last_unsupported = Some(msg.clone());
                Err(EmuError::UnimplementedGpuPacket(msg))
            }
            Packet::Unknown { word, offset } => Err(EmuError::UnimplementedGpuPacket(format!(
                "unknown {:08x} @{}",
                word, offset
            ))),
        }
    }

    /// Register a guest shader by hash. Translation deferred to M5+.
    pub fn register_shader(&mut self, hash: u64, bytes: &[u8]) -> Result<()> {
        if bytes.is_empty() {
            return Err(EmuError::UnimplementedShader {
                hash,
                reason: "empty microcode".into(),
            });
        }
        self.shader_cache.insert(
            hash,
            ShaderInfo {
                hash,
                size: bytes.len(),
                translated: false,
            },
        );
        log::warn!(
            "gpu: shader {:016x} ({}b) cached, translation pending",
            hash,
            bytes.len()
        );
        Err(EmuError::UnimplementedShader {
            hash,
            reason: "translation not implemented yet (M5)".into(),
        })
    }

    /// Host adapter enumeration for diagnostics (wgpu).
    pub fn list_adapters() -> Vec<String> {
        let instance = wgpu::Instance::new(wgpu::InstanceDescriptor::default());
        let adapters = instance.enumerate_adapters(wgpu::Backends::all());
        adapters
            .iter()
            .map(|a| {
                let info = a.get_info();
                format!("{} ({:?}/{:?})", info.name, info.backend, info.device_type)
            })
            .collect()
    }

    /// M5 validation: host triangle through the real encoder.
    /// `Ok(true)` = red pixels read back; `Ok(false)` = no adapter, skip.
    pub fn validate_triangle() -> Result<bool> {
        validation::validate_triangle()
    }
}

impl Default for Xenos {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn type0_applies_regs() {
        let mut g = Xenos::new();
        // type0 header: count=2 (stored count-1=1), reg=0x10
        let header = (1 << 16) | 0x10;
        let words = [header, 0xDEAD_BEEF, 0x1234_5678];
        let (p, used) = g.decode_packet(&words, 0).unwrap();
        assert_eq!(used, 3);
        g.dispatch(&p).unwrap();
        assert_eq!(g.regs.get(&0x40), Some(&0xDEAD_BEEF));
        assert_eq!(g.regs.get(&0x44), Some(&0x1234_5678));
    }
    #[test]
    fn header_only_reports_truncation() {
        let mut g = Xenos::new();
        let word = 0x10;
        assert!(g.decode_header(word, 0).is_err());
    }
    #[test]
    fn unknown_type1_is_error() {
        let mut g = Xenos::new();
        let word = 1u32 << 30;
        assert!(g.decode_header(word, 16).is_err());
    }
    #[test]
    fn type3_is_pending_not_draw() {
        let mut g = Xenos::new();
        let header = (3u32 << 30) | ((0x12u32) << 8);
        let words = [header, 0];
        let (p, _) = g.decode_packet(&words, 0).unwrap();
        assert!(g.dispatch(&p).is_err());
        assert_eq!(g.stats.draws, 0);
    }
    #[test]
    fn shader_registers_but_reports_pending() {
        let mut g = Xenos::new();
        let r = g.register_shader(0x1234, &[1, 2, 3, 4]);
        assert!(r.is_err());
    }

    #[test]
    fn validation_triangle_renders_or_skips() {
        // Passes when red pixels read back; also passes (skip) headless.
        let r = Xenos::validate_triangle();
        assert!(r.is_ok());
    }
}
