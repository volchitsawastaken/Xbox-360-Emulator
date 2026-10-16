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
//! Interrupts queue per set mask bit for boot-runner delivery.

use std::collections::HashSet;
use x360_common::{EmuError, Result};
use x360_memory::Memory;

use crate::uint::VertexFetchConst;
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
const OP_DRAW_INDX_2: u32 = 0x36;
const OP_IM_LOAD_IMMEDIATE: u32 = 0x2B;
const OP_INVALIDATE_STATE: u32 = 0x3B;
/// Xenia-only present hook (reference `xenos.h` `PM4_XE_SWAP` + `VdSwap`
/// posting to the GPU thread + `ExecutePacketType3_XE_SWAP`).
const OP_XE_SWAP: u32 = 0x64;
/// `XE_SWAP` magic (`make_fourcc("SWAP")`, reference `xenos.h`).
const SWAP_MAGIC: u32 = 0x5041_5753;

/// Register indices with executor-visible roles (reference
/// `register_table.inc`).
const REG_WRITEBACK_START: u32 = 0x0A04;
const REG_WRITEBACK_SIZE: u32 = 0x0A05;
const REG_VGT_EVENT_INITIATOR: u32 = 0x21F9;
const REG_RB_SAMPLE_COUNT_ADDR: u32 = 0x2325;
/// Shader float-constant vec4 base (512 entries, reference
/// `SHADER_CONSTANT_000_X` 0x4000).
pub const REG_SHADER_FLOAT_BASE: u32 = 0x4000;
/// Shader float-constant count.
pub const SHADER_FLOAT_COUNT: usize = 512;
/// Vertex-fetch constant pair base (2 dwords each, reference
/// `SHADER_CONSTANT_FETCH_00_0` 0x4800; vertex index n reads
/// regs base+2n/base+2n+1 per `GetVertexFetch`).
pub const REG_SHADER_FETCH_BASE: u32 = 0x4800;
/// Vertex-fetch constant count.
pub const SHADER_FETCH_COUNT: usize = 96;
/// Bool-constant base (2 dwords, reference
/// `SHADER_CONSTANT_BOOL_000_031` 0x4900).
pub const REG_SHADER_BOOL_BASE: u32 = 0x4900;
/// Loop-constant base (32 dwords, reference
/// `SHADER_CONSTANT_LOOP_00` 0x4908).
pub const REG_SHADER_LOOP_BASE: u32 = 0x4908;
/// Loop-constant count.
pub const SHADER_LOOP_COUNT: usize = 32;

/// VGT draw registers mirrored by draws (reference
/// `register_table.inc`).
const REG_VGT_DMA_BASE: u32 = 0x21FA;
const REG_VGT_DMA_SIZE: u32 = 0x21FB;
const REG_VGT_DRAW_INITIATOR: u32 = 0x21FC;

/// Render-surface registers (reference `register_table.inc`).
const REG_RB_SURFACE_INFO: u32 = 0x2000;
const REG_RB_COLOR_INFO: u32 = 0x2001;

/// Decoded color render surface (reference `RB_SURFACE_INFO` +
/// `RB_COLOR_INFO` bit layouts). Facts only; use sites validate
/// format/MSAA support explicitly.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RenderSurface {
    /// Surface pitch in pixels (`surface_pitch :14`).
    pub pitch_px: u32,
    /// MSAA level (`msaa_samples :2`: 0=1x, 1=2x, 2=4x).
    pub msaa: u32,
    /// EDRAM base in tiles (`color_base :11` + bit 11).
    pub base_tiles: u32,
    /// Color format (`color_format :4`, reference
    /// `ColorRenderTargetFormat`).
    pub color_format: u32,
}

impl RenderSurface {
    /// Pitch in 80-sample tiles (rounded up; a zero pixel pitch
    /// stays zero and use sites reject it).
    pub fn pitch_tiles(&self) -> u32 {
        self.pitch_px.div_ceil(EDRAM_TILE_W)
    }
}

/// Decoded draw descriptor (reference
/// `ExecutePacketType3Draw` + `VGT_DRAW_INITIATOR` bit layout:
/// prim_type :6, source_select :2, major_mode :2, index_size :1,
/// num_indices :16; `VGT_DMA_SIZE`: num_words :24, swap :2 at 30).
/// Execution is pending; the descriptor and the register mirror
/// are genuine state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DrawDesc {
    /// Primitive type (6 bits, reference `PrimitiveType`).
    pub prim_type: u32,
    /// Index source (0 DMA, 1 immediate, 2 auto-index).
    pub source: u32,
    /// True when the major-mode explicit bit is set (reference
    /// `IsMajorModeExplicit`; the primitive-forced case resolves
    /// at execution).
    pub major_explicit: bool,
    /// 32-bit indices (else 16-bit).
    pub index_32bit: bool,
    /// Index/vertex count.
    pub num_indices: u32,
    /// DMA base in dwords (`CpuToGpu`: masked to 29 bits, aligned
    /// down by index size; non-DMA draws use 0).
    pub dma_base_dwords: u32,
    /// DMA word count (0 for non-DMA draws).
    pub dma_num_words: u32,
    /// DMA endian swap mode (0-3).
    pub dma_endian: u32,
}

/// Primitive-type mnemonic (reference `PrimitiveType` names;
/// unknown values print raw, never fault).
pub fn prim_type_name(prim: u32) -> &'static str {
    match prim {
        0 => "none",
        1 => "pointlist",
        2 => "linelist",
        3 => "linestrip",
        4 => "trilist",
        5 => "trifan",
        6 => "tristrip",
        7 => "triwflags",
        8 => "rectlist",
        12 => "lineloop",
        _ => "prim?",
    }
}

/// Fetch draw indices from guest memory (reference
/// `primitive_processor.cc` index loading): DMA draws read
/// `num_indices` clamped to `dma_num_words`, endian-swapped per
/// lane width; auto-index draws yield `0..num_indices`;
/// immediate draws are an explicit error (reference `VGT_IMMED_DATA`
/// path is unimplemented there too).
pub fn fetch_draw_indices(mem: &Memory, desc: &DrawDesc) -> Result<Vec<u32>> {
    if desc.source == 2 {
        return Ok((0..desc.num_indices).collect());
    }
    if desc.source != 0 {
        return Err(EmuError::Unsupported(format!(
            "draw immediate source {} pending",
            desc.source
        )));
    }
    let n = desc.num_indices.min(desc.dma_num_words);
    let mut out = Vec::with_capacity(n as usize);
    for i in 0..n {
        if desc.index_32bit {
            let bytes = desc
                .dma_base_dwords
                .wrapping_mul(4)
                .wrapping_add(i.wrapping_mul(4));
            let w = mem
                .read_u32(bytes)
                .map_err(|e| EmuError::Other(format!("draw index {:08x}: {}", bytes, e)))?;
            out.push(gpu_swap(w, desc.dma_endian)?);
        } else {
            let byte = desc
                .dma_base_dwords
                .wrapping_mul(4)
                .wrapping_add(i.wrapping_mul(2));
            let half = (byte / 2) * 2;
            let w = mem
                .read_u32(half & !3)
                .map_err(|e| EmuError::Other(format!("draw index {:08x}: {}", half, e)))?;
            let w = gpu_swap(w, desc.dma_endian)?;
            out.push(if byte & 2 != 0 { w & 0xFFFF } else { w >> 16 });
        }
    }
    Ok(out)
}

/// Maximum IB nesting (reference recurses; real streams nest shallowly).
const MAX_IB_DEPTH: u32 = 8;
/// Runaway guard per pump call (packets, not steps).
const MAX_PACKETS: u64 = 1_000_000;

/// EDRAM size in bytes (reference `xenos.h`: `kEdramTileCount(2048)`
/// × `kEdramTileHeightSamples(16)` × `kEdramTileWidthSamples(80)` ×
/// 4 bytes = 10 MiB).
pub const EDRAM_SIZE: usize = 2048 * 16 * 80 * 4;
/// EDRAM tile width in 32bpp samples (reference `edram.xesli`).
pub const EDRAM_TILE_W: u32 = 80;
/// EDRAM tile height in 32bpp samples.
pub const EDRAM_TILE_H: u32 = 16;
/// EDRAM tile count.
pub const EDRAM_TILE_COUNT: u32 = 2048;

/// Tiled byte offset of pixel (`x`, `y`) for a 1x-MSAA 32bpp color
/// surface (reference `edram.xesli` `XeEdramOffsetBytes` with
/// single-sample, non-depth, `format_ints_log2 = 0`, scale 1).
/// `base_tiles`/`pitch_tiles` come from the surface registers;
/// addressing wraps modulo the EDRAM size like hardware.
pub fn edram_tile_offset_bytes(x: u32, y: u32, base_tiles: u32, pitch_tiles: u32) -> usize {
    let tx = (x / EDRAM_TILE_W) as u64;
    let ty = (y / EDRAM_TILE_H) as u64;
    let lx = (x % EDRAM_TILE_W) as u64;
    let ly = (y % EDRAM_TILE_H) as u64;
    let tile = base_tiles as u64 + ty * pitch_tiles as u64 + tx;
    let dwords = tile * (EDRAM_TILE_W as u64 * EDRAM_TILE_H as u64) + ly * EDRAM_TILE_W as u64 + lx;
    ((dwords % (EDRAM_SIZE as u64 / 4)) * 4) as usize
}

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
    /// `IM_LOAD_IMMEDIATE` shader uploads stored (vertex/pixel ucode).
    pub shaders_loaded: u64,
    /// `DRAW_INDX_2` packets seen (length-skipped; draw demand signal).
    pub draws_seen: u64,
    /// `INVALIDATE_STATE` packets consumed (reference no-op).
    pub invalidates: u64,
    /// `XE_SWAP` presents executed (EDRAM→DRAM resolve + vblank).
    pub swaps: u64,
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

/// Interpreter inputs collected from programmed GPU registers
/// (see [`Kernel::collect_shader_inputs`]).
#[derive(Debug, Clone)]
pub struct ShaderInputs {
    /// Float constants (512 vec4).
    pub floats: [[f32; 4]; SHADER_FLOAT_COUNT],
    /// Vertex-fetch constants (96 pairs).
    pub fetch: [VertexFetchConst; SHADER_FETCH_COUNT],
    /// Bool-constant bits (2 dwords).
    pub bools: [u32; 2],
    /// Loop constants (32 register words).
    pub loops: [u32; SHADER_LOOP_COUNT],
}

impl Kernel {
    /// Collect programmed shader inputs for the interpreter
    /// (reference `register_file.h` fetch/loop accessors +
    /// `shader_interpreter.cc` register reads): float constants
    /// (512 vec4 at 0x4000), vertex-fetch pairs (96 at 0x4800),
    /// bool bits (2 dwords at 0x4900), loop constants (32 at
    /// 0x4908). Unprogrammed registers read as zeros, matching the
    /// zeroed register file. Verified against retail: Braid programs
    /// none of these pre-device (42 control regs only), so this is
    /// draw-backend plumbing ahead of demand, unit-tested
    /// synthetically.
    pub fn collect_shader_inputs(&self) -> ShaderInputs {
        let mut floats = [[0.0f32; 4]; SHADER_FLOAT_COUNT];
        for (i, v) in floats.iter_mut().enumerate() {
            for (c, f) in v.iter_mut().enumerate() {
                *f = f32::from_bits(
                    self.vd_regs
                        .get(&(REG_SHADER_FLOAT_BASE + 4 * i as u32 + c as u32))
                        .copied()
                        .unwrap_or(0),
                );
            }
        }
        let mut fetch = [VertexFetchConst::default(); SHADER_FETCH_COUNT];
        for (i, f) in fetch.iter_mut().enumerate() {
            let w = [
                self.vd_regs
                    .get(&(REG_SHADER_FETCH_BASE + 2 * i as u32))
                    .copied()
                    .unwrap_or(0),
                self.vd_regs
                    .get(&(REG_SHADER_FETCH_BASE + 2 * i as u32 + 1))
                    .copied()
                    .unwrap_or(0),
            ];
            *f = VertexFetchConst::from_words(&w);
        }
        let mut bools = [0u32; 2];
        for (i, b) in bools.iter_mut().enumerate() {
            *b = self
                .vd_regs
                .get(&(REG_SHADER_BOOL_BASE + i as u32))
                .copied()
                .unwrap_or(0);
        }
        let mut loops = [0u32; SHADER_LOOP_COUNT];
        for (i, l) in loops.iter_mut().enumerate() {
            *l = self
                .vd_regs
                .get(&(REG_SHADER_LOOP_BASE + i as u32))
                .copied()
                .unwrap_or(0);
        }
        ShaderInputs {
            floats,
            fetch,
            bools,
            loops,
        }
    }

    /// Decode the programmed color render surface (reference
    /// `RB_SURFACE_INFO` pitch/MSAA + `RB_COLOR_INFO` base/format).
    /// Unprogrammed registers decode as zeros (base 0, pitch 0,
    /// 1x MSAA, `k_8_8_8_8`); use sites validate support.
    pub fn collect_render_surface(&self) -> RenderSurface {
        let info = self.vd_regs.get(&REG_RB_SURFACE_INFO).copied().unwrap_or(0);
        let color = self.vd_regs.get(&REG_RB_COLOR_INFO).copied().unwrap_or(0);
        RenderSurface {
            pitch_px: info & 0x3FFF,
            msaa: (info >> 16) & 3,
            base_tiles: (color & 0x7FF) | (((color >> 11) & 1) << 11),
            color_format: (color >> 16) & 0xF,
        }
    }

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
                let mask = p(0);
                if mask != 0 {
                    // Reference `ExecutePacketType3_INTERRUPT` dispatches
                    // per set bit: `DispatchInterruptCallback(1, n)`.
                    // Queue (source=1, cpu=n) for boot-runner delivery;
                    // the packet itself consumes exactly the mask word.
                    for n in 0..6u32 {
                        if mask & (1 << n) != 0 {
                            self.vd_irq_pending.push_back((1, n));
                            st.interrupts += 1;
                        }
                    }
                    // Non-low-6 bits (if any) are still genuine
                    // interrupts; queue them too rather than dropping.
                    let extra = mask & !0x3F;
                    if extra != 0 {
                        for n in 6..32u32 {
                            if mask & (1 << n) != 0 {
                                self.vd_irq_pending.push_back((1, n));
                                st.interrupts += 1;
                            }
                        }
                    }
                }
                // Reference consumes exactly the mask word.
                Ok(c + 2)
            }
            OP_IM_LOAD_IMMEDIATE => {
                // Sequencer ucode upload (reference
                // `ExecutePacketType3_IM_LOAD_IMMEDIATE`): `[type,
                // start_size, ucode...]`, `start = size >> 16` (must be
                // 0), `size = size & 0xFFFF` dwords. Stores the ucode
                // per shader type (active shader); translation to host
                // GPU is pending draw-backend work, but the upload
                // itself is real state. Consumes exactly like the
                // reference (header + 2 + size); trailing zero pad (if
                // any) parses as skips, matching the reference reader.
                if cnt < 2 {
                    return Err(EmuError::Other("PM4 short IM_LOAD_IMMEDIATE".into()));
                }
                let shader_type = p(0);
                let start_size = p(1);
                let start = start_size >> 16;
                let size = (start_size & 0xFFFF) as usize;
                if start != 0 {
                    return Err(EmuError::Unsupported(format!(
                        "PM4 IM_LOAD nonzero start {:08x}",
                        start
                    )));
                }
                if shader_type > 1 {
                    return Err(EmuError::Unsupported(format!(
                        "PM4 IM_LOAD bad shader type {}",
                        shader_type
                    )));
                }
                if cnt - 2 < size {
                    return Err(EmuError::Other(format!(
                        "PM4 IM_LOAD size {} exceeds cnt {}",
                        size, cnt
                    )));
                }
                let mut ucode = Vec::with_capacity(size);
                for k in 0..size {
                    ucode.push(p(2 + k));
                }
                // Structural check only (storage is unconditional):
                // valid uploads log their census plus a full listing
                // for offline forensics, malformed ones warn loudly
                // but still store exactly what the game sent.
                match crate::ucode::validate_ucode(&ucode) {
                    Ok(st) => {
                        log::debug!(
                            "kernel: IM_LOAD type {} size {}: {:?}",
                            shader_type,
                            size,
                            st
                        );
                        if log::log_enabled!(log::Level::Debug) {
                            if let Ok(lines) =
                                crate::ucode::disassemble_shader(&ucode, shader_type == 0)
                            {
                                for line in lines {
                                    log::debug!("kernel: ucode {}", line);
                                }
                            }
                        }
                    }
                    Err(e) => log::warn!(
                        "kernel: IM_LOAD type {} size {} invalid: {}",
                        shader_type,
                        size,
                        e
                    ),
                }
                if shader_type == 0 {
                    self.vd_vs_ucode = ucode;
                } else {
                    self.vd_ps_ucode = ucode;
                }
                st.shaders_loaded += 1;
                Ok(c + 1 + 2 + size)
            }
            OP_INVALIDATE_STATE => {
                // Selective state-pointer invalidation (reference
                // `ExecutePacketType3_INVALIDATE_STATE`): reads the
                // mask and does nothing (driver call commented out).
                // Faithful no-op: consume exactly the mask word.
                if cnt < 1 {
                    return Err(EmuError::Other("PM4 short INVALIDATE_STATE".into()));
                }
                let _mask = p(0);
                st.invalidates += 1;
                Ok(c + 2)
            }
            OP_XE_SWAP => {
                // Present hook (reference
                // `ExecutePacketType3_XE_SWAP` + `IssueSwap`): `[magic
                // "SWAP", frontbuffer_phys, width, height]`; trailing
                // pad words (reference `AdvanceRead(count - 4)`) are
                // consumed as filler. Resolves solid-cleared EDRAM to
                // the frontbuffer (see `edram_resolve`; patterned
                // content needs detiling, pending), counts the swap,
                // and queues the vblank interrupt `(0, 2)` exactly like
                // the reference `MarkVblank` path. Consumes the whole
                // packet like every other arm.
                if cnt < 4 {
                    return Err(EmuError::Other("PM4 short XE_SWAP".into()));
                }
                if p(0) != SWAP_MAGIC {
                    return Err(EmuError::Other(format!(
                        "PM4 XE_SWAP bad magic {:08x}",
                        p(0)
                    )));
                }
                let (fb, w, h) = (p(1), p(2), p(3));
                if w == 0 || h == 0 || w > xenos_max_wh() || h > xenos_max_wh() {
                    return Err(EmuError::Other(format!("PM4 XE_SWAP bad size {}x{}", w, h)));
                }
                let size = (w as u64)
                    .checked_mul(h as u64)
                    .and_then(|n| n.checked_mul(4))
                    .ok_or_else(|| EmuError::Other("PM4 XE_SWAP size overflows".into()))?;
                if size > EDRAM_SIZE as u64 {
                    return Err(EmuError::Other(format!(
                        "PM4 XE_SWAP {}x{} exceeds EDRAM",
                        w, h
                    )));
                }
                self.edram_resolve(mem, fb, size as usize)?;
                st.swaps += 1;
                self.vd_irq_pending.push_back((0, 2));
                st.interrupts += 1;
                Ok(c + 1 + cnt)
            }
            OP_DRAW_INDX_2 => {
                // Indexed draw descriptor (reference
                // `ExecutePacketType3_DRAW_INDX_2` → `ExecutePacketType3Draw`
                // with no viz token): `[VGT_DRAW_INITIATOR, ...]`.
                // Decode + mirror + record (genuine CPU-visible
                // state); execution is still pending, counted in
                // `draws_seen` like before.
                if cnt < 1 {
                    return Err(EmuError::Other("PM4 short DRAW_INDX_2".into()));
                }
                let initiator = p(0);
                self.vd_regs.insert(REG_VGT_DRAW_INITIATOR, initiator);
                let source = (initiator >> 6) & 3;
                let index_32bit = (initiator >> 11) & 1 != 0;
                let mut desc = DrawDesc {
                    prim_type: initiator & 0x3F,
                    source,
                    major_explicit: (initiator >> 8) & 3 != 0,
                    index_32bit,
                    num_indices: (initiator >> 16) & 0xFFFF,
                    ..DrawDesc::default()
                };
                if source == 0 {
                    // DMA-indexed: two more words or an explicit
                    // truncation error (reference returns false).
                    if cnt < 3 {
                        return Err(EmuError::Other(
                            "PM4 DRAW_INDX_2 short DMA base/size".into(),
                        ));
                    }
                    // `CpuToGpu`: mask to 29 bits (dword-mapped
                    // writeback/XPS window wraps in the translators).
                    let base = p(1) & 0x1FFF_FFFF;
                    let size = p(2);
                    self.vd_regs.insert(REG_VGT_DMA_BASE, base);
                    self.vd_regs.insert(REG_VGT_DMA_SIZE, size);
                    let align = if index_32bit { 4 } else { 2 };
                    desc.dma_base_dwords = base & !(align - 1);
                    desc.dma_num_words = size & 0xFF_FFFF;
                    desc.dma_endian = (size >> 30) & 3;
                }
                if seen_opcodes.insert(opcode) {
                    log::info!(
                        "kernel: PM4 DRAW_INDX_2 {} x{} ({}pending execution)",
                        prim_type_name(desc.prim_type),
                        desc.num_indices,
                        if source == 0 { "dma, " } else { "" }
                    );
                }
                self.vd_draws.push(desc);
                st.draws_seen += 1;
                Ok(c + 1 + cnt)
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

impl Kernel {
    /// Fill EDRAM with a solid 32bpp value (PPC byte order per unit;
    /// reference clear values come from `RB_COLOR_CLEAR`). Exact for
    /// solid fills regardless of tiling (every sample identical);
    /// patterned content needs the tiled layout (pending).
    pub fn edram_clear_32bpp(&mut self, color: u32) {
        let b = color.to_be_bytes();
        let mut i = 0;
        while i + 4 <= self.vd_edram.len() {
            self.vd_edram[i..i + 4].copy_from_slice(&b);
            i += 4;
        }
    }

    /// Resolve the first `size` EDRAM bytes linearly to guest `dest`
    /// (reference resolve copies EDRAM→DRAM; the tiled→linear detile
    /// is an identity for solid fills, which is all EDRAM can hold
    /// until draws land). Out-of-range dest/size are explicit errors.
    pub fn edram_resolve(&self, mem: &mut Memory, dest: u32, size: usize) -> Result<()> {
        if size > EDRAM_SIZE {
            return Err(EmuError::Other(format!(
                "resolve size {} exceeds EDRAM {}",
                size, EDRAM_SIZE
            )));
        }
        if size == 0 {
            return Ok(());
        }
        let src = &self.vd_edram[..size];
        mem.write_bytes(dest, src)
            .map_err(|e| EmuError::Other(format!("resolve dest {:08x}: {}", dest, e)))?;
        Ok(())
    }

    /// Write one 32bpp pixel through the tiled layout (PPC byte
    /// order per unit). Out-of-tile-grid writes are explicit errors
    /// (no silent wrap: resolve callers must size surfaces
    /// correctly).
    pub fn edram_write_pixel_32bpp(
        &mut self,
        x: u32,
        y: u32,
        base_tiles: u32,
        pitch_tiles: u32,
        color: u32,
    ) -> Result<()> {
        let off = edram_tile_offset_bytes(x, y, base_tiles, pitch_tiles);
        if off + 4 > self.vd_edram.len() {
            return Err(EmuError::Other(format!(
                "tiled pixel {},{} base {} pitch {} out of EDRAM",
                x, y, base_tiles, pitch_tiles
            )));
        }
        self.vd_edram[off..off + 4].copy_from_slice(&color.to_be_bytes());
        Ok(())
    }

    /// Detiled resolve of a `w`×`h` 32bpp surface to guest `dest`
    /// in row-major order (reference resolve with the tiled layout
    /// applied). Pitch must cover the width
    /// (`pitch_tiles * 80 >= w`); violations are explicit errors.
    pub fn edram_resolve_tiled(
        &self,
        mem: &mut Memory,
        dest: u32,
        w: u32,
        h: u32,
        base_tiles: u32,
        pitch_tiles: u32,
    ) -> Result<()> {
        if w == 0 || h == 0 {
            return Ok(());
        }
        if (pitch_tiles as u64) * u64::from(EDRAM_TILE_W) < u64::from(w) {
            return Err(EmuError::Other(format!(
                "tiled resolve {}x{} exceeds pitch {} tiles",
                w, h, pitch_tiles
            )));
        }
        let size = (w as u64)
            .checked_mul(h as u64)
            .and_then(|n| n.checked_mul(4))
            .ok_or_else(|| EmuError::Other("tiled resolve size overflows".into()))?;
        if size > EDRAM_SIZE as u64 {
            return Err(EmuError::Other(format!(
                "tiled resolve {}x{} exceeds EDRAM",
                w, h
            )));
        }
        let mut out = Vec::with_capacity(size as usize);
        for y in 0..h {
            for x in 0..w {
                let off = edram_tile_offset_bytes(x, y, base_tiles, pitch_tiles);
                if off + 4 > self.vd_edram.len() {
                    return Err(EmuError::Other(format!(
                        "tiled resolve pixel {},{} out of EDRAM",
                        x, y
                    )));
                }
                out.extend_from_slice(&self.vd_edram[off..off + 4]);
            }
        }
        mem.write_bytes(dest, &out)
            .map_err(|e| EmuError::Other(format!("tiled resolve dest {:08x}: {}", dest, e)))?;
        Ok(())
    }
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
    fn shader_inputs_collect_from_regs() {
        let mut k = kernel();
        // Float const 3 = [1, 2, 3, 4]; fetch const 5 = base/size;
        // bool1 bit 5; loop 0 = count 3.
        for (c, f) in [1.0f32, 2.0, 3.0, 4.0].iter().enumerate() {
            k.vd_regs
                .insert(REG_SHADER_FLOAT_BASE + 4 * 3 + c as u32, f.to_bits());
        }
        k.vd_regs.insert(REG_SHADER_FETCH_BASE + 2 * 5, 0x400 << 2);
        k.vd_regs
            .insert(REG_SHADER_FETCH_BASE + 2 * 5 + 1, (16 << 2) | 2);
        k.vd_regs.insert(REG_SHADER_BOOL_BASE + 1, 1 << 5);
        k.vd_regs.insert(REG_SHADER_LOOP_BASE, 3);
        let si = k.collect_shader_inputs();
        assert_eq!(si.floats[3], [1.0, 2.0, 3.0, 4.0]);
        assert_eq!(si.floats[4], [0.0; 4]);
        assert_eq!(
            (
                si.fetch[5].address_dwords,
                si.fetch[5].size_dwords,
                si.fetch[5].endian
            ),
            (0x400, 16, 2)
        );
        assert_eq!(si.fetch[6].address_dwords, 0);
        assert_eq!(si.bools, [0, 1 << 5]);
        assert_eq!(si.loops[0], 3);
        assert_eq!(si.loops[1], 0);
        // Empty register file collects zeros.
        let si = kernel().collect_shader_inputs();
        assert_eq!(si.floats[0], [0.0; 4]);
        assert_eq!(si.bools, [0, 0]);
    }

    #[test]
    fn render_surface_decodes_regs() {
        let mut k = kernel();
        // Pitch 1280px, 4x MSAA; base tiles 0xABC, format 0.
        k.vd_regs.insert(0x2000, 1280 | (2 << 16));
        k.vd_regs.insert(0x2001, 0xABC);
        let s = k.collect_render_surface();
        assert_eq!(
            (s.pitch_px, s.msaa, s.base_tiles, s.color_format),
            (1280, 2, 0xABC, 0)
        );
        assert_eq!(s.pitch_tiles(), 16);
        // Zero regs decode as the default surface.
        let s = kernel().collect_render_surface();
        assert_eq!((s.pitch_px, s.base_tiles), (0, 0));
        assert_eq!(s.pitch_tiles(), 0);
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

    #[test]
    fn interrupt_queues_per_set_bit() {
        let mut k = kernel();
        let mut m = Memory::new();
        // INTERRUPT cnt 1, mask bits 0 and 2.
        let words = vec![0xC000_5400, 0x0000_0005];
        let mut st = GpuExecStats::default();
        let mut seen = HashSet::new();
        k.gpu_exec_linear(&mut m, &words, 0, &mut st, &mut seen)
            .unwrap();
        assert_eq!(st.interrupts, 2);
        assert_eq!(k.vd_irq_pending.len(), 2);
        assert_eq!(k.vd_irq_pending[0], (1, 0));
        assert_eq!(k.vd_irq_pending[1], (1, 2));
        // Zero mask queues nothing.
        let words = vec![0xC000_5400, 0x0000_0000];
        let mut st = GpuExecStats::default();
        let mut seen = HashSet::new();
        k.gpu_exec_linear(&mut m, &words, 0, &mut st, &mut seen)
            .unwrap();
        assert_eq!(st.interrupts, 0);
        assert_eq!(k.vd_irq_pending.len(), 2);
    }

    #[test]
    fn im_load_stores_ucode_per_type() {
        let mut k = kernel();
        let mut m = Memory::new();
        // IM_LOAD_IMMEDIATE cnt 5: type=1 (pixel), start=0, size=3.
        let words = vec![
            0xC004_2B00,
            0x0000_0001,
            0x0000_0003,
            0xAAAAAAAA,
            0xBBBBBBBB,
            0xCCCCCCCC,
        ];
        let mut st = GpuExecStats::default();
        let mut seen = HashSet::new();
        k.gpu_exec_linear(&mut m, &words, 0, &mut st, &mut seen)
            .unwrap();
        assert_eq!(st.shaders_loaded, 1);
        assert_eq!(k.vd_ps_ucode, vec![0xAAAAAAAA, 0xBBBBBBBB, 0xCCCCCCCC]);
        assert!(k.vd_vs_ucode.is_empty());
        // Vertex upload replaces (active-shader semantics).
        let words = vec![
            0xC003_2B00,
            0x0000_0000,
            0x0000_0002,
            0x11111111,
            0x22222222,
        ];
        let mut st = GpuExecStats::default();
        let mut seen = HashSet::new();
        k.gpu_exec_linear(&mut m, &words, 0, &mut st, &mut seen)
            .unwrap();
        assert_eq!(k.vd_vs_ucode, vec![0x11111111, 0x22222222]);
        // Nonzero start is explicit Unsupported, never silently stored.
        let words = vec![
            0xC003_2B00,
            0x0000_0000,
            0x0001_0002,
            0x11111111,
            0x22222222,
        ];
        let mut st = GpuExecStats::default();
        let mut seen = HashSet::new();
        let e = k.gpu_exec_linear(&mut m, &words, 0, &mut st, &mut seen);
        assert!(e.is_err());
        // Bad shader type likewise explicit.
        let words = vec![
            0xC003_2B00,
            0x0000_0007,
            0x0000_0002,
            0x11111111,
            0x22222222,
        ];
        let mut st = GpuExecStats::default();
        let mut seen = HashSet::new();
        assert!(k
            .gpu_exec_linear(&mut m, &words, 0, &mut st, &mut seen)
            .is_err());
    }

    #[test]
    fn invalidate_is_noop_draws_count() {
        let mut k = kernel();
        let mut m = Memory::new();
        // INVALIDATE_STATE cnt 1 + DRAW_INDX_2 cnt 2 (length-skipped).
        let words = vec![
            0xC000_3B00,
            0x0000_FFFF,
            0xC001_3600,
            0xAAAAAAAA,
            0xBBBBBBBB,
        ];
        let mut st = GpuExecStats::default();
        let mut seen = HashSet::new();
        k.gpu_exec_linear(&mut m, &words, 0, &mut st, &mut seen)
            .unwrap();
        assert_eq!(st.invalidates, 1);
        assert_eq!(st.draws_seen, 1);
        assert_eq!(st.skipped_packets, 0);
    }

    #[test]
    fn draw_indx2_decodes_and_mirrors() {
        let mut k = kernel();
        let mut m = Memory::new();
        // DMA trilist, 32-bit indices, 6 indices; base odd aligns
        // down, endian 3, 9 words.
        let initiator = 4 | (1 << 11) | (6 << 16);
        let words = vec![0xC002_3600, initiator, 0x0100_8001, (3 << 30) | 9];
        let mut st = GpuExecStats::default();
        let mut seen = HashSet::new();
        k.gpu_exec_linear(&mut m, &words, 0, &mut st, &mut seen)
            .unwrap();
        assert_eq!(st.draws_seen, 1);
        assert_eq!(k.vd_draws.len(), 1);
        assert_eq!(
            k.vd_draws[0],
            DrawDesc {
                prim_type: 4,
                source: 0,
                major_explicit: false,
                index_32bit: true,
                num_indices: 6,
                dma_base_dwords: 0x0100_8000,
                dma_num_words: 9,
                dma_endian: 3,
            }
        );
        assert_eq!(k.vd_regs.get(&0x21FC), Some(&initiator));
        assert_eq!(k.vd_regs.get(&0x21FA), Some(&0x0100_8001));
        // Auto-index draw needs no DMA words.
        let words = vec![0xC000_3600, 4 | (2 << 6) | (3 << 16)];
        let mut st = GpuExecStats::default();
        let mut seen = HashSet::new();
        k.gpu_exec_linear(&mut m, &words, 0, &mut st, &mut seen)
            .unwrap();
        assert_eq!(k.vd_draws.len(), 2);
        assert_eq!(k.vd_draws[1].source, 2);
        assert_eq!(k.vd_draws[1].dma_num_words, 0);
        assert_eq!(prim_type_name(4), "trilist");
        assert_eq!(prim_type_name(42), "prim?");
        // Truncated packets are explicit errors, never partial draws.
        let mut st = GpuExecStats::default();
        let mut seen = HashSet::new();
        assert!(k
            .gpu_exec_linear(&mut m, &[0xC000_3600], 0, &mut st, &mut seen)
            .is_err());
        assert_eq!(k.vd_draws.len(), 2);
    }

    #[test]
    fn draw_indices_fetch_from_memory() {
        let mut m = Memory::new();
        // Auto-index yields 0..n without touching memory.
        let auto = DrawDesc {
            source: 2,
            num_indices: 3,
            ..DrawDesc::default()
        };
        assert_eq!(fetch_draw_indices(&m, &auto).unwrap(), vec![0, 1, 2]);
        // Immediate source stays explicit.
        let imm = DrawDesc {
            source: 1,
            ..DrawDesc::default()
        };
        assert!(fetch_draw_indices(&m, &imm).is_err());
        // 32-bit DMA, clamped to the word count.
        m.write_u32(0x0100_9000, 7).unwrap();
        m.write_u32(0x0100_9004, 9).unwrap();
        m.write_u32(0x0100_9008, 11).unwrap();
        let dma32 = DrawDesc {
            source: 0,
            index_32bit: true,
            num_indices: 5,
            dma_base_dwords: 0x0100_9000 / 4,
            dma_num_words: 3,
            ..DrawDesc::default()
        };
        assert_eq!(fetch_draw_indices(&m, &dma32).unwrap(), vec![7, 9, 11]);
        // 16-bit DMA halves in BE order.
        m.write_u32(0x0100_9100, 0x0001_0002).unwrap();
        m.write_u32(0x0100_9104, 0x0003_0004).unwrap();
        let dma16 = DrawDesc {
            source: 0,
            num_indices: 4,
            dma_base_dwords: 0x0100_9100 / 4,
            dma_num_words: 4,
            ..DrawDesc::default()
        };
        assert_eq!(fetch_draw_indices(&m, &dma16).unwrap(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn edram_clear_resolve_roundtrip() {
        assert_eq!(EDRAM_SIZE, 10 * 1024 * 1024);
        let mut k = kernel();
        let mut m = Memory::new();
        // Power-on state resolves as zeros.
        k.edram_resolve(&mut m, 0x0100_A000, 16).unwrap();
        assert_eq!(m.read_u32(0x0100_A000).unwrap(), 0);
        // Solid clear lands in DRAM byte-exact (PPC order per unit).
        k.edram_clear_32bpp(0xFF00_00FF);
        assert_eq!(
            &k.vd_edram[..8],
            &[0xFF, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0xFF]
        );
        k.edram_resolve(&mut m, 0x0100_A000, 8).unwrap();
        assert_eq!(m.read_u32(0x0100_A000).unwrap(), 0xFF00_00FF);
        assert_eq!(m.read_u32(0x0100_A004).unwrap(), 0xFF00_00FF);
        // Zero-size resolve is a no-op success.
        k.edram_resolve(&mut m, 0x0100_A000, 0).unwrap();
        // Oversize and OOB dest are explicit errors.
        assert!(k
            .edram_resolve(&mut m, 0x0100_A000, EDRAM_SIZE + 4)
            .is_err());
        assert!(k.edram_resolve(&mut m, 0xFFFF_FFF0, 16).is_err());
    }

    #[test]
    fn edram_tiled_offsets_and_detile() {
        // Reference layout spot checks (1x 32bpp, pitch 16 tiles).
        assert_eq!(edram_tile_offset_bytes(0, 0, 0, 16), 0);
        assert_eq!(edram_tile_offset_bytes(79, 0, 0, 16), 79 * 4);
        assert_eq!(edram_tile_offset_bytes(80, 0, 0, 16), 1280 * 4);
        assert_eq!(edram_tile_offset_bytes(0, 16, 0, 16), 16 * 1280 * 4);
        assert_eq!(edram_tile_offset_bytes(0, 0, 5, 16), 5 * 1280 * 4);
        assert_eq!(
            edram_tile_offset_bytes(159, 31, 0, 16),
            (17 * 1280 + 15 * 80 + 79) * 4
        );
        // Patterned roundtrip: 160x32 gradient detiles row-major.
        let mut k = kernel();
        let mut m = Memory::new();
        for y in 0..32u32 {
            for x in 0..160u32 {
                k.edram_write_pixel_32bpp(x, y, 0, 2, x * 0x10000 + y)
                    .unwrap();
            }
        }
        k.edram_resolve_tiled(&mut m, 0x0100_A000, 160, 32, 0, 2)
            .unwrap();
        assert_eq!(m.read_u32(0x0100_A000).unwrap(), 0x0000_0000);
        assert_eq!(m.read_u32(0x0100_A000 + 4 * 159).unwrap(), 159 * 0x10000);
        assert_eq!(
            m.read_u32(0x0100_A000 + 4 * (31 * 160 + 159)).unwrap(),
            159 * 0x10000 + 31
        );
        // Linear resolve of the same bytes is NOT row-major (tiling
        // is real: raw EDRAM at linear dword 80 holds pixel (0,1),
        // not pixel (80,0)).
        assert_eq!(
            u32::from_be_bytes(k.vd_edram[320..324].try_into().unwrap()),
            1
        );
        // Narrow pitch and zero-size edges.
        assert!(k
            .edram_resolve_tiled(&mut m, 0x0100_A000, 160, 32, 0, 1)
            .is_err());
        k.edram_resolve_tiled(&mut m, 0x0100_A000, 0, 32, 0, 2)
            .unwrap();
    }

    #[test]
    fn xe_swap_flows_through_pump() {
        use x360_memory::MMIO_BASE;
        let mut k = kernel();
        let mut m = Memory::new();
        // In-ring present exactly like the reference: VdSwap fills
        // 64 words at the ring head, the kick retires them, the
        // frontbuffer resolves and vblank queues.
        let ring = 0x0110_0000;
        k.vd_ring = Some((ring, 20));
        let fb = 0x0116_0000u32;
        let mut seq = vec![
            ((6 - 1) << 16) | 0x1200,
            0,
            0,
            0,
            0,
            0,
            0,
            (3 << 30) | (((4 - 1) & 0x3FFF) << 16) | ((0x64 & 0x7F) << 8),
            SWAP_MAGIC,
            fb,
            64,
            64,
        ];
        seq.extend(std::iter::repeat_n(0x8000_0000, 64 - seq.len()));
        for (i, w) in seq.iter().enumerate() {
            m.write_u32(ring + i as u32 * 4, *w).unwrap();
        }
        k.edram_clear_32bpp(0xFF00_00FF);
        m.write_u32(MMIO_BASE + 0x01C5 * 4, 64).unwrap();
        k.pump_gpu(&mut m).unwrap();
        assert_eq!((k.vd_wptr_seen, k.vd_rptr), (64, 64));
        assert_eq!(m.read_u32(fb).unwrap(), 0xFF00_00FF);
        assert_eq!(k.vd_irq_pending.len(), 1);
        assert_eq!(k.vd_irq_pending[0], (0, 2));
    }

    #[test]
    fn xe_swap_resolves_and_vblanks() {
        let mut k = kernel();
        let mut m = Memory::new();
        let fb = 0x0116_0000;
        k.edram_clear_32bpp(0xFF00_00FF);
        // XE_SWAP cnt 4: [magic, fb, w, h] + 2 NOP-pad words (cnt 6).
        let words = vec![
            0xC005_6400,
            SWAP_MAGIC,
            fb,
            64,
            64,
            0x8000_0000,
            0x8000_0000,
        ];
        let mut st = GpuExecStats::default();
        let mut seen = HashSet::new();
        k.gpu_exec_linear(&mut m, &words, 0, &mut st, &mut seen)
            .unwrap();
        assert_eq!(st.swaps, 1);
        assert_eq!(st.interrupts, 1);
        assert_eq!(m.read_u32(fb).unwrap(), 0xFF00_00FF);
        assert_eq!(m.read_u32(fb + 64 * 64 * 4 - 4).unwrap(), 0xFF00_00FF);
        assert_eq!(k.vd_irq_pending.len(), 1);
        assert_eq!(k.vd_irq_pending[0], (0, 2));
        // Bad magic, zero size, and short packets are explicit errors.
        for bad in [
            vec![0xC003_6400, 0xDEAD_BEEF, fb, 64, 64],
            vec![0xC003_6400, SWAP_MAGIC, fb, 0, 64],
            vec![0xC001_6400, SWAP_MAGIC, fb],
        ] {
            let mut st = GpuExecStats::default();
            let mut seen = HashSet::new();
            assert!(k
                .gpu_exec_linear(&mut m, &bad, 0, &mut st, &mut seen)
                .is_err());
        }
    }
}
