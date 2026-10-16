//! CPU-side ALU clause interpreter (single invocation).
//!
//! Evaluation facts ported from the BSD-licensed Xenia
//! `shader_interpreter.cc` `ExecuteAluInstruction` (+ helpers) and
//! `shader_interpreter.h` address helpers:
//! - 64 temp registers (`kMaxShaderTempRegisters`), index wrapped
//!   mod 64; out-of-range float constants read as zeros.
//! - `FlushDenormal`: denormals become signed zero (only the sign
//!   bit survives).
//! - Operand modifiers are bitwise: absolute clears the f32 sign
//!   bit, negate flips it; swizzle selects per
//!   `GetSwizzledComponentIndex` (`((sw >> 2j) + j) & 3`).
//! - Temp sources/dests fold the loop address (aL) via
//!   `GetTempRegisterIndex` (`(base + (rel ? aL : 0)) & 63`); const
//!   sources fold `a0` or `aL` via `GetFloatConstant` (+ `a0` when
//!   `const_address_register_relative`, else `aL`), negatives and
//!   out-of-range read as zeros.
//! - `GetLoopAddress` (`loop_iterators[depth] * step + start`,
//!   clamped to [-256, 256]; 0 with no active loop).
//! - Vector sources are always all 4 components; scalar ops read
//!   src3 (a = W, b = X, or Z when the paired vector op takes
//!   three operands).
//! - D3D9 multiply rule (`muls`, vector `mul`, `mad`, dots):
//!   `(a && b) ? a*b : +0` (0 or denormal times anything is +0;
//!   `mad`/dots still add the accumulator so `+0 + -0` is `+0`).
//! - `max`/`maxs` keep `a` unless `a < b` (`isgreaterequal`
//!   semantics: NaN stays in `a`); `min`/`mins` keep `a` unless
//!   `a < b` is false... precisely `isless(a,b) ? a : b`.
//! - Scalar ops write `previous_scalar`; vector+scalar results are
//!   clamped (`saturate`: NaN becomes +0) when flagged, then
//!   written through the component masks (temps) or merged into
//!   the export registers for exports.
//!
//! Scope: vector add/mul/max/min/seq/sgt/sge/sne/frc/trunc/floor/
//! mad/dp4/dp3/dp2add; scalar adds/adds_prev/muls/muls_prev/
//! muls_prev2/subs/subs_prev/maxas/maxasf/setp_eq/ne/gt/ge/inv/
//! pop/clr/rstr/kills_eq/gt/ge/ne/one/retain_prev plus the
//! exp/logc/log/rcpc/rcpf/rcp/rsqc/rsqf/rsq/sqrt/sin/cos batch;
//! temp-relative (aL) dests/sources and const-relative (a0/aL)
//! addressing; texture-fetch slots write zeros per the reference
//! fallback (`StoreFetchResult` with a zero result). Vertex fetches
//! (memory + fetch constants) stay explicit `Unsupported`, never a
//! wrong result. CF control flow (loops/calls/jumps/returns) is
//! driven per the reference (`Execute` dispatch); unmatched returns
//! and overflowed nests are faithful no-ops/skips. `eval_alu` skips
//! predicated-out instructions itself (reference per-instruction
//! check); CF-level predication lives in the clause driver.

use x360_common::{EmuError, Result};

use super::ucode::{
    is_end_opcode, is_exec_opcode, parse_alu, parse_fetch, unpack_cf_pair, validate_ucode,
    AluInstr, CfInstr,
};

/// Temp register count (reference `kMaxShaderTempRegisters`).
pub const TEMP_COUNT: usize = 64;

/// Interpreter core: temps, previous-scalar (`ps`), predicate.
#[derive(Debug, Clone)]
pub struct ShaderCore {
    /// 64 vec4 temp registers, zero-initialized.
    pub temps: [[f32; 4]; TEMP_COUNT],
    /// Previous scalar result (`ps`).
    pub previous_scalar: f32,
    /// Current predicate (`p0`).
    pub predicate: bool,
    /// Address register (`a0`, const-relative base).
    pub address_register: i32,
    /// Loop-stack depth (CF loops not yet driven, so this stays 0
    /// and the loop address reads 0 per the reference guard).
    pub loop_depth: u32,
    /// Per-nest loop constants (only the top entry feeds
    /// [`ShaderCore::loop_address`]).
    pub loop_constants: [LoopConstant; 4],
    /// Per-nest iterators.
    pub loop_iters: [u32; 4],
    /// Export registers (reference `ExportRegister`: 0-63 cover
    /// VS interpolators/position/misc and PS colors/depth, plus
    /// memexport address/data at 32-37). Zero-initialized; each
    /// export instruction merges masked components into the
    /// addressed slot. Memory writeback itself is draw-backend
    /// business, not interpreter business.
    pub exports: [[f32; 4]; 64],
    /// Per-export-slot written-component mask (4 bits each).
    pub export_written: [u32; 64],
}

impl Default for ShaderCore {
    fn default() -> Self {
        Self {
            temps: [[0.0; 4]; TEMP_COUNT],
            previous_scalar: 0.0,
            predicate: false,
            address_register: 0,
            loop_depth: 0,
            loop_constants: [LoopConstant::default(); 4],
            loop_iters: [0; 4],
            exports: [[0.0; 4]; 64],
            export_written: [0; 64],
        }
    }
}

/// Loop-constant address base (reference `xenos::LoopConstant`:
/// `count` iterations with `aL = iterator * step + start`,
/// clamped by `GetLoopAddress`).
#[derive(Debug, Clone, Copy, Default)]
pub struct LoopConstant {
    /// Iteration count.
    pub count: u32,
    /// Address start.
    pub start: i32,
    /// Address step.
    pub step: i32,
}

impl LoopConstant {
    /// Decode register bits (reference `xenos::LoopConstant`:
    /// count low 8, start next 8, signed step next 8).
    pub fn from_bits(v: u32) -> Self {
        Self {
            count: v & 0xFF,
            start: ((v >> 8) & 0xFF) as i32,
            step: ((v >> 16) & 0xFF) as u8 as i8 as i32,
        }
    }
}

/// Loop address (reference `GetLoopAddress`): 0 with no
/// active loop, else `iterator * step + start` clamped to
/// [-256, 256].
impl ShaderCore {
    pub fn loop_address(&self) -> i32 {
        if self.loop_depth == 0 || self.loop_depth >= 4 {
            return 0;
        }
        let top = (self.loop_depth - 1) as usize;
        let lc = self.loop_constants[top];
        let it = self.loop_iters[top] as i32;
        it.wrapping_mul(lc.step)
            .wrapping_add(lc.start)
            .clamp(-256, 256)
    }

    /// Temp index with aL-relative bias (reference
    /// `GetTempRegisterIndex`: `(base + (rel ? aL : 0)) & 63`).
    pub fn temp_index(&self, address: u32, is_relative: bool) -> usize {
        let base = (address & 0x3F) as i32;
        let idx = if is_relative {
            base.wrapping_add(self.loop_address())
        } else {
            base
        };
        idx.rem_euclid(64) as usize
    }

    /// Float-constant effective index (reference `GetFloatConstant`
    /// addressing half: `index += rel ? (a0-or-aL) : 0`). Negative
    /// indices read as zeros; range checks against the constant file
    /// happen at the call site.
    pub fn const_index(&self, address: u32, is_relative: bool, is_a0: bool) -> Option<usize> {
        let mut idx = address as i32;
        if is_relative {
            idx = idx.wrapping_add(if is_a0 {
                self.address_register
            } else {
                self.loop_address()
            });
        }
        if idx < 0 {
            None
        } else {
            Some(idx as usize)
        }
    }
}

/// Denormal flush (reference `FlushDenormal`): denormals keep only
/// their sign bit (becoming +0 or -0).
fn flush_denormal(v: f32) -> f32 {
    let b = v.to_bits();
    if b & 0x7F80_0000 != 0 {
        v
    } else {
        f32::from_bits(b & 0x8000_0000)
    }
}

/// Saturate to [0, 1] with NaN becoming +0 (reference `xe::saturate`
/// via `clamp_float`, whose docs pin both behaviors).
fn saturate(v: f32) -> f32 {
    if v.is_nan() {
        0.0
    } else {
        v.clamp(0.0, 1.0)
    }
}

/// Swizzled component index (reference
/// `GetSwizzledComponentIndex`).
fn swizzled(swizzle: u32, j: u32) -> usize {
    (((swizzle >> (2 * j)) + j) & 3) as usize
}

/// Bitwise absolute value (clear f32 sign bit).
fn f32_abs(v: f32) -> f32 {
    f32::from_bits(v.to_bits() & !(1 << 31))
}

/// Bitwise negate (flip f32 sign bit).
fn f32_neg(v: f32) -> f32 {
    f32::from_bits(v.to_bits() ^ (1 << 31))
}

/// Fetch one fully swizzled/modified vector source (reference
/// vector-operand loop: temps via `GetTempRegisterIndex` with the
/// aL bias, consts via `GetFloatConstant` with the a0/aL bias).
fn fetch_vec(core: &ShaderCore, consts: &[[f32; 4]], ins: &AluInstr, i: u32) -> Result<[f32; 4]> {
    let reg = ins.src_reg(i);
    let is_temp = ins.src_is_temp(i);
    let base: [f32; 4] = if is_temp {
        let idx = core.temp_index(
            AluInstr::src_temp_reg(reg),
            AluInstr::is_src_temp_relative(reg),
        );
        core.temps[idx]
    } else {
        match core.const_index(
            reg,
            ins.src_const_is_addressed(i),
            ins.is_const_address_register_relative(),
        ) {
            Some(ci) if ci < consts.len() => consts[ci],
            _ => [0.0; 4],
        }
    };
    let sw = ins.src_swizzle(i);
    // Absolute applies to temp sources only (reference leaves the
    // const path absolute-free).
    let absolute = is_temp && AluInstr::is_src_temp_value_absolute(reg);
    let mut out = [0.0f32; 4];
    for j in 0..4u32 {
        let mut c = flush_denormal(base[swizzled(sw, j)]);
        if absolute {
            c = f32_abs(c);
        }
        if ins.src_negate(i) {
            c = f32_neg(c);
        }
        out[j as usize] = c;
    }
    Ok(out)
}

/// Fetch the scalar pair (a = W, b = X, or Z when the vector op
/// takes three operands), flushed and modified (reference scalar
/// fetch + common abs/negate path).
fn fetch_scalar_pair(
    core: &ShaderCore,
    consts: &[[f32; 4]],
    ins: &AluInstr,
    vec_three_operands: bool,
) -> Result<(f32, f32)> {
    let reg = ins.src_reg(3);
    let is_temp = ins.src_is_temp(3);
    let base: [f32; 4] = if is_temp {
        let idx = core.temp_index(
            AluInstr::src_temp_reg(reg),
            AluInstr::is_src_temp_relative(reg),
        );
        let t = core.temps[idx];
        let mut v = t;
        if AluInstr::is_src_temp_value_absolute(reg) {
            for c in v.iter_mut() {
                *c = f32_abs(*c);
            }
        }
        v
    } else {
        match core.const_index(
            reg,
            ins.src_const_is_addressed(3),
            ins.is_const_address_register_relative(),
        ) {
            Some(ci) if ci < consts.len() => consts[ci],
            _ => [0.0; 4],
        }
    };
    let sw = ins.src_swizzle(3);
    // Note: temp absolute (reg bit 0x80) was applied above;
    // `abs_constants` only feeds the two-operand const-reg form,
    // which is not slice 1.
    let mut a = flush_denormal(base[swizzled(sw, 3)]);
    let mut b = flush_denormal(base[swizzled(sw, if vec_three_operands { 2 } else { 0 })]);
    if ins.src_negate(3) {
        a = f32_neg(a);
        b = f32_neg(b);
    }
    Ok((a, b))
}

/// Mantissa reduction (reference `ReduceFloatPrecision`):
/// round-to-nearest on the low `23 - mantissa_bits` mantissa bits,
/// never rounding a finite result up to infinity; infinities and
/// NaN pass through.
fn reduce_float_precision(value: f32, mantissa_bits: u32) -> f32 {
    let bits = value.to_bits();
    if bits & 0x7F80_0000 == 0x7F80_0000 {
        return value;
    }
    let truncate_bits = 23 - mantissa_bits;
    let discarded_mask = (1u32 << truncate_bits) - 1;
    let truncated_bits = bits & !discarded_mask;
    let mut rounded_bits = truncated_bits + (1u32 << truncate_bits);
    if rounded_bits & 0x7F80_0000 == 0x7F80_0000 {
        rounded_bits = truncated_bits;
    }
    let round_bit = 1u32 << (truncate_bits - 1);
    let result_bits = if bits & discarded_mask >= round_bit {
        rounded_bits
    } else {
        truncated_bits
    };
    f32::from_bits(result_bits)
}

/// Clamp with reference `clamp_float` NaN semantics (NaN takes
/// the min boundary).
fn clamp_float(v: f32, min: f32, max: f32) -> f32 {
    let c = if v > min { v } else { min };
    if c < max {
        c
    } else {
        max
    }
}

/// Quiet greater-or-equal (reference `std::isgreaterequal`):
/// unordered (NaN) compares quiet-true.
fn ge_quiet(a: f32, b: f32) -> bool {
    a.partial_cmp(&b) != Some(std::cmp::Ordering::Less)
}

/// D3D9 multiply: 0 (or flushed denormal) times anything is +0.
fn d3d_mul(a: f32, b: f32) -> f32 {
    if a != 0.0 && b != 0.0 {
        a * b
    } else {
        0.0
    }
}

/// Evaluate one ALU clause instruction against the core, writing
/// masked results (reference `ExecuteAluInstruction` vector op +
/// scalar op + writeback). Predicated-out instructions skip
/// entirely (reference per-instruction check ahead of evaluation).
/// Exports merge into the core's export registers (reference
/// export composition with vector/scalar/const0/const1 masks);
/// memory writeback itself is draw-backend business.
pub fn eval_alu(core: &mut ShaderCore, consts: &[[f32; 4]], ins: &AluInstr) -> Result<()> {
    if ins.is_predicated() && ins.pred_condition() != core.predicate {
        return Ok(());
    }
    let vop = ins.vector_opcode();
    // Sources needed per opcode (reference
    // `operand_components_used`; over-fetching is harmless but OOB
    // temp reads must never happen, so fetch exactly).
    let vec_sources: &[u32] = match vop {
        11..=14 | 17 => &[1, 2, 3],
        8..=10 | 18 | 19 => &[1],
        0..=7 | 15 | 16 | 20..=29 => &[1, 2],
        _ => {
            return Err(EmuError::Unsupported(format!(
                "alu: vector op {} pending",
                super::ucode::alu_vector_opcode_name(vop)
            )));
        }
    };
    let mut src = [[0.0f32; 4]; 3];
    for (k, i) in vec_sources.iter().enumerate() {
        src[k] = fetch_vec(core, consts, ins, *i)?;
    }
    let mut vr = [0.0f32; 4];
    match vop {
        0 => {
            for i in 0..4 {
                vr[i] = src[0][i] + src[1][i];
            }
        }
        1 => {
            for i in 0..4 {
                vr[i] = d3d_mul(src[0][i], src[1][i]);
            }
        }
        2 => {
            for i in 0..4 {
                // isgreaterequal: NaN stays in `a` (written without
                // negation to keep the partial-order semantics clear).
                vr[i] = if src[0][i] < src[1][i] {
                    src[1][i]
                } else {
                    src[0][i]
                };
            }
        }
        3 => {
            for i in 0..4 {
                vr[i] = if src[0][i] < src[1][i] {
                    src[0][i]
                } else {
                    src[1][i]
                };
            }
        }
        4 => {
            for i in 0..4 {
                vr[i] = if src[0][i] == src[1][i] { 1.0 } else { 0.0 };
            }
        }
        5 => {
            for i in 0..4 {
                vr[i] = if src[0][i] > src[1][i] { 1.0 } else { 0.0 };
            }
        }
        6 => {
            for i in 0..4 {
                vr[i] = if src[0][i] < src[1][i] { 0.0 } else { 1.0 };
            }
        }
        7 => {
            for i in 0..4 {
                vr[i] = if src[0][i] != src[1][i] { 1.0 } else { 0.0 };
            }
        }
        8 => {
            for i in 0..4 {
                vr[i] = src[0][i] - src[0][i].floor();
            }
        }
        9 => {
            for i in 0..4 {
                vr[i] = src[0][i].trunc();
            }
        }
        10 => {
            for i in 0..4 {
                vr[i] = src[0][i].floor();
            }
        }
        11 => {
            for i in 0..4 {
                vr[i] = d3d_mul(src[0][i], src[1][i]) + src[2][i];
            }
        }
        15 | 16 => {
            let n = if vop == 15 { 4 } else { 3 };
            let mut sum = 0.0f32;
            for i in 0..n {
                sum += d3d_mul(src[0][i as usize], src[1][i as usize]);
            }
            vr = [sum; 4];
        }
        17 => {
            let mut sum = 0.0f32;
            for i in 0..2 {
                sum += d3d_mul(src[0][i as usize], src[1][i as usize]);
            }
            sum += src[2][0];
            vr = [sum; 4];
        }
        12 => {
            for i in 0..4 {
                vr[i] = if src[0][i] == 0.0 {
                    src[1][i]
                } else {
                    src[2][i]
                };
            }
        }
        13 => {
            for i in 0..4 {
                vr[i] = if src[0][i].partial_cmp(&0.0) != Some(std::cmp::Ordering::Less) {
                    src[1][i]
                } else {
                    src[2][i]
                };
            }
        }
        14 => {
            for i in 0..4 {
                vr[i] = if src[0][i] > 0.0 {
                    src[1][i]
                } else {
                    src[2][i]
                };
            }
        }
        18 => {
            // Cube-map coordinate/face select (reference `kCube`).
            let (x, y, z) = (src[0][2], src[0][3], src[0][0]);
            let (xa, ya, za) = (x.abs(), y.abs(), z.abs());
            if ge_quiet(za, xa) && ge_quiet(za, ya) {
                let zn = z < 0.0;
                vr[0] = -y;
                vr[1] = if zn { -x } else { x };
                vr[2] = z;
                vr[3] = if zn { 5.0 } else { 4.0 };
            } else if ge_quiet(ya, xa) {
                let yn = y < 0.0;
                vr[0] = if yn { -z } else { z };
                vr[1] = x;
                vr[2] = y;
                vr[3] = if yn { 3.0 } else { 2.0 };
            } else {
                let xn = x < 0.0;
                vr[0] = -y;
                vr[1] = if xn { z } else { -z };
                vr[2] = x;
                vr[3] = if xn { 1.0 } else { 0.0 };
            }
            vr[2] *= 2.0;
        }
        19 => {
            let o = &src[0];
            let ge = |a: f32, b: f32| a.partial_cmp(&b) != Some(std::cmp::Ordering::Less);
            if ge(o[0], o[1]) && ge(o[0], o[2]) && ge(o[0], o[3]) {
                vr[0] = o[0];
            } else if ge(o[1], o[2]) && ge(o[1], o[3]) {
                vr[0] = o[1];
            } else if ge(o[2], o[3]) {
                vr[0] = o[2];
            } else {
                vr[0] = o[3];
            }
            vr[1] = vr[0];
            vr[2] = vr[0];
            vr[3] = vr[0];
        }
        20..=23 => {
            // Predicate-push compare on W, counter in X (reference
            // `kSetp*Push`).
            let (a0, a3, b0, b3) = (src[0][0], src[0][3], src[1][0], src[1][3]);
            let (pred, zero) = match vop {
                20 => (a3 == 0.0 && b3 == 0.0, a0 == 0.0 && b0 == 0.0),
                21 => (a3 == 0.0 && b3 != 0.0, a0 == 0.0 && b0 != 0.0),
                22 => (a3 == 0.0 && b3 > 0.0, a0 == 0.0 && b0 > 0.0),
                _ => (
                    a3 == 0.0 && b3.partial_cmp(&0.0) != Some(std::cmp::Ordering::Less),
                    a0 == 0.0 && b0.partial_cmp(&0.0) != Some(std::cmp::Ordering::Less),
                ),
            };
            core.predicate = pred;
            vr[0] = if zero { 0.0 } else { a0 + 1.0 };
            vr[1] = vr[0];
            vr[2] = vr[0];
            vr[3] = vr[0];
        }
        24..=27 => {
            // Kill-test flags (pixel kill itself is unimplemented in
            // the reference too; only the result word is produced).
            let any = match vop {
                24 => (0..4).any(|i| src[0][i] == src[1][i]),
                25 => (0..4).any(|i| src[0][i] > src[1][i]),
                26 => (0..4)
                    .any(|i| src[0][i].partial_cmp(&src[1][i]) != Some(std::cmp::Ordering::Less)),
                _ => (0..4).any(|i| src[0][i] != src[1][i]),
            };
            vr = [if any { 1.0 } else { 0.0 }; 4];
        }
        28 => {
            vr[0] = 1.0;
            vr[1] = d3d_mul(src[0][1], src[1][1]);
            vr[2] = src[0][2];
            vr[3] = src[1][3];
        }
        29 => {
            core.address_register = (clamp_float(src[0][3], -256.0, 255.0) + 0.5).floor() as i32;
            for i in 0..4 {
                vr[i] = if src[0][i] < src[1][i] {
                    src[1][i]
                } else {
                    src[0][i]
                };
            }
        }
        _ => {
            return Err(EmuError::Unsupported(format!(
                "alu: vector op {} pending",
                super::ucode::alu_vector_opcode_name(vop)
            )));
        }
    }
    let sop = ins.scalar_opcode();
    let vec_three = matches!(vop, 11..=14 | 17);
    match sop {
        50 => {}
        5..=13 => {
            // Single-component compares and fractions (reference
            // `kMaxs`..`kFloors`): maxs/mins use W and X, the rest
            // only W.
            let (a, b) = fetch_scalar_pair(core, consts, ins, vec_three)?;
            core.previous_scalar = match sop {
                5 => {
                    if a < b {
                        b
                    } else {
                        a
                    }
                }
                6 => {
                    if a < b {
                        a
                    } else {
                        b
                    }
                }
                7 => {
                    if a == 0.0 {
                        1.0
                    } else {
                        0.0
                    }
                }
                8 => {
                    if a > 0.0 {
                        1.0
                    } else {
                        0.0
                    }
                }
                9 => {
                    if a.partial_cmp(&0.0) != Some(std::cmp::Ordering::Less) {
                        1.0
                    } else {
                        0.0
                    }
                }
                10 => {
                    if a != 0.0 {
                        1.0
                    } else {
                        0.0
                    }
                }
                11 => a - a.floor(),
                12 => a.trunc(),
                _ => a.floor(),
            };
        }
        0 | 1 | 2 | 3 | 4 | 23 | 24 | 25 | 26 => {
            let (a, b) = fetch_scalar_pair(core, consts, ins, vec_three)?;
            match sop {
                0 => core.previous_scalar = a + b,
                1 => core.previous_scalar += a,
                2 => core.previous_scalar = d3d_mul(a, b),
                3 => {
                    let product = a * core.previous_scalar;
                    core.previous_scalar = if a != 0.0 && core.previous_scalar != 0.0 {
                        product
                    } else {
                        0.0
                    };
                }
                4 => {
                    if core.previous_scalar == -f32::MAX
                        || !core.previous_scalar.is_finite()
                        || !b.is_finite()
                        || b <= 0.0
                    {
                        core.previous_scalar = -f32::MAX;
                    } else if a != 0.0 && core.previous_scalar != 0.0 {
                        let product = a * core.previous_scalar;
                        core.previous_scalar = product;
                    } else {
                        core.previous_scalar = 0.0;
                    }
                }
                23 | 24 => {
                    // max-and-set-address (reference `kMaxAs(f)`).
                    let clamped = clamp_float(a, -256.0, 255.0);
                    core.address_register = if sop == 23 {
                        (clamped + 0.5).floor() as i32
                    } else {
                        clamped.floor() as i32
                    };
                    core.previous_scalar = if a < b { b } else { a };
                }
                _ => core.previous_scalar = a - b,
            }
        }
        42..=47 => {
            // Const-reg form (reference case 2): c#.w by src3 (with
            // a0/aL bias), r#.x by the opcode-derived temp index
            // (never relative); flushed, negated, no abs (mirrors
            // the reference, where `abs_constants` never reaches the
            // interpreter path).
            let sw = ins.src_swizzle(3);
            let a = match core.const_index(
                ins.src_reg(3),
                ins.src_const_is_addressed(3),
                ins.is_const_address_register_relative(),
            ) {
                Some(ci) if ci < consts.len() => {
                    let mut v = flush_denormal(consts[ci][swizzled(sw, 3)]);
                    if ins.src_negate(3) {
                        v = f32_neg(v);
                    }
                    v
                }
                _ => 0.0,
            };
            // Temp index per reference
            // `(opc & 1) | (sel << 1) | (swiz & 0x3C)`, wrapped mod 64.
            let sel = if ins.src_is_temp(3) { 1 } else { 0 };
            let t = (((sop & 1) | (sel << 1) | (sw & 0x3C)) & 0x3F) as usize;
            let mut b = flush_denormal(core.temps[t][swizzled(sw, 0)]);
            if ins.src_negate(3) {
                b = f32_neg(b);
            }
            core.previous_scalar = match sop {
                42 | 43 => d3d_mul(a, b),
                44 | 45 => a + b,
                _ => a - b,
            };
        }
        14 | 15 | 16 | 17 | 18 | 19 | 20 | 21 | 22 | 40 | 48 | 49 => {
            let (a, _) = fetch_scalar_pair(core, consts, ins, vec_three)?;
            // Exact fixups per op (reference arms): reduced-precision
            // transcendentals with -inf/+inf mapped per suffix.
            core.previous_scalar = match sop {
                14 => reduce_float_precision(a.exp2(), 21),
                15 => {
                    let v = reduce_float_precision(a.log2(), 21);
                    if v == f32::NEG_INFINITY {
                        -f32::MAX
                    } else {
                        v
                    }
                }
                16 => reduce_float_precision(a.log2(), 21),
                17 => {
                    let v = reduce_float_precision(1.0 / a, 21);
                    if v == f32::NEG_INFINITY {
                        -f32::MAX
                    } else if v == f32::INFINITY {
                        f32::MAX
                    } else {
                        v
                    }
                }
                18 => {
                    let v = reduce_float_precision(1.0 / a, 21);
                    if v == f32::NEG_INFINITY {
                        -0.0
                    } else if v == f32::INFINITY {
                        0.0
                    } else {
                        v
                    }
                }
                19 => reduce_float_precision(1.0 / a, 21),
                20 => {
                    let v = reduce_float_precision(1.0 / a.sqrt(), 21);
                    if v == f32::NEG_INFINITY {
                        -f32::MAX
                    } else if v == f32::INFINITY {
                        f32::MAX
                    } else {
                        v
                    }
                }
                21 => {
                    let v = reduce_float_precision(1.0 / a.sqrt(), 21);
                    if v == f32::NEG_INFINITY {
                        -0.0
                    } else if v == f32::INFINITY {
                        0.0
                    } else {
                        v
                    }
                }
                22 => reduce_float_precision(1.0 / a.sqrt(), 21),
                40 => reduce_float_precision(a.sqrt(), 21),
                48 => a.sin(),
                _ => a.cos(),
            };
        }
        27..=39 => {
            // Predicate writers (reference `kSetp*`; kills only set
            // ps — pixel kill itself is unimplemented in the
            // reference interpreter too).
            let (a, _) = fetch_scalar_pair(core, consts, ins, vec_three)?;
            match sop {
                27 => {
                    core.predicate = a == 0.0;
                    core.previous_scalar = if !core.predicate { 1.0 } else { 0.0 };
                }
                28 => {
                    core.predicate = a != 0.0;
                    core.previous_scalar = if !core.predicate { 1.0 } else { 0.0 };
                }
                29 => {
                    core.predicate = a > 0.0;
                    core.previous_scalar = if !core.predicate { 1.0 } else { 0.0 };
                }
                30 => {
                    // isgreaterequal: quiet-true on NaN (partial_cmp
                    // makes the unordered case explicit).
                    core.predicate = a.partial_cmp(&0.0) != Some(std::cmp::Ordering::Less);
                    core.previous_scalar = if !core.predicate { 1.0 } else { 0.0 };
                }
                31 => {
                    core.predicate = a == 1.0;
                    core.previous_scalar = if core.predicate {
                        0.0
                    } else if a == 0.0 {
                        1.0
                    } else {
                        a
                    };
                }
                32 => {
                    let counter = a - 1.0;
                    core.predicate = counter <= 0.0;
                    core.previous_scalar = if core.predicate { 0.0 } else { counter };
                }
                33 => {
                    core.predicate = false;
                    core.previous_scalar = f32::MAX;
                }
                34 => {
                    core.predicate = a == 0.0;
                    core.previous_scalar = if core.predicate { 0.0 } else { a };
                }
                35 => core.previous_scalar = if a == 0.0 { 1.0 } else { 0.0 },
                36 => core.previous_scalar = if a > 0.0 { 1.0 } else { 0.0 },
                37 => {
                    core.previous_scalar = if a.partial_cmp(&0.0) != Some(std::cmp::Ordering::Less)
                    {
                        1.0
                    } else {
                        0.0
                    }
                }
                38 => core.previous_scalar = if a != 0.0 { 1.0 } else { 0.0 },
                _ => core.previous_scalar = if a == 1.0 { 1.0 } else { 0.0 },
            }
        }
        _ => {
            return Err(EmuError::Unsupported(format!(
                "alu: scalar op {} pending",
                super::ucode::alu_scalar_opcode_name(sop)
            )));
        }
    }
    if ins.vector_clamp() {
        for c in vr.iter_mut() {
            *c = saturate(*c);
        }
    }
    let mut sr = core.previous_scalar;
    if ins.scalar_clamp() {
        sr = saturate(sr);
    }
    if ins.is_export() {
        // Export composition (reference `is_export` branch +
        // `GetConstant0/1WriteMask`): both ops target the vector
        // dest slot; per component, vector wins over scalar, then
        // constant-1 (both masks), then constant-0 (scalar_dest_rel
        // with neither mask), else the slot keeps its value.
        if ins.is_vector_dest_relative() {
            return Err(EmuError::Unsupported(
                "alu: relative export dest malformed".into(),
            ));
        }
        let idx = (ins.vector_dest() & 0x3F) as usize;
        let vmask = ins.vector_write_mask();
        let smask = ins.scalar_write_mask();
        let vec_mask = vmask & !smask;
        let scal_mask = smask & !vmask;
        let const1 = vmask & smask;
        let const0 = if ins.is_scalar_dest_relative() {
            !(vmask | smask) & 0xF
        } else {
            0
        };
        for (i, (slot, v)) in core.exports[idx].iter_mut().zip(vr.iter()).enumerate() {
            let bit = 1 << i;
            if vec_mask & bit != 0 {
                *slot = *v;
                core.export_written[idx] |= bit;
            } else if scal_mask & bit != 0 {
                *slot = sr;
                core.export_written[idx] |= bit;
            } else if const1 & bit != 0 {
                *slot = 1.0;
                core.export_written[idx] |= bit;
            } else if const0 & bit != 0 {
                *slot = 0.0;
                core.export_written[idx] |= bit;
            }
        }
        return Ok(());
    }
    // Dest fields are 6-bit bases plus the aL bias for plain
    // temps (reference `GetTempRegister` on both dests; exports
    // keep the malformed-dest guard above).
    let vd = core.temp_index(ins.vector_dest(), ins.is_vector_dest_relative());
    let vmask = ins.vector_write_mask();
    for (i, (t, v)) in core.temps[vd].iter_mut().zip(vr.iter()).enumerate() {
        if vmask & (1 << i) != 0 {
            *t = *v;
        }
    }
    let sd = core.temp_index(ins.scalar_dest(), ins.is_scalar_dest_relative());
    let smask = ins.scalar_write_mask();
    for (i, t) in core.temps[sd].iter_mut().enumerate() {
        if smask & (1 << i) != 0 {
            *t = sr;
        }
    }
    Ok(())
}

/// CF-driver run stats (execution census).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CfRunStats {
    /// CF instructions visited (including skipped/gated).
    pub cf_visited: u32,
    /// Clause slots executed as ALU.
    pub alu_executed: u32,
    /// Fetch slots executed (texture-fetch zero writes; vertex
    /// fetches are explicit errors, never counted).
    pub fetch_executed: u32,
    /// Control transfers taken (loop entries/skips/back-edges,
    /// calls, returns, jumps).
    pub ctrl_taken: u32,
    /// Whether an end-opcode terminated the run.
    pub ended: bool,
}

/// Bool-constant bit test (reference register-file bits;
/// out-of-range addresses read as false, matching zeroed regs).
fn bool_set(words: &[u32], addr: u32) -> bool {
    let (w, b) = ((addr >> 5) as usize, addr & 31);
    words.get(w).map(|v| v & (1 << b) != 0).unwrap_or(false)
}

/// Fetch dest write with absolute swizzle (reference
/// `StoreFetchResult` + `GetFetchDestinationComponentSwizzle`:
/// 0-3 select the value component, 4 writes 0, 5 writes 1,
/// 7 keeps, anything else (including the invalid 6) writes 0).
fn store_fetch_result(
    core: &mut ShaderCore,
    dest: u32,
    is_relative: bool,
    swizzle: u32,
    value: &[f32; 4],
) {
    let idx = core.temp_index(dest, is_relative);
    for i in 0..4 {
        let sel = (swizzle >> (3 * i)) & 7;
        match sel {
            0..=3 => core.temps[idx][i] = value[sel as usize],
            5 => core.temps[idx][i] = 1.0,
            7 => {}
            _ => core.temps[idx][i] = 0.0,
        }
    }
}

/// Run the CF program, executing ALU/fetch clause slots
/// (reference `ShaderInterpreter::Execute` CF loop).
///
/// Supported: `nop`, the full exec family (bool-constant and
/// predicate gating), loops (nesting depth 4, repeat/skip/break
/// per the reference), conditional calls/returns (depth 4),
/// conditional jumps, `alloc` (no-op without an export sink),
/// `fetchdone` (no-op). Texture-fetch slots write zeros (reference
/// non-vertex fallback); vertex fetches (needing vertex memory +
/// fetch constants) stay explicit `Unsupported`. Ends at the first
/// end-opcode or at the CF program bound; validate errors
/// propagate.
///
/// `loop_words` holds integer loop-constant register bits indexed
/// by loop id (out-of-range ids read count 0, skipping the loop).
/// Loop-stack bookkeeping is 0-based and balanced (deviation from
/// the reference's double-incremented depth, which leaks +1 per
/// loop, is deliberate: ours terminates with identical per-iteration
/// `aL` and trip counts).
pub fn run_cf(
    core: &mut ShaderCore,
    dwords: &[u32],
    consts: &[[f32; 4]],
    bool_words: &[u32],
) -> Result<CfRunStats> {
    run_cf_loops(core, dwords, consts, bool_words, &[])
}

/// [`run_cf`] with loop-constant registers (see `loop_words`).
pub fn run_cf_loops(
    core: &mut ShaderCore,
    dwords: &[u32],
    consts: &[[f32; 4]],
    bool_words: &[u32],
    loop_words: &[u32],
) -> Result<CfRunStats> {
    let st = validate_ucode(dwords)?;
    let mut cf: Vec<CfInstr> = Vec::with_capacity(st.cf_pairs as usize * 2);
    for pair in 0..st.cf_pairs as usize {
        let g = [dwords[3 * pair], dwords[3 * pair + 1], dwords[3 * pair + 2]];
        let [a, b] = unpack_cf_pair(&g);
        cf.push(a);
        cf.push(b);
    }
    // Control-flow state (reference stack depths, 0-based here).
    let mut call_stack: [u32; 4] = [0; 4];
    let mut call_depth: usize = 0;
    let mut stats = CfRunStats::default();
    let mut cf_index: u32 = 0;
    while (cf_index as usize) < cf.len() {
        if stats.cf_visited >= 4096 {
            return Err(EmuError::Other("cf: step budget exceeded".into()));
        }
        let ins = cf[cf_index as usize];
        let mut next = cf_index + 1;
        stats.cf_visited += 1;
        match ins.opcode {
            0 => {}
            1 | 2 | 3 | 4 | 5 | 6 | 13 | 14 => {
                debug_assert!(is_exec_opcode(ins.opcode));
                // Gating (reference per-opcode checks).
                let gated_out = match ins.opcode {
                    3 | 4 | 13 | 14 => bool_set(bool_words, ins.bool_address()) != ins.condition(),
                    5 | 6 => core.predicate != ins.condition(),
                    _ => false,
                };
                if !gated_out {
                    for k in 0..ins.count() {
                        let slot = ins.address().wrapping_add(k) as usize;
                        let base = slot
                            .checked_mul(3)
                            .ok_or_else(|| EmuError::Other("cf: clause slot overflows".into()))?;
                        if base + 3 > dwords.len() {
                            return Err(EmuError::Other(format!(
                                "cf: clause slot {} out of range",
                                slot
                            )));
                        }
                        let seq = (ins.sequence() >> (2 * k)) & 3;
                        if seq & 1 != 0 {
                            let w = [dwords[base], dwords[base + 1], dwords[base + 2]];
                            let fetch = parse_fetch(&w);
                            if fetch.is_predicated() && fetch.pred_condition() != core.predicate {
                                continue;
                            }
                            if fetch.opcode() == 0 {
                                return Err(EmuError::Unsupported(format!(
                                    "cf: slot {}: vfetch needs draw backend (vertex memory + fetch constants)",
                                    slot
                                )));
                            }
                            store_fetch_result(
                                core,
                                fetch.dst_reg(),
                                fetch.is_dest_relative(),
                                fetch.dst_swizzle(),
                                &[0.0; 4],
                            );
                            stats.fetch_executed += 1;
                            continue;
                        }
                        let w = [dwords[base], dwords[base + 1], dwords[base + 2]];
                        eval_alu(core, consts, &parse_alu(&w)).map_err(|e| match e {
                            EmuError::Unsupported(s) => {
                                EmuError::Unsupported(format!("cf: slot {}: {}", slot, s))
                            }
                            EmuError::Other(s) => {
                                EmuError::Other(format!("cf: slot {}: {}", slot, s))
                            }
                            other => other,
                        })?;
                        stats.alu_executed += 1;
                    }
                    if is_end_opcode(ins.opcode) {
                        stats.ended = true;
                        return Ok(stats);
                    }
                }
            }
            7 => {
                // Loop start (reference `kLoopStart` + skip logic).
                if core.loop_depth as usize >= 4 {
                    let t = ins.cf_target() as usize;
                    if t >= cf.len() {
                        return Err(EmuError::Other(format!(
                            "cf: loop skip target {} out of range",
                            t
                        )));
                    }
                    next = t as u32;
                    stats.ctrl_taken += 1;
                } else {
                    let lc = loop_words
                        .get(ins.loop_id() as usize)
                        .copied()
                        .map(LoopConstant::from_bits)
                        .unwrap_or_default();
                    let d = core.loop_depth as usize;
                    if !ins.is_repeat() {
                        core.loop_iters[d] = 0;
                    }
                    if core.loop_iters[d] >= lc.count {
                        let t = ins.cf_target() as usize;
                        if t >= cf.len() {
                            return Err(EmuError::Other(format!(
                                "cf: loop skip target {} out of range",
                                t
                            )));
                        }
                        next = t as u32;
                        stats.ctrl_taken += 1;
                    } else {
                        core.loop_constants[d] = lc;
                        core.loop_depth += 1;
                    }
                }
            }
            8 => {
                // Loop end (reference `kLoopEnd`: increment first,
                // then test count and predicated break).
                if core.loop_depth == 0 {
                    // Unmatched endloop outside a loop is a no-op
                    // (mirrors the reference guard).
                } else {
                    let d = (core.loop_depth - 1) as usize;
                    core.loop_iters[d] = core.loop_iters[d].wrapping_add(1);
                    let lc = core.loop_constants[d];
                    let brk = ins.is_predicated_break() && ins.condition() == core.predicate;
                    if core.loop_iters[d] < lc.count && !brk {
                        let t = ins.cf_target() as usize;
                        if t >= cf.len() {
                            return Err(EmuError::Other(format!(
                                "cf: loop body target {} out of range",
                                t
                            )));
                        }
                        next = t as u32;
                        stats.ctrl_taken += 1;
                    } else {
                        core.loop_depth -= 1;
                    }
                }
            }
            9 => {
                // Conditional call (reference `kCondCall`, depth 4).
                if call_depth >= 4 {
                    // Overflow: skip like the reference.
                } else {
                    let take = ins.is_unconditional() || {
                        if ins.is_ctrl_predicated() {
                            ins.condition() == core.predicate
                        } else {
                            bool_set(bool_words, ins.bool_address()) == ins.condition()
                        }
                    };
                    if take {
                        let t = ins.cf_target() as usize;
                        if t >= cf.len() {
                            return Err(EmuError::Other(format!(
                                "cf: call target {} out of range",
                                t
                            )));
                        }
                        call_stack[call_depth] = cf_index + 1;
                        call_depth += 1;
                        next = t as u32;
                        stats.ctrl_taken += 1;
                    }
                }
            }
            10 => {
                // Return (reference `kReturn`: no-op outside a call).
                if call_depth > 0 {
                    call_depth -= 1;
                    next = call_stack[call_depth];
                    stats.ctrl_taken += 1;
                }
            }
            11 => {
                // Conditional jump (reference `kCondJmp`).
                let take = ins.is_unconditional() || {
                    if ins.is_ctrl_predicated() {
                        ins.condition() == core.predicate
                    } else {
                        bool_set(bool_words, ins.bool_address()) == ins.condition()
                    }
                };
                if take {
                    let t = ins.cf_target() as usize;
                    if t >= cf.len() {
                        return Err(EmuError::Other(format!(
                            "cf: jump target {} out of range",
                            t
                        )));
                    }
                    next = t as u32;
                    stats.ctrl_taken += 1;
                }
            }
            12 | 15 => {}
            _ => {
                return Err(EmuError::Unsupported(format!(
                    "cf: opcode {} ({}) pending",
                    ins.opcode,
                    super::ucode::cf_opcode_name(ins.opcode)
                )));
            }
        }
        cf_index = next;
    }
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ucode::parse_alu;

    /// Triple builder: d0(dest/mask/opc), d1 zero, d2(regs/opc).
    fn triple(vd: u32, vmask: u32, sd: u32, smask: u32, vop: u32, sop: u32) -> [u32; 3] {
        let d0 = (vd & 0x3F)
            | ((sd & 0x3F) << 8)
            | ((vmask & 0xF) << 16)
            | ((smask & 0xF) << 20)
            | ((sop & 0x3F) << 26);
        [d0, 0, (vop & 0x1F) << 24]
    }

    #[test]
    fn mad_add_dp4_writeback() {
        let mut core = ShaderCore::default();
        core.temps[4] = [1.0, 2.0, 3.0, 4.0];
        core.temps[5] = [10.0, 10.0, 10.0, 10.0];
        core.temps[6] = [100.0, 100.0, 100.0, 100.0];
        // mad r1.xyzw, r4, r5, r6 (all-temp sources).
        let d = [
            triple(1, 0xF, 0, 0, 11, 50)[0],
            0,
            (11 << 24) | (4 << 16) | (5 << 8) | 6 | (1 << 31) | (1 << 30) | (1 << 29),
        ];
        eval_alu(&mut core, &[], &parse_alu(&d)).unwrap();
        assert_eq!(core.temps[1], [110.0, 120.0, 130.0, 140.0]);
        // dp4 r2.x, r1, r5 (mask x only).
        let d = [
            triple(2, 0x1, 0, 0, 15, 50)[0],
            0,
            (15 << 24) | (1 << 16) | (5 << 8) | (1 << 31) | (1 << 30),
        ];
        eval_alu(&mut core, &[], &parse_alu(&d)).unwrap();
        assert_eq!(core.temps[2][0], 5000.0);
        assert_eq!(&core.temps[2][1..], &[0.0, 0.0, 0.0]);
    }

    #[test]
    fn scalar_adds_and_clamp() {
        let mut core = ShaderCore::default();
        // c0 = [7.0, 0.0, 0.0, 5.0]: adds takes a=W=5.0, b=X=7.0.
        let consts = [[7.0, 0.0, 0.0, 5.0]];
        // Scalar dest r3 mask x; vector max masked out (its const
        // sources read zeros, harmless).
        let d = [triple(0, 0, 3, 1, 2, 0)[0], 0, (2 << 24)];
        eval_alu(&mut core, &consts, &parse_alu(&d)).unwrap();
        assert_eq!(core.previous_scalar, 12.0);
        assert_eq!(core.temps[3][0], 12.0);
    }

    #[test]
    fn d3d_zero_rules_and_nan() {
        let mut core = ShaderCore::default();
        core.temps[4] = [0.0, 2.0, f32::NAN, -0.0];
        core.temps[5] = [5.0, 0.0, 1.0, 7.0];
        // mul r1.xyzw, r4, r5 (all-temp sources).
        let d = [
            triple(1, 0xF, 0, 0, 1, 50)[0],
            0,
            (1 << 24) | (4 << 16) | (5 << 8) | (1 << 31) | (1 << 30),
        ];
        eval_alu(&mut core, &[], &parse_alu(&d)).unwrap();
        assert_eq!(core.temps[1][0], 0.0);
        assert!(core.temps[1][0].is_sign_positive());
        assert_eq!(core.temps[1][1], 0.0);
        // NaN is truthy (only 0/flushed-denormal zeroes): propagates.
        assert!(core.temps[1][2].is_nan());
        assert_eq!(core.temps[1][3], 0.0);
        // max keeps NaN in a (isgreaterequal semantics).
        let d = [
            triple(2, 0xF, 0, 0, 2, 50)[0],
            0,
            (2 << 24) | (4 << 16) | (5 << 8) | (1 << 31) | (1 << 30),
        ];
        eval_alu(&mut core, &[], &parse_alu(&d)).unwrap();
        assert_eq!(core.temps[2][0], 5.0);
        assert_eq!(core.temps[2][1], 2.0);
        assert!(core.temps[2][2].is_nan());
        assert_eq!(core.temps[2][3], 7.0);
        // Scalar clamp turns NaN previous_scalar into +0.
        let consts = [[0.0, 0.0, 0.0, f32::NAN]];
        // adds r3.x from c0 (a=W=NaN, b=X=0.0), clamped.
        let d = [triple(0, 0, 3, 1, 2, 0)[0] | (1 << 25), 0, (2 << 24)];
        eval_alu(&mut core, &consts, &parse_alu(&d)).unwrap();
        assert!(core.previous_scalar.is_nan());
        assert_eq!(core.temps[3][0], 0.0);
        assert!(core.temps[3][0].is_sign_positive());
    }

    #[test]
    fn scalar_transcendentals_exact() {
        // Scalar op template: dest r3.x, vector max masked out.
        fn op(sop: u32) -> [u32; 3] {
            [(3 << 8) | (1 << 20) | ((sop & 0x3F) << 26), 0, (2 << 24)]
        }
        let mut core = ShaderCore::default();
        // rcp(4.0) = 0.25 exactly (no low mantissa bits to reduce).
        eval_alu(&mut core, &[[0.0, 0.0, 0.0, 4.0]], &parse_alu(&op(19))).unwrap();
        assert_eq!(core.previous_scalar, 0.25);
        // rcp(3.0): 1/3 rounds to 0x3EAAAAAC at 21 mantissa bits.
        eval_alu(&mut core, &[[0.0, 0.0, 0.0, 3.0]], &parse_alu(&op(19))).unwrap();
        assert_eq!(core.previous_scalar.to_bits(), 0x3EAA_AAAC);
        // Fixups: rcpc(0)=+MAX, rcpf(0)=+0, rsqf(-0)=-0, logc(0)=-MAX.
        eval_alu(&mut core, &[[0.0, 0.0, 0.0, 0.0]], &parse_alu(&op(17))).unwrap();
        assert_eq!(core.previous_scalar, f32::MAX);
        eval_alu(&mut core, &[[0.0, 0.0, 0.0, 0.0]], &parse_alu(&op(18))).unwrap();
        assert_eq!(core.previous_scalar, 0.0);
        assert!(core.previous_scalar.is_sign_positive());
        eval_alu(&mut core, &[[0.0, 0.0, 0.0, -0.0]], &parse_alu(&op(21))).unwrap();
        assert_eq!(core.previous_scalar, -0.0);
        assert!(core.previous_scalar.is_sign_negative());
        eval_alu(&mut core, &[[0.0, 0.0, 0.0, 0.0]], &parse_alu(&op(15))).unwrap();
        assert_eq!(core.previous_scalar, -f32::MAX);
        // Exact small cases: logc(1)=0, sin(0)=0, cos(0)=1, sqrt(4)=2.
        eval_alu(&mut core, &[[0.0, 0.0, 0.0, 1.0]], &parse_alu(&op(15))).unwrap();
        assert_eq!(core.previous_scalar, 0.0);
        eval_alu(&mut core, &[[0.0, 0.0, 0.0, 0.0]], &parse_alu(&op(48))).unwrap();
        assert_eq!(core.previous_scalar, 0.0);
        eval_alu(&mut core, &[[0.0, 0.0, 0.0, 0.0]], &parse_alu(&op(49))).unwrap();
        assert_eq!(core.previous_scalar, 1.0);
        eval_alu(&mut core, &[[0.0, 0.0, 0.0, 4.0]], &parse_alu(&op(40))).unwrap();
        assert_eq!(core.previous_scalar, 2.0);
    }

    #[test]
    fn setp_predicate_and_prev_chain() {
        fn op(sop: u32) -> [u32; 3] {
            [(3 << 8) | (1 << 20) | ((sop & 0x3F) << 26), 0, (2 << 24)]
        }
        let mut core = ShaderCore::default();
        // setp_gt on c0.w = 5.0: predicate true, ps = 0.0.
        eval_alu(&mut core, &[[0.0, 0.0, 0.0, 5.0]], &parse_alu(&op(29))).unwrap();
        assert!(core.predicate);
        assert_eq!(core.previous_scalar, 0.0);
        // setp_eq on c0.w = 5.0: predicate false, ps = 1.0.
        eval_alu(&mut core, &[[0.0, 0.0, 0.0, 5.0]], &parse_alu(&op(27))).unwrap();
        assert!(!core.predicate);
        assert_eq!(core.previous_scalar, 1.0);
        // adds_prev chains onto ps = 1.0: 5.0 + 1.0 = 6.0.
        eval_alu(&mut core, &[[0.0, 0.0, 0.0, 5.0]], &parse_alu(&op(1))).unwrap();
        assert_eq!(core.previous_scalar, 6.0);
        // maxas sets a0 = floor(5.0 + 0.5) = 5 and max(a, b).
        eval_alu(&mut core, &[[0.0, 0.0, 0.0, 5.0]], &parse_alu(&op(23))).unwrap();
        assert_eq!(core.address_register, 5);
        // setp_clr clears predicate with ps = MAX.
        eval_alu(&mut core, &[[0.0, 0.0, 0.0, 0.0]], &parse_alu(&op(33))).unwrap();
        assert!(!core.predicate);
        assert_eq!(core.previous_scalar, f32::MAX);
    }

    #[test]
    fn scalar_const_reg_form() {
        // mulsc0: c0.w=3.0 times r4.x=4.0 (temp index derived as
        // (42&1)|(0<<1)|(0x04&0x3C) = 4; swizzle picks W and X).
        let mut core = ShaderCore::default();
        core.temps[4] = [4.0, 0.0, 0.0, 0.0];
        let consts = [[0.0, 0.0, 0.0, 3.0]];
        let d = [(3 << 8) | (1 << 20) | (42 << 26), 0x04, (2 << 24)];
        eval_alu(&mut core, &consts, &parse_alu(&d)).unwrap();
        assert_eq!(core.previous_scalar, 12.0);
        assert_eq!(core.temps[3][0], 12.0);
        // subsc0: 3.0 - 4.0 = -1.0.
        let d = [(3 << 8) | (1 << 20) | (46 << 26), 0x04, (2 << 24)];
        eval_alu(&mut core, &consts, &parse_alu(&d)).unwrap();
        assert_eq!(core.previous_scalar, -1.0);
    }

    #[test]
    fn vector_cnd_dst_max4_setppush() {
        // cndEq r1, r4, r5, r6: op0==0 picks op1 else op2.
        let mut core = ShaderCore::default();
        core.temps[4] = [0.0, 1.0, 0.0, 1.0];
        core.temps[5] = [10.0, 11.0, 12.0, 13.0];
        core.temps[6] = [20.0, 21.0, 22.0, 23.0];
        let temps3 = (1 << 31) | (1 << 30) | (1 << 29);
        let d = [
            triple(1, 0xF, 0, 0, 12, 50)[0],
            0,
            (12 << 24) | (4 << 16) | (5 << 8) | 6 | temps3,
        ];
        eval_alu(&mut core, &[], &parse_alu(&d)).unwrap();
        assert_eq!(core.temps[1], [10.0, 21.0, 12.0, 23.0]);
        // dst r2, r4, r5: [1, y0*y1, z0, w1] = [1, 11, 0, 13].
        let d = [
            triple(2, 0xF, 0, 0, 28, 50)[0],
            0,
            (28 << 24) | (4 << 16) | (5 << 8) | (1 << 31) | (1 << 30),
        ];
        eval_alu(&mut core, &[], &parse_alu(&d)).unwrap();
        assert_eq!(core.temps[2], [1.0, 11.0, 0.0, 13.0]);
        // max4 r3, r4 (r4 = [1,5,3,4]) replicates 5.
        core.temps[4] = [1.0, 5.0, 3.0, 4.0];
        let d = [
            triple(3, 0xF, 0, 0, 19, 50)[0],
            0,
            (19 << 24) | (4 << 16) | (1 << 31),
        ];
        eval_alu(&mut core, &[], &parse_alu(&d)).unwrap();
        assert_eq!(core.temps[3], [5.0, 5.0, 5.0, 5.0]);
        // setp_eq_push r4.x=7: predicate (w: 0==0 && 0==0), result 8.
        core.temps[4] = [7.0, 0.0, 0.0, 0.0];
        core.temps[5] = [0.0, 0.0, 0.0, 0.0];
        let d = [
            triple(1, 0xF, 0, 0, 20, 50)[0],
            0,
            (20 << 24) | (4 << 16) | (5 << 8) | (1 << 31) | (1 << 30),
        ];
        eval_alu(&mut core, &[], &parse_alu(&d)).unwrap();
        assert!(core.predicate);
        assert_eq!(core.temps[1], [8.0, 8.0, 8.0, 8.0]);
    }

    #[test]
    fn scalar_compare_fraction_batch() {
        fn op(sop: u32) -> [u32; 3] {
            [(3 << 8) | (1 << 20) | ((sop & 0x3F) << 26), 0, (2 << 24)]
        }
        let mut core = ShaderCore::default();
        // maxs keeps NaN in a; mins picks the lesser.
        eval_alu(&mut core, &[[0.0, 0.0, 0.0, f32::NAN]], &parse_alu(&op(5))).unwrap();
        assert!(core.previous_scalar.is_nan());
        eval_alu(&mut core, &[[0.0, 0.0, 0.0, 2.0]], &parse_alu(&op(6))).unwrap();
        assert_eq!(core.previous_scalar, 0.0);
        // seqs/sgts/sges/snes on c0.w: 0.0 -> [1,0,1,0].
        for (sop, want) in [(7, 1.0), (8, 0.0), (9, 1.0), (10, 0.0)] {
            eval_alu(&mut core, &[[0.0, 0.0, 0.0, 0.0]], &parse_alu(&op(sop))).unwrap();
            assert_eq!(core.previous_scalar, want);
        }
        // frcs(-1.5) = 0.5; truncs/floors exact.
        eval_alu(&mut core, &[[0.0, 0.0, 0.0, -1.5]], &parse_alu(&op(11))).unwrap();
        assert_eq!(core.previous_scalar, 0.5);
        eval_alu(&mut core, &[[0.0, 0.0, 0.0, -1.5]], &parse_alu(&op(12))).unwrap();
        assert_eq!(core.previous_scalar, -1.0);
        eval_alu(&mut core, &[[0.0, 0.0, 0.0, -1.5]], &parse_alu(&op(13))).unwrap();
        assert_eq!(core.previous_scalar, -2.0);
    }

    #[test]
    fn predicated_alu_skips() {
        // add r1, r4, r5 with predicate required true, core false:
        // skipped, temps and ps untouched.
        let mut core = ShaderCore::default();
        core.temps[4] = [1.0, 1.0, 1.0, 1.0];
        core.temps[5] = [2.0, 2.0, 2.0, 2.0];
        core.predicate = false;
        // d1: is_predicated bit 28 + pred_condition bit 27.
        let d = [
            (1 & 0x3F) | ((0xF) << 16) | ((50 & 0x3F) << 26),
            (1 << 28) | (1 << 27),
            (4 << 16) | (5 << 8) | (1 << 31) | (1 << 30),
        ];
        eval_alu(&mut core, &[], &parse_alu(&d)).unwrap();
        assert_eq!(core.temps[1], [0.0; 4]);
        // Same with matching predicate: executes.
        core.predicate = true;
        eval_alu(&mut core, &[], &parse_alu(&d)).unwrap();
        assert_eq!(core.temps[1], [3.0, 3.0, 3.0, 3.0]);
    }

    /// Two-pair upload builder: pair0 = CF (exec + nop), pair1 =
    /// one ALU clause triple.
    fn cf_upload(cf_word0: u32, cf_d1lo: u32, alu: [u32; 3]) -> Vec<u32> {
        vec![cf_word0, cf_d1lo, 0x0000_0000, alu[0], alu[1], alu[2]]
    }

    #[test]
    fn cf_driver_runs_straight_line() {
        // exec @1 x1 (ALU): mad r1.xyzw = r4*r5 + r6.
        let mut core = ShaderCore::default();
        core.temps[4] = [1.0, 2.0, 3.0, 4.0];
        core.temps[5] = [10.0, 10.0, 10.0, 10.0];
        core.temps[6] = [100.0, 100.0, 100.0, 100.0];
        let alu = [
            (1 & 0x3F) | (0xF << 16) | ((50 & 0x3F) << 26),
            0,
            (11 << 24) | (4 << 16) | (5 << 8) | 6 | (1 << 31) | (1 << 30) | (1 << 29),
        ];
        let words = cf_upload(0x0000_1001, 0x0000_1200, alu);
        let st = run_cf(&mut core, &words, &[], &[]).unwrap();
        assert_eq!((st.cf_visited, st.alu_executed, st.ended), (2, 1, false));
        assert_eq!(core.temps[1], [110.0, 120.0, 130.0, 140.0]);
    }

    #[test]
    fn cf_driver_gating_and_errors() {
        // cexec @1 x1 gated on bool5 == true; bool clear -> skip.
        let alu = [
            (1 & 0x3F) | (0xF << 16) | ((50 & 0x3F) << 26),
            0,
            (4 << 16) | (5 << 8) | (1 << 31) | (1 << 30),
        ];
        let words = cf_upload(0x0000_1001, 0x0000_3414, alu);
        let mut core = ShaderCore::default();
        core.temps[4] = [1.0, 1.0, 1.0, 1.0];
        core.temps[5] = [2.0, 2.0, 2.0, 2.0];
        let st = run_cf(&mut core, &words, &[], &[0]).unwrap();
        assert_eq!((st.alu_executed, st.ended), (0, false));
        assert_eq!(core.temps[1], [0.0; 4]);
        let st = run_cf(&mut core, &words, &[], &[1 << 5]).unwrap();
        assert_eq!(st.alu_executed, 1);
        assert_eq!(core.temps[1], [3.0, 3.0, 3.0, 3.0]);
        // Texture-fetch slot writes zeros with dest swizzle (reference
        // non-vertex fallback), never silent: tfetch2D r3 <- zeros.
        let tfetch = [
            (1 & 0x1F) | ((7 & 0x3F) << 5) | ((3 & 0x3F) << 12) | ((11 & 0x1F) << 20),
            0x0000_01E8,
            (1 << 14),
        ];
        let words = cf_upload(0x0001_1001, 0x0000_1200, tfetch);
        let mut core = ShaderCore::default();
        core.temps[3] = [9.0, 9.0, 9.0, 9.0];
        let st = run_cf(&mut core, &words, &[], &[]).unwrap();
        assert_eq!((st.fetch_executed, st.alu_executed), (1, 0));
        // Swizzle 0x1E8: x<-X(0), y<-1, z<-keep(9), w<-X(0).
        assert_eq!(core.temps[3], [0.0, 1.0, 9.0, 0.0]);
        // Vertex-fetch slot needs draw-backend memory, explicit error.
        let vfetch = [((7 & 0x3F) << 5) | ((3 & 0x3F) << 12), 0, 0];
        let words = cf_upload(0x0001_1001, 0x0000_1200, vfetch);
        let mut core = ShaderCore::default();
        let err = run_cf(&mut core, &words, &[], &[]).unwrap_err();
        assert!(err.to_string().contains("vfetch"));
        // Loop start with no loop words reads count 0 and skips
        // forward to the exec (target 2).
        let p0 = cf_pair((7, 0x0000_0002, 0), (0, 0, 0));
        let p1 = cf_pair((1, exec_w0(2, 1), 0), (2, exec_w0(2, 0), 0));
        let mut words = vec![p0[0], p0[1], p0[2], p1[0], p1[1], p1[2]];
        words.extend_from_slice(&alu);
        let mut core = ShaderCore::default();
        core.temps[4] = [1.0, 1.0, 1.0, 1.0];
        core.temps[5] = [2.0, 2.0, 2.0, 2.0];
        let st = run_cf(&mut core, &words, &[], &[]).unwrap();
        assert_eq!((st.cf_visited, st.alu_executed, st.ctrl_taken), (3, 1, 1));
        assert_eq!(core.temps[1], [3.0, 3.0, 3.0, 3.0]);
        // Malformed jump target is an explicit error, never a wrap.
        let p0 = cf_pair((11, 0x0000_2009, 0), (0, 0, 0));
        let p1 = cf_pair((2, exec_w0(2, 0), 0), (0, 0, 0));
        let mut words = vec![p0[0], p0[1], p0[2], p1[0], p1[1], p1[2]];
        words.extend_from_slice(&alu);
        let mut core = ShaderCore::default();
        let err = run_cf(&mut core, &words, &[], &[]).unwrap_err();
        assert!(err.to_string().contains("out of range"));
    }

    /// CF pair encoder (reference `UnpackControlFlowInstructions`
    /// inverse): two (opcode, word0, word1) instructions share the
    /// middle dword.
    fn cf_pair(a: (u32, u32, u32), b: (u32, u32, u32)) -> [u32; 3] {
        let aw1 = ((a.0 & 0xF) << 12) | (a.2 & 0xFFF);
        let bw1 = ((b.0 & 0xF) << 12) | (b.2 & 0xFFF);
        [
            a.1,
            aw1 | ((b.1 & 0xFFFF) << 16),
            ((b.1 >> 16) & 0xFFFF) | ((bw1 & 0xFFFF) << 16),
        ]
    }

    /// Exec word0 for `address @slot count n` (ALU sequence).
    fn exec_w0(slot: u32, n: u32) -> u32 {
        (slot & 0xFFF) | ((n & 7) << 12)
    }

    #[test]
    fn cf_loops_iterate_and_skip() {
        // add r1, r1, r4 accumulating over 3 loop trips.
        let alu = [
            (1 & 0x3F) | (0xF << 16) | ((50 & 0x3F) << 26),
            0,
            (1 << 16) | (4 << 8) | (1 << 31) | (1 << 30),
        ];
        // CF: loop(id0, skip->3) / exec @2 x1 / endloop(body->1) / exece end.
        let p0 = cf_pair((7, 0x0000_0003, 0), (1, exec_w0(2, 1), 0));
        let p1 = cf_pair((8, 0x0000_0001, 0), (2, exec_w0(2, 0), 0));
        let mut words = vec![p0[0], p0[1], p0[2], p1[0], p1[1], p1[2]];
        words.extend_from_slice(&alu);
        let mut core = ShaderCore::default();
        core.temps[4] = [1.0, 1.0, 1.0, 1.0];
        // Loop id 0: count 3, start 0, step 0.
        let st = run_cf_loops(&mut core, &words, &[], &[], &[3]).unwrap();
        assert_eq!(core.temps[1], [3.0, 3.0, 3.0, 3.0]);
        assert_eq!((st.cf_visited, st.alu_executed, st.ended), (8, 3, true));
        assert_eq!(st.ctrl_taken, 2);
        assert_eq!(core.loop_depth, 0);
        // Count 0 skips the body entirely.
        let mut core = ShaderCore::default();
        core.temps[4] = [1.0, 1.0, 1.0, 1.0];
        let st = run_cf_loops(&mut core, &words, &[], &[], &[0]).unwrap();
        assert_eq!((st.alu_executed, st.ctrl_taken, st.ended), (0, 1, true));
        assert_eq!(core.temps[1], [0.0; 4]);
    }

    #[test]
    fn cf_calls_jumps_and_returns() {
        // add r1, r4, r5 in the subroutine slot.
        let alu = [
            (1 & 0x3F) | (0xF << 16) | ((50 & 0x3F) << 26),
            0,
            (4 << 16) | (5 << 8) | (1 << 31) | (1 << 30),
        ];
        // CF: call ->2 / exece end / exec @2 x1 / ret.
        let p0 = cf_pair((9, 0x0000_2002, 0), (2, exec_w0(2, 0), 0));
        let p1 = cf_pair((1, exec_w0(2, 1), 0), (10, 0, 0));
        let mut words = vec![p0[0], p0[1], p0[2], p1[0], p1[1], p1[2]];
        words.extend_from_slice(&alu);
        let mut core = ShaderCore::default();
        core.temps[4] = [1.0, 1.0, 1.0, 1.0];
        core.temps[5] = [2.0, 2.0, 2.0, 2.0];
        let st = run_cf(&mut core, &words, &[], &[]).unwrap();
        assert_eq!(core.temps[1], [3.0, 3.0, 3.0, 3.0]);
        assert_eq!(
            (st.cf_visited, st.alu_executed, st.ctrl_taken, st.ended),
            (4, 1, 2, true)
        );
        // Unconditional jump skips the middle exec.
        let p0 = cf_pair((11, 0x0000_2002, 0), (1, exec_w0(2, 1), 0));
        let p1 = cf_pair((2, exec_w0(2, 0), 0), (0, 0, 0));
        let mut words = vec![p0[0], p0[1], p0[2], p1[0], p1[1], p1[2]];
        words.extend_from_slice(&alu);
        let mut core = ShaderCore::default();
        core.temps[4] = [1.0, 1.0, 1.0, 1.0];
        core.temps[5] = [2.0, 2.0, 2.0, 2.0];
        let st = run_cf(&mut core, &words, &[], &[]).unwrap();
        assert_eq!(
            (st.cf_visited, st.alu_executed, st.ctrl_taken, st.ended),
            (2, 0, 1, true)
        );
        // Gated conditional jump falls through when the bool is clear.
        let jmp_w1 = (5u32 << 2) | (1 << 10);
        let p0 = cf_pair((11, 0x0000_0002, jmp_w1), (1, exec_w0(2, 1), 0));
        let p1 = cf_pair((2, exec_w0(2, 0), 0), (0, 0, 0));
        let mut words = vec![p0[0], p0[1], p0[2], p1[0], p1[1], p1[2]];
        words.extend_from_slice(&alu);
        let mut core = ShaderCore::default();
        core.temps[4] = [1.0, 1.0, 1.0, 1.0];
        core.temps[5] = [2.0, 2.0, 2.0, 2.0];
        let st = run_cf(&mut core, &words, &[], &[0]).unwrap();
        assert_eq!((st.cf_visited, st.alu_executed, st.ctrl_taken), (3, 1, 0));
        assert_eq!(core.temps[1], [3.0, 3.0, 3.0, 3.0]);
        let mut core = ShaderCore::default();
        core.temps[4] = [1.0, 1.0, 1.0, 1.0];
        core.temps[5] = [2.0, 2.0, 2.0, 2.0];
        let st = run_cf(&mut core, &words, &[], &[1 << 5]).unwrap();
        assert_eq!((st.cf_visited, st.ctrl_taken), (2, 1));
    }

    #[test]
    fn loop_constant_bits_decode() {
        let lc = LoopConstant::from_bits(3 | (1 << 8) | (2 << 16));
        assert_eq!((lc.count, lc.start, lc.step), (3, 1, 2));
        let lc = LoopConstant::from_bits(1 | (0xFE << 16));
        assert_eq!((lc.count, lc.start, lc.step), (1, 0, -2));
    }

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn temp_relative_loop_address() {
        // aL = iter * step + start, clamped to [-256, 256]; 0 idle.
        let mut core = ShaderCore::default();
        assert_eq!(core.loop_address(), 0);
        core.loop_depth = 1;
        core.loop_constants[0] = LoopConstant {
            count: 4,
            start: 2,
            step: 1,
        };
        core.loop_iters[0] = 1;
        assert_eq!(core.loop_address(), 3);
        // Clamp high/low.
        core.loop_constants[0] = LoopConstant {
            count: 4,
            start: 250,
            step: 10,
        };
        core.loop_iters[0] = 1;
        assert_eq!(core.loop_address(), 256);
        core.loop_constants[0] = LoopConstant {
            count: 40,
            start: 0,
            step: -10,
        };
        core.loop_iters[0] = 30;
        assert_eq!(core.loop_address(), -256);
        // Depth guard reads 0.
        core.loop_depth = 0;
        assert_eq!(core.loop_address(), 0);
        core.loop_depth = 4;
        assert_eq!(core.loop_address(), 0);
        // Wrap: (63 + 2) & 63 == 1.
        core.loop_depth = 1;
        core.loop_constants[0] = LoopConstant {
            count: 4,
            start: 2,
            step: 0,
        };
        core.loop_iters[0] = 0;
        assert_eq!(core.temp_index(63, true), 1);
        assert_eq!(core.temp_index(63, false), 63);
        // Negative aL wraps too: (1 - 2) mod 64 == 63.
        core.loop_constants[0] = LoopConstant {
            count: 4,
            start: -2,
            step: 0,
        };
        assert_eq!(core.temp_index(1, true), 63);
    }

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn alu_temp_relative_sources_and_dest() {
        // Source relative: aL=1, src1 base 4 + rel reads r5.
        let mut core = ShaderCore::default();
        core.loop_depth = 1;
        core.loop_constants[0] = LoopConstant {
            count: 2,
            start: 1,
            step: 0,
        };
        core.temps[4] = [1.0, 1.0, 1.0, 1.0];
        core.temps[5] = [7.0, 7.0, 7.0, 7.0];
        core.temps[6] = [1.0, 1.0, 1.0, 1.0];
        // add r1, r4+rel, r6.
        let d0 = triple(1, 0xF, 0, 0, 0, 50)[0];
        let d2 = ((4 | 0x40) << 16) | (6 << 8) | (1 << 31) | (1 << 30);
        eval_alu(&mut core, &[], &parse_alu(&[d0, 0, d2])).unwrap();
        assert_eq!(core.temps[1], [8.0, 8.0, 8.0, 8.0]);
        // Dest relative: aL=2, vd base 1 + rel writes r3.
        let mut core = ShaderCore::default();
        core.loop_depth = 1;
        core.loop_constants[0] = LoopConstant {
            count: 4,
            start: 2,
            step: 0,
        };
        core.temps[4] = [1.0, 2.0, 3.0, 4.0];
        core.temps[5] = [10.0, 20.0, 30.0, 40.0];
        let d0 = (1 & 0x3F) | (1 << 6) | (0xF << 16) | ((50 & 0x3F) << 26);
        let d2 = (4 << 16) | (5 << 8) | (1 << 31) | (1 << 30);
        eval_alu(&mut core, &[], &parse_alu(&[d0, 0, d2])).unwrap();
        assert_eq!(core.temps[3], [11.0, 22.0, 33.0, 44.0]);
        assert_eq!(core.temps[1], [0.0; 4]);
    }

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn alu_const_relative_a0_and_loop() {
        // Vector add r1 = c(src1) + r5, src1 const-relative.
        // d1 bit31 = const_0_rel_abs, bit29 = a0-vs-aL.
        let consts = [
            [10.0, 0.0, 0.0, 0.0],
            [20.0, 0.0, 0.0, 0.0],
            [30.0, 0.0, 0.0, 0.0],
        ];
        // a0 path: c0 + a0(2) reads c2.
        let mut core = ShaderCore::default();
        core.address_register = 2;
        core.temps[5] = [1.0, 1.0, 1.0, 1.0];
        let d0 = triple(1, 0xF, 0, 0, 0, 50)[0];
        let d1 = (1 << 31) | (1 << 29);
        let d2 = (5 << 8) | (1 << 30);
        eval_alu(&mut core, &consts, &parse_alu(&[d0, d1, d2])).unwrap();
        assert_eq!(core.temps[1], [31.0, 1.0, 1.0, 1.0]);
        // aL path: c0 + aL(1) reads c1 (a0 ignored).
        let mut core = ShaderCore::default();
        core.address_register = 99;
        core.loop_depth = 1;
        core.loop_constants[0] = LoopConstant {
            count: 2,
            start: 1,
            step: 0,
        };
        core.temps[5] = [1.0, 1.0, 1.0, 1.0];
        let d1 = 1 << 31;
        eval_alu(&mut core, &consts, &parse_alu(&[d0, d1, d2])).unwrap();
        assert_eq!(core.temps[1], [21.0, 1.0, 1.0, 1.0]);
        // Negative effective index reads zeros.
        let mut core = ShaderCore::default();
        core.address_register = -5;
        core.temps[5] = [1.0, 1.0, 1.0, 1.0];
        let d1 = (1 << 31) | (1 << 29);
        eval_alu(&mut core, &consts, &parse_alu(&[d0, d1, d2])).unwrap();
        assert_eq!(core.temps[1], [1.0, 1.0, 1.0, 1.0]);
    }

    #[test]
    fn export_capture_component_select() {
        // Export to slot 3: x,w from vector add, y from scalar
        // adds, z constant-0 (scalar_dest_rel, neither mask).
        // vmask=0x9, smask=0x2.
        let mut core = ShaderCore::default();
        core.temps[4] = [1.0, 2.0, 3.0, 4.0];
        core.temps[5] = [10.0, 20.0, 30.0, 40.0];
        // d0: vd=3 | scalar_dest_rel bit14 | export bit15 |
        // vmask<<16 | smask<<20 | sop=adds(0).
        let d0 = 3 | (1 << 14) | (1 << 15) | (0x9 << 16) | (0x2 << 20);
        // Vector add r4+r5 (temp sels); scalar src3 const (OOB -> 0).
        let d2 = (4 << 16) | (5 << 8) | (1 << 31) | (1 << 30);
        eval_alu(&mut core, &[], &parse_alu(&[d0, 0, d2])).unwrap();
        assert_eq!(core.exports[3], [11.0, 0.0, 0.0, 44.0]);
        assert_eq!(core.export_written[3], 0xF);
        // Temps untouched by exports.
        assert_eq!(core.temps[3], [0.0; 4]);
        // Constant-1: both masks set on z (vmask=0xF, smask=0x4).
        let mut core = ShaderCore::default();
        core.temps[4] = [1.0, 2.0, 3.0, 4.0];
        core.temps[5] = [10.0, 20.0, 30.0, 40.0];
        let d0 = 5 | (1 << 15) | (0xF << 16) | (0x4 << 20);
        eval_alu(&mut core, &[], &parse_alu(&[d0, 0, d2])).unwrap();
        assert_eq!(core.exports[5][2], 1.0);
        // Relative vector dest on an export is malformed, never
        // silently accepted.
        let d0 = 5 | (1 << 6) | (1 << 15) | (0xF << 16);
        assert!(eval_alu(&mut core, &[], &parse_alu(&[d0, 0, d2])).is_err());
    }
}
