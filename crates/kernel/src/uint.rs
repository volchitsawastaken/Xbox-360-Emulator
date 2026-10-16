//! CPU-side ALU clause interpreter (single invocation).
//!
//! Evaluation facts ported from the BSD-licensed Xenia
//! `shader_interpreter.cc` `ExecuteAluInstruction` (+ helpers):
//! - 64 temp registers (`kMaxShaderTempRegisters`), index wrapped
//!   mod 64; out-of-range float constants read as zeros.
//! - `FlushDenormal`: denormals become signed zero (only the sign
//!   bit survives).
//! - Operand modifiers are bitwise: absolute clears the f32 sign
//!   bit, negate flips it; swizzle selects per
//!   `GetSwizzledComponentIndex` (`((sw >> 2j) + j) & 3`).
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
//!   written through the component masks (non-export only).
//!
//! Scope (slice 1): absolute addressing only; no exports (explicit
//! error); vector add/mul/max/min/seq/sgt/sge/sne/frc/trunc/floor/
//! mad/dp4/dp3/dp2add; scalar adds/muls/subs/retain_prev. Everything
//! else is an explicit `Unsupported`, never a wrong result.
//! Predication is driver business (the reference skips predicated
//! instructions before evaluation); `eval_alu` executes
//! unconditionally.

use x360_common::{EmuError, Result};

use super::ucode::AluInstr;

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
}

impl Default for ShaderCore {
    fn default() -> Self {
        Self {
            temps: [[0.0; 4]; TEMP_COUNT],
            previous_scalar: 0.0,
            predicate: false,
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
/// vector-operand loop).
fn fetch_vec(core: &ShaderCore, consts: &[[f32; 4]], ins: &AluInstr, i: u32) -> Result<[f32; 4]> {
    let reg = ins.src_reg(i);
    let base: [f32; 4] = if ins.src_is_temp(i) {
        if reg & 0x40 != 0 {
            return Err(EmuError::Unsupported(
                "alu: relative temp addressing pending".into(),
            ));
        }
        core.temps[(reg & 0x3F) as usize]
    } else if (reg as usize) < consts.len() {
        consts[reg as usize]
    } else {
        [0.0; 4]
    };
    let sw = ins.src_swizzle(i);
    let mut out = [0.0f32; 4];
    for j in 0..4u32 {
        let mut c = flush_denormal(base[swizzled(sw, j)]);
        if reg & 0x80 != 0 && ins.src_is_temp(i) {
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
    let base: [f32; 4] = if ins.src_is_temp(3) {
        if reg & 0x40 != 0 {
            return Err(EmuError::Unsupported(
                "alu: relative temp addressing pending".into(),
            ));
        }
        let t = core.temps[(reg & 0x3F) as usize];
        let mut v = t;
        if reg & 0x80 != 0 {
            for c in v.iter_mut() {
                *c = f32_abs(*c);
            }
        }
        v
    } else if (reg as usize) < consts.len() {
        consts[reg as usize]
    } else {
        [0.0; 4]
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
/// scalar op + writeback; predicated-skip and exports excluded —
/// exports are an explicit error, predication is the driver's).
pub fn eval_alu(core: &mut ShaderCore, consts: &[[f32; 4]], ins: &AluInstr) -> Result<()> {
    if ins.has_relative_addressing() {
        return Err(EmuError::Unsupported(
            "alu: relative addressing pending".into(),
        ));
    }
    if ins.is_export() {
        return Err(EmuError::Unsupported("alu: export sink pending".into()));
    }
    let vop = ins.vector_opcode();
    // Sources needed per opcode (reference
    // `operand_components_used`; over-fetching is harmless but OOB
    // temp reads must never happen, so fetch exactly).
    let vec_sources: &[u32] = match vop {
        11 | 17 => &[1, 2, 3],
        8..=10 => &[1],
        0..=7 | 15 | 16 => &[1, 2],
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
        _ => {
            return Err(EmuError::Unsupported(format!(
                "alu: vector op {} pending",
                super::ucode::alu_vector_opcode_name(vop)
            )));
        }
    }
    let sop = ins.scalar_opcode();
    let vec_three = matches!(vop, 11 | 17);
    match sop {
        50 => {}
        0 | 2 | 25 => {
            let (a, b) = fetch_scalar_pair(core, consts, ins, vec_three)?;
            core.previous_scalar = match sop {
                0 => a + b,
                2 => d3d_mul(a, b),
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
    // Dest fields are 6 bits (always in range); relative dests
    // were rejected above, so no wrapping is needed here.
    let vd = (ins.vector_dest() & 0x3F) as usize;
    let vmask = ins.vector_write_mask();
    for (i, (t, v)) in core.temps[vd].iter_mut().zip(vr.iter()).enumerate() {
        if vmask & (1 << i) != 0 {
            *t = *v;
        }
    }
    let sd = (ins.scalar_dest() & 0x3F) as usize;
    let smask = ins.scalar_write_mask();
    for (i, t) in core.temps[sd].iter_mut().enumerate() {
        if smask & (1 << i) != 0 {
            *t = sr;
        }
    }
    Ok(())
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
}
