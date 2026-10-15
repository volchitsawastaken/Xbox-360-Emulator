//! Execute decoded instructions against thread + memory.
//!
//! Edge-behavior facts (sraw CA rule, fctiw NaN/VXCVI results,
//! single-precision rounding) follow the BSD-licensed Xenia
//! `ppc_emit_alu.cc` / `ppc_emit_fpu.cc` (facts only, all code
//! original).

use crate::decode::Decoded;
use crate::regs::ThreadState;
use x360_common::{EmuError, Result};
use x360_memory::Memory;

/// Syscall trap surfaced to the kernel.
#[derive(Debug, Clone, Copy)]
pub struct SyscallTrap {
    pub thread: usize,
    pub pc: u32,
}

fn ea_imm(ra: u32, t: &ThreadState, d: i16) -> u32 {
    let base = if ra == 0 {
        0
    } else {
        t.gpr[ra as usize] as u32
    };
    base.wrapping_add(d as i32 as u32)
}

/// Doubleword effective address: full 64-bit base plus the DS offset,
/// wrapped to the 32-bit guest map. Wrapping is load-bearing, not
/// sloppiness: retail code (Braid's boot memcpy) legitimately forms
/// transiently-negative 32-bit EAs (e.g. base `-8` + `8` reads address
/// 0), and the entire guest map — like the reference's `uint32_t`
/// memory system — is 32 bits. Discarded high bits are debug-logged.
/// Genuine wild pointers still fault at translation (unmapped/OOB).
fn ea_ds(t: &ThreadState, ra: u32, ds: i32) -> u32 {
    let base = if ra == 0 { 0 } else { t.gpr[ra as usize] };
    let ea64 = base.wrapping_add(ds as i64 as u64);
    if ea64 >> 32 != 0 {
        log::debug!("cpu: dword EA {:016x} wrapped to {:08x}", ea64, ea64 as u32);
    }
    ea64 as u32
}

fn ea_idx(ra: u32, rb: u32, t: &ThreadState) -> u32 {
    let base = if ra == 0 {
        0
    } else {
        t.gpr[ra as usize] as u32
    };
    base.wrapping_add(t.gpr[rb as usize] as u32)
}

fn cond_ok(bo: u32, bi: u32, t: &mut ThreadState) -> bool {
    // Decrement CTR if BO[2]==0. Used by bc/bclr only.
    if bo & 0b100 == 0 {
        t.ctr = t.ctr.wrapping_sub(1);
        let ctr_ok = if bo & 0b010 != 0 {
            t.ctr == 0
        } else {
            t.ctr != 0
        };
        if !ctr_ok {
            return false;
        }
    }
    cond_cr(bo, bi, t)
}

fn cond_ok_no_ctr(bo: u32, bi: u32, t: &ThreadState) -> bool {
    // bcctr/bcctr: CTR is the target, never decremented. Only CR test.
    cond_cr(bo, bi, t)
}

fn cond_cr(bo: u32, bi: u32, t: &ThreadState) -> bool {
    // Check CR bit if BO[0]==0.
    if bo & 0b10000 == 0 {
        let cr_bit = (t.cr.0 >> (31 - bi)) & 1;
        let expect = (bo >> 3) & 1;
        if cr_bit != expect {
            return false;
        }
    }
    true
}

fn update_cr0(t: &mut ThreadState, v: u32) {
    let so = t.xer.so();
    t.cr.set_cr0(v as i32, so);
}

/// CR field from an ordered comparison. SO copied from XER; XER otherwise
/// untouched (compares never set CA/OV).
fn update_cr_bf(t: &mut ThreadState, bf: u32, lt: bool, gt: bool, eq: bool) {
    let v = ((lt as u8) << 3) | ((gt as u8) << 2) | ((eq as u8) << 1) | (t.xer.so() as u8);
    t.cr.set_field(bf, v);
}

/// CR1 after a floating-point arithmetic Rc form. Exception bits are
/// unmodeled, so the summary reads 0 (documented, never a silent pass:
/// the zero is the honest value of unmodeled state).
fn fp_cr1_zero(t: &mut ThreadState) {
    t.cr.set_field(1, 0);
}

/// Round a double result to single when the primary-59 form ran.
fn fp_single(v: f64, single: bool) -> f64 {
    if single {
        (v as f32) as f64
    } else {
        v
    }
}

/// Float compare onto an arbitrary CR field; unordered (NaN) is FU.
/// fcmpu/fcmpo differ only in SNaN signaling, which is unmodeled.
fn fp_cmp(t: &mut ThreadState, bf: u32, a: f64, b: f64) {
    let v = if a.is_nan() || b.is_nan() {
        0b0001
    } else if a < b {
        0b1000
    } else if a > b {
        0b0100
    } else {
        0b0010
    };
    t.cr.set_field(bf, v);
}

/// fctiw/fctiwz core: double to int32 (nearest-even vs toward-zero),
/// NaN and out-of-range yield 0x80000000 (ISA VXCVI choice, matching
/// reference `InstrEmit_fctiwxx_` NaN case).
fn fp_to_i32(v: f64, to_zero: bool) -> i32 {
    if v.is_nan() {
        return i32::MIN;
    }
    let r = if to_zero {
        v.trunc()
    } else {
        v.round_ties_even()
    };
    if r < i32::MIN as f64 || r > i32::MAX as f64 {
        i32::MIN
    } else {
        r as i32
    }
}

/// fctid/fctidz core: double to int64, NaN and out-of-range yield
/// 0x8000000000000000 (reference `InstrEmit_fctidxx_` NaN case).
fn fp_to_i64(v: f64, to_zero: bool) -> i64 {
    if v.is_nan() {
        return i64::MIN;
    }
    let r = if to_zero {
        v.trunc()
    } else {
        v.round_ties_even()
    };
    if r < i64::MIN as f64 || r > i64::MAX as f64 {
        i64::MIN
    } else {
        r as i64
    }
}

fn cmp_signed(t: &mut ThreadState, bf: u32, a: i32, b: i32) {
    update_cr_bf(t, bf, a < b, a > b, a == b);
}

fn cmp_signed64(t: &mut ThreadState, bf: u32, a: i64, b: i64) {
    update_cr_bf(t, bf, a < b, a > b, a == b);
}

fn cmp_unsigned(t: &mut ThreadState, bf: u32, a: u32, b: u32) {
    update_cr_bf(t, bf, a < b, a > b, a == b);
}

fn cmp_unsigned64(t: &mut ThreadState, bf: u32, a: u64, b: u64) {
    update_cr_bf(t, bf, a < b, a > b, a == b);
}

/// Rotate-and-mask helper: 1s from MB to ME inclusive, wrapping at bit 0.
/// Bit numbering matches registers (bit 0 = MSB).
fn rlw_mask(mb: u32, me: u32) -> u32 {
    let mut mask = 0u32;
    let mut i = mb & 0x1F;
    loop {
        mask |= 1 << (31 - i);
        if i == (me & 0x1F) {
            break;
        }
        i = (i + 1) & 0x1F;
    }
    mask
}

/// 64-bit mask for MDS rotates: 1s from MB to ME inclusive, wrapping.
/// Bit 0 = MSB.
fn rld_mask(mb: u32, me: u32) -> u64 {
    let mut mask = 0u64;
    let mut i = mb & 0x3F;
    loop {
        mask |= 1 << (63 - i);
        if i == (me & 0x3F) {
            break;
        }
        i = (i + 1) & 0x3F;
    }
    mask
}

fn update_cr0_64(t: &mut ThreadState, v: u64) {
    let so = t.xer.so();
    t.cr.set_cr0_64(v as i64, so);
}

/// Read one CR bit by PowerPC bit number (0 = CR0.LT MSB .. 31 = CR7.SO).
fn cr_bit(t: &ThreadState, b: u32) -> u32 {
    (t.cr.0 >> (31 - b)) & 1
}

fn set_cr_bit(t: &mut ThreadState, b: u32, v: u32) {
    let shift = 31 - b;
    if v & 1 != 0 {
        t.cr.0 |= 1 << shift;
    } else {
        t.cr.0 &= !(1 << shift);
    }
}

/// Trap-condition test per PowerPC trap semantics (see reference
/// ppc_emit_control.cc InstrEmit_trap): TO bit 0x10 fires when a<b
/// signed, 0x08 when a>b signed, 0x04 when equal, 0x02 when a<b
/// unsigned, 0x01 when a>b unsigned.
fn trap_fires(to: u32, a: u32, b: u32) -> bool {
    if to & 0x10 != 0 && (a as i32) < b as i32 {
        return true;
    }
    if to & 0x08 != 0 && (a as i32) > b as i32 {
        return true;
    }
    if to & 0x04 != 0 && a == b {
        return true;
    }
    if to & 0x02 != 0 && a < b {
        return true;
    }
    if to & 0x01 != 0 && a > b {
        return true;
    }
    false
}

/// 64-bit twin for td/tdi (same TO layout over full GPRs).
fn trap_fires_64(to: u32, a: u64, b: u64) -> bool {
    if to & 0x10 != 0 && (a as i64) < b as i64 {
        return true;
    }
    if to & 0x08 != 0 && (a as i64) > b as i64 {
        return true;
    }
    if to & 0x04 != 0 && a == b {
        return true;
    }
    if to & 0x02 != 0 && a < b {
        return true;
    }
    if to & 0x01 != 0 && a > b {
        return true;
    }
    false
}

/// 32-bit shift-right-algebraic core shared by sraw/srawi.
/// Port of InstrEmit_srawx/InstrEmit_srawix (reference ppc_emit_alu.cc):
/// the result is the arithmetic shift and CA is set when the source is
/// negative and any shifted-out bit is 1 (cleared for a zero shift).
fn sraw_core(rs_val: u32, n: u32) -> (u32, bool) {
    let v = (rs_val as i32).wrapping_shr(n) as u32;
    let ca = n != 0 && rs_val >> 31 != 0 && v.wrapping_shl(n) != rs_val;
    (v, ca)
}

fn read_half_be(mem: &Memory, ea: u32) -> Result<u16> {
    if !ea.is_multiple_of(2) {
        return Err(EmuError::AlignmentFault { addr: ea });
    }
    let b = mem.read_bytes(ea, 2)?;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}

fn write_half_be(mem: &mut Memory, ea: u32, v: u16) -> Result<()> {
    if !ea.is_multiple_of(2) {
        return Err(EmuError::AlignmentFault { addr: ea });
    }
    mem.write_bytes(ea, &v.to_be_bytes())?;
    Ok(())
}

/// Execute one decoded instruction. Updates PC. Returns optional syscall.
pub fn execute(
    d: Decoded,
    word: u32,
    t: &mut ThreadState,
    mem: &mut Memory,
) -> Result<Option<SyscallTrap>> {
    let next = t.pc.wrapping_add(4);
    match d {
        Decoded::Nop => {
            t.pc = next;
            Ok(None)
        }
        Decoded::Addi { rt, ra, simm } => {
            // 64-bit (reference InstrEmit_addi): RT <- (RA) + EXTS(SI).
            let base = if ra == 0 { 0 } else { t.gpr[ra as usize] };
            t.gpr[rt as usize] = base.wrapping_add(simm as i64 as u64);
            t.pc = next;
            Ok(None)
        }
        Decoded::Addis { rt, ra, simm } => {
            // 64-bit (reference InstrEmit_addis).
            let base = if ra == 0 { 0 } else { t.gpr[ra as usize] };
            t.gpr[rt as usize] = base.wrapping_add(((simm as i64) << 16) as u64);
            t.pc = next;
            Ok(None)
        }
        Decoded::Ori { rs, ra, uimm } => {
            t.gpr[ra as usize] = ((t.gpr[rs as usize] as u32) | uimm as u32) as u64;
            t.pc = next;
            Ok(None)
        }
        Decoded::Oris { rs, ra, uimm } => {
            t.gpr[ra as usize] = ((t.gpr[rs as usize] as u32) | ((uimm as u32) << 16)) as u64;
            t.pc = next;
            Ok(None)
        }
        Decoded::Xoris { rs, ra, uimm } => {
            t.gpr[ra as usize] = ((t.gpr[rs as usize] as u32) ^ ((uimm as u32) << 16)) as u64;
            t.pc = next;
            Ok(None)
        }
        Decoded::Andi { rs, ra, uimm } => {
            let v = (t.gpr[rs as usize] as u32) & (uimm as u32);
            t.gpr[ra as usize] = (v) as u64;
            update_cr0(t, v);
            t.pc = next;
            Ok(None)
        }
        Decoded::Andis { rs, ra, uimm } => {
            let v = (t.gpr[rs as usize] as u32) & ((uimm as u32) << 16);
            t.gpr[ra as usize] = (v) as u64;
            update_cr0(t, v);
            t.pc = next;
            Ok(None)
        }
        Decoded::Mulli { rt, ra, simm } => {
            // 64-bit product, low 64 kept (reference InstrEmit_mulli).
            let v = (t.gpr[ra as usize] as i64).wrapping_mul(simm as i64) as u64;
            t.gpr[rt as usize] = v;
            t.pc = next;
            Ok(None)
        }
        Decoded::Cmpi { bf, l, ra, simm } => {
            // L=0 compares low 32 as signed; L=1 compares full 64
            // against the sign-extended immediate (reference
            // `InstrEmit_cmpi`).
            if l {
                cmp_signed64(t, bf, t.gpr[ra as usize] as i64, simm as i64);
            } else {
                cmp_signed(t, bf, (t.gpr[ra as usize] as u32) as i32, simm as i32);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Cmpli { bf, l, ra, uimm } => {
            // L=1 compares full 64 against the zero-extended immediate
            // (reference `InstrEmit_cmpli`: i48.0 || SI).
            if l {
                cmp_unsigned64(t, bf, t.gpr[ra as usize], uimm as u64);
            } else {
                cmp_unsigned(t, bf, t.gpr[ra as usize] as u32, uimm as u32);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Cmp { bf, l, ra, rb } => {
            // L selects 64-bit (full GPRs) vs 32-bit signed low halves
            // (reference `InstrEmit_cmp`).
            if l {
                cmp_signed64(t, bf, t.gpr[ra as usize] as i64, t.gpr[rb as usize] as i64);
            } else {
                cmp_signed(
                    t,
                    bf,
                    (t.gpr[ra as usize] as u32) as i32,
                    (t.gpr[rb as usize] as u32) as i32,
                );
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Cmpl { bf, l, ra, rb } => {
            // Unsigned twin of Cmp (reference `InstrEmit_cmpl`).
            if l {
                cmp_unsigned64(t, bf, t.gpr[ra as usize], t.gpr[rb as usize]);
            } else {
                cmp_unsigned(t, bf, t.gpr[ra as usize] as u32, t.gpr[rb as usize] as u32);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Rlwimi {
            rs,
            ra,
            sh,
            mb,
            me,
            rc,
        } => {
            let r = (t.gpr[rs as usize] as u32).rotate_left(sh);
            let mask = rlw_mask(mb, me);
            let v = (r & mask) | ((t.gpr[ra as usize] as u32) & !mask);
            t.gpr[ra as usize] = (v) as u64;
            if rc {
                update_cr0(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Rlwinm {
            rs,
            ra,
            sh,
            mb,
            me,
            rc,
        } => {
            let r = (t.gpr[rs as usize] as u32).rotate_left(sh);
            let v = r & rlw_mask(mb, me);
            t.gpr[ra as usize] = (v) as u64;
            if rc {
                update_cr0(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Rlwnm {
            rs,
            ra,
            rb,
            mb,
            me,
            rc,
        } => {
            let sh = (t.gpr[rb as usize] as u32) & 0x1F;
            let r = (t.gpr[rs as usize] as u32).rotate_left(sh);
            let v = r & rlw_mask(mb, me);
            t.gpr[ra as usize] = (v) as u64;
            if rc {
                update_cr0(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Subfic { rt, ra, simm } => {
            // 64-bit (reference InstrEmit_subficx): RT <- EXTS(SI) - (RA);
            // CA set on NOT-borrow out of bit 0. Only CA is affected.
            let b = simm as i64 as u64;
            let a = t.gpr[ra as usize];
            let (v, borrow) = b.overflowing_sub(a);
            t.xer.set_ca(!borrow);
            t.gpr[rt as usize] = v;
            t.pc = next;
            Ok(None)
        }
        Decoded::Addic { rt, ra, simm } => {
            // 64-bit (reference InstrEmit_addic): RT <- (RA) + EXTS(SI);
            // CA set on carry out of bit 0. Only CA is affected.
            let a = t.gpr[ra as usize];
            let total = a as u128 + (simm as i64 as u64) as u128;
            t.xer.set_ca(total > u64::MAX as u128);
            t.gpr[rt as usize] = total as u64;
            t.pc = next;
            Ok(None)
        }
        Decoded::Addic_ { rt, ra, simm } => {
            // 64-bit + CR0 (reference InstrEmit_addicx).
            let a = t.gpr[ra as usize];
            let total = a as u128 + (simm as i64 as u64) as u128;
            t.xer.set_ca(total > u64::MAX as u128);
            let v = total as u64;
            t.gpr[rt as usize] = v;
            update_cr0_64(t, v);
            t.pc = next;
            Ok(None)
        }
        Decoded::B { li, aa, lk } => {
            if lk {
                t.lr = next;
            }
            t.pc = if aa {
                li as u32
            } else {
                t.pc.wrapping_add(li as u32)
            };
            Ok(None)
        }
        Decoded::Bc { bo, bi, bd, aa, lk } => {
            let taken = cond_ok(bo, bi, t);
            let disp = ((bd as i32) << 16 >> 16) as u32;
            if lk {
                t.lr = next;
            }
            if taken {
                t.pc = if aa {
                    disp & !3
                } else {
                    t.pc.wrapping_add(disp & !3)
                };
                // bd is already <<0 with low bits zero; mask to word.
                let _ = disp;
            } else {
                t.pc = next;
            }
            Ok(None)
        }
        Decoded::Bclr { bo, bi, lk } => {
            let target = t.lr & !3;
            let taken = cond_ok(bo, bi, t);
            if lk {
                t.lr = next;
            }
            t.pc = if taken { target } else { next };
            Ok(None)
        }
        Decoded::Bcctr { bo, bi, lk } => {
            let target = t.ctr & !3;
            let taken = cond_ok_no_ctr(bo, bi, t);
            if lk {
                t.lr = next;
            }
            t.pc = if taken { target } else { next };
            Ok(None)
        }
        Decoded::Lwz { rt, ra, d } => {
            let ea = ea_imm(ra, t, d);
            let v = mem.read_u32(ea)?;
            t.gpr[rt as usize] = (v) as u64;
            t.pc = next;
            Ok(None)
        }
        Decoded::Lwzu { rt, ra, d } => {
            if ra == 0 || ra == rt {
                return Err(EmuError::Unsupported("lwzu with ra=0 or ra=rt".into()));
            }
            let ea = ea_imm(ra, t, d);
            let v = mem.read_u32(ea)?;
            t.gpr[rt as usize] = (v) as u64;
            t.gpr[ra as usize] = (ea) as u64;
            t.pc = next;
            Ok(None)
        }
        Decoded::Stw { rs, ra, d } => {
            let ea = ea_imm(ra, t, d);
            mem.write_u32(ea, t.gpr[rs as usize] as u32)?;
            t.pc = next;
            Ok(None)
        }
        Decoded::Stwu { rs, ra, d } => {
            if ra == 0 {
                return Err(EmuError::Unsupported("stwu with ra=0".into()));
            }
            let ea = ea_imm(ra, t, d);
            mem.write_u32(ea, t.gpr[rs as usize] as u32)?;
            t.gpr[ra as usize] = (ea) as u64;
            t.pc = next;
            Ok(None)
        }
        Decoded::Ld { rt, ra, ds } => {
            let ea = ea_ds(t, ra, ds);
            let v = mem.read_u64(ea)?;
            t.gpr[rt as usize] = v;
            t.pc = next;
            Ok(None)
        }
        Decoded::Ldu { rt, ra, ds } => {
            if ra == 0 || ra == rt {
                return Err(EmuError::Unsupported("ldu with ra=0 or ra=rt".into()));
            }
            let ea = ea_ds(t, ra, ds);
            let v = mem.read_u64(ea)?;
            t.gpr[rt as usize] = v;
            t.gpr[ra as usize] = ea as u64;
            t.pc = next;
            Ok(None)
        }
        Decoded::Std { rs, ra, ds } => {
            let ea = ea_ds(t, ra, ds);
            mem.write_u64(ea, t.gpr[rs as usize])?;
            t.pc = next;
            Ok(None)
        }
        Decoded::Stdu { rs, ra, ds } => {
            if ra == 0 {
                return Err(EmuError::Unsupported("stdu with ra=0".into()));
            }
            let ea = ea_ds(t, ra, ds);
            mem.write_u64(ea, t.gpr[rs as usize])?;
            t.gpr[ra as usize] = ea as u64;
            t.pc = next;
            Ok(None)
        }
        Decoded::Rldicl { rs, ra, sh, mb } => {
            let rot = t.gpr[rs as usize].rotate_left(sh);
            let v = rot & rld_mask(mb, 63);
            t.gpr[ra as usize] = v;
            t.pc = next;
            Ok(None)
        }
        Decoded::Rldicr { rs, ra, sh, me } => {
            let rot = t.gpr[rs as usize].rotate_left(sh);
            let v = rot & rld_mask(0, me);
            t.gpr[ra as usize] = v;
            t.pc = next;
            Ok(None)
        }
        Decoded::Rldic { rs, ra, sh, mb, rc } => {
            // Clear under MASK(mb, ~sh) (reference `InstrEmit_rldicx`).
            let rot = t.gpr[rs as usize].rotate_left(sh);
            let v = rot & rld_mask(mb, 64u32.wrapping_sub(sh) & 63);
            t.gpr[ra as usize] = v;
            if rc {
                update_cr0_64(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Rldimi { rs, ra, sh, mb, rc } => {
            // Insert under MASK(mb, ~sh) (reference `InstrEmit_rldimix`).
            let rot = t.gpr[rs as usize].rotate_left(sh);
            let mask = rld_mask(mb, 64u32.wrapping_sub(sh) & 63);
            let v = (rot & mask) | (t.gpr[ra as usize] & !mask);
            t.gpr[ra as usize] = v;
            if rc {
                update_cr0_64(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Extsw { rs, ra, rc } => {
            let v = (t.gpr[rs as usize] as u32) as i32 as i64 as u64;
            t.gpr[ra as usize] = v;
            if rc {
                update_cr0_64(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Cntlzd { rs, ra, rc } => {
            let v = t.gpr[rs as usize].leading_zeros() as u64;
            t.gpr[ra as usize] = v;
            if rc {
                update_cr0_64(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Lbz { rt, ra, d } => {
            let ea = ea_imm(ra, t, d);
            t.gpr[rt as usize] = (mem.read_u8(ea)? as u32) as u64;
            t.pc = next;
            Ok(None)
        }
        Decoded::Stb { rs, ra, d } => {
            let ea = ea_imm(ra, t, d);
            mem.write_u8(ea, (t.gpr[rs as usize] as u32) as u8)?;
            t.pc = next;
            Ok(None)
        }
        Decoded::Lhz { rt, ra, d } => {
            let ea = ea_imm(ra, t, d);
            if !ea.is_multiple_of(2) {
                return Err(EmuError::AlignmentFault { addr: ea });
            }
            let b = mem.read_bytes(ea, 2)?;
            t.gpr[rt as usize] = (((b[0] as u32) << 8) | b[1] as u32) as u64;
            t.pc = next;
            Ok(None)
        }
        Decoded::Sth { rs, ra, d } => {
            let ea = ea_imm(ra, t, d);
            if !ea.is_multiple_of(2) {
                return Err(EmuError::AlignmentFault { addr: ea });
            }
            let v = (t.gpr[rs as usize] as u32) as u16;
            mem.write_bytes(ea, &v.to_be_bytes())?;
            t.pc = next;
            Ok(None)
        }
        Decoded::Lmw { rt, ra, d } => {
            let mut ea = ea_imm(ra, t, d);
            for i in rt..32 {
                let v = mem.read_u32(ea)?;
                t.gpr[i as usize] = (v) as u64;
                ea = ea.wrapping_add(4);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Stmw { rs, ra, d } => {
            let mut ea = ea_imm(ra, t, d);
            for i in rs..32 {
                mem.write_u32(ea, t.gpr[i as usize] as u32)?;
                ea = ea.wrapping_add(4);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Lfs { frt, ra, d } => {
            let ea = ea_imm(ra, t, d);
            let b = mem.read_bytes(ea, 4)?;
            let v = f32::from_be_bytes([b[0], b[1], b[2], b[3]]);
            t.fpr[frt as usize] = v as f64;
            t.pc = next;
            Ok(None)
        }
        Decoded::Lfsu { frt, ra, d } => {
            if ra == 0 {
                return Err(EmuError::Unsupported(format!(
                    "lfsu with ra=0 word={:08x} pc={:08x}",
                    word, t.pc
                )));
            }
            let ea = ea_imm(ra, t, d);
            let b = mem.read_bytes(ea, 4)?;
            let v = f32::from_be_bytes([b[0], b[1], b[2], b[3]]);
            t.fpr[frt as usize] = v as f64;
            t.gpr[ra as usize] = ea as u64;
            t.pc = next;
            Ok(None)
        }
        Decoded::Lfd { frt, ra, d } => {
            let ea = ea_imm(ra, t, d);
            let b = mem.read_bytes(ea, 8)?;
            t.fpr[frt as usize] =
                f64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
            t.pc = next;
            Ok(None)
        }
        Decoded::Lfdu { frt, ra, d } => {
            if ra == 0 {
                return Err(EmuError::Unsupported(format!(
                    "lfdu with ra=0 word={:08x} pc={:08x}",
                    word, t.pc
                )));
            }
            let ea = ea_imm(ra, t, d);
            let b = mem.read_bytes(ea, 8)?;
            t.fpr[frt as usize] =
                f64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
            t.gpr[ra as usize] = ea as u64;
            t.pc = next;
            Ok(None)
        }
        Decoded::Stfs { frs, ra, d } => {
            let ea = ea_imm(ra, t, d);
            let v = t.fpr[frs as usize] as f32;
            mem.write_bytes(ea, &v.to_be_bytes())?;
            t.pc = next;
            Ok(None)
        }
        Decoded::Stfsu { frs, ra, d } => {
            if ra == 0 {
                return Err(EmuError::Unsupported(format!(
                    "stfsu with ra=0 word={:08x} pc={:08x}",
                    word, t.pc
                )));
            }
            let ea = ea_imm(ra, t, d);
            let v = t.fpr[frs as usize] as f32;
            mem.write_bytes(ea, &v.to_be_bytes())?;
            t.gpr[ra as usize] = ea as u64;
            t.pc = next;
            Ok(None)
        }
        Decoded::Stfd { frs, ra, d } => {
            let ea = ea_imm(ra, t, d);
            mem.write_bytes(ea, &t.fpr[frs as usize].to_be_bytes())?;
            t.pc = next;
            Ok(None)
        }
        Decoded::Stfdu { frs, ra, d } => {
            if ra == 0 {
                return Err(EmuError::Unsupported(format!(
                    "stfdu with ra=0 word={:08x} pc={:08x}",
                    word, t.pc
                )));
            }
            let ea = ea_imm(ra, t, d);
            mem.write_bytes(ea, &t.fpr[frs as usize].to_be_bytes())?;
            t.gpr[ra as usize] = ea as u64;
            t.pc = next;
            Ok(None)
        }
        Decoded::Stfiwx { frs, ra, rb } => {
            let ea = ea_idx(ra, rb, t);
            mem.write_u32(ea, t.fpr[frs as usize].to_bits() as u32)?;
            t.pc = next;
            Ok(None)
        }
        Decoded::Lfiwax { frt, ra, rb } => {
            let ea = ea_idx(ra, rb, t);
            t.fpr[frt as usize] = (mem.read_u32(ea)? as i32) as f64;
            t.pc = next;
            Ok(None)
        }
        Decoded::Lfsx { frt, ra, rb } => {
            let ea = ea_idx(ra, rb, t);
            let b = mem.read_bytes(ea, 4)?;
            t.fpr[frt as usize] = f32::from_be_bytes([b[0], b[1], b[2], b[3]]) as f64;
            t.pc = next;
            Ok(None)
        }
        Decoded::Lfsux { frt, ra, rb } => {
            if ra == 0 {
                return Err(EmuError::Unsupported(format!(
                    "lfsux with ra=0 word={:08x} pc={:08x}",
                    word, t.pc
                )));
            }
            let ea = ea_idx(ra, rb, t);
            let b = mem.read_bytes(ea, 4)?;
            t.fpr[frt as usize] = f32::from_be_bytes([b[0], b[1], b[2], b[3]]) as f64;
            t.gpr[ra as usize] = ea as u64;
            t.pc = next;
            Ok(None)
        }
        Decoded::Lfdx { frt, ra, rb } => {
            let ea = ea_idx(ra, rb, t);
            let b = mem.read_bytes(ea, 8)?;
            t.fpr[frt as usize] =
                f64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
            t.pc = next;
            Ok(None)
        }
        Decoded::Lfdux { frt, ra, rb } => {
            if ra == 0 {
                return Err(EmuError::Unsupported(format!(
                    "lfdux with ra=0 word={:08x} pc={:08x}",
                    word, t.pc
                )));
            }
            let ea = ea_idx(ra, rb, t);
            let b = mem.read_bytes(ea, 8)?;
            t.fpr[frt as usize] =
                f64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
            t.gpr[ra as usize] = ea as u64;
            t.pc = next;
            Ok(None)
        }
        Decoded::Stfsx { frs, ra, rb } => {
            let ea = ea_idx(ra, rb, t);
            let v = t.fpr[frs as usize] as f32;
            mem.write_bytes(ea, &v.to_be_bytes())?;
            t.pc = next;
            Ok(None)
        }
        Decoded::Stfsux { frs, ra, rb } => {
            if ra == 0 {
                return Err(EmuError::Unsupported(format!(
                    "stfsux with ra=0 word={:08x} pc={:08x}",
                    word, t.pc
                )));
            }
            let ea = ea_idx(ra, rb, t);
            let v = t.fpr[frs as usize] as f32;
            mem.write_bytes(ea, &v.to_be_bytes())?;
            t.gpr[ra as usize] = ea as u64;
            t.pc = next;
            Ok(None)
        }
        Decoded::Stfdx { frs, ra, rb } => {
            let ea = ea_idx(ra, rb, t);
            mem.write_bytes(ea, &t.fpr[frs as usize].to_be_bytes())?;
            t.pc = next;
            Ok(None)
        }
        Decoded::Stfdux { frs, ra, rb } => {
            if ra == 0 {
                return Err(EmuError::Unsupported(format!(
                    "stfdux with ra=0 word={:08x} pc={:08x}",
                    word, t.pc
                )));
            }
            let ea = ea_idx(ra, rb, t);
            mem.write_bytes(ea, &t.fpr[frs as usize].to_be_bytes())?;
            t.gpr[ra as usize] = ea as u64;
            t.pc = next;
            Ok(None)
        }
        Decoded::Fadd {
            frt,
            fra,
            frb,
            rc,
            single,
        } => {
            let v = fp_single(t.fpr[fra as usize] + t.fpr[frb as usize], single);
            t.fpr[frt as usize] = v;
            if rc {
                fp_cr1_zero(t);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Fsub {
            frt,
            fra,
            frb,
            rc,
            single,
        } => {
            let v = fp_single(t.fpr[fra as usize] - t.fpr[frb as usize], single);
            t.fpr[frt as usize] = v;
            if rc {
                fp_cr1_zero(t);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Fmul {
            frt,
            fra,
            frb,
            rc,
            single,
        } => {
            let v = fp_single(t.fpr[fra as usize] * t.fpr[frb as usize], single);
            t.fpr[frt as usize] = v;
            if rc {
                fp_cr1_zero(t);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Fdiv {
            frt,
            fra,
            frb,
            rc,
            single,
        } => {
            let v = fp_single(t.fpr[fra as usize] / t.fpr[frb as usize], single);
            t.fpr[frt as usize] = v;
            if rc {
                fp_cr1_zero(t);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Fmadd {
            frt,
            fra,
            frb,
            frc,
            rc,
            single,
        } => {
            let v = fp_single(
                t.fpr[fra as usize].mul_add(t.fpr[frb as usize], t.fpr[frc as usize]),
                single,
            );
            t.fpr[frt as usize] = v;
            if rc {
                fp_cr1_zero(t);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Fmsub {
            frt,
            fra,
            frb,
            frc,
            rc,
            single,
        } => {
            let v = fp_single(
                t.fpr[fra as usize].mul_add(t.fpr[frb as usize], -t.fpr[frc as usize]),
                single,
            );
            t.fpr[frt as usize] = v;
            if rc {
                fp_cr1_zero(t);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Fnmadd {
            frt,
            fra,
            frb,
            frc,
            rc,
            single,
        } => {
            let v = fp_single(
                -(t.fpr[fra as usize].mul_add(t.fpr[frb as usize], t.fpr[frc as usize])),
                single,
            );
            t.fpr[frt as usize] = v;
            if rc {
                fp_cr1_zero(t);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Fnmsub {
            frt,
            fra,
            frb,
            frc,
            rc,
            single,
        } => {
            let v = fp_single(
                -(t.fpr[fra as usize].mul_add(t.fpr[frb as usize], -t.fpr[frc as usize])),
                single,
            );
            t.fpr[frt as usize] = v;
            if rc {
                fp_cr1_zero(t);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Fmr { frt, frb, rc } => {
            t.fpr[frt as usize] = t.fpr[frb as usize];
            if rc {
                fp_cr1_zero(t);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Fneg { frt, frb, rc } => {
            t.fpr[frt as usize] = -t.fpr[frb as usize];
            if rc {
                fp_cr1_zero(t);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Fabs { frt, frb, rc } => {
            t.fpr[frt as usize] = t.fpr[frb as usize].abs();
            if rc {
                fp_cr1_zero(t);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Fnabs { frt, frb, rc } => {
            t.fpr[frt as usize] = -t.fpr[frb as usize].abs();
            if rc {
                fp_cr1_zero(t);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Frsp { frt, frb, rc } => {
            t.fpr[frt as usize] = (t.fpr[frb as usize] as f32) as f64;
            if rc {
                fp_cr1_zero(t);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Fctiw { frt, frb, rc } => {
            let i = fp_to_i32(t.fpr[frb as usize], false);
            t.fpr[frt as usize] = f64::from_bits((i as i64) as u64);
            if rc {
                fp_cr1_zero(t);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Fctiwz { frt, frb, rc } => {
            let i = fp_to_i32(t.fpr[frb as usize], true);
            t.fpr[frt as usize] = f64::from_bits((i as i64) as u64);
            if rc {
                fp_cr1_zero(t);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Fctid { frt, frb, rc } => {
            let i = fp_to_i64(t.fpr[frb as usize], false);
            t.fpr[frt as usize] = f64::from_bits(i as u64);
            if rc {
                fp_cr1_zero(t);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Fctidz { frt, frb, rc } => {
            let i = fp_to_i64(t.fpr[frb as usize], true);
            t.fpr[frt as usize] = f64::from_bits(i as u64);
            if rc {
                fp_cr1_zero(t);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Fcfid { frt, frb, rc } => {
            t.fpr[frt as usize] = t.fpr[frb as usize].to_bits() as i64 as f64;
            if rc {
                fp_cr1_zero(t);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Fsqrt {
            frt,
            frb,
            rc,
            single,
        } => {
            let v = fp_single(t.fpr[frb as usize].sqrt(), single);
            t.fpr[frt as usize] = v;
            if rc {
                fp_cr1_zero(t);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Fres { frt, frb, rc } => {
            // Estimate modeled exact; titles iterate to converge.
            let v = (1.0 / t.fpr[frb as usize] as f32) as f64;
            t.fpr[frt as usize] = v;
            if rc {
                fp_cr1_zero(t);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Frsqrte { frt, frb, rc } => {
            // Estimate modeled exact; titles iterate to converge.
            let v = (1.0 / t.fpr[frb as usize].sqrt() as f32) as f64;
            t.fpr[frt as usize] = v;
            if rc {
                fp_cr1_zero(t);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Fsel {
            frt,
            fra,
            frb,
            frc,
            rc,
        } => {
            t.fpr[frt as usize] = if t.fpr[fra as usize] >= 0.0 {
                t.fpr[frb as usize]
            } else {
                t.fpr[frc as usize]
            };
            if rc {
                fp_cr1_zero(t);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Fcmpu { bf, fra, frb } => {
            fp_cmp(t, bf, t.fpr[fra as usize], t.fpr[frb as usize]);
            t.pc = next;
            Ok(None)
        }
        Decoded::Fcmpo { bf, fra, frb } => {
            fp_cmp(t, bf, t.fpr[fra as usize], t.fpr[frb as usize]);
            t.pc = next;
            Ok(None)
        }
        Decoded::Lbzu { rt, ra, d } => {
            if ra == 0 || ra == rt {
                return Err(EmuError::Unsupported(format!(
                    "lbzu with ra=0 or ra=rt word={:08x} pc={:08x}",
                    word, t.pc
                )));
            }
            let ea = ea_imm(ra, t, d);
            let v = mem.read_u8(ea)? as u32;
            t.gpr[rt as usize] = (v) as u64;
            t.gpr[ra as usize] = (ea) as u64;
            t.pc = next;
            Ok(None)
        }
        Decoded::Lhzu { rt, ra, d } => {
            if ra == 0 || ra == rt {
                return Err(EmuError::Unsupported(format!(
                    "lhzu with ra=0 or ra=rt word={:08x} pc={:08x}",
                    word, t.pc
                )));
            }
            let ea = ea_imm(ra, t, d);
            let v = read_half_be(mem, ea)? as u32;
            t.gpr[rt as usize] = (v) as u64;
            t.gpr[ra as usize] = (ea) as u64;
            t.pc = next;
            Ok(None)
        }
        Decoded::Lha { rt, ra, d } => {
            let ea = ea_imm(ra, t, d);
            let v = read_half_be(mem, ea)? as i16 as i32 as u32;
            t.gpr[rt as usize] = (v) as u64;
            t.pc = next;
            Ok(None)
        }
        Decoded::Lhau { rt, ra, d } => {
            if ra == 0 || ra == rt {
                return Err(EmuError::Unsupported(format!(
                    "lhau with ra=0 or ra=rt word={:08x} pc={:08x}",
                    word, t.pc
                )));
            }
            let ea = ea_imm(ra, t, d);
            let v = read_half_be(mem, ea)? as i16 as i32 as u32;
            t.gpr[rt as usize] = (v) as u64;
            t.gpr[ra as usize] = (ea) as u64;
            t.pc = next;
            Ok(None)
        }
        Decoded::Stbu { rs, ra, d } => {
            if ra == 0 {
                return Err(EmuError::Unsupported(format!(
                    "stbu with ra=0 word={:08x} pc={:08x}",
                    word, t.pc
                )));
            }
            let ea = ea_imm(ra, t, d);
            mem.write_u8(ea, (t.gpr[rs as usize] as u32) as u8)?;
            t.gpr[ra as usize] = (ea) as u64;
            t.pc = next;
            Ok(None)
        }
        Decoded::Sthu { rs, ra, d } => {
            if ra == 0 {
                return Err(EmuError::Unsupported(format!(
                    "sthu with ra=0 word={:08x} pc={:08x}",
                    word, t.pc
                )));
            }
            let ea = ea_imm(ra, t, d);
            write_half_be(mem, ea, (t.gpr[rs as usize] as u32) as u16)?;
            t.gpr[ra as usize] = (ea) as u64;
            t.pc = next;
            Ok(None)
        }
        Decoded::Add { rt, ra, rb, rc, oe } => {
            // 64-bit (reference InstrEmit_addx). Plain add records
            // neither CA nor (without OE) OV/SO.
            let a = t.gpr[ra as usize];
            let b = t.gpr[rb as usize];
            let v = a.wrapping_add(b);
            if oe {
                let ov = (a as i64).checked_add(b as i64).is_none();
                t.xer.set_ov_so(ov);
            }
            t.gpr[rt as usize] = v;
            if rc {
                update_cr0_64(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Subf { rt, ra, rb, rc, oe } => {
            // 64-bit (reference InstrEmit_subfx). Plain subf records
            // neither CA nor (without OE) OV/SO.
            let a = t.gpr[ra as usize];
            let b = t.gpr[rb as usize];
            let v = b.wrapping_sub(a);
            if oe {
                let ov = (b as i64).checked_sub(a as i64).is_none();
                t.xer.set_ov_so(ov);
            }
            t.gpr[rt as usize] = v;
            if rc {
                update_cr0_64(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Neg { rt, ra, rc, oe } => {
            // 64-bit (reference InstrEmit_negx): RT <- 0 - (RA).
            let a = t.gpr[ra as usize];
            let v = (0u64).wrapping_sub(a);
            if oe {
                t.xer.set_ov_so(a == 0x8000_0000_0000_0000);
            }
            t.gpr[rt as usize] = v;
            if rc {
                update_cr0_64(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Mullw { rt, ra, rb, rc, oe } => {
            let a = (t.gpr[ra as usize] as u32) as i32 as i64;
            let b = (t.gpr[rb as usize] as u32) as i32 as i64;
            let prod = a * b;
            let v = prod as u32;
            if oe {
                t.xer.set_ov_so(prod != v as i32 as i64);
            }
            t.gpr[rt as usize] = (v) as u64;
            if rc {
                update_cr0(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Mulhw { rt, ra, rb, rc, oe } => {
            let a = (t.gpr[ra as usize] as u32) as i32 as i64;
            let b = (t.gpr[rb as usize] as u32) as i32 as i64;
            let prod = a * b;
            let v = (prod >> 32) as u32;
            if oe {
                t.xer.set_ov_so(prod != v as i32 as i64);
            }
            t.gpr[rt as usize] = (v) as u64;
            if rc {
                update_cr0(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Mulhwu { rt, ra, rb, rc, oe } => {
            let a = (t.gpr[ra as usize] as u32) as u64;
            let b = (t.gpr[rb as usize] as u32) as u64;
            let prod = a * b;
            let v = (prod >> 32) as u32;
            if oe {
                t.xer.set_ov_so(v != 0);
            }
            t.gpr[rt as usize] = (v) as u64;
            if rc {
                update_cr0(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Divw { rt, ra, rb, rc, oe } => {
            let a = (t.gpr[ra as usize] as u32) as i32;
            let b = (t.gpr[rb as usize] as u32) as i32;
            let (v, ov) = if b == 0 {
                (0u32, true)
            } else if a == i32::MIN && b == -1 {
                (0x8000_0000u32, true)
            } else {
                ((a / b) as u32, false)
            };
            if oe {
                t.xer.set_ov_so(ov);
            }
            t.gpr[rt as usize] = (v) as u64;
            if rc {
                update_cr0(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Divwu { rt, ra, rb, rc, oe } => {
            let a = t.gpr[ra as usize] as u32;
            let b = t.gpr[rb as usize] as u32;
            let (v, ov) = a.checked_div(b).map_or((0u32, true), |q| (q, false));
            if oe {
                t.xer.set_ov_so(ov);
            }
            t.gpr[rt as usize] = (v) as u64;
            if rc {
                update_cr0(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Mulld { rt, ra, rb, rc, oe } => {
            let prod = (t.gpr[ra as usize] as i64 as i128) * (t.gpr[rb as usize] as i64 as i128);
            let v = prod as u64;
            if oe {
                t.xer.set_ov_so(prod != v as i64 as i128);
            }
            t.gpr[rt as usize] = v;
            if rc {
                update_cr0_64(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Mulhd { rt, ra, rb, rc, oe } => {
            let prod = (t.gpr[ra as usize] as i64 as i128) * (t.gpr[rb as usize] as i64 as i128);
            let v = (prod >> 64) as u64;
            if oe {
                t.xer.set_ov_so(prod != v as i64 as i128);
            }
            t.gpr[rt as usize] = v;
            if rc {
                update_cr0_64(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Mulhdu { rt, ra, rb, rc, oe } => {
            let prod = (t.gpr[ra as usize] as u128) * (t.gpr[rb as usize] as u128);
            let v = (prod >> 64) as u64;
            if oe {
                t.xer.set_ov_so(v != 0);
            }
            t.gpr[rt as usize] = v;
            if rc {
                update_cr0_64(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Divd { rt, ra, rb, rc, oe } => {
            let a = t.gpr[ra as usize] as i64;
            let b = t.gpr[rb as usize] as i64;
            let (v, ov) = if b == 0 {
                (0u64, true)
            } else if a == i64::MIN && b == -1 {
                (0x8000_0000_0000_0000u64, true)
            } else {
                ((a / b) as u64, false)
            };
            if oe {
                t.xer.set_ov_so(ov);
            }
            t.gpr[rt as usize] = v;
            if rc {
                update_cr0_64(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Divdu { rt, ra, rb, rc, oe } => {
            let a = t.gpr[ra as usize];
            let b = t.gpr[rb as usize];
            let (v, ov) = a.checked_div(b).map_or((0u64, true), |q| (q, false));
            if oe {
                t.xer.set_ov_so(ov);
            }
            t.gpr[rt as usize] = v;
            if rc {
                update_cr0_64(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Addc { rt, ra, rb, rc, oe } => {
            // 64-bit (reference InstrEmit_addcx).
            let a = t.gpr[ra as usize];
            let b = t.gpr[rb as usize];
            let total = a as u128 + b as u128;
            let v = total as u64;
            t.xer.set_ca(total > u64::MAX as u128);
            if oe {
                let ov = (a as i64).checked_add(b as i64).is_none();
                t.xer.set_ov_so(ov);
            }
            t.gpr[rt as usize] = v;
            if rc {
                update_cr0_64(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Subfc { rt, ra, rb, rc, oe } => {
            // 64-bit (reference InstrEmit_subfcx).
            let a = t.gpr[ra as usize];
            let b = t.gpr[rb as usize];
            let total = b as u128 + (!a) as u128 + 1;
            let v = total as u64;
            t.xer.set_ca(total > u64::MAX as u128);
            if oe {
                let ov = (b as i64).checked_sub(a as i64).is_none();
                t.xer.set_ov_so(ov);
            }
            t.gpr[rt as usize] = v;
            if rc {
                update_cr0_64(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Adde { rt, ra, rb, rc, oe } => {
            // 64-bit (reference InstrEmit_addex).
            let a = t.gpr[ra as usize];
            let b = t.gpr[rb as usize];
            let ca = u128::from(t.xer.ca());
            let total = a as u128 + b as u128 + ca;
            let v = total as u64;
            t.xer.set_ca(total > u64::MAX as u128);
            if oe {
                let ov = (a as i128) + (b as i128) + (ca as i128) != v as i64 as i128;
                t.xer.set_ov_so(ov);
            }
            t.gpr[rt as usize] = v;
            if rc {
                update_cr0_64(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Subfe { rt, ra, rb, rc, oe } => {
            // 64-bit: RT <- ~RA + RB + CA.
            let a = t.gpr[ra as usize];
            let b = t.gpr[rb as usize];
            let ca = u128::from(t.xer.ca());
            let total = b as u128 + (!a) as u128 + ca;
            let v = total as u64;
            t.xer.set_ca(total > u64::MAX as u128);
            if oe {
                let ov = (b as i128) - (a as i128) + (ca as i128) - 1 != v as i64 as i128;
                t.xer.set_ov_so(ov);
            }
            t.gpr[rt as usize] = v;
            if rc {
                update_cr0_64(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Addme { rt, ra, rc, oe } => {
            // 64-bit (reference InstrEmit_addmex): RT <- (RA) + CA - 1.
            let a = t.gpr[ra as usize];
            let ca = u128::from(t.xer.ca());
            let total = a as u128 + (u64::MAX as u128) + ca;
            let v = total as u64;
            t.xer.set_ca(total > u64::MAX as u128);
            if oe {
                let ov = (a as i128) + (ca as i128) - 1 != v as i64 as i128;
                t.xer.set_ov_so(ov);
            }
            t.gpr[rt as usize] = v;
            if rc {
                update_cr0_64(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Subfme { rt, ra, rc, oe } => {
            // 64-bit: RT <- ~RA + CA - 1.
            let a = t.gpr[ra as usize];
            let ca = u128::from(t.xer.ca());
            let total = (!a) as u128 + (u64::MAX as u128) + ca;
            let v = total as u64;
            t.xer.set_ca(total > u64::MAX as u128);
            if oe {
                let ov = (!(a as i64)) as i128 + (ca as i128) - 1 != v as i64 as i128;
                t.xer.set_ov_so(ov);
            }
            t.gpr[rt as usize] = v;
            if rc {
                update_cr0_64(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Addze { rt, ra, rc, oe } => {
            // 64-bit (reference InstrEmit_addzex): RT <- (RA) + CA.
            let a = t.gpr[ra as usize];
            let ca = u128::from(t.xer.ca());
            let total = a as u128 + ca;
            let v = total as u64;
            t.xer.set_ca(total > u64::MAX as u128);
            if oe {
                let ov = (a as i128) + (ca as i128) != v as i64 as i128;
                t.xer.set_ov_so(ov);
            }
            t.gpr[rt as usize] = v;
            if rc {
                update_cr0_64(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Subfze { rt, ra, rc, oe } => {
            // 64-bit: RT <- ~RA + CA.
            let a = t.gpr[ra as usize];
            let ca = u128::from(t.xer.ca());
            let total = (!a) as u128 + ca;
            let v = total as u64;
            t.xer.set_ca(total > u64::MAX as u128);
            if oe {
                let ov = (!(a as i64)) as i128 + (ca as i128) != v as i64 as i128;
                t.xer.set_ov_so(ov);
            }
            t.gpr[rt as usize] = v;
            if rc {
                update_cr0_64(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::And { rs, ra, rb, rc } => {
            // 64-bit (reference InstrEmit_andx).
            let v = t.gpr[rs as usize] & t.gpr[rb as usize];
            t.gpr[ra as usize] = v;
            if rc {
                update_cr0_64(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Or { rs, ra, rb, rc } => {
            // 64-bit (reference InstrEmit_orx).
            let v = t.gpr[rs as usize] | t.gpr[rb as usize];
            t.gpr[ra as usize] = v;
            if rc {
                update_cr0_64(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Xor { rs, ra, rb, rc } => {
            // 64-bit (reference InstrEmit_xorx).
            let v = t.gpr[rs as usize] ^ t.gpr[rb as usize];
            t.gpr[ra as usize] = v;
            if rc {
                update_cr0_64(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Nor { rs, ra, rb, rc } => {
            // 64-bit (reference InstrEmit_norx).
            let v = !(t.gpr[rs as usize] | t.gpr[rb as usize]);
            t.gpr[ra as usize] = v;
            if rc {
                update_cr0_64(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Andc { rs, ra, rb, rc } => {
            // 64-bit (reference InstrEmit_andcx).
            let v = t.gpr[rs as usize] & !t.gpr[rb as usize];
            t.gpr[ra as usize] = v;
            if rc {
                update_cr0_64(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Orc { rs, ra, rb, rc } => {
            // 64-bit.
            let v = t.gpr[rs as usize] | !t.gpr[rb as usize];
            t.gpr[ra as usize] = v;
            if rc {
                update_cr0_64(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Nand { rs, ra, rb, rc } => {
            // 64-bit (reference InstrEmit_nandx).
            let v = !(t.gpr[rs as usize] & t.gpr[rb as usize]);
            t.gpr[ra as usize] = v;
            if rc {
                update_cr0_64(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Eqv { rs, ra, rb, rc } => {
            // 64-bit.
            let v = !(t.gpr[rs as usize] ^ t.gpr[rb as usize]);
            t.gpr[ra as usize] = v;
            if rc {
                update_cr0_64(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Slw { rs, ra, rb, rc } => {
            let sh = (t.gpr[rb as usize] as u32) & 0x3F;
            let v = if sh >= 32 {
                0
            } else {
                (t.gpr[rs as usize] as u32) << sh
            };
            t.gpr[ra as usize] = (v) as u64;
            if rc {
                update_cr0(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Srw { rs, ra, rb, rc } => {
            let sh = (t.gpr[rb as usize] as u32) & 0x3F;
            let v = if sh >= 32 {
                0
            } else {
                (t.gpr[rs as usize] as u32) >> sh
            };
            t.gpr[ra as usize] = (v) as u64;
            if rc {
                update_cr0(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Extsh { rs, ra, rc } => {
            // 64-bit sign extend (reference InstrEmit_extshx).
            let v = ((t.gpr[rs as usize] as u16) as i16) as i64 as u64;
            t.gpr[ra as usize] = v;
            if rc {
                update_cr0_64(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Extsb { rs, ra, rc } => {
            // 64-bit sign extend (reference InstrEmit_extsbx).
            let v = ((t.gpr[rs as usize] as u8) as i8) as i64 as u64;
            t.gpr[ra as usize] = v;
            if rc {
                update_cr0_64(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Cntlzw { rs, ra, rc } => {
            let v = (t.gpr[rs as usize] as u32).leading_zeros();
            t.gpr[ra as usize] = (v) as u64;
            if rc {
                update_cr0(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Sraw { rs, ra, rb, rc } => {
            // n mirrors the reference clamp in InstrEmit_srawx
            // (reference ppc_emit_alu.cc): low 6 bits, clamped to 31.
            let n = ((t.gpr[rb as usize] as u32) & 0x3F).min(31);
            let (v, ca) = sraw_core(t.gpr[rs as usize] as u32, n);
            t.xer.set_ca(ca);
            t.gpr[ra as usize] = (v) as u64;
            if rc {
                update_cr0(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Sldx { rs, ra, rb, rc } => {
            let sh = (t.gpr[rb as usize] & 0x7F) as u32;
            let v = if sh >= 64 {
                0
            } else {
                t.gpr[rs as usize] << sh
            };
            t.gpr[ra as usize] = v;
            if rc {
                update_cr0_64(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Srdx { rs, ra, rb, rc } => {
            let sh = (t.gpr[rb as usize] & 0x7F) as u32;
            let v = if sh >= 64 {
                0
            } else {
                t.gpr[rs as usize] >> sh
            };
            t.gpr[ra as usize] = v;
            if rc {
                update_cr0_64(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Sradx { rs, ra, rb, rc } => {
            let rt = t.gpr[rs as usize];
            let sh = (t.gpr[rb as usize] & 0x7F) as u32;
            let clamp = sh.min(63);
            let v = ((rt as i64) >> clamp) as u64;
            // CA = sign & ((v << clamp) != rt) (reference sradx).
            let ca = (rt >> 63) == 1 && (v.wrapping_shl(clamp) != rt);
            t.xer.set_ca(ca);
            t.gpr[ra as usize] = v;
            if rc {
                update_cr0_64(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Srawi { rs, ra, sh, rc } => {
            let (v, ca) = sraw_core(t.gpr[rs as usize] as u32, sh & 0x1F);
            t.xer.set_ca(ca);
            t.gpr[ra as usize] = (v) as u64;
            if rc {
                update_cr0(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Sradix { rs, ra, sh, rc } => {
            // Immediate twin of sradx (reference InstrEmit_sradix):
            // n==0 copies with CA=0, else sign-fill with CA = sign
            // & any-shifted-out-1 (low-n-bits mask).
            let rt = t.gpr[rs as usize];
            let (v, ca) = if sh == 0 {
                (rt, false)
            } else {
                let v = ((rt as i64) >> sh) as u64;
                let mask = if sh >= 64 { u64::MAX } else { (1u64 << sh) - 1 };
                ((v), (rt >> 63) == 1 && (rt & mask) != 0)
            };
            t.xer.set_ca(ca);
            t.gpr[ra as usize] = v;
            if rc {
                update_cr0_64(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Lwzx { rt, ra, rb } => {
            let ea = ea_idx(ra, rb, t);
            t.gpr[rt as usize] = (mem.read_u32(ea)?) as u64;
            t.pc = next;
            Ok(None)
        }
        Decoded::Ldx { rt, ra, rb } => {
            let ea = ea_idx(ra, rb, t);
            t.gpr[rt as usize] = mem.read_u64(ea)?;
            t.pc = next;
            Ok(None)
        }
        Decoded::Ldux { rt, ra, rb } => {
            if ra == 0 || ra == rt {
                return Err(EmuError::Unsupported(format!(
                    "ldux with ra=0 or ra=rt word={:08x} pc={:08x}",
                    word, t.pc
                )));
            }
            let ea = ea_idx(ra, rb, t);
            t.gpr[rt as usize] = mem.read_u64(ea)?;
            t.gpr[ra as usize] = (ea) as u64;
            t.pc = next;
            Ok(None)
        }
        Decoded::Stdx { rs, ra, rb } => {
            let ea = ea_idx(ra, rb, t);
            mem.write_u64(ea, t.gpr[rs as usize])?;
            t.pc = next;
            Ok(None)
        }
        Decoded::Stdux { rs, ra, rb } => {
            if ra == 0 {
                return Err(EmuError::Unsupported(format!(
                    "stdux with ra=0 word={:08x} pc={:08x}",
                    word, t.pc
                )));
            }
            let ea = ea_idx(ra, rb, t);
            mem.write_u64(ea, t.gpr[rs as usize])?;
            t.gpr[ra as usize] = (ea) as u64;
            t.pc = next;
            Ok(None)
        }
        Decoded::Lbzx { rt, ra, rb } => {
            let ea = ea_idx(ra, rb, t);
            t.gpr[rt as usize] = (mem.read_u8(ea)? as u32) as u64;
            t.pc = next;
            Ok(None)
        }
        Decoded::Lbzux { rt, ra, rb } => {
            if ra == 0 || ra == rt {
                return Err(EmuError::Unsupported(format!(
                    "lbzux with ra=0 or ra=rt word={:08x} pc={:08x}",
                    word, t.pc
                )));
            }
            let ea = ea_idx(ra, rb, t);
            let v = mem.read_u8(ea)? as u32;
            t.gpr[rt as usize] = (v) as u64;
            t.gpr[ra as usize] = (ea) as u64;
            t.pc = next;
            Ok(None)
        }
        Decoded::Stbx { rs, ra, rb } => {
            let ea = ea_idx(ra, rb, t);
            mem.write_u8(ea, (t.gpr[rs as usize] as u32) as u8)?;
            t.pc = next;
            Ok(None)
        }
        Decoded::Stbux { rs, ra, rb } => {
            if ra == 0 {
                return Err(EmuError::Unsupported(format!(
                    "stbux with ra=0 word={:08x} pc={:08x}",
                    word, t.pc
                )));
            }
            let ea = ea_idx(ra, rb, t);
            mem.write_u8(ea, (t.gpr[rs as usize] as u32) as u8)?;
            t.gpr[ra as usize] = (ea) as u64;
            t.pc = next;
            Ok(None)
        }
        Decoded::Lhzx { rt, ra, rb } => {
            let ea = ea_idx(ra, rb, t);
            t.gpr[rt as usize] = (read_half_be(mem, ea)? as u32) as u64;
            t.pc = next;
            Ok(None)
        }
        Decoded::Lhzux { rt, ra, rb } => {
            if ra == 0 || ra == rt {
                return Err(EmuError::Unsupported(format!(
                    "lhzux with ra=0 or ra=rt word={:08x} pc={:08x}",
                    word, t.pc
                )));
            }
            let ea = ea_idx(ra, rb, t);
            let v = read_half_be(mem, ea)? as u32;
            t.gpr[rt as usize] = (v) as u64;
            t.gpr[ra as usize] = (ea) as u64;
            t.pc = next;
            Ok(None)
        }
        Decoded::Lhax { rt, ra, rb } => {
            let ea = ea_idx(ra, rb, t);
            t.gpr[rt as usize] = (read_half_be(mem, ea)? as i16 as i32 as u32) as u64;
            t.pc = next;
            Ok(None)
        }
        Decoded::Lhaux { rt, ra, rb } => {
            if ra == 0 || ra == rt {
                return Err(EmuError::Unsupported(format!(
                    "lhaux with ra=0 or ra=rt word={:08x} pc={:08x}",
                    word, t.pc
                )));
            }
            let ea = ea_idx(ra, rb, t);
            let v = read_half_be(mem, ea)? as i16 as i32 as u32;
            t.gpr[rt as usize] = (v) as u64;
            t.gpr[ra as usize] = (ea) as u64;
            t.pc = next;
            Ok(None)
        }
        Decoded::Sthx { rs, ra, rb } => {
            let ea = ea_idx(ra, rb, t);
            write_half_be(mem, ea, (t.gpr[rs as usize] as u32) as u16)?;
            t.pc = next;
            Ok(None)
        }
        Decoded::Sthux { rs, ra, rb } => {
            if ra == 0 {
                return Err(EmuError::Unsupported(format!(
                    "sthux with ra=0 word={:08x} pc={:08x}",
                    word, t.pc
                )));
            }
            let ea = ea_idx(ra, rb, t);
            write_half_be(mem, ea, (t.gpr[rs as usize] as u32) as u16)?;
            t.gpr[ra as usize] = (ea) as u64;
            t.pc = next;
            Ok(None)
        }
        Decoded::Stwux { rs, ra, rb } => {
            if ra == 0 {
                return Err(EmuError::Unsupported(format!(
                    "stwux with ra=0 word={:08x} pc={:08x}",
                    word, t.pc
                )));
            }
            let ea = ea_idx(ra, rb, t);
            mem.write_u32(ea, t.gpr[rs as usize] as u32)?;
            t.gpr[ra as usize] = (ea) as u64;
            t.pc = next;
            Ok(None)
        }
        Decoded::Stwx { rs, ra, rb } => {
            let ea = ea_idx(ra, rb, t);
            mem.write_u32(ea, t.gpr[rs as usize] as u32)?;
            t.pc = next;
            Ok(None)
        }
        Decoded::Lwarx { rt, ra, rb } => {
            let ea = ea_idx(ra, rb, t);
            t.gpr[rt as usize] = (mem.read_u32(ea)?) as u64;
            t.reserved = true;
            t.reserved_addr = ea;
            t.pc = next;
            Ok(None)
        }
        Decoded::Stwcx { rs, ra, rb } => {
            let ea = ea_idx(ra, rb, t);
            if t.reserved && t.reserved_addr == ea {
                mem.write_u32(ea, t.gpr[rs as usize] as u32)?;
                // CR0 EQ set on success.
                t.cr.set_field(0, 0b0010);
                t.reserved = false;
            } else {
                // Reservation lost: CR0 EQ cleared, no store.
                t.cr.set_field(0, 0b0000);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Mfcr { rt } => {
            t.gpr[rt as usize] = (t.cr.0) as u64;
            t.pc = next;
            Ok(None)
        }
        Decoded::Mfmsr { rt } => {
            t.gpr[rt as usize] = t.msr;
            t.pc = next;
            Ok(None)
        }
        Decoded::Mtmsr { rs } => {
            t.msr = t.gpr[rs as usize];
            t.pc = next;
            Ok(None)
        }
        Decoded::Mtmsrd { rs, l: _ } => {
            // Only EE (value bit 0x8000) commits; the rest is
            // preserved (reference `InstrEmit_mtmsrd`).
            t.msr = (t.msr & !0x8000) | (t.gpr[rs as usize] & 0x8000);
            t.pc = next;
            Ok(None)
        }
        Decoded::Mtcrf { rs, fxm } => {
            let v = t.gpr[rs as usize] as u32;
            for i in 0..8u32 {
                if fxm & (0x80 >> i) != 0 {
                    t.cr.set_field(i, ((v >> ((7 - i) * 4)) & 0xF) as u8);
                }
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Mfspr { rt, spr } => {
            let v = match spr {
                8 => t.lr,  // LR
                9 => t.ctr, // CTR
                _ => {
                    return Err(EmuError::Unsupported(format!(
                        "mfspr spr={} word={:08x}",
                        spr, word
                    )))
                }
            };
            t.gpr[rt as usize] = (v) as u64;
            t.pc = next;
            Ok(None)
        }
        Decoded::Mtspr { rs, spr } => {
            let v = t.gpr[rs as usize] as u32;
            match spr {
                8 => t.lr = v,
                9 => t.ctr = v,
                _ => {
                    return Err(EmuError::Unsupported(format!(
                        "mtspr spr={} word={:08x}",
                        spr, word
                    )))
                }
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Mftb { rt, tbr } => {
            // 50MHz-equivalent monotonic ticks from the same wall
            // clock as the millisecond syscall (consistent deltas).
            let ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            let tb = ms.wrapping_mul(50_000);
            let v = match tbr {
                268 => tb as u32,
                269 => (tb >> 32) as u32,
                _ => {
                    return Err(EmuError::Unsupported(format!(
                        "mftb tbr={} word={:08x}",
                        tbr, word
                    )))
                }
            };
            t.gpr[rt as usize] = v as u64;
            t.pc = next;
            Ok(None)
        }
        Decoded::Sync { .. } | Decoded::Isync | Decoded::Eieio => {
            // Scheduler fence for now; accurate barriers at M9.
            t.pc = next;
            Ok(None)
        }
        Decoded::Dcbt { .. }
        | Decoded::Dcbtst { .. }
        | Decoded::Dcbf { .. }
        | Decoded::Dcbst { .. }
        | Decoded::Dcbi { .. }
        | Decoded::Icbi { .. } => {
            // Cacheless memory: touch/flush/invalidate hints and
            // invalidates are semantic no-ops (stores are already
            // globally visible; there is nothing stale to discard).
            t.pc = next;
            Ok(None)
        }
        Decoded::Dcbz { ra, rb } => {
            // Zero the 128-byte cache line containing EA (Xenon line).
            let ea = ea_idx(ra, rb, t);
            let line = ea & !127;
            mem.write_bytes(line, &[0u8; 128])?;
            t.pc = next;
            Ok(None)
        }
        Decoded::Sc => {
            t.pc = next;
            Ok(Some(SyscallTrap {
                thread: t.id,
                pc: t.pc,
            }))
        }
        Decoded::Trap => {
            t.pc = next;
            Ok(None)
        }
        Decoded::Tw { to, ra, rb } => {
            // Trap words never go silent: a fired condition is an
            // explicit Unsupported trap error with opcode+pc context.
            let a = t.gpr[ra as usize] as u32;
            let b = t.gpr[rb as usize] as u32;
            if trap_fires(to, a, b) {
                return Err(EmuError::Unsupported(format!(
                    "tw trap fired to={:05b} ra={} rb={} word={:08x} pc={:08x}",
                    to, ra, rb, word, t.pc
                )));
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Twi { to, ra, simm } => {
            let a = t.gpr[ra as usize] as u32;
            let b = simm as i32 as u32;
            if trap_fires(to, a, b) {
                return Err(EmuError::Unsupported(format!(
                    "twi trap fired to={:05b} ra={} simm={} word={:08x} pc={:08x}",
                    to, ra, simm, word, t.pc
                )));
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Td { to, ra, rb } => {
            let a = t.gpr[ra as usize];
            let b = t.gpr[rb as usize];
            if trap_fires_64(to, a, b) {
                return Err(EmuError::Unsupported(format!(
                    "td trap fired to={:05b} ra={} rb={} word={:08x} pc={:08x}",
                    to, ra, rb, word, t.pc
                )));
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Tdi { to, ra, simm } => {
            let a = t.gpr[ra as usize];
            let b = simm as i64 as u64;
            if trap_fires_64(to, a, b) {
                return Err(EmuError::Unsupported(format!(
                    "tdi trap fired to={:05b} ra={} simm={} word={:08x} pc={:08x}",
                    to, ra, simm, word, t.pc
                )));
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Mcrf { crfd, crfs } => {
            // Whole-field copy; no XER/CR0 side effects.
            let v = t.cr.field(crfs);
            t.cr.set_field(crfd, v);
            t.pc = next;
            Ok(None)
        }
        Decoded::Crand { bt, ba, bb } => {
            let v = cr_bit(t, ba) & cr_bit(t, bb);
            set_cr_bit(t, bt, v);
            t.pc = next;
            Ok(None)
        }
        Decoded::Crandc { bt, ba, bb } => {
            let v = cr_bit(t, ba) & (cr_bit(t, bb) ^ 1);
            set_cr_bit(t, bt, v);
            t.pc = next;
            Ok(None)
        }
        Decoded::Cror { bt, ba, bb } => {
            let v = cr_bit(t, ba) | cr_bit(t, bb);
            set_cr_bit(t, bt, v);
            t.pc = next;
            Ok(None)
        }
        Decoded::Crorc { bt, ba, bb } => {
            let v = cr_bit(t, ba) | (cr_bit(t, bb) ^ 1);
            set_cr_bit(t, bt, v);
            t.pc = next;
            Ok(None)
        }
        Decoded::Crxor { bt, ba, bb } => {
            let v = cr_bit(t, ba) ^ cr_bit(t, bb);
            set_cr_bit(t, bt, v);
            t.pc = next;
            Ok(None)
        }
        Decoded::Crnor { bt, ba, bb } => {
            let v = (cr_bit(t, ba) | cr_bit(t, bb)) ^ 1;
            set_cr_bit(t, bt, v);
            t.pc = next;
            Ok(None)
        }
        Decoded::Crnand { bt, ba, bb } => {
            let v = (cr_bit(t, ba) & cr_bit(t, bb)) ^ 1;
            set_cr_bit(t, bt, v);
            t.pc = next;
            Ok(None)
        }
        Decoded::Creqv { bt, ba, bb } => {
            let v = (cr_bit(t, ba) ^ cr_bit(t, bb)) ^ 1;
            set_cr_bit(t, bt, v);
            t.pc = next;
            Ok(None)
        }
        Decoded::Vslb { vd, va, vb } => {
            // Per-byte `va[i] << (vb[i] & 7)` (reference VECTOR_SHL).
            let a = t.vr[va as usize];
            let b = t.vr[vb as usize];
            let mut v = [0u8; 16];
            for (i, d) in v.iter_mut().enumerate() {
                *d = a[i].wrapping_shl((b[i] & 7) as u32);
            }
            t.vr[vd as usize] = v;
            t.pc = next;
            Ok(None)
        }
        Decoded::Vor { vd, va, vb } => {
            // Full 128-bit OR (reference InstrEmit_vor).
            let a = t.vr[va as usize];
            let b = t.vr[vb as usize];
            let mut v = [0u8; 16];
            for i in 0..16 {
                v[i] = a[i] | b[i];
            }
            t.vr[vd as usize] = v;
            t.pc = next;
            Ok(None)
        }
        Decoded::Vspltb { vd, va, vb } => {
            // Splat VB[VA & 0xF] (reference InstrEmit_vspltb).
            let b = t.vr[vb as usize][(va & 0xF) as usize];
            t.vr[vd as usize] = [b; 16];
            t.pc = next;
            Ok(None)
        }
        Decoded::Lvx128 { vd, ra, rb } => {
            // 16 bytes from EA aligned down (reference InstrEmit_lvx_).
            let ea = ea_idx(ra, rb, t) & !0xF;
            let b = mem.read_bytes(ea, 16)?;
            t.vr[vd as usize].copy_from_slice(b);
            t.pc = next;
            Ok(None)
        }
        Decoded::Stvx128 { vd, ra, rb } => {
            // 16 bytes to EA aligned down (reference InstrEmit_stvx_).
            let ea = ea_idx(ra, rb, t) & !0xF;
            let v = t.vr[vd as usize];
            mem.write_bytes(ea, &v)?;
            t.pc = next;
            Ok(None)
        }
        Decoded::Lvx { rt, ra, rb } => {
            let ea = ea_idx(ra, rb, t) & !0xF;
            let b = mem.read_bytes(ea, 16)?;
            t.vr[rt as usize].copy_from_slice(b);
            t.pc = next;
            Ok(None)
        }
        Decoded::Stvx { rs, ra, rb } => {
            let ea = ea_idx(ra, rb, t) & !0xF;
            let v = t.vr[rs as usize];
            mem.write_bytes(ea, &v)?;
            t.pc = next;
            Ok(None)
        }
        Decoded::Lvlx { rt, ra, rb } => {
            // Tail of the quad from EA, low-placed, rest zero
            // (reference backend LVL TBL: vd[i] = mem[i+o] or 0).
            let ea = ea_idx(ra, rb, t);
            let o = (ea & 0xF) as usize;
            let base = ea & !0xF;
            let b = mem.read_bytes(base, 16)?;
            let mut v = [0u8; 16];
            for i in 0..16 {
                if i + o < 16 {
                    v[i] = b[i + o];
                }
            }
            t.vr[rt as usize] = v;
            t.pc = next;
            Ok(None)
        }
        Decoded::Lvrx { rt, ra, rb } => {
            // Head of the quad before EA, high-placed, rest zero
            // (reference backend LVR: zero for o==0, correct).
            let ea = ea_idx(ra, rb, t);
            let o = (ea & 0xF) as usize;
            let base = ea & !0xF;
            let mut v = [0u8; 16];
            if o != 0 {
                let b = mem.read_bytes(base, 16)?;
                for i in 0..16 {
                    if i + o >= 16 {
                        v[i] = b[i + o - 16];
                    }
                }
            }
            t.vr[rt as usize] = v;
            t.pc = next;
            Ok(None)
        }
        Decoded::Stvlx { rs, ra, rb } => {
            // Low bytes of vs to the quad tail (reference STVL:
            // bytes o..15; o==0 is a full store).
            let ea = ea_idx(ra, rb, t);
            let o = (ea & 0xF) as usize;
            let base = ea & !0xF;
            let v = t.vr[rs as usize];
            if o == 0 {
                mem.write_bytes(base, &v)?;
            } else {
                mem.write_bytes(base + o as u32, &v[..16 - o])?;
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Stvrx { rs, ra, rb } => {
            // High bytes of vs to the quad head (reference STVR;
            // o==0 touches no memory at all, never faults).
            let ea = ea_idx(ra, rb, t);
            let o = (ea & 0xF) as usize;
            if o != 0 {
                let base = ea & !0xF;
                let v = t.vr[rs as usize];
                mem.write_bytes(base, &v[16 - o..])?;
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Lvebx { rt, ra, rb } => {
            let ea = ea_idx(ra, rb, t);
            let o = (ea & 0xF) as usize;
            let mut v = [0u8; 16];
            v[o] = mem.read_u8(ea)?;
            t.vr[rt as usize] = v;
            t.pc = next;
            Ok(None)
        }
        Decoded::Lvehx { rt, ra, rb } => {
            let ea = ea_idx(ra, rb, t);
            let eal = ea & !1;
            let el = ((ea & 0xF) >> 1) as usize;
            let b = mem.read_bytes(eal, 2)?;
            let mut v = [0u8; 16];
            v[el * 2] = b[0];
            v[el * 2 + 1] = b[1];
            t.vr[rt as usize] = v;
            t.pc = next;
            Ok(None)
        }
        Decoded::Lvewx { rt, ra, rb } => {
            let ea = ea_idx(ra, rb, t);
            let eal = ea & !3;
            let el = ((ea & 0xF) >> 2) as usize;
            let b = mem.read_bytes(eal, 4)?;
            let mut v = [0u8; 16];
            v[el * 4..el * 4 + 4].copy_from_slice(b);
            t.vr[rt as usize] = v;
            t.pc = next;
            Ok(None)
        }
        Decoded::Stvebx { rs, ra, rb } => {
            let ea = ea_idx(ra, rb, t);
            let o = (ea & 0xF) as usize;
            mem.write_u8(ea, t.vr[rs as usize][o])?;
            t.pc = next;
            Ok(None)
        }
        Decoded::Stvehx { rs, ra, rb } => {
            let ea = ea_idx(ra, rb, t);
            let eal = ea & !1;
            let el = ((ea & 0xF) >> 1) as usize;
            let v = t.vr[rs as usize];
            mem.write_bytes(eal, &v[el * 2..el * 2 + 2])?;
            t.pc = next;
            Ok(None)
        }
        Decoded::Stvewx { rs, ra, rb } => {
            let ea = ea_idx(ra, rb, t);
            let eal = ea & !3;
            let el = ((ea & 0xF) >> 2) as usize;
            let v = t.vr[rs as usize];
            mem.write_bytes(eal, &v[el * 4..el * 4 + 4])?;
            t.pc = next;
            Ok(None)
        }
        Decoded::Lvlx128 { vd, ra, rb } => {
            let ea = ea_idx(ra, rb, t);
            let o = (ea & 0xF) as usize;
            let base = ea & !0xF;
            let b = mem.read_bytes(base, 16)?;
            let mut v = [0u8; 16];
            for i in 0..16 {
                if i + o < 16 {
                    v[i] = b[i + o];
                }
            }
            t.vr[vd as usize] = v;
            t.pc = next;
            Ok(None)
        }
        Decoded::Lvrx128 { vd, ra, rb } => {
            let ea = ea_idx(ra, rb, t);
            let o = (ea & 0xF) as usize;
            let base = ea & !0xF;
            let mut v = [0u8; 16];
            if o != 0 {
                let b = mem.read_bytes(base, 16)?;
                for i in 0..16 {
                    if i + o >= 16 {
                        v[i] = b[i + o - 16];
                    }
                }
            }
            t.vr[vd as usize] = v;
            t.pc = next;
            Ok(None)
        }
        Decoded::Stvlx128 { vd, ra, rb } => {
            let ea = ea_idx(ra, rb, t);
            let o = (ea & 0xF) as usize;
            let base = ea & !0xF;
            let v = t.vr[vd as usize];
            if o == 0 {
                mem.write_bytes(base, &v)?;
            } else {
                mem.write_bytes(base + o as u32, &v[..16 - o])?;
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Stvrx128 { vd, ra, rb } => {
            let ea = ea_idx(ra, rb, t);
            let o = (ea & 0xF) as usize;
            if o != 0 {
                let base = ea & !0xF;
                let v = t.vr[vd as usize];
                mem.write_bytes(base, &v[16 - o..])?;
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Vspltisb { vd, simm } => {
            // Splat sign-extended 5-bit immediate across all 16 bytes
            // (reference InstrEmit_vspltisb; splat-0 coincides with zero).
            let b = if simm & 0x10 != 0 {
                (simm | 0xFFFF_FFF0) as u8
            } else {
                simm as u8
            };
            t.vr[vd as usize] = [b; 16];
            t.pc = next;
            Ok(None)
        }
        Decoded::Vspltish { vd, simm } => {
            // Splat sign-extended 5-bit immediate as 8 big-endian
            // halfwords (reference InstrEmit_vspltish); 0 zeroes.
            let mut v = [0u8; 16];
            if simm != 0 {
                let h = if simm & 0x10 != 0 {
                    (simm | 0xFFFF_FFF0) as u16
                } else {
                    simm as u16
                };
                for i in 0..8 {
                    v[2 * i] = (h >> 8) as u8;
                    v[2 * i + 1] = h as u8;
                }
            }
            t.vr[vd as usize] = v;
            t.pc = next;
            Ok(None)
        }
        Decoded::Vspltisw { vd, simm } => {
            // Splat sign-extended 5-bit immediate as 4 big-endian
            // words (reference vspltisw immediate form); 0 zeroes.
            let mut v = [0u8; 16];
            if simm != 0 {
                let w = if simm & 0x10 != 0 {
                    simm | 0xFFFF_FFE0
                } else {
                    simm
                };
                for i in 0..4 {
                    v[4 * i] = (w >> 24) as u8;
                    v[4 * i + 1] = (w >> 16) as u8;
                    v[4 * i + 2] = (w >> 8) as u8;
                    v[4 * i + 3] = w as u8;
                }
            }
            t.vr[vd as usize] = v;
            t.pc = next;
            Ok(None)
        }
        Decoded::Lvsl { rt, ra, rb } => {
            // Shift-left permute control: base {0..15} plus EA low
            // 4 bits, byte-wrapped without masking (reference backend
            // `LOAD_VECTOR_SHL`: add, mod 256; high values are valid
            // 5-bit vperm selectors).
            let sh = (ea_idx(ra, rb, t) & 0xF) as u8;
            let mut v = [0u8; 16];
            for (i, b) in v.iter_mut().enumerate() {
                *b = (i as u8).wrapping_add(sh);
            }
            t.vr[rt as usize] = v;
            t.pc = next;
            Ok(None)
        }
        Decoded::Lvsr { rt, ra, rb } => {
            // Shift-right permute control: base {16..31} minus EA low
            // 4 bits, byte-wrapped (reference `LOAD_VECTOR_SHR`).
            let sh = (ea_idx(ra, rb, t) & 0xF) as u8;
            let mut v = [0u8; 16];
            for (i, b) in v.iter_mut().enumerate() {
                *b = (16 + i as u8).wrapping_sub(sh);
            }
            t.vr[rt as usize] = v;
            t.pc = next;
            Ok(None)
        }
        Decoded::Vperm { vd, va, vb, vc } => {
            // Same select as the 128-bit form, 32-reg file.
            let a = t.vr[va as usize];
            let b = t.vr[vb as usize];
            let c = t.vr[vc as usize];
            let mut v = [0u8; 16];
            for (i, d) in v.iter_mut().enumerate() {
                let s = (c[i] & 31) as usize;
                *d = if s < 16 { a[s] } else { b[s - 16] };
            }
            t.vr[vd as usize] = v;
            t.pc = next;
            Ok(None)
        }
        Decoded::Vsel { vd, va, vb, vc } => {
            // Per-bit select: VD = (VA & ~VC) | (VB & VC)
            // (reference InstrEmit_vsel_ comment).
            let a = t.vr[va as usize];
            let b = t.vr[vb as usize];
            let c = t.vr[vc as usize];
            let mut v = [0u8; 16];
            for (i, d) in v.iter_mut().enumerate() {
                *d = (a[i] & !c[i]) | (b[i] & c[i]);
            }
            t.vr[vd as usize] = v;
            t.pc = next;
            Ok(None)
        }
        Decoded::Vperm128 { vd, va, vb, vc } => {
            // Byte select from the VA||VB concat (reference
            // InstrEmit_vperm_ / HIR Permute; PPC byte order here).
            let a = t.vr[va as usize];
            let b = t.vr[vb as usize];
            let c = t.vr[vc as usize];
            let mut v = [0u8; 16];
            for (i, d) in v.iter_mut().enumerate() {
                let s = (c[i] & 31) as usize;
                *d = if s < 16 { a[s] } else { b[s - 16] };
            }
            t.vr[vd as usize] = v;
            t.pc = next;
            Ok(None)
        }
        Decoded::Vaddfp { vd, va, vb } => {
            // 4 x f32 add, PPC byte order (reference
            // `InstrEmit_vaddfp_`).
            let a = t.vr[va as usize];
            let b = t.vr[vb as usize];
            let mut v = [0u8; 16];
            for i in 0..4 {
                let x = f32::from_be_bytes([a[4 * i], a[4 * i + 1], a[4 * i + 2], a[4 * i + 3]]);
                let y = f32::from_be_bytes([b[4 * i], b[4 * i + 1], b[4 * i + 2], b[4 * i + 3]]);
                v[4 * i..4 * i + 4].copy_from_slice(&(x + y).to_be_bytes());
            }
            t.vr[vd as usize] = v;
            t.pc = next;
            Ok(None)
        }
        Decoded::Vsubfp { vd, va, vb } => {
            // 4 x f32 sub (reference `InstrEmit_vsubfp_`).
            let a = t.vr[va as usize];
            let b = t.vr[vb as usize];
            let mut v = [0u8; 16];
            for i in 0..4 {
                let x = f32::from_be_bytes([a[4 * i], a[4 * i + 1], a[4 * i + 2], a[4 * i + 3]]);
                let y = f32::from_be_bytes([b[4 * i], b[4 * i + 1], b[4 * i + 2], b[4 * i + 3]]);
                v[4 * i..4 * i + 4].copy_from_slice(&(x - y).to_be_bytes());
            }
            t.vr[vd as usize] = v;
            t.pc = next;
            Ok(None)
        }
        Decoded::Vmaxfp { vd, va, vb } => {
            // 4 x f32 max (reference `InstrEmit_vmaxfp_`).
            let a = t.vr[va as usize];
            let b = t.vr[vb as usize];
            let mut v = [0u8; 16];
            for i in 0..4 {
                let x = f32::from_be_bytes([a[4 * i], a[4 * i + 1], a[4 * i + 2], a[4 * i + 3]]);
                let y = f32::from_be_bytes([b[4 * i], b[4 * i + 1], b[4 * i + 2], b[4 * i + 3]]);
                v[4 * i..4 * i + 4].copy_from_slice(&x.max(y).to_be_bytes());
            }
            t.vr[vd as usize] = v;
            t.pc = next;
            Ok(None)
        }
        Decoded::Vminfp { vd, va, vb } => {
            // 4 x f32 min (reference `InstrEmit_vminfp_`).
            let a = t.vr[va as usize];
            let b = t.vr[vb as usize];
            let mut v = [0u8; 16];
            for i in 0..4 {
                let x = f32::from_be_bytes([a[4 * i], a[4 * i + 1], a[4 * i + 2], a[4 * i + 3]]);
                let y = f32::from_be_bytes([b[4 * i], b[4 * i + 1], b[4 * i + 2], b[4 * i + 3]]);
                v[4 * i..4 * i + 4].copy_from_slice(&x.min(y).to_be_bytes());
            }
            t.vr[vd as usize] = v;
            t.pc = next;
            Ok(None)
        }
        Decoded::Vaddfp128 { vd, va, vb } => {
            // 4 x f32 add, 128-entry file (reference
            // `InstrEmit_vaddfp128`).
            let a = t.vr[va as usize];
            let b = t.vr[vb as usize];
            let mut v = [0u8; 16];
            for i in 0..4 {
                let x = f32::from_be_bytes([a[4 * i], a[4 * i + 1], a[4 * i + 2], a[4 * i + 3]]);
                let y = f32::from_be_bytes([b[4 * i], b[4 * i + 1], b[4 * i + 2], b[4 * i + 3]]);
                v[4 * i..4 * i + 4].copy_from_slice(&(x + y).to_be_bytes());
            }
            t.vr[vd as usize] = v;
            t.pc = next;
            Ok(None)
        }
        Decoded::Vsubfp128 { vd, va, vb } => {
            // 4 x f32 sub (reference `InstrEmit_vsubfp128`).
            let a = t.vr[va as usize];
            let b = t.vr[vb as usize];
            let mut v = [0u8; 16];
            for i in 0..4 {
                let x = f32::from_be_bytes([a[4 * i], a[4 * i + 1], a[4 * i + 2], a[4 * i + 3]]);
                let y = f32::from_be_bytes([b[4 * i], b[4 * i + 1], b[4 * i + 2], b[4 * i + 3]]);
                v[4 * i..4 * i + 4].copy_from_slice(&(x - y).to_be_bytes());
            }
            t.vr[vd as usize] = v;
            t.pc = next;
            Ok(None)
        }
        Decoded::Vmulfp128 { vd, va, vb } => {
            // 4 x f32 mul (reference `InstrEmit_vmulfp128`).
            let a = t.vr[va as usize];
            let b = t.vr[vb as usize];
            let mut v = [0u8; 16];
            for i in 0..4 {
                let x = f32::from_be_bytes([a[4 * i], a[4 * i + 1], a[4 * i + 2], a[4 * i + 3]]);
                let y = f32::from_be_bytes([b[4 * i], b[4 * i + 1], b[4 * i + 2], b[4 * i + 3]]);
                v[4 * i..4 * i + 4].copy_from_slice(&(x * y).to_be_bytes());
            }
            t.vr[vd as usize] = v;
            t.pc = next;
            Ok(None)
        }
        Decoded::Vmx { word } => Err(EmuError::Unsupported(format!(
            "VMX128 word={:08x} pc={:08x}",
            word, t.pc
        ))),
        Decoded::Unsupported {
            opc,
            word: w,
            reason,
        } => Err(EmuError::Unsupported(format!(
            "opc={} word={:08x} pc={:08x} ({})",
            opc, w, t.pc, reason
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::decode;

    fn setup() -> (ThreadState, Memory) {
        (ThreadState::new(0, 0x1000), Memory::new())
    }

    fn run_word(word: u32, t: &mut ThreadState, m: &mut Memory) {
        let d = decode(word).unwrap();
        execute(d, word, t, m).unwrap();
    }

    fn dform(opc: u32, rt: u32, ra: u32, d: i16) -> u32 {
        (opc << 26) | (rt << 21) | (ra << 16) | (d as u16 as u32)
    }

    fn xform(rt: u32, ra: u32, rb: u32, xo: u32, rc: u32) -> u32 {
        (31 << 26) | (rt << 21) | (ra << 16) | (rb << 11) | (xo << 1) | rc
    }

    fn xlform(bo: u32, bi: u32, bb: u32, xo: u32) -> u32 {
        (19 << 26) | (bo << 21) | (bi << 16) | (bb << 11) | (xo << 1)
    }

    fn expect_unsupported(word: u32, t: &mut ThreadState, m: &mut Memory) -> String {
        let d = decode(word).unwrap();
        match execute(d, word, t, m) {
            Err(EmuError::Unsupported(msg)) => msg,
            Err(e) => panic!("expected Unsupported, got {:?}", e),
            Ok(_) => panic!("expected Unsupported, executed Ok"),
        }
    }

    fn expect_align(word: u32, t: &mut ThreadState, m: &mut Memory) -> u32 {
        let d = decode(word).unwrap();
        match execute(d, word, t, m) {
            Err(EmuError::AlignmentFault { addr }) => addr,
            Err(e) => panic!("expected AlignmentFault, got {:?}", e),
            Ok(_) => panic!("expected AlignmentFault, executed Ok"),
        }
    }

    #[test]
    fn addi_ori_chain() {
        let (mut t, mut m) = setup();
        run_word(0x3860_0010, &mut t, &mut m); // addi r3,0,16
        assert_eq!((t.gpr[3] as u32), 16);
        run_word(0x6063_00FF, &mut t, &mut m); // ori r3,r3,0xFF
        assert_eq!((t.gpr[3] as u32), 0xFF);
    }

    #[test]
    fn dform_logicals_dest_in_ra() {
        // D-form logicals put SOURCE in RT, DEST in RA
        // (`ori [RA],[RS],...`): 0x70600003 is `andi. r0,r3,3`.
        let (mut t, mut m) = setup();
        t.gpr[3] = 0b1101_u64;
        t.gpr[0] = 0xFFFF_u64;
        run_word(0x7060_0003, &mut t, &mut m);
        assert_eq!((t.gpr[0] as u32), 0b0001); // scratch written
        assert_eq!((t.gpr[3] as u32), 0b1101); // source preserved
        assert_eq!(t.cr.field(0) & 0b0010, 0); // 1 -> GT, not EQ
                                               // ori r27,r11,0xFFFF shape (retail 0x617BFFFF): dest r27.
        t.gpr[11] = 0x1234_0000_u64;
        t.gpr[27] = 0_u64;
        run_word(0x617B_FFFF, &mut t, &mut m);
        assert_eq!((t.gpr[27] as u32), 0x1234_FFFF);
        assert_eq!((t.gpr[11] as u32), 0x1234_0000);
    }

    #[test]
    fn dword_indexed_roundtrip() {
        // Retail word: ldx r3,r11,r31 -> 0x7C6BF82A.
        let (mut t, mut m) = setup();
        assert!(matches!(
            decode(0x7C6B_F82A).unwrap(),
            Decoded::Ldx {
                rt: 3,
                ra: 11,
                rb: 31
            }
        ));
        t.gpr[11] = 0x4000_u64;
        t.gpr[31] = 0x100_u64;
        m.write_u64(0x4100, 0x1122_3344_5566_7788).unwrap();
        run_word(0x7C6B_F82A, &mut t, &mut m);
        assert_eq!(t.gpr[3], 0x1122_3344_5566_7788);
        // stdx + update forms.
        run_word(xform(3, 11, 30, 149, 0), &mut t, &mut m); // stdx r3,r11,r30?
                                                            // (r30 = 0 here, so stores back to 0x4000)
        assert_eq!(m.read_u64(0x4000).unwrap(), 0x1122_3344_5566_7788);
        t.gpr[30] = 0x200_u64;
        run_word(xform(4, 11, 30, 181, 0), &mut t, &mut m); // stdux r4,r11,r30
        assert_eq!((t.gpr[11] as u32), 0x4200);
        run_word(xform(5, 11, 30, 53, 0), &mut t, &mut m); // ldux r5,r11,r30
        assert_eq!((t.gpr[11] as u32), 0x4400);
        let bad = xform(5, 0, 30, 53, 0);
        assert!(expect_unsupported(bad, &mut t, &mut m).contains("ldux"));
    }

    #[test]
    fn dword_shifts() {
        // Retail word: srdx r9,r6,r10 -> 0x7D265436.
        let (mut t, mut m) = setup();
        assert!(matches!(
            decode(0x7D26_5436).unwrap(),
            Decoded::Srdx {
                rs: 9,
                ra: 6,
                rb: 10,
                rc: false
            }
        ));
        t.gpr[9] = 0xFF00_0000_0000_00FF;
        t.gpr[10] = 8;
        run_word(0x7D26_5436, &mut t, &mut m);
        assert_eq!(t.gpr[6], 0x00FF_0000_0000_0000);
        // Shift >= 64 yields 0.
        t.gpr[10] = 64;
        run_word(0x7D26_5436, &mut t, &mut m);
        assert_eq!(t.gpr[6], 0);
        // sldx + sradx (sign fill + CA).
        t.gpr[9] = 1;
        t.gpr[10] = 63;
        run_word(xform(9, 6, 10, 27, 0), &mut t, &mut m); // sldx
        assert_eq!(t.gpr[6], 0x8000_0000_0000_0000);
        t.gpr[9] = 0x8000_0000_0000_0001;
        t.gpr[10] = 1;
        run_word(xform(9, 6, 10, 794, 0), &mut t, &mut m); // sradx
        assert_eq!(t.gpr[6], 0xC000_0000_0000_0000);
        assert!(t.xer.ca());
        t.gpr[10] = 0;
        run_word(xform(9, 6, 10, 794, 0), &mut t, &mut m);
        assert_eq!(t.gpr[6], 0x8000_0000_0000_0001);
        assert!(!t.xer.ca());
    }

    #[test]
    fn msr_moves_roundtrip() {
        // Retail word: mfmsr r9 -> 0x7D2000A6 (XO 83).
        let (mut t, mut m) = setup();
        assert!(matches!(
            decode(0x7D20_00A6).unwrap(),
            Decoded::Mfmsr { rt: 9 }
        ));
        run_word(0x7D20_00A6, &mut t, &mut m);
        assert_eq!(t.gpr[9], 0);
        t.gpr[3] = 0x8000;
        run_word(xform(3, 0, 0, 146, 0), &mut t, &mut m); // mtmsr r3
        run_word(0x7D20_00A6, &mut t, &mut m);
        assert_eq!(t.gpr[9], 0x8000);
        // Retail word: mtmsrd r13,r0 -> 0x7DA10164 (masked EE write).
        assert!(matches!(
            decode(0x7DA1_0164).unwrap(),
            Decoded::Mtmsrd { rs: 13, l: 0 }
        ));
        t.gpr[13] = 0xFFFF_FFFF_FFFF_FFFF;
        run_word(0x7DA1_0164, &mut t, &mut m);
        assert_eq!(t.msr, 0x8000);
    }

    #[test]
    fn stw_lwz_roundtrip() {
        let (mut t, mut m) = setup();
        t.gpr[3] = 0x2000_u64;
        t.gpr[4] = 0xAABB_CCDD_u64;
        run_word(0x9083_0000, &mut t, &mut m); // stw r4,0(r3)
        t.gpr[4] = 0_u64;
        run_word(0x8083_0000, &mut t, &mut m); // lwz r4,0(r3)
        assert_eq!((t.gpr[4] as u32), 0xAABB_CCDD);
    }

    #[test]
    fn std_ld_roundtrip_full_width() {
        let (mut t, mut m) = setup();
        t.gpr[3] = 0x3000_u64;
        t.gpr[4] = 0x1122_3344_5566_7788;
        run_word(0xF883_0000, &mut t, &mut m); // std r4,0(r3)
        assert_eq!(m.read_u64(0x3000).unwrap(), 0x1122_3344_5566_7788);
        t.gpr[4] = 0;
        run_word(0xE883_0000, &mut t, &mut m); // ld r4,0(r3)
        assert_eq!(t.gpr[4], 0x1122_3344_5566_7788);
    }

    #[test]
    fn retail_std_prologue_word() {
        // Exact fault word from Braid's first callee: std r28,-40(r1).
        let (mut t, mut m) = setup();
        t.gpr[1] = 0x4000_u64;
        t.gpr[28] = 0xDEAD_BEEF_CAFE_1234;
        run_word(0xFB81_FFD8, &mut t, &mut m);
        assert_eq!(m.read_u64(0x4000 - 40).unwrap(), 0xDEAD_BEEF_CAFE_1234);
    }

    #[test]
    fn indexed_float_load_store() {
        // Retail fault word: stfiwx f0,r29,r9 -> 0x7C1D4FAE
        // (XO 983, not lfdx: masked base 0x7C0007AE per the reference
        // opcode table and IBM Appendix F).
        let (mut t, mut m) = setup();
        assert!(matches!(
            decode(0x7C1D_4FAE).unwrap(),
            Decoded::Stfiwx {
                frs: 0,
                ra: 29,
                rb: 9
            }
        ));
        t.fpr[0] = f64::from_bits(0x0000_0000_0000_002A);
        t.gpr[29] = 0x3000_u64;
        t.gpr[9] = 0x40_u64;
        run_word(0x7C1D_4FAE, &mut t, &mut m);
        assert_eq!(m.read_u32(0x3040).unwrap(), 0x2A);
        // lfdx double roundtrip.
        let lfdx = (31u32 << 26) | (1 << 21) | (29 << 16) | (9 << 11) | (599 << 1);
        m.write_bytes(0x3040, &(-3.75f64).to_be_bytes()).unwrap();
        run_word(lfdx, &mut t, &mut m); // lfdx f1,r29,r9
        assert_eq!(t.fpr[1], -3.75);
        // lfsx single->double.
        m.write_bytes(0x3050, &2.5f32.to_be_bytes()).unwrap();
        let lfsx = (31u32 << 26) | (4 << 21) | (29 << 16) | (10 << 11) | (535 << 1);
        t.gpr[10] = 0x50_u64;
        run_word(lfsx, &mut t, &mut m); // lfsx f4,r29,r10
        assert_eq!(t.fpr[4], 2.5);
        // stfdx/stfsx store back.
        t.fpr[5] = 1.25;
        let stfdx = (31u32 << 26) | (5 << 21) | (29 << 16) | (11 << 11) | (727 << 1);
        t.gpr[11] = 0x60_u64;
        run_word(stfdx, &mut t, &mut m); // stfdx f5,r29,r11
        assert_eq!(m.read_u64(0x3060).unwrap(), 1.25f64.to_bits());
        let stfsx = (31u32 << 26) | (5 << 21) | (29 << 16) | (12 << 11) | (663 << 1);
        t.gpr[12] = 0x70_u64;
        run_word(stfsx, &mut t, &mut m); // stfsx f5,r29,r12
        let b = m.read_bytes(0x3070, 4).unwrap();
        assert_eq!(f32::from_be_bytes([b[0], b[1], b[2], b[3]]), 1.25);
        // Update forms write EA back; ra=0 is an explicit error.
        m.write_bytes(0x3080, &7.5f64.to_be_bytes()).unwrap();
        t.gpr[10] = 0x80_u64;
        let lfdux = (31u32 << 26) | (6 << 21) | (29 << 16) | (10 << 11) | (631 << 1);
        run_word(lfdux, &mut t, &mut m); // lfdux f6,r29,r10
        assert_eq!((t.gpr[29] as u32), 0x3080);
        assert_eq!(t.fpr[6], 7.5);
        let bad = (31u32 << 26) | (6 << 21) | (10 << 11) | (631 << 1);
        assert!(expect_unsupported(bad, &mut t, &mut m).contains("lfdux"));
    }

    #[test]
    fn vector_align_helpers() {
        // Retail dash word: lvsl v13,r0,r4 -> 0x7DA0200C.
        let (mut t, mut m) = setup();
        assert!(matches!(
            decode(0x7DA0_200C).unwrap(),
            Decoded::Lvsl {
                rt: 13,
                ra: 0,
                rb: 4
            }
        ));
        t.gpr[4] = 0x1003_u64;
        run_word(0x7DA0_200C, &mut t, &mut m);
        assert_eq!(
            t.vr[13],
            [3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18]
        );
        // lvsr base {16..31} minus shift (backend LOAD_VECTOR_SHR).
        t.gpr[4] = 0x1003_u64;
        let lvsr = (31u32 << 26) | (13 << 21) | (4 << 11) | (38 << 1);
        assert!(matches!(
            decode(lvsr).unwrap(),
            Decoded::Lvsr {
                rt: 13,
                ra: 0,
                rb: 4
            }
        ));
        run_word(lvsr, &mut t, &mut m);
        assert_eq!(
            t.vr[13],
            [13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28]
        );
        // Zero shift: identity bases.
        t.gpr[4] = 0x1000_u64;
        run_word(0x7DA0_200C, &mut t, &mut m);
        assert_eq!(
            t.vr[13],
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        );
    }

    #[test]
    fn vslb_shifts_per_byte() {
        // Retail dash word: vslb v0,v12,v0 -> 0x100C0104.
        let (mut t, mut m) = setup();
        assert!(matches!(
            decode(0x100C_0104).unwrap(),
            Decoded::Vslb {
                vd: 0,
                va: 12,
                vb: 0
            }
        ));
        t.vr[12] = [0x01, 0x02, 0x80, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        t.vr[0] = [1, 3, 1, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        run_word(0x100C_0104, &mut t, &mut m);
        // Shift amounts masked to 3 bits: 0x80<<0, 0xFF<<0... check:
        // v[0]=0x01<<1, v[1]=0x02<<3, v[2]=0x80<<1, v[3]=0xFF<<0.
        assert_eq!(
            t.vr[0],
            [0x02, 0x10, 0x00, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn vor_ors_full_register() {
        // Retail dash word: vor v0,v13,v0 -> 0x100D0484.
        let (mut t, mut m) = setup();
        assert!(matches!(
            decode(0x100D_0484).unwrap(),
            Decoded::Vor {
                vd: 0,
                va: 13,
                vb: 0
            }
        ));
        t.vr[13] = [0xF0u8; 16];
        t.vr[0] = [0x0Fu8; 16];
        run_word(0x100D_0484, &mut t, &mut m);
        assert_eq!(t.vr[0], [0xFFu8; 16]);
    }

    #[test]
    fn vspltb_splats_indexed_byte() {
        // Retail dash word: vspltb v0,v0,v0 -> 0x1000020C.
        let (mut t, mut m) = setup();
        assert!(matches!(
            decode(0x1000_020C).unwrap(),
            Decoded::Vspltb {
                vd: 0,
                va: 0,
                vb: 0
            }
        ));
        t.vr[3] = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
            0x1E, 0x1F,
        ];
        // vspltb v2,v5,v3 (VD=2, VA=5, VB=3): splat VB[5] = 0x15.
        let w = (4u32 << 26) | (2 << 21) | (5 << 16) | (3 << 11) | 0x20C;
        run_word(w, &mut t, &mut m);
        assert_eq!(t.vr[2], [0x15u8; 16]);
        // Index wraps at 16: VA=17 -> VB[1].
        let w2 = (4u32 << 26) | (2 << 21) | (17 << 16) | (3 << 11) | 0x20C;
        run_word(w2, &mut t, &mut m);
        assert_eq!(t.vr[2], [0x11u8; 16]);
    }

    #[test]
    fn lvx_stvx128_roundtrip_retail() {
        // Retail dash word 0x100051C3 is stvx128 v0 (VD low 0, high 0).
        let (mut t, mut m) = setup();
        assert!(matches!(
            decode(0x1000_51C3).unwrap(),
            Decoded::Stvx128 { vd: 0, .. }
        ));
        t.vr[0] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        t.gpr[9] = 0x4003_u64;
        // stvx128 v0,r0,r9: EA aligns 0x4003 down to 0x4000.
        let stvx = (4u32 << 26) | (9 << 11) | 0x1C0 | 0x3;
        run_word(stvx, &mut t, &mut m);
        assert_eq!(
            m.read_bytes(0x4000, 16).unwrap(),
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
        );
        // lvx128 v3,r0,r9 loads it back (VD=3).
        t.vr[3] = [0u8; 16];
        let lvx = (4u32 << 26) | (3 << 21) | (9 << 11) | 0x0C0 | 3;
        assert!(matches!(
            decode(lvx).unwrap(),
            Decoded::Lvx128 { vd: 3, .. }
        ));
        run_word(lvx, &mut t, &mut m);
        assert_eq!(
            t.vr[3],
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
        );
        // 7-bit VD: bits 2-3 extend the index (v64 here).
        let hi = (4u32 << 26) | (9 << 11) | 0x0C0 | (2 << 2) | 3;
        assert!(matches!(
            decode(hi).unwrap(),
            Decoded::Lvx128 { vd: 64, .. }
        ));
    }

    #[test]
    fn vector_indexed_partial_family() {
        // Retail dash fault word: stvrx r0,r10,r11 -> 0x7C0A5D4E.
        let (mut t, mut m) = setup();
        assert!(matches!(
            decode(0x7C0A_5D4E).unwrap(),
            Decoded::Stvrx {
                rs: 0,
                ra: 10,
                rb: 11
            }
        ));
        // Quad [0x5000..0x5010) = 0..15; EA 0x5003 (o=3).
        m.write_bytes(
            0x5000,
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        )
        .unwrap();
        t.gpr[10] = 0x5000_u64;
        t.gpr[11] = 0x3_u64;
        // lvlx loads the tail low-placed, rest zero.
        run_word(xform(2, 10, 11, 519, 0), &mut t, &mut m);
        assert_eq!(
            t.vr[2],
            [3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 0, 0]
        );
        // lvrx loads the head high-placed, rest zero.
        run_word(xform(3, 10, 11, 551, 0), &mut t, &mut m);
        assert_eq!(t.vr[3], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2]);
        // Roundtrip: stvlx stores low bytes to the tail.
        t.vr[4] = [30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 0, 0, 0];
        run_word(xform(4, 10, 11, 647, 0), &mut t, &mut m);
        assert_eq!(
            m.read_bytes(0x5000, 16).unwrap(),
            &[0, 1, 2, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42]
        );
        // stvrx stores high bytes to the head.
        t.vr[5] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 50, 51, 52];
        run_word(xform(5, 10, 11, 679, 0), &mut t, &mut m);
        assert_eq!(
            m.read_bytes(0x5000, 16).unwrap(),
            &[50, 51, 52, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42]
        );
        // Aligned edges: lvlx full, lvrx zero, stvlx full, stvrx no-op.
        t.gpr[11] = 0x0_u64;
        run_word(xform(6, 10, 11, 519, 0), &mut t, &mut m);
        assert_eq!(
            m.read_bytes(0x5000, 16).unwrap(),
            &t.vr[6][..],
            "aligned lvlx equals the quad"
        );
        run_word(xform(7, 10, 11, 551, 0), &mut t, &mut m);
        assert_eq!(t.vr[7], [0u8; 16]);
        let before = m.read_bytes(0x5000, 16).unwrap().to_vec();
        run_word(xform(7, 10, 11, 679, 0), &mut t, &mut m);
        assert_eq!(m.read_bytes(0x5000, 16).unwrap(), &before[..]);
        // lvx/stvx aligned roundtrip (primary 31).
        t.vr[8] = [9u8; 16];
        run_word(xform(8, 10, 11, 231, 0), &mut t, &mut m);
        t.vr[8] = [0u8; 16];
        run_word(xform(8, 10, 11, 103, 0), &mut t, &mut m);
        assert_eq!(t.vr[8], [9u8; 16]);
        // Element ops: single byte/half/word with zero fill.
        m.write_bytes(0x5010, &[0xAA, 0xBB, 0xCC, 0xDD]).unwrap();
        t.gpr[10] = 0x5010_u64;
        run_word(xform(9, 10, 11, 7, 0), &mut t, &mut m); // lvebx
        assert_eq!(t.vr[9][0], 0xAA);
        assert!(t.vr[9][1..].iter().all(|&b| b == 0));
        run_word(xform(9, 10, 11, 135, 0), &mut t, &mut m); // stvebx
        assert_eq!(m.read_u8(0x5010).unwrap(), 0xAA);
        t.vr[10] = [0u8; 16];
        t.vr[10][0] = 0x11;
        t.vr[10][1] = 0x22;
        run_word(xform(10, 10, 11, 167, 0), &mut t, &mut m); // stvehx
        assert_eq!(m.read_bytes(0x5010, 2).unwrap(), &[0x11, 0x22]);
        run_word(xform(11, 10, 11, 39, 0), &mut t, &mut m); // lvehx
        assert_eq!(&t.vr[11][0..2], &[0x11, 0x22]);
        assert!(t.vr[11][2..].iter().all(|&b| b == 0));
    }

    #[test]
    fn vspltisb_splats_retail_word() {
        // Retail dash word: vspltisb v0,4 -> 0x1004030C.
        let (mut t, mut m) = setup();
        assert!(matches!(
            decode(0x1004_030C).unwrap(),
            Decoded::Vspltisb { vd: 0, simm: 4 }
        ));
        run_word(0x1004_030C, &mut t, &mut m);
        assert_eq!(t.vr[0], [4u8; 16]);
        // Negative immediate sign-extends from 5 bits (0x1F -> 0xFF).
        run_word(0x1004_030C | (0x1F << 16), &mut t, &mut m);
        assert_eq!(t.vr[0], [0xFFu8; 16]);
        // Zero immediate zeroes the register.
        t.vr[1] = [0xAAu8; 16];
        run_word(0x1020_030C, &mut t, &mut m); // vspltisb v1,0
        assert_eq!(t.vr[1], [0u8; 16]);
        // Other primary-4 words stay tracked-unsupported.
        assert!(matches!(decode(0x1000_0083).unwrap(), Decoded::Vmx { .. }));
    }

    #[test]
    fn vspltish_isw_splat_retail_words() {
        // Retail dash word: vspltish v0,0 -> 0x1000034C (zeroes).
        let (mut t, mut m) = setup();
        assert!(matches!(
            decode(0x1000_034C).unwrap(),
            Decoded::Vspltish { vd: 0, simm: 0 }
        ));
        t.vr[0] = [0xAAu8; 16];
        run_word(0x1000_034C, &mut t, &mut m);
        assert_eq!(t.vr[0], [0u8; 16]);
        // vspltish v1,0x1F: sign-extended 0xFFFF as halfwords.
        let w = (4u32 << 26) | (1 << 21) | (0x1F << 16) | 0x34C;
        run_word(w, &mut t, &mut m);
        assert_eq!(t.vr[1], [0xFFu8; 16]);
        // vspltish v2,1: 0x0001 repeated.
        let w2 = (4u32 << 26) | (2 << 21) | (1 << 16) | 0x34C;
        run_word(w2, &mut t, &mut m);
        assert_eq!(t.vr[2], [0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1]);
        // vspltisw v3,0x1F: 0xFFFFFFFF as words.
        let w3 = (4u32 << 26) | (3 << 21) | (0x1F << 16) | 0x38C;
        assert!(matches!(
            decode(w3).unwrap(),
            Decoded::Vspltisw { vd: 3, simm: 0x1F }
        ));
        run_word(w3, &mut t, &mut m);
        assert_eq!(t.vr[3], [0xFFu8; 16]);
        // vspltisw v4,2: 0x00000002 repeated.
        let w4 = (4u32 << 26) | (4 << 21) | (2 << 16) | 0x38C;
        run_word(w4, &mut t, &mut m);
        assert_eq!(t.vr[4], [0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 2]);
    }

    #[test]
    fn vperm128_selects_concat_retail_word() {
        // Retail dash word: vperm128 v63,v63,v62,v0 -> 0x17FFF025.
        let (mut t, mut m) = setup();
        assert!(matches!(
            decode(0x17FF_F025).unwrap(),
            Decoded::Vperm128 {
                vd: 63,
                va: 63,
                vb: 62,
                vc: 0
            }
        ));
        // vaddfp128 now decodes (was tracked before FP landing).
        assert!(matches!(
            decode(0x1400_0010).unwrap(),
            Decoded::Vaddfp128 {
                vd: 0,
                va: 0,
                vb: 0
            }
        ));
        // Classic vperm/vsel share the select core on v0-v31.
        assert!(matches!(
            decode(0x1021_102B).unwrap(),
            Decoded::Vperm {
                vd: 1,
                va: 1,
                vb: 2,
                vc: 0
            }
        ));
        t.vr[63] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        t.vr[62] = [
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
        ];
        // Control: low half from VA, high half from VB.
        t.vr[0] = [0, 1, 2, 3, 4, 5, 6, 7, 16, 17, 18, 19, 20, 21, 22, 23];
        run_word(0x17FF_F025, &mut t, &mut m);
        assert_eq!(
            t.vr[63],
            [0, 1, 2, 3, 4, 5, 6, 7, 16, 17, 18, 19, 20, 21, 22, 23]
        );
        // Classic composition: lvsl control rotates the quad.
        t.gpr[4] = 0x4003_u64;
        run_word(0x7C00_200C, &mut t, &mut m); // lvsl v0,r0,r4 (o=3)
        m.write_bytes(
            0x4000,
            &[
                10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
            ],
        )
        .unwrap();
        run_word(0x13E0_20C7, &mut t, &mut m); // lvx128 v63,r0,r4
        run_word(0x17FF_F025, &mut t, &mut m); // vperm128 v63,v63,v62,v0
        assert_eq!(
            t.vr[63],
            [13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 16, 17, 18]
        );
    }

    #[test]
    fn vperm_vsel_classic_retail_word() {
        // Retail dash word: vperm v1,v1,v2,v0 -> 0x1021102B.
        let (mut t, mut m) = setup();
        t.vr[1] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        t.vr[2] = [16u8; 16];
        t.vr[0] = [8u8; 16]; // select VA[8]
        run_word(0x1021_102B, &mut t, &mut m);
        assert_eq!(t.vr[1], [8u8; 16]);
        // vsel: per-bit mask (VC=0xF0 picks nibbles from each side).
        let vsel = (4u32 << 26) | (5 << 21) | (6 << 16) | (7 << 11) | (8 << 6) | 0x2A;
        assert!(matches!(
            decode(vsel).unwrap(),
            Decoded::Vsel {
                vd: 5,
                va: 6,
                vb: 7,
                vc: 8
            }
        ));
        t.vr[6] = [0xFFu8; 16];
        t.vr[7] = [0x00u8; 16];
        t.vr[8] = [0xF0u8; 16];
        run_word(vsel, &mut t, &mut m);
        assert_eq!(t.vr[5], [0x0Fu8; 16]);
        t.vr[8] = [0x0Fu8; 16];
        run_word(vsel, &mut t, &mut m);
        assert_eq!(t.vr[5], [0xF0u8; 16]);
    }

    #[test]
    fn vaddfp_family_classic() {
        let (mut t, mut m) = setup();
        // vaddfp v3,v1,v2 = 0x1061100A; vsubfp 0x1061104A;
        // vmaxfp 0x1061140A; vminfp 0x1061144A.
        assert!(matches!(
            decode(0x1061_100A).unwrap(),
            Decoded::Vaddfp {
                vd: 3,
                va: 1,
                vb: 2
            }
        ));
        assert!(matches!(
            decode(0x1061_104A).unwrap(),
            Decoded::Vsubfp {
                vd: 3,
                va: 1,
                vb: 2
            }
        ));
        assert!(matches!(
            decode(0x1061_140A).unwrap(),
            Decoded::Vmaxfp {
                vd: 3,
                va: 1,
                vb: 2
            }
        ));
        assert!(matches!(
            decode(0x1061_144A).unwrap(),
            Decoded::Vminfp {
                vd: 3,
                va: 1,
                vb: 2
            }
        ));
        fn put(t: &mut ThreadState, i: usize, xs: [f32; 4]) {
            let mut v = [0u8; 16];
            for (j, x) in xs.iter().enumerate() {
                v[4 * j..4 * j + 4].copy_from_slice(&x.to_be_bytes());
            }
            t.vr[i] = v;
        }
        fn get(t: &ThreadState, i: usize) -> [f32; 4] {
            let mut out = [0.0; 4];
            for (j, o) in out.iter_mut().enumerate() {
                *o = f32::from_be_bytes([
                    t.vr[i][4 * j],
                    t.vr[i][4 * j + 1],
                    t.vr[i][4 * j + 2],
                    t.vr[i][4 * j + 3],
                ]);
            }
            out
        }
        put(&mut t, 1, [1.0, 2.0, -3.0, 4.5]);
        put(&mut t, 2, [0.5, -1.0, 4.0, 1.5]);
        run_word(0x1061_100A, &mut t, &mut m);
        assert_eq!(get(&t, 3), [1.5, 1.0, 1.0, 6.0]);
        run_word(0x1061_104A, &mut t, &mut m);
        assert_eq!(get(&t, 3), [0.5, 3.0, -7.0, 3.0]);
        run_word(0x1061_140A, &mut t, &mut m);
        assert_eq!(get(&t, 3), [1.0, 2.0, 4.0, 4.5]);
        run_word(0x1061_144A, &mut t, &mut m);
        assert_eq!(get(&t, 3), [0.5, -1.0, -3.0, 1.5]);
    }

    #[test]
    fn vfp128_arithmetic_high_regs() {
        let (mut t, mut m) = setup();
        // vaddfp128 v63,v63,v62,v0 shape is vperm128; arithmetic uses
        // the same highs: build vaddfp128 v65,v66,v67 by hand.
        // VD=65: low 1, high 2 (bits2-3). VA=66: low 2, high bit5 + bit10?
        // Simpler: verify bases decode with zero regs + execute.
        assert!(matches!(
            decode(0x1400_0010).unwrap(),
            Decoded::Vaddfp128 {
                vd: 0,
                va: 0,
                vb: 0
            }
        ));
        assert!(matches!(
            decode(0x1400_0050).unwrap(),
            Decoded::Vsubfp128 {
                vd: 0,
                va: 0,
                vb: 0
            }
        ));
        assert!(matches!(
            decode(0x1400_0090).unwrap(),
            Decoded::Vmulfp128 {
                vd: 0,
                va: 0,
                vb: 0
            }
        ));
        fn put(t: &mut ThreadState, i: usize, xs: [f32; 4]) {
            let mut v = [0u8; 16];
            for (j, x) in xs.iter().enumerate() {
                v[4 * j..4 * j + 4].copy_from_slice(&x.to_be_bytes());
            }
            t.vr[i] = v;
        }
        fn get(t: &ThreadState, i: usize) -> [f32; 4] {
            let mut out = [0.0; 4];
            for (j, o) in out.iter_mut().enumerate() {
                *o = f32::from_be_bytes([
                    t.vr[i][4 * j],
                    t.vr[i][4 * j + 1],
                    t.vr[i][4 * j + 2],
                    t.vr[i][4 * j + 3],
                ]);
            }
            out
        }
        // High registers (64+) exercise the 7-bit file.
        put(&mut t, 65, [1.0, 2.0, 3.0, 4.0]);
        put(&mut t, 66, [0.5, 0.5, 0.5, 0.5]);
        // Encode vaddfp128 v67,v65,v66: VD=67 (low 3, high 2),
        // VA=65 (low 1, VA128h=0, VA128H=1), VB=66 (low 2, high 2).
        // Opcode vaddfp128 = 0x10 (bit4). Assemble:
        let vd_low = 67 & 0x1F;
        let va_low = 65 & 0x1F;
        let vb_low = 66 & 0x1F;
        let word = (5u32 << 26)
            | (vd_low << 21)
            | (va_low << 16)
            | (vb_low << 11)
            | (2 << 2) // VDhigh=2
            | (1 << 10) // VA128H (VA=65 needs bit6, not bit5)
            | (2) // VBhigh=2
            | 0x10; // vaddfp128 opcode low
        let d = decode(word).unwrap();
        assert!(
            matches!(
                d,
                Decoded::Vaddfp128 {
                    vd: 67,
                    va: 65,
                    vb: 66
                }
            ),
            "got {:?}",
            d
        );
        run_word(word, &mut t, &mut m);
        assert_eq!(get(&t, 67), [1.5, 2.5, 3.5, 4.5]);
        // vmulfp128 v3,v1,v2.
        put(&mut t, 1, [2.0, 3.0, 4.0, 5.0]);
        put(&mut t, 2, [3.0, 4.0, 5.0, 6.0]);
        let wmul = (5u32 << 26) | (3 << 21) | (1 << 16) | (2 << 11) | 0x90;
        run_word(wmul, &mut t, &mut m);
        assert_eq!(get(&t, 3), [6.0, 12.0, 20.0, 30.0]);
    }

    #[test]
    fn float_load_store_roundtrip() {
        // Retail A-form with nonzero FRC: fmuls f1,f0,f0 with frc=28
        // -> 0xEC200732. The 10-bit XO field carries FRC above the
        // real 5-bit XO (25); decoding must not require FRC == 0.
        let (mut t, mut m) = setup();
        assert!(matches!(
            decode(0xEC20_0732).unwrap(),
            Decoded::Fmul {
                frt: 1,
                fra: 0,
                frb: 0,
                single: true,
                ..
            }
        ));
        t.fpr[0] = 2.0;
        run_word(0xEC20_0732, &mut t, &mut m);
        assert_eq!(t.fpr[1], 4.0);
        let (mut t, mut m) = setup();
        // Retail word shape: lfs f0,r8,24264 -> 0xC0085EC8.
        t.gpr[8] = 0x3000_u64;
        m.write_bytes(0x3000 + 24264, &1.5f32.to_be_bytes())
            .unwrap();
        run_word(0xC008_5EC8, &mut t, &mut m);
        assert_eq!(t.fpr[0], 1.5);
        // stfs f0 back elsewhere.
        t.fpr[1] = 2.25;
        let stfs = (52u32 << 26) | (1 << 21) | (8 << 16) | 16;
        run_word(stfs, &mut t, &mut m); // stfs f1,16(r8)
        let b = m.read_bytes(0x3010, 4).unwrap();
        assert_eq!(f32::from_be_bytes([b[0], b[1], b[2], b[3]]), 2.25);
        // lfd/stfd double roundtrip.
        t.fpr[2] = -3.75;
        let stfd = (54u32 << 26) | (2 << 21) | (8 << 16) | 32;
        run_word(stfd, &mut t, &mut m);
        t.fpr[3] = 0.0;
        let lfd = (50u32 << 26) | (3 << 21) | (8 << 16) | 32;
        run_word(lfd, &mut t, &mut m);
        assert_eq!(t.fpr[3], -3.75);
        // Update forms write back the EA.
        let lfsu = (49u32 << 26) | (4 << 21) | (8 << 16) | 40;
        run_word(lfsu, &mut t, &mut m);
        assert_eq!((t.gpr[8] as u32), 0x3028);
    }

    #[test]
    fn float_arithmetic_retail() {
        let (mut t, mut m) = setup();
        // Retail word: fneg f0,f0 -> 0xFC000050.
        t.fpr[0] = 1.5;
        run_word(0xFC00_0050, &mut t, &mut m);
        assert_eq!(t.fpr[0], -1.5);
        // fmr copies.
        t.fpr[5] = 2.5;
        let fmr = (63u32 << 26) | (6 << 21) | (5 << 11) | (72 << 1);
        run_word(fmr, &mut t, &mut m); // fmr f6,f5
        assert_eq!(t.fpr[6], 2.5);
        // fadd double.
        t.fpr[1] = 1.25;
        t.fpr[2] = 2.5;
        let fadd = (63u32 << 26) | (3 << 21) | (1 << 16) | (2 << 11) | (21 << 1);
        run_word(fadd, &mut t, &mut m); // fadd f3,f1,f2
        assert_eq!(t.fpr[3], 3.75);
        // fctiwz + stfiwx pair: 3.75 -> 3 stored as word
        // (stfiwx XO 983 per IBM Appendix F; 659 is mfsrin).
        t.fpr[4] = 3.75;
        let fctiwz = (63u32 << 26) | (5 << 21) | (4 << 11) | (15 << 1);
        run_word(fctiwz, &mut t, &mut m); // fctiwz f5,f4
        t.gpr[8] = 0x3000_u64;
        let stfiwx = (31u32 << 26) | (5 << 21) | (8 << 11) | (983 << 1);
        run_word(stfiwx, &mut t, &mut m); // stfiwx f5,r8,0
        assert_eq!(m.read_u32(0x3000).unwrap(), 3);
        // lfiwax inverts it (XO 855 per LLVM PPCInstrInfo).
        let lfiwax = (31u32 << 26) | (6 << 21) | (8 << 11) | (855 << 1);
        run_word(lfiwax, &mut t, &mut m); // lfiwax f6,r8,0
        assert_eq!(t.fpr[6], 3.0);
        // fcmpu orders onto the asked field; NaN is FU.
        let fcmpu = (63u32 << 26) | (2 << 21) | (1 << 16) | (2 << 11);
        run_word(fcmpu, &mut t, &mut m); // fcmpu cr0,f1,f2 (1.25<2.5)
        assert_eq!(t.cr.field(0), 0b1000);
        t.fpr[2] = f64::NAN;
        run_word(fcmpu, &mut t, &mut m);
        assert_eq!(t.cr.field(0), 0b0001);
        // fctiw rounds ties to even (2.5 -> 2, 3.5 -> 4).
        t.fpr[7] = 2.5;
        let fctiw = (63u32 << 26) | (8 << 21) | (7 << 11) | (14 << 1);
        run_word(fctiw, &mut t, &mut m);
        assert_eq!(t.fpr[8].to_bits() as u32, 2);
        t.fpr[7] = 3.5;
        run_word(fctiw, &mut t, &mut m);
        assert_eq!(t.fpr[8].to_bits() as u32, 4);
        // Retail word: fcfid f13,f0 -> 0xFDA0069C.
        t.fpr[0] = f64::from_bits(0xFFFF_FFFF_FFFF_FFF0);
        run_word(0xFDA0_069C, &mut t, &mut m);
        assert_eq!(t.fpr[13], -16.0);
        // fctidz truncates toward zero into int64 bits.
        t.fpr[9] = -3.75;
        let fctidz = (63u32 << 26) | (10 << 21) | (9 << 11) | (815 << 1);
        run_word(fctidz, &mut t, &mut m);
        assert_eq!(t.fpr[10].to_bits(), (-3i64) as u64);
    }

    #[test]
    fn stdu_ld_update_ra() {
        let (mut t, mut m) = setup();
        t.gpr[1] = 0x5000_u64;
        t.gpr[5] = 0x0102_0304_0506_0708;
        run_word(0xF821_FFC1, &mut t, &mut m); // stdu r1,-64(r1)? rs=1: stores r1
        assert_eq!((t.gpr[1] as u32), 0x5000 - 64);
        // ldu back with a scratch register.
        t.gpr[6] = (0x5000 - 64) as u64;
        run_word(0xE8E6_0001, &mut t, &mut m); // ldu r7,0(r6)
        assert_eq!(t.gpr[7], 0x5000); // value stored above (old r1)
        assert_eq!((t.gpr[6] as u32), 0x5000 - 64);
    }

    #[test]
    fn dword_four_aligned_roundtrips() {
        // Retail Braid `std` to 4-aligned addresses must work.
        let (mut t, mut m) = setup();
        t.gpr[3] = 0x3004_u64;
        t.gpr[4] = 0x1122_3344_5566_7788;
        run_word(0xF883_0000, &mut t, &mut m); // std r4,0(r3)
        assert_eq!(m.read_u64(0x3004).unwrap(), 0x1122_3344_5566_7788);
    }

    #[test]
    fn dword_ea_wraps_to_32bit_map() {
        // Retail memcpy shape: base -8 (sign-extended) + 8 reads 0.
        let (mut t, mut m) = setup();
        m.write_u64(0x0, 0x1122_3344_5566_7788).unwrap();
        t.gpr[4] = 0xFFFF_FFFF_FFFF_FFF8; // (0) + (-8), 64-bit
        let ldu = (58u32 << 26) | (7 << 21) | (4 << 16) | (2 << 2) | 1;
        run_word(ldu, &mut t, &mut m); // ldu r7,r4,8
        assert_eq!(t.gpr[7], 0x1122_3344_5566_7788);
        assert_eq!((t.gpr[4] as u32), 0);
    }

    #[test]
    fn cache_hints_noop_and_dcbz_zeroes() {
        let (mut t, mut m) = setup();
        t.gpr[4] = 0x3000_u64;
        // dcbt r0,r4: no fault, pc advances.
        run_word(0x7C00_222C, &mut t, &mut m);
        // dcbz r0,r4: 128-byte line at 0x3000 goes to zero.
        m.write_u32(0x3000, 0xDEAD_BEEF).unwrap();
        m.write_u32(0x307C, 0x1234_5678).unwrap();
        let dcbz = (31u32 << 26) | (4 << 11) | (1014 << 1);
        run_word(dcbz, &mut t, &mut m);
        assert_eq!(m.read_u32(0x3000).unwrap(), 0);
        assert_eq!(m.read_u32(0x307C).unwrap(), 0);
        // Misaligned target still zeroes its whole line.
        m.write_u32(0x3040, 0xFFFF_FFFF).unwrap();
        t.gpr[5] = 0x3041_u64;
        let dcbz2 = (31u32 << 26) | (5 << 11) | (1014 << 1);
        run_word(dcbz2, &mut t, &mut m);
        assert_eq!(m.read_u32(0x3040).unwrap(), 0);
    }

    #[test]
    fn word_ops_zero_extend() {
        // True word ops (loads, D-form logicals, word shifts) clear the
        // high half; arithmetic and X-form logicals are full 64-bit.
        let (mut t, mut m) = setup();
        // addi preserves high halves (64-bit add).
        t.gpr[3] = 0xFFFF_FFFF_0000_0000;
        run_word(0x3863_0001, &mut t, &mut m); // addi r3,r3,1
        assert_eq!(t.gpr[3], 0xFFFF_FFFF_0000_0001);
        // ori clears the high half (D-form logicals are 32-bit).
        t.gpr[3] = 0xFFFF_FFFF_0000_0000;
        run_word(0x6063_00FF, &mut t, &mut m); // ori r3,r3,0xFF
        assert_eq!(t.gpr[3], 0xFF);
        // X-form or keeps the high half (64-bit logical).
        t.gpr[4] = 0xFFFF_0000_0000_0000;
        t.gpr[5] = 0x0000_0000_0000_00FF;
        let or = (31u32 << 26) | (4 << 21) | (6 << 16) | (5 << 11) | (444 << 1);
        run_word(or, &mut t, &mut m); // or r6,r4,r5
        assert_eq!(t.gpr[6], 0xFFFF_0000_0000_00FF);
        // extsh sign-extends to 64 bits.
        t.gpr[7] = 0x0000_0000_0000_80FF;
        let extsh = (31u32 << 26) | (7 << 21) | (8 << 16) | (922 << 1);
        run_word(extsh, &mut t, &mut m); // extsh r8,r7
        assert_eq!(t.gpr[8], 0xFFFF_FFFF_FFFF_80FF);
    }

    #[test]
    fn mul_div_doubleword_family() {
        let (mut t, mut m) = setup();
        // Retail word: divd r7,r31,r11 -> 0x7CFF5BD2.
        t.gpr[31] = 100;
        t.gpr[11] = 7;
        run_word(0x7CFF_5BD2, &mut t, &mut m);
        assert_eq!(t.gpr[7], 14);
        // mulld low 64.
        t.gpr[4] = 0xFFFF_FFFF_FFFF_FFFD;
        t.gpr[5] = 5;
        let mulld = (31u32 << 26) | (6 << 21) | (4 << 16) | (5 << 11) | (233 << 1);
        run_word(mulld, &mut t, &mut m);
        assert_eq!(t.gpr[6], 0xFFFF_FFFF_FFFF_FFF1);
        // mulhdu high of max*max.
        t.gpr[4] = u64::MAX;
        t.gpr[5] = u64::MAX;
        let mulhdu = (31u32 << 26) | (6 << 21) | (4 << 16) | (5 << 11) | (9 << 1);
        run_word(mulhdu, &mut t, &mut m);
        assert_eq!(t.gpr[6], 0xFFFF_FFFF_FFFF_FFFE);
        // divdu by zero yields 0.
        t.gpr[5] = 0;
        let divdu = (31u32 << 26) | (6 << 21) | (4 << 16) | (5 << 11) | (457 << 1);
        run_word(divdu, &mut t, &mut m);
        assert_eq!(t.gpr[6], 0);
        // INT64_MIN / -1 yields INT64_MIN, OE set.
        t.gpr[4] = 0x8000_0000_0000_0000;
        t.gpr[5] = 0xFFFF_FFFF_FFFF_FFFF;
        let divdo = (31u32 << 26) | (6 << 21) | (4 << 16) | (5 << 11) | (489 << 1) | (1 << 10);
        run_word(divdo, &mut t, &mut m);
        assert_eq!(t.gpr[6], 0x8000_0000_0000_0000);
        assert!(t.xer.so());
    }

    #[test]
    fn mftb_retail_word() {
        // Retail word: mftb r11,tbl -> 0x7D6C42E6 (tbr 268).
        let (mut t, mut m) = setup();
        run_word(0x7D6C_42E6, &mut t, &mut m);
        let lo = t.gpr[11] as u32;
        // TBU half arrives via tbr 269 (same tick base, high word).
        let tbu = (31u32 << 26) | (11 << 21) | (269 & 31) << 16 | ((269 >> 5) << 11) | (371 << 1);
        run_word(tbu, &mut t, &mut m);
        let hi = t.gpr[11] as u32;
        // Recombined ticks advance with wall time (nonzero on any real clock).
        assert!((hi as u64) << 32 | lo as u64 > 0);
        // Unknown time-base register stays explicit.
        let bad = (31u32 << 26) | (11 << 21) | (270 & 31) << 16 | ((270 >> 5) << 11) | (371 << 1);
        let d = decode(bad).unwrap();
        assert!(execute(d, bad, &mut t, &mut m).is_err());
    }

    #[test]
    fn neg_word_retail() {
        let (mut t, mut m) = setup();
        // Retail word: neg r3,r11 -> 0x7C6B00D0. 64-bit negate
        // (reference InstrEmit_negx): low word matches the old
        // word-oriented expectation, high half is the true 64-bit sign.
        t.gpr[11] = 1_u64;
        run_word(0x7C6B_00D0, &mut t, &mut m);
        assert_eq!((t.gpr[3] as u32), 0xFFFF_FFFF);
        assert_eq!(t.gpr[3], 0xFFFF_FFFF_FFFF_FFFF);
        // Zero stays zero.
        t.gpr[11] = 0_u64;
        run_word(0x7C6B_00D0, &mut t, &mut m);
        assert_eq!((t.gpr[3] as u32), 0);
        // 0x80000000 negates without overflow (fits in 64 bits).
        t.gpr[11] = 0x8000_0000_u64;
        run_word(0x7C6B_00D0, &mut t, &mut m);
        assert_eq!(t.gpr[3], 0xFFFF_FFFF_8000_0000);
        // Only INT64_MIN overflows with OE.
        t.gpr[11] = 0x8000_0000_0000_0000_u64;
        let nego = 0x7C6B_00D0 | (1 << 10);
        run_word(nego, &mut t, &mut m);
        assert_eq!(t.gpr[3], 0x8000_0000_0000_0000);
        assert!(t.xer.so());
    }

    #[test]
    fn carry_chain_addc_adde_addze() {
        let (mut t, mut m) = setup();
        // 64-bit addc (reference InstrEmit_addcx): low-word overflow
        // alone does NOT carry (carry is out of bit 0, 64-bit).
        t.gpr[10] = 0xFFFF_FFFF_u64;
        t.gpr[11] = 1_u64;
        let addc = (31u32 << 26) | (12 << 21) | (10 << 16) | (11 << 11) | (10 << 1);
        run_word(addc, &mut t, &mut m);
        assert_eq!(t.gpr[12], 0x1_0000_0000);
        assert!(!t.xer.ca());
        // True 64-bit carry: MAX + 1 -> 0 with carry.
        t.gpr[10] = 0xFFFF_FFFF_FFFF_FFFF_u64;
        t.gpr[11] = 1_u64;
        run_word(addc, &mut t, &mut m);
        assert_eq!(t.gpr[12], 0);
        assert!(t.xer.ca());
        // High word: 0 + 0 + CA -> 1 (retail addze pattern).
        t.gpr[13] = 0_u64;
        t.gpr[14] = 0_u64;
        let adde = (31u32 << 26) | (15 << 21) | (13 << 16) | (14 << 11) | (138 << 1);
        run_word(adde, &mut t, &mut m);
        assert_eq!(t.gpr[15], 1);
        // Retail pattern: addze r10,r10 with CA set wraps to 0, CA stays set.
        t.xer.set_ca(true);
        t.gpr[10] = 0xFFFF_FFFF_FFFF_FFFF_u64;
        run_word(0x7D4A_0194, &mut t, &mut m); // addze r10,r10 (202<<1=0x194)
        assert_eq!(t.gpr[10], 0);
        assert!(t.xer.ca());
    }

    #[test]
    fn subfe_borrows() {
        let (mut t, mut m) = setup();
        // 3 - 5 with CA=1 -> -2, CA clear.
        t.xer.set_ca(true);
        t.gpr[8] = 5_u64;
        t.gpr[9] = 3_u64;
        let subfe = (31u32 << 26) | (7 << 21) | (8 << 16) | (9 << 11) | (136 << 1);
        run_word(subfe, &mut t, &mut m);
        assert_eq!((t.gpr[7] as u32), 0xFFFF_FFFE);
        assert!(!t.xer.ca());
        // 5 - 3 with CA=1 -> 2, CA set.
        t.xer.set_ca(true);
        t.gpr[8] = 3_u64;
        t.gpr[9] = 5_u64;
        run_word(subfe, &mut t, &mut m);
        assert_eq!((t.gpr[7] as u32), 2);
        assert!(t.xer.ca());
    }

    #[test]
    fn mul_div_word_family() {
        let (mut t, mut m) = setup();
        // Retail word: divwu r11,r30,r3 -> 0x7D7E1B96.
        t.gpr[30] = 100_u64;
        t.gpr[3] = 7_u64;
        run_word(0x7D7E_1B96, &mut t, &mut m);
        assert_eq!((t.gpr[11] as u32), 14);
        // mullw: (-3) * 5 = -15.
        t.gpr[4] = 0xFFFF_FFFD_u64;
        t.gpr[5] = 5_u64;
        let mullw = (31u32 << 26) | (6 << 21) | (4 << 16) | (5 << 11) | (235 << 1);
        run_word(mullw, &mut t, &mut m);
        assert_eq!((t.gpr[6] as u32), 0xFFFF_FFF1);
        // mulhwu: high of 0xFFFFFFFF * 0xFFFFFFFF.
        t.gpr[4] = 0xFFFF_FFFF_u64;
        t.gpr[5] = 0xFFFF_FFFF_u64;
        let mulhwu = (31u32 << 26) | (6 << 21) | (4 << 16) | (5 << 11) | (11 << 1);
        run_word(mulhwu, &mut t, &mut m);
        assert_eq!((t.gpr[6] as u32), 0xFFFF_FFFE);
        // divw: -7 / 2 = -3 (truncate toward zero).
        t.gpr[4] = 0xFFFF_FFF9_u64;
        t.gpr[5] = 2_u64;
        let divw = (31u32 << 26) | (6 << 21) | (4 << 16) | (5 << 11) | (491 << 1);
        run_word(divw, &mut t, &mut m);
        assert_eq!((t.gpr[6] as u32), 0xFFFF_FFFD);
        // divw by zero yields 0 (documented edge choice).
        t.gpr[5] = 0_u64;
        run_word(divw, &mut t, &mut m);
        assert_eq!((t.gpr[6] as u32), 0);
        // divwo by zero sets OV (SO sticky).
        let divwo = divw | (1 << 10);
        run_word(divwo, &mut t, &mut m);
        assert!(t.xer.so());
        // INT_MIN / -1 yields 0x80000000.
        t.gpr[4] = 0x8000_0000_u64;
        t.gpr[5] = 0xFFFF_FFFF_u64;
        run_word(divw, &mut t, &mut m);
        assert_eq!((t.gpr[6] as u32), 0x8000_0000);
    }

    #[test]
    fn logical_complements() {
        let (mut t, mut m) = setup();
        // Retail word: andc r9,r9,r8 -> 0x7D294078.
        t.gpr[8] = 0b1100_u64;
        t.gpr[9] = 0b1010_u64;
        run_word(0x7D29_4078, &mut t, &mut m);
        assert_eq!((t.gpr[9] as u32), 0b0010);
        // orc / nand / eqv vectors (operands reset each time).
        // X-form logicals: RS lives in the RT field, destination in RA.
        let orc = (31u32 << 26) | (8 << 21) | (10 << 16) | (9 << 11) | (412 << 1);
        t.gpr[8] = 0b1100_u64;
        t.gpr[9] = 0b1010_u64;
        run_word(orc, &mut t, &mut m);
        assert_eq!((t.gpr[10] as u32), 0b1100 | !0b1010);
        let nand = (31u32 << 26) | (8 << 21) | (10 << 16) | (9 << 11) | (238 << 1);
        t.gpr[8] = 0b1100_u64;
        t.gpr[9] = 0b1010_u64;
        run_word(nand, &mut t, &mut m);
        assert_eq!((t.gpr[10] as u32), !(0b1100 & 0b1010));
        let eqv = (31u32 << 26) | (8 << 21) | (10 << 16) | (9 << 11) | (289 << 1);
        t.gpr[8] = 0b1100_u64;
        t.gpr[9] = 0b1010_u64;
        run_word(eqv, &mut t, &mut m);
        assert_eq!((t.gpr[10] as u32), !(0b1100 ^ 0b1010));
    }

    #[test]
    fn rotates_masks_inserts() {
        let (mut t, mut m) = setup();
        // Retail word: rldicl r9,r11,0,32 keeps the low half.
        t.gpr[11] = 0x8000_0000_0000_0001;
        run_word(0x7969_0020, &mut t, &mut m);
        assert_eq!(t.gpr[9], 0x0000_0000_0000_0001);
        // Full ones under mask(32,63) keep only the low half.
        t.gpr[11] = 0xFFFF_FFFF_FFFF_FFFF;
        run_word(0x7969_0020, &mut t, &mut m);
        assert_eq!(t.gpr[9], 0x0000_0000_FFFF_FFFF);
        // sldi pattern via rldicr: r5 = r6 << 4 (sh=4, me=59).
        t.gpr[6] = 0x1234;
        run_word(0x78C5_26E4, &mut t, &mut m);
        assert_eq!(t.gpr[5], 0x12340);
        // rldimi r7,r8,60,60 under mask(60,4) = 0xF80000000000000F.
        t.gpr[7] = 0xFFFF_FFFF_FFFF_FFFF;
        t.gpr[8] = 0x12;
        run_word(0x7907_E72E, &mut t, &mut m);
        assert_eq!(t.gpr[7], 0x27FF_FFFF_FFFF_FFF1);
        // rldic r5,r6,8,32 clears under MASK(32,~8=56).
        t.gpr[6] = 0xFFFF_FFFF_FFFF_FFFF;
        let rldic = (30u32 << 26) | (6 << 21) | (5 << 16) | (8 << 11) | (1 << 5) | (2 << 2);
        run_word(rldic, &mut t, &mut m);
        assert_eq!(t.gpr[5], 0x0000_0000_FFFF_FF80);
        // 6-bit shift: rldicl r4,r3,40,0 (SH5 set).
        t.gpr[3] = 1;
        run_word(0x7864_4002, &mut t, &mut m);
        assert_eq!(t.gpr[4], 0x100_0000_0000);
        // extsw r6,r5 sign-extends the low word (RS=r5 in RT field).
        t.gpr[5] = 0x1234_8000_0001;
        run_word(0x7CA6_07B4, &mut t, &mut m); // extsw r6,r5
        assert_eq!(t.gpr[6], 0xFFFF_FFFF_8000_0001);
        // cntlzd r8,r7 counts the high zeros (RS=r7 in RT field).
        t.gpr[7] = 0x0000_F000_0000_0000;
        run_word(0x7CE8_0074, &mut t, &mut m); // cntlzd r8,r7
        assert_eq!(t.gpr[8], 16);
        t.gpr[7] = 0;
        run_word(0x7CE8_0074, &mut t, &mut m);
        assert_eq!(t.gpr[8], 64);
    }

    #[test]
    fn addic_carry_and_cr0() {
        let (mut t, mut m) = setup();
        // 64-bit addic.: 0xFFFFFFFF + 1 = 0x100000000, no 64-bit
        // carry; CR0 GT (nonzero).
        t.gpr[8] = 0xFFFF_FFFF_u64;
        run_word(0x3508_0001, &mut t, &mut m); // addic. r8,r8,1
        assert_eq!(t.gpr[8], 0x1_0000_0000);
        assert!(!t.xer.ca());
        assert_eq!(t.cr.field(0) & 0b0100, 0b0100); // GT
                                                    // True 64-bit carry sets CA and CR0 EQ on zero.
        t.gpr[8] = 0xFFFF_FFFF_FFFF_FFFF_u64;
        run_word(0x3508_0001, &mut t, &mut m);
        assert_eq!(t.gpr[8], 0);
        assert!(t.xer.ca());
        assert_eq!(t.cr.field(0) & 0b0010, 0b0010); // EQ
                                                    // No carry, nonzero result: CA clear, CR0 GT.
        t.gpr[8] = 5_u64;
        run_word(0x3508_0000, &mut t, &mut m); // addic. r8,r8,0
        assert_eq!((t.gpr[8] as u32), 5);
        assert!(!t.xer.ca());
        assert_eq!(t.cr.field(0) & 0b0100, 0b0100); // GT
                                                    // 5 + (-1) = 4 with 64-bit carry out: CA set.
        t.gpr[8] = 5_u64;
        run_word(0x3508_FFFF, &mut t, &mut m); // addic. r8,r8,-1
        assert_eq!((t.gpr[8] as u32), 4);
        assert!(t.xer.ca());
        // Plain addic leaves CR0 alone.
        t.cr.set_field(0, 0b0010);
        run_word(0x3108_0000, &mut t, &mut m); // addic r8,r8,0
        assert_eq!(t.cr.field(0) & 0xF, 0b0010);
    }

    #[test]
    fn lwarx_stwcx_success_sets_cr_eq() {
        let (mut t, mut m) = setup();
        m.write_u32(0x3000, 7).unwrap();
        t.gpr[3] = 0x3000_u64;
        // lwarx r4,0,r3 ; need encoding: XO=20. Build via fields.
        // opcode31 | rt=4<<21 | rb=3<<11 | XO20<<1 (ra=0 omitted)
        let lwarx = (31u32 << 26) | (4 << 21) | (3 << 11) | (20 << 1);
        let stwcx = (31u32 << 26) | (5 << 21) | (3 << 11) | (150 << 1) | 1;
        t.gpr[5] = 42_u64;
        let d = decode(lwarx).unwrap();
        execute(d, lwarx, &mut t, &mut m).unwrap();
        assert_eq!((t.gpr[4] as u32), 7);
        let d2 = decode(stwcx).unwrap();
        execute(d2, stwcx, &mut t, &mut m).unwrap();
        assert_eq!(m.read_u32(0x3000).unwrap(), 42);
        assert_eq!(t.cr.field(0) & 0b0010, 0b0010);
    }

    #[test]
    fn vmx_is_explicit_unsupported() {
        let (mut t, mut m) = setup();
        let d = decode(0x1000_0000).unwrap();
        assert!(execute(d, 0x1000_0000, &mut t, &mut m).is_err());
    }

    #[test]
    fn bcctr_does_not_decrement_ctr() {
        use crate::regs::ThreadState;
        use x360_memory::Memory;
        let mut t = ThreadState::new(0, 0x1000);
        let mut m = Memory::new();
        t.ctr = 0x2000;
        // bcctr always: BO=0b10100 (no CTR test, no CR test), XO=528 (ra field omitted)
        let word = (19u32 << 26) | (0b10100 << 21) | (528 << 1);
        let d = decode(word).unwrap();
        execute(d, word, &mut t, &mut m).unwrap();
        assert_eq!(t.ctr, 0x2000);
        assert_eq!(t.pc, 0x2000);
    }

    #[test]
    fn add_oe_sets_overflow() {
        use crate::regs::ThreadState;
        use x360_memory::Memory;
        let mut t = ThreadState::new(0, 0x1000);
        let mut m = Memory::new();
        // 64-bit overflow only: INT64_MAX + 1 wraps with OE.
        t.gpr[3] = 0x7FFF_FFFF_FFFF_FFFF_u64;
        t.gpr[4] = 1_u64;
        // add r5,r3,r4 with OE=1, Rc=0: XO=266, OE bit10=1
        let word = (31u32 << 26) | (5 << 21) | (3 << 16) | (4 << 11) | (1 << 10) | (266 << 1);
        let d = decode(word).unwrap();
        execute(d, word, &mut t, &mut m).unwrap();
        assert_eq!(t.gpr[5], 0x8000_0000_0000_0000);
        assert!(t.xer.so());
        // 0x7FFFFFFF + 1 fits in 64 bits: value lands, no overflow.
        t.gpr[3] = 0x7FFF_FFFF_u64;
        t.gpr[4] = 1_u64;
        t.xer.0 &= !(1 << 31); // clear sticky SO for the negative check
        execute(d, word, &mut t, &mut m).unwrap();
        assert_eq!(t.gpr[5], 0x8000_0000);
        assert!(!t.xer.so());
    }

    #[test]
    fn add_family_is_64bit() {
        let (mut t, mut m) = setup();
        // addi preserves high halves: (1<<32) + 1.
        t.gpr[6] = 0x1_0000_0000_u64;
        run_word(0x38C6_0001, &mut t, &mut m); // addi r6,r6,1
        assert_eq!(t.gpr[6], 0x1_0000_0001);
        // Plain add records no CA (ISA: only addc/adde/... record CA).
        t.xer.set_ca(true);
        t.gpr[7] = 5_u64;
        t.gpr[8] = 7_u64;
        let add = (31u32 << 26) | (9 << 21) | (7 << 16) | (8 << 11) | (266 << 1);
        run_word(add, &mut t, &mut m);
        assert_eq!(t.gpr[9], 12);
        assert!(t.xer.ca()); // untouched (was set)
        t.xer.set_ca(false);
        t.gpr[7] = 0xFFFF_FFFF_FFFF_FFFF_u64;
        t.gpr[8] = 1_u64;
        run_word(add, &mut t, &mut m);
        assert_eq!(t.gpr[9], 0);
        assert!(!t.xer.ca()); // still untouched (was clear)
                              // addis with negative simm sign-extends into the high half
                              // (retail global-address idiom: addis r11,0,-32248).
        t.gpr[11] = 0_u64;
        run_word(0x3D60_8208, &mut t, &mut m); // addis r11,0,0x8208
        assert_eq!(t.gpr[11], 0xFFFF_FFFF_8208_0000);
        // mulli keeps the full 64-bit product.
        t.gpr[12] = 0x1_0000_u64;
        run_word(0x1DAC_0001, &mut t, &mut m); // mulli r13,r12,1
        assert_eq!(t.gpr[13], 0x1_0000);
        t.gpr[12] = 0x1_0000_0000_u64;
        run_word(0x1DAC_FFFF, &mut t, &mut m); // mulli r13,r12,-1
        assert_eq!(t.gpr[13], 0xFFFF_FFFF_0000_0000);
    }

    // --- Rotate-and-mask + compares (retail prologue staples) ---

    fn mform(opc: u32, rs: u32, ra: u32, sh: u32, mb: u32, me: u32, rc: u32) -> u32 {
        (opc << 26) | (rs << 21) | (ra << 16) | (sh << 11) | (mb << 6) | (me << 1) | rc
    }

    #[test]
    fn rlwinm_extracts_field() {
        // rlwinm r5,r3,0,24,31 — low byte extract.
        let (mut t, mut m) = setup();
        t.gpr[3] = 0xDEAD_BEEF_u64;
        run_word(mform(21, 3, 5, 0, 24, 31, 0), &mut t, &mut m);
        assert_eq!((t.gpr[5] as u32), 0xEF);
    }

    #[test]
    fn rlwinm_rotate_and_wrap_mask() {
        // rlwinm r5,r3,4,0,27 — rotate 4, keep top 28 bits.
        let (mut t, mut m) = setup();
        t.gpr[3] = 0x1234_5678_u64;
        run_word(mform(21, 3, 5, 4, 0, 27, 0), &mut t, &mut m);
        assert_eq!(
            (t.gpr[5] as u32),
            (t.gpr[3] as u32).rotate_left(4) & 0xFFFF_FFF0
        );
    }

    #[test]
    fn rlwimi_inserts() {
        // rlwimi r5,r3,16,0,15 — insert low half of r3 into top of r5.
        let (mut t, mut m) = setup();
        t.gpr[3] = 0x0000_ABCD_u64;
        t.gpr[5] = 0x1234_5678_u64;
        run_word(mform(20, 3, 5, 16, 0, 15, 0), &mut t, &mut m);
        assert_eq!((t.gpr[5] as u32), 0xABCD_5678);
    }

    #[test]
    fn rlwnm_uses_rb_shift() {
        // rlwnm r5,r3,r4,0,31 (full mask) with r4=8.
        let (mut t, mut m) = setup();
        t.gpr[3] = 0x0000_0001_u64;
        t.gpr[4] = 8_u64;
        run_word(mform(23, 3, 5, 4, 0, 31, 0), &mut t, &mut m);
        assert_eq!((t.gpr[5] as u32), 0x100);
    }

    #[test]
    fn rlwinm_rc_sets_cr0() {
        let (mut t, mut m) = setup();
        t.gpr[3] = 0_u64;
        run_word(mform(21, 3, 5, 0, 0, 31, 1), &mut t, &mut m);
        assert_eq!(t.cr.field(0) & 0b0010, 0b0010); // EQ
    }

    #[test]
    fn cmpli_conditions() {
        let (mut t, mut m) = setup();
        // cmpli cr1,r0,5 ; r3=5 -> EQ in cr1
        t.gpr[3] = 5_u64;
        let w = (10u32 << 26) | (1 << 23) | (3 << 16) | 5;
        run_word(w, &mut t, &mut m);
        assert_eq!(t.cr.field(1), 0b0010);
        // cmpli cr1,r0,6 ; 5<6 -> LT
        let w = (10u32 << 26) | (1 << 23) | (3 << 16) | 6;
        run_word(w, &mut t, &mut m);
        assert_eq!(t.cr.field(1) >> 3 & 1, 1);
        // unsigned: 0xFFFFFFFF > 6 -> GT
        t.gpr[3] = 0xFFFF_FFFF_u64;
        run_word(w, &mut t, &mut m);
        assert_eq!(t.cr.field(1) >> 2 & 1, 1);
    }

    #[test]
    fn cmpi_signed() {
        let (mut t, mut m) = setup();
        // cmpi cr0,r3,-1 ; r3=-5 < -1 -> LT
        t.gpr[3] = ((-5i32) as u32) as u64;
        let w = (11u32 << 26) | (3 << 16) | 0xFFFF;
        run_word(w, &mut t, &mut m);
        assert_eq!(t.cr.field(0) >> 3 & 1, 1);
    }

    #[test]
    fn cmp_l64_compares_full_width() {
        let (mut t, mut m) = setup();
        // Retail dash word: cmpli cr?,r?,0 with L=1 -> 0x2B2A0000.
        let d = decode(0x2B2A_0000).unwrap();
        assert!(matches!(
            decode(0x2B2A_0000).unwrap(),
            Decoded::Cmpli { l: true, .. }
        ));
        // cmpli L=1: full 64-bit unsigned vs zero-extended uimm.
        t.gpr[10] = 0x1_0000_0001_u64;
        let w = (10u32 << 26) | (1 << 21) | (10 << 16) | 1;
        run_word(w, &mut t, &mut m); // cmpli cr0,r10,1 (L=1)
        assert_eq!(t.cr.field(0), 0b0100); // GT
        t.gpr[10] = 1_u64;
        run_word(w, &mut t, &mut m);
        assert_eq!(t.cr.field(0), 0b0010); // EQ
                                           // High half decides: low-half-equal values differ in 64 bits.
        t.gpr[9] = 0x1_0000_0005_u64;
        t.gpr[11] = 0x0000_0005_u64;
        let _ = d;
        // cmpd cr6,r9,r11 (X-form L=1: RT=(6<<2)|1=25).
        let cmpd = (31u32 << 26) | (25 << 21) | (9 << 16) | (11 << 11);
        assert!(matches!(
            decode(cmpd).unwrap(),
            Decoded::Cmp { bf: 6, l: true, .. }
        ));
        run_word(cmpd, &mut t, &mut m);
        assert_eq!(t.cr.field(6), 0b0100); // GT in 64 bits, EQ in 32
                                           // cmpld equal in 64 bits.
        let cmpld = (31u32 << 26) | (25 << 21) | (9 << 16) | (9 << 11) | (32 << 1);
        run_word(cmpld, &mut t, &mut m);
        assert_eq!(t.cr.field(6), 0b0010);
        // cmpi L=1 sign-extends the immediate to 64.
        t.gpr[12] = 0xFFFF_FFFF_FFFF_FFFF_u64; // -1
        let cmpi = (11u32 << 26) | (1 << 21) | (12 << 16) | 0xFFFF;
        run_word(cmpi, &mut t, &mut m); // cmpi cr0,r12,-1 (L=1)
        assert_eq!(t.cr.field(0), 0b0010);
    }

    #[test]
    fn cmp_and_cmpl_registers() {
        let (mut t, mut m) = setup();
        // cmplw cr6,r9,r11: XO=32, RT=(6<<2)|0=24.
        t.gpr[9] = 10_u64;
        t.gpr[11] = 20_u64;
        let w = (31u32 << 26) | (24 << 21) | (9 << 16) | (11 << 11) | (32 << 1);
        assert!(matches!(decode(w).unwrap(), Decoded::Cmpl { .. }));
        run_word(w, &mut t, &mut m);
        assert_eq!(t.cr.field(6), 0b1000); // LT
                                           // cmpw cr6,r9,r11 with equal values -> EQ.
        t.gpr[11] = 10_u64;
        let w = (31u32 << 26) | (24 << 21) | (9 << 16) | (11 << 11);
        assert!(matches!(decode(w).unwrap(), Decoded::Cmp { .. }));
        run_word(w, &mut t, &mut m);
        assert_eq!(t.cr.field(6), 0b0010); // EQ
    }

    // --- Update-form stores ---

    #[test]
    fn stwux_store_updates_ra() {
        let (mut t, mut m) = setup();
        t.gpr[3] = 0x2000_u64;
        t.gpr[4] = 4_u64;
        t.gpr[5] = 0xDEAD_BEEF_u64;
        let w = xform(5, 3, 4, 183, 0);
        assert!(matches!(decode(w).unwrap(), Decoded::Stwux { .. }));
        run_word(w, &mut t, &mut m);
        assert_eq!(m.read_u32(0x2004).unwrap(), 0xDEAD_BEEF);
        assert_eq!((t.gpr[3] as u32), 0x2004);
    }

    #[test]
    fn stwux_ra0_rejected() {
        let (mut t, mut m) = setup();
        t.gpr[4] = 4_u64;
        t.gpr[5] = 1_u64;
        let msg = expect_unsupported(xform(5, 0, 4, 183, 0), &mut t, &mut m);
        assert!(msg.contains("stwux"));
    }

    #[test]
    fn stbu_store_updates_ra() {
        let (mut t, mut m) = setup();
        t.gpr[3] = 0x2000_u64;
        t.gpr[5] = 0xAB_u64;
        run_word(dform(39, 5, 3, 1), &mut t, &mut m);
        assert_eq!(m.read_u8(0x2001).unwrap(), 0xAB);
        assert_eq!((t.gpr[3] as u32), 0x2001);
    }

    #[test]
    fn stbu_ra0_rejected() {
        let (mut t, mut m) = setup();
        let msg = expect_unsupported(dform(39, 5, 0, 0), &mut t, &mut m);
        assert!(msg.contains("stbu"));
    }

    #[test]
    fn sthu_store_updates_ra() {
        let (mut t, mut m) = setup();
        t.gpr[3] = 0x2000_u64;
        t.gpr[5] = 0x1234_u64;
        run_word(dform(45, 5, 3, 2), &mut t, &mut m);
        assert_eq!(m.read_bytes(0x2002, 2).unwrap(), &[0x12, 0x34]);
        assert_eq!((t.gpr[3] as u32), 0x2002);
    }

    #[test]
    fn sthu_misaligned_faults() {
        let (mut t, mut m) = setup();
        t.gpr[3] = 0x2001_u64;
        t.gpr[5] = 0x1234_u64;
        assert_eq!(expect_align(dform(45, 5, 3, 0), &mut t, &mut m), 0x2001);
    }

    // --- Update-form loads ---

    #[test]
    fn lbzu_basic() {
        let (mut t, mut m) = setup();
        m.write_u8(0x2002, 0x7F).unwrap();
        t.gpr[3] = 0x2000_u64;
        let w = dform(35, 4, 3, 2);
        assert!(matches!(decode(w).unwrap(), Decoded::Lbzu { .. }));
        run_word(w, &mut t, &mut m);
        assert_eq!((t.gpr[4] as u32), 0x7F);
        assert_eq!((t.gpr[3] as u32), 0x2002);
    }

    #[test]
    fn lbzu_invalid_forms_rejected() {
        let (mut t, mut m) = setup();
        expect_unsupported(dform(35, 4, 0, 0), &mut t, &mut m);
        expect_unsupported(dform(35, 3, 3, 1), &mut t, &mut m);
    }

    #[test]
    fn lhau_sign_extends_and_updates() {
        let (mut t, mut m) = setup();
        m.write_bytes(0x2000, &0x8001u16.to_be_bytes()).unwrap();
        t.gpr[3] = 0x2000_u64;
        let w = dform(43, 4, 3, 0);
        assert!(matches!(decode(w).unwrap(), Decoded::Lhau { .. }));
        run_word(w, &mut t, &mut m);
        assert_eq!((t.gpr[4] as u32), 0xFFFF_8001);
        assert_eq!((t.gpr[3] as u32), 0x2000);
    }

    #[test]
    fn lhau_invalid_forms_rejected() {
        let (mut t, mut m) = setup();
        expect_unsupported(dform(43, 4, 0, 0), &mut t, &mut m);
        expect_unsupported(dform(43, 3, 3, 0), &mut t, &mut m);
    }

    #[test]
    fn lhzu_zero_extends_and_updates() {
        let (mut t, mut m) = setup();
        m.write_bytes(0x2004, &0x80FFu16.to_be_bytes()).unwrap();
        t.gpr[3] = 0x2000_u64;
        run_word(dform(41, 4, 3, 4), &mut t, &mut m);
        assert_eq!((t.gpr[4] as u32), 0x80FF);
        assert_eq!((t.gpr[3] as u32), 0x2004);
    }

    #[test]
    fn lha_ra0_sign_extends() {
        let (mut t, mut m) = setup();
        m.write_bytes(0x2000, &0xFF00u16.to_be_bytes()).unwrap();
        let w = dform(42, 4, 0, 0x2000);
        assert!(matches!(decode(w).unwrap(), Decoded::Lha { .. }));
        run_word(w, &mut t, &mut m);
        assert_eq!((t.gpr[4] as u32), 0xFFFF_FF00);
    }

    // --- Indexed byte/halfword ---

    #[test]
    fn lbzx_ra0_indexed() {
        let (mut t, mut m) = setup();
        m.write_u8(0x2005, 0x42).unwrap();
        t.gpr[4] = 0x2005_u64;
        let w = xform(5, 0, 4, 87, 0);
        assert!(matches!(decode(w).unwrap(), Decoded::Lbzx { .. }));
        run_word(w, &mut t, &mut m);
        assert_eq!((t.gpr[5] as u32), 0x42);
    }

    #[test]
    fn lbzux_basic() {
        let (mut t, mut m) = setup();
        m.write_u8(0x2004, 0x11).unwrap();
        t.gpr[3] = 0x2000_u64;
        t.gpr[4] = 4_u64;
        run_word(xform(5, 3, 4, 119, 0), &mut t, &mut m);
        assert_eq!((t.gpr[5] as u32), 0x11);
        assert_eq!((t.gpr[3] as u32), 0x2004);
    }

    #[test]
    fn stbx_basic() {
        let (mut t, mut m) = setup();
        t.gpr[3] = 0x2000_u64;
        t.gpr[4] = 8_u64;
        t.gpr[5] = 0x99_u64;
        run_word(xform(5, 3, 4, 215, 0), &mut t, &mut m);
        assert_eq!(m.read_u8(0x2008).unwrap(), 0x99);
        // Non-update form leaves RA alone.
        assert_eq!((t.gpr[3] as u32), 0x2000);
    }

    #[test]
    fn stbux_basic_and_ra0_rejected() {
        let (mut t, mut m) = setup();
        t.gpr[3] = 0x2000_u64;
        t.gpr[4] = 2_u64;
        t.gpr[5] = 0x5A_u64;
        run_word(xform(5, 3, 4, 247, 0), &mut t, &mut m);
        assert_eq!(m.read_u8(0x2002).unwrap(), 0x5A);
        assert_eq!((t.gpr[3] as u32), 0x2002);
        expect_unsupported(xform(5, 0, 4, 247, 0), &mut t, &mut m);
    }

    #[test]
    fn lhzx_basic() {
        let (mut t, mut m) = setup();
        m.write_bytes(0x2010, &0xABCDu16.to_be_bytes()).unwrap();
        t.gpr[3] = 0x2000_u64;
        t.gpr[4] = 0x10_u64;
        let w = xform(5, 3, 4, 279, 0);
        assert!(matches!(decode(w).unwrap(), Decoded::Lhzx { .. }));
        run_word(w, &mut t, &mut m);
        assert_eq!((t.gpr[5] as u32), 0xABCD);
    }

    #[test]
    fn lhzx_misaligned_faults() {
        let (mut t, mut m) = setup();
        t.gpr[3] = 0x2000_u64;
        t.gpr[4] = 1_u64;
        assert_eq!(expect_align(xform(5, 3, 4, 279, 0), &mut t, &mut m), 0x2001);
    }

    #[test]
    fn lhzux_basic() {
        let (mut t, mut m) = setup();
        m.write_bytes(0x2004, &0x00EEu16.to_be_bytes()).unwrap();
        t.gpr[3] = 0x2000_u64;
        t.gpr[4] = 4_u64;
        run_word(xform(5, 3, 4, 311, 0), &mut t, &mut m);
        assert_eq!((t.gpr[5] as u32), 0x00EE);
        assert_eq!((t.gpr[3] as u32), 0x2004);
    }

    #[test]
    fn lhax_sign_extends_indexed() {
        let (mut t, mut m) = setup();
        m.write_bytes(0x2006, &0x8002u16.to_be_bytes()).unwrap();
        t.gpr[3] = 0x2000_u64;
        t.gpr[4] = 6_u64;
        run_word(xform(5, 3, 4, 343, 0), &mut t, &mut m);
        assert_eq!((t.gpr[5] as u32), 0xFFFF_8002);
    }

    #[test]
    fn lhaux_basic_and_invalid_rejected() {
        let (mut t, mut m) = setup();
        m.write_bytes(0x2008, &0x0001u16.to_be_bytes()).unwrap();
        t.gpr[3] = 0x2000_u64;
        t.gpr[4] = 8_u64;
        run_word(xform(5, 3, 4, 375, 0), &mut t, &mut m);
        assert_eq!((t.gpr[5] as u32), 1);
        assert_eq!((t.gpr[3] as u32), 0x2008);
        expect_unsupported(xform(5, 0, 4, 375, 0), &mut t, &mut m);
        expect_unsupported(xform(3, 3, 4, 375, 0), &mut t, &mut m);
    }

    #[test]
    fn sthx_basic() {
        let (mut t, mut m) = setup();
        t.gpr[3] = 0x2000_u64;
        t.gpr[4] = 6_u64;
        t.gpr[5] = 0xBEEF_u64;
        let w = xform(5, 3, 4, 407, 0);
        assert!(matches!(decode(w).unwrap(), Decoded::Sthx { .. }));
        run_word(w, &mut t, &mut m);
        assert_eq!(m.read_bytes(0x2006, 2).unwrap(), &[0xBE, 0xEF]);
        assert_eq!((t.gpr[3] as u32), 0x2000);
    }

    #[test]
    fn sthx_misaligned_faults() {
        let (mut t, mut m) = setup();
        t.gpr[3] = 0x2000_u64;
        t.gpr[4] = 3_u64;
        t.gpr[5] = 1_u64;
        assert_eq!(expect_align(xform(5, 3, 4, 407, 0), &mut t, &mut m), 0x2003);
    }

    #[test]
    fn sthux_basic() {
        let (mut t, mut m) = setup();
        t.gpr[3] = 0x2000_u64;
        t.gpr[4] = 4_u64;
        t.gpr[5] = 0xCAFE_u64;
        run_word(xform(5, 3, 4, 439, 0), &mut t, &mut m);
        assert_eq!(m.read_bytes(0x2004, 2).unwrap(), &[0xCA, 0xFE]);
        assert_eq!((t.gpr[3] as u32), 0x2004);
    }

    // --- Shifts ---

    #[test]
    fn sraw_shifts_and_clears_ca() {
        let (mut t, mut m) = setup();
        // Positive value: exact shift, CA stays clear.
        t.gpr[5] = 0x4000_0000_u64;
        t.gpr[6] = 2_u64;
        let w = xform(5, 4, 6, 792, 0);
        assert!(matches!(decode(w).unwrap(), Decoded::Sraw { .. }));
        run_word(w, &mut t, &mut m);
        assert_eq!((t.gpr[4] as u32), 0x1000_0000);
        assert!(!t.xer.ca());
        // Positive value with bits shifted out: CA still clear.
        t.gpr[5] = 0x0000_0003_u64;
        t.gpr[6] = 1_u64;
        run_word(w, &mut t, &mut m);
        assert_eq!((t.gpr[4] as u32), 1);
        assert!(!t.xer.ca());
        // Zero shift clears a sticky CA.
        t.xer.set_ca(true);
        t.gpr[6] = 0_u64;
        run_word(w, &mut t, &mut m);
        assert_eq!((t.gpr[4] as u32), 0x0000_0003);
        assert!(!t.xer.ca());
    }

    #[test]
    fn sraw_negative_sets_ca_and_cr0() {
        let (mut t, mut m) = setup();
        t.gpr[5] = 0x8000_0001_u64;
        t.gpr[6] = 1_u64;
        run_word(xform(5, 4, 6, 792, 1), &mut t, &mut m);
        assert_eq!((t.gpr[4] as u32), 0xC000_0000);
        assert!(t.xer.ca());
        assert_eq!(t.cr.field(0), 0b1000);
    }

    #[test]
    fn srawi_immediate_with_ca() {
        let (mut t, mut m) = setup();
        // sh rides in the RB field; XO=824.
        let w = xform(5, 4, 4, 824, 0);
        assert!(matches!(decode(w).unwrap(), Decoded::Srawi { .. }));
        // -256 >> 4 = -16, low nibble was zero so CA stays clear.
        t.gpr[5] = 0xFFFF_FF00_u64;
        run_word(w, &mut t, &mut m);
        assert_eq!((t.gpr[4] as u32), 0xFFFF_FFF0);
        assert!(!t.xer.ca());
        // Shifted-out 1-bit on a negative value sets CA.
        t.gpr[5] = 0xFFFF_FF01_u64;
        run_word(w, &mut t, &mut m);
        assert_eq!((t.gpr[4] as u32), 0xFFFF_FFF0);
        assert!(t.xer.ca());
    }

    #[test]
    fn srawi_zero_sets_cr0_eq() {
        let (mut t, mut m) = setup();
        t.gpr[5] = 0_u64;
        run_word(xform(5, 4, 5, 824, 1), &mut t, &mut m);
        assert_eq!((t.gpr[4] as u32), 0);
        assert!(!t.xer.ca());
        assert_eq!(t.cr.field(0), 0b0010);
    }

    #[test]
    fn sradix_retail_word() {
        // Retail dash word: sradix r11,r11,1 -> 0x7D6B0E74.
        let (mut t, mut m) = setup();
        assert!(matches!(
            decode(0x7D6B_0E74).unwrap(),
            Decoded::Sradix {
                rs: 11,
                ra: 11,
                sh: 1,
                rc: false
            }
        ));
        t.gpr[11] = 0x8000_0000_0000_0001;
        run_word(0x7D6B_0E74, &mut t, &mut m);
        assert_eq!(t.gpr[11], 0xC000_0000_0000_0000);
        assert!(t.xer.ca()); // sign set, shifted-out 1
                             // Zero count copies and clears CA.
        let z = (31u32 << 26) | (11 << 21) | (11 << 16) | (826 << 1);
        t.gpr[11] = 0x8000_0000_0000_0001;
        t.xer.set_ca(true);
        run_word(z, &mut t, &mut m);
        assert_eq!(t.gpr[11], 0x8000_0000_0000_0001);
        assert!(!t.xer.ca());
        // Positive value: shifted-out bits never set CA.
        t.gpr[11] = 0x0000_0000_0000_0003;
        run_word(0x7D6B_0E74, &mut t, &mut m);
        assert_eq!(t.gpr[11], 1);
        assert!(!t.xer.ca());
        // SH5 extends the count (n=32): word bit 1 set.
        let hi = (31u32 << 26) | (11 << 21) | (11 << 16) | (826 << 1) | 2;
        assert!(matches!(
            decode(hi).unwrap(),
            Decoded::Sradix { sh: 32, .. }
        ));
        t.gpr[11] = 0xFFFF_FFFF_0000_0000;
        run_word(hi, &mut t, &mut m);
        assert_eq!(t.gpr[11], 0xFFFF_FFFF_FFFF_FFFF);
    }

    // --- subfic / cntlzw verification ---

    #[test]
    fn subfic_ca_semantics() {
        let (mut t, mut m) = setup();
        // 10 - 3 = 7, no borrow: CA set.
        t.gpr[3] = 3_u64;
        run_word(dform(8, 4, 3, 10), &mut t, &mut m);
        assert_eq!((t.gpr[4] as u32), 7);
        assert!(t.xer.ca());
        // 3 - 10 borrows: CA clear.
        t.gpr[3] = 10_u64;
        run_word(dform(8, 4, 3, 3), &mut t, &mut m);
        assert_eq!((t.gpr[4] as u32), 0xFFFF_FFF9);
        assert!(!t.xer.ca());
        // Negative immediate, 64-bit compare: -5 (huge unsigned) minus
        // 0xFFFFFFFE does not borrow (CA=1).
        t.gpr[3] = 0xFFFF_FFFE_u64;
        run_word(dform(8, 4, 3, -5), &mut t, &mut m);
        assert_eq!((t.gpr[4] as u32), 0xFFFF_FFFD);
        assert!(t.xer.ca());
        // D-form arithmetic leaves CR0 alone.
        t.cr.set_field(0, 0b0100);
        t.gpr[3] = 1_u64;
        run_word(dform(8, 4, 3, 2), &mut t, &mut m);
        assert_eq!(t.cr.field(0), 0b0100);
    }

    #[test]
    fn cntlzw_counts_and_sets_cr0() {
        let (mut t, mut m) = setup();
        t.gpr[5] = 0x00F0_0000_u64;
        let w = xform(5, 4, 0, 26, 1);
        assert!(matches!(decode(w).unwrap(), Decoded::Cntlzw { .. }));
        run_word(w, &mut t, &mut m);
        assert_eq!((t.gpr[4] as u32), 8);
        assert_eq!(t.cr.field(0), 0b0100);
        t.gpr[5] = 0_u64;
        run_word(w, &mut t, &mut m);
        assert_eq!((t.gpr[4] as u32), 32);
        assert_eq!(t.cr.field(0), 0b0100);
        t.gpr[5] = 0x8000_0000_u64;
        run_word(w, &mut t, &mut m);
        assert_eq!((t.gpr[4] as u32), 0);
        assert_eq!(t.cr.field(0), 0b0010);
    }

    // --- Traps: never silent ---

    #[test]
    fn tw_to0_and_no_fire_advance() {
        let (mut t, mut m) = setup();
        t.gpr[3] = 1_u64;
        t.gpr[4] = 2_u64;
        run_word(xform(0, 3, 4, 4, 0), &mut t, &mut m);
        assert_eq!(t.pc, 0x1004);
        // EQ-only trap that does not fire also advances.
        run_word(xform(0x04, 3, 4, 4, 0), &mut t, &mut m);
        assert_eq!(t.pc, 0x1008);
    }

    #[test]
    fn tw_eq_fires_unsupported() {
        let (mut t, mut m) = setup();
        t.gpr[3] = 7_u64;
        t.gpr[4] = 7_u64;
        let w = xform(0x04, 3, 4, 4, 0);
        assert!(matches!(decode(w).unwrap(), Decoded::Tw { .. }));
        let msg = expect_unsupported(w, &mut t, &mut m);
        assert!(msg.contains("tw trap fired"));
        assert!(msg.contains("pc="));
    }

    #[test]
    fn tw_signed_unsigned_conditions() {
        let (mut t, mut m) = setup();
        // -1 < 1 signed fires SLT (0x10).
        t.gpr[3] = 0xFFFF_FFFF_u64;
        t.gpr[4] = 1_u64;
        expect_unsupported(xform(0x10, 3, 4, 4, 0), &mut t, &mut m);
        // Same pair fires UGT (0x01) unsigned.
        expect_unsupported(xform(0x01, 3, 4, 4, 0), &mut t, &mut m);
        // But not SGT (0x08): -1 > 1 signed is false.
        run_word(xform(0x08, 3, 4, 4, 0), &mut t, &mut m);
    }

    #[test]
    fn twi_fires_and_passes() {
        let (mut t, mut m) = setup();
        t.gpr[3] = 5_u64;
        let w = dform(3, 0x04, 3, 5);
        assert!(matches!(decode(w).unwrap(), Decoded::Twi { .. }));
        let msg = expect_unsupported(w, &mut t, &mut m);
        assert!(msg.contains("twi trap fired"));
        // Non-equal passes through.
        run_word(dform(3, 0x04, 3, 6), &mut t, &mut m);
        assert_eq!(t.pc, 0x1004);
        // TO=0 never traps.
        run_word(dform(3, 0, 3, 5), &mut t, &mut m);
        assert_eq!(t.pc, 0x1008);
    }

    #[test]
    fn tdi_td_64bit() {
        let (mut t, mut m) = setup();
        // Retail word: tdi 6,r11,0 -> 0x08CB0000 (null-check idiom).
        t.gpr[11] = 5;
        run_word(0x08CB_0000, &mut t, &mut m);
        assert_eq!(t.pc, 0x1004);
        // 64-bit values above u32 range pass (32-bit twi would wrap).
        t.gpr[11] = 0x1_0000_0005;
        run_word(0x08CB_0000, &mut t, &mut m);
        // Null fires loudly, never silently.
        t.gpr[11] = 0;
        let msg = expect_unsupported(0x08CB_0000, &mut t, &mut m);
        assert!(msg.contains("tdi trap fired"));
        // td register form compares full width (TO=0x10 signed lt).
        t.gpr[3] = 0xFFFF_FFFF_FFFF_FFFF;
        t.gpr[4] = 1;
        let msg = expect_unsupported(xform(0x10, 3, 4, 68, 0), &mut t, &mut m);
        assert!(msg.contains("td trap fired"));
        // Equal values pass the same trap.
        t.gpr[4] = 0xFFFF_FFFF_FFFF_FFFF;
        run_word(xform(0x10, 3, 4, 68, 0), &mut t, &mut m);
    }

    // --- Condition register ---

    #[test]
    fn mcrf_copies_field() {
        let (mut t, mut m) = setup();
        t.cr.set_field(2, 0b1010);
        t.cr.set_field(5, 0b0000);
        // crfd=5 (BO=20), crfs=2 (BI=8), XO=0.
        let w = xlform(20, 8, 0, 0);
        assert!(matches!(decode(w).unwrap(), Decoded::Mcrf { .. }));
        run_word(w, &mut t, &mut m);
        assert_eq!(t.cr.field(5), 0b1010);
        assert_eq!(t.cr.field(2), 0b1010);
        assert_eq!(t.cr.field(0), 0);
    }

    #[test]
    fn crand_sets_bit() {
        let (mut t, mut m) = setup();
        // ba=0 -> 1, bb=1 -> 0.
        t.cr.0 = 0x8000_0000;
        run_word(xlform(2, 0, 1, 257), &mut t, &mut m);
        assert_eq!((t.cr.0 >> 29) & 1, 0);
        assert_eq!(t.cr.0 & !0x2000_0000, 0x8000_0000);
    }

    #[test]
    fn cror_sets_bit() {
        let (mut t, mut m) = setup();
        t.cr.0 = 0x8000_0000;
        run_word(xlform(2, 0, 1, 449), &mut t, &mut m);
        assert_eq!((t.cr.0 >> 29) & 1, 1);
    }

    #[test]
    fn crxor_sets_bit() {
        let (mut t, mut m) = setup();
        t.cr.0 = 0x8000_0000;
        run_word(xlform(2, 0, 1, 193), &mut t, &mut m);
        assert_eq!((t.cr.0 >> 29) & 1, 1);
        // Same bits cancel.
        t.cr.0 = 0xC000_0000;
        run_word(xlform(2, 0, 1, 193), &mut t, &mut m);
        assert_eq!((t.cr.0 >> 29) & 1, 0);
    }

    #[test]
    fn crnor_clears_bit() {
        let (mut t, mut m) = setup();
        t.cr.0 = 0x8000_0000;
        run_word(xlform(2, 0, 1, 33), &mut t, &mut m);
        assert_eq!((t.cr.0 >> 29) & 1, 0);
        // Both clear -> NOR sets.
        t.cr.0 = 0;
        run_word(xlform(2, 0, 1, 33), &mut t, &mut m);
        assert_eq!((t.cr.0 >> 29) & 1, 1);
    }

    #[test]
    fn cr_complements_behave() {
        let (mut t, mut m) = setup();
        // ba=1, bb=0: crandc -> 1, crorc -> 1, creqv -> 0, crnand -> 1.
        t.cr.0 = 0x8000_0000;
        run_word(xlform(2, 0, 1, 129), &mut t, &mut m);
        assert_eq!((t.cr.0 >> 29) & 1, 1);
        t.cr.0 = 0x8000_0000;
        run_word(xlform(2, 0, 1, 417), &mut t, &mut m);
        assert_eq!((t.cr.0 >> 29) & 1, 1);
        t.cr.0 = 0x8000_0000;
        run_word(xlform(2, 0, 1, 289), &mut t, &mut m);
        assert_eq!((t.cr.0 >> 29) & 1, 0);
        t.cr.0 = 0x8000_0000;
        run_word(xlform(2, 0, 1, 225), &mut t, &mut m);
        assert_eq!((t.cr.0 >> 29) & 1, 1);
    }

    #[test]
    fn unknown_xo31_stays_unsupported() {
        let (mut t, mut m) = setup();
        let w = xform(0, 0, 0, 100, 0);
        assert!(matches!(decode(w).unwrap(), Decoded::Unsupported { .. }));
        let msg = expect_unsupported(w, &mut t, &mut m);
        assert!(msg.contains("xo31"));
    }
}
