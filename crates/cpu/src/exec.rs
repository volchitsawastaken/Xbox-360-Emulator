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

fn cmp_signed(t: &mut ThreadState, bf: u32, a: i32, b: i32) {
    update_cr_bf(t, bf, a < b, a > b, a == b);
}

fn cmp_unsigned(t: &mut ThreadState, bf: u32, a: u32, b: u32) {
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
            let base = if ra == 0 {
                0
            } else {
                t.gpr[ra as usize] as u32
            };
            t.gpr[rt as usize] = (base.wrapping_add(simm as i32 as u32)) as u64;
            t.pc = next;
            Ok(None)
        }
        Decoded::Addis { rt, ra, simm } => {
            let base = if ra == 0 {
                0
            } else {
                t.gpr[ra as usize] as u32
            };
            t.gpr[rt as usize] = (base.wrapping_add((simm as u32) << 16)) as u64;
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
            let a = (t.gpr[ra as usize] as u32) as i32 as i64;
            let v = a.wrapping_mul(simm as i64) as u32;
            t.gpr[rt as usize] = (v) as u64;
            t.pc = next;
            Ok(None)
        }
        Decoded::Cmpi { bf, l, ra, simm } => {
            if l {
                return Err(EmuError::Unsupported(format!(
                    "cmpi L=1 needs 64-bit regs word={:08x} pc={:08x}",
                    word, t.pc
                )));
            }
            cmp_signed(t, bf, (t.gpr[ra as usize] as u32) as i32, simm as i32);
            t.pc = next;
            Ok(None)
        }
        Decoded::Cmpli { bf, l, ra, uimm } => {
            if l {
                return Err(EmuError::Unsupported(format!(
                    "cmpli L=1 needs 64-bit regs word={:08x} pc={:08x}",
                    word, t.pc
                )));
            }
            cmp_unsigned(t, bf, t.gpr[ra as usize] as u32, uimm as u32);
            t.pc = next;
            Ok(None)
        }
        Decoded::Cmp { bf, l, ra, rb } => {
            if l {
                return Err(EmuError::Unsupported(format!(
                    "cmp L=1 needs 64-bit regs word={:08x} pc={:08x}",
                    word, t.pc
                )));
            }
            cmp_signed(
                t,
                bf,
                (t.gpr[ra as usize] as u32) as i32,
                (t.gpr[rb as usize] as u32) as i32,
            );
            t.pc = next;
            Ok(None)
        }
        Decoded::Cmpl { bf, l, ra, rb } => {
            if l {
                return Err(EmuError::Unsupported(format!(
                    "cmpl L=1 needs 64-bit regs word={:08x} pc={:08x}",
                    word, t.pc
                )));
            }
            cmp_unsigned(t, bf, t.gpr[ra as usize] as u32, t.gpr[rb as usize] as u32);
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
            // RT <- EXTS(SI) - (RA); CA set on NOT-borrow, i.e. the
            // unsigned 32-bit subtrahend covers the minuend. Only CA is
            // affected (no OV/SO/CR0 update for D-form arithmetic).
            let b = simm as i32 as u32;
            let a = t.gpr[ra as usize] as u32;
            let (v, borrow) = b.overflowing_sub(a);
            t.xer.set_ca(!borrow);
            t.gpr[rt as usize] = (v) as u64;
            t.pc = next;
            Ok(None)
        }
        Decoded::Addic { rt, ra, simm } => {
            // RT <- (RA) + EXTS(SI); CA set on carry out of bit 0.
            // Only CA is affected (no CR0 update without `.`).
            let a = t.gpr[ra as usize] as u32;
            let (v, carry) = a.overflowing_add(simm as i32 as u32);
            t.xer.set_ca(carry);
            t.gpr[rt as usize] = (v) as u64;
            t.pc = next;
            Ok(None)
        }
        Decoded::Addic_ { rt, ra, simm } => {
            let a = t.gpr[ra as usize] as u32;
            let (v, carry) = a.overflowing_add(simm as i32 as u32);
            t.xer.set_ca(carry);
            t.gpr[rt as usize] = (v) as u64;
            update_cr0(t, v);
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
            let a = t.gpr[ra as usize] as u32;
            let b = t.gpr[rb as usize] as u32;
            let (v, carry) = a.overflowing_add(b);
            t.xer.set_ca(carry);
            if oe {
                let ov = (a as i32).checked_add(b as i32).is_none();
                t.xer.set_ov_so(ov);
            }
            t.gpr[rt as usize] = (v) as u64;
            if rc {
                update_cr0(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Subf { rt, ra, rb, rc, oe } => {
            let a = t.gpr[ra as usize] as u32;
            let b = t.gpr[rb as usize] as u32;
            let (v, borrow) = b.overflowing_sub(a);
            t.xer.set_ca(!borrow);
            if oe {
                let ov = (b as i32).checked_sub(a as i32).is_none();
                t.xer.set_ov_so(ov);
            }
            t.gpr[rt as usize] = (v) as u64;
            if rc {
                update_cr0(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Neg { rt, ra, rc, oe } => {
            let a = t.gpr[ra as usize] as u32;
            let v = (0u32).wrapping_sub(a);
            if oe {
                t.xer.set_ov_so(a == 0x8000_0000);
            }
            t.gpr[rt as usize] = (v) as u64;
            if rc {
                update_cr0(t, v);
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
        Decoded::Addc { rt, ra, rb, rc, oe } => {
            let a = t.gpr[ra as usize] as u32;
            let b = t.gpr[rb as usize] as u32;
            let total = a as u64 + b as u64;
            let v = total as u32;
            t.xer.set_ca(total > u32::MAX as u64);
            if oe {
                let ov = (a as i32 as i64) + (b as i32 as i64) != v as i32 as i64;
                t.xer.set_ov_so(ov);
            }
            t.gpr[rt as usize] = (v) as u64;
            if rc {
                update_cr0(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Subfc { rt, ra, rb, rc, oe } => {
            let a = t.gpr[ra as usize] as u32;
            let b = t.gpr[rb as usize] as u32;
            let total = b as u64 + (!a) as u64 + 1;
            let v = total as u32;
            t.xer.set_ca(total > u32::MAX as u64);
            if oe {
                let ov = (b as i32 as i64) - (a as i32 as i64) != v as i32 as i64;
                t.xer.set_ov_so(ov);
            }
            t.gpr[rt as usize] = (v) as u64;
            if rc {
                update_cr0(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Adde { rt, ra, rb, rc, oe } => {
            let a = t.gpr[ra as usize] as u32;
            let b = t.gpr[rb as usize] as u32;
            let ca = u64::from(t.xer.ca());
            let total = a as u64 + b as u64 + ca;
            let v = total as u32;
            t.xer.set_ca(total > u32::MAX as u64);
            if oe {
                let ov = (a as i32 as i64) + (b as i32 as i64) + ca as i64 != v as i32 as i64;
                t.xer.set_ov_so(ov);
            }
            t.gpr[rt as usize] = (v) as u64;
            if rc {
                update_cr0(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Subfe { rt, ra, rb, rc, oe } => {
            let a = t.gpr[ra as usize] as u32;
            let b = t.gpr[rb as usize] as u32;
            let ca = u64::from(t.xer.ca());
            let total = b as u64 + (!a) as u64 + ca;
            let v = total as u32;
            t.xer.set_ca(total > u32::MAX as u64);
            if oe {
                let ov = (b as i32 as i64) - (a as i32 as i64) + ca as i64 - 1 != v as i32 as i64;
                t.xer.set_ov_so(ov);
            }
            t.gpr[rt as usize] = (v) as u64;
            if rc {
                update_cr0(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Addme { rt, ra, rc, oe } => {
            let a = t.gpr[ra as usize] as u32;
            let ca = u64::from(t.xer.ca());
            let total = a as u64 + u32::MAX as u64 + ca;
            let v = total as u32;
            t.xer.set_ca(total > u32::MAX as u64);
            if oe {
                let ov = (a as i32 as i64) - 1 + ca as i64 != v as i32 as i64;
                t.xer.set_ov_so(ov);
            }
            t.gpr[rt as usize] = (v) as u64;
            if rc {
                update_cr0(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Subfme { rt, ra, rc, oe } => {
            let a = t.gpr[ra as usize] as u32;
            let ca = u64::from(t.xer.ca());
            let total = u32::MAX as u64 + (!a) as u64 + ca;
            let v = total as u32;
            t.xer.set_ca(total > u32::MAX as u64);
            if oe {
                let ov = -1 + ((!a) as i32 as i64) + ca as i64 != v as i32 as i64;
                t.xer.set_ov_so(ov);
            }
            t.gpr[rt as usize] = (v) as u64;
            if rc {
                update_cr0(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Addze { rt, ra, rc, oe } => {
            let a = t.gpr[ra as usize] as u32;
            let ca = u64::from(t.xer.ca());
            let total = a as u64 + ca;
            let v = total as u32;
            t.xer.set_ca(total > u32::MAX as u64);
            if oe {
                let ov = (a as i32 as i64) + ca as i64 != v as i32 as i64;
                t.xer.set_ov_so(ov);
            }
            t.gpr[rt as usize] = (v) as u64;
            if rc {
                update_cr0(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Subfze { rt, ra, rc, oe } => {
            let a = t.gpr[ra as usize] as u32;
            let ca = u64::from(t.xer.ca());
            let total = (!a) as u64 + ca;
            let v = total as u32;
            t.xer.set_ca(total > u32::MAX as u64);
            if oe {
                let ov = -((a as i32 as i64) + 1) + ca as i64 != v as i32 as i64;
                t.xer.set_ov_so(ov);
            }
            t.gpr[rt as usize] = (v) as u64;
            if rc {
                update_cr0(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::And { rs, ra, rb, rc } => {
            let v = (t.gpr[rs as usize] as u32) & (t.gpr[rb as usize] as u32);
            t.gpr[ra as usize] = (v) as u64;
            if rc {
                update_cr0(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Or { rs, ra, rb, rc } => {
            let v = (t.gpr[rs as usize] as u32) | (t.gpr[rb as usize] as u32);
            t.gpr[ra as usize] = (v) as u64;
            if rc {
                update_cr0(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Xor { rs, ra, rb, rc } => {
            let v = (t.gpr[rs as usize] as u32) ^ (t.gpr[rb as usize] as u32);
            t.gpr[ra as usize] = (v) as u64;
            if rc {
                update_cr0(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Nor { rs, ra, rb, rc } => {
            let v = !((t.gpr[rs as usize] as u32) | (t.gpr[rb as usize] as u32));
            t.gpr[ra as usize] = (v) as u64;
            if rc {
                update_cr0(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Andc { rs, ra, rb, rc } => {
            let v = (t.gpr[rs as usize] as u32) & !(t.gpr[rb as usize] as u32);
            t.gpr[ra as usize] = (v) as u64;
            if rc {
                update_cr0(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Orc { rs, ra, rb, rc } => {
            let v = (t.gpr[rs as usize] as u32) | !(t.gpr[rb as usize] as u32);
            t.gpr[ra as usize] = (v) as u64;
            if rc {
                update_cr0(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Nand { rs, ra, rb, rc } => {
            let v = !((t.gpr[rs as usize] as u32) & (t.gpr[rb as usize] as u32));
            t.gpr[ra as usize] = (v) as u64;
            if rc {
                update_cr0(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Eqv { rs, ra, rb, rc } => {
            let v = !((t.gpr[rs as usize] as u32) ^ (t.gpr[rb as usize] as u32));
            t.gpr[ra as usize] = (v) as u64;
            if rc {
                update_cr0(t, v);
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
            let v = ((t.gpr[rs as usize] as u32) as u16 as i16) as u32;
            t.gpr[ra as usize] = (v) as u64;
            if rc {
                update_cr0(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Extsb { rs, ra, rc } => {
            let v = ((t.gpr[rs as usize] as u32) as u8 as i8) as u32;
            t.gpr[ra as usize] = (v) as u64;
            if rc {
                update_cr0(t, v);
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
        Decoded::Lwzx { rt, ra, rb } => {
            let ea = ea_idx(ra, rb, t);
            t.gpr[rt as usize] = (mem.read_u32(ea)?) as u64;
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
    fn float_load_store_roundtrip() {
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
        // fctiwz + stfiwx pair: 3.75 -> 3 stored as word.
        t.fpr[4] = 3.75;
        let fctiwz = (63u32 << 26) | (5 << 21) | (4 << 11) | (15 << 1);
        run_word(fctiwz, &mut t, &mut m); // fctiwz f5,f4
        t.gpr[8] = 0x3000_u64;
        let stfiwx = (31u32 << 26) | (5 << 21) | (8 << 11) | (659 << 1);
        run_word(stfiwx, &mut t, &mut m); // stfiwx f5,r8,0
        assert_eq!(m.read_u32(0x3000).unwrap(), 3);
        // lfiwax inverts it.
        let lfiwax = (31u32 << 26) | (6 << 21) | (8 << 11) | (769 << 1);
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
        // High bits set by a dword load are cleared by the next word op,
        // matching recompiled-code observable behavior.
        let (mut t, mut m) = setup();
        t.gpr[3] = 0xFFFF_FFFF_0000_0000;
        run_word(0x3863_0001, &mut t, &mut m); // addi r3,r3,1
        assert_eq!(t.gpr[3], 1);
    }

    #[test]
    fn neg_word_retail() {
        let (mut t, mut m) = setup();
        // Retail word: neg r3,r11 -> 0x7C6B00D0.
        t.gpr[11] = 1_u64;
        run_word(0x7C6B_00D0, &mut t, &mut m);
        assert_eq!((t.gpr[3] as u32), 0xFFFF_FFFF);
        assert_eq!(t.gpr[3], 0xFFFF_FFFF);
        // Zero stays zero.
        t.gpr[11] = 0_u64;
        run_word(0x7C6B_00D0, &mut t, &mut m);
        assert_eq!((t.gpr[3] as u32), 0);
        // INT_MIN negates to itself; OE reports overflow.
        t.gpr[11] = 0x8000_0000_u64;
        let nego = 0x7C6B_00D0 | (1 << 10);
        run_word(nego, &mut t, &mut m);
        assert_eq!((t.gpr[3] as u32), 0x8000_0000);
        assert!(t.xer.so());
    }

    #[test]
    fn carry_chain_addc_adde_addze() {
        let (mut t, mut m) = setup();
        // Low word: 0xFFFFFFFF + 1 -> 0 with carry.
        t.gpr[10] = 0xFFFF_FFFF_u64;
        t.gpr[11] = 1_u64;
        let addc = (31u32 << 26) | (12 << 21) | (10 << 16) | (11 << 11) | (10 << 1);
        run_word(addc, &mut t, &mut m);
        assert_eq!((t.gpr[12] as u32), 0);
        assert!(t.xer.ca());
        // High word: 0 + 0 + CA -> 1 (retail addze pattern).
        t.gpr[13] = 0_u64;
        t.gpr[14] = 0_u64;
        let adde = (31u32 << 26) | (15 << 21) | (13 << 16) | (14 << 11) | (138 << 1);
        run_word(adde, &mut t, &mut m);
        assert_eq!((t.gpr[15] as u32), 1);
        // Retail pattern: addze r10,r10 with CA set wraps to 0, CA stays set.
        t.xer.set_ca(true);
        t.gpr[10] = 0xFFFF_FFFF_u64;
        run_word(0x7D4A_0194, &mut t, &mut m); // addze r10,r10 (202<<1=0x194)
        assert_eq!((t.gpr[10] as u32), 0);
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
        // 0xFFFFFFFF + 1 wraps with carry, result zero sets CR0 EQ.
        t.gpr[8] = 0xFFFF_FFFF_u64;
        run_word(0x3508_0001, &mut t, &mut m); // addic. r8,r8,1
        assert_eq!((t.gpr[8] as u32), 0);
        assert!(t.xer.ca());
        assert_eq!(t.cr.field(0) & 0b0010, 0b0010); // EQ
                                                    // No carry, nonzero result: CA clear, CR0 GT.
        t.gpr[8] = 5_u64;
        run_word(0x3508_0000, &mut t, &mut m); // addic. r8,r8,0
        assert_eq!((t.gpr[8] as u32), 5);
        assert!(!t.xer.ca());
        assert_eq!(t.cr.field(0) & 0b0100, 0b0100); // GT
                                                    // Borrow-style: 5 + (-1) wraps upward, CA set, result 4.
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
        t.gpr[3] = 0x7FFF_FFFF_u64;
        t.gpr[4] = 1_u64;
        // add r5,r3,r4 with OE=1, Rc=0: XO=266, OE bit10=1
        let word = (31u32 << 26) | (5 << 21) | (3 << 16) | (4 << 11) | (1 << 10) | (266 << 1);
        let d = decode(word).unwrap();
        execute(d, word, &mut t, &mut m).unwrap();
        assert_eq!((t.gpr[5] as u32), 0x8000_0000);
        assert!(t.xer.so());
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
    fn cmp_l64_is_explicit() {
        let (mut t, mut m) = setup();
        // cmpli with L=1 (bit 21).
        let w = (10u32 << 26) | (1 << 21) | (3 << 16) | 5;
        let d = decode(w).unwrap();
        assert!(execute(d, w, &mut t, &mut m).is_err());
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
        // Negative-immediate regression: -5 - 0xFFFFFFFE borrows (CA=0).
        t.gpr[3] = 0xFFFF_FFFE_u64;
        run_word(dform(8, 4, 3, -5), &mut t, &mut m);
        assert_eq!((t.gpr[4] as u32), 0xFFFF_FFFD);
        assert!(!t.xer.ca());
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
