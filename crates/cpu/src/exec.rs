//! Execute decoded instructions against thread + memory.

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
    let base = if ra == 0 { 0 } else { t.gpr[ra as usize] };
    base.wrapping_add(d as i32 as u32)
}

fn ea_idx(ra: u32, rb: u32, t: &ThreadState) -> u32 {
    let base = if ra == 0 { 0 } else { t.gpr[ra as usize] };
    base.wrapping_add(t.gpr[rb as usize])
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
            let base = if ra == 0 { 0 } else { t.gpr[ra as usize] };
            t.gpr[rt as usize] = base.wrapping_add(simm as i32 as u32);
            t.pc = next;
            Ok(None)
        }
        Decoded::Addis { rt, ra, simm } => {
            let base = if ra == 0 { 0 } else { t.gpr[ra as usize] };
            t.gpr[rt as usize] = base.wrapping_add((simm as u32) << 16);
            t.pc = next;
            Ok(None)
        }
        Decoded::Ori { rt, ra, uimm } => {
            t.gpr[rt as usize] = t.gpr[ra as usize] | uimm as u32;
            t.pc = next;
            Ok(None)
        }
        Decoded::Oris { rt, ra, uimm } => {
            t.gpr[rt as usize] = t.gpr[ra as usize] | ((uimm as u32) << 16);
            t.pc = next;
            Ok(None)
        }
        Decoded::Xoris { rt, ra, uimm } => {
            t.gpr[rt as usize] = t.gpr[ra as usize] ^ ((uimm as u32) << 16);
            t.pc = next;
            Ok(None)
        }
        Decoded::Andi { rt, ra, uimm } => {
            let v = t.gpr[ra as usize] & (uimm as u32);
            t.gpr[rt as usize] = v;
            update_cr0(t, v);
            t.pc = next;
            Ok(None)
        }
        Decoded::Andis { rt, ra, uimm } => {
            let v = t.gpr[ra as usize] & ((uimm as u32) << 16);
            t.gpr[rt as usize] = v;
            update_cr0(t, v);
            t.pc = next;
            Ok(None)
        }
        Decoded::Mulli { rt, ra, simm } => {
            let a = t.gpr[ra as usize] as i32 as i64;
            let v = a.wrapping_mul(simm as i64) as u32;
            t.gpr[rt as usize] = v;
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
            cmp_signed(t, bf, t.gpr[ra as usize] as i32, simm as i32);
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
            cmp_unsigned(t, bf, t.gpr[ra as usize], uimm as u32);
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
            cmp_signed(t, bf, t.gpr[ra as usize] as i32, t.gpr[rb as usize] as i32);
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
            cmp_unsigned(t, bf, t.gpr[ra as usize], t.gpr[rb as usize]);
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
            let r = t.gpr[rs as usize].rotate_left(sh);
            let mask = rlw_mask(mb, me);
            let v = (r & mask) | (t.gpr[ra as usize] & !mask);
            t.gpr[ra as usize] = v;
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
            let r = t.gpr[rs as usize].rotate_left(sh);
            let v = r & rlw_mask(mb, me);
            t.gpr[ra as usize] = v;
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
            let sh = t.gpr[rb as usize] & 0x1F;
            let r = t.gpr[rs as usize].rotate_left(sh);
            let v = r & rlw_mask(mb, me);
            t.gpr[ra as usize] = v;
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
            let a = t.gpr[ra as usize];
            let (v, borrow) = b.overflowing_sub(a);
            t.xer.set_ca(!borrow);
            t.gpr[rt as usize] = v;
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
            t.gpr[rt as usize] = v;
            t.pc = next;
            Ok(None)
        }
        Decoded::Lwzu { rt, ra, d } => {
            if ra == 0 || ra == rt {
                return Err(EmuError::Unsupported("lwzu with ra=0 or ra=rt".into()));
            }
            let ea = ea_imm(ra, t, d);
            let v = mem.read_u32(ea)?;
            t.gpr[rt as usize] = v;
            t.gpr[ra as usize] = ea;
            t.pc = next;
            Ok(None)
        }
        Decoded::Stw { rs, ra, d } => {
            let ea = ea_imm(ra, t, d);
            mem.write_u32(ea, t.gpr[rs as usize])?;
            t.pc = next;
            Ok(None)
        }
        Decoded::Stwu { rs, ra, d } => {
            if ra == 0 {
                return Err(EmuError::Unsupported("stwu with ra=0".into()));
            }
            let ea = ea_imm(ra, t, d);
            mem.write_u32(ea, t.gpr[rs as usize])?;
            t.gpr[ra as usize] = ea;
            t.pc = next;
            Ok(None)
        }
        Decoded::Lbz { rt, ra, d } => {
            let ea = ea_imm(ra, t, d);
            t.gpr[rt as usize] = mem.read_u8(ea)? as u32;
            t.pc = next;
            Ok(None)
        }
        Decoded::Stb { rs, ra, d } => {
            let ea = ea_imm(ra, t, d);
            mem.write_u8(ea, t.gpr[rs as usize] as u8)?;
            t.pc = next;
            Ok(None)
        }
        Decoded::Lhz { rt, ra, d } => {
            let ea = ea_imm(ra, t, d);
            if !ea.is_multiple_of(2) {
                return Err(EmuError::AlignmentFault { addr: ea });
            }
            let b = mem.read_bytes(ea, 2)?;
            t.gpr[rt as usize] = ((b[0] as u32) << 8) | b[1] as u32;
            t.pc = next;
            Ok(None)
        }
        Decoded::Sth { rs, ra, d } => {
            let ea = ea_imm(ra, t, d);
            if !ea.is_multiple_of(2) {
                return Err(EmuError::AlignmentFault { addr: ea });
            }
            let v = t.gpr[rs as usize] as u16;
            mem.write_bytes(ea, &v.to_be_bytes())?;
            t.pc = next;
            Ok(None)
        }
        Decoded::Lmw { rt, ra, d } => {
            let mut ea = ea_imm(ra, t, d);
            for i in rt..32 {
                let v = mem.read_u32(ea)?;
                t.gpr[i as usize] = v;
                ea = ea.wrapping_add(4);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Stmw { rs, ra, d } => {
            let mut ea = ea_imm(ra, t, d);
            for i in rs..32 {
                mem.write_u32(ea, t.gpr[i as usize])?;
                ea = ea.wrapping_add(4);
            }
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
            t.gpr[rt as usize] = v;
            t.gpr[ra as usize] = ea;
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
            t.gpr[rt as usize] = v;
            t.gpr[ra as usize] = ea;
            t.pc = next;
            Ok(None)
        }
        Decoded::Lha { rt, ra, d } => {
            let ea = ea_imm(ra, t, d);
            let v = read_half_be(mem, ea)? as i16 as i32 as u32;
            t.gpr[rt as usize] = v;
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
            t.gpr[rt as usize] = v;
            t.gpr[ra as usize] = ea;
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
            mem.write_u8(ea, t.gpr[rs as usize] as u8)?;
            t.gpr[ra as usize] = ea;
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
            write_half_be(mem, ea, t.gpr[rs as usize] as u16)?;
            t.gpr[ra as usize] = ea;
            t.pc = next;
            Ok(None)
        }
        Decoded::Add { rt, ra, rb, rc, oe } => {
            let a = t.gpr[ra as usize];
            let b = t.gpr[rb as usize];
            let (v, carry) = a.overflowing_add(b);
            t.xer.set_ca(carry);
            if oe {
                let ov = (a as i32).checked_add(b as i32).is_none();
                t.xer.set_ov_so(ov);
            }
            t.gpr[rt as usize] = v;
            if rc {
                update_cr0(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Subf { rt, ra, rb, rc, oe } => {
            let a = t.gpr[ra as usize];
            let b = t.gpr[rb as usize];
            let (v, borrow) = b.overflowing_sub(a);
            t.xer.set_ca(!borrow);
            if oe {
                let ov = (b as i32).checked_sub(a as i32).is_none();
                t.xer.set_ov_so(ov);
            }
            t.gpr[rt as usize] = v;
            if rc {
                update_cr0(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::And { rs, ra, rb, rc } => {
            let v = t.gpr[rs as usize] & t.gpr[rb as usize];
            t.gpr[ra as usize] = v;
            if rc {
                update_cr0(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Or { rs, ra, rb, rc } => {
            let v = t.gpr[rs as usize] | t.gpr[rb as usize];
            t.gpr[ra as usize] = v;
            if rc {
                update_cr0(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Xor { rs, ra, rb, rc } => {
            let v = t.gpr[rs as usize] ^ t.gpr[rb as usize];
            t.gpr[ra as usize] = v;
            if rc {
                update_cr0(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Nor { rs, ra, rb, rc } => {
            let v = !(t.gpr[rs as usize] | t.gpr[rb as usize]);
            t.gpr[ra as usize] = v;
            if rc {
                update_cr0(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Slw { rs, ra, rb, rc } => {
            let sh = t.gpr[rb as usize] & 0x3F;
            let v = if sh >= 32 {
                0
            } else {
                t.gpr[rs as usize] << sh
            };
            t.gpr[ra as usize] = v;
            if rc {
                update_cr0(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Srw { rs, ra, rb, rc } => {
            let sh = t.gpr[rb as usize] & 0x3F;
            let v = if sh >= 32 {
                0
            } else {
                t.gpr[rs as usize] >> sh
            };
            t.gpr[ra as usize] = v;
            if rc {
                update_cr0(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Extsh { rs, ra, rc } => {
            let v = (t.gpr[rs as usize] as u16 as i16) as u32;
            t.gpr[ra as usize] = v;
            if rc {
                update_cr0(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Extsb { rs, ra, rc } => {
            let v = (t.gpr[rs as usize] as u8 as i8) as u32;
            t.gpr[ra as usize] = v;
            if rc {
                update_cr0(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Cntlzw { rs, ra, rc } => {
            let v = t.gpr[rs as usize].leading_zeros();
            t.gpr[ra as usize] = v;
            if rc {
                update_cr0(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Sraw { rs, ra, rb, rc } => {
            // n mirrors the reference clamp in InstrEmit_srawx
            // (reference ppc_emit_alu.cc): low 6 bits, clamped to 31.
            let n = (t.gpr[rb as usize] & 0x3F).min(31);
            let (v, ca) = sraw_core(t.gpr[rs as usize], n);
            t.xer.set_ca(ca);
            t.gpr[ra as usize] = v;
            if rc {
                update_cr0(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Srawi { rs, ra, sh, rc } => {
            let (v, ca) = sraw_core(t.gpr[rs as usize], sh & 0x1F);
            t.xer.set_ca(ca);
            t.gpr[ra as usize] = v;
            if rc {
                update_cr0(t, v);
            }
            t.pc = next;
            Ok(None)
        }
        Decoded::Lwzx { rt, ra, rb } => {
            let ea = ea_idx(ra, rb, t);
            t.gpr[rt as usize] = mem.read_u32(ea)?;
            t.pc = next;
            Ok(None)
        }
        Decoded::Lbzx { rt, ra, rb } => {
            let ea = ea_idx(ra, rb, t);
            t.gpr[rt as usize] = mem.read_u8(ea)? as u32;
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
            t.gpr[rt as usize] = v;
            t.gpr[ra as usize] = ea;
            t.pc = next;
            Ok(None)
        }
        Decoded::Stbx { rs, ra, rb } => {
            let ea = ea_idx(ra, rb, t);
            mem.write_u8(ea, t.gpr[rs as usize] as u8)?;
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
            mem.write_u8(ea, t.gpr[rs as usize] as u8)?;
            t.gpr[ra as usize] = ea;
            t.pc = next;
            Ok(None)
        }
        Decoded::Lhzx { rt, ra, rb } => {
            let ea = ea_idx(ra, rb, t);
            t.gpr[rt as usize] = read_half_be(mem, ea)? as u32;
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
            t.gpr[rt as usize] = v;
            t.gpr[ra as usize] = ea;
            t.pc = next;
            Ok(None)
        }
        Decoded::Lhax { rt, ra, rb } => {
            let ea = ea_idx(ra, rb, t);
            t.gpr[rt as usize] = read_half_be(mem, ea)? as i16 as i32 as u32;
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
            t.gpr[rt as usize] = v;
            t.gpr[ra as usize] = ea;
            t.pc = next;
            Ok(None)
        }
        Decoded::Sthx { rs, ra, rb } => {
            let ea = ea_idx(ra, rb, t);
            write_half_be(mem, ea, t.gpr[rs as usize] as u16)?;
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
            write_half_be(mem, ea, t.gpr[rs as usize] as u16)?;
            t.gpr[ra as usize] = ea;
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
            mem.write_u32(ea, t.gpr[rs as usize])?;
            t.gpr[ra as usize] = ea;
            t.pc = next;
            Ok(None)
        }
        Decoded::Stwx { rs, ra, rb } => {
            let ea = ea_idx(ra, rb, t);
            mem.write_u32(ea, t.gpr[rs as usize])?;
            t.pc = next;
            Ok(None)
        }
        Decoded::Lwarx { rt, ra, rb } => {
            let ea = ea_idx(ra, rb, t);
            t.gpr[rt as usize] = mem.read_u32(ea)?;
            t.reserved = true;
            t.reserved_addr = ea;
            t.pc = next;
            Ok(None)
        }
        Decoded::Stwcx { rs, ra, rb } => {
            let ea = ea_idx(ra, rb, t);
            if t.reserved && t.reserved_addr == ea {
                mem.write_u32(ea, t.gpr[rs as usize])?;
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
            t.gpr[rt as usize] = t.cr.0;
            t.pc = next;
            Ok(None)
        }
        Decoded::Mtcrf { rs, fxm } => {
            let v = t.gpr[rs as usize];
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
            t.gpr[rt as usize] = v;
            t.pc = next;
            Ok(None)
        }
        Decoded::Mtspr { rs, spr } => {
            let v = t.gpr[rs as usize];
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
            let a = t.gpr[ra as usize];
            let b = t.gpr[rb as usize];
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
            let a = t.gpr[ra as usize];
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
        assert_eq!(t.gpr[3], 16);
        run_word(0x6063_00FF, &mut t, &mut m); // ori r3,r3,0xFF
        assert_eq!(t.gpr[3], 0xFF);
    }

    #[test]
    fn stw_lwz_roundtrip() {
        let (mut t, mut m) = setup();
        t.gpr[3] = 0x2000;
        t.gpr[4] = 0xAABB_CCDD;
        run_word(0x9083_0000, &mut t, &mut m); // stw r4,0(r3)
        t.gpr[4] = 0;
        run_word(0x8083_0000, &mut t, &mut m); // lwz r4,0(r3)
        assert_eq!(t.gpr[4], 0xAABB_CCDD);
    }

    #[test]
    fn lwarx_stwcx_success_sets_cr_eq() {
        let (mut t, mut m) = setup();
        m.write_u32(0x3000, 7).unwrap();
        t.gpr[3] = 0x3000;
        // lwarx r4,0,r3 ; need encoding: XO=20. Build via fields.
        // opcode31 | rt=4<<21 | rb=3<<11 | XO20<<1 (ra=0 omitted)
        let lwarx = (31u32 << 26) | (4 << 21) | (3 << 11) | (20 << 1);
        let stwcx = (31u32 << 26) | (5 << 21) | (3 << 11) | (150 << 1) | 1;
        t.gpr[5] = 42;
        let d = decode(lwarx).unwrap();
        execute(d, lwarx, &mut t, &mut m).unwrap();
        assert_eq!(t.gpr[4], 7);
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
        t.gpr[3] = 0x7FFF_FFFF;
        t.gpr[4] = 1;
        // add r5,r3,r4 with OE=1, Rc=0: XO=266, OE bit10=1
        let word = (31u32 << 26) | (5 << 21) | (3 << 16) | (4 << 11) | (1 << 10) | (266 << 1);
        let d = decode(word).unwrap();
        execute(d, word, &mut t, &mut m).unwrap();
        assert_eq!(t.gpr[5], 0x8000_0000);
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
        t.gpr[3] = 0xDEAD_BEEF;
        run_word(mform(21, 3, 5, 0, 24, 31, 0), &mut t, &mut m);
        assert_eq!(t.gpr[5], 0xEF);
    }

    #[test]
    fn rlwinm_rotate_and_wrap_mask() {
        // rlwinm r5,r3,4,0,27 — rotate 4, keep top 28 bits.
        let (mut t, mut m) = setup();
        t.gpr[3] = 0x1234_5678;
        run_word(mform(21, 3, 5, 4, 0, 27, 0), &mut t, &mut m);
        assert_eq!(t.gpr[5], t.gpr[3].rotate_left(4) & 0xFFFF_FFF0);
    }

    #[test]
    fn rlwimi_inserts() {
        // rlwimi r5,r3,16,0,15 — insert low half of r3 into top of r5.
        let (mut t, mut m) = setup();
        t.gpr[3] = 0x0000_ABCD;
        t.gpr[5] = 0x1234_5678;
        run_word(mform(20, 3, 5, 16, 0, 15, 0), &mut t, &mut m);
        assert_eq!(t.gpr[5], 0xABCD_5678);
    }

    #[test]
    fn rlwnm_uses_rb_shift() {
        // rlwnm r5,r3,r4,0,31 (full mask) with r4=8.
        let (mut t, mut m) = setup();
        t.gpr[3] = 0x0000_0001;
        t.gpr[4] = 8;
        run_word(mform(23, 3, 5, 4, 0, 31, 0), &mut t, &mut m);
        assert_eq!(t.gpr[5], 0x100);
    }

    #[test]
    fn rlwinm_rc_sets_cr0() {
        let (mut t, mut m) = setup();
        t.gpr[3] = 0;
        run_word(mform(21, 3, 5, 0, 0, 31, 1), &mut t, &mut m);
        assert_eq!(t.cr.field(0) & 0b0010, 0b0010); // EQ
    }

    #[test]
    fn cmpli_conditions() {
        let (mut t, mut m) = setup();
        // cmpli cr1,r0,5 ; r3=5 -> EQ in cr1
        t.gpr[3] = 5;
        let w = (10u32 << 26) | (1 << 23) | (3 << 16) | 5;
        run_word(w, &mut t, &mut m);
        assert_eq!(t.cr.field(1), 0b0010);
        // cmpli cr1,r0,6 ; 5<6 -> LT
        let w = (10u32 << 26) | (1 << 23) | (3 << 16) | 6;
        run_word(w, &mut t, &mut m);
        assert_eq!(t.cr.field(1) >> 3 & 1, 1);
        // unsigned: 0xFFFFFFFF > 6 -> GT
        t.gpr[3] = 0xFFFF_FFFF;
        run_word(w, &mut t, &mut m);
        assert_eq!(t.cr.field(1) >> 2 & 1, 1);
    }

    #[test]
    fn cmpi_signed() {
        let (mut t, mut m) = setup();
        // cmpi cr0,r3,-1 ; r3=-5 < -1 -> LT
        t.gpr[3] = (-5i32) as u32;
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
        t.gpr[9] = 10;
        t.gpr[11] = 20;
        let w = (31u32 << 26) | (24 << 21) | (9 << 16) | (11 << 11) | (32 << 1);
        assert!(matches!(decode(w).unwrap(), Decoded::Cmpl { .. }));
        run_word(w, &mut t, &mut m);
        assert_eq!(t.cr.field(6), 0b1000); // LT
                                           // cmpw cr6,r9,r11 with equal values -> EQ.
        t.gpr[11] = 10;
        let w = (31u32 << 26) | (24 << 21) | (9 << 16) | (11 << 11);
        assert!(matches!(decode(w).unwrap(), Decoded::Cmp { .. }));
        run_word(w, &mut t, &mut m);
        assert_eq!(t.cr.field(6), 0b0010); // EQ
    }

    // --- Update-form stores ---

    #[test]
    fn stwux_store_updates_ra() {
        let (mut t, mut m) = setup();
        t.gpr[3] = 0x2000;
        t.gpr[4] = 4;
        t.gpr[5] = 0xDEAD_BEEF;
        let w = xform(5, 3, 4, 183, 0);
        assert!(matches!(decode(w).unwrap(), Decoded::Stwux { .. }));
        run_word(w, &mut t, &mut m);
        assert_eq!(m.read_u32(0x2004).unwrap(), 0xDEAD_BEEF);
        assert_eq!(t.gpr[3], 0x2004);
    }

    #[test]
    fn stwux_ra0_rejected() {
        let (mut t, mut m) = setup();
        t.gpr[4] = 4;
        t.gpr[5] = 1;
        let msg = expect_unsupported(xform(5, 0, 4, 183, 0), &mut t, &mut m);
        assert!(msg.contains("stwux"));
    }

    #[test]
    fn stbu_store_updates_ra() {
        let (mut t, mut m) = setup();
        t.gpr[3] = 0x2000;
        t.gpr[5] = 0xAB;
        run_word(dform(39, 5, 3, 1), &mut t, &mut m);
        assert_eq!(m.read_u8(0x2001).unwrap(), 0xAB);
        assert_eq!(t.gpr[3], 0x2001);
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
        t.gpr[3] = 0x2000;
        t.gpr[5] = 0x1234;
        run_word(dform(45, 5, 3, 2), &mut t, &mut m);
        assert_eq!(m.read_bytes(0x2002, 2).unwrap(), &[0x12, 0x34]);
        assert_eq!(t.gpr[3], 0x2002);
    }

    #[test]
    fn sthu_misaligned_faults() {
        let (mut t, mut m) = setup();
        t.gpr[3] = 0x2001;
        t.gpr[5] = 0x1234;
        assert_eq!(expect_align(dform(45, 5, 3, 0), &mut t, &mut m), 0x2001);
    }

    // --- Update-form loads ---

    #[test]
    fn lbzu_basic() {
        let (mut t, mut m) = setup();
        m.write_u8(0x2002, 0x7F).unwrap();
        t.gpr[3] = 0x2000;
        let w = dform(35, 4, 3, 2);
        assert!(matches!(decode(w).unwrap(), Decoded::Lbzu { .. }));
        run_word(w, &mut t, &mut m);
        assert_eq!(t.gpr[4], 0x7F);
        assert_eq!(t.gpr[3], 0x2002);
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
        t.gpr[3] = 0x2000;
        let w = dform(43, 4, 3, 0);
        assert!(matches!(decode(w).unwrap(), Decoded::Lhau { .. }));
        run_word(w, &mut t, &mut m);
        assert_eq!(t.gpr[4], 0xFFFF_8001);
        assert_eq!(t.gpr[3], 0x2000);
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
        t.gpr[3] = 0x2000;
        run_word(dform(41, 4, 3, 4), &mut t, &mut m);
        assert_eq!(t.gpr[4], 0x80FF);
        assert_eq!(t.gpr[3], 0x2004);
    }

    #[test]
    fn lha_ra0_sign_extends() {
        let (mut t, mut m) = setup();
        m.write_bytes(0x2000, &0xFF00u16.to_be_bytes()).unwrap();
        let w = dform(42, 4, 0, 0x2000);
        assert!(matches!(decode(w).unwrap(), Decoded::Lha { .. }));
        run_word(w, &mut t, &mut m);
        assert_eq!(t.gpr[4], 0xFFFF_FF00);
    }

    // --- Indexed byte/halfword ---

    #[test]
    fn lbzx_ra0_indexed() {
        let (mut t, mut m) = setup();
        m.write_u8(0x2005, 0x42).unwrap();
        t.gpr[4] = 0x2005;
        let w = xform(5, 0, 4, 87, 0);
        assert!(matches!(decode(w).unwrap(), Decoded::Lbzx { .. }));
        run_word(w, &mut t, &mut m);
        assert_eq!(t.gpr[5], 0x42);
    }

    #[test]
    fn lbzux_basic() {
        let (mut t, mut m) = setup();
        m.write_u8(0x2004, 0x11).unwrap();
        t.gpr[3] = 0x2000;
        t.gpr[4] = 4;
        run_word(xform(5, 3, 4, 119, 0), &mut t, &mut m);
        assert_eq!(t.gpr[5], 0x11);
        assert_eq!(t.gpr[3], 0x2004);
    }

    #[test]
    fn stbx_basic() {
        let (mut t, mut m) = setup();
        t.gpr[3] = 0x2000;
        t.gpr[4] = 8;
        t.gpr[5] = 0x99;
        run_word(xform(5, 3, 4, 215, 0), &mut t, &mut m);
        assert_eq!(m.read_u8(0x2008).unwrap(), 0x99);
        // Non-update form leaves RA alone.
        assert_eq!(t.gpr[3], 0x2000);
    }

    #[test]
    fn stbux_basic_and_ra0_rejected() {
        let (mut t, mut m) = setup();
        t.gpr[3] = 0x2000;
        t.gpr[4] = 2;
        t.gpr[5] = 0x5A;
        run_word(xform(5, 3, 4, 247, 0), &mut t, &mut m);
        assert_eq!(m.read_u8(0x2002).unwrap(), 0x5A);
        assert_eq!(t.gpr[3], 0x2002);
        expect_unsupported(xform(5, 0, 4, 247, 0), &mut t, &mut m);
    }

    #[test]
    fn lhzx_basic() {
        let (mut t, mut m) = setup();
        m.write_bytes(0x2010, &0xABCDu16.to_be_bytes()).unwrap();
        t.gpr[3] = 0x2000;
        t.gpr[4] = 0x10;
        let w = xform(5, 3, 4, 279, 0);
        assert!(matches!(decode(w).unwrap(), Decoded::Lhzx { .. }));
        run_word(w, &mut t, &mut m);
        assert_eq!(t.gpr[5], 0xABCD);
    }

    #[test]
    fn lhzx_misaligned_faults() {
        let (mut t, mut m) = setup();
        t.gpr[3] = 0x2000;
        t.gpr[4] = 1;
        assert_eq!(expect_align(xform(5, 3, 4, 279, 0), &mut t, &mut m), 0x2001);
    }

    #[test]
    fn lhzux_basic() {
        let (mut t, mut m) = setup();
        m.write_bytes(0x2004, &0x00EEu16.to_be_bytes()).unwrap();
        t.gpr[3] = 0x2000;
        t.gpr[4] = 4;
        run_word(xform(5, 3, 4, 311, 0), &mut t, &mut m);
        assert_eq!(t.gpr[5], 0x00EE);
        assert_eq!(t.gpr[3], 0x2004);
    }

    #[test]
    fn lhax_sign_extends_indexed() {
        let (mut t, mut m) = setup();
        m.write_bytes(0x2006, &0x8002u16.to_be_bytes()).unwrap();
        t.gpr[3] = 0x2000;
        t.gpr[4] = 6;
        run_word(xform(5, 3, 4, 343, 0), &mut t, &mut m);
        assert_eq!(t.gpr[5], 0xFFFF_8002);
    }

    #[test]
    fn lhaux_basic_and_invalid_rejected() {
        let (mut t, mut m) = setup();
        m.write_bytes(0x2008, &0x0001u16.to_be_bytes()).unwrap();
        t.gpr[3] = 0x2000;
        t.gpr[4] = 8;
        run_word(xform(5, 3, 4, 375, 0), &mut t, &mut m);
        assert_eq!(t.gpr[5], 1);
        assert_eq!(t.gpr[3], 0x2008);
        expect_unsupported(xform(5, 0, 4, 375, 0), &mut t, &mut m);
        expect_unsupported(xform(3, 3, 4, 375, 0), &mut t, &mut m);
    }

    #[test]
    fn sthx_basic() {
        let (mut t, mut m) = setup();
        t.gpr[3] = 0x2000;
        t.gpr[4] = 6;
        t.gpr[5] = 0xBEEF;
        let w = xform(5, 3, 4, 407, 0);
        assert!(matches!(decode(w).unwrap(), Decoded::Sthx { .. }));
        run_word(w, &mut t, &mut m);
        assert_eq!(m.read_bytes(0x2006, 2).unwrap(), &[0xBE, 0xEF]);
        assert_eq!(t.gpr[3], 0x2000);
    }

    #[test]
    fn sthx_misaligned_faults() {
        let (mut t, mut m) = setup();
        t.gpr[3] = 0x2000;
        t.gpr[4] = 3;
        t.gpr[5] = 1;
        assert_eq!(expect_align(xform(5, 3, 4, 407, 0), &mut t, &mut m), 0x2003);
    }

    #[test]
    fn sthux_basic() {
        let (mut t, mut m) = setup();
        t.gpr[3] = 0x2000;
        t.gpr[4] = 4;
        t.gpr[5] = 0xCAFE;
        run_word(xform(5, 3, 4, 439, 0), &mut t, &mut m);
        assert_eq!(m.read_bytes(0x2004, 2).unwrap(), &[0xCA, 0xFE]);
        assert_eq!(t.gpr[3], 0x2004);
    }

    // --- Shifts ---

    #[test]
    fn sraw_shifts_and_clears_ca() {
        let (mut t, mut m) = setup();
        // Positive value: exact shift, CA stays clear.
        t.gpr[5] = 0x4000_0000;
        t.gpr[6] = 2;
        let w = xform(5, 4, 6, 792, 0);
        assert!(matches!(decode(w).unwrap(), Decoded::Sraw { .. }));
        run_word(w, &mut t, &mut m);
        assert_eq!(t.gpr[4], 0x1000_0000);
        assert!(!t.xer.ca());
        // Positive value with bits shifted out: CA still clear.
        t.gpr[5] = 0x0000_0003;
        t.gpr[6] = 1;
        run_word(w, &mut t, &mut m);
        assert_eq!(t.gpr[4], 1);
        assert!(!t.xer.ca());
        // Zero shift clears a sticky CA.
        t.xer.set_ca(true);
        t.gpr[6] = 0;
        run_word(w, &mut t, &mut m);
        assert_eq!(t.gpr[4], 0x0000_0003);
        assert!(!t.xer.ca());
    }

    #[test]
    fn sraw_negative_sets_ca_and_cr0() {
        let (mut t, mut m) = setup();
        t.gpr[5] = 0x8000_0001;
        t.gpr[6] = 1;
        run_word(xform(5, 4, 6, 792, 1), &mut t, &mut m);
        assert_eq!(t.gpr[4], 0xC000_0000);
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
        t.gpr[5] = 0xFFFF_FF00;
        run_word(w, &mut t, &mut m);
        assert_eq!(t.gpr[4], 0xFFFF_FFF0);
        assert!(!t.xer.ca());
        // Shifted-out 1-bit on a negative value sets CA.
        t.gpr[5] = 0xFFFF_FF01;
        run_word(w, &mut t, &mut m);
        assert_eq!(t.gpr[4], 0xFFFF_FFF0);
        assert!(t.xer.ca());
    }

    #[test]
    fn srawi_zero_sets_cr0_eq() {
        let (mut t, mut m) = setup();
        t.gpr[5] = 0;
        run_word(xform(5, 4, 5, 824, 1), &mut t, &mut m);
        assert_eq!(t.gpr[4], 0);
        assert!(!t.xer.ca());
        assert_eq!(t.cr.field(0), 0b0010);
    }

    // --- subfic / cntlzw verification ---

    #[test]
    fn subfic_ca_semantics() {
        let (mut t, mut m) = setup();
        // 10 - 3 = 7, no borrow: CA set.
        t.gpr[3] = 3;
        run_word(dform(8, 4, 3, 10), &mut t, &mut m);
        assert_eq!(t.gpr[4], 7);
        assert!(t.xer.ca());
        // 3 - 10 borrows: CA clear.
        t.gpr[3] = 10;
        run_word(dform(8, 4, 3, 3), &mut t, &mut m);
        assert_eq!(t.gpr[4], 0xFFFF_FFF9);
        assert!(!t.xer.ca());
        // Negative-immediate regression: -5 - 0xFFFFFFFE borrows (CA=0).
        t.gpr[3] = 0xFFFF_FFFE;
        run_word(dform(8, 4, 3, -5), &mut t, &mut m);
        assert_eq!(t.gpr[4], 0xFFFF_FFFD);
        assert!(!t.xer.ca());
        // D-form arithmetic leaves CR0 alone.
        t.cr.set_field(0, 0b0100);
        t.gpr[3] = 1;
        run_word(dform(8, 4, 3, 2), &mut t, &mut m);
        assert_eq!(t.cr.field(0), 0b0100);
    }

    #[test]
    fn cntlzw_counts_and_sets_cr0() {
        let (mut t, mut m) = setup();
        t.gpr[5] = 0x00F0_0000;
        let w = xform(5, 4, 0, 26, 1);
        assert!(matches!(decode(w).unwrap(), Decoded::Cntlzw { .. }));
        run_word(w, &mut t, &mut m);
        assert_eq!(t.gpr[4], 8);
        assert_eq!(t.cr.field(0), 0b0100);
        t.gpr[5] = 0;
        run_word(w, &mut t, &mut m);
        assert_eq!(t.gpr[4], 32);
        assert_eq!(t.cr.field(0), 0b0100);
        t.gpr[5] = 0x8000_0000;
        run_word(w, &mut t, &mut m);
        assert_eq!(t.gpr[4], 0);
        assert_eq!(t.cr.field(0), 0b0010);
    }

    // --- Traps: never silent ---

    #[test]
    fn tw_to0_and_no_fire_advance() {
        let (mut t, mut m) = setup();
        t.gpr[3] = 1;
        t.gpr[4] = 2;
        run_word(xform(0, 3, 4, 4, 0), &mut t, &mut m);
        assert_eq!(t.pc, 0x1004);
        // EQ-only trap that does not fire also advances.
        run_word(xform(0x04, 3, 4, 4, 0), &mut t, &mut m);
        assert_eq!(t.pc, 0x1008);
    }

    #[test]
    fn tw_eq_fires_unsupported() {
        let (mut t, mut m) = setup();
        t.gpr[3] = 7;
        t.gpr[4] = 7;
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
        t.gpr[3] = 0xFFFF_FFFF;
        t.gpr[4] = 1;
        expect_unsupported(xform(0x10, 3, 4, 4, 0), &mut t, &mut m);
        // Same pair fires UGT (0x01) unsigned.
        expect_unsupported(xform(0x01, 3, 4, 4, 0), &mut t, &mut m);
        // But not SGT (0x08): -1 > 1 signed is false.
        run_word(xform(0x08, 3, 4, 4, 0), &mut t, &mut m);
    }

    #[test]
    fn twi_fires_and_passes() {
        let (mut t, mut m) = setup();
        t.gpr[3] = 5;
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
