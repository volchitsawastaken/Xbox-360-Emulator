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
        Decoded::Subfic { rt, ra, simm } => {
            let (v, _) = (simm as i32 as u32).overflowing_sub(t.gpr[ra as usize]);
            // CA = NOT borrow: simm_ext >= ra (unsigned 64-bit compare).
            let a = t.gpr[ra as usize] as u64;
            let b = simm as i32 as i64 as u64;
            t.xer.set_ca(b >= a);
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
        Decoded::Lwzx { rt, ra, rb } => {
            let ea = ea_idx(ra, rb, t);
            t.gpr[rt as usize] = mem.read_u32(ea)?;
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
}
