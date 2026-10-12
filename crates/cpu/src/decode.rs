//! PowerPC decode. Unknown encodings are explicit Unsupported.

use x360_common::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decoded {
    // D-form immediate arithmetic/logical
    Addi {
        rt: u32,
        ra: u32,
        simm: i16,
    },
    Addis {
        rt: u32,
        ra: u32,
        simm: i16,
    },
    Ori {
        rt: u32,
        ra: u32,
        uimm: u16,
    },
    Oris {
        rt: u32,
        ra: u32,
        uimm: u16,
    },
    Xoris {
        rt: u32,
        ra: u32,
        uimm: u16,
    },
    Andi {
        rt: u32,
        ra: u32,
        uimm: u16,
    },
    Andis {
        rt: u32,
        ra: u32,
        uimm: u16,
    },
    Mulli {
        rt: u32,
        ra: u32,
        simm: i16,
    },
    Subfic {
        rt: u32,
        ra: u32,
        simm: i16,
    },
    // Branches
    B {
        li: i32,
        aa: bool,
        lk: bool,
    },
    Bc {
        bo: u32,
        bi: u32,
        bd: i16,
        aa: bool,
        lk: bool,
    },
    Bclr {
        bo: u32,
        bi: u32,
        lk: bool,
    },
    Bcctr {
        bo: u32,
        bi: u32,
        lk: bool,
    },
    // Loads/stores D-form
    Lwz {
        rt: u32,
        ra: u32,
        d: i16,
    },
    Lwzu {
        rt: u32,
        ra: u32,
        d: i16,
    },
    Stw {
        rs: u32,
        ra: u32,
        d: i16,
    },
    Stwu {
        rs: u32,
        ra: u32,
        d: i16,
    },
    Lbz {
        rt: u32,
        ra: u32,
        d: i16,
    },
    Stb {
        rs: u32,
        ra: u32,
        d: i16,
    },
    Lhz {
        rt: u32,
        ra: u32,
        d: i16,
    },
    Sth {
        rs: u32,
        ra: u32,
        d: i16,
    },
    Lmw {
        rt: u32,
        ra: u32,
        d: i16,
    },
    Stmw {
        rs: u32,
        ra: u32,
        d: i16,
    },
    // D-form update / algebraic-halfword loads and byte/half stores.
    // Primary opcodes per reference ppc_opcode_disasm_gen.cc
    // (lbzu=0x8c, stbu=0x9c, lhzu=0xa4, lha=0xa8, lhau=0xac, sthu=0xb4).
    Lbzu {
        rt: u32,
        ra: u32,
        d: i16,
    },
    Lhzu {
        rt: u32,
        ra: u32,
        d: i16,
    },
    Lha {
        rt: u32,
        ra: u32,
        d: i16,
    },
    Lhau {
        rt: u32,
        ra: u32,
        d: i16,
    },
    Stbu {
        rs: u32,
        ra: u32,
        d: i16,
    },
    Sthu {
        rs: u32,
        ra: u32,
        d: i16,
    },
    // X-form ALU
    Add {
        rt: u32,
        ra: u32,
        rb: u32,
        rc: bool,
        oe: bool,
    },
    Subf {
        rt: u32,
        ra: u32,
        rb: u32,
        rc: bool,
        oe: bool,
    },
    And {
        rs: u32,
        ra: u32,
        rb: u32,
        rc: bool,
    },
    Or {
        rs: u32,
        ra: u32,
        rb: u32,
        rc: bool,
    },
    Xor {
        rs: u32,
        ra: u32,
        rb: u32,
        rc: bool,
    },
    Nor {
        rs: u32,
        ra: u32,
        rb: u32,
        rc: bool,
    },
    Slw {
        rs: u32,
        ra: u32,
        rb: u32,
        rc: bool,
    },
    Srw {
        rs: u32,
        ra: u32,
        rb: u32,
        rc: bool,
    },
    Extsh {
        rs: u32,
        ra: u32,
        rc: bool,
    },
    Extsb {
        rs: u32,
        ra: u32,
        rc: bool,
    },
    Cntlzw {
        rs: u32,
        ra: u32,
        rc: bool,
    },
    // X-form memory indexed
    Lwzx {
        rt: u32,
        ra: u32,
        rb: u32,
    },
    Stwx {
        rs: u32,
        ra: u32,
        rb: u32,
    },
    Lwarx {
        rt: u32,
        ra: u32,
        rb: u32,
    },
    Stwcx {
        rs: u32,
        ra: u32,
        rb: u32,
    },
    // X-form indexed byte/half loads/stores and word-update store.
    // XO values per reference ppc_opcode_disasm_gen.cc base encodings
    // (lbzx=87, lbzux=119, stwux=183, stbx=215, stbux=247, lhzx=279,
    // lhzux=311, lhax=343, lhaux=375, sthx=407, sthux=439).
    Lbzx {
        rt: u32,
        ra: u32,
        rb: u32,
    },
    Lbzux {
        rt: u32,
        ra: u32,
        rb: u32,
    },
    Stbx {
        rs: u32,
        ra: u32,
        rb: u32,
    },
    Stbux {
        rs: u32,
        ra: u32,
        rb: u32,
    },
    Lhzx {
        rt: u32,
        ra: u32,
        rb: u32,
    },
    Lhzux {
        rt: u32,
        ra: u32,
        rb: u32,
    },
    Lhax {
        rt: u32,
        ra: u32,
        rb: u32,
    },
    Lhaux {
        rt: u32,
        ra: u32,
        rb: u32,
    },
    Sthx {
        rs: u32,
        ra: u32,
        rb: u32,
    },
    Sthux {
        rs: u32,
        ra: u32,
        rb: u32,
    },
    Stwux {
        rs: u32,
        ra: u32,
        rb: u32,
    },
    // X-form algebraic shifts. sraw XO=792, srawi XO=824; srawi shift
    // amount rides in the RB field (see reference ppc_emit_alu.cc
    // InstrEmit_srawix, which reads i.X.RB as the count).
    Sraw {
        rs: u32,
        ra: u32,
        rb: u32,
        rc: bool,
    },
    Srawi {
        rs: u32,
        ra: u32,
        sh: u32,
        rc: bool,
    },
    // SPR moves
    Mfcr {
        rt: u32,
    },
    Mtcrf {
        rs: u32,
        fxm: u8,
    },
    Mfspr {
        rt: u32,
        spr: u32,
    },
    Mtspr {
        rs: u32,
        spr: u32,
    },
    // Barriers / traps
    Sync {
        l: u32,
    },
    Isync,
    Eieio,
    Sc,
    Trap,
    // Trap-word instructions. tw XO=4 (opcode 31), twi primary opcode 3;
    // TO in the RT field, per reference ppc_opcode_disasm_gen.cc
    // (0x7c000008 "tw", 0x0c000000 "twi").
    Tw {
        to: u32,
        ra: u32,
        rb: u32,
    },
    Twi {
        to: u32,
        ra: u32,
        simm: i16,
    },
    // Condition-register moves and logical ops (opcode 19 XL form).
    // mcrf XO=0 (0x4c000000); CR logical XOs per reference base
    // encodings: crnor=33, crandc=129, crxor=193, crnand=225,
    // crand=257, creqv=289, crorc=417, cror=449.
    Mcrf {
        crfd: u32,
        crfs: u32,
    },
    Crand {
        bt: u32,
        ba: u32,
        bb: u32,
    },
    Crandc {
        bt: u32,
        ba: u32,
        bb: u32,
    },
    Cror {
        bt: u32,
        ba: u32,
        bb: u32,
    },
    Crorc {
        bt: u32,
        ba: u32,
        bb: u32,
    },
    Crxor {
        bt: u32,
        ba: u32,
        bb: u32,
    },
    Crnor {
        bt: u32,
        ba: u32,
        bb: u32,
    },
    Crnand {
        bt: u32,
        ba: u32,
        bb: u32,
    },
    Creqv {
        bt: u32,
        ba: u32,
        bb: u32,
    },
    Nop,
    // VMX128 (tracked, not executed yet)
    Vmx {
        word: u32,
    },
    Unsupported {
        opc: u32,
        word: u32,
        reason: &'static str,
    },
}

fn sx16(v: u16) -> i32 {
    (v as i16) as i32
}

fn ex_li(word: u32) -> i32 {
    // LI: bits 6..29 shifted <<2, sign-extended 26-bit.
    let li = (word & 0x03FF_FFFC) as i32;
    (li << 6) >> 6
}

fn ex_bd(word: u32) -> i16 {
    (word & 0x0000_FFFC) as i16
}

pub fn decode(word: u32) -> Result<Decoded> {
    if word == 0x6000_0000 {
        return Ok(Decoded::Nop);
    }
    let opc = word >> 26;
    let rt = (word >> 21) & 0x1F;
    let ra = (word >> 16) & 0x1F;
    let rb = (word >> 11) & 0x1F;
    let d = (word & 0xFFFF) as u16;
    match opc {
        3 => Ok(Decoded::Twi {
            to: rt,
            ra,
            simm: d as i16,
        }),
        4 => Ok(Decoded::Vmx { word }),
        7 => Ok(Decoded::Mulli {
            rt,
            ra,
            simm: d as i16,
        }),
        8 => Ok(Decoded::Subfic {
            rt,
            ra,
            simm: d as i16,
        }),
        14 => Ok(Decoded::Addi {
            rt,
            ra,
            simm: d as i16,
        }),
        15 => Ok(Decoded::Addis {
            rt,
            ra,
            simm: d as i16,
        }),
        16 => Ok(Decoded::Bc {
            bo: (word >> 21) & 0x1F,
            bi: (word >> 16) & 0x1F,
            bd: ex_bd(word),
            aa: word & 2 != 0,
            lk: word & 1 != 0,
        }),
        18 => Ok(Decoded::B {
            li: ex_li(word),
            aa: word & 2 != 0,
            lk: word & 1 != 0,
        }),
        19 => {
            let xo = (word >> 1) & 0x3FF;
            let bo = (word >> 21) & 0x1F;
            let bi = (word >> 16) & 0x1F;
            let bb = (word >> 11) & 0x1F;
            let lk = word & 1 != 0;
            match xo {
                0 => Ok(Decoded::Mcrf {
                    crfd: bo >> 2,
                    crfs: bi >> 2,
                }),
                16 => Ok(Decoded::Bclr { bo, bi, lk }),
                33 => Ok(Decoded::Crnor { bt: bo, ba: bi, bb }),
                129 => Ok(Decoded::Crandc { bt: bo, ba: bi, bb }),
                193 => Ok(Decoded::Crxor { bt: bo, ba: bi, bb }),
                225 => Ok(Decoded::Crnand { bt: bo, ba: bi, bb }),
                257 => Ok(Decoded::Crand { bt: bo, ba: bi, bb }),
                289 => Ok(Decoded::Creqv { bt: bo, ba: bi, bb }),
                417 => Ok(Decoded::Crorc { bt: bo, ba: bi, bb }),
                449 => Ok(Decoded::Cror { bt: bo, ba: bi, bb }),
                528 => Ok(Decoded::Bcctr { bo, bi, lk }),
                150 => Ok(Decoded::Isync),
                _ => Ok(Decoded::Unsupported {
                    opc,
                    word,
                    reason: "opcode19-xo",
                }),
            }
        }
        24 => Ok(Decoded::Ori { rt, ra, uimm: d }),
        25 => Ok(Decoded::Oris { rt, ra, uimm: d }),
        26 => Ok(Decoded::Xoris { rt, ra, uimm: d }),
        28 => Ok(Decoded::Andi { rt, ra, uimm: d }),
        29 => Ok(Decoded::Andis { rt, ra, uimm: d }),
        31 => {
            let xo = (word >> 1) & 0x3FF;
            let rc = word & 1 != 0;
            let oe = (word >> 10) & 1 != 0;
            match xo {
                4 => Ok(Decoded::Tw { to: rt, ra, rb }),
                20 => Ok(Decoded::Lwarx { rt, ra, rb }),
                23 => Ok(Decoded::Lwzx { rt, ra, rb }),
                28 => Ok(Decoded::And { rs: rt, ra, rb, rc }),
                // Add/Subf: top XO bit is OE, so accept both OE=0/1 forms.
                40 | 552 => Ok(Decoded::Subf { rt, ra, rb, rc, oe }),
                87 => Ok(Decoded::Lbzx { rt, ra, rb }),
                119 => Ok(Decoded::Lbzux { rt, ra, rb }),
                183 => Ok(Decoded::Stwux { rs: rt, ra, rb }),
                215 => Ok(Decoded::Stbx { rs: rt, ra, rb }),
                247 => Ok(Decoded::Stbux { rs: rt, ra, rb }),
                279 => Ok(Decoded::Lhzx { rt, ra, rb }),
                311 => Ok(Decoded::Lhzux { rt, ra, rb }),
                343 => Ok(Decoded::Lhax { rt, ra, rb }),
                375 => Ok(Decoded::Lhaux { rt, ra, rb }),
                407 => Ok(Decoded::Sthx { rs: rt, ra, rb }),
                439 => Ok(Decoded::Sthux { rs: rt, ra, rb }),
                792 => Ok(Decoded::Sraw { rs: rt, ra, rb, rc }),
                824 => Ok(Decoded::Srawi {
                    rs: rt,
                    ra,
                    sh: rb,
                    rc,
                }),
                144 => Ok(Decoded::Mtcrf {
                    rs: rt,
                    fxm: ((word >> 12) & 0xFF) as u8,
                }),
                150 => Ok(Decoded::Stwcx { rs: rt, ra, rb }),
                151 => Ok(Decoded::Stwx { rs: rt, ra, rb }),
                19 => Ok(Decoded::Mfcr { rt }),
                24 => Ok(Decoded::Slw { rs: rt, ra, rb, rc }),
                26 => Ok(Decoded::Cntlzw { rs: rt, ra, rc }),
                124 => Ok(Decoded::Nor { rs: rt, ra, rb, rc }),
                266 | 778 => Ok(Decoded::Add { rt, ra, rb, rc, oe }),
                316 => Ok(Decoded::Xor { rs: rt, ra, rb, rc }),
                339 => Ok(Decoded::Mfspr {
                    rt,
                    spr: ((rb << 5) | ra),
                }),
                444 => Ok(Decoded::Or { rs: rt, ra, rb, rc }),
                467 => Ok(Decoded::Mtspr {
                    rs: rt,
                    spr: ((rb << 5) | ra),
                }),
                536 => Ok(Decoded::Srw { rs: rt, ra, rb, rc }),
                598 => Ok(Decoded::Sync {
                    l: (word >> 21) & 3,
                }),
                854 => Ok(Decoded::Eieio),
                922 => Ok(Decoded::Extsh { rs: rt, ra, rc }),
                954 => Ok(Decoded::Extsb { rs: rt, ra, rc }),
                _ => Ok(Decoded::Unsupported {
                    opc,
                    word,
                    reason: "xo31",
                }),
            }
        }
        32 => Ok(Decoded::Lwz {
            rt,
            ra,
            d: d as i16,
        }),
        33 => Ok(Decoded::Lwzu {
            rt,
            ra,
            d: d as i16,
        }),
        34 => Ok(Decoded::Lbz {
            rt,
            ra,
            d: d as i16,
        }),
        35 => Ok(Decoded::Lbzu {
            rt,
            ra,
            d: d as i16,
        }),
        36 => Ok(Decoded::Stw {
            rs: rt,
            ra,
            d: d as i16,
        }),
        37 => Ok(Decoded::Stwu {
            rs: rt,
            ra,
            d: d as i16,
        }),
        38 => Ok(Decoded::Stb {
            rs: rt,
            ra,
            d: d as i16,
        }),
        39 => Ok(Decoded::Stbu {
            rs: rt,
            ra,
            d: d as i16,
        }),
        40 => Ok(Decoded::Lhz {
            rt,
            ra,
            d: d as i16,
        }),
        41 => Ok(Decoded::Lhzu {
            rt,
            ra,
            d: d as i16,
        }),
        42 => Ok(Decoded::Lha {
            rt,
            ra,
            d: d as i16,
        }),
        43 => Ok(Decoded::Lhau {
            rt,
            ra,
            d: d as i16,
        }),
        44 => Ok(Decoded::Sth {
            rs: rt,
            ra,
            d: d as i16,
        }),
        45 => Ok(Decoded::Sthu {
            rs: rt,
            ra,
            d: d as i16,
        }),
        46 => Ok(Decoded::Lmw {
            rt,
            ra,
            d: d as i16,
        }),
        47 => Ok(Decoded::Stmw {
            rs: rt,
            ra,
            d: d as i16,
        }),
        17 => Ok(Decoded::Sc),
        _ => Ok(Decoded::Unsupported {
            opc,
            word,
            reason: "primary",
        }),
    }
}

/// Disassemble one word for the debugger. Never panics.
pub fn disasm(word: u32) -> String {
    match decode(word) {
        Ok(d) => format!("{:?} ; {:08x}", d, word),
        Err(e) => format!("decode-error {} ; {:08x}", e, word),
    }
}

#[allow(dead_code)]
fn _sx16(v: u16) -> i32 {
    sx16(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nop_and_addi() {
        assert_eq!(decode(0x6000_0000).unwrap(), Decoded::Nop);
        // addi r3,r0,16 -> 0x3860_0010
        assert!(matches!(
            decode(0x3860_0010).unwrap(),
            Decoded::Addi {
                rt: 3,
                ra: 0,
                simm: 16
            }
        ));
    }
    #[test]
    fn b_form() {
        // b 0x100 (relative) encoding check via roundtrip of AA=0 LK=0
        let d = decode(0x4800_0100).unwrap();
        assert!(matches!(d, Decoded::B { .. }));
    }
    #[test]
    fn unknown_is_unsupported_not_error() {
        // VMX128 opcode 4 is tracked, not failed
        assert!(matches!(
            decode(0x1000_0000).unwrap(),
            Decoded::Vmx { .. } | Decoded::Unsupported { .. }
        ));
    }
}
