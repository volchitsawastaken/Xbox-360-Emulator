//! PowerPC decode. Unknown encodings are explicit Unsupported.
//!
//! Layout facts (RS-in-RT/dest-in-RA for logicals, MDS MD field
//! build, FP XO maps) follow the BSD-licensed Xenia
//! `ppc_decode_data.h` / `ppc_opcode_disasm_gen.cc` (facts only, all
//! code original).

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
    // D-form logicals (primaries 24/25/26/28/29): like X-form
    // logicals, the SOURCE lives in the RT field and the DESTINATION
    // in RA (`ori [RA],[RS],...` per reference disassembler).
    Ori {
        rs: u32,
        ra: u32,
        uimm: u16,
    },
    Oris {
        rs: u32,
        ra: u32,
        uimm: u16,
    },
    Xoris {
        rs: u32,
        ra: u32,
        uimm: u16,
    },
    Andi {
        rs: u32,
        ra: u32,
        uimm: u16,
    },
    Andis {
        rs: u32,
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
    // addic/addic.: D-form carrying add; the `.` form also writes CR0.
    // Primaries 12/13.
    Addic {
        rt: u32,
        ra: u32,
        simm: i16,
    },
    Addic_ {
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
    // Rotate-and-mask (M-form)
    Rlwimi {
        rs: u32,
        ra: u32,
        sh: u32,
        mb: u32,
        me: u32,
        rc: bool,
    },
    Rlwinm {
        rs: u32,
        ra: u32,
        sh: u32,
        mb: u32,
        me: u32,
        rc: bool,
    },
    Rlwnm {
        rs: u32,
        ra: u32,
        rb: u32,
        mb: u32,
        me: u32,
        rc: bool,
    },
    // Compares (D-form with BF/L)
    Cmpi {
        bf: u32,
        l: bool,
        ra: u32,
        simm: i16,
    },
    Cmpli {
        bf: u32,
        l: bool,
        ra: u32,
        uimm: u16,
    },
    // X-form register compares (XO 0 = cmp, XO 32 = cmpl)
    Cmp {
        bf: u32,
        l: bool,
        ra: u32,
        rb: u32,
    },
    Cmpl {
        bf: u32,
        l: bool,
        ra: u32,
        rb: u32,
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
    // Floating-point D-form loads/stores (primaries 48-55). FRT/FRS
    // live in the RT field, base in RA. Singles convert f32<->f64;
    // doubles move f64 bits. Update forms write the EA back to RA.
    Lfs {
        frt: u32,
        ra: u32,
        d: i16,
    },
    Lfsu {
        frt: u32,
        ra: u32,
        d: i16,
    },
    Lfd {
        frt: u32,
        ra: u32,
        d: i16,
    },
    Lfdu {
        frt: u32,
        ra: u32,
        d: i16,
    },
    Stfs {
        frs: u32,
        ra: u32,
        d: i16,
    },
    Stfsu {
        frs: u32,
        ra: u32,
        d: i16,
    },
    Stfd {
        frs: u32,
        ra: u32,
        d: i16,
    },
    Stfdu {
        frs: u32,
        ra: u32,
        d: i16,
    },
    // Doubleword loads/stores, DS-form (primaries 58/62, XO bit 0
    // selects update). `ds` is the sign-extended byte offset
    // (14-bit field << 2). Needed for 64-bit prologues/epilogues.
    Ld {
        rt: u32,
        ra: u32,
        ds: i32,
    },
    Ldu {
        rt: u32,
        ra: u32,
        ds: i32,
    },
    Std {
        rs: u32,
        ra: u32,
        ds: i32,
    },
    Stdu {
        rs: u32,
        ra: u32,
        ds: i32,
    },
    // Floating-point arithmetic. FRT/FRA/FRB live in the RT/RA/RB
    // fields; `single` selects primary 59 (round the result to f32,
    // reference `ppc_emit_fpu.cc` ROUND_TO_SINGLE). A-form ops carry
    // FRC from bits 6-10. Rc on arithmetic copies the (unmodeled)
    // exception summary, so CR1 reads 0; compares write the asked
    // CR field with FU for unordered. Rounding-mode dynamic ops
    // assume round-to-nearest-even (FPSCR RN is never changed by the
    // title path yet; assumed, not hidden).
    Fadd {
        frt: u32,
        fra: u32,
        frb: u32,
        rc: bool,
        single: bool,
    },
    Fsub {
        frt: u32,
        fra: u32,
        frb: u32,
        rc: bool,
        single: bool,
    },
    Fmul {
        frt: u32,
        fra: u32,
        frb: u32,
        rc: bool,
        single: bool,
    },
    Fdiv {
        frt: u32,
        fra: u32,
        frb: u32,
        rc: bool,
        single: bool,
    },
    Fmadd {
        frt: u32,
        fra: u32,
        frb: u32,
        frc: u32,
        rc: bool,
        single: bool,
    },
    Fmsub {
        frt: u32,
        fra: u32,
        frb: u32,
        frc: u32,
        rc: bool,
        single: bool,
    },
    Fnmadd {
        frt: u32,
        fra: u32,
        frb: u32,
        frc: u32,
        rc: bool,
        single: bool,
    },
    Fnmsub {
        frt: u32,
        fra: u32,
        frb: u32,
        frc: u32,
        rc: bool,
        single: bool,
    },
    Fmr {
        frt: u32,
        frb: u32,
        rc: bool,
    },
    Fneg {
        frt: u32,
        frb: u32,
        rc: bool,
    },
    Fabs {
        frt: u32,
        frb: u32,
        rc: bool,
    },
    Fnabs {
        frt: u32,
        frb: u32,
        rc: bool,
    },
    Frsp {
        frt: u32,
        frb: u32,
        rc: bool,
    },
    Fctiw {
        frt: u32,
        frb: u32,
        rc: bool,
    },
    Fctiwz {
        frt: u32,
        frb: u32,
        rc: bool,
    },
    Fctid {
        frt: u32,
        frb: u32,
        rc: bool,
    },
    Fctidz {
        frt: u32,
        frb: u32,
        rc: bool,
    },
    Fcfid {
        frt: u32,
        frb: u32,
        rc: bool,
    },
    Fsqrt {
        frt: u32,
        frb: u32,
        rc: bool,
        single: bool,
    },
    Fres {
        frt: u32,
        frb: u32,
        rc: bool,
    },
    Frsqrte {
        frt: u32,
        frb: u32,
        rc: bool,
    },
    Fsel {
        frt: u32,
        fra: u32,
        frb: u32,
        frc: u32,
        rc: bool,
    },
    Fcmpu {
        bf: u32,
        fra: u32,
        frb: u32,
    },
    Fcmpo {
        bf: u32,
        fra: u32,
        frb: u32,
    },
    // Integer-indexed float/int moves (primary 31): `stfiwx` stores
    // the low word of FRS (the fctiwz companion); `lfiwax` loads a
    // word, sign-extends, and converts to double.
    Stfiwx {
        frs: u32,
        ra: u32,
        rb: u32,
    },
    Lfiwax {
        frt: u32,
        ra: u32,
        rb: u32,
    },
    // 64-bit rotates (MDS-form, primary 30). `mb` is the raw 6-bit
    // mask-begin/end field; rotates feed shifts, extracts, and
    // bitfield inserts. XO: rldicl=0, rldicr=1, rldic=2, rldimi=3.
    Rldicl {
        rs: u32,
        ra: u32,
        sh: u32,
        mb: u32,
    },
    Rldicr {
        rs: u32,
        ra: u32,
        sh: u32,
        me: u32,
    },
    Rldic {
        rs: u32,
        ra: u32,
        sh: u32,
        mb: u32,
        rc: bool,
    },
    Rldimi {
        rs: u32,
        ra: u32,
        sh: u32,
        mb: u32,
        rc: bool,
    },
    // Sign-extend low word (XO 986) and count leading zeros
    // doubleword (XO 58).
    Extsw {
        rs: u32,
        ra: u32,
        rc: bool,
    },
    Cntlzd {
        rs: u32,
        ra: u32,
        rc: bool,
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
    // Negate word (XO 104): RT = 0 - RA (32-bit, zero-extended).
    // OE overflows only on 0x80000000; CA untouched per reference
    // `InstrEmit_negx` (facts only, code original).
    Neg {
        rt: u32,
        ra: u32,
        rc: bool,
        oe: bool,
    },
    // Word multiply/divide (XO-form). Edge behavior is ISA-undefined;
    // choices here are explicit and tested: divide-by-zero yields 0,
    // `INT_MIN / -1` yields `0x80000000`, OE reports either as
    // overflow. XOs: mullw=235, mulhw=75, mulhwu=11, divw=491,
    // divwu=459 (+512 for OE).
    Mullw {
        rt: u32,
        ra: u32,
        rb: u32,
        rc: bool,
        oe: bool,
    },
    Mulhw {
        rt: u32,
        ra: u32,
        rb: u32,
        rc: bool,
        oe: bool,
    },
    Mulhwu {
        rt: u32,
        ra: u32,
        rb: u32,
        rc: bool,
        oe: bool,
    },
    Divw {
        rt: u32,
        ra: u32,
        rb: u32,
        rc: bool,
        oe: bool,
    },
    Divwu {
        rt: u32,
        ra: u32,
        rb: u32,
        rc: bool,
        oe: bool,
    },
    // Doubleword multiply/divide (XO-form, full 64-bit GPR width).
    // Same explicit edges as the word forms: divide-by-zero yields 0,
    // `INT64_MIN / -1` yields `0x8000000000000000`, OE reports either.
    // XOs: mulld=233, mulhd=73, mulhdu=9, divd=489, divdu=457
    // (+512 for OE).
    Mulld {
        rt: u32,
        ra: u32,
        rb: u32,
        rc: bool,
        oe: bool,
    },
    Mulhd {
        rt: u32,
        ra: u32,
        rb: u32,
        rc: bool,
        oe: bool,
    },
    Mulhdu {
        rt: u32,
        ra: u32,
        rb: u32,
        rc: bool,
        oe: bool,
    },
    Divd {
        rt: u32,
        ra: u32,
        rb: u32,
        rc: bool,
        oe: bool,
    },
    Divdu {
        rt: u32,
        ra: u32,
        rb: u32,
        rc: bool,
        oe: bool,
    },
    // Carrying/extended arithmetic (XO-form). `Addc`/`Subfc` set CA like
    // `Add`/`Subf`; the `e`/`me`/`ze` forms fold CA into the sum, so
    // multi-word add/sub chains compare correctly.
    Addc {
        rt: u32,
        ra: u32,
        rb: u32,
        rc: bool,
        oe: bool,
    },
    Subfc {
        rt: u32,
        ra: u32,
        rb: u32,
        rc: bool,
        oe: bool,
    },
    Adde {
        rt: u32,
        ra: u32,
        rb: u32,
        rc: bool,
        oe: bool,
    },
    Subfe {
        rt: u32,
        ra: u32,
        rb: u32,
        rc: bool,
        oe: bool,
    },
    Addme {
        rt: u32,
        ra: u32,
        rc: bool,
        oe: bool,
    },
    Subfme {
        rt: u32,
        ra: u32,
        rc: bool,
        oe: bool,
    },
    Addze {
        rt: u32,
        ra: u32,
        rc: bool,
        oe: bool,
    },
    Subfze {
        rt: u32,
        ra: u32,
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
    // Remaining integer logicals (XOs: andc=60, orc=412, nand=238,
    // eqv=289). Same shape as And/Or/Xor/Nor.
    Andc {
        rs: u32,
        ra: u32,
        rb: u32,
        rc: bool,
    },
    Orc {
        rs: u32,
        ra: u32,
        rb: u32,
        rc: bool,
    },
    Nand {
        rs: u32,
        ra: u32,
        rb: u32,
        rc: bool,
    },
    Eqv {
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
    // Move from time base (XO 371): RT gets TBL (268) or TBU (269)
    // of a real monotonic 50MHz-equivalent tick count (assumed rate,
    // documented; consistent with the millisecond syscall clock).
    Mftb {
        rt: u32,
        tbr: u32,
    },
    // Barriers / traps
    Sync {
        l: u32,
    },
    Isync,
    Eieio,
    Sc,
    Trap,
    // Cache management, X-form (RA/RB). Touch/flush/invalidate are
    // semantic no-ops on a cacheless memory; `dcbz` genuinely zeroes
    // its 128-byte line. XOs per Power ISA: dcbst=54, dcbf=86,
    // dcbtst=246, dcbt=278, dcbi=306, icbi=982, dcbz=1014.
    Dcbt {
        ra: u32,
        rb: u32,
    },
    Dcbtst {
        ra: u32,
        rb: u32,
    },
    Dcbz {
        ra: u32,
        rb: u32,
    },
    Dcbf {
        ra: u32,
        rb: u32,
    },
    Dcbst {
        ra: u32,
        rb: u32,
    },
    Dcbi {
        ra: u32,
        rb: u32,
    },
    Icbi {
        ra: u32,
        rb: u32,
    },
    // Trap-word instructions. tw XO=4 (opcode 31), twi primary opcode 3;
    // TO in the RT field, per reference ppc_opcode_disasm_gen.cc
    // (0x7c000008 "tw", 0x0c000000 "twi"). 64-bit twins: td XO=68
    // (opcode 31), tdi primary opcode 2.
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
    Td {
        to: u32,
        ra: u32,
        rb: u32,
    },
    Tdi {
        to: u32,
        ra: u32,
        simm: i16,
    },
    // Condition-register moves and logical ops (opcode 19 XL form).    // mcrf XO=0 (0x4c000000); CR logical XOs per reference base
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

/// DS field: 14-bit signed value at bits 2..15, scaled by 4.
fn ex_ds(word: u32) -> i32 {
    let raw = ((word >> 2) & 0x3FFF) as u16;
    // Sign-extend 14 bits to 16, then scale.
    let extended = ((raw as i16) << 2) >> 2;
    (extended as i32) << 2
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
        2 => Ok(Decoded::Tdi {
            to: rt,
            ra,
            simm: d as i16,
        }),
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
        12 => Ok(Decoded::Addic {
            rt,
            ra,
            simm: d as i16,
        }),
        13 => Ok(Decoded::Addic_ {
            rt,
            ra,
            simm: d as i16,
        }),
        10 => Ok(Decoded::Cmpli {
            bf: (word >> 23) & 0x7,
            l: word & 0x20_0000 != 0,
            ra,
            uimm: d,
        }),
        11 => Ok(Decoded::Cmpi {
            bf: (word >> 23) & 0x7,
            l: word & 0x20_0000 != 0,
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
        20 => Ok(Decoded::Rlwimi {
            rs: rt,
            ra,
            sh: rb,
            mb: (word >> 6) & 0x1F,
            me: (word >> 1) & 0x1F,
            rc: word & 1 != 0,
        }),
        21 => Ok(Decoded::Rlwinm {
            rs: rt,
            ra,
            sh: rb,
            mb: (word >> 6) & 0x1F,
            me: (word >> 1) & 0x1F,
            rc: word & 1 != 0,
        }),
        23 => Ok(Decoded::Rlwnm {
            rs: rt,
            ra,
            rb,
            mb: (word >> 6) & 0x1F,
            me: (word >> 1) & 0x1F,
            rc: word & 1 != 0,
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
        24 => Ok(Decoded::Ori {
            rs: rt,
            ra,
            uimm: d,
        }),
        25 => Ok(Decoded::Oris {
            rs: rt,
            ra,
            uimm: d,
        }),
        26 => Ok(Decoded::Xoris {
            rs: rt,
            ra,
            uimm: d,
        }),
        28 => Ok(Decoded::Andi {
            rs: rt,
            ra,
            uimm: d,
        }),
        29 => Ok(Decoded::Andis {
            rs: rt,
            ra,
            uimm: d,
        }),
        31 => {
            let xo = (word >> 1) & 0x3FF;
            let rc = word & 1 != 0;
            let oe = (word >> 10) & 1 != 0;
            match xo {
                0 => Ok(Decoded::Cmp {
                    bf: rt >> 2,
                    l: rt & 0x2 != 0,
                    ra,
                    rb,
                }),
                4 => Ok(Decoded::Tw { to: rt, ra, rb }),
                68 => Ok(Decoded::Td { to: rt, ra, rb }),
                20 => Ok(Decoded::Lwarx { rt, ra, rb }),
                23 => Ok(Decoded::Lwzx { rt, ra, rb }),
                28 => Ok(Decoded::And { rs: rt, ra, rb, rc }),
                60 => Ok(Decoded::Andc { rs: rt, ra, rb, rc }),
                32 => Ok(Decoded::Cmpl {
                    bf: rt >> 2,
                    l: rt & 0x2 != 0,
                    ra,
                    rb,
                }),
                // Add/Subf: top XO bit is OE, so accept both OE=0/1 forms.
                40 | 552 => Ok(Decoded::Subf { rt, ra, rb, rc, oe }),
                104 | 616 => Ok(Decoded::Neg { rt, ra, rc, oe }),
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
                58 => Ok(Decoded::Cntlzd { rs: rt, ra, rc }),
                124 => Ok(Decoded::Nor { rs: rt, ra, rb, rc }),
                238 => Ok(Decoded::Nand { rs: rt, ra, rb, rc }),
                266 | 778 => Ok(Decoded::Add { rt, ra, rb, rc, oe }),
                235 | 747 => Ok(Decoded::Mullw { rt, ra, rb, rc, oe }),
                75 | 587 => Ok(Decoded::Mulhw { rt, ra, rb, rc, oe }),
                11 | 523 => Ok(Decoded::Mulhwu { rt, ra, rb, rc, oe }),
                491 | 1003 => Ok(Decoded::Divw { rt, ra, rb, rc, oe }),
                459 | 971 => Ok(Decoded::Divwu { rt, ra, rb, rc, oe }),
                233 | 745 => Ok(Decoded::Mulld { rt, ra, rb, rc, oe }),
                73 | 585 => Ok(Decoded::Mulhd { rt, ra, rb, rc, oe }),
                9 | 521 => Ok(Decoded::Mulhdu { rt, ra, rb, rc, oe }),
                489 | 1001 => Ok(Decoded::Divd { rt, ra, rb, rc, oe }),
                457 | 969 => Ok(Decoded::Divdu { rt, ra, rb, rc, oe }),
                10 | 522 => Ok(Decoded::Addc { rt, ra, rb, rc, oe }),
                138 | 650 => Ok(Decoded::Adde { rt, ra, rb, rc, oe }),
                234 | 746 => Ok(Decoded::Addme { rt, ra, rc, oe }),
                202 | 714 => Ok(Decoded::Addze { rt, ra, rc, oe }),
                8 | 520 => Ok(Decoded::Subfc { rt, ra, rb, rc, oe }),
                136 | 648 => Ok(Decoded::Subfe { rt, ra, rb, rc, oe }),
                232 | 744 => Ok(Decoded::Subfme { rt, ra, rc, oe }),
                200 | 712 => Ok(Decoded::Subfze { rt, ra, rc, oe }),
                289 => Ok(Decoded::Eqv { rs: rt, ra, rb, rc }),
                316 => Ok(Decoded::Xor { rs: rt, ra, rb, rc }),
                339 => Ok(Decoded::Mfspr {
                    rt,
                    spr: ((rb << 5) | ra),
                }),
                371 => Ok(Decoded::Mftb {
                    rt,
                    tbr: ((rb << 5) | ra),
                }),
                444 => Ok(Decoded::Or { rs: rt, ra, rb, rc }),
                412 => Ok(Decoded::Orc { rs: rt, ra, rb, rc }),
                467 => Ok(Decoded::Mtspr {
                    rs: rt,
                    spr: ((rb << 5) | ra),
                }),
                536 => Ok(Decoded::Srw { rs: rt, ra, rb, rc }),
                54 => Ok(Decoded::Dcbst { ra, rb }),
                86 => Ok(Decoded::Dcbf { ra, rb }),
                246 => Ok(Decoded::Dcbtst { ra, rb }),
                278 => Ok(Decoded::Dcbt { ra, rb }),
                306 => Ok(Decoded::Dcbi { ra, rb }),
                982 => Ok(Decoded::Icbi { ra, rb }),
                1014 => Ok(Decoded::Dcbz { ra, rb }),
                598 => Ok(Decoded::Sync {
                    l: (word >> 21) & 3,
                }),
                854 => Ok(Decoded::Eieio),
                922 => Ok(Decoded::Extsh { rs: rt, ra, rc }),
                954 => Ok(Decoded::Extsb { rs: rt, ra, rc }),
                986 => Ok(Decoded::Extsw { rs: rt, ra, rc }),
                659 => Ok(Decoded::Stfiwx { frs: rt, ra, rb }),
                769 => Ok(Decoded::Lfiwax { frt: rt, ra, rb }),
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
        48 => Ok(Decoded::Lfs {
            frt: rt,
            ra,
            d: d as i16,
        }),
        49 => Ok(Decoded::Lfsu {
            frt: rt,
            ra,
            d: d as i16,
        }),
        50 => Ok(Decoded::Lfd {
            frt: rt,
            ra,
            d: d as i16,
        }),
        51 => Ok(Decoded::Lfdu {
            frt: rt,
            ra,
            d: d as i16,
        }),
        52 => Ok(Decoded::Stfs {
            frs: rt,
            ra,
            d: d as i16,
        }),
        53 => Ok(Decoded::Stfsu {
            frs: rt,
            ra,
            d: d as i16,
        }),
        54 => Ok(Decoded::Stfd {
            frs: rt,
            ra,
            d: d as i16,
        }),
        55 => Ok(Decoded::Stfdu {
            frs: rt,
            ra,
            d: d as i16,
        }),
        // Single-precision arithmetic (primary 59): same XO layout
        // as the double side, result rounded to f32.
        59 => {
            let xo = (word >> 1) & 0x3FF;
            let rc = word & 1 != 0;
            let frc = (word >> 6) & 0x1F;
            match xo {
                18 => Ok(Decoded::Fdiv {
                    frt: rt,
                    fra: ra,
                    frb: rb,
                    rc,
                    single: true,
                }),
                20 => Ok(Decoded::Fsub {
                    frt: rt,
                    fra: ra,
                    frb: rb,
                    rc,
                    single: true,
                }),
                21 => Ok(Decoded::Fadd {
                    frt: rt,
                    fra: ra,
                    frb: rb,
                    rc,
                    single: true,
                }),
                22 => Ok(Decoded::Fsqrt {
                    frt: rt,
                    frb: rb,
                    rc,
                    single: true,
                }),
                24 => Ok(Decoded::Fres {
                    frt: rt,
                    frb: rb,
                    rc,
                }),
                25 => Ok(Decoded::Fmul {
                    frt: rt,
                    fra: ra,
                    frb: rb,
                    rc,
                    single: true,
                }),
                28 => Ok(Decoded::Fmsub {
                    frt: rt,
                    fra: ra,
                    frb: rb,
                    frc,
                    rc,
                    single: true,
                }),
                29 => Ok(Decoded::Fmadd {
                    frt: rt,
                    fra: ra,
                    frb: rb,
                    frc,
                    rc,
                    single: true,
                }),
                30 => Ok(Decoded::Fnmsub {
                    frt: rt,
                    fra: ra,
                    frb: rb,
                    frc,
                    rc,
                    single: true,
                }),
                31 => Ok(Decoded::Fnmadd {
                    frt: rt,
                    fra: ra,
                    frb: rb,
                    frc,
                    rc,
                    single: true,
                }),
                _ => Ok(Decoded::Unsupported {
                    opc,
                    word,
                    reason: "fp59-xo",
                }),
            }
        }
        // Double-precision arithmetic (primary 63).
        63 => {
            let xo = (word >> 1) & 0x3FF;
            let rc = word & 1 != 0;
            let frc = (word >> 6) & 0x1F;
            match xo {
                0 => Ok(Decoded::Fcmpu {
                    bf: rt >> 2,
                    fra: ra,
                    frb: rb,
                }),
                12 => Ok(Decoded::Frsp {
                    frt: rt,
                    frb: rb,
                    rc,
                }),
                14 => Ok(Decoded::Fctiw {
                    frt: rt,
                    frb: rb,
                    rc,
                }),
                15 => Ok(Decoded::Fctiwz {
                    frt: rt,
                    frb: rb,
                    rc,
                }),
                18 => Ok(Decoded::Fdiv {
                    frt: rt,
                    fra: ra,
                    frb: rb,
                    rc,
                    single: false,
                }),
                20 => Ok(Decoded::Fsub {
                    frt: rt,
                    fra: ra,
                    frb: rb,
                    rc,
                    single: false,
                }),
                21 => Ok(Decoded::Fadd {
                    frt: rt,
                    fra: ra,
                    frb: rb,
                    rc,
                    single: false,
                }),
                22 => Ok(Decoded::Fsqrt {
                    frt: rt,
                    frb: rb,
                    rc,
                    single: false,
                }),
                23 => Ok(Decoded::Fsel {
                    frt: rt,
                    fra: ra,
                    frb: rb,
                    frc,
                    rc,
                }),
                25 => Ok(Decoded::Fmul {
                    frt: rt,
                    fra: ra,
                    frb: rb,
                    rc,
                    single: false,
                }),
                26 => Ok(Decoded::Frsqrte {
                    frt: rt,
                    frb: rb,
                    rc,
                }),
                28 => Ok(Decoded::Fmsub {
                    frt: rt,
                    fra: ra,
                    frb: rb,
                    frc,
                    rc,
                    single: false,
                }),
                29 => Ok(Decoded::Fmadd {
                    frt: rt,
                    fra: ra,
                    frb: rb,
                    frc,
                    rc,
                    single: false,
                }),
                30 => Ok(Decoded::Fnmsub {
                    frt: rt,
                    fra: ra,
                    frb: rb,
                    frc,
                    rc,
                    single: false,
                }),
                31 => Ok(Decoded::Fnmadd {
                    frt: rt,
                    fra: ra,
                    frb: rb,
                    frc,
                    rc,
                    single: false,
                }),
                32 => Ok(Decoded::Fcmpo {
                    bf: rt >> 2,
                    fra: ra,
                    frb: rb,
                }),
                40 => Ok(Decoded::Fneg {
                    frt: rt,
                    frb: rb,
                    rc,
                }),
                72 => Ok(Decoded::Fmr {
                    frt: rt,
                    frb: rb,
                    rc,
                }),
                136 => Ok(Decoded::Fnabs {
                    frt: rt,
                    frb: rb,
                    rc,
                }),
                264 => Ok(Decoded::Fabs {
                    frt: rt,
                    frb: rb,
                    rc,
                }),
                814 => Ok(Decoded::Fctid {
                    frt: rt,
                    frb: rb,
                    rc,
                }),
                815 => Ok(Decoded::Fctidz {
                    frt: rt,
                    frb: rb,
                    rc,
                }),
                846 => Ok(Decoded::Fcfid {
                    frt: rt,
                    frb: rb,
                    rc,
                }),
                _ => Ok(Decoded::Unsupported {
                    opc,
                    word,
                    reason: "fp63-xo",
                }),
            }
        }
        // MDS-form (primary 30) is actually the MD layout for these
        // four: 6-bit SH/MB built as (bit5 << 5) | low-5, XO select on
        // bits 2-4 (reference `ppc_decode_data.h` FormatMD plus the
        // `n <- sh[5] || sh[0:4]` / `b <- mb[5] || mb[0:4]` rules in
        // `ppc_emit_alu.cc` `InstrEmit_rldiclx/rldicrx/rldimix`).
        30 => {
            let rs = rt;
            let sh = (((word >> 1) & 1) << 5) | ((word >> 11) & 0x1F);
            let mb = (((word >> 5) & 1) << 5) | ((word >> 6) & 0x1F);
            match (word >> 2) & 0x7 {
                0 => Ok(Decoded::Rldicl { rs, ra, sh, mb }),
                1 => Ok(Decoded::Rldicr { rs, ra, sh, me: mb }),
                2 => Ok(Decoded::Rldic {
                    rs,
                    ra,
                    sh,
                    mb,
                    rc: word & 1 != 0,
                }),
                3 => Ok(Decoded::Rldimi {
                    rs,
                    ra,
                    sh,
                    mb,
                    rc: word & 1 != 0,
                }),
                _ => Ok(Decoded::Unsupported {
                    opc,
                    word,
                    reason: "mds-xo",
                }),
            }
        }
        58 => {
            let ds = ex_ds(word);
            match word & 3 {
                0 => Ok(Decoded::Ld { rt, ra, ds }),
                1 => Ok(Decoded::Ldu { rt, ra, ds }),
                _ => Ok(Decoded::Unsupported {
                    opc,
                    word,
                    reason: "ds-xo",
                }),
            }
        }
        62 => {
            let ds = ex_ds(word);
            match word & 3 {
                0 => Ok(Decoded::Std { rs: rt, ra, ds }),
                1 => Ok(Decoded::Stdu { rs: rt, ra, ds }),
                _ => Ok(Decoded::Unsupported {
                    opc,
                    word,
                    reason: "ds-xo",
                }),
            }
        }
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
    fn ds_form_load_store() {
        // Retail fault word: std r28,-40(r1) -> 0xFB81FFD8.
        assert!(matches!(
            decode(0xFB81_FFD8).unwrap(),
            Decoded::Std {
                rs: 28,
                ra: 1,
                ds: -40
            }
        ));
        // ld r3,8(r4): primary 58, XO 0.
        assert!(matches!(
            decode(0xE864_0008).unwrap(),
            Decoded::Ld {
                rt: 3,
                ra: 4,
                ds: 8
            }
        ));
        // stdu r1,-64(r1): primary 62, XO 1.
        assert!(matches!(
            decode(0xF821_FFC1).unwrap(),
            Decoded::Stdu {
                rs: 1,
                ra: 1,
                ds: -64
            }
        ));
        // Reserved XO 2 stays Unsupported, never executed.
        assert!(matches!(
            decode(0xE864_000A).unwrap(),
            Decoded::Unsupported { .. }
        ));
    }
    #[test]
    fn cache_ops_decode() {
        // Retail word: dcbt r0,r4 -> 0x7C00222C.
        assert!(matches!(
            decode(0x7C00_222C).unwrap(),
            Decoded::Dcbt { ra: 0, rb: 4 }
        ));
        assert!(matches!(
            decode((31u32 << 26) | (2 << 16) | (3 << 11) | (1014 << 1)).unwrap(),
            Decoded::Dcbz { ra: 2, rb: 3 }
        ));
    }
    #[test]
    fn addic_form() {
        // Retail word: addic. r8,r8,-1 -> 0x3508FFFF.
        assert!(matches!(
            decode(0x3508_FFFF).unwrap(),
            Decoded::Addic_ {
                rt: 8,
                ra: 8,
                simm: -1
            }
        ));
        assert!(matches!(
            decode(0x30A0_0010).unwrap(),
            Decoded::Addic {
                rt: 5,
                ra: 0,
                simm: 16
            }
        ));
    }
    #[test]
    fn mds_form_decode() {
        // Retail word: rldicl r9,r11,0,32 -> 0x79690020
        // (6-bit fields: SH = 0<<5|0, MB = 1<<5|0; a low-half move).
        assert!(matches!(
            decode(0x7969_0020).unwrap(),
            Decoded::Rldicl {
                rs: 11,
                ra: 9,
                sh: 0,
                mb: 32
            }
        ));
        // Reserved MDS XO (bits 2-4 = 0b100) stays Unsupported.
        assert!(matches!(
            decode(0x7969_0030).unwrap(),
            Decoded::Unsupported { .. }
        ));
        // rldimi r7,r8,60,60 -> 0x7907E72E.
        assert!(matches!(
            decode(0x7907_E72E).unwrap(),
            Decoded::Rldimi {
                rs: 8,
                ra: 7,
                sh: 60,
                mb: 60,
                rc: false
            }
        ));
        // extsw r6,r5 -> 0x7CA607B4; cntlzd r8,r7 -> 0x7CE80074.
        // (RS in RT field, dest in RA: rt=5/ra=6 and rt=7/ra=8.)
        assert!(matches!(
            decode(0x7CA6_07B4).unwrap(),
            Decoded::Extsw {
                rs: 5,
                ra: 6,
                rc: false
            }
        ));
        assert!(matches!(
            decode(0x7CE8_0074).unwrap(),
            Decoded::Cntlzd {
                rs: 7,
                ra: 8,
                rc: false
            }
        ));
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
