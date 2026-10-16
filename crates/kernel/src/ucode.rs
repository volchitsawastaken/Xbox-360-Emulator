//! Xbox 360 shader-microcode structural validation.
//!
//! Format facts ported from the BSD-licensed Xenia code (see also the
//! `ucode.h` header comment: XNA Game Studio assembler + R400/R600
//! ISA docs + freedreno `instr-a2xx.h`):
//! - `UnpackControlFlowInstructions` (`ucode.h`): 3 dwords unpack to
//!   2 control-flow instructions; each CF instruction's opcode is the
//!   top 4 bits of its second dword's low half
//!   (`dword_1 & 0xFFFF) >> 12` for the first, `dword_2 >> 28` for
//!   the second).
//! - `Shader::AnalyzeUcode` (`shader_translator.cc`): CF pairs live
//!   at the top of the upload; the CF program runs to the first
//!   exec-clause address. (Deviates from the reference code's
//!   minimum-over-all scan on purpose: see `validate_ucode`.)
//! - Clause fetch (`shader_translator.cc`): exec `(address, count)`
//!   covers clause slots `[address, address + count)`, each clause
//!   slot is 3 dwords (`op_ptr = ucode + instr_offset * 3`).
//! - Opcode values + exec/end sets (`ucode.h` `ControlFlowOpcode`,
//!   `IsControlFlowOpcodeExec`, `DoesControlFlowOpcodeEndShader`).
//!
//! Scope: structural validation + CF-program disassembly (exec
//! extents, alloc targets, control flow). Clause (ALU/fetch)
//! contents are not decoded yet. Invalid uploads are explicit
//! errors, never silent acceptance.

use x360_common::{EmuError, Result};

/// CF opcodes that execute ALU/fetch clause slots (reference
/// `IsControlFlowOpcodeExec`).
pub fn is_exec_opcode(op: u32) -> bool {
    matches!(op, 1 | 2 | 3 | 4 | 5 | 6 | 13 | 14)
}

/// CF opcodes that terminate the shader after executing (reference
/// `DoesControlFlowOpcodeEndShader`).
pub fn is_end_opcode(op: u32) -> bool {
    matches!(op, 2 | 4 | 6 | 14)
}

/// One unpacked control-flow instruction: raw fields only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CfInstr {
    /// 4-bit opcode (0-15, all defined; 12 = alloc, 15 = fetch-done).
    pub opcode: u32,
    /// Word 0 (address/count/sequence holder for exec-like opcodes).
    pub word0: u32,
    /// Word 1 (alloc size/type holder; exec predicate-clean flag).
    pub word1: u32,
}

impl CfInstr {
    /// Clause-slot address (exec `address_ : 12`).
    pub fn address(&self) -> u32 {
        self.word0 & 0xFFF
    }

    /// Clause-slot count (exec `count_ : 3`).
    pub fn count(&self) -> u32 {
        (self.word0 >> 12) & 7
    }

    /// Sequence bits (exec `sequence_ : 12`, 2 per instruction).
    pub fn sequence(&self) -> u32 {
        (self.word0 >> 16) & 0xFFF
    }

    /// Alloc size (alloc `size_ : 3`).
    pub fn alloc_size(&self) -> u32 {
        self.word0 & 7
    }

    /// Alloc type (alloc `alloc_type_ : 2` at word1 bits 9-10).
    pub fn alloc_type(&self) -> u32 {
        (self.word1 >> 9) & 3
    }

    /// Bool-constant address (cond-exec `bool_address_ : 8` at
    /// word1 bits 2-9).
    pub fn bool_address(&self) -> u32 {
        (self.word1 >> 2) & 0xFF
    }

    /// Control-flow target address (loop/call/jmp `address_ : 13`
    /// at word0 bits 0-12; exec forms use the 12-bit [`Self::address`]
    /// instead).
    pub fn cf_target(&self) -> u32 {
        self.word0 & 0x1FFF
    }

    /// Loop-constant id (`loop_id_ : 5` at word0 bits 16-20).
    pub fn loop_id(&self) -> u32 {
        (self.word0 >> 16) & 0x1F
    }

    /// Loop-start repeat flag (`is_repeat_` at word0 bit 13:
    /// reuse the current iterator instead of resetting to 0).
    pub fn is_repeat(&self) -> bool {
        (self.word0 >> 13) & 1 != 0
    }

    /// Loop-end predicated break (`is_predicated_break_` at word0
    /// bit 21).
    pub fn is_predicated_break(&self) -> bool {
        (self.word0 >> 21) & 1 != 0
    }

    /// Call/jmp unconditional flag (`is_unconditional_` at word0
    /// bit 13: ignore bool/predicate gating).
    pub fn is_unconditional(&self) -> bool {
        (self.word0 >> 13) & 1 != 0
    }

    /// Call/jmp predicated-vs-bool gating (`is_predicated_` at
    /// word0 bit 14: predicate check when set, bool-constant
    /// check when clear).
    pub fn is_ctrl_predicated(&self) -> bool {
        (self.word0 >> 14) & 1 != 0
    }

    /// Required bool/predicate value (`condition_ : 1` at word1
    /// bit 10 for cond-exec and predicated-exec forms).
    pub fn condition(&self) -> bool {
        (self.word1 >> 10) & 1 != 0
    }
}

/// CF opcode mnemonic (reference `ucode.h` `ControlFlowOpcode`).
/// CF opcode mnemonic (reference `shader_translator.cc`
/// `ParseControlFlow*` `opcode_name` + `shader_translator_disasm.cc`).
pub fn cf_opcode_name(op: u32) -> &'static str {
    match op {
        0 => "cnop",
        1 => "exec",
        2 => "exece",
        3 => "cexec",
        4 => "cexece",
        // 5/6 print as exec/exece with a (p0)/(!p0) prefix.
        5 => "exec",
        6 => "exece",
        7 => "loop",
        8 => "endloop",
        9 => "call",
        10 => "ret",
        11 => "jmp",
        12 => "alloc",
        13 => "cexec",
        14 => "cexece",
        // 15 prints nothing in the reference.
        15 => "fetchdone",
        _ => "?",
    }
}

/// Unpack one 3-dword group into its 2 CF instructions (reference
/// `UnpackControlFlowInstructions`).
pub fn unpack_cf_pair(dwords: &[u32; 3]) -> [CfInstr; 2] {
    let (d0, d1, d2) = (dwords[0], dwords[1], dwords[2]);
    [
        CfInstr {
            opcode: (d1 & 0xFFFF) >> 12,
            word0: d0,
            word1: d1 & 0xFFFF,
        },
        CfInstr {
            opcode: d2 >> 28,
            word0: (d1 >> 16) | (d2 << 16),
            word1: d2 >> 16,
        },
    ]
}

/// Disassemble the CF program of an upload, one line per CF
/// instruction (`index: mnemonic operands`). Validates first (same
/// errors as [`validate_ucode`]). Exec lines show the covered clause
/// slots; alloc lines name the target; control opcodes beyond
/// exec/alloc print raw words (honest placeholder until clause
/// translation lands). Mnemonics match the reference disassembler
/// (`shader_translator_disasm.cc`, `ParseControlFlow*` names).
pub fn disassemble_cf(dwords: &[u32], is_vertex_shader: bool) -> Result<Vec<String>> {
    let st = validate_ucode(dwords)?;
    let mut out = Vec::new();
    for pair in 0..st.cf_pairs as usize {
        let g = [dwords[3 * pair], dwords[3 * pair + 1], dwords[3 * pair + 2]];
        for (j, ins) in unpack_cf_pair(&g).iter().enumerate() {
            let idx = pair as u32 * 2 + j as u32;
            out.push(disassemble_cf_instr(idx, *ins, is_vertex_shader));
        }
    }
    Ok(out)
}

/// One CF instruction line (see [`disassemble_cf`]).
pub fn disassemble_cf_instr(idx: u32, ins: CfInstr, is_vertex_shader: bool) -> String {
    let name = cf_opcode_name(ins.opcode);
    match ins.opcode {
        // Exec family: slot range (+ bool/condition for cond forms).
        1 | 2 => format!("{}: {} @{} x{}", idx, name, ins.address(), ins.count()),
        3 | 4 | 13 | 14 => {
            let bool_idx = (ins.word1 >> 2) & 0xFF;
            let cond = (ins.word1 >> 10) & 1;
            format!(
                "{}: {} {}b{} @{} x{}",
                idx,
                name,
                if cond != 0 { "" } else { "!" },
                bool_idx,
                ins.address(),
                ins.count()
            )
        }
        5 | 6 => {
            let cond = (ins.word1 >> 10) & 1;
            format!(
                "{}: ({}) {} @{} x{}",
                idx,
                if cond != 0 { "p0" } else { "!p0" },
                name,
                ins.address(),
                ins.count()
            )
        }
        // Alloc: named target (reference `ParsedAllocInstruction`).
        12 => {
            let what = match ins.alloc_type() {
                1 => "position".to_string(),
                2 => {
                    if is_vertex_shader {
                        "interpolators".to_string()
                    } else {
                        "colors".to_string()
                    }
                }
                3 => format!("export = {}", ins.alloc_size()),
                _ => String::new(),
            };
            if what.is_empty() {
                format!("{}: alloc", idx)
            } else {
                format!("{}: alloc {}", idx, what)
            }
        }
        // The rest: mnemonic + raw words (no invented decode).
        _ => format!(
            "{}: {} w0={:08x} w1={:04x}",
            idx, name, ins.word0, ins.word1
        ),
    }
}

/// Validation census for one shader upload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UcodeStats {
    /// CF pairs (3-dword groups) before the first clause slot.
    pub cf_pairs: u32,
    /// Exec-clause CF instructions in the CF program.
    pub execs: u32,
    /// Of those, ending (`ExecEnd`-family) ones.
    pub ends: u32,
    /// Alloc instructions in the CF program.
    pub allocs: u32,
    /// Highest clause slot referenced (exclusive).
    pub max_slot: u32,
}

/// Validate an `IM_LOAD_IMMEDIATE` shader upload structurally.
/// Returns a census on success; malformed uploads (empty,
/// non-multiple-of-3 length, exec-less, clause extent past the end)
/// are explicit errors.
pub fn validate_ucode(dwords: &[u32]) -> Result<UcodeStats> {
    if dwords.is_empty() {
        return Err(EmuError::Other("ucode: empty upload".into()));
    }
    if !dwords.len().is_multiple_of(3) {
        return Err(EmuError::Other(format!(
            "ucode: length {} not a multiple of 3",
            dwords.len()
        )));
    }
    let pairs = dwords.len() / 3;
    // CF bound: the first exec encountered scanning sequentially
    // (reference `AnalyzeUcode` comment: "scanning for the first
    // kExec-ish instruction"; this is what freedreno does). NOTE:
    // the reference code takes the minimum exec address over the
    // WHOLE upload, which collapses on observed retail uploads:
    // clause triples like `[0xC8.., 0, 0xE2..]` unpack as
    // `CondExecPredCleanEnd @0`, forcing bound 0 and rejecting valid
    // shaders. First-only accepts them; validation is log-only on
    // the upload path, so any residual heuristic gap warns instead
    // of breaking storage.
    let mut bound: Option<u32> = None;
    let mut cf: Vec<CfInstr> = Vec::with_capacity(pairs * 2);
    for i in 0..pairs {
        let g = [dwords[3 * i], dwords[3 * i + 1], dwords[3 * i + 2]];
        let [a, b] = unpack_cf_pair(&g);
        for ins in [a, b] {
            if bound.is_none() && is_exec_opcode(ins.opcode) {
                bound = Some(ins.address());
            }
            cf.push(ins);
        }
    }
    let bound = match bound {
        Some(b) => b.min(pairs as u32),
        None => return Err(EmuError::Other("ucode: no exec clause".into())),
    };
    // Execs live in CF slots [0, bound); each extent must fit.
    // (The bound check above uses pre-push length so execs at/after
    // the bound still narrow it exactly like the reference scan.)
    let total_slots = pairs as u32;
    let mut st = UcodeStats {
        cf_pairs: bound,
        ..Default::default()
    };
    for (idx, ins) in cf.iter().enumerate() {
        let slot = idx as u32 / 2;
        if slot >= bound {
            break;
        }
        if ins.opcode == 12 {
            st.allocs += 1;
        }
        if !is_exec_opcode(ins.opcode) {
            continue;
        }
        st.execs += 1;
        if is_end_opcode(ins.opcode) {
            st.ends += 1;
        }
        let end = ins
            .address()
            .checked_add(ins.count())
            .ok_or_else(|| EmuError::Other("ucode: exec extent overflows".into()))?;
        if end > total_slots {
            return Err(EmuError::Other(format!(
                "ucode: exec @{}+{} exceeds {} slots",
                ins.address(),
                ins.count(),
                total_slots
            )));
        }
        st.max_slot = st.max_slot.max(end);
    }
    if st.execs == 0 {
        return Err(EmuError::Other("ucode: no exec in CF program".into()));
    }
    Ok(st)
}

/// One decoded ALU clause instruction (3 dwords).
///
/// Bit layout facts ported from the BSD-licensed Xenia `ucode.h`
/// `AluInstruction::Data` (three 32-bit structs, LSB0 packing):
/// d0 = vector_dest[0:6], vector_dest_rel[6], abs_constants[7],
/// scalar_dest[8:14], scalar_dest_rel[14], export_data[15],
/// vector_write_mask[16:20], scalar_write_mask[20:24],
/// vector_clamp[24], scalar_clamp[25], scalar_opc[26:32];
/// d1 = src3/2/1_swiz[0:8,8:16,16:24], src3/2/1_reg_negate[24,25,26],
/// pred_condition[27], is_predicated[28],
/// const_address_register_relative[29], const_1_rel_abs[30],
/// const_0_rel_abs[31];
/// d2 = src3/2/1_reg[0:8,8:16,16:24], vector_opc[24:29],
/// src3/2/1_sel[29,30,31] (set = temp r#, clear = const c#).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AluInstr {
    /// Raw clause dwords.
    pub dwords: [u32; 3],
}

/// Wrap 3 clause dwords as an ALU instruction (no validation; the
/// caller selects ALU slots via the exec sequence bits).
pub fn parse_alu(dwords: &[u32; 3]) -> AluInstr {
    AluInstr { dwords: *dwords }
}

impl AluInstr {
    fn d0(&self) -> u32 {
        self.dwords[0]
    }
    fn d1(&self) -> u32 {
        self.dwords[1]
    }
    fn d2(&self) -> u32 {
        self.dwords[2]
    }

    /// Vector opcode (5 bits).
    pub fn vector_opcode(&self) -> u32 {
        (self.d2() >> 24) & 0x1F
    }

    /// Scalar opcode (6 bits).
    pub fn scalar_opcode(&self) -> u32 {
        self.d0() >> 26
    }

    /// Vector destination register.
    pub fn vector_dest(&self) -> u32 {
        self.d0() & 0x3F
    }

    /// Scalar destination register.
    pub fn scalar_dest(&self) -> u32 {
        (self.d0() >> 8) & 0x3F
    }

    /// Per-component write masks.
    pub fn vector_write_mask(&self) -> u32 {
        (self.d0() >> 16) & 0xF
    }

    /// Per-component write masks.
    pub fn scalar_write_mask(&self) -> u32 {
        (self.d0() >> 20) & 0xF
    }

    /// Export (memexport/stream-out) instruction.
    pub fn is_export(&self) -> bool {
        (self.d0() >> 15) & 1 != 0
    }

    /// Result clamp flags.
    pub fn vector_clamp(&self) -> bool {
        (self.d0() >> 24) & 1 != 0
    }

    /// Result clamp flags.
    pub fn scalar_clamp(&self) -> bool {
        (self.d0() >> 25) & 1 != 0
    }

    /// Predicated execution.
    pub fn is_predicated(&self) -> bool {
        (self.d1() >> 28) & 1 != 0
    }

    /// Required predicate value when predicated.
    pub fn pred_condition(&self) -> bool {
        (self.d1() >> 27) & 1 != 0
    }

    /// Source register index (1-3) and temp-select bit.
    pub fn src_reg(&self, i: u32) -> u32 {
        match i {
            1 => (self.d2() >> 16) & 0xFF,
            2 => (self.d2() >> 8) & 0xFF,
            _ => self.d2() & 0xFF,
        }
    }

    /// Set = temp register (`r#`), clear = constant (`c#`).
    pub fn src_is_temp(&self, i: u32) -> bool {
        match i {
            1 => (self.d2() >> 31) & 1 != 0,
            2 => (self.d2() >> 30) & 1 != 0,
            _ => (self.d2() >> 29) & 1 != 0,
        }
    }

    /// Source negate flag.
    pub fn src_negate(&self, i: u32) -> bool {
        match i {
            1 => (self.d1() >> 26) & 1 != 0,
            2 => (self.d1() >> 25) & 1 != 0,
            _ => (self.d1() >> 24) & 1 != 0,
        }
    }

    /// Source swizzle byte (component-relative).
    pub fn src_swizzle(&self, i: u32) -> u32 {
        match i {
            1 => (self.d1() >> 16) & 0xFF,
            2 => (self.d1() >> 8) & 0xFF,
            _ => self.d1() & 0xFF,
        }
    }

    /// Any relative addressing (a0/aL): temp-relative dests or
    /// const-addressing bits. On exports the dest bits are not
    /// addressing (reference `AluInstruction::Data`: the vector dest
    /// "can't be relative" and `scalar_dest_rel` selects constant-0
    /// components instead) — see export handling in `uint.rs`.
    pub fn has_relative_addressing(&self) -> bool {
        if ((self.d1() >> 29) & 7) != 0 {
            return true;
        }
        if self.is_export() {
            return false;
        }
        ((self.d0() >> 6) & 1) != 0 || ((self.d0() >> 14) & 1) != 0
    }

    /// Vector destination relative flag (aL-indexed; never set on
    /// well-formed exports per the reference layout comment).
    pub fn is_vector_dest_relative(&self) -> bool {
        (self.d0() >> 6) & 1 != 0
    }

    /// Scalar destination relative flag (aL-indexed; on exports this
    /// bit instead selects constant-0 components, see
    /// `GetConstant0WriteMask`).
    pub fn is_scalar_dest_relative(&self) -> bool {
        (self.d0() >> 14) & 1 != 0
    }

    /// Constant absolute flag (d0 bit 7, reference `abs_constants`).
    /// Dead in the interpreter path (vector/1-operand scalar sources
    /// only absolutize temps; the 2-operand const-reg form never
    /// reaches it) but decoded for completeness.
    pub fn abs_constants(&self) -> bool {
        (self.d0() >> 7) & 1 != 0
    }

    /// Const-0 relative flag (d1 bit 31, reference `const_0_rel_abs`).
    pub fn is_const_0_addressed(&self) -> bool {
        (self.d1() >> 31) & 1 != 0
    }

    /// Const-1 relative flag (d1 bit 30, reference `const_1_rel_abs`).
    pub fn is_const_1_addressed(&self) -> bool {
        (self.d1() >> 30) & 1 != 0
    }

    /// Const base selector (d1 bit 29): true selects the address
    /// register (a0), false selects the loop address (aL)
    /// (reference `const_address_register_relative`; temps are only
    /// absolute or aL-relative, never a0).
    pub fn is_const_address_register_relative(&self) -> bool {
        (self.d1() >> 29) & 1 != 0
    }

    /// Whether const operand `i` (1-3) uses relative addressing
    /// (reference `src_const_is_addressed`: const_0 covers the first
    /// const operand, const_1 once any earlier operand is a const).
    pub fn src_const_is_addressed(&self, i: u32) -> bool {
        match i {
            1 => self.is_const_0_addressed(),
            2 => {
                if self.src_is_temp(1) {
                    self.is_const_0_addressed()
                } else {
                    self.is_const_1_addressed()
                }
            }
            _ => {
                if self.src_is_temp(1) && self.src_is_temp(2) {
                    self.is_const_0_addressed()
                } else {
                    self.is_const_1_addressed()
                }
            }
        }
    }

    /// Temp base index (low 6 bits, reference `src_temp_reg`).
    pub fn src_temp_reg(reg: u32) -> u32 {
        reg & 0x3F
    }

    /// Temp aL-relative flag (bit 6, reference
    /// `is_src_temp_relative`).
    pub fn is_src_temp_relative(reg: u32) -> bool {
        reg & 0x40 != 0
    }

    /// Temp absolute-value flag (bit 7, reference
    /// `is_src_temp_value_absolute`).
    pub fn is_src_temp_value_absolute(reg: u32) -> bool {
        reg & 0x80 != 0
    }

    /// One source operand in disassembly form (`[-]rN` / `[-]cN`).
    pub fn src_operand(&self, i: u32) -> String {
        let reg = if self.src_is_temp(i) {
            (self.src_reg(i) & 0x3F) as u8
        } else {
            self.src_reg(i) as u8
        };
        format!(
            "{}{odef}{reg}",
            if self.src_negate(i) { "-" } else { "" },
            odef = if self.src_is_temp(i) { "r" } else { "c" },
            reg = reg
        )
    }
}

/// Vector ALU opcode mnemonic (reference `kAluVectorOpcodeInfos`
/// disassembly names, including the `opcode_NN` placeholders).
pub fn alu_vector_opcode_name(op: u32) -> &'static str {
    const NAMES: [&str; 32] = [
        "add",
        "mul",
        "max",
        "min",
        "seq",
        "sgt",
        "sge",
        "sne",
        "frc",
        "trunc",
        "floor",
        "mad",
        "cndeq",
        "cndge",
        "cndgt",
        "dp4",
        "dp3",
        "dp2add",
        "cube",
        "max4",
        "setp_eq_push",
        "setp_ne_push",
        "setp_gt_push",
        "setp_ge_push",
        "kill_eq",
        "kill_gt",
        "kill_ge",
        "kill_ne",
        "dst",
        "maxa",
        "opcode_30",
        "opcode_31",
    ];
    NAMES[op as usize & 31]
}

/// Scalar ALU opcode mnemonic (reference `kAluScalarOpcodeInfos`
/// disassembly names, including the `opcode_NN` placeholders).
pub fn alu_scalar_opcode_name(op: u32) -> &'static str {
    const NAMES: [&str; 64] = [
        "adds",
        "adds_prev",
        "muls",
        "muls_prev",
        "muls_prev2",
        "maxs",
        "mins",
        "seqs",
        "sgts",
        "sges",
        "snes",
        "frcs",
        "truncs",
        "floors",
        "exp",
        "logc",
        "log",
        "rcpc",
        "rcpf",
        "rcp",
        "rsqc",
        "rsqf",
        "rsq",
        "maxas",
        "maxasf",
        "subs",
        "subs_prev",
        "setp_eq",
        "setp_ne",
        "setp_gt",
        "setp_ge",
        "setp_inv",
        "setp_pop",
        "setp_clr",
        "setp_rstr",
        "kills_eq",
        "kills_gt",
        "kills_ge",
        "kills_ne",
        "kills_one",
        "sqrt",
        "opcode_41",
        "mulsc",
        "mulsc",
        "addsc",
        "addsc",
        "subsc",
        "subsc",
        "sin",
        "cos",
        "retain_prev",
        "opcode_51",
        "opcode_52",
        "opcode_53",
        "opcode_54",
        "opcode_55",
        "opcode_56",
        "opcode_57",
        "opcode_58",
        "opcode_59",
        "opcode_60",
        "opcode_61",
        "opcode_62",
        "opcode_63",
    ];
    NAMES[op as usize & 63]
}

/// Write-mask component letters (`xyzw`, empty when masked out).
fn mask_letters(mask: u32) -> String {
    let mut s = String::new();
    for (bit, ch) in [(0, 'x'), (1, 'y'), (2, 'z'), (3, 'w')] {
        if mask & (1 << bit) != 0 {
            s.push(ch);
        }
    }
    s
}

/// One-line ALU disassembly (`[(p0)/(!p0)] alu <vec>[_sat]
/// <vdest> <scal>[_sat] <sdest> src1=.. src2=.. src3=..`).
/// Swizzles, export routing, and NOP collapsing are not decoded
/// yet (pending translation work); `_sat`/`(p0)` tokens match the
/// reference disassembler exactly.
pub fn disassemble_alu(dwords: &[u32; 3]) -> String {
    let a = parse_alu(dwords);
    let vd = match mask_letters(a.vector_write_mask()) {
        m if m.is_empty() => format!("r{}", a.vector_dest()),
        m => format!("r{}.{}", a.vector_dest(), m),
    };
    let vec_op = if a.vector_clamp() {
        format!("{}_sat", alu_vector_opcode_name(a.vector_opcode()))
    } else {
        alu_vector_opcode_name(a.vector_opcode()).to_string()
    };
    let scal_op = if a.scalar_clamp() {
        format!("{}_sat", alu_scalar_opcode_name(a.scalar_opcode()))
    } else {
        alu_scalar_opcode_name(a.scalar_opcode()).to_string()
    };
    format!(
        "{}alu {} {} {} r{} src1={} src2={} src3={}",
        if a.is_predicated() {
            if a.pred_condition() {
                "(p0) "
            } else {
                "(!p0) "
            }
        } else {
            ""
        },
        vec_op,
        vd,
        scal_op,
        a.scalar_dest(),
        a.src_operand(1),
        a.src_operand(2),
        a.src_operand(3)
    )
}

/// One decoded fetch clause instruction (3 dwords).
///
/// Bit layout facts ported from the BSD-licensed Xenia `ucode.h`
/// `FetchInstruction::Data` (LSB0): d0 = opcode[0:5],
/// src_reg[5:11], src_reg_am[11], dst_reg[12:18], dst_reg_am[18],
/// const_index[20:25]; d1 = dst_swiz[0:12], is_predicated[31];
/// d2 = use_reg_gradients[0], sample_location[1], lod_bias[2:9],
/// dimension[14:16], offset_x[16:21], offset_y[21:26],
/// offset_z[26:31], pred_condition[31]. Vertex-specific detail
/// (stride, format) is not decoded yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FetchInstr {
    /// Raw clause dwords.
    pub dwords: [u32; 3],
}

/// Wrap 3 clause dwords as a fetch instruction.
pub fn parse_fetch(dwords: &[u32; 3]) -> FetchInstr {
    FetchInstr { dwords: *dwords }
}

impl FetchInstr {
    /// Fetch opcode (5 bits).
    pub fn opcode(&self) -> u32 {
        self.dwords[0] & 0x1F
    }

    /// Source register.
    pub fn src_reg(&self) -> u32 {
        (self.dwords[0] >> 5) & 0x3F
    }

    /// Destination register.
    pub fn dst_reg(&self) -> u32 {
        (self.dwords[0] >> 12) & 0x3F
    }

    /// Fetch-constant index (0-31).
    pub fn const_index(&self) -> u32 {
        (self.dwords[0] >> 20) & 0x1F
    }

    /// Texture dimension (0=1D, 1=2D, 2=3D, 3=Cube).
    pub fn dimension(&self) -> u32 {
        (self.dwords[2] >> 14) & 3
    }

    /// Destination swizzle (d1 low 12 bits, 3 bits per component,
    /// reference `dst_swiz` + `GetFetchDestinationComponentSwizzle`).
    pub fn dst_swizzle(&self) -> u32 {
        self.dwords[1] & 0xFFF
    }

    /// Destination aL-relative flag (d0 bit 18, reference `dst_reg_am`).
    pub fn is_dest_relative(&self) -> bool {
        (self.dwords[0] >> 18) & 1 != 0
    }

    /// Source aL-relative flag (d0 bit 11, reference `src_reg_am`).
    pub fn is_src_relative(&self) -> bool {
        (self.dwords[0] >> 11) & 1 != 0
    }

    /// Predicated fetch (d1 bit 31, reference `is_predicated`).
    pub fn is_predicated(&self) -> bool {
        (self.dwords[1] >> 31) & 1 != 0
    }

    /// Required predicate value (d2 bit 31, reference `pred_condition`).
    pub fn pred_condition(&self) -> bool {
        (self.dwords[2] >> 31) & 1 != 0
    }

    /// Vertex-fetch constant selector (`const_index_sel : 2` at
    /// d0 bits 25-26; the effective index is
    /// `const_index * 3 + sel`, reference
    /// `VertexFetchInstruction::fetch_constant_index`).
    pub fn vf_const_sel(&self) -> u32 {
        (self.dwords[0] >> 25) & 3
    }

    /// Effective vertex-fetch constant index [0-95].
    pub fn vf_const_index(&self) -> u32 {
        self.const_index() * 3 + self.vf_const_sel()
    }

    /// Vertex source component (`src_swiz : 2` at d0 bits 30-31).
    pub fn vf_src_swiz(&self) -> u32 {
        (self.dwords[0] >> 30) & 3
    }

    /// Signed components (`fomat_comp_all`, d1 bit 12).
    pub fn vf_signed(&self) -> bool {
        (self.dwords[1] >> 12) & 1 != 0
    }

    /// Normalized [0,1]/[-1,1] range (`num_format_all == 0`, d1
    /// bit 13 clear means normalized).
    pub fn vf_normalized(&self) -> bool {
        (self.dwords[1] >> 13) & 1 == 0
    }

    /// OpenGL-style no-zero repeating-fraction mode
    /// (`signed_rf_mode_all`, d1 bit 14).
    pub fn vf_rf_no_zero(&self) -> bool {
        (self.dwords[1] >> 14) & 1 != 0
    }

    /// Rounded (floor(x + 0.5)) vs floored vertex index
    /// (`is_index_rounded`, d1 bit 15).
    pub fn vf_index_rounded(&self) -> bool {
        (self.dwords[1] >> 15) & 1 != 0
    }

    /// Vertex data format (`format : 6`, d1 bits 16-21; reference
    /// `xenos::VertexFormat`).
    pub fn vf_format(&self) -> u32 {
        (self.dwords[1] >> 16) & 0x3F
    }

    /// Exponent adjustment (`exp_adjust : 6`, d1 bits 24-29,
    /// signed; results scale by 2^adjust).
    pub fn vf_exp_adjust(&self) -> i32 {
        (((self.dwords[1] >> 24) & 0x3F) as i32) << 26 >> 26
    }

    /// Mini fetch (`is_mini_fetch`, d1 bit 30: reuses the last full
    /// fetch's constant and address).
    pub fn vf_mini(&self) -> bool {
        (self.dwords[1] >> 30) & 1 != 0
    }

    /// Dword stride (`stride : 8`, d2 bits 0-7).
    pub fn vf_stride(&self) -> u32 {
        self.dwords[2] & 0xFF
    }

    /// Dword offset (`offset : 23`, d2 bits 8-30, sign-extended).
    pub fn vf_offset(&self) -> i32 {
        (((self.dwords[2] >> 8) & 0x7F_FFFF) as i32) << 9 >> 9
    }
}

/// Fetch opcode mnemonic (reference `ParseTextureFetchInstruction`
/// names; `vfetch` covers full/mini, whose bit is in
/// vertex-specific detail not decoded here).
pub fn fetch_opcode_name(op: u32, dim: u32) -> String {
    let d = (dim & 3) as usize;
    const DIM1: [&str; 4] = ["1D", "2D", "3D", "Cube"];
    match op {
        0 => "vfetch".to_string(),
        1 => format!("tfetch{}", DIM1[d]),
        16 => format!("getBCF{}", DIM1[d]),
        17 => format!("getCompTexLOD{}", DIM1[d]),
        18 => "getGradients".to_string(),
        19 => format!("getWeights{}", DIM1[d]),
        24 => "setTexLOD".to_string(),
        25 => "setGradientH".to_string(),
        26 => "setGradientV".to_string(),
        _ => format!("fetch_op_{}", op),
    }
}

/// One-line fetch disassembly (`<name> dst src const`).
pub fn disassemble_fetch(dwords: &[u32; 3]) -> String {
    let f = parse_fetch(dwords);
    format!(
        "{} r{} r{} tf{}",
        fetch_opcode_name(f.opcode(), f.dimension()),
        f.dst_reg(),
        f.src_reg(),
        f.const_index()
    )
}

/// Full shader listing: CF lines from [`disassemble_cf`] plus one
/// clause line per covered slot (`  @slot: ...`), in exec order.
/// The exec sequence bits select ALU vs fetch per instruction
/// (reference `GatherExecInformation`: bit0 fetch, bit1
/// serialize); unknown fetch detail stays raw-hex inside its line.
pub fn disassemble_shader(dwords: &[u32], is_vertex_shader: bool) -> Result<Vec<String>> {
    let st = validate_ucode(dwords)?;
    let mut out = disassemble_cf(dwords, is_vertex_shader)?;
    let pairs = st.cf_pairs as usize;
    for pair in 0..pairs {
        let g = [dwords[3 * pair], dwords[3 * pair + 1], dwords[3 * pair + 2]];
        for ins in unpack_cf_pair(&g) {
            if is_exec_opcode(ins.opcode) {
                for k in 0..ins.count() {
                    let slot = (ins.address() + k) as usize;
                    let seq = (ins.sequence() >> (2 * k)) & 3;
                    let base = slot * 3;
                    let line = if base + 3 <= dwords.len() {
                        let w = [dwords[base], dwords[base + 1], dwords[base + 2]];
                        if seq & 1 != 0 {
                            format!(
                                "  @{}: {}{}",
                                slot,
                                disassemble_fetch(&w),
                                if seq & 2 != 0 { " serialize" } else { "" }
                            )
                        } else {
                            format!(
                                "  @{}: {}{}",
                                slot,
                                disassemble_alu(&w),
                                if seq & 2 != 0 { " serialize" } else { "" }
                            )
                        }
                    } else {
                        format!("  @{}: <out of range>", slot)
                    };
                    out.push(line);
                }
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic vertex-shader-shaped upload: exec/alloc CF pattern
    /// (own clause contents, all zero) over 8 pairs.
    fn synth_vs() -> Vec<u32> {
        vec![
            0x0000_1003,
            0x0000_1200,
            0xC400_0000, // exec@3, alloc
            0x0000_1004,
            0x0000_1200,
            0xC200_0000, // exec@4, alloc
            0x0000_1005,
            0x1006_1200,
            0x2200_0000, // exec@5, exec@6
            0x0000_0000,
            0x0000_0000,
            0x0000_0000, // clauses (zeros)
            0x0000_0000,
            0x0000_0000,
            0x0000_0000, //
            0x0000_0000,
            0x0000_0000,
            0x0000_0000, //
            0x0000_0000,
            0x0000_0000,
            0x0000_0000, //
            0x0000_0000,
            0x0000_0000,
            0x0000_0000, //
        ]
    }

    #[test]
    fn unpack_pair_matches_reference() {
        let [a, b] = unpack_cf_pair(&[0x0000_1003, 0x0000_1200, 0xC400_0000]);
        assert_eq!((a.opcode, a.address(), a.count()), (1, 3, 1));
        assert_eq!(b.opcode, 12);
        assert_eq!(b.word0, 0x0000_0000);
    }

    #[test]
    fn vs_shape_validates() {
        let st = validate_ucode(&synth_vs()).unwrap();
        assert_eq!(st.cf_pairs, 3);
        assert_eq!(st.execs, 4);
        assert_eq!(st.allocs, 2);
        assert_eq!(st.ends, 1);
        assert_eq!(st.max_slot, 7);
    }

    #[test]
    fn ps_shape_validates() {
        // alloc + exec_end@1, one clause triple, zero pad.
        let ps = vec![
            0x0000_0000,
            0x1001_C400,
            0x2200_0000, //
            0x0000_0000,
            0x0000_0000,
            0x0000_0000, //
            0x0000_0000,
            0x0000_0000,
            0x0000_0000, //
        ];
        let st = validate_ucode(&ps).unwrap();
        assert_eq!(st.cf_pairs, 1);
        assert_eq!(st.execs, 1);
        assert_eq!(st.ends, 1);
        assert_eq!(st.allocs, 1);
        assert_eq!(st.max_slot, 2);
    }

    #[test]
    fn malformed_rejected() {
        assert!(validate_ucode(&[]).is_err());
        assert!(validate_ucode(&[0; 4]).is_err());
        // No exec anywhere.
        assert!(validate_ucode(&[0; 6]).is_err());
        // Exec extent past the end: exec@9 in a 3-pair upload.
        let bad = vec![
            0x0000_1009,
            0x0000_1200,
            0x0000_0000, //
            0x0000_0000,
            0x0000_0000,
            0x0000_0000, //
            0x0000_0000,
            0x0000_0000,
            0x0000_0000, //
        ];
        assert!(validate_ucode(&bad).is_err());
    }

    #[test]
    fn cf_disassembly_exact() {
        let vs = vec![
            0x0000_1003,
            0x0000_1200,
            0xC400_0000, //
            0x0000_1004,
            0x0000_1200,
            0xC200_0000, //
            0x0000_1005,
            0x1006_1200,
            0x2200_0000, //
            0x0000_0000,
            0x0000_0000,
            0x0000_0000, //
            0x0000_0000,
            0x0000_0000,
            0x0000_0000, //
            0x0000_0000,
            0x0000_0000,
            0x0000_0000, //
            0x0000_0000,
            0x0000_0000,
            0x0000_0000, //
            0x0000_0000,
            0x0000_0000,
            0x0000_0000, //
        ];
        assert_eq!(
            disassemble_cf(&vs, true).unwrap(),
            vec![
                "0: exec @3 x1",
                "1: alloc interpolators",
                "2: exec @4 x1",
                "3: alloc position",
                "4: exec @5 x1",
                "5: exece @6 x1",
            ]
        );
        let ps = vec![
            0x0000_0000,
            0x1001_C400,
            0x2200_0000, //
            0x0000_0000,
            0x0000_0000,
            0x0000_0000, //
            0x0000_0000,
            0x0000_0000,
            0x0000_0000, //
        ];
        assert_eq!(
            disassemble_cf(&ps, false).unwrap(),
            vec!["0: alloc colors", "1: exece @1 x1",]
        );
        assert!(disassemble_cf(&[], true).is_err());
    }

    #[test]
    fn cf_cond_and_raw_lines() {
        let c = CfInstr {
            opcode: 3,
            word0: 0x0000_1003,
            word1: 0x0000,
        };
        assert_eq!(disassemble_cf_instr(7, c, true), "7: cexec !b0 @3 x1");
        let l = CfInstr {
            opcode: 7,
            word0: 0xABCD_EF01,
            word1: 0x1234,
        };
        assert_eq!(
            disassemble_cf_instr(2, l, true),
            "2: loop w0=abcdef01 w1=1234"
        );
        let n = CfInstr {
            opcode: 0,
            word0: 0,
            word1: 0,
        };
        assert_eq!(
            disassemble_cf_instr(0, n, true),
            "0: cnop w0=00000000 w1=0000"
        );
    }

    #[test]
    fn alu_decode_exact() {
        // Synthetic triple: vector mad to r1 (mask xyzw), scalar
        // adds from const, no export.
        // d0: vd=1 | sd=2<<8 | vmask=0xF<<16 | opc(scalar=0)<<26.
        // d1: zero swizzles/flags. d2: src3/2/1 regs 6,5,4 | vec opc 11<<24.
        let d = [0x000F_0201u32, 0x0000_0000, 0x0B04_0506];
        let a = parse_alu(&d);
        assert_eq!(a.vector_opcode(), 11);
        assert_eq!(alu_vector_opcode_name(11), "mad");
        assert_eq!(a.scalar_opcode(), 0);
        assert_eq!(alu_scalar_opcode_name(0), "adds");
        assert_eq!((a.vector_dest(), a.scalar_dest()), (1, 2));
        assert_eq!((a.vector_write_mask(), a.scalar_write_mask()), (0xF, 0));
        assert_eq!((a.src_reg(1), a.src_reg(2), a.src_reg(3)), (4, 5, 6));
        assert_eq!(
            disassemble_alu(&d),
            "alu mad r1.xyzw adds r2 src1=c4 src2=c5 src3=c6"
        );
        // Reference placeholder names for undefined opcodes.
        assert_eq!(alu_scalar_opcode_name(41), "opcode_41");
        assert_eq!(alu_vector_opcode_name(30), "opcode_30");
        // Clamp + predication markers use exact reference tokens.
        let d = [0x030F_0201u32, 0x1800_0000, 0x0B04_0506];
        let a = parse_alu(&d);
        assert!(a.vector_clamp() && a.scalar_clamp());
        assert!(a.is_predicated() && a.pred_condition());
        assert_eq!(
            disassemble_alu(&d),
            "(p0) alu mad_sat r1.xyzw adds_sat r2 src1=c4 src2=c5 src3=c6"
        );
    }

    #[test]
    fn alu_relative_and_fetch_bits_decode() {
        // ALU const-addressing bits built with code shifts (d1):
        // const_0 (bit31) + a0-select (bit29).
        let d0 = (1 & 0x3F) | (0xF << 16);
        let d1 = (1 << 31) | (1 << 29);
        let d2 = (4 << 16) | (5 << 8);
        let a = parse_alu(&[d0, d1, d2]);
        assert!(a.is_const_0_addressed());
        assert!(!a.is_const_1_addressed());
        assert!(a.is_const_address_register_relative());
        assert!(!a.abs_constants());
        // First const operand uses const_0; temp helpers split the pack.
        assert!(a.src_const_is_addressed(1));
        assert_eq!(AluInstr::src_temp_reg(4 | 0x40 | 0x80), 4);
        assert!(AluInstr::is_src_temp_relative(4 | 0x40));
        assert!(AluInstr::is_src_temp_value_absolute(4 | 0x80));
        assert!(!AluInstr::is_src_temp_relative(4));
        // Fetch dest/src relative + swizzle + predication bits.
        let d0 = (1 & 0x1F) | ((7 & 0x3F) << 5) | (1 << 11) | ((3 & 0x3F) << 12) | (1 << 18);
        let d1 = 0x01E8 | (1 << 31);
        let d2 = (1 << 14) | (1 << 31);
        let f = parse_fetch(&[d0, d1, d2]);
        assert!(f.is_src_relative());
        assert!(f.is_dest_relative());
        assert_eq!(f.dst_swizzle(), 0x01E8);
        assert!(f.is_predicated());
        assert!(f.pred_condition());
    }

    #[test]
    fn vertex_fetch_fields_decode() {
        // Full vfetch: opcode 0, src r7, dst r3, const 11 sel 2,
        // signed + normalized + index-rounded, format 36
        // (k_32_FLOAT), exp_adjust -1, stride 16, offset -4.
        let d0 = (7u32 << 5) | (3 << 12) | (11 << 20) | (2 << 25);
        let d1 = (1 << 12) | (36 << 16) | (0x3F << 24);
        let d2 = 16 | (((-4i32 as u32) & 0x7F_FFFF) << 8);
        let f = parse_fetch(&[d0, d1, d2]);
        assert_eq!(f.opcode(), 0);
        assert_eq!(f.vf_const_index(), 11 * 3 + 2);
        assert!(f.vf_signed());
        assert!(f.vf_normalized());
        assert!(!f.vf_index_rounded());
        assert_eq!(f.vf_format(), 36);
        assert_eq!(f.vf_exp_adjust(), -1);
        assert!(!f.vf_mini());
        assert_eq!(f.vf_stride(), 16);
        assert_eq!(f.vf_offset(), -4);
        // Mini fetch with unnormalized + rf-no-zero + rounded.
        let d1 = (1 << 13) | (1 << 14) | (1 << 15) | (6 << 16) | (1 << 30);
        let f = parse_fetch(&[d0, d1, d2]);
        assert!(!f.vf_normalized());
        assert!(f.vf_rf_no_zero());
        assert!(f.vf_index_rounded());
        assert!(f.vf_mini());
        assert_eq!(f.vf_src_swiz(), 0);
    }

    #[test]
    fn fetch_decode_and_shader_listing() {
        // Synthetic fetch triple: tfetch2D, dst r3, src r7, tf11.
        // d0: opc=1 | src=7<<5 | dst=3<<12 | const=11<<20.
        // d2: dim=1<<14.
        let d = [0x00B0_30E1u32, 0x0000_0000, 0x0000_4000];
        let f = parse_fetch(&d);
        assert_eq!((f.opcode(), f.dimension()), (1, 1));
        assert_eq!((f.dst_reg(), f.src_reg(), f.const_index()), (3, 7, 11));
        assert_eq!(disassemble_fetch(&d), "tfetch2D r3 r7 tf11");
        assert_eq!(fetch_opcode_name(18, 0), "getGradients");
        assert_eq!(fetch_opcode_name(31, 0), "fetch_op_31");
        // Shader listing: CF exec@1 x1 (ALU) over a 2-pair upload.
        // Pair0: exec@1 (word0 0x1001, d1lo 0x1200) + nop.
        // Pair1 (slot 1): the ALU triple above.
        let words = vec![
            0x0000_1001,
            0x0000_1200,
            0x0000_0000,
            0x000F_0201,
            0x0000_0000,
            0x0B04_0506,
        ];
        let listed = disassemble_shader(&words, true).unwrap();
        assert_eq!(listed[0], "0: exec @1 x1");
        assert_eq!(listed[1], "1: cnop w0=00000000 w1=0000");
        assert_eq!(
            listed[2],
            "  @1: alu mad r1.xyzw adds r2 src1=c4 src2=c5 src3=c6"
        );
        // Serialize bit appends the marker.
        let mut seq = words.clone();
        seq[0] = 0x0002_1001; // sequence bits: instr0 = ALU+serialize (0b11).
        let listed = disassemble_shader(&seq, true).unwrap();
        assert_eq!(
            listed[2],
            "  @1: alu mad r1.xyzw adds r2 src1=c4 src2=c5 src3=c6 serialize"
        );
    }
}
