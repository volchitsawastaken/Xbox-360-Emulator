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
//! Scope: structural validation only (length, CF bound, exec extents,
//! end-opcode census). No translation, no execution. Invalid uploads
//! are explicit errors, never silent acceptance.

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
}

/// Unpack one 3-dword group into its 2 CF instructions (reference
/// `UnpackControlFlowInstructions`).
pub fn unpack_cf_pair(dwords: &[u32; 3]) -> [CfInstr; 2] {
    let (d0, d1, d2) = (dwords[0], dwords[1], dwords[2]);
    [
        CfInstr {
            opcode: (d1 & 0xFFFF) >> 12,
            word0: d0,
        },
        CfInstr {
            opcode: d2 >> 28,
            word0: (d1 >> 16) | (d2 << 16),
        },
    ]
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
}
