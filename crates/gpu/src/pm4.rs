//! PM4 Type-3 opcode table (port of data, not code).
//!
//! Values cross-checked against the BSD-licensed Xenia project's
//! `src/xenia/gpu/xenos.h` `Type3Opcode` enum (xenia-canary reference).
//! Only the numeric table and one-line meanings are reused; all decode,
//! dispatch, and translation logic here is original.

/// Opcode byte as stored in bits 8..15 of a Type-3 header word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpcodeInfo {
    pub value: u8,
    pub name: &'static str,
    /// Short meaning from the reference table.
    pub about: &'static str,
    pub kind: OpcodeKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpcodeKind {
    Draw,
    State,
    Sync,
    Memory,
    Other,
}

macro_rules! op {
    ($v:expr, $n:ident, $about:expr, $k:expr) => {
        OpcodeInfo {
            value: $v,
            name: stringify!($n),
            about: $about,
            kind: $k,
        }
    };
}

/// Full Type-3 opcode table. Unknown bytes map to `None`.
pub fn lookup(value: u8) -> Option<OpcodeInfo> {
    use OpcodeKind::*;
    Some(match value {
        0x48 => op!(0x48, PM4_ME_INIT, "initialize CP micro-engine", Other),
        0x10 => op!(0x10, PM4_NOP, "skip N words", Sync),
        0x3F => op!(0x3F, PM4_INDIRECT_BUFFER, "indirect buffer dispatch", Other),
        0x37 => op!(
            0x37,
            PM4_INDIRECT_BUFFER_PFD,
            "indirect buffer, pipelined",
            Other
        ),
        0x26 => op!(0x26, PM4_WAIT_FOR_IDLE, "wait for engine idle", Sync),
        0x3C => op!(
            0x3C,
            PM4_WAIT_REG_MEM,
            "wait on register/memory value",
            Sync
        ),
        0x52 => op!(0x52, PM4_WAIT_REG_EQ, "wait until register equal", Sync),
        0x53 => op!(0x53, PM4_WAIT_REG_GTE, "wait until register >=", Sync),
        0x5C => op!(
            0x5C,
            PM4_WAIT_UNTIL_READ,
            "wait until a read completes",
            Sync
        ),
        0x5D => op!(
            0x5D,
            PM4_WAIT_IB_PFD_COMPLETE,
            "wait for IB_PFD writes",
            Sync
        ),
        0x21 => op!(0x21, PM4_REG_RMW, "register read/modify/write", State),
        0x3E => op!(0x3E, PM4_REG_TO_MEM, "register to memory", Memory),
        0x3D => op!(0x3D, PM4_MEM_WRITE, "write N words to memory", Memory),
        0x4F => op!(
            0x4F,
            PM4_MEM_WRITE_CNTR,
            "write CP_PROG_COUNTER to memory",
            Memory
        ),
        0x44 => op!(0x44, PM4_COND_EXEC, "conditional packet execution", Sync),
        0x45 => op!(0x45, PM4_COND_WRITE, "conditional write", Sync),
        0x46 => op!(0x46, PM4_EVENT_WRITE, "event with memory write", Sync),
        0x58 => op!(0x58, PM4_EVENT_WRITE_SHD, "VS|PS done event", Sync),
        0x59 => op!(0x59, PM4_EVENT_WRITE_CFL, "cache flush done event", Sync),
        0x5A => op!(0x5A, PM4_EVENT_WRITE_EXT, "screen extent event", Sync),
        0x5B => op!(0x5B, PM4_EVENT_WRITE_ZPD, "z-pass done event", Sync),
        0x22 => op!(0x22, PM4_DRAW_INDX, "index-buffer draw", Draw),
        0x36 => op!(0x36, PM4_DRAW_INDX_2, "draw with inline indices", Draw),
        0x34 => op!(0x34, PM4_DRAW_INDX_BIN, "binned index-buffer draw", Draw),
        0x35 => op!(0x35, PM4_DRAW_INDX_2_BIN, "binned inline-index draw", Draw),
        0x23 => op!(0x23, PM4_VIZ_QUERY, "viz query extent begin/end", Draw),
        0x25 => op!(0x25, PM4_SET_STATE, "fetch state, shader DMA", State),
        0x2D => op!(0x2D, PM4_SET_CONSTANT, "load constant", State),
        0x55 => op!(0x55, PM4_SET_CONSTANT2, "incr update state", State),
        0x56 => op!(
            0x56,
            PM4_SET_SHADER_CONSTANTS,
            "incr update constants",
            State
        ),
        0x2F => op!(
            0x2F,
            PM4_LOAD_ALU_CONSTANT,
            "load constants from memory",
            State
        ),
        0x27 => op!(0x27, PM4_IM_LOAD, "load sequencer IM via pointer", State),
        0x2B => op!(
            0x2B,
            PM4_IM_LOAD_IMMEDIATE,
            "load sequencer IM inline",
            State
        ),
        0x2E => op!(
            0x2E,
            PM4_LOAD_CONSTANT_CONTEXT,
            "load constants from memory",
            State
        ),
        0x3B => op!(
            0x3B,
            PM4_INVALIDATE_STATE,
            "invalidate state pointers",
            State
        ),
        0x4A => op!(0x4A, PM4_SET_SHADER_BASES, "shader IM partition", State),
        0x4B => op!(0x4B, PM4_SET_BIN_BASE_OFFSET, "bin base offset", State),
        0x50 => op!(0x50, PM4_SET_BIN_MASK, "BIN_MASK register", State),
        0x51 => op!(0x51, PM4_SET_BIN_SELECT, "BIN_SELECT register", State),
        0x5E => op!(0x5E, PM4_CONTEXT_UPDATE, "context update", State),
        0x54 => op!(0x54, PM4_INTERRUPT, "interrupt from stream", Sync),
        0x64 => op!(0x64, PM4_XE_SWAP, "present/swap (emulator-level)", Other),
        0x2C => op!(0x2C, PM4_IM_STORE, "sequencer IM to memory", Memory),
        0x60 => op!(0x60, PM4_SET_BIN_MASK_LO, "bin mask low (tiled)", State),
        0x61 => op!(0x61, PM4_SET_BIN_MASK_HI, "bin mask high (tiled)", State),
        0x62 => op!(0x62, PM4_SET_BIN_SELECT_LO, "bin select low (tiled)", State),
        0x63 => op!(
            0x63,
            PM4_SET_BIN_SELECT_HI,
            "bin select high (tiled)",
            State
        ),
        _ => return None,
    })
}

/// True for the four draw-initiating opcodes.
pub fn is_draw(value: u8) -> bool {
    matches!(value, 0x22 | 0x36 | 0x34 | 0x35)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_draw_opcodes() {
        for v in [0x22u8, 0x36, 0x34, 0x35] {
            let info = lookup(v).expect("draw opcode known");
            assert_eq!(info.kind, OpcodeKind::Draw);
            assert!(is_draw(v));
        }
        assert_eq!(lookup(0x22).unwrap().name, "PM4_DRAW_INDX");
        assert_eq!(lookup(0x10).unwrap().name, "PM4_NOP");
    }

    #[test]
    fn unknown_byte_is_none() {
        assert!(lookup(0x00).is_none());
        assert!(lookup(0xFF).is_none());
    }

    #[test]
    fn table_covers_reference_set() {
        // Every opcode the reference packet disassembler handles by name.
        for v in [
            0x48u8, 0x10, 0x3F, 0x37, 0x26, 0x3C, 0x21, 0x45, 0x46, 0x58, 0x5A, 0x22, 0x36, 0x23,
            0x2D, 0x55, 0x56, 0x2F, 0x27, 0x2B, 0x3B, 0x5E, 0x54, 0x3D, 0x3E, 0x60, 0x61, 0x62,
            0x63,
        ] {
            assert!(lookup(v).is_some(), "opcode {:02x} known", v);
        }
    }
}
