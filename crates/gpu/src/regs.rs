//! GPU register-address table (port of data, not code).
//!
//! Byte addresses derived from the BSD-licensed Xenia project's
//! `src/xenia/gpu/register_table.inc` dword indices
//! (byte address = dword index * 4); one-line meanings follow the field
//! descriptions in `src/xenia/gpu/registers.h`.
//! Only the numeric table and one-line meanings are reused; all decode,
//! dispatch, and translation logic here is original.

/// Byte address of a register as written by Type-0 packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegInfo {
    pub addr: u32,
    pub name: &'static str,
    /// Short meaning from the reference table.
    pub about: &'static str,
    pub group: RegGroup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegGroup {
    RenderTarget,
    DepthStencil,
    Viewport,
    ShaderSetup,
    DrawState,
    Other,
}

macro_rules! reg {
    ($a:expr, $n:ident, $about:expr, $g:expr) => {
        RegInfo {
            addr: $a,
            name: stringify!($n),
            about: $about,
            group: $g,
        }
    };
}

/// Curated register table. Unknown addresses map to `None`.
pub const TABLE: &[RegInfo] = {
    use RegGroup::*;
    &[
        reg!(
            0x8000,
            RB_SURFACE_INFO,
            "color/depth surface pitch and MSAA sample count",
            RenderTarget
        ),
        reg!(
            0x8004,
            RB_COLOR_INFO,
            "color target 0 base address and format",
            RenderTarget
        ),
        reg!(
            0x8008,
            RB_DEPTH_INFO,
            "depth target base address and format",
            DepthStencil
        ),
        reg!(
            0x800C,
            RB_COLOR1_INFO,
            "color target 1 base address and format",
            RenderTarget
        ),
        reg!(
            0x8010,
            RB_COLOR2_INFO,
            "color target 2 base address and format",
            RenderTarget
        ),
        reg!(
            0x8014,
            RB_COLOR3_INFO,
            "color target 3 base address and format",
            RenderTarget
        ),
        reg!(
            0x8038,
            PA_SC_SCREEN_SCISSOR_TL,
            "screen scissor top-left corner",
            Viewport
        ),
        reg!(
            0x803C,
            PA_SC_SCREEN_SCISSOR_BR,
            "screen scissor bottom-right corner",
            Viewport
        ),
        reg!(
            0x8200,
            PA_SC_WINDOW_OFFSET,
            "window offset for scissor and viewport",
            Viewport
        ),
        reg!(
            0x8204,
            PA_SC_WINDOW_SCISSOR_TL,
            "window scissor top-left corner",
            Viewport
        ),
        reg!(
            0x8208,
            PA_SC_WINDOW_SCISSOR_BR,
            "window scissor bottom-right corner",
            Viewport
        ),
        reg!(
            0x8400,
            VGT_MAX_VTX_INDX,
            "maximum vertex index clamp",
            DrawState
        ),
        reg!(
            0x8404,
            VGT_MIN_VTX_INDX,
            "minimum vertex index clamp",
            DrawState
        ),
        reg!(
            0x8408,
            VGT_INDX_OFFSET,
            "vertex index offset (base vertex)",
            DrawState
        ),
        reg!(
            0x840C,
            VGT_MULTI_PRIM_IB_RESET_INDX,
            "primitive-restart index value",
            DrawState
        ),
        reg!(
            0x8410,
            RB_COLOR_MASK,
            "per-target color channel write mask",
            RenderTarget
        ),
        reg!(
            0x8434,
            RB_STENCILREFMASK,
            "stencil reference, mask, and write mask",
            DepthStencil
        ),
        reg!(
            0x843C,
            PA_CL_VPORT_XSCALE,
            "viewport X scale factor",
            Viewport
        ),
        reg!(0x8440, PA_CL_VPORT_XOFFSET, "viewport X offset", Viewport),
        reg!(
            0x8444,
            PA_CL_VPORT_YSCALE,
            "viewport Y scale factor",
            Viewport
        ),
        reg!(0x8448, PA_CL_VPORT_YOFFSET, "viewport Y offset", Viewport),
        reg!(
            0x844C,
            PA_CL_VPORT_ZSCALE,
            "viewport Z scale factor",
            Viewport
        ),
        reg!(0x8450, PA_CL_VPORT_ZOFFSET, "viewport Z offset", Viewport),
        reg!(
            0x8600,
            SQ_PROGRAM_CNTL,
            "VS/PS GPR counts and export setup",
            ShaderSetup
        ),
        reg!(
            0x8604,
            SQ_CONTEXT_MISC,
            "shader interpolator and sample control",
            ShaderSetup
        ),
        reg!(
            0x87D8,
            SQ_PS_PROGRAM,
            "pixel shader program base address",
            ShaderSetup
        ),
        reg!(
            0x87DC,
            SQ_VS_PROGRAM,
            "vertex shader program base address",
            ShaderSetup
        ),
        reg!(
            0x87F0,
            VGT_DRAW_INITIATOR,
            "draw primitive type and index count",
            DrawState
        ),
        reg!(
            0x8800,
            RB_DEPTHCONTROL,
            "depth/stencil test and write control",
            DepthStencil
        ),
        reg!(
            0x8804,
            RB_BLENDCONTROL0,
            "color/alpha blend factors and ops, target 0",
            RenderTarget
        ),
        reg!(
            0x8808,
            RB_COLORCONTROL,
            "alpha test and alpha-to-coverage control",
            RenderTarget
        ),
        reg!(
            0x880C,
            RB_HIZCONTROL,
            "hierarchical-Z enable and write control",
            DepthStencil
        ),
        reg!(
            0x8814,
            PA_SU_SC_MODE_CNTL,
            "cull mode, polygon mode, and MSAA setup",
            DrawState
        ),
        reg!(
            0x8818,
            PA_CL_VTE_CNTL,
            "viewport transform enable control",
            Viewport
        ),
        reg!(
            0x8C1C,
            SQ_VS_CONST,
            "vertex shader constant buffer base and size",
            ShaderSetup
        ),
        reg!(
            0x8C20,
            SQ_PS_CONST,
            "pixel shader constant buffer base and size",
            ShaderSetup
        ),
        reg!(
            0x8C60,
            RB_COPY_CONTROL,
            "EDRAM resolve/copy command control",
            Other
        ),
        reg!(0x8C74, RB_DEPTH_CLEAR, "depth clear value", DepthStencil),
        reg!(
            0x8C78,
            RB_COLOR_CLEAR,
            "color clear value (high bits)",
            RenderTarget
        ),
    ]
};

/// Look up a register by byte address.
pub fn lookup(addr: u32) -> Option<RegInfo> {
    TABLE.iter().find(|r| r.addr == addr).copied()
}

/// True for byte addresses present in the table.
pub fn is_known(addr: u32) -> bool {
    lookup(addr).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_registers_resolve() {
        let cases: &[(u32, &str, RegGroup)] = &[
            (0x8000, "RB_SURFACE_INFO", RegGroup::RenderTarget),
            (0x8004, "RB_COLOR_INFO", RegGroup::RenderTarget),
            (0x8008, "RB_DEPTH_INFO", RegGroup::DepthStencil),
            (0x8038, "PA_SC_SCREEN_SCISSOR_TL", RegGroup::Viewport),
            (0x843C, "PA_CL_VPORT_XSCALE", RegGroup::Viewport),
            (0x8600, "SQ_PROGRAM_CNTL", RegGroup::ShaderSetup),
            (0x87DC, "SQ_VS_PROGRAM", RegGroup::ShaderSetup),
            (0x87F0, "VGT_DRAW_INITIATOR", RegGroup::DrawState),
            (0x8800, "RB_DEPTHCONTROL", RegGroup::DepthStencil),
            (0x8808, "RB_COLORCONTROL", RegGroup::RenderTarget),
            (0x8C78, "RB_COLOR_CLEAR", RegGroup::RenderTarget),
            (0x8C60, "RB_COPY_CONTROL", RegGroup::Other),
        ];
        for (addr, name, group) in cases {
            let info = lookup(*addr).expect("register known");
            assert_eq!(info.name, *name, "addr {:08x}", addr);
            assert_eq!(info.group, *group, "addr {:08x}", addr);
            assert!(is_known(*addr));
        }
    }

    #[test]
    fn unknown_address_is_none() {
        assert!(lookup(0x0000_0000).is_none());
        assert!(lookup(0xFFFF_FFFF).is_none());
        assert!(!is_known(0x0000_1234));
    }

    #[test]
    fn table_has_no_duplicate_addresses() {
        let mut seen = std::collections::HashSet::new();
        for r in TABLE {
            assert!(seen.insert(r.addr), "duplicate {:08x}", r.addr);
        }
        assert!(
            (25..=40).contains(&TABLE.len()),
            "table len {} out of range",
            TABLE.len()
        );
    }
}
