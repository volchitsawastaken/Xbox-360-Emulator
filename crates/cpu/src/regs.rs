//! Xenon thread register file.

/// Condition register: 8 fields x 4 bits (LT/GT/EQ/SO).
#[derive(Debug, Clone, Copy, Default)]
pub struct CondReg(pub u32);

impl CondReg {
    pub fn field(&self, bf: u32) -> u8 {
        assert!(bf < 8);
        ((self.0 >> ((7 - bf) * 4)) & 0xF) as u8
    }
    pub fn set_field(&mut self, bf: u32, v: u8) {
        assert!(bf < 8);
        let shift = (7 - bf) * 4;
        self.0 = (self.0 & !(0xF << shift)) | (((v & 0xF) as u32) << shift);
    }
    /// CR0 from signed 32-bit result (LT/GT/EQ + SO from XER).
    pub fn set_cr0(&mut self, result: i32, xer_so: bool) {
        let lt = (result < 0) as u8;
        let gt = (result > 0) as u8;
        let eq = (result == 0) as u8;
        let v = (lt << 3) | (gt << 2) | (eq << 1) | (xer_so as u8);
        self.set_field(0, v);
    }
    /// CR0 from a signed 64-bit result (doubleword Rc forms).
    pub fn set_cr0_64(&mut self, result: i64, xer_so: bool) {
        let lt = (result < 0) as u8;
        let gt = (result > 0) as u8;
        let eq = (result == 0) as u8;
        let v = (lt << 3) | (gt << 2) | (eq << 1) | (xer_so as u8);
        self.set_field(0, v);
    }
}

/// Fixed-point exception register subset.
#[derive(Debug, Clone, Copy, Default)]
pub struct Xer(pub u32);

impl Xer {
    const SO: u32 = 1 << 31;
    const OV: u32 = 1 << 30;
    const CA: u32 = 1 << 29;
    pub fn so(&self) -> bool {
        self.0 & Self::SO != 0
    }
    pub fn ca(&self) -> bool {
        self.0 & Self::CA != 0
    }
    pub fn set_ca(&mut self, v: bool) {
        if v {
            self.0 |= Self::CA;
        } else {
            self.0 &= !Self::CA;
        }
    }
    pub fn set_ov_so(&mut self, ov: bool) {
        if ov {
            self.0 |= Self::OV | Self::SO;
        } else {
            self.0 &= !Self::OV;
        }
    }
}

/// One hardware thread.
///
/// GPRs are 64-bit (Xenon is PPC64). Word (32-bit) instructions operate
/// on the low half and zero-extend, matching the observable behavior of
/// recompiled code; genuine doubleword instructions use the full width.
/// FPRs are f64 (singles convert on load/store per Power ISA).
#[derive(Debug, Clone)]
pub struct ThreadState {
    pub gpr: [u64; 32],
    pub fpr: [f64; 32],
    pub fpscr: u32,
    pub pc: u32,
    pub lr: u32,
    pub ctr: u32,
    pub cr: CondReg,
    pub xer: Xer,
    /// Reservation for lwarx/stwcx.
    pub reserved: bool,
    pub reserved_addr: u32,
    /// VMX128 file: 128 vector registers of 16 bytes in PPC order
    /// (vr[i] = lowest-address byte). kVX ops address v0-v31;
    /// 128-bit forms (kVX128_1) address all 128. Ops tracked as
    /// unsupported until implemented one by one against retail.
    pub vr: [[u8; 16]; 128],
    pub vscr: u32,
    /// Machine State Register (mfmsr/mtmsr; bit 48 EE, bit 62 RI).
    /// Starts 0 (interrupts disabled); no interrupt model yet.
    pub msr: u64,
    pub id: usize,
}

impl ThreadState {
    pub fn new(id: usize, entry: u32) -> Self {
        Self {
            gpr: [0; 32],
            fpr: [0.0; 32],
            fpscr: 0,
            pc: entry,
            lr: 0,
            ctr: 0,
            cr: CondReg(0),
            xer: Xer(0),
            reserved: false,
            reserved_addr: 0,
            vr: [[0; 16]; 128],
            vscr: 0,
            msr: 0,
            id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cr0_lt_gt_eq() {
        let mut cr = CondReg(0);
        cr.set_cr0(-1, false);
        assert_eq!(cr.field(0) >> 3 & 1, 1);
        cr.set_cr0(5, false);
        assert_eq!(cr.field(0) >> 2 & 1, 1);
        cr.set_cr0(0, false);
        assert_eq!(cr.field(0) >> 1 & 1, 1);
    }
}
