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
#[derive(Debug, Clone)]
pub struct ThreadState {
    pub gpr: [u32; 32],
    pub pc: u32,
    pub lr: u32,
    pub ctr: u32,
    pub cr: CondReg,
    pub xer: Xer,
    /// Reservation for lwarx/stwcx.
    pub reserved: bool,
    pub reserved_addr: u32,
    /// VMX128 file (stored, ops tracked as unsupported until M6).
    pub vr: [[u8; 16]; 32],
    pub vscr: u32,
    pub id: usize,
}

impl ThreadState {
    pub fn new(id: usize, entry: u32) -> Self {
        Self {
            gpr: [0; 32],
            pc: entry,
            lr: 0,
            ctr: 0,
            cr: CondReg(0),
            xer: Xer(0),
            reserved: false,
            reserved_addr: 0,
            vr: [[0; 16]; 32],
            vscr: 0,
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
