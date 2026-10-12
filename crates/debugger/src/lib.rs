//! Debugger backed by real emulator state.

use std::collections::HashSet;
use x360_common::Result;
use x360_cpu::{decode::disasm, regs::ThreadState};
use x360_memory::Memory;

pub struct Debugger {
    breakpoints: HashSet<u32>,
    pub trace_syscalls: bool,
    pub trace_gpu: bool,
    pub trace_mem: bool,
}

impl Debugger {
    pub fn new() -> Self {
        Self {
            breakpoints: HashSet::new(),
            trace_syscalls: true,
            trace_gpu: false,
            trace_mem: false,
        }
    }

    pub fn add_breakpoint(&mut self, addr: u32) {
        self.breakpoints.insert(addr & !3);
    }
    pub fn remove_breakpoint(&mut self, addr: u32) {
        self.breakpoints.remove(&(addr & !3));
    }
    pub fn is_breakpoint(&self, addr: u32) -> bool {
        self.breakpoints.contains(&(addr & !3))
    }

    pub fn disasm_at(&self, mem: &Memory, addr: u32, count: usize) -> Vec<String> {
        let mut out = Vec::new();
        for i in 0..count {
            let a = addr.wrapping_add(i as u32 * 4);
            match mem.read_u32(a) {
                Ok(w) => out.push(format!("{:08x}: {}", a, disasm(w))),
                Err(e) => out.push(format!("{:08x}: <fault {}>", a, e)),
            }
        }
        out
    }

    pub fn regs(&self, t: &ThreadState) -> Vec<String> {
        let mut v = Vec::new();
        for i in 0..32 {
            v.push(format!("r{:02}={:08x}", i, t.gpr[i]));
        }
        v.push(format!(
            "pc={:08x} lr={:08x} ctr={:08x} cr={:08x} xer={:08x}",
            t.pc, t.lr, t.ctr, t.cr.0, t.xer.0
        ));
        v
    }

    pub fn dump_mem(&self, mem: &Memory, addr: u32, len: usize) -> Result<Vec<u8>> {
        Ok(mem.read_bytes(addr, len)?.to_vec())
    }
}

impl Default for Debugger {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn breakpoints_and_disasm() {
        let mut dbg = Debugger::new();
        dbg.add_breakpoint(0x1001);
        assert!(dbg.is_breakpoint(0x1000));
        let mem = Memory::new();
        let lines = dbg.disasm_at(&mem, 0x1000, 2);
        assert_eq!(lines.len(), 2);
    }
}
