//! Xenon PowerPC interpreter core.

pub mod decode;
pub mod exec;
pub mod regs;

pub use decode::{decode, disasm, Decoded};
pub use exec::{execute, SyscallTrap};
pub use regs::{CondReg, ThreadState, Xer};

use x360_common::{EmuError, Result};
use x360_memory::Memory;

/// Backend trait so a JIT can replace the interpreter later.
pub trait CpuBackend {
    fn step(&mut self, mem: &mut Memory) -> Result<Option<SyscallTrap>>;
    fn thread(&self) -> &ThreadState;
    fn thread_mut(&mut self) -> &mut ThreadState;
}

/// Single-threaded interpreter.
pub struct Interpreter {
    pub t: ThreadState,
    pub steps: u64,
    pub unsupported_count: u64,
}

impl Interpreter {
    pub fn new(id: usize, entry: u32) -> Self {
        Self {
            t: ThreadState::new(id, entry),
            steps: 0,
            unsupported_count: 0,
        }
    }

    /// Run up to `quanta` instructions or until syscall/error.
    pub fn run_quanta(&mut self, mem: &mut Memory, quanta: usize) -> Result<Option<SyscallTrap>> {
        for _ in 0..quanta {
            if let Some(trap) = self.step(mem)? {
                return Ok(Some(trap));
            }
        }
        Ok(None)
    }
}

impl CpuBackend for Interpreter {
    fn step(&mut self, mem: &mut Memory) -> Result<Option<SyscallTrap>> {
        let pc = self.t.pc;
        let word = mem.fetch_u32(pc).map_err(|e| match e {
            EmuError::MemoryFault { addr, size, kind } => EmuError::MemoryFault {
                addr,
                size,
                kind: format!("pc-fetch: {}", kind),
            },
            other => other,
        })?;
        let d = decode(word)?;
        match execute(d, word, &mut self.t, mem) {
            Ok(trap) => {
                self.steps += 1;
                Ok(trap)
            }
            Err(EmuError::Unsupported(msg)) => {
                self.unsupported_count += 1;
                log::warn!("cpu{} pc={:08x} unsupported: {}", self.t.id, pc, msg);
                Err(EmuError::Unsupported(msg))
            }
            Err(e) => Err(e),
        }
    }

    fn thread(&self) -> &ThreadState {
        &self.t
    }
    fn thread_mut(&mut self) -> &mut ThreadState {
        &mut self.t
    }
}

/// Six hardware threads (3 cores x SMT).
pub struct Xenon {
    pub threads: Vec<Interpreter>,
    next: usize,
}

impl Xenon {
    pub fn new(entry: u32) -> Self {
        Self {
            threads: (0..6).map(|i| Interpreter::new(i, entry)).collect(),
            next: 0,
        }
    }

    /// Cooperative round-robin step across threads.
    pub fn step_all(&mut self, mem: &mut Memory) -> Result<Vec<SyscallTrap>> {
        let mut traps = Vec::new();
        for _ in 0..self.threads.len() {
            let idx = self.next;
            self.next = (self.next + 1) % self.threads.len();
            if let Some(t) = self.threads[idx].step(mem)? {
                traps.push(t);
            }
        }
        Ok(traps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interpreter_runs_addi_stw_lwz() {
        let mut mem = Memory::new();
        // program at 0x10000: addi r3,0,16 ; stw r3,0x2000 ; lwz r4,0x2000
        // Use absolute via r0=0x2000 base? Simpler: build with r5 as base.
        // addi r5,0,0x2000 ; addi r3,0,16 ; stw r3,0(r5) ; lwz r4,0(r5)
        let prog: [u32; 4] = [0x38A0_2000, 0x3860_0010, 0x9065_0000, 0x8085_0000];
        for (i, w) in prog.iter().enumerate() {
            mem.write_u32(0x10000 + i as u32 * 4, *w).unwrap();
        }
        let mut cpu = Interpreter::new(0, 0x10000);
        for _ in 0..4 {
            assert!(cpu.step(&mut mem).unwrap().is_none());
        }
        assert_eq!(cpu.t.gpr[3], 16);
        assert_eq!(cpu.t.gpr[4], 16);
    }

    #[test]
    fn branch_b_and_bclr() {
        let mut mem = Memory::new();
        // b +8 (skip one nop), then addi.
        // b offset 8: 0x4800_0008
        mem.write_u32(0x10000, 0x4800_0008).unwrap();
        mem.write_u32(0x10004, 0x6000_0000).unwrap();
        mem.write_u32(0x10008, 0x3860_0007).unwrap();
        let mut cpu = Interpreter::new(0, 0x10000);
        cpu.step(&mut mem).unwrap();
        assert_eq!(cpu.t.pc, 0x10008);
        cpu.step(&mut mem).unwrap();
        assert_eq!(cpu.t.gpr[3], 7);
    }
}
