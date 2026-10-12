//! Minimal single-thread boot runner (M4).
//!
//! Loads nothing by itself; the caller places guest words in memory.
//! Runs thread 0 until syscall 1 (exit), step limit, or hard error.
//! SMP boot is pending; other threads are not stepped here.

use x360_common::{EmuError, Result};
use x360_cpu::{CpuBackend, Xenon};
use x360_memory::Memory;

use crate::Kernel;

/// How a guest run ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestExit {
    pub code: u32,
    pub steps: u64,
    pub output: Vec<u8>,
}

/// Demo guest: prints "HI" via putc then exits 0.
/// Words are big-endian PPC, loaded at the caller's entry.
pub fn demo_guest_words() -> [u32; 8] {
    [
        0x3800_0002, // addi r0,0,2      (putc)
        0x3860_0048, // addi r3,0,0x48   ('H')
        0x4400_0002, // sc
        0x3860_0049, // addi r3,0,0x49   ('I')
        0x4400_0002, // sc
        0x3860_0000, // addi r3,0,0      (exit code)
        0x3800_0001, // addi r0,0,1      (exit)
        0x4400_0002, // sc
    ]
}

/// Boot banner guest: prints "X360-RS BOOT" via putc then exits 0.
/// This is what the boot screen displays. Same syscall convention.
pub fn boot_banner_words() -> Vec<u32> {
    let mut w = vec![0x3800_0002]; // addi r0,0,2 (putc)
    for &c in b"X360-RS BOOT" {
        w.push(0x3860_0000 | c as u32); // addi r3,0,c
        w.push(0x4400_0002); // sc
    }
    w.push(0x3860_0000); // addi r3,0,0 (exit code)
    w.push(0x3800_0001); // addi r0,0,1 (exit)
    w.push(0x4400_0002); // sc
    w
}

/// Run thread 0 until exit. Returns explicit errors for everything else.
pub fn run_until_exit(
    mem: &mut Memory,
    xenon: &mut Xenon,
    kernel: &mut Kernel,
    max_steps: u64,
) -> Result<GuestExit> {
    run_until_exit_traced(mem, xenon, kernel, max_steps, None)
}

/// Run thread 0 until exit, optionally recording each executed
/// instruction into `trace`. `None` costs nothing (no fetch, no format).
pub fn run_until_exit_traced(
    mem: &mut Memory,
    xenon: &mut Xenon,
    kernel: &mut Kernel,
    max_steps: u64,
    mut trace: Option<&mut x360_debugger::TraceBuffer>,
) -> Result<GuestExit> {
    let mut steps = 0u64;
    loop {
        if steps >= max_steps {
            return Err(EmuError::Other(format!(
                "step limit {} exceeded without exit",
                max_steps
            )));
        }
        if let Some(tb) = trace.as_mut() {
            // Extra fetch only on the tracing path; hot path untouched.
            let pc = xenon.threads[0].t.pc;
            if let Ok(word) = mem.fetch_u32(pc) {
                tb.push(pc, word);
            }
        }
        let trap = xenon.threads[0].step(mem)?;
        steps += 1;
        let Some(t) = trap else { continue };
        let id = xenon.threads[t.thread].t.gpr[0];
        let r3 = xenon.threads[t.thread].t.gpr[3];
        match id {
            1 => {
                return Ok(GuestExit {
                    code: r3,
                    steps,
                    output: kernel.console.clone(),
                });
            }
            2 => {
                kernel.syscall(2, &[r3])?;
            }
            0 => {
                let v = kernel.syscall(0, &[])?;
                // Return time in r3 like a real ABI would.
                xenon.threads[t.thread].t.gpr[3] = v;
            }
            other => {
                kernel.syscall(other, &[])?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_boots_with_hi_and_zero() {
        let mut mem = Memory::new();
        let entry = 0x8200_5000;
        for (i, w) in demo_guest_words().iter().enumerate() {
            mem.write_u32(entry + i as u32 * 4, *w).unwrap();
        }
        let mut xenon = Xenon::new(entry);
        let mut kernel = Kernel::new();
        let exit = run_until_exit(&mut mem, &mut xenon, &mut kernel, 100).unwrap();
        assert_eq!(exit.code, 0);
        assert_eq!(exit.output, b"HI");
        assert_eq!(exit.steps, 8);
    }

    #[test]
    fn step_limit_is_error() {
        let mut mem = Memory::new();
        // Infinite branch to self: b . (li=0)
        mem.write_u32(0x60000, 0x4800_0000).unwrap();
        let mut xenon = Xenon::new(0x60000);
        let mut kernel = Kernel::new();
        assert!(run_until_exit(&mut mem, &mut xenon, &mut kernel, 16).is_err());
    }

    #[test]
    fn unknown_syscall_is_error_not_exit() {
        let mut mem = Memory::new();
        let entry = 0x61000;
        // addi r0,0,99 ; sc
        mem.write_u32(entry, 0x3800_0063).unwrap();
        mem.write_u32(entry + 4, 0x4400_0002).unwrap();
        let mut xenon = Xenon::new(entry);
        let mut kernel = Kernel::new();
        let r = run_until_exit(&mut mem, &mut xenon, &mut kernel, 10);
        assert!(r.is_err());
    }

    #[test]
    fn traced_run_records_instructions() {
        use x360_debugger::TraceBuffer;
        let mut mem = Memory::new();
        let entry = 0x8200_7000;
        for (i, w) in demo_guest_words().iter().enumerate() {
            mem.write_u32(entry + i as u32 * 4, *w).unwrap();
        }
        let mut xenon = Xenon::new(entry);
        let mut kernel = Kernel::new();
        let mut trace = TraceBuffer::default();
        let exit = run_until_exit_traced(&mut mem, &mut xenon, &mut kernel, 100, Some(&mut trace))
            .unwrap();
        assert_eq!(exit.code, 0);
        assert_eq!(trace.len() as u64, exit.steps);
        // First recorded instruction is the demo's addi.
        assert!(trace.iter().next().unwrap().disasm.contains("Addi"));
    }

    #[test]
    fn banner_boots_with_text_and_zero() {
        let mut mem = Memory::new();
        let entry = 0x8200_6000;
        let words = boot_banner_words();
        for (i, w) in words.iter().enumerate() {
            mem.write_u32(entry + i as u32 * 4, *w).unwrap();
        }
        let mut xenon = Xenon::new(entry);
        let mut kernel = Kernel::new();
        let exit = run_until_exit(&mut mem, &mut xenon, &mut kernel, 128).unwrap();
        assert_eq!(exit.code, 0);
        assert_eq!(exit.output, b"X360-RS BOOT");
        assert_eq!(exit.steps, words.len() as u64);
    }
}
