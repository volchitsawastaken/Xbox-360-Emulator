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

/// Harness address where guests leave a 2-word Type-0 command buffer
/// (header + RGBA8 color) for the boot renderer. Bring-up convention,
/// not hardware.
pub const RENDER_BUFFER_ADDR: u32 = 0x8200_2000;
/// Harness clear-color register programmed by the buffer (see gpu bridge).
pub const RENDER_COLOR_REG: u32 = 0x2000;

/// Render guest: stores a Type-0 packet (header for one register +
/// opaque red) at [`RENDER_BUFFER_ADDR`], then exits 0. Only uses
/// implemented integer ops so it runs on the real interpreter.
pub fn render_guest_words() -> Vec<u32> {
    vec![
        0x3CA0_8200, // addis r5,0,0x8200
        0x60A5_2000, // ori   r5,r5,0x2000   (r5 = buffer addr)
        0x3860_0800, // addi  r3,0,0x0800    (type0 header: count 1, reg 0x800)
        0x9065_0000, // stw   r3,0(r5)
        0x3C60_FF00, // addis r3,0,0xFF00
        0x6063_00FF, // ori   r3,r3,0x00FF   (r3 = 0xFF0000FF red)
        0x9065_0004, // stw   r3,4(r5)
        0x3860_0000, // addi  r3,0,0         (exit code)
        0x3800_0001, // addi  r0,0,1         (exit)
        0x4400_0002, // sc
    ]
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
/// When `table` holds import thunks, an `sc` fired inside a thunk
/// dispatches to the kernel export handler by return address
/// (`thunk = pc_after_sc - 4`); all other traps use the `r0`-id
/// convention. `None` table preserves the plain demo path exactly.
pub fn run_until_exit_traced(
    mem: &mut Memory,
    xenon: &mut Xenon,
    kernel: &mut Kernel,
    max_steps: u64,
    trace: Option<&mut x360_debugger::TraceBuffer>,
) -> Result<GuestExit> {
    run_until_exit_traced_imports(mem, xenon, kernel, None, max_steps, trace)
}

/// Import-aware run: `table` maps rewritten thunk addresses to their
/// resolved imports. See [`run_until_exit_traced`] for the fallback.
pub fn run_until_exit_traced_imports(
    mem: &mut Memory,
    xenon: &mut Xenon,
    kernel: &mut Kernel,
    mut table: Option<&mut crate::imports::ImportTable>,
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
        // Retire kicked GPU ring batches (PM4 executor); guest fences
        // observe real progress.
        kernel.pump_gpu(mem)?;
        let Some(t) = trap else { continue };
        // Thunk trap? The rewriter leaves `sc` at the thunk address,
        // so the post-`sc` pc minus 4 names the import.
        let after = xenon.threads[t.thread].t.pc;
        let thunk = after.wrapping_sub(4);
        let imp = table.as_ref().and_then(|tab| tab.get(thunk).cloned());
        if let Some(imp) = imp {
            let tab = table.as_mut().expect("import was just found");
            let thread_id = xenon.threads[t.thread].t.id as u32;
            crate::dispatch::dispatch_import(
                kernel,
                mem,
                tab,
                thread_id,
                &mut xenon.threads[t.thread].t,
                &imp,
            )?;
            continue;
        }
        let id = xenon.threads[t.thread].t.gpr[0] as u32;
        let r3 = xenon.threads[t.thread].t.gpr[3] as u32;
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
                xenon.threads[t.thread].t.gpr[3] = (v) as u64;
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

    #[test]
    fn render_guest_writes_command_buffer() {
        let mut mem = Memory::new();
        let entry = 0x8200_8000;
        let words = render_guest_words();
        for (i, w) in words.iter().enumerate() {
            mem.write_u32(entry + i as u32 * 4, *w).unwrap();
        }
        let mut xenon = Xenon::new(entry);
        let mut kernel = Kernel::new();
        let exit = run_until_exit(&mut mem, &mut xenon, &mut kernel, 64).unwrap();
        assert_eq!(exit.code, 0);
        assert_eq!(exit.steps, words.len() as u64);
        // Guest left a Type-0 packet: header then opaque red.
        assert_eq!(mem.read_u32(RENDER_BUFFER_ADDR).unwrap(), 0x0000_0800);
        assert_eq!(mem.read_u32(RENDER_BUFFER_ADDR + 4).unwrap(), 0xFF00_00FF);
    }
}
