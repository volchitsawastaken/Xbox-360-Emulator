//! Minimal boot runner: cooperative thread scheduling.
//!
//! Loads nothing by itself; the caller places guest words in memory.
//! Runs all threads round-robin until syscall 1 (exit), step limit,
//! or hard error.

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

/// Run all threads until exit, optionally recording each executed
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
/// Threads run cooperatively round-robin (one step each): slot 0 is the
/// initial thread, worker slots join as `ExCreateThread` spawns drain.
/// A worker that returns from its entry (LR 0, PC 0) is marked exited,
/// never fatal; any thread's exit syscall ends the run.
pub fn run_until_exit_traced_imports(
    mem: &mut Memory,
    xenon: &mut Xenon,
    kernel: &mut Kernel,
    mut table: Option<&mut crate::imports::ImportTable>,
    max_steps: u64,
    mut trace: Option<&mut x360_debugger::TraceBuffer>,
) -> Result<GuestExit> {
    use x360_cpu::Interpreter;
    let mut steps = 0u64;
    let mut rr: usize = 0;
    loop {
        if steps >= max_steps {
            return Err(EmuError::Other(format!(
                "step limit {} exceeded without exit",
                max_steps
            )));
        }
        // Install queued worker spawns into their Xenon slots
        // (XAPI convention: r1 = stack top, r3 = start context).
        for handle in kernel.take_pending_spawns() {
            if let Some(rec) = kernel.nt_thread(handle).copied() {
                let slot = rec.cpu_slot as usize;
                if slot < xenon.threads.len() {
                    xenon.threads[slot] = Interpreter::new(slot, rec.start_addr);
                    let st = &mut xenon.threads[slot].t;
                    st.gpr[1] = (rec.stack_base + rec.stack_size - 16) as u64;
                    st.gpr[3] = rec.start_context as u64;
                    st.lr = 0;
                    kernel.mark_spawned(handle);
                }
            }
        }
        // Next runnable slot, round-robin.
        let n = xenon.threads.len();
        let mut pick: Option<usize> = None;
        for _ in 0..n {
            let i = rr % n;
            rr += 1;
            if kernel.cpu_runnable(i as u32) {
                pick = Some(i);
                break;
            }
        }
        let i = pick.ok_or_else(|| EmuError::Other("no runnable threads".into()))?;
        if let Some(tb) = trace.as_mut() {
            // Extra fetch only on the tracing path; hot path untouched.
            let pc = xenon.threads[i].t.pc;
            if let Ok(word) = mem.fetch_u32(pc) {
                tb.push(pc, word, i as u32);
            }
        }
        let trap = match xenon.threads[i].step(mem) {
            Err(_) if i != 0 && xenon.threads[i].t.pc == 0 && xenon.threads[i].t.lr == 0 => {
                // Worker returned from its entry with LR 0: clean exit.
                // (Zero words fault as Unsupported, so a returned worker
                // trips this on its very next step.)
                kernel.exit_cpu_thread(i as u32);
                steps += 1;
                kernel.pump_gpu(mem)?;
                continue;
            }
            Err(e) => return Err(e),
            Ok(trap) => trap,
        };
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
            match crate::dispatch::dispatch_import(
                kernel,
                mem,
                tab,
                thread_id,
                &mut xenon.threads[t.thread].t,
                &imp,
            ) {
                Err(EmuError::Blocked(_)) => {
                    // Honest contention: rewind to the thunk so this
                    // thread retries the import on its next turn. The
                    // step budget bounds any genuine deadlock.
                    xenon.threads[t.thread].t.pc = thunk;
                }
                Err(e) => return Err(e),
                Ok(()) => {}
            }
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

    #[test]
    fn worker_thread_runs_and_exits_cleanly() {
        let mut mem = Memory::new();
        // Worker at 0x90000000 (phys 0x10000000): [0x01000100] =
        // 0xAB, then return (LR 0). Main at 0x82000000 (phys
        // 0x02000000): 30 nops, then exit 0. Physical 0 stays zero
        // words so the returned worker faults cleanly into an exit
        // instead of sliding into code.
        let worker = 0x9000_0000u32;
        for (i, w) in [
            0x3C80_0100u32, // addis r4,0,0x0100
            0x3860_00ABu32, // addi r3,0,0xAB
            0x9064_0100u32, // stw r3,0x100(r4)
            0x4E80_0020u32, // blr
        ]
        .iter()
        .enumerate()
        {
            mem.write_u32(worker + i as u32 * 4, *w).unwrap();
        }
        let entry = 0x8200_0000u32;
        for i in 0..30u32 {
            mem.write_u32(entry + i * 4, 0x6000_0000).unwrap();
        }
        mem.write_u32(entry + 120, 0x3860_0000).unwrap();
        mem.write_u32(entry + 124, 0x3800_0001).unwrap();
        mem.write_u32(entry + 128, 0x4400_0002).unwrap();
        let mut xenon = Xenon::new(entry);
        let mut kernel = Kernel::new();
        let (handle, tid, _) = kernel
            .ex_create_thread(&mut mem, 0, worker, 0, 0)
            .expect("spawn worker");
        assert_eq!(tid, 1);
        let exit = run_until_exit(&mut mem, &mut xenon, &mut kernel, 200).unwrap();
        assert_eq!(exit.code, 0);
        // Worker ran (marker) and exited (return, not fatal).
        assert_eq!(mem.read_u32(0x0100_0100).unwrap(), 0xAB);
        let rec = kernel.nt_thread(handle).expect("tracked");
        assert!(rec.exited);
        assert!(rec.spawned);
    }

    #[test]
    fn suspended_worker_waits_for_resume() {
        let mut mem = Memory::new();
        let worker = 0x9000_0000u32;
        mem.write_u32(worker, 0x3860_0001).unwrap(); // addi r3,0,1
        mem.write_u32(worker + 4, 0x9060_FFFC).unwrap(); // stw r3,-4(r0): faults if run
        let entry = 0x8000_0000u32;
        mem.write_u32(entry, 0x3860_0000).unwrap();
        mem.write_u32(entry + 4, 0x3800_0001).unwrap();
        mem.write_u32(entry + 8, 0x4400_0002).unwrap();
        let mut xenon = Xenon::new(entry);
        let mut kernel = Kernel::new();
        // Created suspended (flags bit 0): installed but never stepped.
        let (handle, _, _) = kernel
            .ex_create_thread(&mut mem, 0, worker, 0, 1)
            .expect("spawn worker");
        let exit = run_until_exit(&mut mem, &mut xenon, &mut kernel, 50).unwrap();
        assert_eq!(exit.code, 0);
        // Faulting worker never ran; still suspended, not exited.
        let rec = kernel.nt_thread(handle).expect("tracked");
        assert!(!rec.exited);
        assert_eq!(rec.suspend_count, 1);
    }

    #[test]
    fn traced_run_attributes_threads() {
        use x360_debugger::TraceBuffer;
        let mut mem = Memory::new();
        // Worker: two nops then return.
        let worker = 0x9000_0000u32;
        mem.write_u32(worker, 0x6000_0000).unwrap();
        mem.write_u32(worker + 4, 0x6000_0000).unwrap();
        mem.write_u32(worker + 8, 0x4E80_0020).unwrap();
        // Main: six nops then exit 0 (outlives the worker).
        let entry = 0x8200_0000u32;
        for i in 0..6u32 {
            mem.write_u32(entry + i * 4, 0x6000_0000).unwrap();
        }
        mem.write_u32(entry + 24, 0x3860_0000).unwrap();
        mem.write_u32(entry + 28, 0x3800_0001).unwrap();
        mem.write_u32(entry + 32, 0x4400_0002).unwrap();
        let mut xenon = Xenon::new(entry);
        let mut kernel = Kernel::new();
        kernel
            .ex_create_thread(&mut mem, 0, worker, 0, 0)
            .expect("spawn worker");
        let mut trace = TraceBuffer::new(256);
        let exit = run_until_exit_traced(&mut mem, &mut xenon, &mut kernel, 200, Some(&mut trace))
            .unwrap();
        assert_eq!(exit.code, 0);
        assert_eq!(trace.len() as u64, exit.steps);
        let threads: std::collections::HashSet<u32> = trace.iter().map(|e| e.thread).collect();
        assert!(threads.contains(&0));
        assert!(threads.contains(&1));
    }
}
