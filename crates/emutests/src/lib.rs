//! Integration tests across subsystems.

#[cfg(test)]
mod integration {
    use x360_cpu::CpuBackend;
    use x360_cpu::Interpreter;
    use x360_memory::Memory;

    #[test]
    fn guest_add_store_load() {
        let mut mem = Memory::new();
        // r5=0x4000; r3=10; r4=32; add r6=r3+r4 ; stw r6,0(r5) ; lwz r7,0(r5)
        let prog = [
            0x38A0_4000, // addi r5,0,0x4000
            0x3860_000A, // addi r3,0,10
            0x3880_0020, // addi r4,0,32
            0x7CC3_2214, // add r6,r3,r4 (XO266)
            0x90C5_0000, // stw r6,0(r5)
            0x80E5_0000, // lwz r7,0(r5)
        ];
        for (i, w) in prog.iter().enumerate() {
            mem.write_u32(0x50000 + i as u32 * 4, *w).unwrap();
        }
        let mut cpu = Interpreter::new(0, 0x50000);
        for _ in 0..prog.len() {
            assert!(cpu.step(&mut mem).unwrap().is_none());
        }
        assert_eq!(cpu.t.gpr[6], 42);
        assert_eq!(cpu.t.gpr[7], 42);
    }

    #[test]
    fn loader_then_pc_set() {
        let mut img = vec![0u8; 32];
        img[0..4].copy_from_slice(b"XEX2");
        img[8..12].copy_from_slice(&32u32.to_be_bytes());
        img[20..24].copy_from_slice(&1u32.to_be_bytes());
        img[24..28].copy_from_slice(&0x0001_0100u32.to_be_bytes());
        img[28..32].copy_from_slice(&0x8200_2000u32.to_be_bytes());
        let (_, info) = x360_loader::parse_xex(&img).unwrap();
        assert_eq!(info.entry_point, 0x8200_2000);
    }

    #[test]
    fn load_and_step_at_real_entry() {
        // End-to-end: parse XEX with high entry, place guest code there,
        // fetch via EXEC mirror and step once.
        let mut img = vec![0u8; 32];
        img[0..4].copy_from_slice(b"XEX2");
        img[8..12].copy_from_slice(&32u32.to_be_bytes());
        img[20..24].copy_from_slice(&1u32.to_be_bytes());
        img[24..28].copy_from_slice(&0x0001_0100u32.to_be_bytes());
        img[28..32].copy_from_slice(&0x8200_1000u32.to_be_bytes());
        let (_, info) = x360_loader::parse_xex(&img).unwrap();
        let mut mem = Memory::new();
        // Guest program: addi r3,0,7 at entry.
        mem.write_u32(info.entry_point, 0x3860_0007).unwrap();
        let mut cpu = Interpreter::new(0, info.entry_point);
        assert!(cpu.step(&mut mem).unwrap().is_none());
        assert_eq!(cpu.t.gpr[3], 7);
    }

    #[test]
    fn six_threads_step() {
        let mut mem = Memory::new();
        mem.write_u32(0x60000, 0x6000_0000).unwrap();
        let mut xenon = x360_cpu::Xenon::new(0x60000);
        let traps = xenon.step_all(&mut mem).unwrap();
        assert!(traps.is_empty());
        for t in &xenon.threads {
            assert_eq!(t.t.pc, 0x60004);
        }
    }

    #[test]
    fn gpu_and_kernel_track_unsupported() {
        let mut gpu = x360_gpu::Xenos::new();
        assert!(gpu.decode_header(1u32 << 30, 0).is_err());
        // Type3 dispatch is pending-M5, never fake draw.
        let header = (3u32 << 30) | ((0x22u32) << 8);
        let words = [header, 0];
        let (p, _) = gpu.decode_packet(&words, 0).unwrap();
        assert!(gpu.dispatch(&p).is_err());
        assert_eq!(gpu.stats.draws, 0);
        let mut k = x360_kernel::Kernel::new();
        assert!(k.syscall(9999, &[]).is_err());
    }

    #[test]
    fn demo_guest_boots_end_to_end() {
        use x360_kernel::boot::{demo_guest_words, run_until_exit};
        let mut mem = Memory::new();
        let entry = 0x8200_9000;
        for (i, w) in demo_guest_words().iter().enumerate() {
            mem.write_u32(entry + i as u32 * 4, *w).unwrap();
        }
        let mut xenon = x360_cpu::Xenon::new(entry);
        let mut kernel = x360_kernel::Kernel::new();
        let exit = run_until_exit(&mut mem, &mut xenon, &mut kernel, 64).unwrap();
        assert_eq!(exit.code, 0);
        assert_eq!(exit.output, b"HI");
    }
}
