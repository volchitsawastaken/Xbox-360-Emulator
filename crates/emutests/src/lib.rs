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
        assert_eq!(info.entry_point, Some(0x8200_2000));
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
        let entry = info.entry_point.expect("test image has entry");
        let mut mem = Memory::new();
        // Guest program: addi r3,0,7 at entry.
        mem.write_u32(entry, 0x3860_0007).unwrap();
        let mut cpu = Interpreter::new(0, entry);
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

    /// Throughput measurement, not a timing assert: machines vary, so this
    /// prints MIPS for the log and only asserts correctness. Track the
    /// printed number across commits; it must not silently regress.
    #[test]
    fn interpreter_throughput_mips() {
        use std::time::Instant;
        // 2-word loop: addi r3,r3,1 ; b -4 (li=-4).
        let entry = 0x63000;
        let mut mem = Memory::new();
        mem.write_u32(entry, 0x3863_0001).unwrap();
        mem.write_u32(entry + 4, 0x4BFF_FFFC).unwrap();
        let mut cpu = Interpreter::new(0, entry);
        let target = 200_000u64;
        let start = Instant::now();
        for _ in 0..target {
            assert!(cpu.step(&mut mem).unwrap().is_none());
        }
        let secs = start.elapsed().as_secs_f64().max(1e-9);
        let mips = target as f64 / secs / 1e6;
        println!("interpreter: {:.2} MIPS ({} steps)", mips, target);
        assert_eq!(cpu.t.gpr[3], (target / 2) as u32);
    }

    /// Bridge throughput over a 4K-word guest command buffer.
    #[test]
    fn bridge_throughput_kwords() {
        use std::time::Instant;
        use x360_gpu::bridge::{execute_buffer, HARNESS_CLEAR_COLOR_REG};
        let mut mem = Memory::new();
        let addr = 0x74000u32;
        // 2048 Type0 packets, 1 value each: header + color word.
        for i in 0..2048u32 {
            let header = HARNESS_CLEAR_COLOR_REG / 4;
            mem.write_u32(addr + i * 8, header).unwrap();
            mem.write_u32(addr + i * 8 + 4, 0x1122_3344).unwrap();
        }
        let mut gpu = x360_gpu::Xenos::new();
        let start = Instant::now();
        let stats = execute_buffer(&mut gpu, &mem, addr, 4096).unwrap();
        let secs = start.elapsed().as_secs_f64().max(1e-9);
        println!(
            "bridge: {:.0} Kwords/s ({} packets)",
            4096.0 / secs / 1e3,
            stats.packets
        );
        assert_eq!(stats.packets, 2048);
        assert_eq!(stats.pending_type3, 0);
    }

    /// Full games-track pipeline on a retail package: STFS list →
    /// extract XEX → header parse → decompress → PE sections covering
    /// the entry point. Gated on `$X360_STFS_FILE`. Package bytes stay
    /// out of git.
    #[test]
    fn retail_game_pipeline() {
        use x360_filesystem::stfs::StfsImage;
        let path = match std::env::var("X360_STFS_FILE") {
            Ok(p) => p,
            Err(_) => return,
        };
        let bytes = std::fs::read(&path).expect("read package");
        let stfs = StfsImage::open(&bytes).expect("open package");
        let files = stfs.list_files().expect("list package");
        let xex = files
            .iter()
            .find(|f| !f.is_dir && f.name.to_lowercase().ends_with(".xex"))
            .expect("no .xex in package");
        println!("game xex: {} ({} bytes)", xex.name, xex.length);
        let data = stfs.read_file(xex).expect("extract xex");
        let (hdr, info) = x360_loader::parse_xex(&data).expect("game header parses");
        let image =
            x360_loader::image::loadable_image(&data, &hdr, &info).expect("game decompresses");
        let sections = x360_loader::image::parse_pe_sections(&image).expect("game PE parses");
        println!(
            "entry={:08x} base={:08x} title={:?} sections={} imports={}",
            info.entry_point.unwrap_or(0),
            info.base_address,
            info.title_id.map(|t| format!("{:08x}", t)),
            sections.len(),
            info.import_libs
                .iter()
                .map(|l| l.import_count as usize)
                .sum::<usize>(),
        );
        assert!(!sections.is_empty());
        if let Some(entry) = info.entry_point {
            let rel = entry.wrapping_sub(info.base_address);
            assert!(
                sections.iter().any(|s| (s.virt_addr as usize) < image.len()
                    && rel >= s.virt_addr
                    && rel < s.virt_addr + s.virt_size.max(1)),
                "game entry not covered"
            );
        }
    }
}
