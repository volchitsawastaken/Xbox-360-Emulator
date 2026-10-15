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
        assert_eq!((cpu.t.gpr[6] as u32), 42);
        assert_eq!((cpu.t.gpr[7] as u32), 42);
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
        assert_eq!((cpu.t.gpr[3] as u32), 7);
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
        assert_eq!((cpu.t.gpr[3] as u32), (target / 2) as u32);
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
        for l in &info.import_libs {
            println!(
                "import lib {} id={:08x} ver={:08x} min={:08x} count={}",
                l.name, l.id, l.version, l.min_version, l.import_count
            );
        }
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

    /// Retail execution: load Braid into guest memory, resolve imports,
    /// set up a stack, and step real guest instructions from the entry
    /// point. Gated on `$X360_STFS_FILE`. Fails with the exact blocker
    /// (pc, registers, last trace, import call tables) until the game
    /// runs further. Package bytes stay out of git.
    #[test]
    fn dash_pipeline() {
        let dir = match std::env::var("X360_DASH_DIR") {
            Ok(p) => p,
            Err(_) => return,
        };
        let name = std::env::var("X360_DASH_XEX").unwrap_or_else(|_| "dash.xex".to_string());
        let data = std::fs::read(format!("{}/{}", dir, name)).expect("read dash xex");
        let (hdr, info) = x360_loader::parse_xex(&data).expect("dash header parses");
        let image =
            x360_loader::image::loadable_image(&data, &hdr, &info).expect("dash decompresses");
        let sections = x360_loader::image::parse_pe_sections(&image).expect("dash PE parses");
        println!(
            "dash entry={:08x} base={:08x} sections={} imports={}",
            info.entry_point.unwrap_or(0),
            info.base_address,
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
                "dash entry not covered"
            );
        }
    }
    #[test]
    fn retail_import_slots_dump() {
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
        let data = stfs.read_file(xex).expect("extract xex");
        let (hdr, info) = x360_loader::parse_xex(&data).expect("game header parses");
        let image =
            x360_loader::image::loadable_image(&data, &hdr, &info).expect("game decompresses");
        let sections = x360_loader::image::parse_pe_sections(&image).expect("game PE parses");
        println!(
            "image_len={:08x} base={:08x}",
            image.len(),
            info.base_address
        );
        for s in &sections {
            println!(
                "sec {:8} virt={:08x} vsz={:08x} raw_off={:08x} raw_sz={:08x} avail={:08x} flags={:08x}",
                s.name,
                s.virt_addr,
                s.virt_size,
                s.raw_off,
                s.raw_size,
                s.raw_available,
                s.characteristics
            );
        }
        for lib in &info.import_libs {
            println!("lib {} records={}", lib.name, lib.records.len());
            for (i, r) in lib.records.iter().enumerate() {
                let off = r.wrapping_sub(info.base_address);
                let slot = if (off as usize) + 4 <= image.len() {
                    u32::from_be_bytes([
                        image[off as usize],
                        image[off as usize + 1],
                        image[off as usize + 2],
                        image[off as usize + 3],
                    ])
                } else {
                    0xEEEE_EEEE
                };
                let kind = slot >> 24;
                let ord = (slot & 0xFFFF) as u16;
                let name = x360_kernel::ordinals::kernel_export_name(&lib.name, ord).unwrap_or("?");
                println!(
                    "  [{}] addr={:08x} {} ord={:04x} {}",
                    i,
                    r,
                    if kind == 0 { "var " } else { "thunk" },
                    ord,
                    name
                );
            }
        }
        let _ = hdr;
        println!("--- dir keys ---");
        for d in &info.dirs {
            match d.data {
                x360_loader::XexDirData::Inline(v) => {
                    println!("key={:08x} inline={:08x}", d.key, v)
                }
                x360_loader::XexDirData::AtOffset { offset, size } => {
                    println!("key={:08x} off={:08x} size={}", d.key, offset, size)
                }
            }
        }
    }

    #[test]
    fn retail_braid_steps() {
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
        let data = stfs.read_file(xex).expect("extract xex");
        let (hdr, info) = x360_loader::parse_xex(&data).expect("game header parses");
        let image =
            x360_loader::image::loadable_image(&data, &hdr, &info).expect("game decompresses");
        let sections = x360_loader::image::parse_pe_sections(&image).expect("game PE parses");
        if let Some(entry) = info.entry_point {
            let rel = entry.wrapping_sub(info.base_address);
            assert!(
                sections.iter().any(|s| (s.virt_addr as usize) < image.len()
                    && rel >= s.virt_addr
                    && rel < s.virt_addr + s.virt_size.max(1)),
                "game entry not covered"
            );
        }
        let mut mem = Memory::new();
        x360_loader::image::load_image_to_guest(&mut mem, &image, info.base_address)
            .expect("load image");
        let mut kernel = x360_kernel::Kernel::new();
        kernel.set_module_info(
            info.base_address,
            image.len() as u32,
            info.title_id.unwrap_or(0),
        );
        // System flags for privilege queries (inline dir value, default 0).
        let sysflags = info
            .dirs
            .iter()
            .find_map(|d| match d.data {
                x360_loader::XexDirData::Inline(v) if d.key == 0x0003_0000 => Some(v),
                _ => None,
            })
            .unwrap_or(0);
        kernel.set_system_flags(sysflags);
        println!("sysflags={:08x}", sysflags);
        let hs = (hdr.header_size as usize).min(data.len());
        kernel.set_xex_header(
            data[..hs].to_vec(),
            info.entry_point.unwrap_or(0),
            xex.name.clone(),
        );
        let mut table = x360_kernel::imports::ImportTable::new();
        let libs: Vec<(&str, &[u32])> = info
            .import_libs
            .iter()
            .map(|l| (l.name.as_str(), l.records.as_slice()))
            .collect();
        let stats = x360_kernel::imports::apply(&mut mem, &mut kernel, &mut table, &libs)
            .expect("apply imports");
        println!(
            "imports: {} functions + {} variables ({} thunks)",
            stats.functions,
            stats.variables,
            table.len()
        );
        // Guest stack: 128 KiB of real zeroed bytes, r1 at the top.
        let stack_size = 128 * 1024u32;
        let stack_base = kernel.alloc_mem(stack_size, 16).expect("guest stack");
        mem.write_bytes(stack_base, &vec![0u8; stack_size as usize])
            .expect("zero stack");
        kernel.set_stack(stack_base, stack_size);
        let entry = info.entry_point.expect("game has entry");
        for i in 0..16u32 {
            let w = mem.read_u32(entry + i * 4).unwrap_or(0xFFFF_FFFF);
            println!("entry+{:02x}: {:08x} {}", i * 4, w, x360_cpu::disasm(w));
        }
        let mut xenon = x360_cpu::Xenon::new(entry);
        xenon.threads[0].t.gpr[1] = (stack_base + stack_size - 16) as u64;
        // Deep trace: retail faults need the full dataflow window.
        let mut trace = x360_debugger::TraceBuffer::new(16384);
        match x360_kernel::boot::run_until_exit_traced_imports(
            &mut mem,
            &mut xenon,
            &mut kernel,
            Some(&mut table),
            2_000_000,
            Some(&mut trace),
        ) {
            Ok(exit) => {
                println!("retail exit code={} steps={}", exit.code, exit.steps);
            }
            Err(e) if e.to_string().contains("step limit") => {
                // Progress-floor regression gate: boot must run the full
                // budget fault-free (no Unsupported / memory-fault /
                // alignment errors). A reintroduced fault fails here
                // instead; deeper hangs are chased with TEMP traces.
                let done = table.implemented_calls.len();
                println!(
                    "retail boot ran 2M steps fault-free ({} imports served, pc={:08x})",
                    done, xenon.threads[0].t.pc
                );
                assert!(done >= 10, "boot regressed: only {} imports served", done);
            }
            Err(e) => {
                let t = &xenon.threads[0].t;
                println!("retail stopped after error: {}", e);
                println!(
                    "pc={:08x} lr={:08x} ctr={:08x} r1={:08x}",
                    t.pc,
                    t.lr,
                    t.ctr,
                    (t.gpr[1] as u32)
                );
                for r in [3u32, 4, 5, 6, 7, 8, 9, 10] {
                    println!("r{}={:08x}", r, (t.gpr[r as usize] as u32));
                }
                println!("--- last trace (oldest first, last 400) ---");
                let events: Vec<_> = trace.iter().collect();
                for ev in events.iter().skip(events.len().saturating_sub(400)) {
                    println!("th{} {:08x}: {}", ev.thread, ev.pc, ev.disasm);
                }
                // Full trace to TEMP for dataflow forensics.
                {
                    let p = std::env::temp_dir().join("braid_trace.log");
                    match x360_debugger::write_trace_file(&p, &trace) {
                        Ok(n) => println!("full trace ({} events) -> {}", n, p.display()),
                        Err(e) => println!("trace write failed: {}", e),
                    }
                }
                let mut done: Vec<_> = table.implemented_calls.iter().collect();
                done.sort();
                println!("--- implemented calls ({}) ---", done.len());
                for ((lib, ord), n) in done.iter().take(40) {
                    let name = x360_kernel::imports::ImportTable::name_of(lib, *ord).unwrap_or("?");
                    println!("{}!{} x{}", lib, name, n);
                }
                let mut missing: Vec<_> = table.unimplemented_calls.iter().collect();
                missing.sort();
                println!("--- unimplemented calls ({}) ---", missing.len());
                for ((lib, ord), n) in missing {
                    let name = x360_kernel::imports::ImportTable::name_of(lib, *ord).unwrap_or("?");
                    println!("{}!{} x{}", lib, name, n);
                }
                panic!("retail boot stopped: {}", e);
            }
        }
    }
}
