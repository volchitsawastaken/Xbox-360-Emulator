# x360-rs Technical Design (Milestone 1)

## 1. References

- IBM Xenon: 3 PowerPC cores, 6 hardware threads, 3.2 GHz, in-order with
  SMT, VMX128 vector extension (128 registers of 128-bit, distinct from
  Altivec VMX), time-base, reservations (`lwarx/stwcx.`), `sync/lwsync`,
  `isync`, hypervisor privileged ops.
- PowerPC ISA: PowerPC User Instruction Set Architecture Book I/II
  (integer, branch, load/store, CR/XER handling, exceptions:
  ISI, DSI, ISI, program, FP unavailable, decrementer, system call).
- ATI Xenos: unified shader array, command ringbuffer (PM4-style packets),
  draw packets, state packets, texture fetch, render targets, depth/stencil,
  10 MB eDRAM tile + resolve to DRAM, predicated tiling.
- XEX2 format: header magic `XEX2`, header directory entries
  (security info, resource info, base reference, entry point,
  import libraries), PE-like sections, Base Relocations, TLS, entry point.
- ISO: GDFX/XDVDFS for 360 discs. STFS packages for DLC/XBLA.
- Prior work studied: Xenia (BSD) — PPC recompiler, Xenos Vulkan/D3D12
  translation, XAM HLE, XNet bridging to BSD sockets, Canary Netplay fork
  for System Link tunneling. This project does not reuse Xenia code;
  architecture notes only. Format data ported with attribution:
  XEX directory keys/model from `xex2_info.h`, PM4 Type-3 opcode table
  from `xenos.h` (`gpu/src/pm4.rs`). Reference clone lives outside this
  repo and is never compiled in.

## 2. Dependency assessment

| Area | Candidate | License | Verdict |
|---|---|---|---|
| Host GPU | wgpu | MIT/Apache-2.0 | Selected. Vulkan/DX12/Metal abstraction, Windows-first. |
| GUI | eframe/egui vs tauri vs iced | MIT/Apache-2.0 | eframe/egui for M2-M7 (single binary, native, debugger views). Revisit if docking/layout limits hit. |
| Async net | tokio | MIT | Selected for lobby client + UDP discovery. |
| Logging | log + env_logger | MIT/Apache-2.0 | Selected. |
| Errors | thiserror | MIT/Apache-2.0 | Selected. |
| Config | serde + serde_json + toml | MIT/Apache-2.0 | Selected. |
| Audio out | cpal | Apache-2.0 | Selected, null backend default until XMA path validated. |
| JIT (later) | dynasm-rs vs cranelift | MIT/Apache-2.0 | Deferred to M9. Interpreter trait designed JIT-ready. dynasm-rs favored for manual PPC backend; cranelift favored for maintenance. No commitment until profiling. |
| PPC test suites | ppc-tests style, custom decode/exec vectors | various (test-only) | Custom vectors in `cpu`, differential checks vs trusted decoders where available. |

Licensing: workspace BSD-3-Clause. All deps MIT/Apache-2.0 compatible.
No GPL dependencies. `cargo deny` to be added at M10.

## 3. Module boundaries

```
common <- memory <- cpu <- kernel <- frontend
common <- memory <- loader <- kernel
common <- memory <- gpu <- frontend
common <- audio <- kernel
common <- filesystem <- kernel <- frontend
common <- network <- frontend
common <- cpu/memory/kernel/gpu <- debugger <- frontend
```

One-directional. No cycles. Each crate owns its state and exposes
explicit traits. `unsafe` only in memory access fast paths and host
GPU/audio interop, documented per site.

## 4. CPU plan

- Fetch/decode/execute loop per hardware thread.
- Decoder returns `Decoded` enum; unknown opcodes -> `Unsupported`.
- Registers: 32 GPR, LR, CTR, CR (8x4-bit fields), XER (SO/OV/CA),
  MSR subset, PC, TB, 32 VMX128 VR + VSCR.
- Reservations per thread for `lwarx/stwcx.`.
- Scheduler: cooperative round-robin over 6 threads in M4, preemptive
  quanta + priorities in M6.
- JIT-ready: `CpuBackend` trait (`step`, `run_quanta`,
  `translate_block` deferred). Interpreter implements it now.

## 5. GPU plan

- Stages: ringbuffer reader -> packet decoder -> state tracker ->
  resource manager -> wgpu encoder -> present.
- Packet types 0/1/2/3 with explicit unsupported logging including
  packet word and offset.
- Shader translation: parse guest microcode header, hash, cache,
  translate ALU/fetch to WGSL/NAGA IR incrementally. Untranslatable
  -> `UnsupportedShader` with hash + first bytes, never silent.
- eDRAM: tile metadata + resolve pass, validated by render-target tests.

## 6. Kernel/loader plan

- Loader validates `XEX2` magic, directory, security info, entry point;
  never claims boot from load alone.
- Kernel provides threads, events, semaphores, mutexes, virtual memory
  map, file handles, syscalls via numbered table returning
  `UnimplementedSyscall(id)` until done.
- Homebrew `.xex` first, retail expansion only with dumps and tests.

## 7. Network plan

- `xnet`: socket abstraction over UDP/TCP, System Link discovery
  (UDP broadcast 3074) between instances on LAN.
- Lobby client: configurable HTTP endpoint, session create/join/list,
  presence. No official service claims.
- Identity: locally generated player ID stored in config. No console
  certificates, no credential reuse, no hardcoded secrets.
- Diagnostics: session/discovery/join/disconnect/transport/packet logs.

## 8. Milestone acceptance

- M2: `cargo build` + `cargo test` clean on Windows, CI green.
- M3: PPC decode/exec vectors pass, unsupported tracked.
- M4: memory + loader + scheduler run a test guest entry.
- M5: command pipeline decodes packets, triangle validation only.
- M6-M10 per spec doc. Nothing marked done without evidence.
