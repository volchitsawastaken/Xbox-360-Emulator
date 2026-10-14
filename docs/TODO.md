# TODO board (x360-rs)

Statuses: done (verified), active (in progress), next (queued), later.
Terminal states only: impossible, done, or something rendering.

## Entire Xbox 360 emulation total: ~5 out of 100%

100% = running ANY game released for the Xbox 360. Honest breakdown:
- CPU interpreter (integer+FPU, no JIT) 40% · VMX128 0% · MMU/paging 0%
- Kernel (of ~300+ used imports across xboxkrnl/xam) ~15%
- GPU (shaders/eDRAM/draw path) 3% · audio 5% · input 0% · storage/saves 40%
- Scheduler 15% · networking 10% · frontend 35% · per-game compat work 2%
- One 2D XBLA title (Braid) booting into init; zero titles rendering

## Done (verified by tests and/or retail runs)

- [x] Workspace (12 crates), PPC interpreter core, 512MB mirrored memory
- [x] XEX1/XEX2 header model, Basic decompression, PE section parsing
- [x] STFS reader (CON/PIRS/LIVE, SHA1-verified); Braid GOD extracts
- [x] XEX AES-128-CBC decrypt (public retail key); Braid default.xex
      decrypts to valid PE (entry 8236ef38, 8 sections, 517 imports)
- [x] Import-record parsing + ordinal maps (922 xboxkrnl + 1741 xam)
- [x] Flat XEX placement, thunk rewrite, variable backing stores
- [x] Kernel heap/stack/TLS/critical-sections/module facts
- [x] 30+ export shims (memory, strings, TLS, time, privilege, AV pack,
      system version, title id)
- [x] CPU: 64-bit GPRs, ld/ldu/std/stdu, cache ops, addic., carry chain,
      word mul/div, integer logicals
- [x] X-form/D-form operand-order fix (RS in RT field, dest in RA;
      reference `ppc_decode_data.h` RS()=RT() + disassembler `[RA],[RS]`);
      `neg` word; retail memmove prologue executes
- [x] FPU: FPR file, lfs/lfsu/lfd/lfdu/stfs/stfsu/stfd/stfdu,
      FP ALU (add/sub/mul/div/madd/msub/nmadd/nmsub, mdc+single),
      fmr/fneg/fabs/fnabs/frsp/fctiw/fctiwz/fsqrt/fres/frsqrte/fsel,
      fcmpu/fcmpo, stfiwx/lfiwax
- [x] Retail boots from entry through startup into game code
      (first import call + AV/version/title-id queries pass)
- [x] Retail Braid runs 2M guest steps fault-free (10 kernel imports
      served: TLS/crits/2x NtAllocate/privilege/AV pack/header-field);
      progress-floor gate in `retail_braid_steps`
- [x] CPU: `mftb`, `fcfid`/`fctid`, 64-bit mul/div (`mulhd`/`divd`
      families), `td`/`tdi` traps, `rldic` mask fix (MASK(mb,~sh))
- [x] Heap base moved to 0x01000000 (reference/Xenon low-placement):
      walk-cycle terminates naturally, zero clamps; boot reaches 8M+
      steps into thread/net/sync init
- [x] `KeQueryPerformanceFrequency` returns frequency in r3 (reference
      returns it; game wrapper stores r3 over the slot)
- [x] NT sync objects with real guest backing structs: NtCreateEvent/
      Semaphore/Mutant/Timer, release/set/clear/pulse/wait-single/
      wait-multiple with reference NTSTATUS + guest mirroring
- [x] NT threads: ExCreateThread (real stacks + X_KTHREAD), resume/
      suspend/terminate/yield, Ke* ptr APIs (affinity/priority/boost),
      ObReference/ObLookupThreadByThreadId, XGetGameRegion (0x03FF),
      ExGetXConfigSetting (reference defaults table)
- [x] Retail Braid boots 8M steps fault-free into file I/O
      (`NtCreateFile` next): WSAStartup, semaphore, thread create +
      ObReference + affinity, game region, XConfig language served
- [x] File I/O shims on the read-only STFS backend: `NtCreateFile`/
      `NtOpenFile` (OBJECT_ATTRIBUTES + ANSI path normalize, disposition
      table, ACCESS_DENIED on write intents), `NtReadFile` (offset/pos
      windows, IOSB, PENDING for async opens, EOF), `NtClose`,
      `NtQueryInformationFile` (Internal/Position/NetworkOpen sizes);
      `StfsFs` lazy backend; gate now 2M steps fault-free, 26 imports
- [x] CPU indexed-dword family: `ldx`/`ldux`/`stdx`/`stdux`
      (XOs 21/53/149/181); FP A-form fix (real 5-bit XO, nonzero FRC
      decodes — retail `fmuls` word 0xEC200732); dword shifts
      (`sldx`/`srdx`/`sradx` + CA), `mfmsr`/`mtmsr`/`mtmsrd` (masked EE),
      `stfiwx` (983) / `lfiwax` (855) XO corrections
- [x] CPU 64-bit arithmetic family (reference `ppc_emit_alu.cc`:
      full-width GPR ops): `addi`/`addis`/`addic`/`addic.`/`subfic`/
      `mulli`/`add`/`subf`/`neg`/`addc`/`adde`/`addme`/`addze`/
      `subfc`/`subfe`/`subfme`/`subfze` with 64-bit CA/OV/CR0;
      plain `add`/`subf` no longer clobber CA; X-form logicals
      (`or`/`and`/`xor`/`nor`/`andc`/`orc`/`nand`/`eqv`) 64-bit;
      `extsh`/`extsb` sign-extend to 64 bits (D-form logicals,
      shifts, `cntlzw` unchanged — genuinely 32-bit)
- [x] Guest MMIO window per reference map: `0x7FC80000` (3.5MB real
      backing, game programs GPU ring registers there) + `0x7F000000`
      writeback/XPS window (12.5MB zeroed); EXEC denied in both
- [x] Kernel: KeEnter/LeaveCriticalRegion nesting, video-init batch
      (VdInitializeEngines, VdCallGraphicsNotificationRoutines=0,
      VdGetCurrentDisplayGamma TV+2.22222233, VdRetrainEDRAM(Worker)=0,
      VdIsHSIOTrainingSucceeded, VdSetDisplayMode, 1280x720 query,
      AsicID 0x11), MmGetPhysicalAddress, KiApcNormalRoutineNop,
      RtlNtStatusToDosError (reference table, PATH_NOT_FOUND->3)
- [x] CPU 64-bit compares (reference `ppc_emit_alu.cc`
      `InstrEmit_cmp/cmpi/cmpl/cmpli`): L=1 compares full GPRs
      (signed/unsigned; immediates sign/zero-extended); X-form L-bit
      fix (L is RT bit 0, was misread as bit 1); `sradix` (XO 826,
      XS form with SH5-masked match, sign-fill + CA)
- [x] CPU VMX128 integer subset (VR file widened to 128): `lvsl`/
      `lvsr` permute controls, `vspltisb`/`vspltish`/`vspltisw`,
      `vslb`, `vor`, `vspltb`, `lvx`/`stvx` + `lvlx`/`lvrx`/`stvlx`/
      `stvrx` (zero-fill/no-op edges per backend TBL notes) +
      `lvebx`/`lvehx`/`lvewx`/`stvebx`/`stvehx`/`stvewx` element ops +
      128-bit forms, `vperm`/`vperm128`/`vsel`; FP vector arithmetic
      still `Unsupported`
- [x] Filesystem `HostDirFs`: read-only host-directory backend
      (recursive index, lazy Arc cache, dir listings) for extracted
      layouts and system-update dirs; tested
- [x] Dash boot (HostDirFs over system-update dir): 63 imports served
      through locale/video/sync init — XMsgInProcessCall (LiveBase
      offline table), XamPackageManagerGetExperienceMode=1,
      XamUserFlushLogonQueue noop, XamGetLanguage=1 (English),
      XamGetLocale=36 (US), XamGetOnlineLanguageAndCountry (1/103),
      XamBackgroundDownload{SetMode, ...RegisterChangeCallback} noop,
      XamGetStagingMode=0, XamFitnessClearBodyProfileRecords noop,
      XamSetDashContext (+Get, broadcast 0x8000000C on change),
      XamLoader{Set,Get,GetSize}LaunchData (NOT_FOUND when empty),
      XdfInitialize noop, XamGetDashBackstackData (empty drain),
      XGetVideoMode (=VdQueryVideoMode), ExReadWriteLock family
      (guest-memory X_ERWLOCK: init/acquire/try/release, contended
      acquire explicit Unsupported), EtxProducerRegister noop,
      XUsbcamGetState=0 (not connected), XeCryptRandom (0xFD fill per
      reference), Fsc{Get,Set}CacheElementCount=0, ObCreateSymbolicLink
      (canonical table), KeInitializeDpc (XDPC layout), HalGetCurrentAVPack=8,
      VdSetStudioRGBMode (recorded); retail `sradix`/`vperm128`/
      `vperm` words execute (vector memcpy loops)

## Active

- [x] GPU ring bring-up (reference `command_processor.cc`,
      `graphics_system.cc`, `xenos.h`, `register_table.inc`): runner
      pumps CP_RB_WPTR kicks once per step; `VdInitializeRingBuffer`
      zeroes `1 << (size_log2 + 3)` bytes like the reference; PM4
      executor (`crates/kernel/src/gpu.rs`, unit-tested) runs ring +
      indirect-buffer packets with real CPU-visible effects
      (type-0/1 reg writes, REG_RMW/REG_TO_MEM, MEM_WRITE with
      `GpuSwap`, EVENT_WRITE_SHD/EXT, WAIT/COND single-shot checks,
      INTERRUPT recorded pending); draw/state packets length-skip
      (no draw backend yet); retail Braid kicks twice
      (`0x16`/`0x19`) and the stream executes clean (ME_INIT,
      register programming, nested IBs) — device field still NULL
- [ ] Retail frontier refined: Braid creates 4 worker threads
      RUNNABLE (`flags=0`: 2 job-queue `0x82349E20` + 2 `0x8219E7B8`)
      that our single-thread runner never steps (only thread 0
      executes; dispatch keeps kernel records only, no Xenon CPU
      threads). Workers are the likely fillers of the virgin
      completion slots (`+120` device, post-kick callbacks
      `[r26+21532]`/`[r26+23308]`) and the missing heap-history
      contributors. NEXT: cooperative round-robin scheduler —
      spawn Xenon threads at `start_addr` (r3 = context), step the
      ready set, honor suspend counts; then re-run and confirm the
      graphics-failure path is no longer taken
- [ ] Dash frontier (HostDirFs boot): 63 imports to an entry-table
      walk at `0x921B86BC` (`lwz r8,896(r11)`, r11=0x603400A2 from
      version-string bytes). Walk runs 65537 iterations by
      construction (r24=0x10002 from flag code, verified correct);
      table copies verified faithful (vector memcpy, coherent
      "vs_3_0.2.0.9407.0"); zero entries are safe, string bytes fault.
      Skip-fault run proves the walk is structurally lost (spins into
      wild space). Same shape as Braid: walk overruns valid entries
      into string data — shared COUNT-vs-DATA class. Still open:
      which bound/source differs (copy length vs walk count)

## Next (retail-driven, in expected order)

- [ ] Cooperative thread scheduler (spawn + round-robin + suspend
      counts); goal: Braid workers run, device gets created, no
      "Unable to initialize graphics" path
- [ ] GPU interrupt-callback delivery (safe guest reentry) once the
      scheduler exists; then draw backend
- [ ] VMX128 FP arithmetic (`vaddfp`, `vmulfp`, float permutes)
- [ ] Kernel shims on demand (file data, content)
- [ ] Commit + push; update PORTING.md / COMPATIBILITY.md

## Later roadmap

- [ ] LZX decompression, GPU draw/state + shaders, FP exception/FPSCR control
- [ ] ISO/GDFX/SVOD, audio, input, frontend per-game config
- [ ] Broader unstubbed OS (background track)
- [ ] Fully done emulator OR last verified retail step
