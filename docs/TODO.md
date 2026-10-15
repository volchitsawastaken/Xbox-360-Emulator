# TODO board (x360-rs)

Statuses: done (verified), active (in progress), next (queued), later.
Terminal states only: impossible, done, or something rendering.

## Entire Xbox 360 emulation total: ~5 out of 100%

100% = running ANY game released for the Xbox 360. Honest breakdown:
- CPU interpreter (integer+FPU, no JIT) 40% · VMX128 integer done + FP classic (128-bit FP 0%) · MMU/paging 0%
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
      128-bit forms, `vperm`/`vperm128`/`vsel`
- [x] CPU VMX128 FP arithmetic, classic subset (reference
      `ppc_emit_altivec.cc` `InstrEmit_vaddfp_/vsubfp_/vmaxfp_/vminfp_`):
      `vaddfp` (0x00A) / `vsubfp` (0x04A) / `vmaxfp` (0x40A) /
      `vminfp` (0x44A), 4 x f32 lane ops in PPC byte order;
      unit-tested (add/sub/max/min incl. negatives); 128-bit FP
      (`vaddfp128`/`vsubfp128`/`vmulfp128`/madd/msum) stays tracked
      `Unsupported`
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
- [ ] Retail frontier (STFS-backed boot): scheduler is live — workers
      run and contend (new fault `leave of unowned critical section
      01030610` at `0x82558D18`, a worker executing leave without
      ownership). Still open: whether the imbalance is a divergent
      worker path (heap history now includes worker allocs) or a
      genuine game race; needs an enter/leave trace with thread ids
- [x] Critsec ownership vs thread 0 (found via worker contention):
      main's token 0 collided with "free", letting workers steal
      main-held sections; free is now (lock < 0) or pristine-zero
      (unit-tested); genuine contention blocks cooperatively
      (`EmuError::Blocked` rewind-and-retry in the boot loop) instead
      of fatal errors
- [x] Blocking waits: NULL (infinite) timeouts report `Blocked` for
      rewind-retry instead of bogus TIMEOUT (reference ABI);
      `KeWaitForSingleObject` (0xB0, pointer form) +
      `KeResetEvent` (0x8F, returns previous state) implemented and
      tested; `XamShowMessageBoxUI(Ex)` (0x2CA/0x2DC) mirrors
      reference headless (auto-pick focused button, logs UTF-16
      title/text — retail surfaces its fatal errors here)
- [ ] Retail frontier (STFS-backed boot, with workers live): back at
      the original `bctr` to `0x67735C65` (+16 stale) — worker
      starvation eliminated as a cause (workers run, signal, contend;
      KeWait succeeds via worker signaling). +120/+16 and the
      post-kick callbacks stay virgin: device creation needs the
      undelivered graphics-interrupt callback or adapter state the
      NOP pump doesn't produce. NOTE (verified by full method
      disasm): the lazy block formats on BOTH sides of its
      null-checks and stores +16 on NEITHER — so +16's writer is a
      function that never executes here at all (not a skipped store
      in executed code); the error path reading it is latently buggy
      code that only runs without a GPU. Workers sit idle-blocked in
      job-queue waits (empty queue — main never queues device work),
      so the queueing trigger itself is the missing link. NEXT: GPU
      interrupt-callback delivery (safe guest reentry), then draw
      backend
- [ ] Dash frontier (HostDirFs boot): 63 imports to a table walk at
      `0x921B86BC` (`lwz r8,896(r11)`), fully decoded this session:
      prologue sets r27=r31+896 (table = object itself +896),
      r24=bound from the `[r31+872]` flag word via cntlzw/xoris/addic
      (0x102A1101 -> 0x10002; the EQ-skip branch is dead — the walk
      always runs), r25=r31+40 expansion cursor (+416/iter). Each
      slot is read as a struct pointer (entry+r31, fields
      +872/+896/+900); zero/small entries are safe, slot 6 holds
      version-string bytes ("vs_3_0.2.0.9407.0" → r11=0x603400A2).
      The 148B header (flag+ints+version) is one faithful static
      memcpy (dst=obj+872, src=0x920376A8, len 0x94); the 1028B
      object comes from H (0x921B8740, called from E70 via
      0x92370E9C, backtraced) with static-derived size. The dash
      opens ZERO files (no NtCreateFile/NtOpenFile traffic at all),
      so the table is static+import driven; every link in the
      H→copy→walk chain is statically determined, yet the walk
      faults on static string bytes — same COUNT-vs-DATA class as
      Braid, root cause still open (needs trace-diff harness or a
      verified-good image hash to exclude loader/data drift)

## Next (retail-driven, in expected order)

- [x] Cooperative thread scheduler (reference `xthread.cc`,
      `ExCreateThread`): Xenon slots 1..=5 assigned at creation
      (`thread_id` = slot; exhaustion is an explicit SMP-cap error),
      spawn queue drained by the boot runner (r1 = stack top,
      r3 = context, LR 0), round-robin stepping honors suspend
      counts, worker return (PC/LR 0) marks clean exits; retail Braid
      workers now run and contend (see Active)
- [x] Trace harness as a real debugger feature (file sink for
      `TraceBuffer` + per-thread pcs + fault context): unblocks
      trace-diffing both table-walk frontiers without TEMP cycles
      (`TraceEvent.thread`, `render`/`write_trace_file`, boot wires
      slot ids, gate failure dump uses the sink)
- [x] GPU interrupt-callback delivery (reference
      `graphics_system.cc` `DispatchInterruptCallback` +
      `kernel_state.cc` `EmulateCPInterruptDPC` + `processor.cc`
      `Execute`: LR sentinel `0xBCBCBCBC`, stack pad 176B, args
      `r3=source, r4=user_data`): per-bit queue from INTERRUPT packets
      (`(source=1, cpu=bit)`), boot-runner hijack on thread 0 with full
      context save/restore (strictly safer than the reference's
      volatile clobber), Blocked-safe under round-robin, unregistered
      callbacks drain; unit-tested (delivery/restore, drain, per-bit
      queue). Retail Braid result: queue stays EMPTY (`delivered=0`) —
      its stream contains zero INTERRUPT packets, so this is not the
      missing queueing trigger (documented, not reverted: genuine OS
      feature)
- [x] Game-allocated sync events (found via Braid 4850x
      `KeWait`/`KeReset` storm on game-heap `X_KEVENT`s `0x010462FC` /
      `0x0104634C`): `KeInitializeEvent` (0x70), `KeSetEvent` (0x9D),
      `KePulseEvent` (0x7F) implemented per reference
      (`KeInitializeEvent_entry`/`xeKeSetEvent`); `KeWait`/`KeReset`/
      `KeSet`/`KePulse` resolve in-place headers first (type 0/1,
      signal 0/1, self-pointed wait list — zeroed memory never
      adopts, stays `INVALID_HANDLE`), then handle-backed objects;
      waits keep NULL-block semantics; unit-tested (roundtrip +
      adoption). Retail still faults at the same `bctr` (polls;
      signalers missing) — documented, not reverted
- [ ] Draw backend (next GPU step) OR VMX128 128-bit FP
      (`vaddfp128`/`vsubfp128`/`vmulfp128`/madd/msum) — pick by retail
      demand
- [ ] Kernel shims on demand (file data, content)
- [ ] Commit + push; update PORTING.md / COMPATIBILITY.md

## Later roadmap

- [ ] LZX decompression, GPU draw/state + shaders, FP exception/FPSCR control
- [ ] ISO/GDFX/SVOD, audio, input, frontend per-game config
- [ ] Broader unstubbed OS (background track)
- [ ] Fully done emulator OR last verified retail step
