# TODO board (x360-rs)

Statuses: done (verified), active (in progress), next (queued), later.
Terminal states only: impossible, done, or something rendering.

## Entire Xbox 360 emulation total: ~5 out of 100%

100% = running ANY game released for the Xbox 360. Honest breakdown:
- CPU interpreter (integer+FPU, no JIT) 40% · VMX128 integer + FP add/sub/max/min/mul/madd (compare/convert pending) · MMU/paging 0%
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
- [x] CPU VMX128 FP arithmetic, classic + 128-bit + fused subset
      (reference `ppc_emit_altivec.cc`): `vaddfp` (0x00A) /
      `vsubfp` (0x04A) / `vmaxfp` (0x40A) / `vminfp` (0x44A) +
      `vaddfp128` (0x14000010) / `vsubfp128` (0x14000050) /
      `vmulfp128` (0x14000090) + `vmaddfp` (0x2E) / `vnmsubfp`
      (0x2F, kVA fused `mul_add`), 4 x f32 lane ops in PPC byte
      order, 128-entry file incl. high regs; unit-tested;
      compare/convert FP stays tracked `Unsupported`
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
- [x] Retail `leave of unowned critical section 01030610` (worker
      contention, superseded): root-caused to main thread 0's token
      colliding with "free" (fixed by the critsec change below); the
      fault no longer occurs — subsequent runs fault elsewhere and
      both retail gates run fault-free to their floors. Closed.
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
      post-kick callbacks stay virgin. Deadlock refined further
      (wait-argument histogram over a full 2M-step boot): worker
      thread parks on `0x0104634C` with NULL timeout (353k
      rewind-retries); main polls `0x010462FC` with relative
      timeout `0xFFFB6C20` (~28ms, 9313 TIMEOUT spins). ZERO sets
      of either object anywhere (no KeSetEvent/Pulse, no semaphore
      posts, no timer fires). Static disassembly of the registered
      GPU callback `0x82181718`: branches on source==1, uses
      `KeAcquire/ReleaseSpinLockAtRaisedIrql` (currently
      unimplemented — needed when interrupts ever fire), compares
      against a game-local `0x0BADF00D` sentinel (distinct from the
      PM4 `0xBAADF00D` skip word); no KeSetEvent in its head,
      tails call into `0x821836B0`/`0x82192490` (untraced).
      Init method `0x82150248` disassembled around the fault: the
      `bctr` consumes `[r31+16]` with r3=0 (device-null call).
      Worker map (thread-creation probe + static disassembly):
      2x XAPI wrappers `0x82349E20` (exit, never wait) + 2x
      `0x8219E7B8` with ctx `0x010462DC`/`0x0104632C` — each waits
      its own ctx+0x20 event (`...62FC`/`...634C`) with a
      `0xFFFB6C20` (~28ms) timeout built on-stack. Worker1
      TIMEOUT-cycles through pure-compute callees
      (`0x82192C08`/`0x82192C10`, zero kernel calls) and never
      signals; worker2 parks on its FIRST wait because the
      timeout flows through uninitialized frame slot `[r1+80]`
      (stale 0 = infinite on a zeroed stack — an artifact, not
      the cause: even finite it would spin like worker1 since no
      event is ever set). Signal map exhausted everywhere except
      GPU completion: no KeSetEvent/Pulse, no semaphore posts,
      no timer fires, callback registered but sourceless.
      NEXT: spinlock shims (callback path), then the missing
      signal source (GPU completion for init packets vs D3D
      device state) — draw backend / device work continues to be
      the unblocker, now with the callback's requirements mapped
- [ ] Dash frontier (HostDirFs boot): walk starts ~1.16M steps in
      (past the 1M gate — the gate stays a progress floor, not the
      fault). Fully solved this session down to the mechanism:
      bound chain verified CORRECT instruction by instruction
      (`lwz r11,872(r31)` → `rlwinm ..,26,26` extracts flag bit5=0
      → `cntlzw`=32 → `rlwinm ..,27,31,31`=1 → `xoris …,1`
      (0x10001 — immediate is shifted, easy to mis-derive as 1) →
      `addic_` = 0x10002; the `or r24,r11,r11` dest convention
      confirmed empirically via register trace). Walk: r24=0x10002
      init, r27 cursor from r31+896 striding +8/iter, -1 slot
      marks at +416 stride (the "flag overwrite" is the walk's own
      marking, not an anomalous writer — table otherwise
      byte-identical to the static 148B copy, 36/37 words).
      Fault at iteration 6: slot word 0x5F300032 (version-string
      bytes "_0\02") read as an offset → r11=0x603400A2 wild →
      AlignmentFault on `[r11+896]`. Thread states at fault: th0
      in-walk, th1 parked pre-dispatch infinite KeWait (image obj),
      th2 mid-import-return, rest spare. No vectored-exception
      registrations (fault-tolerance theory ruled out); no
      KeSetEvent anywhere in dash either (thunk exists, never
      called). Root cause still open: identical static bytes must
      fault identically on hardware, so either the walk should
      never reach iteration 6 (early-exit evaluation differs?) or
      the slots should hold live pointers by walk time (a
      concurrent filler starved by scheduling?). Needs a
      memory-map answer for 0x603400A2 or hardware trace-diff.

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
- [x] VMX128 FP estimates `vrefp` (0x10A) / `vrsqrtefp` (0x14A):
      precise 4x f32 reciprocal/reciprocal-sqrt (ISA specifies
      estimates; precise exceeds the accuracy bounds — documented);
      unit-tested incl. 0→inf/inf→0 specials.
- [x] VMX128 FP compares (reference `InstrEmit_vcmpxxfp_`/`vcmpbfp_`
      + `UpdateCR6`): `vcmpeqfp`/`vcmpgefp`/`vcmpgtfp`/`vcmpbfp`
      (kVXR low-10 XOs + Rc bit 10), per-lane masks, NaN lanes 0,
      CR6 `all_equal|0|none_equal|0`; unit-tested incl. Rc paths.
      FP converts remain (no retail demand: zero VMX `Unsupported`
      in any run).
- [x] Draw-backend slicing (reference
      `pm4_command_processor_implement.h` + `xenos.h` `ShaderType`):
      `IM_LOAD_IMMEDIATE` (0x2B) stores sequencer ucode per type
      (vertex/pixel active-shader state, nonzero-start/bad-type
      explicit errors); `INVALIDATE_STATE` (0x3B) faithful no-op;
      `DRAW_INDX_2` (0x36) length-skips but COUNTS draws_seen (draw
      demand signal, never silent); unit-tested. Retail Braid uploads
      one shader in init (now stored); no draws issued pre-device.
- [ ] Draw backend remainder (shader translation + EDRAM tiling for
      patterned content — the substantial part; present path below
      covers solid-cleared surfaces end to end)
- [x] EDRAM clear/resolve state (reference `xenos.h` 10 MiB sizing):
      10 MiB backing, solid-32bpp clear (tiling-independent, exact),
      linear resolve to DRAM with explicit OOB errors; unit-tested.
      Patterned content needs detiling (pending).
- [x] Dash pipeline test (`dash_pipeline`, gated on `X360_DASH_DIR`):
      dash.xex parses/decompresses to 10 PE sections with entry
      `0x92196610` covered, 1628 imports — loader drift excluded for
      the table-walk frontier (fault is logic/data, not placement)
- [x] `VdSwap` present (reference `VdSwap_entry` + `MarkVblank` +
      `ExecutePacketType3_XE_SWAP`): validates all ten args (fetch
      header format/base/size, frontbuffer consistency, k_8_8_8_8 +
      RGB, dimensions within EDRAM), writes the 64-word ring sequence
      (Type0 fetch load + `XE_SWAP` + Type2 NOP fill), counts the
      present. Ring execution resolves solid-cleared EDRAM to the
      frontbuffer and queues vblank `(0, 2)` through the existing
      interrupt-delivery path; unit-tested end to end (ring write →
      execute → DRAM bytes + vblank). Patterned surfaces need
      detiling (pending). Retail Braid registers a vblank callback
      but never swaps; queue stays empty there.
- [x] `VdInitializeScalerCommandBuffer` (0x1C5) per reference
      (`VdInitializeScalerCommandBuffer_entry`, kImplemented): fills
      `dest_count` words with NOPs (`0x80000000`), returns the count;
      absurd counts explicit errors; unit-tested
- [x] `dash_boot_steps` progress floor (HostDirFs, 1M steps
      fault-free, 59 imports, zero unimplemented — permanent gate):
      locks the 63-import Dash init path below the table-walk fault
- [x] `XexGetProcedureAddress` (0x197, reference
      `XexGetProcedureAddress_entry`): ordinal form mints a real
      `sc; blr` thunk (deduped, heap-allocated, registered) so the
      game calls it through normal dispatch — this is Braid's D3D
      path (no static D3D imports; resolves `D3DDevice_*` at
      runtime). Unknown ordinals zero the out pointer +
      `ENTRYPOINT_NOT_FOUND` (0xC0000263); string form + executable
      self-lookup are explicit `Unsupported`. Unit-tested incl.
      thunk routing. `XexGetModuleSection` (0x196) validates handles
      (`INVALID_HANDLE`/`INVALID_PARAMETER`) and resolves the
      executable against the loader-parsed `RESOURCE_INFO` table
      (guest-VA addresses served as-is per `UserModule::GetSection`;
      retail Braid's single entry `584108CE -> 0x82AD0000` verified):
      hits return `SUCCESS`, misses `NOT_FOUND`, system modules
      `UNSUCCESSFUL` (reference base-class behavior). Boot setups
      plumb `info.resources`; unit-tested incl. served values.
- [x] Shader-ucode structural validation (`kernel::ucode`,
      reference `ucode.h` unpack + `AnalyzeUcode` bound +
      translator clause slots): CF unpack, exec extents, census.
      Deliberately first-exec-sequential (NOT the reference
      min-over-all: clause triples like `[0xC8..,0,0xE2..]`
      decode as `exec@0` and collapse the reference heuristic —
      observed on retail Braid uploads). `IM_LOAD` validates
      log-only (storage unconditional); retail Braid vs24/ps9
      validate clean (vs: 3 CF pairs, 4 execs, 2 allocs; ps:
      1 pair, exec_end, colors alloc). Unit-tested synthetic.
- [x] CF disassembler (`kernel::ucode::disassemble_cf`):
      one line per CF instruction with reference mnemonics
      (`exec`/`exece`, `cexec`/`cexece` + bool, `(p0)` predicated,
      `loop`/`endloop`, `call`, `ret`, `jmp`, `alloc`
      position/interpolators/colors/export, `cnop`; control
      opcodes beyond exec/alloc print raw words). Exact-output
      unit tests on synthetic vs/ps shapes.
- [x] ALU clause decode (`kernel::ucode`, reference `ucode.h`
      `AluInstruction::Data` LSB0 layout): vector/scalar opcodes
      with exact disassembly names (50+30, incl. the
      `opcode_NN` placeholders), dests, write masks, export bit,
      per-source reg/sel/swizzle/negate with `r#`/`c#`
      resolution. One-line disassembly. Exact-output unit tests.
      Clamp/predication accessors with exact reference tokens
      (`_sat`, `(p0)`/`(!p0)`) in the line; swizzles, export
      routing, and NOP collapsing pending translation work.
- [x] Fetch clause decode + full shader listing
      (`kernel::ucode`, reference `FetchInstruction::Data` LSB0
      layout): opcode/src/dst/const-index/dimension, exact
      family names (`vfetch`, `tfetch{1D,2D,3D,Cube}`,
      `getBCF*`, `getCompTexLOD*`, `getGradients`, `getWeights*`,
      `setTexLOD`, `setGradientH/V`). `disassemble_shader` walks
      exec sequence bits (ALU vs fetch + serialize marker) and
      lists every covered clause slot. Exact-output unit tests.
- [x] Spinlocks (`KfAcquireSpinLock` 0xB1 /
      `KeAcquireSpinLockAtRaisedIrql` 0x4D, `KfReleaseSpinLock`
      0xB4 / `KeReleaseSpinLockFromRaisedIrql` 0x89,
      `KeTryToAcquireSpinLockAtRaisedIrql` 0xAE): single-threaded
      IRQL tracking (0=PASSIVE, 2=DISPATCH; acquire returns old +
      raises, release restores, try always TRUE uncontended).
      Required by the registered GPU callback `0x82181718`
      (statically disassembled: source==1 branch uses
      acquire/release). Unit-tested incl. nesting.
- [x] Free-running vblank (reference `graphics_system.cc`
      frame-limiter worker + `MarkVblank`): real CRTCs raise
      vblank on display timing with no swap yet, and Xenia beats
      `(0, 2)` on a timer for the same reason. `pump_gpu` beats
      every 16ms wall-time once the ring exists and a callback is
      registered (counter bump + queued `(0, 2)` through the
      existing delivery path; single-threaded, no host threads).
      Retail Braid takes 94 verified deliveries per 2M-step boot
      (queue fully drained, callback registered) with no
      crash (delivery-path robustness proof) but does NOT advance:
      the callback's source-0 path doesn't touch the waited
      events (spinlocks live behind the source==1 branch, which
      needs genuine GPU completion the game never submits
      pre-device). Faithful subsystem, honest negative result.
- [x] ALU interpreter core (`kernel::uint`, reference
      `shader_interpreter.cc` `ExecuteAluInstruction`): 64 temps,
      previous-scalar, predicate; flush-denormal, bitwise
      abs/negate, swizzle select, OOB-const zeros; exact vector
      add/mul/max/min/seq/sgt/sge/sne/frc/trunc/floor/mad/dp4/
      dp3/dp2add (+D3D9 zero rule, NaN-keeping max) and scalar
      adds/muls/subs/retain_prev; NaN-becomes-+0 saturate;
      masked absolute writeback. Relative addressing, exports,
      and remaining ops are explicit `Unsupported`. Unit-tested
      incl. writeback, clamps, D3D9/NaN edges.
- [x] ALU transcendentals (`kernel::uint`, reference scalar arms):
      exact `ReduceFloatPrecision` (round-to-nearest, never to
      infinity, inf/NaN passthrough) under exp/logc/log/rcpc/
      rcpf/rcp/rsqc/rsqf/rsq/sqrt plus plain sin/cos, with the
      per-suffix -inf/+inf fixups (-MAX/MAX, -0/+0). Exact-output
      unit tests incl. a bit-level reduce case.
- [x] ALU const-reg scalar forms (`kernel::uint`, reference
      case-2 fetch): mulsc/addsc/subsc (both suffixes, identical
      eval) with the opcode-derived temp index, flushed + negated
      operands, `abs_constants` correctly ignored (dead in the
      reference interpreter too). Unit-tested.
- [x] ALU scalar compare/fraction batch (`kernel::uint`):
      maxs/mins (two-component, NaN-quiet), seqs/sgts/sges/
      snes, frcs/truncs/floors. Scalar ALU now complete (all
      defined opcodes; undefined ordinals stay `Unsupported`).
      Unit-tested.
- [x] ALU prev/setp/address ops (`kernel::uint`, reference arms):
      adds_prev/muls_prev/muls_prev2/subs_prev chaining `ps`,
      maxas/maxasf writing the address register (exact clamp+
      floor), setp_eq/ne/gt/ge/inv/pop/clr/rstr driving the
      predicate, kills_* setting `ps` only (kill unimplemented
      in the reference too). NaN-quiet comparison semantics kept
      explicit (`partial_cmp`-style, no negated comparisons).
      Unit-tested incl. chaining and address output.
- [x] ALU combinational remainder (`kernel::uint`, reference
      arms): cndEq/cndGe/cndGt select, cube-map coordinate/face
      select, max4 tournament, setp_eq/ne/gt/ge_push (predicate +
      counter), kill_eq/gt/ge/ne flags (result only, kill
      unimplemented like the reference), dst swizzle, maxA
      (address + max). NaN-quiet comparisons via an explicit
      `ge_quiet` helper. Unit-tested.
- [x] ALU predication skip (`kernel::uint::eval_alu`, reference
      per-instruction check): predicated-out ALU instructions skip
      entirely before fetch/eval; accessors on `AluInstr`.
      Unit-tested (skip + execute paths).
- [x] Kernel shims on demand: NO current demand — both retail gates
      (`retail_braid_steps` 2M, `dash_boot_steps` 1M) assert zero
      unimplemented imports; every called import is implemented.
      Reopens automatically on the next unimplemented-import fault.
- [x] Commit + push; update PORTING.md / COMPATIBILITY.md

## Later roadmap

- [ ] LZX decompression, GPU draw/state + shaders, FP exception/FPSCR control
- [ ] ISO/GDFX/SVOD, audio, input, frontend per-game config
- [ ] Broader unstubbed OS (background track)
- [ ] Fully done emulator OR last verified retail step
