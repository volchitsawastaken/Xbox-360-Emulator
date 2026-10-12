# Compatibility Matrix

Statuses: `verified` (tested, evidence), `partial` (some paths work),
`unsupported` (explicit error), `not-started`.

## CPU (Xenon PPC)

| Area | Status | Notes |
|---|---|---|
| Integer ALU (addi, addis, ori, oris, xori, andi, extsh/extsb, shifts) | partial | Covered by unit vectors; OE/OV/SO honored for add/subf |
| Branches (b, bc, bclr + LK) | partial | CR/BI/BO honored, LK writes LR; bcctr does not decrement CTR |
| bcctr | partial | Target from CTR, no decrement; tested |
| Loads/stores (lwz/stw/lbz/stb/lhz/sth/lmw/stmw/multiple) | partial | Alignment + bounds checked; EXEC required for fetch |
| CR/XER/LR/CTR moves (mfcr/mtcr, mflr/mtlr, mfctr/mtctr, mfxer) | partial | LR/CTR only; other SPRs explicit Unsupported |
| lwarx/stwcx. reservations | partial | Single-thread correct + CR EQ; SMP invalidation pending |
| sync/lwsync/isync/eieio | partial | Barriers as scheduler fences for now |
| VMX128 vector ops | unsupported | Tracked per-opcode, required for retail |
| FP unit | unsupported | Tracked |
| Exceptions (DSI/ISI/program/sc) | partial | Fault codes surfaced; sc traps with r0=syscall id convention |
| 6-thread scheduling | partial | Xenon round-robin wired in frontend; priorities pending M6 |

## GPU (Xenos)

| Area | Status | Notes |
|---|---|---|
| Packet decode (type0/2/3) | partial | Real ringbuffer copy via decode_packet; header-only reports truncation; type1 errors |
| Type0 state | partial | Register file applied and tested, including from guest RAM via bridge |
| Command bridge (guest RAM → dispatch) | partial | `execute_buffer` reads PM4 from guest memory; Type3 counted/skipped with stats; tested |
| Host clear from guest state | partial | Harness clear-color reg → `render_clear` readback; convention labeled, hardware mapping pending |
| Draw/state/texture/RT packets | unsupported | Type3 dispatch returns pending-M5, draws stays 0 |
| Shader translate | unsupported | Hash + cache tracked, explicit UnimplementedShader |
| eDRAM tile/resolve | not-started | |
| Validation triangle | partial | Headless wgpu offscreen render + readback (`Xenos::validate_triangle`), tested; not Xenos translation |

## Loader / Kernel

| Area | Status | Notes |
|---|---|---|
| XEX2 header/directory parse | partial | Real XEX1/XEX2 model: 8-byte entries, inline (low byte 00/01) vs offset data, entry/base/stack/title keys, security load address; OOB rejected; tests |
| Relocations/imports/TLS | not-started | Directory slices validated; semantic interpretation pending |
| Threads/events/mutexes/sems | partial | create_thread/event/set/wait with queued waiters; blocking wait pending M6 |
| Syscalls | partial | 0=time, 2=putc console tested; others explicit UnimplementedSyscall; 1=exit handled by boot runner |
| Boot | partial | Demo guest (putc "HI" + exit 0) verified end-to-end via `run_until_exit`; retail boot not-started |
| ISO/GDFX/STFS/extracted dir | partial | identify + default.xex resolve; ISO/STFS payload parsing not-started |

## Audio

| Area | Status | Notes |
|---|---|---|
| XMA decode | unsupported | Explicit error |
| Output | partial | Null sink works and tested; host returns explicit Unsupported (cpal not wired) |

## Network

| Area | Status | Notes |
|---|---|---|
| XSocket UDP bridge | partial | Loopback send/recv tested |
| System Link discovery | partial | UDP beacon send/recv tested between two instances on loopback; broadcast + NAT pending M8 |
| Custom lobby | partial | Endpoint configurable; health check explicit Unsupported when empty; no server claims |
| Official Live compat | unsupported | Not claimed, not attempted |

## Frontend / Debugger

| Area | Status | Notes |
|---|---|---|
| Library launch + per-game config | partial | scan_library reads real FS; identify errors surfaced per-entry; labels state untested/playable explicitly |
| Step execution | partial | Steps all 6 threads; syscall errors propagated to log/status; r0=id convention |
| Boot loading screen | partial | Staged parse→map→gpu→run with progress + per-stage detail, all stages real; failures shown with dismiss |
| Debugger disasm/regs/mem/breakpoints | partial | Backed by real CPU state; shown in UI (disasm@pc, regs, GPU stats) |
| Compat indicators | partial | Labels say loads/not-verified; see matrix, no playable claims |
