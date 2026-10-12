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
| Type0 state | partial | Register file applied and tested |
| Draw/state/texture/RT packets | unsupported | Type3 dispatch returns pending-M5, draws stays 0 |
| Shader translate | unsupported | Hash + cache tracked, explicit UnimplementedShader |
| eDRAM tile/resolve | not-started | |
| Validation triangle | not-started | M5 milestone, not a substitute |

## Loader / Kernel

| Area | Status | Notes |
|---|---|---|
| XEX2 header/directory parse | partial | Magic + bounds + entry validation, OOB dir entries rejected; tests |
| Relocations/imports/TLS | not-started | Explicitly not parsed yet |
| Threads/events/mutexes/sems | partial | create_thread/event/set/wait with queued waiters; blocking wait pending M6 |
| Syscalls | unsupported | Table returns UnimplementedSyscall except id 0 (time); convention r0=id |
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
| Custom lobby | not-started | Endpoint configurable; health check explicit Unsupported when empty; no server claims |
| Official Live compat | unsupported | Not claimed, not attempted |

## Frontend / Debugger

| Area | Status | Notes |
|---|---|---|
| Library launch + per-game config | partial | scan_library reads real FS; identify errors surfaced per-entry; labels state untested/playable explicitly |
| Step execution | partial | Steps all 6 threads; syscall errors propagated to log/status; r0=id convention |
| Debugger disasm/regs/mem/breakpoints | partial | Backed by real CPU state; shown in UI (disasm@pc, regs, GPU stats) |
| Compat indicators | partial | Labels say loads/not-verified; see matrix, no playable claims |
