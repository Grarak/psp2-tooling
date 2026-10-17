// psp2prof: a whole-system CPU profiler for a DevKit with taiHEN (tested on firmware 3.65).
//
// A kernel thread on core 3 reads every core's program counter from the outside, through each
// Cortex-A9's CoreSight debug block (DBGPCSR), so a core with its interrupts masked is sampled
// too. Each sample carries the thread and process the core runs (SceKernelThreadMgr's per-CPU
// blocks) and, while that thread is in a syscall, the syscall number and the user PC and LR
// the SVC handler saved: the user code that called into the kernel.
//
// The sampler runs on core 3, so core 3's samples are the sampler itself: the default mask is
// cores 0-2.
//
// Loaded once a boot (the PSP2PROF0 app, loader.c), it polls host0:psp2prof/request. A request is one line,
// "seconds=S hz=H cores=MASK name=NAME" (profile/psp2prof.py writes it); the capture streams to
// host0:psp2prof/NAME.part, renamed to NAME.p2pf once complete. profile/perf_data.py turns it
// into perf.data.
//
// Capture file, little endian: "P2PF", version 1, hz, core mask, DBGAUTHSTATUS, 3 reserved
// words; then records of a 4-byte tag, a u32 size and the payload padded to 4 bytes:
//   SMPL  samples (Sample below), in the order the cores were read
//   DROP  u32: samples lost to a full ring
//   THRD  u32 thid, u32 pid, char name[32]: each thread the samples name
//   MODL  u32 pid, u32 vaddr, u32 memsz, u32 perms | segment << 8, char name[28]: the segments
//         of the kernel's modules (pid 0x10005) and of each sampled process's
//   STAK  (with stack=BYTES) Snapshot below, then its stack bytes: a core caught in user mode
//   SDRP  u32: snapshots lost to a full ring, then those not taken: the core in a privileged
//         mode, in Debug state already or powered down, its halt or a debug step timing out
//   END   u32 0
//
// Stacks (stack=BYTES in the request, off by default): stackhz times a second (stackcores, cores
// by default) the sampler halts the core through its debug block (DBGDRCR.HRQ; invasive debug,
// DBGAUTHSTATUS), reads r0-r15 and CPSR through the instruction transfer register, and in user
// mode copies BYTES from SP with the halted core's own loads (LDC to the DCC; each page's first
// word in normal mode, the rest in fast mode), so the copy sees the memory map that core runs
// with and stops at the first page it cannot read. Then r0 goes back and the core restarts.
// DBGDSCR's halting and monitor enables are left as they are (a halt request needs neither), and
// the software lock is put back after the capture. A copy that faults stops there: in user mode
// the DFSR and DFAR it sets belong to no exception in progress.

#include <psp2kern/io/dirent.h>
#include <psp2kern/io/fcntl.h>
#include <psp2kern/kernel/debug.h>
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/threadmgr.h>
#include <stdint.h>
#include <taihen.h>

extern int module_get_export_func(SceUID pid, const char *modname, uint32_t libnid,
                                  uint32_t funcnid, uintptr_t *func);
extern int module_get_offset(SceUID pid, SceUID modid, int segidx, size_t offset,
                             uintptr_t *addr);

#define KERNEL_PID 0x10005
#define CPU_AFFINITY(n) (0x10000 << (n))
#define DIR "host0:/psp2prof/"

// The four debug blocks, 0x2000 apart from 0xE3310000 (the PMU in the page after each).
// DBGPCSR reads a recent PC of its core: the instruction's address plus 8 in ARM state and
// plus 4 in Thumb state (bit 0 set); 0xFFFFFFFF when the core cannot be sampled. Reading needs
// no unlock and writes nothing.
#define DBG_PA 0xE3310000u
#define DBG_SIZE 0x8000u
#define DBGPCSR 0x084u
#define DBGAUTHSTATUS 0xFB8u

// SceKernelThreadMgr's per-CPU blocks: the first word of its data segment points at cpuCB[0],
// the four 0x880 bytes apart. +0x00 is the running thread's object, +0x14 and +0x18 its pid and
// thid, +0x34 the core's idle thread (checked to recognise the block).
#define CPUCB_STRIDE 0x880u
#define CPUCB_THREAD 0x00u
#define CPUCB_PID 0x14u
#define CPUCB_THID 0x18u
#define CPUCB_IDLE 0x34u

// While a thread is in a syscall, its object's +0x44 points at the frame the SVC handler saved
// on its kernel stack (0 again on the way out): user r12, the syscall number, at +0x30, the user
// LR and PC at +0x54 and +0x58. The words change under the sampler, so every address is
// translated before it is read and a number past the table's 0x1000 entries is dropped.
#define THREAD_SVC_FRAME 0x44u
#define FRAME_R12 0x30u
#define FRAME_LR 0x54u
#define FRAME_PC 0x58u
#define FRAME_SIZE 0x60u
#define SVC_FLAG 0x80000000u

// The debug registers used for stacks (ARMv7 debug, memory-mapped view).
#define DBGDTRRX 0x080u
#define DBGITR 0x084u // written; the same offset reads DBGPCSR
#define DBGDSCR 0x088u
#define DBGDTRTX 0x08Cu
#define DBGDRCR 0x090u
#define DBGOSLSR 0x304u
#define DBGPRSR 0x314u
#define DBGLAR 0xFB0u
#define DBGLSR 0xFB4u
#define DSCR_HALTED (1u << 0)
#define DSCR_RESTARTED (1u << 1)
#define DSCR_STICKY (7u << 6) // SDABORT_l, ADABORT_l, UND_l
#define DSCR_ITREN (1u << 13)
#define DSCR_DCC_MODE (3u << 20)
#define DSCR_DCC_FAST (2u << 20)
#define DSCR_INSTR_COMPL (1u << 24)
#define DSCR_TXFULL (1u << 29)
#define DSCR_WRITABLE (DSCR_DCC_MODE | 0xFC00u) // ExtDCCmode, MDBGen, HDBGen, ITRen, UDCCdis, INTdis, DBGack
#define DRCR_HALT 1u
#define DRCR_RESTART 2u
#define DRCR_CLEAR_STICKY 4u
// ARM encodings, executed through DBGITR in Debug state.
#define MCR_DTRTX(rt) (0xEE000E15u | (rt) << 12) // mcr p14, 0, rt, c0, c5, 0
#define MRC_DTRRX(rt) (0xEE100E15u | (rt) << 12) // mrc p14, 0, rt, c0, c5, 0
#define MOV_R0_PC 0xE1A0000Fu
#define MRS_R0_CPSR 0xE10F0000u
#define LDC_R0_POST4 0xECB05E01u // ldc p14, c5, [r0], #4
#define STACK_MAX 16384u
#define STACK_RING 64u

typedef struct Snapshot {
    uint32_t time; // ksceKernelGetSystemTimeLow, microseconds
    uint32_t thid, pid, cpu;
    uint32_t regs[16]; // r15: the instruction the core stopped at
    uint32_t cpsr;
    uint32_t size; // stack bytes that follow (the copy stops at a fault)
} Snapshot;

typedef struct Sample {
    uint32_t time;    // ksceKernelGetSystemTimeLow, microseconds
    uint32_t pc;
    uint32_t thid;
    uint32_t pid;
    uint32_t cpu;     // core | read sequence << 2
    uint32_t svc;     // SVC_FLAG | the syscall number, or 0
    uint32_t user_pc; // the user PC after the svc instruction
    uint32_t user_lr;
} Sample;

#define RING 65536u   // samples, 2 MiB
#define CHUNK 1024u   // samples a SMPL record
#define MAX_THREADS 2048u
#define MAX_PIDS 64u

static volatile const uint8_t *cpucb;
static SceUID dbg_uid = -1, ring_uid = -1;
static volatile uint32_t *dbg;
static Sample *ring;
static volatile uint32_t head, tail, dropped, sampling, unloading;
static uint32_t period_us, core_mask;
static uint32_t stack_bytes, stack_every, stack_mask, stack_relock;
static SceUID stack_uid = -1;
static uint8_t *stack_ring; // STACK_RING slots of a Snapshot and STACK_MAX bytes
static volatile uint32_t stack_head, stack_tail, stack_dropped;
static volatile uint32_t stack_kernel, stack_busy, stack_no_halt, stack_no_step;
#define STACK_SLOT (sizeof(Snapshot) + STACK_MAX)
static SceUID sampler_thid = -1, last_sampler = -1, control_thid = -1;
static Sample chunk[CHUNK];
static uint32_t threads[MAX_THREADS]; // open addressing, 0 empty
static uint32_t pids[MAX_PIDS], npids;

// Whether this core's MMU maps va for a privileged read (ATS1CPR, PAR bit 0 the fault), with
// interrupts off so nothing else uses PAR between the two.
static int mapped(uint32_t va) {
    uint32_t cpsr, par;
    asm volatile("mrs %0, cpsr\n\tcpsid i" : "=r"(cpsr)::"memory");
    asm volatile("mcr p15, 0, %1, c7, c8, 0\n\tisb\n\tmrc p15, 0, %0, c7, c4, 0"
                 : "=r"(par)
                 : "r"(va)
                 : "memory");
    asm volatile("msr cpsr_c, %0" ::"r"(cpsr) : "memory");
    return !(par & 1u);
}

static void syscall_frame(uint32_t cpu, Sample *s) {
    s->svc = s->user_pc = s->user_lr = 0;
    const uint32_t thread = *(volatile const uint32_t *)(cpucb + cpu * CPUCB_STRIDE + CPUCB_THREAD);
    if (!thread || !mapped(thread + THREAD_SVC_FRAME)) {
        return;
    }
    const uint32_t frame = *(volatile const uint32_t *)(uintptr_t)(thread + THREAD_SVC_FRAME);
    if (!frame || (frame & 3u) || !mapped(frame) || !mapped(frame + FRAME_SIZE - 4)) {
        return;
    }
    const volatile uint32_t *f = (const volatile uint32_t *)(uintptr_t)frame;
    const uint32_t number = f[FRAME_R12 / 4];
    if (number >= 0x1000u) {
        return;
    }
    s->user_lr = f[FRAME_LR / 4];
    s->user_pc = f[FRAME_PC / 4];
    s->svc = SVC_FLAG | number;
}

// Debug state through core `cpu`'s debug block: each step polls a bounded number of times, and a
// step that never completes gives up (the core is restarted all the same).
#define POLLS 100000u
static int wait_dscr(volatile uint32_t *d, uint32_t bit) {
    for (uint32_t i = 0; i < POLLS; i++) {
        if (d[DBGDSCR / 4] & bit) {
            return 0;
        }
    }
    return -1;
}

static int exec(volatile uint32_t *d, uint32_t insn) {
    d[DBGITR / 4] = insn;
    return wait_dscr(d, DSCR_INSTR_COMPL);
}

static int read_reg(volatile uint32_t *d, uint32_t rt, uint32_t *value) {
    if (exec(d, MCR_DTRTX(rt)) < 0 || wait_dscr(d, DSCR_TXFULL) < 0) {
        return -1;
    }
    *value = d[DBGDTRTX / 4];
    return 0;
}

// Halts `cpu`, and in user mode takes its registers and stack into the next ring slot; restarts
// it in any case. Interrupts stay off on this core meanwhile, so the halt lasts the copy only.
static void snapshot(uint32_t cpu, uint32_t now, uint32_t thid, uint32_t pid) {
    volatile uint32_t *const d = dbg + cpu * 0x2000u / 4;
    const uint32_t h = stack_head;
    if (h - stack_tail >= STACK_RING) {
        stack_dropped++;
        return;
    }
    const uint32_t dscr0 = d[DBGDSCR / 4];
    if (dscr0 & DSCR_HALTED || !(d[DBGPRSR / 4] & 1u)) {
        stack_busy++; // in Debug state already (someone else's), or powered down
        return;
    }
    uint32_t irq;
    asm volatile("mrs %0, cpsr\n\tcpsid i" : "=r"(irq)::"memory");
    Snapshot *const s = (Snapshot *)(stack_ring + (h & (STACK_RING - 1)) * STACK_SLOT);
    uint32_t *const words = (uint32_t *)(s + 1);
    int ok = 0;
    d[DBGDRCR / 4] = DRCR_HALT;
    if (wait_dscr(d, DSCR_HALTED) == 0) {
        const uint32_t base = d[DBGDSCR / 4] & DSCR_WRITABLE & ~DSCR_DCC_MODE;
        d[DBGDSCR / 4] = base | DSCR_ITREN;
        uint32_t r0 = 0, cpsr = 0, pc = 0;
        const int have_r0 = read_reg(d, 0, &r0) == 0;
        const int have_cpsr = have_r0 && exec(d, MRS_R0_CPSR) == 0 && read_reg(d, 0, &cpsr) == 0;
        ok = have_cpsr && (cpsr & 0x1Fu) == 0x10u;
        if (have_cpsr && !ok) {
            stack_kernel++;
        }
        for (uint32_t r = 1; ok && r < 15; r++) {
            ok = read_reg(d, r, &s->regs[r]) == 0;
        }
        // PC reads as the resume address plus 8 in ARM state, plus 4 in Thumb.
        ok = ok && exec(d, MOV_R0_PC) == 0 && read_reg(d, 0, &pc) == 0;
        if (!ok && (!have_cpsr || (cpsr & 0x1Fu) == 0x10u)) {
            stack_no_step++;
        }
        s->size = 0;
        if (ok) {
            s->regs[0] = r0;
            s->regs[15] = pc - (cpsr & 0x20u ? 4u : 8u);
            s->cpsr = cpsr;
            // r0 = SP, then page by page: the page's first word with one LDC in Normal mode, its
            // sticky abort flags checked before anything else is read, so that a page the core
            // cannot read ends the copy there. A DBGDTRTX read in Fast mode after an aborted LDC
            // took the reading core down with an external abort (a stack shallower than BYTES,
            // copied past its top into an unmapped page: a kernel DABT on core 3). The rest of a
            // readable page goes in Fast mode: the LDC is latched in DBGITR, and each DBGDTRTX read
            // returns what the DCC holds and issues it again, the first read the word before
            // (dropped); the page's last word is read in Normal mode, which issues nothing.
            uint32_t n = 0;
            const uint32_t want = stack_bytes / 4;
            uint32_t addr = s->regs[13] & ~3u;
            d[DBGDTRRX / 4] = addr;
            if (exec(d, MRC_DTRRX(0)) == 0) {
                while (n < want) {
                    d[DBGDSCR / 4] = base | DSCR_ITREN;
                    if (exec(d, LDC_R0_POST4) < 0 || d[DBGDSCR / 4] & DSCR_STICKY ||
                        wait_dscr(d, DSCR_TXFULL) < 0) {
                        break;
                    }
                    words[n++] = d[DBGDTRTX / 4];
                    addr += 4;
                    // Words left in this page (none past its end: the next is probed first).
                    uint32_t left = addr & 0xFFFu ? (0x1000u - (addr & 0xFFFu)) / 4u : 0;
                    if (left > want - n) {
                        left = want - n;
                    }
                    if (left == 0) {
                        continue;
                    }
                    d[DBGDSCR / 4] = base | DSCR_ITREN | DSCR_DCC_FAST;
                    d[DBGITR / 4] = LDC_R0_POST4;
                    (void)d[DBGDTRTX / 4];
                    for (uint32_t k = 1; k < left; k++) {
                        words[n++] = d[DBGDTRTX / 4];
                    }
                    d[DBGDSCR / 4] = base | DSCR_ITREN;
                    if (wait_dscr(d, DSCR_TXFULL) < 0) {
                        break;
                    }
                    words[n++] = d[DBGDTRTX / 4];
                    addr += left * 4u;
                    if (d[DBGDSCR / 4] & DSCR_STICKY) {
                        n -= left; // a page read in part: none of it
                        break;
                    }
                }
                wait_dscr(d, DSCR_INSTR_COMPL);
            }
            s->size = n * 4;
        }
        // The sticky aborts cleared first (DBGITR is ignored while one is set), r0 back, then
        // Debug state left.
        d[DBGDRCR / 4] = DRCR_CLEAR_STICKY;
        if (have_r0) {
            d[DBGDTRRX / 4] = r0;
            exec(d, MRC_DTRRX(0));
        }
        d[DBGDSCR / 4] = base;
        d[DBGDRCR / 4] = DRCR_CLEAR_STICKY | DRCR_RESTART;
        wait_dscr(d, DSCR_RESTARTED);
    } else {
        stack_no_halt++;
    }
    asm volatile("msr cpsr_c, %0" ::"r"(irq) : "memory");
    if (ok) {
        s->time = now;
        s->thid = thid;
        s->pid = pid;
        s->cpu = cpu;
        asm volatile("dmb" ::: "memory");
        stack_head = h + 1;
    }
}

static int sampler(SceSize args, void *argp) {
    (void)args;
    (void)argp;
    uint32_t seq = 0;
    while (sampling) {
        const uint32_t now = ksceKernelGetSystemTimeLow();
        for (uint32_t cpu = 0; cpu < 4; cpu++) {
            if (!(core_mask & (1u << cpu))) {
                continue;
            }
            const uint32_t h = head;
            if (h - tail >= RING) {
                dropped++;
                continue;
            }
            Sample *s = &ring[h & (RING - 1)];
            const volatile uint8_t *cb = cpucb + cpu * CPUCB_STRIDE;
            s->time = now;
            s->pc = dbg[(cpu * 0x2000u + DBGPCSR) / 4];
            s->thid = *(volatile const uint32_t *)(cb + CPUCB_THID);
            s->pid = *(volatile const uint32_t *)(cb + CPUCB_PID);
            s->cpu = cpu | seq << 2;
            if (s->pc != 0xFFFFFFFFu) {
                syscall_frame(cpu, s);
            } else {
                s->svc = s->user_pc = s->user_lr = 0;
            }
            asm volatile("dmb" ::: "memory");
            head = h + 1;
            if (stack_bytes && stack_mask & (1u << cpu) && seq % stack_every == 0) {
                snapshot(cpu, now, s->thid, s->pid);
            }
        }
        seq++;
        ksceKernelDelayThread(period_us);
    }
    return 0;
}

// cpuCB[0], or NULL when the block does not look like one (another firmware): four idle
// threads, each its own and in kernel memory.
static volatile const uint8_t *find_cpucb(void) {
    tai_module_info_t tai = {.size = sizeof(tai)};
    uintptr_t data = 0;
    if (taiGetModuleInfoForKernel(KERNEL_PID, "SceKernelThreadMgr", &tai) < 0 ||
        module_get_offset(KERNEL_PID, tai.modid, 1, 0, &data) < 0 || !data) {
        return NULL;
    }
    const uint8_t *priv = *(const uint8_t *const *)data;
    if (!priv) {
        return NULL;
    }
    uint32_t idle[4];
    for (uint32_t cpu = 0; cpu < 4; cpu++) {
        idle[cpu] = *(const uint32_t *)(priv + cpu * CPUCB_STRIDE + CPUCB_IDLE);
        if (idle[cpu] < 0x00100000u || idle[cpu] >= 0x40000000u) {
            return NULL;
        }
        for (uint32_t k = 0; k < cpu; k++) {
            if (idle[k] == idle[cpu]) {
                return NULL;
            }
        }
    }
    return priv;
}

static void stop_sampler(void) {
    if (sampler_thid >= 0) {
        sampling = 0;
        ksceKernelWaitThreadEnd(sampler_thid, NULL, NULL);
        ksceKernelDeleteThread(sampler_thid);
        sampler_thid = -1;
    }
    // The software locks the capture opened, closed again (any value but the key locks).
    for (uint32_t cpu = 0; cpu < 4; cpu++) {
        if (stack_relock & (1u << cpu)) {
            dbg[(cpu * 0x2000u + DBGLAR) / 4] = 0;
        }
    }
    stack_relock = 0;
}

// Stacks on the cores in `mask` that allow them: powered, not OS-locked (whoever set the OS lock
// owns the debug registers), the software lock opened for the capture. Returns those cores.
static uint32_t open_stacks(uint32_t mask) {
    uint32_t usable = 0;
    for (uint32_t cpu = 0; cpu < 4; cpu++) {
        if (!(mask & (1u << cpu))) {
            continue;
        }
        volatile uint32_t *const d = dbg + cpu * 0x2000u / 4;
        if (!(d[DBGPRSR / 4] & 1u) || d[DBGOSLSR / 4] & 2u) {
            ksceKernelPrintf("[psp2prof] cpu%u: no stacks (DBGPRSR %08X DBGOSLSR %08X)\n", cpu,
                             d[DBGPRSR / 4], d[DBGOSLSR / 4]);
            continue;
        }
        if (d[DBGLSR / 4] & 2u) {
            d[DBGLAR / 4] = 0xC5ACCE55u;
            stack_relock |= 1u << cpu;
        }
        usable |= 1u << cpu;
    }
    return usable;
}

static int start_sampler(uint32_t hz, uint32_t cores, uint32_t stack, uint32_t stack_hz,
                         uint32_t stack_cores) {
    if (!cpucb && !(cpucb = find_cpucb())) {
        ksceKernelPrintf("[psp2prof] SceKernelThreadMgr's per-CPU blocks not found (not 3.65?)\n");
        return -1;
    }
    if (dbg_uid < 0) {
        SceKernelAllocMemBlockKernelOpt opt = {0};
        opt.size = sizeof(opt);
        opt.attr = 2; // at the physical address given
        opt.paddr = DBG_PA;
        void *base = NULL;
        dbg_uid = ksceKernelAllocMemBlock("psp2prof_dbg", 0x20100206, DBG_SIZE, &opt);
        if (dbg_uid < 0 || ksceKernelGetMemBlockBase(dbg_uid, &base) < 0) {
            ksceKernelPrintf("[psp2prof] mapping the debug blocks failed: 0x%08X\n", dbg_uid);
            dbg_uid = -1;
            return -1;
        }
        dbg = base;
    }
    if (ring_uid < 0) {
        void *base = NULL;
        ring_uid = ksceKernelAllocMemBlock("psp2prof_ring", SCE_KERNEL_MEMBLOCK_TYPE_KERNEL_RW,
                                           RING * sizeof(Sample), NULL);
        // A retail kernel has about 2 MiB of KD free after boot (0x80024302 here): take
        // kernel RW from PhyCont instead, as the retail port of dtracep does.
        if (ring_uid < 0)
            ring_uid = ksceKernelAllocMemBlock("psp2prof_ring", 0x1080d006, RING * sizeof(Sample), NULL);
        if (ring_uid < 0 || ksceKernelGetMemBlockBase(ring_uid, &base) < 0) {
            ksceKernelPrintf("[psp2prof] the sample ring failed: 0x%08X\n", ring_uid);
            ring_uid = -1;
            return -1;
        }
        ring = base;
    }
    if (stack && stack_uid < 0) {
        void *base = NULL;
        stack_uid = ksceKernelAllocMemBlock("psp2prof_stacks", SCE_KERNEL_MEMBLOCK_TYPE_KERNEL_RW,
                                            (STACK_RING * STACK_SLOT + 0xFFFu) & ~0xFFFu, NULL);
        if (stack_uid < 0)
            stack_uid = ksceKernelAllocMemBlock("psp2prof_stacks", 0x1080d006,
                                                (STACK_RING * STACK_SLOT + 0xFFFu) & ~0xFFFu, NULL);
        if (stack_uid < 0 || ksceKernelGetMemBlockBase(stack_uid, &base) < 0) {
            ksceKernelPrintf("[psp2prof] the stack ring failed: 0x%08X\n", stack_uid);
            stack_uid = -1;
            return -1;
        }
        stack_ring = base;
    }
    head = tail = dropped = 0;
    stack_head = stack_tail = stack_dropped = 0;
    stack_kernel = stack_busy = stack_no_halt = stack_no_step = 0;
    period_us = 1000000u / hz;
    core_mask = cores;
    stack_bytes = stack;
    stack_every = stack ? (hz / stack_hz ? hz / stack_hz : 1u) : 1u;
    stack_mask = stack ? open_stacks(stack_cores) : 0;
    sampling = 1;
    sampler_thid = ksceKernelCreateThread("psp2prof_sampler", sampler, 0x10000100, 0x1000, 0,
                                          CPU_AFFINITY(3), NULL);
    last_sampler = sampler_thid; // named after it is gone (its own samples on core 3)
    if (sampler_thid < 0 || ksceKernelStartThread(sampler_thid, 0, NULL) < 0) {
        ksceKernelPrintf("[psp2prof] the sampler thread failed: 0x%08X\n", sampler_thid);
        sampler_thid = -1;
        return -1;
    }
    return (int)(dbg[DBGAUTHSTATUS / 4] & 0xFFu);
}

// The capture goes out in 64 KiB writes: each host0: write is a round trip over USB (about
// 0.1 s from the kernel, whatever its size).
static uint8_t out[64 * 1024];
static uint32_t out_len;
static int out_failed;

static void flush(SceUID fd) {
    if (out_len && !out_failed && ksceIoWrite(fd, out, out_len) != (int)out_len) {
        out_failed = 1;
    }
    out_len = 0;
}

static void emit(SceUID fd, const void *data, uint32_t size) {
    const uint8_t *p = data;
    while (size) {
        uint32_t n = sizeof(out) - out_len;
        n = n < size ? n : size;
        memcpy(out + out_len, p, n);
        out_len += n;
        p += n;
        size -= n;
        if (out_len == sizeof(out)) {
            flush(fd);
        }
    }
}

static int put(SceUID fd, const char tag[4], const void *data, uint32_t size) {
    static const uint32_t zero = 0;
    emit(fd, tag, 4);
    emit(fd, &size, 4);
    emit(fd, data, size);
    emit(fd, &zero, (4 - (size & 3u)) & 3u);
    return out_failed ? -1 : 0;
}

static void note_thread(uint32_t thid) {
    if (!thid) {
        return;
    }
    for (uint32_t i = (thid * 2654435761u) & (MAX_THREADS - 1);; i = (i + 1) & (MAX_THREADS - 1)) {
        if (threads[i] == thid) {
            return;
        }
        if (!threads[i]) {
            threads[i] = thid;
            return;
        }
    }
}

static void note_pid(uint32_t pid) {
    for (uint32_t i = 0; i < npids; i++) {
        if (pids[i] == pid) {
            return;
        }
    }
    if (npids < MAX_PIDS) {
        pids[npids++] = pid;
    }
}

// Moves the snapshots the sampler took into STAK records.
static int drain_stacks(SceUID fd, uint32_t *count) {
    while (stack_tail != stack_head) {
        const Snapshot *s = (const Snapshot *)(stack_ring + (stack_tail & (STACK_RING - 1)) * STACK_SLOT);
        static const uint32_t zero = 0;
        const uint32_t size = sizeof(Snapshot) + s->size;
        emit(fd, "STAK", 4);
        emit(fd, &size, 4);
        emit(fd, s, size);
        emit(fd, &zero, (4 - (size & 3u)) & 3u);
        note_thread(s->thid);
        note_pid(s->pid);
        stack_tail++;
        ++*count;
        if (out_failed) {
            return -1;
        }
    }
    return 0;
}

// Moves what the sampler left in the ring into SMPL records.
static int drain(SceUID fd, uint32_t *count) {
    static uint32_t filled;
    const uint32_t h = head;
    while (tail != h) {
        const Sample *s = &ring[tail & (RING - 1)];
        chunk[filled++] = *s;
        note_thread(s->thid);
        note_pid(s->pid);
        tail++;
        if (filled == CHUNK) {
            if (put(fd, "SMPL", chunk, sizeof(chunk)) < 0) {
                return -1;
            }
            *count += filled;
            filled = 0;
        }
    }
    if (!sampling && filled) {
        if (put(fd, "SMPL", chunk, filled * sizeof(Sample)) < 0) {
            return -1;
        }
        *count += filled;
        filled = 0;
    }
    return 0;
}

typedef int (*GetModuleList)(SceUID pid, int flags1, int flags2, SceUID *modids, SceSize *num);
typedef int (*GetModuleInfo)(SceUID pid, SceUID modid, SceKernelModuleInfo *info);

// SceModulemgrForKernel's GetModuleList and GetModuleInfo through taiHEN (3.63+ NIDs).
static void write_modules(SceUID fd, uint32_t pid) {
    uintptr_t list = 0, get = 0;
    if (module_get_export_func(KERNEL_PID, "SceKernelModulemgr", 0x92C9FFC2, 0xB72C75A4, &list) < 0 ||
        module_get_export_func(KERNEL_PID, "SceKernelModulemgr", 0x92C9FFC2, 0xDAA90093, &get) < 0) {
        return;
    }
    static SceUID modids[256];
    SceSize n = sizeof(modids) / sizeof(modids[0]);
    if (((GetModuleList)list)(pid, 0x7FFFFFFF, 1, modids, &n) < 0) {
        return;
    }
    for (SceSize m = 0; m < n; m++) {
        static SceKernelModuleInfo info;
        memset(&info, 0, sizeof(info));
        info.size = sizeof(info);
        if (((GetModuleInfo)get)(pid, modids[m], &info) < 0) {
            continue;
        }
        for (uint32_t seg = 0; seg < 4; seg++) {
            if (!info.segments[seg].memsz) {
                continue;
            }
            struct {
                uint32_t pid, vaddr, memsz, perms;
                char name[28];
            } rec;
            memset(&rec, 0, sizeof(rec));
            rec.pid = pid;
            rec.vaddr = (uint32_t)(uintptr_t)info.segments[seg].vaddr;
            rec.memsz = info.segments[seg].memsz;
            rec.perms = info.segments[seg].perms | seg << 8;
            memcpy(rec.name, info.module_name, sizeof(rec.name) - 1);
            put(fd, "MODL", &rec, sizeof(rec));
        }
    }
}

static void capture(uint32_t seconds, uint32_t hz, uint32_t cores, uint32_t stack,
                    uint32_t stack_hz, uint32_t stack_cores, const char *name) {
    char part[96], done[96];
    snprintf(part, sizeof(part), DIR "%s.part", name);
    snprintf(done, sizeof(done), DIR "%s.p2pf", name);
    const SceUID fd = ksceIoOpen(part, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0666);
    if (fd < 0) {
        ksceKernelPrintf("[psp2prof] %s: 0x%08X\n", part, fd);
        return;
    }
    memset(threads, 0, sizeof(threads));
    npids = 0;
    note_pid(KERNEL_PID);
    const int auth = start_sampler(hz, cores, stack, stack_hz, stack_cores);
    const uint32_t header[8] = {0x46503250, 1, hz, cores, (uint32_t)auth, 0, 0, 0}; // P2PF
    uint32_t count = 0, stacks = 0;
    out_len = 0;
    out_failed = 0;
    emit(fd, header, sizeof(header));
    int failed = auth < 0;
    const uint32_t start = ksceKernelGetSystemTimeLow();
    while (!failed && !unloading && ksceKernelGetSystemTimeLow() - start < seconds * 1000000u) {
        ksceKernelDelayThread(20000);
        failed = drain(fd, &count) < 0 || drain_stacks(fd, &stacks) < 0;
    }
    stop_sampler();
    failed = failed || drain(fd, &count) < 0 || drain_stacks(fd, &stacks) < 0;
    const uint32_t lost = dropped;
    put(fd, "DROP", &lost, sizeof(lost));
    if (stack) {
        const uint32_t sdrp[5] = {stack_dropped, stack_kernel, stack_busy, stack_no_halt,
                                  stack_no_step};
        put(fd, "SDRP", sdrp, sizeof(sdrp));
    }
    for (uint32_t i = 0; i < MAX_THREADS; i++) {
        if (!threads[i]) {
            continue;
        }
        SceKernelThreadInfo info;
        memset(&info, 0, sizeof(info));
        info.size = sizeof(info);
        struct {
            uint32_t thid, pid;
            char name[32];
        } rec;
        memset(&rec, 0, sizeof(rec));
        rec.thid = threads[i];
        if (ksceKernelGetThreadInfo(threads[i], &info) >= 0) {
            rec.pid = info.processId;
            memcpy(rec.name, info.name, sizeof(rec.name) - 1);
            note_pid(info.processId);
        } else if (threads[i] == (uint32_t)last_sampler) {
            rec.pid = KERNEL_PID;
            memcpy(rec.name, "psp2prof_sampler", sizeof("psp2prof_sampler"));
        }
        put(fd, "THRD", &rec, sizeof(rec));
    }
    for (uint32_t i = 0; i < npids; i++) {
        write_modules(fd, pids[i]);
    }
    const uint32_t zero = 0;
    put(fd, "END ", &zero, sizeof(zero));
    flush(fd);
    failed = failed || out_failed;
    ksceIoClose(fd);
    if (failed) {
        ksceKernelPrintf("[psp2prof] capture %s failed after %u samples\n", name, count);
        return;
    }
    ksceIoRename(part, done);
    ksceKernelPrintf("[psp2prof] %s: %u samples, %u dropped, %u processes\n", done, count, lost,
                     npids);
    if (stack) {
        ksceKernelPrintf("[psp2prof] %s: %u stacks, %u dropped; not taken: %u privileged, %u in "
                         "Debug state or powered down, %u halts and %u steps timed out\n",
                         done, stacks, stack_dropped, stack_kernel, stack_busy, stack_no_halt,
                         stack_no_step);
    }
}

static uint32_t number(const char *text) {
    uint32_t value = 0, base = 10;
    if (text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        base = 16;
        text += 2;
    }
    for (;; text++) {
        const char c = *text;
        const uint32_t digit = c >= '0' && c <= '9'   ? (uint32_t)(c - '0')
                               : c >= 'a' && c <= 'f' ? (uint32_t)(c - 'a' + 10)
                               : c >= 'A' && c <= 'F' ? (uint32_t)(c - 'A' + 10)
                                                      : 99;
        if (digit >= base) {
            return value;
        }
        value = value * base + digit;
    }
}

// "seconds=S hz=H cores=MASK name=NAME" (defaults 4, 1000, 0x7, capture), and for stacks
// "stack=BYTES stackhz=H stackcores=MASK" (defaults 0: none, 100, the cores); a name keeps
// [A-Za-z0-9._-] only.
static void request(char *text) {
    uint32_t seconds = 4, hz = 1000, cores = 0x7, stack = 0, stack_hz = 100, stack_cores = 0;
    char name[48] = "capture";
    for (char *p = text; *p;) {
        while (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t') {
            p++;
        }
        if (!strncmp(p, "seconds=", 8)) {
            seconds = number(p + 8);
        } else if (!strncmp(p, "hz=", 3)) {
            hz = number(p + 3);
        } else if (!strncmp(p, "cores=", 6)) {
            cores = number(p + 6);
        } else if (!strncmp(p, "stack=", 6)) {
            stack = number(p + 6);
        } else if (!strncmp(p, "stackhz=", 8)) {
            stack_hz = number(p + 8);
        } else if (!strncmp(p, "stackcores=", 11)) {
            stack_cores = number(p + 11);
        } else if (!strncmp(p, "name=", 5)) {
            uint32_t n = 0;
            for (const char *q = p + 5; *q && n < sizeof(name) - 1; q++) {
                const char c = *q;
                if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                      c == '.' || c == '_' || c == '-')) {
                    break;
                }
                name[n++] = c;
            }
            name[n] = 0;
        }
        while (*p && *p != ' ' && *p != '\n' && *p != '\r' && *p != '\t') {
            p++;
        }
    }
    stack_cores = stack_cores ? stack_cores : cores;
    if (!seconds || seconds > 600 || hz < 10 || hz > 10000 || !cores || cores > 0xF || !name[0] ||
        (stack && (stack < 64 || stack > STACK_MAX || stack % 256 || !stack_hz || stack_hz > hz ||
                   stack_cores & ~cores & 0xFu || stack_cores & 8u))) {
        ksceKernelPrintf("[psp2prof] refused: seconds 1..600, hz 10..10000, cores 0x1..0xF; stack "
                         "256..%u in 256s, stackhz 1..hz, stackcores within cores, not core 3\n",
                         STACK_MAX);
        return;
    }
    ksceKernelPrintf("[psp2prof] capturing %s: %u s at %u Hz, cores 0x%X\n", name, seconds, hz,
                     cores);
    if (stack) {
        ksceKernelPrintf("[psp2prof] with stacks: %u bytes at %u Hz, cores 0x%X\n", stack, stack_hz,
                         stack_cores);
    }
    capture(seconds, hz, cores, stack, stack_hz, stack_cores, name);
}

static int control(SceSize args, void *argp) {
    (void)args;
    (void)argp;
    {
        // Whether the kernel reaches host0: (deci4p_host.py serving it).
        const SceUID d = ksceIoDopen(DIR);
        ksceKernelPrintf("[psp2prof] ready: waiting for " DIR "request (open " DIR ": 0x%08X)\n", d);
        if (d >= 0) {
            ksceIoDclose(d);
        }
    }
    while (!unloading) {
        const SceUID fd = ksceIoOpen(DIR "request", SCE_O_RDONLY, 0);
        if (fd >= 0) {
            char text[160];
            const int n = ksceIoRead(fd, text, sizeof(text) - 1);
            ksceIoClose(fd);
            ksceIoRemove(DIR "request");
            text[n > 0 ? n : 0] = 0;
            request(text);
        }
        ksceKernelDelayThread(200000);
    }
    return 0;
}

int module_start(SceSize args, void *argp);
int _start(SceSize args, void *argp) __attribute__((weak, alias("module_start")));
int module_start(SceSize args, void *argp) {
    (void)args;
    (void)argp;
    control_thid = ksceKernelCreateThread("psp2prof_control", control, 0x10000100, 0x2000, 0,
                                          CPU_AFFINITY(3), NULL);
    if (control_thid < 0 || ksceKernelStartThread(control_thid, 0, NULL) < 0) {
        ksceKernelPrintf("[psp2prof] the control thread failed: 0x%08X\n", control_thid);
        return SCE_KERNEL_START_FAILED;
    }
    return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize args, void *argp) {
    (void)args;
    (void)argp;
    unloading = 1;
    if (control_thid >= 0) {
        ksceKernelWaitThreadEnd(control_thid, NULL, NULL);
        ksceKernelDeleteThread(control_thid);
    }
    stop_sampler();
    if (ring_uid >= 0) {
        ksceKernelFreeMemBlock(ring_uid);
    }
    if (stack_uid >= 0) {
        ksceKernelFreeMemBlock(stack_uid);
    }
    if (dbg_uid >= 0) {
        ksceKernelFreeMemBlock(dbg_uid);
    }
    return SCE_KERNEL_STOP_SUCCESS;
}
