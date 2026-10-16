/* The host's words on TTYP7: power, reports, hardware breakpoints, file copies. */
#include "retail-cp.h"

/* One page of device registers at a physical address. */
static SceUID device_map(const char *name, uint32_t pa, volatile uint32_t **base)
{
    SceKernelAllocMemBlockKernelOpt opt;
    SceUID block;
    void *va = NULL;

    memset(&opt, 0, sizeof(opt));
    opt.size = sizeof(opt);
    opt.attr = 2; /* the physical address below, as pamgr maps its registers */
    opt.paddr = pa;
    block = ksceKernelAllocMemBlock(name, 0x20100806, 0x1000, &opt);
    if (block >= 0 && ksceKernelGetMemBlockBase(block, &va) < 0) {
        ksceKernelFreeMemBlock(block);
        return -1;
    }
    *base = va;
    return block;
}

/*
 * The "debugmem" word: each core's debug registers through its memory-mapped debug block
 * (0xE3310000 + core * 0x2000), so a core's CP14 state shows as the thread running there
 * left it, not as this thread's own switch reloaded it: DBGPCSR (a sample of its PC), DBGDSCR,
 * breakpoint pairs 2 and 5, watchpoint pair 1 (the process slots), and the lock and power status.
 */
#define DEBUG_BLOCK_PA 0xE3310000u
#define DEBUG_BLOCK_STRIDE 0x2000u

static int debug_memory_report(void)
{
    for (unsigned core = 0; core < 4; core++) {
        volatile uint32_t *debug;
        SceUID block = device_map("RetailCpDebug", DEBUG_BLOCK_PA + core * DEBUG_BLOCK_STRIDE, &debug);

        if (block < 0) {
            return block;
        }
        ksceKernelPrintf("[retail-cp] core %u pcsr 0x%08x dscr 0x%08x bp2 0x%08x/0x%x bp5 0x%08x/0x%x wp1 0x%08x/0x%x "
                         "lsr 0x%x prsr 0x%x\n",
                         core, debug[0x084 / 4], debug[0x088 / 4], debug[0x108 / 4], debug[0x148 / 4], debug[0x114 / 4],
                         debug[0x154 / 4], debug[0x184 / 4], debug[0x1c4 / 4], debug[0xfb4 / 4], debug[0x314 / 4]);
        ksceKernelFreeMemBlock(block);
    }
    return 0;
}

/*
 * Power control from the host. A DevKit's CP board can cut and restore power whatever the
 * Vita's state; retail has no such processor, so the nearest is asking Syscon from the
 * kernel. This thread reads lines from TTYP7, the last of ttyp's console ports (no process
 * writes there): deci4p_host.py's "power" command and devkit_console.py --retail send one as
 * TTYP input, which ttyp queues in the port's ring until a reader takes it.
 * Each line is one word:
 *   reset    Ernie (Syscon) cold reset, command 0x0801 sent as a raw packet: the SoC restarts
 *            as from power-on and nothing in the OS is asked (the power cycle; works while the
 *            shell or an app hangs). The same packet from a bare-metal payload cold-reset a
 *            physical DevKit.
 *   reboot   ScePower's cold reset: the OS shuts down cleanly first
 *   off      ScePower's standby request, the Vita's power-off: only the power button
 *            brings it back
 *   suspend  ScePower's suspend: in development mode the panel off with the system running
 *            (devmode_sleep)
 *   wake     the end of that sleep, as the power key
 *   qaf      apply the QA flag unlock (again, or when the boot skipped it after a hang)
 *   scratch  read the whole Syscon scratchpad into the report (read only)
 *   threads  every thread's state to the host's tty.log (threads_report; read only)
 *   memory   KD's free pages and largest block, and PhyCont's largest block, to the kernel
 *            console (memory_free)
 *   hwbp PID ADDRESS [CONTROL]  a hardware breakpoint in a process (hardware_breakpoint)
 *   hwwp PID ADDRESS [CONTROL]  a hardware watchpoint in a process
 *   copy SRC DST  one file, such as host0:/x to ur0:tai/x and back (file_copy)
 *   list DIR  a directory's entries to the kernel console (dir_list)
 *   debugmem  each core's live debug registers (debug_memory_report; read only)
 *   uninstall  development mode and hardware debug cleared in Ernie's block, then the Syscon
 *            reset into a retail boot; only once no config.txt loads retail-cp (uninstall)
 * Not ksceSysconSetPowerMode: it enters the SKBL's secure power routine on the calling core,
 * which then waits with interrupts masked while ScePower's shutdown waits for that core's
 * SGI acknowledgement, forever.
 * It needs the kernel and the USB link alive: a hang that stops those needs the power button
 * (a long hold forces Syscon off). Input sent before this thread reads it waits in ttyp's
 * ring; a reset clears it with everything else.
 */
#define POWER_TTY "tty7:"
#define POWER_RETRY_US (1000 * 1000)
#define SYSCON_COLD_RESET 0x0801

static SceUID power_thread = -1;

/*
 * The "threads" word: every thread's state, written to tty0: (the host's tty.log over TTYP),
 * so a hang that leaves the DECI4p link up can be read while it lasts (how DTRACEP_PMEP was
 * found). A line per thread: process, UID, name, status, priority, current and last core, wait
 * type, wait object and its name. For the kernel's SceDeci4p* threads, the words on the top
 * 8 KiB of the stack that point into dtracep's or ThreadMgr's text follow (d+offset, t+offset):
 * the live call chain is nearest the top. First a line with dtrace_send_fix's counters.
 */
const char *ksceGUIDName(SceUID guid);

static void module_text(const char *name, uintptr_t *start, uintptr_t *end)
{
    tai_module_info_t tai = {.size = sizeof(tai)};
    SceKernelModuleInfo module = {.size = sizeof(module)};

    *start = *end = 0;
    if (taiGetModuleInfoForKernel(KERNEL_PID, name, &tai) >= 0 &&
        ksceKernelGetModuleInfo(KERNEL_PID, tai.modid, &module) >= 0) {
        *start = (uintptr_t)module.segments[0].vaddr;
        *end = *start + module.segments[0].memsz;
    }
}

static int threads_report(void)
{
    static SceUID ids[512];
    static SceKernelThreadInfo info;
    static char line[512]; /* the longest, a stack line of 24 hits, is under 240 */
    uintptr_t dtrace_start, dtrace_end, threadmgr_start, threadmgr_end;
    int count = 0, length, result;
    SceUID tty = ksceIoOpen("tty0:", SCE_O_WRONLY, 0);

    if (tty < 0) {
        return tty;
    }
    module_text("SceDeci4pDtracep", &dtrace_start, &dtrace_end);
    module_text("SceKernelThreadMgr", &threadmgr_start, &threadmgr_end);
    length = snprintf(line, sizeof(line),
                      "[threads] dtracep %08x empty-sends %u packet-failures %u shell-ready %d dbgusb-wakes %u\n",
                      (unsigned)dtrace_start, (unsigned)dtrace_empty_sends, (unsigned)dtrace_packet_failures,
                      shell_ready, dbgusb_wakes);
    ksceIoWrite(tty, line, length);
    result = ksceKernelGetThreadIdList(0x10021, ids, sizeof(ids), &count);
    for (int index = 0; result >= 0 && index < count; index++) {
        const char *wait_name = NULL;

        memset(&info, 0, sizeof(info));
        info.size = sizeof(info);
        if (ksceKernelGetThreadInfo(ids[index], &info) < 0) {
            continue;
        }
        info.name[sizeof(info.name) - 1] = '\0';
        if (info.waitId > 0 && (info.waitId & 1)) {
            wait_name = ksceGUIDName(info.waitId);
        }
        length = snprintf(line, sizeof(line), "[threads] %05x %08x %-28s st %4x pr %3x cpu %2d/%d wt %5x wid %08x %.31s\n",
                          (unsigned)info.processId, (unsigned)ids[index], info.name, (unsigned)info.status, info.currentPriority,
                          info.currentCpuId, info.lastExecutedCpuId, (unsigned)info.waitType, (unsigned)info.waitId,
                          wait_name ? wait_name : "-");
        ksceIoWrite(tty, line, length);
        if (info.processId != KERNEL_PID || strncmp(info.name, "SceDeci4p", 9) || !info.stack ||
            info.stackSize <= 0) {
            continue;
        }
        const uint32_t *top = (const uint32_t *)((uintptr_t)info.stack + (unsigned)info.stackSize);
        const unsigned words = ((unsigned)info.stackSize < 0x2000 ? (unsigned)info.stackSize : 0x2000) / 4;
        unsigned hits = 0;

        length = snprintf(line, sizeof(line), "[threads]   stack");
        for (unsigned word = 1; word <= words && hits < 24; word++) {
            const uintptr_t value = top[-(int)word] & ~1u;

            if (value >= dtrace_start && value < dtrace_end) {
                length += snprintf(line + length, sizeof(line) - length, " d+%x", (unsigned)(value - dtrace_start));
                hits++;
            } else if (value >= threadmgr_start && value < threadmgr_end) {
                length += snprintf(line + length, sizeof(line) - length, " t+%x", (unsigned)(value - threadmgr_start));
                hits++;
            }
        }
        line[length++] = '\n';
        ksceIoWrite(tty, line, length);
    }
    ksceIoClose(tty);
    return result < 0 ? result : count;
}

/*
 * Hardware breakpoints and watchpoints as the debugger sets them. With switch 0xE4 ProcessMgr
 * gives every process two tables (3.65 processmgr 0x81002020: +0xc five DBGBVR/DBGBCR pairs, +0x10
 * four DBGWVR/DBGWCR pairs). Only some slots are per process: IntrMgr's return to a thread
 * (3.65 intrmgr 0x810007a4: thread +0x18 is its process) loads breakpoints 2-4 and watchpoints 1-3
 * from those tables, and pair 5 from the thread (+0x1c/+0x20); its kernel entry (0x81000404) loads
 * the same slots from the kernel's tables (intrmgr globals 0x81008240/4); ExcpMgr turns every
 * pair off while it handles an abort (0x810005a4...) and reloads them after (0x81001294).
 * Breakpoints 0-1 and watchpoint 0 are no process's: the setters take them, nothing loads them.
 * The setters check 0xE4:
 *   SceProcessmgrForKernel_597E6D2C(pid, slot 0-4, DBGBVR, DBGBCR): breakpoints (DBGP uses slot 2,
 *     0x4001e5: address mismatch in user mode, its single step)
 *   SceProcessmgrForKernel_B2421F93(pid, slot 0-3, DBGWVR, DBGWCR): watchpoints (DBGP slots 1-3,
 *     dbgp FUN_81007074: mask << 24 | BAS << 5 | load 8 | store 0x10 | 7)
 * A hit stops the thread for DBGP, which debug-suspends it (suspend status 0x800) when no
 * debugger has the process. Words, all hex, ADDRESS also MODULE+OFFSET into that module's text
 * in the process:
 *   "hwbp PID ADDRESS [CONTROL]"  breakpoint slot 2; CONTROL 0x1e5 by default (user mode only,
 *     so kernel code at the same address never traps), 0 clears
 *   "hwwp PID ADDRESS [CONTROL]"  watchpoint slot 1; CONTROL 0x1ff by default (4 bytes, load and
 *     store, any mode), 0 clears
 */
#define PROCESSMGR_SET_BREAKPOINT_NID 0x597e6d2c
#define PROCESSMGR_SET_WATCHPOINT_NID 0xb2421f93
#define HWBP_SLOT 2 /* the first of the process slots: IntrMgr loads breakpoints 2-4, watchpoints 1-3 */
#define HWWP_SLOT 1

static unsigned parse_hex(const char **text)
{
    unsigned value = 0;

    while (**text == ' ') {
        (*text)++;
    }
    if ((*text)[0] == '0' && ((*text)[1] | 0x20) == 'x') {
        *text += 2;
    }
    for (;; (*text)++) {
        const char c = **text | 0x20;

        if (**text >= '0' && **text <= '9') {
            value = value << 4 | (unsigned)(**text - '0');
        } else if (c >= 'a' && c <= 'f') {
            value = value << 4 | (unsigned)(c - 'a' + 10);
        } else {
            return value;
        }
    }
}

/* MODULE+OFFSET: OFFSET into the text of the process's module MODULE (retail executables load
 * at a slide), or 0 when the process has no such module. */
static unsigned module_address(SceUID pid, const char **text)
{
    char name[28];
    unsigned length = 0;
    SceUID modules[64];
    SceSize count = sizeof(modules) / sizeof(modules[0]);

    while (**text == ' ') {
        (*text)++;
    }
    while ((*text)[length] && (*text)[length] != '+' && (*text)[length] != ' ' && length < sizeof(name) - 1) {
        length++;
    }
    memcpy(name, *text, length);
    name[length] = '\0';
    *text += length + 1;
    const unsigned offset = parse_hex(text);

    if (ksceKernelGetModuleList(pid, 0x7fffffff, 1, modules, &count) < 0) {
        return 0;
    }
    for (unsigned i = 0; i < count; i++) {
        SceKernelModuleInfo info;

        memset(&info, 0, sizeof(info));
        info.size = sizeof(info);
        if (ksceKernelGetModuleInfo(pid, modules[i], &info) >= 0 && !strncmp(info.module_name, name, sizeof(info.module_name))) {
            return (unsigned)(uintptr_t)info.segments[0].vaddr + offset;
        }
    }
    return 0;
}

static int hardware_breakpoint(const char *args, int watchpoint)
{
    int (*set_breakpoint)(SceUID pid, int slot, unsigned address, unsigned control);
    uintptr_t function = 0;
    const SceUID pid = (SceUID)parse_hex(&args);
    const char *at = args;

    while (*at == ' ') {
        at++;
    }
    const char *space = strchr(at, ' ');
    const char *plus = strchr(at, '+');
    const unsigned address = plus && (!space || plus < space) ? module_address(pid, &args) : parse_hex(&args);
    unsigned control = watchpoint ? 0x1ff : 0x1e5;
    int result;

    if (!address) {
        return UNAVAILABLE;
    }

    while (*args == ' ') {
        args++;
    }
    if (*args) {
        control = parse_hex(&args);
    }
    result = module_get_export_func(KERNEL_PID, "SceProcessmgr", TAI_ANY_LIBRARY,
                                    watchpoint ? PROCESSMGR_SET_WATCHPOINT_NID : PROCESSMGR_SET_BREAKPOINT_NID, &function);
    if (result < 0) {
        return result;
    }
    set_breakpoint = (int (*)(SceUID, int, unsigned, unsigned))function;
    const int slot = watchpoint ? HWWP_SLOT : HWBP_SLOT;

    result = set_breakpoint(pid, slot, control ? address : 0, control);
    ksceKernelPrintf("[retail-cp] %s pid 0x%x slot %d address 0x%08x control 0x%x: 0x%08x\n", watchpoint ? "hwwp" : "hwbp",
                     pid, slot, address, control, result);
    return result;
}

/*
 * Files over the USB link: "copy SRC DST" copies one file in the kernel, so with deci4p_host
 * serving host0: (DRFP) a file goes host0: -> ur0:/ux0: and back with no other server on the
 * Vita. It writes DST.new, checks its size against SRC and only then replaces DST, so a
 * plugin in ur0:tai is never left half written. The result and size go to the kernel console.
 */
#define COPY_CHUNK 0x10000

static int file_copy(const char *args)
{
    char source[120], target[120], partial[128];
    static char buffer[COPY_CHUNK];
    const char *split = strchr(args, ' ');
    SceIoStat stat;
    SceUID in, out;
    int total = 0, result = 0;

    if (!split || split == args || (unsigned)(split - args) >= sizeof(source) || strlen(split + 1) >= sizeof(target) ||
        !split[1] || strchr(split + 1, ' ')) {
        return UNAVAILABLE;
    }
    memcpy(source, args, (unsigned)(split - args));
    source[split - args] = '\0';
    strcpy(target, split + 1);
    snprintf(partial, sizeof(partial), "%s.new", target);
    if ((result = ksceIoGetstat(source, &stat)) < 0) {
        return result;
    }
    if ((in = ksceIoOpen(source, SCE_O_RDONLY, 0)) < 0) {
        return in;
    }
    if ((out = ksceIoOpen(partial, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0666)) < 0) {
        ksceIoClose(in);
        return out;
    }
    for (;;) {
        int length = ksceIoRead(in, buffer, sizeof(buffer));

        if (length <= 0) {
            result = length;
            break;
        }
        if ((result = ksceIoWrite(out, buffer, length)) != length) {
            result = result < 0 ? result : UNAVAILABLE;
            break;
        }
        total += length;
    }
    ksceIoClose(in);
    if (ksceIoClose(out) < 0 && result >= 0) {
        result = UNAVAILABLE;
    }
    if (result >= 0 && (SceOff)total != stat.st_size) {
        result = UNAVAILABLE;
    }
    if (result >= 0) {
        ksceIoRemove(target);
        result = ksceIoRename(partial, target);
    }
    if (result < 0) {
        ksceIoRemove(partial);
    }
    ksceKernelPrintf("[retail-cp] copy %s %s: 0x%08X (%d bytes)\n", source, target, result, total);
    return result < 0 ? result : total;
}

/* "list DIR": each entry's size, modification time and name to the kernel console. */
static int dir_list(const char *path)
{
    SceUID dir = ksceIoDopen(path);
    SceIoDirent entry;
    int count = 0;

    if (dir < 0) {
        return dir;
    }
    for (;;) {
        memset(&entry, 0, sizeof(entry));
        if (ksceIoDread(dir, &entry) <= 0) {
            break;
        }
        ksceKernelPrintf("[retail-cp] list %s: %10u %04d-%02d-%02d %02d:%02d:%02d %s%s\n", path,
                         (unsigned)entry.d_stat.st_size, entry.d_stat.st_mtime.year, entry.d_stat.st_mtime.month,
                         entry.d_stat.st_mtime.day, entry.d_stat.st_mtime.hour, entry.d_stat.st_mtime.minute,
                         entry.d_stat.st_mtime.second, entry.d_name, SCE_S_ISDIR(entry.d_stat.st_mode) ? "/" : "");
        count++;
    }
    ksceIoDclose(dir);
    ksceKernelPrintf("[retail-cp] list %s: %d entries\n", path, count);
    return count;
}

int power_act(const char *word)
{
    if (!strcmp(word, "reset")) {
        static SceSysconPacket packet;

        memset(&packet, 0, sizeof(packet));
        packet.tx[SCE_SYSCON_PACKET_TX_CMD_LO] = SYSCON_COLD_RESET & 0xff;
        packet.tx[SCE_SYSCON_PACKET_TX_CMD_HI] = SYSCON_COLD_RESET >> 8;
        packet.tx[SCE_SYSCON_PACKET_TX_LENGTH] = 1;  /* no data, the checksum */
        return ksceSysconCmdExec(&packet, 0);
    }
    if (!strcmp(word, "reboot")) {
        /* Without power_transition a cold reset in development mode leaves the Vita off. */
        if (!power_transition_ref) {
            return UNAVAILABLE;
        }
        return kscePowerRequestColdReset();
    }
    if (!strcmp(word, "off")) {
        return kscePowerRequestStandby();
    }
    if (!strcmp(word, "suspend")) {
        /* Without power_transition a suspend in development mode never resumes. */
        if (!power_transition_ref) {
            return UNAVAILABLE;
        }
        return kscePowerRequestSuspend();
    }
    if (!strcmp(word, "wake")) {
        sleep_wake = 1;
        return 0;
    }
    if (!strcmp(word, "qaf")) {
        return qaf_unlock() ? 0 : UNAVAILABLE;
    }
    if (!strcmp(word, "uninstall")) {
        return uninstall();
    }
    if (!strcmp(word, "scratch")) {
        return scratch_dump();
    }
    if (!strcmp(word, "threads")) {
        return threads_report();
    }
    if (!strcmp(word, "debugmem")) {
        return debug_memory_report();
    }
    if (!strcmp(word, "memory")) {
        ksceKernelPrintf("[retail-cp] memory: KD 0x%x free, 0x%x in one block; PhyCont 0x%x in one block\n",
                         memory_free(MEMTYPE_KD, 16u << 20, 0), memory_free(MEMTYPE_KD_PHYCONT, 16u << 20, 1),
                         memory_free(MEMTYPE_PHYCONT, 64u << 20, 1));
        return 0;
    }
    if (!strncmp(word, "list ", 5)) {
        return dir_list(word + 5);
    }
    if (!strncmp(word, "copy ", 5)) {
        return file_copy(word + 5);
    }
    if (!strncmp(word, "hwbp ", 5)) {
        return hardware_breakpoint(word + 5, 0);
    }
    if (!strncmp(word, "hwwp ", 5)) {
        return hardware_breakpoint(word + 5, 1);
    }
    return UNAVAILABLE;
}

static int power_loop(SceSize argc, void *argp)
{
    (void)argc;
    (void)argp;
    for (;;) {
        SceUID tty = ksceIoOpen(POWER_TTY, SCE_O_RDONLY, 0);
        char word[256];
        unsigned length = 0;

        if (tty < 0) {
            ksceKernelDelayThread(POWER_RETRY_US);
            continue;
        }
        for (;;) {
            char ch;

            if (ksceIoRead(tty, &ch, 1) != 1) {
                break;
            }
            if (ch != '\r' && ch != '\n') {
                if (length < sizeof(word) - 1) {
                    word[length++] = ch;
                }
                continue;
            }
            if (!length) {
                continue;
            }
            word[length] = '\0';
            length = 0;
            ksceKernelPrintf("[retail-cp] power %s\n", word);
            ksceKernelPrintf("[retail-cp] power %s: 0x%08X\n", word, power_act(word));
        }
        ksceIoClose(tty);
        ksceKernelDelayThread(POWER_RETRY_US);
    }
    return 0;
}

int power_start(void)
{
    /* Core 0, above dtracep's 0x1e: reset and threads must work while something holds core 3. */
    power_thread = ksceKernelCreateThread("retail_cp_power", power_loop, 0x1d, 0x2000, 0, 0x10000, NULL);
    if (power_thread < 0) {
        return power_thread;
    }
    return ksceKernelStartThread(power_thread, 0, NULL);
}
