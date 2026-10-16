/* Kernel crashes: recorded in Syscon's scratch pad, then a restart; reported the next boot. */
#include "retail-cp.h"

/*
 * Crash recorder. A data or prefetch abort or an undefined instruction in the kernel ends in
 * SceSysmem's report (3.65 0x81019dd4): "*** Kernel %s Exception at CPU%d <...>", "Stopped",
 * then a loop with interrupts masked. A DevKit prints that on its kernel console and its CP
 * resets the target; here the console (console_start) is lost when the core was core 3, where
 * DECI4p runs, and only the power button got the Vita back (DTrace's open on the PCH-2000).
 * The report is hooked: the faulting core copies what it
 * was given into crash_words; a thread on core 0 writes them to the Syscon scratch pad at
 * 0x40-0xDF, which survives a reset, and cold-resets the Vita through Syscon (development mode
 * stays). The next boot's crash_report resolves the addresses with kmods-prev.txt, the crashed
 * boot's module map (kmods.txt is the current one), puts a crash= line in cp.txt and on the
 * kernel console, and clears the record.
 * Words: 'EXC' << 8 | cpu; the report's address pair and offset; 12 bytes of module name; its
 * line; 4 bytes of the exception's name; the context's r0-r12, sp, lr, pc (+0x00-0x3c) and its
 * next 8 words; DFSR, DFAR, IFSR, IFAR; the first 3 words of its stack copy (+0x200) that are
 * Thumb addresses in a kernel module's text.
 */
#define CRASH_MODULES "ur0:data/retail-debug/kmods.txt"
#define CRASH_MODULES_PREVIOUS "ur0:data/retail-debug/kmods-prev.txt"
#define CRASH_SCRATCH 0x40
#define CRASH_MAGIC 0x45584300u /* "EXC" */
#define CRASH_WORDS 40
#define CRASH_PC 24 /* r0 at word 9 */
#define CRASH_LR 23
#define CRASH_DFSR 33
#define CRASH_STACK 37
#define CRASH_TEXTS 160
#define CRASH_POLL_US (100 * 1000)
#define SYSMEM_KERNEL_EXCEPTION 0x19dd4

static tai_hook_ref_t crash_ref;
static volatile uint32_t crash_words[CRASH_WORDS];
static volatile int crash_seen;
static struct {
    uintptr_t start, end;
} crash_texts[CRASH_TEXTS];
static unsigned crash_text_count;

/* The kernel modules' text and data, to kmods.txt, and their text ranges for the hook. */
static void crash_modules(void)
{
    static SceUID ids[CRASH_TEXTS];
    SceSize count = sizeof(ids) / sizeof(ids[0]);
    SceUID file;
    char line[96];

    if (ksceKernelGetModuleList(KERNEL_PID, 0x7fffffff, 1, ids, &count) < 0) {
        return;
    }
    ksceIoRemove(CRASH_MODULES_PREVIOUS);
    ksceIoRename(CRASH_MODULES, CRASH_MODULES_PREVIOUS);
    file = ksceIoOpen(CRASH_MODULES, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0666);
    for (unsigned index = 0; index < count; index++) {
        SceKernelModuleInfo info;
        int length;

        memset(&info, 0, sizeof(info));
        info.size = sizeof(info);
        if (ksceKernelGetModuleInfo(KERNEL_PID, ids[index], &info) < 0) {
            continue;
        }
        if (crash_text_count < CRASH_TEXTS) {
            crash_texts[crash_text_count].start = (uintptr_t)info.segments[0].vaddr;
            crash_texts[crash_text_count].end = (uintptr_t)info.segments[0].vaddr + info.segments[0].memsz;
            crash_text_count++;
        }
        length = snprintf(line, sizeof(line), "%08x %08x %08x %08x %s\n", (unsigned)(uintptr_t)info.segments[0].vaddr,
                          (unsigned)info.segments[0].memsz, (unsigned)(uintptr_t)info.segments[1].vaddr,
                          (unsigned)info.segments[1].memsz, info.module_name);
        if (file >= 0 && length > 0) {
            ksceIoWrite(file, line, length);
        }
    }
    if (file >= 0) {
        ksceIoClose(file);
    }
}

static void crash_name(unsigned word, const char *name, unsigned size)
{
    char copy[16];

    memset(copy, 0, sizeof(copy));
    if (name) {
        strncpy(copy, name, size);
    }
    for (unsigned index = 0; index < size / 4; index++) {
        uint32_t value;

        memcpy(&value, copy + index * 4, 4);
        crash_words[word + index] = value;
    }
}

static void kernel_exception(const uint32_t *info, const uint32_t *context, uint32_t extra, const char *type)
{
    if (!__atomic_exchange_n(&crash_seen, 1, __ATOMIC_ACQ_REL)) {
        uint32_t fault[4];
        unsigned word = CRASH_STACK;

        __asm__ volatile("mrc p15, 0, %0, c5, c0, 0\n\tmrc p15, 0, %1, c6, c0, 0\n\t"
                         "mrc p15, 0, %2, c5, c0, 1\n\tmrc p15, 0, %3, c6, c0, 2"
                         : "=r"(fault[0]), "=r"(fault[1]), "=r"(fault[2]), "=r"(fault[3]));
        crash_words[0] = CRASH_MAGIC | (ksceKernelCpuId() & 0xff);
        crash_words[1] = info[0];
        crash_words[2] = info[1];
        crash_words[3] = info[2];
        crash_name(4, (const char *)(uintptr_t)info[3], 12);
        crash_words[7] = info[4];
        crash_name(8, type, 4);
        for (unsigned index = 0; index < 24; index++) {
            crash_words[9 + index] = context[index];
        }
        for (unsigned index = 0; index < 4; index++) {
            crash_words[CRASH_DFSR + index] = fault[index];
        }
        for (unsigned index = 0x200 / 4; index < 0x400 / 4 && word < CRASH_WORDS; index++) {
            const uintptr_t value = context[index];

            if (!(value & 1)) {
                continue;
            }
            for (unsigned text = 0; text < crash_text_count; text++) {
                if (value >= crash_texts[text].start && value < crash_texts[text].end) {
                    crash_words[word++] = value;
                    break;
                }
            }
        }
        (void)extra;
        __atomic_thread_fence(__ATOMIC_RELEASE);
    }
    TAI_CONTINUE(void, crash_ref, info, context, extra, type);
}

static int crash_thread(SceSize argc, void *args)
{
    uint32_t words[CRASH_WORDS];

    (void)argc;
    (void)args;
    while (!__atomic_load_n(&crash_seen, __ATOMIC_ACQUIRE)) {
        ksceKernelDelayThread(CRASH_POLL_US);
    }
    /* Let the faulting core finish its copy, write it twice, then cold-reset. */
    ksceKernelDelayThread(200 * 1000);
    for (unsigned word = 0; word < CRASH_WORDS; word++) {
        words[word] = crash_words[word];
    }
    for (;;) {
        syscon_scratch(SYSCON_CMD_WRITE_SCRATCH, CRASH_SCRATCH, words, sizeof(words));
        syscon_scratch(SYSCON_CMD_WRITE_SCRATCH, CRASH_SCRATCH, words, sizeof(words));
        ksceKernelDelayThread(500 * 1000);
        power_act("reset");
        ksceKernelDelayThread(1000 * 1000);
    }
    return 0;
}

int crash_start(void)
{
    static const unsigned char prologue[] = {0x2d, 0xe9, 0xf0, 0x47, 0x0f, 0x46, 0x2d, 0xed};
    tai_module_info_t tai = {.size = sizeof(tai)};
    SceKernelModuleInfo module = {.size = sizeof(module)};
    SceUID thread;
    int result;

    crash_modules();
    result = taiGetModuleInfoForKernel(KERNEL_PID, "SceSysmem", &tai);
    if (result < 0 || (result = ksceKernelGetModuleInfo(KERNEL_PID, tai.modid, &module)) < 0) {
        return result;
    }
    if (module.segments[0].memsz != 0x2f280 ||
        memcmp((const char *)module.segments[0].vaddr + SYSMEM_KERNEL_EXCEPTION, prologue, sizeof(prologue))) {
        return UNAVAILABLE;
    }
    thread = ksceKernelCreateThread("retail_cp_crash", crash_thread, 0x10, 0x1000, 0, 0x10000 /* core 0 */, NULL);
    if (thread < 0 || (result = ksceKernelStartThread(thread, 0, NULL)) < 0) {
        return thread < 0 ? thread : result;
    }
    return taiHookFunctionOffsetForKernel(KERNEL_PID, &crash_ref, tai.modid, 0, SYSMEM_KERNEL_EXCEPTION, 1,
                                          kernel_exception);
}

/* An address as module+offset, from the crashed boot's kmods-prev.txt (text segments). */
static void crash_where(const char *map, uint32_t address, char *out, unsigned size)
{
    snprintf(out, size, "%08x", (unsigned)address);
    for (const char *line = map; line && *line;) {
        unsigned start = 0, length = 0;
        const char *field = line;

        for (unsigned digit = 0; digit < 8; digit++, field++) {
            start = start << 4 | (unsigned)(*field <= '9' ? *field - '0' : (*field | 0x20) - 'a' + 10);
        }
        field++;
        for (unsigned digit = 0; digit < 8; digit++, field++) {
            length = length << 4 | (unsigned)(*field <= '9' ? *field - '0' : (*field | 0x20) - 'a' + 10);
        }
        if ((address & ~1u) >= start && (address & ~1u) < start + length) {
            const char *name = line + 36;
            unsigned name_length = 0;

            while (name[name_length] && name[name_length] != '\n') {
                name_length++;
            }
            snprintf(out, size, "%.*s+%x", (int)name_length, name, (unsigned)((address & ~1u) - start));
            return;
        }
        line = strchr(line, '\n');
        line = line ? line + 1 : NULL;
    }
}

int crash_report(void)
{
    static char map[0x2000];
    uint32_t words[CRASH_WORDS];
    char where[5][48], line[384];
    char type[5];
    SceUID file;
    int length, result = syscon_scratch(SYSCON_CMD_READ_SCRATCH, CRASH_SCRATCH, words, sizeof(words));

    if (result < 0) {
        return result;
    }
    if ((words[0] & 0xffffff00u) != CRASH_MAGIC) {
        /* Not a record: clear anything else there (the 2026-10-15 black box's samples). */
        for (unsigned index = 0; index < CRASH_WORDS; index++) {
            if (words[index]) {
                memset(words, 0, sizeof(words));
                return syscon_scratch(SYSCON_CMD_WRITE_SCRATCH, CRASH_SCRATCH, words, sizeof(words));
            }
        }
        return 0;
    }
    file = ksceIoOpen(CRASH_MODULES_PREVIOUS, SCE_O_RDONLY, 0);
    length = file >= 0 ? ksceIoRead(file, map, sizeof(map) - 1) : 0;
    if (file >= 0) {
        ksceIoClose(file);
    }
    map[length > 0 ? length : 0] = '\0';
    memcpy(type, &words[8], 4);
    type[4] = '\0';
    crash_where(map, words[9 + 15], where[0], sizeof(where[0]));
    crash_where(map, words[9 + 14], where[1], sizeof(where[1]));
    for (unsigned index = 0; index < 3; index++) {
        crash_where(map, words[CRASH_STACK + index], where[2 + index], sizeof(where[2 + index]));
    }
    snprintf(line, sizeof(line),
             "%s exception on core %u: pc %s lr %s sp %08x dfsr %08x dfar %08x ifsr %08x ifar %08x stack %s %s %s",
             type, (unsigned)(words[0] & 0xff), where[0], where[1], (unsigned)words[9 + 13],
             (unsigned)words[CRASH_DFSR], (unsigned)words[CRASH_DFSR + 1], (unsigned)words[CRASH_DFSR + 2],
             (unsigned)words[CRASH_DFSR + 3], where[2], where[3], where[4]);
    record_text("crash", line);
    length = 0;
    for (unsigned index = 0; index < 13; index++) {
        length += snprintf(line + length, sizeof(line) - length, "%s%08x", index ? " " : "", (unsigned)words[9 + index]);
    }
    record_text("crash-r0-r12", line);
    memset(words, 0, sizeof(words));
    return syscon_scratch(SYSCON_CMD_WRITE_SCRATCH, CRASH_SCRATCH, words, sizeof(words));
}
