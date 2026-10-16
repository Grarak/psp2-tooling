/* Loading the ported DevKit modules: the early ones before the shell, the Target Manager
 * services after it, with the heaps and memory they need. */
#include "retail-cp.h"

unsigned unavailable_calls;

/* The four SceDbgSdioForDriver imports DfMgr binds: no debug SDIO hardware
 * exists on retail (or in this machine profile), so every call reports the
 * channel unavailable and counts itself. A startup report requires zero calls. */
int absent_sdio_unbind(int channel)
{
    (void)channel;
    __atomic_fetch_add(&unavailable_calls, 1, __ATOMIC_RELAXED);
    return UNAVAILABLE;
}

int absent_sdio_bind(int channel, SceUID event)
{
    (void)event;
    return absent_sdio_unbind(channel);
}

int absent_sdio_read(int channel, void *buffer, unsigned size)
{
    (void)buffer;
    (void)size;
    return absent_sdio_unbind(channel);
}

int absent_sdio_write(int channel, const void *buffer, unsigned size)
{
    (void)buffer;
    (void)size;
    return absent_sdio_unbind(channel);
}

int start(SceUID module, const char *stage)
{
    int status = -1;
    int result = ksceKernelStartModule(module, 0, NULL, 0, NULL, &status);

    record(stage, result);
    record("module-start-status", status);
    return result < 0 ? result : status == SCE_KERNEL_START_SUCCESS ? 0 : -1;
}
/* After an unclean shutdown (a raw Syscon reset, or forcing a hung PCH-2000 off) the next
 * boot's first load can fail in the secure loader with 0x800F0029 while a later boot loads
 * the same file (boots 8 and 22, 2026-10-15); a load the SBL refuses is retried. */
#define LOAD_SBL_RETRIES 10
#define LOAD_SBL_RETRY_US (500 * 1000)

/*
 * What a partition still gives, found by allocating and freeing at once (to 64 KiB). KD is the
 * system's: with the ported services' DevKit Tool-partition memory in KD it had 832 KiB left
 * (a 512-KiB block) once they ran, so udcd_uvc's 1-MiB frame (type 0x10208006, physically
 * contiguous, 4-KiB aligned) failed every frame, ~10 console lines apiece in development mode,
 * and the DECI4p link stopped (2026-10-16). With that memory in PhyCont (port_modules.py)
 * 3.3 MiB stay free. Recorded once the services run (services-kd-free, services-kd-block) and
 * on the "memory" word; each step that fails prints those lines too.
 */

/* contiguous: one physically contiguous block (udcd_uvc's frame); else all the partition's free
 * pages together. */
unsigned memory_free(unsigned memtype, unsigned limit, int contiguous)
{
    unsigned low = 0, high = limit;

    while (high - low > 0x10000) {
        SceKernelAllocMemBlockKernelOpt option;
        const unsigned size = ((low + high) / 2) & ~0xfffu;
        SceUID block;

        memset(&option, 0, sizeof(option));
        option.size = sizeof(option);
        option.attr = SCE_KERNEL_ALLOC_MEMBLOCK_ATTR_PHYCONT | SCE_KERNEL_ALLOC_MEMBLOCK_ATTR_HAS_ALIGNMENT;
        option.alignment = 0x1000;
        block = ksceKernelAllocMemBlock("retail_cp_probe", memtype, size, contiguous ? &option : NULL);
        if (block >= 0) {
            ksceKernelFreeMemBlock(block);
            low = size;
        } else {
            high = size;
        }
    }
    return low;
}

void record_kd_free(const char *stage)
{
    char text[40];

    snprintf(text, sizeof(text), "%s-kd-free", stage);
    record(text, (int)memory_free(MEMTYPE_KD, 16u << 20, 0));
    snprintf(text, sizeof(text), "%s-kd-block", stage);
    record(text, (int)memory_free(MEMTYPE_KD_PHYCONT, 16u << 20, 1));
}

static int load(const char *path, const char *stage)
{
    SceUID module = ksceKernelLoadModule(path, 0, NULL);
    unsigned retries = 0;

    while (module < 0 && ((unsigned)module & 0xffff0000u) == 0x800f0000u && retries < LOAD_SBL_RETRIES) {
        ksceKernelDelayThread(LOAD_SBL_RETRY_US);
        retries++;
        module = ksceKernelLoadModule(path, 0, NULL);
    }
    if (retries) {
        char text[40];

        snprintf(text, sizeof(text), "%s-sbl-retries", stage);
        record(text, retries);
    }
    record(stage, module);
    if (module < 0) {
        return module;
    }
    return start(module, stage);
}

struct service {
    const char *path;
    const char *stage;
    int required;
    unsigned heap;  /* kernel heap the module's start creates and must get */
    int early;      /* loaded by module_start, before the shell; >1: the switch held over its start */
    int after_shell; /* loaded once the shell has reported ready (services_wait_for_shell) */
};

static const struct service services[] = {
    /* pamgr reads 0xD4 in its start only, and syslibtrace is its one non-base import:
     * both load before the shell, 0xD4 held just over pamgr's start (see the header). */
    {"ur0:tai/syslibtrace-retail.skprx", "syslibtrace", 0, 0, 1, 0},
    {"ur0:tai/pamgr-retail.skprx", "pamgr", 0, 0, 0xd4, 0},
    {"ur0:tai/dbgusb-retail.skprx", "dbgusb", 1, 0, 0, 0},
    {"ur0:tai/dfmgr-retail.skprx", "dfmgr", 1, 0, 0, 0},
    {"ur0:tai/ttyp-retail.skprx", "ttyp", 0, 0, 0, 1},
    {"ur0:tai/userp-retail.skprx", "userp", 0, 0, 0, 1},
    {"ur0:tai/ctrlp-retail.skprx", "ctrlp", 0, 0, 0, 1},
    {"ur0:tai/loadp-retail.skprx", "loadp", 0, 0, 0, 1},
    {"ur0:tai/drfp-retail.skprx", "drfp", 0, 0, 0, 1},
    {"ur0:tai/dbgp-retail.skprx", "dbgp", 0, 0, 0, 1},
    /* Its start panics when its heap (patched to 4 MiB of PhyCont) cannot be created. */
    {"ur0:tai/dtracep-retail.skprx", "dtracep", 0, 4u << 20, 0, 1},
    {"ur0:tai/vcp-retail.skprx", "vcp", 0, 0, 0, 1},
};

/* How big a kernel heap retail can give a ported module: dtracep's start
 * creates one (16 MiB on the DevKit's Tool partition) with this exact option
 * block and panics when its first allocation from it fails. */
static unsigned heap_probe(const char *partition, SceUInt32 memtype)
{
    unsigned largest = 0;

    struct {
        SceSize size;
        SceUInt32 attr;
        SceUInt32 reserved[2];
        SceUInt32 memtype;
        SceUInt32 more[2];
    } option = {0x1c, 0x400, {0, 0}, memtype, {0, 0}};

    for (unsigned shift = 24; shift >= 20; shift--) {
        char stage[32];
        SceUID heap = ksceKernelCreateHeap("retail_cp_probe", 1u << shift, (void *)&option);

        snprintf(stage, sizeof(stage), "heap-%s-%umib", partition, 1u << (shift - 20));
        record(stage, heap);
        if (heap >= 0) {
            void *block = ksceKernelAllocHeapMemory(heap, 0x2000);

            record("heap-alloc", block != NULL);
            if (block) {
                ksceKernelFreeHeapMemory(heap, block);
                if (!largest) {
                    largest = 1u << shift;
                }
            }
            ksceKernelDeleteHeap(heap);
        }
    }
    return largest;
}

unsigned heap_report(void)
{
    /* KD (kernel RW, ~2 MiB free) holds the small Tool-partition allocations;
     * PhyCont (0x1080d006, 26 MiB) the large ones. */
    heap_probe("kd", 0x1020d006);
    return heap_probe("phycont", 0x1080d006);
}

/* Razor live's PA trace buffer (psp2-tooling razor/recorder): the recorder registers with pamgr
 * and hands it a physically contiguous user block of its own. pamgr translates only the buffer's
 * first page and trusts SceSysmemForDriver_A7C0D1FC (>= 0: accepted) for the rest; on a DevKit
 * that accepts only the PA window sysmem maps at user VA 0x40000000 from DevKit-only LPDDR2 on a
 * development-mode console. Retail has neither, so the check also accepts a block of the
 * caller's from the physically contiguous partition (USER_MAIN_PHYCONT_*). As on the DevKit,
 * pamgr does not hold the size against the block. */
static tai_hook_ref_t pa_range_ref;

static int pa_range(uintptr_t va)
{
    SceUID block = ksceKernelFindMemBlockByAddrForPid(ksceKernelGetProcessId(), (const void *)va, 0);
    unsigned type = 0;

    int result;

    if (block >= 0 && ksceKernelGetMemBlockType(block, &type) >= 0 && type >> 28 == 0 && (type >> 20 & 0xf) == 8) {
        result = 0;
    } else {
        result = TAI_CONTINUE(int, pa_range_ref, va);
    }
    ksceDebugPrintf("[retail-cp] pa-buffer va=%08x block=%08x type=%08x result=%08x\n", (unsigned)va,
                    (unsigned)block, block >= 0 ? type : 0, (unsigned)result);
    return result;
}

int pa_buffer_hook(void)
{
    return taiHookFunctionExportForKernel(KERNEL_PID, &pa_range_ref, "SceSysmem", TAI_ANY_LIBRARY, 0xa7c0d1fc,
                                          pa_range);
}

static int early_failures;

void load_early_services(void)
{
    for (unsigned index = 0; index < sizeof(services) / sizeof(services[0]); index++) {
        char stage[32];

        if (!services[index].early) {
            continue;
        }
        /* pamgr reads the PA block in its start, which hangs unless SKBL opened it: it does in
         * development mode. A boot without it restarts into it before the
         * Target Manager services (devmode_rearm). */
        if (services[index].early == 0xd4 && !ksceKernelCheckDipsw(0x9f)) {
            record("pamgr-skipped-pa-off", 1);
            early_failures++;
            continue;
        }
        snprintf(stage, sizeof(stage), "%s-load", services[index].stage);
        if (services[index].early > 1) {
            ksceKernelSetDipsw(services[index].early);
        }
        if (load(services[index].path, stage) < 0) {
            early_failures++;
        }
        if (services[index].early > 1) {
            ksceKernelClearDipsw(services[index].early);
            record("switch-d4-after-pamgr", ksceKernelCheckDipsw(services[index].early));
        }
    }
}

/*
 * The Target Manager services wait for the shell. A host that opens them while SceShell is still
 * starting makes it add a LiveArea bubble (host0's app_home, default icon) before its
 * applauncher_plugin is loaded: the shell's assert (SceShell +0x27CAF8, bkpt 0x40) stops
 * SceShellMain, and the kernel takes the Vita to standby (0x101), which in development mode it
 * does not come back from (three boots on 2026-10-15/16, a host connecting 9-12 s after a reset;
 * a host connecting after the boot never did it). So dbgusb and dfmgr come up as before (the USB
 * device and the DECI4p link, with nothing to open yet), and the services after them load once
 * the shell has reported ready (shell_status), or after SERVICES_SHELL_WAIT_US.
 */

static void services_wait_for_shell(void)
{
    unsigned waited = 0;

    while (!shell_ready && waited < SERVICES_SHELL_WAIT_US) {
        ksceKernelDelayThread(SHELL_READY_POLL_US);
        waited += SHELL_READY_POLL_US;
    }
    record("services-shell-ready-ms", shell_ready ? (int)shell_ready_ms : -1);
    record("services-waited-ms", (int)(waited / 1000));
}

int load_services(unsigned heap)
{
    int failures = early_failures;
    int waited = 0;

    for (unsigned index = 0; index < sizeof(services) / sizeof(services[0]); index++) {
        char stage[32];

        if (services[index].early) {
            continue;
        }
        if (!waited && services[index].after_shell) {
            services_wait_for_shell();
            waited = 1;
        }
        snprintf(stage, sizeof(stage), "%s-load", services[index].stage);
        int result = UNAVAILABLE;

        if (services[index].heap > heap) {
            record(stage, UNAVAILABLE);
        } else {
            result = load(services[index].path, stage);
            if (result >= 0 && !strcmp(services[index].stage, "dbgusb")) {
                record("dbgusb-attach-fix", dbgusb_attach_fix());
            }
        }
        if (result < 0) {
            if (services[index].required) {
                return result;
            }
            failures++;
        }
    }
    return failures;
}
