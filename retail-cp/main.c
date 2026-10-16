/*
 * retail-cp: CP emulation for a retail Vita under taiHEN.
 *
 * Built by this directory's CMakeLists.txt.
 *
 * One plugin, two jobs:
 *
 * 1. The Communication Processor's bootparam switches. A DevKit's CP board
 *    writes a 0x20-byte switch block (the SceDipsw struct) that
 *    the kernel reads through SceDipswForDriver. Retail has no CP, so every
 *    bit reads clear. This plugin writes the one debug bit the Target Manager
 *    services need, before the boot config reaches their loaders:
 *      0xC2  debug USB startup (gates SceDbgUsb and SceDeci4pCtrlp module_start)
 *      0xC7  DECI console: ttyp's module_start returns NO_RESIDENT unless both
 *            0xC2 and 0xC7 are set (the DevKit CP default byte 0x18 = 0xe7
 *            carries it).
 *      0xD4  performance analysis: pamgr's module_start (0x810025fc) stays
 *            resident only when it is set (else NO_RESIDENT), and it is its one
 *            read. Modulemgr reads it at every process creation as well and then
 *            preloads its DevKit list, libperf among them; ScePerf imports
 *            SceDTrace, which dtracep cannot export before the shell, and the
 *            shell crashes. So 0xD4 is set only around
 *            pamgr's start and cleared again before the shell. Bit 0xD2 of the
 *            same byte stays clear: it would retarget a processmgr allocation
 *            partition to a DevKit-only id.
 *    It deliberately leaves 0x80 (Tool memory partition), 0x9F (development
 *    mode) and 0xC3 (CP SDIO transport) clear: this stays a 512-MiB CEX
 *    console with DECI4p on its own USB port.
 *
 *    0xE4 (the hardware debug switch) is not set here: setting it in the
 *    running kernel took a kernel data abort at the next process creation,
 *    because ProcessMgr's per-process debug tables and
 *    IntrMgr's CP14 restore must be armed before the first thread exists. Like
 *    development mode it is armed in Ernie's bootparam block instead
 *    (devmode_rearm), where SKBL reads it at boot as a DevKit's CP pushes it;
 *    the kernel's own path then loads each process's hardware breakpoints and
 *    watchpoints (hardware_breakpoint).
 *
 * 2. The CP's DECI4p relay, replaced by the Vita's own USB port: it loads the
 *    offline-ported DevKit modules (port_modules.py) over
 *    UDC bus 2 and then the Target Manager services: console (ttyp), app
 *    stdio (userp), input (ctrlp), launch (loadp), host0: (drfp), the
 *    debugger and DTrace (dbgp, dtracep) and VitaOS screenshots (vcp).
 *
 * Two DevKit capabilities come from the secure world, which a retail console
 * never asks for them. Both are restored from the running kernel, not by
 * patching firmware:
 *
 *   host0: launch (LOADP spawn). QA flags are a 16-byte block in non-secure
 *   memory that the secure world fills at boot from Ernie's NVS (the QAF
 *   token, KBL_Param.txt). A retail console's block is all zero, so
 *   ksceSblQafMgrIsAllowHost0Access (SceQafMgrForDriver 082a4fc2, KBL param
 *   +0x20, byte 0x0e bit 0) answers 0 and LOADP refuses a
 *   host0: spawn with 0x80010058. The DevKit templates QAF_SYS_DEV_I and
 *   QAF_MGVIDEO_* have that bit set; qaf_unlock() sets it too.
 *
 *   Hardware debug (0xE4) and the PA/debug devices. SKBL only enables them
 *   when the bootparam switch block it reads from Ernie's scratchpad has
 *   0xE4 set, which a DevKit CP pushes and retail has no CP to push.
 *   scratch_switch() arms that one bit (Syscon scratchpad 0xfc, command 0x91)
 *   for the next boot, together with development mode (devmode_rearm).
 *
 * The report lands in ur0:data/retail-debug/cp.txt; every line is a
 * stage=value record, including each module's load/start result and the
 * hardware-breakpoint arming it observes. The ported modules are the pinned
 * offline ports and the switch bits go through ksceKernelSetDipsw; in the
 * running kernel only threadmgr's DTrace heap memtype is patched
 * (threadmgr_patch), sceMtpIfStartPort is hooked (mtp_yield), udcd shares the
 * port with other plugins' USB drivers (usb_share) and pamgr's trace-buffer
 * check accepts a user PhyCont block (pa_range).
 */


#include "retail-cp.h"

static SceUID worker = -1;

static int setup(SceSize argc, void *args)
{
    int result;

    (void)argc;
    (void)args;
    ksceKernelDelayThread(2000000);
    ksceIoMkdir("ur0:data", 0777);
    ksceIoMkdir("ur0:data/retail-debug", 0777);
    /* module_start truncated the report and recorded its hooks; append to it. */
    SceUID file = ksceIoOpen(REPORT_PATH, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_APPEND, 0666);

    if (file < 0 || ksceIoClose(file) < 0) {
        return -1;
    }
    record("version", 3);
    result = ksceUdcdGetDeviceStateInternal(USB_BUS);
    record("usb-state-before", result);
    if (result < 0 || result & (SCE_UDCD_STATUS_ACTIVATED | SCE_UDCD_STATUS_CONNECTION_ESTABLISHED)) {
        result = -1;
        goto finish;
    }
    unsigned heap = heap_report();

    result = threadmgr_patch();
    record("threadmgr-dtrace-heap", result);
    if (result < 0) {
        heap = 0;  /* the services needing a heap are dtracep's */
    }
    /* A boot that came up without development mode reboots into it (devmode_rearm) without
     * the Target Manager services, so that no host session starts on a boot about to end. */
    result = devmode_rearm();
    record("devmode-rearm", result);
    if (result == 1) {
        goto finish;
    }
    result = load_services(heap);
    record("dtrace-pmep-off", dtrace_pmep_off());
    record("dtrace-send-fix", dtrace_send_fix());
    record("console", console_start());
    record("service-failures", result);
    record_kd_free("services");
    int usb_state = ksceUdcdGetDeviceStateInternal(USB_BUS);

    usb_shared = usb_shared && usb_state >= 0 && usb_state & SCE_UDCD_STATUS_ACTIVATED;
    record("usb-shared", usb_shared ? usb_member_count : -1);
    if (result < 0) {
        goto finish;
    }
    {
        /* ttyp remounts /tty on its own VFS: a console write reaches the host's tty.log. */
        static const char line[] = "[retail-cp] console over TTYP\n";
        SceUID tty = ksceIoOpen("tty0:", SCE_O_WRONLY, 0);

        record("tty-open", tty);
        if (tty >= 0) {
            record("tty-write", ksceIoWrite(tty, line, sizeof(line) - 1));
            ksceIoClose(tty);
        }
    }
    result = 0;
    /* Before the host can use LOADP, and before the report is complete. */
    record("qaf", qaf_unlock());
    /* Read only, never written at boot. */
    scratch_dump();
    record("crash-report", crash_report());
    record("power-thread", power_start());
    record("awake-thread", awake_start());
    record("devmode-reboot", devmode_reboot_install());
    record("power-notify", power_notify != NULL);
    record("crash", crash_start());
finish:
    record("mtp-start-port-yields", __atomic_load_n(&mtp_yields, __ATOMIC_RELAXED));
    record("sdio-unavailable-calls", __atomic_load_n(&unavailable_calls, __ATOMIC_RELAXED));
    record("report-io-error", report_failed);
    record("complete", result);
    return result;
}

int module_start(SceSize argc, const void *args)
{
    (void)argc;
    (void)args;
    ksceIoMkdir("ur0:data", 0777);
    ksceIoMkdir("ur0:data/retail-debug", 0777);
    ksceIoRemove(REPORT_PREVIOUS);
    ksceIoRename(REPORT_PATH, REPORT_PREVIOUS);
    SceUID file = ksceIoOpen(REPORT_PATH, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0666);

    if (file < 0 || ksceIoClose(file) < 0) {
        return SCE_KERNEL_START_FAILED;
    }
    switches_report();
    cp_switches();
    record("mtp-yield-hook", mtp_yield());
    record("usb-share", usb_share());
    /* Early: the shell may report ready before setup is through its services. */
    record("shell-ready-hook", shell_ready_install());
    record("pa-buffer-hook", pa_buffer_hook());
    record("appmgr-screen-off-suspend", appmgr_patch());
    record("spawn-title-hook", spawn_title_hook());
    load_early_services();
    worker = ksceKernelCreateThread("retail_cp", setup, 0x80, 0x8000, 0, 0, NULL);
    if (worker < 0) {
        return SCE_KERNEL_START_FAILED;
    }
    if (ksceKernelStartThread(worker, 0, NULL) < 0) {
        ksceKernelDeleteThread(worker);
        worker = -1;
        return SCE_KERNEL_START_FAILED;
    }
    return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize argc, const void *args)
{
    (void)argc;
    (void)args;
    return worker < 0 ? SCE_KERNEL_STOP_SUCCESS : SCE_KERNEL_STOP_FAIL;
}
