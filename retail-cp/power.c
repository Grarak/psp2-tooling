/* Power: development-mode reboots, suspend and the shell's death without powering off, the
 * switches kept on, uninstall, and no idle sleep. */
#include "retail-cp.h"

void (*power_notify)(unsigned clear, unsigned set, unsigned once);

/*
 * Reboots in development mode. With switch 0x9F in Ernie's bootparam block, ScePower's cold
 * reset (power FUN_81001120, 0x404: an app's reboot, the "reboot" word, the shell's restart) can
 * leave the PCH-2000 off: it describes the transition to Ernie first (Syscon 0x0C) and Ernie,
 * as on a DevKit, leaves powering on to the CP, which retail lacks. Clearing 0x9F for one boot and arming it again came back on
 * 2026-10-15 but not on 2026-10-16. The raw Syscon cold reset (power_act "reset", 0x0801 with
 * no data) has come back in development mode every time (~25 resets on 2026-10-15/16). So in
 * development mode ScePower's cold reset becomes devmode_restart: the filesystems are synced,
 * then that reset; one boot, development mode kept. LAST_TRANSITION holds the last
 * transition's mode in hex (0x101 is standby).
 * SceShell's death ends in AppMgr's kscePowerRequestStandby (3.65 appmgr 0x81000958: the dying
 * process is the shell), which in development mode leaves the Vita off with no Target Manager
 * to restart it: shell crashes caused by *main plugins looked like power-offs. That import restarts the same way
 * (shell_death), after the shell's core dump is written.
 * Development mode (0x9F) and hardware debug (0xE4) are always on, as on a DevKit: any boot
 * without either arms both and restarts into them; only uninstall clears them. After
 * DEVMODE_ATTEMPTS boots in a row that came up without it (DEVMODE_TRIES; a boot in development
 * mode clears it) one boot is left as it is, so a failing write cannot loop, and the next boot
 * tries again.
 */
#define DEVMODE_TRIES "ur0:data/retail-debug/devmode-tries"
#define DEVMODE_ATTEMPTS 2
#define LAST_TRANSITION "ur0:data/retail-debug/last-power-transition"
#define POWER_TRANSITION 0x1120
#define POWER_COLD_RESET 0x400
#define SHELL_DEATH 0x1ff /* LAST_TRANSITION after shell_death, not a ScePower mode */
#define REARM_SETTLE_US (3 * 1000 * 1000) /* after the shell reports ready */

tai_hook_ref_t power_transition_ref;
static tai_hook_ref_t shell_death_ref;

static void write_marker(const char *path, unsigned value)
{
    char text[16];
    int length = snprintf(text, sizeof(text), "%x\n", value);
    SceUID file = ksceIoOpen(path, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0666);

    if (file >= 0) {
        ksceIoWrite(file, text, length);
        ksceIoClose(file);
    }
}

/*
 * The filesystems are synced, then the raw Syscon reset. That only queues the command, so the
 * caller never goes on: a shell death that went on into AppMgr's standby had ScePower suspend
 * the drivers and truncate files during the moments before the reset landed (2026-10-16).
 */
static void devmode_restart(const char *why)
{
    static const char *const devices[] = {"ux0:", "ur0:", "ud0:", "uma0:", "imc0:", "xmc0:", "vd0:", "tm0:"};

    ksceKernelPrintf("[retail-cp] %s: syncing, then the Syscon cold reset\n", why);
    for (unsigned i = 0; i < sizeof(devices) / sizeof(devices[0]); i++) {
        ksceIoSync(devices[i], 0);
    }
    power_act("reset");
    for (;;) {
        ksceKernelDelayThread(1000 * 1000);
    }
}

/*
 * Suspend in development mode. ScePower's suspend (0x202: the power button's short press, the
 * "suspend" word) leaves a development-mode Vita off for good: Ernie, as on a DevKit, leaves
 * the resume to the CP. So the transition becomes a sleep with the system running: the panel
 * goes off (SceOled on an OLED Vita, SceLcd on an LCD one, whichever is loaded) and ScePower's
 * thread waits here until the power key is pressed again (or the "wake" word), then the panel
 * comes back on and ScePower goes on as after a resume. Apps keep running and the USB link
 * stays up, as on a DevKit under a Target Manager. A suspend asked for within
 * SLEEP_REPEAT_US of waking (the press that woke it, seen by ScePower too) is ignored.
 */
#define POWER_SUSPEND 0x200
#define SLEEP_POLL_US (50 * 1000)
#define SLEEP_REPEAT_US (1000u * 1000)

volatile int sleep_wake;   /* the "wake" word */
static SceUInt64 sleep_woke_at;
/* ScePower's power-callback state (power FUN_81000a58 -> FUN_81000380(clear, set, once)): a
 * real suspend sets SUSPENDING (0x10000), its resume RESUMING (0x20000), then reports
 * RESUME_COMPLETE (0x40000) once. Without them the shell never sees the suspend end and asks
 * for it again two seconds after every wake. */
#define POWER_NOTIFY 0xa58
#define POWER_CB_SUSPENDING 0x10000
#define POWER_CB_RESUMING 0x20000
#define POWER_CB_RESUME_COMPLETE 0x40000
/* The requests wait as bits of ScePower's "ScePowerMain" event flag (its UID at data +0x40c0);
 * a real transition clears them (ClearEventFlag 0xfffff102) or ScePower enters it again. */
#define POWER_MAIN_FLAG 0x40c0
#define POWER_REQUESTS_KEEP 0xfffff102
static volatile const SceUID *power_main_flag;

static void power_requests_clear(void)
{
    if (power_main_flag && *power_main_flag > 0) {
        ksceKernelClearEventFlag(*power_main_flag, POWER_REQUESTS_KEEP);
    }
}

static int display_power(int on)
{
    static const struct {
        const char *module;
        uint32_t library, off, on;
    } panels[] = {
        {"SceOled", 0x60c7478a, 0xbc84602e /* ksceOledDisplayOff */, 0x4c7836c7 /* ksceOledDisplayOn */},
        {"SceLcd", 0xfa916d71, 0x1a0a7519 /* ksceLcdDisplayOff */, 0x5f4124ab /* ksceLcdDisplayOn */},
    };

    for (unsigned i = 0; i < sizeof(panels) / sizeof(panels[0]); i++) {
        uintptr_t function;

        if (module_get_export_func(KERNEL_PID, panels[i].module, panels[i].library, on ? panels[i].on : panels[i].off,
                                   &function) >= 0) {
            int result = ((int (*)(void))function)();

            ksceKernelPrintf("[retail-cp] %s display %s: 0x%08X\n", panels[i].module, on ? "on" : "off", result);
            return result;
        }
    }
    return UNAVAILABLE;
}

static int power_key(void)
{
    SceCtrlData pad;

    memset(&pad, 0, sizeof(pad));
    return ksceCtrlPeekBufferPositive(0, &pad, 1) > 0 && (pad.buttons & SCE_CTRL_POWER);
}

static void devmode_sleep(void)
{
    if (ksceKernelGetSystemTimeWide() - sleep_woke_at < SLEEP_REPEAT_US) {
        power_requests_clear();
        return;
    }
    ksceKernelPrintf("[retail-cp] suspend in development mode: the panel off until the power key\n");
    sleep_wake = 0;
    if (power_notify) {
        power_notify(0, POWER_CB_SUSPENDING, 0);
    }
    display_power(0);
    while (power_key() && !sleep_wake) { /* the press that asked for it */
        ksceKernelDelayThread(SLEEP_POLL_US);
    }
    while (!power_key() && !sleep_wake) {
        ksceKernelDelayThread(SLEEP_POLL_US);
    }
    display_power(1);
    while (power_key()) {
        ksceKernelDelayThread(SLEEP_POLL_US);
    }
    power_requests_clear();
    if (power_notify) {
        power_notify(POWER_CB_SUSPENDING, POWER_CB_RESUMING, 0);
        power_notify(POWER_CB_RESUMING, 0, POWER_CB_RESUME_COMPLETE);
    }
    sleep_woke_at = ksceKernelGetSystemTimeWide();
    ksceKernelPrintf("[retail-cp] awake\n");
}

static void power_transition(unsigned mode)
{
    write_marker(LAST_TRANSITION, mode);
    if ((mode & 0xf00) == POWER_COLD_RESET && ksceKernelCheckDipsw(DIPSW_DEVELOPMENT_MODE)) {
        devmode_restart("cold reset in development mode");
        return;
    }
    if ((mode & 0xf00) == POWER_SUSPEND && ksceKernelCheckDipsw(DIPSW_DEVELOPMENT_MODE)) {
        devmode_sleep();
        return;
    }
    TAI_CONTINUE(void, power_transition_ref, mode);
}

static int shell_death(void)
{
    if (ksceKernelCheckDipsw(DIPSW_DEVELOPMENT_MODE)) {
        write_marker(LAST_TRANSITION, SHELL_DEATH);
        devmode_restart("the shell died");
    }
    return TAI_CONTINUE(int, shell_death_ref);
}

int devmode_reboot_install(void)
{
    static const unsigned char push[] = {0x2d, 0xe9, 0xf0, 0x4f};
    static const unsigned char body[] = {0xbf, 0xb0, 0x22, 0xad, 0x68, 0x26, 0x1b, 0x68, 0x32, 0x46, 0x0b, 0x90};
    tai_module_info_t tai = {.size = sizeof(tai)};
    SceKernelModuleInfo module = {.size = sizeof(module)};
    const char *text;
    int result = taiGetModuleInfoForKernel(KERNEL_PID, "ScePower", &tai);

    if (result < 0 || (result = ksceKernelGetModuleInfo(KERNEL_PID, tai.modid, &module)) < 0) {
        return result;
    }
    text = module.segments[0].vaddr;
    if (module.segments[0].memsz != 0xa9a0 || memcmp(text + POWER_TRANSITION + 4, push, sizeof(push)) ||
        memcmp(text + POWER_TRANSITION + 0x0c, body, sizeof(body))) {
        return UNAVAILABLE;
    }
    {
        static const unsigned char notify[] = {0x08, 0xb5, 0xff, 0xf7, 0x91, 0xfc, 0x08, 0xbd};

        if (!memcmp(text + POWER_NOTIFY, notify, sizeof(notify)) && module.segments[1].memsz == 0x47d8) {
            power_notify = (void (*)(unsigned, unsigned, unsigned))(uintptr_t)(text + POWER_NOTIFY + 1);
            power_main_flag = (volatile const SceUID *)((uintptr_t)module.segments[1].vaddr + POWER_MAIN_FLAG);
        }
    }
    result = taiHookFunctionOffsetForKernel(KERNEL_PID, &power_transition_ref, tai.modid, 0, POWER_TRANSITION, 1,
                                            power_transition);
    if (result < 0) {
        return result;
    }
    /* AppMgr imports kscePowerRequestStandby for the shell's death alone. */
    return taiHookFunctionImportForKernel(KERNEL_PID, &shell_death_ref, "SceAppMgr", 0x1590166f /* ScePowerForDriver */,
                                          0x2b7c7cf4 /* kscePowerRequestStandby */, shell_death);
}

static int devmode_rearm_thread(SceSize argc, void *args)
{
    unsigned waited = 0;

    (void)argc;
    (void)args;
    while (!shell_ready && waited < SERVICES_SHELL_WAIT_US) {
        ksceKernelDelayThread(SHELL_READY_POLL_US);
        waited += SHELL_READY_POLL_US;
    }
    ksceKernelDelayThread(REARM_SETTLE_US);
    devmode_restart("development mode armed again");
    return ksceKernelExitDeleteThread(0);
}

static unsigned devmode_tries(void)
{
    char text[8] = {0};
    SceUID file = ksceIoOpen(DEVMODE_TRIES, SCE_O_RDONLY, 0);

    if (file < 0) {
        return 0;
    }
    ksceIoRead(file, text, sizeof(text) - 1);
    ksceIoClose(file);
    return (unsigned)(text[0] - '0') < 10 ? (unsigned)(text[0] - '0') : DEVMODE_ATTEMPTS;
}

/* Any boot without development mode or hardware debug: 0 both on already, 1 rebooting into
 * them, 2 skipped after DEVMODE_ATTEMPTS boots in a row without them (the next boot tries again).
 * SKBL reads both from Ernie's bootparam block at boot, as a DevKit's CP pushes them. */
int devmode_rearm(void)
{
    static const unsigned switches[] = {DIPSW_DEVELOPMENT_MODE, DIPSW_SWITCH_HWDEBUG};
    unsigned tries;
    SceUID thread;
    int result;

    if (ksceKernelCheckDipsw(DIPSW_DEVELOPMENT_MODE) && ksceKernelCheckDipsw(DIPSW_SWITCH_HWDEBUG)) {
        ksceIoRemove(DEVMODE_TRIES);
        return 0;
    }
    tries = devmode_tries();
    if (tries >= DEVMODE_ATTEMPTS) {
        ksceIoRemove(DEVMODE_TRIES);
        return 2;
    }
    write_marker(DEVMODE_TRIES, tries + 1);
    for (unsigned i = 0; i < sizeof(switches) / sizeof(switches[0]); i++) {
        result = scratch_switch(switches[i], 1);
        if (result < 0) {
            return result;
        }
    }
    thread = ksceKernelCreateThread("retail_cp_rearm", devmode_rearm_thread, 0xA0, 0x1000, 0, 0, NULL);
    if (thread < 0 || (result = ksceKernelStartThread(thread, 0, NULL)) < 0) {
        return thread < 0 ? thread : result;
    }
    return 1;
}

/*
 * The "uninstall" word: the Vita back to a retail console. Development mode and hardware debug
 * live in Ernie's bootparam block, which survives the plugin, so they are cleared there and the
 * Vita restarts through Syscon (the raw reset always comes back; SKBL then reads a clear block).
 * The plugin files in ur0:tai/ and the reports in ur0:data/retail-debug/ are deleted first.
 * Refused while a taiHEN config still loads retail-cp: its next boot would arm both again.
 */
static int config_loads_plugin(const char *path)
{
    static const char name[] = "retail-cp.skprx";
    static char text[16384];
    SceUID file = ksceIoOpen(path, SCE_O_RDONLY, 0);
    int length;

    if (file < 0) {
        return 0;
    }
    length = ksceIoRead(file, text, sizeof(text) - 1);
    ksceIoClose(file);
    if (length <= 0) {
        return 0;
    }
    text[length] = '\0';
    for (const char *line = text; line; line = strchr(line, '\n'), line = line ? line + 1 : NULL) {
        while (*line == ' ' || *line == '\t') {
            line++;
        }
        if (*line == '#') {
            continue;
        }
        for (const char *at = line; *at && *at != '\n'; at++) {
            if (!strncmp(at, name, sizeof(name) - 1)) {
                return 1;
            }
        }
    }
    return 0;
}

/* What the install put on the Vita: the plugins in ur0:tai/ and retail-cp's reports. */
static void uninstall_files(void)
{
    static const char *const plugins[] = {
        "retail-cp.skprx", "dbgusb-retail.skprx", "dfmgr-retail.skprx",
        "syslibtrace-retail.skprx", "pamgr-retail.skprx", "ttyp-retail.skprx", "userp-retail.skprx",
        "ctrlp-retail.skprx", "loadp-retail.skprx", "drfp-retail.skprx", "dbgp-retail.skprx",
        "dtracep-retail.skprx", "vcp-retail.skprx"};
    static SceIoDirent entry;
    static char path[300];
    SceUID dir;

    for (unsigned i = 0; i < sizeof(plugins) / sizeof(plugins[0]); i++) {
        snprintf(path, sizeof(path), "ur0:tai/%s", plugins[i]);
        ksceIoRemove(path);
    }
    dir = ksceIoDopen("ur0:data/retail-debug");
    if (dir >= 0) {
        for (;;) {
            memset(&entry, 0, sizeof(entry));
            if (ksceIoDread(dir, &entry) <= 0) {
                break;
            }
            snprintf(path, sizeof(path), "ur0:data/retail-debug/%s", entry.d_name);
            ksceIoRemove(path);
        }
        ksceIoDclose(dir);
        ksceIoRmdir("ur0:data/retail-debug");
    }
}

int uninstall(void)
{
    static const unsigned switches[] = {DIPSW_DEVELOPMENT_MODE, DIPSW_SWITCH_HWDEBUG};
    int result;

    if (config_loads_plugin("ux0:tai/config.txt") || config_loads_plugin("ur0:tai/config.txt")) {
        ksceKernelPrintf("[retail-cp] uninstall: a taiHEN config.txt still loads retail-cp.skprx\n");
        return UNAVAILABLE;
    }
    for (unsigned i = 0; i < sizeof(switches) / sizeof(switches[0]); i++) {
        result = scratch_switch(switches[i], 0);
        if (result < 0) {
            return result;
        }
    }
    uninstall_files();
    devmode_restart("uninstall");
    return 0;
}
/*
 * Keep the Vita awake. A retail shell left without input suspends about 27 s after it comes
 * up (DfMgr's statuses 0x81 then 0x8E), which drops the USB link and,
 * on a debug target, every tool on it. A DevKit under a Target Manager stays up, so tick the
 * auto-suspend idle timer as an app with SCE_KERNEL_POWER_TICK_DISABLE_AUTO_SUSPEND does.
 * The screen still dims and turns off (appmgr_patch keeps the foreground app running then).
 * "power off" and the power button still work.
 */
#define AWAKE_TICK_US (5 * 1000 * 1000)

static int awake_loop(SceSize argc, void *argp)
{
    (void)argc;
    (void)argp;
    for (;;) {
        ksceKernelPowerTick(SCE_KERNEL_POWER_TICK_DISABLE_AUTO_SUSPEND);
        ksceKernelDelayThread(AWAKE_TICK_US);
    }
    return 0;
}

int awake_start(void)
{
    SceUID thread = ksceKernelCreateThread("retail_cp_awake", awake_loop, 0xA0, 0x1000, 0, 0, NULL);

    if (thread < 0) {
        return thread;
    }
    return ksceKernelStartThread(thread, 0, NULL);
}
