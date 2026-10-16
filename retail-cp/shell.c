/* SceShell and AppMgr: when the shell is ready, apps that keep running with the screen off,
 * taiHEN's *main plugins kept out of spawned processes, and no lock screen. */
#include "retail-cp.h"

volatile int shell_ready; /* the shell reported ready (shell_status) */

/*
 * When the shell is ready. It reports ready once, through vshbridge (NID 0x71D9DB5C,
 * "vshbridge : shell ready"), which calls sysroot's shell-status dispatch (SceSysmem
 * 0x81020274, the slot DfMgr's callback sits in) with 0, about 14 s after power-on on the
 * PCH-2000. load_services waits for it.
 */
#define SYSROOT_SHELL_STATUS 0x20274
#define SHELL_READY_WAIT_US (120u * 1000 * 1000)

static tai_hook_ref_t shell_status_ref;
volatile unsigned shell_ready_ms; /* when it reported ready, ms after power-on */

static void shell_status(int status)
{
    if (status == 0 && !shell_ready) {
        shell_ready_ms = (unsigned)(ksceKernelGetSystemTimeWide() / 1000);
        shell_ready = 1;
        ksceKernelPrintf("[retail-cp] shell ready\n");
    }
    TAI_CONTINUE(void, shell_status_ref, status);
}

int shell_ready_install(void)
{
    static const unsigned char push[] = {0x08, 0xb5};
    static const unsigned char body[] = {0x1b, 0x68, 0xd3, 0xf8, 0xa8, 0x33, 0x03, 0xb1, 0x98, 0x47, 0x08, 0xbd};
    tai_module_info_t tai = {.size = sizeof(tai)};
    SceKernelModuleInfo module = {.size = sizeof(module)};
    const char *text;
    int result = taiGetModuleInfoForKernel(KERNEL_PID, "SceSysmem", &tai);

    if (result < 0 || (result = ksceKernelGetModuleInfo(KERNEL_PID, tai.modid, &module)) < 0) {
        return result;
    }
    text = module.segments[0].vaddr;
    if (module.segments[0].memsz != 0x2f280 || memcmp(text + SYSROOT_SHELL_STATUS, push, sizeof(push)) ||
        memcmp(text + SYSROOT_SHELL_STATUS + 0x0a, body, sizeof(body))) {
        return UNAVAILABLE;
    }
    return taiHookFunctionOffsetForKernel(KERNEL_PID, &shell_status_ref, tai.modid, 0, SYSROOT_SHELL_STATUS, 1,
                                          shell_status);
}

/* When the screen turns off, SceShell has AppMgr suspend the foreground app (3.65
 * FUN_8100acb0, via ProcessMgr's process stop): every thread of an app being profiled freezes
 * mid-session. Its only way out is development mode while some
 * process is debug-suspended. The blx to ksceSblACMgrIsDevelopmentMode that starts that check
 * (0x8100ad12) becomes a branch to the function's `return 0` (0x8100ad0e): the screen still
 * turns off, the app keeps running. */
#define APPMGR_SCREEN_OFF_SUSPEND 0xad12

/* A process LOADP spawns without SceAppMgr has no title of its own, so taiHEN's
 * start_preloaded_modules hook reads the title "main" and loads SceShell's *main plugins
 * into it; a spawned app then stalls right
 * after its first lines. taiHEN's title read answers "SPAWNPROC" instead for any process
 * that is not the running shell, so only *ALL (and a *SPAWNPROC section, if one is written)
 * applies to it. */
#define SYSROOT_GET_PROCESS_TITLE_ID_NID 0xec3124a3
#define SPAWN_TITLE "SPAWNPROC"

static tai_hook_ref_t spawn_title_ref;

/*
 * No lock screen: SceShell boots straight to the home screen, as on a DevKit. power_manage_plugin's
 * startup handler (SceShell 3.65 0x8123553a) shows the keylock (mode 0) unless a wakeup factor or
 * one of a few shell states says otherwise; those take the "unlocked" path (mode 2), which also
 * opens the home screen. The first of those checks is
 *
 *   81235572  2801  cmp r0, #1
 *   81235574  d017  beq 0x812355a6    ; the unlocked path
 *
 * and that beq becomes a b. A passcode still asks for it on that path. The shell's title read
 * comes when taiHEN starts its *main plugins, after SceShell is loaded and before it starts.
 */
#define SHELL_KEYLOCK_BRANCH 0x235574 /* segment 0 starts at 0x81000000 */

static SceUID shell_unlocked = -1;

static void shell_unlock(SceUID pid)
{
    static const unsigned char before[] = {0x01, 0x28, 0x17, 0xd0};
    static const unsigned char after[] = {0x17, 0xe0}; /* b 0x812355a6 */
    tai_module_info_t tai = {.size = sizeof(tai)};
    SceKernelModuleInfo module = {.size = sizeof(module)};
    unsigned char code[sizeof(before)];
    SceUID modid = -1;
    int result;

    if (pid == shell_unlocked) {
        return;
    }
    shell_unlocked = pid;
    /* taiHEN names a process's module by its user UID; the kernel calls take the kernel one. */
    if ((result = taiGetModuleInfoForKernel(pid, "SceShell", &tai)) >= 0 &&
        (result = modid = ksceKernelKernelUidForUserUid(pid, tai.modid)) >= 0 &&
        (result = ksceKernelGetModuleInfo(pid, modid, &module)) >= 0 &&
        (result = ksceKernelCopyFromUserProc(pid, code, (const char *)module.segments[0].vaddr +
                                                            SHELL_KEYLOCK_BRANCH - 2, sizeof(code))) >= 0) {
        result = memcmp(code, before, sizeof(before))
                     ? UNAVAILABLE
                     : taiInjectDataForKernel(pid, modid, 0, SHELL_KEYLOCK_BRANCH, after, sizeof(after));
    }
    record("shell-keylock", result);
}

static int spawn_title(SceUID pid, char *titleid, SceSize len)
{
    int result = TAI_CONTINUE(int, spawn_title_ref, pid, titleid, len);
    SceUID shell;

    if (result >= 0 && titleid && len > sizeof(SPAWN_TITLE) - 1 && !strcmp(titleid, "main")) {
        if ((shell = ksceKernelSysrootGetShellPid()) > 0 && pid != shell) {
            memcpy(titleid, SPAWN_TITLE, sizeof(SPAWN_TITLE));
        } else {
            shell_unlock(pid);
        }
    }
    return result;
}

int spawn_title_hook(void)
{
    return taiHookFunctionImportForKernel(KERNEL_PID, &spawn_title_ref, "taihen", TAI_ANY_LIBRARY,
                                          SYSROOT_GET_PROCESS_TITLE_ID_NID, spawn_title);
}

int appmgr_patch(void)
{
    static const unsigned char before[] = {0x1d, 0xf0, 0xd2, 0xeb};
    static const unsigned char after[] = {0xfc, 0xe7, 0x00, 0xbf}; /* b 0x8100ad0e; nop */
    tai_module_info_t tai = {.size = sizeof(tai)};
    SceKernelModuleInfo module = {.size = sizeof(module)};
    int result = taiGetModuleInfoForKernel(KERNEL_PID, "SceAppMgr", &tai);

    if (result < 0) {
        return result;
    }
    result = ksceKernelGetModuleInfo(KERNEL_PID, tai.modid, &module);
    if (result < 0) {
        return result;
    }
    if (module.segments[0].memsz < APPMGR_SCREEN_OFF_SUSPEND + sizeof(before) ||
        memcmp((const char *)module.segments[0].vaddr + APPMGR_SCREEN_OFF_SUSPEND, before, sizeof(before))) {
        return UNAVAILABLE;
    }
    return taiInjectDataForKernel(KERNEL_PID, tai.modid, 0, APPMGR_SCREEN_OFF_SUSPEND, after, sizeof(after));
}
