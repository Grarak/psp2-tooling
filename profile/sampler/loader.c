// psp2prof's loader: an app (PSP2PROF0) that loads the plugin it carries through taiHEN and
// exits. Install psp2prof.vpk once (devkit/vpk_promoter), then launch PSP2PROF0 once a boot;
// the plugin stays loaded until a reboot. taiHEN gives its unsafe imports (the kernel module
// load) only to installed unsafe apps, not to a SELF launched from host0:.
#include <psp2/kernel/clib.h>
#include <psp2/kernel/processmgr.h>
#include <taihen.h>

#define PLUGIN "ux0:app/PSP2PROF0/psp2prof.skprx"

int main(void) {
    const SceUID module = taiLoadStartKernelModule(PLUGIN, 0, NULL, 0);
    // 0x8002D013: loaded already (an earlier launch this boot).
    sceClibPrintf("[psp2prof] load " PLUGIN ": 0x%08X\n", (unsigned)module);
    sceKernelExitProcess(0);
    return 0;
}
