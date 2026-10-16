#include <psp2/io/dirent.h>
#include <psp2/io/fcntl.h>
#include <psp2/io/stat.h>
#include <psp2/kernel/clib.h>
#include <psp2/kernel/processmgr.h>
#include <psp2/promoterutil.h>
#include <psp2/sysmodule.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int copy_tree(const char *source, const char *destination)
{
    SceUID directory = sceIoDopen(source);
    if (directory < 0) {
        SceUID input = sceIoOpen(source, SCE_O_RDONLY, 0);
        if (input < 0)
            return input;
        SceUID output = sceIoOpen(destination, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0777);
        if (output < 0) {
            sceIoClose(input);
            return output;
        }
        char buffer[8192];
        int result;
        while ((result = sceIoRead(input, buffer, sizeof(buffer))) > 0) {
            int written = 0;
            while (written < result) {
                int count = sceIoWrite(output, buffer + written, result - written);
                if (count <= 0) {
                    sceIoClose(input);
                    sceIoClose(output);
                    return count < 0 ? count : -1;
                }
                written += count;
            }
        }
        sceIoClose(input);
        int close_result = sceIoClose(output);
        return result < 0 ? result : close_result;
    }
    sceIoMkdir(destination, 0777);
    SceIoDirent entry;
    int result;
    memset(&entry, 0, sizeof(entry));
    while ((result = sceIoDread(directory, &entry)) > 0) {
        if (strcmp(entry.d_name, ".") && strcmp(entry.d_name, "..")) {
            char source_path[1024], destination_path[1024];
            int source_length = snprintf(source_path, sizeof(source_path), "%s/%s", source, entry.d_name);
            int destination_length = snprintf(destination_path, sizeof(destination_path), "%s/%s", destination, entry.d_name);
            if (source_length < 0 || source_length >= (int)sizeof(source_path) ||
                destination_length < 0 || destination_length >= (int)sizeof(destination_path)) {
                result = -1;
                break;
            }
            result = copy_tree(source_path, destination_path);
            if (result < 0)
                break;
        }
        memset(&entry, 0, sizeof(entry));
    }
    sceIoDclose(directory);
    return result;
}

int main(void)
{
    const char *package = "ux0:data/vpk-promoter-package";
    sceClibPrintf("[vpk-promoter] copying package\n");
    sceIoMkdir("ux0:data", 0777); /* a freshly formatted card has none */
    int result = copy_tree("host0:/package", package);
    sceClibPrintf("[vpk-promoter] copy: 0x%08X\n", result);
    if (result < 0)
        return 1;
    uint32_t arguments[] = {0x180000, UINT32_MAX, UINT32_MAX, 1, UINT32_MAX, UINT32_MAX};
    int module_result = -1;
    SceSysmoduleOpt options = {16, &module_result, {-1, -1}};
    result = sceSysmoduleLoadModuleInternalWithArg(SCE_SYSMODULE_INTERNAL_PAF,
                                                  sizeof(arguments), arguments, &options);
    sceClibPrintf("[vpk-promoter] PAF: 0x%08X module: 0x%08X\n", result, module_result);
    if (result < 0 || module_result < 0)
        return 1;
    result = sceSysmoduleLoadModuleInternal(SCE_SYSMODULE_INTERNAL_PROMOTER_UTIL);
    sceClibPrintf("[vpk-promoter] module: 0x%08X\n", result);
    if (result < 0)
        return 1;
    result = scePromoterUtilityInit();
    sceClibPrintf("[vpk-promoter] init: 0x%08X\n", result);
    if (result < 0)
        return 1;
    result = scePromoterUtilityPromotePkgWithRif(package, 1);
    sceClibPrintf("[vpk-promoter] promote: 0x%08X\n", result);
    int operation = -1;
    int query = scePromoterUtilityGetResult(&operation);
    sceClibPrintf("[vpk-promoter] result query: 0x%08X operation: 0x%08X\n", query, operation);
    int cleanup = scePromoterUtilityExit();
    sceClibPrintf("[vpk-promoter] exit: 0x%08X\n", cleanup);
    sceSysmoduleUnloadModuleInternal(SCE_SYSMODULE_INTERNAL_PROMOTER_UTIL);
    SceSysmoduleOpt unload_options = {0};
    sceSysmoduleUnloadModuleInternalWithArg(SCE_SYSMODULE_INTERNAL_PAF, 0, NULL, &unload_options);
    sceClibPrintf("[vpk-promoter] finished\n");
    sceKernelExitProcess(result < 0 || query < 0 || operation < 0);
    return 0;
}
