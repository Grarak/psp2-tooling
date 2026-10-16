/* ur0:data/retail-debug/cp.txt, the boot's report: one stage=value line per step. */
#include "retail-cp.h"

int report_failed;
static const char *report_path = REPORT_PATH;

int report_write(const char *text, int length)
{
    SceUID file;
    int offset = 0;

    if (length < 0) {
        report_failed = 1;
        return -1;
    }
    file = ksceIoOpen(report_path, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_APPEND, 0666);
    if (file < 0) {
        report_failed = 1;
        return file;
    }
    while (offset < length) {
        int count = ksceIoWrite(file, text + offset, length - offset);

        if (count <= 0 || count > length - offset) {
            ksceIoClose(file);
            report_failed = 1;
            return -1;
        }
        offset += count;
    }
    int result = ksceIoClose(file);

    if (result < 0) {
        report_failed = 1;
    }
    return result;
}

int record(const char *stage, int value)
{
    char text[112];
    int length = snprintf(text, sizeof(text), "%s=%d\n", stage, value);

    ksceKernelPrintf("[retail-cp] %s=%08x\n", stage, value);
    if (length < 0 || (unsigned)length >= sizeof(text)) {
        report_failed = 1;
        return -1;
    }
    return report_write(text, length);
}

int record_text(const char *stage, const char *value)
{
    char text[448];
    int length = snprintf(text, sizeof(text), "%s=%s\n", stage, value);

    ksceKernelPrintf("[retail-cp] %s=%s\n", stage, value);
    if (length < 0 || (unsigned)length >= sizeof(text)) {
        report_failed = 1;
        return -1;
    }
    return report_write(text, length);
}
