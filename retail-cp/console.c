/* The kernel console: SceSysmem's printf back in place, its lines forwarded to TTY. */
#include "retail-cp.h"

/*
 * The kernel console on retail. ksceKernelPrintf and friends (and SceSysmem's kernel
 * exception report) end in the debug putchar handler, which retail leaves without an output;
 * a DevKit's goes to the host's kernel console. This one only stores the characters in a RAM
 * ring (it is called on any core, at any interrupt state), and a thread forwards whole lines
 * to tty0:, the host's tty.log over TTYP, prefixed "[kernel] ". Registered after boot, so it
 * replaces any earlier handler, such as another plugin's. SceSysmem is the same on retail and DevKit: printf
 * calls the formatter at its data + 0x58 (0x81019ef4, text + 0x19ef4), which a setter beside
 * the registration (0x8101a13c) can replace; it is put back (console-formatter: 1 when it was
 * still SceSysmem's, else what was there).
 */
#define SYSMEM_PRINTF_FORMATTER 0x58 /* data */
#define SYSMEM_FORMATTER 0x19ef4 /* text */
#define CONSOLE_RING 0x4000u
#define CONSOLE_PERIOD_US (50 * 1000)

#define SYSMEM_PUTCHAR_HANDLER 0x5ca0 /* data: the handler; + 0x5c9c its argument */

static char console_ring[CONSOLE_RING];
static volatile unsigned console_head;
static int (*console_previous)(void *args, char c); /* the handler before ours */
static void *console_previous_args;

static int console_putchar(void *args, char c)
{
    (void)args;
    console_ring[__atomic_fetch_add(&console_head, 1, __ATOMIC_RELAXED) % CONSOLE_RING] = c;
    if (console_previous) {
        console_previous(console_previous_args, c);
    }
    return 0;
}

static int console_thread(SceSize argc, void *args)
{
    static char line[256];
    unsigned tail = 0, length = 0;
    SceUID tty = -1;

    (void)argc;
    (void)args;
    for (;; ksceKernelDelayThread(CONSOLE_PERIOD_US)) {
        const unsigned head = __atomic_load_n(&console_head, __ATOMIC_ACQUIRE);

        if (head - tail > CONSOLE_RING) {
            tail = head - CONSOLE_RING; /* overrun: the oldest are lost */
        }
        for (; tail != head; tail++) {
            const char c = console_ring[tail % CONSOLE_RING];

            if (!length) {
                memcpy(line, "[kernel] ", 9);
                length = 9;
            }
            line[length++] = c;
            if (c != '\n' && length < sizeof(line) - 1) {
                continue;
            }
            if (c != '\n') {
                line[length++] = '\n';
            }
            if (tty < 0) {
                tty = ksceIoOpen("tty0:", SCE_O_WRONLY, 0);
            }
            if (tty >= 0 && ksceIoWrite(tty, line, length) < 0) {
                ksceIoClose(tty);
                tty = -1;
            }
            length = 0;
        }
    }
    return 0;
}

int console_start(void)
{
    SceUID thread = ksceKernelCreateThread("retail_cp_console", console_thread, 0x60, 0x2000, 0, 0, NULL);
    int result;

    if (thread < 0) {
        return thread;
    }
    result = ksceKernelStartThread(thread, 0, NULL);
    if (result < 0) {
        return result;
    }
    {
        tai_module_info_t tai = {.size = sizeof(tai)};
        SceKernelModuleInfo module = {.size = sizeof(module)};

        if (taiGetModuleInfoForKernel(KERNEL_PID, "SceSysmem", &tai) >= 0 &&
            ksceKernelGetModuleInfo(KERNEL_PID, tai.modid, &module) >= 0 && module.segments[0].memsz == 0x2f280 &&
            module.segments[1].memsz == 0x7604) {
            volatile uint32_t *formatter =
                (volatile uint32_t *)((uintptr_t)module.segments[1].vaddr + SYSMEM_PRINTF_FORMATTER);
            const uint32_t own = (uint32_t)(uintptr_t)module.segments[0].vaddr + SYSMEM_FORMATTER + 1; /* Thumb */

            const uintptr_t data = (uintptr_t)module.segments[1].vaddr;

            record("console-formatter", *formatter == own ? 1 : (int)*formatter);
            *formatter = own;
            console_previous_args = *(void *volatile *)(data + SYSMEM_PUTCHAR_HANDLER - 4);
            console_previous = *(int (*volatile *)(void *, char))(data + SYSMEM_PUTCHAR_HANDLER);
            record("console-previous", (int)(uintptr_t)console_previous);
        }
    }
    ksceKernelRegisterDebugPutcharHandler(console_putchar, NULL);
    ksceKernelPrintf("[retail-cp] kernel console over TTYP\n");
    return 0;
}
