/* DTrace on retail: threadmgr's DTrace heap, and dtracep's PMEP thread and reply faults. */
#include "retail-cp.h"

/* dtracep's attach calls SceThreadmgrForKernel_0AE9C713(1), which on first
 * use creates threadmgr's own 128-KiB "SceDtraceThreadCB" heap on the Tool
 * partition (0x10f0d006) and panics when retail refuses it (3.65 0x810297a8,
 * LR 0x8101e7c9). Its movt at 0x810298c6 becomes retail
 * PhyCont (0x1080d006), as in the ported modules; any other threadmgr keeps dtracep out. */
#define THREADMGR_DTRACE_MEMTYPE 0x298c6

int threadmgr_patch(void)
{
    static const unsigned char before[] = {0xc1, 0xf2, 0xf0, 0x03};
    static const unsigned char after[] = {0xc1, 0xf2, 0x80, 0x03};
    tai_module_info_t tai = {.size = sizeof(tai)};
    SceKernelModuleInfo module = {.size = sizeof(module)};
    int result = taiGetModuleInfoForKernel(KERNEL_PID, "SceKernelThreadMgr", &tai);

    if (result < 0) {
        return result;
    }
    result = ksceKernelGetModuleInfo(KERNEL_PID, tai.modid, &module);
    if (result < 0) {
        return result;
    }
    if (module.segments[0].memsz < THREADMGR_DTRACE_MEMTYPE + sizeof(before) ||
        memcmp((const char *)module.segments[0].vaddr + THREADMGR_DTRACE_MEMTYPE, before, sizeof(before))) {
        return UNAVAILABLE;
    }
    return taiInjectDataForKernel(KERNEL_PID, tai.modid, 0, THREADMGR_DTRACE_MEMTYPE, after, sizeof(after));
}

/*
 * DTRACEP_PMEP, off. Every DTrace open registers this second DfMgr port (protocol 0x4000;
 * dtracep FUN_81003eec) and starts SceDeci4pDtracepPmep (0x1e, core 3), which asks for a host
 * message and waits for it on event flag bit 1 with no timeout. Sony's host tools send one
 * (a table of names and values for D variables 0x208-0x20f); psp2-tooling's never does. Close
 * (FUN_81003fbc) sets bit 2, which that wait ignores, waits 2 s for the thread, fails to
 * delete it, and deletes the event flag under it. The orphan then runs its state machine on
 * dead objects: either it spins at 0x1e on core 3, where SceShell, IoFileMgr and most of the
 * system run (the "hang": session 1's close never answered, FTP and the shell dead), or a wait
 * error reaches its ksceKernelPanic (FUN_81003c2c) and core 3 stops in a kernel exception (the
 * link dead too). Which one, and when, depends on the next open reusing its globals.
 * The setup becomes a no-op returning 0: no port, no
 * thread, and close skips the teardown (its "registered" flag stays 0).
 */
#define DTRACE_PMEP_SETUP 0x3eec

static tai_hook_ref_t pmep_ref;

static int pmep_setup(void *names)
{
    (void)names;
    return 0;
}

int dtrace_pmep_off(void)
{
    static const unsigned char push[] = {0xf0, 0xb5};
    static const unsigned char body[] = {0x91, 0xb0, 0x33, 0x68, 0x2c, 0x68, 0xa8, 0x62, 0x0f, 0x93, 0x00, 0x2c};
    tai_module_info_t tai = {.size = sizeof(tai)};
    SceKernelModuleInfo module = {.size = sizeof(module)};
    const char *text;
    int result = taiGetModuleInfoForKernel(KERNEL_PID, "SceDeci4pDtracep", &tai);

    if (result < 0 || (result = ksceKernelGetModuleInfo(KERNEL_PID, tai.modid, &module)) < 0) {
        return result;
    }
    text = module.segments[0].vaddr;
    if (module.segments[0].memsz != 0x25514 || memcmp(text + DTRACE_PMEP_SETUP, push, sizeof(push)) ||
        memcmp(text + DTRACE_PMEP_SETUP + 0x12, body, sizeof(body))) {
        return UNAVAILABLE;
    }
    return taiHookFunctionOffsetForKernel(KERNEL_PID, &pmep_ref, tai.modid, 0, DTRACE_PMEP_SETUP, 1, pmep_setup);
}

/*
 * dtracep's replies, made safe. Each reply is a 0x1c-byte descriptor plus its own 68-KiB block
 * ("SceDeci4pDtracepPacket", FUN_8100335c), queued on the port's send queue before a send
 * request (DfMgr BADEF855). DfMgr's sender then calls the port callback with 3 until it
 * returns 0x80080008 ("nothing more"), then with 4 (DfMgrSendHandler). dtracep's case 3 pops
 * a reply and writes it without checking the queue, and never answers 0x80080008: when its
 * entry is queued once more than it has replies (two replies back to back, as hello's, race the
 * sender), it pops NULL and reads NULL + 0x14 (core 3, during an open). Case 4 frees the sent
 * blocks only once the queue is empty. On retail the blocks were patched to KD, a few MiB, and
 * an allocation that fails returns NULL, which the reply builder writes through (NULL + 0xc,
 * during sampling). So: case 3 on an empty queue answers 0x80080008; the blocks come from
 * PhyCont (26 MiB) as the DTrace heap does; and a failed allocation is retried for up to 1 s,
 * counted, before dtracep gets NULL.
 */
#define DTRACE_CALLBACK 0xa80
#define DTRACE_PACKET 0x335c
#define DTRACE_QUEUE_EMPTY 0x3268
#define DFMGR_NO_MORE_DATA ((int)0x80080008)
#define DTRACE_PACKET_RETRIES 100
#define DTRACE_PACKET_RETRY_US (10 * 1000)

typedef int (*dtrace_queue_empty_t)(void *queue);

static dtrace_queue_empty_t dtrace_queue_empty;
static tai_hook_ref_t dtrace_callback_ref, dtrace_packet_ref, dtrace_block_ref;
volatile uint32_t dtrace_empty_sends, dtrace_packet_failures;

static int dtrace_callback(int event, int arg, uint32_t *port)
{
    if (event == 3 && port && dtrace_queue_empty((void *)(uintptr_t)port[6])) {
        __atomic_fetch_add(&dtrace_empty_sends, 1, __ATOMIC_RELAXED);
        return DFMGR_NO_MORE_DATA;
    }
    return TAI_CONTINUE(int, dtrace_callback_ref, event, arg, port);
}

static void *dtrace_packet(void)
{
    for (unsigned attempt = 0; attempt < DTRACE_PACKET_RETRIES; attempt++) {
        void *packet = TAI_CONTINUE(void *, dtrace_packet_ref);

        if (packet) {
            return packet;
        }
        __atomic_fetch_add(&dtrace_packet_failures, 1, __ATOMIC_RELAXED);
        ksceKernelDelayThread(DTRACE_PACKET_RETRY_US);
    }
    return NULL;
}

static SceUID dtrace_block(const char *name, SceKernelMemBlockType type, SceSize size, void *opt)
{
    if (name && !strcmp(name, "SceDeci4pDtracepPacket")) {
        type = 0x1080d006; /* PhyCont */
    }
    return TAI_CONTINUE(SceUID, dtrace_block_ref, name, type, size, opt);
}

int dtrace_send_fix(void)
{
    static const unsigned char callback[] = {0x01, 0x38, 0x70, 0xb5, 0x14, 0x46, 0x04, 0x28, 0x27, 0xd8, 0xdf, 0xe8};
    static const unsigned char packet_push[] = {0x30, 0xb5};
    static const unsigned char packet[] = {0x0b, 0x20}; /* +0x0a, after the relocated movw/movt */
    static const unsigned char queue_empty[] = {0x38, 0xb5, 0x04, 0x46, 0x05, 0x46, 0x01, 0xcc, 0x00, 0x22, 0x01, 0x21};
    tai_module_info_t tai = {.size = sizeof(tai)};
    SceKernelModuleInfo module = {.size = sizeof(module)};
    const char *text;
    int result = taiGetModuleInfoForKernel(KERNEL_PID, "SceDeci4pDtracep", &tai);

    if (result < 0 || (result = ksceKernelGetModuleInfo(KERNEL_PID, tai.modid, &module)) < 0) {
        return result;
    }
    text = module.segments[0].vaddr;
    if (module.segments[0].memsz != 0x25514 || memcmp(text + DTRACE_CALLBACK, callback, sizeof(callback)) ||
        memcmp(text + DTRACE_PACKET, packet_push, sizeof(packet_push)) ||
        memcmp(text + DTRACE_PACKET + 0x0a, packet, sizeof(packet)) ||
        memcmp(text + DTRACE_QUEUE_EMPTY, queue_empty, sizeof(queue_empty))) {
        return UNAVAILABLE;
    }
    dtrace_queue_empty = (dtrace_queue_empty_t)(uintptr_t)(text + DTRACE_QUEUE_EMPTY + 1); /* Thumb */
    result = taiHookFunctionImportForKernel(KERNEL_PID, &dtrace_block_ref, "SceDeci4pDtracep", TAI_ANY_LIBRARY,
                                            0xc94850c9 /* ksceKernelAllocMemBlock */, dtrace_block);
    if (result < 0) {
        return result;
    }
    result = taiHookFunctionOffsetForKernel(KERNEL_PID, &dtrace_packet_ref, tai.modid, 0, DTRACE_PACKET, 1,
                                            dtrace_packet);
    if (result < 0) {
        return result;
    }
    return taiHookFunctionOffsetForKernel(KERNEL_PID, &dtrace_callback_ref, tai.modid, 0, DTRACE_CALLBACK, 1,
                                          dtrace_callback);
}
