/* The USB port: MTP gives way to DECI4p, other plugins' USB drivers share the device, and
 * dbgusb's lost wakeup when a host connects early. */
#include "retail-cp.h"

unsigned mtp_yields;

/*
 * The Vita's one USB port is the DECI4p link here (a DevKit's dbgusb has a bus of its own).
 * The shell starts MTP (Content Manager over USB) at boot, sceMtpIfStartPort fails with
 * 0x80543601 while dbgusb holds the controller, and the shell treats that as fatal
 * (mtpWrapperInitialize: sceMtpStart failed 0x80540008, then an abort). MTP cannot work
 * on this cable anyway, so the failure is reported as success and MTP never connects.
 */
#define MTP_PORT_BUSY 0x80543601
static tai_hook_ref_t mtp_start_port_ref;

static int mtp_start_port(int port, void *options)
{
    int result = TAI_CONTINUE(int, mtp_start_port_ref, port, options);

    if (result == (int)MTP_PORT_BUSY) {
        __atomic_add_fetch(&mtp_yields, 1, __ATOMIC_RELAXED);
        return 0;
    }
    return result;
}

int mtp_yield(void)
{
    return taiHookFunctionExportForKernel(KERNEL_PID, &mtp_start_port_ref, "SceMtpIfDriver", TAI_ANY_LIBRARY,
                                          0x1624280e /* sceMtpIfStartPort */, mtp_start_port);
}

/*
 * Other USB functions share the port. udcd makes one composite device of every driver linked on
 * a bus: interface numbers and endpoints are assigned in link order (udcd's
 * endpoint assignment and configuration descriptor). A plugin such as udcd_uvc takes the port for
 * itself instead: 15 s after the first frame it deactivates the bus, restarts the bus driver and
 * activates its own driver alone. With dbgusb linked the bus driver
 * does not stop (0x80243006), the plugin gives up, and DECI4p is left deactivated.
 *
 * So the drivers that plugins register after this one join DECI4p's device. They are started
 * just before dbgusb's own driver, which keeps them first, at the interface and endpoint numbers
 * their descriptors hard-code, and dbgusb's one activation brings the port up with all of them.
 * A plugin's takeover later finds its driver running: deactivating, stopping or starting the bus
 * driver or a linked driver, and activating, succeed without touching the port. Any other driver
 * still fails to start. udcd lets drivers share a device only when each has device class 0;
 * ActivateInternal's check (0x810035c8: cbz when one driver is linked) always skips, so the
 * device keeps the first driver's class (udcd_uvc's EF/02/01, with its IAD).
 */
#define USB_BUS_DRIVER "USBDeviceControllerDriver"
#define USB_DBGUSB_DRIVER "USB_DbgUsb_Driver"
#define USB_MEMBERS_MAX 4
#define UDCD_SHARED_DEVICE_CHECK 0x35c8


static const char *usb_members[USB_MEMBERS_MAX];
int usb_member_count;
int usb_shared;      /* dbgusb's device is up: takeovers become no-ops */
static tai_hook_ref_t udcd_register_ref;
static tai_hook_ref_t udcd_start_internal_ref;
static tai_hook_ref_t udcd_deactivate_ref;
static tai_hook_ref_t udcd_start_ref;
static tai_hook_ref_t udcd_stop_ref;
static tai_hook_ref_t udcd_activate_ref;

static int usb_linked(const char *name)
{
    if (!name) {
        return 0;
    }
    if (!strncmp(name, USB_BUS_DRIVER, 0x40)) {
        return 1;
    }
    for (int i = 0; i < usb_member_count; i++) {
        if (!strncmp(name, usb_members[i], 0x40)) {
            return 1;
        }
    }
    return 0;
}

static int udcd_register(SceUdcdDriver *driver)
{
    int result = TAI_CONTINUE(int, udcd_register_ref, driver);

    if (result >= 0 && !usb_shared && usb_member_count < USB_MEMBERS_MAX && driver->driverName) {
        usb_members[usb_member_count++] = driver->driverName;
    }
    return result;
}

static int udcd_start_internal(const char *name, int size, void *args, int bus)
{
    if (bus == USB_BUS && name && !strncmp(name, USB_DBGUSB_DRIVER, 0x40)) {
        for (int i = 0; i < usb_member_count; i++) {
            char stage[80];

            snprintf(stage, sizeof(stage), "usb-shared-%s", usb_members[i]);
            record(stage, TAI_CONTINUE(int, udcd_start_internal_ref, usb_members[i], 0, NULL, USB_BUS));
        }
        int result = TAI_CONTINUE(int, udcd_start_internal_ref, name, size, args, bus);

        usb_shared = result >= 0;  /* dbgusb activates the bus next; setup clears it if that fails */
        return result;
    }
    return TAI_CONTINUE(int, udcd_start_internal_ref, name, size, args, bus);
}

static int usb_kept(const char *call, const char *name)
{
    char stage[80];

    snprintf(stage, sizeof(stage), "usb-kept-%s%s%s", call, name ? "-" : "", name ? name : "");
    record(stage, 0);
    return 0;
}

static int udcd_deactivate(void)
{
    return usb_shared ? usb_kept("deactivate", NULL) : TAI_CONTINUE(int, udcd_deactivate_ref);
}

static int udcd_start(const char *name, int size, void *args)
{
    return usb_shared && usb_linked(name) ? usb_kept("start", name)
                                          : TAI_CONTINUE(int, udcd_start_ref, name, size, args);
}

static int udcd_stop(const char *name, int size, void *args)
{
    return usb_shared && usb_linked(name) ? usb_kept("stop", name)
                                          : TAI_CONTINUE(int, udcd_stop_ref, name, size, args);
}

static int udcd_activate(unsigned int product)
{
    return usb_shared ? usb_kept("activate", NULL) : TAI_CONTINUE(int, udcd_activate_ref, product);
}

int usb_share(void)
{
    static const struct {
        tai_hook_ref_t *ref;
        uint32_t nid;
        const void *hook;
    } hooks[] = {
        {&udcd_register_ref, 0x4e55244d /* ksceUdcdRegister */, udcd_register},
        {&udcd_start_internal_ref, 0x90f8bcae /* ksceUdcdStartInternal */, udcd_start_internal},
        {&udcd_deactivate_ref, 0x8ae87657 /* ksceUdcdDeactivate */, udcd_deactivate},
        {&udcd_start_ref, 0x9fd733ea /* ksceUdcdStart */, udcd_start},
        {&udcd_stop_ref, 0x1494293b /* ksceUdcdStop */, udcd_stop},
        {&udcd_activate_ref, 0x4fdea423 /* ksceUdcdActivate */, udcd_activate},
    };
    static const unsigned char before[] = {0x3f, 0xb1, 0x93, 0x69, 0x1b, 0x79};
    static const unsigned char after[] = {0x07, 0xe0}; /* b 0x810035da */
    tai_module_info_t tai = {.size = sizeof(tai)};
    SceKernelModuleInfo module = {.size = sizeof(module)};
    int result = taiGetModuleInfoForKernel(KERNEL_PID, "SceUdcd", &tai);

    if (result < 0) {
        return result;
    }
    result = ksceKernelGetModuleInfo(KERNEL_PID, tai.modid, &module);
    if (result < 0) {
        return result;
    }
    if (module.segments[0].memsz < UDCD_SHARED_DEVICE_CHECK + sizeof(before) ||
        memcmp((const char *)module.segments[0].vaddr + UDCD_SHARED_DEVICE_CHECK, before, sizeof(before))) {
        return UNAVAILABLE;
    }
    result = taiInjectDataForKernel(KERNEL_PID, tai.modid, 0, UDCD_SHARED_DEVICE_CHECK, after, sizeof(after));
    if (result < 0) {
        return result;
    }
    for (unsigned i = 0; i < sizeof(hooks) / sizeof(hooks[0]); i++) {
        result = taiHookFunctionExportForKernel(KERNEL_PID, hooks[i].ref, "SceUdcd", TAI_ANY_LIBRARY,
                                                hooks[i].nid, hooks[i].hook);
        if (result < 0) {
            return result;
        }
    }
    return 0;
}

/*
 * A lost wakeup in dbgusb. Its receive-complete (3.65 DevKit dbgusb 0x810001c8) queues a host
 * transfer on the done list and raises DfMgr's data bit (event flag bit 2) only while its
 * status has 0x11: bound to DfMgr (bit 0, DbgUsbBind) and configured (0x10, attach). dbgusb
 * loads, and the PC can configure the device, before dfmgr loads and binds; a host that sends as
 * soon as the device appears has its first transfers queued without the data bit, and binding
 * or the next attach raise only "configured" (bit 4, through the status thread). Nothing reads
 * the done list again: both OUT buffers stay on it, dbgusb arms no further OUT transfer, and the
 * Vita takes nothing the host sends for the rest of the boot (2026-10-16, a host connecting as
 * the Vita enumerates: DfMgr's receive thread idle on its flag, SceDbgUsbReadQueue waiting on
 * SceDbgUsbFreeFifo). A DevKit's host connects through the CP, after DfMgr is up. After every
 * attach and bind this raises the data bit when the done list holds a transfer; DbgUsbRead
 * raises it again while data is left. The state block is at dbgusb data +0x168: the done list at
 * +0x10, DfMgr's event flag at +0x144.
 */
#define DBGUSB_ATTACH 0x0c
#define DBGUSB_STATE 0x168
#define DBGUSB_DONE_LIST 0x10
#define DBGUSB_DFMGR_FLAG 0x144

static tai_hook_ref_t dbgusb_attach_ref;
static tai_hook_ref_t dbgusb_bind_ref;
static uintptr_t dbgusb_state;
volatile unsigned dbgusb_wakes;

static void dbgusb_wake_pending(void)
{
    const uintptr_t done = dbgusb_state + DBGUSB_DONE_LIST;
    const SceUID dfmgr = *(volatile SceUID *)(dbgusb_state + DBGUSB_DFMGR_FLAG);

    if (dfmgr > 0 && *(volatile uintptr_t *)done != done) {
        ksceKernelSetEventFlag(dfmgr, 2);
        dbgusb_wakes++;
    }
}

static int dbgusb_attach(int usb_version, void *user_data)
{
    int result = TAI_CONTINUE(int, dbgusb_attach_ref, usb_version, user_data);

    dbgusb_wake_pending();
    return result;
}

static int dbgusb_bind(SceUID event_flag)
{
    int result = TAI_CONTINUE(int, dbgusb_bind_ref, event_flag);

    dbgusb_wake_pending();
    return result;
}

int dbgusb_attach_fix(void)
{
    static const unsigned char push[] = {0x08, 0xb5};
    static const unsigned char flag[] = {0x10, 0x21}; /* +0x0a, after the relocated movw/movt */
    static const unsigned char pop[] = {0x08, 0xbd};
    tai_module_info_t tai = {.size = sizeof(tai)};
    SceKernelModuleInfo module = {.size = sizeof(module)};
    const char *text;
    int result = taiGetModuleInfoForKernel(KERNEL_PID, "SceDbgUsb", &tai);

    if (result < 0 || (result = ksceKernelGetModuleInfo(KERNEL_PID, tai.modid, &module)) < 0) {
        return result;
    }
    text = module.segments[0].vaddr;
    if (module.segments[0].memsz != 0x12f4 || module.segments[1].memsz != 0x3d0 ||
        memcmp(text + DBGUSB_ATTACH, push, sizeof(push)) || memcmp(text + DBGUSB_ATTACH + 0x0a, flag, sizeof(flag)) ||
        memcmp(text + DBGUSB_ATTACH + 0x18, pop, sizeof(pop))) {
        return UNAVAILABLE;
    }
    dbgusb_state = (uintptr_t)module.segments[1].vaddr + DBGUSB_STATE;
    result = taiHookFunctionExportForKernel(KERNEL_PID, &dbgusb_bind_ref, "SceDbgUsb", TAI_ANY_LIBRARY,
                                            0xa6bfcc0a /* DbgUsbBind */, dbgusb_bind);
    if (result < 0) {
        return result;
    }
    return taiHookFunctionOffsetForKernel(KERNEL_PID, &dbgusb_attach_ref, tai.modid, 0, DBGUSB_ATTACH, 1,
                                          dbgusb_attach);
}
