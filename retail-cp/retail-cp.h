/* retail-cp: what its parts share. */
#pragma once

#include <stdint.h>
#include <string.h>
#include <psp2kern/io/fcntl.h>
#include <psp2kern/io/stat.h>
#include <psp2kern/io/dirent.h>
#include <psp2kern/ctrl.h>
#include <psp2kern/kernel/cpu.h>
#include <psp2kern/kernel/debug.h>
#include <psp2kern/kernel/dipsw.h>
#include <psp2kern/kernel/suspend.h>
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/sysroot.h>
#include <psp2kern/kernel/syscon.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/power.h>
#include <psp2kern/udcd.h>
#include <taihen.h>

/* taiHEN */
int module_get_export_func(SceUID pid, const char *modname, uint32_t libnid, uint32_t funcnid, uintptr_t *func);

#define KERNEL_PID 0x10005
#define USB_BUS 2
#define REPORT_PATH "ur0:data/retail-debug/cp.txt"
#define REPORT_PREVIOUS "ur0:data/retail-debug/cp-prev.txt" /* the previous boot's */
#define UNAVAILABLE ((int)0x80010013)
#define MEMTYPE_KD_PHYCONT 0x10208006
#define MEMTYPE_KD 0x1020d006
#define MEMTYPE_PHYCONT 0x1080d006
#define SERVICES_SHELL_WAIT_US (60u * 1000 * 1000)
#define SHELL_READY_POLL_US (100 * 1000)
#define SYSCON_CMD_READ_SCRATCH 0x90
#define SYSCON_CMD_WRITE_SCRATCH 0x91
#define DIPSW_SWITCH_HWDEBUG 0xe4
#define DIPSW_DEVELOPMENT_MODE 0x9f

/* console.c */
int console_start(void);

/* crash.c */
int crash_report(void);
int crash_start(void);

/* dtrace.c */
extern volatile uint32_t dtrace_empty_sends, dtrace_packet_failures;
int dtrace_pmep_off(void);
int dtrace_send_fix(void);
int threadmgr_patch(void);

/* power.c */
int awake_start(void);
int devmode_rearm(void);
int devmode_reboot_install(void);
extern tai_hook_ref_t power_transition_ref;
extern volatile int sleep_wake;
int uninstall(void);
extern void (*power_notify)(unsigned clear, unsigned set, unsigned once);

/* report.c */
int record(const char *stage, int value);
int record_text(const char *stage, const char *value);
extern int report_failed;
int report_write(const char *text, int length);

/* services.c */
extern unsigned unavailable_calls;
unsigned heap_report(void);
void load_early_services(void);
int load_services(unsigned heap);
unsigned memory_free(unsigned memtype, unsigned limit, int contiguous);
int pa_buffer_hook(void);
void record_kd_free(const char *stage);
int start(SceUID module, const char *stage);

/* shell.c */
extern volatile int shell_ready;
int appmgr_patch(void);
int shell_ready_install(void);
extern volatile unsigned shell_ready_ms;
int spawn_title_hook(void);

/* switches.c */
void cp_switches(void);
int qaf_unlock(void);
int scratch_dump(void);
int scratch_switch(unsigned sw, int on);
void switches_report(void);
int syscon_scratch(unsigned command, unsigned offset, void *data, unsigned size);

/* usb.c */
extern unsigned mtp_yields;
int dbgusb_attach_fix(void);
extern volatile unsigned dbgusb_wakes;
int mtp_yield(void);
extern int usb_member_count;
int usb_share(void);
extern int usb_shared;

/* words.c */
int power_act(const char *word);
int power_start(void);
