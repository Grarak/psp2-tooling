/* The CP's switches: the bits the Target Manager modules check, the QA flag host0 bit, and
 * development mode and hardware debug in Ernie's bootparam block. */
#include "retail-cp.h"

/*
 * The switch writes run in module_start, not the worker: taiHEN starts this
 * plugin from the boot configuration, and the shell's appspawn follows the
 * same configuration. Setting 0xC2 and 0xE4 synchronously here means
 * Processmgr arms the debug tables when it creates the shell, exactly as a
 * DevKit CP's pushed bootparam would. Everything slow (USB, modules, the
 * report) belongs to the delayed worker below.
 */
void cp_switches(void)
{
    record("switch-c2-before", ksceKernelCheckDipsw(0xc2));
    record("switch-c7-before", ksceKernelCheckDipsw(0xc7));
    ksceKernelSetDipsw(0xc2);
    ksceKernelSetDipsw(0xc7);
    record("switch-c2-after", ksceKernelCheckDipsw(0xc2));
    record("switch-c7-after", ksceKernelCheckDipsw(0xc7));
    /* These must stay clear: a 512-MiB CEX console, not a Tool. 0xE4 stays
     * clear as well; see the header: the kernel's arming path cannot run on
     * retail, and CP14 is driven directly below instead. 0xD2 shares 0xD4's
     * byte but retargets a processmgr allocation; it stays clear too. */
    record("switch-e4-stays", ksceKernelCheckDipsw(0xe4));
    record("switch-80-stays", ksceKernelCheckDipsw(0x80));
    record("switch-9f-stays", ksceKernelCheckDipsw(0x9f));
    record("switch-c3-stays", ksceKernelCheckDipsw(0xc3));
    record("switch-d2-stays", ksceKernelCheckDipsw(0xd2));
    record("debug-control-word", ksceKernelGetDipswInfo(6));
    record("system-control-word", ksceKernelGetDipswInfo(7));
}
/*
 * The QA flag block, and the one bit LOADP's spawn route needs.
 *
 * The block is qa_flags[0x10] at +0x20 of the KBL param (SceKblParam,
 * psp2kern/kernel/kbl/kbl.h), which ksceKernelSysrootGetKblParam
 * (SceSysrootForKernel 9db56d1f, sysmem 0x8101f8e4 on 3.65) returns as
 * sysroot->kbl_param (+0x6c). ksceSblQafMgrIsAllowHost0Access
 * (SceQafMgrForDriver 082a4fc2) reads byte 0x0e bit 0 of it. Not the fixed
 * address that getter is linked against (0x810375f8): sysmem is a relocatable
 * module, and reading that address hung the first boot on the PCH-2000
 * (2026-10-15, cp.txt ends before qaf-host0-before).
 * The DevKit QA templates (QAF_SYS_DEV_I, QAF_MGVIDEO_DEV_I/ADV_I) carry
 * 0x0e = 0x03; retail's block is all zero, so the flag answers 0 and LOADP's
 * no-option-block spawn refuses host0: with 0x80010058 (deci4p_loadp.c 3.1).
 * The other two gates of that route are external storage (bit 2 of the word
 * at sysroot +0x6c) and SceQafMgrForDriver_B9770A13 (byte 0x0d bit 1); the
 * single host0 bit is the minimal unlock. Nothing verifies the block again
 * after boot, so writing the non-secure copy is enough.
 */
#define QAF_HOST0_BYTE 0x0e
#define QAF_HOST0_MASK 0x01

/* 1 when the flag is set; 0 without a KBL param. */
int qaf_unlock(void)
{
    SceKblParam *const param = ksceKernelSysrootGetKblParam();
    volatile uint8_t *flags;

    if (!param) {
        return 0;
    }
    flags = param->qa_flags;
    record("qaf-host0-before", flags[QAF_HOST0_BYTE] & QAF_HOST0_MASK);
    flags[QAF_HOST0_BYTE] |= QAF_HOST0_MASK;
    record("qaf-host0-after", flags[QAF_HOST0_BYTE] & QAF_HOST0_MASK);
    return 1;
}

/*
 * The Syscon scratchpad (0x100 bytes), whose 0x20 bytes at +0xe0 are the
 * bootparam switch block second_loader reads into Bigmac keyslot 0x510 and
 * tests for 0xE4 (KBL_Param.txt "DIP Switches", Second_Loader.txt). Packet
 * layout and limits from syscon.elf's sceSysconReadScratchPadForDriver
 * (0x810039ac, command 0x90) and sceSysconWriteScratchPadForDriver
 * (0x81003a20, command 0x91): 1 to 24 bytes a packet and offset + size at most
 * 0x100; tx[2] is the length counting itself, the payload {offset_lo,
 * offset_hi, size} for a read and {offset_lo, offset_hi, size, data...} for a
 * write, and a read's reply data lands at rx[4]. Done here in 16-byte packets,
 * so every byte stays inside tx[32]/rx[32].
 */
#define SCRATCH_SIZE 0x100
#define SCRATCH_CHUNK 0x10
#define DIPSW_SCRATCH_OFFSET 0xe0

static int syscon_scratch_packet(unsigned command, unsigned offset, uint8_t *data, unsigned size)
{
    /* One packet per call: the black box thread and the TTYP7 words both write the scratch
     * pad, and a shared static packet let one overwrite the other's command mid-flight. */
    SceSysconPacket packet;
    unsigned length = 4;
    int result;

    memset(&packet, 0, sizeof(packet));
    packet.tx[SCE_SYSCON_PACKET_TX_CMD_LO] = command & 0xff;
    packet.tx[SCE_SYSCON_PACKET_TX_CMD_HI] = command >> 8;
    packet.tx[SCE_SYSCON_PACKET_TX_DATA(0)] = offset & 0xff;
    packet.tx[SCE_SYSCON_PACKET_TX_DATA(1)] = offset >> 8;
    packet.tx[SCE_SYSCON_PACKET_TX_DATA(2)] = size;
    if (command == SYSCON_CMD_WRITE_SCRATCH) {
        memcpy(&packet.tx[SCE_SYSCON_PACKET_TX_DATA(3)], data, size);
        length = size + 4;
    }
    packet.tx[SCE_SYSCON_PACKET_TX_LENGTH] = length;
    result = ksceSysconCmdExec(&packet, 0);
    if (result >= 0 && command == SYSCON_CMD_READ_SCRATCH) {
        memcpy(data, &packet.rx[SCE_SYSCON_PACKET_RX_DATA(0)], size);
    }
    return result;
}

int syscon_scratch(unsigned command, unsigned offset, void *data, unsigned size)
{
    if (offset + size > SCRATCH_SIZE) {
        return UNAVAILABLE;
    }
    for (unsigned done = 0; done < size; done += SCRATCH_CHUNK) {
        unsigned chunk = size - done < SCRATCH_CHUNK ? size - done : SCRATCH_CHUNK;
        int result = syscon_scratch_packet(command, offset + done, (uint8_t *)data + done, chunk);

        if (result < 0) {
            return result;
        }
    }
    return 0;
}

/*
 * Read only: the whole scratchpad, one report line per 16 bytes
 * ("scratch-e0=..." holds the first half of the bootparam block), and the
 * kernel's own switch words for comparison. What a retail Ernie keeps there
 * decides whether scratch_switch()'s write is safe.
 */
int scratch_dump(void)
{
    uint8_t bytes[SCRATCH_SIZE];
    char line[96];
    int result, length;

    memset(bytes, 0, sizeof(bytes));
    result = syscon_scratch(SYSCON_CMD_READ_SCRATCH, 0, bytes, sizeof(bytes));
    record("scratch-read", result);
    if (result < 0) {
        return result;
    }
    for (unsigned offset = 0; offset < SCRATCH_SIZE; offset += SCRATCH_CHUNK) {
        const uint8_t *b = bytes + offset;

        length = snprintf(line, sizeof(line),
                          "scratch-%02x=%02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x\n",
                          offset, b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11],
                          b[12], b[13], b[14], b[15]);
        ksceKernelPrintf("[retail-cp] %s", line);
        report_write(line, length);
    }
    length = snprintf(line, sizeof(line), "dipsw-words=%08x %08x %08x %08x %08x %08x %08x %08x\n",
                      ksceKernelGetDipswInfo(0), ksceKernelGetDipswInfo(1), ksceKernelGetDipswInfo(2),
                      ksceKernelGetDipswInfo(3), ksceKernelGetDipswInfo(4), ksceKernelGetDipswInfo(5),
                      ksceKernelGetDipswInfo(6), ksceKernelGetDipswInfo(7));
    ksceKernelPrintf("[retail-cp] %s", line);
    report_write(line, length);
    return 0;
}

/*
 * Arm a switch for the next boot: switch n of the scratchpad's
 * bootparam block (byte 0xe0 + n / 8, bit n % 8), which Second Loader copies into the
 * kernel's switches at boot (0xE4, verified on a PCH-2000). ksceKernelSetDipsw alone
 * cannot do this: it only sets the bit in the non-secure array (sysmem FUN_81018f94), and
 * SKBL has already run by then. Only the one byte is read, changed and written. A retail
 * PCH-2000's block is all zero, and the kernel's switch array is not
 * copied in: it carries retail-cp's emulated 0xC2/0xC7, which the secure world has never
 * seen on retail. Refused: 0x80 (the Tool memory size; this is a 512-MiB console) and 0xD2
 * (retargets a processmgr allocation to a DevKit-only partition).
 */

int scratch_switch(unsigned sw, int on)
{
    const unsigned offset = DIPSW_SCRATCH_OFFSET + (sw >> 3);
    const uint8_t mask = 1u << (sw & 7);
    uint8_t byte = 0;
    char stage[32];
    int result;

    if (sw > 0xff || sw == 0x80 || sw == 0xd2) {
        return UNAVAILABLE;
    }
    result = syscon_scratch(SYSCON_CMD_READ_SCRATCH, offset, &byte, 1);
    snprintf(stage, sizeof(stage), "dipsw-%02x-before", sw);
    record(stage, result < 0 ? result : byte);
    if (result < 0) {
        return result;
    }
    byte = on ? byte | mask : byte & ~mask;
    result = syscon_scratch(SYSCON_CMD_WRITE_SCRATCH, offset, &byte, 1);
    snprintf(stage, sizeof(stage), "dipsw-%02x-write", sw);
    record(stage, result);
    if (result < 0) {
        return result;
    }
    byte = 0;
    result = syscon_scratch(SYSCON_CMD_READ_SCRATCH, offset, &byte, 1);
    snprintf(stage, sizeof(stage), "dipsw-%02x-after", sw);
    record(stage, result < 0 ? result : byte);
    return result;
}

/* module_start: the switches this boot came up with. */
void switches_report(void)
{
    record("hwdebug-switch", ksceKernelCheckDipsw(DIPSW_SWITCH_HWDEBUG));
    record("devmode-switch", ksceKernelCheckDipsw(DIPSW_DEVELOPMENT_MODE));
}
