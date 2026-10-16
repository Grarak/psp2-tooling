#!/usr/bin/env python3
"""Ports the DevKit's Target Manager kernel modules to a retail Vita (taiHEN *KERNEL plugins).

The inputs are decrypted DevKit 3.65 (3.650.011) os0:kd modules, which this repository does
not provide. For each, it applies the patches below, checking the bytes each one replaces
(USB bus 2 in place of the CP's SDIO link, retail memory partitions in place of the DevKit-only
Tool partition) and writes <name>-retail.skprx, a kernel fake SELF, and manifest.json.

    retail-cp/port_modules.py --modules DIR/os0/kd --out OUT
"""
import argparse
import json
import os
from pathlib import Path
import struct
import subprocess


class VitaModule:
    """A Vita ELF's file-backed PT_LOAD segments, to map a virtual address to a file offset."""

    def __init__(self, raw):
        if raw[:7] != b'\x7fELF\x01\x01\x01':
            raise ValueError('expected little-endian ELF32')
        phoff, = struct.unpack_from('<I', raw, 28)
        phsize, phcount = struct.unpack_from('<HH', raw, 42)
        if phsize != 32:
            raise ValueError('invalid program-header size')
        self.segments = [struct.unpack_from('<8I', raw, phoff + index * phsize)
                         for index in range(phcount)]

    def offset(self, address, size):
        for segment in self.segments:
            if segment[0] == 1 and segment[2] <= address and \
                    address + size <= segment[2] + segment[4]:
                return segment[1] + address - segment[2]
        raise ValueError(f'address {address:#x} is not file-backed')


def mark_kernel_fself(data):
    """vita-make-fself writes a user fake SELF; taiHEN loads a kernel one."""
    image = bytearray(data)
    if len(image) < 0xa4 or image[:4] != b'SCE\0':
        raise ValueError('not a Vita SELF')
    appinfo_offset, elf_offset = struct.unpack_from('<QQ', image, 0x38)
    if appinfo_offset + 0x10 > len(image):
        raise ValueError('SELF application info is out of range')
    if image[elf_offset:elf_offset + 4] != b'\x7fELF':
        raise ValueError('SELF is not a plaintext fake SELF')
    struct.pack_into('<H', image, 0x08, 0x1c0)               # fake kernel SDK type
    struct.pack_into('<I', image, appinfo_offset + 0x0c, 7)  # kernel SELF type
    return bytes(image)


MODULES = {
    'dbgusb': 'dbgusb-retail',
    'deci4p_dfmgr': 'dfmgr-retail',
    # Target Manager services and their providers: their SceDipswForDriver
    # checks read the bits the retail-cp plugin sets through ksceKernelSetDipsw.
    # ttyp/userp/loadp/drfp allocate from the DevKit Tool partition
    # (0x10f0d006), which retail lacks; those sites go to retail PhyCont
    # (0x1080d006) below. syslibtrace/pamgr/ctrlp port patchless.
    'syslibtrace': 'syslibtrace-retail',
    'pamgr': 'pamgr-retail',
    'deci4p_ttyp': 'ttyp-retail',
    'deci4p_userp': 'userp-retail',
    'deci4p_ctrlp': 'ctrlp-retail',
    'deci4p_loadp': 'loadp-retail',
    'deci4p_drfp': 'drfp-retail',
    # DTrace (vita_prof.py over 0x29000) and the VitaOS screenshot (vcp_capture.py).
    'deci4p_dbgp': 'dbgp-retail',
    'deci4p_dtracep': 'dtracep-retail',
    'deci4p_vcp': 'vcp-retail',
}
PATCHES = {
    'deci4p_dfmgr': (
        (0x810006b2, 'aaf5a674', '544600bf', 'select existing USB unit instead of SDIO'),
        (0x810006be, '4ff00108', '4ff00208', 'start initialization at unit 1'),
        (0x810006cc, 'cde904a6', '05960c25', 'preserve r6 and select USB transport/DCMP entry'),
        (0x810007f6, '0020', '0120', 'send manager-ready status on USB'),
        (0x810007fa, '0346', '0023', 'preserve zero status argument'),
        (0x810008b4, '04f062ea', '012000bf', 'opt-in debug manager startup'),
        # Registration picks unit (flags >> 9) & 1 while USB is up, else unit 0;
        # ttyp's TTYP0-7 (flags 1) land on the never-initialized SDIO unit and
        # the kernel takes a null write. Only unit 1 exists in this port.
        (0x810009e0, '18bfc3f34023', '0123aff30080', 'register every protocol on the USB unit'),
        # DcmpSendCpStatus(unit, ...) queues on gDcmpQueueSdio + unit: unit 0's slots are
        # never allocated here, so a status for it stores through NULL (DFAR 0xc). The
        # sysroot callback sends one when the shell reports ready, the sysevent handler on
        # suspend; every CP status goes to the USB unit instead.
        (0x81002d26, '0128', '0120', 'CP status always on the USB unit'),
        (0x81002d32, '58d9', '58e0', 'CP status always on the USB unit'),
        (0x81002656, 'c1f2f001', 'c1f28001', 'retail PhyCont DCMP allocation'),
        (0x8100493c, 'c1f2f008', 'c1f28008', 'retail PhyCont USB worker stacks'),
        # DfMgrSdioInit never runs here (initialization starts at unit 1); patched so the
        # port carries no Tool memory type at all.
        (0x8100462c, 'c1f2f008', 'c1f28008', 'retail PhyCont SDIO worker stacks'),
    ),
    # Each is the movt half of 0x10f0d006 (Tool partition kernel RW). Retail
    # has no Tool partition: loadp's thread stack panics the kernel and the
    # others' heaps/blocks fail. A DevKit keeps the Target Manager's memory out
    # of the system's partitions; on retail the place with room is PhyCont
    # (0x1080d006, ~19 MiB free with every service up), not KD (kernel RW,
    # 0x1020d006): KD has ~4 MiB left after boot, and with ttyp and dbgp there
    # udcd_uvc's 1-MiB frame and app launches ran out (2026-10-16, PCH-2000).
    'deci4p_loadp': (
        (0x81004290, 'c1f2f007', 'c1f28007', 'retail PhyCont thread stack and heap'),
    ),
    'deci4p_ttyp': (
        (0x8100091a, 'c1f2f003', 'c1f28003', 'retail PhyCont heap'),
        # Console writes ask kscePmMgrGetProductMode for a byte the caller zeroes first:
        # 0 (development, DevKit) sends over TTYP, 1 (production, retail) prints to UART.
        (0x81000e1e, '00f0eceb', 'aff30080', 'console over TTYP in production mode'),
        # ttyp swaps iofilemgr's /tty VFS for its own and gives up when the unmount fails.
        # On a DevKit it loads before any process; here the shell already holds console
        # descriptors (refcount > 1: 0x80010010). Flag 1 makes vfsUmount close them first;
        # processes started afterwards get TTYP consoles.
        (0x81001cac, '00000000', '01000000', 'force the /tty unmount'),
    ),
    'deci4p_userp': (
        (0x810007c6, 'c1f2f001', 'c1f28001', 'retail PhyCont buffer block'),
        (0x810008c0, 'c1f2f001', 'c1f28001', 'retail PhyCont ring buffer'),
        (0x8100141e, 'c1f2f001', 'c1f28001', 'retail PhyCont string buffer'),
        (0x81001526, 'c1f2f001', 'c1f28001', 'retail PhyCont string buffer'),
    ),
    'deci4p_drfp': (
        (0x81000556, 'c1f2f003', 'c1f28003', 'retail PhyCont heap'),
        (0x8100066c, 'c1f2f001', 'c1f28001', 'retail PhyCont memory blocks'),
    ),
    'deci4p_dbgp': tuple(
        (address, 'c1f2f0%02x' % reg, 'c1f280%02x' % reg, 'retail PhyCont')
        for address, reg in ((0x81000f76, 1), (0x810010fc, 4), (0x8100129e, 3), (0x81001fd2, 1),
                             (0x810035aa, 1), (0x81003722, 1), (0x81010c06, 1))),
    'deci4p_dtracep': tuple(
        (address, 'c1f2f0%02x' % reg, 'c1f280%02x' % reg, 'retail PhyCont')
        for address, reg in ((0x81000be4, 10), (0x81003392, 1), (0x81003822, 7), (0x8101ea08, 14),
                             (0x8101f68c, 14), (0x8101f70a, 6), (0x8101fe24, 6))) + (
        # The 16-MiB DTrace heap lives in the DevKit Tool partition. Retail KD has about 2 MiB
        # free after boot, which app launches need; PhyCont (26 MiB) takes heaps up to 16 MiB.
        # Measured peak: ~640 KiB of probe tables + 8 x bufsize + 8-KiB dynvars (vita_prof),
        # so 4 MiB holds vita_prof's default 256-KiB buffers.
        (0x8102177c, 'c1f2f003', 'c1f28003', 'DTrace heap in retail PhyCont (0x1080d006)'),
        (0x8102178c, '4ff08071', '4ff48001', '4-MiB DTrace heap on retail'),),
    'deci4p_vcp': (
        # The 2-MiB capture frame (DMAC target, physically contiguous, uncached) does not
        # fit KD; PhyCont (26 MiB) is the retail partition dbgusb's buffers also use.
        (0x81000130, 'c1f2f001', 'c3f28001', 'retail physically contiguous noncached frame'),
        (0x810008bc, 'c1f2f007', 'c1f28007', 'retail PhyCont'),
    ),
    'dbgusb': (
        (0x8100015c, '4ff00101', '4ff00201', 'receive requests on retail bus 2'),
        (0x81000638, '4146', '0221', 'send requests on retail bus 2'),
        (0x8100069c, '00f0ceea', '012000bf', 'opt-in debug USB startup'),
        (0x810006ba, '00f0c0ea', '002000bf', 'select genuine USB transport'),
        (0x8100070a, 'c1f2f001', 'c3f28001', 'retail physically contiguous noncached read buffers'),
        (0x8100076c, 'c1f2f001', 'c3f28001', 'retail physically contiguous noncached write buffer'),
        (0x8100086c, 'c1f2f005', 'c1f28005', 'retail PhyCont worker stacks'),
        (0x810009ce, '0120', '0220', 'select retail USB PHY port 2'),
        (0x810009d0, '0146', '0121', 'preserve client mode independently of port'),
        (0x810009de, '0121', '0221', 'register on retail bus 2'),
        (0x810009f8, '0123', '0223', 'start UDC on retail bus 2'),
        (0x81000a0e, '0123', '0223', 'start USB driver on retail bus 2'),
        (0x81000a1e, '0122', '0222', 'activate retail bus 2'),
        (0x81000a36, '0123', '0223', 'unwind USB driver on retail bus 2'),
        (0x81000a48, '0123', '0223', 'unwind UDC on retail bus 2'),
        (0x81000a52, '0121', '0221', 'unregister on retail bus 2'),
    ),
}


def port(name, raw):
    if name not in MODULES:
        raise ValueError(f'{name} is not a module this script ports')
    module = VitaModule(raw)
    updated = bytearray(raw)
    patches = []
    for address, old, new, reason in PATCHES.get(name, ()):
        before, after = bytes.fromhex(old), bytes.fromhex(new)
        offset = module.offset(address, len(before))
        if len(before) != len(after) or updated[offset:offset + len(before)] != before:
            raise ValueError(f'{name}: unexpected bytes at {address:#x} (not the DevKit 3.65 module)')
        updated[offset:offset + len(after)] = after
        patches.append(dict(address=hex(address), before=old, after=new, reason=reason))
    return bytes(updated), patches


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--modules', required=True, type=Path, help='existing fs_dec/os0/kd; never a device')
    parser.add_argument('--out', required=True, type=Path, help='new private build directory')
    parser.add_argument('--make-fself', type=Path,
                        default=Path(os.environ.get('VITASDK', '/usr/local/vitasdk')) / 'bin/vita-make-fself')
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    manifest = {'version': 3, 'scope': 'USB DECI4p transport plus Target Manager services; offline retail port; absent SDIO explicitly unavailable', 'modules': {}}
    for name, output in MODULES.items():
        raw, patches = port(name, (args.modules / (name + '.elf')).read_bytes())
        executable = args.out / (output + '.elf')
        executable.write_bytes(raw)
        target = args.out / (output + '.skprx')
        subprocess.run([str(args.make_fself), '-c', str(executable), str(target)], check=True)
        target.write_bytes(mark_kernel_fself(target.read_bytes()))
        manifest['modules'][name] = dict(patches=patches)
    (args.out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')


if __name__ == '__main__':
    main()
