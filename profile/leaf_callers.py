#!/usr/bin/env python3
"""leaf_callers.py ELF PREFIX...: who calls the samples that DWARF CFI cannot unwind, from
vita_prof.py --registers snapshots (PREFIX.registers.jsonl and PREFIX.stack.bin).

- Sony's modules (a PC outside the ELF: SceLibKernel's sceClibMemcpy and the like) have no
  CFI, and use LR as scratch. The caller is the first word above SP that is a Thumb return
  address into the ELF right after a BL/BLX. They are reported by 128-byte block, since
  their base moves from boot to boot.
- The ELF's asm leaves (memcpy, memset, memcmp, memmove and their __aeabi_ forms): LR when it
  is such a return address, else the same scan.
- __udivsi3 called from __aeabi_uidivmod (stmdb sp!, {r0, r1, lr}; __udivsi3 never moves
  SP): the word at SP + 8.

Each caller is followed by its own caller, found by scanning on past that word.
"""
import bisect
import collections
import json
import os
import re
import struct
import subprocess
import sys

SDK = os.environ.get('VITASDK', '/usr/local/vitasdk') + '/bin/arm-vita-eabi-'
LEAVES = {'memcmp', 'memcpy', 'memmove', 'memset', '__aeabi_memcpy', '__aeabi_memcpy4',
          '__aeabi_memcpy8', '__aeabi_memmove', '__aeabi_memmove4', '__aeabi_memmove8',
          '__aeabi_memset', '__aeabi_memset4', '__aeabi_memset8'}
UDIV = {'__udivsi3', '.udivsi3_skip_div0_test'}

if len(sys.argv) < 3:
    sys.exit(__doc__)
elf, prefixes = sys.argv[1], sys.argv[2:]
syms = []
for line in subprocess.run([SDK + 'nm', '-nC', elf], capture_output=True, text=True).stdout.splitlines():
    f = line.split(' ', 2)
    if len(f) == 3 and f[0] and f[1] in 'tTwW':
        syms.append((int(f[0], 16), f[2]))
addrs = [a for a, _ in syms]
uidivmod = next((a for a, s in syms if s == '__aeabi_uidivmod'), None)
# The text bytes, to check the instruction before a return address.
text = {}
headers = subprocess.run([SDK + 'objdump', '-h', elf], capture_output=True, text=True).stdout
for m in re.finditer(r'\s\d+\s+\.text\S*\s+([0-9a-f]+)\s+([0-9a-f]+)\s+[0-9a-f]+\s+([0-9a-f]+)', headers):
    text[int(m.group(2), 16)] = (int(m.group(1), 16), int(m.group(3), 16))
blob = open(elf, 'rb').read()


def code(a, n):
    for vma, (size, off) in text.items():
        if vma <= a and a + n <= vma + size:
            return blob[off + a - vma:off + a - vma + n]
    return None


def name(pc):
    i = bisect.bisect_right(addrs, pc & ~1) - 1
    return syms[i][1] if i >= 0 and code(pc & ~1, 2) is not None else None


def after_call(ret):
    """Whether ret is a Thumb return address right after a BL/BLX (imm 4 bytes, reg 2)."""
    if not ret & 1:
        return False
    a = ret & ~1
    b4, b2 = code(a - 4, 4), code(a - 2, 2)
    if b4:
        h1, h2 = struct.unpack('<HH', b4)
        if (h1 & 0xf800) == 0xf000 and (h2 & 0xc000) == 0xc000:
            return True
    return bool(b2) and (struct.unpack('<H', b2)[0] & 0xff87) == 0x4780


def scan(stack, start):
    for k in range(start, len(stack) - 3, 4):
        w = struct.unpack_from('<I', stack, k)[0]
        if name(w - 1) and after_call(w):
            return w, k + 4
    return None, None


callers = collections.defaultdict(collections.Counter)
grand = collections.defaultdict(collections.Counter)
for p in prefixes:
    blobs = open(p + '.stack.bin', 'rb').read()
    for line in open(p + '.registers.jsonl'):
        r = json.loads(line)
        pc, lr, at0 = r['upc'], r['registers'][14], r['stack_offset']
        stack = blobs[at0:at0 + r.get('stack_size', 0)]
        fn = name(pc)
        if fn is None:
            key, (caller, at) = f'[other module] {pc & ~0x7f:#x}', scan(stack, 0)
        elif fn in LEAVES:
            key = fn
            caller, at = (lr, 0) if name(lr - 1) and after_call(lr) else scan(stack, 0)
        elif fn in UDIV and uidivmod is not None and uidivmod <= (lr & ~1) < uidivmod + 0x1a \
                and len(stack) >= 12:
            key, caller, at = '__udivsi3 via __aeabi_uidivmod', struct.unpack_from('<I', stack, 8)[0], 12
        elif fn in UDIV:
            key, caller, at = fn, lr, 0
        else:
            continue
        key = (r['tid'], key)
        first = name(caller - 1) if caller else None
        callers[key][first or '(none found)'] += 1
        second = None
        if first and at is not None:
            w, _ = scan(stack, at)
            second = name(w - 1) if w else None
        grand[(key, first)][second or '(none found)'] += 1


def short(s):
    return re.sub(r'\(.*', '', s)[:100]


for (tid, fn), c in sorted(callers.items(), key=lambda x: -sum(x[1].values())):
    print(f'{tid:#x} {fn}: {sum(c.values())}')
    for caller, n in c.most_common(8):
        up = ', '.join(f'{short(k)} {v}' for k, v in grand[((tid, fn), caller if caller != '(none found)' else None)].most_common(3)
                       if k != '(none found)')
        print(f'   {n:5d}  {short(caller)}' + (f'   <- {up}' if up else ''))
