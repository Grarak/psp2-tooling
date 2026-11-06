#!/usr/bin/env python3
"""leaf_callers.py ELF PREFIX...: who calls the samples that DWARF CFI cannot unwind, from
vita_prof.py --registers snapshots (PREFIX.registers.jsonl and PREFIX.stack.bin).

    leaf_callers.py ELF --p2pf CAPTURE PID [--moved OUT.p2pf]

The same from psp2prof's stack snapshots (psp2prof.py --stack: STAK records) of process PID.
With --moved, it also writes OUT.p2pf: the capture with each snapshot whose caller was found
starting at that caller instead (PC the return address, SP past the word that held it), which
unwind_snapshots.py --p2pf then unwinds with the ELF's CFI, and OUT.leaves: each moved
snapshot's index among PID's snapshots and the leaf it was in.

- Sony's modules (a PC outside the ELF: SceLibKernel's sceClibMemcpy and the like; from a
  psp2prof capture, only a PC in a module it lists) have no
  CFI, and use LR as scratch. The caller is the first word above SP that is a Thumb return
  address into the ELF right after a BL/BLX. A psp2prof capture names the module (its MODL
  records), and the BL/BLX before the word must then lead into that module: to one of the
  ELF's import stubs for it (.vitalink.fstubs.MODULE), directly or through branches and
  long-branch thunks. They are reported by module and 128-byte block of it (DTrace snapshots:
  by 128-byte block of the address), since their base moves from boot to boot.
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

args = sys.argv[1:]
moved_out = None
if '--moved' in args:
    i = args.index('--moved')
    moved_out = args[i + 1]
    del args[i:i + 2]
p2pf = None
if len(args) == 4 and args[1] == '--p2pf':
    elf, p2pf, p2pf_pid = args[0], args[2], int(args[3], 0)
    prefixes = []
elif len(args) >= 2 and '--p2pf' not in args and moved_out is None:
    elf, prefixes = args[0], args[1:]
else:
    sys.exit(__doc__)
syms = []
for line in subprocess.run([SDK + 'nm', '-nC', elf], capture_output=True, text=True).stdout.splitlines():
    f = line.split(' ', 2)
    if len(f) == 3 and f[0] and f[1] in 'tTwW':
        syms.append((int(f[0], 16), f[2]))
addrs = [a for a, _ in syms]
by_name = {s: a for a, s in syms}
uidivmod = next((a for a, s in syms if s == '__aeabi_uidivmod'), None)
# The text bytes, to check the instruction before a return address; the import stubs, by module.
text, stubs = {}, collections.defaultdict(list)
headers = subprocess.run([SDK + 'objdump', '-h', elf], capture_output=True, text=True).stdout
for m in re.finditer(r'\s\d+\s+(\S+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+[0-9a-f]+\s+([0-9a-f]+)', headers):
    section, size, vma, off = m.group(1), int(m.group(2), 16), int(m.group(3), 16), int(m.group(4), 16)
    if section.startswith('.text'):
        text[vma] = (size, off)
    elif section.startswith('.vitalink.fstubs.'):
        stubs[section[len('.vitalink.fstubs.'):]].append((vma, vma + size))
blob = open(elf, 'rb').read()


def code(a, n):
    for vma, (size, off) in text.items():
        if vma <= a and a + n <= vma + size:
            return blob[off + a - vma:off + a - vma + n]
    return None


def name(pc):
    i = bisect.bisect_right(addrs, pc & ~1) - 1
    return syms[i][1] if i >= 0 and code(pc & ~1, 2) is not None else None


def thumb_branch(at):
    """The target of the 32-bit Thumb BL/BLX/B.W at `at`, its kind ('bl', 'blx', 'b'), or None."""
    b = code(at, 4)
    if not b:
        return None, None
    h1, h2 = struct.unpack('<HH', b)
    if (h1 & 0xf800) != 0xf000 or (h2 & 0x8000) == 0:
        return None, None
    s, j1, j2 = h1 >> 10 & 1, h2 >> 13 & 1, h2 >> 11 & 1
    imm = s << 24 | (~(j1 ^ s) & 1) << 23 | (~(j2 ^ s) & 1) << 22 | (h1 & 0x3ff) << 12 | (h2 & 0x7ff) << 1
    imm -= (1 << 25) if s else 0
    kind = {0xd000: 'bl', 0xc000: 'blx', 0x9000: 'b'}.get(h2 & 0xd000)
    if kind is None:
        return None, None
    return (((at + 4) & ~3) + imm) & ~3 if kind == 'blx' else at + 4 + imm, kind


def into_module(target, module):
    """Whether a call to target reaches one of the ELF's import stubs for module: directly, or
    through B.W branches (memcpy's into its thunk) and long-branch thunks (by their names)."""
    for _ in range(4):
        if any(a <= target < b for a, b in stubs.get(module, [])):
            return True
        n = name(target)
        if n and n.startswith('__Thumbv7ABSLongThunk_') and n[len('__Thumbv7ABSLongThunk_'):] in by_name:
            target = by_name[n[len('__Thumbv7ABSLongThunk_'):]]
            continue
        nxt, kind = thumb_branch(target & ~1)
        if kind != 'b':
            return False
        target = nxt
    return False


def after_call(ret, module=None):
    """Whether ret is a Thumb return address right after a BL/BLX (imm 4 bytes, reg 2); with
    module, an immediate one into that module's stubs."""
    if not ret & 1:
        return False
    a = ret & ~1
    target, kind = thumb_branch(a - 4)
    if kind in ('bl', 'blx'):
        return module is None or into_module(target, module)
    b2 = code(a - 2, 2)
    return module is None and bool(b2) and (struct.unpack('<H', b2)[0] & 0xff87) == 0x4780


def scan(stack, start, module=None):
    for k in range(start, len(stack) - 3, 4):
        w = struct.unpack_from('<I', stack, k)[0]
        if name(w - 1) and after_call(w, module):
            return w, k + 4
    return None, None


def snapshots():
    """(index, tid, PC, LR, stack bytes, module name or None, the module's base) a snapshot."""
    for p in prefixes:
        blobs = open(p + '.stack.bin', 'rb').read()
        for k, line in enumerate(open(p + '.registers.jsonl')):
            r = json.loads(line)
            at0 = r['stack_offset']
            yield k, r['tid'], r['upc'], r['registers'][14], blobs[at0:at0 + r.get('stack_size', 0)], None, 0
    if p2pf:
        data = open(p2pf, 'rb').read()
        mods, at, k = [], 32, 0
        while at + 8 <= len(data):
            tag, size = struct.unpack_from('<4sI', data, at)
            payload = data[at + 8:at + 8 + size]
            at += 8 + size + (-size % 4)
            if tag == b'MODL':
                pid, vaddr, memsz, perms = struct.unpack_from('<4I', payload)
                if pid == p2pf_pid and perms & 1:
                    mods.append((vaddr, vaddr + memsz, payload[16:44].split(b'\0')[0].decode(errors='replace')))
            elif tag == b'END ':
                break
        at = 32
        while at + 8 <= len(data):
            tag, size = struct.unpack_from('<4sI', data, at)
            payload = data[at + 8:at + 8 + size]
            at += 8 + size + (-size % 4)
            if tag == b'END ':
                break
            if tag != b'STAK':
                continue
            when, tid, pid, cpu = struct.unpack_from('<4I', payload)
            if pid != p2pf_pid:
                continue
            regs = struct.unpack_from('<16I', payload, 16)
            cpsr, stack_size = struct.unpack_from('<2I', payload, 80)
            pc = regs[15] | (cpsr >> 5 & 1)
            module = next(((n, a) for a, b, n in mods if a <= regs[15] < b), (None, 0))
            yield k, tid, pc, regs[14], payload[88:88 + stack_size], module[0], module[1]
            k += 1


callers = collections.defaultdict(collections.Counter)
grand = collections.defaultdict(collections.Counter)
moves = {}
for index, tid, pc, lr, stack, module, base in snapshots():
    fn = name(pc)
    if fn is None and p2pf and not module:
        # Neither the ELF nor a module the capture lists (code the app made or loaded itself).
        continue
    if fn is None:
        where = f'[{module}] +{(pc - base) & ~0x7f:#x}' if module else f'[other module] {pc & ~0x7f:#x}'
        key, (caller, at) = where, scan(stack, 0, module)
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
    first = name(caller - 1) if caller else None
    callers[(tid, key)][first or '(none found)'] += 1
    second = None
    if first and at is not None:
        w, _ = scan(stack, at)
        second = name(w - 1) if w else None
        # A caller from the stack (at > 0) is where its frame starts: SP past the word.
        if at > 0:
            moves[index] = (caller, at, key)
    grand[((tid, key), first)][second or '(none found)'] += 1


def short(s):
    return re.sub(r'\(.*', '', s)[:100]


for (tid, fn), c in sorted(callers.items(), key=lambda x: -sum(x[1].values())):
    print(f'{tid:#x} {fn}: {sum(c.values())}')
    for caller, n in c.most_common(8):
        up = ', '.join(f'{short(k)} {v}' for k, v in grand[((tid, fn), caller if caller != '(none found)' else None)].most_common(3)
                       if k != '(none found)')
        print(f'   {n:5d}  {short(caller)}' + (f'   <- {up}' if up else ''))

if moved_out:
    data = open(p2pf, 'rb').read()
    out, at, k = bytearray(data[:32]), 32, 0
    while at + 8 <= len(data):
        tag, size = struct.unpack_from('<4sI', data, at)
        payload = data[at + 8:at + 8 + size]
        at += 8 + size + (-size % 4)
        if tag == b'STAK' and struct.unpack_from('<I', payload, 8)[0] == p2pf_pid:
            if k in moves:
                caller, skip, _ = moves[k]
                regs = list(struct.unpack_from('<16I', payload, 16))
                cpsr, stack_size = struct.unpack_from('<2I', payload, 80)
                regs[15], regs[13] = caller & ~1, regs[13] + skip
                stack = payload[88 + skip:88 + stack_size]
                payload = payload[:16] + struct.pack('<16I', *regs) + struct.pack('<2I', cpsr | 1 << 5, len(stack)) + stack
            k += 1
        out += struct.pack('<4sI', tag, len(payload)) + payload + b'\0' * (-len(payload) % 4)
        if tag == b'END ':
            break
    open(moved_out, 'wb').write(bytes(out))
    leaves = os.path.splitext(moved_out)[0] + '.leaves'
    with open(leaves, 'w') as f:
        for k, (_, _, key) in sorted(moves.items()):
            f.write(f'{k} {key}\n')
    print(f'{len(moves)} snapshots moved to their callers: {moved_out}, {leaves}')
