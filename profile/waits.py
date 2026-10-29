#!/usr/bin/env python3
"""waits.py CAPTURE.p2pf [--elf ELF --module NAME] [--kelf MODULE=ELF ...] [--thread NAME]
[--top N]: where a process's threads spend their time, blocked included, from a psp2prof
capture taken with --waits PID.

For each watched thread: the share of its state reads that found it running, ready (runnable,
waiting for a core), waiting (blocked) or otherwise; then its waiting reads grouped by what it
waited on (the wait type, and the object by its name), the syscall it blocked in with the kernel
calls found below that syscall's frame (innermost first), and the user code that called the
syscall: the stub (user PC) and its caller (user LR). User addresses are symbolized against ELF
when they fall in its module (NAME, the module's name in the capture: the ELF's by default),
kernel ones against each --kelf ELF in its module; the rest are named by module and offset.
"""
import argparse
import bisect
import collections
import re
import subprocess
import sys
from pathlib import Path

import perf_data

STATUS = {1: 'running', 2: 'ready', 4: 'standby', 8: 'waiting', 16: 'dormant', 32: 'deleted',
          64: 'dead', 128: 'stagnant', 256: 'suspended'}

# SceKernelThreadInfo's wait types on 3.65 (bit 31: the wait checks callbacks).
WAIT_TYPES = {0x1: 'delay', 0x2: 'thread end', 0x4: 'signal', 0x8: 'thread suspend',
              0x10: 'event flag', 0x20: 'semaphore', 0x40: 'mutex', 0x80: 'rw lock',
              0x100: 'cond signal', 0x200: 'cond mutex', 0x1000: 'fast mutex',
              0x2000: 'fast mutex spin', 0x10000: 'event', 0x20000: 'mp events',
              0x40000: 'msg pipe', 0x100000: 'lw mutex', 0x200000: 'lw cond'}


class Symbols:
    """An ELF's function symbols, looked up by runtime address in its module."""

    def __init__(self, elf: Path):
        self.syms = []
        for line in subprocess.run(['arm-vita-eabi-nm', '-nC', '--defined-only', str(elf)],
                                   capture_output=True, text=True).stdout.splitlines():
            f = line.split(' ', 2)
            if len(f) == 3 and f[1] in 'tTwW':
                self.syms.append((int(f[0], 16) & ~1, re.sub(r'\(.*', '', f[2])))
        self.addrs = [a for a, _ in self.syms]
        self.text = min((v for v, _, _, x in perf_data.load_segments(elf) if x), default=None)

    def name(self, segments, address):
        """The symbol of a runtime address in the module whose segments are given, or None."""
        own = [m for m in segments if m[2] & 1]
        if not own or self.text is None or not self.syms:
            return None
        if not any(v <= address < v + n for v, n, _, _ in own):
            return None
        base = min(v for v, _, _, _ in own)
        i = bisect.bisect_right(self.addrs, (address - base + self.text) & ~1) - 1
        return self.syms[i][1] if i >= 0 else None


def wait_type_name(wait_type):
    name = WAIT_TYPES.get(wait_type & 0x7FFFFFFF, f'wait type {wait_type:#x}')
    return name + (' (callbacks)' if wait_type & 0x80000000 else '')


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--elf', type=Path, help="the process's ELF, for its symbols")
    parser.add_argument('--module', help="the ELF's module name in the capture (default: the ELF's file stem)")
    parser.add_argument('--kelf', action='append', default=[], metavar='MODULE=ELF',
                        help="a kernel module's ELF, for the kernel calls' symbols (repeatable)")
    parser.add_argument('--thread', help='only threads whose name holds this')
    parser.add_argument('--top', type=int, default=12, help='wait sites a thread (default 12)')
    args = parser.parse_args()

    cap = perf_data.read_p2pf(args.capture)
    if not cap['waits']:
        # The PID to watch: the process each sampled thread belongs to.
        seen = collections.Counter((pid, cap['threads'].get(thid, (pid, '?'))[1])
                                   for _, _, thid, pid, _, _, _, _ in cap['samples'])
        for (pid, name), n in sorted(seen.items(), key=lambda kv: (kv[0][0], -kv[1])):
            if pid != perf_data.KERNEL_PID:
                print(f'pid {pid:#x} {name}: {n} samples')
        sys.exit(f'{args.capture}: no wait samples (take the capture with psp2prof.py --waits '
                 f'PID, a pid above)')
    names = {thid: name for thid, (_, name) in cap['threads'].items()}
    pids = {thid: pid for thid, (pid, _) in cap['threads'].items()}

    module = args.module or (args.elf.stem if args.elf else None)
    user_syms = {module: Symbols(args.elf)} if args.elf else {}
    kernel_syms = {}
    for spec in args.kelf:
        mod, _, elf = spec.partition('=')
        if not elf:
            sys.exit(f'--kelf {spec}: MODULE=ELF')
        kernel_syms[mod] = Symbols(Path(elf))

    def place(pid, pc, symbols):
        """The symbol (in a module symbols has an ELF for) or module+offset of an address."""
        if not pc:
            return '-'
        segments = cap['modules'].get(pid, [])
        for mod, sym in symbols.items():
            name = sym.name([m for m in segments if m[3] == mod], pc)
            if name:
                return name
        for v, n, _, mod in segments:
            if v <= pc < v + n:
                return f'{mod}+{pc - v:#x}'
        return f'{pc:#x}'

    def object_name(wait_id, wait_type):
        if wait_id in (0, 0xFFFFFFFF):
            return ''
        result, name = cap['wait_objects'].get((wait_id, wait_type), (None, ''))
        if name:
            return f' {name} ({wait_id:#x})'
        return f' {wait_id:#x}' + (f' (unnamed: {result & 0xFFFFFFFF:#x})' if result else '')

    reads = collections.defaultdict(collections.Counter)
    sites = collections.defaultdict(collections.Counter)
    for w in cap['waits']:
        _, thid, status, wait_type, wait_id, svc, user_pc, user_lr = w[:8]
        if args.thread and args.thread not in names.get(thid, ''):
            continue
        state = STATUS.get(status, f'status {status:#x}' if status else 'unread')
        reads[thid][state] += 1
        if status == 8:
            kcalls = tuple(a for a in w[8:16] if a)
            sites[thid][(wait_type, wait_id, svc & 0xFFF if svc else None, kcalls, user_pc,
                         user_lr)] += 1

    span = cap['waits'][-1][0] - cap['waits'][0][0] if len(cap['waits']) > 1 else 0
    print(f'{len(cap["waits"])} state reads of {cap["watched"]} threads over {span / 1e6:.2f} s, '
          f'{cap["wait_dropped"]} dropped')
    for thid, counts in sorted(reads.items(), key=lambda kv: -sum(kv[1].values())):
        total = sum(counts.values())
        shares = ', '.join(f'{state} {100 * n / total:.1f}%' for state, n in counts.most_common())
        print(f'\n{names.get(thid, f"thread {thid:#x}")} ({thid:#x}): {total} reads: {shares}')
        pid = pids.get(thid, 0)
        for (wait_type, wait_id, svc, kcalls, user_pc, user_lr), n in \
                sites[thid].most_common(args.top):
            print(f'  {100 * n / total:5.1f}%  {wait_type_name(wait_type)}'
                  f'{object_name(wait_id, wait_type)}')
            if svc is not None:
                print(f'          svc {svc:#x} from {place(pid, user_pc, user_syms)} <- '
                      f'{place(pid, user_lr, user_syms)}')
            if kcalls:
                chain = ' < '.join(place(perf_data.KERNEL_PID, a, kernel_syms)
                                   for a in reversed(kcalls))
                print(f'          kernel: {chain}')


if __name__ == '__main__':
    main()
