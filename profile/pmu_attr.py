#!/usr/bin/env python3
"""PMU counts per function from a psp2prof capture taken with --pmu.

    profile/pmu_attr.py CAPTURE.p2pf --elf APP.elf --thread main [--top 30]

The plugin reads each core's counters right after each of that core's PC samples, so the
difference between two consecutive reads of a core is what the core counted in the period that
ended at the later sample. Each period's counts are credited to that sample's PC: summed over
many samples, a function's share of a counter estimates how much of it the function caused, as
its share of the samples estimates its share of the time. A period after a dropped sample is
left out. The counters count everything the core runs, so --thread or --pid keeps the periods
whose sample caught that thread.

A period is the whole time between two samples (at 1 kHz over three cores, about 2 ms: a
million cycles), and its counts are everything the core ran in it: they tell apart phases of a
thread that last longer than a period, not the functions called within one. Functions that run
together in one phase come out with the same rates; sample one core faster (psp2prof.py --hz
10000 --cores 0x4) for shorter periods. No period is short enough for single instructions.
Periods are not all alike: the sampler shares its core, and a period that it was held up in
carries more of what ran before its sample. --max-cycles leaves out the periods longer than
that (a function whose periods run long shows it in its median period).

A core waiting for an interrupt (WFI, the kernel's idle thread) answers every counter read with
zero, and a core that enters or leaves WFI during the reads gives some counters and zeros for the
rest: a read in which a counter that has counted on that core reads zero is unread, and a period
that starts or ends at one is left out. The counters themselves keep their counts across it. A period in which any counter went backwards (a core
that powered down) is left out and counted as a reset. A stack snapshot (stack=) halts its core
for several milliseconds and runs its loads on it: on the cores snapshots were taken of, every
period that starts at a snapshot's sample (every hz/stackhz-th) is left out.

A sample's PC is taken as DBGPCSR read it: on the Cortex-A9 the destination of the last branch
(see perf_data), which names the function the core was in.

PCs outside the ELF's text are grouped by the capture's module (MODL) they fall in.
"""
import argparse
import bisect
import collections
import math
import statistics
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from perf_data import KERNEL_PID, PMU_EVENT_NAMES, read_p2pf  # noqa: E402


def symbols(elf):
    syms = []
    for line in subprocess.run(['arm-vita-eabi-nm', '-C', '-n', '-S', '--defined-only', str(elf)],
                               capture_output=True, text=True, check=True).stdout.splitlines():
        parts = line.split(' ', 3)
        if len(parts) == 4 and parts[2] in 'tTwW':
            syms.append((int(parts[0], 16) & ~1, int(parts[1], 16), parts[3]))
    return syms


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--elf', type=Path, help="the app's ELF, for its functions")
    parser.add_argument('--thread', help='only the periods whose sample caught this thread (by name)')
    parser.add_argument('--pid', type=lambda v: int(v, 0), help='only the periods of this process')
    parser.add_argument('--top', type=int, default=30)
    parser.add_argument('--max-cycles', type=int, help='leave out the periods longer than this')
    args = parser.parse_args()

    cap = read_p2pf(args.capture)
    events = cap['pmu_events']
    if not events:
        sys.exit(f'{args.capture}: no PMU counts (capture with psp2prof.py --pmu)')
    names = [PMU_EVENT_NAMES.get(e, f'{e:#04x}') for e in events] + ['cycles']
    samples = {s[4]: s for s in cap['samples']}  # cpu | seq << 2 -> sample
    syms = symbols(args.elf) if args.elf else []
    addrs = [a for a, _, _ in syms]
    mods = [(v, v + n, name, pid) for pid, ms in cap['modules'].items() for v, n, perm, name in ms
            if perm & 1]

    def where(ip, pid):
        i = bisect.bisect_right(addrs, ip) - 1
        if i >= 0 and syms[i][0] <= ip < syms[i][0] + max(syms[i][1], 2):
            return syms[i][2]
        for a, b, name, mp in mods:
            if a <= ip < b and (mp == pid or mp == KERNEL_PID):
                return f'module {name}'
        return 'unknown'

    want = None
    if args.thread:
        want = {t for t, (pid, name) in cap['threads'].items() if name == args.thread}
        if not want:
            sys.exit(f'no thread named {args.thread!r} in the capture')
    by_core = collections.defaultdict(list)
    for p in cap['pmu']:
        by_core[p[0] & 3].append(p)
    # Snapshots are taken at every step-th sample of their cores (whether or not one came out):
    # the step and the cores from the snapshots that did, by their samples' sequence numbers.
    when = {(s[0], s[4] & 3): s[4] >> 2 for s in cap['samples']}
    snap_seqs = [when[t] for t in cap['snapshots'] if t in when]
    snap_step = 0
    for seq in snap_seqs:
        snap_step = math.gcd(snap_step, seq)
    snap_cores = {c for _, c in cap['snapshots']}
    per = collections.defaultdict(lambda: [0] * (len(events) + 2))  # function -> samples, counts...
    lengths = collections.defaultdict(list)  # function -> its periods' cycles
    totals = [0] * (len(events) + 2)
    gaps = resets = unread = halted = long = 0
    for core, rows in by_core.items():
        rows.sort(key=lambda p: p[0] >> 2)
        counted = [n for n in range(1, len(events) + 1) if any(r[n] for r in rows)] + [7]
        for prev, cur in zip(rows, rows[1:]):
            if (cur[0] >> 2) - (prev[0] >> 2) != 1:
                gaps += 1
                continue
            if snap_step and core in snap_cores and (prev[0] >> 2) % snap_step == 0:
                halted += 1
                continue
            if not all(prev[n] for n in counted) or not all(cur[n] for n in counted):
                unread += 1
                continue
            s = samples.get(cur[0])
            if not s or s[1] == 0xFFFFFFFF:
                continue
            if want is not None and s[2] not in want:
                continue
            if args.pid is not None and s[3] != args.pid:
                continue
            delta = [(cur[1 + n] - prev[1 + n]) & 0xFFFFFFFF for n in range(len(events))]
            delta.append((cur[7] - prev[7]) & 0xFFFFFFFF)
            if any(d >= 0x80000000 for d in delta):
                resets += 1
                continue
            if args.max_cycles and delta[-1] > args.max_cycles:
                long += 1
                continue
            ip = s[1] & ~1
            func = where(ip, s[3])
            lengths[func].append(delta[-1])
            row = per[func]
            row[0] += 1
            totals[0] += 1
            for n, d in enumerate(delta):
                row[1 + n] += d
                totals[1 + n] += d

    cores = ', '.join(str(c) for c in sorted(by_core))
    print(f'{args.capture.name}: {totals[0]} periods credited (cores {cores}; left out: {gaps} after '
          f'a gap, {halted} with a stack snapshot, {unread} next to a read in WFI, {resets} with '
          f'a counter reset, {long} longer than --max-cycles; '
          f'{cap["pmu_dropped"]} PMU samples dropped)')
    if not totals[0]:
        return
    cyc = totals[-1]
    print(f'in all: {cyc / totals[0]:.0f} cycles a period; ' + ', '.join(
        f'{names[n]} {totals[1 + n] / totals[0]:.1f}' for n in range(len(events))) + ' a period')
    head = (f"{'samples':>8} {'cycles%':>7} {'median':>7} " +
            ' '.join(f'{nm[:14]:>14}' for nm in names[:-1]))
    print('\nper function: its periods\' median cycles, each counter as its share of the total, '
          'then per 1000 of its cycles')
    print(head + '  function')
    for func, row in sorted(per.items(), key=lambda kv: -kv[1][0])[:args.top]:
        cells = []
        for n in range(len(events)):
            share = 100 * row[1 + n] / totals[1 + n] if totals[1 + n] else 0
            rate = 1000 * row[1 + n] / row[-1] if row[-1] else 0
            cells.append(f'{share:5.1f}% {rate:7.1f}')
        print(f'{row[0]:8d} {100 * row[-1] / cyc:6.1f}% {statistics.median(lengths[func]):7.0f} ' +
              ' '.join(f'{c:>14}' for c in cells)
              + f'  {func[:90]}')

if __name__ == '__main__':
    main()
