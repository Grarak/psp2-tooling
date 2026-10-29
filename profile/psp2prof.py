#!/usr/bin/env python3
"""Ask the psp2prof sampler (profile/sampler) for a capture, and wait for it.

    cmake -S profile/sampler -B BUILD && cmake --build BUILD     # BUILD/psp2prof.vpk
    install psp2prof.vpk once (devkit/vpk_promoter), launch PSP2PROF0 once a boot
    profile/psp2prof.py HOST0 --seconds 4 --name race

The request is a file the plugin polls (host0:psp2prof/request); it samples every core and
streams HOST0/psp2prof/NAME.p2pf, which this waits for. perf_data.py turns it into perf.data.
The plugin reports on the Vita's kernel TTY ([psp2prof] lines, devkit_console.py).

--stack BYTES also takes user-mode stacks: --stack-hz times a second the plugin halts each core
in --stack-cores through its debug block for its registers and BYTES from its SP (whatever the
core runs, interrupts masked or not), then restarts it. unwind_snapshots.py --p2pf unwinds them.

--waits PID also reads the states of that process's threads, running or not: a PC sample sees
only the threads that run, so a blocked thread's time is not in it. Every thread of PID that a
sample catches running is watched, and --waits-hz times a second each one's status, wait type
and object are read, with the syscall it is in and the user code that called it, and for a
blocked thread the kernel calls below that syscall's frame (Thumb return addresses into kernel
modules' code, a stack scan); each object waited on is named. waits.py reports them. A thread
another process created is that process's: give the PID the samples show for it.
"""
import argparse
import sys
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('host0', type=Path, help='the directory deci4p_host.py serves as host0:')
    parser.add_argument('--seconds', type=int, default=4)
    parser.add_argument('--hz', type=int, default=1000, help='samples a second per core (10..10000)')
    parser.add_argument('--cores', type=lambda v: int(v, 0), default=0x7,
                        help='core mask (default 0x7; core 3 runs the sampler, so its samples are the sampler)')
    parser.add_argument('--name', default='capture', help='[A-Za-z0-9._-] only')
    parser.add_argument('--stack', type=int, default=0,
                        help='stack bytes a snapshot, 256..16384 in 256s (default 0: no stacks)')
    parser.add_argument('--stack-hz', type=int, default=100, help='snapshots a second per core')
    parser.add_argument('--stack-cores', type=lambda v: int(v, 0), default=0,
                        help='cores to snapshot (default: --cores; never core 3)')
    parser.add_argument('--waits', type=lambda v: int(v, 0), default=0,
                        help="a process ID: its threads' states, running or blocked, read "
                             '--waits-hz times a second (profile/waits.py reports them)')
    parser.add_argument('--waits-hz', type=int, default=200, help='state reads a second (1..--hz)')
    parser.add_argument('--timeout', type=float, default=30.0,
                        help='seconds past the capture to wait for its file')
    args = parser.parse_args()
    directory = args.host0 / 'psp2prof'
    directory.mkdir(exist_ok=True)
    done = directory / f'{args.name}.p2pf'
    done.unlink(missing_ok=True)
    request = directory / 'request'
    pending = directory / 'request.tmp'
    stack = (f' stack={args.stack} stackhz={args.stack_hz} stackcores={args.stack_cores or args.cores:#x}'
             if args.stack else '')
    waits = f' waits={args.waits:#x} waitshz={args.waits_hz}' if args.waits else ''
    pending.write_text(f'seconds={args.seconds} hz={args.hz} cores={args.cores:#x}{stack}{waits} '
                       f'name={args.name}\n')
    pending.rename(request)
    end = time.monotonic() + args.seconds + args.timeout
    while time.monotonic() < end:
        if done.exists():
            print(done)
            return
        time.sleep(0.2)
    taken = not request.exists()
    # Not taken: withdrawn, or the next boot's plugin would take it on its own.
    request.unlink(missing_ok=True)
    sys.exit(f'no {done} after {args.seconds + args.timeout:g} s; the request was '
             + ('taken: see the [psp2prof] lines on the kernel TTY' if taken else
                'not taken: is the plugin loaded (launch PSP2PROF0) and host0 served?'))


if __name__ == '__main__':
    main()
