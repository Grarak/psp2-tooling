#!/usr/bin/env python3
"""Ask the psp2prof sampler (profile/sampler) for a capture, and wait for it.

    cmake -S profile/sampler -B BUILD && cmake --build BUILD     # BUILD/psp2prof.vpk
    install psp2prof.vpk once (devkit/vpk_promoter), launch PSP2PROF0 once a boot
    profile/psp2prof.py HOST0 --seconds 4 --name race

The request is a file the plugin polls (host0:psp2prof/request); it samples every core and
streams HOST0/psp2prof/NAME.p2pf, which this waits for. perf_data.py turns it into perf.data.
The plugin reports on the Vita's kernel TTY ([psp2prof] lines, devkit_console.py).
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
    parser.add_argument('--timeout', type=float, default=30.0,
                        help='seconds past the capture to wait for its file')
    args = parser.parse_args()
    directory = args.host0 / 'psp2prof'
    directory.mkdir(exist_ok=True)
    done = directory / f'{args.name}.p2pf'
    done.unlink(missing_ok=True)
    request = directory / 'request'
    pending = directory / 'request.tmp'
    pending.write_text(f'seconds={args.seconds} hz={args.hz} cores={args.cores:#x} name={args.name}\n')
    pending.rename(request)
    end = time.monotonic() + args.seconds + args.timeout
    while time.monotonic() < end:
        if done.exists():
            print(done)
            return
        time.sleep(0.2)
    taken = not request.exists()
    sys.exit(f'no {done} after {args.seconds + args.timeout:g} s; the request was '
             + ('taken: see the [psp2prof] lines on the kernel TTY' if taken else
                'not taken: is the plugin loaded (launch PSP2PROF0) and host0 served?'))


if __name__ == '__main__':
    main()
