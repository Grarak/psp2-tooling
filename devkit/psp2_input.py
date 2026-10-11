#!/usr/bin/env python3
"""Presses buttons, moves the sticks and places touch contacts on a DevKit.

devkit/deci4p_host.py, the Target Manager stand-in, opens a control socket beside
each DECI4p link it was given --control for.  Commands sent here become
CTRLP packets, DECI4p's controller protocol; the Vita's own deci4p_ctrlp module
feeds them to SceCtrl and SceTouch through ksceCtrlSetButtonEmulation and the two
Ctrlp callbacks.  Nothing is synthesised on the host side.

    devkit/psp2_input.py RUN/deci4p-input.sock press cross
    devkit/psp2_input.py RUN/deci4p-input.sock touch 480 272
    devkit/psp2_input.py RUN/deci4p-input.sock status
    printf 'touch 480 272\\nuntouch\\n' | devkit/psp2_input.py RUN/deci4p-input.sock

Commands:

    buttons BUTTONS          hold exactly these until changed
    press BUTTONS [SECONDS]  hold, then release (default 0.5, at most 60)
    release                  let go, sticks centred too
    pad BUTTONS LX LY RX RY  hold these buttons and the sticks (0..255, 128 leaves
                             an axis alone)
    playpad PORT BUTTONS LX LY RX RY
                             the same through a playback session on PORT (0..4)
    playpress BUTTONS        hold these through a playback session instead
    playboth BUTTONS X Y     one playback session carrying both a pad record and
                             a touch contact, so the pad half is the control
    playstop                 end that session and give the pad back
    touch X Y [FORCE]        one contact at screen coordinates, 0..959 by 0..543
    untouch                  lift it and give the panel back to the hardware
    panelinfo [PANEL]        ask ctrlp for its cached panel descriptor (0 or 1);
                             the reply body lands in the packet log
    record [CHANNELS]        have the Vita send its own pad and touch back
                             (1 pad, 2 touch, 3 both; default touch)
    recordstop               end that recording session
    status                   what is held now
    launch TARGET [ARG...]   start a SELF by path (host0:/app/eboot.bin) through
                             SceAppMgr, or an installed title by its ID, over
                             LOADP; the result lands in
                             the packet log
    spawn PATH [ARG...]      start a SELF as a bare process, without SceAppMgr
    kill PID_OR_TITLEID      end a process or a running title
    launchstatus             whether LOADP is open, and the last launch's result

BUTTONS is a name, several joined with '+', or a number: select, start, up, right,
down, left, l, r, l2, r2, l3, r3, triangle, circle, cross, square, ps, volup,
voldown.  A held button cannot be cleared this way, because SceCtrl merges the
emulated word with the physical pad.

The stand-in answers commands only while its link to the Vita is up.
"""

import argparse
import socket
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                     epilog='Commands:\n' + __doc__.split('Commands:\n', 1)[1],
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('socket', type=Path, help="the stand-in's --control socket")
    parser.add_argument('command', nargs='*',
                        help='one command; with none, commands are read from stdin')
    args = parser.parse_args()

    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(str(args.socket))
    except OSError as error:
        print(f'{args.socket}: {error}', file=sys.stderr)
        return 1
    status = 0
    with sock, sock.makefile('rw', encoding='utf-8', newline='\n') as link:
        lines = [' '.join(args.command)] if args.command else sys.stdin
        for line in lines:
            line = line.strip()
            if not line:
                continue
            link.write(line + '\n')
            link.flush()
            reply = link.readline()
            if not reply:
                print('the stand-in closed the control socket', file=sys.stderr)
                return 1
            print(reply.rstrip())
            if reply.startswith('error'):
                status = 1
    return status


if __name__ == '__main__':
    sys.exit(main())
