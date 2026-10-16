#!/bin/bash
# A crashed app's core dump: threads, registers, modules, and a backtrace through gdb. In
# development mode the crashed app stays stopped; deci4p_host's "pdump PID" writes the
# psp2core-*.psp2dmp to host0: (psp2_input.py SOCKET pdump PID).
# Usage: core-dump.sh psp2core-X.psp2dmp APP.elf
T=$(cd "$(dirname "$0")/.." && pwd)
python3 $T/devkit/parse_core.py "$1" --elf "$2" --backtrace
