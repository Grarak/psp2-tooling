#!/bin/bash
# A crashed app's core dump (the Vita writes ux0:data/psp2core-*.psp2dmp; copy it off over
# FTP or VitaShell): threads, registers, modules, and a backtrace through gdb.
# Usage: core-dump.sh psp2core-X.psp2dmp APP.elf
T=$(cd "$(dirname "$0")/.." && pwd)
python3 $T/devkit/parse_core.py "$1" --elf "$2" --backtrace
