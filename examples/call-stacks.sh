#!/bin/bash
# Call stacks of an app's threads through Sony's DTrace: register and stack snapshots for
# 10 s from 60 s, unwound on the host with the ELF's DWARF CFI, opened in hotspot with
# callers and callees. Usage: call-stacks.sh HOST0 TITLEID APP.elf
# Build the app with -g and its SELF with vita-make-fself -na (README, profile/).
set -e
T=$(cd "$(dirname "$0")/.." && pwd)
ELF=$(realpath "$3")
# 2048 bytes of stack a snapshot; a copy past a thread's stack top faults and the event is
# lost, so threads that stay near their top need smaller snapshots (1024).
HOST0=$1 OUT=run RUN="60=python3 \$TOOLS/profile/vita_prof.py --socket \$SOCK --deci-log \$DECI_LOG --elf $ELF --seconds 10 --registers --stack-bytes 2048 --out snap" \
    $T/devkit/session.sh 90 "$2"
python3 $T/profile/unwind_snapshots.py --info run/launch-1/snap.register-info.json --elf $ELF --out run/cfi
python3 $T/profile/perf_data.py run/cfi.samples --elf $ELF --deci-log run/launch-1/deci4p.log
hotspot run/cfi.perf.data
# Samples the CFI could not unwind (Sony's memcpy, asm leaves, divisions), by caller:
python3 $T/profile/leaf_callers.py $ELF run/launch-1/snap
