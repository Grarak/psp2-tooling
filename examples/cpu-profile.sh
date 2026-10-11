#!/bin/bash
# Whole-system CPU profile (every core, user and kernel, syscalls under their callers) of an
# installed app, 4 s from 60 s after its launch, opened in hotspot.
# Usage: cpu-profile.sh HOST0 TITLEID APP.elf VITASHELL_HEAD_BIN
set -e
T=$(cd "$(dirname "$0")/.." && pwd)
cmake -S $T/profile/sampler -B build/psp2prof -G Ninja && ninja -C build/psp2prof
cmake -S $T/devkit/vpk_promoter -B build/promoter -G Ninja && ninja -C build/promoter
# Once: install psp2prof.vpk (the PSP2PROF0 app carries the kernel plugin and loads it).
rm -rf host0-install
python3 $T/devkit/vpk_promoter/stage.py --vpk build/psp2prof/psp2prof.vpk --head-template "$4" \
    --promoter build/promoter/promoter.bin --out host0-install
HOST0=host0-install OUT=run-install INSTALL=1 $T/devkit/session.sh 10 PSP2PROF0
# Each boot: PSP2PROF0 first (it loads the plugin and exits), then the app.
HOST0=$1 OUT=run RUN='60=python3 $TOOLS/profile/psp2prof.py $HOST0 --seconds 4 --name app' \
    $T/devkit/session.sh 90 PSP2PROF0 "$2"
# --module: the app's module name on the Vita, when it differs from the ELF's file name.
python3 $T/profile/perf_data.py "$1/psp2prof/app.p2pf" --elf "$3" --out run/app.perf.data
hotspot run/app.perf.data    # or: perf report -i run/app.perf.data --sort comm,dso,sym
