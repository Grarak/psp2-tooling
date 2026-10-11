#!/bin/bash
# Install a VPK on the DevKit and run the app for a minute, with an HDMI frame at 30 s and a
# screenshot over VCP at 40 s. Usage: install-and-run.sh APP.vpk VITASHELL_HEAD_BIN TITLEID
set -e
T=$(cd "$(dirname "$0")/.." && pwd)
HOST0=$PWD/host0
cmake -S $T/devkit/vpk_promoter -B build/promoter -G Ninja && ninja -C build/promoter
python3 $T/devkit/vpk_promoter/stage.py --vpk "$1" --head-template "$2" \
    --promoter build/promoter/promoter.bin --out $HOST0
# The installed title launches by its ID. Logs and grabs land in run/launch-1/.
HOST0=$HOST0 OUT=run INSTALL=1 GRAB="30" \
    RUN='40=python3 $TOOLS/devkit/vcp_capture.py --socket $SOCK screen.png' \
    $T/devkit/session.sh 60 "$3"
