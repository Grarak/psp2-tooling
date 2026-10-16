#!/bin/bash
# Sony Razor GPU metrics of a GXM app. In the app (razor/recorder/razor.h has the options):
#
#   razor::initialize("live=host0:/gpu.rzlv,group=1,start=600,frames=120");
#   sceGxmInitialize(...);
#   for (;;) { ...draw...; sceGxmPadHeartbeat(...); razor::frame(); }
#   sceGxmFinish(ctx); razor::stop(); sceGxmTerminate(); razor::terminate();
#
# Usage: razor.sh HOST0 TITLEID
set -e
T=$(cd "$(dirname "$0")/.." && pwd)
HOST0=$1 OUT=run $T/devkit/session.sh 60 "$2"
python3 $T/razor/rzlv.py "$1/gpu.rzlv" --csv run/gpu-jobs.csv --trace run/gpu.json
# run/gpu.json opens in https://ui.perfetto.dev: each GPU core's TA and 3D busy intervals.
# A frame snapshot instead: capture=host0:/frame.sgx,capture-frame=600, then
python3 $T/razor/sgx_capture.py "$1/frame.sgx" --json run/frame.json --extract-programs run/programs || true
