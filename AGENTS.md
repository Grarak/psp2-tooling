# AGENTS.md

How to debug and profile an app on a PS Vita DevKit from Linux with this repo's tools: power
cycle, launch, profile the CPU and GPU, collect the results, analyze them. It applies to any
app built with VitaSDK. Each tool's `--help` (or its header docstring) has every option;
`examples/` has one script per workflow, and the steps below show what those scripts do so
you can adapt them.

## Tools by step

| Step | Tool | Example |
|---|---|---|
| Power the Vita on, off, cycle; log the consoles | `devkit/devkit_console.py` | (inside `session.sh`) |
| Serve `host0:`, launch and kill apps, input, a socket for the rest | `devkit/deci4p_host.py` | (inside `session.sh`) |
| Commands to that socket from the shell | `devkit/psp2_input.py` | |
| One whole boot: power up, launches, timed actions, power off | `devkit/session.sh` | every example |
| Install a VPK | `devkit/vpk_promoter/` | `examples/install-and-run.sh` |
| Screenshots: HDMI or the framebuffer | `session.sh` `GRAB=`, `devkit/vcp_capture.py` | `examples/install-and-run.sh` |
| CPU, whole system (every core, kernel, syscalls) | `profile/sampler/`, `profile/psp2prof.py`, `profile/perf_data.py` | `examples/cpu-profile.sh` |
| CPU, one process: flat and call stacks | `profile/vita_prof.py`, `profile/unwind_snapshots.py`, `profile/leaf_callers.py`, `profile/perf_data.py` | `examples/call-stacks.sh` |
| GPU | `razor/recorder/`, `razor/rzlv.py`, `razor/sgx_capture.py` | `examples/razor.sh` |
| Crashes | `devkit/parse_core.py` | `examples/core-dump.sh` |

Names used below:

- `HOST0`: the host directory served as `host0:`, always an absolute path (see Rules).
- `TITLEID`: the app's title ID, nine capitals and digits such as `ABCD00001`.
- `APP.elf`: the unstripped ELF of the build that runs.
- `OUT`: a session's output directory (`session.sh`'s `OUT=`).
- `$TOOLS`: this repo's root.

## How a session runs

A session is one boot of the DevKit, and `devkit/session.sh SECONDS LAUNCH...` runs it:

```
power cycle ─▶ launch 1 ─▶ timed GRAB / AUDIO / PRESS / RUN ─▶ kill ─▶ launch 2 ... ─▶ power off
     │                                    │
     ▼                                    ▼
OUT/console.log, OUT/deci4p.log      OUT/launch-N/, HOST0/psp2prof/, HOST0/*.rzlv
```

1. `devkit_console.py --power cycle` through the CP board (the mini-USB port, `054c:0432`);
   the Vita's own USB port (`054c:04cd`) drops and comes back once VitaOS is up.
2. `devkit_console.py --follow` logs the consoles; `deci4p_host.py --usb` serves `HOST0` and
   opens the control socket (`$SOCK`).
3. Each `LAUNCH` (a `host0:` path with its arguments, or an installed `TITLEID`) is started
   over LOADP, the timed actions run T seconds after it, and after `SECONDS` it is killed.
4. The Vita is powered off, also on Ctrl-C, a `STOP` match or a refused launch.

The analysis happens on Linux after the boot. A boot costs about a minute before the app
starts, so plan what to measure, when (seconds after the launch) and for how long first.

## Rules

- **One owner.** Only one session drives the DevKit at a time. Two `deci4p_host.py` on the
  same link, or a second `session.sh`, break both.
- **Always power off.** Ctrl-C `session.sh` (or kill the PID in `OUT/session.pid`); it powers
  the Vita off. Never leave the Vita on a static screen while you work something out: the
  OLED burns in. Power off and relaunch later.
- **Small register snapshots.** With `vita_prof.py --registers` pass `--stack-bytes 2048`
  (the tool's default is 8192; stay at 4096 or below), and keep `--stack-depth` at 0, 8 at
  most. Larger stack copies and deeper USTACK walks overrun the stack and freeze the whole
  console. A thread that runs near its stack top needs 1024.
- **The exact ELF.** The profilers need the unstripped ELF of the same build as the
  `eboot.bin` that ran. Another build's ELF gives wrong symbols without an error, except in
  `unwind_snapshots.py`, which checks the ELF's SHA-256 against the capture. Keep it beside
  the run.
- **Absolute paths.** `RUN=` commands run inside `OUT/launch-N/`: a relative `HOST0` or ELF
  path there points nowhere. The examples take `HOST0` from their first argument, so give
  them an absolute one.
- **Short socket paths.** AF_UNIX paths are at most 108 bytes; `session.sh` puts its socket
  in `$XDG_RUNTIME_DIR`. Do the same for a manual `--control`.
- **Console first.** When the app dies, hangs or a profile comes back empty, read
  `OUT/console.log` and `OUT/tty.log` before anything else (see Crashes).

## Once per DevKit

- **Setup the tools were tested with:** firmware 3.65 with Ensō and taiHEN, unsafe homebrew
  enabled. psp2prof depends on 3.65's kernel layout.
- **Connections:** the CP board's mini-USB, the Vita's USB port, and HDMI into a USB capture
  card that Linux sees as a V4L2 video device and an ALSA sound card. Target Manager must
  not run.
- **Permissions:** Linux needs read/write access to `054c:0432` and `054c:04cd` (the udev
  rule is in `devkit_console.py`'s header). `python3 devkit/devkit_console.py --state` checks
  the CP link.
- **Capture card:** `session.sh` grabs from `CAPDEV` (a V4L2 device that delivers MJPEG
  1280x720 at 60 fps) and records audio from `AUDDEV` (an ALSA device, 48 kHz stereo). Set
  both for your card, `CAPDEV` by its stable `/dev/v4l/by-id/...` path: a `/dev/videoN`
  number can belong to another camera and changes between boots.
- **psp2prof:** build and install it once. The first half of `examples/cpu-profile.sh` builds
  `profile/sampler` (`psp2prof.vpk`, title `PSP2PROF0`) and `devkit/vpk_promoter`, and
  installs the VPK. It has to be installed: taiHEN gives the kernel-module load only to
  installed unsafe apps, not to a SELF launched from `host0:`.

## The session step by step

### 1. Stage HOST0

`HOST0` holds what the app reads from `host0:`: its `eboot.bin`, data and config files. The
Vita can't reach outside it (`..` is refused).

```
HOST0=$PWD/host0
mkdir -p $HOST0/app && cp build/eboot.bin $HOST0/app/
cp build/APP.elf runs/APP.elf          # the ELF of this exact build
```

To run an installed title instead, install the VPK once:

```
examples/install-and-run.sh APP.vpk VITASHELL_HEAD_BIN TITLEID
```

- `devkit/vpk_promoter/stage.py` unpacks the VPK (it needs `sce_sys/param.sfo` and
  `eboot.bin`) into a new `--out` directory with `promoter.bin`, and writes the package
  header from VitaShell's `head.bin`. Without the header the promotion fails with
  `0x8010111C`.
- `session.sh` with `INSTALL=1` runs `host0:/promoter.bin` first and checks for
  `[vpk-promoter] promote: 0x00000000` on the console.
- To update an installed app, unzip the new VPK over `HOST0/package` and stage again: the
  header must stay.

### 2. Power cycle

`session.sh` does it. By hand:

```
python3 devkit/devkit_console.py --state                    # state on, off or standby
python3 devkit/devkit_console.py --power cycle --timeout 5  # off, then on
python3 devkit/devkit_console.py --power on --timeout 5     # when cycle is refused (0x2007): it was off
```

Each request prints its status: `accepted`, or why it was refused (`0x2007` wrong power
state, `0x2011` the Syscon link is gated, `0x2014` the Vita holds the power lock).
`[POWER]` lines in the console show the CP's power events.

### 3. Launch

```
HOST0=$HOST0 OUT=runs/look GRAB="30 60" STOP='assert' \
    devkit/session.sh 90 "host0:/app/eboot.bin -titleid TITLEID"
```

- Each `LAUNCH` argument is one app, run in order in the same boot, with its own
  `OUT/launch-N/`. An installed title launches by its ID: `devkit/session.sh 90 TITLEID`.
- `-titleid` names what to kill at the end (or set `KILL=TITLEID`).
- A launch ends early when its process exits, or when a console line matches `STOP`, which
  also forces the Vita off.
- `session.sh` prints the `LOADP reply` line: `result 0x0 (ok)` with a pid is a started
  process; anything else is a refused launch, with the reason in brackets.

For interactive work (look, poke, decide), run the pieces by hand:

```
RUN=$PWD/runs/manual; SOCK=$XDG_RUNTIME_DIR/psp2.sock; mkdir -p $RUN
python3 devkit/devkit_console.py --log $RUN/cp-console.log --follow --timeout 86400 > /dev/null &
python3 devkit/deci4p_host.py --usb --host0 $HOST0 --control $SOCK --log-dir $RUN &
python3 devkit/psp2_input.py $SOCK launch host0:/app/eboot.bin -titleid TITLEID
python3 devkit/psp2_input.py $SOCK launchstatus      # ok loadp open ... last pid 0x... running
# ... input, profilers, screenshots ...
python3 devkit/psp2_input.py $SOCK kill TITLEID
kill %2 %1                                           # the stand-in, then the console
python3 devkit/devkit_console.py --power off --wait off --timeout 15 ||
    python3 devkit/devkit_console.py --power force-off --wait off --timeout 10
```

- `launch` goes through SceAppMgr, as the shell does. `spawn PATH` starts a bare process.
- `moduleload PID PATH`, `modulestart`, `modulestop` and `moduleunload` load a module into a
  running process.
- LOADP takes one request at a time; the stand-in queues the rest and sends them once LOADP
  is open, so a launch sent early waits instead of failing.
- With no command on its command line, `psp2_input.py` reads one command per line from
  stdin.

### 4. Drive and watch

Input goes through `psp2_input.py SOCKET COMMAND`, or timed through `session.sh`'s
`PRESS="35=press circle;40=press cross"`:

| Command | Use |
|---|---|
| `press circle`, `press up 0.2` | Tap a button (seconds optional; default 0.5) |
| `buttons l+r` / `release` | Hold exactly these until changed / let everything go |
| `pad BUTTONS LX LY RX RY` | Buttons and both sticks, axes 0..255, 128 leaves an axis alone: `pad 0 128 0 128 128` holds the left stick up |
| `touch X Y` / `untouch` | One front-panel contact, 0..959 by 0..543 |
| `status` | What is held now |

- Button names are `select`, `start`, the D-pad's `up`, `right`, `down` and `left`, `l`,
  `r`, `l2`, `r2`, `l3`, `r3`, the face buttons `triangle`, `circle`, `cross` and `square`,
  and `ps`, `volup` and `voldown`. Join several with `+`.
- `pad` sends the axes in both halves of the record, so apps that sample in
  `SCE_CTRL_MODE_ANALOG_WIDE` see them too.
- A button held on the real pad can't be cleared from the host.
- Check with a grab that the input did what you expected before profiling on it.

Pictures and sound:

- `GRAB="T..."`: an HDMI frame `grab-T.png` T seconds after the launch (the capture's first
  frames are stale; `session.sh` keeps the 11th).
- `AUDIO="T SECS"`: HDMI audio `audio-T.wav`.
- `RUN='40=python3 $TOOLS/devkit/vcp_capture.py --socket $SOCK screen.png'`: VitaOS's own
  framebuffer, no capture card needed. `--selector 0` is the app's frame and `1` the shell's;
  by default it tries 0, then 1. Outside a session it opens its own link
  (`--transport vita` or `cp`).

Text:

- `OUT/console.log` (host timestamps) prefixes each line with its channel: `[CP]` the CP board
  and the Vita's UART, `[TTYn]` the OS's TTY channels, `[KTTY0]`..`[KTTY3]` the kernel's
  per-core consoles, `[POWER]` power events.
- `OUT/tty.log` has the kernel's console writes and each process's output, one
  `[TTYPn PID]` prefix per line: the app's own `printf` output is here.

### 5. Profile the CPU

| Question | Tools | Output |
|---|---|---|
| Where does the whole system spend its time: every core, the kernel, syscalls under their callers? | `psp2prof.py` (launch `PSP2PROF0` first in the same boot) | `HOST0/psp2prof/NAME.p2pf` |
| Which functions of the app are hot, per thread? | `vita_prof.py` (Sony's DTrace; nothing to install) | `OUT.txt`, `OUT.samples` |
| Who calls them (inclusive cost)? | `vita_prof.py --registers --stack-bytes 2048` | `OUT.register-info.json`, `.registers.jsonl`, `.stack.bin` |

What each one misses:

- psp2prof's sampler runs on core 3, so the default mask `--cores 0x7` covers cores 0-2: a
  thread pinned to core 3 needs DTrace. It takes no call stacks. Its ring holds 65536
  samples; a capture that outruns the host0: writes reports them as `dropped`.
- DTrace samples from each core's timer interrupt: a core with interrupts masked is never
  sampled, and kernel samples are bare PCs (`[kernel]` in the report). Use it for one
  process's code and its stacks.
- A crashed process has no samples.

Profilers run as `RUN="T=CMD"`, T seconds after the launch. Pick T and the length so the
window covers only what you are measuring (not a loading screen) and add a `GRAB` at the
same T to see it. One profiler per launch; keep T and the length the same across runs you
compare.

Whole system (`examples/cpu-profile.sh HOST0 TITLEID APP.elf VITASHELL_HEAD_BIN` builds and
installs psp2prof, then does this):

```
HOST0=$HOST0 OUT=runs/sys GRAB=60 \
RUN='60=python3 $TOOLS/profile/psp2prof.py $HOST0 --seconds 4 --name sys' \
    devkit/session.sh 90 PSP2PROF0 TITLEID
```

- `PSP2PROF0` loads the kernel plugin and exits, then the app launches.
- The plugin stays loaded until the next boot, and a second load reports `0x8002D013`.
- It reports on the kernel TTY:
  - `[psp2prof] ready: waiting for host0:/psp2prof/request` after loading;
  - `capturing NAME: S s at H Hz, cores 0x7` when a capture starts;
  - `host0:/psp2prof/NAME.p2pf: N samples, M dropped, P processes` when it ends.
- `--seconds` takes 1..600 and `--hz` 10..10000 (default 1000).

One process, flat:

```
ELF=$(realpath runs/APP.elf)
HOST0=$HOST0 OUT=runs/flat \
RUN="60=python3 \$TOOLS/profile/vita_prof.py --socket \$SOCK --deci-log \$DECI_LOG --elf $ELF --seconds 10 --out prof" \
    devkit/session.sh 90 TITLEID
```

Call stacks (`examples/call-stacks.sh HOST0 TITLEID APP.elf` does this and the analysis):

```
HOST0=$HOST0 OUT=runs/stacks \
RUN="60=python3 \$TOOLS/profile/vita_prof.py --socket \$SOCK --deci-log \$DECI_LOG --elf $ELF --seconds 10 --registers --stack-bytes 2048 --out snap" \
    devkit/session.sh 90 TITLEID
```

- `$SOCK`, `$DECI_LOG`, `$LAUNCH_DIR` and `$TOOLS` are set for `RUN` commands. Escape them
  (`\$`) inside double quotes.
- `vita_prof.py` needs a process:
  - `--deci-log` takes the pid and the text base from the last LOADP launch, and follows a
    launch that re-executes itself to the child;
  - `--pid` and `--base` override them;
  - `--all` samples every process.
- For call stacks, pass both `--elf` and `--deci-log`. The capture records the ELF's SHA-256
  and the text base, and `unwind_snapshots.py` refuses another ELF or a relocated base.
- Defaults are 997 Hz (199 Hz with `--registers`), with a 256 KiB buffer per CPU (512 KiB,
  the most, with `--registers`). Larger buffers exhaust the DTrace module's heap and panic
  the kernel, so the tool refuses them.
- `--stack-depth N` adds Sony's native USTACK walk instead (`OUT.stacks.jsonl`). Keep N at 8
  or below.

### 6. Profile the GPU (Razor)

The app records Razor data itself. Add `razor/recorder/razor.cpp`, link
`SceRazorCapture_stub_weak`, `SceRazorHud_stub_weak`, `ScePamgr_stub`, `SceSysmodule_stub`
and `SceGxm_stub`, and call the hooks (`razor/recorder/razor.h` lists the options):

```
razor::initialize("live=host0:/gpu.rzlv,hide-hud,group=1,start=600,frames=120");
sceGxmInitialize(...);
for (;;) { draw(); sceGxmPadHeartbeat(...); razor::frame(); }
sceGxmFinish(ctx); razor::stop(); sceGxmTerminate(); razor::terminate();
```

Then `examples/razor.sh HOST0 TITLEID` writes `LIVE=1` into `HOST0/hud_settings.ini`, runs
the app for 60 s and decodes the result.

- `group=`: 0 parameter buffer, 1 USSE and texture activity, 2 primitive, vertex and pixel
  counts, 3 TA and ISP memory traffic.
- `start=` and `frames=` count `razor::frame()` calls: start past the loading.
- `capture=host0:/frame.sgx,capture-frame=N` saves one frame's snapshot (draws, programs,
  memory; call `register_buffer()` for every `sceGxmMapMemory` buffer). It pauses the GPU:
  never in a run you measure.
- The recorder prints its status to stderr, with the app's output:
  - `razor: <operation> = <status>` for each Razor call;
  - `razor: native performance mode N (live requires 3)`;
  - `razor: dropped N live entries` when the buffer overflowed.

### 7. Collect

| Where | What |
|---|---|
| `OUT/console.log` | The boot's console with host timestamps (`cp-console.log` without) |
| `OUT/tty.log` | The kernel's console writes and each process's output |
| `OUT/deci4p.log` | Every DECI4p packet decoded: LOADP replies and events (pids, exits, the main module's segments), host0: file requests |
| `OUT/launch-N/` | That launch's slice of `console.log` and `deci4p.log`, `actions.log` (when each grab, press and command ran, and their output), `grab-T.png`, `audio-T.wav`, `RUN` outputs |
| `OUT/cp-off.log`, `OUT/deci4p-off.log` | The power-off |
| `HOST0/psp2prof/NAME.p2pf` | psp2prof captures (`NAME.part` while streaming) |
| `HOST0/gpu.rzlv`, `HOST0/frame.sgx` | Razor metrics and snapshots |
| `ux0:data/psp2core-*.psp2dmp` on the Vita | Core dumps; copy them off over FTP or VitaShell |

Name each `OUT` after what it measured and keep the ELF with it.

### 8. Analyze

psp2prof, whole system:

```
python3 profile/perf_data.py $HOST0/psp2prof/sys.p2pf --elf runs/APP.elf --out runs/sys/sys.perf.data
perf report -i runs/sys/sys.perf.data --sort comm,dso,sym --stdio | head -80
hotspot runs/sys/sys.perf.data
```

- `comm` is the thread name. `dso` separates the app's ELF, Sony's modules
  (`MODULE+OFFSET` blocks) and the kernel.
- A syscall's sample carries the user PC that made it as its callchain, so kernel time
  appears under its caller in hotspot's caller view.
- If the app's samples stay hex, its module name on the Vita differs from the ELF's file
  name: pass `--module NAME`.

DTrace, flat:

- `runs/flat/launch-1/prof.txt` already ranks the hottest functions overall and for the 8
  busiest threads. `[other module]` is a PC outside the ELF (Sony's modules).
- For perf or hotspot:

  ```
  python3 profile/perf_data.py runs/flat/launch-1/prof.samples --elf runs/APP.elf \
      --deci-log runs/flat/launch-1/deci4p.log
  ```

- DTrace samples have no thread names: `--threads FILE` takes lines of `TID NAME` (TID in
  hex).

Call stacks:

```
L=runs/stacks/launch-1
python3 profile/unwind_snapshots.py --info $L/snap.register-info.json --elf runs/APP.elf --out $L/cfi
python3 profile/perf_data.py $L/cfi.samples --elf runs/APP.elf --deci-log $L/deci4p.log
perf report -i $L/cfi.perf.data --children --sort sym --stdio | head -80    # inclusive
hotspot $L/cfi.perf.data                                                    # flame graph, callers
python3 profile/leaf_callers.py runs/APP.elf $L/snap                        # what CFI can't unwind
```

- The unwinder follows the ELF's DWARF CFI only, through elfutils' `libdw`. It stops where
  the captured bytes end, so deep stacks are cut short.
- `$L/cfi.cfi.jsonl` says why each snapshot stopped.
- Samples in Sony's modules, asm `memcpy`/`memset` and divisions don't unwind.
  `leaf_callers.py` finds their callers from the return addresses on the stack.

Razor:

```
python3 razor/rzlv.py $HOST0/gpu.rzlv --csv runs/gpu/jobs.csv --trace runs/gpu/gpu.json --json runs/gpu/counters.json
python3 razor/sgx_capture.py $HOST0/frame.sgx --json runs/gpu/frame.json --extract-programs runs/gpu/programs
```

- **The summary.** `rzlv.py` prints a JSON summary: frames, jobs, TA and 3D busy time
  (`busy_us`, the union of job intervals; `core_us` sums the cores) and `gpu_busy_us`.
- **Check it's complete.** `collection_state` must be `stopped` and `trace_complete` true.
  Otherwise the app never called `razor::stop()`, the start failed, or entries overflowed.
- **The timeline.** `gpu.json` opens in https://ui.perfetto.dev and shows each GPU core's
  TA and 3D jobs on the kernel clock.
- **Reading it.** A GPU busy for nearly the whole frame means GPU-bound; long gaps mean
  the CPU isn't feeding it.

### 9. Power off

`session.sh` powers off by itself. After a manual session, or when it couldn't:

```
python3 devkit/devkit_console.py --state
python3 devkit/devkit_console.py --power force-off --wait off --timeout 10
```

## A typical workflow: a slow section

1. **Find it.** Grabs every 20 s show when the section is on screen. `PRESS=` drives the app
   there if it needs input:

   ```
   HOST0=$HOST0 OUT=runs/look GRAB="20 40 60 80" devkit/session.sh 90 TITLEID
   ```

2. **Whole system.** Which thread, which module, how much kernel time:
   `examples/cpu-profile.sh` (or step 5's psp2prof session) with T inside the section, then
   step 8.
3. **Callers.** For the hottest thread: `examples/call-stacks.sh` with its `RUN` time edited
   to the section. Read the inclusive tree from that thread's top function down.
4. **GPU.** If the render thread waits on the GPU: `examples/razor.sh` with `start=` past
   the loading, then `rzlv.py --trace` in Perfetto.
5. **Change, rebuild, rerun.** Keep the same `PRESS`, T and length, and stage the new
   `eboot.bin` with its ELF. Compare per-thread totals and the top functions against the
   previous `OUT`.

## Crashes

1. **Read the kernel's report.**
   - `grep -a 'KTTY' OUT/console.log`: the kernel prints a crashed process's waypoints and
     `Print Backtrace(User stack)` with `PC:0x... [MODULE + 0xOFFSET]` there.
   - Add the offset to the ELF's text address (VitaSDK links at `0x81000000`) and look it
     up with `$VITASDK/bin/arm-vita-eabi-addr2line -f -C -i -e APP.elf ADDRESS`.
2. **Read the core dump**, if there is one (`ux0:data/psp2core-*.psp2dmp`, copied off):

   ```
   examples/core-dump.sh psp2core-X.psp2dmp APP.elf                               # every thread's backtrace
   python3 devkit/parse_core.py psp2core-X.psp2dmp --elf APP.elf --all-threads   # registers and stack scans
   python3 devkit/parse_core.py psp2core-X.psp2dmp --gdb-core core.arm           # for gdb-multiarch APP.elf core.arm
   ```

   `--backtrace` needs `gdb-multiarch` or `arm-vita-eabi-gdb`.
3. **Stop at asserts.** Set `STOP` to the assert's text: the session ends at the message and
   powers off. A process stopped in an assert can block the normal shutdown, so
   `session.sh` kills it.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `waiting for 054c:0432` | The CP board's mini-USB isn't attached, Target Manager holds it, or permissions are missing. |
| `the Vita's USB (054c:04cd) did not appear` | The Vita didn't boot, or the cable or permissions are wrong. Check with `devkit_console.py --state`. |
| `launch refused` | The `LOADP reply` line names the result, for example `no such file, or the path is not allowed` or `no such process or title`. |
| A power request refused with `0x2014` | The Vita holds the power lock, often a running app. Start `deci4p_host.py`, `psp2_input.py SOCK kill TITLEID`, then `--power force-off --wait off`. |
| The console freezes during a profile | Register snapshots or stack depth too big. Force off and rerun with `--stack-bytes 2048` and `--stack-depth 0`. |
| `vita_prof.py`: `no pid` | Give `--deci-log` (with a successful launch in it), `--pid` or `--all`. |
| `unwind_snapshots.py`: `Recorded/local ELF SHA-256 mismatch` or `Relocated/unknown ET_EXEC load base` | A different ELF from the one given to `vita_prof.py`, or the capture had no `--elf` or `--deci-log`. |
| A profile without the app's samples | It crashed (see Crashes), the pid came from another launch, or psp2prof never printed `ready`. |
| Wrong or missing symbols | Not the ELF of this build. For psp2prof, the module name differs from the ELF's file name: pass `--module`. |
| `psp2prof.py`: `no ... after N s; the request was not taken` | `PSP2PROF0` wasn't launched this boot, or `HOST0` isn't the directory `deci4p_host.py` serves. With `was taken`, the capture failed: see the `[psp2prof]` lines. |
| Razor `STAT 0x8008c008` / `0x8008c002` | `HOST0/hud_settings.ini` is missing / doesn't say `LIVE=1`. |
| A black or old HDMI grab | The app wasn't up at T, `CAPDEV` isn't the capture card, or the card can't deliver MJPEG 1280x720 at 60 fps. |
| Promotion fails with `0x8010111C` | The package has no header. Stage it with `vpk_promoter/stage.py`. |
