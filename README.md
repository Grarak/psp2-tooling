# psp2-tooling

Host tools for working with a PS Vita DevKit from Linux: console and power, app installs and
launches, input, HDMI capture, CPU profiles (user and kernel space) and Sony Razor GPU data.
Each tool's `--help` (or its header) says how to use it; `examples/` has worked runs.

- Linux only.
- Tested on a DevKit with firmware 3.65, Ensō and taiHEN (unsafe homebrew enabled).
- The DevKit was connected on every port: the CP board's mini-USB, the Vita's own USB port
  (UDC), and HDMI into a USB capture card (MacroSilicon MS2109). Target Manager must not run.
- Python 3 with pyusb; VitaSDK (`$VITASDK`) for the on-device parts and the profilers'
  symbols; elfutils' libdw for unwinding; perf or [hotspot](https://github.com/KDAB/hotspot)
  to view profiles; ffmpeg and arecord for HDMI.

## Retail Vita

`retail-cp/` makes a retail Vita a DevKit for these tools: a taiHEN kernel plugin stands in for
the DevKit's CP board and loads the DevKit's own Target Manager modules, ported to retail. All
of it over the Vita's USB port:

- launch, spawn and kill apps from the PC, with `host0:` files, console output, input
  (buttons, sticks, touch), screenshots and VPK installs;
- CPU profiling: DTrace sampling with call stacks (backtraces through DWARF CFI), and psp2prof's
  whole-system profiles (every core, kernel and syscalls);
- GPU: Razor live metrics (GPU jobs and counters) and Razor frame captures (.sgx);
- hardware breakpoints and watchpoints in a process;
- core dumps of crashed processes on demand (`pdump`), with backtraces;
- resets, reboots and file copies without FTP or network.

Tested only on a PCH-2000 with firmware 3.65, Ensō and taiHEN: retail-cp patches 3.65 kernel
code at fixed offsets, so other firmware versions will most likely not work. No kernel modules
are provided, neither Sony's nor built plugins. [RETAIL.md](RETAIL.md) has per-tool details.

### What you need

Decrypted DevKit 3.65 (3.650.011) `os0:kd/` modules as ELF files, which you must obtain
yourself:

| File | What it is |
|---|---|
| `dbgusb.elf` | DECI4p over the Vita's USB port |
| `deci4p_dfmgr.elf` | DECI4p manager (DCMP) |
| `syslibtrace.elf` | library tracing, needed by pamgr and DTrace |
| `pamgr.elf` | Performance Analyzer (Razor live) |
| `deci4p_ttyp.elf` | TTY consoles |
| `deci4p_userp.elf` | process stdio |
| `deci4p_ctrlp.elf` | buttons, sticks and touch (CTRLP) |
| `deci4p_loadp.elf` | launch and kill (LOADP) |
| `deci4p_drfp.elf` | host0: (DRFP) |
| `deci4p_dbgp.elf` | debugger and core dumps (DBGP) |
| `deci4p_dtracep.elf` | DTrace |
| `deci4p_vcp.elf` | screenshots (VCP) |

Also VitaSDK (`$VITASDK`, with its taiHEN stubs) and Python 3.

### Build and install

```
cmake -S retail-cp -B build/retail-cp && cmake --build build/retail-cp
retail-cp/port_modules.py --modules DEVKIT_FS/os0/kd --out build/retail-modules
```

Copy `retail-cp.skprx` and the `*-retail.skprx` files to `ur0:tai/`, add
`ur0:tai/retail-cp.skprx` under `*KERNEL` in `ur0:tai/config.txt` (above other USB plugins) and
reboot. The first copy needs VitaShell or FTP; after that `devkit/retail_vita.sh put` works over
USB.

### What changes on the Vita

It behaves like a DevKit in development mode:

- Development mode (switch 0x9F) and hardware debug (0xE4) are set in Syscon's boot block and
  stay set until you uninstall (below): removing the plugin by hand does not clear them.
- No crash dialog and no automatic core dump: a crashed app (or the shell) stays stopped until
  `pdump`/`kill` or a reset; launches fail (LOADP 0x3003B) meanwhile.
- The USB port is the debug port (054C:04CD): no MTP or USB charging-only mode.
- No idle sleep; suspend only turns the screen off. Apps keep running with the screen off.
- OS reboots and kernel crashes restart through Syscon (a crash leaves a `crash=` line in
  `ur0:data/retail-debug/cp.txt`).
- Kernel `printf` output goes over TTY to the host (`devkit_console.py --retail`, deci4p_host's
  `tty.log`), as on a DevKit.
- The QA flag that lets processes open `host0:` is set, so apps can run straight from the host.
- No lock screen: the shell boots straight to the home screen.

### Uninstall

With the Vita connected and retail-cp running:

```
devkit/retail_vita.sh uninstall
```

It takes `retail-cp.skprx` out of `ux0:tai/config.txt` and `ur0:tai/config.txt`, then retail-cp
clears development mode and hardware debug in Syscon's boot block, deletes the files it was
installed with (`ur0:tai/retail-cp.skprx`, the `*-retail.skprx` files and
`ur0:data/retail-debug/`) and restarts the Vita, which comes back as a retail Vita with MTP.
Don't remove retail-cp from the config by hand first: without it nothing can clear the switches.

## devkit/

| Tool | What it does |
|---|---|
| `devkit_console.py` | CP console and the Vita's TTY channels over the mini-USB port; power on, off, cycle, reset and state |
| `deci4p_host.py` | Target Manager stand-in on the Vita's USB port: serves host0:, launches and kills apps (LOADP), buttons, sticks and touch (CTRLP), a control socket for the rest |
| `psp2_input.py` | Client for `deci4p_host.py`'s control socket: input, launch, kill, core dumps of stopped processes (`pdump`) |
| `session.sh` | One boot: power up, optional VPK install, launch apps with timed HDMI grabs, audio, input and commands, power off |
| `vcp_capture.py` | Screenshot of what VitaOS displays (VCP), standalone or through a running `deci4p_host.py` |
| `vpk_promoter/` | Installs a VPK through the Vita's own promoter, over host0: (`stage.py` prepares it) |
| `retail_vita.sh` | Retail Vita only: copy files on and off, list directories, reset, over the USB link alone |
| `parse_core.py` | Reads a Vita core dump (psp2core-*.psp2dmp): threads, registers, modules, backtraces; writes an ARM core for gdb |

## profile/

| Tool | What it does |
|---|---|
| `sampler/` | psp2prof: a taiHEN kernel plugin that samples every core's PC (CoreSight), its thread and process, and a syscall's user caller; `psp2prof.vpk` (PSP2PROF0) loads it |
| `psp2prof.py` | Asks the loaded plugin for a capture over host0: and waits for it |
| `vita_prof.py` | Sony's DTrace sampler over DECI4p: user and kernel PCs, or register and stack snapshots for call stacks |
| `unwind_snapshots.py` | Unwinds `vita_prof.py`'s snapshots with the ELF's DWARF CFI (libdw); `arm32_cfi.py` and `elf32.py` are its parts |
| `leaf_callers.py` | Callers of samples DWARF CFI cannot unwind: Sony's modules, asm memcpy/memset, divisions |
| `perf_data.py` | Turns psp2prof captures or DTrace samples (with stacks) into perf.data for hotspot and perf |

Build an app you profile with `-g` and its SELF with `vita-make-fself -na` (`NOASLR` in
`vita_create_self`). `unwind_snapshots.py` walks the ELF's `.debug_frame`, which only `-g`
emits: without it every snapshot stops at its first frame ("No DWARF information found").
`-na` turns ASLR off, so the app loads at its link address: the Vita loads an ASLR SELF
launched over LOADP at a new base each launch, and `unwind_snapshots.py` and
`leaf_callers.py` read the ELF at its link address.

Why psp2prof when the DevKit already has DTrace: DTrace's profile probe fires from each core's
own timer interrupt, so a core running with interrupts masked is never sampled, and a sample
taken in the kernel is a bare kernel PC with no module name and no link to the user code that
made the syscall. psp2prof reads each core's PC from the outside (the Cortex-A9's CoreSight
debug registers, from core 3), so every core is seen, and it records the kernel's and each
process's module lists, the thread names, and for a sample inside a syscall the user PC and LR
the SVC handler saved: kernel time shows up under its caller. DTrace stays for call stacks: its
register and stack snapshots of user-mode samples are what `unwind_snapshots.py` walks, which
psp2prof cannot take from another core.

## razor/

| Tool | What it does |
|---|---|
| `recorder/` | Hooks for a GXM app that record Razor GPU Live metrics (.rzlv) and GPU snapshots (.sgx) |
| `rzlv.py` | Decodes .rzlv: GPU jobs per core, busy time, counters; CSV, JSON and a Chrome trace for ui.perfetto.dev |
| `sgx_capture.py` | Decodes Razor .sgx snapshots: memory, programs, draws |

## retail-cp/

| File | What it is |
|---|---|
| `main.c`, `retail-cp.h` | retail-cp.skprx, the CP board's part on a retail Vita: what it does, and its start |
| `services.c`, `usb.c`, `console.c` | Loading the ported modules over the Vita's USB port; the kernel console to the host |
| `switches.c`, `power.c`, `crash.c` | The debug switches, power and restarts without the CP, uninstall, crash records |
| `shell.c`, `dtrace.c` | Shell and AppMgr changes (no lock screen, apps run with the screen off), DTrace fixes |
| `words.c`, `report.c` | The host's commands over TTYP7; the boot report in `ur0:data/retail-debug/` |
| `port_modules.py` | Ports the decrypted DevKit modules (see [What you need](#what-you-need)) to `*-retail.skprx` |
| `CMakeLists.txt` | Builds retail-cp.skprx with VitaSDK |

## License

GPL-3.0 (LICENSE).
