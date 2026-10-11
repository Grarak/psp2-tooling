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

## devkit/

| Tool | What it does |
|---|---|
| `devkit_console.py` | CP console and the Vita's TTY channels over the mini-USB port; power on, off, cycle, reset and state |
| `deci4p_host.py` | Target Manager stand-in on the Vita's USB port: serves host0:, launches and kills apps (LOADP), buttons, sticks and touch (CTRLP), a control socket for the rest |
| `psp2_input.py` | Client for `deci4p_host.py`'s control socket: input, launch, kill |
| `session.sh` | One boot: power up, optional VPK install, launch apps with timed HDMI grabs, audio, input and commands, power off |
| `vcp_capture.py` | Screenshot of what VitaOS displays (VCP), standalone or through a running `deci4p_host.py` |
| `vpk_promoter/` | Installs a VPK through the Vita's own promoter, over host0: (`stage.py` prepares it) |
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

## License

GPL-3.0 (LICENSE).
