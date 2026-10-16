# psp2-tooling on a retail Vita

The DevKit tools also run on a retail Vita, with the DevKit's Target Manager modules ported to
it. They were tested on a real PCH-2000, firmware 3.65 with Ensō and taiHEN; only 3.65 is
supported. The [status table](#status) says which. The README lists the
decrypted DevKit modules you have to provide and what changes on the Vita.

## What it takes

A DevKit has a CP board that relays DECI4p (the Target Manager protocol) and holds the debug
switches the kernel's DevKit modules check. A retail Vita has neither. `retail-cp/` stands in
for both:

- `retail-cp.skprx`, a taiHEN `*KERNEL` plugin (`retail-cp/`; `cmake -S retail-cp -B
  build/retail-cp && cmake --build build/retail-cp`). It:
  - sets the debug switches through the kernel's own `ksceKernelSetDipsw`: 0xC2 (debug
    USB), 0xC7 (DECI console), and 0xD4 only while pamgr starts;
  - loads the ported modules over the Vita's own USB port, which takes the port from MTP;
  - shares that port with other kernel plugins' USB functions, such as udcd_uvc's webcam:
    a driver a plugin registers after retail-cp loads becomes part of the same USB device,
    ahead of the DECI4p interface, and the plugin's own later takeover of the port leaves
    it as it is;
  - stands in for the CP's power control: it reads `reset`, `reboot`, `off`, `suspend` or
    `wake` from TTYP7;
  - keeps the Vita out of idle standby, because standby drops the USB link;
  - patches AppMgr so the app keeps running when the screen turns off (the shell would have
    it suspended, which froze a profiled app mid-session);
  - lets pamgr accept the Razor recorder's PA trace buffer, a user block from the
    physically contiguous partition (a DevKit takes only its DevKit-only PA window);
  - records a kernel exception in Syscon's scratch pad and restarts the Vita (see below);
  - writes a report to `ur0:data/retail-debug/cp.txt`.
- The DevKit's DECI4p modules: dbgusb, dfmgr, syslibtrace, pamgr, ttyp, userp, ctrlp, loadp,
  drfp, dbgp, dtracep and vcp. `retail-cp/port_modules.py --modules <DevKit
  fs_dec/os0/kd> --out <dir>` makes the `*-retail.skprx` files from the decrypted 3.65 DevKit
  modules, which this repository does not provide (the README lists them). It moves
  allocations off the DevKit-only Tool memory partition and patches dfmgr to use USB in place
  of the CP's SDIO link, checking the bytes each patch replaces.

On the Vita, in `ur0:tai/`:

```
retail-cp.skprx  dbgusb-retail.skprx  dfmgr-retail.skprx  syslibtrace-retail.skprx
pamgr-retail.skprx  ttyp-retail.skprx  userp-retail.skprx  ctrlp-retail.skprx
loadp-retail.skprx  drfp-retail.skprx  dbgp-retail.skprx  dtracep-retail.skprx  vcp-retail.skprx
```

and in `ur0:tai/config.txt`:

```
*KERNEL
ur0:tai/retail-cp.skprx
```

On a real Vita retail-cp keeps development mode (switch 0x9F) and hardware debug (0xE4) on in
Ernie's bootparam block, as a DevKit's CP does: a boot without either arms both and restarts
into them, and nothing clears them. The second loader then powers the Performance Analyzer, so
pamgr starts, and the kernel arms each process's hardware breakpoints and watchpoints. An OS
reboot in development mode, and the shell's death when AppMgr ends it in standby, come back in
one boot: retail-cp syncs the filesystems and cold-resets through Syscon, where Ernie would
otherwise leave the Vita off. A suspend turns the screen off with the system running; the power
key turns it on again.

With other USB plugins, such as udcd_uvc, retail-cp goes above them in the same `*KERNEL`
section. The Vita then shows up as one 054C:04CD device with their interfaces first, for
example a UVC camera at interfaces 0 and 1, and DECI4p's vendor interface after them. The
tools open the vendor interface. A plugin listed above retail-cp does not join: DECI4p
keeps the port and the plugin's takeover fails.

retail-cp also boots 3.65's shell straight to the home screen without the lock screen, as a
DevKit does. `devkit/retail_vita.sh uninstall` undoes all of it (README, Uninstall).

Connect only the Vita's USB port. There is no CP mini-USB, and a PCH-2000 has no HDMI, so
anything that grabs HDMI does not apply. MTP and USB charging-only mode are gone while
retail-cp holds the port.

### If a boot hangs

A kernel exception restarts the Vita by itself, and the next boot's
`ur0:data/retail-debug/cp.txt` (read it with `retail_vita.sh get`) has a `crash=` line with the
faulting module and offset. A crashed shell (a faulting `*main` plugin, say) stops, as on a
DevKit in development mode, with the DECI4p link up: `pdump` its process for the core file,
then `retail_vita.sh reset`. For anything else, hold the power button until the Vita turns off,
then turn it on;
`cp-prev.txt` is the report of the boot that hung, and it ends at the step that never finished.

A hang outside those steps needs an L-held boot, which skips every taiHEN plugin. Then remove
`ur0:tai/retail-cp.skprx` or its config line.

## Running the tools

`deci4p_host.py` and `devkit_console.py` drive the Vita's USB device directly:

- They need write access to it (root or a udev rule) and pyusb.
- `deci4p_host.py --control` takes a Unix socket path, which must stay under about 100
  characters.

| Tool | On retail |
|---|---|
| `deci4p_host.py`, `psp2_input.py`, `vpk_promoter/`, `vcp_capture.py`, `vita_prof.py` | As on a DevKit. App and console output arrive over TTYP, in deci4p_host's `tty.log`, and so does the kernel console (`[kernel] ` lines: retail-cp restores SceSysmem's printf and forwards it). |
| `psp2prof` | As on a DevKit (pamgr runs in development mode; CoreSight on cores 0-2). |
| `devkit_console.py` | `--retail` (USB product 04CD): the TTY channels, `--power reset\|reboot\|off`, `--wait off\|on`, `--state`. `reset` is a Syscon cold reset and works with the shell wedged. `reboot` and `off` go through the shell. `deci4p_host.py`'s `power reset\|reboot\|off` does the same, and `power qaf\|scratch\|threads\|memory\|debugmem\|suspend\|wake`, `power copy SRC DST`, `power list DIR`, `power hwbp PID ADDRESS [CONTROL]` and `power hwwp PID ADDRESS [CONTROL]` pass retail-cp's other TTYP7 words (hardware breakpoint slot 2 and watchpoint slot 1 of a process, through ProcessMgr; ADDRESS may be MODULE+OFFSET; a hit with no debugger on the process stops it, and `pdump` writes its core file) (`threads` writes every thread's state to `tty.log`, `memory` KD's and PhyCont's free space). |
| `retail_vita.sh` | `get PATH`, `put FILE PATH`, `list DIR`, `reset`, `word WORD...`: files and resets over the USB link alone, through host0: and retail-cp's `copy` (no FTP or network server on the Vita). `put` writes `PATH.new`, checks its size and renames it over `PATH`. |
| `session.sh` | `RETAIL=1`. Turn the Vita on yourself. `boot` and `force_off` reset it through retail-cp (a Syscon cold reset; it comes back in development mode), and `boot` launches once LOADP is announced: retail-cp loads the Target Manager services after the shell has started. `NORESET=1` skips the reset at `boot`. GRAB needs HDMI. |
| `parse_core.py` | `pdump` writes a crashed process's dump to host0: (development mode writes none by itself, as on a DevKit). Retail executables load at 0x81000000 plus a slide; parse_core finds and places them. |
| `examples/` | Run with `RETAIL=1`. |

## Building apps

- As on a DevKit, build an app you profile with `-g` and `vita-make-fself -na` (README,
  profile/).
- On a real Vita, use `launch` (SceAppMgr): a SELF from host0: (`launch host0:/app.bin`)
  or an installed title by its ID. `spawn` (a bare process) works too: retail-cp sets the QA
  flag host0 bit and keeps taiHEN's `*main` plugins out of spawned processes.
- A crash in development mode writes no core file and shows no dialog, as on a DevKit with
  Neighborhood's *Forced Dump on Devmode* Off (the default): the process stays stopped, and
  launches fail with 0x80802025 until it is gone. `psp2_input.py SOCKET pdump PID [full|mini]`
  writes its core file to host0: through DBGP, as psp2ctrl's `pdump` does (`pdumpstatus` names
  the file once it is written); then `kill PID`.
- Apps linked against VitaSDK's newlib and run over LOADP need `-D__DYNAMIC_REENT__`.
  Without it stdout and stderr are uninitialized FILEs and every printf fails (EBADF).
- DTrace register snapshots copy `--stack-bytes` above SP. A copy that runs past the
  thread's stack top drops the event, on a DevKit too, so keep the sampled code a few KiB
  below its stack top or take fewer bytes.

## Razor

Razor's capture module exists only in DevKit firmware, and retail's AuthMgr rejects the
DevKit's encrypted SELFs (0x800f0516). Make an fSELF of the decrypted `librazorcapture_es4` ELF
with `vita-make-fself -c`, then copy it to `ur0:data/`, where the recorder loads it from.

Live metrics need no Razor module: the recorder drives the Performance Analyzer through pamgr,
which runs in development mode, and switches the SGX counters on as the HUD does.

## Status

On a real PCH-2000, firmware 3.65, development mode (which retail-cp keeps on). The test apps
are small homebrew SELFs: a CPU spin loop with a named caller, a crash in a named function, and
a GXM app with the Razor recorder.

| What | Result |
|---|---|
| DECI4p link over USB | works: DfMgr registers TTYP0-7 and the services |
| host0: (DRFP) | works |
| VCP screenshots | works |
| TTY output, input (CTRLP), launch by title ID, VPK install | work (CTRLP also drives system dialogs) |
| Launch a SELF from host0: through SceAppMgr (LOADP `launch`) | works |
| Spawn a SELF from host0: (LOADP `spawn`) | works: a spawned app runs and exits 0 |
| `vita_prof.py` sampling and `--registers` snapshots | work: six sessions in a row in one boot (about 3090 samples each, 0 drops), with retail-cp's DTrace fixes (dtracep's DTRACEP_PMEP thread hung the Vita after the first close) |
| `psp2prof` | works: 10812 samples of the whole system at 1000 Hz, 0 dropped |
| Core dumps + `parse_core.py` | work: a crashed app stays stopped, as on a DevKit in development mode; `pdump` writes its dump to host0: (75 KB, with DBGP's progress notices), `--backtrace` names the faulting function and its caller, and after `kill` the next launch runs. A crashed shell stops the same way; `pdump` wrote its 1.1 MB core file and `reset` brought the Vita back |
| Power reset/reboot/off | `reset` restarts the Vita in about 18 s and keeps development mode (retail-cp retries a load the secure loader refuses with 0x800F0029). An OS reboot (`reboot`, the shell's restart) comes back in one boot (about 10 s to USB): Ernie would leave a development-mode Vita off after ScePower's cold reset (on a DevKit the CP powers it back), so retail-cp syncs the filesystems and sends the Syscon reset instead. Development mode is always on: a boot without it re-arms 0x9F and reboots, and nothing clears it |
| `examples/install-and-run.sh` | passes (no HDMI, so no GRAB): VPK install, RZRA00001 runs; VCP gives 960x544 |
| `examples/cpu-profile.sh` | passes: PSP2PROF0 installed, the test app profiled, perf.data written |
| `examples/core-dump.sh` | passes |
| `examples/call-stacks.sh` | passes: 1998 snapshots, 1996 unwound from the spin loop to its caller, 0 capture errors or drops |
| Razor frame capture (`.sgx`) | works with the fSELF in `ur0:data/`: a 4.2 MB frame.sgx, 960x544, 4 programs, 9 draws |
| Razor live (`examples/razor.sh`, `.rzlv`) | works (development mode has SKBL power the PA): 944 GPU jobs (472 TA, 472 3D) over 119 frames, with the SGX counters on |
| udcd_uvc alongside | one USB device; UAC records (4 s, non-silent); UVC negotiates 960x544 NV12 and starts, but no frame arrives |
| Hardware breakpoints and watchpoints | `power hwbp`/`hwwp PID ADDRESS` (MODULE+OFFSET too) set breakpoint slot 2 and watchpoint slot 1 of a process through ProcessMgr, which the kernel loads into CP14 whenever one of its threads runs. A hit stopped the test app at the breakpoint (prefetch abort) and at the watched load (data abort, DFSR 0x2); with no debugger on the process it stops there, for `pdump` |

A kernel hang that also stops retail-cp's thread can't be reset over USB. It needs a long
press of the power button.
