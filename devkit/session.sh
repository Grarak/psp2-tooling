#!/bin/bash
# session.sh SECONDS LAUNCH...: one DevKit boot that runs each LAUNCH for up to SECONDS, then
# powers the DevKit off. A LAUNCH is what psp2_input.py's launch takes: a path and its arguments
# ("host0:/package/eboot.bin -titleid ABCD00001"), or an installed title's ID. A launch ends
# early when its process exits or a console line matches STOP; one that runs out of time is
# killed over LOADP (KILL=TITLEID names what to kill when the launch line has no title ID).
#
# The Vita's USB link is served by deci4p_host.py (host0: is HOST0, input through its control
# socket); the CP's mini-USB console is logged with host timestamps. Each launch gets
# OUT/launch-N/ with its slice of console.log (timestamped), deci4p.log and actions.log.
#
#   HOST0=DIR        the directory served as host0: (required)
#   OUT=DIR          where the logs go (default devkit-run-DATE-TIME)
#   INSTALL=1        first run host0:/promoter.bin (devkit/vpk_promoter/stage.py staged HOST0)
#   STOP=REGEX       console lines that end a launch and force the DevKit off (an assert ...)
#   GRAB="T..."      an HDMI frame T seconds after each launch: grab-T.png (CAPDEV: the V4L2
#                    device, default the MacroSilicon USB capture card)
#   AUDIO="T SECS"   SECS seconds of HDMI audio from T seconds: audio-T.wav (AUDDEV: the ALSA
#                    device, default the MacroSilicon card's)
#   PRESS="T=CMD;.." psp2_input.py commands T seconds after each launch ("35=press circle")
#   RUN="T=CMD;.."   shell commands T seconds after each launch, in the background, with $SOCK
#                    (the control socket), $DECI_LOG, $LAUNCH_DIR and $TOOLS set (profilers)
#
#   RETAIL=1         a retail Vita with Enso, taiHEN and the retail Target Manager port
#                    (retail-cp/): no CP board, so power goes through the
#                    retail-cp plugin's Syscon reset ("power reset" on the control socket). A
#                    Vita already up is reset for a fresh boot (NORESET=1 keeps it as it is),
#                    a forced stop resets it, and the session leaves it running. Boot it and
#                    plug in its USB port first. The console is the TTY text deci4p_host.py
#                    receives over TTYP (tty.log)
#
# Ctrl-C (or killing the PID in OUT/session.pid) ends the launch and powers the DevKit off.
set -u
TOOLS=$(cd "$(dirname "$0")/.." && pwd)
SECS=$1; shift
: "${HOST0:?HOST0=DIR is required}"
OUT=${OUT:-devkit-run-$(date +%Y%m%d-%H%M%S)}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
# AF_UNIX paths are limited to 108 bytes.
SOCK=${XDG_RUNTIME_DIR:-/tmp}/psp2-session-$$.sock
DECI_LOG=$OUT/deci4p.log
# What console.log is made from: the CP's mini-USB console, or on retail the TTYP channels.
CONSOLE_SRC=$OUT/cp-console.log
[ -n "${RETAIL:-}" ] && CONSOLE_SRC=$OUT/tty.log
CON= STAMP= DECI=
jobs_=()
echo $$ > "$OUT/session.pid"
step() { echo "== $(date +%T) $*"; }
console() { timeout --foreground "$1" python3 -u "$TOOLS/devkit/devkit_console.py" "${@:2}" 2>&1 | grep -v '^\[CP\]' | tail -1; }
count() { local c; c=$(grep -ac "$1" "$DECI_LOG" 2>/dev/null); echo "${c:-0}"; }
input() { echo "$1" | timeout 5 python3 "$TOOLS/devkit/psp2_input.py" "$SOCK" 2>&1; }

down() {
    kill $DECI $CON $STAMP 2>/dev/null
    wait $DECI $CON 2>/dev/null
    DECI= CON= STAMP=
}
usb_wait() { # usb_wait present|gone TENTHS
    for i in $(seq 1 "$2"); do
        if lsusb -d 054c:04cd > /dev/null; then [ "$1" = present ] && return 0
        else [ "$1" = gone ] && return 0; fi
        sleep 0.1
    done
    return 1
}
retail_reset() {
    # retail-cp takes power words as TTYP7 input and asks Syscon for a cold reset: the Vita
    # drops off USB and comes back. Nothing else may hold its port meanwhile.
    step "retail: Syscon cold reset"
    # All of its output: the console reads DfMgr's replay to the end after "power: on".
    timeout --foreground 240 python3 -u "$TOOLS/devkit/devkit_console.py" --retail --log "$OUT/reset.log" \
        --power reset --wait off --wait on --timeout 200 > "$OUT/reset.out" 2>&1
    grep -q 'power: on after' "$OUT/reset.out" || { step "retail: no reset (is retail-cp loaded?)"; return 1; }
}
off() {
    if [ -n "${RETAIL:-}" ]; then
        step "retail: the Vita stays on"
        return
    fi
    # The Vita's shutdown waits until every DECI4p unit has disconnected: a fresh link that
    # ends with the power-off lets it through.
    local link=
    if lsusb -d 054c:04cd > /dev/null; then
        python3 "$TOOLS/devkit/deci4p_host.py" --usb --host0 "$HOST0" --log-dir "$OUT" \
            --log-name deci4p-off.log > "$OUT/deci4p-off.out" 2>&1 &
        link=$!
        sleep 2
    fi
    console 20 --log "$OUT/cp-off.log" --power off --wait off --timeout 15
    [ -n "$link" ] && { kill $link 2>/dev/null; wait $link 2>/dev/null; }
    console 15 --state --timeout 5 | grep -q 'state off' ||
        console 30 --power force-off --wait off --timeout 10
}
force_off() {
    # A process stopped in an assert can hold the shutdown: kill it first.
    [ -n "${current:-}" ] && input "kill $current" > /dev/null
    sleep 1
    if [ -n "${RETAIL:-}" ]; then
        # The software power cycle: whatever hangs, short of the kernel or the USB link.
        input "power reset" > /dev/null
        usb_wait gone 300 || step "retail: the Vita did not reset"
        down
        return
    fi
    down
    console 30 --power force-off --wait off --timeout 10
    console 15 --state --timeout 5 | grep -q 'state off' || off
}
abort() {
    step "interrupted: powering off"
    [ ${#jobs_[@]} -gt 0 ] && kill "${jobs_[@]}" 2>/dev/null
    force_off
    rm -f "$SOCK"
    exit 130
}
trap abort INT TERM

boot() {
    rm -f "$SOCK"
    if [ -n "${RETAIL:-}" ]; then
        step "retail: waiting for the Vita's USB (054c:04cd)"
        usb_wait present 1200 || { step "the Vita's USB (054c:04cd) did not appear"; return 1; }
        [ -n "${NORESET:-}" ] || retail_reset || return 1
    else
        step power up
        # A cycle is refused (0x2007) when the Vita is off already: then power it on.
        console 20 --power cycle --timeout 5 | grep -q accepted || { sleep 3; console 20 --power on --timeout 5; }
        for i in $(seq 1 50); do lsusb -d 054c:04cd > /dev/null || break; sleep 0.2; done
        for i in $(seq 1 300); do lsusb -d 054c:04cd > /dev/null && break; sleep 0.2; done
        lsusb -d 054c:04cd > /dev/null || { step "the Vita's USB (054c:04cd) did not appear"; off; return 1; }
        python3 "$TOOLS/devkit/devkit_console.py" --log "$OUT/cp-console.log" --follow --timeout 86400 > /dev/null 2>&1 &
        CON=$!
    fi
    tail --pid=$$ -n +1 -F "$CONSOLE_SRC" 2>/dev/null |
        while IFS= read -r line; do printf '%s %s\n' "$(date +%T.%3N)" "$line"; done > "$OUT/console.log" &
    STAMP=$!
    local launch=()
    [ -n "${INSTALL:-}" ] && launch=(--launch host0:/promoter.bin --launch-after 25)
    python3 "$TOOLS/devkit/deci4p_host.py" --usb --host0 "$HOST0" --control "$SOCK" --log-dir "$OUT" \
        --log-name deci4p.log "${launch[@]}" > "$OUT/deci4p.out" 2>&1 &
    DECI=$!
    for i in $(seq 1 300); do [ -S "$SOCK" ] && break; sleep 0.1; done
    if [ -n "${RETAIL:-}" ]; then
        # retail-cp loads the Target Manager services once the shell is up (about 15 s after a
        # reset): launch after LOADP (0x24000) is announced.
        step "retail: waiting for LOADP"
        for i in $(seq 1 1200); do grep -aq 'protocol 0x24000' "$OUT/deci4p.log" 2>/dev/null && break; sleep 0.1; done
    fi
    if [ -n "${INSTALL:-}" ]; then
        step install
        for i in $(seq 1 1500); do
            grep -aq 'vpk-promoter\] finished' "$CONSOLE_SRC" && break
            kill -0 $DECI 2>/dev/null || break
            sleep 0.2
        done
        grep -a 'vpk-promoter\] \(promote\|result\)' "$CONSOLE_SRC"
        grep -aq 'vpk-promoter\] promote: 0x00000000' "$CONSOLE_SRC" || { step "install failed"; down; off; return 1; }
        sleep 3 # the promoter exits after its last line
    fi
}

size() { stat -c %s "$OUT/$1" 2>/dev/null || echo 0; }
slice() { tail -c +$(( $2 + 1 )) "$OUT/$1" > "$3/$1" 2>/dev/null; }
# Whether the launched process's last LOADP event since the launch is its exit.
exited() { tail -c +$(( d0 + 1 )) "$DECI_LOG" | grep -a 'LOADP process' | tail -1 | grep -q exited; }
due() { [ $(( $(date +%s) - start )) -ge "$1" ]; }

boot || exit 1
n=0
for launch in "$@"; do
    n=$(( n + 1 ))
    LAUNCH_DIR=$OUT/launch-$n
    mkdir -p "$LAUNCH_DIR"
    export SOCK DECI_LOG LAUNCH_DIR TOOLS
    c0=$(size console.log) d0=$(size deci4p.log)
    # What to kill at the end: KILL, the launch line's -titleid, or a bare title ID.
    current=${KILL:-}
    [ -z "$current" ] && current=$(sed -n 's/.*-titleid \([A-Z0-9]\{9\}\).*/\1/p' <<< "$launch")
    [ -z "$current" ] && [[ "$launch" =~ ^[A-Z0-9]{9}$ ]] && current=$launch
    step "launch $n: $launch"
    replies=$(count 'LOADP reply')
    input "launch $launch" > /dev/null
    for i in $(seq 1 50); do [ "$(count 'LOADP reply')" -gt "$replies" ] && break; sleep 0.1; done
    reply=$(grep -a 'LOADP reply' "$DECI_LOG" | tail -1)
    echo "$reply"
    stopped=
    case "$reply" in *"result 0x0 "*) ;; *) step "launch refused"; stopped=1 ;; esac
    start=$(date +%s)
    declare -A done_at=()
    jobs_=()
    while [ -z "$stopped" ] && ! due "$SECS"; do
        for t in ${GRAB:-}; do
            if due "$t" && [ -z "${done_at[grab$t]:-}" ]; then
                # The capture's first frames after an open are old buffers: the 11th is kept.
                ffmpeg -nostdin -v error -f v4l2 -input_format mjpeg -framerate 60 -video_size 1280x720 \
                    -i "${CAPDEV:-/dev/v4l/by-id/usb-MACROSILICON_USB_Video-video-index0}" \
                    -vf 'select=gte(n\,10)' -frames:v 1 -y "$LAUNCH_DIR/grab-$t.png" 2>> "$LAUNCH_DIR/actions.log"
                echo "grab $t s: $(date +%T.%3N)" >> "$LAUNCH_DIR/actions.log"
                done_at[grab$t]=1
            fi
        done
        if [ -n "${AUDIO:-}" ] && due "${AUDIO%% *}" && [ -z "${done_at[audio]:-}" ]; then
            arecord -q -D "${AUDDEV:-hw:CARD=MS2109,DEV=0}" -f S16_LE -r 48000 -c 2 -d "${AUDIO##* }" \
                "$LAUNCH_DIR/audio-${AUDIO%% *}.wav" 2>> "$LAUNCH_DIR/actions.log" &
            jobs_+=($!)
            echo "audio ${AUDIO%% *} s for ${AUDIO##* } s: $(date +%T.%3N)" >> "$LAUNCH_DIR/actions.log"
            done_at[audio]=1
        fi
        for kind in PRESS RUN; do
            IFS=';' read -ra items <<< "${!kind:-}"
            for k in "${!items[@]}"; do
                t=${items[$k]%%=*} cmd=${items[$k]#*=}
                [ -n "$cmd" ] && due "$t" && [ -z "${done_at[$kind$k]:-}" ] || continue
                if [ $kind = PRESS ]; then
                    input "$cmd" >> "$LAUNCH_DIR/actions.log"
                else
                    (cd "$LAUNCH_DIR" && bash -c "$cmd") >> "$LAUNCH_DIR/actions.log" 2>&1 &
                    jobs_+=($!)
                fi
                echo "${kind,,} $t s: $cmd $(date +%T.%3N)" >> "$LAUNCH_DIR/actions.log"
                done_at[$kind$k]=1
            done
        done
        if [ -n "${STOP:-}" ] && tail -c +$(( c0 + 1 )) "$OUT/console.log" | grep -aEq "$STOP"; then
            sleep 2 # the message's last lines
            step "stopped: $(tail -c +$(( c0 + 1 )) "$OUT/console.log" | grep -aE "$STOP" | head -1 | cut -c1-200)"
            stopped=1
        elif exited; then
            step "the process exited after $(( $(date +%s) - start )) s"
            break
        fi
        sleep 1
    done
    if [ -z "$stopped" ] && ! exited; then
        step "end after $SECS s"
        if [ -n "$current" ]; then
            kills=$(count 'LOADP process killed')
            input "kill $current" > /dev/null
            for i in $(seq 1 100); do [ "$(count 'LOADP process killed')" -gt "$kills" ] && break; sleep 0.1; done
            [ "$(count 'LOADP process killed')" -gt "$kills" ] || { step "kill not confirmed"; stopped=1; }
            sleep 2
        fi
    fi
    [ ${#jobs_[@]} -gt 0 ] && wait "${jobs_[@]}" # RUN commands and the audio recording
    slice console.log $c0 "$LAUNCH_DIR"; slice deci4p.log $d0 "$LAUNCH_DIR"
    if [ -n "$stopped" ]; then
        step force off
        force_off
        rm -f "$SOCK"
        exit 1
    fi
    current=
done
down
step power off
off
rm -f "$SOCK"
