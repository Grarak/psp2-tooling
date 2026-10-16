#!/bin/bash
# A retail Vita with retail-cp (retail-cp/) over its USB link alone: files, resets and words,
# with no FTP or network server on the Vita.
#
#   retail_vita.sh get PATH        copy a file off the Vita (ur0:..., ux0:...) into $HOST0
#   retail_vita.sh put FILE PATH   copy a local file onto the Vita (written to PATH.new,
#                                  size-checked, then renamed over PATH)
#   retail_vita.sh list DIR        a directory's entries (size, time, name)
#   retail_vita.sh reset           Syscon cold reset; waits until the Vita is back on USB and
#                                  its next boot's retail-cp report is complete
#   retail_vita.sh word WORD...    any other retail-cp power word (memory, threads, reboot...)
#   retail_vita.sh uninstall       the Vita back to retail: retail-cp leaves taiHEN's config.txt,
#                                  development mode and hardware debug are cleared in Syscon,
#                                  the installed files are deleted and the Vita restarts
#
# Files go through host0:, which deci4p_host.py serves (DRFP), and retail-cp's "copy" word.
# A deci4p_host.py is started when none of ours serves the link (WORK, default
# /tmp/retail-vita; HOST0, default $WORK/host0); it needs root or a udev rule for the device.
set -u
TOOLS=$(cd "$(dirname "$0")" && pwd)
WORK=${WORK:-/tmp/retail-vita}
HOST0=${HOST0:-$WORK/host0}
PY=${PYTHON:-python3}
SOCK=$WORK/deci4p.sock
REPORT=ur0:data/retail-debug/cp.txt

alive() { [ -S "$SOCK" ] && pgrep -f "deci4p_host.py --usb --host0 $HOST0 " > /dev/null; }
host() {
    alive && return 0
    # Twice: a host that finds the link stuck resets the Vita's USB port and exits.
    for attempt in 1 2; do
        pkill -f "deci4p_host.py --usb --host0 $HOST0 " 2> /dev/null
        rm -f "$SOCK" "$WORK/deci4p.log" "$WORK/tty.log"
        mkdir -p "$HOST0"
        timeout 120 bash -c 'until lsusb -d 054c:04cd > /dev/null; do sleep 0.5; done' ||
            { echo "the Vita is not on USB (054c:04cd)" >&2; return 1; }
        "$PY" -u "$TOOLS/deci4p_host.py" --usb --host0 "$HOST0" --control "$SOCK" --log-dir "$WORK" \
            > "$WORK/deci4p.out" 2>&1 &
        local pid=$!
        # TTYP7 carries retail-cp's words; ttyp loads once the shell is up, ~30 s after a reset.
        timeout 120 bash -c "until [ -S '$SOCK' ] && grep -q 'protocol 0x80030007' '$WORK/deci4p.log' 2> /dev/null; do
            kill -0 $pid 2> /dev/null || exit 1; sleep 0.3; done" && return 0
        tail -1 "$WORK/deci4p.out" >&2
        sleep 3
    done
    echo "no DECI4p link" >&2
    return 1
}
input() { "$PY" "$TOOLS/psp2_input.py" "$SOCK" "$@" > /dev/null; }
result() { # result PREFIX COUNT: wait for retail-cp's next console line starting with PREFIX
    timeout 60 bash -c "until [ \$(grep -acF '[retail-cp] $1' '$WORK/tty.log') -gt $2 ]; do sleep 0.3; done" ||
        { echo "no answer from retail-cp" >&2; return 1; }
    grep -aF "[retail-cp] $1" "$WORK/tty.log" | tail -1 | sed 's/.*\[retail-cp\] //'
}
copy() { # copy SRC DST
    host || return 1
    # DRFP (host0:) opens after the shell has started.
    timeout 90 bash -c "until grep -q 'protocol 0x11100' '$WORK/deci4p.log'; do sleep 0.5; done" ||
        { echo "no DRFP (host0:)" >&2; return 1; }
    local n
    n=$(grep -acF "[retail-cp] copy $1 " "$WORK/tty.log")
    input power copy "$1" "$2"
    local line
    line=$(result "copy $1 " "$n") || return 1
    echo "$line" >&2
    case $line in *": 0x00000000 "*) ;; *) return 1 ;; esac
}

case ${1:-} in
get)
    [ $# = 2 ] || exec sed -n 2,14p "$0"
    copy "$2" "host0:/$(basename "$2")" && echo "$HOST0/$(basename "$2")" ;;
put)
    [ $# = 3 ] || exec sed -n 2,14p "$0"
    host && cp "$2" "$HOST0/$(basename "$2")" && copy "host0:/$(basename "$2")" "$3" ;;
list)
    [ $# = 2 ] || exec sed -n 2,14p "$0"
    host || exit 1
    n=$(grep -acF "[retail-cp] list $2: " "$WORK/tty.log")
    input power list "$2"
    timeout 30 bash -c "until grep -aF '[retail-cp] list $2: ' '$WORK/tty.log' | tail -n +$((n + 1)) | grep -q ' entries\$'; do sleep 0.3; done"
    grep -aF "[retail-cp] list $2: " "$WORK/tty.log" | tail -n +$((n + 1)) | sed "s|.*\[retail-cp\] list $2: ||" ;;
word)
    shift
    [ $# -ge 1 ] || exec sed -n 2,14p "$0"
    host && input power "$@" ;;
reset)
    host || exit 1
    input power reset
    timeout 30 bash -c 'while lsusb -d 054c:04cd > /dev/null; do sleep 0.2; done' ||
        { echo "the Vita did not reset" >&2; exit 1; }
    start=$(date +%s)
    sleep 1
    host || exit 1
    for _ in $(seq 60); do
        f=$("$0" get "$REPORT" 2> /dev/null) && grep -q '^complete' "$f" && break
        sleep 3
    done
    echo "back after $(( $(date +%s) - start )) s" ;;
uninstall)
    host || exit 1
    for config in ux0:tai/config.txt ur0:tai/config.txt; do
        f=$("$0" get "$config" 2> /dev/null) || continue
        grep -q 'retail-cp\.skprx' "$f" || continue
        sed '/retail-cp\.skprx/d' "$f" > "$WORK/config.txt"
        "$0" put "$WORK/config.txt" "$config" || { echo "could not write $config" >&2; exit 1; }
    done
    input power uninstall
    if ! timeout 30 bash -c 'while lsusb -d 054c:04cd > /dev/null; do sleep 0.2; done'; then
        grep -aF '[retail-cp] uninstall' "$WORK/tty.log" | tail -1 >&2
        echo "the Vita did not restart" >&2
        exit 1
    fi
    pkill -f "deci4p_host.py --usb --host0 $HOST0 " 2> /dev/null
    echo "restarting as a retail Vita: retail-cp is uninstalled" ;;
*) exec sed -n 2,14p "$0" ;;
esac
