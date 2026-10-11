#!/usr/bin/env python3
"""Console text from a real DevKit's mini-USB debug port, with no Target Manager.

The mini-USB port belongs to the CP board: its gadget (sce_usb.ko) enumerates as
054C:0432 "PSP2 Devkit", one vendor interface with bulk endpoints 0x81 and 0x01,
and carries nothing but DECI4p.  Two kinds of text arrive on
it:

- The CP console, protocol 0x80030081, sent from boot without any handshake.
  dfcpm relays its ttyS1 there line by line, and on a DevKit that line is the
  Vita's UART1.
- The Vita OS's own TTY channels, 0x80030000 + n.
  The Vita sends them only after the PC has sent the DCMP connect (0/0) and an
  open (0/4) for each channel; this tool does both for
  every TTY channel the Vita announces with a 2/1.

    devkit/devkit_console.py                   # print everything, Ctrl-C to stop
    devkit/devkit_console.py --log log.txt     # also write the text to a file (wiped at start)
    devkit/devkit_console.py --raw raw.bin     # keep the raw DECI4p stream too

It can also ask the CP to switch the Vita's power: dfcpm's 0x2000 service,
request 4/2 with a power code, answered by 4/3 with a status, and 4/0 for the
power state, answered by 4/1.  Power steps
run in the order given, each one after the previous has been answered; the tool
then exits, or keeps printing the console with --follow:

    devkit/devkit_console.py --state                           # on, off or standby
    devkit/devkit_console.py --power reset --wait off --power on --wait on --follow
    devkit/devkit_console.py --power cycle --follow            # off, then on again

Codes (a number is sent as it is): off asks the Vita to shut down and falls
back to Syscon power-off; syscon-off powers off through Syscon at once; on
powers on (or resumes); on-key powers on with the power-key pulse; cycle and
reboot power off and on again; reset pulses Ernie's reset line and leaves the
Vita off; force-off is Syscon power-off without the Vita's shutdown.  dfcpm's
power lock (set by the Vita) and a wrong power state refuse a request; the
status says which.  The CP's own power events print as [POWER] lines.  A suspend
needs the PC's answer: the tool sends it as Target Manager does.

Target Manager must not hold the device.  Linux needs read/write access to it,
for example a udev rule:
    SUBSYSTEM=="usb", ATTR{idVendor}=="054c", ATTR{idProduct}=="0432", MODE="0666"
Requires pyusb (python3-usb).
"""

import argparse
import struct
import sys
import time
import zlib

HEADER = struct.Struct('<IHHII')
HEADER_MAGIC = 0x40
PACKET_MAX = 0x11000

NODE_PC = 0x4000
NODE_CP = 0x6000
NODE_VITA_SDIO = 0xA000

PROTOCOL_DCMP = 0x00000100
# dfcpm's settings and power service; the Vita's side is TSMP.
PROTOCOL_TSMP = 0x00002000
PROTOCOL_CP_CONSOLE = 0x80030081
TTY_FAMILY = 0x80030000
# The kernel's per-core consoles STTYP0-3 (0x90030080 + core): module start-up,
# heap warnings and the exception reports of a crashed process (its waypoints
# and the "Print Backtrace(User stack)" PC/SP list).
KERNEL_TTY = 0x90030080
# The TTY layout after the 16-byte DECI4p header: 0x18 bytes of fields, the u32
# length at +0x18 (packet +0x28) and the text at +0x1C (packet +0x2C).
TTY_LEN = 0x18
TTY_DATA = 0x1C

USB_VENDOR = 0x054C
USB_PRODUCT = 0x0432

# 4/2 power request codes
POWER_CODES = {
    'off': 0x00000000,          # ask the Vita to shut down; Syscon power-off if nobody answers
    'on': 0x00000100,           # Syscon 0x205 {02}; from standby, a resume
    'reboot': 0x00008000,       # as off, then an automatic power-on
    'syscon-off': 0x00008001,   # Syscon 0x205 {00}
    'cycle': 0x00008002,        # Syscon power-off, the off edge, then power-on
    'on-key': 0x40000100,       # power on with the F0023 power-key pulse
    'reset': 0x80000000,        # the reset pulse on F0021; the Vita ends off
    'force-off': 0xA0000000,    # Syscon power-off without asking the Vita
}
# 4/3 statuses
POWER_STATUS = {
    0: 'accepted',
    4: 'no target registered 0x10000100 to ask',
    8: 'unknown code',
    0x2007: 'refused: wrong power state for this code',
    0x2011: 'refused: the Syscon link is gated',
    0x2014: 'refused: the Vita holds the power lock',
}
# 4/1 values
POWER_STATE = {0x100: 'on', 0: 'off', 0x200: 'standby', 1: 'unknown (Syscon link gated)',
               0x2009: 'unknown state'}
WAIT_STATES = {'on': 0x100, 'off': 0, 'standby': 0x200}

# Framebuffer formats (DRM fourccs) -> (bytes per pixel, byte offsets of R, G, B)
FB_FORMATS = {
    'XR24': (4, 2, 1, 0), 'AR24': (4, 2, 1, 0),     # B, G, R, X in memory
    'XB24': (4, 0, 1, 2), 'AB24': (4, 0, 1, 2),     # R, G, B, X
    'RX24': (4, 3, 2, 1), 'RA24': (4, 3, 2, 1),     # X, B, G, R
    'BX24': (4, 1, 2, 3), 'BA24': (4, 1, 2, 3),     # X, R, G, B
    'RG16': (2, None, None, None),                  # RGB565
}
# DCMP 2/4 values dfcpm sends the PC on its own
POWER_EVENTS = {
    0: 'on (from off)',
    1: 'on (from standby)',
    0x80: 'power-off requested',
    0x180: 'off',
    0x181: 'standby',
    0x300: 'power-on timed out',
    0x301: 'resume timed out',
}


def packets(buffer):
    """Yields (src, dst, protocol, payload) for each whole packet, consuming them."""
    while len(buffer) >= HEADER.size:
        word, src, dst, protocol, _ = HEADER.unpack_from(buffer)
        size = word & 0xFFFFFF
        if word >> 24 != HEADER_MAGIC or size < HEADER.size or size > PACKET_MAX:
            # Lost framing (a partial packet from before this tool started): skip
            # to the next plausible header.
            del buffer[:1]
            continue
        if len(buffer) < size:
            return
        payload = bytes(buffer[HEADER.size:size])
        del buffer[:size]
        yield src, dst, protocol, payload


def tty_text(payload):
    """The text of a TTY-layout payload, or None when it is malformed."""
    if len(payload) < TTY_DATA:
        return None
    length = struct.unpack_from('<I', payload, TTY_LEN)[0]
    if length > len(payload) - TTY_DATA:
        return None
    return payload[TTY_DATA:TTY_DATA + length]


def dcmp(dst, kind, code, body=b''):
    payload = struct.pack('<BBH', kind, code, 0) + body
    return HEADER.pack(HEADER_MAGIC << 24 | (HEADER.size + len(payload)), NODE_PC, dst,
                       PROTOCOL_DCMP, 0) + payload


def tsmp(kind, code, tag, data=b''):
    """A request to dfcpm's 0x2000 service: {u8 type, u8 code, u16 0, A, B, data}."""
    payload = struct.pack('<BBHII', kind, code, 0, tag, 0) + data
    return HEADER.pack(HEADER_MAGIC << 24 | (HEADER.size + len(payload)), NODE_PC, NODE_CP,
                       PROTOCOL_TSMP, 0) + payload


def write_png(path, width, height, stride, fourcc, data):
    """Writes an RGB PNG of a framebuffer in one of FB_FORMATS."""
    size, r, g, b = FB_FORMATS[fourcc]
    row = width * size
    pixels = b''.join(data[y * stride:y * stride + row] for y in range(height))
    rgb = bytearray(width * height * 3)
    if size == 4:
        rgb[0::3] = pixels[r::4]
        rgb[1::3] = pixels[g::4]
        rgb[2::3] = pixels[b::4]
    else:
        for i, (value,) in enumerate(struct.iter_unpack('<H', pixels)):
            rgb[i * 3] = (value >> 11) * 255 // 31
            rgb[i * 3 + 1] = (value >> 5 & 0x3F) * 255 // 63
            rgb[i * 3 + 2] = (value & 0x1F) * 255 // 31
    line = width * 3
    raw = b''.join(b'\0' + bytes(rgb[y * line:(y + 1) * line]) for y in range(height))

    def chunk(kind, body):
        return (struct.pack('>I', len(body)) + kind + body +
                struct.pack('>I', zlib.crc32(kind + body)))

    with open(path, 'wb') as out:
        out.write(b'\x89PNG\r\n\x1a\n')
        out.write(chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0)))
        out.write(chunk(b'IDAT', zlib.compress(raw, 6)))
        out.write(chunk(b'IEND', b''))


def power_code(text):
    try:
        return POWER_CODES[text]
    except KeyError:
        pass
    try:
        return int(text, 0)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f'{text!r} is neither a number nor one of {", ".join(POWER_CODES)}') from None


def power_name(code):
    names = [name for name, value in POWER_CODES.items() if value == code]
    return f'0x{code:x} ({names[0]})' if names else f'0x{code:x}'


def note(text):
    print(text, file=sys.stderr, flush=True)


class Steps:
    """Runs the --power, --state and --wait steps in order.

    A 4/2 is sent once only: first a 4/0, repeated each second, has to be
    answered, so dfcpm is known to be listening.  The answer to a request
    carries its A field back, which tells stale answers apart.
    """

    POLL = 0.25
    RETRY = 1.0

    def __init__(self, steps, timeout):
        self.steps = [('probe', None)] + list(steps)
        self.timeout = timeout
        self.write = None
        self.tag = 0x50570000       # 'PW'
        self.pending = None         # (tag, answer code, sent at)
        self.started = None         # when the current step began
        self.next_query = 0.0
        self.failed = False

    @property
    def finished(self):
        return self.failed or not self.steps

    def attach(self, write):
        # A step under way keeps its deadline: a wedged dfcpm times out every
        # write, and the link then drops and comes back without end.  Queries
        # go out again at once; a 4/2 in flight fails the run instead (lost()).
        self.write = write
        self.next_query = 0.0

    def lost(self):
        """The link dropped; True when that has to end the run."""
        if self.pending and self.pending[1] == 3:
            self.fail('the link dropped before dfcpm answered the power request')
        self.pending = None
        self.write = None
        return self.failed

    def fail(self, text):
        note(f'power: {text}')
        self.failed = True

    def send(self, code, data, now):
        self.tag += 1
        self.pending = (self.tag, code + 1, now)
        self.write(tsmp(4, code, self.tag, data))

    def tick(self, now):
        """Advance the current step; also called while detached, for its deadline."""
        if self.finished:
            return
        step, arg = self.steps[0]
        if self.started is not None and now - self.started > self.timeout:
            what = {'probe': 'dfcpm to answer',
                    'power': lambda: f'the answer to {power_name(arg)}',
                    'state': 'the power state',
                    'wait': lambda: f'the Vita to be {arg}'}[step]
            what = what() if callable(what) else what
            self.fail(f'gave up after {self.timeout:g} s waiting for {what}')
            return
        if self.write is None:
            return
        if self.started is None:
            self.started = now
            self.next_query = now
            if step == 'power':
                self.send(2, struct.pack('<I', arg), now)
                return
        if step in ('probe', 'state', 'wait') and now >= self.next_query:
            if self.pending is None or now - self.pending[2] >= self.RETRY:
                self.send(0, b'', now)
                self.next_query = now + (self.POLL if step == 'wait' else self.RETRY)

    # -- dfcpm's power service ----------------------------------------------

    def answer(self, payload, now):
        if len(payload) < 0x10 or self.finished:
            return
        kind, code, _, tag, _ = struct.unpack_from('<BBHII', payload)
        if kind != 4 or self.pending is None or (tag, code) != self.pending[:2]:
            return
        value = struct.unpack_from('<I', payload, 0x0C)[0]
        if code == 1 and len(payload) >= 0x14:
            # 4/1 is {A, B, 0, value}
            value = struct.unpack_from('<I', payload, 0x10)[0]
        self.pending = None
        step, arg = self.steps[0]
        elapsed = now - self.started
        if step == 'power':
            text = POWER_STATUS.get(value, 'unknown status')
            note(f'power: {power_name(arg)}: 0x{value:x} {text} after {elapsed:.1f} s')
            if value != 0:
                self.failed = True
                return
        elif step == 'wait':
            if value != WAIT_STATES[arg]:
                return
            note(f'power: {arg} after {elapsed:.1f} s')
        elif step == 'state':
            note(f'power: state {POWER_STATE.get(value, "0x%x" % value)}')
        elif step == 'probe':
            note(f'power: dfcpm answers after {elapsed:.1f} s; state '
                 f'{POWER_STATE.get(value, "0x%x" % value)}')
        self.steps.pop(0)
        self.started = None
        self.tick(now)


class Console:
    def __init__(self, write, out, log, raw, quiet_cp, power=None):
        self.write = write
        self.out, self.log, self.raw = out, log, raw
        self.quiet_cp = quiet_cp
        self.power = power
        self.connected = set()
        self.opened = set()
        self.buffer = bytearray()
        self.line_start = {}

    def emit(self, channel, text):
        # One prefix per line and channel, so interleaved channels stay readable.
        shown = bytearray()
        for byte in text:
            if self.line_start.get(channel, True):
                shown += f'[{channel}] '.encode()
            shown.append(byte)
            self.line_start[channel] = byte == 0x0A
        self.out.write(shown.decode('utf-8', 'replace'))
        self.out.flush()
        if self.log:
            self.log.write(shown)
            self.log.flush()

    def feed(self, data):
        if self.raw:
            self.raw.write(data)
            self.raw.flush()
        self.buffer += data
        for src, dst, protocol, payload in packets(self.buffer):
            if protocol == PROTOCOL_DCMP:
                self.dcmp(src, payload)
            elif protocol == PROTOCOL_TSMP and src == NODE_CP and self.power:
                self.power.answer(payload, time.monotonic())
            elif protocol == PROTOCOL_CP_CONSOLE:
                text = tty_text(payload)
                if text and not self.quiet_cp:
                    self.emit('CP', text)
            elif protocol & 0xFFFF0000 == TTY_FAMILY:
                text = tty_text(payload)
                if text:
                    self.emit(f'TTY{protocol & 0xFFFF:x}', text)
            elif protocol & 0xFFFFFFFC == KERNEL_TTY:
                text = tty_text(payload)
                if text:
                    self.emit(f'KTTY{protocol & 3}', text)

    def dcmp(self, src, payload):
        if len(payload) < 4:
            return
        kind, code = payload[0], payload[1]
        if (kind, code) == (2, 4) and src == NODE_CP and len(payload) >= 6:
            # dfcpm's own power event
            value = struct.unpack_from('<H', payload, 4)[0]
            subject, state = payload[4], payload[5]
            unit = payload[7] if len(payload) >= 8 else 0
            if (subject, state) == (0x0E, 1):
                # DfMgr's resume sysevent 0x100000: the disconnect is over, and its 0x100002
                # handler waits (100 tries) for every unit it had to connect again. The 0/0
                # also makes it replay its 2/1s, which reopens the TTY channels below.
                self.connected.discard(NODE_VITA_SDIO)
                self.opened.clear()
                self.write(dcmp(NODE_VITA_SDIO, 0, 0))
            elif subject in (0x8E, 0x8F) and state == 0:
                # A suspend (0x8E) or shutdown (0x8F) status, forwarded with the CP target in
                # byte 7 (0 for 0x101, 1 for 0x102). DfMgr's sysevent 0x401 sends one and its
                # 0x402 answers busy until the PC disconnects; SDfMgr's suspend callback sends
                # one per call and spins until its own connection is disconnected
                # (deci4p_sdfmgr.c SDfMgrSuspendCallback). Target Manager's temporary
                # disconnect answers each: the PC-only 0/6 has dfcpm send that target 0/1
                # (0/3 for 0x8F). Unanswered, the Vita never reaches standby or off.
                kind = 1 if subject == 0x8E else 3
                self.write(dcmp(NODE_VITA_SDIO, 0, 6, struct.pack('<BBH', kind, unit, 0)))
                self.emit('POWER', f'status (0x{value:x}) unit {unit}: answered 0/6 kind {kind}\n'.encode())
                return
            self.emit('POWER', f'{POWER_EVENTS.get(value, "status")} (0x{value:x})\n'.encode())
            return
        if (kind, code) != (2, 1) or len(payload) < 0x15:
            return
        protocol = struct.unpack_from('<I', payload, 4)[0]
        status = payload[0x14]
        # A Vita's DECI4p manager announcing itself: connect to it, which makes it
        # replay a 2/1 for every protocol it has registered.
        if src >= NODE_VITA_SDIO and src not in self.connected:
            self.connected.add(src)
            self.write(dcmp(src, 0, 0))
        # A registered TTY channel not yet open: open it.
        if (protocol & 0xFFFF0000 == TTY_FAMILY and protocol != PROTOCOL_CP_CONSOLE
                and status & 1 and not status & 2 and (src, protocol) not in self.opened):
            self.opened.add((src, protocol))
            self.write(dcmp(src, 0, 4, struct.pack('<I', protocol)))


class LinkLost(Exception):
    pass


class UsbLink:
    """The DevKit's mini-USB port: the CP board's 054C:0432 gadget."""

    def __init__(self, vendor, product):
        import usb.core
        import usb.util

        self.usb = usb
        self.device = usb.core.find(idVendor=vendor, idProduct=product)
        self.ok = self.device is not None
        if not self.ok:
            return
        try:
            if self.device.is_kernel_driver_active(0):
                self.device.detach_kernel_driver(0)
        except (NotImplementedError, usb.core.USBError):
            pass
        self.device.set_configuration()
        interface = self.device.get_active_configuration()[(0, 0)]
        usb.util.claim_interface(self.device, interface)

        def endpoint(direction):
            return usb.util.find_descriptor(interface, custom_match=lambda e: (
                usb.util.endpoint_direction(e.bEndpointAddress) == direction and
                usb.util.endpoint_type(e.bmAttributes) == usb.util.ENDPOINT_TYPE_BULK))

        self.reader = endpoint(usb.util.ENDPOINT_IN)
        self.writer = endpoint(usb.util.ENDPOINT_OUT)
        self.name = (f'{vendor:04x}:{product:04x} on bus {self.device.bus} address '
                     f'{self.device.address}')

    def read(self, timeout):
        # One USB packet per read: a larger read only completes on a short packet,
        # and a read that times out part-way loses what it had.
        try:
            return bytes(self.reader.read(self.reader.wMaxPacketSize,
                                          timeout=max(1, int(timeout * 1000))))
        except self.usb.core.USBTimeoutError:
            return b''
        except self.usb.core.USBError as error:
            raise LinkLost(error) from None

    def write(self, data):
        try:
            self.writer.write(data, timeout=1000)
        except self.usb.core.USBError as error:
            raise LinkLost(error) from None

    def close(self):
        self.usb.util.dispose_resources(self.device)



def step(kind, parse=None):
    """An argparse type that tags a value with its step kind, so all steps keep their order."""
    def convert(text):
        return (kind, parse(text) if parse else text)
    return convert


def wait_state(text):
    if text not in WAIT_STATES:
        raise argparse.ArgumentTypeError(f'expected one of {", ".join(WAIT_STATES)}')
    return text


class StateStep(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        steps = getattr(namespace, self.dest) or []
        steps.append(('state', None))
        setattr(namespace, self.dest, steps)


def main():
    parser = argparse.ArgumentParser(
        description=__doc__.split('\n\n')[0],
        epilog='Power codes: ' + ', '.join(f'{name} (0x{code:x})'
                                           for name, code in POWER_CODES.items()))
    parser.add_argument('--log', type=argparse.FileType('wb'),
                        help='write the text here too; an existing file is wiped')
    parser.add_argument('--raw', type=argparse.FileType('ab'),
                        help='append the raw DECI4p byte stream here')
    parser.add_argument('--no-cp', action='store_true',
                        help='hide the CP console (the CP\'s own log and the Vita\'s UART1)')
    parser.add_argument('--vid', type=lambda t: int(t, 0), default=USB_VENDOR)
    parser.add_argument('--pid', type=lambda t: int(t, 0), default=USB_PRODUCT)
    parser.add_argument('--power', dest='steps', action='append', metavar='CODE',
                        type=step('power', power_code),
                        help='send dfcpm this power request and wait for its answer '
                             '(repeatable; codes below)')
    parser.add_argument('--state', dest='steps', action=StateStep, nargs=0,
                        help='print the power state dfcpm reports')
    parser.add_argument('--wait', dest='steps', action='append', metavar='STATE',
                        type=step('wait', wait_state),
                        help='poll the power state until it is on, off or standby')
    parser.add_argument('--timeout', type=float, default=30.0, metavar='SECONDS',
                        help='give up on a step after this long without progress (default 30)')
    parser.add_argument('--follow', action='store_true',
                        help='after the steps, keep printing the console')
    args = parser.parse_args()

    try:
        import usb.core  # noqa: F401
    except ImportError:
        sys.exit('pyusb is missing: apt install python3-usb, or pip install pyusb')

    power = Steps(args.steps, args.timeout) if args.steps else None
    announced = False
    while True:
        try:
            link = UsbLink(args.vid, args.pid)
            if not link.ok:
                if power:
                    power.tick(time.monotonic())
                    if power.finished and not args.follow:
                        return 1 if power.failed else 0
                if not announced:
                    note(f'waiting for {args.vid:04x}:{args.pid:04x} (the DevKit\'s mini-USB port)')
                    announced = True
                time.sleep(1)
                continue
        except KeyboardInterrupt:
            return 130
        note(f'attached to {link.name}')
        console = Console(link.write, sys.stdout, args.log, args.raw, args.no_cp, power)
        if power:
            power.attach(link.write)
        try:
            while True:
                if power:
                    power.tick(time.monotonic())
                    if power.finished and not args.follow:
                        return 1 if power.failed else 0
                console.feed(link.read(0.1 if power and not power.finished else 0.5))
        except LinkLost as error:
            # Unplugged or the CP rebooted: wait for it to come back.
            note(f'\nlink: {error}')
            if power and power.lost():
                return 1
            note('waiting to reattach')
            announced = False
            link.close()
            time.sleep(1)
        except KeyboardInterrupt:
            return 130


if __name__ == '__main__':
    sys.exit(main())
