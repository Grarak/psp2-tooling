#!/usr/bin/env python3
"""Stand-in for the PC's Target Manager on a DevKit's DECI4p links (HLE).

A DevKit PC runs Target Manager, which speaks DECI4p to the Vita.  Neither the
PC nor its software is in the firmware dump, so this tool plays that part.  It
answers the DECI4p connection manager (DCMP), serves host0: through DRFP, the
remote file protocol, presses buttons, moves the sticks and places touch
contacts through CTRLP, the controller protocol, which the Vita's own
deci4p_ctrlp module feeds into SceCtrl and SceTouch, and with --launch starts an
application through LOADP, the process loader, as psp2run does.

With --control it also listens on a second Unix socket for one-line input
commands, "launch host0:/app/eboot.bin" among them; devkit/psp2_input.py is the
client.

There are two ways to reach the Vita.  With --usb it drives the Vita's own USB
port (the UDC port, 054C:04CD) through this machine's USB stack with libusb, as
a PC does.  With --cp-usb it uses the DevKit's mini-USB 054C:0432 and addresses the Vita's
debug-SDIO node 0xA000 through the CP board. Only protocols registered on
that SDIO unit respond; VitaOS VCP on the tested 3.65 DevKit uses USB unit 1.

Either way it writes deci4p.log, a decoded record of every packet, to --log-dir,
and tty.log (named after --log-name: deci4p-cp.log gives tty-cp.log), the text of
the Vita's TTYP console ports.
"""

import argparse
import errno
import os
import select
import socket
import struct
import sys
import threading
import time
from pathlib import Path

HEADER = struct.Struct('<IHHII')
HEADER_MAGIC = 0x40
PACKET_MAX = 0x11000

NODE_PC = 0x4000
NODE_CP = 0x6000
CONNECT_RETRY = 5.0          # seconds without any answer from DfMgr before connecting again
NODE_VITA_SDIO = 0xA000
NODE_VITA_USB = 0xA100

PROTOCOL_DCMP = 0x00000100
PROTOCOL_DRFP = 0x00011100


# The TTYP7 words retail-cp acts on (see the "power" control command): power states, the QA
# flag unlock, and reports.
POWER_WORDS = ('reset', 'reboot', 'off', 'suspend', 'wake', 'qaf', 'scratch', 'threads', 'memory', 'debugmem',
               'uninstall')

class Deci4pStream:
    """Splits the byte stream into DECI4p packets and frames replies."""

    def __init__(self, sock, log):
        self.sock = sock
        self.log = log
        self.buffer = bytearray()
        self.started = time.monotonic()
        self.synced = False

    def note(self, text):
        self.log.write(f'{time.monotonic() - self.started:10.3f} {text}\n')
        self.log.flush()

    def record(self, direction, src, dst, protocol, payload):
        shown = payload[:96].hex(' ', 4)
        more = ' ...' if len(payload) > 96 else ''
        self.note(f'{direction} {src:04x}>{dst:04x} proto {protocol:08x} len {len(payload):5d}: '
                  f'{shown}{more}')

    def send(self, src, dst, protocol, payload):
        size = HEADER.size + len(payload)
        if size > PACKET_MAX:
            raise ValueError(f'DECI4p packet of {size} bytes is too large')
        self.record('>>', src, dst, protocol, payload)
        self.sock.sendall(HEADER.pack(HEADER_MAGIC << 24 | size, src, dst, protocol, 0) + payload)

    def packets(self, data):
        """Yields (src, dst, protocol, reserved, payload) for each whole packet."""
        self.buffer += data
        while len(self.buffer) >= HEADER.size:
            word, src, dst, protocol, reserved = HEADER.unpack_from(self.buffer)
            size = word & 0xFFFFFF
            if word >> 24 != HEADER_MAGIC or size < HEADER.size or size > PACKET_MAX:
                if self.synced:
                    raise ValueError(f'bad DECI4p header {bytes(self.buffer[:16]).hex()}')
                # A link killed mid-transfer can leave the rest of a packet in the Vita's IN
                # endpoint (zeros): skip to the next
                # byte that could start a header (the magic is the word's top byte).
                skip = self.buffer.find(bytes([HEADER_MAGIC]), 4) - 3
                skip = skip if skip > 0 else max(len(self.buffer) - 3, 1)
                self.note(f'skipped {skip} stale bytes before the first packet: '
                          f'{bytes(self.buffer[:16]).hex()}')
                del self.buffer[:skip]
                continue
            if len(self.buffer) < size:
                return
            payload = bytes(self.buffer[HEADER.size:size])
            del self.buffer[:size]
            self.synced = True
            self.record('<<', src, dst, protocol, payload)
            yield src, dst, protocol, reserved, payload


# DRFP opcodes.  Payload offsets below are from the end of
# the 16-byte DECI4p header, so the document's +0x18 is 0x08 here.
DRFP_OPEN = 0x04
DRFP_CLOSE = 0x06
DRFP_READ = 0x08
DRFP_WRITE = 0x0A
DRFP_FGETSTAT = 0x0C
DRFP_GETSTAT = 0x0E
DRFP_MKDIR = 0x10
DRFP_RMDIR = 0x12
DRFP_DOPEN = 0x14
DRFP_DCLOSE = 0x16
DRFP_DREAD = 0x18
DRFP_FTRUNCATE = 0x1A
DRFP_TRUNCATE = 0x1C
DRFP_RENAME = 0x1E
DRFP_REMOVE = 0x20
DRFP_CREATE = 0x26
DRFP_FCHSTAT_TIMES = 0x28
DRFP_CHSTAT_TIMES = 0x2A
DRFP_RESOLVE = 0x2C

# Host open flags, the SceIoOpen bits DRFP forwards.
DRFP_O_READ = 0x001
DRFP_O_WRITE = 0x002
DRFP_O_APPEND = 0x100
DRFP_O_CREAT = 0x200
DRFP_O_TRUNC = 0x400
DRFP_O_EXCL = 0x800

# SceIoStat change bits carried by the time requests.
SCE_CST_CT = 0x08
SCE_CST_AT = 0x10
SCE_CST_MT = 0x20

DRFP_UNSUPPORTED = 0xFFFFFFFF
DRFP_ERROR_BASE = 0x11000
DRFP_ENOTSUP = 0xC0

# The host error numbers DRFP maps to Vita errors; they follow Linux numbering.
# Anything unlisted is reported as an I/O error.
DRFP_ERRNO = {
    errno.ENOENT: 2, errno.EIO: 5, errno.EBADF: 9, errno.ENOMEM: 12, errno.EACCES: 13,
    errno.EPERM: 13, errno.EBUSY: 16, errno.EEXIST: 17, errno.ENOTDIR: 20, errno.EISDIR: 21,
    errno.EINVAL: 22, errno.EMFILE: 24, errno.ENOSPC: 28, errno.EROFS: 30,
    errno.ENAMETOOLONG: 36, errno.ENOTEMPTY: 39, errno.EOPNOTSUPP: DRFP_ENOTSUP,
}

DRFP_READ_CHUNK = 0x10000
DRFP_READ_MAX = 0x400000
DRFP_DREAD_NAME_MAX = 0x400

# Stat times are microseconds since 0001-01-01 00:00:00.
TICKS_AT_UNIX_EPOCH = 62135596800 * 1000000

STAT = struct.Struct('<IIQQQQQ')


class DrfpError(Exception):
    def __init__(self, code):
        super().__init__(f'DRFP error {code:#x}')
        self.code = code


def drfp_error(error):
    return DRFP_ERROR_BASE | DRFP_ERRNO.get(error.errno, errno.EIO)


def ns_to_ticks(ns):
    return max(0, ns // 1000 + TICKS_AT_UNIX_EPOCH)


def ticks_to_ns(ticks):
    return (ticks - TICKS_AT_UNIX_EPOCH) * 1000


def drfp_stat(st):
    """The 0x30-byte host stat record.

    Device and node are 0, so the Vita keys its name cache on the path text
    rather than on "dev0x.../node0x...".
    """
    birth = getattr(st, 'st_birthtime_ns', st.st_ctime_ns)
    return STAT.pack(st.st_mode & 0xFFFF, 0, 0, st.st_size,
                     ns_to_ticks(st.st_atime_ns), ns_to_ticks(st.st_mtime_ns), ns_to_ticks(birth))


def drfp_string(payload, offset):
    """A length-prefixed, 4-byte padded string; returns (text, next offset)."""
    if offset + 4 > len(payload):
        raise DrfpError(DRFP_ERROR_BASE | errno.EINVAL)
    length, = struct.unpack_from('<I', payload, offset)
    raw = payload[offset + 4:offset + 4 + length]
    text = raw.split(b'\0', 1)[0].decode('utf-8', 'surrogateescape')
    return text, offset + 4 + ((length + 3) & ~3)


class DrfpServer:
    """Serves one directory as host0:."""

    def __init__(self, root, send, note):
        self.root = Path(root).resolve()
        self.send = send
        self.note = note
        self.files = {}
        self.dirs = {}
        self.write_errors = {}

    def host_path(self, text):
        parts = [part for part in text.replace('\\', '/').split('/') if part not in ('', '.')]
        if '..' in parts:
            raise DrfpError(DRFP_ERROR_BASE | errno.EACCES)
        return self.root.joinpath(*parts)

    @staticmethod
    def new_handle(table):
        handle = 1
        while handle in table:
            handle += 1
        return handle

    def file(self, handle):
        try:
            return self.files[handle]
        except KeyError:
            raise DrfpError(DRFP_ERROR_BASE | errno.EBADF) from None

    def reply(self, opcode, tag, result, body=b''):
        self.send(struct.pack('<III', opcode, tag, result) + body)

    def receive(self, payload):
        if len(payload) < 8:
            self.note(f'DRFP short request {payload.hex()}')
            return
        opcode, tag = struct.unpack_from('<II', payload)
        handler = self.HANDLERS.get(opcode)
        if handler is None:
            self.note(f'DRFP tag {tag:#06x} unsupported opcode {opcode:#x}')
            self.reply(DRFP_UNSUPPORTED, tag, DRFP_ERROR_BASE | DRFP_ENOTSUP)
            return
        name, method, size = handler
        try:
            text, result, body = method(self, tag, payload)
        except DrfpError as error:
            text, result, body = '', error.code, b''
        except OSError as error:
            text, result, body = str(error), drfp_error(error), b''
        except struct.error:
            text, result, body = f'malformed {payload[:0x40].hex()}', DRFP_ERROR_BASE | errno.EINVAL, b''
        if text is None:
            return
        self.note(f'DRFP tag {tag:#06x} {name} {text} -> {result:#x}')
        if size:
            body = body.ljust(size - 0x1C, b'\0')
        self.reply(opcode, tag, result, body)

    def op_open(self, tag, payload):
        flags, mode = struct.unpack_from('<II', payload, 0x08)
        text, _ = drfp_string(payload, 0x10)
        path = self.host_path(text)
        os_flags = os.O_RDWR if flags & DRFP_O_WRITE else os.O_RDONLY
        for bit, os_bit in ((DRFP_O_APPEND, os.O_APPEND), (DRFP_O_CREAT, os.O_CREAT),
                            (DRFP_O_TRUNC, os.O_TRUNC), (DRFP_O_EXCL, os.O_EXCL)):
            if flags & bit:
                os_flags |= os_bit
        if flags & DRFP_O_WRITE and os.path.isdir(path):
            raise DrfpError(DRFP_ERROR_BASE | errno.EISDIR)
        host_mode = 0o666 if mode & 0x80 or not mode else 0o444
        fd = os.open(path, os_flags, host_mode)
        handle = self.new_handle(self.files)
        self.files[handle] = (fd, bool(flags & DRFP_O_APPEND))
        return (f'{text!r} flags {flags:#x} = {handle}', 0,
                struct.pack('<I', handle) + drfp_stat(os.fstat(fd)))

    def op_close(self, tag, payload):
        handle, = struct.unpack_from('<I', payload, 0x08)
        fd, _ = self.file(handle)
        del self.files[handle]
        self.write_errors.pop(handle, None)
        os.close(fd)
        return f'{handle}', 0, b''

    def op_read(self, tag, payload):
        handle, _, offset, length = struct.unpack_from('<IIQI', payload, 0x08)
        try:
            fd, _ = self.file(handle)
            data = os.pread(fd, min(length, DRFP_READ_MAX), offset)
            result = 0
        except DrfpError as error:
            data, result = b'', error.code
        except OSError as error:
            data, result = b'', drfp_error(error)
        self.note(f'DRFP tag {tag:#06x} read {handle} at {offset:#x} {length:#x} '
                  f'= {len(data):#x} -> {result:#x}')
        # Every chunk but the last is exactly 0x10000 bytes; a shorter chunk or the
        # last index ends the request, and one empty chunk reports end of file.
        count = max(1, -(-len(data) // DRFP_READ_CHUNK))
        for index in range(count):
            chunk = data[index * DRFP_READ_CHUNK:(index + 1) * DRFP_READ_CHUNK]
            self.reply(DRFP_READ, tag, result,
                       struct.pack('<IHHI', 0, count, index + 1, len(chunk)) + chunk)
        return None, 0, b''

    def op_write(self, tag, payload):
        handle, flags, offset, length = struct.unpack_from('<IB3xQI', payload, 0x08)
        data = payload[0x1C:0x1C + length]
        try:
            fd, append = self.file(handle)
            if append:
                written = os.write(fd, data)
            else:
                written = os.pwrite(fd, data, offset)
            if written != len(data):
                raise DrfpError(DRFP_ERROR_BASE | errno.ENOSPC)
        except DrfpError as error:
            self.write_errors.setdefault(handle, error.code)
        except OSError as error:
            self.write_errors.setdefault(handle, drfp_error(error))
        if flags:
            # More chunks follow and the Vita waits for none of them; the last
            # chunk's reply carries the sequence's first failure.
            return None, 0, b''
        result = self.write_errors.pop(handle, 0)
        return f'{handle} at {offset:#x} {length:#x}', result, b''

    def op_fgetstat(self, tag, payload):
        handle, = struct.unpack_from('<I', payload, 0x08)
        fd, _ = self.file(handle)
        return f'{handle}', 0, drfp_stat(os.fstat(fd))

    def op_getstat(self, tag, payload):
        text, _ = drfp_string(payload, 0x08)
        return f'{text!r}', 0, drfp_stat(os.stat(self.host_path(text)))

    def op_mkdir(self, tag, payload):
        text, _ = drfp_string(payload, 0x0C)
        path = self.host_path(text)
        os.mkdir(path)
        return f'{text!r}', 0, struct.pack('<I', 0) + drfp_stat(os.stat(path))

    def op_rmdir(self, tag, payload):
        text, _ = drfp_string(payload, 0x08)
        os.rmdir(self.host_path(text))
        return f'{text!r}', 0, b''

    def op_dopen(self, tag, payload):
        text, _ = drfp_string(payload, 0x08)
        path = self.host_path(text)
        names = sorted(os.listdir(path))
        handle = self.new_handle(self.dirs)
        self.dirs[handle] = (path, names)
        return f'{text!r} = {handle}', 0, struct.pack('<I', handle)

    def op_dclose(self, tag, payload):
        handle, = struct.unpack_from('<I', payload, 0x08)
        if self.dirs.pop(handle, None) is None:
            raise DrfpError(DRFP_ERROR_BASE | errno.EBADF)
        return f'{handle}', 0, b''

    def op_dread(self, tag, payload):
        handle, = struct.unpack_from('<I', payload, 0x08)
        try:
            path, names = self.dirs[handle]
        except KeyError:
            raise DrfpError(DRFP_ERROR_BASE | errno.EBADF) from None
        while names:
            name = names.pop(0)
            try:
                st = os.stat(path / name)
            except OSError:
                continue
            raw = os.fsencode(name)[:DRFP_DREAD_NAME_MAX] + b'\0'
            blob = drfp_stat(st) + struct.pack('<I', len(raw)) + raw
            return (f'{handle} {name!r}', 0,
                    bytes(0x34) + struct.pack('<II', 1, len(blob)) + blob)
        return f'{handle} end', 0, bytes(0x34) + struct.pack('<II', 0, 0)

    def op_ftruncate(self, tag, payload):
        handle, _, size = struct.unpack_from('<IIQ', payload, 0x08)
        fd, _ = self.file(handle)
        os.ftruncate(fd, size)
        return f'{handle} {size:#x}', 0, b''

    def op_truncate(self, tag, payload):
        size, = struct.unpack_from('<Q', payload, 0x08)
        text, _ = drfp_string(payload, 0x10)
        os.truncate(self.host_path(text), size)
        return f'{text!r} {size:#x}', 0, b''

    def op_rename(self, tag, payload):
        old, offset = drfp_string(payload, 0x08)
        new, _ = drfp_string(payload, offset)
        path = self.host_path(new)
        os.rename(self.host_path(old), path)
        return f'{old!r} {new!r}', 0, struct.pack('<I', 0) + drfp_stat(os.stat(path))

    def op_remove(self, tag, payload):
        text, _ = drfp_string(payload, 0x08)
        os.remove(self.host_path(text))
        return f'{text!r}', 0, b''

    def op_create(self, tag, payload):
        text, _ = drfp_string(payload, 0x10)
        path = self.host_path(text)
        # The request carries no exclusive or truncate bit: create the file if it
        # is missing and leave an existing one as it is.
        os.close(os.open(path, os.O_WRONLY | os.O_CREAT, 0o666))
        return f'{text!r}', 0, struct.pack('<I', 0) + drfp_stat(os.stat(path))

    @staticmethod
    def set_times(target, cbit, record):
        _, _, _, _, atime, mtime, _ = STAT.unpack(record)
        if not cbit & (SCE_CST_AT | SCE_CST_MT):
            return
        st = os.stat(target)
        times = (ticks_to_ns(atime) if cbit & SCE_CST_AT else st.st_atime_ns,
                 ticks_to_ns(mtime) if cbit & SCE_CST_MT else st.st_mtime_ns)
        os.utime(target, ns=times)

    def op_fchstat_times(self, tag, payload):
        handle, cbit = struct.unpack_from('<II', payload, 0x08)
        fd, _ = self.file(handle)
        self.set_times(fd, cbit, payload[0x10:0x40])
        return f'{handle} cbit {cbit:#x}', 0, b''

    def op_chstat_times(self, tag, payload):
        cbit, = struct.unpack_from('<I', payload, 0x08)
        text, _ = drfp_string(payload, 0x40)
        self.set_times(self.host_path(text), cbit, payload[0x10:0x40])
        return f'{text!r} cbit {cbit:#x}', 0, b''

    def op_resolve(self, tag, payload):
        first, offset = drfp_string(payload, 0x08)
        second, _ = drfp_string(payload, offset)
        # Unsupported: the Vita then keeps the second string unchanged.
        return f'{first!r} {second!r}', DRFP_ERROR_BASE | DRFP_ENOTSUP, b''

    # opcode: (name, handler, smallest full reply size; 0 when the handler replies itself).
    # The Vita copies a reply over its request buffer, so short replies are padded.
    HANDLERS = {
        DRFP_OPEN: ('open', op_open, 0x50),
        DRFP_CLOSE: ('close', op_close, 0x1C),
        DRFP_READ: ('read', op_read, 0),
        DRFP_WRITE: ('write', op_write, 0x1C),
        DRFP_FGETSTAT: ('fgetstat', op_fgetstat, 0x4C),
        DRFP_GETSTAT: ('getstat', op_getstat, 0x4C),
        DRFP_MKDIR: ('mkdir', op_mkdir, 0x50),
        DRFP_RMDIR: ('rmdir', op_rmdir, 0x1C),
        DRFP_DOPEN: ('dopen', op_dopen, 0x20),
        DRFP_DCLOSE: ('dclose', op_dclose, 0x1C),
        DRFP_DREAD: ('dread', op_dread, 0x58),
        DRFP_FTRUNCATE: ('ftruncate', op_ftruncate, 0x1C),
        DRFP_TRUNCATE: ('truncate', op_truncate, 0x1C),
        DRFP_RENAME: ('rename', op_rename, 0x50),
        DRFP_REMOVE: ('remove', op_remove, 0x1C),
        DRFP_CREATE: ('create', op_create, 0x50),
        DRFP_FCHSTAT_TIMES: ('fchstat-times', op_fchstat_times, 0x1C),
        DRFP_CHSTAT_TIMES: ('chstat-times', op_chstat_times, 0x1C),
        DRFP_RESOLVE: ('resolve', op_resolve, 0x20),
    }

    def close(self):
        for fd, _ in self.files.values():
            os.close(fd)
        self.files.clear()
        self.dirs.clear()
        self.write_errors.clear()


PROTOCOL_CTRLP = 0x0002C000

# CTRLP sub-header at payload +0x00: length (8 + body), opcode, tag.
CTRLP_HDR = struct.Struct('<HHI')

CTRLP_RECORD_START = 0x02
CTRLP_RECORD_STOP = 0x04
CTRLP_PLAY_START = 0x08
CTRLP_PLAY_STOP = 0x0A
CTRLP_PLAY_DATA = 0x0C
CTRLP_SET_PAD = 0x10
CTRLP_PANEL_INFO = 0x16
CTRLP_DATA = 0x07
CTRLP_SPACE = 0x0F

# Channel bits for a playback session, and the "match records by sequence" sync mode.
CTRLP_CHANNEL_PAD = 1
CTRLP_CHANNEL_TOUCH = 2
CTRLP_SYNC_SEQUENCE = 3

CTRLP_BUTTON_MASK = 0x0031FFFF     # gCtrlpButtonMask: no POWER, no HEADPHONE
CTRLP_ANALOG_CENTRE = 0x80         # an emulation offset of 0x80 leaves the axis alone
CTRLP_TOUCH_CONTACTS = 6           # a touch payload always carries all six entries
CTRLP_TOUCH_FORCE = 0x80
CTRLP_RECORD_TOUCH = 0x6C
CTRLP_PAYLOAD_TOUCH = 0x54
CTRLP_ENTRY = 0x0C
CTRLP_KIND_TOUCH = 1
CTRLP_KIND_PAD = 0
CTRLP_RECORD_PAD = 0x28
CTRLP_PAYLOAD_PAD = 0x10
CTRLP_PAD_BODY = 0x10

# The front panel's active area, which is exactly twice the 960x544 screen
# (SceTouch's TouchDecodeReport clamps to these).
CTRLP_PANEL_MAX_X = 0x77F
CTRLP_PANEL_MAX_Y = 0x43F

CTRLP_BUTTONS = {
    'select': 0x000001, 'l3': 0x000002, 'r3': 0x000004, 'start': 0x000008,
    'up': 0x000010, 'right': 0x000020, 'down': 0x000040, 'left': 0x000080,
    'l2': 0x000100, 'r2': 0x000200, 'l': 0x000400, 'r': 0x000800,
    'triangle': 0x001000, 'circle': 0x002000, 'cross': 0x004000, 'square': 0x008000,
    'ps': 0x010000, 'volup': 0x100000, 'voldown': 0x200000,
}


def parse_buttons(text):
    """"cross", "cross+square", or a number."""
    try:
        return int(text, 0)
    except ValueError:
        pass
    value = 0
    for name in text.split('+'):
        if name not in CTRLP_BUTTONS:
            raise ValueError(f'unknown button {name!r}; known: '
                             + ', '.join(sorted(CTRLP_BUTTONS)))
        value |= CTRLP_BUTTONS[name]
    return value


class CtrlpClient:
    """The PC's end of CTRLP, DECI4p's controller protocol.

    The firmware does the injecting: ctrlp feeds SceCtrl and SceTouch through
    ksceCtrlSetButtonEmulation, ksceCtrlSetAnalogEmulation and the two Ctrlp
    callbacks, so nothing here synthesises a Syscon reply.

    Buttons take the stateless 0x10 message, which SceCtrl merges with the physical
    pad and which expires by itself after 3600 polls, about 60 seconds.  Touch has no
    stateless path, so a contact needs a playback session: 0x08 opens one for the
    panel alone, 0x0C queues a record, and 0x0A closes it and gives the panel back.
    A record with timestamp 0 plays on the next frame, so no clock sync is needed.
    """

    def __init__(self, send, note):
        self.send = send
        self.note = note
        self.tag = 0
        self.buttons = 0
        # The sticks (lx, ly, rx, ry), 0..255; 0x80 leaves a physical axis as it is.
        self.axes = [CTRLP_ANALOG_CENTRE] * 4
        self.contacts = []
        self.touch_open = False
        self.play_open = False
        self.play_buttons = 0
        self.record_open = False
        self.sequence = 0
        self.waiting = False        # a request whose reply has not arrived
        self.queue = []

    def request(self, opcode, body=b''):
        """Queues one request.

        The Vita answers one at a time, and DfMgr drops a second one that arrives
        while a reply is still outstanding, with a DCMP 3/3 receiver overflow
        rather than a CTRLP error.  Sending a session's start
        and its first record together therefore loses the record.
        """
        self.queue.append((opcode, body))
        self.pump()

    def pump(self):
        if self.waiting or not self.queue:
            return
        opcode, body = self.queue.pop(0)
        self.tag = (self.tag + 1) & 0xFFFFFFFF
        self.waiting = True
        self.send(CTRLP_HDR.pack(8 + len(body), opcode, self.tag) + body)

    def receive(self, payload):
        if len(payload) < 8:
            return
        _, opcode, tag = CTRLP_HDR.unpack_from(payload)
        if opcode in (CTRLP_DATA, CTRLP_SPACE):
            # Unsolicited, so it answers nothing and releases no request.
            # 0x60 bytes reach past a touch record's header into its contact entries.
            head = payload[8:8 + 0x60]
            self.note(f'CTRLP unsolicited {opcode:#04x} ({len(payload)} bytes)'
                      + (f' head {head.hex(" ", 4)}' if head else ''))
            return
        if len(payload) < 0x0C:
            return
        result, = struct.unpack_from('<I', payload, 8)
        body = payload[0x0C:]
        self.note(f'CTRLP reply {opcode:#04x} tag {tag} result {result:#x}'
                  + (f' body {body.hex(" ", 4)}' if body else ''))
        self.waiting = False
        self.pump()

    def set_pad(self, buttons):
        """0x10: hold these buttons and the sticks at self.axes (centred: left alone).

        The axes go out twice: SceCtrl hands a process that samples in
        SCE_CTRL_MODE_ANALOG the first four bytes and one in
        SCE_CTRL_MODE_ANALOG_WIDE the further four, so axes sent in the first
        four only would not move a game's sticks.
        """
        self.buttons = buttons & CTRLP_BUTTON_MASK
        self.request(CTRLP_SET_PAD,
                     struct.pack('<III8B', 0, CTRLP_PAD_BODY, self.buttons,
                                 *self.axes, *self.axes))

    def touch_record(self, contacts, panel=0):
        """One 0x6C-byte touch record."""
        self.sequence += 1
        entries = b''
        for index in range(CTRLP_TOUCH_CONTACTS):
            if index < len(contacts):
                identifier, force, x, y = contacts[index]
            else:
                identifier, force, x, y = 0, 0, 0, 0
            entries += struct.pack('<IBBHHH', CTRLP_ENTRY, identifier, force, 0, x, y)
        return (struct.pack('<IIQBBHHBB', CTRLP_RECORD_TOUCH, self.sequence, 0,
                            CTRLP_KIND_TOUCH, panel, 0, 0, 0, 0)
                + struct.pack('<III', CTRLP_PAYLOAD_TOUCH, 0, len(contacts))
                + entries)

    def touch(self, contacts, panel=0):
        """Holds these contacts down; the Vita re-applies the last record every frame."""
        if not self.touch_open:
            # Only the touch channel, so the physical pad keeps working.
            self.request(CTRLP_PLAY_START,
                         struct.pack('<II', CTRLP_CHANNEL_TOUCH, CTRLP_SYNC_SEQUENCE))
            self.touch_open = True
            self.sequence = 0
        self.request(CTRLP_PLAY_DATA,
                     struct.pack('<II', 1, 4) + self.touch_record(contacts, panel))
        self.contacts = list(contacts)

    def untouch(self):
        if not self.touch_open:
            return
        self.touch([])
        self.request(CTRLP_PLAY_STOP)
        self.touch_open = False
        self.contacts = []

    def record_start(self, channels=CTRLP_CHANNEL_TOUCH):
        """0x02: the Vita sends the real pad and touch back as 0x07 records.

        Recording is the read-only half of the same callback playback drives, so
        records arriving here prove the callback is being invoked for that
        channel at all.
        """
        self.request(CTRLP_RECORD_START, struct.pack('<II', channels, 0))
        self.record_open = True

    def record_stop(self):
        if not self.record_open:
            return
        self.request(CTRLP_RECORD_STOP)
        self.record_open = False

    def panel_info(self, panel=0):
        """0x16: what ctrlp cached from ksceTouchGetPanelInfo at module_start.

        Every playback contact is clamped against this descriptor, so its
        minAaX/minAaY/maxAaX/maxAaY and minForce/maxForce say whether a contact
        the host sends can reach the screen at all.
        """
        self.request(CTRLP_PANEL_INFO, struct.pack('<I', panel))

    def pad_record(self, buttons, port=0):
        """One 0x28-byte pad record."""
        self.sequence += 1
        return (struct.pack('<IIQBBHHBB', CTRLP_RECORD_PAD, self.sequence, 0,
                            CTRLP_KIND_PAD, port, 0, 0, 0, 0)
                + struct.pack('<II8B', CTRLP_PAYLOAD_PAD, buttons,
                              *self.axes, *self.axes))

    def play_pad(self, buttons, port=0):
        """Drives the pad through a playback session, the path touch has to use.

        The stateless 0x10 reaches SceCtrl through ksceCtrlSetButtonEmulation and
        needs no session; touch has no such path, so it can only
        arrive as playback records.  Driving the pad the same way tells the two
        apart: playback replaces the sample rather than merging into it (4.3).
        """
        if not self.play_open:
            self.request(CTRLP_PLAY_START,
                         struct.pack('<II', CTRLP_CHANNEL_PAD, CTRLP_SYNC_SEQUENCE))
            self.play_open = True
            self.sequence = 0
        self.play_buttons = buttons & CTRLP_BUTTON_MASK
        self.request(CTRLP_PLAY_DATA,
                     struct.pack('<II', 1, 4) + self.pad_record(self.play_buttons, port))

    def play_both(self, buttons, contacts, port=0, panel=0):
        """One playback session carrying a pad record and a touch record.

        The pad half is the control: it is known to reach SceCtrl, so if it moves
        the screen while the touch half does nothing, the session is live and touch
        records alone are being dropped.
        """
        if not self.play_open:
            self.request(CTRLP_PLAY_START,
                         struct.pack('<II', CTRLP_CHANNEL_PAD | CTRLP_CHANNEL_TOUCH,
                                     CTRLP_SYNC_SEQUENCE))
            self.play_open = True
            self.touch_open = True
            self.sequence = 0
        self.play_buttons = buttons & CTRLP_BUTTON_MASK
        self.request(CTRLP_PLAY_DATA,
                     struct.pack('<II', 1, 4) + self.pad_record(self.play_buttons, port))
        self.request(CTRLP_PLAY_DATA,
                     struct.pack('<II', 1, 4) + self.touch_record(contacts, panel))
        self.contacts = list(contacts)

    def play_stop(self):
        if not self.play_open:
            return
        self.play_pad(0)
        self.request(CTRLP_PLAY_STOP)
        self.play_open = False
        self.touch_open = False
        self.play_buttons = 0
        self.contacts = []

    def close(self):
        self.touch_open = False
        self.play_open = False
        self.record_open = False
        self.play_buttons = 0
        self.contacts = []
        self.waiting = False
        self.queue.clear()


PROTOCOL_LOADP = 0x00024000

# LOADP sub-header at payload +0x00: a flags byte, the opcode, and an unused u16.
# A reply carries the request's opcode where the flags were and
# its own opcode, the request's plus 1; a u32 result follows.
LOADP_HDR = struct.Struct('<BBH')

LOADP_CREATE_PROCESS = 0x00
LOADP_KILL_PROCESS = 0x04
LOADP_LAUNCH_TITLE = 0x06
LOADP_KILL_TITLE = 0x08
LOADP_NOTICE = 0x80                # opcodes from here up are unsolicited

LOADP_PATH_MAX = 0x400
LOADP_ARGS_MAX = 0x40
LOADP_TITLE_SIZE = 10              # nine characters and the NUL
LOADP_OPT_SIZE = 0x814             # ksceAppMgrLaunchAppByPath's option block

LOADP_NOTICES = {
    0x80: 'process created', 0x81: 'process exited', 0x82: 'process killed',
    0x83: 'process text', 0x84: 'process event 0x84', 0x85: 'process event 0x85',
    0x90: 'module loaded', 0x91: 'module unloaded',
}

# The results LOADP maps kernel errors to; the rest print as numbers.
LOADP_RESULTS = {
    0: 'ok', 4: 'a helper process is still running', 7: 'bad argument',
    8: 'unknown opcode', 9: 'bad size', 0x30002: 'malformed request',
    0x30008: 'out of memory', 0x3000A: 'no such file, or the path is not allowed',
    0x30010: 'path too long', 0x30012: 'no such process or title',
    0x30026: 'not allowed for this process', 0x3003A: 'unmapped kernel error',
    0x30083: 'not available (0x80010058)',
}


def loadp_string(text):
    """A length-prefixed string, NUL counted, zero-padded to 4 bytes."""
    raw = text.encode('utf-8', 'surrogateescape') + b'\0'
    return struct.pack('<I', len(raw)) + raw.ljust((len(raw) + 3) & ~3, b'\0')


def loadp_is_title(text):
    return len(text) == 9 and text.isalnum() and text == text.upper()


def loadp_create_process(path, arguments=(), appmgr=True, flags=0):
    """Opcode 0x00: run a SELF by path.

    With the option block the Vita launches through ksceAppMgrLaunchAppByPath, as
    it does for its own helper applications; without it, it creates a bare process.
    The block is the one LOADP builds for itself: its size and zeroes.
    """
    if len(path.encode('utf-8', 'surrogateescape')) + 1 > LOADP_PATH_MAX:
        raise ValueError(f'PATH must be shorter than {LOADP_PATH_MAX} bytes')
    if len(arguments) > LOADP_ARGS_MAX:
        raise ValueError(f'at most {LOADP_ARGS_MAX} arguments')
    body = struct.pack('<IIIII', 0, 0, 0, 0, len(arguments)) + loadp_string(path)
    for argument in arguments:
        body += loadp_string(argument)
    if appmgr:
        body += struct.pack('<I', LOADP_OPT_SIZE).ljust(LOADP_OPT_SIZE, b'\0')
    return LOADP_HDR.pack(flags, LOADP_CREATE_PROCESS, 0) + body


def loadp_title(opcode, title):
    """Opcodes 0x06 and 0x08: launch or kill an installed title."""
    if not loadp_is_title(title):
        raise ValueError(f'{title!r} is not a title ID such as VSDK00007')
    raw = title.encode() + b'\0'
    return LOADP_HDR.pack(0, opcode, 0) + struct.pack('<I', len(raw)) + raw.ljust(12, b'\0')


def loadp_module(opcode, pid, target):
    if not 0 <= pid <= 0xffffffff:
        raise ValueError('PID must fit in 32 bits; 0 selects the kernel')
    body = struct.pack('<I', pid)
    if opcode == 0x10:
        if len(target.encode()) + 1 > LOADP_PATH_MAX:
            raise ValueError('module path too long')
        body += loadp_string(target)
    elif opcode in (0x12, 0x14, 0x16):
        module = int(target, 0)
        if not 0 <= module <= 0xffffffff:
            raise ValueError('module ID must fit in 32 bits')
        body += struct.pack('<I', module)
        if opcode != 0x16:
            body += struct.pack('<I', 0)
    else:
        raise ValueError('unsupported module operation')
    return LOADP_HDR.pack(0, opcode, 0) + body


class LoadpClient:
    """The PC's end of LOADP, DECI4p's process loader.

    The Vita's deci4p_loadp module does the launching, through SceAppMgr or
    SceProcessmgr; this only asks.  It works on one request at a time and refuses
    a second one that arrives meanwhile, so requests queue here until the reply.
    """

    def __init__(self, send, note):
        self.send = send
        self.note = note
        self.open = False
        self.waiting = None         # the opcode whose reply has not arrived
        self.queue = []
        self.last = 'nothing launched'

    def request(self, payload, text):
        self.queue.append((payload, text))
        self.pump()

    def pump(self):
        if not self.open or self.waiting is not None or not self.queue:
            return
        payload, text = self.queue.pop(0)
        self.waiting = payload[1]
        self.note(f'LOADP request {self.waiting:#04x} {text}')
        self.send(payload)

    def opened(self):
        """DCMP reported the protocol open, or this host has just opened it."""
        self.open = True
        self.pump()

    def launch(self, target, arguments=(), appmgr=True):
        if loadp_is_title(target) and not arguments:
            self.request(loadp_title(LOADP_LAUNCH_TITLE, target), f'launch title {target}')
        else:
            self.request(loadp_create_process(target, arguments, appmgr),
                         f'{"launch" if appmgr else "spawn"} {target!r} {list(arguments)}')

    def kill(self, target):
        if loadp_is_title(target):
            self.request(loadp_title(LOADP_KILL_TITLE, target), f'kill title {target}')
        else:
            pid = int(target, 0)
            self.request(LOADP_HDR.pack(0, LOADP_KILL_PROCESS, 0) + struct.pack('<I', pid),
                         f'kill pid {pid:#x}')

    def receive(self, payload):
        if len(payload) < 8:
            return
        echo, opcode, _ = LOADP_HDR.unpack_from(payload)
        words = struct.unpack_from(f'<{(len(payload) - 4) // 4}I', payload, 4)
        if opcode >= LOADP_NOTICE:
            name = LOADP_NOTICES.get(opcode, 'notice')
            self.note(f'LOADP {name} {opcode:#04x}: ' + ' '.join(f'{word:#x}' for word in words[:5]))
            if opcode in (0x81, 0x82):
                self.last = f'pid {words[0]:#x} {name.split()[1]}' + (
                    f' status {words[1]:#x}' if opcode == 0x81 else '')
            return
        result = words[0]
        text = LOADP_RESULTS.get(result, 'error')
        pid = words[1] if result == 0 and len(words) > 1 else None
        self.note(f'LOADP reply {opcode:#04x} to {echo:#04x} result {result:#x} ({text})'
                  + (f' pid {pid:#x}' if pid is not None else '')
                  + (f' module {words[2]:#x}' if opcode in (0x11, 0x13, 0x15, 0x17)
                     and result == 0 and len(words) > 2 else ''))
        if (opcode in (LOADP_CREATE_PROCESS + 1, LOADP_LAUNCH_TITLE + 1) and result == 0
                and len(payload) >= 0xA4):
            # The main module: its name at +0x40 and three
            # segment records at +0x64; profile/vita_prof.py reads the text base from here.
            module = payload[0x40:0x5A].split(b'\0')[0].decode('ascii', 'replace')
            segments = struct.unpack_from('<12I', payload, 0x64)
            self.note(f'LOADP main module {module!r} segments '
                      + ' | '.join(' '.join(f'{w:#x}' for w in segments[i:i + 4])
                                   for i in range(0, 12, 4)))
        if opcode in (LOADP_CREATE_PROCESS + 1, LOADP_LAUNCH_TITLE + 1):
            self.last = f'pid {pid:#x} running' if pid is not None else f'failed {result:#x} ({text})'
        if self.waiting is not None and opcode == self.waiting + 1:
            self.waiting = None
            self.pump()

    def close(self):
        self.open = False
        self.waiting = None
        self.queue.clear()


PROTOCOL_DBGP = 0x00020000

# DBGP sub-header at payload +0x00: version 1, a command group, the opcode, a tag the reply
# echoes; then a pid (requests) and, in replies, the result. A reply's opcode is the request's
# plus one; a failed request's reply carries the error in the result word.
DBGP_HDR = struct.Struct('<BBBBII')
DBGP_PROCESS = 0x20               # group: process list, attach and detach
DBGP_ATTACH = 0x10
DBGP_DETACH = 0x12
DBGP_COREDUMP = 0x80              # group: core dumps
DBGP_DUMP = 0x00
DBGP_DUMP_DONE = 0x20             # notice: pid, dump id, status, the core file's path
DBGP_DUMP_PROGRESS = 0x22         # notice: pid, dump id, percent
DBGP_ALREADY_ATTACHED = 0x20052
DBGP_DEST_HOST0 = 1               # SceCoredump's destination 1: host0:
DBGP_LEVELS = {'full': 0, 'mini': 1}   # the wire's words; left out, the Dump Level setting holds


class DbgpClient:
    """The PC's end of DBGP, the debugger protocol: what psp2ctrl's pdump does.

    A DevKit in development mode writes no core file when an application crashes: the
    process stays stopped (debug-suspended) for Target Manager. pdump attaches to it,
    which gives the process a DBGP session of its own, asks that session for a core dump
    to host0: (served here, DRFP), waits for the dump's notice and detaches. Kill the
    process afterwards with LOADP.
    """

    def __init__(self, send, note):
        self.send = send
        self.note = note
        self.tag = 0
        self.job = None             # [pid, level, step]
        self.last = 'no core dump'

    def request(self, group, opcode, pid, body=b''):
        self.tag = (self.tag + 1) & 0xFF
        self.note(f'DBGP request {group:#04x}/{opcode:#04x} pid {pid:#x}')
        self.send(DBGP_HDR.pack(1, group, opcode, self.tag, pid, 0) + body)

    def pdump(self, pid, level=None):
        if self.job is not None:
            raise ValueError(f'a core dump of pid {self.job[0]:#x} is under way')
        self.job = [pid, level, 'attach']
        self.last = f'pid {pid:#x} attaching'
        self.request(DBGP_PROCESS, DBGP_ATTACH, pid, struct.pack('<I', 0))

    def dump(self):
        pid, level, _ = self.job
        self.job[2] = 'dump'
        self.last = f'pid {pid:#x} dumping'
        # Destination, path length (no path: SceCoredump names the file), then the level.
        body = struct.pack('<III', 0, DBGP_DEST_HOST0, 0)
        if level is not None:
            body += struct.pack('<I', DBGP_LEVELS[level])
        self.request(DBGP_COREDUMP, DBGP_DUMP, pid, body)

    def detach(self):
        self.job[2] = 'detach'
        self.request(DBGP_PROCESS, DBGP_DETACH, self.job[0], struct.pack('<I', 0))

    def finish(self, text):
        self.last = text
        self.note(f'DBGP pdump: {text}')
        self.job = None

    def receive(self, payload):
        if len(payload) < DBGP_HDR.size:
            return
        _, group, opcode, _, _, result = DBGP_HDR.unpack_from(payload)
        words = struct.unpack_from(f'<{(len(payload) - 12) // 4}I', payload, 12)
        self.note(f'DBGP {group:#04x}/{opcode:#04x} result {result:#x} '
                  + ' '.join(f'{word:#x}' for word in words[:6]))
        job = self.job
        if group == DBGP_COREDUMP and opcode == DBGP_DUMP_DONE and len(words) >= 5:
            pid, _, _, status, length = words[:5]
            path = payload[0x20:0x20 + length].split(b'\0')[0].decode('utf-8', 'replace')
            if job is not None and job[0] == pid and job[2] == 'dump':
                self.last = (f'pid {pid:#x} core file {path}' if status == 0
                             else f'pid {pid:#x} core dump failed {status:#x}')
                self.detach()
            return
        if job is None or opcode & 1 == 0:
            return
        step = job[2]
        if step == 'attach' and (group, opcode) == (DBGP_PROCESS, DBGP_ATTACH + 1):
            if result in (0, DBGP_ALREADY_ATTACHED):
                self.dump()
            else:
                self.finish(f'pid {job[0]:#x} attach failed {result:#x}')
        elif step == 'dump' and (group, opcode) == (DBGP_COREDUMP, DBGP_DUMP + 1) and result:
            self.last = f'pid {job[0]:#x} core dump refused {result:#x}'
            self.detach()
        elif step == 'detach' and (group, opcode) == (DBGP_PROCESS, DBGP_DETACH + 1):
            self.finish(self.last + ('' if result == 0 else f' (detach {result:#x})'))

    def close(self):
        if self.job is not None:
            self.finish(f'pid {self.job[0]:#x}: the link closed')


PROTOCOL_TTYP = 0x80030000
TTYP_PORTS = 8
TTYP_HEADER = 0x1c          # after the DECI4p header; the text follows, its length at +0x18


# retail-cp's power port: the last console, which no process writes.
POWER_TTYP = 7


def tty_input(text):
    """A TTYP input packet's payload: the output layout, read back by the port's tty reader."""
    data = text.encode()
    return bytes(TTYP_HEADER - 4) + struct.pack('<I', len(data)) + data


class TtyServer:
    """TTYP0-7, the Vita's console ports.

    Kernel console writes and processes' stdout arrive as kind 0 packets; after the
    16-byte DECI4p header: +0x00 origin (0x1000 a process or user thread, 0x8000 the
    kernel), +0x02 kind, +0x04 pid, +0x18 length, +0x1c text.  Kind 2 is ttyp's notice
    that a process exited or was killed.  Each port's text goes to tty.log, one
    "[TTYPn pid]" prefix per line.
    """

    def __init__(self, port, log, note):
        self.port = port
        self.log = log
        self.note = note
        self.line_start = True

    def receive(self, payload):
        if len(payload) < TTYP_HEADER:
            return
        origin, kind, _, pid = struct.unpack_from('<HBBI', payload, 0)
        length = struct.unpack_from('<I', payload, TTYP_HEADER - 4)[0]
        if kind == 2:
            self.note(f'TTYP{self.port} pid {pid:#x} exited')
            return
        if kind != 0 or not self.log:
            return
        text = payload[TTYP_HEADER:TTYP_HEADER + length].decode('utf-8', 'replace')
        out = []
        for ch in text:
            if self.line_start:
                out.append(f'{time.monotonic():.3f} [TTYP{self.port} {pid:#x}] ')
            out.append(ch)
            self.line_start = ch == '\n'
        self.log.write(''.join(out))
        self.log.flush()

    def close(self):
        pass


PIPE_FRAME = struct.Struct('<I')


class PipeServer:
    """A protocol relayed to a control-socket client ("pipe PROTOCOL").

    The client and this host exchange frames of a u32 length and a DECI4p payload (the
    packet after its 16-byte header). Payloads the client sends go to the Vita on the
    protocol; payloads the Vita sends on it go to the client. profile/vita_prof.py uses it
    for DTRACEP.
    """

    def __init__(self, protocol, send, note):
        self.protocol = protocol
        self.send = send
        self.note = note
        self.client = None
        self.buffer = bytearray()

    def attach(self, client):
        self.client = client
        self.buffer.clear()

    def detach(self):
        self.client = None

    def from_client(self, data):
        self.buffer += data
        while len(self.buffer) >= PIPE_FRAME.size:
            size = PIPE_FRAME.unpack_from(self.buffer)[0]
            if len(self.buffer) < PIPE_FRAME.size + size:
                return
            self.send(bytes(self.buffer[PIPE_FRAME.size:PIPE_FRAME.size + size]))
            del self.buffer[:PIPE_FRAME.size + size]

    def receive(self, payload):
        if self.client is None:
            self.note(f'pipe {self.protocol:#x}: no client for {len(payload)} bytes')
            return
        try:
            self.client.sendall(PIPE_FRAME.pack(len(payload)) + payload)
        except OSError:
            self.detach()

    def close(self):
        pass


class TargetManager:
    """The PC's end of one DECI4p link: the DCMP host side and the protocol servers.

    It connects the Vita with DCMP 0/0 when the link opens, and again when a Vita
    manager first announces a protocol or reports itself ready, because a Vita that
    starts after the link opened gets no 0/0 from the CP relay.
    A repeated 0/0 changes nothing on the Vita.  Every protocol this host serves is
    opened with 0/4 as the Vita announces it.
    """

    def __init__(self, stream, args, vita_node):
        self.stream = stream
        self.vita_node = vita_node
        self.vita_managers = set()
        self.disconnecting_units = set()
        self.wait_for_ready = getattr(args, 'wait_for_ready', False)
        self.ctrlp = CtrlpClient(self.sender(PROTOCOL_CTRLP), stream.note)
        self.loadp = LoadpClient(self.sender(PROTOCOL_LOADP), stream.note)
        self.dbgp = DbgpClient(self.sender(PROTOCOL_DBGP), stream.note)
        self.servers = {
            PROTOCOL_DRFP: DrfpServer(args.host0, self.sender(PROTOCOL_DRFP), stream.note),
            PROTOCOL_CTRLP: self.ctrlp,
            PROTOCOL_LOADP: self.loadp,
            PROTOCOL_DBGP: self.dbgp,
        }
        tty_log = getattr(args, 'tty_log', None)
        for port in range(TTYP_PORTS):
            self.servers[PROTOCOL_TTYP + port] = TtyServer(port, tty_log, stream.note)
        # Protocols the Vita announced, with their last 2/1 status.
        self.announced = {}
        self.release_at = None
        # --launch: asked once, LAUNCH_AFTER seconds after LOADP opens.
        self.launch = list(getattr(args, 'launch', None) or [])
        self.launch_after = getattr(args, 'launch_after', 0.0)
        self.launch_at = None
        # The connect is repeated while DfMgr sends nothing at all (connect_due).
        self.answered = False
        self.connect_at = None

    def next_timeout(self):
        """Seconds until a timed press has to be released or --launch is due, or None."""
        due = [at for at in (self.release_at, self.launch_at, self.connect_due()) if at is not None]
        if not due:
            return None
        return max(0.0, min(due) - time.monotonic())

    def connect_due(self):
        return None if self.answered or self.connect_at is None else self.connect_at + CONNECT_RETRY

    def run_timers(self):
        due = self.connect_due()
        if due is not None and time.monotonic() >= due:
            self.stream.note(f'DCMP: no answer {CONNECT_RETRY:g} s after the connect, connecting again')
            self.connect()
        if self.release_at is not None and time.monotonic() >= self.release_at:
            self.release_at = None
            self.ctrlp.set_pad(0)
        if self.launch_at is not None and time.monotonic() >= self.launch_at:
            self.launch_at = None
            self.loadp.launch(self.launch[0], self.launch[1:])
            self.launch = []

    def command(self, text):
        """One line from the control socket; returns the line to answer with."""
        word = text.split()
        if not word or word[0].startswith('#'):
            return ''
        try:
            if word[0] == 'echo' and len(word) == 2:
                challenge = bytes.fromhex(word[1])
                if not 1 <= len(challenge) <= 32:
                    raise ValueError('echo requires 1..32 bytes in hexadecimal')
                self.dcmp(1, 0, struct.pack('<HH', 0, 0) + challenge)
                return f'ok echo {challenge.hex()}; the reply is in the packet log'
            if word[0] == 'buttons' and len(word) == 2:
                self.release_at = None
                self.ctrlp.set_pad(parse_buttons(word[1]))
                return f'ok buttons {self.ctrlp.buttons:#x}'
            if word[0] == 'press' and len(word) in (2, 3):
                # The Vita drops the emulation by itself after about 60 seconds.
                seconds = float(word[2]) if len(word) == 3 else 0.5
                if not 0 < seconds <= 60:
                    raise ValueError('SECONDS must be above 0 and at most 60')
                self.ctrlp.set_pad(parse_buttons(word[1]))
                self.release_at = time.monotonic() + seconds
                return f'ok press {self.ctrlp.buttons:#x} for {seconds:g} s'
            if word[0] in ('pad', 'playpad') and len(word) == (6 if word[0] == 'pad' else 7):
                # Buttons and both sticks; playpad drives them through a playback session.
                playback = word[0] == 'playpad'
                port = int(word[1], 0) if playback else 0
                if not 0 <= port <= 4:
                    raise ValueError('PORT must be in 0..4')
                start = 2 if playback else 1
                axes = [int(v, 0) for v in word[start + 1:]]
                if any(not 0 <= v <= 0xFF for v in axes):
                    raise ValueError('axes must be in 0..255 (128: left alone)')
                self.release_at = None
                self.ctrlp.axes = axes
                if playback:
                    self.ctrlp.play_pad(parse_buttons(word[start]), port)
                    return f'ok playpad port {port} {self.ctrlp.play_buttons:#x} axes {axes}'
                self.ctrlp.set_pad(parse_buttons(word[start]))
                return f'ok pad {self.ctrlp.buttons:#x} axes {axes}'
            if word[0] == 'release' and len(word) == 1:
                self.release_at = None
                self.ctrlp.axes = [CTRLP_ANALOG_CENTRE] * 4
                self.ctrlp.set_pad(0)
                return 'ok release'
            if word[0] == 'playpress' and len(word) == 2:
                self.ctrlp.play_pad(parse_buttons(word[1]))
                return f'ok playpress {self.ctrlp.play_buttons:#x}'
            if word[0] == 'playboth' and len(word) == 4:
                x, y = int(word[2], 0), int(word[3], 0)
                if not 0 <= x <= CTRLP_PANEL_MAX_X // 2 or not 0 <= y <= CTRLP_PANEL_MAX_Y // 2:
                    raise ValueError(f'X must be in 0..{CTRLP_PANEL_MAX_X // 2} and Y in '
                                     f'0..{CTRLP_PANEL_MAX_Y // 2}')
                self.ctrlp.play_both(parse_buttons(word[1]),
                                     [(0, CTRLP_TOUCH_FORCE, x * 2, y * 2)])
                return f'ok playboth {self.ctrlp.play_buttons:#x} at {x},{y}'
            if word[0] == 'playstop' and len(word) == 1:
                self.ctrlp.play_stop()
                return 'ok playstop'
            if word[0] == 'touch' and len(word) in (3, 4):
                # Screen coordinates; the panel grid is exactly twice the screen.
                x, y = int(word[1], 0), int(word[2], 0)
                force = int(word[3], 0) if len(word) == 4 else CTRLP_TOUCH_FORCE
                if not 0 <= x <= CTRLP_PANEL_MAX_X // 2 or not 0 <= y <= CTRLP_PANEL_MAX_Y // 2:
                    raise ValueError(f'X must be in 0..{CTRLP_PANEL_MAX_X // 2} and Y in '
                                     f'0..{CTRLP_PANEL_MAX_Y // 2}')
                if not 0 < force <= 0xFF:
                    raise ValueError('FORCE must be in 1..255')
                self.ctrlp.touch([(0, force, x * 2, y * 2)])
                return f'ok touch {x} {y} force {force}'
            if word[0] == 'untouch' and len(word) == 1:
                self.ctrlp.untouch()
                return 'ok untouch'
            if word[0] == 'record' and len(word) in (1, 2):
                channels = int(word[1], 0) if len(word) == 2 else CTRLP_CHANNEL_TOUCH
                if not 0 < channels <= 3:
                    raise ValueError('CHANNELS must be 1 (pad), 2 (touch) or 3 (both)')
                self.ctrlp.record_start(channels)
                return f'ok record channels {channels}'
            if word[0] == 'recordstop' and len(word) == 1:
                self.ctrlp.record_stop()
                return 'ok recordstop'
            if word[0] == 'panelinfo' and len(word) in (1, 2):
                panel = int(word[1], 0) if len(word) == 2 else 0
                if panel not in (0, 1):
                    raise ValueError('PANEL must be 0 or 1')
                self.ctrlp.panel_info(panel)
                return f'ok panelinfo {panel}; the reply is in the packet log'
            if word[0] in ('launch', 'spawn') and len(word) >= 2:
                # launch goes through SceAppMgr, spawn creates a bare process; a
                # title ID alone launches the installed title.
                self.loadp.launch(word[1], word[2:], appmgr=word[0] == 'launch')
                return (f'ok {word[0]} {word[1]}; the reply is in the packet log'
                        + ('' if self.loadp.open else ', once the Vita opens LOADP'))
            if word[0] == 'power' and ((len(word) == 2 and word[1] in POWER_WORDS)
                                       or (len(word) == 4 and word[1] == 'copy')
                                       or (len(word) == 3 and word[1] == 'list')
                                       or (len(word) in (4, 5) and word[1] in ('hwbp', 'hwwp'))):
                # A retail Vita has no CP to cut power: retail-cp reads TTYP7's input and asks
                # Syscon (retail-cp/words.c). "copy SRC DST" moves a file
                # over this link (host0: is DRFP), "list DIR" lists a directory, and "hwbp" and
                # "hwwp PID ADDRESS [CONTROL]" set a process's hardware breakpoint and watchpoint.
                text = ' '.join(word[1:])
                self.sender(PROTOCOL_TTYP + POWER_TTYP)(tty_input(text + '\n'))
                return f'ok power {text}; the result is on the kernel console'
            if word[0] == 'kill' and len(word) == 2:
                self.loadp.kill(word[1])
                return f'ok kill {word[1]}; the reply is in the packet log'
            if word[0] == 'pdump' and len(word) in (2, 3):
                # A stopped (crashed) process's core file, to host0:, as psp2ctrl pdump.
                if len(word) == 3 and word[2] not in DBGP_LEVELS:
                    raise ValueError('LEVEL must be full or mini')
                self.dbgp.pdump(int(word[1], 0), word[2] if len(word) == 3 else None)
                return f'ok pdump {word[1]}; "pdumpstatus" tells when the file is written'
            if word[0] == 'pdumpstatus' and len(word) == 1:
                return f'ok {"busy" if self.dbgp.job else "idle"} last {self.dbgp.last}'
            module_commands = {'moduleload': 0x10, 'modulestart': 0x12,
                               'modulestop': 0x14, 'moduleunload': 0x16}
            if word[0] in module_commands and len(word) == 3:
                payload = loadp_module(module_commands[word[0]], int(word[1], 0), word[2])
                self.loadp.request(payload, ' '.join(word))
                return f'ok {word[0]}; the reply is in the packet log'
            if word[0] == 'connect' and len(word) == 1:
                # DfMgr answers a 0/0 with a 2/1 for every protocol it has
                # registered, so this picks up ones registered after the first.
                self.dcmp(0, 0)
                return 'ok connect; the announcements are in the packet log'
            if word[0] == 'launchstatus' and len(word) == 1:
                return (f'ok loadp {"open" if self.loadp.open else "closed"} '
                        f'queued {len(self.loadp.queue)} last {self.loadp.last}')
            if word[0] == 'status' and len(word) == 1:
                contacts = ' '.join(f'{x // 2},{y // 2}'
                                    for _, _, x, y in self.ctrlp.contacts) or 'none'
                return (f'ok buttons {self.ctrlp.buttons:#x} '
                        f'touch-session {"open" if self.ctrlp.touch_open else "closed"} '
                        f'pad-playback {"open" if self.ctrlp.play_open else "closed"} '
                        f'contacts {contacts}')
        except ValueError as error:
            return f'error {error}'
        return ('error commands: buttons BUTTONS | press BUTTONS [SECONDS] | release | '
                'pad BUTTONS LX LY RX RY | playpad PORT BUTTONS LX LY RX RY | '
                'playpress BUTTONS | playstop | touch X Y [FORCE] | untouch | status | '
                'launch PATH_OR_TITLEID [ARG...] | spawn PATH [ARG...] | connect | echo HEX | '
                'kill PID_OR_TITLEID | launchstatus | pdump PID [full|mini] | pdumpstatus | '
                'moduleload PID PATH | '
                'modulestart PID ID | modulestop PID ID | moduleunload PID ID | '
                'pipe PROTOCOL (the connection then carries binary frames)')

    def pipe(self, protocol, client):
        """Relays PROTOCOL to a control client, opening it on the Vita (0/4) if needed."""
        server = self.servers.get(protocol)
        if server is None:
            server = self.servers[protocol] = PipeServer(protocol, self.sender(protocol),
                                                         self.stream.note)
        if not isinstance(server, PipeServer):
            raise ValueError(f'protocol {protocol:#x} is served by this host')
        status = self.announced.get(protocol)
        if status is None:
            raise ValueError(f'the Vita has not announced protocol {protocol:#x}')
        server.attach(client)
        if not status & 2:
            # A 0/4 is never acknowledged on the wire, so the announced status keeps saying
            # closed: remember the open, or every later pipe re-opens the protocol. A second
            # 0/4 for DTRACEP, right before the next session's first packet, hangs a real
            # PCH-2000.
            self.dcmp(0, 4, struct.pack('<I', protocol))
            self.announced[protocol] = status | 2
        return server

    def sender(self, protocol):
        return lambda payload: self.stream.send(NODE_PC, self.vita_node, protocol, payload)

    def dcmp(self, kind, code, body=b''):
        self.stream.send(NODE_PC, self.vita_node, PROTOCOL_DCMP,
                         struct.pack('<BBH', kind, code, 0) + body)

    def start(self):
        """Connects: the Vita answers with a 2/1 status for every registered protocol."""
        if self.wait_for_ready:
            self.stream.note('waiting for a genuine manager ready/status announcement')
            return
        self.connect()

    def connect(self):
        """Disconnect, then connect: DfMgr replays a 2/1 for every registered protocol.

        Early in a boot nothing is registered yet and the replay is empty; each protocol sends its
        2/1 when it registers. connect_due repeats the pair only while the Vita sends nothing at
        all: a 0/1 makes DfMgr tell every client it disconnected, and ttyp drops a port's
        pending input then. (A link that stayed silent after the PC's first transfers was
        dbgusb's lost wakeup, fixed in retail-cp, dbgusb_wake_pending.)
        """
        self.vita_managers.add(self.vita_node)
        self.answered = False
        self.connect_at = time.monotonic()
        self.dcmp(0, 1)
        self.dcmp(0, 0)

    def receive(self, src, dst, protocol, reserved, payload):
        if protocol == PROTOCOL_DCMP:
            self.receive_dcmp(src, payload)
            return
        server = self.servers.get(protocol)
        if server is None:
            self.stream.note(f'no server for protocol {protocol:#x} from {src:#06x}')
            return
        server.receive(payload)

    def receive_dcmp(self, src, payload):
        self.handle_dcmp(src, payload)
        # After the handling: a 0x0F/1 that answers this host's own connect must not connect again.
        if len(payload) >= 4 and payload[0] == 2:
            self.answered = True

    def handle_dcmp(self, src, payload):
        if len(payload) < 4:
            return
        kind, code = payload[0], payload[1]
        if (kind, code) == (2, 1) and len(payload) >= 0x18:
            protocol, version, limit, node = struct.unpack_from('<IIIH', payload, 0x04)
            status = payload[0x14]
            self.announced[protocol] = status
            self.stream.note(f'DCMP {src:#06x} protocol {protocol:#x} version {version:#x} '
                             f'limit {limit:#x} node {node:#06x} status {status:#x}')
            if src >= NODE_VITA_SDIO and src not in self.vita_managers:
                self.vita_managers.add(src)
                self.dcmp(0, 0)
            # Registered and not yet open: open the protocols this host serves.
            # The Vita sends nothing back for an open.
            if protocol in self.servers and status & 1 and not status & 2:
                self.dcmp(0, 4, struct.pack('<I', protocol))
            if protocol == PROTOCOL_LOADP and status & 1:
                # Open now either way; the Vita confirms no 0/4.
                self.loadp.opened()
                if self.launch and self.launch_at is None:
                    self.launch_at = time.monotonic() + self.launch_after
            elif protocol == PROTOCOL_LOADP:
                self.loadp.open = False
        elif (kind, code) == (2, 2) and len(payload) >= 0x0C:
            protocol, alias = struct.unpack_from('<II', payload, 0x04)
            self.stream.note(f'DCMP {src:#06x} protocol {protocol:#x} alias {alias:#x}')
        elif (kind, code) == (2, 4) and len(payload) >= 0x08:
            subject, state, _, unit = payload[4:8]
            self.stream.note(f'DCMP {src:#06x} status subject {subject:#x} state {state:#x} '
                             f'unit {unit}')
            if (subject, state) in ((0x0F, 1), (0x0E, 1)):
                # 0x0F/1: DfMgr started with its transports up; 0x0E/1: resume
                # sysevent 0x100000.  Either way the temporary
                # disconnect is over and DfMgr's 0x100002 handler waits, 100
                # retries (22 s) long, for every unit that was connected at the
                # suspend to be connected again by a 0/0.  The resume status
                # names unit 0 only, so forget every unit: the next suspend's
                # 0x8E/0 for unit 1 needs its 0/6 again or DfMgr answers busy to
                # ScePower forever (2026-09-22).
                self.disconnecting_units.clear()
                if (subject, state) == (0x0E, 1):
                    # The resume waits for a plain 0/0 (no 0/1 first).
                    self.dcmp(0, 0)
                elif self.answered:
                    # DfMgr's link came up again under a connected host: connect afresh.
                    self.connect()
                # else it is the answer to the connect under way.
            elif subject in (0x8E, 0x8F) and state == 0:
                # Sony Target Manager performs a temporary target disconnect here. On the
                # direct Vita USB link 0/1 or 0/3 goes straight to DfMgr. Across the CP link,
                # its PC-only 0/6 command asks genuine dfcpm to send that disconnect to the
                # selected SDIO unit, which lets the matching suspend callback finish.
                if unit not in self.disconnecting_units:
                    self.disconnecting_units.add(unit)
                    disconnect_kind = 1 if subject == 0x8E else 3
                    if src == NODE_CP:
                        self.dcmp(0, 6, struct.pack('<BBH', disconnect_kind, unit, 0))
                    else:
                        self.dcmp(0, disconnect_kind)
        elif kind == 3 and len(payload) >= 0x14:
            _, _, _, protocol, _ = HEADER.unpack_from(payload, 0x04)
            reason = {2: 'no such protocol', 3: 'receiver overflow'}.get(code, f'code {code}')
            self.stream.note(f'DCMP {src:#06x} {reason}: protocol {protocol:#x}')

    def close(self):
        for server in self.servers.values():
            server.close()


USB_VENDOR = 0x054C
USB_PRODUCT = 0x04CD
CP_USB_PRODUCT = 0x0432


class UsbLink:
    """The PC's end of the Vita's USB cable, through this machine's USB stack.

    An ordinary libusb program bound to the 054C:04CD (or the CP's 054C:0432);
    the DECI4p stream is that device's bulk endpoint pair.

    It stands in for a socket so serve_link() can poll it: a reader thread owns
    the IN endpoint, because libusb offers no descriptor to select on, and
    forwards what it reads to a socketpair.  Reading one packet at a time keeps
    a transfer that does not end on a short packet from being lost to a timeout.
    """

    def __init__(self, timeout=1000, product=USB_PRODUCT):
        import usb.core
        import usb.util

        self.timeout = timeout
        device = usb.core.find(idVendor=USB_VENDOR, idProduct=product)
        if device is None:
            raise RuntimeError(
                f'no {USB_VENDOR:04x}:{product:04x} on this machine')
        # DECI4p is the vendor interface: on retail other plugins' USB functions can share the
        # device ahead of it (udcd_uvc's video interfaces), and their kernel drivers stay bound.
        configuration = device.get_active_configuration()
        interface = (usb.util.find_descriptor(configuration, bInterfaceClass=0xff) or
                     configuration[(0, 0)])
        if device.is_kernel_driver_active(interface.bInterfaceNumber):
            device.detach_kernel_driver(interface.bInterfaceNumber)

        def endpoint(direction):
            return usb.util.find_descriptor(interface, custom_match=lambda e: (
                usb.util.endpoint_direction(e.bEndpointAddress) == direction and
                usb.util.endpoint_type(e.bmAttributes) == usb.util.ENDPOINT_TYPE_BULK))

        self.device = device
        self.product = product
        self.reader_endpoint = endpoint(usb.util.ENDPOINT_IN)
        self.writer_endpoint = endpoint(usb.util.ENDPOINT_OUT)
        if self.reader_endpoint is None or self.writer_endpoint is None:
            raise RuntimeError('the device has no bulk endpoint pair')
        self.packet = self.writer_endpoint.wMaxPacketSize
        self.host, self.worker = socket.socketpair()
        self.stopping = threading.Event()
        self.thread = threading.Thread(target=self.read_endpoint, daemon=True)
        self.thread.start()

    def describe(self):
        return (f'attached to {USB_VENDOR:04x}:{self.product:04x} on bus {self.device.bus} '
                f'device {self.device.address}, bulk IN '
                f'{self.reader_endpoint.bEndpointAddress:#04x} OUT '
                f'{self.writer_endpoint.bEndpointAddress:#04x}, {self.packet}-byte packets')

    def fileno(self):
        return self.host.fileno()

    def recv(self, size):
        return self.host.recv(size)

    def sendall(self, data):
        import usb.core

        try:
            self.writer_endpoint.write(data, self.timeout)
            # SceDbgUsb ends an OUT transfer on a short packet, so a packet-sized
            # write needs a zero-length one to say the transfer is over.
            if len(data) % self.packet == 0:
                self.writer_endpoint.write(b'', self.timeout)
        except usb.core.USBTimeoutError:
            # dbgusb takes no OUT transfer while one of its IN transfers waits for a PC that
            # is gone (a host killed mid-link): the link stays stuck,
            # whatever is sent. A port reset restarts the device's endpoints; the next host
            # connects as after a replug.
            self.device.reset()
            raise RuntimeError('the Vita took no USB write: its port was reset, start the host again')

    def read_endpoint(self):
        import usb.core

        while not self.stopping.is_set():
            try:
                data = self.reader_endpoint.read(self.packet, self.timeout)
            except usb.core.USBTimeoutError:
                continue
            except usb.core.USBError as error:
                print(f'USB read: {error}', file=sys.stderr, flush=True)
                break
            try:
                if data:
                    self.worker.sendall(bytes(data))
            except OSError:
                break
        self.worker.close()

    def close(self):
        self.stopping.set()
        self.thread.join(timeout=2 * self.timeout / 1000)
        self.host.close()


def serve_link(sock, control, stream, manager):
    """Runs one DECI4p link, taking input commands from the control socket meanwhile."""
    clients = []
    pipes = {}      # control client -> PipeServer, once it asked for "pipe PROTOCOL"
    while True:
        sources = [sock] + clients + ([control] if control is not None else [])
        readable, _, _ = select.select(sources, [], [], manager.next_timeout())
        manager.run_timers()
        if control is not None and control in readable:
            readable.remove(control)
            client, _ = control.accept()
            clients.append(client)
        if sock in readable:
            readable.remove(sock)
            data = sock.recv(0x10000)
            if not data:
                return
            for packet in stream.packets(data):
                manager.receive(*packet)
        for client in readable:
            data = client.recv(0x10000)
            if not data:
                clients.remove(client)
                if client in pipes:
                    pipes.pop(client).detach()
                client.close()
                continue
            if client in pipes:
                pipes[client].from_client(data)
                continue
            head, newline, rest = data.partition(b'\n')
            word = head.split()
            if newline and len(word) == 2 and word[0] == b'pipe':
                # The rest of the connection is binary frames (PipeServer).
                try:
                    pipes[client] = manager.pipe(int(word[1], 0), client)
                    reply = f'ok pipe {int(word[1], 0):#x}'
                except ValueError as error:
                    reply = f'error {error}'
                stream.note(f'control: pipe {word[1].decode()} -> {reply}')
                client.sendall((reply + '\n').encode())
                if client in pipes and rest:
                    pipes[client].from_client(rest)
                continue
            for line in data.decode('utf-8', 'replace').splitlines():
                reply = manager.command(line)
                if reply:
                    stream.note(f'control: {line.strip()} -> {reply}')
                    try:
                        client.sendall((reply + '\n').encode())
                    except OSError:
                        pass


def listener_socket(path, backlog):
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(str(path))
    sock.listen(backlog)
    return sock


def run_link(link, control, args, log, opened):
    stream = Deci4pStream(link, log)
    manager = TargetManager(stream, args, args.vita_node)
    stream.note(opened)
    manager.start()
    serve_link(link, control, stream, manager)
    manager.close()
    stream.note('disconnected')


def serve(args):
    args.log_dir.mkdir(parents=True, exist_ok=True)
    control = listener_socket(args.control, 4) if args.control else None
    with open(args.log_dir / args.log_name, 'w') as log, \
            open(args.log_dir / args.log_name.replace('deci4p', 'tty'), 'w') as tty_log:
        args.tty_log = tty_log
        link = UsbLink(product=CP_USB_PRODUCT if args.cp_usb else USB_PRODUCT)
        print(link.describe(), flush=True)
        try:
            run_link(link, control, args, log, link.describe())
        finally:
            link.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--usb', action='store_true',
                        help=f'drive the Vita\'s USB port, {USB_VENDOR:04x}:{USB_PRODUCT:04x}')
    parser.add_argument('--cp-usb', action='store_true',
                        help='drive the DevKit mini-USB 054c:0432 through its CP board')
    parser.add_argument('--log-dir', type=Path, default=Path('.'),
                        help='directory for the packet log')
    parser.add_argument('--log-name', default='deci4p.log',
                        help='file name of the packet log (default deci4p.log)')
    parser.add_argument('--host0', type=Path, required=True,
                        help='directory served as host0:')
    parser.add_argument('--wait-for-ready', action='store_true',
                        help='do not send startup packets before a genuine manager announcement; '
                             'needed when retail DbgUsb configures before DfMgr binds')
    parser.add_argument('--control', type=Path,
                        help='Unix socket to listen on for one-line input commands, which '
                             'become CTRLP packets (see devkit/psp2_input.py)')
    parser.add_argument('--launch', nargs='+', metavar=('PATH_OR_TITLEID', 'ARG'),
                        help='ask LOADP to run this once it opens: a SELF path such as '
                             'host0:/app/eboot.bin with its arguments, or an installed '
                             'title ID such as VSDK00007')
    parser.add_argument('--launch-after', type=float, default=0.0, metavar='SECONDS',
                        help='wait this long after LOADP opens before --launch (default 0); '
                             'LOADP registers long before SceShell is up')
    parser.add_argument('--vita-node', type=lambda text: int(text, 0),
                        help='destination node for packets to the Vita (default 0xA000 with '
                             '--cp-usb, otherwise 0xA100)')
    args = parser.parse_args()
    if args.usb == args.cp_usb:
        parser.error('give one of --usb and --cp-usb')
    if args.vita_node is None:
        args.vita_node = NODE_VITA_SDIO if args.cp_usb else NODE_VITA_USB
    if not args.host0.is_dir():
        parser.error(f'--host0 {args.host0} is not a directory')
    try:
        serve(args)
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == '__main__':
    sys.exit(main())
