#!/usr/bin/env python3
"""Capture a VitaOS framebuffer through its DECI4p VCP service, as a PNG (and a .raw copy).

Two ways to reach VCP: open a DECI4p USB link of its own (--transport vita: the Vita's USB
port, cp: the CP board's mini-USB), or, while deci4p_host.py serves the Vita's USB link
(a session), ask its control socket for a pipe to VCP (--socket).

    devkit/vcp_capture.py screen.png
    devkit/vcp_capture.py --socket RUN/deci4p.sock screen.png
"""

import argparse
import socket
import struct
import sys
import time
from pathlib import Path

from devkit_console import HEADER, HEADER_MAGIC, UsbLink, dcmp, packets, write_png

PROTOCOL_VCP = 0x2B000
NODE_PC = 0x4000
TRANSPORTS = {'vita': (0x04CD, 0xA100), 'cp': (0x0432, 0xA000)}
REPLY = {0x10: 0x11, 0x14: 0x15}


def check(op, data):
    if len(data) < 8 or struct.unpack_from('<I', data)[0] != REPLY[op]:
        raise ValueError(f'unexpected VCP reply: {data[:32].hex()}')
    status = struct.unpack_from('<I', data, 4)[0]
    if status:
        raise RuntimeError(f'VCP {op:#x} failed: {status:#x}')
    return data


class UsbVcp:
    """VCP over a DECI4p USB link of its own."""

    def __init__(self, transport, timeout):
        product, self.node = TRANSPORTS[transport]
        self.link = UsbLink(0x054C, product)
        if not self.link.ok:
            raise RuntimeError(f'USB device 054c:{product:04x} is not attached (or is in use)')
        self.timeout = timeout
        self.buffer = bytearray()
        self.link.write(dcmp(self.node, 0, 0))
        self.link.write(dcmp(self.node, 0, 4, struct.pack('<I', PROTOCOL_VCP)))

    def request(self, op, first=0, second=0):
        payload = struct.pack('<III', op, first, second)
        packet = HEADER.pack(HEADER_MAGIC << 24 | (HEADER.size + len(payload)),
                             NODE_PC, self.node, PROTOCOL_VCP, 0) + payload
        self.link.write(packet)
        end = time.monotonic() + self.timeout
        while time.monotonic() < end:
            self.buffer.extend(self.link.read(min(0.5, end - time.monotonic())))
            for source, _, protocol, data in packets(self.buffer):
                if protocol == PROTOCOL_VCP and source == self.node:
                    return check(op, data)
        raise TimeoutError(f'VCP {op:#x} did not answer over this DECI interface')

    def close(self):
        try:
            self.link.write(dcmp(self.node, 0, 5, struct.pack('<I', PROTOCOL_VCP)))
            self.link.write(dcmp(self.node, 0, 1))
        finally:
            self.link.close()


class SocketVcp:
    """VCP through deci4p_host.py's control socket: length-prefixed frames over a pipe."""

    def __init__(self, path, timeout):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        self.sock.connect(str(path))
        self.sock.sendall(b'pipe 0x2b000\n')
        response = b''
        while not response.endswith(b'\n'):
            response += self.receive(1)
        if not response.startswith(b'ok'):
            raise RuntimeError(response.decode().strip())

    def receive(self, size):
        data = bytearray()
        while len(data) < size:
            part = self.sock.recv(size - len(data))
            if not part:
                raise RuntimeError('deci4p_host disconnected')
            data.extend(part)
        return bytes(data)

    def request(self, op, first=0, second=0):
        payload = struct.pack('<III', op, first, second)
        self.sock.sendall(struct.pack('<I', len(payload)) + payload)
        size = struct.unpack('<I', self.receive(4))[0]
        if not 8 <= size <= 1280 * 8 * 4 + 28:
            raise RuntimeError(f'invalid VCP response size {size}')
        return check(op, self.receive(size))

    def close(self):
        self.sock.close()


def frame(vcp, selectors):
    for selector in selectors:
        try:
            info = vcp.request(0x10, 1 | selector << 16)
            break
        except RuntimeError:
            if selector == selectors[-1]:
                raise
    if len(info) != 28:
        raise ValueError(f'VCP capture reply has {len(info)} bytes, expected 28')
    width, height = struct.unpack_from('<II', info, 16)
    if not 0 < width <= 1280 or not 0 < height <= 736:
        raise ValueError(f'invalid VCP dimensions {width}x{height}')
    pixels = bytearray(width * height * 4)
    for row in range(0, height, 8):
        count = min(8, height - row)
        data = vcp.request(0x14, row, count)
        if len(data) != 12 + count * width * 4 or struct.unpack_from('<I', data, 8)[0] != count:
            raise ValueError(f'VCP row {row} returned {len(data)} bytes')
        pixels[row * width * 4:(row + count) * width * 4] = data[12:]
    return selector, width, height, pixels


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('output', type=Path, help='PNG output; a .raw copy is kept beside it')
    parser.add_argument('--transport', choices=TRANSPORTS, default='vita',
                        help='Vita debug USB or CP mini-USB DECI interface')
    parser.add_argument('--socket', type=Path, help="deci4p_host.py's --control socket instead")
    parser.add_argument('--selector', type=lambda value: int(value, 0),
                        help='VCP display selector, head << 1 | slot: 0 an app\'s frame on the '
                             'OLED, 1 the shell\'s (default: 0, then 1 if no app has one)')
    parser.add_argument('--timeout', type=float, default=10.0)
    args = parser.parse_args()
    if args.selector not in (None, *range(4)) or args.timeout <= 0:
        parser.error('selector must be 0..3 and timeout must be positive')
    try:
        vcp = (SocketVcp(args.socket, args.timeout) if args.socket
               else UsbVcp(args.transport, args.timeout))
        try:
            selectors = (0, 1) if args.selector is None else (args.selector,)
            selector, width, height, pixels = frame(vcp, selectors)
        finally:
            vcp.close()
    except (OSError, TimeoutError, RuntimeError, ValueError) as error:
        sys.exit(str(error))
    args.output.with_suffix('.raw').write_bytes(pixels)
    write_png(args.output, width, height, width * 4, 'AB24', pixels)
    print(f'{width}x{height} (selector {selector}) captured to {args.output} and '
          f'{args.output.with_suffix(".raw")}')


if __name__ == '__main__':
    main()
