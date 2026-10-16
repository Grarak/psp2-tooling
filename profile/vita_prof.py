#!/usr/bin/env python3
"""Sample a Vita process's program counters through the DevKit's DTrace (DTRACEP).

The DevKit firmware carries Sony's DTrace port (os0/kd/deci4p_dtracep.elf): the kernel half of
DTrace, whose ioctls a PC reaches over DECI4p protocols 0x29000-0x29003.
This tool is a minimal DTrace consumer. It enables one probe, profile-HZ, which fires on every
CPU HZ times a second with the interrupted kernel PC (arg0) and user PC (arg1), records the
timestamp, both PCs, the thread and the process, and reads the per-CPU buffers back.
Nothing of ours runs on the Vita, so any process can be sampled.

It needs devkit/deci4p_host.py running with --control SOCKET on the Vita's USB link; the
profiler asks it for a binary pipe to DTRACEP0 ("pipe 0x29000").

    profile/vita_prof.py --socket RUN/deci4p.sock --deci-log RUN/deci4p.log \\
        --elf app.elf --seconds 10 --out RUN/prof

--deci-log takes the pid and the main module's text base from deci4p_host's record of the
LOADP launch; --pid and --base override them. Without a pid the probe samples every process.
The report lists the hottest functions of the user PCs inside the ELF, overall and per thread;
the raw samples are written to OUT.samples (text, one per line).
"""

import argparse
import bisect
import collections
import hashlib
import json
import re
import socket
import struct
import os
import subprocess
import sys
import time
from pathlib import Path

PROTOCOL_DTRACEP0 = 0x29000
PIPE_FRAME = struct.Struct('<I')

# DTRACEP requests (the byte at payload +0); replies are request + 1.
CMD_HELLO, CMD_OPEN, CMD_CLOSE, CMD_MORE, CMD_UPLOAD = 0, 2, 4, 6, 8
CMD_MESSAGE = 0x80
# DTRACEIOC_n travels as 0x20 + 2 * (its index among the defined ioctls 1, 2, 4..13, 15..21).
IOCTLS = [1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 15, 16, 17, 18, 19, 20, 21]
IOC_BUFSNAP, IOC_ENABLE, IOC_EPROBE, IOC_CONF, IOC_STATUS, IOC_GO, IOC_STOP = 4, 6, 8, 10, 11, 12, 13


def ioctl_cmd(n):
    return 0x20 + 2 * IOCTLS.index(n)


# sys/dtrace.h (Sony's, #pragma pack(4)).
DOF_SECT_ECBDESC, DOF_SECT_PROBEDESC, DOF_SECT_ACTDESC = 3, 4, 5
DOF_SECT_DIFOHDR, DOF_SECT_DIF, DOF_SECT_STRTAB = 6, 7, 8
DOF_SECT_OPTDESC, DOF_SECT_INTTAB = 14, 19
DOF_SECF_LOAD = 1
DOF_SECIDX_NONE = 0xFFFFFFFF
DTRACEACT_DIFEXPR, DTRACEACT_USTACK = 1, 0x101
DTRACEOPT_BUFSIZE, DTRACEOPT_BUFPOLICY, DTRACEOPT_DYNVARSIZE = 0, 1, 2
# The profile actions use no dynamic variables, but dtracep reserves the 1-MiB default for
# them; on a retail console its whole heap is 4 MiB (the DevKit's is 16).
DYNVARSIZE = 8 * 1024
DTRACEOPT_BUFPOLICY_SWITCH = 2
DIF_OP_AND, DIF_OP_MOV, DIF_OP_CMP, DIF_OP_BA, DIF_OP_BE, DIF_OP_BNE, DIF_OP_BGEU, DIF_OP_BLU = \
    3, 14, 15, 17, 18, 19, 23, 25
DIF_OP_RET, DIF_OP_SETX, DIF_OP_LDGA, DIF_OP_LDGS, DIF_OP_CALL, DIF_OP_PUSHTV, DIF_OP_FLUSHTS = \
    35, 37, 40, 41, 47, 49, 51
DIF_TYPE_CTF, CTF_K_INTEGER = 0, 1
DIF_VAR_UREGS = 2
DIF_VAR_TIMESTAMP, DIF_VAR_ARG0, DIF_VAR_PID, DIF_VAR_TID = 0x101, 0x106, 0x116, 0x117
DIF_SUBR_COPYIN, DIF_TF_BYREF = 8, 1
# Two register buffers a CPU on four CPUs come out of SceDeci4pDtracep's 16 MiB pHeap, which
# does not grow: 4 MiB buffers (32 MiB) panic the DevKit kernel a few windows later.
MAX_STACK_BYTES, MAX_REGISTER_BUFSIZE = 32768, 512 * 1024
RAW_CAPTURE_VERSION = 1
EPROBEDESC = struct.Struct('<IIQIi')         # epid, probe id, uarg, size, nrecs
RECDESC = struct.Struct('<HHIIHHQQ')         # action, pad, size, offset, alignment, format,
#                                              arg, uarg: 0x20 bytes
BUFDESC = struct.Struct('<QIIQIIQ')          # size, cpu, errors, drops, data, pad, oldest


def dif(op, r1=0, r2=0, rd=0):
    return op << 24 | r1 << 16 | r2 << 8 | rd


def dif_var(op, var, rd):
    return op << 24 | var << 8 | rd


class Dof:
    """Builds a DOF image section by section, as libdtrace's dt_dof.c lays it out."""

    def __init__(self):
        self.sections = []          # (type, align, entsize, bytes)

    def add(self, kind, align, entsize, data):
        self.sections.append((kind, align, entsize, data))
        return len(self.sections) - 1

    def difo(self, code, ints=(), byte_size=0):
        """A DIF object returning a 64-bit integer; returns its DIFOHDR section index."""
        links = [self.add(DOF_SECT_DIF, 4, 4, struct.pack(f'<{len(code)}I', *code))]
        if ints:
            links.append(self.add(DOF_SECT_INTTAB, 8, 8, struct.pack(f'<{len(ints)}Q', *ints)))
        rtype = struct.pack('<BBBBI', DIF_TYPE_CTF, CTF_K_INTEGER,
                            DIF_TF_BYREF if byte_size else 0, 0, byte_size or 8)
        return self.add(DOF_SECT_DIFOHDR, 4, 0,
                        rtype + struct.pack(f'<{len(links)}I', *links))

    def image(self):
        header_size, section_size = 64, 32
        offset = header_size + section_size * len(self.sections)
        headers, body = [], bytearray()
        for kind, align, entsize, data in self.sections:
            start = offset + len(body)
            pad = (-start) % align
            body += bytes(pad)
            headers.append(struct.pack('<IIIIQQ', kind, align, DOF_SECF_LOAD, entsize,
                                       offset + len(body), len(data)))
            body += data
        body += bytes((-len(body)) % 8)
        total = offset + len(body)
        ident = bytes([0x7F, ord('D'), ord('O'), ord('F'), 1, 1, 2, 2, 8, 8]) + bytes(6)
        header = ident + struct.pack('<IIIIQQQQ', 0, header_size, section_size,
                                     len(self.sections), header_size, total, total, 0)
        return header + b''.join(headers) + bytes(body)


# What each sample records, in order (arg1 is the user PC, arg0 the kernel PC).
RECORDS = [('timestamp', DIF_VAR_TIMESTAMP), ('upc', DIF_VAR_ARG0 + 1),
           ('kpc', DIF_VAR_ARG0), ('tid', DIF_VAR_TID), ('pid', DIF_VAR_PID)]


def profile_dof(hz, pid, bufsize, stack_depth=0, registers=False, stack_bytes=0):
    if not 0 <= stack_depth <= 256:
        raise ValueError("User stack depth must be 0..256")
    if (type(stack_bytes) is not int or not 0 <= stack_bytes <= MAX_STACK_BYTES or
        stack_bytes and (stack_bytes < 16 or stack_bytes % 4)):
        raise ValueError("Stack bytes must be zero or an aligned extent of 16..32768")
    registers = registers or bool(stack_bytes)
    if registers and not 2 * stack_bytes + 512 <= bufsize <= MAX_REGISTER_BUFSIZE:
        raise ValueError("Register capture buffer must fit two snapshot extents and be at most 512 KiB")
    dof = Dof()
    name = f'profile-{hz}'.encode()
    strtab = b'\0profile\0' + name + b'\0'
    strs = dof.add(DOF_SECT_STRTAB, 1, 0, strtab)
    probes = dof.add(DOF_SECT_PROBEDESC, 4, 0,
                     struct.pack('<IIIIII', strs, 1, 0, 0, 9, 0))
    pred = DOF_SECIDX_NONE
    if pid is not None:
        # pid == PID: %r1 = pid; %r2 = PID; branch to 1 or 0.
        pred = dof.difo([
            dif_var(DIF_OP_LDGS, DIF_VAR_PID, 1),
            dif_var(DIF_OP_SETX, 0, 2),
            dif(DIF_OP_CMP, 1, 2),
            DIF_OP_BE << 24 | 6,
            dif(DIF_OP_MOV, 0, 0, 1),
            DIF_OP_BA << 24 | 7,
            dif_var(DIF_OP_SETX, 1, 1),
            dif(DIF_OP_RET, rd=1),
        ], ints=(pid, 1))
    actions = b''
    for _, var in RECORDS:
        difo = dof.difo([dif_var(DIF_OP_LDGS, var, 1), dif(DIF_OP_RET, rd=1)])
        actions += struct.pack('<IIIIQQ', difo, DOF_SECIDX_NONE, DTRACEACT_DIFEXPR, 0, 0, 0)
    if stack_depth:
        # Sony sys/dtrace.h: DTRACE_USTACK_ARG(nframes, 0), no string helper.
        # USTACK has no DIFO and records uint64 PID followed by nframes PCs.
        actions += struct.pack('<IIIIQQ', DOF_SECIDX_NONE, DOF_SECIDX_NONE,
                               DTRACEACT_USTACK, 0, stack_depth, 0)
    acts = dof.add(DOF_SECT_ACTDESC, 8, 32, actions)
    dof.add(DOF_SECT_ECBDESC, 8, 0, struct.pack('<IIIIQ', probes, pred, acts, 0, 0))
    if registers:
        # A separate ECB preserves the PC-only denominator if copyin faults.
        # Its timestamp is independent: never approximate a primary-event join.
        raw_actions = b''
        for _, var in RECORDS:
            difo = dof.difo([dif_var(DIF_OP_LDGS, var, 1), dif(DIF_OP_RET, rd=1)])
            raw_actions += struct.pack('<IIIIQQ', difo, DOF_SECIDX_NONE, DTRACEACT_DIFEXPR, 0, 0, 0)
        for register in range(16):
            difo = dof.difo([dif_var(DIF_OP_SETX, 0, 1),
                            dif(DIF_OP_LDGA, DIF_VAR_UREGS, 1, 2),
                            dif(DIF_OP_RET, rd=2)], ints=(register,))
            raw_actions += struct.pack('<IIIIQQ', difo, DOF_SECIDX_NONE, DTRACEACT_DIFEXPR, 0, 0, 0)
        if stack_bytes:
            # Sony dt_action_tracemem: DIFEXPR + BYREF flag + exact byte size.
            # copyin's tuple values occupy PUSHTV's rd field (SDK DIF format).
            difo = dof.difo([dif(DIF_OP_FLUSHTS), dif_var(DIF_OP_SETX, 0, 1),
                            dif(DIF_OP_LDGA, DIF_VAR_UREGS, 1, 2),
                            dif(DIF_OP_PUSHTV, rd=2), dif_var(DIF_OP_SETX, 1, 3),
                            dif(DIF_OP_PUSHTV, rd=3), dif_var(DIF_OP_CALL, DIF_SUBR_COPYIN, 4),
                            dif(DIF_OP_RET, rd=4)], ints=(13, stack_bytes), byte_size=stack_bytes)
            raw_actions += struct.pack('<IIIIQQ', difo, DOF_SECIDX_NONE, DTRACEACT_DIFEXPR, 0, 0, 0)
        raw_acts = dof.add(DOF_SECT_ACTDESC, 8, 32, raw_actions)
        raw_pred = register_predicate(dof, pid, stack_bytes)
        dof.add(DOF_SECT_ECBDESC, 8, 0, struct.pack('<IIIIQ', probes, raw_pred, raw_acts, 0, 0))
    dof.add(DOF_SECT_OPTDESC, 8, 16,
            struct.pack('<IIQ', DTRACEOPT_BUFSIZE, DOF_SECIDX_NONE, bufsize)
            + struct.pack('<IIQ', DTRACEOPT_BUFPOLICY, DOF_SECIDX_NONE,
                          DTRACEOPT_BUFPOLICY_SWITCH)
            + struct.pack('<IIQ', DTRACEOPT_DYNVARSIZE, DOF_SECIDX_NONE, DYNVARSIZE))
    return dof.image()


def register_predicate(dof, pid, stack_bytes):
    """Filter non-user events; validate exact PC/SP before any user copy."""
    code, ints, reject = [], [], []
    def constant(value, rd):
        index = len(ints)
        ints.append(value)
        code.append(dif_var(DIF_OP_SETX, index, rd))
    def branch(op):
        reject.append(len(code))
        code.append(op << 24)
    if pid is not None:
        code.append(dif_var(DIF_OP_LDGS, DIF_VAR_PID, 1))
        constant(pid, 2)
        code.append(dif(DIF_OP_CMP, 1, 2))
        branch(DIF_OP_BNE)
    code.append(dif_var(DIF_OP_LDGS, DIF_VAR_ARG0 + 1, 1))
    constant(0x40000000, 2)
    code.append(dif(DIF_OP_CMP, 1, 2))
    branch(DIF_OP_BLU)
    constant(0xffffffff, 2)
    code.append(dif(DIF_OP_CMP, 1, 2))
    branch(DIF_OP_BGEU)
    if stack_bytes:
        constant(15, 2)
        code.append(dif(DIF_OP_LDGA, DIF_VAR_UREGS, 2, 3))
        constant(0xfffffffe, 4)
        code.extend([dif(DIF_OP_AND, 1, 4, 1), dif(DIF_OP_AND, 3, 4, 3),
                     dif(DIF_OP_CMP, 1, 3)])
        branch(DIF_OP_BNE)
        constant(13, 2)
        code.append(dif(DIF_OP_LDGA, DIF_VAR_UREGS, 2, 1))
        constant(0x40000000, 2)
        code.append(dif(DIF_OP_CMP, 1, 2))
        branch(DIF_OP_BLU)
        constant(0x100000000 - stack_bytes, 2)
        code.append(dif(DIF_OP_CMP, 1, 2))
        branch(DIF_OP_BGEU)  # Native copyin rejects 32-bit address addition carry.
        constant(3, 2)
        code.extend([dif(DIF_OP_AND, 1, 2, 3), dif(DIF_OP_CMP, 3, 0)])
        branch(DIF_OP_BNE)
    constant(1, 1)
    code.append(dif(DIF_OP_RET, rd=1))
    target = len(code)
    code.extend([dif(DIF_OP_MOV, 0, rd=1), dif(DIF_OP_RET, rd=1)])
    for at in reject:
        code[at] |= target
    return dof.difo(code, ints=ints)


class DtraceError(Exception):
    pass


class Dtracep:
    """One DTRACEP port through deci4p_host's pipe."""

    def __init__(self, path, protocol=PROTOCOL_DTRACEP0, verbose=False):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(str(path))
        self.sock.sendall(f'pipe {protocol:#x}\n'.encode())
        line = b''
        while not line.endswith(b'\n'):
            chunk = self.sock.recv(1)
            if not chunk:
                raise DtraceError('deci4p_host closed the control connection')
            line += chunk
        if not line.startswith(b'ok'):
            raise DtraceError(line.decode().strip())
        self.buffer = bytearray()
        self.verbose = verbose
        self.handle = 0

    def send(self, cmd, tag, body=b''):
        payload = struct.pack('<BxxxI8x', cmd, tag) + body
        payload += bytes((-len(payload)) % 8)
        self.sock.sendall(PIPE_FRAME.pack(len(payload)) + payload)

    def receive(self, timeout):
        deadline = time.monotonic() + timeout
        while True:
            if len(self.buffer) >= PIPE_FRAME.size:
                size = PIPE_FRAME.unpack_from(self.buffer)[0]
                if len(self.buffer) >= PIPE_FRAME.size + size:
                    payload = bytes(self.buffer[4:4 + size])
                    del self.buffer[:4 + size]
                    return payload
            left = deadline - time.monotonic()
            if left <= 0:
                raise DtraceError('no reply from DTRACEP')
            self.sock.settimeout(left)
            data = self.sock.recv(0x20000)
            if not data:
                raise DtraceError('deci4p_host closed the pipe')
            self.buffer += data

    def request(self, cmd, body=b'', tag=None, timeout=10):
        self.send(cmd, self.handle if tag is None else tag, body)
        while True:
            reply = self.receive(timeout)
            if reply[0] == CMD_MESSAGE:
                length = struct.unpack_from('<I', reply, 0x14)[0]
                text = reply[0x18:0x18 + length].decode('utf-8', 'replace')
                if self.verbose:
                    print(f'dtracep message: {text}', file=sys.stderr)
                continue
            if reply[0] != (cmd + 1) & 0xFF:
                raise DtraceError(f'reply {reply[0]:#x} to request {cmd:#x}')
            return reply

    def hello(self, version=1):
        reply = self.request(CMD_HELLO, struct.pack('<I', version), tag=0)
        status, answer = struct.unpack_from('<Ii', reply, 0x10)
        if status:
            raise DtraceError(f'hello refused: {status:#x}')
        return answer

    def open(self, path='/dev/dtrace/dtrace'):
        name = path.encode() + b'\0'
        reply = self.request(CMD_OPEN, struct.pack('<II', 0, len(name)) + name, tag=0)
        handle = struct.unpack_from('<i', reply, 0x10)[0]
        if handle < 0:
            raise DtraceError(f'open {path}: {handle & 0xFFFFFFFF:#x}')
        self.handle = handle
        return handle

    def close(self):
        # dtracep's close handler (deci4p_dtracep FUN_81002924) refuses a request with no
        # body (0x40002) and closes the handle in the tag only when 4 more bytes follow.
        return struct.unpack_from('<i', self.request(CMD_CLOSE, bytes(4)), 0x10)[0]

    def ioctl(self, n, arg=b''):
        """A fixed-size ioctl: returns (rv, the argument as the kernel left it)."""
        reply = self.request(ioctl_cmd(n), arg)
        return struct.unpack_from('<i', reply, 0x10)[0], reply[0x14:0x14 + len(arg)]

    def ioctl_data(self, n, arg, echo):
        """An ioctl with trailing output: returns (rv, arg, data). BUFSNAP's reply echoes the
        argument before the data (echo), EPROBE's carries the data alone."""
        reply = self.request(ioctl_cmd(n), arg)
        rv, more, length = struct.unpack_from('<iII', reply, 0x10)
        start = 0x1C + (len(arg) if echo else 0)
        out_arg = reply[0x1C:0x1C + len(arg)] if echo else b''
        data = bytearray(reply[start:start + length])
        while more:
            reply = self.request(CMD_MORE)
            more, length = struct.unpack_from('<II', reply, 0x14)
            data += reply[0x1C:0x1C + length]
        return rv, out_arg, bytes(data)

    def check(self, what, rv):
        # The reply carries the ioctl's rv (ENABLE: the probes matched) or, when
        # dtrace_ioctl fails, its negative error.
        if rv < 0:
            raise DtraceError(f'{what}: {rv & 0xFFFFFFFF:#x}')
        return rv

    def enable(self, dof):
        if len(dof) + 0x40 > 0x10000:
            raise DtraceError(f'DOF of {len(dof)} bytes needs the upload path')
        reply = self.request(ioctl_cmd(IOC_ENABLE), struct.pack('<I', 0) + dof)
        return struct.unpack_from('<i', reply, 0x10)[0]

    def eprobe(self, epid):
        # dtepd_nrecs in is the capacity: the kernel copies at most that many records (libdtrace
        # asks once for the count, then again); the argument itself stays one record long.
        arg = EPROBEDESC.pack(epid, 0, 0, 0, 64) + bytes(RECDESC.size)
        rv, _, data = self.ioctl_data(IOC_EPROBE, arg, echo=False)
        self.check(f'EPROBE {epid}', rv)
        if len(data) < EPROBEDESC.size:
            raise DtraceError(f'EPROBE {epid}: {len(data)} bytes')
        _, probe, _, size, nrecs = EPROBEDESC.unpack_from(data)
        recs = [RECDESC.unpack_from(data, EPROBEDESC.size + i * RECDESC.size)
                for i in range(nrecs)]
        return probe, size, [(action, rsize, offset) for action, _, rsize, offset, *_ in recs]

    def bufsnap(self, cpu):
        arg = BUFDESC.pack(0, cpu, 0, 0, 0, 0, 0)
        rv, out, data = self.ioctl_data(IOC_BUFSNAP, arg, echo=True)
        if rv < 0:
            return None, 0, 0
        size, _, errors, drops, *_ = BUFDESC.unpack(out)
        return data[:size], errors, drops


def parse_records(data, layouts, byte_size=0):
    """Yields (epid, fields) for each record of a switched-out buffer."""
    offset = 0
    while offset + 4 <= len(data):
        epid = struct.unpack_from('<I', data, offset)[0]
        if epid == 0:                       # alignment padding (DTRACE_EPIDNONE)
            offset += 4
            continue
        layout = layouts.get(epid)
        if layout is None:
            raise DtraceError(f'record with unknown epid {epid} at {offset:#x}')
        size, recs = layout
        if size < 4 or offset + size > len(data):
            raise DtraceError(f'truncated record for epid {epid} at {offset:#x}')
        fields = []
        for action, rsize, roff in recs:
            if roff < 4 or rsize < 1 or roff + rsize > size:
                raise DtraceError(f'invalid record layout for epid {epid}')
            raw = data[offset + roff:offset + roff + rsize]
            if action == DTRACEACT_USTACK:
                if rsize < 16 or rsize % 8 or rsize > 257 * 8:
                    raise DtraceError('invalid USTACK record extent')
                fields.append(struct.unpack(f'<{rsize // 8}Q', raw))
            elif action == DTRACEACT_DIFEXPR and rsize <= 8:
                fields.append(int.from_bytes(raw, 'little'))
            elif action == DTRACEACT_DIFEXPR and rsize == byte_size and 8 < rsize <= MAX_STACK_BYTES:
                fields.append(bytes(raw))
            else:
                raise DtraceError(f'unsupported DTrace action {action:#x}')
        yield epid, fields
        offset += size
    if any(data[offset:]):
        raise DtraceError('nonzero partial record at end of buffer')


def user_stack(sample, raw, requested_depth):
    """Preserve verified native USTACK PCs; never fabricate a caller.

    CSTK flags: 1=depth cap reached, 2=unwind unavailable/inconsistent.
    Kernel samples have no interrupted user PC and do not get a user stack.
    Sony reports errors per CPU buffer, not a per-stack completeness status.
    """
    upc, pid = sample[2], sample[5]
    if not 0x40000000 <= upc < 0xffffffff:
        return None
    flags = 0
    if len(raw) != requested_depth + 1 or raw[0] != pid:
        return {'flags': 2, 'frames': [upc]}
    values = raw[1:]
    frames = []
    for index, pc in enumerate(values):
        if pc == 0:
            if any(values[index + 1:]):
                flags |= 2
            break
        if pc > 0xffffffff or pc == 0xffffffff or not (pc & ~1):
            flags |= 2
            break
        frames.append(pc)
    if not frames or (frames[0] & ~1) != (upc & ~1):
        return {'flags': 2, 'frames': [upc]}
    frames[0] = upc
    if len(frames) == requested_depth:
        flags |= 1
    return {'flags': flags, 'frames': frames}


def raw_context(sample, registers, stack):
    """Keep raw input; context consistency does not establish any caller."""
    if len(registers) != 16 or any(type(v) is not int or not 0 <= v <= 0xffffffff for v in registers):
        raise DtraceError('invalid ARM32 register record')
    upc, sp, pc = sample[2], registers[13], registers[15]
    if not 0x40000000 <= upc < 0xffffffff:
        return 'invalid_sampled_user_pc'
    if (pc & ~1) != (upc & ~1):
        return 'register_pc_mismatch'
    if not 0x40000000 <= sp < 0xffffffff or sp % 4:
        return 'invalid_user_stack_pointer'
    if sp + len(stack) > 0xffffffff:
        return 'stack_address_overflow'
    return None


def write_register_capture(output, raw_events, primary, stack_bytes, hz, base, elf, errors, drops, pid=None):
    """Versioned independent events plus a binary payload; never add CSTK frames."""
    output = Path(output)
    manifest = Path(f'{output}.registers.jsonl')
    binary = Path(f'{output}.stack.bin')
    snapshots = Path(f'{output}.snapshot.samples')
    payload = bytearray()
    valid = 0
    with manifest.open('w') as stream, snapshots.open('w') as samples:
        samples.write('cpu timestamp upc kpc tid pid\n')
        for index, (sample, registers, stack) in enumerate(raw_events):
            cpu, timestamp, upc, kpc, tid, pid = sample
            problem = raw_context(sample, registers, stack)
            valid += problem is None
            row = dict(schema_version=RAW_CAPTURE_VERSION, event_index=index, cpu=cpu,
                       timestamp=timestamp, upc=upc, kpc=kpc, tid=tid, pid=pid,
                       registers=list(registers), stack_address=registers[13],
                       stack_offset=len(payload), stack_size=len(stack),
                       context_error=problem, unwind_status='raw_unwound_pending')
            stream.write(json.dumps(row) + '\n')
            samples.write(' '.join(str(v) if i == 0 else f'{v:#x}' for i, v in enumerate(sample)) + '\n')
            payload.extend(stack)
    binary.write_bytes(payload)
    user_count = sum(0x40000000 <= s[2] < 0xffffffff for s in primary)
    info = dict(schema_version=RAW_CAPTURE_VERSION, source='Sony DTrace uregs + fault-checked copyin',
                method='Independent register ECB; no timestamp pairing with primary samples',
                hz=hz, requested_stack_bytes=stack_bytes, max_stack_bytes=MAX_STACK_BYTES,
                primary_samples=len(primary), primary_user_samples=user_count,
                raw_events=len(raw_events), consistent_context_events=valid,
                primary_user_minus_raw_events=user_count - len(raw_events),
                missing_event_note='Count difference only; ECB events are not paired',
                with_derived_callers=0, unwind_status='raw_unwound_pending',
                aggregate_errors=errors, aggregate_drops=drops,
                selected_pid=pid, loaded_text_base=base,
                recorded_elf_sha256=hashlib.sha256(elf.read_bytes()).hexdigest() if elf else None,
                register_manifest=manifest.name, register_manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest(),
                stack_binary=binary.name, stack_binary_size=len(payload),
                stack_binary_sha256=hashlib.sha256(payload).hexdigest(),
                snapshot_samples=snapshots.name,
                snapshot_samples_sha256=hashlib.sha256(snapshots.read_bytes()).hexdigest())
    Path(f'{output}.register-info.json').write_text(json.dumps(info, indent=2) + '\n')
    return info


def loadp_launch(log_path):
    """(pid, text base) of the last LOADP launch in a deci4p_host log.

    A launched process that starts a child and exits (an eboot that re-executes itself:
    "process created 0x80: PARENT CHILD") is followed to the child, the process that runs.
    """
    pid = base = None
    for line in Path(log_path).read_text(errors='replace').splitlines():
        m = re.search(r'LOADP reply 0x(?:01|0b) to .* result 0x0 .* pid (0x[0-9a-f]+)', line)
        if m:
            pid = int(m.group(1), 16)
        m = re.search(r'LOADP process created 0x80: (0x[0-9a-f]+) (0x[0-9a-f]+)', line)
        if m and pid is not None and int(m.group(1), 16) == pid:
            pid = int(m.group(2), 16)
        m = re.search(r'LOADP main module .* segments (.*)', line)
        if m:
            words = [int(w, 16) for w in m.group(1).replace('|', ' ').split()]
            text = [w for w in words if 0x81000000 <= w < 0xA0000000]
            base = text[0] if text else None
    return pid, base


class Symbols:
    def __init__(self, elf, nm=os.environ.get('VITASDK', '/usr/local/vitasdk') + '/bin/arm-vita-eabi-nm'):
        out = subprocess.run([nm, '-nC', '--defined-only', str(elf)], capture_output=True,
                             text=True, check=True).stdout
        self.addrs, self.names = [], []
        for line in out.splitlines():
            parts = line.split(' ', 2)
            if len(parts) == 3 and parts[1] in 'tTwW':
                self.addrs.append(int(parts[0], 16) & ~1)
                self.names.append(parts[2])
        text = subprocess.run([nm.removesuffix('nm') + 'readelf', '-lW', str(elf)],
                              capture_output=True, text=True, check=True).stdout
        load = [line.split() for line in text.splitlines() if line.strip().startswith('LOAD')]
        self.link_base = int(load[0][2], 16)
        self.end = self.link_base + int(load[0][4], 16)

    def lookup(self, address):
        i = bisect.bisect_right(self.addrs, address) - 1
        return self.names[i] if i >= 0 else f'{address:#x}'


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--socket', type=Path, required=True,
                        help="deci4p_host's --control socket")
    parser.add_argument('--deci-log', type=Path, help="deci4p_host's deci4p.log (pid, base)")
    parser.add_argument('--pid', type=lambda t: int(t, 0), help='process to sample')
    parser.add_argument('--all', action='store_true', help='sample every process')
    parser.add_argument('--base', type=lambda t: int(t, 0),
                        help="the ELF's loaded text base (default from --deci-log)")
    parser.add_argument('--elf', type=Path, help='the main module, unstripped, for symbols')
    parser.add_argument('--hz', type=int, help='samples per second per CPU (default: 997; registers: 199)')
    parser.add_argument('--seconds', type=float, default=10.0)
    parser.add_argument('--interval', type=float, default=0.2, help='buffer read interval')
    parser.add_argument('--bufsize', type=int, help='per-CPU buffer (default: 256 KiB; registers: 512 KiB, the most)')
    parser.add_argument('--stack-depth', type=int, default=0, help='native user-stack frames per sample (0 disables, maximum 256)')
    parser.add_argument('--registers', action='store_true', help='record independent raw ARM32 register events')
    parser.add_argument('--stack-bytes', type=int, help='raw bytes at exact user SP (register default: 8192; 0 is registers only; maximum 32768)')
    parser.add_argument('--top', type=int, default=40)
    parser.add_argument('--out', type=Path, help='write OUT.samples and OUT.txt')
    parser.add_argument('--verbose', action='store_true')
    args = parser.parse_args()
    if not 0 <= args.stack_depth <= 256:
        parser.error('stack depth must be 0..256')

    if args.stack_bytes is None:
        args.stack_bytes = 8192 if args.registers else 0
    if (not 0 <= args.stack_bytes <= MAX_STACK_BYTES or
        args.stack_bytes and (args.stack_bytes < 16 or args.stack_bytes % 4)):
        parser.error('stack bytes must be zero or an aligned extent of 16..32768')
    args.registers = args.registers or bool(args.stack_bytes)
    if args.hz is None:
        args.hz = 199 if args.registers else 997
    if args.hz <= 0:
        parser.error('sample rate must be positive')
    if args.bufsize is None:
        args.bufsize = MAX_REGISTER_BUFSIZE if args.registers else 256 * 1024
    if args.registers and not 2 * args.stack_bytes + 512 <= args.bufsize <= MAX_REGISTER_BUFSIZE:
        parser.error('register capture buffer must fit two snapshot extents and be at most 512 KiB')

    pid, base = (loadp_launch(args.deci_log) if args.deci_log else (None, None))
    pid = args.pid if args.pid is not None else pid
    base = args.base if args.base is not None else base
    if args.all:
        pid = None
    elif pid is None:
        parser.error('no pid: give --pid, --deci-log or --all')

    dt = Dtracep(args.socket, verbose=args.verbose)
    print(f'dtracep hello: {dt.hello()}', file=sys.stderr)
    print(f'dtrace handle {dt.open()}', file=sys.stderr)
    rv, conf = dt.ioctl(IOC_CONF, bytes(0x30))
    dt.check('CONF', rv)
    print('conf: DIF version %d, %d integer and %d tuple registers, CTF model %d'
          % struct.unpack_from('<4I', conf), file=sys.stderr)
    dof = profile_dof(args.hz, pid, args.bufsize, args.stack_depth, args.registers, args.stack_bytes)
    matched = dt.check('ENABLE', dt.enable(dof))
    print(f'ENABLE matched {matched} probe(s)', file=sys.stderr)
    if not matched:
        raise DtraceError(f'no probe matched profile-{args.hz}')
    layouts = {}
    for epid in range(1, 16):
        try:
            probe, size, recs = dt.eprobe(epid)
        except DtraceError:
            break
        layouts[epid] = (size, recs)
        print(f'epid {epid}: probe {probe}, {size} bytes, records {recs}', file=sys.stderr)
    if not layouts:
        raise DtraceError('the enabling has no probes')
    rv, _ = dt.ioctl(IOC_GO, bytes(4))
    dt.check('GO', rv)
    target = f'pid {pid:#x}' if pid is not None else 'all processes'
    print(f'sampling {target} at {args.hz} Hz for {args.seconds:g} s', file=sys.stderr)

    samples, stacks, raw_events, errors, drops = [], [], [], 0, 0
    started = time.monotonic()
    stopped = False
    try:
        while True:
            done = time.monotonic() - started >= args.seconds
            if done and not stopped:
                rv, _ = dt.ioctl(IOC_STOP, bytes(4))
                stopped = True
            for cpu in range(4):
                data, errs, dr = dt.bufsnap(cpu)
                errors, drops = errors + errs, drops + dr
                if data:
                    for _, fields in parse_records(data, layouts, args.stack_bytes):
                        if args.registers and len(fields) == 21 + bool(args.stack_bytes):
                            if (any(type(v) is not int for v in fields[:21]) or
                                args.stack_bytes and (type(fields[-1]) is not bytes or len(fields[-1]) != args.stack_bytes)):
                                raise DtraceError('register action layout differs from requested probe')
                            raw_events.append(((cpu, *fields[:5]), tuple(fields[5:21]),
                                               fields[-1] if args.stack_bytes else b''))
                            continue
                        expected = len(RECORDS) + bool(args.stack_depth)
                        if len(fields) != expected or any(not isinstance(v, int) for v in fields[:5]):
                            raise DtraceError('sample action layout differs from requested probe')
                        sample = (cpu, *fields[:5])
                        if args.stack_depth:
                            stack = user_stack(sample, fields[5], args.stack_depth)
                            if stack is not None:
                                # Retain the native payload even when leaf/PID validation
                                # rejects it, so firmware failures remain diagnosable.
                                stacks.append({'sample_index': len(samples), **stack,
                                               'native_pid': fields[5][0],
                                               'native_frames': list(fields[5][1:])})
                        samples.append(sample)
            if done:
                break
            time.sleep(args.interval)
    finally:
        # A failed parse or interrupted host must not leave profile probes active.
        try:
            if not stopped:
                dt.ioctl(IOC_STOP, bytes(4))
        finally:
            dt.close()

    names = [name for name, _ in RECORDS]
    print(f'{len(samples)} samples, {errors} errors, {drops} drops', file=sys.stderr)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with open(f'{args.out}.samples', 'w') as f:
            f.write('cpu ' + ' '.join(names) + '\n')
            for s in samples:
                f.write(' '.join(f'{v:#x}' if i > 0 else str(v) for i, v in enumerate(s)) + '\n')
    if args.stack_depth:
        stack_info = dict(source='Sony DTrace native USTACK / SceBacktrace',
                          requested_depth=args.stack_depth, samples=len(samples),
                          user_samples=sum(bool(s[2]) for s in samples),
                          stack_records=len(stacks),
                          with_callers=sum(len(s['frames']) > 1 for s in stacks),
                          cap_reached=sum(bool(s['flags'] & 1) for s in stacks),
                          unavailable_or_inconsistent=sum(bool(s['flags'] & 2) for s in stacks),
                          errors=errors, drops=drops)
        print('stack coverage: ' + json.dumps(stack_info), file=sys.stderr)
        if args.out:
            with open(f'{args.out}.stacks.jsonl', 'w') as out:
                for stack in stacks:
                    out.write(json.dumps(stack) + '\n')
            Path(f'{args.out}.stack-info.json').write_text(json.dumps(stack_info, indent=2) + '\n')
    if args.registers:
        if args.out:
            raw_info = write_register_capture(args.out, raw_events, samples, args.stack_bytes,
                                              args.hz, base, args.elf, errors, drops, pid)
            print('raw register coverage: ' + json.dumps(raw_info), file=sys.stderr)
        else:
            print(f'{len(raw_events)} independent raw register events; no derived callers', file=sys.stderr)
    report = summarize(samples, names, args, base)
    print(report)
    if args.out:
        Path(f'{args.out}.txt').write_text(report + '\n')


def summarize(samples, names, args, base):
    lines = []
    col = {name: i + 1 for i, name in enumerate(names)}
    total = len(samples)
    if not total:
        return 'no samples'
    symbols = Symbols(args.elf) if args.elf else None
    offset = (base - symbols.link_base) if symbols and base is not None else 0

    def where(s):
        upc, kpc = s[col['upc']], s[col['kpc']]
        if upc == 0:
            return f'[kernel {kpc:#x}]' if not symbols else '[kernel]'
        if symbols:
            linked = upc - offset
            if symbols.link_base <= linked < symbols.end:
                return symbols.lookup(linked)
            return '[other module]'
        return f'{upc:#x}'

    by_cpu = collections.Counter(s[0] for s in samples)
    lines.append(f'{total} samples; per CPU: '
                 + ', '.join(f'{c}: {n}' for c, n in sorted(by_cpu.items())))
    by_pid = collections.Counter(s[col['pid']] for s in samples)
    lines.append('per process: ' + ', '.join(f'{p:#x}: {n}' for p, n in by_pid.most_common(8)))
    if base is not None:
        lines.append(f'main module text at {base:#x}' + (f' (linked at {symbols.link_base:#x})'
                                                        if symbols else ''))
    functions = collections.Counter(where(s) for s in samples)
    lines.append('')
    lines.append(f'Hottest functions (all threads, {total} samples):')
    for name, n in functions.most_common(args.top):
        lines.append(f'{100.0 * n / total:6.2f}% {n:7d}  {name}')
    threads = collections.Counter(s[col['tid']] for s in samples)
    for tid, count in threads.most_common(8):
        lines.append('')
        lines.append(f'Thread {tid:#x}: {count} samples ({100.0 * count / total:.1f}%)')
        per = collections.Counter(where(s) for s in samples if s[col['tid']] == tid)
        for name, n in per.most_common(min(args.top, 20)):
            lines.append(f'{100.0 * n / count:6.2f}% {n:7d}  {name}')
    return '\n'.join(lines)


if __name__ == '__main__':
    try:
        main()
    except DtraceError as error:
        sys.exit(f'vita_prof: {error}')
