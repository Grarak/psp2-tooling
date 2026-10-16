#!/usr/bin/env python3
"""Parse a PS Vita core dump (psp2core-*.psp2dmp) and convert it for gdb.

A dump is a gzip-compressed ELF32 core. Its PT_LOAD segments hold the memory
the kernel saved (thread stacks and small blocks, not large heaps), and its
PT_NOTE segments hold one note per kind of kernel state, named after it
(THREAD_INFO, MODULE_INFO, ...).

Most notes are tables: a u32 version, a u32 entry count, then the entries.
Each entry starts with a u32 that is the entry's size where entries vary
(threads, registers) and 0 otherwise, followed by the object's UID. Kernel
objects with waiting threads (semaphores, ...) append a (process ID, thread
UID) pair per waiter. Space after the last entry is zero.

The layouts were read from firmware 3.60 dumps; fields not understood are
printed as raw words rather than left out. SYSTEM_INFO2 is encrypted.

  devkit/parse_core.py CORE --elf eboot.elf
  devkit/parse_core.py CORE --elf eboot.elf --backtrace
  devkit/parse_core.py CORE --gdb-core core.arm --json core.json

--gdb-core writes a standard ARM Linux core file (one NT_PRSTATUS and
NT_ARM_VFP per thread, the faulting thread first, and the saved memory), so
`gdb-multiarch ELF CORE` unwinds every thread with the ELF's DWARF;
--backtrace runs that in batch mode.
"""
import argparse
from dataclasses import dataclass, field
import gzip
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile

NOTE_TYPES = {
    0x1000: 'COREFILE_INFO', 0x1001: 'SYSTEM_INFO', 0x1002: 'PROCESS_INFO', 0x1003: 'THREAD_INFO',
    0x1004: 'THREAD_REG_INFO', 0x1005: 'MODULE_INFO', 0x1006: 'LIBRARY_INFO', 0x1007: 'MEM_BLK_INFO',
    0x1009: 'FILE_INFO', 0x100a: 'SEMAPHORE_INFO', 0x100b: 'EVENTFLAG_INFO', 0x100c: 'MUTEX_INFO',
    0x100d: 'LWMUTEX_INFO', 0x1010: 'MESG_PIPE_INFO', 0x1019: 'META_DATA_INFO', 0x101a: 'HW_INFO',
    0x101b: 'STACK_INFO', 0x101c: 'APP_INFO', 0x101d: 'BUILD_VER_INFO', 0x101e: 'EXTNL_PROC_INFO',
    0x101f: 'BUDGET_INFO', 0x1020: 'APP_LIST_INFO', 0x1021: 'DEVICE_INFO', 0x102a: 'TTY_INFO',
    0x102c: 'EVENT_LOG_INFO', 0x102d: 'SYSTEM_INFO2', 0x102e: 'SUMMARY_INFO', 0x102f: 'SYS_DEVICE_INFO',
    0x1031: 'TTY_INFO2', 0x2001: 'GPU_ACT_INFO',
}

# SceThreadStatus (psp2/kernel/threadmgr.h).
THREAD_STATUS = {1: 'running', 2: 'ready', 4: 'standby', 8: 'waiting', 16: 'dormant', 32: 'deleted',
                 64: 'dead', 128: 'stagnant', 256: 'suspended'}

STOP_REASONS = {0: '', 0x30002: 'undefined instruction', 0x30003: 'prefetch abort', 0x30004: 'data abort',
                0x60080: 'division by zero'}

# The signal gdb shows for the faulting thread.
STOP_SIGNALS = {0x30002: 4, 0x30003: 11, 0x30004: 11, 0x60080: 8}

MEMBLOCK_TYPES = {0x0c20d050: 'USER_RX', 0x0c20d060: 'USER_RW', 0x0c208060: 'USER_RW_UNCACHE',
                  0x0c80d060: 'USER_MAIN_PHYCONT_RW', 0x0d808060: 'USER_MAIN_PHYCONT_NC_RW',
                  0x09408060: 'USER_CDRAM_RW'}

SEGMENT_ATTRIBUTES = {5: 'RX', 6: 'RW', 4: 'R', 7: 'RWX'}


def u32(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


def u16(data, offset):
    return struct.unpack_from('<H', data, offset)[0]


def c_string(data, offset, size):
    return data[offset:offset + size].split(b'\0', 1)[0].decode('latin-1')


def strings(data, minimum=4):
    return [s.decode('latin-1') for s in re.findall(rb'[\x20-\x7e]{%d,}' % minimum, data)]


def words(data):
    return list(struct.unpack_from('<%dI' % (len(data) // 4), data))


def is_uid(value):
    return value >> 24 == 0x40 and value & 1


# Container


@dataclass
class Note:
    name: str
    type: int
    data: bytes


@dataclass
class Segment:
    address: int
    data: bytes
    flags: int


class Core:
    def __init__(self, raw):
        if raw[:2] == b'\x1f\x8b':
            raw = gzip.decompress(raw)
        if raw[:4] != b'\x7fELF' or raw[4] != 1 or raw[5] != 1:
            raise ValueError('not a little-endian ELF32 core dump')
        phoff, = struct.unpack_from('<I', raw, 28)
        phentsize, phnum = struct.unpack_from('<HH', raw, 42)
        self.notes = []
        self.segments = []
        for index in range(phnum):
            kind, offset, address, _, filesz, _, flags, _ = struct.unpack_from('<8I', raw, phoff + index * phentsize)
            if offset + filesz > len(raw):
                raise ValueError('segment %d extends past the end of the dump' % index)
            if kind == 1:
                self.segments.append(Segment(address, raw[offset:offset + filesz], flags))
            elif kind == 4:
                self.notes.extend(read_notes(raw[offset:offset + filesz]))
        self.by_name = {}
        for note in self.notes:
            self.by_name.setdefault(note.name, note)

    def note(self, name):
        note = self.by_name.get(name)
        return note.data if note else None

    def read(self, address, size):
        for segment in self.segments:
            if segment.address <= address and address + size <= segment.address + len(segment.data):
                start = address - segment.address
                return segment.data[start:start + size]
        return None

    def unique_segments(self):
        seen = set()
        for segment in self.segments:
            key = (segment.address, len(segment.data))
            if key not in seen:
                seen.add(key)
                yield segment


def read_notes(data):
    notes = []
    at = 0
    while at + 12 <= len(data):
        name_size, desc_size, kind = struct.unpack_from('<3I', data, at)
        at += 12
        name = data[at:at + name_size].split(b'\0', 1)[0].decode('latin-1')
        at += (name_size + 3) & ~3
        if at + desc_size > len(data):
            raise ValueError('note %s extends past its segment' % name)
        notes.append(Note(name or NOTE_TYPES.get(kind, hex(kind)), kind, data[at:at + desc_size]))
        at += (desc_size + 3) & ~3
    return notes


# Tables


def table(data, fixed=None, header=8):
    """Yields each entry of a note table.

    Sized entries (fixed None) start with their size. Fixed-size entries start
    with 0 and the object UID; (process, thread UID) waiter pairs between one
    entry and the next, or before the zero padding, are returned with it.
    """
    count = u32(data, 4)
    at = header
    for index in range(count):
        if fixed is None:
            size = u32(data, at)
            if size < 8 or at + size > len(data):
                raise ValueError('entry %d has an invalid size %d' % (index, size))
            yield data[at:at + size], []
            at += size
            continue
        if at + fixed > len(data):
            raise ValueError('entry %d runs past the note' % index)
        entry = data[at:at + fixed]
        at += fixed
        waiters = []
        last = index == count - 1
        while at + 8 <= len(data):
            pair = struct.unpack_from('<2I', data, at)
            next_entry = not last and at + 8 <= len(data) and pair[0] == 0 and is_uid(pair[1])
            if next_entry or (last and pair == (0, 0)):
                break
            waiters.append(pair)
            at += 8
            if len(waiters) > 4096:
                raise ValueError('entry %d: no next entry found' % index)
        yield entry, waiters


def decode_threads(core):
    data = core.note('THREAD_INFO')
    threads = []
    for entry, _ in table(data):
        thread = {
            'uid': u32(entry, 4), 'name': c_string(entry, 8, 32), 'attributes': u32(entry, 0x28),
            'status': u32(entry, 0x30), 'entry': u32(entry, 0x34), 'stack_base': u32(entry, 0x38),
            'stack_size': u32(entry, 0x3c), 'initial_priority': u32(entry, 0x4c),
            'priority': u32(entry, 0x50), 'affinity': u32(entry, 0x54), 'stop_reason': u32(entry, 0x74),
        }
        thread['pc'] = u32(entry, 0x9c) if len(entry) >= 0xa0 else None
        thread['words'] = words(entry)
        threads.append(thread)
    registers = {}
    if core.note('THREAD_REG_INFO'):
        for entry, _ in table(core.note('THREAD_REG_INFO')):
            w = words(entry)
            registers[w[1]] = {
                'r': w[2:18], 'cpsr': w[18], 'fpscr': w[19], 'tpidruro': w[20],
                'd': [w[21 + 2 * i] | w[22 + 2 * i] << 32 for i in range(32)] if len(w) >= 85 else [],
                # Fault state: the data abort's status and address are the last two words.
                'extra': w[85:], 'dfsr': w[-2] if len(w) >= 94 else None, 'dfar': w[-1] if len(w) >= 94 else None,
            }
    stacks = {}
    if core.note('STACK_INFO'):
        for entry, _ in table(core.note('STACK_INFO'), fixed=16):
            stacks[u32(entry, 4)] = {'peak_used': u32(entry, 8), 'used': u32(entry, 12)}
    for thread in threads:
        thread['registers'] = registers.get(thread['uid'])
        thread['stack'] = stacks.get(thread['uid'])
    return threads


def decode_modules(core):
    data = core.note('MODULE_INFO')
    modules = []
    at = 8
    for _ in range(u32(data, 4)):
        count = u32(data, at + 0x4c)
        module = {'uid': u32(data, at + 4), 'name': c_string(data, at + 0x24, 0x28), 'segments': [],
                  'header': words(data[at:at + 0x50])}
        at += 0x50
        for index in range(count):
            module['segments'].append({'index': index + 1, 'attributes': u32(data, at + 4), 'start': u32(data, at + 8),
                                       'size': u32(data, at + 12), 'align': u32(data, at + 16)})
            at += 0x14
        module['footer'] = words(data[at:at + 0x10])
        at += 0x10
        modules.append(module)
    return modules


def decode_libraries(data):
    """Exported libraries: (NID, address) pairs, the importing modules, the name.

    Header words: [1] library UID, [2] module UID, [5] functions, [6] variables
    (taken to follow the functions as pairs; 0 in the dumps seen), [8]
    importing modules.
    """
    libraries = []
    at = 8
    for _ in range(u32(data, 4)):
        head = words(data[at:at + 0x24])
        functions, variables, importers = head[5], head[6], head[8]
        at += 0x24
        pairs = words(data[at:at + 8 * (functions + variables)])
        at += 8 * (functions + variables)
        users = words(data[at:at + 4 * importers])
        at += 4 * importers
        size = u32(data, at)
        name = c_string(data, at + 4, size)
        at += 4 + ((size + 3) & ~3)
        if at > len(data):
            raise ValueError('library %s runs past the note' % name)
        libraries.append({'uid': head[1], 'module': head[2], 'name': name, 'header': head, 'importers': users,
                          'functions': [(pairs[2 * i], pairs[2 * i + 1]) for i in range(functions)],
                          'variables': [(pairs[2 * i], pairs[2 * i + 1]) for i in range(functions, functions + variables)]})
    if any(data[at:]):
        raise ValueError('LIBRARY_INFO has bytes after its last library')
    return libraries


def decode_objects(data, fixed, named=True, with_process=True):
    """Kernel objects: UID, owner process, name, then raw fields."""
    rows = []
    for entry, waiters in table(data, fixed=fixed):
        row = {'uid': u32(entry, 4)}
        at = 8
        if with_process:
            row['process'] = u32(entry, at)
            at += 4
        if named:
            row['name'] = c_string(entry, at, 32)
            at += 32
        row['fields'] = words(entry[at:])
        row['waiters'] = [{'process': p, 'thread': t} for p, t in waiters]
        rows.append(row)
    return rows


def decode_files(data):
    rows = decode_objects(data, 88, named=False, with_process=False)
    for row in rows:
        w = row['fields']
        row['process'] = w[2]
        row['position'] = w[4] | w[5] << 32
        row['size'] = w[6] | w[7] << 32
    return rows


def decode_memory_blocks(data):
    rows = []
    for entry, _ in table(data, fixed=72):
        w = words(entry)
        rows.append({'uid': w[1], 'name': c_string(entry, 8, 32), 'type': w[10], 'base': w[11], 'size': w[12],
                     'fields': w[13:]})
    return rows


def decode_tty(data):
    size = u32(data, 8)
    return data[12:12 + size].split(b'\0', 1)[0].decode('utf-8', 'replace')


def decode_summary(data):
    rows = []
    for index in range(u32(data, 8)):
        kind, size, total = struct.unpack_from('<3I', data, 12 + index * 12)
        rows.append({'type': kind, 'name': NOTE_TYPES.get(kind, hex(kind)), 'size': size, 'saved': total})
    return rows


def decode_process(data):
    return {'pid': u32(data, 8), 'name': c_string(data, 0x10, 32), 'entry': u32(data, 0x38),
            'path': c_string(data, 0x5c, u32(data, 0x58)), 'words': words(data[8:])}


def decode_system(data):
    version = u32(data, 8)
    return {'firmware': '%x.%02x' % (version >> 24, version >> 16 & 0xff), 'firmware_word': version,
            'words': words(data[8:])}


def decode_raw(data):
    return {'version': u32(data, 0) if len(data) >= 4 else None, 'size': len(data),
            'strings': strings(data)[:64], 'words': words(data[:256])}


def decode(core):
    result = {'notes': [{'name': n.name, 'type': n.type, 'size': len(n.data)} for n in core.notes],
              'segments': [{'address': s.address, 'size': len(s.data), 'flags': s.flags} for s in core.segments]}
    decoders = {
        'PROCESS_INFO': decode_process,
        'SYSTEM_INFO': decode_system,
        'APP_INFO': lambda d: {'strings': strings(d[8:], 2)},
        'BUILD_VER_INFO': lambda d: {'numbers': words(d[8:20]), 'branch': c_string(d, 20, len(d) - 20)},
        'LIBRARY_INFO': decode_libraries,
        'MEM_BLK_INFO': decode_memory_blocks,
        'SEMAPHORE_INFO': lambda d: decode_objects(d, 68),
        'EVENTFLAG_INFO': lambda d: decode_objects(d, 64),
        'MUTEX_INFO': lambda d: decode_objects(d, 72),
        'LWMUTEX_INFO': lambda d: decode_objects(d, 64, with_process=False),
        'MESG_PIPE_INFO': lambda d: decode_objects(d, None),
        'FILE_INFO': decode_files,
        'TTY_INFO': decode_tty,
        'TTY_INFO2': decode_tty,
        'SUMMARY_INFO': decode_summary,
        'SYSTEM_INFO2': lambda d: {'size': len(d), 'magic': d[6:12].decode('latin-1'), 'encrypted': True},
    }
    skipped = {'THREAD_INFO', 'THREAD_REG_INFO', 'STACK_INFO', 'MODULE_INFO'}
    result['threads'] = decode_threads(core) if core.note('THREAD_INFO') else []
    result['modules'] = decode_modules(core) if core.note('MODULE_INFO') else []
    for note in core.notes:
        if note.name in skipped:
            continue
        try:
            result[note.name] = decoders.get(note.name, decode_raw)(note.data)
        except (ValueError, struct.error, IndexError) as error:
            result[note.name] = {'error': str(error), **decode_raw(note.data)}
    return result


# Symbols


class Symbols:
    """addr2line over the ELF, for addresses inside the module it was loaded as."""

    def __init__(self, elf, modules):
        self.elf = elf
        self.tool = next((t for t in ('llvm-addr2line', 'arm-vita-eabi-addr2line', 'addr2line') if shutil.which(t)), None)
        self.cache = {}
        self.ranges = []
        if not elf:
            return
        raw = Path(elf).read_bytes()
        phoff, = struct.unpack_from('<I', raw, 28)
        phentsize, phnum = struct.unpack_from('<HH', raw, 42)
        loads = []
        for index in range(phnum):
            kind, _, address, _, _, memsz, _, _ = struct.unpack_from('<8I', raw, phoff + index * phentsize)
            if kind == 1:
                loads.append((address, memsz))
        # The module loaded at the ELF's address (a DevKit executable), else the one named
        # after the ELF, else the one whose first segment is closest to the ELF's size
        # (relocated: a PRX, or a retail executable, which loads at 0x81000000 plus a slide).
        def size_gap(module):
            return abs(module['segments'][0]['size'] - loads[0][1])
        candidates = [m for m in modules if m['segments']] if loads else []
        stem = Path(elf).stem.replace('-', '_')
        found = ([m for m in candidates if m['segments'][0]['start'] == loads[0][0]] or
                 [m for m in candidates if m['name'] == stem] or
                 sorted((m for m in candidates if size_gap(m) < 0x10000), key=size_gap))
        if found:
            for (address, memsz), segment in zip(loads, found[0]['segments']):
                self.ranges.append((segment['start'], segment['start'] + memsz, address - segment['start']))

    def contains(self, address):
        return any(start <= address < end for start, end, _ in self.ranges)

    def lookup(self, addresses):
        wanted = [a for a in addresses if a not in self.cache and self.contains(a & ~1)]
        if wanted and self.tool:
            biased = []
            for a in wanted:
                bias = next(b for start, end, b in self.ranges if start <= (a & ~1) < end)
                biased.append('%#x' % ((a & ~1) + bias))
            output = subprocess.run([self.tool, '-f', '-C', '-e', self.elf, *biased], capture_output=True, text=True).stdout
            lines = output.splitlines()
            for index, address in enumerate(wanted):
                name = lines[2 * index] if 2 * index < len(lines) else '??'
                where = lines[2 * index + 1].rsplit('/', 1)[-1] if 2 * index + 1 < len(lines) else ''
                self.cache[address] = name if where.startswith('??') else '%s (%s)' % (name, where)
        return {a: self.cache.get(a, '') for a in addresses}


def describe_address(address, modules, symbols):
    for module in modules:
        for segment in module['segments']:
            if segment['start'] <= address < segment['start'] + segment['size']:
                name = symbols.lookup([address])[address] if symbols else ''
                where = '%s@%d+%#x' % (module['name'], segment['index'], address - segment['start'])
                return '%#010x %s%s' % (address, where, ' ' + name if name else '')
    return '%#010x' % address


def scan_stack(core, thread, symbols, limit):
    """Return addresses into the ELF found on the stack: a heuristic, not an unwind."""
    registers = thread['registers']
    if not registers or not symbols:
        return []
    sp = registers['r'][13]
    top = thread['stack_base'] + thread['stack_size']
    found = []
    for address in range(sp, top, 4):
        word = core.read(address, 4)
        if word is None:
            break
        value = u32(word, 0)
        # Thumb return addresses are odd.
        if value & 1 and symbols.contains(value & ~1):
            found.append((address, value))
            if len(found) >= limit:
                break
    names = symbols.lookup([v for _, v in found])
    return [(a, v, names[v]) for a, v in found]


# gdb


def note_bytes(name, kind, desc):
    name = name.encode() + b'\0'
    return struct.pack('<3I', len(name), len(desc), kind) + name.ljust((len(name) + 3) & ~3, b'\0') + desc.ljust((len(desc) + 3) & ~3, b'\0')


def prstatus(thread, signal):
    r = thread['registers']
    regs = list(r['r']) + [r['cpsr'], 0]
    return struct.pack('<3ih2xII4I8I18Ii', signal, 0, 0, signal, 0, 0, thread['uid'], 0, 0, 0, *([0] * 8), *regs, 1)


def vfp(thread):
    r = thread['registers']
    return struct.pack('<32QI', *(r['d'] or [0] * 32), r['fpscr'])


def prpsinfo(name):
    return struct.pack('<4cIHH4I16s80s', b'R', b'R', b'\0', b'\0', 0, 0, 0, 0, 0, 0, 0, name.encode()[:15], name.encode()[:79])


def write_gdb_core(core, decoded, path):
    """An ARM Linux core: faulting thread first (gdb's selected thread)."""
    threads = [t for t in decoded['threads'] if t['registers']]
    threads.sort(key=lambda t: (t['stop_reason'] == 0, t['status'] != 1))
    process = decoded.get('PROCESS_INFO', {})
    notes = note_bytes('CORE', 3, prpsinfo(process.get('name', 'vita') if isinstance(process, dict) else 'vita'))
    for thread in threads:
        notes += note_bytes('CORE', 1, prstatus(thread, STOP_SIGNALS.get(thread['stop_reason'], 0)))
        notes += note_bytes('LINUX', 0x400, vfp(thread))
    segments = list(core.unique_segments())
    count = 1 + len(segments)
    offset = 52 + 32 * count
    headers = [struct.pack('<8I', 4, offset, 0, 0, len(notes), 0, 4, 4)]
    payload = [notes]
    offset += len(notes)
    for segment in segments:
        offset = (offset + 3) & ~3
        payload.append(segment.data)
        headers.append(struct.pack('<8I', 1, offset, segment.address, 0, len(segment.data), len(segment.data),
                                   segment.flags & 7 or 6, 4))
        offset += len(segment.data)
    ident = b'\x7fELF\x01\x01\x01' + bytes(9)
    header = struct.pack('<16sHHIIIIIHHHHHH', ident, 4, 40, 1, 0, 52, 0, 0x05000000, 52, 32, count, 40, 0, 0)
    with open(path, 'wb') as out:
        out.write(header + b''.join(headers))
        for chunk in payload:
            out.write(b'\0' * ((-out.tell()) % 4))
            out.write(chunk)
    return threads


def load_command(elf, symbols):
    """gdb's command to load the ELF where the dumped module sits: each section by its segment's slide."""
    slides = {bias for _, _, bias in symbols.ranges} if symbols else set()
    if not slides or slides == {0}:
        return 'file %s' % elf
    raw = Path(elf).read_bytes()
    shoff, = struct.unpack_from('<I', raw, 32)
    shentsize, shnum, shstrndx = struct.unpack_from('<HHH', raw, 46)
    headers = [struct.unpack_from('<10I', raw, shoff + i * shentsize) for i in range(shnum)]
    strings = headers[shstrndx][4]
    sections = []
    for name, _, flags, address, _, size, _, _, _, _ in headers:
        bias = next((b for start, end, b in symbols.ranges if start <= address - b < end), None)
        if flags & 2 and size and bias is not None:  # SHF_ALLOC
            label = raw[strings + name:raw.index(b'\0', strings + name)].decode()
            sections.append('-s %s %#x' % (label, address - bias))
    return 'add-symbol-file %s %s' % (elf, ' '.join(sections))


def gdb_backtraces(core, decoded, elf, symbols, depth):
    gdb = next((t for t in ('gdb-multiarch', 'arm-vita-eabi-gdb') if shutil.which(t)), None)
    if not gdb:
        return 'gdb-multiarch not found'
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / 'core'
        write_gdb_core(core, decoded, path)
        command = [gdb, '-nx', '-batch', '-ex', 'set pagination off', '-ex', 'set osabi GNU/Linux',
                   '-ex', 'set auto-load safe-path /', '-ex', load_command(elf, symbols),
                   '-ex', 'core-file %s' % path, '-ex', 'thread apply all bt %d' % depth]
        result = subprocess.run(command, capture_output=True, text=True)
        # add-symbol-file echoes every section address it was given.
        return ''.join(line for line in (result.stdout + result.stderr).splitlines(keepends=True)
                       if not line.startswith(('add symbol table from file', '\t.')))


# Report


def report(core, decoded, symbols, args):
    out = []
    p = out.append
    process = decoded.get('PROCESS_INFO', {})
    if 'name' in process:
        p('Process %s (pid %#x) %s' % (process['name'], process['pid'], process['path']))
    app = decoded.get('APP_INFO', {})
    if app.get('strings'):
        p('Application: %s' % ' / '.join(app['strings']))
    if 'firmware' in decoded.get('SYSTEM_INFO', {}):
        p('Firmware %s (%s)' % (decoded['SYSTEM_INFO']['firmware'], decoded.get('BUILD_VER_INFO', {}).get('branch', '')))
    p('')
    modules = decoded['modules']
    names = {t['uid']: t['name'] for t in decoded['threads']}

    def thread_name(uid):
        return '%s <%#x>' % (names.get(uid, '?'), uid)

    p('=== THREADS ===')
    for t in decoded['threads']:
        # The high bit is a flag; the low half is SceThreadStatus.
        status = THREAD_STATUS.get(t['status'] & 0xffff, hex(t['status']))
        stop = STOP_REASONS.get(t['stop_reason'], hex(t['stop_reason']))
        stack = t['stack'] or {}
        p('%-32s %-9s prio %3d affinity %#07x stack %#x+%#x (peak %s)%s' % (
            thread_name(t['uid']), status, t['priority'], t['affinity'], t['stack_base'], t['stack_size'],
            hex(stack['peak_used']) if stack else '?', '  STOPPED: ' + stop if t['stop_reason'] else ''))
        r = t['registers']
        if r:
            p('    PC %s' % describe_address(r['r'][15], modules, symbols))
            p('    LR %s' % describe_address(r['r'][14], modules, symbols))
    for t in decoded['threads']:
        if not t['stop_reason'] and not args.all_threads:
            continue
        r = t['registers']
        p('')
        p('=== THREAD %s %s ===' % (thread_name(t['uid']), STOP_REASONS.get(t['stop_reason'], hex(t['stop_reason']))))
        if not r:
            p('    no registers')
            continue
        for row in range(0, 16, 4):
            p('    ' + '  '.join('%-3s %08x' % (('r%d' % i) if i < 13 else ('sp', 'lr', 'pc')[i - 13], r['r'][i]) for i in range(row, row + 4)))
        p('    cpsr %08x (%s)  fpscr %08x  tpidruro %08x' % (r['cpsr'], 'Thumb' if r['cpsr'] & 0x20 else 'ARM', r['fpscr'], r['tpidruro']))
        if t['stop_reason'] in (0x30003, 0x30004) and r['dfar'] is not None:
            p('    fault status %08x (%s), address %08x' % (r['dfsr'], 'write' if r['dfsr'] & 0x800 else 'read', r['dfar']))
        p('    stack return addresses (scan, not an unwind):')
        for address, value, name in scan_stack(core, t, symbols, args.stack_depth):
            p('      sp+%#06x %#010x %s' % (address - r['r'][13], value, name))
    if args.backtrace:
        p('')
        p('=== GDB BACKTRACES ===')
        p(gdb_backtraces(core, decoded, args.elf, symbols, args.stack_depth).rstrip())
    p('')
    p('=== MODULES ===')
    for m in modules:
        p('%-24s uid %#x  %s' % (m['name'], m['uid'], '  '.join('%d:%s %#x+%#x' % (s['index'], SEGMENT_ATTRIBUTES.get(s['attributes'] & 0xf, hex(s['attributes'])), s['start'], s['size']) for s in m['segments'])))
    blocks = decoded.get('MEM_BLK_INFO')
    if isinstance(blocks, list):
        p('')
        p('=== MEMORY BLOCKS === (%d, %.1f MiB)' % (len(blocks), sum(b['size'] for b in blocks) / 1048576))
        for b in blocks:
            p('%-32s uid %#x  %-22s %#010x %8.2f MiB' % (b['name'], b['uid'], MEMBLOCK_TYPES.get(b['type'], hex(b['type'])), b['base'], b['size'] / 1048576))
    for name, title in (('SEMAPHORE_INFO', 'SEMAPHORES'), ('EVENTFLAG_INFO', 'EVENT FLAGS'), ('MUTEX_INFO', 'MUTEXES'),
                        ('LWMUTEX_INFO', 'LIGHTWEIGHT MUTEXES'), ('MESG_PIPE_INFO', 'MESSAGE PIPES')):
        rows = decoded.get(name)
        if not isinstance(rows, list):
            continue
        waiting = [r for r in rows if r['waiters']]
        p('')
        p('=== %s === (%d, %d with waiters)' % (title, len(rows), len(waiting)))
        for r in rows if args.all_objects else waiting:
            p('%-32s uid %#x  fields %s' % (r.get('name', ''), r['uid'], ' '.join('%x' % w for w in r['fields'])))
            for w in r['waiters']:
                p('    waiter %s' % thread_name(w['thread']))
    files = decoded.get('FILE_INFO')
    if isinstance(files, list):
        p('')
        p('=== FILES === (%d open)' % len(files))
        for f in files:
            p('fd uid %#x  process %#x  position %#x of %#x (%.1f MiB)' % (f['uid'], f['process'], f['position'], f['size'], f['size'] / 1048576))
    for name in ('TTY_INFO2', 'TTY_INFO'):
        text = decoded.get(name)
        if isinstance(text, str) and text.strip():
            lines = text.rstrip('\n').split('\n')
            p('')
            p('=== %s === (last %d of %d lines)' % (name, min(args.tty_lines, len(lines)), len(lines)))
            out.extend(lines[-args.tty_lines:])
    libraries = decoded.get('LIBRARY_INFO')
    if isinstance(libraries, list):
        modules_by_uid = {m['uid']: m['name'] for m in modules}
        p('')
        p('=== EXPORTED LIBRARIES === (%d)' % len(libraries))
        for library in libraries:
            p('%-32s from %-16s %4d functions %3d variables, imported by %s' % (
                library['name'], modules_by_uid.get(library['module'], hex(library['module'])), len(library['functions']),
                len(library['variables']), ', '.join(modules_by_uid.get(u, hex(u)) for u in library['importers']) or '-'))
    errors = [(k, v['error']) for k, v in decoded.items() if isinstance(v, dict) and 'error' in v]
    if errors:
        p('')
        for k, e in errors:
            p('note %s not decoded: %s' % (k, e))
    return '\n'.join(out)


def to_json(value):
    if isinstance(value, dict):
        return {k: to_json(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_json(v) for v in value]
    if isinstance(value, bytes):
        return value.hex()
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('core', help='psp2core-*.psp2dmp (gzip) or its decompressed ELF')
    parser.add_argument('--elf', help='the unstripped ELF of the dumped application, for symbols')
    parser.add_argument('--json', help='write every decoded note here')
    parser.add_argument('--gdb-core', help='write an ARM Linux core file for gdb-multiarch here')
    parser.add_argument('--backtrace', action='store_true', help='unwind every thread with gdb-multiarch (needs --elf)')
    parser.add_argument('--all-threads', action='store_true', help='registers and stack scans of every thread')
    parser.add_argument('--all-objects', action='store_true', help='list every kernel object, not only those with waiters')
    parser.add_argument('--stack-depth', type=int, default=32)
    parser.add_argument('--tty-lines', type=int, default=40)
    args = parser.parse_args(argv)
    if args.backtrace and not args.elf:
        parser.error('--backtrace needs --elf')
    core = Core(Path(args.core).read_bytes())
    decoded = decode(core)
    symbols = Symbols(args.elf, decoded['modules']) if args.elf else None
    if args.gdb_core:
        write_gdb_core(core, decoded, args.gdb_core)
    if args.json:
        Path(args.json).write_text(json.dumps(to_json(decoded), indent=1))
    print(report(core, decoded, symbols, args))
    return 0


if __name__ == '__main__':
    sys.exit(main())
