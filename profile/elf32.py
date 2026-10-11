"""ARM ELF32 reading for the profilers: segments, sections, extents checked."""
from dataclasses import dataclass
import hashlib
from pathlib import Path
import struct


@dataclass(frozen=True)
class Segment:
    kind: int
    offset: int
    address: int
    physical: int
    filesz: int
    memsz: int
    flags: int
    alignment: int


@dataclass(frozen=True)
class Section:
    name: str
    kind: int
    flags: int
    address: int
    offset: int
    size: int
    link: int
    info: int
    alignment: int
    entry_size: int


class Elf:
    def __init__(self, path, kind):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        if len(self.data) < 52 or self.data[:7] != b'\x7fELF\x01\x01\x01':
            raise ValueError(f'{path}: expected little-endian ELF32')
        header = struct.unpack_from('<16sHHIIIIIHHHHHH', self.data)
        if header[1] != kind or header[2] != 40 or header[3] != 1:
            raise ValueError(f'{path}: expected ARM ELF type {kind:#x}, version 1')
        if header[8] != 52 or header[9] != 32 or header[11] != 40:
            raise ValueError(f'{path}: invalid ELF table entry sizes')
        self.entry = header[4]
        phoff, shoff, phcount, shcount, names = header[5], header[6], header[10], header[12], header[13]
        if not shoff:
            raise ValueError(f'{path}: missing section headers')
        self.extent(shoff, 40, 'section zero')
        zero = struct.unpack_from('<10I', self.data, shoff)
        if shcount == 0:
            shcount = zero[5]
        if phcount == 0xffff:
            phcount = zero[7]
        if names == 0xffff:
            names = zero[6]
        if not phcount or not shcount or not 0 < names < shcount:
            raise ValueError(f'{path}: missing ELF tables or section names')
        if phoff < 52 or shoff < 52:
            raise ValueError(f'{path}: ELF tables overlap the header')
        self.extent(phoff, phcount * 32, 'program headers')
        self.extent(shoff, shcount * 40, 'section headers')
        self.segments = [Segment(*struct.unpack_from('<8I', self.data, phoff + i * 32))
                         for i in range(phcount)]
        self.loads = [p for p in self.segments if p.kind == 1]
        if not self.loads:
            raise ValueError(f'{path}: no PT_LOAD segments')
        for p in self.loads:
            self.extent(p.offset, p.filesz, 'load segment')
            if p.filesz > p.memsz or p.address + p.memsz > 0x100000000:
                raise ValueError(f'{path}: invalid load segment extent')
            if p.alignment and p.alignment & (p.alignment - 1):
                raise ValueError(f'{path}: invalid load segment alignment')
        rows = [struct.unpack_from('<10I', self.data, shoff + i * 40) for i in range(shcount)]
        string_section = rows[names]
        if string_section[1] != 3:
            raise ValueError(f'{path}: section names are not a string table')
        strings = self.extent(string_section[4], string_section[5], 'section names')
        self.sections = {}
        for row in rows[1:]:
            if row[0] >= len(strings) or strings.find(b'\0', row[0]) < 0:
                raise ValueError(f'{path}: invalid section name')
            try:
                name = strings[row[0]:strings.find(b'\0', row[0])].decode('ascii')
            except UnicodeDecodeError as error:
                raise ValueError(f'{path}: invalid section name') from error
            section = Section(name, *row[1:])
            if section.kind != 8:
                self.extent(section.offset, section.size, f'{name} section')
            if section.address + section.size > 0x100000000:
                raise ValueError(f'{path}: invalid {name} address extent')
            if name in self.sections:
                raise ValueError(f'{path}: duplicate section {name}')
            self.sections[name] = section

    def extent(self, offset, size, label):
        if offset < 0 or size < 0 or offset > len(self.data) or size > len(self.data) - offset:
            raise ValueError(f'{self.path}: truncated {label}')
        return self.data[offset:offset + size]

    def mapped(self, section, segment):
        delta = section.address - segment.address
        return (delta >= 0 and delta <= segment.filesz and
                section.size <= segment.filesz - delta and
                section.offset == segment.offset + delta)

    def required_section(self, name):
        if name not in self.sections:
            raise ValueError(f'{self.path}: missing {name}')
        return self.sections[name]


def sha(data):
    return hashlib.sha256(data).hexdigest()
