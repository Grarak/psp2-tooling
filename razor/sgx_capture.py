#!/usr/bin/env python3
"""Inspect Sony Razor v2 .sgx GPU snapshots (razor/recorder's capture=); no GPU timings.

Decodes the native section container, scene-local CPU/GPU mappings, memory,
program metadata, shader parameters and bounded VDM draw streams. Unknown
state words remain raw.

    razor/sgx_capture.py frame.sgx --json frame.json
"""
import argparse
import bisect
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct


class FormatError(ValueError):
    """Invalid container or declared extent."""


class MissingMemory(ValueError):
    """Valid container does not capture a requested GPU/CPU address."""


KINDS = {
    0x00: 'file_header', 0x01: 'scene_begin', 0x02: 'scene_stream',
    0x03: 'address_mapping', 0x04: 'memory', 0x05: 'resource_descriptor_raw',
    0x07: 'file_end', 0x08: 'system_info', 0x09: 'scene_context_raw',
    0x0b: 'surface_state_raw', 0x0c: 'usse_bases_raw', 0x0d: 'referenced_range',
    0x0e: 'scene_end', 0x0f: 'program', 0x11: 'buffer_binding',
    0x12: 'uniform_binding', 0x13: 'configuration', 0x14: 'resource_metadata_raw',
    0x15: 'render_target', 0x17: 'program_parameter', 0x18: 'memory_read_failure',
    0x19: 'memory_end', 0x1a: 'scene_clip', 0x1b: 'render_target_tiles_raw',
    0x1c: 'render_target_flags', 0x1d: 'aux_surface_raw',
    0x1e: 'driver_configuration_raw', 0x1f: 'scene_surface_raw',
}
# Payload bytes; total section length additionally includes the 8-byte header.
SIZES = {0: 4, 1: 8, 2: 24, 3: 12, 5: 24, 7: 0, 8: 40, 9: 264,
         0x0b: 48, 0x0c: 64, 0x0d: 8, 0x0e: 4, 0x0f: 128, 0x11: 28,
         0x12: 24, 0x13: 8, 0x14: 48, 0x15: 40, 0x18: 8, 0x19: 0,
         0x1a: 32, 0x1b: 32, 0x1c: 16, 0x1d: 32, 0x1e: 16, 0x1f: 88}
CATEGORIES = {0: 'attribute', 1: 'uniform', 2: 'sampler',
              3: 'auxiliary_surface', 4: 'uniform_buffer'}
TYPES = dict(enumerate(('f32', 'f16', 'c10', 'u32', 's32', 'u16', 's16',
                        'u8', 's8', 'aggregate')))
PRIMITIVES = {0: 'triangles', 1: 'lines', 2: 'points', 3: 'triangle_strip',
              4: 'triangle_fan'}


def hex32(value):
    return f'0x{value:08x}'


def words(data):
    return [hex32(value[0]) for value in struct.iter_unpack('<I', data[:len(data) & ~3])]


def sections(data):
    offset = 0
    while offset < len(data):
        if len(data) - offset < 8:
            raise FormatError(f'Truncated section header at {offset:#x}')
        tag, size = struct.unpack_from('<II', data, offset)
        if size < 8 or size % 4:
            raise FormatError(f'Invalid section length {size} at {offset:#x}')
        if size > len(data) - offset:
            raise FormatError(f'Truncated section {tag:#010x} at {offset:#x}: needs {size} bytes')
        if tag & 0xffff00 != 0x1a2b00:
            raise FormatError(f'Invalid Sony section namespace {tag:#010x} at {offset:#x}')
        yield offset, tag, memoryview(data)[offset + 8:offset + size]
        offset += size


def decode_section(offset, tag, payload):
    kind = tag & 255
    if kind in SIZES and len(payload) != SIZES[kind]:
        raise FormatError(f'Invalid {KINDS[kind]} payload size {len(payload)} at {offset:#x}')
    result = dict(offset=offset, tag=hex32(tag), tag_flags=tag >> 24,
                  total_size=len(payload) + 8, payload_size=len(payload),
                  kind=KINDS.get(kind, 'unknown'), decoding='verified_layout')
    if kind != 4:
        result['raw_words'] = words(payload)
    if kind == 0:
        result['version'] = struct.unpack('<I', payload)[0]
    elif kind == 1:
        frame, fixed, scene_byte, padding = struct.unpack('<IBBH', payload)
        result.update(frame=frame, format_byte=fixed, scene_index_byte=scene_byte,
                      padding_u16=padding)
    elif kind == 2:
        frame, scene_word, stream, *rest = struct.unpack('<6I', payload)
        result.update(frame=frame, scene_index_word=scene_word,
                      vdm_cpu_address=hex32(stream), unknown_words=[hex32(x) for x in rest])
    elif kind == 3:
        cpu, gpu, size = struct.unpack('<3I', payload)
        if size == 0 or cpu + size > 1 << 32 or gpu + size > 1 << 32:
            raise FormatError(f'Invalid mapping extent at {offset:#x}')
        result.update(cpu_start=hex32(cpu), gpu_start=hex32(gpu), bytes=size)
    elif kind == 4:
        if len(payload) < 8:
            raise FormatError(f'Truncated memory bounds at {offset:#x}')
        start, encoded_end = struct.unpack_from('<II', payload)
        end = encoded_end or (1 << 32)
        if end <= start or end - start != len(payload) - 8:
            raise FormatError(f'Memory bounds do not match payload at {offset:#x}')
        result.update(cpu_start=hex32(start), cpu_end_exclusive=f'0x{end:08x}',
                      bytes=end - start, data_offset=offset + 16,
                      sha256=hashlib.sha256(payload[8:]).hexdigest())
    elif kind == 8:
        gpu, wireless = struct.unpack_from('<HH', payload, 4)
        result.update(gpu_clock_mhz=gpu, wireless=wireless,
                      firmware_word=hex32(struct.unpack_from('<I', payload, 20)[0]))
    elif kind == 0x0d:
        start, end = struct.unpack('<II', payload)
        if end < start:
            raise FormatError(f'Invalid referenced range at {offset:#x}')
        result.update(cpu_start=hex32(start), cpu_end_exclusive=hex32(end))
    elif kind == 0x0f:
        values = struct.unpack('<32I', payload)
        result.update(program_cpu_address=hex32(values[0]),
                      binary_guid=hex32(values[2]), source_guid=hex32(values[3]),
                      parameter_count=values[18], primary_registers=values[22],
                      secondary_registers=values[23], temporary_registers=values[24],
                      gxp_u16_36=values[25], native_color=bool(values[28] & 2))
    elif kind == 0x11:
        values = struct.unpack('<5I2HI', payload)
        result.update(buffer_cpu_address=hex32(values[2]), bytes=values[3],
                      unknown_binding_words=[hex32(values[0]), hex32(values[1]), hex32(values[4])],
                      index_u16=values[5], reserved_u16=values[6], unknown_u32=hex32(values[7]))
        if values[2] + values[3] > 1 << 32:
            raise FormatError(f'Invalid buffer binding extent at {offset:#x}')
    elif kind == 0x12:
        values = struct.unpack('<4I4H', payload)
        result.update(binding_words=[hex32(x) for x in values[:4]],
                      offset_u16=values[4], index_u16=values[5],
                      word_count=values[6], reserved_u16=values[7])
    elif kind == 0x13:
        key, value = struct.unpack('<II', payload)
        result.update(key=key, value=value)
    elif kind == 0x15:
        width, height = struct.unpack_from('<II', payload)
        result.update(width=width, height=height)
    elif kind == 0x17:
        if len(payload) < 28:
            raise FormatError(f'Truncated shader parameter at {offset:#x}')
        program, ordinal, descriptor, array_size, resource_index, reserved = struct.unpack_from('<6I', payload)
        name_data = bytes(payload[24:])
        terminator = name_data.find(b'\0')
        if (terminator < 0 or terminator > 256 or any(name_data[terminator:])
                or len(name_data) - terminator != 4 - terminator % 4):
            raise FormatError(f'Invalid shader parameter name/padding at {offset:#x}')
        category = descriptor & 15
        result.update(program_cpu_address=hex32(program), ordinal=ordinal,
                      descriptor=hex32(descriptor), category=CATEGORIES.get(category, f'unknown_{category}'),
                      parameter_type=TYPES.get((descriptor >> 4) & 15, 'unknown'),
                      components=(descriptor >> 8) & 15, container_index=(descriptor >> 12) & 15,
                      semantic_raw=(descriptor >> 16) & 255, semantic_index=(descriptor >> 24) & 15,
                      array_size=array_size, resource_index=resource_index, reserved=reserved,
                      name=name_data[:terminator].decode('utf-8', errors='replace'))
    elif kind == 0x18:
        result['cpu_address'] = hex32(struct.unpack_from('<I', payload)[0])
        result['decoding'] = 'memory_read_failed; bytes may be filler'
    elif kind == 0x1a:
        values = struct.unpack('<8I', payload)
        result.update(clip=dict(x_min=values[0], y_min=values[1], x_max=values[2], y_max=values[3]),
                      flags=hex32(values[4]))
        result['decoding'] = 'verified_layout; clip meaning inferred from native context and target extents'
    elif kind == 0x1c:
        result['flags'] = hex32(struct.unpack_from('<I', payload)[0])
    elif kind not in (7, 0x0e, 0x19):
        result['decoding'] = 'opaque_payload'
        if kind not in KINDS:
            result['raw_hex'] = bytes(payload).hex()
    return result


class Memory:
    def __init__(self, data, scene):
        self.data = data
        self.mappings = [(int(r['gpu_start'], 16), int(r['cpu_start'], 16), r['bytes'])
                         for r in scene['mappings']]
        self.ranges = sorted((int(r['cpu_start'], 16), int(r['cpu_end_exclusive'], 16), r['data_offset'])
                             for r in scene['memory'])
        self.starts = [r[0] for r in self.ranges]
        for previous, current in zip(self.ranges, self.ranges[1:]):
            if previous[1] > current[0]:
                raise FormatError(f'Overlapping captured memory at {current[0]:#x} within one scene')
        self.failed = {int(r['cpu_address'], 16) for r in scene['memory_failures']}

    def read_cpu(self, address, size):
        if size < 0 or address < 0 or address + size > 1 << 32:
            raise MissingMemory('Invalid CPU address extent')
        pieces = []
        while size:
            index = bisect.bisect_right(self.starts, address) - 1
            if index < 0 or address >= self.ranges[index][1]:
                raise MissingMemory(f'CPU memory {address:#010x} is not captured in this scene')
            start, end, offset = self.ranges[index]
            count = min(size, end - address)
            # The failure record has no reliable length. Conservatively reject
            # its whole associated memory section, including native filler.
            if any(start <= failed < end for failed in self.failed):
                raise MissingMemory(f'CPU memory {address:#010x} was marked unreadable by Sony')
            pieces.append(self.data[offset + address - start:offset + address - start + count])
            address += count
            size -= count
        return b''.join(pieces)

    def cpu_address(self, gpu_address, size=1):
        matches = [(cpu + gpu_address - gpu, gpu + count - gpu_address)
                   for gpu, cpu, count in self.mappings if gpu <= gpu_address < gpu + count]
        if not matches:
            raise MissingMemory(f'GPU address {gpu_address:#010x} has no captured mapping')
        if len({cpu for cpu, _ in matches}) != 1:
            raise MissingMemory(f'GPU address {gpu_address:#010x} has ambiguous mappings')
        cpu, count = matches[0]
        if size > count:
            raise MissingMemory(f'GPU extent crosses mapping boundary at {gpu_address:#010x}')
        return cpu

    def read_gpu(self, address, size):
        return self.read_cpu(self.cpu_address(address, size), size)


def decode_vdm(memory, start, limit=65536):
    """Native capture FUN_81002830: links 1 word, PDS 2, indices 2..8.

    Preserve state flags without interpreting or executing PDS/USSE programs.
    Missing snapshots, cycles and exhausted limits end traversal explicitly.
    """
    result = dict(start_cpu_address=hex32(start), terminated=False, commands=[], draws=[])
    pc, seen = start, set()
    try:
        for _ in range(limit):
            if pc in seen:
                raise MissingMemory(f'VDM stream cycle at {pc:#010x}')
            if pc & 3:
                raise MissingMemory(f'Unaligned VDM address {pc:#010x}')
            seen.add(pc)
            head = struct.unpack('<I', memory.read_cpu(pc, 4))[0]
            kind = head >> 30
            command = dict(cpu_address=hex32(pc), words=[hex32(head)])
            if kind == 0:
                target = (head & 0x3fffffff) << 2
                command.update(kind='link', target_gpu_address=hex32(target))
                result['commands'].append(command)
                pc = memory.cpu_address(target, 4)
                continue
            if kind == 1:
                value = struct.unpack('<I', memory.read_cpu(pc + 4, 4))[0]
                command.update(kind='pds_state', words=[hex32(head), hex32(value)],
                               pds_gpu_address=hex32((head & 0x0fffffff) << 4),
                               data_bytes=(value >> 27) * 16, secondary=bool(value & 256),
                               mte_emit=bool(value & (1 << 17)), last_task=bool(head & (1 << 29)))
                try:
                    command['pds_cpu_address'] = hex32(memory.cpu_address((head & 0x0fffffff) << 4))
                except MissingMemory as error:
                    command['pds_mapping_error'] = str(error)
                pc += 8
            elif kind == 2:
                slots = [0, 1]
                for bit, extra in ((22, [2]), (23, [3]), (24, [4, 5]), (25, [6, 7])):
                    if head & (1 << bit):
                        slots.extend(extra)
                values = struct.unpack(f'<{len(slots)}I', memory.read_cpu(pc, len(slots) * 4))
                values_by_slot = dict(zip(slots, values))
                primitive = (head >> 26) & 15
                index_bits = 32 if values_by_slot.get(2, 0) & (1 << 24) else 16
                index_gpu = values[1] & (0xfffffffc if index_bits == 32 else 0xfffffffe)
                count = head & 0x3fffff
                command.update(kind='indexed_draw', draw_index=len(result['draws']),
                               count=count, primitive_code=primitive,
                               primitive=PRIMITIVES.get(primitive, 'unknown'),
                               index_bits=index_bits, index_gpu_address=hex32(index_gpu),
                               slots=slots, words=[hex32(value) for value in values])
                # Native handles an optional instance-count word separately.
                if 3 in values_by_slot:
                    command['instance_count_raw'] = values_by_slot[3] & 0x3fffff
                try:
                    index_data = memory.read_gpu(index_gpu, count * (index_bits // 8))
                    command.update(indices_captured=True, indices_sha256=hashlib.sha256(index_data).hexdigest(),
                                   index_preview=list(struct.unpack(f'<{min(count, 32)}' + ('I' if index_bits == 32 else 'H'),
                                                       index_data[:min(count, 32) * (index_bits // 8)])))
                except MissingMemory as error:
                    command.update(indices_captured=False, index_error=str(error))
                if 4 in values_by_slot:
                    command.update(pds_gpu_address=hex32((values_by_slot[4] & 0x0fffffff) << 4),
                                   data_bytes=(values_by_slot[5] & 31) * 16)
                    try:
                        command['pds_cpu_address'] = hex32(memory.cpu_address((values_by_slot[4] & 0x0fffffff) << 4))
                    except MissingMemory as error:
                        command['pds_mapping_error'] = str(error)
                result['draws'].append(command)
                pc += len(slots) * 4
            else:
                command['kind'] = 'terminate'
                result['commands'].append(command)
                result['terminated'] = True
                return result
            result['commands'].append(command)
        raise MissingMemory(f'VDM command limit {limit} reached without termination')
    except MissingMemory as error:
        result['error'] = str(error)
    return result


def decode_gxp(memory, program, file_bytes):
    address = int(program['program_cpu_address'], 16)
    header = memory.read_cpu(address, 0x94)
    if header[:4] != b'GXP\0':
        raise FormatError(f'Program at {address:#x} does not have a GXP header')
    size = struct.unpack_from('<I', header, 8)[0]
    if size < 0x94 or size > file_bytes:
        raise FormatError(f'Invalid GXP length {size} at {address:#x}')
    blob = memory.read_cpu(address, size)
    flags = struct.unpack_from('<I', header, 0x14)[0]
    pa, sa, temps, unknown_36 = struct.unpack_from('<4H', header, 0x30)
    parameter_count = struct.unpack_from('<I', header, 0x24)[0]
    parameter_offset = 0x28 + struct.unpack_from('<I', header, 0x28)[0]
    if parameter_count and (parameter_offset < 0x94 or parameter_offset + parameter_count * 16 > size):
        raise FormatError(f'GXP parameter table exceeds program at {address:#x}')
    code = {}
    for label, count_offset, relative_offset in (('primary', 0x3c, 0x40), ('secondary', 0x44, 0x48)):
        count = struct.unpack_from('<I', header, count_offset)[0]
        offset = relative_offset + struct.unpack_from('<I', header, relative_offset)[0]
        if count and (offset < 0x94 or offset + count * 8 > size):
            raise FormatError(f'GXP {label} instruction range exceeds program at {address:#x}')
        code[label] = dict(instructions=count, offset=offset, bytes=count * 8)
    result = dict(size=size, sha256=hashlib.sha256(blob).hexdigest(),
                  stage='fragment' if flags & 1 else 'vertex', flags=hex32(flags),
                  primary_registers=pa, secondary_registers=sa, temporary_registers=temps,
                  gxp_u16_36=unknown_36, parameter_count=parameter_count,
                  parameter_offset=parameter_offset, code=code)
    if (pa, sa, temps, parameter_count) != (program['primary_registers'], program['secondary_registers'],
                                           program['temporary_registers'], program['parameter_count']):
        raise FormatError(f'GXP fields disagree with native program metadata at {address:#x}')
    return result, blob


class Capture:
    def __init__(self, data, vdm_limit=65536):
        self.data, self.program_blobs = data, []
        self.document = dict(format='Sony Razor SGX', version=2, size=len(data),
                             sha256=hashlib.sha256(data).hexdigest(),
                             timings_available=False, sections=[], scenes=[], warnings=[])
        scene, footer = None, False
        for offset, tag, payload in sections(data):
            record = decode_section(offset, tag, payload)
            kind = tag & 255
            if footer:
                raise FormatError(f'Section follows file footer at {offset:#x}')
            if not self.document['sections']:
                if kind != 0 or record['version'] != 2:
                    raise FormatError('Expected Sony Razor v2 file header')
            elif kind == 0:
                raise FormatError(f'Duplicate file header at {offset:#x}')
            if kind == 1:
                if scene is not None:
                    raise FormatError(f'New scene before previous scene end at {offset:#x}')
                scene = dict(index=len(self.document['scenes']), frame=record['frame'],
                             begin_offset=offset, scene_index_byte=record['scene_index_byte'],
                             sections=[], mappings=[], memory=[], memory_failures=[],
                             memory_complete=False,
                             programs=[], parameters=[], resources=[], render_targets=[], streams=[])
                self.document['scenes'].append(scene)
            if scene is not None:
                record['scene'] = scene['index']
                scene['sections'].append(len(self.document['sections']))
                category = {2: 'streams', 3: 'mappings', 4: 'memory', 0x0f: 'programs',
                            0x17: 'parameters', 0x18: 'memory_failures', 0x15: 'render_targets'}.get(kind)
                if category:
                    scene[category].append(record)
                elif kind in (5, 0x0b, 0x0d, 0x11, 0x12, 0x14, 0x1b, 0x1c, 0x1d, 0x1f):
                    scene['resources'].append(record)
                elif kind == 0x1a:
                    scene['clip'] = record['clip']
            elif kind in (2, 3, 4, 0x0e, 0x0f, 0x17, 0x18, 0x19):
                raise FormatError(f'Scene section outside scene at {offset:#x}')
            self.document['sections'].append(record)
            if tag >> 24 != 0x80:
                self.document['warnings'].append(f'Unverified tag flags {tag >> 24:#x} at {offset:#x}')
            if kind == 0x0e:
                if not scene['memory_complete']:
                    raise FormatError(f'Scene ends without memory-end marker at {offset:#x}')
                scene['end_offset'] = offset + 8 + len(payload)
                scene = None
            elif kind == 0x19:
                if scene['memory_complete']:
                    raise FormatError(f'Duplicate memory-end marker at {offset:#x}')
                scene['memory_complete'] = True
            elif kind == 7:
                if scene is not None:
                    raise FormatError('File footer before scene end')
                footer = True
        if not footer or scene is not None:
            raise FormatError('Snapshot is incomplete: missing file or scene footer')
        for scene in self.document['scenes']:
            memory = Memory(data, scene)
            for program in scene['programs']:
                program['parameters'] = [parameter for parameter in scene['parameters']
                                         if parameter['program_cpu_address'] == program['program_cpu_address']]
                try:
                    program['gxp'], blob = decode_gxp(memory, program, len(data))
                    self.program_blobs.append((scene['index'], program, blob))
                except (MissingMemory, FormatError) as error:
                    program['gxp_error'] = str(error)
            if vdm_limit:
                scene['vdm'] = [decode_vdm(memory, int(stream['vdm_cpu_address'], 16), vdm_limit)
                                for stream in scene['streams']]
        self.document['summary'] = self.summarize()

    def summarize(self):
        scenes = self.document['scenes']
        return dict(bytes=len(self.data), sha256=self.document['sha256'], scenes=len(scenes),
                    sections=len(self.document['sections']), timings_available=False,
                    section_counts=dict(sorted(Counter(r['tag'] for r in self.document['sections']).items())),
                    mappings=sum(len(s['mappings']) for s in scenes),
                    memory_ranges=sum(len(s['memory']) for s in scenes),
                    captured_bytes=sum(r['bytes'] for s in scenes for r in s['memory']),
                    memory_read_failures=sum(len(s['memory_failures']) for s in scenes),
                    programs=sum(len(s['programs']) for s in scenes),
                    recovered_gxp_programs=len(self.program_blobs),
                    program_parameters=sum(len(s['parameters']) for s in scenes),
                    uniform_bindings=sum(r['kind'] == 'uniform_binding' for s in scenes for r in s['resources']),
                    scene_details=[dict(index=s['index'], frame=s['frame'], clip=s.get('clip'),
                                        targets=[dict(width=r['width'], height=r['height']) for r in s['render_targets']],
                                        programs=len(s['programs']), memory_ranges=len(s['memory']),
                                        indexed_draws=sum(len(v['draws']) for v in s.get('vdm', [])),
                                        vdm_terminated=bool(s.get('vdm')) and all(v['terminated'] for v in s['vdm']),
                                        vdm_errors=[v['error'] for v in s.get('vdm', []) if 'error' in v]) for s in scenes])

    def extract(self, directory, programs=False):
        directory.mkdir(parents=True, exist_ok=True)
        manifest = []
        if programs:
            for scene, program, blob in self.program_blobs:
                name = f'scene-{scene:03d}-{int(program["program_cpu_address"], 16):08x}-{program["gxp"]["stage"]}.gxp'
                (directory / name).write_bytes(blob)
                manifest.append(dict(file=name, scene=scene, cpu_address=program['program_cpu_address'],
                                     **program['gxp']))
        else:
            for scene in self.document['scenes']:
                for record in scene['memory']:
                    name = f'scene-{scene["index"]:03d}-{int(record["cpu_start"], 16):08x}.bin'
                    offset, size = record['data_offset'], record['bytes']
                    (directory / name).write_bytes(self.data[offset:offset + size])
                    manifest.append(dict(file=name, scene=scene['index'], cpu_start=record['cpu_start'],
                                         cpu_end_exclusive=record['cpu_end_exclusive'], bytes=size,
                                         sha256=record['sha256']))
        (directory / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--json', type=Path, help='write decoded container, memory map and draws')
    parser.add_argument('--extract-memory', type=Path, metavar='DIR')
    parser.add_argument('--extract-programs', type=Path, metavar='DIR')
    parser.add_argument('--vdm-limit', type=int, default=65536, help='maximum commands per stream; 0 disables VDM')
    args = parser.parse_args()
    if args.vdm_limit < 0:
        parser.error('--vdm-limit must be nonnegative')
    try:
        capture = Capture(args.capture.read_bytes(), args.vdm_limit)
        print(json.dumps(capture.document['summary'], indent=2))
        if args.json:
            args.json.parent.mkdir(parents=True, exist_ok=True)
            args.json.write_text(json.dumps(capture.document, indent=2, allow_nan=False) + '\n')
        if args.extract_memory:
            capture.extract(args.extract_memory)
        if args.extract_programs:
            capture.extract(args.extract_programs, programs=True)
    except (OSError, ValueError) as error:
        parser.exit(1, f'{error}\n')


if __name__ == '__main__':
    main()
