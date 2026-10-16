#!/usr/bin/env python3
"""Unwind vita_prof.py's register snapshots on the host with the ELF's DWARF CFI.

Reads a register capture (vita_prof.py --registers: OUT.register-info.json, its
.registers.jsonl and .stack.bin) and the exact unstripped ELF that ran (its .debug_frame;
any -g level, -gline-tables-only included). Writes OUT.samples, OUT.stacks.jsonl (each
snapshot's frames: the PC, then return addresses) and OUT.cfi-info.json. perf_data.py
turns them into perf.data callchains.

    profile/unwind_snapshots.py --info RUN/prof.register-info.json --elf app.elf --out RUN/cfi

Unwinding goes through elfutils' libdwfl (libdw.so.1, arm32_cfi.py): it never scans a
stack for plausible addresses or guesses LR, and stops where the captured bytes end.
"""
import argparse
from bisect import bisect_right
from collections import Counter
import json
from pathlib import Path
import re
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import arm32_cfi as engine  # noqa: E402
import elf32 as packaging  # noqa: E402

MAX_BYTES = 32768
VERSION = 1


def require(condition, message):
    if not condition:
        raise ValueError(message)


class VitaElf:
    """Explicit SHA identity for Vita executables without a GNU build-ID note."""
    def __init__(self, path, expected_sha):
        self.path = Path(path)
        elf = packaging.Elf(self.path, 2)
        self.sha256 = packaging.sha(elf.data)
        require(isinstance(expected_sha, str) and re.fullmatch(r'[0-9a-f]{64}', expected_sha)
                and self.sha256 == expected_sha, 'Recorded/local ELF SHA-256 mismatch')
        self.kind = 2
        self.loads = [(p.offset, p.address, p.filesz, p.memsz, p.flags) for p in elf.loads]
        self.base = min(p.address for p in elf.loads)
        self.code = []
        for section in elf.sections.values():
            if section.flags & 6 == 6 and section.size:
                require(section.kind == 1 and any(p.flags & 1 and elf.mapped(section,p)
                                                  for p in elf.loads), 'Unmapped executable section')
                self.code.append(section)
        require(self.code, 'ELF has no mapped executable sections')
        self.unwind_sections = {name:s.size for name,s in elf.sections.items()
                                if name in ('.debug_frame','.eh_frame','.ARM.exidx','.ARM.extab')}
        require(any(self.unwind_sections.get(n,0) for n in ('.debug_frame','.eh_frame')),
                'ELF has no DWARF CFI; EHABI-only input is unsupported by this engine')
        # Preserve ELF section indices. The packaging parser rejects duplicates
        # and retains original order; its dictionary excludes section zero.
        sections = [None] + list(elf.sections.values())
        symbols = set()
        for section in sections[1:]:
            if section.kind not in (2,11):
                continue
            require(section.entry_size == 16 and section.size % 16 == 0 and
                    0 < section.link < len(sections), 'Invalid ELF symbol table')
            strings = sections[section.link]
            require(strings.kind == 3, 'Invalid ELF symbol string table')
            names = elf.extent(strings.offset,strings.size,'symbol names')
            for at in range(section.offset,section.offset+section.size,16):
                name,value,size,info,_other,index = struct.unpack_from('<IIIBBH',elf.data,at)
                if info & 15 != 2 or not index:
                    continue
                require(name < len(names) and names.find(b'\0',name) >= 0,
                        'Invalid ELF function name')
                label = names[name:names.find(b'\0',name)].decode(errors='replace')
                symbols.add((value & ~1,size,label))
        self.symbols = sorted(symbols)
        self.symbol_starts = [s[0] for s in self.symbols]

    def symbol(self, address):
        at = bisect_right(self.symbol_starts,address)-1
        if at >= 0:
            start,size,name = self.symbols[at]
            if size and address < start+size:
                return name
        return f'[{self.path.name}+{address:#x}]'


def input_file(directory, info, name, hash_name):
    filename = info[name]
    require(isinstance(filename,str) and filename and Path(filename).name == filename,
            f'Invalid capture filename {name}')
    data = (directory/filename).read_bytes()
    require(packaging.sha(data) == info[hash_name], f'Capture hash mismatch: {name}')
    return data


def read_capture(path):
    path = Path(path)
    info = json.loads(path.read_text())
    require(isinstance(info,dict), 'Raw capture info must be an object')
    require(type(info.get('schema_version')) is int and info['schema_version'] == VERSION,
            'Unsupported raw capture version')
    require(type(info.get('selected_pid')) is int and 0 < info['selected_pid'] <= 0x7fffffff,
            'A recorded single-process PID filter is required; --all captures are raw-only')
    size = info['requested_stack_bytes']
    require(type(size) is int and (size == 0 or 16 <= size <= MAX_BYTES and size % 4 == 0),
            'Invalid requested snapshot size')
    require(type(info['hz']) is int and info['hz'] > 0, 'Invalid capture rate')
    require(info.get('unwind_status') == 'raw_unwound_pending' and
            type(info.get('with_derived_callers')) is int and info['with_derived_callers'] == 0,
            'Capture info is not an unmodified raw snapshot stream')
    for name in ('primary_samples','primary_user_samples','raw_events','consistent_context_events',
                 'aggregate_errors','aggregate_drops'):
        require(type(info.get(name)) is int and info[name] >= 0, f'Invalid capture count: {name}')
    require(info['primary_user_samples'] <= info['primary_samples'], 'Invalid primary sample counts')
    manifest = input_file(path.parent,info,'register_manifest','register_manifest_sha256')
    blob = input_file(path.parent,info,'stack_binary','stack_binary_sha256')
    samples = input_file(path.parent,info,'snapshot_samples','snapshot_samples_sha256')
    require(type(info['stack_binary_size']) is int and len(blob) == info['stack_binary_size'],
            'Stack binary size differs')
    rows = [json.loads(line) for line in manifest.splitlines() if line.strip()]
    require(type(info['raw_events']) is int and len(rows) == info['raw_events'], 'Raw event count differs')
    generated = ['cpu timestamp upc kpc tid pid']
    offset = 0
    for index,row in enumerate(rows):
        require(isinstance(row,dict), 'Raw event must be an object')
        require(type(row.get('schema_version')) is int and row['schema_version'] == VERSION
                and type(row.get('event_index')) is int
                and row['event_index'] == index, 'Invalid or duplicate raw event index/version')
        for name,bound in [('cpu',3),('timestamp',(1<<64)-1),('upc',0xffffffff),('kpc',0xffffffff),
                           ('tid',0x7fffffff),('pid',0x7fffffff)]:
            require(type(row.get(name)) is int and 0 <= row[name] <= bound, f'Invalid raw {name}')
        require(row['pid'] == info['selected_pid'], 'Raw PID differs from recorded process filter')
        require(row['tid'] > 0 and row['pid'] > 0 and 0x40000000 <= row['upc'] < 0xffffffff,
                'Invalid raw user event identity')
        regs = row['registers']
        require(isinstance(regs,list) and len(regs) == 16 and
                all(type(v) is int and 0 <= v <= 0xffffffff for v in regs), 'Invalid raw ARM32 registers')
        require(type(row['stack_address']) is int and row['stack_address'] == regs[13],
                'Stack address differs from exact captured SP')
        require(type(row['stack_offset']) is int and row['stack_offset'] == offset and
                type(row['stack_size']) is int and row['stack_size'] == size and
                offset+size <= len(blob), 'Invalid stack binary extent')
        require(row.get('unwind_status') == 'raw_unwound_pending', 'Input is not a raw snapshot event')
        reason = None
        if regs[15] & ~1 != row['upc'] & ~1:
            reason = 'register_pc_mismatch'
        elif not 0x40000000 <= regs[13] < 0xffffffff or regs[13] % 4:
            reason = 'invalid_user_stack_pointer'
        elif regs[13]+size > 0xffffffff:
            reason = 'stack_address_overflow'
        require(row.get('context_error') == reason, 'Raw context status differs from captured registers')
        row['raw_stack'] = blob[offset:offset+size]
        offset += size
        values = [row[n] for n in ('cpu','timestamp','upc','kpc','tid','pid')]
        generated.append(' '.join(str(v) if i == 0 else f'{v:#x}' for i,v in enumerate(values)))
    require(offset == len(blob), 'Unreferenced stack binary bytes')
    require(info['consistent_context_events'] == sum(r['context_error'] is None for r in rows),
            'Consistent context count differs')
    require(samples == ('\n'.join(generated)+'\n').encode(), 'Snapshot samples differ from raw event identities')
    return info,rows,samples


class DwarfOp(engine.C.Structure):
    _fields_ = [('atom',engine.C.c_uint8),('number',engine.U),
                ('number2',engine.U),('offset',engine.U)]


class RawCfiObserver:
    """Recover exact return bits from declared CFI, checked against libdwfl.

    libdwfl masks ARM CIE return registers before publishing caller state.
    Public libdw APIs expose the original register location. Support ordinary
    register/CFA-offset rules explicitly; reject other expressions visibly.
    No executable bytes, guessed frame chain or candidate stack words are read.
    """
    def __init__(self,sample):
        self.sample = sample
        self.expected = sample.regs[15]
        self.previous_column = None
        self.previous_raw_return = None
        self.lib = None
        self.error = None
        self.cstdlib = engine.C.CDLL(None)
        self.cstdlib.free.argtypes = [engine.P]
        self.cstdlib.free.restype = None

    def initialize(self,context):
        self.lib = context.lib
        op_pointer = engine.C.POINTER(DwarfOp)
        signatures = {
            'dwfl_module_eh_cfi':(engine.P,[engine.P,engine.C.POINTER(engine.U)]),
            'dwfl_module_dwarf_cfi':(engine.P,[engine.P,engine.C.POINTER(engine.U)]),
            'dwarf_cfi_addrframe':(engine.I,[engine.P,engine.U,engine.C.POINTER(engine.P)]),
            'dwarf_frame_info':(engine.I,[engine.P,engine.P,engine.P,engine.C.POINTER(engine.B)]),
            'dwarf_frame_cfa':(engine.I,[engine.P,engine.C.POINTER(op_pointer),engine.C.POINTER(engine.C.c_size_t)]),
            'dwarf_frame_register':(engine.I,[engine.P,engine.I,op_pointer,
                                            engine.C.POINTER(op_pointer),engine.C.POINTER(engine.C.c_size_t)]),
        }
        for name,(result,args) in signatures.items():
            fn = getattr(self.lib,name)
            fn.restype,fn.argtypes = result,args

    def register(self,state,number):
        require(0 <= number < 16,'raw_cfi_unsupported_register')
        # The only register value libdwfl deliberately masks is the prior
        # CIE's return column. Its exact value was already evaluated in CFI.
        if number == self.previous_column and self.previous_raw_return is not None:
            return self.previous_raw_return
        value = engine.U()
        require(self.lib.dwfl_frame_reg(state,number,engine.C.byref(value)) == 0,
                'raw_cfi_unavailable_register')
        require(value.value <= 0xffffffff,'raw_cfi_invalid_register')
        return value.value

    @staticmethod
    def signed(value):
        return value-(1<<64) if value & (1<<63) else value

    def cfa(self,state,frame):
        ops,count = engine.C.POINTER(DwarfOp)(),engine.C.c_size_t()
        require(self.lib.dwarf_frame_cfa(frame,engine.C.byref(ops),engine.C.byref(count)) == 0,
                'raw_cfi_unavailable_cfa')
        require(count.value == 1,'raw_cfi_unsupported_cfa_expression')
        op = ops[0]
        if 0x70 <= op.atom <= 0x7f:  # DW_OP_breg0..15.
            number,offset = op.atom-0x70,self.signed(op.number)
        elif op.atom == 0x92:  # DW_OP_bregx.
            number,offset = op.number,self.signed(op.number2)
        else:
            raise ValueError('raw_cfi_unsupported_cfa_expression')
        address = self.register(state,number)+offset
        require(0 <= address <= 0xffffffff,'raw_cfi_cfa_overflow')
        return address

    def memory(self,address):
        offset = address-self.sample.regs[13]
        require(0 <= address <= 0xfffffffc and 0 <= offset and offset+4 <= len(self.sample.stack),
                'raw_cfi_captured_stack_unavailable')
        return struct.unpack_from('<I',self.sample.stack,offset)[0]

    def return_pc(self,state,frame,column):
        memory = (DwarfOp*3)()
        ops,count = engine.C.POINTER(DwarfOp)(),engine.C.c_size_t()
        require(self.lib.dwarf_frame_register(frame,column,memory,engine.C.byref(ops),
                                              engine.C.byref(count)) == 0,
                'raw_cfi_unavailable_return_rule')
        if not count.value:
            if not ops:  # CFI same_value, including the interrupted frameless leaf.
                return self.register(state,column)
            raise ValueError('raw_cfi_undefined_return_register')
        require(count.value <= 3,'raw_cfi_unsupported_return_expression')
        rules = [(ops[i].atom,ops[i].number) for i in range(count.value)]
        if len(rules) == 1 and 0x50 <= rules[0][0] <= 0x5f:
            return self.register(state,rules[0][0]-0x50)
        if len(rules) == 1 and rules[0][0] == 0x90:  # DW_OP_regx.
            return self.register(state,rules[0][1])
        require(rules[0][0] == 0x9c,'raw_cfi_unsupported_return_expression')  # call_frame_cfa.
        address = self.cfa(state,frame)
        at = 1
        if at < len(rules) and rules[at][0] == 0x23:  # plus_uconst encodes signed CFI offsets.
            address += self.signed(rules[at][1])
            at += 1
        is_value = at < len(rules) and rules[at][0] == 0x9f  # DW_OP_stack_value.
        if is_value: at += 1
        require(at == len(rules),'raw_cfi_unsupported_return_expression')
        require(0 <= address <= 0xffffffff,'raw_cfi_return_address_overflow')
        return address if is_value else self.memory(address)

    def __call__(self,context,state,address,details):
        if self.lib is None: self.initialize(context)
        if self.expected is None:
            return self.error or 'raw_cfi_return_pc_unavailable'
        if (self.expected & ~1) != (details['pc'] & ~1):
            return 'raw_cfi_normalized_pc_mismatch'
        if context.frames and details['activation']:
            return 'raw_cfi_signal_frame_unsupported'
        details['raw_pc'] = self.expected
        frame = engine.P()
        try:
            module = self.lib.dwfl_addrmodule(context.handle,address)
            found = False
            # Match libdwfl priority: .eh_frame before .debug_frame.
            for name in ('dwfl_module_eh_cfi','dwfl_module_dwarf_cfi'):
                bias = engine.U()
                cfi = getattr(self.lib,name)(module,engine.C.byref(bias))
                if cfi and self.lib.dwarf_cfi_addrframe(cfi,address-bias.value,engine.C.byref(frame)) == 0:
                    found = True
                    break
            require(found,'raw_cfi_missing_frame')
            signal = engine.B()
            column = self.lib.dwarf_frame_info(frame,None,None,engine.C.byref(signal))
            require(not signal.value,'raw_cfi_signal_frame_unsupported')
            require(0 <= column < 16,'raw_cfi_unsupported_return_column')
            value = self.return_pc(state,frame,column)
            self.previous_column,self.previous_raw_return = column,value
            self.expected = value
            self.error = None
            details['raw_return_pc'],details['raw_return_column'] = value,column
            details['raw_return_status'] = 'declared_cfi_verified'
        except ValueError as error:
            self.expected,self.error = None,str(error)
            details['raw_return_status'] = self.error
        finally:
            if frame: self.cstdlib.free(frame)
        return None


def analyze(info_path,elf_path,output,max_depth=64):
    require(type(max_depth) is int and 1 <= max_depth <= 256, 'Depth must be 1..256')
    info,rows,samples = read_capture(info_path)
    elf = VitaElf(elf_path,info['recorded_elf_sha256'])
    require(type(info['loaded_text_base']) is int and info['loaded_text_base'] == elf.base,
            'Relocated/unknown ET_EXEC load base is unsupported (build the SELF with vita-make-fself -na)')
    original_sha = elf.sha256
    path = str(elf.path.resolve())
    mappings = [engine.Mapping(0,s.address,s.size,s.offset,5,path,'') for s in elf.code]
    stops,depths = Counter(),Counter()
    derived,diagnostics = [],[]
    callers = 0
    version = None
    for row in rows:
        frames = [row['upc']]
        flags = 2
        result = dict(event_index=row['event_index'],stop=row['context_error'],frames=[])
        if not row['context_error'] and any(m.contains(row['upc'] & ~1) for m in mappings):
            sample = engine.Sample(row['event_index'],row['stack_offset'],row['pid'],row['tid'],
                                   row['timestamp'],row['upc'],round(1e9/info['hz']),1,
                                   tuple(row['registers']),row['raw_stack'],len(row['raw_stack']))
            observer = RawCfiObserver(sample)
            context = engine.Dwfl({path:(elf,0)},mappings,max_depth,frame_observer=observer)
            try:
                result = context.unwind(sample)
                version = context.version
            finally:
                context.close()
            proven = [frame['raw_pc'] for frame in result['frames']]
            if observer.error and result['stop'] not in ('depth_limit','captured_stack_unavailable'):
                result['stop'] = observer.error
            require(not proven or (proven[0] & ~1) == (row['upc'] & ~1),
                    'CFI interrupted frame differs from native user PC')
            require(all(type(pc) is int and 0 < pc < 0xffffffff and pc & ~1 for pc in proven),
                    'CFI produced an invalid ARM32 PC')
            if proven:
                frames = [row['upc'],*proven[1:]]
                flags = (1 if result['stop'] == 'depth_limit' else
                         0 if result['stop'] in ('cfi_end','zero_return_pc') else 2)
        elif not row['context_error']:
            result['stop'] = 'unverified_interrupted_mapping'
        stops[result['stop']] += 1
        depths[len(frames)] += 1
        callers += len(frames) > 1
        derived.append(dict(sample_index=row['event_index'],flags=flags,frames=frames))
        diagnostics.append(result)
    output = Path(output)
    output.parent.mkdir(parents=True,exist_ok=True)
    Path(f'{output}.samples').write_bytes(samples)
    with Path(f'{output}.stacks.jsonl').open('w') as stream:
        for row in derived: stream.write(json.dumps(row)+'\n')
    with Path(f'{output}.cfi.jsonl').open('w') as stream:
        for row in diagnostics: stream.write(json.dumps(row)+'\n')
    report = dict(schema_version=VERSION,method='SHA-verified fixed ET_EXEC + libdwfl DWARF CFI; captured bytes only',
                  source_info=str(Path(info_path).resolve()),source_info_sha256=packaging.sha(Path(info_path).read_bytes()),
                  elf_sha256=original_sha,identity='Explicit SHA-256; no fabricated GNU build ID',
                  selected_pid=info['selected_pid'],loaded_text_base=elf.base,
                  unwind_sections=elf.unwind_sections,libdw_version=version,
                  engine_sha256=packaging.sha(Path(engine.__file__).read_bytes()),
                  primary_samples=info['primary_samples'],primary_user_samples=info['primary_user_samples'],
                  snapshot_events=len(rows),snapshot_events_with_callers=callers,
                  denominator_note='Snapshot events are independent of primary PC events; no timestamp pairing',
                  stops=dict(stops),depths=dict(depths),max_depth=max_depth,
                  aggregate_capture_errors=info['aggregate_errors'],aggregate_capture_drops=info['aggregate_drops'])
    Path(f'{output}.cfi-info.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--info',type=Path,required=True,help='vita_prof OUT.register-info.json')
    parser.add_argument('--elf',type=Path,required=True,help='the exact unstripped ELF that ran')
    parser.add_argument('--out',type=Path,required=True,help='Derived snapshot output prefix')
    parser.add_argument('--max-depth',type=int,default=64)
    args=parser.parse_args()
    print(json.dumps(analyze(args.info,args.elf,args.out,args.max_depth),indent=2))


if __name__ == '__main__':
    try:
        main()
    except (ValueError,OSError,KeyError,engine.FormatError) as error:
        sys.exit(f'unwind_snapshots: {error}')
