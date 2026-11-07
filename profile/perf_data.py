#!/usr/bin/env python3
"""Convert a Vita CPU profile to a Linux perf.data file, for hotspot or perf report.

Two inputs:
- psp2prof's capture (NAME.p2pf, psp2prof.py): every core, user and kernel, with the
  syscall's user caller as a callchain. Each process gets the kernel's modules and its own
  as perf maps (/tmp/perf-PID.map, 128-byte blocks named MODULE+OFFSET); the module named
  --module (default: the ELF's file name) is mapped to --elf, so perf symbolizes it itself.
- vita_prof.py's DTrace samples (OUT.samples) of one process, or unwind_snapshots.py's
  (their OUT.stacks.jsonl become callchains). The process and its text address come from
  deci4p_host.py's log of the launch (--deci-log) or --pid and --base.

    profile/perf_data.py RUN/race.p2pf --elf app.elf
    profile/perf_data.py RUN/cfi.samples --elf app.elf --deci-log RUN/deci4p.log
    hotspot RUN/race.perf.data      # or: perf report -i RUN/race.perf.data --sort comm,dso,sym

Each sample is a cpu-clock event of the sampling period at its time, CPU and thread. The
app's addresses are moved back to the ELF's, so perf's symbols and perf annotate's offsets
match the ELF, which perf reads itself from the path in the mmap record.
"""
import argparse
import collections
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vita_prof import loadp_launch  # noqa: E402

# perf_event.h / perf's header.h.
PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_CLOCK = 1, 0
SAMPLE_IP, SAMPLE_TID, SAMPLE_TIME, SAMPLE_CALLCHAIN, SAMPLE_CPU, SAMPLE_PERIOD = 1 << 0, 1 << 1, 1 << 2, 1 << 5, 1 << 7, 1 << 8
ATTR_MMAP, ATTR_COMM = 1 << 8, 1 << 9
RECORD_MMAP, RECORD_COMM, RECORD_SAMPLE = 1, 3, 9
MISC_KERNEL, MISC_USER = 1, 2
CONTEXT_KERNEL, CONTEXT_USER = 0xffffffffffffff80, 0xfffffffffffffe00
ATTR_SIZE = 136  # PERF_ATTR_SIZE_VER8
HEADER_SIZE = 104


def read_samples(path: Path):
    """vita_prof.py's rows: (cpu, nanoseconds, user PC, kernel PC, thread, process)."""
    with path.open() as source:
        if source.readline().split() != ['cpu', 'timestamp', 'upc', 'kpc', 'tid', 'pid']:
            raise ValueError(f'{path}: unsupported sample columns')

        return [tuple(int(value, 0) for value in line.split()) for line in source if line.strip()]


def read_stacks(path: Path):
    """Sample row -> frames (the interrupted PC, then return addresses)."""
    stacks = {}

    if path.exists():
        for line in path.read_text().splitlines():
            if line.strip():
                stack = json.loads(line)
                stacks[stack['sample_index']] = stack['frames']

    return stacks


def load_segments(elf: Path):
    """The ELF's PT_LOAD segments: (vaddr, memsz, file offset, executable)."""
    data = elf.read_bytes()

    if data[:7] != b'\x7fELF\x01\x01\x01':
        raise ValueError(f'{elf} is not a little-endian ELF32 file')

    phoff = struct.unpack_from('<I', data, 28)[0]
    phsize, phcount = struct.unpack_from('<HH', data, 42)
    segments = []

    for index in range(phcount):
        kind, offset, vaddr, _, _, memsz, flags, _ = struct.unpack_from('<8I', data, phoff + index * phsize)

        if kind == 1:
            segments.append((vaddr, memsz, offset, bool(flags & 1)))

    return segments


def record(kind, misc, payload):
    payload += bytes((-len(payload)) % 8)
    return struct.pack('<IHH', kind, misc, 8 + len(payload)) + payload


def text(value: str, limit=4095):
    raw = value.encode()[:limit] + b'\0'
    return raw + bytes((-len(raw)) % 8)


def attr(period_ns: int):
    """perf_event_attr: cpu-clock at the sampler's period, with mmap and comm records."""
    sample_type = SAMPLE_IP | SAMPLE_TID | SAMPLE_TIME | SAMPLE_CALLCHAIN | SAMPLE_CPU | SAMPLE_PERIOD
    fields = struct.pack('<IIQQQQQ', PERF_TYPE_SOFTWARE, ATTR_SIZE, PERF_COUNT_SW_CPU_CLOCK, period_ns, sample_type, 0, ATTR_MMAP | ATTR_COMM)
    return fields + bytes(ATTR_SIZE - len(fields))


def caller(pc: int):
    """A return address as its call instruction: the calling function, not the next one."""
    return (pc & ~1) - (2 if pc & 1 else 4)


def convert(rows, stacks, elf: Path, pid: int, base: int, hz: int, names: dict, comm: str, output: Path):
    segments = load_segments(elf)

    # The Vita's load address of the ELF's text: every app address moves
    # back by the difference.
    delta = base - min(s[0] for s in segments)
    app = [(vaddr + delta, vaddr + delta + memsz) for vaddr, memsz, _, _ in segments]

    def relocate(pc):
        return pc - delta if any(start <= pc < end for start, end in app) else pc

    period = round(1e9 / hz)
    events = [record(RECORD_COMM, MISC_USER, struct.pack('<II', pid, pid) + text(comm, 15))]

    for vaddr, memsz, offset, executable in segments:
        if executable:
            events.append(record(RECORD_MMAP, MISC_USER, struct.pack('<IIQQQ', pid, pid, vaddr, memsz, offset) + text(str(elf.resolve()))))

    named = set()
    start = min((row[1] for row in rows if row[5] == pid), default=0)
    written = with_stacks = 0

    for index, (cpu, nanoseconds, upc, kpc, tid, process) in enumerate(rows):
        pc = upc or kpc

        if process != pid or pc in (0, 0xffffffff):
            continue  # another process, or a core the sampler could not read

        if tid not in named:
            named.add(tid)
            events.append(record(RECORD_COMM, MISC_USER, struct.pack('<II', pid, tid) + text(names.get(tid, f'thread-{tid:08x}'), 15)))

        kernel = not upc
        ip = relocate(pc & ~1)
        chain = [CONTEXT_KERNEL if kernel else CONTEXT_USER, ip]

        if not kernel and index in stacks:
            chain += [relocate(caller(frame)) for frame in stacks[index][1:]]
            with_stacks += 1

        payload = struct.pack('<QIIQIIQQ', ip, pid, tid, nanoseconds - start, cpu, 0, period, len(chain))
        payload += struct.pack(f'<{len(chain)}Q', *chain)
        events.append(record(RECORD_SAMPLE, MISC_KERNEL if kernel else MISC_USER, payload))
        written += 1

    write_perf(output, period, events)
    print(f'Wrote {written} samples ({with_stacks} with stacks) at {hz} Hz to {output}')


P2PF_SAMPLE = struct.Struct('<8I')  # time, pc, thid, pid, cpu | seq << 2, svc, user pc, user lr
# time, thid, status, wait type, wait id, svc, user pc, user lr, then 8 kernel return
# addresses below the syscall frame, 0 after the last (psp2prof waits=PID)
P2PF_WAIT = struct.Struct('<16I')
KERNEL_PID = 0x10005
BLOCK = 128


# Cortex-A9 PMU events (Technical Reference Manual r2p2, Performance Monitoring Unit: the
# architectural events and the Cortex-A9's own), by number, for psp2prof's PMU counts.
PMU_EVENT_NAMES = {
    0x00: 'sw-incr', 0x01: 'l1i-refill', 0x02: 'itlb-refill', 0x03: 'l1d-refill',
    0x04: 'l1d-access', 0x05: 'dtlb-refill', 0x06: 'loads', 0x07: 'stores',
    0x09: 'exceptions', 0x0A: 'exception-returns', 0x0B: 'contextidr-writes',
    0x0C: 'pc-writes', 0x0D: 'immediate-branches', 0x0F: 'unaligned', 0x10: 'branch-mispredicts',
    0x11: 'cycles', 0x12: 'predictable-branches',
    0x50: 'coherent-linefill-misses', 0x51: 'coherent-linefill-hits',
    0x60: 'icache-stall-cycles', 0x61: 'dcache-stall-cycles', 0x62: 'tlb-miss-stall-cycles',
    0x63: 'strex-passed', 0x64: 'strex-failed', 0x65: 'data-evictions',
    0x66: 'issue-no-dispatch', 0x67: 'issue-empty', 0x68: 'instructions-renamed',
    0x6E: 'predictable-returns', 0x70: 'main-unit-instructions', 0x71: 'second-unit-instructions',
    0x72: 'load-store-instructions', 0x73: 'fp-instructions', 0x74: 'neon-instructions',
    0x80: 'pld-stall-cycles', 0x81: 'write-stall-cycles', 0x82: 'itlb-main-stall-cycles',
    0x83: 'dtlb-main-stall-cycles', 0x84: 'itlb-micro-stall-cycles',
    0x85: 'dtlb-micro-stall-cycles', 0x86: 'dmb-stall-cycles', 0x8A: 'integer-clock-cycles',
    0x8B: 'data-engine-clock-cycles', 0x90: 'isb', 0x91: 'dsb', 0x92: 'dmb',
    0x93: 'external-interrupts',
}
PMU_EVENT_NUMBERS = {name: number for number, name in PMU_EVENT_NAMES.items()}
# A PMUS record's entry: core | read sequence << 2 (as its SMPL sample's cpu word), the six event
# counters, the cycle counter.
P2PF_PMU = struct.Struct('<8I')


def pmu_event(text):
    """An event by name (PMU_EVENT_NAMES) or number (0x03, 3)."""
    return PMU_EVENT_NUMBERS[text] if text in PMU_EVENT_NUMBERS else int(text, 0)


def read_p2pf(path: Path):
    data = path.read_bytes()
    magic, version, hz, cores, auth = struct.unpack_from('<4sIIII', data)
    if magic != b'P2PF' or version != 1:
        raise ValueError(f'{path}: not a psp2prof capture')
    capture = dict(hz=hz, cores=cores, auth=auth, samples=[], threads={}, dropped=0,
                   modules=collections.defaultdict(list), complete=False, waits=[],
                   wait_dropped=0, watched=0, wait_objects={}, pmu_events=[], pmu_cores=0,
                   pmu=[], pmu_dropped=0, pmu_failed=0, snapshots=[])
    at = 32
    while at + 8 <= len(data):
        tag, size = struct.unpack_from('<4sI', data, at)
        payload = data[at + 8:at + 8 + size]
        at += 8 + size + (-size % 4)
        if tag == b'SMPL':
            capture['samples'].extend(P2PF_SAMPLE.iter_unpack(payload))
        elif tag == b'DROP':
            capture['dropped'] += struct.unpack_from('<I', payload)[0]
        elif tag == b'WAIT':
            capture['waits'].extend(P2PF_WAIT.iter_unpack(payload))
        elif tag == b'WDRP':
            capture['wait_dropped'], capture['watched'] = struct.unpack_from('<2I', payload)
        elif tag == b'WOBJ':
            # wait id, wait type -> (result of the Get*Info call, name)
            wait_id, wait_type, result = struct.unpack_from('<IIi', payload)
            capture['wait_objects'][(wait_id, wait_type)] = (
                result, payload[12:44].split(b'\0')[0].decode(errors='replace'))
        elif tag == b'THRD':
            thid, pid = struct.unpack_from('<II', payload)
            capture['threads'][thid] = (pid, payload[8:40].split(b'\0')[0].decode(errors='replace'))
        elif tag == b'MODL':
            pid, vaddr, memsz, perms = struct.unpack_from('<4I', payload)
            name = payload[16:44].split(b'\0')[0].decode(errors='replace')
            capture['modules'][pid].append((vaddr, memsz, perms, name))
        elif tag == b'PMUC':
            count, *events, mask = struct.unpack_from('<8I', payload)
            capture['pmu_events'], capture['pmu_cores'] = events[:count], mask
        elif tag == b'PMUS':
            capture['pmu'].extend(P2PF_PMU.iter_unpack(payload))
        elif tag == b'STAK':
            # the snapshot's time and core (unwind_snapshots.py reads the rest)
            when, _, _, cpu = struct.unpack_from('<4I', payload)
            capture['snapshots'].append((when, cpu & 3))
        elif tag == b'PDRP':
            capture['pmu_dropped'], capture['pmu_failed'] = struct.unpack_from('<2I', payload)
        elif tag == b'END ':
            capture['complete'] = True
            break
    return capture


def convert_p2pf(capture, elf: Path, module: str, output: Path):
    """psp2prof's capture: every process with the kernel's modules and its own mapped."""
    hz, kernel = capture['hz'], capture['modules'].get(KERNEL_PID, [])
    # A core read while it switched threads names no process: the kernel's.
    capture['samples'] = [s if s[3] != 0xFFFFFFFF else s[:3] + (KERNEL_PID,) + s[4:]
                          for s in capture['samples']]
    period = round(1e9 / hz)
    linked = load_segments(elf) if elf else []
    linked_text = min((v for v, _, _, x in linked if x), default=None)
    pids = sorted({s[3] for s in capture['samples']})
    events, deltas, maps = [], {}, []
    for pid in pids:
        own = capture['modules'].get(pid, []) if pid != KERNEL_PID else []
        app = [m for m in own if m[3] == module and m[2] & 1]
        comm = 'kernel' if pid == KERNEL_PID else (module if app else (own[0][3] if own else f'pid-{pid:x}'))
        events.append(record(RECORD_COMM, MISC_USER, struct.pack('<II', pid, pid) + text(comm, 15)))
        if app and linked_text is not None:
            deltas[pid] = (min(v for v, _, _, _ in app) - linked_text,
                           [(v, v + n) for v, n, _, _ in app])
            for vaddr, memsz, offset, executable in linked:
                if executable:
                    events.append(record(RECORD_MMAP, MISC_USER, struct.pack('<IIQQQ', pid, pid, vaddr, memsz, offset)
                                         + text(str(elf.resolve()))))
        # Everything else executable, the kernel included (mapped into every process), as
        # anonymous memory that perf names from /tmp/perf-PID.map.
        lines = []
        for vaddr, memsz, perms, name in kernel + [m for m in own if m[3] != module or not app]:
            if not perms & 1 or not memsz:
                continue
            events.append(record(RECORD_MMAP, MISC_USER, struct.pack('<IIQQQ', pid, pid, vaddr, memsz, 0) + text('//anon')))
            lines += [f'{vaddr + off:x} {min(BLOCK, memsz - off):x} {name}+{off:#x}' for off in range(0, memsz, BLOCK)]
        perf_map = Path(f'/tmp/perf-{pid}.map')
        perf_map.write_text('\n'.join(lines) + '\n')
        maps.append(perf_map)

    def relocate(pid, pc):
        delta = deltas.get(pid)
        return pc - delta[0] if delta and any(a <= pc < b for a, b in delta[1]) else pc

    named, written, unread, in_syscall = set(), 0, 0, 0
    first = capture['samples'][0][0] if capture['samples'] else 0
    epoch, last = 0, first
    for when, pc, thid, pid, cpu, svc, user_pc, user_lr in capture['samples']:
        if when < last and last - when > 0x80000000:
            epoch += 1 << 32  # the microsecond counter wrapped
        last = when
        if pc == 0xFFFFFFFF:
            unread += 1
            continue
        if (pid, thid) not in named:
            named.add((pid, thid))
            name = capture['threads'].get(thid, (pid, f'thread-{thid:08x}'))[1] or f'thread-{thid:08x}'
            events.append(record(RECORD_COMM, MISC_USER, struct.pack('<II', pid, thid) + text(name, 15)))
        # The Cortex-A9's DBGPCSR reads the destination of the last branch its core executed (the
        # target, or the next instruction after a conditional branch not taken), word-aligned in
        # Thumb (bit 0 set), with no offset: the sample is in the block from there to the next
        # branch. Taken as read.
        ip = relocate(pid, pc & ~1)
        chain = [CONTEXT_USER, ip]
        if svc & 0x80000000 and ip < 0x40000000:
            # In a syscall: the svc instruction in its stub, then the stub's caller.
            # A frame read while the syscall began or ended can hold a zero PC or LR: left out.
            chain += [relocate(pid, (pc_ & ~1) - 2) for pc_ in (user_pc,) if pc_ >= 2]
            chain += [relocate(pid, caller(lr)) for lr in (user_lr,) if lr >= 4]
            in_syscall += 1
        payload = struct.pack('<QIIQIIQQ', ip, pid, thid, epoch + when - first, cpu & 3, 0, period, len(chain))
        events.append(record(RECORD_SAMPLE, MISC_USER, payload + struct.pack(f'<{len(chain)}Q', *chain)))
        written += 1
    write_perf(output, period, events)
    print(f'Wrote {written} samples ({in_syscall} in syscalls, {unread} unreadable cores, '
          f'{capture["dropped"]} dropped{"" if capture["complete"] else ", capture incomplete"}) '
          f'at {hz} Hz to {output}; perf maps: {", ".join(str(m) for m in maps)}')


def write_perf(output: Path, period: int, events):
    data = b''.join(events)
    attrs = attr(period) + struct.pack('<QQ', 0, 0)
    header = struct.pack('<8sQQ', b'PERFILE2', HEADER_SIZE, ATTR_SIZE + 16)
    header += struct.pack('<QQQQQQ', HEADER_SIZE, len(attrs), HEADER_SIZE + len(attrs), len(data), 0, 0)
    header += bytes(32)
    output.write_bytes(header + attrs + data)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('samples', type=Path, help="a psp2prof capture (.p2pf), or vita_prof.py's or unwind_snapshots.py's OUT.samples")
    parser.add_argument('--elf', type=Path, help='the unstripped ELF that ran (required for DTrace samples)')
    parser.add_argument('--module', help="psp2prof: the ELF's module name on the Vita (default: the ELF's file name)")
    parser.add_argument('--deci-log', type=Path, help="deci4p_host.py's log of the launch (the pid and the text base)")
    parser.add_argument('--pid', type=lambda v: int(v, 0), help='the process (default: from --deci-log)')
    parser.add_argument('--base', type=lambda v: int(v, 0), help="the ELF's text address on the Vita (default: from --deci-log)")
    parser.add_argument('--stacks', type=Path, help="callchains (default: the samples' .stacks.jsonl, when present)")
    parser.add_argument('--hz', type=int, help="the sampling rate (default: the capture's register-info.json, else 997)")
    parser.add_argument('--threads', type=Path, help='thread names: lines of "TID NAME" (TID in hex)')
    parser.add_argument('--out', type=Path, help="the perf.data to write (default: the samples' .perf.data)")
    args = parser.parse_args()
    if args.samples.read_bytes()[:4] == b'P2PF':
        convert_p2pf(read_p2pf(args.samples), args.elf, args.module or (args.elf.stem if args.elf else ''),
                     args.out or args.samples.with_suffix('.perf.data'))
        return
    if not args.elf:
        parser.error('DTrace samples need --elf')
    pid, base = loadp_launch(args.deci_log) if args.deci_log else (None, None)
    pid = args.pid if args.pid is not None else pid
    base = args.base if args.base is not None else base
    if pid is None or base is None:
        parser.error('no process: give --deci-log with a LOADP launch, or --pid and --base')
    hz = args.hz
    if hz is None:
        info = [i for i in args.samples.parent.glob('*.register-info.json')
                if args.samples.name.startswith(i.name.removesuffix('.register-info.json'))]
        hz = json.loads(info[0].read_text())['hz'] if info else 997
    names = {}
    if args.threads:
        for line in args.threads.read_text().splitlines():
            if line.strip():
                tid, name = line.split(None, 1)
                names[int(tid, 16)] = name.strip().replace(' ', '-')
    stacks = args.stacks or args.samples.with_suffix('.stacks.jsonl')
    convert(read_samples(args.samples), read_stacks(stacks), args.elf, pid, base, hz, names,
            args.elf.stem, args.out or args.samples.with_suffix('.perf.data'))


if __name__ == '__main__':
    main()
