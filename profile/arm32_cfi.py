"""unwind_snapshots.py's engine: ARM32 user stacks unwound through elfutils' libdwfl.

Offline only: explicitly supplied ELF files and captured bytes. Uses DWARF CFI, never scans
a stack for plausible code addresses or guesses LR. Requires the host's libdw.so.1.
"""
import ctypes as C
import ctypes.util
from dataclasses import dataclass
import struct


class FormatError(ValueError):
    pass


def checked(data, at, size, label):
    if at < 0 or size < 0 or at + size > len(data):
        raise FormatError(f'{label}: truncated/out-of-range bytes at {at:#x}, size {size}')
    return data[at:at + size]


def unpack(fmt, data, at, label):
    checked(data, at, struct.calcsize(fmt), label)
    return struct.unpack_from(fmt, data, at)


@dataclass(frozen=True)
class Mapping:
    pid: int
    start: int
    length: int
    offset: int
    prot: int
    path: str
    build_id: str

    def contains(self, pc):
        return self.start <= pc < self.start + self.length


@dataclass
class Sample:
    index: int
    file_offset: int
    pid: int
    tid: int
    time: int
    ip: int
    period: int
    abi: int
    regs: tuple
    stack: bytes
    allocated_stack: int



P, U, I, B = C.c_void_p, C.c_uint64, C.c_int, C.c_bool


class DwflCallbacks(C.Structure):
    _fields_ = [(name, P) for name in ('find_elf', 'find_debuginfo', 'section_address', 'debuginfo_path')]


class ThreadCallbacks(C.Structure):
    _fields_ = [(name, P) for name in ('next_thread', 'get_thread', 'memory_read',
                                    'set_initial_registers', 'detach', 'thread_detach')]


class Dwfl:
    def __init__(self, modules, mappings, max_depth=64, frame_observer=None):
        name = ctypes.util.find_library('dw')
        if not name:
            raise FormatError('host libdw.so.1 is required for offline DWARF CFI unwinding')
        self.lib = C.CDLL(name)
        signatures = {
            'dwfl_begin': (P, [P]), 'dwfl_end': (None, [P]),
            'dwfl_report_elf': (P, [P, C.c_char_p, C.c_char_p, I, U, B]),
            'dwfl_report_end': (I, [P, P, P]),
            'dwfl_attach_state': (B, [P, P, I, P, P]),
            'dwfl_thread_state_registers': (B, [P, I, C.c_uint, C.POINTER(U)]),
            'dwfl_thread_state_register_pc': (None, [P, U]),
            'dwfl_getthread_frames': (I, [P, I, P, P]),
            'dwfl_frame_pc': (B, [P, C.POINTER(U), C.POINTER(B)]),
            'dwfl_frame_reg': (I, [P, C.c_uint, C.POINTER(U)]),
            'dwfl_addrmodule': (P, [P, U]),
            'dwfl_module_addrname': (C.c_char_p, [P, U]),
            'dwfl_errmsg': (C.c_char_p, [I]), 'dwfl_version': (C.c_char_p, [P]),
        }
        for fn, (result, args) in signatures.items():
            method = getattr(self.lib, fn)
            method.restype, method.argtypes = result, args
        @C.CFUNCTYPE(I, P, P, C.c_char_p, U, C.c_char_p, C.c_char_p, C.c_uint, P)
        def no_external_debug(_module, _userdata, _name, _base, _file, _link, _crc, _out):
            # A non-null callback is required for stripped DSOs. Never search the
            # host filesystem/debuginfod for a different architecture's debug file.
            return -1

        self.no_external_debug = no_external_debug
        self.callbacks = DwflCallbacks(None, C.cast(no_external_debug, P),
                                      C.cast(self.lib.dwfl_offline_section_address, P), None)
        self.handle = self.lib.dwfl_begin(C.byref(self.callbacks))
        if not self.handle:
            raise FormatError('dwfl_begin failed')
        self.modules, self.mappings, self.max_depth = modules, mappings, max_depth
        self.frame_observer = frame_observer
        self.sample = None
        self.frames = []
        self.read_failures = set()
        self.stop = None
        self.callback_error = None
        self.version = self.lib.dwfl_version(self.handle).decode(errors='replace')
        try:
            for path, (elf, bias) in modules.items():
                module = self.lib.dwfl_report_elf(self.handle, path.encode(), str(elf.path).encode(),
                                                   -1, bias, True)
                if not module:
                    raise FormatError(f'dwfl_report_elf failed: {path}')
            if self.lib.dwfl_report_end(self.handle, None, None):
                raise FormatError('dwfl_report_end failed')
            self._make_callbacks()
        except BaseException:
            self.close()
            raise

    def _make_callbacks(self):
        @C.CFUNCTYPE(I, P, P, C.POINTER(P))
        def next_thread(_dwfl, _arg, out):
            if out[0]:
                return 0
            out[0] = 1
            return self.sample.tid

        @C.CFUNCTYPE(B, P, I, P, C.POINTER(P))
        def get_thread(_dwfl, tid, _arg, out):
            out[0] = 1
            return tid == self.sample.tid

        @C.CFUNCTYPE(B, P, U, C.POINTER(U), P)
        def memory_read(_dwfl, address, out, _arg):
            offset = address - self.sample.regs[13]
            if offset < 0 or offset + 4 > len(self.sample.stack):
                self.read_failures.add(address)
                return False
            # Target ARM word is 32 bits; Dwarf_Word is a host-neutral uint64.
            out[0] = struct.unpack_from('<I', self.sample.stack, offset)[0]
            return True

        @C.CFUNCTYPE(B, P, P)
        def initial(thread, _arg):
            values = (U * 16)(*self.sample.regs)
            self.lib.dwfl_thread_state_register_pc(thread, self.sample.regs[15])
            return self.lib.dwfl_thread_state_registers(thread, 0, 16, values)

        @C.CFUNCTYPE(I, P, P)
        def frame(state, _arg):
            # No Python exception can escape a ctypes callback into libdwfl.
            try:
                pc, activation, sp = U(), B(), U()
                if not self.lib.dwfl_frame_pc(state, C.byref(pc), C.byref(activation)):
                    self.stop = 'unavailable_pc'
                    return 1
                if pc.value == 0:
                    self.stop = 'zero_return_pc'
                    return 1
                address = (pc.value & ~1) - (not activation.value)
                mapping = next((m for m in self.mappings if m.contains(address)), None)
                if not mapping or mapping.path not in self.modules:
                    self.stop = 'unverified_return_mapping'
                    return 1
                has_sp = self.lib.dwfl_frame_reg(state, 13, C.byref(sp)) == 0
                identity = (pc.value, sp.value if has_sp else None)
                if any((f['pc'], f['sp']) == identity for f in self.frames):
                    self.stop = 'repeated_frame'
                    return 1
                elf, bias = self.modules[mapping.path]
                module = self.lib.dwfl_addrmodule(self.handle, address)
                label = self.lib.dwfl_module_addrname(module, address) if module else None
                symbol = elf.symbol(address - bias)
                # ARM function symbols can carry bit0=Thumb while an interrupted
                # PC is even. Normalize both for exact function-entry attribution.
                if symbol.startswith('[') and label:
                    symbol = label.decode(errors='replace')
                details = dict(pc=pc.value, activation=activation.value,
                               sp=sp.value if has_sp else None, module=mapping.path,
                               elf_address=address - bias, symbol=symbol)
                if self.frame_observer is not None:
                    observer_stop = self.frame_observer(self, state, address, details)
                    if observer_stop:
                        self.stop = observer_stop
                        return 1
                self.frames.append(details)
                if len(self.frames) >= self.max_depth:
                    self.stop = 'depth_limit'
                    return 1
                return 0
            except Exception as exc:
                self.callback_error = str(exc)
                self.stop = 'callback_error'
                return 1

        self.callback_refs = (next_thread, get_thread, memory_read, initial, frame)
        self.thread_callbacks = ThreadCallbacks(*[C.cast(cb, P) for cb in self.callback_refs[:4]],
                                                None, None)

    def unwind(self, sample):
        self.sample = sample
        self.frames, self.read_failures, self.stop, self.callback_error = [], set(), None, None
        if sample.abi != 1 or len(sample.regs) != 16 or any(r > 0xffffffff for r in sample.regs):
            raise FormatError(f'sample {sample.index}: expected PERF_SAMPLE_REGS_ABI_32/r0-r15')
        if (sample.ip & ~1) != (sample.regs[15] & ~1):
            raise FormatError(f'sample {sample.index}: IP disagrees with captured r15')
        if sample.regs[13] + len(sample.stack) > 1 << 32:
            raise FormatError(f'sample {sample.index}: captured stack exceeds ARM32 address space')
        if not self.lib.dwfl_attach_state(self.handle, None, sample.pid,
                                         C.byref(self.thread_callbacks), None):
            raise FormatError('dwfl_attach_state failed')
        status = self.lib.dwfl_getthread_frames(self.handle, sample.tid,
                                               C.cast(self.callback_refs[4], P), None)
        error = self.lib.dwfl_errmsg(-1).decode(errors='replace') if status < 0 else None
        if self.callback_error:
            raise FormatError(self.callback_error)
        if self.read_failures:
            reason = 'captured_stack_unavailable'
        elif self.stop:
            reason = self.stop
        elif status < 0:
            reason = 'cfi_unwind_error'
        else:
            # A zero status does not certify reaching the process's root frame.
            reason = 'cfi_end'
        return dict(sample_index=sample.index, file_offset=sample.file_offset, pid=sample.pid,
                    tid=sample.tid, time_ns=sample.time, period=sample.period,
                    stack_bytes=len(sample.stack), frames=list(self.frames), stop=reason,
                    cfi_status=status, cfi_error=error,
                    unavailable_reads=sorted(self.read_failures), callback_stop=self.stop)

    def close(self):
        if self.handle:
            self.lib.dwfl_end(self.handle)
            self.handle = None
