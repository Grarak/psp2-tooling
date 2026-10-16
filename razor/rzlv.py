#!/usr/bin/env python3
"""Decode Razor GPU live results (.rzlv, razor/recorder) and export a timeline.

RZLV keeps the Performance Analyzer's raw GPU trace (PACF, PATR); it is decoded
here into each GPU core's TA, 3D and firmware busy intervals the way Sony's Razor
HUD does. Older captures hold the HUD's own job records (BATS, DATA) instead.
GPU busy durations are interval unions; sums of core durations are named core_us. The timeline export
(--trace: Chrome trace-event JSON for ui.perfetto.dev or chrome://tracing) maps
the GPU's PA clock into kernel microseconds through the recorded clock anchors,
never through EndScene/Finish CPU wait times. Optional CPUX spans measure CPU
processing wall time, including waits and preemption; they are not scheduled CPU
execution or utilization.

    razor/rzlv.py live.rzlv --csv jobs.csv --trace gpu.json
"""
import argparse
import bisect
import csv
import json
import struct
from pathlib import Path

JOB_SIZE = 0x48
VERTEX_TYPES = {1, 3, 5, 7}
FRAGMENT_TYPES = {2, 4, 6, 8}

# The PA trace: 128-byte blocks of a u16 sequence, seven u16 tags (high byte: entry type,
# bit 7 overflow; low byte: the entry's index in its sample) and seven 16-byte entries.
# A GPU sample (0x61) starts with a 48-bit timestamp in PA ticks and five u16 counters;
# its further entries hold eight counters each. The counters run core by core, each core
# in its selects' bit order (selectsA, then selectsB). In every metrics group selectsB
# bits 24, 25 and 26 are the core's vertex, fragment and firmware busy GPU cycles in the
# sample period; SceRazorHud (FUN_81008680) reports them as these job types.
PA_BLOCK = 128
PA_GPU_SAMPLE, PA_EVENT = 0x61, 0x7f
GROUP_JOB_TYPES = {0: (7, 8), 1: (1, 2), 2: (3, 4), 3: (5, 6)}


def records(data, magic):
    if len(data) < 8 or data[:4] != magic:
        raise ValueError(f'Expected {magic.decode()} file')
    version = struct.unpack_from('<I', data, 4)[0]
    if version != (1 if magic == b'RZLV' else 3):
        raise ValueError(f'Unsupported {magic.decode()} version {version}')
    offset = 8
    while offset < len(data):
        if len(data) - offset < 8:
            raise ValueError('Truncated record header')
        tag, size = struct.unpack_from('<4sI', data, offset)
        offset += 8
        end = offset + size
        padded = end + (-size % 4)
        if padded > len(data):
            raise ValueError(f'Truncated {tag.decode(errors="replace")} record')
        yield tag, data[offset:end]
        offset = padded


def entries(data, count):
    offset = 0
    result = []
    for _ in range(count):
        if len(data) - offset < 8:
            raise ValueError('Truncated live entry header')
        size, kind, reserved = struct.unpack_from('<HHI', data, offset)
        if size < 8 or size > len(data) - offset:
            raise ValueError('Invalid live entry size')
        blob = data[offset:offset + size]
        entry = {'entry_type': kind, 'entry_size': size}
        if kind == 0:
            if size < JOB_SIZE:
                raise ValueError('Truncated GPU job')
            start, end, job_type, core, scene, frame = struct.unpack_from('<QQBbHI', blob, 8)
            if end < start:
                raise ValueError('GPU job ends before it starts')
            entry.update(start_us=start, end_us=end, duration_us=end - start,
                         job_type=job_type, core=core)
            # Sony explicitly leaves process/frame/scene/values undefined for
            # firmware jobs. Preserve their interval without reading fields.
            if job_type != 0:
                pid, draw_count, flags = struct.unpack_from('<IHH', blob, 64)
                entry.update(scene=scene, frame=frame, pid=pid, flags=flags)
                if job_type in VERTEX_TYPES:
                    entry['stage'] = 'TA'
                elif job_type in FRAGMENT_TYPES:
                    entry['stage'] = '3D'
                else:
                    entry['stage'] = 'unknown'
                metrics = {}
                if job_type == 1:
                    metrics['usse_vertex_percent'] = struct.unpack_from('<f', blob, 32)[0]
                elif job_type == 2:
                    values = struct.unpack_from('<3f', blob, 32)
                    metrics = dict(zip(('usse_fragment_percent', 'dependent_texture_percent',
                                        'nondependent_texture_percent'), values))
                elif job_type == 3:
                    metrics = dict(zip(('input_primitives', 'output_primitives', 'input_vertices',
                                        'output_vertices'), struct.unpack_from('<4I', blob, 32)))
                elif job_type == 4:
                    metrics = dict(zip(('pixels_before_hsr', 'output_pixels', 'output_samples'),
                                       struct.unpack_from('<3I', blob, 32)))
                elif job_type == 5:
                    metrics['ta_write_bytes'] = struct.unpack_from('<I', blob, 32)[0]
                elif job_type == 6:
                    metrics['isp_parameter_read_bytes'] = struct.unpack_from('<I', blob, 32)[0]
                entry['metrics'] = metrics
        elif kind == 1:
            if size < 24:
                raise ValueError('Truncated parameter buffer entry')
            time, peak, partial, paused, _ = struct.unpack_from('<QIBBH', blob, 8)
            entry.update(time_us=time, peak_bytes=peak, partial_render=bool(partial),
                         vertex_paused=bool(paused), scope='PA trace')
        elif kind == 2:
            if size < 32:
                raise ValueError('Truncated frame entry')
            start, duration, frame, activity = struct.unpack_from('<QIII', blob, 8)
            entry.update(start_us=start, duration_us=duration, frame=frame,
                         gpu_activity_us=activity, scope='PA trace')
        else:
            entry['raw_hex'] = blob.hex()
        result.append(entry)
        offset += size
    if offset != len(data):
        raise ValueError('Live data bytes do not match entry count')
    return result


SCENE_FIELDS = ['heartbeat', 'ordinal', 'native_frame', 'notification_serial',
                'width', 'height', 'color_target', 'depth_target', 'display',
                'draws', 'vertices', 'indices', 'instances', 'opaque_draws',
                'translucent_draws', 'discard_draws', 'depth_replace_draws',
                'pass_switches', 'flush_transitions', 'reserved']


def gpu_hz(mhz):
    # The HUD's correction: the 166 MHz setting runs at 166.5 MHz.
    return 166_500_000 if mhz == 166 else mhz * 1_000_000


def decode_pa(capture):
    """SceRazorHud's job edges (FUN_810082b8) over the raw GPU samples.

    A counter is the core's busy cycles in one sample period of P cycles. An open job
    ends when the core was busy for less than the period: at the sample time plus the
    busy cycles. A new job starts when the core was busy at all: at the sample time plus
    the idle cycles. Jobs still open when a trace segment ends close there, truncated.
    """
    config = capture['pa_config']
    selects_a, selects_b = config['selects_a'], config['selects_b']
    if selects_b >> 24 & 7 != 7 or config['group'] not in GROUP_JOB_TYPES:
        raise ValueError('PA trace without the busy counters')
    per_core = bin(selects_a).count('1') + bin(selects_b).count('1')
    first = bin(selects_a).count('1') + bin(selects_b & 0xffffff).count('1')
    vertex, fragment = GROUP_JOB_TYPES[config['group']]
    kinds = ((first, vertex, 'TA'), (first + 1, fragment, '3D'), (first + 2, 0, 'firmware'))
    pa_mhz, period = config['pa_mhz'], config['period']
    jobs, bookmarks = capture['pa_jobs'], capture['pa_bookmarks']

    def finish(job, end, truncated=False):
        job['end_us'] = end // pa_mhz
        job['duration_us'] = job['end_us'] - job['start_us']
        if truncated:
            job['truncated'] = True
        jobs.append(job)

    segments = {}
    for batch, data in capture['pa_chunks']:
        segments.setdefault(batch['segment'], []).append((batch, data))
    for chunks in segments.values():
        open_jobs, sample, sequence, last_end = {}, None, None, None
        for batch, data in chunks:
            hz = gpu_hz(batch['gpu_mhz'] or config['gpu_mhz'])
            cycles = hz * period // (pa_mhz * 1_000_000)
            ticks = lambda value: pa_mhz * 1_000_000 * value // hz
            for offset in range(0, len(data) - PA_BLOCK + 1, PA_BLOCK):
                block = data[offset:offset + PA_BLOCK]
                number = struct.unpack_from('<H', block)[0]
                if sequence is not None and number != (sequence + 1) & 0xffff:
                    batch['overflow_count'] += (number - sequence - 1) & 0xffff
                    sample = None
                sequence = number
                for slot, tag in enumerate(struct.unpack_from('<7H', block, 2)):
                    kind, index, entry = tag >> 8 & 0x7f, tag & 0xff, block[16 + slot * 16:32 + slot * 16]
                    if kind == PA_EVENT and entry[0xb] & 0x1f == 0x12:
                        bookmarks.append(dict(sequence=number, value=f'0x{struct.unpack_from("<I", entry, 12)[0]:08x}'))
                    if kind != PA_GPU_SAMPLE:
                        continue
                    if tag & 0x8000:
                        batch['overflow_count'] += 1
                        sample = None
                    elif index == 0:
                        low, high, *values = struct.unpack('<IH5H', entry)
                        sample = [low | high << 32, values, 1]
                    elif sample and index == sample[2]:
                        sample[1] += struct.unpack('<8H', entry)
                        sample[2] += 1
                    else:
                        sample = None
                    if not sample or len(sample[1]) < per_core * 4:
                        continue
                    time, counters, _ = sample
                    sample = None
                    batch['entry_count'] += 1
                    batch['start_us'] = batch['start_us'] or time // pa_mhz
                    last_end = time + ticks(cycles)
                    batch['end_us'] = last_end // pa_mhz
                    for core in range(4):
                        for counter, job_type, stage in kinds:
                            value = counters[core * per_core + counter]
                            job = open_jobs.get((core, stage))
                            if job:
                                if value < cycles:
                                    finish(open_jobs.pop((core, stage)), time + ticks(value))
                            elif value:
                                open_jobs[core, stage] = dict(
                                    entry_type=0, start_us=(time + ticks(max(cycles - value, 0))) // pa_mhz,
                                    job_type=job_type, core=core, stage=stage, pid=None, scene=None,
                                    frame=None, source='PA busy counters')
        for job in open_jobs.values():
            finish(job, last_end, truncated=True)
    jobs.sort(key=lambda job: (job['start_us'], job['core']))
    # A job's frame: the heartbeats completed when it started, from the per-heartbeat anchors.
    marks = sorted((clock['pa_ticks'] // clock['frequency_mhz'], clock['heartbeat'])
                   for clock in capture['clocks'] if clock['heartbeat'] and clock['frequency_mhz'])
    times = [time for time, _ in marks]
    for job in jobs:
        index = bisect.bisect_right(times, job['start_us']) - 1
        job['frame'] = marks[index][1] if index >= 0 else None


def read_live(path):
    capture = {'metadata': {}, 'clocks': [], 'batches': [], 'status': [],
               'cpu_intervals': [], 'cpu_work_dropped': 0,
               'native_scenes': [], 'native_scene_dropped': 0,
               'pa_config': None, 'pa_chunks': [], 'pa_jobs': [], 'pa_bookmarks': []}
    pending = None
    for tag, data in records(path.read_bytes(), b'RZLV'):
        if pending is not None and tag != b'DATA':
            raise ValueError('Batch data record missing')
        if tag == b'META':
            capture['metadata'].update(line.split('=', 1) for line in data.decode().splitlines() if '=' in line)
        elif tag == b'CLCK':
            if len(data) != 32:
                raise ValueError('Invalid clock anchor')
            before, ticks, after, frequency, heartbeat = struct.unpack('<QQQII', data)
            capture['clocks'].append({'kernel_before_us': before, 'pa_ticks': ticks,
                                     'kernel_after_us': after, 'frequency_mhz': frequency,
                                     'heartbeat': heartbeat})
        elif tag == b'CPUX':
            if len(data) != 24:
                raise ValueError('Invalid CPUX processing interval size')
            start, end, thread, core = struct.unpack('<QQII', data)
            if end < start:
                raise ValueError('CPUX processing interval ends before it starts')
            if core >= 4:
                raise ValueError('Invalid CPUX native CPU core')
            capture['cpu_intervals'].append(dict(start_us=start, end_us=end,
                duration_us=end - start, thread_id=thread, core=core,
                clock='kernel microseconds'))
        elif tag == b'CPUD':
            if len(data) != 4:
                raise ValueError('Invalid CPUX dropped interval count')
            capture['cpu_work_dropped'] += struct.unpack('<I', data)[0]
        elif tag == b'SCNE':
            if len(data) != 208:
                raise ValueError('Invalid SCNE scene record size')
            submitted, *values, label, kind = struct.unpack('<Q20I96s24s', data)
            scene = dict(zip(SCENE_FIELDS, values))
            if scene['display'] > 1 or scene.pop('reserved'):
                raise ValueError('Invalid SCNE scene flags')
            if sum(scene[name] for name in ('opaque_draws', 'translucent_draws',
                    'discard_draws', 'depth_replace_draws')) != scene['draws']:
                raise ValueError('Invalid SCNE draw totals')
            if scene['pass_switches'] > max(scene['draws'] - 1, 0) or scene['flush_transitions'] > scene['pass_switches']:
                raise ValueError('Invalid SCNE pass transitions')
            scene.update(submitted_us=submitted, first_shader=label.split(b'\0', 1)[0].decode(),
                         first_kind=kind.split(b'\0', 1)[0].decode())
            capture['native_scenes'].append(scene)
        elif tag == b'SCND':
            if len(data) != 4:
                raise ValueError('Invalid SCNE dropped scene count')
            capture['native_scene_dropped'] += struct.unpack('<I', data)[0]
        elif tag == b'BATS':
            if len(data) != 48:
                raise ValueError('Invalid batch header')
            sequence, heartbeat, status, count, overflow, size, group, _, start, end = struct.unpack('<8I2Q', data)
            batch = dict(sequence=sequence, heartbeat=heartbeat, status=f'0x{status:08x}',
                         entry_count=count, overflow_count=overflow, bytes=size, group=group,
                         start_us=start, end_us=end, entries=[])
            if bool(count) != bool(size):
                raise ValueError('Invalid empty batch')
            capture['batches'].append(batch)
            if size:
                pending = batch
        elif tag == b'DATA':
            if pending is None or len(data) != pending['bytes']:
                raise ValueError('Unexpected live data record')
            pending['entries'] = entries(data, pending['entry_count'])
            pending = None
        elif tag == b'PACF':
            if len(data) != 32:
                raise ValueError('Invalid PA trace configuration')
            fields = ('group', 'mode', 'selects_a', 'selects_b', 'period', 'trace_bytes', 'pa_mhz', 'gpu_mhz')
            capture['pa_config'] = dict(zip(fields, struct.unpack('<8I', data)))
        elif tag == b'PATR':
            if len(data) < 32 or (len(data) - 32) % PA_BLOCK:
                raise ValueError('Invalid PA trace record')
            sequence, heartbeat, segment, status, offset, size, gpu_mhz, _ = struct.unpack_from('<8I', data)
            if size != len(data) - 32:
                raise ValueError('PA trace record size mismatch')
            batch = dict(sequence=sequence, heartbeat=heartbeat, status='0x00000000', pa_status=f'0x{status:08x}',
                         segment=segment, offset=offset, bytes=size, gpu_mhz=gpu_mhz, group=None,
                         entry_count=0, overflow_count=0, start_us=0, end_us=0, entries=[])
            capture['batches'].append(batch)
            capture['pa_chunks'].append((batch, data[32:]))
        elif tag in (b'STAT', b'STOP', b'MODE'):
            if len(data) != 4:
                raise ValueError('Invalid status record')
            capture['status'].append({'operation': tag.decode(), 'value': f'0x{struct.unpack("<I", data)[0]:08x}'})
    if pending is not None:
        raise ValueError('Capture ends before batch data')
    if capture['pa_chunks']:
        if not capture['pa_config']:
            raise ValueError('PA trace without its configuration')
        for batch, _ in capture['pa_chunks']:
            batch['group'] = capture['pa_config']['group']
        decode_pa(capture)
    del capture['pa_chunks']
    for span in capture['cpu_intervals']:
        span['scope'] = cpu_processing_scope(capture)
    return capture


def cpu_processing_scope(capture):
    if capture['metadata'].get('cpu_scope') == 'native-owner-prepresent':
        return 'native game/render owner pre-presentation wall interval'
    # Historical captures predate explicit scope metadata and bracketed the
    # FIFO render worker. Keep their scope rather than relabeling old evidence.
    return 'render FIFO processing wall interval'


def union(intervals):
    merged = []
    for start, end in sorted(intervals):
        if end <= start:
            continue
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def intersection(first, second):
    """Intersect interval unions without counting coincident cores twice."""
    first, second = union(first), union(second)
    result = []
    i = j = 0
    while i < len(first) and j < len(second):
        start, end = max(first[i][0], second[j][0]), min(first[i][1], second[j][1])
        if start < end:
            result.append((start, end))
        if first[i][1] <= second[j][1]:
            i += 1
        else:
            j += 1
    return result


def interval_us(intervals):
    return sum(end - start for start, end in intervals)


def own_cpu_intervals(capture, pid=None):
    metadata_pid = int(capture['metadata']['pid'], 0)
    return capture.get('cpu_intervals', []) if pid is None or pid == metadata_pid else []


def own_jobs(capture, pid=None):
    own = int(capture['metadata']['pid'], 0)
    if pid is None:
        pid = own
    jobs = [entry for batch in capture['batches'] for entry in batch['entries']
            if entry['entry_type'] == 0 and entry.get('pid') == pid
            and entry.get('stage') in ('TA', '3D')]
    # The PA's counters carry no process: all GPU work counts as the recorder's.
    return jobs + [job for job in capture.get('pa_jobs', []) if pid == own and job['stage'] in ('TA', '3D')]


def summarize(capture, pid=None):
    jobs = own_jobs(capture, pid)
    stopped = any(status == {'operation': 'STOP', 'value': '0x00000000'}
                  for status in capture['status'])
    failed_start = any(status['operation'] == 'STAT' and int(status['value'], 16) & 0x80000000
                       for status in capture['status'])
    collection_state = 'start_failed' if failed_start else ('stopped' if stopped else 'incomplete')
    errors = [batch['status'] for batch in capture['batches'] if int(batch['status'], 16) & 0x80000000]
    summary = {'batches': len(capture['batches']), 'jobs': len(jobs),
               'overflow_entries': sum(batch['overflow_count'] for batch in capture['batches']),
               'frames': len({job['frame'] for job in jobs if job.get('frame') is not None}), 'stages': {},
               'collection_state': collection_state, 'batch_errors': sorted(set(errors)),
               'duration_scope': 'observed native jobs, union across GPU cores'}
    if capture.get('pa_config'):
        summary.update(source='PA busy counters', attribution='none: every process\'s GPU work',
                       frame_basis='heartbeats completed when the job started (CLCK anchors)',
                       trace_segments=len({batch['segment'] for batch in capture['batches']}),
                       truncated_jobs=sum(1 for job in jobs if job.get('truncated')),
                       bookmarks=len(capture['pa_bookmarks']))
    summary['trace_complete'] = stopped and not failed_start and not errors and not summary['overflow_entries']
    for stage in ('TA', '3D'):
        selected = [job for job in jobs if job['stage'] == stage]
        intervals = union((job['start_us'], job['end_us']) for job in selected)
        summary['stages'][stage] = {'jobs': len(selected),
            'core_us': sum(job['duration_us'] for job in selected),
            'busy_us': sum(end - start for start, end in intervals)}
    all_intervals = union((job['start_us'], job['end_us']) for job in jobs)
    summary['gpu_busy_us'] = sum(end - start for start, end in all_intervals)
    # The first empty batch can report start=0 before collection has advanced.
    # Its end is a timestamp, not a measurement beginning at device boot.
    windows = union((batch['start_us'], batch['end_us']) for batch in capture['batches']
                    if 0 < batch['start_us'] < batch['end_us']
                    and not int(batch['status'], 16) & 0x80000000)
    window_us = interval_us(windows)
    busy_us = interval_us(intersection(all_intervals, windows))
    uncovered_us = summary['gpu_busy_us'] - busy_us
    summary['busyness'] = dict(
        available=bool(window_us) and summary['trace_complete'] and not uncovered_us,
        scope='own-PID TA/3D interval union within advancing drained collection batches',
        window_us=window_us, busy_us=busy_us, idle_us=window_us - busy_us,
        own_job_us_outside_window=uncovered_us,
        busy_pct=100 * busy_us / window_us if window_us else None,
        idle_pct=100 * (window_us - busy_us) / window_us if window_us else None)
    summary['clock_anchors'] = len(capture['clocks'])
    summary['cpu_interval_records'] = len(own_cpu_intervals(capture, pid))
    summary['cpu_work_dropped'] = capture.get('cpu_work_dropped', 0)
    if capture.get('native_scenes') or capture.get('native_scene_dropped'):
        summary['native_scene_records'] = len(capture['native_scenes'])
        summary['native_scene_dropped'] = capture['native_scene_dropped']
        summary['native_scene_heartbeats'] = len({scene['heartbeat'] for scene in capture['native_scenes']})
        summary['native_scene_frame_basis'] = 'completed heartbeats at scene begin; ordinal is not assumed to equal PA sceneId'
    if capture.get('cpu_intervals') or summary['cpu_work_dropped']:
        summary['processing_overlap'] = processing_overlap(capture, jobs, pid, summary['trace_complete'])
    return summary


def clock_mapper(capture):
    anchors = []
    for clock in capture['clocks']:
        before, after = clock['kernel_before_us'], clock['kernel_after_us']
        ticks, frequency = clock['pa_ticks'], clock['frequency_mhz']
        if ticks == 0 or not 0 < frequency < 1000 or after < before:
            raise ValueError('No valid native PA clock; cannot map GPU data into kernel time')
        anchors.append((ticks / frequency, (before + after) / 2))
    anchors.sort()
    anchors = list(dict(anchors).items())
    if len(anchors) < 2:
        raise ValueError('At least two advancing PA/kernel clock anchors are required')
    if any(second[1] < first[1] for first, second in zip(anchors, anchors[1:])):
        raise ValueError('PA/kernel clock anchors are not monotonic')
    scale = (anchors[-1][1] - anchors[0][1]) / (anchors[-1][0] - anchors[0][0])
    if not 0.98 < scale < 1.02:
        raise ValueError(f'PA and kernel clock rates disagree (scale={scale:.6f})')
    times = [point[0] for point in anchors]

    def kernel_time(pa_us):
        index = max(0, min(len(anchors) - 2, bisect.bisect_right(times, pa_us) - 1))
        x0, y0 = anchors[index]
        x1, y1 = anchors[index + 1]
        return round(y0 + (pa_us - x0) * (y1 - y0) / (x1 - x0))
    return kernel_time


def processing_overlap(capture, jobs, pid=None, gpu_complete=False):
    """Compare wall spans in kernel time, with no DTrace clock assumption.

    CPUX covers processing (including waits/preemption), not scheduled CPU
    execution. Restrict the comparison to observed CPUX coverage, native batch
    coverage and bracketed clock coverage. Never extrapolate this window.
    """
    cpu = own_cpu_intervals(capture, pid)
    result = dict(available=False, scope=cpu_processing_scope(capture) + '; includes waits and preemption',
                  clock='kernel microseconds; native GPU PA mapped using CLCK anchors',
                  gpu_trace_complete=gpu_complete, cpu_work_dropped=capture.get('cpu_work_dropped', 0),
                  cpu_coverage_complete=not capture.get('cpu_work_dropped', 0) and any(
                      status == {'operation': 'STOP', 'value': '0x00000000'} for status in capture['status']))
    result['coverage_complete'] = result['gpu_trace_complete'] and result['cpu_coverage_complete']
    if not cpu:
        result['reason'] = 'No CPUX intervals for the selected process'
        return result
    try:
        convert = clock_mapper(capture)
    except ValueError as error:
        result['reason'] = str(error)
        return result
    batches = [(convert(batch['start_us']), convert(batch['end_us'])) for batch in capture['batches']
               if batch['start_us'] > 0 and batch['end_us'] > batch['start_us']]
    coverage = [(min(span['start_us'] for span in cpu), max(span['end_us'] for span in cpu))]
    clock_midpoints = [(clock['kernel_before_us'] + clock['kernel_after_us']) / 2 for clock in capture['clocks']]
    window = intersection(intersection(coverage, batches), [(round(min(clock_midpoints)), round(max(clock_midpoints)))])
    if not window:
        result['reason'] = 'No common CPUX, native batch and clock-anchor coverage'
        return result
    cpu_union = intersection(((span['start_us'], span['end_us']) for span in cpu), window)
    gpu_union = intersection(((convert(job['start_us']), convert(job['end_us'])) for job in jobs), window)
    overlap = intersection(cpu_union, gpu_union)
    cpu_us, gpu_us, overlap_us, window_us = map(interval_us, (cpu_union, gpu_union, overlap, window))
    result.update(available=True, window_start_us=window[0][0], window_end_us=window[-1][1],
                  window_us=window_us, window_segments=[dict(start_us=start, end_us=end) for start, end in window],
                  window_rule='intersection of CPUX envelope, valid native batch periods and CLCK midpoint coverage',
                  cpu_interval_union_us=cpu_us, gpu_busy_union_us=gpu_us, overlap_us=overlap_us,
                  cpu_without_gpu_us=cpu_us - overlap_us, gpu_without_cpu_us=gpu_us - overlap_us,
                  neither_us=window_us - cpu_us - gpu_us + overlap_us,
                  cpu_threads=sorted({span['thread_id'] for span in cpu}), cpu_cores=sorted({span['core'] for span in cpu}),
                  max_clock_bracket_us=max(clock['kernel_after_us'] - clock['kernel_before_us'] for clock in capture['clocks']))
    return result


def encoded_record(tag, payload):
    """One record as the recorder writes it: tag, size, payload padded to 4 bytes."""
    return tag + struct.pack('<I', len(payload)) + payload + bytes(-len(payload) % 4)


def export_trace(capture, output, pid=None):
    """Chrome trace-event JSON: each GPU core's TA and 3D jobs, and the CPUX spans, in kernel us."""
    jobs = own_jobs(capture, pid)
    if not jobs:
        raise ValueError('No native GPU jobs for the selected process')
    convert = clock_mapper(capture)
    events = [dict(ph='M', name='process_name', pid=1, args=dict(name='GPU (Razor)'))]
    for stage, lane in (('TA', 0), ('3D', 0x10)):
        for core in range(4):
            events.append(dict(ph='M', name='thread_name', pid=1, tid=lane | core,
                               args=dict(name=f'{stage} core {core}')))
    for job in jobs:
        start, end = convert(job['start_us']), convert(job['end_us'])
        events.append(dict(ph='X', name=f'{job["stage"]} scene {job.get("scene")}', pid=1,
                           tid=(0x10 if job['stage'] == '3D' else 0) | job['core'], ts=start,
                           dur=max(end - start, 0),
                           args={k: v for k, v in job.items() if k not in ('start_us', 'end_us')}))
    cpu = own_cpu_intervals(capture, pid)
    if cpu:
        events.append(dict(ph='M', name='process_name', pid=2,
                           args=dict(name='CPU processing (CPUX: wall time, waits included)')))
        for span in cpu:
            events.append(dict(ph='X', name='processing', pid=2, tid=span['thread_id'],
                               ts=span['start_us'], dur=span['duration_us'], args=dict(core=span['core'])))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(dict(traceEvents=events, displayTimeUnit='ns')) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('capture', type=Path, help='a .rzlv file (razor/recorder)')
    parser.add_argument('--pid', type=lambda value: int(value, 0))
    parser.add_argument('--json', type=Path, help='write decoded entries and counters')
    parser.add_argument('--csv', type=Path, help='write job intervals for the selected process')
    parser.add_argument('--scene-csv', type=Path, help='write optional SCNE application scene records; ordinals are not assumed to be PA scene IDs')
    parser.add_argument('--trace', type=Path, help='write the GPU jobs and CPUX spans as Chrome trace-event JSON')
    args = parser.parse_args()
    capture = read_live(args.capture)
    capture['summary'] = summarize(capture, args.pid)
    print(json.dumps(capture['summary'], indent=2))
    if args.json:
        args.json.write_text(json.dumps(capture, indent=2, allow_nan=False) + '\n')
    if args.csv:
        fields = ['frame', 'scene', 'stage', 'core', 'start_us', 'end_us', 'duration_us', 'pid', 'metrics']
        with args.csv.open('w', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=fields, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(own_jobs(capture, args.pid))
    if args.scene_csv:
        fields = ['submitted_us', *SCENE_FIELDS[:-1], 'first_shader', 'first_kind']
        with args.scene_csv.open('w', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            if args.pid is None or args.pid == int(capture['metadata']['pid'], 0):
                writer.writerows(capture['native_scenes'])
    if args.trace:
        export_trace(capture, args.trace, args.pid)
        print(f'Wrote the GPU timeline to {args.trace}')


if __name__ == '__main__':
    main()
