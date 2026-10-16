#include "razor.h"
#include <psp2/gxm.h>
#include <psp2/io/fcntl.h>
#include <psp2/kernel/modulemgr.h>
#include <psp2/kernel/processmgr.h>
#include <psp2/kernel/sysmem.h>
#include <psp2/kernel/threadmgr.h>
#include <psp2/pamgr.h>
#include <psp2/power.h>
#include <psp2/razor_capture.h>
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <malloc.h>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

// Public Sony exports supplied by vitasdk stubs but missing from its headers.
extern "C" {
int sceGxmAddRazorGpuCaptureBuffer(void* base, uint32_t size);
int sceGxmRemoveRazorGpuCaptureBuffer(void* base);
SceBool sceRazorGpuCaptureIsInProgress(void);
int sceKernelPaRegisterShared(uint32_t first, uint32_t second);
void* sceGxmGetTopContextInternal(void);
// libgpu_es4's SGXGetMiscInfo (SceGpuEs4User 0x09BB98B2): VitaSDK has no stub for it, so
// link the one SceGpuEs4User.yml (beside this file) generates.
int SGXGetMiscInfo(void* devData, void* miscInfo);
}

// _sceKernelPaSetupTraceBufferByKey: a physically contiguous buffer the PA writes trace into.
// pamgr wants base, size and the field after them 128-byte aligned.
struct SceKernelPaTraceBufferParam {
  uint32_t flags; // 1 for a GPU trace, as SceRazorHud sets it
  void* base;
  uint32_t size, reserved, captureFlags;
};
// _sceKernelPaAddGpuTraceByKey, copied into the PA's registers: the mode (+0x1190), the
// sample period in PA ticks twice (+0x1194) and each GPU core's counter selects (+0x1140,
// +0x1150).
struct SceKernelPaGpuTraceParam {
  uint32_t mode;
  uint16_t period[2];
  uint32_t selectsA[4], selectsB[4], reserved[8];
};

static_assert(sizeof(SceKernelPaTraceBufferParam) == 0x14);
static_assert(sizeof(SceKernelPaGpuTraceParam) == 0x48);

namespace razor {
namespace {
// Razor's capture module ships only in DevKit firmware (vs0:sys/external). It is copied to
// ur0:data/ and loaded from there, as vitaGL does, so the same app runs on retail.
constexpr const char* CaptureModule = "ur0:data/librazorcapture_es4.suprx";
// Live metrics drive the Performance Analyzer through pamgr the way SceRazorHud's live start
// does (its FUN_81007248), without the HUD: the same key, buffer setup and GPU trace. The
// counter selects of SceRazorHud's four metric groups (its table at 0x8100d5b0); in every
// group, selectsB bits 24, 25 and 26 are each core's vertex, fragment and firmware busy.
constexpr uint32_t PaKey[2] = {0x7a207888, 0x7a207777};
constexpr uint32_t GroupSelects[4][2] = {
    {0x00000000, 0x07014100}, {0x00000000, 0x07ff2929}, {0x1f000000, 0x070f1f1f}, {0x00000000, 0x07010100}};
// The PA samples the SGX's performance counters, which are off until the driver gets
// SGX_MISC_INFO_REQUEST_SET_HWPERF_STATUS (PowerVR's sgxapi_km.h): SceRazorHud sends it
// (its FUN_810065dc) with each group's eight counter groups and bits, the same table rows
// (+0x08, +0x28) as the selects above. SceGpuEs4 then sets EUR_CR_PERF_DEBUG_CTRL and each
// core's EUR_CR_PERF0-3. Without it every counter in the trace is zero.
struct SgxSetHwPerfStatus {
  uint32_t request = 3; // SGX_MISC_INFO_REQUEST_SET_HWPERF_STATUS
  uint32_t reserved = 0;
  uint32_t status;      // PVRSRV_SGX_HWPERF_STATUS_*: 1 reset counters, 2 graphics on
  uint32_t group[8], bit[8];
};
static_assert(sizeof(SgxSetHwPerfStatus) == 0x4c);
constexpr uint32_t HwPerfGroup[4][8] = {
    {3, 3, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0x64, 0x44, 1, 0}, {0, 0, 0, 0x2c, 0x2c, 0x2c, 0, 0}, {0, 0, 0, 0, 0, 0x36, 0x36, 0}};
constexpr uint32_t HwPerfBit[4][8] = {{0, 8, 0x1c, 0x1c, 0x1c, 8, 0x12, 0},
                                      {0x1c, 0x1c, 0x1c, 0x1c, 0, 0, 0, 0},
                                      {0x1c, 0x1c, 0x1c, 0xf, 0xa, 1, 0x18, 0},
                                      {0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x12, 6, 0}};
constexpr uint16_t SamplePeriod = 0x3408; // PA ticks: 40 us at 333 MHz
constexpr uint32_t PaGpuMode = 2;
// The PA writes into the buffer for the whole window and stops when it is full; the trace is
// read only afterwards, so the measured frames do no host I/O for it.
constexpr unsigned TraceSlack = 64u << 10;
struct ClockRecord {
  uint32_t tag = 0x4b434c43, bytes = 32; // CLCK
  uint64_t kernelBefore, paTicks, kernelAfter;
  uint32_t frequencyMHz, heartbeat;
};

static_assert(sizeof(ClockRecord) == 40);
constexpr unsigned MaxClockRecords = 4096;
struct CpuWorkRecord {
  uint32_t tag = 0x58555043, bytes = 24; // CPUX, then kernel-clock wall interval.
  uint64_t start, end;
  uint32_t thread, core;
};

static_assert(sizeof(CpuWorkRecord) == 32);
constexpr unsigned MaxCpuWorkRecords = 4096;
struct SceneRecord {
  uint32_t tag = 0x454e4353, bytes = 208; // SCNE, fixed little-endian payload.
  uint64_t submittedUs;
  uint32_t heartbeat, ordinal, nativeFrame, serial;
  uint32_t width, height, color, depth, display;
  uint32_t draws = 0, vertices = 0, indices = 0, instances = 0;
  uint32_t opaque = 0, translucent = 0, discard = 0, depthReplace = 0;
  uint32_t passSwitches = 0, flushTransitions = 0;
  uint32_t reserved = 0;
  char firstShader[96]{}, firstKind[24]{};
};

static_assert(sizeof(SceneRecord) == 216);
constexpr unsigned MaxSceneRecords = 64;
struct State {
  bool initialized = false, live = false, finished = false, hwperf = false;
  bool captureTriggered = false, captureBusy = false;
  std::atomic<bool> capture{false};
  const char* capturePath = nullptr;
  const char* livePath = nullptr;
  unsigned captureFrame = 120, liveStartFrame = 120, liveFrames = 120;
  unsigned frame = 0, group = 1, sequence = 0;
  bool cpuTrace = false;
  uint32_t cpuDropped = 0;
  std::vector<CpuWorkRecord> cpuWork;
  bool sceneTrace = false;
  uint32_t sceneDropped = 0, sceneOrdinal = 0, activeScene = UINT32_MAX, previousPass = 4;
  std::vector<SceneRecord> scenes;
  SceUID output = -1;
  SceUID captureModule = -1;
  SceUID traceBlock = -1;
  void* trace = nullptr;
  int paKey = -1;
  uint32_t traceBytes = 8u << 20, traceBase = 0;
  std::vector<ClockRecord> clocks;
} state;
// item[,item...]: live=PATH, group=N, start=N, frames=N, trace-mib=N, scenes, cpu,
// capture=PATH, capture-frame=N, salvage=PATH (razor.h).
struct Options {
  std::vector<std::pair<std::string, std::string>> values;
  std::vector<std::string> flags;
  explicit Options(const char* text) {
    const std::string_view all = text ? text : "";

    for (size_t at = 0; at < all.size();) {
      size_t end = all.find(',', at);

      if (end == std::string_view::npos)
        end = all.size();

      const std::string_view item = all.substr(at, end - at);
      at = end + 1;
      const size_t equals = item.find('=');
      const std::string_view name = item.substr(0, equals);
      bool known = false;

      for (const std::string_view k : {"live", "group", "start", "frames", "trace-mib", "capture", "capture-frame", "salvage"})
        known |= equals != std::string_view::npos && name == k;

      for (const std::string_view k : {"scenes", "cpu"})
        known |= equals == std::string_view::npos && name == k;

      if (!known) {
        if (!item.empty())
          std::fprintf(stderr, "razor: unknown option '%.*s'\n", int(item.size()), item.data());
      } else if (equals == std::string_view::npos) {
        flags.emplace_back(name);
      } else {
        values.emplace_back(std::string(name), std::string(item.substr(equals + 1)));
      }
    }
  }

  const char* option(std::string_view name) const {
    for (const auto& [key, value] : values)
      if (key == name && !value.empty())
        return value.c_str();
    return nullptr;
  }

  bool flag(std::string_view name) const {
    for (const std::string& f : flags)
      if (f == name)
        return true;
    return false;
  }

  unsigned number(std::string_view name, unsigned fallback, unsigned maximum) const {
    const char* value = option(name);

    if (!value)
      return fallback;

    char* end = nullptr;
    errno = 0;
    const unsigned long parsed = std::strtoul(value, &end, 0);

    if (value[0] == '-' || errno || *end || parsed > maximum) {
      std::fprintf(stderr, "razor: invalid %.*s=%s; using %u\n", int(name.size()), name.data(), value, fallback);
      return fallback;
    }

    return unsigned(parsed);
  }
};
const char* error_name(int result) {
  switch (uint32_t(result)) {
  case 0x80020005:
    return "kernel PA invalid argument";
  case 0x80021102:
    return "kernel PA invalid key";
  case 0x80027205:
    return "kernel PA not claimed";
  default:
    return "native API error";
  }
}

void report(int result, const char* operation) {
  std::fprintf(stderr, "razor: %s = %08x (%s)\n", operation, unsigned(result), result >= 0 ? "ok" : error_name(result));
}

bool write_bytes(const void* data, unsigned bytes) {
  const auto* next = static_cast<const char*>(data);

  while (bytes) {
    int written = sceIoWrite(state.output, next, bytes);

    if (written <= 0) {
      report(written, "write live results");
      sceIoClose(state.output);
      state.output = -1;
      return false;
    }

    next += written;
    bytes -= unsigned(written);
  }

  return true;
}

bool record(const char tag[4], const void* data, unsigned bytes) {
  if (state.output < 0)
    return false;

  const uint32_t padding = 0;
  return write_bytes(tag, 4) && write_bytes(&bytes, 4) && write_bytes(data, bytes) && write_bytes(&padding, (4 - bytes % 4) % 4);
}

void flush_cpu_work() {
  // Emit complete RZLV records in one write per heartbeat, outside BATS/DATA.
  if (!state.cpuWork.empty()) {
    write_bytes(state.cpuWork.data(), unsigned(state.cpuWork.size() * sizeof(CpuWorkRecord)));
    state.cpuWork.clear();
  }

  if (state.cpuDropped) {
    record("CPUD", &state.cpuDropped, sizeof(state.cpuDropped));
    state.cpuDropped = 0;
  }
}

void flush_scene_work() {
  if (!state.scenes.empty()) {
    write_bytes(state.scenes.data(), unsigned(state.scenes.size() * sizeof(SceneRecord)));
    state.scenes.clear();
  }

  state.activeScene = UINT32_MAX;

  if (state.sceneDropped) {
    record("SCND", &state.sceneDropped, sizeof(state.sceneDropped));
    state.sceneDropped = 0;
  }
}

// Kept in memory until the window ends. PA frequency is in MHz: the HUD divides raw ticks
// by it to obtain us. Preserve both clock domains and the syscall bracket, never assume
// their epoch matches. A PA block that does not count returns zero ticks.
// SceRazorHud's status 3 (reset the counters, graphics on) with the group's selects, or 0.
int set_hwperf(bool on) {
  SgxSetHwPerfStatus info{};
  info.status = on ? 3 : 0;

  for (unsigned n = 0; on && n < 8; ++n) {
    info.group[n] = HwPerfGroup[state.group][n];
    info.bit[n] = HwPerfBit[state.group][n];
  }

  return SGXGetMiscInfo(sceGxmGetTopContextInternal(), &info);
}

void clock_anchor() {
  if (state.clocks.size() == MaxClockRecords)
    return;

  ClockRecord clock{};
  clock.frequencyMHz = sceKernelPaGetTimebaseFrequency();
  clock.kernelBefore = sceKernelGetSystemTimeWide();
  clock.paTicks = sceKernelPaGetTimebaseValue();
  clock.kernelAfter = sceKernelGetSystemTimeWide();
  clock.heartbeat = state.frame;
  state.clocks.push_back(clock);
}

uint32_t trace_written() {
  return sceKernelPaGetWritePointer() - state.traceBase;
}

bool begin_live() {
  state.output = sceIoOpen(state.livePath, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC | SCE_O_NOBUF, 0777);

  if (state.output < 0) {
    report(state.output, "open live output");
    return false;
  }

  const uint32_t header[2] = {0x564c5a52, 1}; // RZLV, little endian
  if (!write_bytes(header, sizeof(header)))
    return false;

  char metadata[1024];
  const int length =
      std::snprintf(metadata, sizeof(metadata),
                    "pid=0x%08x\ngroup=%u\nsource=Performance Analyzer GPU trace (pamgr)\nclock=PA ticks; CLCK anchors kernel microseconds at each heartbeat\ncollection=in device memory; written after the window\ncpu_processing=%s\ncpu_scope=%s\nscene_records=%s\nscene_frame=completed heartbeats at scene begin; ordinal is not assumed to equal PA sceneId\nscene_clock=kernel microseconds at scene begin\n",
                    unsigned(sceKernelGetProcessId()), state.group, state.cpuTrace ? "kernel microseconds; CPUX native game/render owner pre-presentation wall intervals" : "disabled",
                    state.cpuTrace ? "native-owner-prepresent" : "disabled", state.sceneTrace ? "application draws; excludes driver internal work" : "disabled");
  record("META", metadata, unsigned(length));

  // The PA writes the trace by physical address, and the CPU reads it back uncached.
  state.traceBlock = sceKernelAllocMemBlock("razor_pa_trace", SCE_KERNEL_MEMBLOCK_TYPE_USER_MAIN_PHYCONT_NC_RW, state.traceBytes, nullptr);
  int result = state.traceBlock;

  if (result >= 0)
    result = sceKernelGetMemBlockBase(state.traceBlock, &state.trace);

  report(result, "allocate the PA trace buffer");

  if (result >= 0) {
    result = sceKernelPaRegisterShared(PaKey[0], PaKey[1]);
    report(result, "register with pamgr");
  }

  if (result >= 0) {
    state.paKey = result;

    if (sceKernelPaGetTraceBufferStatus() & 1)
      sceKernelPaStopByKey(state.paKey);

    SceKernelPaGpuTraceParam gpu{PaGpuMode, {SamplePeriod, SamplePeriod}, {}, {}, {}};

    for (unsigned core = 0; core < 4; ++core) {
      gpu.selectsA[core] = GroupSelects[state.group][0];
      gpu.selectsB[core] = GroupSelects[state.group][1];
    }

    // The SGX's counters first: the PA only samples them.
    const int hwperf = set_hwperf(true);
    state.hwperf = hwperf == 0;
    std::fprintf(stderr, "razor: switch the SGX performance counters on = %d (PVRSRV_ERROR, 0: ok)\n", hwperf);
    // SceRazorHud's order: the buffer, the GPU trace, both bookmark channels, then start.
    const SceKernelPaTraceBufferParam buffer{1, state.trace, state.traceBytes, 0, 0};
    result = _sceKernelPaSetupTraceBufferByKey(state.paKey, &buffer);
    report(result, "set up the PA trace buffer");
    // Until the PA writes, the write pointer is the buffer's physical base.
    state.traceBase = sceKernelPaGetWritePointer();

    if (result >= 0) {
      result = _sceKernelPaAddGpuTraceByKey(state.paKey, &gpu);
      report(result, "add the GPU trace");
    }

    for (unsigned fifo = 0; result >= 0 && fifo < 2; ++fifo)
      result = sceKernelPaSetBookmarkChannelEnableByKey(state.paKey, fifo, 0xffff);

    if (result >= 0) {
      struct Config {
        uint32_t group, mode, selectsA, selectsB, period, traceBytes, paMHz, gpuMHz;
      } config{state.group, PaGpuMode, gpu.selectsA[0], gpu.selectsB[0], SamplePeriod, state.traceBytes,
               sceKernelPaGetTimebaseFrequency(), uint32_t(scePowerGetGpuClockFrequency())};
      static_assert(sizeof(Config) == 32);
      record("PACF", &config, sizeof(config));
      result = sceKernelPaStartByKey(state.paKey);
    }
  }

  report(result, "start the PA GPU trace");
  record("STAT", &result, sizeof(result));

  if (result < 0)
    return false;

  state.clocks.reserve(state.liveFrames ? state.liveFrames + 2 : MaxClockRecords);
  clock_anchor();
  state.live = true;
  return true;
}

// One heartbeat: an anchor, and whether the window goes on (frames left, buffer not full).
bool collect() {
  clock_anchor();
  ++state.sequence;
  return (!state.liveFrames || state.sequence < state.liveFrames) && trace_written() + TraceSlack < state.traceBytes &&
         !(sceKernelPaGetTraceBufferStatus() & 4);
}

// The whole trace, raw, as one PATR record: its header, then the 128-byte blocks.
void write_trace(int stopped) {
  struct Header {
    uint32_t sequence, heartbeat, segment, status, offset, bytes, gpuMHz, firstHeartbeat;
  } header{state.sequence, state.frame, 0, sceKernelPaGetTraceBufferStatus(), 0, 0,
           uint32_t(scePowerGetGpuClockFrequency()), state.liveStartFrame};
  static_assert(sizeof(Header) == 32);
  const uint32_t written = trace_written();

  if (stopped >= 0 && written <= state.traceBytes)
    header.bytes = written & ~127u;
  else if (stopped >= 0)
    report(int(0x80020005), "PA write pointer outside the trace buffer");

  const uint32_t bytes = sizeof(header) + header.bytes;
  if (write_bytes("PATR", 4) && write_bytes(&bytes, 4) && write_bytes(&header, sizeof(header)) && header.bytes)
    write_bytes(state.trace, header.bytes);
}

void close_live() {
  if (state.live) {
    const int result = sceKernelPaStopByKey(state.paKey);
    report(result, "stop the PA GPU trace");
    clock_anchor();
    flush_cpu_work();
    flush_scene_work();

    if (!state.clocks.empty())
      write_bytes(state.clocks.data(), unsigned(state.clocks.size() * sizeof(ClockRecord)));

    write_trace(result);
    record("STOP", &result, sizeof(result));
    state.live = false;
  }

  if (state.hwperf) {
    std::fprintf(stderr, "razor: switch the SGX performance counters off = %d (PVRSRV_ERROR, 0: ok)\n", set_hwperf(false));
    state.hwperf = false;
  }

  if (state.paKey >= 0) {
    sceKernelPaRemoveGpuTraceByKey(state.paKey);
    report(sceKernelPaUnregister(state.paKey), "unregister from pamgr");
    state.paKey = -1;
  }

  if (state.traceBlock >= 0) {
    sceKernelFreeMemBlock(state.traceBlock);
    state.traceBlock = -1;
    state.trace = nullptr;
  }

  if (state.output >= 0) {
    sceIoClose(state.output);
    state.output = -1;
  }

  std::vector<ClockRecord>().swap(state.clocks);
  state.finished = true;
}
} // namespace

void initialize(const char* text) noexcept {
  if (state.initialized)
    return;

  state.initialized = true;
  static const Options options(text); // its paths stay valid
  state.capturePath = options.option("capture");
  state.livePath = options.option("live");
  state.cpuTrace = state.livePath && options.flag("cpu");
  state.sceneTrace = state.livePath && options.flag("scenes");

  if (state.cpuTrace)
    state.cpuWork.reserve(MaxCpuWorkRecords);

  if (state.sceneTrace)
    state.scenes.reserve(MaxSceneRecords);

  const char* salvage = options.option("salvage");

  if (!state.capturePath && !state.livePath && !salvage)
    return;

  state.captureFrame = options.number("capture-frame", 120, UINT32_MAX - 1);
  state.liveStartFrame = options.number("start", 120, UINT32_MAX - 1);
  state.liveFrames = options.number("frames", 120, UINT32_MAX - 1);
  state.group = options.number("group", 1, 3);
  state.traceBytes = options.number("trace-mib", 8, 64) << 20;

  if (!state.traceBytes)
    state.traceBytes = 8u << 20;
  if (state.capturePath || salvage) {
    const SceUID result = sceKernelLoadStartModule(CaptureModule, 0, nullptr, 0, nullptr, nullptr);
    report(result, "load ur0:data/librazorcapture_es4.suprx before GXM");
    state.captureModule = result;
    state.capture.store(result >= 0, std::memory_order_relaxed);

    if (result >= 0 && salvage)
      sceRazorGpuCaptureEnableSalvage(salvage);
  }
}

uint64_t begin_cpu_work() noexcept {
  return state.cpuTrace && state.live ? sceKernelGetSystemTimeWide() : 0;
}

void end_cpu_work(uint64_t started) noexcept {
  if (!started || !state.live || !state.cpuTrace)
    return;

  const auto ended = uint64_t(sceKernelGetSystemTimeWide());

  if (state.cpuWork.size() == MaxCpuWorkRecords) {
    ++state.cpuDropped;
    return;
  }

  const auto thread = sceKernelGetThreadId();
  SceKernelThreadInfo info{};
  info.size = sizeof(info);

  // The calling thread and the core it ran on, as the kernel reports them.
  if (sceKernelGetThreadInfo(thread, &info) < 0 || unsigned(info.currentCpuId) >= 4) {
    ++state.cpuDropped;
    return;
  }

  state.cpuWork.push_back({0x58555043, 24, started, ended, unsigned(thread), unsigned(info.currentCpuId)});
}

bool scene_tracing() noexcept {
  return state.sceneTrace && !state.finished;
}

void scene_begin(uint32_t nativeFrame, uint32_t serial, uint32_t width, uint32_t height, uint32_t color, uint32_t depth, bool display) noexcept {
  if (!state.sceneTrace || !state.live)
    return;

  const auto ordinal = state.sceneOrdinal++;
  state.activeScene = UINT32_MAX;
  state.previousPass = 4;

  if (state.scenes.size() == MaxSceneRecords) {
    ++state.sceneDropped;
    return;
  }

  state.activeScene = unsigned(state.scenes.size());
  state.scenes.push_back({0x454e4353, 208, uint64_t(sceKernelGetSystemTimeWide()), state.frame, ordinal, nativeFrame, serial, width, height, color, depth, unsigned(display)});
}

void scene_draw(std::string_view kind, std::string_view label, uint32_t vertices, uint32_t indices, uint32_t instances, bool blend, bool discard, bool depthReplace) noexcept {
  if (!state.sceneTrace || !state.live || state.activeScene == UINT32_MAX)
    return;

  auto& scene = state.scenes[state.activeScene];
  ++scene.draws;
  scene.vertices += vertices;
  scene.indices += indices;
  scene.instances += instances;
  const unsigned pass = depthReplace ? 3 : discard ? 2 : blend ? 1 : 0;

  switch (pass) {
  case 0: ++scene.opaque; break;
  case 1: ++scene.translucent; break;
  case 2: ++scene.discard; break;
  case 3: ++scene.depthReplace; break;
  }

  if (state.previousPass != 4 && pass != state.previousPass) {
    ++scene.passSwitches;

    // Sony's HSR flush rule: Discard/DepthReplace -> Opaque/Translucent.
    // Actual tile flushes depend on the primitives touching that tile.
    scene.flushTransitions += state.previousPass >= 2 && pass < 2;
  }

  state.previousPass = pass;

  if (!scene.firstKind[0] && kind != "clear-color" && kind != "clear-depth") {
    const auto copy = [](char* output, size_t bytes, std::string_view value) {
      const size_t count = value.size() < bytes - 1 ? value.size() : bytes - 1;
      std::memcpy(output, value.data(), count);
      output[count] = 0;
    };

    copy(scene.firstKind, sizeof(scene.firstKind), kind);
    copy(scene.firstShader, sizeof(scene.firstShader), label);
  }
}

void frame() noexcept {
  ++state.frame;
  state.sceneOrdinal = 0;

  if (state.capture.load(std::memory_order_relaxed) && state.capturePath) {
    if (!state.captureTriggered && state.frame >= state.captureFrame) {
      sceRazorGpuCaptureSetTriggerNextFrame(state.capturePath);
      state.captureTriggered = true;
      std::fprintf(stderr, "razor: capture next frame after heartbeat %u -> %s\n", state.frame, state.capturePath);
    }

    if (state.captureTriggered) {
      const bool busy = sceRazorGpuCaptureIsInProgress() != SCE_FALSE;

      if (busy != state.captureBusy)
        std::fprintf(stderr, "razor: native capture %s\n", busy ? "in progress" : "finished");

      state.captureBusy = busy;
    }
  }

  if (!state.livePath || state.finished || state.frame < state.liveStartFrame)
    return;

  if (!state.live && !begin_live()) {
    close_live();
    return;
  }

  flush_cpu_work();
  flush_scene_work();

  if (!collect() || state.output < 0)
    close_live();
}

void stop() noexcept {
  if (state.live || state.output >= 0)
    close_live();
}

void terminate() noexcept {
  stop();

  if (state.capture.exchange(false, std::memory_order_relaxed))
    report(sceKernelStopUnloadModule(state.captureModule, 0, nullptr, 0, nullptr, nullptr),
           "unload capture after GXM");
  state.captureModule = -1;

  std::vector<CpuWorkRecord>().swap(state.cpuWork);
  std::vector<SceneRecord>().swap(state.scenes);
  state.sceneTrace = false;
  state.sceneDropped = state.sceneOrdinal = 0;
  state.activeScene = UINT32_MAX;
  state.previousPass = 4;
  state.cpuTrace = false;
  state.cpuDropped = 0;
  state.initialized = false;
  state.finished = false;
  state.captureTriggered = state.captureBusy = false;
  state.frame = state.sequence = 0;
}

void register_buffer(void* base, std::size_t bytes) noexcept {
  if (!state.capture.load(std::memory_order_relaxed) || !base || !bytes)
    return;

  if (bytes > UINT32_MAX) {
    report(int(0x8008c001), "capture buffer over 4 GiB");
    return;
  }

  const int result = sceGxmAddRazorGpuCaptureBuffer(base, uint32_t(bytes));

  if (result < 0)
    report(result, "register dynamic GPU capture buffer");
}

void unregister_buffer(void* base) noexcept {
  if (!state.capture.load(std::memory_order_relaxed) || !base)
    return;

  const int result = sceGxmRemoveRazorGpuCaptureBuffer(base);

  if (result < 0)
    report(result, "unregister dynamic GPU capture buffer");
}
} // namespace razor
