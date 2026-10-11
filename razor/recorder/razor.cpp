#include "razor.h"
#include <psp2/gxm.h>
#include <psp2/io/fcntl.h>
#include <psp2/kernel/processmgr.h>
#include <psp2/kernel/threadmgr.h>
#include <psp2/pamgr.h>
#include <psp2/razor_capture.h>
#include <psp2/razor_hud.h>
#include <psp2/sysmodule.h>
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
int sceRazorHudReloadSettings(void);
int sceRazorHudSetDisplayEnabled(SceBool displayEnabled);
uint32_t sceRazorGpuPerfGetMode(void);
SceBool sceRazorGpuCaptureIsInProgress(void);
}

namespace razor {
namespace {
constexpr unsigned BufferBytes = 256u << 10;
constexpr uint32_t LiveMode = 3;
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
  bool initialized = false, hud = false, live = false, finished = false;
  bool captureTriggered = false, captureBusy = false;
  std::atomic<bool> capture{false};
  const char* capturePath = nullptr;
  const char* livePath = nullptr;
  unsigned captureFrame = 120, liveStartFrame = 120, liveFrames = 120;
  unsigned frame = 0, group = 1, sequence = 0, index = 0;
  bool cpuTrace = false, hideHud = false;
  uint32_t cpuDropped = 0;
  std::vector<CpuWorkRecord> cpuWork;
  bool sceneTrace = false;
  uint32_t sceneDropped = 0, sceneOrdinal = 0, activeScene = UINT32_MAX, previousPass = 4;
  std::vector<SceneRecord> scenes;
  SceUID output = -1;
  void* buffers[2]{};
} state;
// item[,item...]: live=PATH, group=N, start=N, frames=N, hide-hud, scenes, cpu, capture=PATH,
// capture-frame=N, salvage=PATH (razor.h).
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

      for (const std::string_view k : {"live", "group", "start", "frames", "capture", "capture-frame", "salvage"})
        known |= equals != std::string_view::npos && name == k;

      for (const std::string_view k : {"hide-hud", "scenes", "cpu"})
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
  case 0x8008c000:
    return "not initialized";
  case 0x8008c001:
    return "invalid argument";
  case 0x8008c002:
    return "LIVE=1 required in hud_settings.ini";
  case 0x8008c003:
    return "live collector not started";
  case 0x8008c004:
    return "live collector already started";
  case 0x8008c005:
    return "PA block unavailable";
  case 0x8008c006:
    return "PA trace overflow";
  case 0x8008c007:
    return "buffer not 8-byte aligned";
  case 0x8008c008:
    return "hud_settings.ini not found";
  case 0x8008c009:
    return "invalid pointer";
  case 0x80021102:
    return "kernel PA invalid key";
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

void clock_anchor() {
  // PA frequency is in MHz: the HUD divides raw ticks by it to obtain us.
  // Preserve both clock domains and the syscall bracket, never assume their
  // epoch matches. A PA block that does not count returns zero ticks.
  struct Clock {
    uint64_t kernelBefore, paTicks, kernelAfter;
    uint32_t frequencyMHz, reserved;
  } clock{};
  clock.frequencyMHz = sceKernelPaGetTimebaseFrequency();
  clock.kernelBefore = sceKernelGetSystemTimeWide();
  clock.paTicks = sceKernelPaGetTimebaseValue();
  clock.kernelAfter = sceKernelGetSystemTimeWide();
  static_assert(sizeof(Clock) == 32);
  record("CLCK", &clock, sizeof(clock));
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
                    "pid=0x%08x\ngroup=%u\nsource=Sony Razor GPU Live Metrics\nclock=PA microseconds; CLCK anchors kernel microseconds\ncollection=asynchronous\ncpu_processing=%s\ncpu_scope=%s\nhud_display=%s\nscene_records=%s\nscene_frame=completed heartbeats at scene begin; ordinal is not assumed to equal PA sceneId\nscene_clock=kernel microseconds at scene begin\n",
                    unsigned(sceKernelGetProcessId()), state.group, state.cpuTrace ? "kernel microseconds; CPUX native game/render owner pre-presentation wall intervals" : "disabled",
                    state.cpuTrace ? "native-owner-prepresent" : "disabled", state.hideHud ? "disabled" : "default", state.sceneTrace ? "application draws; excludes driver/HUD internal work" : "disabled");
  record("META", metadata, unsigned(length));
  int result = sceRazorHudReloadSettings();
  report(result, "reload HUD settings");

  if (result < 0) {
    record("STAT", &result, sizeof(result));
    return false;
  }

  if (state.hideHud) {
    // Display visibility and LIVE metrics are separate Sony APIs. Settings
    // reload restores display defaults, so hide only after that reload.
    result = sceRazorHudSetDisplayEnabled(SCE_FALSE);
    report(result, "hide live HUD display");

    if (result < 0) {
      record("STAT", &result, sizeof(result));
      return false;
    }
  }

  const uint32_t mode = sceRazorGpuPerfGetMode();
  record("MODE", &mode, sizeof(mode));
  std::fprintf(stderr, "razor: native performance mode %u (live requires 3)\n", mode);
  result = sceRazorGpuLiveSetMetricsGroup(state.group);
  report(result, "select live metrics group");

  if (result >= 0 && mode == LiveMode)
    result = sceRazorGpuLiveStart();
  else if (result >= 0)
    result = int(0x8008c002);

  report(result, "start live GPU collection");
  record("STAT", &result, sizeof(result));
  clock_anchor();

  if (result < 0)
    return false;

  state.live = true;

  for (auto& buffer : state.buffers) {
    buffer = memalign(8, BufferBytes);

    if (!buffer) {
      report(int(0x8008c009), "allocate live result buffer");
      return false;
    }
  }

  return true;
}

void collect() {
  SceRazorGpuLiveResultInfo results{};
  const int result = sceRazorGpuLiveSetBuffer(state.buffers[state.index], BufferBytes, &results);
  state.index ^= 1;

  // The pointer belongs to the previous buffer. Walk entry sizes within the
  // reported capacity before writing; never serialize a target-side pointer.
  unsigned bytes = 0;

  if (results.result_data) {
    for (unsigned i = 0; i < results.entry_count; ++i) {
      if (bytes > results.buffer_size || results.buffer_size - bytes < sizeof(SceRazorGpuLiveEntryHeader)) {
        report(int(0x8008c001), "truncated live result header");
        return;
      }

      const auto* entry = reinterpret_cast<const SceRazorGpuLiveEntryHeader*>(static_cast<const char*>(results.result_data) + bytes);

      if (entry->entry_size < sizeof(*entry) || entry->entry_size > results.buffer_size - bytes) {
        report(int(0x8008c001), "invalid live result size");
        return;
      }

      bytes += entry->entry_size;
    }
  } else if (results.entry_count) {
    report(int(0x8008c009), "missing live result data");
    return;
  }

  struct Batch {
    uint32_t sequence, heartbeat, status, entryCount, overflowCount, bytes, group, reserved;
    uint64_t start, end;
  } batch{state.sequence++, state.frame, uint32_t(result), results.entry_count, results.overflow_count, bytes, results.metric_group, 0, results.start_time, results.end_time};
  static_assert(sizeof(Batch) == 48);
  clock_anchor();
  record("BATS", &batch, sizeof(batch));

  if (bytes)
    record("DATA", results.result_data, bytes);

  if (result < 0)
    report(result, "collect live GPU results");

  if (results.overflow_count)
    std::fprintf(stderr, "razor: dropped %u live entries at heartbeat %u\n", unsigned(results.overflow_count), state.frame);
}

void close_live() {
  if (state.live) {
    flush_cpu_work();
    flush_scene_work();
    collect();
    const int result = sceRazorGpuLiveStop();
    report(result, "stop live GPU collection");
    record("STOP", &result, sizeof(result));
    state.live = false;
  }

  if (state.output >= 0) {
    sceIoClose(state.output);
    state.output = -1;
  }

  for (auto& buffer : state.buffers) {
    std::free(buffer);
    buffer = nullptr;
  }

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
  state.hideHud = state.livePath && options.flag("hide-hud");
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
  if (state.capturePath || salvage) {
    const int result = sceSysmoduleLoadModule(SCE_SYSMODULE_RAZOR_CAPTURE);
    report(result, "load capture module before GXM");
    state.capture.store(result >= 0, std::memory_order_relaxed);

    if (result >= 0 && salvage)
      sceRazorGpuCaptureEnableSalvage(salvage);
  }

  if (state.livePath) {
    const int result = sceSysmoduleLoadModule(SCE_SYSMODULE_RAZOR_HUD);
    report(result, "load HUD module before GXM");
    state.hud = result >= 0;
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

  if (!state.hud || state.finished || state.frame < state.liveStartFrame)
    return;

  if (!state.live && !begin_live()) {
    close_live();
    return;
  }

  flush_cpu_work();
  flush_scene_work();
  collect();

  if (state.output < 0 || (state.liveFrames && state.sequence >= state.liveFrames))
    close_live();
}

void stop() noexcept {
  if (state.live || state.output >= 0)
    close_live();
}

void terminate() noexcept {
  stop();

  if (state.hud)
    report(sceSysmoduleUnloadModule(SCE_SYSMODULE_RAZOR_HUD), "unload HUD after GXM");

  if (state.capture.exchange(false, std::memory_order_relaxed))
    report(sceSysmoduleUnloadModule(SCE_SYSMODULE_RAZOR_CAPTURE), "unload capture after GXM");

  std::vector<CpuWorkRecord>().swap(state.cpuWork);
  std::vector<SceneRecord>().swap(state.scenes);
  state.sceneTrace = false;
  state.sceneDropped = state.sceneOrdinal = 0;
  state.activeScene = UINT32_MAX;
  state.previousPass = 4;
  state.cpuTrace = false;
  state.cpuDropped = 0;
  state.hud = false;
  state.initialized = false;
  state.finished = false;
  state.captureTriggered = state.captureBusy = false;
  state.frame = state.sequence = state.index = 0;
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
