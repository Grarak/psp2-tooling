#pragma once
// Sony Razor GPU recording for a GXM app on a DevKit: live GPU metrics (.rzlv, razor/rzlv.py)
// and frame snapshots (.sgx, razor/sgx_capture.py). Add razor.cpp to the app and link
// SceRazorCapture_stub_weak, SceRazorHud_stub_weak, ScePamgr_stub, SceSysmodule_stub and
// SceGxm_stub. With no live= or capture= option the hooks make no Razor calls.
//
// Live metrics need LIVE=1 in host0:/hud_settings.ini (missing: STAT 0x8008c008; another
// mode: 0x8008c002, and the collector never starts).
//
// Options, comma-separated:
//   live=PATH        .rzlv output; enables live metrics (host0:/gpu.rzlv)
//   group=N          metrics group: 0 parameter buffer, 1 USSE/texture activity (default),
//                    2 primitive/vertex/pixel counts, 3 TA/ISP memory bytes
//   start=N          start after this many frame() calls (default 120)
//   frames=N         collections to record (default 120; 0: until stop())
//   hide-hud         hide Sony's HUD overlay; collection continues
//   scenes           scene records from scene_begin()/scene_draw()
//   cpu              CPU wall spans from begin_cpu_work()/end_cpu_work() (one thread only)
//   capture=PATH     .sgx snapshot of the frame after capture-frame=N (default 120); a
//                    snapshot pauses the GPU, so leave it off while measuring
//   salvage=PATH     snapshot on a GPU lockup
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace razor {
void initialize(const char* options) noexcept; // before sceGxmInitialize
void frame() noexcept;                         // after each sceGxmPadHeartbeat
void stop() noexcept;                          // after the last sceGxmFinish
void terminate() noexcept;                     // after sceGxmTerminate

// With capture=: every GPU-mapped buffer (sceGxmMapMemory) goes into the snapshot.
void register_buffer(void* base, std::size_t bytes) noexcept;
void unregister_buffer(void* base) noexcept;

// With cpu=: kernel-clock wall time of a span of CPU work, waits and preemption included.
uint64_t begin_cpu_work() noexcept;
void end_cpu_work(uint64_t started) noexcept;

// With scenes=: one record per scene and its draws. The ordinal is not Sony's scene ID.
bool scene_tracing() noexcept;
void scene_begin(uint32_t nativeFrame, uint32_t serial, uint32_t width, uint32_t height, uint32_t color,
                 uint32_t depth, bool display) noexcept;
void scene_draw(std::string_view kind, std::string_view label, uint32_t vertices, uint32_t indices,
                uint32_t instances, bool blend, bool discard, bool depthReplace) noexcept;
} // namespace razor
