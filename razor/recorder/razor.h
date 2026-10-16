#pragma once
// Sony Razor GPU recording for a GXM app on a DevKit or a retail Vita: live GPU metrics (.rzlv,
// razor/rzlv.py) and frame snapshots (.sgx, razor/sgx_capture.py). Add razor.cpp to the app and
// link SceRazorCapture_stub_weak, ScePamgr_stub, ScePower_stub, SceGxm_stub and
// SceGpuEs4User_stub, which VitaSDK lacks: build it from SceGpuEs4User.yml beside this file
// (vita-libs-gen SceGpuEs4User.yml OUT && make -C OUT). With no live= or capture= option the
// hooks make no Razor calls.
//
// Like the HUD, live metrics first switch the SGX's own performance counters on
// (SGXGetMiscInfo, SET_HWPERF_STATUS) with the group's selects: the PA samples those counters,
// and without that every counter in the trace reads zero on hardware.
//
// Live metrics drive the Performance Analyzer through pamgr the way Sony's Razor HUD does,
// without the HUD: the PA samples into the recorder's buffer for the whole window, which is
// written out raw only when the window ends, and razor/rzlv.py turns the samples into
// per-core TA/3D busy intervals offline. The HUD's 40 us sampling makes up to 4 MB/s, so the
// buffer bounds the window (group 1: about 2 s per 8 MiB). pamgr is resident on a
// DevKit; a retail Vita needs retail-cp, which loads it and accepts the recorder's buffer.
//
// Snapshots load librazorcapture_es4.suprx from ur0:data/; copy it there from DevKit firmware's
// vs0:sys/external. A retail Vita rejects that encrypted SELF (0x800f0516): give it an fSELF of
// the decrypted ELF instead (vita-make-fself -c librazorcapture_es4.elf librazorcapture_es4.suprx).
//
// Options, comma-separated:
//   live=PATH        .rzlv output; enables live metrics (host0:/gpu.rzlv)
//   group=N          the PA counter selects of the HUD's metrics group: 0 parameter buffer,
//                    1 USSE/texture activity (default), 2 primitive/vertex/pixel counts,
//                    3 TA/ISP memory bytes; every group carries the TA/3D busy counters
//   start=N          start after this many frame() calls (default 120)
//   frames=N         frames to trace (default 120; 0: until stop()); a full buffer ends the
//                    window early
//   trace-mib=N      trace buffer in MiB, physically contiguous (default 8, at most 64)
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
