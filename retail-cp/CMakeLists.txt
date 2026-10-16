# retail-cp.skprx, the taiHEN kernel plugin that stands in for a DevKit's CP board on a retail
# Vita.
#   cmake -S retail-cp -B build/retail-cp && cmake --build build/retail-cp
cmake_minimum_required(VERSION 3.16)
set(CMAKE_TOOLCHAIN_FILE "$ENV{VITASDK}/share/vita.toolchain.cmake" CACHE PATH "Vita toolchain")
project(psp2_retail C)
include("$ENV{VITASDK}/share/vita.cmake")

add_executable(retail_cp main.c report.c services.c usb.c shell.c dtrace.c console.c switches.c power.c
  crash.c words.c)
target_compile_options(retail_cp PRIVATE -Wall -Wextra -Werror -O2 -std=gnu11 -mgeneral-regs-only)
target_link_options(retail_cp PRIVATE -nostdlib -Wl,-q -Wl,-e,module_start)
target_link_libraries(retail_cp gcc SceSysclibForDriver_stub SceCpuForDriver_stub
  SceThreadmgrForDriver_stub SceIofilemgrForDriver_stub SceDebugForDriver_stub
  SceModulemgrForDriver_stub SceUdcdForDriver_stub SceDipswForDriver_stub
  SceSysmemForDriver_stub SceSysmemForKernel_363_stub SceModulemgrForKernel_363_stub
  SceSysconForDriver_stub ScePowerForDriver_stub SceKernelSuspendForDriver_stub
  SceSysrootForKernel_stub SceSysrootForDriver_stub SceDebugForKernel_363_stub taihenForKernel_stub
  taihenModuleUtils_stub SceCtrlForDriver_stub)
vita_create_self(retail-cp.skprx retail_cp UNSAFE CONFIG ${CMAKE_CURRENT_SOURCE_DIR}/retail-cp-exports.yml)
