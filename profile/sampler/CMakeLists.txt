cmake_minimum_required(VERSION 3.16)
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  if(NOT DEFINED ENV{VITASDK})
    set(ENV{VITASDK} /usr/local/vitasdk)
  endif()
  set(CMAKE_TOOLCHAIN_FILE "$ENV{VITASDK}/share/vita.toolchain.cmake" CACHE PATH "toolchain")
endif()
project(psp2prof C)
include("$ENV{VITASDK}/share/vita.cmake" REQUIRED)

# The loader app (PSP2PROF0). First: vita_create_self's CONFIG carries over to later calls.
add_executable(psp2prof_loader loader.c)
target_compile_options(psp2prof_loader PRIVATE -Wall -Wextra)
target_link_libraries(psp2prof_loader taihen_stub SceLibKernel_stub)
vita_create_self(eboot.bin psp2prof_loader UNSAFE)

# The kernel plugin. No NEON: a kernel plugin must not touch the VFP/NEON registers, which the
# kernel does not save around it, and GCC vectorises plain loops by default.
add_executable(psp2prof psp2prof.c)
target_compile_options(psp2prof PRIVATE -Wall -Wextra -O2 -fno-tree-vectorize)
target_link_options(psp2prof PRIVATE -nostdlib -Wl,-q)
target_link_libraries(psp2prof taihenForKernel_stub taihenModuleUtils_stub
  SceIofilemgrForDriver_stub SceSysclibForDriver_stub SceSysmemForDriver_stub
  SceThreadmgrForDriver_stub SceDebugForDriver_stub)
vita_create_self(psp2prof.skprx psp2prof CONFIG exports.yml UNSAFE)

# psp2prof.vpk: the loader with the plugin beside its eboot.
vita_create_vpk(psp2prof.vpk PSP2PROF0 eboot.bin VERSION 01.00 NAME "psp2prof"
  FILE ${CMAKE_CURRENT_BINARY_DIR}/psp2prof.skprx psp2prof.skprx)
