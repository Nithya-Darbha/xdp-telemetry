cmake_minimum_required(VERSION 3.20)
project(xdp_telemetry LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

# ---------------------------------------------------------------------------
# Toolchain for the BPF side
# ---------------------------------------------------------------------------
find_program(BPF_CLANG NAMES clang REQUIRED)

# Ubuntu ships /usr/sbin/bpftool as a wrapper that only works when a
# linux-tools package matches the running kernel. Probe for a binary that runs.
set(BPFTOOL "" CACHE FILEPATH "Path to a working bpftool")
if(NOT BPFTOOL)
  file(GLOB _bpftool_globs /usr/lib/linux-tools/*/bpftool)
  find_program(_bpftool_path NAMES bpftool)
  foreach(cand ${_bpftool_path} ${_bpftool_globs})
    execute_process(COMMAND ${cand} version RESULT_VARIABLE rc OUTPUT_QUIET ERROR_QUIET)
    if(rc EQUAL 0)
      set(BPFTOOL ${cand} CACHE FILEPATH "Path to a working bpftool" FORCE)
      break()
    endif()
  endforeach()
endif()
if(NOT BPFTOOL)
  message(FATAL_ERROR "No working bpftool found. Install linux-tools-generic or pass -DBPFTOOL=/path/to/bpftool")
endif()
message(STATUS "bpftool: ${BPFTOOL}")

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED IMPORTED_TARGET libbpf>=1.0)

# -target bpf does not search the multiarch include dir, where asm/types.h lives.
execute_process(COMMAND ${CMAKE_C_COMPILER} -print-multiarch
                OUTPUT_VARIABLE MULTIARCH OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
if(NOT MULTIARCH)
  set(MULTIARCH ${CMAKE_SYSTEM_PROCESSOR}-linux-gnu)
endif()

# bpf_add_object(<name> <source.bpf.c>)
#   compiles <source> to <name>.bpf.o and generates <name>.skel.h,
#   exposed as INTERFACE target <name>_skel for userspace to link against.
function(bpf_add_object name src)
  set(obj ${CMAKE_CURRENT_BINARY_DIR}/${name}.bpf.o)
  set(skel ${CMAKE_CURRENT_BINARY_DIR}/${name}.skel.h)
  add_custom_command(
    OUTPUT ${obj}
    COMMAND ${BPF_CLANG} -g -O2 -target bpf -Wall -Werror
            -I${CMAKE_SOURCE_DIR}/include -I${CMAKE_SOURCE_DIR}/bpf
            -I/usr/include/${MULTIARCH}
            -MD -MF ${obj}.d
            -c ${CMAKE_CURRENT_SOURCE_DIR}/${src} -o ${obj}
    DEPENDS ${src}
    DEPFILE ${obj}.d
    COMMENT "BPF ${src}"
    VERBATIM)
  add_custom_command(
    OUTPUT ${skel}
    COMMAND ${BPFTOOL} gen skeleton ${obj} name ${name} > ${skel}
    DEPENDS ${obj}
    COMMENT "skeleton ${name}.skel.h"
    VERBATIM)
  add_custom_target(${name}_skel_gen DEPENDS ${skel})
  add_library(${name}_skel INTERFACE)
  add_dependencies(${name}_skel ${name}_skel_gen)
  target_include_directories(${name}_skel INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
  target_link_libraries(${name}_skel INTERFACE PkgConfig::LIBBPF)
endfunction()

add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-Wall> $<$<COMPILE_LANGUAGE:CXX>:-Wextra>)

bpf_add_object(telemetry bpf/telemetry.bpf.c)

add_executable(xdpt src/collector/main.cpp)
target_include_directories(xdpt PRIVATE include)
target_link_libraries(xdpt PRIVATE telemetry_skel)
target_include_directories(xdpt PRIVATE bpf)

# ---------------------------------------------------------------------------
# Tests: parse.h compiled as userspace C++ under ASan/UBSan
# ---------------------------------------------------------------------------
option(XDPT_BUILD_TESTS "Build unit tests" ON)
if(XDPT_BUILD_TESTS)
  enable_testing()
  add_executable(parser_test tests/parser_test.cpp)
  target_include_directories(parser_test PRIVATE include bpf)
  target_compile_options(parser_test PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
  target_link_options(parser_test PRIVATE -fsanitize=address,undefined)
  add_test(NAME parser COMMAND parser_test)
endif()
