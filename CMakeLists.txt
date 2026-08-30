cmake_minimum_required(VERSION 3.20)
project(gtp_meter
        VERSION 1.0.0
        DESCRIPTION "GTP-U / Diameter parser and line-rate metering pipeline"
        LANGUAGES CXX)

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
option(GTPM_BUILD_TESTS  "Build unit tests"                 ON)
option(GTPM_BUILD_BENCH  "Build benchmark harness"          ON)
option(GTPM_BUILD_FUZZ   "Build fuzz targets"               ON)
option(GTPM_NATIVE_ARCH  "Tune for the host CPU"            ON)
option(GTPM_ASAN         "Build with AddressSanitizer"      OFF)
option(GTPM_UBSAN        "Build with UndefinedBehaviorSan"  OFF)
option(GTPM_TSAN         "Build with ThreadSanitizer"       OFF)
option(GTPM_WERROR       "Treat warnings as errors"         OFF)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# ---------------------------------------------------------------------------
# Warning / architecture flags shared by every target
# ---------------------------------------------------------------------------
add_library(gtpm_flags INTERFACE)
target_compile_options(gtpm_flags INTERFACE
  $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall;-Wextra;-Wpedantic;-Wshadow;-Wconversion;-Wsign-conversion;-Wcast-qual;-Wnon-virtual-dtor>
  $<$<AND:$<BOOL:${GTPM_WERROR}>,$<CXX_COMPILER_ID:GNU,Clang,AppleClang>>:-Werror>
  $<$<CXX_COMPILER_ID:MSVC>:/W4>)

if(GTPM_NATIVE_ARCH AND NOT CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
  include(CheckCXXCompilerFlag)
  check_cxx_compiler_flag("-march=native" GTPM_HAS_MARCH_NATIVE)
  if(GTPM_HAS_MARCH_NATIVE)
    target_compile_options(gtpm_flags INTERFACE -march=native)
  else()
    # Apple silicon clang wants -mcpu=native instead of -march=native.
    check_cxx_compiler_flag("-mcpu=native" GTPM_HAS_MCPU_NATIVE)
    if(GTPM_HAS_MCPU_NATIVE)
      target_compile_options(gtpm_flags INTERFACE -mcpu=native)
    endif()
  endif()
endif()

set(GTPM_SANITIZERS "")
if(GTPM_ASAN)
  list(APPEND GTPM_SANITIZERS address)
endif()
if(GTPM_UBSAN)
  list(APPEND GTPM_SANITIZERS undefined)
endif()
if(GTPM_TSAN)
  list(APPEND GTPM_SANITIZERS thread)
endif()
if(GTPM_SANITIZERS)
  list(JOIN GTPM_SANITIZERS "," GTPM_SANITIZER_LIST)
  target_compile_options(gtpm_flags INTERFACE
                         -fsanitize=${GTPM_SANITIZER_LIST} -fno-omit-frame-pointer -g)
  target_link_options(gtpm_flags INTERFACE -fsanitize=${GTPM_SANITIZER_LIST})
endif()

# ---------------------------------------------------------------------------
# Core library
# ---------------------------------------------------------------------------
add_subdirectory(src)

if(GTPM_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

if(GTPM_BUILD_BENCH)
  add_subdirectory(bench)
endif()

message(STATUS "gtp-meter ${PROJECT_VERSION}")
message(STATUS "  build type : ${CMAKE_BUILD_TYPE}")
message(STATUS "  compiler   : ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "  tests      : ${GTPM_BUILD_TESTS}")
message(STATUS "  bench      : ${GTPM_BUILD_BENCH}")
message(STATUS "  fuzz       : ${GTPM_BUILD_FUZZ}")
message(STATUS "  sanitizers : ${GTPM_SANITIZER_LIST}")
