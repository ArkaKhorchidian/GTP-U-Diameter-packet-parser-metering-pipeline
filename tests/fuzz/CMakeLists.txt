# Fuzz targets.
#
# With a toolchain that has libFuzzer (clang on Linux) these build as real
# fuzzers. Without it (Apple clang ships none) they build against a standalone
# driver that replays corpus files or generates pseudo-random input, so the
# harnesses stay compiled and exercised everywhere, and CTest can run them.

include(CheckCXXSourceCompiles)
set(CMAKE_REQUIRED_FLAGS "-fsanitize=fuzzer")
check_cxx_source_compiles("
  #include <cstdint>
  #include <cstddef>
  extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t*, size_t) { return 0; }
" GTPM_HAS_LIBFUZZER)
unset(CMAKE_REQUIRED_FLAGS)

set(GTPM_FUZZ_TARGETS
  fuzz_gtpu
  fuzz_diameter
  fuzz_pipeline
  fuzz_pcap)

foreach(f IN LISTS GTPM_FUZZ_TARGETS)
  if(GTPM_HAS_LIBFUZZER)
    add_executable(${f} ${f}.cpp)
    target_compile_options(${f} PRIVATE -fsanitize=fuzzer,address,undefined)
    target_link_options(${f} PRIVATE -fsanitize=fuzzer,address,undefined)
  else()
    add_executable(${f} ${f}.cpp standalone_main.cpp)
  endif()
  target_link_libraries(${f} PRIVATE gtpm_core)

  # Under libFuzzer, -runs bounds the CTest invocation; the standalone driver
  # takes an iteration count instead. Either way CI runs the harnesses.
  if(GTPM_HAS_LIBFUZZER)
    add_test(NAME ${f} COMMAND ${f} -runs=20000 -max_len=512 -timeout=10)
  else()
    add_test(NAME ${f} COMMAND ${f} --random 20000)
  endif()
  set_tests_properties(${f} PROPERTIES TIMEOUT 300 LABELS fuzz)
endforeach()

if(GTPM_HAS_LIBFUZZER)
  message(STATUS "  fuzzing    : libFuzzer + ASan + UBSan")
else()
  message(STATUS "  fuzzing    : standalone driver (no libFuzzer in this toolchain)")
endif()
