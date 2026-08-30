# Each test binary is standalone (own main via GTPM_TEST_MAIN) and registered
# with CTest. `ctest --output-on-failure` is the whole test story.

add_library(gtpm_test_support INTERFACE)
target_include_directories(gtpm_test_support INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(gtpm_test_support INTERFACE gtpm_core)

set(GTPM_TESTS
  test_gtpu
  test_diameter
  test_net
  test_spsc
  test_flat_hash
  test_seqlock
  test_meter
  test_pipeline
  test_session
  test_pcap
  test_snapshot
  test_reporter
  test_runtime)

foreach(t IN LISTS GTPM_TESTS)
  add_executable(${t} ${t}.cpp)
  target_link_libraries(${t} PRIVATE gtpm_test_support gtpm_core)
  add_test(NAME ${t} COMMAND ${t})
  set_tests_properties(${t} PROPERTIES TIMEOUT 120)
endforeach()

# Golden test: replay a generated capture and require the pipeline's byte
# counts to match the generator's ground truth exactly. Needs Python 3 and the
# gtp-meter binary; skipped (not failed) when Python is unavailable.
find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_Interpreter_FOUND)
  add_test(NAME golden_replay
           COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/golden_replay.py
                   $<TARGET_FILE:gtp-meter>)
  set_tests_properties(golden_replay PROPERTIES TIMEOUT 300)
else()
  message(STATUS "Python3 not found: skipping the golden replay test")
endif()

if(GTPM_BUILD_FUZZ)
  add_subdirectory(fuzz)
endif()
