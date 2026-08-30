# Each test binary is standalone (own main via GTPM_TEST_MAIN) and registered
# with CTest. `ctest --output-on-failure` is the whole test story.

add_library(gtpm_test_support INTERFACE)
target_include_directories(gtpm_test_support INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(gtpm_test_support INTERFACE gtpm_core)

set(GTPM_TESTS
  test_gtpu
  test_diameter
  test_net)

foreach(t IN LISTS GTPM_TESTS)
  add_executable(${t} ${t}.cpp)
  target_link_libraries(${t} PRIVATE gtpm_test_support)
  add_test(NAME ${t} COMMAND ${t})
  set_tests_properties(${t} PROPERTIES TIMEOUT 120)
endforeach()

if(GTPM_BUILD_FUZZ)
  add_subdirectory(fuzz)
endif()
