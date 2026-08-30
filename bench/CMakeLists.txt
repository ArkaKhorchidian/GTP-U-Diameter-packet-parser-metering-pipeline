# Benchmarks are ordinary executables: no framework, explicit warmup, and they
# print a CSV row so results/ can be regenerated with a shell redirect.

set(GTPM_BENCHES
  bench_parse)

foreach(b IN LISTS GTPM_BENCHES)
  add_executable(${b} ${b}.cpp)
  target_link_libraries(${b} PRIVATE gtpm_core)
  target_include_directories(${b} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
endforeach()
