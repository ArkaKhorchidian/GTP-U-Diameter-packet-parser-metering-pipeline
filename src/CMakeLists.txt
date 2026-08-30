# Core library. The parsers and lock-free data structures are header-only (they
# must inline into the hot path); the pipeline plumbing that does not belong in
# a header is compiled here.

add_library(gtpm_core STATIC
  ingest_pcap.cpp
  ingest_rawsock.cpp
  meter_thread.cpp
  reporter.cpp)

target_include_directories(gtpm_core PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(gtpm_core PUBLIC gtpm_flags Threads::Threads)

add_executable(gtp-meter main.cpp)
target_link_libraries(gtp-meter PRIVATE gtpm_core)

install(TARGETS gtp-meter RUNTIME DESTINATION bin)
install(DIRECTORY ${CMAKE_SOURCE_DIR}/include/gtpm DESTINATION include)
