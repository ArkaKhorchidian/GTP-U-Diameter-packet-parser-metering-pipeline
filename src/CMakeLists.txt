# Core library. The parsers and lock-free data structures are header-only (they
# must inline into the hot path); the pipeline plumbing that does not belong in
# a header lives in the compiled sources below.

add_library(gtpm_core INTERFACE)
target_include_directories(gtpm_core INTERFACE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(gtpm_core INTERFACE gtpm_flags Threads::Threads)
