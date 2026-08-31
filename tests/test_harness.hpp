// SPDX-License-Identifier: MIT
//
// A ~150-line test harness. Deliberately dependency-free: the pipeline itself
// pulls in nothing but libc++ and pthreads, and the tests keep that property so
// the repo builds and self-verifies on a bare toolchain with no network.
#pragma once

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace gtpm::test {

struct TestCase {
  const char* name;
  std::function<void()> fn;
};

inline std::vector<TestCase>& registry() {
  static std::vector<TestCase> tests;
  return tests;
}

inline int& failure_count() {
  static int failures = 0;
  return failures;
}

struct Registrar {
  Registrar(const char* name, std::function<void()> fn) {
    registry().push_back({name, std::move(fn)});
  }
};

/// Thrown by REQUIRE_* to abort the current test case only.
struct FatalFailure {};

inline void report(const char* file, int line, const std::string& what) {
  std::fprintf(stderr, "  FAIL %s:%d: %s\n", file, line, what.c_str());
  ++failure_count();
}

template <typename T>
inline std::string to_display(const T& v) {
  if constexpr (std::is_same_v<T, bool>) {
    return v ? "true" : "false";
  } else if constexpr (std::is_convertible_v<T, std::string_view>) {
    return std::string("\"") + std::string(std::string_view(v)) + "\"";
  } else if constexpr (std::is_enum_v<T>) {
    return std::to_string(static_cast<long long>(v));
  } else if constexpr (std::is_integral_v<T>) {
    return std::to_string(static_cast<long long>(v));
  } else if constexpr (std::is_floating_point_v<T>) {
    return std::to_string(v);
  } else {
    return "<value>";
  }
}

}  // namespace gtpm::test

#define GTPM_CONCAT_INNER(a, b) a##b
#define GTPM_CONCAT(a, b) GTPM_CONCAT_INNER(a, b)

#define TEST(name)                                                            \
  static void GTPM_CONCAT(gtpm_test_fn_, __LINE__)();                         \
  static const ::gtpm::test::Registrar GTPM_CONCAT(gtpm_test_reg_, __LINE__)( \
      name, &GTPM_CONCAT(gtpm_test_fn_, __LINE__));                           \
  static void GTPM_CONCAT(gtpm_test_fn_, __LINE__)()

#define CHECK(cond)                                                            \
  do {                                                                         \
    if (!(cond)) ::gtpm::test::report(__FILE__, __LINE__, "CHECK(" #cond ")"); \
  } while (0)

#define REQUIRE(cond)                                                 \
  do {                                                                \
    if (!(cond)) {                                                    \
      ::gtpm::test::report(__FILE__, __LINE__, "REQUIRE(" #cond ")"); \
      throw ::gtpm::test::FatalFailure{};                             \
    }                                                                 \
  } while (0)

#define GTPM_CMP(a, b, op, fatal)                                          \
  do {                                                                     \
    const auto& gtpm_a = (a);                                              \
    const auto& gtpm_b = (b);                                              \
    if (!(gtpm_a op gtpm_b)) {                                             \
      ::gtpm::test::report(__FILE__, __LINE__,                             \
                           std::string(#a " " #op " " #b " => ") +         \
                               ::gtpm::test::to_display(gtpm_a) + " vs " + \
                               ::gtpm::test::to_display(gtpm_b));          \
      if (fatal) throw ::gtpm::test::FatalFailure{};                       \
    }                                                                      \
  } while (0)

#define CHECK_EQ(a, b) GTPM_CMP(a, b, ==, false)
#define CHECK_NE(a, b) GTPM_CMP(a, b, !=, false)
#define CHECK_LT(a, b) GTPM_CMP(a, b, <, false)
#define CHECK_LE(a, b) GTPM_CMP(a, b, <=, false)
#define CHECK_GT(a, b) GTPM_CMP(a, b, >, false)
#define CHECK_GE(a, b) GTPM_CMP(a, b, >=, false)
#define REQUIRE_EQ(a, b) GTPM_CMP(a, b, ==, true)

#define GTPM_TEST_MAIN()                                                                     \
  int main(int argc, char** argv) {                                                          \
    const char* filter = argc > 1 ? argv[1] : nullptr;                                       \
    int run = 0, failed_cases = 0;                                                           \
    for (auto& tc : ::gtpm::test::registry()) {                                              \
      if (filter && std::strstr(tc.name, filter) == nullptr) continue;                       \
      ++run;                                                                                 \
      const int before = ::gtpm::test::failure_count();                                      \
      std::printf("[ RUN  ] %s\n", tc.name);                                                 \
      try {                                                                                  \
        tc.fn();                                                                             \
      } catch (const ::gtpm::test::FatalFailure&) {                                          \
        /* already reported */                                                               \
      } catch (const std::exception& e) {                                                    \
        ::gtpm::test::report(__FILE__, __LINE__,                                             \
                             std::string("unexpected exception: ") + e.what());              \
      }                                                                                      \
      const bool ok = ::gtpm::test::failure_count() == before;                               \
      if (!ok) ++failed_cases;                                                               \
      std::printf("[ %s ] %s\n", ok ? " OK " : "FAIL", tc.name);                             \
    }                                                                                        \
    std::printf("\n%d test(s) run, %d failed, %d assertion failure(s)\n", run, failed_cases, \
                ::gtpm::test::failure_count());                                              \
    return failed_cases == 0 ? 0 : 1;                                                        \
  }
