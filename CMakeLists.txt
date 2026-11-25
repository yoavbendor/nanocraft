cmake_minimum_required(VERSION 3.22)
project(nanocraft VERSION 0.1.0 LANGUAGES CXX)

# nanom uses C++23 `if consteval` and friends: GCC 13+ / Clang 17+.
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 13)
  message(FATAL_ERROR "nanocraft needs GCC 13 or newer (found ${CMAKE_CXX_COMPILER_VERSION})")
endif()

if(PROJECT_IS_TOP_LEVEL)
  set(_nanocraft_dev ON)
else()
  set(_nanocraft_dev OFF)
endif()
option(NANOCRAFT_BUILD_TESTS "Build the nanocraft tests (ctest)" ${_nanocraft_dev})
option(NANOCRAFT_BUILD_BENCH "Build the nanocraft benchmarks" ${_nanocraft_dev})
option(NANOCRAFT_BUILD_EXAMPLES "Build the nanocraft examples" ${_nanocraft_dev})
option(NANOCRAFT_PROFILE "Compile the built-in profiling counters in (defines NANOCRAFT_PROFILE)" OFF)
option(NANOCRAFT_WERROR "Treat warnings as errors (tests/bench/examples)" OFF)
set(NANOCRAFT_SANITIZER "" CACHE STRING "Sanitizers for tests/bench/examples: '', 'address,undefined', 'thread'")

# ---- nanom (header-only). Pinned; for local co-development point
#      -DFETCHCONTENT_SOURCE_DIR_NANOM=/path/to/nanom at a checkout instead.
include(FetchContent)
set(NANOCRAFT_NANOM_GIT_URL "https://github.com/yoavbendor/nanom.git" CACHE STRING "nanom repository")
FetchContent_Declare(nanom
  GIT_REPOSITORY ${NANOCRAFT_NANOM_GIT_URL}
  GIT_TAG 12f9e2bf36c439802ae3e36e01dad3a70aa96539
  GIT_SHALLOW FALSE)
FetchContent_GetProperties(nanom)
if(NOT nanom_POPULATED)
  # Populate only: nanocraft needs nanom's headers, not its build (tests, apps, ...).
  if(POLICY CMP0169)
    cmake_policy(SET CMP0169 OLD)
  endif()
  FetchContent_Populate(nanom)
endif()
if(NOT TARGET nanocraft_nanom)
  add_library(nanocraft_nanom INTERFACE)
  target_include_directories(nanocraft_nanom SYSTEM INTERFACE "${nanom_SOURCE_DIR}/include")
  target_compile_options(nanocraft_nanom INTERFACE $<$<CXX_COMPILER_ID:MSVC>:/Zc:preprocessor>)
endif()

# ---- the library ----------------------------------------------------------------------------
add_library(nanocraft INTERFACE)
add_library(nanocraft::nanocraft ALIAS nanocraft)
target_include_directories(nanocraft INTERFACE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
target_compile_features(nanocraft INTERFACE cxx_std_23)
target_link_libraries(nanocraft INTERFACE nanocraft_nanom)
if(NANOCRAFT_PROFILE)
  target_compile_definitions(nanocraft INTERFACE NANOCRAFT_PROFILE=1)
endif()

# nanom_shark's pcap scanner is an independent oracle for the writers (tests only).
set(NANOCRAFT_NANOM_INCLUDE "${nanom_SOURCE_DIR}/include")

if(NOT (NANOCRAFT_BUILD_TESTS OR NANOCRAFT_BUILD_BENCH OR NANOCRAFT_BUILD_EXAMPLES))
  return()
endif()

add_library(nanocraft_dev_flags INTERFACE)
target_compile_options(nanocraft_dev_flags INTERFACE -Wall -Wextra -Wpedantic -Wshadow)
if(NANOCRAFT_WERROR)
  target_compile_options(nanocraft_dev_flags INTERFACE -Werror)
endif()
if(NANOCRAFT_SANITIZER)
  target_compile_options(nanocraft_dev_flags INTERFACE -fsanitize=${NANOCRAFT_SANITIZER} -fno-omit-frame-pointer
                                                       -fno-sanitize-recover=all)
  target_link_options(nanocraft_dev_flags INTERFACE -fsanitize=${NANOCRAFT_SANITIZER})
endif()

if(NANOCRAFT_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
if(NANOCRAFT_BUILD_BENCH)
  add_subdirectory(bench)
endif()
if(NANOCRAFT_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()
