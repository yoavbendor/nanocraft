cmake_minimum_required(VERSION 3.25)  # FetchContent SYSTEM
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

# ---- dependencies (header-only): nanowire (the shared protocol core) and nanom (its parser /
#      emitter core). Both pinned. For local co-development point FetchContent at checkouts:
#        -DFETCHCONTENT_SOURCE_DIR_NANOWIRE=/path/to/nanowire -DFETCHCONTENT_SOURCE_DIR_NANOM=/path/to/nanom
#      nanowire fetches nanom itself under the same FetchContent name `nanom`; nanocraft declares and
#      makes nanom available first, so nanowire finds the nanom::nanom target and configures no
#      second copy (keep NANOCRAFT_NANOM_GIT_TAG equal to nanowire's NANOWIRE_NANOM_GIT_TAG).
#      An embedding project that already provides nanom::nanom / nanowire::nanowire wins.
#      SYSTEM: their headers are not subject to nanocraft's -Wshadow / -Werror.
include(FetchContent)
set(NANOCRAFT_NANOM_GIT_URL "https://github.com/yoavbendor/nanom.git" CACHE STRING "nanom repository")
set(NANOCRAFT_NANOM_GIT_TAG "16f8ec1d1113bb6b99160949d1a9b87dcf88c374" CACHE STRING "nanom commit")
set(NANOCRAFT_NANOWIRE_GIT_URL "https://github.com/yoavbendor/nanowire.git" CACHE STRING "nanowire repository")
set(NANOCRAFT_NANOWIRE_GIT_TAG "c4bc59d86c5ff5fe02477e46112d90fae9ec0b98" CACHE STRING "nanowire commit")
if(NOT TARGET nanom::nanom)
  FetchContent_Declare(nanom
    GIT_REPOSITORY ${NANOCRAFT_NANOM_GIT_URL}
    GIT_TAG ${NANOCRAFT_NANOM_GIT_TAG}
    GIT_SHALLOW FALSE
    SYSTEM)
  # nanom's CMakeLists returns before its tests / apps when it is not the top-level project: this
  # only declares the header-only nanom::nanom and nanom::shark targets.
  FetchContent_MakeAvailable(nanom)
endif()
if(NOT TARGET nanowire::nanowire)
  # nanowire builds no tests / benches when it is not the top-level project.
  FetchContent_Declare(nanowire
    GIT_REPOSITORY ${NANOCRAFT_NANOWIRE_GIT_URL}
    GIT_TAG ${NANOCRAFT_NANOWIRE_GIT_TAG}
    GIT_SHALLOW FALSE
    SYSTEM)
  FetchContent_MakeAvailable(nanowire)
endif()

# ---- the library ----------------------------------------------------------------------------
add_library(nanocraft INTERFACE)
add_library(nanocraft::nanocraft ALIAS nanocraft)
target_include_directories(nanocraft INTERFACE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
target_compile_features(nanocraft INTERFACE cxx_std_23)
target_link_libraries(nanocraft INTERFACE nanowire::nanowire nanom::nanom)
# MSVC: NANOM_DESCRIBE needs the conforming preprocessor.
target_compile_options(nanocraft INTERFACE $<$<CXX_COMPILER_ID:MSVC>:/Zc:preprocessor>)
if(NANOCRAFT_PROFILE)
  target_compile_definitions(nanocraft INTERFACE NANOCRAFT_PROFILE=1)
endif()

if(NOT (NANOCRAFT_BUILD_TESTS OR NANOCRAFT_BUILD_BENCH OR NANOCRAFT_BUILD_EXAMPLES))
  return()
endif()

add_library(nanocraft_dev_flags INTERFACE)
target_compile_options(nanocraft_dev_flags INTERFACE
  $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic -Wshadow>
  $<$<CXX_COMPILER_ID:MSVC>:/W4>)
if(NANOCRAFT_WERROR)
  target_compile_options(nanocraft_dev_flags INTERFACE
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Werror>
    $<$<CXX_COMPILER_ID:MSVC>:/WX>)
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
