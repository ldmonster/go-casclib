cmake_minimum_required(VERSION 3.16)
project(casclib_parity_c CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Bring in the vendored CascLib at ../CascLib (relative to this directory's
# parent, which is the repo root).
set(CASCLIB_DIR "${CMAKE_CURRENT_LIST_DIR}/../../CascLib" CACHE PATH "Path to vendored CascLib source tree")

if(NOT EXISTS "${CASCLIB_DIR}/CMakeLists.txt")
    message(FATAL_ERROR "CascLib source not found at ${CASCLIB_DIR}; run `git submodule update --init` or pass -DCASCLIB_DIR=...")
endif()

# Build the static CascLib library only (saves us the headache of rpath).
set(CASC_BUILD_SHARED_LIB OFF CACHE BOOL "" FORCE)
set(CASC_BUILD_STATIC_LIB ON CACHE BOOL "" FORCE)
add_subdirectory(${CASCLIB_DIR} ${CMAKE_BINARY_DIR}/casclib EXCLUDE_FROM_ALL)

add_executable(casclib-parity-c main.cpp)
target_link_libraries(casclib-parity-c PRIVATE casc_static)
target_include_directories(casclib-parity-c PRIVATE ${CASCLIB_DIR}/src)

# CascLib uses pthreads + zlib (vendored). Most platforms need pthread.
find_package(Threads REQUIRED)
target_link_libraries(casclib-parity-c PRIVATE Threads::Threads)

# Some Linux toolchains need explicit libdl.
if(UNIX AND NOT APPLE)
    target_link_libraries(casclib-parity-c PRIVATE dl)
endif()
