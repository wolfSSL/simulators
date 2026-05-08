# CMakeLists.txt
#
# Copyright (C) 2026 wolfSSL Inc.
#
# This file is part of TROPIC01Sim.
#
# TROPIC01Sim is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.

# Builds `tropic01_sim_test` as a libtropic example: links the libtropic
# core library + the mbedTLS v4 CAL + the posix/tcp HAL. Mirrors
# libtropic/examples/model/hello_world/CMakeLists.txt so libtropic's
# CMake-driven mbedTLS v4 fetch + CAL/HAL wiring is reused unchanged.

cmake_minimum_required(VERSION 3.21.0)
include(FetchContent)

project(tropic01_sim_test
        DESCRIPTION "TROPIC01 simulator integration test driver."
        LANGUAGES C)

set(PATH_LIBTROPIC ../../../)

if(NOT UNIX)
    message(FATAL_ERROR "Model is currently compatible with UNIX-like systems only.")
endif()

# Add libtropic core.
add_subdirectory(${PATH_LIBTROPIC} "libtropic")
target_compile_options(tropic PRIVATE -ffunction-sections -fdata-sections)

# MbedTLS v4.0.0 (matches the version libtropic's hello_world example pulls).
set(ENABLE_TESTING OFF CACHE BOOL "Disable mbedtls_v4 test building.")
set(ENABLE_PROGRAMS OFF CACHE BOOL "Disable mbedtls_v4 examples building.")
FetchContent_Declare(
    mbedtls_v4
    URL https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-4.0.0/mbedtls-4.0.0.tar.bz2
    URL_HASH SHA256=2f3a47f7b3a541ddef450e4867eeecb7ce2ef7776093f3a11d6d43ead6bf2827
)
FetchContent_MakeAvailable(mbedtls_v4)
target_link_libraries(tropic PUBLIC mbedtls)

# MbedTLS v4 crypto abstraction layer.
add_subdirectory("${PATH_LIBTROPIC}/cal/mbedtls_v4" "mbedtls_v4_cal")
target_sources(tropic PRIVATE ${LT_CAL_SRCS})
target_include_directories(tropic PUBLIC ${LT_CAL_INC_DIRS})

# POSIX TCP HAL -- talks to our simulator's TCP server.
add_subdirectory("${PATH_LIBTROPIC}/hal/posix/tcp" "posix_tcp_hal")
target_sources(tropic PRIVATE ${LT_HAL_SRCS})
target_include_directories(tropic PUBLIC ${LT_HAL_INC_DIRS})

add_executable(${CMAKE_PROJECT_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/test_tropic01.c)
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE tropic)
