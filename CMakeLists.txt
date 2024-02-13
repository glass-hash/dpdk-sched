cmake_minimum_required(VERSION 3.5)
project(pktgen)

# C++ STD version
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# C STD version
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED True)
set(CMAKE_C_EXTENSIONS True)

# Output targets
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# CXX flags
add_compile_options(-m64 -O3 -march=native -g -Wall -Wextra -Werror -Wfatal-errors)

# Getting sources
file(GLOB SOURCES
    ${PROJECT_SOURCE_DIR}/src/*.c
    ${PROJECT_SOURCE_DIR}/src/*.cpp)

# Modules
set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

# DPDK
find_package(DPDK REQUIRED)

message(DPDK_INCLUDE_DIRS="${DPDK_INCLUDE_DIRS}")
message(DPDK_LIBRARY_DIRS="${DPDK_LIBRARY_DIRS}")

include_directories(${DPDK_INCLUDE_DIRS})
link_directories(${DPDK_LIBRARY_DIRS})

add_executable(${PROJECT_NAME} ${SOURCES})

# https://stackoverflow.com/questions/56381463/executable-missing-full-library-path-after-build
# cmake black magic...
target_link_options(${PROJECT_NAME} PUBLIC "-Wl,--disable-new-dtags")

target_link_libraries(${PROJECT_NAME} ${DPDK_LIBRARIES})
