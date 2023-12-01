cmake_minimum_required(VERSION 3.5)

project (tftpc C)
set(CMAKE_BUILD_TYPE Debug)

add_executable (test test.c)

add_subdirectory (addons)

if (WIN32)
   target_link_libraries (test ws2_32)
endif ()