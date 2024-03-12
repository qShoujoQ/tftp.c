cmake_minimum_required(VERSION 3.5)

project (tftpc C)
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_BUILD_TYPE Debug)

add_subdirectory (tests)
add_subdirectory (examples)
