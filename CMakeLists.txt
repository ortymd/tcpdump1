cmake_minimum_required(VERSION 3.5)
project(tcpdump1 C)
set (EXECUTABLE_OUTPUT_PATH ../bin)
set (CMAKE_BUILD_DIRECTORY ./build)

add_compile_options(-g3 -Wall)
add_executable(tcpdump1 main.c functions.c)
target_link_libraries(tcpdump1 pthread)
