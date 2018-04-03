cmake_minimum_required(VERSION 3.5)
project(tcpdump1)
set (EXECUTABLE_OUTPUT_PATH ../bin)
set (CMAKE_BUILD_DIRECTORY ./build)

include_directories(pcap_include)
add_compile_options(-g3 -Wall)
add_executable(tcpdump1 main.c)
target_link_libraries(tcpdump1 libpcap.a)
