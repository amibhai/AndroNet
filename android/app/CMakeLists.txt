cmake_minimum_required(VERSION 3.22)

project(packet_capture_native)

# Global 16 KB page-size alignment — required for Android 15+
add_link_options("-Wl,-z,max-page-size=16384")

# Set C standard
set(CMAKE_C_STANDARD 11)

# Release optimizations (only applied when Gradle passes -DCMAKE_BUILD_TYPE=Release)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()
set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O2 -DNDEBUG")

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/src/main/zdtun
    ${CMAKE_SOURCE_DIR}/src/main/jni
)

# zdtun's connection limits are constants in its source, chosen for a desktop gateway. It resets a TCP
# connection after 60 s of silence, and phone apps hold quiet connections open for push messages. So the
# build compiles a copy with the limits RFC 4787 and RFC 5382 ask of a NAT, 2 minutes for UDP and
# 2 h 4 min for established TCP, and with room to hold those connections. The submodule stays as published.
set(ZDTUN_LIMITED ${CMAKE_CURRENT_BINARY_DIR}/zdtun_limited.c)
file(READ ${CMAKE_SOURCE_DIR}/src/main/zdtun/zdtun.c ZDTUN_TEXT)
foreach(LIMIT
    "UDP_TIMEOUT_SEC 30|UDP_TIMEOUT_SEC 120"
    "TCP_TIMEOUT_SEC 60|TCP_TIMEOUT_SEC 7440"
    "MAX_NUM_SOCKETS 128|MAX_NUM_SOCKETS 512"
    "NUM_SOCKETS_AFTER_PURGE 96|NUM_SOCKETS_AFTER_PURGE 384")
    string(REPLACE "|" ";" LIMIT_PARTS "${LIMIT}")
    list(GET LIMIT_PARTS 0 LIMIT_OLD)
    list(GET LIMIT_PARTS 1 LIMIT_NEW)
    string(FIND "${ZDTUN_TEXT}" "#define ${LIMIT_OLD}" LIMIT_AT)
    if(LIMIT_AT EQUAL -1)
        message(FATAL_ERROR "zdtun.c no longer defines ${LIMIT_OLD}: review the limits set here")
    endif()
    string(REPLACE "#define ${LIMIT_OLD}" "#define ${LIMIT_NEW}" ZDTUN_TEXT "${ZDTUN_TEXT}")
endforeach()
file(WRITE ${ZDTUN_LIMITED} "${ZDTUN_TEXT}")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${CMAKE_SOURCE_DIR}/src/main/zdtun/zdtun.c)

# zdtun source files
set(ZDTUN_SOURCES
    ${ZDTUN_LIMITED}
    ${CMAKE_SOURCE_DIR}/src/main/zdtun/utils.c
)

# JNI wrappers
set(JNI_SOURCES
    ${CMAKE_SOURCE_DIR}/src/main/jni/zdtun_vpn.c
)

set(PCAP_WRITER_SOURCES
    ${CMAKE_SOURCE_DIR}/src/main/jni/pcap_writer.c
)

# ============================================
# ALWAYS BUILD: VPN mode (works on all devices)
# ============================================
add_library(
    zdtun_vpn
    SHARED
    ${ZDTUN_SOURCES}
    ${JNI_SOURCES}
)

target_link_libraries(
    zdtun_vpn
    log
)

target_link_options(zdtun_vpn PRIVATE "-Wl,-z,max-page-size=16384")

# ============================================
# ALWAYS BUILD: PCAP writer (no libpcap dependency)
# ============================================
add_library(
    pcap_writer
    SHARED
    ${PCAP_WRITER_SOURCES}
)

target_link_libraries(
    pcap_writer
    log
)

target_link_options(pcap_writer PRIVATE "-Wl,-z,max-page-size=16384")

# ============================================
# ALWAYS BUILD: root capture helper, started through su by NetHunterService.
# A real executable, named like a library so that it gets packaged per ABI.
# ============================================
add_executable(
    capd
    ${CMAKE_SOURCE_DIR}/src/main/jni/capture_helper.c
)

set_target_properties(
    capd
    PROPERTIES
    OUTPUT_NAME "libcapd"
    SUFFIX ".so"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}"
    POSITION_INDEPENDENT_CODE ON
)

target_link_options(capd PRIVATE "-pie" "-Wl,-z,max-page-size=16384")

# ============================================
# OPTIONAL: Libpcap capture (only for rooted devices with libpcap)
# This will be skipped on regular Android builds
# For Kali NetHunter: Install libpcap-dev and rebuild
# ============================================
find_library(LIBPCAP_LIB pcap)

if(LIBPCAP_LIB)
    message(STATUS "✅ libpcap found: Building pcap_capture library for rooted mode")

    set(LIBPCAP_JNI_SOURCES
        ${CMAKE_SOURCE_DIR}/src/main/jni/libpcap_capture.c
    )

    add_library(
        pcap_capture
        SHARED
        ${LIBPCAP_JNI_SOURCES}
    )

    target_link_libraries(
        pcap_capture
        ${LIBPCAP_LIB}
        log
    )

    target_link_options(pcap_capture PRIVATE "-Wl,-z,max-page-size=16384")
else()
    message(WARNING "⚠️  libpcap NOT found - Skipping pcap_capture library")
    message(WARNING "    VPN mode will work normally on unrooted devices")
    message(WARNING "    For rooted mode: Install libpcap-dev on Kali NetHunter and rebuild")
endif()
