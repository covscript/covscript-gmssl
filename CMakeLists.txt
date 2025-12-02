cmake_minimum_required(VERSION 3.16)

project(covscript-gmssl)

include_directories(cppcodec)

set(BUILD_SHARED_LIBS OFF CACHE BOOL "Override BUILD_SHARED_LIBS option to OFF")
set(ENABLE_SM4_ECB OFF CACHE BOOL "Override ENABLE_SM4_ECB option to OFF")
set(ENABLE_SM4_OFB OFF CACHE BOOL "Override ENABLE_SM4_OFB option to OFF")
set(ENABLE_SM4_CFB OFF CACHE BOOL "Override ENABLE_SM4_CFB option to OFF")
set(ENABLE_SM4_CCM OFF CACHE BOOL "Override ENABLE_SM4_CCM option to OFF")
set(ENABLE_SM4_XTS OFF CACHE BOOL "Override ENABLE_SM4_XTS option to OFF")
set(ENABLE_SM3_XMSS OFF CACHE BOOL "Override ENABLE_SM3_XMSS option to OFF")
set(ENABLE_SHA1 OFF CACHE BOOL "Override ENABLE_SHA1 option to OFF")
set(ENABLE_SHA2 OFF CACHE BOOL "Override ENABLE_SHA2 option to OFF")
set(ENABLE_AES OFF CACHE BOOL "Override ENABLE_AES option to OFF")

include_directories(GmSSL/include)

if (DEFINED ENV{CS_DEV_PATH})
    message("-- CovScript SDK detected at $ENV{CS_DEV_PATH}")
    include("$ENV{CS_DEV_PATH}/csbuild.cmake")
    include_directories($ENV{CS_DEV_PATH}/include)
    link_directories($ENV{CS_DEV_PATH}/lib)
else ()
    message(FATAL_ERROR "-- CovScript SDK not detected. Please set environment variable CS_DEV_PATH")
endif ()

add_subdirectory(GmSSL EXCLUDE_FROM_ALL)

target_compile_definitions(gmssl PUBLIC -DDEBUG=0)

add_library(covscript-gmssl SHARED gmssl.cpp)

target_link_libraries(covscript-gmssl gmssl covscript)

set_target_properties(covscript-gmssl PROPERTIES OUTPUT_NAME gmssl)
set_target_properties(covscript-gmssl PROPERTIES PREFIX "")
set_target_properties(covscript-gmssl PROPERTIES SUFFIX ".cse")
