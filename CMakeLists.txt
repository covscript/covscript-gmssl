cmake_minimum_required(VERSION 3.13)

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

if(DEFINED ENV{CS_DEV_PATH})
    include_directories($ENV{CS_DEV_PATH}/include)
    link_directories($ENV{CS_DEV_PATH}/lib)
endif()

if(DEFINED ENV{CS_DEV_OUTPUT})
    set(LIBRARY_OUTPUT_PATH $ENV{CS_DEV_OUTPUT})
    set(EXECUTABLE_OUTPUT_PATH $ENV{CS_DEV_OUTPUT})
endif()

# Compiler Options
set(CMAKE_CXX_STANDARD 14)

if (MSVC)
    set(CMAKE_CXX_FLAGS "/O2 /EHsc /utf-8 /w")
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
elseif (CMAKE_COMPILER_IS_GNUCXX)
    if (WIN32)
        set(CMAKE_C_FLAGS "--static -fPIC -s -O3")
        set(CMAKE_CXX_FLAGS "--static -fPIC -s -O3")
    else ()
        set(CMAKE_C_FLAGS "-fPIC -s -O3")
        set(CMAKE_CXX_FLAGS "-fPIC -s -O3")
    endif ()
else ()
    set(CMAKE_C_FLAGS "-fPIC -O3")
    set(CMAKE_CXX_FLAGS "-fPIC -O3")
endif ()

add_subdirectory(GmSSL EXCLUDE_FROM_ALL)

add_library(covscript-gmssl SHARED gmssl.cpp)

target_link_libraries(covscript-gmssl gmssl covscript)

set_target_properties(covscript-gmssl PROPERTIES OUTPUT_NAME gmssl)
set_target_properties(covscript-gmssl PROPERTIES PREFIX "")
set_target_properties(covscript-gmssl PROPERTIES SUFFIX ".cse")
