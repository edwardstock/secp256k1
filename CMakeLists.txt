cmake_minimum_required(VERSION 2.8)
project(libsecp256k1)

set(VERSION_MAJOR  0)
set(VERSION_MINOR  0)
set(VERSION_BUGFIX 0)
set(VERSION "0.0.0")


#-----------------------------------------------------------------------------
# Options for building

option(BUILD_VERBOSE       "Verbose build output." ON)
#option(BUILD_DOCUMENTATION "Build the Doxygen documentation." ON)
option(BUILD_TESTS         "Build the tests." ON)
option(BUILD_BENCHMARK     "Build the benchmark." ON)

option(ENDOMORPHISM                  "Enable  endomorphism." OFF)
set(FIELD  "gmp"       CACHE <TYPE>  "Field operations: gmp|64bit|64bit_asm|32bit")
set(BIGNUM "gmp"       CACHE <TYPE>  "Bignum Implementation: gmp|openssl")

option(RPM                 "Build a RPM" OFF)
option(DEB                 "Build a DEB" OFF)

if(BUILD_VERBOSE)
  set(CMAKE_VERBOSE_MAKEFILE true)
endif()


#-----------------------------------------------------------------------------
# Print system information and build options

message(STATUS "General -------------------------------------")
message(STATUS "CMake version:          ${CMAKE_VERSION}")
message(STATUS "System:                 ${CMAKE_SYSTEM}")
message(STATUS "Processor:              ${CMAKE_SYSTEM_PROCESSOR}")

message(STATUS "Verbose:                ${BUILD_VERBOSE}")
message(STATUS "Testing:                ${BUILD_TESTS}")
message(STATUS "Benchmark:              ${BUILD_BENCHMARK}")

message(STATUS "Build Options -------------------------------")
message(STATUS "Endomorphism:           ${ENDOMORPHISM}")
message(STATUS "Field operations:       ${FIELD}")
message(STATUS "Bignum Implementation:  ${BIGNUM}")

message(STATUS "Packaging -----------------------------------")
message(STATUS "Build RPM:              ${RPM}")
message(STATUS "Build DEB:              ${DEB}")


#-----------------------------------------------------------------------------
# Collect all binaries into bin subdirectory

set(EXECUTABLE_OUTPUT_PATH ${CMAKE_CURRENT_BINARY_DIR}/bin)
set(LIBRARY_OUTPUT_PATH  ${CMAKE_CURRENT_BINARY_DIR}/lib)


#-----------------------------------------------------------------------------
# Set compiler flags

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99")

if(MSVC)
  add_definitions(-D_UNICODE)
endif()

message(STATUS "C Compiler ID: ${CMAKE_C_COMPILER_ID}")
message(STATUS "C Flags:       ${CMAKE_C_FLAGS}")
message(STATUS "C link flags:  ${CMAKE_C_LINK_FLAGS}")


#-----------------------------------------------------------------------------
# System libraries used for linking.

if(UNIX AND NOT APPLE)
  list(APPEND OPENTXS_SYSTEM_LIBRARIES rt)
  list(APPEND OPENTXS_SYSTEM_LIBRARIES dl)
endif()


#-----------------------------------------------------------------------------
# Force out-of-source build

if(${CMAKE_CURRENT_SOURCE_DIR} STREQUAL ${CMAKE_CURRENT_BINARY_DIR})
message(FATAL_ERROR "CMake generation is not allowed within the source directory!
Remove the CMakeCache.txt file and try again from another folder, e.g.:

   rm CMakeCache.txt
   mkdir build
   cd build
   cmake ..
")
endif()


#-----------------------------------------------------------------------------
# Default to Release build

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING
      "Choose the type of build, options are: None Debug Release RelWithDebInfo MinSizeRel."
      FORCE)
endif()


#-----------------------------------------------------------------------------
# Source Definitions

if(ENDOMORPHISM)
  add_definitions(-DUSE_ENDOMORPHISM)
endif()

if(FIELD MATCHES 64bit_asm)
  if(NOT "${CMAKE_SYSTEM_PROCESSOR}" MATCHES "x86_64")
    message(FATAL_ERROR "64bit_asm field support explicitly requested but is not compatible with this host.")
  else()
    enable_language(ASM_NASM)
    if("ASM${ASM_DIALECT}" STREQUAL "YASM")
      add_definitions(-DUSE_FIELD_5X52)
      add_definitions(-DUSE_FIELD_5X52_ASM)
      set(USE_ASM 1)
    else()
      message(FATAL_ERROR "64bit_asm field support explicitly requested but yasm was not found.")
    endif()
  endif()
elseif(FIELD MATCHES gmp) #default
  set(USE_GMP 1)
  add_definitions(-DUSE_FIELD_GMP)
  add_definitions(-DHAVE_LIBGMP)
elseif(FIELD MATCHES 64bit)
  add_definitions(-DUSE_FIELD_5X52)
  add_definitions(-DUSE_FIELD_5X52_INT128)
elseif(FIELD MATCHES 32bit)
  add_definitions(-DUSE_FIELD_10X26)
else()
  message(FATAL_ERROR "Invalid field implementation.")
endif()

if(BIGNUM MATCHES gmp) #default
  set(USE_GMP 1)
  add_definitions(-DHAVE_LIBGMP)
  add_definitions(-DUSE_NUM_GMP)
  add_definitions(-DUSE_FIELD_INV_NUM)
elseif(BIGNUM MATCHES openssl)
  find_package(OpenSSL REQUIRED)
  set(USE_SSL 1)
  add_definitions(-DUSE_NUM_OPENSSL)
  add_definitions(-DUSE_FIELD_INV_BUILTIN)
else()
  message(FATAL_ERROR "Invalid field implementation.")
endif()

if(USE_GMP)
  find_path(GMP_INCLUDE_DIR gmp.h)
  if(GMP_INCLUDE_DIR STREQUAL "GMP_INCLUDE_DIR-NOTFOUND")
    message(FATAL_ERROR "Couldn't find gmp.h. Please install GMP.")  
  else()
    message(STATUS "Found GMP: ${GMP_INCLUDE_DIR}")
  endif()
endif()

#-----------------------------------------------------------------------------
# Build source

#Fix RPATH
if(APPLE)
  set(CMAKE_INSTALL_NAME_DIR @rpath)
endif()
if(NOT RPM)
  set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}")
endif()

add_subdirectory(src)


#-----------------------------------------------------------------------------
# Install

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
        DESTINATION include)


#-----------------------------------------------------------------------------
# Uninstal
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/uninstall.cmake"
    IMMEDIATE @ONLY)

add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/uninstall.cmake)

    
#-----------------------------------------------------------------------------
# Packaging

set(CPACK_GENERATOR "TGZ")
set(CPACK_PACKAGE_VERSION ${VERSION})
set(CPACK_PACKAGE_NAME "libsecp256k1")
set(CPACK_PACKAGE_RELEASE 1)
set(CPACK_PACKAGE_CONTACT "Lucas Betschart")
set(CPACK_PACKAGE_VENDOR "Bitcoin Community")
set(CPACK_PACKAGING_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CPACK_PACKAGE_RELEASE}.${CMAKE_SYSTEM_PROCESSOR}")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Optimized C library for EC operations on curve secp256k1")
set(CPACK_PACKAGE_DESCRIPTION "Optimized C library for EC operations on curve secp256k1

This library is experimental, so use at your own risk.

Features:

- Low-level field and group operations on secp256k1.
- ECDSA signing/verification and key generation.
- Adding/multiplying private/public keys.
- Serialization/parsing of private keys, public keys, signatures.
- Very efficient implementation.
")

if(RPM)
  set(CPACK_GENERATOR "RPM")
  set(CPACK_PACKAGING_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})
  set(CPACK_RPM_COMPONENT_INSTALL ON)
  set(CPACK_RPM_CHANGELOG_FILE "${CMAKE_CURRENT_SOURCE_DIR}/ChangeLog")
endif()

if(DEB)
  set(CPACK_GENERATOR "DEB")
  set(CPACK_DEBIAN_PACKAGE_DEPENDS "")
  set(CPACK_DEBIAN_PACKAGE_PRIORITY "extra")
  set(CPACK_DEBIAN_PACKAGE_SECTION "utils")
  set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "https://github.com/bitcoin/secp256k1")
  set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Lucas Betschart")
endif()

include(CPack)
