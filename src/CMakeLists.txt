#-----------------------------------------------------------------------------
# Build libsecp256k1

set(cxx-sources
  secp256k1.c
)

if(USE_ASM)
  set(can_use_assembler FALSE)

  set(asm-sources
    field_5x52_asm.asm
  )
endif()

include_directories(SYSTEM
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

add_library(secp256k1
  SHARED
  ${cxx-sources}
  ${asm-sources}
)

set_target_properties(secp256k1 PROPERTIES COMPILE_FLAGS "-fPIC")

add_library(secp256k1_static
  STATIC
  ${cxx-sources}
  ${asm-sources}
)

if(USE_SSL)
  include_directories(SYSTEM ${OPENSSL_INCLUDE_DIR})
  target_link_libraries(secp256k1 ${OPENSSL_LIBRARIES})
  target_link_libraries(secp256k1_static ${OPENSSL_LIBRARIES})
endif()

if(USE_GMP)
  target_link_libraries(secp256k1 gmp)
  target_link_libraries(secp256k1_static gmp)
endif()

set_target_properties(secp256k1 PROPERTIES OUTPUT_NAME secp256k1)
set_target_properties(secp256k1_static PROPERTIES OUTPUT_NAME secp256k1)

if(NOT WIN32)
  include(GNUInstallDirs)
  install(TARGETS secp256k1 DESTINATION ${CMAKE_INSTALL_LIBDIR})
  install(TARGETS secp256k1_static DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()


#-----------------------------------------------------------------------------
# Build tests
if(BUILD_TESTS)
  add_definitions(-DENABLE_OPENSSL_TESTS)
  add_executable(tests tests.c)

  if(USE_GMP)
    target_link_libraries(tests secp256k1_static gmp crypto)
  else()
    target_link_libraries(tests secp256k1_static crypto)
  endif()

  enable_testing()
endif()


#-----------------------------------------------------------------------------
# Build benchmark
if(BUILD_BENCHMARK)
  add_executable(bench bench.c)

  if(USE_GMP)
    target_link_libraries(bench secp256k1_static gmp)
  else()
    target_link_libraries(bench secp256k1_static)
  endif()
endif()
