# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

add_library(bitcoin_crypto STATIC EXCLUDE_FROM_ALL
  aes.cpp
  groth16.cpp
  chacha20.cpp
  chacha20poly1305.cpp
  hex_base.cpp
  hkdf_sha256_32.cpp
  hmac_sha256.cpp
  hmac_sha512.cpp
  muhash.cpp
  poly1305.cpp
  ripemd160.cpp
  sha1.cpp
  sha256.cpp
  sha256_sse4.cpp
  sha3.cpp
  sha512.cpp
  siphash.cpp
  ../support/cleanse.cpp
)

target_link_libraries(bitcoin_crypto
  PRIVATE
    core_interface
    blst::blst
)

target_include_directories(bitcoin_crypto
  PRIVATE
    ${blst_SOURCE_DIR}/bindings
)

# ML-DSA (FIPS 204) post-quantum signature verification
# Only compile mldsaverify.cpp if a backend is available
find_library(LIBOQS_LIB NAMES oqs
  PATHS ${CMAKE_PREFIX_PATH} /usr/local/lib /usr/lib
  PATH_SUFFIXES lib lib64
)
find_path(LIBOQS_INCLUDE_DIR NAMES oqs/oqs.h
  PATHS ${CMAKE_PREFIX_PATH} /usr/local/include /usr/include
  PATH_SUFFIXES include
)
if(LIBOQS_LIB AND LIBOQS_INCLUDE_DIR)
  target_sources(bitcoin_crypto PRIVATE mldsaverify.cpp mldsakeygen.cpp)
  target_link_libraries(bitcoin_crypto PUBLIC ${LIBOQS_LIB})
  target_compile_definitions(bitcoin_crypto PUBLIC ENABLE_MLDSA=1)
  target_compile_definitions(bitcoin_crypto PRIVATE USE_LIBOQS=1)
  target_include_directories(bitcoin_crypto PRIVATE ${LIBOQS_INCLUDE_DIR})
  message(STATUS "ML-DSA backend: liboqs (${LIBOQS_LIB})")

  # Export LIBOQS_LIB for use in test helper build
  set(LIBOQS_LIB "${LIBOQS_LIB}" PARENT_SCOPE)
else()
  message(WARNING "liboqs not found - ML-DSA verification disabled. Install from shared-utils/liboqs")
  message(WARNING "  To enable: git submodule add https://github.com/open-quantum-safe/liboqs.git shared-utils/liboqs")
endif()

if(HAVE_SSE41)
  target_compile_definitions(bitcoin_crypto PRIVATE ENABLE_SSE41)
  target_sources(bitcoin_crypto PRIVATE sha256_sse41.cpp)
  set_property(SOURCE sha256_sse41.cpp PROPERTY
    COMPILE_OPTIONS ${SSE41_CXXFLAGS}
  )
endif()

if(HAVE_AVX2)
  target_compile_definitions(bitcoin_crypto PRIVATE ENABLE_AVX2)
  target_sources(bitcoin_crypto PRIVATE sha256_avx2.cpp)
  set_property(SOURCE sha256_avx2.cpp PROPERTY
    COMPILE_OPTIONS ${AVX2_CXXFLAGS}
  )
endif()

if(HAVE_SSE41 AND HAVE_X86_SHANI)
  target_compile_definitions(bitcoin_crypto PRIVATE ENABLE_SSE41 ENABLE_X86_SHANI)
  target_sources(bitcoin_crypto PRIVATE sha256_x86_shani.cpp)
  set_property(SOURCE sha256_x86_shani.cpp PROPERTY
    COMPILE_OPTIONS ${X86_SHANI_CXXFLAGS}
  )
endif()

if(HAVE_ARM_SHANI)
  target_compile_definitions(bitcoin_crypto PRIVATE ENABLE_ARM_SHANI)
  target_sources(bitcoin_crypto PRIVATE sha256_arm_shani.cpp)
  set_property(SOURCE sha256_arm_shani.cpp PROPERTY
    COMPILE_OPTIONS ${ARM_SHANI_CXXFLAGS}
  )
endif()
