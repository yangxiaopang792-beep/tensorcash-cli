# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

# Embed the default asmap (contrib/asmap/ip_asn.map) into the binary so ASN-based
# IP bucketing is on by default for every build — downloaded or compiled from source.
set(EMBEDDED_ASMAP_CPP ${CMAKE_CURRENT_BINARY_DIR}/embedded_asmap.cpp)
add_custom_command(
  OUTPUT ${EMBEDDED_ASMAP_CPP}
  COMMAND ${CMAKE_COMMAND}
    -DINPUT=${PROJECT_SOURCE_DIR}/contrib/asmap/ip_asn.map
    -DOUTPUT=${EMBEDDED_ASMAP_CPP}
    -P ${CMAKE_CURRENT_SOURCE_DIR}/gen_embedded_asmap.cmake
  DEPENDS
    ${PROJECT_SOURCE_DIR}/contrib/asmap/ip_asn.map
    ${CMAKE_CURRENT_SOURCE_DIR}/gen_embedded_asmap.cmake
  COMMENT "Generating embedded default asmap from contrib/asmap/ip_asn.map"
  VERBATIM
)

add_library(bitcoin_util STATIC EXCLUDE_FROM_ALL
  ${EMBEDDED_ASMAP_CPP}
  asmap.cpp
  batchpriority.cpp
  bip32.cpp
  bytevectorhash.cpp
  chaintype.cpp
  check.cpp
  exception.cpp
  feefrac.cpp
  fs.cpp
  fs_helpers.cpp
  hasher.cpp
  moneystr.cpp
  rbf.cpp
  readwritefile.cpp
  serfloat.cpp
  signalinterrupt.cpp
  sock.cpp
  strencodings.cpp
  string.cpp
  syserror.cpp
  thread.cpp
  threadinterrupt.cpp
  threadnames.cpp
  time.cpp
  tokenpipe.cpp
  ../logging.cpp
  ../random.cpp
  ../randomenv.cpp
  ../streams.cpp
  ../support/lockedpool.cpp
  ../sync.cpp
)

target_link_libraries(bitcoin_util
  PRIVATE
    core_interface
    bitcoin_clientversion
    bitcoin_crypto
    $<$<PLATFORM_ID:Windows>:ws2_32>
    $<$<PLATFORM_ID:Windows>:iphlpapi>
)
