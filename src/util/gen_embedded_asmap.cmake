# Copyright (c) 2026-present The TensorCash developers
# Distributed under the MIT software license.
#
# Generate a C++ translation unit embedding a binary file as a byte array.
# Portable (CMake-only; no python/xxd/objcopy). Invoked at build time:
#   cmake -DINPUT=<binfile> -DOUTPUT=<cppfile> -P gen_embedded_asmap.cmake

if(NOT DEFINED INPUT OR NOT DEFINED OUTPUT)
  message(FATAL_ERROR "gen_embedded_asmap: INPUT and OUTPUT must be defined")
endif()

file(READ "${INPUT}" _hex HEX)
string(LENGTH "${_hex}" _hexlen)
math(EXPR _n "${_hexlen} / 2")
# Turn each two-hex-digit byte into "0xNN," (trailing comma is a legal C++ initializer).
string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1," _body "${_hex}")

file(WRITE "${OUTPUT}"
"// Auto-generated from contrib/asmap/ip_asn.map by gen_embedded_asmap.cmake. Do not edit.\n"
"#include <cstddef>\n"
"extern const unsigned char g_embedded_asmap[];\n"
"extern const size_t g_embedded_asmap_len;\n"
"const unsigned char g_embedded_asmap[] = {\n${_body}\n};\n"
"const size_t g_embedded_asmap_len = ${_n};\n")
