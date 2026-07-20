// Copyright (c) 2019-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_ASMAP_H
#define BITCOIN_UTIL_ASMAP_H

#include <util/fs.h>

#include <cstdint>
#include <span>
#include <string>
#include <vector>

uint32_t Interpret(const std::vector<bool> &asmap, const std::vector<bool> &ip);

bool SanityCheckASMap(const std::vector<bool>& asmap, int bits);

/** Read asmap from provided binary file */
std::vector<bool> DecodeAsmap(fs::path path);

/** Decode asmap from an in-memory byte span (e.g. the compiled-in default map).
 *  source_desc is only used for diagnostic logging. Returns {} on sanity failure. */
std::vector<bool> DecodeAsmap(std::span<const uint8_t> raw, const std::string& source_desc);

/** Raw bytes of the compiled-in default asmap, generated at build time from
 *  contrib/asmap/ip_asn.map. Always non-empty in a normal build. */
std::span<const uint8_t> GetEmbeddedAsmapBytes();

#endif // BITCOIN_UTIL_ASMAP_H
