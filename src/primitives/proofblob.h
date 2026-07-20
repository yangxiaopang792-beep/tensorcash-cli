// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_PROOFBLOB_H
#define BITCOIN_PRIMITIVES_PROOFBLOB_H

#include <hash.h>
#include <rpc/proof_generated.h>
#include <rpc/blockheader_generated.h>
#include <serialize.h>
#include <tinyformat.h>
#include <uint256.h>
#include <vector>

#include <string>

struct CPowLeaves {
    uint256 l_tick;
    uint256 l_vdf;
    uint256 l_meta;
    uint256 l_rest;
};

template <typename Stream, typename T>
void Serialize(Stream& s, const std::vector<std::vector<T>>& vv)
{
    ::WriteCompactSize(s, vv.size());
    for (const auto& v : vv) {
        Serialize(s, v);  // falls back to the vector<T> overload in serialize.h
    }
}

template <typename Stream, typename T>
void Unserialize(Stream& s, std::vector<std::vector<T>>& vv)
{
    size_t n = ::ReadCompactSize(s);
    vv.clear();
    vv.reserve(n);
    for (size_t i = 0; i < n; i++) {
        std::vector<T> row;
        Unserialize(s, row);  // uses the built-in vector<T> Unserialize
        vv.emplace_back(std::move(row));
    }
}

class CProofBlob
{
public:
    uint8_t version = 0;
    uint64_t tick = 0;
    uint64_t timestamp = 0;
    std::vector<uint8_t> target;
    std::vector<uint8_t> vdf;
    std::vector<uint8_t> hash;
    std::vector<uint8_t> block_hash;
    std::vector<uint8_t> header_prefix;
    bool is_solution = false;
    std::string model_identifier;
    std::string compute_precision;
    std::string ipfs_cid;
    std::string extra_flags;
    float temperature = 0.;
    float top_p = 0.;
    uint32_t top_k = 0;
    float repetition_penalty = 0.;
    std::vector<uint32_t> chosen_tokens;
    std::vector<float> chosen_probs;
    std::vector<float> sampling_u;
    std::vector<float> softmax_normalizers;
    std::vector<uint32_t> prompt_tokens;
    std::vector<uint8_t> pad_mask;
    std::vector<std::vector<float>> topk_logits;
    std::vector<std::vector<uint32_t>> topk_indices;
    std::vector<std::vector<float>> logsumexp_stats;

    flatbuffers::Offset<proof::Proof> ToFlatBuffer(flatbuffers::FlatBufferBuilder& builder) const;

    void fillFromFB(const proof::Proof* pblob);
    std::string ToString() const;

    SERIALIZE_METHODS(CProofBlob, obj)
    {
        READWRITE(obj.version,
            obj.tick,
            obj.timestamp,
            obj.target,
            obj.vdf,
            obj.hash,
            obj.block_hash,
            obj.header_prefix,
            obj.is_solution,
            obj.model_identifier,
            obj.compute_precision,
            obj.ipfs_cid,
            obj.extra_flags,
            obj.temperature,
            obj.top_p,
            obj.top_k,
            obj.repetition_penalty,
            obj.chosen_tokens,
            obj.chosen_probs,
            obj.sampling_u,
            obj.softmax_normalizers,
            obj.prompt_tokens,
            obj.pad_mask,
            obj.topk_logits,     // uses the helper above
            obj.topk_indices,    // nested vector<uint32_t>
            obj.logsumexp_stats  // nested vector<float>
        );
    }  

    uint256 GetModelHash() const {
        size_t at_pos = model_identifier.find('@');
        if (at_pos == std::string::npos) {
            return uint256();
        }
        std::string input = model_identifier; // "name@commit"
        uint256 out;
        CSHA256().Write(reinterpret_cast<const unsigned char*>(input.data()), input.size()).Finalize(out.begin());
        return out;
    }

    // Legacy serialization hash (compatibility)
    uint256 GetHash() const { return (HashWriter{} << *this).GetHash(); }

    // Return the active commitment (Merkle root if use_merkle=true; otherwise legacy serialization hash)
    uint256 GetCommitment(bool use_merkle) const { return use_merkle ? GetMerkleRoot() : GetHash(); }

    // Compute Merkle root commitment over leaves [L_tick, L_vdf, L_meta, L_rest].
    uint256 GetMerkleRoot() const;
    // Build leaves for Merkle commitment.
    CPowLeaves BuildLeaves() const;
    // Build Merkle branches for L_tick and L_vdf (sibling list bottom-up)
    std::vector<uint256> BuildBranchForTick() const;
    std::vector<uint256> BuildBranchForVdf() const;
};

#endif // BITCOIN_PRIMITIVES_PROOFBLOB_H
