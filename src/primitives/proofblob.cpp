#include "proofblob.h"
#include <streams.h>
#include <serialize.h>
#include <consensus/merkle.h>
#include <logging.h>

flatbuffers::Offset<proof::Proof> CProofBlob::ToFlatBuffer(flatbuffers::FlatBufferBuilder& builder) const {
    auto f_target = builder.CreateVector(target);
    auto f_vdf = builder.CreateVector(vdf);
    auto f_hash = builder.CreateVector(hash);
    auto f_block_hash = builder.CreateVector(block_hash);
    auto f_header_prefix = builder.CreateVector(header_prefix);
    auto f_model = builder.CreateString(model_identifier);
    auto f_precision = builder.CreateString(compute_precision);
    auto f_cid = builder.CreateString(ipfs_cid);
    auto f_flags = builder.CreateString(extra_flags);
    auto f_chosen_tokens = builder.CreateVector(chosen_tokens);
    auto f_chosen_probs = builder.CreateVector(chosen_probs);
    auto f_sampling_u = builder.CreateVector(sampling_u);
    auto f_softmax_normalizers = builder.CreateVector(softmax_normalizers);
    auto f_prompt_tokens = builder.CreateVector(prompt_tokens);
    auto f_pad_mask = builder.CreateVector(pad_mask);

    std::vector<flatbuffers::Offset<proof::FloatArray>> logits;
    for (const auto& row : topk_logits) {
        logits.push_back(proof::CreateFloatArrayDirect(builder, &row));
    }
    auto f_logits = builder.CreateVector(logits);

    std::vector<flatbuffers::Offset<proof::UIntArray>> indices;
    for (const auto& row : topk_indices) {
        indices.push_back(proof::CreateUIntArrayDirect(builder, &row));
    }
    auto f_indices = builder.CreateVector(indices);

    std::vector<flatbuffers::Offset<proof::FloatArray>> stats;
    for (const auto& row : logsumexp_stats) {
        stats.push_back(proof::CreateFloatArrayDirect(builder, &row));
    }
    auto f_stats = builder.CreateVector(stats);

    return proof::CreateProof(
        builder,
        version,
        tick,
        timestamp,
        f_target,
        f_vdf,
        f_hash,
        f_block_hash,
        f_header_prefix,
        is_solution,
        f_model,
        f_precision,
        f_cid,
        f_flags,
        temperature,
        top_p,
        top_k,
        repetition_penalty,
        f_chosen_tokens,
        f_chosen_probs,
        f_sampling_u,
        f_softmax_normalizers,
        f_prompt_tokens,
        f_pad_mask,
        f_logits,
        f_indices,
        f_stats
    );
}

void CProofBlob::fillFromFB(const proof::Proof* p) {
    if (!p) return;

    version = p->version();    
    tick = p->tick();
    timestamp = p->timestamp();
    
    // Safely handle potentially null vectors
    if (p->target()) {
        target.assign(p->target()->begin(), p->target()->end());
    } else {
        target.clear();
    }
    
    if (p->vdf()) {
        vdf.assign(p->vdf()->begin(), p->vdf()->end());
    } else {
        vdf.clear();
    }
    
    if (p->hash()) {
        hash.assign(p->hash()->begin(), p->hash()->end());
    } else {
        hash.clear();
    }

    if (p->block_hash()) {
        block_hash.assign(p->block_hash()->begin(), p->block_hash()->end());
    } else {
        block_hash.clear();
    }
    
    if (p->header_prefix()) {
        header_prefix.assign(p->header_prefix()->begin(), p->header_prefix()->end());
    } else {
        header_prefix.clear();
    }
    
    is_solution = p->is_solution();
    
    // Safely handle strings
    model_identifier = p->model_identifier() ? p->model_identifier()->str() : "";
    compute_precision = p->compute_precision() ? p->compute_precision()->str() : "";
    ipfs_cid = p->ipfs_cid() ? p->ipfs_cid()->str() : "";
    extra_flags = p->extra_flags() ? p->extra_flags()->str() : "";
    
    temperature = p->temperature();
    top_p = p->top_p();
    top_k = p->top_k();
    repetition_penalty = p->repetition_penalty();
    
    // Handle numeric vectors
    if (p->chosen_tokens()) {
        chosen_tokens.assign(p->chosen_tokens()->begin(), p->chosen_tokens()->end());
    } else {
        chosen_tokens.clear();
    }
    
    if (p->chosen_probs()) {
        chosen_probs.assign(p->chosen_probs()->begin(), p->chosen_probs()->end());
    } else {
        chosen_probs.clear();
    }
    
    if (p->sampling_u()) {
        sampling_u.assign(p->sampling_u()->begin(), p->sampling_u()->end());
    } else {
        sampling_u.clear();
    }
    
    if (p->softmax_normalizers()) {
        softmax_normalizers.assign(p->softmax_normalizers()->begin(), p->softmax_normalizers()->end());
    } else {
        softmax_normalizers.clear();
    }
    
    if (p->prompt_tokens()) {
        prompt_tokens.assign(p->prompt_tokens()->begin(), p->prompt_tokens()->end());
    } else {
        prompt_tokens.clear();
    }
    
    if (p->pad_mask()) {
        pad_mask.assign(p->pad_mask()->begin(), p->pad_mask()->end());
    } else {
        pad_mask.clear();
    }
    
    // Clear existing 2D vectors
    topk_logits.clear();
    topk_indices.clear();
    logsumexp_stats.clear();
    
    // Handle 2D arrays
    if (p->topk_logits()) {
        topk_logits.reserve(p->topk_logits()->size());
        for (auto fa : *p->topk_logits()) {
            if (fa && fa->values()) {
                topk_logits.emplace_back(fa->values()->begin(), fa->values()->end());
            } else {
                topk_logits.emplace_back(); // Empty vector
            }
        }
    }
    
    if (p->topk_indices()) {
        topk_indices.reserve(p->topk_indices()->size());
        for (auto ua : *p->topk_indices()) {
            if (ua && ua->values()) {
                topk_indices.emplace_back(ua->values()->begin(), ua->values()->end());
            } else {
                topk_indices.emplace_back(); // Empty vector
            }
        }
    }
    
    if (p->logsumexp_stats()) {
        logsumexp_stats.reserve(p->logsumexp_stats()->size());
        for (auto fa : *p->logsumexp_stats()) {
            if (fa && fa->values()) {
                logsumexp_stats.emplace_back(fa->values()->begin(), fa->values()->end());
            } else {
                logsumexp_stats.emplace_back(); // Empty vector
            }
        }
    }

    // Debug output - only when -debug=validation is active
    if (LogAcceptCategory(BCLog::VALIDATION, BCLog::Level::Debug)) {
        LogDebug(BCLog::VALIDATION, "CProofBlob: tick=%u model=%s precision=%s tokens=%zu temp=%.2f top_p=%.2f top_k=%u\n",
                 tick, model_identifier, compute_precision, chosen_tokens.size(),
                 temperature, top_p, top_k);
    }
}

static uint256 PowLeafHash(uint8_t tag, std::span<const unsigned char> data)
{
    // Leaf encoding: 0xFF || "POW\0" || u8(tag) || u32le(len) || data, then double SHA256
    CHash256 h;
    const unsigned char prefix[6] = {0xff, 'P','O','W','\0', tag};
    h.Write(prefix);
    uint32_t len = (uint32_t)data.size();
    unsigned char lbuf[4];
    WriteLE32(lbuf, len);
    h.Write(lbuf);
    if (len) h.Write(data);
    uint256 out;
    h.Finalize(out);
    return out;
}

CPowLeaves CProofBlob::BuildLeaves() const
{
    CPowLeaves out;
    // L_tick
    unsigned char tbuf[8];
    WriteLE64(tbuf, tick);
    out.l_tick = PowLeafHash(/*tag=*/0x01, MakeUCharSpan(tbuf));
    // L_vdf
    out.l_vdf = PowLeafHash(/*tag=*/0x02, MakeUCharSpan(vdf));
    // L_meta: version (u8) + model_hash (32)
    std::vector<unsigned char> meta;
    meta.reserve(1 + 32);
    meta.push_back(version);
    uint256 mh = GetModelHash();
    meta.insert(meta.end(), mh.begin(), mh.end());
    out.l_meta = PowLeafHash(/*tag=*/0x03, meta);
    // L_rest: serialize full blob bytes
    DataStream ss;
    ss << *this;
    out.l_rest = PowLeafHash(/*tag=*/0x04, MakeUCharSpan(ss));
    return out;
}

uint256 CProofBlob::GetMerkleRoot() const
{
    CPowLeaves leaves = BuildLeaves();
    std::vector<uint256> v{leaves.l_tick, leaves.l_vdf, leaves.l_meta, leaves.l_rest};
    return ComputeMerkleRoot(v);
}

std::vector<uint256> CProofBlob::BuildBranchForTick() const
{
    CPowLeaves l = BuildLeaves();
    // Tree: h01 = H(l_tick, l_vdf); h23 = H(l_meta, l_rest); root = H(h01, h23)
    uint256 h23 = Hash(l.l_meta, l.l_rest);
    // Branch for tick: sibling is l_vdf, then h23
    return std::vector<uint256>{l.l_vdf, h23};
}

std::vector<uint256> CProofBlob::BuildBranchForVdf() const
{
    CPowLeaves l = BuildLeaves();
    uint256 h23 = Hash(l.l_meta, l.l_rest);
    // Branch for vdf: sibling is l_tick, then h23
    return std::vector<uint256>{l.l_tick, h23};
}

std::string CProofBlob::ToString() const {
    return strprintf("ModelRecord(tick=%d, timestamp=%d, model_identifier=%s)",
                        tick, timestamp, model_identifier);
}
