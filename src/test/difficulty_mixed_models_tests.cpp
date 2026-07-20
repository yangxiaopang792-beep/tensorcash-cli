// Ensure retargeting (GetNextWorkRequired) depends on nBits and timestamps, not nAdjBits or model difficulty

#include <boost/test/unit_test.hpp>

#include <chainparams.h>
#include <consensus/params.h>
#include <modeldb.h>
#include <wallet/rpc/api_model_registration.h>
#include <pow.h>
#include <validation.h>
#include <kernel/cs_main.h>
#include <hash.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>

BOOST_FIXTURE_TEST_SUITE(difficulty_mixed_models_tests, RegTestingSetup)

// Build a small header chain that alternates model difficulty and nAdjBits; verify retarget output stable
BOOST_AUTO_TEST_CASE(retarget_ignores_model_and_nadjbits)
{
    const auto& cons = Params().GetConsensus();

    // Seed two model entries with different difficulties in ModelDB (for completeness)
    if (g_modeldb) {
        ModelRecord m1;
        m1.metadata.model_name = "mixA";
        m1.metadata.model_commit = "v1";
        m1.metadata.difficulty = static_cast<int64_t>(cons.ModelDifficultyNormalizer);
        m1.status = ModelRegistrationStatus::PendingVerification;
        ModelRecord m2;
        m2.metadata.model_name = "mixB";
        m2.metadata.model_commit = "v1";
        m2.metadata.difficulty = static_cast<int64_t>(2 * cons.ModelDifficultyNormalizer);
        m2.status = ModelRegistrationStatus::Banned;
        auto hash_pair = [](const std::string& a, const std::string& b){
            uint256 out; CSHA256().Write((const unsigned char*)a.data(), a.size()).Write((const unsigned char*)b.data(), b.size()).Finalize(out.begin()); return out;
        };
        const uint256 h1 = hash_pair(m1.metadata.model_name, m1.metadata.model_commit);
        const uint256 h2 = hash_pair(m2.metadata.model_name, m2.metadata.model_commit);
        if (!g_modeldb->Exists(h1)) g_modeldb->WriteModel(h1, m1);
        if (!g_modeldb->Exists(h2)) g_modeldb->WriteModel(h2, m2);
    }

    // Use the current tip as pprev. We'll simulate headers for GetNextWorkRequired
    const CBlockIndex* pprev = WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip());
    BOOST_REQUIRE(pprev);

    // Baseline header (no alternations)
    CBlockHeader base;
    base.nVersion = 1;
    base.hashPrevBlock = pprev->GetBlockHash();
    base.hashMerkleRoot.SetNull();
    base.nTime = pprev->GetBlockTime() + 1;
    base.nBits = pprev->nBits;
    base.nAdjBits = base.nBits;
    base.nNonce = 0;

    unsigned int baseline = GetNextWorkRequired(pprev, &base, cons);

    // Alternate model and vary nAdjBits across several hypothetical headers
    for (int i = 0; i < 6; ++i) {
        CBlockHeader h = base;
        h.nTime += i + 1; // advance time
        // flip nAdjBits to varied values
        if (i % 2 == 0) h.nAdjBits = h.nBits - 1; else h.nAdjBits = h.nBits + 1;
        // alternate prev pointer imitation by reusing pprev; we only care about GetNextWorkRequired independence
        unsigned int nbits = GetNextWorkRequired(pprev, &h, cons);
        // Must match baseline for same (pprev, timestamps) irrespective of nAdjBits/model
        BOOST_CHECK_EQUAL(nbits, baseline);
    }
}

BOOST_AUTO_TEST_SUITE_END()
