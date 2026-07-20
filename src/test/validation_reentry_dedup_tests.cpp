// Tests for re-processing the same block when validation results are already cached.

#include <boost/test/unit_test.hpp>

#include <chainparams.h>
#include <primitives/block.h>
#include <test/util/mining.h>
#include <test/util/mock_validation_api.h>
#include <test/util/setup_common.h>
#include <test/util/validation.h>
#include <util/time.h>
#include <validationadvisory.h>
#include <validation.h>
#include <validationinterface.h>

namespace {

struct PropagationCatcher : public CValidationInterface {
    int count{0};
    void NewPoWValidBlock(const CBlockIndex*, const std::shared_ptr<const CBlock>&) override { ++count; }
};

size_t CountRequestsFor(const std::vector<ValidationRequest>& requests,
                       const uint256& hash,
                       ValidationReqType type)
{
    size_t count{0};
    for (const auto& request : requests) {
        if (request.hash == hash && request.type == type) {
            ++count;
        }
    }
    return count;
}

void ProcessHeaders(node::NodeContext& node, const std::vector<std::shared_ptr<CBlock>>& blocks)
{
    std::vector<CBlockHeader> headers;
    headers.reserve(blocks.size());
    for (const auto& block : blocks) {
        headers.push_back(block->GetBlockHeader());
    }

    BlockValidationState state;
    const CBlockIndex* tip{nullptr};
    BOOST_REQUIRE(Assert(node.chainman)->ProcessNewBlockHeaders(headers, /*min_pow_checked=*/true, state, &tip));
    BOOST_REQUIRE(tip);
    BOOST_CHECK_EQUAL(tip->nHeight, static_cast<int>(blocks.size()));
}

void RecordActiveTipFirstSeen(node::NodeContext& node)
{
    LOCK(cs_main);
    const CBlockIndex* tip{Assert(node.chainman)->ActiveTip()};
    BOOST_REQUIRE(tip);
    BOOST_REQUIRE(Assert(node.chainman)->m_blockman.RecordBlockFirstSeen(tip->GetBlockHash(), tip->nHeight));
}

int64_t ActiveTipTime(node::NodeContext& node)
{
    LOCK(cs_main);
    const CBlockIndex* tip{Assert(node.chainman)->ActiveTip()};
    BOOST_REQUIRE(tip);
    return tip->GetBlockTime();
}

void AllowQuickSmell(MockValidationAPI& api, const CBlock& block)
{
    api.SetRequestStatus(block.GetHash(), ValidationReqType::Quick_Smell, ValidationResponseValue::Quick_OK_Smell_OK);
}

struct ScopedMockTimeReset {
    ~ScopedMockTimeReset() { SetMockTime(0); }
};

struct TensorMainReentrySetup : public ChainTestingSetup {
    ScopedGenesisApproval genesis_ok;

    TensorMainReentrySetup()
        : ChainTestingSetup{ChainType::TENSOR_MAIN, {/*extra_args*/{}, /*coins_db_in_memory=*/true, /*block_tree_db_in_memory=*/true, /*setup_net=*/false, /*setup_validation_interface=*/true, /*min_validation_cache=*/false}}
        , genesis_ok{Params()}
    {
        LoadVerifyActivateChainstate();
        auto& tcm = static_cast<TestChainstateManager&>(*m_node.chainman);
        tcm.JumpOutOfIbd();
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(validation_reentry_dedup_tests, TensorMainReentrySetup)

BOOST_AUTO_TEST_CASE(reprocessing_with_cached_quick_result_does_not_resend_quick_smell)
{
    CBlock block = CreateTensorBlock(m_node);
    const uint256 hash = block.GetHash();
    auto blockptr = std::make_shared<const CBlock>(block);
    bool new_block{false};

    BOOST_CHECK(!Assert(m_node.chainman)->ProcessNewBlock(blockptr, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
    BOOST_CHECK_EQUAL(CountRequestsFor(genesis_ok->GetCapturedRequests(), hash, ValidationReqType::Quick_Smell), 1U);

    genesis_ok->SetRequestStatus(hash, ValidationReqType::Quick_Smell, ValidationResponseValue::Quick_OK_Smell_Fail);
    genesis_ok->ClearCapturedRequests();

    BOOST_CHECK(!Assert(m_node.chainman)->ProcessNewBlock(blockptr, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));

    const auto requests = genesis_ok->GetCapturedRequests();
    BOOST_CHECK_EQUAL(CountRequestsFor(requests, hash, ValidationReqType::Quick_Smell), 0U);
    BOOST_CHECK_EQUAL(CountRequestsFor(requests, hash, ValidationReqType::Full), 1U);
}

BOOST_AUTO_TEST_CASE(reprocessing_with_cached_full_green_does_not_resend_full)
{
    CBlock block = CreateTensorBlock(m_node);
    const uint256 hash = block.GetHash();
    auto blockptr = std::make_shared<const CBlock>(block);
    bool new_block{false};

    genesis_ok->SetRequestStatus(hash, ValidationReqType::Quick_Smell, ValidationResponseValue::Quick_OK_Smell_OK);

    BOOST_CHECK(!Assert(m_node.chainman)->ProcessNewBlock(blockptr, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
    BOOST_CHECK_EQUAL(CountRequestsFor(genesis_ok->GetCapturedRequests(), hash, ValidationReqType::Full), 1U);

    genesis_ok->SetRequestStatus(hash, ValidationReqType::Full, ValidationResponseValue::Full_Green);
    genesis_ok->ClearCapturedRequests();

    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(blockptr, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));

    const auto requests = genesis_ok->GetCapturedRequests();
    BOOST_CHECK_EQUAL(CountRequestsFor(requests, hash, ValidationReqType::Quick_Smell), 0U);
    BOOST_CHECK_EQUAL(CountRequestsFor(requests, hash, ValidationReqType::Full), 0U);
}

BOOST_AUTO_TEST_CASE(reprocessing_with_cached_full_red_accepts_zero_work_and_does_not_resend_full)
{
    CBlock block = CreateTensorBlock(m_node);
    const uint256 hash = block.GetHash();
    auto blockptr = std::make_shared<const CBlock>(block);
    bool new_block{false};

    genesis_ok->SetRequestStatus(hash, ValidationReqType::Quick_Smell, ValidationResponseValue::Quick_OK_Smell_OK);
    genesis_ok->SetRequestStatus(hash, ValidationReqType::Full, ValidationResponseValue::Full_Red);

    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(blockptr, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
    BOOST_CHECK(new_block);
    genesis_ok->ClearCapturedRequests();

    new_block = false;
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(blockptr, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
    BOOST_CHECK(!new_block);

    const auto requests = genesis_ok->GetCapturedRequests();
    BOOST_CHECK_EQUAL(CountRequestsFor(requests, hash, ValidationReqType::Quick_Smell), 0U);
    BOOST_CHECK_EQUAL(CountRequestsFor(requests, hash, ValidationReqType::Full), 0U);
}

BOOST_AUTO_TEST_CASE(reprocessing_without_full_status_resends_full_but_not_quick_smell)
{
    CBlock block = CreateTensorBlock(m_node);
    const uint256 hash = block.GetHash();
    auto blockptr = std::make_shared<const CBlock>(block);
    bool new_block{false};

    genesis_ok->SetRequestStatus(hash, ValidationReqType::Quick_Smell, ValidationResponseValue::Quick_OK_Smell_Fail);

    BOOST_CHECK(!Assert(m_node.chainman)->ProcessNewBlock(blockptr, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
    BOOST_CHECK_EQUAL(CountRequestsFor(genesis_ok->GetCapturedRequests(), hash, ValidationReqType::Quick_Smell), 0U);
    BOOST_CHECK_EQUAL(CountRequestsFor(genesis_ok->GetCapturedRequests(), hash, ValidationReqType::Full), 1U);

    genesis_ok->ClearCapturedRequests();

    BOOST_CHECK(!Assert(m_node.chainman)->ProcessNewBlock(blockptr, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));

    const auto requests = genesis_ok->GetCapturedRequests();
    BOOST_CHECK_EQUAL(CountRequestsFor(requests, hash, ValidationReqType::Quick_Smell), 0U);
    BOOST_CHECK_EQUAL(CountRequestsFor(requests, hash, ValidationReqType::Full), 1U);
}

BOOST_AUTO_TEST_CASE(reprocessing_with_cached_full_amber_resends_full_once_without_repropagation)
{
    PropagationCatcher catcher;
    m_node.validation_signals->RegisterValidationInterface(&catcher);

    CBlock block = CreateTensorBlock(m_node);
    const uint256 hash = block.GetHash();
    auto blockptr = std::make_shared<const CBlock>(block);
    bool new_block{false};

    genesis_ok->SetRequestStatus(hash, ValidationReqType::Quick_Smell, ValidationResponseValue::Quick_OK_Smell_OK);
    genesis_ok->SetRequestStatus(hash, ValidationReqType::Full, ValidationResponseValue::Full_Amber);

    BOOST_CHECK(!Assert(m_node.chainman)->ProcessNewBlock(blockptr, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
    BOOST_CHECK_EQUAL(catcher.count, 1);
    BOOST_CHECK_EQUAL(CountRequestsFor(genesis_ok->GetCapturedRequests(), hash, ValidationReqType::Quick_Smell), 0U);
    BOOST_CHECK_EQUAL(CountRequestsFor(genesis_ok->GetCapturedRequests(), hash, ValidationReqType::Full), 1U);

    genesis_ok->ClearCapturedRequests();

    BOOST_CHECK(!Assert(m_node.chainman)->ProcessNewBlock(blockptr, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));

    const auto requests = genesis_ok->GetCapturedRequests();
    BOOST_CHECK_EQUAL(catcher.count, 1);
    BOOST_CHECK_EQUAL(CountRequestsFor(requests, hash, ValidationReqType::Quick_Smell), 0U);
    BOOST_CHECK_EQUAL(CountRequestsFor(requests, hash, ValidationReqType::Full), 1U);

    m_node.validation_signals->UnregisterValidationInterface(&catcher);
}

BOOST_AUTO_TEST_CASE(quick_smell_fail_then_full_green_accepts_on_retry)
{
    CBlock block = CreateTensorBlock(m_node);
    const uint256 hash = block.GetHash();
    auto blockptr = std::make_shared<const CBlock>(block);
    bool new_block{false};

    genesis_ok->SetRequestStatus(hash, ValidationReqType::Quick_Smell, ValidationResponseValue::Quick_OK_Smell_Fail);

    BOOST_CHECK(!Assert(m_node.chainman)->ProcessNewBlock(blockptr, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
    BOOST_CHECK_EQUAL(CountRequestsFor(genesis_ok->GetCapturedRequests(), hash, ValidationReqType::Quick_Smell), 0U);
    BOOST_CHECK_EQUAL(CountRequestsFor(genesis_ok->GetCapturedRequests(), hash, ValidationReqType::Full), 1U);

    genesis_ok->SetRequestStatus(hash, ValidationReqType::Full, ValidationResponseValue::Full_Green);
    genesis_ok->ClearCapturedRequests();
    new_block = false;

    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(blockptr, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
    BOOST_CHECK(new_block);

    const auto requests = genesis_ok->GetCapturedRequests();
    BOOST_CHECK_EQUAL(CountRequestsFor(requests, hash, ValidationReqType::Quick_Smell), 0U);
    BOOST_CHECK_EQUAL(CountRequestsFor(requests, hash, ValidationReqType::Full), 0U);
}

BOOST_AUTO_TEST_CASE(quick_smell_fail_then_full_red_accepts_zero_work_on_retry)
{
    CBlock block = CreateTensorBlock(m_node);
    const uint256 hash = block.GetHash();
    auto blockptr = std::make_shared<const CBlock>(block);
    bool new_block{false};

    genesis_ok->SetRequestStatus(hash, ValidationReqType::Quick_Smell, ValidationResponseValue::Quick_OK_Smell_Fail);

    BOOST_CHECK(!Assert(m_node.chainman)->ProcessNewBlock(blockptr, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
    BOOST_CHECK_EQUAL(CountRequestsFor(genesis_ok->GetCapturedRequests(), hash, ValidationReqType::Quick_Smell), 0U);
    BOOST_CHECK_EQUAL(CountRequestsFor(genesis_ok->GetCapturedRequests(), hash, ValidationReqType::Full), 1U);

    genesis_ok->SetRequestStatus(hash, ValidationReqType::Full, ValidationResponseValue::Full_Red);
    genesis_ok->ClearCapturedRequests();
    new_block = false;

    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(blockptr, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
    BOOST_CHECK(new_block);

    const auto requests = genesis_ok->GetCapturedRequests();
    BOOST_CHECK_EQUAL(CountRequestsFor(requests, hash, ValidationReqType::Quick_Smell), 0U);
    BOOST_CHECK_EQUAL(CountRequestsFor(requests, hash, ValidationReqType::Full), 0U);
}

BOOST_AUTO_TEST_CASE(quick_smell_ok_without_full_repropagates_only_once_across_reentries)
{
    PropagationCatcher catcher;
    m_node.validation_signals->RegisterValidationInterface(&catcher);

    CBlock block = CreateTensorBlock(m_node);
    const uint256 hash = block.GetHash();
    auto blockptr = std::make_shared<const CBlock>(block);
    bool new_block{false};

    genesis_ok->SetRequestStatus(hash, ValidationReqType::Quick_Smell, ValidationResponseValue::Quick_OK_Smell_OK);

    BOOST_CHECK(!Assert(m_node.chainman)->ProcessNewBlock(blockptr, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
    BOOST_CHECK_EQUAL(catcher.count, 1);
    BOOST_CHECK_EQUAL(CountRequestsFor(genesis_ok->GetCapturedRequests(), hash, ValidationReqType::Quick_Smell), 0U);
    BOOST_CHECK_EQUAL(CountRequestsFor(genesis_ok->GetCapturedRequests(), hash, ValidationReqType::Full), 1U);

    genesis_ok->ClearCapturedRequests();

    BOOST_CHECK(!Assert(m_node.chainman)->ProcessNewBlock(blockptr, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));

    const auto requests = genesis_ok->GetCapturedRequests();
    BOOST_CHECK_EQUAL(catcher.count, 1);
    BOOST_CHECK_EQUAL(CountRequestsFor(requests, hash, ValidationReqType::Quick_Smell), 0U);
    BOOST_CHECK_EQUAL(CountRequestsFor(requests, hash, ValidationReqType::Full), 1U);

    m_node.validation_signals->UnregisterValidationInterface(&catcher);
}

BOOST_AUTO_TEST_CASE(full_amber_then_full_green_accepts_on_later_retry)
{
    CBlock block = CreateTensorBlock(m_node);
    const uint256 hash = block.GetHash();
    auto blockptr = std::make_shared<const CBlock>(block);
    bool new_block{false};

    genesis_ok->SetRequestStatus(hash, ValidationReqType::Quick_Smell, ValidationResponseValue::Quick_OK_Smell_OK);
    genesis_ok->SetRequestStatus(hash, ValidationReqType::Full, ValidationResponseValue::Full_Amber);

    BOOST_CHECK(!Assert(m_node.chainman)->ProcessNewBlock(blockptr, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
    BOOST_CHECK_EQUAL(CountRequestsFor(genesis_ok->GetCapturedRequests(), hash, ValidationReqType::Full), 1U);

    genesis_ok->SetRequestStatus(hash, ValidationReqType::Full, ValidationResponseValue::Full_Green);
    genesis_ok->ClearCapturedRequests();
    new_block = false;

    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(blockptr, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
    BOOST_CHECK(new_block);

    const auto requests = genesis_ok->GetCapturedRequests();
    BOOST_CHECK_EQUAL(CountRequestsFor(requests, hash, ValidationReqType::Quick_Smell), 0U);
    BOOST_CHECK_EQUAL(CountRequestsFor(requests, hash, ValidationReqType::Full), 0U);
}

BOOST_AUTO_TEST_CASE(full_amber_then_full_red_accepts_zero_work_on_later_retry)
{
    CBlock block = CreateTensorBlock(m_node);
    const uint256 hash = block.GetHash();
    auto blockptr = std::make_shared<const CBlock>(block);
    bool new_block{false};

    genesis_ok->SetRequestStatus(hash, ValidationReqType::Quick_Smell, ValidationResponseValue::Quick_OK_Smell_OK);
    genesis_ok->SetRequestStatus(hash, ValidationReqType::Full, ValidationResponseValue::Full_Amber);

    BOOST_CHECK(!Assert(m_node.chainman)->ProcessNewBlock(blockptr, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
    BOOST_CHECK_EQUAL(CountRequestsFor(genesis_ok->GetCapturedRequests(), hash, ValidationReqType::Full), 1U);

    genesis_ok->SetRequestStatus(hash, ValidationReqType::Full, ValidationResponseValue::Full_Red);
    genesis_ok->ClearCapturedRequests();
    new_block = false;

    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(blockptr, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
    BOOST_CHECK(new_block);

    const auto requests = genesis_ok->GetCapturedRequests();
    BOOST_CHECK_EQUAL(CountRequestsFor(requests, hash, ValidationReqType::Quick_Smell), 0U);
    BOOST_CHECK_EQUAL(CountRequestsFor(requests, hash, ValidationReqType::Full), 0U);
}

BOOST_AUTO_TEST_CASE(non_live_node_skips_blocks_outside_configured_tip_window)
{
    gArgs.ForceSetArg("-fullvalidationtipwindow", "2");

    const auto blocks = CreateBlockChain(3, Params());
    ProcessHeaders(m_node, blocks);
    AllowQuickSmell(*genesis_ok, *blocks.at(0));
    AllowQuickSmell(*genesis_ok, *blocks.at(1));

    bool new_block{false};
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(blocks.at(0), /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
    BOOST_CHECK(new_block);
    BOOST_CHECK_EQUAL(CountRequestsFor(genesis_ok->GetCapturedRequests(), blocks.at(0)->GetHash(), ValidationReqType::Full), 0U);

    genesis_ok->ClearCapturedRequests();
    new_block = false;
    BOOST_CHECK(!Assert(m_node.chainman)->ProcessNewBlock(blocks.at(1), /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
    BOOST_CHECK(!new_block);
    BOOST_CHECK_EQUAL(CountRequestsFor(genesis_ok->GetCapturedRequests(), blocks.at(1)->GetHash(), ValidationReqType::Full), 1U);
}

BOOST_AUTO_TEST_CASE(full_validation_tip_window_zero_revalidates_from_genesis)
{
    gArgs.ForceSetArg("-fullvalidationtipwindow", "0");

    const auto blocks = CreateBlockChain(3, Params());
    ProcessHeaders(m_node, blocks);
    AllowQuickSmell(*genesis_ok, *blocks.at(0));

    bool new_block{false};
    BOOST_CHECK(!Assert(m_node.chainman)->ProcessNewBlock(blocks.at(0), /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
    BOOST_CHECK(!new_block);
    BOOST_CHECK_EQUAL(CountRequestsFor(genesis_ok->GetCapturedRequests(), blocks.at(0)->GetHash(), ValidationReqType::Full), 1U);
}

BOOST_AUTO_TEST_CASE(recent_first_seen_tip_makes_node_live_and_validates_deep_fork_prefix)
{
    ScopedMockTimeReset mock_time_reset;
    gArgs.ForceSetArg("-fullvalidationtipwindow", "2");
    SetMockTime(ActiveTipTime(m_node) + 1);

    CBlock live_block = CreateTensorBlock(m_node);
    const uint256 live_hash{live_block.GetHash()};
    AllowQuickSmell(*genesis_ok, live_block);
    genesis_ok->SetRequestStatus(live_hash, ValidationReqType::Full, ValidationResponseValue::Full_Green);

    bool new_block{false};
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(std::make_shared<const CBlock>(live_block),
                                                         /*force_processing=*/true,
                                                         /*min_pow_checked=*/true,
                                                         &new_block));
    BOOST_CHECK(new_block);

    const auto fork_blocks = CreateBlockChain(3, Params());
    BOOST_REQUIRE(fork_blocks.at(0)->GetHash() != live_hash);
    ProcessHeaders(m_node, fork_blocks);
    AllowQuickSmell(*genesis_ok, *fork_blocks.at(0));

    genesis_ok->ClearCapturedRequests();
    new_block = false;
    BOOST_CHECK(!Assert(m_node.chainman)->ProcessNewBlock(fork_blocks.at(0), /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
    BOOST_CHECK(!new_block);
    BOOST_CHECK_EQUAL(CountRequestsFor(genesis_ok->GetCapturedRequests(), fork_blocks.at(0)->GetHash(), ValidationReqType::Full), 1U);
}

BOOST_AUTO_TEST_CASE(old_first_seen_tip_is_not_live_and_uses_tip_window)
{
    ScopedMockTimeReset mock_time_reset;
    gArgs.ForceSetArg("-fullvalidationtipwindow", "2");
    const int64_t first_seen_time{ActiveTipTime(m_node) + 1};
    SetMockTime(first_seen_time);
    RecordActiveTipFirstSeen(m_node);
    SetMockTime(first_seen_time + ADVISORY_OFFLINE_THRESHOLD_SECS + 1);

    const auto blocks = CreateBlockChain(3, Params());
    ProcessHeaders(m_node, blocks);
    AllowQuickSmell(*genesis_ok, *blocks.at(0));

    bool new_block{false};
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(blocks.at(0), /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
    BOOST_CHECK(new_block);
    BOOST_CHECK_EQUAL(CountRequestsFor(genesis_ok->GetCapturedRequests(), blocks.at(0)->GetHash(), ValidationReqType::Full), 0U);
}

BOOST_AUTO_TEST_CASE(recent_tip_catching_up_to_best_header_uses_tip_window)
{
    ScopedMockTimeReset mock_time_reset;
    gArgs.ForceSetArg("-fullvalidationtipwindow", "2");
    SetMockTime(ActiveTipTime(m_node) + 1);
    RecordActiveTipFirstSeen(m_node);

    const auto blocks = CreateBlockChain(3, Params());
    ProcessHeaders(m_node, blocks);
    AllowQuickSmell(*genesis_ok, *blocks.at(0));

    bool new_block{false};
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(blocks.at(0), /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
    BOOST_CHECK(new_block);
    BOOST_CHECK_EQUAL(CountRequestsFor(genesis_ok->GetCapturedRequests(), blocks.at(0)->GetHash(), ValidationReqType::Full), 0U);
}

BOOST_AUTO_TEST_SUITE_END()
