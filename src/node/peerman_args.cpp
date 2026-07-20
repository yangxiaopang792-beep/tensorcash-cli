#include <node/peerman_args.h>

#include <common/args.h>
#include <net_processing.h>

#include <algorithm>
#include <limits>

namespace node {

void ApplyArgsManOptions(const ArgsManager& argsman, PeerManager::Options& options)
{
    if (auto value{argsman.GetBoolArg("-txreconciliation")}) options.reconcile_txs = *value;

    if (auto value{argsman.GetIntArg("-maxorphantx")}) {
        options.max_orphan_txs = uint32_t((std::clamp<int64_t>(*value, 0, std::numeric_limits<uint32_t>::max())));
    }

    if (auto value{argsman.GetIntArg("-blockreconstructionextratxn")}) {
        options.max_extra_txs = uint32_t((std::clamp<int64_t>(*value, 0, std::numeric_limits<uint32_t>::max())));
    }

    if (auto value{argsman.GetBoolArg("-capturemessages")}) options.capture_messages = *value;

    if (auto value{argsman.GetBoolArg("-blocksonly")}) options.ignore_incoming_txs = *value;

    // SPV selection knobs
    if (auto v{argsman.GetBoolArg("-spv-asn-corroboration")}) options.spv_asn_corroboration = *v;
    if (auto v{argsman.GetIntArg("-spv-asn-min")}) options.spv_asn_min = uint32_t(std::clamp<int64_t>(*v, 0, 100));
    if (auto v{argsman.GetIntArg("-spv-asn-min-reorg-depth")}) options.spv_asn_min_reorg_depth = int(std::clamp<int64_t>(*v, 0, 1000000));
    if (auto v{argsman.GetIntArg("-spv-hysteresis-alpha-bps")}) options.spv_hysteresis_alpha_bps = uint32_t(std::clamp<int64_t>(*v, 0, 10000));
    if (auto v{argsman.GetIntArg("-spv-hysteresis-base-bps")}) options.spv_hysteresis_base_bps = uint32_t(std::clamp<int64_t>(*v, 0, 10000));
    if (auto v{argsman.GetIntArg("-spv-hysteresis-default-tick")}) {
        options.spv_hysteresis_default_tick = *v <= 0 ? 0 : static_cast<uint64_t>(*v);
    }
    if (auto v{argsman.GetIntArg("-spv-min-cumulative-tick-per-block")}) {
        options.spv_min_cumulative_tick_per_block = *v <= 0 ? 0 : static_cast<uint64_t>(*v);
    }
    if (auto v{argsman.GetIntArg("-spv-min-cumulative-tick-slack-days")}) {
        options.spv_min_cumulative_tick_slack_days = uint32_t(std::clamp<int64_t>(*v, 0, 3650));
    }
    if (auto v{argsman.GetIntArg("-spv-reorg-sampling-threshold")}) options.spv_reorg_sampling_threshold = int(std::clamp<int64_t>(*v, 0, 1000));
    if (auto v{argsman.GetIntArg("-spv-sampling-max-n")}) options.spv_sampling_max_n = uint32_t(std::clamp<int64_t>(*v, 1, 1000));
    // Onion diversity knobs
    if (auto v{argsman.GetArg("-spv-onion-prefix")}) options.spv_onion_prefix = *v;
    if (auto v{argsman.GetIntArg("-spv-onion-tag-len")}) options.spv_onion_tag_len = size_t(std::clamp<int64_t>(*v, 1, 10));
    if (auto v{argsman.GetIntArg("-spv-onion-freshness-window")}) options.spv_onion_freshness_window = int(std::clamp<int64_t>(*v, 10, 10000));

    if (auto v{argsman.GetIntArg("-peermanmaxheadersresult")}) {
        options.max_headers_result = uint32_t(std::clamp<int64_t>(*v, 1, int64_t(MAX_HEADERS_RESULTS)));
    }
}

} // namespace node
