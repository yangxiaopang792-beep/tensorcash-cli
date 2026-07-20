// Copyright (c) 2025 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <wallet/pricing/fx_matrix.h>
#include <tinyformat.h>
#include <cmath>
#include <limits>
#include <queue>
#include <set>
#include <algorithm>

namespace wallet {
namespace pricing {

std::optional<std::string> FXQuote::Validate() const
{
    // Check asset IDs (null is OK if is_native flag is set)
    if (!base_is_native && base_asset.IsNull()) {
        return "FX quote has null base asset ID (use base_is_native=true for native)";
    }

    if (!quote_is_native && quote_asset.IsNull()) {
        return "FX quote has null quote asset ID (use quote_is_native=true for native)";
    }

    // Can't have both be native (native/native makes no sense)
    if (base_is_native && quote_is_native) {
        return "FX quote cannot have both base and quote as native";
    }

    // If both are non-native assets, check they're different
    if (!base_is_native && !quote_is_native && base_asset == quote_asset) {
        return "FX quote base and quote assets are identical";
    }

    if (spot_rate <= 0.0) {
        return strprintf("FX spot rate must be positive, got %.8f", spot_rate);
    }

    if (bid_ask_bps < 0.0) {
        return strprintf("Bid-ask spread cannot be negative, got %.2f bps", bid_ask_bps);
    }

    return std::nullopt;
}

std::optional<Warning> FXQuote::CheckStaleness(int64_t current_time,
                                               int64_t warn_threshold_sec,
                                               int64_t critical_threshold_sec) const
{
    const int64_t age_sec = current_time - timestamp;

    if (age_sec >= critical_threshold_sec) {
        return Warning::Critical(
            WarningCategory::FX,
            strprintf("FX quote stale: %d hours old (>24h)", age_sec / 3600),
            static_cast<double>(age_sec)
        );
    }

    if (age_sec >= warn_threshold_sec) {
        return Warning::Warn(
            WarningCategory::FX,
            strprintf("FX quote aging: %d hours old (>12h)", age_sec / 3600),
            static_cast<double>(age_sec)
        );
    }

    return std::nullopt;
}

void FXMatrix::AddQuote(const FXQuote& quote)
{
    if (auto err = quote.Validate()) {
        // Silently skip invalid quotes
        return;
    }

    // Add forward quote
    FXKey forward_key{quote.base_asset, quote.quote_asset, quote.base_is_native, quote.quote_is_native};
    m_quotes[forward_key] = quote;

    // Add inverse quote
    FXQuote inverse = quote.Inverse();
    FXKey inverse_key{inverse.base_asset, inverse.quote_asset, inverse.base_is_native, inverse.quote_is_native};
    m_quotes[inverse_key] = inverse;
}

std::optional<FXResult> FXMatrix::TryDirectQuote(const uint256& base,
                                                 const uint256& quote,
                                                 bool base_is_native,
                                                 bool quote_is_native,
                                                 int64_t current_time) const
{
    FXKey key{base, quote, base_is_native, quote_is_native};
    auto it = m_quotes.find(key);
    if (it == m_quotes.end()) {
        return std::nullopt;
    }

    const auto& q = it->second;
    std::vector<Warning> warnings;

    if (auto warn = q.CheckStaleness(current_time)) {
        warnings.push_back(*warn);
    }

    return FXResult(q.spot_rate, {base, quote}, 1, warnings);
}

std::optional<FXResult> FXMatrix::TryHubTriangulation(const uint256& base,
                                                      const uint256& quote,
                                                      bool base_is_native,
                                                      bool quote_is_native,
                                                      int64_t current_time) const
{
    if (!m_hub_is_native && m_hub.IsNull()) {
        return std::nullopt;
    }

    // base → hub
    FXKey base_to_hub_key{base, m_hub, base_is_native, m_hub_is_native};
    auto base_to_hub_it = m_quotes.find(base_to_hub_key);
    if (base_to_hub_it == m_quotes.end()) {
        return std::nullopt;
    }

    // hub → quote
    FXKey hub_to_quote_key{m_hub, quote, m_hub_is_native, quote_is_native};
    auto hub_to_quote_it = m_quotes.find(hub_to_quote_key);
    if (hub_to_quote_it == m_quotes.end()) {
        return std::nullopt;
    }

    const auto& q1 = base_to_hub_it->second;
    const auto& q2 = hub_to_quote_it->second;

    std::vector<Warning> warnings;

    if (auto warn = q1.CheckStaleness(current_time)) {
        warnings.push_back(*warn);
    }
    if (auto warn = q2.CheckStaleness(current_time)) {
        warnings.push_back(*warn);
    }

    // Combined rate: (base/hub) * (hub/quote) = base/quote
    const double combined_rate = q1.spot_rate * q2.spot_rate;

    return FXResult(combined_rate, {base, m_hub, quote}, 2, warnings);
}

std::optional<FXResult> FXMatrix::FindPathDijkstra(const uint256& base,
                                                   const uint256& quote,
                                                   bool base_is_native,
                                                   bool quote_is_native,
                                                   int64_t current_time) const
{
    // Dijkstra on log prices to find shortest path
    // Distance = -log(rate) so that multiplying rates = adding distances
    // Note: For simplicity, we treat (asset_id, is_native) as the node identity

    struct NodeKey {
        uint256 asset;
        bool is_native;
        bool operator<(const NodeKey& other) const {
            if (is_native != other.is_native) return is_native < other.is_native;
            return asset < other.asset;
        }
        bool operator==(const NodeKey& other) const {
            return is_native == other.is_native && asset == other.asset;
        }
    };

    struct Node {
        NodeKey key;
        double dist;  // Cumulative -log(rate)
        bool operator>(const Node& other) const { return dist > other.dist; }
    };

    std::map<NodeKey, double> distances;
    std::map<NodeKey, NodeKey> predecessors;
    std::priority_queue<Node, std::vector<Node>, std::greater<Node>> pq;

    NodeKey start_key{base, base_is_native};
    NodeKey target_key{quote, quote_is_native};

    distances[start_key] = 0.0;
    pq.push({start_key, 0.0});

    // Guard against cycles/degenerate graphs that would otherwise spin forever.
    // Negative log weights (from arbitrage) can create negative cycles, which
    // Dijkstra is not defined for. Cap the total relaxations to keep the UI responsive.
    const size_t max_iterations = std::max<size_t>(m_quotes.size() * 16, 64);
    size_t iterations = 0;

    while (!pq.empty()) {
        if (++iterations > max_iterations) {
            return std::nullopt; // Graph unstable or too dense; bail out
        }

        Node current = pq.top();
        pq.pop();

        if (current.key == target_key) {
            break; // Found target
        }

        if (current.dist > distances[current.key]) {
            continue; // Already processed better path
        }

        // Explore neighbors by iterating over all quotes
        for (const auto& [fx_key, fx_quote] : m_quotes) {
            // Check if this edge starts from current node
            if (fx_key.base_asset != current.key.asset || fx_key.base_is_native != current.key.is_native) {
                continue;
            }

            NodeKey neighbor{fx_key.quote_asset, fx_key.quote_is_native};
            const double edge_dist = -std::log(fx_quote.spot_rate);
            const double new_dist = current.dist + edge_dist;

            auto it = distances.find(neighbor);
            if (it == distances.end() || new_dist < it->second) {
                distances[neighbor] = new_dist;
                predecessors[neighbor] = current.key;
                pq.push({neighbor, new_dist});
            }
        }
    }

    // Check if path found
    auto it = distances.find(target_key);
    if (it == distances.end()) {
        return std::nullopt;
    }

    // Reconstruct path (for display, just use asset IDs)
    std::vector<uint256> path;
    NodeKey current_key = target_key;
    while (!(current_key == start_key)) {
        path.push_back(current_key.asset);
        auto pred_it = predecessors.find(current_key);
        if (pred_it == predecessors.end()) {
            return std::nullopt; // Path broken
        }
        current_key = pred_it->second;
    }
    path.push_back(start_key.asset);
    std::reverse(path.begin(), path.end());

    // Compute combined rate and collect warnings by walking path
    double combined_rate = 1.0;
    std::vector<Warning> warnings;

    NodeKey walk_key = start_key;
    for (size_t i = 0; i + 1 < path.size(); ++i) {
        // Determine next node's is_native flag by looking up the edge
        NodeKey next_key{path[i+1], false}; // Try non-native first
        FXKey edge_key{walk_key.asset, next_key.asset, walk_key.is_native, false};
        auto quote_it = m_quotes.find(edge_key);

        if (quote_it == m_quotes.end()) {
            // Try native
            next_key.is_native = true;
            edge_key.quote_is_native = true;
            quote_it = m_quotes.find(edge_key);
        }

        if (quote_it == m_quotes.end()) {
            return std::nullopt;
        }

        const auto& q = quote_it->second;
        combined_rate *= q.spot_rate;

        if (auto warn = q.CheckStaleness(current_time)) {
            warnings.push_back(*warn);
        }

        walk_key = next_key;
    }

    const int hops = static_cast<int>(path.size()) - 1;

    // Warn if path is long
    if (hops > 2) {
        warnings.push_back(Warning::Warn(
            WarningCategory::FX,
            strprintf("FX path unusually long: %d hops", hops),
            static_cast<double>(hops)
        ));
    }

    return FXResult(combined_rate, path, hops, warnings);
}

FXResult FXMatrix::GetRate(const uint256& base_asset,
                           const uint256& quote_asset,
                           bool base_is_native,
                           bool quote_is_native,
                           int64_t current_time) const
{
    // Handle identity case (same asset AND same native status)
    if (base_asset == quote_asset && base_is_native == quote_is_native) {
        return FXResult(1.0, {base_asset}, 0, {});
    }

    // Try direct quote
    if (auto result = TryDirectQuote(base_asset, quote_asset, base_is_native, quote_is_native, current_time)) {
        return *result;
    }

    // Try hub triangulation
    if (auto result = TryHubTriangulation(base_asset, quote_asset, base_is_native, quote_is_native, current_time)) {
        return *result;
    }

    // Try general Dijkstra
    if (auto result = FindPathDijkstra(base_asset, quote_asset, base_is_native, quote_is_native, current_time)) {
        return *result;
    }

    // No path found
    std::string base_desc = base_is_native ? "TSC(native)" : base_asset.GetHex().substr(0, 8);
    std::string quote_desc = quote_is_native ? "TSC(native)" : quote_asset.GetHex().substr(0, 8);

    return FXResult(0.0, {}, 0, {
        Warning::Critical(
            WarningCategory::FX,
            strprintf("No FX path found from %s to %s", base_desc, quote_desc)
        )
    });
}

std::optional<Warning> FXMatrix::CheckArbitrage(double threshold_bps) const
{
    // Check for simple triangular arbitrage cycles
    // For each triple (A, B, C), check if A→B→C→A product != 1
    // Note: We need to track (asset_id, is_native) pairs as distinct nodes

    struct AssetNode {
        uint256 asset;
        bool is_native;
        bool operator<(const AssetNode& other) const {
            if (is_native != other.is_native) return is_native < other.is_native;
            return asset < other.asset;
        }
        bool operator==(const AssetNode& other) const {
            return is_native == other.is_native && asset == other.asset;
        }
    };

    std::set<AssetNode> assets;
    for (const auto& [fx_key, quote] : m_quotes) {
        assets.insert({fx_key.base_asset, fx_key.base_is_native});
        assets.insert({fx_key.quote_asset, fx_key.quote_is_native});
    }

    for (const auto& A : assets) {
        for (const auto& B : assets) {
            if (A == B) continue;

            FXKey AB_key{A.asset, B.asset, A.is_native, B.is_native};
            auto AB = m_quotes.find(AB_key);
            if (AB == m_quotes.end()) continue;

            for (const auto& C : assets) {
                if (C == A || C == B) continue;

                FXKey BC_key{B.asset, C.asset, B.is_native, C.is_native};
                FXKey CA_key{C.asset, A.asset, C.is_native, A.is_native};

                auto BC = m_quotes.find(BC_key);
                auto CA = m_quotes.find(CA_key);

                if (BC == m_quotes.end() || CA == m_quotes.end()) continue;

                const double product = AB->second.spot_rate *
                                      BC->second.spot_rate *
                                      CA->second.spot_rate;

                const double deviation = std::abs(product - 1.0);
                const double deviation_bps = deviation * 10000.0;

                if (deviation_bps > threshold_bps) {
                    return Warning::Warn(
                        WarningCategory::FX,
                        strprintf("FX arbitrage detected: %.1f bps deviation in cycle (quotes may be stale)",
                                 deviation_bps),
                        deviation_bps
                    );
                }
            }
        }
    }

    return std::nullopt;
}

} // namespace pricing
} // namespace wallet
