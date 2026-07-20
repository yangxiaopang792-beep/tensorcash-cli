// Copyright (c) 2025 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_WALLET_PRICING_CALIBRATOR_H
#define BITCOIN_WALLET_PRICING_CALIBRATOR_H

#include <wallet/pricing/pricing_context.h>
#include <wallet/pricing/warnings.h>
#include <wallet/contract.h>
#include <univalue.h>
#include <uint256.h>
#include <cstdint>
#include <vector>
#include <map>

namespace wallet {
namespace pricing {

/**
 * Market data calibration from bulletin board offers
 * Implements the algorithm specified in PRICING&VALUATION.md §12
 */

struct ParsedOffer {
    std::string offer_id;
    std::string offer_type;  // "buy", "sell", "swap", "repo", "forward", "spot"
    uint256 asset_send;
    bool asset_send_is_native{false};
    uint256 asset_recv;
    bool asset_recv_is_native{false};
    double amount{0.0};
    double price{0.0};      // For spot offers
    int64_t created_at{0};
    int64_t expires_at{0};

    // Contract-specific fields
    std::string contract_type;  // "repo", "forward", "spot"
    std::string maker_role;     // "lender", "borrower", "long", "short"
    double apr{0.0};
    double ltv{0.0};
    uint32_t tenor_days{0};

    // Parsed contract payload
    std::optional<RepoTerms> repo_terms;
    std::optional<ForwardTerms> forward_terms;
    std::optional<SpotTerms> spot_terms;

    // Proof of funds (for volume weighting)
    bool has_proof{false};
    uint64_t proven_volume{0};
};

struct CalibrationResult {
    bool success{false};
    std::vector<Warning> warnings;

    // Statistics
    size_t offers_fetched{0};
    size_t offers_parsed{0};
    size_t spot_offers{0};
    size_t repo_offers{0};
    size_t forward_offers{0};

    // Market data pushed
    size_t fx_quotes_pushed{0};
    size_t curves_pushed{0};
    size_t vol_surfaces_pushed{0};
};

class Calibrator {
public:
    /**
     * Calibrate market data from bulletin board offers
     *
     * @param wallet Wallet to read offers and push market data
     * @param source Source type ("nostr", "manual", etc.)
     * @param max_age_hours Maximum age of offers to include (default 24h)
     * @param decay_tau Time decay constant in hours (default 6h)
     * @param min_volume Minimum volume threshold to include offer
     * @return CalibrationResult with statistics and warnings
     */
    static CalibrationResult Calibrate(
        CWallet& wallet,
        const std::string& source,
        double max_age_hours = 24.0,
        double decay_tau = 6.0,
        uint64_t min_volume = 0
    );

    /**
     * Calibrate from pre-fetched offers (used by RPC layer)
     *
     * @param wallet Wallet for pricing context
     * @param offers Pre-parsed offers from bulletin board
     * @param current_time Current timestamp
     * @param decay_tau Time decay constant in hours
     * @param min_volume Minimum volume threshold
     * @return CalibrationResult with statistics and warnings
     */
    static CalibrationResult CalibrateFromOffers(
        CWallet& wallet,
        const std::vector<ParsedOffer>& offers,
        int64_t current_time,
        double decay_tau,
        uint64_t min_volume
    );

private:
    /**
     * Fetch and parse offers from bulletin board
     */
    static std::vector<ParsedOffer> FetchOffers(
        CWallet& wallet,
        int64_t current_time,
        double max_age_hours
    );

    /**
     * Parse contract payload JSON into terms
     */
    static bool ParseContractPayload(
        const UniValue& payload_json,
        ParsedOffer& offer
    );

    /**
     * Calculate time-weighted volume for an offer
     * w_i = volume_i * exp(-Δt_i/τ)
     */
    static double CalculateWeight(
        const ParsedOffer& offer,
        int64_t current_time,
        double decay_tau
    );

    /**
     * Calibrate spot FX rates from spot offers
     * Returns number of FX quotes pushed
     */
    static size_t CalibrateSpotFX(
        const std::vector<ParsedOffer>& offers,
        PricingContext& ctx,
        int64_t current_time,
        double decay_tau,
        std::vector<Warning>& warnings
    );

    /**
     * Bootstrap zero curves from repo offers
     * Returns number of curves pushed
     */
    static size_t CalibrateRepoCurves(
        const std::vector<ParsedOffer>& offers,
        PricingContext& ctx,
        int64_t current_time,
        double decay_tau,
        std::vector<Warning>& warnings
    );

    /**
     * Fit volatility surfaces from forward offers
     * Returns number of surfaces pushed
     */
    static size_t CalibrateVolSurfaces(
        const std::vector<ParsedOffer>& offers,
        PricingContext& ctx,
        int64_t current_time,
        double decay_tau,
        std::vector<Warning>& warnings
    );
};

} // namespace pricing
} // namespace wallet

#endif // BITCOIN_WALLET_PRICING_CALIBRATOR_H
