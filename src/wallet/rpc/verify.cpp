// Copyright (c) 2025 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <wallet/contract.h>
#include <wallet/rpc/util.h>
#include <wallet/wallet.h>
#include <rpc/util.h>
#include <util/strencodings.h>
#include <core_io.h>
#include <key_io.h>

namespace wallet {

static UniValue FormatRepoTermsForVerification(const RepoOfferRecord& offer, CWallet& wallet)
{
    UniValue terms(UniValue::VOBJ);

    // Contract type and role
    terms.pushKV("contract_type", "REPO");

        bool is_lender = false;
        if (offer.lender_dest_override) {
            const isminetype mine = WITH_LOCK(wallet.cs_wallet, return wallet.IsMine(GetScriptForDestination(*offer.lender_dest_override)));
            is_lender = (mine != ISMINE_NO);
    }
    terms.pushKV("your_role", is_lender ? "LENDER" : "BORROWER");

    // Financial terms
    UniValue financial(UniValue::VOBJ);
    financial.pushKV("principal", ValueFromAmount(offer.terms.principal_leg.units));
    financial.pushKV("interest", ValueFromAmount(offer.terms.interest_leg.units));
    financial.pushKV("collateral_asset", offer.terms.collateral_leg.asset_id.GetHex());
    financial.pushKV("collateral_amount", ValueFromAmount(offer.terms.collateral_leg.units));
    financial.pushKV("maturity_blocks", (int)offer.terms.maturity_height);
    terms.pushKV("financial_terms", financial);

    // Destinations
    UniValue destinations(UniValue::VOBJ);
    destinations.pushKV("lender_address", EncodeDestination(offer.lender_dest));
    destinations.pushKV("borrower_address", EncodeDestination(offer.borrower_dest));
    terms.pushKV("destinations", destinations);

    // FairSign policy
    UniValue fs_policy(UniValue::VOBJ);
    fs_policy.pushKV("require_adaptor", offer.fs_policy.require_adaptor);
    fs_policy.pushKV("reveal_lockstep", offer.fs_policy.reveal_lockstep);
    terms.pushKV("fairsign_policy", fs_policy);

    // Risks
    UniValue risks(UniValue::VARR);
    if (!is_lender) {
        risks.push_back("You may lose collateral if you fail to repay");
        risks.push_back("Interest continues to accrue after maturity");
    } else {
        risks.push_back("Borrower may default on repayment");
        risks.push_back("Collateral value may fluctuate");
    }
    terms.pushKV("risks", risks);

    // Status
    terms.pushKV("offer_id", offer.offer_id.GetHex());
    terms.pushKV("has_acceptance", offer.acceptance.has_value());

    return terms;
}

static UniValue FormatSpotTermsForVerification(const SpotOfferRecord& offer, CWallet& wallet)
{
    UniValue terms(UniValue::VOBJ);

    terms.pushKV("contract_type", "SPOT");

    // Determine role
    bool is_alice = false;
    const isminetype mine = WITH_LOCK(wallet.cs_wallet, return wallet.IsMine(GetScriptForDestination(offer.alice_recv_dest)));
    is_alice = (mine != ISMINE_NO);
    terms.pushKV("your_role", is_alice ? "ALICE" : "BOB");

    // Trade terms
    UniValue trade(UniValue::VOBJ);
    trade.pushKV("alice_deliver_amount", ValueFromAmount(offer.terms.alice_deliver.units));
    trade.pushKV("alice_deliver_asset", offer.terms.alice_deliver.asset_id.GetHex());
    trade.pushKV("bob_deliver_amount", ValueFromAmount(offer.terms.bob_deliver.units));
    trade.pushKV("bob_deliver_asset", offer.terms.bob_deliver.asset_id.GetHex());

    // Calculate exchange rate
    if (offer.terms.alice_deliver.units > 0 && offer.terms.bob_deliver.units > 0) {
        double rate = (double)offer.terms.bob_deliver.units / (double)offer.terms.alice_deliver.units;
        trade.pushKV("exchange_rate", strprintf("%.8f units per unit", rate));
    }

    terms.pushKV("trade_terms", trade);

    // Destinations
    UniValue destinations(UniValue::VOBJ);
    destinations.pushKV("alice_address", EncodeDestination(offer.alice_recv_dest));
    if (offer.bob_recv_dest_hint) {
        destinations.pushKV("bob_address_hint", EncodeDestination(*offer.bob_recv_dest_hint));
    }
    terms.pushKV("destinations", destinations);

    // FairSign policy
    UniValue fs_policy(UniValue::VOBJ);
    fs_policy.pushKV("require_adaptor", offer.fs_policy.require_adaptor);
    fs_policy.pushKV("reveal_lockstep", offer.fs_policy.reveal_lockstep);
    terms.pushKV("fairsign_policy", fs_policy);

    // Risks
    UniValue risks(UniValue::VARR);
    risks.push_back("Atomic swap is irreversible once executed");
    risks.push_back("Network fees apply to all transactions");
    if (!offer.fs_policy.require_adaptor) {
        risks.push_back("No adaptor signature protection - trust required");
    }
    terms.pushKV("risks", risks);

    terms.pushKV("offer_id", offer.offer_id.GetHex());
    terms.pushKV("has_acceptance", offer.acceptance.has_value());

    return terms;
}

static UniValue FormatForwardTermsForVerification(const ForwardContractRecord& offer, CWallet& wallet)
{
    UniValue terms(UniValue::VOBJ);

    terms.pushKV("contract_type", "FORWARD");
    terms.pushKV("contract_id", offer.contract_id.GetHex());

    // Determine role (long or short)
    bool is_long = (offer.local_side == ForwardSide::LONG);
    terms.pushKV("your_role", is_long ? "LONG" : "SHORT");

    // Contract terms
    UniValue contract(UniValue::VOBJ);
    contract.pushKV("long_deliver_amount", ValueFromAmount(offer.terms.long_party.deliver_leg.units));
    contract.pushKV("long_deliver_asset", offer.terms.long_party.deliver_leg.asset_id.GetHex());
    contract.pushKV("short_deliver_amount", ValueFromAmount(offer.terms.short_party.deliver_leg.units));
    contract.pushKV("short_deliver_asset", offer.terms.short_party.deliver_leg.asset_id.GetHex());
    contract.pushKV("premium", ValueFromAmount(offer.terms.premium_leg.units));
    contract.pushKV("premium_asset", offer.terms.premium_leg.asset_id.GetHex());
    contract.pushKV("deadline_short_blocks", (int)offer.terms.deadline_short);
    contract.pushKV("deadline_long_blocks", (int)offer.terms.deadline_long);
    terms.pushKV("contract_terms", contract);

    // Margin requirements
    UniValue margins(UniValue::VOBJ);
    margins.pushKV("long_margin", ValueFromAmount(offer.terms.long_party.margin_leg.units));
    margins.pushKV("long_margin_asset", offer.terms.long_party.margin_leg.asset_id.GetHex());
    margins.pushKV("short_margin", ValueFromAmount(offer.terms.short_party.margin_leg.units));
    margins.pushKV("short_margin_asset", offer.terms.short_party.margin_leg.asset_id.GetHex());
    terms.pushKV("margin_requirements", margins);

    // Vault information (if available)
    if (offer.long_margin_vault && offer.short_margin_vault) {
        UniValue vaults(UniValue::VOBJ);
        vaults.pushKV("long_vault", offer.long_margin_vault->hash.GetHex() + ":" + std::to_string(offer.long_margin_vault->n));
        vaults.pushKV("short_vault", offer.short_margin_vault->hash.GetHex() + ":" + std::to_string(offer.short_margin_vault->n));
        terms.pushKV("vaults", vaults);
    }

    // Destinations
    UniValue destinations(UniValue::VOBJ);
    destinations.pushKV("long_margin_address", EncodeDestination(offer.terms.long_party.margin_dest));
    destinations.pushKV("long_receive_address", EncodeDestination(offer.terms.long_party.settlement_receive_dest));
    destinations.pushKV("short_margin_address", EncodeDestination(offer.terms.short_party.margin_dest));
    destinations.pushKV("short_receive_address", EncodeDestination(offer.terms.short_party.settlement_receive_dest));
    destinations.pushKV("premium_address", EncodeDestination(offer.terms.premium_dest));
    terms.pushKV("destinations", destinations);

    // FairSign policy
    UniValue fs_policy(UniValue::VOBJ);
    fs_policy.pushKV("require_adaptor", offer.fs_policy.require_adaptor);
    fs_policy.pushKV("reveal_lockstep", offer.fs_policy.reveal_lockstep);
    terms.pushKV("fairsign_policy", fs_policy);

    // Risks
    UniValue risks(UniValue::VARR);
    if (is_long) {
        risks.push_back("You pay premium upfront regardless of outcome");
        risks.push_back("Margin may be liquidated if maintenance requirements not met");
        risks.push_back("Settlement depends on oracle/escrow cooperation");
    } else {
        risks.push_back("You receive premium but have delivery obligation");
        risks.push_back("Margin may be liquidated if maintenance requirements not met");
        risks.push_back("Potential unlimited loss if asset price increases");
    }
    terms.pushKV("risks", risks);

    terms.pushKV("has_acceptance", offer.acceptance_commitment_hex.has_value());

    return terms;
}

RPCHelpMan repo_verify_offer()
{
    return RPCHelpMan(
        "repo.verify_offer",
        "Display and verify repo offer terms before acceptance.\n"
        "This command shows all contract details for user review.",
        {
            {"offer_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Repo offer identifier"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "contract_type", "Type of contract (REPO)"},
                {RPCResult::Type::STR, "your_role", "Your role (LENDER or BORROWER)"},
                {RPCResult::Type::OBJ, "financial_terms", "Financial details",
                    {
                        {RPCResult::Type::NUM, "principal", "Principal amount"},
                        {RPCResult::Type::NUM, "interest", "Interest amount"},
                        {RPCResult::Type::STR, "collateral_asset", "Collateral asset type"},
                        {RPCResult::Type::NUM, "collateral_amount", "Collateral amount required"},
                        {RPCResult::Type::NUM, "maturity_blocks", "Maturity in blocks"},
                    }
                },
                {RPCResult::Type::OBJ, "destinations", "Payment destinations",
                    {
                        {RPCResult::Type::STR, "lender_address", "Lender's address"},
                        {RPCResult::Type::STR, "borrower_address", "Borrower's address"},
                    }
                },
                {RPCResult::Type::ARR, "risks", "Risk warnings", {{RPCResult::Type::STR, "", "Risk description"}}},
                {RPCResult::Type::STR_HEX, "offer_id", "Offer identifier"},
                {RPCResult::Type::BOOL, "has_acceptance", "Whether offer has been accepted"},
            }
        },
        RPCExamples{
            HelpExampleCli("repo.verify_offer", "\"abcd1234...\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            const std::string id_hex = request.params[0].get_str();
            if (!IsHex(id_hex) || id_hex.size() != 64) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "offer_id must be 32-byte hex");
            }

            const auto offer_id = uint256::FromHex(id_hex);
            if (!offer_id) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid offer_id");
            }

            auto offer_opt = pwallet->FindRepoOffer(*offer_id);
            if (!offer_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown repo offer");
            }

            return FormatRepoTermsForVerification(*offer_opt, *pwallet);
        }
    );
}

RPCHelpMan spot_verify_offer()
{
    return RPCHelpMan(
        "spot.verify_offer",
        "Display and verify spot offer terms before acceptance.\n"
        "This command shows all trade details for user review.",
        {
            {"offer_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Spot offer identifier"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "contract_type", "Type of contract (SPOT)"},
                {RPCResult::Type::STR, "your_role", "Your role (OFFERER or ACCEPTOR)"},
                {RPCResult::Type::OBJ, "trade_terms", "Trade details",
                    {
                        {RPCResult::Type::NUM, "offer_amount", "Amount being offered"},
                        {RPCResult::Type::STR, "offer_asset", "Asset being offered"},
                        {RPCResult::Type::NUM, "request_amount", "Amount requested"},
                        {RPCResult::Type::STR, "request_asset", "Asset requested"},
                        {RPCResult::Type::STR, "exchange_rate", "Calculated exchange rate"},
                    }
                },
                {RPCResult::Type::OBJ, "destinations", "Payment destinations",
                    {
                        {RPCResult::Type::STR, "offerer_address", "Offerer's address"},
                        {RPCResult::Type::STR, "acceptor_address", "Acceptor's address"},
                    }
                },
                {RPCResult::Type::ARR, "risks", "Risk warnings", {{RPCResult::Type::STR, "", "Risk description"}}},
                {RPCResult::Type::STR_HEX, "offer_id", "Offer identifier"},
                {RPCResult::Type::BOOL, "has_acceptance", "Whether offer has been accepted"},
            }
        },
        RPCExamples{
            HelpExampleCli("spot.verify_offer", "\"abcd1234...\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            const std::string id_hex = request.params[0].get_str();
            if (!IsHex(id_hex) || id_hex.size() != 64) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "offer_id must be 32-byte hex");
            }

            const auto offer_id = uint256::FromHex(id_hex);
            if (!offer_id) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid offer_id");
            }

            auto offer_opt = pwallet->FindSpotOffer(*offer_id);
            if (!offer_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown spot offer");
            }

            return FormatSpotTermsForVerification(*offer_opt, *pwallet);
        }
    );
}

RPCHelpMan forward_verify_offer()
{
    return RPCHelpMan(
        "forward.verify_offer",
        "Display and verify forward contract terms before acceptance.\n"
        "This command shows all contract details including margins and vaults.",
        {
            {"contract_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Forward contract identifier"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "contract_type", "Type of contract (FORWARD)"},
                {RPCResult::Type::STR, "your_role", "Your role (LONG or SHORT)"},
                {RPCResult::Type::OBJ, "contract_terms", "Contract details",
                    {
                        {RPCResult::Type::NUM, "notional_amount", "Notional amount"},
                        {RPCResult::Type::STR, "notional_asset", "Notional asset"},
                        {RPCResult::Type::NUM, "premium", "Premium amount"},
                        {RPCResult::Type::STR, "settlement_asset", "Settlement asset"},
                        {RPCResult::Type::NUM, "maturity_blocks", "Maturity in blocks"},
                    }
                },
                {RPCResult::Type::OBJ, "margin_requirements", "Margin details",
                    {
                        {RPCResult::Type::NUM, "initial_margin", "Initial margin"},
                        {RPCResult::Type::STR, "initial_margin_asset", "IM asset"},
                        {RPCResult::Type::NUM, "maintenance_margin", "Maintenance margin"},
                        {RPCResult::Type::STR, "maintenance_margin_asset", "MM asset"},
                    }
                },
                {RPCResult::Type::OBJ, "vaults", "Vault locations",
                    {
                        {RPCResult::Type::STR, "long_vault", "Long party vault"},
                        {RPCResult::Type::STR, "short_vault", "Short party vault"},
                    }
                },
                {RPCResult::Type::ARR, "risks", "Risk warnings", {{RPCResult::Type::STR, "", "Risk description"}}},
                {RPCResult::Type::STR_HEX, "contract_id", "Contract identifier"},
                {RPCResult::Type::BOOL, "has_acceptance", "Whether offer has been accepted"},
            }
        },
        RPCExamples{
            HelpExampleCli("forward.verify_offer", "\"abcd1234...\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            const std::string id_hex = request.params[0].get_str();
            if (!IsHex(id_hex) || id_hex.size() != 64) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "contract_id must be 32-byte hex");
            }

            const auto contract_id = uint256::FromHex(id_hex);
            if (!contract_id) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid contract_id");
            }

            auto offer_opt = pwallet->FindForwardContract(*contract_id);
            if (!offer_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown forward contract");
            }

            return FormatForwardTermsForVerification(*offer_opt, *pwallet);
        }
    );
}

} // namespace wallet
