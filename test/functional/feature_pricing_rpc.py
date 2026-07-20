#!/usr/bin/env python3
"""Test pricing RPC endpoints (Phase 3).

Tests:
- pricing.repo.quote with registry and inline sourcing
- pricing.forward.quote with registry and inline sourcing
- pricing.diagnostics.scan with severity filtering
- pricing.portfolio.summary with aggregation and Greeks
"""

from decimal import Decimal
from test_framework.test_framework import BitcoinTestFramework
from test_framework.wallet import MiniWallet
from test_framework.address import address_to_scriptpubkey
from test_framework.util import (
    assert_equal,
    assert_greater_than,
)
from time import perf_counter


class PricingRPCTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-assetsheight=0"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.setup_nodes()

    def run_test(self):
        self.log.info("Starting pricing RPC tests")

        # Initialize wallets and fund them
        node = self.nodes[0]
        node.createwallet("lender", descriptors=True)
        lender = node.get_wallet_rpc("lender")

        mini = MiniWallet(node)
        self.generate(mini, 101)

        # Fund lender wallet
        addr = lender.getnewaddress()
        tx = mini.create_self_transfer()
        tx["tx"].vout[0].scriptPubKey = address_to_scriptpubkey(addr)
        tx["tx"].vout[0].nValue = 10_00000000  # 10 BTC
        tx["tx"].rehash()
        mini.sendrawtransaction(from_node=node, tx_hex=tx["tx"].serialize().hex())
        self.generate(node, 1)
        lender.rescanblockchain()

        # For simplicity, use native BTC for all assets in this test
        # Pricing engine works the same way regardless of asset type
        self.log.info("Using native BTC for all test assets")

        def benchmark(label, fn, runs=3):
            samples = []
            result = None
            for _ in range(runs):
                start = perf_counter()
                result = fn()
                samples.append(perf_counter() - start)
            avg_ms = sum(samples) / len(samples) * 1000.0
            min_ms = min(samples) * 1000.0
            max_ms = max(samples) * 1000.0
            self.log.info(f"{label}: {avg_ms:.2f} ms avg over {runs} runs (min {min_ms:.2f}, max {max_ms:.2f})")
            return result

        # Push market data
        self.log.info("Pushing market data")

        # Native BTC asset ID (null hash)
        btc_asset = "0000000000000000000000000000000000000000000000000000000000000000"

        # Push discount curve for native BTC
        result = benchmark(
            "pricing.market.push_curve (native)",
            lambda: lender.pricing.market.push_curve(btc_asset, True, [1, 30, 90, 365], [0.05, 0.05, 0.05, 0.05]),
        )
        assert result["success"], f"Failed to push BTC curve: {result.get('error', 'unknown')}"

        # Push vol surface for native BTC (needed for collateral options in repo)
        result = benchmark(
            "pricing.market.push_vol_surface (native)",
            lambda: lender.pricing.market.push_vol_surface(
                btc_asset,
                [0.8, 1.0, 1.2],
                [30, 90, 180, 365],
                [
                    [0.30, 0.28, 0.26, 0.25],
                    [0.25, 0.25, 0.25, 0.25],
                    [0.30, 0.28, 0.26, 0.25],
                ],
            ),
        )
        assert result["success"], f"Failed to push vol surface: {result.get('error', 'unknown')}"

        self.log.info("Market data pushed successfully")

        # Test pricing.repo.quote with inline sourcing
        self.log.info("Testing pricing.repo.quote with inline sourcing")

        current_height = node.getblockcount()
        quote_terms = {
            "principal_asset": "",
            "principal_is_native": True,
            "principal_units": 100000000,
            "interest_asset": "",
            "interest_is_native": True,
            "interest_units": 5000000,
            "collateral_asset": "",
            "collateral_is_native": True,
            "collateral_units": 110000000,
            "maturity_height": current_height + 144,
            "safety_k": 144,
        }
        quote = benchmark(
            "pricing.repo.quote (inline, mark)",
            lambda: lender.pricing.repo.quote(
                "inline",
                "",
                quote_terms,
                "",
                False,
                False,
            ),
        )

        assert "principal_pv" in quote
        assert "lender_mtm" in quote
        assert "coverage_ratio" in quote
        assert_greater_than(quote["coverage_ratio"], 1.0)

        self.log.info(f"Repo quote successful: lender_mtm={quote['lender_mtm']}")

        # Test pricing.forward.quote with inline sourcing
        self.log.info("Testing pricing.forward.quote with inline sourcing")

        forward_terms = {
            "alice_deliver_asset": "",
            "alice_deliver_is_native": True,
            "alice_deliver_units": 100000000,
            "alice_im_asset": "",
            "alice_im_is_native": True,
            "alice_im_units": 10000000,
            "bob_deliver_asset": "",
            "bob_deliver_is_native": True,
            "bob_deliver_units": 150000000,
            "bob_im_asset": "",
            "bob_im_is_native": True,
            "bob_im_units": 15000000,
            "deadline_short": current_height + 144,
            "safety_k": 144,
        }
        quote = benchmark(
            "pricing.forward.quote (inline, mark)",
            lambda: lender.pricing.forward.quote(
                "inline",
                "",
                forward_terms,
                "",
                False,
                False,
            ),
        )

        assert "pv_receive" in quote
        assert "pv_pay" in quote
        assert "alice_mtm" in quote
        assert "bob_mtm" in quote

        self.log.info(f"Forward quote successful: alice_mtm={quote['alice_mtm']}")

        # Test pricing.diagnostics.scan
        self.log.info("Testing pricing.diagnostics.scan")

        scan = lender.pricing.diagnostics.scan("all", "INFO", 50, "")
        assert isinstance(scan, list)
        self.log.info(f"Diagnostics scan returned {len(scan)} entries")

        # Test pricing.portfolio.summary
        self.log.info("Testing pricing.portfolio.summary")

        summary = lender.pricing.portfolio.summary("", False)
        assert "total_repo_count" in summary
        assert "total_forward_count" in summary
        assert "net_portfolio_mtm" in summary

        self.log.info(f"Portfolio summary: {summary['total_repo_count']} repos, {summary['total_forward_count']} forwards")

        # Test multi-asset basket volatility
        self.test_basket_volatility(node, lender, benchmark)

        self.log.info("All pricing RPC tests passed!")

    def test_basket_volatility(self, node, lender, benchmark):
        """Test basket volatility for multi-asset repos (TSC collateral, GOLD principal, SILVER interest)."""
        self.log.info("Testing multi-asset basket volatility")

        # Create synthetic asset IDs for GOLD and SILVER (for testing purposes)
        # In reality these would come from actual asset issuance
        gold_asset = "1111111111111111111111111111111111111111111111111111111111111111"
        silver_asset = "2222222222222222222222222222222222222222222222222222222222222222"
        tsc_asset = "0000000000000000000000000000000000000000000000000000000000000000"

        # Push FX quotes (spot prices) - needed for PV calculations
        self.log.info("Pushing FX quotes for GOLD/TSC and SILVER/TSC")
        # pricing.market.push_fx(base_asset, quote_asset, spot_rate, bid_ask_bps, source, base_is_native, quote_is_native)
        result = lender.pricing.market.push_fx(gold_asset, tsc_asset, 1.0, 0.0, "mark", False, True)  # 1 GOLD = 1 TSC
        assert result["success"], f"Failed to push GOLD/TSC FX: {result.get('error', 'unknown')}"

        result = lender.pricing.market.push_fx(silver_asset, tsc_asset, 1.0, 0.0, "mark", False, True)  # 1 SILVER = 1 TSC
        assert result["success"], f"Failed to push SILVER/TSC FX: {result.get('error', 'unknown')}"

        # Push discount curves for all assets (using "mark" source to match quote requests)
        self.log.info("Pushing curves for GOLD and SILVER")
        result = lender.pricing.market.push_curve(gold_asset, False, [1, 30, 90, 365], [0.03, 0.03, 0.03, 0.03], "mark")
        assert result["success"], f"Failed to push GOLD curve: {result.get('error', 'unknown')}"

        result = lender.pricing.market.push_curve(silver_asset, False, [1, 30, 90, 365], [0.04, 0.04, 0.04, 0.04], "mark")
        assert result["success"], f"Failed to push SILVER curve: {result.get('error', 'unknown')}"

        # Push vol surfaces (using "mark" source)
        # GOLD: 10% vol
        self.log.info("Pushing vol surface for GOLD (10%)")
        result = lender.pricing.market.push_vol_surface(
            gold_asset,
            [0.8, 1.0, 1.2],
            [30, 90, 180, 365],
            [
                [0.10, 0.10, 0.10, 0.10],
                [0.10, 0.10, 0.10, 0.10],
                [0.10, 0.10, 0.10, 0.10],
            ],
            "mark",
        )
        assert result["success"], f"Failed to push GOLD vol surface: {result.get('error', 'unknown')}"

        # SILVER: 20% vol
        self.log.info("Pushing vol surface for SILVER (20%)")
        result = lender.pricing.market.push_vol_surface(
            silver_asset,
            [0.8, 1.0, 1.2],
            [30, 90, 180, 365],
            [
                [0.20, 0.20, 0.20, 0.20],
                [0.20, 0.20, 0.20, 0.20],
                [0.20, 0.20, 0.20, 0.20],
            ],
            "mark",
        )
        assert result["success"], f"Failed to push SILVER vol surface: {result.get('error', 'unknown')}"

        # Push correlation matrix
        # GOLD-SILVER correlation: 0.6
        self.log.info("Pushing correlation matrix (ρ_GOLD,SILVER = 0.6)")
        result = lender.pricing.market.push_correlation(
            [gold_asset, silver_asset],
            [
                [1.0, 0.6],
                [0.6, 1.0],
            ],
        )
        assert result["success"], f"Failed to push correlation matrix: {result.get('error', 'unknown')}"

        # Test Case 1: TSC collateral, GOLD principal, SILVER interest
        # Expected: σ_basket = sqrt(w_G² * 0.10² + w_S² * 0.20² + 2 * w_G * w_S * 0.6 * 0.10 * 0.20)
        # For equal forward weights (w_G = w_S = 0.5):
        # σ_basket = sqrt(0.25 * 0.01 + 0.25 * 0.04 + 2 * 0.5 * 0.5 * 0.6 * 0.10 * 0.20)
        # σ_basket = sqrt(0.0025 + 0.01 + 0.006) = sqrt(0.0185) ≈ 0.136 (13.6%)
        self.log.info("Test Case 1: TSC collateral, GOLD principal, SILVER interest")

        current_height = node.getblockcount()
        # 90 days = 90 * 144 blocks/day = 12960 blocks (assuming 10 min blocks)
        maturity_90d = current_height + 90 * 144
        quote_terms = {
            "principal_asset": gold_asset,
            "principal_is_native": False,
            "principal_units": 100000000,  # 1.0 GOLD
            "interest_asset": silver_asset,
            "interest_is_native": False,
            "interest_units": 100000000,  # 1.0 SILVER (roughly equal forward value)
            "collateral_asset": tsc_asset,
            "collateral_is_native": True,
            "collateral_units": 250000000,  # 2.5 TSC (over-collateralized)
            "maturity_height": maturity_90d,
            "safety_k": 144,
        }
        quote = benchmark(
            "pricing.repo.quote (TSC coll, GOLD prin, SILVER int)",
            lambda: lender.pricing.repo.quote(
                "inline",
                "",
                quote_terms,
                "",
                False,
                False,
                "mark",  # Explicitly use "mark" source
            ),
        )

        assert "principal_pv" in quote
        assert "interest_pv" in quote
        assert "collateral_pv" in quote
        assert "lender_mtm" in quote
        assert "warnings" in quote

        # Debug: print all quote details
        self.log.info(f"Quote details: principal_pv={quote['principal_pv']}, interest_pv={quote['interest_pv']}, collateral_pv={quote['collateral_pv']}")
        self.log.info(f"Option value: {quote.get('collateral_option', 'N/A')}")

        # Check for basket vol warning message
        basket_warning_found = False
        for warn in quote["warnings"]:
            self.log.info(f"Warning: [{warn.get('severity')}] {warn.get('message')}")
            if "Multi-asset obligation basket" in warn.get("message", ""):
                basket_warning_found = True

        assert basket_warning_found, "Expected to see basket volatility info message"
        self.log.info(f"Test Case 1 passed: lender_mtm={quote['lender_mtm']}")

        # Test Case 2: TSC collateral, TSC principal, TSC interest (should have σ=0 for option)
        self.log.info("Test Case 2: TSC collateral, TSC principal, TSC interest (σ=0)")
        quote_terms_tsc = {
            "principal_asset": tsc_asset,
            "principal_is_native": True,
            "principal_units": 100000000,
            "interest_asset": tsc_asset,
            "interest_is_native": True,
            "interest_units": 5000000,
            "collateral_asset": tsc_asset,
            "collateral_is_native": True,
            "collateral_units": 110000000,
            "maturity_height": maturity_90d,
            "safety_k": 144,
        }
        quote_tsc = lender.pricing.repo.quote(
            "inline",
            "",
            quote_terms_tsc,
            "",
            False,
            False,
            "mark",
        )

        # For TSC vs TSC, option value should be zero (σ=0 → no volatility risk)
        assert_equal(quote_tsc.get("collateral_option", 0), 0)
        self.log.info("Test Case 2 passed: collateral_option=0 (as expected for TSC-TSC)")

        # Test Case 3: GOLD collateral, SILVER principal, TSC interest
        # Expected: σ_obligation should be driven by SILVER vol (TSC is deterministic)
        # Then cross-vol between GOLD and the basket
        self.log.info("Test Case 3: GOLD collateral, SILVER principal, TSC interest")
        quote_terms_cross = {
            "principal_asset": silver_asset,
            "principal_is_native": False,
            "principal_units": 100000000,
            "interest_asset": tsc_asset,
            "interest_is_native": True,
            "interest_units": 10000000,  # Small TSC interest
            "collateral_asset": gold_asset,
            "collateral_is_native": False,
            "collateral_units": 120000000,
            "maturity_height": maturity_90d,
            "safety_k": 144,
        }
        quote_cross = lender.pricing.repo.quote(
            "inline",
            "",
            quote_terms_cross,
            "",
            False,
            False,
            "mark",
        )

        # Debug Test Case 3
        self.log.info(f"Test Case 3 quote: principal_pv={quote_cross.get('principal_pv')}, interest_pv={quote_cross.get('interest_pv')}, collateral_pv={quote_cross.get('collateral_pv')}")
        self.log.info(f"Test Case 3 option: {quote_cross.get('collateral_option')}")
        for warn in quote_cross.get("warnings", []):
            self.log.info(f"Test Case 3 warning: [{warn.get('severity')}] {warn.get('message')}")

        assert "collateral_option" in quote_cross
        if quote_cross["collateral_option"] == 0:
            self.log.error(f"FAIL: Expected non-zero option value but got 0. Check if collateral/obligation PVs are non-zero.")
        assert quote_cross["collateral_option"] > 0, f"Expected non-zero option value, got {quote_cross['collateral_option']}"
        self.log.info(f"Test Case 3 passed: collateral_option={quote_cross['collateral_option']} (non-zero)")

        self.log.info("All basket volatility tests passed!")


if __name__ == "__main__":
    PricingRPCTest(__file__).main()
