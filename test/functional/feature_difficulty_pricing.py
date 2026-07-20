#!/usr/bin/env python3
# Copyright (c) 2026 The Tensorcash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""End-to-end test of the difficulty PRICING pipeline across the real RPC surface.

Unit tests cover the pricer math; this locks the wiring that only the live RPCs exercise: market-data
population (auto-populate + manual push), mark/market source selection, report-asset FX in the risk
aggregate, persisted market data reload across a restart, the buried-fixing read, and the JSON shape of
pricing.difficulty.quote / pricing.market.status / pricing.portfolio.{summary,risk} / pricing.diagnostics.scan.

Flow: open a difficulty OPTION -> assert flat fallback -> diagnostics coverage gap -> auto-populate model
curve + push vol -> status 'stochastic' -> quote respects price_source (mark vs market) -> portfolio.summary
has nonzero difficulty greeks -> portfolio.risk reports the position, and a non-native report asset scales
its MTM by the native->report FX -> restart reloads the persisted market data -> mining past the fixing
height flips the quote to deterministic 'fixed'.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than
from test_framework.authproxy import JSONRPCException

LAMBDA_SCALE = 1 << 16
RPC_WALLET_ALREADY_LOADED = -35


class DifficultyPricingTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[]]  # standard relay policy
        self.rpc_timeout = 120

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def open_option(self, writer, buyer, contract_id):
        """Co-signed atomic open: writer funds the IM vault, buyer augments with the premium."""
        w_open = writer.difficulty.build_open_option(contract_id, "writer")
        b_open = buyer.difficulty.build_open_option(contract_id, "buyer", {"psbt": w_open["psbt"]})
        w_signed = writer.walletprocesspsbt(b_open["psbt"], True)
        b_signed = buyer.walletprocesspsbt(w_signed["psbt"], True)
        final = buyer.finalizepsbt(b_signed["psbt"])
        assert_equal(final["complete"], True)
        txid = self.nodes[0].sendrawtransaction(final["hex"])
        self.generate(self.nodes[0], 1)
        return txid

    def difficulty_position(self, risk):
        for p in risk["positions"]:
            if p["contract_type"] == "difficulty":
                return p
        raise AssertionError("no difficulty position in risk output")

    def run_test(self):
        node = self.nodes[0]
        node.createwallet("writer", descriptors=True)
        node.createwallet("buyer", descriptors=True)
        writer = node.get_wallet_rpc("writer")
        buyer = node.get_wallet_rpc("buyer")

        # Fund both wallets with mature coinbase (first 110 blocks each end up >100 deep).
        self.generatetoaddress(node, 110, writer.getnewaddress())
        self.generatetoaddress(node, 110, buyer.getnewaddress())
        writer.rescanblockchain()
        buyer.rescanblockchain()

        current_bits = int(node.getblockheader(node.getbestblockhash())["bits"], 16)
        fixing_height = node.getblockcount() + 30           # forecasting horizon, buried in the last step
        settle_lock = fixing_height + 100
        im_btc, premium_btc, lambda_q = 10, 1, 5 * LAMBDA_SCALE

        writer_addr = writer.getnewaddress("", "bech32m")
        buyer_addr = buyer.getnewaddress("", "bech32m")
        terms = {"strike_nbits": current_bits, "fixing_height": fixing_height,   # ATM strike
                 "settle_lock_height": settle_lock, "im": im_btc,
                 "lambda_q": lambda_q, "premium": premium_btc}

        # 1. propose -> accept -> import -> atomic open -> record_open (opened position for risk).
        self.log.info("open difficulty option")
        offer = writer.difficulty.propose_option(terms, "short", "writer", writer_addr)["offer"]
        accepted = buyer.difficulty.accept_option(offer, buyer_addr, {"confirmed": True})
        contract_id = accepted["contract_id"]
        assert_equal(writer.difficulty.import_acceptance(offer, accepted["acceptance"])["contract_id"], contract_id)
        open_txid = self.open_option(writer, buyer, contract_id)
        writer.difficulty.record_open(contract_id, open_txid)
        buyer.difficulty.record_open(contract_id, open_txid)

        # 2. No market data yet -> flat fallback.
        assert_equal(writer.pricing.market.status()["difficulty"]["market"]["pricing_state"], "flat forecast (no curve)")

        # 3. Diagnostics surfaces the coverage gap for the difficulty contract.
        scan = writer.pricing.diagnostics.scan("difficulty", "INFO", 50)
        diff_entries = [e for e in scan if e["contract_type"] == "difficulty"]
        assert_greater_than(len(diff_entries), 0)
        assert any("curve" in w["message"].lower() or "vol" in w["message"].lower()
                   for e in diff_entries for w in e["warnings"])

        # 4. Auto-populate the MODEL forward curve (explicit drift) + push a usable vol surface (market tier).
        self.log.info("auto-populate model curve + calibrate/push vol")
        model = writer.pricing.market.model_difficulty_curve(0.5, None, None, "market")
        assert_equal(model["provenance"], "model")
        assert_equal(model["drift_estimated"], False)
        assert "sigma_annual" in writer.pricing.market.calibrate_difficulty_vol(10, None, None, "market")
        assert_equal(writer.pricing.market.push_difficulty_surface([1, 100000], [0.6, 0.6], "market")["success"], True)
        st = writer.pricing.market.status()["difficulty"]["market"]
        assert_equal(st["curve_provenance"], "model")
        assert_equal(st["pricing_state"], "stochastic")

        # 5. Mark tier with a DIFFERENT sigma -> source selection must change the quote.
        assert_equal(writer.pricing.market.push_difficulty_curve([1, 100000], [current_bits, current_bits], "mark")["success"], True)
        assert_equal(writer.pricing.market.push_difficulty_surface([1, 100000], [0.3, 0.3], "mark")["success"], True)
        q_market = writer.pricing.difficulty.quote("registry", contract_id, None, None, True, "market")
        q_mark = writer.pricing.difficulty.quote("registry", contract_id, None, None, True, "mark")
        assert_equal(q_market["fixing_reached"], False)
        assert_greater_than(q_market["tau_years"], 0.0)
        assert_greater_than(q_market["sigma"], q_mark["sigma"])   # 0.6 (market) vs 0.3 (mark)
        assert_equal(q_mark["forward_provenance"], "mark")

        # 6. Portfolio summary: nonzero difficulty greeks.
        summ = writer.pricing.portfolio.summary("", True)
        assert_greater_than(summ["total_difficulty_count"], 0)
        assert summ["portfolio_greeks"]["difficulty_vega"] != 0.0

        # 7. Portfolio risk in native TSC: the opened difficulty position is reported with FX identity.
        self.log.info("portfolio.risk native + report-asset FX")
        pos_native = self.difficulty_position(writer.pricing.portfolio.risk(False, None, "market", "", True))
        assert_equal(pos_native["report_fx"], 1.0)
        mtm_native = pos_native["mtm"]
        assert mtm_native != 0.0

        # 8. Report-asset FX: a native->ASSET rate must scale the difficulty MTM by report_fx.
        asset_id = "11" * 32
        assert_equal(writer.pricing.market.push_fx("", asset_id, 2.0, 0.0, "market", True, False)["success"], True)
        pos_report = self.difficulty_position(writer.pricing.portfolio.risk(False, None, "market", asset_id, False))
        fx = pos_report["report_fx"]
        assert fx != 1.0, "report FX should differ from the native identity"
        assert abs(pos_report["mtm"] - mtm_native * fx) < 1e-6 * max(1.0, abs(mtm_native))

        # 9. Persisted market data must survive a restart (PricingContext reloads from the wallet DB).
        self.log.info("restart -> persisted market data reload")
        self.restart_node(0, self.extra_args[0])
        try:
            node.loadwallet("writer")
        except JSONRPCException as e:
            if e.error["code"] != RPC_WALLET_ALREADY_LOADED:
                raise
        writer = node.get_wallet_rpc("writer")
        assert_equal(writer.pricing.market.status()["difficulty"]["market"]["pricing_state"], "stochastic")

        # 10. Mine past the fixing height -> the underlying is known -> deterministic 'fixed' quote.
        self.log.info("mine past fixing -> deterministic quote")
        self.generatetoaddress(node, (fixing_height - node.getblockcount()) + 5, writer.getnewaddress())
        q_fixed = writer.pricing.difficulty.quote("registry", contract_id, None, None, True, "market")
        assert_equal(q_fixed["fixing_reached"], True)
        assert_equal(q_fixed["forward_provenance"], "fixed")
        assert_equal(q_fixed["sigma"], 0.0)

        self.log.info("Difficulty pricing pipeline + report-asset FX succeeded")


if __name__ == '__main__':
    DifficultyPricingTest(__file__).main()
