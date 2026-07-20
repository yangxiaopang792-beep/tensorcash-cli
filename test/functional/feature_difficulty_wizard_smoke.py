#!/usr/bin/env python3
# Copyright (c) 2026 The Tensorcash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Smoke test for the Qt Difficulty wizard's data path.

The DifficultyContractBuilder wizard (src/qt/difficultycontractbuilder.cpp) builds its offer from
sensible chain defaults (current `getblockchaininfo` bits + height) and hands the economics to the
WalletModel difficulty wrappers, which marshal them into difficulty.propose / difficulty.propose_option
exactly as exercised here. This test reproduces that EXACT data path (strike = current compact target as a
number, fixing = current height, settle = height + maturity, lambda_q = lambda * 2^16, native-TSC margins)
for both a CFD and an option, and asserts the resulting offer JSON is accepted by the RPC layer
(propose -> accept yields a contract_id). It does NOT drive the GUI; it validates the offer the wizard
produces is RPC-valid."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

COIN = 100_000_000
LAMBDA_SCALE = 1 << 16
DIFFCFD_MATURITY_DEPTH = 100


class DifficultyWizardSmokeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[]]  # STANDARD relay policy

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet("maker", descriptors=True)
        node.createwallet("taker", descriptors=True)
        maker = node.get_wallet_rpc("maker")
        taker = node.get_wallet_rpc("taker")
        self.generatetoaddress(node, 130, maker.getnewaddress())
        maker.rescanblockchain()
        taker.rescanblockchain()

        # ---- chain defaults exactly as WalletModel::difficultyChainDefaults() reads them ----
        info = node.getblockchaininfo()
        strike_nbits = int(info["bits"], 16)   # wizard parses the 8-hex compact target to a number
        fixing_height = info["blocks"]
        settle_lock_height = fixing_height + DIFFCFD_MATURITY_DEPTH
        lam = 10.0                              # wizard default leverage
        lambda_q = round(lam * LAMBDA_SCALE)
        im_tsc = 10.0
        premium_tsc = 1.0

        # ================= CFD path (difficultyPropose) =================
        self.log.info("Wizard CFD data path: getblockchaininfo defaults -> difficulty.propose -> accept")
        cfd_econ = {
            "strike_nbits": strike_nbits,
            "fixing_height": fixing_height,
            "settle_lock_height": settle_lock_height,
            "long": {"im": im_tsc, "lambda_q": lambda_q},
            "short": {"im": im_tsc, "lambda_q": lambda_q},
        }
        # Maker is the proposer/"long"; wizard auto-generates the two bech32m payout addresses.
        m_owner = maker.getnewaddress("", "bech32m")
        m_cp = maker.getnewaddress("", "bech32m")
        cfd_offer = maker.difficulty.propose(cfd_econ, "long", m_owner, m_cp)["offer"]
        assert_equal(cfd_offer["version"], 1)
        assert_equal(cfd_offer["contract_type"], "difficulty")

        t_owner = taker.getnewaddress("", "bech32m")
        t_cp = taker.getnewaddress("", "bech32m")
        cfd_accept = taker.difficulty.accept(cfd_offer, t_owner, t_cp, {"confirmed": True})
        assert "contract_id" in cfd_accept and len(cfd_accept["contract_id"]) == 64
        # Proposer can import the acceptance -> identical contract_id (offer round-trips end to end).
        cfd_import = maker.difficulty.import_acceptance(cfd_offer, cfd_accept["acceptance"])
        assert_equal(cfd_import["contract_id"], cfd_accept["contract_id"])
        self.log.info("CFD wizard offer accepted (contract_id %s)", cfd_accept["contract_id"])

        # ================= Option path (difficultyProposeOption) =================
        self.log.info("Wizard option data path: difficulty.propose_option -> accept_option")
        opt_econ = {
            "strike_nbits": strike_nbits,
            "fixing_height": fixing_height,
            "settle_lock_height": settle_lock_height,
            "im": im_tsc,
            "lambda_q": lambda_q,
            "premium": premium_tsc,
        }
        # Maker writes the option (writer side = long); wizard auto-generates one payout address.
        m_writer = maker.getnewaddress("", "bech32m")
        opt_offer = maker.difficulty.propose_option(opt_econ, "long", "writer", m_writer)["offer"]
        assert_equal(opt_offer["contract_type"], "difficulty")
        assert_equal(opt_offer["kind"], "option")

        t_buyer = taker.getnewaddress("", "bech32m")
        opt_accept = taker.difficulty.accept_option(opt_offer, t_buyer, {"confirmed": True})
        assert "contract_id" in opt_accept and len(opt_accept["contract_id"]) == 64
        self.log.info("Option wizard offer accepted (contract_id %s)", opt_accept["contract_id"])

        # ============ term-sheet metrics source: pricing.difficulty.quote (inline) ============
        # The wizard's difficulty_term_sheet_v1 metrics block comes from pricing.difficulty.quote in the
        # exact inline shape below; assert both products are accepted and return a well-formed quote.
        self.log.info("Wizard term-sheet metrics: pricing.difficulty.quote inline (CFD + option)")
        q_cfd = maker.pricing.difficulty.quote("inline", "", {
            "kind": "cfd",
            "strike_nbits": strike_nbits,
            "fixing_height": fixing_height,
            "settle_lock_height": settle_lock_height,
            "long": {"im": im_tsc, "lambda_q": lambda_q},
            "short": {"im": im_tsc, "lambda_q": lambda_q},
        }, None, True)
        assert_equal(q_cfd["contract_type"], "difficulty")
        assert_equal(q_cfd["kind"], "cfd")
        assert "model_unreliable" in q_cfd

        q_opt = maker.pricing.difficulty.quote("inline", "", {
            "kind": "option",
            "strike_nbits": strike_nbits,
            "fixing_height": fixing_height,
            "settle_lock_height": settle_lock_height,
            "writer_side": "long",
            "im": im_tsc,
            "lambda_q": lambda_q,
            "premium": premium_tsc,
        }, None, True)
        assert_equal(q_opt["kind"], "option")
        assert "model_unreliable" in q_opt
        self.log.info("pricing.difficulty.quote accepts the wizard inline terms (CFD unreliable=%s, option unreliable=%s)",
                      q_cfd["model_unreliable"], q_opt["model_unreliable"])

        self.log.info("Difficulty wizard data path produces RPC-accepted CFD + option offers + a priced term sheet")


if __name__ == '__main__':
    DifficultyWizardSmokeTest(__file__).main()
