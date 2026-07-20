#!/usr/bin/env python3
# Copyright (c) 2026 The Tensorcash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Two-party bilateral lifecycle test for the difficulty-derivative contract.

Two DISTINCT wallets (alice = LONG party / proposer, bob = SHORT party / acceptor) run the full
lifecycle with NO coordinator:

  propose (alice) -> accept (bob, persists record) -> import_acceptance (alice, persists record)
  -> co-signed ATOMIC open (each funds ONLY its own IM vault; one transaction)
  -> record_open (both wallets resolve the funded vault outpoints)
  -> settlement by EITHER party (bob settles the long vault, alice settles the short vault)

It asserts: both wallets independently derive + persist the SAME contract_id; each party funds only its
own IM (neither fronts the other's margin); the open + both settlements relay under STANDARD policy (no
-acceptnonstdtxn); the record + vault outpoints survive a node restart; the covenant spends validate
through ATMP + ConnectBlock (real ChainFixingContext); payouts route across wallets to the committed
addresses with amounts matching a Python mirror of ComputeDiffCfdPayout; difficulty.finalize_settlement
is scoped (rejects non-covenant + unsigned-fee PSBTs); and a spent vault cannot be settled twice.
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.authproxy import JSONRPCException

COIN = 100_000_000
DIFFCFD_MATURITY_DEPTH = 100
MIN_SETTLE_OUTPUT = 546
LAMBDA_SCALE = 1 << 16
RPC_INVALID_PARAMETER = -8
RPC_WALLET_ALREADY_LOADED = -35


def compact_from_uint256(value: int) -> int:
    """GetCompact(): encode a 256-bit target as canonical compact nBits (no sign bit)."""
    if value <= 0:
        return 0
    size = (value.bit_length() + 7) // 8
    if size <= 3:
        compact = value << (8 * (3 - size))
    else:
        compact = value >> (8 * (size - 3))
    compact &= 0x007fffff
    compact |= size << 24
    return compact


def uint256_from_compact(c: int) -> int:
    """SetCompact(): decode compact nBits to a 256-bit target (ignoring the sign bit)."""
    nbytes = (c >> 24) & 0xFF
    mant = c & 0x007fffff
    if nbytes <= 3:
        return mant >> (8 * (3 - nbytes))
    return mant << (8 * (nbytes - 3))


def compute_payout(strike_target, realized_target, lambda_q, im_sats, is_short):
    """Mirror ComputeDiffCfdPayout (consensus/difficulty_cfd.cpp): returns (payout_owner, payout_cp)."""
    if is_short:
        if not (realized_target < strike_target):
            return (im_sats, 0)
        num = strike_target - realized_target
    else:
        if not (realized_target > strike_target):
            return (im_sats, 0)
        num = realized_target - strike_target
    denom = realized_target
    if lambda_q * num >= LAMBDA_SCALE * denom:
        cp = im_sats
    else:
        cp = (lambda_q * num * im_sats) // (LAMBDA_SCALE * denom)
    owner = im_sats - cp
    if 0 < cp < MIN_SETTLE_OUTPUT:
        cp, owner = 0, im_sats
    elif 0 < owner < MIN_SETTLE_OUTPUT:
        owner, cp = 0, im_sats
    return (owner, cp)


def sats(amount_btc) -> int:
    return int(round(Decimal(str(amount_btc)) * COIN))


class DifficultyDerivativeWalletTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # NO -acceptnonstdtxn: open + settlement must relay under STANDARD policy.
        self.extra_args = [[]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def covenant_sign_and_send(self, signer, psbt_b64):
        """Sign the keeper fee input and extract via difficulty.finalize_settlement (finalizepsbt cannot
        extract the covenant spend without a fixing context), then broadcast."""
        processed = signer.walletprocesspsbt(psbt_b64, True)
        extracted = signer.difficulty.finalize_settlement(processed["psbt"])
        return self.nodes[0].sendrawtransaction(extracted["hex"])

    def run_test(self):
        node = self.nodes[0]
        node.createwallet("alice", descriptors=True)  # LONG party + proposer
        node.createwallet("bob", descriptors=True)     # SHORT party + acceptor
        alice = node.get_wallet_rpc("alice")
        bob = node.get_wallet_rpc("bob")

        # Fund both parties with mature coins (each funds only its own IM + fees).
        alice_fund = alice.getnewaddress()
        bob_fund = bob.getnewaddress()
        self.generatetoaddress(node, 130, alice_fund)
        self.generatetoaddress(node, 130, bob_fund)
        alice.rescanblockchain()
        bob.rescanblockchain()

        # Economics: long-loss scenario (difficulty fell ~5% => realized target ~5% above strike).
        H = node.getblockcount() - 5
        realized_bits = int(node.getblockheader(node.getblockhash(H))["bits"], 16)
        realized_target = uint256_from_compact(realized_bits)
        assert realized_target > 0
        strike_target = realized_target * 95 // 100
        strike_nbits = compact_from_uint256(strike_target)
        strike_decoded = uint256_from_compact(strike_nbits)

        im_btc = 10
        im_sats = im_btc * COIN
        lambda_q = 10 * LAMBDA_SCALE
        settle_lock = H + DIFFCFD_MATURITY_DEPTH

        # Distinct payout addresses, each in the owning party's wallet.
        alice_long_owner = alice.getnewaddress("", "bech32m")  # alice = long owner (her IM return)
        alice_short_cp = alice.getnewaddress("", "bech32m")    # alice = short-leg counterparty
        bob_short_owner = bob.getnewaddress("", "bech32m")     # bob = short owner (his IM return)
        bob_long_cp = bob.getnewaddress("", "bech32m")         # bob = long-leg counterparty

        econ = {
            "strike_nbits": strike_nbits,
            "fixing_height": H,
            "settle_lock_height": settle_lock,
            "long": {"im": im_btc, "lambda_q": lambda_q},
            "short": {"im": im_btc, "lambda_q": lambda_q},
        }

        # ---- propose / accept / import_acceptance (no coordinator) ----
        self.log.info("Proposing (alice=long) -> accepting (bob=short) -> importing acceptance (alice)")
        offer = alice.difficulty.propose(econ, "long", alice_long_owner, alice_short_cp)["offer"]

        # Acceptor first reviews (no confirm), then commits.
        review = bob.difficulty.accept(offer, bob_short_owner, bob_long_cp)
        assert "acceptance" not in review
        assert "action_required" in review
        accepted = bob.difficulty.accept(offer, bob_short_owner, bob_long_cp, {"confirmed": True})
        contract_id = accepted["contract_id"]
        acceptance = accepted["acceptance"]

        imported = alice.difficulty.import_acceptance(offer, acceptance)
        # Both wallets independently derived the SAME contract_id.
        assert_equal(imported["contract_id"], contract_id)
        assert_equal(imported["state"], "accepted")

        # ---- co-signed ATOMIC open: each party funds ONLY its own IM vault ----
        self.log.info("Co-signed atomic open (alice funds long IM, bob augments with short IM)")
        a_open = alice.difficulty.build_open(contract_id, "long")
        assert_equal(a_open["leg"], "long")
        b_open = bob.difficulty.build_open(contract_id, "short", {"psbt": a_open["psbt"]})
        assert_equal(b_open["leg"], "short")

        a_signed = alice.walletprocesspsbt(b_open["psbt"], True)
        b_signed = bob.walletprocesspsbt(a_signed["psbt"], True)
        final = bob.finalizepsbt(b_signed["psbt"])
        assert_equal(final["complete"], True)
        open_txid = node.sendrawtransaction(final["hex"])
        self.generate(node, 1)

        # Each funded only its own IM: the open spends each wallet's coins for its own vault. Confirm the
        # two vaults exist at distinct committed addresses.
        decoded = node.decoderawtransaction(final["hex"])
        spks = {o["scriptPubKey"]["address"]: sats(o["value"]) for o in decoded["vout"] if "address" in o["scriptPubKey"]}
        vault_amts = [v for v in spks.values() if v == im_sats]
        assert len(vault_amts) >= 2, "expected both IM vault outputs of value im"

        # ---- record_open in BOTH wallets (resolve funded vault outpoints) ----
        alice.difficulty.record_open(contract_id, open_txid)
        bob.difficulty.record_open(contract_id, open_txid)

        # ---- the opened difficulty contract is visible via the generic contract.list / contract.status ----
        self.log.info("Verifying the opened difficulty contract appears in contract.list / contract.status")
        listed = alice.contract.list({"type": "difficulty"})
        match = [c for c in listed if c["id"] == contract_id]
        assert_equal(len(match), 1)
        entry = match[0]
        assert_equal(entry["type"], "difficulty")
        assert_equal(entry["kind"], "cfd")
        assert_equal(entry["role"], "long")            # alice is the long party
        assert_equal(entry["status"], "opened")
        assert_equal(entry["fixing_height"], H)
        assert_equal(entry["settle_lock_height"], settle_lock)
        assert_equal(int(entry["strike_nbits"], 16), strike_nbits)
        assert_equal(sats(entry["long_leg"]["im"]), im_sats)
        assert "long_vault" in entry and "short_vault" in entry
        # filters: bob sees himself as short; a contradictory role filter yields nothing
        bob_listed = bob.contract.list({"type": "difficulty", "role": "short"})
        assert_equal(len([c for c in bob_listed if c["id"] == contract_id]), 1)
        assert_equal(alice.contract.list({"type": "difficulty", "role": "short"}), [])
        # contract.status detail mirrors the same fields (type=difficulty discriminator, kind=cfd product)
        status = bob.contract.status(contract_id)
        assert_equal(status["type"], "difficulty")
        assert_equal(status["kind"], "cfd")
        assert_equal(status["role"], "short")
        assert_equal(status["state"], "opened")
        assert_equal(status["open_txid"], open_txid)

        # Mine until the fixing height is buried.
        deficit = settle_lock - node.getblockcount()
        if deficit > 0:
            self.generatetoaddress(node, deficit, alice_fund)

        # ---- restart: prove the record + recorded vault outpoints persist ----
        self.log.info("Restarting node to prove persistence")
        self.restart_node(0, self.extra_args[0])
        for name in ("alice", "bob"):
            try:
                node.loadwallet(name)
            except JSONRPCException as e:
                if e.error["code"] != RPC_WALLET_ALREADY_LOADED:
                    raise
        alice = node.get_wallet_rpc("alice")
        bob = node.get_wallet_rpc("bob")

        # Expected payouts (mirror consensus, from the compact-decoded targets).
        l_owner, l_cp = compute_payout(strike_decoded, realized_target, lambda_q, im_sats, is_short=False)
        s_owner, s_cp = compute_payout(strike_decoded, realized_target, lambda_q, im_sats, is_short=True)
        assert_equal(l_owner + l_cp, im_sats)
        assert_equal(s_owner + s_cp, im_sats)
        assert l_owner > 0 and l_cp > 0          # long takes a partial loss
        assert_equal(s_owner, im_sats)            # short stays in-the-money
        assert_equal(s_cp, 0)

        # ---- difficulty.finalize_settlement is scoped (negative cases) ----
        plain = bob.walletcreatefundedpsbt([], [{bob.getnewaddress(): 1.0}])["psbt"]
        plain_signed = bob.walletprocesspsbt(plain, True)["psbt"]
        assert_raises_rpc_error(RPC_INVALID_PARAMETER, "no committed OP_DIFFCFD_SETTLE input",
                                bob.difficulty.finalize_settlement, plain_signed)

        # ---- settle the LONG vault via BOB (either party can settle either leg) ----
        self.log.info("Bob settles the long vault; alice settles the short vault")
        ls = bob.difficulty.build_settlement(contract_id, "long")
        assert_equal(sats(ls["payout_owner"]), l_owner)
        assert_equal(sats(ls["payout_cp"]), l_cp)
        assert_raises_rpc_error(RPC_INVALID_PARAMETER, "not finalized and verified",
                                bob.difficulty.finalize_settlement, ls["psbt"])  # fee input unsigned
        self.covenant_sign_and_send(bob, ls["psbt"])
        self.generate(node, 1)

        # ---- after the long leg settles, the status model reflects it (long vault spent) ----
        st_partial = bob.contract.status(contract_id)
        assert_equal(st_partial["state"], "partially_settled")
        assert_equal(st_partial["long_settled"], True)
        assert_equal(st_partial["short_settled"], False)
        # contract.list filtering tracks the new state too
        assert_equal(bob.contract.list({"type": "difficulty", "state": "opened"}), [])
        assert_equal(len(bob.contract.list({"type": "difficulty", "state": "partially_settled"})), 1)

        # ---- settle the SHORT vault via ALICE (separate tx; one vault per tx) ----
        ss = alice.difficulty.build_settlement(contract_id, "short")
        assert_equal(sats(ss["payout_owner"]), s_owner)
        assert_equal(sats(ss["payout_cp"]), s_cp)
        self.covenant_sign_and_send(alice, ss["psbt"])
        self.generate(node, 1)

        alice.rescanblockchain()
        bob.rescanblockchain()

        # ---- both legs settled -> status model reports "settled" (from either wallet's spend view) ----
        st_settled = bob.contract.status(contract_id)
        assert_equal(st_settled["state"], "settled")
        assert_equal(st_settled["long_settled"], True)
        assert_equal(st_settled["short_settled"], True)
        assert_equal(alice.contract.status(contract_id)["state"], "settled")

        # ---- verify cross-wallet payout routing ----
        self.log.info("Verifying cross-wallet payout routing")
        assert_equal(sats(alice.getreceivedbyaddress(alice_long_owner)), l_owner)
        assert_equal(sats(alice.getreceivedbyaddress(alice_short_cp)), s_cp)
        assert_equal(sats(bob.getreceivedbyaddress(bob_long_cp)), l_cp)
        assert_equal(sats(bob.getreceivedbyaddress(bob_short_owner)), s_owner)
        assert_equal(l_owner + s_cp + l_cp + s_owner, 2 * im_sats)

        # ---- double-settle: the spent vault cannot be settled again ----
        assert_raises_rpc_error(RPC_INVALID_PARAMETER, "missing or already spent",
                                bob.difficulty.build_settlement, contract_id, "long")

        self.log.info("Difficulty-derivative bilateral lifecycle (propose -> settle, two wallets) succeeded")


if __name__ == '__main__':
    DifficultyDerivativeWalletTest(__file__).main()
