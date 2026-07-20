#!/usr/bin/env python3
# Copyright (c) 2026 The Tensorcash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Two-party bilateral lifecycle test for the difficulty OPTION (premium + single margined leg).

Two DISTINCT wallets (writer = posts the IM vault, buyer = pays the premium) run the full lifecycle with
no coordinator:

  propose_option (writer) -> accept_option (buyer, persists) -> import_acceptance (writer, persists)
  -> co-signed ATOMIC open (writer funds the IM vault; buyer funds the premium -> writer)
  -> record_open (both wallets resolve the single writer vault)
  -> settlement of the one vault (buyer settles): payout to the buyer if in-the-money, else writer keeps IM.

It exercises BOTH the ITM (long-loss) and OTM scenarios on the same primitive, asserts both wallets derive
the SAME contract_id, the premium lands at the writer's address, the writer's IM is funded by the writer
only (buyer is out just the premium), the open + settlement relay under STANDARD policy, persistence across
restart, and payout amounts match a Python mirror of ComputeDiffCfdPayout.
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
    if value <= 0:
        return 0
    size = (value.bit_length() + 7) // 8
    compact = value << (8 * (3 - size)) if size <= 3 else value >> (8 * (size - 3))
    compact &= 0x007fffff
    compact |= size << 24
    return compact


def uint256_from_compact(c: int) -> int:
    nbytes = (c >> 24) & 0xFF
    mant = c & 0x007fffff
    return mant >> (8 * (3 - nbytes)) if nbytes <= 3 else mant << (8 * (nbytes - 3))


def compute_payout(strike_target, realized_target, lambda_q, im_sats, is_short):
    """Mirror ComputeDiffCfdPayout: returns (payout_owner=writer, payout_cp=buyer)."""
    if is_short:
        if not (realized_target < strike_target):
            return (im_sats, 0)
        num = strike_target - realized_target
    else:
        if not (realized_target > strike_target):
            return (im_sats, 0)
        num = realized_target - strike_target
    denom = realized_target
    cp = im_sats if lambda_q * num >= LAMBDA_SCALE * denom else (lambda_q * num * im_sats) // (LAMBDA_SCALE * denom)
    owner = im_sats - cp
    if 0 < cp < MIN_SETTLE_OUTPUT:
        cp, owner = 0, im_sats
    elif 0 < owner < MIN_SETTLE_OUTPUT:
        owner, cp = 0, im_sats
    return (owner, cp)


def sats(amount_btc) -> int:
    return int(round(Decimal(str(amount_btc)) * COIN))


class DifficultyOptionWalletTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[]]  # STANDARD relay policy

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def covenant_sign_and_send(self, signer, psbt_b64):
        processed = signer.walletprocesspsbt(psbt_b64, True)
        extracted = signer.difficulty.finalize_settlement(processed["psbt"])
        return self.nodes[0].sendrawtransaction(extracted["hex"])

    def open_option(self, writer, buyer, contract_id):
        """Co-signed atomic open: writer funds the IM vault, buyer augments with the premium. Returns txid."""
        w_open = writer.difficulty.build_open_option(contract_id, "writer")
        assert_equal(w_open["role"], "writer")
        b_open = buyer.difficulty.build_open_option(contract_id, "buyer", {"psbt": w_open["psbt"]})
        assert_equal(b_open["role"], "buyer")
        w_signed = writer.walletprocesspsbt(b_open["psbt"], True)
        b_signed = buyer.walletprocesspsbt(w_signed["psbt"], True)
        final = buyer.finalizepsbt(b_signed["psbt"])
        assert_equal(final["complete"], True)
        txid = self.nodes[0].sendrawtransaction(final["hex"])
        self.generate(self.nodes[0], 1)
        return txid

    def run_one(self, writer_side, lambda_q, expect_buyer_itm):
        """Open + settle one option with the writer holding `writer_side`; verify ITM/OTM payout routing."""
        node = self.nodes[0]
        wname = "writer_" + writer_side
        bname = "buyer_" + writer_side
        node.createwallet(wname, descriptors=True)
        node.createwallet(bname, descriptors=True)
        writer = node.get_wallet_rpc(wname)
        buyer = node.get_wallet_rpc(bname)
        self.generatetoaddress(node, 110, writer.getnewaddress())
        self.generatetoaddress(node, 110, buyer.getnewaddress())
        writer.rescanblockchain()
        buyer.rescanblockchain()

        H = node.getblockcount() - 5
        realized_bits = int(node.getblockheader(node.getblockhash(H))["bits"], 16)
        realized_target = uint256_from_compact(realized_bits)
        # writer LONG loses as difficulty falls (realized target > strike) -> buyer ITM when strike below.
        # To make the buyer ITM: long writer -> strike below realized; short writer -> strike above realized.
        if writer_side == "long":
            strike_target = (realized_target * 95 // 100) if expect_buyer_itm else (realized_target * 2)
        else:
            strike_target = (realized_target * 2) if expect_buyer_itm else (realized_target * 95 // 100)
        strike_nbits = compact_from_uint256(strike_target)
        strike_decoded = uint256_from_compact(strike_nbits)

        im_btc, premium_btc = 10, 1
        im_sats, premium_sats = im_btc * COIN, premium_btc * COIN
        settle_lock = H + DIFFCFD_MATURITY_DEPTH
        writer_is_short = (writer_side == "short")

        writer_addr = writer.getnewaddress("", "bech32m")  # IM-return at settle + premium receipt at open
        buyer_addr = buyer.getnewaddress("", "bech32m")     # option payout if ITM

        terms = {"strike_nbits": strike_nbits, "fixing_height": H, "settle_lock_height": settle_lock,
                 "im": im_btc, "lambda_q": lambda_q, "premium": premium_btc}

        self.log.info("[%s/%s] propose -> accept -> import", writer_side, "ITM" if expect_buyer_itm else "OTM")
        offer = writer.difficulty.propose_option(terms, writer_side, "writer", writer_addr)["offer"]
        accepted = buyer.difficulty.accept_option(offer, buyer_addr, {"confirmed": True})
        contract_id = accepted["contract_id"]
        imported = writer.difficulty.import_acceptance(offer, accepted["acceptance"])
        assert_equal(imported["contract_id"], contract_id)

        # Open (atomic): writer funds IM vault, buyer funds premium.
        open_txid = self.open_option(writer, buyer, contract_id)
        # The premium landed at the writer's address.
        assert_equal(sats(writer.getreceivedbyaddress(writer_addr)), premium_sats)

        writer.difficulty.record_open(contract_id, open_txid)
        buyer.difficulty.record_open(contract_id, open_txid)

        deficit = settle_lock - node.getblockcount()
        if deficit > 0:
            self.generatetoaddress(node, deficit, writer.getnewaddress())

        # Restart -> persistence.
        self.restart_node(0, self.extra_args[0])
        for n in (wname, bname):
            try:
                node.loadwallet(n)
            except JSONRPCException as e:
                if e.error["code"] != RPC_WALLET_ALREADY_LOADED:
                    raise
        writer = node.get_wallet_rpc(wname)
        buyer = node.get_wallet_rpc(bname)

        owner_pay, cp_pay = compute_payout(strike_decoded, realized_target, lambda_q, im_sats, writer_is_short)
        if expect_buyer_itm:
            assert cp_pay > 0, "scenario should be in-the-money for the buyer"
        else:
            assert_equal(cp_pay, 0)  # out-of-the-money: writer keeps full IM

        # Settle the single vault (buyer does it — either party can).
        ss = buyer.difficulty.build_settlement(contract_id, writer_side)
        assert_equal(sats(ss["payout_owner"]), owner_pay)
        assert_equal(sats(ss["payout_cp"]), cp_pay)
        self.covenant_sign_and_send(buyer, ss["psbt"])
        self.generate(node, 1)
        writer.rescanblockchain()
        buyer.rescanblockchain()

        # Payout routing: writer (owner) gets owner_pay back from the vault; buyer (cp) gets cp_pay.
        assert_equal(sats(buyer.getreceivedbyaddress(buyer_addr)), cp_pay)
        # Writer received the premium at open + their IM-return at settle, both at writer_addr.
        assert_equal(sats(writer.getreceivedbyaddress(writer_addr)), premium_sats + owner_pay)
        self.log.info("[%s/%s] settled: writer keeps %d, buyer gets %d (premium %d)",
                      writer_side, "ITM" if expect_buyer_itm else "OTM", owner_pay, cp_pay, premium_sats)

    def run_test(self):
        # In-the-money for the buyer (writer long, difficulty fell): buyer's payout > 0, capped at IM.
        self.run_one("long", 10 * LAMBDA_SCALE, expect_buyer_itm=True)
        # Out-of-the-money (writer short, difficulty did not rise enough): writer keeps full IM, buyer out the premium.
        self.run_one("short", 10 * LAMBDA_SCALE, expect_buyer_itm=False)
        self.log.info("Difficulty OPTION bilateral lifecycle (ITM + OTM, two wallets) succeeded")


if __name__ == '__main__':
    DifficultyOptionWalletTest(__file__).main()
