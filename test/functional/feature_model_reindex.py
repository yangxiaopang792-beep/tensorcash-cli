#!/usr/bin/env python3
"""Regression tests for connect-time model-registry validation.

Covers the layering bug where CheckModel() ran inside context-free
CheckBlock(): during -reindex import (and out-of-order block delivery) a
valid block using an on-chain registered model was rejected `unreg-model`
against a not-yet-replayed ModelDB, marked BLOCK_FAILED_VALID, and its
block data was never indexed (leaving a headers-only entry even after
reconsiderblock).

Scenario 1 (-reindex): register a model on-chain, mine blocks USING it,
restart with -reindex, and require the node to reconverge on the same tip
with the model registered and no invalid chain tips.

Scenario 2 (out-of-order delivery): feed a fresh node all headers, then the
model-using tip block BEFORE its registering ancestors' block data. The
block must not be marked invalid; once the rest of the chain is delivered
in order, the node must connect through to the tip.

This test runs on tensor-reg — the model-registry enforcement (unreg-model)
is gated on TENSOR_* chain types and is OFF on plain regtest. The reindex
scenario additionally depends on the genesis exemption in the contextual VDF
check (genesis carries no VDF proof and is only routed through AcceptBlock
during -reindex import).
"""

from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.messages import CBlock, from_hex, msg_block
from test_framework.p2p import P2PDataStore
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_tensorcash import get_tensorcash_test_params
from test_framework.util import assert_equal


SUCCESSFUL_COMMITS_THRESHOLD = 50
MODEL_NAME = "tensor/reindex-regression"
MODEL_COMMIT = "reindex-commit"
MODEL_BLOCKS = 10


class ModelReindexFunctionalTest(BitcoinTestFramework):
    STATUS_ALIASES = {
        "pending_deposit": {"pending_deposit", "pending"},
        "pending_verification": {"pending_verification"},
        "registered": {"registered"},
        "locked": {"locked"},
    }

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        # The model-registry enforcement (unreg-model) is gated on TENSOR_*
        # chain types — plain regtest never enforces it, so this test MUST
        # run on tensor-reg to be a real regression test.
        self.chain = "tensor-reg"
        # tensor-reg startup re-checks blocks through the mock validation API;
        # default 60s is not enough once the chain has a few hundred blocks.
        self.rpc_timeout = 240
        base_args = get_tensorcash_test_params(disable_extapi=True)
        self.default_wallet_name = "model_reindex"
        self.wallet_names = [self.default_wallet_name, False]
        # Mock defaults are passed as args (not just runtime
        # validationmockdefault calls) so they survive the -reindex restart,
        # where every imported block re-runs the quick checks.
        mock_args = [
            "-validationapi=mock",
            "-mockval-force-external=1",
            "-mockval-default-quick=Quick_OK_Smell_OK",
            "-mockval-default-model=Model_OK",
            "-mockval-default-full=full_green",
            "-rpcdoccheck=0",
        ]
        # node1 must NOT whitelist its peers: with noban, Misbehaving never
        # disconnects, which would make the no-punishment assertion in the
        # out-of-order scenario vacuous. Pre-fix, the store-time unreg-model
        # rejection punished the delivering peer (BLOCK_CONSENSUS -> Misbehaving
        # -> disconnect for non-noban inbound peers).
        node1_args = [a for a in base_args + mock_args if not a.startswith("-whitelist")]
        self.extra_args = [base_args + mock_args, node1_args]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        # Nodes stay disconnected: node1 receives node0's chain explicitly
        # (submitheader/submitblock) in the out-of-order scenario.
        self.setup_nodes()

    def init_wallet(self, *, node):
        # No deterministic-key import: the framework's WIF key is regtest-encoded
        # and invalid on tensor-reg. Mining goes to a wallet-generated address.
        wallet_name = self.wallet_names[node] if self.wallet_names else self.default_wallet_name
        rpc = self.nodes[node]
        if not wallet_name:
            return
        rpc.createwallet(wallet_name=wallet_name)

    def run_test(self):
        node = self.nodes[0]
        wallet = node.get_wallet_rpc(self.default_wallet_name)
        self.miner_address = wallet.getnewaddress()

        self.log.info("Mining spendable outputs with the default model")
        self._mine_blocks(node, 101)

        self.log.info("Registering a model on-chain")
        model_hash = self._register_model(node, wallet)

        self.log.info("Mining blocks that USE the registered model")
        node.setminermodel(f"{MODEL_NAME}@{MODEL_COMMIT}")
        self._mine_blocks(node, MODEL_BLOCKS)
        node.setminermodel("", True)

        tip_height = node.getblockcount()
        tip_hash = node.getbestblockhash()

        self.log.info("Scenario 1: out-of-order delivery must not mark model-using blocks invalid")
        self._run_out_of_order_scenario(tip_height, tip_hash)

        self.log.info("Scenario 2: -reindex replays model registrations before model-using blocks connect")
        self.restart_node(0, extra_args=self.extra_args[0] + ["-reindex"])
        # bcore does not auto-load wallets on restart; getmodelregistrationstatus
        # is a wallet RPC, so reload it explicitly.
        if self.default_wallet_name not in self.nodes[0].listwallets():
            self.nodes[0].loadwallet(self.default_wallet_name)
        self.wait_until(lambda: self.nodes[0].getblockcount() == tip_height, timeout=300)
        assert_equal(self.nodes[0].getbestblockhash(), tip_hash)
        for tip in self.nodes[0].getchaintips():
            assert tip["status"] != "invalid", f"invalid chain tip after -reindex: {tip}"
        status = self._wait_for_status(self.nodes[0], model_hash, expected="registered")
        assert_equal(status["deposit_block_height"] > 0, True)

    def _run_out_of_order_scenario(self, tip_height, tip_hash):
        node0 = self.nodes[0]
        node1 = self.nodes[1]
        assert_equal(node1.getblockcount(), 0)

        self.log.info("Loading node0's chain into a P2P peer")
        blocks = []
        for height in range(1, tip_height + 1):
            block_hash = node0.getblockhash(height)
            block = from_hex(CBlock(), node0.getblock(block_hash, 0))
            block.calc_sha256()
            blocks.append(block)
        peer = node1.add_p2p_connection(P2PDataStore())

        self.log.info("Announcing all headers in order")
        peer.send_headers_with_sidecars_and_ping(blocks, include_sidecars=True)

        self.log.info("Delivering the model-using tip block before its registering ancestors")
        peer.send_without_ping(msg_block(blocks[-1]))
        peer.sync_with_ping()
        # Pre-fix: CheckBlock ran the model check at store time against a
        # ModelDB that has only the default model -> unreg-model ->
        # BLOCK_FAILED_VALID (and peer punishment). Post-fix the block is
        # stored and judged only at connect time, so no tip may be invalid
        # here and the peer must stay connected.
        for tip in node1.getchaintips():
            assert tip["status"] != "invalid", f"out-of-order block marked invalid: {tip}"
        assert peer.is_connected, "peer was disconnected after out-of-order block delivery"

        self.log.info("Delivering the remaining blocks in order")
        for block in blocks[:-1]:
            peer.send_without_ping(msg_block(block))
        peer.sync_with_ping()

        self.wait_until(lambda: node1.getbestblockhash() == tip_hash, timeout=120)
        for tip in node1.getchaintips():
            assert tip["status"] != "invalid", f"invalid chain tip after ordered delivery: {tip}"
        assert peer.is_connected, "peer was disconnected during ordered delivery"

    def _register_model(self, node, wallet):
        # Make sure the wallet has processed all mined blocks before spending
        node.syncwithvalidationinterfacequeue()
        self.wait_until(lambda: wallet.getbalance() > Decimal("1"), timeout=60)
        deposit = wallet.createmodeldeposit(MODEL_NAME, MODEL_COMMIT, 1_000_000)
        deposit_txid = deposit["txid"]
        deposit_vout = deposit["deposit_vout"]
        model_hash = deposit["model_hash"]

        # Mine until the deposit actually confirms (a single generate can race
        # the wallet broadcast and produce a coinbase-only block).
        self._confirm_transactions(node, deposit_txid)
        self._wait_for_status(node, model_hash, expected="pending_deposit")

        funding_utxos = self._prepare_commit_funding(wallet, node, exclude_txid=deposit_txid)
        commit_info = wallet.createmodelcommit(deposit_txid, deposit_vout, SUCCESSFUL_COMMITS_THRESHOLD, funding_utxos)
        commit_txids = [entry["txid"] for entry in commit_info["transactions"]]
        assert commit_txids, "expected commit transactions"

        # Confirm the commit txs robustly (1 block per round, resubmit/
        # generateblock fallback) instead of blind-mining a fixed count.
        self._confirm_transactions(node, commit_txids)
        status = self._wait_for_status(node, model_hash, expected="pending_verification")

        self._mine_to_height(node, status["verification_event_height"])
        self._wait_for_status(node, model_hash, expected="registered")
        return model_hash

    def _prepare_commit_funding(self, wallet, node, *, exclude_txid=None, count=SUCCESSFUL_COMMITS_THRESHOLD):
        utxos = wallet.listunspent()
        min_split_amount = Decimal("0.00000001") * count
        candidate = None
        candidate_amount = Decimal("0")
        for entry in utxos:
            if not entry.get("spendable", True):
                continue
            if entry.get("confirmations", 0) == 0:
                continue
            amount = Decimal(str(entry.get("amount", 0)))
            if amount <= 0 or amount < min_split_amount:
                continue
            if exclude_txid and entry.get("txid") == exclude_txid:
                continue
            if amount > candidate_amount:
                candidate = entry
                candidate_amount = amount
        if candidate is None:
            raise AssertionError("No spendable UTXO available to fund commit transactions")

        split = wallet.splitutxo(candidate["txid"], candidate["vout"], count)
        split_txid = split["txid"]
        self._confirm_transactions(node, [split_txid])
        outputs = split["outputs"]
        if len(outputs) != count:
            raise AssertionError(f"Expected {count} funding outputs from splitutxo, got {len(outputs)}")
        return [{"txid": split_txid, "vout": out["vout"]} for out in outputs]

    def _confirm_transactions(self, node, txids):
        if isinstance(txids, str):
            pending = {txids}
        else:
            pending = set(txids)
        attempts = 0
        while pending:
            # Re-submit any pending tx that fell out of the mempool — the
            # shared dbcache/mempool allowance can evict (reason=sizelimit)
            # right after rapid block generation, and wallet rebroadcast is
            # too slow for the test window.
            mempool = set(node.getrawmempool())
            for txid in list(pending):
                if txid in mempool:
                    continue
                try:
                    tx = node.gettransaction(txid, True, True)
                except JSONRPCException:
                    continue
                if tx.get("confirmations", 0) == 0 and tx.get("hex"):
                    try:
                        node.sendrawtransaction(tx["hex"])
                    except JSONRPCException:
                        pass
            self._mine_blocks(node, 1)
            confirmed = set()
            for txid in list(pending):
                try:
                    tx = node.gettransaction(txid, True, True)
                except JSONRPCException:
                    continue
                if tx.get("confirmations", 0) > 0:
                    confirmed.add(txid)
            pending -= confirmed
            attempts += 1
            if attempts > 200 and pending:
                raise AssertionError(f"Transactions failed to confirm: {sorted(pending)}")

    def _mine_blocks(self, node, count):
        if count <= 0:
            return []
        return self.generatetoaddress(node, count, self.miner_address, sync_fun=self.no_op)

    def _mine_to_height(self, node, target_height, batch_size=50):
        current = node.getblockcount()
        while current < target_height:
            remaining = target_height - current
            step = min(batch_size, remaining)
            self._mine_blocks(node, step)
            current += step

    def _wait_for_status(self, node, model_hash, expected=None, timeout=240):
        def _fetch():
            try:
                return node.getmodelregistrationstatus(model_hash)
            except JSONRPCException:
                return None

        def _ready():
            status_obj = _fetch()
            if status_obj is None:
                return False
            if expected is None:
                return True
            return self._status_matches(status_obj["status"], expected)

        try:
            self.wait_until(_ready, timeout=timeout)
        except AssertionError:
            self.log.error(f"last model status for {model_hash}: {_fetch()!r}")
            try:
                self.log.error(f"models list: {node.getmodelslist(False)!r}")
            except JSONRPCException as exc:
                self.log.error(f"getmodelslist failed: {exc}")
            raise
        status_obj = _fetch()
        assert status_obj is not None
        return status_obj

    def _status_matches(self, actual, expected):
        aliases = self.STATUS_ALIASES.get(expected, {expected})
        return actual in aliases


if __name__ == "__main__":
    ModelReindexFunctionalTest(__file__).main()
