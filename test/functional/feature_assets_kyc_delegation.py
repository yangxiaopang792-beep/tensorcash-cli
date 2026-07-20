#!/usr/bin/env python3
# Copyright (c) 2024 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""End-to-end test for reusable/delegated KYC (REUSABLE_KYC.md).

Asset B delegates its KYC cohort to asset A, then a member of A's cohort spends
B using a real HDv1 proof verified against A's root + VK. This exercises the full
delegation stack on a real node: IssuerReg v2, the genesis activation gate, the
ConnectBlock registration guardrails, the canonical-VK allowlist, the
CheckTxInputs B->A resolution, and the getassetpolicy effective-policy surfacing.
"""

import hashlib
import json
import os
import time
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.descriptors import descsum_create
from test_framework.wallet_util import bytes_to_wif
from test_framework.key import ECKey

PK_FILE = "/build/shared-utils/kyc-prover/vectors_hd_v1/proving_key_v1.bin"
VK_FILE = "/build/shared-utils/kyc-prover/vectors_hd_v1/verification_key_v1.bin"
GOLDEN_HD_V1 = "/build/shared-utils/kyc-prover/vectors_hd_v1/golden_vectors_hd_v1.json"


class AssetKycDelegationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.test_run_id = hashlib.sha256(f"{os.getpid()}_{time.time()}_deleg".encode()).hexdigest()[:16]
        # Assets AND delegation active at genesis (delegation defaults to height 0).
        self.extra_args = [["-assetsheight=0"], ["-assetsheight=0"]]
        self.rpc_timeout = 600  # generatezkproof can be slow

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(0, 1)

    # --- helpers (mirrored from feature_assets_basic_highlevel.py) ---
    def fund(self):
        miner, asset_node = self.nodes[1], self.nodes[0]
        miner.getnewaddress()
        self.generate(miner, 110, sync_fun=self.sync_all)
        miner.sendtoaddress(asset_node.getnewaddress(), 85)
        self.generate(miner, 1, sync_fun=self.sync_all)

    def taproot_addr(self, node):
        return node.getnewaddress(address_type="bech32m")

    def chain_separator_hex(self):
        genesis_le = bytes.fromhex(self.nodes[0].getblockhash(0))[::-1]
        tag = b"TensorCash/ZKChainSeparator"
        chain_le = hashlib.sha256(hashlib.sha256(genesis_le + tag).digest()).digest()
        return "0x" + chain_le[::-1].hex()

    def load_canonical_vk(self):
        with open(GOLDEN_HD_V1, "r", encoding="utf-8") as f:
            vk_hex = json.load(f)[0]["vk_hex"]
        return bytes.fromhex(vk_hex[2:] if vk_hex.startswith("0x") else vk_hex)

    def register_kyc_asset(self, issuer, label, vk_data, ticker, compliance_root):
        asset_id = hashlib.sha256(f"{label}_{self.test_run_id}".encode()).hexdigest()
        opts = {
            "kyc_flags": 1,
            "vk_data": vk_data.hex(),
            "max_root_age": 2016,
            "broadcast": True,
        }
        if compliance_root is not None:
            opts["compliance_root"] = compliance_root
        issuer.registerasset(
            self.taproot_addr(issuer), Decimal("5.0"), asset_id,
            0x0011, 28, 500000000, ticker, 8, opts)
        self.generate(self.nodes[0], 1, sync_fun=self.sync_all)
        return asset_id

    def icu_vout_of(self, issuer, txid):
        wtx = issuer.gettransaction(txid, True, True)
        for i, vout in enumerate(wtx["decoded"]["vout"]):
            if Decimal(str(vout["value"])) == Decimal("5.0"):
                return i
        raise AssertionError("ICU output (5.0) not found")

    def run_test(self):
        self.fund()
        issuer = self.nodes[0]
        holder = self.nodes[1]

        if not os.path.exists(GOLDEN_HD_V1) or not os.path.exists(PK_FILE):
            raise AssertionError(f"HDv1 prover artifacts missing ({GOLDEN_HD_V1} / {PK_FILE})")
        vk_data = self.load_canonical_vk()

        # --- A cohort member (the eventual spender of B) ---
        self.log.info("[1] Building A's cohort with one member")
        member = ECKey(); member.generate()
        member_priv = member.get_bytes().hex()
        member_pub = member.get_pubkey().get_bytes().hex()
        cohort = issuer.generatecomplianceroot(
            [{"master_pubkey": member_pub, "country": 840, "age": 35, "index": 0}], "hd_v1")
        root_a = cohort["compliance_root"]
        member_merkle = cohort["identities"][0]["merkle_proof"]

        # Member's HDv1 child key -> import secret so the wallet can sign the B spend.
        hd = issuer.generatehdwitnessdata(
            member_pub, 840, 35, 0, member_merkle,
            {"account": 0, "index": 0, "salt": 11}, root_a, member_priv)
        child_addr = hd["child_address"]
        child_secret = hd["child_secret"]
        assert child_addr.startswith("bcrt1p") and len(child_secret) == 64
        wif = bytes_to_wif(bytes.fromhex(child_secret))
        desc = descsum_create(f"rawtr({wif})")
        assert_equal(issuer.deriveaddresses(desc)[0], child_addr)
        assert issuer.importdescriptors([{
            "desc": desc, "active": False, "timestamp": "now", "internal": False}])[0]["success"]

        # A DISTINCT own root for B (a different cohort). The spend below proves B->A
        # resolution only if B's own root differs from A's: the proof is against A's root.
        other = ECKey(); other.generate()
        root_b = issuer.generatecomplianceroot(
            [{"master_pubkey": other.get_pubkey().get_bytes().hex(), "country": 840, "age": 40, "index": 0}],
            "hd_v1")["compliance_root"]
        root_b = root_b[2:] if root_b.startswith("0x") else root_b
        assert root_b != root_a, "test setup error: roots must differ"

        # --- Register source A (canonical VK + cohort root) and delegating B (canonical VK) ---
        self.log.info("[2] Registering source asset A and delegating asset B (canonical VK)")
        root_a = root_a[2:] if root_a.startswith("0x") else root_a  # RPCs want bare 64-hex
        aid_a = self.register_kyc_asset(issuer, "deleg_A", vk_data, "DELSRC", None)
        aid_b = self.register_kyc_asset(issuer, "deleg_B", vk_data, "DELB", None)

        # The compliance root is zero at registration; set A's cohort root explicitly.
        self.log.info("  Setting A's cohort root")
        issuer.updatecomplianceroot(aid_a, root_a, {"broadcast": True})
        self.generate(self.nodes[0], 1, sync_fun=self.sync_all)

        pol_a = issuer.getassetpolicy(aid_a)
        assert pol_a["has_kyc"], "A must be a KYC asset"
        assert_equal(pol_a.get("compliance_root_commit"), root_a)

        # --- Mint B units to the cohort member's child address ---
        # --- Install B -> A delegation BEFORE minting (issued_total==0 so the
        # core-policy-immutability check is not yet armed). ---
        self.log.info("[3] Installing B -> A delegation (pre-mint)")
        res = issuer.updatecomplianceroot(aid_b, root_a, {"delegate_asset": aid_a, "broadcast": True})
        self.generate(self.nodes[0], 1, sync_fun=self.sync_all)
        deleg_tx = issuer.gettransaction(res["txid"])
        assert deleg_tx.get("confirmations", 0) >= 1, "delegation-install tx did not confirm (guardrails?)"

        pol_b = issuer.getassetpolicy(aid_b)
        assert_equal(pol_b.get("compliance_delegate_asset_id"), aid_a)
        eff = pol_b.get("effective_kyc_policy") or {}
        assert eff.get("ok") is True, f"effective policy not ok: {eff}"
        assert_equal(eff.get("source_asset_id"), aid_a)
        assert_equal(eff.get("vk_commitment"), pol_a["zk_vk_commitment"])
        self.log.info("  B -> A delegation installed; effective policy resolves to A")

        # Negative: self-delegation must be rejected by the RPC.
        try:
            issuer.updatecomplianceroot(aid_b, root_a, {"delegate_asset": aid_b, "broadcast": False})
            raise AssertionError("self-delegation was not rejected")
        except Exception as e:
            assert "cannot be the asset itself" in str(e) or "delegate" in str(e).lower()

        # --- Mint B units to the cohort member's child address ---
        self.log.info("[4] Minting B units to the cohort member's child address")
        pol_b0 = issuer.getassetpolicy(aid_b)  # ICU moved after the delegation rotation
        issuer.mintasset(
            icu_txid=pol_b0["icu_txid"], icu_vout=pol_b0["icu_vout"], icu_address=self.taproot_addr(issuer),
            icu_amount=Decimal("5.0"), asset_address=child_addr, asset_amount_btc=Decimal("0.001"),
            asset_id=aid_b, asset_units=10000, policy_bits=0x0011, allowed_spk_families=28,
            unlock_fees_sats=500000000, options={"broadcast": True})
        self.generate(self.nodes[0], 1, sync_fun=self.sync_all)

        # Give B a DISTINCT own root (root_b != root_a) via rotatezk (a v1 reg that PRESERVES
        # the delegate). This makes the spend conclusive: the proof is against A's root, so it
        # can only pass if consensus resolves B->A — not B's own root.
        pol_b1 = issuer.getassetpolicy(aid_b)
        issuer.rotatezk(
            icu_txid=pol_b1["icu_txid"], icu_vout=pol_b1["icu_vout"],
            icu_address=self.taproot_addr(issuer), asset_id=aid_b,
            options={"compliance_root": root_b, "broadcast": True})
        self.generate(self.nodes[0], 1, sync_fun=self.sync_all)
        pol_b2 = issuer.getassetpolicy(aid_b)
        assert_equal(pol_b2.get("compliance_delegate_asset_id"), aid_a)   # delegate preserved across v1 rotatezk
        assert_equal(pol_b2.get("compliance_root_commit"), root_b)        # B's OWN root is root_b (!= root_a)
        assert_equal((pol_b2.get("effective_kyc_policy") or {}).get("compliance_root_commit"), root_a)  # effective = A's

        # --- Generate a real HDv1 proof for the member, bound to B + A's root ---
        self.log.info("[5] Generating HDv1 proof (asset_id=B, root=A's cohort)")
        proof_root = root_a if root_a.startswith("0x") else "0x" + root_a
        wit = issuer.generatehdwitnessdata(
            member_pub, 840, 35, 0, member_merkle,
            {"account": 0, "index": 0, "salt": 11}, root_a)
        assert wit.get("root_matches", False), f"witness root mismatch: {wit.get('computed_root')}"
        public_inputs = {
            "chain_separator": self.chain_separator_hex(),
            "asset_id": "0x" + aid_b,                       # bound to B (the spending asset)
            "compliance_root": proof_root,                  # A's cohort root
            "tfr_anchor": "0x" + "0" * 64,
            "output_key_high": wit["witness_data"].get("output_key_high", ""),
            "output_key_low": wit["witness_data"].get("output_key_low", ""),
        }
        proof = issuer.generatezkproof(
            aid_b, json.dumps(public_inputs), json.dumps(wit["witness_data"]),
            {"mode": "local", "pk_file": PK_FILE, "vk_file": VK_FILE, "circuit_type": "kyc_hd_v1"})
        self.log.info(f"  proof generated ({len(proof['proof']) // 2} bytes)")

        # --- Spend B with the proof: consensus must resolve B -> A and accept ---
        self.log.info("[6] Spending B using A's cohort proof")
        dest = holder.getnewaddress()
        send = issuer.sendasset(
            aid_b, dest, 1000,
            {"zk_proof": proof["proof"], "zk_public_inputs": proof["public_inputs"], "broadcast": True})
        txid = send["txid"]
        self.generate(self.nodes[0], 1, sync_fun=self.sync_all)
        spend_tx = issuer.gettransaction(txid)
        assert spend_tx.get("confirmations", 0) >= 1, \
            f"delegated spend not confirmed (resolution/verify failed): {txid}"
        bal = holder.getassetbalance([aid_b])
        assert len(bal) > 0 and bal[0]["balance"] == 1000, f"holder did not receive B units: {bal}"
        self.log.info("  ✓ Spent B using A's cohort — delegation resolved B->A end-to-end")

        # --- Opt-out (post-mint): clear_delegation emits a v2-self reg. Also exercises the
        # updatecomplianceroot kyc_flags fix (a post-issuance reg that doesn't trip
        # policy-core-changed). B falls back to its own root_b afterwards. ---
        self.log.info("[7] Opting B out of delegation (clear_delegation, post-mint)")
        issuer.updatecomplianceroot(aid_b, root_b, {"clear_delegation": True, "broadcast": True})
        self.generate(self.nodes[0], 1, sync_fun=self.sync_all)
        pol_b3 = issuer.getassetpolicy(aid_b)
        assert pol_b3.get("compliance_delegate_asset_id") is None, \
            f"delegation not cleared: {pol_b3.get('compliance_delegate_asset_id')}"
        assert "effective_kyc_policy" not in pol_b3, "effective policy should be gone after opt-out"
        assert_equal(pol_b3.get("compliance_root_commit"), root_b)  # back to B's own root
        self.log.info("  ✓ B opted out — delegation cleared, back to own root")


if __name__ == "__main__":
    AssetKycDelegationTest(__file__).main()
