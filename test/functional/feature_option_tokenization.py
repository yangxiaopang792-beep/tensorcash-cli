#!/usr/bin/env python3
# Copyright (c) 2026 The Tensorcash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Functional test for the tokenized option-series RPC surface (Slice C).

Verifies optionseries.derive end-to-end: the RPC reconstructs the FROZEN conformance vectors
(OPTION_SERIES_FREEZE.md §7.2/§7.3) byte-for-byte from the series terms alone. Passing here proves the
RPC plumbing (param parsing, the derivation core, JSON output) agrees with the unit-tested C++ core AND
the independent Python generator — the same vectors asserted in option_series_tests.cpp. Also checks
the writer_key-as-P2TR-address path and the validation / range guards.
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than_or_equal, assert_raises_rpc_error

RPC_INVALID_PARAMETER = -8

# OPTION_SERIES_FREEZE.md §7.1 — frozen example inputs (self-issuance, D1-b).
WRITER_KEY = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
FROZEN_TERMS = {
    "descriptor_version": 1,
    "issuance_mode": 0,
    "leaf_set": 1,
    "writer_key": WRITER_KEY,
    "strike_nbits": 0x1d00ffff,
    "fixing_height": 150000,
    "settle_lock_height": 150100,
    "lambda_q": 218453,
    "lot_im": "30.00000000",
    "lot_count": 100,
    "reference_premium": "500.00000000",
    "series_salt": "1d59c4b99e941c31d184cf90f76bde031aa142ce855c37b9cd887004baf86f52",
}

# §7.2 authoritative + §7.3 reference-impl vectors.
EXPECTED_DESCRIPTOR = (
    "01000179be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ffff001d"
    "f0490200544a020055550300005ed0b2000000006400000000743ba40b0000001d59c4b99e941c"
    "31d184cf90f76bde031aa142ce855c37b9cd887004baf86f52"
)
EXPECTED_ASSET_ID = "c4ed91972ef3014baa1faccc37b7ec80f43cdd4cccf258ec25215371ccd5e96e"
EXPECTED_LOTS = {
    0: {
        "salt": "14ab1739cea05cf202f22d1fc22dd7456be27cb24966419a4e102507f5e6c9ee",
        "contract_id": "389fc5a66f69b6e25bf270a016df6df7dc47383a01f30246d461bebcb18164ab",
        "pot_key": "69ed5b05f5d0cdb286d4bc4d2e605096cd6a381f97f3eb696888fab967f38430",
        "pot_spk": "512069ed5b05f5d0cdb286d4bc4d2e605096cd6a381f97f3eb696888fab967f38430",
        "vault_key": "093d8c9890b6fea0a2517e4015eb03a20f76b0bdedbea310a7c973f6f09c5d63",
        "vault_spk": "5120093d8c9890b6fea0a2517e4015eb03a20f76b0bdedbea310a7c973f6f09c5d63",
        "settle_leaf": (
            "20389fc5a66f69b6e25bf270a016df6df7dc47383a01f30246d461bebcb18164ab7503544a02b175"
            "04f049020004ffff001d04555503005108005ed0b2000000002079be667ef9dcbbac55a06295ce8"
            "70b07029bfcdb2dce28d959f2815b16f817982069ed5b05f5d0cdb286d4bc4d2e605096cd6a381f9"
            "7f3eb696888fab967f38430be"
        ),
        "buyback_leaf": (
            "2079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ad20a5dbb5b6b8"
            "05513f5560039ece27508611dd730de9fb6751b66b12a308ccb5f620c4ed91972ef3014baa1facc"
            "c37b7ec80f43cdd4cccf258ec25215371ccd5e96e080100000000000000b8"
        ),
    },
    1: {
        "salt": "bb81c9b301ba11646171086ec9ffe45865248357d1d6368c96883a245d2a1351",
        "contract_id": "bc77e3a30d25447763d3edaff6085f17b3ede6617ebaf6824374cae658aff7da",
        "pot_key": "da278d5b096e0723a5bdb2d2ff6b06541842b11c4ccb3e8302f0e446b7f16445",
        "pot_spk": "5120da278d5b096e0723a5bdb2d2ff6b06541842b11c4ccb3e8302f0e446b7f16445",
        "vault_key": "eea7f03826175f675450c3c73f3ec70f3ff3de65d02522d404386546fc9240d4",
        "vault_spk": "5120eea7f03826175f675450c3c73f3ec70f3ff3de65d02522d404386546fc9240d4",
        "settle_leaf": (
            "20bc77e3a30d25447763d3edaff6085f17b3ede6617ebaf6824374cae658aff7da7503544a02b175"
            "04f049020004ffff001d04555503005108005ed0b2000000002079be667ef9dcbbac55a06295ce8"
            "70b07029bfcdb2dce28d959f2815b16f8179820da278d5b096e0723a5bdb2d2ff6b06541842b11c4"
            "ccb3e8302f0e446b7f16445be"
        ),
        "buyback_leaf": (
            "2079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ad20c15e239f14"
            "44c75a12771b7583dbe54fc387d55e395ed4ca6ad4e42c4f10e9cf20c4ed91972ef3014baa1facc"
            "c37b7ec80f43cdd4cccf258ec25215371ccd5e96e080100000000000000b8"
        ),
    },
    99: {
        "salt": "da643369b580f9d917b0226a689f3288ad733cdbcbed1b4f4faafc5d2f06b650",
        "contract_id": "572c312ea94c9c149dcef0f05ee8f08a6c0008f63e5434a96a799c6c4693c751",
        "pot_key": "3b6d50918405d27a02077b04b081f1fab3ef82126d9a97669feb16f30e587b99",
        "pot_spk": "51203b6d50918405d27a02077b04b081f1fab3ef82126d9a97669feb16f30e587b99",
        "vault_key": "0186e24f412829f8b3515551919b1c7c356c9d59ecb3bad9546267f265734051",
        "vault_spk": "51200186e24f412829f8b3515551919b1c7c356c9d59ecb3bad9546267f265734051",
        "settle_leaf": (
            "20572c312ea94c9c149dcef0f05ee8f08a6c0008f63e5434a96a799c6c4693c7517503544a02b175"
            "04f049020004ffff001d04555503005108005ed0b2000000002079be667ef9dcbbac55a06295ce8"
            "70b07029bfcdb2dce28d959f2815b16f81798203b6d50918405d27a02077b04b081f1fab3ef8212"
            "6d9a97669feb16f30e587b99be"
        ),
        "buyback_leaf": (
            "2079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ad206ad381444f"
            "cdc62675b94f1b0c38d20ff7f7fe40012c64bc387c1b4682b68af820c4ed91972ef3014baa1facc"
            "c37b7ec80f43cdd4cccf258ec25215371ccd5e96e080100000000000000b8"
        ),
    },
}


class OptionSeriesRpcTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        # node[0] runs the wallet-only build_register; node[1] has NO wallet at all, proving
        # optionseries.derive / verify are core RPCs that work on any node.
        self.extra_args = [[], ["-disablewallet"]]
        # Skip the framework's automatic per-node wallet init: node[0] creates "ots" in run_test,
        # node[1] is -disablewallet (no wallet RPCs at all).
        self.wallet_names = [False, False]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        # The derive/verify path runs on the -disablewallet node: it has no wallet RPCs at all, so if
        # these work there, the buyer-side "any node, no wallet" claim is true.
        node = self.nodes[1]
        assert_raises_rpc_error(-32601, "Method not found", node.getwalletinfo)

        self.log.info("optionseries.derive reproduces the frozen §7.2/§7.3 conformance vectors")
        res = node.optionseries.derive(FROZEN_TERMS, [0, 1, 99])
        assert_equal(res["asset_id"], EXPECTED_ASSET_ID)
        assert_equal(res["descriptor"], EXPECTED_DESCRIPTOR)
        assert_equal(res["lot_count"], 100)
        assert_equal(len(res["lots"]), 3)
        for lot in res["lots"]:
            expected = EXPECTED_LOTS[lot["index"]]
            for field, value in expected.items():
                assert_equal(lot[field], value)

        self.log.info("omitting `lots` returns asset_id + descriptor only (no lot derivation)")
        res_min = node.optionseries.derive(FROZEN_TERMS)
        assert_equal(res_min["asset_id"], EXPECTED_ASSET_ID)
        assert_equal(res_min["descriptor"], EXPECTED_DESCRIPTOR)
        assert_equal(res_min["lots"], [])

        self.log.info("writer_key accepted as a P2TR (bech32m) address -> same x-only -> same series")
        desc = node.getdescriptorinfo(f"rawtr({WRITER_KEY})")["descriptor"]
        writer_addr = node.deriveaddresses(desc)[0]
        res_addr = node.optionseries.derive({**FROZEN_TERMS, "writer_key": writer_addr}, [0])
        assert_equal(res_addr["asset_id"], EXPECTED_ASSET_ID)
        assert_equal(res_addr["lots"][0]["vault_spk"], EXPECTED_LOTS[0]["vault_spk"])

        self.log.info("CLI path: bitcoin-cli converts the JSON object/array args (client.cpp table)")
        cli = self.nodes[1].cli  # no -rpcwallet: core RPC on the -disablewallet node
        cli_res = getattr(cli, "optionseries.derive")(FROZEN_TERMS, [0, 99])
        assert_equal(cli_res["asset_id"], EXPECTED_ASSET_ID)
        assert_equal(cli_res["lots"][0]["vault_spk"], EXPECTED_LOTS[0]["vault_spk"])
        assert_equal(cli_res["lots"][1]["vault_key"], EXPECTED_LOTS[99]["vault_key"])

        self.log.info("validation + range guards reject malformed terms")
        # CLTV before fixing + maturity.
        bad_cltv = {**FROZEN_TERMS, "settle_lock_height": FROZEN_TERMS["fixing_height"]}
        assert_raises_rpc_error(RPC_INVALID_PARAMETER, "Invalid option series terms",
                                lambda: node.optionseries.derive(bad_cltv))
        # Zero leverage.
        bad_lambda = {**FROZEN_TERMS, "lambda_q": 0}
        assert_raises_rpc_error(RPC_INVALID_PARAMETER, "Invalid option series terms",
                                lambda: node.optionseries.derive(bad_lambda))
        # Lot index >= lot_count.
        assert_raises_rpc_error(RPC_INVALID_PARAMETER, "out of range",
                                lambda: node.optionseries.derive(FROZEN_TERMS, [100]))
        # Missing required field.
        no_salt = {k: v for k, v in FROZEN_TERMS.items() if k != "series_salt"}
        assert_raises_rpc_error(RPC_INVALID_PARAMETER, "series_salt is required",
                                lambda: node.optionseries.derive(no_salt))
        # u8 fields must NOT silently wrap: 257 must error, not pass as 1.
        wrap_version = {**FROZEN_TERMS, "descriptor_version": 257}
        assert_raises_rpc_error(RPC_INVALID_PARAMETER, "descriptor_version out of uint8 range",
                                lambda: node.optionseries.derive(wrap_version))
        wrap_mode = {**FROZEN_TERMS, "issuance_mode": 256}
        assert_raises_rpc_error(RPC_INVALID_PARAMETER, "issuance_mode out of uint8 range",
                                lambda: node.optionseries.derive(wrap_mode))

        self.log.info("optionseries.verify: pre-purchase fraud check (authentic / fraud / sources)")
        # Authentic via the published descriptor.
        v = node.optionseries.verify(EXPECTED_ASSET_ID, {"descriptor": EXPECTED_DESCRIPTOR})
        assert_equal(v["authentic"], True)
        assert_equal(v["terms_valid"], True)
        assert_equal(v["recomputed_asset_id"], EXPECTED_ASSET_ID)
        assert_equal(v["reason"], "")
        assert_equal(v["backing"]["lot_count"], 100)
        assert_equal(v["backing"]["per_lot_im_sats"], 3000000000)
        assert_equal(v["backing"]["total_collateral_sats"], 100 * 3000000000)
        # Authentic via the terms object (serializes to the same descriptor).
        assert_equal(node.optionseries.verify(EXPECTED_ASSET_ID, {"terms": FROZEN_TERMS})["authentic"], True)
        # Wrong asset_id -> not authentic (the terms are not for this asset).
        wrong_id = "00" + EXPECTED_ASSET_ID[2:]
        v_wrong = node.optionseries.verify(wrong_id, {"descriptor": EXPECTED_DESCRIPTOR})
        assert_equal(v_wrong["authentic"], False)
        assert "do not match" in v_wrong["reason"]
        # Tampered descriptor (flip the last byte) -> different recomputed id -> FRAUD detected.
        tampered = EXPECTED_DESCRIPTOR[:-2] + ("00" if EXPECTED_DESCRIPTOR[-2:] != "00" else "11")
        assert_equal(node.optionseries.verify(EXPECTED_ASSET_ID, {"descriptor": tampered})["authentic"], False)
        # Exactly one source must be supplied.
        assert_raises_rpc_error(RPC_INVALID_PARAMETER, "exactly one of",
                                lambda: node.optionseries.verify(EXPECTED_ASSET_ID,
                                                                 {"descriptor": EXPECTED_DESCRIPTOR, "terms": FROZEN_TERMS}))
        # Malformed descriptor source -> clear parameter error, not authentic:false.
        assert_raises_rpc_error(RPC_INVALID_PARAMETER, "not a valid option-series descriptor",
                                lambda: node.optionseries.verify(EXPECTED_ASSET_ID, {"descriptor": "00"}))

        self.log.info("optionseries.verify: ICU metadata band is identity- and canonical-checked")
        md = res["icu_metadata"]  # canonical TSC-ICU-META-1 bytes straight from derive
        v_md = node.optionseries.verify(EXPECTED_ASSET_ID, {"icu_metadata": md})
        assert_equal(v_md["authentic"], True)
        assert_equal(v_md["terms_valid"], True)
        md_json = bytes.fromhex(md).decode()
        # Wrong container spec (still canonical JSON, but not the option-series band) -> rejected.
        bad_spec = md_json.replace('"TSC-ICU-META-1"', '"TSC-ICU-BOGUS-1"').encode().hex()
        assert_raises_rpc_error(RPC_INVALID_PARAMETER, "spec is not TSC-ICU-META-1",
                                lambda: node.optionseries.verify(EXPECTED_ASSET_ID, {"icu_metadata": bad_spec}))
        # Non-canonical JSON (injected whitespace) -> rejected: not the committed on-chain bytes.
        noncanon = md_json.replace("{", "{ ", 1).encode().hex()
        assert_raises_rpc_error(RPC_INVALID_PARAMETER, "not in canonical form",
                                lambda: node.optionseries.verify(EXPECTED_ASSET_ID, {"icu_metadata": noncanon}))
        # Malformed descriptor inside the band -> clear parameter error.
        bad_desc = md_json.replace(EXPECTED_DESCRIPTOR, "00").encode().hex()
        assert_raises_rpc_error(RPC_INVALID_PARAMETER, "not a valid option-series descriptor",
                                lambda: node.optionseries.verify(EXPECTED_ASSET_ID, {"icu_metadata": bad_desc}))

        self.log.info("create a parent root namespace; option series themselves must be sponsored children")
        wnode = self.nodes[0]  # the wallet-capable node
        wnode.createwallet(wallet_name="ots")
        wallet = wnode.get_wallet_rpc("ots")
        self.generatetoaddress(wnode, 110, wallet.getnewaddress())  # mature coinbase for the ICU bond

        parent_root = "ACME"
        parent_id = "11" * 32
        wallet.registerasset(
            wallet.getnewaddress("", "bech32m"),
            5.1,
            parent_id,
            1,      # MINT_ALLOWED is enough for a namespace root in this test
            28,
            510000000,
            parent_root,
            0,
            {"autofund": True, "broadcast": True},
        )
        self.generatetoaddress(wnode, 1, wallet.getnewaddress())
        assert_equal(wnode.getassetpolicy(parent_root)["asset_id"], parent_id)

        self.log.info("optionseries.build_register registers a sponsored child under series_id with the §2.5 invariants")
        assert_raises_rpc_error(RPC_INVALID_PARAMETER, "root must be an existing root ticker",
                                lambda: wallet.optionseries.build_register(FROZEN_TERMS, parent_id, "optbad", {}))
        # No icu_address arg: the child ICU destination is derived from terms.writer_key (§2.5). A lowercase
        # suffix exercises sponsorchildasset uppercase-normalization.
        reg = wallet.optionseries.build_register(FROZEN_TERMS, parent_root, "optacme", {"broadcast": True})
        assert_equal(reg["asset_id"], EXPECTED_ASSET_ID)       # option-series canonical (== descriptor hash)
        assert_equal(reg["ticker"], f"{parent_root}.OPTACME")  # normalized child ticker
        assert_equal(reg["issuance_cap_units"], 100)
        assert "Strike nBits: 486604799" in reg["icu_text"]
        assert "Lots: 100" in reg["icu_text"]
        assert "Reference premium: 500.00 TSC" in reg["icu_text"]  # FormatMoney right-trims trailing zeros
        # The registry stores/looks up the SAME 32 bytes under its reverse-hex display convention.
        REG_ID = reg["registry_asset_id"]
        assert_equal(bytes.fromhex(REG_ID)[::-1].hex(), EXPECTED_ASSET_ID)  # same bytes, reversed hex
        self.generatetoaddress(wnode, 1, wallet.getnewaddress())

        info = wnode.getassetinfo(REG_ID)
        assert_equal(info["asset_id"], REG_ID)
        assert_equal(info["decimals"], 0)
        assert_equal(info["ticker"], f"{parent_root}.OPTACME")

        pol = wnode.getassetpolicy(REG_ID)
        assert_equal(pol["policy_bits"] & 0x1, 0x1)   # MINT_ALLOWED set
        assert_equal(pol["policy_bits"] & 0x2, 0)     # BURN_ALLOWED clear
        assert_equal(pol["issuance_cap_units"], 100)  # cap = N
        assert_equal(pol["policy_quorum_bps"], 0)     # immutable governance
        assert_equal(pol["issued_total"], 0)          # registered, not yet issued
        assert_equal(pol["icu_visibility"], 0)        # public ICU (band is verifiable)

        # Prove the band is COMMITTED ON CHAIN: fetch the ICU payload, its metadata must equal the
        # band the wrapper returned, and verifying with the FETCHED bytes is authentic.
        icu = wallet.geticupayload(REG_ID)
        assert_equal(icu["decrypted"], True)
        assert_equal(icu["metadata"], reg["icu_metadata"])
        v_chain = wnode.optionseries.verify(EXPECTED_ASSET_ID, {"icu_metadata": icu["metadata"]})
        assert_equal(v_chain["authentic"], True)
        assert_equal(v_chain["registry_asset_id"], REG_ID)
        # A buyer who copied the REGISTRY/display id (from getassetinfo or a market listing) verifies
        # just as well — same 32 bytes, either hex convention is accepted.
        assert_equal(wnode.optionseries.verify(REG_ID, {"icu_metadata": icu["metadata"]})["authentic"], True)

        self.log.info("optionseries.build_issue mints N units + funds N vaults (small issuable series)")
        # The frozen series' writer (G.x) is registrable but not wallet-signable. For the issuance
        # lifecycle use a fresh WALLET-OWNED taproot key as the writer, so the wallet can sign the ICU
        # spend at issuance. Small N + lot_im keeps collateral trivially fundable.
        issuer_addr = wallet.getnewaddress("", "bech32m")
        issuer_xonly = wallet.getaddressinfo(issuer_addr)["witness_program"]
        issue_terms = {
            "writer_key": issuer_xonly,
            "strike_nbits": 0x1d00ffff,
            "fixing_height": 150000,
            "settle_lock_height": 150100,
            "lambda_q": 218453,
            "lot_im": "1.00000000",
            "lot_count": 4,
            "reference_premium": "10.00000000",
            "series_salt": "2a" * 32,
        }
        issue_derived = wnode.optionseries.derive(issue_terms)
        ISSUE_ASSET = issue_derived["asset_id"]
        ISSUE_MD = issue_derived["icu_metadata"]

        # Negative: build_issue before the series is registered -> rejected (no mempool chaining).
        assert_raises_rpc_error(RPC_INVALID_PARAMETER, "not registered",
                                lambda: wallet.optionseries.build_issue(issue_terms, {}))

        # Register the small series and confirm.
        reg_issue = wallet.optionseries.build_register(issue_terms, parent_root, "optissue", {"broadcast": True})
        assert_equal(reg_issue["ticker"], f"{parent_root}.OPTISSUE")
        ISSUE_REG_ID = reg_issue["registry_asset_id"]   # registry-convention id for getasset*/geticupayload
        self.generatetoaddress(wnode, 1, wallet.getnewaddress())

        # Negative: too-large lot_count is rejected BEFORE funding (output-cap preflight).
        too_big = {**issue_terms, "lot_count": 200}
        assert_raises_rpc_error(RPC_INVALID_PARAMETER, "too large",
                                lambda: wallet.optionseries.build_issue(too_big, {}))
        # Negative: an unregistered (different-salt) series -> rejected.
        unreg = {**issue_terms, "series_salt": "3b" * 32}
        assert_raises_rpc_error(RPC_INVALID_PARAMETER, "not registered",
                                lambda: wallet.optionseries.build_issue(unreg, {}))

        # Snapshot the registration shell BEFORE issuance (must be unchanged except supply + ICU).
        pol_before = wnode.getassetpolicy(ISSUE_REG_ID)
        icu_ctxt_before = wallet.geticupayload(ISSUE_REG_ID)["icu_ctxt_commit"]

        iss = wallet.optionseries.build_issue(issue_terms, {"broadcast": True})
        assert_equal(iss["asset_id"], ISSUE_ASSET)
        assert_equal(iss["lot_count"], 4)
        assert_equal(len(iss["vault_spks"]), 4)
        issue_txid = iss["mint"]
        self.generatetoaddress(wnode, 1, wallet.getnewaddress())

        # NON-NEGOTIABLE: the minted AssetTag carries series_id byte-for-byte (== what the vault
        # covenants embed), so the units and the vaults reference the SAME 32 bytes. Decode the issuance
        # tx and read the raw AssetTag bytes from the asset output's `outext` (vExt = 01|len|id32|amt8|flags4).
        raw = wallet.gettransaction(issue_txid)["hex"]
        dec = wnode.decoderawtransaction(raw)
        asset_vouts = [v for v in dec["vout"] if v.get("outext", "").startswith("01")]
        assert_equal(len(asset_vouts), 1)
        ext = asset_vouts[0]["outext"]
        assert_equal(ext[4:4 + 64], ISSUE_ASSET)                       # minted asset_id == ComputeOptionSeriesId(terms)
        minted_units = int.from_bytes(bytes.fromhex(ext[4 + 64:4 + 64 + 16]), "little")
        assert_equal(minted_units, 4)                                  # exactly N units
        assert_equal(asset_vouts[0]["scriptPubKey"]["address"], issuer_addr)  # to the writer

        # issued_total == N, cap unchanged, and the registration shell is otherwise immutable.
        pol2 = wnode.getassetpolicy(ISSUE_REG_ID)
        assert_equal(pol2["issued_total"], 4)
        assert_equal(pol2["issuance_cap_units"], 4)
        for field in ("policy_bits", "allowed_spk_families", "policy_quorum_bps", "icu_visibility",
                      "decimals", "ticker", "core_policy_commit"):
            assert_equal(pol2.get(field), pol_before.get(field))

        # ICU commit unchanged + the band still verifies (commit-continuity preserved it through mint).
        icu_after = wallet.geticupayload(ISSUE_REG_ID)
        assert_equal(icu_after["icu_ctxt_commit"], icu_ctxt_before)
        assert_equal(icu_after["metadata"], ISSUE_MD)
        assert_equal(wnode.optionseries.verify(ISSUE_ASSET, {"icu_metadata": icu_after["metadata"]})["authentic"], True)

        # Every derived vault SPK is funded with exactly lot_im_sats (the backing is real).
        scan = wnode.scantxoutset("start", [f"raw({spk})" for spk in iss["vault_spks"]])
        assert_equal(len(scan["unspents"]), 4)
        lot_im_btc = Decimal(issue_terms["lot_im"])
        for u in scan["unspents"]:
            assert_equal(u["amount"], lot_im_btc)
        assert_equal(scan["total_amount"], lot_im_btc * 4)

        # Negative: issuing an already-issued series -> rejected (issued_total != 0).
        assert_raises_rpc_error(RPC_INVALID_PARAMETER, "already issued",
                                lambda: wallet.optionseries.build_issue(issue_terms, {}))

        self.log.info("optionseries.verify check_backing scans the UTXO set on ANY node (backing half live)")
        self.sync_blocks()  # the cold node must have the issuance block to scan it
        # Run it on the -disablewallet node: cold buyer/auditor confirms the backing with no wallet.
        vb = node.optionseries.verify(ISSUE_ASSET, {"terms": issue_terms}, {"check_backing": True})
        assert_equal(vb["authentic"], True)
        oc = vb["backing"]["on_chain"]
        assert_equal(oc["registered"], True)
        assert_equal(oc["issued_total"], 4)
        assert_equal(oc["invariants_ok"], True)   # decimals0 / MINT / no-BURN / quorum0 / public ICU / P2TR
        assert_equal(oc["vaults_funded"], 4)
        assert_equal(oc["vaults_expected"], 4)
        assert_equal(oc["verified"], True)
        # An unissued (registered-only) series scans as not-yet-backed: vaults_funded 0, verified False.
        vb_un = node.optionseries.verify(EXPECTED_ASSET_ID, {"terms": FROZEN_TERMS}, {"check_backing": True})
        assert_equal(vb_un["backing"]["on_chain"]["issued_total"], 0)
        assert_equal(vb_un["backing"]["on_chain"]["verified"], False)
        # A WRONG asset_id with valid terms for a REAL, backed series -> verified is gated on authentic.
        wrong_id = "00" + ISSUE_ASSET[2:]
        vb_wrong = node.optionseries.verify(wrong_id, {"terms": issue_terms}, {"check_backing": True})
        assert_equal(vb_wrong["authentic"], False)
        assert_equal(vb_wrong["backing"]["on_chain"]["vaults_funded"], 4)   # the descriptor's series IS backed
        assert_equal(vb_wrong["backing"]["on_chain"]["verified"], False)    # but the caller's id doesn't match it

        self.log.info("optionseries.record_issue persists the series + resolved vault outpoints")
        rec = wallet.optionseries.record_issue(issue_terms, issue_txid)
        assert_equal(rec["asset_id"], ISSUE_ASSET)
        assert_equal(rec["lot_count"], 4)
        assert_equal(len(rec["lot_vaults"]), 4)
        for op in rec["lot_vaults"]:
            assert op.startswith(issue_txid + ":")          # each vault is an output of the issue tx
        assert rec["icu_outpoint"].startswith(issue_txid + ":")
        assert_equal(rec["persisted"], True)
        # optionseries.list reads the in-memory series map.
        assert any(s["asset_id"] == ISSUE_ASSET for s in wallet.optionseries.list())
        # PROVE the load hook: after a reload, list (which reads the map repopulated from disk) must
        # still contain the record — without re-recording it from chain.
        wnode.unloadwallet("ots")
        wnode.loadwallet("ots")
        wallet = wnode.get_wallet_rpc("ots")
        listed = wallet.optionseries.list()
        loaded = [s for s in listed if s["asset_id"] == ISSUE_ASSET]
        assert_equal(len(loaded), 1)
        assert_equal(loaded[0]["lot_count"], 4)
        assert_equal(loaded[0]["issue_txid"], issue_txid)
        assert_equal(len(loaded[0]["lot_vaults"]), 4)
        # Re-recording is idempotent (RegisterOptionSeries is insert-or-assign).
        assert_equal(wallet.optionseries.record_issue(issue_terms, issue_txid)["persisted"], True)

        # The Qt "Verify backing" button drives exactly this sequence: list -> geticupayload(metadata) ->
        # verify(asset_id, {icu_metadata}, {check_backing}). Lock that combination in (source=icu_metadata
        # AND a backing scan in one call), since the GUI verifies against what is PUBLISHED on chain.
        gui_entry = next(s for s in loaded if s["asset_id"] == ISSUE_ASSET)
        gui_md = wallet.geticupayload(gui_entry["registry_asset_id"])["metadata"]
        gui_vb = wallet.optionseries.verify(ISSUE_ASSET, {"icu_metadata": gui_md}, {"check_backing": True})
        assert_equal(gui_vb["authentic"], True)
        gui_oc = gui_vb["backing"]["on_chain"]
        assert_equal(gui_oc["invariants_ok"], True)
        assert_equal(gui_oc["vaults_funded"], 4)
        assert_equal(gui_oc["vaults_expected"], 4)
        assert_equal(gui_oc["verified"], True)

        # Qt "Verify Option" tab (holder pre-purchase fraud check) drives this from a wallet that has NO
        # record of the series: getassetinfo(ticker)->registry id -> geticupayload(metadata) -> verify by the
        # registry/display id with check_backing. Proves a BUYER can confirm authenticity + backing pre-buy.
        wnode.createwallet(wallet_name="buyer")
        buyer = wnode.get_wallet_rpc("buyer")
        assert_equal(buyer.optionseries.list(), [])                       # buyer never recorded it
        buy_ticker = buyer.getassetinfo(ISSUE_REG_ID)["ticker"]
        buy_id = buyer.getassetinfo(buy_ticker)["asset_id"]              # ticker -> registry id
        assert_equal(buy_id, ISSUE_REG_ID)
        buy_md = buyer.geticupayload(buy_id)["metadata"]
        buy_vb = buyer.optionseries.verify(buy_id, {"icu_metadata": buy_md}, {"check_backing": True})
        assert_equal(buy_vb["authentic"], True)                          # verify accepts the registry-form id
        assert_equal(buy_vb["backing"]["on_chain"]["verified"], True)
        # The canonical option asset_id is the byte-reverse of the registry id; the Verify tab's resolver
        # falls back to reversing a 64-hex input, so a buyer can paste EITHER id and still resolve the series.
        assert_equal(bytes.fromhex(ISSUE_ASSET)[::-1].hex(), ISSUE_REG_ID)
        assert_equal(buyer.getassetinfo(ISSUE_REG_ID)["asset_id"], ISSUE_REG_ID)  # registry-hex resolves directly

        # Negative: record_issue before issuance -> rejected (issued_total != N).
        unissued = {**issue_terms, "series_salt": "4c" * 32}
        wallet.optionseries.build_register(unissued, parent_root, "optnope", {"broadcast": True})
        self.generatetoaddress(wnode, 1, wallet.getnewaddress())
        assert_raises_rpc_error(RPC_INVALID_PARAMETER, "not fully issued",
                                lambda: wallet.optionseries.record_issue(unissued, issue_txid))

        self.log.info("optionseries.build_settlement settles a lot vault through the OP_DIFFCFD_SETTLE covenant")
        # A series whose fixing height we can bury: register/issue/record now, then mine past the
        # fixing burial (DIFFCFD_MATURITY_DEPTH=100) and the settle-lock CLTV.
        h0 = wnode.getblockcount()
        settle_writer = wallet.getaddressinfo(wallet.getnewaddress("", "bech32m"))["witness_program"]
        settle_terms = {
            "writer_key": settle_writer,
            "strike_nbits": 0x1d00ffff,
            "fixing_height": h0 + 8,
            "settle_lock_height": h0 + 8 + 110,
            "lambda_q": 218453,
            "lot_im": "2.00000000",
            "lot_count": 2,
            "reference_premium": "5.00000000",
            "series_salt": "5d" * 32,
        }
        s_reg = wallet.optionseries.build_register(settle_terms, parent_root, "optsettle", {"broadcast": True})
        S_REG_ID = s_reg["registry_asset_id"]
        self.generatetoaddress(wnode, 1, wallet.getnewaddress())
        s_iss = wallet.optionseries.build_issue(settle_terms, {"broadcast": True})
        s_issue_txid = s_iss["mint"]
        self.generatetoaddress(wnode, 1, wallet.getnewaddress())
        s_rec = wallet.optionseries.record_issue(settle_terms, s_issue_txid)
        vault0_txid, vault0_vout = s_rec["lot_vaults"][0].split(":")

        # Negative: settling before the fixing height is buried -> rejected.
        assert_raises_rpc_error(RPC_INVALID_PARAMETER, "not yet buried",
                                lambda: wallet.optionseries.build_settlement(settle_terms, 0))

        # Negative: fixing buried (tip > fixing+100) BUT the settle-lock CLTV not yet reached -> rejected.
        self.generatetoaddress(wnode, (h0 + 8 + 105) - wnode.getblockcount(), wallet.getnewaddress())
        assert_raises_rpc_error(RPC_INVALID_PARAMETER, "CLTV is not open",
                                lambda: wallet.optionseries.build_settlement(settle_terms, 0))

        # A FRESH KEEPER wallet that never issued and has no series record settles the option — proving
        # settlement is trustless/keeper-driven (signatureless vault; the keeper only funds its own fee).
        wnode.createwallet(wallet_name="keeper")
        keeper = wnode.get_wallet_rpc("keeper")
        wallet.sendtoaddress(keeper.getnewaddress(), 5)   # the keeper's only coins (for the fee)
        self.generatetoaddress(wnode, 1, wallet.getnewaddress())
        assert_equal(keeper.optionseries.list(), [])      # keeper has no record of this series

        # Mine past the settle-lock CLTV + fixing burial, then settle lot 0 FROM THE KEEPER.
        self.generatetoaddress(wnode, (h0 + 8 + 110 + 5) - wnode.getblockcount(), wallet.getnewaddress())
        vault0_op = s_rec["lot_vaults"][0]                # public outpoint (e.g. from the issuer / a scan)
        built = keeper.optionseries.build_settlement(settle_terms, 0, {"vault_outpoint": vault0_op})
        processed = keeper.walletprocesspsbt(built["psbt"])   # keeper signs ONLY its own fee input
        extracted = keeper.difficulty.finalize_settlement(processed["psbt"])
        settle_txid = wnode.sendrawtransaction(extracted["hex"])
        self.generatetoaddress(wnode, 1, wallet.getnewaddress())
        # The vault is spent by the settlement (the covenant validated through ConnectBlock).
        assert_equal(wnode.gettxout(vault0_txid, int(vault0_vout)), None)
        assert_greater_than_or_equal(keeper.gettransaction(settle_txid)["confirmations"], 1)
        # If ITM, the payout landed at the derived lot-0 pot (so a holder can later redeem against it).
        if Decimal(built["payout_pot"]) > 0:
            pot0_spk = wnode.optionseries.derive(settle_terms, [0])["lots"][0]["pot_spk"]
            pot_scan = wnode.scantxoutset("start", [f"raw({pot0_spk})"])
            assert_greater_than_or_equal(len(pot_scan["unspents"]), 1)

        self.log.info("optionseries.build_redeem retires one unit per pot and sweeps the pot to the holder")
        # A small issuable series whose units the issuing wallet holds (writer == a wallet key). On regtest
        # the realized target sits at powLimit (the ceiling), so a short-leg vault can never settle ITM; we
        # therefore fund the lot pots DIRECTLY (the redemption covenant only constrains the tx outputs, not
        # how the pot was funded), which is a deterministic stand-in for an ITM settlement payout.
        redeem_writer = wallet.getaddressinfo(wallet.getnewaddress("", "bech32m"))["witness_program"]
        redeem_terms = {
            "writer_key": redeem_writer,
            "strike_nbits": 0x1d00ffff,
            "fixing_height": 150000,
            "settle_lock_height": 150100,
            "lambda_q": 218453,
            "lot_im": "1.00000000",
            "lot_count": 3,
            "reference_premium": "2.00000000",
            "series_salt": "7e" * 32,
        }
        wallet.optionseries.build_register(redeem_terms, parent_root, "optredeem", {"broadcast": True})
        self.generatetoaddress(wnode, 1, wallet.getnewaddress())
        r_iss = wallet.optionseries.build_issue(redeem_terms, {"broadcast": True})  # mints 3 units to the writer (this wallet)
        self.generatetoaddress(wnode, 1, wallet.getnewaddress())
        wallet.optionseries.record_issue(redeem_terms, r_iss["mint"])

        derived = wnode.optionseries.derive(redeem_terms, [0, 1])
        lot0, lot1 = derived["lots"][0], derived["lots"][1]

        def fund_pot(pot_spk, amount):
            """Send native value to a lot pot address (an ITM-payout stand-in) and return its outpoint."""
            addr = wnode.decodescript(pot_spk)["address"]
            txid = wallet.sendtoaddress(addr, amount)
            self.generatetoaddress(wnode, 1, wallet.getnewaddress())
            dec = wnode.decoderawtransaction(wallet.gettransaction(txid)["hex"])
            vout = next(v["n"] for v in dec["vout"] if v["scriptPubKey"]["hex"] == pot_spk)
            return f"{txid}:{vout}"

        pot0a = fund_pot(lot0["pot_spk"], Decimal("1.50000000"))
        pot0b = fund_pot(lot0["pot_spk"], Decimal("0.80000000"))  # a second UTXO at lot 0's pot (same spk)
        pot1 = fund_pot(lot1["pot_spk"], Decimal("0.70000000"))

        # --- 8 guard cases before the happy path ---
        # (1) wrong lot index: out of [0, lot_count).
        assert_raises_rpc_error(RPC_INVALID_PARAMETER, "out of range",
                                lambda: wallet.optionseries.build_redeem(redeem_terms, [{"lot_index": 99, "pot": pot0a}]))
        # (2) wrong pot: lot 1's pot claimed for lot 0 -> the builder re-derives lot 0 and rejects it.
        assert_raises_rpc_error(RPC_INVALID_PARAMETER, "does not match the derived lot pot",
                                lambda: wallet.optionseries.build_redeem(redeem_terms, [{"lot_index": 0, "pot": pot1}]))
        # (3) duplicate lot index (two distinct pot UTXOs, same lot).
        assert_raises_rpc_error(RPC_INVALID_PARAMETER, "duplicate lot_index",
                                lambda: wallet.optionseries.build_redeem(
                                    redeem_terms, [{"lot_index": 0, "pot": pot0a}, {"lot_index": 0, "pot": pot0b}]))
        # (4) duplicate outpoint (same pot UTXO under two lots).
        assert_raises_rpc_error(RPC_INVALID_PARAMETER, "duplicate pot outpoint",
                                lambda: wallet.optionseries.build_redeem(
                                    redeem_terms, [{"lot_index": 0, "pot": pot0a}, {"lot_index": 1, "pot": pot0a}]))
        # (5) a missing/spent pot outpoint is rejected.
        assert_raises_rpc_error(RPC_INVALID_PARAMETER, "missing or already spent",
                                lambda: wallet.optionseries.build_redeem(
                                    redeem_terms, [{"lot_index": 0, "pot": f"{'00'*32}:0"}]))
        # (6) insufficient units / no matching token: the keeper holds native but ZERO units of this series.
        assert_raises_rpc_error(-6, "option units",
                                lambda: keeper.optionseries.build_redeem(redeem_terms, [{"lot_index": 0, "pot": pot0a}]))
        # (7) a malformed pot string is rejected.
        assert_raises_rpc_error(RPC_INVALID_PARAMETER, "txid:vout",
                                lambda: wallet.optionseries.build_redeem(redeem_terms, [{"lot_index": 0, "pot": "not-an-outpoint"}]))
        # (8) empty pots list.
        assert_raises_rpc_error(RPC_INVALID_PARAMETER, "at least one pot",
                                lambda: wallet.optionseries.build_redeem(redeem_terms, []))

        # --- happy path: redeem lot 0 against pot0a ---
        redeem = wallet.optionseries.build_redeem(redeem_terms, [{"lot_index": 0, "pot": pot0a}], {"broadcast": True})
        assert_equal(redeem["units_retired"], 1)
        assert_equal(redeem["token_change_units"], 2)              # 3 minted - 1 retired
        assert_equal(redeem["redeemed_lots"], [0])
        assert_equal(redeem["inputs"]["pots"], 1)
        assert_greater_than_or_equal(Decimal(redeem["native_sweep"]), Decimal("1.49"))  # ~1.5 BTC pot minus fee/dust
        self.generatetoaddress(wnode, 1, wallet.getnewaddress())

        # The pot is spent; the sink received EXACTLY one unit; the holder got 2 units of change.
        pot0a_txid, pot0a_vout = pot0a.split(":")
        assert_equal(wnode.gettxout(pot0a_txid, int(pot0a_vout)), None)
        rdec = wnode.decoderawtransaction(redeem["hex"])
        sink0_spk = redeem["sinks"][0]["sink_spk"]
        assert_equal(sink0_spk, lot0["sink_spk"])
        sink_outs = [v for v in rdec["vout"] if v["scriptPubKey"]["hex"] == sink0_spk]
        assert_equal(len(sink_outs), 1)
        sink_ext = sink_outs[0]["outext"]
        assert_equal(sink_ext[4:4 + 64], redeem["asset_id"])       # the series id
        assert_equal(int.from_bytes(bytes.fromhex(sink_ext[4 + 64:4 + 64 + 16]), "little"), 1)  # exactly 1 unit
        change_outs = [v for v in rdec["vout"]
                       if v.get("outext", "").startswith("01") and v["scriptPubKey"]["hex"] != sink0_spk]
        assert_equal(len(change_outs), 1)
        assert_equal(int.from_bytes(bytes.fromhex(change_outs[0]["outext"][4 + 64:4 + 64 + 16]), "little"), 2)
        # The reported native_sweep matches the actual native (no-outext) output to the holder — catches any
        # stale-fee / reporting drift between the loop and the serialized transaction.
        sweep_outs = [v for v in rdec["vout"]
                      if v["scriptPubKey"].get("address") == redeem["holder_address"] and not v.get("outext")]
        assert_equal(len(sweep_outs), 1)
        assert_equal(sweep_outs[0]["value"], Decimal(redeem["native_sweep"]))

        # Redeeming a second, different lot proves cross-lot redemption + that the change unit is reusable.
        redeem1 = wallet.optionseries.build_redeem(redeem_terms, [{"lot_index": 1, "pot": pot1}], {"broadcast": True})
        assert_equal(redeem1["units_retired"], 1)
        assert_equal(redeem1["token_change_units"], 1)             # 2 left - 1 retired
        self.generatetoaddress(wnode, 1, wallet.getnewaddress())
        pot1_txid, pot1_vout = pot1.split(":")
        assert_equal(wnode.gettxout(pot1_txid, int(pot1_vout)), None)

        self.log.info("optionseries.build_buyback unwinds a lot vault via the writer-signed buy-back leaf")
        # The writer's early unwind: spend a lot vault through its buy-back leaf (output-binding covenant +
        # a writer signature), retiring 1 repurchased unit to the sink and reclaiming the collateral. NO
        # maturity/CLTV wait. writer_key is a wallet key so the wallet can sign the leaf CHECKSIG (the leaf
        # binds the OUTPUT key, so the wallet signs with the internal key tweaked by the address merkle root).
        bb_writer = wallet.getaddressinfo(wallet.getnewaddress("", "bech32m"))["witness_program"]
        bb_terms = {
            "writer_key": bb_writer,
            "strike_nbits": 0x1d00ffff,
            "fixing_height": 150000,
            "settle_lock_height": 150100,
            "lambda_q": 218453,
            "lot_im": "1.00000000",
            "lot_count": 3,
            "reference_premium": "2.00000000",
            "series_salt": "a1" * 32,
        }
        wallet.optionseries.build_register(bb_terms, parent_root, "optbuyb", {"broadcast": True})
        self.generatetoaddress(wnode, 1, wallet.getnewaddress())
        bb_iss = wallet.optionseries.build_issue(bb_terms, {"broadcast": True})  # 3 units to the writer + 3 vaults
        self.generatetoaddress(wnode, 1, wallet.getnewaddress())
        bb_rec = wallet.optionseries.record_issue(bb_terms, bb_iss["mint"])
        vault0 = bb_rec["lot_vaults"][0]

        # Guards.
        # (1) settle-only series has no buy-back leaf.
        settle_only = {**bb_terms, "leaf_set": 0, "series_salt": "b2" * 32}
        assert_raises_rpc_error(RPC_INVALID_PARAMETER, "settle-only",
                                lambda: wallet.optionseries.build_buyback(settle_only, 0))
        # (2) lot index out of range.
        assert_raises_rpc_error(RPC_INVALID_PARAMETER, "out of range",
                                lambda: wallet.optionseries.build_buyback(bb_terms, 9))
        # (3) an unrecorded series with no vault_outpoint hint cannot be discovered.
        unrec = {**bb_terms, "series_salt": "c3" * 32}
        assert_raises_rpc_error(RPC_INVALID_PARAMETER, "not recorded",
                                lambda: wallet.optionseries.build_buyback(unrec, 0))
        # (4) a missing/spent vault outpoint is rejected.
        assert_raises_rpc_error(RPC_INVALID_PARAMETER, "missing or already spent",
                                lambda: wallet.optionseries.build_buyback(bb_terms, 0, {"vault_outpoint": f"{'00'*32}:0"}))
        # (5) a party with no units of the series cannot repurchase (keeper holds native, zero units).
        assert_raises_rpc_error(-6, "no option units",
                                lambda: keeper.optionseries.build_buyback(bb_terms, 0, {"vault_outpoint": vault0}))

        # Happy path: the writer unwinds lot 0. Broadcasting + confirming proves the writer signature AND the
        # output-binding buy-back covenant validate through ConnectBlock (real consensus, not just VerifyScript).
        bb = wallet.optionseries.build_buyback(bb_terms, 0, {"broadcast": True})
        assert_equal(bb["unit_repurchased"], 1)
        assert_equal(bb["token_change_units"], 2)                 # 3 minted - 1 repurchased
        assert_equal(bb["inputs"]["vault"], 1)
        assert_greater_than_or_equal(Decimal(bb["native_sweep"]), Decimal("0.99"))  # ~1 BTC collateral reclaimed
        self.generatetoaddress(wnode, 1, wallet.getnewaddress())

        v0_txid, v0_vout = vault0.split(":")
        assert_equal(wnode.gettxout(v0_txid, int(v0_vout)), None)  # vault spent by the buy-back
        bdec = wnode.decoderawtransaction(bb["hex"])
        sink0 = wnode.optionseries.derive(bb_terms, [0])["lots"][0]["sink_spk"]
        bb_sink_outs = [v for v in bdec["vout"] if v["scriptPubKey"]["hex"] == sink0]
        assert_equal(len(bb_sink_outs), 1)
        assert_equal(bb_sink_outs[0]["scriptPubKey"]["address"], bb["sink_address"])
        bb_sink_ext = bb_sink_outs[0]["outext"]
        assert_equal(bb_sink_ext[4:4 + 64], bb["asset_id"])
        assert_equal(int.from_bytes(bytes.fromhex(bb_sink_ext[4 + 64:4 + 64 + 16]), "little"), 1)  # exactly 1 unit

        # A second buy-back on lot 1 proves repeatability + that the change unit is reusable. Drive it off the
        # terms RETURNED BY optionseries.list (the shape the Qt lifecycle panel feeds back into the build RPCs):
        # this proves list's terms round-trip exactly — writer/salt as natural-order hex, amounts as decimal —
        # since a wrong salt byte-order would derive a different series_id and miss the vault.
        listed_bb = next(s for s in wallet.optionseries.list() if s["asset_id"] == bb["asset_id"])
        bb1 = wallet.optionseries.build_buyback(listed_bb["terms"], 1, {"broadcast": True})
        assert_equal(bb1["asset_id"], bb["asset_id"])            # listed terms derive the SAME series id
        assert_equal(bb1["token_change_units"], 1)               # 2 left - 1
        self.generatetoaddress(wnode, 1, wallet.getnewaddress())
        v1_txid, v1_vout = bb_rec["lot_vaults"][1].split(":")
        assert_equal(wnode.gettxout(v1_txid, int(v1_vout)), None)

        # HOLDER path: recover terms from the ON-CHAIN descriptor (verify) and round-trip them into a build
        # RPC — exactly what the Qt "Verify Option" tab does for a buyer with no wallet record. This mirrors
        # walletmodel's DisplayTermsToParseTerms (lot_im_sats -> decimal lot_im; writer/salt hex unchanged).
        def display_to_parse_terms(dt):
            t = {k: dt[k] for k in ("descriptor_version", "issuance_mode", "leaf_set", "writer_key",
                                    "strike_nbits", "fixing_height", "settle_lock_height", "lambda_q",
                                    "lot_count", "series_salt")}
            t["lot_im"] = f'{dt["lot_im_sats"] // 100000000}.{dt["lot_im_sats"] % 100000000:08d}'
            t["reference_premium"] = f'{dt["reference_premium_sats"] // 100000000}.{dt["reference_premium_sats"] % 100000000:08d}'
            return t
        bb_md = wallet.geticupayload(bb["registry_asset_id"])["metadata"]
        recovered = display_to_parse_terms(wallet.optionseries.verify(bb["asset_id"], {"icu_metadata": bb_md})["terms"])
        bb2 = wallet.optionseries.build_buyback(recovered, 2, {"broadcast": True})  # last remaining lot
        assert_equal(bb2["asset_id"], bb["asset_id"])           # descriptor-recovered terms derive the SAME id
        self.generatetoaddress(wnode, 1, wallet.getnewaddress())
        v2_txid, v2_vout = bb_rec["lot_vaults"][2].split(":")
        assert_equal(wnode.gettxout(v2_txid, int(v2_vout)), None)

        self.log.info("optionseries: a PUT (descriptor v2, writer long) settles ITM through real consensus")
        # Unlike a call, a PUT is in-the-money when realized difficulty sits BELOW the strike — which is the
        # NORMAL regtest condition (realized difficulty == 1, the powLimit floor). So a put with a strike above
        # diff-1 settles ITM, funds its pot, and the holder redeems it — a full long-leg settlement path the
        # call could never exercise on regtest.
        hp = wnode.getblockcount()
        put_writer = wallet.getaddressinfo(wallet.getnewaddress("", "bech32m"))["witness_program"]
        put_terms = {
            "descriptor_version": 2,
            "direction": 1,                      # put: writer funds the LONG leg
            "writer_key": put_writer,
            "strike_nbits": 0x1d00ffff,          # strike target << regtest powLimit -> put is ITM
            "fixing_height": hp + 8,
            "settle_lock_height": hp + 8 + 110,
            "lambda_q": 218453,
            "lot_im": "2.00000000",
            "lot_count": 2,
            "reference_premium": "5.00000000",
            "series_salt": "9f" * 32,
        }
        # A put derives a DIFFERENT asset id + vaults than an otherwise-identical call (direction is committed).
        call_twin = {**put_terms, "direction": 0}
        assert wnode.optionseries.derive(put_terms)["asset_id"] != wnode.optionseries.derive(call_twin)["asset_id"]
        assert_equal(wnode.optionseries.verify(wnode.optionseries.derive(put_terms)["asset_id"],
                                               {"terms": put_terms})["terms"]["option_kind"], "put")

        p_reg = wallet.optionseries.build_register(put_terms, parent_root, "optput", {"broadcast": True})
        self.generatetoaddress(wnode, 1, wallet.getnewaddress())
        p_iss = wallet.optionseries.build_issue(put_terms, {"broadcast": True})  # mints 2 units to the writer
        self.generatetoaddress(wnode, 1, wallet.getnewaddress())
        wallet.optionseries.record_issue(put_terms, p_iss["mint"])

        # Buyer/holder fraud-check of a v2 (104-byte) descriptor via the ON-CHAIN ICU metadata path — the
        # exact geticupayload -> verify(... icu_metadata ...) flow the GUI uses. Proves the descriptor parser
        # accepts 104 bytes (v2) for a series the GUI now creates, not just the {"terms": ...} re-serialization.
        p_md = wallet.geticupayload(p_reg["registry_asset_id"])["metadata"]
        p_vb = wallet.optionseries.verify(p_reg["registry_asset_id"], {"icu_metadata": p_md}, {"check_backing": True})
        assert_equal(p_vb["authentic"], True)
        assert_equal(p_vb["terms"]["option_kind"], "put")           # the v2 direction byte survives the round-trip
        assert_equal(p_vb["backing"]["on_chain"]["verified"], True)  # vaults re-derived from the 104-byte descriptor

        # Mine past fixing burial + the CLTV, then settle lot 0 — ITM, so the covenant funds the pot.
        self.generatetoaddress(wnode, (hp + 8 + 110 + 5) - wnode.getblockcount(), wallet.getnewaddress())
        p_settle = wallet.optionseries.build_settlement(put_terms, 0)
        assert Decimal(p_settle["payout_pot"]) > 0      # put is in-the-money: the pot is funded
        p_proc = wallet.walletprocesspsbt(p_settle["psbt"])
        p_ext = wallet.difficulty.finalize_settlement(p_proc["psbt"])
        p_txid = wnode.sendrawtransaction(p_ext["hex"])  # long-leg OP_DIFFCFD_SETTLE validates in ConnectBlock
        self.generatetoaddress(wnode, 1, wallet.getnewaddress())

        # The pot landed at the derived lot-0 pot; the holder redeems it (retires 1 unit, sweeps the pot).
        pot0_spk = wnode.optionseries.derive(put_terms, [0])["lots"][0]["pot_spk"]
        p_dec = wnode.decoderawtransaction(wallet.gettransaction(p_txid)["hex"])
        p_pot_vout = next(v["n"] for v in p_dec["vout"] if v["scriptPubKey"]["hex"] == pot0_spk)
        p_red = wallet.optionseries.build_redeem(put_terms, [{"lot_index": 0, "pot": f"{p_txid}:{p_pot_vout}"}], {"broadcast": True})
        assert_equal(p_red["units_retired"], 1)
        assert_equal(p_red["token_change_units"], 1)     # 2 minted - 1 retired
        self.generatetoaddress(wnode, 1, wallet.getnewaddress())
        assert_equal(wnode.gettxout(p_txid, p_pot_vout), None)  # pot spent by the redemption

        self.log.info("optionseries full lifecycle: register + issue + record + check_backing + keeper settlement + redeem + buyback + PUT settle/redeem all passed")


if __name__ == '__main__':
    OptionSeriesRpcTest(__file__).main()
