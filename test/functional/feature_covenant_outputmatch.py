#!/usr/bin/env python3
"""Functional coverage for OUTPUTMATCH covenant opcodes."""

import hashlib
from decimal import Decimal

from test_framework.address import address_to_scriptpubkey
from test_framework.key import ECKey, compute_xonly_pubkey
from test_framework.messages import (
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    tx_from_hex,
    uint256_from_str,
)
from test_framework.script import (
    CScript,
    OP_DROP,
    OP_OUTPUTMATCH_ASSET,
    OP_OUTPUTMATCH_NATIVE,
    OP_TRUE,
    OP_VERIFY,
    taproot_construct,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet import MiniWallet


def tap_match(script_pubkey: bytes) -> bytes:
    return hashlib.sha256(b"TapMatch" + script_pubkey).digest()


def u64_le(value: int) -> bytes:
    return value.to_bytes(8, "little", signed=False)


def asset_id_le(asset_hex: str) -> bytes:
    """Return the little-endian bytes used in TLV payloads for the given asset id."""
    return bytes.fromhex(asset_hex)[::-1]


def parse_assettag_amount(tlv_hex: str) -> int:
    data = bytes.fromhex(tlv_hex)
    if not data:
        raise ValueError("Empty TLV")
    if data[0] != 0x01:
        raise ValueError("Unsupported TLV type")
    if len(data) < 2:
        raise ValueError("Malformed TLV")
    length = data[1]
    if len(data) < 2 + length:
        raise ValueError("TLV length mismatch")
    payload = data[2:2 + length]
    if len(payload) < 32 + 8:
        raise ValueError("TLV payload too short")
    amount_bytes = payload[32:32 + 8]
    return int.from_bytes(amount_bytes, "little", signed=False)


class CovenantOutputMatchTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-assetsheight=0"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.setup_nodes()

    def create_taproot_covenant(self, match_items):
        """Return (tap_info, leaf_info, covenant_script)."""
        internal_key = ECKey()
        internal_key.set((1).to_bytes(32, "big"), True)
        xonly = compute_xonly_pubkey(internal_key.get_bytes())[0]
        covenant_script = CScript(match_items)
        tap_info = taproot_construct(xonly, [("covenant", bytes(covenant_script))])
        leaf_info = tap_info.leaves["covenant"]
        return tap_info, leaf_info, covenant_script

    def broadcast_tx(self, node, tx: CTransaction) -> str:
        tx.rehash()
        return node.sendrawtransaction(tx.serialize().hex())

    def set_witness_for_input(self, tx: CTransaction, txid: str, vout: int, witness_stack: list):
        """Find input matching txid:vout and set its witness stack."""
        # Find the input index
        input_index = None
        for i, vin in enumerate(tx.vin):
            if vin.prevout.hash == int(txid, 16) and vin.prevout.n == vout:
                input_index = i
                break
        assert input_index is not None, f"Input {txid}:{vout} not found in transaction"

        # Ensure witness structure exists
        while len(tx.wit.vtxinwit) <= input_index:
            tx.wit.vtxinwit.append(CTxInWitness())

        # Set witness stack
        tx.wit.vtxinwit[input_index].scriptWitness.stack = witness_stack

    @staticmethod
    def _find_vout(decoded_tx, predicate):
        """Return (index, vout) for the first output satisfying predicate."""
        for idx, vout in enumerate(decoded_tx['vout']):
            if predicate(vout):
                return idx, vout
        raise AssertionError("Matching vout not found")

    def run_test(self):
        node = self.nodes[0]
        node.createwallet("covenant")
        wallet = node.get_wallet_rpc("covenant")

        mini = MiniWallet(node)
        self.generate(mini, 101)

        # Fund the wallet so high-level asset RPCs can autofund.
        funding_addr = wallet.getnewaddress()
        funding_tx = mini.create_self_transfer()
        funding_tx["tx"].vout[0].scriptPubKey = address_to_scriptpubkey(funding_addr)
        funding_tx["tx"].rehash()
        mini.sendrawtransaction(from_node=node, tx_hex=funding_tx["tx"].serialize().hex())
        self.generate(node, 1)
        wallet.rescanblockchain()

        self.log.info("Testing native OUTPUTMATCH success path")
        native_target_addr = wallet.getnewaddress(address_type="bech32m")
        native_target_spk = bytes(address_to_scriptpubkey(native_target_addr))
        native_amount_sat = 50_000

        native_match_hash = tap_match(native_target_spk)
        tap_native, leaf_native, cov_native_script = self.create_taproot_covenant([
            native_match_hash,
            u64_le(native_amount_sat),
            OP_OUTPUTMATCH_NATIVE,
        ])

        covenant_tx = mini.create_self_transfer()
        covenant_value = covenant_tx["tx"].vout[0].nValue
        covenant_tx["tx"].vout[0].scriptPubKey = tap_native.scriptPubKey
        covenant_tx["tx"].rehash()
        cov_txid = mini.sendrawtransaction(from_node=node, tx_hex=covenant_tx["tx"].serialize().hex())
        cov_outpoint = {"txid": cov_txid, "vout": 0, "amount": Decimal(covenant_value) / COIN, "scriptPubKey": tap_native.scriptPubKey.hex()}

        spend_inputs = [
            {
                "txid": cov_outpoint["txid"],
                "vout": cov_outpoint["vout"],
                "sequence": 0,
                "amount": float(cov_outpoint["amount"]),
                "scriptPubKey": cov_outpoint["scriptPubKey"],
            }
        ]
        native_outputs = [{native_target_addr: Decimal(native_amount_sat) / COIN}]
        native_raw = wallet.createrawtransaction(spend_inputs, native_outputs)
        funded_native = wallet.fundrawtransaction(native_raw)
        signed_native = wallet.signrawtransactionwithwallet(funded_native["hex"])['hex']
        native_ctx = tx_from_hex(signed_native)

        control_block = bytes([leaf_native.version + tap_native.negflag]) + tap_native.internal_pubkey + leaf_native.merklebranch
        self.set_witness_for_input(native_ctx, cov_txid, 0, [bytes(cov_native_script), control_block])
        native_txid = self.broadcast_tx(node, native_ctx)
        assert native_txid in node.getrawmempool()
        self.generate(node, 1)

        self.log.info("Testing dust policy rejection")
        # Create transaction with dust output, manually construct without wallet signing
        dust_covenant_tx = mini.create_self_transfer()
        tap_dust_cov, leaf_dust_cov, cov_dust_script = self.create_taproot_covenant([
            native_match_hash,
            u64_le(native_amount_sat),
            OP_OUTPUTMATCH_NATIVE,
        ])
        dust_covenant_tx["tx"].vout[0].scriptPubKey = tap_dust_cov.scriptPubKey
        dust_covenant_tx["tx"].rehash()
        dust_covenant_txid = mini.sendrawtransaction(from_node=node, tx_hex=dust_covenant_tx["tx"].serialize().hex())

        # Build transaction manually with dust output included from start
        dust_ctx = CTransaction()
        dust_ctx.vin.append(CTxIn(COutPoint(uint256_from_str(bytes.fromhex(dust_covenant_txid)[::-1]), 0)))
        dust_ctx.vout.append(CTxOut(native_amount_sat, address_to_scriptpubkey(native_target_addr)))
        # Dust output using standard P2WPKH (20-byte witness program)
        dust_addr = wallet.getnewaddress(address_type="bech32")
        dust_ctx.vout.append(CTxOut(100, address_to_scriptpubkey(dust_addr)))

        # Add covenant witness
        control_block_dust = bytes([leaf_dust_cov.version + tap_dust_cov.negflag]) + tap_dust_cov.internal_pubkey + leaf_dust_cov.merklebranch
        dust_ctx.wit.vtxinwit.append(CTxInWitness())
        dust_ctx.wit.vtxinwit[0].scriptWitness.stack = [bytes(cov_dust_script), control_block_dust]

        assert_raises_rpc_error(-26, "dust", node.sendrawtransaction, dust_ctx.serialize().hex(), 0)

        self.log.info("Testing opcode per-input limit")
        key_limit = ECKey()
        key_limit.set((2).to_bytes(32, "big"), True)
        xonly_limit = compute_xonly_pubkey(key_limit.get_bytes())[0]
        limit_pieces = []
        for _ in range(9):
            limit_pieces.extend([
                native_match_hash,
                u64_le(native_amount_sat),
                OP_OUTPUTMATCH_NATIVE,
                OP_DROP,
            ])
        limit_pieces.append(OP_TRUE)
        limit_script = CScript(limit_pieces)
        tap_limit = taproot_construct(xonly_limit, [("limit", bytes(limit_script))])
        leaf_limit = tap_limit.leaves["limit"]
        limit_tx = mini.create_self_transfer()
        limit_tx["tx"].vout[0].scriptPubKey = tap_limit.scriptPubKey
        limit_tx["tx"].rehash()
        limit_txid = mini.sendrawtransaction(from_node=node, tx_hex=limit_tx["tx"].serialize().hex())
        limit_inputs = [{
            "txid": limit_txid,
            "vout": 0,
            "sequence": 0,
            "amount": float(Decimal(limit_tx["tx"].vout[0].nValue) / COIN),
            "scriptPubKey": tap_limit.scriptPubKey.hex(),
        }]
        limit_raw = wallet.createrawtransaction(limit_inputs, [{native_target_addr: Decimal(native_amount_sat) / COIN}])
        limit_funded = wallet.fundrawtransaction(limit_raw)
        limit_signed = wallet.signrawtransactionwithwallet(limit_funded["hex"])['hex']
        limit_ctx = tx_from_hex(limit_signed)
        control_limit = bytes([leaf_limit.version + tap_limit.negflag]) + tap_limit.internal_pubkey + leaf_limit.merklebranch
        self.set_witness_for_input(limit_ctx, limit_txid, 0, [bytes(limit_script), control_limit])
        assert_raises_rpc_error(-26, "", node.sendrawtransaction, limit_ctx.serialize().hex())

        # Rescan and generate more blocks to MiniWallet before heavy UTXO usage
        mini.rescan_utxos()
        self.generate(mini, 50)

        self.log.info("Testing covenant output count limit")
        output_key = ECKey()
        output_key.set((4).to_bytes(32, "big"), True)
        output_xonly = compute_xonly_pubkey(output_key.get_bytes())[0]
        many_script = CScript([
            native_match_hash,
            u64_le(native_amount_sat),
            OP_OUTPUTMATCH_NATIVE,
            OP_VERIFY,
            OP_TRUE,
        ])
        tap_many = taproot_construct(output_xonly, [("many", bytes(many_script))])
        leaf_many = tap_many.leaves["many"]

        many_tx = mini.create_self_transfer()
        many_tx["tx"].vout[0].scriptPubKey = tap_many.scriptPubKey
        many_tx["tx"].rehash()
        many_txid = mini.sendrawtransaction(from_node=node, tx_hex=many_tx["tx"].serialize().hex())

        many_inputs = [{
            "txid": many_txid,
            "vout": 0,
            "sequence": 0,
            "amount": float(Decimal(many_tx["tx"].vout[0].nValue) / COIN),
            "scriptPubKey": tap_many.scriptPubKey.hex(),
        }]

        target_outputs = [{native_target_addr: Decimal(native_amount_sat) / Decimal(COIN)}]
        for _ in range(128):
            target_outputs.append({wallet.getnewaddress(): Decimal("0.0001")})

        many_raw = wallet.createrawtransaction(many_inputs, target_outputs)
        many_funded = wallet.fundrawtransaction(many_raw)
        many_hex = wallet.signrawtransactionwithwallet(many_funded["hex"])['hex']
        many_ctx = tx_from_hex(many_hex)

        control_many = bytes([leaf_many.version + tap_many.negflag]) + tap_many.internal_pubkey + leaf_many.merklebranch
        self.set_witness_for_input(many_ctx, many_txid, 0, [bytes(many_script), control_many])
        assert_raises_rpc_error(-26, "too-many-covenant-outputs", node.sendrawtransaction, many_ctx.serialize().hex())

        self.log.info("Testing asset OUTPUTMATCH success path")
        asset_id = hashlib.sha256(b"covenant-asset").hexdigest()
        icu_addr = wallet.getnewaddress()
        register_result = wallet.registerasset(
            icu_addr,
            5.1,
            asset_id,
            3,
            28,
            510000000,
            "CVT",
            6,
            {"autofund": True, "broadcast": True}
        )
        if isinstance(register_result, dict):
            register_txid = register_result.get('txid')
        else:
            register_txid = register_result
        self.generate(node, 1)
        policy = node.getassetpolicy(asset_id)
        assert_equal(policy['icu_txid'], register_txid)
        icu_txid = policy['icu_txid']
        icu_vout = policy['icu_vout']
        wallet.lockunspent(False, [{"txid": icu_txid, "vout": icu_vout}])

        asset_dest = wallet.getnewaddress(address_type="bech32m")
        new_icu = wallet.getnewaddress()
        mint_result = wallet.mintasset(
            icu_txid,
            icu_vout,
            new_icu,
            5.1,
            asset_dest,
            0.001,
            asset_id,
            500000,
            3,
            28,
            510000000,
            {"autofund": True, "broadcast": True}
        )
        if isinstance(mint_result, dict):
            mint_txid = mint_result['txid']
        else:
            mint_txid = mint_result
        self.generate(node, 1)

        # Get the minted asset UTXO (filter for ASSET_TAG type 0x01, not ISSUER_REG 0x10)
        decoded_mint = wallet.gettransaction(mint_txid, True, True)['decoded']
        asset_vout = next(i for i, v in enumerate(decoded_mint['vout'])
                         if 'outext' in v and i > 0 and v['outext'].startswith('01'))
        asset_vout_entry = decoded_mint['vout'][asset_vout]
        self.log.info(f"Minted asset vout: {asset_vout_entry}")
        asset_spk = bytes.fromhex(asset_vout_entry['scriptPubKey']['hex'])
        asset_value_sat = int(Decimal(str(asset_vout_entry['value'])) * COIN)
        asset_units = parse_assettag_amount(asset_vout_entry['outext'])

        # Lock the new ICU output to avoid wallet selecting it for fees
        new_policy = node.getassetpolicy(asset_id)
        wallet.lockunspent(False, [{"txid": new_policy['icu_txid'], "vout": new_policy['icu_vout']}])

        # Create covenant requiring this asset format
        asset_match_hash = tap_match(asset_spk)
        tap_asset, leaf_asset, cov_asset_script = self.create_taproot_covenant([
            asset_match_hash,
            asset_id_le(asset_id),
            u64_le(asset_units),
            OP_OUTPUTMATCH_ASSET,
        ])

        # Create covenant-locked native output
        covenant_asset_tx = mini.create_self_transfer()
        covenant_asset_tx["tx"].vout[0].scriptPubKey = tap_asset.scriptPubKey
        covenant_asset_tx["tx"].rehash()
        cov_asset_txid = mini.sendrawtransaction(from_node=node, tx_hex=covenant_asset_tx["tx"].serialize().hex())

        asset_inputs = [
            {"txid": cov_asset_txid, "vout": 0},
            {"txid": mint_txid, "vout": asset_vout}
        ]
        asset_outputs = [{asset_dest: Decimal(asset_value_sat) / COIN}]

        raw_asset = node.createrawtransaction(asset_inputs, asset_outputs)
        funded_asset = wallet.fundrawtransaction(raw_asset)
        funded_hex = funded_asset['hex']

        decoded_funded = node.decoderawtransaction(funded_hex)
        asset_vout_idx, _ = self._find_vout(
            decoded_funded,
            lambda v: v['scriptPubKey'].get('address') == asset_dest,
        )

        funded_with_tlv = node.rawtxattachassettag(funded_hex, asset_vout_idx, asset_id, asset_units)
        signed_hex = wallet.signrawtransactionwithwallet(funded_with_tlv)['hex']
        asset_ctx = tx_from_hex(signed_hex)

        decoded_final = node.decoderawtransaction(signed_hex)
        self.log.info(f"Asset covenant tx outputs: {decoded_final['vout']}")

        # Add covenant witness to input 0
        control_block_asset = bytes([leaf_asset.version + tap_asset.negflag]) + tap_asset.internal_pubkey + leaf_asset.merklebranch
        self.set_witness_for_input(asset_ctx, cov_asset_txid, 0, [bytes(cov_asset_script), control_block_asset])

        # Optional debug logging: number of stack entries and hex values
        stack_hex = [element.hex() if isinstance(element, bytes) else element for element in [bytes(cov_asset_script), control_block_asset]]
        self.log.info(f"Asset witness stack: {stack_hex}")

        asset_txid = self.broadcast_tx(node, asset_ctx)
        assert asset_txid in node.getrawmempool()
        self.generate(node, 1)


if __name__ == '__main__':
    CovenantOutputMatchTest(__file__).main()
