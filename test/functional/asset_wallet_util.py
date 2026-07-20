#!/usr/bin/env python3
"""Shared helpers for wallet asset functional tests."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
import hashlib
import os
import time
from typing import Dict, Iterable, Optional, Tuple

SAT = Decimal("0.00000001")
DUST_THRESHOLD = Decimal("0.00005")


def unique_asset_id(label: str) -> str:
    """Derive a deterministic-but-unique asset id for the current test run."""
    payload = f"{os.getpid()}_{time.time()}_{label}".encode()
    return hashlib.sha256(payload).hexdigest()


def _quantize(amount: Decimal) -> float:
    return float(amount.quantize(SAT))


def _decode_vout(node, txid: str, vout: int) -> Tuple[Decimal, Optional[str]]:
    # Use gettransaction for wallet transactions instead of getrawtransaction
    tx_info = node.gettransaction(txid, True, True)
    decoded = tx_info["decoded"]
    entry = decoded["vout"][vout]
    return Decimal(str(entry["value"])), entry.get("outext")


def _first_spendable(node, *, exclude: Iterable[Tuple[str, int]] = ()):
    excluded = {(txid, vout) for txid, vout in exclude}
    for utxo in node.listunspent():
        candidate = (utxo["txid"], utxo["vout"])
        if candidate in excluded:
            continue
        return utxo
    return None


def make_asset_tag_tlv(asset_id_hex: str, units: int, flags: int = 0) -> str:
    aid = bytes.fromhex(asset_id_hex)
    payload = bytearray()
    payload.extend(aid)
    payload.extend((units & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little"))
    if flags:
        payload.extend((flags & 0xFFFFFFFF).to_bytes(4, "little"))
    tlv = bytearray()
    tlv.append(0x01)
    tlv.append(len(payload))
    tlv.extend(payload)
    return tlv.hex()


def make_issuer_reg_tlv(
    asset_id_hex: str,
    *,
    policy_bits: int = 3,
    allowed_families: int = 0x1C,
    unlock_fees_sats: Optional[int] = None,
    ticker: Optional[str] = None,
    decimals: Optional[int] = None,
    # ZK section
    kyc_flags: int = 0,
    vk_commitment_hex: Optional[str] = None,
    max_root_age: int = 0,
    tfr_flags: int = 0,
    # ICU section
    icu_flags: int = 0,
    issuance_cap_units: int = 0,
    icu_ctxt_commit_hex: Optional[str] = None,
    icu_plain_commit_hex: Optional[str] = None,
    kdf_salt_hex: Optional[str] = None,
    icu_version: int = 0,
    icu_visibility: int = 0,
    core_policy_commit_hex: Optional[str] = None,
    policy_epoch: int = 0,
    policy_quorum_bps: int = 0,
) -> str:
    """Create v1 IssuerReg TLV (format_version=1, always includes ZK+ICU sections)."""
    aid = bytes.fromhex(asset_id_hex)
    payload = bytearray()

    # Header
    payload.extend(aid)  # Asset ID
    payload.extend((policy_bits & 0xFFFFFFFF).to_bytes(4, "little"))
    payload.extend((allowed_families & 0xFFFF).to_bytes(2, "little"))
    payload.append(0x01)  # format_version = 1

    # Ticker (empty = not set)
    if ticker is not None:
        encoded = ticker.upper().encode("ascii")
        if not (3 <= len(encoded) <= 11):
            raise ValueError("ticker must be between 3 and 11 characters")
        payload.append(len(encoded))
        payload.extend(encoded)
    else:
        payload.append(0)  # ticker_len = 0

    # Decimals (0xFF = not set)
    if decimals is not None:
        if not (0 <= decimals <= 18):
            raise ValueError("decimals must be 0-18")
        payload.append(decimals & 0xFF)
    else:
        payload.append(0xFF)

    # Unlock fees (UINT64_MAX = not set)
    if unlock_fees_sats is not None:
        payload.extend((unlock_fees_sats & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little"))
    else:
        payload.extend((0xFFFFFFFFFFFFFFFF).to_bytes(8, "little"))

    # ZK section (76 bytes with compliance_root_commit)
    payload.extend((kyc_flags & 0xFFFFFFFF).to_bytes(4, "little"))
    if vk_commitment_hex:
        payload.extend(bytes.fromhex(vk_commitment_hex))
    else:
        payload.extend(bytes(32))  # Zero-filled vk_commitment
    payload.extend((max_root_age & 0xFFFFFFFF).to_bytes(4, "little"))
    payload.extend((tfr_flags & 0xFFFFFFFF).to_bytes(4, "little"))
    # compliance_root_commit (32 bytes) - zero for initial registration
    payload.extend(bytes(32))

    # ICU section (129 bytes with icu_visibility)
    payload.extend((icu_flags & 0xFFFFFFFF).to_bytes(4, "little"))
    payload.extend((issuance_cap_units & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little"))

    # icu_ctxt_commit (32 bytes)
    if icu_ctxt_commit_hex:
        payload.extend(bytes.fromhex(icu_ctxt_commit_hex))
    else:
        payload.extend(bytes(32))

    # icu_plain_commit (32 bytes)
    if icu_plain_commit_hex:
        payload.extend(bytes.fromhex(icu_plain_commit_hex))
    else:
        payload.extend(bytes(32))

    # kdf_salt (16 bytes)
    if kdf_salt_hex:
        salt_bytes = bytes.fromhex(kdf_salt_hex)
        if len(salt_bytes) != 16:
            raise ValueError("kdf_salt must be exactly 16 bytes (32 hex chars)")
        payload.extend(salt_bytes)
    else:
        payload.extend(bytes(16))

    payload.append(icu_version & 0xFF)
    payload.append(icu_visibility & 0xFF)

    # core_policy_commit (32 bytes)
    if core_policy_commit_hex:
        payload.extend(bytes.fromhex(core_policy_commit_hex))
    else:
        payload.extend(bytes(32))

    payload.append(policy_epoch & 0xFF)
    payload.extend((policy_quorum_bps & 0xFFFF).to_bytes(2, "little"))

    # Wrap in TLV
    tlv = bytearray()
    tlv.append(0x10)  # OutExtType::ISSUER_REG
    # Length encoding: varint for payloads >= 253 bytes (v1 format is now 254-265 bytes)
    payload_len = len(payload)
    if payload_len < 253:
        tlv.append(payload_len & 0xFF)
    else:
        tlv.append(253)
        tlv.extend(payload_len.to_bytes(2, "little"))
    tlv.extend(payload)
    return tlv.hex()


@dataclass
class AssetOutpoint:
    txid: str
    vout: int
    value: Decimal
    outext: Optional[str]


def register_asset(
    node,
    asset_id: Optional[str] = None,
    *,
    bond_value: Decimal = Decimal("5.0"),
    fee: Decimal = Decimal("0.0002"),
    policy_bits: int = 3,
    allowed_families: int = 0x1C,
    unlock_fees_sats: Optional[int] = None,
    ticker: Optional[str] = None,
    decimals: Optional[int] = None,
) -> Tuple[str, Dict, Decimal]:
    """Register a new asset and return (asset_id, policy, icu_value)."""
    if asset_id is None:
        asset_id = unique_asset_id("register")

    # If unlock_fees_sats not specified, use smart default: max(bond, 5 BTC)
    if unlock_fees_sats is None:
        bond_sats = int(bond_value * 100000000)  # Convert BTC to sats
        min_bond_sats = 500000000  # 5 BTC in sats
        unlock_fees_sats = max(bond_sats, min_bond_sats)

    target = bond_value + fee

    def _collect_spendable() -> Tuple[list, Decimal]:
        utxos = node.listunspent()
        if not utxos:
            return [], Decimal("0")
        sorted_utxos = sorted(
            utxos,
            key=lambda entry: Decimal(str(entry["amount"])),
            reverse=True,
        )
        selected = []
        total = Decimal("0")
        for entry in sorted_utxos:
            selected.append({"txid": entry["txid"], "vout": entry["vout"]})
            total += Decimal(str(entry["amount"]))
            if total >= target:
                break
        return selected, total

    inputs, total_in = _collect_spendable()
    if total_in < target:
        node.generate(1, called_by_framework=True)
        inputs, total_in = _collect_spendable()
    if total_in < target:
        raise AssertionError("Unable to locate funding UTXOs for registration")

    change = total_in - bond_value - fee
    if change < Decimal("0"):
        raise AssertionError("Collected UTXOs insufficient for registration after fees")

    outputs = [{node.getnewaddress(): _quantize(bond_value)}]
    if change > DUST_THRESHOLD:
        outputs.append({node.getnewaddress(): _quantize(change)})

    raw = node.createrawtransaction(inputs, outputs)
    # Prefer dedicated RPC for TLV construction; ensures consensus-correct encoding.
    raw = node.rawtxattachissuerreg(raw, 0, asset_id, policy_bits, allowed_families, unlock_fees_sats, ticker, decimals)
    signed = node.signrawtransactionwithwallet(raw)
    node.sendrawtransaction(signed["hex"])
    node.generate(1, called_by_framework=True)

    policy = node.getassetpolicy(asset_id)
    if not policy:
        raise AssertionError("Asset policy unavailable after registration")
    icu_value, _ = _decode_vout(node, policy["icu_txid"], policy["icu_vout"])
    return asset_id, policy, icu_value


def mint_asset(
    node,
    asset_id: str,
    policy: Dict,
    icu_value: Decimal,
    *,
    asset_units: int = 1000,
    asset_output_value: Decimal = Decimal("0.05"),
    fee: Decimal = Decimal("0.0005"),
    policy_bits: int = 3,
    allowed_families: int = 0x1C,
    unlock_fees_sats: Optional[int] = None,
) -> Tuple[AssetOutpoint, Dict]:
    """Rotate the ICU and emit an asset-tagged output."""
    icu_txid = policy["icu_txid"]
    icu_vout = policy["icu_vout"]

    # Get unlock_fees_sats from policy if not provided
    if unlock_fees_sats is None:
        unlock_fees_sats = policy.get("unlock_fees_sats")
        if unlock_fees_sats is None:
            raise AssertionError("unlock_fees_sats not found in policy and not provided")

    inputs = [{"txid": icu_txid, "vout": icu_vout}]
    fee_utxo = _first_spendable(node, exclude=[(icu_txid, icu_vout)])
    if fee_utxo is None:
        node.generate(1, called_by_framework=True)
        fee_utxo = _first_spendable(node, exclude=[(icu_txid, icu_vout)])
    if fee_utxo is None:
        raise AssertionError("Unable to locate fee funding UTXO for mint")
    inputs.append({"txid": fee_utxo["txid"], "vout": fee_utxo["vout"]})

    total_in = icu_value + Decimal(str(fee_utxo["amount"]))
    change = total_in - icu_value - asset_output_value - fee
    if change < Decimal("0"):
        raise AssertionError("Mint inputs insufficient for requested outputs")

    outputs = [
        {node.getnewaddress(): _quantize(icu_value)},
        {node.getnewaddress("", "bech32"): _quantize(asset_output_value)},
    ]
    if change > DUST_THRESHOLD:
        outputs.append({node.getnewaddress(): _quantize(change)})

    raw = node.createrawtransaction(inputs, outputs)
    raw = node.rawtxattachissuerreg(raw, 0, asset_id, policy_bits, allowed_families, unlock_fees_sats)
    raw = node.rawtxattachassettag(raw, 1, asset_id, asset_units)
    signed = node.signrawtransactionwithwallet(raw)
    mint_txid = node.sendrawtransaction(signed["hex"])
    node.generate(1, called_by_framework=True)

    asset_vout_value, asset_outext = _decode_vout(node, mint_txid, 1)
    new_policy = node.getassetpolicy(asset_id)
    outpoint = AssetOutpoint(mint_txid, 1, asset_vout_value, asset_outext)
    return outpoint, new_policy


def lock_asset_outputs(node, outpoints: Iterable[AssetOutpoint]) -> None:
    """Optionally lock asset-bearing outputs to prevent accidental selection."""
    if not outpoints:
        return
    params = [{"txid": op.txid, "vout": op.vout} for op in outpoints]
    node.lockunspent(False, params)
