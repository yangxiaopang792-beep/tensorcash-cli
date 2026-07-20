# TensorCash Asset System

This note documents the `bcore` asset implementation: how asset metadata is encoded, persisted, validated, and exposed through RPC tooling. It also collates the unit/functional/fuzz coverage that guards each feature and finishes with a quick usage guide.

## Wire Format & Serialization

*Implementation*
- `CTxOut` carries optional TLV bytes (`vExt`) gated by transaction flag `0x02`; serialization and hashing route through `SerTxOutWithExt` so txid/wtxid plus Taproot/BIP143 hashes always commit to those bytes (`src/primitives/transaction.h:150-398`, `src/primitives/transaction.cpp`, `src/script/interpreter.cpp`).
- Parser safeguards reject unknown marker bits, malformed TLVs, oversize per-output data, and aggregate extensions beyond 128 KiB (`src/primitives/transaction.h:300-318`).

*Key tests*
- Unit: `transaction_tests.cpp` (`tx_vext_unknown_flags_and_malformed`, `tx_vext_marker_flags_matrix_and_empty_ext`, `coin_txoutcompression_vext_roundtrip`, `coin_vext_size_bounds`, `coin_vext_database_persistence`, `tx_vext_total_ext_size_limit`, `bip143_sighash_single_binds_vext`, `taproot_sighash_single_binds_vext`, `tx_vext_hash_and_serialization`).
- Functional: `feature_assets_outext_flow.py`, `feature_assets_unknown_tlv.py`.
- Fuzz: `test/fuzz/asset_tlv_parser.cpp`, `test/fuzz/asset_transaction.cpp`.

## UTXO Persistence & Compression

*Implementation*
- `TxOutCompression` reads/writes `vExt` with legacy fallback and size bounds (`src/compressor.h:77-128`).
- UTXO cache/database need no extra plumbing beyond the updated compressor (`src/coins.h`, `src/coins.cpp`).

*Key tests*
- Unit: `transaction_tests.cpp::coin_vext_database_persistence`, `coin_vext_size_bounds`; `asset_registry_tests.cpp` verifies LevelDB CRUD and undo behaviour.

## Consensus, Registry, and Policy Enforcement

*Implementation*
- Delta accounting, ICU authorization, script-family allowlists, coinbase bans, and overflow protection live in `Consensus::CheckTxInputs` (`src/consensus/tx_verify.cpp:168-360`).
- Registry updates, ticker binding, bond rotation rules, SIGHASH enforcement, fee sharing, and mempool policy are handled in `src/validation.cpp:3080-3535` with undo support in `src/undo.h:33-74` and storage helpers in `src/txdb.cpp:161-213` / `src/assets/registry.h:13-49`.
- Policy knobs (`-policymaxassetspertx`, `-policymaxassetoutsize`, `-assetmindustbtc`, `-assetminmultitouchfee`) are declared in `src/init.cpp:629-640` and consumed in policy/mempool paths (`src/policy/policy.cpp:147-186`, `src/validation.cpp:898-1035`). The minimum initial ICU bond is NOT a policy knob: it is consensus (`Consensus::Params::AssetMinIcuBond`, enforced in ConnectBlock; the former `-assetminicubond` arg was removed). Activation height is controlled by `-assetsheight` (`src/kernel/chainparams.cpp:232-234`).

*Key tests*
- Unit: `asset_validation_tests.cpp`, `asset_arithmetic_tests.cpp`, `asset_edge_tests.cpp`, `asset_registry_tests.cpp`, `validation_asset_tests.cpp`.
- Functional: `feature_assets_basic.py`, `feature_assets_basic_highlevel.py`, `feature_assets_burn_lock.py`, `feature_assets_coin_swap.py`, `feature_assets_multiparty_swap.py`, `feature_assets_multiparty_swap_optimized.py`, `feature_assets_deep_reorg.py`, `feature_assets_network_partition.py`, `feature_assets_unknown_tlv.py`, `feature_assets_ticker.py`, `feature_assets_ticker_reorg.py`, `feature_assets_ticker_reorg_adv.py`, `feature_assets_bond_lock_validation.py`, `feature_assets_bond_lock_unlock.py`, `mempool_assets.py`.
- Fuzz: `test/fuzz/asset_mempool.cpp`, `test/fuzz/asset_registry.cpp`.

## Fee Accumulator and Bond Mechanics

*Implementation*
- IssuerReg TLVs require `unlock_fees_sats >= bond` and optionally capture ticker/decimals (`src/assets/asset.cpp:63-167`, `src/validation.cpp:940-943`).
- `ConnectBlock` tracks `fees_accum_sats`, maintains rotation minimums (95 % of the initial bond until unlock, then dust floor), enforces one new ICU per spend, and writes undo deltas (`src/validation.cpp:3292-3535`).

*Key tests*
- Functional: `feature_assets_bond_lock_unlock.py`, `feature_assets_bond_lock_validation.py`, `feature_assets_ticker.py`, `feature_assets_ticker_reorg_adv.py`, `feature_assets_network_partition.py`.
- Unit: `asset_edge_tests.cpp::asset_amount_overflow_protection`, `asset_validation_tests.cpp::asset_delta_no_overflow`.

## RPC Surface

### Raw transaction helpers
- `rawtxaddoutext` injects arbitrary TLV hex, while `rawtxattachissuerreg`/`rawtxattachassettag` build canonical structures (`src/rpc/rawtransaction.cpp:123-372`).
- `decoderawtransaction` exposes `vout[].outext` for inspection (`src/rpc/rawtransaction.cpp:480-520`).

*Tests*: `rpc_assets.py::test_rawtxaddoutext`, `test_rawtxattachissuerreg`, `test_rawtxattachassettag`, `feature_assets_outext_flow.py`.

### Node-level helpers
- `registerasset`, `mintasset`, `burnasset`, `getassetpolicy`, `getassetbyticker` assemble transactions, enforce unlock-vs-bond rules, and optionally fund/broadcast via a wallet (`src/rpc/rawtransaction.cpp:372-952`, `src/rpc/client.cpp:343-349`).

*Tests*: `rpc_assets.py::test_build_complete_asset_transaction`, `feature_assets_basic_highlevel.py`, `feature_assets_multiparty_swap_optimized.py`.

### Wallet wrappers
- Wallet RPCs add autofunding/PSBT flows for the same operations (`src/wallet/rpc/assets.cpp:541-1550`, `src/wallet/rpc/wallet.cpp:963-1031`).

*Tests*: `feature_assets_basic_highlevel.py`, `feature_assets_bond_lock_unlock.py`, `feature_assets_ticker.py`, `rpc_assets.py::test_build_complete_asset_transaction`.

## Additional Notes

- ICU inputs that participate in non-zero asset deltas must include at least one signature hashed with `SIGHASH_ALL` and without `SIGHASH_ANYONECANPAY`; violations raise `icu-invalid-sighash` (`src/validation.cpp:3236-3280`).
- Coinbase transactions cannot carry AssetTag TLVs (`src/consensus/tx_verify.cpp:289-298`). Asset balances never count toward miner fees; only BTC amounts matter.
- Activation gating rejects any `vExt` usage before the configured height at both consensus and policy layers (`src/consensus/tx_verify.cpp:170-176`, `src/validation.cpp:3055-3068`).
- Registry undo records include ticker binding updates, ensuring clean reorg behaviour (`src/undo.h:33-74`, `src/validation.cpp:2689-2762`).

## Test Coverage Overview

| Feature | Unit Tests | Functional Tests | Fuzz |
| --- | --- | --- | --- |
| TLV parsing & serialization | `transaction_tests.cpp`, `asset_tests.cpp`, `asset_edge_tests.cpp` | `feature_assets_outext_flow.py`, `feature_assets_unknown_tlv.py` | `asset_tlv_parser.cpp` (well-formed + malformed TLVs), `asset_tlv_roundtrip.cpp`, `asset_transaction.cpp` |
| Coins persistence | `transaction_tests.cpp::coin_vext_database_persistence` | – | Covered indirectly by `asset_transaction.cpp` (serialization/deserialization paths) |
| Δ + policy enforcement | `asset_validation_tests.cpp`, `asset_arithmetic_tests.cpp` | `feature_assets_basic.py`, `feature_assets_burn_lock.py`, `feature_assets_coin_swap.py`, `feature_assets_multiparty_swap*.py` | `asset_transaction.cpp` (consensus checks), `asset_mempool.cpp` (policy + AcceptToMemoryPool scenarios) |
| Registry & ticker | `asset_registry_tests.cpp`, `validation_asset_tests.cpp` | `feature_assets_ticker.py`, `feature_assets_ticker_reorg*.py`, `feature_assets_deep_reorg.py` | `asset_registry.cpp` (CRUD/undo), `asset_mempool.cpp` (ticker policy paths) |
| Bond/fee mechanics | `asset_edge_tests.cpp`, `asset_validation_tests.cpp` | `feature_assets_bond_lock_unlock.py`, `feature_assets_bond_lock_validation.py`, `mempool_assets.py` | `asset_fee_accumulator.cpp`, `asset_mempool.cpp` |
| RPC helpers | – | `rpc_assets.py`, `feature_assets_basic_highlevel.py` | – |

Recent CI run (`docker run tensorcash-tests /run_fuzz.sh --all`) completed all 132 fuzz targets without crashes, including the asset-specific harnesses listed above, which provides additional confidence in the updated coverage.

## High-Level Usage Guide

1. **Register an asset issuer**
   - Construct an ICU output with `registerasset` (node or wallet RPC). Supply the asset ID, policy bits (e.g. `MINT_ALLOWED | BURN_ALLOWED` → `3`), allowed script families, optional ticker/decimals, and an unlock threshold no lower than the posted bond. Ensure the resulting transaction is funded, signed, and mined.
2. **Mint asset units**
   - Use `mintasset` to spend the current ICU, rotate it to a new output, and create AssetTag outputs holding the desired units. The transaction must include the ICU input (for authorization) and obey script-family constraints.
3. **Transfer assets**
   - Build standard transactions using raw RPCs or wallet tooling; AssetTag outputs behave like normal UTXOs plus TLV metadata. Ensure conservation (sum in == sum out) unless mint/burn is intended.
4. **Burn assets**
   - Call `burnasset` (or craft manually) to consume asset-bearing inputs while spending the ICU; policy bits must allow burn and the ICU input must remain in the transaction.
5. **Query registry state**
   - Inspect issuer parameters with `getassetpolicy` or `getassetbyticker`; responses include policy bits, family masks, current ICU outpoint, accumulated fees, unlock threshold, ticker, and decimals.
6. **Inspect raw transactions**
   - Use `decoderawtransaction` or `rawtxaddoutext`/`rawtxattach*` helpers to debug TLVs, ensuring serialization matches consensus rules before broadcasting.
