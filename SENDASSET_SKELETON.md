# Using `sendasset` Skeletons in Covenant Workflows

## Background

TensorCash supports assets with optional KYC proofs, ICU key wrapping, and additional TLVs. The canonical RPC for producing asset transfers is `sendasset`. It performs:

- asset UTXO selection with policy checks,
- generation of TLV metadata (issuance tags, KYC proofs, key wraps),
- BTC fee selection, change output tagging,
- when `return_skeleton` is requested, returning an unsigned "skeleton" transaction with metadata so higher-level code can graft additional inputs/outputs before final signing.

The covenant RPCs for atomic swaps (`spot.*`), repos (`repo.*`), and forward contracts (`forward.*`) delegate to `sendasset` for each participant's asset deliver leg. A wallet calls `sendasset(..., {return_skeleton: true, broadcast: false})`, captures the skeleton hex plus metadata, then merges it into the covenant transaction (adding IM/vault inputs, escrow outputs, etc.). This keeps asset selection, metadata, KYC proofs, and key wrapping owned by the wallet that holds the asset, rather than reconstructed by counterparty code.

## The skeleton helper

`BuildForwardAssetSkeleton` (`src/wallet/rpc/contracts.cpp:11190`) is the entry point used by the forward-contract builders for an asset deliver leg. It:

- clones the JSON-RPC request context onto a fresh `sendasset` request,
- builds the params `[asset_id, dest_address, units, {return_skeleton: true, broadcast: false, fee_rate?}]`,
- invokes `sendasset().HandleRequest(...)` and decodes the returned skeleton hex into a `CMutableTransaction`,
- collects the asset and BTC inputs `sendasset` selected (from the `asset_inputs` and `btc_inputs` arrays) into an `inputs_to_lock` set,
- locates the delivery output by matching the destination `scriptPubKey` together with the parsed asset tag (`assets::ParseAssetTag(out.vExt)` matching `asset_id` and `units`),
- records change output indices (from the skeleton's `outputs` array, by `change` type or by falling back to wallet-owned non-delivery outputs).

It returns a `ForwardAssetSkeletonResult` (`src/wallet/rpc/contracts.cpp:11127`):

```cpp
struct ForwardAssetSkeletonResult
{
    CMutableTransaction tx;                       // skeleton transaction
    std::set<COutPoint>  inputs_to_lock;          // asset + BTC inputs sendasset selected
    std::vector<size_t>  change_indices;          // change output positions
    std::optional<size_t> deliver_output_index;   // located asset delivery output
    CAmount estimated_fee{0};
};
```

If `sendasset` returns no skeleton hex, the helper throws `RPC_INTERNAL_ERROR`; if the expected asset delivery output cannot be located in the skeleton, it throws `RPC_WALLET_ERROR`.

A sibling helper `BuildForwardNativeSkeleton` (`src/wallet/rpc/contracts.cpp:11136`) covers native-BTC deliver legs, funding directly via `FundTransaction` and locating the delivery output by `scriptPubKey` plus value.

## Architecture

### Skeleton flow (self-delivery)

```
1. User calls: forward.build_self_delivery(offer_id)
2. Builder identifies: short_party.deliver_leg = {asset_id: X, units: Y}
3. Call BuildForwardAssetSkeleton:
   -> sendasset(asset_id=X, dest=escrow_address, units=Y, {return_skeleton: true, broadcast: false})
   -> Returns: {tx: skeleton, deliver_output_index, change_indices, inputs_to_lock}
4. Builder merges:
   tx.vin  = [vault_input] + skeleton.tx.vin
   tx.vout = [escrow_output (from skeleton), margin_output] + skeleton change outputs
5. Call FundTransaction with vault + skeleton inputs pre-selected
6. Re-apply asset tags to escrow + margin + change outputs (FundTransaction strips vExt)
7. Lock skeleton inputs
8. Return PSBT with output-index annotations
```

### Builders that use the skeleton helper

| Builder | Source |
|---------|--------|
| `BuildForwardSelfDeliveryShort` | `src/wallet/rpc/contracts.cpp:11897` (skeleton at `:12012`) |
| `BuildForwardSelfDeliveryLong` | `src/wallet/rpc/contracts.cpp:12323` (skeleton at `:12449`) |
| `BuildForwardEscrowClaimLong` | `src/wallet/rpc/contracts.cpp:12756` (skeleton at `:12822`) |
| `BuildForwardEscrowClaimShort` | `src/wallet/rpc/contracts.cpp:13231` (skeleton at `:13303`) |
| Cooperative close (`forward_build_coop_close`) | `src/wallet/rpc/contracts.cpp:16332` (per-party skeletons at `:16914`, `:17439`) |

The escrow-refund builders (`BuildForwardEscrowRefundShort` at `src/wallet/rpc/contracts.cpp:13717`, `BuildForwardEscrowRefundLong` at `:13953`) do not use the `BuildForwardAssetSkeleton` helper: a refund returns exactly what was escrowed, so there is no asset selection or change to compute, and the asset tag is applied directly with `BuildAssetTagTlv`. `forward_build_open` (`src/wallet/rpc/contracts.cpp:15019`) constructs the opening PSBT (the two IM vaults plus any premium) and supports both native-BTC and asset-based initial margin; rather than calling `BuildForwardAssetSkeleton`, it performs its own asset input selection and change handling inline (and uses a direct `sendasset` skeleton call for the short-party asset margin leg), re-applying asset tags with `BuildAssetTagTlv`.

### Key invariants

1. **Vault sequences.** Covenant vault spends set `nSequence = CTxIn::SEQUENCE_FINAL - 1` (`0xfffffffe`) for RBF/CLTV behavior (e.g. `src/wallet/rpc/contracts.cpp:11986`, `:12174`, `:12248`, `:12423`). This is re-applied after `FundTransaction`, which resets sequences. CLTV-enforced vault inputs instead use `nSequence = 0`.

2. **Asset-tag restoration.** `FundTransaction` strips `vExt` fields, so the builders re-apply asset tags via `BuildAssetTagTlv` after funding:
   - the escrow / delivery output (from `deliver_leg.asset_id` and `deliver_leg.units`),
   - the margin output (from `margin_leg.asset_id` and `margin_leg.units`),
   - the skeleton change outputs (recorded before funding).

3. **UTXO locking.** Skeleton-selected inputs are locked via `wallet.LockCoin` (e.g. `src/wallet/rpc/contracts.cpp:12258`, `:12723`, `:13129`) to prevent accidental double-spend between PSBT creation and signing.

4. **Output indices.** Builders track and annotate the delivery/escrow output index (from the skeleton), the margin output index, and the change output positions for PSBT consumers.

## Comparison: repo, spot, forward

| Aspect | Repo | Spot | Forward |
|--------|------|------|---------|
| Asset legs via `sendasset` skeleton | borrower (principal) leg | each wallet builds its own leg | each wallet builds its own leg |
| Counterparty leg construction | lender builds toward borrower | each wallet builds its own | each wallet builds its own |
| Metadata support (KYC, key wrap) | borrower leg | full | full |
| UTXO locking | yes | yes | yes |
| Change tracking | yes | yes | yes |
| Vault integration | yes | yes | yes |

In the spot path, each wallet calls `sendasset` for its own asset leg toward the counterparty's receive address (`src/wallet/rpc/contracts.cpp:9358`). In the repo path, the principal (asset) leg is built by the borrower via a `sendasset` skeleton (`src/wallet/rpc/contracts.cpp:3919`), while the lender's leg is built locally.

## Testing

`test/functional/feature_covenant_fwdoption.py` exercises the skeleton path end to end, including multi-asset forward settlement with a skeleton-based self-delivery, escrow claim, and cooperative close. It asserts the delivery/escrow/payment/claim/margin output indices reported by each builder, verifies asset tags on the resulting outputs, and confirms the skeleton-selected inputs are present.

## Quick reference

```cpp
// Self-delivery
BuildForwardSelfDeliveryShort  -> BuildForwardAssetSkeleton
BuildForwardSelfDeliveryLong   -> BuildForwardAssetSkeleton

// Escrow claim
BuildForwardEscrowClaimLong    -> BuildForwardAssetSkeleton
BuildForwardEscrowClaimShort   -> BuildForwardAssetSkeleton

// Cooperative close
forward_build_coop_close       -> BuildForwardAssetSkeleton (per party)

// Helper
BuildForwardAssetSkeleton      -> sendasset().HandleRequest
```

The taproot vault scripts that these covenant spends unlock are constructed by the forward builders alongside the asset deliver legs described here.
