Pricing RPC Interface
=====================

TensorCash provides a comprehensive pricing and valuation framework for repo and forward contracts. This document describes the pricing RPC endpoints.

## Overview

The pricing RPCs enable users to:
- Obtain mark-to-market (MTM) valuations for repo and forward contracts
- Compute option Greeks (delta, gamma, vega, theta, rho)
- Scan for pricing warnings and risk indicators
- View aggregated portfolio statistics

All pricing RPCs require market data to be pushed via the `pricing.market.*` endpoints before use.

## Prerequisites

Before using pricing RPCs, ensure you have pushed the required market data:

1. **Discount Curves**: Interest rate curves for each currency
2. **FX Rates**: Exchange rates between asset pairs
3. **Volatility Surfaces**: Implied volatility data for assets with optionality
4. **Correlations** (optional): For multi-asset portfolios

Example market data setup:

```bash
# Push a discount curve for BTC
bitcoin-cli -rpcwallet=default pricing.market.push_curve \
  '{"asset":"BTC", "is_native":true, "tenors":[1,30,90,365], "rates":[0.05,0.05,0.05,0.05], "timestamp":0}'

# Push FX rate
bitcoin-cli -rpcwallet=default pricing.market.push_fx \
  '{"base_asset":"ASSET_ID", "base_is_native":false, "quote_asset":"BTC", "quote_is_native":true, "rate":0.001, "timestamp":0}'

# Push volatility surface
bitcoin-cli -rpcwallet=default pricing.market.push_vol_surface \
  '{"asset":"ASSET_ID", "is_native":false, "expiries":[30,90,180,365], "strikes":[0.8,1.0,1.2], "vols":[[0.3,0.25,0.3],[0.28,0.25,0.28],[0.26,0.25,0.26],[0.25,0.25,0.25]], "timestamp":0}'
```

## RPC Endpoints

### pricing.repo.quote

Compute mark-to-market valuation for a repo (repurchase agreement) contract.

**Synopsis:**
```
pricing.repo.quote "source_type" ( "registry_id" ) ( inline_terms ) ( "report_asset" ) ( report_is_native ) ( compute_greeks ) ( "source" )
```

**Arguments:**

1. `source_type` (string, required): Contract source - either `"registry"` or `"inline"`
2. `registry_id` (string, optional): Registry contract ID (required if source_type="registry")
3. `inline_terms` (object, optional): Inline repo terms (required if source_type="inline")
   - `principal_asset` (string): Principal asset ID
   - `principal_is_native` (boolean): True if principal is native BTC
   - `principal_units` (numeric): Principal amount in satoshis/units
   - `interest_asset` (string): Interest asset ID
   - `interest_is_native` (boolean): True if interest is native BTC
   - `interest_units` (numeric): Interest amount
   - `collateral_asset` (string): Collateral asset ID
   - `collateral_is_native` (boolean): True if collateral is native BTC
   - `collateral_units` (numeric): Collateral amount
   - `maturity_height` (numeric): Maturity block height
   - `safety_k` (numeric, default=144): Safety window in blocks
4. `report_asset` (string, default=""): Reporting currency (empty for TSC)
5. `report_is_native` (boolean, default=false): True if reporting currency is native BTC
6. `compute_greeks` (boolean, default=true): Compute option Greeks
7. `source` (string, default="mark"): Price data source (`"mark"` manual entries, `"market"` calibrated feeds)

**Result:**
```json
{
  "principal_pv": 1.00000000,          // Present value of principal
  "interest_pv": 0.04995000,           // Present value of interest
  "collateral_pv": 2.00000000,         // Present value of collateral
  "collateral_option": 0.02500000,     // Value of borrower walkaway (put) option
  "lender_mtm": 1.02495000,            // Lender's mark-to-market
  "borrower_mtm": -1.02495000,         // Borrower's mark-to-market
  "coverage_ratio": 1.90476190,        // Collateral coverage ratio
  "ltv_pct": 52.50000000,              // Loan-to-value percentage
  "over_collat_pct": 90.47619048,      // Over-collateralization percentage
  "collateral_greeks": {               // Option Greeks (if compute_greeks=true)
    "delta": 0.65432100,
    "gamma": 0.01234567,
    "vega": 0.23456789,
    "theta": -0.00123456,
    "rho": 0.01234567
  },
  "warnings": [                        // Diagnostic warnings
    {
      "severity": "WARNING",
      "category": "coverage",
      "message": "Coverage ratio below recommended threshold",
      "threshold": 2.0
    }
  ]
}
```

**Examples:**

```bash
# Quote a repo from the registry
bitcoin-cli -rpcwallet=lender pricing.repo.quote \
  "registry" "CONTRACT_ID_HEX"

# Quote an inline repo (prospective quote)
bitcoin-cli -rpcwallet=lender pricing.repo.quote \
  "inline" "" \
  '{"principal_asset":"BTC", "principal_is_native":true, "principal_units":100000000, "interest_asset":"BTC", "interest_is_native":true, "interest_units":5000000, "collateral_asset":"ASSET_ID", "collateral_is_native":false, "collateral_units":2000, "maturity_height":850000, "safety_k":144}'

# Quote without computing Greeks
bitcoin-cli -rpcwallet=lender pricing.repo.quote \
  "registry" "CONTRACT_ID" "" false false
```

**Use Cases:**

- **Lenders**: Assess MTM value of outstanding loans
- **Borrowers**: Determine cost of early termination
- **Risk Management**: Monitor coverage ratios and option exposure
- **Prospective Quotes**: Price hypothetical repos before contract creation

---

### pricing.forward.quote

Compute mark-to-market valuation for a forward (IM-capped DvP) contract.

**Synopsis:**
```
pricing.forward.quote "source_type" ( "registry_id" ) ( inline_terms ) ( "report_asset" ) ( report_is_native ) ( compute_greeks )
```

**Arguments:**

1. `source_type` (string, required): Contract source - `"registry"` or `"inline"`
2. `registry_id` (string, optional): Registry contract ID (required if source_type="registry")
3. `inline_terms` (object, optional): Inline forward terms (required if source_type="inline")
   - `alice_deliver_asset` (string): Asset Alice delivers
   - `alice_deliver_units` (numeric): Units Alice delivers
   - `alice_im_asset` (string): Alice's initial margin asset
   - `alice_im_units` (numeric): Alice's initial margin amount
   - `bob_deliver_asset` (string): Asset Bob delivers
   - `bob_deliver_units` (numeric): Units Bob delivers
   - `bob_im_asset` (string): Bob's initial margin asset
   - `bob_im_units` (numeric): Bob's initial margin amount
   - `premium_asset` (string, default=""): Premium asset (if any)
   - `premium_units` (numeric, default=0): Premium amount
   - `deadline_short` (numeric): Bob's deadline (block height)
   - `safety_k` (numeric, default=144): Safety window in blocks
4. `report_asset` (string, default=""): Reporting currency
5. `report_is_native` (boolean, default=false): True if reporting currency is native BTC
6. `compute_greeks` (boolean, default=true): Compute spread option Greeks

**Result:**
```json
{
  "pv_receive": 1.50000000,            // PV of what Alice receives (Bob delivers)
  "pv_pay": 1.00000000,                // PV of what Alice pays (Alice delivers)
  "net_spread_value": 0.50000000,      // pv_receive - pv_pay
  "premium_pv": 0.00000000,            // Premium PV (paid at t=0)
  "alice_short_call_value": -0.05000000, // Alice's short call on Bob's IM
  "alice_long_put_value": 0.03000000,   // Alice's long put on her own IM
  "alice_mtm": 0.48000000,             // Alice's total MTM
  "bob_mtm": -0.48000000,              // Bob's MTM (-alice_mtm)
  "im_coverage_alice": 0.10000000,     // Alice's IM / pv_pay
  "im_coverage_bob": 0.03333333,       // Bob's IM / pv_receive
  "spread_greeks_call": {              // Greeks for short call component
    "delta": -0.45678900,
    "gamma": -0.01234567,
    "vega": -0.12345678,
    "theta": 0.00123456,
    "rho": -0.00987654
  },
  "spread_greeks_put": {               // Greeks for long put component
    "delta": 0.23456789,
    "gamma": 0.00987654,
    "vega": 0.09876543,
    "theta": -0.00098765,
    "rho": 0.00654321
  },
  "warnings": [
    {
      "severity": "WARNING",
      "category": "deadline",
      "message": "Contract approaching deadline"
    }
  ]
}
```

**Examples:**

```bash
# Quote a forward from the registry
bitcoin-cli -rpcwallet=alice pricing.forward.quote \
  "registry" "CONTRACT_ID_HEX"

# Quote an inline forward
bitcoin-cli -rpcwallet=alice pricing.forward.quote \
  "inline" "" \
  '{"alice_deliver_asset":"BTC", "alice_deliver_units":100000000, "alice_im_asset":"BTC", "alice_im_units":10000000, "bob_deliver_asset":"ASSET_ID", "bob_deliver_units":1500, "bob_im_asset":"ASSET_ID", "bob_im_units":150, "premium_asset":"", "premium_units":0, "deadline_short":850000, "safety_k":144}'
```

**Use Cases:**

- **Alice (Long Party)**: Monitor MTM of forward position
- **Bob (Short Party)**: Assess cost of settlement vs. timeout
- **Options Traders**: Track Greeks for IM-capped spread options
- **Pre-Trade Analysis**: Price hypothetical forwards before execution

---

### pricing.diagnostics.scan

Scan all repo and forward contracts for pricing warnings, sorted by severity.

**Synopsis:**
```
pricing.diagnostics.scan ( "contract_type" ) ( "min_severity" ) ( limit ) ( "report_asset" )
```

**Arguments:**

1. `contract_type` (string, default="all"): Filter - `"all"`, `"repo"`, or `"forward"`
2. `min_severity` (string, default="INFO"): Minimum severity - `"INFO"`, `"WARNING"`, or `"CRITICAL"`
3. `limit` (numeric, default=50): Maximum number of contracts to return
4. `report_asset` (string, default=""): Reporting currency

**Result:**
```json
[
  {
    "contract_type": "repo",
    "contract_id": "CONTRACT_ID_HEX",
    "mtm_value": 1.02495000,
    "warnings": [
      {
        "severity": "CRITICAL",
        "category": "coverage",
        "message": "Collateral coverage critically low",
        "threshold": 1.2
      },
      {
        "severity": "WARNING",
        "category": "deadline",
        "message": "Contract approaching maturity"
      }
    ]
  },
  ...
]
```

Contracts are sorted by maximum warning severity (CRITICAL first).

**Warning Categories:**

- `coverage`: Collateral/margin coverage issues
- `deadline`: Time-to-maturity warnings
- `market_data`: Missing or stale market data
- `model`: Pricing model limitations or failures

**Examples:**

```bash
# Scan all contracts for critical warnings only
bitcoin-cli -rpcwallet=default pricing.diagnostics.scan \
  "all" "CRITICAL" 20

# Scan only repo contracts
bitcoin-cli -rpcwallet=default pricing.diagnostics.scan \
  "repo" "WARNING" 50

# Scan forwards with INFO-level detail
bitcoin-cli -rpcwallet=default pricing.diagnostics.scan \
  "forward" "INFO" 100
```

**Use Cases:**

- **Risk Management**: Daily scans for undercollateralized positions
- **Operations**: Monitor contracts approaching maturity
- **Compliance**: Audit trail of pricing warnings
- **Alerting**: Trigger notifications on CRITICAL warnings

---

### pricing.portfolio.summary

Compute aggregated portfolio statistics across all repo and forward contracts.

**Synopsis:**
```
pricing.portfolio.summary ( "report_asset" ) ( compute_greeks )
```

**Arguments:**

1. `report_asset` (string, default=""): Reporting currency
2. `compute_greeks` (boolean, default=false): Aggregate portfolio Greeks

**Result:**
```json
{
  "total_repo_count": 5,
  "total_forward_count": 3,
  "total_repo_mtm": 5.12475000,
  "total_forward_mtm": 1.44000000,
  "net_portfolio_mtm": 6.56475000,
  "critical_warnings_count": 1,
  "warning_count": 3,
  "portfolio_greeks": {                // Only if compute_greeks=true
    "total_delta": 2.34567890,
    "total_vega": 0.98765432,
    "gamma_note": "Gamma sums are approximate (non-additive across contracts)"
  }
}
```

**Examples:**

```bash
# Portfolio summary without Greeks
bitcoin-cli -rpcwallet=default pricing.portfolio.summary

# Portfolio summary with aggregated Greeks
bitcoin-cli -rpcwallet=default pricing.portfolio.summary \
  "" true

# Portfolio summary in specific reporting currency
bitcoin-cli -rpcwallet=default pricing.portfolio.summary \
  "ASSET_ID_HEX" false
```

**Use Cases:**

- **Portfolio Management**: Monitor total exposure across all contracts
- **Risk Reporting**: Daily P&L and risk metrics
- **Greeks Aggregation**: Portfolio-level delta and vega hedging
- **Executive Dashboards**: High-level portfolio health

**Important Notes:**

- Delta and vega are approximately additive across contracts
- Gamma is **not additive** - portfolio gamma is an approximation
- MTM values sum exactly across contracts
- Warning counts reflect unique warnings, not contract counts

---

## Contract Sourcing Modes

All pricing RPCs support two sourcing modes:

### Registry Sourcing

Load contract terms from the wallet's contract registry. This mode is used for pricing existing, active contracts.

**Advantages:**
- Automatic term retrieval
- Reflects actual on-chain state
- Suitable for production MTM

**Example:**
```bash
bitcoin-cli -rpcwallet=lender pricing.repo.quote \
  "registry" "a1b2c3d4..."
```

### Inline Sourcing

Specify contract terms directly in the RPC call. This mode is used for prospective quotes and hypothetical scenarios.

**Advantages:**
- No contract creation required
- Supports "what-if" analysis
- Pre-trade pricing

**Example:**
```bash
bitcoin-cli -rpcwallet=lender pricing.repo.quote \
  "inline" "" '{"principal_asset":"BTC", ...}'
```

---

## Reporting Currency

All pricing RPCs accept an optional reporting currency via `report_asset` and `report_is_native` parameters.

- **Default** (empty string): Use TSC (TensorCash native currency) as reporting currency
- **Native BTC**: Set `report_asset=""` and `report_is_native=true`
- **Custom Asset**: Set `report_asset="ASSET_ID"` and `report_is_native=false`

All present values, MTMs, and Greeks are denominated in the reporting currency.

---

## Option Greeks

When `compute_greeks=true`, the pricing RPCs compute option sensitivities using the Black-Scholes-Merton framework:

- **Delta (Δ)**: Sensitivity to underlying price (∂V/∂S)
- **Gamma (Γ)**: Convexity, rate of change of delta (∂²V/∂S²)
- **Vega (ν)**: Sensitivity to volatility (∂V/∂σ)
- **Theta (Θ)**: Time decay (-∂V/∂t)
- **Rho (ρ)**: Sensitivity to interest rate (∂V/∂r)

**Repo Greeks**: Computed for the collateral call option (borrower's right to reclaim collateral)

**Forward Greeks**: Computed separately for:
- Short call on Bob's IM (Alice's perspective)
- Long put on Alice's IM (Alice's perspective)

**Greeks Aggregation**: Portfolio delta and vega are approximately additive. Gamma is non-additive; the `gamma_note` field warns about this limitation.

---

## Workflow Examples

### Daily Portfolio Valuation

```bash
# 1. Check market data status
bitcoin-cli -rpcwallet=default pricing.market.status

# 2. Update market data if stale
bitcoin-cli -rpcwallet=default pricing.market.push_curve '...'
bitcoin-cli -rpcwallet=default pricing.market.push_fx '...'
bitcoin-cli -rpcwallet=default pricing.market.push_vol_surface '...'

# 3. Scan for critical warnings
bitcoin-cli -rpcwallet=default pricing.diagnostics.scan \
  "all" "CRITICAL" 50

# 4. Get portfolio summary
bitcoin-cli -rpcwallet=default pricing.portfolio.summary \
  "" true

# 5. Investigate specific contracts with warnings
bitcoin-cli -rpcwallet=default pricing.repo.quote \
  "registry" "CONTRACT_ID"
```

### Pre-Trade Analysis

```bash
# 1. Price a prospective repo
bitcoin-cli -rpcwallet=lender pricing.repo.quote \
  "inline" "" '{"principal_asset":"BTC", "principal_is_native":true, ...}'

# 2. Adjust terms and re-price
bitcoin-cli -rpcwallet=lender pricing.repo.quote \
  "inline" "" '{"principal_asset":"BTC", "collateral_units":2500, ...}'

# 3. Once satisfied, create the actual contract
bitcoin-cli -rpcwallet=lender repo.offer_create '...'
```

### Risk Monitoring

```bash
# 1. Scan for undercollateralized repos
bitcoin-cli -rpcwallet=default pricing.diagnostics.scan \
  "repo" "WARNING" 100 | jq '.[] | select(.warnings[].category == "coverage")'

# 2. Get detailed quote for each flagged contract
for cid in $(... | jq -r '.contract_id'); do
  bitcoin-cli -rpcwallet=default pricing.repo.quote \
    "registry" "$cid"
done

# 3. Aggregate portfolio Greeks for hedging
bitcoin-cli -rpcwallet=default pricing.portfolio.summary \
  "" true | jq '.portfolio_greeks'
```

---

## Error Handling

Pricing RPCs return descriptive errors for common issues:

- **Missing market data**: `"No discount curve for asset X"`
- **Stale data**: `"Volatility surface for asset X is stale (age > threshold)"`
- **Invalid contract**: `"Repo contract not found in registry"`
- **Missing parameters**: `"inline_terms required for source_type='inline'"`
- **Pricing model failure**: `"Black-Scholes pricing failed: negative variance"`

Warnings (non-fatal) are returned in the `warnings` array of the response.

---

## Performance Considerations

- **Greeks Computation**: Setting `compute_greeks=false` reduces computation time by ~30%
- **Portfolio Summary**: Complexity scales linearly with number of contracts
- **Diagnostics Scan**: Use `limit` parameter to cap results for large portfolios
- **Market Data**: Cache market data in memory; updates are incremental

---

## See Also

- **Market Data Management**: `pricing.market.*` RPCs
- **Valuation Engine**: C++ pricing modules
- **Repo Contracts**: `repo.offer_create`, `repo.accept`, etc.
- **Forward Contracts**: Forward contract creation and settlement RPCs
- **Functional Tests**: `test/functional/feature_pricing_rpc.py`

---

## Appendix: Warning Reference

### Coverage Category

| Severity | Message | Threshold |
|----------|---------|-----------|
| CRITICAL | Collateral coverage critically low | < 1.2x |
| WARNING | Coverage ratio below recommended threshold | < 2.0x |
| INFO | Coverage ratio adequate | >= 2.0x |

### Deadline Category

| Severity | Message | Threshold |
|----------|---------|-----------|
| CRITICAL | Contract at or past deadline | <= 0 blocks |
| WARNING | Contract approaching deadline | < 144 blocks (~1 day) |
| INFO | Deadline approaching | < 1008 blocks (~1 week) |

### Market Data Category

| Severity | Message | Threshold |
|----------|---------|-----------|
| CRITICAL | Missing required market data | N/A |
| WARNING | Market data is stale | Age > 86400s (1 day) |
| INFO | Market data updated | Age <= 86400s |

### Model Category

| Severity | Message | Threshold |
|----------|---------|-----------|
| CRITICAL | Pricing model failure | N/A |
| WARNING | Greeks computation failed | N/A |
| INFO | Model approximation in use | N/A |

The pricing RPC interface provides repo quote, forward quote, diagnostics scan, and portfolio summary endpoints.
