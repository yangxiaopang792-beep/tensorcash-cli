#!/usr/bin/env python3
# Copyright (c) 2024 The TensorCash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""TensorCash-specific test configuration and helpers."""

def get_tensorcash_test_params(*,
                               disable_asn_corroboration=True,
                               disable_hysteresis=True,
                               disable_reorg_sampling=True,
                               disable_extapi=True,
                               additional_args=None):
    """
    Get standard TensorCash test parameters for deterministic testing.

    Args:
        disable_asn_corroboration: Disable ASN corroboration requirement
        disable_hysteresis: Set hysteresis base to 0 for predictable switching
        disable_reorg_sampling: Disable deep reorg body sampling
        disable_extapi: Disable external API for faster tests
        additional_args: Additional arguments to append

    Returns:
        List of command-line arguments for test nodes
    """
    args = []

    # Core debug flags
    args.extend([
        "-debug=net",
        "-debug=validation",
        "-whitelist=noban@127.0.0.1",
        "-par=1",  # Single thread for deterministic behavior
    ])

    # VDF SPV policy flags for deterministic testing
    if disable_asn_corroboration:
        # Disable ASN corroboration or set to minimum
        args.extend([
            "-spv-asn-min=1",  # Minimum 1 peer (instead of default 2)
            # Alternative: "-nospv-asn-corroboration" to disable entirely
        ])

    if disable_hysteresis:
        # Set hysteresis margin to 0 for predictable chain switching
        args.extend([
            "-spv-hysteresis-base-bps=0",  # No base margin (default ~50% of E)
            # Optionally reduce EMA alpha for less inertia
            # "-spv-hysteresis-alpha-bps=200",  # 2% (default)
        ])

    if disable_reorg_sampling:
        # Disable deep reorg body sampling
        args.append("-spv-reorg-sampling-threshold=999")  # Effectively disable

    if disable_extapi:
        # Disable external API for faster tests
        args.append("-useextapi=0")

    # Add any additional arguments
    if additional_args:
        args.extend(additional_args)

    return args

def get_vdf_spv_test_params(**kwargs):
    """Convenience wrapper for VDF SPV specific tests."""
    return get_tensorcash_test_params(**kwargs)

def get_tensorcash_regtest_params():
    """Get parameters for regtest with TensorCash features."""
    return [
        "-regtest",
        "-vdfspvcommitmentheight=0",  # Activate VDF SPV from genesis
        "-vdfspvvdfverifyheight=0",   # Activate VDF verification from genesis
        "-maxtipage=999999",           # Accept old timestamps for testing
    ]

# Standard test configurations
TENSORCASH_TEST_PARAMS = {
    'smoke': get_tensorcash_test_params(
        disable_asn_corroboration=True,
        disable_hysteresis=True,
        disable_reorg_sampling=True,
        disable_extapi=True
    ),
    'vdf_spv': get_vdf_spv_test_params(),
    'vdf_spv_with_sampling': get_vdf_spv_test_params(
        disable_reorg_sampling=False
    ),
    'vdf_spv_with_hysteresis': get_vdf_spv_test_params(
        disable_hysteresis=False
    ),
    'vdf_spv_full': get_vdf_spv_test_params(
        disable_asn_corroboration=False,
        disable_hysteresis=False,
        disable_reorg_sampling=False,
        disable_extapi=False
    ),
}