# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

# Do not use generator expressions in test sources because the
# SOURCES property is processed to gather test suite macros.
target_sources(test_bitcoin
  PRIVATE
    init_test_fixture.cpp
    wallet_test_fixture.cpp
    asset_wallet_tests.cpp
    db_tests.cpp
    coinselector_tests.cpp
    coinselection_tests.cpp
    feebumper_tests.cpp
    group_outputs_tests.cpp
    init_tests.cpp
    ismine_tests.cpp
    mldsa_wallet_tests.cpp
    pricing_tests.cpp
    valuation_tests.cpp
    psbt_wallet_tests.cpp
    signmessage_tests.cpp
    repo_tests.cpp
    fairsign_tests.cpp
    scriptpubkeyman_tests.cpp
    spend_tests.cpp
    vault_tests.cpp
    difficulty_contract_tests.cpp
    difficulty_pricer_tests.cpp
    scalar_forward_curve_tests.cpp
    scalar_cfd_pricer_tests.cpp
    option_series_tests.cpp
    option_series_wallet_tests.cpp
    scalar_note_pair_tests.cpp
    scalar_note_pair_wallet_tests.cpp
    scalar_cfd_contract_tests.cpp
    scalar_cfd_contract_wallet_tests.cpp
    wallet_crypto_tests.cpp
    wallet_tests.cpp
    wallet_transaction_tests.cpp
    walletdb_tests.cpp
    walletload_tests.cpp
)
target_link_libraries(test_bitcoin bitcoin_wallet)

set(_wallet_test_dl_lib ${CMAKE_DL_LIBS})
if(NOT _wallet_test_dl_lib)
  find_library(_wallet_test_dl_lib dl)
endif()
if(_wallet_test_dl_lib)
  target_link_libraries(test_bitcoin ${_wallet_test_dl_lib})
endif()
