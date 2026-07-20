# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

add_executable(bench_bitcoin
  bench_bitcoin.cpp
  bench.cpp
  nanobench.cpp
# Benchmarks:
  addrman.cpp
  asset_validation.cpp
  base58.cpp
  groth16_verify.cpp
  bech32.cpp
  bip324_ecdh.cpp
  block_assemble.cpp
  ccoins_caching.cpp
  chacha20.cpp
  checkblockindex.cpp
  checkqueue.cpp
  cluster_linearize.cpp
  connectblock.cpp
  crypto_hash.cpp
  descriptors.cpp
  disconnected_transactions.cpp
  duplicate_inputs.cpp
  ellswift.cpp
  examples.cpp
  gcs_filter.cpp
  hashpadding.cpp
  index_blockfilter.cpp
  lockedpool.cpp
  logging.cpp
  mempool_ephemeral_spends.cpp
  mempool_eviction.cpp
  mempool_stress.cpp
  merkle_root.cpp
  parse_hex.cpp
  peer_eviction.cpp
  poly1305.cpp
  pool.cpp
  prevector.cpp
  random.cpp
  rollingbloom.cpp
  rpc_mempool.cpp
  sign_transaction.cpp
  streams_findbyte.cpp
  util_time.cpp
  verify_script.cpp
  xor.cpp
  vdf_verify.cpp
  sidecar_memory.cpp
  presync_load.cpp
)

target_link_libraries(bench_bitcoin
  core_interface
  test_util
  bitcoin_node
  Boost::headers
)

if(ENABLE_WALLET)
  target_sources(bench_bitcoin
    PRIVATE
      coin_selection.cpp
      wallet_balance.cpp
      wallet_create.cpp
      wallet_create_tx.cpp
      wallet_loading.cpp
      wallet_ismine.cpp
      wallet_migration.cpp
  )
  target_link_libraries(bench_bitcoin bitcoin_wallet)
endif()

add_test(NAME bench_sanity_check
  COMMAND bench_bitcoin -sanity-check
)

install_binary_component(bench_bitcoin)

# Utility to generate TensorCash block for benchmarking
add_executable(gen_tensorcash_block
  gen_tensorcash_block.cpp
)

target_link_libraries(gen_tensorcash_block
  core_interface
  test_util
  bitcoin_node
  bitcoin_common
)

if(ENABLE_WALLET)
  target_link_libraries(gen_tensorcash_block bitcoin_wallet)
endif()
