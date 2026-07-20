// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RPC_REGISTER_H
#define BITCOIN_RPC_REGISTER_H

#include <bitcoin-build-config.h> // IWYU pragma: keep

/** These are in one header file to avoid creating tons of single-function
 * headers for everything under src/rpc/ */
class CRPCTable;

void RegisterBlockchainRPCCommands(CRPCTable &tableRPC);
void RegisterFeeRPCCommands(CRPCTable&);
void RegisterMempoolRPCCommands(CRPCTable&);
void RegisterMiningRPCCommands(CRPCTable &tableRPC);
void RegisterNodeRPCCommands(CRPCTable&);
void RegisterNetRPCCommands(CRPCTable&);
void RegisterOutputScriptRPCCommands(CRPCTable&);
void RegisterRawTransactionRPCCommands(CRPCTable &tableRPC);
void RegisterRotateICURPC(CRPCTable &tableRPC);
void RegisterScalarRPC(CRPCTable &tableRPC);
void RegisterSignMessageRPCCommands(CRPCTable&);
void RegisterBIP322RPCCommands(CRPCTable&);
void RegisterSignerRPCCommands(CRPCTable &tableRPC);
void RegisterTxoutProofRPCCommands(CRPCTable&);
void RegisterCustomRPCCommands(CRPCTable&);
void RegisterCosignRPCCommands(CRPCTable&);
void RegisterOptionSeriesRPCCommands(CRPCTable&);

/// Send a command to the cosign bridge process.
/// Returns the bridge response as UniValue.  Throws on error.
/// Used by wallet-layer code (EthHtlcBackend) to drive bridge commands.
UniValue SendCosignBridgeCommand(const std::string& command, const UniValue& params);

/// Check if the cosign bridge is enabled and running.
bool IsCosignBridgeEnabled();

static inline void RegisterAllCoreRPCCommands(CRPCTable &t)
{
    RegisterBlockchainRPCCommands(t);
    RegisterFeeRPCCommands(t);
    RegisterMempoolRPCCommands(t);
    RegisterMiningRPCCommands(t);
    RegisterNodeRPCCommands(t);
    RegisterNetRPCCommands(t);
    RegisterOutputScriptRPCCommands(t);
    RegisterRawTransactionRPCCommands(t);
    RegisterRotateICURPC(t);
    RegisterScalarRPC(t);
    RegisterOptionSeriesRPCCommands(t);
    RegisterSignMessageRPCCommands(t);
    RegisterBIP322RPCCommands(t);
#ifdef ENABLE_EXTERNAL_SIGNER
    RegisterSignerRPCCommands(t);
#endif // ENABLE_EXTERNAL_SIGNER
    RegisterTxoutProofRPCCommands(t);
    RegisterCustomRPCCommands(t);
    RegisterCosignRPCCommands(t);
}

#endif // BITCOIN_RPC_REGISTER_H
