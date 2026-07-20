// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NETMESSAGEMAKER_H
#define BITCOIN_NETMESSAGEMAKER_H

#include <net.h>
#include <protocol.h>
#include <serialize.h>
#include <type_traits>

namespace NetMsg {
    template <typename T>
    auto SerializeAdaptor(T&& arg)
    {
        if constexpr (std::is_same_v<std::decay_t<T>, std::vector<CBlockHeader>>)
        {
            return HeadersMessage{std::forward<T>(arg)};
        }
        else
        {
            return std::forward<T>(arg);
        }
    }

    template <typename... Args>
    CSerializedNetMsg Make(std::string msg_type, Args&&... args)
    {
        CSerializedNetMsg msg;
        msg.m_type = std::move(msg_type);
        VectorWriter{msg.data, 0, SerializeAdaptor(std::forward<Args>(args))...};
        return msg;
    }
} // namespace NetMsg

#endif // BITCOIN_NETMESSAGEMAKER_H
