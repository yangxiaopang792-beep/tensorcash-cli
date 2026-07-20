// Copyright (c) 2018-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_TEST_UTIL_H
#define BITCOIN_QT_TEST_UTIL_H

#include <chrono>

#include <interfaces/node.h>
#include <node/context.h>

#include <qglobal.h>

QT_BEGIN_NAMESPACE
class QString;
QT_END_NAMESPACE

/**
 * Press "Ok" button in message box dialog.
 *
 * @param text - Optionally store dialog text.
 * @param msec - Number of milliseconds to pause before triggering the callback.
 */
void ConfirmMessage(QString* text, std::chrono::milliseconds msec);

class ScopedNodeContextSetter
{
public:
    ScopedNodeContextSetter(interfaces::Node& node, node::NodeContext* replacement)
        : m_node(node), m_previous(node.context())
    {
        m_node.setContext(replacement);
    }

    ScopedNodeContextSetter(const ScopedNodeContextSetter&) = delete;
    ScopedNodeContextSetter& operator=(const ScopedNodeContextSetter&) = delete;

    ~ScopedNodeContextSetter()
    {
        m_node.setContext(m_previous);
    }

private:
    interfaces::Node& m_node;
    node::NodeContext* m_previous;
};

#endif // BITCOIN_QT_TEST_UTIL_H
