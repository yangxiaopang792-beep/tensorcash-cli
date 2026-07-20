// Copyright (c) 2024-2025 The TensorCash Core developers
// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_GUICONSTANTS_H
#define BITCOIN_QT_GUICONSTANTS_H

#include <chrono>
#include <cstdint>

using namespace std::chrono_literals;

/* A delay between model updates */
static constexpr auto MODEL_UPDATE_DELAY{250ms};

/* A delay between shutdown pollings */
static constexpr auto SHUTDOWN_POLLING_DELAY{200ms};

/* AskPassphraseDialog -- Maximum passphrase length */
static const int MAX_PASSPHRASE_SIZE = 1024;

/* BitcoinGUI -- Size of icons in status bar */
static const int STATUSBAR_ICONSIZE = 16;

static const bool DEFAULT_SPLASHSCREEN = true;

/* Invalid field background style */
#define STYLE_INVALID "border: 3px solid #FF8080"

/* Transaction list -- unconfirmed transaction */
#define COLOR_UNCONFIRMED QColor(128, 128, 128)
/* Transaction list -- negative amount */
#define COLOR_NEGATIVE QColor(255, 0, 0)
/* Transaction list -- bare address (without label) */
#define COLOR_BAREADDRESS QColor(140, 140, 140)
/* Transaction list -- TX status decoration - danger, tx needs attention */
#define COLOR_TX_STATUS_DANGER QColor(200, 100, 100)
/* Transaction list -- TX status decoration - default color */
#define COLOR_BLACK QColor(0, 0, 0)

/* Tooltips longer than this (in characters) are converted into rich text,
   so that they can be word-wrapped.
 */
static const int TOOLTIP_WRAP_THRESHOLD = 80;

/* Number of frames in spinner animation */
#define SPINNER_FRAMES 36

#define QAPP_ORG_NAME "TensorCash"
#define QAPP_ORG_DOMAIN "tensorcash.org"
#define QAPP_APP_NAME_DEFAULT "TensorCash-Qt"
#define QAPP_APP_NAME_TESTNET "TensorCash-Qt-testnet"
#define QAPP_APP_NAME_TESTNET4 "TensorCash-Qt-testnet4"
#define QAPP_APP_NAME_SIGNET "TensorCash-Qt-signet"
#define QAPP_APP_NAME_REGTEST "TensorCash-Qt-regtest"
// TensorCash chain app names.
// NOTE: mainnet uses "TensorCash-Qt-mainnet", NOT the bare "TensorCash-Qt"
// (== QAPP_APP_NAME_DEFAULT). The bare name is the historical SHARED boot
// namespace that every build wrote its QSettings strDataDir under, so reusing
// it for mainnet would let the mainnet app inherit a testnet build's stored
// datadir override. A distinct name keeps the mainnet QSettings (strDataDir +
// window prefs) isolated. Costless: there are no pre-existing desktop mainnet
// users to migrate.
#define QAPP_APP_NAME_TENSOR "TensorCash-Qt-mainnet"
#define QAPP_APP_NAME_TENSOR_TEST "TensorCash-Qt-testnet"
#define QAPP_APP_NAME_TENSOR_REG "TensorCash-Qt-regtest"

/* One gigabyte (GB) in bytes */
static constexpr uint64_t GB_BYTES{1000000000};

// Default prune target displayed in GUI.
static constexpr int DEFAULT_PRUNE_TARGET_GB{2};

#endif // BITCOIN_QT_GUICONSTANTS_H
