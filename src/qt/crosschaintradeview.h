// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_QT_CROSSCHAINTRADEVIEW_H
#define BITCOIN_QT_CROSSCHAINTRADEVIEW_H

#include <QWidget>

QT_BEGIN_NAMESPACE
class QLabel;
class QPushButton;
class QTableWidget;
class QTimer;
QT_END_NAMESPACE

class WalletModel;

/**
 * @brief Widget showing active cross-chain swap execution records.
 *
 * Displays:
 *   - Swap ID, state, chain, adapter
 *   - Confirmation depth counters for both chains
 *   - Countdown to refund boundary
 *   - Fee escalation level
 *   - Mempool / rebroadcast status
 *
 * This widget polls crossChainRecordList() periodically and
 * can also receive push updates from the CrossChainSwapManager
 * via SwapEvent callbacks.
 */
class CrossChainTradeView : public QWidget
{
    Q_OBJECT

public:
    explicit CrossChainTradeView(QWidget* parent = nullptr);
    ~CrossChainTradeView() override;

    void setWalletModel(WalletModel* model);

public Q_SLOTS:
    void refreshRecords();

private:
    void setupUI();
    QString stateToString(int state) const;
    QString stateToColor(int state) const;

    WalletModel* walletModel{nullptr};
    QTableWidget* recordsTable{nullptr};
    QLabel* summaryLabel{nullptr};
    QPushButton* refreshButton{nullptr};
    QTimer* refreshTimer{nullptr};
};

#endif // BITCOIN_QT_CROSSCHAINTRADEVIEW_H
