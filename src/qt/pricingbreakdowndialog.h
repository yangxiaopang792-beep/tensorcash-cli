// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_QT_PRICINGBREAKDOWNDIALOG_H
#define BITCOIN_QT_PRICINGBREAKDOWNDIALOG_H

#include <QDialog>
#include <QString>
#include <QVariantMap>

QT_BEGIN_NAMESPACE
class QTableWidget;
class QPushButton;
class QLabel;
QT_END_NAMESPACE

class WalletModel;

/**
 * Dialog to display pricing breakdown for contracts
 * Can be opened from any context where inline pricing is not available
 */
class PricingBreakdownDialog : public QDialog
{
    Q_OBJECT

public:
    enum ContractType {
        Repo,
        Forward,
        Option,
        Spot,
        Difficulty
    };

    struct PricingData {
        ContractType type;
        QString contractId;          // For opened contracts
        QVariantMap inlineTerms;     // For offers/new contracts
        QString reportAsset;
        bool reportIsNative{true};
        QString priceSource{"mark"}; // "mark" or "market"
    };

    explicit PricingBreakdownDialog(WalletModel* model, const PricingData& data, QWidget* parent = nullptr);
    ~PricingBreakdownDialog() override = default;

private Q_SLOTS:
    void onRefreshPricing();
    void onTogglePriceSource();

private:
    void buildUI();
    void updatePricing();
    void displayRepoPricing();
    void displayForwardPricing();
    void displaySpotPricing();
    void displayDifficultyPricing();

    WalletModel* m_walletModel{nullptr};
    PricingData m_data;

    QTableWidget* m_pricingTable{nullptr};
    QPushButton* m_refreshButton{nullptr};
    QPushButton* m_toggleSourceButton{nullptr};
    QLabel* m_statusLabel{nullptr};
};

#endif // BITCOIN_QT_PRICINGBREAKDOWNDIALOG_H
