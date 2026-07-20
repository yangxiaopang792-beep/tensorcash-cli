// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_CONTRACTDETAILDIALOG_H
#define BITCOIN_QT_CONTRACTDETAILDIALOG_H

#include <QDialog>
#include <QLabel>
#include <QTextEdit>
#include <QPushButton>
#include <QVariantMap>
#include <QGroupBox>
#include <QTableWidget>

/**
 * Dialog for displaying detailed contract information.
 * Shows full contract terms, current status, and available actions.
 */
class WalletModel;

class ContractDetailDialog : public QDialog
{
    Q_OBJECT

public:
    explicit ContractDetailDialog(const QVariantMap& contractData, WalletModel* walletModel, QWidget* parent = nullptr);

private Q_SLOTS:
    void onShowAdvancedView();
    void onShowScriptPreview();

private:
    void setupUI();
    void populateContractDetails();
    void populatePricingBreakdown();
    void populateRepoPricing(const QString& contractId);
    void populateForwardPricing(const QString& contractId);
    void populateDifficultyPricing(const QString& contractId);
    QString formatContractInfo() const;
    QString getContractRawJson() const;

    QVariantMap contractData;
    WalletModel* walletModel{nullptr};

    // UI components
    QLabel* contractIdLabel{nullptr};
    QLabel* statusLabel{nullptr};
    QTextEdit* detailsText{nullptr};
    QGroupBox* pricingGroup{nullptr};
    QTableWidget* pricingTable{nullptr};
    QPushButton* showAdvancedButton{nullptr};
    QPushButton* showScriptButton{nullptr};
    QPushButton* closeButton{nullptr};
};

#endif // BITCOIN_QT_CONTRACTDETAILDIALOG_H
