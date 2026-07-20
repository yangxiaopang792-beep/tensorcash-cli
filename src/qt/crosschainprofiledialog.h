// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_QT_CROSSCHAINPROFILEDIALOG_H
#define BITCOIN_QT_CROSSCHAINPROFILEDIALOG_H

#include <QDialog>

QT_BEGIN_NAMESPACE
class QComboBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QTableWidget;
QT_END_NAMESPACE

class WalletModel;

/**
 * @brief Dialog for managing external settlement profiles.
 *
 * Settlement profiles store external chain addresses (BTC, ETH, TRON)
 * used as payout destinations in cross-chain swaps. Each profile has
 * a signing reference, preferred asset, and fee speed.
 */
class CrossChainProfileDialog : public QDialog
{
    Q_OBJECT

public:
    explicit CrossChainProfileDialog(WalletModel* model, QWidget* parent = nullptr);
    ~CrossChainProfileDialog() override;

private Q_SLOTS:
    void onAddProfile();
    void onRemoveProfile();
    void onChainChanged(int index);
    void refreshProfileList();

private:
    void setupUI();

    WalletModel* walletModel{nullptr};

    // Profile list
    QTableWidget* profileTable{nullptr};
    QPushButton* removeButton{nullptr};

    // Add form
    QLineEdit* profileIdEdit{nullptr};
    QLineEdit* labelEdit{nullptr};
    QComboBox* chainCombo{nullptr};
    QLineEdit* addressEdit{nullptr};
    QLabel* addressHintLabel{nullptr};
    QComboBox* signerRefCombo{nullptr};
    QLineEdit* preferredAssetEdit{nullptr};
    QComboBox* feeSpeedCombo{nullptr};
    QPushButton* addButton{nullptr};
};

#endif // BITCOIN_QT_CROSSCHAINPROFILEDIALOG_H
