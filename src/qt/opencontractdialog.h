// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_OPENCONTRACTDIALOG_H
#define BITCOIN_QT_OPENCONTRACTDIALOG_H

#include <QDialog>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>
#include <QString>
#include <QVariantMap>
#include <QTimer>

class WalletModel;
class QProgressBar;

/**
 * Dialog for building and broadcasting opening transactions.
 * Displays funding requirements, initiates adaptor ceremony, and broadcasts opening PSBT.
 */
class OpenContractDialog : public QDialog
{
    Q_OBJECT

public:
    explicit OpenContractDialog(WalletModel* walletModel, const QString& offerId, const QString& contractType, const QVariantMap& offerData = QVariantMap(), QWidget* parent = nullptr);

    bool wasOpened() const { return opened; }
    QString getOpeningTxId() const { return openingTxId; }

private Q_SLOTS:
    void onBuildOpeningTransaction();
    void onCancel();
    void checkConfirmations();

private:
    void setupUI();
    void checkFundingRequirements();
    void updateStatusLabel(const QString& status);
    void showConfirmationTracking();

    WalletModel* walletModel{nullptr};
    QString offerId;
    QString contractType;
    QVariantMap offerData;
    bool opened;
    QString openingTxId;

    // UI components
    QLabel* contractIdLabel{nullptr};
    QLabel* statusLabel{nullptr};
    QLabel* fundingCheckLabel{nullptr};
    QLabel* nextStepsLabel{nullptr};
    QPushButton* buildButton{nullptr};
    QPushButton* cancelButton{nullptr};

    // Funding info
    double requiredAmount;
    bool fundingAvailable;

    // Confirmation tracking
    QTimer* confirmationTimer{nullptr};
    QDialog* confirmationDialog{nullptr};
    QLabel* confirmationStatusLabel{nullptr};
    QProgressBar* confirmationProgressBar{nullptr};
    int currentConfirmations;
};

#endif // BITCOIN_QT_OPENCONTRACTDIALOG_H
