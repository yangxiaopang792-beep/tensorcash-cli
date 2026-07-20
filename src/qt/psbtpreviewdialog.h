// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_QT_PSBTPREVIEWDIALOG_H
#define BITCOIN_QT_PSBTPREVIEWDIALOG_H

#include <QDialog>

class WalletModel;

QT_BEGIN_NAMESPACE
class QLabel;
class QPushButton;
class QTextEdit;
class QTreeWidget;
class QTreeWidgetItem;
QT_END_NAMESPACE

/**
 * @brief Dialog for previewing PSBT details before broadcast
 *
 * Displays:
 * - Transaction summary (inputs, outputs, fee)
 * - Input details with amounts
 * - Output details with addresses and amounts
 * - Raw PSBT for advanced users
 * - Warning about irreversibility
 */
class PSBTPreviewDialog : public QDialog
{
    Q_OBJECT

public:
    explicit PSBTPreviewDialog(WalletModel* walletModel, const QString& psbt, const QString& context = "", QWidget* parent = nullptr);
    ~PSBTPreviewDialog();

    bool wasApproved() const { return approved; }

private Q_SLOTS:
    void onBroadcast();
    void onCancel();
    void onShowRawPSBT();

private:
    void setupUI();
    void analyzePSBT();
    QString formatAmount(int64_t sats) const;

    WalletModel* walletModel{nullptr};
    QString psbt;
    QString context;
    bool approved{false};

    // UI components
    QLabel* contextLabel{nullptr};
    QLabel* summaryLabel{nullptr};
    QTreeWidget* inputsTree{nullptr};
    QTreeWidget* outputsTree{nullptr};
    QLabel* feeLabel{nullptr};
    QLabel* warningLabel{nullptr};
    QPushButton* broadcastButton{nullptr};
    QPushButton* cancelButton{nullptr};
    QPushButton* showRawButton{nullptr};

    // Parsed PSBT data
    int inputCount{0};
    int outputCount{0};
    int64_t totalInput{0};
    int64_t totalOutput{0};
    int64_t fee{0};
};

#endif // BITCOIN_QT_PSBTPREVIEWDIALOG_H
