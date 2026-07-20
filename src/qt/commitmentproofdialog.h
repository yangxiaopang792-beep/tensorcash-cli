// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_QT_COMMITMENTPROOFDIALOG_H
#define BITCOIN_QT_COMMITMENTPROOFDIALOG_H

#include <QDialog>
#include <QString>
#include <QVariantMap>

QT_BEGIN_NAMESPACE
class QLabel;
class QPushButton;
class QTextEdit;
QT_END_NAMESPACE

class WalletModel;

/**
 * @brief Dialog for adding commitment proof to spot atomic swaps
 *
 * Guides users through the process of:
 * 1. Joining PSBTs from both parties
 * 2. Adding commitment proof (proves decryption capability)
 * 3. Verifying counterparty's commitment
 * 4. Signing the transaction
 *
 * This implements the Pre-Signing Decryption Commitment workflow from
 * feature_covenant_spot.py Test 4.7
 */
class CommitmentProofDialog : public QDialog
{
    Q_OBJECT

public:
    explicit CommitmentProofDialog(WalletModel* model, const QString& offerId, const QString& myPsbt, QWidget* parent = nullptr);

    /** Get the PSBT with commitment proof added */
    QString getPsbtWithCommitment() const { return psbtWithCommitment; }

    /** Get commitment hash (for verification) */
    QString getCommitmentHash() const { return commitmentHash; }

    /** Check if commitment was successfully added */
    bool commitmentAdded() const { return m_commitmentAdded; }

private Q_SLOTS:
    void onAddCommitment();
    void onVerifyCommitments();

private:
    void setupUI();
    void updateStatus(const QString& message, bool isError = false);
    void determineExpectedCommitmentCount();

    WalletModel* walletModel{nullptr};
    QString m_offerId;
    QString m_myPsbt;
    QString psbtWithCommitment;
    QString commitmentHash;
    bool m_commitmentAdded{false};
    int m_expectedCommitmentCount;

    // UI elements
    QLabel* statusLabel{nullptr};
    QTextEdit* commitmentInfoEdit{nullptr};
    QPushButton* addCommitmentButton{nullptr};
    QPushButton* verifyButton{nullptr};
    QPushButton* acceptButton{nullptr};
};

#endif // BITCOIN_QT_COMMITMENTPROOFDIALOG_H
