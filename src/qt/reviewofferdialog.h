// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_REVIEWOFFERDIALOG_H
#define BITCOIN_QT_REVIEWOFFERDIALOG_H

#include <QDialog>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>
#include <QString>
#include <QVariantMap>

class WalletModel;

/**
 * Dialog for reviewing imported offers (borrower/acceptor side).
 * Displays offer terms, risk assessment, and accept/reject actions.
 */
class ReviewOfferDialog : public QDialog
{
    Q_OBJECT

public:
    explicit ReviewOfferDialog(WalletModel* walletModel, const QString& offerId, const QVariantMap& offerData, QWidget* parent = nullptr);

    // Returns acceptance JSON if accepted, empty QString if rejected
    QString getAcceptanceJson() const { return acceptanceJson; }
    bool wasAccepted() const { return accepted; }

private Q_SLOTS:
    void onAcceptOffer();
    void onReject();

private:
    void setupUI();
    void populateOfferDetails();
    QString formatAmount(double amount, int decimals) const;
    QString calculateRiskMetrics();

    WalletModel* walletModel{nullptr};
    QString offerId;
    QVariantMap offerData;
    QString acceptanceJson;
    bool accepted;

    // UI components
    QLabel* offerIdLabel{nullptr};
    QLabel* sessionInfoLabel{nullptr};
    QLabel* termsLabel{nullptr};
    QLabel* riskAssessmentLabel{nullptr};
    QPushButton* acceptButton{nullptr};
    QPushButton* rejectButton{nullptr};
};

#endif // BITCOIN_QT_REVIEWOFFERDIALOG_H
