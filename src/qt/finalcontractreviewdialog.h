// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_QT_FINALCONTRACTREVIEWDIALOG_H
#define BITCOIN_QT_FINALCONTRACTREVIEWDIALOG_H

#include <QDialog>
#include <QString>
#include <QVariantMap>

QT_BEGIN_NAMESPACE
class QComboBox;
class QHBoxLayout;
class QLabel;
class QPushButton;
class QTextBrowser;
QT_END_NAMESPACE

/**
 * Dialog that forces both taker and maker to re-review finalized contract
 * details and raw JSON prior to signing. This replaces the old message-box
 * flow that only displayed zeroed placeholders.
 */
class FinalContractReviewDialog : public QDialog
{
    Q_OBJECT

public:
    struct Options {
        QString title;
        QString headingHtml;
        QString summaryHtml;
        QString offerId;
        QString sessionId;
        QString rawJson;
        QString rawJsonTitle;
        QString extraJson;
        QString extraJsonTitle;
        QString extraJsonButtonLabel;
        QString acceptLabel;
        QString rejectLabel;
        QString footnoteHtml;
        QString userRole;                 // "borrower" or "lender" (for labeling)
        QStringList criticalChecks;       // bulleted critical checks to highlight
        bool showFeeSelector{false};      // Show fee strategy selector (taker only)
        bool showPricingButton{false};    // Show "View Pricing" button
        QVariantMap contractTerms;        // Contract terms for pricing
        QString contractType;             // "repo", "forward", "option", "spot"
    };

    explicit FinalContractReviewDialog(const Options& options, QWidget* parent = nullptr);

    QString getSelectedFeeStrategy() const;

private Q_SLOTS:
    void onShowRawJson();
    void onShowExtraJson();
    void onShowPricing();

private:
    void buildUi();
    void openJsonDialog(const QString& title, const QString& json) const;

    Options m_options;
    QTextBrowser* m_summaryWidget{nullptr};
    QPushButton* m_rawJsonButton{nullptr};
    QPushButton* m_extraJsonButton{nullptr};
    QPushButton* m_pricingButton{nullptr};
    QComboBox* m_feeStrategyCombo{nullptr};
};

#endif // BITCOIN_QT_FINALCONTRACTREVIEWDIALOG_H
