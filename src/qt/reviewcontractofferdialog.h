// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_QT_REVIEWCONTRACTOFFERDIALOG_H
#define BITCOIN_QT_REVIEWCONTRACTOFFERDIALOG_H

#include <QDialog>
#include <QVariantMap>
#include <QJsonObject>

QT_BEGIN_NAMESPACE
class QLabel;
class QLineEdit;
class QPushButton;
class QTextEdit;
QT_END_NAMESPACE

class WalletModel;

/**
 * Dialog presented to takers when they review a bulletin-board repo offer.
 * At the term-sheet stage we collect the taker's repayment address and send it
 * to the maker via the trade request message. The actual `repo.accept` flow is
 * executed later once the maker re-issues a final contract with both parties'
 * addresses embedded.
 */
class ReviewContractOfferDialog : public QDialog
{
    Q_OBJECT

public:
    explicit ReviewContractOfferDialog(const QVariantMap& offerData,
                                       WalletModel* model,
                                       QWidget* parent = nullptr);

private Q_SLOTS:
    void onAccept();
    void onReject();
    void onGenerateBorrowerAddress();
    void onGenerateLenderAddress();
    void onShowRawJson();
    void onShowScriptPreview();
    void onShowPricing();
    void onShowGreeks();

private:
    void setupUI();
    void parseOfferPayload();
    QString formatOfferTerms() const;
    bool validateInputs();
    QString getOfferRawJson() const;

    QVariantMap offerData;
    WalletModel* walletModel;

    // UI components
    QTextEdit* termsDisplay{nullptr};
    QLineEdit* borrowerAddressEdit{nullptr};
    QLineEdit* lenderAddressEdit{nullptr};
    QPushButton* generateBorrowerButton{nullptr};
    QPushButton* generateLenderButton{nullptr};
    QPushButton* showJsonButton{nullptr};
    QPushButton* showScriptButton{nullptr};
    QPushButton* showPricingButton{nullptr};
    QPushButton* showGreeksButton{nullptr};
    QPushButton* acceptButton{nullptr};
    QPushButton* rejectButton{nullptr};

    // Parsed payload state
    bool payloadIsTermSheet{false};
    bool payloadIsFinalOffer{false};
    QString m_contractType;          // "repo", "forward", "option"
    QString makerRole;
    QString makerLenderAddress;
    QVariantMap termSheetTerms;
    QVariantMap termSheetMetrics;
    QJsonObject finalOfferObject;

    // Forward/options fields
    QString m_longDeliverAsset;
    double m_longDeliverQty{0};
    QString m_longDeliverAssetId;
    QString m_longMarginAsset;
    double m_longMarginQty{0};
    QString m_longMarginAssetId;
    QString m_longMarginDest;
    QString m_longSettleDest;

    QString m_shortDeliverAsset;
    double m_shortDeliverQty{0};
    QString m_shortDeliverAssetId;
    QString m_shortMarginAsset;
    double m_shortMarginQty{0};
    QString m_shortMarginAssetId;
    QString m_shortMarginDest;
    QString m_shortSettleDest;

    QString m_premiumAsset;
    double m_premiumQty{0};
    QString m_premiumAssetId;
    QString m_premiumPayer;        // "long" or "short"
    QString m_premiumPayeeDest;

    int m_deadlineShort{0};
    int m_deadlineLong{0};
    int m_safetyK{0};
    int m_reorgConf{0};
    int m_tenorDaysShort{0};
    int m_tenorDaysLong{0};
    double m_longIMPercent{0};
    double m_shortIMPercent{0};

    // Spot-specific fields
    QString m_spotAliceSendAsset;
    double m_spotAliceSendQty{0};
    QString m_spotAliceSendAssetId;
    QString m_spotAliceRecvAsset;
    double m_spotAliceRecvQty{0};
    QString m_spotAliceRecvAssetId;
    QString m_spotAliceDest;

    QString m_spotBobSendAsset;
    double m_spotBobSendQty{0};
    QString m_spotBobSendAssetId;
    QString m_spotBobRecvAsset;
    double m_spotBobRecvQty{0};
    QString m_spotBobRecvAssetId;
    QString m_spotBobDest;

    double m_spotExchangeRate{0};

    // Difficulty-derivative fields (schema difficulty_term_sheet_v1). Kind/role and the rendered
    // economics are all bound to the embedded SIGNED offer, never the outer (spoofable) term sheet.
    QString m_difficultyKind;        // "cfd" or "option" (from the embedded offer)
    QString m_difficultyOfferJson;   // the maker's embedded signed offer JSON (consumed by difficulty.accept*)
    QJsonObject m_difficultyOfferObj;// the same offer parsed, used as the source of truth for display

    // Run the difficulty accept ceremony locally (the term sheet embeds the signed offer, so no
    // maker session is needed): generate the taker's payout address(es), call difficulty.accept[_option],
    // persist the contract in this wallet, and surface the acceptance to hand back to the maker.
    void acceptDifficultyOffer();

    // Scalar-feed CFD fields (schema scalarcfd_term_sheet_v1); the difficulty sibling. As with difficulty,
    // display and accept bind to the embedded SIGNED offer, never the outer (spoofable) term sheet.
    QString m_scalarCfdOfferJson;    // the maker's embedded signed offer JSON (consumed by scalarcfd.accept)
    QJsonObject m_scalarCfdOfferObj; // the same offer parsed, used as the source of truth for display

    // Accept a scalar-feed CFD offer locally: generate the taker's owner/cp payout addresses, call
    // scalarcfd.accept (confirmed), persist the contract, and surface the acceptance to hand back.
    void acceptScalarCfdOffer();
};

#endif // BITCOIN_QT_REVIEWCONTRACTOFFERDIALOG_H
