// Copyright (c) 2026 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_QT_SCALARCFDCONTRACTBUILDER_H
#define BITCOIN_QT_SCALARCFDCONTRACTBUILDER_H

#include <qt/contractwizard.h>

QT_BEGIN_NAMESPACE
class QComboBox;
class QDoubleSpinBox;
class QGroupBox;
class QLabel;
class QLineEdit;
class QSpinBox;
QT_END_NAMESPACE

class WalletModel;

/**
 * @brief Wizard for creating scalar-feed bilateral CFD contract offers.
 *
 * The difficulty builder's sibling: same wizard base and offer→review pipeline, but the instrument is
 * keyed by a published scalar feed (feed_id / strike K / fallback / payoff mode) rather than the on-chain
 * difficulty target, and it drives the scalarcfd.* RPC family. There is no option variant — a scalar-feed
 * CFD always funds two margined legs. Narrow scope: it builds the proposer's offer JSON only (economics +
 * this party's side, with wallet-generated bech32m payout addresses whose internal keys back the
 * cooperative-close 2-of-2). No open/settlement/coop UI here — that lives in the Book.
 */
class ScalarCfdContractBuilder : public ContractWizard
{
    Q_OBJECT

public:
    explicit ScalarCfdContractBuilder(WalletModel* model, QWidget* parent = nullptr);
    ~ScalarCfdContractBuilder() override;

    QString getContractType() const override { return QStringLiteral("scalarcfd"); }

    /** Collected term-sheet values (economics/side); empty if the term page is unavailable. */
    QVariantMap collectedTerms() const;

protected:
    bool createOffer() override;
    bool validateTerms() override;

    friend class ScalarCfdTermSheetPage;
    friend class ScalarCfdReviewPage;

private:
    enum PageId {
        Page_TermSheet = 0,
        Page_Review = 1
    };
};

/**
 * @brief Term-sheet page: collects scalar-feed CFD economics and the proposer's side.
 */
class ScalarCfdTermSheetPage : public QWizardPage
{
    Q_OBJECT

public:
    explicit ScalarCfdTermSheetPage(QWidget* parent = nullptr);

    bool validatePage() override;
    void initializePage() override;

    /** Read all widget values into a flat map (keys consumed by createOffer/formatOfferSummary). */
    QVariantMap collectTerms() const;

private:
    void setupUI();

    QComboBox* payoffModeCombo{nullptr};   // 0 = STRIKE (denom K), 1 = REALIZED (denom X)
    QComboBox* proposerSideCombo{nullptr}; // long / short

    // Feed / fixing terms. v1 is ISSUER_PUBLISHED only (the RPC rejects CHAIN_INTRINSIC — no resolver yet),
    // so a real 64-hex underlying is always required.
    QLineEdit* underlyingEdit{nullptr};    // U asset id (required, 64-hex)
    QLineEdit* feedIdEdit{nullptr};
    QLineEdit* fixingRefEdit{nullptr};     // scalar epoch the contract settles against (uint64)
    QSpinBox*  deadlineHeightSpin{nullptr};// publication_deadline_height
    QSpinBox*  settleLockHeightSpin{nullptr};
    QSpinBox*  formatIdSpin{nullptr};      // scalar_format_id
    QLineEdit* strikeEdit{nullptr};        // K (64-hex)
    QLineEdit* fallbackEdit{nullptr};      // fallback_scalar (64-hex)
    QLineEdit* collateralEdit{nullptr};    // C (native-only for now; disabled)

    // Legs (IM in collateral units — integer sats if native; leverage is a positive multiplier)
    QLineEdit* longImEdit{nullptr};
    QDoubleSpinBox* longLambdaSpin{nullptr};
    QLineEdit* shortImEdit{nullptr};
    QDoubleSpinBox* shortLambdaSpin{nullptr};

    QLabel* addressNote{nullptr};
};

/**
 * @brief Review page: shows the offer summary and creates the offer on Finish.
 */
class ScalarCfdReviewPage : public ContractReviewPage
{
    Q_OBJECT

public:
    explicit ScalarCfdReviewPage(ContractWizard* wizard, QWidget* parent = nullptr);

protected:
    QString formatOfferSummary() const override;
};

#endif // BITCOIN_QT_SCALARCFDCONTRACTBUILDER_H
