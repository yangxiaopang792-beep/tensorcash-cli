// Copyright (c) 2026 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_QT_DIFFICULTYCONTRACTBUILDER_H
#define BITCOIN_QT_DIFFICULTYCONTRACTBUILDER_H

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
 * @brief Wizard for creating Difficulty-derivative (CFD or option) contract offers.
 *
 * Narrow scope: it builds the proposer's offer JSON only — economics + this party's role, with
 * wallet-generated bech32m payout addresses (the cooperative-close keys are derived from those address
 * providers, so they must be wallet-owned). No open/settlement/coop UI here.
 */
class DifficultyContractBuilder : public ContractWizard
{
    Q_OBJECT

public:
    explicit DifficultyContractBuilder(WalletModel* model, QWidget* parent = nullptr);
    ~DifficultyContractBuilder() override;

    QString getContractType() const override { return QStringLiteral("difficulty"); }

    /** Collected term-sheet values (kind/economics/role); empty if the term page is unavailable. */
    QVariantMap collectedTerms() const;

protected:
    bool createOffer() override;
    bool validateTerms() override;

    friend class DifficultyTermSheetPage;
    friend class DifficultyReviewPage;

private:
    enum PageId {
        Page_TermSheet = 0,
        Page_Review = 1
    };
};

/**
 * @brief Term-sheet page: collects difficulty economics and the proposer's role.
 */
class DifficultyTermSheetPage : public QWizardPage
{
    Q_OBJECT

public:
    explicit DifficultyTermSheetPage(QWidget* parent = nullptr);

    bool validatePage() override;
    void initializePage() override;

    /** Read all widget values into a flat map (keys consumed by createOffer/formatOfferSummary). */
    QVariantMap collectTerms() const;

private Q_SLOTS:
    void onKindChanged(int index);

private:
    void setupUI();

    QComboBox* kindCombo{nullptr};        // 0 = CFD, 1 = Option

    // Shared underlying
    QLineEdit* strikeTpsEdit{nullptr};    // primary strike input, tokens/sec (SI-suffixed)
    QLineEdit* strikeNbitsEdit{nullptr};  // derived canonical compact target, 8-hex (read-only)
    QLabel* strikeTokensPerSecLabel{nullptr};  // realized tok/s of the derived nBits
    QSpinBox* fixingHeightSpin{nullptr};
    QSpinBox* settleLockHeightSpin{nullptr};

    // CFD legs
    QGroupBox* cfdGroup{nullptr};
    QComboBox* proposerSideCombo{nullptr}; // long / short
    QDoubleSpinBox* longImSpin{nullptr};
    QDoubleSpinBox* longLambdaSpin{nullptr};
    QDoubleSpinBox* shortImSpin{nullptr};
    QDoubleSpinBox* shortLambdaSpin{nullptr};

    // Option leg
    QGroupBox* optionGroup{nullptr};
    QComboBox* writerSideCombo{nullptr};   // long / short (side the WRITER holds)
    QComboBox* proposerRoleCombo{nullptr}; // writer / buyer
    QDoubleSpinBox* optImSpin{nullptr};
    QDoubleSpinBox* optLambdaSpin{nullptr};
    QDoubleSpinBox* optPremiumSpin{nullptr};

    QLabel* addressNote{nullptr};
};

/**
 * @brief Review page: shows the offer summary and creates the offer on Finish.
 */
class DifficultyReviewPage : public ContractReviewPage
{
    Q_OBJECT

public:
    explicit DifficultyReviewPage(ContractWizard* wizard, QWidget* parent = nullptr);

protected:
    QString formatOfferSummary() const override;
};

#endif // BITCOIN_QT_DIFFICULTYCONTRACTBUILDER_H
