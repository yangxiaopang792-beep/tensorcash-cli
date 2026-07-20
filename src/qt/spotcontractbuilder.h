// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_QT_SPOTCONTRACTBUILDER_H
#define BITCOIN_QT_SPOTCONTRACTBUILDER_H

#include <qt/contractwizard.h>

QT_BEGIN_NAMESPACE
class QButtonGroup;
class QComboBox;
class QDoubleSpinBox;
class QLabel;
class QLineEdit;
class QCheckBox;
class QPushButton;
class QRadioButton;
class QSpinBox;
QT_END_NAMESPACE

class WalletModel;

/**
 * @brief Wizard for creating Spot (atomic swap) contract offers
 *
 * Guides the user through:
 * 1. Term sheet (your offer leg, desired leg, addresses)
 * 2. Review & create offer
 */
class SpotContractBuilder : public ContractWizard
{
    Q_OBJECT

public:
    explicit SpotContractBuilder(WalletModel* model, QWidget* parent = nullptr);
    ~SpotContractBuilder() override;

    QString getContractType() const override { return QStringLiteral("spot"); }

protected:
    bool createOffer() override;
    bool validateTerms() override;

    // Allow term sheet page to access protected methods
    friend class SpotTermSheetPage;

private:
    enum PageId {
        Page_TermSheet = 0,
        Page_Review = 1
    };
};

/**
 * @brief Term sheet page for Spot contracts
 */
class SpotTermSheetPage : public QWizardPage
{
    Q_OBJECT

public:
    explicit SpotTermSheetPage(QWidget* parent = nullptr);

    bool validatePage() override;
    void initializePage() override;
    bool isComplete() const override;

private Q_SLOTS:
    void onYourAssetChanged(int index);
    void onYourAmountChanged(double value);
    void onDesiredAssetChanged(int index);
    void onDesiredAmountChanged(double value);
    void onGenerateYourDestAddress();
    void onGenerateCounterpartyDestAddress();
    void onYourDestManualToggled(bool checked);
    void onCounterpartyDestManualToggled(bool checked);
    void updateCalculations();

private:
    void setupUI();
    void populateAssetComboBox(QComboBox* combo, bool includeNative);
    QString getAssetIdFromCombo(QComboBox* combo) const;
    bool isNativeAsset(QComboBox* combo) const;
    int getAssetDecimals(QComboBox* combo) const;

    // Your offer leg section
    QComboBox* yourAssetCombo{nullptr};
    QDoubleSpinBox* yourAmountSpin{nullptr};
    QLabel* yourUnitLabel{nullptr};
    QLineEdit* yourDestEdit{nullptr};
    QPushButton* generateYourDestButton{nullptr};
    QCheckBox* yourDestManualToggle{nullptr};

    // Desired leg section
    QComboBox* desiredAssetCombo{nullptr};
    QDoubleSpinBox* desiredAmountSpin{nullptr};
    QLabel* desiredUnitLabel{nullptr};
    QLineEdit* counterpartyDestEdit{nullptr};
    QPushButton* generateCounterpartyDestButton{nullptr};
    QCheckBox* counterpartyDestManualToggle{nullptr};

    // Exchange rate display
    QLabel* exchangeRateLabel{nullptr};

    // Commitment proof option
    QCheckBox* requireCommitmentProofCheck{nullptr};
};

/**
 * @brief Review page for Spot contracts
 */
class SpotReviewPage : public ContractReviewPage
{
    Q_OBJECT

public:
    explicit SpotReviewPage(ContractWizard* wizard, QWidget* parent = nullptr);

protected:
    QString formatOfferSummary() const override;
};

#endif // BITCOIN_QT_SPOTCONTRACTBUILDER_H
