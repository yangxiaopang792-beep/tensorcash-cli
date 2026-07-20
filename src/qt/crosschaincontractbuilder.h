// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_QT_CROSSCHAINCONTRACTBUILDER_H
#define BITCOIN_QT_CROSSCHAINCONTRACTBUILDER_H

#include <qt/contractwizard.h>

QT_BEGIN_NAMESPACE
class QButtonGroup;
class QComboBox;
class QDoubleSpinBox;
class QLabel;
class QLineEdit;
class QCheckBox;
class QPushButton;
class QSpinBox;
class QGroupBox;
QT_END_NAMESPACE

class WalletModel;

/**
 * @brief Wizard for creating cross-chain settlement offers.
 *
 * Builds a cross_chain_spot_v1 payload and posts it via the
 * existing SpotContract bulletin board path.
 *
 * Pages:
 *   1. Term sheet: TSC leg, external leg, settlement profile, policies
 *   2. Review & create offer
 */
class CrossChainContractBuilder : public ContractWizard
{
    Q_OBJECT

public:
    explicit CrossChainContractBuilder(WalletModel* model, QWidget* parent = nullptr);
    ~CrossChainContractBuilder() override;

    QString getContractType() const override { return QStringLiteral("cross_chain"); }

    /** The cross_chain_spot_v1 payload JSON (valid after wizard completes) */
    QString getCrossChainPayloadJson() const { return crossChainPayloadJson; }

protected:
    bool createOffer() override;
    bool validateTerms() override;

    friend class CrossChainTermSheetPage;

private:
    enum PageId {
        Page_TermSheet = 0,
        Page_Review = 1
    };

    QString crossChainPayloadJson;
};

/**
 * @brief Term sheet page for cross-chain offers.
 *
 * Collects:
 *   - TSC leg (asset + amount)
 *   - External leg (chain, asset, amount, settlement profile selection)
 *   - Funding order
 *   - Confirmation, timeout, and fee policies
 */
class CrossChainTermSheetPage : public QWizardPage
{
    Q_OBJECT

public:
    explicit CrossChainTermSheetPage(QWidget* parent = nullptr);

    bool validatePage() override;
    void initializePage() override;
    bool isComplete() const override;

private Q_SLOTS:
    void onTscAssetChanged(int index);
    void onTscAmountChanged(double value);
    void onExternalChainChanged(int index);
    void onExternalAmountChanged(double value);
    void onProfileSelected(int index);
    void onGenerateTscAddress();
    void updateCalculations();

private:
    void setupUI();
    void populateAssetComboBox(QComboBox* combo, bool includeNative);
    void populateProfileCombo();
    QString getAssetIdFromCombo(QComboBox* combo) const;
    bool isNativeAsset(QComboBox* combo) const;
    int getAssetDecimals(QComboBox* combo) const;

    // TSC leg
    QComboBox* tscAssetCombo{nullptr};
    QDoubleSpinBox* tscAmountSpin{nullptr};
    QLineEdit* tscDestEdit{nullptr};
    QPushButton* generateTscDestButton{nullptr};

    // External leg
    QComboBox* externalChainCombo{nullptr};
    QLineEdit* externalAssetEdit{nullptr};
    QDoubleSpinBox* externalAmountSpin{nullptr};
    QComboBox* profileCombo{nullptr};
    QLabel* profileAddressLabel{nullptr};

    // Policies
    QComboBox* adapterCombo{nullptr};
    QComboBox* fundingOrderCombo{nullptr};
    QSpinBox* externalMinConfSpin{nullptr};
    QSpinBox* tscMinConfSpin{nullptr};
    QSpinBox* reorgConfSpin{nullptr};
    QSpinBox* externalLockSpin{nullptr};
    QSpinBox* tscLockSpin{nullptr};
    QSpinBox* claimBudgetSpin{nullptr};
    QSpinBox* reorgMarginSpin{nullptr};
    QComboBox* claimStrategyCombo{nullptr};
    QComboBox* feeFundingModeCombo{nullptr};

    // Display
    QLabel* exchangeRateLabel{nullptr};
    QLabel* timeoutGapLabel{nullptr};
};

/**
 * @brief Review page for cross-chain offers.
 */
class CrossChainReviewPage : public ContractReviewPage
{
    Q_OBJECT

public:
    explicit CrossChainReviewPage(ContractWizard* wizard, QWidget* parent = nullptr);

protected:
    QString formatOfferSummary() const override;
};

#endif // BITCOIN_QT_CROSSCHAINCONTRACTBUILDER_H
