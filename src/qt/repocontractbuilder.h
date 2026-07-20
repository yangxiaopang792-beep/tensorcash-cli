// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_QT_REPOCONTRACTBUILDER_H
#define BITCOIN_QT_REPOCONTRACTBUILDER_H

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
 * @brief Wizard for creating Repo contract offers
 *
 * Guides the user through:
 * 1. Role selection (Lender/Borrower)
 * 2. Term sheet (collateral, principal, maturity, addresses)
 * 3. Review & create offer
 */
class RepoContractBuilder : public ContractWizard
{
    Q_OBJECT

public:
    explicit RepoContractBuilder(WalletModel* model, QWidget* parent = nullptr);
    ~RepoContractBuilder() override;

    QString getContractType() const override { return QStringLiteral("repo"); }

    void accept() override;

protected:
    bool createOffer() override;
    bool validateTerms() override;

    // Allow term sheet page to access protected methods
    friend class RepoTermSheetPage;

private:
    enum PageId {
        Page_TermSheet = 0,
        Page_Review = 1
    };
};

/**
 * @brief Term sheet page for Repo contracts
 */
class RepoTermSheetPage : public QWizardPage
{
    Q_OBJECT
    Q_PROPERTY(bool isLenderRole READ isLenderRole NOTIFY roleChanged)

public:
    explicit RepoTermSheetPage(QWidget* parent = nullptr);

    bool validatePage() override;
    void initializePage() override;

    bool isLenderRole() const;

    // Expose current selections for robust offer creation
    bool collateralIsNative() const;
    QString collateralAssetId() const;
    bool principalIsNative() const;
    QString principalAssetId() const;
    bool interestIsNative() const;
    QString interestAssetId() const;
    QString borrowerAddress() const;
    QString lenderAddress() const;

Q_SIGNALS:
    void roleChanged();

private Q_SLOTS:
    void onRoleChanged();
    void onCollateralAssetChanged(int index);
    void onCollateralAmountChanged(double value);
    void onPrincipalAssetChanged(int index);
    void onInterestAssetChanged(int index);
    void onCollateralPriceChanged(double value);
    void onLtvTargetChanged(double value);
    void onInterestRateChanged(double value);
    void onMaturityPeriodChanged(int value);
    void onMaturityUnitChanged(int index);
    void updateCalculations();
    void updateMaturityHeight();
    void onGenerateBorrowerAddress();
    void onGenerateLenderAddress();
    void onBorrowerManualToggled(bool checked);
    void onLenderManualToggled(bool checked);
    bool isComplete() const override;
    void updatePricingBreakdown();
    void onTransportChanged(int index);
    void updateTorStatus();
    void onShowGreeks();

private:
    void setupUI();
    void populateAssetComboBox(QComboBox* combo, bool includeNative);
    QString getAssetIdFromCombo(QComboBox* combo) const;
    bool isNativeAsset(QComboBox* combo) const;
    int getAssetDecimals(QComboBox* combo) const;

    // Role selection
    QRadioButton* lenderRadio{nullptr};
    QRadioButton* borrowerRadio{nullptr};
    QButtonGroup* roleGroup{nullptr};

    // Collateral section
    QComboBox* collateralAssetCombo{nullptr};
    QDoubleSpinBox* collateralAmountSpin{nullptr};
    QLabel* collateralUnitLabel{nullptr};

    // Principal section
    QComboBox* principalAssetCombo{nullptr};
    QDoubleSpinBox* collateralPriceSpin{nullptr};
    QLabel* collateralPriceUnitLabel{nullptr};
    QDoubleSpinBox* ltvTargetSpin{nullptr};
    QDoubleSpinBox* principalAmountSpin{nullptr};
    QLabel* principalUnitLabel{nullptr};

    // Interest section
    QComboBox* interestAssetCombo{nullptr};
    QDoubleSpinBox* interestRateSpin{nullptr};
    QLabel* interestPriceLabel{nullptr};
    QDoubleSpinBox* interestPriceSpin{nullptr};
    QLabel* interestPriceUnitLabel{nullptr};
    QLabel* interestAmountLabel{nullptr};
    QLabel* repayAmountLabel{nullptr};
    QLabel* interestUnitLabel{nullptr};

    // Maturity section
    QSpinBox* maturityPeriodSpin{nullptr};
    QComboBox* maturityUnitCombo{nullptr};
    QCheckBox* useAbsoluteHeightCheck{nullptr};
    QSpinBox* absoluteHeightSpin{nullptr};
    QLabel* currentHeightLabel{nullptr};
    QLabel* targetHeightLabel{nullptr};
    QSpinBox* safetyBufferSpin{nullptr};

    // Addresses section
    QLineEdit* borrowerAddressEdit{nullptr};
    QPushButton* generateBorrowerButton{nullptr};
    QCheckBox* borrowerManualToggle{nullptr};
    QLineEdit* lenderAddressEdit{nullptr};
    QPushButton* generateLenderButton{nullptr};
    QCheckBox* lenderManualToggle{nullptr};

    // Fee policy
    QComboBox* feePolicyCombo{nullptr};

    // Transport selection
    QComboBox* transportCombo{nullptr};
    QLabel* torStatusLabel{nullptr};

    // Pricing breakdown labels
    QLabel* principalInterestPvLabel{nullptr};
    QLabel* collateralPvLabel{nullptr};
    QLabel* collateralOptionLabel{nullptr};
    QLabel* lenderMtmLabel{nullptr};
    QLabel* borrowerMtmLabel{nullptr};
    // Per-principal labels
    QLabel* principalInterestPvPerPrincipalLabel{nullptr};
    QLabel* collateralPvPerPrincipalLabel{nullptr};
    QLabel* collateralOptionPerPrincipalLabel{nullptr};
    QLabel* lenderMtmPerPrincipalLabel{nullptr};
    QLabel* borrowerMtmPerPrincipalLabel{nullptr};
    QTimer* pricingDebounceTimer{nullptr};
    QPushButton* showGreeksButton{nullptr};
};

/**
 * @brief Review page for Repo contracts
 */
class RepoReviewPage : public ContractReviewPage
{
    Q_OBJECT

public:
    explicit RepoReviewPage(ContractWizard* wizard, QWidget* parent = nullptr);

protected:
    QString formatOfferSummary() const override;
};

#endif // BITCOIN_QT_REPOCONTRACTBUILDER_H
