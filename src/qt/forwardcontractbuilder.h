// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_QT_FORWARDCONTRACTBUILDER_H
#define BITCOIN_QT_FORWARDCONTRACTBUILDER_H

#include <qt/contractwizard.h>

QT_BEGIN_NAMESPACE
class QButtonGroup;
class QCheckBox;
class QComboBox;
class QDoubleSpinBox;
class QGroupBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QRadioButton;
class QSpinBox;
class QStackedWidget;
QT_END_NAMESPACE

class WalletModel;

/**
 * @brief Wizard for creating Forward/Option contract offers
 *
 * Guides the user through:
 * 1. Role selection (Long/Short party) + Contract type (Forward/Option)
 * 2. Delivery leg configuration (assets, size, price)
 * 3. Initial margin configuration (IM assets, amounts, notional %)
 * 4. Premium configuration (for options only)
 * 5. Maturity/deadline configuration
 * 6. Review & create offer
 */
class ForwardContractBuilder : public ContractWizard
{
    Q_OBJECT

public:
    explicit ForwardContractBuilder(WalletModel* model, bool isOption = false, QWidget* parent = nullptr);
    ~ForwardContractBuilder() override;

    QString getContractType() const override { return m_isOption ? QStringLiteral("option") : QStringLiteral("forward"); }
    bool isOptionContract() const { return m_isOption; }

protected:
    bool createOffer() override;
    bool createOffer(bool verifyFunds);  // Overload with verifyFunds flag
    bool validateTerms() override;

    // Allow term sheet page to access protected methods
    friend class ForwardTermSheetPage;
    friend class OptionTermSheetPage;
    friend class ForwardReviewPage;

private:
    enum PageId {
        Page_TermSheet = 0,
        Page_Review = 1
    };

    bool m_isOption;
};

/**
 * @brief Term sheet page for Forward contracts (low-level)
 */
class ForwardTermSheetPage : public QWizardPage
{
    Q_OBJECT

public:
    explicit ForwardTermSheetPage(bool isOption, QWidget* parent = nullptr);

    bool validatePage() override;
    void initializePage() override;

private Q_SLOTS:
    void onRoleChanged();
    void onFlipLongShort();
    void onLongDeliverAssetChanged(int index);
    void onShortDeliverAssetChanged(int index);
    void onLongSizeChanged(double value);
    void onPriceChanged(double value);
    void onLongImAssetChanged(int index);
    void onShortImAssetChanged(int index);
    void onLongImModeChanged();
    void onShortImModeChanged();
    void onLongImPercentChanged(double value);
    void onShortImPercentChanged(double value);
    void onLongImAbsoluteChanged(double value);
    void onShortImAbsoluteChanged(double value);
    void onPremiumAssetChanged(int index);
    void onPremiumAmountChanged(double value);
    void onPremiumPayerChanged();
    void onEnablePremiumChanged(bool checked);
    void onMaturityPeriodChanged(int value);
    void onDeliveryGapChanged(int value);
    void onMaturityUnitChanged(int index);
    void onGenerateMyMarginAddress();
    void onGenerateMySettleAddress();
    void onGeneratePremiumAddress();
    void onShowGreeks();
    void updateCalculations();
    void updateDeadlineHeights();

private:
    void setupUI();
    void populateAssetComboBox(QComboBox* combo, bool includeNative);
    QString getAssetIdFromCombo(QComboBox* combo) const;
    bool isNativeAsset(QComboBox* combo) const;
    int getAssetDecimals(QComboBox* combo) const;
    void updateImControls();
    void updatePremiumControls();
    void applySpinBoxDecimals(QDoubleSpinBox* spin, int decimals) const;

    bool m_isOption;

    // Role selection
    QRadioButton* longPartyRadio{nullptr};
    QRadioButton* shortPartyRadio{nullptr};
    QButtonGroup* roleGroup{nullptr};

    // Contract type (Forward vs Option)
    QCheckBox* optionCheckBox{nullptr};
    QLabel* contractTypeLabel{nullptr};

    // Delivery leg section
    QGroupBox* deliveryGroup{nullptr};
    QComboBox* longDeliverAssetCombo{nullptr};
    QLineEdit* longDeliverAssetIdEdit{nullptr};  // Hidden field to store asset ID for registration
    QLineEdit* longDeliverIsNativeEdit{nullptr};  // Hidden field to store is_native flag
    QLabel* longDeliverUnitLabel{nullptr};
    QDoubleSpinBox* longSizeSpin{nullptr};
    QLabel* longSizeUnitLabel{nullptr};
    QComboBox* shortDeliverAssetCombo{nullptr};
    QLineEdit* shortDeliverAssetIdEdit{nullptr};  // Hidden field
    QLineEdit* shortDeliverIsNativeEdit{nullptr};  // Hidden field to store is_native flag
    QLabel* shortDeliverUnitLabel{nullptr};
    QDoubleSpinBox* priceSpin{nullptr};
    QLabel* priceUnitLabel{nullptr};
    QLabel* shortSizeLabel{nullptr};
    QLabel* shortSizeValueLabel{nullptr};

    // Initial margin section
    QGroupBox* marginGroup{nullptr};

    // Long party IM
    QComboBox* longImAssetCombo{nullptr};
    QLineEdit* longImAssetIdEdit{nullptr};  // Hidden field
    QLineEdit* longImIsNativeEdit{nullptr};  // Hidden field to store is_native flag
    QLabel* longImAssetLabel{nullptr};
    QRadioButton* longImPercentRadio{nullptr};
    QRadioButton* longImAbsoluteRadio{nullptr};
    QButtonGroup* longImModeGroup{nullptr};
    QDoubleSpinBox* longImPercentSpin{nullptr};
    QLabel* longImPercentLabel{nullptr};
    QDoubleSpinBox* longImAbsoluteSpin{nullptr};
    QLabel* longImAbsoluteLabel{nullptr};
    QLabel* longImAbsoluteUnitLabel{nullptr};
    QLabel* longImCalculatedLabel{nullptr};

    // Short party IM
    QComboBox* shortImAssetCombo{nullptr};
    QLineEdit* shortImAssetIdEdit{nullptr};  // Hidden field
    QLineEdit* shortImIsNativeEdit{nullptr};  // Hidden field to store is_native flag
    QLabel* shortImAssetLabel{nullptr};
    QRadioButton* shortImPercentRadio{nullptr};
    QRadioButton* shortImAbsoluteRadio{nullptr};
    QButtonGroup* shortImModeGroup{nullptr};
    QDoubleSpinBox* shortImPercentSpin{nullptr};
    QLabel* shortImPercentLabel{nullptr};
    QDoubleSpinBox* shortImAbsoluteSpin{nullptr};
    QLabel* shortImAbsoluteLabel{nullptr};
    QLabel* shortImAbsoluteUnitLabel{nullptr};
    QLabel* shortImCalculatedLabel{nullptr};

    // Premium section (options only)
    QGroupBox* premiumGroup{nullptr};
    QCheckBox* enablePremiumCheckBox{nullptr};
    QWidget* premiumFieldsWidget{nullptr};
    QComboBox* premiumAssetCombo{nullptr};
    QLineEdit* premiumAssetIdEdit{nullptr};  // Hidden field
    QLineEdit* premiumIsNativeEdit{nullptr};  // Hidden field to store is_native flag
    QLabel* premiumAssetLabel{nullptr};
    QDoubleSpinBox* premiumAmountSpin{nullptr};
    QLabel* premiumAmountUnitLabel{nullptr};
    QRadioButton* premiumPayerLongRadio{nullptr};
    QRadioButton* premiumPayerShortRadio{nullptr};
    QButtonGroup* premiumPayerGroup{nullptr};
    QLineEdit* premiumDestEdit{nullptr};
    QPushButton* generatePremiumButton{nullptr};

    // Deadline section
    QGroupBox* deadlineGroup{nullptr};
    QSpinBox* maturityPeriodSpin{nullptr};
    QLabel* maturityPeriodLabel{nullptr};
    QSpinBox* deliveryGapSpin{nullptr};
    QLabel* deliveryGapLabel{nullptr};
    QComboBox* maturityUnitCombo{nullptr};
    QCheckBox* useAbsoluteHeightCheck{nullptr};
    QSpinBox* absoluteShortHeightSpin{nullptr};
    QSpinBox* absoluteLongHeightSpin{nullptr};
    QSpinBox* safetyBufferSpin{nullptr};
    QLabel* currentHeightLabel{nullptr};
    QLabel* deadlineShortHeightLabel{nullptr};
    QLabel* deadlineLongHeightLabel{nullptr};

    // My addresses section (only for proposer's own addresses)
    QGroupBox* addressGroup{nullptr};
    QLineEdit* myMarginDestEdit{nullptr};
    QPushButton* generateMyMarginButton{nullptr};
    QLineEdit* mySettleDestEdit{nullptr};
    QPushButton* generateMySettleButton{nullptr};

    // Pricing breakdown labels
    QLabel* pvReceiveLabel{nullptr};
    QLabel* pvPayLabel{nullptr};
    QLabel* netSpreadLabel{nullptr};
    QLabel* premiumPvLabel{nullptr};
    QLabel* aliceShortCallLabel{nullptr};
    QLabel* aliceLongPutLabel{nullptr};
    QLabel* aliceMtmLabel{nullptr};
    QLabel* bobMtmLabel{nullptr};
    QLabel* imCoverageAliceLabel{nullptr};
    QLabel* imCoverageBobLabel{nullptr};
    QLabel* pvReceivePerNotionalLabel{nullptr};
    QLabel* pvPayPerNotionalLabel{nullptr};
    QLabel* netSpreadPerNotionalLabel{nullptr};
    QLabel* premiumPvPerNotionalLabel{nullptr};
    QLabel* aliceShortCallPerNotionalLabel{nullptr};
    QLabel* aliceLongPutPerNotionalLabel{nullptr};
    QLabel* aliceMtmPerNotionalLabel{nullptr};
    QLabel* bobMtmPerNotionalLabel{nullptr};
    QLabel* imCoverageAlicePerNotionalLabel{nullptr};
    QLabel* imCoverageBobPerNotionalLabel{nullptr};

    // Pricing update timer
    QTimer* pricingDebounceTimer{nullptr};
    QPushButton* showGreeksButton{nullptr};

    void updateForwardPricing();
};

/**
 * @brief Term sheet page for Options (using standard option terminology)
 */
class OptionTermSheetPage : public QWizardPage
{
    Q_OBJECT

public:
    explicit OptionTermSheetPage(QWidget* parent = nullptr);

    bool validatePage() override;
    void initializePage() override;

private Q_SLOTS:
    void onDirectionChanged(int index);
    void onOptionTypeChanged(int index);
    void onBaseAssetChanged(int index);
    void onQuoteAssetChanged(int index);
    void onStrikeChanged(double value);
    void onNotionalChanged(double value);
    void onMaxPayoutChanged(double value);
    void onPremiumChanged(double value);
    void onExpiryChanged(int value);
    void onExpiryUnitChanged(int index);
    void onGenerateDestinationAddresses();
    void onShowAdvancedEditor(bool checked);
    void onAdvancedFieldChanged();
    void onShowGreeks();
    void updateForwardPreview();
    void updateAdvancedFields();
    void updateOptionPricing();

private:
    void setupUI();
    void populateAssetComboBox(QComboBox* combo, bool includeNative);
    QString getAssetIdFromCombo(QComboBox* combo) const;
    bool isNativeAsset(QComboBox* combo) const;
    int getAssetDecimals(QComboBox* combo) const;
    void applySpinBoxDecimals(QDoubleSpinBox* spin, int decimals) const;
    void convertToForwardParams();

    // Option parameters UI
    QComboBox* directionCombo{nullptr};              // Buy / Sell
    QComboBox* optionTypeCombo{nullptr};             // Call / Put
    QComboBox* baseAssetCombo{nullptr};              // Base currency (e.g., TSC)
    QLineEdit* baseAssetIdEdit{nullptr};             // Hidden field
    QComboBox* quoteAssetCombo{nullptr};             // Quote currency (e.g., GOLD)
    QLineEdit* quoteAssetIdEdit{nullptr};            // Hidden field
    QDoubleSpinBox* strikeSpin{nullptr};             // Strike price (base/quote)
    QDoubleSpinBox* notionalSpin{nullptr};           // Notional (reference for percentages)
    QDoubleSpinBox* maxPayoutSpin{nullptr};          // Max payout (%)
    QDoubleSpinBox* premiumSpin{nullptr};            // Premium (%)
    QSpinBox* expirySpin{nullptr};                   // Expiry period
    QComboBox* expiryUnitCombo{nullptr};             // Days/Weeks/Months/Years
    QSpinBox* deliveryGapSpin{nullptr};              // Gap between short/long delivery
    QLineEdit* marginDestEdit{nullptr};              // Margin refund address
    QLineEdit* settlementDestEdit{nullptr};          // Settlement address
    QLineEdit* premiumDestEdit{nullptr};             // Premium destination
    QPushButton* generateAddressesButton{nullptr};

    // Preview labels
    QLabel* forwardPreviewLabel{nullptr};            // Shows the equivalent forward structure
    QLabel* rolePreviewLabel{nullptr};               // Shows maker's role (long/short)
    QLabel* longDeliveryPreviewLabel{nullptr};       // Long delivers X
    QLabel* shortDeliveryPreviewLabel{nullptr};      // Short delivers Y
    QLabel* longImPreviewLabel{nullptr};             // Long IM amount
    QLabel* shortImPreviewLabel{nullptr};            // Short IM amount
    QLabel* premiumAmountPreviewLabel{nullptr};      // Premium amount

    // Pricing breakdown labels
    QLabel* pvReceiveLabel{nullptr};
    QLabel* pvPayLabel{nullptr};
    QLabel* netSpreadLabel{nullptr};
    QLabel* premiumPvLabel{nullptr};
    QLabel* aliceShortCallLabel{nullptr};
    QLabel* aliceLongPutLabel{nullptr};
    QLabel* aliceMtmLabel{nullptr};
    QLabel* bobMtmLabel{nullptr};
    QLabel* imCoverageAliceLabel{nullptr};
    QLabel* imCoverageBobLabel{nullptr};
    QLabel* pvReceivePerNotionalLabel{nullptr};
    QLabel* pvPayPerNotionalLabel{nullptr};
    QLabel* netSpreadPerNotionalLabel{nullptr};
    QLabel* premiumPvPerNotionalLabel{nullptr};
    QLabel* aliceShortCallPerNotionalLabel{nullptr};
    QLabel* aliceLongPutPerNotionalLabel{nullptr};
    QLabel* aliceMtmPerNotionalLabel{nullptr};
    QLabel* bobMtmPerNotionalLabel{nullptr};
    QLabel* imCoverageAlicePerNotionalLabel{nullptr};
    QLabel* imCoverageBobPerNotionalLabel{nullptr};

    // Pricing update timer
    QTimer* pricingDebounceTimer{nullptr};
    QPushButton* showGreeksButton{nullptr};

    // Hidden fields to store converted forward parameters for wizard field system
    QLineEdit* hiddenIsLongParty{nullptr};
    QLineEdit* hiddenLongSize{nullptr};
    QLineEdit* hiddenPrice{nullptr};
    QLineEdit* hiddenLongDeliverAssetId{nullptr};
    QLineEdit* hiddenLongDeliverIsNative{nullptr};
    QLineEdit* hiddenShortDeliverAssetId{nullptr};
    QLineEdit* hiddenShortDeliverIsNative{nullptr};
    QLineEdit* hiddenLongImPercent{nullptr};
    QLineEdit* hiddenLongImPercentValue{nullptr};
    QLineEdit* hiddenLongImAbsoluteValue{nullptr};
    QLineEdit* hiddenLongImAssetId{nullptr};
    QLineEdit* hiddenLongImIsNative{nullptr};
    QLineEdit* hiddenShortImPercent{nullptr};
    QLineEdit* hiddenShortImPercentValue{nullptr};
    QLineEdit* hiddenShortImAbsoluteValue{nullptr};
    QLineEdit* hiddenShortImAssetId{nullptr};
    QLineEdit* hiddenShortImIsNative{nullptr};
    QLineEdit* hiddenPremiumAmount{nullptr};
    QLineEdit* hiddenPremiumPayerIsLong{nullptr};
    QLineEdit* hiddenPremiumAssetId{nullptr};
    QLineEdit* hiddenPremiumIsNative{nullptr};
    QLineEdit* hiddenMaturityPeriod{nullptr};
    QLineEdit* hiddenMaturityUnit{nullptr};
    QLineEdit* hiddenMyMarginDest{nullptr};
    QLineEdit* hiddenMySettleDest{nullptr};
    QLineEdit* hiddenSafetyBuffer{nullptr};

    // Advanced editor
    QCheckBox* showAdvancedCheckBox{nullptr};        // Toggle advanced editor
    QWidget* advancedEditorWidget{nullptr};          // Container for advanced fields
    QDoubleSpinBox* advLongDeliverySpin{nullptr};    // Override long delivery amount
    QDoubleSpinBox* advShortDeliverySpin{nullptr};   // Override short delivery amount
    QDoubleSpinBox* advLongImSpin{nullptr};          // Override long IM amount
    QDoubleSpinBox* advShortImSpin{nullptr};         // Override short IM amount
    QDoubleSpinBox* advPremiumAmountSpin{nullptr};   // Override premium amount
    QRadioButton* advLongImAbsoluteRadio{nullptr};   // Always use absolute IM in advanced mode
    QRadioButton* advShortImAbsoluteRadio{nullptr};
    bool advancedModeActive;                // Track if user has modified advanced fields
};

/**
 * @brief Review page for Forward/Option contracts
 */
class ForwardReviewPage : public ContractReviewPage
{
    Q_OBJECT

public:
    explicit ForwardReviewPage(ContractWizard* wizard, QWidget* parent = nullptr);

protected:
    QString formatOfferSummary() const override;
};

#endif // BITCOIN_QT_FORWARDCONTRACTBUILDER_H
