// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <qt/forwardcontractbuilder.h>
#include <qt/walletmodel.h>
#include <qt/guiutil.h>
#include <qt/themehelpers.h>
#include <qt/greeksvisualizationdialog.h>
#include <logging.h>

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QFormLayout>
#include <QGroupBox>
#include <QLabel>
#include <QRadioButton>
#include <QButtonGroup>
#include <QCheckBox>
#include <QComboBox>
#include <QDoubleSpinBox>
#include <QSpinBox>
#include <QLineEdit>
#include <QPushButton>
#include <QMessageBox>
#include <QScrollArea>
#include <QStackedWidget>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTimer>
#include <QFrame>
#include <algorithm>
#include <cmath>

// ============================================================================
// ForwardContractBuilder
// ============================================================================

ForwardContractBuilder::ForwardContractBuilder(WalletModel* model, bool isOption, QWidget* parent)
    : ContractWizard(model, parent)
    , m_isOption(isOption)
{
    setWindowTitle(m_isOption ? tr("Option Contract Builder") : tr("Forward Contract Builder"));

    // Set reasonable window size (25% wider for better layout)
    setMinimumSize(880, 500);
    resize(1000, 600);

    // Add pages - use OptionTermSheetPage for options, ForwardTermSheetPage for forwards
    if (m_isOption) {
        setPage(Page_TermSheet, new OptionTermSheetPage(this));
    } else {
        setPage(Page_TermSheet, new ForwardTermSheetPage(false, this));
    }
    setPage(Page_Review, new ForwardReviewPage(this, this));

    setStartId(Page_TermSheet);
}

ForwardContractBuilder::~ForwardContractBuilder()
{
}

bool ForwardContractBuilder::validateTerms()
{
    // Validate that all required fields are set
    if (field("longSize").toDouble() <= 0) {
        QMessageBox::warning(this, tr("Validation Error"),
            tr("Long position size must be greater than zero."));
        return false;
    }

    if (field("price").toDouble() <= 0) {
        QMessageBox::warning(this, tr("Validation Error"),
            tr("Price must be greater than zero."));
        return false;
    }

    // Check IM values
    bool longImPercent = field("longImPercent").toBool();
    bool shortImPercent = field("shortImPercent").toBool();

    if (longImPercent && field("longImPercentValue").toDouble() < 0) {
        QMessageBox::warning(this, tr("Validation Error"),
            tr("Long initial margin percentage cannot be negative."));
        return false;
    }

    if (shortImPercent && field("shortImPercentValue").toDouble() < 0) {
        QMessageBox::warning(this, tr("Validation Error"),
            tr("Short initial margin percentage cannot be negative."));
        return false;
    }

    if (!longImPercent && field("longImAbsoluteValue").toDouble() < 0) {
        QMessageBox::warning(this, tr("Validation Error"),
            tr("Long initial margin amount cannot be negative."));
        return false;
    }

    if (!shortImPercent && field("shortImAbsoluteValue").toDouble() < 0) {
        QMessageBox::warning(this, tr("Validation Error"),
            tr("Short initial margin amount cannot be negative."));
        return false;
    }

    // For options, exactly one IM must be zero
    if (m_isOption) {
        double longIm = longImPercent
            ? (field("longSize").toDouble() * field("longImPercentValue").toDouble() / 100.0)
            : field("longImAbsoluteValue").toDouble();
        double shortIm = shortImPercent
            ? (field("longSize").toDouble() * field("price").toDouble() * field("shortImPercentValue").toDouble() / 100.0)
            : field("shortImAbsoluteValue").toDouble();

        if (longIm == 0 && shortIm == 0) {
            QMessageBox::warning(this, tr("Validation Error"),
                tr("For options, at least one party must post initial margin."));
            return false;
        }

        if (field("premiumAmount").toDouble() <= 0) {
            QMessageBox::warning(this, tr("Validation Error"),
                tr("Premium amount must be greater than zero for options."));
            return false;
        }

        // Premium destination: only required if proposer is premium receiver
        bool isLongParty = field("isLongParty").toBool();
        bool premiumPayerIsLong = field("premiumPayerIsLong").toBool();
        bool proposerReceivesPremium = (isLongParty && !premiumPayerIsLong) || (!isLongParty && premiumPayerIsLong);

        if (proposerReceivesPremium && field("premiumDest").toString().isEmpty()) {
            QMessageBox::warning(this, tr("Validation Error"),
                tr("Premium destination address is required when you receive the premium."));
            return false;
        }
    }

    // Check addresses - only for proposer's own role
    bool isLongParty = field("isLongParty").toBool();

    if (isLongParty) {
        if (field("myMarginDest").toString().isEmpty()) {
            QMessageBox::warning(this, tr("Validation Error"),
                tr("Your margin destination address is required."));
            return false;
        }
        if (field("mySettleDest").toString().isEmpty()) {
            QMessageBox::warning(this, tr("Validation Error"),
                tr("Your settlement address is required."));
            return false;
        }
    } else {
        if (field("myMarginDest").toString().isEmpty()) {
            QMessageBox::warning(this, tr("Validation Error"),
                tr("Your margin destination address is required."));
            return false;
        }
        if (field("mySettleDest").toString().isEmpty()) {
            QMessageBox::warning(this, tr("Validation Error"),
                tr("Your settlement address is required."));
            return false;
        }
    }

    // Check deadlines
    if (field("maturityPeriod").toInt() <= 0) {
        QMessageBox::warning(this, tr("Validation Error"),
            tr("Maturity period must be greater than zero."));
        return false;
    }

    if (field("deliveryGap").toInt() < 0) {
        QMessageBox::warning(this, tr("Validation Error"),
            tr("Delivery gap cannot be negative."));
        return false;
    }

    return true;
}

bool ForwardContractBuilder::createOffer()
{
    // Default to fund verification enabled
    return createOffer(true);
}

bool ForwardContractBuilder::createOffer(bool verifyFunds)
{
    try {
        if (!walletModel) {
            QMessageBox::critical(this, tr("Error"), tr("Wallet model not available"));
            return false;
        }

        // Build terms map from wizard fields
        QVariantMap terms;

        // Role
        bool isLongParty = field("isLongParty").toBool();
        terms["role"] = isLongParty ? "long" : "short";

        // Long party delivery leg
        QString longDeliverAssetId = field("longDeliverAssetId").toString();
        bool longDeliverIsNative = longDeliverAssetId.isEmpty();
        terms["long_deliver_is_native"] = longDeliverIsNative;
        if (!longDeliverIsNative) {
            terms["long_deliver_asset_id"] = longDeliverAssetId;
        }
        terms["long_deliver_units"] = field("longSize").toDouble();

        // Short party delivery leg (calculated from price)
        QString shortDeliverAssetId = field("shortDeliverAssetId").toString();
        bool shortDeliverIsNative = shortDeliverAssetId.isEmpty();
        terms["short_deliver_is_native"] = shortDeliverIsNative;
        if (!shortDeliverIsNative) {
            terms["short_deliver_asset_id"] = shortDeliverAssetId;
        }
        double longSize = field("longSize").toDouble();
        double price = field("price").toDouble();
        terms["short_deliver_units"] = longSize * price;

        // Long party initial margin
        QString longImAssetId = field("longImAssetId").toString();
        bool longImIsNative = longImAssetId.isEmpty();
        terms["long_im_is_native"] = longImIsNative;
        if (!longImIsNative) {
            terms["long_im_asset_id"] = longImAssetId;
        }

        bool longImPercent = field("longImPercent").toBool();
        double longImAmount;
        if (longImPercent) {
            double longImPct = field("longImPercentValue").toDouble();
            // IM as % of long delivery notional
            longImAmount = longSize * (longImPct / 100.0);
        } else {
            longImAmount = field("longImAbsoluteValue").toDouble();
        }
        terms["long_im_units"] = longImAmount;

        // Short party initial margin
        QString shortImAssetId = field("shortImAssetId").toString();
        bool shortImIsNative = shortImAssetId.isEmpty();
        terms["short_im_is_native"] = shortImIsNative;
        if (!shortImIsNative) {
            terms["short_im_asset_id"] = shortImAssetId;
        }

        bool shortImPercent = field("shortImPercent").toBool();
        double shortImAmount;
        if (shortImPercent) {
            double shortImPct = field("shortImPercentValue").toDouble();
            // IM as % of short delivery notional
            shortImAmount = (longSize * price) * (shortImPct / 100.0);
        } else {
            shortImAmount = field("shortImAbsoluteValue").toDouble();
        }
        terms["short_im_units"] = shortImAmount;

        // Premium (for options)
        if (m_isOption) {
            terms["has_premium"] = true;
            QString premiumAssetId = field("premiumAssetId").toString();
            bool premiumIsNative = premiumAssetId.isEmpty();
            terms["premium_is_native"] = premiumIsNative;
            if (!premiumIsNative) {
                terms["premium_asset_id"] = premiumAssetId;
            }
            terms["premium_units"] = field("premiumAmount").toDouble();
            terms["premium_payer"] = field("premiumPayerIsLong").toBool() ? "long" : "short";

            // Premium destination: only set if proposer receives premium
            bool premiumPayerIsLong = field("premiumPayerIsLong").toBool();
            bool proposerReceivesPremium = (isLongParty && !premiumPayerIsLong) || (!isLongParty && premiumPayerIsLong);
            if (proposerReceivesPremium) {
                terms["premium_dest"] = field("premiumDest").toString();
            }
        } else {
            terms["has_premium"] = false;
        }

        // Deadlines - use absolute if enabled, otherwise calculate from period
        int deadlineShort;
        int deadlineLong;
        int currentHeight = walletModel->getNumBlocks();
        QString maturityUnit = field("maturityUnit").toString();
        int maturityPeriod = field("maturityPeriod").toInt();
        int deliveryGap = field("deliveryGap").toInt();

        if (field("useAbsoluteHeight").toBool()) {
            // Use absolute block heights
            deadlineShort = field("absoluteShortHeight").toInt();
            deadlineLong = field("absoluteLongHeight").toInt();

            // Calculate effective maturity period for metrics (in blocks)
            maturityPeriod = deadlineShort - currentHeight;
            deliveryGap = deadlineLong - deadlineShort;

            // For tenor calculation, we'll use the block difference
            // We keep maturityUnit as "days" for the tenor calculation logic below
            maturityUnit = "days";
            maturityPeriod = maturityPeriod / 144;  // Convert blocks to days
        } else {
            // Calculate from maturity period + gap between short and long
            int maturityBlocks = 0;
            if (maturityUnit == "days") {
                maturityBlocks = maturityPeriod * 144;
            } else if (maturityUnit == "weeks") {
                maturityBlocks = maturityPeriod * 7 * 144;
            } else if (maturityUnit == "months") {
                maturityBlocks = maturityPeriod * 30 * 144;
            } else if (maturityUnit == "years") {
                maturityBlocks = maturityPeriod * 365 * 144;
            }

            // Short delivery deadline is at maturity
            // Long delivery deadline is maturity + gap
            deadlineShort = currentHeight + maturityBlocks;
            deadlineLong = currentHeight + maturityBlocks + deliveryGap;
        }

        terms["deadline_short"] = deadlineShort;
        terms["deadline_long"] = deadlineLong;
        terms["safety_k"] = field("safetyBuffer").toInt();

        // Addresses - only populate proposer's own
        // Counterparty addresses will be filled when they accept via bulletin board
        if (isLongParty) {
            terms["long_margin_dest"] = field("myMarginDest").toString();
            terms["long_settle_dest"] = field("mySettleDest").toString();
            terms["short_margin_dest"] = "";  // To be filled by counterparty
            terms["short_settle_dest"] = "";  // To be filled by counterparty
        } else {
            terms["short_margin_dest"] = field("myMarginDest").toString();
            terms["short_settle_dest"] = field("mySettleDest").toString();
            terms["long_margin_dest"] = "";  // To be filled by counterparty
            terms["long_settle_dest"] = "";  // To be filled by counterparty
        }

        // Build term sheet JSON for bulletin board posting
        // Do NOT call RPC yet - that happens when counterparty accepts
        QJsonObject termSheet;
        termSheet["schema"] = m_isOption ? QStringLiteral("option_term_sheet_v1") : QStringLiteral("forward_term_sheet_v1");
        termSheet["maker_role"] = terms["role"].toString();

        QJsonObject termsJson = QJsonObject::fromVariantMap(terms);
        termSheet["terms"] = termsJson;

        // Calculate metrics for UI/search
        double daysMaturity = maturityPeriod;
        if (maturityUnit == "weeks") {
            daysMaturity *= 7.0;
        } else if (maturityUnit == "months") {
            daysMaturity *= 30.0;
        } else if (maturityUnit == "years") {
            daysMaturity *= 365.0;
        }

        QJsonObject metricsJson;
        metricsJson["tenor_days_short"] = daysMaturity;
        metricsJson["tenor_days_long"] = daysMaturity + (deliveryGap / 144.0); // Convert gap blocks to days
        metricsJson["long_im_percent"] = longImPercent ? field("longImPercentValue").toDouble() :
            (longSize > 0 ? (longImAmount / longSize) * 100.0 : 0.0);
        metricsJson["short_im_percent"] = shortImPercent ? field("shortImPercentValue").toDouble() :
            ((longSize * price) > 0 ? (shortImAmount / (longSize * price)) * 100.0 : 0.0);
        termSheet["metrics"] = metricsJson;

        termSheetJson = QString::fromUtf8(QJsonDocument(termSheet).toJson(QJsonDocument::Compact));

        // Populate offerData
        offerData = terms;
        offerData["tenor_days_short"] = daysMaturity;
        offerData["tenor_days_long"] = daysMaturity + (deliveryGap / 144.0);
        offerData["term_sheet_json"] = termSheetJson;
        offerData["verify_funds"] = verifyFunds;  // Store fund verification preference

        // Generate a local offer ID for tracking
        // NOTE: The actual RPC call to forward.propose will happen when:
        // 1. Counterparty accepts the offer via bulletin board
        // 2. Their addresses are received
        // 3. The complete terms are then registered via forward.propose
        offerId = QString::number(QDateTime::currentMSecsSinceEpoch());
        offerJson = termSheetJson;
        offerFinalized = true;
        offerData["offer_id"] = offerId;
        offerData["bulletin_board_pending"] = true;  // Flag for bulletin board flow

        return true;

    } catch (const std::exception& e) {
        QMessageBox::critical(this, tr("Error"),
            tr("Exception while creating offer: %1").arg(QString::fromStdString(e.what())));
        return false;
    }
}

// ============================================================================
// ForwardTermSheetPage
// ============================================================================

ForwardTermSheetPage::ForwardTermSheetPage(bool isOption, QWidget* parent)
    : QWizardPage(parent)
    , m_isOption(isOption)
{
    setTitle(m_isOption ? tr("Option Contract Builder") : tr("Forward Contract Builder"));

    setupUI();
}

void ForwardTermSheetPage::setupUI()
{
    QScrollArea* scrollArea = new QScrollArea(this);
    scrollArea->setWidgetResizable(true);
    scrollArea->setFrameShape(QFrame::NoFrame);

    QWidget* scrollWidget = new QWidget();
    QVBoxLayout* mainLayout = new QVBoxLayout(scrollWidget);
    mainLayout->setSpacing(16);

    // ========================================================================
    // Role selection
    // ========================================================================
    QGroupBox* roleGroupBox = new QGroupBox(tr("Your Role"));
    QHBoxLayout* roleLayout = new QHBoxLayout(roleGroupBox);

    // Always Long Party - user can flip parameters instead
    longPartyRadio = new QRadioButton();
    longPartyRadio->setChecked(true);
    longPartyRadio->setVisible(false); // Hidden, only used for registerField

    QLabel* roleLabel = new QLabel(tr("<b>Long Party</b> (delivers long asset, receives short asset at settlement)"));
    roleLayout->addWidget(roleLabel);
    roleLayout->addStretch();

    // Add flip button to swap all long/short parameters
    QPushButton* flipButton = new QPushButton(tr("Flip Long ↔ Short"), this);
    flipButton->setToolTip(tr("Swap all long and short parameters (delivery assets, sizes, initial margins)"));
    flipButton->setStyleSheet("QPushButton { padding: 8px 16px; font-weight: bold; background-color: #2196F3; color: white; border-radius: 4px; } QPushButton:hover { background-color: #1976D2; }");
    connect(flipButton, &QPushButton::clicked, this, &ForwardTermSheetPage::onFlipLongShort);
    roleLayout->addWidget(flipButton);

    mainLayout->addWidget(roleGroupBox);

    registerField("isLongParty", longPartyRadio);

    // ========================================================================
    // Delivery leg configuration - Compact one-line format
    // ========================================================================
    deliveryGroup = new QGroupBox(tr("Delivery Obligations"));
    QVBoxLayout* deliveryMainLayout = new QVBoxLayout(deliveryGroup);

    QLabel* deliveryInfo = new QLabel(tr("The long party delivers (pays out) the long leg and receives the short party's delivery leg."));
    deliveryInfo->setWordWrap(true);
    deliveryMainLayout->addWidget(deliveryInfo);

    // Line 1: Long Party Delivers [qty] [ticker] @ [Price] [ticker short]
    QHBoxLayout* longDeliveryLayout = new QHBoxLayout();
    longDeliveryLayout->addWidget(new QLabel(tr("Long Party Delivers:")));

    longSizeSpin = new QDoubleSpinBox();
    longSizeSpin->setRange(0.00000001, 1000000000.0);
    longSizeSpin->setDecimals(8);
    longSizeSpin->setValue(1.0);
    longSizeSpin->setMinimumWidth(100);
    longDeliveryLayout->addWidget(longSizeSpin);

    longDeliverAssetCombo = new QComboBox();
    longDeliverAssetCombo->setMinimumWidth(130);
    longDeliveryLayout->addWidget(longDeliverAssetCombo);
    longDeliverUnitLabel = new QLabel();
    longDeliverUnitLabel->setVisible(false);

    longDeliveryLayout->addWidget(new QLabel(tr("  @  ")));

    priceSpin = new QDoubleSpinBox();
    priceSpin->setRange(0.00000001, 1000000000.0);
    priceSpin->setDecimals(8);
    priceSpin->setValue(1.0);
    priceSpin->setMinimumWidth(100);
    longDeliveryLayout->addWidget(priceSpin);

    shortDeliverAssetCombo = new QComboBox();
    shortDeliverAssetCombo->setMinimumWidth(130);
    longDeliveryLayout->addWidget(shortDeliverAssetCombo);
    shortDeliverUnitLabel = new QLabel();
    shortDeliverUnitLabel->setVisible(false);

    longDeliveryLayout->addStretch();
    deliveryMainLayout->addLayout(longDeliveryLayout);

    // Line 2: Short Delivers → [computed amount] [ticker]
    QHBoxLayout* shortDeliveryLayout = new QHBoxLayout();
    shortDeliveryLayout->addWidget(new QLabel(tr("Short Delivers  →  ")));

    shortSizeValueLabel = new QLabel();
    shortSizeValueLabel->setStyleSheet(ThemeHelpers::accentLabelStyleSheet(/*bold=*/true));
    shortDeliveryLayout->addWidget(shortSizeValueLabel);

    // priceUnitLabel created but not added here (ticker already in shortSizeValueLabel)
    priceUnitLabel = new QLabel();

    shortSizeLabel = new QLabel(tr("(calculated)"));
    shortSizeLabel->setVisible(false);

    shortDeliveryLayout->addStretch();
    deliveryMainLayout->addLayout(shortDeliveryLayout);

    // Hidden fields to store asset IDs and is_native flags
    longDeliverAssetIdEdit = new QLineEdit(this);
    longDeliverAssetIdEdit->setVisible(false);
    longDeliverIsNativeEdit = new QLineEdit(this);
    longDeliverIsNativeEdit->setVisible(false);
    shortDeliverAssetIdEdit = new QLineEdit(this);
    shortDeliverAssetIdEdit->setVisible(false);
    shortDeliverIsNativeEdit = new QLineEdit(this);
    shortDeliverIsNativeEdit->setVisible(false);
    longSizeUnitLabel = new QLabel();
    longSizeUnitLabel->setVisible(false);

    mainLayout->addWidget(deliveryGroup);

    // Register asset ID and is_native fields
    registerField("longDeliverAssetId", longDeliverAssetIdEdit);
    registerField("longDeliverIsNative", longDeliverIsNativeEdit);
    registerField("shortDeliverAssetId", shortDeliverAssetIdEdit);
    registerField("shortDeliverIsNative", shortDeliverIsNativeEdit);

    registerField("longSize", longSizeSpin, "value", SIGNAL(valueChanged(double)));
    registerField("price", priceSpin, "value", SIGNAL(valueChanged(double)));

    // ========================================================================
    // Initial Margin configuration - Simplified
    // ========================================================================
    marginGroup = new QGroupBox(tr("Initial Margin"));
    QVBoxLayout* marginMainLayout = new QVBoxLayout(marginGroup);

    // Long party IM - Single line: IM [%] [Ticker] → [computed amount]
    QHBoxLayout* longImLayout = new QHBoxLayout();
    longImLayout->addWidget(new QLabel(tr("Long IM:")));

    longImPercentSpin = new QDoubleSpinBox();
    longImPercentSpin->setRange(0.0, 100.0);
    longImPercentSpin->setDecimals(2);
    longImPercentSpin->setValue(10.0);
    longImPercentSpin->setSuffix(" %");
    longImLayout->addWidget(longImPercentSpin);

    longImAssetCombo = new QComboBox();
    longImAssetCombo->setMinimumWidth(130);
    longImLayout->addWidget(longImAssetCombo);
    longImAssetLabel = new QLabel();
    longImAssetLabel->setVisible(false);

    longImLayout->addWidget(new QLabel(tr("  →  ")));

    longImCalculatedLabel = new QLabel();
    longImCalculatedLabel->setStyleSheet(QStringLiteral("font-weight: bold; color: %1;").arg(ThemeHelpers::accentTextColor()));
    longImLayout->addWidget(longImCalculatedLabel);

    longImLayout->addStretch();
    marginMainLayout->addLayout(longImLayout);

    // Hidden fields and controls
    longImAssetIdEdit = new QLineEdit(this);
    longImAssetIdEdit->setVisible(false);
    longImIsNativeEdit = new QLineEdit(this);
    longImIsNativeEdit->setVisible(false);
    longImPercentRadio = new QRadioButton(tr("As % of notional"));
    longImPercentRadio->setVisible(false);
    longImPercentRadio->setChecked(true);
    longImAbsoluteRadio = new QRadioButton(tr("Absolute amount"));
    longImAbsoluteRadio->setVisible(false);
    longImModeGroup = new QButtonGroup(this);
    longImModeGroup->addButton(longImPercentRadio, 0);
    longImModeGroup->addButton(longImAbsoluteRadio, 1);
    longImAbsoluteSpin = new QDoubleSpinBox();
    longImAbsoluteSpin->setVisible(false);
    longImAbsoluteSpin->setRange(0.0, 1000000000.0);
    longImAbsoluteSpin->setDecimals(8);
    longImAbsoluteSpin->setValue(0.1);
    longImAbsoluteUnitLabel = new QLabel();
    longImAbsoluteUnitLabel->setVisible(false);
    longImPercentLabel = new QLabel();
    longImPercentLabel->setVisible(false);

    registerField("longImAssetId", longImAssetIdEdit);
    registerField("longImIsNative", longImIsNativeEdit);
    registerField("longImPercent", longImPercentRadio);
    registerField("longImPercentValue", longImPercentSpin, "value", SIGNAL(valueChanged(double)));
    registerField("longImAbsoluteValue", longImAbsoluteSpin, "value", SIGNAL(valueChanged(double)));

    // Short party IM - Single line: IM [%] [Ticker] → [computed amount]
    QHBoxLayout* shortImLayout = new QHBoxLayout();
    shortImLayout->addWidget(new QLabel(tr("Short IM:")));

    shortImPercentSpin = new QDoubleSpinBox();
    shortImPercentSpin->setRange(0.0, 100.0);
    shortImPercentSpin->setDecimals(2);
    shortImPercentSpin->setValue(10.0);
    shortImPercentSpin->setSuffix(" %");
    shortImLayout->addWidget(shortImPercentSpin);

    shortImAssetCombo = new QComboBox();
    shortImAssetCombo->setMinimumWidth(130);
    shortImLayout->addWidget(shortImAssetCombo);
    shortImAssetLabel = new QLabel();
    shortImAssetLabel->setVisible(false);

    shortImLayout->addWidget(new QLabel(tr("  →  ")));

    shortImCalculatedLabel = new QLabel();
    shortImCalculatedLabel->setStyleSheet(QStringLiteral("font-weight: bold; color: %1;").arg(ThemeHelpers::accentTextColor()));
    shortImLayout->addWidget(shortImCalculatedLabel);

    shortImLayout->addStretch();
    marginMainLayout->addLayout(shortImLayout);

    // Hidden fields and controls
    shortImAssetIdEdit = new QLineEdit(this);
    shortImAssetIdEdit->setVisible(false);
    shortImIsNativeEdit = new QLineEdit(this);
    shortImIsNativeEdit->setVisible(false);
    shortImPercentRadio = new QRadioButton(tr("As % of notional"));
    shortImPercentRadio->setVisible(false);
    shortImPercentRadio->setChecked(true);
    shortImAbsoluteRadio = new QRadioButton(tr("Absolute amount"));
    shortImAbsoluteRadio->setVisible(false);
    shortImModeGroup = new QButtonGroup(this);
    shortImModeGroup->addButton(shortImPercentRadio, 0);
    shortImModeGroup->addButton(shortImAbsoluteRadio, 1);
    shortImAbsoluteSpin = new QDoubleSpinBox();
    shortImAbsoluteSpin->setVisible(false);
    shortImAbsoluteSpin->setRange(0.0, 1000000000.0);
    shortImAbsoluteSpin->setDecimals(8);
    shortImAbsoluteSpin->setValue(0.1);
    shortImAbsoluteUnitLabel = new QLabel();
    shortImAbsoluteUnitLabel->setVisible(false);
    shortImPercentLabel = new QLabel();
    shortImPercentLabel->setVisible(false);

    mainLayout->addWidget(marginGroup);

    registerField("shortImAssetId", shortImAssetIdEdit);
    registerField("shortImIsNative", shortImIsNativeEdit);
    registerField("shortImPercent", shortImPercentRadio);
    registerField("shortImPercentValue", shortImPercentSpin, "value", SIGNAL(valueChanged(double)));
    registerField("shortImAbsoluteValue", shortImAbsoluteSpin, "value", SIGNAL(valueChanged(double)));

    // ========================================================================
    // Deadline configuration - Collapsed to 3 lines
    // ========================================================================
    deadlineGroup = new QGroupBox(tr("Delivery Deadlines"));
    QVBoxLayout* deadlineMainLayout = new QVBoxLayout(deadlineGroup);

    // Line 1: Maturity Period, Gap, Safety
    QHBoxLayout* deadlineLine1 = new QHBoxLayout();
    deadlineLine1->addWidget(new QLabel(tr("Period:")));
    maturityPeriodSpin = new QSpinBox();
    maturityPeriodSpin->setRange(1, 10000);
    maturityPeriodSpin->setValue(7);
    deadlineLine1->addWidget(maturityPeriodSpin);
    maturityUnitCombo = new QComboBox();
    maturityUnitCombo->addItem(tr("Days"), "days");
    maturityUnitCombo->addItem(tr("Weeks"), "weeks");
    maturityUnitCombo->addItem(tr("Months"), "months");
    maturityUnitCombo->addItem(tr("Years"), "years");
    maturityUnitCombo->setCurrentIndex(0);
    deadlineLine1->addWidget(maturityUnitCombo);

    deadlineLine1->addWidget(new QLabel(tr("  Gap:")));
    deliveryGapSpin = new QSpinBox();
    deliveryGapSpin->setRange(0, 100000);
    deliveryGapSpin->setValue(144);  // Default 1 day
    deliveryGapSpin->setSuffix(tr(" blks"));
    deadlineLine1->addWidget(deliveryGapSpin);
    deliveryGapLabel = new QLabel();
    deliveryGapLabel->setVisible(false);

    deadlineLine1->addWidget(new QLabel(tr("  Safety:")));
    safetyBufferSpin = new QSpinBox();
    safetyBufferSpin->setRange(1, 1000);
    safetyBufferSpin->setValue(5);
    safetyBufferSpin->setSuffix(tr(" blks"));
    deadlineLine1->addWidget(safetyBufferSpin);
    deadlineLine1->addStretch();
    deadlineMainLayout->addLayout(deadlineLine1);

    // Line 2: Absolute heights checkbox and spinboxes
    QHBoxLayout* deadlineLine1b = new QHBoxLayout();
    useAbsoluteHeightCheck = new QCheckBox(tr("Absolute heights"), this);
    deadlineLine1b->addWidget(useAbsoluteHeightCheck);
    absoluteShortHeightSpin = new QSpinBox();
    absoluteShortHeightSpin->setRange(1, 10000000);
    absoluteShortHeightSpin->setValue(1000);
    absoluteShortHeightSpin->setEnabled(false);
    absoluteShortHeightSpin->setPrefix(tr("Short: "));
    deadlineLine1b->addWidget(absoluteShortHeightSpin);
    absoluteLongHeightSpin = new QSpinBox();
    absoluteLongHeightSpin->setRange(1, 10000000);
    absoluteLongHeightSpin->setValue(1144);
    absoluteLongHeightSpin->setEnabled(false);
    absoluteLongHeightSpin->setPrefix(tr("Long: "));
    deadlineLine1b->addWidget(absoluteLongHeightSpin);

    connect(useAbsoluteHeightCheck, &QCheckBox::toggled, this, [this](bool checked) {
        maturityPeriodSpin->setEnabled(!checked);
        maturityUnitCombo->setEnabled(!checked);
        deliveryGapSpin->setEnabled(!checked);
        absoluteShortHeightSpin->setEnabled(checked);
        absoluteLongHeightSpin->setEnabled(checked);
        if (checked) {
            deadlineShortHeightLabel->setText(tr("Short: %1").arg(absoluteShortHeightSpin->value()));
            deadlineLongHeightLabel->setText(tr("Long: %1").arg(absoluteLongHeightSpin->value()));
        } else {
            updateDeadlineHeights();
        }
    });
    connect(absoluteShortHeightSpin, QOverload<int>::of(&QSpinBox::valueChanged), this, [this](int value) {
        if (useAbsoluteHeightCheck->isChecked()) {
            deadlineShortHeightLabel->setText(tr("Short: %1").arg(value));
            if (absoluteLongHeightSpin->value() < value) {
                absoluteLongHeightSpin->setValue(value + 144);
            }
        }
    });
    connect(absoluteLongHeightSpin, QOverload<int>::of(&QSpinBox::valueChanged), this, [this](int value) {
        if (useAbsoluteHeightCheck->isChecked()) {
            deadlineLongHeightLabel->setText(tr("Long: %1").arg(value));
        }
    });
    deadlineLine1b->addStretch();
    deadlineMainLayout->addLayout(deadlineLine1b);

    // Line 3: Current height
    QHBoxLayout* deadlineLine2 = new QHBoxLayout();
    deadlineLine2->addWidget(new QLabel(tr("Current:")));
    currentHeightLabel = new QLabel();
    currentHeightLabel->setStyleSheet(ThemeHelpers::mutedLabelStyleSheet());
    deadlineLine2->addWidget(currentHeightLabel);
    deadlineLine2->addStretch();
    deadlineMainLayout->addLayout(deadlineLine2);

    // Line 3: Target heights
    QHBoxLayout* deadlineLine3 = new QHBoxLayout();
    deadlineLine3->addWidget(new QLabel(tr("→ Targets:")));
    deadlineShortHeightLabel = new QLabel();
    deadlineShortHeightLabel->setStyleSheet(ThemeHelpers::accentLabelStyleSheet(/*bold=*/true));
    deadlineLine3->addWidget(deadlineShortHeightLabel);
    deadlineLine3->addWidget(new QLabel(tr(" | ")));
    deadlineLongHeightLabel = new QLabel();
    deadlineLongHeightLabel->setStyleSheet(ThemeHelpers::accentLabelStyleSheet(/*bold=*/true));
    deadlineLine3->addWidget(deadlineLongHeightLabel);
    deadlineLine3->addStretch();
    deadlineMainLayout->addLayout(deadlineLine3);

    maturityPeriodLabel = new QLabel();
    maturityPeriodLabel->setVisible(false);

    mainLayout->addWidget(deadlineGroup);

    registerField("maturityPeriod", maturityPeriodSpin);
    registerField("deliveryGap", deliveryGapSpin);
    registerField("maturityUnit", maturityUnitCombo, "currentData", SIGNAL(currentIndexChanged(int)));
    registerField("useAbsoluteHeight", useAbsoluteHeightCheck);
    registerField("absoluteShortHeight", absoluteShortHeightSpin);
    registerField("absoluteLongHeight", absoluteLongHeightSpin);
    registerField("safetyBuffer", safetyBufferSpin);

    // ========================================================================
    // Addresses - Collapsible (Advanced)
    // ========================================================================
    addressGroup = new QGroupBox(tr("Settlement && Margin Addresses (Advanced)"));
    addressGroup->setCheckable(true);
    addressGroup->setChecked(false); // Hidden by default
    QGridLayout* addressLayout = new QGridLayout(addressGroup);
    int row = 0;

    addressLayout->addWidget(new QLabel(tr("Margin Refund Dest:")), row, 0);
    myMarginDestEdit = new QLineEdit();
    myMarginDestEdit->setPlaceholderText(tr("Address to refund your initial margin"));
    addressLayout->addWidget(myMarginDestEdit, row, 1);
    generateMyMarginButton = new QPushButton(tr("Generate"));
    addressLayout->addWidget(generateMyMarginButton, row, 2);
    row++;

    addressLayout->addWidget(new QLabel(tr("Settlement Receive Dest:")), row, 0);
    mySettleDestEdit = new QLineEdit();
    mySettleDestEdit->setPlaceholderText(tr("Address to receive your settlement asset"));
    addressLayout->addWidget(mySettleDestEdit, row, 1);
    generateMySettleButton = new QPushButton(tr("Generate"));
    addressLayout->addWidget(generateMySettleButton, row, 2);
    row++;

    mainLayout->addWidget(addressGroup);

    registerField("myMarginDest*", myMarginDestEdit);
    registerField("mySettleDest*", mySettleDestEdit);

    // ========================================================================
    // Premium configuration (at bottom to demote importance)
    // ========================================================================
    premiumGroup = new QGroupBox(tr("Premium Payment (Optional)"));
    QVBoxLayout* premiumMainLayout = new QVBoxLayout(premiumGroup);

    // Checkbox to enable/disable premium
    enablePremiumCheckBox = new QCheckBox(tr("Enable premium payment"));
    enablePremiumCheckBox->setChecked(m_isOption); // Default ON for options, OFF for forwards
    premiumMainLayout->addWidget(enablePremiumCheckBox);

    // Widget containing all premium fields (can be hidden)
    premiumFieldsWidget = new QWidget();
    QGridLayout* premiumLayout = new QGridLayout(premiumFieldsWidget);
    int premiumRow = 0;

    premiumLayout->addWidget(new QLabel(tr("Premium Asset:")), premiumRow, 0);
    premiumAssetCombo = new QComboBox();
    premiumLayout->addWidget(premiumAssetCombo, premiumRow, 1);
    premiumAssetLabel = new QLabel();
    premiumLayout->addWidget(premiumAssetLabel, premiumRow, 2);

    // Hidden field to store asset ID and is_native flag
    premiumAssetIdEdit = new QLineEdit(this);
    premiumAssetIdEdit->setVisible(false);
    premiumIsNativeEdit = new QLineEdit(this);
    premiumIsNativeEdit->setVisible(false);
    premiumRow++;

    premiumLayout->addWidget(new QLabel(tr("Premium Amount:")), premiumRow, 0);
    premiumAmountSpin = new QDoubleSpinBox();
    premiumAmountSpin->setRange(0.00000001, 1000000000.0);
    premiumAmountSpin->setDecimals(8);
    premiumAmountSpin->setValue(0.01);
    premiumLayout->addWidget(premiumAmountSpin, premiumRow, 1);
    premiumAmountUnitLabel = new QLabel();
    premiumLayout->addWidget(premiumAmountUnitLabel, premiumRow, 2);
    premiumRow++;

    premiumLayout->addWidget(new QLabel(tr("Premium Payer:")), premiumRow, 0);
    QHBoxLayout* premiumPayerLayout = new QHBoxLayout();
    premiumPayerLongRadio = new QRadioButton(tr("Long Party"));
    premiumPayerShortRadio = new QRadioButton(tr("Short Party"));
    premiumPayerGroup = new QButtonGroup(this);
    premiumPayerGroup->addButton(premiumPayerLongRadio, 0);
    premiumPayerGroup->addButton(premiumPayerShortRadio, 1);
    premiumPayerLongRadio->setChecked(true);
    premiumPayerLayout->addWidget(premiumPayerLongRadio);
    premiumPayerLayout->addWidget(premiumPayerShortRadio);
    premiumPayerLayout->addStretch();
    premiumLayout->addLayout(premiumPayerLayout, premiumRow, 1, 1, 2);
    premiumRow++;

    premiumLayout->addWidget(new QLabel(tr("Premium Destination:")), premiumRow, 0);
    premiumDestEdit = new QLineEdit();
    premiumDestEdit->setPlaceholderText(tr("Address to receive premium (only if you receive it)"));
    premiumLayout->addWidget(premiumDestEdit, premiumRow, 1);
    generatePremiumButton = new QPushButton(tr("Generate"));
    premiumLayout->addWidget(generatePremiumButton, premiumRow, 2);
    premiumRow++;

    premiumMainLayout->addWidget(premiumFieldsWidget);
    premiumFieldsWidget->setVisible(enablePremiumCheckBox->isChecked());
    mainLayout->addWidget(premiumGroup);

    // Register premium asset ID and is_native fields
    registerField("premiumAssetId", premiumAssetIdEdit);
    registerField("premiumIsNative", premiumIsNativeEdit);

    registerField("premiumAmount", premiumAmountSpin, "value", SIGNAL(valueChanged(double)));
    registerField("premiumPayerIsLong", premiumPayerLongRadio);
    registerField("premiumDest", premiumDestEdit);

    connect(enablePremiumCheckBox, &QCheckBox::toggled,
            this, &ForwardTermSheetPage::onEnablePremiumChanged);
    connect(premiumAssetCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &ForwardTermSheetPage::onPremiumAssetChanged);
    connect(premiumAmountSpin, QOverload<double>::of(&QDoubleSpinBox::valueChanged),
            this, &ForwardTermSheetPage::onPremiumAmountChanged);
    connect(premiumPayerLongRadio, &QRadioButton::toggled,
            this, &ForwardTermSheetPage::onPremiumPayerChanged);
    connect(premiumPayerShortRadio, &QRadioButton::toggled,
            this, &ForwardTermSheetPage::onPremiumPayerChanged);
    connect(generatePremiumButton, &QPushButton::clicked,
            this, &ForwardTermSheetPage::onGeneratePremiumAddress);

    // ========================================================================
    // Connect signals
    // ========================================================================
    // Role is always Long Party now, no need for role change signal

    connect(longDeliverAssetCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &ForwardTermSheetPage::onLongDeliverAssetChanged);
    connect(shortDeliverAssetCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &ForwardTermSheetPage::onShortDeliverAssetChanged);
    connect(longSizeSpin, QOverload<double>::of(&QDoubleSpinBox::valueChanged),
            this, &ForwardTermSheetPage::onLongSizeChanged);
    connect(priceSpin, QOverload<double>::of(&QDoubleSpinBox::valueChanged),
            this, &ForwardTermSheetPage::onPriceChanged);

    connect(longImAssetCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &ForwardTermSheetPage::onLongImAssetChanged);
    connect(shortImAssetCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &ForwardTermSheetPage::onShortImAssetChanged);
    connect(longImPercentRadio, &QRadioButton::toggled, this, &ForwardTermSheetPage::onLongImModeChanged);
    connect(longImAbsoluteRadio, &QRadioButton::toggled, this, &ForwardTermSheetPage::onLongImModeChanged);
    connect(shortImPercentRadio, &QRadioButton::toggled, this, &ForwardTermSheetPage::onShortImModeChanged);
    connect(shortImAbsoluteRadio, &QRadioButton::toggled, this, &ForwardTermSheetPage::onShortImModeChanged);
    connect(longImPercentSpin, QOverload<double>::of(&QDoubleSpinBox::valueChanged),
            this, &ForwardTermSheetPage::onLongImPercentChanged);
    connect(longImAbsoluteSpin, QOverload<double>::of(&QDoubleSpinBox::valueChanged),
            this, &ForwardTermSheetPage::onLongImAbsoluteChanged);
    connect(shortImPercentSpin, QOverload<double>::of(&QDoubleSpinBox::valueChanged),
            this, &ForwardTermSheetPage::onShortImPercentChanged);
    connect(shortImAbsoluteSpin, QOverload<double>::of(&QDoubleSpinBox::valueChanged),
            this, &ForwardTermSheetPage::onShortImAbsoluteChanged);

    connect(maturityPeriodSpin, QOverload<int>::of(&QSpinBox::valueChanged),
            this, &ForwardTermSheetPage::onMaturityPeriodChanged);
    connect(deliveryGapSpin, QOverload<int>::of(&QSpinBox::valueChanged),
            this, &ForwardTermSheetPage::onDeliveryGapChanged);
    connect(maturityUnitCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &ForwardTermSheetPage::onMaturityUnitChanged);

    connect(generateMyMarginButton, &QPushButton::clicked,
            this, &ForwardTermSheetPage::onGenerateMyMarginAddress);
    connect(generateMySettleButton, &QPushButton::clicked,
            this, &ForwardTermSheetPage::onGenerateMySettleAddress);

    // ========================================================================
    // Pricing Breakdown Section
    // ========================================================================
    QGroupBox* pricingGroup = new QGroupBox(tr("Pricing Breakdown"), this);
    pricingGroup->setStyleSheet(ThemeHelpers::panelStyleSheet());
    QGridLayout* pricingLayout = new QGridLayout(pricingGroup);

    int pricingRow = 0;

    // Header row
    pricingLayout->addWidget(new QLabel(tr(""), this), pricingRow, 0);
    pricingLayout->addWidget(new QLabel(tr("Absolute"), this), pricingRow, 1);
    pricingLayout->addWidget(new QLabel(tr("Per Notional"), this), pricingRow, 2);
    pricingRow++;

    // PV Receive
    pricingLayout->addWidget(new QLabel(tr("PV Receive:"), this), pricingRow, 0);
    pvReceiveLabel = new QLabel(tr("--"), this);
    pvReceiveLabel->setStyleSheet(ThemeHelpers::accentLabelStyleSheet(/*bold=*/false));
    pricingLayout->addWidget(pvReceiveLabel, pricingRow, 1);
    pvReceivePerNotionalLabel = new QLabel(tr("--"), this);
    pvReceivePerNotionalLabel->setStyleSheet(ThemeHelpers::accentLabelStyleSheet(/*bold=*/false));
    pricingLayout->addWidget(pvReceivePerNotionalLabel, pricingRow++, 2);

    // PV Pay
    pricingLayout->addWidget(new QLabel(tr("PV Pay:"), this), pricingRow, 0);
    pvPayLabel = new QLabel(tr("--"), this);
    pvPayLabel->setStyleSheet(ThemeHelpers::accentLabelStyleSheet(/*bold=*/false));
    pricingLayout->addWidget(pvPayLabel, pricingRow, 1);
    pvPayPerNotionalLabel = new QLabel(tr("--"), this);
    pvPayPerNotionalLabel->setStyleSheet(ThemeHelpers::accentLabelStyleSheet(/*bold=*/false));
    pricingLayout->addWidget(pvPayPerNotionalLabel, pricingRow++, 2);

    // Net Spread Value
    pricingLayout->addWidget(new QLabel(tr("Net Spread Value:"), this), pricingRow, 0);
    netSpreadLabel = new QLabel(tr("--"), this);
    netSpreadLabel->setStyleSheet(ThemeHelpers::accentLabelStyleSheet(/*bold=*/false));
    pricingLayout->addWidget(netSpreadLabel, pricingRow, 1);
    netSpreadPerNotionalLabel = new QLabel(tr("--"), this);
    netSpreadPerNotionalLabel->setStyleSheet(ThemeHelpers::accentLabelStyleSheet(/*bold=*/false));
    pricingLayout->addWidget(netSpreadPerNotionalLabel, pricingRow++, 2);

    // Premium PV
    pricingLayout->addWidget(new QLabel(tr("Premium PV:"), this), pricingRow, 0);
    premiumPvLabel = new QLabel(tr("--"), this);
    premiumPvLabel->setStyleSheet(ThemeHelpers::accentLabelStyleSheet(/*bold=*/false));
    pricingLayout->addWidget(premiumPvLabel, pricingRow, 1);
    premiumPvPerNotionalLabel = new QLabel(tr("--"), this);
    premiumPvPerNotionalLabel->setStyleSheet(ThemeHelpers::accentLabelStyleSheet(/*bold=*/false));
    pricingLayout->addWidget(premiumPvPerNotionalLabel, pricingRow++, 2);

    // Long Short Call Value
    pricingLayout->addWidget(new QLabel(tr("Long Short Call Value:"), this), pricingRow, 0);
    aliceShortCallLabel = new QLabel(tr("--"), this);
    aliceShortCallLabel->setStyleSheet(ThemeHelpers::accentLabelStyleSheet(/*bold=*/false));
    pricingLayout->addWidget(aliceShortCallLabel, pricingRow, 1);
    aliceShortCallPerNotionalLabel = new QLabel(tr("--"), this);
    aliceShortCallPerNotionalLabel->setStyleSheet(ThemeHelpers::accentLabelStyleSheet(/*bold=*/false));
    pricingLayout->addWidget(aliceShortCallPerNotionalLabel, pricingRow++, 2);

    // Long Long Put Value
    pricingLayout->addWidget(new QLabel(tr("Long Long Put Value:"), this), pricingRow, 0);
    aliceLongPutLabel = new QLabel(tr("--"), this);
    aliceLongPutLabel->setStyleSheet(ThemeHelpers::accentLabelStyleSheet(/*bold=*/false));
    pricingLayout->addWidget(aliceLongPutLabel, pricingRow, 1);
    aliceLongPutPerNotionalLabel = new QLabel(tr("--"), this);
    aliceLongPutPerNotionalLabel->setStyleSheet(ThemeHelpers::accentLabelStyleSheet(/*bold=*/false));
    pricingLayout->addWidget(aliceLongPutPerNotionalLabel, pricingRow++, 2);

    // Add separator
    QFrame* separator = new QFrame(this);
    separator->setFrameShape(QFrame::HLine);
    separator->setFrameShadow(QFrame::Sunken);
    pricingLayout->addWidget(separator, pricingRow++, 0, 1, 3);

    // Long MTM
    pricingLayout->addWidget(new QLabel(tr("Long MTM:"), this), pricingRow, 0);
    aliceMtmLabel = new QLabel(tr("--"), this);
    aliceMtmLabel->setStyleSheet("QLabel { font-weight: bold; }");
    pricingLayout->addWidget(aliceMtmLabel, pricingRow, 1);
    aliceMtmPerNotionalLabel = new QLabel(tr("--"), this);
    aliceMtmPerNotionalLabel->setStyleSheet("QLabel { font-weight: bold; }");
    pricingLayout->addWidget(aliceMtmPerNotionalLabel, pricingRow++, 2);

    // Short MTM
    pricingLayout->addWidget(new QLabel(tr("Short MTM:"), this), pricingRow, 0);
    bobMtmLabel = new QLabel(tr("--"), this);
    bobMtmLabel->setStyleSheet("QLabel { font-weight: bold; }");
    pricingLayout->addWidget(bobMtmLabel, pricingRow, 1);
    bobMtmPerNotionalLabel = new QLabel(tr("--"), this);
    bobMtmPerNotionalLabel->setStyleSheet("QLabel { font-weight: bold; }");
    pricingLayout->addWidget(bobMtmPerNotionalLabel, pricingRow++, 2);

    // IM Coverage Long
    pricingLayout->addWidget(new QLabel(tr("IM Coverage Long:"), this), pricingRow, 0);
    imCoverageAliceLabel = new QLabel(tr("--"), this);
    imCoverageAliceLabel->setStyleSheet(ThemeHelpers::accentLabelStyleSheet(/*bold=*/false));
    pricingLayout->addWidget(imCoverageAliceLabel, pricingRow, 1);
    imCoverageAlicePerNotionalLabel = new QLabel(tr("--"), this);
    imCoverageAlicePerNotionalLabel->setStyleSheet(ThemeHelpers::accentLabelStyleSheet(/*bold=*/false));
    pricingLayout->addWidget(imCoverageAlicePerNotionalLabel, pricingRow++, 2);

    // IM Coverage Short
    pricingLayout->addWidget(new QLabel(tr("IM Coverage Short:"), this), pricingRow, 0);
    imCoverageBobLabel = new QLabel(tr("--"), this);
    imCoverageBobLabel->setStyleSheet(ThemeHelpers::accentLabelStyleSheet(/*bold=*/false));
    pricingLayout->addWidget(imCoverageBobLabel, pricingRow, 1);
    imCoverageBobPerNotionalLabel = new QLabel(tr("--"), this);
    imCoverageBobPerNotionalLabel->setStyleSheet(ThemeHelpers::accentLabelStyleSheet(/*bold=*/false));
    pricingLayout->addWidget(imCoverageBobPerNotionalLabel, pricingRow++, 2);

    pricingGroup->setLayout(pricingLayout);
    mainLayout->addWidget(pricingGroup);

    // Add "Show Greeks" button below pricing
    showGreeksButton = new QPushButton(tr("View Greeks"), this);
    showGreeksButton->setStyleSheet(
        "QPushButton { "
        "background-color: #673ab7; "
        "color: white; "
        "font-weight: bold; "
        "padding: 8px 16px; "
        "border-radius: 4px; "
        "}"
        "QPushButton:hover { background-color: #5e35b1; }"
    );
    connect(showGreeksButton, &QPushButton::clicked, this, &ForwardTermSheetPage::onShowGreeks);
    mainLayout->addWidget(showGreeksButton);

    // Create debounce timer for pricing updates
    pricingDebounceTimer = new QTimer(this);
    pricingDebounceTimer->setSingleShot(true);
    pricingDebounceTimer->setInterval(500); // 500ms debounce
    connect(pricingDebounceTimer, &QTimer::timeout, this, &ForwardTermSheetPage::updateForwardPricing);

    // Connect all input fields to restart the timer
    connect(longDeliverAssetCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, [this]() { pricingDebounceTimer->start(); });
    connect(shortDeliverAssetCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, [this]() { pricingDebounceTimer->start(); });
    connect(longSizeSpin, QOverload<double>::of(&QDoubleSpinBox::valueChanged),
            this, [this]() { pricingDebounceTimer->start(); });
    connect(priceSpin, QOverload<double>::of(&QDoubleSpinBox::valueChanged),
            this, [this]() { pricingDebounceTimer->start(); });
    connect(longImAssetCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, [this]() { pricingDebounceTimer->start(); });
    connect(shortImAssetCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, [this]() { pricingDebounceTimer->start(); });
    connect(longImPercentSpin, QOverload<double>::of(&QDoubleSpinBox::valueChanged),
            this, [this]() { pricingDebounceTimer->start(); });
    connect(shortImPercentSpin, QOverload<double>::of(&QDoubleSpinBox::valueChanged),
            this, [this]() { pricingDebounceTimer->start(); });
    connect(longImAbsoluteSpin, QOverload<double>::of(&QDoubleSpinBox::valueChanged),
            this, [this]() { pricingDebounceTimer->start(); });
    connect(shortImAbsoluteSpin, QOverload<double>::of(&QDoubleSpinBox::valueChanged),
            this, [this]() { pricingDebounceTimer->start(); });
    connect(maturityPeriodSpin, QOverload<int>::of(&QSpinBox::valueChanged),
            this, [this]() { pricingDebounceTimer->start(); });
    connect(deliveryGapSpin, QOverload<int>::of(&QSpinBox::valueChanged),
            this, [this]() { pricingDebounceTimer->start(); });
    connect(maturityUnitCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, [this]() { pricingDebounceTimer->start(); });
    connect(safetyBufferSpin, QOverload<int>::of(&QSpinBox::valueChanged),
            this, [this]() { pricingDebounceTimer->start(); });
    connect(absoluteShortHeightSpin, QOverload<int>::of(&QSpinBox::valueChanged),
            this, [this]() { pricingDebounceTimer->start(); });
    connect(absoluteLongHeightSpin, QOverload<int>::of(&QSpinBox::valueChanged),
            this, [this]() { pricingDebounceTimer->start(); });
    if (premiumAssetCombo) {
        connect(premiumAssetCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
                this, [this]() { pricingDebounceTimer->start(); });
    }
    if (premiumAmountSpin) {
        connect(premiumAmountSpin, QOverload<double>::of(&QDoubleSpinBox::valueChanged),
                this, [this]() { pricingDebounceTimer->start(); });
    }
    if (enablePremiumCheckBox) {
        connect(enablePremiumCheckBox, &QCheckBox::toggled,
                this, [this]() { pricingDebounceTimer->start(); });
    }

    mainLayout->addStretch();

    scrollArea->setWidget(scrollWidget);

    QVBoxLayout* pageLayout = new QVBoxLayout(this);
    pageLayout->setContentsMargins(0, 0, 0, 0);
    pageLayout->addWidget(scrollArea);

    // Install wheel event filters to prevent accidental changes while scrolling
    GUIUtil::InstallWheelEventFilter(longDeliverAssetCombo);
    GUIUtil::InstallWheelEventFilter(longSizeSpin);
    GUIUtil::InstallWheelEventFilter(shortDeliverAssetCombo);
    GUIUtil::InstallWheelEventFilter(priceSpin);
    GUIUtil::InstallWheelEventFilter(longImAssetCombo);
    GUIUtil::InstallWheelEventFilter(longImPercentSpin);
    GUIUtil::InstallWheelEventFilter(longImAbsoluteSpin);
    GUIUtil::InstallWheelEventFilter(shortImAssetCombo);
    GUIUtil::InstallWheelEventFilter(shortImPercentSpin);
    GUIUtil::InstallWheelEventFilter(shortImAbsoluteSpin);
    if (premiumAssetCombo) GUIUtil::InstallWheelEventFilter(premiumAssetCombo);
    if (premiumAmountSpin) GUIUtil::InstallWheelEventFilter(premiumAmountSpin);
    GUIUtil::InstallWheelEventFilter(maturityPeriodSpin);
    GUIUtil::InstallWheelEventFilter(maturityUnitCombo);
    GUIUtil::InstallWheelEventFilter(deliveryGapSpin);
    GUIUtil::InstallWheelEventFilter(absoluteShortHeightSpin);
    GUIUtil::InstallWheelEventFilter(absoluteLongHeightSpin);
    GUIUtil::InstallWheelEventFilter(safetyBufferSpin);
}

void ForwardTermSheetPage::initializePage()
{
    // Populate asset combos
    populateAssetComboBox(longDeliverAssetCombo, true);
    populateAssetComboBox(shortDeliverAssetCombo, true);
    populateAssetComboBox(longImAssetCombo, true);
    populateAssetComboBox(shortImAssetCombo, true);

    // Always populate premium combo (visible for both forward and options)
    if (premiumAssetCombo) {
        populateAssetComboBox(premiumAssetCombo, true);
    }

    // Set default IM assets to match delivery assets
    longImAssetCombo->setCurrentIndex(longDeliverAssetCombo->currentIndex());
    shortImAssetCombo->setCurrentIndex(shortDeliverAssetCombo->currentIndex());

    // Auto-generate settlement and margin addresses if empty
    if (myMarginDestEdit->text().isEmpty()) {
        onGenerateMyMarginAddress();
    }
    if (mySettleDestEdit->text().isEmpty()) {
        onGenerateMySettleAddress();
    }

    // Update all labels and calculations
    onLongDeliverAssetChanged(longDeliverAssetCombo->currentIndex());
    onShortDeliverAssetChanged(shortDeliverAssetCombo->currentIndex());
    onLongImAssetChanged(longImAssetCombo->currentIndex());
    onShortImAssetChanged(shortImAssetCombo->currentIndex());

    // Always initialize premium fields (visible for both forward and options)
    if (premiumAssetCombo) {
        onPremiumAssetChanged(premiumAssetCombo->currentIndex());
    }

    updateCalculations();
    updateDeadlineHeights();
}

bool ForwardTermSheetPage::validatePage()
{
    auto* wizard = qobject_cast<ForwardContractBuilder*>(this->wizard());
    if (!wizard) return false;

    return wizard->validateTerms();
}

void ForwardTermSheetPage::populateAssetComboBox(QComboBox* combo, bool includeNative)
{
    if (!combo) return;

    combo->clear();

    if (includeNative) {
        combo->addItem(tr("TSC (Native)"), QVariant::fromValue(QString("native")));
    }

    auto* wizardPtr = qobject_cast<ForwardContractBuilder*>(wizard());
    if (!wizardPtr || !wizardPtr->walletModel) return;

    QList<WalletModel::AssetInfo> assets = wizardPtr->walletModel->listAssets();
    for (const auto& asset : assets) {
        QString label = QString("%1 (%2)").arg(asset.ticker, asset.asset_id.left(8));
        combo->addItem(label, QVariant::fromValue(asset.asset_id));
    }
}

QString ForwardTermSheetPage::getAssetIdFromCombo(QComboBox* combo) const
{
    if (!combo) return QString();
    QString data = combo->currentData().toString();
    // Return empty QString for native asset - "native" is a UI sentinel, not a valid asset_id
    return (data == "native") ? QString() : data;
}

bool ForwardTermSheetPage::isNativeAsset(QComboBox* combo) const
{
    // Check raw combo data directly (not via getAssetIdFromCombo which filters out "native")
    return combo && combo->currentData().toString() == "native";
}

int ForwardTermSheetPage::getAssetDecimals(QComboBox* combo) const
{
    if (isNativeAsset(combo)) return 8;

    auto* wizardPtr = qobject_cast<ForwardContractBuilder*>(wizard());
    if (!wizardPtr || !wizardPtr->walletModel) return 8;

    QString assetId = getAssetIdFromCombo(combo);
    if (assetId.isEmpty()) return 8;  // Native assets return empty from getAssetIdFromCombo

    WalletModel::AssetInfo info = wizardPtr->walletModel->getAssetInfo(assetId);
    return info.has_decimals ? info.decimals : 8;
}

void ForwardTermSheetPage::applySpinBoxDecimals(QDoubleSpinBox* spin, int decimals) const
{
    if (!spin) return;
    if (decimals < 0) decimals = 0;
    const int clamped = std::min(decimals, 12);
    spin->setDecimals(clamped);
    const int step_decimals = std::min(clamped, 8);
    const double step = step_decimals > 0 ? std::pow(10.0, -step_decimals) : 1.0;
    spin->setSingleStep(step);
}

void ForwardTermSheetPage::onRoleChanged()
{
    // Update placeholder text based on role
    bool isLong = longPartyRadio->isChecked();
    myMarginDestEdit->setPlaceholderText(
        isLong ? tr("Address to refund your (long party) initial margin")
               : tr("Address to refund your (short party) initial margin"));
    mySettleDestEdit->setPlaceholderText(
        isLong ? tr("Address to receive long asset at settlement")
               : tr("Address to receive short asset at settlement"));
}

void ForwardTermSheetPage::onFlipLongShort()
{
    // 1. Save all current values first
    int longAssetIndex = longDeliverAssetCombo->currentIndex();
    QString longAssetId = longDeliverAssetIdEdit->text();
    int shortAssetIndex = shortDeliverAssetCombo->currentIndex();
    QString shortAssetId = shortDeliverAssetIdEdit->text();

    double oldLongSize = longSizeSpin->value();
    double oldPrice = priceSpin->value();
    double oldShortSize = (oldPrice > 0) ? (oldLongSize / oldPrice) : 0.0;

    int longImAssetIndex = longImAssetCombo->currentIndex();
    QString longImAssetId = longImAssetIdEdit->text();
    int shortImAssetIndex = shortImAssetCombo->currentIndex();
    QString shortImAssetId = shortImAssetIdEdit->text();

    bool longWasPercent = longImPercentRadio->isChecked();
    bool shortWasPercent = shortImPercentRadio->isChecked();

    double longImPercent = longImPercentSpin->value();
    double longImAbsolute = longImAbsoluteSpin->value();
    double shortImPercent = shortImPercentSpin->value();
    double shortImAbsolute = shortImAbsoluteSpin->value();

    bool longWasPayer = m_isOption && premiumPayerLongRadio ? premiumPayerLongRadio->isChecked() : false;

    // 2. Block signals on all widgets to prevent intermediate recalculations
    longDeliverAssetCombo->blockSignals(true);
    shortDeliverAssetCombo->blockSignals(true);
    longSizeSpin->blockSignals(true);
    priceSpin->blockSignals(true);
    longImAssetCombo->blockSignals(true);
    shortImAssetCombo->blockSignals(true);
    longImPercentRadio->blockSignals(true);
    longImAbsoluteRadio->blockSignals(true);
    shortImPercentRadio->blockSignals(true);
    shortImAbsoluteRadio->blockSignals(true);
    longImPercentSpin->blockSignals(true);
    longImAbsoluteSpin->blockSignals(true);
    shortImPercentSpin->blockSignals(true);
    shortImAbsoluteSpin->blockSignals(true);

    // 3. Swap delivery assets
    longDeliverAssetCombo->setCurrentIndex(shortAssetIndex);
    longDeliverAssetIdEdit->setText(shortAssetId);
    shortDeliverAssetCombo->setCurrentIndex(longAssetIndex);
    shortDeliverAssetIdEdit->setText(longAssetId);

    // 4. Swap delivery sizes and recalculate price
    longSizeSpin->setValue(oldShortSize);
    if (oldShortSize > 0) {
        priceSpin->setValue(oldShortSize / oldLongSize); // Inverted price
    }

    // 5. Swap IM assets
    longImAssetCombo->setCurrentIndex(shortImAssetIndex);
    longImAssetIdEdit->setText(shortImAssetId);
    shortImAssetCombo->setCurrentIndex(longImAssetIndex);
    shortImAssetIdEdit->setText(longImAssetId);

    // 6. Swap IM mode
    if (shortWasPercent) {
        longImPercentRadio->setChecked(true);
    } else {
        longImAbsoluteRadio->setChecked(true);
    }

    if (longWasPercent) {
        shortImPercentRadio->setChecked(true);
    } else {
        shortImAbsoluteRadio->setChecked(true);
    }

    // 7. Swap IM values (this is the critical part that was broken)
    longImPercentSpin->setValue(shortImPercent);
    longImAbsoluteSpin->setValue(shortImAbsolute);
    shortImPercentSpin->setValue(longImPercent);
    shortImAbsoluteSpin->setValue(longImAbsolute);

    // 8. Swap premium payer (if options)
    if (m_isOption && premiumPayerLongRadio && premiumPayerShortRadio) {
        premiumPayerLongRadio->blockSignals(true);
        premiumPayerShortRadio->blockSignals(true);
        premiumPayerLongRadio->setChecked(!longWasPayer);
        premiumPayerShortRadio->setChecked(longWasPayer);
        premiumPayerLongRadio->blockSignals(false);
        premiumPayerShortRadio->blockSignals(false);
    }

    // 9. Unblock signals
    longDeliverAssetCombo->blockSignals(false);
    shortDeliverAssetCombo->blockSignals(false);
    longSizeSpin->blockSignals(false);
    priceSpin->blockSignals(false);
    longImAssetCombo->blockSignals(false);
    shortImAssetCombo->blockSignals(false);
    longImPercentRadio->blockSignals(false);
    longImAbsoluteRadio->blockSignals(false);
    shortImPercentRadio->blockSignals(false);
    shortImAbsoluteRadio->blockSignals(false);
    longImPercentSpin->blockSignals(false);
    longImAbsoluteSpin->blockSignals(false);
    shortImPercentSpin->blockSignals(false);
    shortImAbsoluteSpin->blockSignals(false);

    // 10. Trigger updates once after all swaps are complete
    onLongDeliverAssetChanged(longDeliverAssetCombo->currentIndex());
    onShortDeliverAssetChanged(shortDeliverAssetCombo->currentIndex());
    onLongImAssetChanged(longImAssetCombo->currentIndex());
    onShortImAssetChanged(shortImAssetCombo->currentIndex());
    updateCalculations();
    updateDeadlineHeights();
}

void ForwardTermSheetPage::onLongDeliverAssetChanged(int index)
{
    Q_UNUSED(index);

    bool isNative = isNativeAsset(longDeliverAssetCombo);
    QString assetId = getAssetIdFromCombo(longDeliverAssetCombo);

    // Update hidden fields
    if (!isNative) {
        longDeliverAssetIdEdit->setText(assetId);
    } else {
        longDeliverAssetIdEdit->clear();
    }
    longDeliverIsNativeEdit->setText(isNative ? "true" : "false");

    // Extract ticker from combo box text
    QString longTicker = longDeliverAssetCombo->currentText().split(" ").first();
    QString shortTicker = shortDeliverAssetCombo->currentText().split(" ").first();

    longDeliverUnitLabel->setText(longTicker);
    longSizeUnitLabel->setText(longTicker);
    applySpinBoxDecimals(longSizeSpin, getAssetDecimals(longDeliverAssetCombo));

    // Update price unit label
    QString priceUnit = QString("%1 per %2").arg(shortTicker, longTicker);
    priceUnitLabel->setText(priceUnit);

    // Update IM default
    if (longImAssetCombo->currentIndex() == 0) {
        longImAssetCombo->setCurrentIndex(longDeliverAssetCombo->currentIndex());
    }

    updateCalculations();
}

void ForwardTermSheetPage::onShortDeliverAssetChanged(int index)
{
    Q_UNUSED(index);

    bool isNative = isNativeAsset(shortDeliverAssetCombo);
    QString assetId = getAssetIdFromCombo(shortDeliverAssetCombo);

    // Update hidden fields
    if (!isNative) {
        shortDeliverAssetIdEdit->setText(assetId);
    } else {
        shortDeliverAssetIdEdit->clear();
    }
    shortDeliverIsNativeEdit->setText(isNative ? "true" : "false");

    // Extract ticker from combo box text (format: "TICKER (assetid)" or "TSC (Native)")
    QString shortTicker = shortDeliverAssetCombo->currentText().split(" ").first();
    QString longTicker = longDeliverAssetCombo->currentText().split(" ").first();

    shortDeliverUnitLabel->setText(shortTicker);
    QString priceUnit = QString("%1 per %2").arg(shortTicker, longTicker);
    priceUnitLabel->setText(priceUnit);

    // Update IM default
    if (shortImAssetCombo->currentIndex() == 0) {
        shortImAssetCombo->setCurrentIndex(shortDeliverAssetCombo->currentIndex());
    }

    updateCalculations();
}

void ForwardTermSheetPage::onLongSizeChanged(double value)
{
    Q_UNUSED(value);
    updateCalculations();
}

void ForwardTermSheetPage::onPriceChanged(double value)
{
    Q_UNUSED(value);
    updateCalculations();
}

void ForwardTermSheetPage::onLongImAssetChanged(int index)
{
    Q_UNUSED(index);

    bool isNative = isNativeAsset(longImAssetCombo);
    QString assetId = getAssetIdFromCombo(longImAssetCombo);

    // Update hidden fields
    if (!isNative) {
        longImAssetIdEdit->setText(assetId);
    } else {
        longImAssetIdEdit->clear();
    }
    longImIsNativeEdit->setText(isNative ? "true" : "false");

    // Extract ticker from combo box text
    QString longImTicker = longImAssetCombo->currentText().split(" ").first();
    longImAssetLabel->setText(longImTicker);
    longImAbsoluteUnitLabel->setText(longImTicker);
    applySpinBoxDecimals(longImAbsoluteSpin, getAssetDecimals(longImAssetCombo));

    updateCalculations();
}

void ForwardTermSheetPage::onShortImAssetChanged(int index)
{
    Q_UNUSED(index);

    bool isNative = isNativeAsset(shortImAssetCombo);
    QString assetId = getAssetIdFromCombo(shortImAssetCombo);

    // Update hidden fields
    if (!isNative) {
        shortImAssetIdEdit->setText(assetId);
    } else {
        shortImAssetIdEdit->clear();
    }
    shortImIsNativeEdit->setText(isNative ? "true" : "false");

    // Extract ticker from combo box text
    QString shortImTicker = shortImAssetCombo->currentText().split(" ").first();
    shortImAssetLabel->setText(shortImTicker);
    shortImAbsoluteUnitLabel->setText(shortImTicker);
    applySpinBoxDecimals(shortImAbsoluteSpin, getAssetDecimals(shortImAssetCombo));

    updateCalculations();
}

void ForwardTermSheetPage::onLongImModeChanged()
{
    bool isPercent = longImPercentRadio->isChecked();
    longImPercentSpin->setEnabled(isPercent);
    longImAbsoluteSpin->setEnabled(!isPercent);
    updateCalculations();
}

void ForwardTermSheetPage::onShortImModeChanged()
{
    bool isPercent = shortImPercentRadio->isChecked();
    shortImPercentSpin->setEnabled(isPercent);
    shortImAbsoluteSpin->setEnabled(!isPercent);
    updateCalculations();
}

void ForwardTermSheetPage::onLongImPercentChanged(double value)
{
    Q_UNUSED(value);
    updateCalculations();
}

void ForwardTermSheetPage::onShortImPercentChanged(double value)
{
    Q_UNUSED(value);
    updateCalculations();
}

void ForwardTermSheetPage::onLongImAbsoluteChanged(double value)
{
    Q_UNUSED(value);
    updateCalculations();
}

void ForwardTermSheetPage::onShortImAbsoluteChanged(double value)
{
    Q_UNUSED(value);
    updateCalculations();
}

void ForwardTermSheetPage::onPremiumAssetChanged(int index)
{
    Q_UNUSED(index);

    bool isNative = isNativeAsset(premiumAssetCombo);
    QString assetId = getAssetIdFromCombo(premiumAssetCombo);

    // Update hidden fields
    if (!isNative) {
        premiumAssetIdEdit->setText(assetId);
    } else {
        premiumAssetIdEdit->clear();
    }
    premiumIsNativeEdit->setText(isNative ? "true" : "false");

    premiumAssetLabel->setText(isNative ? tr("TSC") : tr("units"));
    premiumAmountUnitLabel->setText(isNative ? tr("TSC") : tr("units"));
    applySpinBoxDecimals(premiumAmountSpin, getAssetDecimals(premiumAssetCombo));
}

void ForwardTermSheetPage::onPremiumAmountChanged(double value)
{
    Q_UNUSED(value);
}

void ForwardTermSheetPage::onPremiumPayerChanged()
{
    // Update UI based on who pays premium
}

void ForwardTermSheetPage::onEnablePremiumChanged(bool checked)
{
    premiumFieldsWidget->setVisible(checked);
}

void ForwardTermSheetPage::onMaturityPeriodChanged(int value)
{
    Q_UNUSED(value);
    updateDeadlineHeights();
}

void ForwardTermSheetPage::onDeliveryGapChanged(int value)
{
    Q_UNUSED(value);
    updateDeadlineHeights();
}

void ForwardTermSheetPage::onMaturityUnitChanged(int index)
{
    Q_UNUSED(index);
    updateDeadlineHeights();
}

void ForwardTermSheetPage::onGenerateMyMarginAddress()
{
    auto* wizardPtr = qobject_cast<ForwardContractBuilder*>(wizard());
    if (!wizardPtr || !wizardPtr->walletModel) return;

    QString address = wizardPtr->walletModel->getNewAddress("bech32m");
    if (!address.isEmpty()) {
        myMarginDestEdit->setText(address);
    }
}

void ForwardTermSheetPage::onGenerateMySettleAddress()
{
    auto* wizardPtr = qobject_cast<ForwardContractBuilder*>(wizard());
    if (!wizardPtr || !wizardPtr->walletModel) return;

    QString address = wizardPtr->walletModel->getNewAddress("bech32m");
    if (!address.isEmpty()) {
        mySettleDestEdit->setText(address);
    }
}

void ForwardTermSheetPage::onGeneratePremiumAddress()
{
    auto* wizardPtr = qobject_cast<ForwardContractBuilder*>(wizard());
    if (!wizardPtr || !wizardPtr->walletModel) return;

    QString address = wizardPtr->walletModel->getNewAddress("bech32m");
    if (!address.isEmpty()) {
        premiumDestEdit->setText(address);
    }
}

void ForwardTermSheetPage::updateCalculations()
{
    double longSize = longSizeSpin->value();
    double price = priceSpin->value();
    double shortSize = longSize * price;

    QString shortTicker = shortDeliverAssetCombo->currentText().split(" ").first();
    shortSizeValueLabel->setText(QString("%1 %2").arg(shortSize, 0, 'f', 8).arg(shortTicker));

    // Calculate long IM
    double longIm;
    QString longImTicker = longImAssetCombo->currentText().split(" ").first();
    if (longImPercentRadio->isChecked()) {
        double pct = longImPercentSpin->value();
        longIm = longSize * (pct / 100.0);
        longImCalculatedLabel->setText(tr("IM Amount: %1 %2").arg(longIm, 0, 'f', 8).arg(longImTicker));
    } else {
        longIm = longImAbsoluteSpin->value();
        longImCalculatedLabel->setText(tr("IM Amount: %1 %2")
            .arg(longIm, 0, 'f', 8)
            .arg(longImTicker));
    }

    // Calculate short IM
    double shortIm;
    QString shortImTicker = shortImAssetCombo->currentText().split(" ").first();
    if (shortImPercentRadio->isChecked()) {
        double pct = shortImPercentSpin->value();
        shortIm = shortSize * (pct / 100.0);
        shortImCalculatedLabel->setText(tr("IM Amount: %1 %2").arg(shortIm, 0, 'f', 8).arg(shortImTicker));
    } else {
        shortIm = shortImAbsoluteSpin->value();
        shortImCalculatedLabel->setText(tr("IM Amount: %1 %2")
            .arg(shortIm, 0, 'f', 8)
            .arg(shortImTicker));
    }
}

void ForwardTermSheetPage::updateDeadlineHeights()
{
    auto* wizardPtr = qobject_cast<ForwardContractBuilder*>(wizard());
    if (!wizardPtr || !wizardPtr->walletModel) return;

    int currentHeight = wizardPtr->walletModel->getNumBlocks();
    currentHeightLabel->setText(tr("Current block height: %1").arg(currentHeight));

    // If using absolute heights, labels are updated by spinbox change handlers
    if (useAbsoluteHeightCheck->isChecked()) {
        deadlineShortHeightLabel->setText(tr("Short deadline: block %1").arg(absoluteShortHeightSpin->value()));
        deadlineLongHeightLabel->setText(tr("Long deadline: block %1").arg(absoluteLongHeightSpin->value()));
        return;
    }

    // Calculate from maturity period
    QString unit = maturityUnitCombo->currentData().toString();
    int maturityPeriod = maturityPeriodSpin->value();
    int deliveryGap = deliveryGapSpin->value();

    int maturityBlocks = 0;

    if (unit == "days") {
        maturityBlocks = maturityPeriod * 144;
    } else if (unit == "weeks") {
        maturityBlocks = maturityPeriod * 7 * 144;
    } else if (unit == "months") {
        maturityBlocks = maturityPeriod * 30 * 144;
    } else if (unit == "years") {
        maturityBlocks = maturityPeriod * 365 * 144;
    }

    deadlineShortHeightLabel->setText(tr("Short delivery deadline: block %1 (maturity at %2 blocks)")
        .arg(currentHeight + maturityBlocks).arg(maturityBlocks));
    deadlineLongHeightLabel->setText(tr("Long delivery deadline: block %1 (maturity + %2 block gap)")
        .arg(currentHeight + maturityBlocks + deliveryGap).arg(deliveryGap));
}

void ForwardTermSheetPage::updateForwardPricing()
{
    // Get wallet model
    ForwardContractBuilder* fwdWizard = qobject_cast<ForwardContractBuilder*>(wizard());
    if (!fwdWizard || !fwdWizard->walletModel) {
        // Reset all labels to "--"
        pvReceiveLabel->setText(tr("--"));
        pvPayLabel->setText(tr("--"));
        netSpreadLabel->setText(tr("--"));
        premiumPvLabel->setText(tr("--"));
        aliceShortCallLabel->setText(tr("--"));
        aliceLongPutLabel->setText(tr("--"));
        aliceMtmLabel->setText(tr("--"));
        bobMtmLabel->setText(tr("--"));
        imCoverageAliceLabel->setText(tr("--"));
        imCoverageBobLabel->setText(tr("--"));
        pvReceivePerNotionalLabel->setText(tr("--"));
        pvPayPerNotionalLabel->setText(tr("--"));
        netSpreadPerNotionalLabel->setText(tr("--"));
        premiumPvPerNotionalLabel->setText(tr("--"));
        aliceShortCallPerNotionalLabel->setText(tr("--"));
        aliceLongPutPerNotionalLabel->setText(tr("--"));
        aliceMtmPerNotionalLabel->setText(tr("--"));
        bobMtmPerNotionalLabel->setText(tr("--"));
        imCoverageAlicePerNotionalLabel->setText(tr("--"));
        imCoverageBobPerNotionalLabel->setText(tr("--"));
        return;
    }

    WalletModel* model = fwdWizard->walletModel;

    // Build inline terms from current wizard fields
    QVariantMap inlineTerms;

    // Get long delivery info
    QString longDeliverAssetId = getAssetIdFromCombo(longDeliverAssetCombo);
    bool longDeliverIsNative = isNativeAsset(longDeliverAssetCombo);
    inlineTerms["long_party_deliver_asset"] = longDeliverAssetId.isEmpty() ? "" : longDeliverAssetId;
    inlineTerms["long_party_deliver_is_native"] = longDeliverIsNative;
    inlineTerms["long_party_deliver_units"] = static_cast<qint64>(longSizeSpin->value() * 1e8);

    // Get short delivery info
    QString shortDeliverAssetId = getAssetIdFromCombo(shortDeliverAssetCombo);
    bool shortDeliverIsNative = isNativeAsset(shortDeliverAssetCombo);
    double shortSize = longSizeSpin->value() * priceSpin->value();
    inlineTerms["short_party_deliver_asset"] = shortDeliverAssetId.isEmpty() ? "" : shortDeliverAssetId;
    inlineTerms["short_party_deliver_is_native"] = shortDeliverIsNative;
    inlineTerms["short_party_deliver_units"] = static_cast<qint64>(shortSize * 1e8);

    // Get long IM info
    QString longImAssetId = getAssetIdFromCombo(longImAssetCombo);
    bool longImIsNative = isNativeAsset(longImAssetCombo);
    double longIm = longImPercentRadio->isChecked() ?
        (longSizeSpin->value() * longImPercentSpin->value() / 100.0) :
        longImAbsoluteSpin->value();
    inlineTerms["long_party_margin_asset"] = longImAssetId.isEmpty() ? "" : longImAssetId;
    inlineTerms["long_party_margin_is_native"] = longImIsNative;
    inlineTerms["long_party_margin_units"] = static_cast<qint64>(longIm * 1e8);

    // Get short IM info
    QString shortImAssetId = getAssetIdFromCombo(shortImAssetCombo);
    bool shortImIsNative = isNativeAsset(shortImAssetCombo);
    double shortIm = shortImPercentRadio->isChecked() ?
        (shortSize * shortImPercentSpin->value() / 100.0) :
        shortImAbsoluteSpin->value();
    inlineTerms["short_party_margin_asset"] = shortImAssetId.isEmpty() ? "" : shortImAssetId;
    inlineTerms["short_party_margin_is_native"] = shortImIsNative;
    inlineTerms["short_party_margin_units"] = static_cast<qint64>(shortIm * 1e8);

    // Get premium info (if enabled)
    if (enablePremiumCheckBox && enablePremiumCheckBox->isChecked()) {
        QString premiumAssetId = getAssetIdFromCombo(premiumAssetCombo);
        bool premiumIsNative = isNativeAsset(premiumAssetCombo);
        inlineTerms["premium_asset"] = premiumAssetId.isEmpty() ? "" : premiumAssetId;
        inlineTerms["premium_is_native"] = premiumIsNative;
        inlineTerms["premium_units"] = static_cast<qint64>(premiumAmountSpin->value() * 1e8);
    } else {
        inlineTerms["premium_asset"] = "";
        inlineTerms["premium_is_native"] = true;
        inlineTerms["premium_units"] = 0;
    }

    // Calculate deadline heights
    int deadlineShort, deadlineLong;
    if (useAbsoluteHeightCheck->isChecked()) {
        deadlineShort = absoluteShortHeightSpin->value();
        deadlineLong = absoluteLongHeightSpin->value();
    } else {
        int currentHeight = model->getNumBlocks();
        QString unit = maturityUnitCombo->currentData().toString();
        int maturityPeriod = maturityPeriodSpin->value();
        int deliveryGap = deliveryGapSpin->value();

        int maturityBlocks = 0;
        if (unit == "days") {
            maturityBlocks = maturityPeriod * 144;
        } else if (unit == "weeks") {
            maturityBlocks = maturityPeriod * 7 * 144;
        } else if (unit == "months") {
            maturityBlocks = maturityPeriod * 30 * 144;
        } else if (unit == "years") {
            maturityBlocks = maturityPeriod * 365 * 144;
        }

        deadlineShort = currentHeight + maturityBlocks;
        deadlineLong = deadlineShort + deliveryGap;
    }

    inlineTerms["deadline_short"] = deadlineShort;
    inlineTerms["deadline_long"] = deadlineLong;
    inlineTerms["safety_k"] = safetyBufferSpin->value();

    // Debug: log inline terms
    LogPrintf( "Forward pricing: calling with inline_terms: long_deliver=%s/%d, short_deliver=%s/%d, long_im=%s/%d, short_im=%s/%d, deadline_short=%d\n",
        inlineTerms.value("long_party_deliver_asset").toString().toStdString(),
        inlineTerms.value("long_party_deliver_units").toLongLong(),
        inlineTerms.value("short_party_deliver_asset").toString().toStdString(),
        inlineTerms.value("short_party_deliver_units").toLongLong(),
        inlineTerms.value("long_party_margin_asset").toString().toStdString(),
        inlineTerms.value("long_party_margin_units").toLongLong(),
        inlineTerms.value("short_party_margin_asset").toString().toStdString(),
        inlineTerms.value("short_party_margin_units").toLongLong(),
        inlineTerms.value("deadline_short").toInt());

    // Call pricing RPC
    try {
        auto result = model->pricingForwardQuote(
            "inline",
            "",
            inlineTerms,
            "",     // report_asset (empty for TSC)
            true,   // report_is_native (default to TSC)
            true   // compute_greeks
        );

        if (result.success) {
            LogPrintf( "Forward pricing: SUCCESS! alice_mtm=%f bob_mtm=%f\n", result.alice_mtm, result.bob_mtm);
            // Get report currency decimals (TSC = 8 decimals by default)
            int reportDecimals = 8;
            if (model) {
                WalletModel::AssetInfo tscInfo = model->getAssetInfo(""); // Empty = native TSC
                if (tscInfo.has_decimals) {
                    reportDecimals = tscInfo.decimals;
                }
            }
            const double toDisplayUnits = 1.0 / std::pow(10.0, reportDecimals);

            // Get notional in display units for per-notional calculations (use long delivery size as notional)
            double notionalDisplay = longSizeSpin->value();
            double perNotionalDivisor = (notionalDisplay > 0.0) ? notionalDisplay : 1.0;

            // Update PV Receive
            double pvReceive = result.pv_receive * toDisplayUnits;
            pvReceiveLabel->setText(QString("%1 TSC").arg(pvReceive, 0, 'f', 8));
            pvReceivePerNotionalLabel->setText(QString("%1").arg(pvReceive / perNotionalDivisor, 0, 'f', 6));

            // Update PV Pay
            double pvPay = result.pv_pay * toDisplayUnits;
            pvPayLabel->setText(QString("%1 TSC").arg(pvPay, 0, 'f', 8));
            pvPayPerNotionalLabel->setText(QString("%1").arg(pvPay / perNotionalDivisor, 0, 'f', 6));

            // Update Net Spread Value
            double netSpread = result.net_spread_value * toDisplayUnits;
            netSpreadLabel->setText(QString("%1 TSC").arg(netSpread, 0, 'f', 8));
            netSpreadPerNotionalLabel->setText(QString("%1").arg(netSpread / perNotionalDivisor, 0, 'f', 6));

            // Update Premium PV
            double premiumPv = result.premium_pv * toDisplayUnits;
            premiumPvLabel->setText(QString("%1 TSC").arg(premiumPv, 0, 'f', 8));
            premiumPvPerNotionalLabel->setText(QString("%1").arg(premiumPv / perNotionalDivisor, 0, 'f', 6));

            // Update Alice Short Call Value
            double aliceShortCall = result.alice_short_call_value * toDisplayUnits;
            aliceShortCallLabel->setText(QString("%1 TSC").arg(aliceShortCall, 0, 'f', 8));
            aliceShortCallPerNotionalLabel->setText(QString("%1").arg(aliceShortCall / perNotionalDivisor, 0, 'f', 6));

            // Update Alice Long Put Value
            double aliceLongPut = result.alice_long_put_value * toDisplayUnits;
            aliceLongPutLabel->setText(QString("%1 TSC").arg(aliceLongPut, 0, 'f', 8));
            aliceLongPutPerNotionalLabel->setText(QString("%1").arg(aliceLongPut / perNotionalDivisor, 0, 'f', 6));

            // Update Alice MTM with color coding
            double aliceMtm = result.alice_mtm * toDisplayUnits;
            if (aliceMtm > 0.0) {
                aliceMtmLabel->setText(QString("+%1 TSC").arg(aliceMtm, 0, 'f', 8));
                aliceMtmLabel->setStyleSheet("QLabel { font-weight: bold; color: #4caf50; }"); // Green
                aliceMtmPerNotionalLabel->setText(QString("+%1").arg(aliceMtm / perNotionalDivisor, 0, 'f', 6));
                aliceMtmPerNotionalLabel->setStyleSheet("QLabel { font-weight: bold; color: #4caf50; }");
            } else if (aliceMtm < 0.0) {
                aliceMtmLabel->setText(QString("%1 TSC").arg(aliceMtm, 0, 'f', 8));
                aliceMtmLabel->setStyleSheet("QLabel { font-weight: bold; color: #f44336; }"); // Red
                aliceMtmPerNotionalLabel->setText(QString("%1").arg(aliceMtm / perNotionalDivisor, 0, 'f', 6));
                aliceMtmPerNotionalLabel->setStyleSheet("QLabel { font-weight: bold; color: #f44336; }");
            } else {
                aliceMtmLabel->setText(QString("0.00000000 TSC"));
                aliceMtmLabel->setStyleSheet("QLabel { font-weight: bold; color: #9e9e9e; }"); // Gray
                aliceMtmPerNotionalLabel->setText(QString("0.000000"));
                aliceMtmPerNotionalLabel->setStyleSheet("QLabel { font-weight: bold; color: #9e9e9e; }");
            }

            // Update Bob MTM with color coding
            double bobMtm = result.bob_mtm * toDisplayUnits;
            if (bobMtm > 0.0) {
                bobMtmLabel->setText(QString("+%1 TSC").arg(bobMtm, 0, 'f', 8));
                bobMtmLabel->setStyleSheet("QLabel { font-weight: bold; color: #4caf50; }"); // Green
                bobMtmPerNotionalLabel->setText(QString("+%1").arg(bobMtm / perNotionalDivisor, 0, 'f', 6));
                bobMtmPerNotionalLabel->setStyleSheet("QLabel { font-weight: bold; color: #4caf50; }");
            } else if (bobMtm < 0.0) {
                bobMtmLabel->setText(QString("%1 TSC").arg(bobMtm, 0, 'f', 8));
                bobMtmLabel->setStyleSheet("QLabel { font-weight: bold; color: #f44336; }"); // Red
                bobMtmPerNotionalLabel->setText(QString("%1").arg(bobMtm / perNotionalDivisor, 0, 'f', 6));
                bobMtmPerNotionalLabel->setStyleSheet("QLabel { font-weight: bold; color: #f44336; }");
            } else {
                bobMtmLabel->setText(QString("0.00000000 TSC"));
                bobMtmLabel->setStyleSheet("QLabel { font-weight: bold; color: #9e9e9e; }"); // Gray
                bobMtmPerNotionalLabel->setText(QString("0.000000"));
                bobMtmPerNotionalLabel->setStyleSheet("QLabel { font-weight: bold; color: #9e9e9e; }");
            }

            // Update IM Coverage Alice
            double imCoverageAlice = result.im_coverage_alice;
            imCoverageAliceLabel->setText(QString("%1%").arg(imCoverageAlice * 100.0, 0, 'f', 2));
            imCoverageAlicePerNotionalLabel->setText(QString("%1").arg(imCoverageAlice, 0, 'f', 4));

            // Update IM Coverage Bob
            double imCoverageBob = result.im_coverage_bob;
            imCoverageBobLabel->setText(QString("%1%").arg(imCoverageBob * 100.0, 0, 'f', 2));
            imCoverageBobPerNotionalLabel->setText(QString("%1").arg(imCoverageBob, 0, 'f', 4));

        } else {
            // Pricing failed - show error and reset to "--"
            LogPrintf( "Forward pricing: FAILED - %s\n", result.error.toStdString());
            pvReceiveLabel->setText(tr("--"));
            pvPayLabel->setText(tr("--"));
            netSpreadLabel->setText(tr("--"));
            premiumPvLabel->setText(tr("--"));
            aliceShortCallLabel->setText(tr("--"));
            aliceLongPutLabel->setText(tr("--"));
            aliceMtmLabel->setText(tr("--"));
            bobMtmLabel->setText(tr("--"));
            imCoverageAliceLabel->setText(tr("--"));
            imCoverageBobLabel->setText(tr("--"));
            pvReceivePerNotionalLabel->setText(tr("--"));
            pvPayPerNotionalLabel->setText(tr("--"));
            netSpreadPerNotionalLabel->setText(tr("--"));
            premiumPvPerNotionalLabel->setText(tr("--"));
            aliceShortCallPerNotionalLabel->setText(tr("--"));
            aliceLongPutPerNotionalLabel->setText(tr("--"));
            aliceMtmPerNotionalLabel->setText(tr("--"));
            bobMtmPerNotionalLabel->setText(tr("--"));
            imCoverageAlicePerNotionalLabel->setText(tr("--"));
            imCoverageBobPerNotionalLabel->setText(tr("--"));
        }
    } catch (const std::exception& e) {
        // Exception - show error and reset to "--"
        LogPrintf( "Forward pricing: EXCEPTION - %s\n", e.what());
        pvReceiveLabel->setText(tr("--"));
        pvPayLabel->setText(tr("--"));
        netSpreadLabel->setText(tr("--"));
        premiumPvLabel->setText(tr("--"));
        aliceShortCallLabel->setText(tr("--"));
        aliceLongPutLabel->setText(tr("--"));
        aliceMtmLabel->setText(tr("--"));
        bobMtmLabel->setText(tr("--"));
        imCoverageAliceLabel->setText(tr("--"));
        imCoverageBobLabel->setText(tr("--"));
        pvReceivePerNotionalLabel->setText(tr("--"));
        pvPayPerNotionalLabel->setText(tr("--"));
        netSpreadPerNotionalLabel->setText(tr("--"));
        premiumPvPerNotionalLabel->setText(tr("--"));
        aliceShortCallPerNotionalLabel->setText(tr("--"));
        aliceLongPutPerNotionalLabel->setText(tr("--"));
        aliceMtmPerNotionalLabel->setText(tr("--"));
        bobMtmPerNotionalLabel->setText(tr("--"));
        imCoverageAlicePerNotionalLabel->setText(tr("--"));
        imCoverageBobPerNotionalLabel->setText(tr("--"));
    }
}

void OptionTermSheetPage::onShowGreeks()
{
    auto* wizardPtr = qobject_cast<ForwardContractBuilder*>(wizard());
    WalletModel* walletModel = wizardPtr ? wizardPtr->getWalletModel() : nullptr;

    if (!walletModel) {
        QMessageBox::warning(this, tr("Greeks"), tr("Wallet model not available"));
        return;
    }

    try {
        // Use EXACT same inline_terms building as updateOptionPricing()
        QString baseAssetId = getAssetIdFromCombo(baseAssetCombo);
        bool baseIsNative = isNativeAsset(baseAssetCombo);
        QString quoteAssetId = getAssetIdFromCombo(quoteAssetCombo);
        bool quoteIsNative = isNativeAsset(quoteAssetCombo);
        QString optionType = optionTypeCombo->currentData().toString();
        double strike = strikeSpin->value();
        double notional = notionalSpin->value();
        double maxPayout = maxPayoutSpin->value();
        double premium = premiumSpin->value();
        int expiryPeriod = expirySpin->value();
        QString expiryUnit = expiryUnitCombo->currentData().toString();
        int deliveryGap = deliveryGapSpin->value();

        // Calculate long and short delivery amounts based on option structure
        double longDeliverAmount;
        double shortDeliverAmount;
        QString longDeliverAsset;
        QString shortDeliverAsset;
        bool longDeliverIsNative;
        bool shortDeliverIsNative;

        if (optionType == "call") {
            // Call: long delivers quote, short delivers base
            longDeliverAmount = notional * strike * (maxPayout / 100.0);
            shortDeliverAmount = notional * (maxPayout / 100.0);
            longDeliverAsset = quoteAssetId;
            shortDeliverAsset = baseAssetId;
            longDeliverIsNative = quoteIsNative;
            shortDeliverIsNative = baseIsNative;
        } else {
            // Put: long delivers base, short delivers quote
            longDeliverAmount = notional * (maxPayout / 100.0);
            shortDeliverAmount = notional * strike * (maxPayout / 100.0);
            longDeliverAsset = baseAssetId;
            shortDeliverAsset = quoteAssetId;
            longDeliverIsNative = baseIsNative;
            shortDeliverIsNative = quoteIsNative;
        }

        // Calculate initial margins (10% of notional for both parties)
        double longImAmount = notional * 0.1;
        double shortImAmount = notional * 0.1;

        // Calculate premium amount
        double premiumAmount = notional * (premium / 100.0);

        // Calculate deadline heights
        int currentHeight = walletModel->getNumBlocks();
        int maturityBlocks = 0;
        if (expiryUnit == "days") {
            maturityBlocks = expiryPeriod * 144;
        } else if (expiryUnit == "weeks") {
            maturityBlocks = expiryPeriod * 7 * 144;
        } else if (expiryUnit == "months") {
            maturityBlocks = expiryPeriod * 30 * 144;
        } else {
            maturityBlocks = expiryPeriod * 365 * 144;
        }
        int deadlineShort = currentHeight + maturityBlocks;
        int deadlineLong = deadlineShort + deliveryGap;

        // Build inline_terms for the RPC call - MUST use correct field names and SATOSHI units (×1e8)
        QVariantMap inlineTerms;
        inlineTerms["long_party_deliver_units"] = static_cast<qint64>(longDeliverAmount * 1e8);
        inlineTerms["long_party_deliver_asset"] = longDeliverAsset.isEmpty() ? "" : longDeliverAsset;
        inlineTerms["long_party_deliver_is_native"] = longDeliverIsNative;
        inlineTerms["short_party_deliver_units"] = static_cast<qint64>(shortDeliverAmount * 1e8);
        inlineTerms["short_party_deliver_asset"] = shortDeliverAsset.isEmpty() ? "" : shortDeliverAsset;
        inlineTerms["short_party_deliver_is_native"] = shortDeliverIsNative;
        inlineTerms["long_party_margin_units"] = static_cast<qint64>(longImAmount * 1e8);
        inlineTerms["long_party_margin_asset"] = baseAssetId.isEmpty() ? "" : baseAssetId;
        inlineTerms["long_party_margin_is_native"] = baseIsNative;
        inlineTerms["short_party_margin_units"] = static_cast<qint64>(shortImAmount * 1e8);
        inlineTerms["short_party_margin_asset"] = baseAssetId.isEmpty() ? "" : baseAssetId;
        inlineTerms["short_party_margin_is_native"] = baseIsNative;
        inlineTerms["premium_units"] = static_cast<qint64>(premiumAmount * 1e8);
        inlineTerms["premium_asset"] = baseAssetId.isEmpty() ? "" : baseAssetId;
        inlineTerms["premium_is_native"] = baseIsNative;
        inlineTerms["deadline_short"] = deadlineShort;
        inlineTerms["deadline_long"] = deadlineLong;
        inlineTerms["safety_k"] = 3;  // Default safety buffer

        // Create GreeksData and open dialog
        GreeksVisualizationDialog::GreeksData greeksData;
        greeksData.type = GreeksVisualizationDialog::Forward;  // Options use Forward pricer!
        greeksData.contractId = "";
        greeksData.inlineTerms = inlineTerms;
        greeksData.reportAsset = "";
        greeksData.reportIsNative = true;

        GreeksVisualizationDialog dialog(walletModel, greeksData, this);
        dialog.exec();

    } catch (const std::exception& e) {
        QMessageBox::critical(this, tr("Greeks Error"),
            tr("Failed to open Greeks visualization:\n\n%1").arg(QString::fromStdString(e.what())));
    }
}

void ForwardTermSheetPage::onShowGreeks()
{
    ForwardContractBuilder* fwdWizard = qobject_cast<ForwardContractBuilder*>(wizard());
    WalletModel* walletModel = fwdWizard ? fwdWizard->getWalletModel() : nullptr;

    if (!walletModel) {
        QMessageBox::warning(this, tr("Greeks"), tr("Wallet model not available"));
        return;
    }

    try {
        // Build inline terms from current form values
        QVariantMap inlineTerms;

        // Get long delivery info
        QString longDeliverAssetId = getAssetIdFromCombo(longDeliverAssetCombo);
        bool longDeliverIsNative = isNativeAsset(longDeliverAssetCombo);
        inlineTerms["long_party_deliver_asset"] = longDeliverAssetId.isEmpty() ? "" : longDeliverAssetId;
        inlineTerms["long_party_deliver_is_native"] = longDeliverIsNative;
        inlineTerms["long_party_deliver_units"] = static_cast<qint64>(longSizeSpin->value() * 1e8);

        // Get short delivery info
        QString shortDeliverAssetId = getAssetIdFromCombo(shortDeliverAssetCombo);
        bool shortDeliverIsNative = isNativeAsset(shortDeliverAssetCombo);
        double shortSize = longSizeSpin->value() * priceSpin->value();
        inlineTerms["short_party_deliver_asset"] = shortDeliverAssetId.isEmpty() ? "" : shortDeliverAssetId;
        inlineTerms["short_party_deliver_is_native"] = shortDeliverIsNative;
        inlineTerms["short_party_deliver_units"] = static_cast<qint64>(shortSize * 1e8);

        // Get long IM info
        QString longImAssetId = getAssetIdFromCombo(longImAssetCombo);
        bool longImIsNative = isNativeAsset(longImAssetCombo);
        double longIm = longImPercentRadio->isChecked() ?
            (longSizeSpin->value() * longImPercentSpin->value() / 100.0) :
            longImAbsoluteSpin->value();
        inlineTerms["long_party_margin_asset"] = longImAssetId.isEmpty() ? "" : longImAssetId;
        inlineTerms["long_party_margin_is_native"] = longImIsNative;
        inlineTerms["long_party_margin_units"] = static_cast<qint64>(longIm * 1e8);

        // Get short IM info
        QString shortImAssetId = getAssetIdFromCombo(shortImAssetCombo);
        bool shortImIsNative = isNativeAsset(shortImAssetCombo);
        double shortIm = shortImPercentRadio->isChecked() ?
            (shortSize * shortImPercentSpin->value() / 100.0) :
            shortImAbsoluteSpin->value();
        inlineTerms["short_party_margin_asset"] = shortImAssetId.isEmpty() ? "" : shortImAssetId;
        inlineTerms["short_party_margin_is_native"] = shortImIsNative;
        inlineTerms["short_party_margin_units"] = static_cast<qint64>(shortIm * 1e8);

        // Get premium info (if enabled)
        if (enablePremiumCheckBox && enablePremiumCheckBox->isChecked()) {
            QString premiumAssetId = getAssetIdFromCombo(premiumAssetCombo);
            bool premiumIsNative = isNativeAsset(premiumAssetCombo);
            inlineTerms["premium_asset"] = premiumAssetId.isEmpty() ? "" : premiumAssetId;
            inlineTerms["premium_is_native"] = premiumIsNative;
            inlineTerms["premium_units"] = static_cast<qint64>(premiumAmountSpin->value() * 1e8);
        } else {
            inlineTerms["premium_asset"] = "";
            inlineTerms["premium_is_native"] = true;
            inlineTerms["premium_units"] = 0;
        }

        // Calculate deadline heights
        int deadlineShort, deadlineLong;
        if (useAbsoluteHeightCheck->isChecked()) {
            deadlineShort = absoluteShortHeightSpin->value();
            deadlineLong = absoluteLongHeightSpin->value();
        } else {
            int currentHeight = walletModel->getNumBlocks();
            QString unit = maturityUnitCombo->currentData().toString();
            int maturityPeriod = maturityPeriodSpin->value();
            int deliveryGap = deliveryGapSpin->value();

            int maturityBlocks = 0;
            if (unit == "days") {
                maturityBlocks = maturityPeriod * 144;
            } else if (unit == "weeks") {
                maturityBlocks = maturityPeriod * 7 * 144;
            } else if (unit == "months") {
                maturityBlocks = maturityPeriod * 30 * 144;
            } else if (unit == "years") {
                maturityBlocks = maturityPeriod * 365 * 144;
            }

            deadlineShort = currentHeight + maturityBlocks;
            deadlineLong = deadlineShort + deliveryGap;
        }

        inlineTerms["deadline_short"] = deadlineShort;
        inlineTerms["deadline_long"] = deadlineLong;
        inlineTerms["safety_k"] = safetyBufferSpin->value();

        // Create GreeksData and open dialog
        GreeksVisualizationDialog::GreeksData greeksData;
        greeksData.type = GreeksVisualizationDialog::Forward;
        greeksData.contractId = "";
        greeksData.inlineTerms = inlineTerms;
        greeksData.reportAsset = "";
        greeksData.reportIsNative = true;

        GreeksVisualizationDialog dialog(walletModel, greeksData, this);
        dialog.exec();

    } catch (const std::exception& e) {
        QMessageBox::critical(this, tr("Greeks Error"),
            tr("Failed to open Greeks visualization:\n\n%1").arg(QString::fromStdString(e.what())));
    }
}

// ============================================================================
// ForwardReviewPage
// ============================================================================

ForwardReviewPage::ForwardReviewPage(ContractWizard* wizard, QWidget* parent)
    : ContractReviewPage(wizard, parent)
{
    setTitle(tr("Review Forward/Option Contract"));
    setSubTitle(tr("Review the contract terms below and click 'Finish' to create the offer."));
}

QString ForwardReviewPage::formatOfferSummary() const
{
    auto* fwdWizard = qobject_cast<const ForwardContractBuilder*>(contractWizard);
    if (!fwdWizard) return tr("Error: Invalid wizard type");

    bool isOption = fwdWizard->isOptionContract();
    QString summary;

    summary += QString("<h3>%1</h3>").arg(isOption ? tr("Option Contract") : tr("Forward Contract"));
    summary += "<table cellpadding='4'>";

    // Role
    bool isLong = contractWizard->field("isLongParty").toBool();
    summary += QString("<tr><td><b>Your Role:</b></td><td>%1</td></tr>")
        .arg(isLong ? tr("Long Party") : tr("Short Party"));

    // Delivery legs
    summary += QString("<tr><td colspan='2'><b>Delivery Obligations</b></td></tr>");

    double longSize = contractWizard->field("longSize").toDouble();
    QString longAsset = contractWizard->field("longDeliverIsNative").toBool() ?
        tr("TSC") : contractWizard->field("longDeliverAssetId").toString().left(8);
    summary += QString("<tr><td>Long Party Delivers (Short receives):</td><td>%1 %2</td></tr>")
        .arg(longSize, 0, 'f', 8).arg(longAsset);

    double price = contractWizard->field("price").toDouble();
    double shortSize = longSize * price;
    QString shortAsset = contractWizard->field("shortDeliverIsNative").toBool() ?
        tr("TSC") : contractWizard->field("shortDeliverAssetId").toString().left(8);
    summary += QString("<tr><td>Short Party Delivers (Long receives):</td><td>%1 %2</td></tr>")
        .arg(shortSize, 0, 'f', 8).arg(shortAsset);
    summary += QString("<tr><td colspan='2'><i>%1</i></td></tr>")
        .arg(tr("Each party receives the counterparty's delivery leg at settlement."));

    summary += QString("<tr><td>Price:</td><td>%1 %2 per %3</td></tr>")
        .arg(price, 0, 'f', 8).arg(shortAsset).arg(longAsset);

    // Initial margins
    summary += QString("<tr><td colspan='2'><b>Initial Margins</b></td></tr>");

    bool longImPercent = contractWizard->field("longImPercent").toBool();
    double longIm = longImPercent ?
        (longSize * contractWizard->field("longImPercentValue").toDouble() / 100.0) :
        contractWizard->field("longImAbsoluteValue").toDouble();
    QString longImAsset = contractWizard->field("longImIsNative").toBool() ?
        tr("TSC") : contractWizard->field("longImAssetId").toString().left(8);
    summary += QString("<tr><td>Long IM:</td><td>%1 %2 %3</td></tr>")
        .arg(longIm, 0, 'f', 8).arg(longImAsset)
        .arg(longImPercent ? QString("(%1%)").arg(contractWizard->field("longImPercentValue").toDouble(), 0, 'f', 2) : QString());

    bool shortImPercent = contractWizard->field("shortImPercent").toBool();
    double shortIm = shortImPercent ?
        (shortSize * contractWizard->field("shortImPercentValue").toDouble() / 100.0) :
        contractWizard->field("shortImAbsoluteValue").toDouble();
    QString shortImAsset = contractWizard->field("shortImIsNative").toBool() ?
        tr("TSC") : contractWizard->field("shortImAssetId").toString().left(8);
    summary += QString("<tr><td>Short IM:</td><td>%1 %2 %3</td></tr>")
        .arg(shortIm, 0, 'f', 8).arg(shortImAsset)
        .arg(shortImPercent ? QString("(%1%)").arg(contractWizard->field("shortImPercentValue").toDouble(), 0, 'f', 2) : QString());

    // Premium (for options)
    if (isOption) {
        summary += QString("<tr><td colspan='2'><b>Premium</b></td></tr>");
        double premiumAmount = contractWizard->field("premiumAmount").toDouble();
        QString premiumAsset = contractWizard->field("premiumIsNative").toBool() ?
            tr("TSC") : contractWizard->field("premiumAssetId").toString().left(8);
        bool premiumPayerIsLong = contractWizard->field("premiumPayerIsLong").toBool();
        summary += QString("<tr><td>Amount:</td><td>%1 %2</td></tr>")
            .arg(premiumAmount, 0, 'f', 8).arg(premiumAsset);
        summary += QString("<tr><td>Payer:</td><td>%1</td></tr>")
            .arg(premiumPayerIsLong ? tr("Long Party") : tr("Short Party"));

        QString premiumDest = contractWizard->field("premiumDest").toString();
        if (!premiumDest.isEmpty()) {
            summary += QString("<tr><td>Destination:</td><td>%1</td></tr>").arg(premiumDest);
        } else {
            summary += QString("<tr><td>Destination:</td><td><i>To be provided by counterparty</i></td></tr>");
        }
    }

    // Deadlines
    summary += QString("<tr><td colspan='2'><b>Delivery Deadlines</b></td></tr>");

    int maturityPeriod = contractWizard->field("maturityPeriod").toInt();
    int deliveryGap = contractWizard->field("deliveryGap").toInt();
    QString unit = contractWizard->field("maturityUnit").toString();

    summary += QString("<tr><td>Maturity Period:</td><td>%1 %2</td></tr>")
        .arg(maturityPeriod).arg(unit);
    summary += QString("<tr><td>Delivery Gap:</td><td>%1 blocks (between short and long delivery)</td></tr>")
        .arg(deliveryGap);
    summary += QString("<tr><td>Safety Buffer:</td><td>%1 blocks</td></tr>")
        .arg(contractWizard->field("safetyBuffer").toInt());

    // Addresses - only proposer's own
    summary += QString("<tr><td colspan='2'><b>Your Addresses</b></td></tr>");
    summary += QString("<tr><td>Your Margin Dest:</td><td>%1</td></tr>")
        .arg(contractWizard->field("myMarginDest").toString());
    summary += QString("<tr><td>Your Settle Dest:</td><td>%1</td></tr>")
        .arg(contractWizard->field("mySettleDest").toString());
    summary += QString("<tr><td colspan='2'><i>Counterparty addresses will be provided when they accept the offer.</i></td></tr>");

    summary += "</table>";

    // ========================================================================
    // Pricing Breakdown Section
    // ========================================================================
    summary += QString("<h3>%1</h3>").arg(tr("Pricing Breakdown"));

    // Build inline terms for pricing
    QVariantMap inlineTerms;

    // Get delivery info
    QString longDeliverAssetId = contractWizard->field("longDeliverAssetId").toString();
    bool longDeliverIsNative = (contractWizard->field("longDeliverIsNative").toString() == "true");
    QString shortDeliverAssetId = contractWizard->field("shortDeliverAssetId").toString();
    bool shortDeliverIsNative = (contractWizard->field("shortDeliverIsNative").toString() == "true");

    // For now, we need to calculate units - this is tricky in review page
    // We'll use display values and assume 8 decimals for simplicity (or get from asset info)
    const double longScale = 100000000.0; // 8 decimals
    const double shortScale = 100000000.0;

    inlineTerms["long_party_deliver_asset"] = longDeliverIsNative ? "" : longDeliverAssetId;
    inlineTerms["long_party_deliver_is_native"] = longDeliverIsNative;
    inlineTerms["long_party_deliver_units"] = static_cast<qint64>(longSize * longScale);

    inlineTerms["short_party_deliver_asset"] = shortDeliverIsNative ? "" : shortDeliverAssetId;
    inlineTerms["short_party_deliver_is_native"] = shortDeliverIsNative;
    inlineTerms["short_party_deliver_units"] = static_cast<qint64>(shortSize * shortScale);

    // Get IM info
    QString longImAssetId = contractWizard->field("longImAssetId").toString();
    bool longImIsNative = (contractWizard->field("longImIsNative").toString() == "true");
    QString shortImAssetId = contractWizard->field("shortImAssetId").toString();
    bool shortImIsNative = (contractWizard->field("shortImIsNative").toString() == "true");

    const double longImScale = 100000000.0;
    const double shortImScale = 100000000.0;

    inlineTerms["long_party_margin_asset"] = longImIsNative ? "" : longImAssetId;
    inlineTerms["long_party_margin_is_native"] = longImIsNative;
    inlineTerms["long_party_margin_units"] = static_cast<qint64>(longIm * longImScale);

    inlineTerms["short_party_margin_asset"] = shortImIsNative ? "" : shortImAssetId;
    inlineTerms["short_party_margin_is_native"] = shortImIsNative;
    inlineTerms["short_party_margin_units"] = static_cast<qint64>(shortIm * shortImScale);

    // Get premium info (if option)
    if (isOption) {
        double premiumAmount = contractWizard->field("premiumAmount").toDouble();
        QString premiumAssetId = contractWizard->field("premiumAssetId").toString();
        bool premiumIsNative = (contractWizard->field("premiumIsNative").toString() == "true");
        const double premiumScale = 100000000.0;

        inlineTerms["premium_asset"] = premiumIsNative ? "" : premiumAssetId;
        inlineTerms["premium_is_native"] = premiumIsNative;
        inlineTerms["premium_units"] = static_cast<qint64>(premiumAmount * premiumScale);
    } else {
        inlineTerms["premium_asset"] = "";
        inlineTerms["premium_is_native"] = true;
        inlineTerms["premium_units"] = 0;
    }

    // Calculate deadline heights
    int deadlineShort, deadlineLong;
    bool useAbsoluteHeight = contractWizard->field("useAbsoluteHeight").toBool();

    if (useAbsoluteHeight) {
        deadlineShort = contractWizard->field("absoluteShortHeight").toInt();
        deadlineLong = contractWizard->field("absoluteLongHeight").toInt();
    } else {
        // Get current height
        int currentHeight = 0;
        if (fwdWizard->walletModel) {
            currentHeight = fwdWizard->walletModel->getNumBlocks();
        }

        int maturityBlocks = 0;
        if (unit == "days") {
            maturityBlocks = maturityPeriod * 144;
        } else if (unit == "weeks") {
            maturityBlocks = maturityPeriod * 7 * 144;
        } else if (unit == "months") {
            maturityBlocks = maturityPeriod * 30 * 144;
        } else if (unit == "years") {
            maturityBlocks = maturityPeriod * 365 * 144;
        }

        deadlineShort = currentHeight + maturityBlocks;
        deadlineLong = deadlineShort + deliveryGap;
    }

    inlineTerms["deadline_short"] = deadlineShort;
    inlineTerms["deadline_long"] = deadlineLong;
    inlineTerms["safety_k"] = contractWizard->field("safetyBuffer").toInt();

    // Try to call pricing RPC
    try {
        if (fwdWizard->walletModel) {
            auto result = fwdWizard->walletModel->pricingForwardQuote(
                "inline",
                "",
                inlineTerms,
                "",     // report_asset (empty for TSC)
                true,   // report_is_native (default to TSC)
                false  // compute_greeks (skip for performance)
            );

            if (result.success) {
                // Get report decimals
                int reportDecimals = 8;
                WalletModel::AssetInfo tscInfo = fwdWizard->walletModel->getAssetInfo("");
                if (tscInfo.has_decimals) {
                    reportDecimals = tscInfo.decimals;
                }
                const double toDisplayUnits = 1.0 / std::pow(10.0, reportDecimals);

                // Helper to format MTM values with color
                auto formatMtm = [](double value) -> QString {
                    if (value > 0.0) {
                        return QString("<span style='color: #4caf50; font-weight: bold;'>+%1 TSC</span>").arg(value, 0, 'f', 8);
                    } else if (value < 0.0) {
                        return QString("<span style='color: #f44336; font-weight: bold;'>%1 TSC</span>").arg(value, 0, 'f', 8);
                    } else {
                        return QString("<span style='color: #9e9e9e; font-weight: bold;'>0.00000000 TSC</span>");
                    }
                };

                const QString headerBg = ThemeHelpers::isDarkPalette() ? QStringLiteral("#3a3a3a") : QStringLiteral("#f0f0f0");
                summary += "<table cellpadding='4' border='1' style='border-collapse: collapse; width: 100%;'>";
                summary += QString("<tr style='background-color: %1;'><th>Metric</th><th>Mark Prices</th></tr>").arg(headerBg);

                // PV Receive
                double pvReceive = result.pv_receive * toDisplayUnits;
                summary += QString("<tr><td>PV Receive</td><td>%1 TSC</td></tr>").arg(pvReceive, 0, 'f', 8);

                // PV Pay
                double pvPay = result.pv_pay * toDisplayUnits;
                summary += QString("<tr><td>PV Pay</td><td>%1 TSC</td></tr>").arg(pvPay, 0, 'f', 8);

                // Net Spread Value
                double netSpread = result.net_spread_value * toDisplayUnits;
                summary += QString("<tr><td>Net Spread Value</td><td>%1 TSC</td></tr>").arg(netSpread, 0, 'f', 8);

                // Premium PV
                double premiumPv = result.premium_pv * toDisplayUnits;
                summary += QString("<tr><td>Premium PV</td><td>%1 TSC</td></tr>").arg(premiumPv, 0, 'f', 8);

                // Alice Short Call Value
                double aliceShortCall = result.alice_short_call_value * toDisplayUnits;
                summary += QString("<tr><td>Alice Short Call Value</td><td>%1 TSC</td></tr>").arg(aliceShortCall, 0, 'f', 8);

                // Alice Long Put Value
                double aliceLongPut = result.alice_long_put_value * toDisplayUnits;
                summary += QString("<tr><td>Alice Long Put Value</td><td>%1 TSC</td></tr>").arg(aliceLongPut, 0, 'f', 8);

                // Alice MTM
                double aliceMtm = result.alice_mtm * toDisplayUnits;
                summary += QString("<tr><td><b>Alice MTM</b></td><td>%1</td></tr>").arg(formatMtm(aliceMtm));

                // Bob MTM
                double bobMtm = result.bob_mtm * toDisplayUnits;
                summary += QString("<tr><td><b>Bob MTM</b></td><td>%1</td></tr>").arg(formatMtm(bobMtm));

                // IM Coverage Alice
                summary += QString("<tr><td>IM Coverage Alice</td><td>%1%</td></tr>")
                    .arg(result.im_coverage_alice * 100.0, 0, 'f', 2);

                // IM Coverage Bob
                summary += QString("<tr><td>IM Coverage Bob</td><td>%1%</td></tr>")
                    .arg(result.im_coverage_bob * 100.0, 0, 'f', 2);

                summary += "</table>";
            } else {
                summary += QString("<p><i>%1</i></p>").arg(tr("Pricing data unavailable - please ensure market data is loaded."));
            }
        } else {
            summary += QString("<p><i>%1</i></p>").arg(tr("Pricing data unavailable - wallet model not found."));
        }
    } catch (...) {
        summary += QString("<p><i>%1</i></p>").arg(tr("Error calculating pricing - market data may not be available."));
    }

    return summary;
}

// ============================================================================
// OptionTermSheetPage - Option-focused UI with standard terminology
// ============================================================================

OptionTermSheetPage::OptionTermSheetPage(QWidget* parent)
    : QWizardPage(parent)
    , advancedModeActive(false)
{
    setTitle(tr("Option Contract Parameters"));

    setupUI();
}

void OptionTermSheetPage::setupUI()
{
    QScrollArea* scrollArea = new QScrollArea(this);
    scrollArea->setWidgetResizable(true);
    scrollArea->setFrameShape(QFrame::NoFrame);

    QWidget* scrollWidget = new QWidget();
    QVBoxLayout* mainLayout = new QVBoxLayout(scrollWidget);
    mainLayout->setSpacing(16);

    // ========================================================================
    // Option Parameters
    // ========================================================================
    QGroupBox* optionGroup = new QGroupBox(tr("Option Parameters"));
    QGridLayout* optionLayout = new QGridLayout(optionGroup);
    int row = 0;

    // Direction: Buy / Sell
    optionLayout->addWidget(new QLabel(tr("<b>Direction:</b>")), row, 0);
    directionCombo = new QComboBox();
    directionCombo->addItem(tr("Buy"), "buy");
    directionCombo->addItem(tr("Sell"), "sell");
    optionLayout->addWidget(directionCombo, row, 1);
    optionLayout->addWidget(new QLabel(tr("(from maker's perspective)")), row, 2);
    row++;

    // Option Type: Call / Put
    optionLayout->addWidget(new QLabel(tr("<b>Type:</b>")), row, 0);
    optionTypeCombo = new QComboBox();
    optionTypeCombo->addItem(tr("Call"), "call");
    optionTypeCombo->addItem(tr("Put"), "put");
    optionLayout->addWidget(optionTypeCombo, row, 1);
    row++;

    // Base Asset (e.g., TSC)
    optionLayout->addWidget(new QLabel(tr("<b>Base Asset:</b>")), row, 0);
    baseAssetCombo = new QComboBox();
    optionLayout->addWidget(baseAssetCombo, row, 1);
    baseAssetIdEdit = new QLineEdit(this);
    baseAssetIdEdit->setVisible(false);
    row++;

    // Quote Asset (e.g., GOLD)
    optionLayout->addWidget(new QLabel(tr("<b>Quote Asset:</b>")), row, 0);
    quoteAssetCombo = new QComboBox();
    optionLayout->addWidget(quoteAssetCombo, row, 1);
    quoteAssetIdEdit = new QLineEdit(this);
    quoteAssetIdEdit->setVisible(false);
    row++;

    // Strike Price (base/quote, e.g., 1.2 TSC/GOLD)
    optionLayout->addWidget(new QLabel(tr("<b>Strike Price:</b>")), row, 0);
    strikeSpin = new QDoubleSpinBox();
    strikeSpin->setRange(0.00000001, 1000000000.0);
    strikeSpin->setDecimals(8);
    strikeSpin->setValue(1.0);
    optionLayout->addWidget(strikeSpin, row, 1);
    optionLayout->addWidget(new QLabel(tr("(base per quote)")), row, 2);
    row++;

    // Notional (reference for percentages)
    optionLayout->addWidget(new QLabel(tr("<b>Notional:</b>")), row, 0);
    notionalSpin = new QDoubleSpinBox();
    notionalSpin->setRange(0.00000001, 1000000000.0);
    notionalSpin->setDecimals(8);
    notionalSpin->setValue(10.0);
    optionLayout->addWidget(notionalSpin, row, 1);
    optionLayout->addWidget(new QLabel(tr("(reference for max payout and premium)")), row, 2);
    row++;

    // Max Payout (%)
    optionLayout->addWidget(new QLabel(tr("<b>Max Payout:</b>")), row, 0);
    maxPayoutSpin = new QDoubleSpinBox();
    maxPayoutSpin->setRange(0.0, 100.0);
    maxPayoutSpin->setDecimals(2);
    maxPayoutSpin->setValue(10.0);
    maxPayoutSpin->setSuffix(" %");
    optionLayout->addWidget(maxPayoutSpin, row, 1);
    row++;

    // Premium (%)
    optionLayout->addWidget(new QLabel(tr("<b>Premium:</b>")), row, 0);
    premiumSpin = new QDoubleSpinBox();
    premiumSpin->setRange(0.0, 100.0);
    premiumSpin->setDecimals(2);
    premiumSpin->setValue(1.0);
    premiumSpin->setSuffix(" %");
    optionLayout->addWidget(premiumSpin, row, 1);
    row++;

    // Expiry Period
    optionLayout->addWidget(new QLabel(tr("<b>Expiry:</b>")), row, 0);
    QHBoxLayout* expiryLayout = new QHBoxLayout();
    expirySpin = new QSpinBox();
    expirySpin->setRange(1, 10000);
    expirySpin->setValue(365);
    expiryLayout->addWidget(expirySpin);
    expiryUnitCombo = new QComboBox();
    expiryUnitCombo->addItem(tr("Days"), "days");
    expiryUnitCombo->addItem(tr("Weeks"), "weeks");
    expiryUnitCombo->addItem(tr("Months"), "months");
    expiryUnitCombo->addItem(tr("Years"), "years");
    expiryUnitCombo->setCurrentIndex(0);
    expiryLayout->addWidget(expiryUnitCombo);
    expiryLayout->addStretch();
    optionLayout->addLayout(expiryLayout, row, 1, 1, 2);
    row++;

    // Delivery Gap
    optionLayout->addWidget(new QLabel(tr("Delivery Gap:")), row, 0);
    deliveryGapSpin = new QSpinBox();
    deliveryGapSpin->setRange(0, 100000);
    deliveryGapSpin->setValue(144);
    optionLayout->addWidget(deliveryGapSpin, row, 1);
    optionLayout->addWidget(new QLabel(tr("blocks (between short and long delivery)")), row, 2);
    row++;

    mainLayout->addWidget(optionGroup);

    // ========================================================================
    // Pricing Breakdown Section
    // ========================================================================
    QGroupBox* pricingGroup = new QGroupBox(tr("Pricing Breakdown"));
    pricingGroup->setStyleSheet(ThemeHelpers::panelStyleSheet());
    QGridLayout* pricingLayout = new QGridLayout(pricingGroup);

    int pricingRow = 0;

    // Header row
    pricingLayout->addWidget(new QLabel(tr("")), pricingRow, 0);
    pricingLayout->addWidget(new QLabel(tr("Absolute")), pricingRow, 1);
    pricingLayout->addWidget(new QLabel(tr("Per Notional")), pricingRow, 2);
    pricingRow++;

    // PV Receive
    pricingLayout->addWidget(new QLabel(tr("PV Receive:")), pricingRow, 0);
    pvReceiveLabel = new QLabel(tr("--"));
    pvReceiveLabel->setStyleSheet(ThemeHelpers::accentLabelStyleSheet(/*bold=*/false));
    pricingLayout->addWidget(pvReceiveLabel, pricingRow, 1);
    pvReceivePerNotionalLabel = new QLabel(tr("--"));
    pvReceivePerNotionalLabel->setStyleSheet(ThemeHelpers::accentLabelStyleSheet(/*bold=*/false));
    pricingLayout->addWidget(pvReceivePerNotionalLabel, pricingRow++, 2);

    // PV Pay
    pricingLayout->addWidget(new QLabel(tr("PV Pay:")), pricingRow, 0);
    pvPayLabel = new QLabel(tr("--"));
    pvPayLabel->setStyleSheet(ThemeHelpers::accentLabelStyleSheet(/*bold=*/false));
    pricingLayout->addWidget(pvPayLabel, pricingRow, 1);
    pvPayPerNotionalLabel = new QLabel(tr("--"));
    pvPayPerNotionalLabel->setStyleSheet(ThemeHelpers::accentLabelStyleSheet(/*bold=*/false));
    pricingLayout->addWidget(pvPayPerNotionalLabel, pricingRow++, 2);

    // Net Spread Value
    pricingLayout->addWidget(new QLabel(tr("Net Spread Value:")), pricingRow, 0);
    netSpreadLabel = new QLabel(tr("--"));
    netSpreadLabel->setStyleSheet(ThemeHelpers::accentLabelStyleSheet(/*bold=*/false));
    pricingLayout->addWidget(netSpreadLabel, pricingRow, 1);
    netSpreadPerNotionalLabel = new QLabel(tr("--"));
    netSpreadPerNotionalLabel->setStyleSheet(ThemeHelpers::accentLabelStyleSheet(/*bold=*/false));
    pricingLayout->addWidget(netSpreadPerNotionalLabel, pricingRow++, 2);

    // Premium PV
    pricingLayout->addWidget(new QLabel(tr("Premium PV:")), pricingRow, 0);
    premiumPvLabel = new QLabel(tr("--"));
    premiumPvLabel->setStyleSheet(ThemeHelpers::accentLabelStyleSheet(/*bold=*/false));
    pricingLayout->addWidget(premiumPvLabel, pricingRow, 1);
    premiumPvPerNotionalLabel = new QLabel(tr("--"));
    premiumPvPerNotionalLabel->setStyleSheet(ThemeHelpers::accentLabelStyleSheet(/*bold=*/false));
    pricingLayout->addWidget(premiumPvPerNotionalLabel, pricingRow++, 2);

    // Long Short Call Value
    pricingLayout->addWidget(new QLabel(tr("Long Short Call Value:")), pricingRow, 0);
    aliceShortCallLabel = new QLabel(tr("--"));
    aliceShortCallLabel->setStyleSheet(ThemeHelpers::accentLabelStyleSheet(/*bold=*/false));
    pricingLayout->addWidget(aliceShortCallLabel, pricingRow, 1);
    aliceShortCallPerNotionalLabel = new QLabel(tr("--"));
    aliceShortCallPerNotionalLabel->setStyleSheet(ThemeHelpers::accentLabelStyleSheet(/*bold=*/false));
    pricingLayout->addWidget(aliceShortCallPerNotionalLabel, pricingRow++, 2);

    // Long Long Put Value
    pricingLayout->addWidget(new QLabel(tr("Long Long Put Value:")), pricingRow, 0);
    aliceLongPutLabel = new QLabel(tr("--"));
    aliceLongPutLabel->setStyleSheet(ThemeHelpers::accentLabelStyleSheet(/*bold=*/false));
    pricingLayout->addWidget(aliceLongPutLabel, pricingRow, 1);
    aliceLongPutPerNotionalLabel = new QLabel(tr("--"));
    aliceLongPutPerNotionalLabel->setStyleSheet(ThemeHelpers::accentLabelStyleSheet(/*bold=*/false));
    pricingLayout->addWidget(aliceLongPutPerNotionalLabel, pricingRow++, 2);

    // Add separator
    QFrame* separator = new QFrame();
    separator->setFrameShape(QFrame::HLine);
    separator->setFrameShadow(QFrame::Sunken);
    pricingLayout->addWidget(separator, pricingRow++, 0, 1, 3);

    // Long MTM
    pricingLayout->addWidget(new QLabel(tr("Long MTM:")), pricingRow, 0);
    aliceMtmLabel = new QLabel(tr("--"));
    aliceMtmLabel->setStyleSheet("QLabel { font-weight: bold; }");
    pricingLayout->addWidget(aliceMtmLabel, pricingRow, 1);
    aliceMtmPerNotionalLabel = new QLabel(tr("--"));
    aliceMtmPerNotionalLabel->setStyleSheet("QLabel { font-weight: bold; }");
    pricingLayout->addWidget(aliceMtmPerNotionalLabel, pricingRow++, 2);

    // Short MTM
    pricingLayout->addWidget(new QLabel(tr("Short MTM:")), pricingRow, 0);
    bobMtmLabel = new QLabel(tr("--"));
    bobMtmLabel->setStyleSheet("QLabel { font-weight: bold; }");
    pricingLayout->addWidget(bobMtmLabel, pricingRow, 1);
    bobMtmPerNotionalLabel = new QLabel(tr("--"));
    bobMtmPerNotionalLabel->setStyleSheet("QLabel { font-weight: bold; }");
    pricingLayout->addWidget(bobMtmPerNotionalLabel, pricingRow++, 2);

    // IM Coverage Long
    pricingLayout->addWidget(new QLabel(tr("IM Coverage Long:")), pricingRow, 0);
    imCoverageAliceLabel = new QLabel(tr("--"));
    imCoverageAliceLabel->setStyleSheet(ThemeHelpers::accentLabelStyleSheet(/*bold=*/false));
    pricingLayout->addWidget(imCoverageAliceLabel, pricingRow, 1);
    imCoverageAlicePerNotionalLabel = new QLabel(tr("--"));
    imCoverageAlicePerNotionalLabel->setStyleSheet(ThemeHelpers::accentLabelStyleSheet(/*bold=*/false));
    pricingLayout->addWidget(imCoverageAlicePerNotionalLabel, pricingRow++, 2);

    // IM Coverage Short
    pricingLayout->addWidget(new QLabel(tr("IM Coverage Short:")), pricingRow, 0);
    imCoverageBobLabel = new QLabel(tr("--"));
    imCoverageBobLabel->setStyleSheet(ThemeHelpers::accentLabelStyleSheet(/*bold=*/false));
    pricingLayout->addWidget(imCoverageBobLabel, pricingRow, 1);
    imCoverageBobPerNotionalLabel = new QLabel(tr("--"));
    imCoverageBobPerNotionalLabel->setStyleSheet(ThemeHelpers::accentLabelStyleSheet(/*bold=*/false));
    pricingLayout->addWidget(imCoverageBobPerNotionalLabel, pricingRow++, 2);

    mainLayout->addWidget(pricingGroup);

    // Add "Show Greeks" button below pricing
    showGreeksButton = new QPushButton(tr("View Greeks"));
    showGreeksButton->setStyleSheet(
        "QPushButton { "
        "background-color: #673ab7; "
        "color: white; "
        "font-weight: bold; "
        "padding: 8px 16px; "
        "border-radius: 4px; "
        "}"
        "QPushButton:hover { background-color: #5e35b1; }"
    );
    connect(showGreeksButton, &QPushButton::clicked, this, &OptionTermSheetPage::onShowGreeks);
    mainLayout->addWidget(showGreeksButton);

    // Create debounce timer for pricing updates
    pricingDebounceTimer = new QTimer();
    pricingDebounceTimer->setSingleShot(true);
    pricingDebounceTimer->setInterval(500); // 500ms debounce
    connect(pricingDebounceTimer, &QTimer::timeout, this, &OptionTermSheetPage::updateOptionPricing);

    // Connect all input fields to restart the timer
    connect(directionCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, [this]() { pricingDebounceTimer->start(); });
    connect(optionTypeCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, [this]() { pricingDebounceTimer->start(); });
    connect(baseAssetCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, [this]() { pricingDebounceTimer->start(); });
    connect(quoteAssetCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, [this]() { pricingDebounceTimer->start(); });
    connect(strikeSpin, QOverload<double>::of(&QDoubleSpinBox::valueChanged),
            this, [this]() { pricingDebounceTimer->start(); });
    connect(notionalSpin, QOverload<double>::of(&QDoubleSpinBox::valueChanged),
            this, [this]() { pricingDebounceTimer->start(); });
    connect(maxPayoutSpin, QOverload<double>::of(&QDoubleSpinBox::valueChanged),
            this, [this]() { pricingDebounceTimer->start(); });
    connect(premiumSpin, QOverload<double>::of(&QDoubleSpinBox::valueChanged),
            this, [this]() { pricingDebounceTimer->start(); });
    connect(expirySpin, QOverload<int>::of(&QSpinBox::valueChanged),
            this, [this]() { pricingDebounceTimer->start(); });
    connect(expiryUnitCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, [this]() { pricingDebounceTimer->start(); });
    connect(deliveryGapSpin, QOverload<int>::of(&QSpinBox::valueChanged),
            this, [this]() { pricingDebounceTimer->start(); });

    // ========================================================================
    // Addresses - collapsible advanced section
    // ========================================================================
    QGroupBox* addressGroup = new QGroupBox(tr("Advanced: Settlement Addresses"));
    addressGroup->setCheckable(true);
    addressGroup->setChecked(false);  // Collapsed by default
    QGridLayout* addressLayout = new QGridLayout(addressGroup);
    row = 0;

    addressLayout->addWidget(new QLabel(tr("Margin Refund:")), row, 0);
    marginDestEdit = new QLineEdit();
    marginDestEdit->setPlaceholderText(tr("Address to receive margin refund"));
    addressLayout->addWidget(marginDestEdit, row, 1);
    row++;

    addressLayout->addWidget(new QLabel(tr("Settlement:")), row, 0);
    settlementDestEdit = new QLineEdit();
    settlementDestEdit->setPlaceholderText(tr("Address to receive settlement"));
    addressLayout->addWidget(settlementDestEdit, row, 1);
    row++;

    addressLayout->addWidget(new QLabel(tr("Premium:")), row, 0);
    premiumDestEdit = new QLineEdit();
    premiumDestEdit->setPlaceholderText(tr("Address to receive premium (if you receive it)"));
    addressLayout->addWidget(premiumDestEdit, row, 1);
    row++;

    generateAddressesButton = new QPushButton(tr("Generate All Addresses"));
    addressLayout->addWidget(generateAddressesButton, row, 0, 1, 2);
    row++;

    mainLayout->addWidget(addressGroup);

    // ========================================================================
    // Forward Preview
    // ========================================================================
    QGroupBox* previewGroup = new QGroupBox(tr("Equivalent Forward Contract Structure"));
    QVBoxLayout* previewLayout = new QVBoxLayout(previewGroup);

    forwardPreviewLabel = new QLabel(tr("The option parameters above will be converted to the following forward structure:"));
    forwardPreviewLabel->setWordWrap(true);
    previewLayout->addWidget(forwardPreviewLabel);

    rolePreviewLabel = new QLabel();
    rolePreviewLabel->setStyleSheet("font-weight: bold;");
    previewLayout->addWidget(rolePreviewLabel);

    longDeliveryPreviewLabel = new QLabel();
    previewLayout->addWidget(longDeliveryPreviewLabel);

    shortDeliveryPreviewLabel = new QLabel();
    previewLayout->addWidget(shortDeliveryPreviewLabel);

    longImPreviewLabel = new QLabel();
    previewLayout->addWidget(longImPreviewLabel);

    shortImPreviewLabel = new QLabel();
    previewLayout->addWidget(shortImPreviewLabel);

    premiumAmountPreviewLabel = new QLabel();
    previewLayout->addWidget(premiumAmountPreviewLabel);

    mainLayout->addWidget(previewGroup);

    // ========================================================================
    // Advanced Editor (collapsible)
    // ========================================================================
    showAdvancedCheckBox = new QCheckBox(tr("Show Advanced Editor (modify auto-populated forward parameters)"));
    mainLayout->addWidget(showAdvancedCheckBox);

    advancedEditorWidget = new QWidget();
    QGroupBox* advancedGroup = new QGroupBox(tr("Advanced Forward Parameters"));
    QVBoxLayout* advancedMainLayout = new QVBoxLayout(advancedEditorWidget);
    advancedMainLayout->setContentsMargins(0, 0, 0, 0);
    advancedMainLayout->addWidget(advancedGroup);

    QGridLayout* advancedLayout = new QGridLayout(advancedGroup);
    int advRow = 0;

    QLabel* advWarning = new QLabel(tr("<b>Warning:</b> Modifying these values will override the auto-calculated option parameters. "
                                       "Only change these if you know what you're doing."));
    advWarning->setWordWrap(true);
    advWarning->setStyleSheet("QLabel { color: #ff6600; }");
    advancedLayout->addWidget(advWarning, advRow, 0, 1, 3);
    advRow++;

    // Long delivery amount
    advancedLayout->addWidget(new QLabel(tr("Long Delivery Amount:")), advRow, 0);
    advLongDeliverySpin = new QDoubleSpinBox();
    advLongDeliverySpin->setRange(0.00000001, 1000000000.0);
    advLongDeliverySpin->setDecimals(8);
    advancedLayout->addWidget(advLongDeliverySpin, advRow, 1);
    advancedLayout->addWidget(new QLabel(tr("(base asset)")), advRow, 2);
    advRow++;

    // Short delivery amount
    advancedLayout->addWidget(new QLabel(tr("Short Delivery Amount:")), advRow, 0);
    advShortDeliverySpin = new QDoubleSpinBox();
    advShortDeliverySpin->setRange(0.00000001, 1000000000.0);
    advShortDeliverySpin->setDecimals(8);
    advancedLayout->addWidget(advShortDeliverySpin, advRow, 1);
    advancedLayout->addWidget(new QLabel(tr("(quote asset)")), advRow, 2);
    advRow++;

    // Long IM
    advancedLayout->addWidget(new QLabel(tr("Long Initial Margin:")), advRow, 0);
    advLongImSpin = new QDoubleSpinBox();
    advLongImSpin->setRange(0.0, 1000000000.0);
    advLongImSpin->setDecimals(8);
    advancedLayout->addWidget(advLongImSpin, advRow, 1);
    advancedLayout->addWidget(new QLabel(tr("(base asset)")), advRow, 2);
    advRow++;

    // Short IM
    advancedLayout->addWidget(new QLabel(tr("Short Initial Margin:")), advRow, 0);
    advShortImSpin = new QDoubleSpinBox();
    advShortImSpin->setRange(0.0, 1000000000.0);
    advShortImSpin->setDecimals(8);
    advancedLayout->addWidget(advShortImSpin, advRow, 1);
    advancedLayout->addWidget(new QLabel(tr("(base asset)")), advRow, 2);
    advRow++;

    // Premium amount
    advancedLayout->addWidget(new QLabel(tr("Premium Amount:")), advRow, 0);
    advPremiumAmountSpin = new QDoubleSpinBox();
    advPremiumAmountSpin->setRange(0.0, 1000000000.0);
    advPremiumAmountSpin->setDecimals(8);
    advancedLayout->addWidget(advPremiumAmountSpin, advRow, 1);
    advancedLayout->addWidget(new QLabel(tr("(base asset)")), advRow, 2);
    advRow++;

    advancedEditorWidget->setVisible(false);  // Hidden by default
    mainLayout->addWidget(advancedEditorWidget);

    mainLayout->addStretch();

    scrollArea->setWidget(scrollWidget);

    QVBoxLayout* pageLayout = new QVBoxLayout(this);
    pageLayout->setContentsMargins(0, 0, 0, 0);
    pageLayout->addWidget(scrollArea);

    // Create hidden fields for storing converted forward parameters
    hiddenIsLongParty = new QLineEdit(this);
    hiddenIsLongParty->setVisible(false);
    hiddenLongSize = new QLineEdit(this);
    hiddenLongSize->setVisible(false);
    hiddenPrice = new QLineEdit(this);
    hiddenPrice->setVisible(false);
    hiddenLongDeliverAssetId = new QLineEdit(this);
    hiddenLongDeliverAssetId->setVisible(false);
    hiddenLongDeliverIsNative = new QLineEdit(this);
    hiddenLongDeliverIsNative->setVisible(false);
    hiddenShortDeliverAssetId = new QLineEdit(this);
    hiddenShortDeliverAssetId->setVisible(false);
    hiddenShortDeliverIsNative = new QLineEdit(this);
    hiddenShortDeliverIsNative->setVisible(false);
    hiddenLongImPercent = new QLineEdit(this);
    hiddenLongImPercent->setVisible(false);
    hiddenLongImPercentValue = new QLineEdit(this);
    hiddenLongImPercentValue->setVisible(false);
    hiddenLongImAbsoluteValue = new QLineEdit(this);
    hiddenLongImAbsoluteValue->setVisible(false);
    hiddenLongImAssetId = new QLineEdit(this);
    hiddenLongImAssetId->setVisible(false);
    hiddenLongImIsNative = new QLineEdit(this);
    hiddenLongImIsNative->setVisible(false);
    hiddenShortImPercent = new QLineEdit(this);
    hiddenShortImPercent->setVisible(false);
    hiddenShortImPercentValue = new QLineEdit(this);
    hiddenShortImPercentValue->setVisible(false);
    hiddenShortImAbsoluteValue = new QLineEdit(this);
    hiddenShortImAbsoluteValue->setVisible(false);
    hiddenShortImAssetId = new QLineEdit(this);
    hiddenShortImAssetId->setVisible(false);
    hiddenShortImIsNative = new QLineEdit(this);
    hiddenShortImIsNative->setVisible(false);
    hiddenPremiumAmount = new QLineEdit(this);
    hiddenPremiumAmount->setVisible(false);
    hiddenPremiumPayerIsLong = new QLineEdit(this);
    hiddenPremiumPayerIsLong->setVisible(false);
    hiddenPremiumAssetId = new QLineEdit(this);
    hiddenPremiumAssetId->setVisible(false);
    hiddenPremiumIsNative = new QLineEdit(this);
    hiddenPremiumIsNative->setVisible(false);
    hiddenMaturityPeriod = new QLineEdit(this);
    hiddenMaturityPeriod->setVisible(false);
    hiddenMaturityUnit = new QLineEdit(this);
    hiddenMaturityUnit->setVisible(false);
    hiddenMyMarginDest = new QLineEdit(this);
    hiddenMyMarginDest->setVisible(false);
    hiddenMySettleDest = new QLineEdit(this);
    hiddenMySettleDest->setVisible(false);
    hiddenSafetyBuffer = new QLineEdit(this);
    hiddenSafetyBuffer->setVisible(false);

    // Register option parameter fields
    registerField("direction", directionCombo, "currentData", SIGNAL(currentIndexChanged(int)));
    registerField("optionType", optionTypeCombo, "currentData", SIGNAL(currentIndexChanged(int)));
    registerField("baseAssetId", baseAssetIdEdit);
    registerField("quoteAssetId", quoteAssetIdEdit);
    registerField("strike", strikeSpin, "value", SIGNAL(valueChanged(double)));
    registerField("notional", notionalSpin, "value", SIGNAL(valueChanged(double)));
    registerField("maxPayoutPercent", maxPayoutSpin, "value", SIGNAL(valueChanged(double)));
    registerField("premiumPercent", premiumSpin, "value", SIGNAL(valueChanged(double)));
    registerField("expiryPeriod", expirySpin);
    registerField("expiryUnit", expiryUnitCombo, "currentData", SIGNAL(currentIndexChanged(int)));
    registerField("deliveryGap", deliveryGapSpin);
    registerField("marginDest*", marginDestEdit);
    registerField("settlementDest*", settlementDestEdit);
    registerField("premiumDest", premiumDestEdit);

    // Register the hidden converted forward fields
    registerField("isLongParty", hiddenIsLongParty);
    registerField("longSize", hiddenLongSize);
    registerField("price", hiddenPrice);
    registerField("longDeliverAssetId", hiddenLongDeliverAssetId);
    registerField("longDeliverIsNative", hiddenLongDeliverIsNative);
    registerField("shortDeliverAssetId", hiddenShortDeliverAssetId);
    registerField("shortDeliverIsNative", hiddenShortDeliverIsNative);
    registerField("longImPercent", hiddenLongImPercent);
    registerField("longImPercentValue", hiddenLongImPercentValue);
    registerField("longImAbsoluteValue", hiddenLongImAbsoluteValue);
    registerField("longImAssetId", hiddenLongImAssetId);
    registerField("longImIsNative", hiddenLongImIsNative);
    registerField("shortImPercent", hiddenShortImPercent);
    registerField("shortImPercentValue", hiddenShortImPercentValue);
    registerField("shortImAbsoluteValue", hiddenShortImAbsoluteValue);
    registerField("shortImAssetId", hiddenShortImAssetId);
    registerField("shortImIsNative", hiddenShortImIsNative);
    registerField("premiumAmount", hiddenPremiumAmount);
    registerField("premiumPayerIsLong", hiddenPremiumPayerIsLong);
    registerField("premiumAssetId", hiddenPremiumAssetId);
    registerField("premiumIsNative", hiddenPremiumIsNative);
    registerField("maturityPeriod", hiddenMaturityPeriod);
    registerField("maturityUnit", hiddenMaturityUnit);
    registerField("myMarginDest", hiddenMyMarginDest);
    registerField("mySettleDest", hiddenMySettleDest);
    registerField("safetyBuffer", hiddenSafetyBuffer);

    // Connect signals
    connect(directionCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &OptionTermSheetPage::onDirectionChanged);
    connect(optionTypeCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &OptionTermSheetPage::onOptionTypeChanged);
    connect(baseAssetCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &OptionTermSheetPage::onBaseAssetChanged);
    connect(quoteAssetCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &OptionTermSheetPage::onQuoteAssetChanged);
    connect(strikeSpin, QOverload<double>::of(&QDoubleSpinBox::valueChanged),
            this, &OptionTermSheetPage::onStrikeChanged);
    connect(notionalSpin, QOverload<double>::of(&QDoubleSpinBox::valueChanged),
            this, &OptionTermSheetPage::onNotionalChanged);
    connect(maxPayoutSpin, QOverload<double>::of(&QDoubleSpinBox::valueChanged),
            this, &OptionTermSheetPage::onMaxPayoutChanged);
    connect(premiumSpin, QOverload<double>::of(&QDoubleSpinBox::valueChanged),
            this, &OptionTermSheetPage::onPremiumChanged);
    connect(expirySpin, QOverload<int>::of(&QSpinBox::valueChanged),
            this, &OptionTermSheetPage::onExpiryChanged);
    connect(expiryUnitCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &OptionTermSheetPage::onExpiryUnitChanged);
    connect(generateAddressesButton, &QPushButton::clicked,
            this, &OptionTermSheetPage::onGenerateDestinationAddresses);
    connect(showAdvancedCheckBox, &QCheckBox::toggled,
            this, &OptionTermSheetPage::onShowAdvancedEditor);

    // Connect advanced editor fields
    connect(advLongDeliverySpin, QOverload<double>::of(&QDoubleSpinBox::valueChanged),
            this, &OptionTermSheetPage::onAdvancedFieldChanged);
    connect(advShortDeliverySpin, QOverload<double>::of(&QDoubleSpinBox::valueChanged),
            this, &OptionTermSheetPage::onAdvancedFieldChanged);
    connect(advLongImSpin, QOverload<double>::of(&QDoubleSpinBox::valueChanged),
            this, &OptionTermSheetPage::onAdvancedFieldChanged);
    connect(advShortImSpin, QOverload<double>::of(&QDoubleSpinBox::valueChanged),
            this, &OptionTermSheetPage::onAdvancedFieldChanged);
    connect(advPremiumAmountSpin, QOverload<double>::of(&QDoubleSpinBox::valueChanged),
            this, &OptionTermSheetPage::onAdvancedFieldChanged);

    // Install wheel event filters
    GUIUtil::InstallWheelEventFilter(directionCombo);
    GUIUtil::InstallWheelEventFilter(optionTypeCombo);
    GUIUtil::InstallWheelEventFilter(baseAssetCombo);
    GUIUtil::InstallWheelEventFilter(quoteAssetCombo);
    GUIUtil::InstallWheelEventFilter(strikeSpin);
    GUIUtil::InstallWheelEventFilter(notionalSpin);
    GUIUtil::InstallWheelEventFilter(maxPayoutSpin);
    GUIUtil::InstallWheelEventFilter(premiumSpin);
    GUIUtil::InstallWheelEventFilter(expirySpin);
    GUIUtil::InstallWheelEventFilter(expiryUnitCombo);
    GUIUtil::InstallWheelEventFilter(deliveryGapSpin);
    GUIUtil::InstallWheelEventFilter(advLongDeliverySpin);
    GUIUtil::InstallWheelEventFilter(advShortDeliverySpin);
    GUIUtil::InstallWheelEventFilter(advLongImSpin);
    GUIUtil::InstallWheelEventFilter(advShortImSpin);
    GUIUtil::InstallWheelEventFilter(advPremiumAmountSpin);
}

void OptionTermSheetPage::initializePage()
{
    // Populate asset combos
    populateAssetComboBox(baseAssetCombo, true);
    populateAssetComboBox(quoteAssetCombo, true);

    // Auto-generate addresses if empty
    if (marginDestEdit->text().isEmpty() || settlementDestEdit->text().isEmpty()) {
        onGenerateDestinationAddresses();
    }

    // Update preview
    updateForwardPreview();
}

bool OptionTermSheetPage::validatePage()
{
    // Convert option parameters to forward parameters
    convertToForwardParams();

    auto* wizard = qobject_cast<ForwardContractBuilder*>(this->wizard());
    if (!wizard) return false;

    return wizard->validateTerms();
}

void OptionTermSheetPage::populateAssetComboBox(QComboBox* combo, bool includeNative)
{
    if (!combo) return;

    combo->clear();

    if (includeNative) {
        combo->addItem(tr("TSC (Native)"), QVariant::fromValue(QString("native")));
    }

    auto* wizardPtr = qobject_cast<ForwardContractBuilder*>(wizard());
    WalletModel* walletModel = wizardPtr ? wizardPtr->getWalletModel() : nullptr;
    if (!walletModel) return;

    QList<WalletModel::AssetInfo> assets = walletModel->listAssets();
    for (const auto& asset : assets) {
        QString label = QString("%1 (%2)").arg(asset.ticker, asset.asset_id.left(8));
        combo->addItem(label, QVariant::fromValue(asset.asset_id));
    }
}

QString OptionTermSheetPage::getAssetIdFromCombo(QComboBox* combo) const
{
    if (!combo) return QString();
    QString data = combo->currentData().toString();
    // Return empty QString for native asset - "native" is a UI sentinel, not a valid asset_id
    return (data == "native") ? QString() : data;
}

bool OptionTermSheetPage::isNativeAsset(QComboBox* combo) const
{
    // Check raw combo data directly (not via getAssetIdFromCombo which filters out "native")
    return combo && combo->currentData().toString() == "native";
}

int OptionTermSheetPage::getAssetDecimals(QComboBox* combo) const
{
    if (isNativeAsset(combo)) return 8;

    auto* wizardPtr = qobject_cast<ForwardContractBuilder*>(wizard());
    WalletModel* walletModel = wizardPtr ? wizardPtr->getWalletModel() : nullptr;
    if (!walletModel) return 8;

    QString assetId = getAssetIdFromCombo(combo);
    if (assetId.isEmpty()) return 8;  // Native assets return empty from getAssetIdFromCombo

    WalletModel::AssetInfo info = walletModel->getAssetInfo(assetId);
    return info.has_decimals ? info.decimals : 8;
}

void OptionTermSheetPage::applySpinBoxDecimals(QDoubleSpinBox* spin, int decimals) const
{
    if (!spin) return;
    if (decimals < 0) decimals = 0;
    const int clamped = std::min(decimals, 12);
    spin->setDecimals(clamped);
    const int step_decimals = std::min(clamped, 8);
    const double step = step_decimals > 0 ? std::pow(10.0, -step_decimals) : 1.0;
    spin->setSingleStep(step);
}

void OptionTermSheetPage::convertToForwardParams()
{
    // Get option parameters
    QString direction = directionCombo->currentData().toString();  // "buy" or "sell"
    QString optionType = optionTypeCombo->currentData().toString();  // "call" or "put"
    double strike = strikeSpin->value();
    double notional = notionalSpin->value();
    double maxPayoutPercent = maxPayoutSpin->value();
    double premiumPercent = premiumSpin->value();

    QString baseAssetId = getAssetIdFromCombo(baseAssetCombo);
    QString quoteAssetId = getAssetIdFromCombo(quoteAssetCombo);
    bool baseIsNative = isNativeAsset(baseAssetCombo);
    bool quoteIsNative = isNativeAsset(quoteAssetCombo);

    bool isBuy = (direction == "buy");
    bool isCall = (optionType == "call");

    // Determine maker's role and forward structure based on option type and direction
    //
    // Buy Call:  Maker is long, has right to buy base (deliver base, receive quote). Minimal IM.
    // Sell Call: Maker is short, obligated to sell base (receive base, deliver quote). Max payout IM.
    // Buy Put:   Maker is short, has right to sell base (deliver quote, receive base). Minimal IM.
    // Sell Put:  Maker is long, obligated to buy base (deliver base, receive quote). Max payout IM.

    bool makerIsLong;
    bool optionBuyerIsLong;  // True if option buyer is long party in forward

    if (isCall) {
        // For calls: long party delivers base, short party delivers quote
        makerIsLong = isBuy;           // Buy Call: maker=long, Sell Call: maker=short
        optionBuyerIsLong = true;      // Call buyer is long party
    } else {
        // For puts: short party delivers base, long party delivers quote
        // This is inverted from calls!
        makerIsLong = !isBuy;          // Buy Put: maker=short, Sell Put: maker=long
        optionBuyerIsLong = false;     // Put buyer is short party
    }

    // Use advanced editor values if user has modified them, otherwise auto-calculate
    double longDelivers, shortDelivers, longIm, shortIm, premiumAmount;

    if (advancedModeActive && showAdvancedCheckBox->isChecked()) {
        // Use user-modified advanced values
        longDelivers = advLongDeliverySpin->value();
        shortDelivers = advShortDeliverySpin->value();
        longIm = advLongImSpin->value();
        shortIm = advShortImSpin->value();
        premiumAmount = advPremiumAmountSpin->value();
    } else {
        // Auto-calculate from option parameters
        double maxPayoutAmount = (maxPayoutPercent / 100.0) * notional;
        premiumAmount = (premiumPercent / 100.0) * notional;

        // For calls: IMs are in base asset. For puts: IMs are in quote asset.
        // Get the IM asset decimals to calculate minimal unit (1 unit = 1/10^decimals)
        int imAssetDecimals;
        if (isCall) {
            imAssetDecimals = getAssetDecimals(baseAssetCombo);
        } else {
            imAssetDecimals = getAssetDecimals(quoteAssetCombo);
        }
        double minimalIm = 1.0 / std::pow(10.0, imAssetDecimals);  // 1 unit of the IM asset

        if (isCall) {
            // Call: long delivers base, short delivers quote
            longDelivers = notional * strike;  // e.g., 10 * 1.2 = 12 TSC
            shortDelivers = notional;          // e.g., 10 GOLD

            // Call buyer (long) has option, posts minimal IM
            // Call seller (short) has obligation, posts max payout IM
            longIm = minimalIm;  // 1 unit of IM asset
            shortIm = maxPayoutAmount;
        } else {
            // Put: short delivers base, long delivers quote
            shortDelivers = notional * strike;  // e.g., 10 * 1.2 = 12 TSC
            longDelivers = notional;            // e.g., 10 GOLD

            // Put buyer (short) has option, posts minimal IM
            // Put seller (long) has obligation, posts max payout IM
            shortIm = minimalIm;  // 1 unit of IM asset
            longIm = maxPayoutAmount;
        }
    }

    // Premium is always paid by the option buyer (whether they're long or short in the forward)
    bool premiumPayerIsLong = optionBuyerIsLong;

    // Determine which assets are native
    // For calls: long delivers base, short delivers quote
    // For puts: long delivers quote, short delivers base
    bool longDeliverIsNative, shortDeliverIsNative;
    QString longDeliverAsset, shortDeliverAsset;

    if (isCall) {
        longDeliverIsNative = baseIsNative;
        shortDeliverIsNative = quoteIsNative;
        longDeliverAsset = baseAssetId;
        shortDeliverAsset = quoteAssetId;
    } else {
        // Put: assets are swapped
        longDeliverIsNative = quoteIsNative;
        shortDeliverIsNative = baseIsNative;
        longDeliverAsset = quoteAssetId;
        shortDeliverAsset = baseAssetId;
    }

    // For IMs and premium, determine which asset is used
    QString longImAssetId, shortImAssetId, premiumAssetId;
    bool longImIsNative, shortImIsNative, premiumIsNative;

    if (isCall) {
        // Call: base asset used for IMs and premium
        longImAssetId = baseAssetId;
        longImIsNative = baseIsNative;
        shortImAssetId = baseAssetId;
        shortImIsNative = baseIsNative;
        premiumAssetId = baseAssetId;
        premiumIsNative = baseIsNative;
    } else {
        // Put: quote asset used for IMs and premium
        longImAssetId = quoteAssetId;
        longImIsNative = quoteIsNative;
        shortImAssetId = quoteAssetId;
        shortImIsNative = quoteIsNative;
        premiumAssetId = quoteAssetId;
        premiumIsNative = quoteIsNative;
    }

    // Set wizard fields by writing to hidden QLineEdit widgets
    // Use "1"/"0" for booleans for reliable QVariant::toBool() conversion
    hiddenIsLongParty->setText(makerIsLong ? "1" : "0");
    hiddenLongSize->setText(QString::number(longDelivers, 'f', 8));
    hiddenPrice->setText(QString::number(shortDelivers / longDelivers, 'f', 8));
    hiddenLongDeliverAssetId->setText(longDeliverIsNative ? QString() : longDeliverAsset);
    hiddenLongDeliverIsNative->setText(longDeliverIsNative ? "1" : "0");
    hiddenShortDeliverAssetId->setText(shortDeliverIsNative ? QString() : shortDeliverAsset);
    hiddenShortDeliverIsNative->setText(shortDeliverIsNative ? "1" : "0");

    // Long IM (absolute)
    hiddenLongImPercent->setText("0");
    hiddenLongImPercentValue->setText("0");
    hiddenLongImAbsoluteValue->setText(QString::number(longIm, 'f', 8));
    hiddenLongImAssetId->setText(longImIsNative ? QString() : longImAssetId);
    hiddenLongImIsNative->setText(longImIsNative ? "1" : "0");

    // Short IM (absolute)
    hiddenShortImPercent->setText("0");
    hiddenShortImPercentValue->setText("0");
    hiddenShortImAbsoluteValue->setText(QString::number(shortIm, 'f', 8));
    hiddenShortImAssetId->setText(shortImIsNative ? QString() : shortImAssetId);
    hiddenShortImIsNative->setText(shortImIsNative ? "1" : "0");

    // Premium
    hiddenPremiumAmount->setText(QString::number(premiumAmount, 'f', 8));
    hiddenPremiumPayerIsLong->setText(premiumPayerIsLong ? "1" : "0");
    hiddenPremiumAssetId->setText(premiumIsNative ? QString() : premiumAssetId);
    hiddenPremiumIsNative->setText(premiumIsNative ? "1" : "0");

    // Maturity
    hiddenMaturityPeriod->setText(QString::number(expirySpin->value()));
    hiddenMaturityUnit->setText(expiryUnitCombo->currentData().toString());

    // Addresses
    hiddenMyMarginDest->setText(marginDestEdit->text());
    hiddenMySettleDest->setText(settlementDestEdit->text());

    // Safety buffer
    hiddenSafetyBuffer->setText("5");
}

void OptionTermSheetPage::updateForwardPreview()
{
    QString direction = directionCombo->currentData().toString();
    QString optionType = optionTypeCombo->currentData().toString();
    double strike = strikeSpin->value();
    double notional = notionalSpin->value();
    double maxPayoutPercent = maxPayoutSpin->value();
    double premiumPercent = premiumSpin->value();

    QString baseAsset = baseAssetCombo->currentText();
    QString quoteAsset = quoteAssetCombo->currentText();

    bool isBuy = (direction == "buy");
    bool isCall = (optionType == "call");

    // Determine maker's role
    bool makerIsLong = isCall ? isBuy : !isBuy;
    bool optionBuyerIsLong = isCall;

    // Calculate forward structure
    double longDelivers, shortDelivers, longIm, shortIm;
    double maxPayoutAmount = (maxPayoutPercent / 100.0) * notional;
    double premiumAmount = (premiumPercent / 100.0) * notional;

    // Get IM asset decimals to calculate minimal unit
    int imAssetDecimals;
    if (isCall) {
        imAssetDecimals = getAssetDecimals(baseAssetCombo);
    } else {
        imAssetDecimals = getAssetDecimals(quoteAssetCombo);
    }
    double minimalIm = 1.0 / std::pow(10.0, imAssetDecimals);  // 1 unit of the IM asset

    if (isCall) {
        // Call: long delivers base, short delivers quote
        longDelivers = notional * strike;
        shortDelivers = notional;
        longIm = minimalIm;  // Buyer (long) posts minimal
        shortIm = maxPayoutAmount;  // Seller (short) posts max payout
    } else {
        // Put: short delivers base, long delivers quote
        shortDelivers = notional * strike;
        longDelivers = notional;
        shortIm = minimalIm;  // Buyer (short) posts minimal
        longIm = maxPayoutAmount;  // Seller (long) posts max payout
    }

    QString longImAsset = isCall ? baseAsset : quoteAsset;
    QString shortImAsset = isCall ? baseAsset : quoteAsset;
    QString premiumAsset = baseAsset;  // Premium is typically in base asset

    rolePreviewLabel->setText(QString("<b>Your Role:</b> %1 (%2 %3)")
        .arg(makerIsLong ? tr("Long Party") : tr("Short Party"))
        .arg(isBuy ? tr("Buy") : tr("Sell"))
        .arg(isCall ? tr("Call") : tr("Put")));

    longDeliveryPreviewLabel->setText(QString("<b>Long delivers:</b> %1 %2")
        .arg(longDelivers, 0, 'f', 8)
        .arg(isCall ? baseAsset : quoteAsset));

    shortDeliveryPreviewLabel->setText(QString("<b>Short delivers:</b> %1 %2")
        .arg(shortDelivers, 0, 'f', 8)
        .arg(isCall ? quoteAsset : baseAsset));

    longImPreviewLabel->setText(QString("<b>Long IM:</b> %1 %2")
        .arg(longIm, 0, 'f', 8).arg(longImAsset));

    shortImPreviewLabel->setText(QString("<b>Short IM:</b> %1 %2")
        .arg(shortIm, 0, 'f', 8).arg(shortImAsset));

    QString premiumPayer = optionBuyerIsLong ? tr("Long (buyer)") : tr("Short (buyer)");
    premiumAmountPreviewLabel->setText(QString("<b>Premium:</b> %1 %2 (%3%), paid by %4")
        .arg(premiumAmount, 0, 'f', 8).arg(premiumAsset).arg(premiumPercent, 0, 'f', 2)
        .arg(premiumPayer));

    // Update advanced fields if not in advanced mode (i.e., user hasn't manually modified them)
    if (!advancedModeActive) {
        updateAdvancedFields();
    }
}

void OptionTermSheetPage::updateAdvancedFields()
{
    // Block signals to prevent triggering advancedModeActive
    advLongDeliverySpin->blockSignals(true);
    advShortDeliverySpin->blockSignals(true);
    advLongImSpin->blockSignals(true);
    advShortImSpin->blockSignals(true);
    advPremiumAmountSpin->blockSignals(true);

    QString optionType = optionTypeCombo->currentData().toString();
    bool isCall = (optionType == "call");

    double strike = strikeSpin->value();
    double notional = notionalSpin->value();
    double maxPayoutPercent = maxPayoutSpin->value();
    double premiumPercent = premiumSpin->value();

    double longDelivers, shortDelivers, longIm, shortIm;
    double maxPayoutAmount = (maxPayoutPercent / 100.0) * notional;
    double premiumAmount = (premiumPercent / 100.0) * notional;

    if (isCall) {
        // Call: long delivers base, short delivers quote
        longDelivers = notional * strike;
        shortDelivers = notional;
        longIm = 0.00000001;  // Buyer (long) posts minimal
        shortIm = maxPayoutAmount;  // Seller (short) posts max payout
    } else {
        // Put: short delivers base, long delivers quote
        shortDelivers = notional * strike;
        longDelivers = notional;
        shortIm = 0.00000001;  // Buyer (short) posts minimal
        longIm = maxPayoutAmount;  // Seller (long) posts max payout
    }

    advLongDeliverySpin->setValue(longDelivers);
    advShortDeliverySpin->setValue(shortDelivers);
    advLongImSpin->setValue(longIm);
    advShortImSpin->setValue(shortIm);
    advPremiumAmountSpin->setValue(premiumAmount);

    advLongDeliverySpin->blockSignals(false);
    advShortDeliverySpin->blockSignals(false);
    advLongImSpin->blockSignals(false);
    advShortImSpin->blockSignals(false);
    advPremiumAmountSpin->blockSignals(false);
}

void OptionTermSheetPage::onShowAdvancedEditor(bool checked)
{
    advancedEditorWidget->setVisible(checked);

    if (checked) {
        // Populate advanced fields with current auto-calculated values
        updateAdvancedFields();
    }
}

void OptionTermSheetPage::onAdvancedFieldChanged()
{
    // User has manually modified advanced fields, so disable auto-update
    advancedModeActive = true;
}

void OptionTermSheetPage::onDirectionChanged(int) { updateForwardPreview(); }
void OptionTermSheetPage::onOptionTypeChanged(int) { updateForwardPreview(); }
void OptionTermSheetPage::onBaseAssetChanged(int index)
{
    Q_UNUSED(index);
    QString assetId = getAssetIdFromCombo(baseAssetCombo);
    // getAssetIdFromCombo returns empty for native, so use isEmpty() check
    if (!assetId.isEmpty()) {
        baseAssetIdEdit->setText(assetId);
    } else {
        baseAssetIdEdit->clear();
    }
    applySpinBoxDecimals(strikeSpin, getAssetDecimals(baseAssetCombo));
    applySpinBoxDecimals(notionalSpin, getAssetDecimals(baseAssetCombo));
    updateForwardPreview();
}
void OptionTermSheetPage::onQuoteAssetChanged(int index)
{
    Q_UNUSED(index);
    QString assetId = getAssetIdFromCombo(quoteAssetCombo);
    // getAssetIdFromCombo returns empty for native, so use isEmpty() check
    if (!assetId.isEmpty()) {
        quoteAssetIdEdit->setText(assetId);
    } else {
        quoteAssetIdEdit->clear();
    }
    updateForwardPreview();
}
void OptionTermSheetPage::onStrikeChanged(double) { updateForwardPreview(); }
void OptionTermSheetPage::onNotionalChanged(double) { updateForwardPreview(); }
void OptionTermSheetPage::onMaxPayoutChanged(double) { updateForwardPreview(); }
void OptionTermSheetPage::onPremiumChanged(double) { updateForwardPreview(); }
void OptionTermSheetPage::onExpiryChanged(int) { updateForwardPreview(); }
void OptionTermSheetPage::onExpiryUnitChanged(int) { updateForwardPreview(); }

void OptionTermSheetPage::onGenerateDestinationAddresses()
{
    auto* wizardPtr = qobject_cast<ForwardContractBuilder*>(wizard());
    WalletModel* walletModel = wizardPtr ? wizardPtr->getWalletModel() : nullptr;
    if (!walletModel) return;

    if (marginDestEdit->text().isEmpty()) {
        QString address = walletModel->getNewAddress("bech32m");
        if (!address.isEmpty()) {
            marginDestEdit->setText(address);
        }
    }

    if (settlementDestEdit->text().isEmpty()) {
        QString address = walletModel->getNewAddress("bech32m");
        if (!address.isEmpty()) {
            settlementDestEdit->setText(address);
        }
    }

    if (premiumDestEdit->text().isEmpty()) {
        QString address = walletModel->getNewAddress("bech32m");
        if (!address.isEmpty()) {
            premiumDestEdit->setText(address);
        }
    }
}

void OptionTermSheetPage::updateOptionPricing()
{
    auto* wizardPtr = qobject_cast<ForwardContractBuilder*>(wizard());
    WalletModel* walletModel = wizardPtr ? wizardPtr->getWalletModel() : nullptr;

    if (!walletModel) {
        // Reset all labels to "--"
        pvReceiveLabel->setText(tr("--"));
        pvPayLabel->setText(tr("--"));
        netSpreadLabel->setText(tr("--"));
        premiumPvLabel->setText(tr("--"));
        aliceShortCallLabel->setText(tr("--"));
        aliceLongPutLabel->setText(tr("--"));
        aliceMtmLabel->setText(tr("--"));
        bobMtmLabel->setText(tr("--"));
        imCoverageAliceLabel->setText(tr("--"));
        imCoverageBobLabel->setText(tr("--"));
        pvReceivePerNotionalLabel->setText(tr("--"));
        pvPayPerNotionalLabel->setText(tr("--"));
        netSpreadPerNotionalLabel->setText(tr("--"));
        premiumPvPerNotionalLabel->setText(tr("--"));
        aliceShortCallPerNotionalLabel->setText(tr("--"));
        aliceLongPutPerNotionalLabel->setText(tr("--"));
        aliceMtmPerNotionalLabel->setText(tr("--"));
        bobMtmPerNotionalLabel->setText(tr("--"));
        imCoverageAlicePerNotionalLabel->setText(tr("--"));
        imCoverageBobPerNotionalLabel->setText(tr("--"));
        return;
    }

    try {
        // First, convert option parameters to forward parameters (this populates hidden fields)
        // We need this to call the pricing RPC
        const_cast<OptionTermSheetPage*>(this)->convertToForwardParams();

        // Extract forward parameters from the conversion
        QString direction = directionCombo->currentData().toString();
        QString optionType = optionTypeCombo->currentData().toString();
        QString baseAssetId = getAssetIdFromCombo(baseAssetCombo);
        bool baseIsNative = isNativeAsset(baseAssetCombo);
        QString quoteAssetId = getAssetIdFromCombo(quoteAssetCombo);
        bool quoteIsNative = isNativeAsset(quoteAssetCombo);
        double strike = strikeSpin->value();
        double notional = notionalSpin->value();
        double maxPayout = maxPayoutSpin->value();
        double premium = premiumSpin->value();
        int expiryPeriod = expirySpin->value();
        QString expiryUnit = expiryUnitCombo->currentData().toString();
        int deliveryGap = deliveryGapSpin->value();

        // Calculate long and short delivery amounts based on option structure
        double longDeliverAmount;
        double shortDeliverAmount;
        QString longDeliverAsset;
        QString shortDeliverAsset;
        bool longDeliverIsNative;
        bool shortDeliverIsNative;

        if (optionType == "call") {
            // Call: long delivers quote, short delivers base
            longDeliverAmount = notional * strike * (maxPayout / 100.0);
            shortDeliverAmount = notional * (maxPayout / 100.0);
            longDeliverAsset = quoteAssetId;
            shortDeliverAsset = baseAssetId;
            longDeliverIsNative = quoteIsNative;
            shortDeliverIsNative = baseIsNative;
        } else {
            // Put: long delivers base, short delivers quote
            longDeliverAmount = notional * (maxPayout / 100.0);
            shortDeliverAmount = notional * strike * (maxPayout / 100.0);
            longDeliverAsset = baseAssetId;
            shortDeliverAsset = quoteAssetId;
            longDeliverIsNative = baseIsNative;
            shortDeliverIsNative = quoteIsNative;
        }

        // Calculate initial margins (10% of notional for both parties)
        double longImAmount = notional * 0.1;
        double shortImAmount = notional * 0.1;

        // Calculate premium amount
        double premiumAmount = notional * (premium / 100.0);

        // Calculate deadline heights
        int currentHeight = wizardPtr->walletModel->getNumBlocks();
        int maturityBlocks = 0;
        if (expiryUnit == "days") {
            maturityBlocks = expiryPeriod * 144;
        } else if (expiryUnit == "weeks") {
            maturityBlocks = expiryPeriod * 7 * 144;
        } else if (expiryUnit == "months") {
            maturityBlocks = expiryPeriod * 30 * 144;
        } else {
            maturityBlocks = expiryPeriod * 365 * 144;
        }
        int deadlineShort = currentHeight + maturityBlocks;
        int deadlineLong = deadlineShort + deliveryGap;

        // Build inline_terms for the RPC call - MUST use correct field names and SATOSHI units (×1e8)
        QVariantMap inlineTerms;
        inlineTerms["long_party_deliver_units"] = static_cast<qint64>(longDeliverAmount * 1e8);
        inlineTerms["long_party_deliver_asset"] = longDeliverAsset.isEmpty() ? "" : longDeliverAsset;
        inlineTerms["long_party_deliver_is_native"] = longDeliverIsNative;
        inlineTerms["short_party_deliver_units"] = static_cast<qint64>(shortDeliverAmount * 1e8);
        inlineTerms["short_party_deliver_asset"] = shortDeliverAsset.isEmpty() ? "" : shortDeliverAsset;
        inlineTerms["short_party_deliver_is_native"] = shortDeliverIsNative;
        inlineTerms["long_party_margin_units"] = static_cast<qint64>(longImAmount * 1e8);
        inlineTerms["long_party_margin_asset"] = baseAssetId.isEmpty() ? "" : baseAssetId;
        inlineTerms["long_party_margin_is_native"] = baseIsNative;
        inlineTerms["short_party_margin_units"] = static_cast<qint64>(shortImAmount * 1e8);
        inlineTerms["short_party_margin_asset"] = baseAssetId.isEmpty() ? "" : baseAssetId;
        inlineTerms["short_party_margin_is_native"] = baseIsNative;
        inlineTerms["premium_units"] = static_cast<qint64>(premiumAmount * 1e8);
        inlineTerms["premium_asset"] = baseAssetId.isEmpty() ? "" : baseAssetId;
        inlineTerms["premium_is_native"] = baseIsNative;
        inlineTerms["deadline_short"] = deadlineShort;
        inlineTerms["deadline_long"] = deadlineLong;
        inlineTerms["safety_k"] = 3;  // Default safety buffer

        // Call pricingForwardQuote RPC
        auto result = walletModel->pricingForwardQuote(
            "inline",
            "",
            inlineTerms,
            "",
            true,
            true   // compute_greeks
        );

        // Get decimals for display and convert from satoshis
        int reportDecimals = 8;
        const double toDisplayUnits = 1.0 / std::pow(10.0, reportDecimals);

        // Update absolute value labels (convert from satoshis to display units)
        pvReceiveLabel->setText(QString("%1 TSC").arg(result.pv_receive * toDisplayUnits, 0, 'f', 8));
        pvPayLabel->setText(QString("%1 TSC").arg(result.pv_pay * toDisplayUnits, 0, 'f', 8));
        netSpreadLabel->setText(QString("%1 TSC").arg(result.net_spread_value * toDisplayUnits, 0, 'f', 8));
        premiumPvLabel->setText(QString("%1 TSC").arg(result.premium_pv * toDisplayUnits, 0, 'f', 8));
        aliceShortCallLabel->setText(QString("%1 TSC").arg(result.alice_short_call_value * toDisplayUnits, 0, 'f', 8));
        aliceLongPutLabel->setText(QString("%1 TSC").arg(result.alice_long_put_value * toDisplayUnits, 0, 'f', 8));

        // MTM values with color coding
        auto formatMtm = [toDisplayUnits](double value) -> QString {
            double displayValue = value * toDisplayUnits;
            QString color = displayValue >= 0 ? "#4caf50" : "#f44336";
            QString prefix = displayValue > 0 ? "+" : "";
            return QString("<span style='color: %1;'>%2%3 TSC</span>").arg(color).arg(prefix).arg(displayValue, 0, 'f', 8);
        };

        aliceMtmLabel->setText(formatMtm(result.alice_mtm));
        bobMtmLabel->setText(formatMtm(result.bob_mtm));

        imCoverageAliceLabel->setText(QString("%1%").arg(result.im_coverage_alice * 100.0, 0, 'f', 2));
        imCoverageBobLabel->setText(QString("%1%").arg(result.im_coverage_bob * 100.0, 0, 'f', 2));

        // Update per-notional labels
        double notionalDivisor = std::max(0.00000001, notional);
        pvReceivePerNotionalLabel->setText(QString("%1").arg((result.pv_receive * toDisplayUnits) / notionalDivisor, 0, 'f', 6));
        pvPayPerNotionalLabel->setText(QString("%1").arg((result.pv_pay * toDisplayUnits) / notionalDivisor, 0, 'f', 6));
        netSpreadPerNotionalLabel->setText(QString("%1").arg((result.net_spread_value * toDisplayUnits) / notionalDivisor, 0, 'f', 6));
        premiumPvPerNotionalLabel->setText(QString("%1").arg((result.premium_pv * toDisplayUnits) / notionalDivisor, 0, 'f', 6));
        aliceShortCallPerNotionalLabel->setText(QString("%1").arg((result.alice_short_call_value * toDisplayUnits) / notionalDivisor, 0, 'f', 6));
        aliceLongPutPerNotionalLabel->setText(QString("%1").arg((result.alice_long_put_value * toDisplayUnits) / notionalDivisor, 0, 'f', 6));

        double aliceMtmDisplay = result.alice_mtm * toDisplayUnits;
        double bobMtmDisplay = result.bob_mtm * toDisplayUnits;
        QString aliceColor = aliceMtmDisplay >= 0 ? "#4caf50" : "#f44336";
        QString bobColor = bobMtmDisplay >= 0 ? "#4caf50" : "#f44336";
        aliceMtmPerNotionalLabel->setText(QString("<span style='color: %1;'>%2</span>").arg(aliceColor).arg(aliceMtmDisplay / notionalDivisor, 0, 'f', 6));
        bobMtmPerNotionalLabel->setText(QString("<span style='color: %1;'>%2</span>").arg(bobColor).arg(bobMtmDisplay / notionalDivisor, 0, 'f', 6));

        imCoverageAlicePerNotionalLabel->setText(QString("%1%").arg(result.im_coverage_alice * 100.0, 0, 'f', 2));
        imCoverageBobPerNotionalLabel->setText(QString("%1%").arg(result.im_coverage_bob * 100.0, 0, 'f', 2));

    } catch (const std::exception& e) {
        LogPrintf("OptionTermSheetPage::updateOptionPricing: Exception: %s\n", e.what());
        // Reset to "--" on error
        pvReceiveLabel->setText(tr("--"));
        pvPayLabel->setText(tr("--"));
        netSpreadLabel->setText(tr("--"));
        premiumPvLabel->setText(tr("--"));
        aliceShortCallLabel->setText(tr("--"));
        aliceLongPutLabel->setText(tr("--"));
        aliceMtmLabel->setText(tr("--"));
        bobMtmLabel->setText(tr("--"));
        imCoverageAliceLabel->setText(tr("--"));
        imCoverageBobLabel->setText(tr("--"));
        pvReceivePerNotionalLabel->setText(tr("--"));
        pvPayPerNotionalLabel->setText(tr("--"));
        netSpreadPerNotionalLabel->setText(tr("--"));
        premiumPvPerNotionalLabel->setText(tr("--"));
        aliceShortCallPerNotionalLabel->setText(tr("--"));
        aliceLongPutPerNotionalLabel->setText(tr("--"));
        aliceMtmPerNotionalLabel->setText(tr("--"));
        bobMtmPerNotionalLabel->setText(tr("--"));
        imCoverageAlicePerNotionalLabel->setText(tr("--"));
        imCoverageBobPerNotionalLabel->setText(tr("--"));
    }
}
