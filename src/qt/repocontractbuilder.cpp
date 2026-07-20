// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <qt/repocontractbuilder.h>
#include <qt/walletmodel.h>
#include <qt/guiutil.h>
#include <qt/themehelpers.h>
#include <qt/tormanager.h>
#include <qt/greeksvisualizationdialog.h>
#include <logging.h>

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
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
#include <QWidget>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTimer>
#include <QFrame>
#include <cmath>

// ============================================================================
// RepoContractBuilder
// ============================================================================

RepoContractBuilder::RepoContractBuilder(WalletModel* model, QWidget* parent)
    : ContractWizard(model, parent)
{
    setWindowTitle(tr("Repo Contract Builder"));

    // Set minimum size and make resizable
    setMinimumSize(900, 700);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);

    // Add pages
    setPage(Page_TermSheet, new RepoTermSheetPage(this));
    setPage(Page_Review, new RepoReviewPage(this, this));

    setStartId(Page_TermSheet);
}

RepoContractBuilder::~RepoContractBuilder()
{
}

void RepoContractBuilder::accept()
{
    // Update transport from wizard field before accepting
    QString selectedTransport = field("transport").toString();
    setTransport(selectedTransport);
    LogPrintf("RepoContractBuilder: Setting transport to '%s' from wizard field\n",
             selectedTransport.toStdString().c_str());

    QWizard::accept();
}

bool RepoContractBuilder::validateTerms()
{
    // Validate that all required fields are set
    // This is called by the term sheet page before proceeding to review

    if (field("collateralAmount").toDouble() <= 0) {
        QMessageBox::warning(this, tr("Validation Error"),
            tr("Collateral amount must be greater than zero."));
        return false;
    }

    if (field("principalAmount").toDouble() <= 0) {
        QMessageBox::warning(this, tr("Validation Error"),
            tr("Principal amount must be greater than zero."));
        return false;
    }

    // For bulletin board term sheets, only require maker's own address
    bool isLender = field("isLender").toBool();
    QString borrowerAddr = field("borrowerAddress").toString();
    QString lenderAddr = field("lenderAddress").toString();

    if (isLender) {
        // Maker is lender - require lender address, borrower is optional (bulletin board flow)
        if (lenderAddr.isEmpty()) {
            QMessageBox::warning(this, tr("Validation Error"),
                tr("Lender receive address is required."));
            return false;
        }
    } else {
        // Maker is borrower - require borrower address, lender is optional (bulletin board flow)
        if (borrowerAddr.isEmpty()) {
            QMessageBox::warning(this, tr("Validation Error"),
                tr("Borrower repay address is required."));
            return false;
        }
    }

    return true;
}

bool RepoContractBuilder::createOffer()
{
    try {
        if (!walletModel) {
            QMessageBox::critical(this, tr("Error"), tr("Wallet model not available"));
            return false;
        }

        // Build terms map from wizard fields
        QVariantMap terms;

        // Role
        terms["role"] = field("isLender").toBool() ? "lender" : "borrower";

        // Collateral - read directly from the term sheet page to avoid field binding issues
        RepoTermSheetPage* ts = qobject_cast<RepoTermSheetPage*>(page(Page_TermSheet));
        bool collateralIsNative = ts ? ts->collateralIsNative() : field("collateralIsNative").toBool();
        QString collateralAssetId = ts ? ts->collateralAssetId() : field("collateralAssetId").toString();
        // Note: accessor methods already return empty QString for native, so no override needed

        LogPrintf("[createOffer] Collateral: isNative=%d, assetId=%s\n", collateralIsNative, collateralAssetId.toStdString());

        terms["collateral_is_native"] = collateralIsNative;
        if (!collateralIsNative && !collateralAssetId.isEmpty()) {
            terms["collateral_asset_id"] = collateralAssetId;
        }
        terms["collateral_amount"] = field("collateralAmount").toDouble();

        // Principal - read directly from the term sheet page
        bool principalIsNative = ts ? ts->principalIsNative() : field("principalIsNative").toBool();
        QString principalAssetId = ts ? ts->principalAssetId() : field("principalAssetId").toString();
        // Note: accessor methods already return empty QString for native, so no override needed

        LogPrintf("[createOffer] Principal: isNative=%d, assetId=%s\n", principalIsNative, principalAssetId.toStdString());

        terms["principal_is_native"] = principalIsNative;
        if (!principalIsNative && !principalAssetId.isEmpty()) {
            terms["principal_asset_id"] = principalAssetId;
        }
        double principalAmount = field("principalAmount").toDouble();
        terms["principal_amount"] = principalAmount;

        // Interest - read directly from the term sheet page
        bool interestIsNative = ts ? ts->interestIsNative() : field("interestIsNative").toBool();
        QString interestAssetId = ts ? ts->interestAssetId() : field("interestAssetId").toString();
        // Note: accessor methods already return empty QString for native, so no override needed

        LogPrintf("[createOffer] Interest: isNative=%d, assetId=%s\n", interestIsNative, interestAssetId.toStdString());

        terms["interest_is_native"] = interestIsNative;
        if (!interestIsNative && !interestAssetId.isEmpty()) {
            terms["interest_asset_id"] = interestAssetId;
        }

        // Get maturity period for interest calculation and block height calculation
        double interestRate = field("interestRate").toDouble();
        int maturityPeriod = field("maturityPeriod").toInt();
        QString maturityUnit = field("maturityUnit").toString();

        // Calculate interest amount from rate + time period
        double days = maturityPeriod;
        if (maturityUnit == "weeks") {
            days = maturityPeriod * 7.0;
        } else if (maturityUnit == "months") {
            days = maturityPeriod * 30.0;
        } else if (maturityUnit == "years") {
            days = maturityPeriod * 365.0;
        }

        double interestAmount = principalAmount * (interestRate / 100.0) * (days / 365.0);
        terms["interest_amount"] = interestAmount;

        // Calculate maturity height: use absolute if enabled, otherwise calculate from period
        int maturityHeight;
        if (field("useAbsoluteHeight").toBool()) {
            maturityHeight = field("absoluteHeight").toInt();
        } else {
            int currentHeight = walletModel->getNumBlocks();
            int blocks = 0;
            if (maturityUnit == "days") {
                blocks = maturityPeriod * 144;
            } else if (maturityUnit == "weeks") {
                blocks = maturityPeriod * 7 * 144;
            } else if (maturityUnit == "months") {
                blocks = maturityPeriod * 30 * 144;
            } else if (maturityUnit == "years") {
                blocks = maturityPeriod * 365 * 144;
            }
            maturityHeight = currentHeight + blocks;
        }
        terms["maturity_height"] = maturityHeight;
        terms["safety_buffer"] = field("safetyBuffer").toInt();

        // Addresses (may be empty for bulletin-board draft)
        QString borrowerAddress = ts ? ts->borrowerAddress() : field("borrowerAddress").toString();
        QString lenderAddress = ts ? ts->lenderAddress() : field("lenderAddress").toString();
        terms["borrower_address"] = borrowerAddress;
        terms["lender_address"] = lenderAddress;

        // Fee policy
        terms["fee_policy"] = field("feePolicy").toString();

        // Build term sheet JSON (always available)
        QJsonObject termSheet;
        termSheet["schema"] = QStringLiteral("repo_term_sheet_v1");
        termSheet["maker_role"] = terms["role"].toString();
        termSheet["lender_address"] = lenderAddress;

        QJsonObject termsJson = QJsonObject::fromVariantMap(terms);
        termSheet["terms"] = termsJson;

        // Basic metrics for UI/search
        double apr = 0.0;
        if (principalAmount > 0.0 && days > 0.0) {
            apr = (interestAmount / principalAmount) * (365.0 / days) * 100.0;
        }

        double ltv = 0.0;
        double collateralAmount = field("collateralAmount").toDouble();
        if (collateralAmount > 0.0 && principalAmount > 0.0) {
            ltv = (principalAmount / collateralAmount) * 100.0;
        }

        QJsonObject metricsJson;
        metricsJson["apr_percent"] = apr;
        metricsJson["ltv_percent"] = ltv;
        metricsJson["tenor_days"] = days;
        termSheet["metrics"] = metricsJson;

        termSheetJson = QString::fromUtf8(QJsonDocument(termSheet).toJson(QJsonDocument::Compact));

        // Populate offerData with term sheet values (used by review/result dialog)
        offerData = terms;
        offerData["apr_percent"] = apr;
        offerData["ltv_percent"] = ltv;
        offerData["tenor_days"] = days;
        offerData["term_sheet_json"] = termSheetJson;

        // Determine whether we have sufficient information to build a finalized offer
        offerFinalized = false;
        offerId.clear();
        offerJson.clear();

        // For bulletin board flow: DO NOT call RPC yet
        // Generate local offer ID for tracking
        // The actual repo.propose RPC will be called when:
        // 1. Counterparty accepts the offer via bulletin board
        // 2. Their address is received
        // 3. The complete terms are then registered via repo.propose
        offerId = QString::number(QDateTime::currentMSecsSinceEpoch());
        offerJson = termSheetJson;
        offerData = terms;
        offerData["role"] = terms["role"];
        offerData["apr_percent"] = apr;
        offerData["ltv_percent"] = ltv;
        offerData["tenor_days"] = days;
        offerData["term_sheet_json"] = termSheetJson;
        offerData["offer_id"] = offerId;
        offerData["bulletin_board_pending"] = true;  // Flag for bulletin board flow
        offerFinalized = true;

        return true;

    } catch (const std::exception& e) {
        QMessageBox::critical(this, tr("Error"), tr("Exception occurred: %1").arg(QString::fromStdString(e.what())));
        return false;
    } catch (...) {
        QMessageBox::critical(this, tr("Error"), tr("Unknown exception occurred while creating offer"));
        return false;
    }
}

// ============================================================================
// RepoTermSheetPage
// ============================================================================

RepoTermSheetPage::RepoTermSheetPage(QWidget* parent)
    : QWizardPage(parent)
{
    setTitle(tr("Repo Contract Builder"));

    setupUI();
}

bool RepoTermSheetPage::collateralIsNative() const
{
    return isNativeAsset(collateralAssetCombo);
}

QString RepoTermSheetPage::collateralAssetId() const
{
    return isNativeAsset(collateralAssetCombo) ? QString() : getAssetIdFromCombo(collateralAssetCombo);
}

bool RepoTermSheetPage::principalIsNative() const
{
    return isNativeAsset(principalAssetCombo);
}

QString RepoTermSheetPage::principalAssetId() const
{
    return isNativeAsset(principalAssetCombo) ? QString() : getAssetIdFromCombo(principalAssetCombo);
}

bool RepoTermSheetPage::interestIsNative() const
{
    return isNativeAsset(interestAssetCombo);
}

QString RepoTermSheetPage::interestAssetId() const
{
    return isNativeAsset(interestAssetCombo) ? QString() : getAssetIdFromCombo(interestAssetCombo);
}

QString RepoTermSheetPage::borrowerAddress() const
{
    return borrowerAddressEdit ? borrowerAddressEdit->text() : QString();
}

QString RepoTermSheetPage::lenderAddress() const
{
    return lenderAddressEdit ? lenderAddressEdit->text() : QString();
}

void RepoTermSheetPage::setupUI()
{
    // Create scroll area for content
    QScrollArea* scrollArea = new QScrollArea(this);
    scrollArea->setWidgetResizable(true);
    scrollArea->setFrameShape(QFrame::NoFrame);

    // Create container widget for all form content
    QWidget* container = new QWidget();
    QVBoxLayout* mainLayout = new QVBoxLayout(container);

    // Role Selection
    QGroupBox* roleGroupBox = new QGroupBox(tr("Your Role"), this);
    QHBoxLayout* roleLayout = new QHBoxLayout(roleGroupBox);

    roleGroup = new QButtonGroup(this);
    lenderRadio = new QRadioButton(tr("Lender (providing principal)"), this);
    borrowerRadio = new QRadioButton(tr("Borrower (providing collateral)"), this);

    lenderRadio->setChecked(true);

    roleGroup->addButton(lenderRadio, 0);
    roleGroup->addButton(borrowerRadio, 1);

    roleLayout->addWidget(lenderRadio);
    roleLayout->addWidget(borrowerRadio);
    roleGroupBox->setLayout(roleLayout);

    mainLayout->addWidget(roleGroupBox);

    // Connect both radio buttons to emit the roleChanged signal
    connect(lenderRadio, &QRadioButton::toggled, this, &RepoTermSheetPage::onRoleChanged);
    connect(borrowerRadio, &QRadioButton::toggled, this, &RepoTermSheetPage::onRoleChanged);

    // Register button group as field - this properly tracks which button is selected
    registerField("isLender*", this, "isLenderRole", SIGNAL(roleChanged()));

    // Collateral Section - Single line
    QGroupBox* collateralGroup = new QGroupBox(tr("Collateral Leg"), this);
    QHBoxLayout* collateralLayout = new QHBoxLayout(collateralGroup);

    collateralLayout->addWidget(new QLabel(tr("Amount:"), this));
    collateralAmountSpin = new QDoubleSpinBox(this);
    collateralAmountSpin->setDecimals(8);
    collateralAmountSpin->setMaximum(21000000.0);
    collateralAmountSpin->setMinimum(0.00000001);
    collateralAmountSpin->setValue(2.0);
    collateralLayout->addWidget(collateralAmountSpin);
    connect(collateralAmountSpin, QOverload<double>::of(&QDoubleSpinBox::valueChanged),
            this, &RepoTermSheetPage::onCollateralAmountChanged);

    collateralAssetCombo = new QComboBox(this);
    collateralAssetCombo->setMinimumWidth(200);
    // Populate later in initializePage() when wizard() is available
    collateralLayout->addWidget(collateralAssetCombo);
    connect(collateralAssetCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &RepoTermSheetPage::onCollateralAssetChanged);

    collateralUnitLabel = new QLabel(tr("TSC"), this);
    collateralUnitLabel->setVisible(false); // Not needed on single line
    collateralLayout->addStretch();

    collateralGroup->setLayout(collateralLayout);
    mainLayout->addWidget(collateralGroup);

    // Hidden fields for asset metadata (set programmatically in validatePage)
    QCheckBox* collateralIsNativeCheck = new QCheckBox(this);
    collateralIsNativeCheck->setVisible(false);
    QLineEdit* collateralAssetIdEdit = new QLineEdit(this);
    collateralAssetIdEdit->setVisible(false);

    registerField("collateralIsNative", collateralIsNativeCheck);
    registerField("collateralAssetId", collateralAssetIdEdit);
    registerField("collateralAmount", collateralAmountSpin, "value");

    // Principal Section - Two lines
    QGroupBox* principalGroup = new QGroupBox(tr("Principal Leg"), this);
    QVBoxLayout* principalLayout = new QVBoxLayout(principalGroup);

    // Line 1: Asset and Price
    QHBoxLayout* principalLine1 = new QHBoxLayout();
    principalLine1->addWidget(new QLabel(tr("Asset:"), this));
    principalAssetCombo = new QComboBox(this);
    principalAssetCombo->setMinimumWidth(200);
    // Populate later in initializePage() when wizard() is available
    principalLine1->addWidget(principalAssetCombo);
    connect(principalAssetCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &RepoTermSheetPage::onPrincipalAssetChanged);

    principalLine1->addWidget(new QLabel(tr("  Price:"), this));
    collateralPriceSpin = new QDoubleSpinBox(this);
    collateralPriceSpin->setDecimals(8);
    collateralPriceSpin->setMaximum(10000000.0);
    collateralPriceSpin->setMinimum(0.00000001);
    collateralPriceSpin->setValue(1.0);
    principalLine1->addWidget(collateralPriceSpin);
    collateralPriceUnitLabel = new QLabel(tr("TSC per TSC"), this);
    principalLine1->addWidget(collateralPriceUnitLabel);
    connect(collateralPriceSpin, QOverload<double>::of(&QDoubleSpinBox::valueChanged),
            this, &RepoTermSheetPage::onCollateralPriceChanged);
    principalLine1->addStretch();
    principalLayout->addLayout(principalLine1);

    // Line 2: LTV and Calculated Principal
    QHBoxLayout* principalLine2 = new QHBoxLayout();
    principalLine2->addWidget(new QLabel(tr("LTV:"), this));
    ltvTargetSpin = new QDoubleSpinBox(this);
    ltvTargetSpin->setDecimals(2);
    ltvTargetSpin->setMaximum(100.0);
    ltvTargetSpin->setMinimum(1.0);
    ltvTargetSpin->setValue(80.0);
    ltvTargetSpin->setSuffix(tr(" %"));
    principalLine2->addWidget(ltvTargetSpin);
    connect(ltvTargetSpin, QOverload<double>::of(&QDoubleSpinBox::valueChanged),
            this, &RepoTermSheetPage::onLtvTargetChanged);

    principalLine2->addWidget(new QLabel(tr("  → Principal:"), this));
    principalAmountSpin = new QDoubleSpinBox(this);
    principalAmountSpin->setDecimals(8);
    principalAmountSpin->setReadOnly(true);
    principalAmountSpin->setButtonSymbols(QAbstractSpinBox::NoButtons);
    principalAmountSpin->setMaximum(1000000000.0);
    principalAmountSpin->setValue(1.60000000);
    principalAmountSpin->setStyleSheet(QStringLiteral("QDoubleSpinBox { font-weight: bold; color: %1; }").arg(ThemeHelpers::accentTextColor()));
    principalLine2->addWidget(principalAmountSpin);
    principalUnitLabel = new QLabel(tr("TSC"), this);
    principalLine2->addWidget(principalUnitLabel);
    principalLine2->addStretch();
    principalLayout->addLayout(principalLine2);

    principalGroup->setLayout(principalLayout);
    mainLayout->addWidget(principalGroup);

    // Hidden fields for asset metadata (set programmatically in validatePage)
    QCheckBox* principalIsNativeCheck = new QCheckBox(this);
    principalIsNativeCheck->setVisible(false);
    QLineEdit* principalAssetIdEdit = new QLineEdit(this);
    principalAssetIdEdit->setVisible(false);

    registerField("principalIsNative", principalIsNativeCheck);
    registerField("principalAssetId", principalAssetIdEdit);
    registerField("principalAmount", principalAmountSpin, "value");
    registerField("collateralPrice", collateralPriceSpin, "value");
    registerField("ltvTarget", ltvTargetSpin, "value");

    // Interest Section - Two lines
    QGroupBox* interestGroup = new QGroupBox(tr("Interest"), this);
    QVBoxLayout* interestLayout = new QVBoxLayout(interestGroup);

    // Line 1: Asset and Rate
    QHBoxLayout* interestLine1 = new QHBoxLayout();
    interestLine1->addWidget(new QLabel(tr("Asset:"), this));
    interestAssetCombo = new QComboBox(this);
    interestAssetCombo->setMinimumWidth(200);
    // Populate later in initializePage() when wizard() is available
    interestLine1->addWidget(interestAssetCombo);
    connect(interestAssetCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &RepoTermSheetPage::onInterestAssetChanged);

    interestLine1->addWidget(new QLabel(tr("  Rate:"), this));
    interestRateSpin = new QDoubleSpinBox(this);
    interestRateSpin->setDecimals(2);
    interestRateSpin->setMaximum(1000.0);
    interestRateSpin->setMinimum(0.01);
    interestRateSpin->setValue(5.0);
    interestRateSpin->setSuffix(tr(" % p.a."));
    interestLine1->addWidget(interestRateSpin);
    connect(interestRateSpin, QOverload<double>::of(&QDoubleSpinBox::valueChanged),
            this, &RepoTermSheetPage::onInterestRateChanged);
    interestLine1->addStretch();
    interestLayout->addLayout(interestLine1);

    // Line 2: Computed values
    QHBoxLayout* interestLine2 = new QHBoxLayout();
    interestLine2->addWidget(new QLabel(tr("→ Interest:"), this));
    interestAmountLabel = new QLabel(tr("0.00657534"), this);
    interestAmountLabel->setStyleSheet(ThemeHelpers::mutedLabelStyleSheet());
    interestLine2->addWidget(interestAmountLabel);
    interestUnitLabel = new QLabel(tr("TSC"), this);
    interestLine2->addWidget(interestUnitLabel);

    interestLine2->addWidget(new QLabel(tr("  → Repay:"), this));
    repayAmountLabel = new QLabel(tr("1.60657534 TSC"), this);
    repayAmountLabel->setStyleSheet("QLabel { font-weight: bold; color: #d32f2f; }");
    interestLine2->addWidget(repayAmountLabel);
    interestLine2->addStretch();
    interestLayout->addLayout(interestLine2);

    // Interest price (hidden unless interest asset differs from principal) - kept for compatibility
    interestPriceLabel = new QLabel(tr("Interest Asset Price:"), this);
    interestPriceLabel->setVisible(false);
    interestPriceSpin = new QDoubleSpinBox(this);
    interestPriceSpin->setDecimals(8);
    interestPriceSpin->setMaximum(10000000.0);
    interestPriceSpin->setMinimum(0.00000001);
    interestPriceSpin->setValue(1.0);
    interestPriceSpin->setVisible(false);
    interestPriceUnitLabel = new QLabel(tr("TSC per ASSET"), this);
    interestPriceUnitLabel->setVisible(false);
    connect(interestPriceSpin, QOverload<double>::of(&QDoubleSpinBox::valueChanged),
            this, &RepoTermSheetPage::onInterestRateChanged);

    interestGroup->setLayout(interestLayout);
    mainLayout->addWidget(interestGroup);

    // Hidden fields for asset metadata (set programmatically in validatePage)
    QCheckBox* interestIsNativeCheck = new QCheckBox(this);
    interestIsNativeCheck->setVisible(false);
    QLineEdit* interestAssetIdEdit = new QLineEdit(this);
    interestAssetIdEdit->setVisible(false);

    registerField("interestIsNative", interestIsNativeCheck);
    registerField("interestAssetId", interestAssetIdEdit);
    registerField("interestRate", interestRateSpin, "value");

    // Maturity Section - Two lines
    QGroupBox* maturityGroup = new QGroupBox(tr("Maturity"), this);
    QVBoxLayout* maturityLayout = new QVBoxLayout(maturityGroup);

    // Line 1: Inputs (period, safety, absolute height checkbox and value)
    QHBoxLayout* maturityLine1 = new QHBoxLayout();
    maturityLine1->addWidget(new QLabel(tr("Period:"), this));
    maturityPeriodSpin = new QSpinBox(this);
    maturityPeriodSpin->setMaximum(10000);
    maturityPeriodSpin->setMinimum(1);
    maturityPeriodSpin->setValue(30);
    maturityLine1->addWidget(maturityPeriodSpin);
    maturityUnitCombo = new QComboBox(this);
    maturityUnitCombo->addItem(tr("Days"), "days");
    maturityUnitCombo->addItem(tr("Weeks"), "weeks");
    maturityUnitCombo->addItem(tr("Months"), "months");
    maturityUnitCombo->addItem(tr("Years"), "years");
    maturityUnitCombo->setCurrentIndex(0); // Days by default
    maturityLine1->addWidget(maturityUnitCombo);
    connect(maturityPeriodSpin, QOverload<int>::of(&QSpinBox::valueChanged),
            this, &RepoTermSheetPage::onMaturityPeriodChanged);
    connect(maturityUnitCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &RepoTermSheetPage::onMaturityUnitChanged);

    maturityLine1->addWidget(new QLabel(tr("  Safety:"), this));
    safetyBufferSpin = new QSpinBox(this);
    safetyBufferSpin->setMaximum(100);
    safetyBufferSpin->setMinimum(0);
    safetyBufferSpin->setValue(2);
    safetyBufferSpin->setSuffix(tr(" blks"));
    maturityLine1->addWidget(safetyBufferSpin);

    useAbsoluteHeightCheck = new QCheckBox(tr("Absolute height"), this);
    maturityLine1->addWidget(useAbsoluteHeightCheck);
    absoluteHeightSpin = new QSpinBox(this);
    absoluteHeightSpin->setMaximum(999999999);
    absoluteHeightSpin->setMinimum(1);
    absoluteHeightSpin->setValue(1000);
    absoluteHeightSpin->setEnabled(false);
    maturityLine1->addWidget(absoluteHeightSpin);
    connect(useAbsoluteHeightCheck, &QCheckBox::toggled, this, [this](bool checked) {
        maturityPeriodSpin->setEnabled(!checked);
        maturityUnitCombo->setEnabled(!checked);
        absoluteHeightSpin->setEnabled(checked);
        if (checked) {
            targetHeightLabel->setText(QString::number(absoluteHeightSpin->value()));
        } else {
            onMaturityPeriodChanged(maturityPeriodSpin->value());
        }
    });
    connect(absoluteHeightSpin, QOverload<int>::of(&QSpinBox::valueChanged), this, [this](int value) {
        if (useAbsoluteHeightCheck->isChecked()) {
            targetHeightLabel->setText(QString::number(value));
        }
    });
    maturityLine1->addStretch();
    maturityLayout->addLayout(maturityLine1);

    // Line 2: Current and Target Heights
    QHBoxLayout* maturityLine2 = new QHBoxLayout();
    maturityLine2->addWidget(new QLabel(tr("Current:"), this));
    currentHeightLabel = new QLabel(tr("Loading..."), this);
    currentHeightLabel->setStyleSheet(ThemeHelpers::mutedLabelStyleSheet());
    maturityLine2->addWidget(currentHeightLabel);

    maturityLine2->addWidget(new QLabel(tr("  → Target:"), this));
    targetHeightLabel = new QLabel(tr("Calculating..."), this);
    targetHeightLabel->setStyleSheet(ThemeHelpers::accentLabelStyleSheet(/*bold=*/true));
    maturityLine2->addWidget(targetHeightLabel);
    maturityLine2->addStretch();
    maturityLayout->addLayout(maturityLine2);

    maturityGroup->setLayout(maturityLayout);
    mainLayout->addWidget(maturityGroup);

    registerField("maturityPeriod", maturityPeriodSpin);
    registerField("maturityUnit", maturityUnitCombo, "currentData");
    registerField("useAbsoluteHeight", useAbsoluteHeightCheck);
    registerField("absoluteHeight", absoluteHeightSpin);
    registerField("safetyBuffer", safetyBufferSpin);

    // Pricing Breakdown Section
    QGroupBox* pricingGroup = new QGroupBox(tr("Pricing Breakdown"), this);
    pricingGroup->setStyleSheet(ThemeHelpers::panelStyleSheet());
    QGridLayout* pricingLayout = new QGridLayout(pricingGroup);

    int pricingRow = 0;

    // Header row
    pricingLayout->addWidget(new QLabel(tr(""), this), pricingRow, 0);
    pricingLayout->addWidget(new QLabel(tr("Absolute"), this), pricingRow, 1);
    pricingLayout->addWidget(new QLabel(tr("Per Principal"), this), pricingRow, 2);
    pricingRow++;

    // Principal + Interest PV
    pricingLayout->addWidget(new QLabel(tr("Principal + Interest PV:"), this), pricingRow, 0);
    principalInterestPvLabel = new QLabel(tr("--"), this);
    principalInterestPvLabel->setStyleSheet(ThemeHelpers::accentLabelStyleSheet(/*bold=*/false));
    pricingLayout->addWidget(principalInterestPvLabel, pricingRow, 1);
    principalInterestPvPerPrincipalLabel = new QLabel(tr("--"), this);
    principalInterestPvPerPrincipalLabel->setStyleSheet(ThemeHelpers::accentLabelStyleSheet(/*bold=*/false));
    pricingLayout->addWidget(principalInterestPvPerPrincipalLabel, pricingRow++, 2);

    // Collateral PV
    pricingLayout->addWidget(new QLabel(tr("Collateral PV:"), this), pricingRow, 0);
    collateralPvLabel = new QLabel(tr("--"), this);
    collateralPvLabel->setStyleSheet(ThemeHelpers::accentLabelStyleSheet(/*bold=*/false));
    pricingLayout->addWidget(collateralPvLabel, pricingRow, 1);
    collateralPvPerPrincipalLabel = new QLabel(tr("--"), this);
    collateralPvPerPrincipalLabel->setStyleSheet(ThemeHelpers::accentLabelStyleSheet(/*bold=*/false));
    pricingLayout->addWidget(collateralPvPerPrincipalLabel, pricingRow++, 2);

    // Collateral Option Value
    pricingLayout->addWidget(new QLabel(tr("Collateral Option Value:"), this), pricingRow, 0);
    collateralOptionLabel = new QLabel(tr("--"), this);
    collateralOptionLabel->setStyleSheet(ThemeHelpers::accentLabelStyleSheet(/*bold=*/false));
    pricingLayout->addWidget(collateralOptionLabel, pricingRow, 1);
    collateralOptionPerPrincipalLabel = new QLabel(tr("--"), this);
    collateralOptionPerPrincipalLabel->setStyleSheet(ThemeHelpers::accentLabelStyleSheet(/*bold=*/false));
    pricingLayout->addWidget(collateralOptionPerPrincipalLabel, pricingRow++, 2);

    // Add separator
    QFrame* separator = new QFrame(this);
    separator->setFrameShape(QFrame::HLine);
    separator->setFrameShadow(QFrame::Sunken);
    pricingLayout->addWidget(separator, pricingRow++, 0, 1, 3);

    // Lender MTM
    pricingLayout->addWidget(new QLabel(tr("Lender MTM:"), this), pricingRow, 0);
    lenderMtmLabel = new QLabel(tr("--"), this);
    lenderMtmLabel->setStyleSheet("QLabel { font-weight: bold; }");
    pricingLayout->addWidget(lenderMtmLabel, pricingRow, 1);
    lenderMtmPerPrincipalLabel = new QLabel(tr("--"), this);
    lenderMtmPerPrincipalLabel->setStyleSheet("QLabel { font-weight: bold; }");
    pricingLayout->addWidget(lenderMtmPerPrincipalLabel, pricingRow++, 2);

    // Borrower MTM
    pricingLayout->addWidget(new QLabel(tr("Borrower MTM:"), this), pricingRow, 0);
    borrowerMtmLabel = new QLabel(tr("--"), this);
    borrowerMtmLabel->setStyleSheet("QLabel { font-weight: bold; }");
    pricingLayout->addWidget(borrowerMtmLabel, pricingRow, 1);
    borrowerMtmPerPrincipalLabel = new QLabel(tr("--"), this);
    borrowerMtmPerPrincipalLabel->setStyleSheet("QLabel { font-weight: bold; }");
    pricingLayout->addWidget(borrowerMtmPerPrincipalLabel, pricingRow++, 2);

    // Greeks button
    showGreeksButton = new QPushButton(tr("View Greeks"), this);
    showGreeksButton->setStyleSheet("QPushButton { background-color: #7c3aed; color: white; font-weight: bold; padding: 6px 12px; border-radius: 4px; } QPushButton:hover { background-color: #6d28d9; }");
    pricingLayout->addWidget(showGreeksButton, pricingRow++, 0, 1, 3);
    connect(showGreeksButton, &QPushButton::clicked, this, &RepoTermSheetPage::onShowGreeks);

    pricingGroup->setLayout(pricingLayout);
    mainLayout->addWidget(pricingGroup);

    // Create debounce timer for pricing updates
    pricingDebounceTimer = new QTimer(this);
    pricingDebounceTimer->setSingleShot(true);
    pricingDebounceTimer->setInterval(500); // 500ms debounce
    connect(pricingDebounceTimer, &QTimer::timeout, this, &RepoTermSheetPage::updatePricingBreakdown);

    // Addresses Section - Collapsible (Advanced)
    QGroupBox* addressGroup = new QGroupBox(tr("Addresses (Advanced)"), this);
    addressGroup->setCheckable(true);
    addressGroup->setChecked(false); // Hidden by default
    QGridLayout* addressLayout = new QGridLayout(addressGroup);

    addressLayout->addWidget(new QLabel(tr("Borrower Repay Address:"), this), 0, 0);
    borrowerAddressEdit = new QLineEdit(this);
    borrowerAddressEdit->setPlaceholderText(tr("bc1p..."));
    addressLayout->addWidget(borrowerAddressEdit, 0, 1);

    QWidget* borrowerActions = new QWidget(this);
    QVBoxLayout* borrowerActionLayout = new QVBoxLayout(borrowerActions);
    borrowerActionLayout->setContentsMargins(0, 0, 0, 0);
    borrowerActionLayout->setSpacing(4);

    generateBorrowerButton = new QPushButton(tr("Generate New"), this);
    borrowerActionLayout->addWidget(generateBorrowerButton);
    connect(generateBorrowerButton, &QPushButton::clicked,
            this, &RepoTermSheetPage::onGenerateBorrowerAddress);

    borrowerManualToggle = new QCheckBox(tr("Manual entry"), this);
    borrowerManualToggle->setToolTip(tr("Enable to enter the counterparty's borrower address manually."));
    borrowerManualToggle->setVisible(false);
    borrowerActionLayout->addWidget(borrowerManualToggle);
    connect(borrowerManualToggle, &QCheckBox::toggled,
            this, &RepoTermSheetPage::onBorrowerManualToggled);

    borrowerActionLayout->addStretch();
    addressLayout->addWidget(borrowerActions, 0, 2);

    addressLayout->addWidget(new QLabel(tr("Lender Receive Address:"), this), 1, 0);
    lenderAddressEdit = new QLineEdit(this);
    lenderAddressEdit->setPlaceholderText(tr("Will auto-generate if empty"));
    lenderAddressEdit->setToolTip(tr("Address where lender receives principal repayment. Auto-generated if left empty."));
    addressLayout->addWidget(lenderAddressEdit, 1, 1);

    QWidget* lenderActions = new QWidget(this);
    QVBoxLayout* lenderActionLayout = new QVBoxLayout(lenderActions);
    lenderActionLayout->setContentsMargins(0, 0, 0, 0);
    lenderActionLayout->setSpacing(4);

    generateLenderButton = new QPushButton(tr("Generate New"), this);
    generateLenderButton->setToolTip(tr("Generate a new address from your wallet"));
    lenderActionLayout->addWidget(generateLenderButton);
    connect(generateLenderButton, &QPushButton::clicked,
            this, &RepoTermSheetPage::onGenerateLenderAddress);

    lenderManualToggle = new QCheckBox(tr("Manual entry"), this);
    lenderManualToggle->setToolTip(tr("Enable to enter the counterparty's lender address manually."));
    lenderManualToggle->setVisible(false);
    lenderActionLayout->addWidget(lenderManualToggle);
    connect(lenderManualToggle, &QCheckBox::toggled,
            this, &RepoTermSheetPage::onLenderManualToggled);

    lenderActionLayout->addStretch();
    addressLayout->addWidget(lenderActions, 1, 2);

    connect(borrowerAddressEdit, &QLineEdit::textChanged, this, [this]() { Q_EMIT completeChanged(); });
    connect(lenderAddressEdit, &QLineEdit::textChanged, this, [this]() { Q_EMIT completeChanged(); });

    addressGroup->setLayout(addressLayout);
    mainLayout->addWidget(addressGroup);

    // Register address fields without mandatory marker - validation checks role-specific requirement
    registerField("borrowerAddress", borrowerAddressEdit);
    registerField("lenderAddress", lenderAddressEdit);

    // Fee Policy
    QGroupBox* feeGroup = new QGroupBox(tr("Fee Policy"), this);
    QHBoxLayout* feeLayout = new QHBoxLayout(feeGroup);

    feeLayout->addWidget(new QLabel(tr("Priority:"), this));
    feePolicyCombo = new QComboBox(this);
    feePolicyCombo->addItem(tr("Low Priority (~2 sat/vB)"), "low");
    feePolicyCombo->addItem(tr("Medium Priority (~10 sat/vB)"), "medium");
    feePolicyCombo->addItem(tr("High Priority (~50 sat/vB)"), "high");
    feePolicyCombo->setCurrentIndex(0); // Low by default
    feeLayout->addWidget(feePolicyCombo);
    feeLayout->addStretch();

    feeGroup->setLayout(feeLayout);
    mainLayout->addWidget(feeGroup);

    registerField("feePolicy", feePolicyCombo, "currentData");

    // Transport Selection
    QGroupBox* transportGroup = new QGroupBox(tr("Session Transport"), this);
    QVBoxLayout* transportLayout = new QVBoxLayout(transportGroup);

    QHBoxLayout* transportComboLayout = new QHBoxLayout();
    transportComboLayout->addWidget(new QLabel(tr("Protocol:"), this));
    transportCombo = new QComboBox(this);
    transportCombo->addItem(tr("Auto (Recommended)"), "auto");
    transportCombo->addItem(tr("WebSocket Relay"), "websocket");
    transportCombo->addItem(tr("Tor Hidden Service"), "tor");
    transportCombo->setCurrentIndex(0);
    transportCombo->setToolTip(tr("Choose how to establish secure bilateral sessions.\nAuto: Uses WebSocket for fast, reliable connections.\nWebSocket: Fast through central relay.\nTor: Maximum privacy, slower setup."));
    transportComboLayout->addWidget(transportCombo);
    transportComboLayout->addStretch();
    transportLayout->addLayout(transportComboLayout);

    // Tor status label (initially hidden)
    torStatusLabel = new QLabel(this);
    torStatusLabel->setWordWrap(true);
    torStatusLabel->setStyleSheet("QLabel { padding: 8px; border-radius: 4px; font-size: 11px; }");
    torStatusLabel->hide();
    transportLayout->addWidget(torStatusLabel);

    transportGroup->setLayout(transportLayout);
    mainLayout->addWidget(transportGroup);

    registerField("transport", transportCombo, "currentData");

    connect(transportCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &RepoTermSheetPage::onTransportChanged);

    mainLayout->addStretch();

    // Set the container widget in the scroll area
    scrollArea->setWidget(container);

    // Create page layout and add scroll area
    QVBoxLayout* pageLayout = new QVBoxLayout(this);
    pageLayout->setContentsMargins(0, 0, 0, 0);
    pageLayout->addWidget(scrollArea);
    setLayout(pageLayout);

    // Initialize calculations
    updateCalculations();

    // Set initial address field state based on default role (lender)
    onRoleChanged();

    // Connect pricing update triggers (debounced)
    connect(collateralAmountSpin, QOverload<double>::of(&QDoubleSpinBox::valueChanged),
            this, [this]() { pricingDebounceTimer->start(); });
    connect(collateralAssetCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, [this]() { pricingDebounceTimer->start(); });
    connect(principalAmountSpin, QOverload<double>::of(&QDoubleSpinBox::valueChanged),
            this, [this]() { pricingDebounceTimer->start(); });
    connect(principalAssetCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, [this]() { pricingDebounceTimer->start(); });
    connect(interestRateSpin, QOverload<double>::of(&QDoubleSpinBox::valueChanged),
            this, [this]() { pricingDebounceTimer->start(); });
    connect(interestAssetCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, [this]() { pricingDebounceTimer->start(); });
    connect(maturityPeriodSpin, QOverload<int>::of(&QSpinBox::valueChanged),
            this, [this]() { pricingDebounceTimer->start(); });
    connect(maturityUnitCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, [this]() { pricingDebounceTimer->start(); });
    connect(absoluteHeightSpin, QOverload<int>::of(&QSpinBox::valueChanged),
            this, [this]() { pricingDebounceTimer->start(); });
    connect(safetyBufferSpin, QOverload<int>::of(&QSpinBox::valueChanged),
            this, [this]() { pricingDebounceTimer->start(); });

    // Install wheel event filters to prevent accidental changes while scrolling
    GUIUtil::InstallWheelEventFilter(collateralAssetCombo);
    GUIUtil::InstallWheelEventFilter(collateralAmountSpin);
    GUIUtil::InstallWheelEventFilter(principalAssetCombo);
    GUIUtil::InstallWheelEventFilter(collateralPriceSpin);
    GUIUtil::InstallWheelEventFilter(ltvTargetSpin);
    GUIUtil::InstallWheelEventFilter(principalAmountSpin);
    GUIUtil::InstallWheelEventFilter(interestAssetCombo);
    GUIUtil::InstallWheelEventFilter(interestRateSpin);
    GUIUtil::InstallWheelEventFilter(interestPriceSpin);
    GUIUtil::InstallWheelEventFilter(maturityPeriodSpin);
    GUIUtil::InstallWheelEventFilter(maturityUnitCombo);
    GUIUtil::InstallWheelEventFilter(safetyBufferSpin);
    GUIUtil::InstallWheelEventFilter(feePolicyCombo);
}

void RepoTermSheetPage::initializePage()
{
    // Populate asset combos (wizard() is now available)
    if (collateralAssetCombo->count() == 0) {
        populateAssetComboBox(collateralAssetCombo, true);
    }
    if (principalAssetCombo->count() == 0) {
        populateAssetComboBox(principalAssetCombo, true);
    }
    if (interestAssetCombo->count() == 0) {
        populateAssetComboBox(interestAssetCombo, true);
    }

    // Update maturity height and calculations
    updateMaturityHeight();
    updateCalculations();

    // Auto-generate ONLY the maker's own address based on role
    bool isLender = lenderRadio->isChecked();
    if (isLender) {
        // Maker is lender - only generate lender address
        if (lenderAddressEdit->text().isEmpty()) {
            onGenerateLenderAddress();
        }
    } else {
        // Maker is borrower - only generate borrower address
        if (borrowerAddressEdit->text().isEmpty()) {
            onGenerateBorrowerAddress();
        }
    }
}

bool RepoTermSheetPage::validatePage()
{
    // Validate all fields before proceeding to review
    RepoContractBuilder* repoWizard = qobject_cast<RepoContractBuilder*>(wizard());
    if (!repoWizard) return false;

    // Store collateral asset info - use accessor methods that correctly return empty QString for native
    bool collNative = collateralIsNative();
    QString collAssetId = collateralAssetId();

    qDebug() << "[validatePage] Storing collateral asset fields:";
    qDebug() << "  Combo currentText:" << collateralAssetCombo->currentText();
    qDebug() << "  Combo currentData:" << collateralAssetCombo->currentData().toString();
    qDebug() << "  isNative:" << collNative;
    qDebug() << "  assetId:" << collAssetId;

    setField("collateralIsNative", collNative);
    setField("collateralAssetId", collAssetId);

    // Store principal asset info - use accessor methods that correctly return empty QString for native
    setField("principalIsNative", principalIsNative());
    setField("principalAssetId", principalAssetId());

    // Store interest asset info - use accessor methods that correctly return empty QString for native
    setField("interestIsNative", interestIsNative());
    setField("interestAssetId", interestAssetId());

    return repoWizard->validateTerms();
}

bool RepoTermSheetPage::isLenderRole() const
{
    return lenderRadio && lenderRadio->isChecked();
}

void RepoTermSheetPage::onRoleChanged()
{
    // Emit signal for Q_PROPERTY field registration
    Q_EMIT roleChanged();

    RepoContractBuilder* repoWizard = qobject_cast<RepoContractBuilder*>(wizard());
    WalletModel* model = repoWizard ? repoWizard->walletModel : nullptr;

    // Control address field visibility based on role
    bool isLender = lenderRadio->isChecked();

    if (isLender) {
        // Maker is LENDER - own address (lender) editable with generator
        lenderAddressEdit->setEnabled(true);
        lenderAddressEdit->setReadOnly(false);
        lenderAddressEdit->setPlaceholderText(tr("Will auto-generate if empty"));
        generateLenderButton->setVisible(true);
        generateLenderButton->setEnabled(true);
        lenderManualToggle->blockSignals(true);
        lenderManualToggle->setChecked(false);
        lenderManualToggle->setVisible(false);
        lenderManualToggle->blockSignals(false);

        // Counterparty (borrower) address hidden by default but manual entry available
        borrowerAddressEdit->setEnabled(false);
        borrowerAddressEdit->setReadOnly(true);
        borrowerAddressEdit->setPlaceholderText(tr("Will be provided by taker"));
        borrowerAddressEdit->clear();
        generateBorrowerButton->setVisible(false);
        generateBorrowerButton->setEnabled(false);
        borrowerManualToggle->blockSignals(true);
        borrowerManualToggle->setChecked(false);
        borrowerManualToggle->setVisible(true);
        borrowerManualToggle->setEnabled(true);
        borrowerManualToggle->blockSignals(false);

        if (lenderAddressEdit->text().isEmpty() && model) {
            onGenerateLenderAddress();
        }
    } else {
        // Maker is BORROWER - own address editable with generator
        borrowerAddressEdit->setEnabled(true);
        borrowerAddressEdit->setReadOnly(false);
        borrowerAddressEdit->setPlaceholderText(tr("bc1p..."));
        generateBorrowerButton->setVisible(true);
        generateBorrowerButton->setEnabled(true);
        borrowerManualToggle->blockSignals(true);
        borrowerManualToggle->setChecked(false);
        borrowerManualToggle->setVisible(false);
        borrowerManualToggle->blockSignals(false);

        // Counterparty (lender) address hidden by default but manual entry available
        lenderAddressEdit->setEnabled(false);
        lenderAddressEdit->setReadOnly(true);
        lenderAddressEdit->setPlaceholderText(tr("Will be provided by taker"));
        lenderAddressEdit->clear();
        generateLenderButton->setVisible(false);
        generateLenderButton->setEnabled(false);
        lenderManualToggle->blockSignals(true);
        lenderManualToggle->setChecked(false);
        lenderManualToggle->setVisible(true);
        lenderManualToggle->setEnabled(true);
        lenderManualToggle->blockSignals(false);

        if (borrowerAddressEdit->text().isEmpty() && model) {
            onGenerateBorrowerAddress();
        }
    }

    Q_EMIT completeChanged();
}

void RepoTermSheetPage::onCollateralAssetChanged(int index)
{
    // Update unit labels
    QString collateralAsset = collateralAssetCombo->currentText().split(" ").first();
    QString principalAsset = principalAssetCombo->currentText().split(" ").first();

    collateralUnitLabel->setText(collateralAsset);
    collateralPriceUnitLabel->setText(QString("%1 per %2").arg(principalAsset, collateralAsset));

    // Update decimals based on asset
    int decimals = getAssetDecimals(collateralAssetCombo);
    collateralAmountSpin->setDecimals(decimals);

    updateCalculations();
}

void RepoTermSheetPage::onPrincipalAssetChanged(int index)
{
    // Update unit labels
    QString principalAsset = principalAssetCombo->currentText().split(" ").first();
    QString collateralAsset = collateralAssetCombo->currentText().split(" ").first();

    principalUnitLabel->setText(principalAsset);
    collateralPriceUnitLabel->setText(QString("%1 per %2").arg(principalAsset, collateralAsset));

    // Update decimals based on asset
    int decimals = getAssetDecimals(principalAssetCombo);
    principalAmountSpin->setDecimals(decimals);
    collateralPriceSpin->setDecimals(decimals);

    updateCalculations();
}

void RepoTermSheetPage::onLtvTargetChanged(double value)
{
    updateCalculations();
}

void RepoTermSheetPage::onCollateralPriceChanged(double value)
{
    updateCalculations();
}

void RepoTermSheetPage::onCollateralAmountChanged(double value)
{
    updateCalculations();
}

void RepoTermSheetPage::onInterestAssetChanged(int index)
{
    QString interestAsset = interestAssetCombo->currentText().split(" ").first();
    QString principalAsset = principalAssetCombo->currentText().split(" ").first();

    // Show interest price field only if interest asset differs from principal
    bool needsPrice = (interestAsset != principalAsset);
    interestPriceLabel->setVisible(needsPrice);
    interestPriceSpin->setVisible(needsPrice);
    interestPriceUnitLabel->setVisible(needsPrice);

    if (needsPrice) {
        interestPriceUnitLabel->setText(QString("%1 per %2").arg(principalAsset, interestAsset));
    }

    // Update interest unit label
    interestUnitLabel->setText(interestAsset);

    updateCalculations();
}

void RepoTermSheetPage::onInterestRateChanged(double value)
{
    updateCalculations();
}

void RepoTermSheetPage::onMaturityPeriodChanged(int value)
{
    updateMaturityHeight();
    updateCalculations();
}

void RepoTermSheetPage::onMaturityUnitChanged(int index)
{
    updateMaturityHeight();
    updateCalculations();
}

void RepoTermSheetPage::updateCalculations()
{
    double collateralAmount = collateralAmountSpin->value();
    double collateralPrice = collateralPriceSpin->value();
    double ltvTarget = ltvTargetSpin->value();
    double interestRate = interestRateSpin->value();

    // Calculate collateral value = collateral × price
    double collateralValue = collateralAmount * collateralPrice;

    // Calculate principal = collateral value × (LTV / 100)
    double principal = collateralValue * (ltvTarget / 100.0);
    principalAmountSpin->setValue(principal);

    // Calculate interest amount = principal × (rate/100) × (days/365)
    // Get maturity period in days
    int period = maturityPeriodSpin->value();
    QString unit = maturityUnitCombo->currentData().toString();
    double days = period;
    if (unit == "weeks") {
        days = period * 7.0;
    } else if (unit == "months") {
        days = period * 30.0;
    } else if (unit == "years") {
        days = period * 365.0;
    }

    double interestAmount = principal * (interestRate / 100.0) * (days / 365.0);
    interestAmountLabel->setText(QString::number(interestAmount, 'f', 8));

    // Calculate repay amount only if interest is in same currency as principal
    QString interestAsset = interestAssetCombo->currentText().split(" ").first();
    QString principalAsset = principalAssetCombo->currentText().split(" ").first();

    if (interestAsset == principalAsset) {
        double repayAmount = principal + interestAmount;
        repayAmountLabel->setText(QString::number(repayAmount, 'f', 8) + " " + principalAsset);
    } else {
        repayAmountLabel->setText(QString::number(principal, 'f', 8) + " " + principalAsset +
                                  " + " + QString::number(interestAmount, 'f', 8) + " " + interestAsset);
    }
}

void RepoTermSheetPage::updateMaturityHeight()
{
    // Get current height from wallet/client model
    WalletModel* model = qobject_cast<RepoContractBuilder*>(wizard())->walletModel;
    if (!model) {
        targetHeightLabel->setText(tr("Error: No wallet"));
        return;
    }

    int currentHeight = model->getNumBlocks();
    currentHeightLabel->setText(QString::number(currentHeight));

    // Convert time period to blocks (assuming ~10 min blocks = 144 blocks/day)
    int period = maturityPeriodSpin->value();
    QString unit = maturityUnitCombo->currentData().toString();
    int blocks = 0;

    if (unit == "days") {
        blocks = period * 144;
    } else if (unit == "weeks") {
        blocks = period * 7 * 144;
    } else if (unit == "months") {
        blocks = period * 30 * 144;
    } else if (unit == "years") {
        blocks = period * 365 * 144;
    }

    int targetHeight = currentHeight + blocks;
    targetHeightLabel->setText(QString::number(targetHeight));
}

void RepoTermSheetPage::updatePricingBreakdown()
{
    // Get wallet model
    RepoContractBuilder* repoWizard = qobject_cast<RepoContractBuilder*>(wizard());
    if (!repoWizard || !repoWizard->walletModel) {
        // Reset all labels to "--"
        principalInterestPvLabel->setText(tr("--"));
        collateralPvLabel->setText(tr("--"));
        collateralOptionLabel->setText(tr("--"));
        lenderMtmLabel->setText(tr("--"));
        borrowerMtmLabel->setText(tr("--"));
        principalInterestPvPerPrincipalLabel->setText(tr("--"));
        collateralPvPerPrincipalLabel->setText(tr("--"));
        collateralOptionPerPrincipalLabel->setText(tr("--"));
        lenderMtmPerPrincipalLabel->setText(tr("--"));
        borrowerMtmPerPrincipalLabel->setText(tr("--"));
        return;
    }

    WalletModel* model = repoWizard->walletModel;

    // Build inline terms from current wizard fields
    QVariantMap inlineTerms;

    // Get collateral info
    QString collateralAssetId = getAssetIdFromCombo(collateralAssetCombo);
    bool collateralIsNative = isNativeAsset(collateralAssetCombo);
    inlineTerms["collateral_asset"] = collateralAssetId.isEmpty() ? "" : collateralAssetId;
    inlineTerms["collateral_is_native"] = collateralIsNative;
    inlineTerms["collateral_units"] = static_cast<qint64>(collateralAmountSpin->value() * 1e8);

    // Get principal info
    QString principalAssetId = getAssetIdFromCombo(principalAssetCombo);
    bool principalIsNative = isNativeAsset(principalAssetCombo);
    inlineTerms["principal_asset"] = principalAssetId.isEmpty() ? "" : principalAssetId;
    inlineTerms["principal_is_native"] = principalIsNative;
    inlineTerms["principal_units"] = static_cast<qint64>(principalAmountSpin->value() * 1e8);

    // Calculate interest amount
    double interestRate = interestRateSpin->value();
    int maturityPeriod = maturityPeriodSpin->value();
    QString maturityUnit = maturityUnitCombo->currentData().toString();

    double days = maturityPeriod;
    if (maturityUnit == "weeks") {
        days = maturityPeriod * 7.0;
    } else if (maturityUnit == "months") {
        days = maturityPeriod * 30.0;
    } else if (maturityUnit == "years") {
        days = maturityPeriod * 365.0;
    }

    double interestAmount = principalAmountSpin->value() * (interestRate / 100.0) * (days / 365.0);

    // Get interest info
    QString interestAssetId = getAssetIdFromCombo(interestAssetCombo);
    bool interestIsNative = isNativeAsset(interestAssetCombo);
    inlineTerms["interest_asset"] = interestAssetId.isEmpty() ? "" : interestAssetId;
    inlineTerms["interest_is_native"] = interestIsNative;
    inlineTerms["interest_units"] = static_cast<qint64>(interestAmount * 1e8);

    // Calculate maturity height
    int maturityHeight;
    if (useAbsoluteHeightCheck->isChecked()) {
        maturityHeight = absoluteHeightSpin->value();
    } else {
        int currentHeight = model->getNumBlocks();
        int blocks = 0;
        if (maturityUnit == "days") {
            blocks = maturityPeriod * 144;
        } else if (maturityUnit == "weeks") {
            blocks = maturityPeriod * 7 * 144;
        } else if (maturityUnit == "months") {
            blocks = maturityPeriod * 30 * 144;
        } else if (maturityUnit == "years") {
            blocks = maturityPeriod * 365 * 144;
        }
        maturityHeight = currentHeight + blocks;
    }
    inlineTerms["maturity_height"] = maturityHeight;
    inlineTerms["safety_k"] = safetyBufferSpin->value();

    // Call pricing RPC
    try {
        auto result = model->pricingRepoQuote(
            "inline",
            "",
            inlineTerms,
            "",     // report_asset (empty for TSC)
            true,   // report_is_native (default to TSC)
            true,   // compute_greeks
            QStringLiteral("mark"), // price source
            true    // include inception cashflows
        );

        if (result.success) {
            // Get report currency decimals (TSC = 8 decimals by default)
            int reportDecimals = 8;
            if (model) {
                WalletModel::AssetInfo tscInfo = model->getAssetInfo(""); // Empty = native TSC
                if (tscInfo.has_decimals) {
                    reportDecimals = tscInfo.decimals;
                }
            }
            const double toDisplayUnits = 1.0 / std::pow(10.0, reportDecimals);

            // Get principal in display units for per-principal calculations
            double principalDisplay = principalAmountSpin->value();
            double perPrincipalDivisor = (principalDisplay > 0.0) ? principalDisplay : 1.0;

            // Update Principal + Interest PV
            double principalInterestPv = (result.principal_pv + result.interest_pv) * toDisplayUnits;
            principalInterestPvLabel->setText(tr("%1 TSC").arg(principalInterestPv, 0, 'f', 8));
            principalInterestPvPerPrincipalLabel->setText(QString("%1").arg(principalInterestPv / perPrincipalDivisor, 0, 'f', 6));

            // Update Collateral PV
            double collateralPv = result.collateral_pv * toDisplayUnits;
            collateralPvLabel->setText(tr("%1 TSC").arg(collateralPv, 0, 'f', 8));
            collateralPvPerPrincipalLabel->setText(QString("%1").arg(collateralPv / perPrincipalDivisor, 0, 'f', 6));

            // Update Collateral Option Value
            double collateralOption = result.collateral_option * toDisplayUnits;
            collateralOptionLabel->setText(tr("%1 TSC").arg(collateralOption, 0, 'f', 8));
            collateralOptionPerPrincipalLabel->setText(QString("%1").arg(collateralOption / perPrincipalDivisor, 0, 'f', 6));

            // Update Lender MTM with color coding
            double lenderMtm = result.lender_mtm * toDisplayUnits;
            if (lenderMtm > 0.0) {
                lenderMtmLabel->setText(tr("+%1 TSC").arg(lenderMtm, 0, 'f', 8));
                lenderMtmLabel->setStyleSheet("QLabel { font-weight: bold; color: #4caf50; }"); // Green
                lenderMtmPerPrincipalLabel->setText(QString("+%1").arg(lenderMtm / perPrincipalDivisor, 0, 'f', 6));
                lenderMtmPerPrincipalLabel->setStyleSheet("QLabel { font-weight: bold; color: #4caf50; }");
            } else if (lenderMtm < 0.0) {
                lenderMtmLabel->setText(tr("%1 TSC").arg(lenderMtm, 0, 'f', 8));
                lenderMtmLabel->setStyleSheet("QLabel { font-weight: bold; color: #f44336; }"); // Red
                lenderMtmPerPrincipalLabel->setText(QString("%1").arg(lenderMtm / perPrincipalDivisor, 0, 'f', 6));
                lenderMtmPerPrincipalLabel->setStyleSheet("QLabel { font-weight: bold; color: #f44336; }");
            } else {
                lenderMtmLabel->setText(tr("0.00000000 TSC"));
                lenderMtmLabel->setStyleSheet("QLabel { font-weight: bold; color: #9e9e9e; }"); // Gray
                lenderMtmPerPrincipalLabel->setText(QString("0.000000"));
                lenderMtmPerPrincipalLabel->setStyleSheet("QLabel { font-weight: bold; color: #9e9e9e; }");
            }

            // Update Borrower MTM with color coding
            double borrowerMtm = result.borrower_mtm * toDisplayUnits;
            if (borrowerMtm > 0.0) {
                borrowerMtmLabel->setText(tr("+%1 TSC").arg(borrowerMtm, 0, 'f', 8));
                borrowerMtmLabel->setStyleSheet("QLabel { font-weight: bold; color: #4caf50; }"); // Green
                borrowerMtmPerPrincipalLabel->setText(QString("+%1").arg(borrowerMtm / perPrincipalDivisor, 0, 'f', 6));
                borrowerMtmPerPrincipalLabel->setStyleSheet("QLabel { font-weight: bold; color: #4caf50; }");
            } else if (borrowerMtm < 0.0) {
                borrowerMtmLabel->setText(tr("%1 TSC").arg(borrowerMtm, 0, 'f', 8));
                borrowerMtmLabel->setStyleSheet("QLabel { font-weight: bold; color: #f44336; }"); // Red
                borrowerMtmPerPrincipalLabel->setText(QString("%1").arg(borrowerMtm / perPrincipalDivisor, 0, 'f', 6));
                borrowerMtmPerPrincipalLabel->setStyleSheet("QLabel { font-weight: bold; color: #f44336; }");
            } else {
                borrowerMtmLabel->setText(tr("0.00000000 TSC"));
                borrowerMtmLabel->setStyleSheet("QLabel { font-weight: bold; color: #9e9e9e; }"); // Gray
                borrowerMtmPerPrincipalLabel->setText(QString("0.000000"));
                borrowerMtmPerPrincipalLabel->setStyleSheet("QLabel { font-weight: bold; color: #9e9e9e; }");
            }
        } else {
            // Pricing failed - show error or reset
            principalInterestPvLabel->setText(tr("Error"));
            collateralPvLabel->setText(tr("Error"));
            collateralOptionLabel->setText(tr("Error"));
            lenderMtmLabel->setText(tr("Error"));
            borrowerMtmLabel->setText(tr("Error"));
            principalInterestPvPerPrincipalLabel->setText(tr("Error"));
            collateralPvPerPrincipalLabel->setText(tr("Error"));
            collateralOptionPerPrincipalLabel->setText(tr("Error"));
            lenderMtmPerPrincipalLabel->setText(tr("Error"));
            borrowerMtmPerPrincipalLabel->setText(tr("Error"));
        }
    } catch (...) {
        // Exception occurred - reset labels
        principalInterestPvLabel->setText(tr("--"));
        collateralPvLabel->setText(tr("--"));
        collateralOptionLabel->setText(tr("--"));
        lenderMtmLabel->setText(tr("--"));
        borrowerMtmLabel->setText(tr("--"));
        principalInterestPvPerPrincipalLabel->setText(tr("--"));
        collateralPvPerPrincipalLabel->setText(tr("--"));
        collateralOptionPerPrincipalLabel->setText(tr("--"));
        lenderMtmPerPrincipalLabel->setText(tr("--"));
        borrowerMtmPerPrincipalLabel->setText(tr("--"));
    }
}

void RepoTermSheetPage::onGenerateBorrowerAddress()
{
    // Generate new address via wallet
    RepoContractBuilder* repoWizard = qobject_cast<RepoContractBuilder*>(wizard());
    if (!repoWizard) {
        LogPrintf("RepoTermSheetPage: ERROR - wizard() cast failed\n");
        return;
    }

    WalletModel* model = repoWizard->walletModel;
    if (!model) {
        LogPrintf("RepoTermSheetPage: ERROR - walletModel is null, cannot generate borrower address\n");
        QMessageBox::warning(this, tr("Address Generation Failed"),
            tr("Wallet model not available. Please enter address manually or restart wallet."));
        return;
    }

    QString newAddress = model->getNewAddress("Repo borrower repay");
    if (!newAddress.isEmpty()) {
        borrowerAddressEdit->setText(newAddress);
        LogPrintf("RepoTermSheetPage: Generated borrower address: %s\n", newAddress.toStdString().c_str());
    } else {
        LogPrintf("RepoTermSheetPage: WARNING - getNewAddress returned empty string\n");
    }
}

void RepoTermSheetPage::onGenerateLenderAddress()
{
    // Generate new address via wallet
    RepoContractBuilder* repoWizard = qobject_cast<RepoContractBuilder*>(wizard());
    if (!repoWizard) {
        LogPrintf("RepoTermSheetPage: ERROR - wizard() cast failed\n");
        return;
    }

    WalletModel* model = repoWizard->walletModel;
    if (!model) {
        LogPrintf("RepoTermSheetPage: ERROR - walletModel is null, cannot generate lender address\n");
        QMessageBox::warning(this, tr("Address Generation Failed"),
            tr("Wallet model not available. Please enter address manually or restart wallet."));
        return;
    }

    QString newAddress = model->getNewAddress("Repo lender receive");
    if (!newAddress.isEmpty()) {
        lenderAddressEdit->setText(newAddress);
        LogPrintf("RepoTermSheetPage: Generated lender address: %s\n", newAddress.toStdString().c_str());
    } else {
        LogPrintf("RepoTermSheetPage: WARNING - getNewAddress returned empty string\n");
    }
}

void RepoTermSheetPage::onBorrowerManualToggled(bool checked)
{
    if (!lenderRadio->isChecked()) {
        return;
    }

    borrowerAddressEdit->setEnabled(checked);
    borrowerAddressEdit->setReadOnly(!checked);
    borrowerAddressEdit->setPlaceholderText(checked
        ? tr("Paste counterparty borrower address")
        : tr("Will be provided by taker"));
    if (!checked) {
        borrowerAddressEdit->clear();
    }

    Q_EMIT completeChanged();
}

void RepoTermSheetPage::onLenderManualToggled(bool checked)
{
    if (lenderRadio->isChecked()) {
        return;
    }

    lenderAddressEdit->setEnabled(checked);
    lenderAddressEdit->setReadOnly(!checked);
    lenderAddressEdit->setPlaceholderText(checked
        ? tr("Paste counterparty lender address")
        : tr("Will be provided by taker"));
    if (!checked) {
        lenderAddressEdit->clear();
    }

    Q_EMIT completeChanged();
}

bool RepoTermSheetPage::isComplete() const
{
    if (lenderRadio && lenderRadio->isChecked()) {
        return lenderAddressEdit && !lenderAddressEdit->text().trimmed().isEmpty();
    }
    if (borrowerRadio && borrowerRadio->isChecked()) {
        return borrowerAddressEdit && !borrowerAddressEdit->text().trimmed().isEmpty();
    }
    return true;
}

void RepoTermSheetPage::populateAssetComboBox(QComboBox* combo, bool includeNative)
{
    combo->clear();

    if (includeNative) {
        combo->addItem(tr("TSC (Native)"), QVariant::fromValue(QString("native")));
    }

    // Get registered assets from wallet
    WalletModel* model = qobject_cast<RepoContractBuilder*>(wizard())->walletModel;
    if (!model) return;

    QList<WalletModel::AssetInfo> assets = model->listAssets();

    for (const auto& asset : assets) {
        QString label = QString("%1 (%2)").arg(asset.ticker, asset.asset_id.left(8) + "...");
        combo->addItem(label, QVariant::fromValue(asset.asset_id));
    }
}

QString RepoTermSheetPage::getAssetIdFromCombo(QComboBox* combo) const
{
    QString data = combo->currentData().toString();
    // Return empty QString for native asset - "native" is a UI sentinel, not a valid asset_id
    return (data == "native") ? QString() : data;
}

bool RepoTermSheetPage::isNativeAsset(QComboBox* combo) const
{
    return combo->currentData().toString() == "native";
}

int RepoTermSheetPage::getAssetDecimals(QComboBox* combo) const
{
    if (isNativeAsset(combo)) {
        return 8; // TSC decimals
    }

    // Query asset info for decimals
    WalletModel* model = qobject_cast<RepoContractBuilder*>(wizard())->walletModel;
    if (!model) return 8;

    QString assetId = getAssetIdFromCombo(combo);
    WalletModel::AssetInfo info = model->getAssetInfo(assetId);

    return info.decimals;
}

void RepoTermSheetPage::onTransportChanged(int index)
{
    QString transport = transportCombo->itemData(index).toString();

    if (transport == "tor") {
        // Show Tor status when Tor is selected
        updateTorStatus();
        torStatusLabel->show();

        // Connect to TorManager status updates
        connect(TorManager::instance(), &TorManager::statusChanged,
                this, &RepoTermSheetPage::updateTorStatus);
    } else {
        // Hide Tor status for auto and ws
        torStatusLabel->hide();
        disconnect(TorManager::instance(), &TorManager::statusChanged,
                   this, &RepoTermSheetPage::updateTorStatus);
    }

    Q_EMIT completeChanged();
}

void RepoTermSheetPage::updateTorStatus()
{
    TorManager* tor = TorManager::instance();

    const QString smallFont = QStringLiteral(" font-size: 11px;");
    switch (tor->status()) {
        case TorManager::Status::NotStarted:
            torStatusLabel->setText(tr("● Tor: Not Started"));
            torStatusLabel->setStyleSheet(QStringLiteral("QLabel {%1 %2 }").arg(ThemeHelpers::warningPanelStyleSheet(), smallFont));
            break;
        case TorManager::Status::Starting:
            torStatusLabel->setText(tr("● Tor: Starting... (this may take 10-30 seconds)"));
            torStatusLabel->setStyleSheet(QStringLiteral("QLabel {%1 %2 }").arg(ThemeHelpers::infoPanelStyleSheet(), smallFont));
            break;
        case TorManager::Status::Ready:
            torStatusLabel->setText(tr("● Tor: Ready"));
            torStatusLabel->setStyleSheet(QStringLiteral("QLabel {%1 %2 }").arg(ThemeHelpers::successPanelStyleSheet(), smallFont));
            break;
        case TorManager::Status::Failed:
            torStatusLabel->setText(tr("● Tor: Failed (%1)").arg(tor->lastError()));
            torStatusLabel->setStyleSheet(QStringLiteral("QLabel {%1 %2 }").arg(ThemeHelpers::errorPanelStyleSheet(), smallFont));
            break;
        case TorManager::Status::Stopped:
            torStatusLabel->setText(tr("● Tor: Stopped"));
            torStatusLabel->setStyleSheet(QStringLiteral("QLabel {%1 %2 }").arg(ThemeHelpers::warningPanelStyleSheet(), smallFont));
            break;
    }
}

// ============================================================================
// RepoReviewPage
// ============================================================================

RepoReviewPage::RepoReviewPage(ContractWizard* wizard, QWidget* parent)
    : ContractReviewPage(wizard, parent)
{
    setTitle(tr("Repo Contract - Review && Create Offer"));
    setSubTitle(tr("Review the contract summary below. Click 'Finish' to create the offer."));
}

QString RepoReviewPage::formatOfferSummary() const
{
    bool isLender = field("isLender").toBool();
    double collateralAmount = field("collateralAmount").toDouble();
    double principalAmount = field("principalAmount").toDouble();
    double interestRate = field("interestRate").toDouble();
    int maturityPeriod = field("maturityPeriod").toInt();
    QString maturityUnit = field("maturityUnit").toString();
    QString borrowerAddr = field("borrowerAddress").toString();
    QString lenderAddr = field("lenderAddress").toString();

    // Get asset labels
    bool collateralIsNative = field("collateralIsNative").toBool();
    bool principalIsNative = field("principalIsNative").toBool();
    bool interestIsNative = field("interestIsNative").toBool();

    QString collateralAsset = "TSC";
    QString principalAsset = "TSC";
    QString interestAsset = "TSC";

    RepoContractBuilder* builder = qobject_cast<RepoContractBuilder*>(wizard());
    if (builder && builder->walletModel) {
        if (!collateralIsNative) {
            QString assetId = field("collateralAssetId").toString();
            WalletModel::AssetInfo info = builder->walletModel->getAssetInfo(assetId);
            if (!info.ticker.isEmpty()) {
                collateralAsset = info.ticker;
            }
        }
        if (!principalIsNative) {
            QString assetId = field("principalAssetId").toString();
            WalletModel::AssetInfo info = builder->walletModel->getAssetInfo(assetId);
            if (!info.ticker.isEmpty()) {
                principalAsset = info.ticker;
            }
        }
        if (!interestIsNative) {
            QString assetId = field("interestAssetId").toString();
            WalletModel::AssetInfo info = builder->walletModel->getAssetInfo(assetId);
            if (!info.ticker.isEmpty()) {
                interestAsset = info.ticker;
            }
        }
    }

    // Calculate interest based on period
    double days = maturityPeriod;
    if (maturityUnit == "weeks") {
        days = maturityPeriod * 7.0;
    } else if (maturityUnit == "months") {
        days = maturityPeriod * 30.0;
    } else if (maturityUnit == "years") {
        days = maturityPeriod * 365.0;
    }
    double interestAmount = principalAmount * (interestRate / 100.0) * (days / 365.0);

    // Calculate maturity height: use absolute if enabled, otherwise calculate from period
    int maturityHeight;
    if (field("useAbsoluteHeight").toBool()) {
        maturityHeight = field("absoluteHeight").toInt();
    } else {
        int currentHeight = builder ? builder->walletModel->getNumBlocks() : 0;
        int blocks = 0;
        if (maturityUnit == "days") {
            blocks = maturityPeriod * 144;
        } else if (maturityUnit == "weeks") {
            blocks = maturityPeriod * 7 * 144;
        } else if (maturityUnit == "months") {
            blocks = maturityPeriod * 30 * 144;
        } else if (maturityUnit == "years") {
            blocks = maturityPeriod * 365 * 144;
        }
        maturityHeight = currentHeight + blocks;
    }

    QString summary;
    summary += tr("<h3>Summary:</h3>");
    summary += QStringLiteral("<ul>");
    summary += tr("<li><b>Role:</b> %1</li>").arg(isLender ? tr("Lender") : tr("Borrower"));
    summary += tr("<li><b>Collateral:</b> %1 %2</li>").arg(collateralAmount, 0, 'f', 8).arg(collateralAsset);
    summary += tr("<li><b>Principal:</b> %1 %2</li>").arg(principalAmount, 0, 'f', 8).arg(principalAsset);
    summary += tr("<li><b>Interest Rate:</b> %1% per annum (%2 %3)</li>")
                .arg(interestRate, 0, 'f', 2)
                .arg(maturityPeriod)
                .arg(maturityUnit);
    summary += tr("<li><b>Interest Amount:</b> %1 %2</li>").arg(interestAmount, 0, 'f', 8).arg(interestAsset);

    // Only show combined repay amount if interest is in same asset as principal
    if (interestAsset == principalAsset) {
        double repayAmount = principalAmount + interestAmount;
        summary += tr("<li><b>Repay Amount:</b> %1 %2</li>").arg(repayAmount, 0, 'f', 8).arg(principalAsset);
    } else {
        summary += tr("<li><b>Principal Repayment:</b> %1 %2</li>").arg(principalAmount, 0, 'f', 8).arg(principalAsset);
        summary += tr("<li><b>Interest Payment:</b> %1 %2 (separate)</li>").arg(interestAmount, 0, 'f', 8).arg(interestAsset);
    }
    summary += tr("<li><b>Maturity:</b> Block %1 (~%2 %3)</li>")
                .arg(maturityHeight)
                .arg(maturityPeriod)
                .arg(maturityUnit);
    summary += QStringLiteral("</ul>");

    summary += tr("<h3>Covenant Details:</h3>");
    summary += QStringLiteral("<ul>");
    summary += tr("<li><b>Vault Script:</b> 2-leaf Taproot</li>");
    summary += tr("<li style='margin-left: 20px;'>• Leaf A (Repayment): OP_OUTPUTMATCH_ASSET + Borrower sig</li>");
    summary += tr("<li style='margin-left: 20px;'>• Leaf B (Default): CLTV(%1) + Lender sig</li>")
                .arg(maturityHeight);
    summary += tr("<li><b>Deterministic sinks:</b> Committed via TapMatch(spk)</li>");
    summary += QStringLiteral("</ul>");

    summary += tr("<h3>Fair-Sign Policy:</h3>");
    summary += QStringLiteral("<ul>");
    summary += tr("<li><b>Adaptor signatures:</b> REQUIRED</li>");
    summary += tr("<li><b>Reveal mode:</b> Lock-step (2-phase commit)</li>");
    summary += tr("<li><b>Ceremony timeout:</b> 600s (10 minutes)</li>");
    summary += QStringLiteral("</ul>");

    summary += tr("<h3>Addresses:</h3>");
    summary += QStringLiteral("<ul>");
    summary += tr("<li><b>Borrower Repay:</b> <code>%1</code></li>").arg(borrowerAddr);
    summary += tr("<li><b>Lender Receive:</b> <code>%1</code></li>").arg(lenderAddr);
    summary += QStringLiteral("</ul>");

    return summary;
}

void RepoTermSheetPage::onShowGreeks()
{
    auto* repoWizard = qobject_cast<RepoContractBuilder*>(wizard());
    WalletModel* walletModel = repoWizard ? repoWizard->walletModel : nullptr;

    if (!walletModel) {
        QMessageBox::warning(this, tr("Greeks"), tr("Wallet model not available"));
        return;
    }

    try {
        // Build inline_terms from current form values
        QVariantMap inlineTerms;

        // Get collateral info
        QString collateralAssetId = getAssetIdFromCombo(collateralAssetCombo);
        bool collateralIsNative = isNativeAsset(collateralAssetCombo);
        double collateralAmount = collateralAmountSpin->value();
        inlineTerms["collateral_asset"] = collateralAssetId.isEmpty() ? "" : collateralAssetId;
        inlineTerms["collateral_is_native"] = collateralIsNative;
        inlineTerms["collateral_units"] = static_cast<qint64>(collateralAmount * 1e8);

        // Get principal info
        QString principalAssetId = getAssetIdFromCombo(principalAssetCombo);
        bool principalIsNative = isNativeAsset(principalAssetCombo);
        double principalAmount = principalAmountSpin->value();
        inlineTerms["principal_asset"] = principalAssetId.isEmpty() ? "" : principalAssetId;
        inlineTerms["principal_is_native"] = principalIsNative;
        inlineTerms["principal_units"] = static_cast<qint64>(principalAmount * 1e8);

        // Get interest info
        QString interestAssetId = getAssetIdFromCombo(interestAssetCombo);
        bool interestIsNative = isNativeAsset(interestAssetCombo);
        double interestRate = interestRateSpin->value();
        double interestAmount = principalAmount * (interestRate / 100.0) * (maturityPeriodSpin->value() / (maturityUnitCombo->currentData().toString() == "days" ? 365.0 : (maturityUnitCombo->currentData().toString() == "weeks" ? 52.0 : (maturityUnitCombo->currentData().toString() == "months" ? 12.0 : 1.0))));
        inlineTerms["interest_asset"] = interestAssetId.isEmpty() ? "" : interestAssetId;
        inlineTerms["interest_is_native"] = interestIsNative;
        inlineTerms["interest_units"] = static_cast<qint64>(interestAmount * 1e8);

        // Calculate maturity height
        int currentHeight = walletModel->getNumBlocks();
        int maturityBlocks = 0;
        QString maturityUnit = maturityUnitCombo->currentData().toString();
        int maturityPeriod = maturityPeriodSpin->value();

        if (maturityUnit == "days") {
            maturityBlocks = maturityPeriod * 144;
        } else if (maturityUnit == "weeks") {
            maturityBlocks = maturityPeriod * 7 * 144;
        } else if (maturityUnit == "months") {
            maturityBlocks = maturityPeriod * 30 * 144;
        } else { // years
            maturityBlocks = maturityPeriod * 365 * 144;
        }

        int maturityHeight = useAbsoluteHeightCheck->isChecked() ? absoluteHeightSpin->value() : (currentHeight + maturityBlocks);
        inlineTerms["maturity_height"] = maturityHeight;
        inlineTerms["safety_k"] = safetyBufferSpin->value();

        // Collateral price (for calculating current LTV)
        double collateralPrice = collateralPriceSpin->value();
        inlineTerms["collateral_price"] = collateralPrice;

        // Create GreeksData and open dialog
        GreeksVisualizationDialog::GreeksData greeksData;
        greeksData.type = GreeksVisualizationDialog::Repo;
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
