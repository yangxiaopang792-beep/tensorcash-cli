// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <qt/spotcontractbuilder.h>
#include <qt/walletmodel.h>
#include <qt/guiutil.h>
#include <logging.h>

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QGroupBox>
#include <QLabel>
#include <QCheckBox>
#include <QComboBox>
#include <QDoubleSpinBox>
#include <QLineEdit>
#include <QPushButton>
#include <QMessageBox>
#include <QScrollArea>
#include <QJsonDocument>
#include <QJsonObject>

// ============================================================================
// SpotContractBuilder
// ============================================================================

SpotContractBuilder::SpotContractBuilder(WalletModel* model, QWidget* parent)
    : ContractWizard(model, parent)
{
    setWindowTitle(tr("Spot Contract Builder (Atomic Swap)"));

    // Reasonable size that fits most screens
    setMinimumSize(700, 500);
    resize(800, 600);

    // Add pages
    setPage(Page_TermSheet, new SpotTermSheetPage(this));
    setPage(Page_Review, new SpotReviewPage(this, this));

    setStartId(Page_TermSheet);
}

SpotContractBuilder::~SpotContractBuilder()
{
}

bool SpotContractBuilder::validateTerms()
{
    // Validate that all required fields are set
    if (field("yourAmount").toDouble() <= 0) {
        QMessageBox::warning(this, tr("Validation Error"),
            tr("Your offer amount must be greater than zero."));
        return false;
    }

    if (field("desiredAmount").toDouble() <= 0) {
        QMessageBox::warning(this, tr("Validation Error"),
            tr("Desired amount must be greater than zero."));
        return false;
    }

    // Require your destination address (proposer always provides their own address)
    QString yourDest = field("yourDestAddress").toString();
    if (yourDest.isEmpty()) {
        QMessageBox::warning(this, tr("Validation Error"),
            tr("Your destination address is required."));
        return false;
    }

    // Prevent swapping same asset for same asset (pointless swap)
    bool yourIsNative = field("yourIsNative").toBool();
    bool desiredIsNative = field("desiredIsNative").toBool();
    QString yourAssetId = field("yourAssetId").toString();
    QString desiredAssetId = field("desiredAssetId").toString();

    // Check if both are native TSC
    if (yourIsNative && desiredIsNative) {
        QMessageBox::warning(this, tr("Validation Error"),
            tr("Cannot swap TSC for TSC.\n\nPlease select different assets for the exchange."));
        return false;
    }

    // Check if both are the same registered asset
    if (!yourIsNative && !desiredIsNative && !yourAssetId.isEmpty() && yourAssetId == desiredAssetId) {
        QMessageBox::warning(this, tr("Validation Error"),
            tr("Cannot swap the same asset for itself.\n\nPlease select different assets for the exchange."));
        return false;
    }

    return true;
}

bool SpotContractBuilder::createOffer()
{
    try {
        if (!walletModel) {
            QMessageBox::critical(this, tr("Error"), tr("Wallet model not available"));
            return false;
        }

        // Build terms map from wizard fields
        QVariantMap terms;

        // Alice leg (proposer/offerer - "your" leg)
        bool yourIsNative = field("yourIsNative").toBool();
        QString yourAssetId = field("yourAssetId").toString();
        double yourAmount = field("yourAmount").toDouble();

        // Get decimals for your asset
        int yourDecimals = 8;  // Default for native TSC
        if (!yourIsNative && walletModel) {
            WalletModel::AssetInfo yourAssetInfo = walletModel->getAssetInfo(yourAssetId);
            if (yourAssetInfo.has_decimals) {
                yourDecimals = yourAssetInfo.decimals;
            }
        }

        // Convert display amount to base units (e.g., 2.0 BTC → 200000000 sats)
        int64_t yourUnits = static_cast<int64_t>(std::llround(yourAmount * std::pow(10.0, yourDecimals)));

        QVariantMap aliceLeg;
        if (yourIsNative) {
            aliceLeg["is_native"] = true;
        } else {
            aliceLeg["is_native"] = false;
            aliceLeg["asset_id"] = yourAssetId;
        }
        aliceLeg["units"] = static_cast<qlonglong>(yourUnits);  // Store as base units (int64)
        aliceLeg["decimals"] = yourDecimals;  // Store decimals used for conversion
        terms["alice_leg"] = aliceLeg;

        // Alice destination address (where alice receives bob's asset)
        QString yourDest = field("yourDestAddress").toString();
        terms["alice_dest"] = yourDest;

        // Bob leg (acceptor - "desired" leg)
        bool desiredIsNative = field("desiredIsNative").toBool();
        QString desiredAssetId = field("desiredAssetId").toString();
        double desiredAmount = field("desiredAmount").toDouble();

        // Get decimals for desired asset
        int desiredDecimals = 8;  // Default for native TSC
        if (!desiredIsNative && walletModel) {
            WalletModel::AssetInfo desiredAssetInfo = walletModel->getAssetInfo(desiredAssetId);
            if (desiredAssetInfo.has_decimals) {
                desiredDecimals = desiredAssetInfo.decimals;
            }
        }

        // Convert display amount to base units
        int64_t desiredUnits = static_cast<int64_t>(std::llround(desiredAmount * std::pow(10.0, desiredDecimals)));

        QVariantMap bobLeg;
        if (desiredIsNative) {
            bobLeg["is_native"] = true;
        } else {
            bobLeg["is_native"] = false;
            bobLeg["asset_id"] = desiredAssetId;
        }
        bobLeg["units"] = static_cast<qlonglong>(desiredUnits);  // Store as base units (int64)
        bobLeg["decimals"] = desiredDecimals;  // Store decimals used for conversion
        terms["bob_leg"] = bobLeg;

        // Bob destination address (optional for bulletin board flow)
        QString counterpartyDest = field("counterpartyDestAddress").toString();
        if (!counterpartyDest.isEmpty()) {
            terms["bob_dest"] = counterpartyDest;
        } else {
            terms["bob_dest"] = "";  // Will be filled by acceptor
        }

        // Commitment proof requirement (for WRAP_REQUIRED assets)
        bool requireCommitment = field("requireCommitmentProof").toBool();
        terms["require_commitment_proof"] = requireCommitment;

        // Build term sheet JSON (always available)
        QJsonObject termSheet;
        termSheet["schema"] = QStringLiteral("spot_term_sheet_v1");
        termSheet["maker_role"] = QStringLiteral("alice");  // Proposer is always alice

        QJsonObject termsJson = QJsonObject::fromVariantMap(terms);
        termSheet["terms"] = termsJson;

        // Calculate exchange rate for metrics (using variables already declared above)
        double exchangeRate = 0.0;
        if (yourAmount > 0.0) {
            exchangeRate = desiredAmount / yourAmount;
        }

        QJsonObject metricsJson;
        metricsJson["exchange_rate"] = exchangeRate;
        termSheet["metrics"] = metricsJson;

        termSheetJson = QString::fromUtf8(QJsonDocument(termSheet).toJson(QJsonDocument::Compact));

        // Populate offerData with term sheet values (used by review/result dialog)
        offerData = terms;
        offerData["exchange_rate"] = exchangeRate;
        offerData["term_sheet_json"] = termSheetJson;
        offerData["require_commitment_proof"] = requireCommitment;

        // Call spot.propose RPC to register the offer in the wallet
        WalletModel::SpotProposeResult result = walletModel->spotPropose(terms);

        if (!result.success) {
            QMessageBox::critical(this, tr("Spot Propose Failed"),
                tr("Failed to create spot offer:\n\n%1").arg(result.error));
            return false;
        }

        // Store RPC results
        offerId = result.offer_id;
        offerJson = result.offer_json;
        offerData["offer_id"] = offerId;
        offerData["offer_json"] = offerJson;
        offerFinalized = true;

        LogPrintf("SpotContractBuilder: Created spot offer with ID: %s\n", offerId.toStdString().c_str());

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
// SpotTermSheetPage
// ============================================================================

SpotTermSheetPage::SpotTermSheetPage(QWidget* parent)
    : QWizardPage(parent)
{
    setTitle(tr("Spot Contract - Atomic Swap"));

    setupUI();
}

void SpotTermSheetPage::setupUI()
{
    // Create scroll area for content
    QScrollArea* scrollArea = new QScrollArea(this);
    scrollArea->setWidgetResizable(true);
    scrollArea->setFrameShape(QFrame::NoFrame);

    // Create container widget for all form content
    QWidget* container = new QWidget();
    QVBoxLayout* mainLayout = new QVBoxLayout(container);

    // Your Offer Leg Section - Compact one-line format
    QGroupBox* yourLegGroup = new QGroupBox(tr("Your Offer (What You Provide)"), this);
    QHBoxLayout* yourLegLayout = new QHBoxLayout(yourLegGroup);

    yourAmountSpin = new QDoubleSpinBox(this);
    yourAmountSpin->setDecimals(8);
    yourAmountSpin->setMaximum(21000000.0);
    yourAmountSpin->setMinimum(0.00000001);
    yourAmountSpin->setValue(1.0);
    yourLegLayout->addWidget(yourAmountSpin);
    connect(yourAmountSpin, QOverload<double>::of(&QDoubleSpinBox::valueChanged),
            this, &SpotTermSheetPage::onYourAmountChanged);

    yourAssetCombo = new QComboBox(this);
    yourAssetCombo->setMinimumWidth(150);
    yourLegLayout->addWidget(yourAssetCombo);
    connect(yourAssetCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &SpotTermSheetPage::onYourAssetChanged);

    yourUnitLabel = new QLabel(tr("TSC"), this);
    yourUnitLabel->setVisible(false);  // Unit is shown in combo box

    yourLegLayout->addStretch();
    yourLegGroup->setLayout(yourLegLayout);
    mainLayout->addWidget(yourLegGroup);

    // Hidden fields for asset metadata
    QCheckBox* yourIsNativeCheck = new QCheckBox(this);
    yourIsNativeCheck->setVisible(false);
    QLineEdit* yourAssetIdEdit = new QLineEdit(this);
    yourAssetIdEdit->setVisible(false);

    registerField("yourIsNative", yourIsNativeCheck);
    registerField("yourAssetId", yourAssetIdEdit);
    registerField("yourAmount", yourAmountSpin, "value");

    // Desired Leg Section - Compact one-line format
    QGroupBox* desiredLegGroup = new QGroupBox(tr("Desired Exchange (What You Want)"), this);
    QHBoxLayout* desiredLegLayout = new QHBoxLayout(desiredLegGroup);

    desiredAmountSpin = new QDoubleSpinBox(this);
    desiredAmountSpin->setDecimals(8);
    desiredAmountSpin->setMaximum(21000000.0);
    desiredAmountSpin->setMinimum(0.00000001);
    desiredAmountSpin->setValue(1.0);
    desiredLegLayout->addWidget(desiredAmountSpin);
    connect(desiredAmountSpin, QOverload<double>::of(&QDoubleSpinBox::valueChanged),
            this, &SpotTermSheetPage::onDesiredAmountChanged);

    desiredAssetCombo = new QComboBox(this);
    desiredAssetCombo->setMinimumWidth(150);
    desiredLegLayout->addWidget(desiredAssetCombo);
    connect(desiredAssetCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &SpotTermSheetPage::onDesiredAssetChanged);

    desiredUnitLabel = new QLabel(tr("TSC"), this);
    desiredUnitLabel->setVisible(false);  // Unit is shown in combo box

    desiredLegLayout->addStretch();
    desiredLegGroup->setLayout(desiredLegLayout);
    mainLayout->addWidget(desiredLegGroup);

    // Hidden fields for asset metadata
    QCheckBox* desiredIsNativeCheck = new QCheckBox(this);
    desiredIsNativeCheck->setVisible(false);
    QLineEdit* desiredAssetIdEdit = new QLineEdit(this);
    desiredAssetIdEdit->setVisible(false);

    registerField("desiredIsNative", desiredIsNativeCheck);
    registerField("desiredAssetId", desiredAssetIdEdit);
    registerField("desiredAmount", desiredAmountSpin, "value");

    // Exchange Rate Display
    QGroupBox* rateGroup = new QGroupBox(tr("Exchange Rate"), this);
    QVBoxLayout* rateLayout = new QVBoxLayout(rateGroup);

    exchangeRateLabel = new QLabel(tr("1.00000000 TSC per TSC"), this);
    exchangeRateLabel->setStyleSheet("QLabel { font-weight: bold; color: #1976d2; font-size: 12pt; }");
    exchangeRateLabel->setAlignment(Qt::AlignCenter);
    rateLayout->addWidget(exchangeRateLabel);

    rateGroup->setLayout(rateLayout);
    mainLayout->addWidget(rateGroup);

    // Addresses Section - Separate at bottom
    QGroupBox* addressGroup = new QGroupBox(tr("Settlement Addresses"), this);
    QGridLayout* addressLayout = new QGridLayout(addressGroup);

    addressLayout->addWidget(new QLabel(tr("Your Destination:"), this), 0, 0);
    yourDestEdit = new QLineEdit(this);
    yourDestEdit->setPlaceholderText(tr("Address where you receive the desired asset"));
    addressLayout->addWidget(yourDestEdit, 0, 1);
    generateYourDestButton = new QPushButton(tr("Generate"), this);
    addressLayout->addWidget(generateYourDestButton, 0, 2);
    connect(generateYourDestButton, &QPushButton::clicked,
            this, &SpotTermSheetPage::onGenerateYourDestAddress);

    yourDestManualToggle = new QCheckBox(tr("Manual entry"), this);
    yourDestManualToggle->setToolTip(tr("Enable to enter address manually."));
    yourDestManualToggle->setVisible(false);

    addressLayout->addWidget(new QLabel(tr("Counterparty Dest:"), this), 1, 0);
    counterpartyDestEdit = new QLineEdit(this);
    counterpartyDestEdit->setPlaceholderText(tr("Optional - will be provided by acceptor"));
    counterpartyDestEdit->setEnabled(false);  // Disabled by default
    counterpartyDestEdit->setReadOnly(true);
    addressLayout->addWidget(counterpartyDestEdit, 1, 1);

    generateCounterpartyDestButton = new QPushButton(tr("Generate"), this);
    generateCounterpartyDestButton->setVisible(false);
    addressLayout->addWidget(generateCounterpartyDestButton, 1, 2);
    connect(generateCounterpartyDestButton, &QPushButton::clicked,
            this, &SpotTermSheetPage::onGenerateCounterpartyDestAddress);

    counterpartyDestManualToggle = new QCheckBox(tr("Manual entry"), this);
    counterpartyDestManualToggle->setToolTip(tr("Enable to enter counterparty destination manually."));
    addressLayout->addWidget(counterpartyDestManualToggle, 1, 3);
    connect(counterpartyDestManualToggle, &QCheckBox::toggled,
            this, &SpotTermSheetPage::onCounterpartyDestManualToggled);

    addressGroup->setLayout(addressLayout);
    mainLayout->addWidget(addressGroup);

    registerField("yourDestAddress*", yourDestEdit);  // Required
    registerField("counterpartyDestAddress", counterpartyDestEdit);  // Optional

    // Decryption Commitment - Simple non-collapsible section with one checkbox
    QGroupBox* commitmentGroup = new QGroupBox(tr("Decryption Commitment (Advanced)"), this);
    QVBoxLayout* commitmentLayout = new QVBoxLayout(commitmentGroup);

    requireCommitmentProofCheck = new QCheckBox(
        tr("Require cryptographic commitment proof of decryption"), this);
    commitmentLayout->addWidget(requireCommitmentProofCheck);

    QLabel* commitmentInfo = new QLabel(this);
    commitmentInfo->setTextFormat(Qt::RichText);
    commitmentInfo->setText(
        tr("If the asset has governance text that is visible to the holder only, you can request that both parties "
           "exchange a cryptographic commitment that the encrypted governance text has been decrypted, viewed, and accepted. "
           "<br><br><b>WARNING:</b> If you are a holder of an encrypted asset, consider that the potential receiver will be able to "
           "decrypt the text even if not going through with the transaction. If you are a receiver of the encrypted asset, "
           "please bear in mind that by accepting you would be implicitly stating that you have viewed and reviewed the governance text. "
           "If there are any legal obligations contained therein, you might not be able to claim that you have not reviewed the "
           "asset governance text."));
    commitmentInfo->setWordWrap(true);
    commitmentInfo->setStyleSheet("QLabel { color: #666; font-size: 9pt; }");
    commitmentLayout->addWidget(commitmentInfo);

    commitmentGroup->setLayout(commitmentLayout);
    mainLayout->addWidget(commitmentGroup);

    registerField("requireCommitmentProof", requireCommitmentProofCheck);

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

    // Install wheel event filters to prevent accidental changes while scrolling
    GUIUtil::InstallWheelEventFilter(yourAssetCombo);
    GUIUtil::InstallWheelEventFilter(yourAmountSpin);
    GUIUtil::InstallWheelEventFilter(desiredAssetCombo);
    GUIUtil::InstallWheelEventFilter(desiredAmountSpin);
}

void SpotTermSheetPage::initializePage()
{
    // Populate asset combos (wizard() is now available)
    if (yourAssetCombo->count() == 0) {
        populateAssetComboBox(yourAssetCombo, true);
    }
    if (desiredAssetCombo->count() == 0) {
        populateAssetComboBox(desiredAssetCombo, true);
    }

    // Auto-generate proposer's destination address
    if (yourDestEdit->text().isEmpty()) {
        onGenerateYourDestAddress();
    }

    updateCalculations();
}

bool SpotTermSheetPage::validatePage()
{
    // Validate all fields before proceeding to review
    SpotContractBuilder* spotWizard = qobject_cast<SpotContractBuilder*>(wizard());
    if (!spotWizard) return false;

    // Store your asset info
    setField("yourIsNative", isNativeAsset(yourAssetCombo));
    setField("yourAssetId", getAssetIdFromCombo(yourAssetCombo));

    // Store desired asset info
    setField("desiredIsNative", isNativeAsset(desiredAssetCombo));
    setField("desiredAssetId", getAssetIdFromCombo(desiredAssetCombo));

    return spotWizard->validateTerms();
}

bool SpotTermSheetPage::isComplete() const
{
    // Page is complete if proposer has provided their destination address
    return yourDestEdit && !yourDestEdit->text().trimmed().isEmpty();
}

void SpotTermSheetPage::onYourAssetChanged(int index)
{
    // Update unit labels
    QString yourAsset = yourAssetCombo->currentText().split(" ").first();
    yourUnitLabel->setText(yourAsset);

    // Update decimals based on asset
    int decimals = getAssetDecimals(yourAssetCombo);
    yourAmountSpin->setDecimals(decimals);

    updateCalculations();
}

void SpotTermSheetPage::onYourAmountChanged(double value)
{
    updateCalculations();
}

void SpotTermSheetPage::onDesiredAssetChanged(int index)
{
    // Update unit labels
    QString desiredAsset = desiredAssetCombo->currentText().split(" ").first();
    desiredUnitLabel->setText(desiredAsset);

    // Update decimals based on asset
    int decimals = getAssetDecimals(desiredAssetCombo);
    desiredAmountSpin->setDecimals(decimals);

    updateCalculations();
}

void SpotTermSheetPage::onDesiredAmountChanged(double value)
{
    updateCalculations();
}

void SpotTermSheetPage::onGenerateYourDestAddress()
{
    // Generate new address via wallet
    SpotContractBuilder* spotWizard = qobject_cast<SpotContractBuilder*>(wizard());
    if (!spotWizard) {
        LogPrintf("SpotTermSheetPage: ERROR - wizard() cast failed\n");
        return;
    }

    WalletModel* model = spotWizard->walletModel;
    if (!model) {
        LogPrintf("SpotTermSheetPage: ERROR - walletModel is null, cannot generate address\n");
        QMessageBox::warning(this, tr("Address Generation Failed"),
            tr("Wallet model not available. Please enter address manually or restart wallet."));
        return;
    }

    QString newAddress = model->getNewAddress("Spot proposer receive");
    if (!newAddress.isEmpty()) {
        yourDestEdit->setText(newAddress);
        LogPrintf("SpotTermSheetPage: Generated proposer address: %s\n", newAddress.toStdString().c_str());
    } else {
        LogPrintf("SpotTermSheetPage: WARNING - getNewAddress returned empty string\n");
    }
}

void SpotTermSheetPage::onGenerateCounterpartyDestAddress()
{
    // Generate new address via wallet (rarely used - for testing or when proposer knows counterparty's wallet)
    SpotContractBuilder* spotWizard = qobject_cast<SpotContractBuilder*>(wizard());
    if (!spotWizard) return;

    WalletModel* model = spotWizard->walletModel;
    if (!model) {
        QMessageBox::warning(this, tr("Address Generation Failed"),
            tr("Wallet model not available. Please enter address manually or restart wallet."));
        return;
    }

    QString newAddress = model->getNewAddress("Spot counterparty receive");
    if (!newAddress.isEmpty()) {
        counterpartyDestEdit->setText(newAddress);
    }
}

void SpotTermSheetPage::onYourDestManualToggled(bool checked)
{
    // Allow manual entry vs auto-generation
    yourDestEdit->setEnabled(true);
    yourDestEdit->setReadOnly(!checked);
    if (!checked && yourDestEdit->text().isEmpty()) {
        onGenerateYourDestAddress();
    }
    Q_EMIT completeChanged();
}

void SpotTermSheetPage::onCounterpartyDestManualToggled(bool checked)
{
    // Allow manual entry of counterparty address (optional for bulletin board flow)
    counterpartyDestEdit->setEnabled(checked);
    counterpartyDestEdit->setReadOnly(!checked);
    counterpartyDestEdit->setPlaceholderText(checked
        ? tr("Paste counterparty destination address")
        : tr("Optional - will be provided by acceptor"));
    if (!checked) {
        counterpartyDestEdit->clear();
    }
}

void SpotTermSheetPage::updateCalculations()
{
    double yourAmount = yourAmountSpin->value();
    double desiredAmount = desiredAmountSpin->value();

    QString yourAsset = yourAssetCombo->currentText().split(" ").first();
    QString desiredAsset = desiredAssetCombo->currentText().split(" ").first();

    // Calculate exchange rate
    if (yourAmount > 0.0) {
        double rate = desiredAmount / yourAmount;
        exchangeRateLabel->setText(QString("%1 %2 per %3 %4")
            .arg(rate, 0, 'f', 8)
            .arg(desiredAsset)
            .arg(QString::number(1.0))
            .arg(yourAsset));
    } else {
        exchangeRateLabel->setText(tr("Enter amounts to calculate rate"));
    }
}

void SpotTermSheetPage::populateAssetComboBox(QComboBox* combo, bool includeNative)
{
    combo->clear();

    if (includeNative) {
        combo->addItem(tr("TSC (Native)"), QVariant::fromValue(QString("native")));
    }

    // Get registered assets from wallet
    SpotContractBuilder* builder = qobject_cast<SpotContractBuilder*>(wizard());
    WalletModel* model = builder ? builder->getWalletModel() : nullptr;
    if (!model) return;

    QList<WalletModel::AssetInfo> assets = model->listAssets();

    for (const auto& asset : assets) {
        QString label = QString("%1 (%2)").arg(asset.ticker, asset.asset_id.left(8) + "...");
        combo->addItem(label, QVariant::fromValue(asset.asset_id));
    }
}

QString SpotTermSheetPage::getAssetIdFromCombo(QComboBox* combo) const
{
    QString data = combo->currentData().toString();
    // Return empty QString for native asset - "native" is a UI sentinel, not a valid asset_id
    return (data == "native") ? QString() : data;
}

bool SpotTermSheetPage::isNativeAsset(QComboBox* combo) const
{
    // Check raw combo data directly (not via getAssetIdFromCombo which filters out "native")
    return combo->currentData().toString() == "native";
}

int SpotTermSheetPage::getAssetDecimals(QComboBox* combo) const
{
    if (isNativeAsset(combo)) {
        return 8; // TSC decimals
    }

    // Query asset info for decimals
    WalletModel* model = qobject_cast<SpotContractBuilder*>(wizard())->walletModel;
    if (!model) return 8;

    QString assetId = getAssetIdFromCombo(combo);
    WalletModel::AssetInfo info = model->getAssetInfo(assetId);

    return info.decimals;
}

// ============================================================================
// SpotReviewPage
// ============================================================================

SpotReviewPage::SpotReviewPage(ContractWizard* wizard, QWidget* parent)
    : ContractReviewPage(wizard, parent)
{
    setTitle(tr("Spot Contract - Review && Create Offer"));
    setSubTitle(tr("Review the atomic swap summary below. Click 'Finish' to create the offer."));
}

QString SpotReviewPage::formatOfferSummary() const
{
    double yourAmount = field("yourAmount").toDouble();
    double desiredAmount = field("desiredAmount").toDouble();
    QString yourDest = field("yourDestAddress").toString();
    QString counterpartyDest = field("counterpartyDestAddress").toString();

    // Get asset labels
    bool yourIsNative = field("yourIsNative").toBool();
    bool desiredIsNative = field("desiredIsNative").toBool();

    QString yourAsset = "TSC";
    QString desiredAsset = "TSC";

    SpotContractBuilder* builder = qobject_cast<SpotContractBuilder*>(wizard());
    if (builder && builder->getWalletModel()) {
        if (!yourIsNative) {
            QString assetId = field("yourAssetId").toString();
            WalletModel::AssetInfo info = builder->getWalletModel()->getAssetInfo(assetId);
            if (!info.ticker.isEmpty()) {
                yourAsset = info.ticker;
            }
        }
        if (!desiredIsNative) {
            QString assetId = field("desiredAssetId").toString();
            WalletModel::AssetInfo info = builder->getWalletModel()->getAssetInfo(assetId);
            if (!info.ticker.isEmpty()) {
                desiredAsset = info.ticker;
            }
        }
    }

    // Calculate exchange rate
    double exchangeRate = 0.0;
    if (yourAmount > 0.0) {
        exchangeRate = desiredAmount / yourAmount;
    }

    QString summary;
    summary += tr("<h3>Atomic Swap Summary:</h3>");
    summary += QStringLiteral("<ul>");
    summary += tr("<li><b>Your Offer:</b> %1 %2</li>").arg(yourAmount, 0, 'f', 8).arg(yourAsset);
    summary += tr("<li><b>You Receive:</b> %1 %2</li>").arg(desiredAmount, 0, 'f', 8).arg(desiredAsset);
    summary += tr("<li><b>Exchange Rate:</b> %1 %2 per 1 %3</li>")
                .arg(exchangeRate, 0, 'f', 8)
                .arg(desiredAsset)
                .arg(yourAsset);
    summary += QStringLiteral("</ul>");

    summary += tr("<h3>Settlement:</h3>");
    summary += QStringLiteral("<ul>");
    summary += tr("<li><b>Type:</b> Atomic swap (instant settlement)</li>");
    summary += tr("<li><b>Transaction:</b> Single CoinJoin-style PSBT</li>");
    summary += tr("<li><b>Both parties:</b> Contribute inputs and receive outputs simultaneously</li>");
    summary += tr("<li><b>No maturity:</b> Settles in one transaction</li>");
    summary += QStringLiteral("</ul>");

    summary += tr("<h3>Fair-Sign Policy:</h3>");
    summary += QStringLiteral("<ul>");
    summary += tr("<li><b>Adaptor signatures:</b> REQUIRED for atomic execution</li>");
    summary += tr("<li><b>Reveal mode:</b> Lock-step (2-phase commit)</li>");
    summary += tr("<li><b>Ceremony timeout:</b> 600s (10 minutes)</li>");
    summary += QStringLiteral("</ul>");

    summary += tr("<h3>Addresses:</h3>");
    summary += QStringLiteral("<ul>");
    summary += tr("<li><b>Your Destination:</b> <code>%1</code></li>").arg(yourDest);
    if (!counterpartyDest.isEmpty()) {
        summary += tr("<li><b>Counterparty Destination:</b> <code>%1</code></li>").arg(counterpartyDest);
    } else {
        summary += tr("<li><b>Counterparty Destination:</b> <i>(will be provided by acceptor)</i></li>");
    }
    summary += QStringLiteral("</ul>");

    summary += tr("<h3>Next Steps:</h3>");
    summary += QStringLiteral("<ul>");
    summary += tr("<li>1. Offer will be published to the bulletin board</li>");
    summary += tr("<li>2. Counterparty reviews and accepts with their address</li>");

    // Add commitment proof workflow if enabled
    bool requireCommitment = field("requireCommitmentProof").toBool();
    if (requireCommitment) {
        summary += tr("<li>3. Both parties build PSBTs and join them</li>");
        summary += tr("<li>4. <b>Each party adds commitment proof</b> (proves decryption capability)</li>");
        summary += tr("<li style='margin-left: 20px;'>• Unwrap DEK from PSBT asset output</li>");
        summary += tr("<li style='margin-left: 20px;'>• Decrypt counterparty's ICU payload</li>");
        summary += tr("<li style='margin-left: 20px;'>• Compute hash(canonical_text | own_receive_addr)</li>");
        summary += tr("<li style='margin-left: 20px;'>• Add OP_RETURN commitment to transaction</li>");
        summary += tr("<li>5. Both parties verify commitments then sign</li>");
        summary += tr("<li>6. Transaction is broadcast with 2 OP_RETURN commitment proofs</li>");
    } else {
        summary += tr("<li>3. Both parties build and sign the atomic swap PSBT</li>");
        summary += tr("<li>4. Transaction is broadcast and settles instantly</li>");
    }

    summary += QStringLiteral("</ul>");

    if (requireCommitment) {
        summary += tr("<h3>Commitment Proof Security:</h3>");
        summary += QStringLiteral("<ul>");
        summary += tr("<li>✓ Cryptographic proof of decryption capability</li>");
        summary += tr("<li>✓ No plaintext transmission (extracted from PSBT only)</li>");
        summary += tr("<li>✓ Commitment binds to specific recipient address</li>");
        summary += tr("<li>✓ Provides proof of acceptance before signing</li>");
        summary += QStringLiteral("</ul>");
    }

    return summary;
}
