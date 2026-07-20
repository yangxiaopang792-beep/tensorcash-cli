// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <qt/crosschaincontractbuilder.h>
#include <qt/walletmodel.h>
#include <qt/guiutil.h>
#include <qt/themehelpers.h>
#include <logging.h>

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QGroupBox>
#include <QLabel>
#include <QCheckBox>
#include <QComboBox>
#include <QDoubleSpinBox>
#include <QSpinBox>
#include <QLineEdit>
#include <QPushButton>
#include <QMessageBox>
#include <QScrollArea>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QUuid>

// ============================================================================
// CrossChainContractBuilder
// ============================================================================

CrossChainContractBuilder::CrossChainContractBuilder(WalletModel* model, QWidget* parent)
    : ContractWizard(model, parent)
{
    setWindowTitle(tr("Cross-Chain Settlement Offer"));
    setMinimumSize(750, 600);
    resize(850, 700);

    setPage(Page_TermSheet, new CrossChainTermSheetPage(this));
    setPage(Page_Review, new CrossChainReviewPage(this, this));
    setStartId(Page_TermSheet);
}

CrossChainContractBuilder::~CrossChainContractBuilder()
{
}

bool CrossChainContractBuilder::validateTerms()
{
    if (field("tscAmount").toDouble() <= 0) {
        QMessageBox::warning(this, tr("Validation Error"),
            tr("TSC leg amount must be greater than zero."));
        return false;
    }
    if (field("externalAmount").toDouble() <= 0) {
        QMessageBox::warning(this, tr("Validation Error"),
            tr("External leg amount must be greater than zero."));
        return false;
    }
    if (field("settlementAddress").toString().isEmpty()) {
        QMessageBox::warning(this, tr("Validation Error"),
            tr("A settlement profile must be selected (provides the external settlement address)."));
        return false;
    }
    if (field("tscDestAddress").toString().isEmpty()) {
        QMessageBox::warning(this, tr("Validation Error"),
            tr("TSC destination address is required."));
        return false;
    }

    // Timeout validation: the first funder must have the LONGER lock time
    // (they need more protection since they fund first).  The gap between
    // the first funder's lock and the second funder's lock must exceed
    // claim_budget + reorg_margin.
    int claimBudget = field("claimBudgetSeconds").toInt();
    int reorgMargin = field("reorgMarginSeconds").toInt();
    int externalLock = field("externalLockSeconds").toInt();
    int tscLockBlocks = field("tscLockBlocks").toInt();
    QString fundingOrder = field("fundingOrder").toString();

    // Approximate TSC lock in seconds (10-minute blocks)
    int tscLockSeconds = tscLockBlocks * 600;

    // The first funder must have the longer lock
    int firstFunderLock, secondFunderLock;
    QString firstFunderName, secondFunderName;
    if (fundingOrder == "tsc_first") {
        firstFunderLock = tscLockSeconds;
        secondFunderLock = externalLock;
        firstFunderName = tr("TSC");
        secondFunderName = tr("External");
    } else {
        firstFunderLock = externalLock;
        secondFunderLock = tscLockSeconds;
        firstFunderName = tr("External");
        secondFunderName = tr("TSC");
    }

    if (firstFunderLock <= secondFunderLock) {
        QMessageBox::warning(this, tr("Timeout Policy"),
            tr("%1 funds first but has a shorter or equal lock (%2s) "
               "than %3 (%4s).\n\nThe first funder must have the longer "
               "lock time for refund safety.")
            .arg(firstFunderName).arg(firstFunderLock)
            .arg(secondFunderName).arg(secondFunderLock));
        return false;
    }

    int gap = firstFunderLock - secondFunderLock;
    int required = claimBudget + reorgMargin;

    if (gap < required) {
        QMessageBox::warning(this, tr("Timeout Policy"),
            tr("Timeout gap (%1s) must be >= claim_budget + reorg_margin (%2s).\n\n"
               "Increase the first funder's lock time or decrease the second "
               "funder's, or reduce claim budget / reorg margin.")
            .arg(gap).arg(required));
        return false;
    }

    return true;
}

bool CrossChainContractBuilder::createOffer()
{
    try {
        if (!walletModel) {
            QMessageBox::critical(this, tr("Error"), tr("Wallet model not available"));
            return false;
        }

        // Build the cross_chain_spot_v1 payload
        QJsonObject payload;
        payload["schema"] = QStringLiteral("cross_chain_spot_v1");
        payload["id"] = QUuid::createUuid().toString(QUuid::WithoutBraces);
        payload["contract_kind"] = QStringLiteral("spot_contract");
        payload["role"] = QStringLiteral("maker");
        payload["price_mode"] = QStringLiteral("manual_terms");

        // TSC leg
        bool tscIsNative = field("tscIsNative").toBool();
        QString tscAssetId = field("tscAssetId").toString();
        double tscAmount = field("tscAmount").toDouble();
        int tscDecimals = 8;
        if (!tscIsNative && walletModel) {
            WalletModel::AssetInfo info = walletModel->getAssetInfo(tscAssetId);
            if (info.has_decimals) tscDecimals = info.decimals;
        }
        int64_t tscUnits = static_cast<int64_t>(std::llround(tscAmount * std::pow(10.0, tscDecimals)));

        QJsonObject tscLeg;
        tscLeg["asset_id"] = tscIsNative ? QStringLiteral("native") : tscAssetId;
        tscLeg["units"] = QString::number(tscUnits);
        payload["tsc_leg"] = tscLeg;

        // External leg
        QString chain = field("externalChain").toString();
        QString externalAsset = field("externalAsset").toString();
        double externalAmount = field("externalAmount").toDouble();
        QString adapter = field("adapter").toString();
        QString settlementAddress = field("settlementAddress").toString();

        // External leg units: 8 decimals for BTC, 18 for ETH, 6 for USDT/TRON
        int externalDecimals = 8;
        if (chain == "ethereum") externalDecimals = 18;
        else if (chain == "tron") externalDecimals = 6;

        // Convert display amount to decimal-string base units.
        //
        // The QDoubleSpinBox is limited to 8 decimal digits, so the actual
        // user-visible precision is at most ~8 fractional digits regardless
        // of the chain's native decimal count.  For chains with more decimals
        // (ETH: 18), we scale to 10^15 (the largest power that fits in a
        // double without precision loss for 8-digit inputs) and then
        // zero-pad the remaining (decimals - 15) digits.  This is safe
        // because the user cannot enter sub-picoether amounts through the
        // spinner, and the bridge re-validates the decimal string.
        QString externalUnitsStr;
        if (externalDecimals <= 15) {
            int64_t externalUnits = static_cast<int64_t>(std::llround(externalAmount * std::pow(10.0, externalDecimals)));
            externalUnitsStr = QString::number(externalUnits);
        } else {
            // Scale to 10^15 (max safe double precision), then zero-pad
            int safePow = 15;
            int64_t scaledUnits = static_cast<int64_t>(std::llround(externalAmount * std::pow(10.0, safePow)));
            externalUnitsStr = QString::number(scaledUnits);
            int remaining = externalDecimals - safePow;
            for (int i = 0; i < remaining; ++i) externalUnitsStr += '0';
        }

        QJsonObject externalLeg;
        externalLeg["chain"] = chain;
        externalLeg["asset"] = externalAsset;
        externalLeg["units"] = externalUnitsStr;
        externalLeg["settlement_address"] = settlementAddress;
        externalLeg["refund_address"] = settlementAddress;  // Same address for v1
        externalLeg["adapter"] = adapter;
        payload["external_leg"] = externalLeg;

        // Funding order
        payload["funding_order"] = field("fundingOrder").toString();

        // Confirmation policy
        QJsonObject confPolicy;
        confPolicy["external_min_conf"] = field("externalMinConf").toInt();
        confPolicy["tsc_min_conf"] = field("tscMinConf").toInt();
        confPolicy["reorg_conf"] = field("reorgConf").toInt();
        payload["confirmation_policy"] = confPolicy;

        // Timeout policy
        QJsonObject timeoutPolicy;
        timeoutPolicy["external_lock_seconds"] = field("externalLockSeconds").toInt();
        timeoutPolicy["tsc_lock_blocks"] = field("tscLockBlocks").toInt();
        timeoutPolicy["claim_budget_seconds"] = field("claimBudgetSeconds").toInt();
        timeoutPolicy["reorg_margin_seconds"] = field("reorgMarginSeconds").toInt();
        int claimBudget = field("claimBudgetSeconds").toInt();
        int reorgMargin = field("reorgMarginSeconds").toInt();
        timeoutPolicy["min_timeout_gap_seconds"] = claimBudget + reorgMargin;
        payload["timeout_policy"] = timeoutPolicy;

        // Fee policy
        // v1: refund_strategy mirrors claim_strategy — both use the same
        // fee-bump approach per chain (rbf_or_cpfp for UTXO, gas_escalator
        // for account-model chains).  A separate refund strategy selector
        // is deferred to a later phase.
        QJsonObject feePolicy;
        QString claimStrategy = field("claimStrategy").toString();
        feePolicy["claim_strategy"] = claimStrategy;
        feePolicy["refund_strategy"] = claimStrategy;
        feePolicy["fee_funding_mode"] = field("feeFundingMode").toString();
        payload["fee_policy"] = feePolicy;

        crossChainPayloadJson = QString::fromUtf8(
            QJsonDocument(payload).toJson(QJsonDocument::Compact));

        // Pre-flight validation via bridge
        auto validateResult = walletModel->crossChainValidatePayload(crossChainPayloadJson);
        if (!validateResult.valid) {
            QMessageBox::critical(this, tr("Payload Validation Failed"),
                tr("The cross-chain payload did not pass validation:\n\n%1").arg(validateResult.error));
            return false;
        }

        // Post the offer via bridge (rides on SpotContract board path)
        auto postResult = walletModel->crossChainPostOffer(crossChainPayloadJson);
        if (!postResult.success) {
            QMessageBox::critical(this, tr("Post Failed"),
                tr("Failed to post cross-chain offer:\n\n%1").arg(postResult.error));
            return false;
        }

        offerId = postResult.offer_id;
        offerJson = crossChainPayloadJson;
        offerFinalized = true;

        // Populate offerData for downstream
        offerData["offer_id"] = offerId;
        offerData["cross_chain_payload"] = crossChainPayloadJson;
        offerData["external_chain"] = chain;
        offerData["adapter"] = adapter;
        offerData["funding_order"] = field("fundingOrder").toString();

        // Build term sheet for bulletin board compatibility
        QJsonObject termSheet;
        termSheet["schema"] = QStringLiteral("cross_chain_spot_v1");
        termSheet["terms"] = payload;
        termSheetJson = QString::fromUtf8(QJsonDocument(termSheet).toJson(QJsonDocument::Compact));

        LogPrintf("CrossChainContractBuilder: Created cross-chain offer ID=%s chain=%s adapter=%s\n",
                  offerId.toStdString().c_str(), chain.toStdString().c_str(),
                  adapter.toStdString().c_str());

        return true;

    } catch (const std::exception& e) {
        QMessageBox::critical(this, tr("Error"),
            tr("Exception: %1").arg(QString::fromStdString(e.what())));
        return false;
    } catch (...) {
        QMessageBox::critical(this, tr("Error"), tr("Unknown exception while creating offer"));
        return false;
    }
}

// ============================================================================
// CrossChainTermSheetPage
// ============================================================================

CrossChainTermSheetPage::CrossChainTermSheetPage(QWidget* parent)
    : QWizardPage(parent)
{
    setTitle(tr("Cross-Chain Settlement - Term Sheet"));
    setupUI();
}

void CrossChainTermSheetPage::setupUI()
{
    QScrollArea* scrollArea = new QScrollArea(this);
    scrollArea->setWidgetResizable(true);
    scrollArea->setFrameShape(QFrame::NoFrame);

    QWidget* container = new QWidget();
    QVBoxLayout* mainLayout = new QVBoxLayout(container);

    // --- TSC Leg ---
    QGroupBox* tscGroup = new QGroupBox(tr("TSC Leg (Your Side)"), this);
    QGridLayout* tscLayout = new QGridLayout(tscGroup);

    tscLayout->addWidget(new QLabel(tr("Asset:"), this), 0, 0);
    tscAssetCombo = new QComboBox(this);
    tscAssetCombo->setMinimumWidth(150);
    tscLayout->addWidget(tscAssetCombo, 0, 1);
    connect(tscAssetCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &CrossChainTermSheetPage::onTscAssetChanged);

    tscLayout->addWidget(new QLabel(tr("Amount:"), this), 0, 2);
    tscAmountSpin = new QDoubleSpinBox(this);
    tscAmountSpin->setDecimals(8);
    tscAmountSpin->setMaximum(21000000.0);
    tscAmountSpin->setMinimum(0.00000001);
    tscAmountSpin->setValue(1.0);
    tscLayout->addWidget(tscAmountSpin, 0, 3);
    connect(tscAmountSpin, QOverload<double>::of(&QDoubleSpinBox::valueChanged),
            this, &CrossChainTermSheetPage::onTscAmountChanged);

    tscLayout->addWidget(new QLabel(tr("TSC Destination:"), this), 1, 0);
    tscDestEdit = new QLineEdit(this);
    tscDestEdit->setPlaceholderText(tr("Address where you receive TSC"));
    tscLayout->addWidget(tscDestEdit, 1, 1, 1, 2);
    generateTscDestButton = new QPushButton(tr("Generate"), this);
    tscLayout->addWidget(generateTscDestButton, 1, 3);
    connect(generateTscDestButton, &QPushButton::clicked,
            this, &CrossChainTermSheetPage::onGenerateTscAddress);

    // Hidden fields
    QCheckBox* tscIsNativeCheck = new QCheckBox(this);
    tscIsNativeCheck->setVisible(false);
    QLineEdit* tscAssetIdEdit = new QLineEdit(this);
    tscAssetIdEdit->setVisible(false);

    registerField("tscIsNative", tscIsNativeCheck);
    registerField("tscAssetId", tscAssetIdEdit);
    registerField("tscAmount", tscAmountSpin, "value");
    registerField("tscDestAddress*", tscDestEdit);

    tscGroup->setLayout(tscLayout);
    mainLayout->addWidget(tscGroup);

    // --- External Leg ---
    QGroupBox* extGroup = new QGroupBox(tr("External Leg (Counterparty Chain)"), this);
    QGridLayout* extLayout = new QGridLayout(extGroup);

    extLayout->addWidget(new QLabel(tr("Chain:"), this), 0, 0);
    externalChainCombo = new QComboBox(this);
    externalChainCombo->addItem(tr("Bitcoin (BTC)"), QStringLiteral("btc"));
    externalChainCombo->addItem(tr("Ethereum (ETH)"), QStringLiteral("ethereum"));
    externalChainCombo->addItem(tr("Tron (TRX)"), QStringLiteral("tron"));
    extLayout->addWidget(externalChainCombo, 0, 1);
    connect(externalChainCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &CrossChainTermSheetPage::onExternalChainChanged);

    extLayout->addWidget(new QLabel(tr("Asset:"), this), 0, 2);
    externalAssetEdit = new QLineEdit(this);
    externalAssetEdit->setText(QStringLiteral("BTC"));
    extLayout->addWidget(externalAssetEdit, 0, 3);

    extLayout->addWidget(new QLabel(tr("Amount:"), this), 1, 0);
    externalAmountSpin = new QDoubleSpinBox(this);
    externalAmountSpin->setDecimals(8);
    externalAmountSpin->setMaximum(21000000.0);
    externalAmountSpin->setMinimum(0.00000001);
    externalAmountSpin->setValue(1.0);
    extLayout->addWidget(externalAmountSpin, 1, 1);
    connect(externalAmountSpin, QOverload<double>::of(&QDoubleSpinBox::valueChanged),
            this, &CrossChainTermSheetPage::onExternalAmountChanged);

    extLayout->addWidget(new QLabel(tr("Adapter:"), this), 1, 2);
    adapterCombo = new QComboBox(this);
    adapterCombo->addItem(tr("BTC Scriptless v1"), QStringLiteral("btc_scriptless_v1"));
    adapterCombo->addItem(tr("ETH HTLC v1"), QStringLiteral("eth_htlc_v1"));
    adapterCombo->addItem(tr("TRON HTLC v1"), QStringLiteral("tron_htlc_v1"));
    extLayout->addWidget(adapterCombo, 1, 3);

    extLayout->addWidget(new QLabel(tr("Settlement Profile:"), this), 2, 0);
    profileCombo = new QComboBox(this);
    extLayout->addWidget(profileCombo, 2, 1, 1, 2);
    connect(profileCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &CrossChainTermSheetPage::onProfileSelected);

    profileAddressLabel = new QLabel(this);
    profileAddressLabel->setStyleSheet(QStringLiteral("QLabel { color: %1; font-family: monospace; font-size: 9pt; }").arg(ThemeHelpers::accentTextColor()));
    profileAddressLabel->setWordWrap(true);
    extLayout->addWidget(profileAddressLabel, 3, 0, 1, 4);

    // Hidden fields for external leg
    QLineEdit* externalChainEdit = new QLineEdit(this);
    externalChainEdit->setVisible(false);
    QLineEdit* settlementAddressEdit = new QLineEdit(this);
    settlementAddressEdit->setVisible(false);
    QLineEdit* adapterEdit = new QLineEdit(this);
    adapterEdit->setVisible(false);

    registerField("externalChain", externalChainEdit);
    registerField("externalAsset", externalAssetEdit);
    registerField("externalAmount", externalAmountSpin, "value");
    registerField("settlementAddress", settlementAddressEdit);
    registerField("adapter", adapterEdit);

    extGroup->setLayout(extLayout);
    mainLayout->addWidget(extGroup);

    // --- Exchange Rate ---
    exchangeRateLabel = new QLabel(tr("Rate: --"), this);
    exchangeRateLabel->setStyleSheet(QStringLiteral("QLabel { font-weight: bold; color: %1; font-size: 11pt; }").arg(ThemeHelpers::accentTextColor()));
    exchangeRateLabel->setAlignment(Qt::AlignCenter);
    mainLayout->addWidget(exchangeRateLabel);

    // --- Funding Order ---
    QGroupBox* fundingGroup = new QGroupBox(tr("Funding Order"), this);
    QHBoxLayout* fundingLayout = new QHBoxLayout(fundingGroup);
    fundingLayout->addWidget(new QLabel(tr("Who funds first:"), this));
    fundingOrderCombo = new QComboBox(this);
    fundingOrderCombo->addItem(tr("TSC First"), QStringLiteral("tsc_first"));
    fundingOrderCombo->addItem(tr("External First"), QStringLiteral("external_first"));
    fundingLayout->addWidget(fundingOrderCombo);
    fundingLayout->addStretch();
    fundingGroup->setLayout(fundingLayout);
    mainLayout->addWidget(fundingGroup);

    QLineEdit* fundingOrderEdit = new QLineEdit(this);
    fundingOrderEdit->setVisible(false);
    registerField("fundingOrder", fundingOrderEdit);

    // --- Confirmation Policy ---
    QGroupBox* confGroup = new QGroupBox(tr("Confirmation Policy"), this);
    QGridLayout* confLayout = new QGridLayout(confGroup);

    confLayout->addWidget(new QLabel(tr("External min conf:"), this), 0, 0);
    externalMinConfSpin = new QSpinBox(this);
    externalMinConfSpin->setRange(1, 100);
    externalMinConfSpin->setValue(6);
    confLayout->addWidget(externalMinConfSpin, 0, 1);

    confLayout->addWidget(new QLabel(tr("TSC min conf:"), this), 0, 2);
    tscMinConfSpin = new QSpinBox(this);
    tscMinConfSpin->setRange(1, 100);
    tscMinConfSpin->setValue(1);
    confLayout->addWidget(tscMinConfSpin, 0, 3);

    confLayout->addWidget(new QLabel(tr("Reorg conf:"), this), 0, 4);
    reorgConfSpin = new QSpinBox(this);
    reorgConfSpin->setRange(1, 100);
    reorgConfSpin->setValue(6);
    confLayout->addWidget(reorgConfSpin, 0, 5);

    registerField("externalMinConf", externalMinConfSpin);
    registerField("tscMinConf", tscMinConfSpin);
    registerField("reorgConf", reorgConfSpin);

    confGroup->setLayout(confLayout);
    mainLayout->addWidget(confGroup);

    // --- Timeout Policy ---
    QGroupBox* timeGroup = new QGroupBox(tr("Timeout Policy"), this);
    QGridLayout* timeLayout = new QGridLayout(timeGroup);

    timeLayout->addWidget(new QLabel(tr("External lock (seconds):"), this), 0, 0);
    externalLockSpin = new QSpinBox(this);
    externalLockSpin->setRange(3600, 604800);
    externalLockSpin->setValue(86400);
    externalLockSpin->setSingleStep(3600);
    timeLayout->addWidget(externalLockSpin, 0, 1);

    timeLayout->addWidget(new QLabel(tr("TSC lock (blocks):"), this), 0, 2);
    tscLockSpin = new QSpinBox(this);
    tscLockSpin->setRange(6, 2016);
    tscLockSpin->setValue(288);
    timeLayout->addWidget(tscLockSpin, 0, 3);

    timeLayout->addWidget(new QLabel(tr("Claim budget (seconds):"), this), 1, 0);
    claimBudgetSpin = new QSpinBox(this);
    claimBudgetSpin->setRange(1800, 86400);
    claimBudgetSpin->setValue(21600);
    claimBudgetSpin->setSingleStep(1800);
    timeLayout->addWidget(claimBudgetSpin, 1, 1);

    timeLayout->addWidget(new QLabel(tr("Reorg margin (seconds):"), this), 1, 2);
    reorgMarginSpin = new QSpinBox(this);
    reorgMarginSpin->setRange(600, 86400);
    reorgMarginSpin->setValue(3600);
    reorgMarginSpin->setSingleStep(600);
    timeLayout->addWidget(reorgMarginSpin, 1, 3);

    registerField("externalLockSeconds", externalLockSpin);
    registerField("tscLockBlocks", tscLockSpin);
    registerField("claimBudgetSeconds", claimBudgetSpin);
    registerField("reorgMarginSeconds", reorgMarginSpin);

    timeoutGapLabel = new QLabel(this);
    timeoutGapLabel->setStyleSheet(QStringLiteral("QLabel { color: %1; font-size: 9pt; }").arg(ThemeHelpers::mutedTextColor()));
    timeLayout->addWidget(timeoutGapLabel, 2, 0, 1, 4);

    timeGroup->setLayout(timeLayout);
    mainLayout->addWidget(timeGroup);

    // --- Fee Policy ---
    QGroupBox* feeGroup = new QGroupBox(tr("Fee Policy"), this);
    QGridLayout* feeLayout = new QGridLayout(feeGroup);

    feeLayout->addWidget(new QLabel(tr("Claim strategy:"), this), 0, 0);
    claimStrategyCombo = new QComboBox(this);
    claimStrategyCombo->addItem(tr("RBF or CPFP (UTXO chains)"), QStringLiteral("rbf_or_cpfp"));
    claimStrategyCombo->addItem(tr("Gas Escalator (ETH/TRON)"), QStringLiteral("gas_escalator"));
    feeLayout->addWidget(claimStrategyCombo, 0, 1);

    feeLayout->addWidget(new QLabel(tr("Fee funding mode:"), this), 1, 0);
    feeFundingModeCombo = new QComboBox(this);
    feeFundingModeCombo->addItem(tr("Reserved UTXO"), QStringLiteral("reserved_utxo"));
    feeFundingModeCombo->addItem(tr("Reserved Balance"), QStringLiteral("reserved_balance"));
    feeLayout->addWidget(feeFundingModeCombo, 1, 1);

    QLineEdit* claimStrategyEdit = new QLineEdit(this);
    claimStrategyEdit->setVisible(false);
    QLineEdit* feeFundingModeEdit = new QLineEdit(this);
    feeFundingModeEdit->setVisible(false);
    registerField("claimStrategy", claimStrategyEdit);
    registerField("feeFundingMode", feeFundingModeEdit);

    feeGroup->setLayout(feeLayout);
    mainLayout->addWidget(feeGroup);

    mainLayout->addStretch();

    scrollArea->setWidget(container);
    QVBoxLayout* pageLayout = new QVBoxLayout(this);
    pageLayout->setContentsMargins(0, 0, 0, 0);
    pageLayout->addWidget(scrollArea);
    setLayout(pageLayout);

    // Wheel event filters
    GUIUtil::InstallWheelEventFilter(tscAssetCombo);
    GUIUtil::InstallWheelEventFilter(tscAmountSpin);
    GUIUtil::InstallWheelEventFilter(externalChainCombo);
    GUIUtil::InstallWheelEventFilter(externalAmountSpin);
    GUIUtil::InstallWheelEventFilter(adapterCombo);
    GUIUtil::InstallWheelEventFilter(profileCombo);
    GUIUtil::InstallWheelEventFilter(fundingOrderCombo);
    GUIUtil::InstallWheelEventFilter(claimStrategyCombo);
    GUIUtil::InstallWheelEventFilter(feeFundingModeCombo);
}

void CrossChainTermSheetPage::initializePage()
{
    if (tscAssetCombo->count() == 0) {
        populateAssetComboBox(tscAssetCombo, true);
    }

    populateProfileCombo();

    if (tscDestEdit->text().isEmpty()) {
        onGenerateTscAddress();
    }

    // Set defaults for chain-dependent fields
    onExternalChainChanged(0);
    updateCalculations();
}

bool CrossChainTermSheetPage::validatePage()
{
    CrossChainContractBuilder* builder = qobject_cast<CrossChainContractBuilder*>(wizard());
    if (!builder) return false;

    // Store hidden field values from combos
    setField("tscIsNative", isNativeAsset(tscAssetCombo));
    setField("tscAssetId", getAssetIdFromCombo(tscAssetCombo));
    setField("externalChain", externalChainCombo->currentData().toString());
    setField("adapter", adapterCombo->currentData().toString());
    setField("fundingOrder", fundingOrderCombo->currentData().toString());
    setField("claimStrategy", claimStrategyCombo->currentData().toString());
    setField("feeFundingMode", feeFundingModeCombo->currentData().toString());

    // Settlement address from selected profile
    if (profileCombo->currentIndex() >= 0) {
        setField("settlementAddress", profileCombo->currentData().toString());
    }

    return builder->validateTerms();
}

bool CrossChainTermSheetPage::isComplete() const
{
    return tscDestEdit && !tscDestEdit->text().trimmed().isEmpty()
        && profileCombo && profileCombo->currentIndex() >= 0;
}

void CrossChainTermSheetPage::onTscAssetChanged(int /*index*/)
{
    int decimals = getAssetDecimals(tscAssetCombo);
    tscAmountSpin->setDecimals(decimals);
    updateCalculations();
}

void CrossChainTermSheetPage::onTscAmountChanged(double /*value*/)
{
    updateCalculations();
}

void CrossChainTermSheetPage::onExternalChainChanged(int /*index*/)
{
    QString chain = externalChainCombo->currentData().toString();

    // Update adapter default and external asset
    if (chain == "btc") {
        adapterCombo->setCurrentIndex(0);  // btc_scriptless_v1
        externalAssetEdit->setText(QStringLiteral("BTC"));
        claimStrategyCombo->setCurrentIndex(0);  // rbf_or_cpfp
        feeFundingModeCombo->setCurrentIndex(0);  // reserved_utxo
        externalMinConfSpin->setValue(6);
    } else if (chain == "ethereum") {
        adapterCombo->setCurrentIndex(1);  // eth_htlc_v1
        externalAssetEdit->setText(QStringLiteral("ETH"));
        claimStrategyCombo->setCurrentIndex(1);  // gas_escalator
        feeFundingModeCombo->setCurrentIndex(1);  // reserved_balance
        fundingOrderCombo->setCurrentIndex(1);    // external_first for ETH/TRON
        externalMinConfSpin->setValue(12);
    } else if (chain == "tron") {
        adapterCombo->setCurrentIndex(2);  // tron_htlc_v1
        externalAssetEdit->setText(QStringLiteral("USDT"));
        claimStrategyCombo->setCurrentIndex(1);  // gas_escalator
        feeFundingModeCombo->setCurrentIndex(1);  // reserved_balance
        fundingOrderCombo->setCurrentIndex(1);    // external_first for ETH/TRON
        externalMinConfSpin->setValue(19);
    }

    // Re-populate profile combo filtered by chain
    populateProfileCombo();
    updateCalculations();
}

void CrossChainTermSheetPage::onExternalAmountChanged(double /*value*/)
{
    updateCalculations();
}

void CrossChainTermSheetPage::onProfileSelected(int index)
{
    if (index < 0) {
        profileAddressLabel->clear();
        return;
    }

    QString address = profileCombo->currentData().toString();
    profileAddressLabel->setText(tr("Settlement address: %1").arg(address));
    Q_EMIT completeChanged();
}

void CrossChainTermSheetPage::onGenerateTscAddress()
{
    CrossChainContractBuilder* builder = qobject_cast<CrossChainContractBuilder*>(wizard());
    if (!builder) return;

    WalletModel* model = builder->walletModel;
    if (!model) {
        QMessageBox::warning(this, tr("Error"), tr("Wallet model not available"));
        return;
    }

    QString newAddress = model->getNewAddress("Cross-chain TSC receive");
    if (!newAddress.isEmpty()) {
        tscDestEdit->setText(newAddress);
    }
}

void CrossChainTermSheetPage::updateCalculations()
{
    double tscAmount = tscAmountSpin->value();
    double externalAmount = externalAmountSpin->value();

    QString externalAsset = externalAssetEdit->text();

    if (tscAmount > 0.0 && externalAmount > 0.0) {
        double rate = externalAmount / tscAmount;
        exchangeRateLabel->setText(
            tr("Rate: 1 TSC = %1 %2").arg(rate, 0, 'f', 8).arg(externalAsset));
    } else {
        exchangeRateLabel->setText(tr("Rate: --"));
    }

    // Timeout gap display (directional: first funder must have longer lock)
    int externalLock = externalLockSpin->value();
    int tscLockBlocks = tscLockSpin->value();
    int tscLockSeconds = tscLockBlocks * 600;
    int required = claimBudgetSpin->value() + reorgMarginSpin->value();

    QString fundOrder = fundingOrderCombo->currentData().toString();
    int firstLock = (fundOrder == "tsc_first") ? tscLockSeconds : externalLock;
    int secondLock = (fundOrder == "tsc_first") ? externalLock : tscLockSeconds;
    int gap = firstLock - secondLock;

    bool ok = (firstLock > secondLock) && (gap >= required);
    QString gapColor = ok ? "#4CAF50" : "#c62828";
    QString gapText;
    if (firstLock <= secondLock) {
        gapText = tr("First funder's lock must be longer than second funder's");
    } else {
        gapText = tr("Timeout gap: %1s (required: >= %2s)").arg(gap).arg(required);
    }
    timeoutGapLabel->setText(gapText);
    timeoutGapLabel->setStyleSheet(
        QString("QLabel { color: %1; font-size: 9pt; }").arg(gapColor));
}

void CrossChainTermSheetPage::populateProfileCombo()
{
    profileCombo->clear();
    profileAddressLabel->clear();

    CrossChainContractBuilder* builder = qobject_cast<CrossChainContractBuilder*>(wizard());
    WalletModel* model = builder ? builder->getWalletModel() : nullptr;
    if (!model) return;

    QString selectedChain = externalChainCombo->currentData().toString();

    QList<WalletModel::SettlementProfileItem> profiles = model->settlementProfileList();
    for (const auto& p : profiles) {
        if (p.chain == selectedChain) {
            QString label = QString("%1 (%2)").arg(p.label, p.address.left(12) + "...");
            profileCombo->addItem(label, QVariant::fromValue(p.address));
        }
    }

    if (profileCombo->count() == 0) {
        profileCombo->addItem(tr("No profiles for this chain"), QString());
        profileAddressLabel->setText(
            tr("Add a settlement profile first via the Profiles button."));
    }
}

void CrossChainTermSheetPage::populateAssetComboBox(QComboBox* combo, bool includeNative)
{
    combo->clear();

    if (includeNative) {
        combo->addItem(tr("TSC (Native)"), QVariant::fromValue(QString("native")));
    }

    CrossChainContractBuilder* builder = qobject_cast<CrossChainContractBuilder*>(wizard());
    WalletModel* model = builder ? builder->getWalletModel() : nullptr;
    if (!model) return;

    QList<WalletModel::AssetInfo> assets = model->listAssets();
    for (const auto& asset : assets) {
        QString label = QString("%1 (%2)").arg(asset.ticker, asset.asset_id.left(8) + "...");
        combo->addItem(label, QVariant::fromValue(asset.asset_id));
    }
}

QString CrossChainTermSheetPage::getAssetIdFromCombo(QComboBox* combo) const
{
    QString data = combo->currentData().toString();
    return (data == "native") ? QString() : data;
}

bool CrossChainTermSheetPage::isNativeAsset(QComboBox* combo) const
{
    return combo->currentData().toString() == "native";
}

int CrossChainTermSheetPage::getAssetDecimals(QComboBox* combo) const
{
    if (isNativeAsset(combo)) return 8;

    CrossChainContractBuilder* builder = qobject_cast<CrossChainContractBuilder*>(wizard());
    WalletModel* model = builder ? builder->walletModel : nullptr;
    if (!model) return 8;

    QString assetId = getAssetIdFromCombo(combo);
    WalletModel::AssetInfo info = model->getAssetInfo(assetId);
    return info.has_decimals ? info.decimals : 8;
}

// ============================================================================
// CrossChainReviewPage
// ============================================================================

CrossChainReviewPage::CrossChainReviewPage(ContractWizard* wizard, QWidget* parent)
    : ContractReviewPage(wizard, parent)
{
    setTitle(tr("Cross-Chain Offer - Review & Create"));
    setSubTitle(tr("Review the cross-chain settlement terms. Click 'Finish' to create and publish."));
}

QString CrossChainReviewPage::formatOfferSummary() const
{
    double tscAmount = field("tscAmount").toDouble();
    double externalAmount = field("externalAmount").toDouble();
    QString externalAsset = field("externalAsset").toString();
    QString externalChain = field("externalChain").toString();
    QString adapter = field("adapter").toString();
    QString fundingOrder = field("fundingOrder").toString();
    QString settlementAddress = field("settlementAddress").toString();
    QString tscDest = field("tscDestAddress").toString();

    QString chainLabel = externalChain.toUpper();
    if (externalChain == "ethereum") chainLabel = "ETH";
    if (externalChain == "tron") chainLabel = "TRON";

    double rate = (tscAmount > 0.0) ? externalAmount / tscAmount : 0.0;

    QString summary;
    summary += tr("<h3>Cross-Chain Settlement Summary</h3>");

    summary += tr("<h4>Trade Legs</h4>") + QStringLiteral("<ul>");
    summary += tr("<li><b>TSC Leg:</b> %1 TSC</li>")
        .arg(tscAmount, 0, 'f', 8);
    summary += tr("<li><b>External Leg:</b> %1 %2 on %3</li>")
        .arg(externalAmount, 0, 'f', 8).arg(externalAsset, chainLabel);
    summary += tr("<li><b>Exchange Rate:</b> 1 TSC = %1 %2</li>")
        .arg(rate, 0, 'f', 8).arg(externalAsset);
    summary += QStringLiteral("</ul>");

    summary += tr("<h4>Settlement</h4>") + QStringLiteral("<ul>");
    summary += tr("<li><b>Adapter:</b> %1</li>").arg(adapter);
    summary += tr("<li><b>Funding Order:</b> %1</li>").arg(fundingOrder);
    summary += tr("<li><b>External Address:</b> <code>%1</code></li>").arg(settlementAddress);
    summary += tr("<li><b>TSC Address:</b> <code>%1</code></li>").arg(tscDest);
    summary += QStringLiteral("</ul>");

    summary += tr("<h4>Confirmation Policy</h4>") + QStringLiteral("<ul>");
    summary += tr("<li><b>External min conf:</b> %1</li>").arg(field("externalMinConf").toInt());
    summary += tr("<li><b>TSC min conf:</b> %1</li>").arg(field("tscMinConf").toInt());
    summary += tr("<li><b>Reorg conf:</b> %1</li>").arg(field("reorgConf").toInt());
    summary += QStringLiteral("</ul>");

    summary += tr("<h4>Timeout Policy</h4>") + QStringLiteral("<ul>");
    summary += tr("<li><b>External lock:</b> %1 seconds (%2 hours)</li>")
        .arg(field("externalLockSeconds").toInt())
        .arg(field("externalLockSeconds").toInt() / 3600.0, 0, 'f', 1);
    summary += tr("<li><b>TSC lock:</b> %1 blocks (~%2 hours)</li>")
        .arg(field("tscLockBlocks").toInt())
        .arg(field("tscLockBlocks").toInt() * 10.0 / 60.0, 0, 'f', 1);
    summary += tr("<li><b>Claim budget:</b> %1 seconds (%2 hours)</li>")
        .arg(field("claimBudgetSeconds").toInt())
        .arg(field("claimBudgetSeconds").toInt() / 3600.0, 0, 'f', 1);
    summary += tr("<li><b>Reorg margin:</b> %1 seconds (%2 hours)</li>")
        .arg(field("reorgMarginSeconds").toInt())
        .arg(field("reorgMarginSeconds").toInt() / 3600.0, 0, 'f', 1);
    summary += QStringLiteral("</ul>");

    summary += tr("<h4>Fee Policy</h4>") + QStringLiteral("<ul>");
    summary += tr("<li><b>Claim/Refund strategy:</b> %1</li>").arg(field("claimStrategy").toString());
    summary += tr("<li><b>Fee funding mode:</b> %1</li>").arg(field("feeFundingMode").toString());
    summary += QStringLiteral("</ul>");

    summary += tr("<h4>Next Steps</h4>") + QStringLiteral("<ul>");
    summary += tr("<li>1. Offer will be published to the bulletin board as a SpotContract payload</li>");
    summary += tr("<li>2. Counterparty reviews cross-chain terms and settlement address</li>");
    summary += tr("<li>3. Both parties establish a cosign session</li>");
    summary += tr("<li>4. Wallet drives the settlement ceremony in background</li>");
    summary += QStringLiteral("</ul>");

    return summary;
}
