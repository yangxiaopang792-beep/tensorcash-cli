// Copyright (c) 2026 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <qt/scalarcfdcontractbuilder.h>
#include <qt/walletmodel.h>
#include <logging.h>

#include <QComboBox>
#include <QDoubleSpinBox>
#include <QFormLayout>
#include <QJsonDocument>
#include <QJsonObject>
#include <QGroupBox>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QScrollArea>
#include <QSpinBox>
#include <QVBoxLayout>

#include <cmath>

namespace {
//! lambda is stored Q16 (lambda_q = lambda * 2^16), matching ScalarCfdLegTerms::lambda_q.
constexpr double SCALAR_LAMBDA_SCALE = 65536.0;
constexpr double SCALAR_LAMBDA_Q_MAX = 4294967295.0; // lambda_q is a uint32
constexpr int DEFAULT_DEADLINE_OFFSET = 144;         // default publication deadline = tip + this (~1 day)
constexpr int DEFAULT_SETTLE_LOCK_GAP = 100;         // settle-lock burial past the deadline (CLTV headroom)
} // namespace

// ============================================================================
// ScalarCfdContractBuilder
// ============================================================================

ScalarCfdContractBuilder::ScalarCfdContractBuilder(WalletModel* model, QWidget* parent)
    : ContractWizard(model, parent)
{
    setWindowTitle(tr("Scalar-feed CFD Builder"));
    setMinimumSize(700, 560);
    resize(820, 640);

    setPage(Page_TermSheet, new ScalarCfdTermSheetPage(this));
    setPage(Page_Review, new ScalarCfdReviewPage(this, this));

    setStartId(Page_TermSheet);
}

ScalarCfdContractBuilder::~ScalarCfdContractBuilder() = default;

QVariantMap ScalarCfdContractBuilder::collectedTerms() const
{
    if (auto* page = qobject_cast<ScalarCfdTermSheetPage*>(this->page(Page_TermSheet))) {
        return page->collectTerms();
    }
    return QVariantMap();
}

bool ScalarCfdContractBuilder::validateTerms()
{
    const QVariantMap t = collectedTerms();

    // Heights: a publication deadline before which the fixing must be published, and a settle-lock CLTV
    // burial that must not precede it.
    const qlonglong deadline = t.value("publication_deadline_height").toLongLong();
    const qlonglong settle = t.value("settle_lock_height").toLongLong();
    if (deadline <= 0) {
        QMessageBox::warning(this, tr("Validation Error"), tr("Publication deadline height must be positive."));
        return false;
    }
    if (settle < deadline) {
        QMessageBox::warning(this, tr("Validation Error"),
            tr("Settle-lock height must be at or after the publication deadline height."));
        return false;
    }

    // v1 is ISSUER_PUBLISHED only, which requires a non-zero underlying (the RPC rejects a zero U and does
    // not support CHAIN_INTRINSIC yet), so U must be exactly 64 hex characters.
    if (t.value("underlying").toString().trimmed().size() != 64) {
        QMessageBox::warning(this, tr("Validation Error"),
            tr("Underlying (U) asset id must be exactly 64 hex characters."));
        return false;
    }
    if (t.value("strike").toString().trimmed().size() != 64) {
        QMessageBox::warning(this, tr("Validation Error"), tr("Strike (K) must be exactly 64 hex characters."));
        return false;
    }
    if (t.value("fallback").toString().trimmed().size() != 64) {
        QMessageBox::warning(this, tr("Validation Error"), tr("Fallback scalar must be exactly 64 hex characters."));
        return false;
    }
    // Asset-collateral opens are not yet supported (build_open is native-only); refuse to persist an
    // unopenable contract, mirroring the Treasury form's guard.
    if (!t.value("collateral").toString().trimmed().isEmpty()) {
        QMessageBox::warning(this, tr("Validation Error"),
            tr("Asset-collateral bilateral CFDs cannot be opened yet — leave Collateral blank (native TSC)."));
        return false;
    }

    // Legs: non-negative integer IM (collateral units) + positive leverage whose lambda_q fits a uint32.
    auto legOk = [&](const QString& imKey, const QString& lamKey, const QString& name) -> bool {
        bool ok = false;
        const qlonglong im = t.value(imKey).toString().trimmed().toLongLong(&ok);
        if (!ok || im < 0) {
            QMessageBox::warning(this, tr("Validation Error"),
                tr("%1 IM must be a non-negative integer (collateral units).").arg(name));
            return false;
        }
        const double lev = t.value(lamKey).toDouble();
        if (!std::isfinite(lev) || lev <= 0.0) {
            QMessageBox::warning(this, tr("Validation Error"),
                tr("%1 leverage must be a positive number.").arg(name));
            return false;
        }
        if (lev * SCALAR_LAMBDA_SCALE > SCALAR_LAMBDA_Q_MAX) {
            QMessageBox::warning(this, tr("Validation Error"), tr("%1 leverage is too large.").arg(name));
            return false;
        }
        return true;
    };
    if (!legOk("long_im", "long_lambda", tr("Long"))) return false;
    if (!legOk("short_im", "short_lambda", tr("Short"))) return false;
    return true;
}

bool ScalarCfdContractBuilder::createOffer()
{
    try {
        if (!walletModel) {
            QMessageBox::critical(this, tr("Error"), tr("Wallet model not available"));
            return false;
        }
        if (!validateTerms()) {
            return false;
        }

        const QVariantMap t = collectedTerms();

        WalletModel::ScalarCfdTermsInput in;
        in.source_type = 0; // ISSUER_PUBLISHED (the RPC rejects CHAIN_INTRINSIC — no resolver yet)
        in.payoff_mode = t.value("payoff_mode").toInt();
        in.underlying_asset_id = t.value("underlying").toString().trimmed();
        in.feed_id = static_cast<quint32>(t.value("feed_id").toString().trimmed().toUInt());
        in.fixing_ref = t.value("fixing_ref").toString().trimmed().toULongLong();
        in.publication_deadline_height = static_cast<quint32>(t.value("publication_deadline_height").toLongLong());
        in.settle_lock_height = static_cast<quint32>(t.value("settle_lock_height").toLongLong());
        in.scalar_format_id = t.value("scalar_format_id").toInt();
        in.strike = t.value("strike").toString().trimmed();
        in.fallback_scalar = t.value("fallback").toString().trimmed();
        in.collateral_asset_id = t.value("collateral").toString().trimmed(); // enforced empty above
        in.long_leg.im_sats = t.value("long_im").toString().trimmed().toLongLong();
        in.long_leg.lambda_q = static_cast<quint32>(qRound64(t.value("long_lambda").toDouble() * SCALAR_LAMBDA_SCALE));
        in.short_leg.im_sats = t.value("short_im").toString().trimmed().toLongLong();
        in.short_leg.lambda_q = static_cast<quint32>(qRound64(t.value("short_lambda").toDouble() * SCALAR_LAMBDA_SCALE));

        const bool isShort = t.value("proposer_side").toString() == QStringLiteral("short");
        const QString role = isShort ? QStringLiteral("short") : QStringLiteral("long");

        // Wallet-generated payout addresses: owner = the leg this party posts; cp = its claim on the
        // counterparty's leg. The coop-close internal keys are derived from these providers, so they must
        // be wallet-owned (same requirement as the difficulty CFD).
        const QString owner = walletModel->getNewAddress(tr("Scalar CFD owner (IM return)"));
        const QString cp = walletModel->getNewAddress(tr("Scalar CFD counterparty claim"));
        if (owner.isEmpty() || cp.isEmpty()) {
            QMessageBox::critical(this, tr("Error"), tr("Failed to generate payout addresses."));
            return false;
        }
        offerData["owner"] = owner;
        offerData["cp"] = cp;

        WalletModel::ScalarCfdProposeResult result = walletModel->scalarCfdPropose(in, isShort, owner, cp);
        if (!result.success) {
            QMessageBox::critical(this, tr("Scalar CFD Propose Failed"),
                tr("Failed to create the scalar-feed CFD offer:\n\n%1").arg(result.error));
            return false;
        }

        offerJson = result.offer_json;
        offerData["kind"] = QStringLiteral("cfd");
        offerData["offer_json"] = offerJson;

        // ---- Build the structured scalarcfd_term_sheet_v1 (terms + the embedded raw offer) ----
        // Unlike the difficulty builder there is no pre-open inline pricer (scalarcfd.price needs an opened
        // contract), so the metrics block is informational: priced=false with a note. The full terms + the
        // embedded raw offer make the term sheet self-contained for the counterparty's review dialog.
        QJsonObject termSheet;
        termSheet["schema"] = QStringLiteral("scalarcfd_term_sheet_v1");
        termSheet["kind"] = QStringLiteral("cfd");
        termSheet["maker_role"] = role;

        QJsonObject termsObj;
        termsObj["payoff_mode"] = in.payoff_mode;
        termsObj["underlying_asset_id"] = in.underlying_asset_id;
        termsObj["feed_id"] = static_cast<double>(in.feed_id);
        termsObj["fixing_ref"] = QString::number(in.fixing_ref);
        termsObj["publication_deadline_height"] = static_cast<double>(in.publication_deadline_height);
        termsObj["settle_lock_height"] = static_cast<double>(in.settle_lock_height);
        termsObj["scalar_format_id"] = in.scalar_format_id;
        termsObj["strike"] = in.strike;
        termsObj["fallback_scalar"] = in.fallback_scalar;
        termsObj["collateral_asset_id"] = in.collateral_asset_id; // empty = native TSC
        QJsonObject lo;
        lo["im"] = static_cast<double>(in.long_leg.im_sats);
        lo["lambda"] = t.value("long_lambda").toDouble();
        lo["lambda_q"] = static_cast<double>(in.long_leg.lambda_q);
        QJsonObject so;
        so["im"] = static_cast<double>(in.short_leg.im_sats);
        so["lambda"] = t.value("short_lambda").toDouble();
        so["lambda_q"] = static_cast<double>(in.short_leg.lambda_q);
        termsObj["long"] = lo;
        termsObj["short"] = so;
        termSheet["terms"] = termsObj;

        QJsonObject metrics;
        metrics["priced"] = false;
        metrics["note"] = QStringLiteral("scalar-feed CFDs are priced (MTM) only once opened");
        termSheet["metrics"] = metrics;

        // Embed the offer as the EXACT raw JSON STRING (not a parsed object). fixing_ref is a uint64 and Qt's
        // JSON stores every number as a double, so parsing→reserializing the offer would silently round any
        // fixing_ref above 2^53 — which changes contract_id = H(terms||salt) and breaks accept/import. Keeping
        // the raw bytes lets scalarcfd.accept (C++/UniValue) parse the true uint64. The counterparty's review
        // dialog reads this string verbatim for the accept, and parses a lossy copy for display only.
        termSheet["offer_raw"] = result.offer_json;

        termSheetJson = QString::fromUtf8(QJsonDocument(termSheet).toJson(QJsonDocument::Compact));
        offerData["term_sheet_json"] = termSheetJson;
        offerFinalized = true;

        LogPrintf("ScalarCfdContractBuilder: created scalar-feed CFD offer\n");
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
// ScalarCfdTermSheetPage
// ============================================================================

ScalarCfdTermSheetPage::ScalarCfdTermSheetPage(QWidget* parent)
    : QWizardPage(parent)
{
    setTitle(tr("Scalar-feed CFD - Terms"));
    setSubTitle(tr("A scalar-feed CFD settles on a published scalar feed at a chosen epoch. Margins are in "
                   "the collateral's units (native TSC for now). Your payout addresses are generated for you."));
    setupUI();
}

void ScalarCfdTermSheetPage::setupUI()
{
    QScrollArea* scrollArea = new QScrollArea(this);
    scrollArea->setWidgetResizable(true);
    scrollArea->setFrameShape(QFrame::NoFrame);

    QWidget* container = new QWidget();
    QVBoxLayout* mainLayout = new QVBoxLayout(container);

    // Instrument / side
    QGroupBox* instGroup = new QGroupBox(tr("Instrument"), container);
    QFormLayout* instForm = new QFormLayout(instGroup);
    payoffModeCombo = new QComboBox(instGroup);
    payoffModeCombo->addItem(tr("STRIKE (denominated in K)"));
    payoffModeCombo->addItem(tr("REALIZED (denominated in X)"));
    instForm->addRow(tr("Payoff mode:"), payoffModeCombo);
    proposerSideCombo = new QComboBox(instGroup);
    proposerSideCombo->addItem(tr("Long (loses as X falls below K)"));
    proposerSideCombo->addItem(tr("Short (loses as X rises above K)"));
    instForm->addRow(tr("Your side:"), proposerSideCombo);
    mainLayout->addWidget(instGroup);

    // Feed / fixing
    QGroupBox* feedGroup = new QGroupBox(tr("Feed && fixing"), container);
    QFormLayout* feedForm = new QFormLayout(feedGroup);
    // v1 is ISSUER_PUBLISHED only (the RPC rejects CHAIN_INTRINSIC — no chain resolver yet), so a real
    // 64-hex underlying is always required.
    underlyingEdit = new QLineEdit(feedGroup);
    underlyingEdit->setPlaceholderText(tr("underlying U asset id (required, 64-hex)"));
    feedForm->addRow(tr("Underlying (U):"), underlyingEdit);
    feedIdEdit = new QLineEdit(QStringLiteral("0"), feedGroup);
    feedForm->addRow(tr("Feed id:"), feedIdEdit);
    fixingRefEdit = new QLineEdit(QStringLiteral("1"), feedGroup);
    fixingRefEdit->setToolTip(tr("The scalar epoch (fixing reference) the contract settles against."));
    feedForm->addRow(tr("Fixing ref (epoch):"), fixingRefEdit);
    deadlineHeightSpin = new QSpinBox(feedGroup);
    deadlineHeightSpin->setRange(0, 2000000000);
    deadlineHeightSpin->setToolTip(tr("Height by which the fixing must be published, else the fallback scalar is used."));
    feedForm->addRow(tr("Publication deadline height:"), deadlineHeightSpin);
    settleLockHeightSpin = new QSpinBox(feedGroup);
    settleLockHeightSpin->setRange(0, 2000000000);
    settleLockHeightSpin->setToolTip(tr("CLTV burial; must be at or after the publication deadline."));
    feedForm->addRow(tr("Settle-lock height:"), settleLockHeightSpin);
    formatIdSpin = new QSpinBox(feedGroup);
    formatIdSpin->setRange(0, 65535);
    formatIdSpin->setValue(1);
    feedForm->addRow(tr("Scalar format id:"), formatIdSpin);
    strikeEdit = new QLineEdit(feedGroup);
    strikeEdit->setPlaceholderText(tr("strike K (64-hex)"));
    feedForm->addRow(tr("Strike (K):"), strikeEdit);
    fallbackEdit = new QLineEdit(feedGroup);
    fallbackEdit->setPlaceholderText(tr("fallback_scalar (64-hex)"));
    feedForm->addRow(tr("Fallback:"), fallbackEdit);
    collateralEdit = new QLineEdit(feedGroup);
    collateralEdit->setPlaceholderText(tr("native TSC only — asset-collateral open is not yet supported"));
    collateralEdit->setEnabled(false); // build_open is native-only; don't let the UI persist an unopenable contract
    feedForm->addRow(tr("Collateral (C):"), collateralEdit);
    mainLayout->addWidget(feedGroup);

    // Legs
    QGroupBox* legGroup = new QGroupBox(tr("CFD legs"), container);
    QFormLayout* legForm = new QFormLayout(legGroup);
    longImEdit = new QLineEdit(legGroup);
    longImEdit->setPlaceholderText(tr("collateral units (sats if native)"));
    legForm->addRow(tr("Long IM:"), longImEdit);
    longLambdaSpin = new QDoubleSpinBox(legGroup);
    longLambdaSpin->setDecimals(4);
    longLambdaSpin->setRange(0.0, 1000.0);
    longLambdaSpin->setValue(1.0);
    legForm->addRow(tr("Long leverage (lambda):"), longLambdaSpin);
    shortImEdit = new QLineEdit(legGroup);
    shortImEdit->setPlaceholderText(tr("collateral units (sats if native)"));
    legForm->addRow(tr("Short IM:"), shortImEdit);
    shortLambdaSpin = new QDoubleSpinBox(legGroup);
    shortLambdaSpin->setDecimals(4);
    shortLambdaSpin->setRange(0.0, 1000.0);
    shortLambdaSpin->setValue(1.0);
    legForm->addRow(tr("Short leverage (lambda):"), shortLambdaSpin);
    mainLayout->addWidget(legGroup);

    addressNote = new QLabel(
        tr("Your bech32m payout address(es) are generated automatically when the offer is created — "
           "the cooperative-close keys are derived from them, so they must be wallet-owned."), container);
    addressNote->setWordWrap(true);
    addressNote->setStyleSheet("QLabel { color: #666; font-size: 11px; }");
    mainLayout->addWidget(addressNote);

    mainLayout->addStretch();

    scrollArea->setWidget(container);
    QVBoxLayout* pageLayout = new QVBoxLayout(this);
    pageLayout->addWidget(scrollArea);
    setLayout(pageLayout);
}

void ScalarCfdTermSheetPage::initializePage()
{
    auto* builder = qobject_cast<ScalarCfdContractBuilder*>(wizard());
    if (!builder || !builder->getWalletModel()) return;

    // Seed sensible future heights from the current tip so a freshly-built offer validates without the
    // user having to hand-enter heights.
    if (deadlineHeightSpin->value() == 0) {
        const int tip = builder->getWalletModel()->getNumBlocks();
        if (tip > 0) {
            const int deadline = tip + DEFAULT_DEADLINE_OFFSET;
            deadlineHeightSpin->setValue(deadline);
            settleLockHeightSpin->setValue(deadline + DEFAULT_SETTLE_LOCK_GAP);
        }
    }
}

bool ScalarCfdTermSheetPage::validatePage()
{
    auto* builder = qobject_cast<ScalarCfdContractBuilder*>(wizard());
    return builder ? builder->validateTerms() : true;
}

QVariantMap ScalarCfdTermSheetPage::collectTerms() const
{
    QVariantMap t;
    t["payoff_mode"] = payoffModeCombo ? payoffModeCombo->currentIndex() : 0;
    t["proposer_side"] = (proposerSideCombo && proposerSideCombo->currentIndex() == 1) ? QStringLiteral("short")
                                                                                       : QStringLiteral("long");
    t["underlying"] = underlyingEdit ? underlyingEdit->text().trimmed() : QString();
    t["feed_id"] = feedIdEdit ? feedIdEdit->text().trimmed() : QString();
    t["fixing_ref"] = fixingRefEdit ? fixingRefEdit->text().trimmed() : QString();
    t["publication_deadline_height"] = deadlineHeightSpin ? deadlineHeightSpin->value() : 0;
    t["settle_lock_height"] = settleLockHeightSpin ? settleLockHeightSpin->value() : 0;
    t["scalar_format_id"] = formatIdSpin ? formatIdSpin->value() : 0;
    t["strike"] = strikeEdit ? strikeEdit->text().trimmed() : QString();
    t["fallback"] = fallbackEdit ? fallbackEdit->text().trimmed() : QString();
    t["collateral"] = collateralEdit ? collateralEdit->text().trimmed() : QString();
    t["long_im"] = longImEdit ? longImEdit->text().trimmed() : QString();
    t["long_lambda"] = longLambdaSpin ? longLambdaSpin->value() : 0.0;
    t["short_im"] = shortImEdit ? shortImEdit->text().trimmed() : QString();
    t["short_lambda"] = shortLambdaSpin ? shortLambdaSpin->value() : 0.0;
    return t;
}

// ============================================================================
// ScalarCfdReviewPage
// ============================================================================

ScalarCfdReviewPage::ScalarCfdReviewPage(ContractWizard* wizard, QWidget* parent)
    : ContractReviewPage(wizard, parent)
{
    setTitle(tr("Scalar-feed CFD - Review && Create Offer"));
    setSubTitle(tr("Review the terms below. Click 'Finish' to generate your payout addresses and create the offer."));
}

QString ScalarCfdReviewPage::formatOfferSummary() const
{
    auto* builder = qobject_cast<ScalarCfdContractBuilder*>(wizard());
    if (!builder) return QString();
    const QVariantMap t = builder->collectedTerms();

    QString s;
    s += tr("<b>Scalar-feed CFD</b><br>");
    s += tr("Your side: %1<br>").arg(t.value("proposer_side").toString());
    s += tr("Payoff mode: %1<br>").arg(t.value("payoff_mode").toInt() == 1 ? tr("REALIZED") : tr("STRIKE"));
    s += tr("Underlying (U): %1<br>").arg(t.value("underlying").toString());
    s += tr("Feed id: %1 &nbsp;|&nbsp; Fixing ref: %2<br>").arg(t.value("feed_id").toString(), t.value("fixing_ref").toString());
    s += tr("Strike (K): %1<br>").arg(t.value("strike").toString());
    s += tr("Fallback: %1<br>").arg(t.value("fallback").toString());
    s += tr("Publication deadline: H%1<br>").arg(t.value("publication_deadline_height").toLongLong());
    s += tr("Settle-lock height: H%1<br>").arg(t.value("settle_lock_height").toLongLong());
    s += tr("Long IM: %1, lambda %2<br>").arg(t.value("long_im").toString()).arg(t.value("long_lambda").toDouble());
    s += tr("Short IM: %1, lambda %2<br>").arg(t.value("short_im").toString()).arg(t.value("short_lambda").toDouble());
    return s;
}
