// Copyright (c) 2026 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <qt/difficultycontractbuilder.h>
#include <qt/walletmodel.h>
#include <consensus/difficulty_cfd.h> // MIN_SETTLE_OUTPUT, DIFFCFD_LAMBDA_SCALE, DIFFCFD_MATURITY_DEPTH (+ COIN)
#include <wallet/difficulty_contract.h> // DifficultyNBitsToTokensPerSec (term-sheet representation)
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
#include <QSignalBlocker>
#include <QSpinBox>
#include <QVBoxLayout>

#include <cmath>

namespace {
// Consensus constants (LAMBDA scale, maturity depth, dust floor) come from <consensus/difficulty_cfd.h>
// so the wizard cannot drift from consensus. The two below are UI-only.
constexpr int DEFAULT_FIXING_OFFSET = 144;        // default fixing height = tip + this (~1 day ahead)
constexpr qulonglong NBITS_MAX = 0xffffffffULL;   // nBits is a uint32 compact target
//! IM / premium dust floor (MIN_SETTLE_OUTPUT) expressed in TSC for the UI.
inline double MinSettleTsc() { return static_cast<double>(MIN_SETTLE_OUTPUT) / COIN; }

//! Parse a human strike in tokens/sec, accepting an optional SI suffix (k/M/G/T/P) and a trailing
//! "tok/s" — e.g. "5G", "5.5 T", "5000000000", "750M tok/s". Sets *ok on a positive parse.
double ParseTokensPerSec(QString text, bool* ok)
{
    if (ok) *ok = false;
    QString s = text.trimmed();
    s.remove(QStringLiteral("tok/s"), Qt::CaseInsensitive);
    s.remove(QStringLiteral("/s"), Qt::CaseInsensitive);
    s = s.trimmed();
    if (s.isEmpty()) return 0.0;
    double mult = 1.0;
    switch (s.at(s.size() - 1).toLower().toLatin1()) {
        case 'k': mult = 1e3; s.chop(1); break;
        case 'm': mult = 1e6; s.chop(1); break;  // SI mega (throughput context)
        case 'g': mult = 1e9; s.chop(1); break;
        case 't': mult = 1e12; s.chop(1); break;
        case 'p': mult = 1e15; s.chop(1); break;
        default: break;
    }
    bool parsed = false;
    const double v = s.trimmed().toDouble(&parsed);
    if (!parsed || !(v > 0.0)) return 0.0;
    if (ok) *ok = true;
    return v * mult;
}
} // namespace

// ============================================================================
// DifficultyContractBuilder
// ============================================================================

DifficultyContractBuilder::DifficultyContractBuilder(WalletModel* model, QWidget* parent)
    : ContractWizard(model, parent)
{
    setWindowTitle(tr("Difficulty Derivative Builder"));
    setMinimumSize(700, 560);
    resize(820, 640);

    setPage(Page_TermSheet, new DifficultyTermSheetPage(this));
    setPage(Page_Review, new DifficultyReviewPage(this, this));

    setStartId(Page_TermSheet);
}

DifficultyContractBuilder::~DifficultyContractBuilder() = default;

QVariantMap DifficultyContractBuilder::collectedTerms() const
{
    if (auto* page = qobject_cast<DifficultyTermSheetPage*>(this->page(Page_TermSheet))) {
        return page->collectTerms();
    }
    return QVariantMap();
}

bool DifficultyContractBuilder::validateTerms()
{
    const QVariantMap t = collectedTerms();
    const bool isOption = t.value("kind").toInt() == 1;

    bool hexOk = false;
    const qulonglong strikeVal = t.value("strike_nbits").toString().trimmed().toULongLong(&hexOk, 16);
    if (!hexOk || strikeVal == 0 || strikeVal > NBITS_MAX) {
        QMessageBox::warning(this, tr("Validation Error"),
            tr("Strike nBits must be a 32-bit compact target: 1–8 hex digits, non-zero (e.g. 1d00ffff)."));
        return false;
    }
    const qlonglong fixing = t.value("fixing_height").toLongLong();
    const qlonglong settle = t.value("settle_lock_height").toLongLong();
    if (settle < fixing + DIFFCFD_MATURITY_DEPTH) {
        QMessageBox::warning(this, tr("Validation Error"),
            tr("Settle-lock height must be at least fixing height + %1 (the maturity depth).")
                .arg(DIFFCFD_MATURITY_DEPTH));
        return false;
    }

    const double minTsc = MinSettleTsc(); // dust floor (MIN_SETTLE_OUTPUT) in TSC
    if (isOption) {
        if (t.value("im").toDouble() < minTsc) {
            QMessageBox::warning(this, tr("Validation Error"),
                tr("Writer initial margin must be at least %1 TSC (the dust floor).").arg(minTsc, 0, 'f', 8));
            return false;
        }
        if (t.value("lambda").toDouble() <= 0.0) {
            QMessageBox::warning(this, tr("Validation Error"), tr("Leverage (lambda) must be positive."));
            return false;
        }
        if (t.value("premium").toDouble() < minTsc) {
            QMessageBox::warning(this, tr("Validation Error"),
                tr("Option premium must be at least %1 TSC (the dust floor).").arg(minTsc, 0, 'f', 8));
            return false;
        }
    } else {
        if (t.value("long_im").toDouble() < minTsc || t.value("short_im").toDouble() < minTsc) {
            QMessageBox::warning(this, tr("Validation Error"),
                tr("Both legs' initial margins must be at least %1 TSC (the dust floor).").arg(minTsc, 0, 'f', 8));
            return false;
        }
        if (t.value("long_lambda").toDouble() <= 0.0 || t.value("short_lambda").toDouble() <= 0.0) {
            QMessageBox::warning(this, tr("Validation Error"), tr("Both legs' leverage (lambda) must be positive."));
            return false;
        }
    }
    return true;
}

bool DifficultyContractBuilder::createOffer()
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
        const bool isOption = t.value("kind").toInt() == 1;

        bool hexOk = false;
        const qulonglong strikeNbits = t.value("strike_nbits").toString().trimmed().toULongLong(&hexOk, 16);
        if (!hexOk || strikeNbits == 0 || strikeNbits > NBITS_MAX) {
            QMessageBox::critical(this, tr("Error"), tr("Invalid strike nBits (must be a non-zero 32-bit compact target)"));
            return false;
        }

        QVariantMap econ;
        econ["strike_nbits"] = static_cast<qulonglong>(strikeNbits);
        econ["fixing_height"] = static_cast<qulonglong>(t.value("fixing_height").toLongLong());
        econ["settle_lock_height"] = static_cast<qulonglong>(t.value("settle_lock_height").toLongLong());

        WalletModel::DifficultyProposeResult result;
        QString role;

        if (isOption) {
            econ["im"] = t.value("im").toDouble();
            econ["lambda_q"] = static_cast<qulonglong>(std::llround(t.value("lambda").toDouble() * DIFFCFD_LAMBDA_SCALE));
            econ["premium"] = t.value("premium").toDouble();
            econ["writer_side"] = t.value("writer_side").toString();

            role = t.value("proposer_role").toString(); // "writer" / "buyer"
            const QString payout = walletModel->getNewAddress(tr("Difficulty option payout"));
            if (payout.isEmpty()) {
                QMessageBox::critical(this, tr("Error"), tr("Failed to generate a payout address."));
                return false;
            }
            offerData["payout"] = payout;
            result = walletModel->difficultyProposeOption(econ, role, payout);
        } else {
            econ["long_im"] = t.value("long_im").toDouble();
            econ["long_lambda_q"] = static_cast<qulonglong>(std::llround(t.value("long_lambda").toDouble() * DIFFCFD_LAMBDA_SCALE));
            econ["short_im"] = t.value("short_im").toDouble();
            econ["short_lambda_q"] = static_cast<qulonglong>(std::llround(t.value("short_lambda").toDouble() * DIFFCFD_LAMBDA_SCALE));

            role = t.value("proposer_side").toString(); // "long" / "short"
            const QString owner = walletModel->getNewAddress(tr("Difficulty owner (IM return)"));
            const QString cp = walletModel->getNewAddress(tr("Difficulty counterparty claim"));
            if (owner.isEmpty() || cp.isEmpty()) {
                QMessageBox::critical(this, tr("Error"), tr("Failed to generate payout addresses."));
                return false;
            }
            offerData["owner"] = owner;
            offerData["cp"] = cp;
            result = walletModel->difficultyPropose(econ, role, owner, cp);
        }

        if (!result.success) {
            QMessageBox::critical(this, tr("Difficulty Propose Failed"),
                tr("Failed to create the difficulty offer:\n\n%1").arg(result.error));
            return false;
        }

        offerJson = result.offer_json;
        offerData["kind"] = isOption ? QStringLiteral("option") : QStringLiteral("cfd");
        offerData["offer_json"] = offerJson;

        // ---- Build the structured difficulty_term_sheet_v1 (terms + a pricing metrics block) ----
        // The metrics come from pricing.difficulty.quote (inline mode, chain-tip nBits forecast). The call is
        // best-effort: if the pricer is unavailable the term sheet still carries the full terms, just with a
        // priced=false metrics block (a freshly-built offer must never fail because pricing is down).
        QVariantMap inlineTerms;
        inlineTerms["kind"] = isOption ? QStringLiteral("option") : QStringLiteral("cfd");
        inlineTerms["strike_nbits"] = static_cast<uint>(strikeNbits);
        inlineTerms["fixing_height"] = static_cast<uint>(econ["fixing_height"].toULongLong());
        inlineTerms["settle_lock_height"] = static_cast<uint>(econ["settle_lock_height"].toULongLong());
        if (isOption) {
            inlineTerms["writer_side"] = t.value("writer_side").toString();
            inlineTerms["im"] = QString::number(t.value("im").toDouble(), 'f', 8);
            inlineTerms["lambda_q"] = static_cast<uint>(econ["lambda_q"].toULongLong());
            inlineTerms["premium"] = QString::number(t.value("premium").toDouble(), 'f', 8);
        } else {
            inlineTerms["long_im"] = QString::number(t.value("long_im").toDouble(), 'f', 8);
            inlineTerms["long_lambda_q"] = static_cast<uint>(econ["long_lambda_q"].toULongLong());
            inlineTerms["short_im"] = QString::number(t.value("short_im").toDouble(), 'f', 8);
            inlineTerms["short_lambda_q"] = static_cast<uint>(econ["short_lambda_q"].toULongLong());
        }
        WalletModel::PricingDifficultyQuoteResult q =
            walletModel->pricingDifficultyQuote(QStringLiteral("inline"), QString(), inlineTerms,
                                                /*compute_greeks=*/true, /*forecast_nbits=*/0);

        QJsonObject termSheet;
        termSheet["schema"] = QStringLiteral("difficulty_term_sheet_v1");
        termSheet["kind"] = isOption ? QStringLiteral("option") : QStringLiteral("cfd");
        termSheet["maker_role"] = role;

        QJsonObject termsObj;
        termsObj["strike_nbits"] = t.value("strike_nbits").toString().trimmed();
        termsObj["fixing_height"] = static_cast<double>(econ["fixing_height"].toLongLong());
        termsObj["settle_lock_height"] = static_cast<double>(econ["settle_lock_height"].toLongLong());
        if (isOption) {
            termsObj["writer_side"] = t.value("writer_side").toString();
            termsObj["im_tsc"] = t.value("im").toDouble();
            termsObj["lambda"] = t.value("lambda").toDouble();
            termsObj["lambda_q"] = static_cast<double>(econ["lambda_q"].toLongLong());
            termsObj["premium_tsc"] = t.value("premium").toDouble();
        } else {
            QJsonObject lo;
            lo["im_tsc"] = t.value("long_im").toDouble();
            lo["lambda"] = t.value("long_lambda").toDouble();
            lo["lambda_q"] = static_cast<double>(econ["long_lambda_q"].toLongLong());
            QJsonObject so;
            so["im_tsc"] = t.value("short_im").toDouble();
            so["lambda"] = t.value("short_lambda").toDouble();
            so["lambda_q"] = static_cast<double>(econ["short_lambda_q"].toLongLong());
            termsObj["long"] = lo;
            termsObj["short"] = so;
        }
        termSheet["terms"] = termsObj;

        QJsonObject metrics;
        if (q.success) {
            metrics["priced"] = true;
            metrics["model"] = QStringLiteral("deterministic intrinsic mark (forecast = chain-tip nBits)");
            metrics["model_unreliable"] = q.model_unreliable;
            metrics["mtm_units"] = QStringLiteral("native atomic (sats)");
            if (isOption) {
                metrics["expected_writer_mtm"] = q.expected_writer_mtm;
                metrics["expected_buyer_mtm"] = q.expected_buyer_mtm;
                metrics["writer_delta_to_difficulty"] = q.writer_delta_to_difficulty;
                metrics["buyer_delta_to_difficulty"] = q.buyer_delta_to_difficulty;
            } else {
                metrics["expected_long_mtm"] = q.expected_long_mtm;
                metrics["expected_short_mtm"] = q.expected_short_mtm;
                metrics["long_delta_to_difficulty"] = q.long_delta_to_difficulty;
                metrics["short_delta_to_difficulty"] = q.short_delta_to_difficulty;
            }
        } else {
            metrics["priced"] = false;
            metrics["note"] = q.error.isEmpty() ? QStringLiteral("pricing.difficulty.quote unavailable") : q.error;
        }
        // Human-readable representation of the strike: raw nBits is opaque, so also express the implied
        // genesis inference throughput (tokens/sec) for the term sheet + pricing.
        bool nbits_ok = false;
        const uint32_t strike_nbits_u = t.value("strike_nbits").toString().trimmed().toUInt(&nbits_ok, 16);
        if (nbits_ok) {
            metrics["strike_tokens_per_sec"] = wallet::DifficultyNBitsToTokensPerSec(strike_nbits_u);
        }
        termSheet["metrics"] = metrics;

        // Embed the offer JSON so the term sheet is self-contained for the counterparty.
        QJsonParseError perr;
        const QJsonDocument offerDoc = QJsonDocument::fromJson(result.offer_json.toUtf8(), &perr);
        if (perr.error == QJsonParseError::NoError && offerDoc.isObject()) {
            termSheet["offer"] = offerDoc.object();
        }

        termSheetJson = QString::fromUtf8(QJsonDocument(termSheet).toJson(QJsonDocument::Compact));
        offerData["term_sheet_json"] = termSheetJson;
        offerFinalized = true;

        LogPrintf("DifficultyContractBuilder: created %s offer (term sheet priced=%d)\n",
                  isOption ? "option" : "cfd", q.success);
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
// DifficultyTermSheetPage
// ============================================================================

DifficultyTermSheetPage::DifficultyTermSheetPage(QWidget* parent)
    : QWizardPage(parent)
{
    setTitle(tr("Difficulty Derivative - Terms"));
    setSubTitle(tr("A difficulty contract settles on the network's nBits at a buried fixing height. "
                   "Margins and payouts are in native TSC. Your payout addresses are generated for you."));
    setupUI();
}

void DifficultyTermSheetPage::setupUI()
{
    QScrollArea* scrollArea = new QScrollArea(this);
    scrollArea->setWidgetResizable(true);
    scrollArea->setFrameShape(QFrame::NoFrame);

    QWidget* container = new QWidget();
    QVBoxLayout* mainLayout = new QVBoxLayout(container);

    // Instrument kind
    QGroupBox* kindGroup = new QGroupBox(tr("Instrument"), container);
    QFormLayout* kindForm = new QFormLayout(kindGroup);
    kindCombo = new QComboBox(kindGroup);
    kindCombo->addItem(tr("CFD (both legs margined)"));
    kindCombo->addItem(tr("Option (single margined leg + premium)"));
    kindForm->addRow(tr("Kind:"), kindCombo);
    mainLayout->addWidget(kindGroup);

    // Shared underlying
    QGroupBox* underGroup = new QGroupBox(tr("Underlying"), container);
    QFormLayout* underForm = new QFormLayout(underGroup);
    // Primary strike input is the human-meaningful network inference throughput (tokens/sec); the UI
    // derives the canonical compact target (nBits) the contract actually settles on. Nobody should have
    // to hand-author nBits.
    strikeTpsEdit = new QLineEdit(underGroup);
    strikeTpsEdit->setPlaceholderText(QStringLiteral("e.g. 5G  (5 billion tok/s)"));
    strikeTpsEdit->setToolTip(tr("Strike difficulty as network inference throughput (tokens/sec). "
                                 "Accepts SI suffixes k/M/G/T/P. Defaults to the current chain difficulty."));
    underForm->addRow(tr("Strike (tok/s):"), strikeTpsEdit);

    // Derived canonical strike — read-only; this is the consensus value embedded in the contract.
    strikeNbitsEdit = new QLineEdit(underGroup);
    strikeNbitsEdit->setReadOnly(true);
    strikeNbitsEdit->setToolTip(tr("Canonical compact target (nBits) the contract settles on, derived from the tok/s strike."));
    underForm->addRow(tr("→ strike nBits (hex):"), strikeNbitsEdit);

    // Realized strike: the compact encoding is lossy, so show the throughput the derived nBits actually represents.
    strikeTokensPerSecLabel = new QLabel(underGroup);
    strikeTokensPerSecLabel->setStyleSheet("QLabel { color: #888; font-size: 11px; }");
    underForm->addRow(QString(), strikeTokensPerSecLabel);

    auto recomputeStrike = [this]() {
        bool ok = false;
        const double tps = ParseTokensPerSec(strikeTpsEdit->text(), &ok);
        if (ok && tps > 0.0) {
            const uint32_t nbits = wallet::DifficultyTokensPerSecToNBits(tps);
            strikeNbitsEdit->setText(QStringLiteral("%1").arg(nbits, 8, 16, QChar('0')));
            const double realized = wallet::DifficultyNBitsToTokensPerSec(nbits);
            strikeTokensPerSecLabel->setText(tr("canonical strike ≈ %1")
                .arg(QString::fromStdString(wallet::DifficultyFormatTokensPerSec(realized))));
        } else {
            strikeNbitsEdit->clear();
            strikeTokensPerSecLabel->clear();
        }
    };
    connect(strikeTpsEdit, &QLineEdit::textChanged, this, recomputeStrike);
    recomputeStrike();

    fixingHeightSpin = new QSpinBox(underGroup);
    fixingHeightSpin->setRange(0, 2000000000);
    fixingHeightSpin->setToolTip(tr("Block height H whose nBits is the settled underlying."));
    underForm->addRow(tr("Fixing height:"), fixingHeightSpin);

    settleLockHeightSpin = new QSpinBox(underGroup);
    settleLockHeightSpin->setRange(0, 2000000000);
    settleLockHeightSpin->setToolTip(tr("CLTV burial; must be at least fixing height + maturity depth."));
    underForm->addRow(tr("Settle-lock height:"), settleLockHeightSpin);
    mainLayout->addWidget(underGroup);

    // CFD legs
    cfdGroup = new QGroupBox(tr("CFD legs"), container);
    QFormLayout* cfdForm = new QFormLayout(cfdGroup);
    proposerSideCombo = new QComboBox(cfdGroup);
    proposerSideCombo->addItem(tr("Long (loses as difficulty falls)"));
    proposerSideCombo->addItem(tr("Short (loses as difficulty rises)"));
    cfdForm->addRow(tr("Your side:"), proposerSideCombo);

    longImSpin = new QDoubleSpinBox(cfdGroup);
    longImSpin->setDecimals(8);
    longImSpin->setRange(MinSettleTsc(), 21000000.0);
    longImSpin->setValue(10.0);
    cfdForm->addRow(tr("Long IM (TSC):"), longImSpin);
    longLambdaSpin = new QDoubleSpinBox(cfdGroup);
    longLambdaSpin->setDecimals(4);
    longLambdaSpin->setRange(0.0, 1000.0);
    longLambdaSpin->setValue(10.0);
    cfdForm->addRow(tr("Long leverage (lambda):"), longLambdaSpin);

    shortImSpin = new QDoubleSpinBox(cfdGroup);
    shortImSpin->setDecimals(8);
    shortImSpin->setRange(MinSettleTsc(), 21000000.0);
    shortImSpin->setValue(10.0);
    cfdForm->addRow(tr("Short IM (TSC):"), shortImSpin);
    shortLambdaSpin = new QDoubleSpinBox(cfdGroup);
    shortLambdaSpin->setDecimals(4);
    shortLambdaSpin->setRange(0.0, 1000.0);
    shortLambdaSpin->setValue(10.0);
    cfdForm->addRow(tr("Short leverage (lambda):"), shortLambdaSpin);
    mainLayout->addWidget(cfdGroup);

    // Option leg
    optionGroup = new QGroupBox(tr("Option leg"), container);
    QFormLayout* optForm = new QFormLayout(optionGroup);
    proposerRoleCombo = new QComboBox(optionGroup);
    proposerRoleCombo->addItem(tr("Writer (posts IM, receives premium)"));
    proposerRoleCombo->addItem(tr("Buyer (pays premium)"));
    optForm->addRow(tr("Your role:"), proposerRoleCombo);

    writerSideCombo = new QComboBox(optionGroup);
    writerSideCombo->addItem(tr("Long (writer loses as difficulty falls)"));
    writerSideCombo->addItem(tr("Short (writer loses as difficulty rises)"));
    optForm->addRow(tr("Writer side:"), writerSideCombo);

    optImSpin = new QDoubleSpinBox(optionGroup);
    optImSpin->setDecimals(8);
    optImSpin->setRange(MinSettleTsc(), 21000000.0);
    optImSpin->setValue(10.0);
    optForm->addRow(tr("Writer IM (TSC):"), optImSpin);
    optLambdaSpin = new QDoubleSpinBox(optionGroup);
    optLambdaSpin->setDecimals(4);
    optLambdaSpin->setRange(0.0, 1000.0);
    optLambdaSpin->setValue(10.0);
    optForm->addRow(tr("Leverage (lambda):"), optLambdaSpin);
    optPremiumSpin = new QDoubleSpinBox(optionGroup);
    optPremiumSpin->setDecimals(8);
    optPremiumSpin->setRange(MinSettleTsc(), 21000000.0);
    optPremiumSpin->setValue(1.0);
    optForm->addRow(tr("Premium (TSC):"), optPremiumSpin);
    mainLayout->addWidget(optionGroup);

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

    connect(kindCombo, &QComboBox::currentIndexChanged, this, &DifficultyTermSheetPage::onKindChanged);
    onKindChanged(kindCombo->currentIndex());
}

void DifficultyTermSheetPage::onKindChanged(int index)
{
    const bool isOption = (index == 1);
    if (cfdGroup) cfdGroup->setVisible(!isOption);
    if (optionGroup) optionGroup->setVisible(isOption);
}

void DifficultyTermSheetPage::initializePage()
{
    auto* builder = qobject_cast<DifficultyContractBuilder*>(wizard());
    if (!builder || !builder->getWalletModel()) return;

    // Seed sensible, RPC-valid defaults from the current chain (so a freshly-built offer validates). The
    // fixing height defaults to a FUTURE block (tip + offset) so the contract is not immediately fixed.
    if (strikeNbitsEdit->text().trimmed().isEmpty() || fixingHeightSpin->value() == 0) {
        WalletModel::DifficultyChainDefaults d = builder->getWalletModel()->difficultyChainDefaults();
        if (d.success) {
            if (strikeNbitsEdit->text().trimmed().isEmpty() && !d.strike_nbits.isEmpty()) {
                // Default the human strike (tok/s) to the current chain difficulty, but keep the derived
                // nBits EXACTLY equal to the chain target (block the recompute so the lossy round-trip
                // doesn't perturb the default). The user editing tok/s recomputes nBits normally.
                bool ok = false;
                const uint32_t nbits = d.strike_nbits.trimmed().toUInt(&ok, 16);
                const double tps = ok ? wallet::DifficultyNBitsToTokensPerSec(nbits) : 0.0;
                const QSignalBlocker block(strikeTpsEdit);
                if (tps > 0.0) {
                    strikeTpsEdit->setText(QString::fromStdString(wallet::DifficultyFormatTokensPerSec(tps)));
                    strikeTokensPerSecLabel->setText(tr("canonical strike ≈ %1")
                        .arg(QString::fromStdString(wallet::DifficultyFormatTokensPerSec(tps))));
                }
                strikeNbitsEdit->setText(d.strike_nbits);
            }
            if (fixingHeightSpin->value() == 0) {
                const int fixing = d.height + DEFAULT_FIXING_OFFSET;
                fixingHeightSpin->setValue(fixing);
                settleLockHeightSpin->setValue(fixing + static_cast<int>(DIFFCFD_MATURITY_DEPTH));
            }
        }
    }
}

bool DifficultyTermSheetPage::validatePage()
{
    // Normalize the strike to canonical 8-digit lowercase hex when it parses as a uint32 compact target.
    if (strikeNbitsEdit) {
        bool ok = false;
        const qulonglong v = strikeNbitsEdit->text().trimmed().toULongLong(&ok, 16);
        if (ok && v != 0 && v <= NBITS_MAX) {
            strikeNbitsEdit->setText(QStringLiteral("%1").arg(v, 8, 16, QChar('0')));
        }
    }
    auto* builder = qobject_cast<DifficultyContractBuilder*>(wizard());
    return builder ? builder->validateTerms() : true;
}

QVariantMap DifficultyTermSheetPage::collectTerms() const
{
    QVariantMap t;
    t["kind"] = kindCombo ? kindCombo->currentIndex() : 0;
    t["strike_nbits"] = strikeNbitsEdit ? strikeNbitsEdit->text().trimmed() : QString();
    t["fixing_height"] = fixingHeightSpin ? fixingHeightSpin->value() : 0;
    t["settle_lock_height"] = settleLockHeightSpin ? settleLockHeightSpin->value() : 0;

    // CFD
    t["proposer_side"] = (proposerSideCombo && proposerSideCombo->currentIndex() == 1) ? QStringLiteral("short")
                                                                                       : QStringLiteral("long");
    t["long_im"] = longImSpin ? longImSpin->value() : 0.0;
    t["long_lambda"] = longLambdaSpin ? longLambdaSpin->value() : 0.0;
    t["short_im"] = shortImSpin ? shortImSpin->value() : 0.0;
    t["short_lambda"] = shortLambdaSpin ? shortLambdaSpin->value() : 0.0;

    // Option
    t["proposer_role"] = (proposerRoleCombo && proposerRoleCombo->currentIndex() == 1) ? QStringLiteral("buyer")
                                                                                       : QStringLiteral("writer");
    t["writer_side"] = (writerSideCombo && writerSideCombo->currentIndex() == 1) ? QStringLiteral("short")
                                                                                 : QStringLiteral("long");
    t["im"] = optImSpin ? optImSpin->value() : 0.0;
    t["lambda"] = optLambdaSpin ? optLambdaSpin->value() : 0.0;
    t["premium"] = optPremiumSpin ? optPremiumSpin->value() : 0.0;
    return t;
}

// ============================================================================
// DifficultyReviewPage
// ============================================================================

DifficultyReviewPage::DifficultyReviewPage(ContractWizard* wizard, QWidget* parent)
    : ContractReviewPage(wizard, parent)
{
    setTitle(tr("Difficulty Derivative - Review && Create Offer"));
    setSubTitle(tr("Review the terms below. Click 'Finish' to generate your payout addresses and create the offer."));
}

QString DifficultyReviewPage::formatOfferSummary() const
{
    auto* builder = qobject_cast<DifficultyContractBuilder*>(wizard());
    if (!builder) return QString();
    const QVariantMap t = builder->collectedTerms();
    const bool isOption = t.value("kind").toInt() == 1;

    QString s;
    s += tr("<b>Difficulty %1</b><br>").arg(isOption ? tr("Option") : tr("CFD"));
    s += tr("Strike nBits: %1<br>").arg(t.value("strike_nbits").toString());
    s += tr("Fixing height: %1<br>").arg(t.value("fixing_height").toLongLong());
    s += tr("Settle-lock height: %1<br>").arg(t.value("settle_lock_height").toLongLong());
    if (isOption) {
        s += tr("Your role: %1<br>").arg(t.value("proposer_role").toString());
        s += tr("Writer side: %1<br>").arg(t.value("writer_side").toString());
        s += tr("Writer IM: %1 TSC, lambda %2<br>").arg(t.value("im").toDouble()).arg(t.value("lambda").toDouble());
        s += tr("Premium: %1 TSC<br>").arg(t.value("premium").toDouble());
    } else {
        s += tr("Your side: %1<br>").arg(t.value("proposer_side").toString());
        s += tr("Long IM: %1 TSC, lambda %2<br>").arg(t.value("long_im").toDouble()).arg(t.value("long_lambda").toDouble());
        s += tr("Short IM: %1 TSC, lambda %2<br>").arg(t.value("short_im").toDouble()).arg(t.value("short_lambda").toDouble());
    }
    return s;
}
