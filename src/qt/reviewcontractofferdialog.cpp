// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <qt/reviewcontractofferdialog.h>
#include <qt/walletmodel.h>
#include <wallet/difficulty_contract.h> // DifficultyNBitsToTokensPerSec (strike representation)
#include <qt/guiutil.h>
#include <qt/proofbuilder.h>
#include <qt/pricingbreakdowndialog.h>
#include <qt/greeksvisualizationdialog.h>
#include <qt/themehelpers.h>
#include <logging.h>
#include <univalue.h>
#include <cmath>

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QGroupBox>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTextEdit>
#include <QMessageBox>
#include <QJsonDocument>
#include <QRegularExpression>
#include <QJsonObject>
#include <QDateTime>
#include <QApplication>
#include <QClipboard>
#include <QFont>
#include <QFrame>
#include <cmath>

namespace {

QString formatAmount(double amount)
{
    if (std::abs(amount) >= 1.0) {
        return QString::number(amount, 'f', 2);
    }
    return QString::number(amount, 'f', 8);
}

} // namespace

ReviewContractOfferDialog::ReviewContractOfferDialog(const QVariantMap& data,
                                                     WalletModel* model,
                                                     QWidget* parent)
    : QDialog(parent),
      offerData(data),
      walletModel(model)
{
    setWindowTitle(tr("Review Contract Offer"));

    // Set reasonable size that fits on screen
    setMinimumSize(700, 500);
    resize(800, 600);

    parseOfferPayload();
    setupUI();
}

void ReviewContractOfferDialog::parseOfferPayload()
{
    makerRole = offerData.value("maker_role").toString().toLower();

    // Try both contract_payload and term_sheet_json keys (bulletin board may use either)
    QString payload = offerData.value("contract_payload").toString();
    if (payload.isEmpty()) {
        payload = offerData.value("term_sheet_json").toString();
    }
    if (payload.isEmpty()) {
        return;
    }

    QJsonParseError err;
    const QJsonDocument doc = QJsonDocument::fromJson(payload.toUtf8(), &err);
    if (doc.isNull() || !doc.isObject()) {
        return;
    }

    const QJsonObject root = doc.object();
    const QString schema = root.value("schema").toString();

    if (schema == QLatin1String("repo_term_sheet_v1")) {
        payloadIsTermSheet = true;
        m_contractType = QStringLiteral("repo");
        termSheetTerms = root.value("terms").toObject().toVariantMap();
        termSheetMetrics = root.value("metrics").toObject().toVariantMap();
        makerRole = root.value("maker_role").toString().toLower();
        makerLenderAddress = root.value("lender_address").toString();
    } else if (schema == QLatin1String("forward_term_sheet_v1") ||
               schema == QLatin1String("option_term_sheet_v1")) {
        payloadIsTermSheet = true;
        m_contractType = (schema == QLatin1String("option_term_sheet_v1"))
            ? QStringLiteral("option")
            : QStringLiteral("forward");

        // Extract maker_role
        if (root.contains("maker_role")) {
            makerRole = root.value("maker_role").toString().toLower(); // "long" or "short"
        }

        // Parse terms (flat schema from forwardcontractbuilder.cpp)
        const QJsonObject terms = root.value("terms").toObject();

        // Helper: resolve asset label via registry
        auto resolveAssetLabel = [this](const QString& assetIdOrLabel) -> QString {
            if (assetIdOrLabel.isEmpty()) return QString();
            if (assetIdOrLabel == QLatin1String("TSC")) return assetIdOrLabel;
            if (walletModel) {
                WalletModel::AssetInfo ai = walletModel->getAssetInfo(assetIdOrLabel);
                if (!ai.ticker.isEmpty()) return ai.ticker;
            }
            return assetIdOrLabel.left(8) + "...";
        };

        // Helper: extract asset label and return amount (units are already human-readable)
        auto processAmount = [this, &resolveAssetLabel](double amount, bool isNative, const QString& assetId)
            -> std::tuple<double, QString, QString> {
            QString label;
            QString actualAssetId = assetId;

            if (isNative) {
                label = QStringLiteral("TSC");
                actualAssetId = QString(); // Native = empty asset ID
            } else if (!assetId.isEmpty()) {
                label = resolveAssetLabel(assetId);
                actualAssetId = assetId;
            } else {
                label = QStringLiteral("TSC");
                actualAssetId = QString();
            }

            // Note: units in term sheet are already human-readable amounts, not base units
            // (see forwardcontractbuilder.cpp - stores field values directly)
            return std::make_tuple(amount, label, actualAssetId);
        };

        // Parse long deliver leg
        double longDeliverAmount = terms.value("long_deliver_units").toDouble();
        bool longDeliverIsNative = terms.value("long_deliver_is_native").toBool(true);
        QString longDeliverAssetId = terms.value("long_deliver_asset_id").toString();
        auto [longDeliverQty, longDeliverAsset, longDeliverAssetIdResolved] =
            processAmount(longDeliverAmount, longDeliverIsNative, longDeliverAssetId);
        m_longDeliverQty = longDeliverQty;
        m_longDeliverAsset = longDeliverAsset;
        m_longDeliverAssetId = longDeliverAssetIdResolved;

        // Parse long IM leg
        double longImAmount = terms.value("long_im_units").toDouble();
        bool longImIsNative = terms.value("long_im_is_native").toBool(true);
        QString longImAssetId = terms.value("long_im_asset_id").toString();
        auto [longImQty, longImAsset, longImAssetIdResolved] =
            processAmount(longImAmount, longImIsNative, longImAssetId);
        m_longMarginQty = longImQty;
        m_longMarginAsset = longImAsset;
        m_longMarginAssetId = longImAssetIdResolved;

        // Parse long addresses
        m_longMarginDest = terms.value("long_margin_dest").toString();
        m_longSettleDest = terms.value("long_settle_dest").toString();

        // Parse short deliver leg
        double shortDeliverAmount = terms.value("short_deliver_units").toDouble();
        bool shortDeliverIsNative = terms.value("short_deliver_is_native").toBool(true);
        QString shortDeliverAssetId = terms.value("short_deliver_asset_id").toString();
        auto [shortDeliverQty, shortDeliverAsset, shortDeliverAssetIdResolved] =
            processAmount(shortDeliverAmount, shortDeliverIsNative, shortDeliverAssetId);
        m_shortDeliverQty = shortDeliverQty;
        m_shortDeliverAsset = shortDeliverAsset;
        m_shortDeliverAssetId = shortDeliverAssetIdResolved;

        // Parse short IM leg
        double shortImAmount = terms.value("short_im_units").toDouble();
        bool shortImIsNative = terms.value("short_im_is_native").toBool(true);
        QString shortImAssetId = terms.value("short_im_asset_id").toString();
        auto [shortImQty, shortImAsset, shortImAssetIdResolved] =
            processAmount(shortImAmount, shortImIsNative, shortImAssetId);
        m_shortMarginQty = shortImQty;
        m_shortMarginAsset = shortImAsset;
        m_shortMarginAssetId = shortImAssetIdResolved;

        // Parse short addresses
        m_shortMarginDest = terms.value("short_margin_dest").toString();
        m_shortSettleDest = terms.value("short_settle_dest").toString();

        // Parse premium (optional)
        bool hasPremium = terms.value("has_premium").toBool(false);
        if (hasPremium) {
            double premiumAmount = terms.value("premium_units").toDouble();
            bool premiumIsNative = terms.value("premium_is_native").toBool(true);
            QString premiumAssetId = terms.value("premium_asset_id").toString();
            auto [premiumQty, premiumAsset, premiumAssetIdResolved] =
                processAmount(premiumAmount, premiumIsNative, premiumAssetId);
            m_premiumQty = premiumQty;
            m_premiumAsset = premiumAsset;
            m_premiumAssetId = premiumAssetIdResolved;
            m_premiumPayer = terms.value("premium_payer").toString(); // "long" or "short"
            m_premiumPayeeDest = terms.value("premium_dest").toString();
        }

        // Parse deadlines
        m_deadlineShort = terms.value("deadline_short").toInt();
        m_deadlineLong = terms.value("deadline_long").toInt();
        m_safetyK = terms.value("safety_k").toInt();
        m_reorgConf = terms.value("reorg_conf").toInt();

        // Metrics (if present in term sheet)
        if (root.contains("metrics") && root.value("metrics").isObject()) {
            const QJsonObject metrics = root.value("metrics").toObject();
            m_tenorDaysShort = metrics.value("tenor_days_short").toInt();
            m_tenorDaysLong = metrics.value("tenor_days_long").toInt();
            m_longIMPercent = metrics.value("long_im_percent").toDouble();
            m_shortIMPercent = metrics.value("short_im_percent").toDouble();
        } else {
            // Compute IM percentages if not provided
            if (m_longDeliverQty > 0) {
                m_longIMPercent = (m_longMarginQty / m_longDeliverQty) * 100.0;
            }
            if (m_shortDeliverQty > 0) {
                m_shortIMPercent = (m_shortMarginQty / m_shortDeliverQty) * 100.0;
            }
        }

        LogPrintf("ReviewContractOfferDialog: Parsed forward/option term sheet - "
                  "contract_type=%s, maker_role=%s, long_deliver=%f %s, short_deliver=%f %s, "
                  "premium=%f %s (payer=%s)\n",
                  m_contractType.toStdString().c_str(),
                  makerRole.toStdString().c_str(),
                  m_longDeliverQty, m_longDeliverAsset.toStdString().c_str(),
                  m_shortDeliverQty, m_shortDeliverAsset.toStdString().c_str(),
                  m_premiumQty, m_premiumAsset.toStdString().c_str(),
                  m_premiumPayer.toStdString().c_str());

    } else if (schema == QLatin1String("spot_term_sheet_v1")) {
        payloadIsTermSheet = true;
        m_contractType = QStringLiteral("spot");

        // Extract maker_role (always "alice" from Qt wizard)
        if (root.contains("maker_role")) {
            makerRole = root.value("maker_role").toString().toLower();  // "alice"
        }

        // Parse terms object
        const QJsonObject terms = root.value("terms").toObject();

        // Helper: resolve asset label via registry
        auto resolveAssetLabel = [this](const QString& assetIdOrLabel) -> QString {
            if (assetIdOrLabel.isEmpty()) return QString();
            if (assetIdOrLabel == QLatin1String("TSC")) return assetIdOrLabel;
            if (walletModel) {
                WalletModel::AssetInfo ai = walletModel->getAssetInfo(assetIdOrLabel);
                if (!ai.ticker.isEmpty()) return ai.ticker;
            }
            return assetIdOrLabel.left(8) + "...";
        };

        // Helper: convert base units to human-readable amount
        auto fromUnits = [this](int64_t units, bool isNative, const QString& assetId) -> double {
            int decimals = 8;  // default
            if (!isNative && !assetId.isEmpty() && walletModel) {
                WalletModel::AssetInfo ai = walletModel->getAssetInfo(assetId);
                if (ai.has_decimals) decimals = ai.decimals;
            }
            return static_cast<double>(units) / std::pow(10.0, decimals);
        };

        // Parse alice_leg
        if (terms.contains("alice_leg")) {
            const QJsonObject aliceLeg = terms["alice_leg"].toObject();
            bool alice_is_native = aliceLeg.value("is_native").toBool(true);
            QString alice_asset_id = aliceLeg.value("asset_id").toString();
            int64_t alice_units = aliceLeg.value("units").toVariant().toLongLong();

            m_spotAliceSendQty = fromUnits(alice_units, alice_is_native, alice_asset_id);
            m_spotAliceSendAssetId = alice_is_native ? QString() : alice_asset_id;
            m_spotAliceSendAsset = alice_is_native ? QStringLiteral("TSC") : resolveAssetLabel(alice_asset_id);

            // Alice sends alice_leg, receives bob_leg
            m_spotAliceRecvAssetId = QString();  // Will be set from bob_leg
            m_spotAliceRecvAsset = QString();
            m_spotAliceRecvQty = 0;
        }

        // Parse bob_leg
        if (terms.contains("bob_leg")) {
            const QJsonObject bobLeg = terms["bob_leg"].toObject();
            bool bob_is_native = bobLeg.value("is_native").toBool(true);
            QString bob_asset_id = bobLeg.value("asset_id").toString();
            int64_t bob_units = bobLeg.value("units").toVariant().toLongLong();

            m_spotBobSendQty = fromUnits(bob_units, bob_is_native, bob_asset_id);
            m_spotBobSendAssetId = bob_is_native ? QString() : bob_asset_id;
            m_spotBobSendAsset = bob_is_native ? QStringLiteral("TSC") : resolveAssetLabel(bob_asset_id);

            // Set alice's receive = bob's send
            m_spotAliceRecvQty = m_spotBobSendQty;
            m_spotAliceRecvAsset = m_spotBobSendAsset;
            m_spotAliceRecvAssetId = m_spotBobSendAssetId;

            // Set bob's receive = alice's send
            m_spotBobRecvQty = m_spotAliceSendQty;
            m_spotBobRecvAsset = m_spotAliceSendAsset;
            m_spotBobRecvAssetId = m_spotAliceSendAssetId;
        }

        // Parse destination addresses
        m_spotAliceDest = terms.value("alice_dest").toString();
        m_spotBobDest = terms.value("bob_dest").toString();

        // Parse exchange rate from metrics
        if (root.contains("metrics") && root.value("metrics").isObject()) {
            const QJsonObject metrics = root.value("metrics").toObject();
            m_spotExchangeRate = metrics.value("exchange_rate").toDouble();
        } else if (m_spotAliceSendQty > 0) {
            // Compute exchange rate if not provided
            m_spotExchangeRate = m_spotBobSendQty / m_spotAliceSendQty;
        }

        LogPrintf("ReviewContractOfferDialog: Parsed spot term sheet - "
                  "maker_role=%s, alice_send=%f %s, bob_send=%f %s, exchange_rate=%f\n",
                  makerRole.toStdString().c_str(),
                  m_spotAliceSendQty, m_spotAliceSendAsset.toStdString().c_str(),
                  m_spotBobSendQty, m_spotBobSendAsset.toStdString().c_str(),
                  m_spotExchangeRate);

    } else if (schema == QLatin1String("difficulty_term_sheet_v1")) {
        payloadIsTermSheet = true;
        m_contractType = QStringLiteral("difficulty");
        // Advisory pricing mark from the outer sheet (informational only, NOT part of the signed offer).
        termSheetMetrics = root.value("metrics").toObject().toVariantMap();
        // SECURITY: both render and accept must bind to the embedded SIGNED offer, never the outer
        // term sheet — a malicious market post could otherwise show benign economics over a different
        // signed offer. Kind, maker role, and all binding terms come from the embedded offer.
        if (root.contains("offer") && root.value("offer").isObject()) {
            m_difficultyOfferObj = root.value("offer").toObject();
            m_difficultyOfferJson = QString::fromUtf8(
                QJsonDocument(m_difficultyOfferObj).toJson(QJsonDocument::Compact));
            m_difficultyKind = m_difficultyOfferObj.value("kind").toString().toLower();
            makerRole = m_difficultyOfferObj.value("proposer_role").toString().toLower();
        } else {
            // No embedded offer: keep outer kind only so the UI can show a clear "cannot accept".
            m_difficultyKind = root.value("kind").toString().toLower();
            makerRole = root.value("maker_role").toString().toLower();
        }
    } else if (schema == QLatin1String("scalarcfd_term_sheet_v1")) {
        payloadIsTermSheet = true;
        m_contractType = QStringLiteral("scalarcfd");
        // Advisory metrics from the outer sheet (informational only, NOT part of the signed offer).
        termSheetMetrics = root.value("metrics").toObject().toVariantMap();
        // SECURITY: as with difficulty, both render and accept bind to the embedded SIGNED offer, never the
        // outer term sheet — a market post could otherwise show benign economics over a different offer.
        // The offer is embedded as the EXACT raw JSON string (offer_raw) so the uint64 fixing_ref survives
        // to scalarcfd.accept losslessly (Qt JSON would round it); we parse a copy for DISPLAY only. Fall back
        // to a legacy embedded object if offer_raw is absent.
        if (root.contains("offer_raw") && root.value("offer_raw").isString()) {
            m_scalarCfdOfferJson = root.value("offer_raw").toString();  // exact bytes -> accept
            m_scalarCfdOfferObj = QJsonDocument::fromJson(m_scalarCfdOfferJson.toUtf8()).object();  // display copy
            makerRole = m_scalarCfdOfferObj.value("proposer_role").toString().toLower();
        } else if (root.contains("offer") && root.value("offer").isObject()) {
            m_scalarCfdOfferObj = root.value("offer").toObject();
            m_scalarCfdOfferJson = QString::fromUtf8(
                QJsonDocument(m_scalarCfdOfferObj).toJson(QJsonDocument::Compact));
            makerRole = m_scalarCfdOfferObj.value("proposer_role").toString().toLower();
        } else {
            makerRole = root.value("maker_role").toString().toLower();
        }
    } else {
        // Treat anything else as a finalized contract JSON so taker can review.
        payloadIsFinalOffer = true;
        finalOfferObject = root;
    }
}

void ReviewContractOfferDialog::setupUI()
{
    QVBoxLayout* mainLayout = new QVBoxLayout(this);

    QString offerId = offerData.value("offer_id").toString();
    QLabel* titleLabel = new QLabel(tr("<h2>Contract Offer Review</h2>"), this);
    mainLayout->addWidget(titleLabel);

    QLabel* offerIdLabel = new QLabel(tr("<b>Offer ID:</b> %1")
        .arg(offerId.isEmpty() ? tr("pending") : offerId.left(16) + "..."), this);
    mainLayout->addWidget(offerIdLabel);

    mainLayout->addSpacing(10);

    QGroupBox* termsGroup = new QGroupBox(tr("Maker's Terms"), this);
    QVBoxLayout* termsLayout = new QVBoxLayout(termsGroup);

    termsDisplay = new QTextEdit(this);
    termsDisplay->setReadOnly(true);
    termsDisplay->setMinimumHeight(400);  // Increased from 320 for better visibility
    termsDisplay->setHtml(formatOfferTerms());
    termsLayout->addWidget(termsDisplay);

    mainLayout->addWidget(termsGroup);
    mainLayout->addSpacing(10);

    // Display maker's proofs verification status (already verified during ingestion)
    bool proof_verified = offerData.value("proof_verified").toBool();
    uint64_t proof_verified_units = offerData.value("proof_verified_units").toULongLong();
    QString proof_verification_error = offerData.value("proof_verification_error").toString();
    QString proof_verified_asset = offerData.value("proof_verified_asset").toString();

    LogPrintf("ReviewContractOfferDialog: proof_verified=%d, proof_verified_units=%lu, proof_verified_asset='%s', error='%s'\n",
        proof_verified, proof_verified_units, proof_verified_asset.toStdString().c_str(),
        proof_verification_error.toStdString().c_str());

    if (offerData.contains("proof_of_funds") && offerData["proof_of_funds"].canConvert<QVariantList>()) {
        QVariantList proofs = offerData["proof_of_funds"].toList();
        if (!proofs.isEmpty()) {
            QGroupBox* proofGroup = new QGroupBox(tr("Maker's Proof of Funds (%1)").arg(proofs.size()), this);
            proofGroup->setCheckable(true);
            proofGroup->setChecked(false);  // Collapsed by default
            QVBoxLayout* proofLayout = new QVBoxLayout(proofGroup);

            // Resolve asset_id to ticker for display
            QString assetDisplay;
            if (proof_verified_asset.isEmpty()) {
                assetDisplay = QString("TSC");
            } else if (walletModel) {
                WalletModel::AssetInfo assetInfo = walletModel->getAssetInfo(proof_verified_asset);
                if (!assetInfo.ticker.isEmpty()) {
                    assetDisplay = assetInfo.ticker;
                } else {
                    assetDisplay = proof_verified_asset.left(16) + "...";
                }
            } else {
                assetDisplay = proof_verified_asset.left(16) + "...";
            }

            if (!proof_verified) {
                // Proof verification FAILED - show critical error
                QLabel* errorLabel = new QLabel(
                    tr("<b style='color:red;font-size:14pt;'>✗ PROOF VERIFICATION FAILED</b><br><br>"
                       "Error: %1<br><br>"
                       "<b>This offer cannot be accepted.</b>")
                        .arg(proof_verification_error), this);
                errorLabel->setWordWrap(true);
                proofLayout->addWidget(errorLabel);
                mainLayout->addWidget(proofGroup);
                mainLayout->addSpacing(10);

                // Disable accept button (will be added later)
                // User must close dialog
                return; // Skip the rest of UI setup
            }

            // Proofs verified successfully - show compact status in group title
            proofGroup->setTitle(tr("✓ Maker's Proof of Funds - %1 %2 verified (expand for details)")
                .arg(proof_verified_units)
                .arg(assetDisplay));

            proofLayout->addWidget(new QLabel(tr("<b style='color:green;'>✓ All proofs verified</b><br>"
                "Total: <b>%1</b> units of %2")
                .arg(proof_verified_units)
                .arg(assetDisplay), this));

            // Check sufficiency against contract requirements
            auto variantToBool = [](const QVariant& value, bool fallback) {
                if (!value.isValid()) return fallback;
                switch (static_cast<QMetaType::Type>(value.typeId())) {
                case QMetaType::Bool:
                    return value.toBool();
                case QMetaType::Int:
                case QMetaType::LongLong:
                    return value.toInt() != 0;
                case QMetaType::QString: {
                    const QString s = value.toString().trimmed().toLower();
                    if (s == QLatin1String("true") || s == QLatin1String("1") || s == QLatin1String("yes")) return true;
                    if (s == QLatin1String("false") || s == QLatin1String("0") || s == QLatin1String("no")) return false;
                    return fallback;
                }
                default:
                    break;
                }
                return value.toBool();
            };

            uint64_t requiredAmount = 0;
            QString requiredAssetId;
            bool requirementKnown = false;

            if (makerRole == "lender") {
                // Lender must prove principal
                double principalAmount = termSheetTerms.value("principal_amount").toDouble();
                bool principalIsNative = variantToBool(termSheetTerms.value("principal_is_native"), true);
                if (!principalIsNative) {
                    requiredAssetId = termSheetTerms.value("principal_asset_id").toString();
                    // Use actual asset decimals
                    if (walletModel) {
                        WalletModel::AssetInfo assetInfo = walletModel->getAssetInfo(requiredAssetId);
                        int decimals = (assetInfo.has_decimals) ? assetInfo.decimals : 8;
                        requiredAmount = static_cast<uint64_t>(principalAmount * std::pow(10.0, decimals));
                    } else {
                        requiredAmount = static_cast<uint64_t>(principalAmount * 100000000);
                    }
                } else {
                    // Native TSC uses 8 decimals
                    requiredAmount = static_cast<uint64_t>(principalAmount * 100000000);
                }
                requirementKnown = true;
            } else if (makerRole == "borrower") {
                // Borrower must prove collateral
                double collateralAmount = termSheetTerms.value("collateral_amount").toDouble();
                bool collateralIsNative = variantToBool(termSheetTerms.value("collateral_is_native"), true);
                if (!collateralIsNative) {
                    requiredAssetId = termSheetTerms.value("collateral_asset_id").toString();
                    // Use actual asset decimals
                    if (walletModel) {
                        WalletModel::AssetInfo assetInfo = walletModel->getAssetInfo(requiredAssetId);
                        int decimals = (assetInfo.has_decimals) ? assetInfo.decimals : 8;
                        requiredAmount = static_cast<uint64_t>(collateralAmount * std::pow(10.0, decimals));
                    } else {
                        requiredAmount = static_cast<uint64_t>(collateralAmount * 100000000);
                    }
                } else {
                    // Native TSC uses 8 decimals
                    requiredAmount = static_cast<uint64_t>(collateralAmount * 100000000);
                }
                requirementKnown = true;
            }

            if (requirementKnown) {
                // Normalize asset IDs: treat "TSC" and empty as equivalent (native)
                QString normalizedProofAsset = (proof_verified_asset == "TSC" || proof_verified_asset.isEmpty()) ? QString() : proof_verified_asset;
                QString normalizedRequiredAsset = requiredAssetId.isEmpty() ? QString() : requiredAssetId;

                // Check if asset matches and amount is sufficient
                bool assetMatches = (normalizedProofAsset.isEmpty() && normalizedRequiredAsset.isEmpty()) ||
                                   (normalizedProofAsset == normalizedRequiredAsset);
                bool sufficient = assetMatches && (proof_verified_units >= requiredAmount);

                QString reqAssetDisplay = requiredAssetId.isEmpty() ? QStringLiteral("TSC") : (requiredAssetId.left(16) + "...");

                if (!sufficient) {
                    // INSUFFICIENT - show critical error
                    QLabel* errorLabel = new QLabel(
                        tr("<b style='color:red;font-size:14pt;'>✗ INSUFFICIENT FUNDS</b><br><br>"
                           "Required: <b>%1</b> units of %2<br>"
                           "Proven: <b>%3</b> units<br><br>"
                           "<b>This offer cannot be accepted.</b>")
                            .arg(requiredAmount)
                            .arg(reqAssetDisplay)
                            .arg(proof_verified_units), this);
                    errorLabel->setWordWrap(true);
                    proofLayout->addWidget(errorLabel);
                    mainLayout->addWidget(proofGroup);
                    mainLayout->addSpacing(10);
                    return; // Skip rest of UI setup
                }

                // Sufficient - show success
                QLabel* sufficientLabel = new QLabel(
                    tr("<b style='color:green;'>✓ Sufficient funds proven</b><br>"
                       "Required: %1 units of %2")
                        .arg(requiredAmount)
                        .arg(reqAssetDisplay), this);
                proofLayout->addWidget(sufficientLabel);
            }

            // Connect toggled signal to hide/show children and collapse layout
            connect(proofGroup, &QGroupBox::toggled, this, [proofGroup, proofLayout](bool checked) {
                // Hide/show all widgets in the layout
                for (int i = 0; i < proofLayout->count(); ++i) {
                    QWidget* w = proofLayout->itemAt(i)->widget();
                    if (w) w->setVisible(checked);
                }
                // Force layout recalculation to actually collapse/expand
                // When unchecked, limit height to just the title bar (~40px)
                proofGroup->setMaximumHeight(checked ? QWIDGETSIZE_MAX : 40);
                proofGroup->updateGeometry();
            });

            // Initially hide all children since unchecked by default
            for (int i = 0; i < proofLayout->count(); ++i) {
                QWidget* w = proofLayout->itemAt(i)->widget();
                if (w) w->setVisible(false);
            }
            // Set initial max height to just the title bar
            proofGroup->setMaximumHeight(40);

            mainLayout->addWidget(proofGroup);
            mainLayout->addSpacing(10);
        }
    }

    // Pricing Analysis Section (for repo contracts)
    if (m_contractType == QLatin1String("repo") && walletModel) {
        QGroupBox* pricingGroup = new QGroupBox(tr("Pricing Analysis"), this);
        pricingGroup->setStyleSheet(ThemeHelpers::panelStyleSheet());
        QGridLayout* pricingLayout = new QGridLayout(pricingGroup);

        // Build inline terms from termSheetTerms
        QVariantMap inlineTerms;

        auto variantToBool = [](const QVariant& value, bool fallback) {
            if (!value.isValid()) return fallback;
            switch (static_cast<QMetaType::Type>(value.typeId())) {
            case QMetaType::Bool:
                return value.toBool();
            case QMetaType::Int:
            case QMetaType::LongLong:
                return value.toInt() != 0;
            case QMetaType::QString: {
                const QString s = value.toString().trimmed().toLower();
                if (s == QLatin1String("true") || s == QLatin1String("1") || s == QLatin1String("yes")) return true;
                if (s == QLatin1String("false") || s == QLatin1String("0") || s == QLatin1String("no")) return false;
                return fallback;
            }
            default:
                break;
            }
            return value.toBool();
        };

        bool collateralIsNative = variantToBool(termSheetTerms.value("collateral_is_native"), true);
        bool principalIsNative = variantToBool(termSheetTerms.value("principal_is_native"), true);
        bool interestIsNative = variantToBool(termSheetTerms.value("interest_is_native"), true);

        inlineTerms["collateral_asset"] = collateralIsNative ? "" : termSheetTerms.value("collateral_asset_id").toString();
        inlineTerms["collateral_is_native"] = collateralIsNative;
        inlineTerms["collateral_units"] = static_cast<qint64>(termSheetTerms.value("collateral_amount").toDouble() * 1e8);

        inlineTerms["principal_asset"] = principalIsNative ? "" : termSheetTerms.value("principal_asset_id").toString();
        inlineTerms["principal_is_native"] = principalIsNative;
        inlineTerms["principal_units"] = static_cast<qint64>(termSheetTerms.value("principal_amount").toDouble() * 1e8);

        inlineTerms["interest_asset"] = interestIsNative ? "" : termSheetTerms.value("interest_asset_id").toString();
        inlineTerms["interest_is_native"] = interestIsNative;
        inlineTerms["interest_units"] = static_cast<qint64>(termSheetTerms.value("interest_amount").toDouble() * 1e8);

        inlineTerms["maturity_height"] = termSheetTerms.value("maturity_height").toInt();
        inlineTerms["safety_k"] = termSheetTerms.value("safety_buffer", 144).toInt();

        // Call pricing RPC
        try {
            auto result = walletModel->pricingRepoQuote(
                "inline",
                "",
                inlineTerms,
                "",     // report_asset (empty for TSC)
                true,   // report_is_native
                false,  // compute_greeks (skip for performance)
                QStringLiteral("mark"),
                true    // include inception cashflows for pre-exec view
            );

            if (result.success) {
                int row = 0;

                // NOTE: Pricing RPC returns values in base units of the reporting currency
                // Get TSC decimals (default report currency)
                int reportDecimals = 8; // TSC default
                if (walletModel) {
                    WalletModel::AssetInfo tscInfo = walletModel->getAssetInfo(""); // Empty = native TSC
                    if (tscInfo.has_decimals) {
                        reportDecimals = tscInfo.decimals;
                    }
                }
                const double toDisplayUnits = 1.0 / std::pow(10.0, reportDecimals);

                // Get principal amount for per-principal calculations
                double principalAmount = termSheetTerms.value("principal_amount").toDouble();
                double perPrincipalDivisor = (principalAmount > 0.0) ? principalAmount : 1.0;

                // Header row
                pricingLayout->addWidget(new QLabel(tr(""), this), row, 0);
                pricingLayout->addWidget(new QLabel(tr("<b>Absolute</b>"), this), row, 1);
                pricingLayout->addWidget(new QLabel(tr("<b>Per Principal</b>"), this), row, 2);
                row++;

                // Principal + Interest PV
                pricingLayout->addWidget(new QLabel(tr("Principal + Interest PV:"), this), row, 0);
                double principalInterestPv = (result.principal_pv + result.interest_pv) * toDisplayUnits;
                QLabel* pvLabel = new QLabel(tr("%1 TSC").arg(principalInterestPv, 0, 'f', 8), this);
                pvLabel->setStyleSheet(ThemeHelpers::accentLabelStyleSheet(/*bold=*/false));
                pricingLayout->addWidget(pvLabel, row, 1);
                QLabel* pvPerPLabel = new QLabel(QString("%1").arg(principalInterestPv / perPrincipalDivisor, 0, 'f', 6), this);
                pvPerPLabel->setStyleSheet(ThemeHelpers::accentLabelStyleSheet(/*bold=*/false));
                pricingLayout->addWidget(pvPerPLabel, row++, 2);

                // Collateral PV
                pricingLayout->addWidget(new QLabel(tr("Collateral PV:"), this), row, 0);
                double collateralPv = result.collateral_pv * toDisplayUnits;
                QLabel* collPvLabel = new QLabel(tr("%1 TSC").arg(collateralPv, 0, 'f', 8), this);
                collPvLabel->setStyleSheet(ThemeHelpers::accentLabelStyleSheet(/*bold=*/false));
                pricingLayout->addWidget(collPvLabel, row, 1);
                QLabel* collPvPerPLabel = new QLabel(QString("%1").arg(collateralPv / perPrincipalDivisor, 0, 'f', 6), this);
                collPvPerPLabel->setStyleSheet(ThemeHelpers::accentLabelStyleSheet(/*bold=*/false));
                pricingLayout->addWidget(collPvPerPLabel, row++, 2);

                // Collateral Option Value
                pricingLayout->addWidget(new QLabel(tr("Collateral Option Value:"), this), row, 0);
                double collateralOption = result.collateral_option * toDisplayUnits;
                QLabel* optionLabel = new QLabel(tr("%1 TSC").arg(collateralOption, 0, 'f', 8), this);
                optionLabel->setStyleSheet(ThemeHelpers::accentLabelStyleSheet(/*bold=*/false));
                pricingLayout->addWidget(optionLabel, row, 1);
                QLabel* optionPerPLabel = new QLabel(QString("%1").arg(collateralOption / perPrincipalDivisor, 0, 'f', 6), this);
                optionPerPLabel->setStyleSheet(ThemeHelpers::accentLabelStyleSheet(/*bold=*/false));
                pricingLayout->addWidget(optionPerPLabel, row++, 2);

                // Coverage Ratio removed as requested

                // Separator
                QFrame* separator = new QFrame(this);
                separator->setFrameShape(QFrame::HLine);
                separator->setFrameShadow(QFrame::Sunken);
                pricingLayout->addWidget(separator, row++, 0, 1, 3);

                // Your MTM (taker's perspective)
                bool takerIsLender = (makerRole == QLatin1String("borrower"));
                double yourMtm = (takerIsLender ? result.lender_mtm : result.borrower_mtm) * toDisplayUnits;
                QString yourRole = takerIsLender ? tr("Your MTM (Lender):") : tr("Your MTM (Borrower):");

                pricingLayout->addWidget(new QLabel(yourRole, this), row, 0);
                QLabel* mtmLabel = new QLabel(this);
                if (yourMtm > 0.0) {
                    mtmLabel->setText(tr("+%1 TSC").arg(yourMtm, 0, 'f', 8));
                    mtmLabel->setStyleSheet("QLabel { font-weight: bold; color: #4caf50; }"); // Green
                } else if (yourMtm < 0.0) {
                    mtmLabel->setText(tr("%1 TSC").arg(yourMtm, 0, 'f', 8));
                    mtmLabel->setStyleSheet("QLabel { font-weight: bold; color: #f44336; }"); // Red
                } else {
                    mtmLabel->setText(tr("0.00000000 TSC"));
                    mtmLabel->setStyleSheet("QLabel { font-weight: bold; color: #9e9e9e; }"); // Gray
                }
                pricingLayout->addWidget(mtmLabel, row, 1);

                QLabel* mtmPerPLabel = new QLabel(this);
                double yourMtmPerP = yourMtm / perPrincipalDivisor;
                if (yourMtm > 0.0) {
                    mtmPerPLabel->setText(QString("+%1").arg(yourMtmPerP, 0, 'f', 6));
                    mtmPerPLabel->setStyleSheet("QLabel { font-weight: bold; color: #4caf50; }");
                } else if (yourMtm < 0.0) {
                    mtmPerPLabel->setText(QString("%1").arg(yourMtmPerP, 0, 'f', 6));
                    mtmPerPLabel->setStyleSheet("QLabel { font-weight: bold; color: #f44336; }");
                } else {
                    mtmPerPLabel->setText(QString("0.000000"));
                    mtmPerPLabel->setStyleSheet("QLabel { font-weight: bold; color: #9e9e9e; }");
                }
                pricingLayout->addWidget(mtmPerPLabel, row++, 2);

                // Warning icon if negative MTM
                if (yourMtm < 0.0) {
                    QLabel* warningLabel = new QLabel(this);
                    warningLabel->setWordWrap(true);
                    warningLabel->setText(tr("⚠ <b>Warning:</b> This contract has negative mark-to-market for you at current market prices."));
                    warningLabel->setStyleSheet(QStringLiteral("QLabel { %1 }").arg(ThemeHelpers::warningPanelStyleSheet()));
                    pricingLayout->addWidget(warningLabel, row++, 0, 1, 3);
                }
            }
        } catch (...) {
            // Pricing failed - show informational message
            QLabel* errorLabel = new QLabel(tr("Pricing data unavailable. Please ensure market data is calibrated."), this);
            errorLabel->setStyleSheet("QLabel { color: #9e9e9e; font-style: italic; }");
            pricingLayout->addWidget(errorLabel, 0, 0, 1, 3);
        }

        pricingGroup->setLayout(pricingLayout);
        mainLayout->addWidget(pricingGroup);
        mainLayout->addSpacing(10);
    }

    // Bilateral CFDs (difficulty and scalar-feed) generate the taker's payout address(es) internally
    // during accept and have no repo/forward-style manual address inputs, so they skip the advanced
    // address group entirely (otherwise they would fall into the repo-terminology else branch below).
    if (m_contractType != QLatin1String("difficulty") && m_contractType != QLatin1String("scalarcfd")) {
    QGroupBox* addressGroup = new QGroupBox(tr("Your Addresses (Advanced)"), this);
    addressGroup->setCheckable(true);
    addressGroup->setChecked(false);  // Hidden by default
    QGridLayout* addressLayout = new QGridLayout(addressGroup);

    // Handle forward/options vs repo address labels
    if (m_contractType == QLatin1String("forward") || m_contractType == QLatin1String("option")) {
        // Forward/Options: use long/short terminology
        bool takerIsLong = (makerRole == QLatin1String("short"));
        bool takerIsShort = (makerRole == QLatin1String("long"));

        if (takerIsLong) {
            // Taker is long - ask for margin recovery address
            addressLayout->addWidget(new QLabel(tr("Long Margin Recovery (you):"), this), 0, 0);
            lenderAddressEdit = new QLineEdit(this);
            lenderAddressEdit->setPlaceholderText(tr("bc1p... (where IM vault returns)"));
            addressLayout->addWidget(lenderAddressEdit, 0, 1);

            generateLenderButton = new QPushButton(tr("Generate New"), this);
            addressLayout->addWidget(generateLenderButton, 0, 2);
            connect(generateLenderButton, &QPushButton::clicked,
                    this, &ReviewContractOfferDialog::onGenerateLenderAddress);

            addressLayout->addWidget(new QLabel(tr("Long Settlement (auto):"), this), 1, 0);
            borrowerAddressEdit = new QLineEdit(this);
            borrowerAddressEdit->setPlaceholderText(tr("Auto-generated"));
            borrowerAddressEdit->setReadOnly(true);
            addressLayout->addWidget(borrowerAddressEdit, 1, 1);

            generateBorrowerButton = new QPushButton(tr(""), this);
            generateBorrowerButton->setEnabled(false);
            generateBorrowerButton->setVisible(false);
            addressLayout->addWidget(generateBorrowerButton, 1, 2);

            // Show maker's addresses if available
            if (!m_shortMarginDest.isEmpty()) {
                addressLayout->addWidget(new QLabel(tr("Short Margin (maker):"), this), 2, 0);
                QLineEdit* makerAddr = new QLineEdit(this);
                makerAddr->setText(m_shortMarginDest);
                makerAddr->setReadOnly(true);
                addressLayout->addWidget(makerAddr, 2, 1, 1, 2);
            }

            QLabel* noteLabel = new QLabel(this);
            noteLabel->setWordWrap(true);
            noteLabel->setStyleSheet(ThemeHelpers::mutedLabelStyleSheet());
            noteLabel->setText(tr("<i>Provide your margin recovery address (where your IM vault returns). "
                                  "Settlement address will be auto-generated.</i>"));
            addressLayout->addWidget(noteLabel, 3, 0, 1, 3);

            if (walletModel) {
                onGenerateLenderAddress();
            }

        } else if (takerIsShort) {
            // Taker is short - ask for margin recovery address
            addressLayout->addWidget(new QLabel(tr("Short Margin Recovery (you):"), this), 0, 0);
            borrowerAddressEdit = new QLineEdit(this);
            borrowerAddressEdit->setPlaceholderText(tr("bc1p... (where IM vault returns)"));
            addressLayout->addWidget(borrowerAddressEdit, 0, 1);

            generateBorrowerButton = new QPushButton(tr("Generate New"), this);
            addressLayout->addWidget(generateBorrowerButton, 0, 2);
            connect(generateBorrowerButton, &QPushButton::clicked,
                    this, &ReviewContractOfferDialog::onGenerateBorrowerAddress);

            addressLayout->addWidget(new QLabel(tr("Short Settlement (auto):"), this), 1, 0);
            lenderAddressEdit = new QLineEdit(this);
            lenderAddressEdit->setPlaceholderText(tr("Auto-generated"));
            lenderAddressEdit->setReadOnly(true);
            addressLayout->addWidget(lenderAddressEdit, 1, 1);

            generateLenderButton = new QPushButton(tr(""), this);
            generateLenderButton->setEnabled(false);
            generateLenderButton->setVisible(false);
            addressLayout->addWidget(generateLenderButton, 1, 2);

            // Show maker's addresses if available
            if (!m_longMarginDest.isEmpty()) {
                addressLayout->addWidget(new QLabel(tr("Long Margin (maker):"), this), 2, 0);
                QLineEdit* makerAddr = new QLineEdit(this);
                makerAddr->setText(m_longMarginDest);
                makerAddr->setReadOnly(true);
                addressLayout->addWidget(makerAddr, 2, 1, 1, 2);
            }

            QLabel* noteLabel = new QLabel(this);
            noteLabel->setWordWrap(true);
            noteLabel->setStyleSheet(ThemeHelpers::mutedLabelStyleSheet());
            noteLabel->setText(tr("<i>Provide your margin recovery address (where your IM vault returns). "
                                  "Settlement address will be auto-generated.</i>"));
            addressLayout->addWidget(noteLabel, 3, 0, 1, 3);

            if (walletModel) {
                onGenerateBorrowerAddress();
            }
        } else {
            // Fallback: unknown role
            addressLayout->addWidget(new QLabel(tr("Margin Recovery:"), this), 0, 0);
            borrowerAddressEdit = new QLineEdit(this);
            borrowerAddressEdit->setPlaceholderText(tr("bc1p..."));
            addressLayout->addWidget(borrowerAddressEdit, 0, 1);

            generateBorrowerButton = new QPushButton(tr("Generate New"), this);
            addressLayout->addWidget(generateBorrowerButton, 0, 2);
            connect(generateBorrowerButton, &QPushButton::clicked,
                    this, &ReviewContractOfferDialog::onGenerateBorrowerAddress);
        }

    } else if (m_contractType == QLatin1String("spot")) {
        // Spot: taker is always Bob, only needs one receive address
        addressLayout->addWidget(new QLabel(tr("Your Receive Address (Bob):"), this), 0, 0);
        borrowerAddressEdit = new QLineEdit(this);
        borrowerAddressEdit->setPlaceholderText(tr("bc1p... (where you receive swapped asset)"));
        addressLayout->addWidget(borrowerAddressEdit, 0, 1);

        generateBorrowerButton = new QPushButton(tr("Generate New"), this);
        addressLayout->addWidget(generateBorrowerButton, 0, 2);
        connect(generateBorrowerButton, &QPushButton::clicked,
                this, &ReviewContractOfferDialog::onGenerateBorrowerAddress);

        // Show maker's address if available
        if (!m_spotAliceDest.isEmpty()) {
            addressLayout->addWidget(new QLabel(tr("Maker's Receive Address (Alice):"), this), 1, 0);
            QLineEdit* makerAddr = new QLineEdit(this);
            makerAddr->setText(m_spotAliceDest);
            makerAddr->setReadOnly(true);
            addressLayout->addWidget(makerAddr, 1, 1, 1, 2);
        }

        QLabel* noteLabel = new QLabel(this);
        noteLabel->setWordWrap(true);
        noteLabel->setStyleSheet(ThemeHelpers::mutedLabelStyleSheet());
        noteLabel->setText(tr("<i>Provide your receive address where you will receive the swapped asset. "
                              "The swap settles atomically in a single transaction.</i>"));
        addressLayout->addWidget(noteLabel, 2, 0, 1, 3);

        if (walletModel) {
            onGenerateBorrowerAddress();
        }

    } else {
        // Repo: use lender/borrower terminology
        bool takerIsBorrower = (makerRole == "lender");
        bool takerIsLender = (makerRole == "borrower");

        if (takerIsBorrower) {
            // Taker is borrower - ask for borrower address, show maker's lender address
            addressLayout->addWidget(new QLabel(tr("Borrower Repay Address (you):"), this), 0, 0);
            borrowerAddressEdit = new QLineEdit(this);
            borrowerAddressEdit->setPlaceholderText(tr("bc1p... (Taproot address)"));
            addressLayout->addWidget(borrowerAddressEdit, 0, 1);

            generateBorrowerButton = new QPushButton(tr("Generate New"), this);
            addressLayout->addWidget(generateBorrowerButton, 0, 2);
            connect(generateBorrowerButton, &QPushButton::clicked,
                    this, &ReviewContractOfferDialog::onGenerateBorrowerAddress);

            addressLayout->addWidget(new QLabel(tr("Lender Receive Address (maker):"), this), 1, 0);
            lenderAddressEdit = new QLineEdit(this);
            lenderAddressEdit->setPlaceholderText(tr("Provided by maker"));
            lenderAddressEdit->setReadOnly(true);
            if (!makerLenderAddress.isEmpty()) {
                lenderAddressEdit->setText(makerLenderAddress);
            }
            addressLayout->addWidget(lenderAddressEdit, 1, 1);

            generateLenderButton = new QPushButton(tr(""), this);
            generateLenderButton->setEnabled(false);
            generateLenderButton->setVisible(false);
            addressLayout->addWidget(generateLenderButton, 1, 2);

            QLabel* noteLabel = new QLabel(this);
            noteLabel->setWordWrap(true);
            noteLabel->setStyleSheet(ThemeHelpers::mutedLabelStyleSheet());
            noteLabel->setText(tr("<i>Provide the repayment address where you (borrower) will send collateral back. "
                                  "The lender's address is fixed by the maker.</i>"));
            addressLayout->addWidget(noteLabel, 2, 0, 1, 3);

            if (walletModel) {
                onGenerateBorrowerAddress();
            }
        } else if (takerIsLender) {
            // Taker is lender - ask for lender address, show maker's borrower address (if available)
            addressLayout->addWidget(new QLabel(tr("Lender Receive Address (you):"), this), 0, 0);
            lenderAddressEdit = new QLineEdit(this);
            lenderAddressEdit->setPlaceholderText(tr("bc1p... (Taproot address)"));
            addressLayout->addWidget(lenderAddressEdit, 0, 1);

            generateLenderButton = new QPushButton(tr("Generate New"), this);
            addressLayout->addWidget(generateLenderButton, 0, 2);
            connect(generateLenderButton, &QPushButton::clicked,
                    this, &ReviewContractOfferDialog::onGenerateLenderAddress);

            addressLayout->addWidget(new QLabel(tr("Borrower Repay Address (maker):"), this), 1, 0);
            borrowerAddressEdit = new QLineEdit(this);
            borrowerAddressEdit->setPlaceholderText(tr("Provided by maker"));
            borrowerAddressEdit->setReadOnly(true);
            addressLayout->addWidget(borrowerAddressEdit, 1, 1);

            generateBorrowerButton = new QPushButton(tr(""), this);
            generateBorrowerButton->setEnabled(false);
            generateBorrowerButton->setVisible(false);
            addressLayout->addWidget(generateBorrowerButton, 1, 2);

            QLabel* noteLabel = new QLabel(this);
            noteLabel->setWordWrap(true);
            noteLabel->setStyleSheet(ThemeHelpers::mutedLabelStyleSheet());
            noteLabel->setText(tr("<i>Provide the address where you (lender) will receive principal repayment. "
                                  "The borrower's address is fixed by the maker.</i>"));
            addressLayout->addWidget(noteLabel, 2, 0, 1, 3);

            if (walletModel) {
                onGenerateLenderAddress();
            }
        } else {
            // Fallback: unknown role, ask for both
            addressLayout->addWidget(new QLabel(tr("Borrower Repay Address:"), this), 0, 0);
            borrowerAddressEdit = new QLineEdit(this);
            borrowerAddressEdit->setPlaceholderText(tr("bc1p..."));
            addressLayout->addWidget(borrowerAddressEdit, 0, 1);

            generateBorrowerButton = new QPushButton(tr("Generate New"), this);
            addressLayout->addWidget(generateBorrowerButton, 0, 2);
            connect(generateBorrowerButton, &QPushButton::clicked,
                    this, &ReviewContractOfferDialog::onGenerateBorrowerAddress);

            addressLayout->addWidget(new QLabel(tr("Lender Receive Address:"), this), 1, 0);
            lenderAddressEdit = new QLineEdit(this);
            lenderAddressEdit->setPlaceholderText(tr("bc1p..."));
            addressLayout->addWidget(lenderAddressEdit, 1, 1);

            generateLenderButton = new QPushButton(tr("Generate New"), this);
            addressLayout->addWidget(generateLenderButton, 1, 2);
            connect(generateLenderButton, &QPushButton::clicked,
                    this, &ReviewContractOfferDialog::onGenerateLenderAddress);
        }
    }

    // Connect toggled signal to hide/show children and collapse layout
    connect(addressGroup, &QGroupBox::toggled, this, [addressGroup, addressLayout](bool checked) {
        // Hide/show all widgets in the layout to collapse/expand
        for (int i = 0; i < addressLayout->count(); ++i) {
            QLayoutItem* item = addressLayout->itemAt(i);
            if (item && item->widget()) {
                item->widget()->setVisible(checked);
            }
        }
        // Force layout recalculation to actually collapse/expand
        // When unchecked, limit height to just the title bar (~40px)
        addressGroup->setMaximumHeight(checked ? QWIDGETSIZE_MAX : 40);
        addressGroup->updateGeometry();
    });

    // Initially hide all children since unchecked by default
    for (int i = 0; i < addressLayout->count(); ++i) {
        QLayoutItem* item = addressLayout->itemAt(i);
        if (item && item->widget()) {
            item->widget()->setVisible(false);
        }
    }
    // Set initial max height to just the title bar
    addressGroup->setMaximumHeight(40);

    mainLayout->addWidget(addressGroup);
    } // end non-bilateral-CFD advanced address group

    mainLayout->addSpacing(20);

    QHBoxLayout* buttonLayout = new QHBoxLayout();

    // Advanced view buttons
    showJsonButton = new QPushButton(tr("Show Raw JSON"), this);
    showJsonButton->setToolTip(tr("View the raw JSON of this offer/contract"));
    connect(showJsonButton, &QPushButton::clicked, this, &ReviewContractOfferDialog::onShowRawJson);
    buttonLayout->addWidget(showJsonButton);

    // Script preview / Greeks describe repo + forward/option leaves and pricing; they have no
    // difficulty-specific variant, so hide them for difficulty term sheets. Scalar-feed CFDs have no
    // pre-open inline pricer at all (scalarcfd.price needs an opened contract), so they hide the
    // script/pricing/greeks buttons entirely — MTM shows in the Book once opened.
    const bool isDifficulty = (m_contractType == QLatin1String("difficulty"));
    const bool isScalarCfd = (m_contractType == QLatin1String("scalarcfd"));

    if (!isDifficulty && !isScalarCfd) {
        showScriptButton = new QPushButton(tr("Show Script Preview"), this);
        showScriptButton->setToolTip(tr("Preview the Bitcoin script for this contract (if available)"));
        connect(showScriptButton, &QPushButton::clicked, this, &ReviewContractOfferDialog::onShowScriptPreview);
        buttonLayout->addWidget(showScriptButton);
    }

    // Add Pricing button for Forward/Option and Difficulty contracts
    if (m_contractType == QLatin1String("forward") || m_contractType == QLatin1String("option")
        || m_contractType == QLatin1String("difficulty")) {
        showPricingButton = new QPushButton(tr("View Pricing"), this);
        showPricingButton->setStyleSheet("QPushButton { background-color: #2196f3; color: white; font-weight: bold; }");
        showPricingButton->setToolTip(tr("View detailed pricing breakdown"));
        connect(showPricingButton, &QPushButton::clicked, this, &ReviewContractOfferDialog::onShowPricing);
        buttonLayout->addWidget(showPricingButton);
    }

    // Add Greeks button (Repo: collateral-option Greeks; Forward/Option: spread Greeks;
    // Difficulty: delta/vega/theta to difficulty). Skipped for scalar-feed CFDs (no pre-open pricer).
    if (!isScalarCfd) {
        showGreeksButton = new QPushButton(tr("View Greeks"), this);
        showGreeksButton->setStyleSheet("QPushButton { background-color: #7c3aed; color: white; font-weight: bold; }");
        showGreeksButton->setToolTip(isDifficulty ? tr("View difficulty Greeks (delta, vega, theta)")
                                                  : tr("View option Greeks (delta, gamma, vega, theta, rho)"));
        connect(showGreeksButton, &QPushButton::clicked, this, &ReviewContractOfferDialog::onShowGreeks);
        buttonLayout->addWidget(showGreeksButton);
    }

    buttonLayout->addStretch();

    rejectButton = new QPushButton(tr("Cancel"), this);
    acceptButton = new QPushButton(
        (isDifficulty || isScalarCfd) ? tr("Accept Offer") : tr("Send Trade Request"), this);
    acceptButton->setStyleSheet(QStringLiteral("QPushButton { background-color: %1; color: white; font-weight: bold; padding: 8px 16px; }").arg(ThemeHelpers::accentTextColor()));

    buttonLayout->addWidget(rejectButton);
    buttonLayout->addWidget(acceptButton);

    connect(rejectButton, &QPushButton::clicked, this, &ReviewContractOfferDialog::onReject);
    connect(acceptButton, &QPushButton::clicked, this, &ReviewContractOfferDialog::onAccept);

    mainLayout->addLayout(buttonLayout);
}

// Compact SI rendering of an inference throughput (tokens/sec) for the difficulty strike representation.
static QString FormatTokensPerSec(double tps)
{
    if (!(tps > 0.0)) return QStringLiteral("n/a");
    static const char* kSuffix[] = {"", "k", "M", "G", "T", "P"};
    int s = 0;
    while (tps >= 1000.0 && s < 5) { tps /= 1000.0; ++s; }
    const int prec = tps < 10.0 ? 2 : (tps < 100.0 ? 1 : 0);
    return QStringLiteral("%1%2 tok/s").arg(QString::number(tps, 'f', prec), kSuffix[s]);
}

QString ReviewContractOfferDialog::formatOfferTerms() const
{
    QString html;

    // Handle difficulty derivative contracts (CFD / option on mining difficulty).
    // SECURITY: render strictly from the embedded SIGNED offer (the bytes that will be accepted),
    // never the outer term sheet — see parseOfferPayload.
    if (m_contractType == QLatin1String("difficulty")) {
        const bool isOption = (m_difficultyKind == QLatin1String("option"));

        if (m_difficultyOfferObj.isEmpty()) {
            html += tr("<p style='color:red;'><b>Warning:</b> This term sheet has no embedded signed "
                       "offer; it cannot be accepted in-app.</p>");
            return html;
        }

        const QJsonObject offer = m_difficultyOfferObj;
        const QJsonObject oterms = offer.value("terms").toObject();
        const double lambdaScale = 65536.0;  // Q16: lambda = lambda_q / 2^16

        const quint32 strike = static_cast<quint32>(oterms.value("strike_nbits").toDouble());
        html += "<table border='0' cellpadding='4' cellspacing='0'>";
        html += tr("<tr><td><b>Contract Type:</b></td><td>Difficulty %1</td></tr>")
            .arg(isOption ? tr("Option") : tr("CFD"));
        html += tr("<tr><td><b>Maker Role:</b></td><td>%1</td></tr>").arg(makerRole.toUpper());
        html += tr("<tr><td><b>Strike (nBits):</b></td><td>0x%1 &nbsp;"
                   "<span style='color:#555;'>&asymp; %2</span></td></tr>")
            .arg(QString::number(strike, 16), FormatTokensPerSec(wallet::DifficultyNBitsToTokensPerSec(strike)));
        html += tr("<tr><td><b>Fixing height:</b></td><td>%1</td></tr>")
            .arg(static_cast<qlonglong>(oterms.value("fixing_height").toDouble()));
        html += tr("<tr><td><b>Settle-lock height:</b></td><td>%1</td></tr>")
            .arg(static_cast<qlonglong>(oterms.value("settle_lock_height").toDouble()));
        html += "</table>";

        if (isOption) {
            html += tr("<h3 style='color:#7E57C2;'>Option Economics</h3>");
            html += "<table border='0' cellpadding='4' cellspacing='0'>";
            html += tr("<tr><td><b>Writer side:</b></td><td>%1</td></tr>")
                .arg(offer.value("writer_side").toString().toUpper());
            html += tr("<tr><td><b>Writer IM:</b></td><td>%1 TSC</td></tr>")
                .arg(QString::number(oterms.value("im").toDouble(), 'f', 8));
            html += tr("<tr><td><b>Leverage (&lambda;):</b></td><td>%1</td></tr>")
                .arg(QString::number(oterms.value("lambda_q").toDouble() / lambdaScale, 'f', 2));
            html += tr("<tr><td><b>Premium:</b></td><td>%1 TSC</td></tr>")
                .arg(QString::number(oterms.value("premium").toDouble(), 'f', 8));
            html += "</table>";
        } else {
            const QJsonObject lo = oterms.value("long").toObject();
            const QJsonObject so = oterms.value("short").toObject();
            html += tr("<h3 style='color:#1976d2;'>Long Leg</h3>");
            html += "<table border='0' cellpadding='4' cellspacing='0'>";
            html += tr("<tr><td><b>Initial margin:</b></td><td>%1 TSC</td></tr>")
                .arg(QString::number(lo.value("im").toDouble(), 'f', 8));
            html += tr("<tr><td><b>Leverage (&lambda;):</b></td><td>%1</td></tr>")
                .arg(QString::number(lo.value("lambda_q").toDouble() / lambdaScale, 'f', 2));
            html += "</table>";
            html += tr("<h3 style='color:#c62828;'>Short Leg</h3>");
            html += "<table border='0' cellpadding='4' cellspacing='0'>";
            html += tr("<tr><td><b>Initial margin:</b></td><td>%1 TSC</td></tr>")
                .arg(QString::number(so.value("im").toDouble(), 'f', 8));
            html += tr("<tr><td><b>Leverage (&lambda;):</b></td><td>%1</td></tr>")
                .arg(QString::number(so.value("lambda_q").toDouble() / lambdaScale, 'f', 2));
            html += "</table>";
        }

        // Advisory pricing mark from the outer term sheet (informational, NOT part of the signed offer).
        html += tr("<h3 style='color:#555;'>Maker's advisory mark "
                   "<span style='color:#9e9e9e;font-weight:normal;'>(informational, not signed)</span></h3>");
        html += "<table border='0' cellpadding='4' cellspacing='0'>";
        if (termSheetMetrics.value("priced").toBool()) {
            html += tr("<tr><td><b>Model:</b></td><td>%1</td></tr>")
                .arg(termSheetMetrics.value("model").toString());
            if (termSheetMetrics.value("model_unreliable").toBool()) {
                html += tr("<tr><td><b>Note:</b></td><td style='color:#b26a00;'>Mark flagged model_unreliable</td></tr>");
            }
            auto mtmRow = [&](const QString& label, const QString& key) {
                if (termSheetMetrics.contains(key)) {
                    html += QStringLiteral("<tr><td><b>%1:</b></td><td>%2 TSC</td></tr>")
                        .arg(label, QString::number(termSheetMetrics.value(key).toDouble() / 1e8, 'f', 8));
                }
            };
            if (isOption) {
                mtmRow(tr("Expected writer MTM"), QStringLiteral("expected_writer_mtm"));
                mtmRow(tr("Expected buyer MTM"), QStringLiteral("expected_buyer_mtm"));
            } else {
                mtmRow(tr("Expected long MTM"), QStringLiteral("expected_long_mtm"));
                mtmRow(tr("Expected short MTM"), QStringLiteral("expected_short_mtm"));
            }
        } else {
            const QString note = termSheetMetrics.value("note").toString();
            html += tr("<tr><td><b>Status:</b></td><td>%1</td></tr>")
                .arg(note.isEmpty() ? tr("Not priced") : note);
        }
        html += "</table>";
        return html;
    }

    // Handle scalar-feed bilateral CFDs (the difficulty sibling, keyed by a published scalar feed).
    // SECURITY: render strictly from the embedded SIGNED offer, never the outer term sheet.
    if (m_contractType == QLatin1String("scalarcfd")) {
        if (m_scalarCfdOfferObj.isEmpty()) {
            html += tr("<p style='color:red;'><b>Warning:</b> This term sheet has no embedded signed "
                       "offer; it cannot be accepted in-app.</p>");
            return html;
        }

        const QJsonObject offer = m_scalarCfdOfferObj;
        const QJsonObject oterms = offer.value("terms").toObject();
        const double lambdaScale = 65536.0;  // Q16: lambda = lambda_q / 2^16
        const int payoffMode = static_cast<int>(oterms.value("payoff_mode").toDouble());
        const int sourceType = static_cast<int>(oterms.value("source_type").toDouble());
        const QString underlying = oterms.value("underlying_asset_id").toString();
        // A chain-intrinsic source commits a zero U (source_type==1, or an all-zero/empty underlying hex).
        static const QRegularExpression allZeroRe(QStringLiteral("^0*$"));
        const bool chainIntrinsic = (sourceType == 1) || underlying.isEmpty() || allZeroRe.match(underlying).hasMatch();

        html += "<table border='0' cellpadding='4' cellspacing='0'>";
        html += tr("<tr><td><b>Contract Type:</b></td><td>Scalar-feed CFD</td></tr>");
        html += tr("<tr><td><b>Maker Role:</b></td><td>%1</td></tr>").arg(makerRole.toUpper());
        html += tr("<tr><td><b>Source:</b></td><td>%1</td></tr>")
            .arg(chainIntrinsic ? tr("chain-intrinsic metric") : tr("issuer-published feed"));
        html += tr("<tr><td><b>Payoff mode:</b></td><td>%1</td></tr>")
            .arg(payoffMode == 1 ? tr("REALIZED (denom X)") : tr("STRIKE (denom K)"));
        html += tr("<tr><td><b>Underlying (U):</b></td><td>%1</td></tr>")
            .arg(chainIntrinsic ? tr("(none — chain-intrinsic)") : underlying);
        html += tr("<tr><td><b>Feed id:</b></td><td>%1</td></tr>")
            .arg(static_cast<qlonglong>(oterms.value("feed_id").toDouble()));
        html += tr("<tr><td><b>Fixing ref (epoch):</b></td><td>%1</td></tr>")
            .arg(static_cast<qlonglong>(oterms.value("fixing_ref").toDouble()));
        html += tr("<tr><td><b>Strike (K):</b></td><td><span style='font-family:monospace;'>%1</span></td></tr>")
            .arg(oterms.value("strike").toString());
        html += tr("<tr><td><b>Fallback scalar:</b></td><td><span style='font-family:monospace;'>%1</span></td></tr>")
            .arg(oterms.value("fallback_scalar").toString());
        html += tr("<tr><td><b>Publication deadline:</b></td><td>H%1</td></tr>")
            .arg(static_cast<qlonglong>(oterms.value("publication_deadline_height").toDouble()));
        html += tr("<tr><td><b>Settle-lock height:</b></td><td>H%1</td></tr>")
            .arg(static_cast<qlonglong>(oterms.value("settle_lock_height").toDouble()));
        html += "</table>";

        // Per-leg IM is a decimal string (collateral units) in the offer; render it verbatim.
        const QJsonObject lo = oterms.value("long").toObject();
        const QJsonObject so = oterms.value("short").toObject();
        html += tr("<h3 style='color:#1976d2;'>Long Leg</h3>");
        html += "<table border='0' cellpadding='4' cellspacing='0'>";
        html += tr("<tr><td><b>Initial margin:</b></td><td>%1</td></tr>").arg(lo.value("im").toString());
        html += tr("<tr><td><b>Leverage (&lambda;):</b></td><td>%1</td></tr>")
            .arg(QString::number(lo.value("lambda_q").toDouble() / lambdaScale, 'f', 2));
        html += "</table>";
        html += tr("<h3 style='color:#c62828;'>Short Leg</h3>");
        html += "<table border='0' cellpadding='4' cellspacing='0'>";
        html += tr("<tr><td><b>Initial margin:</b></td><td>%1</td></tr>").arg(so.value("im").toString());
        html += tr("<tr><td><b>Leverage (&lambda;):</b></td><td>%1</td></tr>")
            .arg(QString::number(so.value("lambda_q").toDouble() / lambdaScale, 'f', 2));
        html += "</table>";
        html += tr("<p style='color:#9e9e9e;'>Mark-to-market is available in the Book once the contract is "
                   "opened (scalar-feed CFDs have no pre-open pricer).</p>");
        return html;
    }

    // Handle forward/options contracts
    if (m_contractType == QLatin1String("forward") || m_contractType == QLatin1String("option")) {
        html += "<table border='0' cellpadding='4' cellspacing='0'>";

        html += tr("<tr><td><b>Contract Type:</b></td><td>%1</td></tr>")
            .arg(m_contractType == QLatin1String("option") ? tr("Option") : tr("Forward"));

        html += tr("<tr><td><b>Maker Role:</b></td><td>%1</td></tr>")
            .arg(makerRole == QLatin1String("long") ? tr("Long") : tr("Short"));

        html += "</table>";

        // Long Party Section
        html += tr("<h3 style='color:#1976d2;'>Long Party</h3>");
        html += "<table border='0' cellpadding='4' cellspacing='0'>";

        html += tr("<tr><td><b>Delivers:</b></td><td>%1 %2</td></tr>")
            .arg(formatAmount(m_longDeliverQty))
            .arg(m_longDeliverAsset);

        html += tr("<tr><td><b>Initial Margin:</b></td><td>%1 %2 (%3%)</td></tr>")
            .arg(formatAmount(m_longMarginQty))
            .arg(m_longMarginAsset)
            .arg(QString::number(m_longIMPercent, 'f', 1));

        if (!m_longMarginDest.isEmpty()) {
            html += tr("<tr><td><b>IM Recovery:</b></td><td>%1</td></tr>")
                .arg(m_longMarginDest);
        }

        if (!m_longSettleDest.isEmpty()) {
            html += tr("<tr><td><b>Settlement Receive:</b></td><td>%1</td></tr>")
                .arg(m_longSettleDest);
        }

        html += "</table>";

        // Short Party Section
        html += tr("<h3 style='color:#d32f2f;'>Short Party</h3>");
        html += "<table border='0' cellpadding='4' cellspacing='0'>";

        html += tr("<tr><td><b>Delivers:</b></td><td>%1 %2</td></tr>")
            .arg(formatAmount(m_shortDeliverQty))
            .arg(m_shortDeliverAsset);

        html += tr("<tr><td><b>Initial Margin:</b></td><td>%1 %2 (%3%)</td></tr>")
            .arg(formatAmount(m_shortMarginQty))
            .arg(m_shortMarginAsset)
            .arg(QString::number(m_shortIMPercent, 'f', 1));

        if (!m_shortMarginDest.isEmpty()) {
            html += tr("<tr><td><b>IM Recovery:</b></td><td>%1</td></tr>")
                .arg(m_shortMarginDest);
        }

        if (!m_shortSettleDest.isEmpty()) {
            html += tr("<tr><td><b>Settlement Receive:</b></td><td>%1</td></tr>")
                .arg(m_shortSettleDest);
        }

        html += "</table>";

        // Premium Section (if applicable)
        if (m_premiumQty > 0) {
            html += tr("<h3 style='color:#f57c00;'>Premium</h3>");
            html += "<table border='0' cellpadding='4' cellspacing='0'>";

            html += tr("<tr><td><b>Amount:</b></td><td>%1 %2</td></tr>")
                .arg(formatAmount(m_premiumQty))
                .arg(m_premiumAsset);

            html += tr("<tr><td><b>Payer:</b></td><td>%1</td></tr>")
                .arg(m_premiumPayer == QLatin1String("long") ? tr("Long") : tr("Short"));

            if (!m_premiumPayeeDest.isEmpty()) {
                html += tr("<tr><td><b>Payee Address:</b></td><td>%1</td></tr>")
                    .arg(m_premiumPayeeDest);
            }

            html += "</table>";
        }

        // Deadlines Section
        html += tr("<h3 style='color:#388e3c;'>Deadlines</h3>");
        html += "<table border='0' cellpadding='4' cellspacing='0'>";

        html += tr("<tr><td><b>Short Delivery:</b></td><td>Block %1 (~%2 days)</td></tr>")
            .arg(m_deadlineShort)
            .arg(m_tenorDaysShort > 0 ? QString::number(m_tenorDaysShort) : tr("TBD"));

        html += tr("<tr><td><b>Long Delivery:</b></td><td>Block %1 (~%2 days)</td></tr>")
            .arg(m_deadlineLong)
            .arg(m_tenorDaysLong > 0 ? QString::number(m_tenorDaysLong) : tr("TBD"));

        if (m_safetyK > 0) {
            html += tr("<tr><td><b>Safety Parameter:</b></td><td>%1</td></tr>")
                .arg(m_safetyK);
        }

        if (m_reorgConf > 0) {
            html += tr("<tr><td><b>Reorg Protection:</b></td><td>%1 blocks</td></tr>")
                .arg(m_reorgConf);
        }

        html += "</table>";

        if (payloadIsTermSheet) {
            html += tr("<p><b><font color='#f57c00'>This is a term sheet. "
                       "The maker will re-issue a finalized offer after receiving your addresses.</font></b></p>");
        }

        return html;
    }

    // Handle spot contracts
    if (m_contractType == QLatin1String("spot")) {
        html += "<table border='0' cellpadding='4' cellspacing='0'>";

        html += tr("<tr><td><b>Contract Type:</b></td><td>Spot Atomic Swap</td></tr>");
        html += tr("<tr><td><b>Maker Role:</b></td><td>Alice</td></tr>");

        html += "</table>";

        // Maker (Alice) Section
        html += tr("<h3 style='color:#1976d2;'>Maker (Alice)</h3>");
        html += "<table border='0' cellpadding='4' cellspacing='0'>";

        html += tr("<tr><td><b>Sends:</b></td><td>%1 %2</td></tr>")
            .arg(formatAmount(m_spotAliceSendQty))
            .arg(m_spotAliceSendAsset);

        html += tr("<tr><td><b>Receives:</b></td><td>%1 %2</td></tr>")
            .arg(formatAmount(m_spotAliceRecvQty))
            .arg(m_spotAliceRecvAsset);

        if (!m_spotAliceDest.isEmpty()) {
            html += tr("<tr><td><b>Receive Address:</b></td><td>%1</td></tr>")
                .arg(m_spotAliceDest);
        }

        html += "</table>";

        // Taker (Bob) Section
        html += tr("<h3 style='color:#d32f2f;'>Taker (You - Bob)</h3>");
        html += "<table border='0' cellpadding='4' cellspacing='0'>";

        html += tr("<tr><td><b>You Send:</b></td><td>%1 %2</td></tr>")
            .arg(formatAmount(m_spotBobSendQty))
            .arg(m_spotBobSendAsset);

        html += tr("<tr><td><b>You Receive:</b></td><td>%1 %2</td></tr>")
            .arg(formatAmount(m_spotBobRecvQty))
            .arg(m_spotBobRecvAsset);

        html += tr("<tr><td><b>Your Receive Address:</b></td><td><i>(Enter below)</i></td></tr>");

        html += "</table>";

        // Exchange Rate Section
        if (m_spotExchangeRate > 0) {
            html += tr("<h3 style='color:#388e3c;'>Exchange Rate</h3>");
            html += "<table border='0' cellpadding='4' cellspacing='0'>";

            html += tr("<tr><td colspan='2'><b>%1 %2 per 1 %3</b></td></tr>")
                .arg(QString::number(m_spotExchangeRate, 'f', 8))
                .arg(m_spotBobSendAsset)
                .arg(m_spotAliceSendAsset);

            html += "</table>";
        }

        // Risk note
        html += tr("<p><b><font color='#f57c00'>Risk Note:</font></b> "
                   "Atomic swap settles in a single transaction. Once broadcast, the transaction is irreversible. "
                   "Verify all amounts and addresses before accepting.</p>");

        return html;
    }

    // Original repo handling
    html += "<table border='0' cellpadding='4' cellspacing='0'>";

    html += tr("<tr><td><b>Maker Role:</b></td><td>%1</td></tr>")
        .arg(makerRole.isEmpty() ? tr("Unknown") : makerRole.toUpper());

    auto getDouble = [](const QVariantMap& map, const QString& key) -> double {
        return map.value(key).toDouble();
    };

    // Robust bool parser for possibly string-normalized fields
    auto variantToBool = [](const QVariant& value, bool fallback) {
        if (!value.isValid()) return fallback;
        switch (static_cast<QMetaType::Type>(value.typeId())) {
        case QMetaType::Bool:
            return value.toBool();
        case QMetaType::Int:
        case QMetaType::LongLong:
            return value.toInt() != 0;
        case QMetaType::QString: {
            const QString s = value.toString().trimmed().toLower();
            if (s == QLatin1String("true") || s == QLatin1String("1") || s == QLatin1String("yes")) return true;
            if (s == QLatin1String("false") || s == QLatin1String("0") || s == QLatin1String("no")) return false;
            return fallback;
        }
        default:
            break;
        }
        return value.toBool();
    };

    // Helper to resolve asset label from term sheet
    auto resolveAsset = [this, &variantToBool](const QString& isNativeKey, const QString& assetIdKey) -> QString {
        bool isNative = variantToBool(termSheetTerms.value(isNativeKey), true);
        if (isNative) {
            return QStringLiteral("TSC");
        }
        QString assetId = termSheetTerms.value(assetIdKey).toString();
        if (assetId.isEmpty()) {
            return QStringLiteral("TSC");
        }
        if (walletModel) {
            WalletModel::AssetInfo assetInfo = walletModel->getAssetInfo(assetId);
            if (!assetInfo.ticker.isEmpty()) {
                return assetInfo.ticker;
            }
        }
        return assetId.left(8) + "...";
    };

    const double collateralAmount = getDouble(termSheetTerms, "collateral_amount");
    const double principalAmount = getDouble(termSheetTerms, "principal_amount");
    const double interestAmount = termSheetTerms.value("interest_amount").toDouble();

    QString collateralAsset = resolveAsset("collateral_is_native", "collateral_asset_id");
    QString principalAsset = resolveAsset("principal_is_native", "principal_asset_id");
    QString interestAsset = resolveAsset("interest_is_native", "interest_asset_id");

    // Determine if interest was explicitly set as native or non-native
    const bool principalIsNative = variantToBool(termSheetTerms.value("principal_is_native"), true);
    const bool interestIsNative = variantToBool(termSheetTerms.value("interest_is_native"), principalIsNative);

    // If interest asset isn't specified, it defaults to principal asset
    if (!interestIsNative && !termSheetTerms.contains("interest_asset_id")) {
        // Only default to principal if interest is non-native but asset_id not provided
        interestAsset = principalAsset;
    }

    html += tr("<tr><td><b>Collateral Amount:</b></td><td>%1 %2</td></tr>")
        .arg(formatAmount(collateralAmount))
        .arg(collateralAsset);
    html += tr("<tr><td><b>Principal Amount:</b></td><td>%1 %2</td></tr>")
        .arg(formatAmount(principalAmount))
        .arg(principalAsset);
    html += tr("<tr><td><b>Interest Amount:</b></td><td>%1 %2</td></tr>")
        .arg(formatAmount(interestAmount))
        .arg(interestAsset);

    if (termSheetMetrics.contains("apr_percent")) {
        html += tr("<tr><td><b>APR:</b></td><td>%1%</td></tr>")
            .arg(QString::number(termSheetMetrics.value("apr_percent").toDouble(), 'f', 2));
    }
    if (termSheetMetrics.contains("ltv_percent")) {
        html += tr("<tr><td><b>LTV:</b></td><td>%1%</td></tr>")
            .arg(QString::number(termSheetMetrics.value("ltv_percent").toDouble(), 'f', 2));
    }
    if (termSheetTerms.contains("maturity_height")) {
        html += tr("<tr><td><b>Maturity Height:</b></td><td>%1</td></tr>")
            .arg(termSheetTerms.value("maturity_height").toInt());
    }

    if (!makerLenderAddress.isEmpty()) {
        html += tr("<tr><td><b>Lender Receive Address:</b></td><td>%1</td></tr>")
            .arg(makerLenderAddress);
    }

    html += "</table>";

    if (payloadIsTermSheet) {
        html += tr("<p><b><font color='#f57c00'>This is a term sheet. "
                   "The maker will re-issue a finalized offer after receiving your repayment address.</font></b></p>");
    }

    return html;
}

bool ReviewContractOfferDialog::validateInputs()
{
    if (!walletModel) {
        QMessageBox::critical(this, tr("Error"), tr("Wallet model not available."));
        return false;
    }

    // Spot-specific validation
    if (m_contractType == QLatin1String("spot")) {
        // Taker (Bob) only needs their receive address
        if (borrowerAddressEdit->text().trimmed().isEmpty()) {
            QMessageBox::warning(this, tr("Validation Error"),
                                 tr("Your receive address is required."));
            return false;
        }

        if (!walletModel->validateAddress(borrowerAddressEdit->text())) {
            QMessageBox::warning(this, tr("Validation Error"),
                                 tr("Receive address is invalid. Provide a valid Taproot address (bc1p...)."));
            return false;
        }

        return true;
    }

    // Determine taker role
    bool takerIsBorrower = (makerRole == "lender");
    bool takerIsLender = (makerRole == "borrower");

    if (takerIsBorrower) {
        // Taker is borrower - validate borrower address
        if (borrowerAddressEdit->text().trimmed().isEmpty()) {
            QMessageBox::warning(this, tr("Validation Error"),
                                 tr("Borrower repayment address is required."));
            return false;
        }

        if (!walletModel->validateAddress(borrowerAddressEdit->text())) {
            QMessageBox::warning(this, tr("Validation Error"),
                                 tr("Borrower address is invalid. Provide a Taproot address you control."));
            return false;
        }
    } else if (takerIsLender) {
        // Taker is lender - validate lender address
        if (lenderAddressEdit->text().trimmed().isEmpty()) {
            QMessageBox::warning(this, tr("Validation Error"),
                                 tr("Lender receive address is required."));
            return false;
        }

        if (!walletModel->validateAddress(lenderAddressEdit->text())) {
            QMessageBox::warning(this, tr("Validation Error"),
                                 tr("Lender address is invalid. Provide a Taproot address you control."));
            return false;
        }
    } else {
        // Fallback: validate both if role is unknown
        if (borrowerAddressEdit->text().trimmed().isEmpty()) {
            QMessageBox::warning(this, tr("Validation Error"),
                                 tr("Borrower repayment address is required."));
            return false;
        }
        if (!walletModel->validateAddress(borrowerAddressEdit->text())) {
            QMessageBox::warning(this, tr("Validation Error"),
                                 tr("Borrower address is invalid."));
            return false;
        }
    }

    return true;
}

void ReviewContractOfferDialog::onAccept()
{
    LogPrintf("[ReviewContractOfferDialog] onAccept called\n");

    // Difficulty derivatives accept locally off the embedded signed offer (no maker session /
    // trade-request round-trip), so they take a dedicated path.
    if (m_contractType == QLatin1String("difficulty")) {
        acceptDifficultyOffer();
        return;
    }
    // Scalar-feed CFDs accept the same way — locally off the embedded signed offer.
    if (m_contractType == QLatin1String("scalarcfd")) {
        acceptScalarCfdOffer();
        return;
    }

    if (!validateInputs()) {
        LogPrintf("[ReviewContractOfferDialog] validateInputs failed, returning\n");
        return;
    }

    const QString offerId = offerData.value("offer_id").toString();
    if (offerId.isEmpty()) {
        LogPrintf("[ReviewContractOfferDialog] offerId is empty, showing error\n");
        QMessageBox::critical(this, tr("Error"),
            tr("Offer identifier missing. Unable to submit trade request."));
        return;
    }

    LogPrintf("[ReviewContractOfferDialog] Processing trade request for offerId: %s\n",
              offerId.toStdString());

    // Determine taker role and include appropriate address
    bool takerIsBorrower = (makerRole == "lender");
    bool takerIsLender = (makerRole == "borrower");

    QJsonObject details;
    QString message;

    // Handle spot taker details
    if (m_contractType == QLatin1String("spot")) {
        details["schema"] = QStringLiteral("spot_taker_details_v1");
        details["timestamp"] = QDateTime::currentDateTimeUtc().toSecsSinceEpoch();
        details["taker_role"] = QStringLiteral("bob");

        // Taker (Bob) provides their receive address
        const QString bobDest = borrowerAddressEdit ? borrowerAddressEdit->text().trimmed() : QString();
        if (bobDest.isEmpty()) {
            QMessageBox::warning(this, tr("Missing Address"),
                tr("Please provide your receive address (where you'll receive the swapped asset)"));
            return;
        }
        details["bob_address"] = bobDest;

        // Include maker's alice_address if known
        if (!m_spotAliceDest.isEmpty()) {
            details["alice_address"] = m_spotAliceDest;
        }

        message = QString::fromUtf8(QJsonDocument(details).toJson(QJsonDocument::Compact));

        LogPrintf("ReviewContractOfferDialog: Spot taker details JSON created: %s\n",
                  message.toStdString().c_str());

    } else if (m_contractType == QLatin1String("forward") || m_contractType == QLatin1String("option")) {
        // Handle forward/options taker details
        details["schema"] = (m_contractType == QLatin1String("option"))
            ? QStringLiteral("option_taker_details_v1")
            : QStringLiteral("forward_taker_details_v1");
        details["timestamp"] = QDateTime::currentDateTimeUtc().toSecsSinceEpoch();

        // Determine taker role (opposite of maker)
        QString takerRole;
        if (makerRole == QLatin1String("long")) {
            takerRole = QStringLiteral("short");
        } else if (makerRole == QLatin1String("short")) {
            takerRole = QStringLiteral("long");
        } else {
            QMessageBox::critical(this, tr("Invalid Offer"),
                tr("Cannot determine taker role: maker_role is '%1'").arg(makerRole));
            return;
        }

        details["taker_role"] = takerRole;

        // Collect taker's addresses based on role
        if (takerRole == QLatin1String("long")) {
            // Taker is long, need long addresses

            // Margin destination (where IM vault will be recovered)
            QString marginDest = lenderAddressEdit ? lenderAddressEdit->text().trimmed() : QString();
            if (marginDest.isEmpty()) {
                QMessageBox::warning(this, tr("Missing Address"),
                    tr("Please provide your margin recovery address (Long IM destination)"));
                return;
            }
            details["long_margin_dest"] = marginDest;

            // Settlement receive (where you'll receive short's asset)
            QString settleDest = borrowerAddressEdit ? borrowerAddressEdit->text().trimmed() : QString();
            if (settleDest.isEmpty()) {
                // Generate a new address if not provided
                if (walletModel) {
                    settleDest = walletModel->getNewAddress(tr("Forward long settlement"), "bech32m");
                    LogPrintf("ReviewContractOfferDialog: Generated long settlement address: %s\n",
                             settleDest.toStdString().c_str());
                }
            }
            if (!settleDest.isEmpty()) {
                details["long_settlement_receive_dest"] = settleDest;
            }

        } else if (takerRole == QLatin1String("short")) {
            // Taker is short, need short addresses

            QString marginDest = borrowerAddressEdit ? borrowerAddressEdit->text().trimmed() : QString();
            if (marginDest.isEmpty()) {
                QMessageBox::warning(this, tr("Missing Address"),
                    tr("Please provide your margin recovery address (Short IM destination)"));
                return;
            }
            details["short_margin_dest"] = marginDest;

            QString settleDest = lenderAddressEdit ? lenderAddressEdit->text().trimmed() : QString();
            if (settleDest.isEmpty()) {
                // Generate a new address if not provided
                if (walletModel) {
                    settleDest = walletModel->getNewAddress(tr("Forward short settlement"), "bech32m");
                    LogPrintf("ReviewContractOfferDialog: Generated short settlement address: %s\n",
                             settleDest.toStdString().c_str());
                }
            }
            if (!settleDest.isEmpty()) {
                details["short_settlement_receive_dest"] = settleDest;
            }
        }

        // Premium payee address (if taker receives premium)
        if (m_premiumQty > 0) {
            // Check if taker is premium receiver
            bool takerReceivesPremium = false;
            if (m_premiumPayer == QLatin1String("long") && takerRole == QLatin1String("short")) {
                takerReceivesPremium = true;
            } else if (m_premiumPayer == QLatin1String("short") && takerRole == QLatin1String("long")) {
                takerReceivesPremium = true;
            }

            if (takerReceivesPremium) {
                // Generate a premium receive address
                QString premiumReceiveAddr;
                if (walletModel) {
                    premiumReceiveAddr = walletModel->getNewAddress(tr("Forward premium receive"), "bech32m");
                    details["premium_payee_dest"] = premiumReceiveAddr;
                    LogPrintf("ReviewContractOfferDialog: Generated premium receive address: %s\n",
                             premiumReceiveAddr.toStdString().c_str());
                } else {
                    QMessageBox::warning(this, tr("Missing Address"),
                        tr("You will receive premium of %1 %2. Unable to generate receive address.")
                        .arg(QString::number(m_premiumQty, 'f', 8)).arg(m_premiumAsset));
                    return;
                }
            }
        }

        message = QString::fromUtf8(QJsonDocument(details).toJson(QJsonDocument::Compact));

    } else {
        // Original repo handling
        details["schema"] = QStringLiteral("repo_taker_details_v1");
        details["timestamp"] = QDateTime::currentDateTimeUtc().toSecsSinceEpoch();

        if (takerIsBorrower) {
            // Taker is borrower - send borrower address
            details["borrower_address"] = borrowerAddressEdit->text();
            if (!makerLenderAddress.isEmpty()) {
                details["maker_lender_address"] = makerLenderAddress;
            }
        } else if (takerIsLender) {
            // Taker is lender - send lender address
            details["lender_address"] = lenderAddressEdit->text();
            // Maker's borrower address would have been in the offer if available
        } else {
            // Fallback: send borrower address (old behavior)
            details["borrower_address"] = borrowerAddressEdit->text();
        }

        message = QString::fromUtf8(QJsonDocument(details).toJson(QJsonDocument::Compact));
    }

    LogPrintf("[ReviewContractOfferDialog] takerIsBorrower: %d takerIsLender: %d walletModel: %p\n",
              takerIsBorrower, takerIsLender, walletModel);

    // Automatic proof of funds generation
    QVariantList proofs;
    LogPrintf("[ReviewContractOfferDialog] Auto-generating proof of funds for taker\n");

    try {
        // Determine required asset and amount based on taker's role
        QString assetToProve;
        uint64_t requiredUnits = 0;
        QString context = QString("trade:%1:taker").arg(offerId);

        // Handle forward/options proof requirements
        if (m_contractType == QLatin1String("forward") || m_contractType == QLatin1String("option")) {
            // For forward/options, determine what taker needs to prove based on their role
            QString takerRole;
            if (makerRole == QLatin1String("long")) {
                takerRole = QStringLiteral("short");
            } else if (makerRole == QLatin1String("short")) {
                takerRole = QStringLiteral("long");
            }

            if (takerRole == QLatin1String("long")) {
                // Taker is long, needs to prove ONLY long INITIAL MARGIN (not delivery asset!)
                double totalRequired = m_longMarginQty;
                assetToProve = m_longMarginAssetId;

                // Convert human-readable amount to base units
                // (amounts are in whole units, need to multiply by 10^decimals)
                if (!m_longMarginAssetId.isEmpty() && walletModel) {
                    WalletModel::AssetInfo assetInfo = walletModel->getAssetInfo(m_longMarginAssetId);
                    int decimals = (assetInfo.has_decimals) ? assetInfo.decimals : 8;
                    requiredUnits = static_cast<uint64_t>(totalRequired * std::pow(10.0, decimals));
                } else {
                    // Native asset (TSC) uses 8 decimals
                    requiredUnits = static_cast<uint64_t>(totalRequired * 1e8);
                }

                LogPrintf("[ReviewContractOfferDialog] Taker is long, needs to prove ONLY MARGIN: %f (%llu base units) of %s\n",
                         totalRequired, requiredUnits, assetToProve.isEmpty() ? "TSC" : assetToProve.toStdString().c_str());

            } else if (takerRole == QLatin1String("short")) {
                // Taker is short, needs to prove ONLY short INITIAL MARGIN (not delivery asset!)
                double totalRequired = m_shortMarginQty;
                assetToProve = m_shortMarginAssetId;

                // Convert human-readable amount to base units
                if (!m_shortMarginAssetId.isEmpty() && walletModel) {
                    WalletModel::AssetInfo assetInfo = walletModel->getAssetInfo(m_shortMarginAssetId);
                    int decimals = (assetInfo.has_decimals) ? assetInfo.decimals : 8;
                    requiredUnits = static_cast<uint64_t>(totalRequired * std::pow(10.0, decimals));
                } else {
                    // Native asset (TSC) uses 8 decimals
                    requiredUnits = static_cast<uint64_t>(totalRequired * 1e8);
                }

                LogPrintf("[ReviewContractOfferDialog] Taker is short, needs to prove ONLY MARGIN: %f (%llu base units) of %s\n",
                         totalRequired, requiredUnits, assetToProve.isEmpty() ? "TSC" : assetToProve.toStdString().c_str());
            }

        } else if (m_contractType == QLatin1String("spot")) {
            // Taker is Bob (spot atomic swap), needs to prove bob_leg funds
            LogPrintf("[ReviewContractOfferDialog] Taker is Bob (spot), calculating bob_leg proof requirement\n");

            // Bob sends bob_leg (Alice receives bob_leg)
            double bobSendQty = m_spotBobSendQty;
            QString bobAssetId = m_spotBobSendAssetId;

            // Determine if bob's asset is native
            bool bobIsNative = bobAssetId.isEmpty();
            assetToProve = bobAssetId;  // Empty for native

            // Get decimals for bob's asset
            int decimals = 8;
            if (!bobIsNative && walletModel) {
                WalletModel::AssetInfo assetInfo = walletModel->getAssetInfo(bobAssetId);
                if (assetInfo.has_decimals) {
                    decimals = assetInfo.decimals;
                }
            }

            // Convert display amount to base units
            requiredUnits = static_cast<uint64_t>(bobSendQty * std::pow(10.0, decimals));

            LogPrintf("[ReviewContractOfferDialog] Bob needs to prove %f %s (%llu base units)\n",
                     bobSendQty, bobIsNative ? "TSC" : bobAssetId.toStdString().c_str(), requiredUnits);

        } else if (takerIsBorrower) {
            // Taker is borrower (repo), needs to prove collateral
            LogPrintf("[ReviewContractOfferDialog] Taker is borrower, calculating collateral proof requirement\n");
            requiredUnits = termSheetTerms.value("collateral_amount").toDouble() * 1e8;  // Convert to units
            LogPrintf("[ReviewContractOfferDialog] Base requiredUnits: %llu\n", requiredUnits);
            bool collateralIsNative = termSheetTerms.value("collateral_is_native", true).toBool();
            LogPrintf("[ReviewContractOfferDialog] collateralIsNative: %d\n", collateralIsNative);
            if (!collateralIsNative) {
                assetToProve = termSheetTerms.value("collateral_asset_id").toString();
                LogPrintf("[ReviewContractOfferDialog] assetToProve: %s\n", assetToProve.toStdString().c_str());
                // For assets, get correct decimal places
                if (walletModel) {
                    LogPrintf("[ReviewContractOfferDialog] Calling getAssetInfo\n");
                    WalletModel::AssetInfo assetInfo = walletModel->getAssetInfo(assetToProve);
                    LogPrintf("[ReviewContractOfferDialog] Got assetInfo, decimals: %d\n", assetInfo.decimals);
                    if (assetInfo.has_decimals) {
                        requiredUnits = static_cast<uint64_t>(termSheetTerms.value("collateral_amount").toDouble() * std::pow(10.0, assetInfo.decimals));
                        LogPrintf("[ReviewContractOfferDialog] Adjusted requiredUnits: %llu\n", requiredUnits);
                    }
                }
            }
            LogPrintf("[ReviewContractOfferDialog] Final requiredUnits: %llu, assetToProve: %s\n", requiredUnits, assetToProve.toStdString().c_str());
        } else if (takerIsLender) {
            // Taker is lender (repo), needs to prove principal
            double principalAmount = termSheetTerms.value("principal_amount").toDouble();
            bool principalIsNative = termSheetTerms.value("principal_is_native", true).toBool();
            if (!principalIsNative) {
                assetToProve = termSheetTerms.value("principal_asset_id").toString();
                // For assets, get correct decimal places
                if (walletModel) {
                    WalletModel::AssetInfo assetInfo = walletModel->getAssetInfo(assetToProve);
                    int decimals = (assetInfo.has_decimals) ? assetInfo.decimals : 8;
                    requiredUnits = static_cast<uint64_t>(principalAmount * std::pow(10.0, decimals));
                } else {
                    requiredUnits = static_cast<uint64_t>(principalAmount * 1e8);
                }
            } else {
                // Native TSC uses 8 decimals
                requiredUnits = static_cast<uint64_t>(principalAmount * 1e8);
            }
        }

        // Auto-generate proofs if requirement known
        if (requiredUnits > 0 && walletModel) {
            auto autoProofResult = walletModel->createProofOfFunds(assetToProve, requiredUnits, context);
            if (autoProofResult.success && !autoProofResult.proofs.isEmpty()) {
                proofs = autoProofResult.proofs;
                LogPrintf("[ReviewContractOfferDialog] Auto-generated %d proofs covering %llu units\n",
                         proofs.size(), autoProofResult.total_units);
            } else {
                LogPrintf("[ReviewContractOfferDialog] Auto-proof generation failed: %s\n",
                         autoProofResult.error.toStdString().c_str());
                // Ask user if they want to proceed without proof or cancel
                QMessageBox::StandardButton proceed = QMessageBox::warning(this,
                    tr("Proof Generation Failed"),
                    tr("Could not automatically generate proof of funds:\n\n%1\n\nDo you want to proceed without proof?\n\n"
                       "Note: The maker may reject your request without proof.").arg(autoProofResult.error),
                    QMessageBox::Yes | QMessageBox::No,
                    QMessageBox::No);

                if (proceed == QMessageBox::No) {
                    LogPrintf("[ReviewContractOfferDialog] User chose not to proceed without proof\n");
                    return;  // Cancel the request
                }
            }
        }
    } catch (const UniValue& e) {
        LogPrintf("[ReviewContractOfferDialog] UniValue exception during auto-proof generation\n");
        QMessageBox::StandardButton proceed = QMessageBox::warning(this,
            tr("Proof Generation Error"),
            tr("An RPC error occurred while generating proof of funds.\n\nDo you want to proceed without proof?\n\n"
               "Note: The maker may reject your request without proof."),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);

        if (proceed == QMessageBox::No) {
            LogPrintf("[ReviewContractOfferDialog] User chose not to proceed after UniValue exception\n");
            return;  // Cancel the request
        }
    } catch (const std::exception& e) {
        LogPrintf("[ReviewContractOfferDialog] Exception during auto-proof generation: %s\n", e.what());
        QMessageBox::StandardButton proceed = QMessageBox::warning(this,
            tr("Proof Generation Error"),
            tr("An error occurred while generating proof of funds:\n\n%1\n\nDo you want to proceed without proof?\n\n"
               "Note: The maker may reject your request without proof.").arg(QString::fromStdString(e.what())),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);

        if (proceed == QMessageBox::No) {
            LogPrintf("[ReviewContractOfferDialog] User chose not to proceed after exception\n");
            return;  // Cancel the request
        }
    } catch (...) {
        LogPrintf("[ReviewContractOfferDialog] Unknown exception during auto-proof generation\n");
        QMessageBox::StandardButton proceed = QMessageBox::warning(this,
            tr("Proof Generation Error"),
            tr("An unknown error occurred while generating proof of funds.\n\nDo you want to proceed without proof?\n\n"
               "Note: The maker may reject your request without proof."),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);

        if (proceed == QMessageBox::No) {
            LogPrintf("[ReviewContractOfferDialog] User chose not to proceed after unknown exception\n");
            return;  // Cancel the request
        }
    }

    // Debug: Log proof count
    LogPrintf("[ReviewContractOfferDialog] Requesting trade with %d proofs\n", proofs.size());
    for (int i = 0; i < proofs.size(); ++i) {
        QVariantMap proof = proofs[i].toMap();
        LogPrintf("  Proof %d: %s asset_id=%s units=%lld\n", i,
                  proof["utxo_ref"].toString().toStdString().c_str(),
                  proof["asset_id"].toString().toStdString().c_str(),
                  proof["asset_units"].toLongLong());
    }

    WalletModel::BulletinBoardRequestTradeResult requestResult =
        walletModel->bulletinBoardRequestTrade(offerId, message, proofs);

    if (!requestResult.success) {
        QMessageBox::warning(this, tr("Request Failed"),
            tr("Trade request could not be submitted:\n\n%1").arg(requestResult.error));
        return;
    }

    QMessageBox::information(this, tr("Request Submitted"),
        tr("Your trade request has been submitted!\n\n"
           "Request ID: %1\n\n"
           "The maker will rebuild the contract with your address and respond shortly.")
            .arg(requestResult.request_id));

    accept();
}

void ReviewContractOfferDialog::acceptDifficultyOffer()
{
    if (!walletModel) {
        QMessageBox::critical(this, tr("Error"), tr("Wallet model not available."));
        return;
    }
    if (m_difficultyOfferJson.isEmpty()) {
        QMessageBox::critical(this, tr("Cannot Accept"),
            tr("This difficulty term sheet does not embed the maker's signed offer, so it "
               "cannot be accepted from the app."));
        return;
    }

    const bool isOption = (m_difficultyKind == QLatin1String("option"));

    // The taker is the opposite side of the maker; surface it in the confirm prompt.
    QString takerRole;
    if (isOption) {
        takerRole = (makerRole == QLatin1String("writer")) ? tr("buyer") : tr("writer");
    } else {
        takerRole = (makerRole == QLatin1String("long")) ? tr("short") : tr("long");
    }

    const QMessageBox::StandardButton confirm = QMessageBox::question(this, tr("Accept Difficulty Offer"),
        tr("Accept this difficulty %1 as the %2 side?\n\n"
           "This generates your payout address(es), registers the contract in this wallet, and "
           "produces an acceptance to send back to the maker so both legs can be funded.")
            .arg(isOption ? tr("option") : tr("CFD"), takerRole),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
    if (confirm != QMessageBox::Yes) return;

    WalletModel::DifficultyAcceptResult res;
    if (isOption) {
        const QString payout = walletModel->getNewAddress(tr("Difficulty option payout"), "bech32m");
        if (payout.isEmpty()) {
            QMessageBox::critical(this, tr("Error"), tr("Failed to generate a payout address."));
            return;
        }
        res = walletModel->difficultyAcceptOption(m_difficultyOfferJson, payout, /*confirmed=*/true);
    } else {
        // CFD: the acceptor supplies two of their own P2TR payout addresses (owner = the leg they
        // post / IM return; cp = their claim on the proposer's leg).
        const QString owner = walletModel->getNewAddress(tr("Difficulty IM return"), "bech32m");
        const QString cp = walletModel->getNewAddress(tr("Difficulty counterparty claim"), "bech32m");
        if (owner.isEmpty() || cp.isEmpty()) {
            QMessageBox::critical(this, tr("Error"), tr("Failed to generate payout addresses."));
            return;
        }
        res = walletModel->difficultyAccept(m_difficultyOfferJson, owner, cp, /*confirmed=*/true);
    }

    if (!res.success) {
        QMessageBox::critical(this, tr("Accept Failed"),
            tr("Could not accept the offer:\n%1").arg(res.error));
        return;
    }

    // The contract is now registered locally (it appears in Active Contracts as "accepted").
    // Hand the acceptance back to the maker so they can import + fund their leg.
    QMessageBox done(this);
    done.setIcon(QMessageBox::Information);
    done.setWindowTitle(tr("Offer Accepted"));
    done.setText(tr("Difficulty %1 accepted.\n\nContract ID: %2\n\n"
                    "Send the acceptance below back to the maker (difficulty.import_acceptance), "
                    "then both parties fund their legs from the Active Contracts tab.")
                    .arg(isOption ? tr("option") : tr("CFD"), res.contract_id));
    if (!res.acceptance_json.isEmpty()) {
        done.setDetailedText(res.acceptance_json);
    }
    QPushButton* copyBtn = done.addButton(tr("Copy Acceptance"), QMessageBox::ActionRole);
    done.addButton(QMessageBox::Ok);
    done.exec();
    if (done.clickedButton() == copyBtn && !res.acceptance_json.isEmpty()) {
        QApplication::clipboard()->setText(res.acceptance_json);
    }

    accept();  // close the review dialog
}

void ReviewContractOfferDialog::acceptScalarCfdOffer()
{
    if (!walletModel) {
        QMessageBox::critical(this, tr("Error"), tr("Wallet model not available."));
        return;
    }
    if (m_scalarCfdOfferJson.isEmpty()) {
        QMessageBox::critical(this, tr("Cannot Accept"),
            tr("This scalar-feed CFD term sheet does not embed the maker's signed offer, so it "
               "cannot be accepted from the app."));
        return;
    }

    // The taker is the opposite side of the maker.
    const QString takerRole = (makerRole == QLatin1String("long")) ? tr("short") : tr("long");

    const QMessageBox::StandardButton confirm = QMessageBox::question(this, tr("Accept Scalar CFD Offer"),
        tr("Accept this scalar-feed CFD as the %1 side?\n\n"
           "This generates your payout addresses, registers the contract in this wallet, and produces an "
           "acceptance to send back to the maker so both legs can be funded.").arg(takerRole),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
    if (confirm != QMessageBox::Yes) return;

    // The acceptor supplies two of their own P2TR payout addresses (owner = the leg they post / IM return;
    // cp = their claim on the proposer's leg).
    const QString owner = walletModel->getNewAddress(tr("Scalar CFD IM return"), "bech32m");
    const QString cp = walletModel->getNewAddress(tr("Scalar CFD counterparty claim"), "bech32m");
    if (owner.isEmpty() || cp.isEmpty()) {
        QMessageBox::critical(this, tr("Error"), tr("Failed to generate payout addresses."));
        return;
    }

    WalletModel::ScalarCfdAcceptResult res =
        walletModel->scalarCfdAccept(m_scalarCfdOfferJson, owner, cp, /*confirmed=*/true);
    if (!res.success) {
        QMessageBox::critical(this, tr("Accept Failed"),
            tr("Could not accept the offer:\n%1").arg(res.error));
        return;
    }

    // The contract is now registered locally (it appears in the Book as "accepted"). Hand the acceptance
    // back to the maker so they can import it (Import Scalar Acceptance) and both legs can be funded.
    QMessageBox done(this);
    done.setIcon(QMessageBox::Information);
    done.setWindowTitle(tr("Offer Accepted"));
    done.setText(tr("Scalar-feed CFD accepted.\n\nContract ID: %1\n\n"
                    "Send the acceptance below back to the maker (Import Scalar Acceptance), then both "
                    "parties fund their legs from the Book.").arg(res.contract_id));
    if (!res.acceptance_json.isEmpty()) {
        done.setDetailedText(res.acceptance_json);
    } else if (!res.action_required.isEmpty()) {
        done.setInformativeText(tr("Next: %1").arg(res.action_required));
    }
    QPushButton* copyBtn = done.addButton(tr("Copy Acceptance"), QMessageBox::ActionRole);
    done.addButton(QMessageBox::Ok);
    done.exec();
    if (done.clickedButton() == copyBtn && !res.acceptance_json.isEmpty()) {
        QApplication::clipboard()->setText(res.acceptance_json);
    }

    accept();  // close the review dialog
}

void ReviewContractOfferDialog::onReject()
{
    reject();
}

void ReviewContractOfferDialog::onGenerateBorrowerAddress()
{
    if (!walletModel) {
        return;
    }

    QString newAddress = walletModel->getNewAddress(tr("Repo borrower repay"));
    if (!newAddress.isEmpty()) {
        borrowerAddressEdit->setText(newAddress);
    }
}

void ReviewContractOfferDialog::onGenerateLenderAddress()
{
    if (!walletModel) {
        return;
    }

    QString newAddress = walletModel->getNewAddress(tr("Repo lender receive"));
    if (!newAddress.isEmpty()) {
        lenderAddressEdit->setText(newAddress);
    }
}

QString ReviewContractOfferDialog::getOfferRawJson() const
{
    // Difficulty term sheets carry their own schema + embedded signed offer; reconstructing them
    // as repo would drop both, so return the original payload verbatim. Scalar-feed CFDs carry the same
    // schema-plus-embedded-offer shape and need the identical verbatim treatment.
    if (m_contractType == QLatin1String("difficulty") || m_contractType == QLatin1String("scalarcfd")) {
        QString payload = offerData.value("contract_payload").toString();
        if (payload.isEmpty()) payload = offerData.value("term_sheet_json").toString();
        const QJsonDocument doc = QJsonDocument::fromJson(payload.toUtf8());
        if (doc.isObject()) {
            return QString::fromUtf8(doc.toJson(QJsonDocument::Indented));
        }
        return payload;
    }

    // If we have parsed payload, show that
    if (payloadIsTermSheet && !termSheetTerms.isEmpty()) {
        QJsonObject root;
        root["schema"] = "repo_term_sheet_v1";
        root["maker_role"] = makerRole;

        // Sanitize boolean fields that might be string-typed (e.g., relays normalizing to strings)
        QVariantMap termsMap = termSheetTerms;
        auto coerceBool = [](const QVariant& v) -> QVariant {
            if (!v.isValid()) return v;
            if (v.typeId() == QMetaType::QString) {
                const QString s = v.toString().trimmed().toLower();
                if (s == QLatin1String("true") || s == QLatin1String("1") || s == QLatin1String("yes")) return QVariant(true);
                if (s == QLatin1String("false") || s == QLatin1String("0") || s == QLatin1String("no")) return QVariant(false);
            }
            return v;
        };
        const QStringList boolKeys = {
            QStringLiteral("collateral_is_native"),
            QStringLiteral("principal_is_native"),
            QStringLiteral("interest_is_native")
        };
        for (const QString& k : boolKeys) {
            if (termsMap.contains(k)) {
                termsMap[k] = coerceBool(termsMap.value(k));
            }
        }
        root["terms"] = QJsonObject::fromVariantMap(termsMap);
        root["metrics"] = QJsonObject::fromVariantMap(termSheetMetrics);
        if (!makerLenderAddress.isEmpty()) {
            root["lender_address"] = makerLenderAddress;
        }
        QJsonDocument doc(root);
        return QString::fromUtf8(doc.toJson(QJsonDocument::Indented));
    } else if (payloadIsFinalOffer) {
        QJsonDocument doc(finalOfferObject);
        return QString::fromUtf8(doc.toJson(QJsonDocument::Indented));
    } else {
        // Fallback: show the raw offerData
        QJsonObject jsonObj = QJsonObject::fromVariantMap(offerData);
        QJsonDocument doc(jsonObj);
        return QString::fromUtf8(doc.toJson(QJsonDocument::Indented));
    }
}

void ReviewContractOfferDialog::onShowRawJson()
{
    QDialog* jsonDialog = new QDialog(this);
    jsonDialog->setWindowTitle(tr("Offer Raw JSON"));
    jsonDialog->setMinimumWidth(700);
    jsonDialog->setMinimumHeight(500);

    QVBoxLayout* layout = new QVBoxLayout(jsonDialog);

    QLabel* titleLabel = new QLabel(tr("<b>Raw JSON Representation:</b>"));
    layout->addWidget(titleLabel);

    QTextEdit* jsonText = new QTextEdit();
    jsonText->setReadOnly(true);
    jsonText->setFont(QFont("Courier", 10));
    jsonText->setPlainText(getOfferRawJson());
    layout->addWidget(jsonText);

    QHBoxLayout* buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch();

    QPushButton* copyButton = new QPushButton(tr("Copy to Clipboard"));
    connect(copyButton, &QPushButton::clicked, [jsonText]() {
        QApplication::clipboard()->setText(jsonText->toPlainText());
    });
    buttonLayout->addWidget(copyButton);

    QPushButton* closeBtn = new QPushButton(tr("Close"));
    connect(closeBtn, &QPushButton::clicked, jsonDialog, &QDialog::accept);
    buttonLayout->addWidget(closeBtn);

    layout->addLayout(buttonLayout);

    jsonDialog->exec();
    delete jsonDialog;
}

void ReviewContractOfferDialog::onShowScriptPreview()
{
    // Check if script information is available
    QString scriptInfo;

    if (payloadIsFinalOffer) {
        if (finalOfferObject.contains("script_hex")) {
            scriptInfo = finalOfferObject.value("script_hex").toString();
        } else if (finalOfferObject.contains("witness_script")) {
            scriptInfo = finalOfferObject.value("witness_script").toString();
        } else if (finalOfferObject.contains("taproot_script")) {
            scriptInfo = finalOfferObject.value("taproot_script").toString();
        }
    }

    if (scriptInfo.isEmpty()) {
        // Script not available - show informational message
        QMessageBox infoBox(this);
        infoBox.setWindowTitle(tr("Script Preview"));
        infoBox.setIcon(QMessageBox::Information);
        infoBox.setText(tr("Bitcoin Script Preview"));

        QString detailText = tr("<b>Script Type:</b> Taproot v1 (P2TR)<br><br>"
                       "<b>Structure:</b> 2-leaf Taproot script<br>"
                       "• <b>Key Path:</b> Disabled (NUMS point)<br>"
                       "• <b>Leaf A (Repayment):</b> OP_OUTPUTMATCH_ASSET + Borrower signature<br>"
                       "• <b>Leaf B (Default):</b> OP_CHECKLOCKTIMEVERIFY + Lender signature<br><br>"
                       "<b>Note:</b> The actual script will be created when the contract is opened on-chain. "
                       "This is a term sheet or offer - the full script details will be available after contract creation.");

        infoBox.setInformativeText(detailText);
        infoBox.setStandardButtons(QMessageBox::Ok);
        infoBox.exec();
        return;
    }

    // Script is available - show it in a dialog
    QDialog* scriptDialog = new QDialog(this);
    scriptDialog->setWindowTitle(tr("Bitcoin Script Preview"));
    scriptDialog->setMinimumWidth(700);
    scriptDialog->setMinimumHeight(500);

    QVBoxLayout* layout = new QVBoxLayout(scriptDialog);

    QLabel* titleLabel = new QLabel(tr("<b>Bitcoin Script (Hex):</b>"));
    layout->addWidget(titleLabel);

    QTextEdit* scriptText = new QTextEdit();
    scriptText->setReadOnly(true);
    scriptText->setFont(QFont("Courier", 10));
    scriptText->setPlainText(scriptInfo);
    layout->addWidget(scriptText);

    QHBoxLayout* buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch();

    QPushButton* copyButton = new QPushButton(tr("Copy to Clipboard"));
    connect(copyButton, &QPushButton::clicked, [scriptText]() {
        QApplication::clipboard()->setText(scriptText->toPlainText());
    });
    buttonLayout->addWidget(copyButton);

    QPushButton* closeBtn = new QPushButton(tr("Close"));
    connect(closeBtn, &QPushButton::clicked, scriptDialog, &QDialog::accept);
    buttonLayout->addWidget(closeBtn);

    layout->addLayout(buttonLayout);

    scriptDialog->exec();
    delete scriptDialog;
}

namespace {
// Build pricing.difficulty.quote inline_terms from a parsed difficulty offer object.
QVariantMap BuildDifficultyInlineTerms(const QJsonObject& offer, const QString& kind)
{
    QVariantMap t;
    const QJsonObject oterms = offer.value("terms").toObject();
    t["kind"] = kind;
    t["strike_nbits"] = static_cast<qlonglong>(oterms.value("strike_nbits").toDouble());
    t["fixing_height"] = static_cast<qlonglong>(oterms.value("fixing_height").toDouble());
    t["settle_lock_height"] = static_cast<qlonglong>(oterms.value("settle_lock_height").toDouble());
    if (kind == QLatin1String("option")) {
        t["writer_side"] = offer.value("writer_side").toString();
        t["im"] = oterms.value("im").toDouble();          // TSC; wrapper stringifies for AmountFromValue
        t["lambda_q"] = static_cast<qlonglong>(oterms.value("lambda_q").toDouble());
        t["premium"] = oterms.value("premium").toDouble();
    } else {
        const QJsonObject lo = oterms.value("long").toObject();
        const QJsonObject so = oterms.value("short").toObject();
        t["long_im"] = lo.value("im").toDouble();
        t["long_lambda_q"] = static_cast<qlonglong>(lo.value("lambda_q").toDouble());
        t["short_im"] = so.value("im").toDouble();
        t["short_lambda_q"] = static_cast<qlonglong>(so.value("lambda_q").toDouble());
    }
    return t;
}
} // namespace

void ReviewContractOfferDialog::onShowPricing()
{
    if (!walletModel) {
        QMessageBox::warning(this, tr("Pricing"), tr("Wallet model not available"));
        return;
    }

    try {
        // Build inline_terms from parsed contract data
        QVariantMap inlineTerms;

        if (m_contractType == QLatin1String("forward") || m_contractType == QLatin1String("option")) {
            // Forward/Option contracts
            inlineTerms["long_party_deliver_units"] = static_cast<qint64>(m_longDeliverQty * 1e8);
            inlineTerms["long_party_deliver_asset"] = m_longDeliverAssetId.isEmpty() ? "" : m_longDeliverAssetId;
            inlineTerms["long_party_deliver_is_native"] = m_longDeliverAssetId.isEmpty();

            inlineTerms["short_party_deliver_units"] = static_cast<qint64>(m_shortDeliverQty * 1e8);
            inlineTerms["short_party_deliver_asset"] = m_shortDeliverAssetId.isEmpty() ? "" : m_shortDeliverAssetId;
            inlineTerms["short_party_deliver_is_native"] = m_shortDeliverAssetId.isEmpty();

            inlineTerms["long_party_margin_units"] = static_cast<qint64>(m_longMarginQty * 1e8);
            inlineTerms["long_party_margin_asset"] = m_longMarginAssetId.isEmpty() ? "" : m_longMarginAssetId;
            inlineTerms["long_party_margin_is_native"] = m_longMarginAssetId.isEmpty();

            inlineTerms["short_party_margin_units"] = static_cast<qint64>(m_shortMarginQty * 1e8);
            inlineTerms["short_party_margin_asset"] = m_shortMarginAssetId.isEmpty() ? "" : m_shortMarginAssetId;
            inlineTerms["short_party_margin_is_native"] = m_shortMarginAssetId.isEmpty();

            inlineTerms["premium_units"] = static_cast<qint64>(m_premiumQty * 1e8);
            inlineTerms["premium_asset"] = m_premiumAssetId.isEmpty() ? "" : m_premiumAssetId;
            inlineTerms["premium_is_native"] = m_premiumAssetId.isEmpty();

            inlineTerms["deadline_short"] = m_deadlineShort;
            inlineTerms["deadline_long"] = m_deadlineLong;
            inlineTerms["safety_k"] = m_safetyK;

            PricingBreakdownDialog::PricingData pricingData;
            pricingData.type = m_contractType == QLatin1String("option") ?
                               PricingBreakdownDialog::Option : PricingBreakdownDialog::Forward;
            pricingData.contractId = "";
            pricingData.inlineTerms = inlineTerms;
            pricingData.reportAsset = "";
            pricingData.reportIsNative = true;
            pricingData.priceSource = "mark";

            PricingBreakdownDialog dialog(walletModel, pricingData, this);
            dialog.exec();
        }
        else if (m_contractType == QLatin1String("difficulty")) {
            if (m_difficultyOfferObj.isEmpty()) {
                QMessageBox::information(this, tr("Pricing"), tr("This term sheet has no embedded offer to price."));
                return;
            }
            PricingBreakdownDialog::PricingData pricingData;
            pricingData.type = PricingBreakdownDialog::Difficulty;
            pricingData.contractId = "";
            pricingData.inlineTerms = BuildDifficultyInlineTerms(m_difficultyOfferObj, m_difficultyKind);
            pricingData.reportAsset = "";
            pricingData.reportIsNative = true;
            pricingData.priceSource = "market";  // difficulty model/calibrated tier
            PricingBreakdownDialog dialog(walletModel, pricingData, this);
            dialog.exec();
        }

    } catch (const std::exception& e) {
        QMessageBox::critical(this, tr("Pricing Error"),
            tr("Failed to show pricing:\n\n%1").arg(QString::fromStdString(e.what())));
    }
}

void ReviewContractOfferDialog::onShowGreeks()
{
    if (!walletModel) {
        QMessageBox::warning(this, tr("Greeks"), tr("Wallet model not available"));
        return;
    }

    try {
        // Build inline_terms from parsed contract data
        QVariantMap inlineTerms;
        GreeksVisualizationDialog::GreeksData greeksData;

        if (m_contractType == QLatin1String("repo")) {
            // Repo contracts - extract from termSheetTerms
            inlineTerms["collateral_asset"] = termSheetTerms.value("collateral_asset").toString();
            inlineTerms["collateral_is_native"] = termSheetTerms.value("collateral_is_native").toBool();
            inlineTerms["collateral_units"] = termSheetTerms.value("collateral_units").toLongLong();

            inlineTerms["principal_asset"] = termSheetTerms.value("principal_asset").toString();
            inlineTerms["principal_is_native"] = termSheetTerms.value("principal_is_native").toBool();
            inlineTerms["principal_units"] = termSheetTerms.value("principal_units").toLongLong();

            inlineTerms["interest_asset"] = termSheetTerms.value("interest_asset").toString();
            inlineTerms["interest_is_native"] = termSheetTerms.value("interest_is_native").toBool();
            inlineTerms["interest_units"] = termSheetTerms.value("interest_units").toLongLong();

            inlineTerms["maturity_height"] = termSheetTerms.value("maturity_height").toInt();
            inlineTerms["safety_k"] = termSheetTerms.value("safety_k", 2).toInt();

            greeksData.type = GreeksVisualizationDialog::Repo;

        } else if (m_contractType == QLatin1String("forward") || m_contractType == QLatin1String("option")) {
            // Forward/Option contracts
            inlineTerms["long_party_deliver_units"] = static_cast<qint64>(m_longDeliverQty * 1e8);
            inlineTerms["long_party_deliver_asset"] = m_longDeliverAssetId.isEmpty() ? "" : m_longDeliverAssetId;
            inlineTerms["long_party_deliver_is_native"] = m_longDeliverAssetId.isEmpty();

            inlineTerms["short_party_deliver_units"] = static_cast<qint64>(m_shortDeliverQty * 1e8);
            inlineTerms["short_party_deliver_asset"] = m_shortDeliverAssetId.isEmpty() ? "" : m_shortDeliverAssetId;
            inlineTerms["short_party_deliver_is_native"] = m_shortDeliverAssetId.isEmpty();

            inlineTerms["long_party_margin_units"] = static_cast<qint64>(m_longMarginQty * 1e8);
            inlineTerms["long_party_margin_asset"] = m_longMarginAssetId.isEmpty() ? "" : m_longMarginAssetId;
            inlineTerms["long_party_margin_is_native"] = m_longMarginAssetId.isEmpty();

            inlineTerms["short_party_margin_units"] = static_cast<qint64>(m_shortMarginQty * 1e8);
            inlineTerms["short_party_margin_asset"] = m_shortMarginAssetId.isEmpty() ? "" : m_shortMarginAssetId;
            inlineTerms["short_party_margin_is_native"] = m_shortMarginAssetId.isEmpty();

            inlineTerms["premium_units"] = static_cast<qint64>(m_premiumQty * 1e8);
            inlineTerms["premium_asset"] = m_premiumAssetId.isEmpty() ? "" : m_premiumAssetId;
            inlineTerms["premium_is_native"] = m_premiumAssetId.isEmpty();

            inlineTerms["deadline_short"] = m_deadlineShort;
            inlineTerms["deadline_long"] = m_deadlineLong;
            inlineTerms["safety_k"] = m_safetyK;

            greeksData.type = m_contractType == QLatin1String("option") ?
                              GreeksVisualizationDialog::Option : GreeksVisualizationDialog::Forward;
        } else if (m_contractType == QLatin1String("difficulty")) {
            if (m_difficultyOfferObj.isEmpty()) {
                QMessageBox::information(this, tr("Greeks"), tr("This term sheet has no embedded offer to price."));
                return;
            }
            inlineTerms = BuildDifficultyInlineTerms(m_difficultyOfferObj, m_difficultyKind);
            greeksData.type = GreeksVisualizationDialog::Difficulty;
        }

        greeksData.contractId = "";
        greeksData.inlineTerms = inlineTerms;
        greeksData.reportAsset = "";
        greeksData.reportIsNative = true;

        GreeksVisualizationDialog dialog(walletModel, greeksData, this);
        dialog.exec();

    } catch (const std::exception& e) {
        QMessageBox::critical(this, tr("Greeks Error"),
            tr("Failed to show Greeks:\n\n%1").arg(QString::fromStdString(e.what())));
    }
}
