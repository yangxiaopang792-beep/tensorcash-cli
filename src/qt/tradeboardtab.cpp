// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <qt/tradeboardtab.h>
#include <qt/bridgesessionmanager.h>
#include <qt/commitmentproofdialog.h>
#include <qt/platformstyle.h>
#include <qt/walletmodel.h>
#include <qt/clientmodel.h>
#include <qt/guiutil.h>
#include <qt/bitcoinunits.h>
#include <qt/repocontractbuilder.h>
#include <qt/forwardcontractbuilder.h>
#include <qt/spotcontractbuilder.h>
#include <qt/difficultycontractbuilder.h>
#include <qt/crosschaincontractbuilder.h>
#include <qt/crosschainprofiledialog.h>
#include <qt/crosschaintradeview.h>
#include <qt/opencontractdialog.h>
#include <qt/reviewcontractofferdialog.h>
#include <qt/finalcontractreviewdialog.h>
#include <qt/proofbuilder.h>
#include <qt/assetpricetab.h>
#include <qt/tormanager.h>
#include <logging.h>
#include <interfaces/handler.h>
#include <interfaces/node.h>
#include <psbt.h>
#include <uint256.h>
#include <univalue.h>
#include <key_io.h>
#include <common/args.h>
#include <addresstype.h>
#include <wallet/difficulty_contract.h>  // DifficultyNBitsToTokensPerSec / DifficultyFormatTokensPerSec
#include <util/strencodings.h>
#include <util/moneystr.h>
#include <algorithm>
#include <cmath>

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QTableWidget>
#include <QHeaderView>
#include <QGroupBox>
#include <QMessageBox>
#include <QDateTime>
#include <QAbstractButton>
#include <QTimer>
#include <QInputDialog>
#include <QCheckBox>
#include <QLineEdit>
#include <QDoubleSpinBox>
#include <QDialog>
#include <QSplitter>
#include <QComboBox>
#include <QRegularExpression>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QApplication>
#include <QClipboard>
#include <QFile>
#include <QFileDialog>
#include <QTextEdit>
#include <QMetaType>
#include <QProgressDialog>
#include <QSettings>
#include <QtConcurrent/QtConcurrent>
#include <QFuture>
#include <QFutureWatcher>
#include <QStringList>
#include <QPointer>
#include <assets/asset.h>
#include <functional>
#include <atomic>
#include <cmath>
#include <optional>
#include <QCryptographicHash>
#include <QUuid>
#include <QRandomGenerator>
#include <limits>
#include <set>
#include <variant>

#include <qt/sasverificationdialog.h>

namespace {
QWidget* TopLevelDialogParent(QWidget* widget)
{
    return widget && widget->window() ? widget->window() : widget;
}

QString CosignRoomIdFromInviteLink(const QString& inviteLink)
{
    const int queryStart = inviteLink.indexOf('?');
    if (queryStart < 0) return QString();

    int queryEnd = inviteLink.indexOf('#', queryStart + 1);
    if (queryEnd < 0) queryEnd = inviteLink.size();

    const QString query = inviteLink.mid(queryStart + 1, queryEnd - queryStart - 1);
    const QStringList parts = query.split('&', Qt::SkipEmptyParts);
    for (const QString& part : parts) {
        if (part.startsWith(QStringLiteral("r="))) {
            return QString::fromUtf8(QByteArray::fromPercentEncoding(part.mid(2).toUtf8()));
        }
    }
    return QString();
}

QString AutoJoinAttemptKey(const QString& requestId, const QString& inviteLink)
{
    return requestId + QStringLiteral("\n") + inviteLink;
}

QString ComputePsbtTxHash(const QString& psbtBase64)
{
    const std::string psbtStr = psbtBase64.toStdString();
    PartiallySignedTransaction decoded;
    std::string error;
    if (DecodeBase64PSBT(decoded, psbtStr, error) && decoded.tx) {
        return QString::fromStdString(decoded.tx->GetHash().ToString());
    }
    std::vector<unsigned char> psbtBytes(psbtStr.begin(), psbtStr.end());
    return QString::fromStdString(Hash(psbtBytes).ToString());
}

static bool IsTaprootScript(const CScript& spk)
{
    int witversion = 0;
    std::vector<unsigned char> witprog;
    return spk.IsWitnessProgram(witversion, witprog) && witversion == 1 && witprog.size() == 32;
}

// Decide a safe sighash override for walletprocesspsbt(sign=true):
// - If ALL inputs are Taproot (v1, 32-byte program), use "DEFAULT" (preferred for Taproot).
// - Otherwise use "ALL" to ensure segwit v0/legacy inputs get a valid sighash and avoid ANYONECANPAY.
// This keeps asset policy constraints intact while allowing mixed-input transactions to sign.
// Note: sighash selection is delegated to walletprocesspsbt via empty override.

// Minimal struct to hold repo terms extracted from a finalized offer JSON
struct RepoTermsSnapshot {
    bool principal_is_native{true};
    QString principal_asset_id; // empty when native
    uint64_t principal_units{0};
    bool collateral_is_native{true};
    QString collateral_asset_id; // empty when native
    uint64_t collateral_units{0};
    QString borrower_address;
    QString lender_address;
};

static bool ExtractRepoTermsFromJson(const QString& offerJson, RepoTermsSnapshot& out)
{
    if (offerJson.isEmpty()) return false;
    QJsonParseError perr;
    QJsonDocument doc = QJsonDocument::fromJson(offerJson.toUtf8(), &perr);
    if (doc.isNull() || !doc.isObject()) return false;
    QJsonObject root = doc.object();

    if (root.contains("borrower_address")) out.borrower_address = root.value("borrower_address").toString();
    if (root.contains("lender_address")) out.lender_address = root.value("lender_address").toString();

    auto parse_legs = [&](const QJsonObject& terms) {
        if (terms.contains("principal_leg") && terms.value("principal_leg").isObject()) {
            QJsonObject leg = terms.value("principal_leg").toObject();
            out.principal_is_native = leg.value("is_native").toBool(true);
            out.principal_asset_id = leg.value("asset_id").toString();
            out.principal_units = static_cast<uint64_t>(leg.value("units").toDouble(0.0));
        } else {
            // Fallback
            out.principal_is_native = terms.value("principal_is_native").toBool(true);
            out.principal_asset_id = terms.value("principal_asset_id").toString();
            out.principal_units = static_cast<uint64_t>(terms.value("principal_sats").toDouble(0.0));
        }

        if (terms.contains("collateral_leg") && terms.value("collateral_leg").isObject()) {
            QJsonObject leg = terms.value("collateral_leg").toObject();
            out.collateral_is_native = leg.value("is_native").toBool(true);
            out.collateral_asset_id = leg.value("asset_id").toString();
            out.collateral_units = static_cast<uint64_t>(leg.value("units").toDouble(0.0));
        } else {
            out.collateral_is_native = terms.value("collateral_is_native").toBool(true);
            out.collateral_asset_id = terms.value("collateral_asset_id").toString();
            out.collateral_units = static_cast<uint64_t>(terms.value("collateral_sats").toDouble(0.0));
        }
    };

    if (root.contains("terms") && root.value("terms").isObject()) {
        parse_legs(root.value("terms").toObject());
        return true;
    }
    return false;
}

static bool RepoPsbtMatchesTerms(const PartiallySignedTransaction& psbtx,
                                 const RepoTermsSnapshot& t,
                                 bool require_principal,
                                 bool require_collateral,
                                 QString* why_not)
{
    // Build borrower script
    CTxDestination borrower_dest = DecodeDestination(t.borrower_address.toStdString());
    CScript borrower_spk = GetScriptForDestination(borrower_dest);

    bool principal_ok = !require_principal; // if not required, it's ok by default
    bool collateral_ok = !require_collateral;

    for (const CTxOut& out : psbtx.tx->vout) {
        // Check principal to borrower
        if (!principal_ok && out.scriptPubKey == borrower_spk) {
            if (t.principal_is_native) {
                if (out.nValue == static_cast<CAmount>(t.principal_units)) principal_ok = true;
            } else {
                if (const auto tag = assets::ParseAssetTag(out.vExt)) {
                    if (QString::fromStdString(tag->id.GetHex()) == t.principal_asset_id &&
                        tag->amount == t.principal_units) {
                        principal_ok = true;
                    }
                }
            }
        }

        // Check collateral vault presence and quantity
        if (!collateral_ok && IsTaprootScript(out.scriptPubKey)) {
            if (t.collateral_is_native) {
                if (out.nValue == static_cast<CAmount>(t.collateral_units)) collateral_ok = true;
            } else {
                if (const auto tag = assets::ParseAssetTag(out.vExt)) {
                    if (QString::fromStdString(tag->id.GetHex()) == t.collateral_asset_id &&
                        tag->amount == t.collateral_units) {
                        collateral_ok = true;
                    }
                }
            }
        }

        if (principal_ok && collateral_ok) break;
    }

    if (!principal_ok && why_not) *why_not = QObject::tr("Principal output missing or mismatched");
    if (!collateral_ok && why_not) *why_not = QObject::tr("Collateral vault output missing or mismatched");
    return principal_ok && collateral_ok;
}

// Helper to unlock wallet-level Fair-Sign UTXOs for a specific PSBT
static void UnlockFairSignUTXOsForPsbt(WalletModel* walletModel, const QString& psbtBase64, const QString& context)
{
    if (!walletModel || psbtBase64.isEmpty()) return;

    QString txid = ComputePsbtTxHash(psbtBase64);
    if (txid.isEmpty()) {
        LogPrintf("TradeBoardTab: %s - Cannot unlock UTXOs, invalid PSBT\n", context.toStdString().c_str());
        return;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(txid.toStdString());

        // Call lockunspent to unlock all coins for this specific tx
        // We use the wallet's internal mechanism via RPC to ensure proper unlocking
        UniValue unlock_params(UniValue::VARR);
        unlock_params.push_back(true); // unlock = true

        // Get list of locked coins to filter by our txid
        UniValue locked_list = walletModel->node().executeRpc("listlockunspent", UniValue(UniValue::VARR), walletModel->getWalletName().toStdString());

        if (locked_list.isArray() && locked_list.size() > 0) {
            UniValue outputs_to_unlock(UniValue::VARR);
            for (size_t i = 0; i < locked_list.size(); ++i) {
                const UniValue& locked_coin = locked_list[i];
                // Unlock all locked coins (Fair-Sign sessions use wallet-level locking)
                outputs_to_unlock.push_back(locked_coin);
            }

            if (outputs_to_unlock.size() > 0) {
                unlock_params.push_back(outputs_to_unlock);
                UniValue result = walletModel->node().executeRpc("lockunspent", unlock_params, walletModel->getWalletName().toStdString());
                LogPrintf("TradeBoardTab: %s - Unlocked %d UTXOs for tx %s\n",
                         context.toStdString().c_str(), (int)outputs_to_unlock.size(), txid.toStdString().c_str());
            }
        }
    } catch (const std::exception& e) {
        LogPrintf("TradeBoardTab: %s - Failed to unlock Fair-Sign UTXOs for tx %s: %s\n",
                 context.toStdString().c_str(), txid.toStdString().c_str(), e.what());
    }
}

enum class AcceptanceStage {
    None,
    ImportOffer,
    AcceptOffer,
    ParseAcceptance,
    SendAcceptance
};

enum class ConfirmationStage {
    None,
    ImportAcceptance,
    SendCeremonyInvite
};

struct AcceptanceFlowResult {
    bool success{false};
    AcceptanceStage failureStage{AcceptanceStage::None};
    QString errorDetail;
    QString acceptanceEnvelope;
    bool sessionLost{false};
    bool parseError{false};
    bool missingAcceptanceField{false};
};

struct ConfirmationFlowResult {
    bool success{false};
    ConfirmationStage failureStage{ConfirmationStage::None};
    QString errorDetail;
    QString ceremonyInviteJson;
    bool sessionLost{false};
};

QString extractPsbtFromPayload(const QString& payloadJson, QString* typeOut = nullptr, QString* errorOut = nullptr)
{
    if (payloadJson.isEmpty()) {
        if (errorOut) *errorOut = QCoreApplication::translate("TradeBoardTab", "Empty payload");
        return {};
    }

    QJsonParseError parseError;
    QJsonDocument doc = QJsonDocument::fromJson(payloadJson.toUtf8(), &parseError);
    if (doc.isNull() || !doc.isObject()) {
        if (errorOut) {
            *errorOut = parseError.errorString().isEmpty() ? QCoreApplication::translate("TradeBoardTab", "Invalid JSON") : parseError.errorString();
        }
        return {};
    }

    std::function<QString(const QJsonObject&)> finder = [&](const QJsonObject& obj) -> QString {
        if (obj.contains("type") && obj.value("type").isString()) {
            QString type = obj.value("type").toString();
            if (type == QStringLiteral("ceremony_error")) {
                QString detail = obj.value("error").toString();
                if (errorOut) {
                    if (detail.isEmpty()) {
                        *errorOut = QCoreApplication::translate("TradeBoardTab", "Peer reported ceremony error");
                    } else {
                        *errorOut = QCoreApplication::translate("TradeBoardTab", "Peer reported ceremony error: %1").arg(detail);
                    }
                }
                return {};
            }
            if (type == QStringLiteral("ceremony_abort")) {
                // Counterparty has unwound their ceremony and will not send any
                // further phase messages. Compose a single readable string from
                // phase/role/reason so receivePsbt() surfaces it through
                // stageError() instead of the generic "payload missing PSBT".
                if (errorOut) {
                    const QString phase = obj.value("phase").toString();
                    const QString role = obj.value("role").toString();
                    const QString reason = obj.value("reason").toString();
                    const QString actor = role.isEmpty()
                        ? QCoreApplication::translate("TradeBoardTab", "counterparty")
                        : QCoreApplication::translate("TradeBoardTab", "counterparty (%1)").arg(role);
                    QString detail;
                    if (!phase.isEmpty() && !reason.isEmpty()) {
                        detail = QCoreApplication::translate("TradeBoardTab", "during %1: %2").arg(phase, reason);
                    } else if (!phase.isEmpty()) {
                        detail = QCoreApplication::translate("TradeBoardTab", "during %1").arg(phase);
                    } else if (!reason.isEmpty()) {
                        detail = reason;
                    }
                    *errorOut = detail.isEmpty()
                        ? QCoreApplication::translate("TradeBoardTab", "%1 aborted the ceremony").arg(actor)
                        : QCoreApplication::translate("TradeBoardTab", "%1 aborted the ceremony %2").arg(actor, detail);
                }
                return {};
            }
        }

        if (obj.contains("psbt") && obj.value("psbt").isString()) {
            if (typeOut && obj.contains("type") && obj.value("type").isString()) {
                *typeOut = obj.value("type").toString();
            }
            return obj.value("psbt").toString();
        }

        static const char* kNestedKeys[] = {"payload", "echo", "data", "response"};
        for (const char* key : kNestedKeys) {
            if (obj.contains(key) && obj.value(key).isObject()) {
                QString nested = finder(obj.value(key).toObject());
                if (!nested.isEmpty()) {
                    return nested;
                }
            }
        }
        return {};
    };

    QString psbt = finder(doc.object());
    if (psbt.isEmpty() && errorOut && errorOut->isEmpty()) {
        *errorOut = QCoreApplication::translate("TradeBoardTab", "PSBT not found in payload");
    }
    return psbt;
}

} // namespace

// Lightweight helper to query if an address belongs to this wallet.
// Returns true/false and sets okOut to indicate RPC success; when RPC fails,
// okOut=false and the ownership is unknown.
static bool AddressOwnedByWallet(WalletModel* wm, const QString& address, bool* okOut)
{
    if (okOut) *okOut = false;
    if (!wm || address.isEmpty()) return false;
    try {
        UniValue params(UniValue::VARR);
        params.push_back(address.toStdString());
        UniValue resp = wm->node().executeRpc("getaddressinfo", params, wm->getWalletName().toStdString());
        if (resp.isObject()) {
            bool isMine = resp.exists("ismine") && resp["ismine"].isBool() && resp["ismine"].get_bool();
            bool isWatch = resp.exists("iswatchonly") && resp["iswatchonly"].isBool() && resp["iswatchonly"].get_bool();
            if (okOut) *okOut = true;
            return isMine || isWatch;
        }
    } catch (const std::exception&) {
    }
    return false;
}

// Local helper (GUI scope): verify that a PSBT contains at least one
// wallet-controlled SPENDABLE input (i.e. wallet has the private key).
// Produces a compact per-input detail string on failure for clear UX.
static bool PsbtHasSpendableInputs(WalletModel* model,
                                   const QString& psbtBase64,
                                   QString* detailsOut,
                                   QString* errorOut)
{
    if (!model) {
        if (errorOut) *errorOut = QObject::tr("Wallet unavailable");
        return false;
    }

    QString annotated = psbtBase64;
    // Annotate with wallet metadata (BIP32 paths) to better detect signability
    if (model) {
        auto ann = model->walletProcessPsbt(psbtBase64,
                                            /*sign=*/false,
                                            QStringLiteral("DEFAULT"),
                                            /*bip32derivs=*/true,
                                            /*finalize=*/false);
        if (ann.success && !ann.psbt.isEmpty()) {
            annotated = ann.psbt;
        }
    }

    PartiallySignedTransaction psbtx;
    std::string decodeErr;
    if (!DecodeBase64PSBT(psbtx, annotated.toStdString(), decodeErr) || !psbtx.tx) {
        if (errorOut) *errorOut = decodeErr.empty() ? QObject::tr("Unable to decode PSBT")
                                                    : QString::fromStdString(decodeErr);
        return false;
    }

    interfaces::Wallet& walletIface = model->wallet();
    int signableInputs = 0;
    int watchOnlyInputs = 0;
    int notMineInputs = 0;
    QString detail;

    // Prefer PSBT-provided UTXO data to avoid false negatives from wallet tx index lookups
    for (size_t i = 0; i < psbtx.tx->vin.size(); ++i) {
        CTxOut utxo;
        bool signable = false;
        // Check PSBT metadata for derivations indicating we have keys
        const bool has_deriv = (i < psbtx.inputs.size()) &&
                               (!psbtx.inputs[i].hd_keypaths.empty() || !psbtx.inputs[i].m_tap_bip32_paths.empty());

        if (psbtx.GetInputUTXO(utxo, i)) {
            unsigned int mine = static_cast<unsigned int>(walletIface.txoutIsMine(utxo));
            if (mine == 1) {
                signable = true;
                detail += QString("input%1:ismine=1,key=yes;").arg(i);
            } else if (mine == 2) {
                // Watch-only may still be signable for covenant or when derivations are present
                if (has_deriv) signable = true;
                watchOnlyInputs++;
                detail += QString("input%1:ismine=2,key=%2;").arg(i).arg(has_deriv ? "deriv" : "none");
            } else {
                if (has_deriv) signable = true;
                notMineInputs++;
                detail += QString("input%1:ismine=0,key=%2;").arg(i).arg(has_deriv ? "deriv" : "none");
            }
        } else {
            // Fallback to txin-based check if PSBT lacks UTXO data
            const CTxIn& txin = psbtx.tx->vin[i];
            unsigned int mine = static_cast<unsigned int>(walletIface.txinIsMine(txin));
            if (mine == 1) {
                signable = true;
                detail += QString("input%1:ismine=1,key=yes;").arg(i);
            } else if (mine == 2) {
                if (has_deriv) signable = true;
                watchOnlyInputs++;
                detail += QString("input%1:ismine=2,key=%2;").arg(i).arg(has_deriv ? "deriv" : "none");
            } else {
                if (has_deriv) signable = true;
                notMineInputs++;
                detail += QString("input%1:ismine=0,key=%2;").arg(i).arg(has_deriv ? "deriv" : "none");
            }
        }
        if (signable) ++signableInputs;
    }

    if (detailsOut) *detailsOut = detail;

    // Require at least one signable input (spendable or derivation-linked)
    if (signableInputs == 0) {
        if (errorOut) {
            *errorOut = QObject::tr("No wallet-controlled inputs eligible for adaptor preparation (%1)")
                            .arg(detail);
        }
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Cooperative (non-atomic) signing helpers
//
// These exist to support the asymmetric cooperative signing path used when the
// augmented PSBT has no Taproot inputs eligible for the atomic adaptor ceremony.
// Each helper is pure (no side effects on wallet state) and used by both sides
// of the ceremony to validate PSBT integrity before sending bytes to the peer
// or accepting bytes from them.
// ---------------------------------------------------------------------------

struct PsbtInputClassification {
    int taproot_inputs{0};
    int non_taproot_inputs{0};
    int unknown_inputs{0};   // missing witness_utxo, missing scriptPubKey.type, or other ambiguity
    bool decode_succeeded{false};
};

// Classify each input by its scriptPubKey using the C++ PSBT decoder.
// GetInputUTXO transparently falls back from witness_utxo to non_witness_utxo,
// so this correctly classifies legacy/segwit-v0 inputs that only carry the
// previous transaction (non_witness_utxo) rather than a synthetic witness_utxo.
// Anything we can't resolve to a scriptPubKey lands in unknown_inputs — the
// cooperative path then refuses with a user-visible "cannot classify funding"
// rather than silently routing into a guaranteed-to-fail atomic ceremony.
//
// NOTE: This is the SINGLE source of truth for the Taproot-vs-not decision.
// Do not add parallel ad-hoc detectors that only inspect witness_utxo —
// they will disagree on legacy inputs and produce exactly the
// modal-shows-but-cooperative-doesn't-run footgun we hit before.
static PsbtInputClassification ClassifyPsbtInputs(const QString& psbtBase64)
{
    PsbtInputClassification c;
    if (psbtBase64.isEmpty()) return c;
    PartiallySignedTransaction psbtx;
    std::string decodeErr;
    if (!DecodeBase64PSBT(psbtx, psbtBase64.toStdString(), decodeErr) || !psbtx.tx) {
        return c;  // decode_succeeded stays false → callers treat as "unknown"
    }
    c.decode_succeeded = true;
    for (size_t i = 0; i < psbtx.tx->vin.size(); ++i) {
        CTxOut utxo;
        if (!psbtx.GetInputUTXO(utxo, i)) {
            // Neither witness_utxo nor non_witness_utxo gave us a script.
            ++c.unknown_inputs;
            continue;
        }
        int version = 0;
        std::vector<unsigned char> program;
        if (utxo.scriptPubKey.IsWitnessProgram(version, program)) {
            // P2TR = witness v1 + 32-byte program. Everything else (P2WPKH v0,
            // P2WSH v0, future v2+) cannot host Schnorr adaptor signatures, so
            // counts as non-Taproot for ceremony classification.
            if (version == 1 && program.size() == 32) {
                ++c.taproot_inputs;
            } else {
                ++c.non_taproot_inputs;
            }
        } else {
            ++c.non_taproot_inputs;  // P2PKH, P2SH, bare multisig, etc.
        }
    }
    return c;
}

// Set of input indices that hold any signature material — partial signatures,
// Taproot keypath signature, Taproot scriptpath signatures, or finalised
// scriptwitness/scriptSig. Used to detect whether walletprocesspsbt actually
// added signatures (RPC success alone is not enough) and to verify the peer's
// signed PSBT shows progress on their inputs.
static QSet<int> PsbtSignedInputIndices(WalletModel* wallet, const QString& psbtBase64)
{
    QSet<int> result;
    if (!wallet || psbtBase64.isEmpty()) return result;
    QVariantMap decoded = wallet->decodePsbt(psbtBase64);
    if (!decoded.contains("inputs") || !decoded["inputs"].canConvert<QVariantList>()) {
        return result;
    }
    const QVariantList inputs = decoded["inputs"].toList();
    auto nonempty = [](const QVariant& v) -> bool {
        if (!v.isValid() || v.isNull()) return false;
        if (v.canConvert<QVariantList>()) return !v.toList().isEmpty();
        if (v.canConvert<QVariantMap>()) return !v.toMap().isEmpty();
        if (v.canConvert<QString>()) return !v.toString().isEmpty();
        return true;
    };
    for (int i = 0; i < inputs.size(); ++i) {
        if (!inputs[i].canConvert<QVariantMap>()) continue;
        const QVariantMap input = inputs[i].toMap();
        if (nonempty(input.value("partial_signatures")) ||
            nonempty(input.value("taproot_key_path_sig")) ||
            nonempty(input.value("taproot_script_path_sigs")) ||
            nonempty(input.value("tap_key_sig")) ||
            nonempty(input.value("tap_script_sigs")) ||
            nonempty(input.value("final_scriptwitness")) ||
            nonempty(input.value("final_scriptSig"))) {
            result.insert(i);
        }
    }
    return result;
}

// Returns true if any input declares an ANYONECANPAY sighash flag. Cooperative
// signing rejects these because they break the all-inputs-committed invariant
// that protects both parties from in-flight transaction modification after
// signatures are exchanged.
static bool PsbtHasAnyonecanpay(WalletModel* wallet, const QString& psbtBase64)
{
    if (!wallet || psbtBase64.isEmpty()) return false;
    QVariantMap decoded = wallet->decodePsbt(psbtBase64);
    if (!decoded.contains("inputs") || !decoded["inputs"].canConvert<QVariantList>()) {
        return false;
    }
    const QVariantList inputs = decoded["inputs"].toList();
    for (const QVariant& v : inputs) {
        const QString sighash = v.toMap().value("sighash").toString();
        if (sighash.contains(QStringLiteral("ANYONECANPAY"), Qt::CaseInsensitive)) {
            return true;
        }
    }
    return false;
}

// For cooperative signing: refuse any input whose stored sighash_type is
// neither DEFAULT nor ALL. Stricter than PsbtHasAnyonecanpay — that helper
// only catches the ANYONECANPAY flag, leaving NONE / SINGLE undetected.
// Cooperative signing normalises every input to SIGHASH_ALL before calling
// walletprocesspsbt(..., "ALL", ...), and that normalisation MUST NOT
// silently overwrite a peer-set commitment-weakening sighash (NONE drops
// the outputs commitment; SINGLE only commits to one matched output;
// any ANYONECANPAY variant drops the all-inputs commitment).
//
// Empty sighash means "not yet set"; signing will fill it in via the
// global ALL override, which is what we want. DEFAULT (Taproot-only,
// equivalent to ALL behaviour per BIP-341) and ALL are both safe.
//
// Returns a description of the first offending input, or empty if all
// inputs are safe to normalise. Fails CLOSED: any decode anomaly (null
// wallet, empty PSBT, missing/non-array inputs field, zero inputs)
// returns a non-empty description so the caller treats the PSBT as
// unsafe. Defaulting to "safe" on unrecognised decode shape would let
// a malformed PSBT slip past the cooperative-preflight guard.
static QString PsbtCooperativeUnsafeSighash(WalletModel* wallet, const QString& psbtBase64)
{
    if (!wallet) return QStringLiteral("wallet unavailable for sighash inspection");
    if (psbtBase64.isEmpty()) return QStringLiteral("empty PSBT");
    QVariantMap decoded = wallet->decodePsbt(psbtBase64);
    if (!decoded.contains("inputs") || !decoded["inputs"].canConvert<QVariantList>()) {
        return QStringLiteral("decodepsbt returned no inputs field");
    }
    const QVariantList inputs = decoded["inputs"].toList();
    if (inputs.isEmpty()) {
        return QStringLiteral("decodepsbt returned empty inputs array");
    }
    for (int i = 0; i < inputs.size(); ++i) {
        const QString sighash = inputs[i].toMap().value("sighash").toString();
        if (sighash.isEmpty()) continue;
        if (sighash == QStringLiteral("DEFAULT")) continue;
        if (sighash == QStringLiteral("ALL")) continue;
        return QStringLiteral("input %1: '%2'").arg(i).arg(sighash);
    }
    return {};
}

/**
 * Custom QTableWidgetItem that sorts numerically instead of lexicographically.
 * The numeric value is stored in Qt::UserRole and used for comparison.
 */
class NumericTableWidgetItem : public QTableWidgetItem
{
public:
    NumericTableWidgetItem(const QString& text, double numericValue)
        : QTableWidgetItem(text)
    {
        setData(Qt::UserRole, QVariant::fromValue(numericValue));
    }

    bool operator<(const QTableWidgetItem& other) const override
    {
        // Use the numeric value stored in UserRole for comparison
        return data(Qt::UserRole).toDouble() < other.data(Qt::UserRole).toDouble();
    }
};

TradeBoardTab::TradeBoardTab(const PlatformStyle* _platformStyle, QWidget* parent)
    : QWidget(parent),
      platformStyle(_platformStyle)
{
    setupUI();

    // Create update timers (but don't start yet - wait for wallet model)
    offersUpdateTimer = new QTimer(this);
    connect(offersUpdateTimer, &QTimer::timeout, this, &TradeBoardTab::updateOffersList);

    requestsUpdateTimer = new QTimer(this);
    connect(requestsUpdateTimer, &QTimer::timeout, this, &TradeBoardTab::updateTradeRequestsList);

    // Create cache timer update (updates the "Next refresh in X seconds" label every second)
    cacheTimerUpdateTimer = new QTimer(this);
    connect(cacheTimerUpdateTimer, &QTimer::timeout, this, &TradeBoardTab::updateCacheTimer);

    // Create session message polling timer
    sessionPollTimer = new QTimer(this);
    connect(sessionPollTimer, &QTimer::timeout, this, &TradeBoardTab::pollSessionMessages);

    // Connect to TorManager status updates
    connect(TorManager::instance(), &TorManager::statusChanged,
            this, &TradeBoardTab::updateTorStatus);

    // Initial Tor status update
    updateTorStatus();
}

TradeBoardTab::~TradeBoardTab()
{
    // Stop every owned timer first thing. They are parented to `this` so Qt
    // will delete them via parent-child cleanup, but Qt does NOT stop them
    // before deletion — a tick that fires between this destructor running
    // and the timer's own destructor running will call into a slot whose
    // captured `this` is in the middle of being destroyed (members are
    // already gone, vptr may have shifted). That's a documented source of
    // QObject::~QObject -> std::terminate -> SIGABRT shutdown crashes in
    // this codebase (see bitcoin.cpp shutdown try/catch and 2026-05-23
    // crash 7BB19689-...). Stopping the timers here closes that window.
    if (offersUpdateTimer) offersUpdateTimer->stop();
    if (requestsUpdateTimer) requestsUpdateTimer->stop();
    if (cacheTimerUpdateTimer) cacheTimerUpdateTimer->stop();
    if (sessionPollTimer) sessionPollTimer->stop();

    // Wait for in-flight QtConcurrent::run() bodies that captured `this` to
    // finish before we proceed with member destruction. See header for
    // rationale. Bounded at 5s; on timeout we log and let the shutdown
    // try/catch backstop catch any resulting throw.
    waitForInflightShutdown();
}

TradeBoardTab::InflightGuard::InflightGuard(TradeBoardTab* tab) noexcept
    : m_tab(tab)
{
    if (m_tab) m_tab->incrementInflight();
}

TradeBoardTab::InflightGuard::~InflightGuard()
{
    if (m_tab) m_tab->decrementInflight();
}

void TradeBoardTab::incrementInflight()
{
    std::lock_guard<std::mutex> lock(m_inflight_mutex);
    ++m_inflight_count;
}

void TradeBoardTab::decrementInflight()
{
    bool notify = false;
    {
        std::lock_guard<std::mutex> lock(m_inflight_mutex);
        --m_inflight_count;
        notify = (m_inflight_count == 0);
    }
    if (notify) m_inflight_cv.notify_all();
}

void TradeBoardTab::waitForInflightShutdown()
{
    using namespace std::chrono_literals;
    std::unique_lock<std::mutex> lock(m_inflight_mutex);
    const bool drained = m_inflight_cv.wait_for(lock, 5s, [this] {
        return m_inflight_count == 0;
    });
    if (!drained) {
        LogPrintf("TradeBoardTab: shutdown timeout — %d in-flight QtConcurrent body(ies) still running; proceeding anyway (BitcoinApplication ~dtor try/catch will backstop any throw)\n",
                  m_inflight_count);
    }
}

void TradeBoardTab::setWalletModel(WalletModel* model)
{
    this->walletModel = model;
    assetDecimalsCache.clear();
    repoMtmCache.clear();
    repoMtmPending.clear();

    LogPrintf("TradeBoardTab::setWalletModel called, model=%p\n", model);

    if (walletModel) {
        // Delay initialization to ensure wallet is fully ready
        // Use a single-shot timer to initialize after 2 seconds
        LogPrintf("TradeBoardTab: Scheduling bulletin board init in 2 seconds\n");
        QTimer::singleShot(2000, this, [this]() {
            LogPrintf("TradeBoardTab: Init timer fired, checking initialization\n");
            if (!walletModel) {
                LogPrintf("TradeBoardTab: ERROR - walletModel is null in timer callback\n");
                return;
            }

            // Auto-initialize bulletin board if not initialized
            if (!bbInitialized) {
                // Use default Nostr relays
                QStringList defaultRelays = {
                    "wss://relay.damus.io",
                    "wss://nos.lol",
                    "wss://relay.snort.social"
                };

                // Generate instance-specific key path using datadir to ensure uniqueness
                // Each bitcoin-qt instance with different datadir will have unique Nostr keys
                // Use /tmp which is writable in containers
                LogPrintf("TradeBoardTab: Initializing bulletin board with wallet-managed key path\n");

                auto result = walletModel->bulletinBoardInit(defaultRelays);
                if (result.success) {
                    bbPubkey = result.pubkey;
                    bbRelayCount = result.relays.size();
                    bbInitialized = true;

                    // Update UI to show connected status
                    updateBulletinBoardStatus();

                    // Initial data fetch
                    updateOffersList();
                    updateTradeRequestsList();
                } else {
                    // Show error to user
                    QMessageBox::critical(this, tr("Initialization Failed"),
                        tr("Failed to initialize bulletin board:\n\n%1\n\nError details:\n%2\n\nYou can try:\n1. Restart wallet\n2. Manual RPC: cosign.init_bb")
                        .arg(result.success ? "Unknown error" : "RPC call failed")
                        .arg(result.error));
                }
            } else {
                // Already initialized (maybe manually via RPC) - just refresh
                updateBulletinBoardStatus();
                updateOffersList();
                updateTradeRequestsList();
            }
        });

        // Start periodic updates
        if (offersUpdateTimer && !offersUpdateTimer->isActive()) {
            offersUpdateTimer->start(30000); // Update offers every 30 seconds
        }

        if (requestsUpdateTimer && !requestsUpdateTimer->isActive()) {
            requestsUpdateTimer->start(10000); // Check requests every 10 seconds for auto-join
        }

        if (cacheTimerUpdateTimer && !cacheTimerUpdateTimer->isActive()) {
            cacheTimerUpdateTimer->start(1000); // Update cache timer display every second
        }

        if (sessionPollTimer && !sessionPollTimer->isActive()) {
            sessionPollTimer->start(500); // Poll sessions every 500ms for messages
        }

        // Initialize cache timestamp
        lastCacheRefresh = QDateTime::currentDateTime();

        // Wire cross-chain trade view
        crossChainTradeView->setWalletModel(walletModel);
    }
}

void TradeBoardTab::setSessionManager(BridgeSessionManager* manager)
{
    this->sessionManager = manager;
}

void TradeBoardTab::setupUI()
{
    QVBoxLayout* mainLayout = new QVBoxLayout(this);

    // ========== Available Offers Section ==========
    QGroupBox* offersGroup = new QGroupBox(this);
    QVBoxLayout* offersLayout = new QVBoxLayout(offersGroup);

    // Control bar with contract type tabs and action buttons
    QHBoxLayout* offersControlLayout = new QHBoxLayout();

    // Contract type tab buttons with different shades of blue
    auto createTabButton = [this, offersControlLayout](const QString& text, const QString& contractType, QPushButton*& buttonPtr, const QString& baseColor) {
        buttonPtr = new QPushButton(text, this);
        buttonPtr->setToolTip(tr("Switch to %1 contracts").arg(text.toLower()));
        buttonPtr->setCheckable(true);
        buttonPtr->setMinimumWidth(95);
        buttonPtr->setMaximumHeight(24);
        buttonPtr->setProperty("contractType", contractType);
        buttonPtr->setProperty("baseColor", baseColor);
        buttonPtr->setSizePolicy(QSizePolicy::Minimum, QSizePolicy::Fixed);

        // Style for unselected state
        QString unselectedStyle = QString("QPushButton { padding: 5px 14px; background-color: %1; color: white; border: none; border-radius: 4px; line-height: 1.2; } "
                                         "QPushButton:hover { background-color: %2; }").arg(baseColor, baseColor);
        // Style for selected state (darker and bold) - reduce padding to account for bold + border
        QString selectedStyle = QString("QPushButton:checked { padding: 3px 12px; background-color: %1; color: white; border: 2px solid #0D47A1; font-weight: bold; border-radius: 4px; line-height: 1.2; }").arg(baseColor);

        buttonPtr->setStyleSheet(unselectedStyle + selectedStyle);

        connect(buttonPtr, &QPushButton::clicked, this, [this, contractType, buttonPtr]() {
            // Update current contract type
            currentContractType = contractType;

            // Uncheck all other buttons
            spotButton->setChecked(false);
            repoButton->setChecked(false);
            forwardButton->setChecked(false);
            optionButton->setChecked(false);
            crossChainButton->setChecked(false);
            if (difficultyButton) difficultyButton->setChecked(false);

            // Check this button
            buttonPtr->setChecked(true);

            // Update tables visibility and create button
            onContractTypeChanged(-1);
        });

        offersControlLayout->addWidget(buttonPtr);
    };

    createTabButton(tr("Spot"), "spot", spotButton, "#1976D2");
    createTabButton(tr("Repo"), "repo", repoButton, "#2196F3");
    createTabButton(tr("Forward"), "forward", forwardButton, "#42A5F5");
    createTabButton(tr("Option"), "options", optionButton, "#64B5F6");
    createTabButton(tr("Difficulty"), "difficulty", difficultyButton, "#7E57C2");
    createTabButton(tr("Cross-Chain"), "cross_chain", crossChainButton, "#FF9800");

    // Settlement profiles button
    profilesButton = new QPushButton(tr("Profiles"), this);
    profilesButton->setToolTip(tr("Manage external settlement profiles (BTC, ETH, TRON)"));
    profilesButton->setMaximumWidth(70);
    profilesButton->setMaximumHeight(24);
    profilesButton->setStyleSheet("QPushButton { padding: 5px 10px; border: 1px solid #FF9800; border-radius: 4px; background-color: white; color: #E65100; line-height: 1.2; } QPushButton:hover { background-color: #FFF3E0; }");
    connect(profilesButton, &QPushButton::clicked, this, [this]() {
        CrossChainProfileDialog dialog(walletModel, this);
        dialog.exec();
    });
    offersControlLayout->addWidget(profilesButton);

    // ETH Manager start button
    startManagerButton = new QPushButton(tr("ETH"), this);
    startManagerButton->setToolTip(tr("Configure ETH provider and start cross-chain manager"));
    startManagerButton->setMaximumWidth(50);
    startManagerButton->setMaximumHeight(24);
    startManagerButton->setStyleSheet(
        "QPushButton { padding: 5px 8px; border: 1px solid #1976D2; border-radius: 4px; "
        "background-color: white; color: #1565C0; line-height: 1.2; } "
        "QPushButton:hover { background-color: #E3F2FD; }");
    connect(startManagerButton, &QPushButton::clicked, this, [this]() {
        if (!walletModel) return;

        // Prompt for ETH RPC URL
        bool ok;
        QString savedUrl = QString::fromStdString(
            gArgs.GetArg("-xchain_eth_rpc_url", ""));
        QString rpcUrl = QInputDialog::getText(this, tr("ETH Provider"),
            tr("Enter Ethereum JSON-RPC URL\n(e.g. https://sepolia.infura.io/v3/YOUR_KEY):"),
            QLineEdit::Normal, savedUrl, &ok);
        if (!ok || rpcUrl.isEmpty()) return;

        // Optional: secondary provider
        QString rpcUrl2 = QInputDialog::getText(this, tr("Secondary Provider (Optional)"),
            tr("Enter secondary ETH RPC URL for dual-provider verification\n(leave empty to skip):"),
            QLineEdit::Normal, QString(), &ok);

        // Optional: derivation seed
        QString seed = QString::fromStdString(
            gArgs.GetArg("-xchain_eth_derivation_seed", ""));

        auto result = walletModel->crossChainStartManager(rpcUrl, rpcUrl2, QString(), seed);
        if (result.success) {
            startManagerButton->setText(tr("ETH ●"));
            startManagerButton->setStyleSheet(
                "QPushButton { padding: 5px 8px; border: 1px solid #4CAF50; border-radius: 4px; "
                "background-color: #E8F5E9; color: #2E7D32; font-weight: bold; } ");
            showAutoClosingInfo(tr("Manager Started"),
                tr("Cross-chain manager started.\n\nMode: %1\nDual provider: %2\nActive swaps: %3")
                .arg(result.mode,
                     result.dual_provider ? tr("Yes") : tr("No"),
                     QString::number(result.active_swaps)));
        } else {
            QMessageBox::critical(this, tr("Manager Failed"),
                tr("Failed to start cross-chain manager:\n\n%1").arg(result.error));
        }
    });
    offersControlLayout->addWidget(startManagerButton);

    // Refresh icon button
    offersRefreshButton = new QPushButton(this);
    offersRefreshButton->setText("↻");
    offersRefreshButton->setToolTip(tr("Refresh offers list"));
    offersRefreshButton->setFixedSize(24, 24);
    offersRefreshButton->setStyleSheet("QPushButton { font-size: 12pt; font-weight: bold; border: none; background: transparent; } QPushButton:hover { background-color: rgba(0,0,0,0.1); border-radius: 4px; }");
    offersRefreshButton->setFlat(true);
    connect(offersRefreshButton, &QPushButton::clicked, this, &TradeBoardTab::onForceRefresh);
    offersControlLayout->addWidget(offersRefreshButton);

    // Add filter button
    QPushButton* filterButton = new QPushButton(tr("Filter"), this);
    filterButton->setToolTip(tr("Filter displayed offers by asset, amount, and other criteria"));
    filterButton->setMaximumWidth(70);
    filterButton->setMaximumHeight(24);
    filterButton->setStyleSheet("QPushButton { padding: 5px 10px; border: 1px solid #999; border-radius: 4px; background-color: white; line-height: 1.2; } QPushButton:hover { background-color: #f0f0f0; }");
    connect(filterButton, &QPushButton::clicked, this, [this]() {
        showFilterDialog();
    });
    offersControlLayout->addWidget(filterButton);

    offersControlLayout->addStretch();

    createContractButton = new QPushButton(tr("+ add"), this);
    createContractButton->setToolTip(tr("Add a repo offer"));
    createContractButton->setStyleSheet("QPushButton { padding: 6px 12px; font-weight: bold; background-color: #4CAF50; color: white; border-radius: 4px; } QPushButton:hover { background-color: #45a049; }");
    connect(createContractButton, &QPushButton::clicked, this, &TradeBoardTab::onCreateContract);
    offersControlLayout->addWidget(createContractButton);

    offersLayout->addLayout(offersControlLayout);

    // Create Repo Table
    repoTable = new QTableWidget(this);
    repoTable->setColumnCount(14);
    repoTable->setHorizontalHeaderLabels({
        tr("Maker"),
        tr("Role"),
        tr("MTM\n(Marks)"),
        tr("MTM\n(Market)"),
        tr("Collateral"),
        tr("Principal"),
        tr("Interest"),
        tr("Price"),
        tr("APR"),
        tr("LTV"),
        tr("Tenor"),
        tr("Funds\nVerified"),
        tr("Age"),
        tr("Actions")
    });
    repoTable->setSortingEnabled(true);

    // Enable multi-line header labels (newlines in labels will automatically wrap)
    repoTable->horizontalHeader()->setDefaultAlignment(Qt::AlignCenter);
    repoTable->horizontalHeader()->setMinimumHeight(40); // Allow space for two lines

    repoTable->horizontalHeader()->setStretchLastSection(false);
    repoTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    // Column sizing: use ResizeToContents for data columns so they adapt to
    // the platform font metrics (Windows Segoe UI renders wider than macOS).
    // Maker stretches to fill, Actions is fixed, everything else adapts.
    repoTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch); // Maker - stretch
    repoTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);  // Role
    repoTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);  // MTM (Marks)
    repoTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);  // MTM (Market)
    repoTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);  // Collateral
    repoTable->horizontalHeader()->setSectionResizeMode(5, QHeaderView::ResizeToContents);  // Principal
    repoTable->horizontalHeader()->setSectionResizeMode(6, QHeaderView::ResizeToContents);  // Interest
    repoTable->horizontalHeader()->setSectionResizeMode(7, QHeaderView::ResizeToContents);  // Price
    repoTable->horizontalHeader()->setSectionResizeMode(8, QHeaderView::ResizeToContents);  // APR
    repoTable->horizontalHeader()->setSectionResizeMode(9, QHeaderView::ResizeToContents);  // LTV
    repoTable->horizontalHeader()->setSectionResizeMode(10, QHeaderView::ResizeToContents); // Tenor
    repoTable->horizontalHeader()->setSectionResizeMode(11, QHeaderView::ResizeToContents); // Funds Verified
    repoTable->horizontalHeader()->setSectionResizeMode(12, QHeaderView::ResizeToContents); // Age
    repoTable->horizontalHeader()->setSectionResizeMode(13, QHeaderView::Fixed); // Actions - fixed
    repoTable->setColumnWidth(13, 100);
    // Enable horizontal scrollbar when columns exceed available width
    repoTable->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    repoTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    repoTable->setSelectionMode(QAbstractItemView::SingleSelection);
    repoTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    repoTable->setAlternatingRowColors(true);
    repoTable->verticalHeader()->setVisible(false);
    // Reduce font size by 20-25%
    QFont tableFont = repoTable->font();
    tableFont.setPointSize(tableFont.pointSize() * 0.78);
    repoTable->setFont(tableFont);
    repoTable->verticalHeader()->setDefaultSectionSize(22); // Smaller row height
    QPointer<TradeBoardTab> repoTableSelfPtr(this);
    connect(repoTable, &QTableWidget::cellDoubleClicked, this, [repoTableSelfPtr](int row, int column) {
        if (!repoTableSelfPtr) return;
        Q_UNUSED(column);
        if (row < 0 || row >= repoTableSelfPtr->repoTable->rowCount()) return;

        // Retrieve offer_id stored in the row data (column 0)
        QTableWidgetItem* item = repoTableSelfPtr->repoTable->item(row, 0);
        if (!item) return;

        QString offer_id = item->data(Qt::UserRole).toString();
        if (offer_id.isEmpty()) return;

        if (!repoTableSelfPtr->activeOffers.contains(offer_id)) return;

        OfferInfo offerInfo = repoTableSelfPtr->activeOffers[offer_id];
        QVariantMap offerForDialog;
        offerForDialog["offer_id"] = offerInfo.offer_id;
        offerForDialog["contract_payload"] = offerInfo.contract_payload;
        offerForDialog["contract_type"] = offerInfo.contract_type;
        offerForDialog["maker_role"] = offerInfo.maker_role;
        offerForDialog["proof_of_funds"] = offerInfo.proof_of_funds;
        offerForDialog["proof_verified"] = offerInfo.proof_verified;
        offerForDialog["proof_verified_units"] = static_cast<qlonglong>(offerInfo.proof_verified_units);
        offerForDialog["proof_verified_asset"] = offerInfo.proof_verified_asset;
        offerForDialog["proof_verification_error"] = offerInfo.proof_verification_error;
        ReviewContractOfferDialog dialog(offerForDialog, repoTableSelfPtr->walletModel, repoTableSelfPtr);
        dialog.exec();
    });

    // Create Forward Table with individual columns for sorting/filtering
    forwardTable = new QTableWidget(this);
    forwardTable->setColumnCount(12);
    forwardTable->setHorizontalHeaderLabels({
        tr("Maker"),
        tr("Role"),
        tr("MTM\n(Marks)"),
        tr("MTM\n(Market)"),
        tr("Long\nAsset"),
        tr("Short\nAsset"),
        tr("Long\nIM %"),
        tr("Short\nIM %"),
        tr("Tenor"),
        tr("Age"),
        tr("Proof"),
        tr("Actions")
    });
    forwardTable->setSortingEnabled(true);

    // Enable multi-line header labels
    forwardTable->horizontalHeader()->setDefaultAlignment(Qt::AlignCenter);
    forwardTable->horizontalHeader()->setMinimumHeight(40);

    forwardTable->horizontalHeader()->setStretchLastSection(true);
    forwardTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    forwardTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    forwardTable->setSelectionMode(QAbstractItemView::SingleSelection);
    forwardTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    forwardTable->setAlternatingRowColors(true);
    forwardTable->verticalHeader()->setVisible(false);
    forwardTable->setVisible(false);
    // Reduce font size by 20-25%
    QFont forwardFont = forwardTable->font();
    forwardFont.setPointSize(forwardFont.pointSize() * 0.78);
    forwardTable->setFont(forwardFont);
    forwardTable->verticalHeader()->setDefaultSectionSize(22); // Smaller row height
    QPointer<TradeBoardTab> forwardTableSelfPtr(this);
    connect(forwardTable, &QTableWidget::cellDoubleClicked, this, [forwardTableSelfPtr](int row, int column) {
        if (!forwardTableSelfPtr) return;
        Q_UNUSED(column);
        if (row < 0 || row >= forwardTableSelfPtr->forwardTable->rowCount()) return;

        // Retrieve offer_id stored in the row data (column 0)
        QTableWidgetItem* item = forwardTableSelfPtr->forwardTable->item(row, 0);
        if (!item) return;

        QString offer_id = item->data(Qt::UserRole).toString();
        if (offer_id.isEmpty()) return;

        if (!forwardTableSelfPtr->activeOffers.contains(offer_id)) return;

        OfferInfo offerInfo = forwardTableSelfPtr->activeOffers[offer_id];
        QVariantMap offerForDialog;
        offerForDialog["offer_id"] = offerInfo.offer_id;
        offerForDialog["contract_payload"] = offerInfo.contract_payload;
        offerForDialog["contract_type"] = offerInfo.contract_type;
        offerForDialog["maker_role"] = offerInfo.maker_role;
        offerForDialog["proof_of_funds"] = offerInfo.proof_of_funds;
        offerForDialog["proof_verified"] = offerInfo.proof_verified;
        offerForDialog["proof_verified_units"] = static_cast<qlonglong>(offerInfo.proof_verified_units);
        offerForDialog["proof_verified_asset"] = offerInfo.proof_verified_asset;
        offerForDialog["proof_verification_error"] = offerInfo.proof_verification_error;
        ReviewContractOfferDialog dialog(offerForDialog, forwardTableSelfPtr->walletModel, forwardTableSelfPtr);
        dialog.exec();
    });

    // Create Options Table with individual columns
    optionsTable = new QTableWidget(this);
    optionsTable->setColumnCount(12);
    optionsTable->setHorizontalHeaderLabels({
        tr("Maker"),
        tr("Role"),
        tr("MTM\n(Marks)"),
        tr("MTM\n(Market)"),
        tr("Long\nAsset"),
        tr("Short\nAsset"),
        tr("Premium"),
        tr("Prem\nPayer"),
        tr("Tenor"),
        tr("Age"),
        tr("Proof"),
        tr("Actions")
    });
    optionsTable->setSortingEnabled(true);

    // Enable multi-line header labels
    optionsTable->horizontalHeader()->setDefaultAlignment(Qt::AlignCenter);
    optionsTable->horizontalHeader()->setMinimumHeight(40);

    optionsTable->horizontalHeader()->setStretchLastSection(true);
    optionsTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    optionsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    optionsTable->setSelectionMode(QAbstractItemView::SingleSelection);
    optionsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    optionsTable->setAlternatingRowColors(true);
    optionsTable->verticalHeader()->setVisible(false);
    optionsTable->setVisible(false);
    // Reduce font size by 20-25%
    QFont optionsFont = optionsTable->font();
    optionsFont.setPointSize(optionsFont.pointSize() * 0.78);
    optionsTable->setFont(optionsFont);
    optionsTable->verticalHeader()->setDefaultSectionSize(22); // Smaller row height
    QPointer<TradeBoardTab> optionsTableSelfPtr(this);
    connect(optionsTable, &QTableWidget::cellDoubleClicked, this, [optionsTableSelfPtr](int row, int column) {
        if (!optionsTableSelfPtr) return;
        Q_UNUSED(column);
        if (row < 0 || row >= optionsTableSelfPtr->optionsTable->rowCount()) return;

        // Retrieve offer_id stored in the row data (column 0)
        QTableWidgetItem* item = optionsTableSelfPtr->optionsTable->item(row, 0);
        if (!item) return;

        QString offer_id = item->data(Qt::UserRole).toString();
        if (offer_id.isEmpty()) return;

        if (!optionsTableSelfPtr->activeOffers.contains(offer_id)) return;

        OfferInfo offerInfo = optionsTableSelfPtr->activeOffers[offer_id];
        QVariantMap offerForDialog;
        offerForDialog["offer_id"] = offerInfo.offer_id;
        offerForDialog["contract_payload"] = offerInfo.contract_payload;
        offerForDialog["contract_type"] = "option";
        offerForDialog["maker_role"] = offerInfo.maker_role;
        offerForDialog["proof_of_funds"] = offerInfo.proof_of_funds;
        offerForDialog["proof_verified"] = offerInfo.proof_verified;
        offerForDialog["proof_verified_units"] = static_cast<qlonglong>(offerInfo.proof_verified_units);
        offerForDialog["proof_verified_asset"] = offerInfo.proof_verified_asset;
        offerForDialog["proof_verification_error"] = offerInfo.proof_verification_error;
        ReviewContractOfferDialog dialog(offerForDialog, optionsTableSelfPtr->walletModel, optionsTableSelfPtr);
        dialog.exec();
    });

    // Create Spot Table
    spotTable = new QTableWidget(this);
    spotTable->setColumnCount(10);
    spotTable->setHorizontalHeaderLabels({
        tr("Maker"),
        tr("MTM\n(Marks)"),
        tr("MTM\n(Market)"),
        tr("Asset\nSend"),
        tr("Amount\nSend"),
        tr("Asset\nRecv"),
        tr("Amount\nRecv"),
        tr("Price"),
        tr("Funds\nVerified"),
        tr("Actions")
    });
    spotTable->setSortingEnabled(true);

    // Enable multi-line header labels
    spotTable->horizontalHeader()->setDefaultAlignment(Qt::AlignCenter);
    spotTable->horizontalHeader()->setMinimumHeight(40);

    spotTable->horizontalHeader()->setStretchLastSection(true);
    spotTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    spotTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    spotTable->setSelectionMode(QAbstractItemView::SingleSelection);
    spotTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    spotTable->setAlternatingRowColors(true);
    spotTable->verticalHeader()->setVisible(false);
    spotTable->setVisible(false);
    // Reduce font size by 20-25%
    QFont spotFont = spotTable->font();
    spotFont.setPointSize(spotFont.pointSize() * 0.78);
    spotTable->setFont(spotFont);
    spotTable->verticalHeader()->setDefaultSectionSize(22); // Smaller row height

    QPointer<TradeBoardTab> spotTableSelfPtr(this);
    connect(spotTable, &QTableWidget::cellDoubleClicked, this, [spotTableSelfPtr](int row, int column) {
        if (!spotTableSelfPtr) return;
        Q_UNUSED(column);
        if (row < 0 || row >= spotTableSelfPtr->spotTable->rowCount()) return;

        // Retrieve offer_id stored in the row data (column 0)
        QTableWidgetItem* item = spotTableSelfPtr->spotTable->item(row, 0);
        if (!item) return;

        QString offer_id = item->data(Qt::UserRole).toString();
        if (offer_id.isEmpty()) return;

        if (!spotTableSelfPtr->activeOffers.contains(offer_id)) return;

        OfferInfo offerInfo = spotTableSelfPtr->activeOffers[offer_id];
        QVariantMap offerForDialog;
        offerForDialog["offer_id"] = offerInfo.offer_id;
        offerForDialog["contract_payload"] = offerInfo.contract_payload;
        offerForDialog["contract_type"] = "spot";
        offerForDialog["maker_role"] = offerInfo.maker_role;
        offerForDialog["proof_of_funds"] = offerInfo.proof_of_funds;
        offerForDialog["proof_verified"] = offerInfo.proof_verified;
        offerForDialog["proof_verified_units"] = static_cast<qlonglong>(offerInfo.proof_verified_units);
        offerForDialog["proof_verified_asset"] = offerInfo.proof_verified_asset;
        offerForDialog["proof_verification_error"] = offerInfo.proof_verification_error;

        // TODO: When spot.build/join flow is implemented, check if require_commitment_proof
        // is set in the offer terms. If true, show CommitmentProofDialog after PSBT joining
        // and before final signing. The dialog will guide users through:
        //   1. Join PSBTs from both parties
        //   2. Add commitment proof (proves decryption capability)
        //   3. Verify counterparty's commitment
        //   4. Sign the transaction

        ReviewContractOfferDialog dialog(offerForDialog, spotTableSelfPtr->walletModel, spotTableSelfPtr);
        dialog.exec();
    });

    // Create Cross-Chain Table
    crossChainTable = new QTableWidget(this);
    crossChainTable->setColumnCount(8);
    crossChainTable->setHorizontalHeaderLabels({
        tr("Maker"),
        tr("Chain"),
        tr("Adapter"),
        tr("TSC\nAmount"),
        tr("External\nAmount"),
        tr("External\nAsset"),
        tr("Funding\nOrder"),
        tr("Actions")
    });
    crossChainTable->setSortingEnabled(true);
    crossChainTable->horizontalHeader()->setDefaultAlignment(Qt::AlignCenter);
    crossChainTable->horizontalHeader()->setMinimumHeight(40);
    crossChainTable->horizontalHeader()->setStretchLastSection(true);
    crossChainTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    crossChainTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    crossChainTable->setSelectionMode(QAbstractItemView::SingleSelection);
    crossChainTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    crossChainTable->setAlternatingRowColors(true);
    crossChainTable->verticalHeader()->setVisible(false);
    crossChainTable->setVisible(false);
    QFont crossChainFont = crossChainTable->font();
    crossChainFont.setPointSize(crossChainFont.pointSize() * 0.78);
    crossChainTable->setFont(crossChainFont);
    crossChainTable->verticalHeader()->setDefaultSectionSize(22);

    // Create Difficulty table (CFD + option derivatives on mining difficulty)
    difficultyTable = new QTableWidget(this);
    difficultyTable->setColumnCount(12);
    difficultyTable->setHorizontalHeaderLabels({
        tr("Maker"), tr("Role"), tr("Product"), tr("Strike"), tr("Fixing→Settle"),
        tr("IM"), tr("λ"), tr("Premium"), tr("MTM"), tr("Funds\nVerified"), tr("Age"), tr("Actions")});
    difficultyTable->setSortingEnabled(true);
    difficultyTable->horizontalHeader()->setDefaultAlignment(Qt::AlignCenter);
    difficultyTable->horizontalHeader()->setMinimumHeight(40);
    difficultyTable->horizontalHeader()->setStretchLastSection(false);
    difficultyTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    difficultyTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch); // Maker
    difficultyTable->horizontalHeader()->setSectionResizeMode(11, QHeaderView::Fixed);  // Actions
    difficultyTable->setColumnWidth(11, 110);
    difficultyTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    difficultyTable->setSelectionMode(QAbstractItemView::SingleSelection);
    difficultyTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    difficultyTable->setAlternatingRowColors(true);
    difficultyTable->verticalHeader()->setVisible(false);
    difficultyTable->setVisible(false);
    QFont difficultyFont = difficultyTable->font();
    difficultyFont.setPointSize(difficultyFont.pointSize() * 0.78);
    difficultyTable->setFont(difficultyFont);
    difficultyTable->verticalHeader()->setDefaultSectionSize(22);
    QPointer<TradeBoardTab> difficultyTableSelfPtr(this);
    connect(difficultyTable, &QTableWidget::cellDoubleClicked, this, [difficultyTableSelfPtr](int row, int column) {
        if (!difficultyTableSelfPtr) return;
        Q_UNUSED(column);
        if (row < 0 || row >= difficultyTableSelfPtr->difficultyTable->rowCount()) return;
        QTableWidgetItem* item = difficultyTableSelfPtr->difficultyTable->item(row, 0);
        if (!item) return;
        QString offer_id = item->data(Qt::UserRole).toString();
        if (offer_id.isEmpty() || !difficultyTableSelfPtr->activeOffers.contains(offer_id)) return;
        OfferInfo offerInfo = difficultyTableSelfPtr->activeOffers[offer_id];
        QVariantMap offerForDialog;
        offerForDialog["offer_id"] = offerInfo.offer_id;
        offerForDialog["contract_payload"] = offerInfo.contract_payload;
        offerForDialog["contract_type"] = offerInfo.contract_type;
        offerForDialog["maker_role"] = offerInfo.maker_role;
        offerForDialog["proof_of_funds"] = offerInfo.proof_of_funds;
        offerForDialog["proof_verified"] = offerInfo.proof_verified;
        ReviewContractOfferDialog dialog(offerForDialog, difficultyTableSelfPtr->walletModel, difficultyTableSelfPtr);
        dialog.exec();
    });

    offersLayout->addWidget(repoTable);
    offersLayout->addWidget(forwardTable);
    offersLayout->addWidget(optionsTable);
    offersLayout->addWidget(spotTable);
    offersLayout->addWidget(crossChainTable);
    offersLayout->addWidget(difficultyTable);

    offersGroup->setLayout(offersLayout);

    // Default to repo contracts. Apply the initial view state after all
    // widgets referenced by onContractTypeChanged() have been constructed.
    currentContractType = "repo";
    repoButton->setChecked(true);

    // ========== Trade Requests Section ==========
    QGroupBox* requestsGroup = new QGroupBox(tr("Trade Requests"), this);
    QVBoxLayout* requestsLayout = new QVBoxLayout(requestsGroup);

    // Requests Table
    requestsTable = new QTableWidget(this);
    requestsTable->setColumnCount(7);
    requestsTable->setHorizontalHeaderLabels({
        tr("Offer"),
        tr("Role"),
        tr("Counterparty"),
        tr("Status"),
        tr("Funds Verified"),
        tr("Updated"),
        tr("Actions")
    });

    // Enable sorting
    requestsTable->setSortingEnabled(true);

    // Make table stretch to fill available space
    requestsTable->horizontalHeader()->setStretchLastSection(true);
    requestsTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    requestsTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    requestsTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    requestsTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    requestsTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    requestsTable->horizontalHeader()->setSectionResizeMode(5, QHeaderView::Fixed);
    requestsTable->horizontalHeader()->resizeSection(5, 150);  // Fixed width for Actions button

    requestsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    requestsTable->setSelectionMode(QAbstractItemView::SingleSelection);
    requestsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    requestsTable->setAlternatingRowColors(true);
    requestsTable->verticalHeader()->setVisible(false);
    // Reduce font size by 20-25%
    QFont requestsFont = requestsTable->font();
    requestsFont.setPointSize(requestsFont.pointSize() * 0.78);
    requestsTable->setFont(requestsFont);
    requestsTable->verticalHeader()->setDefaultSectionSize(22); // Smaller row height

    requestsLayout->addWidget(requestsTable);
    requestsGroup->setLayout(requestsLayout);

    // ========== Cross-Chain Active Trades View ==========
    crossChainTradeView = new CrossChainTradeView(this);
    crossChainTradeView->setVisible(false);

    onContractTypeChanged(-1);

    // ========== Use QSplitter for 2/3 vs 1/3 layout ==========
    QSplitter* splitter = new QSplitter(Qt::Vertical, this);
    splitter->addWidget(offersGroup);
    splitter->addWidget(requestsGroup);
    splitter->addWidget(crossChainTradeView);
    splitter->setStretchFactor(0, 2);  // Offers get 2/3 of space
    splitter->setStretchFactor(1, 1);  // Requests get 1/3 of space
    splitter->setStretchFactor(2, 1);  // Cross-chain trades get 1/3
    splitter->setChildrenCollapsible(false);  // Prevent collapsing sections

    mainLayout->addWidget(splitter);

    // ========== Bottom Status Bar with Control Buttons ==========
    QHBoxLayout* bottomLayout = new QHBoxLayout();
    bottomLayout->setContentsMargins(6, 4, 6, 4);
    bottomLayout->setSpacing(8);

    // Connection status labels
    bbStatusLabel = new QLabel(tr("● Not Connected"), this);
    bbStatusLabel->setStyleSheet("QLabel { color: #d32f2f; font-weight: bold; }");
    bottomLayout->addWidget(bbStatusLabel);

    // Tor status label (for cosign sessions)
    torStatusLabel = new QLabel(tr("🔐 Tor: Unknown"), this);
    torStatusLabel->setStyleSheet("QLabel { color: #666; font-weight: bold; }");
    torStatusLabel->setToolTip(tr("Tor status for private cosign bridge sessions"));
    bottomLayout->addWidget(torStatusLabel);

    // Refresh button after connection status
    forceRefreshButton = new QPushButton(this);
    forceRefreshButton->setText("↻");  // Circular arrow for refresh
    forceRefreshButton->setToolTip(tr("Force immediate refresh from Nostr relays (bypasses 5-minute cache)"));
    forceRefreshButton->setFixedSize(20, 20);
    forceRefreshButton->setStyleSheet("QPushButton { font-size: 11pt; font-weight: bold; border: none; background: transparent; } QPushButton:hover { background-color: rgba(0,0,0,0.1); }");
    forceRefreshButton->setFlat(true);
    connect(forceRefreshButton, &QPushButton::clicked, this, &TradeBoardTab::onForceRefresh);
    bottomLayout->addWidget(forceRefreshButton);

    bbPubkeyLabel = new QLabel(tr("Pubkey: Unknown"), this);
    bbPubkeyLabel->setStyleSheet("QLabel { color: #666; font-size: 9pt; }");
    bottomLayout->addWidget(bbPubkeyLabel);

    bbRelaysLabel = new QLabel(tr("Relays: 0"), this);
    bbRelaysLabel->setStyleSheet("QLabel { color: #666; font-size: 9pt; }");
    bottomLayout->addWidget(bbRelaysLabel);

    bbCacheTimerLabel = new QLabel(tr("Cache: ---"), this);
    bbCacheTimerLabel->setStyleSheet("QLabel { color: #666; font-size: 9pt; }");
    bottomLayout->addWidget(bbCacheTimerLabel);

    bottomLayout->addStretch();

    // Icon-only buttons with fixed symbols
    forceRestartButton = new QPushButton(this);
    forceRestartButton->setText("⚠");  // Warning triangle for restart
    forceRestartButton->setToolTip(tr("Force restart bulletin board (re-initialize from scratch)"));
    forceRestartButton->setFixedSize(20, 20);
    forceRestartButton->setStyleSheet("QPushButton { font-size: 12px; font-weight: bold; border: none; background: transparent; } QPushButton:hover { background-color: rgba(0,0,0,0.1); }");
    forceRestartButton->setFlat(true);
    connect(forceRestartButton, &QPushButton::clicked, this, &TradeBoardTab::onForceRestart);
    bottomLayout->addWidget(forceRestartButton);

    // Clear stuck button
    QPushButton* clearStuckButton = new QPushButton(this);
    clearStuckButton->setText("X");  // X for clear/stop - more compatible than emoji
    clearStuckButton->setToolTip(tr("Clear stuck trade requests and unlock frozen coins"));
    clearStuckButton->setFixedSize(20, 20);
    clearStuckButton->setStyleSheet("QPushButton { font-size: 14px; font-weight: bold; border: none; background: transparent; color: #ff9800; } QPushButton:hover { background-color: rgba(255,152,0,0.1); }");
    clearStuckButton->setFlat(true);
    connect(clearStuckButton, &QPushButton::clicked, this, &TradeBoardTab::clearStuckTradeRequests);
    bottomLayout->addWidget(clearStuckButton);

    mainLayout->addLayout(bottomLayout);

    setLayout(mainLayout);
}

void TradeBoardTab::onForceRefresh()
{
    if (!walletModel) return;

    LogPrintf("TradeBoardTab::onForceRefresh() Force refreshing from Nostr relays\n");

    // Force refresh clears the backend cache and re-fetches fresh from the relays.
    // Route it through the async offers path (force_refresh=true) so the relay
    // round-trip runs off-thread and never beachballs the GUI. The previous code
    // did a synchronous force fetch here AND then called updateOffersList() — a
    // redundant double round-trip; the single async fetch now renders directly.
    // Coalescing in dispatchOffersFetch() de-dups rapid re-clicks, so the old
    // button-disable/enable gating is no longer needed (and could not bracket an
    // async fetch anyway). Relay failures on this click path are surfaced to the
    // user by the fetch continuation (force_refresh branch).
    dispatchOffersFetch(/*force_refresh=*/true);
    updateTradeRequestsList();
}

void TradeBoardTab::onForceRestart()
{
    if (!walletModel) {
        QMessageBox::warning(this, tr("Error"), tr("Wallet model not available"));
        return;
    }

    LogPrintf("TradeBoardTab::onForceRestart() Force restarting bulletin board\n");

    // Disable button during restart
    forceRestartButton->setEnabled(false);

    // Use default Nostr relays for restart
    QStringList defaultRelays = {
        "wss://relay.damus.io",
        "wss://nos.lol",
        "wss://relay.snort.social"
    };

    // Call init RPC to restart bulletin board
    auto result = walletModel->bulletinBoardInit(defaultRelays);

    if (result.success) {
        LogPrintf("TradeBoardTab::onForceRestart() Bulletin board restarted successfully\n");

        // Reset state
        bbInitialized = true;
        bbPubkey = result.pubkey;
        bbRelayCount = result.relays.size();
        lastCacheRefresh = QDateTime::currentDateTime();

        // Clear cached data
        activeOffers.clear();
        activeRequests.clear();

        showAutoClosingInfo(tr("Success"),
            tr("Bulletin board restarted successfully!\nPubkey: %1\nRelays: %2")
                .arg(formatPubkey(result.pubkey))
                .arg(result.relays.size()));

        // Update status and refresh data
        updateBulletinBoardStatus();
        updateOffersList();
        updateTradeRequestsList();
    } else {
        LogPrintf("TradeBoardTab::onForceRestart() ERROR: Failed to restart bulletin board: %s\n",
                  result.error.toStdString().c_str());

        bbInitialized = false;

        QMessageBox::warning(this, tr("Error"),
            tr("Failed to restart bulletin board: %1").arg(result.error));
    }

    // Re-enable button
    forceRestartButton->setEnabled(true);
}

void TradeBoardTab::updateCacheTimer()
{
    if (!bbInitialized) {
        bbCacheTimerLabel->setText(tr("Cache: Not initialized"));
        return;
    }

    qint64 secondsSinceRefresh = lastCacheRefresh.secsTo(QDateTime::currentDateTime());
    qint64 secondsUntilNextRefresh = 300 - secondsSinceRefresh; // 300 = 5 minutes

    if (secondsUntilNextRefresh <= 0) {
        bbCacheTimerLabel->setText(tr("Cache: Refreshing..."));
        bbCacheTimerLabel->setStyleSheet("QLabel { color: #f57c00; font-size: 10pt; }");
    } else {
        int minutes = secondsUntilNextRefresh / 60;
        int seconds = secondsUntilNextRefresh % 60;
        bbCacheTimerLabel->setText(tr("Cache: Next refresh in %1:%2")
            .arg(minutes)
            .arg(seconds, 2, 10, QChar('0')));
        bbCacheTimerLabel->setStyleSheet("QLabel { color: #666; font-size: 10pt; }");
    }
}

void TradeBoardTab::onRequestTrade()
{
    LogPrintf("TradeBoardTab::onRequestTrade() called\n");

    QPushButton* button = qobject_cast<QPushButton*>(sender());
    if (!button) {
        LogPrintf("TradeBoardTab::onRequestTrade() ERROR: sender() returned null\n");
        QMessageBox::warning(this, tr("Debug"), tr("Button sender is null!"));
        return;
    }

    QString offer_id = button->property("offer_id").toString();
    LogPrintf("TradeBoardTab::onRequestTrade() offer_id: %s\n", offer_id.toStdString().c_str());

    if (offer_id.isEmpty()) {
        LogPrintf("TradeBoardTab::onRequestTrade() ERROR: offer_id is empty\n");
        QMessageBox::warning(this, tr("Debug"), tr("Offer ID is empty!"));
        return;
    }

    if (!walletModel) {
        LogPrintf("TradeBoardTab::onRequestTrade() ERROR: walletModel is null\n");
        QMessageBox::warning(this, tr("Error"), tr("Wallet model not available"));
        return;
    }

    // Get the offer data from activeOffers
    if (!activeOffers.contains(offer_id)) {
        QMessageBox::warning(this, tr("Error"), tr("Offer not found in cache."));
        return;
    }

    OfferInfo offerInfo = activeOffers[offer_id];

    // CROSS-CHAIN OFFER: detect schema and validate taker has a profile
    {
        QJsonDocument payloadDoc = QJsonDocument::fromJson(offerInfo.contract_payload.toUtf8());
        QString schema = payloadDoc.object().value("schema").toString();
        if (schema == "cross_chain_spot_v1") {
            LogPrintf("TradeBoardTab::onRequestTrade: Cross-chain offer detected\n");

            // Validate taker has a settlement profile for this chain
            QList<WalletModel::SettlementProfileItem> profiles = walletModel->settlementProfileList();
            bool hasProfile = false;
            for (const auto& p : profiles) {
                if (p.chain == "ethereum") { hasProfile = true; break; }
            }

            if (!hasProfile) {
                QMessageBox::warning(this, tr("No ETH Profile"),
                    tr("You need an Ethereum settlement profile to accept cross-chain offers.\n\n"
                       "Add one via the Profiles button in the Cross-Chain tab."));
                return;
            }

            // Request trade on the bulletin board (session established by maker later)
            auto result = walletModel->bulletinBoardRequestTrade(offer_id);
            if (!result.success) {
                QMessageBox::warning(this, tr("Error"),
                    tr("Failed to request trade: %1").arg(result.error));
                return;
            }

            // Refresh requests so the new request appears in activeRequests
            updateTradeRequestsList();

            // Mark this request as cross-chain so that when the session is
            // established (maker accepts), we auto-send xchain_accept.
            if (activeRequests.contains(result.request_id)) {
                activeRequests[result.request_id].offer_summary["xchain_pending"] = true;
            } else {
                // Request might take a moment to appear — store in a side map
                pendingXchainRequests.insert(result.request_id);
                LogPrintf("TradeBoardTab: Request %s not yet in activeRequests, "
                          "added to pendingXchainRequests\n",
                          result.request_id.toStdString().c_str());
            }

            showAutoClosingInfo(tr("Cross-Chain Request Sent"),
                tr("Trade request sent for cross-chain offer %1.\n\n"
                   "Waiting for maker to accept and establish session...")
                .arg(offer_id.left(12)));
            return;
        }
        if (schema == "difficulty_term_sheet_v1" || offerInfo.contract_type == "difficulty") {
            // Difficulty: request a trade to establish a session with the maker. Once the SPAKE handshake
            // completes, onHandshakeCompleteTaker auto-accepts (difficulty.accept) and sends
            // difficulty_acceptance; the maker imports and the standard maker_base_psbt -> ceremony_ready
            // -> adaptor ceremony path runs. (The double-click ReviewContractOfferDialog stays as a
            // read-only preview / manual-accept fallback.)
            auto result = walletModel->bulletinBoardRequestTrade(offer_id);
            if (!result.success) {
                QMessageBox::warning(this, tr("Error"),
                    tr("Failed to request difficulty trade: %1").arg(result.error));
                return;
            }
            updateTradeRequestsList();
            showAutoClosingInfo(tr("Difficulty Trade Requested"),
                tr("Trade request sent for difficulty offer %1.\n\nWaiting for the maker to accept and "
                   "establish the session; the atomic open ceremony then runs automatically.")
                .arg(offer_id.left(12)));
            return;
        }
    }

    // FORWARD/OPTIONS PREFLIGHT VALIDATION
    if (offerInfo.contract_type == "forward" || offerInfo.contract_type == "option" || offerInfo.contract_type == "options") {

        // 1. Validate deadlines are properly ordered
        if (offerInfo.deadline_short <= 0 || offerInfo.deadline_long <= 0) {
            QMessageBox::critical(this, tr("Invalid Offer"),
                tr("This forward/option offer is missing deadline information and cannot be accepted."));
            return;
        }

        if (offerInfo.deadline_short >= offerInfo.deadline_long) {
            QMessageBox::critical(this, tr("Invalid Offer"),
                tr("Invalid deadlines: Short deadline (%1) must be before Long deadline (%2)")
                .arg(offerInfo.deadline_short).arg(offerInfo.deadline_long));
            return;
        }

        // 2. Check deadlines are in the future
        int currentHeight = walletModel->clientModel().node().getNumBlocks();
        if (offerInfo.deadline_short <= currentHeight) {
            QMessageBox::critical(this, tr("Offer Expired"),
                tr("Short deadline (%1) has already passed (current height: %2)")
                .arg(offerInfo.deadline_short).arg(currentHeight));
            return;
        }

        // 3. Determine taker role and required margin
        QString makerRole = offerInfo.maker_role.toLower();
        QString takerRole;
        double requiredMargin = 0.0;
        QString requiredMarginAsset;
        QString requiredMarginAssetId;

        if (makerRole == "long") {
            takerRole = "short";
            requiredMargin = offerInfo.short_margin_qty;
            requiredMarginAsset = offerInfo.short_margin_asset;
            requiredMarginAssetId = offerInfo.short_margin_asset_id;
        } else if (makerRole == "short") {
            takerRole = "long";
            requiredMargin = offerInfo.long_margin_qty;
            requiredMarginAsset = offerInfo.long_margin_asset;
            requiredMarginAssetId = offerInfo.long_margin_asset_id;
        } else {
            QMessageBox::critical(this, tr("Invalid Offer"),
                tr("Unknown maker role: %1").arg(offerInfo.maker_role));
            return;
        }

        // 4. Check if taker needs to pay premium
        double requiredPremium = 0.0;
        if (offerInfo.premium_amount > 0 && offerInfo.premium_payer.toLower() == takerRole) {
            requiredPremium = offerInfo.premium_amount;
        }

        // 5. Validate balance for native TSC (simplified check)
        if ((requiredMarginAsset.isEmpty() || requiredMarginAsset == "TSC") && requiredMarginAssetId.isEmpty()) {
            double totalRequired = requiredMargin + requiredPremium;
            CAmount walletBalance = walletModel->wallet().getBalance();
            double availableBTC = static_cast<double>(walletBalance) / COIN;

            if (availableBTC < totalRequired) {
                QMessageBox::warning(this, tr("Insufficient Balance"),
                    tr("Not enough TSC for Initial Margin (%1) + premium (%2)\n\n"
                       "Total Required: %3 TSC\n"
                       "Available: %4 TSC\n\n"
                       "You can proceed, but the contract opening may fail.")
                    .arg(requiredMargin, 0, 'f', 8)
                    .arg(requiredPremium, 0, 'f', 8)
                    .arg(totalRequired, 0, 'f', 8)
                    .arg(availableBTC, 0, 'f', 8));
            } else {
                LogPrintf("TradeBoardTab: Forward/option preflight passed - available=%f, required=%f\n",
                          availableBTC, totalRequired);
            }
        }

        // 6. Validate maker's addresses are present (only for finalized offers, not term sheets)
        // Term sheets may not have maker addresses yet - they're filled during finalization
        if (!offerInfo.is_term_sheet) {
            if (takerRole == "short") {
                if (offerInfo.long_margin_dest.isEmpty()) {
                    QMessageBox::warning(this, tr("Incomplete Offer"),
                        tr("Long party's margin address is missing from this finalized offer. "
                           "This may cause the ceremony to fail."));
                    // Don't return - allow user to proceed with warning
                }
            } else if (takerRole == "long") {
                if (offerInfo.short_margin_dest.isEmpty()) {
                    QMessageBox::warning(this, tr("Incomplete Offer"),
                        tr("Short party's margin address is missing from this finalized offer. "
                           "This may cause the ceremony to fail."));
                    // Don't return - allow user to proceed with warning
                }
            }
        }
        // For term sheets, maker will provide addresses during finalization, so no validation needed
    }

    // For CONTRACT offers, show review dialog
    QString offerType = offerInfo.offer_type.toLower();
    if (offerType == "repocontract" || offerType == "forwardcontract" || offerType == "spotcontract") {
        // Build offer data map for dialog
        QVariantMap offerData;
        offerData["offer_id"] = offerInfo.offer_id;
        offerData["maker_pubkey"] = offerInfo.maker_pubkey;
        offerData["offer_type"] = offerInfo.offer_type;
        offerData["contract_type"] = offerInfo.contract_type;
        offerData["maker_role"] = offerInfo.maker_role;
        offerData["apr"] = offerInfo.apr;
        offerData["ltv"] = offerInfo.ltv;
        offerData["tenor_days"] = offerInfo.tenor_days;
        offerData["contract_payload"] = offerInfo.contract_payload;
        offerData["is_term_sheet"] = offerInfo.is_term_sheet;
        offerData["term_sheet_json"] = offerInfo.term_sheet_json;
        offerData["proof_of_funds"] = offerInfo.proof_of_funds;
        offerData["proof_verified"] = offerInfo.proof_verified;
        offerData["proof_verified_units"] = static_cast<qlonglong>(offerInfo.proof_verified_units);
        offerData["proof_verified_asset"] = offerInfo.proof_verified_asset;
        offerData["proof_verification_error"] = offerInfo.proof_verification_error;

        // Launch review dialog
        ReviewContractOfferDialog dialog(offerData, walletModel, this);
        if (dialog.exec() == QDialog::Accepted) {
            // Dialog handles the acceptance and RPC calls
            // Refresh requests list to show new request
            updateTradeRequestsList();
        }
        return;
    }

    // For legacy asset trades, use simple flow
    // Note: taker_pubkey is derived internally by cosign.request_trade RPC
    auto result = walletModel->bulletinBoardRequestTrade(offer_id);

    if (result.success) {
        showAutoClosingInfo(tr("Success"),
            tr("Trade request sent!\n\nRequest ID: %1\n\nWait for maker to accept.\n\nCheck 'Trade Requests' below.")
            .arg(result.request_id.left(16) + "..."));

        // Immediately refresh to show the new request
        updateTradeRequestsList();
    } else {
        QMessageBox::warning(this, tr("Error"),
            tr("Failed to request trade: %1").arg(result.error));
    }
}

void TradeBoardTab::onDeleteOffer()
{
    LogPrintf("TradeBoardTab::onDeleteOffer() called\n");

    QPushButton* button = qobject_cast<QPushButton*>(sender());
    if (!button) {
        LogPrintf("TradeBoardTab::onDeleteOffer() ERROR: sender() returned null\n");
        QMessageBox::warning(this, tr("Debug"), tr("Button sender is null!"));
        return;
    }
    LogPrintf("TradeBoardTab::onDeleteOffer() button valid\n");

    QString offer_id = button->property("offer_id").toString();
    LogPrintf("TradeBoardTab::onDeleteOffer() offer_id: %s\n", offer_id.toStdString().c_str());

    if (offer_id.isEmpty()) {
        LogPrintf("TradeBoardTab::onDeleteOffer() ERROR: offer_id is empty\n");
        QMessageBox::warning(this, tr("Debug"), tr("Offer ID is empty!"));
        return;
    }

    if (!walletModel) {
        LogPrintf("TradeBoardTab::onDeleteOffer() ERROR: walletModel is null\n");
        QMessageBox::warning(this, tr("Debug"), tr("Wallet model is null!"));
        return;
    }
    LogPrintf("TradeBoardTab::onDeleteOffer() walletModel valid\n");

    QMessageBox::StandardButton reply = QMessageBox::question(this,
        tr("Delete Offer"),
        tr("Are you sure you want to delete this offer?\n\nOffer ID: %1")
        .arg(offer_id.left(16) + "..."),
        QMessageBox::Yes | QMessageBox::No);

    if (reply == QMessageBox::Yes) {
        LogPrintf("TradeBoardTab::onDeleteOffer() User confirmed deletion, calling RPC\n");
        // Call RPC to delete offer
        bool success = walletModel->bulletinBoardDeleteOffer(offer_id);
        LogPrintf("TradeBoardTab::onDeleteOffer() RPC returned: success=%d\n", success);

        if (success) {
            showAutoClosingInfo(tr("Success"),
                tr("Offer deleted successfully!\n\nOffer ID: %1\n\nThe offer has been removed from Nostr relays.")
                .arg(offer_id.left(16) + "..."));
        } else {
            QMessageBox::warning(this, tr("Error"),
                tr("Failed to delete offer.\n\nThe offer may have already been deleted or expired."));
        }

        // Refresh offers list
        updateOffersList();
    } else {
        LogPrintf("TradeBoardTab::onDeleteOffer() User cancelled deletion\n");
    }
}

void TradeBoardTab::clearStuckTradeRequests()
{
    LogPrintf("TradeBoardTab::clearStuckTradeRequests() Unlocking wallet-level Fair-Sign UTXOs\n");

    // Unlock all wallet-level Fair-Sign ceremony UTXOs
    int unlocked_count = 0;
    int sessions_cleaned = 0;
    if (walletModel) {
        try {
            UniValue params(UniValue::VARR);
            UniValue response = walletModel->node().executeRpc("adaptor.unlock_all", params, walletModel->getWalletName().toStdString());
            if (response.isObject()) {
                unlocked_count = response["unlocked_count"].getInt<int>();
                sessions_cleaned = response["sessions_cleaned"].getInt<int>();
                LogPrintf("TradeBoardTab: Unlocked %d UTXOs, cleaned %d expired sessions\n", unlocked_count, sessions_cleaned);
            }
        } catch (const std::exception& e) {
            LogPrintf("TradeBoardTab: Failed to unlock Fair-Sign UTXOs: %s\n", e.what());
            QMessageBox::warning(this, tr("Unlock Failed"),
                tr("Failed to unlock wallet UTXOs:\n\n%1").arg(QString::fromStdString(e.what())));
            return;
        }
    }

    // Clear GUI-level locked PSBT flags (don't reset sessions - that creates spam)
    int clearedCount = 0;
    for (auto it = activeRequests.begin(); it != activeRequests.end(); ++it) {
        if (it->psbt_locked) {
            LogPrintf("TradeBoardTab: Clearing locked PSBT flag for request %s (hash=%s)\n",
                      it->request_id.toStdString().c_str(),
                      it->augmented_psbt_hash.toStdString().c_str());
            it->psbt_locked = false;
            it->augmented_psbt.clear();
            it->augmented_psbt_hash.clear();
            clearedCount++;
        }
    }

    LogPrintf("TradeBoardTab: Cleared %d locked PSBT flags\n", clearedCount);

    if (unlocked_count > 0 || clearedCount > 0) {
        showAutoClosingInfo(tr("Funds Unlocked"),
            tr("Unlocked %1 wallet UTXO(s) and cleared %2 GUI lock(s).\n\n"
               "Your coins should now be spendable again.\n"
               "Sessions remain active - no spam created.")
            .arg(unlocked_count).arg(clearedCount));
    } else {
        showAutoClosingInfo(tr("No Locked Funds"),
            tr("No locked UTXOs or stuck requests found."));
    }

    // Refresh the UI
    updateOffersList();
    updateTradeRequestsList();
}

void TradeBoardTab::onContractTypeChanged(int index)
{
    Q_UNUSED(index);

    LogPrintf("TradeBoardTab::onContractTypeChanged() Contract type changed to: %s\n",
              currentContractType.toStdString().c_str());

    // Show only the relevant table
    repoTable->setVisible(currentContractType == "repo");
    forwardTable->setVisible(currentContractType == "forward");
    optionsTable->setVisible(currentContractType == "options");
    spotTable->setVisible(currentContractType == "spot");
    crossChainTable->setVisible(currentContractType == "cross_chain");
    if (difficultyTable) difficultyTable->setVisible(currentContractType == "difficulty");
    if (crossChainTradeView) {
        crossChainTradeView->setVisible(currentContractType == "cross_chain");
    }

    // Update create button tooltip
    QString contractTypeName;
    if (currentContractType == "repo") {
        contractTypeName = tr("repo");
    } else if (currentContractType == "forward") {
        contractTypeName = tr("forward");
    } else if (currentContractType == "options") {
        contractTypeName = tr("option");
    } else if (currentContractType == "spot") {
        contractTypeName = tr("spot");
    } else if (currentContractType == "difficulty") {
        contractTypeName = tr("difficulty");
    } else if (currentContractType == "cross_chain") {
        contractTypeName = tr("cross-chain");
    }

    createContractButton->setToolTip(tr("Add a %1 offer").arg(contractTypeName));

    // Re-render the offers with current filter
    updateOffersList();
}

void TradeBoardTab::showFilterDialog()
{
    QDialog dialog(this);
    dialog.setWindowTitle(tr("Filter Offers"));
    dialog.setModal(true);
    dialog.setMinimumWidth(400);

    QVBoxLayout* layout = new QVBoxLayout(&dialog);

    // Filter non-registry assets checkbox
    QCheckBox* filterRegistryCheck = new QCheckBox(tr("Hide assets not in registry"), &dialog);
    filterRegistryCheck->setChecked(filterSettings.filterNonRegistryAssets);
    filterRegistryCheck->setToolTip(tr("Only show offers with assets that are in the asset registry"));
    layout->addWidget(filterRegistryCheck);

    // Asset filter
    QHBoxLayout* assetLayout = new QHBoxLayout();
    assetLayout->addWidget(new QLabel(tr("Asset Symbol/ID:")));
    QLineEdit* assetEdit = new QLineEdit(&dialog);
    assetEdit->setText(filterSettings.assetFilter);
    assetEdit->setPlaceholderText(tr("e.g., TSC or asset ID"));
    assetLayout->addWidget(assetEdit);
    layout->addLayout(assetLayout);

    // Role filter
    QHBoxLayout* roleLayout = new QHBoxLayout();
    roleLayout->addWidget(new QLabel(tr("Role Filter:")));
    QComboBox* roleCombo = new QComboBox(&dialog);
    roleCombo->addItem(tr("All"), "all");

    if (currentContractType == "repo") {
        roleCombo->addItem(tr("Lender"), "lender");
        roleCombo->addItem(tr("Borrower"), "borrower");
    } else if (currentContractType == "forward" || currentContractType == "options") {
        roleCombo->addItem(tr("Long"), "long");
        roleCombo->addItem(tr("Short"), "short");
    }

    // Set current selection
    int roleIndex = roleCombo->findData(filterSettings.roleFilter);
    if (roleIndex >= 0) roleCombo->setCurrentIndex(roleIndex);
    roleLayout->addWidget(roleCombo);
    layout->addLayout(roleLayout);

    // Min amount filter
    QGroupBox* minGroup = new QGroupBox(tr("Minimum Amount"), &dialog);
    QHBoxLayout* minLayout = new QHBoxLayout(minGroup);
    QCheckBox* minCheck = new QCheckBox(tr("Enable"), minGroup);
    minCheck->setChecked(filterSettings.filterByMinAmount);
    QDoubleSpinBox* minSpin = new QDoubleSpinBox(minGroup);
    minSpin->setRange(0.0, 1e12);
    minSpin->setDecimals(8);
    minSpin->setValue(filterSettings.minAmount);
    minSpin->setSuffix(" units");
    minSpin->setEnabled(filterSettings.filterByMinAmount);
    connect(minCheck, &QCheckBox::toggled, minSpin, &QDoubleSpinBox::setEnabled);
    minLayout->addWidget(minCheck);
    minLayout->addWidget(minSpin);
    layout->addWidget(minGroup);

    // Max amount filter
    QGroupBox* maxGroup = new QGroupBox(tr("Maximum Amount"), &dialog);
    QHBoxLayout* maxLayout = new QHBoxLayout(maxGroup);
    QCheckBox* maxCheck = new QCheckBox(tr("Enable"), maxGroup);
    maxCheck->setChecked(filterSettings.filterByMaxAmount);
    QDoubleSpinBox* maxSpin = new QDoubleSpinBox(maxGroup);
    maxSpin->setRange(0.0, 1e12);
    maxSpin->setDecimals(8);
    maxSpin->setValue(filterSettings.maxAmount);
    maxSpin->setSuffix(" units");
    maxSpin->setEnabled(filterSettings.filterByMaxAmount);
    connect(maxCheck, &QCheckBox::toggled, maxSpin, &QDoubleSpinBox::setEnabled);
    maxLayout->addWidget(maxCheck);
    maxLayout->addWidget(maxSpin);
    layout->addWidget(maxGroup);

    // Buttons
    QHBoxLayout* buttonLayout = new QHBoxLayout();
    QPushButton* resetButton = new QPushButton(tr("Reset"), &dialog);
    QPushButton* applyButton = new QPushButton(tr("Apply"), &dialog);
    QPushButton* cancelButton = new QPushButton(tr("Cancel"), &dialog);

    buttonLayout->addWidget(resetButton);
    buttonLayout->addStretch();
    buttonLayout->addWidget(cancelButton);
    buttonLayout->addWidget(applyButton);
    layout->addLayout(buttonLayout);

    // Connect reset button
    connect(resetButton, &QPushButton::clicked, [&]() {
        filterRegistryCheck->setChecked(true);
        assetEdit->clear();
        roleCombo->setCurrentIndex(0);
        minCheck->setChecked(false);
        minSpin->setValue(0.0);
        maxCheck->setChecked(false);
        maxSpin->setValue(0.0);
    });

    // Connect apply button
    connect(applyButton, &QPushButton::clicked, [&]() {
        filterSettings.filterNonRegistryAssets = filterRegistryCheck->isChecked();
        filterSettings.assetFilter = assetEdit->text().trimmed();
        filterSettings.roleFilter = roleCombo->currentData().toString();
        filterSettings.filterByMinAmount = minCheck->isChecked();
        filterSettings.minAmount = minSpin->value();
        filterSettings.filterByMaxAmount = maxCheck->isChecked();
        filterSettings.maxAmount = maxSpin->value();

        // Update the offers list with new filters
        updateOffersList();

        dialog.accept();
    });

    // Connect cancel button
    connect(cancelButton, &QPushButton::clicked, &dialog, &QDialog::reject);

    dialog.exec();
}

void TradeBoardTab::onCreateContract()
{
    if (!walletModel) {
        QMessageBox::warning(this, tr("Error"), tr("Wallet model not available"));
        return;
    }

    if (currentContractType == "repo") {
        // Launch Repo Contract Builder wizard directly
        RepoContractBuilder wizard(walletModel, this);

        if (wizard.exec() == QDialog::Accepted) {
            QString offerId = wizard.getOfferId();
            QVariantMap offerData = wizard.getOfferData();
            QString offerJson = wizard.getOfferJson();

            // CACHE POPULATION: Wizard propose success - populate canonical cache
            cacheContractFlavor(offerId, "repo", offerJson);
            LogPrintf("TradeBoardTab: Cached contract flavor at wizard propose - offer_id=%s, type=repo\n",
                      offerId.toStdString().c_str());

            // Create custom dialog with multiple sharing options
            QMessageBox shareDialog(TopLevelDialogParent(this));
            shareDialog.setWindowTitle(tr("Repo Offer Created Successfully"));
            shareDialog.setText(tr("Repo contract offer created!\n\nOffer ID: %1\n\n"
                                   "Choose how to share this offer:").arg(offerId));
            shareDialog.setIcon(QMessageBox::Information);

            QPushButton* postWithProofButton = shareDialog.addButton(tr("Publish with Proof"), QMessageBox::AcceptRole);
            postWithProofButton->setStyleSheet("QPushButton { background-color: #2e7d32; color: white; font-weight: bold; }");
            QPushButton* postBBButton = shareDialog.addButton(tr("Publish to Market"), QMessageBox::ActionRole);
            postBBButton->setStyleSheet("QPushButton { background-color: #4caf50; color: white; font-weight: bold; }");
            QPushButton* exportButton = shareDialog.addButton(tr("Export Manually"), QMessageBox::ActionRole);
            QPushButton* openButton = shareDialog.addButton(tr("Open Now"), QMessageBox::ActionRole);
            shareDialog.addButton(tr("Decide Later"), QMessageBox::RejectRole);

            shareDialog.setDefaultButton(postWithProofButton);
            shareDialog.exec();

            QAbstractButton* clickedButton = shareDialog.clickedButton();

            if (clickedButton == postBBButton || clickedButton == postWithProofButton) {
                // Post to bulletin board (with or without automatic proof)
                QString offerJson = wizard.getOfferJson();
                QString role = offerData.value("role").toString();

                // Calculate display fields
                double apr = 0.0;
                double ltv = 0.0;
                int tenor_days = 0;

                if (offerData.contains("interest_units") && offerData.contains("principal_units")) {
                    double interest = offerData["interest_units"].toDouble();
                    double principal = offerData["principal_units"].toDouble();
                    if (principal > 0) {
                        int maturity_height = offerData.value("maturity_height", 0).toInt();
                        int current_height = walletModel->clientModel().node().getNumBlocks();
                        double days = (maturity_height - current_height) / 144.0;
                        if (days > 0) {
                            apr = (interest / principal) * (365.0 / days) * 100.0;
                            tenor_days = static_cast<int>(days);
                        }
                    }
                }

                if (offerData.contains("collateral_sats") && offerData.contains("principal_units")) {
                    double collateral = offerData["collateral_sats"].toDouble();
                    double principal = offerData["principal_units"].toDouble();
                    if (collateral > 0) {
                        ltv = (principal / collateral) * 100.0;
                    }
                }

                // Automatic or no proof based on button clicked
                QVariantList proofs;
                if (clickedButton == postWithProofButton) {
                    try {
                        LogPrintf("[TradeBoardTab] Auto-generating proof of funds for offer\n");

                        // Parse term_sheet_json to get actual amounts
                        QString termSheetJson = offerData.value("term_sheet_json").toString();
                        QJsonDocument termSheetDoc = QJsonDocument::fromJson(termSheetJson.toUtf8());
                        QJsonObject termSheetObj = termSheetDoc.object();
                        QJsonObject terms = termSheetObj.value("terms").toObject();

                        // Determine required asset and amount based on role
                        QString assetToProve;
                        uint64_t requiredUnits = 0;
                        QString context = QString("offer:%1:%2").arg(offerId).arg(role);

                        if (role == "lender") {
                            // Lender proves principal asset
                            double principalAmount = terms.value("principal_amount").toDouble();
                            bool principalIsNative = terms.value("principal_is_native").toBool(true);
                            QString principalAssetId = terms.value("principal_asset_id").toString();

                            int decimals = 8;
                            if (!principalIsNative && !principalAssetId.isEmpty() && walletModel) {
                                assetToProve = principalAssetId;
                                WalletModel::AssetInfo assetInfo = walletModel->getAssetInfo(principalAssetId);
                                if (assetInfo.has_decimals) {
                                    decimals = assetInfo.decimals;
                                }
                            }
                            requiredUnits = static_cast<uint64_t>(principalAmount * std::pow(10.0, decimals));
                        } else {  // borrower
                            // Borrower proves collateral asset
                            double collateralAmount = terms.value("collateral_amount").toDouble();
                            bool collateralIsNative = terms.value("collateral_is_native").toBool(true);
                            QString collateralAssetId = terms.value("collateral_asset_id").toString();

                            int decimals = 8;
                            if (!collateralIsNative && !collateralAssetId.isEmpty() && walletModel) {
                                assetToProve = collateralAssetId;
                                WalletModel::AssetInfo assetInfo = walletModel->getAssetInfo(collateralAssetId);
                                if (assetInfo.has_decimals) {
                                    decimals = assetInfo.decimals;
                                }
                            }
                            requiredUnits = static_cast<uint64_t>(collateralAmount * std::pow(10.0, decimals));
                        }

                        LogPrintf("[TradeBoardTab] Auto-proof: role=%s, requiredUnits=%llu, assetToProve=%s\n",
                                 role.toStdString().c_str(), requiredUnits,
                                 assetToProve.isEmpty() ? "native" : assetToProve.toStdString().c_str());

                        // Auto-select UTXOs: pick just enough to meet requirement
                        if (requiredUnits > 0 && walletModel) {
                            auto autoProofResult = walletModel->createProofOfFunds(assetToProve, requiredUnits, context);
                            if (autoProofResult.success && !autoProofResult.proofs.isEmpty()) {
                                proofs = autoProofResult.proofs;
                                LogPrintf("[TradeBoardTab] Auto-generated %d proofs covering %llu units\n",
                                         proofs.size(), autoProofResult.total_units);
                            } else {
                                LogPrintf("[TradeBoardTab] Failed to auto-generate proof: %s\n",
                                         autoProofResult.error.toStdString().c_str());
                                QMessageBox::warning(this, tr("Proof Generation Failed"),
                                    tr("Could not automatically generate proof of funds:\n\n%1\n\nProceeding without proof.")
                                       .arg(autoProofResult.error));
                            }
                        } else {
                            LogPrintf("[TradeBoardTab] requiredUnits is 0 or walletModel null, skipping proof generation\n");
                            QMessageBox::warning(this, tr("Proof Generation Skipped"),
                                tr("Could not determine required amount for proof generation.\n\nProceeding without proof."));
                        }
                    } catch (const UniValue& e) {
                        LogPrintf("[TradeBoardTab] UniValue exception during auto-proof generation\n");
                        QMessageBox::warning(this, tr("Proof Generation Error"),
                            tr("An RPC error occurred while generating proof of funds.\n\nProceeding without proof."));
                    } catch (const std::exception& e) {
                        LogPrintf("[TradeBoardTab] Exception during auto-proof generation: %s\n", e.what());
                        QMessageBox::warning(this, tr("Proof Generation Error"),
                            tr("An error occurred while generating proof of funds:\n\n%1\n\nProceeding without proof.")
                               .arg(QString::fromStdString(e.what())));
                    } catch (...) {
                        LogPrintf("[TradeBoardTab] Unknown exception during auto-proof generation\n");
                        QMessageBox::warning(this, tr("Proof Generation Error"),
                            tr("An unknown error occurred while generating proof of funds.\n\nProceeding without proof."));
                    }
                }

                LogPrintf("[TradeBoardTab] Posting offer with %d proofs\n", proofs.size());

                auto result = walletModel->bulletinBoardPostContractOffer("repo", offerJson, role, apr, ltv, tenor_days, proofs);

                if (result.success) {
                    // FIX: Link bulletin-board UUID to contract ID in cache (dual-key mapping)
                    cacheContractFlavor(offerId, "repo", offerJson, result.offer_id);
                    LogPrintf("TradeBoardTab: Post-publication cache link - contract_id=%s, bb_uuid=%s, type=repo\n",
                              offerId.toStdString().c_str(), result.offer_id.toStdString().c_str());

                    // Store transport preference for this offer
                    QString transport = wizard.getTransport();
                    offerTransportPreferences[result.offer_id] = transport;
                    LogPrintf("TradeBoardTab: Stored transport preference for offer %s: %s\n",
                             result.offer_id.toStdString().c_str(), transport.toStdString().c_str());

                    showAutoClosingInfo(tr("Posted to Bulletin Board"),
                        tr("Offer posted to Nostr!\n\nOffer ID: %1\n\nOthers can now discover and request this trade.").arg(result.offer_id));

                    // Refresh the offers list to show the new offer
                    updateOffersList();
                } else {
                    QMessageBox::warning(this, tr("Posting Failed"), tr("Failed: %1").arg(result.error));
                }

            } else if (clickedButton == exportButton) {
                // Export offer JSON to file
                QString offerJson = wizard.getOfferJson();

                // Offer choice: save to file or copy to clipboard
                QMessageBox exportChoice(TopLevelDialogParent(this));
                exportChoice.setWindowTitle(tr("Export Offer"));
                exportChoice.setText(tr("How would you like to export the offer?"));
                exportChoice.setIcon(QMessageBox::Question);

                QPushButton* saveFileBtn = exportChoice.addButton(tr("Save to File"), QMessageBox::AcceptRole);
                QPushButton* copyClipboardBtn = exportChoice.addButton(tr("Copy to Clipboard"), QMessageBox::ActionRole);
                exportChoice.addButton(QMessageBox::Cancel);

                exportChoice.exec();
                QAbstractButton* exportChoice_clicked = exportChoice.clickedButton();

                if (exportChoice_clicked == saveFileBtn) {
                    QString fileName = QFileDialog::getSaveFileName(this, tr("Save Offer JSON"),
                        QString("repo_offer_%1.json").arg(offerId),
                        tr("JSON Files (*.json);;All Files (*)"));

                    if (!fileName.isEmpty()) {
                        QFile file(fileName);
                        if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
                            file.write(offerJson.toUtf8());
                            file.close();
                            showAutoClosingInfo(tr("Export Successful"),
                                tr("Offer exported to:\n%1").arg(fileName));
                        } else {
                            QMessageBox::warning(this, tr("Export Failed"),
                                tr("Failed to write file:\n%1").arg(fileName));
                        }
                    }
                } else if (exportChoice_clicked == copyClipboardBtn) {
                    QApplication::clipboard()->setText(offerJson);
                    showAutoClosingInfo(tr("Copied to Clipboard"),
                        tr("Offer JSON copied to clipboard.\n\nOffer ID: %1").arg(offerId));
                }

            } else if (clickedButton == openButton) {
                // To open the contract, we need to call repo.propose RPC first to get a proper 32-byte hex offer ID
                // Extract terms from offerData
                QVariantMap terms;

                // Copy all fields from offerData that are needed for repo.propose
                QStringList keys = offerData.keys();
                for (const QString& key : keys) {
                    // Skip metadata fields that aren't part of the terms
                    if (key != "apr_percent" && key != "ltv_percent" && key != "tenor_days" &&
                        key != "term_sheet_json" && key != "offer_id" && key != "bulletin_board_pending") {
                        terms[key] = offerData[key];
                    }
                }

                // Call repo.propose to get a proper offer ID
                WalletModel::RepoProposeResult proposeResult = walletModel->repoPropose(terms);

                if (!proposeResult.success) {
                    QMessageBox::critical(this, tr("Propose Failed"),
                        tr("Failed to create finalized offer:\n%1").arg(proposeResult.error));
                    return;
                }

                // Now open with the proper hex offer ID
                OpenContractDialog openDialog(walletModel, proposeResult.offer_id, "repo", proposeResult.offer_data, this);
                if (openDialog.exec() == QDialog::Accepted && openDialog.wasOpened()) {
                    showAutoClosingInfo(tr("Contract Opened"),
                        tr("Contract opened!\n\nTXID: %1").arg(openDialog.getOpeningTxId()));
                }
            }
        }
    } else if (currentContractType == "forward") {
        // Launch Forward Contract Builder wizard
        ForwardContractBuilder wizard(walletModel, false, this);

        if (wizard.exec() == QDialog::Accepted) {
            QString offerId = wizard.getOfferId();
            QVariantMap offerData = wizard.getOfferData();
            QString offerJson = wizard.getOfferJson();

            // CACHE POPULATION: Wizard propose success - populate canonical cache
            cacheContractFlavor(offerId, "forward", offerJson);
            LogPrintf("TradeBoardTab: Cached contract flavor at wizard propose - offer_id=%s, type=forward\n",
                      offerId.toStdString().c_str());

            // Create share dialog
            QMessageBox shareDialog(TopLevelDialogParent(this));
            shareDialog.setWindowTitle(tr("Forward Offer Created"));
            shareDialog.setText(tr("Forward contract offer created!\n\nOffer ID: %1\n\n"
                                   "Choose how to share this offer:").arg(offerId));
            shareDialog.setIcon(QMessageBox::Information);

            QPushButton* postWithProofButton = shareDialog.addButton(tr("Publish with Proof"), QMessageBox::AcceptRole);
            postWithProofButton->setStyleSheet("QPushButton { background-color: #2e7d32; color: white; font-weight: bold; }");
            QPushButton* postBBButton = shareDialog.addButton(tr("Publish to Market"), QMessageBox::ActionRole);
            postBBButton->setStyleSheet("QPushButton { background-color: #4caf50; color: white; font-weight: bold; }");
            QPushButton* exportButton = shareDialog.addButton(tr("Export Manually"), QMessageBox::ActionRole);
            shareDialog.addButton(tr("Decide Later"), QMessageBox::RejectRole);

            shareDialog.setDefaultButton(postWithProofButton);
            shareDialog.exec();

            QAbstractButton* clickedButton = shareDialog.clickedButton();

            if (clickedButton == postBBButton || clickedButton == postWithProofButton) {
                // Extract display fields for bulletin board
                QString role = offerData.value("role", "").toString();
                double tenorDaysShort = offerData.value("tenor_days_short", 0).toDouble();

                QString tenorStr = QString::number(static_cast<int>(std::round(tenorDaysShort))) + "d";

                // Leg A / Leg B: delivery assets
                QString legA = "TBD";
                QString legB = "TBD";
                if (offerData.contains("long_deliver_is_native") && offerData["long_deliver_is_native"].toBool()) {
                    legA = "TSC";
                } else if (offerData.contains("long_deliver_asset_id")) {
                    legA = offerData["long_deliver_asset_id"].toString().left(8);
                }
                if (offerData.contains("short_deliver_is_native") && offerData["short_deliver_is_native"].toBool()) {
                    legB = "TSC";
                } else if (offerData.contains("short_deliver_asset_id")) {
                    legB = offerData["short_deliver_asset_id"].toString().left(8);
                }

                // Margin A / Margin B: IM percentages from metrics
                QString marginA = "TBD";
                QString marginB = "TBD";
                if (offerData.contains("long_im_percent")) {
                    marginA = QString::number(offerData["long_im_percent"].toDouble(), 'f', 1) + "%";
                }
                if (offerData.contains("short_im_percent")) {
                    marginB = QString::number(offerData["short_im_percent"].toDouble(), 'f', 1) + "%";
                }

                // Auto-generate proof of funds for maker (only if "Publish with Proof" was clicked)
                QVariantList proofs;
                if (clickedButton == postWithProofButton) {
                    try {
                        LogPrintf("[TradeBoardTab] Auto-generating proof of funds for forward offer (role=%s)\n", role.toStdString().c_str());

                    // Parse term_sheet_json to get actual amounts
                    QString termSheetJson = offerData.value("term_sheet_json").toString();
                    QJsonDocument termSheetDoc = QJsonDocument::fromJson(termSheetJson.toUtf8());
                    QJsonObject termSheetObj = termSheetDoc.object();
                    QJsonObject terms = termSheetObj.value("terms").toObject();

                    // Determine required asset and amount based on role (long or short)
                    QString assetToProve;
                    uint64_t requiredUnits = 0;
                    QString context = QString("offer:%1:%2").arg(offerId).arg(role);

                    if (role == "long") {
                        // Long party needs to prove: IM only (NOT deliver - that's the whole point of forwards!)
                        bool isNative = terms.value("long_im_is_native").toBool(true);
                        QString assetId = terms.value("long_im_asset_id").toString();

                        int decimals = 8;
                        if (!isNative && !assetId.isEmpty() && walletModel) {
                            assetToProve = assetId;
                            WalletModel::AssetInfo assetInfo = walletModel->getAssetInfo(assetId);
                            if (assetInfo.has_decimals) {
                                decimals = assetInfo.decimals;
                            }
                        }

                        // Both _amount and _units are decimal values (need to multiply by decimals)
                        double imAmount = 0.0;
                        if (terms.contains("long_im_amount")) {
                            imAmount = terms.value("long_im_amount").toDouble();
                        } else if (terms.contains("long_im_units")) {
                            imAmount = terms.value("long_im_units").toDouble();
                        }
                        requiredUnits = static_cast<uint64_t>(imAmount * std::pow(10.0, decimals));

                    } else if (role == "short") {
                        // Short party needs to prove: IM only (NOT deliver - that's the whole point of forwards!)
                        bool isNative = terms.value("short_im_is_native").toBool(true);
                        QString assetId = terms.value("short_im_asset_id").toString();

                        int decimals = 8;
                        if (!isNative && !assetId.isEmpty() && walletModel) {
                            assetToProve = assetId;
                            WalletModel::AssetInfo assetInfo = walletModel->getAssetInfo(assetId);
                            if (assetInfo.has_decimals) {
                                decimals = assetInfo.decimals;
                            }
                        }

                        // Both _amount and _units are decimal values (need to multiply by decimals)
                        double imAmount = 0.0;
                        if (terms.contains("short_im_amount")) {
                            imAmount = terms.value("short_im_amount").toDouble();
                        } else if (terms.contains("short_im_units")) {
                            imAmount = terms.value("short_im_units").toDouble();
                        }
                        requiredUnits = static_cast<uint64_t>(imAmount * std::pow(10.0, decimals));
                    }

                    LogPrintf("[TradeBoardTab] Forward auto-proof: role=%s, requiredUnits=%llu, assetToProve=%s\n",
                             role.toStdString().c_str(), requiredUnits,
                             assetToProve.isEmpty() ? "native" : assetToProve.toStdString().c_str());

                    // Auto-select UTXOs: pick just enough to meet requirement
                    if (requiredUnits > 0 && walletModel) {
                        auto autoProofResult = walletModel->createProofOfFunds(assetToProve, requiredUnits, context);
                        if (autoProofResult.success && !autoProofResult.proofs.isEmpty()) {
                            proofs = autoProofResult.proofs;
                            LogPrintf("[TradeBoardTab] Auto-generated %d proofs covering %llu units\n",
                                     proofs.size(), autoProofResult.total_units);
                        } else {
                            LogPrintf("[TradeBoardTab] Failed to auto-generate proof: %s\n",
                                     autoProofResult.error.toStdString().c_str());
                            QMessageBox::warning(this, tr("Proof Generation Failed"),
                                tr("Could not automatically generate proof of funds:\n\n%1\n\nProceeding without proof.")
                                   .arg(autoProofResult.error));
                        }
                    } else {
                        LogPrintf("[TradeBoardTab] requiredUnits is 0 or walletModel null, skipping proof generation\n");
                    }
                } catch (const UniValue& e) {
                    LogPrintf("[TradeBoardTab] UniValue exception during forward auto-proof generation\n");
                    QMessageBox::warning(this, tr("Proof Generation Error"),
                        tr("An RPC error occurred while generating proof of funds.\n\nProceeding without proof."));
                } catch (const std::exception& e) {
                    LogPrintf("[TradeBoardTab] Exception during forward auto-proof generation: %s\n", e.what());
                    QMessageBox::warning(this, tr("Proof Generation Error"),
                        tr("An error occurred while generating proof of funds:\n\n%1\n\nProceeding without proof.")
                           .arg(QString::fromStdString(e.what())));
                    } catch (...) {
                        LogPrintf("[TradeBoardTab] Unknown exception during forward auto-proof generation\n");
                        QMessageBox::warning(this, tr("Proof Generation Error"),
                            tr("An unknown error occurred while generating proof of funds.\n\nProceeding without proof."));
                    }
                }

                bool verifyFunds = (clickedButton == postWithProofButton);
                LogPrintf("[TradeBoardTab] Posting forward offer with %d proofs (verify_funds=%s)\n",
                         proofs.size(), verifyFunds ? "true" : "false");

                // Calculate tenor in days from offerData
                int tenorDays = static_cast<int>(std::round(tenorDaysShort));
                auto result = walletModel->bulletinBoardPostContractOffer("forward", offerJson, role, 0.0, 0.0, tenorDays, proofs);

                if (result.success) {
                    // FIX: Link bulletin-board UUID to contract ID in cache (dual-key mapping)
                    cacheContractFlavor(offerId, "forward", offerJson, result.offer_id);
                    LogPrintf("TradeBoardTab: Post-publication cache link - contract_id=%s, bb_uuid=%s, type=forward\n",
                              offerId.toStdString().c_str(), result.offer_id.toStdString().c_str());

                    // Store transport preference for this offer
                    QString transport = wizard.getTransport();
                    offerTransportPreferences[result.offer_id] = transport;
                    LogPrintf("TradeBoardTab: Stored transport preference for offer %s: %s\n",
                             result.offer_id.toStdString().c_str(), transport.toStdString().c_str());

                    showAutoClosingInfo(tr("Posted to Bulletin Board"),
                        tr("Forward offer posted to bulletin board!\n\nOffer ID: %1").arg(result.offer_id));
                    updateOffersList();
                } else {
                    QMessageBox::critical(this, tr("Bulletin Board Error"),
                        tr("Failed to post offer:\n%1").arg(result.error));
                }
            } else if (clickedButton == exportButton) {
                // Export offer JSON - choice between file or clipboard
                QMessageBox exportChoice(TopLevelDialogParent(this));
                exportChoice.setWindowTitle(tr("Export Offer"));
                exportChoice.setText(tr("How would you like to export the offer?"));
                exportChoice.setIcon(QMessageBox::Question);

                QPushButton* saveFileBtn = exportChoice.addButton(tr("Save to File"), QMessageBox::AcceptRole);
                QPushButton* copyClipboardBtn = exportChoice.addButton(tr("Copy to Clipboard"), QMessageBox::ActionRole);
                exportChoice.addButton(QMessageBox::Cancel);

                exportChoice.exec();
                QAbstractButton* exportChoice_clicked = exportChoice.clickedButton();

                if (exportChoice_clicked == saveFileBtn) {
                    QString fileName = QFileDialog::getSaveFileName(this, tr("Save Offer JSON"),
                        QString("forward_offer_%1.json").arg(offerId),
                        tr("JSON Files (*.json);;All Files (*)"));

                    if (!fileName.isEmpty()) {
                        QFile file(fileName);
                        if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
                            file.write(offerJson.toUtf8());
                            file.close();
                            showAutoClosingInfo(tr("Export Successful"),
                                tr("Offer exported to:\n%1").arg(fileName));
                        } else {
                            QMessageBox::warning(this, tr("Export Failed"),
                                tr("Failed to write file:\n%1").arg(fileName));
                        }
                    }
                } else if (exportChoice_clicked == copyClipboardBtn) {
                    QApplication::clipboard()->setText(offerJson);
                    showAutoClosingInfo(tr("Copied to Clipboard"),
                        tr("Forward offer JSON copied to clipboard.\n\nOffer ID: %1").arg(offerId));
                }
            }
        }
    } else if (currentContractType == "options") {
        // Launch Options Contract Builder wizard
        ForwardContractBuilder wizard(walletModel, true, this);

        if (wizard.exec() == QDialog::Accepted) {
            QString offerId = wizard.getOfferId();
            QVariantMap offerData = wizard.getOfferData();
            QString offerJson = wizard.getOfferJson();

            // CACHE POPULATION: Wizard propose success - populate canonical cache
            cacheContractFlavor(offerId, "option", offerJson);
            LogPrintf("TradeBoardTab: Cached contract flavor at wizard propose - offer_id=%s, type=option\n",
                      offerId.toStdString().c_str());

            // Create share dialog
            QMessageBox shareDialog(TopLevelDialogParent(this));
            shareDialog.setWindowTitle(tr("Option Offer Created"));
            shareDialog.setText(tr("Option contract offer created!\n\nOffer ID: %1\n\n"
                                   "Choose how to share this offer:").arg(offerId));
            shareDialog.setIcon(QMessageBox::Information);

            QPushButton* postWithProofButton = shareDialog.addButton(tr("Publish with Proof"), QMessageBox::AcceptRole);
            postWithProofButton->setStyleSheet("QPushButton { background-color: #2e7d32; color: white; font-weight: bold; }");
            QPushButton* postBBButton = shareDialog.addButton(tr("Publish to Market"), QMessageBox::ActionRole);
            postBBButton->setStyleSheet("QPushButton { background-color: #4caf50; color: white; font-weight: bold; }");
            QPushButton* exportButton = shareDialog.addButton(tr("Export Manually"), QMessageBox::ActionRole);
            shareDialog.addButton(tr("Decide Later"), QMessageBox::RejectRole);

            shareDialog.setDefaultButton(postWithProofButton);
            shareDialog.exec();

            QAbstractButton* clickedButton = shareDialog.clickedButton();

            if (clickedButton == postBBButton || clickedButton == postWithProofButton) {
                // Extract display fields for bulletin board
                QString role = offerData.value("role", "").toString();
                double tenorDaysShort = offerData.value("tenor_days_short", 0).toDouble();

                QString tenorStr = QString::number(static_cast<int>(std::round(tenorDaysShort))) + "d";

                // Leg A / Leg B: delivery assets
                QString legA = "TBD";
                QString legB = "TBD";
                if (offerData.contains("long_deliver_is_native") && offerData["long_deliver_is_native"].toBool()) {
                    legA = "TSC";
                } else if (offerData.contains("long_deliver_asset_id")) {
                    legA = offerData["long_deliver_asset_id"].toString().left(8);
                }
                if (offerData.contains("short_deliver_is_native") && offerData["short_deliver_is_native"].toBool()) {
                    legB = "TSC";
                } else if (offerData.contains("short_deliver_asset_id")) {
                    legB = offerData["short_deliver_asset_id"].toString().left(8);
                }

                // For options, show premium info
                QString marginA = "TBD";
                QString marginB = "Premium";
                if (offerData.contains("premium_units")) {
                    double premium = offerData["premium_units"].toDouble();
                    marginB = QString("Prem: %1").arg(premium, 0, 'f', 4);
                }

                // Auto-generate proof of funds for maker (IM + premium if payer) - only if "Publish with Proof" was clicked
                QVariantList proofs;
                if (clickedButton == postWithProofButton) {
                    try {
                        LogPrintf("[TradeBoardTab] Auto-generating proof of funds for option offer (role=%s)\n", role.toStdString().c_str());

                    // Parse term_sheet_json to get actual amounts
                    QString termSheetJson = offerData.value("term_sheet_json").toString();
                    QJsonDocument termSheetDoc = QJsonDocument::fromJson(termSheetJson.toUtf8());
                    QJsonObject termSheetObj = termSheetDoc.object();
                    QJsonObject terms = termSheetObj.value("terms").toObject();

                    // Determine required asset and amount based on role (long or short)
                    QString assetToProve;
                    uint64_t requiredUnits = 0;
                    QString context = QString("offer:%1:%2").arg(offerId).arg(role);

                    if (role == "long") {
                        // Long party needs to prove: IM + premium if payer
                        bool isNative = terms.value("long_im_is_native").toBool(true);
                        QString assetId = terms.value("long_im_asset_id").toString();

                        int decimals = 8;
                        if (!isNative && !assetId.isEmpty() && walletModel) {
                            assetToProve = assetId;
                            WalletModel::AssetInfo assetInfo = walletModel->getAssetInfo(assetId);
                            if (assetInfo.has_decimals) {
                                decimals = assetInfo.decimals;
                            }
                        }

                        // Both _amount and _units are decimal values (need to multiply by decimals)
                        double imAmount = 0.0;
                        if (terms.contains("long_im_amount")) {
                            imAmount = terms.value("long_im_amount").toDouble();
                        } else if (terms.contains("long_im_units")) {
                            imAmount = terms.value("long_im_units").toDouble();
                        }
                        uint64_t imUnits = static_cast<uint64_t>(imAmount * std::pow(10.0, decimals));

                        // Add premium if long is payer (both _amount and _units are decimal)
                        uint64_t premiumUnits = 0;
                        QString premiumPayer = terms.value("premium_payer").toString();
                        if (premiumPayer.toLower() == "long") {
                            double premiumAmount = 0.0;
                            if (terms.contains("premium_amount")) {
                                premiumAmount = terms.value("premium_amount").toDouble();
                            } else if (terms.contains("premium_units")) {
                                premiumAmount = terms.value("premium_units").toDouble();
                            }
                            premiumUnits = static_cast<uint64_t>(premiumAmount * std::pow(10.0, decimals));
                        }

                        requiredUnits = imUnits + premiumUnits;

                    } else if (role == "short") {
                        // Short party needs to prove: IM + premium if payer
                        bool isNative = terms.value("short_im_is_native").toBool(true);
                        QString assetId = terms.value("short_im_asset_id").toString();

                        int decimals = 8;
                        if (!isNative && !assetId.isEmpty() && walletModel) {
                            assetToProve = assetId;
                            WalletModel::AssetInfo assetInfo = walletModel->getAssetInfo(assetId);
                            if (assetInfo.has_decimals) {
                                decimals = assetInfo.decimals;
                            }
                        }

                        // Both _amount and _units are decimal values (need to multiply by decimals)
                        double imAmount = 0.0;
                        if (terms.contains("short_im_amount")) {
                            imAmount = terms.value("short_im_amount").toDouble();
                        } else if (terms.contains("short_im_units")) {
                            imAmount = terms.value("short_im_units").toDouble();
                        }
                        uint64_t imUnits = static_cast<uint64_t>(imAmount * std::pow(10.0, decimals));

                        // Add premium if short is payer (both _amount and _units are decimal)
                        uint64_t premiumUnits = 0;
                        QString premiumPayer = terms.value("premium_payer").toString();
                        if (premiumPayer.toLower() == "short") {
                            double premiumAmount = 0.0;
                            if (terms.contains("premium_amount")) {
                                premiumAmount = terms.value("premium_amount").toDouble();
                            } else if (terms.contains("premium_units")) {
                                premiumAmount = terms.value("premium_units").toDouble();
                            }
                            premiumUnits = static_cast<uint64_t>(premiumAmount * std::pow(10.0, decimals));
                        }

                        requiredUnits = imUnits + premiumUnits;
                    }

                    LogPrintf("[TradeBoardTab] Option auto-proof: role=%s, requiredUnits=%llu, assetToProve=%s\n",
                             role.toStdString().c_str(), requiredUnits,
                             assetToProve.isEmpty() ? "native" : assetToProve.toStdString().c_str());

                    // Auto-select UTXOs: pick just enough to meet requirement
                    if (requiredUnits > 0 && walletModel) {
                        auto autoProofResult = walletModel->createProofOfFunds(assetToProve, requiredUnits, context);
                        if (autoProofResult.success && !autoProofResult.proofs.isEmpty()) {
                            proofs = autoProofResult.proofs;
                            LogPrintf("[TradeBoardTab] Auto-generated %d proofs covering %llu units\n",
                                     proofs.size(), autoProofResult.total_units);
                        } else {
                            LogPrintf("[TradeBoardTab] Failed to auto-generate proof: %s\n",
                                     autoProofResult.error.toStdString().c_str());
                            QMessageBox::warning(this, tr("Proof Generation Failed"),
                                tr("Could not automatically generate proof of funds:\n\n%1\n\nProceeding without proof.")
                                   .arg(autoProofResult.error));
                        }
                    } else {
                        LogPrintf("[TradeBoardTab] requiredUnits is 0 or walletModel null, skipping proof generation\n");
                    }
                } catch (const UniValue& e) {
                    LogPrintf("[TradeBoardTab] UniValue exception during option auto-proof generation\n");
                    QMessageBox::warning(this, tr("Proof Generation Error"),
                        tr("An RPC error occurred while generating proof of funds.\n\nProceeding without proof."));
                } catch (const std::exception& e) {
                    LogPrintf("[TradeBoardTab] Exception during option auto-proof generation: %s\n", e.what());
                    QMessageBox::warning(this, tr("Proof Generation Error"),
                        tr("An error occurred while generating proof of funds:\n\n%1\n\nProceeding without proof.")
                           .arg(QString::fromStdString(e.what())));
                } catch (...) {
                        LogPrintf("[TradeBoardTab] Unknown exception during option auto-proof generation\n");
                        QMessageBox::warning(this, tr("Proof Generation Error"),
                            tr("An unknown error occurred while generating proof of funds.\n\nProceeding without proof."));
                    }
                }

                LogPrintf("[TradeBoardTab] Posting option offer with %d proofs\n", proofs.size());

                // Calculate tenor in days from offerData
                int tenorDays = static_cast<int>(std::round(tenorDaysShort));
                // Options are posted as "forward" type (with has_premium flag in the term sheet)
                auto result = walletModel->bulletinBoardPostContractOffer("forward", offerJson, role, 0.0, 0.0, tenorDays, proofs);

                if (result.success) {
                    // FIX: Link bulletin-board UUID to contract ID in cache (dual-key mapping)
                    cacheContractFlavor(offerId, "option", offerJson, result.offer_id);
                    LogPrintf("TradeBoardTab: Post-publication cache link - contract_id=%s, bb_uuid=%s, type=option\n",
                              offerId.toStdString().c_str(), result.offer_id.toStdString().c_str());

                    // Store transport preference for this offer
                    QString transport = wizard.getTransport();
                    offerTransportPreferences[result.offer_id] = transport;
                    LogPrintf("TradeBoardTab: Stored transport preference for offer %s: %s\n",
                             result.offer_id.toStdString().c_str(), transport.toStdString().c_str());

                    showAutoClosingInfo(tr("Posted to Bulletin Board"),
                        tr("Option offer posted to bulletin board!\n\nOffer ID: %1").arg(result.offer_id));
                    updateOffersList();
                } else {
                    QMessageBox::critical(this, tr("Bulletin Board Error"),
                        tr("Failed to post offer:\n%1").arg(result.error));
                }
            } else if (clickedButton == exportButton) {
                // Export offer JSON - choice between file or clipboard
                QMessageBox exportChoice(TopLevelDialogParent(this));
                exportChoice.setWindowTitle(tr("Export Offer"));
                exportChoice.setText(tr("How would you like to export the offer?"));
                exportChoice.setIcon(QMessageBox::Question);

                QPushButton* saveFileBtn = exportChoice.addButton(tr("Save to File"), QMessageBox::AcceptRole);
                QPushButton* copyClipboardBtn = exportChoice.addButton(tr("Copy to Clipboard"), QMessageBox::ActionRole);
                exportChoice.addButton(QMessageBox::Cancel);

                exportChoice.exec();
                QAbstractButton* exportChoice_clicked = exportChoice.clickedButton();

                if (exportChoice_clicked == saveFileBtn) {
                    QString fileName = QFileDialog::getSaveFileName(this, tr("Save Offer JSON"),
                        QString("option_offer_%1.json").arg(offerId),
                        tr("JSON Files (*.json);;All Files (*)"));

                    if (!fileName.isEmpty()) {
                        QFile file(fileName);
                        if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
                            file.write(offerJson.toUtf8());
                            file.close();
                            showAutoClosingInfo(tr("Export Successful"),
                                tr("Offer exported to:\n%1").arg(fileName));
                        } else {
                            QMessageBox::warning(this, tr("Export Failed"),
                                tr("Failed to write file:\n%1").arg(fileName));
                        }
                    }
                } else if (exportChoice_clicked == copyClipboardBtn) {
                    QApplication::clipboard()->setText(offerJson);
                    showAutoClosingInfo(tr("Copied to Clipboard"),
                        tr("Option offer JSON copied to clipboard.\n\nOffer ID: %1").arg(offerId));
                }
            }
        }
    } else if (currentContractType == "spot") {
        // Launch Spot Contract Builder wizard
        SpotContractBuilder wizard(walletModel, this);

        if (wizard.exec() == QDialog::Accepted) {
            QString offerId = wizard.getOfferId();
            QVariantMap offerData = wizard.getOfferData();
            QString offerJson = wizard.getOfferJson();

            // CACHE POPULATION: Wizard propose success - populate canonical cache
            cacheContractFlavor(offerId, "spot", offerJson);
            LogPrintf("TradeBoardTab: Cached contract flavor at wizard propose - offer_id=%s, type=spot\n",
                      offerId.toStdString().c_str());

            // Create share dialog
            QMessageBox shareDialog(TopLevelDialogParent(this));
            shareDialog.setWindowTitle(tr("Spot Swap Offer Created"));
            shareDialog.setText(tr("Spot atomic swap offer created!\n\nOffer ID: %1\n\n"
                                   "Choose how to share this offer:").arg(offerId));
            shareDialog.setIcon(QMessageBox::Information);

            QPushButton* postWithProofButton = shareDialog.addButton(tr("Publish with Proof"), QMessageBox::AcceptRole);
            postWithProofButton->setStyleSheet("QPushButton { background-color: #2e7d32; color: white; font-weight: bold; }");
            QPushButton* postBBButton = shareDialog.addButton(tr("Publish to Market"), QMessageBox::ActionRole);
            postBBButton->setStyleSheet("QPushButton { background-color: #4caf50; color: white; font-weight: bold; }");
            QPushButton* exportButton = shareDialog.addButton(tr("Export Manually"), QMessageBox::ActionRole);
            shareDialog.addButton(tr("Decide Later"), QMessageBox::RejectRole);

            shareDialog.setDefaultButton(postWithProofButton);
            shareDialog.exec();

            QAbstractButton* clickedButton = shareDialog.clickedButton();

            if (clickedButton == postWithProofButton || clickedButton == postBBButton) {
                // Post to bulletin board, optionally with proof of funds for alice_leg
                QString termSheetJson = offerData.value("term_sheet_json").toString();
                QString makerRole = "alice";  // Spot maker is always alice
                double exchangeRate = offerData.value("exchange_rate", 0.0).toDouble();

                QVariantList proofs;
                if (clickedButton == postWithProofButton) {
                    // Generate proof of funds for alice_leg (what Alice sends)
                    try {
                        QJsonDocument termSheetDoc = QJsonDocument::fromJson(termSheetJson.toUtf8());
                        if (termSheetDoc.isObject()) {
                            QJsonObject termSheet = termSheetDoc.object();
                            QJsonObject terms = termSheet.value("terms").toObject();
                            QJsonObject aliceLeg = terms.value("alice_leg").toObject();

                            bool isNative = aliceLeg.value("is_native").toBool(true);
                            QString assetId = aliceLeg.value("asset_id").toString();
                            int64_t requiredUnits = static_cast<int64_t>(aliceLeg.value("units").toDouble());

                            QString assetToProve = isNative ? QString() : assetId;
                            QString context = QString("spot_propose_%1").arg(offerId);

                            LogPrintf("[TradeBoardTab] Spot offer: Alice needs to prove %lld units of %s\n",
                                      requiredUnits, assetToProve.isEmpty() ? "native" : assetToProve.toStdString().c_str());

                            if (requiredUnits > 0 && walletModel) {
                                auto autoProofResult = walletModel->createProofOfFunds(assetToProve, requiredUnits, context);
                                if (autoProofResult.success && !autoProofResult.proofs.isEmpty()) {
                                    proofs = autoProofResult.proofs;
                                    LogPrintf("[TradeBoardTab] Auto-generated %d proofs covering %llu units for spot offer\n",
                                              proofs.size(), autoProofResult.total_units);
                                } else {
                                    LogPrintf("[TradeBoardTab] Failed to auto-generate spot proof: %s\n",
                                              autoProofResult.error.toStdString().c_str());
                                    QMessageBox::warning(this, tr("Proof Generation Failed"),
                                        tr("Could not automatically generate proof of funds:\n\n%1\n\nProceeding without proof.")
                                           .arg(autoProofResult.error));
                                }
                            }
                        }
                    } catch (const std::exception& e) {
                        LogPrintf("[TradeBoardTab] Exception during spot proof generation: %s\n", e.what());
                        QMessageBox::warning(this, tr("Proof Generation Error"),
                            tr("An error occurred while generating proof of funds:\n\n%1\n\nProceeding without proof.")
                               .arg(QString::fromStdString(e.what())));
                    } catch (...) {
                        LogPrintf("[TradeBoardTab] Unknown exception during spot proof generation\n");
                        QMessageBox::warning(this, tr("Proof Generation Error"),
                            tr("An unknown error occurred while generating proof of funds.\n\nProceeding without proof."));
                    }
                }

                LogPrintf("[TradeBoardTab] Posting spot offer with %d proofs\n", proofs.size());

                auto result = walletModel->bulletinBoardPostContractOffer("spot", termSheetJson, makerRole, exchangeRate, 0.0, 0, proofs);

                if (result.success) {
                    // Store transport preference for this offer
                    QString transport = wizard.getTransport();
                    offerTransportPreferences[result.offer_id] = transport;
                    LogPrintf("TradeBoardTab: Stored transport preference for offer %s: %s\n",
                             result.offer_id.toStdString().c_str(), transport.toStdString().c_str());

                    showAutoClosingInfo(tr("Posted to Bulletin Board"),
                        tr("Spot swap offer posted to bulletin board!\n\nOffer ID: %1\n\n"
                           "Takers can now review and accept your atomic swap offer.").arg(result.offer_id));
                    updateOffersList();
                } else {
                    QMessageBox::critical(this, tr("Bulletin Board Error"),
                        tr("Failed to post spot offer:\n%1").arg(result.error));
                }
            } else if (clickedButton == exportButton) {
                // Export offer JSON - choice between file or clipboard
                QMessageBox exportChoice(TopLevelDialogParent(this));
                exportChoice.setWindowTitle(tr("Export Spot Offer"));
                exportChoice.setText(tr("How would you like to export the spot offer?"));
                exportChoice.setIcon(QMessageBox::Question);

                QPushButton* saveFileBtn = exportChoice.addButton(tr("Save to File"), QMessageBox::AcceptRole);
                QPushButton* copyClipboardBtn = exportChoice.addButton(tr("Copy to Clipboard"), QMessageBox::ActionRole);
                exportChoice.addButton(QMessageBox::Cancel);

                exportChoice.exec();
                QAbstractButton* exportChoice_clicked = exportChoice.clickedButton();

                if (exportChoice_clicked == saveFileBtn) {
                    QString fileName = QFileDialog::getSaveFileName(this, tr("Save Spot Offer JSON"),
                        QString("spot_offer_%1.json").arg(offerId),
                        tr("JSON Files (*.json);;All Files (*)"));

                    if (!fileName.isEmpty()) {
                        QFile file(fileName);
                        if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
                            file.write(offerJson.toUtf8());
                            file.close();
                            showAutoClosingInfo(tr("Export Successful"),
                                tr("Spot offer exported to:\n%1").arg(fileName));
                        } else {
                            QMessageBox::warning(this, tr("Export Failed"),
                                tr("Failed to write file:\n%1").arg(fileName));
                        }
                    }
                } else if (exportChoice_clicked == copyClipboardBtn) {
                    QApplication::clipboard()->setText(offerJson);
                    showAutoClosingInfo(tr("Copied to Clipboard"),
                        tr("Spot offer JSON copied to clipboard.\n\nOffer ID: %1").arg(offerId));
                }
            }
        }
    } else if (currentContractType == "difficulty") {
        // Launch Difficulty Derivative Builder wizard (CFD / option on mining difficulty).
        DifficultyContractBuilder wizard(walletModel, this);

        // TIMER SAFETY: Pause background updates during modal dialog. The blocking
        // updateOffersList() poll otherwise fires into the wizard's nested event loop
        // and rebuilds the offer tables underneath a half-shown QComboBox popup, which
        // tears the popup's backing QWindow out from under QComboBox::showPopup()
        // (SIGSEGV in QWindow::geometry()) and stalls the GUI on every relay round-trip.
        pauseUpdateTimers();
        const int wizardResult = wizard.exec();
        resumeUpdateTimers();

        if (wizardResult == QDialog::Accepted) {
            const QString termSheetJson = wizard.getTermSheetJson();
            if (termSheetJson.isEmpty()) {
                QMessageBox::warning(this, tr("Offer Not Created"),
                    tr("The difficulty offer could not be finalized."));
                return;
            }

            // Pull maker role + fixing height + kind out of the self-contained term sheet
            // for posting metadata and the share-dialog wording.
            QString makerRole;
            QString contractKind;
            int fixingHeight = 0;
            bool hasEmbeddedOffer = false;
            QString tsSchema;
            QString embeddedKind;
            QString embeddedRole;
            {
                const QJsonDocument tsDoc = QJsonDocument::fromJson(termSheetJson.toUtf8());
                if (tsDoc.isObject()) {
                    const QJsonObject ts = tsDoc.object();
                    tsSchema = ts.value("schema").toString();
                    makerRole = ts.value("maker_role").toString();
                    contractKind = ts.value("kind").toString();
                    fixingHeight = ts.value("terms").toObject().value("fixing_height").toInt();
                    hasEmbeddedOffer = ts.value("offer").isObject();
                    if (hasEmbeddedOffer) {
                        const QJsonObject off = ts.value("offer").toObject();
                        embeddedKind = off.value("kind").toString();
                        embeddedRole = off.value("proposer_role").toString();
                    }
                }
            }

            // Hard-validate before the offer can leave this node: cosign.post_contract_offer passes
            // arbitrary contract types straight to the relay, so the GUI is the only gate. The outer
            // advertised kind/role must also match the embedded signed offer (the bytes a taker will
            // accept) so we never publish a term sheet that misrepresents what's signed.
            const bool validRole = (contractKind == QLatin1String("option"))
                ? (makerRole == QLatin1String("writer") || makerRole == QLatin1String("buyer"))
                : (makerRole == QLatin1String("long") || makerRole == QLatin1String("short"));
            const bool embeddedMatches = hasEmbeddedOffer &&
                embeddedKind == contractKind && embeddedRole == makerRole;
            if (tsSchema != QLatin1String("difficulty_term_sheet_v1") ||
                (contractKind != QLatin1String("cfd") && contractKind != QLatin1String("option")) ||
                !validRole || !embeddedMatches) {
                QMessageBox::critical(this, tr("Invalid Term Sheet"),
                    tr("This difficulty term sheet failed validation and will not be published.\n\n"
                       "Expected schema difficulty_term_sheet_v1, a valid kind (cfd/option), a maker "
                       "role matching the kind, and an embedded signed offer whose kind/role match the "
                       "advertised terms."));
                return;
            }

            // Tenor is informational metadata for the board: blocks-to-fixing at ~144/day.
            int tenorDays = 0;
            if (fixingHeight > 0) {
                const int currentHeight = walletModel->clientModel().node().getNumBlocks();
                if (fixingHeight > currentHeight) {
                    tenorDays = (fixingHeight - currentHeight) / 144;
                }
            }

            // CACHE POPULATION: record this flavor so downstream lookups resolve it.
            const QString offerId = wizard.getOfferId();
            if (!offerId.isEmpty()) {
                cacheContractFlavor(offerId, "difficulty", termSheetJson);
            }

            QMessageBox shareDialog(TopLevelDialogParent(this));
            shareDialog.setWindowTitle(tr("Difficulty Offer Created"));
            shareDialog.setText(tr("Difficulty %1 term sheet created!\n\n"
                                   "Choose how to share this offer:")
                                   .arg(contractKind == QLatin1String("option") ? tr("option") : tr("CFD")));
            shareDialog.setIcon(QMessageBox::Information);

            QPushButton* postBBButton = shareDialog.addButton(tr("Publish to Market"), QMessageBox::AcceptRole);
            postBBButton->setStyleSheet("QPushButton { background-color: #7E57C2; color: white; font-weight: bold; }");
            QPushButton* copyButton = shareDialog.addButton(tr("Copy Term Sheet"), QMessageBox::ActionRole);
            shareDialog.addButton(tr("Decide Later"), QMessageBox::RejectRole);
            shareDialog.setDefaultButton(postBBButton);
            shareDialog.exec();

            QAbstractButton* clickedButton = shareDialog.clickedButton();
            if (clickedButton == postBBButton) {
                WalletModel::BulletinBoardPostOfferResult result =
                    walletModel->bulletinBoardPostContractOffer(
                        "difficulty", termSheetJson, makerRole,
                        /*apr=*/0.0, /*ltv=*/0.0, tenorDays, /*proof_of_funds=*/{});
                if (result.success) {
                    showAutoClosingInfo(tr("Posted to Bulletin Board"),
                        tr("Difficulty offer posted to the market!\n\nOffer ID: %1").arg(result.offer_id));
                    updateOffersList();
                } else {
                    QMessageBox::critical(this, tr("Bulletin Board Error"),
                        tr("Failed to post offer:\n%1").arg(result.error));
                }
            } else if (clickedButton == copyButton) {
                QApplication::clipboard()->setText(termSheetJson);
                showAutoClosingInfo(tr("Copied to Clipboard"),
                    tr("Difficulty term sheet copied to clipboard."));
            }
        }
    } else if (currentContractType == "cross_chain") {
        // Launch Cross-Chain Contract Builder wizard
        CrossChainContractBuilder wizard(walletModel, this);

        if (wizard.exec() == QDialog::Accepted) {
            QString offerId = wizard.getOfferId();

            showAutoClosingInfo(tr("Cross-Chain Offer Created"),
                tr("Cross-chain settlement offer published!\n\nOffer ID: %1\n\n"
                   "The offer is now visible on the bulletin board as a SpotContract payload.\n"
                   "Takers can review and accept through the Cross-Chain tab.").arg(offerId));
            updateOffersList();
        }
    }
}

void TradeBoardTab::updateBulletinBoardStatus()
{
    if (!walletModel) return;

    // Check if bulletin board is initialized by attempting to list offers
    auto result = walletModel->bulletinBoardListOffers("", "", 0);

    if (result.success) {
        // Only log state change to avoid spam
        if (!bbInitialized) {
            LogPrintf("TradeBoardTab::updateBulletinBoardStatus() Bulletin board now INITIALIZED\n");
        }
        bbInitialized = true;
        bbStatusLabel->setText(tr("● Connected"));
        bbStatusLabel->setStyleSheet("QLabel { color: #388e3c; font-weight: bold; }");

        // Display pubkey (shortened)
        if (!bbPubkey.isEmpty()) {
            bbPubkeyLabel->setText(tr("Pubkey: %1").arg(bbPubkey));
        } else {
            bbPubkeyLabel->setText(tr("Pubkey: Initialized"));
        }

        bbRelaysLabel->setText(tr("Relays: %1").arg(bbRelayCount));
    } else {
        // Log detailed error when status check fails
        if (bbInitialized) {
            LogPrintf("TradeBoardTab::updateBulletinBoardStatus() ERROR: Bulletin board became UNINITIALIZED! Error: %s\n",
                      result.error.toStdString().c_str());
        }
        bbInitialized = false;
        bbStatusLabel->setText(tr("● Error"));
        bbStatusLabel->setStyleSheet("QLabel { color: #f57c00; font-weight: bold; }");  // Orange for error state
        bbPubkeyLabel->setText(tr("Pubkey: Error"));
        bbRelaysLabel->setText(tr("Status: %1").arg(result.error.left(40)));  // Show error in status
    }
}

void TradeBoardTab::updateTorStatus()
{
    TorManager* tor = TorManager::instance();

    switch (tor->status()) {
        case TorManager::Status::NotStarted:
            torStatusLabel->setText(tr("● Tor: Not Started"));
            torStatusLabel->setStyleSheet("QLabel { color: #666; font-weight: bold; }");
            torStatusLabel->setToolTip(tr("Tor daemon has not been initialized"));
            break;
        case TorManager::Status::Starting:
            torStatusLabel->setText(tr("● Tor: Starting..."));
            torStatusLabel->setStyleSheet("QLabel { color: #1976d2; font-weight: bold; }");
            torStatusLabel->setToolTip(tr("Tor daemon is starting (may take 10-30 seconds)"));
            break;
        case TorManager::Status::Ready:
            torStatusLabel->setText(tr("● Tor: Ready"));
            torStatusLabel->setStyleSheet("QLabel { color: #388e3c; font-weight: bold; }");
            torStatusLabel->setToolTip(tr("Tor daemon is ready for private cosign sessions\nSOCKS: %1").arg(tor->socksAddress()));
            break;
        case TorManager::Status::Failed:
            torStatusLabel->setText(tr("● Tor: Failed"));
            torStatusLabel->setStyleSheet("QLabel { color: #d32f2f; font-weight: bold; }");
            torStatusLabel->setToolTip(tr("Tor daemon failed to start: %1").arg(tor->lastError()));
            break;
        case TorManager::Status::Stopped:
            torStatusLabel->setText(tr("● Tor: Stopped"));
            torStatusLabel->setStyleSheet("QLabel { color: #f57c00; font-weight: bold; }");
            torStatusLabel->setToolTip(tr("Tor daemon was stopped"));
            break;
    }

    LogPrintf("TradeBoardTab::updateTorStatus() Status: %s\n",
             tor->statusString().toStdString());
}

void TradeBoardTab::updateOffersList()
{
    // Thin wrapper so this stays a 0-arg slot (connected to QTimer::timeout and
    // called from ~25 sites). The force-refresh button routes through the same
    // async path via dispatchOffersFetch(true).
    dispatchOffersFetch(/*force_refresh=*/false);
}

void TradeBoardTab::dispatchOffersFetch(bool force_refresh)
{
    // NOTE: do NOT gate this on isVisible(). Offer freshness drives
    // trade-request decisions and must run regardless of which tab is shown.
    // Repaint work below is cheap on a hidden widget.
    if (!walletModel) {
        LogPrintf("TradeBoardTab::dispatchOffersFetch() ERROR: walletModel is null\n");
        return;
    }
    if (!bbInitialized) {
        LogPrintf("TradeBoardTab::dispatchOffersFetch() WARNING: BB not initialized, skipping update\n");
        return;
    }

    // Coalesce concurrent calls: if a fetch is already in flight, record that
    // another refresh is wanted and return. The in-flight continuation re-dispatches
    // so a caller that just mutated state (cancel/accept/create, etc.) never loses
    // its refresh. Mirrors updateTradeRequestsList(). GUI-thread-only flags.
    if (m_offersUpdateInFlight) {
        m_offersUpdatePending = true;
        // Latch force intent across coalesced calls: a force-refresh click that
        // lands mid-fetch must NOT silently degrade into a cached refresh when the
        // continuation re-dispatches. Force wins — it is a superset (clears the
        // backend cache + re-fetches from relays).
        if (force_refresh) m_offersUpdatePendingForceRefresh = true;
        return;
    }
    m_offersUpdateInFlight = true;

    LogPrintf("TradeBoardTab::dispatchOffersFetch() Calling RPC off-thread (force_refresh=%d)...\n", force_refresh);
    // bulletinBoardListOffers() goes through the cosign bridge -> Nostr relays and
    // blocks in poll() until the relay answers — that is the GUI-thread stall that
    // shows up as the macOS rainbow spinner. With force_refresh it also clears the
    // backend cache first, so it is even slower and MUST NOT run on the GUI thread.
    // Run it on a worker (touches only walletModel, which is bridge-mutex-serialized
    // / thread-safe; never `this`). InflightGuard + parented QFutureWatcher give the
    // same shutdown safety as the poll path. Rendered on the GUI thread in renderOffers().
    auto inflightGuard = std::make_shared<InflightGuard>(this);
    WalletModel* const wm = walletModel;
    auto* watcher = new QFutureWatcher<WalletModel::BulletinBoardListOffersResult>(this);
    connect(watcher, &QFutureWatcher<WalletModel::BulletinBoardListOffersResult>::finished, this, [this, watcher, force_refresh]() {
        watcher->deleteLater();
        const WalletModel::BulletinBoardListOffersResult result = watcher->result();
        renderOffers(result);
        // A user-initiated force refresh surfaces relay failures to the user (this
        // restores the pre-async QMessageBox on the force-refresh click path).
        // Background/auto refreshes stay silent — renderOffers() only logs failures
        // — so the timer cadence never spams dialogs.
        if (force_refresh && !result.success) {
            LogPrintf("TradeBoardTab::dispatchOffersFetch() force refresh FAILED: %s\n",
                      result.error.toStdString().c_str());
            QMessageBox::warning(this, tr("Refresh Failed"),
                tr("Failed to refresh from Nostr relays: %1").arg(result.error));
        }
        m_offersUpdateInFlight = false;
        if (m_offersUpdatePending) {
            m_offersUpdatePending = false;
            const bool pendingForce = m_offersUpdatePendingForceRefresh;
            m_offersUpdatePendingForceRefresh = false;
            // Re-dispatch directly (not via updateOffersList()) so a coalesced force
            // refresh keeps its force semantics.
            dispatchOffersFetch(pendingForce);
        }
    });
    watcher->setFuture(QtConcurrent::run([wm, inflightGuard, force_refresh]() -> WalletModel::BulletinBoardListOffersResult {
        (void)inflightGuard;  // keeps the guard alive for the duration of the body
        return wm->bulletinBoardListOffers("", "", 0, force_refresh);
    }));
}

// GUI-thread render half of updateOffersList(): rebuilds the offer tables from the
// off-thread fetch result. `result` is taken by value so the QtConcurrent result is
// safely owned here. All work below touches widgets and must stay on the GUI thread.
void TradeBoardTab::renderOffers(WalletModel::BulletinBoardListOffersResult result)
{
    // Belt-and-suspenders alongside pauseUpdateTimers(): never rebuild the offer
    // tables while a modal dialog/wizard is open. A fetch already in flight when a
    // modal opened can deliver its QFutureWatcher::finished into the modal's nested
    // event loop; tearing table widgets down underneath a live QComboBox popup
    // crashes QComboBox::showPopup() on macOS (SIGSEGV in QWindow::geometry()).
    // Drop this render — the post-modal refresh (action path / next timer tick)
    // re-fetches from the still-warm BB cache and renders cleanly.
    if (QApplication::activeModalWidget() != nullptr) {
        LogPrintf("TradeBoardTab::renderOffers() deferred: modal widget active\n");
        // Remember that a completed fetch was dropped so resumeUpdateTimers() can
        // re-render once the modal closes, instead of leaving the tables stale
        // until the next periodic tick.
        m_offersRenderDeferredByModal = true;
        return;
    }

    if (!result.success) {
        // Don't show error on auto-refresh, just log
        LogPrintf("TradeBoardTab::updateOffersList() RPC FAILED: %s\n", result.error.toStdString().c_str());
        return;
    }

    LogPrintf("TradeBoardTab::updateOffersList() RPC SUCCESS\n");

    // We are committing to a real, non-modal render: the tables are about to be
    // rebuilt fresh, so any earlier modal-drop staleness is resolved here. Clearing
    // unconditionally (not just on the resumeUpdateTimers path) covers modals that
    // are not bracketed by pause/resume, avoiding a stale flag that would trigger a
    // redundant future refresh.
    m_offersRenderDeferredByModal = false;

    // Update cache timestamp on successful fetch
    lastCacheRefresh = QDateTime::currentDateTime();

    // Disable sorting while updating to prevent data corruption
    bool repoSorting = repoTable->isSortingEnabled();
    bool forwardSorting = forwardTable->isSortingEnabled();
    bool optionsSorting = optionsTable->isSortingEnabled();
    bool spotSorting = spotTable->isSortingEnabled();
    bool crossChainSorting = crossChainTable->isSortingEnabled();
    bool difficultySorting = difficultyTable->isSortingEnabled();

    repoTable->setSortingEnabled(false);
    forwardTable->setSortingEnabled(false);
    optionsTable->setSortingEnabled(false);
    spotTable->setSortingEnabled(false);
    crossChainTable->setSortingEnabled(false);
    difficultyTable->setSortingEnabled(false);

    // Clear existing offers from all tables
    repoTable->setRowCount(0);
    forwardTable->setRowCount(0);
    optionsTable->setRowCount(0);
    spotTable->setRowCount(0);
    crossChainTable->setRowCount(0);
    difficultyTable->setRowCount(0);
    activeOffers.clear();

    // Determine which table to populate based on current contract type
    QTableWidget* targetTable = nullptr;
    if (currentContractType == "repo") {
        targetTable = repoTable;
    } else if (currentContractType == "forward") {
        targetTable = forwardTable;
    } else if (currentContractType == "options") {
        targetTable = optionsTable;
    } else if (currentContractType == "spot") {
        targetTable = spotTable;
    } else if (currentContractType == "difficulty") {
        targetTable = difficultyTable;
    } else if (currentContractType == "cross_chain") {
        targetTable = crossChainTable;
    } else {
        targetTable = repoTable;  // Default
    }

    // Populate table
    LogPrintf("TradeBoardTab::updateOffersList() Processing %d offers for contract type: %s\n",
              result.offers.size(), currentContractType.toStdString().c_str());
    for (const QVariant& offerVar : result.offers) {
        QVariantMap offer = offerVar.toMap();

        // DEBUG: Print all keys in the map
        LogPrintf("TradeBoardTab::updateOffersList() Offer has %d keys:\n", offer.size());
        for (auto it = offer.begin(); it != offer.end(); ++it) {
            LogPrintf("  Key: '%s' = '%s'\n",
                it.key().toStdString().c_str(),
                it.value().toString().toStdString().c_str());
        }

        OfferInfo info;
        // NOTE: WalletModel converts field names:
        //   "id" -> "offer_id"
        //   "price" -> "price_btc"
        //   "amount" -> QString (not double)
        info.offer_id = offer["offer_id"].toString();
        info.maker_pubkey = offer["maker_pubkey"].toString();
        info.offer_type = offer["offer_type"].toString();
        info.asset_send = offer["asset_send"].toString();
        info.asset_recv = offer["asset_recv"].toString();
        info.amount = offer["amount"].toString().toDouble();
        info.price = offer["price_btc"].toString().toDouble();
        info.created_at = offer["created_at"].toLongLong();
        info.expires_at = offer["expires_at"].toLongLong();
        info.state = offer["state"].toString();

        // Parse contract-specific fields
        info.contract_type = offer["contract_type"].toString();
        info.maker_role = offer["maker_role"].toString();
        // APR, LTV, and tenor_days will be computed from immutable params, not trusted from JSON

        // Parse proof of funds
        if (offer.contains("proof_of_funds") && offer["proof_of_funds"].canConvert<QVariantList>()) {
            info.proof_of_funds = offer["proof_of_funds"].toList();

            // Verify proofs on ingestion
            if (!info.proof_of_funds.isEmpty()) {
                try {
                    auto verifyResult = walletModel->verifyProofList(info.proof_of_funds);
                    info.proof_verified = verifyResult.all_verified;
                    info.proof_verified_units = verifyResult.total_verified_units;
                    info.proof_verified_asset = verifyResult.asset_id;
                    info.proof_verification_error = verifyResult.error;
                    info.proof_verified_at = QDateTime::currentSecsSinceEpoch();

                    LogPrintf("TradeBoardTab::updateOffersList() Offer %s: verified=%d, units=%lu, asset='%s', error='%s'\n",
                        info.offer_id.toStdString().c_str(),
                        info.proof_verified,
                        info.proof_verified_units,
                        info.proof_verified_asset.toStdString().c_str(),
                        info.proof_verification_error.toStdString().c_str());

                    if (!verifyResult.all_verified) {
                        LogPrintf("TradeBoardTab::updateOffersList() Proof verification FAILED for offer %s: %s\n",
                            info.offer_id.toStdString().c_str(),
                            verifyResult.error.toStdString().c_str());
                    }
                } catch (const UniValue& e) {
                    LogPrintf("TradeBoardTab::updateOffersList() UniValue exception during proof verification for offer %s\n",
                        info.offer_id.toStdString().c_str());
                    info.proof_verified = false;
                    info.proof_verification_error = "Verification error: UniValue exception";
                } catch (const std::exception& e) {
                    LogPrintf("TradeBoardTab::updateOffersList() Exception during proof verification for offer %s: %s\n",
                        info.offer_id.toStdString().c_str(), e.what());
                    info.proof_verified = false;
                    info.proof_verification_error = QString("Verification error: %1").arg(e.what());
                } catch (...) {
                    LogPrintf("TradeBoardTab::updateOffersList() Unknown exception during proof verification for offer %s\n",
                        info.offer_id.toStdString().c_str());
                    info.proof_verified = false;
                    info.proof_verification_error = "Unknown verification error";
                }
            }
        }

        // Parse contract_payload JSON (term sheet or finalized contract)
        QString contractPayload = offer["contract_payload"].toString();
        info.contract_payload = contractPayload;  // Store for dialogs
        info.is_term_sheet = false;
        info.term_sheet_json.clear();
        info.term_sheet_terms.clear();
        info.term_sheet_metrics.clear();

        if (!contractPayload.isEmpty() && walletModel) {
            QJsonParseError parseError;
            QJsonDocument payloadDoc = QJsonDocument::fromJson(contractPayload.toUtf8(), &parseError);
            if (!payloadDoc.isNull() && payloadDoc.isObject()) {
                QJsonObject payloadObj = payloadDoc.object();

                // Extract contract ID from finalized payload for later cache population
                QString payloadContractId = payloadObj.value("id").toString();

                const QString schema = payloadObj.value("schema").toString();

                auto variantToBool = [](const QVariant& value, bool fallback) {
                    if (!value.isValid()) {
                        return fallback;
                    }
                    switch (static_cast<QMetaType::Type>(value.typeId())) {
                    case QMetaType::Bool:
                        return value.toBool();
                    case QMetaType::Int:
                    case QMetaType::LongLong:
                        return value.toInt() != 0;
                    case QMetaType::QString: {
                        const QString str = value.toString().trimmed().toLower();
                        if (str == QLatin1String("true") || str == QLatin1String("1") || str == QLatin1String("yes")) {
                            return true;
                        }
                        if (str == QLatin1String("false") || str == QLatin1String("0") || str == QLatin1String("no")) {
                            return false;
                        }
                        return fallback;
                    }
                    default:
                        break;
                    }
                    return value.toBool();
                };

                auto resolveAssetLabel = [&](const QString& assetId, const QString& fallbackLabel) -> QString {
                    if (!walletModel) {
                        return fallbackLabel;
                    }
                    WalletModel::AssetInfo assetInfo = walletModel->getAssetInfo(assetId);
                    if (!assetInfo.ticker.isEmpty()) {
                        return assetInfo.ticker;
                    }
                    if (!assetId.isEmpty()) {
                        return assetId.left(8) + "...";
                    }
                    return fallbackLabel;
                };

                auto populateFromFlatTerms = [&](const QJsonObject& flatTerms) {
                    const bool collateral_is_native = variantToBool(flatTerms.value("collateral_is_native").toVariant(), true);
                    const bool principal_is_native = variantToBool(flatTerms.value("principal_is_native").toVariant(), true);
                    const bool interest_is_native = variantToBool(flatTerms.value("interest_is_native").toVariant(), principal_is_native);
                    const QString collateral_asset_id = flatTerms.value("collateral_asset_id").toString();
                    const QString principal_asset_id = flatTerms.value("principal_asset_id").toString();
                    const QString interest_asset_id = flatTerms.value("interest_asset_id").toString().isEmpty()
                                                       ? principal_asset_id
                                                       : flatTerms.value("interest_asset_id").toString();

                    info.collateral_qty = flatTerms.value("collateral_amount").toDouble(info.collateral_qty);
                    info.principal_qty = flatTerms.value("principal_amount").toDouble(info.principal_qty);
                    info.interest_qty = flatTerms.value("interest_amount").toDouble(info.interest_qty);

                    // Store asset IDs (empty for native)
                    info.collateral_asset_id = collateral_is_native ? QString() : collateral_asset_id;
                    info.principal_asset_id = principal_is_native ? QString() : principal_asset_id;
                    info.interest_asset_id = interest_is_native ? QString() : interest_asset_id;

                    info.collateral_asset = collateral_is_native ? QStringLiteral("TSC")
                                                                 : resolveAssetLabel(collateral_asset_id, tr("ASSET"));
                    info.principal_asset = principal_is_native ? QStringLiteral("TSC")
                                                               : resolveAssetLabel(principal_asset_id, tr("ASSET"));
                    info.interest_asset = interest_is_native ? QStringLiteral("TSC")
                                                              : resolveAssetLabel(interest_asset_id, tr("ASSET"));
                };

                if (schema == QLatin1String("repo_term_sheet_v1")) {
                    info.is_term_sheet = true;
                    info.term_sheet_json = contractPayload;
                    info.term_sheet_terms = payloadObj.value("terms").toObject().toVariantMap();
                    info.term_sheet_metrics = payloadObj.value("metrics").toObject().toVariantMap();
                    if (payloadObj.contains("maker_role")) {
                        info.maker_role = payloadObj.value("maker_role").toString();
                    }

                    // Populate human-friendly values
                    const QVariantMap& terms = info.term_sheet_terms;
                    const bool collateral_is_native = variantToBool(terms.value("collateral_is_native"), true);
                    const bool principal_is_native = variantToBool(terms.value("principal_is_native"), true);
                    const bool interest_is_native = variantToBool(terms.value("interest_is_native"), principal_is_native);
                    const QString collateral_asset_id = terms.value("collateral_asset_id").toString();
                    const QString principal_asset_id = terms.value("principal_asset_id").toString();
                    const QString interest_asset_id = terms.value("interest_asset_id").toString().isEmpty()
                                                    ? principal_asset_id
                                                    : terms.value("interest_asset_id").toString();

                    info.collateral_qty = terms.value("collateral_amount").toDouble();
                    info.principal_qty = terms.value("principal_amount").toDouble();
                    info.interest_qty = terms.value("interest_amount").toDouble();

                    // Store asset IDs (empty for native)
                    info.collateral_asset_id = collateral_is_native ? QString() : collateral_asset_id;
                    info.principal_asset_id = principal_is_native ? QString() : principal_asset_id;
                    info.interest_asset_id = interest_is_native ? QString() : interest_asset_id;

                    info.collateral_asset = collateral_is_native ? QStringLiteral("TSC")
                                                                 : resolveAssetLabel(collateral_asset_id, tr("ASSET"));
                    info.principal_asset = principal_is_native ? QStringLiteral("TSC")
                                                               : resolveAssetLabel(principal_asset_id, tr("ASSET"));
                    info.interest_asset = interest_is_native ? QStringLiteral("TSC")
                                                              : resolveAssetLabel(interest_asset_id, tr("ASSET"));

                    // Compute metrics from immutable blockchain parameters (never trust cached JSON)
                    int maturity_height = terms.value("maturity_height").toInt();
                    if (maturity_height == 0 && info.term_sheet_metrics.contains("tenor_days")) {
                        // Fallback: estimate from tenor_days if maturity_height missing (legacy term sheets)
                        int current_height = walletModel->clientModel().node().getNumBlocks();
                        int estimated_days = info.term_sheet_metrics.value("tenor_days").toInt();
                        maturity_height = current_height + (estimated_days * 144);
                        LogPrintf("TradeBoardTab: WARNING - maturity_height missing for term sheet %s, estimated %d from tenor_days\n",
                                 info.offer_id.toStdString().c_str(), maturity_height);
                    }
                    auto computed = computeMetricsFromImmutables(
                        info.principal_qty, info.principal_asset,
                        info.collateral_qty, info.collateral_asset,
                        info.interest_qty, info.interest_asset,
                        maturity_height);
                    if (computed.computed) {
                        // Log discrepancies for security auditing
                        double cached_apr = info.term_sheet_metrics.value("apr_percent").toDouble();
                        double cached_ltv = info.term_sheet_metrics.value("ltv_percent").toDouble();
                        if (std::abs(computed.apr - cached_apr) > 0.1) {
                            LogPrintf("TradeBoardTab: APR mismatch: computed=%.2f%%, cached=%.2f%% (offer %s)\n",
                                     computed.apr, cached_apr, info.offer_id.toStdString().c_str());
                        }
                        if (std::abs(computed.ltv - cached_ltv) > 1.0) {
                            LogPrintf("TradeBoardTab: LTV mismatch: computed=%.2f%%, cached=%.2f%% (offer %s)\n",
                                     computed.ltv, cached_ltv, info.offer_id.toStdString().c_str());
                        }
                        info.apr = computed.apr;
                        info.ltv = computed.ltv;
                        info.tenor_days = computed.tenor_days;
                        info.maturity_height = computed.maturity_height;
                    }

                    // FIX: Set contract_type for repo term sheets
                    if (info.contract_type.isEmpty()) {
                        info.contract_type = "repo";
                    }
                } else if (schema == QLatin1String("forward_term_sheet_v1") || schema == QLatin1String("option_term_sheet_v1")) {
                    info.is_term_sheet = true;
                    info.term_sheet_json = contractPayload;
                    info.term_sheet_terms = payloadObj.value("terms").toObject().toVariantMap();
                    info.term_sheet_metrics = payloadObj.value("metrics").toObject().toVariantMap();
                    if (payloadObj.contains("maker_role")) {
                        info.maker_role = payloadObj.value("maker_role").toString();
                    }

                    // Forward/Option specific metrics
                    if (info.term_sheet_metrics.contains("long_im_percent")) {
                        info.long_im_percent = info.term_sheet_metrics.value("long_im_percent").toDouble();
                    }
                    if (info.term_sheet_metrics.contains("short_im_percent")) {
                        info.short_im_percent = info.term_sheet_metrics.value("short_im_percent").toDouble();
                    }

                    // Extract deadlines from terms (immutable blockchain params)
                    info.deadline_short = info.term_sheet_terms.value("deadline_short").toInt();
                    info.deadline_long = info.term_sheet_terms.value("deadline_long").toInt();
                    info.safety_k = info.term_sheet_terms.value("safety_k").toInt();
                    info.reorg_conf = info.term_sheet_terms.value("reorg_conf").toInt();

                    // Compute tenor_days from deadlines (immutable blockchain param), never trust cached JSON
                    if (info.deadline_short > 0 && info.deadline_long > 0 && walletModel) {
                        int current_height = walletModel->clientModel().node().getNumBlocks();
                        int tenor_short = std::max(0, (info.deadline_short - current_height) / 144);
                        int tenor_long = std::max(0, (info.deadline_long - current_height) / 144);
                        // Use average of short and long for single tenor_days display
                        info.tenor_days = (tenor_short + tenor_long) / 2;
                        info.tenor_days_short = tenor_short;
                        info.tenor_days_long = tenor_long;
                        LogPrintf("TradeBoardTab: Forward/option term sheet computed tenor from deadlines: short=%dd, long=%dd, avg=%dd\n",
                                 tenor_short, tenor_long, info.tenor_days);
                    } else if (info.term_sheet_metrics.contains("tenor_days")) {
                        // Fallback for legacy term sheets without deadlines
                        info.tenor_days = static_cast<int>(info.term_sheet_metrics.value("tenor_days").toDouble());
                        LogPrintf("TradeBoardTab: WARNING - maturity_height missing for forward/option term sheet %s, using cached tenor_days\n",
                                 info.offer_id.toStdString().c_str());
                    }

                    // Parse from terms like repo does (collateral_amount, principal_amount pattern)
                    const QVariantMap& terms = info.term_sheet_terms;

                    // DEBUG: Log what fields exist
                    QStringList termKeys = terms.keys();
                    LogPrintf("TradeBoardTab: Forward/option term sheet TERMS keys: %s\n",
                             termKeys.join(", ").toStdString().c_str());

                    // Long deliver leg - try "_amount" first (like repo), fallback to "_units" (display values)
                    if (terms.contains("long_deliver_amount")) {
                        info.long_deliver_qty = terms.value("long_deliver_amount").toDouble();
                    } else if (terms.contains("long_deliver_units")) {
                        info.long_deliver_qty = terms.value("long_deliver_units").toDouble();
                    }
                    bool long_deliver_is_native = variantToBool(terms.value("long_deliver_is_native"), true);
                    QString long_deliver_asset_id = terms.value("long_deliver_asset_id").toString();
                    info.long_deliver_asset = long_deliver_is_native ? "TSC" : resolveAssetLabel(long_deliver_asset_id, long_deliver_asset_id.left(8));
                    info.long_deliver_asset_id = long_deliver_is_native ? "" : long_deliver_asset_id;

                    // Short deliver leg
                    if (terms.contains("short_deliver_amount")) {
                        info.short_deliver_qty = terms.value("short_deliver_amount").toDouble();
                    } else if (terms.contains("short_deliver_units")) {
                        info.short_deliver_qty = terms.value("short_deliver_units").toDouble();
                    }
                    bool short_deliver_is_native = variantToBool(terms.value("short_deliver_is_native"), true);
                    QString short_deliver_asset_id = terms.value("short_deliver_asset_id").toString();
                    info.short_deliver_asset = short_deliver_is_native ? "TSC" : resolveAssetLabel(short_deliver_asset_id, short_deliver_asset_id.left(8));
                    info.short_deliver_asset_id = short_deliver_is_native ? "" : short_deliver_asset_id;

                    // Long IM leg
                    if (terms.contains("long_im_amount")) {
                        info.long_margin_qty = terms.value("long_im_amount").toDouble();
                    } else if (terms.contains("long_im_units")) {
                        info.long_margin_qty = terms.value("long_im_units").toDouble();
                    }
                    bool long_im_is_native = variantToBool(terms.value("long_im_is_native"), true);
                    QString long_im_asset_id = terms.value("long_im_asset_id").toString();
                    info.long_margin_asset = long_im_is_native ? "TSC" : resolveAssetLabel(long_im_asset_id, long_im_asset_id.left(8));
                    info.long_margin_asset_id = long_im_is_native ? "" : long_im_asset_id;

                    // Short IM leg
                    if (terms.contains("short_im_amount")) {
                        info.short_margin_qty = terms.value("short_im_amount").toDouble();
                    } else if (terms.contains("short_im_units")) {
                        info.short_margin_qty = terms.value("short_im_units").toDouble();
                    }
                    bool short_im_is_native = variantToBool(terms.value("short_im_is_native"), true);
                    QString short_im_asset_id = terms.value("short_im_asset_id").toString();
                    info.short_margin_asset = short_im_is_native ? "TSC" : resolveAssetLabel(short_im_asset_id, short_im_asset_id.left(8));
                    info.short_margin_asset_id = short_im_is_native ? "" : short_im_asset_id;

                    // Premium (options only)
                    if (terms.contains("premium_amount")) {
                        info.premium_amount = terms.value("premium_amount").toDouble();
                    } else if (terms.contains("premium_units")) {
                        info.premium_amount = terms.value("premium_units").toDouble();
                    }
                    if (info.premium_amount > 0) {
                        bool premium_is_native = variantToBool(terms.value("premium_is_native"), true);
                        QString premium_asset_id = terms.value("premium_asset_id").toString();
                        info.premium_asset = premium_is_native ? "TSC" : resolveAssetLabel(premium_asset_id, premium_asset_id.left(8));
                        info.premium_asset_id = premium_is_native ? "" : premium_asset_id;
                    }
                    if (terms.contains("premium_payer")) {
                        info.premium_payer = terms.value("premium_payer").toString();
                    }

                    // FIX: Set contract_type for forward/option term sheets based on schema or premium
                    if (info.contract_type.isEmpty()) {
                        if (schema == QLatin1String("option_term_sheet_v1")) {
                            info.contract_type = "option";
                        } else if (schema == QLatin1String("forward_term_sheet_v1")) {
                            // Forward term sheet - but check if it has premium (which makes it an option)
                            const double premiumThreshold = 0.00001;
                            if (info.premium_amount > premiumThreshold) {
                                info.contract_type = "option";
                            } else {
                                info.contract_type = "forward";
                            }
                        } else {
                            // Fallback: detect by premium amount
                            const double premiumThreshold = 0.00001;
                            if (info.premium_amount > premiumThreshold) {
                                info.contract_type = "option";
                            } else {
                                info.contract_type = "forward";
                            }
                        }
                    }
                } else if (schema == QLatin1String("difficulty_term_sheet_v1")) {
                    // Difficulty derivative (CFD / option). The render reads term_sheet_terms (with "kind"
                    // injected) + term_sheet_metrics; no per-field OfferInfo plumbing is needed.
                    info.is_term_sheet = true;
                    info.term_sheet_json = contractPayload;
                    info.term_sheet_terms = payloadObj.value("terms").toObject().toVariantMap();
                    info.term_sheet_terms["kind"] = payloadObj.value("kind").toString();
                    info.term_sheet_metrics = payloadObj.value("metrics").toObject().toVariantMap();
                    if (payloadObj.contains("maker_role")) {
                        info.maker_role = payloadObj.value("maker_role").toString();
                    }
                    if (info.contract_type.isEmpty()) {
                        info.contract_type = "difficulty";
                    }
                } else if (schema == QLatin1String("spot_term_sheet_v1")) {
                    info.is_term_sheet = true;
                    info.term_sheet_json = contractPayload;
                    info.term_sheet_terms = payloadObj.value("terms").toObject().toVariantMap();
                    info.term_sheet_metrics = payloadObj.value("metrics").toObject().toVariantMap();
                    if (payloadObj.contains("maker_role")) {
                        info.maker_role = payloadObj.value("maker_role").toString();
                    }

                    // Parse alice_leg and bob_leg from terms
                    const QVariantMap& terms = info.term_sheet_terms;

                    // Read base units as int64_t for precision safety
                    int64_t alice_units = 0;
                    int64_t bob_units = 0;
                    int alice_decimals = 8;
                    int bob_decimals = 8;
                    bool alice_is_native = true;
                    bool bob_is_native = true;
                    QString alice_asset_id;
                    QString bob_asset_id;

                    // Alice leg (maker sends)
                    if (terms.contains("alice_leg") && terms["alice_leg"].canConvert<QVariantMap>()) {
                        QVariantMap aliceLeg = terms["alice_leg"].toMap();
                        alice_is_native = variantToBool(aliceLeg.value("is_native"), true);
                        alice_asset_id = aliceLeg.value("asset_id").toString();
                        alice_units = aliceLeg.value("units").toLongLong();

                        if (!alice_is_native && walletModel) {
                            WalletModel::AssetInfo assetInfo = walletModel->getAssetInfo(alice_asset_id);
                            if (assetInfo.has_decimals) alice_decimals = assetInfo.decimals;
                        }

                        // Convert to display amount
                        info.amount = static_cast<double>(alice_units) / std::pow(10.0, alice_decimals);
                        info.asset_send = alice_is_native ? "TSC" : resolveAssetLabel(alice_asset_id, alice_asset_id.left(8));

                        // Store asset ID and units for proof verification
                        info.alice_send_asset_id = alice_is_native ? QString() : alice_asset_id;
                        info.alice_send_units = alice_units;
                    }

                    // Bob leg (taker sends)
                    if (terms.contains("bob_leg") && terms["bob_leg"].canConvert<QVariantMap>()) {
                        QVariantMap bobLeg = terms["bob_leg"].toMap();
                        bob_is_native = variantToBool(bobLeg.value("is_native"), true);
                        bob_asset_id = bobLeg.value("asset_id").toString();
                        bob_units = bobLeg.value("units").toLongLong();

                        if (!bob_is_native && walletModel) {
                            WalletModel::AssetInfo assetInfo = walletModel->getAssetInfo(bob_asset_id);
                            if (assetInfo.has_decimals) bob_decimals = assetInfo.decimals;
                        }

                        info.asset_recv = bob_is_native ? "TSC" : resolveAssetLabel(bob_asset_id, bob_asset_id.left(8));

                        // Store asset ID and units for proof verification
                        info.bob_send_asset_id = bob_is_native ? QString() : bob_asset_id;
                        info.bob_send_units = bob_units;
                    }

                    // Decimal-safe price calculation: (bob_units / 10^bob_decimals) / (alice_units / 10^alice_decimals)
                    // = (bob_units * 10^alice_decimals) / (alice_units * 10^bob_decimals)
                    // To avoid overflow, compute in double but preserve precision where possible
                    if (alice_units > 0) {
                        // For display purposes, convert to decimal amounts then divide
                        // This is safe because we're using int64 for reading units (no precision loss there)
                        double alice_amount = static_cast<double>(alice_units) / std::pow(10.0, alice_decimals);
                        double bob_amount = static_cast<double>(bob_units) / std::pow(10.0, bob_decimals);
                        info.price = bob_amount / alice_amount;
                    }

                    // Extract exchange rate from metrics as fallback/validation
                    if (info.term_sheet_metrics.contains("exchange_rate")) {
                        double cached_rate = info.term_sheet_metrics.value("exchange_rate").toDouble();
                        if (qFuzzyIsNull(info.price)) {
                            info.price = cached_rate;
                        } else if (std::abs(info.price - cached_rate) / cached_rate > 0.0001) {
                            // Log discrepancy if computed vs cached differs by >0.01%
                            LogPrintf("TradeBoardTab: Spot exchange rate mismatch - computed=%.8f, cached=%.8f (offer %s)\n",
                                     info.price, cached_rate, info.offer_id.toStdString().c_str());
                        }
                    }

                    LogPrintf("TradeBoardTab: Parsed spot term sheet - alice sends: %f %s (%lld units), bob sends: %f %s (%lld units), rate: %.8f\n",
                              info.amount, info.asset_send.toStdString().c_str(), alice_units,
                              bob_units / std::pow(10.0, bob_decimals), info.asset_recv.toStdString().c_str(), bob_units,
                              info.price);


                } else {
                    // Assume this is a fully finalized contract payload.
                    if (payloadObj.contains("terms") && payloadObj["terms"].isObject()) {
                        QJsonObject terms = payloadObj["terms"].toObject();

                        // Detect contract type: forward/option (has long_party/short_party) vs repo (has principal_leg)
                        bool isForwardOrOption = terms.contains("long_party") || terms.contains("short_party");

                        if (isForwardOrOption) {
                            // FORWARD/OPTION finalized contract
                            populateForwardTermsFromJson(info, payloadObj);

                            // Set contract_type if not already set
                            if (info.contract_type.isEmpty()) {
                                // Distinguish by premium
                                const double premiumThreshold = 0.00001;
                                if (info.premium_amount > premiumThreshold) {
                                    info.contract_type = "option";
                                } else {
                                    info.contract_type = "forward";
                                }
                            }

                            LogPrintf("TradeBoardTab: Populated finalized forward/option - long: %f %s, short: %f %s, premium: %f %s\n",
                                      info.long_deliver_qty, info.long_deliver_asset.toStdString().c_str(),
                                      info.short_deliver_qty, info.short_deliver_asset.toStdString().c_str(),
                                      info.premium_amount, info.premium_asset.toStdString().c_str());
                        } else {
                            // REPO finalized contract (existing logic)
                            double principal_units = 0.0;
                        double interest_units = 0.0;
                        double collateral_units = 0.0;
                        bool principal_is_native = true;
                        bool interest_is_native = true;
                        bool collateral_is_native = true;
                        QString principal_asset_id;
                        QString interest_asset_id;
                        QString collateral_asset_id;

                        if (terms.contains("principal_leg") && terms["principal_leg"].isObject()) {
                            QJsonObject principal_leg = terms["principal_leg"].toObject();
                            principal_units = principal_leg.value("units").toDouble();
                            principal_is_native = variantToBool(principal_leg.value("is_native").toVariant(), true);
                            principal_asset_id = principal_leg.value("asset_id").toString();
                        } else {
                            principal_units = terms.value("principal_units").toDouble();
                            principal_is_native = variantToBool(terms.value("principal_is_native").toVariant(), true);
                            principal_asset_id = terms.value("principal_asset_id").toString();
                        }

                        if (terms.contains("interest_leg") && terms["interest_leg"].isObject()) {
                            QJsonObject interest_leg = terms["interest_leg"].toObject();
                            interest_units = interest_leg.value("units").toDouble();
                            interest_is_native = variantToBool(interest_leg.value("is_native").toVariant(), true);
                            interest_asset_id = interest_leg.value("asset_id").toString();
                        } else {
                            interest_units = terms.value("interest_units").toDouble();
                            // Prefer explicit interest keys; fallback to principal if absent
                            interest_is_native = variantToBool(terms.value("interest_is_native").toVariant(), principal_is_native);
                            interest_asset_id = terms.value("interest_asset_id").toString();
                            if (!interest_is_native && interest_asset_id.isEmpty()) {
                                interest_asset_id = principal_asset_id;
                            }
                        }

                        if (terms.contains("collateral_leg") && terms["collateral_leg"].isObject()) {
                            QJsonObject collateral_leg = terms["collateral_leg"].toObject();
                            collateral_units = collateral_leg.value("units").toDouble();
                            collateral_is_native = variantToBool(collateral_leg.value("is_native").toVariant(), true);
                            collateral_asset_id = collateral_leg.value("asset_id").toString();
                        } else {
                            collateral_units = terms.value("collateral_units").toDouble();
                            if (qFuzzyIsNull(collateral_units)) {
                                collateral_units = terms.value("collateral_sats").toDouble();
                            }
                            collateral_is_native = true;
                        }

                        auto amountFromUnits = [&](double units, bool is_native, const QString& asset_id) -> double {
                            if (units <= 0.0) {
                                return 0.0;
                            }
                            int decimals = 8;
                            if (!is_native && walletModel) {
                                WalletModel::AssetInfo assetInfo = walletModel->getAssetInfo(asset_id);
                                if (assetInfo.has_decimals) {
                                    decimals = assetInfo.decimals;
                                }
                            }
                            const double divisor = std::pow(10.0, decimals);
                            return units / divisor;
                        };

                        const QString resolved_interest_asset_id = !interest_asset_id.isEmpty() ? interest_asset_id : principal_asset_id;
                        const double principal_amount_units = amountFromUnits(principal_units, principal_is_native, principal_asset_id);
                        const double interest_amount_units = amountFromUnits(interest_units, interest_is_native, resolved_interest_asset_id);
                        const double collateral_amount_units = amountFromUnits(collateral_units, collateral_is_native, collateral_asset_id);

                        int maturity_height = terms.value("maturity_height").toInt();

                        // Store asset IDs (empty for native)
                        info.collateral_asset_id = collateral_is_native ? QString() : collateral_asset_id;
                        info.principal_asset_id = principal_is_native ? QString() : principal_asset_id;
                        info.interest_asset_id = interest_is_native ? QString() : resolved_interest_asset_id;

                        if (collateral_is_native) {
                            info.collateral_asset = QStringLiteral("TSC");
                        } else if (!collateral_asset_id.isEmpty()) {
                            info.collateral_asset = resolveAssetLabel(collateral_asset_id, tr("ASSET"));
                        } else {
                            info.collateral_asset = tr("ASSET");
                        }

                        if (principal_is_native) {
                            info.principal_asset = QStringLiteral("TSC");
                        } else if (!principal_asset_id.isEmpty()) {
                            info.principal_asset = resolveAssetLabel(principal_asset_id, tr("ASSET"));
                        } else {
                            info.principal_asset = tr("ASSET");
                        }

                        info.collateral_qty = collateral_amount_units;
                        info.principal_qty = principal_amount_units;
                        info.interest_qty = interest_amount_units;

                        if (interest_is_native) {
                            info.interest_asset = QStringLiteral("TSC");
                        } else if (!resolved_interest_asset_id.isEmpty()) {
                            info.interest_asset = resolveAssetLabel(resolved_interest_asset_id, tr("ASSET"));
                        } else if (!info.principal_asset.isEmpty()) {
                            info.interest_asset = info.principal_asset;
                        } else {
                            info.interest_asset = tr("ASSET");
                        }

                        // Compute metrics from immutable blockchain parameters (never trust cached values)
                        auto computed = computeMetricsFromImmutables(
                            principal_amount_units, info.principal_asset,
                            collateral_amount_units, info.collateral_asset,
                            interest_amount_units, info.interest_asset,
                            maturity_height);
                        if (computed.computed) {
                            info.apr = computed.apr;
                            info.ltv = computed.ltv;
                            info.tenor_days = computed.tenor_days;
                            info.maturity_height = computed.maturity_height;
                        }

                        // Some finalized payloads (or down-level relays) may still ship the flat fields.
                        if (!terms.contains("collateral_leg") && terms.contains("collateral_is_native")) {
                            populateFromFlatTerms(terms);
                        }
                            // Set contract_type if not already set
                            if (info.contract_type.isEmpty()) {
                                info.contract_type = "repo";
                            }
                        }  // End repo finalized contract parsing
                    }  // End if (payloadObj.contains("terms"))

                    // Set maker role from address fields if not set
                    if (info.maker_role.isEmpty()) {
                        if (payloadObj.contains("lender_address")) {
                            info.maker_role = QStringLiteral("lender");
                        } else if (payloadObj.contains("long_margin_dest")) {
                            // Forward/option: guess from terms presence
                            info.maker_role = QStringLiteral("long");  // Default
                        }
                    }
                }

                // FIX: Deferred cache population after all type inference completes
                // Populate cache with dual-key mapping from bulletin-board listings
                if (!payloadContractId.isEmpty() && !info.contract_type.isEmpty()) {
                    QString normalizedType = info.contract_type.toLower();
                    if (normalizedType == "options") normalizedType = QStringLiteral("option");
                    cacheContractFlavor(payloadContractId, normalizedType, contractPayload, info.offer_id);
                    LogPrintf("TradeBoardTab::updateOffersList: Deferred cache population - contract_id=%s, bb_uuid=%s, type=%s\n",
                              payloadContractId.toStdString().c_str(), info.offer_id.toStdString().c_str(), normalizedType.toStdString().c_str());
                }
            } else if (parseError.error != QJsonParseError::NoError) {
                LogPrintf("TradeBoardTab::updateOffersList() WARNING: Failed to parse contract payload JSON: %s\n",
                          parseError.errorString().toStdString().c_str());
            }
        }

        LogPrintf("TradeBoardTab::updateOffersList() Offer: id=%s, maker=%s, type=%s\n",
            info.offer_id.toStdString().c_str(),
            info.maker_pubkey.toStdString().c_str(),
            info.offer_type.toStdString().c_str());

        // CRITICAL: Only add to activeOffers and create buttons if we have a valid ID
        if (info.offer_id.isEmpty()) {
            LogPrintf("TradeBoardTab::updateOffersList() WARNING: Offer has empty ID! Will try to display anyway.\n");
            // Generate a temporary ID so we can still show the offer
            info.offer_id = QString("temp-%1").arg(QDateTime::currentSecsSinceEpoch());
        }

        activeOffers[info.offer_id] = info;

        // Filter: only show contracts matching current contract type
        // ⚠️ CRITICAL: Accept BOTH "forward" AND "option"/"options" contract types
        // Server may post as "forward" or "options" - we distinguish by:
        // - Explicit contract_type == "option" or "options"
        // - OR: contract_type == "forward" with non-zero premium (implicit option)
        QString targetContractType = currentContractType;
        bool skipThisOffer = false;

        if (currentContractType == "forward" || currentContractType == "options") {
            QString contractTypeLower = info.contract_type.toLower();

            // Accept if contract_type is "forward", "option", or "options"
            if (contractTypeLower != "forward" && contractTypeLower != "option" && contractTypeLower != "options") {
                skipThisOffer = true;  // Not a forward/option contract
            } else {
                // Distinguish forwards from options based on premium
                const double premiumThreshold = 0.00001;  // Consider > 0.00001 as non-zero premium
                bool hasPremium = (info.premium_amount > premiumThreshold);
                bool isExplicitOption = (contractTypeLower == "option" || contractTypeLower == "options");

                if (currentContractType == "options") {
                    // Viewing options: show if explicit option OR has premium
                    if (!isExplicitOption && !hasPremium) {
                        skipThisOffer = true;  // Forward without premium
                    }
                } else if (currentContractType == "forward") {
                    // Viewing forwards: show if NOT explicit option AND no premium
                    if (isExplicitOption || hasPremium) {
                        skipThisOffer = true;  // This is an option
                    }
                }
            }
        } else if (info.contract_type.toLower() != targetContractType.toLower()) {
            skipThisOffer = true;  // Skip contracts that don't match current view
        }

        // Apply custom filters
        if (!skipThisOffer) {
            // Filter by asset registry
            if (filterSettings.filterNonRegistryAssets) {
                // Check if assets are in registry (simplified check - you may need to implement proper registry lookup)
                // For now, we'll filter out assets that have hexadecimal IDs (not in registry)
                auto isHexAssetId = [](const QString& asset) {
                    if (asset.isEmpty() || asset.toLower() == "tsc") return false;
                    // Check if it looks like a hex asset ID (64 character hex string)
                    QRegularExpression hexPattern("^[0-9a-fA-F]+$");
                    return asset.length() == 64 && hexPattern.match(asset).hasMatch();
                };

                if (currentContractType == "repo") {
                    if (isHexAssetId(info.principal_asset) || isHexAssetId(info.collateral_asset) || isHexAssetId(info.interest_asset)) {
                        skipThisOffer = true;
                    }
                } else if (currentContractType == "forward" || currentContractType == "options") {
                    if (isHexAssetId(info.long_deliver_asset) || isHexAssetId(info.short_deliver_asset) ||
                        isHexAssetId(info.long_margin_asset) || isHexAssetId(info.short_margin_asset) ||
                        isHexAssetId(info.premium_asset)) {
                        skipThisOffer = true;
                    }
                } else if (currentContractType == "spot") {
                    if (isHexAssetId(info.asset_send) || isHexAssetId(info.asset_recv)) {
                        skipThisOffer = true;
                    }
                }
            }

            // Filter by asset symbol/ID
            if (!skipThisOffer && !filterSettings.assetFilter.isEmpty()) {
                QString filterLower = filterSettings.assetFilter.toLower();
                bool matchesAsset = false;

                if (currentContractType == "repo") {
                    matchesAsset = info.principal_asset.toLower().contains(filterLower) ||
                                   info.collateral_asset.toLower().contains(filterLower) ||
                                   info.interest_asset.toLower().contains(filterLower);
                } else if (currentContractType == "forward" || currentContractType == "options") {
                    matchesAsset = info.long_deliver_asset.toLower().contains(filterLower) ||
                                   info.short_deliver_asset.toLower().contains(filterLower) ||
                                   info.long_margin_asset.toLower().contains(filterLower) ||
                                   info.short_margin_asset.toLower().contains(filterLower) ||
                                   info.premium_asset.toLower().contains(filterLower);
                } else if (currentContractType == "spot") {
                    matchesAsset = info.asset_send.toLower().contains(filterLower) ||
                                   info.asset_recv.toLower().contains(filterLower);
                }

                if (!matchesAsset) {
                    skipThisOffer = true;
                }
            }

            // Filter by role
            if (!skipThisOffer && filterSettings.roleFilter != "all" && !filterSettings.roleFilter.isEmpty()) {
                if (currentContractType == "repo") {
                    if (info.maker_role.toLower() != filterSettings.roleFilter.toLower()) {
                        skipThisOffer = true;
                    }
                } else if (currentContractType == "forward" || currentContractType == "options") {
                    if (info.maker_role.toLower() != filterSettings.roleFilter.toLower()) {
                        skipThisOffer = true;
                    }
                }
            }

            // Filter by amount range
            if (!skipThisOffer && (filterSettings.filterByMinAmount || filterSettings.filterByMaxAmount)) {
                double amount = 0.0;

                if (currentContractType == "repo") {
                    amount = info.principal_qty;
                } else if (currentContractType == "forward" || currentContractType == "options") {
                    amount = info.long_deliver_qty; // Use deliver quantity as the amount
                } else if (currentContractType == "spot") {
                    amount = info.amount;
                }

                if (filterSettings.filterByMinAmount && amount < filterSettings.minAmount) {
                    skipThisOffer = true;
                }
                if (filterSettings.filterByMaxAmount && amount > filterSettings.maxAmount) {
                    skipThisOffer = true;
                }
            }
        }

        if (skipThisOffer) {
            continue;
        }

        // Add row to the appropriate table
        int row = targetTable->rowCount();
        targetTable->insertRow(row);

        // Populate based on contract type
        if (currentContractType == "repo") {
            // Repo: Maker, Role, MTM (Marks), MTM (Market), Collateral, Principal, Interest, Price, APR, LTV, Tenor, Funds Verified, Age, Actions
            QTableWidgetItem* makerItem = new QTableWidgetItem(formatPubkey(info.maker_pubkey));
            makerItem->setData(Qt::UserRole, info.offer_id);  // Store full offer_id for double-click
            targetTable->setItem(row, 0, makerItem);
            targetTable->setItem(row, 1, new QTableWidgetItem(info.maker_role.toUpper()));

            // MTM (Marks) and MTM (Market) - compute using inline pricing
            // Build inline terms for pricing.repo.quote
            QVariantMap inlineTerms;
            inlineTerms["principal_asset"] = info.principal_asset_id.isEmpty() ? "" : info.principal_asset_id;
            inlineTerms["principal_is_native"] = info.principal_asset_id.isEmpty();
            inlineTerms["principal_units"] = static_cast<qulonglong>(info.principal_qty * 1e8);
            inlineTerms["interest_asset"] = info.interest_asset_id.isEmpty() ? "" : info.interest_asset_id;
            inlineTerms["interest_is_native"] = info.interest_asset_id.isEmpty();
            inlineTerms["interest_units"] = static_cast<qulonglong>(info.interest_qty * 1e8);
            inlineTerms["collateral_asset"] = info.collateral_asset_id.isEmpty() ? "" : info.collateral_asset_id;
            inlineTerms["collateral_is_native"] = info.collateral_asset_id.isEmpty();
            inlineTerms["collateral_units"] = static_cast<qulonglong>(info.collateral_qty * 1e8);
            inlineTerms["maturity_height"] = info.maturity_height;
            inlineTerms["safety_k"] = 144;

            auto initMtmItem = []() {
                QTableWidgetItem* item = new QTableWidgetItem(QStringLiteral("--"));
                item->setForeground(QBrush(QColor(158, 158, 158)));
                item->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
                return item;
            };

            QTableWidgetItem* mtmMarksItem = initMtmItem();
            mtmMarksItem->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
            targetTable->setItem(row, 2, mtmMarksItem);

            QTableWidgetItem* mtmMarketItem = initMtmItem();
            mtmMarketItem->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
            targetTable->setItem(row, 3, mtmMarketItem);

            scheduleRepoMtmUpdate(targetTable, row, info, inlineTerms);

            // Collateral: "Asset Qty" format
            QString collateralStr = QString("%1 %2")
                .arg(QString::number(info.collateral_qty, 'f', info.collateral_qty < 1.0 ? 8 : 2))
                .arg(info.collateral_asset);
            targetTable->setItem(row, 4, new QTableWidgetItem(collateralStr));

            // Principal: "Asset Qty" format
            QString principalStr = QString("%1 %2")
                .arg(QString::number(info.principal_qty, 'f', info.principal_qty < 1.0 ? 8 : 2))
                .arg(info.principal_asset);
            targetTable->setItem(row, 5, new QTableWidgetItem(principalStr));

            // Interest: "Asset Qty" format
            QString interestStr = QString("%1 %2")
                .arg(QString::number(info.interest_qty, 'f', info.interest_qty < 1.0 ? 8 : 2))
                .arg(info.interest_asset);
            targetTable->setItem(row, 6, new QTableWidgetItem(interestStr));

            // Price: Collateral/Principal ratio
            double price = (info.principal_qty > 0.0) ? (info.collateral_qty / info.principal_qty) : 0.0;
            targetTable->setItem(row, 7, new NumericTableWidgetItem(
                QString::number(price, 'f', price < 1.0 ? 8 : 4), price));

            // APR
            targetTable->setItem(row, 8, new NumericTableWidgetItem(
                QString::number(info.apr, 'f', 2) + "%", info.apr));

            // LTV
            targetTable->setItem(row, 9, new NumericTableWidgetItem(
                QString::number(info.ltv, 'f', 2) + "%", info.ltv));

            // Tenor
            targetTable->setItem(row, 10, new NumericTableWidgetItem(
                QString::number(info.tenor_days) + "d", static_cast<double>(info.tenor_days)));

            // Proof - use cached verification result with sufficiency check
            QString proofStatus;
            QTableWidgetItem* proofItem;
            if (info.proof_of_funds.isEmpty()) {
                proofStatus = "-";
                proofItem = new QTableWidgetItem(proofStatus);
                proofItem->setForeground(QBrush(QColor(158, 158, 158)));  // Gray
            } else if (info.proof_verified) {
                // Proofs verified - now check sufficiency using asset IDs (not labels)
                uint64_t requiredAmount = 0;
                QString requiredAssetId;
                bool requirementKnown = false;

                if (info.maker_role.toLower() == "lender") {
                    // Convert principal_qty from display units to blockchain units using correct decimals
                    int decimals = 8;  // Default for native
                    if (!info.principal_asset_id.isEmpty() && walletModel) {
                        WalletModel::AssetInfo assetInfo = walletModel->getAssetInfo(info.principal_asset_id);
                        if (assetInfo.has_decimals) {
                            decimals = assetInfo.decimals;
                        }
                    }
                    requiredAmount = static_cast<uint64_t>(info.principal_qty * std::pow(10.0, decimals));
                    requiredAssetId = info.principal_asset_id;  // Use asset ID, not label
                    requirementKnown = true;
                } else if (info.maker_role.toLower() == "borrower") {
                    // Convert collateral_qty from display units to blockchain units using correct decimals
                    int decimals = 8;  // Default for native
                    if (!info.collateral_asset_id.isEmpty() && walletModel) {
                        WalletModel::AssetInfo assetInfo = walletModel->getAssetInfo(info.collateral_asset_id);
                        if (assetInfo.has_decimals) {
                            decimals = assetInfo.decimals;
                        }
                    }
                    requiredAmount = static_cast<uint64_t>(info.collateral_qty * std::pow(10.0, decimals));
                    requiredAssetId = info.collateral_asset_id;  // Use asset ID, not label
                    requirementKnown = true;
                }

                bool sufficient = true;
                if (requirementKnown) {
                    // Normalize asset IDs: empty means native
                    QString normalizedProofAsset = info.proof_verified_asset.isEmpty() ? QString() : info.proof_verified_asset;
                    QString normalizedRequiredAsset = requiredAssetId.isEmpty() ? QString() : requiredAssetId;

                    bool assetMatches = (normalizedProofAsset.isEmpty() && normalizedRequiredAsset.isEmpty()) ||
                                       (normalizedProofAsset == normalizedRequiredAsset);
                    sufficient = assetMatches && (info.proof_verified_units >= requiredAmount);

                    LogPrintf("TradeBoardTab: Proof sufficiency - offer=%s, required=%llu, verified=%llu, asset_match=%d, sufficient=%d\n",
                             info.offer_id.toStdString().c_str(), requiredAmount, info.proof_verified_units, assetMatches, sufficient);
                }

                if (sufficient) {
                    proofStatus = QString("✓");
                    proofItem = new QTableWidgetItem(proofStatus);
                    proofItem->setForeground(QBrush(QColor(76, 175, 80)));  // Green
                    proofItem->setToolTip(tr("Verified: %1 units (sufficient)")
                        .arg(info.proof_verified_units));
                } else {
                    proofStatus = QString("⚠");
                    proofItem = new QTableWidgetItem(proofStatus);
                    proofItem->setForeground(QBrush(QColor(255, 152, 0)));  // Orange
                    proofItem->setToolTip(tr("Verified but INSUFFICIENT: %1 units (need %2)")
                        .arg(info.proof_verified_units)
                        .arg(requiredAmount));
                }
            } else {
                proofStatus = QString("✗");
                proofItem = new QTableWidgetItem(proofStatus);
                proofItem->setForeground(QBrush(QColor(244, 67, 54)));  // Red
                proofItem->setToolTip(tr("Proof verification FAILED: %1").arg(info.proof_verification_error));
            }
            targetTable->setItem(row, 11, proofItem);

            // Age
            targetTable->setItem(row, 12, new NumericTableWidgetItem(
                formatTimestamp(info.created_at), static_cast<double>(info.created_at)));

        } else if (currentContractType == "forward") {
            LogPrintf("TradeBoardTab: Processing forward offer %s in forward table\n", info.offer_id.toStdString());
            // Forward: Maker, Role, MTM (Marks), MTM (Market), Long Asset, Short Asset, Long IM %, Short IM %, Tenor, Age, Proof, Actions
            QTableWidgetItem* makerItem = new QTableWidgetItem(formatPubkey(info.maker_pubkey));
            makerItem->setData(Qt::UserRole, info.offer_id);  // Store full offer_id for double-click
            targetTable->setItem(row, 0, makerItem);
            targetTable->setItem(row, 1, new QTableWidgetItem(info.maker_role.toUpper()));

            // MTM (Marks) and MTM (Market) - compute using inline pricing
            // Build inline terms for pricing.forward.quote
            // NOTE: walletModel translates long_party/short_party to alice/bob for RPC
            QVariantMap inlineTerms;
            // Long (Alice) delivery leg
            inlineTerms["long_party_deliver_asset"] = info.long_deliver_asset_id.isEmpty() ? "" : info.long_deliver_asset_id;
            inlineTerms["long_party_deliver_is_native"] = info.long_deliver_asset_id.isEmpty();
            inlineTerms["long_party_deliver_units"] = static_cast<qulonglong>(info.long_deliver_qty * 1e8);
            // Short (Bob) delivery leg
            inlineTerms["short_party_deliver_asset"] = info.short_deliver_asset_id.isEmpty() ? "" : info.short_deliver_asset_id;
            inlineTerms["short_party_deliver_is_native"] = info.short_deliver_asset_id.isEmpty();
            inlineTerms["short_party_deliver_units"] = static_cast<qulonglong>(info.short_deliver_qty * 1e8);
            // Long (Alice) IM
            inlineTerms["long_party_margin_asset"] = info.long_margin_asset_id.isEmpty() ? "" : info.long_margin_asset_id;
            inlineTerms["long_party_margin_is_native"] = info.long_margin_asset_id.isEmpty();
            inlineTerms["long_party_margin_units"] = static_cast<qulonglong>(info.long_margin_qty * 1e8);
            // Short (Bob) IM
            inlineTerms["short_party_margin_asset"] = info.short_margin_asset_id.isEmpty() ? "" : info.short_margin_asset_id;
            inlineTerms["short_party_margin_is_native"] = info.short_margin_asset_id.isEmpty();
            inlineTerms["short_party_margin_units"] = static_cast<qulonglong>(info.short_margin_qty * 1e8);
            // Premium (must provide valid values - RPC rejects empty string for premium_asset)
            if (!info.premium_asset_id.isEmpty()) {
                inlineTerms["premium_asset"] = info.premium_asset_id;
                inlineTerms["premium_is_native"] = false;
            } else {
                // No premium or native premium - use native
                inlineTerms["premium_is_native"] = true;
            }
            inlineTerms["premium_units"] = static_cast<qulonglong>(info.premium_amount * 1e8);
            inlineTerms["deadline_short"] = info.deadline_short;
            inlineTerms["safety_k"] = info.safety_k > 0 ? info.safety_k : 144;

            auto initMtmItem = []() {
                QTableWidgetItem* item = new QTableWidgetItem(QStringLiteral("--"));
                item->setForeground(QBrush(QColor(158, 158, 158)));
                item->setTextAlignment(Qt::AlignCenter | Qt::AlignVCenter);
                return item;
            };

            QTableWidgetItem* mtmMarksItem = initMtmItem();
            targetTable->setItem(row, 2, mtmMarksItem);

            QTableWidgetItem* mtmMarketItem = initMtmItem();
            targetTable->setItem(row, 3, mtmMarketItem);

            scheduleForwardMtmUpdate(targetTable, row, info, inlineTerms);

            // Long deliver leg: "Qty Asset" format (column 4, was 2)
            QString longDeliverText;
            if (info.long_deliver_qty > 0) {
                longDeliverText = QString("%1 %2")
                    .arg(QString::number(info.long_deliver_qty, 'f', info.long_deliver_qty < 1.0 ? 8 : 2))
                    .arg(info.long_deliver_asset.isEmpty() ? tr("TSC") : info.long_deliver_asset);
            } else {
                longDeliverText = info.long_deliver_asset.isEmpty() ? tr("TBD") : info.long_deliver_asset;
            }
            targetTable->setItem(row, 4, new NumericTableWidgetItem(longDeliverText, info.long_deliver_qty));

            // Short deliver leg: "Qty Asset" format (column 5, was 3)
            QString shortDeliverText;
            if (info.short_deliver_qty > 0) {
                shortDeliverText = QString("%1 %2")
                    .arg(QString::number(info.short_deliver_qty, 'f', info.short_deliver_qty < 1.0 ? 8 : 2))
                    .arg(info.short_deliver_asset.isEmpty() ? tr("TSC") : info.short_deliver_asset);
            } else {
                shortDeliverText = info.short_deliver_asset.isEmpty() ? tr("TBD") : info.short_deliver_asset;
            }
            targetTable->setItem(row, 5, new NumericTableWidgetItem(shortDeliverText, info.short_deliver_qty));

            // Long IM: "Qty Asset (X%)" format (column 6, was 4)
            QString longIMText;
            if (info.long_margin_qty > 0) {
                longIMText = QString("%1 %2 (%3%)")
                    .arg(QString::number(info.long_margin_qty, 'f', info.long_margin_qty < 1.0 ? 8 : 2))
                    .arg(info.long_margin_asset.isEmpty() ? tr("TSC") : info.long_margin_asset)
                    .arg(QString::number(info.long_im_percent, 'f', 1));
            } else {
                longIMText = QString::number(info.long_im_percent, 'f', 1) + "%";
            }
            targetTable->setItem(row, 6, new NumericTableWidgetItem(longIMText, info.long_im_percent));

            // Short IM: "Qty Asset (X%)" format (column 7, was 5)
            QString shortIMText;
            if (info.short_margin_qty > 0) {
                shortIMText = QString("%1 %2 (%3%)")
                    .arg(QString::number(info.short_margin_qty, 'f', info.short_margin_qty < 1.0 ? 8 : 2))
                    .arg(info.short_margin_asset.isEmpty() ? tr("TSC") : info.short_margin_asset)
                    .arg(QString::number(info.short_im_percent, 'f', 1));
            } else {
                shortIMText = QString::number(info.short_im_percent, 'f', 1) + "%";
            }
            targetTable->setItem(row, 7, new NumericTableWidgetItem(shortIMText, info.short_im_percent));

            // Tenor: show deadline spread (short → long) (column 8, was 6)
            QString tenorText;
            if (info.deadline_short > 0 && info.deadline_long > 0) {
                int currentHeight = walletModel
                    ? walletModel->clientModel().node().getNumBlocks() : 0;
                int tenorDaysShort = std::max(0, (info.deadline_short - currentHeight) / 144);
                int tenorDaysLong = std::max(0, (info.deadline_long - currentHeight) / 144);
                tenorText = QString("%1d - %2d").arg(tenorDaysShort).arg(tenorDaysLong);
            } else {
                tenorText = QString::number(info.tenor_days) + "d";
            }
            targetTable->setItem(row, 8, new QTableWidgetItem(tenorText));

            // Age (column 9, was 7)
            targetTable->setItem(row, 9, new NumericTableWidgetItem(
                formatTimestamp(info.created_at), static_cast<double>(info.created_at)));

            // Proof of Funds (column 10, was 8)
            QTableWidgetItem* proofItem = nullptr;
            QString proofStatus;
            if (info.proof_verified) {
                // Determine required amount based on maker role
                uint64_t requiredAmount = 0;
                QString requiredAssetId;  // Use asset_id instead of label
                bool assetMatches = false;

                if (info.maker_role.toLower() == "long") {
                    // Long needs to prove IM only (NOT deliver - forwards are for assets you don't have!)
                    requiredAmount = static_cast<uint64_t>(info.long_margin_qty * 1e8);
                    requiredAssetId = info.long_margin_asset_id;  // Use IM asset_id (empty = native)
                } else if (info.maker_role.toLower() == "short") {
                    // Short needs to prove IM only (NOT deliver - forwards are for assets you don't have!)
                    requiredAmount = static_cast<uint64_t>(info.short_margin_qty * 1e8);
                    requiredAssetId = info.short_margin_asset_id;  // Use IM asset_id (empty = native)
                }

                // Normalize: empty asset_id means native TSC
                QString normalizedProofAsset = info.proof_verified_asset.isEmpty() ? QString() : info.proof_verified_asset;
                QString normalizedRequiredAsset = requiredAssetId.isEmpty() ? QString() : requiredAssetId;

                // Both empty = both native = match, OR both same non-empty asset_id = match
                assetMatches = (normalizedProofAsset.isEmpty() && normalizedRequiredAsset.isEmpty()) ||
                               (normalizedProofAsset == normalizedRequiredAsset);

                bool sufficient = assetMatches && (info.proof_verified_units >= requiredAmount);

                if (sufficient) {
                    proofStatus = QString("✓");
                    proofItem = new QTableWidgetItem(proofStatus);
                    proofItem->setForeground(QBrush(QColor(76, 175, 80)));  // Green
                    proofItem->setToolTip(tr("Verified: %1 units (sufficient)")
                        .arg(info.proof_verified_units));
                } else {
                    proofStatus = QString("⚠");
                    proofItem = new QTableWidgetItem(proofStatus);
                    proofItem->setForeground(QBrush(QColor(255, 152, 0)));  // Orange
                    proofItem->setToolTip(tr("Verified but INSUFFICIENT: %1 units (need %2)")
                        .arg(info.proof_verified_units)
                        .arg(requiredAmount));
                }
            } else if (!info.proof_verification_error.isEmpty()) {
                proofStatus = QString("✗");
                proofItem = new QTableWidgetItem(proofStatus);
                proofItem->setForeground(QBrush(QColor(244, 67, 54)));  // Red
                proofItem->setToolTip(tr("Proof verification FAILED: %1").arg(info.proof_verification_error));
            } else {
                proofStatus = QString("-");
                proofItem = new QTableWidgetItem(proofStatus);
                proofItem->setToolTip(tr("No proof provided"));
            }
            targetTable->setItem(row, 10, proofItem);

        } else if (currentContractType == "options") {
            // Options: Maker, Role, MTM (Marks), MTM (Market), Long Asset, Short Asset, Premium, Prem Payer, Tenor, Age, Proof, Actions
            QTableWidgetItem* makerItem = new QTableWidgetItem(formatPubkey(info.maker_pubkey));
            makerItem->setData(Qt::UserRole, info.offer_id);  // Store full offer_id for double-click
            targetTable->setItem(row, 0, makerItem);
            targetTable->setItem(row, 1, new QTableWidgetItem(info.maker_role.toUpper()));

            // MTM (Marks) and MTM (Market) - compute using same forward pricing (options use same RPC)
            auto initMtmItem = []() {
                QTableWidgetItem* item = new QTableWidgetItem(QStringLiteral("--"));
                item->setForeground(QBrush(QColor(158, 158, 158)));
                item->setTextAlignment(Qt::AlignCenter | Qt::AlignVCenter);
                return item;
            };

            QTableWidgetItem* mtmMarksItem = initMtmItem();
            targetTable->setItem(row, 2, mtmMarksItem);

            QTableWidgetItem* mtmMarketItem = initMtmItem();
            targetTable->setItem(row, 3, mtmMarketItem);

            // Build inline terms for pricing.forward.quote (options use same RPC)
            QVariantMap inlineTerms;
            inlineTerms["long_party_deliver_asset"] = info.long_deliver_asset_id.isEmpty() ? "" : info.long_deliver_asset_id;
            inlineTerms["long_party_deliver_is_native"] = info.long_deliver_asset_id.isEmpty();
            inlineTerms["long_party_deliver_units"] = static_cast<qulonglong>(info.long_deliver_qty * 1e8);
            inlineTerms["short_party_deliver_asset"] = info.short_deliver_asset_id.isEmpty() ? "" : info.short_deliver_asset_id;
            inlineTerms["short_party_deliver_is_native"] = info.short_deliver_asset_id.isEmpty();
            inlineTerms["short_party_deliver_units"] = static_cast<qulonglong>(info.short_deliver_qty * 1e8);
            inlineTerms["long_party_margin_asset"] = info.long_margin_asset_id.isEmpty() ? "" : info.long_margin_asset_id;
            inlineTerms["long_party_margin_is_native"] = info.long_margin_asset_id.isEmpty();
            inlineTerms["long_party_margin_units"] = static_cast<qulonglong>(info.long_margin_qty * 1e8);
            inlineTerms["short_party_margin_asset"] = info.short_margin_asset_id.isEmpty() ? "" : info.short_margin_asset_id;
            inlineTerms["short_party_margin_is_native"] = info.short_margin_asset_id.isEmpty();
            inlineTerms["short_party_margin_units"] = static_cast<qulonglong>(info.short_margin_qty * 1e8);
            // Premium (must provide valid values - RPC rejects empty string for premium_asset)
            if (!info.premium_asset_id.isEmpty()) {
                inlineTerms["premium_asset"] = info.premium_asset_id;
                inlineTerms["premium_is_native"] = false;
            } else {
                // No premium asset or native premium - use native
                inlineTerms["premium_is_native"] = true;
            }
            inlineTerms["premium_units"] = static_cast<qulonglong>(info.premium_amount * 1e8);
            inlineTerms["deadline_short"] = info.deadline_short;
            inlineTerms["safety_k"] = info.safety_k > 0 ? info.safety_k : 144;

            scheduleForwardMtmUpdate(targetTable, row, info, inlineTerms);

            // Long deliver leg: "Qty Asset" format
            QString longDeliverText;
            if (info.long_deliver_qty > 0) {
                longDeliverText = QString("%1 %2")
                    .arg(QString::number(info.long_deliver_qty, 'f', info.long_deliver_qty < 1.0 ? 8 : 2))
                    .arg(info.long_deliver_asset.isEmpty() ? tr("TSC") : info.long_deliver_asset);
            } else {
                longDeliverText = info.long_deliver_asset.isEmpty() ? tr("TBD") : info.long_deliver_asset;
            }
            targetTable->setItem(row, 4, new NumericTableWidgetItem(longDeliverText, info.long_deliver_qty));

            // Short deliver leg: "Qty Asset" format
            QString shortDeliverText;
            if (info.short_deliver_qty > 0) {
                shortDeliverText = QString("%1 %2")
                    .arg(QString::number(info.short_deliver_qty, 'f', info.short_deliver_qty < 1.0 ? 8 : 2))
                    .arg(info.short_deliver_asset.isEmpty() ? tr("TSC") : info.short_deliver_asset);
            } else {
                shortDeliverText = info.short_deliver_asset.isEmpty() ? tr("TBD") : info.short_deliver_asset;
            }
            targetTable->setItem(row, 5, new NumericTableWidgetItem(shortDeliverText, info.short_deliver_qty));

            // Premium with asset
            QString premiumText;
            if (info.premium_amount > 0) {
                premiumText = QString("%1 %2")
                    .arg(QString::number(info.premium_amount, 'f', info.premium_amount < 1.0 ? 8 : 2))
                    .arg(info.premium_asset.isEmpty() ? tr("TSC") : info.premium_asset);
            } else {
                premiumText = tr("-");
            }
            targetTable->setItem(row, 6, new NumericTableWidgetItem(premiumText, info.premium_amount));

            targetTable->setItem(row, 7, new QTableWidgetItem(
                info.premium_payer.isEmpty() ? tr("-") : info.premium_payer.toUpper()));

            // Tenor: show deadline spread (short → long)
            QString tenorText;
            if (info.deadline_short > 0 && info.deadline_long > 0) {
                int currentHeight = walletModel
                    ? walletModel->clientModel().node().getNumBlocks() : 0;
                int tenorDaysShort = std::max(0, (info.deadline_short - currentHeight) / 144);
                int tenorDaysLong = std::max(0, (info.deadline_long - currentHeight) / 144);
                tenorText = QString("%1d - %2d").arg(tenorDaysShort).arg(tenorDaysLong);
            } else {
                tenorText = QString::number(info.tenor_days) + "d";
            }
            targetTable->setItem(row, 8, new QTableWidgetItem(tenorText));

            targetTable->setItem(row, 9, new NumericTableWidgetItem(
                formatTimestamp(info.created_at), static_cast<double>(info.created_at)));

            // Proof of Funds (column 10) - same logic as forward
            QTableWidgetItem* proofItem = nullptr;
            QString proofStatus;
            if (info.proof_verified) {
                // Determine required amount based on maker role
                uint64_t requiredAmount = 0;
                QString requiredAssetId;  // Use asset_id instead of label
                bool assetMatches = false;

                if (info.maker_role.toLower() == "long") {
                    // Long needs to prove IM only + premium if payer (NOT deliver - options are for assets you don't have!)
                    double totalRequired = info.long_margin_qty;
                    if (info.premium_payer.toLower() == "long") {
                        totalRequired += info.premium_amount;
                    }
                    requiredAmount = static_cast<uint64_t>(totalRequired * 1e8);
                    requiredAssetId = info.long_margin_asset_id;  // Use IM asset_id (empty = native)
                } else if (info.maker_role.toLower() == "short") {
                    // Short needs to prove IM only + premium if payer (NOT deliver - options are for assets you don't have!)
                    double totalRequired = info.short_margin_qty;
                    if (info.premium_payer.toLower() == "short") {
                        totalRequired += info.premium_amount;
                    }
                    requiredAmount = static_cast<uint64_t>(totalRequired * 1e8);
                    requiredAssetId = info.short_margin_asset_id;  // Use IM asset_id (empty = native)
                }

                // Normalize: empty asset_id means native TSC
                QString normalizedProofAsset = info.proof_verified_asset.isEmpty() ? QString() : info.proof_verified_asset;
                QString normalizedRequiredAsset = requiredAssetId.isEmpty() ? QString() : requiredAssetId;

                // Both empty = both native = match, OR both same non-empty asset_id = match
                assetMatches = (normalizedProofAsset.isEmpty() && normalizedRequiredAsset.isEmpty()) ||
                               (normalizedProofAsset == normalizedRequiredAsset);

                bool sufficient = assetMatches && (info.proof_verified_units >= requiredAmount);

                if (sufficient) {
                    proofStatus = QString("✓");
                    proofItem = new QTableWidgetItem(proofStatus);
                    proofItem->setForeground(QBrush(QColor(76, 175, 80)));  // Green
                    proofItem->setToolTip(tr("Verified: %1 units (sufficient)")
                        .arg(info.proof_verified_units));
                } else {
                    proofStatus = QString("⚠");
                    proofItem = new QTableWidgetItem(proofStatus);
                    proofItem->setForeground(QBrush(QColor(255, 152, 0)));  // Orange
                    proofItem->setToolTip(tr("Verified but INSUFFICIENT: %1 units (need %2)")
                        .arg(info.proof_verified_units)
                        .arg(requiredAmount));
                }
            } else if (!info.proof_verification_error.isEmpty()) {
                proofStatus = QString("✗");
                proofItem = new QTableWidgetItem(proofStatus);
                proofItem->setForeground(QBrush(QColor(244, 67, 54)));  // Red
                proofItem->setToolTip(tr("Proof verification FAILED: %1").arg(info.proof_verification_error));
            } else {
                proofStatus = QString("-");
                proofItem = new QTableWidgetItem(proofStatus);
                proofItem->setToolTip(tr("No proof provided"));
            }
            targetTable->setItem(row, 10, proofItem);

        } else if (currentContractType == "spot") {
            // Spot: Maker, MTM (Marks), MTM (Market), Asset Send, Amount Send, Asset Recv, Amount Recv, Price, Funds Verified, Actions
            QTableWidgetItem* makerItem = new QTableWidgetItem(formatPubkey(info.maker_pubkey));
            makerItem->setData(Qt::UserRole, info.offer_id);  // Store full offer_id for double-click
            targetTable->setItem(row, 0, makerItem);

            // MTM (Marks) and MTM (Market) - compute using trivial FX
            auto initMtmItem = []() {
                QTableWidgetItem* item = new QTableWidgetItem(QStringLiteral("--"));
                item->setForeground(QBrush(QColor(158, 158, 158)));
                item->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
                return item;
            };

            QTableWidgetItem* mtmMarksItem = initMtmItem();
            targetTable->setItem(row, 1, mtmMarksItem);

            QTableWidgetItem* mtmMarketItem = initMtmItem();
            targetTable->setItem(row, 2, mtmMarketItem);

            // Calculate spot MTM (trivial FX calculation)
            scheduleSpotMtmUpdate(targetTable, row, info);

            // Asset Send
            targetTable->setItem(row, 3, new QTableWidgetItem(info.asset_send.isEmpty() ? "TSC" : info.asset_send));

            // Amount Send
            targetTable->setItem(row, 4, new NumericTableWidgetItem(
                QString::number(info.amount, 'f', info.amount < 1.0 ? 8 : 2), info.amount));

            // Asset Recv
            targetTable->setItem(row, 5, new QTableWidgetItem(info.asset_recv.isEmpty() ? "TSC" : info.asset_recv));

            // Amount Recv (computed from price * amount)
            double amountRecv = info.amount * info.price;
            targetTable->setItem(row, 6, new NumericTableWidgetItem(
                QString::number(amountRecv, 'f', amountRecv < 1.0 ? 8 : 2), amountRecv));

            // Price (exchange rate)
            targetTable->setItem(row, 7, new NumericTableWidgetItem(
                QString::number(info.price, 'f', 8), info.price));

            // Funds Verified (column 8) - check proof-of-funds for spot contracts
            QTableWidgetItem* proofItem = nullptr;
            QString proofStatus;
            if (info.proof_of_funds.isEmpty()) {
                proofStatus = "-";
                proofItem = new QTableWidgetItem(proofStatus);
                proofItem->setForeground(QBrush(QColor(158, 158, 158)));  // Gray
                proofItem->setToolTip(tr("No proof provided"));
            } else if (info.proof_verified) {
                // Proofs verified - check sufficiency based on maker role
                uint64_t requiredAmount = 0;
                QString requiredAssetId;
                bool requirementKnown = false;

                if (info.maker_role.toLower() == "alice") {
                    // Alice needs to prove alice_leg funds
                    requiredAmount = static_cast<uint64_t>(info.alice_send_units);
                    requiredAssetId = info.alice_send_asset_id;  // Empty for native
                    requirementKnown = true;
                } else if (info.maker_role.toLower() == "bob") {
                    // Bob needs to prove bob_leg funds
                    requiredAmount = static_cast<uint64_t>(info.bob_send_units);
                    requiredAssetId = info.bob_send_asset_id;  // Empty for native
                    requirementKnown = true;
                }

                bool sufficient = true;
                if (requirementKnown) {
                    // Normalize asset IDs: empty means native
                    QString normalizedProofAsset = info.proof_verified_asset.isEmpty() ? QString() : info.proof_verified_asset;
                    QString normalizedRequiredAsset = requiredAssetId.isEmpty() ? QString() : requiredAssetId;

                    bool assetMatches = (normalizedProofAsset.isEmpty() && normalizedRequiredAsset.isEmpty()) ||
                                       (normalizedProofAsset == normalizedRequiredAsset);
                    sufficient = assetMatches && (info.proof_verified_units >= requiredAmount);

                    LogPrintf("TradeBoardTab: Spot proof sufficiency - offer=%s, role=%s, required=%llu, verified=%llu, asset_match=%d, sufficient=%d\n",
                             info.offer_id.toStdString().c_str(), info.maker_role.toStdString().c_str(),
                             requiredAmount, info.proof_verified_units, assetMatches, sufficient);
                }

                if (sufficient) {
                    proofStatus = QString("✓");
                    proofItem = new QTableWidgetItem(proofStatus);
                    proofItem->setForeground(QBrush(QColor(76, 175, 80)));  // Green
                    proofItem->setToolTip(tr("Verified: %1 units (sufficient)")
                        .arg(info.proof_verified_units));
                } else {
                    proofStatus = QString("⚠");
                    proofItem = new QTableWidgetItem(proofStatus);
                    proofItem->setForeground(QBrush(QColor(255, 152, 0)));  // Orange
                    proofItem->setToolTip(tr("Verified but INSUFFICIENT: %1 units (need %2)")
                        .arg(info.proof_verified_units)
                        .arg(requiredAmount));
                }
            } else if (!info.proof_verification_error.isEmpty()) {
                proofStatus = QString("✗");
                proofItem = new QTableWidgetItem(proofStatus);
                proofItem->setForeground(QBrush(QColor(244, 67, 54)));  // Red
                proofItem->setToolTip(tr("Proof verification FAILED: %1").arg(info.proof_verification_error));
            } else {
                proofStatus = QString("-");
                proofItem = new QTableWidgetItem(proofStatus);
                proofItem->setToolTip(tr("No proof provided"));
            }
            targetTable->setItem(row, 8, proofItem);
        } else if (currentContractType == "difficulty") {
            // Difficulty: Maker, Role, Product, Strike, Fixing→Settle, IM, λ, Premium, MTM, Funds, Age, Actions
            const QVariantMap& terms = info.term_sheet_terms;
            const QVariantMap& metrics = info.term_sheet_metrics;
            const bool isOption = terms.value("kind").toString() == "option";

            QTableWidgetItem* makerItem = new QTableWidgetItem(formatPubkey(info.maker_pubkey));
            makerItem->setData(Qt::UserRole, info.offer_id);
            targetTable->setItem(row, 0, makerItem);
            targetTable->setItem(row, 1, new QTableWidgetItem(info.maker_role.toUpper()));
            targetTable->setItem(row, 2, new QTableWidgetItem(isOption ? tr("Option") : tr("CFD")));
            // Strike shown as human-meaningful throughput (tok/s); raw nBits kept in the tooltip.
            const QString strikeNbitsStr = terms.value("strike_nbits").toString().trimmed();
            bool strikeOk = false;
            const uint32_t strikeNbits = strikeNbitsStr.toUInt(&strikeOk, 16);
            QString strikeText = strikeNbitsStr;  // fallback to raw nBits if unparseable
            if (strikeOk && strikeNbits != 0) {
                strikeText = QString::fromStdString(
                    wallet::DifficultyFormatTokensPerSec(wallet::DifficultyNBitsToTokensPerSec(strikeNbits)));
            }
            auto* strikeItem = new QTableWidgetItem(strikeText);
            strikeItem->setToolTip(tr("Strike nBits: %1").arg(strikeNbitsStr));
            targetTable->setItem(row, 3, strikeItem);

            const qlonglong fixing = terms.value("fixing_height").toLongLong();
            const qlonglong settle = terms.value("settle_lock_height").toLongLong();
            targetTable->setItem(row, 4, new QTableWidgetItem(QStringLiteral("%1→%2").arg(fixing).arg(settle)));

            QString imStr, lambdaStr, premiumStr;
            if (isOption) {
                imStr = QString::number(terms.value("im_tsc").toDouble(), 'f', 8) + " TSC";
                lambdaStr = QString::number(terms.value("lambda").toDouble(), 'f', 2);
                premiumStr = QString::number(terms.value("premium_tsc").toDouble(), 'f', 8) + " TSC";
            } else {
                const QVariantMap lo = terms.value("long").toMap();
                const QVariantMap so = terms.value("short").toMap();
                imStr = QStringLiteral("L %1 / S %2 TSC")
                    .arg(QString::number(lo.value("im_tsc").toDouble(), 'f', 4),
                         QString::number(so.value("im_tsc").toDouble(), 'f', 4));
                lambdaStr = QStringLiteral("L %1 / S %2")
                    .arg(QString::number(lo.value("lambda").toDouble(), 'f', 1),
                         QString::number(so.value("lambda").toDouble(), 'f', 1));
                premiumStr = QStringLiteral("-");
            }
            targetTable->setItem(row, 5, new QTableWidgetItem(imStr));
            targetTable->setItem(row, 6, new QTableWidgetItem(lambdaStr));
            targetTable->setItem(row, 7, new QTableWidgetItem(premiumStr));

            // MTM from the term-sheet metrics block (native atomic units -> TSC), shown from the
            // MAKER's perspective so the sign matches their role (writer/buyer, long/short).
            QString mtmStr = QStringLiteral("--");
            if (metrics.value("priced").toBool()) {
                const QString role = info.maker_role.toLower();
                QString mtmKey;
                if (isOption) {
                    mtmKey = (role == "buyer") ? "expected_buyer_mtm" : "expected_writer_mtm";
                } else {
                    mtmKey = (role == "short") ? "expected_short_mtm" : "expected_long_mtm";
                }
                if (metrics.contains(mtmKey)) {
                    const double mtmSats = metrics.value(mtmKey).toDouble();
                    mtmStr = QString::number(mtmSats / 1e8, 'f', 8) + " TSC";
                }
            }
            QTableWidgetItem* mtmItem = new QTableWidgetItem(mtmStr);
            mtmItem->setForeground(QBrush(QColor(158, 158, 158)));
            mtmItem->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
            targetTable->setItem(row, 8, mtmItem);

            QTableWidgetItem* dProofItem = new QTableWidgetItem(
                info.proof_verified ? QStringLiteral("✓")
                                    : (info.proof_of_funds.isEmpty() ? QStringLiteral("-") : QStringLiteral("…")));
            if (info.proof_verified) dProofItem->setForeground(QBrush(QColor(76, 175, 80)));
            targetTable->setItem(row, 9, dProofItem);

            targetTable->setItem(row, 10, new NumericTableWidgetItem(
                formatTimestamp(info.created_at), static_cast<double>(info.created_at)));
        }

        // Add "Request Trade" or "Delete" button based on ownership (last column for all types)
        int actionCol = targetTable->columnCount() - 1;
        QWidget* actionWidget = new QWidget(this);
        QHBoxLayout* actionLayout = new QHBoxLayout();
        actionLayout->setContentsMargins(0, 0, 0, 0);
        actionLayout->setSpacing(6);

        // Check if this is our own offer
        if (info.maker_pubkey == bbPubkey) {
            LogPrintf("TradeBoardTab::updateOffersList() Creating DELETE button for own offer %s\n",
                info.offer_id.toStdString().c_str());
            QPushButton* deleteBtn = new QPushButton(tr("Delete"), actionWidget);
            deleteBtn->setProperty("offer_id", info.offer_id);
            connect(deleteBtn, &QPushButton::clicked, this, &TradeBoardTab::onDeleteOffer);
            actionLayout->addWidget(deleteBtn);
        } else {
            LogPrintf("TradeBoardTab::updateOffersList() Creating REQUEST TRADE button for offer %s\n",
                info.offer_id.toStdString().c_str());
            QPushButton* requestBtn = new QPushButton(tr("Request Trade"), actionWidget);
            requestBtn->setProperty("offer_id", info.offer_id);
            connect(requestBtn, &QPushButton::clicked, this, &TradeBoardTab::onRequestTrade);
            actionLayout->addWidget(requestBtn);
        }

        actionWidget->setLayout(actionLayout);
        targetTable->setCellWidget(row, actionCol, actionWidget);
    }

    // Re-enable sorting
    repoTable->setSortingEnabled(repoSorting);
    forwardTable->setSortingEnabled(forwardSorting);
    optionsTable->setSortingEnabled(optionsSorting);
    spotTable->setSortingEnabled(spotSorting);
    crossChainTable->setSortingEnabled(crossChainSorting);
    difficultyTable->setSortingEnabled(difficultySorting);

    // Populate cross-chain table from bridge listing (separate from normal BB offers)
    if (currentContractType == "cross_chain" && walletModel) {
        auto xcResult = walletModel->crossChainListOffers();
        if (xcResult.success) {
            crossChainTable->setSortingEnabled(false);
            for (const auto& offer : xcResult.offers) {
                int row = crossChainTable->rowCount();
                crossChainTable->insertRow(row);

                QTableWidgetItem* makerItem = new QTableWidgetItem(
                    offer.maker_pubkey.left(12) + "...");
                makerItem->setData(Qt::UserRole, offer.offer_id);
                crossChainTable->setItem(row, 0, makerItem);

                // WalletModel flattens the payload: external_chain, external_asset,
                // external_units, tsc_units, adapter, funding_order (no nesting)
                QVariantMap payload = offer.payload;

                QString chain = payload.value("external_chain").toString().toUpper();
                if (chain == "ETHEREUM") chain = "ETH";
                crossChainTable->setItem(row, 1, new QTableWidgetItem(chain));
                crossChainTable->setItem(row, 2, new QTableWidgetItem(
                    payload.value("adapter").toString()));

                crossChainTable->setItem(row, 3, new QTableWidgetItem(
                    payload.value("tsc_units").toString()));
                crossChainTable->setItem(row, 4, new QTableWidgetItem(
                    payload.value("external_units").toString()));
                crossChainTable->setItem(row, 5, new QTableWidgetItem(
                    payload.value("external_asset").toString()));
                crossChainTable->setItem(row, 6, new QTableWidgetItem(
                    payload.value("funding_order").toString()));

                QPushButton* viewBtn = new QPushButton(tr("View"), crossChainTable);
                viewBtn->setStyleSheet("QPushButton { padding: 2px 8px; }");
                crossChainTable->setCellWidget(row, 7, viewBtn);

                // Show full payload JSON on click
                QString rawJson = payload.value("_raw_json").toString();
                QString offerId = offer.offer_id;
                QPointer<TradeBoardTab> safeThis(this);
                connect(viewBtn, &QPushButton::clicked, this, [safeThis, offerId, rawJson, payload]() {
                    if (!safeThis) return;

                    QString chain = payload.value("external_chain").toString().toUpper();
                    if (chain == "ETHEREUM") chain = "ETH";

                    QString details;
                    details += QString("<h3>Cross-Chain Offer %1</h3>").arg(offerId.left(12) + "...");
                    details += QString("<h4>Trade</h4><ul>");
                    details += QString("<li><b>TSC Units:</b> %1</li>").arg(payload.value("tsc_units").toString());
                    details += QString("<li><b>External:</b> %1 %2 on %3</li>")
                        .arg(payload.value("external_units").toString(),
                             payload.value("external_asset").toString(), chain);
                    details += QString("<li><b>Adapter:</b> %1</li>").arg(payload.value("adapter").toString());
                    details += QString("<li><b>Funding Order:</b> %1</li>").arg(payload.value("funding_order").toString());
                    details += QString("</ul>");

                    if (payload.contains("settlement_address")) {
                        details += QString("<h4>Settlement</h4><ul>");
                        details += QString("<li><b>Address:</b> <code>%1</code></li>")
                            .arg(payload.value("settlement_address").toString());
                        details += QString("</ul>");
                    }

                    if (payload.contains("external_min_conf")) {
                        details += QString("<h4>Confirmation Policy</h4><ul>");
                        details += QString("<li><b>External min:</b> %1</li>").arg(payload.value("external_min_conf").toInt());
                        details += QString("<li><b>TSC min:</b> %1</li>").arg(payload.value("tsc_min_conf").toInt());
                        details += QString("<li><b>Reorg conf:</b> %1</li>").arg(payload.value("reorg_conf").toInt());
                        details += QString("</ul>");
                    }

                    if (payload.contains("external_lock_seconds")) {
                        details += QString("<h4>Timeout Policy</h4><ul>");
                        details += QString("<li><b>External lock:</b> %1s</li>").arg(payload.value("external_lock_seconds").toLongLong());
                        details += QString("<li><b>TSC lock:</b> %1 blocks</li>").arg(payload.value("tsc_lock_blocks").toInt());
                        details += QString("<li><b>Claim budget:</b> %1s</li>").arg(payload.value("claim_budget_seconds").toLongLong());
                        details += QString("<li><b>Reorg margin:</b> %1s</li>").arg(payload.value("reorg_margin_seconds").toLongLong());
                        details += QString("</ul>");
                    }

                    QDialog dialog(safeThis);
                    dialog.setWindowTitle(QObject::tr("Cross-Chain Offer Details"));
                    dialog.setMinimumSize(500, 400);
                    QVBoxLayout* layout = new QVBoxLayout(&dialog);

                    QTextEdit* textEdit = new QTextEdit(&dialog);
                    textEdit->setReadOnly(true);
                    textEdit->setHtml(details);
                    layout->addWidget(textEdit);

                    QPushButton* jsonBtn = new QPushButton(QObject::tr("Show Raw JSON"), &dialog);
                    QObject::connect(jsonBtn, &QPushButton::clicked, &dialog, [textEdit, rawJson]() {
                        // Pretty-print the raw JSON
                        QJsonDocument doc = QJsonDocument::fromJson(rawJson.toUtf8());
                        textEdit->setPlainText(doc.isNull() ? rawJson : QString::fromUtf8(doc.toJson(QJsonDocument::Indented)));
                    });
                    layout->addWidget(jsonBtn);

                    QPushButton* closeBtn = new QPushButton(QObject::tr("Close"), &dialog);
                    QObject::connect(closeBtn, &QPushButton::clicked, &dialog, &QDialog::accept);
                    layout->addWidget(closeBtn);

                    dialog.exec();
                });
            }
            crossChainTable->setSortingEnabled(crossChainSorting);
        }
    }
}

void TradeBoardTab::pauseUpdateTimers()
{
    if (offersUpdateTimer) {
        offersUpdateTimer->stop();
    }
    if (requestsUpdateTimer) {
        requestsUpdateTimer->stop();
    }
    LogPrintf("TradeBoardTab: Paused update timers for modal dialog safety\n");
}

void TradeBoardTab::resumeUpdateTimers()
{
    if (offersUpdateTimer) {
        offersUpdateTimer->start(30000);  // 30 seconds
    }
    if (requestsUpdateTimer) {
        requestsUpdateTimer->start(5000);  // 5 seconds
    }
    LogPrintf("TradeBoardTab: Resumed update timers\n");

    // If a fetch completed while a modal was open, renderOffers() dropped it for
    // crash-safety (see renderOffers()). The modal has now closed, so re-fetch and
    // render so the tables reflect the latest state immediately rather than after
    // the next 30s tick.
    if (m_offersRenderDeferredByModal) {
        m_offersRenderDeferredByModal = false;
        LogPrintf("TradeBoardTab: re-dispatching offers refresh deferred during modal\n");
        updateOffersList();
    }
}

void TradeBoardTab::updateTradeRequestsList()
{
    // CRITICAL: do NOT gate this on isVisible(). This path drives both the
    // trade-DM fetch (via cosign.list_requests -> fetch_dms) and auto-join
    // (checkForAutoJoin below). If the user is on any other tab, accept-DMs
    // from counterparties would silently never get pulled and SPAKE2 sessions
    // would never get joined. Protocol liveness must not depend on UI focus.
    if (!walletModel) return;
    if (!bbInitialized) return;

    // Coalesce concurrent calls: if a fetch is already in flight, record that
    // another refresh is wanted and return. The in-flight continuation re-dispatches
    // so a caller that just mutated state (reject/cancel/accept, etc.) never loses
    // its refresh — preserving the DM-fetch / auto-join liveness contract above.
    if (m_tradeRequestsUpdateInFlight) {
        m_tradeRequestsUpdatePending = true;
        return;
    }
    m_tradeRequestsUpdateInFlight = true;

    // bulletinBoardListRequests() goes through cosign.list_requests -> fetch_dms
    // on the cosign bridge and blocks in poll() until the relay answers — that is
    // the sampled GUI-thread stall. Run it on a worker (touches only walletModel,
    // which is bridge-mutex-serialized / thread-safe; never `this`). InflightGuard
    // + parented QFutureWatcher give the same shutdown safety as the poll path.
    auto inflightGuard = std::make_shared<InflightGuard>(this);
    WalletModel* const wm = walletModel;
    auto* watcher = new QFutureWatcher<WalletModel::BulletinBoardListRequestsResult>(this);
    connect(watcher, &QFutureWatcher<WalletModel::BulletinBoardListRequestsResult>::finished, this, [this, watcher]() {
        watcher->deleteLater();
        renderTradeRequests(watcher->result());
        m_tradeRequestsUpdateInFlight = false;
        if (m_tradeRequestsUpdatePending) {
            m_tradeRequestsUpdatePending = false;
            updateTradeRequestsList();   // serve the coalesced refresh request(s)
        }
    });
    watcher->setFuture(QtConcurrent::run([wm, inflightGuard]() -> WalletModel::BulletinBoardListRequestsResult {
        (void)inflightGuard;  // keeps the guard alive for the duration of the body
        return wm->bulletinBoardListRequests("all");
    }));
}

// GUI-thread render half of updateTradeRequestsList(): rebuilds the requests
// table from the off-thread fetch result. `result` is taken by value to preserve
// the original local-variable (mutable) semantics of the synchronous version.
void TradeBoardTab::renderTradeRequests(WalletModel::BulletinBoardListRequestsResult result)
{
    bool previousSorting = requestsTable->isSortingEnabled();
    requestsTable->setSortingEnabled(false);

    if (!result.success) {
        // Don't show error on auto-refresh
        requestsTable->setSortingEnabled(previousSorting);
        return;
    }

    QMap<QString, TradeRequestInfo> previousRequests = activeRequests;

    requestsTable->setRowCount(0);
    activeRequests.clear();

    for (const QVariant& reqVar : result.requests) {
        QVariantMap request = reqVar.toMap();

        TradeRequestInfo info;
        info.request_id = request["request_id"].toString();
        info.offer_id = request["offer_id"].toString();
        info.direction = request["direction"].toString();
        info.maker_pubkey = request["maker_pubkey"].toString();
        info.taker_pubkey = request["taker_pubkey"].toString();
        info.counterparty_pubkey = request.value("counterparty_pubkey").toString();
        info.status = request["status"].toString();
        info.message = request.value("message").toString();
        info.timestamp = request.value("timestamp").toLongLong();
        info.updated_at = request.value("updated_at", QVariant::fromValue(info.timestamp)).toLongLong();
        info.invite_link = request["invite_link"].toString();
        info.invite_expires_at = request.value("invite_expires_at").toLongLong();
        info.offer_summary = request.value("offer").toMap();
        populateRepoTermsFromSummary(info, info.offer_summary);
        info.maker_role = info.offer_summary.value("maker_role").toString().toLower();
        info.contract_type = info.offer_summary.value("contract_type").toString().toLower();

        // Parse proof of funds
        if (request.contains("proof_of_funds") && request["proof_of_funds"].canConvert<QVariantList>()) {
            info.proof_of_funds = request["proof_of_funds"].toList();

            // Verify proofs on ingestion
            if (!info.proof_of_funds.isEmpty()) {
                try {
                    auto verifyResult = walletModel->verifyProofList(info.proof_of_funds);
                    info.proof_verified = verifyResult.all_verified;
                    info.proof_verified_units = verifyResult.total_verified_units;
                    info.proof_verified_asset = verifyResult.asset_id;
                    info.proof_verification_error = verifyResult.error;
                    info.proof_verified_at = QDateTime::currentSecsSinceEpoch();

                    if (!verifyResult.all_verified) {
                        LogPrintf("TradeBoardTab::updateTradeRequestsList() Proof verification FAILED for request %s: %s\n",
                            info.request_id.toStdString().c_str(),
                            verifyResult.error.toStdString().c_str());
                    }
                } catch (const UniValue& e) {
                    LogPrintf("TradeBoardTab::updateTradeRequestsList() UniValue exception during proof verification for request %s\n",
                        info.request_id.toStdString().c_str());
                    info.proof_verified = false;
                    info.proof_verification_error = "Verification error: UniValue exception";
                } catch (const std::exception& e) {
                    LogPrintf("TradeBoardTab::updateTradeRequestsList() Exception during proof verification for request %s: %s\n",
                        info.request_id.toStdString().c_str(), e.what());
                    info.proof_verified = false;
                    info.proof_verification_error = QString("Verification error: %1").arg(e.what());
                } catch (...) {
                    LogPrintf("TradeBoardTab::updateTradeRequestsList() Unknown exception during proof verification for request %s\n",
                        info.request_id.toStdString().c_str());
                    info.proof_verified = false;
                    info.proof_verification_error = "Unknown verification error";
                }
            }
        }

        if (info.counterparty_pubkey.isEmpty()) {
            info.counterparty_pubkey = info.direction == "incoming" ? info.taker_pubkey : info.maker_pubkey;
        }

        if (previousRequests.contains(info.request_id)) {
            const TradeRequestInfo& prev = previousRequests.value(info.request_id);
            info.auto_joined = prev.auto_joined;
            info.final_offer_processed = prev.final_offer_processed;
            info.final_offer_id = prev.final_offer_id;
            if (!prev.final_offer_json.isEmpty()) {
                info.final_offer_json = prev.final_offer_json;
                LogPrintf("TradeBoardTab: Restored cached final offer for request %s (offer_id=%s, bytes=%d)\n",
                          info.request_id.toStdString().c_str(),
                          prev.final_offer_id.toStdString().c_str(),
                          prev.final_offer_json.size());

                // FIX: Rehydrate canonical cache from restored finalized offer
                // Ensures cache persists across refreshes and wallet restarts
                QString contractType = prev.offer_summary.value("contract_type").toString().toLower();
                if (contractType.isEmpty()) {
                    contractType = prev.contract_type.toLower();
                }
                if (!contractType.isEmpty() && !prev.final_offer_id.isEmpty()) {
                    if (contractType == "options") contractType = QStringLiteral("option");
                    cacheContractFlavor(prev.final_offer_id, contractType, prev.final_offer_json, info.offer_id);
                    LogPrintf("TradeBoardTab::updateTradeRequestsList: Cache rehydration - contract_id=%s, bb_uuid=%s, type=%s\n",
                              prev.final_offer_id.toStdString().c_str(), info.offer_id.toStdString().c_str(), contractType.toStdString().c_str());
                }
            }
            info.ceremony_invite_sent = prev.ceremony_invite_sent;
            info.ceremony_ready_sent = prev.ceremony_ready_sent;
            info.taker_ready_for_ceremony = prev.taker_ready_for_ceremony;
            info.staged_local_base_ready = prev.staged_local_base_ready;
            info.staged_local_base_psbt = prev.staged_local_base_psbt;
            info.last_ceremony_invite = prev.last_ceremony_invite;
            info.waiting_for_base_notice_sent = prev.waiting_for_base_notice_sent;
            // Preserve addresses for ceremony (may be populated from finalized offer)
            if (!prev.borrower_address.isEmpty()) {
                info.borrower_address = prev.borrower_address;
            }
            if (!prev.lender_address.isEmpty()) {
                info.lender_address = prev.lender_address;
            }
            if (!prev.spot_alice_address.isEmpty()) {
                info.spot_alice_address = prev.spot_alice_address;
            }
            if (!prev.spot_bob_address.isEmpty()) {
                info.spot_bob_address = prev.spot_bob_address;
            }
            // Preserve maker_role if it was explicitly set during ceremony flow
            if (!prev.maker_role.isEmpty()) {
                info.maker_role = prev.maker_role;
            }
            // IMMUTABILITY GUARDS: Preserve augmented PSBT across UI refreshes
            if (!prev.maker_base_psbt.isEmpty()) {
                info.maker_base_psbt = prev.maker_base_psbt;
            }
            if (!prev.augmented_psbt.isEmpty()) {
                info.augmented_psbt = prev.augmented_psbt;
                info.augmented_psbt_hash = prev.augmented_psbt_hash;
                info.psbt_locked = prev.psbt_locked;
                LogPrintf("TradeBoardTab: Preserved immutable PSBT for request %s (hash=%s, locked=%d)\n",
                          info.request_id.toStdString().c_str(),
                          info.augmented_psbt_hash.toStdString().c_str(),
                          info.psbt_locked);
            }
            if (!info.terms_available && prev.terms_available) {
                info.principal_qty = prev.principal_qty;
                info.principal_asset = prev.principal_asset;
                info.collateral_qty = prev.collateral_qty;
                info.collateral_asset = prev.collateral_asset;
                info.interest_qty = prev.interest_qty;
                info.interest_asset = prev.interest_asset;
                info.apr = prev.apr;
                info.ltv = prev.ltv;
                info.tenor_days = prev.tenor_days;
                info.maturity_height = prev.maturity_height;
                info.terms_available = true;
            }
        }

        // Parse taker-supplied details (JSON message)
        if (!info.message.isEmpty()) {
            QJsonParseError detailError;
            const QJsonDocument messageDoc = QJsonDocument::fromJson(info.message.toUtf8(), &detailError);
            if (!messageDoc.isNull() && messageDoc.isObject()) {
                info.taker_message_json = info.message;
                const QJsonObject detailObj = messageDoc.object();
                QString schema = detailObj.value("schema").toString();

                if (schema == QLatin1String("repo_taker_details_v1")) {
                    // Only update addresses if provided in message (don't overwrite with empty strings)
                    QString msgBorrowerAddr = detailObj.value("borrower_address").toString();
                    QString msgLenderAddr = detailObj.value("lender_address").toString();
                    if (!msgBorrowerAddr.isEmpty()) {
                        info.borrower_address = msgBorrowerAddr;
                    }
                    if (!msgLenderAddr.isEmpty()) {
                        info.lender_address = msgLenderAddr;
                    }
                }
                else if (schema == QLatin1String("spot_taker_details_v1")) {
                    // Extract spot addresses from taker details (Bob is always taker in spot)
                    QString msgBobAddr = detailObj.value("bob_address").toString();
                    QString msgAliceAddr = detailObj.value("alice_address").toString();
                    if (!msgBobAddr.isEmpty()) {
                        info.spot_bob_address = msgBobAddr;
                        LogPrintf("TradeBoardTab: Spot taker provided bob_address=%s\n",
                                  msgBobAddr.toStdString().c_str());
                    }
                    if (!msgAliceAddr.isEmpty()) {
                        info.spot_alice_address = msgAliceAddr;
                        LogPrintf("TradeBoardTab: Spot taker provided alice_address=%s\n",
                                  msgAliceAddr.toStdString().c_str());
                    }
                }
                else if (schema == QLatin1String("forward_taker_details_v1") ||
                         schema == QLatin1String("option_taker_details_v1")) {
                    // Parse forward/options taker details
                    // Taker provides their role-specific addresses
                    QString takerRole = detailObj.value("taker_role").toString().toLower();

                    LogPrintf("TradeBoardTab: Parsing %s - taker_role=%s\n",
                              schema.toStdString().c_str(),
                              takerRole.toStdString().c_str());

                    if (takerRole == QLatin1String("long")) {
                        // Taker is long party - extract long addresses
                        QString longMarginDest = detailObj.value("long_margin_dest").toString();
                        QString longSettleDest = detailObj.value("long_settlement_receive_dest").toString();

                        if (!longMarginDest.isEmpty()) {
                            info.long_margin_dest = longMarginDest;
                            LogPrintf("TradeBoardTab: Taker (Long) margin_dest=%s\n",
                                      longMarginDest.toStdString().c_str());
                        }
                        if (!longSettleDest.isEmpty()) {
                            info.long_settlement_dest = longSettleDest;
                            LogPrintf("TradeBoardTab: Taker (Long) settlement_dest=%s\n",
                                      longSettleDest.toStdString().c_str());
                        }

                        // Validation: ensure addresses were provided
                        if (info.long_margin_dest.isEmpty() || info.long_settlement_dest.isEmpty()) {
                            LogPrintf("TradeBoardTab: WARNING - Taker (Long) provided incomplete addresses: "
                                      "margin_dest=%s, settlement_dest=%s\n",
                                      info.long_margin_dest.toStdString().c_str(),
                                      info.long_settlement_dest.toStdString().c_str());
                        }
                    }
                    else if (takerRole == QLatin1String("short")) {
                        // Taker is short party - extract short addresses
                        QString shortMarginDest = detailObj.value("short_margin_dest").toString();
                        QString shortSettleDest = detailObj.value("short_settlement_receive_dest").toString();

                        if (!shortMarginDest.isEmpty()) {
                            info.short_margin_dest = shortMarginDest;
                            LogPrintf("TradeBoardTab: Taker (Short) margin_dest=%s\n",
                                      shortMarginDest.toStdString().c_str());
                        }
                        if (!shortSettleDest.isEmpty()) {
                            info.short_settlement_dest = shortSettleDest;
                            LogPrintf("TradeBoardTab: Taker (Short) settlement_dest=%s\n",
                                      shortSettleDest.toStdString().c_str());
                        }

                        // Validation: ensure addresses were provided
                        if (info.short_margin_dest.isEmpty() || info.short_settlement_dest.isEmpty()) {
                            LogPrintf("TradeBoardTab: WARNING - Taker (Short) provided incomplete addresses: "
                                      "margin_dest=%s, settlement_dest=%s\n",
                                      info.short_margin_dest.toStdString().c_str(),
                                      info.short_settlement_dest.toStdString().c_str());
                        }
                    }
                    else {
                        LogPrintf("TradeBoardTab: ERROR - Invalid or missing taker_role in %s: '%s'\n",
                                  schema.toStdString().c_str(),
                                  takerRole.toStdString().c_str());
                    }

                    // Parse premium payee address (if taker receives premium)
                    if (detailObj.contains("premium_payee_dest")) {
                        QString premiumPayeeDest = detailObj.value("premium_payee_dest").toString();
                        if (!premiumPayeeDest.isEmpty()) {
                            info.premium_payee_dest = premiumPayeeDest;
                            LogPrintf("TradeBoardTab: Taker provided premium_payee_dest=%s\n",
                                      premiumPayeeDest.toStdString().c_str());
                        }
                    }

                    // Parse and verify proofs of funds (if provided in taker details)
                    if (detailObj.contains("proofs") && detailObj.value("proofs").isArray()) {
                        QJsonArray proofsArray = detailObj.value("proofs").toArray();
                        QVariantList proofsList;
                        for (const QJsonValue& proofVal : proofsArray) {
                            if (proofVal.isObject()) {
                                proofsList.append(proofVal.toObject().toVariantMap());
                            }
                        }

                        if (!proofsList.isEmpty()) {
                            info.proof_of_funds = proofsList;

                            // Verify proofs immediately
                            try {
                                auto verifyResult = walletModel->verifyProofList(proofsList);
                                info.proof_verified = verifyResult.all_verified;
                                info.proof_verified_units = verifyResult.total_verified_units;
                                info.proof_verified_asset = verifyResult.asset_id;
                                info.proof_verification_error = verifyResult.error;
                                info.proof_verified_at = QDateTime::currentSecsSinceEpoch();

                                LogPrintf("TradeBoardTab: Forward taker proofs verified=%s, units=%llu, asset=%s\n",
                                          info.proof_verified ? "YES" : "NO",
                                          info.proof_verified_units,
                                          info.proof_verified_asset.toStdString().c_str());

                                if (!verifyResult.all_verified) {
                                    LogPrintf("TradeBoardTab: Forward taker proof verification FAILED: %s\n",
                                              verifyResult.error.toStdString().c_str());
                                }
                            } catch (const UniValue& e) {
                                LogPrintf("TradeBoardTab: UniValue exception during forward taker proof verification\n");
                                info.proof_verified = false;
                                info.proof_verification_error = "Verification error: UniValue exception";
                            } catch (const std::exception& e) {
                                LogPrintf("TradeBoardTab: Exception during forward taker proof verification: %s\n", e.what());
                                info.proof_verified = false;
                                info.proof_verification_error = QString("Verification error: %1").arg(e.what());
                            } catch (...) {
                                LogPrintf("TradeBoardTab: Unknown exception during forward taker proof verification\n");
                                info.proof_verified = false;
                                info.proof_verification_error = "Unknown verification error";
                            }
                        }
                    }
                }
            }
        }

        int row = requestsTable->rowCount();
        requestsTable->insertRow(row);

        // Try to enrich offer_summary with data from activeOffers if available
        QVariantMap enrichedOfferSummary = info.offer_summary;
        if (activeOffers.contains(info.offer_id)) {
            const OfferInfo& fullOffer = activeOffers[info.offer_id];
            enrichedOfferSummary["contract_type"] = fullOffer.contract_type;
            enrichedOfferSummary["contract_payload"] = fullOffer.contract_payload;
            enrichedOfferSummary["maker_role"] = fullOffer.maker_role;
            if (!fullOffer.maker_role.isEmpty()) {
                info.maker_role = fullOffer.maker_role.toLower();
            }
            QVariantMap offerTerms = fullOffer.term_sheet_terms;

            // Determine contract type for enrichment
            QString contractType = fullOffer.contract_type.toLower();

            if (contractType == "forward" || contractType == "option" || contractType == "options") {
                // Forward/Options enrichment
                offerTerms["long_deliver_amount"] = fullOffer.long_deliver_qty;
                offerTerms["long_deliver_asset"] = fullOffer.long_deliver_asset;
                offerTerms["short_deliver_amount"] = fullOffer.short_deliver_qty;
                offerTerms["short_deliver_asset"] = fullOffer.short_deliver_asset;
                offerTerms["long_im_amount"] = fullOffer.long_margin_qty;
                offerTerms["long_im_asset"] = fullOffer.long_margin_asset;
                offerTerms["short_im_amount"] = fullOffer.short_margin_qty;
                offerTerms["short_im_asset"] = fullOffer.short_margin_asset;
                offerTerms["long_im_percent"] = fullOffer.long_im_percent;
                offerTerms["short_im_percent"] = fullOffer.short_im_percent;
                offerTerms["premium_amount"] = fullOffer.premium_amount;
                offerTerms["premium_asset"] = fullOffer.premium_asset;
                offerTerms["premium_payer"] = fullOffer.premium_payer;
                offerTerms["tenor_days"] = fullOffer.tenor_days;
                offerTerms["tenor_days_short"] = fullOffer.tenor_days_short;
                offerTerms["tenor_days_long"] = fullOffer.tenor_days_long;
                offerTerms["deadline_short"] = fullOffer.deadline_short;
                offerTerms["deadline_long"] = fullOffer.deadline_long;

                // Copy to info for display
                info.long_deliver_qty = fullOffer.long_deliver_qty;
                info.long_deliver_asset = fullOffer.long_deliver_asset;
                info.short_deliver_qty = fullOffer.short_deliver_qty;
                info.short_deliver_asset = fullOffer.short_deliver_asset;
                info.long_margin_qty = fullOffer.long_margin_qty;
                info.long_margin_asset = fullOffer.long_margin_asset;
                info.short_margin_qty = fullOffer.short_margin_qty;
                info.short_margin_asset = fullOffer.short_margin_asset;
                info.long_im_percent = fullOffer.long_im_percent;
                info.short_im_percent = fullOffer.short_im_percent;
                info.premium_amount = fullOffer.premium_amount;
                info.premium_asset = fullOffer.premium_asset;
                info.premium_payer = fullOffer.premium_payer;
                info.tenor_days = fullOffer.tenor_days;
                info.tenor_days_short = fullOffer.tenor_days_short;
                info.tenor_days_long = fullOffer.tenor_days_long;
                info.deadline_short = fullOffer.deadline_short;
                info.deadline_long = fullOffer.deadline_long;
                info.terms_available = true;

                // CRITICAL: Also add to enrichedOfferSummary for formatOfferSummary to use
                enrichedOfferSummary["long_deliver_amount"] = fullOffer.long_deliver_qty;
                enrichedOfferSummary["long_deliver_asset"] = fullOffer.long_deliver_asset;
                enrichedOfferSummary["short_deliver_amount"] = fullOffer.short_deliver_qty;
                enrichedOfferSummary["short_deliver_asset"] = fullOffer.short_deliver_asset;
                enrichedOfferSummary["long_im_amount"] = fullOffer.long_margin_qty;
                enrichedOfferSummary["long_im_asset"] = fullOffer.long_margin_asset;
                enrichedOfferSummary["short_im_amount"] = fullOffer.short_margin_qty;
                enrichedOfferSummary["short_im_asset"] = fullOffer.short_margin_asset;
                enrichedOfferSummary["premium_amount"] = fullOffer.premium_amount;
                enrichedOfferSummary["premium_asset"] = fullOffer.premium_asset;
            } else {
                // Repo enrichment (existing logic)
                offerTerms["principal_amount"] = fullOffer.principal_qty;
                offerTerms["principal_asset"] = fullOffer.principal_asset;
                offerTerms["collateral_amount"] = fullOffer.collateral_qty;
                offerTerms["collateral_asset"] = fullOffer.collateral_asset;
                offerTerms["interest_amount"] = fullOffer.interest_qty;
                offerTerms["interest_asset"] = fullOffer.interest_asset;
                offerTerms["apr"] = fullOffer.apr;
                offerTerms["ltv"] = fullOffer.ltv;
                offerTerms["tenor_days"] = fullOffer.tenor_days;
                if (!offerTerms.isEmpty()) {
                    populateRepoTermsFromSummary(info, offerTerms);
                }
            }
        }
        populateRepoTermsFromSummary(info, enrichedOfferSummary);

        requestsTable->setItem(row, 0, new QTableWidgetItem(formatOfferSummary(enrichedOfferSummary, info.offer_id)));

        QString roleLabel;
        if (info.direction == "incoming") {
            roleLabel = tr("Incoming (maker)");
        } else if (info.direction == "outgoing") {
            roleLabel = tr("Outgoing (taker)");
        } else {
            roleLabel = tr("Unknown");
        }
        requestsTable->setItem(row, 1, new QTableWidgetItem(roleLabel));

        requestsTable->setItem(row, 2, new QTableWidgetItem(formatPubkey(info.counterparty_pubkey)));
        requestsTable->setItem(row, 3, new QTableWidgetItem(formatStatusLabel(info)));

        // Funds Verified column - use cached verification result (same style as trade table)
        QString proofStatus;
        QTableWidgetItem* proofItem;
        if (info.proof_of_funds.isEmpty()) {
            proofStatus = "-";
            proofItem = new QTableWidgetItem(proofStatus);
            proofItem->setForeground(QBrush(QColor(158, 158, 158)));  // Gray
        } else if (info.proof_verified) {
            proofStatus = "✓";
            proofItem = new QTableWidgetItem(proofStatus);
            proofItem->setForeground(QBrush(QColor(76, 175, 80)));  // Green
            proofItem->setToolTip(tr("Funds verified: %1 units")
                .arg(info.proof_verified_units));
        } else {
            proofStatus = "✗";
            proofItem = new QTableWidgetItem(proofStatus);
            proofItem->setForeground(QBrush(QColor(244, 67, 54)));  // Red
            proofItem->setToolTip(tr("Verification FAILED: %1").arg(info.proof_verification_error));
        }
        requestsTable->setItem(row, 4, proofItem);

        int64_t updatedRef = info.updated_at > 0 ? info.updated_at : info.timestamp;
        requestsTable->setItem(row, 5, new QTableWidgetItem(formatTimestamp(updatedRef)));

        QWidget* actionWidget = new QWidget(this);
        QHBoxLayout* actionLayout = new QHBoxLayout();
        actionLayout->setContentsMargins(0, 0, 0, 0);
        actionLayout->setSpacing(6);
        bool hasAction = false;

        // MAKER SIDE: Incoming requests that need accept/reject
        if (info.direction == "incoming" && info.status == "pending") {
            LogPrintf("TradeBoardTab::updateTradeRequestsList() Creating FINALIZE button for incoming request %s\n",
                info.request_id.toStdString().c_str());

            QPushButton* acceptBtn = new QPushButton(tr("Finalize"), actionWidget);
            acceptBtn->setStyleSheet("QPushButton { background-color: #4CAF50; color: white; font-weight: bold; }");
            QPointer<TradeBoardTab> selfPtr(this);
            connect(acceptBtn, &QPushButton::clicked, this, [this, selfPtr, info]() {
                if (!selfPtr || !selfPtr->walletModel) return;

                LogPrintf("TradeBoardTab: User clicked FINALIZE for request %s\n", info.request_id.toStdString().c_str());

                // ================================================================
                // COPY ALL DATA UPFRONT - NO SHARED STATE ACCESS AFTER THIS POINT
                // ================================================================

                // Copy offer data from shared state (activeOffers)
                OfferInfo originalOffer;
                {
                    // Scoped access to shared state
                    if (!selfPtr->activeOffers.contains(info.offer_id)) {
                        QMessageBox::warning(selfPtr, tr("Offer Not Found"),
                            tr("Original offer not found in cache.\n\nTry refreshing the offers list."));
                        return;
                    }
                    originalOffer = selfPtr->activeOffers[info.offer_id];  // Deep copy
                }

                if (!originalOffer.is_term_sheet || originalOffer.term_sheet_terms.isEmpty()) {
                    QMessageBox::warning(selfPtr, tr("Invalid Offer"),
                        tr("Original offer is not a valid term sheet.\n\nCannot finalize."));
                    return;
                }

                // Copy all needed data from OfferInfo
                QString makerRole = originalOffer.maker_role.toLower();
                QVariantMap terms = originalOffer.term_sheet_terms;  // Deep copy
                QString contractType = originalOffer.contract_type.toLower();

                // Copy pointers to long-lived objects (safe to capture)
                WalletModel* walletModel = selfPtr->walletModel;
                BridgeSessionManager* sessionManager = selfPtr->sessionManager;

                // Check taker's proofs (already verified during ingestion) BEFORE finalizing
                if (!info.proof_of_funds.isEmpty()) {
                    // Use cached verification result - no re-verification
                    if (!info.proof_verified) {
                        QMessageBox::critical(selfPtr,
                            tr("Proof Verification Failed"),
                            tr("Taker's proof verification FAILED:\n\n%1\n\n"
                               "Cannot finalize contract with invalid proofs.")
                                .arg(info.proof_verification_error));
                        return;
                    }

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

                    // Check contract type to determine what to verify
                    QString contractType = originalOffer.contract_type.toLower();

                    if (contractType == "forward" || contractType == "option" || contractType == "options") {
                        // FORWARD/OPTIONS: Verify INITIAL MARGIN (not delivery assets!)
                        // Taker role is opposite of maker role
                        if (makerRole == "long") {
                            // Taker is SHORT - must prove short initial margin
                            double shortImUnits = terms.value("short_im_units").toDouble();
                            requiredAmount = static_cast<uint64_t>(shortImUnits * 100000000);
                            bool shortImIsNative = variantToBool(terms.value("short_im_is_native"), true);
                            if (!shortImIsNative) {
                                requiredAssetId = terms.value("short_im_asset_id").toString();
                            }
                            requirementKnown = true;
                        } else if (makerRole == "short") {
                            // Taker is LONG - must prove long initial margin
                            double longImUnits = terms.value("long_im_units").toDouble();
                            requiredAmount = static_cast<uint64_t>(longImUnits * 100000000);
                            bool longImIsNative = variantToBool(terms.value("long_im_is_native"), true);
                            if (!longImIsNative) {
                                requiredAssetId = terms.value("long_im_asset_id").toString();
                            }
                            requirementKnown = true;
                        }
                    } else if (contractType == "difficulty") {
                        // DIFFICULTY (native-TSC): the taker funds the opposite side of the maker.
                        const QString kind = terms.value("kind").toString().toLower();
                        double reqTsc = 0.0;
                        if (kind == "option") {
                            // maker writer -> taker buyer pays the premium; maker buyer -> taker writer posts IM.
                            reqTsc = (makerRole == "writer") ? terms.value("premium").toDouble()
                                                             : terms.value("im").toDouble();
                        } else {  // cfd
                            // maker long -> taker short posts short IM; maker short -> taker long posts long IM.
                            const QVariantMap leg = (makerRole == "long") ? terms.value("short").toMap()
                                                                          : terms.value("long").toMap();
                            reqTsc = leg.value("im").toDouble();
                        }
                        requiredAmount = static_cast<uint64_t>(reqTsc * 100000000);
                        // difficulty v1 IM/premium are native TSC -> requiredAssetId stays empty (native)
                        requirementKnown = true;
                    } else {
                        // REPO: Verify collateral or principal
                        // Taker role is opposite of maker role
                        if (makerRole == "lender") {
                            // Taker is borrower - must prove collateral
                            double collateralAmount = terms.value("collateral_amount").toDouble();
                            requiredAmount = static_cast<uint64_t>(collateralAmount * 100000000);
                            bool collateralIsNative = variantToBool(terms.value("collateral_is_native"), true);
                            if (!collateralIsNative) {
                                requiredAssetId = terms.value("collateral_asset_id").toString();
                            }
                            requirementKnown = true;
                        } else if (makerRole == "borrower") {
                            // Taker is lender - must prove principal
                            double principalAmount = terms.value("principal_amount").toDouble();
                            requiredAmount = static_cast<uint64_t>(principalAmount * 100000000);
                            bool principalIsNative = variantToBool(terms.value("principal_is_native"), true);
                            if (!principalIsNative) {
                                requiredAssetId = terms.value("principal_asset_id").toString();
                            }
                            requirementKnown = true;
                        }
                    }

                    if (requirementKnown) {
                        // Normalize asset IDs: treat "TSC" and empty as equivalent (native)
                        QString normalizedProofAsset = (info.proof_verified_asset == "TSC" || info.proof_verified_asset.isEmpty()) ? QString() : info.proof_verified_asset;
                        QString normalizedRequiredAsset = requiredAssetId.isEmpty() ? QString() : requiredAssetId;

                        bool assetMatches = (normalizedProofAsset.isEmpty() && normalizedRequiredAsset.isEmpty()) ||
                                           (normalizedProofAsset == normalizedRequiredAsset);
                        bool sufficient = assetMatches && (info.proof_verified_units >= requiredAmount);

                        if (!sufficient) {
                            QString reqAssetDisplay = requiredAssetId.isEmpty() ? QString("TSC") : (requiredAssetId.left(16) + "...");
                            QMessageBox::critical(selfPtr,
                                tr("Insufficient Funds"),
                                tr("Taker has INSUFFICIENT funds for this contract:\n\n"
                                   "Required: %1 units of %2\n"
                                   "Proven: %3 units\n\n"
                                   "Cannot finalize contract.")
                                    .arg(requiredAmount)
                                    .arg(reqAssetDisplay)
                                    .arg(info.proof_verified_units));
                            return;
                        }
                    }
                }

                // ============================================================================
                // DETECT CONTRACT TYPE AND BRANCH TO APPROPRIATE FINALIZATION LOGIC
                // ============================================================================
                LogPrintf("TradeBoardTab: Finalizing contract type=%s, maker_role=%s\n",
                          contractType.toStdString().c_str(),
                          makerRole.toStdString().c_str());

                QString finalizedOfferId;
                QString finalizedOfferJson;

                if (contractType == QLatin1String("spot")) {
                    // ========================================================================
                    // SPOT FINALIZATION PATH
                    // ========================================================================
                    LogPrintf("TradeBoardTab: Spot finalization starting\n");

                    // Validate maker role for spot (should be "alice")
                    if (makerRole != QLatin1String("alice")) {
                        QMessageBox::critical(selfPtr, tr("Invalid Role"),
                            tr("Spot maker role must be 'alice', got: '%1'").arg(makerRole));
                        return;
                    }

                    // ========================================================================
                    // INJECT ADDRESSES FROM TAKER DETAILS (same pattern as repo at line 4550)
                    // ========================================================================
                    // Maker is ALICE, so taker is BOB - must provide bob_dest
                    QString takerBobAddr = info.spot_bob_address;
                    if (takerBobAddr.isEmpty()) {
                        QMessageBox::warning(selfPtr, tr("Missing Address"),
                            tr("Taker did not provide Bob's receive address.\n\nCannot finalize the offer."));
                        return;
                    }
                    terms["bob_dest"] = takerBobAddr;

                    // Alice address should already be in term sheet (maker's address)
                    if (!terms.contains("alice_dest") || terms.value("alice_dest").toString().isEmpty()) {
                        // If alice_dest is missing from terms, check if taker provided it
                        if (!info.spot_alice_address.isEmpty()) {
                            terms["alice_dest"] = info.spot_alice_address;
                            LogPrintf("TradeBoardTab: Using alice_dest from taker_details: %s\n",
                                      info.spot_alice_address.toStdString().c_str());
                        } else {
                            QMessageBox::critical(selfPtr, tr("Missing Maker Address"),
                                tr("Original term sheet is missing Alice's receive address.\n\nCannot finalize."));
                            return;
                        }
                    }

                    LogPrintf("TradeBoardTab: Calling spot.propose with alice_dest=%s, bob_dest=%s\n",
                              terms.value("alice_dest").toString().toStdString().c_str(),
                              takerBobAddr.toStdString().c_str());

                    // CRITICAL: Regenerate contract ID by calling spot.propose with the same terms
                    // (Same pattern as repo at line 4616)
                    auto proposeResult = walletModel->spotPropose(terms);
                    if (!proposeResult.success) {
                        QMessageBox::critical(selfPtr, tr("Finalization Failed"),
                            tr("Failed to regenerate contract ID:\n\n%1").arg(proposeResult.error));
                        return;
                    }

                    QString contractId = proposeResult.offer_id;
                    finalizedOfferId = contractId;
                    finalizedOfferJson = proposeResult.offer_json;

                    LogPrintf("TradeBoardTab: Spot contract ID regenerated: %s\n",
                              contractId.toStdString().c_str());

                    // For spot, maker doesn't call spot.accept (that's the TAKER's call)
                    // Maker just regenerates the contract ID and proceeds to ceremony
                    // The actual acceptance flow happens via handleAcceptanceReceived → startMakerConfirmationWorkflow

                    LogPrintf("TradeBoardTab: Spot accepted successfully - accept_id=%s\n",
                              finalizedOfferId.toStdString().c_str());

                    // CRITICAL: Store final_offer_id and cache (same as repo/forward pattern)
                    if (selfPtr->activeRequests.contains(info.request_id)) {
                        selfPtr->activeRequests[info.request_id].final_offer_id = finalizedOfferId;
                        selfPtr->activeRequests[info.request_id].final_offer_json = finalizedOfferJson;
                        LogPrintf("TradeBoardTab: Stored spot final_offer_id=%s for request=%s\n",
                                 finalizedOfferId.toStdString().c_str(),
                                 info.request_id.toStdString().c_str());
                    }

                    // CRITICAL: Cache contract flavor so getCanonicalContractType() works
                    selfPtr->cacheContractFlavor(finalizedOfferId, "spot", finalizedOfferJson, info.offer_id);
                    LogPrintf("TradeBoardTab: Cached spot contract flavor - accept_id=%s\n",
                             finalizedOfferId.toStdString().c_str());

                    // Spot finalization complete - proceed to session creation and ceremony
                    // (Same flow as repo/forward: create session → handshake → wait for ceremony_ready)

                } else if (contractType == QLatin1String("forward") ||
                    contractType == QLatin1String("option") ||
                    contractType == QLatin1String("options")) {
                    // ========================================================================
                    // FORWARD/OPTIONS FINALIZATION PATH
                    // ========================================================================
                    LogPrintf("TradeBoardTab: Forward/Options finalization starting\n");

                    // Validate maker role for forward/options
                    bool makerIsLong = (makerRole == "long");
                    bool makerIsShort = (makerRole == "short");

                    if (!makerIsLong && !makerIsShort) {
                        QMessageBox::critical(selfPtr, tr("Invalid Role"),
                            tr("Forward/Options maker role must be 'long' or 'short', got: '%1'").arg(makerRole));
                        return;
                    }

                    // FOLLOW REPO PATTERN: Copy term sheet and just add missing addresses
                    QVariantMap forwardTerms = terms;  // Copy entire term sheet as-is

                    // Merge taker's addresses based on role (REPO PATTERN)
                    if (makerIsLong) {
                        // Taker is SHORT - add short addresses
                        if (info.short_margin_dest.isEmpty() || info.short_settlement_dest.isEmpty()) {
                            QMessageBox::critical(selfPtr, tr("Missing Taker Addresses"),
                                tr("Taker (Short) did not provide required addresses.\n\nCannot finalize."));
                            return;
                        }
                        forwardTerms["short_margin_dest"] = info.short_margin_dest;
                        forwardTerms["short_settle_dest"] = info.short_settlement_dest;

                        LogPrintf("TradeBoardTab: Added taker's short addresses - margin=%s, settle=%s\n",
                                  info.short_margin_dest.toStdString().c_str(),
                                  info.short_settlement_dest.toStdString().c_str());
                    } else {
                        // Taker is LONG - add long addresses
                        if (info.long_margin_dest.isEmpty() || info.long_settlement_dest.isEmpty()) {
                            QMessageBox::critical(selfPtr, tr("Missing Taker Addresses"),
                                tr("Taker (Long) did not provide required addresses.\n\nCannot finalize."));
                            return;
                        }
                        forwardTerms["long_margin_dest"] = info.long_margin_dest;
                        forwardTerms["long_settle_dest"] = info.long_settlement_dest;

                        LogPrintf("TradeBoardTab: Added taker's long addresses - margin=%s, settle=%s\n",
                                  info.long_margin_dest.toStdString().c_str(),
                                  info.long_settlement_dest.toStdString().c_str());
                    }

                    // Add premium payee address if taker receives premium
                    if (forwardTerms.contains("has_premium") && forwardTerms.value("has_premium").toBool()) {
                        QString premiumPayer = forwardTerms.value("premium_payer").toString().toLower();
                        bool takerReceivesPremium = ((premiumPayer == "long" && makerIsShort) ||
                                                     (premiumPayer == "short" && makerIsLong));

                        if (takerReceivesPremium && !info.premium_payee_dest.isEmpty()) {
                            forwardTerms["premium_dest"] = info.premium_payee_dest;
                            LogPrintf("TradeBoardTab: Added taker's premium_dest: %s\n",
                                      info.premium_payee_dest.toStdString().c_str());
                        }
                    }

                    LogPrintf("TradeBoardTab: Calling forward.propose with term sheet + merged addresses\n");

                    // Call forward.propose to generate finalized offer (uses copied walletModel pointer)
                    auto proposeResult = walletModel->forwardPropose(forwardTerms);
                    if (!proposeResult.success) {
                        QMessageBox::critical(selfPtr, tr("Forward Finalization Failed"),
                            tr("Failed to create finalized forward/options contract:\n\n%1").arg(proposeResult.error));
                        return;
                    }

                    finalizedOfferId = proposeResult.offer_id;
                    finalizedOfferJson = proposeResult.offer_json;

                    LogPrintf("TradeBoardTab: Forward/Options finalized successfully - offer_id=%s\n",
                              finalizedOfferId.toStdString().c_str());

                    // NOTE: Cache population deferred until after async handshake completes

                } else if (contractType == QLatin1String("difficulty")) {
                    // ========================================================================
                    // DIFFICULTY FINALIZATION PATH
                    // ========================================================================
                    // The maker's difficulty offer is already complete and published. The taker supplies
                    // its payout key by calling difficulty.accept during the post-handshake ceremony
                    // (onHandshakeCompleteTaker -> difficulty_acceptance -> the maker imports). So there is
                    // nothing to re-propose or address-merge here: validate the role and reuse the original
                    // signed term sheet as the finalized offer, then fall through to the session/handshake.
                    LogPrintf("TradeBoardTab: Difficulty finalization starting (role=%s)\n",
                              makerRole.toStdString().c_str());

                    const bool roleOk = (makerRole == "long" || makerRole == "short" ||
                                         makerRole == "writer" || makerRole == "buyer");
                    if (!roleOk) {
                        QMessageBox::critical(selfPtr, tr("Invalid Role"),
                            tr("Difficulty maker role must be 'long'/'short' (CFD) or 'writer'/'buyer' (option), "
                               "got: '%1'").arg(makerRole));
                        return;
                    }

                    if (originalOffer.term_sheet_json.isEmpty()) {
                        QMessageBox::critical(selfPtr, tr("Invalid Offer"),
                            tr("Original difficulty term sheet is empty.\n\nCannot finalize."));
                        return;
                    }

                    finalizedOfferId = info.offer_id;
                    finalizedOfferJson = originalOffer.term_sheet_json;

                    LogPrintf("TradeBoardTab: Difficulty finalized (reused original offer %s)\n",
                              finalizedOfferId.toStdString().c_str());

                } else {
                    // ========================================================================
                    // REPO FINALIZATION PATH (EXISTING LOGIC)
                    // ========================================================================
                    LogPrintf("TradeBoardTab: Repo finalization starting\n");

                    // Determine maker and taker roles
                    bool makerIsLender = (makerRole == "lender");
                    bool makerIsBorrower = (makerRole == "borrower");

                    // Add role to terms
                    terms["role"] = makerRole;

                    // Validate and add addresses based on roles
                    if (makerIsBorrower) {
                        // Maker is BORROWER, so taker is LENDER
                        QString takerLenderAddr = info.lender_address;
                        if (takerLenderAddr.isEmpty()) {
                            QMessageBox::warning(selfPtr, tr("Missing Address"),
                                tr("Taker did not provide a lender receive address.\n\nCannot finalize the offer."));
                            return;
                        }
                        terms["lender_address"] = takerLenderAddr;

                        // Borrower address should already be in term sheet (maker's address)
                        if (!terms.contains("borrower_address") || terms.value("borrower_address").toString().isEmpty()) {
                            LogPrintf("TradeBoardTab: ERROR - borrower_address missing from terms (contains=%d, value='%s')\n",
                                      terms.contains("borrower_address") ? 1 : 0,
                                      terms.value("borrower_address").toString().toStdString().c_str());
                            QMessageBox::critical(selfPtr, tr("Missing Maker Address"),
                                tr("Original term sheet is missing maker's borrower address.\n\nCannot finalize."));
                            return;
                        }

                        LogPrintf("TradeBoardTab: Calling repo.propose with maker=borrower, borrower_address=%s, taker_lender_address=%s\n",
                                  terms.value("borrower_address").toString().toStdString().c_str(),
                                  takerLenderAddr.toStdString().c_str());
                    } else if (makerIsLender) {
                        // Maker is LENDER, so taker is BORROWER
                        // Taker must provide borrower address
                        QString takerBorrowerAddr = info.borrower_address;
                        if (takerBorrowerAddr.isEmpty()) {
                            QMessageBox::warning(selfPtr, tr("Missing Address"),
                                tr("Taker did not provide a borrower repayment address.\n\nCannot finalize the offer."));
                            return;
                        }
                        terms["borrower_address"] = takerBorrowerAddr;

                        // Lender address should already be in term sheet (maker's address)
                        if (!terms.contains("lender_address") || terms.value("lender_address").toString().isEmpty()) {
                            QMessageBox::critical(selfPtr, tr("Missing Maker Address"),
                                tr("Original term sheet is missing maker's lender address.\n\nCannot finalize."));
                            return;
                        }

                        LogPrintf("TradeBoardTab: Calling repo.propose with maker=lender, taker_borrower_address=%s\n",
                                  takerBorrowerAddr.toStdString().c_str());
                    } else {
                        QMessageBox::critical(selfPtr, tr("Invalid Role"),
                            tr("Maker role is unknown or invalid.\n\nCannot finalize."));
                        return;
                    }

                    // Call repo.propose to generate finalized offer (uses copied walletModel pointer)
                    auto proposeResult = walletModel->repoPropose(terms);
                    if (!proposeResult.success) {
                        QMessageBox::critical(selfPtr, tr("Finalization Failed"),
                            tr("Failed to create finalized offer:\n\n%1").arg(proposeResult.error));
                        return;
                    }

                    finalizedOfferId = proposeResult.offer_id;
                    finalizedOfferJson = proposeResult.offer_json;

                    LogPrintf("TradeBoardTab: Repo finalized successfully - offer_id=%s\n",
                              finalizedOfferId.toStdString().c_str());

                    // NOTE: Cache population deferred until after async handshake completes
                }

                LogPrintf("TradeBoardTab: Finalized offer created: %s\n", finalizedOfferId.toStdString().c_str());

                // ================================================================
                // CREATE SESSION AND START ASYNC HANDSHAKE
                // All shared state mutations deferred until handshake completes
                // ================================================================

                // Now create a cosign session and send the finalized offer to the taker
                LogPrintf("TradeBoardTab: Creating cosign session and accepting trade request %s\n",
                          info.request_id.toStdString().c_str());

                // Retrieve transport preference for this offer
                QString transport = offerTransportPreferences.value(info.offer_id, "auto");
                LogPrintf("TradeBoardTab: Retrieved transport preference '%s' for offer %s (Tor status: %s)\n",
                         transport.toStdString().c_str(),
                         info.offer_id.toStdString().c_str(),
                         TorManager::instance()->statusString().toStdString().c_str());

                auto result = walletModel->bulletinBoardAcceptRequest(info.request_id, transport);
                if (result.success) {
                    QString session_id = result.session_id;

                    // NOTE: DO NOT add to activeSessions yet - must wait for handshake to complete!
                    // Session will be added in onHandshakeCompleteMaker() after handshake succeeds

                    // Add session to session manager so it appears in Bridge Sessions tab
                    if (sessionManager && !session_id.isEmpty()) {
                        BridgeSessionManager::SessionInfo sessionInfo;
                        sessionInfo.session_id = session_id;
                        sessionInfo.sas = tr("(handshaking...)");
                        sessionInfo.sas_numeric = "";
                        sessionInfo.transport = result.transport.isEmpty() ? "auto" : result.transport;
                        sessionInfo.relay_url = result.relay_url;
                        sessionInfo.started_timestamp = QDateTime::currentSecsSinceEpoch();
                        sessionInfo.handshake_complete = false;
                        sessionInfo.is_initiator = true;  // Maker is initiator
                        sessionManager->addSession(sessionInfo);
                        LogPrintf("TradeBoardTab: Added session %s to session manager (transport=%s, relay=%s)\n",
                                  session_id.toStdString().c_str(),
                                  result.transport.toStdString().c_str(),
                                  result.relay_url.toStdString().c_str());
                    }

                    // AUTOMATICALLY start handshake (maker is initiator) - NON-BLOCKING
                    LogPrintf("TradeBoardTab: Auto-starting non-blocking handshake for maker session %s (initiator=true)\n",
                              session_id.toStdString().c_str());

                    // Capture all data needed for async operation and completion callback
                    QString capturedSessionId = session_id;
                    QString capturedRequestId = info.request_id;
                    QString capturedFinalizedOfferId = finalizedOfferId;
                    QString capturedFinalizedOfferJson = finalizedOfferJson;
                    QString capturedContractType = contractType;  // Needed for cache normalization
                    QString capturedLegacyOfferId = info.offer_id;

                    // Run handshake in worker thread - uses ONLY copied walletModel pointer
                    QFuture<QVariantMap> future = QtConcurrent::run([walletModel, capturedSessionId]() -> QVariantMap {
                        auto result = walletModel->cosignHandshakeAuto(capturedSessionId, true);
                        QVariantMap resultMap;
                        resultMap["success"] = result.success;
                        resultMap["handshake_complete"] = result.handshake_complete;
                        resultMap["sas"] = result.sas;
                        resultMap["sas_numeric"] = result.sas_numeric;
                        resultMap["error"] = result.error;
                        return resultMap;
                    });

                    // Create a watcher to handle completion in main thread
                    QFutureWatcher<QVariantMap>* watcher = new QFutureWatcher<QVariantMap>(selfPtr);
                    connect(watcher, &QFutureWatcher<QVariantMap>::finished, selfPtr, [selfPtr, watcher, capturedSessionId, capturedRequestId, capturedFinalizedOfferId, capturedFinalizedOfferJson, capturedContractType, capturedLegacyOfferId]() {
                        if (!selfPtr) return;
                        QVariantMap handshakeResult = watcher->result();
                        watcher->deleteLater();

                        // ALL shared state mutations happen here in main thread after async work completes
                        selfPtr->onHandshakeCompleteMaker(capturedSessionId, capturedRequestId, capturedFinalizedOfferId, capturedFinalizedOfferJson, handshakeResult);

                        // Populate caches NOW (in main thread, after handshake)
                        QString normalizedType = capturedContractType;
                        if (normalizedType == "options") {
                            normalizedType = "option";
                        }
                        selfPtr->cacheContractFlavor(capturedFinalizedOfferId, normalizedType, capturedFinalizedOfferJson, capturedLegacyOfferId);

                        // Update UI
                        selfPtr->updateTradeRequestsList();
                    });

                    watcher->setFuture(future);
                } else {
                    QMessageBox::warning(selfPtr, tr("Accept failed"),
                        tr("Could not complete the accept right now: %1\n\n"
                           "The request is still pending. You can try Finalize again, "
                           "or wait if the counterparty is offline.")
                            .arg(result.error));
                }
            });
            actionLayout->addWidget(acceptBtn);

            QPushButton* rejectBtn = new QPushButton(tr("Reject"), actionWidget);
            rejectBtn->setStyleSheet("QPushButton { background-color: #f44336; color: white; }");
            QPointer<TradeBoardTab> rejectSelfPtr(this);
            connect(rejectBtn, &QPushButton::clicked, this, [rejectSelfPtr, info]() {
                if (!rejectSelfPtr || !rejectSelfPtr->walletModel) return;

                LogPrintf("TradeBoardTab: User clicked REJECT for request %s\n", info.request_id.toStdString().c_str());

                bool success = rejectSelfPtr->walletModel->bulletinBoardRejectRequest(info.request_id);
                if (success) {
                    rejectSelfPtr->showAutoClosingInfo(tr("Request Rejected"),
                        tr("Trade request was rejected."));
                    rejectSelfPtr->updateTradeRequestsList();
                } else {
                    QMessageBox::warning(rejectSelfPtr, tr("Error"),
                        tr("Failed to reject trade request."));
                }
            });
            actionLayout->addWidget(rejectBtn);
            hasAction = true;
        }

        // TAKER SIDE: Outgoing requests that can be cancelled
        if (info.direction == "outgoing" && info.status == "pending") {
            QPushButton* cancelBtn = new QPushButton(tr("Cancel"), actionWidget);
            QPointer<TradeBoardTab> cancelSelfPtr(this);
            connect(cancelBtn, &QPushButton::clicked, this, [cancelSelfPtr, info]() {
                if (!cancelSelfPtr || !cancelSelfPtr->walletModel) return;

                QMessageBox::StandardButton confirm = QMessageBox::question(
                    cancelSelfPtr,
                    tr("Cancel Trade Request"),
                    tr("Cancel trade request %1?\n\nOffer: %2")
                        .arg(info.request_id.left(16) + "...")
                        .arg(info.offer_id.left(16) + "..."),
                    QMessageBox::Yes | QMessageBox::No
                );

                if (confirm != QMessageBox::Yes) {
                    return;
                }

                bool success = cancelSelfPtr->walletModel->bulletinBoardCancelRequest(info.request_id);
                if (success) {
                    cancelSelfPtr->showAutoClosingInfo(tr("Request Cancelled"),
                        tr("Trade request was cancelled successfully."));
                    cancelSelfPtr->updateTradeRequestsList();
                } else {
                    QMessageBox::warning(cancelSelfPtr, tr("Cancellation Failed"),
                        tr("Failed to cancel trade request. It may have already been accepted or processed."));
                }
            });
            actionLayout->addWidget(cancelBtn);
            hasAction = true;
        }

        // TAKER SIDE: Outgoing requests that were accepted
        if (info.direction == "outgoing" && info.status == "accepted" && !info.invite_link.isEmpty() && !info.auto_joined) {
            QPushButton* joinBtn = new QPushButton(tr("Join Session"), actionWidget);
            QPointer<TradeBoardTab> joinSelfPtr(this);
            connect(joinBtn, &QPushButton::clicked, this, [joinSelfPtr, info]() {
                if (!joinSelfPtr || !joinSelfPtr->walletModel) return;

                auto joinResult = joinSelfPtr->walletModel->cosignJoin(info.invite_link, "trade");
                if (joinResult.success) {
                    // Mark as joined locally to avoid duplicate prompts
                    if (joinSelfPtr->activeRequests.contains(info.request_id)) {
                        joinSelfPtr->activeRequests[info.request_id].auto_joined = true;
                    }

                    QMessageBox::information(joinSelfPtr, tr("Session Joined"),
                        tr("Successfully joined trade session!\n\n"
                           "Session ID: %1\n"
                           "SAS: %2\n\n"
                           "NEXT STEP:\n"
                           "Go to 'Exchange P2P > Bridge Sessions' tab.\n"
                           "Verify SAS matches with maker.")
                        .arg(joinResult.session_id.left(16) + "...")
                        .arg(joinResult.sas));
                } else {
                    QMessageBox::warning(joinSelfPtr, tr("Error"),
                        tr("Failed to join session: %1").arg(joinResult.error));
                }
            });
            actionLayout->addWidget(joinBtn);
            hasAction = true;
        }

        if (!hasAction) {
            actionLayout->addStretch();
        }

        actionWidget->setLayout(actionLayout);
        requestsTable->setCellWidget(row, 6, actionWidget);

        // Preserve local-only ceremony state before overwriting with bulletin board data
        // Use value() to get a safe copy (not a reference that could be invalidated)
        bool had_existing = activeRequests.contains(info.request_id);
        TradeRequestInfo preserved;

        if (had_existing) {
            // Make a complete copy of existing entry to avoid reference invalidation issues
            preserved = activeRequests.value(info.request_id);
            LogPrintf("TradeBoardTab::updateTradeRequestsList: Preserving ceremony state for request_id='%s', taker_fee_strategy='%s', auto_joined=%d, psbt_locked=%d\n",
                     info.request_id.toStdString().c_str(),
                     preserved.taker_fee_strategy.toStdString().c_str(),
                     preserved.auto_joined,
                     preserved.psbt_locked);
        }

        // Update with new data from bulletin board
        activeRequests[info.request_id] = info;

        // Restore local-only ceremony state fields that don't come from bulletin board
        if (had_existing) {
            TradeRequestInfo& updated = activeRequests[info.request_id];
            updated.taker_fee_strategy = preserved.taker_fee_strategy;
            updated.auto_joined = preserved.auto_joined;
            updated.maker_base_psbt = preserved.maker_base_psbt;
            updated.augmented_psbt = preserved.augmented_psbt;
            updated.augmented_psbt_hash = preserved.augmented_psbt_hash;
            updated.psbt_locked = preserved.psbt_locked;
            updated.merged_ceremony_psbt = preserved.merged_ceremony_psbt;
            updated.merged_ceremony_psbt_hash = preserved.merged_ceremony_psbt_hash;
            updated.ceremony_phase = preserved.ceremony_phase;
            updated.alice_vault_index = preserved.alice_vault_index;
            updated.bob_vault_index = preserved.bob_vault_index;
            updated.premium_output_index = preserved.premium_output_index;
            updated.acceptance_sent = preserved.acceptance_sent;
            updated.ceremony_invite_sent = preserved.ceremony_invite_sent;
            updated.recovering_session = preserved.recovering_session;
            updated.staged_local_base_psbt = preserved.staged_local_base_psbt;
            updated.staged_local_base_ready = preserved.staged_local_base_ready;
            updated.staged_peer_base_psbt = preserved.staged_peer_base_psbt;
            updated.staged_peer_base_ready = preserved.staged_peer_base_ready;
            updated.final_offer_processed = preserved.final_offer_processed;

            LogPrintf("TradeBoardTab::updateTradeRequestsList: Restored ceremony state for request_id='%s', taker_fee_strategy='%s'\n",
                     info.request_id.toStdString().c_str(),
                     updated.taker_fee_strategy.toStdString().c_str());
        }
    }

    // After updating, check for auto-join opportunities
    checkForAutoJoin();

    requestsTable->setSortingEnabled(previousSorting);
}

void TradeBoardTab::checkForAutoJoin()
{
    if (!walletModel) return;

    // Check activeRequests for any that have invite_link and haven't been auto-joined yet
    for (auto it = activeRequests.begin(); it != activeRequests.end(); ++it) {
        TradeRequestInfo& req = it.value();

        if (req.direction == "outgoing" && req.status == "accepted" && !req.invite_link.isEmpty() && !req.auto_joined) {
            // This request has been accepted and has an invite link - auto-join!
            QString invite_link = req.invite_link;
            QString request_id = req.request_id;
            const QString session_hint = CosignRoomIdFromInviteLink(invite_link);
            const QString attempt_key = AutoJoinAttemptKey(request_id, invite_link);

            if (autoJoinAttemptedRequests.contains(attempt_key) ||
                (!session_hint.isEmpty() && autoJoinAttemptedSessions.contains(session_hint))) {
                req.auto_joined = true;
                LogPrintf("TradeBoardTab: Skipping auto-join for request %s/session %s; already attempted\n",
                          request_id.toStdString().c_str(),
                          session_hint.toStdString().c_str());
                continue;
            }

            if (autoJoinInFlightRequests.contains(attempt_key) ||
                (!session_hint.isEmpty() && autoJoinInFlightSessions.contains(session_hint))) {
                req.auto_joined = true;
                LogPrintf("TradeBoardTab: Skipping auto-join for request %s/session %s; join already in flight\n",
                          request_id.toStdString().c_str(),
                          session_hint.toStdString().c_str());
                continue;
            }

            if (!session_hint.isEmpty() &&
                (activeSessions.contains(session_hint) || ceremonySessions.contains(session_hint))) {
                req.auto_joined = true;
                autoJoinAttemptedRequests.insert(attempt_key);
                autoJoinAttemptedSessions.insert(session_hint);
                LogPrintf("TradeBoardTab: Skipping auto-join for request %s; session %s is already active\n",
                          request_id.toStdString().c_str(),
                          session_hint.toStdString().c_str());
                continue;
            }

            // Mark as auto-joined to prevent duplicate joins
            req.auto_joined = true;
            autoJoinAttemptedRequests.insert(attempt_key);
            autoJoinInFlightRequests.insert(attempt_key);
            if (!session_hint.isEmpty()) {
                autoJoinAttemptedSessions.insert(session_hint);
                autoJoinInFlightSessions.insert(session_hint);
            }

            // Auto-join the session
            auto joinResult = walletModel->cosignJoin(invite_link, "trade");

            if (joinResult.success) {
                QString session_id = joinResult.session_id;

                // NOTE: DO NOT add to activeSessions yet - must wait for handshake to complete!
                // Session will be added in onHandshakeCompleteTaker() after handshake succeeds

                // Add session to session manager so it appears in Bridge Sessions tab
                if (sessionManager && !session_id.isEmpty()) {
                    BridgeSessionManager::SessionInfo sessionInfo;
                    sessionInfo.session_id = session_id;
                    sessionInfo.sas = tr("(handshaking...)");
                    sessionInfo.sas_numeric = "";
                    sessionInfo.transport = joinResult.transport.isEmpty() ? "auto" : joinResult.transport;
                    sessionInfo.relay_url = joinResult.relay_url;
                    sessionInfo.started_timestamp = QDateTime::currentSecsSinceEpoch();
                    sessionInfo.handshake_complete = false;
                    sessionInfo.is_initiator = false;  // Taker is not initiator
                    sessionManager->addSession(sessionInfo);
                    LogPrintf("TradeBoardTab: Auto-joined and added session %s to session manager (transport=%s, relay=%s)\n",
                              session_id.toStdString().c_str(),
                              joinResult.transport.toStdString().c_str(),
                              joinResult.relay_url.toStdString().c_str());
                }

                // AUTOMATICALLY start handshake (taker is NOT initiator) - NON-BLOCKING
                LogPrintf("TradeBoardTab: Auto-starting non-blocking handshake for taker session %s (initiator=false)\n",
                          session_id.toStdString().c_str());

                // Capture variables for the lambda
                QString capturedSessionId = session_id;
                QString capturedRequestId = req.request_id;
                QString capturedAttemptKey = attempt_key;
                QString capturedSessionHint = session_hint;

                // Run handshake in worker thread
                auto inflightGuard = std::make_shared<InflightGuard>(this);
                QFuture<QVariantMap> future = QtConcurrent::run([this, inflightGuard, capturedSessionId]() -> QVariantMap {
                    (void)inflightGuard;  // keeps the guard alive for the duration of the body
                    auto result = walletModel->cosignHandshakeAuto(capturedSessionId, false);
                    QVariantMap resultMap;
                    resultMap["success"] = result.success;
                    resultMap["handshake_complete"] = result.handshake_complete;
                    resultMap["sas"] = result.sas;
                    resultMap["sas_numeric"] = result.sas_numeric;
                    resultMap["error"] = result.error;
                    return resultMap;
                });

                // Create a watcher to handle completion
                QFutureWatcher<QVariantMap>* watcher = new QFutureWatcher<QVariantMap>(this);
                connect(watcher, &QFutureWatcher<QVariantMap>::finished, this, [this, watcher, capturedSessionId, capturedRequestId, capturedAttemptKey, capturedSessionHint]() {
                    QVariantMap handshakeResult = watcher->result();
                    watcher->deleteLater();

                    autoJoinInFlightRequests.remove(capturedAttemptKey);
                    if (!capturedSessionHint.isEmpty()) {
                        autoJoinInFlightSessions.remove(capturedSessionHint);
                    }

                    onHandshakeCompleteTaker(capturedSessionId, capturedRequestId, handshakeResult);
                });

                watcher->setFuture(future);
            } else {
                autoJoinInFlightRequests.remove(attempt_key);
                if (!session_hint.isEmpty()) {
                    autoJoinInFlightSessions.remove(session_hint);
                }

                // Only show popup once per request to prevent spam
                QString joinFailureKey = QString("join_failure_%1").arg(request_id);
                if (!handshakeFailureShown.contains(joinFailureKey)) {
                    handshakeFailureShown.insert(joinFailureKey);
                    QMessageBox::critical(this, tr("Auto-Join Failed"),
                        tr("Could not join trade session: %1\n\n"
                           "This usually means:\n"
                           "• Tor failed to start (check status indicator)\n"
                           "• Network connectivity issues\n"
                           "• Invite link expired or invalid\n\n"
                           "You can manually retry from the Bridge Sessions tab.")
                        .arg(joinResult.error));
                }
                // Do NOT retry automatically - user can manually retry if needed
                // req.auto_joined stays true to prevent infinite retry loop
            }
        }
    }
}

QString TradeBoardTab::formatTimestamp(int64_t timestamp)
{
    QDateTime dt = QDateTime::fromSecsSinceEpoch(timestamp);
    qint64 secondsAgo = dt.secsTo(QDateTime::currentDateTime());

    if (secondsAgo < 60) {
        return tr("%1s ago").arg(secondsAgo);
    } else if (secondsAgo < 3600) {
        return tr("%1m ago").arg(secondsAgo / 60);
    } else if (secondsAgo < 86400) {
        return tr("%1h ago").arg(secondsAgo / 3600);
    } else {
        return tr("%1d ago").arg(secondsAgo / 86400);
    }
}

QString TradeBoardTab::formatPubkey(const QString& pubkey)
{
    if (pubkey.length() <= 16) {
        return pubkey;
    }
    return pubkey.left(8) + "..." + pubkey.right(8);
}

// Contract flavor detection and caching implementation
TradeBoardTab::ContractFlavor TradeBoardTab::detectContractFlavor(const QString& contractId, const QVariantMap& summary, const QString& payloadJson)
{
    ContractFlavor flavor;
    flavor.contract_id = contractId;
    flavor.cached_at = QDateTime::currentMSecsSinceEpoch();

    // Precedence: payloadJson (authoritative) > summary (fallback)
    if (!payloadJson.isEmpty()) {
        QJsonDocument doc = QJsonDocument::fromJson(payloadJson.toUtf8());
        if (doc.isObject()) {
            QString type = doc.object().value("contract_type").toString().toLower();
            if (!type.isEmpty()) {
                flavor.contract_type = type;
                flavor.full_payload_json = payloadJson;
                LogPrintf("TradeBoardTab: Detected contract_type='%s' from payload for contract %s\n",
                          type.toStdString().c_str(), contractId.toStdString().c_str());
                return flavor;
            }
        }
    }

    // Fallback to summary
    QString summaryType = summary.value("contract_type").toString().toLower();
    if (!summaryType.isEmpty()) {
        flavor.contract_type = summaryType;
        LogPrintf("TradeBoardTab: Detected contract_type='%s' from summary for contract %s\n",
                  summaryType.toStdString().c_str(), contractId.toStdString().c_str());
        return flavor;
    }

    // Hard error - no valid contract type found
    LogPrintf("ERROR: Unable to detect contract_type for contract %s (payload_len=%d, summary.keys=%d)\n",
              contractId.toStdString().c_str(), payloadJson.length(), summary.size());
    return flavor;  // Returns with empty contract_type
}

void TradeBoardTab::cacheContractFlavor(const QString& contractId,
                                        const QString& contractType,
                                        const QString& payloadJson,
                                        const QString& legacyOfferId)
{
    auto cacheOne = [&](const QString& key) {
        if (key.isEmpty()) return;
        if (contractFlavorCache.contains(key)) {
            const ContractFlavor& existing = contractFlavorCache[key];
            if (existing.contract_type != contractType) {
                LogPrintf("WARNING: Contract type mismatch for %s! Cached='%s', New='%s'\n",
                          key.toStdString().c_str(),
                          existing.contract_type.toStdString().c_str(),
                          contractType.toStdString().c_str());
            }
            return;
        }
        ContractFlavor flavor;
        flavor.contract_id = key;
        flavor.contract_type = contractType;
        flavor.full_payload_json = payloadJson;
        flavor.cached_at = QDateTime::currentMSecsSinceEpoch();
        contractFlavorCache[key] = flavor;
        LogPrintf("TradeBoardTab: Cached contract_type='%s' for contract %s\n",
                  contractType.toStdString().c_str(), key.toStdString().c_str());
    };

    if (contractId.isEmpty() && legacyOfferId.isEmpty()) {
        LogPrintf("ERROR: cacheContractFlavor called with no identifier\n");
        return;
    }

    QString normalized = contractType.toLower();
    if (normalized == "options") normalized = QStringLiteral("option");
    if (normalized != "repo" && normalized != "forward" && normalized != "option" && normalized != "spot" && normalized != "difficulty") {
        LogPrintf("ERROR: Invalid contract_type='%s' for ids (%s, %s)\n",
                  contractType.toStdString().c_str(),
                  contractId.toStdString().c_str(),
                  legacyOfferId.toStdString().c_str());
        return;
    }

    cacheOne(contractId);
    cacheOne(legacyOfferId);
}

QString TradeBoardTab::getCanonicalContractType(const QString& contractId)
{
    if (contractId.isEmpty()) {
        return QString();
    }

    if (contractFlavorCache.contains(contractId)) {
        return contractFlavorCache[contractId].contract_type;
    }

    return QString();  // Not cached
}

bool TradeBoardTab::ensureContractFlavorLoaded(const QString& contractId, const QString& fallbackSummaryType)
{
    if (contractId.isEmpty()) {
        LogPrintf("ERROR: ensureContractFlavorLoaded called with empty contractId\n");
        return false;
    }

    // Already cached?
    if (contractFlavorCache.contains(contractId)) {
        return true;
    }

    // Try to fetch from contract.status RPC
    try {
        UniValue params(UniValue::VARR);
        params.push_back(contractId.toStdString());
        UniValue status_resp = walletModel->node().executeRpc("contract.status", params, walletModel->getWalletName().toStdString());

        if (status_resp.isObject() && status_resp.exists("offer")) {
            QString offerJson = QString::fromStdString(status_resp["offer"].write());
            QJsonDocument offerDoc = QJsonDocument::fromJson(offerJson.toUtf8());
            if (offerDoc.isObject()) {
                QString type = offerDoc.object().value("contract_type").toString();
                if (!type.isEmpty()) {
                    cacheContractFlavor(contractId, type, offerJson);
                    return true;
                }
            }
        }
    } catch (const std::exception& e) {
        LogPrintf("ERROR: Failed to fetch contract.status for %s: %s\n",
                  contractId.toStdString().c_str(), e.what());
    }

    // Last resort: use fallback if provided
    if (!fallbackSummaryType.isEmpty()) {
        LogPrintf("WARNING: Using fallback contract_type='%s' for %s\n",
                  fallbackSummaryType.toStdString().c_str(), contractId.toStdString().c_str());
        cacheContractFlavor(contractId, fallbackSummaryType, QString());
        return true;
    }

    LogPrintf("FATAL: Cannot determine contract type for %s\n", contractId.toStdString().c_str());
    return false;
}

QString TradeBoardTab::formatOfferSummary(const QVariantMap& offer, const QString& fallbackId) const
{
    if (offer.isEmpty()) {
        if (!fallbackId.isEmpty()) {
            return tr("Offer %1").arg(fallbackId.left(16) + "...");
        }
        return tr("Offer (unknown)");
    }

    QString contractType = offer.value("contract_type").toString();

    // For contract offers (repo, forward, options), show contract-specific summary
    if (!contractType.isEmpty() && (contractType.toLower() == "repo" ||
                                     contractType.toLower() == "forward" ||
                                     contractType.toLower() == "spot")) {
        QString contractPayload = offer.value("contract_payload").toString();

        if (contractType.toLower() == "repo") {
            // Try to parse contract payload to get collateral and principal
            if (!contractPayload.isEmpty()) {
                QJsonParseError parseError;
                QJsonDocument payloadDoc = QJsonDocument::fromJson(contractPayload.toUtf8(), &parseError);
                if (!payloadDoc.isNull() && payloadDoc.isObject()) {
                    QJsonObject payloadObj = payloadDoc.object();
                    QString collateralAsset, principalAsset;
                    double collateralQty = 0.0, principalQty = 0.0;

                    // Try to extract from term sheet structure
                    if (payloadObj.contains("terms")) {
                        QJsonObject terms = payloadObj.value("terms").toObject();
                        collateralQty = terms.value("collateral_amount").toDouble();
                        principalQty = terms.value("principal_amount").toDouble();

                        bool collateralIsNative = terms.value("collateral_is_native").toBool(true);
                        bool principalIsNative = terms.value("principal_is_native").toBool(true);

                        // Resolve asset IDs to tickers
                        if (collateralIsNative) {
                            collateralAsset = "TSC";
                        } else {
                            QString collateralAssetId = terms.value("collateral_asset_id").toString();
                            if (walletModel) {
                                WalletModel::AssetInfo assetInfo = walletModel->getAssetInfo(collateralAssetId);
                                if (!assetInfo.ticker.isEmpty()) {
                                    collateralAsset = assetInfo.ticker;
                                } else if (!collateralAssetId.isEmpty()) {
                                    collateralAsset = collateralAssetId.left(6);
                                } else {
                                    collateralAsset = "ASSET";
                                }
                            } else {
                                collateralAsset = collateralAssetId.left(6);
                            }
                        }

                        if (principalIsNative) {
                            principalAsset = "TSC";
                        } else {
                            QString principalAssetId = terms.value("principal_asset_id").toString();
                            if (walletModel) {
                                WalletModel::AssetInfo assetInfo = walletModel->getAssetInfo(principalAssetId);
                                if (!assetInfo.ticker.isEmpty()) {
                                    principalAsset = assetInfo.ticker;
                                } else if (!principalAssetId.isEmpty()) {
                                    principalAsset = principalAssetId.left(6);
                                } else {
                                    principalAsset = "ASSET";
                                }
                            } else {
                                principalAsset = principalAssetId.left(6);
                            }
                        }
                    }

                    if (collateralQty > 0.0 && principalQty > 0.0) {
                        return tr("Repo: %1 %2 ↔ %3 %4")
                            .arg(QString::number(collateralQty, 'f', collateralQty < 1.0 ? 4 : 2))
                            .arg(collateralAsset)
                            .arg(QString::number(principalQty, 'f', principalQty < 1.0 ? 4 : 2))
                            .arg(principalAsset);
                    }
                }
            }
            return tr("Repo Contract");
        } else if (contractType.toLower() == "forward" || contractType.toLower() == "option" || contractType.toLower() == "options") {
            // Try to parse contract payload to get long/short assets
            if (!contractPayload.isEmpty()) {
                QJsonParseError parseError;
                QJsonDocument payloadDoc = QJsonDocument::fromJson(contractPayload.toUtf8(), &parseError);
                if (!payloadDoc.isNull() && payloadDoc.isObject()) {
                    QJsonObject payloadObj = payloadDoc.object();

                    // Check for metrics (term sheet) or terms (finalized)
                    QJsonObject metrics = payloadObj.value("metrics").toObject();
                    QJsonObject terms = payloadObj.value("terms").toObject();

                    double longDeliverQty = metrics.value("long_deliver_amount").toDouble();
                    double shortDeliverQty = metrics.value("short_deliver_amount").toDouble();
                    double longIMQty = metrics.value("long_im_amount").toDouble();
                    double shortIMQty = metrics.value("short_im_amount").toDouble();

                    // Premium can be in metrics OR terms (term sheets have it in terms.premium_units)
                    double premiumAmount = metrics.value("premium_amount").toDouble();
                    if (premiumAmount == 0.0) {
                        premiumAmount = terms.value("premium_units").toDouble();
                    }

                    QString longDeliverAsset, shortDeliverAsset, premiumAsset;

                    // Resolve long deliver asset
                    bool longIsNative = terms.value("long_deliver_is_native").toBool(true);
                    if (longIsNative) {
                        longDeliverAsset = "TSC";
                    } else {
                        QString assetId = terms.value("long_deliver_asset_id").toString();
                        if (walletModel) {
                            WalletModel::AssetInfo assetInfo = walletModel->getAssetInfo(assetId);
                            longDeliverAsset = assetInfo.ticker.isEmpty() ? assetId.left(6) : assetInfo.ticker;
                        } else {
                            longDeliverAsset = assetId.left(6);
                        }
                    }

                    // Resolve short deliver asset
                    bool shortIsNative = terms.value("short_deliver_is_native").toBool(true);
                    if (shortIsNative) {
                        shortDeliverAsset = "TSC";
                    } else {
                        QString assetId = terms.value("short_deliver_asset_id").toString();
                        if (walletModel) {
                            WalletModel::AssetInfo assetInfo = walletModel->getAssetInfo(assetId);
                            shortDeliverAsset = assetInfo.ticker.isEmpty() ? assetId.left(6) : assetInfo.ticker;
                        } else {
                            shortDeliverAsset = assetId.left(6);
                        }
                    }

                    // Determine if option by premium
                    bool isOption = (premiumAmount > 0.00001) || contractType.toLower() == "option" || contractType.toLower() == "options";

                    if (longDeliverQty > 0.0 && shortDeliverQty > 0.0) {
                        if (isOption) {
                            // Option format: "Option: 100 GOLD ↔ 1000 TSC + 5 TSC premium"
                            if (premiumAmount > 0) {
                                return tr("Option: %1 %2 ↔ %3 %4 + %5 premium")
                                    .arg(QString::number(longDeliverQty, 'f', longDeliverQty < 1.0 ? 4 : 2))
                                    .arg(longDeliverAsset)
                                    .arg(QString::number(shortDeliverQty, 'f', shortDeliverQty < 1.0 ? 4 : 2))
                                    .arg(shortDeliverAsset)
                                    .arg(QString::number(premiumAmount, 'f', premiumAmount < 1.0 ? 4 : 2));
                            } else {
                                return tr("Option: %1 %2 ↔ %3 %4")
                                    .arg(QString::number(longDeliverQty, 'f', longDeliverQty < 1.0 ? 4 : 2))
                                    .arg(longDeliverAsset)
                                    .arg(QString::number(shortDeliverQty, 'f', shortDeliverQty < 1.0 ? 4 : 2))
                                    .arg(shortDeliverAsset);
                            }
                        } else {
                            // Forward format: "Forward: 100 GOLD ↔ 1000 TSC (IM: 10 + 100)"
                            return tr("Forward: %1 %2 ↔ %3 %4 (IM: %5 + %6)")
                                .arg(QString::number(longDeliverQty, 'f', longDeliverQty < 1.0 ? 4 : 2))
                                .arg(longDeliverAsset)
                                .arg(QString::number(shortDeliverQty, 'f', shortDeliverQty < 1.0 ? 4 : 2))
                                .arg(shortDeliverAsset)
                                .arg(QString::number(longIMQty, 'f', longIMQty < 1.0 ? 4 : 2))
                                .arg(QString::number(shortIMQty, 'f', shortIMQty < 1.0 ? 4 : 2));
                        }
                    }
                }
            }

            // Fallback: Try to extract basic info from offer map directly (for trade requests without full payload)
            // Try multiple field name variations
            double longQty = offer.value("long_deliver_amount").toDouble();
            if (longQty == 0.0) longQty = offer.value("long_deliver_qty").toDouble();

            QString longAsset = offer.value("long_deliver_asset").toString();
            if (longAsset.isEmpty()) longAsset = offer.value("long_asset").toString();

            double shortQty = offer.value("short_deliver_amount").toDouble();
            if (shortQty == 0.0) shortQty = offer.value("short_deliver_qty").toDouble();

            QString shortAsset = offer.value("short_deliver_asset").toString();
            if (shortAsset.isEmpty()) shortAsset = offer.value("short_asset").toString();

            if (longQty > 0.0 && shortQty > 0.0 && !longAsset.isEmpty() && !shortAsset.isEmpty()) {
                bool isOption = contractType.toLower() == "option" || contractType.toLower() == "options";
                if (isOption) {
                    return tr("Option: %1 %2 ↔ %3 %4")
                        .arg(QString::number(longQty, 'f', longQty < 1.0 ? 4 : 2))
                        .arg(longAsset)
                        .arg(QString::number(shortQty, 'f', shortQty < 1.0 ? 4 : 2))
                        .arg(shortAsset);
                } else {
                    return tr("Forward: %1 %2 ↔ %3 %4")
                        .arg(QString::number(longQty, 'f', longQty < 1.0 ? 4 : 2))
                        .arg(longAsset)
                        .arg(QString::number(shortQty, 'f', shortQty < 1.0 ? 4 : 2))
                        .arg(shortAsset);
                }
            }

            return tr("%1 Contract").arg(contractType.toLower() == "option" || contractType.toLower() == "options" ? "Option" : "Forward");
        } else if (contractType.toLower() == "spot") {
            // Format: "Spot • 100 TOKA ↔ 200 TOKB"
            if (!contractPayload.isEmpty()) {
                QJsonParseError parseError;
                QJsonDocument payloadDoc = QJsonDocument::fromJson(contractPayload.toUtf8(), &parseError);
                if (!payloadDoc.isNull() && payloadDoc.isObject()) {
                    QJsonObject payloadObj = payloadDoc.object();
                    QJsonObject terms = payloadObj.value("terms").toObject();

                    // Extract alice_leg and bob_leg
                    QJsonObject aliceLeg = terms.value("alice_leg").toObject();
                    QJsonObject bobLeg = terms.value("bob_leg").toObject();

                    if (!aliceLeg.isEmpty() && !bobLeg.isEmpty()) {
                        // Parse alice leg
                        bool aliceIsNative = aliceLeg.value("is_native").toBool();
                        QString aliceAssetId = aliceLeg.value("asset_id").toString();
                        qint64 aliceUnits = aliceLeg.value("units").toVariant().toLongLong();

                        // Parse bob leg
                        bool bobIsNative = bobLeg.value("is_native").toBool();
                        QString bobAssetId = bobLeg.value("asset_id").toString();
                        qint64 bobUnits = bobLeg.value("units").toVariant().toLongLong();

                        // Get asset tickers and decimals
                        QString aliceAsset = aliceIsNative ? "TSC" : "???";
                        int aliceDecimals = 8;
                        if (!aliceIsNative && walletModel) {
                            WalletModel::AssetInfo info = walletModel->getAssetInfo(aliceAssetId);
                            if (!info.ticker.isEmpty()) {
                                aliceAsset = info.ticker;
                                aliceDecimals = info.has_decimals ? info.decimals : 8;
                            }
                        }

                        QString bobAsset = bobIsNative ? "TSC" : "???";
                        int bobDecimals = 8;
                        if (!bobIsNative && walletModel) {
                            WalletModel::AssetInfo info = walletModel->getAssetInfo(bobAssetId);
                            if (!info.ticker.isEmpty()) {
                                bobAsset = info.ticker;
                                bobDecimals = info.has_decimals ? info.decimals : 8;
                            }
                        }

                        // Convert units to display amounts
                        double aliceQty = aliceUnits / std::pow(10.0, aliceDecimals);
                        double bobQty = bobUnits / std::pow(10.0, bobDecimals);

                        return tr("Spot: %1 %2 ↔ %3 %4")
                            .arg(QString::number(aliceQty, 'f', aliceQty < 1.0 ? 4 : 2))
                            .arg(aliceAsset)
                            .arg(QString::number(bobQty, 'f', bobQty < 1.0 ? 4 : 2))
                            .arg(bobAsset);
                    }
                }
            }
            return tr("Spot Contract");
        }
    }

    // Fallback to original logic for non-contract offers
    QString offerType = offer.value("offer_type").toString();
    double amount = offer.value("amount").toDouble();
    QString assetSend = offer.value("asset_send").toString();
    QString assetRecv = offer.value("asset_recv").toString();

    QString direction;
    if (!offerType.isEmpty()) {
        direction = offerType.toUpper();
    }

    QString amountStr;
    if (amount > 0.0) {
        amountStr = QString::number(amount, 'f', amount < 1.0 ? 4 : 2);
    }

    if (!direction.isEmpty() && !amountStr.isEmpty() && !assetSend.isEmpty() && !assetRecv.isEmpty()) {
        return tr("%1 • %2 %3 → %4")
            .arg(direction)
            .arg(amountStr)
            .arg(assetSend)
            .arg(assetRecv);
    }

    if (!direction.isEmpty() && !assetSend.isEmpty()) {
        return tr("%1 • %2").arg(direction).arg(assetSend);
    }

    QString offerId = offer.value("id").toString();
    if (!offerId.isEmpty()) {
        return tr("Offer %1").arg(offerId.left(16) + "...");
    }

    if (!fallbackId.isEmpty()) {
        return tr("Offer %1").arg(fallbackId.left(16) + "...");
    }

    return tr("Offer (unknown)");
}

QString TradeBoardTab::formatStatusLabel(const TradeRequestInfo& info) const
{
    const QString statusLower = info.status.toLower();

    if (statusLower == "pending") {
        return tr("Pending");
    }

    if (statusLower == "accepted") {
        if (!info.invite_link.isEmpty()) {
            if (info.invite_expires_at > 0) {
                const qint64 now = QDateTime::currentDateTimeUtc().toSecsSinceEpoch();
                qint64 secondsLeft = info.invite_expires_at - now;
                if (secondsLeft <= 0) {
                    return tr("Accepted (invite expired)");
                }

                QString remaining;
                if (secondsLeft < 60) {
                    remaining = tr("%1s left").arg(secondsLeft);
                } else if (secondsLeft < 3600) {
                    remaining = tr("%1m left").arg(secondsLeft / 60);
                } else {
                    remaining = tr("%1h left").arg(secondsLeft / 3600);
                }

                return tr("Accepted (%1)").arg(remaining);
            }
            return tr("Accepted (invite ready)");
        }
        return tr("Accepted");
    }

    if (statusLower == "rejected") {
        return tr("Rejected");
    }

    if (statusLower == "cancelled") {
        return tr("Cancelled");
    }

    return info.status;
}


void TradeBoardTab::pollSessionMessages()
{
    if (!isVisible()) return;
    if (!walletModel) return;

    // A previous batch is still running on the worker thread. Skip this tick
    // rather than queue another: the cosign bridge serializes every command on
    // a single mutex (SendBridgeCommand holds m_mutex for the whole round-trip),
    // so overlapping batches would only stack up behind it and we'd fall
    // progressively further behind real time.
    if (m_sessionPollInFlight) return;

    // Snapshot the sessions to poll on the GUI thread (activeSessions /
    // ceremonySessions are GUI-thread state). Skip ceremony-busy sessions — the
    // TradeCeremonyRunner owns their stream.
    QStringList toPoll;
    const QStringList sessionIds = activeSessions.keys();
    for (const QString& session_id : sessionIds) {
        if (ceremonySessions.contains(session_id)) continue;
        toPoll.append(session_id);
    }
    if (toPoll.isEmpty()) return;

    if (!activeSessions.isEmpty()) {
        LogPrintf("TradeBoardTab::pollSessionMessages: Dispatching poll of %d session(s)\n", toPoll.size());
    }

    // Run the blocking per-session cosignRecv() round-trips on a worker thread.
    // Each blocks up to 100ms in poll(); with several sessions that is a visible
    // GUI stall on every 500ms tick. The worker touches only walletModel (bridge
    // access is mutex-serialized / thread-safe) and never `this`, so member
    // destruction during shutdown cannot race it; the InflightGuard keeps the
    // destructor's waitForInflightShutdown() blocked until the body returns, and
    // the QFutureWatcher is parented to `this` so Qt disconnects its finished
    // slot before any queued delivery after teardown.
    //
    // cosignRecv() is a DESTRUCTIVE read: it pops the next frame off each
    // session's bridge stream, and that frame may belong to a ceremony runner if
    // a ceremony starts for the session mid-poll. So we "claim" every polled
    // session in m_sessionsBeingPolled for the duration; launchOpeningCeremony()
    // and startPreparedTakerCeremony() defer while a session is claimed (see
    // those sites + drainDeferredCeremonyStarts()), which guarantees no consumed
    // frame is ever stranded. The claim and the in-flight flag are released only
    // AFTER processPolledSessionMessages() finishes — that method can open modal
    // dialogs which spin a nested event loop, and we must not let the 500ms timer
    // dispatch an overlapping batch in the meantime.
    m_sessionPollInFlight = true;
    for (const QString& session_id : toPoll) m_sessionsBeingPolled.insert(session_id);
    auto inflightGuard = std::make_shared<InflightGuard>(this);
    WalletModel* const wm = walletModel;  // worker uses ONLY this copied pointer
    auto* watcher = new QFutureWatcher<QList<PolledSessionRecv>>(this);
    connect(watcher, &QFutureWatcher<QList<PolledSessionRecv>>::finished, this,
            [this, watcher, toPoll]() {
        watcher->deleteLater();
        processPolledSessionMessages(watcher->result());
        for (const QString& session_id : toPoll) m_sessionsBeingPolled.remove(session_id);
        m_sessionPollInFlight = false;
        drainDeferredCeremonyStarts();
    });
    watcher->setFuture(QtConcurrent::run([wm, toPoll, inflightGuard]() -> QList<PolledSessionRecv> {
        (void)inflightGuard;  // keeps the guard alive for the duration of the body
        QList<PolledSessionRecv> out;
        out.reserve(toPoll.size());
        for (const QString& session_id : toPoll) {
            out.append({session_id, wm->cosignRecv(session_id, 100)});
        }
        return out;
    }));
}

// GUI-thread continuation of pollSessionMessages(): consumes the cosignRecv()
// results gathered off-thread and runs the per-session message state machine.
// It mutates activeSessions / activeRequests and drives ceremony handlers, so
// it must stay on the GUI thread.
void TradeBoardTab::processPolledSessionMessages(const QList<PolledSessionRecv>& polled)
{
    // Several branches below can call activeSessions.remove(session_id); defer
    // those to sessionsToRemove and drain after the loop, mirroring the original
    // inline-loop behavior (snapshot iteration so removals stay reentrant-safe).
    QStringList sessionsToRemove;
    for (const PolledSessionRecv& pr : polled) {
        const QString session_id = pr.session_id;
        // The session may have been torn down between snapshot and now (a prior
        // iteration's removal, or a ceremony start). Re-validate before use.
        if (!activeSessions.contains(session_id)) continue;
        const QString request_id = activeSessions.value(session_id);  // copy by value

        // No ceremony-ownership re-check here: this session was held in
        // m_sessionsBeingPolled for the entire poll, so launchOpeningCeremony() /
        // startPreparedTakerCeremony() could not have claimed it meanwhile (they
        // defer while a session is being polled). Every consumed frame is
        // therefore safe to apply — dropping one would strand it off the stream.
        auto recvResult = pr.result;

        if (!recvResult.success) {
            // Session might be closed or error
            LogPrintf("TradeBoardTab::pollSessionMessages: cosignRecv failed for session %s: %s\n",
                      session_id.toStdString().c_str(),
                      recvResult.error.toStdString().c_str());

            QString loweredError = recvResult.error.toLower();
            if (loweredError.contains("closed") ||
                loweredError.contains("unknown session") ||
                loweredError.contains("session not found") ||
                loweredError.contains("session expired") ||
                loweredError.contains("bridge restarted")) {
                sessionsToRemove.append(session_id);
                handleSessionLoss(session_id, request_id, recvResult.error);
            }
            continue;
        }

        if (recvResult.payload_json.isEmpty()) {
            continue; // No message
        }

        LogPrintf("TradeBoardTab: Received message on session %s: %s\n",
                  session_id.toStdString().c_str(),
                  recvResult.payload_json.left(200).toStdString().c_str());

        // Parse message JSON
        QJsonParseError parseError;
        QJsonDocument msgDoc = QJsonDocument::fromJson(recvResult.payload_json.toUtf8(), &parseError);
        if (msgDoc.isNull() || !msgDoc.isObject()) {
            LogPrintf("TradeBoardTab: Failed to parse message JSON: %s\n",
                      parseError.errorString().toStdString().c_str());
            continue;
        }

        QJsonObject msgObj = msgDoc.object();

        // CRITICAL: Unwrap message envelope (tests expect recv["payload"]["echo"]["data"])
        QString msgType = msgObj.value("type").toString();
        if (msgType == "response" && msgObj.contains("echo")) {
            QJsonValue echoValue = msgObj.value("echo");
            if (echoValue.isObject()) {
                msgObj = echoValue.toObject();
                LogPrintf("TradeBoardTab: Unwrapped echo envelope\n");
            }
        }

        QString schema = msgObj.value("schema").toString();
        LogPrintf("TradeBoardTab: Message schema='%s', has_id=%d, has_acceptance=%d\n",
                  schema.toStdString().c_str(),
                  msgObj.contains("id") ? 1 : 0,
                  msgObj.contains("acceptance") || msgObj.contains("acceptance_json") ? 1 : 0);

        // Handle based on message schema/type (after unwrapping echo)
        QString innerType = msgObj.value("type").toString();

        LogPrintf("TradeBoardTab: Processing message type='%s'\n", innerType.toStdString().c_str());

        // Match functional test message types
        if (innerType == "repo_acceptance" || innerType == "spot_acceptance" || innerType == "forward_acceptance") {
            // Acceptance from taker to maker (matches feature_fairsign_adaptor.py:1611-1624)
            LogPrintf("TradeBoardTab: Detected acceptance message (type=%s)\n", innerType.toStdString().c_str());
            if (msgObj.contains("acceptance")) {
                if (innerType == "forward_acceptance" && activeRequests.contains(request_id)) {
                    // Safe single-access update
                    activeRequests[request_id].offer_summary["contract_type"] = QStringLiteral("forward");
                    LogPrintf("TradeBoardTab: Marked request %s as forward contract based on acceptance envelope\n",
                              request_id.toStdString().c_str());
                }
                QJsonValue acceptanceValue = msgObj.value("acceptance");
                if (acceptanceValue.isObject()) {
                    QJsonDocument acceptanceDoc(acceptanceValue.toObject());
                    handleAcceptanceReceived(session_id, request_id, QString::fromUtf8(acceptanceDoc.toJson(QJsonDocument::Compact)));
                } else {
                    QJsonObject fallback;
                    fallback["acceptance"] = acceptanceValue;
                    QJsonDocument acceptanceDoc(fallback);
                    handleAcceptanceReceived(session_id, request_id, QString::fromUtf8(acceptanceDoc.toJson(QJsonDocument::Compact)));
                }
            }
        } else if (innerType == "difficulty_acceptance") {
            // Maker side: the taker accepted the self-contained difficulty term sheet. Import + verify,
            // then build the maker's base and drop into the standard maker_base_psbt -> ceremony path.
            LogPrintf("TradeBoardTab: Received difficulty_acceptance on session %s\n", session_id.toStdString().c_str());
            handleDifficultyAcceptanceReceived(session_id, request_id, msgObj);
        } else if (innerType == "ceremony_invite") {
            LogPrintf("TradeBoardTab: Detected ceremony invitation message\n");
            QJsonDocument unwrappedDoc(msgObj);
            handleCeremonyInviteReceived(session_id, QString::fromUtf8(unwrappedDoc.toJson(QJsonDocument::Compact)));
        } else if (innerType == "ceremony_ready") {
            // Taker has clicked "Proceed" and is ready to start ceremony
            LogPrintf("TradeBoardTab: Received ceremony_ready from taker on session %s\n",
                      session_id.toStdString().c_str());

            if (!activeRequests.contains(request_id)) {
                LogPrintf("TradeBoardTab: Cannot launch ceremony - request %s not found\n",
                          request_id.toStdString().c_str());
                continue;
            }

            // CRITICAL: Copy info to avoid QMap reference invalidation during processing
            TradeRequestInfo info = activeRequests[request_id];  // Deep copy
        if (!info.ceremony_invite_sent) {
            LogPrintf("TradeBoardTab: Ignoring ceremony_ready - not maker (request_id=%s, ceremony_invite_sent=%d, direction=%s)\n",
                      request_id.toStdString().c_str(),
                      info.ceremony_invite_sent, info.direction.toStdString().c_str());
            continue;
        }

            // Extract augmented PSBT from taker (immutability pattern)
            QString augmentedPsbt = msgObj.value("psbt").toString();  // Taker sends augmented PSBT as "psbt"
            if (augmentedPsbt.isEmpty()) {
                augmentedPsbt = msgObj.value("augmented_psbt").toString();  // Fallback for old format
            }
            if (!augmentedPsbt.isEmpty()) {
                info.augmented_psbt = augmentedPsbt;
                if (walletModel) {
                    auto annotate = walletModel->walletProcessPsbt(info.augmented_psbt,
                                                                   /*sign=*/false,
                                                                   QStringLiteral("DEFAULT"),
                                                                   /*bip32derivs=*/true,
                                                                   /*finalize=*/false);
                    if (annotate.success && !annotate.psbt.isEmpty()) {
                        info.augmented_psbt = annotate.psbt;
                    }
                }
                // Compute hash for verification
                info.augmented_psbt_hash = ComputePsbtTxHash(info.augmented_psbt);
                info.psbt_locked = true;
                info.staged_peer_base_psbt = info.augmented_psbt;
                info.staged_peer_base_ready = true;
                LogPrintf("TradeBoardTab: Maker received and locked augmented PSBT from taker (%d bytes, hash=%s)\n",
                          info.augmented_psbt.length(), info.augmented_psbt_hash.toStdString().c_str());

                // Guard: verify augmented PSBT matches finalized terms (both legs must be present)
                // NOTE: Only validate repo contracts - forward contracts have IM vaults not principal/collateral
                if (!info.final_offer_json.isEmpty()) {
                    // Use canonical cache to determine contract type
                    QString contractId = info.final_offer_id.isEmpty() ? info.offer_id : info.final_offer_id;
                    QString contractType = getCanonicalContractType(contractId);
                    if (contractType.isEmpty()) {
                        contractType = info.offer_summary.value("contract_type").toString().toLower();
                        LogPrintf("TradeBoardTab: WARNING - No cached contract type for %s, using offer_summary fallback\n",
                                  contractId.toStdString().c_str());
                    }
                    bool isForward = (contractType == "forward" || contractType == "option");
                    bool isSpot = (contractType == "spot");

                    if (isForward) {
                        // FORWARD: Skip PSBT validation - IM vaults validated by wallet RPC
                        LogPrintf("TradeBoardTab: Skipping PSBT validation for forward contract (validated by wallet)\n");
                    } else if (isSpot) {
                        // SPOT: Skip detailed PSBT validation - atomic swap structure validated by wallet RPC
                        LogPrintf("TradeBoardTab: Skipping PSBT validation for spot contract (validated by wallet)\n");
                    } else {
                        // REPO: Validate principal + collateral outputs
                        RepoTermsSnapshot terms;
                        if (ExtractRepoTermsFromJson(info.final_offer_json, terms)) {
                            PartiallySignedTransaction aug;
                            std::string derr;
                            if (DecodeBase64PSBT(aug, info.augmented_psbt.toStdString(), derr) && aug.tx) {
                                QString why;
                                if (!RepoPsbtMatchesTerms(aug, terms, /*require_principal=*/true, /*require_collateral=*/true, &why)) {
                                    LogPrintf("TradeBoardTab: Rejecting augmented PSBT - %s\n", why.toStdString().c_str());
                                    sendCeremonyError(session_id, tr("augmented_psbt check"), why);
                                    info.staged_peer_base_ready = false;
                                    continue;
                                }
                            } else {
                                LogPrintf("TradeBoardTab: ERROR decoding augmented PSBT: %s\n", derr.c_str());
                                sendCeremonyError(session_id, tr("augmented_psbt check"), tr("Invalid augmented PSBT"));
                                info.staged_peer_base_ready = false;
                                continue;
                            }
                        }
                    }
                }
            } else {
                LogPrintf("TradeBoardTab: WARNING - ceremony_ready missing augmented PSBT\n");
            }

            // Write modified info back to map before launching ceremony (safe single-access)
            if (activeRequests.contains(request_id)) {
                activeRequests[request_id] = info;
                LogPrintf("TradeBoardTab: Wrote ceremony_ready updates back to activeRequests for request %s\n",
                          request_id.toStdString().c_str());
            }

            // If the taker advertised cooperative non-atomic signing, get
            // explicit maker consent BEFORE starting the ceremony. The maker
            // is the last signer and broadcaster so they aren't structurally
            // worse off, but they should still see and acknowledge the loss
            // of cryptographic atomicity.
            const QString signingMode = msgObj.value("signing_mode").toString();

            // Defence-in-depth: refuse outright only when the taker's augmented
            // PSBT cannot be classified at all (undecodable or unknown input
            // types). Mixed Taproot+non-Taproot funding is supported through
            // the cooperative non-atomic path below — the whole PSBT collapses
            // to non-atomic signing under SIGHASH_ALL, with no hybrid where
            // some inputs retain atomicity. Pure-Taproot ceremonies still go
            // atomic via the runner's adaptor path.
            {
                const auto preClass = ClassifyPsbtInputs(info.augmented_psbt);
                if (!preClass.decode_succeeded || preClass.unknown_inputs > 0) {
                    LogPrintf("TradeBoardTab: Refusing ceremony_ready — PSBT classification ambiguous (decode_ok=%d, unknown=%d, signing_mode='%s')\n",
                              preClass.decode_succeeded ? 1 : 0,
                              preClass.unknown_inputs,
                              signingMode.toStdString().c_str());
                    sendCeremonyError(session_id, tr("funding classification"),
                        tr("Refusing ceremony: cannot classify funding inputs "
                           "(decode_ok=%1, unknown_inputs=%2). Atomic adaptor "
                           "and cooperative non-atomic paths both require a "
                           "PSBT whose inputs we can fully classify.")
                            .arg(preClass.decode_succeeded ? 1 : 0)
                            .arg(preClass.unknown_inputs));
                    if (walletModel) {
                        walletModel->cosignClose(session_id);
                    }
                    activeSessions.remove(session_id);
                    ceremonySessions.remove(session_id);
                    if (sessionManager) sessionManager->removeSession(session_id);
                    activeRequests[request_id] = info;
                    continue;
                }
            }

            if (signingMode == QStringLiteral("cooperative_non_atomic")) {
                const auto classification = ClassifyPsbtInputs(info.augmented_psbt);
                if (classification.unknown_inputs > 0 || !classification.decode_succeeded) {
                    LogPrintf("TradeBoardTab: Refusing cooperative downgrade — PSBT classification ambiguous (decode_ok=%d, unknown=%d)\n",
                              classification.decode_succeeded ? 1 : 0,
                              classification.unknown_inputs);
                    sendCeremonyError(session_id, tr("cooperative consent"),
                        tr("Refusing cooperative non-atomic signing: PSBT input classification is ambiguous"));
                    activeRequests[request_id] = info;
                    continue;
                }
                if (classification.non_taproot_inputs == 0) {
                    LogPrintf("TradeBoardTab: Refusing cooperative downgrade — PSBT has no non-Taproot inputs (taproot=%d)\n",
                              classification.taproot_inputs);
                    sendCeremonyError(session_id, tr("cooperative consent"),
                        tr("Refusing cooperative non-atomic signing: PSBT has no non-Taproot inputs (nothing to downgrade)"));
                    activeRequests[request_id] = info;
                    continue;
                }
                // Mixed Taproot+non-Taproot funding IS supported via cooperative.
                // The whole PSBT collapses to non-atomic signing (no hybrid).
                // The taker has consented via signing_mode=cooperative_non_atomic
                // in ceremony_ready, knowingly giving up Taproot atomicity on
                // any Taproot inputs they contribute. The maker is the last
                // signer and broadcaster regardless, so structurally safe.
                const bool psbtHasTaproot = classification.taproot_inputs > 0;

                QMessageBox msgBox(TopLevelDialogParent(this));
                msgBox.setIcon(QMessageBox::Warning);
                msgBox.setWindowTitle(tr("Cooperative Signing Requested"));
                QString bodyText = tr(
                    "Your counterparty has %1 non-Taproot funding input(s)%2, "
                    "so the atomic adaptor ceremony cannot run. They have "
                    "requested cooperative non-atomic signing: they sign first, "
                    "you sign second and broadcast.\n\n"
                    "You will be the last signer and the broadcaster — you can "
                    "inspect their signed PSBT and refuse to sign if anything "
                    "looks wrong. The trade-off is that the protocol no longer "
                    "provides a cryptographic guarantee that both sides reveal "
                    "their secrets simultaneously; once your counterparty hands "
                    "you their signed PSBT they are committing to the deal even "
                    "if you walk away.")
                    .arg(classification.non_taproot_inputs)
                    .arg(psbtHasTaproot
                        ? tr(" plus %1 Taproot input(s) that lose their atomicity guarantee in this mode")
                            .arg(classification.taproot_inputs)
                        : QString());
                bodyText += tr("\n\nAccept their offer and continue with cooperative signing, "
                               "or reject and abort the ceremony?");
                msgBox.setText(bodyText);
                QPushButton* acceptBtn = msgBox.addButton(tr("Accept downgrade"), QMessageBox::AcceptRole);
                QPushButton* rejectBtn = msgBox.addButton(tr("Reject and abort"), QMessageBox::RejectRole);
                msgBox.setDefaultButton(rejectBtn);
                msgBox.exec();

                if (msgBox.clickedButton() == rejectBtn || msgBox.clickedButton() == nullptr) {
                    LogPrintf("TradeBoardTab: Maker rejected cooperative downgrade — aborting ceremony for request %s\n",
                              request_id.toStdString().c_str());
                    QJsonObject abort;
                    abort["type"] = QStringLiteral("ceremony_abort");
                    abort["reason"] = QStringLiteral("maker_rejected_cooperative_downgrade");
                    const QString abortJson = QString::fromUtf8(QJsonDocument(abort).toJson(QJsonDocument::Compact));
                    walletModel->cosignSend(session_id, abortJson);  // best-effort
                    walletModel->cosignClose(session_id);             // tear down bridge session
                    activeSessions.remove(session_id);
                    ceremonySessions.remove(session_id);
                    if (sessionManager) sessionManager->removeSession(session_id);
                    activeRequests[request_id] = info;
                    continue;
                }

                LogPrintf("TradeBoardTab: Maker accepted cooperative downgrade for request %s\n",
                          request_id.toStdString().c_str());
                info.cooperative_consent = true;
            }
            activeRequests[request_id] = info;

            // Launch maker's ceremony now that taker is ready
            LogPrintf("TradeBoardTab: READ maker_role='%s' from request %s (offer=%s)\n",
                      info.maker_role.toStdString().c_str(),
                      request_id.toStdString().c_str(),
                      info.offer_id.toStdString().c_str());
            QString makerRoleNormalized = info.maker_role.toLower();
            LogPrintf("TradeBoardTab: Taker is ready, launching maker ceremony for offer %s (cooperative=%d)\n",
                      info.offer_id.toStdString().c_str(),
                      info.cooperative_consent ? 1 : 0);
            launchOpeningCeremony(info.offer_id, session_id, makerRoleNormalized);
        } else if (innerType == "finalized_offer" && msgObj.contains("offer")) {
            // Wrapped finalized offer from maker to taker (with maker base PSBT for immutability)
            LogPrintf("TradeBoardTab: Detected wrapped finalized offer message\n");
            QJsonValue offerValue = msgObj.value("offer");
            QString makerBasePsbt = msgObj.value("maker_base_psbt").toString();
            if (offerValue.isObject()) {
                QJsonDocument offerDoc(offerValue.toObject());
                handleFinalizedOfferReceived(session_id, request_id, QString::fromUtf8(offerDoc.toJson(QJsonDocument::Compact)), makerBasePsbt);
            }
        } else if (innerType == "maker_base_psbt" && msgObj.contains("psbt")) {
            // Maker sends base PSBT after importing taker's acceptance (immutability pattern)
            LogPrintf("TradeBoardTab: Received maker_base_psbt message on session %s\n", session_id.toStdString().c_str());
            QString makerBasePsbt = msgObj.value("psbt").toString();
            QString offer_id = msgObj.value("offer_id").toString();
            QString makerRole = msgObj.value("maker_role").toString();

            if (makerBasePsbt.isEmpty()) {
                LogPrintf("TradeBoardTab: Ignoring empty maker base PSBT\n");
                continue;
            }

            if (!activeRequests.contains(request_id)) {
                LogPrintf("TradeBoardTab: Received maker base PSBT for unknown request %s\n", request_id.toStdString().c_str());
                continue;
            }

            TradeRequestInfo& info = activeRequests[request_id];

            // Guard: Verify maker base PSBT matches the accepted terms before caching (REPO only)
            // Determine contract type
            QString contractId = info.final_offer_id.isEmpty() ? info.offer_id : info.final_offer_id;
            QString contractType = getCanonicalContractType(contractId);
            if (contractType.isEmpty()) {
                contractType = info.offer_summary.value("contract_type").toString().toLower();
            }

            // Only validate PSBT structure for repo contracts
            // Spot and forward PSBTs are validated by wallet RPC during build
            if (contractType == "repo") {
                bool terms_ok = false;
                RepoTermsSnapshot terms;
                if (!info.final_offer_json.isEmpty()) {
                    terms_ok = ExtractRepoTermsFromJson(info.final_offer_json, terms);
                }
                if (terms_ok) {
                    PartiallySignedTransaction basePsbtDecoded;
                    std::string decodeError;
                    if (!DecodeBase64PSBT(basePsbtDecoded, makerBasePsbt.toStdString(), decodeError) || !basePsbtDecoded.tx) {
                        LogPrintf("TradeBoardTab: ERROR decoding maker_base_psbt: %s\n", decodeError.c_str());
                        sendCeremonyError(session_id, tr("base_psbt check"), tr("Invalid PSBT from maker"));
                        continue;
                    }
                    const QString roleLower = makerRole.toLower();
                    const bool require_principal = (roleLower == QLatin1String("lender"));
                    const bool require_collateral = (roleLower == QLatin1String("borrower"));
                    QString why;
                    if (!RepoPsbtMatchesTerms(basePsbtDecoded, terms, require_principal, require_collateral, &why)) {
                        LogPrintf("TradeBoardTab: Rejecting maker_base_psbt - %s\n", why.toStdString().c_str());
                        sendCeremonyError(session_id, tr("base_psbt check"), why);
                        continue;
                    }
                } else {
                    LogPrintf("TradeBoardTab: WARNING - No finalized terms available to verify maker_base_psbt\n");
                }
            } else {
                LogPrintf("TradeBoardTab: Skipping PSBT structure validation for %s contract (validated by wallet)\n",
                          contractType.toStdString().c_str());
            }

            info.maker_base_psbt = makerBasePsbt;
            info.maker_role = makerRole;  // Cache maker role for later
            LogPrintf("TradeBoardTab: Taker received and cached maker base PSBT (%d bytes)\n", makerBasePsbt.length());

            // DIFFICULTY: the taker already committed by sending difficulty_acceptance, so it auto-augments
            // + sends ceremony_ready the moment the maker's base arrives — no separate ceremony_invite, no
            // manual "Proceed". The base is cached (above) BEFORE this trigger, so launchOpeningCeremonyTaker
            // always finds it. launchOpeningCeremonyTaker is idempotent (augmented_psbt / ceremony_ready_sent).
            if (contractType == "difficulty") {
                const QString oid = info.offer_id, sid = session_id, mr = makerRole;
                updateTradeRequestsList();
                QTimer::singleShot(0, this, [this, oid, sid, mr]() { launchOpeningCeremonyTaker(oid, sid, mr); });
            } else {
                // Other types: wait for the maker's ceremony_invite (handleCeremonyInviteReceived) / Proceed.
                updateTradeRequestsList();
            }
        } else if (innerType.startsWith("base_psbt_") && msgObj.contains("psbt")) {
            QString basePsbt = msgObj.value("psbt").toString();
            if (basePsbt.isEmpty()) {
                LogPrintf("TradeBoardTab: Ignoring empty base PSBT for session %s\n",
                          session_id.toStdString().c_str());
                continue;
            }

            if (!activeRequests.contains(request_id)) {
                LogPrintf("TradeBoardTab: Received base PSBT for unknown request %s (session %s)\n",
                          request_id.toStdString().c_str(),
                          session_id.toStdString().c_str());
                continue;
            }

            TradeRequestInfo& info = activeRequests[request_id];
            info.staged_peer_base_psbt = basePsbt;
            info.staged_peer_base_ready = true;

            // Determine ceremony role based on who sent the ceremony_invite, not trade direction
            // - Maker sent ceremony_invite → we are the maker
            // - Maker sent ceremony_invite → we are the taker (acceptor)
            const bool isMaker = info.ceremony_invite_sent;
            QString makerRoleLower = info.maker_role.toLower();
            QString takerRole;
            if (makerRoleLower == "lender") {
                takerRole = QStringLiteral("borrower");
            } else if (makerRoleLower == "borrower") {
                takerRole = QStringLiteral("lender");
            } else if (makerRoleLower == "long") {
                takerRole = QStringLiteral("short");
            } else if (makerRoleLower == "short") {
                takerRole = QStringLiteral("long");
            }

            if (!isMaker) {
                if (info.staged_local_base_ready) {
                    LogPrintf("TradeBoardTab: Taker already staged augmented base for request %s; skipping duplicate\n",
                              request_id.toStdString().c_str());
                    continue;
                }

                if (!walletModel) {
                    LogPrintf("TradeBoardTab: Wallet unavailable while augmenting base PSBT (request %s)\n",
                              request_id.toStdString().c_str());
                    continue;
                }

                // Use finalized contract ID (32-byte hex), not bulletin board offer_id (UUID)
                QString contractId = info.final_offer_id.isEmpty() ? info.offer_id : info.final_offer_id;

                // CRITICAL: Use canonical contract type from cache, not heuristics
                // Cache should have been populated when finalized offer was received
                QString contractType = getCanonicalContractType(contractId);
                if (contractType.isEmpty()) {
                    // Cache miss - try to populate from available data
                    if (!ensureContractFlavorLoaded(contractId, info.offer_summary.value("contract_type").toString())) {
                        LogPrintf("ERROR: Cannot determine contract type for %s\n", contractId.toStdString().c_str());
                        sendCeremonyError(session_id, tr("contract type"), tr("Unable to determine contract type"));
                        showNonBlockingInfo(tr("Ceremony Preparation Failed"),
                            tr("Cannot determine if this is a repo or forward contract.\n\nContract ID: %1").arg(contractId));
                        continue;
                    }
                    contractType = getCanonicalContractType(contractId);
                }

                bool isForward = (contractType == "forward" || contractType == "option");
                LogPrintf("TradeBoardTab: Taker augmenting base PSBT (contract_type=%s [canonical], taker_role=%s, contract_id=%s)\n",
                          contractType.toStdString().c_str(), takerRole.toStdString().c_str(),
                          contractId.toStdString().c_str());

                QVariantMap buildOptions;
                buildOptions["psbt"] = basePsbt;

                // Use user-selected fee strategy for taker's funding (stored during acceptance)
                QString feeStrategy = info.taker_fee_strategy.isEmpty() ? QStringLiteral("medium") : info.taker_fee_strategy;
                LogPrintf("TradeBoardTab: Taker using user-selected fee_strategy='%s' for funding\n", feeStrategy.toStdString().c_str());
                buildOptions["strategy"] = feeStrategy;

                // Convert fee strategy to numeric rate (low=2, medium=10, high=50 sat/vB)
                double feeRate = 10.0;
                QString strategyLower = feeStrategy.toLower();
                if (strategyLower == "low") {
                    feeRate = 2.0;
                } else if (strategyLower == "high") {
                    feeRate = 50.0;
                }
                buildOptions["fee_rate"] = feeRate;
                LogPrintf("TradeBoardTab: TAKER pollSessionMessages - fee_rate=%.1f sat/vB (strategy=%s)\n",
                          feeRate, feeStrategy.toStdString().c_str());

                QString augmentedPsbt;
                int alice_vault_idx = -1;
                int bob_vault_idx = -1;
                int premium_out_idx = -1;

                if (isForward) {
                    // DEFENSIVE: Verify we're calling the right RPC
                    if (contractType != "forward" && contractType != "option") {
                        LogPrintf("FATAL: About to call forward.build_open but contract_type='%s'\n",
                                  contractType.toStdString().c_str());
                        sendCeremonyError(session_id, tr("RPC mismatch"), tr("Internal error: contract type mismatch"));
                        showNonBlockingInfo(tr("Ceremony Preparation Failed"),
                            tr("Internal error: attempted to use forward RPC for %1 contract").arg(contractType));
                        continue;
                    }

                    // FORWARD/OPTIONS: Auto-fund based on taker role
                    if (takerRole == "long") {
                        buildOptions["auto_fund_long"] = true;
                        buildOptions["auto_fund_premium"] = true;  // Long may pay premium
                    } else if (takerRole == "short") {
                        buildOptions["auto_fund_short"] = true;
                        // Note: Do NOT set auto_fund_premium here
                        // Premium is funded by long party in their base PSBT
                        // Short party only adds their short IM funding
                    }

                    auto forwardResult = walletModel->forwardBuildOpen(contractId, buildOptions);
                    if (!forwardResult.success) {
                        LogPrintf("TradeBoardTab: Failed to augment forward base PSBT for request %s: %s\n",
                                  request_id.toStdString().c_str(),
                                  forwardResult.error.toStdString().c_str());
                        sendCeremonyError(session_id, tr("augment base"), forwardResult.error);
                        showNonBlockingInfo(tr("Ceremony Preparation Failed"),
                            tr("Could not add your funding to the forward opening transaction:\n\n%1")
                                .arg(forwardResult.error));
                        continue;
                    }

                    augmentedPsbt = forwardResult.psbt;
                    alice_vault_idx = forwardResult.alice_vault_index;
                    bob_vault_idx = forwardResult.bob_vault_index;
                    premium_out_idx = forwardResult.premium_output_index;

                    LogPrintf("TradeBoardTab: Taker augmented forward PSBT - alice_vault=%d, bob_vault=%d, premium=%d\n",
                              alice_vault_idx, bob_vault_idx, premium_out_idx);

                    // Store vault indices
                    info.alice_vault_index = alice_vault_idx;
                    info.bob_vault_index = bob_vault_idx;
                    info.premium_output_index = premium_out_idx;

                } else if (contractType == "spot") {
                    // SPOT: Build atomic swap PSBT
                    LogPrintf("TradeBoardTab: Taker building spot atomic swap PSBT (offer=%s)\n",
                              contractId.toStdString().c_str());

                    auto spotResult = walletModel->spotBuildAtomic(contractId, buildOptions);
                    if (!spotResult.success) {
                        LogPrintf("TradeBoardTab: Failed to build spot atomic PSBT for request %s: %s\n",
                                  request_id.toStdString().c_str(),
                                  spotResult.error.toStdString().c_str());
                        sendCeremonyError(session_id, tr("build atomic"), spotResult.error);
                        showNonBlockingInfo(tr("Ceremony Preparation Failed"),
                            tr("Could not build the atomic swap transaction:\n\n%1")
                                .arg(spotResult.error));
                        continue;
                    }

                    augmentedPsbt = spotResult.psbt;
                    LogPrintf("TradeBoardTab: Taker built spot atomic swap PSBT (%d bytes)\n",
                              augmentedPsbt.length() / 2);

                } else {
                    // DEFENSIVE: Verify we're calling the right RPC
                    if (contractType != "repo") {
                        LogPrintf("FATAL: About to call repo.build_open but contract_type='%s'\n",
                                  contractType.toStdString().c_str());
                        sendCeremonyError(session_id, tr("RPC mismatch"), tr("Internal error: contract type mismatch"));
                        showNonBlockingInfo(tr("Ceremony Preparation Failed"),
                            tr("Internal error: attempted to use repo RPC for %1 contract").arg(contractType));
                        continue;
                    }

                    // REPO: Auto-fund based on taker role
                    if (takerRole == "borrower") {
                        buildOptions["auto_fund_collateral"] = true;
                    } else {
                        buildOptions["auto_fund_principal"] = true;
                    }

                    auto augmentResult = walletModel->repoBuildOpen(contractId, buildOptions);
                    if (!augmentResult.success) {
                        LogPrintf("TradeBoardTab: Failed to augment repo base PSBT for request %s: %s\n",
                                  request_id.toStdString().c_str(),
                                  augmentResult.error.toStdString().c_str());
                        sendCeremonyError(session_id, tr("augment base"), augmentResult.error);
                        showNonBlockingInfo(tr("Ceremony Preparation Failed"),
                            tr("Could not add your funding to the opening transaction:\n\n%1")
                                .arg(augmentResult.error));
                        continue;
                    }

                    augmentedPsbt = augmentResult.psbt;
                }

                // Annotate augmented PSBT with wallet metadata similar to tests
                {
                    auto annotate = walletModel->walletProcessPsbt(augmentedPsbt,
                                                                   /*sign=*/false,
                                                                   QStringLiteral("DEFAULT"),
                                                                   /*bip32derivs=*/true,
                                                                   /*finalize=*/false);
                    if (annotate.success && !annotate.psbt.isEmpty()) {
                        augmentedPsbt = annotate.psbt;
                    }
                }

                // Preflight: ensure augmented PSBT has at least one SPENDABLE input owned by this wallet
                {
                    QString details;
                    QString errText;
                    if (!PsbtHasSpendableInputs(walletModel, augmentedPsbt, &details, &errText)) {
                        LogPrintf("TradeBoardTab: Taker augmented PSBT not signable by this wallet: %s\n",
                                  errText.toStdString().c_str());
                        sendCeremonyError(session_id, tr("augment base"), errText);
                        showNonBlockingInfo(tr("Ceremony Preparation Failed"),
                            tr("Your augmented PSBT does not include any inputs this wallet can sign.\n\n%1")
                                .arg(details));
                        continue;
                    }
                }

                info.staged_local_base_psbt = augmentedPsbt;
                info.staged_local_base_ready = true;
                LogPrintf("TradeBoardTab: Taker staged augmented base PSBT for request %s (%s contract)\n",
                          request_id.toStdString().c_str(), contractType.toStdString().c_str());

                QString replyType = takerRole.isEmpty()
                    ? QStringLiteral("base_psbt_peer")
                    : QStringLiteral("base_psbt_%1").arg(takerRole);
                QJsonObject payload;
                payload["type"] = replyType;
                payload["psbt"] = augmentedPsbt;

                // Include vault indices for forward contracts
                if (isForward) {
                    if (alice_vault_idx >= 0) {
                        payload["alice_vault_index"] = alice_vault_idx;
                    }
                    if (bob_vault_idx >= 0) {
                        payload["bob_vault_index"] = bob_vault_idx;
                    }
                    if (premium_out_idx >= 0) {
                        payload["premium_output_index"] = premium_out_idx;
                    }
                }
                QString json = QString::fromUtf8(QJsonDocument(payload).toJson(QJsonDocument::Compact));
                WalletModel::CosignSendResult sendRes = walletModel->cosignSend(session_id, json);
                if (!sendRes.success) {
                    LogPrintf("TradeBoardTab: Failed to send augmented base PSBT on session %s: %s\n",
                              session_id.toStdString().c_str(),
                              sendRes.error.toStdString().c_str());
                    sendCeremonyError(session_id, tr("send base"), sendRes.error);
                } else {
                    LogPrintf("TradeBoardTab: Sent augmented base PSBT (type=%s) on session %s\n",
                              replyType.toStdString().c_str(),
                              session_id.toStdString().c_str());
                }

                maybeStartTakerCeremony(session_id, info.maker_role);
            } else {
                LogPrintf("TradeBoardTab: Maker staged taker base PSBT (type=%s) for request %s\n",
                          innerType.toStdString().c_str(),
                          request_id.toStdString().c_str());
                // FIX: Also check if taker ceremony should start (handles case where taker has outgoing direction)
                maybeStartTakerCeremony(session_id, info.maker_role);
            }
            continue;
        } else if (msgObj.contains("id") && (msgObj.contains("contract_type") || msgObj.contains("version"))) {
            // Unwrapped contract (legacy or direct send) - no maker base PSBT available
            LogPrintf("TradeBoardTab: Detected unwrapped contract message\n");
            QJsonDocument unwrappedDoc(msgObj);
            handleFinalizedOfferReceived(session_id, request_id, QString::fromUtf8(unwrappedDoc.toJson(QJsonDocument::Compact)), QString());
        } else if (innerType == "ceremony_error" || innerType == "ceremony_abort") {
            // Pre-runner terminal frame. We can only reach this branch when no
            // TradeCeremonyRunner is active for this session, because the guard
            // at the top of pollSessionMessages() skips sessions in
            // ceremonySessions before reading. If we fell through to the
            // generic "skip to let ceremony runner handle it" branch below,
            // the frame would be silently dropped — the runner doesn't exist,
            // and the maker would keep polling forever for a ceremony_ready
            // that the peer has already refused. Surface the failure,
            // unlock funds, and tear down the bridge session here.
            QString peerStage = msgObj.value("stage").toString();   // ceremony_error
            QString peerPhase = msgObj.value("phase").toString();   // ceremony_abort
            QString peerRole  = msgObj.value("role").toString();    // ceremony_abort
            QString reason = (innerType == "ceremony_error")
                ? msgObj.value("error").toString()
                : msgObj.value("reason").toString();
            LogPrintf("TradeBoardTab: Pre-runner terminal frame on session %s: type=%s stage='%s' phase='%s' role='%s' reason='%s'\n",
                      session_id.toStdString().c_str(),
                      innerType.toStdString().c_str(),
                      peerStage.toStdString().c_str(),
                      peerPhase.toStdString().c_str(),
                      peerRole.toStdString().c_str(),
                      reason.toStdString().c_str());

            const QString headline = (innerType == "ceremony_error")
                ? tr("Counterparty refused the ceremony")
                : tr("Counterparty aborted the ceremony");
            QString detail;
            if (!peerPhase.isEmpty() && !reason.isEmpty()) {
                detail = tr("Phase %1: %2").arg(peerPhase, reason);
            } else if (!peerStage.isEmpty() && !reason.isEmpty()) {
                detail = tr("Stage %1: %2").arg(peerStage, reason);
            } else if (!reason.isEmpty()) {
                detail = reason;
            } else {
                detail = tr("No reason provided.");
            }

            if (!request_id.isEmpty() && activeRequests.contains(request_id)) {
                TradeRequestInfo& infoRef = activeRequests[request_id];
                if (infoRef.psbt_locked) {
                    LogPrintf("TradeBoardTab: Unlocking PSBT for request %s after pre-runner terminal frame\n",
                              request_id.toStdString().c_str());
                    if (!infoRef.augmented_psbt.isEmpty()) {
                        UnlockFairSignUTXOsForPsbt(walletModel, infoRef.augmented_psbt,
                                                   "Pre-runner ceremony terminal frame");
                    }
                    infoRef.psbt_locked = false;
                    infoRef.augmented_psbt.clear();
                    infoRef.augmented_psbt_hash.clear();
                }
                infoRef.ceremony_ready_sent = false;
                infoRef.taker_ready_for_ceremony = false;
                infoRef.waiting_for_base_notice_sent = false;
                infoRef.recovering_session = false;
            }

            if (walletModel) {
                walletModel->cosignClose(session_id);  // best-effort
            }
            activeSessions.remove(session_id);
            ceremonySessions.remove(session_id);
            if (sessionManager) sessionManager->removeSession(session_id);

            QMessageBox::critical(this, headline,
                tr("%1\n\n%2\n\nThe session has been closed.").arg(headline, detail));

            updateOffersList();
            updateTradeRequestsList();
            continue;
        } else if (innerType.startsWith("nonce_psbt_") || innerType.startsWith("partial_psbt_") ||
                   innerType.startsWith("base_psbt_") || innerType.startsWith("complete_psbt_") ||
                   innerType.startsWith("signed_psbt_") ||
                   innerType == "bip322_challenge" || innerType == "bip322_response" ||
                   innerType == "ceremony_complete") {
            // Phase / attestation / cooperative-complete frames that belong to
            // an in-flight TradeCeremonyRunner. The guard at the top of
            // pollSessionMessages() skips sessions where the runner is active,
            // so if we reach here it means the runner isn't currently reading.
            // Leave the frame untouched in case the runner is about to start
            // (the immediate post-handshake / pre-runner window). The terminal
            // ceremony_error / ceremony_abort cases are handled separately
            // above so they don't get stuck here forever.
            LogPrintf("TradeBoardTab: Detected ceremony message type='%s', skipping to let ceremony runner handle it\n",
                      innerType.toStdString().c_str());
            continue;
        // -- Cross-chain session messages --
        } else if (innerType == "xchain_accept") {
            // Taker accepted a cross-chain offer.  Extract their settlement
            // profile, secret hash, and expected HTLC parameters.  Maker
            // auto-creates the CrossChainRecord and replies with xchain_params.
            LogPrintf("TradeBoardTab: Received xchain_accept on session %s\n",
                      session_id.toStdString().c_str());
            handleXchainAccept(session_id, request_id, msgObj);

        } else if (innerType == "xchain_params") {
            // Maker confirmed HTLC parameters.  Taker auto-creates the
            // CrossChainRecord with expected values and registers with the
            // manager.
            LogPrintf("TradeBoardTab: Received xchain_params on session %s\n",
                      session_id.toStdString().c_str());
            handleXchainParams(session_id, request_id, msgObj);

        } else if (innerType == "xchain_lock_notify") {
            // Advisory: peer reports they broadcast the lock tx.
            // Truth comes from chain, but this accelerates detection.
            LogPrintf("TradeBoardTab: Received xchain_lock_notify on session %s: tx=%s\n",
                      session_id.toStdString().c_str(),
                      msgObj.value("lock_tx_hash").toString().toStdString().c_str());

        } else if (innerType == "xchain_claim_notify") {
            // Advisory: peer reports they revealed the secret.
            LogPrintf("TradeBoardTab: Received xchain_claim_notify on session %s\n",
                      session_id.toStdString().c_str());

        } else {
            LogPrintf("TradeBoardTab: Unknown/unhandled message type='%s', keys=%s\n",
                      innerType.toStdString().c_str(),
                      msgObj.keys().join(", ").toStdString().c_str());
        }
    }

    // Remove closed sessions
    for (const QString& sid : sessionsToRemove) {
        activeSessions.remove(sid);
    }
}

// Replays ceremony starts that launchOpeningCeremony()/startPreparedTakerCeremony()
// deferred because their session was mid-poll. Called by the poll continuation
// right after it releases the session claims (and before it yields to the event
// loop, so no fresh batch can re-claim in between under normal flow). The queue
// is swapped out first so a defensive re-defer can't spin.
void TradeBoardTab::drainDeferredCeremonyStarts()
{
    if (m_deferredCeremonyStarts.isEmpty()) return;
    QList<PendingCeremonyStart> pending;
    pending.swap(m_deferredCeremonyStarts);
    for (const PendingCeremonyStart& p : pending) {
        if (m_sessionsBeingPolled.contains(p.session_id)) {
            // A new poll batch already re-claimed this session — defer again.
            m_deferredCeremonyStarts.append(p);
            continue;
        }
        if (ceremonySessions.contains(p.session_id)) {
            // Ownership was taken by another path in the meantime; nothing to do.
            continue;
        }
        if (p.isMaker) {
            launchOpeningCeremony(p.offer_id, p.session_id, p.maker_role);
        } else if (activeRequests.contains(p.request_id)) {
            startPreparedTakerCeremony(p.offer_id, p.session_id, activeRequests[p.request_id], p.maker_role);
        } else {
            LogPrintf("TradeBoardTab: Dropping deferred taker ceremony for session %s — request %s no longer active\n",
                      p.session_id.toStdString().c_str(), p.request_id.toStdString().c_str());
        }
    }
}

void TradeBoardTab::handleFinalizedOfferReceived(const QString& session_id, const QString& request_id, const QString& offer_json, const QString& makerBasePsbt)
{
    LogPrintf("TradeBoardTab: Taker received finalized offer on session %s (maker_base_psbt=%d bytes)\n",
              session_id.toStdString().c_str(), makerBasePsbt.length());

    if (!walletModel) return;

    QJsonParseError parseError;
    QJsonDocument offerDoc = QJsonDocument::fromJson(offer_json.toUtf8(), &parseError);
    if (offerDoc.isNull() || !offerDoc.isObject()) {
        QMessageBox::critical(this, tr("Parse Error"),
            tr("Failed to parse finalized offer JSON:\n%1").arg(parseError.errorString()));
        return;
    }

    QJsonObject offerObj = offerDoc.object();
    QString offer_id = offerObj.value("id").toString();

    if (offer_id.isEmpty()) {
        QMessageBox::critical(this, tr("Invalid Offer"),
            tr("Finalized offer is missing offer ID."));
        return;
    }

    // Maker base PSBT is optional here - maker cannot build it until after importing taker's acceptance
    // (immutability pattern: acceptance → import → build PSBT → send PSBT separately)
    if (makerBasePsbt.isEmpty()) {
        LogPrintf("TradeBoardTab: Finalized offer received without maker base PSBT (will arrive after acceptance)\n");
    }

    if (!activeRequests.contains(request_id)) {
        QMessageBox::warning(this, tr("Unknown Request"),
            tr("Received finalized offer for unknown request %1.\n\nPlease refresh the Trade Board.").arg(request_id.left(16) + "..."));
        return;
    }

    // =============================================================================================
    // SNAPSHOT-BASED ARCHITECTURE: Create immutable snapshot before any modal dialogs
    // =============================================================================================

    // Get cached request info for role fallback (safe single-access)
    TradeRequestInfo cachedInfo = activeRequests[request_id];

    // Determine contract type using canonical cache first, then fall back to JSON/summary
    QString contractType = getCanonicalContractType(offer_id).toLower();
    if (contractType.isEmpty() && offerObj.contains("contract_type")) {
        contractType = offerObj.value("contract_type").toString().toLower();
    }
    if (contractType.isEmpty() && cachedInfo.offer_summary.contains("contract_type")) {
        contractType = cachedInfo.offer_summary.value("contract_type").toString().toLower();
    }
    if (contractType.isEmpty() && !cachedInfo.contract_type.isEmpty()) {
        contractType = cachedInfo.contract_type.toLower();
    }
    if (contractType.isEmpty()) {
        QString summaryHint = cachedInfo.offer_summary.value("contract_type").toString().toLower();
        if (summaryHint == "options") summaryHint = QStringLiteral("option");
        if (ensureContractFlavorLoaded(offer_id, summaryHint)) {
            contractType = getCanonicalContractType(offer_id).toLower();
        }
    }
    if (contractType == "options") {
        contractType = QStringLiteral("option");
    }
    if (contractType.isEmpty()) {
        QMessageBox::critical(this, tr("Unknown Contract"),
            tr("The finalized offer %1 did not include a contract type. Please refresh the Trade Board.")
                .arg(offer_id.left(16) + "..."));
        return;
    }

    // Determine taker role by inverting maker role from offer
    QString takerRole;
    bool isForward = (contractType == "forward" || contractType == "option");
    bool isSpot = (contractType == "spot");

    if (isSpot) {
        // SPOT: Taker is always "bob" (receiver), maker is "alice" (sender)
        takerRole = QStringLiteral("bob");
        LogPrintf("TradeBoardTab: Taker dialog (Spot) - taker_role=%s\n", takerRole.toStdString().c_str());
    } else if (isForward) {
        QString makerRole;
        if (offerObj.contains("maker_role")) {
            makerRole = offerObj.value("maker_role").toString().toLower();
        } else if (cachedInfo.offer_summary.contains("maker_role")) {
            makerRole = cachedInfo.offer_summary.value("maker_role").toString().toLower();
        } else if (!cachedInfo.maker_role.isEmpty()) {
            makerRole = cachedInfo.maker_role.toLower();
        }

        if (!makerRole.isEmpty()) {
            takerRole = (makerRole == "long") ? QStringLiteral("short") : QStringLiteral("long");
        } else {
            LogPrintf("TradeBoardTab: ERROR - Cannot determine maker_role for forward contract, defaulting taker to short\n");
            takerRole = QStringLiteral("short");  // Safe default fallback
        }

        LogPrintf("TradeBoardTab: Taker dialog (Forward) - contract_type=%s, maker_role=%s, taker_role=%s\n",
                  contractType.toStdString().c_str(),
                  makerRole.toStdString().c_str(),
                  takerRole.toStdString().c_str());
    } else {
        // REPO: Taker role is opposite of maker role (borrower/lender)
        if (offerObj.contains("maker_role")) {
            const QString makerRole = offerObj.value("maker_role").toString().toLower();
            takerRole = (makerRole == "lender") ? QStringLiteral("borrower") : QStringLiteral("lender");
        } else if (cachedInfo.offer_summary.contains("maker_role")) {
            const QString makerRole = cachedInfo.offer_summary.value("maker_role").toString().toLower();
            takerRole = (makerRole == "lender") ? QStringLiteral("borrower") : QStringLiteral("lender");
        } else {
            const QString makerRole = cachedInfo.maker_role.toLower();
            takerRole = (makerRole == "lender") ? QStringLiteral("borrower") : QStringLiteral("lender");
        }
        LogPrintf("TradeBoardTab: Taker dialog (Repo) - taker_role=%s\n", takerRole.toStdString().c_str());
    }

    // Cache contract type for ceremony
    cacheContractFlavor(offer_id, contractType, offer_json, cachedInfo.offer_id);

    // Update activeRequests with essential data for workflow compatibility
    if (activeRequests.contains(request_id)) {
        TradeRequestInfo& reqInfo = activeRequests[request_id];
        reqInfo.final_offer_json = offer_json;
        reqInfo.final_offer_id = offer_id;
        if (!makerBasePsbt.isEmpty()) {
            reqInfo.maker_base_psbt = makerBasePsbt;
        }
        reqInfo.offer_summary["contract_type"] = contractType;
        if (offerObj.contains("maker_role")) {
            reqInfo.offer_summary["maker_role"] = offerObj.value("maker_role").toString().toLower();
            reqInfo.maker_role = offerObj.value("maker_role").toString().toLower();
        }
        if (isSpot) {
            populateSpotTermsFromJson(reqInfo, offerObj);
        } else if (isForward) {
            populateForwardTermsFromJson(reqInfo, offerObj);
            // Ceremony runner expects borrower=long, lender=short
            reqInfo.borrower_address = reqInfo.long_margin_dest;
            reqInfo.lender_address = reqInfo.short_margin_dest;
        } else {
            populateRepoTermsFromJson(reqInfo, offerObj);
            const QString borrowerAddr = offerObj.value("borrower_address").toString();
            const QString lenderAddr = offerObj.value("lender_address").toString();
            if (!borrowerAddr.isEmpty()) {
                reqInfo.borrower_address = borrowerAddr;
            }
            if (!lenderAddr.isEmpty()) {
                reqInfo.lender_address = lenderAddr;
            }
        }
        reqInfo.final_offer_processed = true;
    }

    // Create immutable snapshot with all contract data
    TradeRequestInfo snapshotSource = activeRequests.value(request_id);
    FinalContractSnapshot snapshot = createTakerSnapshot(
        request_id, session_id, offer_id, offer_json,
        makerBasePsbt, takerRole, "medium",
        snapshotSource, contractType  // Default fee strategy, user will select in dialog
    );

    // Build dialog options from snapshot
    const QString heading = tr("<b>Maker has delivered the finalized contract.</b><br>"
                               "Review every field before you accept—this flow will automatically fund and sign your leg.");

    FinalContractReviewDialog::Options options;
    options.headingHtml = heading;
    options.summaryHtml = snapshot.summary_html;
    options.offerId = snapshot.contract_id;
    options.sessionId = snapshot.session_id;
    options.rawJson = snapshot.raw_json_pretty;
    options.rawJsonTitle = tr("Final Contract JSON");
    options.acceptLabel = tr("Accept && Send to Maker");
    options.rejectLabel = tr("Decline");
    options.userRole = snapshot.user_role;
    options.criticalChecks = snapshot.critical_checks;
    options.footnoteHtml = tr("<b>Warning:</b> After you accept, the wallet automatically transmits "
                              "your acceptance and prepares the adaptor ceremony. Make sure the figures match "
                              "what you intend to sign.");
    options.showFeeSelector = true;  // Taker chooses their own fee strategy

    // TIMER SAFETY: Pause background updates during modal dialog
    pauseUpdateTimers();

    FinalContractReviewDialog reviewDialog(options, this);

    LogPrintf("TradeBoardTab: Showing taker acceptance dialog for offer %s\n", offer_id.toStdString().c_str());
    int dialogResult = reviewDialog.exec();

    // TIMER SAFETY: Resume background updates after dialog closes
    resumeUpdateTimers();

    LogPrintf("TradeBoardTab: Dialog returned with result=%d\n", dialogResult);

    if (dialogResult != QDialog::Accepted) {
        LogPrintf("TradeBoardTab: Taker dismissed finalized offer %s without accepting\n", offer_id.toStdString().c_str());
        return;
    }

    // Get user-selected fee strategy for taker's funding
    QString selectedFeeStrategy = reviewDialog.getSelectedFeeStrategy();
    LogPrintf("TradeBoardTab: Taker selected fee strategy='%s' for funding\n", selectedFeeStrategy.toStdString().c_str());

    // Update snapshot with user-selected fee strategy
    snapshot.selected_fee_strategy = selectedFeeStrategy;

    // Optional strict ownership enforcement (off by default)
    QSettings s;
    bool strict = s.value("StrictAddressOwnership", false).toBool();
    if (strict) {
        bool ok=false;
        QString addressToCheck;
        if (snapshot.contract_type == "repo") {
            if (snapshot.user_role == "borrower") {
                addressToCheck = snapshot.repo.borrower_address;
            } else {
                addressToCheck = snapshot.repo.lender_address;
            }
        } else if (snapshot.contract_type == "forward" || snapshot.contract_type == "option") {
            if (snapshot.user_role == "long") {
                addressToCheck = snapshot.forward.long_margin_dest;
            } else {
                addressToCheck = snapshot.forward.short_margin_dest;
            }
        }

        if (!addressToCheck.isEmpty() && (!AddressOwnedByWallet(walletModel, addressToCheck, &ok) || !ok)) {
            QMessageBox::critical(this, tr("Ownership Validation Failed"),
                tr("Your contract address is not owned by this wallet. Update settings to allow external addresses or fix the address."));
            return;
        }
    }

    // Call snapshot-based workflow (timer-safe, no activeRequests access during workflow)
    startTakerAcceptanceWorkflow(snapshot);
}

void TradeBoardTab::startTakerAcceptanceWorkflow(const QString& request_id,
                                                 const QString& offer_id,
                                                 const QString& session_id,
                                                 const QString& offer_json,
                                                 const TradeRequestInfo& reqInfo,
                                                 const QString& fee_strategy)
{
    if (!walletModel) return;

    QString progressLabel = tr("Importing finalized contract %1 and transmitting your acceptance...")
                                .arg(offer_id.left(16) + "...");

    QWidget* dialog_parent = window() ? window() : this;
    QProgressDialog* progress = new QProgressDialog(dialog_parent);
    progress->setWindowTitle(tr("Sending Acceptance"));
    progress->setLabelText(progressLabel);
    progress->setRange(0, 0);
    progress->setCancelButton(nullptr);
    progress->setWindowModality(Qt::WindowModal);
    progress->setMinimumDuration(0);
    progress->show();
    // REMOVED QApplication::processEvents() - causes re-entrancy and crashes

    auto* watcher = new QFutureWatcher<AcceptanceFlowResult>(this);

    // Guard UI and watcher lifetimes
    QPointer<TradeBoardTab> self(this);
    QPointer<QProgressDialog> progressPtr(progress);
    QPointer<QFutureWatcher<AcceptanceFlowResult>> watcherPtr(watcher);

    // Close progress when work finishes, but don't delete watcher yet
    QObject::connect(watcher, &QFutureWatcher<AcceptanceFlowResult>::finished, progress, &QProgressDialog::close);

    connect(watcher, &QFutureWatcher<AcceptanceFlowResult>::finished, this,
            [self, watcherPtr, progressPtr, request_id, offer_id, session_id, fee_strategy]( ) {
        if (!self) return;  // parent destroyed

        // Progress already closed via direct connection above
        if (progressPtr) {
            progressPtr->deleteLater();
        }

        AcceptanceFlowResult result;
        if (watcherPtr) {
            result = watcherPtr->result();
        } else {
            result.success = false;
            result.failureStage = AcceptanceStage::None;
            result.errorDetail = QObject::tr("Internal watcher disposed");
        }

        if (!self->activeRequests.contains(request_id)) {
            LogPrintf("TradeBoardTab: Acceptance flow finished but request %s no longer active\n",
                      request_id.toStdString().c_str());
            // Clean up watcher before returning
            if (watcherPtr) {
                watcherPtr->deleteLater();
            }
            return;
        }

        TradeRequestInfo& mutableInfo = self->activeRequests[request_id];

        if (result.success) {
            mutableInfo.acceptance_sent = true;
            mutableInfo.last_acceptance_envelope = result.acceptanceEnvelope;
            mutableInfo.taker_fee_strategy = fee_strategy; // Store user's fee choice
            LogPrintf("TradeBoardTab: Acceptance for offer %s sent successfully over session %s (fee_strategy='%s')\n",
                      offer_id.toStdString().c_str(),
                      session_id.toStdString().c_str(),
                      fee_strategy.toStdString().c_str());
            LogPrintf("TradeBoardTab: STORED taker_fee_strategy='%s' for request_id='%s'\n",
                      mutableInfo.taker_fee_strategy.toStdString().c_str(),
                      request_id.toStdString().c_str());

            // IMMUTABILITY PATTERN: Augment maker's base PSBT immediately after acceptance
            if (!mutableInfo.maker_base_psbt.isEmpty() && mutableInfo.augmented_psbt.isEmpty()) {
                QString takerRole;
                if (mutableInfo.offer_summary.contains("maker_role")) {
                    const QString makerRole = mutableInfo.offer_summary.value("maker_role").toString().toLower();
                    takerRole = (makerRole == "lender") ? QStringLiteral("borrower") : QStringLiteral("lender");
                } else {
                    const QString makerRole = mutableInfo.maker_role.toLower();
                    takerRole = (makerRole == "lender") ? QStringLiteral("borrower") : QStringLiteral("lender");
                }

                QVariantMap buildOptions;
                buildOptions["psbt"] = mutableInfo.maker_base_psbt;

                // Use user-selected fee strategy for taker's funding (not extracted from maker's offer)
                LogPrintf("TradeBoardTab: Taker (post-acceptance) using user-selected fee_strategy='%s' for funding\n", fee_strategy.toStdString().c_str());
                buildOptions["strategy"] = fee_strategy;

                if (takerRole == "borrower") {
                    buildOptions["auto_fund_collateral"] = true;
                } else {
                    buildOptions["auto_fund_principal"] = true;
                }

                QString contractId = mutableInfo.final_offer_id.isEmpty() ? offer_id : mutableInfo.final_offer_id;
                LogPrintf("TradeBoardTab: Taker augmenting maker's base PSBT after acceptance (role=%s, contract=%s)\n",
                          takerRole.toStdString().c_str(), contractId.toStdString().c_str());
                auto augmentResult = self->walletModel->repoBuildOpen(contractId, buildOptions);
                if (augmentResult.success) {
                    // Annotate augmented PSBT with wallet metadata similar to tests
                    auto annotate = self->walletModel->walletProcessPsbt(augmentResult.psbt,
                                                                   /*sign=*/false,
                                                                   QStringLiteral("DEFAULT"),
                                                                   /*bip32derivs=*/true,
                                                                   /*finalize=*/false);
                    if (annotate.success && !annotate.psbt.isEmpty()) {
                        augmentResult.psbt = annotate.psbt;
                    }

                    // Preflight: ensure augmented PSBT has at least one SPENDABLE input we can sign
                    QString details;
                    QString errText;
                    if (!PsbtHasSpendableInputs(self->walletModel, augmentResult.psbt, &details, &errText)) {
                        LogPrintf("TradeBoardTab: Taker augmented PSBT (post-acceptance) not signable: %s\n",
                                  errText.toStdString().c_str());
                        self->showNonBlockingInfo(self->tr("Acceptance Sent"),
                            self->tr("Your funding could not be used for the ceremony because no signable inputs were found.\n\n%1")
                                .arg(details));
                        self->updateTradeRequestsList();
                        // Clean up watcher before returning
                        if (watcherPtr) {
                            watcherPtr->deleteLater();
                        }
                        return;
                    }

                    mutableInfo.augmented_psbt = augmentResult.psbt;
                    // Compute hash of PSBT bytes for immutability verification
                    mutableInfo.augmented_psbt_hash = ComputePsbtTxHash(mutableInfo.augmented_psbt);
                    mutableInfo.psbt_locked = true;
                    LogPrintf("TradeBoardTab: Taker locked augmented PSBT (%d bytes, hash=%s)\n",
                              mutableInfo.augmented_psbt.length(), mutableInfo.augmented_psbt_hash.toStdString().c_str());
                } else {
                    LogPrintf("TradeBoardTab: WARNING - Failed to augment maker base PSBT: %s\n",
                              augmentResult.error.toStdString().c_str());
                }
            }

            self->showAutoClosingInfo(self->tr("Offer Accepted"),
                self->tr("✓ Acceptance sent to maker.\n\n"
                   "Wait for maker confirmation. The adaptor ceremony will start automatically once both sides are ready."));
            self->updateTradeRequestsList();

            // Clean up watcher on success path
            if (watcherPtr) {
                watcherPtr->deleteLater();
            }
            return;
        }

        QString errorMessage;
        switch (result.failureStage) {
            case AcceptanceStage::ImportOffer:
                errorMessage = self->tr("Failed to import finalized offer:\n\n%1").arg(result.errorDetail);
                break;
            case AcceptanceStage::AcceptOffer:
                errorMessage = self->tr("Failed to accept offer:\n\n%1").arg(result.errorDetail);
                break;
            case AcceptanceStage::ParseAcceptance:
                if (result.missingAcceptanceField) {
                    errorMessage = self->tr("The acceptance RPC did not return the required 'acceptance' field.");
                } else if (result.parseError) {
                    errorMessage = self->tr("Failed to parse acceptance payload:\n\n%1").arg(result.errorDetail);
                } else {
                    errorMessage = self->tr("Unexpected acceptance payload error.");
                }
                break;
            case AcceptanceStage::SendAcceptance:
                if (result.sessionLost) {
                    errorMessage = self->tr("The cosign session was lost while attempting to send your acceptance.\n\n"
                                      "The acceptance is saved locally and will be retried after the session reconnects.");
                    self->handleSessionLoss(session_id, request_id, result.errorDetail);
                } else {
                    errorMessage = self->tr("Failed to send acceptance to maker:\n\n%1").arg(result.errorDetail);
                }
                break;
            case AcceptanceStage::None:
            default:
                errorMessage = self->tr("Acceptance failed due to an unexpected error:\n\n%1").arg(result.errorDetail);
                break;
        }

        if (!result.acceptanceEnvelope.isEmpty()) {
            mutableInfo.last_acceptance_envelope = result.acceptanceEnvelope;
        }

        QMessageBox::critical(self, self->tr("Acceptance Failed"), errorMessage);
        self->updateTradeRequestsList();

        // Clean up watcher on error path too
        if (watcherPtr) {
            watcherPtr->deleteLater();
        }
    });

    auto inflightGuard = std::make_shared<InflightGuard>(this);
    QFuture<AcceptanceFlowResult> future = QtConcurrent::run([this, inflightGuard, offer_id, session_id, offer_json]() {
        (void)inflightGuard;
        AcceptanceFlowResult result;
        try {
            // Detect contract type from offer JSON
            QJsonParseError offerParseError;
            QJsonDocument offerDoc = QJsonDocument::fromJson(offer_json.toUtf8(), &offerParseError);
            QString contractType;
            if (!offerDoc.isNull() && offerDoc.isObject()) {
                contractType = offerDoc.object().value("contract_type").toString().toLower();
            }

            bool isSpot = (contractType == "spot");
            bool isForward = (contractType == "forward" || contractType == "option" || contractType == "options");

            LogPrintf("TradeBoardTab: Taker accepting contract_type='%s' (isSpot=%d, isForward=%d)\n",
                      contractType.toStdString().c_str(), isSpot ? 1 : 0, isForward ? 1 : 0);

            QString messageToSend;

            if (isSpot) {
                // SPOT: Cannot use this async worker - taker must provide bob_address via bulletin board
                result.failureStage = AcceptanceStage::AcceptOffer;
                result.errorDetail = QObject::tr("Spot contracts cannot be accepted via this flow.\n\n"
                                                "Spot atomic swaps require you to provide your receive address (bob_address) "
                                                "when requesting the trade via bulletin board.\n\n"
                                                "Please use 'Request Trade' from the Trade Board instead.");
                LogPrintf("TradeBoardTab: ERROR - Spot contract reached async worker (should use bulletin board path)\n");
                return result;
            } else if (isForward) {
                // FORWARD/OPTIONS: Import offer, accept, and send acceptance (mirrors repo pattern)
                auto importResult = walletModel->forwardImportOffer(offer_json);
                if (!importResult.success) {
                    result.failureStage = AcceptanceStage::ImportOffer;
                    result.errorDetail = importResult.error;
                    return result;
                }

                auto acceptResult = walletModel->forwardAccept(offer_id, true);
                if (!acceptResult.success) {
                    result.failureStage = AcceptanceStage::AcceptOffer;
                    result.errorDetail = acceptResult.error;
                    return result;
                }

                QString acceptanceObjJson = acceptResult.acceptance_obj_json;
                if (acceptanceObjJson.isEmpty()) {
                    result.failureStage = AcceptanceStage::ParseAcceptance;
                    result.missingAcceptanceField = true;
                    return result;
                }

                QJsonParseError parseError;
                QJsonDocument acceptanceDoc = QJsonDocument::fromJson(acceptanceObjJson.toUtf8(), &parseError);
                if (acceptanceDoc.isNull() || !acceptanceDoc.isObject()) {
                    result.failureStage = AcceptanceStage::ParseAcceptance;
                    result.parseError = true;
                    result.errorDetail = parseError.errorString();
                    return result;
                }

                QJsonObject wrapper;
                wrapper["type"] = "forward_acceptance";
                wrapper["acceptance"] = acceptanceDoc.object();
                messageToSend = QString::fromUtf8(QJsonDocument(wrapper).toJson(QJsonDocument::Compact));
                result.acceptanceEnvelope = messageToSend;

            } else {
                // REPO: Import offer then accept
                auto importResult = walletModel->repoImportOffer(offer_json);
                if (!importResult.success) {
                    result.failureStage = AcceptanceStage::ImportOffer;
                    result.errorDetail = importResult.error;
                    return result;
                }

                auto acceptResult = walletModel->repoAccept(offer_id, true);
                if (!acceptResult.success) {
                    result.failureStage = AcceptanceStage::AcceptOffer;
                    result.errorDetail = acceptResult.error;
                    return result;
                }

                QString acceptanceObjJson = acceptResult.acceptance_obj_json;
                if (acceptanceObjJson.isEmpty()) {
                    result.failureStage = AcceptanceStage::ParseAcceptance;
                    result.missingAcceptanceField = true;
                    return result;
                }

                QJsonParseError parseError;
                QJsonDocument acceptanceDoc = QJsonDocument::fromJson(acceptanceObjJson.toUtf8(), &parseError);
                if (acceptanceDoc.isNull() || !acceptanceDoc.isObject()) {
                    result.failureStage = AcceptanceStage::ParseAcceptance;
                    result.parseError = true;
                    result.errorDetail = parseError.errorString();
                    return result;
                }

                QJsonObject wrapper;
                wrapper["type"] = "repo_acceptance";
                wrapper["acceptance"] = acceptanceDoc.object();
                messageToSend = QString::fromUtf8(QJsonDocument(wrapper).toJson(QJsonDocument::Compact));
                result.acceptanceEnvelope = messageToSend;
            }

            auto sendResult = walletModel->cosignSend(session_id, messageToSend);
            if (!sendResult.success) {
                result.failureStage = AcceptanceStage::SendAcceptance;
                result.errorDetail = sendResult.error;
                QString lower = sendResult.error.toLower();
                if (lower.contains("session not found") || lower.contains("session expired") ||
                    lower.contains("bridge restarted") || lower.contains("unknown session")) {
                    result.sessionLost = true;
                }
                return result;
            }

            result.success = true;
            return result;
        } catch (const std::exception& e) {
            result.failureStage = AcceptanceStage::None;
            result.errorDetail = QString::fromStdString(e.what());
            return result;
        } catch (...) {
            result.failureStage = AcceptanceStage::None;
            result.errorDetail = QCoreApplication::translate("TradeBoardTab", "Unknown exception");
            return result;
        }
    });

    watcher->setFuture(future);
}

void TradeBoardTab::startMakerConfirmationWorkflow(const QString& request_id,
                                                   const QString& offer_id,
                                                   const QString& session_id,
                                                   const QString& maker_role,
                                                   const QString& acceptancePayloadJson,
                                                   TradeRequestInfo reqInfo)
{
    if (!walletModel) return;
    LogPrintf("TradeBoardTab: startMakerConfirmationWorkflow entry request_id=%s offer_id=%s session_id=%s maker_role=%s\n",
              request_id.toStdString().c_str(),
              offer_id.toStdString().c_str(),
              session_id.toStdString().c_str(),
              maker_role.toStdString().c_str());

    const QString makerRoleNormalized = maker_role.toLower();

    // CRITICAL: Extract data we need from reqInfo BEFORE QApplication::processEvents()
    // to avoid dangling reference after activeRequests map is modified by event handlers
    const QVariantMap offerSummaryCopy = reqInfo.offer_summary;
    const QString finalOfferJsonCopy = reqInfo.final_offer_json;
    const QString finalOfferIdCopy = reqInfo.final_offer_id;

    QString progressLabel = tr("Importing taker acceptance and preparing ceremony invite...");

    QWidget* dialog_parent = window() ? window() : this;
    QProgressDialog* progress = new QProgressDialog(dialog_parent);
    progress->setWindowTitle(tr("Confirming Acceptance"));
    progress->setLabelText(progressLabel);
    progress->setRange(0, 0);
    progress->setCancelButton(nullptr);
    progress->setWindowModality(Qt::WindowModal);
    progress->setMinimumDuration(0);
    progress->show();
    // Avoid forcing a re-entrant event loop here; re-entrancy can lead to
    // UI updates running while widgets are being torn down, causing
    // intermittent BadWindow/TranslateCoords errors and crashes.

    // DIAGNOSTIC: Verify safe copies are valid after processEvents()
    LogPrintf("TradeBoardTab: POST-processEvents diagnostic - summary.keys=%d, final_offer_bytes=%d, final_offer_id=%s\n",
              offerSummaryCopy.size(),
              finalOfferJsonCopy.length(),
              finalOfferIdCopy.toStdString().c_str());

    auto* watcher = new QFutureWatcher<ConfirmationFlowResult>(this);

    // Guard UI and watcher lifetimes across the async boundary
    QPointer<TradeBoardTab> self(this);
    QPointer<QProgressDialog> progressPtr(progress);
    QPointer<QFutureWatcher<ConfirmationFlowResult>> watcherPtr(watcher);

    // Close progress when work finishes, but don't delete watcher yet -
    // the lambda below needs to read the result first
    QObject::connect(watcher, &QFutureWatcher<ConfirmationFlowResult>::finished, progress, &QProgressDialog::close);

    connect(watcher, &QFutureWatcher<ConfirmationFlowResult>::finished, this,
            [self, watcherPtr, progressPtr, request_id, offer_id, session_id, makerRoleNormalized]() {
        if (!self) return;  // parent destroyed, nothing to do

        // Progress dialog is already closed via the direct connection above.
        // Do NOT call close() again here - that causes double cleanup

        ConfirmationFlowResult result;
        if (watcherPtr) {
            result = watcherPtr->result();
        } else {
            result.success = false;
            result.failureStage = ConfirmationStage::None;
            result.errorDetail = QObject::tr("Internal watcher disposed");
        }

        if (!self->activeRequests.contains(request_id)) {
            LogPrintf("TradeBoardTab: Maker confirmation finished but request %s not found\n",
                      request_id.toStdString().c_str());
            return;
        }

        TradeRequestInfo& mutableInfo = self->activeRequests[request_id];

        if (result.success) {
            mutableInfo.last_ceremony_invite = result.ceremonyInviteJson;
            mutableInfo.ceremony_invite_sent = true;
            mutableInfo.maker_role = makerRoleNormalized;
            LogPrintf("TradeBoardTab: SET ceremony_invite_sent=TRUE and maker_role='%s' for request_id=%s\n",
                      makerRoleNormalized.toStdString().c_str(),
                      request_id.toStdString().c_str());

            LogPrintf("TradeBoardTab: Both parties accepted, ceremony invite sent. Waiting for taker to be ready...\n");
            self->updateTradeRequestsList();

            // Clean up watcher on success path too
            if (watcherPtr) {
                watcherPtr->deleteLater();
            }
            return;
        }

        QString errorMessage;
        switch (result.failureStage) {
            case ConfirmationStage::ImportAcceptance:
                errorMessage = self->tr("Failed to import taker's acceptance:\n\n%1").arg(result.errorDetail);
                break;
            case ConfirmationStage::SendCeremonyInvite:
                if (result.sessionLost) {
                    errorMessage = self->tr("The cosign session was lost while notifying the taker to start the ceremony.\n\n"
                                            "The invite will be re-sent after the session reconnects.");
                    self->handleSessionLoss(session_id, request_id, result.errorDetail);
                } else {
                    errorMessage = self->tr("Failed to send ceremony invite to taker:\n\n%1").arg(result.errorDetail);
                }
                break;
            case ConfirmationStage::None:
            default:
                errorMessage = self->tr("Opening ceremony could not be started:\n\n%1").arg(result.errorDetail);
                break;
        }

        if (!result.ceremonyInviteJson.isEmpty()) {
            mutableInfo.last_ceremony_invite = result.ceremonyInviteJson;
        }

        QMessageBox::critical(self, self->tr("Ceremony Not Started"), errorMessage);
        self->updateTradeRequestsList();

        // Now safe to delete the watcher after we've used it
        if (watcherPtr) {
            watcherPtr->deleteLater();
        }
    },
    Qt::QueuedConnection);

    // Do wallet operations synchronously on main thread to avoid race conditions
    // Only the cosign send operation is moved to background thread
    ConfirmationFlowResult result;

    // CRITICAL: Use canonical contract type from cache
    QString contractId = finalOfferIdCopy.isEmpty() ? offer_id : finalOfferIdCopy;
    QString contractType = getCanonicalContractType(contractId);

    if (contractType.isEmpty()) {
        // Cache miss - try to populate from available data
        LogPrintf("TradeBoardTab: Cache miss for contract %s, attempting to populate\n", contractId.toStdString().c_str());
        if (!ensureContractFlavorLoaded(contractId, offerSummaryCopy.value("contract_type").toString())) {
            result.success = false;
            result.failureStage = ConfirmationStage::None;
            result.errorDetail = tr("Cannot determine contract type for contract %1").arg(contractId);
            progress->close();
            progress->deleteLater();
            watcher->deleteLater();
            QMessageBox::critical(this, tr("Contract Type Error"),
                tr("Cannot determine if this is a repo or forward contract.\n\nContract ID: %1").arg(contractId));
            return;
        }
        contractType = getCanonicalContractType(contractId);
    }

    bool isForward = (contractType == "forward" || contractType == "option");
    LogPrintf("TradeBoardTab: Maker importing acceptance for contract_type=%s [canonical] (contract_id=%s)\n",
              contractType.toStdString().c_str(), contractId.toStdString().c_str());

    // Import acceptance (repo or forward)
    if (isForward) {
        // FORWARD: Import acceptance to register taker's commitment in wallet state machine
        LogPrintf("TradeBoardTab: Using forward.import_acceptance for offer %s\n", offer_id.toStdString().c_str());
        auto importResult = walletModel->forwardImportAcceptance(acceptancePayloadJson);
        if (!importResult.success) {
            progress->close();
            progress->deleteLater();
            watcher->deleteLater();

            QMessageBox::critical(this, tr("Import Failed"),
                tr("Failed to import taker's forward acceptance:\n\n%1").arg(importResult.error));
            return;
        }
        LogPrintf("TradeBoardTab: Forward acceptance imported successfully (acceptance_id=%s)\n",
                  importResult.acceptance_id.toStdString().c_str());
    } else {
        LogPrintf("TradeBoardTab: Using repo.import_acceptance for offer %s\n", offer_id.toStdString().c_str());
        auto importResult = walletModel->repoImportAcceptance(acceptancePayloadJson);
        if (!importResult.success) {
            progress->close();
            progress->deleteLater();
            delete watcher;  // Delete the unstarted watcher

            QMessageBox::critical(this, tr("Import Failed"),
                tr("Failed to import taker's acceptance:\n\n%1").arg(importResult.error));
            return;
        }
    }

    // Build maker's base PSBT (immutability pattern)
    // contractId already set above
    QString basePsbt;
    int alice_vault_index = -1;
    int bob_vault_index = -1;
    int premium_output_index = -1;

    // Extract fee policy from offer (critical - without this, min relay fees may not be met)
    QString feeStrategy;
    // First try offer_summary
    if (reqInfo.offer_summary.contains("fee_policy_strategy")) {
        feeStrategy = reqInfo.offer_summary.value("fee_policy_strategy").toString();
    }
    // Then try contract_payload from offer_summary
    if (feeStrategy.isEmpty() && reqInfo.offer_summary.contains("contract_payload")) {
        QString payloadStr = reqInfo.offer_summary.value("contract_payload").toString();
        QJsonDocument payloadDoc = QJsonDocument::fromJson(payloadStr.toUtf8());
        if (payloadDoc.isObject()) {
            QJsonObject payloadObj = payloadDoc.object();
            if (payloadObj.contains("terms")) {
                QJsonObject terms = payloadObj.value("terms").toObject();
                if (terms.contains("fee_policy")) {
                    feeStrategy = terms.value("fee_policy").toString();
                }
            }
        }
    }
    // Fallback to final_offer_json
    if (feeStrategy.isEmpty() && !reqInfo.final_offer_json.isEmpty()) {
        QJsonDocument offerDoc = QJsonDocument::fromJson(reqInfo.final_offer_json.toUtf8());
        if (offerDoc.isObject()) {
            QJsonObject offerObj = offerDoc.object();
            if (offerObj.contains("fee_policy_strategy")) {
                feeStrategy = offerObj.value("fee_policy_strategy").toString();
            }
            if (feeStrategy.isEmpty() && offerObj.contains("contract_payload")) {
                QString payloadStr = offerObj.value("contract_payload").toString();
                QJsonDocument payloadDoc = QJsonDocument::fromJson(payloadStr.toUtf8());
                if (payloadDoc.isObject()) {
                    QJsonObject payloadObj = payloadDoc.object();
                    if (payloadObj.contains("terms")) {
                        QJsonObject terms = payloadObj.value("terms").toObject();
                        if (terms.contains("fee_policy")) {
                            feeStrategy = terms.value("fee_policy").toString();
                        }
                    }
                }
            }
        }
    }
    if (feeStrategy.isEmpty()) {
        feeStrategy = "medium";  // Default fallback
        LogPrintf("TradeBoardTab: No fee_policy in offer, defaulting to 'medium'\n");
    } else {
        LogPrintf("TradeBoardTab: Using fee_policy='%s' from offer\n", feeStrategy.toStdString().c_str());
    }

    if (isForward) {
        // DEFENSIVE: Verify we're calling the right RPC
        if (contractType != "forward" && contractType != "option") {
            LogPrintf("FATAL: About to call forward.build_open but contract_type='%s'\n",
                      contractType.toStdString().c_str());
            progress->close();
            progress->deleteLater();
            watcher->deleteLater();
            QMessageBox::critical(this, tr("RPC Mismatch"),
                tr("Internal error: attempted to use forward RPC for %1 contract").arg(contractType));
            return;
        }

        // FORWARD/OPTIONS CONTRACT
        QVariantMap buildOptions;
        buildOptions["strategy"] = feeStrategy;  // Pass fee policy to RPC

        // Two-party PSBT construction: long party creates base PSBT, short party augments
        // The maker calling this is creating the base PSBT, so they must be the long party
        // (If short party is maker, they need to wait for long party's PSBT via message flow)
        buildOptions["auto_fund_long"] = true;
        buildOptions["auto_fund_premium"] = true;  // Long party funds premium initially

        // TODO: Detect premium payment direction from contract terms and set auto_fund_premium accordingly

        LogPrintf("TradeBoardTab: Calling forward.build_open with contract_id=%s, options=%s\n",
                  contractId.toStdString().c_str(),
                  buildOptions.isEmpty() ? "empty" : "non-empty");

        auto forwardResult = walletModel->forwardBuildOpen(contractId, buildOptions);
        if (!forwardResult.success) {
            progress->close();
            progress->deleteLater();
            delete watcher;  // Delete the unstarted watcher

            QMessageBox::critical(this, tr("Build Base PSBT Failed"),
                tr("Failed to build forward opening PSBT:\n\n%1").arg(forwardResult.error));
            return;
        }

        basePsbt = forwardResult.psbt;
        alice_vault_index = forwardResult.alice_vault_index;
        bob_vault_index = forwardResult.bob_vault_index;
        premium_output_index = forwardResult.premium_output_index;

        LogPrintf("TradeBoardTab: Maker built forward base PSBT - role=%s, %d bytes, alice_vault=%d, bob_vault=%d, premium=%d\n",
                  makerRoleNormalized.toStdString().c_str(), basePsbt.length(),
                  alice_vault_index, bob_vault_index, premium_output_index);

        // Extract long/short addresses from finalized offer for ceremony
        // and store vault indices (need mutable access via activeRequests)
        if (activeRequests.contains(request_id)) {
            TradeRequestInfo& mutableReqInfo = activeRequests[request_id];

            if (!finalOfferJsonCopy.isEmpty()) {
                QJsonDocument offerDoc = QJsonDocument::fromJson(finalOfferJsonCopy.toUtf8());
                if (offerDoc.isObject()) {
                    QJsonObject offerObj = offerDoc.object();
                    QJsonObject terms = offerObj.value("terms").toObject();

                    // Extract long party addresses
                    QJsonObject longParty = terms.value("long_party").toObject();
                    QString longMarginDest = longParty.value("margin_dest").toString();

                    // Extract short party addresses
                    QJsonObject shortParty = terms.value("short_party").toObject();
                    QString shortMarginDest = shortParty.value("margin_dest").toString();

                    // CRITICAL: Map long/short to borrower/lender for ceremony runner
                    // TradeCeremonyRunner maps: borrower="long", lender="short" (line 6100-6103)
                    mutableReqInfo.borrower_address = longMarginDest;
                    mutableReqInfo.lender_address = shortMarginDest;

                    LogPrintf("TradeBoardTab: Extracted forward addresses for ceremony - long(borrower)=%s, short(lender)=%s\n",
                              longMarginDest.toStdString().c_str(), shortMarginDest.toStdString().c_str());
                }
            }

            // Store vault indices
            mutableReqInfo.alice_vault_index = alice_vault_index;
            mutableReqInfo.bob_vault_index = bob_vault_index;
            mutableReqInfo.premium_output_index = premium_output_index;
        }

    } else {
        // DEFENSIVE: Verify we're calling the right RPC
        if (contractType != "repo") {
            LogPrintf("FATAL: About to call repo.build_open but contract_type='%s'\n",
                      contractType.toStdString().c_str());
            progress->close();
            progress->deleteLater();
            watcher->deleteLater();
            QMessageBox::critical(this, tr("RPC Mismatch"),
                tr("Internal error: attempted to use repo RPC for %1 contract").arg(contractType));
            return;
        }

        // REPO CONTRACT
        QVariantMap buildOptions;
        buildOptions["strategy"] = feeStrategy;  // Pass fee policy to RPC

        if (makerRoleNormalized == "borrower") {
            buildOptions["auto_fund_collateral"] = true;
            LogPrintf("TradeBoardTab: Maker (borrower) building base PSBT with auto_fund_collateral for contract %s\n",
                     contractId.toStdString().c_str());
        } else {
            buildOptions["auto_fund_principal"] = true;
            LogPrintf("TradeBoardTab: Maker (lender) building base PSBT with auto_fund_principal for contract %s\n",
                     contractId.toStdString().c_str());
        }

        auto basePsbtResult = walletModel->repoBuildOpen(contractId, buildOptions);
        if (!basePsbtResult.success) {
            progress->close();
            progress->deleteLater();
            delete watcher;  // Delete the unstarted watcher

            QMessageBox::critical(this, tr("Build Base PSBT Failed"),
                tr("Failed to build maker's base PSBT:\n\n%1").arg(basePsbtResult.error));
            return;
        }

        basePsbt = basePsbtResult.psbt;

        LogPrintf("TradeBoardTab: Maker built repo base PSBT for contract %s (role=%s, %d bytes)\n",
                  contractId.toStdString().c_str(), makerRoleNormalized.toStdString().c_str(),
                  basePsbt.length());
    }

    // Log the inputs in the base PSBT
    {
        PartiallySignedTransaction basePsbtDecoded;
        std::string decodeError;
        if (DecodeBase64PSBT(basePsbtDecoded, basePsbt.toStdString(), decodeError) && basePsbtDecoded.tx) {
            for (size_t i = 0; i < basePsbtDecoded.tx->vin.size(); ++i) {
                const CTxIn& txin = basePsbtDecoded.tx->vin[i];
                LogPrintf("TradeBoardTab: Base PSBT input %zu: %s:%d\n",
                         i, txin.prevout.hash.ToString().c_str(), txin.prevout.n);
            }
        }
    }

    // Canonicalize PSBT now so subsequent walletprocesspsbt calls during ceremony
    // do not mutate the string (immutability guard relies on byte-for-byte match).
    auto canonicalize_psbt = [&](const QString& psbt) -> QString {
        if (!walletModel || psbt.isEmpty()) return psbt;
        auto processed = walletModel->walletProcessPsbt(psbt,
                                                        /*sign=*/false,
                                                        QStringLiteral("DEFAULT"),
                                                        /*bip32derivs=*/true,
                                                        /*finalize=*/false);
        if (processed.success && !processed.psbt.isEmpty()) {
            LogPrintf("TradeBoardTab: Canonicalized maker base PSBT via walletprocesspsbt (len %d -> %d)\n",
                      psbt.length(), processed.psbt.length());
            return processed.psbt;
        }
        return psbt;
    };
    basePsbt = canonicalize_psbt(basePsbt);

    // Store maker base PSBT in request info
    if (activeRequests.contains(request_id)) {
        activeRequests[request_id].maker_base_psbt = basePsbt;
        LogPrintf("TradeBoardTab: Cached maker base PSBT for request %s\n", request_id.toStdString().c_str());
    }

    // Preflight: ensure maker base PSBT appears signable by this wallet
    // (derivations or spendable). Do not hard-fail; ceremony will validate again.
    {
        QString details;
        QString errText;
        if (!PsbtHasSpendableInputs(walletModel, basePsbt, &details, &errText)) {
            LogPrintf("TradeBoardTab: WARNING - Maker base PSBT preflight advisory failed: %s\n",
                      errText.toStdString().c_str());
            // Continue: adaptor.prepare will be the authoritative check
        }
    }

    // IMMUTABILITY PATTERN: Send maker's base PSBT to taker immediately after building
    // (taker will augment it, lock it, and send ceremony_ready back)
    QJsonObject basePsbtMsg;
    basePsbtMsg["type"] = "maker_base_psbt";
    basePsbtMsg["offer_id"] = offer_id;
    if (contractId != offer_id) {
        basePsbtMsg["contract_id"] = contractId;
    }
    basePsbtMsg["psbt"] = basePsbt;
    basePsbtMsg["maker_role"] = makerRoleNormalized;

    // Include vault indices for forward contracts (helps taker validate)
    if (isForward) {
        if (alice_vault_index >= 0) {
            basePsbtMsg["alice_vault_index"] = alice_vault_index;
        }
        if (bob_vault_index >= 0) {
            basePsbtMsg["bob_vault_index"] = bob_vault_index;
        }
        if (premium_output_index >= 0) {
            basePsbtMsg["premium_output_index"] = premium_output_index;
        }
    }

    QString basePsbtJson = QString::fromUtf8(QJsonDocument(basePsbtMsg).toJson(QJsonDocument::Compact));

    auto sendPsbtResult = walletModel->cosignSend(session_id, basePsbtJson);
    if (!sendPsbtResult.success) {
        progress->close();
        progress->deleteLater();
        delete watcher;  // Delete the unstarted watcher

        QMessageBox::critical(this, tr("Send Base PSBT Failed"),
            tr("Failed to send maker's base PSBT to taker:\n\n%1").arg(sendPsbtResult.error));
        return;
    }
    LogPrintf("TradeBoardTab: Sent maker base PSBT (%d bytes) to taker on session %s\n",
              basePsbt.length(), session_id.toStdString().c_str());

    // Don't send ceremony_invite yet - wait for taker to send ceremony_ready first
    // (ceremony_invite will be sent when we receive ceremony_ready message)

    // Cache ceremony invite for when taker is ready
    QJsonObject ceremonyInvite;
    ceremonyInvite["type"] = "ceremony_invite";
    ceremonyInvite["offer_id"] = offer_id;
    ceremonyInvite["maker_role"] = makerRoleNormalized;
    ceremonyInvite["taker_role"] = (makerRoleNormalized == "lender") ? "borrower" :
                                   (makerRoleNormalized == "borrower") ? "lender" : "";

    QString inviteJson = QString::fromUtf8(QJsonDocument(ceremonyInvite).toJson(QJsonDocument::Compact));

    // Cache ceremony invite (will be sent asynchronously below)
    if (activeRequests.contains(request_id)) {
        activeRequests[request_id].last_ceremony_invite = inviteJson;
        activeRequests[request_id].ceremony_invite_sent = false;
        activeRequests[request_id].maker_role = makerRoleNormalized;
    }

    auto inflightGuard = std::make_shared<InflightGuard>(this);
    QFuture<ConfirmationFlowResult> future = QtConcurrent::run([this, inflightGuard, session_id, inviteJson]() {
        (void)inflightGuard;
        ConfirmationFlowResult result;
        try {
            auto sendResult = walletModel->cosignSend(session_id, inviteJson);
            if (!sendResult.success) {
                result.failureStage = ConfirmationStage::SendCeremonyInvite;
                result.errorDetail = sendResult.error;
                QString lower = sendResult.error.toLower();
                if (lower.contains("session not found") || lower.contains("session expired") ||
                    lower.contains("bridge restarted") || lower.contains("unknown session")) {
                    result.sessionLost = true;
                }
                return result;
            }

            result.success = true;
            result.ceremonyInviteJson = inviteJson;
            return result;
        } catch (const std::exception& e) {
            result.failureStage = ConfirmationStage::None;
            result.errorDetail = QString::fromStdString(e.what());
            return result;
        } catch (...) {
            result.failureStage = ConfirmationStage::None;
            result.errorDetail = QCoreApplication::translate("TradeBoardTab", "Unknown exception");
            return result;
        }
    });

    watcher->setFuture(future);
}

// ============================================================================
// Cross-chain session message handlers
// ============================================================================

void TradeBoardTab::handleXchainAccept(
    const QString& session_id, const QString& request_id, const QJsonObject& msg)
{
    // Maker receives this from taker after offer acceptance.
    //
    // For external_first (ETH/TRON):
    //   - Taker is the external funder (locks ETH, signs lock/refund)
    //   - Maker is the secret holder (funds TSC second, signs claim)
    //
    // Message shape:
    //   { "type": "xchain_accept",
    //     "offer_id": "...",
    //     "taker_refund_address": "0x...",   // taker's ETH addr (lock sender, refund dest)
    //     "taker_tsc_address": "...",        // taker's TSC address
    //     "taker_signer_ref": "derived:auto" // taker's external signer ref
    //     "token_address": "0x..." }         // ERC-20 or empty for native
    if (!walletModel) return;

    QString offerId = msg.value("offer_id").toString();
    QString takerRefundAddr = msg.value("taker_refund_address").toString();
    QString takerTscAddr = msg.value("taker_tsc_address").toString();
    QString takerSignerRef = msg.value("taker_signer_ref").toString();
    QString tokenAddr = msg.value("token_address").toString();

    if (offerId.isEmpty() || takerRefundAddr.isEmpty()) {
        LogPrintf("TradeBoardTab::handleXchainAccept: Missing required fields\n");
        return;
    }

    if (!activeOffers.contains(offerId)) {
        LogPrintf("TradeBoardTab::handleXchainAccept: Offer %s not found\n",
                  offerId.toStdString().c_str());
        return;
    }

    const OfferInfo& offer = activeOffers[offerId];
    QString swapId = QUuid::createUuid().toString(QUuid::WithoutBraces);
    QString htlcSwapId = QStringLiteral("0x") + QString::fromLatin1(
        QCryptographicHash::hash(swapId.toUtf8(), QCryptographicHash::Sha256).toHex());

    // MAKER generates the secret (second funder = secret holder per plan)
    QByteArray secretBytes(32, 0);
    QRandomGenerator::securelySeeded().fillRange(
        reinterpret_cast<quint32*>(secretBytes.data()), 8);
    QString claimSecret = QStringLiteral("0x") + QString::fromLatin1(secretBytes.toHex());
    QString secretHash = QStringLiteral("0x") + QString::fromLatin1(
        QCryptographicHash::hash(secretBytes, QCryptographicHash::Sha256).toHex());

    // Parse amounts from the offer payload
    QJsonDocument payloadDoc = QJsonDocument::fromJson(offer.contract_payload.toUtf8());
    QJsonObject extLeg = payloadDoc.object().value("external_leg").toObject();
    QString expectedAmount = extLeg.value("units").toString();

    // Maker's own ETH settlement address and signer ref from their profile
    QString makerEthAddr = extLeg.value("settlement_address").toString();
    QList<WalletModel::SettlementProfileItem> profiles = walletModel->settlementProfileList();
    QString makerSignerRef;
    for (const auto& p : profiles) {
        if (p.chain == "ethereum" && p.address == makerEthAddr) {
            makerSignerRef = p.signer_ref;
            break;
        }
    }

    // HTLC contract address: session-negotiated, not from payload.
    // The maker selects which deployed HTLC contract to use.
    // Read from -xchain_eth_htlc_address command-line arg.
    QString htlcContractAddr = QString::fromStdString(
        gArgs.GetArg("-xchain_eth_htlc_address", ""));
    if (htlcContractAddr.isEmpty()) {
        LogPrintf("TradeBoardTab::handleXchainAccept: No HTLC contract address configured "
                  "(set -xchain_eth_htlc_address=0x...)\n");
        showAutoClosingInfo(tr("Configuration Missing"),
            tr("Set -xchain_eth_htlc_address in your config to accept cross-chain offers."));
        return;
    }

    // Create the cross-chain record (maker side)
    auto createResult = walletModel->crossChainCreateRecord(
        swapId, offerId,
        QStringLiteral("ethereum"), QStringLiteral("eth_htlc_v1"),
        QStringLiteral("external_first"), QStringLiteral("maker"),
        offer.contract_payload);

    if (!createResult.success) {
        LogPrintf("TradeBoardTab::handleXchainAccept: Failed to create record: %s\n",
                  createResult.error.toStdString().c_str());
        return;
    }

    // Set HTLC params on maker record:
    //   - external_signer_ref: MAKER's signer (they sign the claim tx)
    //   - claim_secret: maker holds the preimage
    //   - expected_recipient: maker's ETH addr (HTLC recipient)
    auto paramsResult = walletModel->crossChainSetHtlcParams(
        swapId, htlcContractAddr, htlcSwapId,
        makerSignerRef,           // maker's signer — they claim
        claimSecret,              // maker holds the secret
        secretHash,               // expected on-chain secret hash
        makerEthAddr,             // expected HTLC recipient = maker's ETH address
        expectedAmount, tokenAddr);

    if (!paramsResult) {
        LogPrintf("TradeBoardTab::handleXchainAccept: Failed to set HTLC params\n");
        return;
    }

    // Persist taker's session addresses on the maker record
    // (needed for TSC-side ceremony: taker_tsc_address is the output destination)
    walletModel->crossChainUpdateSessionAddresses(swapId, takerTscAddr, takerRefundAddr);

    // Reply with xchain_params — carries ALL session-negotiated values
    QJsonObject reply;
    reply["type"] = QStringLiteral("xchain_params");
    reply["swap_id"] = swapId;
    reply["htlc_swap_id"] = htlcSwapId;
    reply["htlc_contract_address"] = htlcContractAddr;
    reply["offer_id"] = offerId;
    reply["secret_hash"] = secretHash;
    reply["htlc_recipient"] = makerEthAddr;
    reply["expected_amount"] = expectedAmount;
    reply["token_address"] = tokenAddr;

    auto sendResult = walletModel->cosignSend(session_id,
        QString::fromUtf8(QJsonDocument(reply).toJson(QJsonDocument::Compact)));

    if (!sendResult.success) {
        LogPrintf("TradeBoardTab::handleXchainAccept: CRITICAL — failed to send "
                  "xchain_params: %s. NOT registering swap.\n",
                  sendResult.error.toStdString().c_str());
        // TODO: clean up the record we just created
        return;
    }

    // Only register with manager AFTER confirming the send succeeded
    walletModel->crossChainRegisterSwap(swapId);

    LogPrintf("TradeBoardTab::handleXchainAccept: Created maker record %s, "
              "secret generated, xchain_params sent successfully\n",
              swapId.toStdString().c_str());

    showAutoClosingInfo(tr("Cross-Chain Accept"),
        tr("Taker accepted cross-chain offer %1.\n\nSwap ID: %2\n"
           "Secret generated. Waiting for ETH HTLC lock...")
        .arg(offerId.left(12), swapId.left(12)));
}

void TradeBoardTab::handleXchainParams(
    const QString& session_id, const QString& request_id, const QJsonObject& msg)
{
    // Taker receives this from maker after sending xchain_accept.
    //
    // For external_first: taker is the external funder.
    // All HTLC parameters are session-negotiated (from this message),
    // not from the original offer payload.
    //
    // Message shape:
    //   { "type": "xchain_params",
    //     "swap_id": "...",
    //     "htlc_swap_id": "0x...",
    //     "htlc_contract_address": "0x...",
    //     "offer_id": "...",
    //     "secret_hash": "0x...",
    //     "htlc_recipient": "0x...",
    //     "expected_amount": "...",
    //     "token_address": "0x..." }
    if (!walletModel) return;

    QString swapId = msg.value("swap_id").toString();
    QString htlcSwapId = msg.value("htlc_swap_id").toString();
    QString htlcContractAddr = msg.value("htlc_contract_address").toString();
    QString offerId = msg.value("offer_id").toString();
    QString secretHash = msg.value("secret_hash").toString();
    QString htlcRecipient = msg.value("htlc_recipient").toString();
    QString expectedAmount = msg.value("expected_amount").toString();
    QString tokenAddr = msg.value("token_address").toString();

    if (swapId.isEmpty() || htlcSwapId.isEmpty() || htlcContractAddr.isEmpty() ||
        secretHash.isEmpty() || htlcRecipient.isEmpty()) {
        LogPrintf("TradeBoardTab::handleXchainParams: Missing required fields\n");
        return;
    }

    // Get the offer payload for record creation
    QString payloadJson;
    if (activeOffers.contains(offerId)) {
        payloadJson = activeOffers[offerId].contract_payload;
    }

    // Taker's signer ref — from their settlement profile for this chain
    QList<WalletModel::SettlementProfileItem> profiles = walletModel->settlementProfileList();
    QString takerSignerRef;
    for (const auto& p : profiles) {
        if (p.chain == "ethereum") {
            takerSignerRef = p.signer_ref;
            break;
        }
    }

    // Create the cross-chain record (taker side)
    auto createResult = walletModel->crossChainCreateRecord(
        swapId, offerId,
        QStringLiteral("ethereum"), QStringLiteral("eth_htlc_v1"),
        QStringLiteral("external_first"), QStringLiteral("taker"),
        payloadJson);

    if (!createResult.success) {
        LogPrintf("TradeBoardTab::handleXchainParams: Failed to create record: %s\n",
                  createResult.error.toStdString().c_str());
        return;
    }

    // Set HTLC params on taker record:
    //   - external_signer_ref: TAKER's signer (they sign lock/refund)
    //   - claim_secret: empty — taker does NOT hold it (maker does)
    //   - All values from the session message, NOT from payload
    auto paramsResult = walletModel->crossChainSetHtlcParams(
        swapId, htlcContractAddr, htlcSwapId,
        takerSignerRef,      // taker's signer — they lock/refund
        QString(),           // taker does NOT hold the claim secret
        secretHash,          // expected on-chain: sha256(maker's secret)
        htlcRecipient,       // expected HTLC recipient = maker's ETH address
        expectedAmount, tokenAddr);

    if (!paramsResult) {
        LogPrintf("TradeBoardTab::handleXchainParams: Failed to set HTLC params\n");
        return;
    }

    // Register with the manager
    walletModel->crossChainRegisterSwap(swapId);

    LogPrintf("TradeBoardTab::handleXchainParams: Created taker record %s "
              "(signer=%s). Prompting taker to lock ETH.\n",
              swapId.toStdString().c_str(),
              takerSignerRef.toStdString().c_str());

    // Prompt taker to lock ETH
    int ret = QMessageBox::question(this, tr("Lock ETH?"),
        tr("Maker confirmed cross-chain swap parameters.\n\n"
           "Swap ID: %1\n"
           "HTLC Contract: %2\n"
           "Recipient: %3\n"
           "Amount: %4\n\n"
           "Do you want to lock your ETH now?\n\n"
           "This will send a transaction to the HTLC contract.")
        .arg(swapId.left(12),
             htlcContractAddr,
             htlcRecipient,
             expectedAmount),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::Yes);

    if (ret != QMessageBox::Yes) {
        showAutoClosingInfo(tr("Lock Deferred"),
            tr("You can lock ETH later from the Cross-Chain active trades view."));
        return;
    }

    // Compute timelock from the offer's timeout policy
    QJsonDocument lockPayloadDoc = QJsonDocument::fromJson(payloadJson.toUtf8());
    QJsonObject timeoutPolicy = lockPayloadDoc.object().value("timeout_policy").toObject();
    int64_t externalLockSeconds = timeoutPolicy.value("external_lock_seconds").toInteger(86400);
    int64_t timelock = QDateTime::currentSecsSinceEpoch() + externalLockSeconds;

    // Lock ETH via the bridge
    auto lockResult = walletModel->ethLockHtlc(
        htlcContractAddr, htlcSwapId, htlcRecipient,
        secretHash, timelock, expectedAmount, takerSignerRef,
        tokenAddr);

    if (lockResult.success) {
        LogPrintf("TradeBoardTab::handleXchainParams: ETH lock broadcast tx=%s\n",
                  lockResult.tx_hash.toStdString().c_str());

        // Send advisory lock_notify to maker
        QJsonObject lockNotify;
        lockNotify["type"] = QStringLiteral("xchain_lock_notify");
        lockNotify["swap_id"] = swapId;
        lockNotify["lock_tx_hash"] = lockResult.tx_hash;
        walletModel->cosignSend(session_id,
            QString::fromUtf8(QJsonDocument(lockNotify).toJson(QJsonDocument::Compact)));

        showAutoClosingInfo(tr("ETH Locked"),
            tr("ETH lock transaction broadcast!\n\nTx: %1\n\n"
               "The manager will track confirmations automatically.")
            .arg(lockResult.tx_hash.left(16) + "..."));
    } else {
        QMessageBox::critical(this, tr("Lock Failed"),
            tr("Failed to lock ETH:\n\n%1").arg(lockResult.error));
    }
}

void TradeBoardTab::handleSessionLoss(const QString& session_id,
                                      const QString& request_id,
                                      const QString& errorText)
{
    if (!activeRequests.contains(request_id)) {
        LogPrintf("TradeBoardTab: Session %s lost but request %s not found\n",
                  session_id.toStdString().c_str(),
                  request_id.toStdString().c_str());
        return;
    }

    TradeRequestInfo& info = activeRequests[request_id];
    if (info.recovering_session) {
        LogPrintf("TradeBoardTab: Session loss already noted for request %s\n",
                  request_id.toStdString().c_str());
        return;
    }

    info.recovering_session = true;
    activeSessions.remove(session_id);
    ceremonySessions.remove(session_id);

    if (sessionManager && !session_id.isEmpty()) {
        sessionManager->removeSession(session_id);
    }

    LogPrintf("TradeBoardTab: Detected session loss on %s (request %s, direction=%s, error=%s)\n",
              session_id.toStdString().c_str(),
              request_id.toStdString().c_str(),
              info.direction.toStdString().c_str(),
              errorText.toStdString().c_str());

    if (info.direction == "outgoing") {
        showNonBlockingInfo(tr("Session Dropped"),
            tr("Cosign session %1 was dropped (%2).\n\n"
               "Automatic recovery is disabled. Please re-open the contract from the Trade Board when both parties are ready.")
                .arg(session_id.left(16) + "...")
                .arg(errorText));
    } else {
        showNonBlockingInfo(tr("Session Dropped"),
            tr("Cosign session %1 was dropped (%2).\n\n"
               "Automatic re-creation is disabled. Ask the taker to request the trade again when ready.")
                .arg(session_id.left(16) + "...")
                .arg(errorText));
    }

    info.staged_local_base_psbt.clear();
    info.staged_local_base_ready = false;
    info.staged_peer_base_psbt.clear();
    info.staged_peer_base_ready = false;
    info.taker_ready_for_ceremony = false;
    info.ceremony_ready_sent = false;
    info.waiting_for_base_notice_sent = false;

    info.recovering_session = false;
}

void TradeBoardTab::recoverTakerSession(const QString& request_id)
{
    if (!walletModel) return;
    if (!activeRequests.contains(request_id)) return;

    TradeRequestInfo& info = activeRequests[request_id];

    if (info.invite_link.isEmpty()) {
        LogPrintf("TradeBoardTab: Cannot recover taker session for request %s - missing invite link\n",
                  request_id.toStdString().c_str());
        info.recovering_session = false;
        showNonBlockingInfo(tr("Manual Action Required"),
            tr("The maker's session was lost but no invite link is cached.\n"
               "Please coordinate with the maker to receive a new invite."));
        return;
    }

    auto joinResult = walletModel->cosignJoin(info.invite_link, "trade");
    if (!joinResult.success) {
        LogPrintf("TradeBoardTab: Failed to re-join session for request %s: %s\n",
                  request_id.toStdString().c_str(),
                  joinResult.error.toStdString().c_str());
        info.auto_joined = true;
        info.recovering_session = false;
        autoJoinAttemptedRequests.insert(AutoJoinAttemptKey(request_id, info.invite_link));
        const QString sessionHint = CosignRoomIdFromInviteLink(info.invite_link);
        if (!sessionHint.isEmpty()) {
            autoJoinAttemptedSessions.insert(sessionHint);
        }
        showNonBlockingInfo(tr("Reconnect Failed"),
            tr("Automatic re-join attempt failed:\n\n%1\n\n"
               "You can retry from the Bridge Sessions tab.")
                .arg(joinResult.error));
        return;
    }

    QString newSessionId = joinResult.session_id;
    info.auto_joined = true;

    if (sessionManager && !newSessionId.isEmpty()) {
        BridgeSessionManager::SessionInfo sessionInfo;
        sessionInfo.session_id = newSessionId;
        sessionInfo.sas = tr("(handshaking...)");
        sessionInfo.sas_numeric = "";
        sessionInfo.transport = joinResult.transport.isEmpty() ? "auto" : joinResult.transport;
        sessionInfo.relay_url = joinResult.relay_url;
        sessionInfo.started_timestamp = QDateTime::currentSecsSinceEpoch();
        sessionInfo.handshake_complete = false;
        sessionInfo.is_initiator = false;
        sessionManager->addSession(sessionInfo);
    }

    QString capturedSessionId = newSessionId;
    QString capturedRequestId = request_id;

    auto inflightGuard = std::make_shared<InflightGuard>(this);
    QFuture<QVariantMap> future = QtConcurrent::run([this, inflightGuard, capturedSessionId]() -> QVariantMap {
        (void)inflightGuard;
        auto result = walletModel->cosignHandshakeAuto(capturedSessionId, false);
        QVariantMap resultMap;
        resultMap["success"] = result.success;
        resultMap["handshake_complete"] = result.handshake_complete;
        resultMap["sas"] = result.sas;
        resultMap["sas_numeric"] = result.sas_numeric;
        resultMap["error"] = result.error;
        return resultMap;
    });

    auto* watcher = new QFutureWatcher<QVariantMap>(this);
    connect(watcher, &QFutureWatcher<QVariantMap>::finished, this,
            [this, watcher, capturedSessionId, capturedRequestId]() {
        QVariantMap handshakeResult = watcher->result();
        watcher->deleteLater();
        onHandshakeCompleteTaker(capturedSessionId, capturedRequestId, handshakeResult);
    });

    watcher->setFuture(future);
}

void TradeBoardTab::recoverMakerSession(const QString& request_id)
{
    if (!walletModel) return;
    if (!activeRequests.contains(request_id)) return;

    TradeRequestInfo& info = activeRequests[request_id];

    if (info.final_offer_json.isEmpty() || info.final_offer_id.isEmpty()) {
        LogPrintf("TradeBoardTab: Cannot recover maker session for request %s - missing finalized offer cache\n",
                  request_id.toStdString().c_str());
        info.recovering_session = false;
        showNonBlockingInfo(tr("Manual Intervention Required"),
            tr("The finalized offer payload is not cached locally. "
               "You may need to rebuild the offer manually."));
        return;
    }

    // Retrieve transport preference for this offer (defaults to "auto" if not found)
    QString transport = offerTransportPreferences.value(info.offer_id, "auto");
    LogPrintf("TradeBoardTab: Using transport '%s' for offer %s during session recovery\n",
             transport.toStdString().c_str(), info.offer_id.toStdString().c_str());

    auto acceptResult = walletModel->bulletinBoardAcceptRequest(request_id, transport);
    if (!acceptResult.success) {
        LogPrintf("TradeBoardTab: cosign.accept_request failed during recovery for %s: %s\n",
                  request_id.toStdString().c_str(),
                  acceptResult.error.toStdString().c_str());
        info.recovering_session = false;
        showNonBlockingInfo(tr("Session Recovery Failed"),
            tr("Could not create a replacement session:\n\n%1").arg(acceptResult.error));
        return;
    }

    if (!acceptResult.invite_link.isEmpty()) {
        info.invite_link = acceptResult.invite_link;
    }

    QString newSessionId = acceptResult.session_id;

    if (sessionManager && !newSessionId.isEmpty()) {
        BridgeSessionManager::SessionInfo sessionInfo;
        sessionInfo.session_id = newSessionId;
        sessionInfo.sas = tr("(handshaking...)");
        sessionInfo.sas_numeric = "";
        sessionInfo.transport = acceptResult.transport.isEmpty() ? "auto" : acceptResult.transport;
        sessionInfo.relay_url = acceptResult.relay_url;
        sessionInfo.started_timestamp = QDateTime::currentSecsSinceEpoch();
        sessionInfo.handshake_complete = false;
        sessionInfo.is_initiator = true;
        sessionManager->addSession(sessionInfo);
    }

    QString capturedSessionId = newSessionId;
    QString capturedRequestId = request_id;
    QString capturedFinalOfferId = info.final_offer_id;
    QString capturedFinalOfferJson = info.final_offer_json;

    auto inflightGuard = std::make_shared<InflightGuard>(this);
    QFuture<QVariantMap> future = QtConcurrent::run([this, inflightGuard, capturedSessionId]() -> QVariantMap {
        (void)inflightGuard;
        auto result = walletModel->cosignHandshakeAuto(capturedSessionId, true);
        QVariantMap resultMap;
        resultMap["success"] = result.success;
        resultMap["handshake_complete"] = result.handshake_complete;
        resultMap["sas"] = result.sas;
        resultMap["sas_numeric"] = result.sas_numeric;
        resultMap["error"] = result.error;
        return resultMap;
    });

    auto* watcher = new QFutureWatcher<QVariantMap>(this);
    connect(watcher, &QFutureWatcher<QVariantMap>::finished, this,
            [this, watcher, capturedSessionId, capturedRequestId, capturedFinalOfferId, capturedFinalOfferJson]() {
        QVariantMap handshakeResult = watcher->result();
        watcher->deleteLater();
        onHandshakeCompleteMaker(capturedSessionId, capturedRequestId, capturedFinalOfferId, capturedFinalOfferJson, handshakeResult);
    });

    watcher->setFuture(future);
}

void TradeBoardTab::handleDifficultyAcceptanceReceived(const QString& session_id, const QString& request_id, const QJsonObject& msg)
{
    if (!walletModel) return;

    const QJsonObject acceptanceObj = msg.value("acceptance").toObject();
    const QString expectedId = msg.value("contract_id").toString();

    // SECURITY: use OUR OWN published offer as the authoritative source for kind / maker role / the offer
    // fed to import_acceptance — never the taker's message fields (which a spoofed outer term sheet could
    // have steered). Fall back to the message's offer only if our cache lost it; import_acceptance's
    // contract_id recompute is the backstop either way.
    QString offerId;
    if (activeRequests.contains(request_id)) offerId = activeRequests[request_id].offer_id;
    QJsonObject ownOffer;
    if (!offerId.isEmpty() && activeOffers.contains(offerId)) {
        ownOffer = QJsonDocument::fromJson(activeOffers[offerId].contract_payload.toUtf8())
                       .object().value("offer").toObject();
    }
    const QJsonObject offerToUse = !ownOffer.isEmpty() ? ownOffer : msg.value("offer").toObject();
    const QString kind = offerToUse.value("kind").toString();               // "cfd" | "option" (signed)
    const QString makerRole = offerToUse.value("proposer_role").toString(); // long/short | writer/buyer (signed)
    if (offerToUse.isEmpty() || acceptanceObj.isEmpty() || kind.isEmpty() || makerRole.isEmpty()) {
        LogPrintf("TradeBoardTab: difficulty_acceptance: no valid own/signed offer; ignoring\n");
        return;
    }
    const QString offerJson = QString::fromUtf8(QJsonDocument(offerToUse).toJson(QJsonDocument::Compact));
    const QString acceptanceJson = QString::fromUtf8(QJsonDocument(acceptanceObj).toJson(QJsonDocument::Compact));

    // Import + verify. difficulty.import_acceptance recomputes contract_id from our signed offer + the
    // acceptance and HARD-FAILS on mismatch; idempotent for session retries (insert_or_assign by id).
    WalletModel::DifficultyImportResult ir = walletModel->difficultyImportAcceptance(offerJson, acceptanceJson);
    if (!ir.success) {
        LogPrintf("TradeBoardTab: difficulty.import_acceptance failed: %s\n", ir.error.toStdString().c_str());
        return;
    }
    const QString contractId = ir.contract_id;
    if (!expectedId.isEmpty() && expectedId != contractId) {
        LogPrintf("TradeBoardTab: difficulty_acceptance contract_id mismatch (got %s, expected %s); aborting\n",
                  contractId.toStdString().c_str(), expectedId.toStdString().c_str());
        return;
    }

    // A wallet-owned address for the ceremony's BIP-322 attestation (proves key control; the slot label
    // is irrelevant — getAddressForRole falls back across both slots and checks ownership).
    const QString makerAttestAddr = walletModel->getNewAddress(tr("Difficulty attestation"), "bech32m");
    if (activeRequests.contains(request_id)) {
        // WATCHPOINT: the contract_id is canonical from here — never the bulletin-board UUID.
        activeRequests[request_id].final_offer_id = contractId;
        activeRequests[request_id].offer_summary["contract_type"] = QStringLiteral("difficulty");
        activeRequests[request_id].maker_role = makerRole;
        activeRequests[request_id].borrower_address = makerAttestAddr;
    }
    cacheContractFlavor(contractId, QStringLiteral("difficulty"), QString(), offerId);

    // Build the maker's OWN side base. build_open_option is role-order tolerant (maker-first works even if
    // the maker is the option buyer); the taker later augments with the opposite role.
    WalletModel::DifficultyPsbtResult br = (kind == QLatin1String("option"))
        ? walletModel->difficultyBuildOpenOption(contractId, makerRole)
        : walletModel->difficultyBuildOpen(contractId, makerRole);
    if (!br.success || br.psbt.isEmpty()) {
        LogPrintf("TradeBoardTab: difficulty maker build_open failed: %s\n", br.error.toStdString().c_str());
        return;
    }

    // CACHE the maker's own base: launchOpeningCeremony() (triggered by the taker's ceremony_ready) reads
    // info.maker_base_psbt for the runner's Phase-0 base verification and aborts with "Maker's base PSBT
    // is missing" if it is unset.
    if (activeRequests.contains(request_id)) {
        activeRequests[request_id].maker_base_psbt = br.psbt;
    }

    // Send the EXISTING maker_base_psbt; the taker augments via difficulty.build_open(psbt=...) and replies
    // with the existing ceremony_ready, after which the generic adaptor ceremony runs unchanged.
    QJsonObject basePsbtMsg;
    basePsbtMsg["type"] = QStringLiteral("maker_base_psbt");
    basePsbtMsg["offer_id"] = offerId;
    basePsbtMsg["contract_id"] = contractId;
    basePsbtMsg["psbt"] = br.psbt;
    basePsbtMsg["maker_role"] = makerRole;
    auto sendResult = walletModel->cosignSend(session_id,
        QString::fromUtf8(QJsonDocument(basePsbtMsg).toJson(QJsonDocument::Compact)));
    if (!sendResult.success) {
        LogPrintf("TradeBoardTab: failed to send difficulty maker_base_psbt: %s\n", sendResult.error.toStdString().c_str());
        return;
    }

    // Mark the maker READY so the generic ceremony_ready handler accepts it (it ignores the maker unless
    // ceremony_invite_sent == true). Difficulty deliberately does NOT send a separate ceremony_invite: the
    // taker already committed by accepting, so its maker_base_psbt handler auto-augments and replies with
    // ceremony_ready directly. ONE ordered message (maker_base_psbt) -> no invite-before-base race.
    if (activeRequests.contains(request_id)) {
        activeRequests[request_id].ceremony_invite_sent = true;
    }
    LogPrintf("TradeBoardTab: difficulty maker base sent + cached (contract %s); ready for ceremony_ready\n",
              contractId.toStdString().c_str());
}

void TradeBoardTab::handleAcceptanceReceived(const QString& session_id, const QString& request_id, const QString& acceptance_json)
{
    LogPrintf("TradeBoardTab: Maker received acceptance on session %s\n", session_id.toStdString().c_str());

    if (!walletModel) return;

    // Parse the acceptance JSON to extract offer_id
    QJsonParseError parseError;
    QJsonDocument acceptanceDoc = QJsonDocument::fromJson(acceptance_json.toUtf8(), &parseError);
    if (acceptanceDoc.isNull() || !acceptanceDoc.isObject()) {
        QMessageBox::critical(this, tr("Parse Error"),
            tr("Failed to parse acceptance JSON:\n%1").arg(parseError.errorString()));
        return;
    }

    QJsonObject acceptanceObj = acceptanceDoc.object();
    if (!acceptanceObj.contains("offer_id") && acceptanceObj.contains("acceptance") && acceptanceObj.value("acceptance").isObject()) {
        acceptanceObj = acceptanceObj.value("acceptance").toObject();
        LogPrintf("TradeBoardTab: Unwrapped acceptance envelope for offer %s\n",
                  acceptanceObj.value("offer_id").toString().toStdString().c_str());
    }

    QString acceptancePayloadJson = QString::fromUtf8(QJsonDocument(acceptanceObj).toJson(QJsonDocument::Compact));
    QString offer_id = acceptanceObj.value("offer_id").toString();

    if (offer_id.isEmpty()) {
        QMessageBox::critical(this, tr("Invalid Acceptance"),
            tr("Acceptance is missing offer ID."));
        return;
    }

    if (!activeRequests.contains(request_id)) {
        QMessageBox::warning(this, tr("Unknown Request"),
            tr("Received acceptance for unknown request %1.\n\nPlease refresh the Trade Board.").arg(request_id.left(16) + "..."));
        return;
    }

    // CRITICAL: Copy TradeRequestInfo instead of using reference to avoid QMap invalidation
    TradeRequestInfo reqInfo = activeRequests[request_id];  // Deep copy
    QString detectedContractType;

    // Parse terms from the maker's original offer (stored in final_offer_json), not from acceptance
    LogPrintf("TradeBoardTab: handleAcceptanceReceived - final_offer_json.isEmpty=%d, offer_id=%s\n",
              reqInfo.final_offer_json.isEmpty(), offer_id.toStdString().c_str());

    if (!reqInfo.final_offer_json.isEmpty()) {
        QJsonParseError offerParseError;
        QJsonDocument offerDoc = QJsonDocument::fromJson(reqInfo.final_offer_json.toUtf8(), &offerParseError);
        if (!offerDoc.isNull() && offerDoc.isObject()) {
            QJsonObject offerObj = offerDoc.object();
            QString contractType = offerObj.value("contract_type").toString().toLower();
            if (contractType == "options") {
                contractType = QStringLiteral("option");
            }
            detectedContractType = contractType;

            // CRITICAL: Update offer_summary so downstream code sees contract_type (mirrors taker path)
            reqInfo.offer_summary["contract_type"] = contractType;
            if (offerObj.contains("maker_role")) {
                const QString makerRoleStr = offerObj.value("maker_role").toString();
                reqInfo.offer_summary["maker_role"] = makerRoleStr;
                reqInfo.maker_role = makerRoleStr.toLower();
            }

            // CACHE POPULATION: Acceptance envelope - populate from cached offer JSON
            cacheContractFlavor(offer_id, contractType, reqInfo.final_offer_json, reqInfo.offer_id);
            LogPrintf("TradeBoardTab: Cached contract flavor from acceptance (cached) - offer_id=%s, type=%s\n",
                      offer_id.toStdString().c_str(), contractType.toStdString().c_str());

            LogPrintf("TradeBoardTab: Parsing maker offer - contract_type='%s'\n", contractType.toStdString().c_str());
            if (contractType == "forward" || contractType == "option" || contractType == "options") {
                LogPrintf("TradeBoardTab: Calling populateForwardTermsFromJson for maker dialog\n");
                populateForwardTermsFromJson(reqInfo, offerObj);
                reqInfo.borrower_address = reqInfo.long_margin_dest;
                reqInfo.lender_address = reqInfo.short_margin_dest;
            } else if (contractType == "spot") {
                LogPrintf("TradeBoardTab: Spot contract - will populate snapshot directly (no reqInfo fields)\n");
                // Spot populates snapshot directly via populateSpotTermsFromJson later
                reqInfo.contract_type = contractType;
            } else {
                LogPrintf("TradeBoardTab: Calling populateRepoTermsFromJson for maker dialog\n");
                populateRepoTermsFromJson(reqInfo, offerObj);
                const QString borrowerAddr = offerObj.value("borrower_address").toString();
                const QString lenderAddr = offerObj.value("lender_address").toString();
                if (!borrowerAddr.isEmpty()) {
                    reqInfo.borrower_address = borrowerAddr;
                }
                if (!lenderAddr.isEmpty()) {
                    reqInfo.lender_address = lenderAddr;
                }
            }
        } else {
            LogPrintf("TradeBoardTab: ERROR - Failed to parse final_offer_json: %s\n", offerParseError.errorString().toStdString().c_str());
        }
    } else if (!offer_id.isEmpty()) {
        // Maker's offer JSON wasn't cached - fetch it from wallet via contract.status RPC
        try {
            UniValue params(UniValue::VARR);
            params.push_back(offer_id.toStdString());
            UniValue status_resp = walletModel->node().executeRpc("contract.status", params, walletModel->getWalletName().toStdString());
            if (status_resp.isObject() && status_resp.exists("offer")) {
                QString offerJson = QString::fromStdString(status_resp["offer"].write());
                reqInfo.final_offer_json = offerJson;
                QJsonDocument offerDoc = QJsonDocument::fromJson(offerJson.toUtf8());
                if (!offerDoc.isNull() && offerDoc.isObject()) {
                    QJsonObject offerObj = offerDoc.object();
                    QString contractType = offerObj.value("contract_type").toString().toLower();
                    if (contractType == "options") {
                        contractType = QStringLiteral("option");
                    }
                    detectedContractType = contractType;

                    // CRITICAL: Update offer_summary so downstream code sees contract_type (mirrors taker path)
                    reqInfo.offer_summary["contract_type"] = contractType;
                    if (offerObj.contains("maker_role")) {
                        const QString makerRoleStr = offerObj.value("maker_role").toString();
                        reqInfo.offer_summary["maker_role"] = makerRoleStr;
                        reqInfo.maker_role = makerRoleStr.toLower();
                    }

                    // CACHE POPULATION: Acceptance envelope - populate from RPC-fetched offer JSON
                    cacheContractFlavor(offer_id, contractType, offerJson, reqInfo.offer_id);
                    LogPrintf("TradeBoardTab: Cached contract flavor from acceptance (RPC) - offer_id=%s, type=%s\n",
                              offer_id.toStdString().c_str(), contractType.toStdString().c_str());

                    if (contractType == "forward" || contractType == "option" || contractType == "options") {
                        populateForwardTermsFromJson(reqInfo, offerObj);
                        LogPrintf("TradeBoardTab: Populated forward terms via contract.status fallback for offer %s\n",
                                  offer_id.toStdString().c_str());
                        reqInfo.borrower_address = reqInfo.long_margin_dest;
                        reqInfo.lender_address = reqInfo.short_margin_dest;
                    } else if (contractType == "spot") {
                        LogPrintf("TradeBoardTab: Spot contract via RPC - will populate snapshot directly\n");
                        // Spot populates snapshot directly via populateSpotTermsFromJson later
                        reqInfo.contract_type = contractType;
                    } else {
                        populateRepoTermsFromJson(reqInfo, offerObj);
                        LogPrintf("TradeBoardTab: Populated repo terms via contract.status fallback for offer %s\n",
                                  offer_id.toStdString().c_str());
                        const QString borrowerAddr = offerObj.value("borrower_address").toString();
                        const QString lenderAddr = offerObj.value("lender_address").toString();
                        if (!borrowerAddr.isEmpty()) {
                            reqInfo.borrower_address = borrowerAddr;
                        }
                        if (!lenderAddr.isEmpty()) {
                            reqInfo.lender_address = lenderAddr;
                        }
                    }
                }
            }
        } catch (const std::exception& e) {
            LogPrintf("TradeBoardTab: Failed to fetch offer for maker review: %s\n", e.what());
        }
    }
    if (reqInfo.final_offer_json.isEmpty()) {
        LogPrintf("TradeBoardTab: WARNING - No cached final offer JSON available for offer %s (request %s)\n",
                  offer_id.toStdString().c_str(),
                  request_id.toStdString().c_str());
    }

    // FIX: Fallback contract type detection if JSON parsing failed
    if (detectedContractType.isEmpty()) {
        // Try canonical cache first
        QString cachedType = getCanonicalContractType(offer_id);
        if (!cachedType.isEmpty()) {
            detectedContractType = cachedType.toLower();
            LogPrintf("TradeBoardTab: Using canonical cache for contract type: %s\n", detectedContractType.toStdString().c_str());
        } else if (reqInfo.offer_summary.contains("contract_type")) {
            detectedContractType = reqInfo.offer_summary.value("contract_type").toString().toLower();
            if (detectedContractType == "options") detectedContractType = QStringLiteral("option");
            LogPrintf("TradeBoardTab: Using offer_summary for contract type: %s\n", detectedContractType.toStdString().c_str());
        } else if (!reqInfo.contract_type.isEmpty()) {
            detectedContractType = reqInfo.contract_type.toLower();
            if (detectedContractType == "options") detectedContractType = QStringLiteral("option");
            LogPrintf("TradeBoardTab: Using reqInfo.contract_type for contract type: %s\n", detectedContractType.toStdString().c_str());
        }
    }

    QString makerRole = QStringLiteral("lender");
    if (!reqInfo.maker_role.isEmpty()) {
        makerRole = reqInfo.maker_role;
    } else if (reqInfo.offer_summary.contains("maker_role")) {
        makerRole = reqInfo.offer_summary.value("maker_role").toString().toLower();
        reqInfo.maker_role = makerRole;
    }

    // Write populated data back to map (safe single-access)
    if (activeRequests.contains(request_id)) {
        activeRequests[request_id] = reqInfo;
        LogPrintf("TradeBoardTab: Wrote populated reqInfo back to activeRequests for request %s\n",
                  request_id.toStdString().c_str());
    }

    // =============================================================================================
    // SNAPSHOT-BASED ARCHITECTURE: Create immutable snapshot before modal dialog
    // =============================================================================================

    // CRITICAL: reqInfo is already populated with terms at this point (lines 6825-6831)
    // Deep-copy the values by value to create immutable snapshot (don't re-parse!)
    FinalContractSnapshot snapshot;
    snapshot.request_id = request_id;
    snapshot.session_id = session_id;
    snapshot.contract_id = offer_id;
    snapshot.user_role = makerRole.toLower();
    snapshot.is_taker = false;
    snapshot.is_maker = true;
    snapshot.offer_json = reqInfo.final_offer_json;
    snapshot.acceptance_json = acceptancePayloadJson;
    snapshot.contract_type = detectedContractType;

    // Parse JSONs for display only
    if (!snapshot.offer_json.isEmpty()) {
        QJsonDocument offerDoc = QJsonDocument::fromJson(snapshot.offer_json.toUtf8());
        if (!offerDoc.isNull() && offerDoc.isObject()) {
            snapshot.offer_obj = offerDoc.object();
            snapshot.raw_json_pretty = QString::fromUtf8(QJsonDocument(snapshot.offer_obj).toJson(QJsonDocument::Indented));
        }
    }
    QJsonParseError accParseErr;
    QJsonDocument acceptancePayloadDoc = QJsonDocument::fromJson(acceptancePayloadJson.toUtf8(), &accParseErr);
    if (!acceptancePayloadDoc.isNull() && acceptancePayloadDoc.isObject()) {
        snapshot.acceptance_obj = acceptancePayloadDoc.object();
        snapshot.extra_json_pretty = QString::fromUtf8(QJsonDocument(snapshot.acceptance_obj).toJson(QJsonDocument::Indented));
        snapshot.extra_json_title = tr("Acceptance JSON");
    }

    // Copy already-populated terms from reqInfo (by value - immutable!)
    if (detectedContractType == "repo") {
        snapshot.repo.principal_qty = reqInfo.principal_qty;
        snapshot.repo.principal_asset = reqInfo.principal_asset;
        snapshot.repo.collateral_qty = reqInfo.collateral_qty;
        snapshot.repo.collateral_asset = reqInfo.collateral_asset;
        snapshot.repo.interest_qty = reqInfo.interest_qty;
        snapshot.repo.interest_asset = reqInfo.interest_asset;
        snapshot.repo.apr = reqInfo.apr;
        snapshot.repo.ltv = reqInfo.ltv;
        snapshot.repo.tenor_days = reqInfo.tenor_days;
        snapshot.repo.maturity_height = reqInfo.maturity_height;
        snapshot.repo.borrower_address = reqInfo.borrower_address;
        snapshot.repo.lender_address = reqInfo.lender_address;
    } else if (detectedContractType == "forward" || detectedContractType == "option") {
        snapshot.forward.long_deliver_qty = reqInfo.long_deliver_qty;
        snapshot.forward.long_deliver_asset = reqInfo.long_deliver_asset;
        snapshot.forward.long_deliver_asset_id = reqInfo.long_deliver_asset_id;
        snapshot.forward.long_margin_qty = reqInfo.long_margin_qty;
        snapshot.forward.long_margin_asset = reqInfo.long_margin_asset;
        snapshot.forward.long_margin_asset_id = reqInfo.long_margin_asset_id;
        snapshot.forward.long_im_percent = reqInfo.long_im_percent;
        snapshot.forward.long_margin_dest = reqInfo.long_margin_dest;
        snapshot.forward.long_settlement_dest = reqInfo.long_settlement_dest;
        snapshot.forward.short_deliver_qty = reqInfo.short_deliver_qty;
        snapshot.forward.short_deliver_asset = reqInfo.short_deliver_asset;
        snapshot.forward.short_deliver_asset_id = reqInfo.short_deliver_asset_id;
        snapshot.forward.short_margin_qty = reqInfo.short_margin_qty;
        snapshot.forward.short_margin_asset = reqInfo.short_margin_asset;
        snapshot.forward.short_margin_asset_id = reqInfo.short_margin_asset_id;
        snapshot.forward.short_im_percent = reqInfo.short_im_percent;
        snapshot.forward.short_margin_dest = reqInfo.short_margin_dest;
        snapshot.forward.short_settlement_dest = reqInfo.short_settlement_dest;
        snapshot.forward.premium_amount = reqInfo.premium_amount;
        snapshot.forward.premium_asset = reqInfo.premium_asset;
        snapshot.forward.premium_asset_id = reqInfo.premium_asset_id;
        snapshot.forward.premium_payer = reqInfo.premium_payer;
        snapshot.forward.premium_payee_dest = reqInfo.premium_payee_dest;
        snapshot.forward.deadline_short = reqInfo.deadline_short;
        snapshot.forward.deadline_long = reqInfo.deadline_long;
        snapshot.forward.safety_k = reqInfo.safety_k;
        snapshot.forward.reorg_conf = reqInfo.reorg_conf;
        snapshot.forward.maturity_height = reqInfo.deadline_long;
    } else if (detectedContractType == "spot") {
        // Populate spot terms directly from offer JSON
        populateSpotTermsFromJson(snapshot, snapshot.offer_obj);
    }

    // Build display HTML and checks from snapshot data
    snapshot.summary_html = buildSummaryHtml(snapshot);
    snapshot.critical_checks = buildCriticalChecks(snapshot);

    // Build dialog options from snapshot
    FinalContractReviewDialog::Options reviewOptions;
    reviewOptions.headingHtml = tr("<b>Taker accepted your finalized contract.</b><br>"
                                   "Review the terms and the taker's acceptance details before launching the opening ceremony.");
    reviewOptions.summaryHtml = snapshot.summary_html;
    reviewOptions.offerId = snapshot.contract_id;
    reviewOptions.sessionId = snapshot.session_id;
    reviewOptions.userRole = snapshot.user_role;
    reviewOptions.rawJson = snapshot.raw_json_pretty;
    reviewOptions.rawJsonTitle = tr("Final Contract JSON");
    reviewOptions.extraJson = snapshot.extra_json_pretty;
    reviewOptions.extraJsonTitle = snapshot.extra_json_title;
    reviewOptions.extraJsonButtonLabel = tr("View Acceptance JSON");
    reviewOptions.acceptLabel = tr("Confirm && Launch Ceremony");
    reviewOptions.rejectLabel = tr("Cancel");
    reviewOptions.criticalChecks = snapshot.critical_checks;
    reviewOptions.footnoteHtml = tr("<b>Warning:</b> Confirming will fund your leg immediately and broadcast once the adaptor "
                                    "ceremony finishes. Double-check the figures before continuing.");

    // TIMER SAFETY: Pause background updates during modal dialog
    pauseUpdateTimers();

    int dialogResult = QDialog::Rejected;
    try {
        FinalContractReviewDialog makerDialog(reviewOptions, this);
        LogPrintf("TradeBoardTab: Showing maker confirmation dialog for offer %s\n", offer_id.toStdString().c_str());
        dialogResult = makerDialog.exec();
        LogPrintf("TradeBoardTab: Maker dialog result=%d for offer %s\n", dialogResult, offer_id.toStdString().c_str());
    } catch (const std::exception& e) {
        resumeUpdateTimers();  // Resume timers on error path
        LogPrintf("TradeBoardTab: FATAL - Maker dialog crashed: %s\n", e.what());
        QMessageBox::critical(this, tr("Dialog Error"),
            tr("Failed to display confirmation dialog:\n\n%1").arg(QString::fromStdString(e.what())));
        return;
    } catch (...) {
        resumeUpdateTimers();  // Resume timers on error path
        LogPrintf("TradeBoardTab: FATAL - Maker dialog crashed with unknown error\n");
        QMessageBox::critical(this, tr("Dialog Error"),
            tr("Failed to display confirmation dialog due to an internal error."));
        return;
    }

    // TIMER SAFETY: Resume background updates after dialog closes
    resumeUpdateTimers();

    if (dialogResult != QDialog::Accepted) {
        LogPrintf("TradeBoardTab: Maker cancelled acceptance review for offer %s\n", offer_id.toStdString().c_str());
        return;
    }
    LogPrintf("TradeBoardTab: Maker confirmed acceptance review for offer %s (request_id=%s), launching confirmation workflow\n",
              offer_id.toStdString().c_str(),
              request_id.toStdString().c_str());

    // Defer workflow to next event loop iteration to ensure dialog cleanup (using snapshot - no manual copying needed!)
    // Snapshot is immutable and safe to capture by value
    QTimer::singleShot(0, this, [this, snapshot]() {
        LogPrintf("TradeBoardTab: Lambda executing, starting maker confirmation workflow for offer %s\n",
                  snapshot.contract_id.toStdString().c_str());
        try {
            startMakerConfirmationWorkflow(snapshot);
        } catch (const std::exception& e) {
            LogPrintf("TradeBoardTab: CRASH in startMakerConfirmationWorkflow: %s\n", e.what());
        } catch (...) {
            LogPrintf("TradeBoardTab: CRASH in startMakerConfirmationWorkflow: unknown error\n");
        }
    });
    LogPrintf("TradeBoardTab: Timer scheduled successfully\n");
}

void TradeBoardTab::showNonBlockingInfo(const QString& title, const QString& text)
{
    QWidget* dialog_parent = window() ? window() : this;
    QMessageBox* box = new QMessageBox(QMessageBox::Information, title, text, QMessageBox::Ok, dialog_parent);
    box->setAttribute(Qt::WA_DeleteOnClose);
    box->setWindowModality(Qt::NonModal);
    box->show();
}

void TradeBoardTab::showAutoClosingInfo(const QString& title, const QString& text, int milliseconds)
{
    QWidget* dialog_parent = window() ? window() : this;
    QMessageBox* box = new QMessageBox(QMessageBox::Information, title, text, QMessageBox::NoButton, dialog_parent);
    box->setAttribute(Qt::WA_DeleteOnClose);
    box->setWindowModality(Qt::NonModal);
    box->show();

    // Auto-close after specified milliseconds
    QTimer::singleShot(milliseconds, box, [box]() {
        if (box) {
            box->close();
        }
    });
}

void TradeBoardTab::showNonBlockingDecision(const QString& title, const QString& text, const QString& acceptLabel, const std::function<void()>& onAccept, const QString& rejectLabel, const std::function<void()>& onReject)
{
    QWidget* dialog_parent = window() ? window() : this;
    QMessageBox* box = new QMessageBox(QMessageBox::Warning, title, text, QMessageBox::NoButton, dialog_parent);
    box->setAttribute(Qt::WA_DeleteOnClose);
    box->setWindowModality(Qt::NonModal);
    QPushButton* acceptBtn = box->addButton(acceptLabel, QMessageBox::AcceptRole);
    QPushButton* rejectBtn = box->addButton(rejectLabel, QMessageBox::RejectRole);
    QObject::connect(box, &QMessageBox::buttonClicked, this,
        [this, box, acceptBtn, rejectBtn, onAccept, onReject](QAbstractButton* button) {
        box->setEnabled(false);
        const bool accepted = (button == acceptBtn);
        const bool rejected = (button == rejectBtn);
        box->close();
        box->deleteLater();

        if (accepted && onAccept) {
            QTimer::singleShot(0, this, [onAccept]() { onAccept(); });
        } else if (rejected && onReject) {
            QTimer::singleShot(0, this, [onReject]() { onReject(); });
        }
    });
    box->show();
}

// ============================================================================
// TradeCeremonyRunner - Consolidated ceremony state machine
// Matches feature_fairsign_adaptor.py Test 17 (lines 1630-1787)
// ============================================================================

class TradeCeremonyRunner
{
public:
    TradeCeremonyRunner(WalletModel* wallet,
                        const QString& offerId,
                        const QString& sessionId,
                        const QString& localPsbt,
                        const QString& localRole,
                        bool isMaker,
                        const QString& stagedPeerBase,
                        const QString& peerAugmentedHash,
                        const QString& expectedPeerPsbt,
                        const QString& borrowerAddress,
                        const QString& lenderAddress,
                        const std::shared_ptr<std::atomic_bool>& cancelFlag,
                        std::function<void(TradeBoardTab::CeremonyPhase, const QString&)> progressCallback = nullptr,
                        std::function<void(const QString&)> phase0PsbtCallback = nullptr,
                        bool cooperativeConsent = false)
        : m_wallet(wallet)
        , m_offerId(offerId)
        , m_sessionId(sessionId)
        , m_localPsbt(localPsbt)
        , m_localRole(localRole)
        , m_isMaker(isMaker)
        , m_stagedPeerBase(stagedPeerBase)
        , m_peerAugmentedHash(peerAugmentedHash)
        , m_expectedPeerPsbt(expectedPeerPsbt)
        , m_borrowerAddress(borrowerAddress)
        , m_lenderAddress(lenderAddress)
        , m_cancelFlag(cancelFlag)
        , m_progressCallback(progressCallback)
        , m_phase0PsbtCallback(phase0PsbtCallback)
        , m_cooperative_consent(cooperativeConsent)
    {
        if (!m_stagedPeerBase.isEmpty()) {
            m_pendingPeerBase = m_stagedPeerBase;
        }
    }

    WalletModel::CosignAdaptorRoundtripResult run()
    {
        WalletModel::CosignAdaptorRoundtripResult result = runImpl();
        // Tell the peer the ceremony is over before we unwind, so they don't
        // sit on a receivePsbt() timeout. Skipped on session_lost — the
        // transport is already gone and the bridge would reject the send with
        // the same error we just observed. The cooperative-maker broadcast-
        // fail path emits its own ceremony_abort with the same wire shape
        // before populating result.error; that one still wins (this send
        // is best-effort and idempotent on the peer side).
        if (!result.success && !result.session_lost) {
            sendCeremonyAbort(result.error, result.cancelled);
        }
        return result;
    }

private:
    WalletModel::CosignAdaptorRoundtripResult runImpl()
    {
        WalletModel::CosignAdaptorRoundtripResult result;
        result.success = false;
        result.complete = false;
        result.cancelled = false;
        result.session_lost = false;

        if (!m_wallet) {
            result.error = QObject::tr("Wallet unavailable");
            return result;
        }

        QString roleTag = m_localRole.isEmpty() ? QStringLiteral("peer") : m_localRole.toLower();
        std::string roleStd = roleTag.toStdString();

        try {
            QString ceremonyPsbt = m_localPsbt;
            const bool haveLocalBase = !m_localPsbt.isEmpty();

            // Phase 0: Exchange base PSBTs
            if (!runPhase0BaseExchange(ceremonyPsbt, haveLocalBase, roleTag, result)) {
                return result;
            }
            drainBufferedMessages();  // Clear any stale messages before Phase 1

            // Phase 1: BIP-322 peer attestation (feature_fairsign_adaptor.py:1636-1691)
            if (!runPhase1Attestation(result)) {
                return result;
            }

            // Branch on consent. The atomic adaptor ceremony (Phases 2/3/4)
            // runs unless BOTH parties have explicitly opted into cooperative
            // non-atomic signing — taker via "Pre-sign and Continue" in the
            // Non-Taproot Funding Detected dialog, maker via the downgrade
            // modal triggered when ceremony_ready carries
            // signing_mode="cooperative_non_atomic".
            if (m_cooperative_consent) {
                LogPrintf("TradeCeremonyRunner: [%s] Cooperative consent set on both sides; running asymmetric non-atomic signing (isMaker=%d)\n",
                          roleTag.toStdString().c_str(), m_isMaker ? 1 : 0);

                if (!validateCooperativePreconditions(ceremonyPsbt, result)) {
                    return result;
                }

                drainBufferedMessages(QStringLiteral("signed_psbt_"));  // Keep cooperative-sign messages

                bool ok = m_isMaker
                    ? runCooperativeSignMaker(ceremonyPsbt, roleTag, result)
                    : runCooperativeSignTaker(ceremonyPsbt, roleTag, result);
                if (!ok) {
                    return result;
                }
                drainBufferedMessages();
                result.success = true;
                logStage(QObject::tr("✓ Cooperative ceremony completed"));
                return result;
            }

            drainBufferedMessages(QStringLiteral("nonce_psbt_"));  // Keep nonce messages for Phase 2

            // Phase 2: Nonce exchange
            if (!runPhase2NonceExchange(ceremonyPsbt, roleTag, result)) {
                return result;
            }
            drainBufferedMessages(QStringLiteral("partial_psbt_"));  // Keep partial sig messages for Phase 3

            // Phase 3: Partial signature exchange
            if (!runPhase3PartialExchange(ceremonyPsbt, roleTag, result)) {
                return result;
            }
            drainBufferedMessages(QStringLiteral("final_psbt_"));  // Keep final messages for Phase 4

            // Phase 4: Complete ceremony
            if (!runPhase4Complete(ceremonyPsbt, result)) {
                return result;
            }
            drainBufferedMessages();  // Clear any remaining messages after completion

            result.success = true;
            logStage(QObject::tr("Ceremony completed successfully"));
            return result;

        } catch (const std::exception& e) {
            result.error = QCoreApplication::translate("TradeBoardTab", "Ceremony exception: %1").arg(QString::fromUtf8(e.what()));
            return result;
        } catch (...) {
            result.error = QCoreApplication::translate("TradeBoardTab", "Ceremony exception: unknown");
            return result;
        }
    }

private:
    WalletModel* m_wallet;
    QString m_offerId;
    QString m_sessionId;
    QString m_localPsbt;
    QString m_localRole;
    bool m_isMaker;
    QString m_stagedPeerBase;
    QString m_peerAugmentedHash;
    QString m_expectedPeerPsbt;
    QString m_borrowerAddress;
    QString m_lenderAddress;
    std::shared_ptr<std::atomic_bool> m_cancelFlag;
    std::function<void(TradeBoardTab::CeremonyPhase, const QString&)> m_progressCallback;
    std::function<void(const QString&)> m_phase0PsbtCallback;
    // True when both sides have explicitly opted into the cooperative non-atomic
    // signing path (taker requested via signing_mode in ceremony_ready, maker
    // accepted via the downgrade modal). When false, the atomic adaptor
    // ceremony runs exactly as before.
    bool m_cooperative_consent{false};
    QString m_pendingPeerBase;
    QMap<QString, QString> m_messageBuffer;  // Buffer for out-of-order messages (type -> psbt)

    // Updated as each phase function is entered. The run() wrapper reads this
    // when populating the ceremony_abort envelope sent to the peer, and
    // stageError() includes it in the LogPrintf so a debug.log reader can tell
    // which phase died without scanning back for the matching "Phase X" line.
    QString m_currentPhase{QStringLiteral("handshake_complete")};

    bool decodePsbt(const QString& psbtBase64,
                    PartiallySignedTransaction& out,
                    QString* errorOut = nullptr) const
    {
        std::string error;
        if (!DecodeBase64PSBT(out, psbtBase64.toStdString(), error)) {
            if (errorOut) {
                *errorOut = error.empty() ? QObject::tr("Unable to decode PSBT") : QString::fromStdString(error);
            }
            return false;
        }
        if (!out.tx) {
            if (errorOut) {
                *errorOut = QObject::tr("Decoded PSBT missing unsigned transaction");
            }
            return false;
        }
        return true;
    }

    std::optional<uint256> extractPsbtTxid(const QString& psbtBase64, QString* errorOut = nullptr) const
    {
        PartiallySignedTransaction psbtx;
        if (!decodePsbt(psbtBase64, psbtx, errorOut)) {
            return std::nullopt;
        }
        return psbtx.tx->GetHash();
    }

    QString encodePsbt(const PartiallySignedTransaction& psbt) const
    {
        DataStream ss{};
        ss << psbt;
        return QString::fromStdString(EncodeBase64(ss.str()));
    }

    // Decode the PSBT, override every input's sighash_type to SIGHASH_ALL,
    // re-encode. Cooperative signing needs the per-input stored sighash to
    // match the global override we pass to walletprocesspsbt(..., "ALL", ...)
    // — bcore's RPC rejects mismatches with -22 ("Specified sighash value
    // does not match value stored in PSBT"), which is exactly what killed
    // session …978853000000_… at 2026-05-25T14:41:02Z when the augmented
    // PSBT had DEFAULT on Taproot inputs and ALL on legacy inputs.
    //
    // Caller MUST have already validated the inputs via
    // PsbtCooperativeUnsafeSighash() — this helper only normalises; it
    // does NOT enforce the safety invariant. SIGHASH_ALL is valid on
    // Taproot per BIP-341 (DEFAULT=0x00 is just shorthand for "behave as
    // ALL with no explicit byte") so normalising preserves semantics.
    QString normalizeCooperativeSighashAll(const QString& psbtBase64, QString* errorOut = nullptr) const
    {
        PartiallySignedTransaction psbtx;
        QString decodeErr;
        if (!decodePsbt(psbtBase64, psbtx, &decodeErr)) {
            if (errorOut) *errorOut = decodeErr;
            return {};
        }
        for (auto& in : psbtx.inputs) {
            in.sighash_type = SIGHASH_ALL;
        }
        return encodePsbt(psbtx);
    }

    bool verifyPsbtContainsAllInputs(const PartiallySignedTransaction& basePsbt,
                                     const PartiallySignedTransaction& augmentedPsbt,
                                     QString* missingInputOut = nullptr) const
    {
        // Build set of inputs in base PSBT
        std::set<COutPoint> baseInputs;
        for (const CTxIn& txin : basePsbt.tx->vin) {
            baseInputs.insert(txin.prevout);
        }

        // Build set of inputs in augmented PSBT
        std::set<COutPoint> augmentedInputs;
        for (const CTxIn& txin : augmentedPsbt.tx->vin) {
            augmentedInputs.insert(txin.prevout);
        }

        // Verify every base input exists in augmented PSBT
        for (const auto& baseInput : baseInputs) {
            if (augmentedInputs.find(baseInput) == augmentedInputs.end()) {
                if (missingInputOut) {
                    *missingInputOut = QString::fromStdString(baseInput.ToString());
                }
                return false;
            }
        }
        return true;
    }

	    bool ensureWalletControlsInputs(const QString& psbtBase64,
	                                    WalletModel::CosignAdaptorRoundtripResult& result,
	                                    const QString& stageLabel)
	    {
	        if (!m_wallet) {
	            result.error = QObject::tr("Wallet unavailable");
	            return false;
	        }

        // First, process the PSBT with the wallet to add metadata
        QString processedPsbt = psbtBase64;
        UniValue params(UniValue::VARR);
        params.push_back(psbtBase64.toStdString());

        try {
            UniValue response = m_wallet->node().executeRpc(
                "walletprocesspsbt", params, m_wallet->getWalletName().toStdString());
            if (response.isObject() && response.exists("psbt")) {
                processedPsbt = QString::fromStdString(response["psbt"].get_str());
            }
        } catch (const std::exception& e) {
            // If walletprocesspsbt fails, continue with original PSBT
            LogPrintf("TradeCeremonyRunner: walletprocesspsbt failed: %s\n", e.what());
        }

        PartiallySignedTransaction psbtx;
        QString decodeError;
        if (!decodePsbt(processedPsbt, psbtx, &decodeError)) {
            result.error = stageError(stageLabel, decodeError);
            return false;
        }

	        int spendableInputs = 0;
	        int nonSpendableInputs = 0;
	        QString inputDetails;
	        bool has_foreign_unsigned_non_taproot = false;
	        QString foreignDetails;

	        // Check PSBT inputs for signing capability and detect unsafe foreign non-Taproot inputs.
	        for (size_t i = 0; i < psbtx.inputs.size(); ++i) {
	            const PSBTInput& input = psbtx.inputs[i];
	            bool canSign = false;
	            bool isTaproot = false;

            // Log the actual UTXO we're checking
            if (i < psbtx.tx->vin.size()) {
                const CTxIn& txin = psbtx.tx->vin[i];
                LogPrintf("TradeCeremonyRunner: Checking input %zu: %s:%d\n",
                         i, txin.prevout.hash.ToString().c_str(), txin.prevout.n);
            }

	            // Check if we have witness_utxo (required for standard signing checks)
	            if (!input.witness_utxo.IsNull()) {
	                LogPrintf("TradeCeremonyRunner: Input %zu has witness_utxo (value=%s)\n",
	                         i, FormatMoney(input.witness_utxo.nValue).c_str());

	                // Try to extract and classify the address
	                CTxDestination dest;
	                if (ExtractDestination(input.witness_utxo.scriptPubKey, dest)) {
	                    QString address = QString::fromStdString(EncodeDestination(dest));
	                    LogPrintf("TradeCeremonyRunner: Input %zu address: %s\n",
	                             i, address.toStdString().c_str());

	                    // Classify Taproot vs non-Taproot based on destination type
	                    isTaproot = std::holds_alternative<WitnessV1Taproot>(dest);

	                    // Check if wallet owns this address
	                    UniValue params(UniValue::VARR);
	                    params.push_back(address.toStdString());
	                    try {
	                        UniValue response = m_wallet->node().executeRpc(
	                            "getaddressinfo", params, m_wallet->getWalletName().toStdString());
	                        if (response.isObject()) {
	                            bool isMine = response.exists("ismine") && response["ismine"].get_bool();
	                            bool isWatchOnly = response.exists("iswatchonly") && response["iswatchonly"].get_bool();
	                            bool solvable = response.exists("solvable") && response["solvable"].get_bool();
	                            LogPrintf("TradeCeremonyRunner: Input %zu address ismine=%s iswatchonly=%s solvable=%s taproot=%s\n",
	                                     i,
	                                     isMine ? "true" : "false",
	                                     isWatchOnly ? "true" : "false",
	                                     solvable ? "true" : "false",
	                                     isTaproot ? "true" : "false");
	                            if (isMine) {
	                                canSign = true;
	                            }
	                        }
	                    } catch (const std::exception& e) {
	                        LogPrintf("TradeCeremonyRunner: getaddressinfo failed: %s\n", e.what());
	                    }
	                }

	                // Also check for BIP32 derivation paths (indicates we have the key)
	                if (!input.hd_keypaths.empty()) {
	                    canSign = true;
	                    LogPrintf("TradeCeremonyRunner: Input %zu has %zu BIP32 derivation paths\n",
	                             i, input.hd_keypaths.size());
	                } else if (!input.m_tap_bip32_paths.empty()) {
	                    // Check for Taproot BIP32 paths
	                    canSign = true;
	                    LogPrintf("TradeCeremonyRunner: Input %zu has %zu Taproot BIP32 paths\n",
	                             i, input.m_tap_bip32_paths.size());
	                } else {
	                    LogPrintf("TradeCeremonyRunner: Input %zu has no derivation paths\n", i);
	                }
	            } else {
	                LogPrintf("TradeCeremonyRunner: Input %zu missing witness_utxo\n", i);
	            }

	            // Track foreign unsigned non-Taproot inputs. If this wallet cannot sign them,
	            // and they are not already finalized, the peer has not pre-signed their
	            // legacy/segwit funding, which would make adaptor ceremony pointless.
	            bool has_final =
	                !input.final_script_witness.IsNull() ||
	                !input.final_script_sig.empty();
	            if (!isTaproot && !canSign && !has_final) {
	                has_foreign_unsigned_non_taproot = true;
	                foreignDetails += QString("input%1;").arg(i);
	            }

	            if (canSign) {
	                spendableInputs++;
	                inputDetails += QString("input%1:can_sign=yes;").arg(i);
	            } else {
	                nonSpendableInputs++;
	                inputDetails += QString("input%1:can_sign=no;").arg(i);
	            }
	        }

	        QString roleTag = m_localRole.isEmpty() ? QStringLiteral("peer") : m_localRole.toLower();

	        if (spendableInputs == 0) {
	            // This is the critical check - we need at least one input we can sign
	            result.error = stageError(stageLabel,
	                QObject::tr("No wallet-controlled inputs eligible for adaptor preparation (%1)")
	                    .arg(inputDetails));
	            LogPrintf("TradeCeremonyRunner: [%s] ERROR - No signable inputs found (signable=%d, non-signable=%d): %s\n",
	                      roleTag.toStdString().c_str(), spendableInputs, nonSpendableInputs,
	                      inputDetails.toStdString().c_str());
	            return false;
	        }

	        if (has_foreign_unsigned_non_taproot) {
	            result.error = stageError(stageLabel,
	                QObject::tr("Peer PSBT contains unsigned non-Taproot funding inputs that this wallet cannot sign (%1)")
	                    .arg(foreignDetails));
	            LogPrintf("TradeCeremonyRunner: [%s] ERROR - Foreign unsigned non-Taproot inputs before adaptor.%s: %s\n",
	                      roleTag.toStdString().c_str(), stageLabel.toStdString().c_str(),
	                      foreignDetails.toStdString().c_str());
	            return false;
	        }

	        LogPrintf("TradeCeremonyRunner: [%s] Found %d signable input(s) before adaptor.%s (non-signable=%d)\n",
	                  roleTag.toStdString().c_str(), spendableInputs, stageLabel.toStdString().c_str(),
	                  nonSpendableInputs);
	        return true;
	    }

    void publishMergedPsbt(const QString& psbt)
    {
        if (m_phase0PsbtCallback && !psbt.isEmpty()) {
            m_phase0PsbtCallback(psbt);
        }
    }

    void logStage(const QString& stage)
    {
        QString roleTag = m_localRole.isEmpty() ? QStringLiteral("peer") : m_localRole.toLower();
        LogPrintf("TradeCeremonyRunner: [%s] %s\n", roleTag.toStdString().c_str(), stage.toStdString().c_str());
    }

    void notifyProgress(TradeBoardTab::CeremonyPhase phase, const QString& message)
    {
        if (m_progressCallback) {
            m_progressCallback(phase, message);
        }
    }

    QString stageError(const QString& stage, const QString& detail)
    {
        const QString roleTag = m_localRole.isEmpty() ? QStringLiteral("peer") : m_localRole.toLower();
        LogPrintf("TradeCeremonyRunner: [%s] STAGE FAILURE phase=%s stage='%s' detail='%s'\n",
                  roleTag.toStdString().c_str(),
                  m_currentPhase.toStdString().c_str(),
                  stage.toStdString().c_str(),
                  detail.toStdString().c_str());
        return QObject::tr("%1 failed: %2").arg(stage, detail);
    }

    bool isCancelled()
    {
        return m_cancelFlag && m_cancelFlag->load(std::memory_order_acquire);
    }

    bool walletOwnsAddress(const QString& address) const
    {
        if (!m_wallet || address.isEmpty()) {
            return false;
        }

        try {
            UniValue params(UniValue::VARR);
            params.push_back(address.toStdString());
            UniValue response = m_wallet->node().executeRpc(
                "getaddressinfo", params, m_wallet->getWalletName().toStdString());

            if (response.exists("ismine") && response["ismine"].isBool() && response["ismine"].get_bool()) {
                return true;
            }
            if (response.exists("iswatchonly") && response["iswatchonly"].isBool() && response["iswatchonly"].get_bool()) {
                return true;
            }
        } catch (const UniValue&) {
        } catch (const std::exception&) {
        } catch (...) {
        }
        return false;
    }

    bool sendEnvelope(const QString& type, const QString& psbtData, const QString& stage,
                      WalletModel::CosignAdaptorRoundtripResult& result)
    {
        if (isCancelled()) {
            result.cancelled = true;
            result.error = QObject::tr("Ceremony cancelled by user");
            return false;
        }

        QJsonObject payload;
        payload["type"] = type;
        payload["psbt"] = psbtData;
        QString payloadJson = QString::fromUtf8(QJsonDocument(payload).toJson(QJsonDocument::Compact));
        auto sendResult = m_wallet->cosignSend(m_sessionId, payloadJson);
        if (!sendResult.success) {
            result.error = stageError(stage, sendResult.error);
            return false;
        }
        return true;
    }

    // Best-effort: tell the peer the ceremony is dead so they don't sit on a
    // receivePsbt() timeout. Caller must have already populated result.error
    // (or set result.cancelled). The run() wrapper invokes this on every
    // non-session_lost failure path after runImpl() returns. The cooperative
    // maker broadcast-fail path sends its own pre-existing ceremony_abort
    // with the same wire shape; both peers' polling loops already accept this
    // envelope.
    void sendCeremonyAbort(const QString& reason, bool cancelled)
    {
        if (!m_wallet) return;
        const QString roleTag = m_localRole.isEmpty() ? QStringLiteral("peer") : m_localRole.toLower();
        QJsonObject obj;
        obj["type"] = QStringLiteral("ceremony_abort");
        obj["phase"] = m_currentPhase;
        obj["role"] = m_localRole;
        obj["reason"] = cancelled ? QStringLiteral("peer cancelled") : reason;
        const QString json = QString::fromUtf8(QJsonDocument(obj).toJson(QJsonDocument::Compact));
        try {
            auto sr = m_wallet->cosignSend(m_sessionId, json);
            LogPrintf("TradeCeremonyRunner: [%s] Sent ceremony_abort phase=%s reason='%s' send_ok=%d send_err='%s'\n",
                      roleTag.toStdString().c_str(),
                      m_currentPhase.toStdString().c_str(),
                      reason.toStdString().c_str(),
                      sr.success ? 1 : 0,
                      sr.error.toStdString().c_str());
        } catch (const std::exception& e) {
            LogPrintf("TradeCeremonyRunner: [%s] ceremony_abort send threw: %s\n",
                      roleTag.toStdString().c_str(), e.what());
        } catch (...) {
            LogPrintf("TradeCeremonyRunner: [%s] ceremony_abort send threw unknown exception\n",
                      roleTag.toStdString().c_str());
        }
    }

    QString receivePsbt(const QString& stage, WalletModel::CosignAdaptorRoundtripResult& result, const QString& expectedTypePrefix = QString(), int customMaxAttempts = 10)
    {
        // Check for staged peer PSBT first
        if (!m_pendingPeerBase.isEmpty()) {
            QString staged = m_pendingPeerBase;
            m_pendingPeerBase.clear();
            logStage(QObject::tr("Using staged peer PSBT for %1").arg(stage));
            return staged;
        }

        // Check message buffer for a matching message (fix for out-of-order message reception)
        if (!expectedTypePrefix.isEmpty()) {
            for (auto it = m_messageBuffer.begin(); it != m_messageBuffer.end(); ++it) {
                if (it.key().startsWith(expectedTypePrefix)) {
                    QString psbtData = it.value();
                    QString messageType = it.key();
                    m_messageBuffer.erase(it);
                    logStage(QObject::tr("Retrieved buffered %1 from peer (type=%2)").arg(stage, messageType));
                    return psbtData;
                }
            }
            // Log buffered messages for debugging
            if (!m_messageBuffer.isEmpty()) {
                QStringList bufferedTypes;
                for (auto it = m_messageBuffer.begin(); it != m_messageBuffer.end(); ++it) {
                    bufferedTypes << it.key();
                }
                logStage(QObject::tr("Waiting for %1 (buffered: %2)").arg(expectedTypePrefix, bufferedTypes.join(", ")));
            }
        }

        // Keep receive attempts bounded to maintain responsiveness
        // Default 10 attempts (5 seconds), but caller can specify longer timeout for user review stages
        const int maxAttempts = customMaxAttempts;
        int attempts = 0;
        QString lastError;

        while (true) {
            if (isCancelled()) {
                result.cancelled = true;
                result.error = QObject::tr("Ceremony cancelled by user");
                return {};
            }

            auto recvResult = m_wallet->cosignRecv(m_sessionId, 500);
            if (!recvResult.success) {
                lastError = recvResult.error;
                QString loweredError = recvResult.error.toLower();
                if (loweredError.contains("session not found") ||
                    loweredError.contains("unknown session") ||
                    loweredError.contains("session expired") ||
                    loweredError.contains("bridge restarted")) {
                    result.session_lost = true;
                    result.error = stageError(stage, recvResult.error);
                    return {};
                }
            } else if (!recvResult.payload_json.isEmpty()) {
                // Unwrap response envelope if present (matches pollSessionMessages pattern)
                QString unwrappedJson = recvResult.payload_json;
                QJsonParseError parseError;
                QJsonDocument doc = QJsonDocument::fromJson(recvResult.payload_json.toUtf8(), &parseError);
                if (!doc.isNull() && doc.isObject()) {
                    QJsonObject obj = doc.object();
                    if (obj.contains("timeout") && obj.value("timeout").toBool()) {
                        continue;
                    }
                    // Unwrap {"type":"response","echo":{...}} -> {...}
                    QString respType = obj.value("type").toString();
                    if (respType == "response" && obj.contains("echo") && obj.value("echo").isObject()) {
                        QJsonDocument unwrappedDoc(obj.value("echo").toObject());
                        unwrappedJson = QString::fromUtf8(unwrappedDoc.toJson(QJsonDocument::Compact));
                        logStage(QObject::tr("Unwrapped response envelope for %1").arg(stage));
                    }
                }

                QString messageType;
                QString extractError;
                QString psbtData = ::extractPsbtFromPayload(unwrappedJson, &messageType, &extractError);
                if (!psbtData.isEmpty()) {
                    // If we're expecting a specific message type, verify it matches
                    if (!expectedTypePrefix.isEmpty() && !messageType.startsWith(expectedTypePrefix)) {
                        // FIXED: Buffer the message instead of discarding it
                        m_messageBuffer[messageType] = psbtData;
                        logStage(QObject::tr("Buffering out-of-order message type=%1 (expecting %2)").arg(messageType, expectedTypePrefix));
                        continue;  // Continue polling for the expected message
                    }
                    logStage(QObject::tr("Received %1 from peer (type=%2)").arg(stage, messageType));
                    return psbtData;
                }
                // If extractError contains ceremony_error, that's the real error
                lastError = extractError.isEmpty() ? QObject::tr("payload missing PSBT") : extractError;
                result.error = stageError(stage, lastError);
                return {};
            }

            if (++attempts >= maxAttempts) {
                QString timeoutDetail = lastError.isEmpty()
                    ? QObject::tr("timeout waiting for peer")
                    : QObject::tr("timeout waiting for peer (%1)").arg(lastError);
                result.error = stageError(stage, timeoutDetail);
                return {};
            }
        }
    }

    // Drain buffered messages between phases to prevent stale messages from interfering
    void drainBufferedMessages(const QString& phasePrefix = QString())
    {
        if (m_messageBuffer.isEmpty()) {
            return;
        }

        QStringList drainedTypes;
        for (auto it = m_messageBuffer.begin(); it != m_messageBuffer.end(); ) {
            const QString& messageType = it.key();

            // If a phase prefix is specified, only drain messages NOT matching that prefix
            // (i.e., keep messages that might be needed for the next phase)
            if (!phasePrefix.isEmpty() && messageType.startsWith(phasePrefix)) {
                ++it;
                continue;
            }

            drainedTypes << messageType;
            it = m_messageBuffer.erase(it);
        }

        if (!drainedTypes.isEmpty()) {
            logStage(QObject::tr("Drained %1 buffered message(s) between phases: %2")
                .arg(drainedTypes.size())
                .arg(drainedTypes.join(", ")));
        }
    }

    bool runPhase0BaseExchange(QString& ceremonyPsbt, bool haveLocalBase, const QString& roleTag,
                               WalletModel::CosignAdaptorRoundtripResult& result)
    {
        m_currentPhase = QStringLiteral("phase_0_base_exchange");
        if (isCancelled()) {
            result.cancelled = true;
            result.error = QObject::tr("Ceremony cancelled by user");
            return false;
        }

        notifyProgress(TradeBoardTab::CeremonyPhase::PHASE0_BASE,
                       QObject::tr("Synchronizing base PSBT with peer"));
        logStage(QObject::tr("Phase 0 - synchronizing base PSBTs"));

        if (!haveLocalBase || ceremonyPsbt.isEmpty()) {
            result.error = m_isMaker
                ? QObject::tr("Maker base PSBT is missing")
                : QObject::tr("Cached augmented PSBT is missing");
            return false;
        }

        if (m_wallet) {
            auto annotate = m_wallet->walletProcessPsbt(ceremonyPsbt,
                                                        /*sign=*/false,
                                                        QStringLiteral("DEFAULT"),
                                                        /*bip32derivs=*/true,
                                                        /*finalize=*/false);
            if (annotate.success && !annotate.psbt.isEmpty()) {
                ceremonyPsbt = annotate.psbt;
            }
        }

        QString baseType = QStringLiteral("base_psbt_%1").arg(roleTag);

        if (m_isMaker) {
            if (!sendEnvelope(baseType, ceremonyPsbt, QObject::tr("PSBT send"), result)) {
                return false;
            }
            LogPrintf("TradeCeremonyRunner: [MAKER] Phase 0 - sent base PSBT (%d bytes)\n", ceremonyPsbt.length());

            // Extended timeout (120 attempts = 60 seconds) to allow taker time to review ICU commitment proofs
            QString peerPsbt = receivePsbt(QObject::tr("PSBT receive"), result, QStringLiteral("base_psbt_"), 120);
            if (peerPsbt.isEmpty()) {
                return false;
            }

            PartiallySignedTransaction localDecoded;
            QString localDecodeErr;
            if (!decodePsbt(ceremonyPsbt, localDecoded, &localDecodeErr)) {
                result.error = stageError(QObject::tr("PSBT decode"), localDecodeErr);
                return false;
            }
            // Keep a copy of the maker's local base PSBT for liveness verification
            QString localBasePsbt = ceremonyPsbt;

            PartiallySignedTransaction peerDecoded;
            QString peerDecodeErr;
            if (!decodePsbt(peerPsbt, peerDecoded, &peerDecodeErr)) {
                result.error = stageError(QObject::tr("PSBT decode"), peerDecodeErr);
                return false;
            }

            // Log transaction structure for debugging
            auto localTxid = localDecoded.tx->GetHash();
            auto peerTxid = peerDecoded.tx->GetHash();
            LogPrintf("TradeCeremonyRunner: [MAKER] Phase 0 - maker base: %d inputs, txid=%s\n",
                      localDecoded.tx->vin.size(), localTxid.ToString().c_str());
            LogPrintf("TradeCeremonyRunner: [MAKER] Phase 0 - taker augmented: %d inputs, txid=%s\n",
                      peerDecoded.tx->vin.size(), peerTxid.ToString().c_str());

            // CRITICAL: Verify taker's augmented PSBT contains ALL maker's base inputs
            // (txids will differ because taker adds inputs, but inputs must be preserved)
            QString missingInput;
            if (!verifyPsbtContainsAllInputs(localDecoded, peerDecoded, &missingInput)) {
                result.error = QObject::tr("PSBT immutability violation: taker's augmented PSBT is missing maker input %1").arg(missingInput);
                LogPrintf("TradeCeremonyRunner: [MAKER] Phase 0 FAILED - augmented PSBT missing maker input %s\n",
                          missingInput.toStdString().c_str());
                LogPrintf("TradeCeremonyRunner: [MAKER] Phase 0 FAILED - maker had %d inputs, taker has %d inputs\n",
                          localDecoded.tx->vin.size(), peerDecoded.tx->vin.size());
                return false;
            }
            LogPrintf("TradeCeremonyRunner: [MAKER] Phase 0 - ✓ verified taker's augmented PSBT contains all %d maker input(s)\n",
                      localDecoded.tx->vin.size());

            LogPrintf("TradeCeremonyRunner: [MAKER] Phase 0 - adopting taker's augmented PSBT (%d inputs, %d outputs)\n",
                      peerDecoded.tx->vin.size(), peerDecoded.tx->vout.size());

            // Merge maker metadata into taker's augmented PSBT by matching prevouts, not by index.
            // The taker may prepend/insert their own inputs which shifts indices; merging by index
            // corrupts input metadata and breaks wallet signing for non-adaptor inputs.
            PartiallySignedTransaction mergedDecoded = peerDecoded;

            // Build map: prevout -> index for the peer (augmented) PSBT
            std::map<COutPoint, size_t> peer_index_by_prevout;
            for (size_t j = 0; j < mergedDecoded.tx->vin.size(); ++j) {
                peer_index_by_prevout.emplace(mergedDecoded.tx->vin[j].prevout, j);
            }

            // Helper lambdas to union‑merge PSBT input fields without clobbering peer data
            auto merge_input = [](PSBTInput& dst, const PSBTInput& src) {
                // Preserve utxo fields; only add if missing on dst
                if (dst.witness_utxo.IsNull() && !src.witness_utxo.IsNull()) {
                    dst.witness_utxo = src.witness_utxo;
                }
                if (dst.non_witness_utxo == nullptr && src.non_witness_utxo != nullptr) {
                    dst.non_witness_utxo = src.non_witness_utxo;
                }

                // Taproot internal key
                if (dst.m_tap_internal_key.IsNull() && !src.m_tap_internal_key.IsNull()) {
                    dst.m_tap_internal_key = src.m_tap_internal_key;
                }

                // BIP32 keypaths (legacy) – union
                for (const auto& [pk, origin] : src.hd_keypaths) {
                    dst.hd_keypaths.emplace(pk, origin);
                }
                // Taproot BIP32 paths – union
                for (const auto& [xonly, path] : src.m_tap_bip32_paths) {
                    dst.m_tap_bip32_paths.emplace(xonly, path);
                }

                // Sighash type – keep existing, set if missing
                if (!src.sighash_type.has_value()) {
                    // nothing
                } else if (!dst.sighash_type.has_value()) {
                    dst.sighash_type = src.sighash_type;
                }

                // Proprietary fields – union (noop for Phase 0 but safe)
                for (const auto& prop : src.m_proprietary) {
                    dst.m_proprietary.insert(prop);
                }
            };

            // Merge inputs by prevout match
            for (size_t i = 0; i < localDecoded.tx->vin.size(); ++i) {
                const COutPoint& prev = localDecoded.tx->vin[i].prevout;
                auto it = peer_index_by_prevout.find(prev);
                if (it == peer_index_by_prevout.end()) continue; // peer may have dropped; already validated above
                const size_t j = it->second;
                if (j >= mergedDecoded.inputs.size() || i >= localDecoded.inputs.size()) continue;
                merge_input(mergedDecoded.inputs[j], localDecoded.inputs[i]);
            }

            // Outputs: preserve indices (peer may have rebalanced/change outputs). Only merge simple metadata.
            const size_t localOutputCount = localDecoded.outputs.size();
            for (size_t i = 0; i < std::min(localOutputCount, mergedDecoded.outputs.size()); ++i) {
                PSBTOutput& dst = mergedDecoded.outputs[i];
                const PSBTOutput& src = localDecoded.outputs[i];
                // Taproot internal key (rare on outputs), keypaths, and proprietary – union where applicable
                for (const auto& [pk, origin] : src.hd_keypaths) {
                    dst.hd_keypaths.emplace(pk, origin);
                }
                for (const auto& [xonly, path] : src.m_tap_bip32_paths) {
                    dst.m_tap_bip32_paths.emplace(xonly, path);
                }
                for (const auto& prop : src.m_proprietary) {
                    dst.m_proprietary.insert(prop);
                }
            }

            ceremonyPsbt = encodePsbt(mergedDecoded);
            if (m_wallet) {
                auto annotate = m_wallet->walletProcessPsbt(ceremonyPsbt,
                                                               /*sign=*/false,
                                                               QStringLiteral("DEFAULT"),
                                                               /*bip32derivs=*/true,
                                                               /*finalize=*/false);
                if (annotate.success && !annotate.psbt.isEmpty()) {
                    ceremonyPsbt = annotate.psbt;
                }
                // Merge local metadata (keypaths) into the adopted PSBT without altering txid
                auto mergedMeta = m_wallet->combinePsbt(QStringList{ceremonyPsbt, localBasePsbt});
                if (mergedMeta.success && !mergedMeta.psbt.isEmpty()) {
                    ceremonyPsbt = mergedMeta.psbt;
                }
            }

            // Liveness: verify spendability against the maker's local base inputs, not the adopted PSBT
            if (!ensureWalletControlsInputs(localBasePsbt, result, QObject::tr("maker base verify"))) {
                return false;
            }

            if (!m_peerAugmentedHash.isEmpty()) {
                QString mergedHash = ComputePsbtTxHash(ceremonyPsbt);
                if (mergedHash.compare(m_peerAugmentedHash, Qt::CaseInsensitive) != 0) {
                    result.error = QObject::tr("PSBT immutability violation: merged PSBT hash differs from taker's locked hash");
                    LogPrintf("TradeCeremonyRunner: [MAKER] Phase 0 FAILED - hash mismatch (expected %s, got %s)\n",
                              m_peerAugmentedHash.toStdString().c_str(),
                              mergedHash.toStdString().c_str());
                    return false;
                }
                LogPrintf("TradeCeremonyRunner: [MAKER] Phase 0 - merged PSBT hash verified (%s)\n",
                          mergedHash.toStdString().c_str());
            }
        } else {
            // TAKER BRANCH: Receive maker's base PSBT and verify our augmented PSBT contains it
            // Extended timeout (120 attempts = 60 seconds) to allow maker time to review ICU commitment proofs
            QString peerPsbt = receivePsbt(QObject::tr("PSBT receive"), result, QStringLiteral("base_psbt_"), 120);
            if (peerPsbt.isEmpty()) {
                return false;
            }

            // If we cached the expected maker base PSBT, verify it matches exactly
            if (!m_expectedPeerPsbt.isEmpty() && peerPsbt != m_expectedPeerPsbt) {
                result.error = QObject::tr("PSBT immutability violation: maker's PSBT differs from cached base");
                LogPrintf("TradeCeremonyRunner: [TAKER] Phase 0 FAILED - maker base mismatch (expected %d bytes, got %d bytes)\n",
                          m_expectedPeerPsbt.length(), peerPsbt.length());
                return false;
            }

            // Decode maker's base PSBT
            PartiallySignedTransaction makerBaseDecoded;
            QString makerDecodeErr;
            if (!decodePsbt(peerPsbt, makerBaseDecoded, &makerDecodeErr)) {
                result.error = stageError(QObject::tr("PSBT decode"), makerDecodeErr);
                return false;
            }

            // Decode taker's augmented PSBT
            PartiallySignedTransaction takerAugmentedDecoded;
            QString takerDecodeErr;
            if (!decodePsbt(ceremonyPsbt, takerAugmentedDecoded, &takerDecodeErr)) {
                result.error = stageError(QObject::tr("PSBT decode"), takerDecodeErr);
                return false;
            }

            auto makerTxid = makerBaseDecoded.tx->GetHash();
            auto takerTxid = takerAugmentedDecoded.tx->GetHash();
            LogPrintf("TradeCeremonyRunner: [TAKER] Phase 0 - maker base: %d inputs, txid=%s\n",
                      makerBaseDecoded.tx->vin.size(), makerTxid.ToString().c_str());
            LogPrintf("TradeCeremonyRunner: [TAKER] Phase 0 - taker augmented: %d inputs, txid=%s\n",
                      takerAugmentedDecoded.tx->vin.size(), takerTxid.ToString().c_str());

            // CRITICAL: Verify our augmented PSBT contains ALL maker's base inputs
            QString missingInput;
            if (!verifyPsbtContainsAllInputs(makerBaseDecoded, takerAugmentedDecoded, &missingInput)) {
                result.error = QObject::tr("PSBT construction error: augmented PSBT is missing maker input %1").arg(missingInput);
                LogPrintf("TradeCeremonyRunner: [TAKER] Phase 0 FAILED - augmented PSBT missing maker input %s\n",
                          missingInput.toStdString().c_str());
                LogPrintf("TradeCeremonyRunner: [TAKER] Phase 0 FAILED - maker had %d inputs, taker has %d inputs\n",
                          makerBaseDecoded.tx->vin.size(), takerAugmentedDecoded.tx->vin.size());
                return false;
            }
            LogPrintf("TradeCeremonyRunner: [TAKER] Phase 0 - ✓ verified augmented PSBT contains all %d maker input(s)\n",
                      makerBaseDecoded.tx->vin.size());

            if (!sendEnvelope(baseType, ceremonyPsbt, QObject::tr("PSBT send"), result)) {
                return false;
            }
            LogPrintf("TradeCeremonyRunner: [TAKER] Phase 0 - sent augmented PSBT (%d bytes, %d inputs)\n",
                      ceremonyPsbt.length(), takerAugmentedDecoded.tx->vin.size());
        }

        publishMergedPsbt(ceremonyPsbt);
        logStage(QObject::tr("✓ Phase 0 complete - base PSBTs synchronized"));
        return true;
    }

    bool runPhase1Attestation(WalletModel::CosignAdaptorRoundtripResult& result)
    {
        m_currentPhase = QStringLiteral("phase_1_attestation");
        if (isCancelled()) {
            result.cancelled = true;
            result.error = QObject::tr("Ceremony cancelled by user");
            return false;
        }

        notifyProgress(TradeBoardTab::CeremonyPhase::PHASE1_ATTEST, QObject::tr("Performing BIP-322 attestation"));
        logStage(QObject::tr("Phase 1 - BIP-322 peer attestation"));

        // Get address for this role (implementation will query from offer/request)
        QString localAddress = getAddressForRole();
        LogPrintf("TradeCeremonyRunner: Phase 1 - role=%s, selected_address=%s, borrower=%s, lender=%s, owns=%d\n",
                  m_localRole.toStdString().c_str(),
                  localAddress.toStdString().c_str(),
                  m_borrowerAddress.toStdString().c_str(),
                  m_lenderAddress.toStdString().c_str(),
                  walletOwnsAddress(localAddress));
        if (localAddress.isEmpty()) {
            result.error = QObject::tr("Cannot determine address for BIP-322 attestation");
            return false;
        }

        // Step 1: Request challenge
        auto attestStep1 = m_wallet->cosignAttest(m_sessionId, localAddress);
        if (!attestStep1.success) {
            result.error = stageError(QObject::tr("attestation challenge"), attestStep1.error);
            return false;
        }

        logStage(QObject::tr("Received BIP-322 challenge"));

        // Step 2: Sign challenge using signmessagebip322 RPC
        try {
            // Ensure wallet is unlocked before signing the BIP-322 challenge
            WalletModel::UnlockContext ctx(m_wallet->requestUnlock());
            if (!ctx.isValid()) {
                result.error = QObject::tr("Wallet unlock required to sign BIP-322 challenge");
                return false;
            }

            UniValue signParams(UniValue::VARR);
            signParams.push_back(localAddress.toStdString());
            signParams.push_back(attestStep1.challenge.toStdString());

            UniValue signResult = m_wallet->node().executeRpc("signmessagebip322", signParams,
                                                              m_wallet->getWalletName().toStdString());

            if (!signResult.isStr()) {
                result.error = QObject::tr("Failed to sign BIP-322 challenge");
                return false;
            }

            QString signature = QString::fromStdString(signResult.get_str());
            logStage(QObject::tr("Signed BIP-322 challenge"));

            // Step 3: Submit signature for verification
            auto attestStep2 = m_wallet->cosignAttest(m_sessionId, localAddress, signature);
            if (!attestStep2.success || !attestStep2.verified) {
                result.error = stageError(QObject::tr("attestation verification"),
                                        attestStep2.error.isEmpty() ? QObject::tr("verification failed") : attestStep2.error);
                return false;
            }

            logStage(QObject::tr("✓ Phase 1 complete - Peer identity attested via BIP-322"));
            return true;

        } catch (const UniValue& e) {
            result.error = QObject::tr("BIP-322 signing failed: UniValue exception");
            return false;
        } catch (const std::exception& e) {
            result.error = QObject::tr("BIP-322 signing failed: %1").arg(QString::fromStdString(e.what()));
            return false;
        }
    }

    QString getAddressForRole()
    {
        // BIP-322 attestation uses MY role's contract address (feature_fairsign_adaptor.py:1636-1661)
        // If I'm the borrower → use borrower_address (my address)
        // If I'm the lender → use lender_address (my address)
        QString roleLower = m_localRole.toLower();

        QStringList preferred;

        if (roleLower == "borrower" || roleLower == "long") {
            if (!m_borrowerAddress.isEmpty()) preferred << m_borrowerAddress;
        } else if (roleLower == "lender" || roleLower == "short") {
            if (!m_lenderAddress.isEmpty()) preferred << m_lenderAddress;
        }

        // Add the opposite role as fallback (handles mislabelled data)
        if (!m_borrowerAddress.isEmpty() && !preferred.contains(m_borrowerAddress)) {
            preferred << m_borrowerAddress;
        }
        if (!m_lenderAddress.isEmpty() && !preferred.contains(m_lenderAddress)) {
            preferred << m_lenderAddress;
        }

        for (const QString& candidate : preferred) {
            if (walletOwnsAddress(candidate)) {
                LogPrintf("TradeCeremonyRunner: Using wallet-owned address %s for role %s\n",
                          candidate.toStdString().c_str(), roleLower.toStdString().c_str());
                return candidate;
            }
        }

        if (!preferred.isEmpty()) {
            LogPrintf("TradeCeremonyRunner: WARNING - no wallet-owned address available for role '%s'. Using %s\n",
                      roleLower.toStdString().c_str(), preferred.first().toStdString().c_str());
            return preferred.first();
        }

        LogPrintf("TradeCeremonyRunner: Warning - unknown role '%s' for BIP-322 attestation\n",
                  roleLower.toStdString().c_str());
        return QString();
    }

    bool runPhase2NonceExchange(QString& ceremonyPsbt, const QString& roleTag,
                                WalletModel::CosignAdaptorRoundtripResult& result)
    {
        m_currentPhase = QStringLiteral("phase_2_nonce");
        if (isCancelled()) {
            result.cancelled = true;
            result.error = QObject::tr("Ceremony cancelled by user");
            return false;
        }

        // Both parties MUST prepare nonces on the SAME transaction (the augmented/merged PSBT)
        // This matches the functional test where both use the same opening_psbt
        QString psbtToPrepare = ceremonyPsbt;

        if (m_isMaker) {
            LogPrintf("TradeCeremonyRunner: [MAKER] Phase 2 - preparing nonces on augmented PSBT (%d bytes)\n",
                      psbtToPrepare.length());
        } else {
            LogPrintf("TradeCeremonyRunner: [TAKER] Phase 2 - preparing nonces on augmented PSBT (%d bytes)\n",
                      psbtToPrepare.length());
        }

        if (!ensureWalletControlsInputs(psbtToPrepare, result, QObject::tr("prepare"))) {
            return false;
        }

        notifyProgress(TradeBoardTab::CeremonyPhase::PHASE2_NONCE, QObject::tr("Exchanging nonce commitments"));
        logStage(QObject::tr("Phase 2 - preparing nonces"));

        auto prepareResult = m_wallet->adaptorPrepare(psbtToPrepare);
        if (!prepareResult.success) {
            result.error = stageError(QObject::tr("prepare"), prepareResult.error);
            return false;
        }

        QString nonceType = QStringLiteral("nonce_psbt_%1").arg(roleTag);
        if (!sendEnvelope(nonceType, prepareResult.psbt, QObject::tr("nonce send"), result)) {
            return false;
        }

        QString peerNoncePsbt = receivePsbt(QObject::tr("nonce receive"), result, QStringLiteral("nonce_psbt_"));
        if (peerNoncePsbt.isEmpty()) {
            return false;
        }

        auto mergedNonces = m_wallet->combinePsbt(QStringList{prepareResult.psbt, peerNoncePsbt});
        if (!mergedNonces.success) {
            result.error = stageError(QObject::tr("merge nonces"), mergedNonces.error);
            return false;
        }

        ceremonyPsbt = mergedNonces.psbt;
        logStage(QObject::tr("✓ Phase 2 complete - Nonces merged"));
        return true;
    }

    bool runPhase3PartialExchange(QString& ceremonyPsbt, const QString& roleTag,
                                  WalletModel::CosignAdaptorRoundtripResult& result)
    {
        m_currentPhase = QStringLiteral("phase_3_partial");
        if (isCancelled()) {
            result.cancelled = true;
            result.error = QObject::tr("Ceremony cancelled by user");
            return false;
        }

        notifyProgress(TradeBoardTab::CeremonyPhase::PHASE3_PARTIAL, QObject::tr("Exchanging partial signatures"));
        logStage(QObject::tr("Phase 3 - creating partial signatures"));

        auto partialResult = m_wallet->adaptorPartial(ceremonyPsbt);
        if (!partialResult.success) {
            result.error = stageError(QObject::tr("partial"), partialResult.error);
            return false;
        }

        QString partialType = QStringLiteral("partial_psbt_%1").arg(roleTag);
        if (!sendEnvelope(partialType, partialResult.psbt, QObject::tr("partial send"), result)) {
            return false;
        }

        QString peerPartialPsbt = receivePsbt(QObject::tr("partial receive"), result, QStringLiteral("partial_psbt_"));
        if (peerPartialPsbt.isEmpty()) {
            return false;
        }

        auto mergedPartials = m_wallet->combinePsbt(QStringList{partialResult.psbt, peerPartialPsbt});
        if (!mergedPartials.success) {
            result.error = stageError(QObject::tr("merge partials"), mergedPartials.error);
            return false;
        }

        ceremonyPsbt = mergedPartials.psbt;
        logStage(QObject::tr("✓ Phase 3 complete - Partial signatures merged"));
        return true;
    }

    // ------------------------------------------------------------------
    // Cooperative non-atomic signing path (asymmetric)
    //
    // Taker signs FIRST and sends the signed PSBT to the maker. Maker
    // verifies, signs SECOND, finalises, broadcasts, then sends
    // ceremony_complete (with txid) to the taker. The taker cannot open
    // the contract without the maker's signature; the maker only signs
    // after inspecting the taker's signed PSBT — so the maker is the
    // last signer and broadcaster and is no worse off than in the atomic
    // path (modulo the loss of cryptographic atomicity guarantees on
    // the taker's collateral, which the taker explicitly accepted via
    // the "Pre-sign and Continue" dialog and the maker explicitly
    // accepted via the downgrade modal).
    // ------------------------------------------------------------------

    // Helper: wait for the maker's ceremony_complete envelope (or a
    // ceremony_abort / ceremony_error envelope, which propagates as an
    // error). Returns the broadcast txid on success, empty on error/abort.
    QString receiveCeremonyComplete(const QString& stage,
                                    WalletModel::CosignAdaptorRoundtripResult& result,
                                    int maxAttempts)
    {
        int attempts = 0;
        while (true) {
            if (isCancelled()) {
                result.cancelled = true;
                result.error = QObject::tr("Ceremony cancelled by user");
                return {};
            }

            auto recvResult = m_wallet->cosignRecv(m_sessionId, 500);
            if (!recvResult.success) {
                const QString errorLower = recvResult.error.toLower();
                // Transport-level failures all map to "session lost" so the
                // caller can tear down cleanly. Includes the explicit bridge
                // error strings plus websocket / connection / relay closures
                // that a peer's cosign.close (or a dropped link) produces.
                if (errorLower.contains("session not found") ||
                    errorLower.contains("unknown session") ||
                    errorLower.contains("session expired") ||
                    errorLower.contains("bridge restarted") ||
                    errorLower.contains("websocket") ||
                    errorLower.contains("connection closed") ||
                    errorLower.contains("connection reset") ||
                    errorLower.contains("transport closed") ||
                    errorLower.contains("relay closed") ||
                    errorLower.contains("not connected")) {
                    result.session_lost = true;
                    result.error = stageError(stage, recvResult.error);
                    return {};
                }
            } else if (!recvResult.payload_json.isEmpty()) {
                QJsonParseError parseError;
                QJsonDocument doc = QJsonDocument::fromJson(recvResult.payload_json.toUtf8(), &parseError);
                if (!doc.isNull() && doc.isObject()) {
                    QJsonObject obj = doc.object();
                    if (obj.value("timeout").toBool()) {
                        // bridge poll empty; just keep waiting
                    } else {
                        if (obj.value("type").toString() == "response" && obj.value("echo").isObject()) {
                            obj = obj.value("echo").toObject();
                        }
                        const QString type = obj.value("type").toString();
                        if (type == "ceremony_complete") {
                            const QString txid = obj.value("txid").toString();
                            if (txid.isEmpty()) {
                                result.error = stageError(stage,
                                    QObject::tr("ceremony_complete missing txid"));
                                return {};
                            }
                            return txid;
                        }
                        if (type == "ceremony_abort") {
                            const QString reason = obj.value("reason").toString();
                            const QString detail = obj.value("error").toString();
                            result.error = stageError(stage,
                                QObject::tr("Counterparty aborted: %1")
                                    .arg(detail.isEmpty() ? reason : detail));
                            return {};
                        }
                        if (type == "ceremony_error") {
                            const QString error = obj.value("error").toString();
                            result.error = stageError(stage,
                                error.isEmpty() ? QObject::tr("peer reported ceremony_error") : error);
                            return {};
                        }
                        // Other envelopes (e.g. stale signed_psbt_*) are ignored.
                    }
                }
            }

            if (++attempts >= maxAttempts) {
                result.error = stageError(stage, QObject::tr("timeout waiting for broadcast confirmation"));
                return {};
            }
        }
    }

    // Validate the PSBT we're about to enter the cooperative path with.
    // Conservative: any uncertainty (decode failure, unknown input types,
    // ANYONECANPAY) aborts here rather than risk an unsafe downgrade.
    bool validateCooperativePreconditions(const QString& ceremonyPsbt,
                                          WalletModel::CosignAdaptorRoundtripResult& result)
    {
        m_currentPhase = QStringLiteral("cooperative_preflight");
        const auto classification = ClassifyPsbtInputs(ceremonyPsbt);
        if (!classification.decode_succeeded) {
            result.error = stageError(QObject::tr("cooperative preflight"),
                QObject::tr("Failed to decode PSBT for input classification"));
            return false;
        }
        if (classification.unknown_inputs > 0) {
            result.error = stageError(QObject::tr("cooperative preflight"),
                QObject::tr("PSBT has %1 inputs of unknown type; refusing cooperative signing")
                    .arg(classification.unknown_inputs));
            return false;
        }
        if (classification.non_taproot_inputs == 0) {
            // Pure-Taproot PSBTs should use the atomic adaptor path, not
            // cooperative. If we got here, the peer requested cooperative on
            // a PSBT that doesn't need it — refuse rather than silently
            // accepting a downgrade.
            result.error = stageError(QObject::tr("cooperative preflight"),
                QObject::tr("PSBT has no non-Taproot inputs; cooperative signing not applicable"));
            return false;
        }
        // Mixed Taproot+non-Taproot is supported: walletprocesspsbt(sign=true,
        // SIGHASH=ALL) signs Taproot key-path and legacy inputs in one pass,
        // and PsbtSignedInputIndices counts both. The whole transaction signs
        // with SIGHASH_ALL — there is no "partially atomic, partially not"
        // hybrid. The taker has opted into giving up the Taproot atomicity
        // guarantee on those inputs via the preflight dialog, and the maker
        // has accepted via the downgrade modal.
        if (PsbtHasAnyonecanpay(m_wallet, ceremonyPsbt)) {
            result.error = stageError(QObject::tr("cooperative preflight"),
                QObject::tr("PSBT contains ANYONECANPAY sighash; refusing to sign"));
            return false;
        }
        // Stricter than the ANYONECANPAY check: the cooperative path normalises
        // every input to SIGHASH_ALL before signing, so any pre-set sighash
        // other than DEFAULT/ALL/unset would either be silently overwritten
        // (NONE / SINGLE — both commitment-weakening, must not silently
        // upgrade) or break the normalisation contract. Refuse before we
        // touch the PSBT.
        const QString unsafeSighash = PsbtCooperativeUnsafeSighash(m_wallet, ceremonyPsbt);
        if (!unsafeSighash.isEmpty()) {
            result.error = stageError(QObject::tr("cooperative preflight"),
                QObject::tr("PSBT has unsupported sighash for cooperative signing (%1); only DEFAULT/ALL/unset are accepted")
                    .arg(unsafeSighash));
            return false;
        }
        return true;
    }

    // Taker side of cooperative signing. Signs local inputs with SIGHASH_ALL,
    // verifies signatures were actually added, sends to maker, waits for the
    // maker's ceremony_complete (txid) envelope.
    bool runCooperativeSignTaker(QString& ceremonyPsbt, const QString& roleTag,
                                 WalletModel::CosignAdaptorRoundtripResult& result)
    {
        m_currentPhase = QStringLiteral("cooperative_taker_sign");
        if (isCancelled()) {
            result.cancelled = true;
            result.error = QObject::tr("Ceremony cancelled by user");
            return false;
        }

        notifyProgress(TradeBoardTab::CeremonyPhase::PHASE2_NONCE,
                       QObject::tr("Cooperative signing (non-atomic) - signing your inputs"));
        logStage(QObject::tr("Cooperative signing (taker) - signing local inputs with SIGHASH_ALL"));

        // Normalise every input's stored sighash_type to SIGHASH_ALL before
        // signing. bcore's walletprocesspsbt RPC rejects any mismatch
        // between the global override ("ALL" below) and a per-input stored
        // value — typically DEFAULT on Taproot inputs vs ALL on legacy —
        // with -22 "Specified sighash value does not match value stored in
        // PSBT". The validateCooperativePreconditions() check above has
        // already proved every input's pre-set sighash is in {unset,
        // DEFAULT, ALL}, so this normalisation is semantics-preserving.
        {
            QString normErr;
            QString normalised = normalizeCooperativeSighashAll(ceremonyPsbt, &normErr);
            if (normalised.isEmpty()) {
                result.error = stageError(QObject::tr("cooperative taker sign"),
                    QObject::tr("sighash normalisation failed: %1").arg(normErr));
                return false;
            }
            ceremonyPsbt = normalised;
        }

        const QSet<int> signedBefore = PsbtSignedInputIndices(m_wallet, ceremonyPsbt);

        // SIGHASH_ALL forces signatures to commit to every input and output —
        // no ANYONECANPAY, no in-flight transaction modification after we
        // hand the signed PSBT to the maker.
        auto signResult = m_wallet->walletProcessPsbt(
            ceremonyPsbt,
            /*sign=*/true,
            QStringLiteral("ALL"),
            /*bip32derivs=*/true,
            /*finalize=*/false);
        if (!signResult.success || signResult.psbt.isEmpty()) {
            result.error = stageError(QObject::tr("cooperative taker sign"),
                signResult.error.isEmpty() ? QObject::tr("walletprocesspsbt returned no PSBT") : signResult.error);
            return false;
        }

        // RPC success ≠ signatures added. Verify progress before sending.
        const QSet<int> signedAfter = PsbtSignedInputIndices(m_wallet, signResult.psbt);
        QSet<int> newlySigned = signedAfter;
        newlySigned.subtract(signedBefore);
        if (newlySigned.isEmpty()) {
            result.error = stageError(QObject::tr("cooperative taker sign"),
                QObject::tr("walletprocesspsbt returned without adding any signatures "
                            "(wallet locked, missing keys, or no inputs owned)"));
            return false;
        }
        logStage(QObject::tr("Signed %1 local input(s)").arg(newlySigned.size()));

        // Defence in depth: refuse to emit a PSBT that has ANYONECANPAY anywhere.
        if (PsbtHasAnyonecanpay(m_wallet, signResult.psbt)) {
            result.error = stageError(QObject::tr("cooperative taker sign"),
                QObject::tr("Refusing to send PSBT containing ANYONECANPAY sighash"));
            return false;
        }

        const QString signedType = QStringLiteral("signed_psbt_%1").arg(roleTag);
        if (!sendEnvelope(signedType, signResult.psbt,
                          QObject::tr("cooperative taker send"), result)) {
            return false;
        }
        logStage(QObject::tr("Sent signed PSBT to maker; waiting for maker to broadcast"));

        notifyProgress(TradeBoardTab::CeremonyPhase::PHASE4_COMPLETE,
                       QObject::tr("Waiting for maker to finalise and broadcast"));

        // Generous timeout — finalize+broadcast can be slow under mempool
        // congestion, and the maker may need to type their passphrase.
        // 600 attempts × 500ms = 5 minutes.
        const QString txid = receiveCeremonyComplete(
            QObject::tr("cooperative taker wait"), result, /*maxAttempts=*/600);
        if (txid.isEmpty()) {
            return false;  // error / abort already populated in result
        }
        logStage(QObject::tr("✓ Maker broadcast transaction: %1").arg(txid));

        // Taker doesn't broadcast; the maker's broadcast is the source of truth.
        // Record the txid so the taker post-ceremony handler can surface it in
        // the success dialog ("transaction X has been broadcast"). already_broadcast
        // stays false on the taker side — the broadcast was the maker's; we just
        // confirmed it landed via ceremony_complete.
        result.psbt = signResult.psbt;
        result.complete = true;
        result.txid = txid;
        ceremonyPsbt = signResult.psbt;
        return true;
    }

    // Maker side of cooperative signing. Receives taker's signed PSBT, verifies,
    // signs maker's inputs LAST, finalises, broadcasts, then notifies the taker.
    bool runCooperativeSignMaker(QString& ceremonyPsbt, const QString& roleTag,
                                 WalletModel::CosignAdaptorRoundtripResult& result)
    {
        m_currentPhase = QStringLiteral("cooperative_maker_sign");
        if (isCancelled()) {
            result.cancelled = true;
            result.error = QObject::tr("Ceremony cancelled by user");
            return false;
        }

        notifyProgress(TradeBoardTab::CeremonyPhase::PHASE2_NONCE,
                       QObject::tr("Cooperative signing (non-atomic) - waiting for counterparty's signed PSBT"));
        logStage(QObject::tr("Cooperative signing (maker) - waiting for taker's signed PSBT"));

        drainBufferedMessages(QStringLiteral("signed_psbt_"));

        // Normalise the local copy's sighashes to SIGHASH_ALL before combine
        // and sign. Symmetric with the taker side — both sides apply the
        // same deterministic transform on their own copy of the augmented
        // PSBT, so the resulting combinePsbt(local, taker_signed) merges
        // two consistently-normalised views. validateCooperativePreconditions
        // already proved each input's pre-set sighash is in {unset,
        // DEFAULT, ALL}, so the override is semantics-preserving.
        {
            QString normErr;
            QString normalised = normalizeCooperativeSighashAll(ceremonyPsbt, &normErr);
            if (normalised.isEmpty()) {
                result.error = stageError(QObject::tr("cooperative maker sign"),
                    QObject::tr("sighash normalisation failed: %1").arg(normErr));
                return false;
            }
            ceremonyPsbt = normalised;
        }

        // Snapshot before-state for signature-progress verification on receipt.
        const QSet<int> signedBefore = PsbtSignedInputIndices(m_wallet, ceremonyPsbt);

        // 240 × 500ms = 2 minutes for taker to sign (covers wallet-unlock prompts).
        const QString takerSignedPsbt = receivePsbt(
            QObject::tr("cooperative maker receive"), result,
            QStringLiteral("signed_psbt_"), /*customMaxAttempts=*/240);
        if (takerSignedPsbt.isEmpty()) {
            return false;
        }
        logStage(QObject::tr("Received taker's signed PSBT"));

        // Verify taker actually added signatures — RPC ack alone is not enough.
        const QSet<int> takerSigned = PsbtSignedInputIndices(m_wallet, takerSignedPsbt);
        QSet<int> takerProgress = takerSigned;
        takerProgress.subtract(signedBefore);
        if (takerProgress.isEmpty()) {
            result.error = stageError(QObject::tr("cooperative maker verify"),
                QObject::tr("Taker's PSBT shows no new signatures; refusing to proceed"));
            return false;
        }
        logStage(QObject::tr("Verified %1 taker input(s) have signatures").arg(takerProgress.size()));

        // Reject if taker tried to slip in ANYONECANPAY.
        if (PsbtHasAnyonecanpay(m_wallet, takerSignedPsbt)) {
            result.error = stageError(QObject::tr("cooperative maker verify"),
                QObject::tr("Taker's PSBT contains ANYONECANPAY sighash; refusing"));
            return false;
        }

        // Apply the same strict sighash policy to the taker's signed PSBT as
        // validateCooperativePreconditions() applied to our local copy:
        // refuse anything outside {unset, DEFAULT, ALL}. A well-behaved
        // taker has normalised to ALL in runCooperativeSignTaker before
        // signing, so this check should be a no-op for legitimate flows.
        // It exists to catch a malicious or buggy peer who flips an input
        // to NONE or SINGLE between our local-side validation and the
        // taker's signing — without this gate, combinePsbt would happily
        // merge a weaker sighash in and we'd lose the all-inputs-committed
        // invariant on whatever the taker rewrote.
        const QString takerUnsafeSighash =
            PsbtCooperativeUnsafeSighash(m_wallet, takerSignedPsbt);
        if (!takerUnsafeSighash.isEmpty()) {
            result.error = stageError(QObject::tr("cooperative maker verify"),
                QObject::tr("Taker's PSBT has unsupported sighash for cooperative signing (%1); refusing")
                    .arg(takerUnsafeSighash));
            return false;
        }

        // Combine: our (unsigned) view + taker-signed view → both sides' signatures.
        auto merged = m_wallet->combinePsbt(QStringList{ceremonyPsbt, takerSignedPsbt});
        if (!merged.success || merged.psbt.isEmpty()) {
            result.error = stageError(QObject::tr("cooperative maker combine"),
                merged.error.isEmpty() ? QObject::tr("combinepsbt failed") : merged.error);
            return false;
        }
        QString combinedPsbt = merged.psbt;

        notifyProgress(TradeBoardTab::CeremonyPhase::PHASE4_COMPLETE,
                       QObject::tr("Cooperative signing (non-atomic) - signing your inputs"));
        logStage(QObject::tr("Cooperative signing (maker) - signing local inputs with SIGHASH_ALL"));

        const QSet<int> beforeMakerSign = PsbtSignedInputIndices(m_wallet, combinedPsbt);
        auto signResult = m_wallet->walletProcessPsbt(
            combinedPsbt,
            /*sign=*/true,
            QStringLiteral("ALL"),
            /*bip32derivs=*/true,
            /*finalize=*/false);
        if (!signResult.success || signResult.psbt.isEmpty()) {
            result.error = stageError(QObject::tr("cooperative maker sign"),
                signResult.error.isEmpty() ? QObject::tr("walletprocesspsbt returned no PSBT") : signResult.error);
            return false;
        }
        const QSet<int> afterMakerSign = PsbtSignedInputIndices(m_wallet, signResult.psbt);
        QSet<int> makerProgress = afterMakerSign;
        makerProgress.subtract(beforeMakerSign);
        if (makerProgress.isEmpty()) {
            result.error = stageError(QObject::tr("cooperative maker sign"),
                QObject::tr("walletprocesspsbt returned without adding any maker signatures"));
            return false;
        }
        logStage(QObject::tr("Signed %1 maker input(s)").arg(makerProgress.size()));

        if (PsbtHasAnyonecanpay(m_wallet, signResult.psbt)) {
            result.error = stageError(QObject::tr("cooperative maker sign"),
                QObject::tr("Refusing to broadcast PSBT containing ANYONECANPAY"));
            return false;
        }

        notifyProgress(TradeBoardTab::CeremonyPhase::PHASE4_COMPLETE,
                       QObject::tr("Broadcasting"));
        logStage(QObject::tr("Finalising and broadcasting"));

        auto broadcast = m_wallet->broadcastPsbt(signResult.psbt);
        if (!broadcast.success) {
            // Notify the taker we're aborting so they don't sit on a wait.
            QJsonObject abort;
            abort["type"] = "ceremony_abort";
            abort["reason"] = "broadcast_failed";
            abort["error"] = broadcast.error;
            const QString abortJson = QString::fromUtf8(QJsonDocument(abort).toJson(QJsonDocument::Compact));
            (void)m_wallet->cosignSend(m_sessionId, abortJson);

            result.error = stageError(QObject::tr("cooperative maker broadcast"),
                broadcast.error.isEmpty() ? QObject::tr("broadcast failed") : broadcast.error);
            return false;
        }
        logStage(QObject::tr("✓ Broadcast complete: txid=%1").arg(broadcast.txid));

        // Tell the taker so they can stop waiting. Best-effort: broadcast
        // already succeeded; if the notify fails the trade is still on-chain.
        QJsonObject complete;
        complete["type"] = "ceremony_complete";
        complete["txid"] = broadcast.txid;
        const QString completeJson = QString::fromUtf8(QJsonDocument(complete).toJson(QJsonDocument::Compact));
        auto sendRes = m_wallet->cosignSend(m_sessionId, completeJson);
        if (!sendRes.success) {
            LogPrintf("TradeCeremonyRunner: Warning - ceremony_complete send failed (txid=%s): %s\n",
                      broadcast.txid.toStdString().c_str(),
                      sendRes.error.toStdString().c_str());
        }

        result.psbt = signResult.psbt;
        result.complete = true;
        // Tell the post-ceremony handler not to broadcast again. The cooperative
        // path has already submitted the transaction; without this short-circuit
        // the standard handler would re-sign + broadcastPsbt → second broadcast
        // fails with "transaction already in mempool" and surfaces a misleading
        // failure dialog over a successful trade.
        result.already_broadcast = true;
        result.txid = broadcast.txid;
        ceremonyPsbt = signResult.psbt;
        return true;
    }

    bool runPhase4Complete(const QString& ceremonyPsbt,
                          WalletModel::CosignAdaptorRoundtripResult& result)
    {
        m_currentPhase = QStringLiteral("phase_4_complete");
        if (isCancelled()) {
            result.cancelled = true;
            result.error = QObject::tr("Ceremony cancelled by user");
            return false;
        }

        notifyProgress(TradeBoardTab::CeremonyPhase::PHASE4_COMPLETE, QObject::tr("Finalizing ceremony"));
        logStage(QObject::tr("Phase 4 - completing ceremony"));

        auto completeResult = m_wallet->adaptorComplete(ceremonyPsbt);
        if (!completeResult.success) {
            result.error = stageError(QObject::tr("complete"), completeResult.error);
            return false;
        }

        // IMPORTANT: In a two-party ceremony, adaptor.complete only completes OUR signatures
        // We need to merge the result with the peer's signatures to get a fully signed PSBT
        // The ceremonyPsbt from Phase 3 already has both parties' partial signatures merged

        QString finalPsbt = completeResult.psbt;

        // Exchange completed PSBTs if we're the maker (who broadcasts)
        if (m_isMaker) {
            // Send our completed PSBT to the taker
            QString completeType = QStringLiteral("complete_psbt_%1").arg(m_localRole == "lender" ? "lender" : "borrower");
            if (!sendEnvelope(completeType, finalPsbt, QObject::tr("complete send"), result)) {
                return false;
            }

            // Receive the taker's completed PSBT
            QString peerCompletePsbt = receivePsbt(QObject::tr("complete receive"), result, QStringLiteral("complete_psbt_"));
            if (peerCompletePsbt.isEmpty()) {
                return false;
            }

            // Combine both completed PSBTs
            auto mergedComplete = m_wallet->combinePsbt(QStringList{finalPsbt, peerCompletePsbt});
            if (!mergedComplete.success) {
                result.error = stageError(QObject::tr("merge complete"), mergedComplete.error);
                return false;
            }
            finalPsbt = mergedComplete.psbt;
            logStage(QObject::tr("✓ Merged both parties' completed signatures"));
        } else {
            // Taker: send our completed PSBT to the maker for broadcast
            QString completeType = QStringLiteral("complete_psbt_%1").arg(m_localRole == "lender" ? "lender" : "borrower");
            if (!sendEnvelope(completeType, finalPsbt, QObject::tr("complete send"), result)) {
                return false;
            }
            // Taker doesn't broadcast, just mark success
        }

        // Maker: sign any remaining wallet-owned inputs (fee/change) not covered by adaptor signatures
        // This mirrors repowallet flow where walletprocesspsbt(sign=true) is called prior to finalize/broadcast.
        {
            // Let the wallet wrapper choose a compatible sighash per the PSBT
            // (uses DEFAULT for uniform Taproot, otherwise per-input or default ALL).
            auto signedRes = m_wallet->walletProcessPsbt(
                finalPsbt,
                /*sign=*/true,
                QString(),
                /*bip32derivs=*/true,
                /*finalize=*/false);
            if (signedRes.success && !signedRes.psbt.isEmpty()) {
                finalPsbt = signedRes.psbt;
                logStage(QObject::tr("Signed remaining wallet inputs"));
            }
        }

        result.complete = completeResult.complete;
        result.psbt = finalPsbt;

        if (result.psbt.isEmpty()) {
            result.success = false;
            result.error = stageError(QObject::tr("complete"), QObject::tr("RPC returned empty PSBT"));
            return false;
        }

        logStage(QObject::tr("✓ Phase 4 complete"));
        return true;
    }
};

void TradeBoardTab::sendCeremonyError(const QString& session_id,
                                      const QString& stage,
                                      const QString& detail) const
{
    if (!walletModel) return;

    QJsonObject obj;
    obj["type"] = QStringLiteral("ceremony_error");
    obj["stage"] = stage;
    obj["error"] = detail;

    QString json = QString::fromUtf8(QJsonDocument(obj).toJson(QJsonDocument::Compact));
    WalletModel::CosignSendResult sendResult = walletModel->cosignSend(session_id, json);
    if (!sendResult.success) {
        LogPrintf("TradeBoardTab: Failed to send ceremony error on session %s: %s\n",
                  session_id.toStdString().c_str(),
                  sendResult.error.toStdString().c_str());
    } else {
        LogPrintf("TradeBoardTab: Sent ceremony error on session %s (stage=%s, detail=%s)\n",
                  session_id.toStdString().c_str(),
                  stage.toStdString().c_str(),
                  detail.toStdString().c_str());
    }
}

void TradeBoardTab::launchOpeningCeremony(const QString& offer_id, const QString& session_id, const QString& maker_role)
{
    if (!walletModel) return;

    // Prevent duplicate ceremony launch - ceremony already running for this session
    if (ceremonySessions.contains(session_id)) {
        LogPrintf("TradeBoardTab: Skipping maker ceremony launch - already running for session %s\n",
                  session_id.toStdString().c_str());
        return;
    }

    // If a session poll is in flight for this session, its next frame has already
    // been (or is about to be) consumed off-thread. Defer the launch until the
    // poll continuation releases the claim and applies that frame, so we neither
    // strand the frame nor race the runner onto a half-read stream.
    if (m_sessionsBeingPolled.contains(session_id)) {
        LogPrintf("TradeBoardTab: Deferring maker ceremony launch for session %s (poll in flight)\n",
                  session_id.toStdString().c_str());
        m_deferredCeremonyStarts.append({/*isMaker=*/true, offer_id, session_id, /*request_id=*/QString(), maker_role});
        return;
    }

    // CRITICAL: Insert session IMMEDIATELY to close TOCTOU race window
    // Must happen before any long-running validation/setup code
    ceremonySessions.insert(session_id);
    LogPrintf("TradeBoardTab: Maker ceremony session %s locked\n", session_id.toStdString().c_str());

    LogPrintf("TradeBoardTab: Launching opening ceremony for offer %s, session %s\n",
              offer_id.toStdString().c_str(), session_id.toStdString().c_str());

    // Get finalized contract ID from request info (bulletin board offer_id is UUID, need 32-byte hex contract ID)
    const QString requestId = activeSessions.value(session_id);
    QString contractId = offer_id;  // fallback
    QString localBasePsbt;
    QString stagedPeerBase;
    QString peerPsbtHash;
    bool cooperativeConsent = false;  // Captured into the QtConcurrent lambda below.

    TradeRequestInfo* infoPtr = activeRequests.contains(requestId) ? &activeRequests[requestId] : nullptr;
    if (infoPtr) {
        cooperativeConsent = infoPtr->cooperative_consent;
        if (!infoPtr->final_offer_id.isEmpty()) {
            contractId = infoPtr->final_offer_id;
            LogPrintf("TradeBoardTab: Using finalized contract ID: %s\n", contractId.toStdString().c_str());
        }
        if (!infoPtr->maker_base_psbt.isEmpty()) {
            localBasePsbt = infoPtr->maker_base_psbt;
            LogPrintf("TradeBoardTab: Maker using cached base PSBT for ceremony (%d bytes)\n",
                      localBasePsbt.length());
        }
        if (!infoPtr->augmented_psbt.isEmpty()) {
            stagedPeerBase = infoPtr->augmented_psbt;
            peerPsbtHash = infoPtr->augmented_psbt_hash;
            LogPrintf("TradeBoardTab: Maker staged taker augmented PSBT (%d bytes, hash=%s)\n",
                      stagedPeerBase.length(), peerPsbtHash.toStdString().c_str());
        } else if (infoPtr->staged_peer_base_ready && !infoPtr->staged_peer_base_psbt.isEmpty()) {
            stagedPeerBase = infoPtr->staged_peer_base_psbt;
            LogPrintf("TradeBoardTab: Maker loaded staged taker base PSBT for session %s\n",
                      session_id.toStdString().c_str());
        } else if (!infoPtr->merged_ceremony_psbt.isEmpty()) {
            stagedPeerBase = infoPtr->merged_ceremony_psbt;
            peerPsbtHash = infoPtr->merged_ceremony_psbt_hash;
            LogPrintf("TradeBoardTab: Maker using cached merged ceremony PSBT (%d bytes)\n",
                      stagedPeerBase.length());
        }
    }

    if (localBasePsbt.isEmpty()) {
        QMessageBox::critical(this, tr("Ceremony Not Ready"),
            tr("Maker's base PSBT is missing. Cannot start ceremony."));
        ceremonySessions.remove(session_id);  // Cleanup on early return
        return;
    }

    if (stagedPeerBase.isEmpty()) {
        QMessageBox::critical(this, tr("Ceremony Not Ready"),
            tr("Taker's augmented PSBT is missing. Wait for the taker to send ceremony_ready again."));
        ceremonySessions.remove(session_id);  // Cleanup on early return
        return;
    }

    const QString roleLower = maker_role.toLower();
    LogPrintf("TradeBoardTab: Maker role for ceremony: %s\n", roleLower.toStdString().c_str());

    // Detect contract type (forward vs repo vs spot) using canonical cache
    QString contractType;
    bool isForward = false;
    bool isSpot = false;
    if (infoPtr) {
        QString contractId = infoPtr->final_offer_id.isEmpty() ? infoPtr->offer_id : infoPtr->final_offer_id;
        contractType = getCanonicalContractType(contractId);
        if (contractType.isEmpty()) {
            contractType = infoPtr->offer_summary.value("contract_type").toString().toLower();
            LogPrintf("TradeBoardTab: WARNING - No cached contract type for %s, using offer_summary fallback\n",
                      contractId.toStdString().c_str());
        }
        isForward = (contractType == "forward" || contractType == "option");
        isSpot = (contractType == "spot");

        // For spot contracts, check if ICU commitment proofs are required and, if so,
        // prompt the maker to add their commitment before starting the ceremony.
        if (isSpot) {
            bool requireCommitment = false;
            WalletModel::ContractStatusResult status = walletModel->getContractStatus(contractId);
            if (status.success && status.offer.contains("terms")) {
                const QVariant termsVar = status.offer.value("terms");
                if (termsVar.canConvert<QVariantMap>()) {
                    QVariantMap termsMap = termsVar.toMap();
                    if (termsMap.contains("require_commitment_proof")) {
                        requireCommitment = termsMap.value("require_commitment_proof").toBool();
                    }
                }
            }

            if (requireCommitment) {
                LogPrintf("TradeBoardTab: Spot contract %s requires ICU commitment proof (maker path)\n",
                          contractId.toStdString().c_str());

                CommitmentProofDialog dlg(walletModel, contractId, stagedPeerBase, this);
                if (dlg.exec() != QDialog::Accepted || !dlg.commitmentAdded()) {
                    LogPrintf("TradeBoardTab: Maker cancelled ICU commitment proof dialog for spot contract %s, aborting ceremony\n",
                              contractId.toStdString().c_str());
                    return;
                }

                stagedPeerBase = dlg.getPsbtWithCommitment();
            }
        }
    }

    // Extract party addresses based on contract type
    // NOTE: TradeCeremonyRunner uses borrowerAddress/lenderAddress parameter names,
    // but for forwards we map: long→borrower slot, short→lender slot
    QString borrowerAddress;  // For repo: borrower, For forward: long party
    QString lenderAddress;    // For repo: lender, For forward: short party

    if (infoPtr) {
        if (isSpot) {
            // SPOT: Extract alice/bob addresses for BIP-322 attestation
            // Map: alice→borrower slot, bob→lender slot (ceremony infrastructure naming)
            if (!infoPtr->final_offer_json.isEmpty()) {
                QJsonDocument offerDoc = QJsonDocument::fromJson(infoPtr->final_offer_json.toUtf8());
                if (offerDoc.isObject()) {
                    QJsonObject offerObj = offerDoc.object();
                    borrowerAddress = offerObj.value("alice_address").toString();   // Alice → borrower slot
                    lenderAddress = offerObj.value("bob_address").toString();        // Bob → lender slot
                }
            }
            LogPrintf("TradeBoardTab: Maker ceremony addresses (SPOT) - alice=%s, bob=%s, maker_role=%s\n",
                      borrowerAddress.toStdString().c_str(), lenderAddress.toStdString().c_str(), roleLower.toStdString().c_str());
        } else if (isForward) {
            // FORWARD: Use long/short addresses
            borrowerAddress = infoPtr->long_margin_dest;   // Maps to "borrower" slot for ceremony runner
            lenderAddress = infoPtr->short_margin_dest;    // Maps to "lender" slot for ceremony runner
            LogPrintf("TradeBoardTab: Maker ceremony addresses (FORWARD) - long=%s, short=%s, maker_role=%s\n",
                      borrowerAddress.toStdString().c_str(), lenderAddress.toStdString().c_str(), roleLower.toStdString().c_str());
        } else {
            // REPO: Use borrower/lender addresses
            borrowerAddress = infoPtr->borrower_address;
            lenderAddress = infoPtr->lender_address;
            LogPrintf("TradeBoardTab: Maker ceremony addresses (REPO) - borrower=%s, lender=%s, maker_role=%s\n",
                      borrowerAddress.toStdString().c_str(), lenderAddress.toStdString().c_str(), roleLower.toStdString().c_str());
        }
    }

    // Fallback: Extract addresses from finalized offer if missing
    if (requestId.isEmpty() == false && activeRequests.contains(requestId)) {
        const TradeRequestInfo& reqInfo = activeRequests[requestId];
        if (!reqInfo.final_offer_json.isEmpty() && (borrowerAddress.isEmpty() || lenderAddress.isEmpty())) {
            QJsonParseError parseErr;
            QJsonDocument offerDoc = QJsonDocument::fromJson(reqInfo.final_offer_json.toUtf8(), &parseErr);
            if (!offerDoc.isNull() && offerDoc.isObject()) {
                QJsonObject offerObj = offerDoc.object();

                if (isForward) {
                    // FORWARD: Extract from terms.long_party/short_party.margin_dest
                    if (offerObj.contains("terms") && offerObj["terms"].isObject()) {
                        QJsonObject terms = offerObj["terms"].toObject();
                        if (borrowerAddress.isEmpty() && terms.contains("long_party") && terms["long_party"].isObject()) {
                            borrowerAddress = terms["long_party"].toObject().value("margin_dest").toString();
                            LogPrintf("TradeBoardTab: Extracted long_margin_dest from final offer: %s\n",
                                      borrowerAddress.toStdString().c_str());
                        }
                        if (lenderAddress.isEmpty() && terms.contains("short_party") && terms["short_party"].isObject()) {
                            lenderAddress = terms["short_party"].toObject().value("margin_dest").toString();
                            LogPrintf("TradeBoardTab: Extracted short_margin_dest from final offer: %s\n",
                                      lenderAddress.toStdString().c_str());
                        }
                    }
                } else {
                    // REPO: Extract from borrower_address/lender_address
                    if (borrowerAddress.isEmpty() && offerObj.contains("borrower_address")) {
                        borrowerAddress = offerObj.value("borrower_address").toString();
                        LogPrintf("TradeBoardTab: Extracted borrower_address from final offer: %s\n",
                                  borrowerAddress.toStdString().c_str());
                    }
                    if (lenderAddress.isEmpty() && offerObj.contains("lender_address")) {
                        lenderAddress = offerObj.value("lender_address").toString();
                        LogPrintf("TradeBoardTab: Extracted lender_address from final offer: %s\n",
                                  lenderAddress.toStdString().c_str());
                    }
                }
            }
        }
    }

    // Last resort: Generate fresh address if still missing
    if (isSpot) {
        // SPOT: Generate based on alice/bob role (mapped to borrower/lender slots)
        if (roleLower == "alice" && borrowerAddress.isEmpty()) {
            borrowerAddress = walletModel->getNewAddress("ceremony_attest", "bech32m");
            LogPrintf("TradeBoardTab: Generated alice address for spot BIP-322: %s\n",
                      borrowerAddress.toStdString().c_str());
        } else if (roleLower == "bob" && lenderAddress.isEmpty()) {
            lenderAddress = walletModel->getNewAddress("ceremony_attest", "bech32m");
            LogPrintf("TradeBoardTab: Generated bob address for spot BIP-322: %s\n",
                      lenderAddress.toStdString().c_str());
        }
    } else if (isForward) {
        // FORWARD: Generate based on long/short role
        if (roleLower == "long" && borrowerAddress.isEmpty()) {
            borrowerAddress = walletModel->getNewAddress("ceremony_attest", "bech32m");
            LogPrintf("TradeBoardTab: Generated long margin address for maker BIP-322: %s\n",
                      borrowerAddress.toStdString().c_str());
        } else if (roleLower == "short" && lenderAddress.isEmpty()) {
            lenderAddress = walletModel->getNewAddress("ceremony_attest", "bech32m");
            LogPrintf("TradeBoardTab: Generated short margin address for maker BIP-322: %s\n",
                      lenderAddress.toStdString().c_str());
        }
    } else {
        // REPO: Generate based on borrower/lender role
        if (roleLower == "borrower" && borrowerAddress.isEmpty()) {
            borrowerAddress = walletModel->getNewAddress("ceremony_attest", "bech32m");
            LogPrintf("TradeBoardTab: Generated borrower address for maker BIP-322: %s\n",
                      borrowerAddress.toStdString().c_str());
        } else if (roleLower == "lender" && lenderAddress.isEmpty()) {
            lenderAddress = walletModel->getNewAddress("ceremony_attest", "bech32m");
            LogPrintf("TradeBoardTab: Generated lender address for maker BIP-322: %s\n",
                      lenderAddress.toStdString().c_str());
        }
    }

    auto cancelFlag = std::make_shared<std::atomic_bool>(false);

    // Create progress dialog for ceremony
    QWidget* dialog_parent = window() ? window() : this;
    QProgressDialog* progress = new QProgressDialog(dialog_parent);
    progress->setWindowTitle(tr("Opening Ceremony"));
    progress->setLabelText(tr("Executing fully automated adaptor ceremony...\n\n"
                              "• Exchanging base PSBTs\n"
                              "• BIP-322 peer attestation\n"
                              "• Exchanging nonce commitments\n"
                              "• Exchanging partial signatures\n"
                              "• Finalizing transaction\n\n"
                              "This may take 1-2 minutes. Please wait."));
    progress->setRange(0, 0); // Indeterminate

    // Guard UI lifetimes BEFORE connecting signals
    QPointer<QProgressDialog> progressPtr(progress);

    QPushButton* cancelButton = new QPushButton(tr("Cancel Ceremony"), progress);
    progress->setCancelButton(cancelButton);
    QObject::connect(cancelButton, &QPushButton::clicked, this, [this, cancelFlag, progressPtr, session_id]() {
        if (!cancelFlag->exchange(true, std::memory_order_acq_rel)) {
            if (progressPtr) {
                progressPtr->setLabelText(tr("Cancelling ceremony..."));
            }
            LogPrintf("TradeBoardTab: Maker requested ceremony cancellation for session %s\n",
                      session_id.toStdString().c_str());
        }
    });
    QObject::connect(progress, &QProgressDialog::canceled, this, [cancelFlag, progressPtr]() {
        if (!cancelFlag->exchange(true, std::memory_order_acq_rel)) {
            if (progressPtr) {
                progressPtr->setLabelText(tr("Cancelling ceremony..."));
            }
        }
    });

    progress->setWindowModality(Qt::WindowModal);
    progress->setMinimumDuration(0);
    progress->show();
    // REMOVED QApplication::processEvents() - causes re-entrancy and crashes

    // Step 2: Run adaptor ceremony ASYNCHRONOUSLY
    // Maker is the initiator in this flow
    // (Session already inserted at function entry to prevent TOCTOU race)
    // Create watcher without a QObject parent to avoid double-destruction paths
    // when the parent QWidget is torn down while a deleteLater() is already queued.
    auto* watcher = new QFutureWatcher<WalletModel::CosignAdaptorRoundtripResult>(nullptr);

    // Guard UI and watcher lifetimes
    QPointer<TradeBoardTab> self(this);
    QPointer<QFutureWatcher<WalletModel::CosignAdaptorRoundtripResult>> watcherPtr(watcher);

    // Run ceremony using TradeCeremonyRunner (immutability pattern - both sides have same augmented PSBT)
    auto mergedPsbtCallback = [this, requestId](const QString& mergedPsbt) {
        if (mergedPsbt.isEmpty() || requestId.isEmpty()) {
            return;
        }
        QMetaObject::invokeMethod(this, [this, requestId, mergedPsbt]() {
            if (!activeRequests.contains(requestId)) {
                return;
            }
            TradeRequestInfo& info = activeRequests[requestId];
            info.merged_ceremony_psbt = mergedPsbt;
            info.merged_ceremony_psbt_hash = ComputePsbtTxHash(mergedPsbt);
            LogPrintf("TradeBoardTab: Cached merged ceremony PSBT (%d bytes) for request %s\n",
                      mergedPsbt.length(), requestId.toStdString().c_str());
        }, Qt::QueuedConnection);
    };

    auto inflightGuard = std::make_shared<InflightGuard>(this);
    QFuture<WalletModel::CosignAdaptorRoundtripResult> future = QtConcurrent::run(
        [this, inflightGuard, contractId, session_id, localBasePsbt, stagedPeerBase, peerPsbtHash, roleLower, cancelFlag, borrowerAddress, lenderAddress, progress, mergedPsbtCallback, cooperativeConsent]() {
            (void)inflightGuard;
            auto progressCallback = [progress](CeremonyPhase phase, const QString& message) {
                QMetaObject::invokeMethod(progress, [progress, phase, message]() {
                    QString phaseText;
                    switch (phase) {
                        case CeremonyPhase::PHASE0_BASE:
                            phaseText = QObject::tr("Phase 0/4: Synchronizing base PSBT");
                            break;
                        case CeremonyPhase::PHASE1_ATTEST:
                            phaseText = QObject::tr("Phase 1/4: BIP-322 peer attestation");
                            break;
                        case CeremonyPhase::PHASE2_NONCE:
                            phaseText = QObject::tr("Phase 2/4: Exchanging nonce commitments");
                            break;
                        case CeremonyPhase::PHASE3_PARTIAL:
                            phaseText = QObject::tr("Phase 3/4: Exchanging partial signatures");
                            break;
                        case CeremonyPhase::PHASE4_COMPLETE:
                            phaseText = QObject::tr("Phase 4/4: Finalizing transaction");
                            break;
                        default:
                            phaseText = message;
                            break;
                    }
                    progress->setLabelText(phaseText + "\n\n" + message);
                }, Qt::QueuedConnection);
            };
            TradeCeremonyRunner runner(walletModel, contractId, session_id, localBasePsbt, roleLower, true,
                                       stagedPeerBase, peerPsbtHash, QString(), borrowerAddress, lenderAddress, cancelFlag,
                                       progressCallback, mergedPsbtCallback, cooperativeConsent);
            return runner.run();
        }
    );
    watcher->setFuture(future);

    // Close progress when work finishes, but don't delete watcher yet
    QObject::connect(watcher, &QFutureWatcher<WalletModel::CosignAdaptorRoundtripResult>::finished, progress, &QProgressDialog::close);

    connect(watcher, &QFutureWatcher<WalletModel::CosignAdaptorRoundtripResult>::finished, this,
            [self, watcherPtr, progressPtr, offer_id, session_id, cancelFlag]() {
        if (!self) return;  // parent destroyed

        // Progress already closed via direct connection above
        if (progressPtr) {
            progressPtr->deleteLater();
        }

        WalletModel::CosignAdaptorRoundtripResult ceremonyResult;
        if (watcherPtr) {
            ceremonyResult = watcherPtr->result();
        } else {
            ceremonyResult.success = false;
            ceremonyResult.error = QObject::tr("Internal watcher disposed");
        }

        self->ceremonySessions.remove(session_id);

        const QString requestId = self->activeSessions.value(session_id);
        if (!requestId.isEmpty() && self->activeRequests.contains(requestId)) {
            TradeRequestInfo& infoRef = self->activeRequests[requestId];
            infoRef.recovering_session = false;
            infoRef.taker_ready_for_ceremony = false;
            infoRef.waiting_for_base_notice_sent = false;
            infoRef.ceremony_ready_sent = false;
        }

        if (!ceremonyResult.success) {
            // Common failure cleanup, runs for cancel / abort / timeout / any
            // other non-success exit. Previously only the cancel branch
            // unlocked the PSBT and removed from activeSessions, and only the
            // session_lost/timeout heuristic triggered handleSessionLoss —
            // a clean ceremony_abort from the peer would leave the PSBT
            // locked and the bridge session open ("session remains active
            // for manual recovery"), so the user's UTXOs stayed unusable
            // and the next attempt collided with the stale session.
            if (!requestId.isEmpty() && self->activeRequests.contains(requestId)) {
                TradeRequestInfo& infoRef = self->activeRequests[requestId];
                if (infoRef.psbt_locked) {
                    const char* ctxStr = ceremonyResult.cancelled ? "cancellation" : "failure";
                    LogPrintf("TradeBoardTab: Maker unlocking PSBT for request %s after ceremony %s\n",
                              requestId.toStdString().c_str(), ctxStr);
                    if (!infoRef.augmented_psbt.isEmpty()) {
                        UnlockFairSignUTXOsForPsbt(self->walletModel, infoRef.augmented_psbt,
                                                   ceremonyResult.cancelled
                                                       ? "Maker ceremony cancellation"
                                                       : "Maker ceremony failure");
                    }
                    infoRef.psbt_locked = false;
                    infoRef.augmented_psbt.clear();
                    infoRef.augmented_psbt_hash.clear();
                }
            }
            if (self->walletModel) {
                self->walletModel->cosignClose(session_id);  // best-effort
            }
            self->activeSessions.remove(session_id);
            if (self->sessionManager) {
                self->sessionManager->removeSession(session_id);
            }

            if (ceremonyResult.cancelled) {
                self->showAutoClosingInfo(self->tr("Ceremony Cancelled"),
                    self->tr("Opening ceremony was cancelled. You can restart it from the Trade Board when ready."));
            } else {
                QMessageBox::critical(self, self->tr("Ceremony Failed"),
                    self->tr("Adaptor ceremony failed:\n\n%1\n\n"
                       "The session has been closed.").arg(ceremonyResult.error));

                // session_lost-specific recovery (registry rollback, retry
                // tracking). The string heuristic stays for legacy transport
                // errors that don't set session_lost; ceremony_abort now
                // surfaces as a clean error string and does NOT match these
                // patterns, which is correct — a peer abort is not a session
                // loss, the session just ended cleanly with the peer.
                const QString lower = ceremonyResult.error.toLower();
                if (ceremonyResult.session_lost ||
                    lower.contains("session not found") ||
                    lower.contains("unknown session") ||
                    lower.contains("session expired") ||
                    lower.contains("bridge restarted")) {
                    if (!requestId.isEmpty()) {
                        self->handleSessionLoss(session_id, requestId, ceremonyResult.error);
                    }
                }
            }

            self->updateOffersList();
            self->updateTradeRequestsList();
            if (watcherPtr) {
                watcherPtr->deleteLater();
            }
            return;
        }

        QString finalized_psbt = ceremonyResult.psbt;
        if (finalized_psbt.isEmpty() && !ceremonyResult.already_broadcast) {
            QMessageBox::critical(self, self->tr("Ceremony Result Missing"),
                self->tr("Adaptor ceremony reported success but did not return a PSBT.\n\n"
                   "Please check bridge logs and try again."));
            self->updateOffersList();
            self->updateTradeRequestsList();
            // Clean up watcher
            if (watcherPtr) {
                watcherPtr->deleteLater();
            }
            return;
        }

        // DIFFICULTY: when the counterparty already broadcast and told us the txid via ceremony_complete
        // (taker, or the cooperative-maker path), persist the funded vault outpoints. record_open is
        // idempotent and locates vaults by their committed scripts; the atomic-maker path records below
        // from its own broadcast txid. The GUI/Active Contracts state model depends on this.
        if (self->walletModel && !ceremonyResult.txid.isEmpty() && !requestId.isEmpty()
            && self->activeRequests.contains(requestId)) {
            const QString cid = self->activeRequests[requestId].final_offer_id;
            if (!cid.isEmpty() && self->getCanonicalContractType(cid) == QLatin1String("difficulty")) {
                auto ro = self->walletModel->difficultyRecordOpen(cid, ceremonyResult.txid);
                if (!ro.success) {
                    LogPrintf("TradeBoardTab: difficulty.record_open (peer txid) failed: %s\n", ro.error.toStdString().c_str());
                }
            }
        }

        // Short-circuit for the cooperative non-atomic signing path: the maker's
        // TradeCeremonyRunner already finalised, broadcast, and notified the taker
        // via ceremony_complete inside runCooperativeSignMaker. Re-running the
        // sign + broadcast block below would attempt a second broadcast and fail
        // with "transaction already in mempool", masking a successful trade as a
        // broadcast failure. Apply the same success cleanup the normal path does
        // (FairSign UTXO unlock, PSBT clear, activeSessions remove, balanceChanged
        // emit) so we don't leak session state or wallet locks.
        if (ceremonyResult.already_broadcast) {
            LogPrintf("TradeBoardTab: Cooperative ceremony already broadcast (txid=%s); skipping post-ceremony sign/broadcast\n",
                      ceremonyResult.txid.toStdString().c_str());

            const QString requestId = self->activeSessions.value(session_id);
            if (!requestId.isEmpty() && self->activeRequests.contains(requestId)) {
                TradeRequestInfo& infoRef = self->activeRequests[requestId];
                if (infoRef.psbt_locked) {
                    LogPrintf("TradeBoardTab: Unlocking PSBT for request %s after cooperative broadcast\n",
                              requestId.toStdString().c_str());
                    // Wallet-level Fair-Sign UTXO unlock must happen BEFORE we
                    // clear augmented_psbt, otherwise the helper has nothing to
                    // walk inputs against.
                    if (!infoRef.augmented_psbt.isEmpty()) {
                        UnlockFairSignUTXOsForPsbt(self->walletModel, infoRef.augmented_psbt,
                                                   "Maker cooperative ceremony success");
                    }
                    infoRef.psbt_locked = false;
                    infoRef.augmented_psbt.clear();
                    infoRef.augmented_psbt_hash.clear();
                }
            }

            self->activeSessions.remove(session_id);

            self->showAutoClosingInfo(self->tr("Contract Opened"),
                self->tr("✓ Contract opened (cooperative non-atomic signing)\n\n"
                   "Transaction ID: %1\n\n"
                   "The contract will automatically appear in Active Contracts "
                   "once confirmed on the blockchain.")
                .arg(ceremonyResult.txid));

            self->updateOffersList();
            self->updateTradeRequestsList();
            if (self->walletModel) {
                Q_EMIT self->walletModel->balanceChanged(self->walletModel->wallet().getBalances());
            }
            if (watcherPtr) {
                watcherPtr->deleteLater();
            }
            return;
        }

        LogPrintf("TradeBoardTab: Adaptor ceremony completed, signing non-adaptor inputs\n");

        // CRITICAL: Sign all non-adaptor inputs before broadcast
        // The ceremony only signs adaptor inputs (vault funding), but non-adaptor inputs
        // (change, fees, etc.) from FundTransaction still need regular wallet signatures
        {
            // Use wrapper auto-detection (empty sighash) to avoid mismatches with per-input values
            auto processResult = self->walletModel->walletProcessPsbt(finalized_psbt, /*sign=*/true, QString(), /*bip32derivs=*/true, /*finalize=*/false);
            if (!processResult.success) {
                QMessageBox::critical(self, self->tr("Signing Failed"),
                    self->tr("Failed to sign non-adaptor inputs:\n\n%1\n\n"
                       "The ceremony completed but wallet signing failed.").arg(processResult.error));
                self->updateOffersList();
                self->updateTradeRequestsList();
                // Clean up watcher
                if (watcherPtr) {
                    watcherPtr->deleteLater();
                }
                return;
            }

	            // Policy guard: ensure no input requests ANYONECANPAY after signing
	            QVariantMap decoded = self->walletModel->decodePsbt(processResult.psbt);
	            if (decoded.contains("inputs") && decoded["inputs"].canConvert<QVariantList>()) {
	                const auto inputs = decoded["inputs"].toList();
	                for (int i = 0; i < inputs.size(); ++i) {
	                    const QVariant& v = inputs[i];
	                    if (!v.canConvert<QVariantMap>()) continue;
	                    const QVariantMap m = v.toMap();
	                    const QString sighash = m.value("sighash").toString();
	                    if (!sighash.isEmpty() && sighash.contains("ANYONECANPAY", Qt::CaseInsensitive)) {
	                        LogPrintf("TradeBoardTab: ANYONECANPAY detected in PSBT input %d after signing, aborting broadcast\n", i);
	                        QMessageBox::critical(self, self->tr("Signing Failed"),
	                                              self->tr("Refusing to broadcast: sighash ANYONECANPAY detected in PSBT inputs (input %1).")
	                                                  .arg(i));
                        self->updateOffersList();
                        self->updateTradeRequestsList();
                        if (watcherPtr) watcherPtr->deleteLater();
                        return;
                    }
                }
            }

            LogPrintf("TradeBoardTab: walletProcessPsbt returned success=%d, complete=%d\n",
                      processResult.success, processResult.complete);
            LogPrintf("TradeBoardTab: Non-adaptor inputs signed, broadcasting\n");

            // Step 3: Broadcast the opening transaction
            auto broadcastResult = self->walletModel->broadcastPsbt(processResult.psbt);
            if (!broadcastResult.success) {
                // UNLOCK COINS: Clear the locked PSBT after broadcast failure
                const QString requestId = self->activeSessions.value(session_id);
                if (!requestId.isEmpty() && self->activeRequests.contains(requestId)) {
                    TradeRequestInfo& infoRef = self->activeRequests[requestId];
                if (infoRef.psbt_locked) {
                    LogPrintf("TradeBoardTab: Unlocking PSBT for request %s after broadcast failure\n",
                              requestId.toStdString().c_str());
                    infoRef.psbt_locked = false;
                    infoRef.augmented_psbt.clear();
                    infoRef.augmented_psbt_hash.clear();
                }
                }

                QMessageBox::critical(self, self->tr("Broadcast Failed"),
                    self->tr("Ceremony succeeded but broadcast failed:\n\n%1\n\n"
                       "The signed PSBT may need manual broadcast.").arg(broadcastResult.error));
                self->updateOffersList();
                self->updateTradeRequestsList();
                // Clean up watcher
                if (watcherPtr) {
                    watcherPtr->deleteLater();
                }
                return;
            }

            QString txid = broadcastResult.txid;
            LogPrintf("TradeBoardTab: Opening transaction broadcast: %s\n", txid.toStdString().c_str());

            self->showAutoClosingInfo(self->tr("Contract Opened"),
                self->tr("✓ Contract opened successfully!\n\n"
                   "Transaction ID: %1\n\n"
                   "The contract will automatically appear in Active Contracts "
                   "once confirmed on the blockchain.")
                .arg(txid));

            // DIFFICULTY: persist the funded vault outpoints. The ceremony proving funds exist is NOT
            // enough — the GUI/Active Contracts state model depends on record_open. The taker records the
            // same on ceremony_complete.
            if (self->walletModel && !requestId.isEmpty() && self->activeRequests.contains(requestId)) {
                const QString cid = self->activeRequests[requestId].final_offer_id;
                if (!cid.isEmpty() && self->getCanonicalContractType(cid) == QLatin1String("difficulty")) {
                    auto ro = self->walletModel->difficultyRecordOpen(cid, txid);
                    if (!ro.success) {
                        LogPrintf("TradeBoardTab: difficulty.record_open (maker) failed: %s\n", ro.error.toStdString().c_str());
                    }
                }
            }
        }

        // UNLOCK COINS: Clear the locked PSBT after successful broadcast
        // requestId already declared at the top of this lambda
        if (!requestId.isEmpty() && self->activeRequests.contains(requestId)) {
            TradeRequestInfo& infoRef = self->activeRequests[requestId];
            if (infoRef.psbt_locked) {
                LogPrintf("TradeBoardTab: Unlocking PSBT for request %s after successful broadcast\n",
                          requestId.toStdString().c_str());
                // Unlock wallet-level Fair-Sign UTXOs
                if (!infoRef.augmented_psbt.isEmpty()) {
                    UnlockFairSignUTXOsForPsbt(self->walletModel, infoRef.augmented_psbt, "Maker ceremony success");
                }
                infoRef.psbt_locked = false;
                infoRef.augmented_psbt.clear();
                infoRef.augmented_psbt_hash.clear();
            }
        }

        self->activeSessions.remove(session_id);

        // Refresh UI and trigger registry update
        self->updateOffersList();
        self->updateTradeRequestsList();
        if (self->walletModel) {
            Q_EMIT self->walletModel->balanceChanged(self->walletModel->wallet().getBalances());
        }

        // Clean up watcher
        if (watcherPtr) {
            watcherPtr->deleteLater();
        }
    });
}

void TradeBoardTab::maybeStartTakerCeremony(const QString& session_id, const QString& maker_role)
{
    const QString requestId = activeSessions.value(session_id);
    if (requestId.isEmpty() || !activeRequests.contains(requestId)) {
        return;
    }

    // CRITICAL: Copy to avoid QMap reference invalidation
    TradeRequestInfo info = activeRequests[requestId];  // Deep copy
    if (!info.taker_ready_for_ceremony) {
        return;
    }

    // Check for augmented PSBT (immutability pattern)
    if (info.augmented_psbt.isEmpty()) {
        if (!info.waiting_for_base_notice_sent) {
            LogPrintf("TradeBoardTab: Waiting for augmented PSBT before starting ceremony (session %s)\n",
                      session_id.toStdString().c_str());
            info.waiting_for_base_notice_sent = true;
            // Write back modified flag (safe single-access)
            if (activeRequests.contains(requestId)) {
                activeRequests[requestId].waiting_for_base_notice_sent = true;
            }
        }
        return;
    }

    QString resolvedMakerRole = maker_role.isEmpty() ? info.maker_role : maker_role.toLower();
    startPreparedTakerCeremony(info.offer_id, session_id, info, resolvedMakerRole);
}

void TradeBoardTab::onHandshakeCompleteMaker(const QString& session_id, const QString& request_id, const QString& finalizedOfferId, const QString& finalizedOfferJson, const QVariantMap& handshakeResult)
{
    // CRITICAL: NEVER take pointers to QMap elements - they become invalid if map is modified!
    // Copy the data we need instead
    bool requestExists = activeRequests.contains(request_id);
    bool recovering = false;
    QString makerBasePsbt;

    if (requestExists) {
        recovering = activeRequests[request_id].recovering_session;
        makerBasePsbt = activeRequests[request_id].maker_base_psbt;
    }

    bool success = handshakeResult["success"].toBool();
    bool handshake_complete = handshakeResult["handshake_complete"].toBool();

    if (success && handshake_complete) {
        QString sas = handshakeResult["sas"].toString();
        QString sas_numeric = handshakeResult["sas_numeric"].toString();

        // Update session with handshake results
        if (sessionManager) {
            BridgeSessionManager::SessionInfo sessionInfo = sessionManager->getSession(session_id);
            sessionInfo.handshake_complete = true;
            sessionInfo.sas = sas;
            sessionInfo.sas_numeric = sas_numeric;
            sessionManager->updateSession(session_id, sessionInfo);
        }

        LogPrintf("TradeBoardTab: Handshake completed successfully! SAS=%s\n",
                  sas.toStdString().c_str());

        // Show auto-closing SAS dialog (non-modal). If user clicks Abort, treat it
        // as an explicit session abort and close the cosign session safely.
        auto* sasDialog = new SASVerificationDialog(sas, sas_numeric, 12, TopLevelDialogParent(this));
        sasDialog->setAttribute(Qt::WA_DeleteOnClose);
        sasDialog->setModal(false);
        connect(sasDialog, &SASVerificationDialog::sasAbortRequested,
                this, [this, session_id, request_id]() {
            if (!walletModel) return;
            LogPrintf("TradeBoardTab: User aborted via SAS dialog for maker session %s\n",
                      session_id.toStdString().c_str());

            // Defer close/cleanup to avoid re-entrancy with dialog destruction
            QTimer::singleShot(0, this, [this, session_id, request_id]() {
                if (!walletModel) return;
                walletModel->cosignClose(session_id);
                handleSessionLoss(session_id, request_id,
                                  tr("Session aborted by user in SAS dialog"));
            });
        });
        sasDialog->show();

        // NOW that handshake is complete, add session to polling
        if (!session_id.isEmpty()) {
            activeSessions[session_id] = request_id;
            LogPrintf("TradeBoardTab: Maker added session %s to polling after handshake (request_id=%s)\n",
                      session_id.toStdString().c_str(),
                      request_id.toStdString().c_str());
        }

        // Update recovering flag (safe single access)
        if (requestExists && activeRequests.contains(request_id)) {
            activeRequests[request_id].recovering_session = false;
        }

        // Send the finalized offer JSON through the session (wrapped, with maker base PSBT for immutability)
        QJsonDocument offerDoc = QJsonDocument::fromJson(finalizedOfferJson.toUtf8());
        QJsonObject wrapper;
        wrapper["type"] = "finalized_offer";
        wrapper["offer"] = offerDoc.object();
        // Include maker's base PSBT so taker can augment immediately (immutability pattern)
        if (!makerBasePsbt.isEmpty()) {
            wrapper["maker_base_psbt"] = makerBasePsbt;
            LogPrintf("TradeBoardTab: Including maker base PSBT in finalized offer (%d bytes)\n",
                      makerBasePsbt.length());
        }
        QJsonDocument wrapperDoc(wrapper);
        QString wrappedJson = QString::fromUtf8(wrapperDoc.toJson(QJsonDocument::Compact));

        auto sendResult = walletModel->cosignSend(session_id, wrappedJson);
        if (!sendResult.success) {
            LogPrintf("TradeBoardTab: WARNING: Failed to send finalized offer: %s\n",
                      sendResult.error.toStdString().c_str());
            QString lower = sendResult.error.toLower();
            if (lower.contains("session not found") ||
                lower.contains("unknown session") ||
                lower.contains("session expired") ||
                lower.contains("bridge restarted")) {
                handleSessionLoss(session_id, request_id, sendResult.error);
            } else {
                QMessageBox::warning(this, tr("Send Failed"),
                    tr("Failed to deliver finalized offer to taker:\n\n%1").arg(sendResult.error));
            }
        } else if (requestExists && activeRequests.contains(request_id)) {
            // Safe single-access updates
            activeRequests[request_id].final_offer_processed = true;
            activeRequests[request_id].final_offer_id = finalizedOfferId;
            // FIX: Store finalized offer JSON so handleAcceptanceReceived can extract contract type
            activeRequests[request_id].final_offer_json = finalizedOfferJson;
            LogPrintf("TradeBoardTab: Stored finalized offer JSON for request %s (%d bytes)\n",
                      request_id.toStdString().c_str(), finalizedOfferJson.length());
        }

        if (recovering) {
            showAutoClosingInfo(tr("Session Reconnected"),
                tr("Reconnected to taker and re-sent the finalized contract.\n\n"
                   "Waiting for taker to confirm acceptance..."));
        }
    } else {
        QString error = handshakeResult["error"].toString();
        LogPrintf("TradeBoardTab: Auto-handshake failed: %s\n",
                  error.toStdString().c_str());
        if (requestExists && activeRequests.contains(request_id)) {
            activeRequests[request_id].recovering_session = false;
        }
        QMessageBox::critical(this, tr("Handshake Failed"),
            tr("Failed to complete handshake:\n\n%1\n\n"
               "The session was created but handshake did not complete. "
               "You may need to retry or use manual mode.")
            .arg(error));
    }

    updateTradeRequestsList();
}

void TradeBoardTab::onHandshakeCompleteTaker(const QString& session_id, const QString& request_id, const QVariantMap& handshakeResult)
{
    // CRITICAL: NEVER take pointers to QMap elements - they become invalid if map is modified!
    bool requestExists = activeRequests.contains(request_id);
    bool recovering = false;
    bool acceptanceSent = false;
    QString lastAcceptanceEnvelope;

    if (requestExists) {
        const TradeRequestInfo& info = activeRequests[request_id];
        recovering = info.recovering_session;
        acceptanceSent = info.acceptance_sent;
        lastAcceptanceEnvelope = info.last_acceptance_envelope;
    }

    bool success = handshakeResult["success"].toBool();
    bool handshake_complete = handshakeResult["handshake_complete"].toBool();

    if (success && handshake_complete) {
        QString sas = handshakeResult["sas"].toString();
        QString sas_numeric = handshakeResult["sas_numeric"].toString();

        // Update session with handshake results
        if (sessionManager) {
            BridgeSessionManager::SessionInfo sessionInfo = sessionManager->getSession(session_id);
            sessionInfo.handshake_complete = true;
            sessionInfo.sas = sas;
            sessionInfo.sas_numeric = sas_numeric;
            sessionManager->updateSession(session_id, sessionInfo);
        }

        // CRITICAL: Track this session for message polling so we receive the finalized offer
        if (!session_id.isEmpty()) {
            activeSessions[session_id] = request_id;
            LogPrintf("TradeBoardTab: Taker added session %s to polling (request_id=%s)\n",
                      session_id.toStdString().c_str(),
                      request_id.toStdString().c_str());
        }

        // AUTO-SEND xchain_accept if this is a pending cross-chain request
        if (requestExists && walletModel) {
            const TradeRequestInfo& reqInfo = activeRequests[request_id];
            bool isXchainPending = reqInfo.offer_summary.value("xchain_pending").toBool()
                || pendingXchainRequests.contains(request_id);
            if (isXchainPending) {
                QString offerId = reqInfo.offer_id;
                if (activeOffers.contains(offerId)) {
                    QJsonDocument payloadDoc = QJsonDocument::fromJson(
                        activeOffers[offerId].contract_payload.toUtf8());
                    QJsonObject extLeg = payloadDoc.object().value("external_leg").toObject();

                    // Get taker's ETH address and signer ref from settlement profile
                    QList<WalletModel::SettlementProfileItem> profiles = walletModel->settlementProfileList();
                    QString takerRefundAddr;
                    QString takerSignerRef;
                    for (const auto& p : profiles) {
                        if (p.chain == "ethereum") {
                            takerRefundAddr = p.address;
                            takerSignerRef = p.signer_ref;
                            break;
                        }
                    }
                    QString takerTscAddr = walletModel->getNewAddress("Cross-chain TSC receive");

                    // Resolve token address from the offer's external asset.
                    // Native ETH: empty. ERC-20: read from -xchain_eth_token_<ASSET> config.
                    QString asset = extLeg.value("asset").toString();
                    QString tokenAddr;
                    if (asset != "ETH" && !asset.isEmpty()) {
                        QString configKey = QString("-xchain_eth_token_%1").arg(asset.toLower());
                        tokenAddr = QString::fromStdString(
                            gArgs.GetArg(configKey.toStdString(), ""));
                        if (tokenAddr.isEmpty()) {
                            LogPrintf("TradeBoardTab: WARNING — no token address configured for %s "
                                      "(set %s=0x...)\n",
                                      asset.toStdString().c_str(), configKey.toStdString().c_str());
                        }
                    }

                    if (!takerRefundAddr.isEmpty()) {
                        QJsonObject xchainAccept;
                        xchainAccept["type"] = QStringLiteral("xchain_accept");
                        xchainAccept["offer_id"] = offerId;
                        xchainAccept["taker_refund_address"] = takerRefundAddr;
                        xchainAccept["taker_tsc_address"] = takerTscAddr;
                        xchainAccept["taker_signer_ref"] = takerSignerRef;
                        xchainAccept["token_address"] = tokenAddr;

                        auto sendResult = walletModel->cosignSend(session_id,
                            QString::fromUtf8(QJsonDocument(xchainAccept).toJson(QJsonDocument::Compact)));
                        if (sendResult.success) {
                            pendingXchainRequests.remove(request_id);
                            LogPrintf("TradeBoardTab: Auto-sent xchain_accept on session %s for offer %s\n",
                                      session_id.toStdString().c_str(), offerId.toStdString().c_str());
                        } else {
                            LogPrintf("TradeBoardTab: FAILED to send xchain_accept on session %s: %s\n",
                                      session_id.toStdString().c_str(),
                                      sendResult.error.toStdString().c_str());
                        }
                    }
                }
            }
        }

        // DIFFICULTY: the term sheet is self-contained (it embeds the maker's SIGNED offer), so once the
        // session is up the taker accepts locally and sends ONE difficulty-specific message
        // (difficulty_acceptance). The maker imports it and then drops into the standard
        // maker_base_psbt -> ceremony_ready -> adaptor ceremony path (no finalized_offer re-issue).
        if (requestExists && walletModel && !acceptanceSent) {
            const TradeRequestInfo& reqInfo = activeRequests[request_id];
            const QString offerId = reqInfo.offer_id;
            QString ctype = reqInfo.offer_summary.value("contract_type").toString().toLower();
            if (ctype.isEmpty()) ctype = reqInfo.contract_type.toLower();
            if (ctype == QLatin1String("difficulty") && activeOffers.contains(offerId)) {
                const QString payload = activeOffers[offerId].contract_payload;
                const QJsonObject ts = QJsonDocument::fromJson(payload.toUtf8()).object();
                const QJsonObject embeddedOffer = ts.value("offer").toObject();
                // SECURITY: kind + maker role come from the EMBEDDED SIGNED offer (proposer_role), never the
                // outer (spoofable) term sheet — outer fields are display-only. Matches the review dialog's
                // signed-offer binding; a spoofed outer maker_role must not steer which leg gets funded.
                const QString kind = embeddedOffer.value("kind").toString();              // "cfd" | "option"
                const QString makerRole = embeddedOffer.value("proposer_role").toString();// long/short | writer/buyer
                if (embeddedOffer.isEmpty() || kind.isEmpty() || makerRole.isEmpty()) {
                    LogPrintf("TradeBoardTab: difficulty term sheet has no valid embedded offer; cannot session-accept\n");
                } else {
                    const QString offerJson = QString::fromUtf8(QJsonDocument(embeddedOffer).toJson(QJsonDocument::Compact));
                    // Difficulty CFD uses long/short, OPTION uses writer/buyer — keep the vocab separate;
                    // pick accept vs accept_option strictly by the embedded kind, never a generic "option".
                    WalletModel::DifficultyAcceptResult ar;
                    QString takerAttestAddr;  // the taker's own owner payout, used for BIP-322 attestation
                    if (kind == QLatin1String("option")) {
                        const QString payout = walletModel->getNewAddress(tr("Difficulty option payout"), "bech32m");
                        takerAttestAddr = payout;
                        ar = walletModel->difficultyAcceptOption(offerJson, payout, /*confirmed=*/true);
                    } else {
                        const QString owner = walletModel->getNewAddress(tr("Difficulty IM return"), "bech32m");
                        const QString cp = walletModel->getNewAddress(tr("Difficulty counterparty claim"), "bech32m");
                        takerAttestAddr = owner;
                        ar = walletModel->difficultyAccept(offerJson, owner, cp, /*confirmed=*/true);
                    }
                    if (ar.success && !ar.contract_id.isEmpty()) {
                        // WATCHPOINT: from here the contract_id is the canonical id — NOT the bulletin-board UUID.
                        activeRequests[request_id].final_offer_id = ar.contract_id;
                        // Stash the taker's own owned address so the ceremony's BIP-322 attestation can find
                        // a wallet-owned address (getAddressForRole falls back across both slots + checks
                        // ownership, so the slot label does not matter).
                        activeRequests[request_id].borrower_address = takerAttestAddr;
                        cacheContractFlavor(ar.contract_id, QStringLiteral("difficulty"), payload, offerId);

                        QJsonObject msg;
                        msg["type"] = QStringLiteral("difficulty_acceptance");
                        msg["kind"] = kind;
                        msg["maker_role"] = makerRole;
                        msg["contract_id"] = ar.contract_id;          // expected id (maker recomputes + verifies)
                        msg["offer"] = embeddedOffer;                 // maker's own signed offer (authoritative)
                        msg["acceptance"] = QJsonDocument::fromJson(ar.acceptance_json.toUtf8()).object();
                        const QString envelope = QString::fromUtf8(QJsonDocument(msg).toJson(QJsonDocument::Compact));
                        auto sendResult = walletModel->cosignSend(session_id, envelope);
                        if (sendResult.success) {
                            activeRequests[request_id].acceptance_sent = true;
                            activeRequests[request_id].last_acceptance_envelope = envelope;
                            LogPrintf("TradeBoardTab: Sent difficulty_acceptance (contract %s) on session %s\n",
                                      ar.contract_id.toStdString().c_str(), session_id.toStdString().c_str());
                        } else {
                            LogPrintf("TradeBoardTab: FAILED to send difficulty_acceptance on session %s: %s\n",
                                      session_id.toStdString().c_str(), sendResult.error.toStdString().c_str());
                        }
                    } else {
                        LogPrintf("TradeBoardTab: session difficulty.accept failed: %s\n", ar.error.toStdString().c_str());
                    }
                }
            }
        }

        LogPrintf("TradeBoardTab: Handshake completed successfully! SAS=%s\n",
                  sas.toStdString().c_str());

        // Show auto-closing SAS dialog (non-modal) for taker. Abort here also
        // closes the underlying cosign session safely.
        auto* sasDialog = new SASVerificationDialog(sas, sas_numeric, 12, TopLevelDialogParent(this));
        sasDialog->setAttribute(Qt::WA_DeleteOnClose);
        sasDialog->setModal(false);
        connect(sasDialog, &SASVerificationDialog::sasAbortRequested,
                this, [this, session_id, request_id]() {
            if (!walletModel) return;
            LogPrintf("TradeBoardTab: User aborted via SAS dialog for taker session %s\n",
                      session_id.toStdString().c_str());

            QTimer::singleShot(0, this, [this, session_id, request_id]() {
                if (!walletModel) return;
                walletModel->cosignClose(session_id);
                handleSessionLoss(session_id, request_id,
                                  tr("Session aborted by user in SAS dialog"));
            });
        });
        sasDialog->show();

        if (requestExists && activeRequests.contains(request_id)) {
            activeRequests[request_id].recovering_session = false;
            activeRequests[request_id].auto_joined = true;
        }

        if (recovering) {
            LogPrintf("TradeBoardTab: Session %s recovered for request %s\n",
                      session_id.toStdString().c_str(),
                      request_id.toStdString().c_str());

            if (acceptanceSent && !lastAcceptanceEnvelope.isEmpty()) {
                QString envelope = lastAcceptanceEnvelope;
                auto* resendWatcher = new QFutureWatcher<WalletModel::CosignSendResult>(this);
                connect(resendWatcher, &QFutureWatcher<WalletModel::CosignSendResult>::finished, this,
                        [this, resendWatcher, session_id, request_id]() {
                    WalletModel::CosignSendResult sendResult = resendWatcher->result();
                    resendWatcher->deleteLater();

                    if (!sendResult.success) {
                        LogPrintf("TradeBoardTab: Failed to re-send acceptance on recovered session %s: %s\n",
                                  session_id.toStdString().c_str(),
                                  sendResult.error.toStdString().c_str());
                        QString lower = sendResult.error.toLower();
                        if (lower.contains("session not found") ||
                            lower.contains("unknown session") ||
                            lower.contains("session expired") ||
                            lower.contains("bridge restarted")) {
                            handleSessionLoss(session_id, request_id, sendResult.error);
                        } else {
                            QMessageBox::warning(this, tr("Acceptance Retry Failed"),
                                tr("Failed to re-send acceptance:\n\n%1").arg(sendResult.error));
                        }
                    } else {
                        LogPrintf("TradeBoardTab: Acceptance re-sent on recovered session %s\n",
                                  session_id.toStdString().c_str());
                    }
                });

                auto resendInflightGuard = std::make_shared<InflightGuard>(this);
                QFuture<WalletModel::CosignSendResult> resendFuture =
                    QtConcurrent::run([this, resendInflightGuard, session_id, envelope]() {
                        (void)resendInflightGuard;
                        return walletModel->cosignSend(session_id, envelope);
                    });
                resendWatcher->setFuture(resendFuture);
            }

            showAutoClosingInfo(tr("Session Reconnected"),
                tr("Reconnected to cosign session.\n\n"
                   "Waiting for maker confirmation..."));
        }
    } else {
        QString error = handshakeResult["error"].toString();
        LogPrintf("TradeBoardTab: Auto-handshake failed: %s\n",
                  error.toStdString().c_str());

        if (requestExists && activeRequests.contains(request_id)) {
            activeRequests[request_id].recovering_session = false;
            // Do not re-arm timer-driven auto-join on failure. Retrying the
            // same invite/session every request refresh replays the same relay
            // room and can corrupt the bridge's in-memory handshake state.
            activeRequests[request_id].auto_joined = true;
        }
        activeSessions.remove(session_id);
        ceremonySessions.remove(session_id);
        QString failedAttemptKey = request_id;
        if (activeRequests.contains(request_id) && !activeRequests[request_id].invite_link.isEmpty()) {
            failedAttemptKey = AutoJoinAttemptKey(request_id, activeRequests[request_id].invite_link);
        }
        autoJoinAttemptedRequests.insert(failedAttemptKey);
        if (!session_id.isEmpty()) {
            autoJoinAttemptedSessions.insert(session_id);
        }

        // Only show popup once per session to prevent infinite spam
        if (!handshakeFailureShown.contains(session_id)) {
            handshakeFailureShown.insert(session_id);
            QMessageBox::critical(this, tr("Handshake Failed"),
                tr("Failed to complete handshake for session %1:\n\n%2\n\n"
                   "This usually means:\n"
                   "• Tor failed to start (check status indicator)\n"
                   "• Network connectivity issues\n"
                   "• Counterparty disconnected\n\n"
                   "Check 'Exchange P2P > Bridge Sessions' tab for details.")
                .arg(session_id.left(16) + "...")
                .arg(error));
        }
    }
}

void TradeBoardTab::handleCeremonyInviteReceived(const QString& session_id, const QString& invite_json)
{
    LogPrintf("TradeBoardTab: Taker received ceremony invitation on session %s\n", session_id.toStdString().c_str());

    if (!walletModel) return;

    // Parse invite
    QJsonParseError parseError;
    QJsonDocument inviteDoc = QJsonDocument::fromJson(invite_json.toUtf8(), &parseError);
    if (inviteDoc.isNull() || !inviteDoc.isObject()) {
        QMessageBox::critical(this, tr("Parse Error"),
            tr("Failed to parse ceremony invitation:\n%1").arg(parseError.errorString()));
        return;
    }

    QJsonObject invite = inviteDoc.object();
    QString offer_id = invite.value("offer_id").toString();
    QString maker_role = invite.value("maker_role").toString().toLower();
    const std::string offer_id_str = offer_id.toStdString();
    const std::string maker_role_str = maker_role.toStdString();
    LogPrintf("TradeBoardTab: Ceremony invite details - offer=%s, maker_role=%s\n",
              offer_id_str.c_str(),
              maker_role_str.c_str());
    if (maker_role.isEmpty() && activeOffers.contains(offer_id) && !activeOffers[offer_id].maker_role.isEmpty()) {
        maker_role = activeOffers[offer_id].maker_role.toLower();
    }
    QString taker_role = invite.value("taker_role").toString().toLower();
    if (taker_role.isEmpty()) {
        taker_role = (maker_role == "lender") ? QStringLiteral("borrower") :
                     (maker_role == "borrower") ? QStringLiteral("lender") : QString();
    }
    const std::string taker_role_str = taker_role.toStdString();
    LogPrintf("TradeBoardTab: Ceremony invite taker_role=%s\n", taker_role_str.c_str());

    if (offer_id.isEmpty()) {
        QMessageBox::critical(this, tr("Invalid Invitation"),
            tr("Ceremony invitation is missing offer ID."));
        return;
    }

    QString participantText;
    if (taker_role == "lender") {
        participantText = tr("• Fund the principal leg\n"
                             "• Complete the adaptor ceremony\n"
                             "• Sign the opening transaction");
    } else {
        participantText = tr("• Fund your collateral\n"
                             "• Complete the adaptor ceremony\n"
                             "• Sign the opening transaction");
    }

    // Auto-proceed to opening ceremony without extra confirmation.
    // User can still cancel from the ceremony progress dialog.
    QTimer::singleShot(0, this, [this, offer_id, session_id, maker_role]() {
        launchOpeningCeremonyTaker(offer_id, session_id, maker_role);
    });
}

void TradeBoardTab::launchOpeningCeremonyTaker(const QString& offer_id, const QString& session_id, const QString& maker_role)
{
    if (!walletModel) return;

    const QString requestId = activeSessions.value(session_id);
    if (!activeRequests.contains(requestId)) {
        QMessageBox::critical(this, tr("Ceremony Not Ready"),
            tr("Opening ceremony cannot start because the session state is missing. Please retry the invite."));
        return;
    }

    // Make a COPY to avoid dangling reference if activeRequests is modified during RPC/dialog
    TradeRequestInfo info = activeRequests.value(requestId);

    // CRITICAL FIX: Use finalized contract ID (32-byte hex), not bulletin board UUID
    QString contractId = offer_id;
    if (!info.final_offer_id.isEmpty()) {
        contractId = info.final_offer_id;
        LogPrintf("TradeBoardTab: Taker using finalized contract ID: %s (was passed %s)\n",
                  contractId.toStdString().c_str(), offer_id.toStdString().c_str());
    } else {
        LogPrintf("TradeBoardTab: WARNING - Taker has no final_offer_id, using bulletin board ID: %s\n",
                  offer_id.toStdString().c_str());
    }

    if (info.maker_role.isEmpty() && !maker_role.isEmpty()) {
        info.maker_role = maker_role.toLower();
    }

    // NOW augment maker's base PSBT (user clicked "Proceed" - approved funding)
    if (info.augmented_psbt.isEmpty()) {
        if (info.maker_base_psbt.isEmpty()) {
            activeRequests[requestId] = info;  // Store modified copy back
            QMessageBox::critical(this, tr("Ceremony Not Ready"),
                tr("Maker's base PSBT is missing. Cannot proceed with ceremony."));
            return;
        }

        // Augment maker's base PSBT to create immutable locked PSBT
        // Use canonical cache to detect contract type
        QString contractType = getCanonicalContractType(contractId);
        if (contractType.isEmpty()) {
            if (!ensureContractFlavorLoaded(contractId, info.offer_summary.value("contract_type").toString())) {
                QMessageBox::critical(this, tr("Contract Type Unknown"),
                    tr("Cannot determine contract type for %1.\n\nPlease refresh the Trade Board.").arg(contractId.left(16) + "..."));
                return;
            }
            contractType = getCanonicalContractType(contractId);
        }
        bool isForward = (contractType == "forward" || contractType == "option");

        QString takerRole;
        if (isForward) {
            // FORWARD: Taker role is opposite of maker role (long/short)
            takerRole = (info.maker_role.toLower() == "long") ? QStringLiteral("short") : QStringLiteral("long");
        } else if (contractType == "spot") {
            // SPOT: Maker role is always "alice", taker is "bob"
            takerRole = QStringLiteral("bob");
        } else if (contractType == "difficulty") {
            // DIFFICULTY: opposite side — CFD long<->short, OPTION writer<->buyer (vocab kept separate).
            const QString mr = info.maker_role.toLower();
            takerRole = (mr == "long")   ? QStringLiteral("short")
                      : (mr == "short")  ? QStringLiteral("long")
                      : (mr == "writer") ? QStringLiteral("buyer")
                      : (mr == "buyer")  ? QStringLiteral("writer") : QString();
        } else {
            // REPO: Taker role is opposite of maker role (borrower/lender)
            takerRole = (info.maker_role.toLower() == "lender") ? QStringLiteral("borrower") : QStringLiteral("lender");
        }

        QVariantMap buildOptions;
        buildOptions["psbt"] = info.maker_base_psbt;

        // Use taker's user-selected fee strategy (stored during acceptance)
        LogPrintf("TradeBoardTab: Taker after approval - Reading taker_fee_strategy from info (request_id='%s'), value='%s', isEmpty=%d\n",
                  requestId.toStdString().c_str(),
                  info.taker_fee_strategy.toStdString().c_str(),
                  info.taker_fee_strategy.isEmpty());
        QString feeStrategy = info.taker_fee_strategy.isEmpty() ? QStringLiteral("medium") : info.taker_fee_strategy;
        LogPrintf("TradeBoardTab: Taker after approval - Using user-selected fee_strategy='%s' for funding\n", feeStrategy.toStdString().c_str());
        buildOptions["strategy"] = feeStrategy;

        QString augmentedPsbt;

        if (isForward) {
            // FORWARD: Auto-fund based on taker role and premium payer
            const QString premiumPayer = info.premium_payer.toLower();
            const bool takerPaysPremium = (info.premium_amount > 0) &&
                                          !premiumPayer.isEmpty() &&
                                          (premiumPayer == takerRole);

            if (takerRole == "long") {
                buildOptions["auto_fund_long"] = true;
                if (takerPaysPremium) {
                    buildOptions["auto_fund_premium"] = true;
                }
            } else if (takerRole == "short") {
                buildOptions["auto_fund_short"] = true;
                if (takerPaysPremium) {
                    LogPrintf("TradeBoardTab: WARNING - Contract %s expects short party to fund premium, "
                              "but short-paid premiums are unsupported in two-party flow\n",
                              contractId.toStdString().c_str());
                }
            }

            LogPrintf("TradeBoardTab: Taker augmenting maker's forward base PSBT after user approval (role=%s, offer=%s, maker_base_psbt=%d bytes)\n",
                      takerRole.toStdString().c_str(), contractId.toStdString().c_str(), info.maker_base_psbt.length());

            auto forwardResult = walletModel->forwardBuildOpen(contractId, buildOptions);
            if (!forwardResult.success) {
                activeRequests[requestId] = info;  // Store modified copy back
                QMessageBox::critical(this, tr("Augmentation Failed"),
                    tr("Failed to augment maker's forward base PSBT:\n\n%1").arg(forwardResult.error));
                return;
            }

            augmentedPsbt = forwardResult.psbt;
            info.alice_vault_index = forwardResult.alice_vault_index;
            info.bob_vault_index = forwardResult.bob_vault_index;
            info.premium_output_index = forwardResult.premium_output_index;

        } else if (contractType == "spot") {
            // SPOT: Build atomic swap PSBT (no role-based funding, both parties contribute)
            LogPrintf("TradeBoardTab: Taker building spot atomic swap PSBT after user approval (offer=%s, maker_base_psbt=%d bytes)\n",
                      contractId.toStdString().c_str(), info.maker_base_psbt.length());

            auto spotResult = walletModel->spotBuildAtomic(contractId, buildOptions);
            if (!spotResult.success) {
                activeRequests[requestId] = info;  // Store modified copy back
                QMessageBox::critical(this, tr("Augmentation Failed"),
                    tr("Failed to build spot atomic swap PSBT:\n\n%1").arg(spotResult.error));
                return;
            }

            augmentedPsbt = spotResult.psbt;
            LogPrintf("TradeBoardTab: Taker built spot atomic swap PSBT after user approval (%d bytes)\n",
                      augmentedPsbt.length() / 2);

            // For WRAP_REQUIRED ICU assets, require a pre-signing decryption commitment
            // before signalling readiness for the ceremony.
            WalletModel::ContractStatusResult status = walletModel->getContractStatus(contractId);
            bool requireCommitment = false;
            if (status.success && status.offer.contains("terms")) {
                const QVariant termsVar = status.offer.value("terms");
                if (termsVar.canConvert<QVariantMap>()) {
                    QVariantMap termsMap = termsVar.toMap();
                    if (termsMap.contains("require_commitment_proof")) {
                        requireCommitment = termsMap.value("require_commitment_proof").toBool();
                    }
                }
            }

            if (requireCommitment) {
                LogPrintf("TradeBoardTab: Spot contract %s requires ICU commitment proof (taker path)\n",
                          contractId.toStdString().c_str());

                CommitmentProofDialog dlg(walletModel, contractId, augmentedPsbt, this);
                if (dlg.exec() != QDialog::Accepted || !dlg.commitmentAdded()) {
                    LogPrintf("TradeBoardTab: Taker cancelled ICU commitment proof dialog for spot contract %s, aborting ceremony_ready\n",
                              contractId.toStdString().c_str());
                    activeRequests[requestId] = info;  // Preserve current state
                    return;
                }

                augmentedPsbt = dlg.getPsbtWithCommitment();
            }

        } else if (contractType == "difficulty") {
            // DIFFICULTY: augment the maker's base by funding the taker's OWN leg (build_open is role-order
            // tolerant). The merged PSBT (both IM vaults / IM + premium) then runs the generic ceremony.
            const bool isOption = (takerRole == "writer" || takerRole == "buyer");
            LogPrintf("TradeBoardTab: Taker augmenting maker's difficulty base PSBT (role=%s, contract=%s)\n",
                      takerRole.toStdString().c_str(), contractId.toStdString().c_str());
            WalletModel::DifficultyPsbtResult dr = isOption
                ? walletModel->difficultyBuildOpenOption(contractId, takerRole, info.maker_base_psbt)
                : walletModel->difficultyBuildOpen(contractId, takerRole, info.maker_base_psbt);
            if (!dr.success) {
                activeRequests[requestId] = info;  // Store modified copy back
                QMessageBox::critical(this, tr("Augmentation Failed"),
                    tr("Failed to augment maker's difficulty base PSBT:\n\n%1").arg(dr.error));
                return;
            }
            augmentedPsbt = dr.psbt;

        } else {
            // REPO: Auto-fund based on taker role
            if (takerRole == "borrower") {
                buildOptions["auto_fund_collateral"] = true;
                LogPrintf("TradeBoardTab: Taker (borrower) will auto_fund_collateral for contract %s\n",
                         contractId.toStdString().c_str());
            } else {
                buildOptions["auto_fund_principal"] = true;
                LogPrintf("TradeBoardTab: Taker (lender) will auto_fund_principal for contract %s\n",
                         contractId.toStdString().c_str());
            }

            LogPrintf("TradeBoardTab: Taker augmenting maker's repo base PSBT after user approval (role=%s, offer=%s, maker_base_psbt=%d bytes)\n",
                      takerRole.toStdString().c_str(), contractId.toStdString().c_str(), info.maker_base_psbt.length());

            auto augmentResult = walletModel->repoBuildOpen(contractId, buildOptions);
            if (!augmentResult.success) {
                activeRequests[requestId] = info;  // Store modified copy back
                QMessageBox::critical(this, tr("Augmentation Failed"),
                    tr("Failed to augment maker's repo base PSBT:\n\n%1").arg(augmentResult.error));
                return;
            }

            augmentedPsbt = augmentResult.psbt;
        }

        info.augmented_psbt = augmentedPsbt;
        auto annotate = walletModel->walletProcessPsbt(info.augmented_psbt,
                                                       /*sign=*/false,
                                                       QStringLiteral("DEFAULT"),
                                                       /*bip32derivs=*/true,
                                                       /*finalize=*/false);
        if (annotate.success && !annotate.psbt.isEmpty()) {
            info.augmented_psbt = annotate.psbt;
        }
        // Compute hash for immutability verification
        info.augmented_psbt_hash = ComputePsbtTxHash(info.augmented_psbt);
        info.psbt_locked = true;
        LogPrintf("TradeBoardTab: Taker locked augmented PSBT (%d bytes, hash=%s)\n",
                  info.augmented_psbt.length(), info.augmented_psbt_hash.toStdString().c_str());
    }

	    // Before signalling readiness, classify funding inputs. Mixed (Taproot +
	    // non-Taproot) is refused outright — neither path supports it. Pure
	    // non-Taproot offers the user a choice: require Taproot-only funding, or
	    // continue via the cooperative non-atomic signing path (losing atomicity).
	    if (walletModel) {
	        // Get contract type for warning message
	        QString contractType = getCanonicalContractType(contractId);
	        if (contractType.isEmpty()) {
	            contractType = QStringLiteral("contract");  // Fallback if cache miss
	        }

	        // Every refusal path below must notify the maker + tear down the
	        // bridge session, otherwise the maker (who has already sent
	        // maker_base_psbt + ceremony_invite and is polling for ceremony_ready)
	        // sits forever until the user manually closes the session. Symmetric
	        // to the maker-side ceremony_ready handler's reject paths.
	        //
	        // Captures session_id, info, requestId by reference; mutates info
	        // and writes it back to activeRequests on exit.
	        auto refuseAndTeardown = [&](const QString& stage, const QString& detail) {
	            LogPrintf("TradeBoardTab: Taker preflight refusal — stage='%s' detail='%s' session=%s request=%s\n",
	                      stage.toStdString().c_str(),
	                      detail.toStdString().c_str(),
	                      session_id.toStdString().c_str(),
	                      requestId.toStdString().c_str());
	            sendCeremonyError(session_id, stage, detail);
	            if (walletModel) {
	                walletModel->cosignClose(session_id);  // best-effort
	            }
	            activeSessions.remove(session_id);
	            ceremonySessions.remove(session_id);
	            if (sessionManager) sessionManager->removeSession(session_id);
	            if (info.psbt_locked) {
	                if (!info.augmented_psbt.isEmpty()) {
	                    UnlockFairSignUTXOsForPsbt(walletModel, info.augmented_psbt,
	                                               "Taker preflight refusal");
	                }
	                info.psbt_locked = false;
	                info.augmented_psbt.clear();
	                info.augmented_psbt_hash.clear();
	            }
	            activeRequests[requestId] = info;  // Store modified copy back
	        };

	        // Use the unified classifier (C++ PSBT decode + GetInputUTXO with
	        // non_witness_utxo fallback). Previously this code had a parallel
	        // detector that only checked witness_utxo.scriptPubKey.type via
	        // QVariant; for legacy inputs without a synthetic witness_utxo the
	        // two detectors disagreed — the modal popped but the cooperative
	        // path silently fell through to the atomic ceremony, which then
	        // failed with "No wallet-controlled inputs eligible for adaptor
	        // preparation". Both code paths now consult the same source of truth.
	        const auto preflightClassification = ClassifyPsbtInputs(info.augmented_psbt);
	        LogPrintf("TradeBoardTab: Taker preflight classification - decode_ok=%d, taproot=%d, non_taproot=%d, unknown=%d\n",
	                  preflightClassification.decode_succeeded ? 1 : 0,
	                  preflightClassification.taproot_inputs,
	                  preflightClassification.non_taproot_inputs,
	                  preflightClassification.unknown_inputs);

	        // Refuse to proceed when input classification is ambiguous. Falling
	        // back silently would land us in the failure mode the previous
	        // implementation produced. The user can rebuild the augmented PSBT
	        // (e.g. consolidate funds to fresh UTXOs) and retry.
	        if (!preflightClassification.decode_succeeded ||
	            preflightClassification.unknown_inputs > 0) {
	            refuseAndTeardown(tr("funding classification"),
	                tr("Taker refusing ceremony: cannot classify funding inputs "
	                   "(decode_ok=%1, unknown_inputs=%2).")
	                    .arg(preflightClassification.decode_succeeded ? 1 : 0)
	                    .arg(preflightClassification.unknown_inputs));
	            QMessageBox::critical(this, tr("Cannot Classify Funding"),
	                tr("Unable to classify all funding inputs in the augmented PSBT "
	                   "(decode_ok=%1, unknown_inputs=%2). Refusing to enter either "
	                   "the atomic adaptor ceremony or the cooperative non-atomic "
	                   "signing path.\n\n"
	                   "This usually means one or more inputs are missing both "
	                   "witness_utxo and non_witness_utxo metadata. Try regenerating "
	                   "your funding UTXOs or restarting the ceremony.")
	                    .arg(preflightClassification.decode_succeeded ? 1 : 0)
	                    .arg(preflightClassification.unknown_inputs));
	            return;
	        }

	        const bool hasNonTaproot = preflightClassification.non_taproot_inputs > 0;
	        const bool hasTaproot = preflightClassification.taproot_inputs > 0;

	        // Any non-Taproot input — whether pure non-Taproot or mixed with
	        // Taproot — routes the entire PSBT through cooperative non-atomic
	        // signing. The whole transaction is signed with SIGHASH_ALL in one
	        // walletprocesspsbt(sign=true) call: there is no hybrid where some
	        // inputs are atomic and others aren't. For the mixed case the taker
	        // is voluntarily waiving the Taproot atomicity guarantee on their
	        // Taproot inputs too; the dialog spells that out explicitly so it
	        // is a conscious choice, not a silent downgrade.
	        if (hasNonTaproot) {
	            QMessageBox msgBox(TopLevelDialogParent(this));
	            msgBox.setIcon(QMessageBox::Warning);
	            msgBox.setWindowTitle(hasTaproot
	                ? tr("Mixed Funding — Cooperative Signing Required")
	                : tr("Non-Taproot Funding Detected"));

	            QString headline = hasTaproot
	                ? tr("Your augmented PSBT contains %1 Taproot and %2 non-Taproot funding input(s).")
	                    .arg(preflightClassification.taproot_inputs)
	                    .arg(preflightClassification.non_taproot_inputs)
	                : tr("Your augmented PSBT contains only non-Taproot funding inputs (%1).")
	                    .arg(preflightClassification.non_taproot_inputs);

	            QString mainBody = tr(
	                "Atomic adaptor ceremonies require ALL funding inputs to be Taproot. "
	                "Because your PSBT has at least one non-Taproot input, the WHOLE "
	                "transaction falls back to cooperative non-atomic signing:\n\n"
	                "  • You sign your inputs FIRST (every input you control, with "
	                "SIGHASH_ALL) and send the signed PSBT to your counterparty.\n"
	                "  • Your counterparty signs SECOND, finalises, and broadcasts.\n"
	                "  • If they walk away after seeing your signatures, your funds "
	                "stay on-chain (no broadcast happens), but you have committed "
	                "signatures bound to a specific transaction.");

	            QString taprootWarning;
	            if (hasTaproot) {
	                taprootWarning = tr(
	                    "\n\nImportant: your %1 Taproot input(s) would normally provide "
	                    "a cryptographic atomicity guarantee in the standard ceremony. "
	                    "Going cooperative for a mixed PSBT means you give up that "
	                    "protection on those Taproot inputs too — they are signed "
	                    "with the same SIGHASH_ALL commitment as the legacy inputs.")
	                    .arg(preflightClassification.taproot_inputs);
	            }

	            QString options = tr(
	                "\n\nYou can:\n"
	                "  • Use Taproot Only (regenerate Taproot UTXOs and retry to get "
	                "atomic adaptor signing), or\n"
	                "  • Continue with Cooperative Signing (accept the loss of "
	                "atomicity for the whole transaction), or\n"
	                "  • Cancel and abandon this ceremony.");

	            msgBox.setText(headline + tr("\n\n") + mainBody + taprootWarning + options);

	            QPushButton* taprootOnlyBtn = msgBox.addButton(tr("Use Taproot Only"), QMessageBox::RejectRole);
	            QPushButton* presignBtn = msgBox.addButton(tr("Continue with Cooperative Signing"), QMessageBox::AcceptRole);
	            QPushButton* cancelBtn = msgBox.addButton(tr("Cancel"), QMessageBox::DestructiveRole);
	            msgBox.setDefaultButton(presignBtn);

	            msgBox.exec();

	            if (msgBox.clickedButton() == cancelBtn) {
	                refuseAndTeardown(tr("user cancelled"),
	                    tr("Taker cancelled ceremony at non-Taproot funding dialog."));
	                return;
	            }
	            if (msgBox.clickedButton() == taprootOnlyBtn) {
	                refuseAndTeardown(tr("taker requested Taproot-only"),
	                    tr("Taker has non-Taproot funding inputs and prefers to retry with "
	                       "Taproot-only funding instead of cooperative non-atomic signing."));
	                QMessageBox::information(this, tr("Taproot Funding Required"),
	                    tr("This contract requires Taproot-only funding for atomic adaptor ceremonies.\n\n"
	                       "Please consolidate or regenerate funds into Taproot addresses and try again.\n\n"
	                       "Your counterparty has been notified."));
	                return;
	            }

	            LogPrintf("TradeBoardTab: User chose cooperative non-atomic signing for %s funding (taproot=%d, non_taproot=%d, unknown=%d)\n",
	                      hasTaproot ? "MIXED" : "pure-non-Taproot",
	                      preflightClassification.taproot_inputs,
	                      preflightClassification.non_taproot_inputs,
	                      preflightClassification.unknown_inputs);
	            info.cooperative_consent = true;
	            // The runner signs all wallet-controlled inputs inside
	            // runCooperativeSignTaker via walletprocesspsbt(sign=true,
	            // SIGHASH=ALL) in one pass — Taproot and legacy alike. We
	            // deliberately do NOT pre-sign here so the runner's
	            // signature-progress verification can detect genuine progress
	            // and a wallet-locked state errors cleanly.
	        }
	    }

	    if (!info.ceremony_ready_sent) {
	        QJsonObject readyMsg;
	        readyMsg["type"] = "ceremony_ready";
	        readyMsg["offer_id"] = contractId;
	        readyMsg["psbt"] = info.augmented_psbt;  // Send augmented PSBT (possibly pre-signed) to maker
	        if (info.cooperative_consent) {
	            // Tell the maker the taker has requested cooperative non-atomic signing.
	            // The maker will display a downgrade modal and either accept (setting
	            // their own cooperative_consent) or reject (sending ceremony_abort).
	            readyMsg["signing_mode"] = QStringLiteral("cooperative_non_atomic");
	            readyMsg["non_atomic_consent"] = true;
	        }
	        QString readyJson = QString::fromUtf8(QJsonDocument(readyMsg).toJson(QJsonDocument::Compact));
	        LogPrintf("TradeBoardTab: Taker sending ceremony_ready with augmented PSBT to maker on session %s\n",
	                  session_id.toStdString().c_str());
	        WalletModel::CosignSendResult readySend = walletModel->cosignSend(session_id, readyJson);
	        if (!readySend.success) {
	            LogPrintf("TradeBoardTab: Failed to send ceremony_ready: %s\n",
	                      readySend.error.toStdString().c_str());
	            activeRequests[requestId] = info;  // Store modified copy back
	            QMessageBox::critical(this, tr("Communication Error"),
	                tr("Failed to notify maker that you're ready:\n\n%1").arg(readySend.error));
	            return;
	        }
	        info.ceremony_ready_sent = true;
	        LogPrintf("TradeBoardTab: Sent ceremony_ready successfully\n");
	    }

    info.taker_ready_for_ceremony = true;
    info.waiting_for_base_notice_sent = false;

    // Store modified copy back to activeRequests
    activeRequests[requestId] = info;

    maybeStartTakerCeremony(session_id, maker_role);
}

void TradeBoardTab::startPreparedTakerCeremony(const QString& offer_id,
                                               const QString& session_id,
                                               TradeRequestInfo& info,
                                               const QString& maker_role)
{
    if (!walletModel) return;

    // Prevent duplicate ceremony launch - ceremony already running for this session
    if (ceremonySessions.contains(session_id)) {
        LogPrintf("TradeBoardTab: Skipping taker ceremony launch - already running for session %s\n",
                  session_id.toStdString().c_str());
        return;
    }

    // Defer if a session poll is mid-flight for this session (see the matching
    // guard in launchOpeningCeremony() and drainDeferredCeremonyStarts()).
    if (m_sessionsBeingPolled.contains(session_id)) {
        LogPrintf("TradeBoardTab: Deferring taker ceremony launch for session %s (poll in flight)\n",
                  session_id.toStdString().c_str());
        m_deferredCeremonyStarts.append({/*isMaker=*/false, info.offer_id, session_id, info.request_id, maker_role});
        return;
    }

    // CRITICAL: Insert session IMMEDIATELY to close TOCTOU race window
    // Must happen before any long-running validation/setup code
    ceremonySessions.insert(session_id);
    LogPrintf("TradeBoardTab: Taker ceremony session %s locked\n", session_id.toStdString().c_str());

    // CRITICAL FIX: Use finalized contract ID (32-byte hex), not bulletin board UUID
    QString contractId = offer_id;
    if (!info.final_offer_id.isEmpty()) {
        contractId = info.final_offer_id;
        LogPrintf("TradeBoardTab: Taker ceremony using finalized contract ID: %s (was passed %s)\n",
                  contractId.toStdString().c_str(), offer_id.toStdString().c_str());
    } else {
        LogPrintf("TradeBoardTab: WARNING - Taker ceremony has no final_offer_id, using bulletin board ID: %s\n",
                  offer_id.toStdString().c_str());
    }

    LogPrintf("TradeBoardTab: Launching opening ceremony for taker, offer %s, session %s\n",
              contractId.toStdString().c_str(), session_id.toStdString().c_str());

    // Use canonical cache to determine roles correctly
    QString contractType = getCanonicalContractType(contractId);
    if (contractType.isEmpty()) {
        if (!ensureContractFlavorLoaded(contractId, info.offer_summary.value("contract_type").toString())) {
            QMessageBox::critical(this, tr("Contract Type Unknown"),
                tr("Cannot determine contract type for %1.\n\nPlease refresh the Trade Board.").arg(contractId.left(16) + "..."));
            ceremonySessions.remove(session_id);  // Cleanup on early return
            return;
        }
        contractType = getCanonicalContractType(contractId);
    }
    bool isForward = (contractType == "forward" || contractType == "option");

    // Determine taker role (opposite of maker) - handle both forward and repo
    const QString makerRoleLower = maker_role.toLower();
    QString takerRole;
    if (isForward) {
        // FORWARD: Taker role is opposite of maker role (long/short)
        takerRole = (makerRoleLower == "long") ? QStringLiteral("short") : QStringLiteral("long");
    } else if (contractType == "difficulty") {
        // DIFFICULTY: opposite side, KEEPING the contract's own vocab so the maker/taker role labels form
        // a matched pair (CFD long/short, OPTION writer/buyer) — do NOT remap to repo borrower/lender. The
        // BIP-322 address comes from info.borrower_address (set at accept) via the slot-agnostic fallback.
        takerRole = (makerRoleLower == "long")   ? QStringLiteral("short")
                  : (makerRoleLower == "short")  ? QStringLiteral("long")
                  : (makerRoleLower == "writer") ? QStringLiteral("buyer")
                  : (makerRoleLower == "buyer")  ? QStringLiteral("writer") : makerRoleLower;
    } else {
        // REPO: Taker role is opposite of maker role (borrower/lender)
        takerRole = (makerRoleLower == "lender") ? QStringLiteral("borrower") : QStringLiteral("lender");
    }
    LogPrintf("TradeBoardTab: Taker role for ceremony: %s (contract_type=%s, isForward=%d)\n",
              takerRole.toStdString().c_str(), contractType.toStdString().c_str(), isForward);

    // Use cached augmented PSBT (immutability pattern - match functional test)
    QString localBase = info.augmented_psbt;

    // Extract party addresses based on contract type
    QString borrowerAddress;  // For repo: borrower, For forward: long party
    QString lenderAddress;    // For repo: lender, For forward: short party

    if (isForward) {
        // FORWARD: Use long/short addresses
        borrowerAddress = info.long_margin_dest;   // Maps to "borrower" slot for ceremony runner
        lenderAddress = info.short_margin_dest;    // Maps to "lender" slot for ceremony runner
    } else {
        // REPO: Use borrower/lender addresses
        borrowerAddress = info.borrower_address;
        lenderAddress = info.lender_address;
    }

    if (localBase.isEmpty()) {
        LogPrintf("TradeBoardTab: Taker ceremony aborted - augmented PSBT not cached (session %s)\n",
                  session_id.toStdString().c_str());
        ceremonySessions.remove(session_id);  // Cleanup on early return
        return;
    }

    LogPrintf("TradeBoardTab: Taker using cached augmented PSBT for ceremony (%d bytes, hash=%s)\n",
              localBase.length(), info.augmented_psbt_hash.toStdString().c_str());

    info.staged_local_base_psbt.clear();
    info.staged_local_base_ready = false;
    info.staged_peer_base_psbt.clear();
    info.staged_peer_base_ready = false;
    info.taker_ready_for_ceremony = false;
    info.waiting_for_base_notice_sent = false;

    if (isForward) {
        LogPrintf("TradeBoardTab: Taker ceremony addresses from request (FORWARD) - long=%s, short=%s, taker_role=%s\n",
                  borrowerAddress.toStdString().c_str(), lenderAddress.toStdString().c_str(), takerRole.toStdString().c_str());
    } else {
        LogPrintf("TradeBoardTab: Taker ceremony addresses from request (REPO) - borrower=%s, lender=%s, taker_role=%s\n",
                  borrowerAddress.toStdString().c_str(), lenderAddress.toStdString().c_str(), takerRole.toStdString().c_str());
    }

    // Extract addresses from final offer if missing
    if (!info.final_offer_json.isEmpty() && (borrowerAddress.isEmpty() || lenderAddress.isEmpty())) {
        QJsonParseError parseErr;
        QJsonDocument offerDoc = QJsonDocument::fromJson(info.final_offer_json.toUtf8(), &parseErr);
        if (!offerDoc.isNull() && offerDoc.isObject()) {
            QJsonObject offerObj = offerDoc.object();

            if (isForward) {
                // FORWARD: Extract from terms.long_party/short_party.margin_dest
                if (offerObj.contains("terms") && offerObj["terms"].isObject()) {
                    QJsonObject terms = offerObj["terms"].toObject();

                    if (borrowerAddress.isEmpty() && terms.contains("long_party") && terms["long_party"].isObject()) {
                        borrowerAddress = terms["long_party"].toObject().value("margin_dest").toString();
                        LogPrintf("TradeBoardTab: Extracted long_margin_dest from final offer: %s\n",
                                  borrowerAddress.toStdString().c_str());
                    }
                    if (lenderAddress.isEmpty() && terms.contains("short_party") && terms["short_party"].isObject()) {
                        lenderAddress = terms["short_party"].toObject().value("margin_dest").toString();
                        LogPrintf("TradeBoardTab: Extracted short_margin_dest from final offer: %s\n",
                                  lenderAddress.toStdString().c_str());
                    }
                }
            } else {
                // REPO: Extract from borrower_address/lender_address
                if (borrowerAddress.isEmpty() && offerObj.contains("borrower_address")) {
                    borrowerAddress = offerObj.value("borrower_address").toString();
                    LogPrintf("TradeBoardTab: Extracted borrower_address from final offer: %s\n",
                              borrowerAddress.toStdString().c_str());
                }
                if (lenderAddress.isEmpty() && offerObj.contains("lender_address")) {
                    lenderAddress = offerObj.value("lender_address").toString();
                    LogPrintf("TradeBoardTab: Extracted lender_address from final offer: %s\n",
                              lenderAddress.toStdString().c_str());
                }
            }
        }
    }

    // Generate address for taker if missing
    if (isForward) {
        // FORWARD: Generate based on long/short role
        if (takerRole == "long" && borrowerAddress.isEmpty()) {
            borrowerAddress = walletModel->getNewAddress("ceremony_attest", "bech32m");
            LogPrintf("TradeBoardTab: Generated long margin address for taker BIP-322: %s\n",
                      borrowerAddress.toStdString().c_str());
        } else if (takerRole == "short" && lenderAddress.isEmpty()) {
            lenderAddress = walletModel->getNewAddress("ceremony_attest", "bech32m");
            LogPrintf("TradeBoardTab: Generated short margin address for taker BIP-322: %s\n",
                      lenderAddress.toStdString().c_str());
        }
    } else {
        // REPO: Generate based on borrower/lender role
        if (takerRole == "borrower" && borrowerAddress.isEmpty()) {
            borrowerAddress = walletModel->getNewAddress("ceremony_attest", "bech32m");
            LogPrintf("TradeBoardTab: Generated borrower address for taker BIP-322: %s\n",
                      borrowerAddress.toStdString().c_str());
        } else if (takerRole == "lender" && lenderAddress.isEmpty()) {
            lenderAddress = walletModel->getNewAddress("ceremony_attest", "bech32m");
            LogPrintf("TradeBoardTab: Generated lender address for taker BIP-322: %s\n",
                      lenderAddress.toStdString().c_str());
        }
    }

    LogPrintf("TradeBoardTab: Taker loaded augmented base PSBT (session %s)\n",
              session_id.toStdString().c_str());

    auto cancelFlag = std::make_shared<std::atomic_bool>(false);

    // Create progress dialog for ceremony
    QWidget* dialog_parent = window() ? window() : this;
    QProgressDialog* progress = new QProgressDialog(dialog_parent);
    progress->setWindowTitle(tr("Opening Ceremony"));
    progress->setLabelText(tr("Executing fully automated adaptor ceremony...\n\n"
                              "• Exchanging base PSBTs\n"
                              "• BIP-322 peer attestation\n"
                              "• Exchanging nonce commitments\n"
                              "• Exchanging partial signatures\n"
                              "• Finalizing transaction\n\n"
                              "This may take 1-2 minutes. Please wait."));
    progress->setRange(0, 0); // Indeterminate

    // Guard UI lifetimes BEFORE connecting signals
    QPointer<QProgressDialog> progressPtr(progress);

    QPushButton* cancelButton = new QPushButton(tr("Cancel Ceremony"), progress);
    progress->setCancelButton(cancelButton);
    QObject::connect(cancelButton, &QPushButton::clicked, this, [this, cancelFlag, progressPtr, session_id]() {
        if (!cancelFlag->exchange(true, std::memory_order_acq_rel)) {
            if (progressPtr) {
                progressPtr->setLabelText(tr("Cancelling ceremony..."));
            }
            LogPrintf("TradeBoardTab: Taker requested ceremony cancellation for session %s\n",
                      session_id.toStdString().c_str());
        }
    });
    QObject::connect(progress, &QProgressDialog::canceled, this, [cancelFlag, progressPtr]() {
        if (!cancelFlag->exchange(true, std::memory_order_acq_rel)) {
            if (progressPtr) {
                progressPtr->setLabelText(tr("Cancelling ceremony..."));
            }
        }
    });

    progress->setWindowModality(Qt::WindowModal);
    progress->setMinimumDuration(0);
    progress->show();

    // Taker participates as responder (is_initiator=false)
    // (Session already inserted at function entry to prevent TOCTOU race)
    // Avoid parenting to 'this' to prevent potential double free on shutdown
    auto* watcher = new QFutureWatcher<WalletModel::CosignAdaptorRoundtripResult>(nullptr);

    connect(watcher, &QFutureWatcher<WalletModel::CosignAdaptorRoundtripResult>::finished, this,
            [this, watcher, progressPtr, session_id, cancelFlag]() {
        if (progressPtr) {
            progressPtr->close();
            progressPtr->deleteLater();
        }

        auto ceremonyResult = watcher->result();
        watcher->deleteLater();

        ceremonySessions.remove(session_id);

        const QString requestId = activeSessions.value(session_id);
        if (!requestId.isEmpty() && activeRequests.contains(requestId)) {
            TradeRequestInfo& infoRef = activeRequests[requestId];
            infoRef.recovering_session = false;
            infoRef.taker_ready_for_ceremony = false;
            infoRef.waiting_for_base_notice_sent = false;
            infoRef.ceremony_ready_sent = false;
        }

        if (!ceremonyResult.success) {
            // Common failure cleanup, runs for cancel / abort / timeout / any
            // other non-success exit. Symmetric with the maker handler — see
            // there for the rationale on why a peer ceremony_abort must
            // always trigger the unlock + close path even though it neither
            // sets session_lost nor matches the legacy timeout heuristic.
            if (!requestId.isEmpty() && activeRequests.contains(requestId)) {
                TradeRequestInfo& infoRef = activeRequests[requestId];
                if (infoRef.psbt_locked) {
                    const char* ctxStr = ceremonyResult.cancelled ? "cancellation" : "failure";
                    LogPrintf("TradeBoardTab: [Taker] Unlocking PSBT for request %s after ceremony %s\n",
                              requestId.toStdString().c_str(), ctxStr);
                    if (!infoRef.augmented_psbt.isEmpty()) {
                        UnlockFairSignUTXOsForPsbt(walletModel, infoRef.augmented_psbt,
                                                   ceremonyResult.cancelled
                                                       ? "Taker ceremony cancellation"
                                                       : "Taker ceremony failure");
                    }
                    infoRef.psbt_locked = false;
                    infoRef.augmented_psbt.clear();
                    infoRef.augmented_psbt_hash.clear();
                }
            }
            if (walletModel) {
                walletModel->cosignClose(session_id);  // best-effort
            }
            activeSessions.remove(session_id);
            if (sessionManager) {
                sessionManager->removeSession(session_id);
            }

            if (ceremonyResult.cancelled) {
                showAutoClosingInfo(tr("Ceremony Cancelled"),
                    tr("Opening ceremony was cancelled. You can restart it from the Trade Board when ready."));
            } else {
                QMessageBox::critical(this, tr("Ceremony Failed"),
                    tr("Adaptor ceremony failed:\n\n%1\n\n"
                       "The session has been closed.").arg(ceremonyResult.error));

                const QString lower = ceremonyResult.error.toLower();
                if (ceremonyResult.session_lost ||
                    lower.contains("session not found") ||
                    lower.contains("unknown session") ||
                    lower.contains("session expired") ||
                    lower.contains("bridge restarted")) {
                    if (!requestId.isEmpty()) {
                        handleSessionLoss(session_id, requestId, ceremonyResult.error);
                    }
                }
            }

            updateOffersList();
            updateTradeRequestsList();
            return;
        }

        // Taker doesn't broadcast - just waits for maker to finalize and broadcast
        LogPrintf("TradeBoardTab: Taker ceremony completed successfully\n");

        // UNLOCK COINS: Clear the locked PSBT after successful ceremony completion
        if (!requestId.isEmpty() && activeRequests.contains(requestId)) {
            TradeRequestInfo& infoRef = activeRequests[requestId];
            if (infoRef.psbt_locked) {
                LogPrintf("TradeBoardTab: [Taker] Unlocking PSBT for request %s after successful ceremony\n",
                          requestId.toStdString().c_str());
                // Unlock wallet-level Fair-Sign UTXOs
                if (!infoRef.augmented_psbt.isEmpty()) {
                    UnlockFairSignUTXOsForPsbt(walletModel, infoRef.augmented_psbt, "Taker ceremony success");
                }
                infoRef.psbt_locked = false;
                infoRef.augmented_psbt.clear();
                infoRef.augmented_psbt_hash.clear();
            }
        }

        // Cooperative path differs in wording: by the time the taker runner
        // returns success, the maker has already broadcast the transaction
        // and sent a ceremony_complete envelope with the txid — there's no
        // "waiting for maker" step left. Reading info.cooperative_consent
        // is safe here because it was set at "Pre-sign and Continue" time
        // and isn't cleared on success.
        bool takerCooperativePath = false;
        {
            const QString requestId = activeSessions.value(session_id);
            if (!requestId.isEmpty() && activeRequests.contains(requestId)) {
                takerCooperativePath = activeRequests[requestId].cooperative_consent;
            }
        }
        if (takerCooperativePath) {
            const QString txidLine = ceremonyResult.txid.isEmpty()
                ? QString()
                : tr("Transaction ID: %1\n\n").arg(ceremonyResult.txid);
            showAutoClosingInfo(tr("Ceremony Complete"),
                tr("✓ Cooperative (non-atomic) signing completed.\n\n"
                   "Your counterparty has finalised and broadcast the transaction.\n\n"
                   "%1"
                   "The contract will automatically appear in Active Contracts once confirmed.")
                    .arg(txidLine));
        } else {
            showAutoClosingInfo(tr("Ceremony Complete"),
                tr("✓ Adaptor ceremony completed successfully!\n\n"
                   "Waiting for maker to finalize and broadcast the opening transaction...\n\n"
                   "The contract will automatically appear in Active Contracts once confirmed."));
        }

        // Remove session from active polling
        activeSessions.remove(session_id);

        // Refresh UI and trigger registry update
        updateOffersList();
        updateTradeRequestsList();
        if (walletModel) {
            Q_EMIT walletModel->balanceChanged(walletModel->wallet().getBalances());
        }
        return;
    });

    // Run ceremony using TradeCeremonyRunner (immutability pattern - both sides have same augmented PSBT)
    QString localBaseCopy = localBase;
    QString makerBaseCopy = info.maker_base_psbt;
    const QString infoRequestId = info.request_id;
    const bool cooperativeConsent = info.cooperative_consent;
    auto mergedPsbtCallback = [this, infoRequestId](const QString& mergedPsbt) {
        if (mergedPsbt.isEmpty() || infoRequestId.isEmpty()) {
            return;
        }
        QMetaObject::invokeMethod(this, [this, infoRequestId, mergedPsbt]() {
            if (!activeRequests.contains(infoRequestId)) {
                return;
            }
            TradeRequestInfo& infoRef = activeRequests[infoRequestId];
            infoRef.merged_ceremony_psbt = mergedPsbt;
            infoRef.merged_ceremony_psbt_hash = ComputePsbtTxHash(mergedPsbt);
            LogPrintf("TradeBoardTab: (TAKER) Cached merged ceremony PSBT (%d bytes) for request %s\n",
                      mergedPsbt.length(), infoRequestId.toStdString().c_str());
        }, Qt::QueuedConnection);
    };
    auto inflightGuard = std::make_shared<InflightGuard>(this);
    QFuture<WalletModel::CosignAdaptorRoundtripResult> future = QtConcurrent::run(
        [this, inflightGuard, contractId, session_id, takerRole, cancelFlag, localBaseCopy, makerBaseCopy, borrowerAddress, lenderAddress, progress, mergedPsbtCallback, cooperativeConsent]() {
            (void)inflightGuard;
            auto progressCallback = [progress](CeremonyPhase phase, const QString& message) {
                QMetaObject::invokeMethod(progress, [progress, phase, message]() {
                    QString phaseText;
                    switch (phase) {
                        case CeremonyPhase::PHASE0_BASE:
                            phaseText = QObject::tr("Phase 0/4: Synchronizing base PSBT");
                            break;
                        case CeremonyPhase::PHASE1_ATTEST:
                            phaseText = QObject::tr("Phase 1/4: BIP-322 peer attestation");
                            break;
                        case CeremonyPhase::PHASE2_NONCE:
                            phaseText = QObject::tr("Phase 2/4: Exchanging nonce commitments");
                            break;
                        case CeremonyPhase::PHASE3_PARTIAL:
                            phaseText = QObject::tr("Phase 3/4: Exchanging partial signatures");
                            break;
                        case CeremonyPhase::PHASE4_COMPLETE:
                            phaseText = QObject::tr("Phase 4/4: Finalizing transaction");
                            break;
                        default:
                            phaseText = message;
                            break;
                    }
                    progress->setLabelText(phaseText + "\n\n" + message);
                }, Qt::QueuedConnection);
            };
            // Immutability pattern: both sides use same augmented PSBT, no staged peer base needed
            TradeCeremonyRunner runner(walletModel, contractId, session_id, localBaseCopy, takerRole, false,
                                       QString(), QString(), makerBaseCopy, borrowerAddress, lenderAddress, cancelFlag,
                                       progressCallback, mergedPsbtCallback, cooperativeConsent);
            return runner.run();
        }
    );
    watcher->setFuture(future);
}
namespace {
double readDouble(const QVariant& value, double fallback = 0.0)
{
    bool ok = false;
    const double result = value.toDouble(&ok);
    return ok ? result : fallback;
}
}

void TradeBoardTab::populateRepoTermsFromSummary(TradeRequestInfo& info, const QVariantMap& summary)
{
    if (summary.isEmpty()) return;

    auto resolveAssetLabel = [](const QVariantMap& map,
                                const char* assetKey,
                                const char* assetTickerKey,
                                const char* isNativeKey,
                                const QString& fallback) -> QString {
        QString asset = map.value(assetKey).toString();
        if (asset.isEmpty()) {
            asset = map.value(assetTickerKey).toString();
        }
        if (asset.isEmpty()) {
            if (map.contains(isNativeKey) && map.value(isNativeKey).toBool()) {
                asset = fallback;
            }
        }
        return asset.isEmpty() ? fallback : asset;
    };

    const double principalAmount = readDouble(summary.value("principal_amount"), info.principal_qty);
    const double collateralAmount = readDouble(summary.value("collateral_amount"), info.collateral_qty);
    double interestAmount = readDouble(summary.value("interest_amount"), info.interest_qty);
    const double aprValue = readDouble(summary.value("apr"), info.apr);
    const double ltvValue = readDouble(summary.value("ltv"), info.ltv);
    const int tenorValue = summary.value("tenor_days", info.tenor_days).toInt();
    const int maturityHeightValue = summary.value("maturity_height", info.maturity_height).toInt();

    QString principalAsset = resolveAssetLabel(summary, "principal_asset", "principal_asset_ticker",
                                               "principal_is_native", info.principal_asset.isEmpty() ? QStringLiteral("TSC") : info.principal_asset);
    QString collateralAsset = resolveAssetLabel(summary, "collateral_asset", "collateral_asset_ticker",
                                                "collateral_is_native", info.collateral_asset.isEmpty() ? QStringLiteral("TSC") : info.collateral_asset);
    QString interestAsset = resolveAssetLabel(summary, "interest_asset", "interest_asset_ticker",
                                              "interest_is_native", principalAsset);

    // Derive interest from APR if not present
    if (interestAmount <= 0.0 && principalAmount > 0.0 && aprValue > 0.0 && tenorValue > 0) {
        interestAmount = principalAmount * (aprValue / 100.0) * (static_cast<double>(tenorValue) / 365.0);
    }

    bool anyUpdated = false;
    auto assignIfChanged = [&](double& target, double value) {
        if (!qFuzzyCompare(target, value)) {
            target = value;
            anyUpdated = true;
        }
    };

    assignIfChanged(info.principal_qty, principalAmount);
    assignIfChanged(info.collateral_qty, collateralAmount);
    assignIfChanged(info.interest_qty, interestAmount);
    assignIfChanged(info.apr, aprValue);
    assignIfChanged(info.ltv, ltvValue);
    if (info.tenor_days != tenorValue) { info.tenor_days = tenorValue; anyUpdated = true; }
    if (info.maturity_height != maturityHeightValue) { info.maturity_height = maturityHeightValue; anyUpdated = true; }

    if (!principalAsset.isEmpty() && principalAsset != info.principal_asset) {
        info.principal_asset = principalAsset;
        anyUpdated = true;
    }
    if (!collateralAsset.isEmpty() && collateralAsset != info.collateral_asset) {
        info.collateral_asset = collateralAsset;
        anyUpdated = true;
    }
    if (!interestAsset.isEmpty() && interestAsset != info.interest_asset) {
        info.interest_asset = interestAsset;
        anyUpdated = true;
    }

    info.terms_available = info.terms_available || anyUpdated;
}

void TradeBoardTab::populateRepoTermsFromJson(TradeRequestInfo& info, const QJsonObject& obj)
{
    if (obj.isEmpty()) return;

    QJsonObject terms;
    if (obj.contains("terms") && obj.value("terms").isObject()) {
        terms = obj.value("terms").toObject();
    } else if (obj.contains("offer") && obj.value("offer").isObject()) {
        terms = obj.value("offer").toObject();
        if (terms.contains("terms") && terms.value("terms").isObject()) {
            terms = terms.value("terms").toObject();
        }
    }

    if (terms.isEmpty()) {
        populateRepoTermsFromSummary(info, QJsonObject(obj).toVariantMap());
        return;
    }

    auto resolveAssetLabel = [&](const QString& assetIdOrLabel) -> QString {
        if (assetIdOrLabel.isEmpty()) return QString();
        // If already looks like a short label, keep it
        if (assetIdOrLabel == QLatin1String("TSC")) return assetIdOrLabel;
        if (walletModel) {
            WalletModel::AssetInfo ai = walletModel->getAssetInfo(assetIdOrLabel);
            if (!ai.ticker.isEmpty()) return ai.ticker;
        }
        // Fallback: shorten raw id
        return assetIdOrLabel.left(8) + "...";
    };

    auto amountFromUnits = [&](const QJsonObject& leg, const char* unitsKey, const char* isNativeKey,
                               const char* assetKey, const QString& fallbackAssetLabel) -> std::pair<double, QString> {
        double units = leg.value(unitsKey).toDouble();
        bool isNative = leg.value(isNativeKey).toBool(true);
        QString assetId = leg.value(assetKey).toString();
        QString label;
        if (isNative) {
            label = QStringLiteral("TSC");
        } else if (!assetId.isEmpty()) {
            label = resolveAssetLabel(assetId);
        } else {
            label = fallbackAssetLabel;
        }

        int decimals = 8;
        if (!isNative && walletModel) {
            WalletModel::AssetInfo assetInfo = walletModel->getAssetInfo(assetId);
            if (assetInfo.has_decimals) decimals = assetInfo.decimals;
        }
        double amount = (decimals > 0) ? units / std::pow(10.0, decimals) : units;
        return {amount, label};
    };

    auto extractLeg = [&](const char* key,
                          const char* fallbackUnits,
                          const char* fallbackIsNative,
                          const char* fallbackAsset,
                          const QString& defaultAssetLabel) -> std::pair<double, QString> {
        if (terms.contains(key) && terms.value(key).isObject()) {
            return amountFromUnits(terms.value(key).toObject(), "units", "is_native", "asset_id", defaultAssetLabel);
        }
        QJsonObject fallback;
        fallback.insert("units", terms.value(fallbackUnits));
        fallback.insert("is_native", terms.value(fallbackIsNative));
        fallback.insert("asset_id", terms.value(fallbackAsset));
        return amountFromUnits(fallback, "units", "is_native", "asset_id", defaultAssetLabel);
    };

    auto [principalAmount, principalAssetLabel] = extractLeg("principal_leg", "principal_units",
                                                            "principal_is_native", "principal_asset_id", QStringLiteral("TSC"));
    auto [interestAmount, interestAssetLabel] = extractLeg("interest_leg", "interest_units",
                                                          "interest_is_native", "interest_asset_id", principalAssetLabel);
    auto [collateralAmount, collateralAssetLabel] = extractLeg("collateral_leg", "collateral_units",
                                                              "collateral_is_native", "collateral_asset_id", QStringLiteral("TSC"));

    if (qFuzzyIsNull(collateralAmount)) {
        collateralAmount = terms.value("collateral_sats").toDouble() / 100000000.0;
    }

    QVariantMap tmp;
    tmp.insert("principal_amount", principalAmount);
    tmp.insert("principal_asset", principalAssetLabel);
    tmp.insert("collateral_amount", collateralAmount);
    tmp.insert("collateral_asset", collateralAssetLabel);
    tmp.insert("interest_amount", interestAmount);
    tmp.insert("interest_asset", interestAssetLabel);
    if (terms.contains("apr")) tmp.insert("apr", terms.value("apr").toDouble());
    if (terms.contains("ltv")) tmp.insert("ltv", terms.value("ltv").toDouble());
    if (terms.contains("tenor_days")) tmp.insert("tenor_days", terms.value("tenor_days").toInt());
    if (terms.contains("maturity_height")) tmp.insert("maturity_height", terms.value("maturity_height").toInt());

    populateRepoTermsFromSummary(info, tmp);
}

void TradeBoardTab::populateSpotTermsFromJson(TradeRequestInfo& info, const QJsonObject& obj)
{
    if (obj.isEmpty()) return;

    // Extract basic spot info for TradeRequestInfo (detailed population happens in snapshot)
    QJsonObject terms;
    if (obj.contains("terms") && obj.value("terms").isObject()) {
        terms = obj.value("terms").toObject();
    }

    // Store contract ID if available
    if (obj.contains("id")) {
        QString contractId = obj.value("id").toString();
        if (!contractId.isEmpty() && info.final_offer_id.isEmpty()) {
            info.final_offer_id = contractId;
        }
    }

    // Note: alice/bob addresses are extracted in snapshot population
    // TradeRequestInfo doesn't have spot-specific address fields

    info.terms_available = true;
}

void TradeBoardTab::populateSpotTermsFromJson(FinalContractSnapshot& snapshot, const QJsonObject& obj)
{
    if (obj.isEmpty()) return;

    // Extract terms object
    QJsonObject terms;
    if (obj.contains("terms") && obj.value("terms").isObject()) {
        terms = obj.value("terms").toObject();
    } else if (obj.contains("offer") && obj.value("offer").isObject()) {
        terms = obj.value("offer").toObject();
        if (terms.contains("terms") && terms.value("terms").isObject()) {
            terms = terms.value("terms").toObject();
        }
    }

    if (terms.isEmpty()) {
        LogPrintf("TradeBoardTab::populateSpotTermsFromJson: No terms found in JSON\n");
        return;
    }

    auto resolveAssetLabel = [&](const QString& assetIdOrLabel) -> QString {
        if (assetIdOrLabel.isEmpty()) return QString();
        if (assetIdOrLabel == QLatin1String("TSC")) return assetIdOrLabel;
        if (walletModel) {
            WalletModel::AssetInfo ai = walletModel->getAssetInfo(assetIdOrLabel);
            if (!ai.ticker.isEmpty()) return ai.ticker;
        }
        return assetIdOrLabel.left(8) + "...";
    };

    // Parse alice_leg (what Alice sends, Bob receives)
    if (terms.contains("alice_leg") && terms.value("alice_leg").isObject()) {
        QJsonObject aliceLeg = terms.value("alice_leg").toObject();
        bool isNative = aliceLeg.value("is_native").toBool(true);
        QString assetId = aliceLeg.value("asset_id").toString();
        double units = aliceLeg.value("units").toDouble();

        QString label;
        if (isNative) {
            label = QStringLiteral("TSC");
        } else if (!assetId.isEmpty()) {
            label = resolveAssetLabel(assetId);
        }

        int decimals = 8;
        if (!isNative && walletModel) {
            WalletModel::AssetInfo assetInfo = walletModel->getAssetInfo(assetId);
            if (assetInfo.has_decimals) decimals = assetInfo.decimals;
        }
        double amount = (decimals > 0) ? units / std::pow(10.0, decimals) : units;

        snapshot.spot.alice_send_qty = amount;
        snapshot.spot.alice_send_asset = label;
        snapshot.spot.alice_send_asset_id = isNative ? QString() : assetId;

        // Alice receives what Bob sends (bob_leg), but set alice recv values when we parse bob_leg
        snapshot.spot.bob_recv_qty = amount;
        snapshot.spot.bob_recv_asset = label;
        snapshot.spot.bob_recv_asset_id = isNative ? QString() : assetId;
    }

    // Parse bob_leg (what Bob sends, Alice receives)
    if (terms.contains("bob_leg") && terms.value("bob_leg").isObject()) {
        QJsonObject bobLeg = terms.value("bob_leg").toObject();
        bool isNative = bobLeg.value("is_native").toBool(true);
        QString assetId = bobLeg.value("asset_id").toString();
        double units = bobLeg.value("units").toDouble();

        QString label;
        if (isNative) {
            label = QStringLiteral("TSC");
        } else if (!assetId.isEmpty()) {
            label = resolveAssetLabel(assetId);
        }

        int decimals = 8;
        if (!isNative && walletModel) {
            WalletModel::AssetInfo assetInfo = walletModel->getAssetInfo(assetId);
            if (assetInfo.has_decimals) decimals = assetInfo.decimals;
        }
        double amount = (decimals > 0) ? units / std::pow(10.0, decimals) : units;

        snapshot.spot.bob_send_qty = amount;
        snapshot.spot.bob_send_asset = label;
        snapshot.spot.bob_send_asset_id = isNative ? QString() : assetId;

        // Bob receives what Alice sends (alice_leg), but set bob recv values
        snapshot.spot.alice_recv_qty = amount;
        snapshot.spot.alice_recv_asset = label;
        snapshot.spot.alice_recv_asset_id = isNative ? QString() : assetId;
    }

    // Extract addresses
    if (obj.contains("alice_address") && !obj.value("alice_address").isNull()) {
        snapshot.spot.alice_dest = obj.value("alice_address").toString();
    }
    // Check both bob_address and bob_address_hint (finalized offers use bob_address)
    if (obj.contains("bob_address") && !obj.value("bob_address").isNull()) {
        snapshot.spot.bob_dest = obj.value("bob_address").toString();
    } else if (obj.contains("bob_address_hint") && !obj.value("bob_address_hint").isNull()) {
        snapshot.spot.bob_dest = obj.value("bob_address_hint").toString();
    }

    LogPrintf("TradeBoardTab::populateSpotTermsFromJson: Alice sends %f %s, receives %f %s; Bob sends %f %s, receives %f %s\n",
              snapshot.spot.alice_send_qty, snapshot.spot.alice_send_asset.toStdString().c_str(),
              snapshot.spot.alice_recv_qty, snapshot.spot.alice_recv_asset.toStdString().c_str(),
              snapshot.spot.bob_send_qty, snapshot.spot.bob_send_asset.toStdString().c_str(),
              snapshot.spot.bob_recv_qty, snapshot.spot.bob_recv_asset.toStdString().c_str());
}

void TradeBoardTab::populateForwardTermsFromJson(TradeRequestInfo& info, const QJsonObject& obj)
{
    if (obj.isEmpty()) return;

    // Extract terms object (same pattern as repo)
    QJsonObject terms;
    if (obj.contains("terms") && obj.value("terms").isObject()) {
        terms = obj.value("terms").toObject();
    } else if (obj.contains("offer") && obj.value("offer").isObject()) {
        QJsonObject offer = obj.value("offer").toObject();
        if (offer.contains("terms") && offer.value("terms").isObject()) {
            terms = offer.value("terms").toObject();
        }
    }

    if (terms.isEmpty()) {
        LogPrintf("TradeBoardTab: Forward terms object is empty, cannot populate\n");
        return;
    }

    // Helper: resolve asset ticker via registry (reuse from repo pattern)
    auto resolveAssetLabel = [&](const QString& assetIdOrLabel) -> QString {
        if (assetIdOrLabel.isEmpty()) return QString();
        if (assetIdOrLabel == QLatin1String("TSC")) return assetIdOrLabel;
        if (walletModel) {
            WalletModel::AssetInfo ai = walletModel->getAssetInfo(assetIdOrLabel);
            if (!ai.ticker.isEmpty()) return ai.ticker;
        }
        return assetIdOrLabel.left(8) + "...";
    };

    // Helper: convert units to decimal amount with asset-specific decimals
    auto amountFromUnits = [&](const QJsonObject& leg, const char* unitsKey,
                               const char* isNativeKey, const char* assetKey,
                               const QString& fallbackAssetLabel) -> std::pair<double, QString> {
        double units = leg.value(unitsKey).toDouble();
        bool isNative = leg.value(isNativeKey).toBool(false);
        QString assetId = leg.value(assetKey).toString();
        QString label;

        if (isNative) {
            label = QStringLiteral("TSC");
        } else if (!assetId.isEmpty()) {
            label = resolveAssetLabel(assetId);
        } else {
            label = fallbackAssetLabel;
        }

        int decimals = 8;
        if (!isNative && walletModel) {
            WalletModel::AssetInfo assetInfo = walletModel->getAssetInfo(assetId);
            if (assetInfo.has_decimals) decimals = assetInfo.decimals;
        }
        double amount = (decimals > 0) ? units / std::pow(10.0, decimals) : units;
        return {amount, label};
    };

    // Parse long_party
    if (terms.contains("long_party") && terms.value("long_party").isObject()) {
        QJsonObject longParty = terms.value("long_party").toObject();

        // Deliver leg
        if (longParty.contains("deliver_leg") && longParty.value("deliver_leg").isObject()) {
            QJsonObject deliverLeg = longParty.value("deliver_leg").toObject();
            auto [qty, asset] = amountFromUnits(deliverLeg, "units", "is_native", "asset_id", "UNKNOWN");
            info.long_deliver_qty = qty;
            info.long_deliver_asset = asset;
            info.long_deliver_asset_id = deliverLeg.value("asset_id").toString();
        }

        // Margin leg
        if (longParty.contains("margin_leg") && longParty.value("margin_leg").isObject()) {
            QJsonObject marginLeg = longParty.value("margin_leg").toObject();
            auto [qty, asset] = amountFromUnits(marginLeg, "units", "is_native", "asset_id", "UNKNOWN");
            info.long_margin_qty = qty;
            info.long_margin_asset = asset;
            info.long_margin_asset_id = marginLeg.value("asset_id").toString();
        }

        // Addresses
        info.long_margin_dest = longParty.value("margin_dest").toString();
        info.long_settlement_dest = longParty.value("settlement_receive_dest").toString();
    }

    // Parse short_party (identical pattern)
    if (terms.contains("short_party") && terms.value("short_party").isObject()) {
        QJsonObject shortParty = terms.value("short_party").toObject();

        // Deliver leg
        if (shortParty.contains("deliver_leg") && shortParty.value("deliver_leg").isObject()) {
            QJsonObject deliverLeg = shortParty.value("deliver_leg").toObject();
            auto [qty, asset] = amountFromUnits(deliverLeg, "units", "is_native", "asset_id", "UNKNOWN");
            info.short_deliver_qty = qty;
            info.short_deliver_asset = asset;
            info.short_deliver_asset_id = deliverLeg.value("asset_id").toString();
        }

        // Margin leg
        if (shortParty.contains("margin_leg") && shortParty.value("margin_leg").isObject()) {
            QJsonObject marginLeg = shortParty.value("margin_leg").toObject();
            auto [qty, asset] = amountFromUnits(marginLeg, "units", "is_native", "asset_id", "UNKNOWN");
            info.short_margin_qty = qty;
            info.short_margin_asset = asset;
            info.short_margin_asset_id = marginLeg.value("asset_id").toString();
        }

        // Addresses
        info.short_margin_dest = shortParty.value("margin_dest").toString();
        info.short_settlement_dest = shortParty.value("settlement_receive_dest").toString();
    }

    // Parse premium (optional)
    if (terms.contains("premium") && terms.value("premium").isObject()) {
        QJsonObject premium = terms.value("premium").toObject();
        auto [qty, asset] = amountFromUnits(premium, "units", "is_native", "asset_id", "UNKNOWN");
        info.premium_amount = qty;
        info.premium_asset = asset;
        info.premium_asset_id = premium.value("asset_id").toString();
        info.premium_payer = premium.value("payer").toString(); // "long" or "short"
        info.premium_payee_dest = premium.value("payee_dest").toString();
    }

    // Parse deadlines
    info.deadline_short = terms.value("deadline_short").toInt();
    info.deadline_long = terms.value("deadline_long").toInt();
    info.safety_k = terms.value("safety_k").toInt();
    info.reorg_conf = terms.value("reorg_conf").toInt();

    // Parse maker role
    if (obj.contains("maker_role")) {
        info.maker_role = obj.value("maker_role").toString().toLower(); // "long" or "short"
    }

    // Compute derived metrics for display
    if (info.long_deliver_qty > 0) {
        info.long_im_percent = (info.long_margin_qty / info.long_deliver_qty) * 100.0;
    }
    if (info.short_deliver_qty > 0) {
        info.short_im_percent = (info.short_margin_qty / info.short_deliver_qty) * 100.0;
    }

    // Compute tenor days from deadlines (requires current height)
    if (walletModel) {
        int currentHeight = walletModel->clientModel().node().getNumBlocks();
        info.tenor_days_short = std::max(0, (info.deadline_short - currentHeight) / 144);
        info.tenor_days_long = std::max(0, (info.deadline_long - currentHeight) / 144);
    }

    info.terms_available = true;

    LogPrintf("TradeBoardTab: Populated forward terms - long deliver: %f %s, short deliver: %f %s, premium: %f %s (payer: %s)\n",
              info.long_deliver_qty, info.long_deliver_asset.toStdString().c_str(),
              info.short_deliver_qty, info.short_deliver_asset.toStdString().c_str(),
              info.premium_amount, info.premium_asset.toStdString().c_str(),
              info.premium_payer.toStdString().c_str());
}

// OfferInfo overload
void TradeBoardTab::populateForwardTermsFromJson(OfferInfo& info, const QJsonObject& obj)
{
    // Extract terms object
    QJsonObject terms;
    if (obj.contains("terms") && obj.value("terms").isObject()) {
        terms = obj.value("terms").toObject();
    }

    // Helper: resolve asset label via registry
    auto resolveAssetLabel = [&](const QString& assetIdOrLabel) -> QString {
        if (assetIdOrLabel.isEmpty() || assetIdOrLabel == "native") return "TSC";
        if (!walletModel) return assetIdOrLabel.left(8);
        WalletModel::AssetInfo assetInfo = walletModel->getAssetInfo(assetIdOrLabel);
        return assetInfo.ticker.isEmpty() ? assetIdOrLabel.left(8) : assetInfo.ticker;
    };

    // Helper: convert units with asset decimals
    auto amountFromUnits = [&](const QJsonObject& leg, const QString& unitsKey,
                               const QString& isNativeKey, const QString& assetIdKey,
                               const QString& fallbackLabel) -> std::pair<double, QString> {
        double units = leg.value(unitsKey).toDouble();
        bool isNative = leg.value(isNativeKey).toBool();
        QString assetId = leg.value(assetIdKey).toString();
        QString label = isNative ? "TSC" : resolveAssetLabel(assetId);
        if (label.isEmpty() || label == assetId) label = fallbackLabel;
        int decimals = 8;
        if (!isNative && walletModel) {
            WalletModel::AssetInfo assetInfo = walletModel->getAssetInfo(assetId);
            if (assetInfo.has_decimals) decimals = assetInfo.decimals;
        }
        double amount = (decimals > 0) ? units / std::pow(10.0, decimals) : units;
        return {amount, label};
    };

    // Parse long_party
    if (terms.contains("long_party") && terms.value("long_party").isObject()) {
        QJsonObject longParty = terms.value("long_party").toObject();

        // Deliver leg
        if (longParty.contains("deliver_leg") && longParty.value("deliver_leg").isObject()) {
            QJsonObject deliverLeg = longParty.value("deliver_leg").toObject();
            auto [qty, asset] = amountFromUnits(deliverLeg, "units", "is_native", "asset_id", "UNKNOWN");
            info.long_deliver_qty = qty;
            info.long_deliver_asset = asset;
            info.long_deliver_asset_id = deliverLeg.value("asset_id").toString();
        }

        // IM leg
        if (longParty.contains("im_leg") && longParty.value("im_leg").isObject()) {
            QJsonObject imLeg = longParty.value("im_leg").toObject();
            auto [qty, asset] = amountFromUnits(imLeg, "units", "is_native", "asset_id", "UNKNOWN");
            info.long_margin_qty = qty;
            info.long_margin_asset = asset;
            info.long_margin_asset_id = imLeg.value("asset_id").toString();
        }

        // Destinations
        info.long_margin_dest = longParty.value("im_recovery_dest").toString();
        info.long_settlement_dest = longParty.value("settlement_dest").toString();
    }

    // Parse short_party
    if (terms.contains("short_party") && terms.value("short_party").isObject()) {
        QJsonObject shortParty = terms.value("short_party").toObject();

        // Deliver leg
        if (shortParty.contains("deliver_leg") && shortParty.value("deliver_leg").isObject()) {
            QJsonObject deliverLeg = shortParty.value("deliver_leg").toObject();
            auto [qty, asset] = amountFromUnits(deliverLeg, "units", "is_native", "asset_id", "UNKNOWN");
            info.short_deliver_qty = qty;
            info.short_deliver_asset = asset;
            info.short_deliver_asset_id = deliverLeg.value("asset_id").toString();
        }

        // IM leg
        if (shortParty.contains("im_leg") && shortParty.value("im_leg").isObject()) {
            QJsonObject imLeg = shortParty.value("im_leg").toObject();
            auto [qty, asset] = amountFromUnits(imLeg, "units", "is_native", "asset_id", "UNKNOWN");
            info.short_margin_qty = qty;
            info.short_margin_asset = asset;
            info.short_margin_asset_id = imLeg.value("asset_id").toString();
        }

        // Destinations
        info.short_margin_dest = shortParty.value("im_recovery_dest").toString();
        info.short_settlement_dest = shortParty.value("settlement_dest").toString();
    }

    // Parse premium (optional)
    if (terms.contains("premium") && terms.value("premium").isObject()) {
        QJsonObject premium = terms.value("premium").toObject();
        auto [qty, asset] = amountFromUnits(premium, "units", "is_native", "asset_id", "UNKNOWN");
        info.premium_amount = qty;
        info.premium_asset = asset;
        info.premium_asset_id = premium.value("asset_id").toString();
        info.premium_payer = premium.value("payer").toString();
        info.premium_payee_dest = premium.value("payee_dest").toString();
    }

    // Parse deadlines
    info.deadline_short = terms.value("deadline_short").toInt();
    info.deadline_long = terms.value("deadline_long").toInt();
    info.safety_k = terms.value("safety_k").toInt();
    info.reorg_conf = terms.value("reorg_conf").toInt();

    // Compute IM percentages
    if (info.long_deliver_qty > 0.0) {
        info.long_im_percent = (info.long_margin_qty / info.long_deliver_qty) * 100.0;
    }
    if (info.short_deliver_qty > 0.0) {
        info.short_im_percent = (info.short_margin_qty / info.short_deliver_qty) * 100.0;
    }

    // Compute tenor days from deadlines
    if (walletModel && info.deadline_short > 0 && info.deadline_long > 0) {
        int currentHeight = walletModel->clientModel().node().getNumBlocks();
        info.tenor_days_short = std::max(0, (info.deadline_short - currentHeight) / 144);
        info.tenor_days_long = std::max(0, (info.deadline_long - currentHeight) / 144);
    }

    LogPrintf("TradeBoardTab: Populated forward terms (OfferInfo) - long deliver: %f %s, short deliver: %f %s, premium: %f %s (payer: %s)\n",
              info.long_deliver_qty, info.long_deliver_asset.toStdString().c_str(),
              info.short_deliver_qty, info.short_deliver_asset.toStdString().c_str(),
              info.premium_amount, info.premium_asset.toStdString().c_str(),
              info.premium_payer.toStdString().c_str());
}

// ============================================================================
// SNAPSHOT BUILDER FUNCTIONS - Immutable contract snapshots for modal dialogs
// ============================================================================

TradeBoardTab::FinalContractSnapshot TradeBoardTab::createTakerSnapshot(
    const QString& request_id,
    const QString& session_id,
    const QString& offer_id,
    const QString& offer_json,
    const QString& maker_base_psbt,
    const QString& user_role,
    const QString& fee_strategy,
    const TradeRequestInfo& fallbackInfo,
    const QString& contract_type_hint)
{
    FinalContractSnapshot snapshot;

    // Identity
    snapshot.contract_id = offer_id;
    snapshot.request_id = request_id;
    snapshot.session_id = session_id;
    snapshot.user_role = user_role.toLower();
    snapshot.selected_fee_strategy = fee_strategy;
    snapshot.is_taker = true;
    snapshot.is_maker = false;
    snapshot.maker_base_psbt = maker_base_psbt;

    // Parse offer JSON
    snapshot.offer_json = offer_json;
    QJsonParseError parseError;
    QJsonDocument offerDoc = QJsonDocument::fromJson(offer_json.toUtf8(), &parseError);
    if (offerDoc.isNull() || !offerDoc.isObject()) {
        LogPrintf("TradeBoardTab::createTakerSnapshot: Failed to parse offer JSON: %s\n",
                  parseError.errorString().toStdString().c_str());
        snapshot.summary_html = tr("ERROR: Failed to parse contract offer JSON");
        return snapshot;
    }

    snapshot.offer_obj = offerDoc.object();

    // CRITICAL: Use provided hint/canonical cache to get contract type
    snapshot.contract_type = contract_type_hint.toLower();
    if (snapshot.contract_type == "options") {
        snapshot.contract_type = QStringLiteral("option");
    }
    if (snapshot.contract_type.isEmpty()) {
        snapshot.contract_type = getCanonicalContractType(offer_id);
    }
    if (snapshot.contract_type.isEmpty()) {
        // Cache miss - try JSON extraction as fallback
        QString jsonType = snapshot.offer_obj.value("contract_type").toString().toLower();
        if (jsonType == "options") jsonType = QStringLiteral("option");
        if (!jsonType.isEmpty()) {
            snapshot.contract_type = jsonType;
            // Populate cache for future lookups
            cacheContractFlavor(offer_id, jsonType, offer_json, fallbackInfo.offer_id);
            LogPrintf("TradeBoardTab::createTakerSnapshot: Populated cache from JSON - offer_id=%s, type=%s\n",
                      offer_id.toStdString().c_str(), jsonType.toStdString().c_str());
        } else if (fallbackInfo.offer_summary.contains("contract_type")) {
            snapshot.contract_type = fallbackInfo.offer_summary.value("contract_type").toString().toLower();
            if (snapshot.contract_type == "options") {
                snapshot.contract_type = QStringLiteral("option");
            }
        }
    }
    if (snapshot.contract_type.isEmpty()) {
        LogPrintf("TradeBoardTab::createTakerSnapshot: ERROR - Cannot determine contract type for %s\n",
                  offer_id.toStdString().c_str());
        snapshot.summary_html = tr("ERROR: Cannot determine contract type");
        return snapshot;
    }
    LogPrintf("TradeBoardTab::createTakerSnapshot: Using contract type=%s for offer %s\n",
              snapshot.contract_type.toStdString().c_str(), offer_id.toStdString().c_str());

    // CRITICAL FIX: Use existing battle-tested parsers instead of reimplementing
    // This ensures proper asset decimal handling, ticker resolution, and terms extraction
    TradeRequestInfo tempInfo;  // Temporary container for existing parsers
    tempInfo.terms_available = false;

    if (snapshot.contract_type == "repo") {
        // Use existing repo parser (handles terms object, asset decimals, etc.)
        populateRepoTermsFromJson(tempInfo, snapshot.offer_obj);

        // Copy parsed data to snapshot
        auto& repo = snapshot.repo;
        repo.principal_qty = tempInfo.principal_qty;
        repo.principal_asset = tempInfo.principal_asset;
        repo.collateral_qty = tempInfo.collateral_qty;
        repo.collateral_asset = tempInfo.collateral_asset;
        repo.interest_qty = tempInfo.interest_qty;
        repo.interest_asset = tempInfo.interest_asset;
        repo.apr = tempInfo.apr;
        repo.ltv = tempInfo.ltv;
        repo.tenor_days = tempInfo.tenor_days;
        repo.maturity_height = tempInfo.maturity_height;
        repo.borrower_address = tempInfo.borrower_address;
        repo.lender_address = tempInfo.lender_address;

    } else if (snapshot.contract_type == "forward" || snapshot.contract_type == "option") {
        // Use existing forward parser (handles terms object, asset registry, decimals, etc.)
        populateForwardTermsFromJson(tempInfo, snapshot.offer_obj);

        // Copy parsed data to snapshot
        auto& fwd = snapshot.forward;
        fwd.long_deliver_qty = tempInfo.long_deliver_qty;
        fwd.long_deliver_asset = tempInfo.long_deliver_asset;
        fwd.long_deliver_asset_id = tempInfo.long_deliver_asset_id;
        fwd.long_margin_qty = tempInfo.long_margin_qty;
        fwd.long_margin_asset = tempInfo.long_margin_asset;
        fwd.long_margin_asset_id = tempInfo.long_margin_asset_id;
        fwd.long_im_percent = tempInfo.long_im_percent;
        fwd.long_margin_dest = tempInfo.long_margin_dest;
        fwd.long_settlement_dest = tempInfo.long_settlement_dest;

        fwd.short_deliver_qty = tempInfo.short_deliver_qty;
        fwd.short_deliver_asset = tempInfo.short_deliver_asset;
        fwd.short_deliver_asset_id = tempInfo.short_deliver_asset_id;
        fwd.short_margin_qty = tempInfo.short_margin_qty;
        fwd.short_margin_asset = tempInfo.short_margin_asset;
        fwd.short_margin_asset_id = tempInfo.short_margin_asset_id;
        fwd.short_im_percent = tempInfo.short_im_percent;
        fwd.short_margin_dest = tempInfo.short_margin_dest;
        fwd.short_settlement_dest = tempInfo.short_settlement_dest;

        fwd.premium_amount = tempInfo.premium_amount;
        fwd.premium_asset = tempInfo.premium_asset;
        fwd.premium_asset_id = tempInfo.premium_asset_id;
        fwd.premium_payer = tempInfo.premium_payer;
        fwd.premium_payee_dest = tempInfo.premium_payee_dest;

        fwd.deadline_short = tempInfo.deadline_short;
        fwd.deadline_long = tempInfo.deadline_long;
        fwd.safety_k = tempInfo.safety_k;
        fwd.reorg_conf = tempInfo.reorg_conf;
        fwd.maturity_height = tempInfo.deadline_long;

    } else if (snapshot.contract_type == "spot") {
        // Parse spot contract using dedicated spot parser
        populateSpotTermsFromJson(snapshot, snapshot.offer_obj);
    }

    auto applyAmountFallback = [](double& target, double fallback) {
        if (fallback <= 0.0) return;
        if (target <= 0.0) { target = fallback; return; }
        const double ratio = fallback == 0.0 ? 1.0 : target / fallback;
        if (ratio > 50.0 || ratio < 0.02) {
            target = fallback;
        }
    };
    auto applyStringFallback = [](QString& target, const QString& fallback) {
        if (fallback.isEmpty()) return;
        if (target.isEmpty() || target.endsWith("...")) {
            target = fallback;
        }
    };

    if (snapshot.contract_type == "repo") {
        const auto& fb = fallbackInfo;
        applyAmountFallback(snapshot.repo.principal_qty, fb.principal_qty);
        applyAmountFallback(snapshot.repo.collateral_qty, fb.collateral_qty);
        applyAmountFallback(snapshot.repo.interest_qty, fb.interest_qty);
        applyStringFallback(snapshot.repo.principal_asset, fb.principal_asset);
        applyStringFallback(snapshot.repo.collateral_asset, fb.collateral_asset);
        applyStringFallback(snapshot.repo.interest_asset, fb.interest_asset);
        if (snapshot.repo.borrower_address.isEmpty() && !fb.borrower_address.isEmpty()) {
            snapshot.repo.borrower_address = fb.borrower_address;
        }
        if (snapshot.repo.lender_address.isEmpty() && !fb.lender_address.isEmpty()) {
            snapshot.repo.lender_address = fb.lender_address;
        }
    } else if (snapshot.contract_type == "forward" || snapshot.contract_type == "option") {
        const auto& fb = fallbackInfo;
        applyAmountFallback(snapshot.forward.long_deliver_qty, fb.long_deliver_qty);
        applyAmountFallback(snapshot.forward.short_deliver_qty, fb.short_deliver_qty);
        applyAmountFallback(snapshot.forward.long_margin_qty, fb.long_margin_qty);
        applyAmountFallback(snapshot.forward.short_margin_qty, fb.short_margin_qty);
        applyAmountFallback(snapshot.forward.premium_amount, fb.premium_amount);
        applyStringFallback(snapshot.forward.long_deliver_asset, fb.long_deliver_asset);
        applyStringFallback(snapshot.forward.short_deliver_asset, fb.short_deliver_asset);
        applyStringFallback(snapshot.forward.long_margin_asset, fb.long_margin_asset);
        applyStringFallback(snapshot.forward.short_margin_asset, fb.short_margin_asset);
        if (snapshot.forward.long_margin_dest.isEmpty() && !fb.long_margin_dest.isEmpty()) {
            snapshot.forward.long_margin_dest = fb.long_margin_dest;
        }
        if (snapshot.forward.short_margin_dest.isEmpty() && !fb.short_margin_dest.isEmpty()) {
            snapshot.forward.short_margin_dest = fb.short_margin_dest;
        }
        if (snapshot.forward.long_settlement_dest.isEmpty() && !fb.long_settlement_dest.isEmpty()) {
            snapshot.forward.long_settlement_dest = fb.long_settlement_dest;
        }
        if (snapshot.forward.short_settlement_dest.isEmpty() && !fb.short_settlement_dest.isEmpty()) {
            snapshot.forward.short_settlement_dest = fb.short_settlement_dest;
        }
    }

    // Build display data
    snapshot.summary_html = buildSummaryHtml(snapshot);
    snapshot.critical_checks = buildCriticalChecks(snapshot);
    snapshot.raw_json_pretty = QString::fromUtf8(QJsonDocument(snapshot.offer_obj).toJson(QJsonDocument::Indented));

    LogPrintf("TradeBoardTab::createTakerSnapshot: Created snapshot for %s contract %s\n",
              snapshot.contract_type.toStdString().c_str(),
              snapshot.contract_id.toStdString().c_str());

    return snapshot;
}

TradeBoardTab::FinalContractSnapshot TradeBoardTab::createMakerSnapshot(
    const QString& request_id,
    const QString& session_id,
    const QString& offer_id,
    const QString& offer_json,
    const QString& acceptance_json,
    const QString& user_role)
{
    // Start with taker snapshot (parses offer using canonical cache)
    TradeRequestInfo fallback = activeRequests.value(request_id);
    FinalContractSnapshot snapshot = createTakerSnapshot(
        request_id, session_id, offer_id, offer_json,
        QString(),  // maker_base_psbt not needed here
        user_role, "medium", fallback, fallback.offer_summary.value("contract_type").toString());

    // Override taker/maker flags
    snapshot.is_taker = false;
    snapshot.is_maker = true;

    // Parse acceptance JSON
    snapshot.acceptance_json = acceptance_json;
    QJsonParseError parseError;
    QJsonDocument acceptanceDoc = QJsonDocument::fromJson(acceptance_json.toUtf8(), &parseError);
    if (!acceptanceDoc.isNull() && acceptanceDoc.isObject()) {
        snapshot.acceptance_obj = acceptanceDoc.object();
        snapshot.extra_json_pretty = QString::fromUtf8(QJsonDocument(snapshot.acceptance_obj).toJson(QJsonDocument::Indented));
        snapshot.extra_json_title = tr("Acceptance JSON");
    }

    // Try to get maker_base_psbt from activeRequests cache (safe single-access)
    if (activeRequests.contains(request_id)) {
        snapshot.maker_base_psbt = activeRequests[request_id].maker_base_psbt;
    }

    return snapshot;
}

QString TradeBoardTab::buildSummaryHtml(const FinalContractSnapshot& snapshot) const
{
    QString html;

    // Helper lambda to format address with ownership verification
    auto formatAddressWithOwnership = [this](const QString& address, bool shouldBeOwned) -> QString {
        if (address.isEmpty()) return tr("(not set)");
        if (!walletModel) return address;

        bool ok = false;
        bool owned = AddressOwnedByWallet(walletModel, address, &ok);

        if (!ok) {
            // Could not verify ownership
            return QString("<span style='color: #ff9800;'>%1 <b>[⚠ cannot verify]</b></span>").arg(address);
        }

        if (shouldBeOwned) {
            // This is supposed to be YOUR address
            if (owned) {
                // Good: your address IS owned by you
                return QString("<span style='color: #4caf50;'>%1 <b>[✓ owned]</b></span>").arg(address);
            } else {
                // Bad: your address is NOT owned by you
                return QString("<span style='color: #f44336;'><b>%1 [✗ NOT OWNED]</b></span>").arg(address);
            }
        } else {
            // This is supposed to be COUNTERPARTY's address
            if (owned) {
                // Warning: counterparty is using YOUR address!
                return QString("<span style='color: #f44336;'><b>%1 [⚠ WARNING: YOUR ADDRESS!]</b></span>").arg(address);
            } else {
                // Good: counterparty address is not yours (show in gray to indicate verified)
                return QString("<span style='color: #757575;'>%1 <b>[✓ not yours]</b></span>").arg(address);
            }
        }
    };

    if (snapshot.contract_type == "repo") {
        const auto& repo = snapshot.repo;
        QString perspectiveRole = snapshot.user_role;

        html += tr("<b>Contract Type:</b> Repo Contract<br>");
        html += tr("<b>Your Role:</b> %1<br>").arg(perspectiveRole == "lender" ? tr("Lender") : tr("Borrower"));
        html += tr("<b>Principal:</b> %1 %2<br>").arg(repo.principal_qty).arg(repo.principal_asset);
        html += tr("<b>Collateral:</b> %1 %2<br>").arg(repo.collateral_qty).arg(repo.collateral_asset);
        html += tr("<b>Interest:</b> %1 %2<br>").arg(repo.interest_qty).arg(repo.interest_asset);
        html += tr("<b>APR:</b> %1%<br>").arg(repo.apr, 0, 'f', 2);
        html += tr("<b>LTV:</b> %1%<br>").arg(repo.ltv, 0, 'f', 2);
        html += tr("<b>Tenor:</b> %1 days<br>").arg(repo.tenor_days);
        html += tr("<b>Maturity Height:</b> %1<br>").arg(repo.maturity_height);

        if (perspectiveRole == "lender") {
            html += tr("<b>Your Receive Address:</b> %1<br>").arg(formatAddressWithOwnership(repo.lender_address, true));
            html += tr("<b>Borrower Repay Address:</b> %1<br>").arg(formatAddressWithOwnership(repo.borrower_address, false));
        } else {
            html += tr("<b>Your Refund Address:</b> %1<br>").arg(formatAddressWithOwnership(repo.borrower_address, true));
            html += tr("<b>Lender Repay-to Address:</b> %1<br>").arg(formatAddressWithOwnership(repo.lender_address, false));
        }

    } else if (snapshot.contract_type == "forward" || snapshot.contract_type == "option") {
        const auto& fwd = snapshot.forward;
        QString perspectiveRole = snapshot.user_role;
        bool isOption = (snapshot.contract_type == "option");

        html += tr("<b>Contract Type:</b> %1<br>").arg(isOption ? tr("Options Contract") : tr("Forward Contract"));
        html += tr("<b>Your Role:</b> %1 Party<br>").arg(perspectiveRole == "long" ? tr("Long") : tr("Short"));

        if (perspectiveRole == "long") {
            html += tr("<b>You Deliver:</b> %1 %2<br>").arg(fwd.long_deliver_qty).arg(fwd.long_deliver_asset);
            html += tr("<b>You Receive:</b> %1 %2<br>").arg(fwd.short_deliver_qty).arg(fwd.short_deliver_asset);
            html += tr("<b>Your Initial Margin:</b> %1 %2 (%3%)<br>")
                        .arg(fwd.long_margin_qty).arg(fwd.long_margin_asset).arg(fwd.long_im_percent, 0, 'f', 1);
            html += tr("<b>Your Margin Destination:</b> %1<br>").arg(formatAddressWithOwnership(fwd.long_margin_dest, true));
            html += tr("<b>Your Settlement Receive:</b> %1<br>").arg(formatAddressWithOwnership(fwd.long_settlement_dest, true));
            html += tr("<b>Your Settlement Deadline:</b> Block %1<br>").arg(fwd.deadline_long);
        } else {
            html += tr("<b>You Deliver:</b> %1 %2<br>").arg(fwd.short_deliver_qty).arg(fwd.short_deliver_asset);
            html += tr("<b>You Receive:</b> %1 %2<br>").arg(fwd.long_deliver_qty).arg(fwd.long_deliver_asset);
            html += tr("<b>Your Initial Margin:</b> %1 %2 (%3%)<br>")
                        .arg(fwd.short_margin_qty).arg(fwd.short_margin_asset).arg(fwd.short_im_percent, 0, 'f', 1);
            html += tr("<b>Your Margin Destination:</b> %1<br>").arg(formatAddressWithOwnership(fwd.short_margin_dest, true));
            html += tr("<b>Your Settlement Receive:</b> %1<br>").arg(formatAddressWithOwnership(fwd.short_settlement_dest, true));
            html += tr("<b>Your Settlement Deadline:</b> Block %1<br>").arg(fwd.deadline_short);
        }

        if (isOption && fwd.premium_amount > 0) {
            bool youPayPremium = (fwd.premium_payer == perspectiveRole);
            html += tr("<b>Premium:</b> %1 %2 (%3)<br>")
                        .arg(fwd.premium_amount).arg(fwd.premium_asset)
                        .arg(youPayPremium ? tr("you pay") : tr("you receive"));
        }

        html += tr("<b>Maturity Height:</b> %1<br>").arg(fwd.maturity_height);

    } else if (snapshot.contract_type == "spot") {
        const auto& spot = snapshot.spot;
        QString perspectiveRole = snapshot.user_role;

        html += tr("<b>Contract Type:</b> Spot Swap<br>");
        html += tr("<b>Your Role:</b> %1<br>").arg(perspectiveRole == "alice" ? tr("Alice") : tr("Bob"));

        if (perspectiveRole == "alice") {
            html += tr("<b>You Send:</b> %1 %2<br>").arg(spot.alice_send_qty).arg(spot.alice_send_asset);
            html += tr("<b>You Receive:</b> %1 %2<br>").arg(spot.alice_recv_qty).arg(spot.alice_recv_asset);
            html += tr("<b>Your Receive Address:</b> %1<br>").arg(formatAddressWithOwnership(spot.alice_dest, true));
        } else {
            html += tr("<b>You Send:</b> %1 %2<br>").arg(spot.bob_send_qty).arg(spot.bob_send_asset);
            html += tr("<b>You Receive:</b> %1 %2<br>").arg(spot.bob_recv_qty).arg(spot.bob_recv_asset);
            html += tr("<b>Your Receive Address:</b> %1<br>").arg(formatAddressWithOwnership(spot.bob_dest, true));
        }
    } else {
        html = tr("<b>Unknown contract type:</b> %1").arg(snapshot.contract_type);
    }

    return html;
}

QStringList TradeBoardTab::buildCriticalChecks(const FinalContractSnapshot& snapshot) const
{
    QStringList checks;

    if (!walletModel) {
        return checks;  // Address verification now shown inline in summary
    }

    // Address ownership is now displayed inline in the summary HTML (buildSummaryHtml)
    // Only keep non-redundant checks here (e.g., proof of funds for spot contracts)

    try {
        if (snapshot.contract_type == "repo") {
            // No additional checks needed - addresses shown inline with ownership status

        } else if (snapshot.contract_type == "forward" || snapshot.contract_type == "option") {
            // No additional checks needed - addresses shown inline with ownership status

        } else if (snapshot.contract_type == "spot") {
            const auto& spot = snapshot.spot;
            QString perspectiveRole = snapshot.user_role;

            // Keep proof of funds checks as they provide additional value beyond address display
            if (perspectiveRole == "alice") {
                // Verify Alice has funds to send
                if (spot.alice_send_qty > 0) {
                    QString assetId = spot.alice_send_asset_id;
                    bool isNative = assetId.isEmpty();
                    double availableBalance = 0.0;

                    if (isNative) {
                        CAmount nativeBalance = walletModel->wallet().getBalance();
                        availableBalance = static_cast<double>(nativeBalance) / COIN;
                    } else {
                        // Get asset balances and find matching asset
                        auto assetBalances = walletModel->getAssetBalances();
                        for (const auto& assetBal : assetBalances) {
                            if (QString::fromStdString(assetBal.asset_id.ToString()) == assetId) {
                                availableBalance = static_cast<double>(assetBal.balance) / COIN;
                                break;
                            }
                        }
                    }

                    bool hasFunds = availableBalance >= spot.alice_send_qty;
                    checks << tr("Proof of Funds (Alice sends %1 %2): Available %3 %2 — %4")
                                  .arg(spot.alice_send_qty).arg(spot.alice_send_asset)
                                  .arg(availableBalance)
                                  .arg(hasFunds ? tr("✓ VERIFIED") : tr("✗ INSUFFICIENT"));
                }
            } else { // bob
                // Verify Bob has funds to send
                if (spot.bob_send_qty > 0) {
                    QString assetId = spot.bob_send_asset_id;
                    bool isNative = assetId.isEmpty();
                    double availableBalance = 0.0;

                    if (isNative) {
                        CAmount nativeBalance = walletModel->wallet().getBalance();
                        availableBalance = static_cast<double>(nativeBalance) / COIN;
                    } else {
                        // Get asset balances and find matching asset
                        auto assetBalances = walletModel->getAssetBalances();
                        for (const auto& assetBal : assetBalances) {
                            if (QString::fromStdString(assetBal.asset_id.ToString()) == assetId) {
                                availableBalance = static_cast<double>(assetBal.balance) / COIN;
                                break;
                            }
                        }
                    }

                    bool hasFunds = availableBalance >= spot.bob_send_qty;
                    checks << tr("Proof of Funds (Bob sends %1 %2): Available %3 %2 — %4")
                                  .arg(spot.bob_send_qty).arg(spot.bob_send_asset)
                                  .arg(availableBalance)
                                  .arg(hasFunds ? tr("✓ VERIFIED") : tr("✗ INSUFFICIENT"));
                }
            }
        }

    } catch (const std::exception& e) {
        LogPrintf("TradeBoardTab::buildCriticalChecks: Exception during address validation: %s\n", e.what());
        checks << tr("⚠ Address verification failed - review addresses manually");
    } catch (...) {
        LogPrintf("TradeBoardTab::buildCriticalChecks: Unknown exception during address validation\n");
        checks << tr("⚠ Address verification failed - review addresses manually");
    }

    return checks;
}

// ============================================================================================
// NEW SNAPSHOT-BASED WORKFLOW FUNCTIONS (Wrapper implementations)
// ============================================================================================

void TradeBoardTab::startTakerAcceptanceWorkflow(const FinalContractSnapshot& snapshot)
{
    LogPrintf("TradeBoardTab::startTakerAcceptanceWorkflow (snapshot-based): Starting workflow for contract %s\n",
              snapshot.contract_id.toStdString().c_str());

    if (!walletModel) return;

    QString progressLabel = tr("Importing finalized contract %1 and transmitting your acceptance...")
                                .arg(snapshot.contract_id.left(16) + "...");

    QWidget* dialog_parent = window() ? window() : this;
    QProgressDialog* progress = new QProgressDialog(dialog_parent);
    progress->setWindowTitle(tr("Sending Acceptance"));
    progress->setLabelText(progressLabel);
    progress->setRange(0, 0);
    progress->setCancelButton(nullptr);
    progress->setWindowModality(Qt::WindowModal);
    progress->setMinimumDuration(0);
    progress->show();

    auto* watcher = new QFutureWatcher<AcceptanceFlowResult>(this);

    // Guard UI and watcher lifetimes
    QPointer<TradeBoardTab> self(this);
    QPointer<QProgressDialog> progressPtr(progress);
    QPointer<QFutureWatcher<AcceptanceFlowResult>> watcherPtr(watcher);

    // Close progress when work finishes
    QObject::connect(watcher, &QFutureWatcher<AcceptanceFlowResult>::finished, progress, &QProgressDialog::close);

    // SNAPSHOT-BASED: Capture snapshot by value, zero activeRequests access during workflow
    connect(watcher, &QFutureWatcher<AcceptanceFlowResult>::finished, this,
            [self, watcherPtr, progressPtr, snapshot]() {
        if (!self) return;

        if (progressPtr) {
            progressPtr->deleteLater();
        }

        AcceptanceFlowResult result;
        if (watcherPtr) {
            result = watcherPtr->result();
        } else {
            result.success = false;
            result.failureStage = AcceptanceStage::None;
            result.errorDetail = QObject::tr("Internal watcher disposed");
        }

        // ATOMIC UPDATE: Only touch activeRequests after all async work is done
        if (self->activeRequests.contains(snapshot.request_id)) {
            TradeRequestInfo& reqInfo = self->activeRequests[snapshot.request_id];

            if (result.success) {
                reqInfo.acceptance_sent = true;
                reqInfo.last_acceptance_envelope = result.acceptanceEnvelope;
                reqInfo.taker_fee_strategy = snapshot.selected_fee_strategy;

                LogPrintf("TradeBoardTab: Acceptance for offer %s sent successfully (fee_strategy='%s')\n",
                          snapshot.contract_id.toStdString().c_str(),
                          snapshot.selected_fee_strategy.toStdString().c_str());

                // IMMUTABILITY PATTERN: Augment maker's base PSBT after acceptance
                if (!snapshot.maker_base_psbt.isEmpty() && reqInfo.augmented_psbt.isEmpty()) {
                    QVariantMap buildOptions;
                    buildOptions["psbt"] = snapshot.maker_base_psbt;
                    buildOptions["strategy"] = snapshot.selected_fee_strategy;

                    // Convert fee strategy to numeric rate for spot contracts
                    // Strategy mapping: low=2, medium=10, high=50 sat/vB
                    double feeRate = 10.0;  // Default medium
                    QString strategy = snapshot.selected_fee_strategy.toLower();
                    if (strategy == "low") {
                        feeRate = 2.0;
                    } else if (strategy == "high") {
                        feeRate = 50.0;
                    }
                    buildOptions["fee_rate"] = feeRate;

                    bool isForward = (snapshot.contract_type == "forward" || snapshot.contract_type == "option");
                    bool isSpot = (snapshot.contract_type == "spot");
                    bool augmentSuccess = false;
                    QString augmentedPsbt;
                    QString augmentError;

                    if (isSpot) {
                        // SPOT: Augment Alice's base PSBT with Bob's inputs
                        auto spotResult = self->walletModel->spotBuildAtomic(snapshot.contract_id, buildOptions);
                        augmentSuccess = spotResult.success;
                        augmentedPsbt = spotResult.psbt;
                        augmentError = spotResult.error;
                        LogPrintf("TradeBoardTab: Spot taker augmentation result: success=%d, role=%s\n",
                                  augmentSuccess, spotResult.my_role.toStdString().c_str());
                    } else if (isForward) {
                        // FORWARD/OPTIONS: Use forwardBuildOpen with role-specific flags
                        if (snapshot.user_role == "long") {
                            buildOptions["auto_fund_long"] = true;
                            buildOptions["auto_fund_premium"] = true;  // Long may pay premium
                        } else if (snapshot.user_role == "short") {
                            buildOptions["auto_fund_short"] = true;
                            // Premium funded by long party, short only adds IM
                        }
                        auto forwardResult = self->walletModel->forwardBuildOpen(snapshot.contract_id, buildOptions);
                        augmentSuccess = forwardResult.success;
                        augmentedPsbt = forwardResult.psbt;
                        augmentError = forwardResult.error;
                    } else {
                        // REPO: Use repoBuildOpen with borrower/lender flags
                        if (snapshot.user_role == "borrower") {
                            buildOptions["auto_fund_collateral"] = true;
                        } else {
                            buildOptions["auto_fund_principal"] = true;
                        }
                        auto repoResult = self->walletModel->repoBuildOpen(snapshot.contract_id, buildOptions);
                        augmentSuccess = repoResult.success;
                        augmentedPsbt = repoResult.psbt;
                        augmentError = repoResult.error;
                    }

                    if (augmentSuccess) {
                        auto annotate = self->walletModel->walletProcessPsbt(augmentedPsbt,
                                                                       false, QStringLiteral("DEFAULT"),
                                                                       true, false);
                        if (annotate.success && !annotate.psbt.isEmpty()) {
                            augmentedPsbt = annotate.psbt;
                        }

                        QString details, errText;
                        if (!PsbtHasSpendableInputs(self->walletModel, augmentedPsbt, &details, &errText)) {
                            LogPrintf("TradeBoardTab: Taker augmented PSBT not signable: %s\n",
                                      errText.toStdString().c_str());
                            self->showNonBlockingInfo(self->tr("Acceptance Sent"),
                                self->tr("Your funding could not be used for the ceremony because no signable inputs were found.\n\n%1")
                                    .arg(details));
                            self->updateTradeRequestsList();
                            if (watcherPtr) watcherPtr->deleteLater();
                            return;
                        }

                        reqInfo.augmented_psbt = augmentedPsbt;
                        reqInfo.augmented_psbt_hash = ComputePsbtTxHash(reqInfo.augmented_psbt);
                        reqInfo.psbt_locked = true;
                        LogPrintf("TradeBoardTab: Taker locked augmented PSBT (%d bytes, hash=%s)\n",
                                  reqInfo.augmented_psbt.length(), reqInfo.augmented_psbt_hash.toStdString().c_str());
                    } else {
                        LogPrintf("TradeBoardTab: WARNING - Failed to augment maker base PSBT: %s\n",
                                  augmentError.toStdString().c_str());
                    }
                }

                self->showAutoClosingInfo(self->tr("Offer Accepted"),
                    self->tr("✓ Acceptance sent to maker.\n\n"
                       "Wait for maker confirmation. The adaptor ceremony will start automatically once both sides are ready."));
            } else {
                // Error path
                if (!result.acceptanceEnvelope.isEmpty()) {
                    reqInfo.last_acceptance_envelope = result.acceptanceEnvelope;
                }

                QString errorMessage;
                switch (result.failureStage) {
                    case AcceptanceStage::ImportOffer:
                        errorMessage = self->tr("Failed to import finalized offer:\n\n%1").arg(result.errorDetail);
                        break;
                    case AcceptanceStage::AcceptOffer:
                        errorMessage = self->tr("Failed to accept offer:\n\n%1").arg(result.errorDetail);
                        break;
                    case AcceptanceStage::ParseAcceptance:
                        errorMessage = result.missingAcceptanceField ?
                            self->tr("The acceptance RPC did not return the required 'acceptance' field.") :
                            self->tr("Failed to parse acceptance payload:\n\n%1").arg(result.errorDetail);
                        break;
                    case AcceptanceStage::SendAcceptance:
                        if (result.sessionLost) {
                            errorMessage = self->tr("The cosign session was lost while attempting to send your acceptance.\n\n"
                                              "The acceptance is saved locally and will be retried after the session reconnects.");
                            self->handleSessionLoss(snapshot.session_id, snapshot.request_id, result.errorDetail);
                        } else {
                            errorMessage = self->tr("Failed to send acceptance to maker:\n\n%1").arg(result.errorDetail);
                        }
                        break;
                    default:
                        errorMessage = self->tr("Acceptance failed due to an unexpected error:\n\n%1").arg(result.errorDetail);
                        break;
                }
                QMessageBox::critical(self, self->tr("Acceptance Failed"), errorMessage);
            }
        } else {
            LogPrintf("TradeBoardTab: Acceptance flow finished but request %s no longer active\n",
                      snapshot.request_id.toStdString().c_str());
        }

        // SAFE: updateTradeRequestsList only called after all activeRequests mutations complete
        self->updateTradeRequestsList();
        if (watcherPtr) watcherPtr->deleteLater();
    });

    // Background RPC work - no activeRequests access
    auto inflightGuard = std::make_shared<InflightGuard>(this);
    QFuture<AcceptanceFlowResult> future = QtConcurrent::run([this, inflightGuard, snapshot]() {
        (void)inflightGuard;
        AcceptanceFlowResult result;
        try {
            bool isForward = (snapshot.contract_type == "forward" || snapshot.contract_type == "option");
            bool isSpot = (snapshot.contract_type == "spot");
            LogPrintf("TradeBoardTab: Taker accepting contract_type='%s' (isForward=%d, isSpot=%d)\n",
                      snapshot.contract_type.toStdString().c_str(), isForward ? 1 : 0, isSpot ? 1 : 0);

            QString messageToSend;

            if (isSpot) {
                // SPOT: Import offer, accept with bob_address (taker provided it when requesting)
                auto importResult = walletModel->spotImportOffer(snapshot.offer_json);
                if (!importResult.success) {
                    result.failureStage = AcceptanceStage::ImportOffer;
                    result.errorDetail = importResult.error;
                    return result;
                }

                // Get bob_address from snapshot (taker's receive address)
                QString bobAddress = snapshot.spot.bob_dest;
                if (bobAddress.isEmpty()) {
                    result.failureStage = AcceptanceStage::AcceptOffer;
                    result.errorDetail = QObject::tr("Missing bob_address for spot acceptance.\n\n"
                                                    "Spot atomic swaps require you to provide your receive address (bob_address).");
                    LogPrintf("TradeBoardTab: ERROR - Missing bob_address for spot acceptance\n");
                    return result;
                }

                auto acceptResult = walletModel->spotAccept(snapshot.contract_id, true, bobAddress);
                if (!acceptResult.success) {
                    result.failureStage = AcceptanceStage::AcceptOffer;
                    result.errorDetail = acceptResult.error;
                    return result;
                }

                QString acceptanceObjJson = acceptResult.acceptance_json;
                if (acceptanceObjJson.isEmpty()) {
                    result.failureStage = AcceptanceStage::ParseAcceptance;
                    result.missingAcceptanceField = true;
                    return result;
                }

                QJsonParseError parseError;
                QJsonDocument acceptanceDoc = QJsonDocument::fromJson(acceptanceObjJson.toUtf8(), &parseError);
                if (acceptanceDoc.isNull() || !acceptanceDoc.isObject()) {
                    result.failureStage = AcceptanceStage::ParseAcceptance;
                    result.parseError = true;
                    result.errorDetail = parseError.errorString();
                    return result;
                }

                QJsonObject wrapper;
                wrapper["type"] = "spot_acceptance";
                wrapper["acceptance"] = acceptanceDoc.object();
                messageToSend = QString::fromUtf8(QJsonDocument(wrapper).toJson(QJsonDocument::Compact));
                result.acceptanceEnvelope = messageToSend;

            } else if (isForward) {
                auto importResult = walletModel->forwardImportOffer(snapshot.offer_json);
                if (!importResult.success) {
                    result.failureStage = AcceptanceStage::ImportOffer;
                    result.errorDetail = importResult.error;
                    return result;
                }

                auto acceptResult = walletModel->forwardAccept(snapshot.contract_id, true);
                if (!acceptResult.success) {
                    result.failureStage = AcceptanceStage::AcceptOffer;
                    result.errorDetail = acceptResult.error;
                    return result;
                }

                QString acceptanceObjJson = acceptResult.acceptance_obj_json;
                if (acceptanceObjJson.isEmpty()) {
                    result.failureStage = AcceptanceStage::ParseAcceptance;
                    result.missingAcceptanceField = true;
                    return result;
                }

                QJsonParseError parseError;
                QJsonDocument acceptanceDoc = QJsonDocument::fromJson(acceptanceObjJson.toUtf8(), &parseError);
                if (acceptanceDoc.isNull() || !acceptanceDoc.isObject()) {
                    result.failureStage = AcceptanceStage::ParseAcceptance;
                    result.parseError = true;
                    result.errorDetail = parseError.errorString();
                    return result;
                }

                QJsonObject wrapper;
                wrapper["type"] = "forward_acceptance";
                wrapper["acceptance"] = acceptanceDoc.object();
                messageToSend = QString::fromUtf8(QJsonDocument(wrapper).toJson(QJsonDocument::Compact));
                result.acceptanceEnvelope = messageToSend;

            } else {
                // REPO: Import offer then accept
                auto importResult = walletModel->repoImportOffer(snapshot.offer_json);
                if (!importResult.success) {
                    result.failureStage = AcceptanceStage::ImportOffer;
                    result.errorDetail = importResult.error;
                    return result;
                }

                auto acceptResult = walletModel->repoAccept(snapshot.contract_id, true);
                if (!acceptResult.success) {
                    result.failureStage = AcceptanceStage::AcceptOffer;
                    result.errorDetail = acceptResult.error;
                    return result;
                }

                QString acceptanceObjJson = acceptResult.acceptance_obj_json;
                if (acceptanceObjJson.isEmpty()) {
                    result.failureStage = AcceptanceStage::ParseAcceptance;
                    result.missingAcceptanceField = true;
                    return result;
                }

                QJsonParseError parseError;
                QJsonDocument acceptanceDoc = QJsonDocument::fromJson(acceptanceObjJson.toUtf8(), &parseError);
                if (acceptanceDoc.isNull() || !acceptanceDoc.isObject()) {
                    result.failureStage = AcceptanceStage::ParseAcceptance;
                    result.parseError = true;
                    result.errorDetail = parseError.errorString();
                    return result;
                }

                QJsonObject wrapper;
                wrapper["type"] = "repo_acceptance";
                wrapper["acceptance"] = acceptanceDoc.object();
                messageToSend = QString::fromUtf8(QJsonDocument(wrapper).toJson(QJsonDocument::Compact));
                result.acceptanceEnvelope = messageToSend;
            }

            auto sendResult = walletModel->cosignSend(snapshot.session_id, messageToSend);
            if (!sendResult.success) {
                result.failureStage = AcceptanceStage::SendAcceptance;
                result.errorDetail = sendResult.error;
                QString lower = sendResult.error.toLower();
                if (lower.contains("session not found") || lower.contains("session expired") ||
                    lower.contains("bridge restarted") || lower.contains("unknown session")) {
                    result.sessionLost = true;
                }
                return result;
            }

            result.success = true;
            return result;
        } catch (const std::exception& e) {
            result.failureStage = AcceptanceStage::None;
            result.errorDetail = QString::fromStdString(e.what());
            return result;
        } catch (...) {
            result.failureStage = AcceptanceStage::None;
            result.errorDetail = QCoreApplication::translate("TradeBoardTab", "Unknown exception");
            return result;
        }
    });

    watcher->setFuture(future);
}

void TradeBoardTab::startMakerConfirmationWorkflow(const FinalContractSnapshot& snapshot)
{
    LogPrintf("TradeBoardTab::startMakerConfirmationWorkflow (snapshot-based): Starting workflow for contract %s\n",
              snapshot.contract_id.toStdString().c_str());

    if (!walletModel) return;

    // CRITICAL: Extract offer_id from acceptance JSON and use canonical cache
    // (Don't blindly trust snapshot.contract_type - it may be stale or wrong)
    QJsonParseError parseError;
    QJsonDocument acceptanceDoc = QJsonDocument::fromJson(snapshot.acceptance_json.toUtf8(), &parseError);
    if (acceptanceDoc.isNull() || !acceptanceDoc.isObject()) {
        QMessageBox::critical(this, tr("Acceptance Parse Error"),
            tr("Failed to parse acceptance JSON:\n\n%1").arg(parseError.errorString()));
        return;
    }

    QJsonObject acceptanceObj = acceptanceDoc.object();
    QString contractId = acceptanceObj.value("offer_id").toString();
    if (contractId.isEmpty()) {
        contractId = snapshot.contract_id;  // Fallback
        LogPrintf("TradeBoardTab: WARNING - No offer_id in acceptance, using snapshot contract_id\n");
    }

    // Use canonical cache to determine contract type (NOT snapshot guess)
    QString contractType = getCanonicalContractType(contractId);
    if (contractType.isEmpty()) {
        // Cache miss - try to populate from available data
        LogPrintf("TradeBoardTab: Cache miss for contract %s, attempting to populate\n", contractId.toStdString().c_str());
        if (!ensureContractFlavorLoaded(contractId, snapshot.contract_type)) {
            QMessageBox::critical(this, tr("Contract Type Unknown"),
                tr("Cannot determine contract type for %1.\n\nPlease refresh the Trade Board.").arg(contractId.left(16) + "..."));
            return;
        }
        contractType = getCanonicalContractType(contractId);
    }

    bool isForward = (contractType == "forward" || contractType == "option");
    bool isSpot = (contractType == "spot");
    LogPrintf("TradeBoardTab: Maker importing acceptance for contract_type=%s [canonical cache] (contract_id=%s)\n",
              contractType.toStdString().c_str(), contractId.toStdString().c_str());

    // Resolve negotiated fee strategy from cached offer data or the snapshot JSON
    auto extractFeeFromTermsObj = [](const QJsonObject& obj) -> QString {
        if (obj.contains("fee_policy")) {
            return obj.value("fee_policy").toString();
        }
        return QString();
    };
    auto extractFeeFromPayloadValue = [&](const QJsonValue& val) -> QString {
        if (val.isString()) {
            const QString payload = val.toString();
            if (payload.isEmpty()) return QString();
            QJsonParseError err;
            QJsonDocument doc = QJsonDocument::fromJson(payload.toUtf8(), &err);
            if (doc.isObject()) {
                QJsonObject obj = doc.object();
                if (obj.contains("terms") && obj.value("terms").isObject()) {
                    QString extracted = extractFeeFromTermsObj(obj.value("terms").toObject());
                    if (!extracted.isEmpty()) return extracted;
                }
                if (obj.contains("fee_policy")) {
                    return obj.value("fee_policy").toString();
                }
            }
            return QString();
        }
        if (val.isObject()) {
            QJsonObject obj = val.toObject();
            if (obj.contains("terms") && obj.value("terms").isObject()) {
                QString extracted = extractFeeFromTermsObj(obj.value("terms").toObject());
                if (!extracted.isEmpty()) return extracted;
            }
            if (obj.contains("fee_policy")) {
                return obj.value("fee_policy").toString();
            }
        }
        return QString();
    };
    auto extractFeeFromOfferObj = [&](const QJsonObject& obj) -> QString {
        QString candidate = obj.value("fee_policy_strategy").toString();
        if (!candidate.isEmpty()) return candidate;
        if (obj.contains("terms") && obj.value("terms").isObject()) {
            candidate = extractFeeFromTermsObj(obj.value("terms").toObject());
            if (!candidate.isEmpty()) return candidate;
        }
        if (obj.contains("contract_payload")) {
            candidate = extractFeeFromPayloadValue(obj.value("contract_payload"));
            if (!candidate.isEmpty()) return candidate;
        }
        return QString();
    };
    auto extractFeeFromJsonString = [&](const QString& json) -> QString {
        if (json.isEmpty()) return QString();
        QJsonParseError err;
        QJsonDocument doc = QJsonDocument::fromJson(json.toUtf8(), &err);
        if (doc.isObject()) {
            return extractFeeFromOfferObj(doc.object());
        }
        return QString();
    };

    QString feeStrategy;
    if (activeRequests.contains(snapshot.request_id)) {
        const TradeRequestInfo reqInfoCopy = activeRequests[snapshot.request_id];
        if (reqInfoCopy.offer_summary.contains("fee_policy_strategy")) {
            feeStrategy = reqInfoCopy.offer_summary.value("fee_policy_strategy").toString();
        }
        if (feeStrategy.isEmpty() && reqInfoCopy.offer_summary.contains("contract_payload")) {
            feeStrategy = extractFeeFromJsonString(reqInfoCopy.offer_summary.value("contract_payload").toString());
        }
        if (feeStrategy.isEmpty()) {
            feeStrategy = extractFeeFromJsonString(reqInfoCopy.final_offer_json);
        }
    }
    if (feeStrategy.isEmpty()) {
        feeStrategy = extractFeeFromOfferObj(snapshot.offer_obj);
    }
    if (feeStrategy.isEmpty()) {
        feeStrategy = QStringLiteral("medium");
        LogPrintf("TradeBoardTab: No fee_policy in offer, defaulting to '%s'\n", feeStrategy.toStdString().c_str());
    } else {
        LogPrintf("TradeBoardTab: Using fee_policy='%s' from offer\n", feeStrategy.toStdString().c_str());
    }

    // Step 1: Import acceptance using appropriate RPC
    bool importSuccess = false;
    QString importError;

    if (isSpot) {
        auto spotImport = walletModel->spotImportAcceptance(contractId, snapshot.acceptance_json);
        importSuccess = spotImport.success;
        importError = spotImport.error;
    } else if (isForward) {
        auto forwardImport = walletModel->forwardImportAcceptance(snapshot.acceptance_json);
        importSuccess = forwardImport.success;
        importError = forwardImport.error;
    } else {
        auto repoImport = walletModel->repoImportAcceptance(snapshot.acceptance_json);
        importSuccess = repoImport.success;
        importError = repoImport.error;
    }

    if (!importSuccess) {
        QString errorMessage = tr("Failed to import taker's acceptance:\n\n%1\n\n"
                                 "The acceptance is saved locally and you can retry later.")
                                 .arg(importError);
        QMessageBox::critical(this, tr("Import Failed"), errorMessage);
        return;
    }

    LogPrintf("TradeBoardTab: Maker imported acceptance successfully, building base PSBT\n");

    // Step 2: Build maker's base PSBT (to send to taker)
    QVariantMap buildOptions;
    buildOptions["strategy"] = feeStrategy;

    if (isSpot) {
        // Spot atomic swap: Convert fee strategy to numeric rate
        double feeRate = 10.0;
        QString strategyLower = feeStrategy.toLower();
        if (strategyLower == "low") {
            feeRate = 2.0;
        } else if (strategyLower == "high") {
            feeRate = 50.0;
        }
        buildOptions["fee_rate"] = feeRate;
        LogPrintf("TradeBoardTab: MAKER Spot contract - fee_rate=%.1f sat/vB (strategy=%s)\n",
                  feeRate, feeStrategy.toStdString().c_str());
    } else if (isForward) {
        // Forward contracts: maker can be long OR short
        if (snapshot.user_role == "long") {
            buildOptions["auto_fund_long"] = true;
            buildOptions["auto_fund_premium"] = true;  // Long party funds premium
        } else if (snapshot.user_role == "short") {
            buildOptions["auto_fund_short"] = true;
            // Premium is funded by long party, short only adds IM
        }
    } else {
        // Repo contracts: use role-based flags
        if (snapshot.user_role == "borrower") {
            buildOptions["auto_fund_collateral"] = true;
        } else {
            buildOptions["auto_fund_principal"] = true;
        }
    }

    bool buildSuccess = false;
    QString basePsbt;
    QString buildError;
    int alice_vault_index = -1;
    int bob_vault_index = -1;
    int premium_output_index = -1;

    if (isSpot) {
        // For spot, use spot.build_atomic to create Alice's PSBT
        auto spotBuild = walletModel->spotBuildAtomic(contractId, buildOptions);
        buildSuccess = spotBuild.success;
        basePsbt = spotBuild.psbt;  // Alice's PSBT to send to Bob
        buildError = spotBuild.error;
        LogPrintf("TradeBoardTab: MAKER Spot build_atomic result: success=%d, my_role=%s, psbt_len=%d\n",
                 buildSuccess, spotBuild.my_role.toStdString().c_str(), basePsbt.length());
    } else if (isForward) {
        auto forwardBuild = walletModel->forwardBuildOpen(contractId, buildOptions);
        buildSuccess = forwardBuild.success;
        basePsbt = forwardBuild.psbt;
        buildError = forwardBuild.error;
        alice_vault_index = forwardBuild.alice_vault_index;
        bob_vault_index = forwardBuild.bob_vault_index;
        premium_output_index = forwardBuild.premium_output_index;
    } else {
        auto repoBuild = walletModel->repoBuildOpen(contractId, buildOptions);
        buildSuccess = repoBuild.success;
        basePsbt = repoBuild.psbt;
        buildError = repoBuild.error;
    }

    if (!buildSuccess) {
        QString errorMessage = tr("Failed to build your leg of the opening transaction:\n\n%1\n\n"
                                 "Check that you have sufficient funds.")
                                 .arg(buildError);
        QMessageBox::critical(this, tr("Build Failed"), errorMessage);
        return;
    }
    LogPrintf("TradeBoardTab: Maker built base PSBT (%d bytes)\n", basePsbt.length());

    // Annotate with wallet metadata
    auto annotate = walletModel->walletProcessPsbt(basePsbt, false, QStringLiteral("DEFAULT"), true, false);
    if (annotate.success && !annotate.psbt.isEmpty()) {
        basePsbt = annotate.psbt;
    }

    // Preflight: ensure maker PSBT has spendable inputs
    QString details, errText;
    if (!PsbtHasSpendableInputs(walletModel, basePsbt, &details, &errText)) {
        LogPrintf("TradeBoardTab: WARNING - Maker base PSBT preflight advisory failed: %s\n", errText.toStdString().c_str());
        // Continue - ceremony will validate again
    }

    // Step 3: Send base PSBT to taker
    QJsonObject basePsbtMsg;
    basePsbtMsg["type"] = "maker_base_psbt";
    const QString offerIdForMessage = snapshot.contract_id;
    basePsbtMsg["offer_id"] = offerIdForMessage;
    if (contractId != offerIdForMessage) {
        basePsbtMsg["contract_id"] = contractId;
    }
    basePsbtMsg["psbt"] = basePsbt;
    basePsbtMsg["maker_role"] = snapshot.user_role;
    if (isForward) {
        if (alice_vault_index >= 0) basePsbtMsg["alice_vault_index"] = alice_vault_index;
        if (bob_vault_index >= 0) basePsbtMsg["bob_vault_index"] = bob_vault_index;
        if (premium_output_index >= 0) basePsbtMsg["premium_output_index"] = premium_output_index;
    }

    QString basePsbtJson = QString::fromUtf8(QJsonDocument(basePsbtMsg).toJson(QJsonDocument::Compact));

    auto sendPsbtResult = walletModel->cosignSend(snapshot.session_id, basePsbtJson);
    if (!sendPsbtResult.success) {
        QMessageBox::critical(this, tr("Send Base PSBT Failed"),
            tr("Failed to send maker's base PSBT to taker:\n\n%1").arg(sendPsbtResult.error));
        return;
    }
    LogPrintf("TradeBoardTab: Sent maker base PSBT (%d bytes) to taker on session %s\n",
              basePsbt.length(), snapshot.session_id.toStdString().c_str());

    // Step 4: Build and send ceremony_invite
    QString takerRole = (snapshot.user_role == "lender") ? "borrower" :
                        (snapshot.user_role == "borrower") ? "lender" :
                        (snapshot.user_role == "long") ? "short" : "long";

    QJsonObject ceremonyInvite;
    ceremonyInvite["type"] = "ceremony_invite";
    ceremonyInvite["offer_id"] = contractId;  // Use contractId from acceptance, not snapshot
    ceremonyInvite["maker_role"] = snapshot.user_role;
    ceremonyInvite["taker_role"] = takerRole;

    QString inviteJson = QString::fromUtf8(QJsonDocument(ceremonyInvite).toJson(QJsonDocument::Compact));

    auto sendInviteResult = walletModel->cosignSend(snapshot.session_id, inviteJson);
    bool inviteSent = sendInviteResult.success;

    if (!inviteSent) {
        LogPrintf("TradeBoardTab: WARNING - Failed to send ceremony_invite: %s\n",
                  sendInviteResult.error.toStdString().c_str());
    } else {
        LogPrintf("TradeBoardTab: Sent ceremony_invite to taker on session %s\n",
                  snapshot.session_id.toStdString().c_str());
    }

    // Step 5: ATOMIC UPDATE - Cache base PSBT and ceremony state
    if (activeRequests.contains(snapshot.request_id)) {
        TradeRequestInfo& reqInfo = activeRequests[snapshot.request_id];
        reqInfo.maker_base_psbt = basePsbt;  // CRITICAL: Store in maker_base_psbt, NOT augmented_psbt
        reqInfo.last_ceremony_invite = inviteJson;
        reqInfo.ceremony_invite_sent = inviteSent;
        reqInfo.maker_role = snapshot.user_role;
        if (isForward) {
            reqInfo.borrower_address = snapshot.forward.long_margin_dest;
            reqInfo.lender_address = snapshot.forward.short_margin_dest;
            reqInfo.long_margin_dest = snapshot.forward.long_margin_dest;
            reqInfo.short_margin_dest = snapshot.forward.short_margin_dest;
            reqInfo.alice_vault_index = alice_vault_index;
            reqInfo.bob_vault_index = bob_vault_index;
            reqInfo.premium_output_index = premium_output_index;
        } else {
            if (!snapshot.repo.borrower_address.isEmpty()) {
                reqInfo.borrower_address = snapshot.repo.borrower_address;
            }
            if (!snapshot.repo.lender_address.isEmpty()) {
                reqInfo.lender_address = snapshot.repo.lender_address;
            }
        }
        LogPrintf("TradeBoardTab: Cached maker base PSBT for request %s (ceremony_invite_sent=%d)\n",
                  snapshot.request_id.toStdString().c_str(), inviteSent ? 1 : 0);
    }

    // Step 6: Update UI and WAIT for taker's ceremony_ready
    // (launchOpeningCeremony will be called by handleSessionMessages when ceremony_ready arrives)
    updateTradeRequestsList();

    showAutoClosingInfo(tr("Ceremony Invited"),
        tr("✓ Your base PSBT has been sent to the taker.\n\n"
           "Waiting for taker to augment and send ceremony_ready..."));
}

// ============================================================================================
// END NEW SNAPSHOT-BASED WORKFLOW FUNCTIONS
// ============================================================================================

QString TradeBoardTab::describeRepoTerms(const TradeRequestInfo& info, const QString& perspectiveRole) const
{
    if (!info.terms_available) {
        return tr("Contract terms unavailable. Please refresh the Trade Board.");
    }

    const QString principalAsset = info.principal_asset.isEmpty() ? tr("TSC") : info.principal_asset;
    const QString collateralAsset = info.collateral_asset.isEmpty() ? tr("Collateral") : info.collateral_asset;
    const QString interestAsset = info.interest_asset.isEmpty() ? principalAsset : info.interest_asset;

    const double principalQty = info.principal_qty;
    const double collateralQty = info.collateral_qty;
    const double interestQty = info.interest_qty;
    const int tenorDays = info.tenor_days;
    const int maturityHeight = info.maturity_height;

    // Price-aware recomputations. Use extracted helper method.
    const double pPriceTSC = priceInTSC(principalAsset);
    const double cPriceTSC = priceInTSC(collateralAsset);
    const double iPriceTSC = priceInTSC(interestAsset);

    // Convert values to TSC, when possible
    const bool havePV = (pPriceTSC > 0.0);
    const bool haveCV = (cPriceTSC > 0.0);
    const bool haveIV = (iPriceTSC > 0.0);
    const double principalValueTSC = havePV ? (principalQty * pPriceTSC) : 0.0;
    const double collateralValueTSC = haveCV ? (collateralQty * cPriceTSC) : 0.0;

    // Interest in principal units (for APR)
    double interestInPrincipal = 0.0;
    bool haveAPR = false;
    if (interestAsset.compare(principalAsset, Qt::CaseInsensitive) == 0) {
        interestInPrincipal = interestQty;
        haveAPR = (principalQty > 0.0 && tenorDays > 0);
    } else if (haveIV && havePV && pPriceTSC > 0.0) {
        // Convert interest to TSC then to principal units
        double interestValueTSC = interestQty * iPriceTSC;
        double principalUnitTSC = pPriceTSC; // 1 principal asset = pPriceTSC TSC
        if (principalUnitTSC > 0.0) {
            interestInPrincipal = interestValueTSC / principalUnitTSC;
            haveAPR = (principalQty > 0.0 && tenorDays > 0);
        }
    }

    double aprComputed = 0.0;
    if (haveAPR) {
        aprComputed = (interestInPrincipal / principalQty) * (365.0 / static_cast<double>(tenorDays)) * 100.0;
    }

    // LTV based on price feed (principal value / collateral value)
    bool haveLTV = (principalValueTSC > 0.0 && collateralValueTSC > 0.0);
    double ltvComputed = haveLTV ? ((principalValueTSC / collateralValueTSC) * 100.0) : 0.0;

    // Implied price (collateral per principal unit)
    double impliedPrice = (principalQty > 0.0) ? (collateralQty / principalQty) : 0.0;

    // Build role-aware summary
    const QString role = perspectiveRole.trimmed().toLower();
    QStringList lines;

    if (role == QLatin1String("borrower")) {
        lines << tr("<b>You Borrow:</b> %1 %2")
                     .arg(QString::number(principalQty, 'f', principalQty < 1.0 ? 8 : 4), principalAsset);
        lines << tr("<b>You Pledge as Collateral:</b> %1 %2")
                     .arg(QString::number(collateralQty, 'f', collateralQty < 1.0 ? 8 : 4), collateralAsset);
        if (interestAsset.compare(principalAsset, Qt::CaseInsensitive) == 0) {
            lines << tr("<b>You Repay:</b> %1 %2 (principal + interest)")
                         .arg(QString::number(principalQty + interestQty, 'f', (principalQty + interestQty) < 1.0 ? 8 : 4), principalAsset);
        } else {
            lines << tr("<b>You Repay (Principal):</b> %1 %2")
                         .arg(QString::number(principalQty, 'f', principalQty < 1.0 ? 8 : 4), principalAsset);
            lines << tr("<b>You Repay (Interest):</b> %1 %2")
                         .arg(QString::number(interestQty, 'f', interestQty < 1.0 ? 8 : 4), interestAsset);
        }
    } else if (role == QLatin1String("lender")) {
        lines << tr("<b>You Lend:</b> %1 %2")
                     .arg(QString::number(principalQty, 'f', principalQty < 1.0 ? 8 : 4), principalAsset);
        lines << tr("<b>Borrower Pledges:</b> %1 %2")
                     .arg(QString::number(collateralQty, 'f', collateralQty < 1.0 ? 8 : 4), collateralAsset);
        if (interestAsset.compare(principalAsset, Qt::CaseInsensitive) == 0) {
            lines << tr("<b>Borrower Repays:</b> %1 %2 (principal + interest)")
                         .arg(QString::number(principalQty + interestQty, 'f', (principalQty + interestQty) < 1.0 ? 8 : 4), principalAsset);
        } else {
            lines << tr("<b>Borrower Repays (Principal):</b> %1 %2")
                         .arg(QString::number(principalQty, 'f', principalQty < 1.0 ? 8 : 4), principalAsset);
            lines << tr("<b>Borrower Repays (Interest):</b> %1 %2")
                         .arg(QString::number(interestQty, 'f', interestQty < 1.0 ? 8 : 4), interestAsset);
        }
    } else {
        // Fallback neutral copy
        lines << tr("<b>Principal:</b> %1 %2").arg(QString::number(principalQty, 'f', principalQty < 1.0 ? 8 : 4), principalAsset);
        lines << tr("<b>Interest:</b> %1 %2").arg(QString::number(interestQty, 'f', interestQty < 1.0 ? 8 : 4), interestAsset);
        lines << tr("<b>Collateral:</b> %1 %2").arg(QString::number(collateralQty, 'f', collateralQty < 1.0 ? 8 : 4), collateralAsset);
    }

    // Price metrics
    if (haveAPR) {
        lines << tr("<b>APR:</b> %1%")
                     .arg(QString::number(aprComputed, 'f', 2));
    } else {
        // Keep existing APR if present, else show N/A
        if (info.apr > 0.0) {
            lines << tr("<b>APR (from offer):</b> %1%")
                         .arg(QString::number(info.apr, 'f', 2));
        } else {
            lines << tr("<b>APR:</b> N/A (insufficient price data)");
        }
    }

    if (haveLTV) {
        lines << tr("<b>LTV:</b> %1%")
                     .arg(QString::number(ltvComputed, 'f', 2));
    } else {
        lines << tr("<b>LTV:</b> 0% (no price; implied price: %1 %2 per %3)")
                     .arg(QString::number(impliedPrice, 'f', impliedPrice < 1.0 ? 8 : 4), collateralAsset, principalAsset);
    }

    // Maturity display: both blocks and human-friendly tenor
    if (tenorDays > 0 || maturityHeight > 0) {
        QString maturityLine = tr("<b>Maturity:</b> block %1 (~%2 days)")
                                   .arg(maturityHeight > 0 ? QString::number(maturityHeight) : tr("n/a"))
                                   .arg(tenorDays);
        lines << maturityLine;
    }

    // Address confirmations
    if (role == QLatin1String("borrower")) {
        if (!info.borrower_address.isEmpty()) {
            lines << tr("<b>Your refund/return address:</b> %1").arg(info.borrower_address);
        }
        if (!info.lender_address.isEmpty()) {
            lines << tr("<b>Repay to (maker):</b> %1").arg(info.lender_address);
        }
    } else if (role == QLatin1String("lender")) {
        if (!info.lender_address.isEmpty()) {
            lines << tr("<b>Your repay-to address:</b> %1").arg(info.lender_address);
        }
        if (!info.borrower_address.isEmpty()) {
            lines << tr("<b>Borrower refund address:</b> %1").arg(info.borrower_address);
        }
    }

    return lines.join("\n");
}

QString TradeBoardTab::describeForwardTerms(const TradeRequestInfo& info, const QString& perspectiveRole) const
{
    if (!info.terms_available) {
        return tr("Contract terms unavailable. Please refresh the Trade Board.");
    }

    const QString role = perspectiveRole.trimmed().toLower();
    QStringList lines;

    // Helper to format asset display
    auto formatAsset = [](const QString& asset) -> QString {
        return asset.isEmpty() ? QString("TSC") : asset;
    };

    // Helper to format qty
    auto formatQty = [](double qty) -> QString {
        return QString::number(qty, 'f', qty < 1.0 ? 8 : 4);
    };

    if (role == QLatin1String("long")) {
        // Long party view
        lines << tr("<b>You Post as Initial Margin:</b> %1 %2")
                     .arg(formatQty(info.long_margin_qty), formatAsset(info.long_margin_asset));
        lines << tr("<b>You Deliver at Maturity:</b> %1 %2")
                     .arg(formatQty(info.long_deliver_qty), formatAsset(info.long_deliver_asset));
        lines << tr("<b>You Receive at Maturity:</b> %1 %2")
                     .arg(formatQty(info.short_deliver_qty), formatAsset(info.short_deliver_asset));
        lines << tr("<b>Short Party Posts:</b> %1 %2 (initial margin)")
                     .arg(formatQty(info.short_margin_qty), formatAsset(info.short_margin_asset));

        // Premium (if option)
        if (info.premium_amount > 0.0) {
            QString premiumPayer = info.premium_payer.toLower();
            if (premiumPayer == "long") {
                lines << tr("<b>You Pay Premium:</b> %1 %2")
                             .arg(formatQty(info.premium_amount), formatAsset(info.premium_asset));
            } else {
                lines << tr("<b>You Receive Premium:</b> %1 %2")
                             .arg(formatQty(info.premium_amount), formatAsset(info.premium_asset));
            }
        }

        // IM percentage
        if (info.long_im_percent > 0.0) {
            lines << tr("<b>Your Initial Margin:</b> %1%")
                         .arg(QString::number(info.long_im_percent, 'f', 2));
        }

    } else if (role == QLatin1String("short")) {
        // Short party view
        lines << tr("<b>You Post as Initial Margin:</b> %1 %2")
                     .arg(formatQty(info.short_margin_qty), formatAsset(info.short_margin_asset));
        lines << tr("<b>You Deliver at Maturity:</b> %1 %2")
                     .arg(formatQty(info.short_deliver_qty), formatAsset(info.short_deliver_asset));
        lines << tr("<b>You Receive at Maturity:</b> %1 %2")
                     .arg(formatQty(info.long_deliver_qty), formatAsset(info.long_deliver_asset));
        lines << tr("<b>Long Party Posts:</b> %1 %2 (initial margin)")
                     .arg(formatQty(info.long_margin_qty), formatAsset(info.long_margin_asset));

        // Premium (if option)
        if (info.premium_amount > 0.0) {
            QString premiumPayer = info.premium_payer.toLower();
            if (premiumPayer == "short") {
                lines << tr("<b>You Pay Premium:</b> %1 %2")
                             .arg(formatQty(info.premium_amount), formatAsset(info.premium_asset));
            } else {
                lines << tr("<b>You Receive Premium:</b> %1 %2")
                             .arg(formatQty(info.premium_amount), formatAsset(info.premium_asset));
            }
        }

        // IM percentage
        if (info.short_im_percent > 0.0) {
            lines << tr("<b>Your Initial Margin:</b> %1%")
                         .arg(QString::number(info.short_im_percent, 'f', 2));
        }

    } else {
        // Fallback neutral view
        lines << tr("<b>Long Delivers:</b> %1 %2")
                     .arg(formatQty(info.long_deliver_qty), formatAsset(info.long_deliver_asset));
        lines << tr("<b>Short Delivers:</b> %1 %2")
                     .arg(formatQty(info.short_deliver_qty), formatAsset(info.short_deliver_asset));
        lines << tr("<b>Long Initial Margin:</b> %1 %2")
                     .arg(formatQty(info.long_margin_qty), formatAsset(info.long_margin_asset));
        lines << tr("<b>Short Initial Margin:</b> %1 %2")
                     .arg(formatQty(info.short_margin_qty), formatAsset(info.short_margin_asset));
    }

    // Deadlines (common for all roles)
    if (info.deadline_short > 0 || info.deadline_long > 0) {
        lines << tr("<b>Short Deadline:</b> block %1 (~%2 days)")
                     .arg(info.deadline_short).arg(info.tenor_days_short);
        lines << tr("<b>Long Deadline:</b> block %1 (~%2 days)")
                     .arg(info.deadline_long).arg(info.tenor_days_long);
    }

    // Addresses
    if (role == QLatin1String("long")) {
        if (!info.long_margin_dest.isEmpty()) {
            lines << tr("<b>Your margin refund address:</b> %1").arg(info.long_margin_dest);
        }
        if (!info.long_settlement_dest.isEmpty()) {
            lines << tr("<b>Your settlement receive address:</b> %1").arg(info.long_settlement_dest);
        }
    } else if (role == QLatin1String("short")) {
        if (!info.short_margin_dest.isEmpty()) {
            lines << tr("<b>Your margin refund address:</b> %1").arg(info.short_margin_dest);
        }
        if (!info.short_settlement_dest.isEmpty()) {
            lines << tr("<b>Your settlement receive address:</b> %1").arg(info.short_settlement_dest);
        }
    }

    return lines.join("\n");
}

double TradeBoardTab::priceInTSC(const QString& symbolRaw) const
{
    const QString symbol = symbolRaw.trimmed().toUpper();
    if (symbol.isEmpty() || symbol == QLatin1String("TSC") || symbol == QLatin1String("NATIVE")) {
        return 1.0;
    }
    if (assetPriceTab) {
        double price = assetPriceTab->getAssetPriceInTSC(symbol);
        // Default to 1.0 if no price found (FX=1 assumption)
        return (price > 0.0) ? price : 1.0;
    }
    QSettings s;
    s.beginGroup("AssetPrices");
    int size = s.beginReadArray("prices");
    double result = 0.0;
    for (int i = 0; i < size; ++i) {
        s.setArrayIndex(i);
        const QString key = s.value("symbol").toString().trimmed().toUpper();
        if (key == symbol) {
            result = s.value("price").toDouble();
            break;
        }
    }
    s.endArray();
    s.endGroup();
    // Default to 1.0 if no price found (FX=1 assumption)
    return (result > 0.0) ? result : 1.0;
}

void TradeBoardTab::scheduleRepoMtmUpdate(QTableWidget* table, int row, const OfferInfo& info, const QVariantMap& inlineTerms)
{
    if (!walletModel || !table) {
        return;
    }

    QByteArray termsHash = hashInlineTerms(inlineTerms);
    auto cacheIt = repoMtmCache.constFind(info.offer_id);
    if (cacheIt != repoMtmCache.end() && cacheIt->terms_hash == termsHash) {
        applyRepoMtmResult(table, row, info.offer_id, cacheIt->mark_mtm, cacheIt->market_mtm);
        return;
    }

    if (repoMtmPending.contains(info.offer_id)) {
        return;
    }
    repoMtmPending.insert(info.offer_id);

    QPointer<TradeBoardTab> self(this);
    QPointer<WalletModel> wm(walletModel);
    QPointer<QTableWidget> tablePtr(table);
    QVariantMap inlineCopy = inlineTerms;
    QString offerId = info.offer_id;
    QString makerRoleLower = info.maker_role.toLower();

    (void)QtConcurrent::run([self, wm, tablePtr, inlineCopy, offerId, makerRoleLower, row, termsHash]() {
        if (!self || !wm || !tablePtr) {
            return;
        }

        auto computeQuoteMtm = [&](const QString& source) -> std::optional<double> {
            auto quote = wm->pricingRepoQuote(
                "inline",
                "",
                inlineCopy,
                "",
                true,  // report_is_native (TSC)
                false,
                source,
                true   // include inception cashflows for pre-exec offers
            );
            if (!quote.success) {
                return std::nullopt;
            }

            double mtmBase = 0.0;
            if (makerRoleLower == "lender") {
                mtmBase = quote.borrower_mtm;
            } else {
                mtmBase = quote.lender_mtm;
            }
            return mtmBase;
        };

        auto markMtm = computeQuoteMtm("mark");
        auto marketMtm = computeQuoteMtm("market");

        QMetaObject::invokeMethod(self, [self, tablePtr, row, offerId, markMtm, marketMtm, termsHash]() {
            if (!self || !tablePtr) {
                return;
            }
            self->repoMtmPending.remove(offerId);
            TradeBoardTab::RepoMtmCacheEntry entry;
            entry.terms_hash = termsHash;
            entry.mark_mtm = markMtm;
            entry.market_mtm = marketMtm;
            self->repoMtmCache.insert(offerId, entry);
            self->applyRepoMtmResult(tablePtr, row, offerId, markMtm, marketMtm);
        }, Qt::QueuedConnection);
    });
}

void TradeBoardTab::applyRepoMtmResult(QTableWidget* table, int row, const QString& offerId,
                                       const std::optional<double>& markMtm,
                                       const std::optional<double>& marketMtm)
{
    repoMtmPending.remove(offerId);

    if (!table || row < 0 || row >= table->rowCount()) {
        return;
    }

    QTableWidgetItem* makerItem = table->item(row, 0);
    if (!makerItem || makerItem->data(Qt::UserRole).toString() != offerId) {
        return;
    }

    int reportDecimals = 8;
    if (walletModel) {
        WalletModel::AssetInfo tscInfo = walletModel->getAssetInfo("");
        if (tscInfo.has_decimals) {
            reportDecimals = tscInfo.decimals;
        }
    }
    const double toDisplayUnits = 1.0 / std::pow(10.0, reportDecimals);

    auto formatMtm = [&](const std::optional<double>& mtmBase) -> std::pair<QString, QColor> {
        if (!mtmBase) {
            return {QStringLiteral("--"), QColor(158, 158, 158)};
        }
        double mtm = *mtmBase * toDisplayUnits;
        if (mtm > 0.0) {
            return {QString("+%1").arg(mtm, 0, 'f', 8), QColor(76, 175, 80)};
        }
        if (mtm < 0.0) {
            return {QString("%1").arg(mtm, 0, 'f', 8), QColor(244, 67, 54)};
        }
        return {QStringLiteral("0.00000000"), QColor(158, 158, 158)};
    };

    QTableWidgetItem* marksItem = table->item(row, 2);
    if (marksItem) {
        auto display = formatMtm(markMtm);
        marksItem->setText(display.first);
        marksItem->setForeground(QBrush(display.second));
    }

    QTableWidgetItem* marketItem = table->item(row, 3);
    if (marketItem) {
        auto display = formatMtm(marketMtm ? marketMtm : markMtm);
        marketItem->setText(display.first);
        marketItem->setForeground(QBrush(display.second));
    }
}

void TradeBoardTab::scheduleForwardMtmUpdate(QTableWidget* table, int row, const OfferInfo& info, const QVariantMap& inlineTerms)
{
    LogPrintf("scheduleForwardMtmUpdate: ENTERED for offer %s\n", info.offer_id.toStdString());

    if (!walletModel || !table) {
        LogPrintf("scheduleForwardMtmUpdate: Early return - walletModel=%d table=%d\n", !!walletModel, !!table);
        return;
    }

    QByteArray termsHash = hashInlineTerms(inlineTerms);
    auto cacheIt = forwardMtmCache.constFind(info.offer_id);
    if (cacheIt != forwardMtmCache.end() && cacheIt->terms_hash == termsHash) {
        applyForwardMtmResult(table, row, info.offer_id, info.maker_role, cacheIt->mark_mtm, cacheIt->market_mtm);
        return;
    }

    if (forwardMtmPending.contains(info.offer_id)) {
        return;
    }
    forwardMtmPending.insert(info.offer_id);

    QPointer<TradeBoardTab> self(this);
    QPointer<WalletModel> wm(walletModel);
    QPointer<QTableWidget> tablePtr(table);
    QVariantMap inlineCopy = inlineTerms;
    QString offerId = info.offer_id;
    QString makerRoleLower = info.maker_role.toLower();

    (void)QtConcurrent::run([self, wm, tablePtr, inlineCopy, offerId, makerRoleLower, row, termsHash]() {
        if (!self || !wm || !tablePtr) {
            LogPrintf("scheduleForwardMtmUpdate: NULL pointer check failed (self=%d wm=%d tablePtr=%d)\n",
                     !!self, !!wm, !!tablePtr);
            return;
        }

        LogPrintf("scheduleForwardMtmUpdate: Calling pricingForwardQuote for offer %s, role=%s\n",
                 offerId.toStdString(), makerRoleLower.toStdString());
        LogPrintf("  inlineTerms keys: %s\n", inlineCopy.keys().join(", ").toStdString());

        // Note: forward pricing doesn't have separate mark/market sources
        auto quote = wm->pricingForwardQuote(
            "inline",
            "",
            inlineCopy,
            "",     // report_asset (empty = native TSC)
            true,   // report_is_native
            false  // compute_greeks
        );

        LogPrintf("scheduleForwardMtmUpdate: quote.success=%d, error=%s\n",
                 quote.success, quote.error.toStdString());
        if (quote.success) {
            LogPrintf("  alice_mtm=%f, bob_mtm=%f\n", quote.alice_mtm, quote.bob_mtm);
        }

        std::optional<double> mtmResult;
        if (quote.success) {
            // Extract MTM based on maker's role
            // If maker is long, we want alice_mtm (long party MTM)
            // If maker is short, we want bob_mtm (short party MTM)
            double mtmBase = 0.0;
            if (makerRoleLower == "long") {
                mtmBase = quote.alice_mtm;
            } else {
                mtmBase = quote.bob_mtm;
            }
            LogPrintf("  Using mtmBase=%f for role=%s\n", mtmBase, makerRoleLower.toStdString());
            mtmResult = mtmBase;
        }

        // Use same result for both mark and market since forward pricing has no source parameter
        auto markMtm = mtmResult;
        auto marketMtm = mtmResult;

        QMetaObject::invokeMethod(self, [self, tablePtr, row, offerId, makerRoleLower, markMtm, marketMtm, termsHash]() {
            if (!self || !tablePtr) {
                return;
            }
            self->forwardMtmPending.remove(offerId);
            TradeBoardTab::ForwardMtmCacheEntry entry;
            entry.terms_hash = termsHash;
            entry.mark_mtm = markMtm;
            entry.market_mtm = marketMtm;
            self->forwardMtmCache.insert(offerId, entry);
            self->applyForwardMtmResult(tablePtr, row, offerId, makerRoleLower, markMtm, marketMtm);
        }, Qt::QueuedConnection);
    });
}

void TradeBoardTab::applyForwardMtmResult(QTableWidget* table, int row, const QString& offerId, const QString& makerRole,
                                          const std::optional<double>& markMtm,
                                          const std::optional<double>& marketMtm)
{
    forwardMtmPending.remove(offerId);

    if (!table || row < 0 || row >= table->rowCount()) {
        return;
    }

    QTableWidgetItem* makerItem = table->item(row, 0);
    if (!makerItem || makerItem->data(Qt::UserRole).toString() != offerId) {
        return;
    }

    int reportDecimals = 8;
    if (walletModel) {
        WalletModel::AssetInfo tscInfo = walletModel->getAssetInfo("");
        if (tscInfo.has_decimals) {
            reportDecimals = tscInfo.decimals;
        }
    }
    const double toDisplayUnits = 1.0 / std::pow(10.0, reportDecimals);

    auto formatMtm = [&](const std::optional<double>& mtmBase) -> std::pair<QString, QColor> {
        if (!mtmBase) {
            return {QStringLiteral("--"), QColor(158, 158, 158)};
        }
        double mtm = *mtmBase * toDisplayUnits;
        if (mtm > 0.0) {
            return {QString("+%1").arg(mtm, 0, 'f', 8), QColor(76, 175, 80)};
        }
        if (mtm < 0.0) {
            return {QString("%1").arg(mtm, 0, 'f', 8), QColor(244, 67, 54)};
        }
        return {QStringLiteral("0.00000000"), QColor(158, 158, 158)};
    };

    QTableWidgetItem* marksItem = table->item(row, 2);
    if (marksItem) {
        auto display = formatMtm(markMtm);
        marksItem->setText(display.first);
        marksItem->setForeground(QBrush(display.second));
    }

    QTableWidgetItem* marketItem = table->item(row, 3);
    if (marketItem) {
        auto display = formatMtm(marketMtm ? marketMtm : markMtm);
        marketItem->setText(display.first);
        marketItem->setForeground(QBrush(display.second));
    }
}

void TradeBoardTab::scheduleSpotMtmUpdate(QTableWidget* table, int row, const OfferInfo& info)
{
    if (!walletModel || !table) {
        return;
    }

    // For spot offers, MTM shows the gain/loss vs fair market value:
    // MTM = (market_value of what you'd receive) - (market_value of what you'd send)
    // Where market_value uses current FX rates, and offer uses info.price

    QPointer<TradeBoardTab> self(this);
    QPointer<WalletModel> wm(walletModel);
    QPointer<QTableWidget> tablePtr(table);
    QString offerId = info.offer_id;
    QString assetSendTicker = info.asset_send;  // Empty = TSC, otherwise ticker like "GOLD"
    QString assetRecvTicker = info.asset_recv;  // Empty = TSC, otherwise ticker like "SILVER"
    double amountSend = info.amount;
    double offerPrice = info.price;
    double amountRecv = amountSend * offerPrice;

    // Get prices NOW (on main thread) before entering async context - assetPriceTab is not thread-safe
    double sendMarketPrice = assetSendTicker.isEmpty() ? 1.0 : priceInTSC(assetSendTicker);
    double recvMarketPrice = assetRecvTicker.isEmpty() ? 1.0 : priceInTSC(assetRecvTicker);

    // Convert amounts to atomic units (satoshis) for MTM calculation
    // The result will be in atomic units, which applySpotMtmResult will convert to display units
    int reportDecimals = 8;
    if (walletModel) {
        WalletModel::AssetInfo tscInfo = walletModel->getAssetInfo("");
        if (tscInfo.has_decimals) {
            reportDecimals = tscInfo.decimals;
        }
    }
    const double toAtomicUnits = std::pow(10.0, reportDecimals);

    (void)QtConcurrent::run([self, wm, tablePtr, offerId, amountSend, amountRecv, sendMarketPrice, recvMarketPrice, toAtomicUnits, row]() {
        if (!self || !wm || !tablePtr) {
            return;
        }

        // Calculate MTM from MAKER's perspective
        // Maker sends amountSend, receives amountRecv
        std::optional<double> mtmResult;

        // Convert to atomic units and calculate market values in atomic TSC units
        // Market value of what maker receives (in atomic units)
        double marketValueMakerReceives = (amountRecv * recvMarketPrice) * toAtomicUnits;
        // Market value of what maker sends (in atomic units)
        double marketValueMakerSends = (amountSend * sendMarketPrice) * toAtomicUnits;
        // MTM = market value of what you receive - market value of what you send (in atomic units)
        mtmResult = marketValueMakerReceives - marketValueMakerSends;

        QMetaObject::invokeMethod(self, [self, tablePtr, row, offerId, mtmResult]() {
            if (!self || !tablePtr) {
                return;
            }
            self->applySpotMtmResult(tablePtr, row, offerId, mtmResult, mtmResult);
        }, Qt::QueuedConnection);
    });
}

void TradeBoardTab::applySpotMtmResult(QTableWidget* table, int row, const QString& offerId,
                                       const std::optional<double>& markMtm,
                                       const std::optional<double>& marketMtm)
{
    if (!table || row < 0 || row >= table->rowCount()) {
        return;
    }

    QTableWidgetItem* makerItem = table->item(row, 0);
    if (!makerItem || makerItem->data(Qt::UserRole).toString() != offerId) {
        return;
    }

    int reportDecimals = 8;
    if (walletModel) {
        WalletModel::AssetInfo tscInfo = walletModel->getAssetInfo("");
        if (tscInfo.has_decimals) {
            reportDecimals = tscInfo.decimals;
        }
    }
    const double toDisplayUnits = 1.0 / std::pow(10.0, reportDecimals);

    auto formatMtm = [&](const std::optional<double>& mtmBase) -> std::pair<QString, QColor> {
        if (!mtmBase) {
            return {QStringLiteral("--"), QColor(158, 158, 158)};
        }
        double mtm = *mtmBase * toDisplayUnits;
        if (mtm > 0.0) {
            return {QString("+%1").arg(mtm, 0, 'f', 8), QColor(76, 175, 80)};
        }
        if (mtm < 0.0) {
            return {QString("%1").arg(mtm, 0, 'f', 8), QColor(244, 67, 54)};
        }
        return {QStringLiteral("0.00000000"), QColor(158, 158, 158)};
    };

    QTableWidgetItem* marksItem = table->item(row, 1);
    if (marksItem) {
        auto display = formatMtm(markMtm);
        marksItem->setText(display.first);
        marksItem->setForeground(QBrush(display.second));
    }

    QTableWidgetItem* marketItem = table->item(row, 2);
    if (marketItem) {
        auto display = formatMtm(marketMtm ? marketMtm : markMtm);
        marketItem->setText(display.first);
        marketItem->setForeground(QBrush(display.second));
    }
}

qulonglong TradeBoardTab::convertToAtomicUnits(double amount, const QString& asset_id) const
{
    if (!std::isfinite(amount) || amount <= 0.0) {
        return 0;
    }

    const int decimals = assetDecimals(asset_id);

    const double scale = std::pow(10.0, decimals);
    if (!std::isfinite(scale) || scale <= 0.0) {
        return 0;
    }

    double scaled = amount * scale;
    if (!std::isfinite(scaled) || scaled <= 0.0) {
        return 0;
    }

    const double maxInt = static_cast<double>(std::numeric_limits<int64_t>::max());
    if (scaled > maxInt) {
        scaled = maxInt;
    }

    return static_cast<qulonglong>(std::llround(scaled));
}

int TradeBoardTab::assetDecimals(const QString& asset_id) const
{
    QString key = asset_id;
    if (key.isEmpty()) {
        key = QStringLiteral("__NATIVE__");
    }
    key = key.toUpper();

    if (assetDecimalsCache.contains(key)) {
        return assetDecimalsCache.value(key);
    }

    int decimals = 8;
    if (walletModel && !asset_id.isEmpty()) {
        WalletModel::AssetInfo info = walletModel->getAssetInfo(asset_id);
        if (info.decimals >= 0) {
            decimals = info.decimals;
        }
    }

    assetDecimalsCache.insert(key, decimals);
    return decimals;
}

QByteArray TradeBoardTab::hashInlineTerms(const QVariantMap& inlineTerms) const
{
    QJsonObject obj = QJsonObject::fromVariantMap(inlineTerms);
    QJsonDocument doc(obj);
    return QCryptographicHash::hash(doc.toJson(QJsonDocument::Compact), QCryptographicHash::Sha1);
}

TradeBoardTab::ComputedMetrics TradeBoardTab::computeMetricsFromImmutables(
    double principal_qty, const QString& principal_asset,
    double collateral_qty, const QString& collateral_asset,
    double interest_qty, const QString& interest_asset,
    int maturity_height) const
{
    ComputedMetrics result;
    result.maturity_height = maturity_height;

    if (!walletModel) {
        return result;  // computed=false
    }

    // 1. Compute tenor_days from maturity_height (immutable blockchain param)
    if (maturity_height > 0) {
        int current_height = walletModel->clientModel().node().getNumBlocks();
        double blocks_remaining = std::max(0, maturity_height - current_height);
        result.tenor_days = static_cast<int>(std::round(blocks_remaining / 144.0));
    }

    // 2. Get current prices from AssetPriceTab (same as final review dialog)
    const double pPriceTSC = priceInTSC(principal_asset);
    const double cPriceTSC = priceInTSC(collateral_asset);
    const double iPriceTSC = priceInTSC(interest_asset);

    // 3. Compute LTV (principal value / collateral value in TSC)
    const bool havePV = (pPriceTSC > 0.0 && principal_qty > 0.0);
    const bool haveCV = (cPriceTSC > 0.0 && collateral_qty > 0.0);
    if (havePV && haveCV) {
        double principalValueTSC = principal_qty * pPriceTSC;
        double collateralValueTSC = collateral_qty * cPriceTSC;
        result.ltv = (principalValueTSC / collateralValueTSC) * 100.0;
    } else if (principal_qty > 0.0 && collateral_qty > 0.0 &&
               principal_asset.compare(collateral_asset, Qt::CaseInsensitive) == 0) {
        // Same asset - direct ratio
        result.ltv = (principal_qty / collateral_qty) * 100.0;
    }

    // 4. Compute APR (with cross-asset conversion if needed)
    if (interest_qty > 0.0 && principal_qty > 0.0 && result.tenor_days > 0) {
        double interestInPrincipal = 0.0;

        if (interest_asset.compare(principal_asset, Qt::CaseInsensitive) == 0) {
            // Same asset - direct ratio
            interestInPrincipal = interest_qty;
        } else if (iPriceTSC > 0.0 && pPriceTSC > 0.0) {
            // Cross-asset conversion via TSC
            double interestValueTSC = interest_qty * iPriceTSC;
            interestInPrincipal = interestValueTSC / pPriceTSC;
        }

        if (interestInPrincipal > 0.0) {
            // Day count fraction: Actual/365
            result.apr = (interestInPrincipal / principal_qty) *
                        (365.0 / static_cast<double>(result.tenor_days)) * 100.0;
        }
    }

    result.computed = true;
    return result;
}
