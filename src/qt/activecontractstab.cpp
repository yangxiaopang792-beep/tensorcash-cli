// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/activecontractstab.h>
#include <qt/contractregistrymodel.h>
#include <qt/contractdetaildialog.h>
#include <qt/walletmodel.h>
#include <qt/platformstyle.h>
#include <qt/themehelpers.h>

#include <univalue.h>
#include <interfaces/node.h>
#include <logging.h>

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QHeaderView>
#include <QGroupBox>
#include <QMessageBox>
#include <QStyledItemDelegate>
#include <QPainter>
#include <QApplication>
#include <QMouseEvent>
#include <QDialog>
#include <QDialogButtonBox>
#include <QSpinBox>
#include <QStringList>
#include <QMenu>
#include <QCursor>
#include <QLineEdit>
#include <QInputDialog>
#include <QRegularExpression>
#include <QComboBox>
#include <QPlainTextEdit>
#include <QFormLayout>
#include <QPushButton>
#include <QClipboard>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QByteArray>

#include <cmath>
#include <algorithm>

namespace {

QString AbbreviateId(const QString& contractId)
{
    if (contractId.isEmpty()) return contractId;
    return contractId.left(16) + "...";
}

QString FormatBtcAmount(double amount)
{
    return QString::number(amount, 'f', 8) + QObject::tr(" TSC");
}

QVariantMap UniValueToVariantMap(const UniValue& value)
{
    if (!value.isObject()) return {};
    QByteArray raw = QByteArray::fromStdString(value.write());
    QJsonParseError parseError;
    QJsonDocument doc = QJsonDocument::fromJson(raw, &parseError);
    if (parseError.error != QJsonParseError::NoError || !doc.isObject()) {
        return {};
    }
    return doc.object().toVariantMap();
}

struct RepoLifecycleContext {
    QString id;
    QString role;
    QString state;
    QString borrowerAddress;
    QString collateralAddress;
    QString lenderAddress;
    QString repayAddress;
    QString openingTxid;
    QString covenantScriptHex;
    QString vaultTxid;
    int vaultVout{-1};
    double vaultAmountBtc{0.0};
    QString vaultAmountFormatted;
    double collateralAmountBtc{0.0};
    int maturityHeight{0};
    int reorgConf{0};
    bool inferredVault{false};

    QVariantMap builderOptions() const
    {
        QVariantMap opts;
        if (!vaultTxid.isEmpty() && vaultVout >= 0) {
            opts.insert("vault_txid", vaultTxid);
            opts.insert("vault_vout", vaultVout);
            if (!vaultAmountFormatted.isEmpty()) {
                opts.insert("vault_amount", vaultAmountFormatted);
            }
        }
        if (!collateralAddress.isEmpty()) {
            opts.insert("collateral_address", collateralAddress);
        }
        return opts;
    }

    QString vaultLabel() const
    {
        if (vaultTxid.isEmpty() || vaultVout < 0) {
            return QObject::tr("unknown");
        }
        return QString("%1:%2").arg(vaultTxid.left(12) + "...").arg(vaultVout);
    }
};

QVariantMap FindContractSnapshot(WalletModel* walletModel, const QString& contractId)
{
    if (!walletModel) return {};
    const QList<QVariantMap> contracts = walletModel->listContracts();
    for (const QVariantMap& entry : contracts) {
        if (entry.value("id").toString() == contractId) {
            return entry;
        }
    }
    return {};
}

bool InferVaultFromOpeningTx(WalletModel* walletModel, RepoLifecycleContext& ctx, QString& error_out)
{
    if (!walletModel) {
        error_out = QObject::tr("Wallet unavailable");
        return false;
    }
    if (ctx.openingTxid.isEmpty()) {
        error_out = QObject::tr("Opening transaction for contract %1 is unknown. Refresh the contract list and try again.")
                        .arg(AbbreviateId(ctx.id));
        return false;
    }
    if (ctx.covenantScriptHex.isEmpty()) {
        error_out = QObject::tr("Covenant script fingerprint missing for contract %1. Re-import the offer or acceptance.")
                        .arg(AbbreviateId(ctx.id));
        return false;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(ctx.openingTxid.toStdString());
        params.push_back(true);
        UniValue txResp = walletModel->node().executeRpc("getrawtransaction", params, "");

        QVariantMap txMap = UniValueToVariantMap(txResp);
        QVariantList vouts = txMap.value("vout").toList();
        const QString targetScript = ctx.covenantScriptHex.toLower();

        for (const QVariant& entry : vouts) {
            const QVariantMap vout = entry.toMap();
            const QVariantMap script = vout.value("scriptPubKey").toMap();
            const QString scriptHex = script.value("hex").toString().toLower();
            if (scriptHex == targetScript) {
                ctx.vaultTxid = ctx.openingTxid;
                ctx.vaultVout = vout.value("n").toInt();
                const double valueBtc = vout.value("value").toDouble();
                if (valueBtc > 0.0) {
                    ctx.vaultAmountBtc = valueBtc;
                    ctx.vaultAmountFormatted = QString::number(valueBtc, 'f', 8);
                }
                ctx.inferredVault = true;
                return true;
            }
        }

        error_out = QObject::tr("Unable to locate the covenant output in opening transaction %1.")
                        .arg(AbbreviateId(ctx.openingTxid));
        return false;
    } catch (const UniValue& e) {
        error_out = QString::fromStdString(e.write());
        return false;
    } catch (const std::exception& e) {
        error_out = QString::fromStdString(e.what());
        return false;
    }
}

bool BuildRepoLifecycleContext(WalletModel* walletModel,
                               const QString& contractId,
                               RepoLifecycleContext& ctx,
                               QString& error_out)
{
    if (!walletModel) {
        error_out = QObject::tr("Wallet unavailable");
        return false;
    }

    ctx.id = contractId;
    QVariantMap snapshot = FindContractSnapshot(walletModel, contractId);
    if (snapshot.isEmpty()) {
        error_out = QObject::tr("Contract %1 is not tracked by this wallet.")
                        .arg(AbbreviateId(contractId));
        return false;
    }

    ctx.role = snapshot.value("role").toString();
    ctx.state = snapshot.value("status").toString();
    ctx.collateralAmountBtc = snapshot.value("collateral_amount").toDouble();
    ctx.openingTxid = snapshot.value("opening_txid").toString();

    try {
        UniValue params(UniValue::VARR);
        params.push_back(contractId.toStdString());
        UniValue statusResp = walletModel->node().executeRpc("contract.status", params, walletModel->getWalletName().toStdString());
        QVariantMap statusMap = UniValueToVariantMap(statusResp);

        if (statusMap.contains("state")) {
            ctx.state = statusMap.value("state").toString();
        }
        QVariantMap deadlines = statusMap.value("deadlines").toMap();
        if (!deadlines.isEmpty()) {
            ctx.maturityHeight = deadlines.value("maturity_height").toInt();
            ctx.reorgConf = deadlines.value("reorg_conf").toInt();
        }

        QVariantMap offer = statusMap.value("offer").toMap();
        if (!offer.isEmpty()) {
            ctx.borrowerAddress = offer.value("borrower_address").toString();
            ctx.collateralAddress = ctx.borrowerAddress;
            ctx.lenderAddress = offer.value("lender_address").toString();
            ctx.repayAddress = offer.value("repay_address_override").toString();
            if (ctx.repayAddress.isEmpty()) {
                ctx.repayAddress = ctx.lenderAddress;
            }
            QVariantMap sinks = offer.value("sinks").toMap();
            ctx.covenantScriptHex = sinks.value("collateral_spk").toString();

            QVariantMap vault = offer.value("vault").toMap();
            if (!vault.isEmpty()) {
                ctx.vaultTxid = vault.value("txid").toString();
                ctx.vaultVout = vault.value("vout").toInt();
                ctx.vaultAmountBtc = vault.value("amount").toDouble();
            }
        }
    } catch (const UniValue& e) {
        error_out = QString::fromStdString(e.write());
        return false;
    } catch (const std::exception& e) {
        error_out = QString::fromStdString(e.what());
        return false;
    }

    if (ctx.collateralAddress.isEmpty()) {
        ctx.collateralAddress = ctx.borrowerAddress;
    }
    if (ctx.vaultAmountBtc <= 0.0) {
        ctx.vaultAmountBtc = ctx.collateralAmountBtc;
    }
    ctx.vaultAmountFormatted = QString::number(ctx.vaultAmountBtc, 'f', 8);

    if (ctx.vaultTxid.isEmpty() || ctx.vaultVout < 0) {
        QString inferError;
        if (!InferVaultFromOpeningTx(walletModel, ctx, inferError)) {
            error_out = inferError;
            return false;
        }
    }

    return true;
}

} // namespace

// Custom delegate to render action buttons in the Actions column
class ActionButtonsDelegate : public QStyledItemDelegate
{
public:
    ActionButtonsDelegate(WalletModel* wallet, QObject* parent = nullptr)
        : QStyledItemDelegate(parent), walletModel(wallet) {}
private:
    WalletModel* walletModel{nullptr};
public:

    void paint(QPainter* painter, const QStyleOptionViewItem& option,
               const QModelIndex& index) const override
    {
        if (index.column() != ContractRegistryModel::Actions) {
            QStyledItemDelegate::paint(painter, option, index);
            return;
        }

        // Get contract data
        QString contractType = index.sibling(index.row(), ContractRegistryModel::Type).data().toString();
        QString contractRole = index.sibling(index.row(), ContractRegistryModel::Role).data().toString();
        QString contractStatus = index.sibling(index.row(), ContractRegistryModel::Status).data().toString();

        // Debug logging
        LogPrintf("ActionButtonsDelegate: type=%s, role=%s, status=%s\n",
                  contractType.toStdString().c_str(),
                  contractRole.toStdString().c_str(),
                  contractStatus.toStdString().c_str());

        QString statusLower = contractStatus.toLower();
        QString typeLower = contractType.toLower();
        QString roleLower = contractRole.toLower();
        // Raw contract family (the Type column DISPLAY shows "Difficulty CFD/Option", so dispatch off the
        // raw ContractTypeRole rather than the displayed Type text).
        QString rawTypeLower = index.data(ContractRegistryModel::ContractTypeRole).toString().toLower();

        // Determine which button to show based on contract type and state
        QString buttonText;
        QColor buttonColor;

        if (typeLower == "repo") {
            // Repo contracts: only show buttons for opened contracts
            if (statusLower != "opened") {
                LogPrintf("ActionButtonsDelegate: Skipping button - repo status=%s (need 'opened')\n", statusLower.toStdString().c_str());
                return;
            }

            if (roleLower == "borrower") {
                buttonText = tr("Repay");
                buttonColor = QColor(76, 175, 80);  // Green
            } else if (roleLower == "lender") {
            // Get maturity height from contract's full data
            QVariant contractData = index.data(ContractRegistryModel::ContractDataRole);
            int maturityHeight = 0;
            if (contractData.isValid() && contractData.canConvert<QVariantMap>()) {
                QVariantMap dataMap = contractData.toMap();
                maturityHeight = dataMap.value("maturity_height", 0).toInt();
            }

            // Get current block height
            int currentHeight = 0;
            if (walletModel) {
                currentHeight = walletModel->getNumBlocks();
            }

                // Only show Claim button if matured (with 2 block reorg_conf buffer)
                if (currentHeight >= maturityHeight + 2) {
                    buttonText = tr("Claim");
                    buttonColor = QColor(244, 67, 54);  // Red - can claim now
                } else if (currentHeight >= maturityHeight) {
                    buttonText = tr("Wait");
                    buttonColor = QColor(255, 152, 0);  // Orange - almost ready
                    return; // Don't show button yet, need reorg_conf blocks
                } else {
                    // Not matured yet, don't show button
                    return;
                }
            } else {
                return;  // Unknown role, no button
            }
        } else if (typeLower == "forward" || typeLower == "option") {
            // Forward/Option contracts: show settlement action menu
            if (statusLower == "opened" || statusLower == "delivery_pending") {
                // Contract is opened on blockchain
                if (roleLower == "long" || roleLower == "short") {
                    buttonText = tr("Actions ▼");  // Dropdown indicator
                    buttonColor = QColor(33, 150, 243);  // Blue
                } else {
                    return;  // Unknown role
                }
            } else {
                // No actions for completed contracts (closed/defaulted) or pending contracts (proposed/accepted)
                return;
            }
        } else if (rawTypeLower == "difficulty") {
            // Difficulty actions: Record Open once accepted (binds the funded vaults), then Settle once
            // opened/partially_settled: the "Actions ▼" menu offers unilateral Settle and Cooperative Close.
            if (statusLower == "accepted") {
                buttonText = tr("Record Open");
                buttonColor = QColor(33, 150, 243);  // Blue
            } else if (statusLower == "opened" || statusLower == "partially_settled") {
                buttonText = tr("Actions ▼");        // Settle leg / Cooperative close
                buttonColor = QColor(76, 175, 80);   // Green
            } else {
                return;  // "settled" (or unknown): no live legs to act on
            }
        } else if (rawTypeLower == "scalarcfd") {
            // Scalar-feed CFD: once accepted the two-party open PSBT flow (and record-open) is available;
            // once opened/partially_settled the "Actions ▼" menu offers unilateral Settle and Coop Close.
            if (statusLower == "accepted") {
                buttonText = tr("Actions ▼");        // Build open PSBT / Record open
                buttonColor = QColor(33, 150, 243);  // Blue
            } else if (statusLower == "opened" || statusLower == "partially_settled") {
                buttonText = tr("Actions ▼");        // Settle leg / Cooperative close
                buttonColor = QColor(76, 175, 80);   // Green
            } else {
                return;  // "settled" (or unknown): no live legs to act on
            }
        } else {
            // Spot contracts (atomic swaps) have no lifecycle actions after acceptance
            // Unknown contract types also have no actions
            return;
        }

        // Draw button
        painter->save();

        QRect buttonRect = option.rect.adjusted(5, 5, -5, -5);

        // Button background
        painter->setBrush(buttonColor);
        painter->setPen(Qt::NoPen);
        painter->drawRoundedRect(buttonRect, 3, 3);

        // Button text
        painter->setPen(Qt::white);
        painter->drawText(buttonRect, Qt::AlignCenter, buttonText);

        painter->restore();
    }

    bool editorEvent(QEvent* event, QAbstractItemModel* model,
                     const QStyleOptionViewItem& option,
                     const QModelIndex& index) override
    {
        if (index.column() != ContractRegistryModel::Actions) {
            return QStyledItemDelegate::editorEvent(event, model, option, index);
        }

        if (event->type() == QEvent::MouseButtonRelease) {
            QMouseEvent* mouseEvent = static_cast<QMouseEvent*>(event);

            if (option.rect.contains(mouseEvent->pos())) {
                // Get contract data - use ContractIdRole to get full ID, not truncated display version
                QString contractId = index.sibling(index.row(), ContractRegistryModel::ContractId).data(ContractRegistryModel::ContractIdRole).toString();
                QString contractType = index.sibling(index.row(), ContractRegistryModel::Type).data().toString();
                QString contractRole = index.sibling(index.row(), ContractRegistryModel::Role).data().toString();

                LogPrintf("ActionButtonsDelegate::editorEvent: contractId=%s, type=%s, role=%s\n",
                          contractId.toStdString().c_str(),
                          contractType.toStdString().c_str(),
                          contractRole.toStdString().c_str());

                QString typeLower = contractType.toLower();
                QString roleLower = contractRole.toLower();
                QString rawTypeLower = index.data(ContractRegistryModel::ContractTypeRole).toString().toLower();

                if (typeLower == "repo") {
                    if (roleLower == "borrower") {
                        handleRepay(contractId, contractRole);
                    } else if (roleLower == "lender") {
                        handleClaim(contractId, contractRole);
                    }
                } else if (typeLower == "forward" || typeLower == "option") {
                    handleForwardSettle(contractId, contractType, contractRole);
                } else if (rawTypeLower == "difficulty") {
                    const QString statusLower = index.sibling(index.row(), ContractRegistryModel::Status).data().toString().toLower();
                    bool changed = false;
                    if (statusLower == "accepted") {
                        changed = handleDifficultyRecordOpen(contractId);
                    } else if (statusLower == "opened" || statusLower == "partially_settled") {
                        const QVariantMap d = index.data(ContractRegistryModel::ContractDataRole).toMap();
                        QWidget* p = qobject_cast<QWidget*>(QApplication::activeWindow());
                        QMessageBox actBox(p);
                        actBox.setWindowTitle(tr("Difficulty Actions"));
                        actBox.setText(tr("Choose an action for this difficulty contract:"));
                        QPushButton* settleBtn = actBox.addButton(tr("Settle Leg (unilateral)"), QMessageBox::AcceptRole);
                        QPushButton* coopBtn = actBox.addButton(tr("Cooperative Close (2-of-2)"), QMessageBox::ActionRole);
                        actBox.addButton(QMessageBox::Cancel);
                        actBox.exec();
                        if (actBox.clickedButton() == settleBtn) {
                            changed = handleDifficultySettle(contractId, d.value("kind").toString(),
                                                             d.value("writer_side").toString(),
                                                             d.value("long_settled").toBool(),
                                                             d.value("short_settled").toBool());
                        } else if (actBox.clickedButton() == coopBtn) {
                            changed = handleDifficultyCoopClose(contractId, d);
                        }
                    }
                    if (changed) {
                        if (auto* rm = qobject_cast<ContractRegistryModel*>(model)) rm->refresh();
                    }
                } else if (rawTypeLower == "scalarcfd") {
                    const QString statusLower = index.sibling(index.row(), ContractRegistryModel::Status).data().toString().toLower();
                    const QVariantMap d = index.data(ContractRegistryModel::ContractDataRole).toMap();
                    const QString role = index.sibling(index.row(), ContractRegistryModel::Role).data().toString();
                    QWidget* p = qobject_cast<QWidget*>(QApplication::activeWindow());
                    bool changed = false;
                    if (statusLower == "accepted") {
                        // Two-party open PSBT flow, then record-open once broadcast.
                        QMessageBox actBox(p);
                        actBox.setWindowTitle(tr("Scalar CFD Actions"));
                        actBox.setText(tr("Choose an action for this scalar-feed CFD:"));
                        QPushButton* openBtn = actBox.addButton(tr("Open (build/continue PSBT)"), QMessageBox::AcceptRole);
                        QPushButton* recBtn = actBox.addButton(tr("Record Open (txid)"), QMessageBox::ActionRole);
                        actBox.addButton(QMessageBox::Cancel);
                        actBox.exec();
                        if (actBox.clickedButton() == openBtn) {
                            changed = handleScalarCfdOpen(contractId, role);
                        } else if (actBox.clickedButton() == recBtn) {
                            changed = handleScalarCfdRecordOpen(contractId, QString());
                        }
                    } else if (statusLower == "opened" || statusLower == "partially_settled") {
                        QMessageBox actBox(p);
                        actBox.setWindowTitle(tr("Scalar CFD Actions"));
                        actBox.setText(tr("Choose an action for this scalar-feed CFD:"));
                        QPushButton* settleBtn = actBox.addButton(tr("Settle Leg (unilateral)"), QMessageBox::AcceptRole);
                        QPushButton* coopBtn = actBox.addButton(tr("Cooperative Close (2-of-2)"), QMessageBox::ActionRole);
                        actBox.addButton(QMessageBox::Cancel);
                        actBox.exec();
                        if (actBox.clickedButton() == settleBtn) {
                            changed = handleScalarCfdSettle(contractId, d.value("long_settled").toBool(),
                                                            d.value("short_settled").toBool());
                        } else if (actBox.clickedButton() == coopBtn) {
                            changed = handleScalarCfdCoopClose(contractId, d);
                        }
                    }
                    if (changed) {
                        if (auto* rm = qobject_cast<ContractRegistryModel*>(model)) rm->refresh();
                    }
                } else if (typeLower == "spot") {
                    // No actions for spot contracts
                }
                return true;
            }
        }

        return false;
    }

    QSize sizeHint(const QStyleOptionViewItem& option,
                   const QModelIndex& index) const override
    {
        if (index.column() == ContractRegistryModel::Actions) {
            return QSize(80, 30);
        }
        return QStyledItemDelegate::sizeHint(option, index);
    }

private:
    // Record-Open action for a difficulty contract: bind the funded vault(s) into the wallet record from
    // the broadcast open txid.
    bool handleDifficultyRecordOpen(const QString& contractId) const
    {
        if (!walletModel) return false;
        QWidget* parent = qobject_cast<QWidget*>(QApplication::activeWindow());

        bool ok = false;
        const QString txid = QInputDialog::getText(parent, tr("Record Difficulty Open"),
            tr("Enter the broadcast open transaction id that funded this contract's vault(s):"),
            QLineEdit::Normal, QString(), &ok).trimmed();
        if (!ok || txid.isEmpty()) return false;

        static const QRegularExpression hexRe(QStringLiteral("^[0-9a-fA-F]{64}$"));
        if (!hexRe.match(txid).hasMatch()) {
            QMessageBox::warning(parent, tr("Record Open"),
                tr("That does not look like a 64-character transaction id."));
            return false;
        }

        WalletModel::DifficultyRecordOpenResult res = walletModel->difficultyRecordOpen(contractId, txid);
        if (!res.success) {
            QMessageBox::critical(parent, tr("Record Open Failed"),
                tr("Failed to record the open transaction:\n\n%1").arg(res.error));
            return false;
        }
        QMessageBox::information(parent, tr("Open Recorded"),
            tr("The funded vault(s) for contract %1 were recorded; it is now marked opened.")
                .arg(contractId.left(16) + "..."));
        return true;
    }

    // Unilateral covenant settlement of one difficulty leg: build_settlement -> sign the keeper fee input
    // -> difficulty.finalize_settlement (NOT finalizepsbt, which re-verifies the covenant leaf) -> broadcast.
    bool handleDifficultySettle(const QString& contractId, const QString& product, const QString& writerSide,
                                bool longSettled, bool shortSettled) const
    {
        if (!walletModel) return false;
        QWidget* parent = qobject_cast<QWidget*>(QApplication::activeWindow());

        // Which leg's IM vault to settle. An option has a single funded vault (the writer's leg); a CFD has
        // both, so let the user pick among the legs that are still LIVE (not already settled).
        QString leg;
        if (product == "option") {
            leg = (writerSide == "short") ? QStringLiteral("short") : QStringLiteral("long");
        } else {
            QStringList legs;
            if (!longSettled) legs << QStringLiteral("long");
            if (!shortSettled) legs << QStringLiteral("short");
            if (legs.isEmpty()) {
                QMessageBox::information(parent, tr("Nothing to Settle"),
                    tr("Both legs of this contract have already been settled."));
                return false;
            }
            if (legs.size() == 1) {
                leg = legs.first();
            } else {
                bool ok = false;
                const QString choice = QInputDialog::getItem(parent, tr("Settle Difficulty Leg"),
                    tr("Which leg's IM vault do you want to settle?"), legs, 0, false, &ok);
                if (!ok) return false;
                leg = choice;
            }
        }

        WalletModel::DifficultyPsbtResult built = walletModel->difficultyBuildSettlement(contractId, leg);
        if (!built.success) {
            QMessageBox::critical(parent, tr("Settlement Failed"),
                tr("Failed to build the settlement for the %1 leg:\n\n%2").arg(leg, built.error));
            return false;
        }

        const QString summary = tr("Settle the %1 leg of contract %2?\n\n"
                                   "Owner payout: %3 TSC\nCounterparty payout: %4 TSC\nKeeper fee: %5 TSC")
            .arg(leg, contractId.left(16) + "...")
            .arg(built.payout_owner, 0, 'f', 8)
            .arg(built.payout_cp, 0, 'f', 8)
            .arg(built.fee, 0, 'f', 8);
        if (QMessageBox::question(parent, tr("Confirm Settlement"), summary,
                                  QMessageBox::Yes | QMessageBox::No) != QMessageBox::Yes) {
            return false;
        }

        // Sign only the keeper's fee input (walletProcessPsbt handles unlock); the vault input is already
        // finalized signatureless by build_settlement, so do NOT finalize here.
        WalletModel::WalletProcessPsbtResult processed =
            walletModel->walletProcessPsbt(built.psbt, /*sign=*/true, /*sighash=*/QString(),
                                           /*bip32derivs=*/true, /*finalize=*/false);
        if (!processed.success) {
            QMessageBox::critical(parent, tr("Settlement Failed"),
                tr("Failed to sign the settlement fee input:\n\n%1").arg(processed.error));
            return false;
        }

        WalletModel::DifficultyPsbtResult finalized = walletModel->difficultyFinalizeSettlement(processed.psbt);
        if (!finalized.success || finalized.hex.isEmpty()) {
            QMessageBox::critical(parent, tr("Settlement Failed"),
                tr("Failed to extract the settlement transaction:\n\n%1").arg(finalized.error));
            return false;
        }

        try {
            UniValue params(UniValue::VARR);
            params.push_back(finalized.hex.toStdString());
            UniValue txidVal = walletModel->node().executeRpc("sendrawtransaction", params, "");
            const QString txid = QString::fromStdString(txidVal.isStr() ? txidVal.get_str() : txidVal.write());
            QMessageBox::information(parent, tr("Settlement Broadcast"),
                tr("The %1 leg settled. Transaction id:\n\n%2").arg(leg, txid));
            return true;
        } catch (const UniValue& e) {
            QMessageBox::critical(parent, tr("Broadcast Failed"),
                tr("Failed to broadcast the settlement transaction:\n\n%1").arg(QString::fromStdString(e.write())));
            return false;
        } catch (const std::exception& e) {
            QMessageBox::critical(parent, tr("Broadcast Failed"),
                tr("Failed to broadcast the settlement transaction:\n\n%1").arg(QString::fromStdString(e.what())));
            return false;
        }
    }

    // Cooperative close (early/negotiated 2-of-2 spend of a live leg's vault). Two-party: the proposer
    // picks a leg, enters the agreed split, signs its half and exports the PSBT; the counterparty pastes it,
    // adds its half (difficulty.sign_coop completes the 2-of-2) and broadcasts.
    bool handleDifficultyCoopClose(const QString& contractId, const QVariantMap& d) const
    {
        if (!walletModel) return false;
        QWidget* parent = qobject_cast<QWidget*>(QApplication::activeWindow());

        const QString product = d.value("kind").toString();
        const bool longSettled = d.value("long_settled").toBool();
        const bool shortSettled = d.value("short_settled").toBool();

        // Pick a still-live leg (mirrors the settle leg logic).
        QString leg;
        if (product == "option") {
            leg = (d.value("writer_side").toString() == "short") ? QStringLiteral("short") : QStringLiteral("long");
        } else {
            QStringList legs;
            if (!longSettled) legs << QStringLiteral("long");
            if (!shortSettled) legs << QStringLiteral("short");
            if (legs.isEmpty()) {
                QMessageBox::information(parent, tr("Nothing to Close"), tr("Both legs have already been settled/closed."));
                return false;
            }
            if (legs.size() == 1) {
                leg = legs.first();
            } else {
                bool ok = false;
                leg = QInputDialog::getItem(parent, tr("Cooperative Close Leg"),
                    tr("Which leg's IM vault do you want to cooperatively close?"), legs, 0, false, &ok);
                if (!ok) return false;
            }
        }
        const double vaultIm = (leg == "short") ? d.value("diff_short_im").toDouble() : d.value("diff_long_im").toDouble();

        // Propose (build + sign first half, export) vs Co-sign (complete a partner's PSBT, broadcast).
        QMessageBox modeBox(parent);
        modeBox.setWindowTitle(tr("Cooperative Close"));
        modeBox.setText(tr("A cooperative close needs BOTH parties to sign the 2-of-2 leaf.\n\n"
                           "Propose: enter the agreed split, sign your half, and hand the PSBT to the counterparty.\n"
                           "Co-sign: paste the counterparty's PSBT to add your half and broadcast."));
        QPushButton* proposeBtn = modeBox.addButton(tr("Propose"), QMessageBox::AcceptRole);
        QPushButton* cosignBtn = modeBox.addButton(tr("Co-sign Partner PSBT"), QMessageBox::ActionRole);
        modeBox.addButton(QMessageBox::Cancel);
        modeBox.exec();

        if (modeBox.clickedButton() == proposeBtn) {
            return coopClosePropose(contractId, leg, vaultIm);
        } else if (modeBox.clickedButton() == cosignBtn) {
            return coopCloseCosign(contractId, leg);
        }
        return false;
    }

    bool coopClosePropose(const QString& contractId, const QString& leg, double vaultIm) const
    {
        QWidget* parent = qobject_cast<QWidget*>(QApplication::activeWindow());

        bool ok = false;
        const QString text = QInputDialog::getMultiLineText(parent, tr("Cooperative Close — Agreed Outputs"),
            tr("Leg: %1.  Vault value: %2 TSC.\n\nEnter the agreed outputs, one per line as:\n\n  <address> <amount>\n\n"
               "The total must be ≤ the vault value; the remainder is the fee.").arg(leg).arg(vaultIm, 0, 'f', 8),
            QString(), &ok);
        if (!ok || text.trimmed().isEmpty()) return false;

        QVariantList outputs;
        for (const QString& rawLine : text.split('\n', Qt::SkipEmptyParts)) {
            const QString line = rawLine.trimmed();
            if (line.isEmpty()) continue;
            const QStringList parts = line.split(QRegularExpression("\\s+"), Qt::SkipEmptyParts);
            bool amtOk = false;
            const double amt = parts.size() == 2 ? parts[1].toDouble(&amtOk) : 0.0;
            if (parts.size() != 2 || !amtOk || amt <= 0.0) {
                QMessageBox::warning(parent, tr("Invalid Output"),
                    tr("Each line must be '<address> <amount>' with a positive amount:\n\n%1").arg(line));
                return false;
            }
            QVariantMap o;
            o["address"] = parts[0];
            o["amount"] = amt;
            outputs << o;
        }
        if (outputs.isEmpty()) return false;

        WalletModel::DifficultyPsbtResult built = walletModel->difficultyBuildCoopClose(contractId, leg, outputs);
        if (!built.success) {
            QMessageBox::critical(parent, tr("Cooperative Close Failed"),
                tr("Failed to build the cooperative-close PSBT:\n\n%1").arg(built.error));
            return false;
        }
        // Sign this wallet's half (difficulty.sign_coop requests unlock internally).
        WalletModel::DifficultyPsbtResult half = walletModel->difficultySignCoop(contractId, leg, built.psbt);
        if (!half.success) {
            QMessageBox::critical(parent, tr("Cooperative Close Failed"),
                tr("Failed to sign your half of the cooperative close:\n\n%1").arg(half.error));
            return false;
        }
        if (half.complete && !half.hex.isEmpty()) {
            // This wallet controls both cosign keys (single-party case): broadcast directly.
            return coopBroadcast(half.hex);
        }
        // Hand the half-signed PSBT to the counterparty.
        QMessageBox box(parent);
        box.setWindowTitle(tr("Cooperative Close — Your Half Signed"));
        box.setIcon(QMessageBox::Information);
        box.setText(tr("Your half of the 2-of-2 is signed. Send this PSBT to the counterparty; they Co-sign it "
                       "and broadcast."));
        box.setDetailedText(half.psbt);
        QPushButton* copyBtn = box.addButton(tr("Copy PSBT"), QMessageBox::ActionRole);
        box.addButton(QMessageBox::Close);
        box.exec();
        if (box.clickedButton() == copyBtn) {
            QClipboard* cb = QApplication::clipboard();
            if (cb) cb->setText(half.psbt);
        }
        return false; // nothing broadcast yet -> no contract state change
    }

    bool coopCloseCosign(const QString& contractId, const QString& leg) const
    {
        QWidget* parent = qobject_cast<QWidget*>(QApplication::activeWindow());

        bool ok = false;
        const QString psbt = QInputDialog::getMultiLineText(parent, tr("Co-sign Cooperative Close"),
            tr("Paste the counterparty's cooperative-close PSBT for the %1 leg:").arg(leg), QString(), &ok).trimmed();
        if (!ok || psbt.isEmpty()) return false;

        WalletModel::DifficultyPsbtResult done = walletModel->difficultySignCoop(contractId, leg, psbt);
        if (!done.success) {
            QMessageBox::critical(parent, tr("Cooperative Close Failed"),
                tr("Failed to add your signature:\n\n%1").arg(done.error));
            return false;
        }
        if (!done.complete || done.hex.isEmpty()) {
            QMessageBox::warning(parent, tr("Not Fully Signed"),
                tr("The PSBT is still not complete after adding your half. Both parties must sign the same PSBT."));
            return false;
        }
        return coopBroadcast(done.hex);
    }

    bool coopBroadcast(const QString& hex) const
    {
        QWidget* parent = qobject_cast<QWidget*>(QApplication::activeWindow());
        try {
            UniValue params(UniValue::VARR);
            params.push_back(hex.toStdString());
            UniValue txidVal = walletModel->node().executeRpc("sendrawtransaction", params, "");
            const QString txid = QString::fromStdString(txidVal.isStr() ? txidVal.get_str() : txidVal.write());
            QMessageBox::information(parent, tr("Cooperative Close Broadcast"),
                tr("The cooperative close was broadcast. Transaction id:\n\n%1").arg(txid));
            return true;
        } catch (const UniValue& e) {
            QMessageBox::critical(parent, tr("Broadcast Failed"),
                tr("Failed to broadcast the cooperative close:\n\n%1").arg(QString::fromStdString(e.write())));
            return false;
        } catch (const std::exception& e) {
            QMessageBox::critical(parent, tr("Broadcast Failed"),
                tr("Failed to broadcast the cooperative close:\n\n%1").arg(QString::fromStdString(e.what())));
            return false;
        }
    }

    // ===== Scalar-feed CFD (bilateral) Book handlers — the difficulty sibling ==========================
    // scalarcfd.* takes a bool isShort rather than a leg string; the OPEN is a genuine two-party multi-round
    // PSBT exchange (unlike difficulty's txid-only record_open), so it has its own build/sign/broadcast dialog.

    // Multi-round two-party open: scalarcfd.build_open funds THIS party's vault leg, optionally augmenting the
    // counterparty's prior partial PSBT. Party A builds its leg (no prior), signs, hands the PSBT over; party B
    // augments with the prior PSBT; when both legs are signed the tx is a normal funding tx -> finalize +
    // broadcast, then BOTH parties record_open(txid).
    bool handleScalarCfdOpen(const QString& contractId, const QString& role) const
    {
        if (!walletModel) return false;
        QWidget* parent = qobject_cast<QWidget*>(QApplication::activeWindow());

        QDialog dlg(parent);
        dlg.setWindowTitle(tr("Open Scalar CFD"));
        dlg.setModal(true);
        dlg.setMinimumWidth(560);
        QVBoxLayout* layout = new QVBoxLayout(&dlg);
        QLabel* intro = new QLabel(tr(
            "Fund your leg's vault. If your counterparty already built + signed their leg, paste their PSBT "
            "below to augment it; otherwise leave it blank to start. When both legs are signed the open is "
            "broadcast, and both parties then Record Open with the resulting txid."), &dlg);
        intro->setWordWrap(true);
        layout->addWidget(intro);

        QFormLayout* form = new QFormLayout();
        QComboBox* legCombo = new QComboBox(&dlg);
        legCombo->addItem(tr("long"));
        legCombo->addItem(tr("short"));
        legCombo->setCurrentIndex(role.toLower() == QLatin1String("short") ? 1 : 0);
        form->addRow(tr("Your leg:"), legCombo);
        QLineEdit* feeEdit = new QLineEdit(&dlg);
        feeEdit->setPlaceholderText(tr("fee rate sat/vB (optional)"));
        form->addRow(tr("Fee rate:"), feeEdit);
        QPlainTextEdit* priorEdit = new QPlainTextEdit(&dlg);
        priorEdit->setPlaceholderText(tr("counterparty partial open PSBT (leave blank to start)"));
        priorEdit->setMinimumHeight(70);
        form->addRow(tr("Prior PSBT:"), priorEdit);
        layout->addLayout(form);

        QDialogButtonBox* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dlg);
        buttons->button(QDialogButtonBox::Ok)->setText(tr("Build + Sign My Leg"));
        layout->addWidget(buttons);
        QObject::connect(buttons, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
        QObject::connect(buttons, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
        if (dlg.exec() != QDialog::Accepted) return false;

        const bool isShort = legCombo->currentIndex() == 1;
        const QString priorPsbt = priorEdit->toPlainText().trimmed();
        // A supplied prior PSBT means this wallet is the SECOND party augmenting the counterparty's already-
        // funded leg, so the resulting tx funds BOTH vaults and may be broadcast. Without a prior, build_open
        // funds only THIS wallet's single leg (scalar_cfd.cpp: one vault), and that partial can come back
        // walletprocesspsbt-"complete" (all of this party's own inputs signed) — but broadcasting it would
        // publish a one-leg tx that record_open cannot bind. So the first party must ALWAYS hand off, never
        // broadcast, regardless of the complete flag.
        const bool hadPrior = !priorPsbt.isEmpty();
        double fr = 0.0;
        const QString feeText = feeEdit->text().trimmed();
        if (!feeText.isEmpty()) {
            bool okfr = false; fr = feeText.toDouble(&okfr);
            if (!okfr || !std::isfinite(fr) || fr <= 0.0) {
                QMessageBox::warning(parent, tr("Open"), tr("Invalid fee rate.")); return false;
            }
        }

        WalletModel::ScalarCfdOpenResult built =
            walletModel->scalarCfdBuildOpen(contractId, isShort, priorPsbt, fr);
        if (!built.success) {
            QMessageBox::critical(parent, tr("Open Failed"),
                tr("Failed to build the open for the %1 leg:\n\n%2")
                    .arg(isShort ? tr("short") : tr("long"), built.error));
            return false;
        }

        // Sign this wallet's inputs; only the AUGMENTING party (prior supplied) may finalize + broadcast a
        // now-complete PSBT — that tx funds both legs. The first party always hands its partial off.
        WalletModel::WalletProcessPsbtResult processed =
            walletModel->walletProcessPsbt(built.psbt, /*sign=*/true, /*sighash=*/QString(),
                                           /*bip32derivs=*/true, /*finalize=*/false);
        if (!processed.success) {
            QMessageBox::critical(parent, tr("Open Failed"),
                tr("Failed to sign your open inputs:\n\n%1").arg(processed.error));
            return false;
        }

        if (processed.complete && hadPrior) {
            // Both legs signed: finalize + broadcast the funding tx (a normal tx, so finalizepsbt — NOT the
            // covenant-specific scalarcfd.finalize_settlement), then offer to record the open now.
            try {
                const std::string wname = walletModel->getWalletName().toStdString();
                UniValue fp(UniValue::VARR); fp.push_back(processed.psbt.toStdString());
                UniValue fres = walletModel->node().executeRpc("finalizepsbt", fp, wname);
                if (!(fres.exists("complete") && fres["complete"].get_bool() && fres.exists("hex"))) {
                    QMessageBox::warning(parent, tr("Open"),
                        tr("The open PSBT is fully signed but did not finalize; finalize + broadcast it manually."));
                    return false;
                }
                UniValue sp(UniValue::VARR); sp.push_back(fres["hex"].get_str());
                const QString txid = QString::fromStdString(
                    walletModel->node().executeRpc("sendrawtransaction", sp, wname).get_str());
                QMessageBox done(parent);
                done.setIcon(QMessageBox::Information);
                done.setWindowTitle(tr("Open Broadcast"));
                done.setText(tr("The open was broadcast.\n\nTxid: %1\n\nRecord Open in BOTH wallets to bind the "
                                "funded vaults.").arg(txid));
                QPushButton* recordBtn = done.addButton(tr("Record Open Now"), QMessageBox::AcceptRole);
                done.addButton(QMessageBox::Close);
                done.exec();
                if (done.clickedButton() == recordBtn) {
                    return handleScalarCfdRecordOpen(contractId, txid);
                }
                return false; // recorded separately; no state change until record_open
            } catch (const UniValue& e) {
                QMessageBox::critical(parent, tr("Broadcast Failed"),
                    tr("Failed to broadcast the open:\n\n%1").arg(QString::fromStdString(e.write())));
                return false;
            } catch (const std::exception& e) {
                QMessageBox::critical(parent, tr("Broadcast Failed"),
                    tr("Failed to broadcast the open:\n\n%1").arg(QString::fromStdString(e.what())));
                return false;
            }
        }

        // Partial: hand the half-built PSBT to the counterparty to augment + co-sign.
        QMessageBox box(parent);
        box.setWindowTitle(tr("Open — Your Leg Signed"));
        box.setIcon(QMessageBox::Information);
        box.setText(tr("Built + signed your %1 leg (vout %2). Send this PSBT to the counterparty to augment "
                       "their leg and broadcast; then Record Open in both wallets.")
                       .arg(built.leg).arg(built.vault_index));
        box.setDetailedText(processed.psbt);
        QPushButton* copyBtn = box.addButton(tr("Copy PSBT"), QMessageBox::ActionRole);
        box.addButton(QMessageBox::Close);
        box.exec();
        if (box.clickedButton() == copyBtn) {
            QClipboard* cb = QApplication::clipboard();
            if (cb) cb->setText(processed.psbt);
        }
        return false;
    }

    // Bind the funded vault(s) from the broadcast open txid. txidIn prefills from a just-broadcast open;
    // empty prompts interactively.
    bool handleScalarCfdRecordOpen(const QString& contractId, const QString& txidIn) const
    {
        if (!walletModel) return false;
        QWidget* parent = qobject_cast<QWidget*>(QApplication::activeWindow());
        QString txid = txidIn.trimmed();
        if (txid.isEmpty()) {
            bool ok = false;
            txid = QInputDialog::getText(parent, tr("Record Scalar CFD Open"),
                tr("Enter the broadcast open transaction id that funded this contract's vault(s):"),
                QLineEdit::Normal, QString(), &ok).trimmed();
            if (!ok || txid.isEmpty()) return false;
        }
        static const QRegularExpression hexRe(QStringLiteral("^[0-9a-fA-F]{64}$"));
        if (!hexRe.match(txid).hasMatch()) {
            QMessageBox::warning(parent, tr("Record Open"),
                tr("That does not look like a 64-character transaction id."));
            return false;
        }
        WalletModel::ScalarCfdRecordOpenResult res = walletModel->scalarCfdRecordOpen(contractId, txid);
        if (!res.success) {
            QMessageBox::critical(parent, tr("Record Open Failed"),
                tr("Failed to record the open transaction:\n\n%1").arg(res.error));
            return false;
        }
        QMessageBox::information(parent, tr("Open Recorded"),
            tr("The funded vault(s) for contract %1 were recorded; it is now marked opened.")
                .arg(contractId.left(16) + "..."));
        return true;
    }

    // Unilateral covenant settlement of one live scalar leg: build_settlement -> sign the keeper fee input
    // -> scalarcfd.finalize_settlement (NOT finalizepsbt, which re-verifies the covenant leaf) -> broadcast.
    bool handleScalarCfdSettle(const QString& contractId, bool longSettled, bool shortSettled) const
    {
        if (!walletModel) return false;
        QWidget* parent = qobject_cast<QWidget*>(QApplication::activeWindow());

        QStringList legs;
        if (!longSettled) legs << QStringLiteral("long");
        if (!shortSettled) legs << QStringLiteral("short");
        if (legs.isEmpty()) {
            QMessageBox::information(parent, tr("Nothing to Settle"),
                tr("Both legs of this contract have already been settled."));
            return false;
        }
        QString leg = legs.first();
        if (legs.size() > 1) {
            bool ok = false;
            leg = QInputDialog::getItem(parent, tr("Settle Scalar CFD Leg"),
                tr("Which leg's IM vault do you want to settle?"), legs, 0, false, &ok);
            if (!ok) return false;
        }
        const bool isShort = (leg == QLatin1String("short"));

        WalletModel::ScalarCfdSettlementResult built = walletModel->scalarCfdBuildSettlement(contractId, isShort, 0.0);
        if (!built.success) {
            QMessageBox::critical(parent, tr("Settlement Failed"),
                tr("Failed to build the settlement for the %1 leg:\n\n%2").arg(leg, built.error));
            return false;
        }
        const QString summary = tr("Settle the %1 leg of contract %2?\n\n"
                                   "Owner payout: %3\nCounterparty payout: %4\nKeeper fee: %5%6")
            .arg(leg, contractId.left(16) + "...", built.payout_owner, built.payout_cp, built.fee)
            .arg(built.is_fallback ? tr("\n(using the fallback scalar)") : QString());
        if (QMessageBox::question(parent, tr("Confirm Settlement"), summary,
                                  QMessageBox::Yes | QMessageBox::No) != QMessageBox::Yes) {
            return false;
        }

        // Sign only the keeper's fee input; the vault input is already finalized signatureless by
        // build_settlement, so do NOT finalize here — use scalarcfd.finalize_settlement to extract.
        WalletModel::WalletProcessPsbtResult processed =
            walletModel->walletProcessPsbt(built.psbt, /*sign=*/true, /*sighash=*/QString(),
                                           /*bip32derivs=*/true, /*finalize=*/false);
        if (!processed.success) {
            QMessageBox::critical(parent, tr("Settlement Failed"),
                tr("Failed to sign the settlement fee input:\n\n%1").arg(processed.error));
            return false;
        }
        WalletModel::ScalarCfdFinalizeResult finalized = walletModel->scalarCfdFinalizeSettlement(processed.psbt);
        if (!finalized.success || finalized.hex.isEmpty()) {
            QMessageBox::critical(parent, tr("Settlement Failed"),
                tr("Failed to extract the settlement transaction:\n\n%1").arg(finalized.error));
            return false;
        }
        try {
            UniValue params(UniValue::VARR);
            params.push_back(finalized.hex.toStdString());
            UniValue txidVal = walletModel->node().executeRpc("sendrawtransaction", params, "");
            const QString txid = QString::fromStdString(txidVal.isStr() ? txidVal.get_str() : txidVal.write());
            QMessageBox::information(parent, tr("Settlement Broadcast"),
                tr("The %1 leg settled. Transaction id:\n\n%2").arg(leg, txid));
            return true;
        } catch (const UniValue& e) {
            QMessageBox::critical(parent, tr("Broadcast Failed"),
                tr("Failed to broadcast the settlement transaction:\n\n%1").arg(QString::fromStdString(e.write())));
            return false;
        } catch (const std::exception& e) {
            QMessageBox::critical(parent, tr("Broadcast Failed"),
                tr("Failed to broadcast the settlement transaction:\n\n%1").arg(QString::fromStdString(e.what())));
            return false;
        }
    }

    // Cooperative close of one live scalar leg (2-of-2). Propose (build + sign half, export) vs Co-sign.
    bool handleScalarCfdCoopClose(const QString& contractId, const QVariantMap& d) const
    {
        if (!walletModel) return false;
        QWidget* parent = qobject_cast<QWidget*>(QApplication::activeWindow());
        const bool longSettled = d.value("long_settled").toBool();
        const bool shortSettled = d.value("short_settled").toBool();

        QStringList legs;
        if (!longSettled) legs << QStringLiteral("long");
        if (!shortSettled) legs << QStringLiteral("short");
        if (legs.isEmpty()) {
            QMessageBox::information(parent, tr("Nothing to Close"), tr("Both legs have already been settled/closed."));
            return false;
        }
        QString leg = legs.first();
        if (legs.size() > 1) {
            bool ok = false;
            leg = QInputDialog::getItem(parent, tr("Cooperative Close Leg"),
                tr("Which leg's IM vault do you want to cooperatively close?"), legs, 0, false, &ok);
            if (!ok) return false;
        }
        const bool isShort = (leg == QLatin1String("short"));

        QMessageBox modeBox(parent);
        modeBox.setWindowTitle(tr("Cooperative Close"));
        modeBox.setText(tr("A cooperative close needs BOTH parties to sign the 2-of-2 leaf.\n\n"
                           "Propose: enter the agreed split, sign your half, and hand the PSBT to the counterparty.\n"
                           "Co-sign: paste the counterparty's PSBT to add your half and broadcast."));
        QPushButton* proposeBtn = modeBox.addButton(tr("Propose"), QMessageBox::AcceptRole);
        QPushButton* cosignBtn = modeBox.addButton(tr("Co-sign Partner PSBT"), QMessageBox::ActionRole);
        modeBox.addButton(QMessageBox::Cancel);
        modeBox.exec();
        if (modeBox.clickedButton() == proposeBtn) return scalarCoopPropose(contractId, isShort, leg);
        if (modeBox.clickedButton() == cosignBtn) return scalarCoopCosign(contractId, isShort, leg);
        return false;
    }

    bool scalarCoopPropose(const QString& contractId, bool isShort, const QString& leg) const
    {
        QWidget* parent = qobject_cast<QWidget*>(QApplication::activeWindow());
        bool ok = false;
        const QString text = QInputDialog::getMultiLineText(parent, tr("Cooperative Close — Agreed Outputs"),
            tr("Leg: %1.\n\nEnter the agreed outputs, one per line as:\n\n  <address> <amount-TSC>\n\n"
               "The total must be ≤ the vault value; the remainder is the fee.").arg(leg), QString(), &ok);
        if (!ok || text.trimmed().isEmpty()) return false;

        // scalarcfd.build_coop_close takes amounts in sats (qint64); collect TSC and convert.
        QList<QPair<QString, qint64>> outputs;
        for (const QString& rawLine : text.split('\n', Qt::SkipEmptyParts)) {
            const QString line = rawLine.trimmed();
            if (line.isEmpty()) continue;
            const QStringList parts = line.split(QRegularExpression("\\s+"), Qt::SkipEmptyParts);
            bool amtOk = false;
            const double amt = parts.size() == 2 ? parts[1].toDouble(&amtOk) : 0.0;
            if (parts.size() != 2 || !amtOk || !std::isfinite(amt) || amt <= 0.0 || amt > 21000000.0) {
                QMessageBox::warning(parent, tr("Invalid Output"),
                    tr("Each line must be '<address> <amount>' with 0 < amount ≤ 21,000,000:\n\n%1").arg(line));
                return false;
            }
            outputs.append({parts[0], static_cast<qint64>(qRound64(amt * 100000000.0))});
        }
        if (outputs.isEmpty()) return false;

        WalletModel::ScalarCfdCoopCloseResult built = walletModel->scalarCfdBuildCoopClose(contractId, isShort, outputs);
        if (!built.success) {
            QMessageBox::critical(parent, tr("Cooperative Close Failed"),
                tr("Failed to build the cooperative-close PSBT:\n\n%1").arg(built.error));
            return false;
        }
        WalletModel::ScalarCfdSignCoopResult half = walletModel->scalarCfdSignCoop(contractId, isShort, built.psbt);
        if (!half.success) {
            QMessageBox::critical(parent, tr("Cooperative Close Failed"),
                tr("Failed to sign your half of the cooperative close:\n\n%1").arg(half.error));
            return false;
        }
        if (half.complete && !half.hex.isEmpty()) {
            return coopBroadcast(half.hex);  // single-party controls both cosign keys
        }
        QMessageBox box(parent);
        box.setWindowTitle(tr("Cooperative Close — Your Half Signed"));
        box.setIcon(QMessageBox::Information);
        box.setText(tr("Your half of the 2-of-2 is signed. Send this PSBT to the counterparty; they Co-sign it "
                       "and broadcast."));
        box.setDetailedText(half.psbt);
        QPushButton* copyBtn = box.addButton(tr("Copy PSBT"), QMessageBox::ActionRole);
        box.addButton(QMessageBox::Close);
        box.exec();
        if (box.clickedButton() == copyBtn) {
            QClipboard* cb = QApplication::clipboard();
            if (cb) cb->setText(half.psbt);
        }
        return false;
    }

    bool scalarCoopCosign(const QString& contractId, bool isShort, const QString& leg) const
    {
        QWidget* parent = qobject_cast<QWidget*>(QApplication::activeWindow());
        bool ok = false;
        const QString psbt = QInputDialog::getMultiLineText(parent, tr("Co-sign Cooperative Close"),
            tr("Paste the counterparty's cooperative-close PSBT for the %1 leg:").arg(leg), QString(), &ok).trimmed();
        if (!ok || psbt.isEmpty()) return false;
        WalletModel::ScalarCfdSignCoopResult done = walletModel->scalarCfdSignCoop(contractId, isShort, psbt);
        if (!done.success) {
            QMessageBox::critical(parent, tr("Cooperative Close Failed"),
                tr("Failed to add your signature:\n\n%1").arg(done.error));
            return false;
        }
        if (!done.complete || done.hex.isEmpty()) {
            QMessageBox::warning(parent, tr("Not Fully Signed"),
                tr("The PSBT is still not complete after adding your half. Both parties must sign the same PSBT."));
            return false;
        }
        return coopBroadcast(done.hex);
    }

    void handleRepay(const QString& contractId, const QString& contractRole) const
    {
        if (!walletModel) return;

        // Get the main application window as parent
        QWidget* parent = qobject_cast<QWidget*>(QApplication::activeWindow());

        // Create custom dialog with fee rate input
        QDialog dialog(parent);
        dialog.setWindowTitle(tr("Repay Loan"));
        dialog.setModal(true);

        QVBoxLayout* layout = new QVBoxLayout(&dialog);

        RepoLifecycleContext ctx;
        QString ctxError;
        if (!BuildRepoLifecycleContext(walletModel, contractId, ctx, ctxError)) {
            QMessageBox::critical(parent, tr("Repay Unavailable"), ctxError);
            return;
        }

        if (ctx.state.toLower() != "opened") {
            QMessageBox::warning(parent, tr("Repay Unavailable"),
                                 tr("Contract %1 is currently in '%2' state.")
                                     .arg(AbbreviateId(contractId))
                                     .arg(ctx.state));
            return;
        }

        if (!contractRole.isEmpty() && contractRole.toLower() != ctx.role.toLower()) {
            QMessageBox::warning(parent, tr("Repay Unavailable"),
                                 tr("This wallet is not the borrower for contract %1.")
                                     .arg(AbbreviateId(contractId)));
            return;
        }

        const QVariantMap builderOptions = ctx.builderOptions();
        if (!builderOptions.contains("vault_txid") || !builderOptions.contains("vault_vout")) {
            QMessageBox::warning(parent, tr("Repay Unavailable"),
                                 tr("Vault metadata for contract %1 is incomplete. Refresh the contract list or rescan the wallet.")
                                     .arg(AbbreviateId(contractId)));
            return;
        }

        QStringList infoLines;
        infoLines << tr("Contract ID: %1").arg(AbbreviateId(contractId));
        infoLines << tr("Repay destination: %1").arg(ctx.repayAddress.isEmpty() ? tr("unknown") : ctx.repayAddress);
        infoLines << tr("Collateral return address: %1").arg(ctx.collateralAddress.isEmpty() ? tr("unknown") : ctx.collateralAddress);
        infoLines << tr("Collateral size: %1").arg(FormatBtcAmount(ctx.collateralAmountBtc));
        infoLines << tr("Vault outpoint: %1").arg(ctx.vaultLabel());
        if (ctx.inferredVault) {
            infoLines << tr("Vault location inferred from opening transaction");
        }

        QLabel* infoLabel = new QLabel(infoLines.join("\n"));
        infoLabel->setWordWrap(true);
        infoLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        layout->addWidget(infoLabel);

        layout->addSpacing(10);

        // Fee rate input
        QHBoxLayout* feeLayout = new QHBoxLayout();
        feeLayout->addWidget(new QLabel(tr("Fee Rate (sat/vB):")));

        QSpinBox* feeSpinBox = new QSpinBox();
        feeSpinBox->setMinimum(1);
        feeSpinBox->setMaximum(1000);
        feeSpinBox->setValue(2); // Default 2 sat/vB
        feeSpinBox->setSuffix(" sat/vB");
        feeLayout->addWidget(feeSpinBox);
        feeLayout->addStretch();

        layout->addLayout(feeLayout);
        layout->addSpacing(10);

        // Buttons
        QDialogButtonBox* buttonBox = new QDialogButtonBox(QDialogButtonBox::Yes | QDialogButtonBox::No);
        connect(buttonBox, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
        connect(buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
        layout->addWidget(buttonBox);

        if (dialog.exec() != QDialog::Accepted) {
            return;
        }

        double feeRate = feeSpinBox->value();

        // User accepted, proceed with repay
        try {
            // Build repay transaction with user-specified fee rate
            WalletModel::RepoBuildResult buildResult = walletModel->repoBuildRepayRelease(contractId, feeRate, builderOptions);

            if (!buildResult.success) {
                QMessageBox::critical(parent, tr("Repay Failed"),
                    tr("Failed to build repay transaction:\n\n%1").arg(buildResult.error));
                return;
            }

            // CRITICAL: Always use PSBT path to match functional test behavior
            // build_repay_release only signs the vault input, not the funding inputs
            // We need walletprocesspsbt to sign ALL inputs (both vault and funding)
            if (buildResult.psbt.isEmpty()) {
                QMessageBox::critical(parent, tr("Repay Failed"),
                    tr("No PSBT returned from build_repay_release"));
                return;
            }

            // Process and sign the PSBT (signs all inputs including funding inputs)
            // Do not override per-input sighash; let PSBT normalization from
            // the builder (DEFAULT for Taproot) prevail.
            WalletModel::WalletProcessPsbtResult processResult = walletModel->walletProcessPsbt(
                buildResult.psbt, true, "", true, false);

            if (!processResult.success) {
                QMessageBox::critical(parent, tr("Repay Failed"),
                    tr("Failed to sign repay transaction:\n\n%1").arg(processResult.error));
                return;
            }

            QString txToBroadcast = processResult.psbt;

            // Broadcast the transaction
            WalletModel::BroadcastPsbtResult broadcastResult = walletModel->broadcastPsbt(txToBroadcast);

            if (!broadcastResult.success) {
                QMessageBox::critical(parent, tr("Repay Failed"),
                    tr("Failed to broadcast repay transaction:\n\n%1").arg(broadcastResult.error));
                return;
            }

            QMessageBox::information(parent, tr("Repay Success"),
                tr("Loan repaid successfully!\n\n"
                   "Transaction ID: %1\n\n"
                   "Your collateral will be recovered once confirmed.")
                .arg(broadcastResult.txid.left(16) + "..."));
        } catch (const UniValue& e) {
            // Handle UniValue exceptions (JSON-RPC errors)
            QString errorMsg = tr("Transaction failed");
            if (e.isStr()) {
                errorMsg = QString::fromStdString(e.get_str());
            } else if (e.isObject() && e.exists("message")) {
                errorMsg = QString::fromStdString(e["message"].get_str());
            }
            QMessageBox::critical(parent, tr("Repay Failed"),
                tr("Failed to process repay transaction:\n\n%1").arg(errorMsg));
        } catch (const std::exception& e) {
            QMessageBox::critical(parent, tr("Repay Failed"),
                tr("Failed to process repay transaction:\n\n%1")
                .arg(QString::fromStdString(e.what())));
        } catch (...) {
            QMessageBox::critical(parent, tr("Repay Failed"),
                tr("Failed to process repay transaction: Unknown error"));
        }
    }

    void handleClaim(const QString& contractId, const QString& contractRole) const
    {
        if (!walletModel) return;

        // Get the main application window as parent
        QWidget* parent = qobject_cast<QWidget*>(QApplication::activeWindow());

        // Create custom dialog with fee rate input
        QDialog dialog(parent);
        dialog.setWindowTitle(tr("Claim Collateral"));
        dialog.setModal(true);

        QVBoxLayout* layout = new QVBoxLayout(&dialog);

        RepoLifecycleContext ctx;
        QString ctxError;
        if (!BuildRepoLifecycleContext(walletModel, contractId, ctx, ctxError)) {
            QMessageBox::critical(parent, tr("Claim Unavailable"), ctxError);
            return;
        }

        if (ctx.state.toLower() != "opened") {
            QMessageBox::warning(parent, tr("Claim Unavailable"),
                                 tr("Contract %1 is currently in '%2' state.")
                                     .arg(AbbreviateId(contractId))
                                     .arg(ctx.state));
            return;
        }

        if (!contractRole.isEmpty() && contractRole.toLower() != ctx.role.toLower()) {
            QMessageBox::warning(parent, tr("Claim Unavailable"),
                                 tr("This wallet is not the lender for contract %1.")
                                     .arg(AbbreviateId(contractId)));
            return;
        }

        const QVariantMap builderOptions = ctx.builderOptions();
        if (!builderOptions.contains("vault_txid") || !builderOptions.contains("vault_vout")) {
            QMessageBox::warning(parent, tr("Claim Unavailable"),
                                 tr("Vault metadata for contract %1 is incomplete. Refresh the contract list or rescan the wallet.")
                                     .arg(AbbreviateId(contractId)));
            return;
        }

        const int currentHeight = walletModel->getNumBlocks();
        if (ctx.maturityHeight > 0) {
            if (currentHeight < ctx.maturityHeight) {
                const int remaining = ctx.maturityHeight - currentHeight;
                QMessageBox::information(parent, tr("Cannot Claim Yet"),
                                         tr("Collateral can only be claimed after maturity (block %1).\n\nWait %2 more blocks.")
                                             .arg(ctx.maturityHeight)
                                             .arg(std::max(1, remaining)));
                return;
            }
            const int requiredHeight = ctx.maturityHeight + std::max(1, ctx.reorgConf);
            if (currentHeight < requiredHeight) {
                QMessageBox::information(parent, tr("Waiting For Finality"),
                                         tr("A reorg buffer of %1 blocks is required.\n\nNeed block %2, current height %3.")
                                             .arg(std::max(1, ctx.reorgConf))
                                             .arg(requiredHeight)
                                             .arg(currentHeight));
                return;
            }
        }

        QStringList infoLines;
        infoLines << tr("Contract ID: %1").arg(AbbreviateId(contractId));
        infoLines << tr("Collateral size: %1").arg(FormatBtcAmount(ctx.collateralAmountBtc));
        infoLines << tr("Vault outpoint: %1").arg(ctx.vaultLabel());
        if (ctx.maturityHeight > 0) {
            infoLines << tr("Maturity height: %1 (current %2)").arg(ctx.maturityHeight).arg(currentHeight);
            infoLines << tr("Reorg buffer: %1 blocks").arg(std::max(1, ctx.reorgConf));
        }
        if (ctx.inferredVault) {
            infoLines << tr("Vault location inferred from opening transaction");
        }

        QLabel* infoLabel = new QLabel(infoLines.join("\n"));
        infoLabel->setWordWrap(true);
        infoLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        layout->addWidget(infoLabel);

        layout->addSpacing(10);

        // Fee rate input
        QHBoxLayout* feeLayout = new QHBoxLayout();
        feeLayout->addWidget(new QLabel(tr("Fee Rate (sat/vB):")));

        QSpinBox* feeSpinBox = new QSpinBox();
        feeSpinBox->setMinimum(1);
        feeSpinBox->setMaximum(1000);
        feeSpinBox->setValue(2); // Default 2 sat/vB
        feeSpinBox->setSuffix(" sat/vB");
        feeLayout->addWidget(feeSpinBox);
        feeLayout->addStretch();

        layout->addLayout(feeLayout);
        layout->addSpacing(10);

        // Buttons
        QDialogButtonBox* buttonBox = new QDialogButtonBox(QDialogButtonBox::Yes | QDialogButtonBox::No);
        connect(buttonBox, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
        connect(buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
        layout->addWidget(buttonBox);

        if (dialog.exec() != QDialog::Accepted) {
            return;
        }

        double feeRate = feeSpinBox->value();

        // User accepted, proceed with claim
        try {
            // Build sweep transaction with user-specified fee rate
            WalletModel::RepoBuildResult buildResult = walletModel->repoBuildDefaultSweep(contractId, feeRate, builderOptions);

            if (!buildResult.success) {
                // Check if it's a maturity error
                if (buildResult.error.contains("Maturity not satisfied", Qt::CaseInsensitive)) {
                    QMessageBox::warning(parent, tr("Cannot Claim Yet"),
                        tr("The loan has not matured yet.\n\n"
                           "You can only claim collateral after the maturity height is reached."));
                } else {
                    QMessageBox::critical(parent, tr("Claim Failed"),
                        tr("Failed to build sweep transaction:\n\n%1").arg(buildResult.error));
                }
                return;
            }

            // CRITICAL: Always use PSBT path to match functional test behavior
            // build_default_sweep only signs the vault input, not the funding inputs
            // We need walletprocesspsbt to sign ALL inputs (both vault and funding)
            if (buildResult.psbt.isEmpty()) {
                QMessageBox::critical(parent, tr("Claim Failed"),
                    tr("No PSBT returned from build_default_sweep"));
                return;
            }

            // Process and sign the PSBT (signs all inputs including funding inputs)
            // Do not override per-input sighash; let PSBT normalization from
            // the builder (DEFAULT for Taproot) prevail.
            WalletModel::WalletProcessPsbtResult processResult = walletModel->walletProcessPsbt(
                buildResult.psbt, true, "", true, false);

            if (!processResult.success) {
                QMessageBox::critical(parent, tr("Claim Failed"),
                    tr("Failed to sign sweep transaction:\n\n%1").arg(processResult.error));
                return;
            }

            QString txToBroadcast = processResult.psbt;

            // Broadcast the transaction
            WalletModel::BroadcastPsbtResult broadcastResult = walletModel->broadcastPsbt(txToBroadcast);

            if (!broadcastResult.success) {
                QMessageBox::critical(parent, tr("Claim Failed"),
                    tr("Failed to broadcast sweep transaction:\n\n%1").arg(broadcastResult.error));
                return;
            }

            QMessageBox::information(parent, tr("Claim Success"),
                tr("Collateral claimed successfully!\n\n"
                   "Transaction ID: %1")
                .arg(broadcastResult.txid.left(16) + "..."));
            } catch (const UniValue& e) {
                // Handle UniValue exceptions (JSON-RPC errors)
                QString errorMsg = tr("Transaction failed");
                if (e.isStr()) {
                    errorMsg = QString::fromStdString(e.get_str());
                } else if (e.isObject() && e.exists("message")) {
                    errorMsg = QString::fromStdString(e["message"].get_str());
                }
                QMessageBox::critical(parent, tr("Claim Failed"),
                    tr("Failed to process claim transaction:\n\n%1").arg(errorMsg));
            } catch (const std::exception& e) {
                QMessageBox::critical(parent, tr("Claim Failed"),
                    tr("Failed to process claim transaction:\n\n%1")
                    .arg(QString::fromStdString(e.what())));
            } catch (...) {
                QMessageBox::critical(parent, tr("Claim Failed"),
                    tr("Failed to process claim transaction: Unknown error"));
            }
        }

    void handleForwardSettle(const QString& contractId, const QString& contractType, const QString& contractRole) const
    {
        if (!walletModel) return;

        // Get the main application window as parent
        QWidget* parent = qobject_cast<QWidget*>(QApplication::activeWindow());

        // Query contract state to determine available actions
        WalletModel::ContractStatusResult status = walletModel->getContractStatus(contractId);
        if (!status.success) {
            QMessageBox::warning(parent, tr("Settlement Error"),
                tr("Failed to query contract status:\n\n%1").arg(status.error));
            return;
        }

        // Get current block height
        int currentHeight = walletModel->getNumBlocks();

        // Extract deadlines
        int deadline_short = status.deadlines.value("deadline_short", 0).toInt();
        int deadline_long = status.deadlines.value("deadline_long", 0).toInt();
        int reorg_conf = 2; // Default reorg confirmation blocks

        // Extract reorg_conf from offer terms if available
        if (status.offer.contains("terms")) {
            QVariantMap terms = status.offer.value("terms").toMap();
            reorg_conf = terms.value("reorg_conf", 2).toInt();
        }

        QString roleLower = contractRole.toLower();

        // Detect escrow existence from contract.status
        const QString stateLower = status.state.toLower();
        const bool shortAlreadyDelivered = (stateLower == "delivery_pending" && roleLower == "short");
        bool escrowExists = false;
        bool aEscrowExists = false;  // A_ESCROW created by Long
        bool bEscrowExists = false;  // B_ESCROW created by Short
        for (const QVariant& utxoVar : status.utxos) {
            QVariantMap utxo = utxoVar.toMap();
            QString role = utxo.value("role", "").toString().toLower();
            if (role.contains("escrow")) {
                escrowExists = true;
                if (role.contains("escrow_a")) {
                    aEscrowExists = true;
                } else if (role.contains("escrow_b")) {
                    bEscrowExists = true;
                }
            }
        }

        // Create action menu
        QMenu menu(parent);
        menu.setStyleSheet("QMenu { font-size: 12px; }");

        QAction* selfDeliveryAction = menu.addAction(tr("Deliver"));
        QAction* escrowClaimAction = menu.addAction(tr("Counter-Deliver"));
        QAction* escrowRefundAction = menu.addAction(tr("Refund Unclaimed Escrow"));
        QAction* imTimeoutAction = menu.addAction(tr("Claim IM Penalty"));
        menu.addSeparator();
        QAction* coopCloseAction = menu.addAction(tr("Cooperative Close"));
        menu.addSeparator();
        QAction* cancelAction = menu.addAction(tr("Cancel"));

        // Determine which actions are available based on deadlines and role
        bool canSelfDeliver = false;

        // Deliver: Short can deliver before deadline_short
        // Long can deliver ONLY after deadline_short (CLTV requirement in a_self leaf)
        if (roleLower == "short") {
            if (shortAlreadyDelivered) {
                canSelfDeliver = false;
                selfDeliveryAction->setEnabled(false);
                selfDeliveryAction->setToolTip(tr("You already delivered. Waiting for counterparty."));
            } else {
                canSelfDeliver = (currentHeight < deadline_short);
                if (!canSelfDeliver) {
                    selfDeliveryAction->setEnabled(false);
                    selfDeliveryAction->setToolTip(tr("Deadline passed (needed: < %1, current: %2)")
                        .arg(deadline_short).arg(currentHeight));
                }
            }
        } else if (roleLower == "long") {
            // Long can only deliver if:
            // 1. Current height >= deadline_short (CLTV requirement in a_self leaf)
            // 2. Current height < deadline_long (before long's deadline expires)
            // NOTE: We use deadline_short + reorg_conf for safety to avoid reorg issues
            bool cltvSatisfied = (currentHeight >= deadline_short + reorg_conf);
            canSelfDeliver = cltvSatisfied && (currentHeight < deadline_long);

            if (!cltvSatisfied) {
                selfDeliveryAction->setEnabled(false);
                selfDeliveryAction->setToolTip(tr("Too early - wait for Short deadline + safety margin (needed: ≥ %1, current: %2)")
                    .arg(deadline_short + reorg_conf).arg(currentHeight));
            } else if (currentHeight >= deadline_long) {
                selfDeliveryAction->setEnabled(false);
                selfDeliveryAction->setToolTip(tr("Your deadline passed (needed: < %1, current: %2)")
                    .arg(deadline_long).arg(currentHeight));
            }
        }

        // Counter-Deliver (escrow claim): Available immediately when counterparty created escrow
        // NO CLTV requirement - can be used as soon as escrow exists
        if (!escrowExists) {
            escrowClaimAction->setEnabled(false);
            escrowClaimAction->setToolTip(tr("Counterparty must deliver first (no escrow detected)"));
        } else if (roleLower == "short" && shortAlreadyDelivered) {
            escrowClaimAction->setEnabled(false);
            escrowClaimAction->setToolTip(tr("Await Long party delivery/claim"));
        } else if (currentHeight >= deadline_long) {
            escrowClaimAction->setEnabled(false);
            escrowClaimAction->setToolTip(tr("Deadline passed (needed: < %1, current: %2)")
                .arg(deadline_long).arg(currentHeight));
        } else {
            if (roleLower == "long") {
                escrowClaimAction->setToolTip(tr("Deliver your asset and claim Short's delivery from escrow (recovers your IM atomically)"));
            } else {
                escrowClaimAction->setToolTip(tr("Deliver your asset and claim Long's delivery from escrow"));
            }
        }

        // Refund Unclaimed Escrow: Available for whoever created the escrow
        // Short refunds if Short delivered and Long didn't claim
        // Long refunds if Long delivered (after Short's deadline) and Short didn't claim
        if (!escrowExists) {
            escrowRefundAction->setEnabled(false);
            escrowRefundAction->setToolTip(tr("You must deliver first to create escrow"));
        } else if (currentHeight < deadline_long + reorg_conf) {
            escrowRefundAction->setEnabled(false);
            escrowRefundAction->setToolTip(tr("Too early (needed: ≥ %1, current: %2)")
                .arg(deadline_long + reorg_conf).arg(currentHeight));
        } else {
            escrowRefundAction->setToolTip(tr("Get refund since counterparty didn't claim your escrow"));
        }

        // IM timeout: Only available if counterparty GHOSTED (never delivered)
        // NOTE: If they delivered, they already got their IM back via self_delivery
        // When SHORT delivers → creates B_ESCROW
        // When LONG delivers → creates A_ESCROW
        if (roleLower == "long") {
            // Long can sweep short's vault ONLY if short ghosted (no B_ESCROW exists)
            bool shortGhosted = !bEscrowExists;  // B_ESCROW only exists if SHORT delivered
            bool deadlinePassed = (currentHeight >= deadline_short + reorg_conf);
            if (!deadlinePassed) {
                imTimeoutAction->setEnabled(false);
                imTimeoutAction->setToolTip(tr("Too early (needed: ≥ %1, current: %2)")
                    .arg(deadline_short + reorg_conf).arg(currentHeight));
            } else if (!shortGhosted) {
                imTimeoutAction->setEnabled(false);
                imTimeoutAction->setToolTip(tr("Cannot claim: Short delivered and already recovered their IM"));
            } else {
                imTimeoutAction->setText(tr("Claim Short's IM (Ghosted)"));
                imTimeoutAction->setToolTip(tr("Sweep short party's IM vault as penalty for ghosting (never delivered)"));
            }
        } else if (roleLower == "short") {
            // Short can sweep long's vault ONLY if long ghosted (no A_ESCROW exists)
            bool longGhosted = !aEscrowExists;  // A_ESCROW only exists if LONG delivered
            bool deadlinePassed = (currentHeight >= deadline_long + reorg_conf);
            if (!deadlinePassed) {
                imTimeoutAction->setEnabled(false);
                imTimeoutAction->setToolTip(tr("Too early (needed: ≥ %1, current: %2)")
                    .arg(deadline_long + reorg_conf).arg(currentHeight));
            } else if (!longGhosted) {
                imTimeoutAction->setEnabled(false);
                imTimeoutAction->setToolTip(tr("Cannot claim: Long delivered and already recovered their IM"));
            } else {
                imTimeoutAction->setText(tr("Claim Long's IM (Ghosted)"));
                imTimeoutAction->setToolTip(tr("Sweep long party's IM vault as penalty for ghosting (never delivered)"));
            }
        }

        // Cooperative Close: Always available
        coopCloseAction->setToolTip(tr("Mutually agree on settlement distribution (requires counterparty cooperation)"));

        // Show menu at cursor position
        QAction* selectedAction = menu.exec(QCursor::pos());

        if (!selectedAction || selectedAction == cancelAction) {
            return;
        }

        // Handle selected action
        if (selectedAction == selfDeliveryAction) {
            handleForwardSelfDelivery(contractId, contractRole);
        } else if (selectedAction == escrowClaimAction) {
            handleForwardEscrowClaim(contractId, contractRole);
        } else if (selectedAction == escrowRefundAction) {
            handleForwardEscrowRefund(contractId, contractRole);
        } else if (selectedAction == imTimeoutAction) {
            handleForwardIMTimeout(contractId, contractRole);
        } else if (selectedAction == coopCloseAction) {
            QMessageBox::information(parent, tr("Not Implemented"),
                tr("Cooperative close requires interactive ceremony coordination.\n\n"
                   "Please use the cosign bridge or CLI:\n"
                   "forward.close_over_channel <session_id> <id>"));
        }
    }

    void handleForwardSelfDelivery(const QString& contractId, const QString& contractRole) const
    {
        if (!walletModel) return;

        QWidget* parent = qobject_cast<QWidget*>(QApplication::activeWindow());

        // Query contract status to get details
        WalletModel::ContractStatusResult status = walletModel->getContractStatus(contractId);
        if (!status.success) {
            QMessageBox::critical(parent, tr("Delivery Error"),
                tr("Failed to query contract status:\n\n%1").arg(status.error));
            return;
        }

        // Extract contract details for display
        QString roleLower = contractRole.toLower();
        int deadline_short = status.deadlines.value("deadline_short", 0).toInt();
        int deadline_long = status.deadlines.value("deadline_long", 0).toInt();
        int currentHeight = walletModel->getNumBlocks();

        // Validate deadline
        int yourDeadline = (roleLower == "short") ? deadline_short : deadline_long;
        if (currentHeight >= yourDeadline) {
            QMessageBox::warning(parent, tr("Delivery Unavailable"),
                tr("Your delivery deadline has passed.\n\n"
                   "Deadline: %1\n"
                   "Current Height: %2\n\n"
                   "Cannot execute self-delivery.")
                   .arg(yourDeadline).arg(currentHeight));
            return;
        }

        // Create confirmation dialog
        QDialog dialog(parent);
        dialog.setWindowTitle(tr("Deliver Asset"));
        dialog.setModal(true);

        QVBoxLayout* layout = new QVBoxLayout(&dialog);

        // Contract info
        QStringList infoLines;
        infoLines << tr("<b>Forward Contract - Deliver Your Asset</b>");
        infoLines << tr("Contract ID: %1").arg(AbbreviateId(contractId));
        infoLines << tr("Your Role: %1").arg(contractRole.toUpper());
        infoLines << "";
        infoLines << tr("Current Block Height: %1").arg(currentHeight);
        infoLines << tr("Your Delivery Deadline: %1").arg(yourDeadline);
        infoLines << tr("Blocks Remaining: %1").arg(yourDeadline - currentHeight);
        infoLines << "";
        infoLines << tr("<b>What will happen:</b>");
        infoLines << tr("• Your delivery asset will be placed in escrow");
        infoLines << tr("• Your initial margin (IM) will be refunded");
        infoLines << tr("• Counter-party can then claim from escrow by delivering their asset");

        QLabel* infoLabel = new QLabel(infoLines.join("\n"));
        infoLabel->setWordWrap(true);
        infoLabel->setTextFormat(Qt::RichText);
        infoLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        layout->addWidget(infoLabel);

        layout->addSpacing(10);

        // Fee rate input
        QHBoxLayout* feeLayout = new QHBoxLayout();
        feeLayout->addWidget(new QLabel(tr("Fee Rate (sat/vB):")));

        QSpinBox* feeSpinBox = new QSpinBox();
        feeSpinBox->setMinimum(1);
        feeSpinBox->setMaximum(1000);
        feeSpinBox->setValue(2); // Default 2 sat/vB
        feeSpinBox->setSuffix(" sat/vB");
        feeLayout->addWidget(feeSpinBox);
        feeLayout->addStretch();

        layout->addLayout(feeLayout);
        layout->addSpacing(10);

        // Advanced options (optional vault override)
        QLabel* advancedLabel = new QLabel(tr("<b>Advanced Options (Optional)</b>"));
        advancedLabel->setTextFormat(Qt::RichText);
        layout->addWidget(advancedLabel);

        QLabel* vaultHelpLabel = new QLabel(tr("Vault location is auto-detected. Only specify if auto-detection fails:"));
        vaultHelpLabel->setWordWrap(true);
        vaultHelpLabel->setStyleSheet("color: gray; font-size: 10pt;");
        layout->addWidget(vaultHelpLabel);

        QLineEdit* vaultTxidEdit = new QLineEdit();
        vaultTxidEdit->setPlaceholderText(tr("Vault txid (optional - leave empty for auto-detect)"));
        layout->addWidget(vaultTxidEdit);

        QSpinBox* vaultVoutSpinBox = new QSpinBox();
        vaultVoutSpinBox->setMinimum(0);
        vaultVoutSpinBox->setMaximum(999);
        vaultVoutSpinBox->setValue(0);
        vaultVoutSpinBox->setPrefix(tr("Vault vout: "));
        vaultVoutSpinBox->setEnabled(false); // Disabled until txid is provided
        layout->addWidget(vaultVoutSpinBox);

        // Enable vout spinbox only when txid is provided
        // Use context parameter (vaultVoutSpinBox) to auto-disconnect when widget is destroyed
        connect(vaultTxidEdit, &QLineEdit::textChanged, vaultVoutSpinBox,
                [vaultVoutSpinBox](const QString& text) {
            vaultVoutSpinBox->setEnabled(!text.trimmed().isEmpty());
        });

        layout->addSpacing(10);

        // Buttons
        QDialogButtonBox* buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
        buttonBox->button(QDialogButtonBox::Ok)->setText(tr("Deliver Asset"));
        connect(buttonBox, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
        connect(buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
        layout->addWidget(buttonBox);

        if (dialog.exec() != QDialog::Accepted) {
            return;
        }

        // Get user-specified fee rate
        double feeRate = feeSpinBox->value();

        // Get optional vault override
        QString vaultTxid = vaultTxidEdit->text().trimmed();
        int vaultVout = vaultVoutSpinBox->value();

        WalletModel::ForwardBuildSelfDeliveryResult buildResult;
        QList<QPair<QString, int>> lockedInputs;
        bool inputsUnlocked = false;
        auto unlockInputs = [&]() {
            if (!inputsUnlocked && walletModel && !lockedInputs.isEmpty()) {
                walletModel->unlockCoins(lockedInputs);
                inputsUnlocked = true;
            }
        };

        // User confirmed, proceed with self-delivery
        try {
            // Build self-delivery transaction with user-specified fee rate
            QVariantMap options;
            options["fee_rate"] = feeRate;

            // Add vault override if provided (otherwise RPC auto-detects)
            if (!vaultTxid.isEmpty()) {
                QString roleLower = contractRole.toLower();
                if (roleLower == "short") {
                    options["short_vault_txid"] = vaultTxid;
                    options["short_vault_vout"] = vaultVout;
                } else if (roleLower == "long") {
                    options["long_vault_txid"] = vaultTxid;
                    options["long_vault_vout"] = vaultVout;
                }
                LogPrintf("ActionButtonsDelegate: Manual vault override specified - %s_vault: %s:%d\n",
                          roleLower.toStdString().c_str(), vaultTxid.toStdString().c_str(), vaultVout);
            } else {
                LogPrintf("ActionButtonsDelegate: Using auto-detected vault location\n");
            }

            buildResult = walletModel->forwardBuildSelfDelivery(contractId, options);
            lockedInputs = buildResult.lockedInputs;

            if (!buildResult.success) {
                unlockInputs();
                QMessageBox::critical(parent, tr("Delivery Failed"),
                    tr("Failed to build self-delivery transaction:\n\n%1").arg(buildResult.error));
                return;
            }

            LogPrintf("ActionButtonsDelegate: Self-delivery PSBT built - side=%s, escrow_idx=%d, margin_idx=%d, complete=%d\n",
                      buildResult.side.toStdString().c_str(), buildResult.escrow_output_index,
                      buildResult.margin_output_index, buildResult.complete);

            QString txToBroadcast;

            // Check if transaction is already complete (hot wallet)
            if (buildResult.complete && !buildResult.hex.isEmpty()) {
                // Hot wallet - transaction is already signed
                txToBroadcast = buildResult.hex;
                LogPrintf("ActionButtonsDelegate: Self-delivery complete from hot wallet, broadcasting directly\n");
            } else {
                // Watch-only or hardware wallet - need to sign PSBT
                if (buildResult.psbt.isEmpty()) {
                    unlockInputs();
                    QMessageBox::critical(parent, tr("Delivery Failed"),
                        tr("No PSBT returned from build_self_delivery"));
                    return;
                }

                // Sign the PSBT
                WalletModel::WalletProcessPsbtResult processResult =
                    walletModel->walletProcessPsbt(buildResult.psbt, true, "", true, false);

                if (!processResult.success) {
                    unlockInputs();
                    QMessageBox::critical(parent, tr("Delivery Failed"),
                        tr("Failed to sign self-delivery transaction:\n\n%1").arg(processResult.error));
                    return;
                }

                txToBroadcast = processResult.psbt;
                LogPrintf("ActionButtonsDelegate: Self-delivery PSBT signed, complete=%d\n", processResult.complete);
            }

            // Broadcast the transaction
            WalletModel::BroadcastPsbtResult broadcastResult = walletModel->broadcastPsbt(txToBroadcast);

            if (!broadcastResult.success) {
                unlockInputs();
                QMessageBox::critical(parent, tr("Delivery Failed"),
                    tr("Failed to broadcast self-delivery transaction:\n\n%1").arg(broadcastResult.error));
                return;
            }

            // Success!
            QString successMsg = tr(
                "Self-delivery executed successfully!\n\n"
                "Transaction ID: %1\n\n"
                "Your delivery asset is now in escrow.\n"
                "Your initial margin has been refunded.\n\n"
                "Counter-party can claim from escrow by delivering their asset before the deadline."
            ).arg(broadcastResult.txid);

            QMessageBox::information(parent, tr("Delivery Success"), successMsg);

            LogPrintf("ActionButtonsDelegate: Self-delivery broadcast successful - txid=%s\n",
                      broadcastResult.txid.toStdString().c_str());

            unlockInputs();

        } catch (const UniValue& e) {
            QString errorMsg = tr("Transaction failed");
            if (e.isStr()) {
                errorMsg = QString::fromStdString(e.get_str());
            } else if (e.isObject() && e.exists("message")) {
                errorMsg = QString::fromStdString(e["message"].get_str());
            }
            unlockInputs();
            QMessageBox::critical(parent, tr("Delivery Failed"),
                tr("Failed to process self-delivery transaction:\n\n%1").arg(errorMsg));
        } catch (const std::exception& e) {
            unlockInputs();
            QMessageBox::critical(parent, tr("Delivery Failed"),
                tr("Failed to process self-delivery transaction:\n\n%1")
                .arg(QString::fromStdString(e.what())));
        } catch (...) {
            unlockInputs();
            QMessageBox::critical(parent, tr("Delivery Failed"),
                tr("Failed to process self-delivery transaction: Unknown error"));
        }
    }

    void handleForwardEscrowClaim(const QString& contractId, const QString& contractRole) const
    {
        if (!walletModel) return;

        QWidget* parent = qobject_cast<QWidget*>(QApplication::activeWindow());

        // Query contract status
        WalletModel::ContractStatusResult status = walletModel->getContractStatus(contractId);
        if (!status.success) {
            QMessageBox::critical(parent, tr("Escrow Claim Error"),
                tr("Failed to query contract status:\n\n%1").arg(status.error));
            return;
        }

        int deadline_long = status.deadlines.value("deadline_long", 0).toInt();
        int currentHeight = walletModel->getNumBlocks();

        // Validate timing
        if (currentHeight >= deadline_long) {
            QMessageBox::warning(parent, tr("Escrow Claim Unavailable"),
                tr("Deadline for claiming from escrow has passed.\n\n"
                   "Deadline: %1\n"
                   "Current Height: %2")
                   .arg(deadline_long).arg(currentHeight));
            return;
        }

        // AUTO-DETECT escrow from contract.status UTXOs
        QString autoDetectedEscrow;
        QString roleLower = contractRole.toLower();

        for (const QVariant& utxoVar : status.utxos) {
            QVariantMap utxo = utxoVar.toMap();
            QString role = utxo.value("role", "").toString().toLower();
            QString txid = utxo.value("txid", "").toString();
            int vout = utxo.value("vout", -1).toInt();

            // Look for escrow output based on role
            // Short party created escrow (role=short_escrow or similar)
            // Long party claims it (looks for escrow_b or forward_escrow_b)
            if (role.contains("escrow") && !txid.isEmpty() && vout >= 0) {
                autoDetectedEscrow = QString("%1:%2").arg(txid).arg(vout);
                LogPrintf("ActionButtonsDelegate: Auto-detected escrow outpoint: %s (role=%s)\n",
                          autoDetectedEscrow.toStdString().c_str(), role.toStdString().c_str());
                break;
            }
        }

        // Create input dialog
        QDialog dialog(parent);
        dialog.setWindowTitle(tr("Counter-Deliver"));
        dialog.setModal(true);

        QVBoxLayout* layout = new QVBoxLayout(&dialog);

        // Contract info
        QStringList infoLines;
        infoLines << tr("<b>Claim Asset from Escrow</b>");
        infoLines << tr("Contract ID: %1").arg(AbbreviateId(contractId));
        infoLines << tr("Your Role: %1").arg(contractRole.toUpper());
        infoLines << "";
        infoLines << tr("Current Height: %1").arg(currentHeight);
        infoLines << tr("Claim Deadline: %1").arg(deadline_long);
        infoLines << tr("Blocks Remaining: %1").arg(deadline_long - currentHeight);
        infoLines << "";
        infoLines << tr("<b>What will happen:</b>");
        infoLines << tr("• You will deliver your asset to counter-party");
        infoLines << tr("• You will claim the escrowed asset");
        infoLines << tr("• Both parties complete the forward contract");

        QLabel* infoLabel = new QLabel(infoLines.join("\n"));
        infoLabel->setWordWrap(true);
        infoLabel->setTextFormat(Qt::RichText);
        layout->addWidget(infoLabel);

        layout->addSpacing(10);

        // Escrow outpoint input (auto-detected or manual)
        QLabel* escrowLabel = new QLabel(tr("Escrow Outpoint (txid:vout):"));
        layout->addWidget(escrowLabel);

        QLineEdit* escrowEdit = new QLineEdit();

        QString hintText;
        if (!autoDetectedEscrow.isEmpty()) {
            // Auto-detected! Pre-fill and make it clear
            escrowEdit->setText(autoDetectedEscrow);
            escrowEdit->setStyleSheet(ThemeHelpers::isDarkPalette() ? "background-color: #1f3a23;" : "background-color: #e8f5e9;"); // Success-tinted background
            hintText = tr("<i><b>✓ Auto-detected</b> escrow from contract state.<br>"
                         "You can edit this if incorrect.</i>");
        } else {
            // No auto-detection, manual entry required
            escrowEdit->setPlaceholderText(tr("Enter txid:vout (e.g., abc123...def456:0)"));
            escrowEdit->setStyleSheet(ThemeHelpers::isDarkPalette() ? "background-color: #4a3a1a;" : "background-color: #fff3e0;"); // Warning-tinted background
            hintText = tr("<i><b>⚠ Manual entry required:</b> Escrow not auto-detected.<br>"
                         "Enter the txid:vout from the counter-party's self-delivery transaction.</i>");
        }
        layout->addWidget(escrowEdit);

        QLabel* escrowHint = new QLabel(hintText);
        escrowHint->setWordWrap(true);
        escrowHint->setTextFormat(Qt::RichText);
        layout->addWidget(escrowHint);

        layout->addSpacing(10);

        // Fee rate input
        QHBoxLayout* feeLayout = new QHBoxLayout();
        feeLayout->addWidget(new QLabel(tr("Fee Rate (sat/vB):")));

        QSpinBox* feeSpinBox = new QSpinBox();
        feeSpinBox->setMinimum(1);
        feeSpinBox->setMaximum(1000);
        feeSpinBox->setValue(2);
        feeSpinBox->setSuffix(" sat/vB");
        feeLayout->addWidget(feeSpinBox);
        feeLayout->addStretch();

        layout->addLayout(feeLayout);
        layout->addSpacing(10);

        // Advanced options (optional vault override for margin recovery)
        QLabel* advancedLabel = new QLabel(tr("<b>Advanced Options (Optional)</b>"));
        advancedLabel->setTextFormat(Qt::RichText);
        layout->addWidget(advancedLabel);

        QLabel* vaultHelpLabel = new QLabel(tr("Vault for margin recovery is auto-detected. Only specify if auto-detection fails:"));
        vaultHelpLabel->setWordWrap(true);
        vaultHelpLabel->setStyleSheet("color: gray; font-size: 10pt;");
        layout->addWidget(vaultHelpLabel);

        QLineEdit* vaultTxidEdit = new QLineEdit();
        vaultTxidEdit->setPlaceholderText(tr("Vault txid (optional - leave empty for auto-detect)"));
        layout->addWidget(vaultTxidEdit);

        QSpinBox* vaultVoutSpinBox = new QSpinBox();
        vaultVoutSpinBox->setMinimum(0);
        vaultVoutSpinBox->setMaximum(999);
        vaultVoutSpinBox->setValue(0);
        vaultVoutSpinBox->setPrefix(tr("Vault vout: "));
        vaultVoutSpinBox->setEnabled(false);
        layout->addWidget(vaultVoutSpinBox);

        connect(vaultTxidEdit, &QLineEdit::textChanged, [vaultVoutSpinBox](const QString& text) {
            vaultVoutSpinBox->setEnabled(!text.trimmed().isEmpty());
        });

        layout->addSpacing(10);

        // Buttons
        QDialogButtonBox* buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
        buttonBox->button(QDialogButtonBox::Ok)->setText(tr("Counter-Deliver"));
        connect(buttonBox, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
        connect(buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
        layout->addWidget(buttonBox);

        if (dialog.exec() != QDialog::Accepted) {
            return;
        }

        // Parse escrow outpoint
        QString escrowOutpointStr = escrowEdit->text().trimmed();
        if (escrowOutpointStr.isEmpty()) {
            QMessageBox::warning(parent, tr("Invalid Input"),
                tr("Please provide the escrow outpoint (txid:vout)"));
            return;
        }

        QStringList parts = escrowOutpointStr.split(":");
        if (parts.size() != 2) {
            QMessageBox::warning(parent, tr("Invalid Format"),
                tr("Escrow outpoint must be in format: txid:vout\n\n"
                   "Example: abc123...def456:0"));
            return;
        }

        QString escrowTxid = parts[0].trimmed();
        bool ok;
        int escrowVout = parts[1].trimmed().toInt(&ok);
        if (!ok || escrowVout < 0) {
            QMessageBox::warning(parent, tr("Invalid Vout"),
                tr("Output index must be a non-negative integer"));
            return;
        }

        // Get fee rate from user input
        double feeRate = feeSpinBox->value();

        // Get optional vault override
        QString vaultTxid = vaultTxidEdit->text().trimmed();
        int vaultVout = vaultVoutSpinBox->value();

        // User confirmed, proceed with escrow claim
        try {
            QVariantMap options;
            options["fee_rate"] = feeRate;

            // Add vault override if provided (for margin recovery)
            if (!vaultTxid.isEmpty()) {
                QString roleLower = contractRole.toLower();
                if (roleLower == "short") {
                    options["short_vault_txid"] = vaultTxid;
                    options["short_vault_vout"] = vaultVout;
                } else if (roleLower == "long") {
                    options["long_vault_txid"] = vaultTxid;
                    options["long_vault_vout"] = vaultVout;
                }
                LogPrintf("ActionButtonsDelegate: Manual vault override for margin recovery - %s_vault: %s:%d\n",
                          roleLower.toStdString().c_str(), vaultTxid.toStdString().c_str(), vaultVout);
            }

            WalletModel::ForwardBuildEscrowClaimResult buildResult =
                walletModel->forwardBuildEscrowClaim(contractId, escrowTxid, escrowVout, options);

            if (!buildResult.success) {
                QMessageBox::critical(parent, tr("Escrow Claim Failed"),
                    tr("Failed to build escrow claim transaction:\n\n%1").arg(buildResult.error));
                return;
            }

            LogPrintf("ActionButtonsDelegate: Escrow claim PSBT built - payment_idx=%d, complete=%d\n",
                      buildResult.payment_output_index, buildResult.complete);

            QString txToBroadcast;

            if (buildResult.complete && !buildResult.hex.isEmpty()) {
                txToBroadcast = buildResult.hex;
                LogPrintf("ActionButtonsDelegate: Escrow claim complete from hot wallet\n");
            } else {
                if (buildResult.psbt.isEmpty()) {
                    QMessageBox::critical(parent, tr("Escrow Claim Failed"),
                        tr("No PSBT returned from build_escrow_claim"));
                    return;
                }

                WalletModel::WalletProcessPsbtResult processResult =
                    walletModel->walletProcessPsbt(buildResult.psbt, true, "", true, false);

                if (!processResult.success) {
                    QMessageBox::critical(parent, tr("Escrow Claim Failed"),
                        tr("Failed to sign escrow claim transaction:\n\n%1").arg(processResult.error));
                    return;
                }

                txToBroadcast = processResult.psbt;
            }

            WalletModel::BroadcastPsbtResult broadcastResult = walletModel->broadcastPsbt(txToBroadcast);

            if (!broadcastResult.success) {
                QMessageBox::critical(parent, tr("Escrow Claim Failed"),
                    tr("Failed to broadcast escrow claim transaction:\n\n%1").arg(broadcastResult.error));
                return;
            }

            QString successMsg = tr(
                "Escrow claim executed successfully!\n\n"
                "Transaction ID: %1\n\n"
                "You have claimed the escrowed asset by delivering your asset.\n"
                "Forward contract is now complete!"
            ).arg(broadcastResult.txid);

            QMessageBox::information(parent, tr("Escrow Claim Success"), successMsg);

            LogPrintf("ActionButtonsDelegate: Escrow claim broadcast successful - txid=%s\n",
                      broadcastResult.txid.toStdString().c_str());

        } catch (const UniValue& e) {
            QString errorMsg = tr("Transaction failed");
            if (e.isStr()) {
                errorMsg = QString::fromStdString(e.get_str());
            } else if (e.isObject() && e.exists("message")) {
                errorMsg = QString::fromStdString(e["message"].get_str());
            }
            QMessageBox::critical(parent, tr("Escrow Claim Failed"),
                tr("Failed to process escrow claim transaction:\n\n%1").arg(errorMsg));
        } catch (const std::exception& e) {
            QMessageBox::critical(parent, tr("Escrow Claim Failed"),
                tr("Failed to process escrow claim transaction:\n\n%1")
                .arg(QString::fromStdString(e.what())));
        } catch (...) {
            QMessageBox::critical(parent, tr("Escrow Claim Failed"),
                tr("Failed to process escrow claim transaction: Unknown error"));
        }
    }

    void handleForwardEscrowRefund(const QString& contractId, const QString& contractRole) const
    {
        if (!walletModel) return;

        QWidget* parent = qobject_cast<QWidget*>(QApplication::activeWindow());

        // Query contract status
        WalletModel::ContractStatusResult status = walletModel->getContractStatus(contractId);
        if (!status.success) {
            QMessageBox::critical(parent, tr("Escrow Refund Error"),
                tr("Failed to query contract status:\n\n%1").arg(status.error));
            return;
        }

        int deadline_long = status.deadlines.value("deadline_long", 0).toInt();
        int reorg_conf = 2; // Default
        if (status.offer.contains("terms")) {
            QVariantMap terms = status.offer.value("terms").toMap();
            reorg_conf = terms.value("reorg_conf", 2).toInt();
        }
        int currentHeight = walletModel->getNumBlocks();
        int requiredHeight = deadline_long + reorg_conf;

        // Validate timing
        if (currentHeight < requiredHeight) {
            QMessageBox::warning(parent, tr("Escrow Refund Unavailable"),
                tr("Too early to claim escrow refund.\n\n"
                   "Required Height: %1\n"
                   "Current Height: %2\n"
                   "Blocks Remaining: %3")
                   .arg(requiredHeight).arg(currentHeight).arg(requiredHeight - currentHeight));
            return;
        }

        // AUTO-DETECT escrow from contract.status UTXOs
        QString autoDetectedEscrow;

        for (const QVariant& utxoVar : status.utxos) {
            QVariantMap utxo = utxoVar.toMap();
            QString role = utxo.value("role", "").toString().toLower();
            QString txid = utxo.value("txid", "").toString();
            int vout = utxo.value("vout", -1).toInt();

            // Look for escrow output
            if (role.contains("escrow") && !txid.isEmpty() && vout >= 0) {
                autoDetectedEscrow = QString("%1:%2").arg(txid).arg(vout);
                LogPrintf("ActionButtonsDelegate: Auto-detected escrow for refund: %s (role=%s)\n",
                          autoDetectedEscrow.toStdString().c_str(), role.toStdString().c_str());
                break;
            }
        }

        // Create input dialog
        QDialog dialog(parent);
        dialog.setWindowTitle(tr("Refund Unclaimed Escrow"));
        dialog.setModal(true);

        QVBoxLayout* layout = new QVBoxLayout(&dialog);

        // Contract info
        QStringList infoLines;
        infoLines << tr("<b>Refund Asset from Escrow</b>");
        infoLines << tr("Contract ID: %1").arg(AbbreviateId(contractId));
        infoLines << tr("Your Role: %1").arg(contractRole.toUpper());
        infoLines << "";
        infoLines << tr("Current Height: %1").arg(currentHeight);
        infoLines << tr("Required Height: %1").arg(requiredHeight);
        infoLines << "";
        infoLines << tr("<b>What will happen:</b>");
        infoLines << tr("• Counter-party failed to claim before deadline");
        infoLines << tr("• Your escrowed asset will be returned to you");
        infoLines << tr("• You keep your IM refund from self-delivery");

        QLabel* infoLabel = new QLabel(infoLines.join("\n"));
        infoLabel->setWordWrap(true);
        infoLabel->setTextFormat(Qt::RichText);
        layout->addWidget(infoLabel);

        layout->addSpacing(10);

        // Escrow outpoint input (auto-detected or manual)
        QLabel* escrowLabel = new QLabel(tr("Escrow Outpoint (txid:vout):"));
        layout->addWidget(escrowLabel);

        QLineEdit* escrowEdit = new QLineEdit();

        QString hintText;
        if (!autoDetectedEscrow.isEmpty()) {
            // Auto-detected! Pre-fill and make it clear
            escrowEdit->setText(autoDetectedEscrow);
            escrowEdit->setStyleSheet(ThemeHelpers::isDarkPalette() ? "background-color: #1f3a23;" : "background-color: #e8f5e9;"); // Success-tinted background
            hintText = tr("<i><b>✓ Auto-detected</b> escrow from your self-delivery transaction.<br>"
                         "You can edit this if incorrect.</i>");
        } else {
            // No auto-detection, manual entry required
            escrowEdit->setPlaceholderText(tr("Enter txid:vout (e.g., abc123...def456:0)"));
            escrowEdit->setStyleSheet(ThemeHelpers::isDarkPalette() ? "background-color: #4a3a1a;" : "background-color: #fff3e0;"); // Warning-tinted background
            hintText = tr("<i><b>⚠ Manual entry required:</b> Escrow not auto-detected.<br>"
                         "Enter the txid:vout from your self-delivery transaction.</i>");
        }
        layout->addWidget(escrowEdit);

        QLabel* escrowHint = new QLabel(hintText);
        escrowHint->setWordWrap(true);
        escrowHint->setTextFormat(Qt::RichText);
        layout->addWidget(escrowHint);

        layout->addSpacing(10);

        // Fee rate input
        QHBoxLayout* feeLayout = new QHBoxLayout();
        feeLayout->addWidget(new QLabel(tr("Fee Rate (sat/vB):")));

        QSpinBox* feeSpinBox = new QSpinBox();
        feeSpinBox->setMinimum(1);
        feeSpinBox->setMaximum(1000);
        feeSpinBox->setValue(2);
        feeSpinBox->setSuffix(" sat/vB");
        feeLayout->addWidget(feeSpinBox);
        feeLayout->addStretch();

        layout->addLayout(feeLayout);
        layout->addSpacing(10);

        // Advanced options (optional vault override)
        QLabel* advancedLabel = new QLabel(tr("<b>Advanced Options (Optional)</b>"));
        advancedLabel->setTextFormat(Qt::RichText);
        layout->addWidget(advancedLabel);

        QLabel* vaultHelpLabel = new QLabel(tr("Vault location is auto-detected. Only specify if auto-detection fails:"));
        vaultHelpLabel->setWordWrap(true);
        vaultHelpLabel->setStyleSheet("color: gray; font-size: 10pt;");
        layout->addWidget(vaultHelpLabel);

        QLineEdit* vaultTxidEdit = new QLineEdit();
        vaultTxidEdit->setPlaceholderText(tr("Vault txid (optional - leave empty for auto-detect)"));
        layout->addWidget(vaultTxidEdit);

        QSpinBox* vaultVoutSpinBox = new QSpinBox();
        vaultVoutSpinBox->setMinimum(0);
        vaultVoutSpinBox->setMaximum(999);
        vaultVoutSpinBox->setValue(0);
        vaultVoutSpinBox->setPrefix(tr("Vault vout: "));
        vaultVoutSpinBox->setEnabled(false);
        layout->addWidget(vaultVoutSpinBox);

        connect(vaultTxidEdit, &QLineEdit::textChanged, [vaultVoutSpinBox](const QString& text) {
            vaultVoutSpinBox->setEnabled(!text.trimmed().isEmpty());
        });

        layout->addSpacing(10);

        // Buttons
        QDialogButtonBox* buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
        buttonBox->button(QDialogButtonBox::Ok)->setText(tr("Refund Escrow"));
        connect(buttonBox, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
        connect(buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
        layout->addWidget(buttonBox);

        if (dialog.exec() != QDialog::Accepted) {
            return;
        }

        // Get user-specified fee rate
        double feeRate = feeSpinBox->value();

        // Get optional vault override
        QString vaultTxid = vaultTxidEdit->text().trimmed();
        int vaultVout = vaultVoutSpinBox->value();

        // Parse escrow outpoint
        QString escrowOutpointStr = escrowEdit->text().trimmed();
        if (escrowOutpointStr.isEmpty()) {
            QMessageBox::warning(parent, tr("Invalid Input"),
                tr("Please provide the escrow outpoint (txid:vout)"));
            return;
        }

        QStringList parts = escrowOutpointStr.split(":");
        if (parts.size() != 2) {
            QMessageBox::warning(parent, tr("Invalid Format"),
                tr("Escrow outpoint must be in format: txid:vout\n\n"
                   "Example: abc123...def456:0"));
            return;
        }

        QString escrowTxid = parts[0].trimmed();
        bool ok;
        int escrowVout = parts[1].trimmed().toInt(&ok);
        if (!ok || escrowVout < 0) {
            QMessageBox::warning(parent, tr("Invalid Vout"),
                tr("Output index must be a non-negative integer"));
            return;
        }

        // User confirmed, proceed with escrow refund
        try {
            QVariantMap options;
            options["fee_rate"] = feeRate;

            // Add vault override if provided
            if (!vaultTxid.isEmpty()) {
                QString roleLower = contractRole.toLower();
                if (roleLower == "short") {
                    options["short_vault_txid"] = vaultTxid;
                    options["short_vault_vout"] = vaultVout;
                } else if (roleLower == "long") {
                    options["long_vault_txid"] = vaultTxid;
                    options["long_vault_vout"] = vaultVout;
                }
                LogPrintf("ActionButtonsDelegate: Manual vault override for escrow refund - %s_vault: %s:%d\n",
                          roleLower.toStdString().c_str(), vaultTxid.toStdString().c_str(), vaultVout);
            }

            WalletModel::ForwardBuildEscrowRefundResult buildResult =
                walletModel->forwardBuildEscrowRefund(contractId, escrowTxid, escrowVout, options);

            if (!buildResult.success) {
                QMessageBox::critical(parent, tr("Escrow Refund Failed"),
                    tr("Failed to build escrow refund transaction:\n\n%1").arg(buildResult.error));
                return;
            }

            LogPrintf("ActionButtonsDelegate: Escrow refund PSBT built - refund_idx=%d, complete=%d\n",
                      buildResult.refund_output_index, buildResult.complete);

            QString txToBroadcast;

            if (buildResult.complete && !buildResult.hex.isEmpty()) {
                txToBroadcast = buildResult.hex;
                LogPrintf("ActionButtonsDelegate: Escrow refund complete from hot wallet\n");
            } else {
                if (buildResult.psbt.isEmpty()) {
                    QMessageBox::critical(parent, tr("Escrow Refund Failed"),
                        tr("No PSBT returned from build_escrow_refund"));
                    return;
                }

                WalletModel::WalletProcessPsbtResult processResult =
                    walletModel->walletProcessPsbt(buildResult.psbt, true, "", true, false);

                if (!processResult.success) {
                    QMessageBox::critical(parent, tr("Escrow Refund Failed"),
                        tr("Failed to sign escrow refund transaction:\n\n%1").arg(processResult.error));
                    return;
                }

                txToBroadcast = processResult.psbt;
            }

            WalletModel::BroadcastPsbtResult broadcastResult = walletModel->broadcastPsbt(txToBroadcast);

            if (!broadcastResult.success) {
                QMessageBox::critical(parent, tr("Escrow Refund Failed"),
                    tr("Failed to broadcast escrow refund transaction:\n\n%1").arg(broadcastResult.error));
                return;
            }

            QString successMsg = tr(
                "Escrow refund executed successfully!\n\n"
                "Transaction ID: %1\n\n"
                "Your escrowed asset has been returned.\n"
                "Counter-party failed to claim before the deadline."
            ).arg(broadcastResult.txid);

            QMessageBox::information(parent, tr("Escrow Refund Success"), successMsg);

            LogPrintf("ActionButtonsDelegate: Escrow refund broadcast successful - txid=%s\n",
                      broadcastResult.txid.toStdString().c_str());

        } catch (const UniValue& e) {
            QString errorMsg = tr("Transaction failed");
            if (e.isStr()) {
                errorMsg = QString::fromStdString(e.get_str());
            } else if (e.isObject() && e.exists("message")) {
                errorMsg = QString::fromStdString(e["message"].get_str());
            }
            QMessageBox::critical(parent, tr("Escrow Refund Failed"),
                tr("Failed to process escrow refund transaction:\n\n%1").arg(errorMsg));
        } catch (const std::exception& e) {
            QMessageBox::critical(parent, tr("Escrow Refund Failed"),
                tr("Failed to process escrow refund transaction:\n\n%1")
                .arg(QString::fromStdString(e.what())));
        } catch (...) {
            QMessageBox::critical(parent, tr("Escrow Refund Failed"),
                tr("Failed to process escrow refund transaction: Unknown error"));
        }
    }

    void handleForwardIMTimeout(const QString& contractId, const QString& contractRole) const
    {
        if (!walletModel) return;

        QWidget* parent = qobject_cast<QWidget*>(QApplication::activeWindow());

        // Query contract status
        WalletModel::ContractStatusResult status = walletModel->getContractStatus(contractId);
        if (!status.success) {
            QMessageBox::critical(parent, tr("IM Timeout Error"),
                tr("Failed to query contract status:\n\n%1").arg(status.error));
            return;
        }

        QString roleLower = contractRole.toLower();
        int deadline_short = status.deadlines.value("deadline_short", 0).toInt();
        int deadline_long = status.deadlines.value("deadline_long", 0).toInt();
        int reorg_conf = 2; // Default
        if (status.offer.contains("terms")) {
            QVariantMap terms = status.offer.value("terms").toMap();
            reorg_conf = terms.value("reorg_conf", 2).toInt();
        }
        int currentHeight = walletModel->getNumBlocks();

        // Determine which vault to sweep and validate timing
        QString vaultType;
        QString vaultDescription;
        QString defaultReason;
        int requiredHeight;

        if (roleLower == "long") {
            vaultType = "bob";  // Long sweeps bob's (short's) vault
            vaultDescription = tr("Short party's IM vault");
            defaultReason = tr("Short party failed to deliver before deadline");
            requiredHeight = deadline_short + reorg_conf;
        } else {
            vaultType = "alice";  // Short sweeps alice's (long's) vault
            vaultDescription = tr("Long party's IM vault");
            defaultReason = tr("Long party failed to claim after short delivered");
            requiredHeight = deadline_long + reorg_conf;
        }

        // Validate timing
        if (currentHeight < requiredHeight) {
            QMessageBox::warning(parent, tr("IM Timeout Unavailable"),
                tr("Too early to claim IM penalty.\n\n"
                   "Required Height: %1\n"
                   "Current Height: %2\n"
                   "Blocks Remaining: %3")
                   .arg(requiredHeight).arg(currentHeight).arg(requiredHeight - currentHeight));
            return;
        }

        // Create confirmation dialog
        QDialog dialog(parent);
        dialog.setWindowTitle(tr("Claim IM Penalty"));
        dialog.setModal(true);

        QVBoxLayout* layout = new QVBoxLayout(&dialog);

        // Contract info
        QStringList infoLines;
        infoLines << tr("<b>Initial Margin Timeout Penalty</b>");
        infoLines << tr("Contract ID: %1").arg(AbbreviateId(contractId));
        infoLines << tr("Your Role: %1").arg(contractRole.toUpper());
        infoLines << "";
        infoLines << tr("Target Vault: %1").arg(vaultDescription);
        infoLines << tr("Vault Type: %1").arg(vaultType);
        infoLines << "";
        infoLines << tr("Default Reason: %1").arg(defaultReason);
        infoLines << tr("Required Height: %1").arg(requiredHeight);
        infoLines << tr("Current Height: %1").arg(currentHeight);
        infoLines << "";
        infoLines << tr("<b>What will happen:</b>");
        infoLines << tr("• Counter-party's IM vault will be swept");
        infoLines << tr("• IM funds will be sent to your wallet as penalty");
        infoLines << tr("• This compensates you for the defaulted contract");

        QLabel* infoLabel = new QLabel(infoLines.join("\n"));
        infoLabel->setWordWrap(true);
        infoLabel->setTextFormat(Qt::RichText);
        infoLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        layout->addWidget(infoLabel);

        layout->addSpacing(10);

        // Fee rate input
        QHBoxLayout* feeLayout = new QHBoxLayout();
        feeLayout->addWidget(new QLabel(tr("Fee Rate (sat/vB):")));

        QSpinBox* feeSpinBox = new QSpinBox();
        feeSpinBox->setMinimum(1);
        feeSpinBox->setMaximum(1000);
        feeSpinBox->setValue(2);
        feeSpinBox->setSuffix(" sat/vB");
        feeLayout->addWidget(feeSpinBox);
        feeLayout->addStretch();

        layout->addLayout(feeLayout);
        layout->addSpacing(10);

        // Advanced options (optional vault override)
        QLabel* advancedLabel = new QLabel(tr("<b>Advanced Options (Optional)</b>"));
        advancedLabel->setTextFormat(Qt::RichText);
        layout->addWidget(advancedLabel);

        QLabel* vaultHelpLabel = new QLabel(tr("Vault location is auto-detected. Only specify if auto-detection fails:"));
        vaultHelpLabel->setWordWrap(true);
        vaultHelpLabel->setStyleSheet("color: gray; font-size: 10pt;");
        layout->addWidget(vaultHelpLabel);

        QLineEdit* vaultTxidEdit = new QLineEdit();
        vaultTxidEdit->setPlaceholderText(tr("Vault txid (optional - leave empty for auto-detect)"));
        layout->addWidget(vaultTxidEdit);

        QSpinBox* vaultVoutSpinBox = new QSpinBox();
        vaultVoutSpinBox->setMinimum(0);
        vaultVoutSpinBox->setMaximum(999);
        vaultVoutSpinBox->setValue(0);
        vaultVoutSpinBox->setPrefix(tr("Vault vout: "));
        vaultVoutSpinBox->setEnabled(false); // Disabled until txid is provided
        layout->addWidget(vaultVoutSpinBox);

        // Enable vout spinbox only when txid is provided
        // Use context parameter (vaultVoutSpinBox) to auto-disconnect when widget is destroyed
        connect(vaultTxidEdit, &QLineEdit::textChanged, vaultVoutSpinBox,
                [vaultVoutSpinBox](const QString& text) {
            vaultVoutSpinBox->setEnabled(!text.trimmed().isEmpty());
        });

        layout->addSpacing(10);

        // Buttons
        QDialogButtonBox* buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
        buttonBox->button(QDialogButtonBox::Ok)->setText(tr("Claim IM Penalty"));
        connect(buttonBox, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
        connect(buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
        layout->addWidget(buttonBox);

        if (dialog.exec() != QDialog::Accepted) {
            return;
        }

        // Get user-specified fee rate
        double feeRate = feeSpinBox->value();

        // Get optional vault override
        QString vaultTxid = vaultTxidEdit->text().trimmed();
        int vaultVout = vaultVoutSpinBox->value();

        // User confirmed, proceed with IM timeout
        try {
            QVariantMap options;
            options["fee_rate"] = feeRate;

            // Add vault override if provided (otherwise RPC auto-detects)
            if (!vaultTxid.isEmpty()) {
                // RPC expects "vault_txid" and "vault_vout" parameters
                options["vault_txid"] = vaultTxid;
                options["vault_vout"] = vaultVout;
                LogPrintf("ActionButtonsDelegate: Manual vault override specified - %s vault: %s:%d\n",
                          vaultType.toStdString().c_str(), vaultTxid.toStdString().c_str(), vaultVout);
            } else {
                LogPrintf("ActionButtonsDelegate: Using auto-detected %s vault location\n",
                          vaultType.toStdString().c_str());
            }

            WalletModel::ForwardBuildIMTimeoutResult buildResult =
                walletModel->forwardBuildIMTimeout(contractId, vaultType, options);

            if (!buildResult.success) {
                QMessageBox::critical(parent, tr("IM Timeout Failed"),
                    tr("Failed to build IM timeout transaction:\n\n%1").arg(buildResult.error));
                return;
            }

            LogPrintf("ActionButtonsDelegate: IM timeout PSBT built - vault=%s, penalty_idx=%d, complete=%d\n",
                      vaultType.toStdString().c_str(), buildResult.penalty_output_index, buildResult.complete);

            QString txToBroadcast;

            if (buildResult.complete && !buildResult.hex.isEmpty()) {
                txToBroadcast = buildResult.hex;
                LogPrintf("ActionButtonsDelegate: IM timeout complete from hot wallet\n");
            } else {
                if (buildResult.psbt.isEmpty()) {
                    QMessageBox::critical(parent, tr("IM Timeout Failed"),
                        tr("No PSBT returned from build_im_timeout"));
                    return;
                }

                WalletModel::WalletProcessPsbtResult processResult =
                    walletModel->walletProcessPsbt(buildResult.psbt, true, "", true, false);

                if (!processResult.success) {
                    QMessageBox::critical(parent, tr("IM Timeout Failed"),
                        tr("Failed to sign IM timeout transaction:\n\n%1").arg(processResult.error));
                    return;
                }

                txToBroadcast = processResult.psbt;
            }

            WalletModel::BroadcastPsbtResult broadcastResult = walletModel->broadcastPsbt(txToBroadcast);

            if (!broadcastResult.success) {
                QMessageBox::critical(parent, tr("IM Timeout Failed"),
                    tr("Failed to broadcast IM timeout transaction:\n\n%1").arg(broadcastResult.error));
                return;
            }

            QString successMsg = tr(
                "IM penalty claimed successfully!\n\n"
                "Transaction ID: %1\n\n"
                "Counter-party's initial margin has been swept to your wallet as penalty.\n"
                "This compensates you for the defaulted forward contract."
            ).arg(broadcastResult.txid);

            QMessageBox::information(parent, tr("IM Penalty Claimed"), successMsg);

            LogPrintf("ActionButtonsDelegate: IM timeout broadcast successful - txid=%s\n",
                      broadcastResult.txid.toStdString().c_str());

        } catch (const UniValue& e) {
            QString errorMsg = tr("Transaction failed");
            if (e.isStr()) {
                errorMsg = QString::fromStdString(e.get_str());
            } else if (e.isObject() && e.exists("message")) {
                errorMsg = QString::fromStdString(e["message"].get_str());
            }
            QMessageBox::critical(parent, tr("IM Timeout Failed"),
                tr("Failed to process IM timeout transaction:\n\n%1").arg(errorMsg));
        } catch (const std::exception& e) {
            QMessageBox::critical(parent, tr("IM Timeout Failed"),
                tr("Failed to process IM timeout transaction:\n\n%1")
                .arg(QString::fromStdString(e.what())));
        } catch (...) {
            QMessageBox::critical(parent, tr("IM Timeout Failed"),
                tr("Failed to process IM timeout transaction: Unknown error"));
        }
    }

    // kept above as walletModel{nullptr}
};

ActiveContractsTab::ActiveContractsTab(const PlatformStyle* _platformStyle, QWidget* parent)
    : QWidget(parent),
      platformStyle(_platformStyle),
      walletModel(nullptr),
      registryModel(nullptr)
{
    setupUI();

    // Set up countdown timer (update every 30 seconds)
    countdownTimer = new QTimer(this);
    connect(countdownTimer, &QTimer::timeout, this, &ActiveContractsTab::updateMaturityCountdowns);
    countdownTimer->start(30000); // 30 seconds
}

ActiveContractsTab::~ActiveContractsTab()
{
    // Stop the maturity countdown timer explicitly. Same rationale as
    // TradeBoardTab::~TradeBoardTab — Qt's parent-child cleanup will
    // destroy the timer but does not stop it first, leaving a window
    // where a tick fires into a half-destroyed slot. Closing that window
    // is the cheapest available step against shutdown-time SIGABRT.
    if (countdownTimer) countdownTimer->stop();
}

void ActiveContractsTab::setWalletModel(WalletModel* model)
{
    walletModel = model;

    if (walletModel) {
        // Create registry model
        registryModel = new ContractRegistryModel(walletModel, this);
        contractsTable->setModel(registryModel);

        // Configure table columns (keep MTM columns compact, allow ID to stretch)
        QHeaderView* header = contractsTable->horizontalHeader();
        header->setSectionResizeMode(ContractRegistryModel::ContractId, QHeaderView::Stretch);
        header->setSectionResizeMode(ContractRegistryModel::MTMMarks, QHeaderView::ResizeToContents);
        header->setSectionResizeMode(ContractRegistryModel::MTMMarket, QHeaderView::ResizeToContents);
        header->setSectionResizeMode(ContractRegistryModel::Type, QHeaderView::ResizeToContents);
        header->setSectionResizeMode(ContractRegistryModel::Role, QHeaderView::ResizeToContents);
        header->setSectionResizeMode(ContractRegistryModel::PrimaryValue, QHeaderView::ResizeToContents);
        header->setSectionResizeMode(ContractRegistryModel::SecondaryValue, QHeaderView::ResizeToContents);
        header->setSectionResizeMode(ContractRegistryModel::KeyMetric, QHeaderView::ResizeToContents);
        header->setSectionResizeMode(ContractRegistryModel::Status, QHeaderView::ResizeToContents);
        header->setSectionResizeMode(ContractRegistryModel::Timeline, QHeaderView::ResizeToContents);
        header->setSectionResizeMode(ContractRegistryModel::Actions, QHeaderView::ResizeToContents);

        // Set up custom delegate for Actions column to render buttons
        contractsTable->setItemDelegateForColumn(ContractRegistryModel::Actions,
                                                 new ActionButtonsDelegate(walletModel, this));

        // Connect to balance changed signal (fires on new blocks)
        connect(walletModel, &WalletModel::balanceChanged, this, &ActiveContractsTab::onNewBlock);

        // Load initial contracts
        loadContracts();
    }
}

void ActiveContractsTab::setupUI()
{
    QVBoxLayout* mainLayout = new QVBoxLayout(this);

    // Filter bar
    QHBoxLayout* filterLayout = new QHBoxLayout();

    QLabel* typeLabel = new QLabel(tr("Type:"), this);
    filterLayout->addWidget(typeLabel);

    typeFilterCombo = new QComboBox(this);
    typeFilterCombo->addItem(tr("All"), "all");
    typeFilterCombo->addItem(tr("Repo"), "repo");
    typeFilterCombo->addItem(tr("Forward"), "forward");
    typeFilterCombo->addItem(tr("Option"), "option");
    typeFilterCombo->addItem(tr("Spot"), "spot");
    connect(typeFilterCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &ActiveContractsTab::onFilterChanged);
    filterLayout->addWidget(typeFilterCombo);

    filterLayout->addSpacing(20);

    QLabel* statusLabel = new QLabel(tr("Status:"), this);
    filterLayout->addWidget(statusLabel);

    statusFilterCombo = new QComboBox(this);
    statusFilterCombo->addItem(tr("All"), "all");
    statusFilterCombo->addItem(tr("Opened"), "opened");
    statusFilterCombo->addItem(tr("Accepted"), "accepted");
    statusFilterCombo->addItem(tr("Proposed"), "proposed");
    statusFilterCombo->addItem(tr("Repaid"), "repaid");
    statusFilterCombo->addItem(tr("Defaulted"), "defaulted");
    connect(statusFilterCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &ActiveContractsTab::onFilterChanged);
    filterLayout->addWidget(statusFilterCombo);

    filterLayout->addStretch();

    refreshButton = new QPushButton(tr("Refresh"), this);
    connect(refreshButton, &QPushButton::clicked, this, &ActiveContractsTab::onRefreshClicked);
    filterLayout->addWidget(refreshButton);

    mainLayout->addLayout(filterLayout);

    mainLayout->addSpacing(10);

    // Contracts table
    contractsTable = new QTableView(this);
    contractsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    contractsTable->setSelectionMode(QAbstractItemView::SingleSelection);
    contractsTable->setAlternatingRowColors(true);
    contractsTable->setSortingEnabled(false);
    contractsTable->verticalHeader()->setVisible(false);
    contractsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    connect(contractsTable, &QTableView::doubleClicked, this, &ActiveContractsTab::onContractDoubleClicked);
    mainLayout->addWidget(contractsTable);

    // Action buttons
    QHBoxLayout* actionLayout = new QHBoxLayout();
    actionLayout->addStretch();

    viewDetailsButton = new QPushButton(tr("View Details"), this);
    connect(viewDetailsButton, &QPushButton::clicked, [this]() {
        QModelIndex current = contractsTable->currentIndex();
        if (current.isValid()) {
            onContractDoubleClicked(current);
        }
    });
    actionLayout->addWidget(viewDetailsButton);

    mainLayout->addLayout(actionLayout);
}

void ActiveContractsTab::loadContracts()
{
    if (registryModel) {
        registryModel->refresh();
    }
}

void ActiveContractsTab::onFilterChanged()
{
    if (!registryModel) {
        return;
    }

    QString typeFilter = typeFilterCombo->currentData().toString();
    QString statusFilter = statusFilterCombo->currentData().toString();

    registryModel->setTypeFilter(typeFilter);
    registryModel->setStatusFilter(statusFilter);
}

void ActiveContractsTab::onRefreshClicked()
{
    loadContracts();
}

void ActiveContractsTab::onContractDoubleClicked(const QModelIndex& index)
{
    if (!registryModel || !index.isValid()) {
        return;
    }

    // Capture stable contract ID immediately to avoid race with model refresh
    QString contractId = index.sibling(index.row(), ContractRegistryModel::ContractId)
                             .data(ContractRegistryModel::ContractIdRole).toString();
    QVariantMap contractData;
    if (!contractId.isEmpty()) {
        contractData = registryModel->getContractDataById(contractId);
    } else {
        // Fallback to row lookup
        contractData = registryModel->getContractData(index.row());
    }
    if (contractData.isEmpty()) {
        return;
    }

    // Open contract detail dialog (with wallet model for enhanced previews)
    ContractDetailDialog dialog(contractData, walletModel, this);
    dialog.exec();
}

void ActiveContractsTab::onNewBlock()
{
    // Refresh contracts on new block
    loadContracts();
}

void ActiveContractsTab::updateMaturityCountdowns()
{
    // Refresh the model to update countdowns
    if (registryModel) {
        registryModel->refresh();
    }
}
