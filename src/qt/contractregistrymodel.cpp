// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/contractregistrymodel.h>
#include <qt/walletmodel.h>

#include <logging.h>

#include <QColor>
#include <QElapsedTimer>
#include <QFutureWatcher>
#include <QPointer>
#include <QtConcurrent/QtConcurrent>

ContractRegistryModel::ContractRegistryModel(WalletModel* wallet, QObject* parent)
    : QAbstractTableModel(parent),
      walletModel(wallet),
      typeFilter("all"),
      statusFilter("all")
{
    // Initial load is async — do NOT call buildSnapshot() synchronously here.
    // Constructing the model is on the GUI thread (it happens during wallet
    // setup), and a blocking listContracts + MTM sweep here would stall
    // startup on a slow RPC backend. refresh() schedules the worker.
    refresh();
}

int ContractRegistryModel::rowCount(const QModelIndex& parent) const
{
    if (parent.isValid()) {
        return 0;
    }
    return filteredContracts.size();
}

int ContractRegistryModel::columnCount(const QModelIndex& parent) const
{
    if (parent.isValid()) {
        return 0;
    }
    return ColumnCount;
}

QVariant ContractRegistryModel::data(const QModelIndex& index, int role) const
{
    if (!index.isValid() || index.row() >= filteredContracts.size()) {
        return QVariant();
    }

    const ContractEntry& contract = filteredContracts.at(index.row());

    if (role == Qt::DisplayRole) {
        switch (index.column()) {
        case ContractId:
            return QString(contract.id.left(16) + "...");
        case MTMMarks:
            // MTM is computed during buildSnapshot() and refreshed on every async refresh
            return formatMTM(contract.mtmMarks, contract.mtmComputed);
        case MTMMarket:
            // MTM is computed during buildSnapshot() and refreshed on every async refresh
            return formatMTM(contract.mtmMarket, contract.mtmComputed);
        case Type:
            // Show the product for difficulty so CFD vs Option is visible directly in the column.
            if (contract.type == "difficulty") {
                return contract.diffProduct == "option" ? tr("Difficulty Option") : tr("Difficulty CFD");
            }
            if (contract.type == "scalarcfd") {
                return tr("Scalar CFD");
            }
            return contract.type;
        case Role:
            return contract.role;
        case PrimaryValue:
            // Display type-specific primary value
            if (contract.type == "repo") {
                return QString("%1 %2").arg(contract.collateralAmount, 0, 'f', 8).arg(contract.collateralAsset);
            } else if (contract.type == "forward" || contract.type == "option") {
                // Show delivery legs: "Long delivers X → Short delivers Y"
                return QString("%1 %2 ⇄ %3 %4")
                    .arg(contract.longDeliverAmount, 0, 'f', 8)
                    .arg(contract.longDeliverAsset)
                    .arg(contract.shortDeliverAmount, 0, 'f', 8)
                    .arg(contract.shortDeliverAsset);
            } else if (contract.type == "spot") {
                // Show trade: "Alice: X ⇄ Bob: Y"
                // Use proper precision based on amount magnitude
                int alicePrecision = contract.aliceDeliverAmount < 1.0 ? 4 : 2;
                int bobPrecision = contract.bobDeliverAmount < 1.0 ? 4 : 2;
                return QString("%1 %2 ⇄ %3 %4")
                    .arg(contract.aliceDeliverAmount, 0, 'f', alicePrecision)
                    .arg(contract.aliceDeliverAsset)
                    .arg(contract.bobDeliverAmount, 0, 'f', bobPrecision)
                    .arg(contract.bobDeliverAsset);
            } else if (contract.type == "difficulty") {
                if (contract.diffProduct == "option") {
                    return tr("Writer IM: %1 TSC (%2)")
                        .arg(contract.diffLongIm > 0.0 ? contract.diffLongIm : contract.diffShortIm, 0, 'f', 8)
                        .arg(contract.writerSide);
                }
                return tr("L IM: %1 ⇄ S IM: %2 TSC")
                    .arg(contract.diffLongIm, 0, 'f', 8)
                    .arg(contract.diffShortIm, 0, 'f', 8);
            } else if (contract.type == "scalarcfd") {
                // IMs are in the collateral's units (sats if native); show raw units.
                return tr("L IM: %1 ⇄ S IM: %2")
                    .arg(contract.scfdLongIm, 0, 'f', 0)
                    .arg(contract.scfdShortIm, 0, 'f', 0);
            }
            return tr("N/A");
        case SecondaryValue:
            // Display type-specific secondary value
            if (contract.type == "repo") {
                return QString("%1 %2").arg(contract.principalAmount, 0, 'f', 8).arg(contract.principalAsset);
            } else if (contract.type == "forward" || contract.type == "option") {
                // Show margins: "L: X% | S: Y%"
                return QString("L: %1 %2 | S: %3 %4")
                    .arg(contract.longMarginAmount, 0, 'f', 8)
                    .arg(contract.longMarginAsset)
                    .arg(contract.shortMarginAmount, 0, 'f', 8)
                    .arg(contract.shortMarginAsset);
            } else if (contract.type == "spot") {
                // Show exchange rate
                return tr("Rate: %1").arg(contract.exchangeRate, 0, 'f', 8);
            } else if (contract.type == "difficulty") {
                if (contract.diffProduct == "option") {
                    return tr("λ %1 | Premium: %2 TSC")
                        .arg(contract.diffLongLambda > 0.0 ? contract.diffLongLambda : contract.diffShortLambda, 0, 'f', 2)
                        .arg(contract.diffPremium, 0, 'f', 8);
                }
                return tr("L λ %1 | S λ %2")
                    .arg(contract.diffLongLambda, 0, 'f', 2)
                    .arg(contract.diffShortLambda, 0, 'f', 2);
            } else if (contract.type == "scalarcfd") {
                return tr("L λ %1 | S λ %2")
                    .arg(contract.scfdLongLambda, 0, 'f', 2)
                    .arg(contract.scfdShortLambda, 0, 'f', 2);
            }
            return tr("N/A");
        case KeyMetric:
            // Display type-specific key metric
            if (contract.type == "repo") {
                return tr("LTV %1%").arg(contract.ltv, 0, 'f', 2);
            } else if (contract.type == "forward") {
                // Show IM percentages: "L: X% | S: Y%"
                return tr("L: %1% | S: %2%")
                    .arg(contract.longImPercent, 0, 'f', 2)
                    .arg(contract.shortImPercent, 0, 'f', 2);
            } else if (contract.type == "option") {
                // Show premium for options
                if (contract.premiumAmount > 0) {
                    return tr("Premium: %1 %2")
                        .arg(contract.premiumAmount, 0, 'f', 8)
                        .arg(contract.premiumAsset);
                } else {
                    return tr("No premium");
                }
            } else if (contract.type == "spot") {
                return tr("-");
            } else if (contract.type == "difficulty") {
                return tr("Strike %1 @ H%2").arg(contract.strikeNbits).arg(contract.fixingHeight);
            } else if (contract.type == "scalarcfd") {
                return tr("Feed %1 | Strike %2…")
                    .arg(contract.scfdFeedId)
                    .arg(contract.scfdStrike.left(10));
            }
            return tr("N/A");
        case Status:
            return contract.status;
        case Timeline:
            // Display type-specific timeline
            if (contract.type == "repo") {
                return contract.maturityTime;
            } else if (contract.type == "forward" || contract.type == "option") {
                // Show deadline_long countdown (maturityTime uses deadline_long)
                return tr("Long: %1").arg(contract.maturityTime);
            } else if (contract.type == "spot") {
                return tr("-");
            } else if (contract.type == "difficulty") {
                return tr("Settle @ H%1").arg(contract.settleLockHeight);
            } else if (contract.type == "scalarcfd") {
                return tr("Fix by H%1 | Settle @ H%2")
                    .arg(contract.scfdFixingDeadline)
                    .arg(contract.scfdSettleLockHeight);
            }
            return tr("N/A");
        case Actions:
            return QString(""); // Actions column will be handled by custom delegate/buttons
        default:
            return QVariant();
        }
    } else if (role == Qt::TextAlignmentRole) {
        if (index.column() == MTMMarks || index.column() == MTMMarket ||
            index.column() == PrimaryValue || index.column() == SecondaryValue ||
            index.column() == KeyMetric) {
            return QVariant::fromValue(Qt::AlignRight | Qt::AlignVCenter);
        }
        return QVariant::fromValue(Qt::AlignLeft | Qt::AlignVCenter);
    } else if (role == Qt::ToolTipRole) {
        // Add tooltips to explain what each column means for different contract types
        switch (index.column()) {
        case ContractId:
            // Difficulty rows carry a full detail summary (terms, settled state, vault outpoints).
            if (contract.type == "difficulty") {
                QString d = tr("<b>Difficulty %1</b><br>")
                                .arg(contract.diffProduct == "option" ? tr("Option") : tr("CFD"));
                d += tr("ID: %1<br>").arg(contract.id);
                d += tr("Role: %1 &nbsp;|&nbsp; Status: %2<br>").arg(contract.role, contract.status);
                d += tr("Strike nBits: %1<br>").arg(contract.strikeNbits);
                d += tr("Fixing height: %1<br>").arg(contract.fixingHeight);
                d += tr("Settle-lock height: %1<br>").arg(contract.settleLockHeight);
                const bool longSettled = contract.fullData.value("long_settled").toBool();
                const bool shortSettled = contract.fullData.value("short_settled").toBool();
                const bool opened = !contract.openTxid.isEmpty();
                if (contract.diffProduct == "option") {
                    const double im = contract.diffLongIm > 0.0 ? contract.diffLongIm : contract.diffShortIm;
                    const double lam = contract.diffLongLambda > 0.0 ? contract.diffLongLambda : contract.diffShortLambda;
                    const bool writerSettled = (contract.writerSide == "short") ? shortSettled : longSettled;
                    d += tr("Writer side: %1<br>").arg(contract.writerSide);
                    d += tr("Writer IM: %1 TSC, λ %2<br>").arg(im, 0, 'f', 8).arg(lam, 0, 'f', 2);
                    d += tr("Premium: %1 TSC<br>").arg(contract.diffPremium, 0, 'f', 8);
                    if (opened) d += tr("Writer vault settled: %1<br>").arg(writerSettled ? tr("yes") : tr("no"));
                } else {
                    d += tr("Long IM: %1 TSC, λ %2<br>").arg(contract.diffLongIm, 0, 'f', 8).arg(contract.diffLongLambda, 0, 'f', 2);
                    d += tr("Short IM: %1 TSC, λ %2<br>").arg(contract.diffShortIm, 0, 'f', 8).arg(contract.diffShortLambda, 0, 'f', 2);
                    if (opened) {
                        d += tr("Long settled: %1 &nbsp;|&nbsp; Short settled: %2<br>")
                                 .arg(longSettled ? tr("yes") : tr("no"), shortSettled ? tr("yes") : tr("no"));
                    }
                }
                if (!contract.longVault.isEmpty()) d += tr("Long vault: %1<br>").arg(contract.longVault);
                if (!contract.shortVault.isEmpty()) d += tr("Short vault: %1<br>").arg(contract.shortVault);
                if (!contract.openTxid.isEmpty()) d += tr("Open txid: %1").arg(contract.openTxid);
                return d;
            }
            // Scalar-feed CFD rows carry an analogous detail summary.
            if (contract.type == "scalarcfd") {
                QString d = tr("<b>Scalar-feed CFD</b><br>");
                d += tr("ID: %1<br>").arg(contract.id);
                d += tr("Role: %1 &nbsp;|&nbsp; Status: %2<br>").arg(contract.role, contract.status);
                d += tr("Feed: %1 &nbsp;|&nbsp; Fixing ref: %2<br>").arg(contract.scfdFeedId).arg(contract.scfdFixingRef);
                d += tr("Strike: %1<br>").arg(contract.scfdStrike);
                d += tr("Fixing deadline: H%1<br>").arg(contract.scfdFixingDeadline);
                d += tr("Settle-lock height: H%1<br>").arg(contract.scfdSettleLockHeight);
                d += tr("Long IM: %1, λ %2<br>").arg(contract.scfdLongIm, 0, 'f', 0).arg(contract.scfdLongLambda, 0, 'f', 2);
                d += tr("Short IM: %1, λ %2<br>").arg(contract.scfdShortIm, 0, 'f', 0).arg(contract.scfdShortLambda, 0, 'f', 2);
                const bool opened = !contract.openTxid.isEmpty();
                if (opened) {
                    d += tr("Long settled: %1 &nbsp;|&nbsp; Short settled: %2<br>")
                             .arg(contract.scfdLongSettled ? tr("yes") : tr("no"),
                                  contract.scfdShortSettled ? tr("yes") : tr("no"));
                }
                if (!contract.longVault.isEmpty()) d += tr("Long vault: %1<br>").arg(contract.longVault);
                if (!contract.shortVault.isEmpty()) d += tr("Short vault: %1<br>").arg(contract.shortVault);
                if (!contract.openTxid.isEmpty()) d += tr("Open txid: %1").arg(contract.openTxid);
                return d;
            }
            break;
        case PrimaryValue:
            if (contract.type == "repo") {
                return tr("Collateral: Assets locked by borrower");
            } else if (contract.type == "forward" || contract.type == "option") {
                return tr("Delivery legs: Long delivers first asset, Short delivers second asset");
            } else if (contract.type == "spot") {
                return tr("Atomic swap: Alice delivers first asset, Bob delivers second asset");
            } else if (contract.type == "difficulty") {
                return tr("Initial margin posted per leg (CFD) or by the writer (Option), in native TSC");
            } else if (contract.type == "scalarcfd") {
                return tr("Initial margin posted per leg, in the collateral's units (sats if native)");
            }
            break;
        case SecondaryValue:
            if (contract.type == "repo") {
                return tr("Principal: Loan amount");
            } else if (contract.type == "forward" || contract.type == "option") {
                return tr("Initial Margins: L = Long party margin, S = Short party margin");
            } else if (contract.type == "spot") {
                return tr("Exchange rate: Bob's delivery / Alice's delivery");
            } else if (contract.type == "difficulty") {
                return tr("Leverage (lambda) per leg; for an option, also the premium");
            } else if (contract.type == "scalarcfd") {
                return tr("Leverage (lambda) per leg");
            }
            break;
        case KeyMetric:
            if (contract.type == "repo") {
                return tr("Loan-to-Value ratio (Principal/Collateral)");
            } else if (contract.type == "forward") {
                return tr("Initial Margin percentages: L = Long IM%, S = Short IM%");
            } else if (contract.type == "option") {
                return tr("Option premium paid by one party to the other");
            } else if (contract.type == "difficulty") {
                return tr("Strike difficulty (compact nBits) and the fixing block height");
            } else if (contract.type == "scalarcfd") {
                return tr("Scalar feed id and the strike level (K) the payoff references");
            }
            break;
        case Timeline:
            if (contract.type == "repo") {
                return tr("Contract maturity date/blocks");
            } else if (contract.type == "forward" || contract.type == "option") {
                return tr("Exercise/Settlement deadlines");
            } else if (contract.type == "difficulty") {
                return tr("Settle-lock height (fixing height + maturity depth)");
            } else if (contract.type == "scalarcfd") {
                return tr("Publication deadline for the fixing, and the settle-lock height");
            }
            break;
        }
    } else if (role == ContractIdRole) {
        return contract.id;
    } else if (role == ContractTypeRole) {
        return contract.type;
    } else if (role == ContractRoleRole) {
        return contract.role;
    } else if (role == ContractStatusRole) {
        return contract.status;
    } else if (role == ContractDataRole) {
        return contract.fullData;
    } else if (role == Qt::ForegroundRole) {
        // Color-code MTM columns
        if (index.column() == MTMMarks || index.column() == MTMMarket) {
            if (!contract.mtmComputed) {
                return QColor(158, 158, 158); // Gray - not computed
            }
            double mtm = (index.column() == MTMMarks) ? contract.mtmMarks : contract.mtmMarket;
            if (mtm > 0.0) {
                return QColor(76, 175, 80); // Green - positive MTM
            } else if (mtm < 0.0) {
                return QColor(244, 67, 54); // Red - negative MTM
            } else {
                return QColor(158, 158, 158); // Gray - zero MTM
            }
        }
        // Color-code by status for other columns
        if (contract.status == "opened") {
            return QColor(76, 175, 80); // Green - on blockchain / fully live
        } else if (contract.status == "proposed" || contract.status == "accepted") {
            return QColor(255, 152, 0); // Orange - pending
        } else if (contract.status == "partially_settled") {
            return QColor(255, 193, 7); // Amber - one difficulty leg still live
        } else if (contract.status == "repaid" || contract.status == "defaulted" ||
                   contract.status == "closed" || contract.status == "settled") {
            return QColor(158, 158, 158); // Gray - completed/settled
        }
    }

    return QVariant();
}

QVariant ContractRegistryModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation == Qt::Horizontal && role == Qt::DisplayRole) {
        switch (section) {
        case ContractId:
            return tr("Contract ID");
        case MTMMarks:
            return tr("MTM (Marks)");
        case MTMMarket:
            return tr("MTM (Market)");
        case Type:
            return tr("Type");
        case Role:
            return tr("Role");
        case PrimaryValue:
            return tr("Primary Value");
        case SecondaryValue:
            return tr("Secondary Value");
        case KeyMetric:
            return tr("Key Metric");
        case Status:
            return tr("Status");
        case Timeline:
            return tr("Timeline");
        case Actions:
            return tr("Actions");
        default:
            return QVariant();
        }
    } else if (orientation == Qt::Horizontal && role == Qt::ToolTipRole) {
        // Add tooltips to column headers explaining what they show
        switch (section) {
        case MTMMarks:
            return tr("Mark-to-market using internal pricing curves");
        case MTMMarket:
            return tr("Mark-to-market using market-calibrated curves");
        case PrimaryValue:
            return tr("Repo: Collateral | Forward/Option: Delivery legs | Spot: Trade amount");
        case SecondaryValue:
            return tr("Repo: Principal | Forward/Option: Margins | Spot: Price");
        case KeyMetric:
            return tr("Repo: LTV% | Forward: IM% | Option: Premium | Spot: -");
        case Timeline:
            return tr("Repo: Maturity | Forward/Option: Deadlines | Spot: -");
        default:
            return QVariant();
        }
    }
    return QVariant();
}

void ContractRegistryModel::refresh()
{
    if (!walletModel) {
        return;
    }

    // Coalesce: if a worker is already building a snapshot, just mark that
    // another refresh is wanted. The in-flight worker's completion handler
    // will relaunch. Prevents piling up N concurrent listContracts sweeps
    // when the overview page and the contracts tab both tick.
    if (m_refreshInFlight) {
        m_refreshPending = true;
        return;
    }
    m_refreshInFlight = true;

    const uint64_t generation = m_refreshGeneration.fetch_add(1, std::memory_order_acq_rel) + 1;
    QPointer<ContractRegistryModel> self(this);
    QPointer<WalletModel> wm(walletModel);

    LogPrintf("ContractRegistryModel::refresh start (async) wallet=%s gen=%llu rows_before=%d type_filter=%s status_filter=%s\n",
              walletModel->getWalletName().toStdString().c_str(),
              static_cast<unsigned long long>(generation),
              filteredContracts.size(),
              typeFilter.toStdString().c_str(),
              statusFilter.toStdString().c_str());

    auto* watcher = new QFutureWatcher<QList<ContractEntry>>(this);
    connect(watcher, &QFutureWatcher<QList<ContractEntry>>::finished, this,
            [self, wm, watcher, generation]() {
        QList<ContractEntry> snapshot = watcher->result();
        watcher->deleteLater();

        if (!self) {
            return;  // model destroyed while the worker ran
        }

        self->m_refreshInFlight = false;

        // Stale-result guard: a newer refresh() was requested after this
        // worker started. Drop this snapshot; the newer one is or will be
        // in flight.
        if (generation != self->m_refreshGeneration.load(std::memory_order_acquire)) {
            LogPrintf("ContractRegistryModel::refresh dropping stale snapshot gen=%llu current=%llu\n",
                      static_cast<unsigned long long>(generation),
                      static_cast<unsigned long long>(self->m_refreshGeneration.load(std::memory_order_acquire)));
        } else {
            self->applySnapshot(std::move(snapshot));
        }

        // Relaunch if a refresh was requested while this one ran.
        if (self->m_refreshPending) {
            self->m_refreshPending = false;
            self->refresh();
        }
    });

    // Worker captures only the QPointer<WalletModel> by value. It calls the
    // static buildSnapshot(), which touches no `this` state, so the model
    // being destroyed mid-build cannot corrupt anything — the worker just
    // operates on walletModel (guarded) and returns a plain list.
    watcher->setFuture(QtConcurrent::run([wm]() -> QList<ContractEntry> {
        if (!wm) return {};
        return ContractRegistryModel::buildSnapshot(wm.data());
    }));
}

void ContractRegistryModel::applyFilters()
{
    filteredContracts.clear();
    for (const ContractEntry& entry : contracts) {
        const bool typeMatch = (typeFilter == "all" || entry.type == typeFilter);
        const bool statusMatch = (statusFilter == "all" || entry.status == statusFilter);
        if (typeMatch && statusMatch) {
            filteredContracts.append(entry);
        }
    }
}

void ContractRegistryModel::applySnapshot(QList<ContractEntry> snapshot)
{
    beginResetModel();
    contracts = std::move(snapshot);
    applyFilters();
    endResetModel();
    LogPrintf("ContractRegistryModel::applySnapshot wallet=%s contracts=%d filtered=%d\n",
              walletModel ? walletModel->getWalletName().toStdString().c_str() : "",
              contracts.size(),
              filteredContracts.size());
}

void ContractRegistryModel::setTypeFilter(const QString& type)
{
    // Filter changes are a pure re-slice of the already-loaded snapshot — no
    // RPC reload needed. New contracts arrive via the periodic async refresh.
    typeFilter = type;
    beginResetModel();
    applyFilters();
    endResetModel();
}

void ContractRegistryModel::setStatusFilter(const QString& status)
{
    statusFilter = status;
    beginResetModel();
    applyFilters();
    endResetModel();
}

QVariantMap ContractRegistryModel::getContractData(int row) const
{
    if (row < 0 || row >= filteredContracts.size()) {
        return QVariantMap();
    }
    return filteredContracts.at(row).fullData;
}

QVariantMap ContractRegistryModel::getContractDataById(const QString& id) const
{
    for (const auto& entry : contracts) {
        if (entry.id == id) return entry.fullData;
    }
    return QVariantMap();
}

QList<ContractRegistryModel::ContractEntry> ContractRegistryModel::buildSnapshot(WalletModel* walletModel)
{
    // RUNS ON A WORKER THREAD. Must not touch any ContractRegistryModel
    // instance state — only the passed-in walletModel (whose RPC wrappers
    // are thread-safe, same as the cosign* calls used from QtConcurrent in
    // tradeboardtab) and local variables. Returns the full unfiltered list;
    // the GUI thread applies filters in applyFilters().
    QList<ContractEntry> result;

    QElapsedTimer timer;
    timer.start();

    if (!walletModel) {
        return result;
    }

    LogPrintf("ContractRegistryModel::buildSnapshot start wallet=%s\n",
              walletModel->getWalletName().toStdString().c_str());

    // Call contract.list RPC to get all contracts
    QList<QVariantMap> contractList = walletModel->listContracts();
    LogPrintf("ContractRegistryModel::buildSnapshot contract.list returned wallet=%s count=%d elapsed_ms=%lld\n",
              walletModel->getWalletName().toStdString().c_str(),
              contractList.size(),
              timer.elapsed());

    for (const QVariantMap& contractData : contractList) {
        ContractEntry entry;
        entry.id = contractData.value("id").toString();
        entry.type = contractData.value("type").toString();
        entry.role = contractData.value("role").toString();
        entry.status = contractData.value("status").toString();
        entry.maturityHeight = contractData.value("maturity_height", 0).toInt();

        // Amounts and assets
        entry.collateralAmount = contractData.value("collateral_amount", 0.0).toDouble();
        entry.collateralAsset = resolveAssetLabel(walletModel, contractData.value("collateral_asset", "TSC").toString());
        entry.principalAmount = contractData.value("principal_amount", 0.0).toDouble();
        entry.principalAsset = resolveAssetLabel(walletModel, contractData.value("principal_asset", "TSC").toString());
        entry.interestAmount = contractData.value("interest_amount", 0.0).toDouble();
        entry.interestAsset = resolveAssetLabel(walletModel, contractData.value("interest_asset", "TSC").toString());
        entry.ltv = contractData.value("ltv", 0.0).toDouble();
        entry.createdHeight = contractData.value("created_height", 0).toInt();

        // Forward/Option contract fields
        entry.longDeliverAmount = contractData.value("long_deliver_amount", 0.0).toDouble();
        entry.longDeliverAsset = resolveAssetLabel(walletModel, contractData.value("long_deliver_asset").toString());
        entry.longMarginAmount = contractData.value("long_margin_amount", 0.0).toDouble();
        entry.longMarginAsset = resolveAssetLabel(walletModel, contractData.value("long_margin_asset").toString());
        entry.shortDeliverAmount = contractData.value("short_deliver_amount", 0.0).toDouble();
        entry.shortDeliverAsset = resolveAssetLabel(walletModel, contractData.value("short_deliver_asset").toString());
        entry.shortMarginAmount = contractData.value("short_margin_amount", 0.0).toDouble();
        entry.shortMarginAsset = resolveAssetLabel(walletModel, contractData.value("short_margin_asset").toString());
        entry.premiumAmount = contractData.value("premium_amount", 0.0).toDouble();
        entry.premiumAsset = resolveAssetLabel(walletModel, contractData.value("premium_asset").toString());
        entry.deadlineShort = contractData.value("deadline_short", 0).toInt();
        entry.deadlineLong = contractData.value("deadline_long", 0).toInt();
        entry.longImPercent = contractData.value("long_im_percent", 0.0).toDouble();
        entry.shortImPercent = contractData.value("short_im_percent", 0.0).toDouble();

        // Spot contract fields
        entry.aliceDeliverAmount = contractData.value("alice_deliver_amount", 0.0).toDouble();
        entry.aliceDeliverAsset = resolveAssetLabel(walletModel, contractData.value("alice_deliver_asset").toString());
        entry.bobDeliverAmount = contractData.value("bob_deliver_amount", 0.0).toDouble();
        entry.bobDeliverAsset = resolveAssetLabel(walletModel, contractData.value("bob_deliver_asset").toString());
        entry.exchangeRate = contractData.value("exchange_rate", 0.0).toDouble();

        // Difficulty-derivative fields (native TSC; no asset resolution needed)
        entry.diffProduct = contractData.value("kind").toString();
        entry.strikeNbits = contractData.value("strike_nbits").toString();
        entry.fixingHeight = contractData.value("fixing_height", 0).toInt();
        entry.settleLockHeight = contractData.value("settle_lock_height", 0).toInt();
        entry.diffLongIm = contractData.value("diff_long_im", 0.0).toDouble();
        entry.diffLongLambda = contractData.value("diff_long_lambda", 0.0).toDouble();
        entry.diffShortIm = contractData.value("diff_short_im", 0.0).toDouble();
        entry.diffShortLambda = contractData.value("diff_short_lambda", 0.0).toDouble();
        entry.diffPremium = contractData.value("diff_premium", 0.0).toDouble();
        entry.writerSide = contractData.value("writer_side").toString();
        entry.longVault = contractData.value("long_vault").toString();
        entry.shortVault = contractData.value("short_vault").toString();
        entry.openTxid = contractData.value("open_txid").toString();

        // Scalar-feed bilateral CFD fields (collateral units; legs flattened to scfd_* in listContracts()
        // to avoid colliding with the difficulty diff_* / forward long_margin_* keys). long_vault/
        // short_vault/open_txid/long_settled/short_settled share the keys parsed above.
        if (entry.type == "scalarcfd") {
            entry.scfdFeedId = contractData.value("scfd_feed_id", 0).toInt();
            entry.scfdFixingRef = contractData.value("scfd_fixing_ref", 0).toULongLong();
            entry.scfdStrike = contractData.value("scfd_strike").toString();
            entry.scfdFixingDeadline = contractData.value("scfd_publication_deadline_height", 0).toInt();
            entry.scfdSettleLockHeight = contractData.value("settle_lock_height", 0).toInt();
            entry.scfdLongIm = contractData.value("scfd_long_im", 0.0).toDouble();
            entry.scfdLongLambda = contractData.value("scfd_long_lambda", 0.0).toDouble();
            entry.scfdShortIm = contractData.value("scfd_short_im", 0.0).toDouble();
            entry.scfdShortLambda = contractData.value("scfd_short_lambda", 0.0).toDouble();
            entry.scfdLongSettled = contractData.value("long_settled", false).toBool();
            entry.scfdShortSettled = contractData.value("short_settled", false).toBool();
        }

        // Store resolved asset labels in fullData for dialogs
        QVariantMap enrichedData = contractData;
        enrichedData["collateral_asset_label"] = entry.collateralAsset;
        enrichedData["principal_asset_label"] = entry.principalAsset;
        enrichedData["interest_asset_label"] = entry.interestAsset;
        enrichedData["long_deliver_asset_label"] = entry.longDeliverAsset;
        enrichedData["long_margin_asset_label"] = entry.longMarginAsset;
        enrichedData["short_deliver_asset_label"] = entry.shortDeliverAsset;
        enrichedData["short_margin_asset_label"] = entry.shortMarginAsset;
        enrichedData["premium_asset_label"] = entry.premiumAsset;
        enrichedData["alice_deliver_asset_label"] = entry.aliceDeliverAsset;
        enrichedData["bob_deliver_asset_label"] = entry.bobDeliverAsset;
        entry.fullData = enrichedData;

        // Format maturity countdown
        entry.maturityTime = formatMaturityCountdown(walletModel, entry.maturityHeight);

        // Compute MTM for this contract (refreshed on every snapshot build)
        computeMTM(walletModel, entry);

        result.append(entry);
        // NB: filtering is intentionally NOT applied here — buildSnapshot
        // returns the full list and the GUI thread slices it in
        // applyFilters(), which lets filter changes re-slice without an RPC
        // reload.
    }

    LogPrintf("ContractRegistryModel::buildSnapshot done wallet=%s contracts=%d elapsed_ms=%lld\n",
              walletModel->getWalletName().toStdString().c_str(),
              result.size(),
              timer.elapsed());
    return result;
}

QString ContractRegistryModel::resolveAssetLabel(WalletModel* walletModel, const QString& assetIdOrLabel)
{
    // If it's already "TSC" or a short ticker, return it
    if (assetIdOrLabel == "TSC" || assetIdOrLabel.length() <= 11) {
        return assetIdOrLabel;
    }

    // If it's a 64-char hex asset ID, look up the ticker
    if (assetIdOrLabel.length() == 64 && walletModel) {
        WalletModel::AssetInfo info = walletModel->getAssetInfo(assetIdOrLabel);
        if (!info.ticker.isEmpty()) {
            return info.ticker;
        }
        // Fallback to first 8 chars if lookup fails
        return assetIdOrLabel.left(8) + "...";
    }

    return assetIdOrLabel;
}

QString ContractRegistryModel::formatMaturityCountdown(WalletModel* walletModel, int height)
{
    if (height == 0) {
        return tr("N/A");
    }

    if (!walletModel) {
        return tr("Block %1").arg(height);
    }

    // Get current block height
    int currentHeight = walletModel->getNumBlocks();
    int blocksRemaining = height - currentHeight;

    if (blocksRemaining <= 0) {
        return tr("Matured");
    }

    // Estimate time (10 min per block)
    int minutesRemaining = blocksRemaining * 10;
    int hours = minutesRemaining / 60;
    int days = hours / 24;

    if (days > 0) {
        return tr("%1 days (%2 blocks)").arg(days).arg(blocksRemaining);
    } else if (hours > 0) {
        return tr("%1 hours (%2 blocks)").arg(hours).arg(blocksRemaining);
    } else {
        return tr("%1 blocks").arg(blocksRemaining);
    }
}

void ContractRegistryModel::computeMTM(WalletModel* walletModel, ContractEntry& entry)
{
    if (!walletModel) {
        entry.mtmComputed = false;
        return;
    }

    QElapsedTimer timer;
    timer.start();
    LogPrintf("ContractRegistryModel::computeMTM start wallet=%s id=%s type=%s role=%s status=%s\n",
              walletModel->getWalletName().toStdString().c_str(),
              entry.id.toStdString().c_str(),
              entry.type.toStdString().c_str(),
              entry.role.toStdString().c_str(),
              entry.status.toStdString().c_str());

    try {
        if (entry.type == "repo") {
            // Call pricing.repo.quote RPC with registry source for "mark" prices
            LogPrintf("ContractRegistryModel::computeMTM pricing.repo.quote mark start id=%s\n",
                      entry.id.toStdString().c_str());
            auto resultMark = walletModel->pricingRepoQuote(
                "registry",
                entry.id,
                QVariantMap(),  // empty inline_terms
                "",             // report_asset (empty for TSC)
                true,           // report_is_native (default to TSC)
                false,          // compute_greeks (skip for performance)
                QStringLiteral("mark"),
                false           // DO NOT include inception cashflows for opened contracts
            );
            LogPrintf("ContractRegistryModel::computeMTM pricing.repo.quote mark done id=%s success=%d elapsed_ms=%lld\n",
                      entry.id.toStdString().c_str(),
                      resultMark.success,
                      timer.elapsed());

            // Call pricing.repo.quote RPC with registry source for "market" prices
            LogPrintf("ContractRegistryModel::computeMTM pricing.repo.quote market start id=%s\n",
                      entry.id.toStdString().c_str());
            auto resultMarket = walletModel->pricingRepoQuote(
                "registry",
                entry.id,
                QVariantMap(),  // empty inline_terms
                "",             // report_asset (empty for TSC)
                true,           // report_is_native (default to TSC)
                false,          // compute_greeks (skip for performance)
                QStringLiteral("market"),
                false           // DO NOT include inception cashflows for opened contracts
            );
            LogPrintf("ContractRegistryModel::computeMTM pricing.repo.quote market done id=%s success=%d elapsed_ms=%lld\n",
                      entry.id.toStdString().c_str(),
                      resultMarket.success,
                      timer.elapsed());

            if (resultMark.success && resultMarket.success) {
                // Determine MTM based on user's role in the contract
                if (entry.role == "lender") {
                    entry.mtmMarks = resultMark.lender_mtm;
                    entry.mtmMarket = resultMarket.lender_mtm;
                } else if (entry.role == "borrower") {
                    entry.mtmMarks = resultMark.borrower_mtm;
                    entry.mtmMarket = resultMarket.borrower_mtm;
                } else {
                    // Unknown role, default to lender MTM
                    entry.mtmMarks = resultMark.lender_mtm;
                    entry.mtmMarket = resultMarket.lender_mtm;
                }
                entry.mtmComputed = true;
            } else {
                entry.mtmComputed = false;
            }
        } else if (entry.type == "forward" || entry.type == "option") {
            // Call pricing.forward.quote RPC with registry source
            // Note: Forward pricing doesn't have separate mark/market sources yet
            LogPrintf("ContractRegistryModel::computeMTM pricing.forward.quote start id=%s\n",
                      entry.id.toStdString().c_str());
            auto result = walletModel->pricingForwardQuote(
                "registry",
                entry.id,
                QVariantMap(),  // empty inline_terms (registry source reads from DB)
                "",             // report_asset (empty for TSC)
                true,           // report_is_native (default to TSC)
                false           // compute_greeks (skip for performance)
            );
            LogPrintf("ContractRegistryModel::computeMTM pricing.forward.quote done id=%s success=%d elapsed_ms=%lld\n",
                      entry.id.toStdString().c_str(),
                      result.success,
                      timer.elapsed());

            if (result.success) {
                // Determine MTM based on user's role (long = alice, short = bob)
                if (entry.role == "long") {
                    entry.mtmMarks = result.alice_mtm;
                    entry.mtmMarket = result.alice_mtm;  // Same for now (no mark/market split)
                } else if (entry.role == "short") {
                    entry.mtmMarks = result.bob_mtm;
                    entry.mtmMarket = result.bob_mtm;
                } else {
                    // Unknown role, default to alice MTM
                    entry.mtmMarks = result.alice_mtm;
                    entry.mtmMarket = result.alice_mtm;
                }
                entry.mtmComputed = true;
            } else {
                entry.mtmComputed = false;
            }
        } else if (entry.type == "difficulty") {
            if (entry.status != "opened") {
                entry.mtmComputed = false;
            } else {
                LogPrintf("ContractRegistryModel::computeMTM pricing.difficulty.quote start id=%s\n",
                          entry.id.toStdString().c_str());
                auto result = walletModel->pricingDifficultyQuote(
                    "registry",
                    entry.id,
                    QVariantMap(),
                    false
                );
                LogPrintf("ContractRegistryModel::computeMTM pricing.difficulty.quote done id=%s success=%d elapsed_ms=%lld\n",
                          entry.id.toStdString().c_str(),
                          result.success,
                          timer.elapsed());

                if (result.success && !result.model_unreliable) {
                    if (entry.diffProduct == "option") {
                        if (entry.role == "writer") {
                            entry.mtmMarks = result.expected_writer_mtm;
                            entry.mtmMarket = result.expected_writer_mtm;
                        } else if (entry.role == "buyer") {
                            entry.mtmMarks = result.expected_buyer_mtm;
                            entry.mtmMarket = result.expected_buyer_mtm;
                        } else {
                            entry.mtmMarks = result.expected_buyer_mtm;
                            entry.mtmMarket = result.expected_buyer_mtm;
                        }
                    } else {
                        if (entry.role == "short") {
                            entry.mtmMarks = result.expected_short_mtm;
                            entry.mtmMarket = result.expected_short_mtm;
                        } else {
                            entry.mtmMarks = result.expected_long_mtm;
                            entry.mtmMarket = result.expected_long_mtm;
                        }
                    }
                    entry.mtmComputed = true;
                } else {
                    entry.mtmComputed = false;
                }
            }
        } else if (entry.type == "scalarcfd") {
            // Scalar-feed bilateral CFD: only priced once opened (a funded pair exists to mark).
            if (entry.status != "opened" && entry.status != "partially_settled") {
                entry.mtmComputed = false;
            } else {
                LogPrintf("ContractRegistryModel::computeMTM scalarcfd.price start id=%s\n",
                          entry.id.toStdString().c_str());
                auto result = walletModel->scalarCfdPrice(entry.id);
                LogPrintf("ContractRegistryModel::computeMTM scalarcfd.price done id=%s success=%d elapsed_ms=%lld\n",
                          entry.id.toStdString().c_str(),
                          result.success,
                          timer.elapsed());

                if (result.success && !result.model_unreliable) {
                    // No separate mark/market curve for scalar-feed yet: expected MTM for both columns.
                    if (entry.role == "short") {
                        entry.mtmMarks = result.expected_short_mtm;
                        entry.mtmMarket = result.expected_short_mtm;
                    } else {
                        entry.mtmMarks = result.expected_long_mtm;
                        entry.mtmMarket = result.expected_long_mtm;
                    }
                    entry.mtmComputed = true;
                } else {
                    entry.mtmComputed = false;
                }
            }
        } else {
            // Unsupported contract type (e.g., spot)
            entry.mtmComputed = false;
        }
    } catch (const std::exception& e) {
        LogPrintf("ContractRegistryModel::computeMTM exception wallet=%s id=%s elapsed_ms=%lld error=%s\n",
                  walletModel->getWalletName().toStdString().c_str(),
                  entry.id.toStdString().c_str(),
                  timer.elapsed(),
                  e.what());
        entry.mtmComputed = false;
    } catch (...) {
        LogPrintf("ContractRegistryModel::computeMTM unknown exception wallet=%s id=%s elapsed_ms=%lld\n",
                  walletModel->getWalletName().toStdString().c_str(),
                  entry.id.toStdString().c_str(),
                  timer.elapsed());
        entry.mtmComputed = false;
    }

    LogPrintf("ContractRegistryModel::computeMTM done wallet=%s id=%s computed=%d mark=%f market=%f elapsed_ms=%lld\n",
              walletModel->getWalletName().toStdString().c_str(),
              entry.id.toStdString().c_str(),
              entry.mtmComputed,
              entry.mtmMarks,
              entry.mtmMarket,
              timer.elapsed());
}

QString ContractRegistryModel::formatMTM(double mtm, bool computed) const
{
    if (!computed) {
        return tr("--");
    }

    // Get TSC decimals for proper conversion from base units
    int reportDecimals = 8;
    if (walletModel) {
        WalletModel::AssetInfo tscInfo = walletModel->getAssetInfo("");
        if (tscInfo.has_decimals) {
            reportDecimals = tscInfo.decimals;
        }
    }
    const double toDisplayUnits = 1.0 / std::pow(10.0, reportDecimals);
    double displayMtm = mtm * toDisplayUnits;

    // Format with sign and 8 decimal places
    if (displayMtm > 0.0) {
        return tr("+%1 TSC").arg(displayMtm, 0, 'f', 8);
    } else if (displayMtm < 0.0) {
        return tr("%1 TSC").arg(displayMtm, 0, 'f', 8);
    } else {
        return tr("0.00000000 TSC");
    }
}
