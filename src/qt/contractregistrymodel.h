// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_CONTRACTREGISTRYMODEL_H
#define BITCOIN_QT_CONTRACTREGISTRYMODEL_H

#include <QAbstractTableModel>
#include <QDateTime>
#include <QString>
#include <QList>
#include <QVariantMap>

#include <atomic>
#include <cstdint>

class WalletModel;

/**
 * Model for the active contracts table.
 * In-memory cache of contracts from wallet registry.
 */
class ContractRegistryModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    explicit ContractRegistryModel(WalletModel* wallet, QObject* parent = nullptr);

    enum ColumnIndex {
        ContractId = 0,
        MTMMarks = 1,       // MTM using internal pricing curves
        MTMMarket = 2,      // MTM using market-calibrated curves
        Type = 3,
        Role = 4,
        PrimaryValue = 5,   // Repo: Collateral, Forward/Option: Delivery legs, Spot: Trade amount
        SecondaryValue = 6, // Repo: Principal, Forward/Option: Margins, Spot: Price
        KeyMetric = 7,      // Repo: LTV%, Forward: IM%, Option: Premium, Spot: N/A
        Status = 8,
        Timeline = 9,       // Repo: Maturity, Forward: Deadlines, Spot: N/A
        Actions = 10,
        ColumnCount
    };

    enum ContractDataRole {
        ContractIdRole = Qt::UserRole,
        ContractTypeRole,
        ContractRoleRole,
        ContractStatusRole,
        ContractDataRole // Full contract data as QVariantMap
    };

    // QAbstractTableModel interface
    int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    int columnCount(const QModelIndex& parent = QModelIndex()) const override;
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;

    // Contract management
    void refresh();
    void setTypeFilter(const QString& type);
    void setStatusFilter(const QString& status);
    QVariantMap getContractData(int row) const;
    QVariantMap getContractDataById(const QString& id) const;

private:
    struct ContractEntry {
        QString id;
        QString type;
        QString role;
        QString status;
        int maturityHeight;
        QString maturityTime;
        int createdHeight;

        // Repo-specific fields
        double collateralAmount{0.0};
        QString collateralAsset;
        double principalAmount{0.0};
        QString principalAsset;
        double interestAmount{0.0};
        QString interestAsset;
        double ltv{0.0};

        // Forward/Option-specific fields
        double longDeliverAmount{0.0};
        QString longDeliverAsset;
        double longMarginAmount{0.0};
        QString longMarginAsset;
        double shortDeliverAmount{0.0};
        QString shortDeliverAsset;
        double shortMarginAmount{0.0};
        QString shortMarginAsset;
        double premiumAmount{0.0};
        QString premiumAsset;
        int deadlineShort{0};
        int deadlineLong{0};
        double longImPercent{0.0};
        double shortImPercent{0.0};

        // Spot-specific fields
        double aliceDeliverAmount{0.0};
        QString aliceDeliverAsset;
        double bobDeliverAmount{0.0};
        QString bobDeliverAsset;
        double exchangeRate{0.0};

        // Difficulty-derivative fields (type == "difficulty"); native TSC
        QString diffProduct;            // "cfd" / "option"
        QString strikeNbits;            // compact target, 8-hex
        int fixingHeight{0};
        int settleLockHeight{0};
        double diffLongIm{0.0};
        double diffLongLambda{0.0};
        double diffShortIm{0.0};
        double diffShortLambda{0.0};
        double diffPremium{0.0};
        QString writerSide;             // option: side the writer holds
        QString longVault;              // funded vault outpoint (or empty)
        QString shortVault;
        QString openTxid;

        // Scalar-feed bilateral CFD fields (type == "scalarcfd"); the difficulty sibling, keyed by a
        // published scalar feed rather than the on-chain difficulty target. Vault/open fields reuse
        // longVault/shortVault/openTxid above (shared bilateral covenant shape).
        int scfdFeedId{0};
        quint64 scfdFixingRef{0};
        QString scfdStrike;             // K, 32-hex scalar
        int scfdFixingDeadline{0};      // publication_deadline_height
        int scfdSettleLockHeight{0};
        double scfdLongIm{0.0};
        double scfdLongLambda{0.0};
        double scfdShortIm{0.0};
        double scfdShortLambda{0.0};
        bool scfdLongSettled{false};
        bool scfdShortSettled{false};

        // MTM pricing fields
        double mtmMarks{0.0};       // MTM using internal curves
        double mtmMarket{0.0};      // MTM using market-calibrated curves
        bool mtmComputed{false};    // Whether MTM has been computed

        QVariantMap fullData;
    };

    // Worker-thread snapshot builder. Does the blocking RPC work
    // (listContracts + per-contract asset-label resolution + MTM/pricing
    // quotes) and returns a plain list. STATIC and takes WalletModel*
    // explicitly so it touches no `this` state — safe to run on a
    // QtConcurrent worker. The three helpers it calls are static for the
    // same reason. Filtering is NOT applied here; the full list is returned
    // and the GUI thread slices it in applyFilters().
    static QList<ContractEntry> buildSnapshot(WalletModel* walletModel);

    // GUI-thread appliers (must run on the GUI thread — they touch the
    // QAbstractTableModel's row data and emit model reset signals).
    void applySnapshot(QList<ContractEntry> snapshot);  // contracts = snapshot; applyFilters()
    void applyFilters();                                // rebuild filteredContracts from contracts

    static QString formatMaturityCountdown(WalletModel* walletModel, int height);
    static QString resolveAssetLabel(WalletModel* walletModel, const QString& assetIdOrLabel);
    static void computeMTM(WalletModel* walletModel, ContractEntry& entry);
    QString formatMTM(double mtm, bool computed) const;

    WalletModel* walletModel;
    QList<ContractEntry> contracts;
    QList<ContractEntry> filteredContracts;
    QString typeFilter;
    QString statusFilter;

    // Async refresh coordination. refresh() runs buildSnapshot() on a worker
    // and applies the result on the GUI thread, so a slow RPC backend cannot
    // stall the GUI event loop past the 60s watchdog (observed 2026-05-27,
    // ContractRegistryModel::loadContracts blocked >60s on a slow network).
    //  - m_refreshGeneration: bumped on every refresh(); the worker captures
    //    its value and the GUI applier drops the result if a newer refresh
    //    has since been requested (stale-result guard).
    //  - m_refreshInFlight / m_refreshPending: coalesce. If a refresh is
    //    requested while one is running, mark pending instead of launching a
    //    second worker; relaunch once when the current one completes.
    std::atomic<uint64_t> m_refreshGeneration{0};
    bool m_refreshInFlight{false};
    bool m_refreshPending{false};
};

#endif // BITCOIN_QT_CONTRACTREGISTRYMODEL_H
