// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_QT_RISKTAB_H
#define BITCOIN_QT_RISKTAB_H

#include <QPointer>
#include <QWidget>
#include <QTimer>
#include <memory>

class WalletModel;
class PlatformStyle;

QT_BEGIN_NAMESPACE
class QTableView;
class QCheckBox;
class QPushButton;
class QLabel;
class QTreeWidget;
class QTreeWidgetItem;
class QSplitter;
QT_END_NAMESPACE

namespace wallet {
    struct AssetGreeks {
        std::vector<double> delta;
        std::vector<double> vega;
        std::vector<double> gamma;
        std::vector<std::vector<double>> cross_gamma;
        std::vector<double> rate_delta;
    };
}

class RiskTab : public QWidget
{
    Q_OBJECT

public:
    explicit RiskTab(const PlatformStyle* platformStyle, QWidget* parent = nullptr);
    ~RiskTab();

    void setWalletModel(WalletModel* model);

private Q_SLOTS:
    void updateRiskDisplay();
    void onIncludeBalancesChanged(int state);
    void onPositionCheckChanged(QTreeWidgetItem* item, int column);
    void refreshData();

private:
    void setupUi();
    void populatePositionsTree();
    void updateAggregateRisk();
    void clearDisplay();

    // QPointer auto-nulls when the WalletModel QObject is destroyed (e.g. on
    // wallet unload). Raw pointer here would dangle and the refreshTimer slot
    // would crash inside walletModel->getWalletName() despite the null check.
    QPointer<WalletModel> walletModel;
    const PlatformStyle* platformStyle{nullptr};

    // UI Components
    QSplitter* mainSplitter{nullptr};

    // Left panel - positions
    QTreeWidget* positionsTree{nullptr};
    QCheckBox* includeBalancesCheck{nullptr};
    QPushButton* refreshButton{nullptr};

    // Right panel - risk metrics
    QTreeWidget* riskMetricsTree{nullptr};
    QLabel* totalMtmLabel{nullptr};
    QLabel* positionCountLabel{nullptr};
    QLabel* filterStatusLabel{nullptr};

    // Auto-refresh
    QTimer* refreshTimer{nullptr};

    // Risk data cache
    struct PositionData {
        QString contractId;
        QString contractType;
        QString role;
        double mtm;
        wallet::AssetGreeks greeks;
    };

    std::vector<PositionData> positions;
    std::map<std::string, double> aggregateDeltas;
    std::map<std::string, double> aggregateVegas;
    std::map<std::string, double> aggregateGammas;
    std::map<std::pair<std::string, std::string>, double> crossGammas;
    std::map<std::string, double> rateDeltas;
    // Bucketed rate deltas: asset -> tenor_days -> sensitivity
    std::map<std::string, std::map<uint32_t, double>> rateDeltasBucketed;
    std::map<std::string, double> balanceDeltas;  // Wallet-only balance deltas
    double totalMtm;
    double walletMtm;

    // Preserve tree expansion state
    void saveTreeState();
    void restoreTreeState();
    std::map<QString, bool> treeExpandedState;  // Map of item text to expanded state
    std::map<QString, bool> contractCheckStates;  // Track contract check states across refreshes
    int positionsScrollValue{0};
    int riskMetricsScrollValue{0};
};

#endif // BITCOIN_QT_RISKTAB_H
