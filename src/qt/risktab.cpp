// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <qt/risktab.h>
#include <qt/platformstyle.h>
#include <qt/walletmodel.h>
#include <qt/clientmodel.h>
#include <qt/guiutil.h>
#include <qt/themehelpers.h>

#include <interfaces/wallet.h>
#include <interfaces/node.h>

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QLabel>
#include <QCheckBox>
#include <QPushButton>
#include <QGroupBox>
#include <QSplitter>
#include <QHeaderView>
#include <QTimer>
#include <QScrollBar>
#include <QMessageBox>

#include <univalue.h>
#include <rpc/client.h>

RiskTab::RiskTab(const PlatformStyle* _platformStyle, QWidget* parent)
    : QWidget(parent),
      platformStyle(_platformStyle),
      totalMtm(0.0),
      walletMtm(0.0)
{
    setupUi();

    // Setup auto-refresh timer (every 10 seconds)
    refreshTimer = new QTimer(this);
    connect(refreshTimer, &QTimer::timeout, this, &RiskTab::refreshData);
    refreshTimer->start(10000); // 10 seconds
}

RiskTab::~RiskTab()
{
    if (refreshTimer) {
        refreshTimer->stop();
    }
}

void RiskTab::setupUi()
{
    QVBoxLayout* mainLayout = new QVBoxLayout(this);

    // Create main splitter
    mainSplitter = new QSplitter(Qt::Horizontal, this);

    // Left panel - Positions
    QWidget* leftPanel = new QWidget(this);
    QVBoxLayout* leftLayout = new QVBoxLayout(leftPanel);

    QGroupBox* positionsGroup = new QGroupBox(tr("Open Positions"), leftPanel);
    QVBoxLayout* positionsLayout = new QVBoxLayout(positionsGroup);

    // Controls
    QHBoxLayout* controlsLayout = new QHBoxLayout();
    includeBalancesCheck = new QCheckBox(tr("Include wallet balances"), this);
    includeBalancesCheck->setChecked(true);
    connect(includeBalancesCheck, &QCheckBox::stateChanged, this, &RiskTab::onIncludeBalancesChanged);

    QPushButton* checkAllButton = new QPushButton(tr("Check All"), this);
    checkAllButton->setMaximumWidth(80);
    connect(checkAllButton, &QPushButton::clicked, this, [this]() {
        positionsTree->blockSignals(true);
        for (int i = 0; i < positionsTree->topLevelItemCount(); ++i) {
            QTreeWidgetItem* item = positionsTree->topLevelItem(i);
            if (item->data(0, Qt::UserRole).isValid()) {
                item->setCheckState(0, Qt::Checked);
                contractCheckStates[item->data(0, Qt::UserRole).toString()] = true;
            }
        }
        positionsTree->blockSignals(false);
        refreshData();
    });

    QPushButton* uncheckAllButton = new QPushButton(tr("Uncheck All"), this);
    uncheckAllButton->setMaximumWidth(80);
    connect(uncheckAllButton, &QPushButton::clicked, this, [this]() {
        positionsTree->blockSignals(true);
        for (int i = 0; i < positionsTree->topLevelItemCount(); ++i) {
            QTreeWidgetItem* item = positionsTree->topLevelItem(i);
            if (item->data(0, Qt::UserRole).isValid()) {
                item->setCheckState(0, Qt::Unchecked);
                contractCheckStates[item->data(0, Qt::UserRole).toString()] = false;
            }
        }
        positionsTree->blockSignals(false);
        refreshData();
    });

    refreshButton = new QPushButton(tr("Refresh"), this);
    connect(refreshButton, &QPushButton::clicked, this, &RiskTab::refreshData);

    controlsLayout->addWidget(includeBalancesCheck);
    controlsLayout->addWidget(checkAllButton);
    controlsLayout->addWidget(uncheckAllButton);
    controlsLayout->addStretch();
    controlsLayout->addWidget(refreshButton);

    // Positions tree
    positionsTree = new QTreeWidget(this);
    positionsTree->setHeaderLabels(QStringList() << tr("Contract") << tr("Type") << tr("Role") << tr("MTM"));
    positionsTree->setSelectionMode(QAbstractItemView::NoSelection);
    positionsTree->setEditTriggers(QAbstractItemView::NoEditTriggers);  // Prevent edit mode on double-click
    positionsTree->header()->setStretchLastSection(false);
    positionsTree->header()->setSectionResizeMode(0, QHeaderView::Stretch);
    connect(positionsTree, &QTreeWidget::itemChanged, this, &RiskTab::onPositionCheckChanged);
    // Ignore double-clicks to prevent any unhandled behavior
    connect(positionsTree, &QTreeWidget::itemDoubleClicked, this, [](QTreeWidgetItem*, int) {
        // Intentionally empty - double-click has no action in Risk tab
    });

    // Add helpful tooltip explaining checkbox behavior
    positionsTree->setToolTip(tr("Check/uncheck contracts to include or exclude them from aggregated risk metrics. Wallet balances are controlled by the checkbox above."));

    positionsLayout->addLayout(controlsLayout);
    positionsLayout->addWidget(positionsTree);

    leftLayout->addWidget(positionsGroup);

    // Summary labels
    QHBoxLayout* summaryLayout = new QHBoxLayout();
    positionCountLabel = new QLabel(tr("Positions: 0"), this);
    totalMtmLabel = new QLabel(tr("Total MTM: 0.00"), this);
    totalMtmLabel->setStyleSheet("font-weight: bold;");
    filterStatusLabel = new QLabel(this);
    filterStatusLabel->setStyleSheet(QStringLiteral("color: %1; font-style: italic;").arg(ThemeHelpers::accentTextColor()));
    filterStatusLabel->setWordWrap(true);
    filterStatusLabel->setMaximumWidth(260);
    filterStatusLabel->setVisible(false);
    summaryLayout->addWidget(positionCountLabel);
    summaryLayout->addWidget(filterStatusLabel);
    summaryLayout->addStretch();
    summaryLayout->addWidget(totalMtmLabel);
    leftLayout->addLayout(summaryLayout);

    // Right panel - Risk Metrics
    QWidget* rightPanel = new QWidget(this);
    QVBoxLayout* rightLayout = new QVBoxLayout(rightPanel);

    QGroupBox* metricsGroup = new QGroupBox(tr("Portfolio Risk Metrics"), rightPanel);
    QVBoxLayout* metricsLayout = new QVBoxLayout(metricsGroup);

    riskMetricsTree = new QTreeWidget(this);
    riskMetricsTree->setHeaderLabels(QStringList() << tr("Metric") << tr("Asset") << tr("Tenor (days)") << tr("Value"));
    riskMetricsTree->header()->setStretchLastSection(false);
    riskMetricsTree->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    riskMetricsTree->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    riskMetricsTree->header()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    riskMetricsTree->header()->setSectionResizeMode(3, QHeaderView::Stretch);

    metricsLayout->addWidget(riskMetricsTree);
    rightLayout->addWidget(metricsGroup);

    // Add panels to splitter
    mainSplitter->addWidget(leftPanel);
    mainSplitter->addWidget(rightPanel);
    mainSplitter->setStretchFactor(0, 1);
    mainSplitter->setStretchFactor(1, 2);

    mainLayout->addWidget(mainSplitter);
    setLayout(mainLayout);
}

void RiskTab::setWalletModel(WalletModel* model)
{
    walletModel = model;
    if (walletModel) {
        refreshData();
    }
}

void RiskTab::refreshData()
{
    if (!walletModel) return;

    try {
        // Call the pricing.portfolio.risk RPC
        UniValue params(UniValue::VARR);
        params.push_back(includeBalancesCheck->isChecked());

        // Collect checked contract IDs for filtering aggregate Greeks
        // Note: RPC will return ALL positions but only aggregate checked ones
        UniValue contractIds(UniValue::VARR);
        int totalContracts = 0;
        int checkedContracts = 0;

        for (int i = 0; i < positionsTree->topLevelItemCount(); ++i) {
            QTreeWidgetItem* item = positionsTree->topLevelItem(i);
            if (item->data(0, Qt::UserRole).isValid()) {
                totalContracts++;
                if (item->checkState(0) == Qt::Checked) {
                    contractIds.push_back(item->data(0, Qt::UserRole).toString().toStdString());
                    checkedContracts++;
                }
            }
        }

        // Build optional per-contract filter for aggregate Greeks:
        // - No filter param           → all opened contracts are aggregated.
        // - Filter with N>0 IDs       → only those N contracts are aggregated.
        // - Filter with 0 IDs         → no contracts are aggregated (wallet balances may still be included).
        if (totalContracts > 0 && checkedContracts < totalContracts) {
            params.push_back(contractIds);

            if (checkedContracts == 0) {
                filterStatusLabel->setText(tr("(No contracts selected; showing wallet balances only)"));
            } else {
                filterStatusLabel->setText(
                    tr("(Contract Greeks for %1 of %2 contracts)").arg(checkedContracts).arg(totalContracts));
            }
            filterStatusLabel->setVisible(true);
        } else {
            // All contracts selected, or none available → no filter needed
            filterStatusLabel->clear();
            filterStatusLabel->setVisible(false);
        }

        // Execute RPC call through node interface
        UniValue result = walletModel->node().executeRpc(
            "pricing.portfolio.risk", params, walletModel->getWalletName().toStdString());

        if (result.isObject()) {
            // Preserve current tree state (expansion/scroll) before clearing
            saveTreeState();

            // Clear existing data
            clearDisplay();

            // Parse balance_deltas (wallet-only deltas)
            if (result.exists("balance_deltas")) {
                const UniValue& bal_deltas = result["balance_deltas"];
                for (const auto& key : bal_deltas.getKeys()) {
                    balanceDeltas[key] = bal_deltas[key].get_real();
                }
            }

            // Parse aggregate risk
            if (result.exists("aggregate_risk")) {
                const UniValue& aggregate = result["aggregate_risk"];

                // Parse deltas
                if (aggregate.exists("deltas")) {
                    const UniValue& deltas = aggregate["deltas"];
                    for (const auto& key : deltas.getKeys()) {
                        aggregateDeltas[key] = deltas[key].get_real();
                    }
                }

                // Parse vegas
                if (aggregate.exists("vegas")) {
                    const UniValue& vegas = aggregate["vegas"];
                    for (const auto& key : vegas.getKeys()) {
                        aggregateVegas[key] = vegas[key].get_real();
                    }
                }

                // Parse gammas
                if (aggregate.exists("gammas")) {
                    const UniValue& gammas = aggregate["gammas"];
                    for (const auto& key : gammas.getKeys()) {
                        aggregateGammas[key] = gammas[key].get_real();
                    }
                }

                // Parse cross-gammas
                if (aggregate.exists("cross_gammas")) {
                    const UniValue& xgammas = aggregate["cross_gammas"];
                    for (const auto& key : xgammas.getKeys()) {
                        // Split key by '/'
                        size_t pos = key.find('/');
                        if (pos != std::string::npos) {
                            std::string asset1 = key.substr(0, pos);
                            std::string asset2 = key.substr(pos + 1);
                            crossGammas[std::make_pair(asset1, asset2)] = xgammas[key].get_real();
                        }
                    }
                }

                // Parse rate deltas (per-asset total)
                if (aggregate.exists("rate_deltas")) {
                    const UniValue& rdeltas = aggregate["rate_deltas"];
                    for (const auto& key : rdeltas.getKeys()) {
                        rateDeltas[key] = rdeltas[key].get_real();
                    }
                }

                // Parse bucketed rate deltas: asset -> tenor_days -> dv/dr(tenor)
                if (aggregate.exists("rate_deltas_bucketed")) {
                    const UniValue& bucketed = aggregate["rate_deltas_bucketed"];
                    for (const auto& assetKey : bucketed.getKeys()) {
                        const UniValue& perAsset = bucketed[assetKey];
                        for (const auto& tenorKey : perAsset.getKeys()) {
                            // tenorKey is a stringified integer number of days
                            bool ok = true;
                            int tenor_days = QString::fromStdString(tenorKey).toInt(&ok);
                            if (!ok || tenor_days < 0) continue;
                            double value = perAsset[tenorKey].get_real();
                            rateDeltasBucketed[assetKey][static_cast<uint32_t>(tenor_days)] = value;
                        }
                    }
                }
            }

            // Parse positions
            if (result.exists("positions")) {
                const UniValue& positionsArr = result["positions"];
                for (size_t i = 0; i < positionsArr.size(); ++i) {
                    const UniValue& pos = positionsArr[i];
                    PositionData data;
                    data.contractId = QString::fromStdString(pos["contract_id"].get_str());
                    data.contractType = QString::fromStdString(pos["contract_type"].get_str());

                    if (pos.exists("role")) {
                        data.role = QString::fromStdString(pos["role"].get_str());
                    } else if (pos.exists("side")) {
                        data.role = QString::fromStdString(pos["side"].get_str());
                    }

                    data.mtm = pos["mtm"].get_real();
                    positions.push_back(data);
                }
            }

            // Parse totals
            if (result.exists("total_mtm")) {
                totalMtm = result["total_mtm"].get_real();
            }

            walletMtm = 0.0;
            if (result.exists("wallet_mtm")) {
                walletMtm = result["wallet_mtm"].get_real();
            }

            int positionCount = 0;
            if (result.exists("positions_count")) {
                positionCount = result["positions_count"].getInt<int>();
            }

            // Update displays
            populatePositionsTree();
            updateAggregateRisk();

            // Restore tree expansion state after updating
            restoreTreeState();

            // Update summary labels
            positionCountLabel->setText(tr("Positions: %1").arg(positionCount));

            // Show breakdown of MTM (already in display TSC units)
            QString mtmText;
            if (std::abs(walletMtm) > 1e-10) {
                mtmText = tr("Total MTM: %1 TSC (Wallet: %2 TSC)")
                    .arg(QString::number(totalMtm, 'f', 8))
                    .arg(QString::number(walletMtm, 'f', 8));
            } else {
                mtmText = tr("Total MTM: %1 TSC").arg(QString::number(totalMtm, 'f', 8));
            }
            totalMtmLabel->setText(mtmText);
        }
    } catch (const UniValue& e) {
        LogPrintf("RiskTab::refreshData RPC error wallet=%s error=%s\n",
                  walletModel->getWalletName().toStdString().c_str(),
                  GUIUtil::RpcExceptionMessage(e).toStdString());
    } catch (const std::exception& e) {
        QMessageBox::warning(this, tr("Error"), tr("Failed to fetch risk data: %1").arg(e.what()));
    } catch (...) {
        LogPrintf("RiskTab::refreshData unknown exception wallet=%s\n",
                  walletModel->getWalletName().toStdString().c_str());
    }
}

void RiskTab::clearDisplay()
{
    positions.clear();
    aggregateDeltas.clear();
    aggregateVegas.clear();
    aggregateGammas.clear();
    crossGammas.clear();
    rateDeltas.clear();
    rateDeltasBucketed.clear();
    balanceDeltas.clear();
    totalMtm = 0.0;
    walletMtm = 0.0;
    positionsTree->clear();
    riskMetricsTree->clear();
}

namespace {

// Local helper to format asset units in the same way as Overview/AssetBalanceWidget
QString FormatAssetUnits(uint64_t units, uint8_t decimals, bool has_decimals)
{
    if (!has_decimals || decimals == 0) {
        return QString::number(units);
    }

    uint64_t factor = 1;
    for (uint8_t i = 0; i < decimals; ++i) {
        factor *= 10;
    }

    uint64_t whole = units / factor;
    uint64_t remainder = units % factor;

    return QString("%1.%2")
        .arg(whole)
        .arg(remainder, decimals, 10, QLatin1Char('0'));
}

} // namespace

void RiskTab::populatePositionsTree()
{
    // Block signals while populating to avoid triggering refreshes
    positionsTree->blockSignals(true);
    positionsTree->clear();

    for (const auto& pos : positions) {
        QTreeWidgetItem* item = new QTreeWidgetItem(positionsTree);

        // Store full contract ID in user data for filtering
        item->setData(0, Qt::UserRole, pos.contractId);

        // Display shortened contract ID
        QString shortId = pos.contractId.left(8) + "...";
        item->setText(0, shortId);
        item->setToolTip(0, pos.contractId);

        // Add checkbox - checked by default
        item->setFlags(item->flags() | Qt::ItemIsUserCheckable);

        // Restore previous check state if available, otherwise default to checked
        auto it = contractCheckStates.find(pos.contractId);
        if (it != contractCheckStates.end()) {
            item->setCheckState(0, it->second ? Qt::Checked : Qt::Unchecked);
        } else {
            item->setCheckState(0, Qt::Checked);
        }

        item->setText(1, pos.contractType);
        item->setText(2, pos.role);
        // MTM is already converted to display units
        item->setText(3, QString::number(pos.mtm, 'f', 8));

        // Color code MTM
        if (pos.mtm > 0) {
            item->setForeground(3, QBrush(QColor(0, 128, 0))); // Green
        } else if (pos.mtm < 0) {
            item->setForeground(3, QBrush(QColor(255, 0, 0))); // Red
        }
    }

    positionsTree->blockSignals(false);

    // Add wallet balances section if included
    if (includeBalancesCheck->isChecked()) {
        QTreeWidgetItem* balanceItem = new QTreeWidgetItem(positionsTree);
        balanceItem->setText(0, tr("Wallet Balances"));
        balanceItem->setText(1, tr("Asset"));
        balanceItem->setText(2, tr("Units"));

        // Use the wallet_mtm value from RPC (already in display units, TSC)
        balanceItem->setText(3, QString::number(walletMtm, 'f', 8));

        // Make wallet balances section non-selectable (it's not a contract position)
        balanceItem->setFlags(balanceItem->flags() & ~Qt::ItemIsSelectable);

        // Highlight wallet balance row (theme-aware: light grey on light, dark grey on dark)
        const QColor rowBg = ThemeHelpers::isDarkPalette() ? QColor(45, 45, 45) : QColor(240, 240, 240);
        const QBrush rowBrush(rowBg);
        balanceItem->setBackground(0, rowBrush);
        balanceItem->setBackground(1, rowBrush);
        balanceItem->setBackground(2, rowBrush);
        balanceItem->setBackground(3, rowBrush);

        // Color code MTM
        if (walletMtm > 0) {
            balanceItem->setForeground(3, QBrush(QColor(0, 128, 0)));
        } else if (walletMtm < 0) {
            balanceItem->setForeground(3, QBrush(QColor(255, 0, 0)));
        }

        // Add child items for each asset balance, using the same units/decimals
        // as the Overview tab (via WalletModel::getAssetBalances()).
        if (walletModel) {
            const std::vector<interfaces::AssetBalance> balances = walletModel->getAssetBalances();
            for (const auto& bal : balances) {
                if (bal.balance == 0) continue;

                // Identifier column: ticker if available, otherwise short asset ID
                QString id;
                if (!bal.ticker.empty()) {
                    id = QString::fromStdString(bal.ticker);
                } else {
                    id = QString::fromStdString(bal.asset_id.ToString()).left(8) + "...";
                }

                QTreeWidgetItem* assetItem = new QTreeWidgetItem(balanceItem);
                assetItem->setText(0, id);
                assetItem->setToolTip(0, QString::fromStdString(bal.asset_id.ToString()));

                // Make child asset items non-selectable too
                assetItem->setFlags(assetItem->flags() & ~Qt::ItemIsSelectable);

                // Asset label
                assetItem->setText(1, tr("Asset"));

                // Units in native asset units (same as Overview)
                QString unitsStr = FormatAssetUnits(bal.balance, bal.decimals, bal.has_decimals);
                assetItem->setText(2, unitsStr);

                // If we have a TSC MTM for this asset from balance_deltas, show it in column 3
                std::string key = !bal.ticker.empty()
                    ? bal.ticker
                    : (bal.asset_id.ToString().substr(0, 8) + "...");
                auto it = balanceDeltas.find(key);
                if (it != balanceDeltas.end() && std::abs(it->second) > 1e-10) {
                    double value = it->second;
                    assetItem->setText(3, QString::number(value, 'f', 8));

                    if (value > 0) {
                        assetItem->setForeground(3, QBrush(QColor(0, 128, 0)));
                    } else if (value < 0) {
                        assetItem->setForeground(3, QBrush(QColor(255, 0, 0)));
                    }
                }
            }
        }
    }
}

void RiskTab::updateAggregateRisk()
{
    riskMetricsTree->clear();

    // Delta section
    if (!aggregateDeltas.empty()) {
        QTreeWidgetItem* deltaRoot = new QTreeWidgetItem(riskMetricsTree);
        deltaRoot->setText(0, tr("Delta (∂V/∂S)"));
        deltaRoot->setExpanded(true);
        deltaRoot->setFont(0, QFont("", -1, QFont::Bold));

        double totalDelta = 0.0;
        for (const auto& [asset, value] : aggregateDeltas) {
            if (asset == "_TOTAL") {
                totalDelta = value;
                continue;  // Process total separately at the end
            }

            if (std::abs(value) > 1e-10) {
                QTreeWidgetItem* item = new QTreeWidgetItem(deltaRoot);
                item->setText(1, QString::fromStdString(asset));
                item->setText(3, QString::number(value, 'f', 6));

                // Color code
                if (value > 0) {
                    item->setForeground(2, QBrush(QColor(0, 128, 0)));
                } else {
                    item->setForeground(2, QBrush(QColor(255, 0, 0)));
                }
            }
        }

        // Add total row with separator
        if (std::abs(totalDelta) > 1e-10) {
            QTreeWidgetItem* separator = new QTreeWidgetItem(deltaRoot);
            separator->setText(1, "────────");
            separator->setDisabled(true);

            QTreeWidgetItem* totalItem = new QTreeWidgetItem(deltaRoot);
            totalItem->setText(1, tr("TOTAL"));
            totalItem->setText(3, QString::number(totalDelta, 'f', 6));
            totalItem->setFont(1, QFont("", -1, QFont::Bold));
            totalItem->setFont(3, QFont("", -1, QFont::Bold));

            if (totalDelta > 0) {
                totalItem->setForeground(3, QBrush(QColor(0, 128, 0)));
            } else if (totalDelta < 0) {
                totalItem->setForeground(3, QBrush(QColor(255, 0, 0)));
            }
        }
    }

    // Vega section
    if (!aggregateVegas.empty()) {
        QTreeWidgetItem* vegaRoot = new QTreeWidgetItem(riskMetricsTree);
        vegaRoot->setText(0, tr("Vega (∂V/∂σ)"));
        vegaRoot->setExpanded(true);
        vegaRoot->setFont(0, QFont("", -1, QFont::Bold));

        double totalVega = 0.0;
        for (const auto& [asset, value] : aggregateVegas) {
            if (asset == "_TOTAL") {
                totalVega = value;
                continue;
            }

            if (std::abs(value) > 1e-10) {
                QTreeWidgetItem* item = new QTreeWidgetItem(vegaRoot);
                item->setText(1, QString::fromStdString(asset));
                item->setText(3, QString::number(value, 'f', 6));
            }
        }

        // Add total row
        if (std::abs(totalVega) > 1e-10) {
            QTreeWidgetItem* separator = new QTreeWidgetItem(vegaRoot);
            separator->setText(1, "────────");
            separator->setDisabled(true);

            QTreeWidgetItem* totalItem = new QTreeWidgetItem(vegaRoot);
            totalItem->setText(1, tr("TOTAL"));
            totalItem->setText(3, QString::number(totalVega, 'f', 6));
            totalItem->setFont(1, QFont("", -1, QFont::Bold));
            totalItem->setFont(3, QFont("", -1, QFont::Bold));
        }
    }

    // Gamma section
    if (!aggregateGammas.empty()) {
        QTreeWidgetItem* gammaRoot = new QTreeWidgetItem(riskMetricsTree);
        gammaRoot->setText(0, tr("Gamma (∂²V/∂S²)"));
        gammaRoot->setExpanded(false);
        gammaRoot->setFont(0, QFont("", -1, QFont::Bold));

        double totalGamma = 0.0;
        for (const auto& [asset, value] : aggregateGammas) {
            if (asset == "_TOTAL") {
                totalGamma = value;
                continue;
            }

            if (std::abs(value) > 1e-10) {
                QTreeWidgetItem* item = new QTreeWidgetItem(gammaRoot);
                item->setText(1, QString::fromStdString(asset));
                item->setText(3, QString::number(value, 'f', 8));
            }
        }

        // Add total row
        if (std::abs(totalGamma) > 1e-10) {
            QTreeWidgetItem* separator = new QTreeWidgetItem(gammaRoot);
            separator->setText(1, "────────");
            separator->setDisabled(true);

            QTreeWidgetItem* totalItem = new QTreeWidgetItem(gammaRoot);
            totalItem->setText(1, tr("TOTAL"));
            totalItem->setText(3, QString::number(totalGamma, 'f', 8));
            totalItem->setFont(1, QFont("", -1, QFont::Bold));
            totalItem->setFont(3, QFont("", -1, QFont::Bold));
        }
    }

    // Cross-gamma section
    if (!crossGammas.empty()) {
        QTreeWidgetItem* crossRoot = new QTreeWidgetItem(riskMetricsTree);
        crossRoot->setText(0, tr("Cross-Gamma"));
        crossRoot->setExpanded(false);
        crossRoot->setFont(0, QFont("", -1, QFont::Bold));

        for (const auto& [pair, value] : crossGammas) {
            if (std::abs(value) > 1e-10) {
                QTreeWidgetItem* item = new QTreeWidgetItem(crossRoot);
                item->setText(1, QString::fromStdString(pair.first + "/" + pair.second));
                item->setText(3, QString::number(value, 'f', 8));
            }
        }
    }

    // Rate deltas section
    if (!rateDeltas.empty()) {
        QTreeWidgetItem* rateRoot = new QTreeWidgetItem(riskMetricsTree);
        rateRoot->setText(0, tr("Rate Delta (∂V/∂r) - Total"));
        rateRoot->setExpanded(false);
        rateRoot->setFont(0, QFont("", -1, QFont::Bold));

        for (const auto& [curve, value] : rateDeltas) {
            if (std::abs(value) > 1e-10) {
                QTreeWidgetItem* item = new QTreeWidgetItem(rateRoot);
                item->setText(1, QString::fromStdString(curve));
                item->setText(3, QString::number(value, 'f', 6));
            }
        }
    }

    // Bucketed rate deltas section (per asset, per tenor)
    if (!rateDeltasBucketed.empty()) {
        QTreeWidgetItem* bucketRoot = new QTreeWidgetItem(riskMetricsTree);
        bucketRoot->setText(0, tr("Rate Delta (∂V/∂r) - Bucketed"));
        bucketRoot->setExpanded(false);
        bucketRoot->setFont(0, QFont("", -1, QFont::Bold));

        for (const auto& [asset, buckets] : rateDeltasBucketed) {
            for (const auto& [tenor_days, value] : buckets) {
                if (std::abs(value) <= 1e-10) continue;
                QTreeWidgetItem* item = new QTreeWidgetItem(bucketRoot);
                item->setText(1, QString::fromStdString(asset));
                item->setText(2, QString::number(tenor_days));
                item->setText(3, QString::number(value, 'f', 6));
            }
        }
    }
}

void RiskTab::onIncludeBalancesChanged(int state)
{
    Q_UNUSED(state);
    refreshData();
}

void RiskTab::onPositionCheckChanged(QTreeWidgetItem* item, int column)
{
    Q_UNUSED(column);

    // Save the check state for this contract
    if (item && item->data(0, Qt::UserRole).isValid()) {
        QString contractId = item->data(0, Qt::UserRole).toString();
        contractCheckStates[contractId] = (item->checkState(0) == Qt::Checked);

        // Refresh to update filtered risk metrics
        refreshData();
    }
}

void RiskTab::updateRiskDisplay()
{
    // This can be called from other parts of the application
    refreshData();
}

void RiskTab::saveTreeState()
{
    treeExpandedState.clear();

    if (positionsTree) {
        positionsScrollValue = positionsTree->verticalScrollBar()->value();

        // Save positions tree expansion state
        for (int i = 0; i < positionsTree->topLevelItemCount(); ++i) {
            QTreeWidgetItem* item = positionsTree->topLevelItem(i);
            QString key = item->text(0);
            treeExpandedState[key] = item->isExpanded();
        }

        // Save check states for all contracts
        for (int i = 0; i < positionsTree->topLevelItemCount(); ++i) {
            QTreeWidgetItem* item = positionsTree->topLevelItem(i);
            if (item->data(0, Qt::UserRole).isValid()) {
                QString contractId = item->data(0, Qt::UserRole).toString();
                contractCheckStates[contractId] = (item->checkState(0) == Qt::Checked);
            }
        }
    }

    if (riskMetricsTree) {
        riskMetricsScrollValue = riskMetricsTree->verticalScrollBar()->value();

        // Save risk metrics tree state
        for (int i = 0; i < riskMetricsTree->topLevelItemCount(); ++i) {
            QTreeWidgetItem* item = riskMetricsTree->topLevelItem(i);
            QString key = "metrics_" + item->text(0);  // Prefix to avoid collision
            treeExpandedState[key] = item->isExpanded();
        }
    }
}

void RiskTab::restoreTreeState()
{
    if (positionsTree) {
        // Restore positions tree expansion
        for (int i = 0; i < positionsTree->topLevelItemCount(); ++i) {
            QTreeWidgetItem* item = positionsTree->topLevelItem(i);
            QString key = item->text(0);
            auto it = treeExpandedState.find(key);
            if (it != treeExpandedState.end()) {
                item->setExpanded(it->second);
            }
        }

        // Check states are already restored in populatePositionsTree()

        // Restore scroll position
        positionsTree->verticalScrollBar()->setValue(positionsScrollValue);
    }

    if (riskMetricsTree) {
        // Restore risk metrics tree expansion
        for (int i = 0; i < riskMetricsTree->topLevelItemCount(); ++i) {
            QTreeWidgetItem* item = riskMetricsTree->topLevelItem(i);
            QString key = "metrics_" + item->text(0);
            auto it = treeExpandedState.find(key);
            if (it != treeExpandedState.end()) {
                item->setExpanded(it->second);
            } else {
                // Default expansion state for first-time items
                if (item->text(0).contains("Delta") || item->text(0).contains("Vega")) {
                    item->setExpanded(true);
                }
            }
        }
        // Restore scroll position
        riskMetricsTree->verticalScrollBar()->setValue(riskMetricsScrollValue);
    }
}
