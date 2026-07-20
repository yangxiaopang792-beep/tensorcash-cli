// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <qt/assetpricetab.h>
#include <qt/platformstyle.h>
#include <qt/walletmodel.h>
#include <qt/guiutil.h>
#include <qt/pricefeed.h>
#include <qt/themehelpers.h>

#include <interfaces/node.h>
#include <logging.h>
#include <univalue.h>

#include <cmath>

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QTableWidget>
#include <QHeaderView>
#include <QGroupBox>
#include <QMessageBox>
#include <QMenu>
#include <QAction>
#include <QInputDialog>
#include <QBrush>
#include <QColor>
#include <QSettings>
#include <array>
#include <memory>
#include <QPointer>
#include <QtConcurrent/QtConcurrentRun>
#include <QTableWidgetItem>
#include <QDoubleSpinBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QComboBox>

namespace {
    // Table columns for both Marks and Market tables
    enum ColumnIndex {
        COL_ASSET = 0,
        COL_FX,
        COL_RATE,
        COL_SIGMA,
        COL_COUNT
    };

    // Default values
    constexpr double DEFAULT_FX = 1.0;
    constexpr double DEFAULT_RATE = 0.0;
    constexpr double DEFAULT_SIGMA = 30.0;  // 30% volatility
}

AssetPriceTab::AssetPriceTab(const PlatformStyle* _platformStyle, QWidget* parent)
    : QWidget(parent),
      platformStyle(_platformStyle)
{
    m_priceFeed = new PriceFeed(this);
    {
        QSettings settings;
        settings.beginGroup("AssetPricing");
        m_dataFeed = settings.value("dataFeed", "Manual").toString();
        settings.endGroup();
    }
    setupUI();
    loadSettings();
}

AssetPriceTab::~AssetPriceTab()
{
    saveSettings();
}

void AssetPriceTab::setWalletModel(WalletModel* model)
{
    this->walletModel = model;
    assetDecimalsCache.clear();
    if (walletModel) {
        refreshAssetList();
    }
}

void AssetPriceTab::setupUI()
{
    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(10, 10, 10, 10);
    mainLayout->setSpacing(15);

    // Refresh Assets button and Source selector at the top
    QHBoxLayout* topButtonLayout = new QHBoxLayout();
    QPushButton* refreshButton = new QPushButton(tr("Refresh Assets"), this);
    refreshButton->setToolTip(tr("Reload asset list from wallet and registry"));
    refreshButton->setMaximumWidth(150);
    connect(refreshButton, &QPushButton::clicked, this, &AssetPriceTab::refreshAssetList);
    topButtonLayout->addWidget(refreshButton);

    QLabel* sourceLabel = new QLabel(tr("Source:"), this);
    topButtonLayout->addWidget(sourceLabel);

    QComboBox* sourceSelector = new QComboBox(this);
    sourceSelector->addItem(tr("Manual"));
    sourceSelector->addItem(tr("Nostr"));
    sourceSelector->addItem(tr("Oracle"));
    sourceSelector->setMaximumWidth(150);
    sourceSelector->setToolTip(tr("Select pricing data source"));
    topButtonLayout->addWidget(sourceSelector);

    topButtonLayout->addStretch();
    mainLayout->addLayout(topButtonLayout);

    // === SIDE-BY-SIDE TABLES ===
    QHBoxLayout* tablesLayout = new QHBoxLayout();
    tablesLayout->setSpacing(10);

    // === MARKS TABLE (LEFT) ===
    QGroupBox* marksGroup = new QGroupBox(tr("Marks (own view of the market)"), this);
    QVBoxLayout* marksLayout = new QVBoxLayout(marksGroup);

    // Marks action buttons
    QHBoxLayout* marksButtonLayout = new QHBoxLayout();

    QPushButton* commitButton = new QPushButton(tr("Commit"), this);
    commitButton->setToolTip(tr("Commit marks to pricing engine"));
    commitButton->setMaximumWidth(120);
    commitButton->setStyleSheet("QPushButton { background-color: #4CAF50; color: white; font-weight: bold; }");
    connect(commitButton, &QPushButton::clicked, this, &AssetPriceTab::onCommitMarks);
    marksButtonLayout->addWidget(commitButton);

    QPushButton* copyMarketButton = new QPushButton(tr("Copy Market"), this);
    copyMarketButton->setToolTip(tr("Copy prices from Market table"));
    copyMarketButton->setMaximumWidth(120);
    copyMarketButton->setStyleSheet("QPushButton { background-color: #FFC107; color: black; }");
    connect(copyMarketButton, &QPushButton::clicked, this, &AssetPriceTab::onCopyFromMarket);
    marksButtonLayout->addWidget(copyMarketButton);

    QPushButton* marksFXMatrixBtn = new QPushButton(tr("FX Matrix"), this);
    marksFXMatrixBtn->setMaximumWidth(120);
    marksFXMatrixBtn->setToolTip(tr("View FX cross rates matrix (read-only, no arbitrage)"));
    connect(marksFXMatrixBtn, &QPushButton::clicked, this, &AssetPriceTab::onShowMarksFXMatrix);
    marksButtonLayout->addWidget(marksFXMatrixBtn);

    QPushButton* marksCorrelBtn = new QPushButton(tr("Correlation"), this);
    marksCorrelBtn->setMaximumWidth(120);
    marksCorrelBtn->setToolTip(tr("Edit correlation matrix"));
    connect(marksCorrelBtn, &QPushButton::clicked, this, &AssetPriceTab::onShowMarksCorrelMatrix);
    marksButtonLayout->addWidget(marksCorrelBtn);

    QPushButton* marksRatesBtn = new QPushButton(tr("Rate Curves"), this);
    marksRatesBtn->setMaximumWidth(120);
    marksRatesBtn->setToolTip(tr("Edit rate term structures"));
    connect(marksRatesBtn, &QPushButton::clicked, this, &AssetPriceTab::onShowMarksRatesCurves);
    marksButtonLayout->addWidget(marksRatesBtn);

    marksButtonLayout->addStretch();
    marksLayout->addLayout(marksButtonLayout);

    // Marks table
    priceTable = new QTableWidget(this);
    priceTable->setColumnCount(4);
    QStringList marksHeaders;
    marksHeaders << tr("Asset") << tr("FX") << tr("Rate %") << tr("Vol %");
    priceTable->setHorizontalHeaderLabels(marksHeaders);
    priceTable->horizontalHeader()->setStretchLastSection(true);
    priceTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    priceTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    priceTable->setSelectionMode(QAbstractItemView::SingleSelection);
    priceTable->setAlternatingRowColors(true);
    priceTable->verticalHeader()->setVisible(false);

    // Set font size to 85%
    QFont marksFont = priceTable->font();
    marksFont.setPointSizeF(marksFont.pointSizeF() * 0.85);
    priceTable->setFont(marksFont);

    marksLayout->addWidget(priceTable);

    tablesLayout->addWidget(marksGroup);

    // === MARKET TABLE (RIGHT) ===
    QGroupBox* marketGroup = new QGroupBox(tr("Market (market view of pricing)"), this);
    QVBoxLayout* marketLayout = new QVBoxLayout(marketGroup);

    // Market action buttons
    QHBoxLayout* marketButtonLayout = new QHBoxLayout();

    QPushButton* calibrateButton = new QPushButton(tr("Calibrate"), this);
    calibrateButton->setToolTip(tr("Calibrate prices from market data"));
    calibrateButton->setMaximumWidth(120);
    calibrateButton->setStyleSheet("QPushButton { background-color: #4CAF50; color: white; font-weight: bold; }");
    connect(calibrateButton, &QPushButton::clicked, this, &AssetPriceTab::onCalibrateFromMarket);
    marketButtonLayout->addWidget(calibrateButton);

    QPushButton* dataFeedButton = new QPushButton(tr("Data Feed"), this);
    dataFeedButton->setToolTip(tr("Select data feed source"));
    dataFeedButton->setMaximumWidth(120);
    dataFeedButton->setStyleSheet("QPushButton { background-color: #FFC107; color: black; }");
    QMenu* dataFeedMenu = new QMenu(dataFeedButton);
    dataFeedMenu->addAction(tr("Nostr"), this, &AssetPriceTab::onSelectDataFeed);
    dataFeedMenu->addAction(tr("Oracle"), this, &AssetPriceTab::onSelectDataFeed);
    dataFeedMenu->addAction(tr("External API"), this, &AssetPriceTab::onSelectDataFeed);
    dataFeedButton->setMenu(dataFeedMenu);
    marketButtonLayout->addWidget(dataFeedButton);

    QPushButton* marketFXMatrixBtn = new QPushButton(tr("FX Matrix"), this);
    marketFXMatrixBtn->setMaximumWidth(120);
    marketFXMatrixBtn->setToolTip(tr("View FX cross rates matrix (read-only, no arbitrage)"));
    connect(marketFXMatrixBtn, &QPushButton::clicked, this, &AssetPriceTab::onShowMarketFXMatrix);
    marketButtonLayout->addWidget(marketFXMatrixBtn);

    QPushButton* marketCorrelBtn = new QPushButton(tr("Correlation"), this);
    marketCorrelBtn->setMaximumWidth(120);
    marketCorrelBtn->setToolTip(tr("Edit correlation matrix"));
    connect(marketCorrelBtn, &QPushButton::clicked, this, &AssetPriceTab::onShowMarketCorrelMatrix);
    marketButtonLayout->addWidget(marketCorrelBtn);

    QPushButton* marketRatesBtn = new QPushButton(tr("Rate Curves"), this);
    marketRatesBtn->setMaximumWidth(120);
    marketRatesBtn->setToolTip(tr("Edit rate term structures"));
    connect(marketRatesBtn, &QPushButton::clicked, this, &AssetPriceTab::onShowMarketRatesCurves);
    marketButtonLayout->addWidget(marketRatesBtn);

    marketButtonLayout->addStretch();
    marketLayout->addLayout(marketButtonLayout);

    // Market table
    QTableWidget* marketTable = new QTableWidget(this);
    marketTable->setObjectName("marketTable");
    marketTable->setColumnCount(4);
    QStringList marketHeaders;
    marketHeaders << tr("Asset") << tr("FX") << tr("Rate %") << tr("Vol %");
    marketTable->setHorizontalHeaderLabels(marketHeaders);
    marketTable->horizontalHeader()->setStretchLastSection(true);
    marketTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    marketTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    marketTable->setSelectionMode(QAbstractItemView::SingleSelection);
    marketTable->setAlternatingRowColors(true);
    marketTable->verticalHeader()->setVisible(false);

    // Set font size to 85%
    QFont marketFont = marketTable->font();
    marketFont.setPointSizeF(marketFont.pointSizeF() * 0.85);
    marketTable->setFont(marketFont);

    marketLayout->addWidget(marketTable);

    tablesLayout->addWidget(marketGroup);

    mainLayout->addLayout(tablesLayout);

    // Connect signals for both tables
    connect(priceTable, &QTableWidget::cellChanged, this, &AssetPriceTab::onCellChanged);
    connect(marketTable, &QTableWidget::cellChanged, this, &AssetPriceTab::onCellChanged);

    // Info section
    QLabel* infoLabel = new QLabel(
        tr("TSC (Native): FX=1.0 (locked), Vol=0.0 (locked), Rate editable. "
           "FX in decimal (e.g., 2.5 means 1 unit = 2.5 TSC), Rate in % p.a., Vol in % (default 30%)."),
        this);
    infoLabel->setWordWrap(true);
    {
        const QString bg = ThemeHelpers::isDarkPalette() ? QStringLiteral("#2d2d2d") : QStringLiteral("#f9f9f9");
        infoLabel->setStyleSheet(QStringLiteral("QLabel { color: %1; font-size: 9pt; padding: 8px; background-color: %2; border-radius: 3px; }").arg(ThemeHelpers::mutedTextColor(), bg));
    }
    mainLayout->addWidget(infoLabel);

    setLayout(mainLayout);
}

void AssetPriceTab::refreshAssetList()
{
    if (!walletModel) return;

    QTableWidget* marketTable = findChild<QTableWidget*>("marketTable");
    if (!marketTable) return;

    // Disable cell change signals while updating
    disconnect(priceTable, &QTableWidget::cellChanged, this, &AssetPriceTab::onCellChanged);
    disconnect(marketTable, &QTableWidget::cellChanged, this, &AssetPriceTab::onCellChanged);

    // Save current data before reloading
    QMap<QString, AssetPricingData> oldData = assetData;
    assetData.clear();

    // 1. Add TSC (Native) as the first row with proper defaults
    AssetPricingData tscData("", "TSC", true);
    if (oldData.contains("TSC")) {
        tscData = oldData["TSC"];
        tscData.isNative = true;
    }
    // Enforce TSC constraints
    tscData.marketFX = 1.0;
    tscData.marketSigma = 0.0;
    tscData.markFX = 1.0;
    tscData.markSigma = 0.0;
    assetData["TSC"] = tscData;

    // 2. Add wallet assets
    const auto balances = walletModel->getAssetBalances();
    QMap<QString, AssetPricingData> walletAssets;

    for (const auto& asset_balance : balances) {
        const uint64_t total_units = asset_balance.balance + asset_balance.pending + asset_balance.locked;
        if (total_units == 0) continue;

        QString assetId = QString::fromStdString(asset_balance.asset_id.ToString());
        QString ticker = asset_balance.ticker.empty() ?
                        (assetId.left(8) + "...") :
                        QString::fromStdString(asset_balance.ticker);

        AssetPricingData data(assetId, ticker, false);
        if (oldData.contains(ticker)) {
            data = oldData[ticker];
            data.assetId = assetId;
            data.ticker = ticker;
            data.isNative = false;
        } else {
            // Set proper defaults for new assets
            data.markFX = DEFAULT_FX;
            data.markRate = DEFAULT_RATE;
            data.markSigma = DEFAULT_SIGMA;
            data.marketFX = DEFAULT_FX;
            data.marketRate = DEFAULT_RATE;
            data.marketSigma = DEFAULT_SIGMA;
        }
        walletAssets[ticker] = data;
    }

    // 3. Add registry assets
    QMap<QString, AssetPricingData> registryAssets;
    try {
        if (walletModel) {
            UniValue listParams(UniValue::VARR);
            listParams.push_back(true);  // include_unregistered = true
            listParams.push_back(false); // verbose = false

            UniValue assetsResult = walletModel->node().executeRpc("listassets", listParams, walletModel->getWalletName().toStdString());

            if (assetsResult.isArray()) {
                for (size_t i = 0; i < assetsResult.size(); ++i) {
                    const UniValue& assetObj = assetsResult[i];

                    QString assetId = QString::fromStdString(assetObj.find_value("asset_id").get_str());
                    QString ticker = QString::fromStdString(assetObj.find_value("ticker").get_str());

                    if (ticker.isEmpty()) {
                        ticker = assetId.left(8) + "...";
                    }

                    // Skip if already in wallet assets
                    if (walletAssets.contains(ticker)) {
                        continue;
                    }

                    AssetPricingData data(assetId, ticker, false);
                    if (oldData.contains(ticker)) {
                        data = oldData[ticker];
                        data.assetId = assetId;
                        data.ticker = ticker;
                        data.isNative = false;
                    } else {
                        // Set proper defaults for new assets
                        data.markFX = DEFAULT_FX;
                        data.markRate = DEFAULT_RATE;
                        data.markSigma = DEFAULT_SIGMA;
                        data.marketFX = DEFAULT_FX;
                        data.marketRate = DEFAULT_RATE;
                        data.marketSigma = DEFAULT_SIGMA;
                    }
                    registryAssets[ticker] = data;
                }
            }
        }
    } catch (const UniValue& e) {
        LogPrintf("AssetPriceTab: Failed to load registry assets (RPC error): %s\n",
                  GUIUtil::RpcExceptionMessage(e).toStdString());
    } catch (const std::exception& e) {
        LogPrintf("AssetPriceTab: Failed to load registry assets: %s\n", e.what());
    } catch (...) {
        LogPrintf("AssetPriceTab: Failed to load registry assets (unknown exception)\n");
    }

    // Merge wallet and registry assets, sorting alphabetically by ticker
    for (auto it = walletAssets.begin(); it != walletAssets.end(); ++it) {
        assetData[it.key()] = it.value();
    }
    for (auto it = registryAssets.begin(); it != registryAssets.end(); ++it) {
        assetData[it.key()] = it.value();
    }

    updateTable();

    // Re-enable cell change signals
    connect(priceTable, &QTableWidget::cellChanged, this, &AssetPriceTab::onCellChanged);
    connect(marketTable, &QTableWidget::cellChanged, this, &AssetPriceTab::onCellChanged);
}

void AssetPriceTab::updateTable()
{
    // Get both tables
    QTableWidget* marketTable = findChild<QTableWidget*>("marketTable");
    if (!marketTable) return;

    // Disconnect signals while updating
    disconnect(priceTable, &QTableWidget::cellChanged, this, &AssetPriceTab::onCellChanged);
    disconnect(marketTable, &QTableWidget::cellChanged, this, &AssetPriceTab::onCellChanged);

    priceTable->setRowCount(0);
    marketTable->setRowCount(0);

    // Sort keys: TSC first, then alphabetically
    QStringList sortedKeys = assetData.keys();
    sortedKeys.removeAll("TSC");
    sortedKeys.sort();
    sortedKeys.prepend("TSC");

    // Helper to create items
    auto createEditableItem = [](double value) {
        QTableWidgetItem* item = new QTableWidgetItem(QString::number(value, 'f', 6));
        item->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
        return item;
    };

    auto createReadOnlyItem = [](double value) {
        QTableWidgetItem* item = new QTableWidgetItem(QString::number(value, 'f', 6));
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        item->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
        item->setBackground(QBrush(QColor(245, 245, 245)));
        return item;
    };

    int row = 0;
    for (const QString& key : sortedKeys) {
        const AssetPricingData& data = assetData[key];

        // === MARKS TABLE ===
        priceTable->insertRow(row);

        // Asset name
        QTableWidgetItem* marksAssetItem = new QTableWidgetItem(data.ticker);
        marksAssetItem->setFlags(marksAssetItem->flags() & ~Qt::ItemIsEditable);
        marksAssetItem->setToolTip(data.isNative ? tr("Native TSC") : data.assetId);
        if (data.isNative) {
            marksAssetItem->setFont(QFont(marksAssetItem->font().family(), -1, QFont::Bold));
        }
        priceTable->setItem(row, COL_ASSET, marksAssetItem);

        // FX, Rate, Sigma
        if (data.isNative) {
            priceTable->setItem(row, COL_FX, createReadOnlyItem(1.0));
        } else {
            priceTable->setItem(row, COL_FX, createEditableItem(data.markFX));
        }
        priceTable->setItem(row, COL_RATE, createEditableItem(data.markRate));
        if (data.isNative) {
            priceTable->setItem(row, COL_SIGMA, createReadOnlyItem(0.0));
        } else {
            priceTable->setItem(row, COL_SIGMA, createEditableItem(data.markSigma));
        }

        // === MARKET TABLE ===
        marketTable->insertRow(row);

        // Asset name
        QTableWidgetItem* marketAssetItem = new QTableWidgetItem(data.ticker);
        marketAssetItem->setFlags(marketAssetItem->flags() & ~Qt::ItemIsEditable);
        marketAssetItem->setToolTip(data.isNative ? tr("Native TSC") : data.assetId);
        if (data.isNative) {
            marketAssetItem->setFont(QFont(marketAssetItem->font().family(), -1, QFont::Bold));
        }
        marketTable->setItem(row, COL_ASSET, marketAssetItem);

        // FX, Rate, Sigma
        if (data.isNative) {
            marketTable->setItem(row, COL_FX, createReadOnlyItem(1.0));
        } else {
            marketTable->setItem(row, COL_FX, createEditableItem(data.marketFX));
            // Badge live-feed provenance on the Market FX cell (verified vs
            // issuer-claimed) so unverified prices are visibly distinct.
            if (m_marketVerified.contains(data.ticker)) {
                QTableWidgetItem* fxItem = marketTable->item(row, COL_FX);
                if (fxItem) {
                    if (m_marketVerified.value(data.ticker)) {
                        fxItem->setToolTip(tr("Live price (verified source)"));
                        fxItem->setForeground(QBrush(QColor(0x2e, 0x7d, 0x32)));
                    } else {
                        fxItem->setToolTip(tr("Live price (issuer-claimed, unverified)"));
                        fxItem->setForeground(QBrush(QColor(0xb2, 0x6a, 0x00)));
                    }
                }
            }
        }
        marketTable->setItem(row, COL_RATE, createEditableItem(data.marketRate));
        if (data.isNative) {
            marketTable->setItem(row, COL_SIGMA, createReadOnlyItem(0.0));
        } else {
            marketTable->setItem(row, COL_SIGMA, createEditableItem(data.marketSigma));
        }

        row++;
    }

    // Reconnect signals
    connect(priceTable, &QTableWidget::cellChanged, this, &AssetPriceTab::onCellChanged);
    connect(marketTable, &QTableWidget::cellChanged, this, &AssetPriceTab::onCellChanged);
}

void AssetPriceTab::onCellChanged(int row, int column)
{
    // Skip asset column
    if (column == COL_ASSET) {
        return;
    }

    // Determine which table was changed
    QTableWidget* senderTable = qobject_cast<QTableWidget*>(sender());
    if (!senderTable) return;

    bool isMarksTable = (senderTable == priceTable);

    QTableWidgetItem* assetItem = senderTable->item(row, COL_ASSET);
    if (!assetItem) return;

    QString ticker = assetItem->text();
    if (!assetData.contains(ticker)) return;

    AssetPricingData& data = assetData[ticker];

    QTableWidgetItem* item = senderTable->item(row, column);
    if (!item) return;

    bool ok = false;
    double value = item->text().toDouble(&ok);

    if (!ok || value < 0.0) {
        // Reset to previous value
        QTableWidget* marketTable = findChild<QTableWidget*>("marketTable");
        disconnect(priceTable, &QTableWidget::cellChanged, this, &AssetPriceTab::onCellChanged);
        disconnect(marketTable, &QTableWidget::cellChanged, this, &AssetPriceTab::onCellChanged);
        updateTable();
        connect(priceTable, &QTableWidget::cellChanged, this, &AssetPriceTab::onCellChanged);
        connect(marketTable, &QTableWidget::cellChanged, this, &AssetPriceTab::onCellChanged);
        QMessageBox::warning(this, tr("Invalid Input"),
            tr("Please enter a valid non-negative number."));
        return;
    }

    // Update data based on table and column
    if (isMarksTable) {
        switch (column) {
            case COL_FX:
                if (!data.isNative) data.markFX = value;
                break;
            case COL_RATE:
                data.markRate = value;
                break;
            case COL_SIGMA:
                if (!data.isNative) data.markSigma = value;
                break;
        }
    } else {
        switch (column) {
            case COL_FX:
                if (!data.isNative) data.marketFX = value;
                break;
            case COL_RATE:
                data.marketRate = value;
                break;
            case COL_SIGMA:
                if (!data.isNative) data.marketSigma = value;
                break;
        }
    }

    saveSettings();
    Q_EMIT pricesUpdated();
}

void AssetPriceTab::onCopyFromMarket()
{
    if (assetData.isEmpty()) {
        QMessageBox::information(this, tr("No Assets"),
            tr("No assets to copy. Please refresh the asset list."));
        return;
    }

    // Copy all market values to marks
    for (auto it = assetData.begin(); it != assetData.end(); ++it) {
        AssetPricingData& data = it.value();
        data.markFX = data.marketFX;
        data.markRate = data.marketRate;
        data.markSigma = data.marketSigma;
    }

    QTableWidget* marketTable = findChild<QTableWidget*>("marketTable");
    disconnect(priceTable, &QTableWidget::cellChanged, this, &AssetPriceTab::onCellChanged);
    disconnect(marketTable, &QTableWidget::cellChanged, this, &AssetPriceTab::onCellChanged);
    updateTable();
    connect(priceTable, &QTableWidget::cellChanged, this, &AssetPriceTab::onCellChanged);
    connect(marketTable, &QTableWidget::cellChanged, this, &AssetPriceTab::onCellChanged);

    saveSettings();

    QMessageBox::information(this, tr("Success"),
        tr("All mark prices have been copied from market prices."));

    Q_EMIT pricesUpdated();
}

void AssetPriceTab::onCommitMarks()
{
    if (!walletModel) {
        QMessageBox::warning(this, tr("Error"), tr("Wallet model not available."));
        return;
    }

    if (assetData.isEmpty()) {
        QMessageBox::information(this, tr("No Assets"),
            tr("No assets to commit. Please refresh the asset list."));
        return;
    }

    // Push all mark prices to the pricing engine
    int successCount = 0;
    int failCount = 0;

    for (auto it = assetData.begin(); it != assetData.end(); ++it) {
        const AssetPricingData& data = it.value();

        QString asset_hex = data.assetId;
        if (data.isNative) {
            asset_hex = "";  // Empty for TSC
        } else if (asset_hex.isEmpty()) {
            asset_hex = walletModel->resolveAssetId(data.ticker);
        }

        // Don't normalize FX - the pricing engine handles decimal conversion internally
        const double pushFX = data.markFX;
        const double pushVol = data.markSigma;
        const double pushRate = data.markRate;

        QPointer<WalletModel> wm(walletModel);
        bool success = true;

        // Push FX
        if (!data.isNative && pushFX > 0.0) {
            const bool BASE_IS_NATIVE = false;
            const bool QUOTE_IS_NATIVE = true;

            if (!wm->pricingMarketPushFX(asset_hex, "", pushFX, 0.0, "mark",
                                        BASE_IS_NATIVE, QUOTE_IS_NATIVE)) {
                success = false;
                LogPrintf("AssetPriceTab: Failed to push FX mark for %s\n", data.ticker.toStdString().c_str());
            }
        }

        // Push volatility
        if (pushVol > 0.0) {
            if (!wm->pricingMarketPushVolSurface(asset_hex, pushVol, "mark")) {
                success = false;
                LogPrintf("AssetPriceTab: Failed to push vol mark for %s\n", data.ticker.toStdString().c_str());
            }
        }

        // Push interest rate
        if (pushRate > 0.0) {
            const bool is_native = data.isNative;
            if (!wm->pricingMarketPushCurve(asset_hex, is_native, pushRate, "mark")) {
                success = false;
                LogPrintf("AssetPriceTab: Failed to push rate mark for %s\n", data.ticker.toStdString().c_str());
            }
        }

        if (success) {
            successCount++;
        } else {
            failCount++;
        }
    }

    QString message = tr("Committed %1 asset marks to pricing engine.").arg(successCount);
    if (failCount > 0) {
        message += tr("\n%1 assets failed to commit (see log).").arg(failCount);
    }

    QMessageBox::information(this, tr("Commit Complete"), message);
    Q_EMIT pricesUpdated();
}

void AssetPriceTab::onSelectDataFeed()
{
    // The Nostr / Oracle menu actions remain placeholders; "External API" wires
    // the live CoinGecko feed. The slot is shared, so branch on the sender text.
    QString choice;
    if (QAction* act = qobject_cast<QAction*>(sender())) {
        choice = act->text();
    }

    if (choice == tr("External API") || choice.isEmpty()) {
        // Privacy notice: a sovereign wallet contacting CoinGecko reveals which
        // assets you hold and your IP. Opt-in only.
        const auto ret = QMessageBox::question(this, tr("Enable live price feed"),
            tr("Enable the live CoinGecko price feed?\n\n"
               "This contacts api.coingecko.com over the network to fetch USD "
               "prices. It reveals your IP and the assets you are pricing. "
               "If you run Tor-only, route it through your SOCKS proxy first.\n\n"
               "TSC is priced as %1 basis points of live BTC.")
                .arg(pricefeed::TSC_BTC_RATIO_BPS),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
        if (ret != QMessageBox::Yes) {
            return;
        }
        m_dataFeed = "CoinGecko";
    } else {
        // Nostr / Oracle not yet implemented — keep manual.
        QMessageBox::information(this, tr("Not Yet Available"),
            tr("The %1 data feed is not implemented yet. "
               "Use 'External API' for the live CoinGecko feed, or enter prices "
               "manually.").arg(choice));
        return;
    }

    QSettings settings;
    settings.beginGroup("AssetPricing");
    settings.setValue("dataFeed", m_dataFeed);
    settings.endGroup();

    QMessageBox::information(this, tr("Data Feed Enabled"),
        tr("Live feed set to %1. Press 'Calibrate from Market' to fetch prices.")
            .arg(m_dataFeed));
}

PriceDescriptor AssetPriceTab::readOnchainPriceOracle(const QString& assetId) const
{
    PriceDescriptor d;
    if (!walletModel || assetId.isEmpty()) return d;
    try {
        UniValue params(UniValue::VARR);
        params.push_back(assetId.toStdString());
        UniValue res = walletModel->node().executeRpc(
            "geticupayload", params, walletModel->getWalletName().toStdString());

        const UniValue& wb = res.find_value("witness_bundle");
        if (!wb.isObject()) return d;
        const UniValue& po = wb.find_value("price_oracle");
        if (!po.isObject()) return d;

        const UniValue& cg = po.find_value("coingecko_id");
        const UniValue& plat = po.find_value("platform");
        const UniValue& contract = po.find_value("contract");
        const UniValue& peg = po.find_value("peg");

        if (peg.isObject()) {
            const UniValue& ref = peg.find_value("ref");
            const UniValue& ratio = peg.find_value("ratio");
            if (ref.isStr()) {
                d.kind = PriceDescriptor::Kind::Peg;
                d.pegRef = QString::fromStdString(ref.get_str());
                d.pegRatio = ratio.isNum() ? ratio.get_real() : 1.0;
            }
        } else if (cg.isStr()) {
            d.kind = PriceDescriptor::Kind::Direct;
            d.coingeckoId = QString::fromStdString(cg.get_str());
        } else if (plat.isStr() && contract.isStr()) {
            d.kind = PriceDescriptor::Kind::Direct;
            d.platform = QString::fromStdString(plat.get_str());
            d.contract = QString::fromStdString(contract.get_str());
        }
        d.verified = false;  // issuer-claimed until confirmed by the allowlist
    } catch (const UniValue& e) {
        LogPrintf("AssetPriceTab: geticupayload RPC failed for %s: %s\n",
                  assetId.toStdString(), GUIUtil::RpcExceptionMessage(e).toStdString());
    } catch (const std::exception& e) {
        LogPrintf("AssetPriceTab: price_oracle read failed: %s\n", e.what());
    } catch (...) {
    }
    return d;
}

void AssetPriceTab::onCalibrateFromMarket()
{
    if (m_dataFeed != "CoinGecko") {
        QMessageBox::information(this, tr("Select a Live Feed"),
            tr("No live data feed is enabled. Use the 'Data Feed' button and "
               "choose 'External API' to enable the CoinGecko feed."));
        return;
    }
    if (!m_priceFeed) return;

    // Build a descriptor per asset: bundled allowlist (verified) first, then the
    // on-chain issuer hint (unverified). Always include TSC so its USD value can
    // anchor the asset->TSC conversion (TSC = bps of BTC).
    QHash<QString, PriceDescriptor> descriptors;
    for (auto it = assetData.constBegin(); it != assetData.constEnd(); ++it) {
        const AssetPricingData& data = it.value();
        const QString ticker = it.key();

        PriceDescriptor d;
        if (data.isNative) {
            // The native row (isNative) is the one legitimate ticker-keyed
            // (verified) lookup. A non-native asset that merely *names* itself
            // "TSC" must NOT match here — it falls through to the asset_id path.
            d = PriceFeed::allowlistLookup("TSC");
        } else {
            // TRUST BOUNDARY: an on-chain asset is keyed by its canonical
            // asset_id, never by ticker — a ticker is attacker-chosen, so
            // allowlistLookup(ticker) would let a fake asset claim "WBTC"/"BTC"
            // and inherit a verified price.
            if (!data.assetId.isEmpty()) {
                d = PriceFeed::allowlistLookup(data.assetId);
            }
            if (!d.isValid()) {
                d = readOnchainPriceOracle(data.assetId);  // unverified
            }
        }
        if (d.isValid()) descriptors.insert(ticker, d);
    }

    if (descriptors.isEmpty()) {
        QMessageBox::information(this, tr("Nothing to Price"),
            tr("None of the listed assets can be resolved to an external price "
               "(no allowlist entry and no on-chain price hint)."));
        return;
    }

    // One-shot: whichever of pricesReady/failed fires first tears down BOTH
    // connections, so repeated calibrations don't accumulate stale callbacks.
    QPointer<AssetPriceTab> self(this);
    auto conns = std::make_shared<std::array<QMetaObject::Connection, 2>>();
    auto cleanup = [conns]() {
        QObject::disconnect((*conns)[0]);
        QObject::disconnect((*conns)[1]);
    };
    (*conns)[0] = connect(m_priceFeed, &PriceFeed::pricesReady, this,
        [self, cleanup](const QHash<QString, AssetUsdPrice>& prices) {
            cleanup();
            if (self) self->applyMarketUsdPrices(prices);
        });
    (*conns)[1] = connect(m_priceFeed, &PriceFeed::failed, this,
        [self, cleanup](const QString& err) {
            cleanup();
            if (self) QMessageBox::warning(self, tr("Price Feed Error"), err);
        });

    m_priceFeed->fetchUsdPrices(descriptors);
}

void AssetPriceTab::applyMarketUsdPrices(const QHash<QString, AssetUsdPrice>& prices)
{
    // TSC is the numeraire; its USD value anchors every asset->TSC conversion.
    const auto tscIt = prices.find("TSC");
    if (tscIt == prices.constEnd() || !tscIt->hasUsd || tscIt->usd <= 0.0) {
        QMessageBox::warning(this, tr("Price Feed Error"),
            tr("Could not determine the live TSC/USD anchor (BTC price "
               "unavailable). Market prices were not updated."));
        return;
    }
    const double tscUsd = tscIt->usd;

    int updated = 0;
    for (auto it = prices.constBegin(); it != prices.constEnd(); ++it) {
        const QString& ticker = it.key();
        const AssetUsdPrice& p = it.value();
        if (!p.hasUsd || !assetData.contains(ticker)) continue;

        AssetPricingData& data = assetData[ticker];
        if (data.isNative || ticker == "TSC") {
            data.marketFX = 1.0;  // numeraire stays fixed
        } else {
            // Market FX = price of asset in TSC.
            data.marketFX = p.usd / tscUsd;
        }
        m_marketVerified[ticker] = p.verified;
        ++updated;
    }

    updateTable();
    saveSettings();
    pushToWallet();
    Q_EMIT pricesUpdated();

    QMessageBox::information(this, tr("Calibration Complete"),
        tr("Updated %1 market price(s) from the live feed "
           "(TSC/USD ≈ %2).").arg(updated).arg(tscUsd, 0, 'f', 2));
}

void AssetPriceTab::pushToWallet()
{
    // Push the market-side data to the pricing engine under source "market"
    // (calibrated prices) — the market mirror of onCommitMarks, which pushes
    // the mark side under "mark". Silent: callers run inside feed/calibration
    // flows that surface their own summary dialogs.
    if (!walletModel || assetData.isEmpty()) return;

    for (auto it = assetData.constBegin(); it != assetData.constEnd(); ++it) {
        const AssetPricingData& data = it.value();

        QString asset_hex = data.assetId;
        if (data.isNative) {
            asset_hex = "";  // Empty for TSC
        } else if (asset_hex.isEmpty()) {
            asset_hex = walletModel->resolveAssetId(data.ticker);
        }

        QPointer<WalletModel> wm(walletModel);
        if (!wm) return;

        if (!data.isNative && data.marketFX > 0.0) {
            const bool BASE_IS_NATIVE = false;
            const bool QUOTE_IS_NATIVE = true;
            if (!wm->pricingMarketPushFX(asset_hex, "", data.marketFX, 0.0, "market",
                                         BASE_IS_NATIVE, QUOTE_IS_NATIVE)) {
                LogPrintf("AssetPriceTab: Failed to push market FX for %s\n", data.ticker.toStdString().c_str());
            }
        }

        if (data.marketSigma > 0.0) {
            if (!wm->pricingMarketPushVolSurface(asset_hex, data.marketSigma, "market")) {
                LogPrintf("AssetPriceTab: Failed to push market vol for %s\n", data.ticker.toStdString().c_str());
            }
        }

        if (data.marketRate > 0.0) {
            if (!wm->pricingMarketPushCurve(asset_hex, data.isNative, data.marketRate, "market")) {
                LogPrintf("AssetPriceTab: Failed to push market rate for %s\n", data.ticker.toStdString().c_str());
            }
        }
    }
}

void AssetPriceTab::loadSettings()
{
    QSettings settings;
    settings.beginGroup("AssetPricing");

    int size = settings.beginReadArray("assets");
    for (int i = 0; i < size; ++i) {
        settings.setArrayIndex(i);

        QString ticker = settings.value("ticker").toString();
        QString assetId = settings.value("assetId").toString();
        bool isNative = settings.value("isNative", false).toBool();

        AssetPricingData data(assetId, ticker, isNative);
        data.marketFX = settings.value("marketFX", 1.0).toDouble();
        data.marketRate = settings.value("marketRate", 0.0).toDouble();
        data.marketSigma = settings.value("marketSigma", 0.0).toDouble();
        data.markFX = settings.value("markFX", 1.0).toDouble();
        data.markRate = settings.value("markRate", 0.0).toDouble();
        data.markSigma = settings.value("markSigma", 0.0).toDouble();

        if (!ticker.isEmpty()) {
            assetData[ticker] = data;
        }
    }
    settings.endArray();
    settings.endGroup();
}

void AssetPriceTab::saveSettings()
{
    QSettings settings;
    settings.beginGroup("AssetPricing");

    settings.beginWriteArray("assets");
    int i = 0;
    for (auto it = assetData.begin(); it != assetData.end(); ++it) {
        settings.setArrayIndex(i);
        const AssetPricingData& data = it.value();

        settings.setValue("ticker", data.ticker);
        settings.setValue("assetId", data.assetId);
        settings.setValue("isNative", data.isNative);
        settings.setValue("marketFX", data.marketFX);
        settings.setValue("marketRate", data.marketRate);
        settings.setValue("marketSigma", data.marketSigma);
        settings.setValue("markFX", data.markFX);
        settings.setValue("markRate", data.markRate);
        settings.setValue("markSigma", data.markSigma);

        ++i;
    }
    settings.endArray();
    settings.endGroup();
}

double AssetPriceTab::normalizePriceForFX(double displayPrice, const QString& asset_id) const
{
    if (!std::isfinite(displayPrice) || displayPrice <= 0.0) {
        return displayPrice;
    }

    const int baseDecimals = assetDecimals(asset_id);
    const int quoteDecimals = assetDecimals(QString()); // Native TSC
    const int diff = quoteDecimals - baseDecimals;
    const double scale = std::pow(10.0, diff);

    if (!std::isfinite(scale) || scale <= 0.0) {
        return displayPrice;
    }

    return displayPrice * scale;
}

int AssetPriceTab::assetDecimals(const QString& asset_id) const
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

bool AssetPriceTab::isPricerDefault(const AssetPricingData& data) const
{
    // Check if the data matches pricer defaults
    // For now, we consider defaults as FX=1.0, Rate=0.0, Sigma=0.0
    return (data.markFX == 1.0 && data.markRate == 0.0 && data.markSigma == 0.0);
}

double AssetPriceTab::getAssetPriceInTSC(const QString& assetSymbol) const
{
    // Return market FX rate for the asset
    QString symbol = assetSymbol.toUpper();
    if (assetData.contains(symbol)) {
        return assetData[symbol].marketFX;
    }
    return 0.0;
}

// ========== MATRIX DIALOGS ==========

void AssetPriceTab::onShowMarksFXMatrix()
{
    showFXMatrix(true);
}

void AssetPriceTab::onShowMarketFXMatrix()
{
    showFXMatrix(false);
}

void AssetPriceTab::showFXMatrix(bool isMarks)
{
    QDialog dialog(this);
    dialog.setWindowTitle(isMarks ? tr("FX Cross Rates Matrix (Marks)") : tr("FX Cross Rates Matrix (Market)"));
    dialog.setMinimumSize(600, 400);

    QVBoxLayout* layout = new QVBoxLayout(&dialog);

    QLabel* infoLabel = new QLabel(
        tr("This matrix shows implied FX cross rates between all asset pairs. "
           "Values are calculated from direct rates to avoid arbitrage opportunities. "
           "Matrix is read-only."), &dialog);
    infoLabel->setWordWrap(true);
    infoLabel->setStyleSheet(QStringLiteral("QLabel { %1 margin-bottom: 10px; }").arg(ThemeHelpers::warningPanelStyleSheet()));
    layout->addWidget(infoLabel);

    // Build FX matrix
    QStringList assets = assetData.keys();
    assets.sort();

    int n = assets.size();
    QTableWidget* matrix = new QTableWidget(n, n, &dialog);
    matrix->setHorizontalHeaderLabels(assets);
    matrix->setVerticalHeaderLabels(assets);
    matrix->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);

    // Populate matrix
    for (int i = 0; i < n; ++i) {
        for (int j = 0; j < n; ++j) {
            double rate = 1.0;
            if (i != j) {
                double baseFX = isMarks ? assetData[assets[i]].markFX : assetData[assets[i]].marketFX;
                double quoteFX = isMarks ? assetData[assets[j]].markFX : assetData[assets[j]].marketFX;
                if (quoteFX > 0.0) {
                    rate = baseFX / quoteFX;
                }
            }

            QTableWidgetItem* item = new QTableWidgetItem(QString::number(rate, 'f', 6));
            item->setFlags(item->flags() & ~Qt::ItemIsEditable);
            item->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
            if (i == j) {
                item->setBackground(QBrush(QColor(240, 240, 240)));
            }
            matrix->setItem(i, j, item);
        }
    }

    layout->addWidget(matrix);

    QDialogButtonBox* buttonBox = new QDialogButtonBox(QDialogButtonBox::Close, &dialog);
    connect(buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    layout->addWidget(buttonBox);

    dialog.exec();
}

void AssetPriceTab::onShowMarksCorrelMatrix()
{
    showCorrelationMatrix(true);
}

void AssetPriceTab::onShowMarketCorrelMatrix()
{
    showCorrelationMatrix(false);
}

void AssetPriceTab::showCorrelationMatrix(bool isMarks)
{
    QDialog dialog(this);
    dialog.setWindowTitle(isMarks ? tr("Correlation Matrix (Marks)") : tr("Correlation Matrix (Market)"));
    dialog.setMinimumSize(600, 400);

    QVBoxLayout* layout = new QVBoxLayout(&dialog);

    QLabel* infoLabel = new QLabel(
        tr("Edit correlations between asset pairs. Values must be between -1.0 and 1.0. "
           "Diagonal values are always 1.0. Matrix is symmetric."), &dialog);
    infoLabel->setWordWrap(true);
    infoLabel->setStyleSheet(QStringLiteral("QLabel { %1 margin-bottom: 10px; }").arg(ThemeHelpers::infoPanelStyleSheet()));
    layout->addWidget(infoLabel);

    // Build correlation matrix
    QStringList assets = assetData.keys();
    assets.sort();

    int n = assets.size();
    QTableWidget* matrix = new QTableWidget(n, n, &dialog);
    matrix->setHorizontalHeaderLabels(assets);
    matrix->setVerticalHeaderLabels(assets);
    matrix->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);

    // Populate matrix with default 0.0 correlation (except diagonal)
    for (int i = 0; i < n; ++i) {
        for (int j = 0; j < n; ++j) {
            double correl = (i == j) ? 1.0 : 0.0;  // Default: no correlation (independence)

            QTableWidgetItem* item = new QTableWidgetItem(QString::number(correl, 'f', 4));
            item->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);

            if (i == j) {
                item->setFlags(item->flags() & ~Qt::ItemIsEditable);
                item->setBackground(QBrush(QColor(240, 240, 240)));
            } else if (i > j) {
                // Lower triangle mirrors upper triangle
                item->setFlags(item->flags() & ~Qt::ItemIsEditable);
                item->setBackground(QBrush(QColor(250, 250, 250)));
            }

            matrix->setItem(i, j, item);
        }
    }

    // Connect cell changes to mirror across diagonal
    connect(matrix, &QTableWidget::cellChanged, [matrix, n](int row, int col) {
        if (row < col) {  // Only update if in upper triangle
            QTableWidgetItem* item = matrix->item(row, col);
            if (item) {
                double val = item->text().toDouble();
                // Clamp to [-1, 1]
                if (val < -1.0) val = -1.0;
                if (val > 1.0) val = 1.0;
                item->setText(QString::number(val, 'f', 4));

                // Mirror to lower triangle
                QTableWidgetItem* mirrorItem = matrix->item(col, row);
                if (mirrorItem) {
                    QSignalBlocker blocker(matrix);
                    mirrorItem->setText(QString::number(val, 'f', 4));
                }
            }
        }
    });

    layout->addWidget(matrix);

    QDialogButtonBox* buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
    connect(buttonBox, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    connect(buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    layout->addWidget(buttonBox);

    if (dialog.exec() == QDialog::Accepted) {
        if (!walletModel) {
            QMessageBox::warning(this, tr("Error"), tr("Wallet model not available"));
            return;
        }

        // Extract correlation matrix from table
        QStringList asset_ids_hex;
        QVector<QVector<double>> corr_matrix;

        for (int i = 0; i < n; ++i) {
            const QString& ticker = assets[i];
            const AssetPricingData& data = assetData[ticker];

            // Use zero hash for TSC/native, otherwise use hex ID
            asset_ids_hex.append(data.isNative ? QString("0000000000000000000000000000000000000000000000000000000000000000") : data.assetId);

            QVector<double> row;
            for (int j = 0; j < n; ++j) {
                QTableWidgetItem* item = matrix->item(i, j);
                double val = item ? item->text().toDouble() : (i == j ? 1.0 : 0.0);
                row.append(val);
            }
            corr_matrix.append(row);
        }

        // Push to pricing engine
        try {
            bool success = walletModel->pricingMarketPushCorrelation(asset_ids_hex, corr_matrix);

            if (success) {
                QMessageBox::information(this, tr("Success"),
                    tr("Correlation matrix saved to pricing engine."));
            } else {
                QMessageBox::warning(this, tr("Error"),
                    tr("Failed to save correlation matrix. Check debug.log for details."));
            }
        } catch (const std::exception& e) {
            QMessageBox::critical(this, tr("Error"),
                tr("Exception while saving correlation matrix: %1").arg(QString::fromStdString(e.what())));
        } catch (...) {
            QMessageBox::critical(this, tr("Error"),
                tr("Unknown exception while saving correlation matrix."));
        }
    }
}

void AssetPriceTab::onShowMarksRatesCurves()
{
    showRatesCurves(true);
}

void AssetPriceTab::onShowMarketRatesCurves()
{
    showRatesCurves(false);
}

void AssetPriceTab::showRatesCurves(bool isMarks)
{
    QDialog dialog(this);
    dialog.setWindowTitle(isMarks ? tr("Rate Term Structures (Marks)") : tr("Rate Term Structures (Market)"));
    dialog.setMinimumSize(700, 500);

    QVBoxLayout* layout = new QVBoxLayout(&dialog);

    QLabel* infoLabel = new QLabel(
        tr("Edit interest rate term structures for each asset. "
           "Rates are in % per annum. Standard tenors: 7D, 30D, 90D, 180D, 365D."), &dialog);
    infoLabel->setWordWrap(true);
    infoLabel->setStyleSheet(QStringLiteral("QLabel { %1 margin-bottom: 10px; }").arg(ThemeHelpers::successPanelStyleSheet()));
    layout->addWidget(infoLabel);

    // Build rate curves table
    QStringList assets = assetData.keys();
    assets.sort();

    QStringList tenors;
    tenors << "7D" << "30D" << "90D" << "180D" << "365D";

    QTableWidget* table = new QTableWidget(assets.size(), tenors.size() + 1, &dialog);

    QStringList headers;
    headers << "Asset" << tenors;
    table->setHorizontalHeaderLabels(headers);
    table->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    table->verticalHeader()->setVisible(false);

    // Populate table with current flat rates
    for (int i = 0; i < assets.size(); ++i) {
        // Asset column
        QTableWidgetItem* assetItem = new QTableWidgetItem(assets[i]);
        assetItem->setFlags(assetItem->flags() & ~Qt::ItemIsEditable);
        assetItem->setBackground(QBrush(QColor(240, 240, 240)));
        table->setItem(i, 0, assetItem);

        // Rate columns (using flat rate from main table)
        double flatRate = isMarks ? assetData[assets[i]].markRate : assetData[assets[i]].marketRate;
        for (int j = 0; j < tenors.size(); ++j) {
            QTableWidgetItem* item = new QTableWidgetItem(QString::number(flatRate, 'f', 4));
            item->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
            table->setItem(i, j + 1, item);
        }
    }

    layout->addWidget(table);

    QDialogButtonBox* buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
    connect(buttonBox, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    connect(buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    layout->addWidget(buttonBox);

    if (dialog.exec() == QDialog::Accepted) {
        if (!walletModel) {
            QMessageBox::warning(this, tr("Error"), tr("Wallet model not available"));
            return;
        }

        // Extract rate curves from table and push to pricing engine
        try {
            QVector<int> tenors_days;
            tenors_days << 7 << 30 << 90 << 180 << 365;

            int success_count = 0;
            int fail_count = 0;

            for (int i = 0; i < assets.size(); ++i) {
                const QString& ticker = assets[i];
                const AssetPricingData& data = assetData[ticker];

                // Extract rates for all tenors
                QVector<double> rates;
                for (int j = 0; j < tenors.size(); ++j) {
                    QTableWidgetItem* item = table->item(i, j + 1);
                    double rate = item ? item->text().toDouble() : 0.0;
                    rates.append(rate);
                }

                // Push to pricing engine
                bool success = walletModel->pricingMarketPushCurve(
                    data.isNative ? QString("") : data.assetId,
                    data.isNative,
                    tenors_days,
                    rates,
                    "mark"  // Using marks source
                );

                if (success) {
                    ++success_count;
                    // Update the main table's rate with the average of the term structure
                    double avg_rate = 0.0;
                    for (double r : rates) avg_rate += r;
                    avg_rate /= rates.size();

                    if (isMarks) {
                        assetData[ticker].markRate = avg_rate;
                    } else {
                        assetData[ticker].marketRate = avg_rate;
                    }
                } else {
                    ++fail_count;
                }
            }

            updateTable();

            if (fail_count == 0) {
                QMessageBox::information(this, tr("Success"),
                    tr("All %1 rate term structures saved to pricing engine.").arg(success_count));
            } else {
                QMessageBox::warning(this, tr("Partial Success"),
                    tr("%1 curves saved, %2 failed. Check debug.log for details.").arg(success_count).arg(fail_count));
            }
        } catch (const std::exception& e) {
            QMessageBox::critical(this, tr("Error"),
                tr("Exception while saving rate curves: %1").arg(QString::fromStdString(e.what())));
        } catch (...) {
            QMessageBox::critical(this, tr("Error"),
                tr("Unknown exception while saving rate curves."));
        }
    }
}
