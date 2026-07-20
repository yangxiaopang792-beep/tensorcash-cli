// Copyright (c) 2024 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/assetbalancewidget.h>

#include <qt/clientmodel.h>
#include <qt/guiconstants.h>
#include <qt/guiutil.h>
#include <qt/platformstyle.h>
#include <qt/walletmodel.h>

#include <QApplication>
#include <QClipboard>
#include <uint256.h>

#include <optional>

#include <QAction>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QMenu>
#include <QMessageBox>
#include <QPushButton>
#include <QSizePolicy>
#include <QTableWidget>
#include <QVBoxLayout>

AssetBalanceWidget::AssetBalanceWidget(QWidget* parent)
    : QFrame(parent),
      m_platform_style(nullptr)
{
    // UI will be set up when setPlatformStyle is called
}

void AssetBalanceWidget::setPlatformStyle(const PlatformStyle* platformStyle)
{
    m_platform_style = platformStyle;
    if (m_platform_style && !mainLayout) {
        setupUi();
        // If we have cached balances, update the display now that UI is ready
        if (!m_cached_balances.empty()) {
            updateAssetBalances(m_cached_balances);
        }
    }
}

AssetBalanceWidget::~AssetBalanceWidget() = default;

void AssetBalanceWidget::setupUi()
{
    // Frame style is already set in the .ui file
    // Don't override it here to preserve the box appearance

    // Keep this frame from being stretched vertically by the overview page —
    // we want the frame to hug a compact 5-row table, not consume free space
    // that would otherwise crowd out the Wallet MTM section below.
    setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Maximum);

    // Create main layout
    mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(10, 10, 10, 10);

    // Create header with title and buttons
    headerLayout = new QHBoxLayout();

    // Title label
    titleLabel = new QLabel(tr("Asset Balances"));
    QFont titleFont = titleLabel->font();
    titleFont.setBold(true);
    titleFont.setPointSize(titleFont.pointSize() + 1);
    titleLabel->setFont(titleFont);
    headerLayout->addWidget(titleLabel);

    headerLayout->addStretch();

    // Refresh button
    refreshButton = new QPushButton(tr("Refresh"));
    refreshButton->setToolTip(tr("Refresh asset balances"));
    refreshButton->setMaximumWidth(100);
    connect(refreshButton, &QPushButton::clicked, this, &AssetBalanceWidget::onRefreshClicked);
    headerLayout->addWidget(refreshButton);

    // Collapse/expand button
    toggleButton = new QPushButton(tr("Hide"));
    toggleButton->setToolTip(tr("Hide or show asset balance details"));
    toggleButton->setMaximumWidth(100);
    connect(toggleButton, &QPushButton::clicked, this, &AssetBalanceWidget::onToggleCollapsed);
    headerLayout->addWidget(toggleButton);

    mainLayout->addLayout(headerLayout);

    // Create asset table
    assetTable = new QTableWidget(0, 5);
    assetTable->setHorizontalHeaderLabels({
        tr("Ticker/ID"),
        tr("Balance"),
        tr("Pending"),
        tr("Locked"),
        tr("UTXOs")
    });

    // Set table properties
    assetTable->setAlternatingRowColors(true);
    assetTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    assetTable->setSelectionMode(QAbstractItemView::SingleSelection);
    assetTable->horizontalHeader()->setStretchLastSection(true);
    // Make balance column stretch to use available space
    assetTable->horizontalHeader()->setSectionResizeMode(COLUMN_TICKER, QHeaderView::ResizeToContents);
    assetTable->horizontalHeader()->setSectionResizeMode(COLUMN_BALANCE, QHeaderView::Stretch);
    assetTable->horizontalHeader()->setSectionResizeMode(COLUMN_PENDING, QHeaderView::ResizeToContents);
    assetTable->horizontalHeader()->setSectionResizeMode(COLUMN_LOCKED, QHeaderView::ResizeToContents);
    assetTable->horizontalHeader()->setSectionResizeMode(COLUMN_UTXO, QHeaderView::ResizeToContents);
    assetTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    assetTable->setSortingEnabled(true);
    assetTable->verticalHeader()->setVisible(false);
    // Set minimum width to ensure table uses full available space
    assetTable->setMinimumWidth(600);

    // Connect table click and double-click handlers
    connect(assetTable, &QTableWidget::cellClicked, this, &AssetBalanceWidget::onTableItemClicked);
    connect(assetTable, &QTableWidget::cellDoubleClicked, this, &AssetBalanceWidget::onTableItemDoubleClicked);

    // Right-click context menu (e.g. "Reveal DEK" for holder-only assets)
    assetTable->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(assetTable, &QTableWidget::customContextMenuRequested, this, &AssetBalanceWidget::onShowContextMenu);

    // Cap the table at ~5 rows visible so the table can't grow without bound
    // and crowd out the Wallet MTM section below it. Anything beyond 5 rows is
    // reachable via the table's own vertical scrollbar.
    const int kVisibleRows = 5;
    const int rowHeight = assetTable->verticalHeader()->defaultSectionSize();
    const int headerHeight = assetTable->horizontalHeader()->sizeHint().height();
    const int frame = 2 * assetTable->frameWidth();
    const int tableHeight = headerHeight + rowHeight * kVisibleRows + frame;
    // setFixedHeight (not just setMaximumHeight) so the table's sizeHint also
    // collapses — otherwise the parent QFrame keeps reserving the table's
    // default (much larger) sizeHint and we get a huge empty band above it.
    assetTable->setFixedHeight(tableHeight);

    mainLayout->addWidget(assetTable);

    // Create empty state label
    emptyLabel = new QLabel(tr("No assets found in this wallet"));
    emptyLabel->setAlignment(Qt::AlignCenter);
    emptyLabel->setStyleSheet("QLabel { color: gray; padding: 20px; }");
    emptyLabel->hide();

    mainLayout->addWidget(emptyLabel);
}

void AssetBalanceWidget::setWalletModel(WalletModel* model)
{
    walletModel = model;

    if (walletModel) {
        // Connect to asset balance updates
        connect(walletModel, &WalletModel::assetBalancesChanged,
                this, &AssetBalanceWidget::updateAssetBalances);

        // Get initial balances
        refreshBalances();
    }
}

void AssetBalanceWidget::setClientModel(ClientModel* model)
{
    clientModel = model;
}

void AssetBalanceWidget::updateAssetBalances(const std::vector<interfaces::AssetBalance>& balances)
{
    m_cached_balances = balances;

    // Skip update if UI hasn't been initialized yet
    if (!assetTable || !emptyLabel) {
        return;
    }

    // Clear and repopulate table
    clearTable();

    if (balances.empty()) {
        assetTable->hide();
        emptyLabel->show();
        return;
    }

    assetTable->show();
    emptyLabel->hide();

    // Disable sorting while updating to prevent row reordering during population
    assetTable->setSortingEnabled(false);

    assetTable->setRowCount(balances.size());

    for (size_t i = 0; i < balances.size(); ++i) {
        updateTableRow(i, balances[i]);
    }

    // Re-enable sorting after update is complete
    assetTable->setSortingEnabled(true);

    // Resize columns to content
    assetTable->resizeColumnsToContents();
}

void AssetBalanceWidget::updateTableRow(int row, const interfaces::AssetBalance& balance)
{
    // Ticker/ID column
    QString identifier;
    if (!balance.ticker.empty()) {
        identifier = QString::fromStdString(balance.ticker);
    } else {
        identifier = QString::fromStdString(balance.asset_id.ToString()).left(8) + "...";
    }

    QTableWidgetItem* idItem = new QTableWidgetItem(identifier);
    idItem->setToolTip(QString::fromStdString(balance.asset_id.ToString()));
    // Store the actual asset_id in UserRole for reliable access after sorting
    idItem->setData(Qt::UserRole, QString::fromStdString(balance.asset_id.ToString()));
    if (!balance.is_registered) {
        idItem->setForeground(QBrush(COLOR_NEGATIVE));
    }
    assetTable->setItem(row, COLUMN_TICKER, idItem);

    // Balance column
    QString balanceStr = m_privacy
        ? "***"
        : formatAssetUnits(balance.balance, balance.decimals, balance.has_decimals);
    QTableWidgetItem* balanceItem = new QTableWidgetItem(balanceStr);
    balanceItem->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
    assetTable->setItem(row, COLUMN_BALANCE, balanceItem);

    // Pending column
    QString pendingStr = m_privacy
        ? "***"
        : formatAssetUnits(balance.pending, balance.decimals, balance.has_decimals);
    QTableWidgetItem* pendingItem = new QTableWidgetItem(pendingStr);
    pendingItem->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
    if (!m_privacy && balance.pending > 0) {
        pendingItem->setForeground(QBrush(COLOR_UNCONFIRMED));
    }
    assetTable->setItem(row, COLUMN_PENDING, pendingItem);

    // Locked column
    QString lockedStr = m_privacy
        ? "***"
        : formatAssetUnits(balance.locked, balance.decimals, balance.has_decimals);
    QTableWidgetItem* lockedItem = new QTableWidgetItem(lockedStr);
    lockedItem->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
    assetTable->setItem(row, COLUMN_LOCKED, lockedItem);

    // UTXO count column
    QString utxoStr = m_privacy
        ? "***"
        : QString::number(balance.utxo_count);
    QTableWidgetItem* utxoItem = new QTableWidgetItem(utxoStr);
    utxoItem->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
    assetTable->setItem(row, COLUMN_UTXO, utxoItem);

    // Status column removed: registry status is not useful here
}

QString AssetBalanceWidget::formatAssetUnits(uint64_t units, uint8_t decimals, bool has_decimals) const
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

void AssetBalanceWidget::clearTable()
{
    if (assetTable) {
        assetTable->clearContents();
        assetTable->setRowCount(0);
    }
}

void AssetBalanceWidget::setPrivacy(bool privacy)
{
    m_privacy = privacy;
    if (assetTable) {
        updateAssetBalances(m_cached_balances);
    }
}

void AssetBalanceWidget::refreshBalances()
{
    if (walletModel) {
        walletModel->refreshAssetBalances();
    }
}

void AssetBalanceWidget::onToggleCollapsed()
{
    if (!assetTable || !emptyLabel || !toggleButton) {
        return;
    }
    m_collapsed = !m_collapsed;
    assetTable->setVisible(!m_collapsed);
    emptyLabel->setVisible(!m_collapsed && m_cached_balances.empty());
    toggleButton->setText(m_collapsed ? tr("Show") : tr("Hide"));
}

void AssetBalanceWidget::onRefreshClicked()
{
    refreshBalances();
}

void AssetBalanceWidget::onTableItemClicked(int row, int column)
{
    // If clicking on the ID column, copy asset ID to clipboard
    if (column == COLUMN_TICKER && row >= 0) {
        QTableWidgetItem* item = assetTable->item(row, column);
        if (item) {
            // Get the asset ID from the UserRole data (reliable after sorting)
            QString assetId = item->data(Qt::UserRole).toString();
            if (!assetId.isEmpty()) {
                QApplication::clipboard()->setText(assetId);

                // Show tooltip
                item->setToolTip(tr("Asset ID copied to clipboard"));

                Q_EMIT assetClicked(assetId);
            }
        }
    }
}

void AssetBalanceWidget::onTableItemDoubleClicked(int row, int column)
{
    // Double-clicking any cell in a row should navigate to holder view for that asset
    if (row >= 0) {
        QTableWidgetItem* item = assetTable->item(row, COLUMN_TICKER);
        if (item) {
            // Get the asset ID from the UserRole data (reliable after sorting)
            QString assetId = item->data(Qt::UserRole).toString();
            if (!assetId.isEmpty()) {
                Q_EMIT assetDoubleClicked(assetId);
            }
        }
    }
}

void AssetBalanceWidget::onShowContextMenu(const QPoint& pos)
{
    const int row = assetTable->rowAt(pos.y());
    if (row < 0) return;

    QMenu menu(this);
    QAction* revealAction = menu.addAction(tr("Reveal DEK…"));
    QAction* chosen = menu.exec(assetTable->viewport()->mapToGlobal(pos));
    if (chosen == revealAction) {
        revealDekForRow(row);
    }
}

void AssetBalanceWidget::revealDekForRow(int row)
{
    if (!walletModel || row < 0) return;
    QTableWidgetItem* item = assetTable->item(row, COLUMN_TICKER);
    if (!item) return;
    const QString assetIdHex = item->data(Qt::UserRole).toString();
    if (assetIdHex.isEmpty()) return;

    const auto asset_id = uint256::FromHex(assetIdHex.toStdString());
    if (!asset_id) {
        QMessageBox::warning(this, tr("Reveal DEK"), tr("Invalid asset id."));
        return;
    }

    // The DEK decrypts the asset's holder-only ICU document. Sharing it lets
    // anyone read that document — make the user acknowledge before revealing.
    const auto confirm = QMessageBox::warning(
        this, tr("Reveal asset DEK"),
        tr("The Data Encryption Key (DEK) decrypts this asset's confidential ICU "
           "document. Anyone you share it with can read that document.\n\n"
           "Only reveal it if you intend to share access. Continue?"),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
    if (confirm != QMessageBox::Yes) return;

    const std::optional<std::string> dek = walletModel->wallet().getAssetDek(*asset_id);
    if (!dek || dek->empty()) {
        QMessageBox::information(
            this, tr("Reveal DEK"),
            tr("No DEK is held for this asset. The wallet only stores DEKs for "
               "holder-only assets it has received or imported."));
        return;
    }

    const QString dekStr = QString::fromStdString(*dek);
    QMessageBox box(this);
    box.setIcon(QMessageBox::Information);
    box.setWindowTitle(tr("Asset DEK"));
    box.setText(tr("Base64-encoded DEK for this asset:"));
    box.setInformativeText(dekStr);
    box.setTextInteractionFlags(Qt::TextSelectableByMouse);
    QPushButton* copyBtn = box.addButton(tr("Copy to clipboard"), QMessageBox::ActionRole);
    box.addButton(QMessageBox::Close);
    box.exec();
    if (box.clickedButton() == copyBtn) {
        QApplication::clipboard()->setText(dekStr);
    }
}
