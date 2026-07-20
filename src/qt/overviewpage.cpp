// Copyright (c) 2024-2025 The TensorCash Core developers
// Copyright (c) 2011-2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/overviewpage.h>
#include <qt/forms/ui_overviewpage.h>

#include <qt/assetbalancewidget.h>
#include <qt/bitcoinunits.h>
#include <qt/clientmodel.h>
#include <qt/contractregistrymodel.h>
#include <qt/guiconstants.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>
#include <qt/platformstyle.h>
#include <qt/transactionfilterproxy.h>
#include <qt/transactionoverviewwidget.h>
#include <qt/transactiontablemodel.h>
#include <qt/walletmodel.h>

#include <interfaces/node.h>
#include <logging.h>
#include <univalue.h>

#include <QAbstractItemDelegate>
#include <QApplication>
#include <QDateTime>
#include <QElapsedTimer>
#include <QFrame>
#include <QFutureWatcher>
#include <QtConcurrent/QtConcurrent>
#include <QGridLayout>
#include <QListView>
#include <QPainter>
#include <QStatusTipEvent>
#include <QTimer>
#include <QVBoxLayout>

#include <algorithm>
#include <map>

#define DECORATION_SIZE 54
#define NUM_ITEMS 5

Q_DECLARE_METATYPE(interfaces::WalletBalances)

class TxViewDelegate : public QAbstractItemDelegate
{
    Q_OBJECT
public:
    explicit TxViewDelegate(const PlatformStyle* _platformStyle, QObject* parent = nullptr)
        : QAbstractItemDelegate(parent), platformStyle(_platformStyle)
    {
        connect(this, &TxViewDelegate::width_changed, this, &TxViewDelegate::sizeHintChanged);
    }

    inline void paint(QPainter *painter, const QStyleOptionViewItem &option,
                      const QModelIndex &index ) const override
    {
        painter->save();

        QIcon icon = qvariant_cast<QIcon>(index.data(TransactionTableModel::RawDecorationRole));
        QRect mainRect = option.rect;
        QRect decorationRect(mainRect.topLeft(), QSize(DECORATION_SIZE, DECORATION_SIZE));
        int xspace = DECORATION_SIZE + 8;
        int ypad = 6;
        int halfheight = (mainRect.height() - 2*ypad)/2;
        QRect amountRect(mainRect.left() + xspace, mainRect.top()+ypad, mainRect.width() - xspace, halfheight);
        QRect addressRect(mainRect.left() + xspace, mainRect.top()+ypad+halfheight, mainRect.width() - xspace, halfheight);
        icon = platformStyle->SingleColorIcon(icon);
        icon.paint(painter, decorationRect);

        QDateTime date = index.data(TransactionTableModel::DateRole).toDateTime();
        QString address = index.data(Qt::DisplayRole).toString();
        qint64 amount = index.data(TransactionTableModel::AmountRole).toLongLong();
        bool confirmed = index.data(TransactionTableModel::ConfirmedRole).toBool();
        QVariant value = index.data(Qt::ForegroundRole);
        QColor foreground = option.palette.color(QPalette::Text);
        if(value.canConvert<QBrush>())
        {
            QBrush brush = qvariant_cast<QBrush>(value);
            foreground = brush.color();
        }

        if (index.data(TransactionTableModel::WatchonlyRole).toBool()) {
            QIcon iconWatchonly = qvariant_cast<QIcon>(index.data(TransactionTableModel::WatchonlyDecorationRole));
            QRect watchonlyRect(addressRect.left(), addressRect.top(), 16, addressRect.height());
            iconWatchonly = platformStyle->TextColorIcon(iconWatchonly);
            iconWatchonly.paint(painter, watchonlyRect);
            addressRect.setLeft(addressRect.left() + watchonlyRect.width() + 5);
        }

        painter->setPen(foreground);
        QRect boundingRect;
        painter->drawText(addressRect, Qt::AlignLeft | Qt::AlignVCenter, address, &boundingRect);

        if(amount < 0)
        {
            foreground = COLOR_NEGATIVE;
        }
        else if(!confirmed)
        {
            foreground = COLOR_UNCONFIRMED;
        }
        else
        {
            foreground = option.palette.color(QPalette::Text);
        }
        painter->setPen(foreground);

        // Check if this is an asset transaction
        // Get data from the Asset column to check the asset ticker
        QModelIndex assetIndex = index.sibling(index.row(), TransactionTableModel::Asset);
        QString assetTicker = assetIndex.data(Qt::DisplayRole).toString();
        QString amountText;

        if (!assetTicker.isEmpty() && assetTicker != "TSC") {
            // Asset transaction - show asset ticker and amount in same format as TSC
            QModelIndex assetAmountIndex = index.sibling(index.row(), TransactionTableModel::AssetAmount);
            QString assetAmountStr = assetAmountIndex.data(Qt::DisplayRole).toString();
            amountText = QString("%1 %2").arg(assetAmountStr, assetTicker);
        } else {
            // TSC transaction - show TSC amount
            amountText = BitcoinUnits::formatWithUnit(unit, amount, true, BitcoinUnits::SeparatorStyle::ALWAYS);
        }

        if(!confirmed)
        {
            amountText = QString("[") + amountText + QString("]");
        }

        QRect amount_bounding_rect;
        painter->drawText(amountRect, Qt::AlignRight | Qt::AlignVCenter, amountText, &amount_bounding_rect);

        painter->setPen(option.palette.color(QPalette::Text));
        QRect date_bounding_rect;
        painter->drawText(amountRect, Qt::AlignLeft | Qt::AlignVCenter, GUIUtil::dateTimeStr(date), &date_bounding_rect);

        // 0.4*date_bounding_rect.width() is used to visually distinguish a date from an amount.
        const int minimum_width = 1.4 * date_bounding_rect.width() + amount_bounding_rect.width();
        const auto search = m_minimum_width.find(index.row());
        if (search == m_minimum_width.end() || search->second != minimum_width) {
            m_minimum_width[index.row()] = minimum_width;
            Q_EMIT width_changed(index);
        }

        painter->restore();
    }

    inline QSize sizeHint(const QStyleOptionViewItem &option, const QModelIndex &index) const override
    {
        const auto search = m_minimum_width.find(index.row());
        const int minimum_text_width = search == m_minimum_width.end() ? 0 : search->second;
        return {DECORATION_SIZE + 8 + minimum_text_width, DECORATION_SIZE};
    }

    BitcoinUnit unit{BitcoinUnit::BTC};

Q_SIGNALS:
    //! An intermediate signal for emitting from the `paint() const` member function.
    void width_changed(const QModelIndex& index) const;

private:
    const PlatformStyle* platformStyle;
    mutable std::map<int, int> m_minimum_width;
};

#define CONTRACT_DECORATION_SIZE 42
#define NUM_CONTRACTS 5

class ContractOverviewDelegate : public QAbstractItemDelegate
{
    Q_OBJECT
public:
    explicit ContractOverviewDelegate(const PlatformStyle* _platformStyle, QObject* parent = nullptr)
        : QAbstractItemDelegate(parent), platformStyle(_platformStyle)
    {
    }

    inline void paint(QPainter *painter, const QStyleOptionViewItem &option,
                      const QModelIndex &index) const override
    {
        painter->save();

        QRect mainRect = option.rect;
        int xspace = 8;
        int ypad = 4;
        int halfheight = (mainRect.height() - 2*ypad)/2;
        QRect topRect(mainRect.left() + xspace, mainRect.top()+ypad, mainRect.width() - xspace, halfheight);
        QRect bottomRect(mainRect.left() + xspace, mainRect.top()+ypad+halfheight, mainRect.width() - xspace, halfheight);

        // Get contract data
        QString contractType = index.data(ContractRegistryModel::ContractTypeRole).toString();
        QString contractRole = index.data(ContractRegistryModel::ContractRoleRole).toString();
        QString contractStatus = index.data(ContractRegistryModel::ContractStatusRole).toString();
        QString contractId = index.data(ContractRegistryModel::ContractIdRole).toString();

        // Get MTM from display columns
        QModelIndex mtmIndex = index.sibling(index.row(), ContractRegistryModel::MTMMarks);
        QString mtmText = mtmIndex.data(Qt::DisplayRole).toString();

        // Draw type and role on top line
        QString typeRole = contractType.toUpper() + " (" + contractRole + ")";
        painter->setPen(option.palette.color(QPalette::Text));
        painter->drawText(topRect, Qt::AlignLeft | Qt::AlignVCenter, typeRole);

        // Draw status on top right
        QColor statusColor = option.palette.color(QPalette::Text);
        if (contractStatus == "opened") {
            statusColor = QColor(0, 128, 0); // Green
        } else if (contractStatus == "proposed" || contractStatus == "accepted") {
            statusColor = QColor(255, 165, 0); // Orange
        }
        painter->setPen(statusColor);
        painter->drawText(topRect, Qt::AlignRight | Qt::AlignVCenter, contractStatus);

        // Draw contract ID (shortened) on bottom left
        painter->setPen(option.palette.color(QPalette::Text));
        QString shortId = contractId.left(12) + "...";
        painter->drawText(bottomRect, Qt::AlignLeft | Qt::AlignVCenter, shortId);

        // Draw MTM on bottom right with color coding
        if (!mtmText.isEmpty() && mtmText != "N/A") {
            bool ok;
            double mtmValue = mtmText.toDouble(&ok);
            if (ok) {
                if (mtmValue > 0) {
                    painter->setPen(QColor(0, 128, 0)); // Green
                } else if (mtmValue < 0) {
                    painter->setPen(QColor(255, 0, 0)); // Red
                }
            }
            painter->drawText(bottomRect, Qt::AlignRight | Qt::AlignVCenter, mtmText + " TSC");
        }

        painter->restore();
    }

    inline QSize sizeHint(const QStyleOptionViewItem &option, const QModelIndex &index) const override
    {
        Q_UNUSED(option);
        Q_UNUSED(index);
        return {200, CONTRACT_DECORATION_SIZE};
    }

private:
    const PlatformStyle* platformStyle;
};

#include <qt/overviewpage.moc>

OverviewPage::OverviewPage(const PlatformStyle *platformStyle, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::OverviewPage),
    m_platform_style{platformStyle},
    txdelegate(new TxViewDelegate(platformStyle, this)),
    contractDelegate(new ContractOverviewDelegate(platformStyle, this))
{
    ui->setupUi(this);

    // Get reference to the AssetBalanceWidget from the UI file and set platform style
    assetBalanceWidget = ui->assetBalanceWidget;
    assetBalanceWidget->setPlatformStyle(m_platform_style);

    // use a SingleColorIcon for the "out of sync warning" icon
    QIcon icon = m_platform_style->SingleColorIcon(QStringLiteral(":/icons/warning"));
    ui->labelTransactionsStatus->setIcon(icon);
    ui->labelWalletStatus->setIcon(icon);

    // Recent transactions
    ui->listTransactions->setItemDelegate(txdelegate);
    ui->listTransactions->setIconSize(QSize(DECORATION_SIZE, DECORATION_SIZE));
    ui->listTransactions->setMinimumHeight(NUM_ITEMS * (DECORATION_SIZE + 2));
    ui->listTransactions->setAttribute(Qt::WA_MacShowFocusRect, false);

    connect(ui->listTransactions, &TransactionOverviewWidget::clicked, this, &OverviewPage::handleTransactionClicked);

    // Connect asset balance widget double-click signal
    connect(assetBalanceWidget, &AssetBalanceWidget::assetDoubleClicked, this, &OverviewPage::assetDoubleClicked);

    // Set up Wallet MTM section (below asset balances)
    setupWalletMtmSection();

    // Set up Contracts Overview section (below recent transactions)
    setupContractsOverviewSection();

    // Set up MTM refresh timer (every 30 seconds)
    mtmRefreshTimer = new QTimer(this);
    connect(mtmRefreshTimer, &QTimer::timeout, this, &OverviewPage::refreshOverviewPanels);
    mtmRefreshTimer->start(30000); // 30 seconds

    // start with displaying the "out of sync" warnings
    showOutOfSyncWarning(true);
    connect(ui->labelWalletStatus, &QPushButton::clicked, this, &OverviewPage::outOfSyncWarningClicked);
    connect(ui->labelTransactionsStatus, &QPushButton::clicked, this, &OverviewPage::outOfSyncWarningClicked);
}

void OverviewPage::handleTransactionClicked(const QModelIndex &index)
{
    if(filter)
        Q_EMIT transactionClicked(filter->mapToSource(index));
}

void OverviewPage::setPrivacy(bool privacy)
{
    m_privacy = privacy;
    clientModel->getOptionsModel()->setOption(OptionsModel::OptionID::MaskValues, privacy);
    const auto& balances = walletModel->getCachedBalance();
    if (balances.balance != -1) {
        setBalance(balances);
    }

    ui->listTransactions->setVisible(!m_privacy);

    // Apply privacy setting to asset balance widget
    if (assetBalanceWidget) {
        assetBalanceWidget->setPrivacy(privacy);
    }

    // Hide/show Wallet MTM section based on privacy mode
    if (walletMtmFrame) {
        walletMtmFrame->setVisible(!m_privacy);
    }

    // Hide/show Contracts Overview section based on privacy mode
    if (contractsOverviewFrame) {
        contractsOverviewFrame->setVisible(!m_privacy);
    }

    const QString status_tip = m_privacy ? tr("Privacy mode activated for the Overview tab. To unmask the values, uncheck Settings->Mask values.") : "";
    setStatusTip(status_tip);
    QStatusTipEvent event(status_tip);
    QApplication::sendEvent(this, &event);
}

OverviewPage::~OverviewPage()
{
    if (mtmRefreshTimer) {
        mtmRefreshTimer->stop();
    }
    delete ui;
}

void OverviewPage::setBalance(const interfaces::WalletBalances& balances)
{
    BitcoinUnit unit = walletModel->getOptionsModel()->getDisplayUnit();
    ui->labelBalance->setText(BitcoinUnits::formatWithPrivacy(unit, balances.balance, BitcoinUnits::SeparatorStyle::ALWAYS, m_privacy));
    ui->labelUnconfirmed->setText(BitcoinUnits::formatWithPrivacy(unit, balances.unconfirmed_balance, BitcoinUnits::SeparatorStyle::ALWAYS, m_privacy));
    ui->labelImmature->setText(BitcoinUnits::formatWithPrivacy(unit, balances.immature_balance, BitcoinUnits::SeparatorStyle::ALWAYS, m_privacy));
    ui->labelTotal->setText(BitcoinUnits::formatWithPrivacy(unit, balances.balance + balances.unconfirmed_balance + balances.immature_balance + balances.bonded_balance, BitcoinUnits::SeparatorStyle::ALWAYS, m_privacy));
    // only show immature (newly mined) balance if it's non-zero, so as not to complicate things
    // for the non-mining users
    bool showImmature = balances.immature_balance != 0;
    bool showWatchOnlyImmature = balances.immature_watch_only_balance != 0;

    // for symmetry reasons also show immature label when the watch-only one is shown
    ui->labelImmature->setVisible(showImmature || showWatchOnlyImmature);
    ui->labelImmatureText->setVisible(showImmature || showWatchOnlyImmature);
    ui->labelWatchImmature->setVisible(!walletModel->wallet().privateKeysDisabled() && showWatchOnlyImmature); // show watch-only immature balance

    // Update bonded balance display (UI elements added programmatically or via .ui file)
    // For now we'll use dynamic label creation if labels don't exist in .ui
    QLabel* labelBondedText = findChild<QLabel*>("labelBondedText");
    QLabel* labelBonded = findChild<QLabel*>("labelBonded");
    QLabel* labelWatchBonded = findChild<QLabel*>("labelWatchBonded");

    if (!labelBondedText) {
        // Create bonded balance labels dynamically if not in .ui file
        labelBondedText = new QLabel("Bonded:", this);
        labelBondedText->setObjectName("labelBondedText");
        labelBonded = new QLabel(this);
        labelBonded->setObjectName("labelBonded");
        labelBonded->setAlignment(Qt::AlignRight | Qt::AlignTrailing | Qt::AlignVCenter);
        labelBonded->setTextInteractionFlags(Qt::LinksAccessibleByMouse | Qt::TextSelectableByKeyboard | Qt::TextSelectableByMouse);
        labelBonded->setCursor(Qt::IBeamCursor);
        labelBonded->setToolTip("Balance bonded in ICU rotation, repo collateral (as borrower), and forward/option initial margins");
        labelBonded->setFont(ui->labelBalance->font());

        labelWatchBonded = new QLabel(this);
        labelWatchBonded->setObjectName("labelWatchBonded");
        labelWatchBonded->setAlignment(Qt::AlignRight | Qt::AlignTrailing | Qt::AlignVCenter);
        labelWatchBonded->setTextInteractionFlags(Qt::LinksAccessibleByMouse | Qt::TextSelectableByKeyboard | Qt::TextSelectableByMouse);
        labelWatchBonded->setCursor(Qt::IBeamCursor);
        labelWatchBonded->setToolTip("Watch-only balance bonded in ICU, repo collateral, and forward/option margins");
        labelWatchBonded->setFont(ui->labelWatchAvailable->font());

        // Find and move existing widgets to make room
        QWidget* line = ui->gridLayout->itemAtPosition(4, 0)->widget();
        QWidget* lineWatch = ui->gridLayout->itemAtPosition(4, 2)->widget();
        QWidget* totalText = ui->gridLayout->itemAtPosition(5, 0)->widget();
        QWidget* total = ui->gridLayout->itemAtPosition(5, 1)->widget();
        QWidget* totalWatch = ui->gridLayout->itemAtPosition(5, 2)->widget();

        // Remove from old positions
        ui->gridLayout->removeWidget(line);
        ui->gridLayout->removeWidget(lineWatch);
        ui->gridLayout->removeWidget(totalText);
        ui->gridLayout->removeWidget(total);
        ui->gridLayout->removeWidget(totalWatch);

        // Insert bonded row at position 4
        ui->gridLayout->addWidget(labelBondedText, 4, 0);
        ui->gridLayout->addWidget(labelBonded, 4, 1);
        ui->gridLayout->addWidget(labelWatchBonded, 4, 2);

        // Re-add separator and total at new positions (rows 5 and 6)
        ui->gridLayout->addWidget(line, 5, 0, 1, 2);  // colspan=2
        ui->gridLayout->addWidget(lineWatch, 5, 2);
        ui->gridLayout->addWidget(totalText, 6, 0);
        ui->gridLayout->addWidget(total, 6, 1);
        ui->gridLayout->addWidget(totalWatch, 6, 2);
    }

    if (labelBonded) {
        labelBonded->setText(BitcoinUnits::formatWithPrivacy(unit, balances.bonded_balance, BitcoinUnits::SeparatorStyle::ALWAYS, m_privacy));
    }
    if (labelWatchBonded) {
        labelWatchBonded->setText(BitcoinUnits::formatWithPrivacy(unit, balances.watch_only_bonded_balance, BitcoinUnits::SeparatorStyle::ALWAYS, m_privacy));
        labelWatchBonded->setVisible(!walletModel->wallet().privateKeysDisabled() && balances.watch_only_bonded_balance != 0);
    }

    // Show bonded labels only if balance is non-zero
    bool showBonded = balances.bonded_balance != 0;
    bool showWatchOnlyBonded = balances.watch_only_bonded_balance != 0;
    if (labelBondedText) labelBondedText->setVisible(showBonded || showWatchOnlyBonded);
    if (labelBonded) labelBonded->setVisible(showBonded || showWatchOnlyBonded);
}

// show/hide watch-only labels
void OverviewPage::updateWatchOnlyLabels(bool showWatchOnly)
{
    ui->labelSpendable->setVisible(showWatchOnly);      // show spendable label (only when watch-only is active)
    ui->labelWatchonly->setVisible(showWatchOnly);      // show watch-only label
    ui->lineWatchBalance->setVisible(showWatchOnly);    // show watch-only balance separator line
    ui->labelWatchAvailable->setVisible(showWatchOnly); // show watch-only available balance
    ui->labelWatchPending->setVisible(showWatchOnly);   // show watch-only pending balance
    ui->labelWatchTotal->setVisible(showWatchOnly);     // show watch-only total balance

    if (!showWatchOnly)
        ui->labelWatchImmature->hide();
}

void OverviewPage::setClientModel(ClientModel *model)
{
    this->clientModel = model;
    if (model) {
        // Show warning, for example if this is a prerelease version
        connect(model, &ClientModel::alertsChanged, this, &OverviewPage::updateAlerts);
        updateAlerts(model->getStatusBarWarnings());

        connect(model->getOptionsModel(), &OptionsModel::fontForMoneyChanged, this, &OverviewPage::setMonospacedFont);
        setMonospacedFont(clientModel->getOptionsModel()->getFontForMoney());

        // Set client model for asset balance widget
        if (assetBalanceWidget) {
            assetBalanceWidget->setClientModel(model);
        }
    }
}

void OverviewPage::setWalletModel(WalletModel *model)
{
    this->walletModel = model;
    if(model && model->getOptionsModel())
    {
        // Set up transaction list
        filter.reset(new TransactionFilterProxy());
        filter->setSourceModel(model->getTransactionTableModel());
        filter->setDynamicSortFilter(true);
        filter->setSortRole(Qt::EditRole);
        filter->setShowInactive(false);
        filter->sort(TransactionTableModel::Date, Qt::DescendingOrder);

        ui->listTransactions->setModel(filter.get());
        ui->listTransactions->setModelColumn(TransactionTableModel::ToAddress);

        connect(filter.get(), &TransactionFilterProxy::rowsInserted, this, &OverviewPage::LimitTransactionRows);
        connect(filter.get(), &TransactionFilterProxy::rowsRemoved, this, &OverviewPage::LimitTransactionRows);
        connect(filter.get(), &TransactionFilterProxy::rowsMoved, this, &OverviewPage::LimitTransactionRows);
        LimitTransactionRows();
        // Keep up to date with wallet
        setBalance(model->getCachedBalance());
        connect(model, &WalletModel::balanceChanged, this, &OverviewPage::setBalance);

        connect(model->getOptionsModel(), &OptionsModel::displayUnitChanged, this, &OverviewPage::updateDisplayUnit);

        updateWatchOnlyLabels(false);

        // Set wallet model for asset balance widget
        if (assetBalanceWidget) {
            assetBalanceWidget->setWalletModel(model);
        }

        // Set up contracts overview model (only show OPENED contracts)
        contractModel = new ContractRegistryModel(model, this);
        contractModel->setStatusFilter("opened"); // Only show opened contracts in overview
        if (listContracts) {
            listContracts->setModel(contractModel);
            listContracts->setModelColumn(ContractRegistryModel::ContractId);
        }

        // Trigger initial MTM and contracts refresh through the same instrumented path
        refreshOverviewPanels();
    }

    // update the display unit, to not use the default ("TSC")
    updateDisplayUnit();
}

void OverviewPage::changeEvent(QEvent* e)
{
    if (e->type() == QEvent::PaletteChange) {
        QIcon icon = m_platform_style->SingleColorIcon(QStringLiteral(":/icons/warning"));
        ui->labelTransactionsStatus->setIcon(icon);
        ui->labelWalletStatus->setIcon(icon);
    }

    QWidget::changeEvent(e);
}

// Only show most recent NUM_ITEMS rows
void OverviewPage::LimitTransactionRows()
{
    if (filter && ui->listTransactions && ui->listTransactions->model() && filter.get() == ui->listTransactions->model()) {
        for (int i = 0; i < filter->rowCount(); ++i) {
            ui->listTransactions->setRowHidden(i, i >= NUM_ITEMS);
        }
    }
}

void OverviewPage::updateDisplayUnit()
{
    if (walletModel && walletModel->getOptionsModel()) {
        const auto& balances = walletModel->getCachedBalance();
        if (balances.balance != -1) {
            setBalance(balances);
        }

        // Update txdelegate->unit with the current unit
        txdelegate->unit = walletModel->getOptionsModel()->getDisplayUnit();

        ui->listTransactions->update();
    }
}

void OverviewPage::updateAlerts(const QString &warnings)
{
    this->ui->labelAlerts->setVisible(!warnings.isEmpty());
    this->ui->labelAlerts->setText(warnings);
}

void OverviewPage::showOutOfSyncWarning(bool fShow)
{
    ui->labelWalletStatus->setVisible(fShow);
    ui->labelTransactionsStatus->setVisible(fShow);
}

void OverviewPage::setMonospacedFont(const QFont& f)
{
    ui->labelBalance->setFont(f);
    ui->labelUnconfirmed->setFont(f);
    ui->labelImmature->setFont(f);
    ui->labelTotal->setFont(f);
    ui->labelWatchAvailable->setFont(f);
    ui->labelWatchPending->setFont(f);
    ui->labelWatchImmature->setFont(f);
    ui->labelWatchTotal->setFont(f);

    if (QLabel* labelBonded = findChild<QLabel*>("labelBonded")) {
        labelBonded->setFont(f);
    }
    if (QLabel* labelWatchBonded = findChild<QLabel*>("labelWatchBonded")) {
        labelWatchBonded->setFont(f);
    }
}

void OverviewPage::refreshOverviewPanels()
{
    if (!walletModel || m_privacy) {
        return;
    }

    LogPrintf("OverviewPage::refreshOverviewPanels dispatch wallet=%s visible=%d privacy=%d\n",
              walletModel->getWalletName().toStdString().c_str(),
              isVisible(),
              m_privacy);

    // Both halves run async: the MTM fetch on a worker thread, the contracts
    // overview via ContractRegistryModel::refresh() (already off-thread).
    dispatchWalletMtmFetch();
    refreshContractsOverview();
}

void OverviewPage::setupWalletMtmSection()
{
    // Create frame for Wallet MTM section
    walletMtmFrame = new QFrame(this);
    walletMtmFrame->setFrameShape(QFrame::StyledPanel);
    walletMtmFrame->setFrameShadow(QFrame::Raised);

    QVBoxLayout* mtmLayout = new QVBoxLayout(walletMtmFrame);

    // Title
    labelWalletMtmTitle = new QLabel(tr("Wallet Mark to Market"), walletMtmFrame);
    QFont boldFont = labelWalletMtmTitle->font();
    boldFont.setBold(true);
    labelWalletMtmTitle->setFont(boldFont);
    mtmLayout->addWidget(labelWalletMtmTitle);

    // Grid for MTM values
    QGridLayout* mtmGrid = new QGridLayout();
    mtmGrid->setSpacing(12);

    // TSC row
    QLabel* labelTscText = new QLabel(tr("TSC:"), walletMtmFrame);
    labelTscMtm = new QLabel("0.00000000 TSC", walletMtmFrame);
    labelTscMtm->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    labelTscMtm->setCursor(Qt::IBeamCursor);
    labelTscMtm->setTextInteractionFlags(Qt::TextSelectableByMouse);
    labelTscMtm->setToolTip(tr("TSC balance value"));
    mtmGrid->addWidget(labelTscText, 0, 0);
    mtmGrid->addWidget(labelTscMtm, 0, 1);

    // Assets row
    QLabel* labelAssetsText = new QLabel(tr("Assets (FX):"), walletMtmFrame);
    labelAssetMtm = new QLabel("0.00000000 TSC", walletMtmFrame);
    labelAssetMtm->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    labelAssetMtm->setCursor(Qt::IBeamCursor);
    labelAssetMtm->setTextInteractionFlags(Qt::TextSelectableByMouse);
    labelAssetMtm->setToolTip(tr("Asset balances converted to TSC via FX rates"));
    mtmGrid->addWidget(labelAssetsText, 1, 0);
    mtmGrid->addWidget(labelAssetMtm, 1, 1);

    // Contracts MTM row
    QLabel* labelContractsText = new QLabel(tr("Contracts MTM:"), walletMtmFrame);
    labelContractsMtm = new QLabel("0.00000000 TSC", walletMtmFrame);
    labelContractsMtm->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    labelContractsMtm->setCursor(Qt::IBeamCursor);
    labelContractsMtm->setTextInteractionFlags(Qt::TextSelectableByMouse);
    labelContractsMtm->setToolTip(tr("Mark-to-market value of all open contracts"));
    mtmGrid->addWidget(labelContractsText, 2, 0);
    mtmGrid->addWidget(labelContractsMtm, 2, 1);

    // Separator
    QFrame* line = new QFrame(walletMtmFrame);
    line->setFrameShape(QFrame::HLine);
    line->setFrameShadow(QFrame::Sunken);
    mtmGrid->addWidget(line, 3, 0, 1, 2);

    // Total row
    QLabel* labelTotalMtmText = new QLabel(tr("Total:"), walletMtmFrame);
    labelTotalMtmText->setFont(boldFont);
    labelTotalMtm = new QLabel("0.00000000 TSC", walletMtmFrame);
    labelTotalMtm->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    labelTotalMtm->setCursor(Qt::IBeamCursor);
    labelTotalMtm->setTextInteractionFlags(Qt::TextSelectableByMouse);
    labelTotalMtm->setFont(boldFont);
    labelTotalMtm->setToolTip(tr("Total portfolio mark-to-market value in TSC"));
    mtmGrid->addWidget(labelTotalMtmText, 4, 0);
    mtmGrid->addWidget(labelTotalMtm, 4, 1);

    mtmLayout->addLayout(mtmGrid);

    // Insert into the left column layout (verticalLayout_2), after asset balance widget
    // Find the index of assetBalanceWidget and insert after it
    int assetWidgetIndex = ui->verticalLayout_2->indexOf(ui->assetBalanceWidget);
    if (assetWidgetIndex >= 0) {
        // Insert after assetBalanceWidget, before the spacer
        ui->verticalLayout_2->insertWidget(assetWidgetIndex + 1, walletMtmFrame);
    } else {
        // Fallback: insert before the last item (spacer)
        ui->verticalLayout_2->insertWidget(ui->verticalLayout_2->count() - 1, walletMtmFrame);
    }
}

void OverviewPage::setupContractsOverviewSection()
{
    // Create frame for Contracts Overview section
    contractsOverviewFrame = new QFrame(this);
    contractsOverviewFrame->setFrameShape(QFrame::StyledPanel);
    contractsOverviewFrame->setFrameShadow(QFrame::Raised);

    QVBoxLayout* contractsLayout = new QVBoxLayout(contractsOverviewFrame);

    // Title
    labelContractsOverviewTitle = new QLabel(tr("Contracts Overview"), contractsOverviewFrame);
    QFont boldFont = labelContractsOverviewTitle->font();
    boldFont.setBold(true);
    labelContractsOverviewTitle->setFont(boldFont);
    contractsLayout->addWidget(labelContractsOverviewTitle);

    // Contracts list view
    listContracts = new QListView(contractsOverviewFrame);
    listContracts->setItemDelegate(contractDelegate);
    listContracts->setMinimumHeight(NUM_CONTRACTS * (CONTRACT_DECORATION_SIZE + 2));
    listContracts->setAttribute(Qt::WA_MacShowFocusRect, false);
    listContracts->setStyleSheet("QListView { background: transparent; }");
    listContracts->setFrameShape(QFrame::NoFrame);
    listContracts->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    listContracts->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    listContracts->setSelectionMode(QAbstractItemView::NoSelection);
    listContracts->setUniformItemSizes(true);

    connect(listContracts, &QListView::clicked, this, &OverviewPage::handleContractClicked);

    contractsLayout->addWidget(listContracts);

    // Insert into the right column layout (verticalLayout_3), after transactions frame (frame_2)
    // frame_2 contains the Recent transactions section
    int txFrameIndex = ui->verticalLayout_3->indexOf(ui->frame_2);
    if (txFrameIndex >= 0) {
        // Insert after frame_2, before the spacer
        ui->verticalLayout_3->insertWidget(txFrameIndex + 1, contractsOverviewFrame);
    } else {
        // Fallback: insert before the last item (spacer)
        ui->verticalLayout_3->insertWidget(ui->verticalLayout_3->count() - 1, contractsOverviewFrame);
    }
}

void OverviewPage::handleContractClicked(const QModelIndex &index)
{
    if (contractModel) {
        QString contractId = index.data(ContractRegistryModel::ContractIdRole).toString();
        if (!contractId.isEmpty()) {
            Q_EMIT contractClicked(contractId);
        }
    }
}

void OverviewPage::dispatchWalletMtmFetch()
{
    if (!walletModel || m_privacy) return;

    // Coalesce: one fetch in flight at a time. A tick that lands mid-fetch is
    // remembered and re-dispatched by the completion handler, so on a slow
    // network the fetches queue up 1-deep instead of piling on.
    // GUI-thread-only flags (mirrors ContractRegistryModel::refresh()).
    if (m_mtmFetchInFlight) {
        m_mtmFetchPending = true;
        return;
    }
    m_mtmFetchInFlight = true;

    LogPrintf("OverviewPage::refreshWalletMtm dispatch (async) wallet=%s\n",
              walletModel->getWalletName().toStdString().c_str());

    QPointer<OverviewPage> self(this);
    QPointer<WalletModel> wm(walletModel);

    auto* watcher = new QFutureWatcher<WalletMtmSnapshot>(this);
    connect(watcher, &QFutureWatcher<WalletMtmSnapshot>::finished, this,
            [self, wm, watcher]() {
        const WalletMtmSnapshot snap = watcher->result();
        watcher->deleteLater();

        if (!self) {
            return; // page destroyed while the worker ran
        }
        self->m_mtmFetchInFlight = false;

        // Drop results that raced a wallet switch: only render if the wallet
        // this fetch ran against is still the active one.
        if (snap.ok && wm && self->walletModel == wm.data()) {
            self->renderWalletMtm(snap);
        }

        if (self->m_mtmFetchPending) {
            self->m_mtmFetchPending = false;
            self->dispatchWalletMtmFetch();
        }
    });

    // Worker captures only the QPointer<WalletModel> by value and calls the
    // static fetchWalletMtm(), which touches no `this` state — same shutdown
    // contract as ContractRegistryModel::buildSnapshot().
    watcher->setFuture(QtConcurrent::run([wm]() -> WalletMtmSnapshot {
        if (!wm) return {};
        return OverviewPage::fetchWalletMtm(wm.data());
    }));
}

// RUNS ON A WORKER THREAD. Must not touch any OverviewPage state — only the
// passed-in walletModel (node().executeRpc is thread-safe, same as the
// contract.list call in ContractRegistryModel::buildSnapshot()) and locals.
OverviewPage::WalletMtmSnapshot OverviewPage::fetchWalletMtm(WalletModel* wm)
{
    WalletMtmSnapshot snap;
    if (!wm) return snap;

    QElapsedTimer timer;
    timer.start();
    const std::string wallet_name = wm->getWalletName().toStdString();
    LogPrintf("OverviewPage::refreshWalletMtm start wallet=%s\n", wallet_name.c_str());

    try {
        // Call the pricing.portfolio.risk RPC
        UniValue params(UniValue::VARR);
        params.push_back(true); // include_balances

        LogPrintf("OverviewPage::refreshWalletMtm calling pricing.portfolio.risk wallet=%s\n",
                  wallet_name.c_str());

        UniValue result = wm->node().executeRpc("pricing.portfolio.risk", params, wallet_name);

        LogPrintf("OverviewPage::refreshWalletMtm pricing.portfolio.risk returned wallet=%s elapsed_ms=%lld\n",
                  wallet_name.c_str(),
                  timer.elapsed());

        if (result.isObject()) {
            // Parse balance_deltas to get TSC and asset values
            if (result.exists("balance_deltas")) {
                const UniValue& balDeltas = result["balance_deltas"];
                for (const auto& key : balDeltas.getKeys()) {
                    double value = balDeltas[key].get_real();
                    if (key == "TSC") {
                        snap.tscMtm = value;
                    } else {
                        snap.assetMtm += value;
                    }
                }
            }

            // Parse positions to sum contract MTMs
            if (result.exists("positions")) {
                const UniValue& positions = result["positions"];
                for (size_t i = 0; i < positions.size(); ++i) {
                    const UniValue& pos = positions[i];
                    if (pos.exists("mtm")) {
                        snap.contractsMtm += pos["mtm"].get_real();
                    }
                }
            }

            // Get total MTM (which should be sum of all)
            if (result.exists("total_mtm")) {
                snap.totalMtm = result["total_mtm"].get_real();
            }

            snap.ok = true;
        }
    } catch (const UniValue& e) {
        LogPrintf("OverviewPage::refreshWalletMtm RPC error wallet=%s elapsed_ms=%lld error=%s\n",
                  wallet_name.c_str(),
                  timer.elapsed(),
                  GUIUtil::RpcExceptionMessage(e).toStdString());
    } catch (const std::exception& e) {
        LogPrintf("OverviewPage::refreshWalletMtm exception wallet=%s elapsed_ms=%lld error=%s\n",
                  wallet_name.c_str(),
                  timer.elapsed(),
                  e.what());
    } catch (...) {
        LogPrintf("OverviewPage::refreshWalletMtm unknown exception wallet=%s elapsed_ms=%lld\n",
                  wallet_name.c_str(),
                  timer.elapsed());
    }

    LogPrintf("OverviewPage::refreshWalletMtm done wallet=%s elapsed_ms=%lld\n",
              wallet_name.c_str(),
              timer.elapsed());
    return snap;
}

// GUI-thread render half: applies a completed off-thread fetch to the labels.
void OverviewPage::renderWalletMtm(const WalletMtmSnapshot& snap)
{
    if (labelTscMtm) {
        labelTscMtm->setText(QString::number(snap.tscMtm, 'f', 8) + " TSC");
    }
    if (labelAssetMtm) {
        labelAssetMtm->setText(QString::number(snap.assetMtm, 'f', 8) + " TSC");
    }
    if (labelContractsMtm) {
        labelContractsMtm->setText(QString::number(snap.contractsMtm, 'f', 8) + " TSC");
        // Color code contracts MTM
        if (snap.contractsMtm > 0) {
            labelContractsMtm->setStyleSheet("color: green;");
        } else if (snap.contractsMtm < 0) {
            labelContractsMtm->setStyleSheet("color: red;");
        } else {
            labelContractsMtm->setStyleSheet("");
        }
    }
    if (labelTotalMtm) {
        labelTotalMtm->setText(QString::number(snap.totalMtm, 'f', 8) + " TSC");
    }
}

void OverviewPage::refreshContractsOverview()
{
    if (!contractModel || m_privacy) return;

    QElapsedTimer timer;
    timer.start();
    const int rows_before = listContracts && listContracts->model() ? listContracts->model()->rowCount() : -1;
    LogPrintf("OverviewPage::refreshContractsOverview start wallet=%s rows_before=%d\n",
              walletModel ? walletModel->getWalletName().toStdString().c_str() : "",
              rows_before);

    contractModel->refresh();

    // Limit to top NUM_CONTRACTS contracts
    if (listContracts && listContracts->model()) {
        for (int i = 0; i < listContracts->model()->rowCount(); ++i) {
            listContracts->setRowHidden(i, i >= NUM_CONTRACTS);
        }
    }

    const int rows_after = listContracts && listContracts->model() ? listContracts->model()->rowCount() : -1;
    LogPrintf("OverviewPage::refreshContractsOverview done wallet=%s rows_after=%d elapsed_ms=%lld\n",
              walletModel ? walletModel->getWalletName().toStdString().c_str() : "",
              rows_after,
              timer.elapsed());
}
