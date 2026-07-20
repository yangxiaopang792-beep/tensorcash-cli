// Copyright (c) 2024-2025 The TensorCash Core developers
// Copyright (c) 2011-2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/wallet.h>

#include <qt/receivecoinsdialog.h>
#include <qt/forms/ui_receivecoinsdialog.h>

#include <qt/addresstablemodel.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>
#include <qt/platformstyle.h>
#include <qt/receiverequestdialog.h>
#include <qt/recentrequeststablemodel.h>
#include <qt/walletmodel.h>

#include <assets/asset.h>
#include <uint256.h>

#include <QAction>
#include <QComboBox>
#include <QCursor>
#include <QFormLayout>
#include <QMessageBox>
#include <QScrollBar>
#include <QSettings>
#include <QSignalBlocker>
#include <QSortFilterProxyModel>
#include <QTextDocument>
#include <QSet>

#include <limits>

ReceiveCoinsDialog::ReceiveCoinsDialog(const PlatformStyle *_platformStyle, QWidget *parent) :
    QDialog(parent, GUIUtil::dialog_flags),
    ui(new Ui::ReceiveCoinsDialog),
    platformStyle(_platformStyle)
{
    ui->setupUi(this);

    // Get reference to asset combo box from UI form
    assetComboBox = ui->assetComboBox;

    // Connect asset combo box signal
    connect(assetComboBox, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &ReceiveCoinsDialog::on_assetComboBox_currentIndexChanged);

    if (!_platformStyle->getImagesOnButtons()) {
        ui->clearButton->setIcon(QIcon());
        ui->receiveButton->setIcon(QIcon());
        ui->showRequestButton->setIcon(QIcon());
        ui->removeRequestButton->setIcon(QIcon());
    } else {
        ui->clearButton->setIcon(_platformStyle->SingleColorIcon(":/icons/remove"));
        ui->receiveButton->setIcon(_platformStyle->SingleColorIcon(":/icons/receiving_addresses"));
        ui->showRequestButton->setIcon(_platformStyle->SingleColorIcon(":/icons/eye"));
        ui->removeRequestButton->setIcon(_platformStyle->SingleColorIcon(":/icons/remove"));
    }

    // context menu
    contextMenu = new QMenu(this);
    contextMenu->addAction(tr("Copy &URI"), this, &ReceiveCoinsDialog::copyURI);
    contextMenu->addAction(tr("&Copy address"), this, &ReceiveCoinsDialog::copyAddress);
    copyLabelAction = contextMenu->addAction(tr("Copy &label"), this, &ReceiveCoinsDialog::copyLabel);
    copyMessageAction = contextMenu->addAction(tr("Copy &message"), this, &ReceiveCoinsDialog::copyMessage);
    copyAmountAction = contextMenu->addAction(tr("Copy &amount"), this, &ReceiveCoinsDialog::copyAmount);
    connect(ui->recentRequestsView, &QWidget::customContextMenuRequested, this, &ReceiveCoinsDialog::showMenu);

    connect(ui->clearButton, &QPushButton::clicked, this, &ReceiveCoinsDialog::clear);

    QTableView* tableView = ui->recentRequestsView;
    tableView->verticalHeader()->hide();
    tableView->setAlternatingRowColors(true);
    tableView->setSelectionBehavior(QAbstractItemView::SelectRows);
    tableView->setSelectionMode(QAbstractItemView::ContiguousSelection);

    QSettings settings;
    if (!tableView->horizontalHeader()->restoreState(settings.value("RecentRequestsViewHeaderState").toByteArray())) {
        tableView->setColumnWidth(RecentRequestsTableModel::Date, DATE_COLUMN_WIDTH);
        tableView->setColumnWidth(RecentRequestsTableModel::Label, LABEL_COLUMN_WIDTH);
        tableView->setColumnWidth(RecentRequestsTableModel::Amount, AMOUNT_MINIMUM_COLUMN_WIDTH);
        tableView->horizontalHeader()->setMinimumSectionSize(MINIMUM_COLUMN_WIDTH);
        tableView->horizontalHeader()->setStretchLastSection(true);
    }
}

void ReceiveCoinsDialog::setModel(WalletModel *_model)
{
    this->model = _model;

    if(_model && _model->getOptionsModel())
    {
        _model->getRecentRequestsTableModel()->sort(RecentRequestsTableModel::Date, Qt::DescendingOrder);
        connect(_model->getOptionsModel(), &OptionsModel::displayUnitChanged, this, &ReceiveCoinsDialog::updateDisplayUnit);
        updateDisplayUnit();

        // Set up proxy model for filtering
        requestsProxyModel = new QSortFilterProxyModel(this);
        requestsProxyModel->setSourceModel(_model->getRecentRequestsTableModel());
        requestsProxyModel->setFilterKeyColumn(RecentRequestsTableModel::Asset);
        requestsProxyModel->setFilterCaseSensitivity(Qt::CaseInsensitive);

        QTableView* tableView = ui->recentRequestsView;
        tableView->setModel(requestsProxyModel);
        tableView->sortByColumn(RecentRequestsTableModel::Date, Qt::DescendingOrder);

        connect(tableView->selectionModel(),
            &QItemSelectionModel::selectionChanged, this,
            &ReceiveCoinsDialog::recentRequestsView_selectionChanged);

        // Populate address type dropdown and select default
        auto add_address_type = [&](OutputType type, const QString& text, const QString& tooltip) {
            const auto index = ui->addressType->count();
            ui->addressType->addItem(text, (int) type);
            ui->addressType->setItemData(index, tooltip, Qt::ToolTipRole);
            if (model->wallet().getDefaultAddressType() == type) ui->addressType->setCurrentIndex(index);
        };
        add_address_type(OutputType::LEGACY, tr("Base58 (Legacy)"), tr("Not recommended due to higher fees and less protection against typos."));
        add_address_type(OutputType::P2SH_SEGWIT, tr("Base58 (P2SH-SegWit)"), tr("Generates an address compatible with older wallets."));
        add_address_type(OutputType::BECH32, tr("Bech32 (SegWit)"), tr("Generates a native segwit address (BIP-173). Some old wallets don't support it."));
        if (model->wallet().taprootEnabled()) {
            add_address_type(OutputType::BECH32M, tr("Bech32m (Taproot)"), tr("Bech32m (BIP-350) is an upgrade to Bech32, wallet support is still limited."));
        }
        if (model->mldsaEnabled()) {
            add_address_type(OutputType::WITNESS_V2_TAPROOT, tr("Bech32m (Post-Quantum)"),
                tr("Quantum-resistant ML-DSA signatures. WARNING: Transaction fees are ~70x higher. "
                   "Recommended for long-term storage of high-value assets only."));
        }

        // Connect address type change signal
        connect(ui->addressType, QOverload<int>::of(&QComboBox::currentIndexChanged),
                this, &ReceiveCoinsDialog::on_addressType_currentIndexChanged);

        // Create ML-DSA UI elements dynamically (Sprint 2) - only once!
        if (model->mldsaEnabled() && !mldsaSecurityLevelCombo) {
            // Create security level combo box
            mldsaSecurityLevelCombo = new QComboBox(this);
            mldsaSecurityLevelCombo->addItem(tr("Basic (ML-DSA-44)"), 44);
            mldsaSecurityLevelCombo->setItemData(0, tr("Basic quantum resistance (~128-bit). Smaller transaction fees."), Qt::ToolTipRole);
            mldsaSecurityLevelCombo->addItem(tr("Standard (ML-DSA-65, recommended)"), 65);
            mldsaSecurityLevelCombo->setItemData(1, tr("Standard quantum resistance (~192-bit). Good balance of security and size."), Qt::ToolTipRole);
            mldsaSecurityLevelCombo->addItem(tr("High (ML-DSA-87)"), 87);
            mldsaSecurityLevelCombo->setItemData(2, tr("High quantum resistance (~256-bit). Largest transaction fees."), Qt::ToolTipRole);
            mldsaSecurityLevelCombo->setCurrentIndex(1); // Default to ML-DSA-65
            mldsaSecurityLevelCombo->setVisible(false);
            connect(mldsaSecurityLevelCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
                    this, &ReceiveCoinsDialog::on_mldsaSecurityLevel_currentIndexChanged);

            // Create security level label
            QLabel* securityLevelLabel = new QLabel(tr("Security Level:"), this);
            securityLevelLabel->setAlignment(Qt::AlignRight | Qt::AlignTrailing | Qt::AlignVCenter);
            securityLevelLabel->setVisible(false);

            // Create backup warning label
            mldsaWarningLabel = new QLabel(this);
            mldsaWarningLabel->setText(tr("<b>Warning:</b> ML-DSA keys are NOT HD-derived. Back up your wallet after generating!"));
            mldsaWarningLabel->setWordWrap(true);
            mldsaWarningLabel->setStyleSheet("QLabel { color: #856404; background-color: #fff3cd; padding: 8px; border-radius: 4px; }");
            mldsaWarningLabel->setVisible(false);

            // Create security badge label
            mldsaSecurityBadge = new QLabel(this);
            mldsaSecurityBadge->setVisible(false);
            mldsaSecurityBadge->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
            mldsaSecurityBadge->setStyleSheet("QLabel { background-color: #4CAF50; color: white; "
                                             "padding: 4px 8px; border-radius: 3px; font-weight: bold; }");

            // Create fee warning label
            mldsaFeeWarningLabel = new QLabel(this);
            mldsaFeeWarningLabel->setText(tr("⚠ Transaction fees ~70x higher than standard addresses"));
            mldsaFeeWarningLabel->setWordWrap(true);
            mldsaFeeWarningLabel->setStyleSheet("QLabel { color: #FF9800; font-style: italic; padding: 4px; }");
            mldsaFeeWarningLabel->setVisible(false);

            // Find the grid layout in frame2 and add ML-DSA widgets
            QGridLayout* gridLayout = ui->frame2->findChild<QGridLayout*>("gridLayout");
            if (gridLayout) {
                // Get current row count - we'll add after existing rows
                int currentRows = gridLayout->rowCount();

                // Row for security level (label in col 0, combo in col 2)
                gridLayout->addWidget(securityLevelLabel, currentRows, 0, Qt::AlignRight | Qt::AlignTrailing | Qt::AlignVCenter);
                gridLayout->addWidget(mldsaSecurityLevelCombo, currentRows, 2);

                // Row for security badge
                gridLayout->addWidget(mldsaSecurityBadge, currentRows + 1, 2);

                // Row for backup warning
                gridLayout->addWidget(mldsaWarningLabel, currentRows + 2, 2);

                // Row for fee warning
                gridLayout->addWidget(mldsaFeeWarningLabel, currentRows + 3, 2);

                // Store label reference for later hiding/showing
                mldsaSecurityLevelCombo->setProperty("mldsaLabel", QVariant::fromValue<QWidget*>(securityLevelLabel));
            }
        }

        // Set the button to be enabled or disabled based on whether the wallet can give out new addresses.
        ui->receiveButton->setEnabled(model->wallet().canGetAddresses());

        // Enable/disable the receive button if the wallet is now able/unable to give out new addresses.
        connect(model, &WalletModel::canGetAddressesChanged, [this] {
            ui->receiveButton->setEnabled(model->wallet().canGetAddresses());
        });

        // Populate asset combo box
        populateAssetComboBox();

        // Connect to asset balance changes to refresh the dropdown
        connect(model, &WalletModel::assetBalancesChanged,
                this, &ReceiveCoinsDialog::populateAssetComboBox);

        // Set up asset filter combo box
        populateAssetFilterComboBox();
        connect(ui->assetFilterComboBox, QOverload<int>::of(&QComboBox::currentIndexChanged),
                this, &ReceiveCoinsDialog::on_assetFilterComboBox_currentIndexChanged);
    }
}

ReceiveCoinsDialog::~ReceiveCoinsDialog()
{
    QSettings settings;
    settings.setValue("RecentRequestsViewHeaderState", ui->recentRequestsView->horizontalHeader()->saveState());
    delete ui;
}

void ReceiveCoinsDialog::clear()
{
    ui->reqAmount->clear();
    ui->reqLabel->setText("");
    ui->reqMessage->setText("");

    // Reset asset selection to BTC
    if (assetComboBox) {
        assetComboBox->setCurrentIndex(0);
    }

    // Reset amount label to default
    ui->label->setText(tr("&Amount:"));

    updateDisplayUnit();
}

void ReceiveCoinsDialog::reject()
{
    clear();
}

void ReceiveCoinsDialog::accept()
{
    clear();
}

void ReceiveCoinsDialog::updateDisplayUnit()
{
    if(model && model->getOptionsModel())
    {
        // Only update the amount field's display unit if we're in BTC mode
        // Asset mode keeps its own display context
        if (!getSelectedAsset().has_value()) {
            ui->reqAmount->setDisplayUnit(model->getOptionsModel()->getDisplayUnit());
        }
    }
}

void ReceiveCoinsDialog::on_receiveButton_clicked()
{
    if(!model || !model->getOptionsModel() || !model->getAddressTableModel() || !model->getRecentRequestsTableModel())
        return;

    QString address;
    QString label = ui->reqLabel->text();
    /* Generate new receiving address */
    const OutputType address_type = (OutputType)ui->addressType->currentData().toInt();

    // Handle ML-DSA address generation separately
    if (address_type == OutputType::WITNESS_V2_TAPROOT) {
        int level = getSelectedMLDSALevel();
        auto mldsa_info = model->generateMLDSAAddress(level);

        if (!mldsa_info.success) {
            QMessageBox::critical(this, tr("Address Generation Failed"),
                tr("Failed to generate ML-DSA address: %1").arg(mldsa_info.error));
            return;
        }

        address = mldsa_info.address;

        // Show backup warning on first ML-DSA address generation
        showMLDSABackupWarning();

        // Success - create payment request
        SendCoinsRecipient info(address, label,
            ui->reqAmount->value(), ui->reqMessage->text());

        // Continue with asset handling below...
        goto handle_asset_info;
    }

    // Standard address generation (non-ML-DSA)
    address = model->getAddressTableModel()->addRow(AddressTableModel::Receive, label, "", address_type);

    switch(model->getAddressTableModel()->getEditStatus())
    {
    case AddressTableModel::EditStatus::OK: {
        handle_asset_info:
        // Success
        SendCoinsRecipient info(address, label,
            ui->reqAmount->value(), ui->reqMessage->text());

        // Add asset information if an asset is selected
        auto selectedAsset = getSelectedAsset();
        if (selectedAsset.has_value()) {
            // Set asset information for the request
            info.asset_id = *selectedAsset;

            // Get asset ticker for display
            QString assetTicker = assetComboBox->currentText();

            // Extract just the ticker part (before balance in parentheses)
            int parenIndex = assetTicker.indexOf('(');
            if (parenIndex > 0) {
                assetTicker = assetTicker.left(parenIndex).trimmed();
            }

            if (assetTicker != "TSC") {
                info.asset_ticker = assetTicker;
            }

            // Set asset decimals
            info.asset_decimals = getAssetDecimals(*selectedAsset);

            if (info.asset_decimals > 8) {
                QMessageBox::warning(this,
                    tr("Unsupported Asset Precision"),
                    tr("Receiving assets with more than 8 decimal places is not supported in this version."));
                return;
            }

            // Convert amount to asset units based on decimals
            // The BitcoinAmountField gives us the value in satoshis (10^8 units)
            // We need to interpret this as the user entering in asset units
            CAmount enteredAmount = ui->reqAmount->value();  // This is in satoshis (10^8)

            if (enteredAmount > 0) {
                // The user entered a value thinking in asset units with asset decimals
                // We received it as if it were BTC (8 decimals)
                // We need to convert from 8-decimal representation to asset-decimal representation

                if (info.asset_decimals <= 8) {
                    // Asset has fewer or equal decimals than the UI supports
                    // Divide to remove extra precision
                    uint64_t divisor = 1;
                    for (uint8_t i = 0; i < (8 - info.asset_decimals); ++i) {
                        divisor *= 10;
                    }
                    info.asset_units = static_cast<uint64_t>(enteredAmount / divisor);
                } else {
                    // Asset has more decimals than the UI supports (>8)
                    // We can only capture up to 8 decimal places from the UI
                    // Need to add zeros for the missing precision
                    uint64_t multiplier = 1;
                    for (uint8_t i = 0; i < (info.asset_decimals - 8); ++i) {
                        multiplier *= 10;
                    }

                    // Check for overflow before multiplication
                    if (enteredAmount > 0 &&
                        static_cast<uint64_t>(enteredAmount) > (std::numeric_limits<uint64_t>::max() / multiplier)) {
                        // Amount too large, warn user
                        QMessageBox::warning(this, tr("Amount Too Large"),
                            tr("The requested amount is too large for this asset."));
                        return;
                    }

                    info.asset_units = static_cast<uint64_t>(enteredAmount) * multiplier;
                }

            } else {
                info.asset_units = 0;
                info.amount = 0;
            }

            info.asset_amount_string = GUIUtil::formatAssetAmount(info.asset_units, info.asset_decimals);
            info.amount = 0; // ensure BTC field is not used for assets
        }

        // Own the request window from the top-level wallet window, not the
        // embedded receive page. This avoids Windows focus/activation issues
        // when closing a non-modal dialog spawned from a page hosted inside a
        // stacked widget.
        ReceiveRequestDialog *dialog = new ReceiveRequestDialog(window());
        dialog->setAttribute(Qt::WA_DeleteOnClose);
        dialog->setWindowModality(Qt::NonModal);
        dialog->setModel(model);
        dialog->setInfo(info);
        dialog->show();

        /* Store request for later reference */
        model->getRecentRequestsTableModel()->addNewRequest(info);
        break;
    }
    case AddressTableModel::EditStatus::WALLET_UNLOCK_FAILURE:
        QMessageBox::critical(this, windowTitle(),
            tr("Could not unlock wallet."),
            QMessageBox::Ok, QMessageBox::Ok);
        break;
    case AddressTableModel::EditStatus::KEY_GENERATION_FAILURE:
        QMessageBox::critical(this, windowTitle(),
            tr("Could not generate new %1 address").arg(QString::fromStdString(FormatOutputType(address_type))),
            QMessageBox::Ok, QMessageBox::Ok);
        break;
    // These aren't valid return values for our action
    case AddressTableModel::EditStatus::INVALID_ADDRESS:
    case AddressTableModel::EditStatus::DUPLICATE_ADDRESS:
    case AddressTableModel::EditStatus::NO_CHANGES:
        assert(false);
    }
    clear();
}

void ReceiveCoinsDialog::on_recentRequestsView_doubleClicked(const QModelIndex &index)
{
    const RecentRequestsTableModel *submodel = model->getRecentRequestsTableModel();

    // Map proxy index to source model index
    QModelIndex sourceIndex = index;
    if (requestsProxyModel) {
        sourceIndex = requestsProxyModel->mapToSource(index);
    }

    ReceiveRequestDialog *dialog = new ReceiveRequestDialog(window());
    dialog->setModel(model);
    dialog->setInfo(submodel->entry(sourceIndex.row()).recipient);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->setWindowModality(Qt::NonModal);
    dialog->show();
}

void ReceiveCoinsDialog::recentRequestsView_selectionChanged(const QItemSelection &selected, const QItemSelection &deselected)
{
    // Enable Show/Remove buttons only if anything is selected.
    bool enable = !ui->recentRequestsView->selectionModel()->selectedRows().isEmpty();
    ui->showRequestButton->setEnabled(enable);
    ui->removeRequestButton->setEnabled(enable);
}

void ReceiveCoinsDialog::on_showRequestButton_clicked()
{
    if(!model || !model->getRecentRequestsTableModel() || !ui->recentRequestsView->selectionModel())
        return;
    QModelIndexList selection = ui->recentRequestsView->selectionModel()->selectedRows();

    for (const QModelIndex& index : selection) {
        on_recentRequestsView_doubleClicked(index);
    }
}

void ReceiveCoinsDialog::on_removeRequestButton_clicked()
{
    if(!model || !model->getRecentRequestsTableModel() || !ui->recentRequestsView->selectionModel())
        return;
    QModelIndexList selection = ui->recentRequestsView->selectionModel()->selectedRows();
    if(selection.empty())
        return;

    // Map proxy indices to source model indices
    QModelIndexList sourceSelection;
    if (requestsProxyModel) {
        for (const QModelIndex& proxyIndex : selection) {
            sourceSelection.append(requestsProxyModel->mapToSource(proxyIndex));
        }
    } else {
        sourceSelection = selection;
    }

    // correct for selection mode ContiguousSelection
    QModelIndex firstIndex = sourceSelection.at(0);
    model->getRecentRequestsTableModel()->removeRows(firstIndex.row(), sourceSelection.length(), firstIndex.parent());
}

QModelIndex ReceiveCoinsDialog::selectedRow()
{
    if(!model || !model->getRecentRequestsTableModel() || !ui->recentRequestsView->selectionModel())
        return QModelIndex();
    QModelIndexList selection = ui->recentRequestsView->selectionModel()->selectedRows();
    if(selection.empty())
        return QModelIndex();
    // correct for selection mode ContiguousSelection
    QModelIndex firstIndex = selection.at(0);
    return firstIndex;
}

// copy column of selected row to clipboard
void ReceiveCoinsDialog::copyColumnToClipboard(int column)
{
    QModelIndex firstIndex = selectedRow();
    if (!firstIndex.isValid()) {
        return;
    }

    // Map proxy index to source model index
    QModelIndex sourceIndex = firstIndex;
    if (requestsProxyModel) {
        sourceIndex = requestsProxyModel->mapToSource(firstIndex);
    }

    GUIUtil::setClipboard(model->getRecentRequestsTableModel()->index(sourceIndex.row(), column).data(Qt::EditRole).toString());
}

// context menu
void ReceiveCoinsDialog::showMenu(const QPoint &point)
{
    const QModelIndex sel = selectedRow();
    if (!sel.isValid()) {
        return;
    }

    // Map proxy index to source model index
    QModelIndex sourceIndex = sel;
    if (requestsProxyModel) {
        sourceIndex = requestsProxyModel->mapToSource(sel);
    }

    // disable context menu actions when appropriate
    const RecentRequestsTableModel* const submodel = model->getRecentRequestsTableModel();
    const RecentRequestEntry& req = submodel->entry(sourceIndex.row());
    copyLabelAction->setDisabled(req.recipient.label.isEmpty());
    copyMessageAction->setDisabled(req.recipient.message.isEmpty());

    // For assets, check asset_units instead of amount
    if (req.recipient.asset_id.has_value()) {
        copyAmountAction->setDisabled(req.recipient.asset_units == 0);
    } else {
        copyAmountAction->setDisabled(req.recipient.amount == 0);
    }

    contextMenu->exec(QCursor::pos());
}

// context menu action: copy URI
void ReceiveCoinsDialog::copyURI()
{
    QModelIndex sel = selectedRow();
    if (!sel.isValid()) {
        return;
    }

    // Map proxy index to source model index
    QModelIndex sourceIndex = sel;
    if (requestsProxyModel) {
        sourceIndex = requestsProxyModel->mapToSource(sel);
    }

    const RecentRequestsTableModel * const submodel = model->getRecentRequestsTableModel();
    const QString uri = GUIUtil::formatBitcoinURI(submodel->entry(sourceIndex.row()).recipient);
    GUIUtil::setClipboard(uri);
}

// context menu action: copy address
void ReceiveCoinsDialog::copyAddress()
{
    const QModelIndex sel = selectedRow();
    if (!sel.isValid()) {
        return;
    }

    // Map proxy index to source model index
    QModelIndex sourceIndex = sel;
    if (requestsProxyModel) {
        sourceIndex = requestsProxyModel->mapToSource(sel);
    }

    const RecentRequestsTableModel* const submodel = model->getRecentRequestsTableModel();
    const QString address = submodel->entry(sourceIndex.row()).recipient.address;
    GUIUtil::setClipboard(address);
}

// context menu action: copy label
void ReceiveCoinsDialog::copyLabel()
{
    copyColumnToClipboard(RecentRequestsTableModel::Label);
}

// context menu action: copy message
void ReceiveCoinsDialog::copyMessage()
{
    copyColumnToClipboard(RecentRequestsTableModel::Message);
}

// context menu action: copy amount
void ReceiveCoinsDialog::copyAmount()
{
    QModelIndex firstIndex = selectedRow();
    if (!firstIndex.isValid()) {
        return;
    }

    // Map proxy index to source model index
    QModelIndex sourceIndex = firstIndex;
    if (requestsProxyModel) {
        sourceIndex = requestsProxyModel->mapToSource(firstIndex);
    }

    const RecentRequestsTableModel* submodel = model->getRecentRequestsTableModel();
    const RecentRequestEntry& entry = submodel->entry(sourceIndex.row());

    QString amountText;
    if (entry.recipient.asset_id.has_value()) {
        // For assets, include the ticker with the amount
        QString amount = model->getRecentRequestsTableModel()->index(sourceIndex.row(), RecentRequestsTableModel::Amount).data(Qt::EditRole).toString();
        QString ticker = entry.recipient.asset_ticker;
        if (ticker.isEmpty()) {
            ticker = QString::fromStdString(entry.recipient.asset_id->ToString().substr(0, 8)) + "...";
        }
        amountText = amount + " " + ticker;
    } else {
        // For BTC, use the standard format
        amountText = model->getRecentRequestsTableModel()->index(sourceIndex.row(), RecentRequestsTableModel::Amount).data(Qt::EditRole).toString();
    }

    GUIUtil::setClipboard(amountText);
}

// Asset-related method implementations
void ReceiveCoinsDialog::populateAssetComboBox()
{
    if (!assetComboBox || !model) {
        return;
    }

    // Save current selection
    QVariant currentData = assetComboBox->currentData();
    QString currentText = assetComboBox->currentText();

    assetComboBox->clear();
    assetComboBox->addItem("TSC", QVariant());

    // Get asset balances from wallet
    auto balances = model->wallet().getAssetBalances();
    for (const auto& balance : balances) {
        // Show all known assets, not just those with positive balance
        // This allows users to request payments for zero-balance assets
        QString ticker = !balance.ticker.empty() ?
            QString::fromStdString(balance.ticker) :
            QString::fromStdString(balance.asset_id.ToString().substr(0, 8));

        // Add balance info to the display text if non-zero
        QString displayText = ticker;
        if (balance.balance > 0) {
            const QString balanceStr = GUIUtil::formatAssetAmount(balance.balance, balance.decimals);
            displayText = QString("%1 (%2)").arg(ticker, balanceStr);
        }

        if (!balance.is_registered) {
            displayText = QStringLiteral("⚠ %1").arg(displayText);
        }

        const QString assetId = QString::fromStdString(balance.asset_id.ToString());
        assetComboBox->addItem(displayText, assetId);
        int idx = assetComboBox->count() - 1;
        if (!balance.is_registered) {
            assetComboBox->setItemData(idx,
                tr("Registry entry missing for %1 (%2)").arg(ticker, assetId),
                Qt::ToolTipRole);
        }
    }

    // Restore selection if it still exists
    int index = assetComboBox->findData(currentData);
    if (index >= 0) {
        assetComboBox->setCurrentIndex(index);
    } else if (!currentText.isEmpty()) {
        // Try to find by text prefix (in case balance changed)
        for (int i = 0; i < assetComboBox->count(); ++i) {
            if (assetComboBox->itemText(i).startsWith(currentText)) {
                assetComboBox->setCurrentIndex(i);
                break;
            }
        }
    }

    populateAssetFilterComboBox();
}

void ReceiveCoinsDialog::updateAssetSelection()
{
    if (!model) return;

    // Clear amount when asset changes to avoid confusion
    ui->reqAmount->clear();

    // Update amount label and tooltip based on selected asset
    auto selectedAsset = getSelectedAsset();
    if (selectedAsset.has_value()) {
        uint8_t decimals = getAssetDecimals(*selectedAsset);
        if (decimals > 8) {
            QSignalBlocker blocker(assetComboBox);
            assetComboBox->setCurrentIndex(0);
            QMessageBox::warning(this,
                tr("Unsupported Asset Precision"),
                tr("Receiving assets with more than 8 decimal places is not supported in this version."));

            ui->label->setText(tr("&Amount:"));
            ui->label->setToolTip(tr("An optional amount to request. Leave this empty or zero to not request a specific amount."));
            ui->reqAmount->setToolTip(tr("An optional amount to request. Leave this empty or zero to not request a specific amount."));
            return;
        }

        // Get asset ticker for display
        QString ticker = assetComboBox->currentText();

        // Extract just the ticker part (before balance in parentheses)
        int parenIndex = ticker.indexOf('(');
        if (parenIndex > 0) {
            ticker = ticker.left(parenIndex).trimmed();
        }

        if (ticker != "TSC" && !ticker.isEmpty()) {
            ui->label->setText(QString("&Amount (%1):").arg(ticker));

            QString tooltip = QString("Enter amount in %1 units. This asset has %2 decimal places.")
                                .arg(ticker)
                                .arg(decimals);
            ui->label->setToolTip(tooltip);
            ui->reqAmount->setToolTip(tooltip);
        }
    } else {
        // BTC selected - restore default label
        ui->label->setText(tr("&Amount:"));
        ui->label->setToolTip(tr("An optional amount to request. Leave this empty or zero to not request a specific amount."));
        ui->reqAmount->setToolTip(tr("An optional amount to request. Leave this empty or zero to not request a specific amount."));
    }

    // Update the unit label
    updateAssetUnitLabel();

    // The BitcoinAmountField always works with 8 decimal places
    // We'll interpret the value based on the selected asset when creating the request
}

std::optional<uint256> ReceiveCoinsDialog::getSelectedAsset() const
{
    if (!assetComboBox) {
        return std::nullopt;
    }

    QVariant data = assetComboBox->currentData();
    if (!data.isValid() || data.isNull()) {
        return std::nullopt;  // BTC selected
    }

    QString assetIdStr = data.toString();
    if (assetIdStr.isEmpty()) {
        return std::nullopt;
    }

    auto assetId = uint256::FromHex(assetIdStr.toStdString());
    return assetId;
}

uint8_t ReceiveCoinsDialog::getAssetDecimals(const uint256& assetId) const
{
    if (!model) {
        return 8;  // Default to 8 decimals
    }

    // Get asset metadata to determine decimal places
    auto balances = model->wallet().getAssetBalances();
    for (const auto& balance : balances) {
        if (balance.asset_id == assetId) {
            return balance.decimals;
        }
    }

    return 8;  // Default to 8 decimals if not found
}

void ReceiveCoinsDialog::on_assetComboBox_currentIndexChanged(int index)
{
    Q_UNUSED(index);
    updateAssetSelection();
}

void ReceiveCoinsDialog::populateAssetFilterComboBox()
{
    if (!ui->assetFilterComboBox || !model) {
        return;
    }

    QVariant currentData = ui->assetFilterComboBox->currentData();

    ui->assetFilterComboBox->clear();
    ui->assetFilterComboBox->addItem(tr("All"), QString());

    // Add TSC as an option
    ui->assetFilterComboBox->addItem("TSC", QStringLiteral("TSC"));

    QSet<QString> seen;
    seen.insert(QStringLiteral("TSC"));

    // Add all known assets to the filter
    const auto balances = model->wallet().getAssetBalances();
    for (const auto& balance : balances) {
        QString ticker = !balance.ticker.empty() ?
            QString::fromStdString(balance.ticker) :
            QString::fromStdString(balance.asset_id.ToString().substr(0, 8));

        if (seen.contains(ticker)) {
            continue;
        }
        ui->assetFilterComboBox->addItem(ticker, ticker);
        seen.insert(ticker);
    }

    int restoreIndex = ui->assetFilterComboBox->findData(currentData);
    if (restoreIndex >= 0) {
        ui->assetFilterComboBox->setCurrentIndex(restoreIndex);
    }
}

void ReceiveCoinsDialog::on_assetFilterComboBox_currentIndexChanged(int index)
{
    Q_UNUSED(index);
    if (!requestsProxyModel) {
        return;
    }

    QString filterText = ui->assetFilterComboBox->currentData().toString();
    if (filterText.isEmpty()) {
        // Show all requests
        requestsProxyModel->setFilterFixedString("");
    } else {
        // Filter by specific asset
        requestsProxyModel->setFilterFixedString(filterText);
    }
}

void ReceiveCoinsDialog::updateAssetUnitLabel()
{
    if (!ui->reqAmount) return;

    auto selected_asset = getSelectedAsset();
    if (selected_asset.has_value() && assetComboBox) {
        // Get the asset ticker from combo box
        QString ticker = assetComboBox->currentText();

        // Extract just the ticker part (before balance in parentheses)
        int parenIndex = ticker.indexOf('(');
        if (parenIndex > 0) {
            ticker = ticker.left(parenIndex).trimmed();
        }

        if (ticker != "TSC" && !ticker.isEmpty()) {
            // Asset selected - hide TSC unit dropdown since asset units are fixed
            ui->reqAmount->setUnitVisible(false);
            return;
        }
    }

    // TSC selected - show TSC unit dropdown
    ui->reqAmount->setUnitVisible(true);
}

// ML-DSA (Post-Quantum) Methods Implementation

void ReceiveCoinsDialog::on_addressType_currentIndexChanged(int index)
{
    if (!model) return;

    OutputType type = static_cast<OutputType>(ui->addressType->currentData().toInt());
    updateMLDSAUIVisibility();

    // Update security badge when address type or security level changes
    if (type == OutputType::WITNESS_V2_TAPROOT && mldsaSecurityBadge) {
        int level = getSelectedMLDSALevel();
        QString badgeText = QString("Post-Quantum (ML-DSA-%1)").arg(level);
        mldsaSecurityBadge->setText(badgeText);
    }
}

void ReceiveCoinsDialog::on_mldsaSecurityLevel_currentIndexChanged(int index)
{
    if (!model || !mldsaSecurityBadge) return;

    OutputType type = static_cast<OutputType>(ui->addressType->currentData().toInt());
    if (type == OutputType::WITNESS_V2_TAPROOT) {
        int level = getSelectedMLDSALevel();
        QString badgeText = QString("Post-Quantum (ML-DSA-%1)").arg(level);
        mldsaSecurityBadge->setText(badgeText);
    }
}

void ReceiveCoinsDialog::updateMLDSAUIVisibility()
{
    if (!model) return;

    OutputType type = static_cast<OutputType>(ui->addressType->currentData().toInt());
    bool is_mldsa = (type == OutputType::WITNESS_V2_TAPROOT);

    // Show/hide ML-DSA specific UI elements
    if (mldsaSecurityLevelCombo) {
        mldsaSecurityLevelCombo->setVisible(is_mldsa);
        // Also show/hide the associated label
        QWidget* label = mldsaSecurityLevelCombo->property("mldsaLabel").value<QWidget*>();
        if (label) {
            label->setVisible(is_mldsa);
        }
    }
    if (mldsaWarningLabel) {
        mldsaWarningLabel->setVisible(is_mldsa);
    }
    if (mldsaFeeWarningLabel) {
        mldsaFeeWarningLabel->setVisible(is_mldsa);
    }
    if (mldsaSecurityBadge) {
        if (is_mldsa) {
            int level = getSelectedMLDSALevel();
            QString badgeText = QString("Post-Quantum (ML-DSA-%1)").arg(level);
            mldsaSecurityBadge->setText(badgeText);
            mldsaSecurityBadge->setVisible(true);
        } else {
            mldsaSecurityBadge->setVisible(false);
        }
    }
}

int ReceiveCoinsDialog::getSelectedMLDSALevel() const
{
    if (!mldsaSecurityLevelCombo) {
        return 65; // Default to ML-DSA-65
    }
    return mldsaSecurityLevelCombo->currentData().toInt();
}

void ReceiveCoinsDialog::showMLDSABackupWarning()
{
    if (!model) return;

    QSettings settings;
    if (settings.contains("mldsa_backup_warning_shown")) {
        // User has already seen the warning
        return;
    }

    // Show comprehensive backup warning dialog
    QMessageBox msgBox(this);
    msgBox.setWindowTitle(tr("Backup Required"));
    msgBox.setIcon(QMessageBox::Warning);
    msgBox.setText(tr("<b>ML-DSA addresses require wallet backup</b>"));
    msgBox.setInformativeText(
        tr("ML-DSA (Post-Quantum) keys are NOT derived from your HD seed.\n\n"
           "You MUST back up your wallet file to preserve these keys!\n\n"
           "Losing your wallet file will result in PERMANENT LOSS of funds "
           "sent to this address.\n\n"
           "Important:\n"
           "• Back up your wallet: File > Backup Wallet\n"
           "• Store backup in a secure location\n"
           "• Do NOT reuse ML-DSA addresses (each signature leaks key information)\n\n"
           "Would you like to back up your wallet now?")
    );

    QPushButton* backupButton = msgBox.addButton(tr("Backup Now"), QMessageBox::AcceptRole);
    QPushButton* laterButton = msgBox.addButton(tr("Remind Me Later"), QMessageBox::RejectRole);
    QPushButton* dontAskButton = msgBox.addButton(tr("Don't Ask Again"), QMessageBox::DestructiveRole);
    msgBox.setDefaultButton(backupButton);

    msgBox.exec();

    if (msgBox.clickedButton() == backupButton) {
        // Trigger backup wallet action
        // Note: The actual backup functionality would need to be triggered here
        // via the main window. We just set the preference for now.
        QMessageBox::information(this, tr("Backup Wallet"),
                                tr("Please use File > Backup Wallet to save your wallet backup to a secure location."));
        settings.setValue("mldsa_backup_warning_shown", true);
    } else if (msgBox.clickedButton() == dontAskButton) {
        settings.setValue("mldsa_backup_warning_shown", true);
    }
    // If "Remind Me Later" was clicked, don't set the preference
    Q_UNUSED(laterButton);
}
