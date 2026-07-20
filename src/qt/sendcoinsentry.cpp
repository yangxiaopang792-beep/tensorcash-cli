// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/sendcoinsentry.h>
#include <qt/forms/ui_sendcoinsentry.h>

#include <qt/addressbookpage.h>
#include <qt/addresstablemodel.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>
#include <qt/platformstyle.h>
#include <qt/walletmodel.h>

#include <addresstype.h>
#include <key_io.h>

#include <QApplication>
#include <QClipboard>
#include <QComboBox>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QSignalBlocker>
#include <limits>

SendCoinsEntry::SendCoinsEntry(const PlatformStyle *_platformStyle, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::SendCoinsEntry),
    platformStyle(_platformStyle)
{
    ui->setupUi(this);

    ui->addressBookButton->setIcon(platformStyle->SingleColorIcon(":/icons/address-book"));
    ui->pasteButton->setIcon(platformStyle->SingleColorIcon(":/icons/editpaste"));
    ui->deleteButton->setIcon(platformStyle->SingleColorIcon(":/icons/remove"));

    if (platformStyle->getUseExtraSpacing())
        ui->payToLayout->setSpacing(4);

    GUIUtil::setupAddressWidget(ui->payTo, this);

    // Create asset dropdown
    assetComboBox = new QComboBox(this);
    assetComboBox->setToolTip(tr("Select the asset to send (TSC or other assets)"));
    assetComboBox->setMinimumWidth(150);
    assetComboBox->setMaximumWidth(200);

    // Insert the asset dropdown before the amount field
    // Try multiple methods to ensure it's added to the UI
    bool dropdownAdded = false;

    // Method 1: Try the direct parent of payAmount
    QWidget* amountParent = ui->payAmount->parentWidget();
    if (amountParent) {
        QHBoxLayout* parentLayout = qobject_cast<QHBoxLayout*>(amountParent->layout());
        if (parentLayout) {
            parentLayout->insertWidget(0, assetComboBox);
            parentLayout->insertSpacing(1, 10);
            dropdownAdded = true;
        }
    }

    // Method 2: If that didn't work, try finding the grid and adding next to amount label
    if (!dropdownAdded) {
        QGridLayout* gridLayout = this->findChild<QGridLayout*>("gridLayout");
        if (gridLayout) {
            // Create a new horizontal layout for the amount row
            QHBoxLayout* newAmountLayout = new QHBoxLayout();
            newAmountLayout->addWidget(assetComboBox);
            newAmountLayout->addWidget(ui->payAmount);
            if (ui->useAvailableBalanceButton) {
                newAmountLayout->addWidget(ui->useAvailableBalanceButton);
            }
            if (ui->checkboxSubtractFeeFromAmount) {
                newAmountLayout->addWidget(ui->checkboxSubtractFeeFromAmount);
            }
            newAmountLayout->addStretch();

            // Try to replace what's at row 2, column 1
            QLayoutItem* oldItem = gridLayout->itemAtPosition(2, 1);
            if (oldItem) {
                gridLayout->removeItem(oldItem);
                delete oldItem;
            }
            gridLayout->addLayout(newAmountLayout, 2, 1);
            dropdownAdded = true;
        }
    }

    // Method 3: Last resort - add to payToLayout so it's at least visible
    if (!dropdownAdded && ui->payToLayout) {
        ui->payToLayout->insertWidget(0, assetComboBox);
        dropdownAdded = true;
    }

    // Create ML-DSA warning labels
    mldsaFeeWarningLabel = new QLabel(this);
    mldsaFeeWarningLabel->setWordWrap(true);
    mldsaFeeWarningLabel->setStyleSheet("QLabel { background-color: #fff3cd; color: #856404; padding: 8px; border-radius: 4px; }");
    mldsaFeeWarningLabel->hide();

    mldsaAddressTypeBadge = new QLabel(this);
    mldsaAddressTypeBadge->setStyleSheet("QLabel { background-color: #4CAF50; color: white; padding: 4px 8px; border-radius: 3px; font-weight: bold; }");
    mldsaAddressTypeBadge->setText(tr("Post-Quantum Address"));
    mldsaAddressTypeBadge->hide();

    // Find the main grid layout and add warning labels below the payTo row
    QGridLayout* gridLayout = this->findChild<QGridLayout*>("gridLayout");
    if (gridLayout) {
        // Get the current row count to know where to add new rows
        int currentRows = gridLayout->rowCount();

        // Add the address type badge in a new row spanning both columns
        gridLayout->addWidget(mldsaAddressTypeBadge, currentRows, 0, 1, 2, Qt::AlignLeft);

        // Add the fee warning label in the next row spanning both columns
        gridLayout->addWidget(mldsaFeeWarningLabel, currentRows + 1, 0, 1, 2);
    }

    // Connect signals
    connect(ui->payAmount, &BitcoinAmountField::valueChanged, this, &SendCoinsEntry::payAmountChanged);
    connect(ui->checkboxSubtractFeeFromAmount, &QCheckBox::toggled, this, &SendCoinsEntry::subtractFeeFromAmountChanged);
    connect(ui->deleteButton, &QPushButton::clicked, this, &SendCoinsEntry::deleteClicked);
    connect(ui->useAvailableBalanceButton, &QPushButton::clicked, this, &SendCoinsEntry::useAvailableBalanceClicked);
    connect(assetComboBox, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &SendCoinsEntry::on_assetComboBox_currentIndexChanged);

    // Initialize with TSC as default
    assetComboBox->addItem(tr("TSC (TensorCash)"), QVariant());
}

SendCoinsEntry::~SendCoinsEntry()
{
    delete ui;
}

void SendCoinsEntry::on_pasteButton_clicked()
{
    // Paste text from clipboard into recipient field
    ui->payTo->setText(QApplication::clipboard()->text());
}

void SendCoinsEntry::on_addressBookButton_clicked()
{
    if(!model)
        return;
    AddressBookPage dlg(platformStyle, AddressBookPage::ForSelection, AddressBookPage::SendingTab, this);
    dlg.setModel(model->getAddressTableModel());
    if(dlg.exec())
    {
        ui->payTo->setText(dlg.getReturnValue());
        ui->payAmount->setFocus();
    }
}

void SendCoinsEntry::on_payTo_textChanged(const QString &address)
{
    updateLabel(address);
    updateMLDSAWarnings(address);
}

void SendCoinsEntry::setModel(WalletModel *_model)
{
    this->model = _model;

    if (_model && _model->getOptionsModel())
        connect(_model->getOptionsModel(), &OptionsModel::displayUnitChanged, this, &SendCoinsEntry::updateDisplayUnit);

    // Update asset list when model is set
    if (_model) {
        updateAssetList();

        // Connect to asset balance changes
        connect(_model, &WalletModel::assetBalancesChanged,
                this, &SendCoinsEntry::updateAssetSelection);
    }

    clear();
}

void SendCoinsEntry::clear()
{
    // clear UI elements for normal payment
    ui->payTo->clear();
    ui->addAsLabel->clear();
    ui->payAmount->clear();
    if (model && model->getOptionsModel()) {
        ui->checkboxSubtractFeeFromAmount->setChecked(model->getOptionsModel()->getSubFeeFromAmount());
    }
    ui->messageTextLabel->clear();
    ui->messageTextLabel->hide();
    ui->messageLabel->hide();

    // update the display unit, to not use the default ("TSC")
    updateDisplayUnit();
}

void SendCoinsEntry::checkSubtractFeeFromAmount()
{
    ui->checkboxSubtractFeeFromAmount->setChecked(true);
}

void SendCoinsEntry::deleteClicked()
{
    Q_EMIT removeEntry(this);
}

void SendCoinsEntry::useAvailableBalanceClicked()
{
    Q_EMIT useAvailableBalance(this);
}

bool SendCoinsEntry::validate(interfaces::Node& node)
{
    if (!model)
        return false;

    // Check input validity
    bool retval = true;

    if (!model->validateAddress(ui->payTo->text()))
    {
        ui->payTo->setValid(false);
        retval = false;
    }

    if (!ui->payAmount->validate())
    {
        retval = false;
    }

    // Sending a zero amount is invalid
    if (ui->payAmount->value(nullptr) <= 0)
    {
        ui->payAmount->setValid(false);
        retval = false;
    }

    // Asset-specific validation
    if (retval && getSelectedAsset().has_value()) {
        // For asset transactions, we need different validation
        // 1. Check if amount exceeds available asset balance
        uint256 asset_id = getSelectedAsset().value();

        // Find the selected asset's balance
        uint64_t available_balance = 0;
        for (const auto& asset : availableAssets) {
            if (asset.asset_id == asset_id) {
                available_balance = asset.balance;
                break;
            }
        }

        // Convert entered amount to asset units for comparison
        // Use integer arithmetic to avoid precision loss
        uint64_t requested_units;
        uint8_t decimals = getAssetDecimals();
        CAmount entered_amount = ui->payAmount->value();

        if (decimals <= 8) {
            // Asset has fewer or equal decimals than Bitcoin
            uint64_t divisor = 1;
            for (uint8_t i = 0; i < (8 - decimals); ++i) {
                divisor *= 10;
            }
            requested_units = static_cast<uint64_t>(entered_amount / divisor);
        } else {
            // Asset has more than 8 decimals
            uint64_t multiplier = 1;
            for (uint8_t i = 0; i < (decimals - 8); ++i) {
                multiplier *= 10;
            }
            // Check for overflow
            if (entered_amount < 0 || static_cast<uint64_t>(entered_amount) > (std::numeric_limits<uint64_t>::max() / multiplier)) {
                requested_units = std::numeric_limits<uint64_t>::max(); // Will fail validation
            } else {
                requested_units = static_cast<uint64_t>(entered_amount) * multiplier;
            }
        }

        if (requested_units > available_balance) {
            ui->payAmount->setValid(false);
            retval = false;
        }

        // Note: For assets, we don't check dust limits as they have fixed output values
    } else {
        // For BTC, reject dust outputs:
        if (retval && GUIUtil::isDust(node, ui->payTo->text(), ui->payAmount->value())) {
            ui->payAmount->setValid(false);
            retval = false;
        }
    }

    return retval;
}

SendCoinsRecipient SendCoinsEntry::getValue()
{
    recipient.address = ui->payTo->text();
    recipient.label = ui->addAsLabel->text();
    recipient.amount = ui->payAmount->value();
    recipient.message = ui->messageTextLabel->text();
    recipient.fSubtractFeeFromAmount = (ui->checkboxSubtractFeeFromAmount->checkState() == Qt::Checked);

    // Set asset information
    recipient.asset_id = getSelectedAsset();
    recipient.asset_decimals = getAssetDecimals();

    // Convert amount to asset units based on decimals
    if (recipient.asset_id.has_value()) {
        // For assets, we need to convert from the displayed amount to raw units
        // WITHOUT using floating point to maintain precision

        // BitcoinAmountField gives us satoshis (10^8 precision)
        // We need to convert to asset units with asset's decimal precision

        if (recipient.asset_decimals <= 8) {
            // Asset has fewer or equal decimals than Bitcoin
            // Divide by the difference in precision
            uint64_t divisor = 1;
            for (uint8_t i = 0; i < (8 - recipient.asset_decimals); ++i) {
                divisor *= 10;
            }
            recipient.asset_units = static_cast<uint64_t>(recipient.amount / divisor);
        } else {
            // Asset has more decimals than Bitcoin (>8)
            // This is a limitation - we can only support up to 8 decimal places in the UI
            // For now, multiply by the difference but this will lose precision beyond 8 decimals
            uint64_t multiplier = 1;
            for (uint8_t i = 0; i < (recipient.asset_decimals - 8); ++i) {
                multiplier *= 10;
            }
            // Check for overflow
            if (recipient.amount < 0 || static_cast<uint64_t>(recipient.amount) > (std::numeric_limits<uint64_t>::max() / multiplier)) {
                // Amount too large - set to 0 to trigger validation error
                recipient.asset_units = 0;
            } else {
                recipient.asset_units = static_cast<uint64_t>(recipient.amount) * multiplier;
            }

            // Note: For assets with >8 decimals, users can only specify up to 8 decimal places
            // This is a fundamental limitation of using BitcoinAmountField
        }

        recipient.asset_amount_string = GUIUtil::formatAssetAmount(recipient.asset_units, recipient.asset_decimals);
        recipient.amount = 0;
    } else {
        // For BTC, amount is already in satoshis
        recipient.asset_units = 0;  // Not used for BTC
        recipient.asset_amount_string.clear();
    }

    // Set asset ticker
    int index = assetComboBox->currentIndex();
    if (index > 0 && index <= static_cast<int>(availableAssets.size())) {
        const auto& asset = availableAssets[index - 1];
        recipient.asset_ticker = QString::fromStdString(asset.has_ticker ? asset.ticker : "");
    } else {
        recipient.asset_ticker.clear();
    }

    return recipient;
}

QWidget *SendCoinsEntry::setupTabChain(QWidget *prev)
{
    QWidget::setTabOrder(prev, ui->payTo);
    QWidget::setTabOrder(ui->payTo, ui->addAsLabel);
    QWidget *w = ui->payAmount->setupTabChain(ui->addAsLabel);
    QWidget::setTabOrder(w, ui->checkboxSubtractFeeFromAmount);
    QWidget::setTabOrder(ui->checkboxSubtractFeeFromAmount, ui->addressBookButton);
    QWidget::setTabOrder(ui->addressBookButton, ui->pasteButton);
    QWidget::setTabOrder(ui->pasteButton, ui->deleteButton);
    return ui->deleteButton;
}

void SendCoinsEntry::setValue(const SendCoinsRecipient &value)
{
    recipient = value;

    // Handle asset amount string conversion if present
    if (recipient.asset_id.has_value() && !recipient.asset_amount_string.isEmpty()) {
        uint8_t decimals = recipient.asset_decimals;
        uint64_t units = 0;

        auto tryConvert = [&](uint8_t dec) {
            return GUIUtil::convertAssetAmountStringToUnits(recipient.asset_amount_string, dec, units);
        };

        bool converted = tryConvert(decimals);
        if (!converted && model) {
            decimals = getAssetDecimals();
            converted = tryConvert(decimals);
        }

        if (converted) {
            recipient.asset_units = units;
            recipient.asset_decimals = decimals;
            recipient.asset_amount_string.clear();
        }
    }

    {
        // message
        ui->messageTextLabel->setText(recipient.message);
        ui->messageTextLabel->setVisible(!recipient.message.isEmpty());
        ui->messageLabel->setVisible(!recipient.message.isEmpty());

        ui->addAsLabel->clear();
        ui->payTo->setText(recipient.address); // this may set a label from addressbook
        if (!recipient.label.isEmpty()) // if a label had been set from the addressbook, don't overwrite with an empty label
            ui->addAsLabel->setText(recipient.label);

        if (recipient.asset_id.has_value()) {
        if (recipient.asset_decimals > 8) {
            QSignalBlocker blocker(assetComboBox);
            assetComboBox->setCurrentIndex(0);
            QMessageBox::warning(this,
                tr("Unsupported Asset Precision"),
                tr("Sending assets with more than 8 decimal places is not supported in this version."));
            ui->payAmount->setValue(0);
            recipient.asset_id.reset();
            recipient.asset_ticker.clear();
            ui->checkboxSubtractFeeFromAmount->setEnabled(true);
            ui->checkboxSubtractFeeFromAmount->setToolTip(tr("The fee will be deducted from the amount being sent"));
        } else {
                uint64_t multiplier = 1;
                for (uint8_t i = 0; i < (8 - recipient.asset_decimals); ++i) {
                    multiplier *= 10;
                }

                // Prevent overflow when converting to satoshis
                uint64_t displayUnits = 0;
                if (recipient.asset_decimals <= 8 && multiplier > 0) {
                    if (recipient.asset_units > std::numeric_limits<uint64_t>::max() / multiplier) {
                        displayUnits = std::numeric_limits<uint64_t>::max();
                    } else {
                        displayUnits = recipient.asset_units * multiplier;
                    }
                }

                ui->payAmount->setValue(static_cast<CAmount>(displayUnits));
            }
        } else {
            ui->payAmount->setValue(recipient.amount);
        }
    }
}

void SendCoinsEntry::setAddress(const QString &address)
{
    ui->payTo->setText(address);
    ui->payAmount->setFocus();
}

void SendCoinsEntry::setAmount(const CAmount &amount)
{
    ui->payAmount->setValue(amount);
}

bool SendCoinsEntry::isClear()
{
    return ui->payTo->text().isEmpty();
}

void SendCoinsEntry::setFocus()
{
    ui->payTo->setFocus();
}

void SendCoinsEntry::updateDisplayUnit()
{
    if (model && model->getOptionsModel()) {
        ui->payAmount->setDisplayUnit(model->getOptionsModel()->getDisplayUnit());
    }
}

void SendCoinsEntry::changeEvent(QEvent* e)
{
    if (e->type() == QEvent::PaletteChange) {
        ui->addressBookButton->setIcon(platformStyle->SingleColorIcon(QStringLiteral(":/icons/address-book")));
        ui->pasteButton->setIcon(platformStyle->SingleColorIcon(QStringLiteral(":/icons/editpaste")));
        ui->deleteButton->setIcon(platformStyle->SingleColorIcon(QStringLiteral(":/icons/remove")));
    }

    QWidget::changeEvent(e);
}

bool SendCoinsEntry::updateLabel(const QString &address)
{
    if(!model)
        return false;

    // Fill in label from address book, if address has an associated label
    QString associatedLabel = model->getAddressTableModel()->labelForAddress(address);
    if(!associatedLabel.isEmpty())
    {
        ui->addAsLabel->setText(associatedLabel);
        return true;
    }

    return false;
}

void SendCoinsEntry::updateAssetList()
{
    if (!model) return;

    // Save current selection
    QVariant currentData = assetComboBox->currentData();

    // Clear and repopulate
    assetComboBox->clear();

    // Always add TSC as first option
    assetComboBox->addItem(tr("TSC (TensorCash)"), QVariant());

    // Get available assets from wallet
    availableAssets = model->getAssetBalances();

    // Add each asset to the dropdown
    for (const auto& asset : availableAssets) {
        QString label;
        QString balance;

        // Format the balance
        if (asset.has_decimals && asset.decimals > 0) {
            uint64_t factor = 1;
            for (uint8_t i = 0; i < asset.decimals; ++i) {
                factor *= 10;
            }
            uint64_t whole = asset.balance / factor;
            uint64_t remainder = asset.balance % factor;
            balance = QString("%1.%2")
                .arg(whole)
                .arg(remainder, asset.decimals, 10, QChar('0'));
        } else {
            balance = QString::number(asset.balance);
        }

        // Create label with ticker or truncated ID
        QString ticker = !asset.ticker.empty() ? QString::fromStdString(asset.ticker)
                                               : QString::fromStdString(asset.asset_id.ToString()).left(8) + "...";
        label = QString("%1 (%2)").arg(ticker).arg(balance);

        if (!asset.is_registered) {
            label = QStringLiteral("⚠ %1").arg(label);
        }

        // Store the asset_id and metadata as data
        const QString assetId = QString::fromStdString(asset.asset_id.ToString());
        QVariant assetData;
        assetData.setValue(assetId);
        assetComboBox->addItem(label, assetData);
        const int newIndex = assetComboBox->count() - 1;
        if (!asset.is_registered) {
            assetComboBox->setItemData(newIndex,
                tr("Registry entry missing for %1 (%2)").arg(ticker, assetId),
                Qt::ToolTipRole);
        }
        assetComboBox->setItemData(newIndex, asset.is_registered, Qt::UserRole + 1);
    }

    // Restore selection if it still exists
    int index = assetComboBox->findData(currentData);
    if (index >= 0) {
        assetComboBox->setCurrentIndex(index);
    }
}

void SendCoinsEntry::setSelectedAsset(const QString& assetIdOrTicker)
{
    // Try to find by ticker first
    for (size_t i = 0; i < availableAssets.size(); ++i) {
        if (!availableAssets[i].ticker.empty() &&
            QString::fromStdString(availableAssets[i].ticker) == assetIdOrTicker) {
            assetComboBox->setCurrentIndex(i + 1); // +1 for BTC at index 0
            return;
        }
    }

    // Try to find by asset ID
    int index = assetComboBox->findData(assetIdOrTicker);
    if (index >= 0) {
        assetComboBox->setCurrentIndex(index);
    }
}

std::optional<uint256> SendCoinsEntry::getSelectedAsset() const
{
    if (assetComboBox->currentIndex() == 0) {
        // BTC selected
        return std::nullopt;
    }

    QVariant data = assetComboBox->currentData();
    if (data.isValid()) {
        QString assetIdStr = data.toString();
        auto assetId = uint256::FromHex(assetIdStr.toStdString());
        if (assetId) {
            return *assetId;
        }
    }

    return std::nullopt;
}

uint8_t SendCoinsEntry::getAssetDecimals() const
{
    if (assetComboBox->currentIndex() == 0) {
        // BTC has 8 decimals
        return 8;
    }

    int assetIndex = assetComboBox->currentIndex() - 1;
    if (assetIndex >= 0 && assetIndex < static_cast<int>(availableAssets.size())) {
        if (availableAssets[assetIndex].has_decimals) {
            return availableAssets[assetIndex].decimals;
        }
    }

    return 0; // Default to no decimals if unknown
}

void SendCoinsEntry::on_assetComboBox_currentIndexChanged(int index)
{
    Q_UNUSED(index);

    // Update amount field decimals based on selected asset
    uint8_t decimals = getAssetDecimals();

    // Clear amount when asset changes to avoid confusion
    ui->payAmount->clear();

    // Update the recipient structure
    recipient.asset_id = getSelectedAsset();
    recipient.asset_decimals = decimals;

    if (recipient.asset_id.has_value() && decimals > 8) {
        QSignalBlocker blocker(assetComboBox);
        assetComboBox->setCurrentIndex(0);
        recipient.asset_id.reset();
        recipient.asset_ticker.clear();
        recipient.asset_decimals = 8;

        QMessageBox::warning(this,
            tr("Unsupported Asset Precision"),
            tr("Sending assets with more than 8 decimal places is not supported in this version."));

        ui->checkboxSubtractFeeFromAmount->setEnabled(true);
        ui->checkboxSubtractFeeFromAmount->setToolTip(tr("The fee will be deducted from the amount being sent"));

        Q_EMIT assetSelectionChanged();
        return;
    }

    if (index > 0 && index <= static_cast<int>(availableAssets.size())) {
        // Asset selected
        const auto& asset = availableAssets[index - 1];
        if (!asset.is_registered) {
            QSignalBlocker blocker(assetComboBox);
            assetComboBox->setCurrentIndex(0);
            recipient.asset_id.reset();
            recipient.asset_ticker.clear();
            recipient.asset_decimals = 8;

            QMessageBox::warning(this,
                tr("Unregistered Asset"),
                tr("This wallet holds outputs for an asset that is missing a registry entry. "
                   "Please rescan or sync the node before attempting to send it."));

            ui->checkboxSubtractFeeFromAmount->setEnabled(true);
            ui->checkboxSubtractFeeFromAmount->setToolTip(tr("The fee will be deducted from the amount being sent"));

            Q_EMIT assetSelectionChanged();
            return;
        }

        recipient.asset_ticker = QString::fromStdString(!asset.ticker.empty() ? asset.ticker : "");

        // Disable subtract fee for assets - fees must be paid in BTC
        ui->checkboxSubtractFeeFromAmount->setChecked(false);
        ui->checkboxSubtractFeeFromAmount->setEnabled(false);
        ui->checkboxSubtractFeeFromAmount->setToolTip(tr("Cannot subtract fees from asset amounts. Fees are paid in TSC."));
    } else {
        // BTC selected
        recipient.asset_ticker.clear();

        // Enable subtract fee for BTC
        ui->checkboxSubtractFeeFromAmount->setEnabled(true);
        ui->checkboxSubtractFeeFromAmount->setToolTip(tr("The fee will be deducted from the amount being sent"));
    }

    // Update the unit label
    updateAssetUnitLabel();

    Q_EMIT assetSelectionChanged();
}

void SendCoinsEntry::updateAssetSelection()
{
    updateAssetList();
}

void SendCoinsEntry::updateAssetUnitLabel()
{
    if (!ui->payAmount) return;

    auto selected_asset = getSelectedAsset();
    if (selected_asset.has_value() && !recipient.asset_ticker.isEmpty()) {
        // Asset selected - hide TSC unit dropdown since asset units are fixed
        ui->payAmount->setUnitVisible(false);
    } else {
        // TSC selected - show TSC unit dropdown
        ui->payAmount->setUnitVisible(true);
    }
}

void SendCoinsEntry::updateMLDSAWarnings(const QString &address)
{
    if (!mldsaFeeWarningLabel || !mldsaAddressTypeBadge) {
        return;
    }

    // Clear warnings by default
    mldsaFeeWarningLabel->hide();
    mldsaAddressTypeBadge->hide();

    // Only show warnings if address is not empty
    if (address.isEmpty()) {
        return;
    }

    // Decode the destination address
    CTxDestination dest = DecodeDestination(address.toStdString());

    // Check if this is a WitnessV2Taproot (ML-DSA) address
    if (std::holds_alternative<WitnessV2Taproot>(dest)) {
        // Show the address type badge
        mldsaAddressTypeBadge->show();

        // Build the fee warning message
        QString warningText = tr("⚠ Warning: Post-Quantum addresses require significantly larger transactions (~70x higher fees). ");

        // Add asset-specific warnings if applicable
        auto selected_asset = getSelectedAsset();
        if (selected_asset.has_value()) {
            // For asset transactions, warn if the fee might exceed the asset value
            warningText += tr("When sending assets to PQ addresses, transaction fees (paid in TSC) may be substantial. "
                            "Ensure you have sufficient TSC balance to cover fees.");
        } else {
            // For TSC transactions
            warningText += tr("A typical ML-DSA transaction costs ~0.007 TSC in fees vs ~0.0001 TSC for standard addresses. "
                            "Consider using standard addresses when high security is not required.");
        }

        mldsaFeeWarningLabel->setText(warningText);
        mldsaFeeWarningLabel->show();
    }
}
