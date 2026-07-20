// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <qt/crosschainprofiledialog.h>
#include <qt/walletmodel.h>
#include <qt/guiutil.h>
#include <logging.h>

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QGroupBox>
#include <QLabel>
#include <QComboBox>
#include <QLineEdit>
#include <QPushButton>
#include <QTableWidget>
#include <QHeaderView>
#include <QMessageBox>

CrossChainProfileDialog::CrossChainProfileDialog(WalletModel* model, QWidget* parent)
    : QDialog(parent), walletModel(model)
{
    setWindowTitle(tr("Settlement Profiles"));
    setMinimumSize(750, 500);
    resize(850, 550);

    setupUI();
    refreshProfileList();
}

CrossChainProfileDialog::~CrossChainProfileDialog()
{
}

void CrossChainProfileDialog::setupUI()
{
    QVBoxLayout* mainLayout = new QVBoxLayout(this);

    // --- Existing profiles table ---
    QGroupBox* listGroup = new QGroupBox(tr("Saved Profiles"), this);
    QVBoxLayout* listLayout = new QVBoxLayout(listGroup);

    profileTable = new QTableWidget(0, 6, this);
    profileTable->setHorizontalHeaderLabels({
        tr("ID"), tr("Label"), tr("Chain"), tr("Address"), tr("Asset"), tr("Fee Speed")
    });
    profileTable->horizontalHeader()->setStretchLastSection(true);
    profileTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    profileTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    profileTable->setSelectionMode(QAbstractItemView::SingleSelection);
    profileTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    profileTable->verticalHeader()->hide();
    listLayout->addWidget(profileTable);

    removeButton = new QPushButton(tr("Remove Selected"), this);
    removeButton->setStyleSheet("QPushButton { color: #c62828; }");
    connect(removeButton, &QPushButton::clicked, this, &CrossChainProfileDialog::onRemoveProfile);
    listLayout->addWidget(removeButton, 0, Qt::AlignRight);

    listGroup->setLayout(listLayout);
    mainLayout->addWidget(listGroup);

    // --- Add new profile form ---
    QGroupBox* addGroup = new QGroupBox(tr("Add New Profile"), this);
    QGridLayout* formLayout = new QGridLayout(addGroup);
    int row = 0;

    formLayout->addWidget(new QLabel(tr("Profile ID:"), this), row, 0);
    profileIdEdit = new QLineEdit(this);
    profileIdEdit->setPlaceholderText(tr("e.g. btc-cold, eth-main"));
    formLayout->addWidget(profileIdEdit, row, 1);
    ++row;

    formLayout->addWidget(new QLabel(tr("Label:"), this), row, 0);
    labelEdit = new QLineEdit(this);
    labelEdit->setPlaceholderText(tr("Human-readable name"));
    formLayout->addWidget(labelEdit, row, 1);
    ++row;

    formLayout->addWidget(new QLabel(tr("Chain:"), this), row, 0);
    chainCombo = new QComboBox(this);
    chainCombo->addItem(tr("Bitcoin (BTC)"), QStringLiteral("btc"));
    chainCombo->addItem(tr("Ethereum (ETH)"), QStringLiteral("ethereum"));
    chainCombo->addItem(tr("Tron (TRX)"), QStringLiteral("tron"));
    connect(chainCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &CrossChainProfileDialog::onChainChanged);
    formLayout->addWidget(chainCombo, row, 1);
    ++row;

    formLayout->addWidget(new QLabel(tr("Address:"), this), row, 0);
    addressEdit = new QLineEdit(this);
    addressEdit->setPlaceholderText(tr("bc1q... / 0x... / T..."));
    formLayout->addWidget(addressEdit, row, 1);
    ++row;

    addressHintLabel = new QLabel(this);
    addressHintLabel->setStyleSheet("QLabel { color: #666; font-size: 9pt; }");
    addressHintLabel->setWordWrap(true);
    formLayout->addWidget(addressHintLabel, row, 0, 1, 2);
    ++row;

    formLayout->addWidget(new QLabel(tr("Signing:"), this), row, 0);
    signerRefCombo = new QComboBox(this);
    signerRefCombo->addItem(tr("Auto-derived from wallet seed"), QStringLiteral("derived:auto"));
    signerRefCombo->setEditable(true);
    signerRefCombo->lineEdit()->setPlaceholderText(tr("derived:auto or imported:<key-id>"));
    formLayout->addWidget(signerRefCombo, row, 1);
    ++row;

    formLayout->addWidget(new QLabel(tr("Preferred Asset:"), this), row, 0);
    preferredAssetEdit = new QLineEdit(this);
    preferredAssetEdit->setPlaceholderText(tr("BTC, ETH, USDT, etc."));
    formLayout->addWidget(preferredAssetEdit, row, 1);
    ++row;

    formLayout->addWidget(new QLabel(tr("Fee Speed:"), this), row, 0);
    feeSpeedCombo = new QComboBox(this);
    feeSpeedCombo->addItem(tr("Normal"), QStringLiteral("normal"));
    feeSpeedCombo->addItem(tr("Fast"), QStringLiteral("fast"));
    feeSpeedCombo->addItem(tr("Urgent"), QStringLiteral("urgent"));
    formLayout->addWidget(feeSpeedCombo, row, 1);
    ++row;

    addButton = new QPushButton(tr("Add Profile"), this);
    addButton->setStyleSheet(
        "QPushButton { padding: 6px 16px; font-weight: bold; "
        "background-color: #4CAF50; color: white; border-radius: 4px; } "
        "QPushButton:hover { background-color: #45a049; }");
    connect(addButton, &QPushButton::clicked, this, &CrossChainProfileDialog::onAddProfile);
    formLayout->addWidget(addButton, row, 1, Qt::AlignRight);

    addGroup->setLayout(formLayout);
    mainLayout->addWidget(addGroup);

    // Close button
    QPushButton* closeButton = new QPushButton(tr("Close"), this);
    connect(closeButton, &QPushButton::clicked, this, &QDialog::accept);
    mainLayout->addWidget(closeButton, 0, Qt::AlignRight);

    setLayout(mainLayout);

    GUIUtil::InstallWheelEventFilter(chainCombo);
    GUIUtil::InstallWheelEventFilter(signerRefCombo);
    GUIUtil::InstallWheelEventFilter(feeSpeedCombo);

    // Prime the chain-dependent hint/asset fields now that every widget
    // (addressHintLabel, preferredAssetEdit) has been constructed.
    onChainChanged(chainCombo->currentIndex());
}

void CrossChainProfileDialog::onChainChanged(int index)
{
    QString chain = chainCombo->currentData().toString();
    if (chain == "btc") {
        addressHintLabel->setText(tr("Bech32 (bc1...), Base58 (1... / 3...), or testnet (tb1... / m... / n...)."));
        preferredAssetEdit->setText(QStringLiteral("BTC"));
    } else if (chain == "ethereum") {
        addressHintLabel->setText(tr("0x-prefixed, 40 hex chars. Use all-lowercase for settlement profiles."));
        preferredAssetEdit->setText(QStringLiteral("ETH"));
    } else if (chain == "tron") {
        addressHintLabel->setText(tr("Base58 T-prefix (34 chars) or hex 41-prefix (42 chars)."));
        preferredAssetEdit->setText(QStringLiteral("USDT"));
    }
}

void CrossChainProfileDialog::onAddProfile()
{
    if (!walletModel) return;

    QString profileId = profileIdEdit->text().trimmed();
    QString label = labelEdit->text().trimmed();
    QString chain = chainCombo->currentData().toString();
    QString address = addressEdit->text().trimmed();
    QString signerRef = signerRefCombo->currentText().trimmed();
    QString preferredAsset = preferredAssetEdit->text().trimmed();
    QString feeSpeed = feeSpeedCombo->currentData().toString();

    if (profileId.isEmpty()) {
        QMessageBox::warning(this, tr("Validation"), tr("Profile ID is required."));
        return;
    }
    if (label.isEmpty()) {
        QMessageBox::warning(this, tr("Validation"), tr("Label is required."));
        return;
    }
    if (address.isEmpty()) {
        QMessageBox::warning(this, tr("Validation"), tr("Address is required."));
        return;
    }
    if (signerRef.isEmpty()) {
        QMessageBox::warning(this, tr("Validation"), tr("Signing reference is required."));
        return;
    }
    if (preferredAsset.isEmpty()) {
        QMessageBox::warning(this, tr("Validation"), tr("Preferred asset is required."));
        return;
    }

    auto result = walletModel->settlementProfileAdd(
        profileId, label, chain, address, signerRef, preferredAsset, feeSpeed);

    if (!result.success) {
        QMessageBox::critical(this, tr("Failed to Add Profile"),
            tr("Could not save settlement profile:\n\n%1").arg(result.error));
        return;
    }

    LogPrintf("CrossChainProfileDialog: Added profile '%s' for chain %s\n",
              profileId.toStdString().c_str(), chain.toStdString().c_str());

    // Clear form
    profileIdEdit->clear();
    labelEdit->clear();
    addressEdit->clear();

    refreshProfileList();
}

void CrossChainProfileDialog::onRemoveProfile()
{
    if (!walletModel) return;

    int row = profileTable->currentRow();
    if (row < 0) {
        QMessageBox::information(this, tr("No Selection"), tr("Select a profile to remove."));
        return;
    }

    QString profileId = profileTable->item(row, 0)->text();

    int ret = QMessageBox::question(this, tr("Remove Profile"),
        tr("Remove settlement profile \"%1\"?\n\nThis cannot be undone.").arg(profileId),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);

    if (ret != QMessageBox::Yes) return;

    bool ok = walletModel->settlementProfileRemove(profileId);
    if (!ok) {
        QMessageBox::warning(this, tr("Error"), tr("Failed to remove profile."));
        return;
    }

    LogPrintf("CrossChainProfileDialog: Removed profile '%s'\n", profileId.toStdString().c_str());
    refreshProfileList();
}

void CrossChainProfileDialog::refreshProfileList()
{
    profileTable->setRowCount(0);

    if (!walletModel) return;

    QList<WalletModel::SettlementProfileItem> profiles = walletModel->settlementProfileList();

    for (const auto& p : profiles) {
        int row = profileTable->rowCount();
        profileTable->insertRow(row);
        profileTable->setItem(row, 0, new QTableWidgetItem(p.profile_id));
        profileTable->setItem(row, 1, new QTableWidgetItem(p.label));
        profileTable->setItem(row, 2, new QTableWidgetItem(p.chain.toUpper()));
        profileTable->setItem(row, 3, new QTableWidgetItem(p.address));
        profileTable->setItem(row, 4, new QTableWidgetItem(p.preferred_asset));
        profileTable->setItem(row, 5, new QTableWidgetItem(p.fee_speed));
    }
}
