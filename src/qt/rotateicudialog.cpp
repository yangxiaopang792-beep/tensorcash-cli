// Copyright (c) 2024 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/rotateicudialog.h>

#include <qt/guiutil.h>
#include <qt/walletmodel.h>
#include <qt/clientmodel.h>
#include <qt/platformstyle.h>
#include <interfaces/node.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <assets/asset.h>
#include <assets/icu_payload.h>

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QGroupBox>
#include <QComboBox>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QTextEdit>
#include <QMessageBox>
#include <QStyle>
#include <cmath>
#include <set>

RotateICUDialog::RotateICUDialog(const PlatformStyle* platformStyle, QWidget* parent)
    : QDialog(parent), m_platform_style(platformStyle)
{
    setWindowTitle(tr("Rotate ICU"));
    setMinimumWidth(600);
    setMinimumHeight(500);

    QVBoxLayout* mainLayout = new QVBoxLayout(this);

    // Asset selection
    QGroupBox* selectGroup = new QGroupBox(tr("Select Asset"));
    QHBoxLayout* selectLayout = new QHBoxLayout();

    assetCombo = new QComboBox();
    connect(assetCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &RotateICUDialog::onAssetSelected);
    selectLayout->addWidget(new QLabel(tr("Asset:")));
    selectLayout->addWidget(assetCombo);

    refreshButton = new QPushButton(tr("Refresh"));
    connect(refreshButton, &QPushButton::clicked, this, &RotateICUDialog::onRefresh);
    selectLayout->addWidget(refreshButton);

    selectGroup->setLayout(selectLayout);
    mainLayout->addWidget(selectGroup);

    // Current ICU info
    QGroupBox* infoGroup = new QGroupBox(tr("Current ICU Information"));
    QFormLayout* infoForm = new QFormLayout();

    currentICULabel = new QLabel(tr("N/A"));
    currentICULabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    infoForm->addRow(tr("ICU Location:"), currentICULabel);

    currentBondLabel = new QLabel(tr("N/A"));
    infoForm->addRow(tr("Current Bond:"), currentBondLabel);

    feesLabel = new QLabel(tr("N/A"));
    infoForm->addRow(tr("Fees Accumulated:"), feesLabel);

    minBondLabel = new QLabel(tr("N/A"));
    infoForm->addRow(tr("Minimum Bond:"), minBondLabel);

    infoGroup->setLayout(infoForm);
    mainLayout->addWidget(infoGroup);

    // Rotation parameters
    QGroupBox* paramsGroup = new QGroupBox(tr("Rotation Parameters"));
    QFormLayout* paramsForm = new QFormLayout();

    QHBoxLayout* icuAddressLayout = new QHBoxLayout();
    newICUAddressEdit = new QLineEdit();
    newICUAddressEdit->setPlaceholderText(tr("New ICU address"));
    icuAddressLayout->addWidget(newICUAddressEdit);

    QPushButton* generateTaprootButton = new QPushButton(tr("Generate Taproot"));
    generateTaprootButton->setMaximumWidth(140);
    generateTaprootButton->setToolTip(tr("Generate a new Taproot (P2TR) address for ICU"));
    connect(generateTaprootButton, &QPushButton::clicked, this, &RotateICUDialog::onGenerateTaproot);
    icuAddressLayout->addWidget(generateTaprootButton);

    paramsForm->addRow(tr("New ICU Address:"), icuAddressLayout);

    newBondEdit = new QLineEdit();
    newBondEdit->setPlaceholderText(tr("Must be >= rotation_min_sats"));
    paramsForm->addRow(tr("New Bond (TSC):"), newBondEdit);

    paramsGroup->setLayout(paramsForm);
    mainLayout->addWidget(paramsGroup);

    // Rotate button
    rotateButton = new QPushButton(tr("Rotate ICU"));
    if (m_platform_style->getImagesOnButtons()) {
        rotateButton->setIcon(m_platform_style->SingleColorIcon(":/icons/synced"));
    }
    connect(rotateButton, &QPushButton::clicked, this, &RotateICUDialog::onRotateICU);
    mainLayout->addWidget(rotateButton);

    // Status text
    statusText = new QTextEdit();
    statusText->setReadOnly(true);
    statusText->setMaximumHeight(150);
    mainLayout->addWidget(statusText);

    // Dialog buttons
    QHBoxLayout* buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch();
    QPushButton* closeButton = new QPushButton(tr("Close"));
    connect(closeButton, &QPushButton::clicked, this, &QDialog::accept);
    buttonLayout->addWidget(closeButton);
    mainLayout->addLayout(buttonLayout);

    mainLayout->addStretch();

    // Install wheel event filter to prevent accidental changes while scrolling
    GUIUtil::InstallWheelEventFilter(assetCombo);
}

RotateICUDialog::~RotateICUDialog() = default;

void RotateICUDialog::setWalletModel(WalletModel* model)
{
    walletModel = model;
}

void RotateICUDialog::setClientModel(ClientModel* model)
{
    clientModel = model;
}

void RotateICUDialog::setAssetList(const QMap<QString, QString>& assets)
{
    const QString selected = assetCombo->currentData().toString();
    assetCombo->clear();

    for (auto it = assets.begin(); it != assets.end(); ++it) {
        assetCombo->addItem(it.value(), it.key());  // value=display name, key=asset ID
    }

    // Restore selection
    if (!selected.isEmpty()) {
        int idx = assetCombo->findData(selected);
        if (idx >= 0) {
            assetCombo->setCurrentIndex(idx);
        }
    }

    if (assetCombo->count() > 0 && assetCombo->currentIndex() < 0) {
        assetCombo->setCurrentIndex(0);
    }
}

void RotateICUDialog::setAsset(const QString& assetId)
{
    if (assetId.isEmpty()) return;

    // Find and select the asset in the combo box
    int index = assetCombo->findData(assetId);
    if (index >= 0) {
        assetCombo->setCurrentIndex(index);
    } else {
        // Asset not found, refresh and try again
        refreshAssetList();
        index = assetCombo->findData(assetId);
        if (index >= 0) {
            assetCombo->setCurrentIndex(index);
        }
    }
}

void RotateICUDialog::refreshAssetList()
{
    if (!walletModel || !clientModel) return;

    const std::string wallet_name = walletModel->getWalletName().toStdString();
    const QString selected = assetCombo->currentData().toString();

    assetCombo->clear();

    try {
        // Scan transactions to find assets we've issued (IssuerReg outputs we control)
        UniValue listTxParams(UniValue::VARR);
        listTxParams.push_back("*");      // label filter
        listTxParams.push_back(99999);    // count
        listTxParams.push_back(0);        // skip
        listTxParams.push_back(false);    // include_watchonly
        UniValue txs = clientModel->node().executeRpc("listtransactions", listTxParams, wallet_name);

        if (!txs.isArray()) {
            return;
        }

        std::set<QString> foundAssets;

        for (size_t i = 0; i < txs.size(); ++i) {
            try {
                const UniValue& txEntry = txs[i];
                if (txEntry.find_value("category").get_str() != "receive") continue;

                QString txid = QString::fromStdString(txEntry.find_value("txid").get_str());

                // Decode transaction
                UniValue getTxParams(UniValue::VARR);
                getTxParams.push_back(txid.toStdString());
                getTxParams.push_back(true);  // verbose
                UniValue decoded = clientModel->node().executeRpc("getrawtransaction", getTxParams, "");

                const UniValue& vouts = decoded.find_value("vout");
                if (!vouts.isArray()) continue;

                // Check each output for IssuerReg TLV
                for (size_t vout = 0; vout < vouts.size(); ++vout) {
                    const UniValue& output = vouts[vout];
                    if (!output.exists("outext")) continue;

                    QString outext = QString::fromStdString(output.find_value("outext").get_str());
                    if (!outext.startsWith("10")) continue;  // IssuerReg TLV type 0x10

                    // Parse IssuerReg TLV
                    std::vector<unsigned char> vext = ParseHex(outext.toStdString());
                    auto issuerReg = assets::ParseIssuerReg(vext);
                    if (!issuerReg) continue;

                    QString assetId = QString::fromStdString(issuerReg->asset_id.ToString());
                    if (foundAssets.count(assetId)) continue;
                    foundAssets.insert(assetId);

                    QString ticker = QString::fromStdString(issuerReg->ticker);
                    QString displayName = ticker.isEmpty() ? (assetId.left(16) + "...") : ticker;

                    assetCombo->addItem(displayName, assetId);
                }
            } catch (...) {
                continue;  // Skip failed transactions
            }
        }

        // Restore selection
        if (!selected.isEmpty()) {
            int idx = assetCombo->findData(selected);
            if (idx >= 0) {
                assetCombo->setCurrentIndex(idx);
            }
        }

        if (assetCombo->count() > 0 && assetCombo->currentIndex() < 0) {
            assetCombo->setCurrentIndex(0);
        }

    } catch (UniValue& objError) {
        try {
            int code = objError.find_value("code").getInt<int>();
            std::string message = objError.find_value("message").get_str();
            showError(tr("RPC Error (%1): %2").arg(code).arg(QString::fromStdString(message)));
        } catch (const std::runtime_error&) {
            showError(tr("RPC Error: %1").arg(QString::fromStdString(objError.write())));
        }
    } catch (const std::exception& e) {
        showError(tr("Failed to list assets: %1").arg(e.what()));
    }
}

void RotateICUDialog::updateAssetInfo(const QString& assetId)
{
    if (!clientModel || assetId.isEmpty()) {
        currentICULabel->setText(tr("N/A"));
        currentBondLabel->setText(tr("N/A"));
        feesLabel->setText(tr("N/A"));
        minBondLabel->setText(tr("N/A"));
        return;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(assetId.toStdString());
        UniValue policy = clientModel->node().executeRpc("getassetpolicy", params, "");

        if (policy.isNull() || !policy.exists("icu_txid")) {
            // Asset not yet in registry - likely unconfirmed
            currentICULabel->setText(tr("Pending confirmation..."));
            currentBondLabel->setText(tr("Pending confirmation..."));
            feesLabel->setText(tr("Pending confirmation..."));
            minBondLabel->setText(tr("Pending confirmation..."));
            return;
        }

        QString icuTxid = QString::fromStdString(policy.find_value("icu_txid").get_str());
        int icuVout = policy.find_value("icu_vout").getInt<int>();
        uint64_t feesAccum = policy.find_value("fees_accum_sats").getInt<uint64_t>();
        uint64_t unlockFees = policy.find_value("unlock_fees_sats").getInt<uint64_t>();
        uint64_t rotationMin = policy.find_value("rotation_min_sats").getInt<uint64_t>();

        // Get bond amount from wallet transaction
        UniValue getTxParams(UniValue::VARR);
        getTxParams.push_back(icuTxid.toStdString());
        getTxParams.push_back(true);  // include_watchonly
        UniValue walletTx = clientModel->node().executeRpc("gettransaction", getTxParams, walletModel->getWalletName().toStdString());

        // Decode the hex to get vout info
        QString hexStr = QString::fromStdString(walletTx.find_value("hex").get_str());
        UniValue decodeParams(UniValue::VARR);
        decodeParams.push_back(hexStr.toStdString());
        UniValue tx = clientModel->node().executeRpc("decoderawtransaction", decodeParams, "");

        const UniValue& vouts = tx.find_value("vout");
        if (!vouts.isArray() || static_cast<size_t>(icuVout) >= vouts.size()) {
            throw std::runtime_error("ICU vout not found");
        }
        double bond = vouts[icuVout].find_value("value").get_real();

        currentICULabel->setText(QString("%1:%2").arg(icuTxid).arg(icuVout));
        currentBondLabel->setText(tr("%1 TSC").arg(bond, 0, 'f', 8));
        feesLabel->setText(tr("%1 / %2 sats").arg(feesAccum).arg(unlockFees));
        minBondLabel->setText(tr("%1 TSC").arg(rotationMin / 100000000.0, 0, 'f', 8));

    } catch (UniValue& objError) {
        currentICULabel->setText(tr("Pending confirmation..."));
        currentBondLabel->setText(tr("Pending confirmation..."));
        feesLabel->setText(tr("Pending confirmation..."));
        minBondLabel->setText(tr("Pending confirmation..."));
    } catch (const std::exception& e) {
        currentICULabel->setText(tr("Pending confirmation..."));
        currentBondLabel->setText(tr("Pending confirmation..."));
        feesLabel->setText(tr("Pending confirmation..."));
        minBondLabel->setText(tr("Pending confirmation..."));
    }
}

void RotateICUDialog::onAssetSelected(int index)
{
    if (index < 0 || !walletModel) return;

    QString assetId = assetCombo->currentData().toString();
    updateAssetInfo(assetId);
}

void RotateICUDialog::onRefresh()
{
    int index = assetCombo->currentIndex();
    if (index >= 0) {
        QString assetId = assetCombo->currentData().toString();
        if (!assetId.isEmpty()) {
            refreshAssetList();
            updateAssetInfo(assetId);
            statusText->append(tr("Asset info refreshed"));
        }
    }
}

void RotateICUDialog::onGenerateTaproot()
{
    if (!walletModel) {
        showError(tr("Wallet model not initialized"));
        return;
    }
    try {
        UniValue params(UniValue::VARR);
        params.push_back("");  // empty label
        params.push_back("bech32m");  // address_type for taproot
        UniValue result = clientModel->node().executeRpc("getnewaddress", params, walletModel->getWalletName().toStdString());
        QString newAddress = QString::fromStdString(result.get_str());
        newICUAddressEdit->setText(newAddress);
        statusText->append(tr("✓ Generated new Taproot address: %1").arg(newAddress));
    } catch (UniValue& objError) {
        try {
            int code = objError.find_value("code").getInt<int>();
            std::string message = objError.find_value("message").get_str();
            statusText->append(tr("✗ RPC Error (%1): %2").arg(code).arg(QString::fromStdString(message)));
            showError(QString::fromStdString(message));
        } catch (const std::runtime_error&) {
            statusText->append(tr("✗ Error: %1").arg(QString::fromStdString(objError.write())));
            showError(tr("RPC Error: %1").arg(QString::fromStdString(objError.write())));
        }
    } catch (const std::exception& e) {
        showError(tr("Failed to generate Taproot address: %1").arg(e.what()));
    }
}

void RotateICUDialog::onRotateICU()
{
    if (!walletModel || !clientModel) {
        showError(tr("Wallet or client model not initialized"));
        return;
    }

    QString assetId = assetCombo->currentData().toString();
    QString newICUAddress = newICUAddressEdit->text().trimmed();
    QString newBondStr = newBondEdit->text().trimmed();

    if (assetId.isEmpty() || newICUAddress.isEmpty() || newBondStr.isEmpty()) {
        showError(tr("All fields are required for ICU rotation"));
        return;
    }

    // Check if the new ICU address is controlled by this wallet
    bool addressOwned = isAddressOwnedByWallet(newICUAddress);
    if (!addressOwned) {
        QMessageBox::StandardButton reply = QMessageBox::warning(
            this,
            tr("Address Not Controlled by Wallet"),
            tr("WARNING: The ICU address you specified (%1) is not controlled by this wallet.\n\n"
               "This means you will NOT be able to perform future operations (minting, burning, or rotation) "
               "for this asset unless you have access to the private key for this address.\n\n"
               "Are you sure you want to continue?").arg(newICUAddress),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No
        );

        if (reply != QMessageBox::Yes) {
            statusText->append(tr("ICU rotation cancelled by user"));
            return;
        }
    }

    double newBond = newBondStr.toDouble();

    statusText->append(tr("Rotating ICU to %1 with bond %2 TSC...").arg(newICUAddress).arg(newBond));

    try {
        // Get current policy
        UniValue policyParams(UniValue::VARR);
        policyParams.push_back(assetId.toStdString());
        UniValue policy = clientModel->node().executeRpc("getassetpolicy", policyParams, "");

        QString icuTxid = QString::fromStdString(policy.find_value("icu_txid").get_str());
        int icuVout = policy.find_value("icu_vout").getInt<int>();
        uint64_t rotationMin = policy.find_value("rotation_min_sats").getInt<uint64_t>();

        // Validate new bond meets the rotation minimum
        uint64_t newBondSats = static_cast<uint64_t>(std::round(newBond * 100000000.0));
        if (newBondSats < rotationMin) {
            showError(tr("New bond %1 TSC is below minimum %2 TSC")
                .arg(newBond, 0, 'f', 8)
                .arg(rotationMin / 100000000.0, 0, 'f', 8));
            return;
        }

        // Read the current ICU output amount so we can express the change as rotateicu's unlock-fee bump.
        UniValue txoutParams(UniValue::VARR);
        txoutParams.push_back(icuTxid.toStdString());
        txoutParams.push_back(icuVout);
        UniValue txout = clientModel->node().executeRpc("gettxout", txoutParams, "");
        if (!txout.isObject() || !txout.exists("value")) {
            showError(tr("Could not read the current ICU output amount (is the ICU UTXO unspent?)"));
            return;
        }
        uint64_t currentBondSats = static_cast<uint64_t>(std::llround(txout.find_value("value").get_real() * 100000000.0));

        // Rotate via the maintained `rotateicu` RPC, NOT the obsolete `rotateicu_raw`. rotateicu carries
        // the ENTIRE existing ICU forward (canonical text + inline TSC-ICU-CONTEXT-1 clauses + witness +
        // quorum + cap + KYC/TFR + visibility) and changes only the address/bond. rotateicu_raw emitted a
        // stub 46-byte IssuerReg that dropped all of that and is rejected by the 254-byte consensus parser.
        // rotateicu requires the new bond to exceed the current by at least 0.5 BTC (the unlock-fee bump),
        // and sets the new ICU amount = current + bump.
        if (newBondSats <= currentBondSats || (newBondSats - currentBondSats) < 50'000'000ULL) {
            showError(tr("ICU rotation requires increasing the bond by at least 0.5 BTC over the current "
                         "%1 TSC (the unlock-fee bump). Enter a higher new bond.")
                         .arg(currentBondSats / 100000000.0, 0, 'f', 8));
            return;
        }
        double unlockBumpBtc = static_cast<double>(newBondSats - currentBondSats) / 100000000.0;

        UniValue params(UniValue::VARR);
        params.push_back(icuTxid.toStdString());        // 0: icu_txid
        params.push_back(icuVout);                       // 1: icu_vout
        params.push_back(newICUAddress.toStdString());   // 2: new icu_address
        params.push_back(unlockBumpBtc);                 // 3: unlock_fee_bump (new ICU amount = current + bump)
        params.push_back(assetId.toStdString());         // 4: asset_id

        UniValue options(UniValue::VOBJ);
        options.pushKV("autofund", true);
        options.pushKV("broadcast", true);
        options.pushKV("fee_rate", 2.0);
        params.push_back(options);                        // 5: options

        UniValue result = clientModel->node().executeRpc("rotateicu", params, walletModel->getWalletName().toStdString());

        QString txid = QString::fromStdString(result.isStr() ? result.get_str() : result.find_value("txid").get_str());

        statusText->append(tr("\n✓ ICU rotation submitted successfully!"));
        statusText->append(tr("TxID: %1").arg(txid));
        statusText->append(tr("New ICU: %1").arg(newICUAddress));
        statusText->append(tr("New Bond: %1 TSC").arg(newBond, 0, 'f', 8));
        showSuccess(tr("ICU rotated! TxID: %1").arg(txid.left(16) + "..."));

        // Clear form and refresh
        newICUAddressEdit->clear();
        newBondEdit->clear();
        updateAssetInfo(assetId);

    } catch (UniValue& objError) {
        try {
            int code = objError.find_value("code").getInt<int>();
            std::string message = objError.find_value("message").get_str();
            statusText->append(tr("\n✗ RPC Error (%1): %2").arg(code).arg(QString::fromStdString(message)));
            showError(QString::fromStdString(message));
        } catch (const std::runtime_error&) {
            statusText->append(tr("\n✗ Error: %1").arg(QString::fromStdString(objError.write())));
            showError(tr("RPC Error: %1").arg(QString::fromStdString(objError.write())));
        }
    } catch (const std::exception& e) {
        statusText->append(tr("\n✗ Error: %1").arg(e.what()));
        showError(tr("Failed to rotate ICU: %1").arg(e.what()));
    }
}

void RotateICUDialog::showError(const QString& message)
{
    QMessageBox::critical(this, tr("Error"), message);
}

void RotateICUDialog::showSuccess(const QString& message)
{
    QMessageBox::information(this, tr("Success"), message);
}

bool RotateICUDialog::isAddressOwnedByWallet(const QString& address)
{
    if (!walletModel || !clientModel || address.isEmpty()) {
        return false;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(address.toStdString());
        UniValue result = clientModel->node().executeRpc("getaddressinfo", params, walletModel->getWalletName().toStdString());

        if (result.exists("ismine")) {
            return result.find_value("ismine").get_bool();
        }
        return false;
    } catch (...) {
        // If we can't determine, assume not owned for safety
        return false;
    }
}
