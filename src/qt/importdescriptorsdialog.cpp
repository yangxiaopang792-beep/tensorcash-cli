// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/importdescriptorsdialog.h>
#include <qt/clientmodel.h>
#include <qt/guiutil.h>
#include <qt/walletcontroller.h>

#include <interfaces/node.h>
#include <univalue.h>

#include <QApplication>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QMessageBox>
#include <QThread>
#include <QVBoxLayout>

ImportDescriptorsDialog::ImportDescriptorsDialog(WalletController* _walletController, ClientModel* _clientModel, QWidget* parent)
    : QDialog(parent, GUIUtil::dialog_flags)
    , walletController(_walletController)
    , clientModel(_clientModel)
{
    setWindowTitle(tr("Import Descriptors from Hosted Wallet"));
    setMinimumSize(600, 560);

    auto* layout = new QVBoxLayout(this);

    // Bundle input
    auto* inputHeader = new QHBoxLayout();
    auto* inputLabel = new QLabel(tr("Migration Bundle JSON:"), this);
    loadFileButton = new QPushButton(tr("Load .json file..."), this);
    inputHeader->addWidget(inputLabel);
    inputHeader->addStretch();
    inputHeader->addWidget(loadFileButton);
    layout->addLayout(inputHeader);

    bundleTextEdit = new QPlainTextEdit(this);
    bundleTextEdit->setFont(QFont("Monospace", 9));
    bundleTextEdit->setMinimumHeight(140);
    bundleTextEdit->setPlaceholderText(tr("Paste the JSON bundle exported from the hosted wallet, or load a .json file"));
    layout->addWidget(bundleTextEdit);

    // Preview
    previewLabel = new QLabel(this);
    previewLabel->setWordWrap(true);
    previewLabel->setStyleSheet("QLabel { padding: 8px; border-radius: 4px; }");
    layout->addWidget(previewLabel);

    // Wallet name
    auto* nameLayout = new QHBoxLayout();
    nameLayout->addWidget(new QLabel(tr("New wallet name:"), this));
    walletNameEdit = new QLineEdit(this);
    walletNameEdit->setPlaceholderText(tr("e.g. imported-hosted-wallet"));
    nameLayout->addWidget(walletNameEdit);
    layout->addLayout(nameLayout);

    // Optional passphrase
    auto* passLayout = new QHBoxLayout();
    passLayout->addWidget(new QLabel(tr("Encryption passphrase (optional):"), this));
    passphraseEdit = new QLineEdit(this);
    passphraseEdit->setEchoMode(QLineEdit::Password);
    passphraseEdit->setPlaceholderText(tr("Leave empty for unencrypted wallet"));
    passLayout->addWidget(passphraseEdit);
    layout->addLayout(passLayout);

    // Warnings and confirmations
    auto* warningLabel = new QLabel(this);
    warningLabel->setWordWrap(true);
    warningLabel->setText(
        tr("<b>Importing private descriptors gives this wallet full spending authority</b> "
           "over the funds controlled by these keys. A blockchain rescan will occur to "
           "discover historical transactions. With birth_timestamp=0 (full rescan), "
           "this scans the entire chain and may take several minutes."));
    warningLabel->setStyleSheet(
        "QLabel { background-color: rgba(255, 152, 0, 0.1); border: 1px solid #ff9800; "
        "border-radius: 6px; padding: 10px; }");
    layout->addWidget(warningLabel);

    confirmSpendCheckbox = new QCheckBox(
        tr("I understand this creates a live copy of my hosted wallet keys"), this);
    layout->addWidget(confirmSpendCheckbox);

    confirmRescanCheckbox = new QCheckBox(
        tr("I understand a blockchain rescan will occur"), this);
    layout->addWidget(confirmRescanCheckbox);

    // Import button
    importButton = new QPushButton(tr("Create Wallet && Import Descriptors"), this);
    importButton->setEnabled(false);
    layout->addWidget(importButton);

    // Progress
    progressBar = new QProgressBar(this);
    progressBar->setRange(0, 0); // indeterminate
    progressBar->setVisible(false);
    layout->addWidget(progressBar);

    // Status
    statusLabel = new QLabel(this);
    layout->addWidget(statusLabel);

    // Close
    closeButton = new QPushButton(tr("Close"), this);
    layout->addWidget(closeButton);

    // Enable import only when all conditions met
    auto updateImportEnabled = [this]() {
        importButton->setEnabled(
            bundleValid &&
            !walletNameEdit->text().trimmed().isEmpty() &&
            confirmSpendCheckbox->isChecked() &&
            confirmRescanCheckbox->isChecked());
    };

    connect(bundleTextEdit, &QPlainTextEdit::textChanged, this, &ImportDescriptorsDialog::validateBundle);
    connect(walletNameEdit, &QLineEdit::textChanged, [=]() { updateImportEnabled(); });
    connect(confirmSpendCheckbox, &QCheckBox::toggled, [=]() { updateImportEnabled(); });
    connect(confirmRescanCheckbox, &QCheckBox::toggled, [=]() { updateImportEnabled(); });
    connect(loadFileButton, &QPushButton::clicked, this, &ImportDescriptorsDialog::loadFromFile);
    connect(importButton, &QPushButton::clicked, this, &ImportDescriptorsDialog::doImport);
    connect(closeButton, &QPushButton::clicked, this, &QDialog::accept);
}

ImportDescriptorsDialog::~ImportDescriptorsDialog() = default;

void ImportDescriptorsDialog::validateBundle()
{
    bundleValid = false;
    parsedFamilies.clear();
    previewLabel->clear();

    QString text = bundleTextEdit->toPlainText().trimmed();
    if (text.isEmpty()) return;

    try {
        UniValue bundle;
        if (!bundle.read(text.toStdString())) {
            previewLabel->setText(tr("Invalid JSON."));
            previewLabel->setStyleSheet("QLabel { color: #d32f2f; padding: 8px; }");
            return;
        }

        if (!bundle.exists("version") || bundle["version"].getInt<int>() != 1) {
            previewLabel->setText(tr("Unsupported bundle version (expected 1)."));
            previewLabel->setStyleSheet("QLabel { color: #d32f2f; padding: 8px; }");
            return;
        }

        if (!bundle.exists("chain") || !bundle.exists("network") || !bundle.exists("script_families")) {
            previewLabel->setText(tr("Missing required fields: chain, network, or script_families."));
            previewLabel->setStyleSheet("QLabel { color: #d32f2f; padding: 8px; }");
            return;
        }

        parsedChain = bundle["chain"].get_str();
        parsedNetwork = bundle["network"].get_str();

        const UniValue& families = bundle["script_families"];
        if (!families.isArray() || families.empty()) {
            previewLabel->setText(tr("Bundle contains no descriptor families."));
            previewLabel->setStyleSheet("QLabel { color: #d32f2f; padding: 8px; }");
            return;
        }

        QString preview = tr("<b>Bundle validated:</b><br>"
                             "Chain: %1 | Network: %2<br>")
                              .arg(QString::fromStdString(parsedChain).toUpper())
                              .arg(QString::fromStdString(parsedNetwork));

        for (size_t i = 0; i < families.size(); ++i) {
            const UniValue& fam = families[i];
            ParsedFamily pf;
            pf.script_type = fam["script_type"].get_str();
            pf.external_desc = fam["external"]["descriptor"].get_str();
            pf.internal_desc = fam["internal"]["descriptor"].get_str();
            pf.external_next_index = fam["external"].exists("next_index") ? fam["external"]["next_index"].getInt<int>() : 0;
            pf.internal_next_index = fam["internal"].exists("next_index") ? fam["internal"]["next_index"].getInt<int>() : 0;
            pf.birth_timestamp = fam.exists("birth_timestamp") ? fam["birth_timestamp"].getInt<int64_t>() : 0;

            // Verify private key material present
            if (pf.external_desc.find("xprv") == std::string::npos &&
                pf.external_desc.find("tprv") == std::string::npos) {
                previewLabel->setText(tr("Family %1: external descriptor has no private key.").arg(QString::fromStdString(pf.script_type)));
                previewLabel->setStyleSheet("QLabel { color: #d32f2f; padding: 8px; }");
                return;
            }

            preview += tr("%1: ext idx=%2, int idx=%3%4<br>")
                           .arg(QString::fromStdString(pf.script_type))
                           .arg(pf.external_next_index)
                           .arg(pf.internal_next_index)
                           .arg(pf.birth_timestamp == 0 ? tr(" (full rescan)") :
                                tr(" (birth: %1)").arg(pf.birth_timestamp));

            parsedFamilies.push_back(pf);
        }

        previewLabel->setText(preview);
        previewLabel->setStyleSheet("QLabel { color: #388e3c; background-color: rgba(56, 142, 60, 0.05); "
                                    "border: 1px solid rgba(56, 142, 60, 0.3); padding: 8px; border-radius: 4px; }");
        bundleValid = true;

    } catch (const std::exception& e) {
        previewLabel->setText(tr("Parse error: %1").arg(e.what()));
        previewLabel->setStyleSheet("QLabel { color: #d32f2f; padding: 8px; }");
    }

    // Trigger import button state update
    importButton->setEnabled(
        bundleValid &&
        !walletNameEdit->text().trimmed().isEmpty() &&
        confirmSpendCheckbox->isChecked() &&
        confirmRescanCheckbox->isChecked());
}

void ImportDescriptorsDialog::loadFromFile()
{
    QString filename = GUIUtil::getOpenFileName(this,
        tr("Load Descriptor Bundle"), QString(),
        tr("JSON Files") + QLatin1String(" (*.json)"), nullptr);
    if (filename.isEmpty()) return;

    QFile file(filename);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        statusLabel->setText(tr("Could not open file."));
        statusLabel->setStyleSheet("QLabel { color: #d32f2f; }");
        return;
    }
    bundleTextEdit->setPlainText(QString::fromUtf8(file.readAll()));
    file.close();
}

void ImportDescriptorsDialog::doImport()
{
    if (!walletController || !clientModel || parsedFamilies.empty()) return;

    QString walletName = walletNameEdit->text().trimmed();
    if (walletName.isEmpty()) return;

    // Disable UI during import
    importButton->setEnabled(false);
    bundleTextEdit->setEnabled(false);
    walletNameEdit->setEnabled(false);
    passphraseEdit->setEnabled(false);
    loadFileButton->setEnabled(false);
    progressBar->setVisible(true);
    statusLabel->setText(tr("Creating wallet and importing descriptors..."));
    statusLabel->setStyleSheet("QLabel { color: #1976d2; }");

    QApplication::processEvents();

    try {
        // Step 0: Validate bundle chain/network against this node
        UniValue chainInfo = clientModel->node().executeRpc("getblockchaininfo", UniValue(UniValue::VARR), "");
        std::string nodeChain = chainInfo["chain"].get_str();

        // Map node chain name to bundle chain/network expectations
        // (chain names per ChainTypeToString, util/chaintype.cpp)
        // tensor-test → chain=tsc, network=testnet
        // tensor → chain=tsc, network=mainnet
        // test/regtest → chain=btc, network=testnet
        // main → chain=btc, network=mainnet
        bool chainMatch = false;
        if (nodeChain == "tensor-test") {
            chainMatch = (parsedChain == "tsc" && parsedNetwork == "testnet");
        } else if (nodeChain == "tensor") {
            chainMatch = (parsedChain == "tsc" && parsedNetwork == "mainnet");
        } else if (nodeChain == "test" || nodeChain == "regtest" || nodeChain == "signet") {
            chainMatch = (parsedChain == "btc" && parsedNetwork == "testnet");
        } else if (nodeChain == "main") {
            chainMatch = (parsedChain == "btc" && parsedNetwork == "mainnet");
        }

        if (!chainMatch) {
            QMessageBox::critical(this, tr("Chain Mismatch"),
                tr("This bundle is for %1/%2 but this node runs on chain '%3'.\n"
                   "Import aborted to prevent importing descriptors for the wrong network.")
                    .arg(QString::fromStdString(parsedChain).toUpper())
                    .arg(QString::fromStdString(parsedNetwork))
                    .arg(QString::fromStdString(nodeChain)));
            progressBar->setVisible(false);
            statusLabel->setText(tr("Import aborted: chain/network mismatch."));
            statusLabel->setStyleSheet("QLabel { color: #d32f2f; }");
            bundleTextEdit->setEnabled(true);
            walletNameEdit->setEnabled(true);
            passphraseEdit->setEnabled(true);
            loadFileButton->setEnabled(true);
            return;
        }

        // Step 1: Create a new blank descriptor wallet
        std::string passphrase = passphraseEdit->text().toStdString();

        UniValue createParams(UniValue::VARR);
        createParams.push_back(walletName.toStdString()); // wallet_name
        createParams.push_back(false);                     // disable_private_keys
        createParams.push_back(true);                      // blank
        createParams.push_back(passphrase);                // passphrase (empty = unencrypted)
        createParams.push_back(false);                     // avoid_reuse
        createParams.push_back(true);                      // descriptors

        UniValue createResult = clientModel->node().executeRpc("createwallet", createParams, "");

        std::string createdName = createResult["name"].get_str();
        statusLabel->setText(tr("Wallet '%1' created. Importing descriptors...").arg(QString::fromStdString(createdName)));
        QApplication::processEvents();

        // Step 2: If encrypted, unlock it for import
        if (!passphrase.empty()) {
            UniValue unlockParams(UniValue::VARR);
            unlockParams.push_back(passphrase);
            unlockParams.push_back(600); // 10 minute timeout
            clientModel->node().executeRpc("walletpassphrase", unlockParams, createdName);
        }

        // Step 3: Build importdescriptors request
        UniValue importRequests(UniValue::VARR);

        for (const auto& fam : parsedFamilies) {
            // External descriptor
            UniValue extReq(UniValue::VOBJ);
            extReq.pushKV("desc", fam.external_desc);
            extReq.pushKV("active", true);
            extReq.pushKV("timestamp", fam.birth_timestamp);
            extReq.pushKV("internal", false);
            if (fam.external_next_index > 0) {
                extReq.pushKV("next_index", fam.external_next_index);
            }
            importRequests.push_back(extReq);

            // Internal descriptor
            UniValue intReq(UniValue::VOBJ);
            intReq.pushKV("desc", fam.internal_desc);
            intReq.pushKV("active", true);
            intReq.pushKV("timestamp", fam.birth_timestamp);
            intReq.pushKV("internal", true);
            if (fam.internal_next_index > 0) {
                intReq.pushKV("next_index", fam.internal_next_index);
            }
            importRequests.push_back(intReq);
        }

        UniValue importParams(UniValue::VARR);
        importParams.push_back(importRequests);

        statusLabel->setText(tr("Importing %1 descriptors and rescanning...").arg(importRequests.size()));
        QApplication::processEvents();

        UniValue importResult = clientModel->node().executeRpc("importdescriptors", importParams, createdName);

        // Step 4: Check results
        bool allSuccess = true;
        QString warnings;
        if (importResult.isArray()) {
            for (size_t i = 0; i < importResult.size(); ++i) {
                const UniValue& r = importResult[i];
                if (!r.exists("success") || !r["success"].get_bool()) {
                    allSuccess = false;
                    if (r.exists("error")) {
                        warnings += QString::fromStdString(r["error"]["message"].get_str()) + "\n";
                    }
                }
            }
        }

        // Step 5: Lock wallet again if it was encrypted
        if (!passphrase.empty()) {
            try {
                UniValue lockParams(UniValue::VARR);
                clientModel->node().executeRpc("walletlock", lockParams, createdName);
            } catch (...) { /* non-fatal */ }
        }

        progressBar->setVisible(false);

        if (allSuccess) {
            statusLabel->setText(tr("Import successful! Wallet '%1' is ready. "
                                    "You can load it from File > Open Wallet.").arg(walletName));
            statusLabel->setStyleSheet("QLabel { color: #388e3c; font-weight: bold; }");
            Q_EMIT walletImported(walletName);
        } else {
            statusLabel->setText(tr("Import completed with warnings:\n%1").arg(warnings));
            statusLabel->setStyleSheet("QLabel { color: #ff9800; }");
        }

    } catch (const UniValue& objError) {
        progressBar->setVisible(false);
        statusLabel->setText(tr("RPC error: %1").arg(QString::fromStdString(objError.write())));
        statusLabel->setStyleSheet("QLabel { color: #d32f2f; }");
    } catch (const std::exception& e) {
        progressBar->setVisible(false);
        statusLabel->setText(tr("Error: %1").arg(e.what()));
        statusLabel->setStyleSheet("QLabel { color: #d32f2f; }");
    }

    // Re-enable UI
    bundleTextEdit->setEnabled(true);
    walletNameEdit->setEnabled(true);
    passphraseEdit->setEnabled(true);
    loadFileButton->setEnabled(true);
}
