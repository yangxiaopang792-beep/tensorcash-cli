// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/exportdescriptorsdialog.h>
#include <qt/walletmodel.h>
#include <qt/clientmodel.h>
#include <qt/guiutil.h>

#include <interfaces/node.h>
#include <univalue.h>

#include <QApplication>
#include <QButtonGroup>
#include <QClipboard>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QMessageBox>
#include <QVBoxLayout>

ExportDescriptorsDialog::ExportDescriptorsDialog(WalletModel* _walletModel, ClientModel* _clientModel, QWidget* parent)
    : QDialog(parent, GUIUtil::dialog_flags)
    , walletModel(_walletModel)
    , clientModel(_clientModel)
{
    setWindowTitle(tr("Export Descriptors for Hosted Wallet"));
    setMinimumSize(600, 560);

    auto* layout = new QVBoxLayout(this);

    // Export-mode selector. Watch-only is the default and the safe choice.
    auto* modeLabel = new QLabel(tr("Export type:"), this);
    layout->addWidget(modeLabel);

    watchOnlyRadio = new QRadioButton(
        tr("Watch-only (safe to share) — public descriptors, cannot spend"), this);
    fullBackupRadio = new QRadioButton(
        tr("Full backup (includes private keys) — for restoring this wallet only"), this);
    watchOnlyRadio->setChecked(true);
    auto* modeGroup = new QButtonGroup(this);
    modeGroup->addButton(watchOnlyRadio);
    modeGroup->addButton(fullBackupRadio);
    layout->addWidget(watchOnlyRadio);
    layout->addWidget(fullBackupRadio);

    // Red warning banner (only shown in full-backup mode)
    warningLabel = new QLabel(this);
    warningLabel->setWordWrap(true);
    warningLabel->setText(
        tr("<b style='color: #d32f2f;'>WARNING: This export contains your private keys.</b><br>"
           "Anyone with this data can spend your funds.<br>"
           "Do not share this file or clipboard content with anyone.<br>"
           "Delete any saved files after import is complete.<br>"
           "Only import into your own hosted wallet on a trusted device."));
    warningLabel->setStyleSheet(
        "QLabel { background-color: rgba(211, 47, 47, 0.1); border: 1px solid #d32f2f; "
        "border-radius: 6px; padding: 12px; }");
    layout->addWidget(warningLabel);

    // Confirmation checkbox
    confirmCheckbox = new QCheckBox(
        tr("I understand my private keys will be exposed and I will securely delete this export after use"), this);
    layout->addWidget(confirmCheckbox);

    // Generate button
    generateButton = new QPushButton(tr("Generate Export Bundle"), this);
    generateButton->setEnabled(false);
    layout->addWidget(generateButton);

    // Bundle text area (read-only, initially hidden)
    bundleTextEdit = new QPlainTextEdit(this);
    bundleTextEdit->setReadOnly(true);
    bundleTextEdit->setVisible(false);
    bundleTextEdit->setFont(QFont("Monospace", 9));
    bundleTextEdit->setMinimumHeight(200);
    layout->addWidget(bundleTextEdit);

    // Action buttons (initially hidden)
    auto* buttonLayout = new QHBoxLayout();
    copyButton = new QPushButton(tr("Copy to Clipboard"), this);
    copyButton->setVisible(false);
    saveButton = new QPushButton(tr("Save to File..."), this);
    saveButton->setVisible(false);
    buttonLayout->addWidget(copyButton);
    buttonLayout->addWidget(saveButton);
    layout->addLayout(buttonLayout);

    // Status label
    statusLabel = new QLabel(this);
    statusLabel->setStyleSheet("QLabel { color: #388e3c; }");
    layout->addWidget(statusLabel);

    // Close button
    closeButton = new QPushButton(tr("Close"), this);
    layout->addWidget(closeButton);

    // Clipboard auto-clear timer
    clipboardClearTimer = new QTimer(this);
    clipboardClearTimer->setSingleShot(true);
    connect(clipboardClearTimer, &QTimer::timeout, [this]() {
        QApplication::clipboard()->clear();
        statusLabel->setText(tr("Clipboard cleared for security."));
    });

    // Connections
    connect(watchOnlyRadio, &QRadioButton::toggled, this, &ExportDescriptorsDialog::updateModeUI);
    connect(fullBackupRadio, &QRadioButton::toggled, this, &ExportDescriptorsDialog::updateModeUI);
    connect(confirmCheckbox, &QCheckBox::toggled, this, &ExportDescriptorsDialog::updateModeUI);
    connect(generateButton, &QPushButton::clicked, this, &ExportDescriptorsDialog::generateBundle);
    connect(copyButton, &QPushButton::clicked, this, &ExportDescriptorsDialog::copyToClipboard);
    connect(saveButton, &QPushButton::clicked, this, &ExportDescriptorsDialog::saveToFile);
    connect(closeButton, &QPushButton::clicked, this, &QDialog::accept);

    // Apply initial (watch-only) state.
    updateModeUI();
}

ExportDescriptorsDialog::~ExportDescriptorsDialog() = default;

bool ExportDescriptorsDialog::isPrivateExport() const
{
    return fullBackupRadio && fullBackupRadio->isChecked();
}

void ExportDescriptorsDialog::updateModeUI()
{
    // The private-key warning + confirmation gate only apply to full backups.
    const bool priv = isPrivateExport();
    warningLabel->setVisible(priv);
    confirmCheckbox->setVisible(priv);

    if (priv) {
        // Full backup: require the explicit confirmation checkbox.
        generateButton->setEnabled(confirmCheckbox->isChecked());
    } else {
        // Watch-only: safe to share, no confirmation needed.
        generateButton->setEnabled(true);
    }
}

void ExportDescriptorsDialog::generateBundle()
{
    if (!walletModel || !clientModel) return;

    // Watch-only (default): listdescriptors(false) → normalized public
    // descriptors. Full backup: listdescriptors(true) → private keys.
    const bool priv = isPrivateExport();

    // Unlock if encrypted. On an unencrypted wallet this returns valid with no
    // prompt; ToNormalizedString for the watch-only path also benefits from the
    // wallet being unlocked if the last-hardened xpub cache is not yet present.
    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if (!ctx.isValid()) {
        statusLabel->setText(tr("Wallet unlock cancelled."));
        statusLabel->setStyleSheet("QLabel { color: #d32f2f; }");
        return;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(priv);
        UniValue result = clientModel->node().executeRpc(
            "listdescriptors", params, walletModel->getWalletName().toStdString());

        if (!result.isObject() || !result.exists("descriptors")) {
            statusLabel->setText(tr("Failed to retrieve descriptors from wallet."));
            statusLabel->setStyleSheet("QLabel { color: #d32f2f; }");
            return;
        }

        const UniValue& descriptors = result["descriptors"];
        if (!descriptors.isArray() || descriptors.empty()) {
            statusLabel->setText(tr("No descriptors found in wallet."));
            statusLabel->setStyleSheet("QLabel { color: #d32f2f; }");
            return;
        }

        // Detect chain/network from the running node via getblockchaininfo
        std::string network = "testnet";
        std::string chain = "tsc";
        try {
            UniValue chainInfo = clientModel->node().executeRpc("getblockchaininfo", UniValue(UniValue::VARR), "");
            std::string nodeChain = chainInfo["chain"].get_str();
            if (nodeChain == "tensor-test") {
                chain = "tsc"; network = "testnet";
            } else if (nodeChain == "tensor") {
                // ChainTypeToString(ChainType::TENSOR_MAIN) == "tensor"
                chain = "tsc"; network = "mainnet";
            } else if (nodeChain == "test" || nodeChain == "regtest" || nodeChain == "signet") {
                chain = "btc"; network = "testnet";
            } else if (nodeChain == "main") {
                chain = "btc"; network = "mainnet";
            }
        } catch (...) {
            // Fallback: infer network from descriptor key types
            for (size_t i = 0; i < descriptors.size(); ++i) {
                const std::string& desc = descriptors[i]["desc"].get_str();
                if (desc.find("xprv") != std::string::npos || desc.find("xpub") != std::string::npos) {
                    network = "mainnet";
                }
                break;
            }
        }

        // Group active descriptors by script type (wpkh → bip84, tr → bip86)
        struct DescFamily {
            std::string script_type;
            std::string external_desc;
            std::string internal_desc;
            int external_next_index{0};
            int internal_next_index{0};
            int64_t birth_timestamp{0}; // earliest timestamp in the family
        };
        std::map<std::string, DescFamily> families;

        for (size_t i = 0; i < descriptors.size(); ++i) {
            const UniValue& d = descriptors[i];
            if (!d.exists("active") || !d["active"].get_bool()) continue;

            const std::string& desc = d["desc"].get_str();
            bool is_internal = d.exists("internal") && d["internal"].get_bool();
            int next_index = d.exists("next_index") ? d["next_index"].getInt<int>() : 0;
            int64_t timestamp = d.exists("timestamp") ? d["timestamp"].getInt<int64_t>() : 0;

            // Determine script type from descriptor prefix
            std::string script_type;
            if (desc.substr(0, 5) == "wpkh(") {
                script_type = "bip84";
            } else if (desc.substr(0, 3) == "tr(") {
                script_type = "bip86";
            } else {
                continue; // skip unsupported types (pkh, wsh, etc.)
            }

            auto& fam = families[script_type];
            fam.script_type = script_type;
            if (is_internal) {
                fam.internal_desc = desc;
                fam.internal_next_index = next_index;
            } else {
                fam.external_desc = desc;
                fam.external_next_index = next_index;
            }
            // Use earliest timestamp across the family
            if (fam.birth_timestamp == 0 || (timestamp > 0 && timestamp < fam.birth_timestamp)) {
                fam.birth_timestamp = timestamp;
            }
        }

        // Build canonical bundle JSON
        UniValue bundle(UniValue::VOBJ);
        bundle.pushKV("version", 1);
        bundle.pushKV("chain", chain);
        bundle.pushKV("network", network);
        bundle.pushKV("export_type", priv ? "full" : "watch_only");

        UniValue scriptFamilies(UniValue::VARR);
        for (const auto& [type, fam] : families) {
            if (fam.external_desc.empty() || fam.internal_desc.empty()) continue;

            UniValue famObj(UniValue::VOBJ);
            famObj.pushKV("script_type", fam.script_type);

            UniValue ext(UniValue::VOBJ);
            ext.pushKV("descriptor", fam.external_desc);
            ext.pushKV("next_index", fam.external_next_index);
            famObj.pushKV("external", ext);

            UniValue intl(UniValue::VOBJ);
            intl.pushKV("descriptor", fam.internal_desc);
            intl.pushKV("next_index", fam.internal_next_index);
            famObj.pushKV("internal", intl);

            famObj.pushKV("birth_timestamp", fam.birth_timestamp);
            scriptFamilies.push_back(famObj);
        }
        bundle.pushKV("script_families", scriptFamilies);

        if (scriptFamilies.empty()) {
            statusLabel->setText(tr("No active wpkh or tr descriptor pairs found."));
            statusLabel->setStyleSheet("QLabel { color: #d32f2f; }");
            return;
        }

        // Pretty-print the JSON
        std::string bundleStr = bundle.write(2);
        bundleTextEdit->setPlainText(QString::fromStdString(bundleStr));
        bundleTextEdit->setVisible(true);
        copyButton->setVisible(true);
        saveButton->setVisible(true);
        generateButton->setEnabled(false);
        confirmCheckbox->setEnabled(false);
        watchOnlyRadio->setEnabled(false);
        fullBackupRadio->setEnabled(false);
        bundleGenerated = true;

        statusLabel->setText(priv
            ? tr("Full backup (private keys) generated with %1 descriptor family(ies).").arg(scriptFamilies.size())
            : tr("Watch-only bundle generated with %1 descriptor family(ies) — safe to share.").arg(scriptFamilies.size()));
        statusLabel->setStyleSheet("QLabel { color: #388e3c; }");

    } catch (const UniValue& objError) {
        statusLabel->setText(tr("RPC error: %1").arg(QString::fromStdString(objError.write())));
        statusLabel->setStyleSheet("QLabel { color: #d32f2f; }");
    } catch (const std::exception& e) {
        statusLabel->setText(tr("Error: %1").arg(e.what()));
        statusLabel->setStyleSheet("QLabel { color: #d32f2f; }");
    }
}

void ExportDescriptorsDialog::copyToClipboard()
{
    QApplication::clipboard()->setText(bundleTextEdit->toPlainText());
    if (isPrivateExport()) {
        // Private keys on the clipboard: auto-clear for safety.
        statusLabel->setText(tr("Copied to clipboard. Will auto-clear in 60 seconds."));
        clipboardClearTimer->start(60000);
    } else {
        statusLabel->setText(tr("Copied watch-only bundle to clipboard."));
    }
    statusLabel->setStyleSheet("QLabel { color: #388e3c; }");
}

void ExportDescriptorsDialog::saveToFile()
{
    QString filename = GUIUtil::getSaveFileName(this,
        tr("Save Descriptor Bundle"), QString(),
        tr("JSON Files") + QLatin1String(" (*.json)"), nullptr);
    if (filename.isEmpty()) return;

    QFile file(filename);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::critical(this, tr("Save Error"),
            tr("Could not write to file %1.").arg(filename));
        return;
    }
    file.write(bundleTextEdit->toPlainText().toUtf8());
    file.close();
    statusLabel->setText(isPrivateExport()
        ? tr("Saved to %1. Contains private keys — delete this file after import.").arg(filename)
        : tr("Saved watch-only bundle to %1.").arg(filename));
    statusLabel->setStyleSheet("QLabel { color: #388e3c; }");
}
