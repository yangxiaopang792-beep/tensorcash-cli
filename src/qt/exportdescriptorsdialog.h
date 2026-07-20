// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_EXPORTDESCRIPTORSDIALOG_H
#define BITCOIN_QT_EXPORTDESCRIPTORSDIALOG_H

#include <QDialog>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QLabel>
#include <QCheckBox>
#include <QRadioButton>
#include <QTimer>

class WalletModel;
class ClientModel;

/**
 * Dialog for exporting wallet descriptors as a canonical migration bundle
 * for import into the hosted wallet (or another Core/Qt wallet).
 *
 * Two explicit export modes:
 *   - Watch-only (default, safe to share): listdescriptors(false) → normalized
 *     account-level public descriptors (wpkh([fp/84h/.../0h]xpub/0/*)). No
 *     private keys; suitable for payout/watch-only registration.
 *   - Full backup (includes private keys): listdescriptors(true) → master-rooted
 *     private descriptors for restoring a wallet. Gated behind a warning + an
 *     explicit confirmation checkbox.
 * Formats the output as the canonical DescriptorMigrationBundle JSON, tagged
 * with "export_type": "watch_only" | "full".
 */
class ExportDescriptorsDialog : public QDialog
{
    Q_OBJECT

public:
    explicit ExportDescriptorsDialog(WalletModel* walletModel, ClientModel* clientModel, QWidget* parent = nullptr);
    ~ExportDescriptorsDialog() override;

private Q_SLOTS:
    void generateBundle();
    void copyToClipboard();
    void saveToFile();
    void updateModeUI();

private:
    // True when the "Full backup (includes private keys)" mode is selected.
    bool isPrivateExport() const;

    WalletModel* walletModel;
    ClientModel* clientModel;

    QRadioButton* watchOnlyRadio;
    QRadioButton* fullBackupRadio;
    QLabel* warningLabel;
    QCheckBox* confirmCheckbox;
    QPlainTextEdit* bundleTextEdit;
    QPushButton* generateButton;
    QPushButton* copyButton;
    QPushButton* saveButton;
    QPushButton* closeButton;
    QLabel* statusLabel;
    QTimer* clipboardClearTimer;

    bool bundleGenerated{false};
};

#endif // BITCOIN_QT_EXPORTDESCRIPTORSDIALOG_H
