// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_IMPORTDESCRIPTORSDIALOG_H
#define BITCOIN_QT_IMPORTDESCRIPTORSDIALOG_H

#include <QDialog>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QCheckBox>
#include <QProgressBar>

class WalletController;
class ClientModel;

namespace interfaces {
class Node;
} // namespace interfaces

/**
 * Dialog for importing a DescriptorMigrationBundle JSON into a new blank
 * Core/Qt wallet. Creates a new descriptor wallet, then calls
 * importdescriptors with the bundle's private descriptors.
 */
class ImportDescriptorsDialog : public QDialog
{
    Q_OBJECT

public:
    explicit ImportDescriptorsDialog(WalletController* walletController, ClientModel* clientModel, QWidget* parent = nullptr);
    ~ImportDescriptorsDialog() override;

Q_SIGNALS:
    void walletImported(const QString& walletName);

private Q_SLOTS:
    void validateBundle();
    void loadFromFile();
    void doImport();

private:
    WalletController* walletController;
    ClientModel* clientModel;

    QPlainTextEdit* bundleTextEdit;
    QPushButton* loadFileButton;
    QLabel* previewLabel;
    QLineEdit* walletNameEdit;
    QLineEdit* passphraseEdit;
    QCheckBox* confirmSpendCheckbox;
    QCheckBox* confirmRescanCheckbox;
    QPushButton* importButton;
    QProgressBar* progressBar;
    QLabel* statusLabel;
    QPushButton* closeButton;

    // Parsed bundle state
    bool bundleValid{false};
    std::string parsedChain;
    std::string parsedNetwork;

    struct ParsedFamily {
        std::string script_type;
        std::string external_desc;
        std::string internal_desc;
        int external_next_index{0};
        int internal_next_index{0};
        int64_t birth_timestamp{0};
    };
    std::vector<ParsedFamily> parsedFamilies;
};

#endif // BITCOIN_QT_IMPORTDESCRIPTORSDIALOG_H
