// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_QT_IMPORTOFFERDIALOG_H
#define BITCOIN_QT_IMPORTOFFERDIALOG_H

#include <QDialog>

class WalletModel;
class BridgeSessionManager;

QT_BEGIN_NAMESPACE
class QComboBox;
class QLabel;
class QPushButton;
class QTextEdit;
QT_END_NAMESPACE

/**
 * @brief Dialog for importing contract offers
 *
 * Allows importing offers via:
 * 1. Manual JSON paste
 * 2. File selection
 * 3. Active cosign session
 */
class ImportOfferDialog : public QDialog
{
    Q_OBJECT

public:
    explicit ImportOfferDialog(WalletModel* model, BridgeSessionManager* sessionManager, QWidget* parent = nullptr);
    ~ImportOfferDialog();

    QString getOfferId() const { return offerId; }
    QString getContractType() const { return contractType; }
    QString getOfferJson() const { return offerJson; }

private Q_SLOTS:
    void onImportMethodChanged(int index);
    void onPasteFromClipboard();
    void onLoadFromFile();
    void onReceiveFromSession();
    void onImport();

private:
    void setupUI();
    bool validateAndImportOffer(const QString& json);

    WalletModel* walletModel{nullptr};
    BridgeSessionManager* sessionManager{nullptr};

    // UI components
    QComboBox* methodCombo{nullptr};
    QTextEdit* offerJsonEdit{nullptr};
    QPushButton* pasteButton{nullptr};
    QPushButton* loadFileButton{nullptr};
    QComboBox* sessionCombo{nullptr};
    QPushButton* receiveButton{nullptr};
    QLabel* statusLabel{nullptr};
    QPushButton* importButton{nullptr};
    QPushButton* cancelButton{nullptr};

    // Import results
    QString offerId;
    QString contractType;
    QString offerJson;
};

#endif // BITCOIN_QT_IMPORTOFFERDIALOG_H
