// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_QT_STARTSESSIONDIALOG_H
#define BITCOIN_QT_STARTSESSIONDIALOG_H

#include <QDialog>

class QRImageWidget;
class WalletModel;

QT_BEGIN_NAMESPACE
class QComboBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QSpinBox;
class QTextEdit;
QT_END_NAMESPACE

/**
 * @brief Dialog for creating a new cosign bridge session
 *
 * Allows the user to configure and create a new session,
 * then displays the invite link with QR code for sharing.
 */
class StartSessionDialog : public QDialog
{
    Q_OBJECT

public:
    explicit StartSessionDialog(WalletModel* model, QWidget* parent = nullptr);
    ~StartSessionDialog();

    QString getSessionId() const { return sessionId; }
    QString getSAS() const { return sas; }
    QString getSASNumeric() const { return sasNumeric; }
    QString getTransport() const { return transport; }
    QString getRelayUrl() const { return relay_url; }

private Q_SLOTS:
    void onCreateSession();
    void onCopyInviteLink();
    void onShowQRCode();
    void onTransportChanged(int index);

private:
    void setupUI();
    void showStep1();
    void showStep2();

    WalletModel* walletModel{nullptr};

    // Step 1: Configuration
    QLineEdit* contextEdit{nullptr};
    QComboBox* transportCombo{nullptr};
    QLineEdit* relayUrlEdit{nullptr};
    QLabel* relayUrlLabel{nullptr};
    QSpinBox* ttlSpinBox{nullptr};
    QPushButton* createButton{nullptr};
    QPushButton* cancelButton{nullptr};

    // Step 2: Display invite
    QTextEdit* inviteLinkEdit{nullptr};
    QLabel* sessionIdLabel{nullptr};
    QPushButton* copyLinkButton{nullptr};
    QPushButton* showQRButton{nullptr};
    QPushButton* doneButton{nullptr};

    // QR Code dialog
    QRImageWidget* qrWidget{nullptr};

    // Session data
    QString sessionId;
    QString inviteLink;
    QString sas;
    QString sasNumeric;
    QString qrData;
    QString transport;
    QString relay_url;

    // UI containers for steps
    QWidget* step1Widget{nullptr};
    QWidget* step2Widget{nullptr};
};

#endif // BITCOIN_QT_STARTSESSIONDIALOG_H
