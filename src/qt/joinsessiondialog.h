// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_QT_JOINSESSIONDIALOG_H
#define BITCOIN_QT_JOINSESSIONDIALOG_H

#include <QDialog>

class WalletModel;

QT_BEGIN_NAMESPACE
class QLineEdit;
class QPushButton;
class QTextEdit;
QT_END_NAMESPACE

/**
 * @brief Dialog for joining an existing cosign bridge session
 *
 * Allows the user to paste an invite link or scan a QR code
 * to join a session created by another party.
 */
class JoinSessionDialog : public QDialog
{
    Q_OBJECT

public:
    explicit JoinSessionDialog(WalletModel* model, QWidget* parent = nullptr);
    ~JoinSessionDialog();

    QString getSessionId() const { return sessionId; }
    QString getSAS() const { return sas; }
    QString getSASNumeric() const { return sasNumeric; }

private Q_SLOTS:
    void onJoinSession();
    void onPasteFromClipboard();

private:
    void setupUI();

    WalletModel* walletModel{nullptr};

    QTextEdit* inviteLinkEdit{nullptr};
    QLineEdit* contextEdit{nullptr};
    QPushButton* pasteButton{nullptr};
    QPushButton* joinButton{nullptr};
    QPushButton* cancelButton{nullptr};

    // Session data
    QString sessionId;
    QString sas;
    QString sasNumeric;
};

#endif // BITCOIN_QT_JOINSESSIONDIALOG_H
