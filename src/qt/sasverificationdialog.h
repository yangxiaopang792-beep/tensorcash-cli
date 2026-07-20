// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_QT_SASVERIFICATIONDIALOG_H
#define BITCOIN_QT_SASVERIFICATIONDIALOG_H

#include <QDialog>
#include <QString>

QT_BEGIN_NAMESPACE
class QLabel;
class QPushButton;
QT_END_NAMESPACE

/**
 * @brief Dialog for verifying Short Authentication String (SAS)
 *
 * Displays the SAS to the user and provides instructions for
 * verbal verification with the peer.
 */
class SASVerificationDialog : public QDialog
{
    Q_OBJECT

public:
    explicit SASVerificationDialog(const QString& sas, const QString& sasNumeric, QWidget* parent = nullptr);
    // Optional auto-close countdown (in seconds). If >0, the dialog auto-accepts
    // after the countdown and hides the explicit "Verified" button, showing only
    // an Abort button and a visible countdown.
    explicit SASVerificationDialog(const QString& sas, const QString& sasNumeric, int autoCloseSeconds, QWidget* parent = nullptr);
    ~SASVerificationDialog();

Q_SIGNALS:
    // Emitted when the user explicitly clicks the Abort button because SAS
    // does not match. Callers can use this to terminate the underlying session.
    void sasAbortRequested();

private:
    void setupUI();
    void setupAutoClose(int seconds);

    QString sas;
    QString sasNumeric;

    QLabel* sasLabel{nullptr};
    QLabel* sasNumericLabel{nullptr};
    QLabel* countdownLabel{nullptr};
    QPushButton* verifiedButton{nullptr};
    QPushButton* abortButton{nullptr};

    int remainingSeconds{-1};
};

#endif // BITCOIN_QT_SASVERIFICATIONDIALOG_H
