// Copyright (c) 2024 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_ROTATEICUDIALOG_H
#define BITCOIN_QT_ROTATEICUDIALOG_H

#include <QDialog>
#include <QMap>
#include <QString>

class WalletModel;
class ClientModel;
class PlatformStyle;

QT_BEGIN_NAMESPACE
class QComboBox;
class QLineEdit;
class QPushButton;
class QLabel;
class QTextEdit;
QT_END_NAMESPACE

/** Dialog for rotating ICU for an asset */
class RotateICUDialog : public QDialog
{
    Q_OBJECT

public:
    explicit RotateICUDialog(const PlatformStyle* platformStyle, QWidget* parent = nullptr);
    ~RotateICUDialog();

    void setWalletModel(WalletModel* walletModel);
    void setClientModel(ClientModel* clientModel);

    /** Set the asset list (to avoid slow scanning) */
    void setAssetList(const QMap<QString, QString>& assets);

    /** Set the asset to rotate ICU for */
    void setAsset(const QString& assetId);

public Q_SLOTS:
    void refreshAssetList();

Q_SIGNALS:
    void message(const QString& title, const QString& message, unsigned int style);

private:
    WalletModel* walletModel{nullptr};
    ClientModel* clientModel{nullptr};
    const PlatformStyle* m_platform_style;

    // UI components
    QComboBox* assetCombo{nullptr};
    QLabel* currentICULabel{nullptr};
    QLabel* currentBondLabel{nullptr};
    QLabel* feesLabel{nullptr};
    QLabel* minBondLabel{nullptr};
    QLineEdit* newICUAddressEdit{nullptr};
    QLineEdit* newBondEdit{nullptr};
    QPushButton* rotateButton{nullptr};
    QPushButton* refreshButton{nullptr};
    QTextEdit* statusText{nullptr};

    // Helper methods
    void updateAssetInfo(const QString& assetId);
    void showError(const QString& message);
    void showSuccess(const QString& message);
    bool isAddressOwnedByWallet(const QString& address);

private Q_SLOTS:
    void onAssetSelected(int index);
    void onRotateICU();
    void onRefresh();
    void onGenerateTaproot();
};

#endif // BITCOIN_QT_ROTATEICUDIALOG_H
