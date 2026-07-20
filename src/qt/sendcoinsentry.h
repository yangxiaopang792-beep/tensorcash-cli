// Copyright (c) 2024-2025 The TensorCash Core developers
// Copyright (c) 2011-2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_SENDCOINSENTRY_H
#define BITCOIN_QT_SENDCOINSENTRY_H

#include <qt/sendcoinsrecipient.h>
#include <interfaces/wallet.h>

#include <QWidget>

class WalletModel;
class PlatformStyle;
class QComboBox;
class QLabel;

namespace interfaces {
class Node;
} // namespace interfaces

namespace Ui {
    class SendCoinsEntry;
}

/**
 * A single entry in the dialog for sending bitcoins.
 */
class SendCoinsEntry : public QWidget
{
    Q_OBJECT

public:
    explicit SendCoinsEntry(const PlatformStyle *platformStyle, QWidget *parent = nullptr);
    ~SendCoinsEntry();

    void setModel(WalletModel *model);
    bool validate(interfaces::Node& node);
    SendCoinsRecipient getValue();

    /** Return whether the entry is still empty and unedited */
    bool isClear();

    void setValue(const SendCoinsRecipient &value);
    void setAddress(const QString &address);
    void setAmount(const CAmount &amount);

    /** Set up the tab chain manually, as Qt messes up the tab chain by default in some cases
     *  (issue https://bugreports.qt-project.org/browse/QTBUG-10907).
     */
    QWidget *setupTabChain(QWidget *prev);

    void setFocus();

    // Asset-specific methods
    void updateAssetList();
    void setSelectedAsset(const QString& assetIdOrTicker);
    std::optional<uint256> getSelectedAsset() const;
    uint8_t getAssetDecimals() const;

public Q_SLOTS:
    void clear();
    void checkSubtractFeeFromAmount();
    void updateAssetSelection();

Q_SIGNALS:
    void removeEntry(SendCoinsEntry *entry);
    void useAvailableBalance(SendCoinsEntry* entry);
    void payAmountChanged();
    void subtractFeeFromAmountChanged();
    void assetSelectionChanged();

private Q_SLOTS:
    void deleteClicked();
    void useAvailableBalanceClicked();
    void on_payTo_textChanged(const QString &address);
    void on_addressBookButton_clicked();
    void on_pasteButton_clicked();
    void updateDisplayUnit();
    void on_assetComboBox_currentIndexChanged(int index);

protected:
    void changeEvent(QEvent* e) override;

private:
    SendCoinsRecipient recipient;
    Ui::SendCoinsEntry *ui;
    WalletModel* model{nullptr};
    const PlatformStyle *platformStyle;

    // Asset-related members
    QComboBox* assetComboBox{nullptr};
    std::vector<interfaces::AssetBalance> availableAssets;
    std::optional<uint256> selectedAssetId;

    // ML-DSA (Post-Quantum) related members
    QLabel* mldsaFeeWarningLabel{nullptr};
    QLabel* mldsaAddressTypeBadge{nullptr};

    bool updateLabel(const QString &address);
    void updateAssetUnitLabel();
    void updateMLDSAWarnings(const QString &address);
};

#endif // BITCOIN_QT_SENDCOINSENTRY_H
