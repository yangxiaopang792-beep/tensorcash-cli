// Copyright (c) 2024-2025 The TensorCash Core developers
// Copyright (c) 2011-2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_RECEIVECOINSDIALOG_H
#define BITCOIN_QT_RECEIVECOINSDIALOG_H

#include <qt/guiutil.h>

#include <QDialog>
#include <QHeaderView>
#include <QItemSelection>
#include <QKeyEvent>
#include <QMenu>
#include <QPoint>
#include <QVariant>
#include <QComboBox>
#include <QSortFilterProxyModel>

#include <uint256.h>
#include <optional>

class PlatformStyle;
class WalletModel;

namespace Ui {
    class ReceiveCoinsDialog;
}

QT_BEGIN_NAMESPACE
class QModelIndex;
class QLabel;
QT_END_NAMESPACE

/** Dialog for requesting payment of bitcoins */
class ReceiveCoinsDialog : public QDialog
{
    Q_OBJECT

public:
    enum ColumnWidths {
        DATE_COLUMN_WIDTH = 130,
        LABEL_COLUMN_WIDTH = 120,
        AMOUNT_MINIMUM_COLUMN_WIDTH = 180,
        MINIMUM_COLUMN_WIDTH = 130
    };

    explicit ReceiveCoinsDialog(const PlatformStyle *platformStyle, QWidget *parent = nullptr);
    ~ReceiveCoinsDialog();

    void setModel(WalletModel *model);

public Q_SLOTS:
    void clear();
    void reject() override;
    void accept() override;

private:
    Ui::ReceiveCoinsDialog *ui;
    WalletModel* model{nullptr};
    QMenu *contextMenu;
    QAction* copyLabelAction;
    QAction* copyMessageAction;
    QAction* copyAmountAction;
    const PlatformStyle *platformStyle;

    // Asset-related members
    QComboBox* assetComboBox;
    QSortFilterProxyModel* requestsProxyModel{nullptr};

    // ML-DSA (Post-Quantum) related members
    QComboBox* mldsaSecurityLevelCombo{nullptr};
    QLabel* mldsaWarningLabel{nullptr};
    QLabel* mldsaSecurityBadge{nullptr};
    QLabel* mldsaFeeWarningLabel{nullptr};

    QModelIndex selectedRow();
    void copyColumnToClipboard(int column);
    void populateAssetComboBox();
    void populateAssetFilterComboBox();
    void updateAssetSelection();
    void updateAssetUnitLabel();
    std::optional<uint256> getSelectedAsset() const;
    uint8_t getAssetDecimals(const uint256& assetId) const;

    // ML-DSA methods
    void updateMLDSAUIVisibility();
    int getSelectedMLDSALevel() const;
    void showMLDSABackupWarning();

private Q_SLOTS:
    void on_receiveButton_clicked();
    void on_showRequestButton_clicked();
    void on_removeRequestButton_clicked();
    void on_recentRequestsView_doubleClicked(const QModelIndex &index);
    void recentRequestsView_selectionChanged(const QItemSelection &selected, const QItemSelection &deselected);
    void updateDisplayUnit();
    void showMenu(const QPoint &point);
    void copyURI();
    void copyAddress();
    void copyLabel();
    void copyMessage();
    void copyAmount();
    void on_assetComboBox_currentIndexChanged(int index);
    void on_assetFilterComboBox_currentIndexChanged(int index);
    void on_addressType_currentIndexChanged(int index);
    void on_mldsaSecurityLevel_currentIndexChanged(int index);
};

#endif // BITCOIN_QT_RECEIVECOINSDIALOG_H
