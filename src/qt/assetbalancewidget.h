// Copyright (c) 2024 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_ASSETBALANCEWIDGET_H
#define BITCOIN_QT_ASSETBALANCEWIDGET_H

#include <interfaces/wallet.h>

#include <QWidget>
#include <QFrame>
#include <memory>
#include <vector>

class WalletModel;
class ClientModel;
class PlatformStyle;

QT_BEGIN_NAMESPACE
class QLabel;
class QPushButton;
class QTableWidget;
class QVBoxLayout;
class QHBoxLayout;
QT_END_NAMESPACE

/** Widget for displaying asset balances on the overview page */
class AssetBalanceWidget : public QFrame
{
    Q_OBJECT

public:
    explicit AssetBalanceWidget(QWidget* parent = nullptr);
    ~AssetBalanceWidget();

    void setPlatformStyle(const PlatformStyle* platformStyle);
    void setWalletModel(WalletModel* walletModel);
    void setClientModel(ClientModel* clientModel);

public Q_SLOTS:
    void updateAssetBalances(const std::vector<interfaces::AssetBalance>& balances);
    void setPrivacy(bool privacy);
    void refreshBalances();

Q_SIGNALS:
    void assetClicked(const QString& assetId);
    void assetDoubleClicked(const QString& assetId);

private:
    static constexpr int COLUMN_TICKER = 0;
    static constexpr int COLUMN_BALANCE = 1;
    static constexpr int COLUMN_PENDING = 2;
    static constexpr int COLUMN_LOCKED = 3;
    static constexpr int COLUMN_UTXO = 4;

    void setupUi();
    QString formatAssetUnits(uint64_t units, uint8_t decimals, bool has_decimals) const;
    void updateTableRow(int row, const interfaces::AssetBalance& balance);
    void clearTable();

    WalletModel* walletModel{nullptr};
    ClientModel* clientModel{nullptr};
    const PlatformStyle* m_platform_style;
    bool m_privacy{false};

    // UI elements
    QVBoxLayout* mainLayout{nullptr};
    QHBoxLayout* headerLayout{nullptr};
    QLabel* titleLabel{nullptr};
    QPushButton* refreshButton{nullptr};
    QPushButton* toggleButton{nullptr};
    QTableWidget* assetTable{nullptr};
    QLabel* emptyLabel{nullptr};

    bool m_collapsed{false};
    std::vector<interfaces::AssetBalance> m_cached_balances;

private Q_SLOTS:
    void onToggleCollapsed();
    void onRefreshClicked();
    void onTableItemClicked(int row, int column);
    void onTableItemDoubleClicked(int row, int column);
    void onShowContextMenu(const QPoint& pos);
    void revealDekForRow(int row);
};

#endif // BITCOIN_QT_ASSETBALANCEWIDGET_H
