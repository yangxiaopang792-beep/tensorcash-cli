// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_QT_ASSETPRICETAB_H
#define BITCOIN_QT_ASSETPRICETAB_H

#include <QPointer>
#include <QWidget>
#include <QHash>
#include <QMap>
#include <QString>

#include <qt/pricefeed.h>

class PlatformStyle;
class WalletModel;
class PriceFeed;

QT_BEGIN_NAMESPACE
class QLabel;
class QPushButton;
class QTableWidget;
class QLineEdit;
class QComboBox;
class QDoubleSpinBox;
class QSpinBox;
class QMenu;
class QDialogButtonBox;
QT_END_NAMESPACE

/**
 * @brief Asset pricing data for marks and market
 */
struct AssetPricingData {
    QString assetId;        // Asset ID hex string (empty for TSC)
    QString ticker;         // Asset ticker symbol
    bool isNative{true};    // True for TSC

    // Market data (user editable)
    double marketFX{1.0};
    double marketRate{0.0};
    double marketSigma{0.0};

    // Marks data (from pricer defaults, then committable)
    double markFX{1.0};
    double markRate{0.0};
    double markSigma{0.0};

    AssetPricingData() = default;
    AssetPricingData(QString id, QString tick, bool native = false)
        : assetId(id), ticker(tick), isNative(native) {}
};

/**
 * @brief Asset Price tab - P2P Exchange pricing interface
 *
 * Manages market and mark pricing for all assets (TSC, wallet assets, and registry assets).
 * Market prices are user-editable. Mark prices can be copied from market and committed to the pricer.
 */
class AssetPriceTab : public QWidget
{
    Q_OBJECT

public:
    explicit AssetPriceTab(const PlatformStyle* platformStyle, QWidget* parent = nullptr);
    ~AssetPriceTab();

    void setWalletModel(WalletModel* model);

    /** Get price of an asset in TSC (from market data) */
    double getAssetPriceInTSC(const QString& assetSymbol) const;

Q_SIGNALS:
    /** Emitted when prices are updated */
    void pricesUpdated();

private Q_SLOTS:
    void onCellChanged(int row, int column);
    void onCopyFromMarket();
    void onCommitMarks();
    void onCalibrateFromMarket();
    void onSelectDataFeed();
    void refreshAssetList();

    // Matrix dialogs
    void onShowMarksFXMatrix();
    void onShowMarksCorrelMatrix();
    void onShowMarksRatesCurves();
    void onShowMarketFXMatrix();
    void onShowMarketCorrelMatrix();
    void onShowMarketRatesCurves();

private:
    void setupUI();
    void updateTable();
    void loadSettings();
    void saveSettings();
    void pushToWallet();

    // Matrix dialog helpers
    void showFXMatrix(bool isMarks);
    void showCorrelationMatrix(bool isMarks);
    void showRatesCurves(bool isMarks);

    // QPointer auto-nulls on WalletModel destruction so refresh slots
    // survive wallet unload / app shutdown.
    QPointer<WalletModel> walletModel;
    const PlatformStyle* platformStyle;

    // UI components
    QTableWidget* priceTable;

    // Asset data storage (ticker -> pricing data)
    QMap<QString, AssetPricingData> assetData;

    // Helper methods
    double normalizePriceForFX(double displayPrice, const QString& asset_id) const;
    int assetDecimals(const QString& asset_id) const;
    mutable QHash<QString, int> assetDecimalsCache;
    bool isPricerDefault(const AssetPricingData& data) const;

    // --- Live market data feed (sovereign, direct external — no gateway) ---
    // Read the on-chain `price_oracle` hint (ICU witness_bundle) for an asset.
    // Returns an invalid descriptor when absent/unparseable. Always unverified.
    PriceDescriptor readOnchainPriceOracle(const QString& assetId) const;
    void applyMarketUsdPrices(const QHash<QString, AssetUsdPrice>& prices);

    PriceFeed* m_priceFeed{nullptr};
    QString m_dataFeed;  // "Manual" (default) or "CoinGecko"
    // ticker -> whether its current Market FX came from a verified live source
    QHash<QString, bool> m_marketVerified;
};

#endif // BITCOIN_QT_ASSETPRICETAB_H
