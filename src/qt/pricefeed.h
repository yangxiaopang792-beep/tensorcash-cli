// Copyright (c) 2026 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_QT_PRICEFEED_H
#define BITCOIN_QT_PRICEFEED_H

#include <QHash>
#include <QObject>
#include <QString>

class QNetworkAccessManager;
class QNetworkReply;

namespace pricefeed {
// Indicative TSC price = TSC_BTC_RATIO_BPS basis points of live BTC.
// "for now, live" — a temporary peg until TSC has its own market.
// 10000 bps = 100%; 100 bps = 1% of BTC.
static constexpr int TSC_BTC_RATIO_BPS = 100;
} // namespace pricefeed

/**
 * How an on-chain asset maps to an external USD price source.
 *
 * Mirrors the gateway convention (services/asset_price_resolver.py) so the
 * sovereign wallet and the hosted wallet speak the same `price_oracle` language,
 * even though they resolve independently (the wallet never calls the gateway).
 */
struct PriceDescriptor {
    enum class Kind { None, Direct, Peg };
    Kind kind{Kind::None};

    // Direct
    QString coingeckoId;   // e.g. "bitcoin", "wrapped-bitcoin"
    QString platform;      // e.g. "ethereum" (alternative to coingeckoId)
    QString contract;      // 0x... token address (used with platform)

    // Peg (indirect): asset tracks `pegRef` scaled by `pegRatio`.
    QString pegRef;        // "BTC"/"ETH" or a CoinGecko id
    double  pegRatio{1.0}; // units of pegRef per 1 unit of this asset

    // Trust: true only when confirmed by the bundled verified allowlist.
    bool    verified{false};

    bool isValid() const { return kind != Kind::None; }
};

/** Resolved live USD price for one asset. */
struct AssetUsdPrice {
    double  usd{0.0};
    bool    hasUsd{false};
    QString source;        // "coingecko:bitcoin", "peg:BTC", ...
    bool    verified{false};
    QString indirectVia;   // peg reference, when priced indirectly
};

/**
 * Asynchronous external price client for the sovereign Qt wallet.
 *
 * Direct external only — fetches from CoinGecko (and resolves pegs against the
 * fetched references). Opt-in; the caller is expected to surface a privacy
 * notice before enabling it, and may route it through a SOCKS proxy (Tor).
 */
class PriceFeed : public QObject
{
    Q_OBJECT

public:
    explicit PriceFeed(QObject* parent = nullptr);

    // Optional SOCKS5 proxy (e.g. the wallet's Tor proxy). Empty host = direct.
    void setSocksProxy(const QString& host, quint16 port);

    // False when this Qt build lacks QT_CONFIG(networkproxy) (static depends
    // builds): a configured proxy cannot be honoured and fetches with a proxy
    // set are refused instead of silently going direct.
    bool proxySupported() const;

    // Bundled, verified mapping for a native ticker or asset_id (TSC, BTC, ...).
    // Returns an invalid descriptor when the key is unknown.
    static PriceDescriptor allowlistLookup(const QString& tickerOrAssetId);

    // Resolve a set of {key -> descriptor} into USD prices. Batches the CoinGecko
    // calls, resolves pegs against the fetched references, then emits pricesReady
    // exactly once. `key` is opaque (the caller's ticker) and echoed back.
    void fetchUsdPrices(const QHash<QString, PriceDescriptor>& descriptors);

Q_SIGNALS:
    void pricesReady(const QHash<QString, AssetUsdPrice>& prices);
    void failed(const QString& error);

private:
    void applyProxy();
    void requestSimplePrices(const QStringList& ids);
    void requestTokenPrice(const QString& platform, const QString& contract);
    void maybeFinish();
    double referenceUsd(const QString& ref) const;

    QNetworkAccessManager* m_nam{nullptr};
    QString m_proxyHost;
    quint16 m_proxyPort{0};

    int m_outstanding{0};
    bool m_anyError{false};

    QHash<QString, PriceDescriptor> m_pending;     // key -> descriptor
    QHash<QString, double> m_cgUsd;                 // coingecko id -> usd
    QHash<QString, double> m_tokenUsd;             // "platform/contract" -> usd
};

#endif // BITCOIN_QT_PRICEFEED_H
