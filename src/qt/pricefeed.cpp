// Copyright (c) 2026 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <qt/pricefeed.h>

#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QList>
#include <QNetworkAccessManager>
#if QT_CONFIG(networkproxy)
#include <QNetworkProxy>
#endif
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QPair>
#include <QStringList>
#include <QUrl>

namespace {
constexpr const char* CG_BASE = "https://api.coingecko.com/api/v3";

// CoinGecko id for the majors so pegs can reference them by ticker.
QString majorCoingeckoId(const QString& ref)
{
    const QString up = ref.toUpper();
    if (up == "BTC" || up == "XBT") return "bitcoin";
    if (up == "ETH") return "ethereum";
    return QString();
}
} // namespace

PriceFeed::PriceFeed(QObject* parent) : QObject(parent) {}

void PriceFeed::setSocksProxy(const QString& host, quint16 port)
{
    m_proxyHost = host;
    m_proxyPort = port;
}

void PriceFeed::applyProxy()
{
    if (!m_nam) return;
#if QT_CONFIG(networkproxy)
    if (!m_proxyHost.isEmpty()) {
        m_nam->setProxy(QNetworkProxy(QNetworkProxy::Socks5Proxy, m_proxyHost, m_proxyPort));
    } else {
        m_nam->setProxy(QNetworkProxy(QNetworkProxy::NoProxy));
    }
#endif
    // Without QT_CONFIG(networkproxy) (static depends Qt) requests go direct;
    // a configured SOCKS proxy cannot be honoured, so refuse to fetch rather
    // than leak the lookup outside the proxy. fetchUsdPrices checks this.
}

bool PriceFeed::proxySupported() const
{
#if QT_CONFIG(networkproxy)
    return true;
#else
    return false;
#endif
}

// ---- Bundled verified allowlist -------------------------------------------
// The sovereign user's own trust anchor: keys listed here are surfaced as
// `verified`. Anything resolved only from an on-chain issuer hint stays
// `verified=false` (issuer-claimed).
//
// TRUST BOUNDARY: callers must pass EITHER a chain-native ticker (e.g. "TSC")
// OR an asset's canonical asset_id (64-hex) — NEVER an on-chain asset's
// self-declared ticker. A ticker is attacker-chosen, so a ticker-keyed verified
// entry (e.g. "WBTC") would let a fake asset inherit a verified price. To mark
// a wrapped/issued asset verified, add its canonical asset_id below (a 64-hex
// id can never collide with these native ticker constants).
PriceDescriptor PriceFeed::allowlistLookup(const QString& tickerOrAssetId)
{
    const QString key = tickerOrAssetId.trimmed().toUpper();
    PriceDescriptor d;

    if (key == "TSC") {
        // TSC priced as TSC_BTC_RATIO_BPS basis points of live BTC ("for now").
        d.kind = PriceDescriptor::Kind::Peg;
        d.pegRef = "BTC";
        d.pegRatio = static_cast<double>(pricefeed::TSC_BTC_RATIO_BPS) / 10000.0;
        d.verified = true;
        return d;
    }
    if (key == "BTC") {
        // Native BTC (chain coin), used for native-ticker requests only.
        d.kind = PriceDescriptor::Kind::Direct;
        d.coingeckoId = "bitcoin";
        d.verified = true;
        return d;
    }
    if (key == "ETH") {
        d.kind = PriceDescriptor::Kind::Direct;
        d.coingeckoId = "ethereum";
        d.verified = true;
        return d;
    }

    // Verified wrapped/issued assets go here keyed by canonical asset_id, e.g.:
    //   if (key == "<64-HEX-ASSET-ID>") { d.kind = Peg; d.pegRef = "BTC";
    //       d.pegRatio = 1.0; d.verified = true; return d; }

    return d; // invalid / unknown
}

void PriceFeed::fetchUsdPrices(const QHash<QString, PriceDescriptor>& descriptors)
{
    m_pending = descriptors;
    m_cgUsd.clear();
    m_tokenUsd.clear();
    m_outstanding = 0;
    m_anyError = false;

    if (!m_proxyHost.isEmpty() && !proxySupported()) {
        // Privacy over availability: never fall back to a direct request when
        // the caller asked for a proxy this Qt build cannot provide.
        Q_EMIT failed(tr("Price feed proxy is not supported by this build."));
        return;
    }

    if (!m_nam) m_nam = new QNetworkAccessManager(this);
    applyProxy();

    // Collect the distinct CoinGecko ids and platform/contract pairs to fetch.
    QStringList ids;
    QList<QPair<QString, QString>> tokens; // (platform, contract)
    for (auto it = m_pending.constBegin(); it != m_pending.constEnd(); ++it) {
        const PriceDescriptor& d = it.value();
        if (d.kind == PriceDescriptor::Kind::Direct) {
            if (!d.coingeckoId.isEmpty()) {
                if (!ids.contains(d.coingeckoId)) ids << d.coingeckoId;
            } else if (!d.platform.isEmpty() && !d.contract.isEmpty()) {
                tokens.append({d.platform, d.contract.toLower()});
            }
        } else if (d.kind == PriceDescriptor::Kind::Peg) {
            const QString major = majorCoingeckoId(d.pegRef);
            const QString id = major.isEmpty() ? d.pegRef : major;
            if (!id.isEmpty() && !ids.contains(id)) ids << id;
        }
    }

    if (ids.isEmpty() && tokens.isEmpty()) {
        // Nothing externally resolvable; emit empty result.
        Q_EMIT pricesReady(QHash<QString, AssetUsdPrice>());
        return;
    }

    if (!ids.isEmpty()) requestSimplePrices(ids);
    for (const auto& t : tokens) requestTokenPrice(t.first, t.second);
}

void PriceFeed::requestSimplePrices(const QStringList& ids)
{
    QUrl url(QString("%1/simple/price?ids=%2&vs_currencies=usd")
                 .arg(CG_BASE, ids.join(',')));
    QNetworkRequest req(url);
    req.setRawHeader("Accept", "application/json");
    QNetworkReply* reply = m_nam->get(req);
    ++m_outstanding;
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        if (reply->error() == QNetworkReply::NoError) {
            const QJsonObject root = QJsonDocument::fromJson(reply->readAll()).object();
            for (auto it = root.constBegin(); it != root.constEnd(); ++it) {
                const QJsonValue usd = it.value().toObject().value("usd");
                if (usd.isDouble()) m_cgUsd.insert(it.key(), usd.toDouble());
            }
        } else {
            m_anyError = true;
        }
        reply->deleteLater();
        --m_outstanding;
        maybeFinish();
    });
}

void PriceFeed::requestTokenPrice(const QString& platform, const QString& contract)
{
    QUrl url(QString("%1/simple/token_price/%2?contract_addresses=%3&vs_currencies=usd")
                 .arg(CG_BASE, platform, contract));
    QNetworkRequest req(url);
    req.setRawHeader("Accept", "application/json");
    QNetworkReply* reply = m_nam->get(req);
    const QString key = platform + "/" + contract;
    ++m_outstanding;
    connect(reply, &QNetworkReply::finished, this, [this, reply, key, contract]() {
        if (reply->error() == QNetworkReply::NoError) {
            const QJsonObject root = QJsonDocument::fromJson(reply->readAll()).object();
            const QJsonValue usd = root.value(contract).toObject().value("usd");
            if (usd.isDouble()) m_tokenUsd.insert(key, usd.toDouble());
        } else {
            m_anyError = true;
        }
        reply->deleteLater();
        --m_outstanding;
        maybeFinish();
    });
}

double PriceFeed::referenceUsd(const QString& ref) const
{
    const QString major = majorCoingeckoId(ref);
    const QString id = major.isEmpty() ? ref : major;
    return m_cgUsd.value(id, 0.0);
}

void PriceFeed::maybeFinish()
{
    if (m_outstanding > 0) return;

    QHash<QString, AssetUsdPrice> out;
    for (auto it = m_pending.constBegin(); it != m_pending.constEnd(); ++it) {
        const PriceDescriptor& d = it.value();
        AssetUsdPrice p;
        p.verified = d.verified;

        if (d.kind == PriceDescriptor::Kind::Direct) {
            if (!d.coingeckoId.isEmpty()) {
                if (m_cgUsd.contains(d.coingeckoId)) {
                    p.usd = m_cgUsd.value(d.coingeckoId);
                    p.hasUsd = true;
                    p.source = "coingecko:" + d.coingeckoId;
                }
            } else if (!d.platform.isEmpty() && !d.contract.isEmpty()) {
                const QString key = d.platform + "/" + d.contract.toLower();
                if (m_tokenUsd.contains(key)) {
                    p.usd = m_tokenUsd.value(key);
                    p.hasUsd = true;
                    p.source = "coingecko:" + key;
                }
            }
        } else if (d.kind == PriceDescriptor::Kind::Peg) {
            const double refUsd = referenceUsd(d.pegRef);
            if (refUsd > 0.0) {
                p.usd = refUsd * d.pegRatio;
                p.hasUsd = true;
                p.source = "peg:" + d.pegRef;
                p.indirectVia = d.pegRef;
            }
        }

        if (p.hasUsd) out.insert(it.key(), p);
    }

    if (out.isEmpty() && m_anyError) {
        Q_EMIT failed(tr("Price feed request failed (network or CoinGecko error)."));
        return;
    }
    Q_EMIT pricesReady(out);
}
