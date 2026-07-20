// Copyright (c) 2024 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_ZKPARAMSMANAGER_H
#define BITCOIN_QT_ZKPARAMSMANAGER_H

#include <QByteArray>
#include <QFile>
#include <QFileInfo>
#include <QObject>
#include <QString>

class QNetworkAccessManager;
class QNetworkReply;
class QProgressDialog;
class QWidget;

namespace zkparams {

// HDv1 raw gnark verification key (968 bytes, 6 public inputs).
// Generated from shared-utils/kyc-prover/vectors_hd_v1/verification_key_v1.bin.
static constexpr unsigned char VK_HD_V1[] = {
#include "zkparamsmanager_vk_hd_v1.inc"
};
static constexpr size_t VK_HD_V1_SIZE = 968;

static constexpr const char* VK_HD_V1_SHA256 =
    "b005553aa1a6b47ade4879988687f0fb8dd109e05eafb7a482fa0eabc4354eae";

static constexpr const char* PK_HD_V1_SHA256 =
    "b388b68612c342554f154881f185b6114ab0215abe5329c2bd6c1528a6dfd297";

static constexpr qint64 PK_HD_V1_SIZE = 551913716;

static constexpr const char* GHCR_REGISTRY = "ghcr.io";
static constexpr const char* GHCR_REPO = "tensorcash/zkparams";
static constexpr const char* GHCR_TAG = "hd-v1";

} // namespace zkparams

class ZKParamsManager : public QObject
{
    Q_OBJECT

public:
    explicit ZKParamsManager(const QString& dataDir, QObject* parent = nullptr);

    static QByteArray embeddedVK();
    static QString embeddedVKSha256();

    QString provingKeyPath() const;
    bool isProvingKeyAvailable() const;
    void ensureProvingKey(QWidget* parent);
    void setManualProvingKeyPath(const QString& path);

Q_SIGNALS:
    void provingKeyReady(const QString& path);
    void provingKeyFailed(const QString& error);

private Q_SLOTS:
    void onManifestReply();
    void onBlobReply();
    void onDownloadProgress(qint64 received, qint64 total);
    void onDownloadCancelled();

private:
    QString zkparamsDir() const;
    QString defaultPKPath() const;
    bool verifyPKHash(const QString& path) const;

    QString m_dataDir;
    QString m_manualPKPath;
    bool m_downloading{false};

    QNetworkAccessManager* m_nam{nullptr};
    QNetworkReply* m_currentReply{nullptr};
    QProgressDialog* m_progressDialog{nullptr};
    QFile* m_partFile{nullptr};
    QString m_blobDigest;
};

#endif // BITCOIN_QT_ZKPARAMSMANAGER_H
