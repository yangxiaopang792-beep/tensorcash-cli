// Copyright (c) 2024 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/zkparamsmanager.h>

#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QLocale>
#include <QMessageBox>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QProgressDialog>

namespace {

QString FormatProvingKeySize()
{
    return QLocale().formattedDataSize(zkparams::PK_HD_V1_SIZE);
}

} // namespace

ZKParamsManager::ZKParamsManager(const QString& dataDir, QObject* parent)
    : QObject(parent), m_dataDir(dataDir)
{
}

QByteArray ZKParamsManager::embeddedVK()
{
    return QByteArray(reinterpret_cast<const char*>(zkparams::VK_HD_V1),
                      zkparams::VK_HD_V1_SIZE);
}

QString ZKParamsManager::embeddedVKSha256()
{
    return QString(zkparams::VK_HD_V1_SHA256);
}

QString ZKParamsManager::zkparamsDir() const
{
    return m_dataDir + "/zkparams";
}

QString ZKParamsManager::defaultPKPath() const
{
    return zkparamsDir() + "/proving_key_v1.bin";
}

QString ZKParamsManager::provingKeyPath() const
{
    if (!m_manualPKPath.isEmpty() && QFile::exists(m_manualPKPath)) {
        return m_manualPKPath;
    }
    QString path = defaultPKPath();
    if (QFile::exists(path)) {
        return path;
    }
    return QString();
}

bool ZKParamsManager::verifyPKHash(const QString& path) const
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) return false;

    QCryptographicHash hash(QCryptographicHash::Sha256);
    const qint64 bufSize = 8 * 1024 * 1024;
    while (!file.atEnd()) {
        hash.addData(file.read(bufSize));
    }
    file.close();

    return hash.result().toHex() == zkparams::PK_HD_V1_SHA256;
}

bool ZKParamsManager::isProvingKeyAvailable() const
{
    QString path = provingKeyPath();
    if (path.isEmpty()) return false;

    QFileInfo fi(path);
    if (fi.size() != zkparams::PK_HD_V1_SIZE) return false;

    return true;
}

void ZKParamsManager::setManualProvingKeyPath(const QString& path)
{
    m_manualPKPath = path;
}

void ZKParamsManager::ensureProvingKey(QWidget* parent)
{
    if (isProvingKeyAvailable()) {
        Q_EMIT provingKeyReady(provingKeyPath());
        return;
    }

    if (m_downloading) return;

    // Ask user before downloading
    auto reply = QMessageBox::question(parent,
        tr("Download Proving Key"),
        tr("The ZK proving key (%1) needs to be downloaded.\n\n"
           "Download now from ghcr.io?").arg(FormatProvingKeySize()),
        QMessageBox::Yes | QMessageBox::No);

    if (reply != QMessageBox::Yes) {
        Q_EMIT provingKeyFailed(tr("Download cancelled by user"));
        return;
    }

    m_downloading = true;

    if (!m_nam) {
        m_nam = new QNetworkAccessManager(this);
    }

    // Step 1: Fetch OCI manifest to get blob digest
    QUrl manifestUrl(QString("https://%1/v2/%2/manifests/%3")
        .arg(zkparams::GHCR_REGISTRY, zkparams::GHCR_REPO, zkparams::GHCR_TAG));

    QNetworkRequest req(manifestUrl);
    req.setRawHeader("Accept", "application/vnd.oci.image.manifest.v1+json");

    m_currentReply = m_nam->get(req);
    connect(m_currentReply, &QNetworkReply::finished, this, &ZKParamsManager::onManifestReply);

    // Set up progress dialog
    m_progressDialog = new QProgressDialog(
        tr("Fetching manifest..."), tr("Cancel"), 0, 100, parent);
    m_progressDialog->setWindowModality(Qt::WindowModal);
    m_progressDialog->setMinimumDuration(0);
    m_progressDialog->setValue(0);
    connect(m_progressDialog, &QProgressDialog::canceled, this, &ZKParamsManager::onDownloadCancelled);
}

void ZKParamsManager::onManifestReply()
{
    QNetworkReply* reply = m_currentReply;
    m_currentReply = nullptr;

    if (reply->error() != QNetworkReply::NoError) {
        m_downloading = false;
        if (m_progressDialog) { m_progressDialog->close(); m_progressDialog->deleteLater(); m_progressDialog = nullptr; }
        Q_EMIT provingKeyFailed(tr("Failed to fetch manifest: %1").arg(reply->errorString()));
        reply->deleteLater();
        return;
    }

    QByteArray data = reply->readAll();
    reply->deleteLater();

    // Parse OCI manifest to find the blob layer digest
    QJsonParseError parseErr;
    QJsonDocument doc = QJsonDocument::fromJson(data, &parseErr);
    if (parseErr.error != QJsonParseError::NoError || !doc.isObject()) {
        m_downloading = false;
        if (m_progressDialog) { m_progressDialog->close(); m_progressDialog->deleteLater(); m_progressDialog = nullptr; }
        Q_EMIT provingKeyFailed(tr("Invalid manifest JSON"));
        return;
    }

    QJsonArray layers = doc.object().value("layers").toArray();
    if (layers.isEmpty()) {
        m_downloading = false;
        if (m_progressDialog) { m_progressDialog->close(); m_progressDialog->deleteLater(); m_progressDialog = nullptr; }
        Q_EMIT provingKeyFailed(tr("No layers in manifest"));
        return;
    }

    // Use the first layer's digest
    m_blobDigest = layers[0].toObject().value("digest").toString();
    if (m_blobDigest.isEmpty()) {
        m_downloading = false;
        if (m_progressDialog) { m_progressDialog->close(); m_progressDialog->deleteLater(); m_progressDialog = nullptr; }
        Q_EMIT provingKeyFailed(tr("No digest in manifest layer"));
        return;
    }

    // Ensure directory exists
    QDir dir;
    dir.mkpath(zkparamsDir());

    // Open .part file for streaming
    QString partPath = defaultPKPath() + ".part";
    m_partFile = new QFile(partPath, this);
    if (!m_partFile->open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        m_downloading = false;
        if (m_progressDialog) { m_progressDialog->close(); m_progressDialog->deleteLater(); m_progressDialog = nullptr; }
        Q_EMIT provingKeyFailed(tr("Cannot create file: %1").arg(partPath));
        delete m_partFile;
        m_partFile = nullptr;
        return;
    }

    // Step 2: Download the blob
    QUrl blobUrl(QString("https://%1/v2/%2/blobs/%3")
        .arg(zkparams::GHCR_REGISTRY, zkparams::GHCR_REPO, m_blobDigest));

    QNetworkRequest blobReq(blobUrl);
    m_currentReply = m_nam->get(blobReq);

    if (m_progressDialog) {
        m_progressDialog->setLabelText(tr("Downloading proving key (%1)...").arg(FormatProvingKeySize()));
        m_progressDialog->setMaximum(zkparams::PK_HD_V1_SIZE);
    }

    connect(m_currentReply, &QNetworkReply::downloadProgress, this, &ZKParamsManager::onDownloadProgress);
    connect(m_currentReply, &QNetworkReply::readyRead, this, [this]() {
        if (m_partFile && m_currentReply) {
            m_partFile->write(m_currentReply->readAll());
        }
    });
    connect(m_currentReply, &QNetworkReply::finished, this, &ZKParamsManager::onBlobReply);
}

void ZKParamsManager::onBlobReply()
{
    QNetworkReply* reply = m_currentReply;
    m_currentReply = nullptr;

    // Write any remaining data
    if (m_partFile && reply) {
        m_partFile->write(reply->readAll());
        m_partFile->close();
    }

    bool success = (reply && reply->error() == QNetworkReply::NoError);
    if (reply) reply->deleteLater();

    if (m_progressDialog) {
        m_progressDialog->close();
        m_progressDialog->deleteLater();
        m_progressDialog = nullptr;
    }

    QString partPath = defaultPKPath() + ".part";

    if (!success) {
        QFile::remove(partPath);
        if (m_partFile) { delete m_partFile; m_partFile = nullptr; }
        m_downloading = false;
        Q_EMIT provingKeyFailed(tr("Download failed"));
        return;
    }

    if (m_partFile) { delete m_partFile; m_partFile = nullptr; }

    // Verify SHA256
    if (!verifyPKHash(partPath)) {
        QFile::remove(partPath);
        m_downloading = false;
        Q_EMIT provingKeyFailed(tr("SHA256 verification failed — file corrupted"));
        return;
    }

    // Rename .part to final
    QString finalPath = defaultPKPath();
    QFile::remove(finalPath); // remove old if exists
    if (!QFile::rename(partPath, finalPath)) {
        QFile::remove(partPath);
        m_downloading = false;
        Q_EMIT provingKeyFailed(tr("Failed to move downloaded file to final location"));
        return;
    }

    m_downloading = false;
    Q_EMIT provingKeyReady(finalPath);
}

void ZKParamsManager::onDownloadProgress(qint64 received, qint64 total)
{
    if (m_progressDialog) {
        if (total > 0) {
            m_progressDialog->setMaximum(total);
        }
        m_progressDialog->setValue(received);
    }
}

void ZKParamsManager::onDownloadCancelled()
{
    if (m_currentReply) {
        m_currentReply->abort();
        m_currentReply->deleteLater();
        m_currentReply = nullptr;
    }

    QString partPath = defaultPKPath() + ".part";
    if (m_partFile) {
        m_partFile->close();
        delete m_partFile;
        m_partFile = nullptr;
    }
    QFile::remove(partPath);

    if (m_progressDialog) {
        m_progressDialog->deleteLater();
        m_progressDialog = nullptr;
    }

    m_downloading = false;
    Q_EMIT provingKeyFailed(tr("Download cancelled"));
}
