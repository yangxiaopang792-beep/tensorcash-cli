// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <chainparams.h>
#include <chainparamsbase.h>
#include <qt/intro.h>
#include <qt/forms/ui_intro.h>
#include <util/chaintype.h>
#include <util/fs.h>

#include <qt/guiconstants.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>

#include <common/args.h>
#include <interfaces/node.h>
#include <util/fs_helpers.h>
#include <validation.h>

#include <QFileDialog>
#include <QSettings>
#include <QMessageBox>
#include <QDebug>

#ifdef WIN32
#include <shlobj.h>
#endif

#include <cmath>
#include <cstdlib>
#include <cstring>
#include <string_view>
#include <optional>
#include <vector>

/* Check free space asynchronously to prevent hanging the UI thread.

   Up to one request to check a path is in flight to this thread; when the check()
   function runs, the current path is requested from the associated Intro object.
   The reply is sent back through a signal.

   This ensures that no queue of checking requests is built up while the user is
   still entering the path, and that always the most recently entered path is checked as
   soon as the thread becomes available.
*/
class FreespaceChecker : public QObject
{
    Q_OBJECT

public:
    explicit FreespaceChecker(Intro *intro);

    enum Status {
        ST_OK,
        ST_ERROR
    };

public Q_SLOTS:
    void check();

Q_SIGNALS:
    void reply(int status, const QString &message, quint64 available);

private:
    Intro *intro;
};

#include <qt/intro.moc>

FreespaceChecker::FreespaceChecker(Intro *_intro)
{
    this->intro = _intro;
}

void FreespaceChecker::check()
{
    QString dataDirStr = intro->getPathToCheck();
    fs::path dataDir = GUIUtil::QStringToPath(dataDirStr);
    uint64_t freeBytesAvailable = 0;
    int replyStatus = ST_OK;
    QString replyMessage = tr("A new data directory will be created.");

    /* Find first parent that exists, so that fs::space does not fail */
    fs::path parentDir = dataDir;
    fs::path parentDirOld = fs::path();
    while(parentDir.has_parent_path() && !fs::exists(parentDir))
    {
        parentDir = parentDir.parent_path();

        /* Check if we make any progress, break if not to prevent an infinite loop here */
        if (parentDirOld == parentDir)
            break;

        parentDirOld = parentDir;
    }

    try {
        freeBytesAvailable = fs::space(parentDir).available;
        if(fs::exists(dataDir))
        {
            if(fs::is_directory(dataDir))
            {
                QString separator = "<code>" + QDir::toNativeSeparators("/") + tr("name") + "</code>";
                replyStatus = ST_OK;
                replyMessage = tr("Directory already exists. Add %1 if you intend to create a new directory here.").arg(separator);
            } else {
                replyStatus = ST_ERROR;
                replyMessage = tr("Path already exists, and is not a directory.");
            }
        }
    } catch (const fs::filesystem_error&)
    {
        /* Parent directory does not exist or is not accessible */
        replyStatus = ST_ERROR;
        replyMessage = tr("Cannot create data directory here.");
    }
    Q_EMIT reply(replyStatus, replyMessage, freeBytesAvailable);
}

namespace {
//! Return pruning size that will be used if automatic pruning is enabled.
int GetPruneTargetGB()
{
    int64_t prune_target_mib = gArgs.GetIntArg("-prune", 0);
    // >1 means automatic pruning is enabled by config, 1 means manual pruning, 0 means no pruning.
    return prune_target_mib > 1 ? PruneMiBtoGB(prune_target_mib) : DEFAULT_PRUNE_TARGET_GB;
}

QString NetworkSettingsAppName(const ChainType chain)
{
    switch (chain) {
    case ChainType::TESTNET:
        return QStringLiteral(QAPP_APP_NAME_TESTNET);
    case ChainType::TESTNET4:
        return QStringLiteral(QAPP_APP_NAME_TESTNET4);
    case ChainType::SIGNET:
        return QStringLiteral(QAPP_APP_NAME_SIGNET);
    case ChainType::REGTEST:
        return QStringLiteral(QAPP_APP_NAME_REGTEST);
    case ChainType::TENSOR_MAIN:
        return QStringLiteral(QAPP_APP_NAME_TENSOR);
    case ChainType::TENSOR_TEST:
        return QStringLiteral(QAPP_APP_NAME_TENSOR_TEST);
    case ChainType::TENSOR_REG:
        return QStringLiteral(QAPP_APP_NAME_TENSOR_REG);
    case ChainType::MAIN:
        return QStringLiteral(QAPP_APP_NAME_DEFAULT);
    }
    return QStringLiteral(QAPP_APP_NAME_DEFAULT);
}

QString LegacyBitcoinQtAppName(const ChainType chain)
{
    switch (chain) {
    case ChainType::TESTNET:
    case ChainType::TENSOR_TEST:
        return QStringLiteral("Bitcoin-Qt-testnet");
    case ChainType::TESTNET4:
        return QStringLiteral("Bitcoin-Qt-testnet4");
    case ChainType::SIGNET:
        return QStringLiteral("Bitcoin-Qt-signet");
    case ChainType::REGTEST:
    case ChainType::TENSOR_REG:
        return QStringLiteral("Bitcoin-Qt-regtest");
    case ChainType::MAIN:
    case ChainType::TENSOR_MAIN:
        return QStringLiteral("Bitcoin-Qt");
    }
    return QStringLiteral("Bitcoin-Qt");
}

fs::path LegacyDefaultDataDir()
{
#ifdef WIN32
    return GetSpecialFolderPath(CSIDL_APPDATA) / "Bitcoin";
#else
    fs::path path_ret;
    const char* home = std::getenv("HOME");
    if (home == nullptr || std::strlen(home) == 0) {
        path_ret = fs::path("/");
    } else {
        path_ret = fs::path(home);
    }
#ifdef __APPLE__
    return path_ret / "Library/Application Support" / "Bitcoin";
#else
    return path_ret / ".bitcoin";
#endif
#endif
}

fs::path ChainDataPath(const fs::path& base_path, const ChainType chain)
{
    const auto params = CreateBaseChainParams(chain);
    return params->DataDir().empty() ? base_path : base_path / fs::PathFromString(params->DataDir());
}

// The historical SHARED base directory that every tensor* build used before the
// per-chain datadir split (mainnet still uses it). Mirrors GetDefaultDataDir()'s
// platform layout with the fixed "TensorCash" / ".tensorcash" name, so a
// non-mainnet build can locate and migrate its data out of it.
fs::path LegacySharedTensorCashDir()
{
#ifdef WIN32
    return GetSpecialFolderPath(CSIDL_APPDATA) / "TensorCash";
#else
    fs::path path_ret;
    const char* home = std::getenv("HOME");
    if (home == nullptr || std::strlen(home) == 0) {
        path_ret = fs::path("/");
    } else {
        path_ret = fs::path(home);
    }
#ifdef __APPLE__
    return path_ret / "Library/Application Support" / "TensorCash";
#else
    return path_ret / ".tensorcash";
#endif
#endif
}

bool PathsMatch(const fs::path& lhs, const fs::path& rhs)
{
    if (lhs.empty() || rhs.empty()) return lhs.empty() && rhs.empty();

    std::error_code ec;
    if (fs::exists(lhs) && fs::exists(rhs) && fs::equivalent(lhs, rhs, ec)) {
        return true;
    }
    return lhs.lexically_normal() == rhs.lexically_normal();
}

bool WalletDirHasEntries(const fs::path& wallet_dir)
{
    if (!fs::exists(wallet_dir) || !fs::is_directory(wallet_dir)) return false;

    for (const auto& entry : fs::recursive_directory_iterator(wallet_dir, fs::directory_options::skip_permission_denied)) {
        if (entry.is_regular_file()) return true;
    }
    return false;
}

bool HasChainData(const fs::path& chain_dir)
{
    return fs::exists(chain_dir / "chainstate" / "CURRENT") ||
           fs::exists(chain_dir / "blocks" / "index") ||
           fs::exists(chain_dir / "blocks" / "blk00000.dat");
}

bool HasRecoverableData(const fs::path& base_path, const ChainType chain)
{
    const fs::path chain_dir = ChainDataPath(base_path, chain);
    return WalletDirHasEntries(chain_dir / "wallets") || HasChainData(chain_dir);
}

std::optional<QString> FindLegacyDataDir(const QString& current_dir_q, const QString& default_dir_q, const ChainType chain)
{
    const fs::path current_dir = GUIUtil::QStringToPath(current_dir_q);
    const fs::path default_dir = GUIUtil::QStringToPath(default_dir_q);

    // Only auto-switch when startup is still targeting the current default dir
    // (or a missing dir). Respect explicit custom datadirs chosen by the user.
    if (fs::exists(current_dir) && !PathsMatch(current_dir, default_dir)) return std::nullopt;

    const auto current_chain_dir = ChainDataPath(current_dir, chain);
    const bool current_has_wallets = WalletDirHasEntries(current_chain_dir / "wallets");
    const bool current_has_chain = HasChainData(current_chain_dir);

    auto prefer_candidate = [&](const fs::path& candidate_base) -> std::optional<QString> {
        if (candidate_base.empty() || !fs::exists(candidate_base)) return std::nullopt;
        if (PathsMatch(candidate_base, current_dir)) return std::nullopt;
        if (!HasRecoverableData(candidate_base, chain)) return std::nullopt;

        const auto candidate_chain_dir = ChainDataPath(candidate_base, chain);
        const bool candidate_has_wallets = WalletDirHasEntries(candidate_chain_dir / "wallets");
        const bool candidate_has_chain = HasChainData(candidate_chain_dir);

        if (candidate_has_wallets && !current_has_wallets) {
            return GUIUtil::PathToQString(candidate_base);
        }
        if (candidate_has_chain && !current_has_chain) {
            return GUIUtil::PathToQString(candidate_base);
        }
        return std::nullopt;
    };

    const std::vector<QString> legacy_orgs{
        QStringLiteral("bitcoin.org"),
        QStringLiteral("Bitcoin"),
    };
    const std::vector<QString> legacy_apps{
        QStringLiteral(QAPP_APP_NAME_DEFAULT),
        NetworkSettingsAppName(chain),
        QStringLiteral("Bitcoin-Qt"),
        LegacyBitcoinQtAppName(chain),
    };

    for (const auto& org : legacy_orgs) {
        for (const auto& app : legacy_apps) {
            QSettings legacy_settings(QSettings::NativeFormat, QSettings::UserScope, org, app);
            const QString candidate = legacy_settings.value("strDataDir").toString();
            if (candidate.isEmpty()) continue;
            if (auto preferred = prefer_candidate(GUIUtil::QStringToPath(candidate))) {
                return preferred;
            }
        }
    }

    return prefer_candidate(LegacyDefaultDataDir());
}

// One-time upgrade migration: relocate this chain's data OUT of the historical
// shared "TensorCash" base into the per-chain default datadir, so a non-mainnet
// build stops sharing a root (bitcoin.conf / settings.json) with the mainnet
// app. SAFE BY DESIGN: a same-filesystem rename is atomic; on ANY error we
// no-op and leave the data in the shared base, where FindLegacyDataDir still
// recovers it — there is no data-loss path. Only acts for builds whose datadir
// actually moved (tensor-test / tensor-reg); the mainnet build keeps
// "TensorCash" and must never touch the testnet data living there.
void MigrateLegacySharedDatadir(const ChainType chain)
{
    constexpr const char* default_chain = DEFAULT_CHAIN_TYPE;
    const std::string_view dc{default_chain};
    if (dc.empty() || dc == "tensor" || !dc.starts_with("tensor")) return;

    // Wrap everything: bcore's fs::exists(path) has no no-throw overload, so a
    // probe error must never escape into the startup datadir-resolution path.
    // Loss-proof — on any failure we leave the data in the shared base, where
    // FindLegacyDataDir() recovers it.
    try {
        const fs::path new_base = GUIUtil::QStringToPath(GUIUtil::getDefaultDataDirectory());
        const fs::path shared_base = LegacySharedTensorCashDir();
        if (PathsMatch(new_base, shared_base)) return; // nothing moved for this build

        const fs::path src = ChainDataPath(shared_base, chain); // e.g. TensorCash/tensor-test
        const fs::path dst = ChainDataPath(new_base, chain);    // e.g. TensorCash-Testnet/tensor-test
        if (PathsMatch(src, dst)) return;
        if (!fs::exists(src)) return;  // nothing to migrate
        if (fs::exists(dst)) return;   // new datadir already populated — never clobber

        TryCreateDirectories(new_base);
        std::error_code ec;
        fs::rename(src, dst, ec);      // atomic on same filesystem
        if (ec) {
            // Cross-device or any other failure: leave the source untouched.
            // FindLegacyDataDir() will recover it from the shared base as before.
            qWarning() << "Datadir migration skipped (left in place, will be recovered):"
                       << GUIUtil::PathToQString(src) << "->" << GUIUtil::PathToQString(dst)
                       << QString::fromStdString(ec.message());
        } else {
            qInfo() << "Datadir migration: moved" << GUIUtil::PathToQString(src)
                    << "->" << GUIUtil::PathToQString(dst) << "for chain isolation";
        }
    } catch (const std::exception& e) {
        qWarning() << "Datadir migration aborted (data left in place):" << e.what();
    }
}
} // namespace

Intro::Intro(QWidget *parent, int64_t blockchain_size_gb, int64_t chain_state_size_gb) :
    QDialog(parent, GUIUtil::dialog_flags),
    ui(new Ui::Intro),
    m_blockchain_size_gb(blockchain_size_gb),
    m_chain_state_size_gb(chain_state_size_gb),
    m_prune_target_gb{GetPruneTargetGB()}
{
    ui->setupUi(this);
    ui->welcomeLabel->setText(ui->welcomeLabel->text().arg(CLIENT_NAME));
    ui->storageLabel->setText(ui->storageLabel->text().arg(CLIENT_NAME));

    ui->lblExplanation1->setText(ui->lblExplanation1->text()
        .arg(CLIENT_NAME)
        .arg(m_blockchain_size_gb)
        .arg(2009)
        .arg(tr("TensorCash"))
    );
    ui->lblExplanation2->setText(ui->lblExplanation2->text().arg(CLIENT_NAME));

    const int min_prune_target_GB = std::ceil(MIN_DISK_SPACE_FOR_BLOCK_FILES / 1e9);
    ui->pruneGB->setRange(min_prune_target_GB, std::numeric_limits<int>::max());
    if (const auto arg{gArgs.GetIntArg("-prune")}) {
        m_prune_checkbox_is_default = false;
        ui->prune->setChecked(*arg >= 1);
        ui->prune->setEnabled(false);
    }
    ui->pruneGB->setValue(m_prune_target_gb);
    ui->pruneGB->setToolTip(ui->prune->toolTip());
    ui->lblPruneSuffix->setToolTip(ui->prune->toolTip());
    UpdatePruneLabels(ui->prune->isChecked());

    connect(ui->prune, &QCheckBox::toggled, [this](bool prune_checked) {
        m_prune_checkbox_is_default = false;
        UpdatePruneLabels(prune_checked);
        UpdateFreeSpaceLabel();
    });
    connect(ui->pruneGB, qOverload<int>(&QSpinBox::valueChanged), [this](int prune_GB) {
        m_prune_target_gb = prune_GB;
        UpdatePruneLabels(ui->prune->isChecked());
        UpdateFreeSpaceLabel();
    });

    startThread();
}

Intro::~Intro()
{
    delete ui;
    /* Ensure thread is finished before it is deleted */
    thread->quit();
    thread->wait();
}

QString Intro::getDataDirectory()
{
    return ui->dataDirectory->text();
}

void Intro::setDataDirectory(const QString &dataDir)
{
    ui->dataDirectory->setText(dataDir);
    if(dataDir == GUIUtil::getDefaultDataDirectory())
    {
        ui->dataDirDefault->setChecked(true);
        ui->dataDirectory->setEnabled(false);
        ui->ellipsisButton->setEnabled(false);
    } else {
        ui->dataDirCustom->setChecked(true);
        ui->dataDirectory->setEnabled(true);
        ui->ellipsisButton->setEnabled(true);
    }
}

int64_t Intro::getPruneMiB() const
{
    switch (ui->prune->checkState()) {
    case Qt::Checked:
        return PruneGBtoMiB(m_prune_target_gb);
    case Qt::Unchecked: default:
        return 0;
    }
}

bool Intro::showIfNeeded(bool& did_show_intro, int64_t& prune_MiB)
{
    did_show_intro = false;

    QSettings settings;
    /* If data directory provided on command line, no need to look at settings
       or show a picking dialog */
    if(!gArgs.GetArg("-datadir", "").empty())
        return true;
    /* 1) Default data directory for operating system */
    const QString default_data_dir = GUIUtil::getDefaultDataDirectory();
    // Before resolving the datadir, relocate this chain's data out of the old
    // shared "TensorCash" base into the per-chain default (testnet/regtest
    // builds only). Loss-proof: any failure leaves the data in place for
    // FindLegacyDataDir() below to recover.
    MigrateLegacySharedDatadir(gArgs.GetChainType());
    QString dataDir = default_data_dir;
    /* 2) Allow QSettings to override default dir */
    dataDir = settings.value("strDataDir", dataDir).toString();

    // Recover an older custom/default datadir before we create a fresh one
    // under the rebranded TensorCash paths.
    if (const auto legacy_data_dir = FindLegacyDataDir(dataDir, default_data_dir, gArgs.GetChainType())) {
        if (dataDir != *legacy_data_dir) {
            dataDir = *legacy_data_dir;
            settings.setValue("strDataDir", dataDir);
            QMessageBox::information(
                nullptr,
                CLIENT_NAME,
                tr("Found an existing TensorCash data directory from an older build at \"%1\".\n\n"
                   "TensorCash will keep using that directory to avoid starting with an empty wallet or chain.")
                    .arg(QDir::toNativeSeparators(dataDir)));
        }
    }

    if(!fs::exists(GUIUtil::QStringToPath(dataDir)) || gArgs.GetBoolArg("-choosedatadir", DEFAULT_CHOOSE_DATADIR) || settings.value("fReset", false).toBool() || gArgs.GetBoolArg("-resetguisettings", false))
    {
        /* Use selectParams here to guarantee Params() can be used by node interface */
        try {
            SelectParams(gArgs.GetChainType());
        } catch (const std::exception&) {
            return false;
        }

        /* If current default data directory does not exist, let the user choose one */
        Intro intro(nullptr, Params().AssumedBlockchainSize(), Params().AssumedChainStateSize());
        intro.setDataDirectory(dataDir);
        intro.setWindowIcon(QIcon(":icons/bitcoin"));  // Note: icon file still named bitcoin but contains TensorCash logo
        did_show_intro = true;

        while(true)
        {
            if(!intro.exec())
            {
                /* Cancel clicked */
                return false;
            }
            dataDir = intro.getDataDirectory();
            try {
                if (TryCreateDirectories(GUIUtil::QStringToPath(dataDir))) {
                    // If a new data directory has been created, make wallets subdirectory too
                    TryCreateDirectories(GUIUtil::QStringToPath(dataDir) / "wallets");
                }
                break;
            } catch (const fs::filesystem_error&) {
                QMessageBox::critical(nullptr, CLIENT_NAME,
                    tr("Error: Specified data directory \"%1\" cannot be created.").arg(dataDir));
                /* fall through, back to choosing screen */
            }
        }

        // Additional preferences:
        prune_MiB = intro.getPruneMiB();

        settings.setValue("strDataDir", dataDir);
        settings.setValue("fReset", false);
    }
    /* Only override -datadir if different from the default, to make it possible to
     * override -datadir in the tensorcash.conf file in the default data directory
     * (to be consistent with tensorcashd behavior)
     */
    if(dataDir != default_data_dir) {
        gArgs.SoftSetArg("-datadir", fs::PathToString(GUIUtil::QStringToPath(dataDir))); // use OS locale for path setting
    }
    return true;
}

void Intro::setStatus(int status, const QString &message, quint64 bytesAvailable)
{
    switch(status)
    {
    case FreespaceChecker::ST_OK:
        ui->errorMessage->setText(message);
        ui->errorMessage->setStyleSheet("");
        break;
    case FreespaceChecker::ST_ERROR:
        ui->errorMessage->setText(tr("Error") + ": " + message);
        ui->errorMessage->setStyleSheet("QLabel { color: #800000 }");
        break;
    }
    /* Indicate number of bytes available */
    if(status == FreespaceChecker::ST_ERROR)
    {
        ui->freeSpace->setText("");
    } else {
        m_bytes_available = bytesAvailable;
        if (ui->prune->isEnabled() && m_prune_checkbox_is_default) {
            ui->prune->setChecked(m_bytes_available < (m_blockchain_size_gb + m_chain_state_size_gb + 10) * GB_BYTES);
        }
        UpdateFreeSpaceLabel();
    }
    /* Don't allow confirm in ERROR state */
    ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(status != FreespaceChecker::ST_ERROR);
}

void Intro::UpdateFreeSpaceLabel()
{
    QString freeString = tr("%n GB of space available", "", m_bytes_available / GB_BYTES);
    if (m_bytes_available < m_required_space_gb * GB_BYTES) {
        freeString += " " + tr("(of %n GB needed)", "", m_required_space_gb);
        ui->freeSpace->setStyleSheet("QLabel { color: #800000 }");
    } else if (m_bytes_available / GB_BYTES - m_required_space_gb < 10) {
        freeString += " " + tr("(%n GB needed for full chain)", "", m_required_space_gb);
        ui->freeSpace->setStyleSheet("QLabel { color: #999900 }");
    } else {
        ui->freeSpace->setStyleSheet("");
    }
    ui->freeSpace->setText(freeString + ".");
}

void Intro::on_dataDirectory_textChanged(const QString &dataDirStr)
{
    /* Disable OK button until check result comes in */
    ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(false);
    checkPath(dataDirStr);
}

void Intro::on_ellipsisButton_clicked()
{
    QString dir = QDir::toNativeSeparators(QFileDialog::getExistingDirectory(nullptr, tr("Choose data directory"), ui->dataDirectory->text()));
    if(!dir.isEmpty())
        ui->dataDirectory->setText(dir);
}

void Intro::on_dataDirDefault_clicked()
{
    setDataDirectory(GUIUtil::getDefaultDataDirectory());
}

void Intro::on_dataDirCustom_clicked()
{
    ui->dataDirectory->setEnabled(true);
    ui->ellipsisButton->setEnabled(true);
}

void Intro::startThread()
{
    thread = new QThread(this);
    FreespaceChecker *executor = new FreespaceChecker(this);
    executor->moveToThread(thread);

    connect(executor, &FreespaceChecker::reply, this, &Intro::setStatus);
    connect(this, &Intro::requestCheck, executor, &FreespaceChecker::check);
    /*  make sure executor object is deleted in its own thread */
    connect(thread, &QThread::finished, executor, &QObject::deleteLater);

    thread->start();
}

void Intro::checkPath(const QString &dataDir)
{
    mutex.lock();
    pathToCheck = dataDir;
    if(!signalled)
    {
        signalled = true;
        Q_EMIT requestCheck();
    }
    mutex.unlock();
}

QString Intro::getPathToCheck()
{
    QString retval;
    mutex.lock();
    retval = pathToCheck;
    signalled = false; /* new request can be queued now */
    mutex.unlock();
    return retval;
}

void Intro::UpdatePruneLabels(bool prune_checked)
{
    m_required_space_gb = m_blockchain_size_gb + m_chain_state_size_gb;
    QString storageRequiresMsg = tr("At least %1 GB of data will be stored in this directory, and it will grow over time.");
    if (prune_checked && m_prune_target_gb <= m_blockchain_size_gb) {
        m_required_space_gb = m_prune_target_gb + m_chain_state_size_gb;
        storageRequiresMsg = tr("Approximately %1 GB of data will be stored in this directory.");
    }
    ui->lblExplanation3->setVisible(prune_checked);
    ui->pruneGB->setEnabled(prune_checked);
    static constexpr uint64_t nPowTargetSpacing = 10 * 60;  // from chainparams, which we don't have at this stage
    static constexpr uint32_t expected_block_data_size = 2250000;  // includes undo data
    const uint64_t expected_backup_days = m_prune_target_gb * 1e9 / (uint64_t(expected_block_data_size) * 86400 / nPowTargetSpacing);
    ui->lblPruneSuffix->setText(
        //: Explanatory text on the capability of the current prune target.
        tr("(sufficient to restore backups %n day(s) old)", "", expected_backup_days));
    ui->sizeWarningLabel->setText(
        tr("%1 will download and store a copy of the TensorCash block chain.").arg(CLIENT_NAME) + " " +
        storageRequiresMsg.arg(m_required_space_gb) + " " +
        tr("The wallet will also be stored in this directory.")
    );
    this->adjustSize();
}
