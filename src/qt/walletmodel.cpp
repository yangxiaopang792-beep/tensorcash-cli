// Copyright (c) 2024-2025 The TensorCash Core developers
// Copyright (c) 2011-2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/walletmodel.h>

#include <qt/addresstablemodel.h>
#include <qt/clientmodel.h>
#include <qt/guiconstants.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>
#include <qt/paymentserver.h>
#include <qt/recentrequeststablemodel.h>
#include <qt/sendcoinsdialog.h>
#include <qt/tormanager.h>
#include <qt/transactiontablemodel.h>
#include <QCryptographicHash>
#include <QDebug>
#include <QDir>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QProcessEnvironment>
#include <QPair>
#include <QRegularExpression>
#include <QStandardPaths>
#include <QUuid>
#include <QStringList>
#include <cmath>

#include <logging.h>
#include <common/args.h> // for GetBoolArg
#include <interfaces/handler.h>
#include <interfaces/node.h>
#include <key_io.h>
#include <node/interface_ui.h>
#include <node/types.h>
#include <psbt.h>
#include <script/interpreter.h>
#include <util/translation.h>
#include <wallet/coincontrol.h>
#include <wallet/wallet.h> // for CRecipient
#include <assets/asset.h> // for asset types
#include <script/script.h>    // for script building
#include <serialize.h>         // for WriteLE64
#include <primitives/transaction.h> // for CTransaction, CMutableTransaction
#include <univalue.h>          // for UniValue
#include <addresstype.h>       // for WitnessV2Taproot, ExtractDestination
#include <core_io.h>           // for EncodeHexTx, DecodeHexTx
#include <util/strencodings.h> // for HexStr
#include <rpc/util.h>          // for ValueFromAmount

#include <algorithm>
#include <map>
#include <stdint.h>
#include <functional>

#include <QDebug>
#include <QMessageBox>
#include <QMetaType>
#include <QSet>
#include <QTimer>

// Default BTC value for asset outputs
// Must be high enough to avoid dust rejection once TLV is added
static constexpr CAmount DEFAULT_ASSET_OUTPUT_VALUE = 1000; // 0.00001 BTC (1k sats), matches RPC

using wallet::CCoinControl;
using wallet::CRecipient;
using wallet::DEFAULT_DISABLE_WALLET;

namespace {

void AppendExtraOptionsToUniValue(const QVariantMap& extraOptions, UniValue& options, bool& hasOptions)
{
    for (auto it = extraOptions.constBegin(); it != extraOptions.constEnd(); ++it) {
        const QVariant& value = it.value();
        if (!value.isValid()) {
            continue;
        }

        UniValue converted;
        switch (value.typeId()) {
        case QMetaType::Bool:
            converted.setBool(value.toBool());
            break;
        case QMetaType::Int:
        case QMetaType::LongLong:
            converted.setInt(static_cast<int64_t>(value.toLongLong()));
            break;
        case QMetaType::UInt:
        case QMetaType::ULongLong:
            converted.setInt(static_cast<int64_t>(value.toULongLong()));
            break;
        case QMetaType::Double: {
            converted.setNumStr(QString::number(value.toDouble(), 'f', 8).toStdString());
            break;
        }
        default:
            converted.setStr(value.toString().toStdString());
            break;
        }

        options.pushKV(it.key().toStdString(), converted);
        hasOptions = true;
    }
}

} // namespace

WalletModel::WalletModel(std::unique_ptr<interfaces::Wallet> wallet, ClientModel& client_model, const PlatformStyle *platformStyle, QObject *parent) :
    QObject(parent),
    m_wallet(std::move(wallet)),
    m_client_model(&client_model),
    m_node(client_model.node()),
    optionsModel(client_model.getOptionsModel()),
    timer(new QTimer(this))
{
    addressTableModel = new AddressTableModel(this);
    transactionTableModel = new TransactionTableModel(platformStyle, this);
    recentRequestsTableModel = new RecentRequestsTableModel(this);

    subscribeToCoreSignals();
}

WalletModel::~WalletModel()
{
    unsubscribeFromCoreSignals();
}

void WalletModel::startPollBalance()
{
    // Update the cached balance right away, so every view can make use of it,
    // so them don't need to waste resources recalculating it.
    pollBalanceChanged();

    // This timer will be fired repeatedly to update the balance
    // Since the QTimer::timeout is a private signal, it cannot be used
    // in the GUIUtil::ExceptionSafeConnect directly.
    connect(timer, &QTimer::timeout, this, &WalletModel::timerTimeout);
    GUIUtil::ExceptionSafeConnect(this, &WalletModel::timerTimeout, this, &WalletModel::pollBalanceChanged);
    timer->start(MODEL_UPDATE_DELAY);
}

void WalletModel::setClientModel(ClientModel* client_model)
{
    m_client_model = client_model;
    if (!m_client_model) timer->stop();
}

void WalletModel::updateStatus()
{
    EncryptionStatus newEncryptionStatus = getEncryptionStatus();

    if(cachedEncryptionStatus != newEncryptionStatus) {
        Q_EMIT encryptionStatusChanged();
    }
}

void WalletModel::pollBalanceChanged()
{
    // Avoid recomputing wallet balances unless a TransactionChanged or
    // BlockTip notification was received.
    if (!fForceCheckBalanceChanged && m_cached_last_update_tip == getLastBlockProcessed()) return;

    // Try to get balances and return early if locks can't be acquired. This
    // avoids the GUI from getting stuck on periodical polls if the core is
    // holding the locks for a longer time - for example, during a wallet
    // rescan.
    interfaces::WalletBalances new_balances;
    uint256 block_hash;
    if (!m_wallet->tryGetBalances(new_balances, block_hash)) {
        return;
    }

    if (fForceCheckBalanceChanged || block_hash != m_cached_last_update_tip) {
        fForceCheckBalanceChanged = false;

        // Balance and number of transactions might have changed
        m_cached_last_update_tip = block_hash;

        checkBalanceChanged(new_balances);
        if(transactionTableModel)
            transactionTableModel->updateConfirmations();
    }
}

void WalletModel::checkBalanceChanged(const interfaces::WalletBalances& new_balances)
{
    if (new_balances.balanceChanged(m_cached_balances)) {
        m_cached_balances = new_balances;
        Q_EMIT balanceChanged(new_balances);
    }
}

interfaces::WalletBalances WalletModel::getCachedBalance() const
{
    return m_cached_balances;
}

void WalletModel::updateTransaction()
{
    // Balance and number of transactions might have changed
    fForceCheckBalanceChanged = true;
}

void WalletModel::updateAddressBook(const QString &address, const QString &label,
        bool isMine, wallet::AddressPurpose purpose, int status)
{
    if(addressTableModel)
        addressTableModel->updateEntry(address, label, isMine, purpose, status);
}

bool WalletModel::validateAddress(const QString& address) const
{
    return IsValidDestinationString(address.toStdString());
}

WalletModel::SendCoinsReturn WalletModel::prepareTransaction(WalletModelTransaction &transaction, const CCoinControl& coinControl)
{
    CAmount total = 0;
    bool fSubtractFeeFromAmount = false;
    QList<SendCoinsRecipient> recipients = transaction.getRecipients();
    std::vector<CRecipient> vecSend;

    if(recipients.empty())
    {
        return OK;
    }

    // Check if this is an asset transaction
    bool is_asset_transaction = false;
    uint256 asset_id;
    for (const SendCoinsRecipient &rcp : recipients) {
        if (rcp.asset_id.has_value()) {
            if (!is_asset_transaction) {
                is_asset_transaction = true;
                asset_id = rcp.asset_id.value();
            } else if (asset_id != rcp.asset_id.value()) {
                // Mixed assets not supported
                return InvalidAddress;
            }
        }
    }

    // If this is an asset transaction, delegate to specialized handler
    if (is_asset_transaction) {
        return prepareAssetTransaction(transaction, coinControl, asset_id);
    }

    QSet<QString> setAddress; // Used to detect duplicates
    int nAddresses = 0;

    // Pre-check input data for validity
    for (const SendCoinsRecipient &rcp : recipients)
    {
        if (rcp.fSubtractFeeFromAmount)
            fSubtractFeeFromAmount = true;
        {   // User-entered bitcoin address / amount:
            if(!validateAddress(rcp.address))
            {
                return InvalidAddress;
            }
            if(rcp.amount <= 0)
            {
                return InvalidAmount;
            }
            setAddress.insert(rcp.address);
            ++nAddresses;

            CRecipient recipient{DecodeDestination(rcp.address.toStdString()), rcp.amount, rcp.fSubtractFeeFromAmount};
            vecSend.push_back(recipient);

            total += rcp.amount;
        }
    }
    if(setAddress.size() != nAddresses)
    {
        return DuplicateAddress;
    }

    // If no coin was manually selected, use the cached balance
    // Future: can merge this call with 'createTransaction'.
    CAmount nBalance = getAvailableBalance(&coinControl);

    if(total > nBalance)
    {
        return AmountExceedsBalance;
    }

    try {
        CAmount nFeeRequired = 0;
        int nChangePosRet = -1;

        auto& newTx = transaction.getWtx();
        const auto& res = m_wallet->createTransaction(vecSend, coinControl, /*sign=*/!wallet().privateKeysDisabled(), nChangePosRet, nFeeRequired);
        newTx = res ? *res : nullptr;
        transaction.setTransactionFee(nFeeRequired);
        if (fSubtractFeeFromAmount && newTx)
            transaction.reassignAmounts(nChangePosRet);

        if(!newTx)
        {
            if(!fSubtractFeeFromAmount && (total + nFeeRequired) > nBalance)
            {
                return SendCoinsReturn(AmountWithFeeExceedsBalance);
            }
            Q_EMIT message(tr("Send Coins"), QString::fromStdString(util::ErrorString(res).translated),
                CClientUIInterface::MSG_ERROR);
            return TransactionCreationFailed;
        }

        // Reject absurdly high fee. (This can never happen because the
        // wallet never creates transactions with fee greater than
        // m_default_max_tx_fee. This merely a belt-and-suspenders check).
        if (nFeeRequired > m_wallet->getDefaultMaxTxFee()) {
            return AbsurdFee;
        }
    } catch (const std::runtime_error& err) {
        // Something unexpected happened, instruct user to report this bug.
        Q_EMIT message(tr("Send Coins"), QString::fromStdString(err.what()),
                       CClientUIInterface::MSG_ERROR);
        return TransactionCreationFailed;
    }

    return SendCoinsReturn(OK);
}

WalletModel::SendCoinsReturn WalletModel::prepareAssetTransaction(WalletModelTransaction &transaction, const CCoinControl& coinControl, const uint256& asset_id)
{
    QList<SendCoinsRecipient> recipients = transaction.getRecipients();
    if (recipients.empty()) {
        return OK;
    }

    // Validate that all recipients are for the same asset
    for (const SendCoinsRecipient &rcp : recipients) {
        if (!validateAddress(rcp.address)) {
            return InvalidAddress;
        }
        if (rcp.asset_units <= 0) {
            return InvalidAmount;
        }
    }

    // For now, only support single recipient (multi-recipient requires batching multiple sendasset calls)
    if (recipients.size() > 1) {
        Q_EMIT message(tr("Send Coins"), tr("Multiple asset recipients not yet supported in GUI. Please send one at a time."),
            CClientUIInterface::MSG_ERROR);
        return TransactionCreationFailed;
    }

    const SendCoinsRecipient& rcp = recipients.first();

    // Use sendasset RPC which handles ICU_KEYWRAP automatically
    try {
        UniValue params(UniValue::VARR);
        params.push_back(asset_id.ToString());
        params.push_back(rcp.address.toStdString());
        params.push_back(static_cast<int64_t>(rcp.asset_units));

        // Build options
        UniValue options(UniValue::VOBJ);
        if (coinControl.m_feerate) {
            options.pushKV("fee_rate", coinControl.m_feerate->GetFeePerK() / 1000.0);  // Convert to sat/vB
        }
        options.pushKV("broadcast", false);  // We'll broadcast via commitTransaction
        options.pushKV("replaceable", coinControl.m_signal_bip125_rbf.value_or(true));
        params.push_back(options);

        // Call sendasset RPC
        LogPrintf("prepareAssetTransaction: Calling sendasset RPC with asset_id=%s, address=%s, amount=%d\n",
                  asset_id.ToString(), rcp.address.toStdString(), rcp.asset_units);
        UniValue result = m_node.executeRpc("sendasset", params, getWalletName().toStdString());

        // Extract transaction hex and fee
        std::string hex = result["hex"].get_str();
        CAmount fee = AmountFromValue(result["fee"]);

        // Deserialize transaction
        CMutableTransaction mtx;
        if (!DecodeHexTx(mtx, hex, false, true)) {
            Q_EMIT message(tr("Send Coins"), tr("Failed to decode transaction from sendasset RPC"),
                CClientUIInterface::MSG_ERROR);
            return TransactionCreationFailed;
        }

        // Store in transaction object
        auto txRef = std::make_shared<const CTransaction>(mtx);
        transaction.setTransactionFee(fee);
        transaction.getWtx() = txRef;

    } catch (const std::exception& e) {
        LogPrintf("prepareAssetTransaction: std::exception caught: %s\n", e.what());
        Q_EMIT message(tr("Send Coins"), QString::fromStdString(e.what()),
            CClientUIInterface::MSG_ERROR);
        return TransactionCreationFailed;
    } catch (...) {
        LogPrintf("prepareAssetTransaction: Unknown exception caught (non-std::exception). This usually means sendasset RPC failed.\n");
        Q_EMIT message(tr("Send Coins"), tr("Failed to prepare asset transaction. Please check that you have sufficient balance and the fee rate is adequate. Try increasing the transaction fee."),
            CClientUIInterface::MSG_ERROR);
        return TransactionCreationFailed;
    }

    return SendCoinsReturn(OK);
}

void WalletModel::sendCoins(WalletModelTransaction& transaction)
{
    QByteArray transaction_array; /* store serialized transaction */

    {
        std::vector<std::pair<std::string, std::string>> vOrderForm;
        for (const SendCoinsRecipient &rcp : transaction.getRecipients())
        {
            if (!rcp.message.isEmpty()) // Message from normal bitcoin:URI (bitcoin:123...?message=example)
                vOrderForm.emplace_back("Message", rcp.message.toStdString());
        }

        auto& newTx = transaction.getWtx();
        wallet().commitTransaction(newTx, /*value_map=*/{}, std::move(vOrderForm));

        DataStream ssTx;
        ssTx << TX_WITH_WITNESS(*newTx);
        transaction_array.append((const char*)ssTx.data(), ssTx.size());
    }

    // Add addresses / update labels that we've sent to the address book,
    // and emit coinsSent signal for each recipient
    for (const SendCoinsRecipient &rcp : transaction.getRecipients())
    {
        {
            std::string strAddress = rcp.address.toStdString();
            CTxDestination dest = DecodeDestination(strAddress);
            std::string strLabel = rcp.label.toStdString();
            {
                // Check if we have a new address or an updated label
                std::string name;
                if (!m_wallet->getAddress(
                     dest, &name, /* is_mine= */ nullptr, /* purpose= */ nullptr))
                {
                    m_wallet->setAddressBook(dest, strLabel, wallet::AddressPurpose::SEND);
                }
                else if (name != strLabel)
                {
                    m_wallet->setAddressBook(dest, strLabel, {}); // {} means don't change purpose
                }
            }
        }
        Q_EMIT coinsSent(this, rcp, transaction_array);
    }

    checkBalanceChanged(m_wallet->getBalances()); // update balance immediately, otherwise there could be a short noticeable delay until pollBalanceChanged hits
}

OptionsModel* WalletModel::getOptionsModel() const
{
    return optionsModel;
}

AddressTableModel* WalletModel::getAddressTableModel() const
{
    return addressTableModel;
}

TransactionTableModel* WalletModel::getTransactionTableModel() const
{
    return transactionTableModel;
}

RecentRequestsTableModel* WalletModel::getRecentRequestsTableModel() const
{
    return recentRequestsTableModel;
}

WalletModel::EncryptionStatus WalletModel::getEncryptionStatus() const
{
    if(!m_wallet->isCrypted())
    {
        // A previous bug allowed for watchonly wallets to be encrypted (encryption keys set, but nothing is actually encrypted).
        // To avoid misrepresenting the encryption status of such wallets, we only return NoKeys for watchonly wallets that are unencrypted.
        if (m_wallet->privateKeysDisabled()) {
            return NoKeys;
        }
        return Unencrypted;
    }
    else if(m_wallet->isLocked())
    {
        return Locked;
    }
    else
    {
        return Unlocked;
    }
}

bool WalletModel::setWalletEncrypted(const SecureString& passphrase)
{
    return m_wallet->encryptWallet(passphrase);
}

bool WalletModel::setWalletLocked(bool locked, const SecureString &passPhrase)
{
    if(locked)
    {
        // Lock
        return m_wallet->lock();
    }
    else
    {
        // Unlock
        return m_wallet->unlock(passPhrase);
    }
}

bool WalletModel::changePassphrase(const SecureString &oldPass, const SecureString &newPass)
{
    m_wallet->lock(); // Make sure wallet is locked before attempting pass change
    return m_wallet->changeWalletPassphrase(oldPass, newPass);
}

// Handlers for core signals
static void NotifyUnload(WalletModel* walletModel)
{
    qDebug() << "NotifyUnload";
    bool invoked = QMetaObject::invokeMethod(walletModel, "unload");
    assert(invoked);
}

static void NotifyKeyStoreStatusChanged(WalletModel *walletmodel)
{
    qDebug() << "NotifyKeyStoreStatusChanged";
    bool invoked = QMetaObject::invokeMethod(walletmodel, "updateStatus", Qt::QueuedConnection);
    assert(invoked);
}

static void NotifyAddressBookChanged(WalletModel *walletmodel,
        const CTxDestination &address, const std::string &label, bool isMine,
        wallet::AddressPurpose purpose, ChangeType status)
{
    QString strAddress = QString::fromStdString(EncodeDestination(address));
    QString strLabel = QString::fromStdString(label);

    qDebug() << "NotifyAddressBookChanged: " + strAddress + " " + strLabel + " isMine=" + QString::number(isMine) + " purpose=" + QString::number(static_cast<uint8_t>(purpose)) + " status=" + QString::number(status);
    bool invoked = QMetaObject::invokeMethod(walletmodel, "updateAddressBook",
                              Q_ARG(QString, strAddress),
                              Q_ARG(QString, strLabel),
                              Q_ARG(bool, isMine),
                              Q_ARG(wallet::AddressPurpose, purpose),
                              Q_ARG(int, status));
    assert(invoked);
}

static void NotifyTransactionChanged(WalletModel *walletmodel, const Txid& hash, ChangeType status)
{
    Q_UNUSED(hash);
    Q_UNUSED(status);
    bool invoked = QMetaObject::invokeMethod(walletmodel, "updateTransaction", Qt::QueuedConnection);
    assert(invoked);
}

static void ShowProgress(WalletModel *walletmodel, const std::string &title, int nProgress)
{
    // emits signal "showProgress"
    bool invoked = QMetaObject::invokeMethod(walletmodel, "showProgress", Qt::QueuedConnection,
                              Q_ARG(QString, QString::fromStdString(title)),
                              Q_ARG(int, nProgress));
    assert(invoked);
}

static void NotifyCanGetAddressesChanged(WalletModel* walletmodel)
{
    bool invoked = QMetaObject::invokeMethod(walletmodel, "canGetAddressesChanged");
    assert(invoked);
}

void WalletModel::subscribeToCoreSignals()
{
    // Connect signals to wallet
    m_handler_unload = m_wallet->handleUnload(std::bind(&NotifyUnload, this));
    m_handler_status_changed = m_wallet->handleStatusChanged(std::bind(&NotifyKeyStoreStatusChanged, this));
    m_handler_address_book_changed = m_wallet->handleAddressBookChanged(std::bind(NotifyAddressBookChanged, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5));
    m_handler_transaction_changed = m_wallet->handleTransactionChanged(std::bind(NotifyTransactionChanged, this, std::placeholders::_1, std::placeholders::_2));
    m_handler_show_progress = m_wallet->handleShowProgress(std::bind(ShowProgress, this, std::placeholders::_1, std::placeholders::_2));
    m_handler_can_get_addrs_changed = m_wallet->handleCanGetAddressesChanged(std::bind(NotifyCanGetAddressesChanged, this));
}

void WalletModel::unsubscribeFromCoreSignals()
{
    // Disconnect signals from wallet
    m_handler_unload->disconnect();
    m_handler_status_changed->disconnect();
    m_handler_address_book_changed->disconnect();
    m_handler_transaction_changed->disconnect();
    m_handler_show_progress->disconnect();
    m_handler_can_get_addrs_changed->disconnect();
}

// WalletModel::UnlockContext implementation
WalletModel::UnlockContext WalletModel::requestUnlock()
{
    // Bugs in earlier versions may have resulted in wallets with private keys disabled to become "encrypted"
    // (encryption keys are present, but not actually doing anything).
    // To avoid issues with such wallets, check if the wallet has private keys disabled, and if so, return a context
    // that indicates the wallet is not encrypted.
    if (m_wallet->privateKeysDisabled()) {
        return UnlockContext(this, /*valid=*/true, /*relock=*/false);
    }
    bool was_locked = getEncryptionStatus() == Locked;
    if(was_locked)
    {
        // Request UI to unlock wallet
        Q_EMIT requireUnlock();
    }
    // If wallet is still locked, unlock was failed or cancelled, mark context as invalid
    bool valid = getEncryptionStatus() != Locked;

    return UnlockContext(this, valid, was_locked);
}

WalletModel::UnlockContext::UnlockContext(WalletModel *_wallet, bool _valid, bool _relock):
        wallet(_wallet),
        valid(_valid),
        relock(_relock)
{
}

WalletModel::UnlockContext::~UnlockContext()
{
    if(valid && relock)
    {
        wallet->setWalletLocked(true);
    }
}

bool WalletModel::bumpFee(Txid hash, Txid& new_hash)
{
    CCoinControl coin_control;
    coin_control.m_signal_bip125_rbf = true;
    std::vector<bilingual_str> errors;
    CAmount old_fee;
    CAmount new_fee;
    CMutableTransaction mtx;
    if (!m_wallet->createBumpTransaction(hash, coin_control, errors, old_fee, new_fee, mtx)) {
        QMessageBox::critical(nullptr, tr("Fee bump error"), tr("Increasing transaction fee failed") + "<br />(" +
            (errors.size() ? QString::fromStdString(errors[0].translated) : "") +")");
        return false;
    }

    // allow a user based fee verification
    /*: Asks a user if they would like to manually increase the fee of a transaction that has already been created. */
    QString questionString = tr("Do you want to increase the fee?");
    questionString.append("<br />");
    questionString.append("<table style=\"text-align: left;\">");
    questionString.append("<tr><td>");
    questionString.append(tr("Current fee:"));
    questionString.append("</td><td>");
    questionString.append(BitcoinUnits::formatHtmlWithUnit(getOptionsModel()->getDisplayUnit(), old_fee));
    questionString.append("</td></tr><tr><td>");
    questionString.append(tr("Increase:"));
    questionString.append("</td><td>");
    questionString.append(BitcoinUnits::formatHtmlWithUnit(getOptionsModel()->getDisplayUnit(), new_fee - old_fee));
    questionString.append("</td></tr><tr><td>");
    questionString.append(tr("New fee:"));
    questionString.append("</td><td>");
    questionString.append(BitcoinUnits::formatHtmlWithUnit(getOptionsModel()->getDisplayUnit(), new_fee));
    questionString.append("</td></tr></table>");

    // Display warning in the "Confirm fee bump" window if the "Coin Control Features" option is enabled
    if (getOptionsModel()->getCoinControlFeatures()) {
        questionString.append("<br><br>");
        questionString.append(tr("Warning: This may pay the additional fee by reducing change outputs or adding inputs, when necessary. It may add a new change output if one does not already exist. These changes may potentially leak privacy."));
    }

    const bool enable_send{!wallet().privateKeysDisabled() || wallet().hasExternalSigner()};
    const bool always_show_unsigned{getOptionsModel()->getEnablePSBTControls()};
    auto confirmationDialog = new SendConfirmationDialog(tr("Confirm fee bump"), questionString, "", "", SEND_CONFIRM_DELAY, enable_send, always_show_unsigned, nullptr);
    confirmationDialog->setAttribute(Qt::WA_DeleteOnClose);
    // TODO: Replace QDialog::exec() with safer QDialog::show().
    const auto retval = static_cast<QMessageBox::StandardButton>(confirmationDialog->exec());

    // cancel sign&broadcast if user doesn't want to bump the fee
    if (retval != QMessageBox::Yes && retval != QMessageBox::Save) {
        return false;
    }

    // Short-circuit if we are returning a bumped transaction PSBT to clipboard
    if (retval == QMessageBox::Save) {
        // "Create Unsigned" clicked
        PartiallySignedTransaction psbtx(mtx);
        bool complete = false;
        const auto err{wallet().fillPSBT(SIGHASH_ALL, /*sign=*/false, /*bip32derivs=*/true, nullptr, psbtx, complete)};
        if (err || complete) {
            QMessageBox::critical(nullptr, tr("Fee bump error"), tr("Can't draft transaction."));
            return false;
        }
        // Serialize the PSBT
        DataStream ssTx{};
        ssTx << psbtx;
        GUIUtil::setClipboard(EncodeBase64(ssTx.str()).c_str());
        Q_EMIT message(tr("PSBT copied"), tr("Fee-bump PSBT copied to clipboard"), CClientUIInterface::MSG_INFORMATION | CClientUIInterface::MODAL);
        return true;
    }

    WalletModel::UnlockContext ctx(requestUnlock());
    if (!ctx.isValid()) {
        return false;
    }

    assert(!m_wallet->privateKeysDisabled() || wallet().hasExternalSigner());

    // sign bumped transaction
    if (!m_wallet->signBumpTransaction(mtx)) {
        QMessageBox::critical(nullptr, tr("Fee bump error"), tr("Can't sign transaction."));
        return false;
    }
    // commit the bumped transaction
    if(!m_wallet->commitBumpTransaction(hash, std::move(mtx), errors, new_hash)) {
        QMessageBox::critical(nullptr, tr("Fee bump error"), tr("Could not commit transaction") + "<br />(" +
            QString::fromStdString(errors[0].translated)+")");
        return false;
    }
    return true;
}

void WalletModel::displayAddress(std::string sAddress) const
{
    CTxDestination dest = DecodeDestination(sAddress);
    try {
        util::Result<void> result = m_wallet->displayAddress(dest);
        if (!result) {
            QMessageBox::warning(nullptr, tr("Signer error"), QString::fromStdString(util::ErrorString(result).translated));
        }
    } catch (const std::runtime_error& e) {
        QMessageBox::critical(nullptr, tr("Can't display address"), e.what());
    }
}

bool WalletModel::isWalletEnabled()
{
   return !gArgs.GetBoolArg("-disablewallet", DEFAULT_DISABLE_WALLET);
}

QString WalletModel::getWalletName() const
{
    return QString::fromStdString(m_wallet->getWalletName());
}

bool WalletModel::unlockCoins(const QList<QPair<QString, int>>& outputs) const
{
    if (!m_client_model || outputs.isEmpty()) {
        return true;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(true); // unlock

        UniValue outsArr(UniValue::VARR);
        for (const auto& entry : outputs) {
            UniValue obj(UniValue::VOBJ);
            obj.pushKV("txid", entry.first.toStdString());
            obj.pushKV("vout", entry.second);
            outsArr.push_back(obj);
        }

        params.push_back(outsArr);
        m_client_model->node().executeRpc("lockunspent", params, getWalletName().toStdString());
        return true;
    } catch (...) {
        return false;
    }
}

QString WalletModel::getDisplayName() const
{
    return GUIUtil::WalletDisplayName(getWalletName());
}

bool WalletModel::isMultiwallet() const
{
    return m_node.walletLoader().getWallets().size() > 1;
}

void WalletModel::refresh(bool pk_hash_only)
{
    addressTableModel = new AddressTableModel(this, pk_hash_only);
}

uint256 WalletModel::getLastBlockProcessed() const
{
    return m_client_model ? m_client_model->getBestBlockHash() : uint256{};
}

CAmount WalletModel::getAvailableBalance(const CCoinControl* control)
{
    // No selected coins, return the cached balance
    if (!control || !control->HasSelected()) {
        const interfaces::WalletBalances& balances = getCachedBalance();
        CAmount available_balance = balances.balance;
        // if wallet private keys are disabled, this is a watch-only wallet
        // so, let's include the watch-only balance.
        if (balances.have_watch_only && m_wallet->privateKeysDisabled()) {
            available_balance += balances.watch_only_balance;
        }
        return available_balance;
    }
    // Fetch balance from the wallet, taking into account the selected coins
    return wallet().getAvailableBalance(*control);
}

std::vector<interfaces::AssetBalance> WalletModel::getAssetBalances() const
{
    if (!m_cached_asset_balances.empty()) {
        return m_cached_asset_balances;
    }
    return m_wallet->getAssetBalances();
}

void WalletModel::refreshAssetBalances()
{
    std::vector<interfaces::AssetBalance> new_balances = m_wallet->getAssetBalances();

    // Check if balances have changed
    bool changed = false;

    if (new_balances.size() != m_cached_asset_balances.size()) {
        changed = true;
    } else {
        // Create maps for efficient comparison by asset ID
        std::map<uint256, interfaces::AssetBalance> new_map;
        std::map<uint256, interfaces::AssetBalance> cached_map;

        for (const auto& bal : new_balances) {
            new_map[bal.asset_id] = bal;
        }
        for (const auto& bal : m_cached_asset_balances) {
            cached_map[bal.asset_id] = bal;
        }

        // Compare each asset's fields
        for (const auto& [asset_id, new_bal] : new_map) {
            auto cached_it = cached_map.find(asset_id);
            if (cached_it == cached_map.end()) {
                changed = true;
                break;
            }

            const auto& cached = cached_it->second;
            if (new_bal.balance != cached.balance ||
                new_bal.pending != cached.pending ||
                new_bal.locked != cached.locked ||
                new_bal.ticker != cached.ticker ||
                new_bal.has_ticker != cached.has_ticker ||
                new_bal.decimals != cached.decimals ||
                new_bal.has_decimals != cached.has_decimals ||
                new_bal.is_registered != cached.is_registered ||
                new_bal.utxo_count != cached.utxo_count) {
                changed = true;
                break;
            }
        }
    }

    if (changed) {
        m_cached_asset_balances = std::move(new_balances);
        Q_EMIT assetBalancesChanged(m_cached_asset_balances);
    }
}

// ML-DSA (Post-Quantum) address generation implementation
WalletModel::MLDSAAddressInfo WalletModel::generateMLDSAAddress(int level)
{
    MLDSAAddressInfo info;
    info.success = false;
    info.level = level;

    // Validate security level
    if (level != 44 && level != 65 && level != 87) {
        info.error = tr("Invalid ML-DSA security level. Must be 44, 65, or 87.");
        return info;
    }

#ifndef ENABLE_MLDSA
    info.error = tr("ML-DSA support not enabled in this build. Rebuild with -DENABLE_MLDSA=ON.");
    return info;
#endif

    // Ensure wallet is unlocked so we can derive and store new ML-DSA keys
    WalletModel::UnlockContext ctx(requestUnlock());
    if (!ctx.isValid()) {
        info.error = tr("Wallet is locked. Please unlock wallet to generate ML-DSA addresses.");
        return info;
    }

    try {
        // Call generatemldsaaddress RPC through client model
        if (!m_client_model) {
            info.error = tr("Client model not available");
            return info;
        }

        UniValue params(UniValue::VARR);
        params.push_back(level);

        UniValue result = m_client_model->node().executeRpc("generatemldsaaddress", params, getWalletName().toStdString());

        info.address = QString::fromStdString(result["address"].get_str());
        info.pubkey = QString::fromStdString(result["pubkey"].get_str());
        info.scriptPubKey = QString::fromStdString(result["scriptPubKey"].get_str());
        info.tapscript = QString::fromStdString(result["tapscript"].get_str());
        info.internal_pubkey = QString::fromStdString(result["internal_pubkey"].get_str());
        info.merkle_root = QString::fromStdString(result["merkle_root"].get_str());
        info.output_pubkey = QString::fromStdString(result["output_pubkey"].get_str());
        info.leaf_hash = QString::fromStdString(result["leaf_hash"].get_str());
        info.encoded_pubkey = QString::fromStdString(result["encoded_pubkey"].get_str());
        info.level = result["level"].getInt<int>();
        info.parity = result["parity"].get_bool();
        info.warning = QString::fromStdString(result["warning"].get_str());

        info.success = true;

    } catch (const std::exception& e) {
        info.error = tr("Failed to generate ML-DSA address: %1").arg(QString::fromStdString(e.what()));
        info.success = false;
    }

    return info;
}

bool WalletModel::mldsaEnabled() const
{
#ifdef ENABLE_MLDSA
    return true;
#else
    return false;
#endif
}

// Cosign bridge RPC wrapper implementations

WalletModel::CosignInitResult WalletModel::cosignInit(const QString& context, const QString& transport, int ttl_sec, const QString& relay_url)
{
    CosignInitResult result;

    if (!m_client_model) {
        result.error = tr("Client model not available");
        return result;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(""); // psbt (empty for session-only)
        params.push_back(context.toStdString());
        params.push_back(transport.toStdString());
        params.push_back(ttl_sec);

        // Add relay_url if provided (for WebSocket transport)
        if (!relay_url.isEmpty()) {
            params.push_back(relay_url.toStdString());
        }

        UniValue response = m_client_model->node().executeRpc("cosign.init", params, "");

        result.success = true;

        // Safely extract required fields with existence checks
        if (response.exists("session_id") && response["session_id"].isStr()) {
            result.session_id = QString::fromStdString(response["session_id"].get_str());
        }
        if (response.exists("invite_link") && response["invite_link"].isStr()) {
            result.invite_link = QString::fromStdString(response["invite_link"].get_str());
        }
        if (response.exists("invite_code") && response["invite_code"].isStr()) {
            result.invite_code = QString::fromStdString(response["invite_code"].get_str());
        }
        if (response.exists("qr_data") && response["qr_data"].isStr()) {
            result.qr_data = QString::fromStdString(response["qr_data"].get_str());
        }
        if (response.exists("sas") && response["sas"].isStr()) {
            result.sas = QString::fromStdString(response["sas"].get_str());
        }
        if (response.exists("sas_numeric") && response["sas_numeric"].isStr()) {
            result.sas_numeric = QString::fromStdString(response["sas_numeric"].get_str());
        }
        if (response.exists("transport_selected") && response["transport_selected"].isStr()) {
            result.transport_selected = QString::fromStdString(response["transport_selected"].get_str());
        }

    } catch (const UniValue& e) {
        result.success = false;
        result.error = tr("Failed to initialize cosign session: UniValue exception");
    } catch (const std::exception& e) {
        result.success = false;
        result.error = tr("Failed to initialize cosign session: %1").arg(QString::fromStdString(e.what()));
    } catch (...) {
        result.success = false;
        result.error = tr("Failed to initialize cosign session: Unknown exception");
    }

    return result;
}

WalletModel::CosignJoinResult WalletModel::cosignJoin(const QString& invite_link, const QString& context)
{
    CosignJoinResult result;

    if (!m_client_model) {
        result.error = tr("Client model not available");
        return result;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(invite_link.toStdString());
        params.push_back(context.toStdString());

        LogPrintf("WalletModel::cosignJoin: Calling cosign.join with params: %s\n", params.write().c_str());
        UniValue response = m_client_model->node().executeRpc("cosign.join", params, "");
        LogPrintf("WalletModel::cosignJoin: Got response: %s\n", response.write().c_str());

        result.success = true;

        // Safely extract fields with existence checks
        if (response.exists("session_id") && response["session_id"].isStr()) {
            result.session_id = QString::fromStdString(response["session_id"].get_str());
        }
        if (response.exists("sas") && response["sas"].isStr()) {
            result.sas = QString::fromStdString(response["sas"].get_str());
        }
        if (response.exists("sas_numeric") && response["sas_numeric"].isStr()) {
            result.sas_numeric = QString::fromStdString(response["sas_numeric"].get_str());
        }
        if (response.exists("transport") && response["transport"].isStr()) {
            result.transport = QString::fromStdString(response["transport"].get_str());
        }
        if (response.exists("relay_url") && response["relay_url"].isStr()) {
            result.relay_url = QString::fromStdString(response["relay_url"].get_str());
        }

    } catch (const UniValue& e) {
        result.success = false;
        QString errorMsg = QString::fromStdString(e.write(0, 0));
        result.error = tr("Failed to join cosign session: %1").arg(errorMsg);
        LogPrintf("WalletModel::cosignJoin: UniValue exception: %s\n", errorMsg.toStdString().c_str());
    } catch (const std::exception& e) {
        result.success = false;
        result.error = tr("Failed to join cosign session: %1").arg(QString::fromStdString(e.what()));
        LogPrintf("WalletModel::cosignJoin: std::exception: %s\n", e.what());
    } catch (...) {
        result.success = false;
        result.error = tr("Failed to join cosign session: Unknown exception");
        LogPrintf("WalletModel::cosignJoin: Unknown exception\n");
    }

    return result;
}

WalletModel::CosignHandshakeResult WalletModel::cosignHandshakeAuto(const QString& session_id, bool is_initiator)
{
    CosignHandshakeResult result;

    if (!m_client_model) {
        result.error = tr("Client model not available");
        return result;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(session_id.toStdString());
        params.push_back(is_initiator);

        UniValue response = m_client_model->node().executeRpc("cosign.handshake_auto", params, "");

        result.success = true;

        // Safely extract fields with existence checks
        if (response.exists("handshake_complete") && response["handshake_complete"].isBool()) {
            result.handshake_complete = response["handshake_complete"].get_bool();
        }
        if (response.exists("sas") && response["sas"].isStr()) {
            result.sas = QString::fromStdString(response["sas"].get_str());
        }
        if (response.exists("sas_numeric") && response["sas_numeric"].isStr()) {
            result.sas_numeric = QString::fromStdString(response["sas_numeric"].get_str());
        }
        if (response.exists("message") && response["message"].isStr()) {
            result.message = QString::fromStdString(response["message"].get_str());
        }

    } catch (const UniValue& e) {
        result.success = false;
        result.error = tr("Failed to complete handshake: UniValue exception: %1").arg(QString::fromStdString(e.write()));
    } catch (const std::exception& e) {
        result.success = false;
        result.error = tr("Failed to complete handshake: %1").arg(QString::fromStdString(e.what()));
    } catch (...) {
        result.success = false;
        result.error = tr("Failed to complete handshake: Unknown exception");
    }

    return result;
}

WalletModel::CosignSendResult WalletModel::cosignSend(const QString& session_id, const QString& payload_json)
{
    CosignSendResult result;

    if (!m_client_model) {
        result.error = tr("Client model not available");
        return result;
    }

    try {
        // Parse payload_json to UniValue
        UniValue payload;
        if (!payload.read(payload_json.toStdString())) {
            result.error = tr("Invalid JSON payload");
            return result;
        }

        UniValue params(UniValue::VARR);
        params.push_back(session_id.toStdString());
        params.push_back(payload);

        UniValue response = m_client_model->node().executeRpc("cosign.send", params, "");

        result.success = true;

        // Safely extract fields with existence checks
        if (response.exists("ok") && response["ok"].isBool()) {
            result.ok = response["ok"].get_bool();
        }
        if (response.exists("seq") && response["seq"].isNum()) {
            result.seq = response["seq"].getInt<int>();
        }

    } catch (const UniValue& e) {
        result.success = false;
        result.error = tr("Failed to send message: UniValue exception: %1").arg(QString::fromStdString(e.write()));
    } catch (const std::exception& e) {
        result.success = false;
        result.error = tr("Failed to send message: %1").arg(QString::fromStdString(e.what()));
    } catch (...) {
        result.success = false;
        result.error = tr("Failed to send message: Unknown exception");
    }

    return result;
}

WalletModel::CosignRecvResult WalletModel::cosignRecv(const QString& session_id, int timeout_ms)
{
    CosignRecvResult result;

    if (!m_client_model) {
        result.error = tr("Client model not available");
        return result;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(session_id.toStdString());
        params.push_back(timeout_ms);

        UniValue response = m_client_model->node().executeRpc("cosign.recv", params, "");

        result.success = true;
        // Convert payload back to JSON string
        if (response.exists("payload")) {
            result.payload_json = QString::fromStdString(response["payload"].write());
        }

    } catch (const UniValue& e) {
        result.success = false;
        result.error = tr("Failed to receive message: UniValue exception: %1").arg(QString::fromStdString(e.write()));
    } catch (const std::exception& e) {
        result.success = false;
        result.error = tr("Failed to receive message: %1").arg(QString::fromStdString(e.what()));
    } catch (...) {
        result.success = false;
        result.error = tr("Failed to receive message: Unknown exception");
    }

    return result;
}

bool WalletModel::cosignClose(const QString& session_id)
{
    if (!m_client_model) {
        return false;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(session_id.toStdString());

        UniValue response = m_client_model->node().executeRpc("cosign.close", params, "");

        // Safely access ok field with existence check
        if (response.exists("ok") && response["ok"].isBool()) {
            return response["ok"].get_bool();
        }
        return false;

    } catch (const UniValue& e) {
        return false;
    } catch (const std::exception& e) {
        return false;
    } catch (...) {
        return false;
    }
}

WalletModel::CosignStatusResult WalletModel::cosignStatus(const QString& session_id)
{
    CosignStatusResult result;

    if (!m_client_model) {
        result.error = tr("Client model not available");
        return result;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(session_id.toStdString());

        UniValue response = m_client_model->node().executeRpc("cosign.status", params, "");

        result.success = true;

        // Safely extract fields with existence checks
        if (response.exists("state") && response["state"].isStr()) {
            result.state = QString::fromStdString(response["state"].get_str());
        }
        if (response.exists("peer_verified") && response["peer_verified"].isBool()) {
            result.peer_verified = response["peer_verified"].get_bool();
        }
        if (response.exists("messages_sent") && response["messages_sent"].isNum()) {
            result.messages_sent = response["messages_sent"].getInt<int>();
        }
        if (response.exists("messages_received") && response["messages_received"].isNum()) {
            result.messages_received = response["messages_received"].getInt<int>();
        }
        if (response.exists("age_sec") && response["age_sec"].isNum()) {
            result.age_sec = response["age_sec"].getInt<int>();
        }
        if (response.exists("ttl_sec") && response["ttl_sec"].isNum()) {
            result.ttl_sec = response["ttl_sec"].getInt<int>();
        }
        if (response.exists("transport") && response["transport"].isStr()) {
            result.transport = QString::fromStdString(response["transport"].get_str());
        }

    } catch (const UniValue& e) {
        result.success = false;
        result.error = tr("Failed to get session status: UniValue exception");
    } catch (const std::exception& e) {
        result.success = false;
        result.error = tr("Failed to get session status: %1").arg(QString::fromStdString(e.what()));
    } catch (...) {
        result.success = false;
        result.error = tr("Failed to get session status: Unknown exception");
    }

    return result;
}

WalletModel::CosignPingResult WalletModel::cosignPing()
{
    CosignPingResult result;

    if (!m_client_model) {
        result.error = tr("Client model not available");
        return result;
    }

    try {
        UniValue params(UniValue::VARR);

        UniValue response = m_client_model->node().executeRpc("cosign.ping", params, "");

        result.success = true;

        // Safely extract fields with existence checks
        if (response.exists("bridge_alive") && response["bridge_alive"].isBool()) {
            result.bridge_alive = response["bridge_alive"].get_bool();
        }
        if (response.exists("version") && response["version"].isStr()) {
            result.version = QString::fromStdString(response["version"].get_str());
        }
        if (response.exists("uptime_sec") && response["uptime_sec"].isNum()) {
            result.uptime_sec = response["uptime_sec"].getInt<int>();
        }

        // Parse transports array
        if (response.exists("transports") && response["transports"].isArray()) {
            const UniValue& transports = response["transports"].get_array();
            for (size_t i = 0; i < transports.size(); ++i) {
                result.transports.append(QString::fromStdString(transports[i].get_str()));
            }
        }

        // Parse capabilities array
        if (response.exists("capabilities") && response["capabilities"].isArray()) {
            const UniValue& capabilities = response["capabilities"].get_array();
            for (size_t i = 0; i < capabilities.size(); ++i) {
                result.capabilities.append(QString::fromStdString(capabilities[i].get_str()));
            }
        }

    } catch (const UniValue& e) {
        result.success = false;
        result.bridge_alive = false;
        result.error = tr("Failed to ping bridge: UniValue exception");
    } catch (const std::exception& e) {
        result.success = false;
        result.error = tr("Failed to ping bridge: %1").arg(QString::fromStdString(e.what()));
    } catch (...) {
        result.success = false;
        result.error = tr("Failed to ping bridge: Unknown exception");
    }

    return result;
}

WalletModel::CosignAttestResult WalletModel::cosignAttest(const QString& session_id, const QString& address, const QString& signature)
{
    CosignAttestResult result;

    if (!m_client_model) {
        result.error = tr("Client model not available");
        return result;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(session_id.toStdString());
        params.push_back(address.toStdString());
        if (!signature.isEmpty()) {
            params.push_back(signature.toStdString());
        }

        UniValue response = m_client_model->node().executeRpc("cosign.attest", params, "");

        result.success = true;

        // Step 1: Challenge generation
        if (response.exists("challenge") && response["challenge"].isStr()) {
            result.challenge = QString::fromStdString(response["challenge"].get_str());
        }

        // Step 2: Verification result
        if (response.exists("verified") && response["verified"].isBool()) {
            result.verified = response["verified"].get_bool();
        }

        return result;

    } catch (const UniValue& e) {
        result.success = false;
        if (e.isObject() && e.exists("message")) {
            result.error = QString::fromStdString(e["message"].get_str());
        } else {
            result.error = tr("BIP-322 attestation failed: UniValue exception");
        }
        return result;
    } catch (const std::exception& e) {
        result.success = false;
        result.error = tr("BIP-322 attestation failed: %1").arg(QString::fromStdString(e.what()));
        return result;
    } catch (...) {
        result.success = false;
        result.error = tr("BIP-322 attestation failed: Unknown exception");
        return result;
    }
}

// ============================================================================
// Bulletin Board Trading RPCs
// ============================================================================

WalletModel::BulletinBoardInitResult WalletModel::bulletinBoardInit(const QStringList& relays, const QString& key_path)
{
    BulletinBoardInitResult result;

    if (!m_client_model) {
        result.error = tr("Client model not available");
        return result;
    }

    try {
        // Build params as object (matches bridge expectations)
        UniValue params(UniValue::VOBJ);

        // Only forward "relays" when the caller actually supplied some. The
        // bridge (cosign-bridge stdio.rs:handle_init_bb) treats an explicit
        // empty array as "connect to zero relays", and only falls back to its
        // default relay set when the key is ABSENT. Pushing an empty array
        // (e.g. the treasury path calling bulletinBoardInit(QStringList{}))
        // would leave the bulletin board with no Nostr relays — omit the key
        // when empty so the bridge defaults apply.
        if (!relays.isEmpty()) {
            UniValue relays_param(UniValue::VARR);
            for (const QString& relay : relays) {
                relays_param.push_back(relay.toStdString());
            }
            params.pushKV("relays", relays_param);
        }

        QString resolved_key_path = key_path;

        if (resolved_key_path.isEmpty()) {
            const QString envPath = QProcessEnvironment::systemEnvironment().value(QStringLiteral("TENSORCASH_NOSTR_KEY_PATH"));
            if (!envPath.isEmpty()) {
                resolved_key_path = envPath;
            }
        }

        if (resolved_key_path.isEmpty() && !m_bulletin_board_key_path.isEmpty()) {
            resolved_key_path = m_bulletin_board_key_path;
        }

        if (resolved_key_path.isEmpty()) {
            QString baseDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
            if (baseDir.isEmpty()) {
                baseDir = QDir::homePath() + "/.tensorcash";
            }

            QDir rootDir(baseDir);
            if (!rootDir.exists()) {
                rootDir.mkpath(".");
            }

            QString keyDirPath = rootDir.filePath(QStringLiteral("nostr_keys"));
            QDir keyDir(keyDirPath);
            if (!keyDir.exists()) {
                keyDir.mkpath(".");
            }

            QString sanitizedWallet = getWalletName();
            if (sanitizedWallet.isEmpty()) {
                sanitizedWallet = QStringLiteral("default");
            }
            sanitizedWallet.replace(QRegularExpression(QStringLiteral("[^a-zA-Z0-9_-]")), QStringLiteral("_"));

            const QString uuid = QUuid::createUuid().toString(QUuid::WithoutBraces);
            resolved_key_path = keyDir.filePath(QStringLiteral("%1_%2.nsec").arg(sanitizedWallet, uuid));
        }

        if (!resolved_key_path.isEmpty()) {
            qInfo() << "cosign.init_bb using nostr key file" << resolved_key_path;
            params.pushKV("nostr_key_path", resolved_key_path.toStdString());
        } else {
            qWarning() << "cosign.init_bb proceeding without explicit nostr key path (will fall back to bridge default)";
        }

        UniValue response = m_client_model->node().executeRpc("cosign.init_bb", params, "");

        result.success = true;
        if (!resolved_key_path.isEmpty()) {
            m_bulletin_board_key_path = resolved_key_path;
        }
        // Cache the relay list so executeBulletinBoardRpc() can replay init_bb
        // transparently after a bridge process respawn.
        m_bulletin_board_relays = relays;

        // Extract pubkey
        if (response.exists("pubkey") && response["pubkey"].isStr()) {
            result.pubkey = QString::fromStdString(response["pubkey"].get_str());
            m_bulletin_board_pubkey = result.pubkey;
        }

        // Extract relays array
        if (response.exists("relays") && response["relays"].isArray()) {
            const UniValue& relays_response = response["relays"].get_array();
            for (size_t i = 0; i < relays_response.size(); ++i) {
                result.relays.append(QString::fromStdString(relays_response[i].get_str()));
            }
        }

    } catch (const UniValue& e) {
        result.success = false;
        result.error = tr("Failed to initialize bulletin board: %1").arg(QString::fromStdString(e.write()));
    } catch (const std::exception& e) {
        result.success = false;
        result.error = tr("Failed to initialize bulletin board: %1").arg(QString::fromStdString(e.what()));
    } catch (...) {
        result.success = false;
        result.error = tr("Failed to initialize bulletin board: Unknown exception");
    }

    return result;
}

UniValue WalletModel::executeBulletinBoardRpc(const std::string& method, const UniValue& params)
{
    // Caller is expected to have checked m_client_model.
    try {
        return m_client_model->node().executeRpc(method, params, "");
    } catch (const UniValue& e) {
        const QString errorMsg = QString::fromStdString(e.write(0, 0));
        const bool needsInit =
            errorMsg.contains("init_bb first", Qt::CaseInsensitive) ||
            errorMsg.contains("not initialized", Qt::CaseInsensitive);
        if (!needsInit || m_bulletin_board_relays.isEmpty()) {
            throw;
        }
        // The bridge process was respawned (transport error, response timeout,
        // or external kill) and its in-memory bulletin-board manager was lost.
        // Transparently re-issue init_bb with the cached relays + key path and
        // retry the original call once. Same identity, same network.
        LogPrintf("WalletModel::executeBulletinBoardRpc: bridge needs init_bb for method %s, replaying with cached relays\n",
                  method.c_str());
        auto initResult = bulletinBoardInit(m_bulletin_board_relays);
        if (!initResult.success) {
            LogPrintf("WalletModel::executeBulletinBoardRpc: replay init_bb failed: %s\n",
                      initResult.error.toStdString().c_str());
            throw;
        }
        return m_client_model->node().executeRpc(method, params, "");
    }
}

WalletModel::BulletinBoardPostOfferResult WalletModel::bulletinBoardPostOffer(const QString& offer_type, const QString& asset_label, const QString& amount, const QString& price_btc, const QString& memo)
{
    BulletinBoardPostOfferResult result;

    if (!m_client_model) {
        result.error = tr("Client model not available");
        return result;
    }

    try {
        // RPC expects asset_send and asset_recv separately
        // Map based on offer type: sell GOLD for BTC vs buy GOLD with BTC
        std::string asset_send, asset_recv;
        if (offer_type.toLower() == "sell") {
            asset_send = asset_label.toStdString();  // Selling GOLD
            asset_recv = "BTC";                       // Wants BTC
        } else if (offer_type.toLower() == "buy") {
            asset_send = "BTC";                       // Offering BTC
            asset_recv = asset_label.toStdString();  // Wants GOLD
        } else {
            // For "swap" or other types, use asset_label for both
            asset_send = asset_label.toStdString();
            asset_recv = "BTC";
        }

        // Convert amount and price to numeric values
        bool amount_ok = false;
        double amount_val = amount.toDouble(&amount_ok);
        if (!amount_ok) {
            result.error = tr("Invalid amount: must be a valid number");
            return result;
        }

        bool price_ok = false;
        double price_val = price_btc.toDouble(&price_ok);
        if (!price_ok) {
            result.error = tr("Invalid price: must be a valid number");
            return result;
        }

        // Build params as object (not array)
        UniValue params(UniValue::VOBJ);
        params.pushKV("offer_type", offer_type.toLower().toStdString());
        params.pushKV("asset_send", asset_send);
        params.pushKV("asset_recv", asset_recv);
        params.pushKV("amount", amount_val);
        params.pushKV("price", price_val);
        if (!memo.isEmpty()) {
            params.pushKV("memo", memo.toStdString());
        }

        UniValue response = executeBulletinBoardRpc("cosign.post_offer", params);

        result.success = true;

        // Extract offer_id
        if (response.exists("offer_id") && response["offer_id"].isStr()) {
            result.offer_id = QString::fromStdString(response["offer_id"].get_str());
        }

    } catch (const UniValue& e) {
        result.success = false;
        result.error = tr("Failed to post offer: UniValue exception");
    } catch (const std::exception& e) {
        result.success = false;
        result.error = tr("Failed to post offer: %1").arg(QString::fromStdString(e.what()));
    } catch (...) {
        result.success = false;
        result.error = tr("Failed to post offer: Unknown exception");
    }

    return result;
}

WalletModel::BulletinBoardPostOfferResult WalletModel::bulletinBoardPostContractOffer(const QString& contract_type, const QString& contract_payload, const QString& maker_role, double apr, double ltv, int tenor_days, const QVariantList& proof_of_funds)
{
    BulletinBoardPostOfferResult result;

    if (!m_client_model) {
        result.error = tr("Client model not available");
        return result;
    }

    try {
        // Build params as array (positional for cosign.post_contract_offer)
        UniValue params(UniValue::VARR);
        params.push_back(contract_type.toStdString());       // params[0]: contract_type
        params.push_back(contract_payload.toStdString());    // params[1]: contract_payload
        params.push_back(maker_role.toStdString());          // params[2]: maker_role

        // Optional parameters
        if (apr > 0.0) {
            params.push_back(apr);                            // params[3]: apr
        } else {
            params.push_back(UniValue::VNULL);
        }

        if (ltv > 0.0) {
            params.push_back(ltv);                            // params[4]: ltv
        } else {
            params.push_back(UniValue::VNULL);
        }

        if (tenor_days > 0) {
            params.push_back(tenor_days);                     // params[5]: tenor_days
        } else {
            params.push_back(UniValue::VNULL);
        }

        // Optional proof_of_funds array (params[6])
        if (!proof_of_funds.isEmpty()) {
            UniValue proof_array(UniValue::VARR);
            for (const QVariant& proof_var : proof_of_funds) {
                QVariantMap proof_map = proof_var.toMap();
                UniValue proof_obj(UniValue::VOBJ);

                proof_obj.pushKV("utxo_ref", proof_map["utxo_ref"].toString().toStdString());
                proof_obj.pushKV("address", proof_map["address"].toString().toStdString());
                proof_obj.pushKV("message", proof_map["message"].toString().toStdString());
                proof_obj.pushKV("signature", proof_map["signature"].toString().toStdString());
                proof_obj.pushKV("asset_units", proof_map["asset_units"].toLongLong());

                if (proof_map.contains("asset_id") && !proof_map["asset_id"].toString().isEmpty()) {
                    proof_obj.pushKV("asset_id", proof_map["asset_id"].toString().toStdString());
                }

                proof_array.push_back(proof_obj);
            }
            params.push_back(proof_array);
        }

        UniValue response = executeBulletinBoardRpc("cosign.post_contract_offer", params);

        result.success = true;

        // Extract offer_id
        if (response.exists("offer_id") && response["offer_id"].isStr()) {
            result.offer_id = QString::fromStdString(response["offer_id"].get_str());
        }

    } catch (const UniValue& e) {
        result.success = false;
        // Extract actual error message from UniValue exception
        if (e.isObject() && e.exists("message")) {
            result.error = tr("Failed to post contract offer: %1").arg(QString::fromStdString(e["message"].get_str()));
        } else if (e.isStr()) {
            result.error = tr("Failed to post contract offer: %1").arg(QString::fromStdString(e.get_str()));
        } else {
            result.error = tr("Failed to post contract offer: UniValue exception: %1").arg(QString::fromStdString(e.write()));
        }
    } catch (const std::exception& e) {
        result.success = false;
        result.error = tr("Failed to post contract offer: %1").arg(QString::fromStdString(e.what()));
    } catch (...) {
        result.success = false;
        result.error = tr("Failed to post contract offer: Unknown exception");
    }

    return result;
}

WalletModel::BulletinBoardListOffersResult WalletModel::bulletinBoardListOffers(const QString& offer_type, const QString& asset_label, int since, bool force_refresh)
{
    BulletinBoardListOffersResult result;

    if (!m_client_model) {
        result.error = tr("Client model not available");
        return result;
    }

    try {
        UniValue params(UniValue::VARR);

        // Positional parameters for cosign.list_offers
        // params[0] = offer_type (string, optional)
        // params[1] = min_amount (number, optional)
        // params[2] = max_amount (number, optional)
        // params[3] = region (string, optional)
        // params[4] = payment_method (string, optional)
        // params[5] = min_reputation (number, optional)
        // params[6] = force_refresh (bool, optional)

        // We only use offer_type and force_refresh, skip the others (nulls)
        if (!offer_type.isEmpty()) {
            params.push_back(offer_type.toStdString());
        }

        // If we need force_refresh, we must pad nulls up to position 6
        if (force_refresh) {
            // Pad with nulls to reach position 6
            while (params.size() < 6) {
                params.push_back(UniValue());  // null
            }
            params.push_back(true);  // force_refresh at position 6
        }

        UniValue response = executeBulletinBoardRpc("cosign.list_offers", params);

        const bool filterByOfferType = !offer_type.isEmpty();
        const bool filterByAsset = !asset_label.isEmpty();
        const bool filterBySince = since > 0;

        result.success = true;

        // Extract offers array
        if (response.exists("offers") && response["offers"].isArray()) {
            const UniValue& offers_arr = response["offers"].get_array();
            for (size_t i = 0; i < offers_arr.size(); ++i) {
                const UniValue& offer = offers_arr[i];
                QVariantMap offer_map;

                // Map RPC field names to GUI-friendly names
                if (offer.exists("id") && offer["id"].isStr()) {
                    offer_map["offer_id"] = QString::fromStdString(offer["id"].get_str());
                }
                if (offer.exists("maker_pubkey") && offer["maker_pubkey"].isStr()) {
                    offer_map["maker_pubkey"] = QString::fromStdString(offer["maker_pubkey"].get_str());
                }
                if (offer.exists("offer_type") && offer["offer_type"].isStr()) {
                    offer_map["offer_type"] = QString::fromStdString(offer["offer_type"].get_str());
                }
                // Combine asset_send and asset_recv into displayable format
                QString asset_send, asset_recv;
                if (offer.exists("asset_send") && offer["asset_send"].isStr()) {
                    asset_send = QString::fromStdString(offer["asset_send"].get_str());
                }
                if (offer.exists("asset_recv") && offer["asset_recv"].isStr()) {
                    asset_recv = QString::fromStdString(offer["asset_recv"].get_str());
                }
                offer_map["asset_label"] = QString("%1 → %2").arg(asset_send).arg(asset_recv);
                offer_map["asset_send"] = asset_send;
                offer_map["asset_recv"] = asset_recv;

                if (offer.exists("amount") && offer["amount"].isNum()) {
                    offer_map["amount"] = QString::number(offer["amount"].get_real());
                }
                if (offer.exists("price") && offer["price"].isNum()) {
                    offer_map["price_btc"] = QString::number(offer["price"].get_real());
                }
                if (offer.exists("created_at") && offer["created_at"].isNum()) {
                    offer_map["created_at"] = static_cast<qlonglong>(offer["created_at"].getInt<int64_t>());
                }
                if (offer.exists("expires_at") && offer["expires_at"].isNum()) {
                    offer_map["expires_at"] = static_cast<qlonglong>(offer["expires_at"].getInt<int64_t>());
                }
                if (offer.exists("state") && offer["state"].isStr()) {
                    offer_map["state"] = QString::fromStdString(offer["state"].get_str());
                }
                if (offer.exists("memo") && offer["memo"].isStr()) {
                    offer_map["memo"] = QString::fromStdString(offer["memo"].get_str());
                }

                // Extract contract-specific fields
                if (offer.exists("contract_type") && offer["contract_type"].isStr()) {
                    offer_map["contract_type"] = QString::fromStdString(offer["contract_type"].get_str());
                }
                if (offer.exists("contract_payload") && offer["contract_payload"].isStr()) {
                    offer_map["contract_payload"] = QString::fromStdString(offer["contract_payload"].get_str());
                }
                if (offer.exists("maker_role") && offer["maker_role"].isStr()) {
                    offer_map["maker_role"] = QString::fromStdString(offer["maker_role"].get_str());
                }
                if (offer.exists("apr") && offer["apr"].isNum()) {
                    offer_map["apr"] = offer["apr"].get_real();
                }
                if (offer.exists("ltv") && offer["ltv"].isNum()) {
                    offer_map["ltv"] = offer["ltv"].get_real();
                }
                if (offer.exists("tenor_days") && offer["tenor_days"].isNum()) {
                    offer_map["tenor_days"] = offer["tenor_days"].getInt<int>();
                }

                // Parse proof_of_funds array
                if (offer.exists("proof_of_funds") && offer["proof_of_funds"].isArray()) {
                    const UniValue& proofs_arr = offer["proof_of_funds"].get_array();
                    QVariantList proofs_list;
                    for (size_t j = 0; j < proofs_arr.size(); ++j) {
                        const UniValue& proof = proofs_arr[j];
                        QVariantMap proof_map;
                        if (proof.exists("utxo_ref")) proof_map["utxo_ref"] = QString::fromStdString(proof["utxo_ref"].get_str());
                        if (proof.exists("address")) proof_map["address"] = QString::fromStdString(proof["address"].get_str());
                        if (proof.exists("message")) proof_map["message"] = QString::fromStdString(proof["message"].get_str());
                        if (proof.exists("signature")) proof_map["signature"] = QString::fromStdString(proof["signature"].get_str());
                        if (proof.exists("asset_units")) proof_map["asset_units"] = static_cast<qlonglong>(proof["asset_units"].getInt<int64_t>());
                        if (proof.exists("asset_id")) proof_map["asset_id"] = QString::fromStdString(proof["asset_id"].get_str());
                        proofs_list.append(proof_map);
                    }
                    offer_map["proof_of_funds"] = proofs_list;
                }

                // Apply client-side filters that the RPC does not support yet.
                if (filterByOfferType && offer_map["offer_type"].toString() != offer_type) {
                    continue;
                }
                if (filterByAsset && offer_map["asset_label"].toString() != asset_label) {
                    continue;
                }
                if (filterBySince && offer_map["created_at"].toLongLong() < since) {
                    continue;
                }

                result.offers.append(offer_map);
            }
        }

    } catch (const UniValue& e) {
        result.success = false;
        result.error = tr("Failed to list offers: UniValue exception: %1").arg(QString::fromStdString(e.write()));
    } catch (const std::exception& e) {
        result.success = false;
        result.error = tr("Failed to list offers: %1").arg(QString::fromStdString(e.what()));
    } catch (...) {
        result.success = false;
        result.error = tr("Failed to list offers: Unknown exception");
    }

    return result;
}

// ---------------------------------------------------------------------------
// Cross-chain settlement WalletModel methods
// ---------------------------------------------------------------------------

WalletModel::CrossChainPostResult WalletModel::crossChainPostOffer(const QString& payload_json, const QVariantList& proof_of_funds)
{
    CrossChainPostResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(payload_json.toStdString());

        if (!proof_of_funds.isEmpty()) {
            UniValue proof_array(UniValue::VARR);
            for (const QVariant& pv : proof_of_funds) {
                QVariantMap pm = pv.toMap();
                UniValue po(UniValue::VOBJ);
                po.pushKV("utxo_ref", pm["utxo_ref"].toString().toStdString());
                po.pushKV("address", pm["address"].toString().toStdString());
                po.pushKV("message", pm["message"].toString().toStdString());
                po.pushKV("signature", pm["signature"].toString().toStdString());
                po.pushKV("asset_units", pm["asset_units"].toLongLong());
                if (pm.contains("asset_id") && !pm["asset_id"].toString().isEmpty())
                    po.pushKV("asset_id", pm["asset_id"].toString().toStdString());
                proof_array.push_back(po);
            }
            params.push_back(proof_array);
        }

        UniValue response = executeBulletinBoardRpc("cosign.post_cross_chain_offer", params);
        result.success = true;
        if (response.exists("offer_id")) result.offer_id = QString::fromStdString(response["offer_id"].get_str());
        if (response.exists("schema")) result.schema = QString::fromStdString(response["schema"].get_str());
        if (response.exists("external_chain")) result.external_chain = QString::fromStdString(response["external_chain"].get_str());
        if (response.exists("adapter")) result.adapter = QString::fromStdString(response["adapter"].get_str());
        if (response.exists("funding_order")) result.funding_order = QString::fromStdString(response["funding_order"].get_str());
    } catch (const UniValue& e) {
        result.error = e.isObject() && e.exists("message")
            ? tr("Cross-chain post failed: %1").arg(QString::fromStdString(e["message"].get_str()))
            : tr("Cross-chain post failed: %1").arg(QString::fromStdString(e.write()));
    } catch (const std::exception& e) {
        result.error = tr("Cross-chain post failed: %1").arg(QString::fromStdString(e.what()));
    } catch (...) {
        result.error = tr("Cross-chain post failed: unknown error");
    }
    return result;
}

WalletModel::CrossChainValidateResult WalletModel::crossChainValidatePayload(const QString& payload_json)
{
    CrossChainValidateResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(payload_json.toStdString());

        UniValue response = m_client_model->node().executeRpc("cosign.validate_cross_chain_payload", params, "");
        result.valid = response.exists("valid") && response["valid"].get_bool();
        if (response.exists("schema")) result.schema = QString::fromStdString(response["schema"].get_str());
        if (response.exists("external_chain")) result.external_chain = QString::fromStdString(response["external_chain"].get_str());
        if (response.exists("error")) result.error = QString::fromStdString(response["error"].get_str());
    } catch (const UniValue& e) {
        result.error = e.isObject() && e.exists("message")
            ? QString::fromStdString(e["message"].get_str())
            : QString::fromStdString(e.write());
    } catch (const std::exception& e) {
        result.error = QString::fromStdString(e.what());
    }
    return result;
}

WalletModel::CrossChainListResult WalletModel::crossChainListOffers(const QString& external_chain, const QString& adapter, bool force_refresh)
{
    CrossChainListResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(external_chain.isEmpty() ? UniValue() : UniValue(external_chain.toStdString()));
        params.push_back(adapter.isEmpty() ? UniValue() : UniValue(adapter.toStdString()));
        if (force_refresh) params.push_back(true);

        UniValue response = executeBulletinBoardRpc("cosign.list_cross_chain_offers", params);
        result.success = response.exists("success") && response["success"].get_bool();

        if (response.exists("offers") && response["offers"].isArray()) {
            const UniValue& offers = response["offers"];
            for (size_t i = 0; i < offers.size(); ++i) {
                const UniValue& o = offers[i];
                CrossChainOfferItem item;
                if (o.exists("offer_id")) item.offer_id = QString::fromStdString(o["offer_id"].get_str());
                if (o.exists("maker_pubkey")) item.maker_pubkey = QString::fromStdString(o["maker_pubkey"].get_str());
                if (o.exists("network")) item.network = QString::fromStdString(o["network"].get_str());
                if (o.exists("cross_chain_payload")) {
                    // Preserve the full payload as a JSON string so Qt can
                    // render all fields: addresses, confirmation policy,
                    // timeout policy, fee policy, etc.
                    const UniValue& payload = o["cross_chain_payload"];
                    item.payload["_raw_json"] = QString::fromStdString(payload.write());

                    // Also extract top-level fields for quick access without re-parsing
                    if (payload.exists("schema")) item.payload["schema"] = QString::fromStdString(payload["schema"].get_str());
                    if (payload.exists("id")) item.payload["id"] = QString::fromStdString(payload["id"].get_str());
                    if (payload.exists("role")) item.payload["role"] = QString::fromStdString(payload["role"].get_str());
                    if (payload.exists("funding_order")) item.payload["funding_order"] = QString::fromStdString(payload["funding_order"].get_str());

                    // TSC leg
                    if (payload.exists("tsc_leg")) {
                        const UniValue& tl = payload["tsc_leg"];
                        if (tl.exists("asset_id")) item.payload["tsc_asset_id"] = QString::fromStdString(tl["asset_id"].get_str());
                        if (tl.exists("units")) item.payload["tsc_units"] = QString::fromStdString(tl["units"].get_str());
                    }

                    // External leg (all fields)
                    if (payload.exists("external_leg")) {
                        const UniValue& el = payload["external_leg"];
                        if (el.exists("chain")) item.payload["external_chain"] = QString::fromStdString(el["chain"].get_str());
                        if (el.exists("asset")) item.payload["external_asset"] = QString::fromStdString(el["asset"].get_str());
                        if (el.exists("units")) item.payload["external_units"] = QString::fromStdString(el["units"].get_str());
                        if (el.exists("settlement_address")) item.payload["settlement_address"] = QString::fromStdString(el["settlement_address"].get_str());
                        if (el.exists("refund_address")) item.payload["refund_address"] = QString::fromStdString(el["refund_address"].get_str());
                        if (el.exists("adapter")) item.payload["adapter"] = QString::fromStdString(el["adapter"].get_str());
                    }

                    // Confirmation policy
                    if (payload.exists("confirmation_policy")) {
                        const UniValue& cp = payload["confirmation_policy"];
                        if (cp.exists("external_min_conf")) item.payload["external_min_conf"] = cp["external_min_conf"].getInt<int>();
                        if (cp.exists("tsc_min_conf")) item.payload["tsc_min_conf"] = cp["tsc_min_conf"].getInt<int>();
                        if (cp.exists("reorg_conf")) item.payload["reorg_conf"] = cp["reorg_conf"].getInt<int>();
                    }

                    // Timeout policy
                    if (payload.exists("timeout_policy")) {
                        const UniValue& tp = payload["timeout_policy"];
                        if (tp.exists("external_lock_seconds")) item.payload["external_lock_seconds"] = static_cast<qint64>(tp["external_lock_seconds"].getInt<int64_t>());
                        if (tp.exists("tsc_lock_blocks")) item.payload["tsc_lock_blocks"] = tp["tsc_lock_blocks"].getInt<int>();
                        if (tp.exists("claim_budget_seconds")) item.payload["claim_budget_seconds"] = static_cast<qint64>(tp["claim_budget_seconds"].getInt<int64_t>());
                        if (tp.exists("reorg_margin_seconds")) item.payload["reorg_margin_seconds"] = static_cast<qint64>(tp["reorg_margin_seconds"].getInt<int64_t>());
                        if (tp.exists("min_timeout_gap_seconds")) item.payload["min_timeout_gap_seconds"] = static_cast<qint64>(tp["min_timeout_gap_seconds"].getInt<int64_t>());
                    }

                    // Fee policy
                    if (payload.exists("fee_policy")) {
                        const UniValue& fp = payload["fee_policy"];
                        if (fp.exists("claim_strategy")) item.payload["claim_strategy"] = QString::fromStdString(fp["claim_strategy"].get_str());
                        if (fp.exists("refund_strategy")) item.payload["refund_strategy"] = QString::fromStdString(fp["refund_strategy"].get_str());
                        if (fp.exists("fee_funding_mode")) item.payload["fee_funding_mode"] = QString::fromStdString(fp["fee_funding_mode"].get_str());
                    }
                }
                result.offers.append(item);
            }
        }
    } catch (const UniValue& e) {
        result.error = e.isObject() && e.exists("message")
            ? QString::fromStdString(e["message"].get_str())
            : QString::fromStdString(e.write());
    } catch (const std::exception& e) {
        result.error = QString::fromStdString(e.what());
    }
    return result;
}

WalletModel::SettlementProfileAddResult WalletModel::settlementProfileAdd(const QString& profile_id, const QString& label, const QString& chain, const QString& address, const QString& signer_ref, const QString& preferred_asset, const QString& fee_speed)
{
    SettlementProfileAddResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }
    try {
        UniValue params(UniValue::VARR);
        params.push_back(profile_id.toStdString());
        params.push_back(label.toStdString());
        params.push_back(chain.toStdString());
        params.push_back(address.toStdString());
        params.push_back(signer_ref.toStdString());
        params.push_back(preferred_asset.toStdString());
        params.push_back(fee_speed.toStdString());
        m_client_model->node().executeRpc("settlement_profile.add", params, getWalletName().toStdString());
        result.success = true;
    } catch (const UniValue& e) {
        result.error = e.isObject() && e.exists("message")
            ? QString::fromStdString(e["message"].get_str())
            : QString::fromStdString(e.write());
    } catch (const std::exception& e) {
        result.error = QString::fromStdString(e.what());
    } catch (...) {
        result.error = tr("Unknown error adding settlement profile");
    }
    return result;
}

bool WalletModel::settlementProfileRemove(const QString& profile_id)
{
    if (!m_client_model) return false;
    try {
        UniValue params(UniValue::VARR);
        params.push_back(profile_id.toStdString());
        m_client_model->node().executeRpc("settlement_profile.remove", params, getWalletName().toStdString());
        return true;
    } catch (...) {
        return false;
    }
}

QList<WalletModel::SettlementProfileItem> WalletModel::settlementProfileList()
{
    QList<SettlementProfileItem> out;
    if (!m_client_model) return out;
    try {
        UniValue params(UniValue::VARR);
        UniValue response = m_client_model->node().executeRpc("settlement_profile.list", params, getWalletName().toStdString());
        if (response.isArray()) {
            for (size_t i = 0; i < response.size(); ++i) {
                const UniValue& p = response[i];
                SettlementProfileItem item;
                if (p.exists("profile_id")) item.profile_id = QString::fromStdString(p["profile_id"].get_str());
                if (p.exists("label")) item.label = QString::fromStdString(p["label"].get_str());
                if (p.exists("chain")) item.chain = QString::fromStdString(p["chain"].get_str());
                if (p.exists("address")) item.address = QString::fromStdString(p["address"].get_str());
                if (p.exists("signer_ref")) item.signer_ref = QString::fromStdString(p["signer_ref"].get_str());
                if (p.exists("preferred_asset")) item.preferred_asset = QString::fromStdString(p["preferred_asset"].get_str());
                if (p.exists("fee_speed")) item.fee_speed = QString::fromStdString(p["fee_speed"].get_str());
                out.append(item);
            }
        }
    } catch (...) {
        // Return empty list on error
    }
    return out;
}

// ---------------------------------------------------------------------------
// Cross-chain execution record access
// ---------------------------------------------------------------------------

static WalletModel::CrossChainRecordItem parseCrossChainRecord(const UniValue& r)
{
    WalletModel::CrossChainRecordItem item;
    if (r.exists("swap_id")) item.swap_id = QString::fromStdString(r["swap_id"].get_str());
    if (r.exists("offer_id")) item.offer_id = QString::fromStdString(r["offer_id"].get_str());
    if (r.exists("state")) item.state = r["state"].getInt<int>();
    if (r.exists("local_role")) item.local_role = QString::fromStdString(r["local_role"].get_str());
    if (r.exists("counterparty_pubkey")) item.counterparty_pubkey = QString::fromStdString(r["counterparty_pubkey"].get_str());
    if (r.exists("external_chain")) item.external_chain = QString::fromStdString(r["external_chain"].get_str());
    if (r.exists("adapter")) item.adapter = QString::fromStdString(r["adapter"].get_str());
    if (r.exists("tsc_funding_txid")) item.tsc_funding_txid = QString::fromStdString(r["tsc_funding_txid"].get_str());
    if (r.exists("external_funding_txid")) item.external_funding_txid = QString::fromStdString(r["external_funding_txid"].get_str());
    if (r.exists("external_conf_depth")) item.external_conf_depth = r["external_conf_depth"].getInt<int>();
    if (r.exists("tsc_conf_depth")) item.tsc_conf_depth = r["tsc_conf_depth"].getInt<int>();
    if (r.exists("fee_escalation_level")) item.fee_escalation_level = r["fee_escalation_level"].getInt<int>();
    if (r.exists("created_time")) item.created_time = r["created_time"].getInt<int64_t>();
    if (r.exists("updated_time")) item.updated_time = r["updated_time"].getInt<int64_t>();
    if (r.exists("payload_json")) item.payload_json = QString::fromStdString(r["payload_json"].get_str());
    if (r.exists("oracle_attestation")) item.oracle_attestation = QString::fromStdString(r["oracle_attestation"].get_str());
    if (r.exists("adaptor_secret_ref")) item.adaptor_secret_ref = QString::fromStdString(r["adaptor_secret_ref"].get_str());
    // HTLC execution artifacts (V2)
    if (r.exists("htlc_contract_address")) item.htlc_contract_address = QString::fromStdString(r["htlc_contract_address"].get_str());
    if (r.exists("htlc_swap_id")) item.htlc_swap_id = QString::fromStdString(r["htlc_swap_id"].get_str());
    if (r.exists("external_signer_ref")) item.external_signer_ref = QString::fromStdString(r["external_signer_ref"].get_str());
    if (r.exists("claim_tx_hash")) item.claim_tx_hash = QString::fromStdString(r["claim_tx_hash"].get_str());
    if (r.exists("refund_tx_hash")) item.refund_tx_hash = QString::fromStdString(r["refund_tx_hash"].get_str());
    if (r.exists("external_lock_tx_hash")) item.external_lock_tx_hash = QString::fromStdString(r["external_lock_tx_hash"].get_str());
    if (r.exists("htlc_timelock")) item.htlc_timelock = r["htlc_timelock"].getInt<int64_t>();
    return item;
}

QList<WalletModel::CrossChainRecordItem> WalletModel::crossChainRecordList()
{
    QList<CrossChainRecordItem> out;
    if (!m_client_model) return out;
    try {
        UniValue params(UniValue::VARR);
        UniValue response = m_client_model->node().executeRpc("crosschain.list", params, getWalletName().toStdString());
        if (response.isArray()) {
            for (size_t i = 0; i < response.size(); ++i) {
                out.append(parseCrossChainRecord(response[i]));
            }
        }
    } catch (...) {
        // Return empty on error
    }
    return out;
}

std::optional<WalletModel::CrossChainRecordItem> WalletModel::crossChainRecordGet(const QString& swap_id)
{
    if (!m_client_model) return std::nullopt;
    try {
        UniValue params(UniValue::VARR);
        params.push_back(swap_id.toStdString());
        UniValue response = m_client_model->node().executeRpc("crosschain.get", params, getWalletName().toStdString());
        return parseCrossChainRecord(response);
    } catch (...) {
        return std::nullopt;
    }
}

// ---------------------------------------------------------------------------
// ETH lock — user-initiated
// ---------------------------------------------------------------------------

WalletModel::EthLockHtlcResult WalletModel::ethLockHtlc(
    const QString& htlc_address, const QString& swap_id,
    const QString& recipient, const QString& secret_hash,
    qint64 timelock, const QString& amount_wei,
    const QString& signing_key,
    const QString& token_address)
{
    EthLockHtlcResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }
    try {
        UniValue params(UniValue::VARR);
        params.push_back(htlc_address.toStdString());
        params.push_back(swap_id.toStdString());
        params.push_back(recipient.toStdString());
        params.push_back(secret_hash.toStdString());
        params.push_back(timelock);
        params.push_back(amount_wei.toStdString());
        params.push_back(signing_key.toStdString());
        params.push_back(token_address.isEmpty() ? UniValue() : UniValue(token_address.toStdString()));
        UniValue response = m_client_model->node().executeRpc("cosign.eth_lock_htlc", params, "");
        result.success = response.exists("success") && response["success"].get_bool();
        if (response.exists("tx_hash")) result.tx_hash = QString::fromStdString(response["tx_hash"].get_str());
        if (response.exists("from")) result.from = QString::fromStdString(response["from"].get_str());
    } catch (const UniValue& e) {
        result.error = e.isObject() && e.exists("message")
            ? QString::fromStdString(e["message"].get_str()) : QString::fromStdString(e.write());
    } catch (const std::exception& e) {
        result.error = QString::fromStdString(e.what());
    }
    return result;
}

// ---------------------------------------------------------------------------
// Cross-chain session automation WalletModel methods
// ---------------------------------------------------------------------------

WalletModel::CrossChainCreateRecordResult WalletModel::crossChainCreateRecord(
    const QString& swap_id, const QString& offer_id,
    const QString& chain, const QString& adapter,
    const QString& funding_order, const QString& role,
    const QString& payload_json)
{
    CrossChainCreateRecordResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }
    try {
        UniValue params(UniValue::VARR);
        params.push_back(swap_id.toStdString());
        params.push_back(offer_id.toStdString());
        params.push_back(chain.toStdString());
        params.push_back(adapter.toStdString());
        params.push_back(funding_order.toStdString());
        params.push_back(role.toStdString());
        params.push_back(payload_json.toStdString());
        UniValue response = m_client_model->node().executeRpc("crosschain.create_record", params, getWalletName().toStdString());
        result.success = true;
    } catch (const UniValue& e) {
        result.error = e.isObject() && e.exists("message")
            ? QString::fromStdString(e["message"].get_str()) : QString::fromStdString(e.write());
    } catch (const std::exception& e) {
        result.error = QString::fromStdString(e.what());
    }
    return result;
}

bool WalletModel::crossChainSetHtlcParams(
    const QString& swap_id, const QString& htlc_address,
    const QString& htlc_swap_id, const QString& signer_ref,
    const QString& claim_secret,
    const QString& expected_secret_hash,
    const QString& expected_recipient,
    const QString& expected_amount,
    const QString& expected_token_address)
{
    if (!m_client_model) return false;
    try {
        UniValue params(UniValue::VARR);
        params.push_back(swap_id.toStdString());
        params.push_back(htlc_address.toStdString());
        params.push_back(htlc_swap_id.toStdString());
        params.push_back(signer_ref.toStdString());
        params.push_back(claim_secret.isEmpty() ? UniValue() : UniValue(claim_secret.toStdString()));
        params.push_back(expected_secret_hash.isEmpty() ? UniValue() : UniValue(expected_secret_hash.toStdString()));
        params.push_back(expected_recipient.isEmpty() ? UniValue() : UniValue(expected_recipient.toStdString()));
        params.push_back(expected_amount.isEmpty() ? UniValue() : UniValue(expected_amount.toStdString()));
        params.push_back(expected_token_address.isEmpty() ? UniValue() : UniValue(expected_token_address.toStdString()));
        m_client_model->node().executeRpc("crosschain.set_htlc_params", params, getWalletName().toStdString());
        return true;
    } catch (...) {
        return false;
    }
}

bool WalletModel::crossChainRegisterSwap(const QString& swap_id)
{
    if (!m_client_model) return false;
    try {
        UniValue params(UniValue::VARR);
        params.push_back(swap_id.toStdString());
        m_client_model->node().executeRpc("crosschain.register_swap", params, getWalletName().toStdString());
        return true;
    } catch (...) {
        return false;
    }
}

bool WalletModel::crossChainUpdateSessionAddresses(
    const QString& swap_id,
    const QString& taker_tsc_address,
    const QString& taker_refund_address)
{
    if (!m_client_model) return false;
    try {
        UniValue params(UniValue::VARR);
        params.push_back(swap_id.toStdString());
        params.push_back(taker_tsc_address.toStdString());
        params.push_back(taker_refund_address.toStdString());
        m_client_model->node().executeRpc("crosschain.set_session_addresses", params, getWalletName().toStdString());
        return true;
    } catch (...) {
        return false;
    }
}

WalletModel::CrossChainStartManagerResult WalletModel::crossChainStartManager(
    const QString& eth_rpc_url,
    const QString& eth_rpc_url_secondary,
    const QString& oracle_pubkey,
    const QString& eth_derivation_seed)
{
    CrossChainStartManagerResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }
    try {
        UniValue params(UniValue::VARR);
        params.push_back(eth_rpc_url.toStdString());
        params.push_back(eth_rpc_url_secondary.isEmpty() ? UniValue() : UniValue(eth_rpc_url_secondary.toStdString()));
        params.push_back(oracle_pubkey.isEmpty() ? UniValue() : UniValue(oracle_pubkey.toStdString()));
        params.push_back(eth_derivation_seed.isEmpty() ? UniValue() : UniValue(eth_derivation_seed.toStdString()));
        UniValue response = m_client_model->node().executeRpc("crosschain.start_manager", params, getWalletName().toStdString());
        result.success = response.exists("success") && response["success"].get_bool();
        if (response.exists("active_swaps")) result.active_swaps = response["active_swaps"].getInt<int>();
        if (response.exists("mode")) result.mode = QString::fromStdString(response["mode"].get_str());
        if (response.exists("dual_provider")) result.dual_provider = response["dual_provider"].get_bool();
    } catch (const UniValue& e) {
        result.error = e.isObject() && e.exists("message")
            ? QString::fromStdString(e["message"].get_str()) : QString::fromStdString(e.write());
    } catch (const std::exception& e) {
        result.error = QString::fromStdString(e.what());
    }
    return result;
}

// ---------------------------------------------------------------------------
// ETH HTLC adapter WalletModel methods
// ---------------------------------------------------------------------------

WalletModel::EthInitResult WalletModel::ethInit(const QString& rpc_url)
{
    EthInitResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }
    try {
        UniValue params(UniValue::VARR);
        params.push_back(rpc_url.toStdString());
        UniValue response = m_client_model->node().executeRpc("cosign.eth_init", params, "");
        result.success = response.exists("success") && response["success"].get_bool();
        if (response.exists("rpc_url")) result.rpc_url = QString::fromStdString(response["rpc_url"].get_str());
    } catch (const UniValue& e) {
        result.error = e.isObject() && e.exists("message")
            ? QString::fromStdString(e["message"].get_str()) : QString::fromStdString(e.write());
    } catch (const std::exception& e) {
        result.error = QString::fromStdString(e.what());
    }
    return result;
}

// Lock/Claim/Refund are driven by CrossChainSwapManager through HtlcBackend.
// No Qt wrapper — signing keys never transit the GUI/RPC boundary.

WalletModel::EthSwapStatusResult WalletModel::ethGetSwapStatus(
    const QString& htlc_address, const QString& swap_id, const QString& lock_tx_hash)
{
    EthSwapStatusResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }
    try {
        UniValue params(UniValue::VARR);
        params.push_back(htlc_address.toStdString());
        params.push_back(swap_id.toStdString());
        if (!lock_tx_hash.isEmpty()) params.push_back(lock_tx_hash.toStdString());
        UniValue response = m_client_model->node().executeRpc("cosign.eth_get_swap_status", params, "");
        result.success = response.exists("success") && response["success"].get_bool();
        if (response.exists("state")) result.state = response["state"].getInt<int>();
        if (response.exists("state_name")) result.state_name = QString::fromStdString(response["state_name"].get_str());
        if (response.exists("sender")) result.sender = QString::fromStdString(response["sender"].get_str());
        if (response.exists("recipient")) result.recipient = QString::fromStdString(response["recipient"].get_str());
        if (response.exists("token_address")) result.token_address = QString::fromStdString(response["token_address"].get_str());
        if (response.exists("amount")) result.amount = QString::fromStdString(response["amount"].get_str());
        if (response.exists("secret_hash")) result.secret_hash = QString::fromStdString(response["secret_hash"].get_str());
        if (response.exists("timelock")) result.timelock = response["timelock"].getInt<qint64>();
        if (response.exists("confirmation_depth") && !response["confirmation_depth"].isNull())
            result.confirmation_depth = response["confirmation_depth"].getInt<qint64>();
    } catch (const UniValue& e) {
        result.error = e.isObject() && e.exists("message")
            ? QString::fromStdString(e["message"].get_str()) : QString::fromStdString(e.write());
    } catch (const std::exception& e) {
        result.error = QString::fromStdString(e.what());
    }
    return result;
}

WalletModel::EthVerifyAttestationResult WalletModel::ethVerifyAttestation(
    const QString& oracle_pubkey, const QVariantMap& attestation)
{
    EthVerifyAttestationResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }
    try {
        UniValue params(UniValue::VARR);
        params.push_back(oracle_pubkey.toStdString());

        UniValue att(UniValue::VOBJ);
        for (auto it = attestation.constBegin(); it != attestation.constEnd(); ++it) {
            const QVariant& v = it.value();
            if (v.typeId() == QMetaType::Int || v.typeId() == QMetaType::LongLong)
                att.pushKV(it.key().toStdString(), v.toLongLong());
            else
                att.pushKV(it.key().toStdString(), v.toString().toStdString());
        }
        params.push_back(att);

        UniValue response = m_client_model->node().executeRpc("cosign.eth_verify_attestation", params, "");
        result.valid = response.exists("valid") && response["valid"].get_bool();
        if (response.exists("swap_id")) result.swap_id = QString::fromStdString(response["swap_id"].get_str());
        if (response.exists("confirmation_depth")) result.confirmation_depth = response["confirmation_depth"].getInt<qint64>();
        if (response.exists("error")) result.error = QString::fromStdString(response["error"].get_str());
    } catch (const UniValue& e) {
        result.error = e.isObject() && e.exists("message")
            ? QString::fromStdString(e["message"].get_str()) : QString::fromStdString(e.write());
    } catch (const std::exception& e) {
        result.error = QString::fromStdString(e.what());
    }
    return result;
}

// ---------------------------------------------------------------------------
// Bulletin board request/accept
// ---------------------------------------------------------------------------

WalletModel::BulletinBoardRequestTradeResult WalletModel::bulletinBoardRequestTrade(const QString& offer_id, const QString& message, const QVariantList& proof_of_funds)
{
    BulletinBoardRequestTradeResult result;

    if (!m_client_model) {
        result.error = tr("Client model not available");
        return result;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(offer_id.toStdString());

        // Only add message if provided (taker pubkey is derived internally by RPC)
        if (!message.isEmpty()) {
            params.push_back(message.toStdString());
        } else {
            params.push_back(UniValue::VNULL);
        }

        // Optional proof_of_funds array (params[2])
        if (!proof_of_funds.isEmpty()) {
            UniValue proof_array(UniValue::VARR);
            for (const QVariant& proof_var : proof_of_funds) {
                QVariantMap proof_map = proof_var.toMap();
                UniValue proof_obj(UniValue::VOBJ);

                proof_obj.pushKV("utxo_ref", proof_map["utxo_ref"].toString().toStdString());
                proof_obj.pushKV("address", proof_map["address"].toString().toStdString());
                proof_obj.pushKV("message", proof_map["message"].toString().toStdString());
                proof_obj.pushKV("signature", proof_map["signature"].toString().toStdString());
                proof_obj.pushKV("asset_units", proof_map["asset_units"].toLongLong());

                if (proof_map.contains("asset_id") && !proof_map["asset_id"].toString().isEmpty()) {
                    proof_obj.pushKV("asset_id", proof_map["asset_id"].toString().toStdString());
                }

                proof_array.push_back(proof_obj);
            }
            params.push_back(proof_array);
        }

        UniValue response = executeBulletinBoardRpc("cosign.request_trade", params);

        result.success = true;

        // Extract request_id
        if (response.exists("request_id") && response["request_id"].isStr()) {
            result.request_id = QString::fromStdString(response["request_id"].get_str());
        }

    } catch (const UniValue& e) {
        result.success = false;
        result.error = tr("Failed to request trade: UniValue exception");
    } catch (const std::exception& e) {
        result.success = false;
        result.error = tr("Failed to request trade: %1").arg(QString::fromStdString(e.what()));
    } catch (...) {
        result.success = false;
        result.error = tr("Failed to request trade: Unknown exception");
    }

    return result;
}

WalletModel::BulletinBoardListRequestsResult WalletModel::bulletinBoardListRequests(const QString& filter)
{
    BulletinBoardListRequestsResult result;

    if (!m_client_model) {
        result.error = tr("Client model not available");
        return result;
    }

    try {
        UniValue params(UniValue::VARR);
        if (!filter.isEmpty() && filter != "all") {
            params.push_back(filter.toStdString());
        }

        UniValue response = executeBulletinBoardRpc("cosign.list_requests", params);

        result.success = true;

        // Extract requests array
        if (response.exists("requests") && response["requests"].isArray()) {
            const UniValue& requests_arr = response["requests"].get_array();
            for (size_t i = 0; i < requests_arr.size(); ++i) {
                const UniValue& request = requests_arr[i];
                QVariantMap request_map;

                // Flattened TradeRequest fields
                if (request.exists("id") && request["id"].isStr()) {
                    request_map["request_id"] = QString::fromStdString(request["id"].get_str());
                }
                if (request.exists("offer_id") && request["offer_id"].isStr()) {
                    request_map["offer_id"] = QString::fromStdString(request["offer_id"].get_str());
                }
                if (request.exists("taker_pubkey") && request["taker_pubkey"].isStr()) {
                    request_map["taker_pubkey"] = QString::fromStdString(request["taker_pubkey"].get_str());
                }
                if (request.exists("maker_pubkey") && request["maker_pubkey"].isStr()) {
                    request_map["maker_pubkey"] = QString::fromStdString(request["maker_pubkey"].get_str());
                }
                if (request.exists("counterparty_pubkey") && request["counterparty_pubkey"].isStr()) {
                    request_map["counterparty_pubkey"] = QString::fromStdString(request["counterparty_pubkey"].get_str());
                }
                if (request.exists("direction") && request["direction"].isStr()) {
                    request_map["direction"] = QString::fromStdString(request["direction"].get_str());
                }
                if (request.exists("status") && request["status"].isStr()) {
                    request_map["status"] = QString::fromStdString(request["status"].get_str());
                }
                if (request.exists("message") && request["message"].isStr()) {
                    request_map["message"] = QString::fromStdString(request["message"].get_str());
                }
                if (request.exists("timestamp") && request["timestamp"].isNum()) {
                    request_map["timestamp"] = static_cast<qlonglong>(request["timestamp"].getInt<int64_t>());
                }
                if (request.exists("updated_at") && request["updated_at"].isNum()) {
                    request_map["updated_at"] = static_cast<qlonglong>(request["updated_at"].getInt<int64_t>());
                }
                if (request.exists("invite_link") && request["invite_link"].isStr()) {
                    request_map["invite_link"] = QString::fromStdString(request["invite_link"].get_str());
                }
                if (request.exists("invite_expires_at") && request["invite_expires_at"].isNum()) {
                    request_map["invite_expires_at"] = static_cast<qlonglong>(request["invite_expires_at"].getInt<int64_t>());
                }

                // Parse proof_of_funds array
                if (request.exists("proof_of_funds") && request["proof_of_funds"].isArray()) {
                    const UniValue& proofs_arr = request["proof_of_funds"].get_array();
                    QVariantList proofs_list;
                    for (size_t j = 0; j < proofs_arr.size(); ++j) {
                        const UniValue& proof = proofs_arr[j];
                        QVariantMap proof_map;
                        if (proof.exists("utxo_ref")) proof_map["utxo_ref"] = QString::fromStdString(proof["utxo_ref"].get_str());
                        if (proof.exists("address")) proof_map["address"] = QString::fromStdString(proof["address"].get_str());
                        if (proof.exists("message")) proof_map["message"] = QString::fromStdString(proof["message"].get_str());
                        if (proof.exists("signature")) proof_map["signature"] = QString::fromStdString(proof["signature"].get_str());
                        if (proof.exists("asset_units")) proof_map["asset_units"] = static_cast<qlonglong>(proof["asset_units"].getInt<int64_t>());
                        if (proof.exists("asset_id")) proof_map["asset_id"] = QString::fromStdString(proof["asset_id"].get_str());
                        proofs_list.append(proof_map);
                    }
                    request_map["proof_of_funds"] = proofs_list;
                }

                // Offer summary (optional)
                if (request.exists("offer") && request["offer"].isObject()) {
                    QVariantMap offer_map;
                    const UniValue& offer_obj = request["offer"].get_obj();

                    if (offer_obj.exists("id") && offer_obj["id"].isStr()) {
                        offer_map["id"] = QString::fromStdString(offer_obj["id"].get_str());
                    }
                    if (offer_obj.exists("offer_type") && offer_obj["offer_type"].isStr()) {
                        offer_map["offer_type"] = QString::fromStdString(offer_obj["offer_type"].get_str());
                    }
                    if (offer_obj.exists("asset_send") && offer_obj["asset_send"].isStr()) {
                        offer_map["asset_send"] = QString::fromStdString(offer_obj["asset_send"].get_str());
                    }
                    if (offer_obj.exists("asset_recv") && offer_obj["asset_recv"].isStr()) {
                        offer_map["asset_recv"] = QString::fromStdString(offer_obj["asset_recv"].get_str());
                    }
                    if (offer_obj.exists("amount") && offer_obj["amount"].isNum()) {
                        offer_map["amount"] = offer_obj["amount"].get_real();
                    }
                    if (offer_obj.exists("price") && offer_obj["price"].isNum()) {
                        offer_map["price"] = offer_obj["price"].get_real();
                    }
                    if (offer_obj.exists("maker_pubkey") && offer_obj["maker_pubkey"].isStr()) {
                        offer_map["maker_pubkey"] = QString::fromStdString(offer_obj["maker_pubkey"].get_str());
                    }
                    if (offer_obj.exists("expires_at") && offer_obj["expires_at"].isNum()) {
                        offer_map["expires_at"] = static_cast<qlonglong>(offer_obj["expires_at"].getInt<int64_t>());
                    }
                    if (offer_obj.exists("state") && offer_obj["state"].isStr()) {
                        offer_map["state"] = QString::fromStdString(offer_obj["state"].get_str());
                    }
                    if (offer_obj.exists("requires_escrow") && offer_obj["requires_escrow"].isBool()) {
                        offer_map["requires_escrow"] = offer_obj["requires_escrow"].get_bool();
                    }
                    if (offer_obj.exists("payment_methods") && offer_obj["payment_methods"].isArray()) {
                        QStringList methods;
                        const UniValue& arr = offer_obj["payment_methods"].get_array();
                        for (size_t j = 0; j < arr.size(); ++j) {
                            if (arr[j].isStr()) {
                                methods.append(QString::fromStdString(arr[j].get_str()));
                            }
                        }
                        offer_map["payment_methods"] = methods;
                    }
                    if (offer_obj.exists("regions") && offer_obj["regions"].isArray()) {
                        QStringList regions;
                        const UniValue& arr = offer_obj["regions"].get_array();
                        for (size_t j = 0; j < arr.size(); ++j) {
                            if (arr[j].isStr()) {
                                regions.append(QString::fromStdString(arr[j].get_str()));
                            }
                        }
                        offer_map["regions"] = regions;
                    }

                    request_map["offer"] = offer_map;
                }

                result.requests.append(request_map);
            }
        }

    } catch (const UniValue& e) {
        result.success = false;
        result.error = tr("Failed to list requests: UniValue exception");
    } catch (const std::exception& e) {
        result.success = false;
        result.error = tr("Failed to list requests: %1").arg(QString::fromStdString(e.what()));
    } catch (...) {
        result.success = false;
        result.error = tr("Failed to list requests: Unknown exception");
    }

    return result;
}

WalletModel::BulletinBoardAcceptRequestResult WalletModel::bulletinBoardAcceptRequest(const QString& request_id, const QString& transport)
{
    BulletinBoardAcceptRequestResult result;

    if (!m_client_model) {
        result.error = tr("Client model not available");
        return result;
    }

    try {
        // Resolve transport: if "auto", use websocket (fast and reliable)
        QString resolvedTransport = transport;
        if (transport == "auto" || transport.isEmpty()) {
            resolvedTransport = "websocket";
            LogPrintf("WalletModel: Auto transport selected, using websocket (fast and reliable)\n");
        }

        // Normalize "ws" to "websocket" for bridge compatibility
        if (resolvedTransport == "ws") {
            resolvedTransport = "websocket";
        }

        UniValue params(UniValue::VARR);
        params.push_back(request_id.toStdString());
        params.push_back(resolvedTransport.toStdString());  // "websocket" or "tor"

        LogPrintf("WalletModel::bulletinBoardAcceptRequest: Calling cosign.accept_request with params: %s\n", params.write().c_str());
        UniValue response = executeBulletinBoardRpc("cosign.accept_request", params);
        LogPrintf("WalletModel::bulletinBoardAcceptRequest: Got response: %s\n", response.write().c_str());

        result.success = true;

        // Extract invite_link, session_id, transport, relay_url, sas, and sas_numeric
        if (response.exists("invite_link") && response["invite_link"].isStr()) {
            result.invite_link = QString::fromStdString(response["invite_link"].get_str());
        }
        if (response.exists("session_id") && response["session_id"].isStr()) {
            result.session_id = QString::fromStdString(response["session_id"].get_str());
        }
        if (response.exists("transport") && response["transport"].isStr()) {
            result.transport = QString::fromStdString(response["transport"].get_str());
        }
        if (response.exists("relay_url") && response["relay_url"].isStr()) {
            result.relay_url = QString::fromStdString(response["relay_url"].get_str());
        }
        // NOTE: SAS extraction removed - it's meaningless before handshake completes.
        // Both parties will get matching SAS after calling cosignHandshakeAuto.

    } catch (const UniValue& e) {
        result.success = false;
        QString errorMsg = QString::fromStdString(e.write(0, 0));
        result.error = tr("Failed to accept request: %1").arg(errorMsg);
        LogPrintf("WalletModel::bulletinBoardAcceptRequest: UniValue exception: %s\n", errorMsg.toStdString().c_str());
    } catch (const std::exception& e) {
        result.success = false;
        result.error = tr("Failed to accept request: %1").arg(QString::fromStdString(e.what()));
        LogPrintf("WalletModel::bulletinBoardAcceptRequest: std::exception: %s\n", e.what());
    } catch (...) {
        result.success = false;
        result.error = tr("Failed to accept request: Unknown exception");
        LogPrintf("WalletModel::bulletinBoardAcceptRequest: Unknown exception\n");
    }

    return result;
}

bool WalletModel::bulletinBoardRejectRequest(const QString& request_id)
{
    if (!m_client_model) {
        return false;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(request_id.toStdString());

        UniValue response = executeBulletinBoardRpc("cosign.reject_request", params);

        if (response.exists("success") && response["success"].isBool()) {
            return response["success"].get_bool();
        }
        if (response.exists("ok") && response["ok"].isBool()) {
            return response["ok"].get_bool();
        }
        return false;

    } catch (const UniValue& e) {
        return false;
    } catch (const std::exception& e) {
        return false;
    } catch (...) {
        return false;
    }
}

bool WalletModel::bulletinBoardDeleteOffer(const QString& offer_id)
{
    if (!m_client_model) {
        return false;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(offer_id.toStdString());

        UniValue response = executeBulletinBoardRpc("cosign.delete_offer", params);

        if (response.exists("success") && response["success"].isBool()) {
            return response["success"].get_bool();
        }
        if (response.exists("ok") && response["ok"].isBool()) {
            return response["ok"].get_bool();
        }
        return false;

    } catch (const UniValue& e) {
        return false;
    } catch (const std::exception& e) {
        return false;
    } catch (...) {
        return false;
    }
}

bool WalletModel::bulletinBoardCancelRequest(const QString& request_id)
{
    if (!m_client_model) {
        return false;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(request_id.toStdString());

        UniValue response = executeBulletinBoardRpc("cosign.cancel_request", params);

        if (response.exists("success") && response["success"].isBool()) {
            return response["success"].get_bool();
        }
        if (response.exists("ok") && response["ok"].isBool()) {
            return response["ok"].get_bool();
        }
        return false;

    } catch (const UniValue&) {
        return false;
    } catch (const std::exception&) {
        return false;
    } catch (...) {
        return false;
    }
}

// ============================================================================
// Governance RPCs
// ============================================================================

WalletModel::GovernanceListProposalsResult WalletModel::governanceListProposals(const QString& asset_id, bool include_expired)
{
    GovernanceListProposalsResult result;

    if (!m_client_model) {
        result.error = tr("Client model not available");
        return result;
    }

    try {
        UniValue params(UniValue::VARR);

        // cosign.list_governance parameters:
        // params[0] = asset_id (string, optional)
        // params[1] = include_expired (bool, optional)

        if (!asset_id.isEmpty()) {
            params.push_back(asset_id.toStdString());

            // If we want to set include_expired, we need asset_id first
            if (include_expired) {
                params.push_back(include_expired);
            }
        } else if (include_expired) {
            // If asset_id is empty but include_expired is true, pass null for asset_id
            params.push_back(UniValue());  // null
            params.push_back(include_expired);
        }

        UniValue response = executeBulletinBoardRpc("cosign.list_governance", params);

        // Response should be an array of proposal summary objects
        if (response.isArray()) {
            for (size_t i = 0; i < response.size(); ++i) {
                const UniValue& proposal = response[i];
                QVariantMap proposalMap;

                // Core proposal fields
                if (proposal.exists("proposal_id"))
                    proposalMap["proposal_id"] = QString::fromStdString(proposal["proposal_id"].get_str());
                if (proposal.exists("asset_id"))
                    proposalMap["asset_id"] = QString::fromStdString(proposal["asset_id"].get_str());
                if (proposal.exists("issuer_nostr_pubkey"))
                    proposalMap["issuer_nostr_pubkey"] = QString::fromStdString(proposal["issuer_nostr_pubkey"].get_str());
                if (proposal.exists("created_at"))
                    proposalMap["created_at"] = (qint64)proposal["created_at"].getInt<int64_t>();
                if (proposal.exists("expires_at"))
                    proposalMap["expires_at"] = (qint64)proposal["expires_at"].getInt<int64_t>();
                if (proposal.exists("flow_type"))
                    proposalMap["flow_type"] = QString::fromStdString(proposal["flow_type"].get_str());

                // Extract metadata (title, description, discussion_url)
                if (proposal.exists("metadata") && proposal["metadata"].isObject()) {
                    const UniValue& metadata = proposal["metadata"];
                    if (metadata.exists("title"))
                        proposalMap["title"] = QString::fromStdString(metadata["title"].get_str());
                    if (metadata.exists("description"))
                        proposalMap["description"] = QString::fromStdString(metadata["description"].get_str());
                    if (metadata.exists("discussion_url"))
                        proposalMap["discussion_url"] = QString::fromStdString(metadata["discussion_url"].get_str());
                }

                // Extract flow_type (PR3: needed to determine private vs public)
                if (proposal.exists("flow_type")) {
                    QString flow_type = QString::fromStdString(proposal["flow_type"].get_str());
                    proposalMap["flow_type"] = flow_type;
                    LogPrintf("WalletModel: Proposal %s has flow_type='%s'\n",
                              proposalMap["proposal_id"].toString().toStdString().substr(0, 16).c_str(),
                              flow_type.toStdString().c_str());
                } else {
                    LogPrintf("WalletModel: WARNING - Proposal %s MISSING flow_type field!\n",
                              proposalMap["proposal_id"].toString().toStdString().substr(0, 16).c_str());
                    proposalMap["flow_type"] = "public";  // Default to public
                }

                // Compute is_expired
                if (proposal.exists("expires_at")) {
                    qint64 expires = proposal["expires_at"].getInt<int64_t>();
                    qint64 now = QDateTime::currentSecsSinceEpoch();
                    proposalMap["is_expired"] = (now >= expires);
                }

                // Extract current_policy
                if (proposal.exists("current_policy") && proposal["current_policy"].isObject()) {
                    QVariantMap currentPolicy;
                    const UniValue& cp = proposal["current_policy"];

                    if (cp.exists("policy_quorum_bps")) {
                        currentPolicy["policy_quorum_bps"] = cp["policy_quorum_bps"].getInt<int>();
                    }
                    if (cp.exists("issuance_cap_units")) {
                        currentPolicy["issuance_cap_units"] = static_cast<qint64>(cp["issuance_cap_units"].getInt<int64_t>());
                    }
                    if (cp.exists("policy_epoch")) {
                        currentPolicy["policy_epoch"] = cp["policy_epoch"].getInt<int>();
                    }

                    proposalMap["current_policy"] = currentPolicy;
                }

                // Extract proposed_policy and compute policy_changes string
                if (proposal.exists("proposed_policy") && proposal["proposed_policy"].isObject()) {
                    QVariantMap policy;
                    QStringList changes;
                    const UniValue& pp = proposal["proposed_policy"];

                    if (pp.exists("policy_quorum_bps")) {
                        int quorum = pp["policy_quorum_bps"].getInt<int>();
                        policy["policy_quorum_bps"] = quorum;
                        changes << QString("Quorum: %1%").arg(quorum / 100.0, 0, 'f', 2);
                    }
                    if (pp.exists("issuance_cap_units")) {
                        qint64 cap = pp["issuance_cap_units"].getInt<int64_t>();
                        policy["issuance_cap_units"] = cap;
                        changes << QString("Cap: %1 units").arg(cap);
                    }

                    proposalMap["proposed_policy"] = policy;
                    proposalMap["policy_changes"] = changes.isEmpty() ? "(no changes)" : changes.join(", ");
                } else {
                    proposalMap["policy_changes"] = "(no changes)";
                }

                // Extract ICU attestation
                if (proposal.exists("icu_attestation") && proposal["icu_attestation"].isObject()) {
                    QVariantMap attestation;
                    const UniValue& att = proposal["icu_attestation"];
                    if (att.exists("address"))
                        attestation["address"] = QString::fromStdString(att["address"].get_str());
                    if (att.exists("message"))
                        attestation["message"] = QString::fromStdString(att["message"].get_str());
                    if (att.exists("signature"))
                        attestation["signature"] = QString::fromStdString(att["signature"].get_str());
                    proposalMap["icu_attestation"] = attestation;
                }

                // Extract ICU text and hashes
                if (proposal.exists("icu_text"))
                    proposalMap["icu_text"] = QString::fromStdString(proposal["icu_text"].get_str());
                if (proposal.exists("canonical_icu_hash"))
                    proposalMap["canonical_icu_hash"] = QString::fromStdString(proposal["canonical_icu_hash"].get_str());
                if (proposal.exists("witness_bundle"))
                    proposalMap["witness_bundle"] = QString::fromStdString(proposal["witness_bundle"].get_str());
                if (proposal.exists("witness_bundle_hash"))
                    proposalMap["witness_bundle_hash"] = QString::fromStdString(proposal["witness_bundle_hash"].get_str());

                // Extract template PSBT and hash
                if (proposal.exists("template_psbt"))
                    proposalMap["template_psbt"] = QString::fromStdString(proposal["template_psbt"].get_str());
                if (proposal.exists("template_psbt_hash"))
                    proposalMap["template_psbt_hash"] = QString::fromStdString(proposal["template_psbt_hash"].get_str());

                // Filter: Only show proposals for assets this wallet holds (holder mode)
                // listAssets() returns only assets with balance > 0 in this wallet
                QString prop_asset_id = proposalMap.value("asset_id").toString();
                bool asset_held = false;

                if (!prop_asset_id.isEmpty()) {
                    QList<AssetInfo> held_assets = listAssets();
                    for (const auto& held_asset : held_assets) {
                        if (held_asset.asset_id == prop_asset_id) {
                            asset_held = true;
                            break;
                        }
                    }
                }

                // Skip proposals for assets not held (unless empty asset_id)
                if (!prop_asset_id.isEmpty() && !asset_held) {
                    LogPrintf("WalletModel: Skipping proposal %s (asset %s not held)\n",
                              proposalMap.value("proposal_id").toString().toStdString().substr(0, 16).c_str(),
                              prop_asset_id.toStdString().substr(0, 8).c_str());
                    continue;
                }

                result.proposals.append(proposalMap);
            }
            result.success = true;
        } else {
            result.error = tr("Unexpected response format");
        }

    } catch (const UniValue& e) {
        result.error = QString::fromStdString(e.write());
    } catch (const std::exception& e) {
        result.error = QString::fromStdString(e.what());
    } catch (...) {
        result.error = tr("Unknown error");
    }

    return result;
}

bool WalletModel::governanceForceRefresh()
{
    if (!m_client_model) {
        return false;
    }

    try {
        UniValue params(UniValue::VARR);
        UniValue response = executeBulletinBoardRpc("cosign.force_refresh_governance", params);

        // Response should be {"success": true}
        if (response.exists("success") && response["success"].isBool()) {
            return response["success"].get_bool();
        }

        return false;

    } catch (const UniValue&) {
        return false;
    } catch (const std::exception&) {
        return false;
    } catch (...) {
        return false;
    }
}

bool WalletModel::verifyMessage(const QString& address, const QString& signature, const QString& message)
{
    if (!m_client_model) {
        return false;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(address.toStdString());
        params.push_back(signature.toStdString());
        params.push_back(message.toStdString());

        UniValue response = m_client_model->node().executeRpc("verifymessage", params, "");

        // verifymessage returns a boolean
        if (response.isBool()) {
            return response.get_bool();
        }

        return false;

    } catch (const UniValue&) {
        return false;
    } catch (const std::exception&) {
        return false;
    } catch (...) {
        return false;
    }
}

bool WalletModel::verifyMessageBip322(const QString& address, const QString& signature, const QString& message)
{
    if (!m_client_model) {
        return false;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(address.toStdString());
        params.push_back(signature.toStdString());
        params.push_back(message.toStdString());

        UniValue response = m_client_model->node().executeRpc("verifymessagebip322", params, "");

        // verifymessagebip322 returns a boolean
        if (response.isBool()) {
            return response.get_bool();
        }

        return false;

    } catch (const UniValue&) {
        return false;
    } catch (const std::exception&) {
        return false;
    } catch (...) {
        return false;
    }
}

QString WalletModel::signMessageBip322(const QString& address, const QString& message)
{
    if (!m_client_model) {
        return QString();
    }

    // Ensure wallet is unlocked before attempting to sign
    WalletModel::UnlockContext ctx(requestUnlock());
    if (!ctx.isValid()) {
        return QString();
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(address.toStdString());
        params.push_back(message.toStdString());

        UniValue response = m_client_model->node().executeRpc("signmessagebip322", params, getWalletName().toStdString());

        // signmessagebip322 returns a string (signature)
        if (response.isStr()) {
            return QString::fromStdString(response.get_str());
        }

        return QString();

    } catch (const UniValue&) {
        return QString();
    } catch (const std::exception&) {
        return QString();
    } catch (...) {
        return QString();
    }
}

WalletModel::OwnershipProofVerifyResult WalletModel::verifyOwnershipProof(
    const QString& utxo_ref,
    const QString& address,
    const QString& message,
    const QString& signature,
    const QString& asset_id,
    uint64_t claimed_units)
{
    OwnershipProofVerifyResult result;

    if (!m_client_model) {
        result.error = tr("Client model not available");
        return result;
    }

    // Parse utxo_ref (format: "txid:vout")
    QStringList parts = utxo_ref.split(':');
    if (parts.size() != 2) {
        result.error = tr("Invalid utxo_ref format (expected 'txid:vout')");
        return result;
    }

    QString txid = parts[0];
    bool ok;
    int vout = parts[1].toInt(&ok);
    if (!ok) {
        result.error = tr("Invalid vout in utxo_ref");
        return result;
    }

    try {
        // Call gettxout RPC (blockchain-scoped, not wallet-scoped)
        UniValue params(UniValue::VARR);
        params.push_back(txid.toStdString());
        params.push_back(vout);
        params.push_back(false); // include_mempool = false (only confirmed UTXOs)

        LogPrintf("WalletModel::verifyOwnershipProof() Calling gettxout for %s:%d\n",
            txid.toStdString().c_str(), vout);
        UniValue utxo_result = m_client_model->node().executeRpc("gettxout", params, "");

        // gettxout returns null if UTXO doesn't exist or was spent
        if (utxo_result.isNull()) {
            result.error = tr("UTXO does not exist or has been spent");
            LogPrintf("WalletModel::verifyOwnershipProof() gettxout returned NULL\n");
            return result;
        }
        LogPrintf("WalletModel::verifyOwnershipProof() gettxout SUCCESS\n");

        // Require at least 1 confirmation
        int confirmations = 0;
        if (utxo_result.exists("confirmations") && utxo_result["confirmations"].isNum()) {
            confirmations = utxo_result["confirmations"].getInt<int>();
        }
        if (confirmations < 1) {
            result.error = tr("UTXO has %1 confirmations, require at least 1").arg(confirmations);
            return result;
        }

        // Check if this is native coin (TSC) or registered asset
        bool isNative = (asset_id.isEmpty() || asset_id == "TSC");

        uint64_t actual_units = 0;
        QString actual_asset_id;

        if (isNative) {
            // Native coin: check 'value' field (in BTC)
            if (!utxo_result.exists("value") || !utxo_result["value"].isNum()) {
                result.error = tr("UTXO does not contain value field for native coin");
                return result;
            }
            double value_btc = utxo_result["value"].get_real();
            actual_units = static_cast<uint64_t>(value_btc * 100000000); // Convert BTC to satoshis
            actual_asset_id = ""; // Native
        } else {
            // Registered asset: check asset_id and asset_units in vExt
            if (!utxo_result.exists("asset_id") || !utxo_result.exists("asset_units")) {
                result.error = tr("UTXO does not contain asset_id/asset_units for registered asset");
                return result;
            }
            actual_asset_id = QString::fromStdString(utxo_result["asset_id"].get_str());
            actual_units = utxo_result["asset_units"].getInt<uint64_t>();

            // Verify asset_id matches
            if (actual_asset_id != asset_id) {
                result.error = tr("UTXO contains different asset: %1").arg(actual_asset_id);
                return result;
            }
        }

        // Extract address from scriptPubKey
        if (utxo_result.exists("scriptPubKey") && utxo_result["scriptPubKey"].isObject()) {
            const UniValue& spk = utxo_result["scriptPubKey"];
            if (spk.exists("address") && spk["address"].isStr()) {
                result.actual_address = QString::fromStdString(spk["address"].get_str());
            }
        }

        // Verify UTXO is at claimed address
        if (!result.actual_address.isEmpty() && result.actual_address != address) {
            result.error = tr("UTXO is at address %1, not claimed address %2")
                .arg(result.actual_address).arg(address);
            return result;
        }

        // Verify UTXO contains at least the claimed asset units
        if (actual_units < claimed_units) {
            result.error = tr("UTXO contains only %1 units, but %2 units were claimed")
                .arg(actual_units).arg(claimed_units);
            return result;
        }

        // Extract bestblock for chain binding
        QString bestblock;
        if (utxo_result.exists("bestblock") && utxo_result["bestblock"].isStr()) {
            bestblock = QString::fromStdString(utxo_result["bestblock"].get_str());
        }

        // Verify bestblock exists in current chain (prevents stale proofs from old regtest runs)
        if (!bestblock.isEmpty()) {
            try {
                UniValue hash_params(UniValue::VARR);
                hash_params.push_back(bestblock.toStdString());
                UniValue block_header = m_client_model->node().executeRpc("getblockheader", hash_params, "");
                if (block_header.isNull()) {
                    result.error = tr("UTXO's bestblock %1 not found in current chain").arg(bestblock.left(16));
                    LogPrintf("WalletModel::verifyOwnershipProof() bestblock not in chain\n");
                    return result;
                }
                LogPrintf("WalletModel::verifyOwnershipProof() bestblock verified in chain\n");
            } catch (const std::exception& e) {
                result.error = tr("UTXO's bestblock %1 not found in current chain: %2")
                    .arg(bestblock.left(16))
                    .arg(QString::fromStdString(e.what()));
                LogPrintf("WalletModel::verifyOwnershipProof() bestblock verification failed: %s\n", e.what());
                return result;
            }
        }

        // Verify BIP-322 signature (address, signature, message)
        UniValue verify_params(UniValue::VARR);
        verify_params.push_back(address.toStdString());
        verify_params.push_back(signature.toStdString());
        verify_params.push_back(message.toStdString());

        UniValue verify_result = m_client_model->node().executeRpc("verifymessagebip322", verify_params, "");

        if (!verify_result.isBool() || !verify_result.get_bool()) {
            result.error = tr("BIP-322 signature verification failed");
            return result;
        }

        result.verified = true;
        result.actual_units = actual_units;
        result.bestblock = bestblock;
        return result;

    } catch (const UniValue& e) {
        result.error = tr("Failed to query UTXO: UniValue exception");
        return result;
    } catch (const std::exception& e) {
        result.error = tr("Failed to query UTXO: %1").arg(QString::fromStdString(e.what()));
        return result;
    } catch (...) {
        result.error = tr("Failed to query UTXO: Unknown exception");
        return result;
    }
}

// Cache key for an individual proof: utxo_ref + address + sha256(signature) +
// asset_id + claimed_units. We hash the signature (which can be long) to keep
// the key bounded; the other fields are short enough to inline. Two distinct
// proofs for the same UTXO with different signatures or different claimed
// units produce different keys, so the cache cannot collapse genuinely
// different claims.
static QString ProofCacheKey(const QString& utxo_ref,
                             const QString& address,
                             const QString& signature,
                             const QString& asset_id,
                             uint64_t claimed_units)
{
    const QByteArray sig_hash = QCryptographicHash::hash(
        signature.toUtf8(), QCryptographicHash::Sha256).toHex();
    return utxo_ref + QLatin1Char('|')
         + address + QLatin1Char('|')
         + QString::fromUtf8(sig_hash) + QLatin1Char('|')
         + asset_id + QLatin1Char('|')
         + QString::number(claimed_units);
}

WalletModel::AggregateProofVerifyResult WalletModel::verifyProofList(const QVariantList& proofs)
{
    AggregateProofVerifyResult result;

    try {
        if (proofs.isEmpty()) {
            result.all_verified = true; // Empty list is trivially verified
            return result;
        }

        // Current bestblock at the start of this verification pass. Cached
        // entries from a prior tip are stale (their UTXO could have been
        // spent in a block we now have) so we ignore them on tip change.
        // Computed once for the whole pass; if the tip changes mid-iteration,
        // worst case we accept stale entries for this pass and recompute on
        // the next call. uint256{} → "00...00" if m_client_model is null;
        // we treat empty/zero as "do not trust the cache".
        const uint256 tip = getLastBlockProcessed();
        const QString currentBestBlock = tip.IsNull()
            ? QString()
            : QString::fromStdString(tip.GetHex());

        QSet<QString> seen_utxos; // Deduplicate UTXOs
        QString unified_asset_id;
        bool first = true;

        for (const QVariant& proofVar : proofs) {
            QVariantMap proof = proofVar.toMap();
            QString utxo_ref = proof["utxo_ref"].toString();
            QString address = proof["address"].toString();
            QString message = proof["message"].toString();
            QString signature = proof["signature"].toString();
            QString asset_id = proof["asset_id"].toString();
            uint64_t claimed_units = proof["asset_units"].toLongLong();

            // Deduplicate: skip if we've already counted this UTXO
            if (seen_utxos.contains(utxo_ref)) {
                result.failed_count++;
                result.error = tr("Duplicate UTXO %1 in proof list").arg(utxo_ref);
                result.all_verified = false;
                return result;
            }
            seen_utxos.insert(utxo_ref);

            // Verify asset consistency
            if (first) {
                unified_asset_id = asset_id;
                first = false;
            } else {
                if (asset_id != unified_asset_id) {
                    result.failed_count++;
                    result.error = tr("Mixed assets in proof list: %1 vs %2").arg(unified_asset_id).arg(asset_id);
                    result.all_verified = false;
                    return result;
                }
            }

            // Cache lookup. Hot path on every poll tick after the first; lets
            // updateTradeRequestsList() avoid re-issuing gettxout for every
            // proof of every active request every 5 seconds. Cache value
            // carries the bestblock it was computed against; mismatch =
            // treat as cold and recompute.
            const QString cache_key = ProofCacheKey(utxo_ref, address,
                                                    signature, asset_id, claimed_units);
            bool cache_hit = false;
            OwnershipProofVerifyResult verifyResult;
            if (!currentBestBlock.isEmpty()) {
                std::lock_guard<std::mutex> lock(m_proof_cache_mutex);
                if (CachedProofEntry* entry = m_proof_cache.object(cache_key)) {
                    if (entry->bestblock == currentBestBlock) {
                        verifyResult.verified = entry->verified;
                        verifyResult.actual_units = entry->actual_units;
                        verifyResult.error = entry->error;
                        verifyResult.actual_address = entry->actual_address;
                        verifyResult.bestblock = entry->bestblock;
                        cache_hit = true;
                    }
                }
            }

            if (!cache_hit) {
                // Cold path: full verification. Only log on miss so the
                // debug.log doesn't drown in "Verifying / SUCCESS" lines
                // every poll tick on hot caches.
                LogPrintf("WalletModel::verifyProofList() Verifying UTXO %s for asset %s, claimed %lu units\n",
                    utxo_ref.toStdString().c_str(), asset_id.toStdString().c_str(), claimed_units);
                verifyResult = verifyOwnershipProof(utxo_ref, address, message, signature, asset_id, claimed_units);

                // Cache both success and failure. A spent UTXO ("FAILED")
                // stays spent within a block; on the next block we recompute.
                if (!currentBestBlock.isEmpty()) {
                    auto* entry = new CachedProofEntry{
                        verifyResult.verified,
                        verifyResult.actual_units,
                        verifyResult.error,
                        verifyResult.actual_address,
                        currentBestBlock,
                    };
                    std::lock_guard<std::mutex> lock(m_proof_cache_mutex);
                    m_proof_cache.insert(cache_key, entry, /*cost=*/1);
                }
            }

            if (!verifyResult.verified) {
                result.failed_count++;
                result.error = tr("Proof for %1 failed: %2").arg(utxo_ref).arg(verifyResult.error);
                result.all_verified = false;
                if (!cache_hit) {
                    LogPrintf("WalletModel::verifyProofList() FAILED: %s\n", result.error.toStdString().c_str());
                }
                return result;
            }

            // Use actual_units from blockchain, not claimed_units from JSON
            if (!cache_hit) {
                LogPrintf("WalletModel::verifyProofList() SUCCESS: actual_units=%lu\n", verifyResult.actual_units);
            }
            result.total_verified_units += verifyResult.actual_units;
            result.verified_count++;
        }

        result.all_verified = true;
        result.asset_id = unified_asset_id;
        return result;

    } catch (const UniValue& e) {
        LogPrintf("WalletModel::verifyProofList() Caught UniValue exception\n");
        result.all_verified = false;
        result.error = tr("Verification error: UniValue exception");
        return result;
    } catch (const std::exception& e) {
        LogPrintf("WalletModel::verifyProofList() Caught exception: %s\n", e.what());
        result.all_verified = false;
        result.error = tr("Verification error: %1").arg(QString::fromStdString(e.what()));
        return result;
    } catch (...) {
        LogPrintf("WalletModel::verifyProofList() Caught unknown exception\n");
        result.all_verified = false;
        result.error = tr("Unknown verification error");
        return result;
    }
}

WalletModel::CreateProofOfFundsResult WalletModel::createProofOfFunds(const QString& asset_id, uint64_t required_units, const QString& context)
{
    CreateProofOfFundsResult result;

    if (!m_client_model) {
        result.error = "Client model not available";
        return result;
    }

    if (required_units == 0) {
        result.error = "Required units cannot be zero";
        LogPrintf("WalletModel::createProofOfFunds() REJECTED: required_units is 0\n");
        return result;
    }

    LogPrintf("WalletModel::createProofOfFunds() START: asset_id='%s', required_units=%llu, context='%s'\n",
              asset_id.toStdString().c_str(), required_units, context.toStdString().c_str());

    // Ensure wallet is unlocked before generating BIP-322 proofs
    WalletModel::UnlockContext ctx(requestUnlock());
    if (!ctx.isValid()) {
        result.error = tr("Wallet is locked. Please unlock the wallet to generate proofs of funds.");
        return result;
    }

    try {
        // Get wallet name for RPC calls
        std::string walletName = getWalletName().toStdString();
        LogPrintf("WalletModel::createProofOfFunds() Using wallet: '%s'\n", walletName.c_str());

        // List unspent outputs for the asset
        // Use listunspent for native assets, listassetutxos for registered assets
        UniValue unspent;

        if (asset_id.isEmpty()) {
            // Native coin - use listunspent
            LogPrintf("WalletModel::createProofOfFunds() Using listunspent for native asset\n");
            UniValue params(UniValue::VARR);
            // minconf and include_unsafe must match the verifier's eligibility
            // rules, otherwise the builder can select a UTXO that the verifier
            // immediately rejects. Verifier (verifyOwnershipProof) calls
            // gettxout(..., /*include_mempool=*/false) and requires
            // confirmations >= 1; so the builder must also require at least 1
            // confirmation and must not consider unsafe candidates. createDiscussionProof
            // already aligned with the verifier in this way (see "must be >=1,
            // strict verifier rejects unconfirmed" comment at line 3704); this
            // brings createProofOfFunds in line.
            params.push_back(1);  // minconf — match strict verifier (gettxout include_mempool=false)
            params.push_back(9999999);  // maxconf
            params.push_back(UniValue(UniValue::VARR));  // empty addresses array = all
            params.push_back(false);  // include_unsafe — match strict verifier

            try {
                unspent = m_client_model->node().executeRpc("listunspent", params, walletName);
                LogPrintf("WalletModel::createProofOfFunds() listunspent RPC succeeded, returned %d results\n", unspent.size());
            } catch (const UniValue& e) {
                LogPrintf("WalletModel::createProofOfFunds() listunspent RPC threw UniValue exception\n");
                result.error = "RPC error: UniValue exception";
                return result;
            } catch (const std::runtime_error& e) {
                LogPrintf("WalletModel::createProofOfFunds() listunspent RPC threw runtime_error: %s\n", e.what());
                result.error = QString("RPC error: %1").arg(e.what());
                return result;
            } catch (const std::exception& e) {
                LogPrintf("WalletModel::createProofOfFunds() listunspent RPC threw std::exception: %s\n", e.what());
                result.error = QString("RPC error: %1").arg(e.what());
                return result;
            } catch (...) {
                LogPrintf("WalletModel::createProofOfFunds() listunspent RPC threw unknown exception (non-std)\n");
                result.error = "Unknown RPC error (non-standard exception)";
                return result;
            }
        } else {
            // Registered asset - use listassetutxos
            LogPrintf("WalletModel::createProofOfFunds() Using listassetutxos for registered asset: %s\n", asset_id.toStdString().c_str());
            UniValue params(UniValue::VARR);
            UniValue assets_array(UniValue::VARR);
            assets_array.push_back(asset_id.toStdString());
            params.push_back(assets_array);

            try {
                unspent = m_client_model->node().executeRpc("listassetutxos", params, walletName);
                LogPrintf("WalletModel::createProofOfFunds() listassetutxos RPC succeeded, returned %d results\n", unspent.size());
            } catch (const UniValue& e) {
                LogPrintf("WalletModel::createProofOfFunds() listassetutxos RPC threw UniValue exception\n");
                result.error = "RPC error: UniValue exception";
                return result;
            } catch (const std::runtime_error& e) {
                LogPrintf("WalletModel::createProofOfFunds() listassetutxos RPC threw runtime_error: %s\n", e.what());
                result.error = QString("RPC error: %1").arg(e.what());
                return result;
            } catch (const std::exception& e) {
                LogPrintf("WalletModel::createProofOfFunds() listassetutxos RPC threw std::exception: %s\n", e.what());
                result.error = QString("RPC error: %1").arg(e.what());
                return result;
            } catch (...) {
                LogPrintf("WalletModel::createProofOfFunds() listassetutxos RPC threw unknown exception (non-std)\n");
                result.error = "Unknown RPC error (non-standard exception)";
                return result;
            }
        }

        LogPrintf("WalletModel::createProofOfFunds() Processing %d UTXO results\n", unspent.size());

        if (!unspent.isArray() || unspent.size() == 0) {
            result.error = "No UTXOs available for " + (asset_id.isEmpty() ? QString("native asset") : asset_id);
            return result;
        }

        // Sort UTXOs by amount (ascending) to pick smallest first
        //
        // The asset path uses listassetutxos, which (unlike listunspent above)
        // does not honour minconf / include_unsafe at the RPC layer — its
        // internal candidate set can include unconfirmed and unsafe outputs.
        // The verifier (verifyOwnershipProof) requires confirmations >= 1 and
        // queries with include_mempool=false, so we must mirror those rules
        // here. Filter every candidate (native AND asset) for spendable=true,
        // safe=true, confirmations>=1 before passing into the proof builder.
        auto utxo_eligible = [](const UniValue& utxo) -> bool {
            if (utxo.exists("spendable") && !utxo["spendable"].get_bool()) return false;
            if (utxo.exists("safe") && !utxo["safe"].get_bool()) return false;
            if (utxo.exists("confirmations") && utxo["confirmations"].isNum()
                && utxo["confirmations"].getInt<int>() < 1) return false;
            return true;
        };

        std::vector<UniValue> utxos;
        for (size_t i = 0; i < unspent.size(); ++i) {
            const UniValue& utxo = unspent[i];
            if (!utxo_eligible(utxo)) continue;

            if (asset_id.isEmpty()) {
                // Native asset: spendable check now folded into utxo_eligible.
                utxos.push_back(utxo);
            } else {
                // Registered asset: filter by asset_id and skip non-asset UTXOs.
                if (!utxo.exists("asset_id") || !utxo.exists("asset_units")) {
                    continue;  // Skip BTC-only UTXOs
                }
                std::string utxo_asset_id = utxo["asset_id"].get_str();
                if (utxo_asset_id == asset_id.toStdString()) {
                    utxos.push_back(utxo);
                }
            }
        }

        std::sort(utxos.begin(), utxos.end(), [&asset_id](const UniValue& a, const UniValue& b) {
            uint64_t amt_a = 0, amt_b = 0;
            if (asset_id.isEmpty()) {
                // Native asset uses "amount" field (BTC)
                if (a.exists("amount")) {
                    amt_a = static_cast<uint64_t>(a["amount"].get_real() * 1e8);
                }
                if (b.exists("amount")) {
                    amt_b = static_cast<uint64_t>(b["amount"].get_real() * 1e8);
                }
            } else {
                // Registered asset uses "asset_units" field
                if (a.exists("asset_units")) {
                    amt_a = a["asset_units"].getInt<int64_t>();
                }
                if (b.exists("asset_units")) {
                    amt_b = b["asset_units"].getInt<int64_t>();
                }
            }
            return amt_a < amt_b;
        });

        // Select UTXOs until we meet the requirement
        uint64_t accumulated = 0;
        QVariantList proofs;

        for (const UniValue& utxo : utxos) {
            if (accumulated >= required_units) {
                break;  // We have enough
            }

            QString txid = QString::fromStdString(utxo["txid"].get_str());
            int vout = utxo["vout"].getInt<int>();
            QString address = QString::fromStdString(utxo["address"].get_str());
            uint64_t amount_units = 0;

            if (asset_id.isEmpty()) {
                // Native asset uses "amount" field (BTC)
                if (utxo.exists("amount")) {
                    amount_units = static_cast<uint64_t>(utxo["amount"].get_real() * 1e8);
                }
            } else {
                // Registered asset uses "asset_units" field
                if (utxo.exists("asset_units")) {
                    amount_units = utxo["asset_units"].getInt<int64_t>();
                }
            }

            // Sign with BIP322
            QString message = QString("Proof of funds: %1").arg(context);
            UniValue signParams(UniValue::VARR);
            signParams.push_back(address.toStdString());
            signParams.push_back(message.toStdString());

            QString signature;
            try {
                UniValue sigResult = m_client_model->node().executeRpc("signmessagebip322", signParams, walletName);
                signature = QString::fromStdString(sigResult.get_str());
            } catch (const UniValue& e) {
                LogPrintf("WalletModel::createProofOfFunds() Failed to sign for %s:%d: UniValue exception\n",
                         txid.toStdString().c_str(), vout);
                continue;  // Skip this UTXO if we can't sign
            } catch (const std::exception& e) {
                LogPrintf("WalletModel::createProofOfFunds() Failed to sign for %s:%d: %s\n",
                         txid.toStdString().c_str(), vout, e.what());
                continue;  // Skip this UTXO if we can't sign
            }

            // Create proof entry
            QVariantMap proof;
            proof["utxo_ref"] = QString("%1:%2").arg(txid).arg(vout);
            proof["address"] = address;
            proof["message"] = message;
            proof["signature"] = signature;
            proof["asset_id"] = asset_id;
            proof["asset_units"] = static_cast<qulonglong>(amount_units);

            proofs.append(proof);
            accumulated += amount_units;

            LogPrintf("WalletModel::createProofOfFunds() Added UTXO %s:%d (%llu units), accumulated=%llu\n",
                     txid.toStdString().c_str(), vout, amount_units, accumulated);
        }

        if (accumulated < required_units) {
            result.error = QString("Insufficient funds: found %1 units, need %2 units")
                .arg(accumulated).arg(required_units);
            return result;
        }

        result.success = true;
        result.proofs = proofs;
        result.total_units = accumulated;

        LogPrintf("WalletModel::createProofOfFunds() SUCCESS: %d proofs covering %llu units\n",
                 proofs.size(), accumulated);

    } catch (const UniValue& e) {
        result.error = "RPC error: UniValue exception";
        LogPrintf("WalletModel::createProofOfFunds() FAILED: UniValue exception\n");
    } catch (const std::exception& e) {
        result.error = QString("RPC error: %1").arg(e.what());
        LogPrintf("WalletModel::createProofOfFunds() FAILED: %s\n", e.what());
    } catch (...) {
        result.error = "Unknown RPC error occurred";
        LogPrintf("WalletModel::createProofOfFunds() FAILED: Unknown exception\n");
    }

    return result;
}

WalletModel::CreateProofOfFundsResult WalletModel::createDiscussionProof(
    const QString& scope_type,
    const QString& scope_id,
    const QString& network,
    const QString& nostr_pubkey,
    int expiry_height,
    uint64_t min_units)
{
    // Build the canonical discussion proof message
    QString message = QString("TENSORCASH_DISCUSS:v1:%1:%2:%3:%4:%5")
        .arg(network)
        .arg(scope_type)
        .arg(scope_id)
        .arg(nostr_pubkey)
        .arg(expiry_height);

    LogPrintf("WalletModel::createDiscussionProof() message='%s', min_units=%llu\n",
              message.toStdString().c_str(), (unsigned long long)min_units);

    // Delegate to createProofOfFunds with the discussion-specific message as context.
    // However, createProofOfFunds uses "Proof of funds: <context>" format which is wrong here.
    // We need to sign with the exact canonical message, so we replicate the UTXO selection
    // and signing logic with our own message.

    CreateProofOfFundsResult result;

    if (!m_client_model) {
        result.error = "Client model not available";
        return result;
    }

    if (min_units == 0) {
        result.error = "Minimum units cannot be zero";
        return result;
    }

    // Validate inputs
    if (scope_type != "model_prealert" && scope_type != "model_challenge") {
        result.error = QString("Invalid scope_type: %1").arg(scope_type);
        return result;
    }
    if (network != "main" && network != "test" && network != "testnet4" &&
        network != "signet" && network != "regtest" &&
        network != "tensor" && network != "tensor-test" && network != "tensor-reg") {
        result.error = QString("Invalid network: %1").arg(network);
        return result;
    }

    // Ensure wallet is unlocked
    WalletModel::UnlockContext ctx(requestUnlock());
    if (!ctx.isValid()) {
        result.error = tr("Wallet is locked. Please unlock the wallet to generate discussion proofs.");
        return result;
    }

    try {
        std::string walletName = getWalletName().toStdString();

        // List native TSC UTXOs via listunspent (minconf=1 to match strict verifier)
        UniValue params(UniValue::VARR);
        params.push_back(1);       // minconf — must be >=1, strict verifier rejects unconfirmed
        params.push_back(9999999); // maxconf
        UniValue unspent = m_client_model->node().executeRpc("listunspent", params, walletName);

        if (!unspent.isArray() || unspent.size() == 0) {
            result.error = "No native TSC UTXOs available";
            return result;
        }

        // Collect spendable UTXOs, sort by amount ascending
        std::vector<UniValue> utxos;
        for (size_t i = 0; i < unspent.size(); ++i) {
            const UniValue& utxo = unspent[i];
            if (utxo.exists("spendable") && utxo["spendable"].get_bool()) {
                utxos.push_back(utxo);
            }
        }

        std::sort(utxos.begin(), utxos.end(), [](const UniValue& a, const UniValue& b) {
            uint64_t amt_a = 0, amt_b = 0;
            if (a.exists("amount")) amt_a = static_cast<uint64_t>(a["amount"].get_real() * 1e8);
            if (b.exists("amount")) amt_b = static_cast<uint64_t>(b["amount"].get_real() * 1e8);
            return amt_a < amt_b;
        });

        // Select UTXOs and sign with canonical discussion message
        uint64_t accumulated = 0;
        QVariantList proofs;

        for (const UniValue& utxo : utxos) {
            if (accumulated >= min_units) break;

            QString txid = QString::fromStdString(utxo["txid"].get_str());
            int vout = utxo["vout"].getInt<int>();
            QString address = QString::fromStdString(utxo["address"].get_str());
            uint64_t amount_units = 0;
            if (utxo.exists("amount")) {
                amount_units = static_cast<uint64_t>(utxo["amount"].get_real() * 1e8);
            }

            // Sign with BIP-322 using the canonical discussion message
            UniValue signParams(UniValue::VARR);
            signParams.push_back(address.toStdString());
            signParams.push_back(message.toStdString());

            QString signature;
            try {
                UniValue sigResult = m_client_model->node().executeRpc("signmessagebip322", signParams, walletName);
                signature = QString::fromStdString(sigResult.get_str());
            } catch (const std::exception& e) {
                LogPrintf("WalletModel::createDiscussionProof() Failed to sign for %s:%d: %s\n",
                         txid.toStdString().c_str(), vout, e.what());
                continue;
            }

            QVariantMap proof;
            proof["utxo_ref"] = QString("%1:%2").arg(txid).arg(vout);
            proof["address"] = address;
            proof["message"] = message;
            proof["signature"] = signature;
            proof["asset_id"] = QString(); // native TSC
            proof["asset_units"] = static_cast<qulonglong>(amount_units);

            proofs.append(proof);
            accumulated += amount_units;
        }

        if (accumulated < min_units) {
            result.error = QString("Insufficient funds: found %1 sat, need %2 sat")
                .arg(accumulated).arg(min_units);
            return result;
        }

        result.success = true;
        result.proofs = proofs;
        result.total_units = accumulated;

        LogPrintf("WalletModel::createDiscussionProof() SUCCESS: %d proofs covering %llu sat\n",
                 proofs.size(), (unsigned long long)accumulated);

    } catch (const UniValue& e) {
        result.error = "RPC error: UniValue exception";
    } catch (const std::exception& e) {
        result.error = QString("RPC error: %1").arg(e.what());
    } catch (...) {
        result.error = "Unknown RPC error occurred";
    }

    return result;
}

QString WalletModel::getBridgeNostrPubkey()
{
    return m_bulletin_board_pubkey;
}

QList<QVariant> WalletModel::listAssetUTXOs(const QString& asset_id)
{
    QList<QVariant> result;

    if (!m_client_model) {
        return result;
    }

    try {
        UniValue response;

        // For native asset (empty asset_id), use listunspent
        // For registered assets, use listassetutxos
        if (asset_id.isEmpty()) {
            // Native coin - use listunspent
            UniValue params(UniValue::VARR);
            // minconf = 1, maxconf = 9999999, addresses = [], include_unsafe = true
            params.push_back(1);
            params.push_back(9999999);
            params.push_back(UniValue(UniValue::VARR)); // empty addresses array = all

            response = m_client_model->node().executeRpc("listunspent", params, getWalletName().toStdString());

            if (response.isArray()) {
                for (size_t i = 0; i < response.size(); i++) {
                    const UniValue& utxo = response[i];

                    QVariantMap utxoMap;
                    utxoMap["txid"] = QString::fromStdString(utxo["txid"].get_str());
                    utxoMap["vout"] = utxo["vout"].getInt<int>();
                    utxoMap["address"] = QString::fromStdString(utxo["address"].get_str());
                    // For native coin, use "amount" field (in BTC) and convert to satoshis
                    double amount_btc = utxo["amount"].get_real();
                    utxoMap["asset_units"] = static_cast<qint64>(amount_btc * 100000000); // Convert to satoshis
                    utxoMap["confirmations"] = utxo["confirmations"].getInt<int>();

                    result.append(utxoMap);
                }
            }
        } else {
            // Registered asset - use listassetutxos
            UniValue params(UniValue::VARR);
            UniValue assets_array(UniValue::VARR);
            assets_array.push_back(asset_id.toStdString());
            params.push_back(assets_array);

            response = m_client_model->node().executeRpc("listassetutxos", params, getWalletName().toStdString());

            if (response.isArray()) {
                for (size_t i = 0; i < response.size(); i++) {
                    const UniValue& utxo = response[i];

                    // CRITICAL: Only include UTXOs that actually contain the requested asset
                    // (listassetutxos may return UTXOs with different assets or BTC-only outputs)
                    if (!utxo.exists("asset_id") || !utxo.exists("asset_units")) {
                        continue;  // Skip BTC-only UTXOs
                    }

                    std::string utxo_asset_id = utxo["asset_id"].get_str();
                    int64_t utxo_asset_units = utxo["asset_units"].getInt<int64_t>();

                    // Verify this UTXO contains the specific asset we're looking for
                    if (utxo_asset_id != asset_id.toStdString() || utxo_asset_units <= 0) {
                        continue;  // Skip UTXOs with different assets or zero balance
                    }

                    QVariantMap utxoMap;
                    utxoMap["txid"] = QString::fromStdString(utxo["txid"].get_str());
                    utxoMap["vout"] = utxo["vout"].getInt<int>();
                    utxoMap["address"] = QString::fromStdString(utxo["address"].get_str());
                    utxoMap["asset_units"] = static_cast<qint64>(utxo_asset_units);
                    utxoMap["confirmations"] = utxo["confirmations"].getInt<int>();

                    result.append(utxoMap);
                }
            }
        }

    } catch (const UniValue&) {
        // Return empty list on error
    } catch (const std::exception&) {
        // Return empty list on error
    }

    return result;
}

// ============================================================================
// Repo Contract RPCs
// ============================================================================

WalletModel::RepoProposeResult WalletModel::repoPropose(const QVariantMap& terms)
{
    RepoProposeResult result;

    if (!m_client_model) {
        result.error = tr("Client model not available");
        return result;
    }

    try {
        UniValue params(UniValue::VARR);

        // Build terms object
        UniValue termsObj(UniValue::VOBJ);

        auto variantToBool = [](const QVariant& value, bool fallback) {
            if (!value.isValid()) {
                return fallback;
            }
            switch (static_cast<QMetaType::Type>(value.typeId())) {
            case QMetaType::Bool:
                return value.toBool();
            case QMetaType::Int:
            case QMetaType::LongLong:
                return value.toInt() != 0;
            case QMetaType::QString: {
                const QString str = value.toString().trimmed().toLower();
                if (str == QLatin1String("true") || str == QLatin1String("1") || str == QLatin1String("yes")) {
                    return true;
                }
                if (str == QLatin1String("false") || str == QLatin1String("0") || str == QLatin1String("no")) {
                    return false;
                }
                return fallback;
            }
            default:
                break;
            }
            return value.toBool();
        };

        // Role
        termsObj.pushKV("role", terms["role"].toString().toStdString());

        auto decimalsForAsset = [&](bool is_native, const QString& asset_id) -> int {
            if (is_native) {
                return 8;
            }
            if (asset_id.isEmpty()) {
                return 8;
            }
            WalletModel::AssetInfo info = getAssetInfo(asset_id);
            return info.has_decimals ? info.decimals : 8;
        };

        auto toUnits = [&](double amount, bool is_native, const QString& asset_id) -> int64_t {
            const int decimals = decimalsForAsset(is_native, asset_id);
            const double scaled = amount * std::pow(10.0, decimals);
            return static_cast<int64_t>(std::llround(scaled));
        };

        // Sanitize "native" sentinel value - legacy code may pass "native" string instead of empty
        auto sanitizeAssetId = [](const QString& id) -> QString {
            return (id.toLower() == "native") ? QString() : id;
        };

        // Collateral
        const bool collateral_is_native = variantToBool(terms.value("collateral_is_native"), true);
        const QString collateral_asset_id = sanitizeAssetId(terms.value("collateral_asset_id").toString());
        const double collateral_amount = terms.value("collateral_amount").toDouble();
        const int64_t collateral_units = toUnits(collateral_amount, collateral_is_native, collateral_asset_id);

        termsObj.pushKV("collateral_is_native", collateral_is_native);
        if (!collateral_is_native && !collateral_asset_id.isEmpty()) {
            termsObj.pushKV("collateral_asset_id", collateral_asset_id.toStdString());
        }
        if (collateral_is_native) {
            termsObj.pushKV("collateral_sats", collateral_units);
        } else {
            termsObj.pushKV("collateral_units", collateral_units);
        }
        UniValue collateral_leg(UniValue::VOBJ);
        collateral_leg.pushKV("is_native", collateral_is_native);
        if (!collateral_is_native && !collateral_asset_id.isEmpty()) {
            collateral_leg.pushKV("asset_id", collateral_asset_id.toStdString());
        }
        collateral_leg.pushKV("units", collateral_units);
        termsObj.pushKV("collateral_leg", collateral_leg);

        // Principal
        const bool principal_is_native = variantToBool(terms.value("principal_is_native"), true);
        const QString principal_asset_id = sanitizeAssetId(terms.value("principal_asset_id").toString());
        const double principal_amount = terms.value("principal_amount").toDouble();
        const int64_t principal_units = toUnits(principal_amount, principal_is_native, principal_asset_id);

        termsObj.pushKV("principal_is_native", principal_is_native);
        if (!principal_is_native && !principal_asset_id.isEmpty()) {
            termsObj.pushKV("principal_asset_id", principal_asset_id.toStdString());
        }
        termsObj.pushKV("principal_units", principal_units);
        UniValue principal_leg(UniValue::VOBJ);
        principal_leg.pushKV("is_native", principal_is_native);
        if (!principal_is_native && !principal_asset_id.isEmpty()) {
            principal_leg.pushKV("asset_id", principal_asset_id.toStdString());
        }
        principal_leg.pushKV("units", principal_units);
        termsObj.pushKV("principal_leg", principal_leg);

        // Interest (calculated from rate in the wizard, sent as absolute amount)
        const bool interest_is_native = variantToBool(terms.value("interest_is_native"), principal_is_native);
        QString interest_asset_id = sanitizeAssetId(terms.value("interest_asset_id").toString());
        if (!interest_is_native && interest_asset_id.isEmpty()) {
            interest_asset_id = principal_asset_id;
        }
        const double interest_amount = terms.value("interest_amount").toDouble();
        const int64_t interest_units = toUnits(interest_amount, interest_is_native, interest_asset_id);

        termsObj.pushKV("interest_is_native", interest_is_native);
        if (!interest_is_native && !interest_asset_id.isEmpty()) {
            termsObj.pushKV("interest_asset_id", interest_asset_id.toStdString());
        }
        termsObj.pushKV("interest_units", interest_units);
        UniValue interest_leg(UniValue::VOBJ);
        interest_leg.pushKV("is_native", interest_is_native);
        if (!interest_is_native && !interest_asset_id.isEmpty()) {
            interest_leg.pushKV("asset_id", interest_asset_id.toStdString());
        }
        interest_leg.pushKV("units", interest_units);
        termsObj.pushKV("interest_leg", interest_leg);

        // Maturity
        termsObj.pushKV("maturity_height", terms["maturity_height"].toInt());
        termsObj.pushKV("safety_k", terms["safety_buffer"].toInt());

        // Addresses
        termsObj.pushKV("borrower_address", terms["borrower_address"].toString().toStdString());
        termsObj.pushKV("lender_address", terms["lender_address"].toString().toStdString());

        // Fee policy
        termsObj.pushKV("fee_policy", terms["fee_policy"].toString().toStdString());

        params.push_back(termsObj);

        UniValue response = m_client_model->node().executeRpc("repo.propose", params, getWalletName().toStdString());

        result.success = true;
        result.offer_id = QString::fromStdString(response["offer_id"].get_str());
        result.offer_json = QString::fromStdString(response["offer"].write());

        // Store offer data for later use
        result.offer_data["offer_id"] = result.offer_id;
        result.offer_data["offer_json"] = result.offer_json;

    } catch (const UniValue& e) {
        result.success = false;
        result.error = tr("RPC error: %1").arg(QString::fromStdString(e.write()));
    } catch (const std::exception& e) {
        result.success = false;
        result.error = tr("RPC error: %1").arg(QString::fromStdString(e.what()));
    } catch (...) {
        result.success = false;
        result.error = tr("Unknown error occurred");
    }

    return result;
}

WalletModel::RepoImportOfferResult WalletModel::repoImportOffer(const QString& offer_json)
{
    RepoImportOfferResult result;

    if (!m_client_model) {
        result.error = tr("Client model not available");
        return result;
    }

    try {
        UniValue params(UniValue::VARR);

        // Parse JSON string to UniValue
        UniValue offerVal;
        if (!offerVal.read(offer_json.toStdString())) {
            result.error = tr("Invalid JSON format");
            return result;
        }

        params.push_back(offerVal);

        UniValue response = m_client_model->node().executeRpc("repo.import_offer", params, getWalletName().toStdString());

        result.success = true;
        result.offer_id = QString::fromStdString(response["offer_id"].get_str());

    } catch (const UniValue& e) {
        result.success = false;
        result.error = tr("RPC error: %1").arg(QString::fromStdString(e.write()));
    } catch (const std::exception& e) {
        result.success = false;
        result.error = tr("RPC error: %1").arg(QString::fromStdString(e.what()));
    } catch (...) {
        result.success = false;
        result.error = tr("Unknown error occurred");
    }

    return result;
}

// ============================================================================
// Asset Helper Methods
// ============================================================================

QString WalletModel::getNewAddress(const QString& label, const QString& addressType)
{
    if (!m_wallet || !m_client_model) {
        return QString();
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(label.toStdString());
        params.push_back(addressType.toStdString());

        UniValue response = m_client_model->node().executeRpc("getnewaddress", params, getWalletName().toStdString());

        return QString::fromStdString(response.get_str());

    } catch (const UniValue& e) {
        // bitcoind RPC errors are thrown as UniValue, not std::exception.
        // Swallow here so callers see an empty QString instead of the GUI aborting.
        LogPrintf("WalletModel::getNewAddress RPC error: %s\n", e.write().c_str());
        return QString();
    } catch (const std::exception& e) {
        LogPrintf("WalletModel::getNewAddress std::exception: %s\n", e.what());
        return QString();
    } catch (...) {
        LogPrintf("WalletModel::getNewAddress unknown exception\n");
        return QString();
    }
}

QList<WalletModel::AssetInfo> WalletModel::listAssets()
{
    QList<AssetInfo> assets;

    if (!m_client_model) {
        return assets;
    }

    try {
        UniValue params(UniValue::VARR);

        UniValue response = m_client_model->node().executeRpc("listassets", params, getWalletName().toStdString());

        if (response.isArray()) {
            const UniValue& arr = response.get_array();
            for (size_t i = 0; i < arr.size(); ++i) {
                const UniValue& assetObj = arr[i];

                AssetInfo info;
                if (assetObj.exists("asset_id")) {
                    info.asset_id = QString::fromStdString(assetObj["asset_id"].get_str());
                }
                if (assetObj.exists("ticker")) {
                    info.ticker = QString::fromStdString(assetObj["ticker"].get_str());
                }
                if (assetObj.exists("decimals")) {
                    info.decimals = assetObj["decimals"].getInt<int>();
                    info.has_decimals = true;
                }
                if (assetObj.exists("issuer")) {
                    info.issuer = QString::fromStdString(assetObj["issuer"].get_str());
                }

                assets.append(info);
            }
        }

    } catch (const UniValue&) {
        // Return empty list on error
    } catch (const std::exception&) {
        // Return empty list on error
    } catch (...) {
        // Return empty list on error
    }

    return assets;
}

WalletModel::AssetInfo WalletModel::getAssetInfo(const QString& asset_id)
{
    AssetInfo info;

    if (!m_client_model || asset_id.isEmpty()) {
        return info;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(asset_id.toStdString());

        UniValue response = m_client_model->node().executeRpc("getassetinfo", params, "");

        if (response.exists("asset_id")) {
            info.asset_id = QString::fromStdString(response["asset_id"].get_str());
        }
        if (response.exists("ticker")) {
            info.ticker = QString::fromStdString(response["ticker"].get_str());
        }
        if (response.exists("decimals")) {
            info.decimals = response["decimals"].getInt<int>();
            info.has_decimals = true;
        }
        if (response.exists("issuer")) {
            info.issuer = QString::fromStdString(response["issuer"].get_str());
        }

    } catch (const UniValue&) {
        // Swallow RPC-layer UniValue throws and return empty info to callers
    } catch (const std::exception&) {
        // Return empty info on error
    } catch (...) {
        // Non-standard exception; return empty info
    }

    return info;
}

bool WalletModel::assetRequiresKeywrap(const QString& asset_id)
{
    if (!m_client_model || asset_id.isEmpty()) {
        return false;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(asset_id.toStdString());

        UniValue policy = m_client_model->node().executeRpc("getassetpolicy", params, "");

        if (policy.exists("icu_flags")) {
            int icu_flags = policy["icu_flags"].getInt<int>();
            return (icu_flags & 0x01) != 0; // WRAP_REQUIRED flag
        }

    } catch (const UniValue&) {
    } catch (const std::exception&) {
    } catch (...) {
    }

    return false;
}

WalletModel::RepoAcceptResult WalletModel::repoAccept(const QString& offer_id, bool confirmed)
{
    RepoAcceptResult result;

    if (!m_client_model) {
        result.error = "Client model not available";
        return result;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(offer_id.toStdString());

        UniValue options(UniValue::VOBJ);
        options.pushKV("confirmed", confirmed);
        params.push_back(options);

        UniValue response = m_client_model->node().executeRpc("repo.accept", params, getWalletName().toStdString());

        result.success = true;
        if (response.exists("acceptance_id")) {
            result.acceptance_id = QString::fromStdString(response["acceptance_id"].get_str());
        }
        if (response.exists("acceptance_json")) {
            result.acceptance_json = QString::fromStdString(response["acceptance_json"].get_str());
        }
        // Extract the "acceptance" object (matching functional test pattern)
        if (response.exists("acceptance")) {
            const UniValue& acceptanceObj = response["acceptance"];
            result.acceptance_obj_json = QString::fromStdString(acceptanceObj.write());
        }
        if (response.exists("acceptance_data")) {
            // Convert UniValue object to QVariantMap
            const UniValue& dataObj = response["acceptance_data"];
            // Simplified: in production, recursively convert UniValue to QVariant
            result.acceptance_data["raw"] = QString::fromStdString(dataObj.write());
        }

    } catch (const UniValue& e) {
        result.success = false;
        result.error = "RPC error: " + QString::fromStdString(e.write());
    } catch (const std::exception& e) {
        result.success = false;
        result.error = QString::fromStdString(e.what());
    } catch (...) {
        result.success = false;
        result.error = "Unknown exception occurred";
    }

    return result;
}

WalletModel::RepoImportAcceptanceResult WalletModel::repoImportAcceptance(const QString& acceptance_json)
{
    RepoImportAcceptanceResult result;

    if (!m_client_model) {
        result.error = "Client model not available";
        return result;
    }

    try {
        UniValue params(UniValue::VARR);

        // Parse JSON string to UniValue object (RPC expects object, not string)
        UniValue acceptanceVal;
        if (!acceptanceVal.read(acceptance_json.toStdString())) {
            result.error = "Invalid JSON format";
            return result;
        }

        params.push_back(acceptanceVal);

        UniValue response = m_client_model->node().executeRpc("repo.import_acceptance", params, getWalletName().toStdString());

        result.success = true;
        if (response.exists("acceptance_id")) {
            result.acceptance_id = QString::fromStdString(response["acceptance_id"].get_str());
        }

    } catch (const UniValue& e) {
        result.success = false;
        result.error = "RPC error: " + QString::fromStdString(e.write());
    } catch (const std::exception& e) {
        result.success = false;
        result.error = QString::fromStdString(e.what());
    } catch (...) {
        result.success = false;
        result.error = "Unknown exception occurred";
    }

    return result;
}

WalletModel::RepoBuildOpenResult WalletModel::repoBuildOpen(const QString& offer_id, const QVariantMap& options)
{
    RepoBuildOpenResult result;

    if (!m_client_model) {
        result.error = "Client model not available";
        return result;
    }

    // Ensure wallet is unlocked before building the repo contract funding PSBT
    WalletModel::UnlockContext ctx(requestUnlock());
    if (!ctx.isValid()) {
        result.error = tr("Wallet locked. Please unlock the wallet to build the repo contract funding transaction.");
        return result;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(offer_id.toStdString());

        // Build options object with ALL options, not just fee policy
        UniValue optionsObj(UniValue::VOBJ);

        // Fee policy options
        if (options.contains("strategy")) {
            QString strategy = options["strategy"].toString();
            LogPrintf("WalletModel::repoBuildOpen: Passing fee strategy='%s' to RPC\n", strategy.toStdString());
            optionsObj.pushKV("strategy", strategy.toStdString());
        } else {
            LogPrintf("WalletModel::repoBuildOpen: No 'strategy' in options - RPC will use stored fee_policy_strategy\n");
        }
        if (options.contains("satvb")) {
            optionsObj.pushKV("satvb", options["satvb"].toInt());
        }

        // Funding options (CRITICAL: These were being silently dropped before!)
        if (options.contains("auto_fund_principal")) {
            optionsObj.pushKV("auto_fund_principal", options["auto_fund_principal"].toBool());
        }
        if (options.contains("auto_fund_collateral")) {
            optionsObj.pushKV("auto_fund_collateral", options["auto_fund_collateral"].toBool());
        }

        // CRITICAL: Pass maker's base PSBT for taker augmentation
        if (options.contains("psbt")) {
            optionsObj.pushKV("psbt", options["psbt"].toString().toStdString());
        }

        // Coin selection options
        if (options.contains("change_position")) {
            optionsObj.pushKV("change_position", options["change_position"].toInt());
        }
        if (options.contains("subtract_fee_from_outputs")) {
            // Convert QList to UniValue array if needed
            if (options["subtract_fee_from_outputs"].canConvert<QVariantList>()) {
                UniValue subtractArray(UniValue::VARR);
                for (const QVariant& v : options["subtract_fee_from_outputs"].toList()) {
                    subtractArray.push_back(v.toInt());
                }
                optionsObj.pushKV("subtract_fee_from_outputs", subtractArray);
            }
        }

        params.push_back(optionsObj);

        UniValue response = m_client_model->node().executeRpc("repo.build_open", params, getWalletName().toStdString());

        result.success = true;
        if (response.exists("psbt")) {
            result.psbt = QString::fromStdString(response["psbt"].get_str());
        }
        if (response.exists("session_id")) {
            result.session_id = QString::fromStdString(response["session_id"].get_str());
        }
        if (response.exists("is_initiator")) {
            result.is_initiator = response["is_initiator"].get_bool();
        }

    } catch (const UniValue& e) {
        result.success = false;
        result.error = "RPC error: " + QString::fromStdString(e.write());
    } catch (const std::exception& e) {
        result.success = false;
        result.error = QString::fromStdString(e.what());
    } catch (...) {
        result.success = false;
        result.error = "Unknown exception occurred";
    }

    return result;
}

WalletModel::ForwardBuildOpenResult WalletModel::forwardBuildOpen(const QString& offer_id, const QVariantMap& options)
{
    ForwardBuildOpenResult result;

    if (!m_client_model) {
        result.error = "Client model not available";
        return result;
    }

    // Ensure wallet is unlocked before building the forward contract funding PSBT
    WalletModel::UnlockContext ctx(requestUnlock());
    if (!ctx.isValid()) {
        result.error = tr("Wallet locked. Please unlock the wallet to build the forward contract funding transaction.");
        return result;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(offer_id.toStdString());

        // Build options object
        UniValue optionsObj(UniValue::VOBJ);

        // Fee policy options
        if (options.contains("strategy")) {
            QString strategy = options["strategy"].toString();
            LogPrintf("WalletModel::forwardBuildOpen: Passing fee strategy='%s' to RPC\n", strategy.toStdString());
            optionsObj.pushKV("strategy", strategy.toStdString());
        } else {
            LogPrintf("WalletModel::forwardBuildOpen: No 'strategy' in options - RPC will use stored fee_policy_strategy\n");
        }
        if (options.contains("satvb")) {
            optionsObj.pushKV("satvb", options["satvb"].toInt());
        }

        // Auto-funding options (for maker)
        if (options.contains("auto_fund_long")) {
            optionsObj.pushKV("auto_fund_long", options["auto_fund_long"].toBool());
        }
        if (options.contains("auto_fund_short")) {
            optionsObj.pushKV("auto_fund_short", options["auto_fund_short"].toBool());
        }
        if (options.contains("auto_fund_premium")) {
            optionsObj.pushKV("auto_fund_premium", options["auto_fund_premium"].toBool());
        }

        // Maker's base PSBT for taker augmentation
        if (options.contains("psbt")) {
            optionsObj.pushKV("psbt", options["psbt"].toString().toStdString());
        }

        // Coin selection options
        if (options.contains("change_position")) {
            optionsObj.pushKV("change_position", options["change_position"].toInt());
        }
        if (options.contains("subtract_fee_from_outputs")) {
            if (options["subtract_fee_from_outputs"].canConvert<QVariantList>()) {
                UniValue subtractArray(UniValue::VARR);
                for (const QVariant& v : options["subtract_fee_from_outputs"].toList()) {
                    subtractArray.push_back(v.toInt());
                }
                optionsObj.pushKV("subtract_fee_from_outputs", subtractArray);
            }
        }

        params.push_back(optionsObj);

        UniValue response = m_client_model->node().executeRpc("forward.build_open", params, getWalletName().toStdString());

        // DIAGNOSTIC: Log the raw RPC response to debug integer overflow
        LogPrintf("WalletModel::forwardBuildOpen - RPC response: %s\n", response.write(2).c_str());

        result.success = true;

        // Extract PSBT
        if (response.exists("psbt")) {
            result.psbt = QString::fromStdString(response["psbt"].get_str());
        }

        // Extract dual vault indices (CRITICAL for forward contracts)
        if (response.exists("alice_vault_index") && response["alice_vault_index"].isNum()) {
            result.alice_vault_index = response["alice_vault_index"].getInt<int>();
        }
        if (response.exists("bob_vault_index") && response["bob_vault_index"].isNum()) {
            result.bob_vault_index = response["bob_vault_index"].getInt<int>();
        }

        // Extract premium output index (optional)
        if (response.exists("premium_output_index") && response["premium_output_index"].isNum()) {
            result.premium_output_index = response["premium_output_index"].getInt<int>();
        }

        // Store full response for debugging (skip taproot objects to avoid uint8_t parsing issues)
        // The taproot tree contains uint8_t depth/leaf_version fields that cause integer range errors
        // We don't need these in raw_response since we already extracted the critical indices above
        // if (response.isObject()) {
        //     result.raw_response = uniValueToVariantMap(response);
        // }

        LogPrintf("WalletModel::forwardBuildOpen - alice_vault=%d, bob_vault=%d, premium=%d\n",
                  result.alice_vault_index, result.bob_vault_index, result.premium_output_index);

    } catch (const UniValue& e) {
        result.success = false;
        result.error = "RPC error: " + QString::fromStdString(e.write());
    } catch (const std::exception& e) {
        result.success = false;
        result.error = QString::fromStdString(e.what());
    } catch (...) {
        result.success = false;
        result.error = "Unknown exception occurred";
    }

    return result;
}

WalletModel::CosignAdaptorRoundtripResult WalletModel::cosignAdaptorRoundtrip(const QString& session_id, const QString& psbt, bool is_initiator)
{
    CosignAdaptorRoundtripResult result;

    if (!m_client_model) {
        result.error = "Client model not available";
        return result;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(session_id.toStdString());
        params.push_back(psbt.toStdString());
        params.push_back(is_initiator);

        // cosign.* are not wallet-scoped; leave empty wallet context
        UniValue response = m_client_model->node().executeRpc("cosign.adaptor_roundtrip", params, "");

        result.success = true;
        if (response.exists("psbt")) {
            result.psbt = QString::fromStdString(response["psbt"].get_str());
        }
        if (response.exists("complete") && response["complete"].isBool()) {
            result.complete = response["complete"].get_bool();
        } else {
            result.complete = true; // Backward compatibility with bridges that omit the flag
        }

    } catch (const UniValue& e) {
        result.success = false;
        result.error = "RPC error: " + QString::fromStdString(e.write());
    } catch (const std::exception& e) {
        result.success = false;
        result.error = QString::fromStdString(e.what());
    } catch (...) {
        result.success = false;
        result.error = "Unknown exception occurred";
    }

    return result;
}

WalletModel::AdaptorPrepareResult WalletModel::adaptorPrepare(const QString& psbt)
{
    AdaptorPrepareResult result;

    if (!m_client_model) {
        result.error = "Client model not available";
        return result;
    }

    // Ensure wallet is unlocked before preparing adaptor signatures
    WalletModel::UnlockContext ctx(requestUnlock());
    if (!ctx.isValid()) {
        result.error = tr("Wallet locked. Please unlock the wallet to prepare adaptor signatures.");
        return result;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(psbt.toStdString());

        UniValue response = m_client_model->node().executeRpc("adaptor.prepare", params, getWalletName().toStdString());

        result.success = true;
        if (response.exists("psbt")) {
            result.psbt = QString::fromStdString(response["psbt"].get_str());
        }

    } catch (const UniValue& e) {
        result.success = false;
        result.error = "RPC error: " + QString::fromStdString(e.write());
    } catch (const std::exception& e) {
        result.success = false;
        result.error = QString::fromStdString(e.what());
    } catch (...) {
        result.success = false;
        result.error = "Unknown exception occurred";
    }

    return result;
}

WalletModel::AdaptorPartialResult WalletModel::adaptorPartial(const QString& psbt)
{
    AdaptorPartialResult result;

    if (!m_client_model) {
        result.error = "Client model not available";
        return result;
    }

    // Ensure wallet is unlocked before creating partial adaptor signatures
    WalletModel::UnlockContext ctx(requestUnlock());
    if (!ctx.isValid()) {
        result.error = tr("Wallet locked. Please unlock the wallet to create partial adaptor signatures.");
        return result;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(psbt.toStdString());

        UniValue response = m_client_model->node().executeRpc("adaptor.partial", params, getWalletName().toStdString());

        result.success = true;
        if (response.exists("psbt")) {
            result.psbt = QString::fromStdString(response["psbt"].get_str());
        }
        if (response.exists("complete") && response["complete"].isBool()) {
            result.complete = response["complete"].get_bool();
        }

    } catch (const UniValue& e) {
        result.success = false;
        result.error = "RPC error: " + QString::fromStdString(e.write());
    } catch (const std::exception& e) {
        result.success = false;
        result.error = QString::fromStdString(e.what());
    } catch (...) {
        result.success = false;
        result.error = "Unknown exception occurred";
    }

    return result;
}

WalletModel::AdaptorCompleteResult WalletModel::adaptorComplete(const QString& psbt)
{
    AdaptorCompleteResult result;

    if (!m_client_model) {
        result.error = "Client model not available";
        return result;
    }

    // Ensure wallet is unlocked before completing adaptor signatures
    WalletModel::UnlockContext ctx(requestUnlock());
    if (!ctx.isValid()) {
        result.error = tr("Wallet locked. Please unlock the wallet to complete adaptor signatures.");
        return result;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(psbt.toStdString());
        params.push_back(UniValue());  // peer_commit_reveal: null
        UniValue emptyArray(UniValue::VARR);
        params.push_back(emptyArray);  // commit_reveals: []

        UniValue response = m_client_model->node().executeRpc("adaptor.complete", params, getWalletName().toStdString());

        result.success = true;
        if (response.exists("psbt")) {
            result.psbt = QString::fromStdString(response["psbt"].get_str());
        }
        if (response.exists("complete") && response["complete"].isBool()) {
            result.complete = response["complete"].get_bool();
        }

    } catch (const UniValue& e) {
        result.success = false;
        result.error = "RPC error: " + QString::fromStdString(e.write());
    } catch (const std::exception& e) {
        result.success = false;
        result.error = QString::fromStdString(e.what());
    } catch (...) {
        result.success = false;
        result.error = "Unknown exception occurred";
    }

    return result;
}

WalletModel::CombinePsbtResult WalletModel::combinePsbt(const QStringList& psbts)
{
    CombinePsbtResult result;

    if (!m_client_model) {
        result.error = "Client model not available";
        return result;
    }

    try {
        UniValue params(UniValue::VARR);
        UniValue psbtArray(UniValue::VARR);
        for (const QString& psbt : psbts) {
            psbtArray.push_back(psbt.toStdString());
        }
        params.push_back(psbtArray);

        // combinepsbt is node-scoped; leave empty wallet context
        UniValue response = m_client_model->node().executeRpc("combinepsbt", params, "");

        result.success = true;
        result.psbt = QString::fromStdString(response.get_str());

    } catch (const UniValue& e) {
        result.success = false;
        result.error = "RPC error: " + QString::fromStdString(e.write());
    } catch (const std::exception& e) {
        result.success = false;
        result.error = QString::fromStdString(e.what());
    } catch (...) {
        result.success = false;
        result.error = "Unknown exception occurred";
    }

    return result;
}

WalletModel::WalletProcessPsbtResult WalletModel::walletProcessPsbt(const QString& psbt,
                                                                    bool sign,
                                                                    const QString& sighash,
                                                                    bool bip32derivs,
                                                                    bool finalize)
{
    WalletProcessPsbtResult result;

    if (!m_client_model) {
        result.error = "Client model not available";
        return result;
    }

    auto process_psbt = [&]() {
        try {
            UniValue params(UniValue::VARR);
            params.push_back(psbt.toStdString());
            params.push_back(sign);

            // Determine effective sighash override when caller did not specify one.
            // If the PSBT has a homogeneous per-input sighash (ALL or DEFAULT),
            // pass that literal to avoid -22 mismatches inside walletprocesspsbt.
            // Otherwise, pass null to honor per-input settings.
            if (sighash.isEmpty()) {
                QString effective;
                try {
                    UniValue decodeParams(UniValue::VARR);
                    decodeParams.push_back(psbt.toStdString());
                    UniValue decoded = m_client_model->node().executeRpc("decodepsbt", decodeParams, getWalletName().toStdString());
                    if (decoded.exists("inputs") && decoded["inputs"].isArray()) {
                        std::set<std::string> types;
                        for (const UniValue& in : decoded["inputs"].getValues()) {
                            if (in.isObject() && in.exists("sighash") && in["sighash"].isStr()) {
                                types.insert(in["sighash"].get_str());
                            }
                        }
                        if (types.size() == 1) {
                            const std::string& t = *types.begin();
                            if (t == "ALL" || t == "DEFAULT") {
                                effective = QString::fromStdString(t);
                            }
                        } else if (types.size() == 2 && types.count("DEFAULT") && types.count("ALL")) {
                            // Mixed DEFAULT/ALL (typical for vault repayment: vault=DEFAULT, others=ALL).
                            // Use ALL to prevent ANYONECANPAY, since DEFAULT for Taproot is functionally
                            // equivalent to ALL but ALL is more explicit and prevents ANYONECANPAY flag.
                            effective = QStringLiteral("ALL");
                        }
                    }
                } catch (...) {
                    // Fall through to null on any decode issues
                }
                if (effective.isEmpty()) {
                    params.push_back(UniValue()); // null override
                } else {
                    params.push_back(effective.toStdString());
                }
            } else {
                params.push_back(sighash.toStdString());
            }
            params.push_back(bip32derivs);
            params.push_back(finalize);

            UniValue response = m_client_model->node().executeRpc("walletprocesspsbt", params, getWalletName().toStdString());

            result.success = true;
            if (response.exists("psbt")) {
                result.psbt = QString::fromStdString(response["psbt"].get_str());
            }
            if (response.exists("complete") && response["complete"].isBool()) {
                result.complete = response["complete"].get_bool();
            }

        } catch (const UniValue& e) {
            result.success = false;
            result.error = "RPC error: " + QString::fromStdString(e.write());
        } catch (const std::exception& e) {
            result.success = false;
            result.error = QString::fromStdString(e.what());
        } catch (...) {
            result.success = false;
            result.error = "Unknown exception occurred";
        }
    };

    if (sign) {
        WalletModel::UnlockContext ctx(requestUnlock());
        if (!ctx.isValid()) {
            result.success = false;
            result.error = tr("Wallet locked. Please unlock the wallet to sign the PSBT.");
            return result;
        }
        process_psbt();
    } else {
        process_psbt();
    }

    return result;
}

WalletModel::BroadcastPsbtResult WalletModel::broadcastPsbt(const QString& psbt)
{
    BroadcastPsbtResult result;

    if (!m_client_model) {
        result.error = "Client model not available";
        return result;
    }

    try {
        std::string hexTx;

        // First check if this is already a raw transaction (not a PSBT)
        try {
            UniValue decodeParams(UniValue::VARR);
            decodeParams.push_back(psbt.toStdString());
            UniValue decodeResponse = m_client_model->node().executeRpc("decoderawtransaction", decodeParams, "");

            // If decoderawtransaction succeeded, we already have a raw transaction
            if (decodeResponse.isObject() && decodeResponse.exists("txid")) {
                LogPrintf("broadcastPsbt: Input is already a raw transaction, broadcasting directly\n");
                hexTx = psbt.toStdString();
            }
        } catch (...) {
            // Not a raw transaction, try to finalize as PSBT
            LogPrintf("broadcastPsbt: Input is a PSBT, attempting to finalize\n");
        }

        // If we don't have a raw transaction yet, try to finalize the PSBT
        if (hexTx.empty()) {
            UniValue finalizeParams(UniValue::VARR);
            finalizeParams.push_back(psbt.toStdString());

            UniValue finalizeResponse = m_client_model->node().executeRpc("finalizepsbt", finalizeParams, "");
            LogPrintf("broadcastPsbt: finalizepsbt response type=%s\n",
                      finalizeResponse.isObject() ? "object" : (finalizeResponse.isStr() ? "string" : "other"));

            // Check if we have a complete transaction
            if (finalizeResponse.isObject()) {
                if (finalizeResponse.exists("complete") && !finalizeResponse["complete"].get_bool()) {
                    // Diagnostic logging to identify which inputs are incomplete.
                    LogPrintf("broadcastPsbt: finalizepsbt incomplete. Collecting diagnostics...\n");
                    try {
                        std::string diag_psbt;
                        if (finalizeResponse.exists("psbt") && finalizeResponse["psbt"].isStr()) {
                            diag_psbt = finalizeResponse["psbt"].get_str();
                        } else {
                            // Fallback to original PSBT if finalizepsbt didn't echo it back
                            diag_psbt = psbt.toStdString();
                        }

                        UniValue decodeParams(UniValue::VARR);
                        decodeParams.push_back(diag_psbt);
                        UniValue decoded = m_client_model->node().executeRpc("decodepsbt", decodeParams, getWalletName().toStdString());

	                        if (decoded.isObject() && decoded.exists("inputs") && decoded["inputs"].isArray()) {
	                            const UniValue& ins = decoded["inputs"].get_array();
	                            for (size_t i = 0; i < ins.size(); ++i) {
	                                const UniValue& in = ins[i];
	                                bool has_final_wit = in.exists("final_scriptwitness");
	                                int final_wit_elems = 0;
	                                if (has_final_wit && in["final_scriptwitness"].isArray()) {
	                                    final_wit_elems = static_cast<int>(in["final_scriptwitness"].size());
	                                }
	                                int tr_script_sig_count = 0;
	                                if (in.exists("taproot_script_path_sigs") && in["taproot_script_path_sigs"].isArray()) {
	                                    tr_script_sig_count = static_cast<int>(in["taproot_script_path_sigs"].size());
	                                }
	                                bool has_tr_internal = in.exists("taproot_internal_key");
	                                int tr_scripts_count = 0;
	                                if (in.exists("taproot_scripts") && in["taproot_scripts"].isArray()) {
	                                    tr_scripts_count = static_cast<int>(in["taproot_scripts"].size());
	                                }
	                                int partial_sigs = 0;
	                                if (in.exists("partial_signatures") && in["partial_signatures"].isObject()) {
	                                    partial_sigs = static_cast<int>(in["partial_signatures"].getKeys().size());
	                                }

	                                // Additional diagnostics: per-input sighash and scriptPubKey type (when available).
	                                std::string sighash_type;
	                                if (in.exists("sighash") && in["sighash"].isStr()) {
	                                    sighash_type = in["sighash"].get_str();
	                                }
	                                std::string spk_type;
	                                if (in.exists("witness_utxo") && in["witness_utxo"].isObject()) {
	                                    const UniValue& wu = in["witness_utxo"];
	                                    if (wu.exists("scriptPubKey") && wu["scriptPubKey"].isObject()) {
	                                        const UniValue& spk = wu["scriptPubKey"];
	                                        if (spk.exists("type") && spk["type"].isStr()) {
	                                            spk_type = spk["type"].get_str();
	                                        }
	                                    }
	                                }

	                                LogPrintf(
	                                    "broadcastPsbt: input %d diag: final_witness=%d elem(s), tap_script_sigs=%d, tap_scripts=%d, has_tr_internal=%d, partial_sigs=%d, sighash='%s', spk_type='%s'\n",
	                                    static_cast<int>(i), has_final_wit ? final_wit_elems : 0, tr_script_sig_count,
	                                    tr_scripts_count, has_tr_internal ? 1 : 0, partial_sigs,
	                                    sighash_type.empty() ? "unset" : sighash_type.c_str(),
	                                    spk_type.empty() ? "unknown" : spk_type.c_str());
	                            }
	                        } else {
                            LogPrintf("broadcastPsbt: decodepsbt failed or returned no inputs\n");
                        }
                    } catch (const std::exception& e) {
                        LogPrintf("broadcastPsbt: diagnostics failed: %s\n", e.what());
                    } catch (...) {
                        LogPrintf("broadcastPsbt: diagnostics failed: unknown exception\n");
                    }

                    result.error = "PSBT could not be finalized - missing signatures";
                    return result;
                }
                if (finalizeResponse.exists("hex")) {
                    hexTx = finalizeResponse["hex"].get_str();
                } else if (finalizeResponse.exists("psbt")) {
                    // Sometimes finalizepsbt returns a psbt field instead of hex
                    // Try to extract hex from the PSBT
                    result.error = "PSBT finalized but no hex transaction returned";
                    return result;
                }
            } else if (finalizeResponse.isStr()) {
                // Sometimes finalizepsbt returns just the hex string directly
                hexTx = finalizeResponse.get_str();
            }
        }

        if (hexTx.empty()) {
            result.error = "Failed to finalize PSBT - no transaction hex";
            return result;
        }

        // Now broadcast the finalized transaction
        UniValue broadcastParams(UniValue::VARR);
        broadcastParams.push_back(hexTx);

        UniValue response = m_client_model->node().executeRpc("sendrawtransaction", broadcastParams, "");

        result.success = true;
        result.txid = QString::fromStdString(response.get_str());

    } catch (const UniValue& e) {
        result.success = false;
        result.error = "RPC error: " + QString::fromStdString(e.write());
    } catch (const std::exception& e) {
        result.success = false;
        result.error = QString::fromStdString(e.what());
    } catch (...) {
        result.success = false;
        result.error = "Unknown exception occurred";
    }

    return result;
}

QList<QVariantMap> WalletModel::listContracts()
{
    QList<QVariantMap> contracts;

    if (!m_client_model) {
        return contracts;
    }

    try {
        UniValue params(UniValue::VARR);
        UniValue response = m_client_model->node().executeRpc("contract.list", params, getWalletName().toStdString());

        if (response.isArray()) {
            for (size_t i = 0; i < response.size(); i++) {
                const UniValue& contractObj = response[i];
                QVariantMap contract;

                // Extract contract fields
                if (contractObj.exists("id")) {
                    contract["id"] = QString::fromStdString(contractObj["id"].get_str());
                }
                if (contractObj.exists("type")) {
                    contract["type"] = QString::fromStdString(contractObj["type"].get_str());
                }
                if (contractObj.exists("role")) {
                    contract["role"] = QString::fromStdString(contractObj["role"].get_str());
                }
                if (contractObj.exists("status")) {
                    contract["status"] = QString::fromStdString(contractObj["status"].get_str());
                }
                if (contractObj.exists("maturity_height")) {
                    contract["maturity_height"] = contractObj["maturity_height"].getInt<int>();
                }
                if (contractObj.exists("principal_amount")) {
                    contract["principal_amount"] = contractObj["principal_amount"].get_real();
                }
                if (contractObj.exists("collateral_amount")) {
                    contract["collateral_amount"] = contractObj["collateral_amount"].get_real();
                }
                if (contractObj.exists("collateral_asset")) {
                    contract["collateral_asset"] = QString::fromStdString(contractObj["collateral_asset"].get_str());
                }
                if (contractObj.exists("principal_asset")) {
                    contract["principal_asset"] = QString::fromStdString(contractObj["principal_asset"].get_str());
                }
                if (contractObj.exists("interest_asset")) {
                    contract["interest_asset"] = QString::fromStdString(contractObj["interest_asset"].get_str());
                }
                if (contractObj.exists("haircut_amount")) {
                    contract["haircut_amount"] = contractObj["haircut_amount"].get_real();
                }
                if (contractObj.exists("interest_amount")) {
                    contract["interest_amount"] = contractObj["interest_amount"].get_real();
                }
                if (contractObj.exists("opening_txid")) {
                    contract["opening_txid"] = QString::fromStdString(contractObj["opening_txid"].get_str());
                }
                if (contractObj.exists("closing_txid")) {
                    contract["closing_txid"] = QString::fromStdString(contractObj["closing_txid"].get_str());
                }
                if (contractObj.exists("borrower_address")) {
                    contract["borrower_address"] = QString::fromStdString(contractObj["borrower_address"].get_str());
                }
                if (contractObj.exists("lender_address")) {
                    contract["lender_address"] = QString::fromStdString(contractObj["lender_address"].get_str());
                }
                if (contractObj.exists("ltv")) {
                    contract["ltv"] = contractObj["ltv"].get_real();
                }
                if (contractObj.exists("created_height")) {
                    contract["created_height"] = contractObj["created_height"].getInt<int>();
                }

                // Extract forward/option contract fields
                if (contractObj.exists("long_deliver_amount")) {
                    contract["long_deliver_amount"] = contractObj["long_deliver_amount"].get_real();
                }
                if (contractObj.exists("long_deliver_asset")) {
                    contract["long_deliver_asset"] = QString::fromStdString(contractObj["long_deliver_asset"].get_str());
                }
                if (contractObj.exists("long_margin_amount")) {
                    contract["long_margin_amount"] = contractObj["long_margin_amount"].get_real();
                }
                if (contractObj.exists("long_margin_asset")) {
                    contract["long_margin_asset"] = QString::fromStdString(contractObj["long_margin_asset"].get_str());
                }
                if (contractObj.exists("short_deliver_amount")) {
                    contract["short_deliver_amount"] = contractObj["short_deliver_amount"].get_real();
                }
                if (contractObj.exists("short_deliver_asset")) {
                    contract["short_deliver_asset"] = QString::fromStdString(contractObj["short_deliver_asset"].get_str());
                }
                if (contractObj.exists("short_margin_amount")) {
                    contract["short_margin_amount"] = contractObj["short_margin_amount"].get_real();
                }
                if (contractObj.exists("short_margin_asset")) {
                    contract["short_margin_asset"] = QString::fromStdString(contractObj["short_margin_asset"].get_str());
                }
                if (contractObj.exists("premium_amount")) {
                    contract["premium_amount"] = contractObj["premium_amount"].get_real();
                }
                if (contractObj.exists("premium_asset")) {
                    contract["premium_asset"] = QString::fromStdString(contractObj["premium_asset"].get_str());
                }
                if (contractObj.exists("deadline_short")) {
                    contract["deadline_short"] = contractObj["deadline_short"].getInt<int>();
                }
                if (contractObj.exists("deadline_long")) {
                    contract["deadline_long"] = contractObj["deadline_long"].getInt<int>();
                }
                if (contractObj.exists("long_im_percent")) {
                    contract["long_im_percent"] = contractObj["long_im_percent"].get_real();
                }
                if (contractObj.exists("short_im_percent")) {
                    contract["short_im_percent"] = contractObj["short_im_percent"].get_real();
                }
                if (contractObj.exists("safety_k")) {
                    contract["safety_k"] = contractObj["safety_k"].getInt<int>();
                }
                if (contractObj.exists("reorg_conf")) {
                    contract["reorg_conf"] = contractObj["reorg_conf"].getInt<int>();
                }

                // Extract spot contract fields
                if (contractObj.exists("alice_deliver_amount")) {
                    contract["alice_deliver_amount"] = contractObj["alice_deliver_amount"].get_real();
                }
                if (contractObj.exists("alice_deliver_asset")) {
                    contract["alice_deliver_asset"] = QString::fromStdString(contractObj["alice_deliver_asset"].get_str());
                }
                if (contractObj.exists("bob_deliver_amount")) {
                    contract["bob_deliver_amount"] = contractObj["bob_deliver_amount"].get_real();
                }
                if (contractObj.exists("bob_deliver_asset")) {
                    contract["bob_deliver_asset"] = QString::fromStdString(contractObj["bob_deliver_asset"].get_str());
                }
                if (contractObj.exists("exchange_rate")) {
                    contract["exchange_rate"] = contractObj["exchange_rate"].get_real();
                }

                // Extract difficulty-derivative fields (CFD + option). The per-leg objects are flattened to
                // diff_long_* / diff_short_* and the option premium to diff_premium to avoid colliding with
                // the forward's long_margin_amount / premium_amount keys.
                if (contractObj.exists("kind")) {
                    contract["kind"] = QString::fromStdString(contractObj["kind"].get_str());
                }
                if (contractObj.exists("strike_nbits")) {
                    contract["strike_nbits"] = QString::fromStdString(contractObj["strike_nbits"].get_str());
                }
                if (contractObj.exists("fixing_height")) {
                    contract["fixing_height"] = contractObj["fixing_height"].getInt<int>();
                }
                if (contractObj.exists("settle_lock_height")) {
                    contract["settle_lock_height"] = contractObj["settle_lock_height"].getInt<int>();
                }
                if (contractObj.exists("long_leg") && contractObj["long_leg"].isObject()) {
                    const UniValue& ll = contractObj["long_leg"];
                    if (ll.exists("im")) contract["diff_long_im"] = ll["im"].get_real();
                    if (ll.exists("lambda")) contract["diff_long_lambda"] = ll["lambda"].get_real();
                }
                if (contractObj.exists("short_leg") && contractObj["short_leg"].isObject()) {
                    const UniValue& sl = contractObj["short_leg"];
                    if (sl.exists("im")) contract["diff_short_im"] = sl["im"].get_real();
                    if (sl.exists("lambda")) contract["diff_short_lambda"] = sl["lambda"].get_real();
                }
                if (contractObj.exists("premium")) {
                    contract["diff_premium"] = contractObj["premium"].get_real();
                }
                if (contractObj.exists("writer_side")) {
                    contract["writer_side"] = QString::fromStdString(contractObj["writer_side"].get_str());
                }
                if (contractObj.exists("long_vault")) {
                    contract["long_vault"] = QString::fromStdString(contractObj["long_vault"].get_str());
                }
                if (contractObj.exists("short_vault")) {
                    contract["short_vault"] = QString::fromStdString(contractObj["short_vault"].get_str());
                }
                if (contractObj.exists("open_txid")) {
                    contract["open_txid"] = QString::fromStdString(contractObj["open_txid"].get_str());
                }
                if (contractObj.exists("long_settled")) {
                    contract["long_settled"] = contractObj["long_settled"].get_bool();
                }
                if (contractObj.exists("short_settled")) {
                    contract["short_settled"] = contractObj["short_settled"].get_bool();
                }

                // Extract scalar-feed bilateral CFD fields (type == "scalarcfd"). Shares the vault/open/
                // settled/settle_lock keys above; only its feed-specific terms + legs are flattened here to
                // scfd_* to avoid colliding with the difficulty diff_* / forward long_margin_* keys. IMs are
                // in the collateral's units (kept as-is, not TSC-scaled).
                if (contractObj.exists("feed_id")) {
                    contract["scfd_feed_id"] = contractObj["feed_id"].getInt<int>();
                }
                if (contractObj.exists("fixing_ref")) {
                    contract["scfd_fixing_ref"] = static_cast<qulonglong>(contractObj["fixing_ref"].getInt<int64_t>());
                }
                if (contractObj.exists("strike")) {
                    contract["scfd_strike"] = QString::fromStdString(contractObj["strike"].get_str());
                }
                if (contractObj.exists("publication_deadline_height")) {
                    contract["scfd_publication_deadline_height"] = contractObj["publication_deadline_height"].getInt<int>();
                }
                if (contract.value("type").toString() == "scalarcfd") {
                    if (contractObj.exists("long_leg") && contractObj["long_leg"].isObject()) {
                        const UniValue& ll = contractObj["long_leg"];
                        if (ll.exists("im")) contract["scfd_long_im"] = ll["im"].get_real();
                        if (ll.exists("lambda")) contract["scfd_long_lambda"] = ll["lambda"].get_real();
                    }
                    if (contractObj.exists("short_leg") && contractObj["short_leg"].isObject()) {
                        const UniValue& sl = contractObj["short_leg"];
                        if (sl.exists("im")) contract["scfd_short_im"] = sl["im"].get_real();
                        if (sl.exists("lambda")) contract["scfd_short_lambda"] = sl["lambda"].get_real();
                    }
                }

                // Detect option contracts: forwards with non-zero premium
                // Options are registered as "forward" in the backend, but we need to distinguish them in the UI
                if (contract.value("type").toString() == "forward") {
                    double premiumAmount = contract.value("premium_amount", 0.0).toDouble();
                    if (premiumAmount > 0.00001) {  // Non-zero premium threshold
                        contract["type"] = "option";
                    }
                }

                contracts.append(contract);
            }
        }

    } catch (const UniValue&) {
        // RPC method doesn't exist yet or returned error - return empty list
    } catch (const std::exception& e) {
        // Return empty list on error
    } catch (...) {
        // Catch any other exceptions
    }

    return contracts;
}

// ============================================================================
// Repo Contract Lifecycle RPC Wrappers
// ============================================================================

WalletModel::RepoBuildResult WalletModel::repoBuildRepayRelease(const QString& contractId, double feeRate, const QVariantMap& extraOptions)
{
    RepoBuildResult result;

    if (!m_client_model) {
        result.error = tr("Client model not available");
        return result;
    }

    // Ensure wallet is unlocked before building the repay-and-release transaction
    WalletModel::UnlockContext ctx(requestUnlock());
    if (!ctx.isValid()) {
        result.error = tr("Wallet locked. Please unlock the wallet to build the repay-and-release transaction.");
        return result;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(contractId.toStdString());

        UniValue options(UniValue::VOBJ);
        bool hasOptions = false;
        if (feeRate > 0.0) {
            options.pushKV("fee_rate", feeRate);
            hasOptions = true;
        }
        if (!extraOptions.isEmpty()) {
            AppendExtraOptionsToUniValue(extraOptions, options, hasOptions);
        }
        if (hasOptions) {
            params.push_back(options);
        }

        UniValue response = m_client_model->node().executeRpc("repo.build_repay_release", params, getWalletName().toStdString());

        if (!response.isObject()) {
            result.error = tr("Invalid response from RPC");
            return result;
        }

        result.success = true;

        // Extract PSBT
        if (response.exists("psbt")) {
            result.psbt = QString::fromStdString(response["psbt"].get_str());
        }

        // Extract output indices
        if (response.exists("repay_output_index")) {
            result.repayOutputIndex = response["repay_output_index"].getInt<int>();
        }
        if (response.exists("collateral_output_index")) {
            result.collateralOutputIndex = response["collateral_output_index"].getInt<int>();
        }
        if (response.exists("vault_input_index")) {
            result.vaultInputIndex = response["vault_input_index"].getInt<int>();
        }

    } catch (const std::exception& e) {
        result.error = QString::fromStdString(e.what());
    }

    return result;
}

WalletModel::RepoBuildResult WalletModel::repoBuildDefaultSweep(const QString& contractId, double feeRate, const QVariantMap& extraOptions)
{
    RepoBuildResult result;

    if (!m_client_model) {
        result.error = tr("Client model not available");
        return result;
    }

    // Ensure wallet is unlocked before building the default sweep transaction
    WalletModel::UnlockContext ctx(requestUnlock());
    if (!ctx.isValid()) {
        result.error = tr("Wallet locked. Please unlock the wallet to build the default sweep transaction.");
        return result;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(contractId.toStdString());

        UniValue options(UniValue::VOBJ);
        bool hasOptions = false;
        if (feeRate > 0.0) {
            options.pushKV("fee_rate", feeRate);
            hasOptions = true;
        }
        if (!extraOptions.isEmpty()) {
            AppendExtraOptionsToUniValue(extraOptions, options, hasOptions);
        }
        if (hasOptions) {
            params.push_back(options);
        }

        UniValue response = m_client_model->node().executeRpc("repo.build_default_sweep", params, getWalletName().toStdString());

        if (!response.isObject()) {
            result.error = tr("Invalid response from RPC");
            return result;
        }

        result.success = true;

        // Check if transaction is complete (hot wallet)
        if (response.exists("complete")) {
            result.complete = response["complete"].get_bool();
        }

        // Extract hex for complete transactions
        if (result.complete && response.exists("hex")) {
            result.hex = QString::fromStdString(response["hex"].get_str());
        }

        // Extract txid if available
        if (response.exists("txid")) {
            result.txid = QString::fromStdString(response["txid"].get_str());
        }

        // Extract PSBT when provided (both hot-wallet and watch-only paths may include it)
        if (response.exists("psbt")) {
            result.psbt = QString::fromStdString(response["psbt"].get_str());
        }

        // Extract sweep output index
        if (response.exists("sweep_output_index")) {
            result.sweepOutputIndex = response["sweep_output_index"].getInt<int>();
        }
        if (response.exists("vault_input_index")) {
            result.vaultInputIndex = response["vault_input_index"].getInt<int>();
        }

    } catch (const std::exception& e) {
        result.error = QString::fromStdString(e.what());
    }

    return result;
}

// ============================================================================
// Spot Atomic Swap RPC Wrappers
// ============================================================================

QVariantMap WalletModel::spotAddCommitmentProof(const QString& psbt, const QString& offerId)
{
    QVariantMap result;

    if (!m_client_model) {
        result["success"] = false;
        result["error"] = tr("Client model not available");
        return result;
    }

     // Ensure wallet is unlocked before adding spot commitment proofs
     WalletModel::UnlockContext ctx(requestUnlock());
     if (!ctx.isValid()) {
         result["success"] = false;
         result["error"] = tr("Wallet locked. Please unlock the wallet to add the commitment proof.");
         return result;
     }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(psbt.toStdString());
        params.push_back(offerId.toStdString());

        UniValue response = m_client_model->node().executeRpc("spot.add_commitment_proof", params, getWalletName().toStdString());

        if (!response.isObject()) {
            result["success"] = false;
            result["error"] = tr("Invalid response from RPC");
            return result;
        }

        result["success"] = true;

        if (response.exists("psbt")) {
            result["psbt"] = QString::fromStdString(response["psbt"].get_str());
        }
        if (response.exists("commitment_hash")) {
            result["commitment_hash"] = QString::fromStdString(response["commitment_hash"].get_str());
        }
        if (response.exists("commitment_preimage_info")) {
            result["commitment_preimage_info"] = QString::fromStdString(response["commitment_preimage_info"].get_str());
        }
        if (response.exists("canonical_text")) {
            result["canonical_text"] = QString::fromStdString(response["canonical_text"].get_str());
        }

    } catch (const UniValue& e) {
        result["success"] = false;
        result["error"] = tr("RPC error: %1").arg(QString::fromStdString(e.write()));
    } catch (const std::exception& e) {
        result["success"] = false;
        result["error"] = QString::fromStdString(e.what());
    } catch (...) {
        result["success"] = false;
        result["error"] = tr("Unknown error occurred while adding commitment proof");
    }

    return result;
}

QVariantMap WalletModel::decodePsbt(const QString& psbt)
{
    QVariantMap result;

    if (!m_client_model) {
        LogPrintf("WalletModel::decodePsbt() ERROR: m_client_model is null\n");
        return result; // Return empty map on error
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(psbt.toStdString());

        UniValue response = m_client_model->node().executeRpc("decodepsbt", params, getWalletName().toStdString());

        if (!response.isObject()) {
            LogPrintf("WalletModel::decodePsbt() ERROR: response is not an object, response.isNull()=%d, response.type()=%d\n",
                      response.isNull(), response.type());
            return result; // Return empty map
        }

        // Convert UniValue response to QVariantMap
        result = uniValueToVariantMap(response);
        LogPrintf("WalletModel::decodePsbt() SUCCESS: decoded %zu top-level keys\n", result.size());

    } catch (const std::exception& e) {
        // Return empty map on error (caller checks isEmpty())
        LogPrintf("WalletModel::decodePsbt() EXCEPTION: %s\n", e.what());
        result.clear();
    }

    return result;
}

// Helper function to convert UniValue to QVariantMap recursively
QVariantMap WalletModel::uniValueToVariantMap(const UniValue& uv)
{
    QVariantMap map;

    if (!uv.isObject()) {
        return map;
    }

    const std::vector<std::string>& keys = uv.getKeys();
    for (const std::string& key_str : keys) {
        const QString key = QString::fromStdString(key_str);
        const UniValue& val = uv[key_str];

        if (val.isNull()) {
            map[key] = QVariant();
        } else if (val.isBool()) {
            map[key] = val.get_bool();
        } else if (val.isNum()) {
            // Try to parse as 64-bit integer; if it fails (value out of range), keep as string
            try {
                map[key] = QVariant::fromValue(val.getInt<qint64>());
            } catch (const std::runtime_error&) {
                // Value exceeds int64_t range, keep as string for display purposes
                map[key] = QString::fromStdString(val.getValStr());
            }
        } else if (val.isStr()) {
            map[key] = QString::fromStdString(val.get_str());
        } else if (val.isArray()) {
            QVariantList list;
            for (size_t i = 0; i < val.size(); ++i) {
                const UniValue& item = val[i];
                if (item.isObject()) {
                    list.append(uniValueToVariantMap(item));
                } else if (item.isStr()) {
                    list.append(QString::fromStdString(item.get_str()));
                } else if (item.isNum()) {
                    // Try to parse as 64-bit integer; if it fails (value out of range), keep as string
                    try {
                        list.append(QVariant::fromValue(item.getInt<qint64>()));
                    } catch (const std::runtime_error&) {
                        // Value exceeds int64_t range, keep as string for display purposes
                        list.append(QString::fromStdString(item.getValStr()));
                    }
                } else if (item.isBool()) {
                    list.append(item.get_bool());
                }
            }
            map[key] = list;
        } else if (val.isObject()) {
            map[key] = uniValueToVariantMap(val);
        }
    }

    return map;
}

// ============================================================================
// Forward Contract RPC Wrappers
// ============================================================================

WalletModel::ForwardProposeResult WalletModel::forwardPropose(const QVariantMap& terms)
{
    ForwardProposeResult result;

    if (!m_client_model) {
        result.error = tr("Client model not available");
        return result;
    }

    auto resolve_asset_decimals = [&](bool is_native, const QString& assetId) -> int {
        if (is_native || assetId.isEmpty()) {
            return 8;
        }
        WalletModel::AssetInfo info = getAssetInfo(assetId);
        return info.has_decimals ? info.decimals : 8;
    };

    auto convert_amount_to_units = [&](double amount, int decimals) -> qint64 {
        const double scale = std::pow(10.0, decimals);
        return static_cast<qint64>(std::llround(amount * scale));
    };

    try {
        UniValue params(UniValue::VARR);
        UniValue termsObj(UniValue::VOBJ);

        // Build long_party object
        UniValue longParty(UniValue::VOBJ);

        // Long delivery leg
        UniValue longDeliverLeg(UniValue::VOBJ);
        const bool longDeliverIsNative = terms.value("long_deliver_is_native", false).toBool();
        const QString longDeliverAssetId = terms.value("long_deliver_asset_id").toString();
        if (longDeliverIsNative) {
            longDeliverLeg.pushKV("is_native", true);
        } else if (!longDeliverAssetId.isEmpty()) {
            longDeliverLeg.pushKV("asset_id", longDeliverAssetId.toStdString());
        }
        const qint64 longDeliverUnits = convert_amount_to_units(
            terms.value("long_deliver_units").toDouble(),
            resolve_asset_decimals(longDeliverIsNative, longDeliverAssetId));
        longDeliverLeg.pushKV("units", static_cast<int64_t>(longDeliverUnits));
        longParty.pushKV("deliver_leg", longDeliverLeg);

        // Long margin leg
        UniValue longMarginLeg(UniValue::VOBJ);
        const bool longImIsNative = terms.value("long_im_is_native", false).toBool();
        const QString longImAssetId = terms.value("long_im_asset_id").toString();
        if (longImIsNative) {
            longMarginLeg.pushKV("is_native", true);
        } else if (!longImAssetId.isEmpty()) {
            longMarginLeg.pushKV("asset_id", longImAssetId.toStdString());
        }
        const qint64 longImUnits = convert_amount_to_units(
            terms.value("long_im_units").toDouble(),
            resolve_asset_decimals(longImIsNative, longImAssetId));
        longMarginLeg.pushKV("units", static_cast<int64_t>(longImUnits));
        longParty.pushKV("margin_leg", longMarginLeg);

        // Long addresses
        longParty.pushKV("margin_dest", terms["long_margin_dest"].toString().toStdString());
        longParty.pushKV("settlement_receive_dest", terms["long_settle_dest"].toString().toStdString());

        termsObj.pushKV("long_party", longParty);

        // Build short_party object
        UniValue shortParty(UniValue::VOBJ);

        // Short delivery leg
        UniValue shortDeliverLeg(UniValue::VOBJ);
        const bool shortDeliverIsNative = terms.value("short_deliver_is_native", false).toBool();
        const QString shortDeliverAssetId = terms.value("short_deliver_asset_id").toString();
        if (shortDeliverIsNative) {
            shortDeliverLeg.pushKV("is_native", true);
        } else if (!shortDeliverAssetId.isEmpty()) {
            shortDeliverLeg.pushKV("asset_id", shortDeliverAssetId.toStdString());
        }
        const qint64 shortDeliverUnits = convert_amount_to_units(
            terms.value("short_deliver_units").toDouble(),
            resolve_asset_decimals(shortDeliverIsNative, shortDeliverAssetId));
        shortDeliverLeg.pushKV("units", static_cast<int64_t>(shortDeliverUnits));
        shortParty.pushKV("deliver_leg", shortDeliverLeg);

        // Short margin leg
        UniValue shortMarginLeg(UniValue::VOBJ);
        const bool shortImIsNative = terms.value("short_im_is_native", false).toBool();
        const QString shortImAssetId = terms.value("short_im_asset_id").toString();
        if (shortImIsNative) {
            shortMarginLeg.pushKV("is_native", true);
        } else if (!shortImAssetId.isEmpty()) {
            shortMarginLeg.pushKV("asset_id", shortImAssetId.toStdString());
        }
        const qint64 shortImUnits = convert_amount_to_units(
            terms.value("short_im_units").toDouble(),
            resolve_asset_decimals(shortImIsNative, shortImAssetId));
        shortMarginLeg.pushKV("units", static_cast<int64_t>(shortImUnits));
        shortParty.pushKV("margin_leg", shortMarginLeg);

        // Short addresses
        shortParty.pushKV("margin_dest", terms["short_margin_dest"].toString().toStdString());
        shortParty.pushKV("settlement_receive_dest", terms["short_settle_dest"].toString().toStdString());

        termsObj.pushKV("short_party", shortParty);

        // Premium (optional, for options)
        LogPrintf("WalletModel::forwardPropose - Checking premium: has_premium=%s, type=%s, toBool=%d\n",
                  terms.contains("has_premium") ? "true" : "false",
                  terms.value("has_premium").typeName(),
                  terms.value("has_premium").toBool());
        if (terms.contains("has_premium") && terms["has_premium"].toBool()) {
            UniValue premium(UniValue::VOBJ);

            const bool premiumIsNative = terms.value("premium_is_native", false).toBool();
            if (premiumIsNative) {
                // Don't include asset_id for native
            } else if (terms.contains("premium_asset_id")) {
                premium.pushKV("asset_id", terms["premium_asset_id"].toString().toStdString());
            }

            const QString premiumAssetId = terms.value("premium_asset_id").toString();
            const qint64 premiumUnits = convert_amount_to_units(
                terms.value("premium_units").toDouble(),
                resolve_asset_decimals(premiumIsNative, premiumAssetId));
            premium.pushKV("units", static_cast<int64_t>(premiumUnits));
            premium.pushKV("payer", terms["premium_payer"].toString().toStdString());
            premium.pushKV("payee_dest", terms["premium_dest"].toString().toStdString());

            LogPrintf("WalletModel::forwardPropose - Premium object: units=%d, payer=%s, payee_dest=%s, asset_id=%s, is_native=%d\n",
                      static_cast<int64_t>(premiumUnits),
                      terms["premium_payer"].toString().toStdString().c_str(),
                      terms["premium_dest"].toString().toStdString().c_str(),
                      premiumAssetId.toStdString().c_str(),
                      premiumIsNative);

            termsObj.pushKV("premium", premium);
        }

        // Deadlines
        termsObj.pushKV("deadline_short", terms["deadline_short"].toInt());
        termsObj.pushKV("deadline_long", terms["deadline_long"].toInt());
        termsObj.pushKV("safety_k", terms["safety_k"].toInt());

        params.push_back(termsObj);

        UniValue response = m_client_model->node().executeRpc("forward.propose", params, getWalletName().toStdString());

        result.success = true;
        result.offer_id = QString::fromStdString(response["offer_id"].get_str());
        result.offer_json = QString::fromStdString(response["offer"].write());

        // Store offer data for later use
        result.offer_data["offer_id"] = result.offer_id;
        result.offer_data["offer_json"] = result.offer_json;

    } catch (const UniValue& e) {
        result.success = false;
        result.error = tr("RPC error: %1").arg(QString::fromStdString(e.write()));
    } catch (const std::exception& e) {
        result.success = false;
        result.error = tr("RPC error: %1").arg(QString::fromStdString(e.what()));
    } catch (...) {
        result.success = false;
        result.error = tr("Unknown error occurred");
    }

    return result;
}

WalletModel::ForwardImportOfferResult WalletModel::forwardImportOffer(const QString& offer_json)
{
    ForwardImportOfferResult result;

    if (!m_client_model) {
        result.error = tr("Client model not available");
        return result;
    }

    try {
        UniValue params(UniValue::VARR);

        // Parse JSON string to UniValue
        UniValue offerVal;
        if (!offerVal.read(offer_json.toStdString())) {
            result.error = tr("Invalid JSON format");
            return result;
        }

        params.push_back(offerVal);

        UniValue response = m_client_model->node().executeRpc("forward.import_offer", params, getWalletName().toStdString());

        result.success = true;
        result.offer_id = QString::fromStdString(response["offer_id"].get_str());

    } catch (const UniValue& e) {
        result.success = false;
        result.error = tr("RPC error: %1").arg(QString::fromStdString(e.write()));
    } catch (const std::exception& e) {
        result.success = false;
        result.error = tr("RPC error: %1").arg(QString::fromStdString(e.what()));
    } catch (...) {
        result.success = false;
        result.error = tr("Unknown error occurred");
    }

    return result;
}

WalletModel::ForwardAcceptResult WalletModel::forwardAccept(const QString& offer_id, bool confirmed)
{
    ForwardAcceptResult result;

    if (!m_client_model) {
        result.error = "Client model not available";
        return result;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(offer_id.toStdString());

        UniValue options(UniValue::VOBJ);
        options.pushKV("confirmed", confirmed);
        params.push_back(options);

        UniValue response = m_client_model->node().executeRpc("forward.accept", params, getWalletName().toStdString());

        result.success = true;
        if (response.exists("acceptance_id")) {
            result.acceptance_id = QString::fromStdString(response["acceptance_id"].get_str());
        }
        if (response.exists("acceptance_json")) {
            result.acceptance_json = QString::fromStdString(response["acceptance_json"].get_str());
        }
        // Extract the "acceptance" object (matching functional test pattern)
        if (response.exists("acceptance")) {
            const UniValue& acceptanceObj = response["acceptance"];
            result.acceptance_obj_json = QString::fromStdString(acceptanceObj.write());
        }
        if (response.exists("acceptance_data")) {
            // Convert UniValue object to QVariantMap
            const UniValue& dataObj = response["acceptance_data"];
            // Simplified: in production, recursively convert UniValue to QVariant
            result.acceptance_data["raw"] = QString::fromStdString(dataObj.write());
        }

    } catch (const UniValue& e) {
        result.success = false;
        result.error = "RPC error: " + QString::fromStdString(e.write());
    } catch (const std::exception& e) {
        result.success = false;
        result.error = QString::fromStdString(e.what());
    } catch (...) {
        result.success = false;
        result.error = "Unknown exception occurred";
    }

    return result;
}

WalletModel::ForwardImportAcceptanceResult WalletModel::forwardImportAcceptance(const QString& acceptance_json)
{
    ForwardImportAcceptanceResult result;

    if (!m_client_model) {
        result.error = "Client model not available";
        return result;
    }

    try {
        UniValue params(UniValue::VARR);

        // Parse JSON string to UniValue object (RPC expects object, not string)
        UniValue acceptanceVal;
        if (!acceptanceVal.read(acceptance_json.toStdString())) {
            result.error = "Invalid JSON format";
            return result;
        }

        params.push_back(acceptanceVal);

        UniValue response = m_client_model->node().executeRpc("forward.import_acceptance", params, getWalletName().toStdString());

        result.success = true;
        if (response.exists("acceptance_id")) {
            result.acceptance_id = QString::fromStdString(response["acceptance_id"].get_str());
        }

    } catch (const UniValue& e) {
        result.success = false;
        result.error = "RPC error: " + QString::fromStdString(e.write());
    } catch (const std::exception& e) {
        result.success = false;
        result.error = QString::fromStdString(e.what());
    } catch (...) {
        result.success = false;
        result.error = "Unknown exception occurred";
    }

    return result;
}

// ============================================================================
// Difficulty-derivative RPC Wrappers (CFD + option)
// ============================================================================

// Parse a PSBT-shaped difficulty RPC response into the shared result struct. Fields are parsed best-effort:
// each builder returns the subset that applies to it (build_open: leg/vault_index; build_open_option: role;
// build_settlement: payout_owner/payout_cp/vault_input_index; sign_coop/finalize_settlement: hex/complete).
static void ParseDifficultyPsbt(const UniValue& r, WalletModel::DifficultyPsbtResult& res)
{
    res.success = true;
    if (r.exists("psbt") && r["psbt"].isStr()) res.psbt = QString::fromStdString(r["psbt"].get_str());
    if (r.exists("hex") && r["hex"].isStr()) res.hex = QString::fromStdString(r["hex"].get_str());
    if (r.exists("complete") && r["complete"].isBool()) res.complete = r["complete"].get_bool();
    if (r.exists("leg") && r["leg"].isStr()) res.leg = QString::fromStdString(r["leg"].get_str());
    if (r.exists("role") && r["role"].isStr()) res.role = QString::fromStdString(r["role"].get_str());
    if (r.exists("fee")) res.fee = r["fee"].get_real();
    if (r.exists("vault_index")) res.vault_index = r["vault_index"].getInt<int>();
    if (r.exists("vault_input_index")) res.vault_input_index = r["vault_input_index"].getInt<int>();
    if (r.exists("payout_owner")) res.payout_owner = r["payout_owner"].get_real();
    if (r.exists("payout_cp")) res.payout_cp = r["payout_cp"].get_real();
}

WalletModel::DifficultyProposeResult WalletModel::difficultyPropose(const QVariantMap& econ, const QString& role,
                                                                    const QString& owner_addr, const QString& cp_addr)
{
    DifficultyProposeResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }
    try {
        UniValue terms(UniValue::VOBJ);
        terms.pushKV("strike_nbits", UniValue(static_cast<int64_t>(econ.value("strike_nbits").toULongLong())));
        terms.pushKV("fixing_height", UniValue(static_cast<int64_t>(econ.value("fixing_height").toULongLong())));
        terms.pushKV("settle_lock_height", UniValue(static_cast<int64_t>(econ.value("settle_lock_height").toULongLong())));
        UniValue longLeg(UniValue::VOBJ);
        longLeg.pushKV("im", UniValue(econ.value("long_im").toDouble()));
        longLeg.pushKV("lambda_q", UniValue(static_cast<int64_t>(econ.value("long_lambda_q").toULongLong())));
        UniValue shortLeg(UniValue::VOBJ);
        shortLeg.pushKV("im", UniValue(econ.value("short_im").toDouble()));
        shortLeg.pushKV("lambda_q", UniValue(static_cast<int64_t>(econ.value("short_lambda_q").toULongLong())));
        terms.pushKV("long", longLeg);
        terms.pushKV("short", shortLeg);

        UniValue params(UniValue::VARR);
        params.push_back(terms);
        params.push_back(role.toStdString());
        params.push_back(owner_addr.toStdString());
        params.push_back(cp_addr.toStdString());

        UniValue response = m_client_model->node().executeRpc("difficulty.propose", params, getWalletName().toStdString());
        result.success = true;
        if (response.exists("offer")) result.offer_json = QString::fromStdString(response["offer"].write());
    } catch (const UniValue& e) {
        result.error = tr("RPC error: %1").arg(QString::fromStdString(e.write()));
    } catch (const std::exception& e) {
        result.error = tr("RPC error: %1").arg(QString::fromStdString(e.what()));
    } catch (...) {
        result.error = tr("Unknown error occurred");
    }
    return result;
}

WalletModel::DifficultyProposeResult WalletModel::difficultyProposeOption(const QVariantMap& econ, const QString& role,
                                                                          const QString& payout_addr)
{
    DifficultyProposeResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }
    try {
        UniValue terms(UniValue::VOBJ);
        terms.pushKV("strike_nbits", UniValue(static_cast<int64_t>(econ.value("strike_nbits").toULongLong())));
        terms.pushKV("fixing_height", UniValue(static_cast<int64_t>(econ.value("fixing_height").toULongLong())));
        terms.pushKV("settle_lock_height", UniValue(static_cast<int64_t>(econ.value("settle_lock_height").toULongLong())));
        terms.pushKV("im", UniValue(econ.value("im").toDouble()));
        terms.pushKV("lambda_q", UniValue(static_cast<int64_t>(econ.value("lambda_q").toULongLong())));
        terms.pushKV("premium", UniValue(econ.value("premium").toDouble()));

        UniValue params(UniValue::VARR);
        params.push_back(terms);
        params.push_back(econ.value("writer_side").toString().toStdString());
        params.push_back(role.toStdString());
        params.push_back(payout_addr.toStdString());

        UniValue response = m_client_model->node().executeRpc("difficulty.propose_option", params, getWalletName().toStdString());
        result.success = true;
        if (response.exists("offer")) result.offer_json = QString::fromStdString(response["offer"].write());
    } catch (const UniValue& e) {
        result.error = tr("RPC error: %1").arg(QString::fromStdString(e.write()));
    } catch (const std::exception& e) {
        result.error = tr("RPC error: %1").arg(QString::fromStdString(e.what()));
    } catch (...) {
        result.error = tr("Unknown error occurred");
    }
    return result;
}

WalletModel::DifficultyAcceptResult WalletModel::difficultyAccept(const QString& offer_json, const QString& owner_addr,
                                                                  const QString& cp_addr, bool confirmed)
{
    DifficultyAcceptResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }
    try {
        UniValue offerVal;
        if (!offerVal.read(offer_json.toStdString())) { result.error = tr("Invalid offer JSON"); return result; }

        UniValue params(UniValue::VARR);
        params.push_back(offerVal);
        params.push_back(owner_addr.toStdString());
        params.push_back(cp_addr.toStdString());
        UniValue options(UniValue::VOBJ);
        options.pushKV("confirmed", confirmed);
        params.push_back(options);

        UniValue response = m_client_model->node().executeRpc("difficulty.accept", params, getWalletName().toStdString());
        result.success = true;
        result.confirmed = confirmed;
        if (response.exists("contract_id")) result.contract_id = QString::fromStdString(response["contract_id"].get_str());
        if (response.exists("acceptance")) result.acceptance_json = QString::fromStdString(response["acceptance"].write());
        if (response.exists("action_required")) result.action_required = QString::fromStdString(response["action_required"].get_str());
    } catch (const UniValue& e) {
        result.error = tr("RPC error: %1").arg(QString::fromStdString(e.write()));
    } catch (const std::exception& e) {
        result.error = tr("RPC error: %1").arg(QString::fromStdString(e.what()));
    } catch (...) {
        result.error = tr("Unknown error occurred");
    }
    return result;
}

WalletModel::DifficultyAcceptResult WalletModel::difficultyAcceptOption(const QString& offer_json,
                                                                        const QString& payout_addr, bool confirmed)
{
    DifficultyAcceptResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }
    try {
        UniValue offerVal;
        if (!offerVal.read(offer_json.toStdString())) { result.error = tr("Invalid offer JSON"); return result; }

        UniValue params(UniValue::VARR);
        params.push_back(offerVal);
        params.push_back(payout_addr.toStdString());
        UniValue options(UniValue::VOBJ);
        options.pushKV("confirmed", confirmed);
        params.push_back(options);

        UniValue response = m_client_model->node().executeRpc("difficulty.accept_option", params, getWalletName().toStdString());
        result.success = true;
        result.confirmed = confirmed;
        if (response.exists("contract_id")) result.contract_id = QString::fromStdString(response["contract_id"].get_str());
        if (response.exists("acceptance")) result.acceptance_json = QString::fromStdString(response["acceptance"].write());
        if (response.exists("action_required")) result.action_required = QString::fromStdString(response["action_required"].get_str());
    } catch (const UniValue& e) {
        result.error = tr("RPC error: %1").arg(QString::fromStdString(e.write()));
    } catch (const std::exception& e) {
        result.error = tr("RPC error: %1").arg(QString::fromStdString(e.what()));
    } catch (...) {
        result.error = tr("Unknown error occurred");
    }
    return result;
}

WalletModel::DifficultyImportResult WalletModel::difficultyImportAcceptance(const QString& offer_json,
                                                                            const QString& acceptance_json)
{
    DifficultyImportResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }
    try {
        UniValue offerVal, acceptanceVal;
        if (!offerVal.read(offer_json.toStdString())) { result.error = tr("Invalid offer JSON"); return result; }
        if (!acceptanceVal.read(acceptance_json.toStdString())) { result.error = tr("Invalid acceptance JSON"); return result; }

        UniValue params(UniValue::VARR);
        params.push_back(offerVal);
        params.push_back(acceptanceVal);

        UniValue response = m_client_model->node().executeRpc("difficulty.import_acceptance", params, getWalletName().toStdString());
        result.success = true;
        if (response.exists("contract_id")) result.contract_id = QString::fromStdString(response["contract_id"].get_str());
        if (response.exists("state")) result.state = QString::fromStdString(response["state"].get_str());
    } catch (const UniValue& e) {
        result.error = tr("RPC error: %1").arg(QString::fromStdString(e.write()));
    } catch (const std::exception& e) {
        result.error = tr("RPC error: %1").arg(QString::fromStdString(e.what()));
    } catch (...) {
        result.error = tr("Unknown error occurred");
    }
    return result;
}

WalletModel::DifficultyPsbtResult WalletModel::difficultyBuildOpen(const QString& contract_id, const QString& leg,
                                                                   const QString& partial_psbt, double fee_rate)
{
    DifficultyPsbtResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }
    try {
        UniValue params(UniValue::VARR);
        params.push_back(contract_id.toStdString());
        params.push_back(leg.toStdString());
        UniValue options(UniValue::VOBJ);
        if (!partial_psbt.isEmpty()) options.pushKV("psbt", partial_psbt.toStdString());
        if (fee_rate > 0.0) options.pushKV("fee_rate", UniValue(fee_rate));
        if (!options.empty()) params.push_back(options);
        UniValue response = m_client_model->node().executeRpc("difficulty.build_open", params, getWalletName().toStdString());
        ParseDifficultyPsbt(response, result);
    } catch (const UniValue& e) {
        result.error = tr("RPC error: %1").arg(QString::fromStdString(e.write()));
    } catch (const std::exception& e) {
        result.error = tr("RPC error: %1").arg(QString::fromStdString(e.what()));
    } catch (...) {
        result.error = tr("Unknown error occurred");
    }
    return result;
}

WalletModel::DifficultyPsbtResult WalletModel::difficultyBuildOpenOption(const QString& contract_id, const QString& role,
                                                                         const QString& partial_psbt, double fee_rate)
{
    DifficultyPsbtResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }
    try {
        UniValue params(UniValue::VARR);
        params.push_back(contract_id.toStdString());
        params.push_back(role.toStdString());
        UniValue options(UniValue::VOBJ);
        if (!partial_psbt.isEmpty()) options.pushKV("psbt", partial_psbt.toStdString());
        if (fee_rate > 0.0) options.pushKV("fee_rate", UniValue(fee_rate));
        if (!options.empty()) params.push_back(options);
        UniValue response = m_client_model->node().executeRpc("difficulty.build_open_option", params, getWalletName().toStdString());
        ParseDifficultyPsbt(response, result);
    } catch (const UniValue& e) {
        result.error = tr("RPC error: %1").arg(QString::fromStdString(e.write()));
    } catch (const std::exception& e) {
        result.error = tr("RPC error: %1").arg(QString::fromStdString(e.what()));
    } catch (...) {
        result.error = tr("Unknown error occurred");
    }
    return result;
}

WalletModel::DifficultyRecordOpenResult WalletModel::difficultyRecordOpen(const QString& contract_id,
                                                                          const QString& open_txid)
{
    DifficultyRecordOpenResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }
    try {
        UniValue params(UniValue::VARR);
        params.push_back(contract_id.toStdString());
        params.push_back(open_txid.toStdString());
        m_client_model->node().executeRpc("difficulty.record_open", params, getWalletName().toStdString());
        result.success = true;
    } catch (const UniValue& e) {
        result.error = tr("RPC error: %1").arg(QString::fromStdString(e.write()));
    } catch (const std::exception& e) {
        result.error = tr("RPC error: %1").arg(QString::fromStdString(e.what()));
    } catch (...) {
        result.error = tr("Unknown error occurred");
    }
    return result;
}

WalletModel::DifficultyPsbtResult WalletModel::difficultyBuildSettlement(const QString& contract_id, const QString& leg,
                                                                         double fee_rate)
{
    DifficultyPsbtResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }
    try {
        UniValue params(UniValue::VARR);
        params.push_back(contract_id.toStdString());
        params.push_back(leg.toStdString());
        if (fee_rate > 0.0) {
            UniValue options(UniValue::VOBJ);
            options.pushKV("fee_rate", UniValue(fee_rate));
            params.push_back(options);
        }
        UniValue response = m_client_model->node().executeRpc("difficulty.build_settlement", params, getWalletName().toStdString());
        ParseDifficultyPsbt(response, result);
    } catch (const UniValue& e) {
        result.error = tr("RPC error: %1").arg(QString::fromStdString(e.write()));
    } catch (const std::exception& e) {
        result.error = tr("RPC error: %1").arg(QString::fromStdString(e.what()));
    } catch (...) {
        result.error = tr("Unknown error occurred");
    }
    return result;
}

WalletModel::DifficultyPsbtResult WalletModel::difficultyFinalizeSettlement(const QString& psbt)
{
    DifficultyPsbtResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }
    try {
        UniValue params(UniValue::VARR);
        params.push_back(psbt.toStdString());
        UniValue response = m_client_model->node().executeRpc("difficulty.finalize_settlement", params, getWalletName().toStdString());
        ParseDifficultyPsbt(response, result);
    } catch (const UniValue& e) {
        result.error = tr("RPC error: %1").arg(QString::fromStdString(e.write()));
    } catch (const std::exception& e) {
        result.error = tr("RPC error: %1").arg(QString::fromStdString(e.what()));
    } catch (...) {
        result.error = tr("Unknown error occurred");
    }
    return result;
}

WalletModel::DifficultyPsbtResult WalletModel::difficultyBuildCoopClose(const QString& contract_id, const QString& leg,
                                                                        const QVariantList& outputs)
{
    DifficultyPsbtResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }
    try {
        UniValue outs(UniValue::VARR);
        for (const QVariant& ov : outputs) {
            const QVariantMap om = ov.toMap();
            UniValue o(UniValue::VOBJ);
            o.pushKV("address", om.value("address").toString().toStdString());
            o.pushKV("amount", UniValue(om.value("amount").toDouble()));
            outs.push_back(o);
        }
        UniValue params(UniValue::VARR);
        params.push_back(contract_id.toStdString());
        params.push_back(leg.toStdString());
        params.push_back(outs);
        UniValue response = m_client_model->node().executeRpc("difficulty.build_coop_close", params, getWalletName().toStdString());
        ParseDifficultyPsbt(response, result);
    } catch (const UniValue& e) {
        result.error = tr("RPC error: %1").arg(QString::fromStdString(e.write()));
    } catch (const std::exception& e) {
        result.error = tr("RPC error: %1").arg(QString::fromStdString(e.what()));
    } catch (...) {
        result.error = tr("Unknown error occurred");
    }
    return result;
}

WalletModel::DifficultyPsbtResult WalletModel::difficultySignCoop(const QString& contract_id, const QString& leg,
                                                                  const QString& psbt)
{
    DifficultyPsbtResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }

    // sign_coop produces a Schnorr signature with this wallet's payout key, so the wallet must be unlocked
    // (mirrors walletProcessPsbt(sign=true)).
    WalletModel::UnlockContext ctx(requestUnlock());
    if (!ctx.isValid()) {
        result.error = tr("Wallet unlock required to sign the cooperative close");
        return result;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(contract_id.toStdString());
        params.push_back(leg.toStdString());
        params.push_back(psbt.toStdString());
        UniValue response = m_client_model->node().executeRpc("difficulty.sign_coop", params, getWalletName().toStdString());
        ParseDifficultyPsbt(response, result);
    } catch (const UniValue& e) {
        result.error = tr("RPC error: %1").arg(QString::fromStdString(e.write()));
    } catch (const std::exception& e) {
        result.error = tr("RPC error: %1").arg(QString::fromStdString(e.what()));
    } catch (...) {
        result.error = tr("Unknown error occurred");
    }
    return result;
}

WalletModel::DifficultyChainDefaults WalletModel::difficultyChainDefaults()
{
    DifficultyChainDefaults result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }
    try {
        UniValue params(UniValue::VARR);
        UniValue response = m_client_model->node().executeRpc("getblockchaininfo", params, /*walletName=*/"");
        if (response.exists("blocks")) result.height = response["blocks"].getInt<int>();
        if (response.exists("bits") && response["bits"].isStr()) {
            result.strike_nbits = QString::fromStdString(response["bits"].get_str());
        }
        result.success = true;
    } catch (const UniValue& e) {
        result.error = tr("RPC error: %1").arg(QString::fromStdString(e.write()));
    } catch (const std::exception& e) {
        result.error = tr("RPC error: %1").arg(QString::fromStdString(e.what()));
    } catch (...) {
        result.error = tr("Unknown error occurred");
    }
    return result;
}

// ============================================================================
// Option-series (tokenized option) RPC Wrappers
// ============================================================================

// Format an exact sat amount as a canonical 8-decimal string ("1.50000000"). The RPC parses lot_im /
// reference_premium with AmountFromValue, which reads this string exactly — so the descriptor bytes (and
// thus the asset_id) are derived from the user's exact amount, with no floating-point round-trip.
static std::string SatsToAmountStr(qint64 sats)
{
    char buf[32];
    snprintf(buf, sizeof(buf), "%lld.%08lld",
             static_cast<long long>(sats / 100000000LL), static_cast<long long>(sats % 100000000LL));
    return std::string(buf);
}

// Convert optionseries.verify's decoded `terms` (display shape: lot_im_sats / reference_premium_sats) into
// the shape ParseOptionSeriesTermsFromJson accepts (lot_im / reference_premium as decimals), so a holder
// who has no wallet record can drive build_redeem from the on-chain descriptor. writer_key / series_salt are
// natural-order hex in both shapes (they round-trip as-is).
static UniValue DisplayTermsToParseTerms(const UniValue& dt)
{
    UniValue t(UniValue::VOBJ);
    for (const char* k : {"descriptor_version", "issuance_mode", "leaf_set", "writer_key", "strike_nbits",
                          "fixing_height", "settle_lock_height", "lambda_q", "lot_count", "series_salt",
                          "direction"}) {
        if (dt.exists(k)) t.pushKV(k, dt[k]);
    }
    if (dt.exists("lot_im_sats")) t.pushKV("lot_im", SatsToAmountStr(dt["lot_im_sats"].getInt<int64_t>()));
    if (dt.exists("reference_premium_sats")) t.pushKV("reference_premium", SatsToAmountStr(dt["reference_premium_sats"].getInt<int64_t>()));
    return t;
}

// Build the `terms` object shared by optionseries.derive/build_register/build_issue/record_issue. Heights
// and nBits/lambda are integers; lot_im/reference_premium are emitted as exact decimal strings (NOT doubles).
// A blank/short salt is rejected by the dialog before reaching here.
static UniValue OptionSeriesTermsToUni(const WalletModel::OptionSeriesTermsInput& t)
{
    UniValue terms(UniValue::VOBJ);
    // The GUI always creates descriptor v2 (so it can carry the call/put direction); v1 (call-only) stays
    // valid for externally-authored series.
    terms.pushKV("descriptor_version", static_cast<int64_t>(2));
    terms.pushKV("direction", static_cast<int64_t>(t.direction));
    terms.pushKV("writer_key", t.writer_key.toStdString());
    terms.pushKV("strike_nbits", static_cast<int64_t>(t.strike_nbits));
    terms.pushKV("fixing_height", static_cast<int64_t>(t.fixing_height));
    terms.pushKV("settle_lock_height", static_cast<int64_t>(t.settle_lock_height));
    terms.pushKV("lambda_q", static_cast<int64_t>(t.lambda_q));
    terms.pushKV("lot_im", SatsToAmountStr(t.lot_im_sats));
    terms.pushKV("lot_count", static_cast<int64_t>(t.lot_count));
    terms.pushKV("reference_premium", SatsToAmountStr(t.reference_premium_sats));
    terms.pushKV("series_salt", t.series_salt.toStdString());
    return terms;
}

WalletModel::OptionSeriesDeriveResult WalletModel::optionSeriesDerive(const OptionSeriesTermsInput& termsIn)
{
    OptionSeriesDeriveResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }
    try {
        UniValue params(UniValue::VARR);
        params.push_back(OptionSeriesTermsToUni(termsIn));
        // derive is a read-only core RPC; no wallet needed (pass the wallet name harmlessly for routing).
        UniValue r = m_client_model->node().executeRpc("optionseries.derive", params, getWalletName().toStdString());
        result.success = true;
        if (r.exists("asset_id")) result.asset_id = QString::fromStdString(r["asset_id"].get_str());
        if (r.exists("registry_asset_id")) result.registry_asset_id = QString::fromStdString(r["registry_asset_id"].get_str());
        if (r.exists("descriptor")) result.descriptor = QString::fromStdString(r["descriptor"].get_str());
        if (r.exists("lot_count")) result.lot_count = r["lot_count"].getInt<int>();
    } catch (const UniValue& e) {
        result.error = QString::fromStdString(e.isObject() && e.exists("message") ? e["message"].get_str() : e.write());
    } catch (const std::exception& e) {
        result.error = QString::fromStdString(e.what());
    } catch (...) {
        result.error = tr("Unknown error occurred");
    }
    return result;
}

WalletModel::OptionSeriesRegisterResult WalletModel::optionSeriesBuildRegister(const OptionSeriesTermsInput& termsIn,
                                                                               const QString& root, const QString& suffix,
                                                                               qint64 child_bond_sats, double fee_rate, bool broadcast)
{
    OptionSeriesRegisterResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }
    try {
        UniValue options(UniValue::VOBJ);
        options.pushKV("broadcast", broadcast);
        if (fee_rate > 0.0) options.pushKV("fee_rate", UniValue(fee_rate));
        if (child_bond_sats > 0) options.pushKV("child_bond_sats", static_cast<int64_t>(child_bond_sats));

        UniValue params(UniValue::VARR);
        params.push_back(OptionSeriesTermsToUni(termsIn));
        params.push_back(root.toStdString());
        params.push_back(suffix.toStdString());
        params.push_back(options);

        UniValue r = m_client_model->node().executeRpc("optionseries.build_register", params, getWalletName().toStdString());
        result.success = true;
        if (r.exists("asset_id")) result.asset_id = QString::fromStdString(r["asset_id"].get_str());
        if (r.exists("registry_asset_id")) result.registry_asset_id = QString::fromStdString(r["registry_asset_id"].get_str());
        if (r.exists("ticker")) result.ticker = QString::fromStdString(r["ticker"].get_str());
        if (r.exists("icu_text")) result.icu_text = QString::fromStdString(r["icu_text"].get_str());
        if (r.exists("lot_count")) result.lot_count = r["lot_count"].getInt<int>();
        if (r.exists("registration") && r["registration"].isObject() && r["registration"].exists("txid")) {
            result.txid = QString::fromStdString(r["registration"]["txid"].get_str());
        } else {
            result.txid = tr("(pending)");
        }
    } catch (const UniValue& e) {
        result.error = QString::fromStdString(e.isObject() && e.exists("message") ? e["message"].get_str() : e.write());
    } catch (const std::exception& e) {
        result.error = QString::fromStdString(e.what());
    } catch (...) {
        result.error = tr("Unknown error occurred");
    }
    return result;
}

WalletModel::OptionSeriesIssueResult WalletModel::optionSeriesBuildIssue(const OptionSeriesTermsInput& termsIn,
                                                                         double fee_rate, bool broadcast)
{
    OptionSeriesIssueResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }
    try {
        UniValue options(UniValue::VOBJ);
        options.pushKV("broadcast", broadcast);
        if (fee_rate > 0.0) options.pushKV("fee_rate", UniValue(fee_rate));

        UniValue params(UniValue::VARR);
        params.push_back(OptionSeriesTermsToUni(termsIn));
        params.push_back(options);

        UniValue r = m_client_model->node().executeRpc("optionseries.build_issue", params, getWalletName().toStdString());
        result.success = true;
        if (r.exists("asset_id")) result.asset_id = QString::fromStdString(r["asset_id"].get_str());
        if (r.exists("registry_asset_id")) result.registry_asset_id = QString::fromStdString(r["registry_asset_id"].get_str());
        if (r.exists("lot_count")) result.lot_count = r["lot_count"].getInt<int>();
        if (r.exists("per_lot_im_sats")) result.per_lot_im = r["per_lot_im_sats"].getInt<int64_t>() / 100000000.0;
        if (r.exists("mint") && r["mint"].isObject() && r["mint"].exists("txid")) {
            result.txid = QString::fromStdString(r["mint"]["txid"].get_str());
        } else if (r.exists("mint") && r["mint"].isStr()) {
            result.txid = QString::fromStdString(r["mint"].get_str());
        }
    } catch (const UniValue& e) {
        result.error = QString::fromStdString(e.isObject() && e.exists("message") ? e["message"].get_str() : e.write());
    } catch (const std::exception& e) {
        result.error = QString::fromStdString(e.what());
    } catch (...) {
        result.error = tr("Unknown error occurred");
    }
    return result;
}

WalletModel::OptionSeriesRecordResult WalletModel::optionSeriesRecordIssue(const OptionSeriesTermsInput& termsIn,
                                                                           const QString& issue_txid)
{
    OptionSeriesRecordResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }
    try {
        UniValue params(UniValue::VARR);
        params.push_back(OptionSeriesTermsToUni(termsIn));
        params.push_back(issue_txid.toStdString());

        UniValue r = m_client_model->node().executeRpc("optionseries.record_issue", params, getWalletName().toStdString());
        result.success = true;
        if (r.exists("asset_id")) result.asset_id = QString::fromStdString(r["asset_id"].get_str());
        if (r.exists("lot_count")) result.lot_count = r["lot_count"].getInt<int>();
        if (r.exists("persisted")) result.persisted = r["persisted"].get_bool();
    } catch (const UniValue& e) {
        result.error = QString::fromStdString(e.isObject() && e.exists("message") ? e["message"].get_str() : e.write());
    } catch (const std::exception& e) {
        result.error = QString::fromStdString(e.what());
    } catch (...) {
        result.error = tr("Unknown error occurred");
    }
    return result;
}

WalletModel::OptionSeriesListResult WalletModel::optionSeriesList()
{
    OptionSeriesListResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }
    try {
        UniValue params(UniValue::VARR);
        UniValue r = m_client_model->node().executeRpc("optionseries.list", params, getWalletName().toStdString());
        result.success = true;
        if (r.isArray()) {
            for (size_t i = 0; i < r.size(); ++i) {
                const UniValue& o = r[i];
                OptionSeriesListEntry e;
                if (o.exists("asset_id")) e.asset_id = QString::fromStdString(o["asset_id"].get_str());
                if (o.exists("registry_asset_id")) e.registry_asset_id = QString::fromStdString(o["registry_asset_id"].get_str());
                if (o.exists("lot_count")) e.lot_count = o["lot_count"].getInt<int>();
                if (o.exists("issue_txid")) e.issue_txid = QString::fromStdString(o["issue_txid"].get_str());
                if (o.exists("icu_outpoint")) e.icu_outpoint = QString::fromStdString(o["icu_outpoint"].get_str());
                if (o.exists("lot_vaults") && o["lot_vaults"].isArray()) e.vault_count = static_cast<int>(o["lot_vaults"].size());
                if (o.exists("terms") && o["terms"].isObject()) e.terms_json = QString::fromStdString(o["terms"].write());
                result.series.append(e);
            }
        }
    } catch (const UniValue& e) {
        result.error = QString::fromStdString(e.isObject() && e.exists("message") ? e["message"].get_str() : e.write());
    } catch (const std::exception& e) {
        result.error = QString::fromStdString(e.what());
    } catch (...) {
        result.error = tr("Unknown error occurred");
    }
    return result;
}

WalletModel::OptionSeriesBackingResult WalletModel::optionSeriesVerifyBacking(const QString& registry_asset_id, const QString& asset_id)
{
    OptionSeriesBackingResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }
    try {
        // Fetch the published ICU metadata band (the committed descriptor) to verify against on chain.
        UniValue gp(UniValue::VARR);
        gp.push_back(registry_asset_id.toStdString());
        UniValue icu = m_client_model->node().executeRpc("geticupayload", gp, getWalletName().toStdString());
        if (!icu.exists("metadata") || !icu["metadata"].isStr() || icu["metadata"].get_str().empty()) {
            result.error = tr("Series ICU has no published metadata band to verify against");
            return result;
        }

        UniValue source(UniValue::VOBJ);
        source.pushKV("icu_metadata", icu["metadata"].get_str());
        UniValue options(UniValue::VOBJ);
        options.pushKV("check_backing", true);
        UniValue params(UniValue::VARR);
        params.push_back(asset_id.toStdString());
        params.push_back(source);
        params.push_back(options);

        UniValue r = m_client_model->node().executeRpc("optionseries.verify", params, getWalletName().toStdString());
        result.success = true;
        if (r.exists("authentic")) result.authentic = r["authentic"].get_bool();
        if (r.exists("reason") && r["reason"].isStr()) result.reason = QString::fromStdString(r["reason"].get_str());
        // Recover parser-compatible terms from the on-chain descriptor so a holder can redeem with no record.
        if (r.exists("terms") && r["terms"].isObject()) {
            const UniValue parse_terms = DisplayTermsToParseTerms(r["terms"]);
            result.terms_json = QString::fromStdString(parse_terms.write());
            if (parse_terms.exists("lot_count")) result.lot_count = parse_terms["lot_count"].getInt<int>();
        }
        if (r.exists("backing") && r["backing"].isObject() && r["backing"].exists("on_chain")) {
            const UniValue& oc = r["backing"]["on_chain"];
            if (oc.exists("registered")) result.registered = oc["registered"].get_bool();
            if (oc.exists("issued_total")) result.issued_total = oc["issued_total"].getInt<int64_t>();
            if (oc.exists("invariants_ok")) result.invariants_ok = oc["invariants_ok"].get_bool();
            if (oc.exists("vaults_funded")) result.vaults_funded = oc["vaults_funded"].getInt<int>();
            if (oc.exists("vaults_expected")) result.vaults_expected = oc["vaults_expected"].getInt<int>();
            if (oc.exists("verified")) result.verified = oc["verified"].get_bool();
        }
    } catch (const UniValue& e) {
        result.error = QString::fromStdString(e.isObject() && e.exists("message") ? e["message"].get_str() : e.write());
    } catch (const std::exception& e) {
        result.error = QString::fromStdString(e.what());
    } catch (...) {
        result.error = tr("Unknown error occurred");
    }
    return result;
}

WalletModel::OptionSeriesBackingResult WalletModel::optionSeriesVerifyById(const QString& identifier)
{
    OptionSeriesBackingResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }
    const QString ident = identifier.trimmed();
    if (ident.isEmpty()) { result.error = tr("Enter a ticker or asset id"); return result; }
    try {
        const std::string wname = getWalletName().toStdString();
        // Resolve a ticker OR an asset id to the registry/display asset_id. getassetinfo speaks the registry
        // hex; the CANONICAL option id is its byte-reverse, so if a 64-hex input fails, retry reversed — a
        // buyer may have copied EITHER id (derive/verify return the canonical asset_id, getassetinfo the registry).
        QString registry_id, ticker;
        auto tryResolve = [&](const QString& id) -> bool {
            try {
                UniValue gi(UniValue::VARR);
                gi.push_back(id.toStdString());
                UniValue info = m_client_model->node().executeRpc("getassetinfo", gi, wname);
                if (!info.exists("asset_id")) return false;
                registry_id = QString::fromStdString(info["asset_id"].get_str());
                if (info.exists("ticker") && info["ticker"].isStr()) ticker = QString::fromStdString(info["ticker"].get_str());
                return true;
            } catch (...) { return false; }
        };

        bool resolved = tryResolve(ident);
        if (!resolved) {
            const QString s = ident.toLower();
            bool hex64 = s.size() == 64;
            for (const QChar& c : s) { if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) { hex64 = false; break; } }
            if (hex64) {
                QString rev;
                for (int i = s.size() - 2; i >= 0; i -= 2) rev += s.mid(i, 2);  // canonical -> registry byte order
                resolved = tryResolve(rev);
            }
        }
        if (!resolved) {
            result.error = tr("Unknown series '%1' (try the ticker, or the registry/option asset id)").arg(ident);
            return result;
        }

        // Same fraud-check flow as the recorded-series path, but against an arbitrary published series.
        OptionSeriesBackingResult vb = optionSeriesVerifyBacking(registry_id, registry_id);
        vb.resolved_asset_id = registry_id;
        vb.ticker = ticker;
        return vb;
    } catch (const UniValue& e) {
        result.error = QString::fromStdString(e.isObject() && e.exists("message") ? e["message"].get_str() : e.write());
    } catch (const std::exception& e) {
        result.error = QString::fromStdString(e.what());
    } catch (...) {
        result.error = tr("Unknown error occurred");
    }
    return result;
}

WalletModel::OptionSeriesActionResult WalletModel::optionSeriesSettle(const QString& terms_json, int lot_index, double fee_rate)
{
    OptionSeriesActionResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }
    try {
        UniValue terms;
        if (!terms.read(terms_json.toStdString())) { result.error = tr("Invalid series terms"); return result; }
        const std::string wname = getWalletName().toStdString();

        // 1) Build the settlement PSBT (vault input finalized; fee input to be signed). The RPC enforces
        //    fixing burial + an open CLTV; a too-early call throws here and we surface it.
        UniValue bopts(UniValue::VOBJ);
        if (fee_rate > 0.0) bopts.pushKV("fee_rate", UniValue(fee_rate));
        UniValue bparams(UniValue::VARR);
        bparams.push_back(terms);
        bparams.push_back(static_cast<int64_t>(lot_index));
        bparams.push_back(bopts);
        UniValue built = m_client_model->node().executeRpc("optionseries.build_settlement", bparams, wname);
        const QString psbt = built.exists("psbt") ? QString::fromStdString(built["psbt"].get_str()) : QString();
        if (psbt.isEmpty()) { result.error = tr("build_settlement returned no PSBT"); return result; }

        // 2) Sign our fee input.
        UniValue wpp(UniValue::VARR);
        wpp.push_back(psbt.toStdString());
        UniValue processed = m_client_model->node().executeRpc("walletprocesspsbt", wpp, wname);
        const std::string signed_psbt = processed.exists("psbt") ? processed["psbt"].get_str() : std::string();

        // 3) Extract (this skips re-verifying the signatureless covenant, unlike finalizepsbt).
        UniValue fp(UniValue::VARR);
        fp.push_back(signed_psbt);
        UniValue extracted = m_client_model->node().executeRpc("difficulty.finalize_settlement", fp, wname);
        const std::string hex = extracted.exists("hex") ? extracted["hex"].get_str() : std::string();
        if (hex.empty()) { result.error = tr("Could not extract the settlement transaction"); return result; }

        // 4) Broadcast.
        UniValue sr(UniValue::VARR);
        sr.push_back(hex);
        UniValue txid = m_client_model->node().executeRpc("sendrawtransaction", sr, wname);
        result.success = true;
        result.txid = QString::fromStdString(txid.get_str());
        const double pw = built.exists("payout_writer") ? built["payout_writer"].get_real() : 0.0;
        const double pp = built.exists("payout_pot") ? built["payout_pot"].get_real() : 0.0;

        // If in-the-money, locate the funded pot output so the caller can redeem it without hunting the vout:
        // derive the lot's pot scriptPubKey, then find it in the settlement transaction.
        if (pp > 0.0) {
            try {
                UniValue dlots(UniValue::VARR);
                dlots.push_back(static_cast<int64_t>(lot_index));
                UniValue dparams(UniValue::VARR);
                dparams.push_back(terms);
                dparams.push_back(dlots);
                UniValue derived = m_client_model->node().executeRpc("optionseries.derive", dparams, wname);
                const std::string pot_spk = derived["lots"][0]["pot_spk"].get_str();
                UniValue drp(UniValue::VARR);
                drp.push_back(hex);
                UniValue dec = m_client_model->node().executeRpc("decoderawtransaction", drp, /*walletName=*/"");
                const UniValue& vout = dec["vout"];
                for (size_t i = 0; i < vout.size(); ++i) {
                    if (vout[i]["scriptPubKey"]["hex"].get_str() == pot_spk) {
                        result.pot_outpoint = result.txid + ":" + QString::number(vout[i]["n"].getInt<int>());
                        break;
                    }
                }
            } catch (...) { /* best-effort; redeem can still be done with a manually-entered pot */ }
        }
        result.detail = tr("settled lot %1 — writer %2 TSC, pot %3 TSC").arg(lot_index).arg(pw, 0, 'f', 8).arg(pp, 0, 'f', 8);
    } catch (const UniValue& e) {
        result.error = QString::fromStdString(e.isObject() && e.exists("message") ? e["message"].get_str() : e.write());
    } catch (const std::exception& e) {
        result.error = QString::fromStdString(e.what());
    } catch (...) {
        result.error = tr("Unknown error occurred");
    }
    return result;
}

WalletModel::OptionSeriesActionResult WalletModel::optionSeriesBuyback(const QString& terms_json, int lot_index)
{
    OptionSeriesActionResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }
    try {
        UniValue terms;
        if (!terms.read(terms_json.toStdString())) { result.error = tr("Invalid series terms"); return result; }
        UniValue opts(UniValue::VOBJ);
        opts.pushKV("broadcast", true);
        UniValue params(UniValue::VARR);
        params.push_back(terms);
        params.push_back(static_cast<int64_t>(lot_index));
        params.push_back(opts);
        UniValue r = m_client_model->node().executeRpc("optionseries.build_buyback", params, getWalletName().toStdString());
        result.success = true;
        if (r.exists("txid")) result.txid = QString::fromStdString(r["txid"].get_str());
        const int change = r.exists("token_change_units") ? r["token_change_units"].getInt<int>() : 0;
        const double sweep = r.exists("native_sweep") ? r["native_sweep"].get_real() : 0.0;
        result.detail = tr("bought back lot %1 — reclaimed %2 TSC, token change %3 units").arg(lot_index).arg(sweep, 0, 'f', 8).arg(change);
    } catch (const UniValue& e) {
        result.error = QString::fromStdString(e.isObject() && e.exists("message") ? e["message"].get_str() : e.write());
    } catch (const std::exception& e) {
        result.error = QString::fromStdString(e.what());
    } catch (...) {
        result.error = tr("Unknown error occurred");
    }
    return result;
}

WalletModel::OptionSeriesActionResult WalletModel::optionSeriesRedeem(const QString& terms_json, int lot_index, const QString& pot_outpoint)
{
    OptionSeriesActionResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }
    try {
        UniValue terms;
        if (!terms.read(terms_json.toStdString())) { result.error = tr("Invalid series terms"); return result; }
        UniValue pot(UniValue::VOBJ);
        pot.pushKV("lot_index", static_cast<int64_t>(lot_index));
        pot.pushKV("pot", pot_outpoint.toStdString());
        UniValue pots(UniValue::VARR);
        pots.push_back(pot);
        UniValue opts(UniValue::VOBJ);
        opts.pushKV("broadcast", true);
        UniValue params(UniValue::VARR);
        params.push_back(terms);
        params.push_back(pots);
        params.push_back(opts);
        UniValue r = m_client_model->node().executeRpc("optionseries.build_redeem", params, getWalletName().toStdString());
        result.success = true;
        if (r.exists("txid")) result.txid = QString::fromStdString(r["txid"].get_str());
        const int change = r.exists("token_change_units") ? r["token_change_units"].getInt<int>() : 0;
        const double sweep = r.exists("native_sweep") ? r["native_sweep"].get_real() : 0.0;
        result.detail = tr("redeemed lot %1 pot — swept %2 TSC, token change %3 units").arg(lot_index).arg(sweep, 0, 'f', 8).arg(change);
    } catch (const UniValue& e) {
        result.error = QString::fromStdString(e.isObject() && e.exists("message") ? e["message"].get_str() : e.write());
    } catch (const std::exception& e) {
        result.error = QString::fromStdString(e.what());
    } catch (...) {
        result.error = tr("Unknown error occurred");
    }
    return result;
}

// ============================================================================
// Scalar note-pair (securitised CFD asset series) + scalar feed RPC wrappers
// ============================================================================

// Map the GUI terms input to the `terms` object the scalar.* RPCs parse (ParseScalarNotePairTermsFromJson).
// The L/S token ids are DERIVED by the RPC from these economics and are never supplied; keeping series_salt
// constant across the register → issue → record steps keeps the descriptor (and thus the vault addresses)
// stable, exactly like the option-series wizard re-collects the same terms each step.
static UniValue ScalarNotePairTermsToUni(const WalletModel::ScalarNotePairTermsInput& t)
{
    UniValue terms(UniValue::VOBJ);
    terms.pushKV("source_type", static_cast<int64_t>(t.source_type));
    terms.pushKV("payoff_mode", static_cast<int64_t>(t.payoff_mode));
    terms.pushKV("loss_direction", static_cast<int64_t>(t.loss_direction));
    if (!t.underlying_asset_id.isEmpty()) terms.pushKV("underlying_asset_id", t.underlying_asset_id.toStdString());
    terms.pushKV("feed_id", static_cast<int64_t>(t.feed_id));
    terms.pushKV("fixing_ref", static_cast<uint64_t>(t.fixing_ref));
    terms.pushKV("publication_deadline_height", static_cast<int64_t>(t.publication_deadline_height));
    terms.pushKV("settle_lock_height", static_cast<int64_t>(t.settle_lock_height));
    terms.pushKV("scalar_format_id", static_cast<int64_t>(t.scalar_format_id));
    if (!t.strike.isEmpty()) terms.pushKV("strike", t.strike.toStdString());
    if (!t.fallback_scalar.isEmpty()) terms.pushKV("fallback_scalar", t.fallback_scalar.toStdString());
    terms.pushKV("lambda_q", static_cast<int64_t>(t.lambda_q));
    if (!t.collateral_asset_id.isEmpty()) terms.pushKV("collateral_asset_id", t.collateral_asset_id.toStdString());
    terms.pushKV("vault_im", static_cast<uint64_t>(t.vault_im));
    terms.pushKV("lot_count", static_cast<int64_t>(t.lot_count));
    if (!t.series_salt.isEmpty()) terms.pushKV("series_salt", t.series_salt.toStdString());
    return terms;
}

WalletModel::ScalarNotePairRegisterResult WalletModel::scalarNotePairBuildRegister(const ScalarNotePairTermsInput& termsIn,
                                                                                   const QString& root, const QString& long_suffix,
                                                                                   const QString& short_suffix, qint64 child_bond_sats,
                                                                                   double fee_rate, bool broadcast)
{
    ScalarNotePairRegisterResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }
    try {
        UniValue options(UniValue::VOBJ);
        options.pushKV("broadcast", broadcast);
        if (fee_rate > 0.0) options.pushKV("fee_rate", UniValue(fee_rate));
        if (child_bond_sats > 0) options.pushKV("child_bond_sats", static_cast<int64_t>(child_bond_sats));

        UniValue params(UniValue::VARR);
        params.push_back(ScalarNotePairTermsToUni(termsIn));
        params.push_back(root.toStdString());
        params.push_back(long_suffix.toStdString());
        params.push_back(short_suffix.toStdString());
        params.push_back(options);

        UniValue r = m_client_model->node().executeRpc("scalar.build_register", params, getWalletName().toStdString());
        result.success = true;
        if (r.exists("pair_id")) result.pair_id = QString::fromStdString(r["pair_id"].get_str());
        if (r.exists("long_token_id")) result.long_token_id = QString::fromStdString(r["long_token_id"].get_str());
        if (r.exists("short_token_id")) result.short_token_id = QString::fromStdString(r["short_token_id"].get_str());
        if (r.exists("long_ticker")) result.long_ticker = QString::fromStdString(r["long_ticker"].get_str());
        if (r.exists("short_ticker")) result.short_ticker = QString::fromStdString(r["short_ticker"].get_str());
        result.txid = r.exists("txid") ? QString::fromStdString(r["txid"].get_str()) : tr("(pending)");
    } catch (const UniValue& e) {
        result.error = QString::fromStdString(e.isObject() && e.exists("message") ? e["message"].get_str() : e.write());
    } catch (const std::exception& e) {
        result.error = QString::fromStdString(e.what());
    } catch (...) {
        result.error = tr("Unknown error occurred");
    }
    return result;
}

WalletModel::ScalarNotePairIssueResult WalletModel::scalarNotePairBuildIssue(const ScalarNotePairTermsInput& termsIn,
                                                                             qint64 vault_native_sats, double fee_rate, bool broadcast)
{
    ScalarNotePairIssueResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }
    try {
        UniValue options(UniValue::VOBJ);
        options.pushKV("broadcast", broadcast);
        if (fee_rate > 0.0) options.pushKV("fee_rate", UniValue(fee_rate));
        if (vault_native_sats > 0) options.pushKV("vault_native_sats", static_cast<int64_t>(vault_native_sats));

        UniValue params(UniValue::VARR);
        params.push_back(ScalarNotePairTermsToUni(termsIn));
        params.push_back(options);

        UniValue r = m_client_model->node().executeRpc("scalar.build_issue", params, getWalletName().toStdString());
        result.success = true;
        if (r.exists("pair_id")) result.pair_id = QString::fromStdString(r["pair_id"].get_str());
        if (r.exists("lot_count")) result.lot_count = r["lot_count"].getInt<int>();
        if (r.exists("txid")) result.txid = QString::fromStdString(r["txid"].get_str());
    } catch (const UniValue& e) {
        result.error = QString::fromStdString(e.isObject() && e.exists("message") ? e["message"].get_str() : e.write());
    } catch (const std::exception& e) {
        result.error = QString::fromStdString(e.what());
    } catch (...) {
        result.error = tr("Unknown error occurred");
    }
    return result;
}

WalletModel::ScalarNotePairRecordResult WalletModel::scalarNotePairRecordIssue(const ScalarNotePairTermsInput& termsIn,
                                                                               const QString& issue_txid, const QString& register_txid)
{
    ScalarNotePairRecordResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }
    try {
        UniValue params(UniValue::VARR);
        params.push_back(ScalarNotePairTermsToUni(termsIn));
        params.push_back(issue_txid.toStdString());
        if (!register_txid.isEmpty()) params.push_back(register_txid.toStdString());

        UniValue r = m_client_model->node().executeRpc("scalar.record_issue", params, getWalletName().toStdString());
        result.success = true;
        if (r.exists("pair_id")) result.pair_id = QString::fromStdString(r["pair_id"].get_str());
        if (r.exists("lot_count")) result.lot_count = r["lot_count"].getInt<int>();
        if (r.exists("persisted")) result.persisted = r["persisted"].get_bool();
    } catch (const UniValue& e) {
        result.error = QString::fromStdString(e.isObject() && e.exists("message") ? e["message"].get_str() : e.write());
    } catch (const std::exception& e) {
        result.error = QString::fromStdString(e.what());
    } catch (...) {
        result.error = tr("Unknown error occurred");
    }
    return result;
}

WalletModel::ScalarNotePairListResult WalletModel::scalarNotePairList()
{
    ScalarNotePairListResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }
    try {
        UniValue params(UniValue::VARR);
        UniValue r = m_client_model->node().executeRpc("scalar.list", params, getWalletName().toStdString());
        result.success = true;
        if (r.isArray()) {
            for (size_t i = 0; i < r.size(); ++i) {
                const UniValue& o = r[i];
                ScalarNotePairListEntry e;
                if (o.exists("pair_id")) e.pair_id = QString::fromStdString(o["pair_id"].get_str());
                if (o.exists("lot_count")) e.lot_count = o["lot_count"].getInt<int>();
                if (o.exists("issue_txid")) e.issue_txid = QString::fromStdString(o["issue_txid"].get_str());
                if (o.exists("long_icu_outpoint")) e.long_icu_outpoint = QString::fromStdString(o["long_icu_outpoint"].get_str());
                if (o.exists("short_icu_outpoint")) e.short_icu_outpoint = QString::fromStdString(o["short_icu_outpoint"].get_str());
                if (o.exists("lot_vaults") && o["lot_vaults"].isArray()) {
                    const UniValue& lv = o["lot_vaults"];
                    for (size_t j = 0; j < lv.size(); ++j) e.lot_vaults.append(QString::fromStdString(lv[j].get_str()));
                }
                if (o.exists("terms") && o["terms"].isObject()) e.terms_json = QString::fromStdString(o["terms"].write());
                result.pairs.append(e);
            }
        }
    } catch (const UniValue& e) {
        result.error = QString::fromStdString(e.isObject() && e.exists("message") ? e["message"].get_str() : e.write());
    } catch (const std::exception& e) {
        result.error = QString::fromStdString(e.what());
    } catch (...) {
        result.error = tr("Unknown error occurred");
    }
    return result;
}

WalletModel::ScalarNotePairActionResult WalletModel::scalarNotePairSettle(const QString& terms_json, int lot_index,
                                                                          const QString& vault_outpoint, double fee_rate)
{
    ScalarNotePairActionResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }
    try {
        UniValue terms;
        if (!terms.read(terms_json.toStdString())) { result.error = tr("Invalid note-pair terms"); return result; }
        UniValue opts(UniValue::VOBJ);
        opts.pushKV("broadcast", true);
        if (fee_rate > 0.0) opts.pushKV("fee_rate", UniValue(fee_rate));
        UniValue params(UniValue::VARR);
        params.push_back(terms);
        params.push_back(static_cast<int64_t>(lot_index));
        params.push_back(vault_outpoint.toStdString());
        params.push_back(opts);
        UniValue r = m_client_model->node().executeRpc("scalar.build_settlement", params, getWalletName().toStdString());
        result.success = true;
        if (r.exists("txid")) result.txid = QString::fromStdString(r["txid"].get_str());
        if (r.exists("long_pot")) result.long_pot = QString::fromStdString(r["long_pot"].get_str());
        if (r.exists("short_pot")) result.short_pot = QString::fromStdString(r["short_pot"].get_str());
        const QString owner = r.exists("payout_owner") ? QString::fromStdString(r["payout_owner"].get_str()) : QStringLiteral("0");
        const QString cp = r.exists("payout_cp") ? QString::fromStdString(r["payout_cp"].get_str()) : QStringLiteral("0");
        const bool fb = r.exists("is_fallback") && r["is_fallback"].get_bool();
        result.detail = tr("settled lot %1 — owner %2 / cp %3%4").arg(lot_index).arg(owner).arg(cp)
                            .arg(fb ? tr(" (fallback fixing)") : QString());
    } catch (const UniValue& e) {
        result.error = QString::fromStdString(e.isObject() && e.exists("message") ? e["message"].get_str() : e.write());
    } catch (const std::exception& e) {
        result.error = QString::fromStdString(e.what());
    } catch (...) {
        result.error = tr("Unknown error occurred");
    }
    return result;
}

WalletModel::ScalarNotePairActionResult WalletModel::scalarNotePairRedeem(const QString& terms_json, bool redeem_long, int lot_index,
                                                                          const QString& pot_outpoint, const QString& holder_address,
                                                                          double fee_rate)
{
    ScalarNotePairActionResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }
    try {
        UniValue terms;
        if (!terms.read(terms_json.toStdString())) { result.error = tr("Invalid note-pair terms"); return result; }
        UniValue pot(UniValue::VOBJ);
        pot.pushKV("lot_index", static_cast<int64_t>(lot_index));
        pot.pushKV("pot", pot_outpoint.toStdString());
        UniValue pots(UniValue::VARR);
        pots.push_back(pot);
        UniValue opts(UniValue::VOBJ);
        opts.pushKV("broadcast", true);
        if (fee_rate > 0.0) opts.pushKV("fee_rate", UniValue(fee_rate));
        if (!holder_address.isEmpty()) opts.pushKV("holder_address", holder_address.toStdString());
        UniValue params(UniValue::VARR);
        params.push_back(terms);
        params.push_back(redeem_long);
        params.push_back(pots);
        params.push_back(opts);
        UniValue r = m_client_model->node().executeRpc("scalar.build_redeem", params, getWalletName().toStdString());
        result.success = true;
        if (r.exists("txid")) result.txid = QString::fromStdString(r["txid"].get_str());
        const int retired = r.exists("units_retired") ? r["units_retired"].getInt<int>() : 0;
        const int change = r.exists("token_change_units") ? r["token_change_units"].getInt<int>() : 0;
        result.detail = tr("redeemed %1 token, lot %2 — retired %3 units, change %4")
                            .arg(redeem_long ? tr("long (L)") : tr("short (S)")).arg(lot_index).arg(retired).arg(change);
    } catch (const UniValue& e) {
        result.error = QString::fromStdString(e.isObject() && e.exists("message") ? e["message"].get_str() : e.write());
    } catch (const std::exception& e) {
        result.error = QString::fromStdString(e.what());
    } catch (...) {
        result.error = tr("Unknown error occurred");
    }
    return result;
}

WalletModel::ScalarNotePairActionResult WalletModel::scalarNotePairUnwind(const QString& terms_json, int lot_index,
                                                                          const QString& vault_outpoint, const QString& holder_address,
                                                                          double fee_rate)
{
    ScalarNotePairActionResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }
    try {
        UniValue terms;
        if (!terms.read(terms_json.toStdString())) { result.error = tr("Invalid note-pair terms"); return result; }
        UniValue opts(UniValue::VOBJ);
        opts.pushKV("broadcast", true);
        if (fee_rate > 0.0) opts.pushKV("fee_rate", UniValue(fee_rate));
        if (!holder_address.isEmpty()) opts.pushKV("holder_address", holder_address.toStdString());
        UniValue params(UniValue::VARR);
        params.push_back(terms);
        params.push_back(static_cast<int64_t>(lot_index));
        params.push_back(vault_outpoint.toStdString());
        params.push_back(opts);
        UniValue r = m_client_model->node().executeRpc("scalar.build_unwind", params, getWalletName().toStdString());
        result.success = true;
        if (r.exists("txid")) result.txid = QString::fromStdString(r["txid"].get_str());
        result.detail = tr("unwound lot %1 — retired 1 L + 1 S, reclaimed full collateral").arg(lot_index);
    } catch (const UniValue& e) {
        result.error = QString::fromStdString(e.isObject() && e.exists("message") ? e["message"].get_str() : e.write());
    } catch (const std::exception& e) {
        result.error = QString::fromStdString(e.what());
    } catch (...) {
        result.error = tr("Unknown error occurred");
    }
    return result;
}

WalletModel::ScalarFeedPublishResult WalletModel::scalarPublish(const QString& asset_id, const QString& icu_txid, int icu_vout,
                                                                const QString& new_icu_address, qint64 new_icu_amount_sats,
                                                                quint32 feed_id, quint64 scalar_epoch, const QString& scalar_hex,
                                                                int scalar_format_id, double fee_rate)
{
    ScalarFeedPublishResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }
    try {
        UniValue options(UniValue::VOBJ);
        options.pushKV("autofund", true);
        options.pushKV("broadcast", true);
        if (fee_rate > 0.0) options.pushKV("fee_rate", UniValue(fee_rate));

        UniValue params(UniValue::VARR);
        params.push_back(icu_txid.toStdString());
        params.push_back(static_cast<int64_t>(icu_vout));
        params.push_back(asset_id.toStdString());
        params.push_back(new_icu_address.toStdString());
        params.push_back(SatsToAmountStr(new_icu_amount_sats));
        params.push_back(static_cast<int64_t>(feed_id));
        params.push_back(static_cast<uint64_t>(scalar_epoch));
        params.push_back(scalar_hex.toStdString());
        params.push_back(static_cast<int64_t>(scalar_format_id));
        params.push_back(options);

        UniValue r = m_client_model->node().executeRpc("scalarpublish_raw", params, getWalletName().toStdString());
        result.success = true;
        if (r.exists("hex")) result.hex = QString::fromStdString(r["hex"].get_str());
        if (r.exists("txid")) result.txid = QString::fromStdString(r["txid"].get_str());
    } catch (const UniValue& e) {
        result.error = QString::fromStdString(e.isObject() && e.exists("message") ? e["message"].get_str() : e.write());
    } catch (const std::exception& e) {
        result.error = QString::fromStdString(e.what());
    } catch (...) {
        result.error = tr("Unknown error occurred");
    }
    return result;
}

WalletModel::ScalarFeedListResult WalletModel::scalarListFeeds(const QString& asset_id)
{
    ScalarFeedListResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }
    try {
        UniValue params(UniValue::VARR);
        params.push_back(asset_id.toStdString());
        UniValue r = m_client_model->node().executeRpc("scalarlistfeeds", params, getWalletName().toStdString());
        result.success = true;
        if (r.isArray()) {
            for (size_t i = 0; i < r.size(); ++i) {
                const UniValue& o = r[i];
                ScalarFeedEntry e;
                if (o.exists("feed_id")) e.feed_id = static_cast<quint32>(o["feed_id"].getInt<int64_t>());
                if (o.exists("last_epoch")) e.last_epoch = static_cast<quint64>(o["last_epoch"].getInt<int64_t>());
                result.feeds.append(e);
            }
        }
    } catch (const UniValue& e) {
        result.error = QString::fromStdString(e.isObject() && e.exists("message") ? e["message"].get_str() : e.write());
    } catch (const std::exception& e) {
        result.error = QString::fromStdString(e.what());
    } catch (...) {
        result.error = tr("Unknown error occurred");
    }
    return result;
}

WalletModel::ScalarFeedGetResult WalletModel::scalarGetFeed(const QString& asset_id, quint32 feed_id, qint64 epoch)
{
    ScalarFeedGetResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }
    try {
        UniValue params(UniValue::VARR);
        params.push_back(asset_id.toStdString());
        params.push_back(static_cast<int64_t>(feed_id));
        if (epoch >= 0) params.push_back(static_cast<uint64_t>(epoch));
        UniValue r = m_client_model->node().executeRpc("scalargetfeed", params, getWalletName().toStdString());
        result.success = true;
        if (r.exists("epoch")) result.epoch = static_cast<quint64>(r["epoch"].getInt<int64_t>());
        if (r.exists("last_epoch")) result.last_epoch = static_cast<quint64>(r["last_epoch"].getInt<int64_t>());
        if (r.exists("scalar")) result.scalar = QString::fromStdString(r["scalar"].get_str());
        if (r.exists("scalar_format_id")) result.scalar_format_id = r["scalar_format_id"].getInt<int>();
        if (r.exists("publication_height")) result.publication_height = r["publication_height"].getInt<int64_t>();
        if (r.exists("buried")) result.buried = r["buried"].get_bool();
    } catch (const UniValue& e) {
        result.error = QString::fromStdString(e.isObject() && e.exists("message") ? e["message"].get_str() : e.write());
    } catch (const std::exception& e) {
        result.error = QString::fromStdString(e.what());
    } catch (...) {
        result.error = tr("Unknown error occurred");
    }
    return result;
}

// ============================================================================
// Bilateral scalar CFD (scalarcfd.*) RPC wrappers
// ============================================================================

namespace {
//! ECONOMICS-only terms object (no payout keys — those come from the addresses), matching
//! ParseScalarCfdEconomics: source/payoff + the shared scalar fixing + each leg's IM (decimal string,
//! collateral units) and leverage. collateral_asset_id omitted == native.
UniValue ScalarCfdTermsToUni(const WalletModel::ScalarCfdTermsInput& t)
{
    UniValue u(UniValue::VOBJ);
    u.pushKV("source_type", static_cast<int64_t>(t.source_type));
    u.pushKV("payoff_mode", static_cast<int64_t>(t.payoff_mode));
    u.pushKV("underlying_asset_id", t.underlying_asset_id.toStdString());
    u.pushKV("feed_id", static_cast<int64_t>(t.feed_id));
    u.pushKV("fixing_ref", static_cast<uint64_t>(t.fixing_ref));
    u.pushKV("publication_deadline_height", static_cast<int64_t>(t.publication_deadline_height));
    u.pushKV("settle_lock_height", static_cast<int64_t>(t.settle_lock_height));
    u.pushKV("scalar_format_id", static_cast<int64_t>(t.scalar_format_id));
    u.pushKV("strike", t.strike.toStdString());
    u.pushKV("fallback_scalar", t.fallback_scalar.toStdString());
    if (!t.collateral_asset_id.isEmpty()) u.pushKV("collateral_asset_id", t.collateral_asset_id.toStdString());
    UniValue lj(UniValue::VOBJ), sj(UniValue::VOBJ);
    // im is a DECIMAL INTEGER string in collateral units (uint64; sats when native) — ParseUnits, NOT a BTC amount.
    lj.pushKV("im", QString::number(static_cast<qulonglong>(t.long_leg.im_sats)).toStdString());
    lj.pushKV("lambda_q", static_cast<int64_t>(t.long_leg.lambda_q));
    sj.pushKV("im", QString::number(static_cast<qulonglong>(t.short_leg.im_sats)).toStdString());
    sj.pushKV("lambda_q", static_cast<int64_t>(t.short_leg.lambda_q));
    u.pushKV("long", lj);
    u.pushKV("short", sj);
    return u;
}
QString UniErr(const UniValue& e) { return QString::fromStdString(e.isObject() && e.exists("message") ? e["message"].get_str() : e.write()); }
} // namespace

WalletModel::ScalarCfdProposeResult WalletModel::scalarCfdPropose(const ScalarCfdTermsInput& terms, bool proposerIsShort,
                                                                 const QString& ownerAddr, const QString& cpAddr)
{
    ScalarCfdProposeResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }
    try {
        UniValue params(UniValue::VARR);
        params.push_back(ScalarCfdTermsToUni(terms));
        params.push_back(std::string(proposerIsShort ? "short" : "long"));
        params.push_back(ownerAddr.toStdString());
        params.push_back(cpAddr.toStdString());
        UniValue r = m_client_model->node().executeRpc("scalarcfd.propose", params, getWalletName().toStdString());
        result.success = true;
        if (r.exists("offer")) result.offer_json = QString::fromStdString(r["offer"].write());
    } catch (const UniValue& e) { result.error = UniErr(e); }
    catch (const std::exception& e) { result.error = QString::fromStdString(e.what()); }
    catch (...) { result.error = tr("Unknown error occurred"); }
    return result;
}

WalletModel::ScalarCfdAcceptResult WalletModel::scalarCfdAccept(const QString& offer_json, const QString& ownerAddr,
                                                               const QString& cpAddr, bool confirmed)
{
    ScalarCfdAcceptResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }
    try {
        UniValue offer; if (!offer.read(offer_json.toStdString())) { result.error = tr("Invalid offer JSON"); return result; }
        UniValue opts(UniValue::VOBJ); opts.pushKV("confirmed", confirmed);
        UniValue params(UniValue::VARR);
        params.push_back(offer); params.push_back(ownerAddr.toStdString()); params.push_back(cpAddr.toStdString()); params.push_back(opts);
        UniValue r = m_client_model->node().executeRpc("scalarcfd.accept", params, getWalletName().toStdString());
        result.success = true;
        if (r.exists("contract_id")) result.contract_id = QString::fromStdString(r["contract_id"].get_str());
        if (r.exists("acceptance")) result.acceptance_json = QString::fromStdString(r["acceptance"].write());
        if (r.exists("action_required")) result.action_required = QString::fromStdString(r["action_required"].get_str());
    } catch (const UniValue& e) { result.error = UniErr(e); }
    catch (const std::exception& e) { result.error = QString::fromStdString(e.what()); }
    catch (...) { result.error = tr("Unknown error occurred"); }
    return result;
}

WalletModel::ScalarCfdImportResult WalletModel::scalarCfdImportAcceptance(const QString& offer_json, const QString& acceptance_json)
{
    ScalarCfdImportResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }
    try {
        UniValue offer, acc;
        if (!offer.read(offer_json.toStdString()) || !acc.read(acceptance_json.toStdString())) { result.error = tr("Invalid offer/acceptance JSON"); return result; }
        UniValue params(UniValue::VARR); params.push_back(offer); params.push_back(acc);
        UniValue r = m_client_model->node().executeRpc("scalarcfd.import_acceptance", params, getWalletName().toStdString());
        result.success = true;
        if (r.exists("contract_id")) result.contract_id = QString::fromStdString(r["contract_id"].get_str());
        if (r.exists("state")) result.state = QString::fromStdString(r["state"].get_str());
    } catch (const UniValue& e) { result.error = UniErr(e); }
    catch (const std::exception& e) { result.error = QString::fromStdString(e.what()); }
    catch (...) { result.error = tr("Unknown error occurred"); }
    return result;
}

WalletModel::ScalarCfdOpenResult WalletModel::scalarCfdBuildOpen(const QString& contract_id, bool isShort,
                                                               const QString& priorPsbt, double fee_rate)
{
    ScalarCfdOpenResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }
    try {
        UniValue opts(UniValue::VOBJ);
        if (!priorPsbt.isEmpty()) opts.pushKV("psbt", priorPsbt.toStdString());
        if (fee_rate > 0.0) opts.pushKV("fee_rate", UniValue(fee_rate));
        UniValue params(UniValue::VARR);
        params.push_back(contract_id.toStdString());
        params.push_back(std::string(isShort ? "short" : "long"));
        if (!opts.getKeys().empty()) params.push_back(opts);
        UniValue r = m_client_model->node().executeRpc("scalarcfd.build_open", params, getWalletName().toStdString());
        result.success = true;
        if (r.exists("psbt")) result.psbt = QString::fromStdString(r["psbt"].get_str());
        if (r.exists("fee")) result.fee = QString::fromStdString(r["fee"].getValStr());
        if (r.exists("leg")) result.leg = QString::fromStdString(r["leg"].get_str());
        if (r.exists("vault_index")) result.vault_index = r["vault_index"].getInt<int>();
    } catch (const UniValue& e) { result.error = UniErr(e); }
    catch (const std::exception& e) { result.error = QString::fromStdString(e.what()); }
    catch (...) { result.error = tr("Unknown error occurred"); }
    return result;
}

WalletModel::ScalarCfdRecordOpenResult WalletModel::scalarCfdRecordOpen(const QString& contract_id, const QString& txid)
{
    ScalarCfdRecordOpenResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }
    try {
        UniValue params(UniValue::VARR); params.push_back(contract_id.toStdString()); params.push_back(txid.toStdString());
        UniValue r = m_client_model->node().executeRpc("scalarcfd.record_open", params, getWalletName().toStdString());
        result.success = true;
        if (r.exists("long_vault")) result.long_vault = QString::fromStdString(r["long_vault"].get_str());
        if (r.exists("short_vault")) result.short_vault = QString::fromStdString(r["short_vault"].get_str());
    } catch (const UniValue& e) { result.error = UniErr(e); }
    catch (const std::exception& e) { result.error = QString::fromStdString(e.what()); }
    catch (...) { result.error = tr("Unknown error occurred"); }
    return result;
}

WalletModel::ScalarCfdSettlementResult WalletModel::scalarCfdBuildSettlement(const QString& contract_id, bool isShort, double fee_rate)
{
    ScalarCfdSettlementResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }
    try {
        UniValue params(UniValue::VARR);
        params.push_back(contract_id.toStdString());
        params.push_back(std::string(isShort ? "short" : "long"));
        if (fee_rate > 0.0) { UniValue opts(UniValue::VOBJ); opts.pushKV("fee_rate", UniValue(fee_rate)); params.push_back(opts); }
        UniValue r = m_client_model->node().executeRpc("scalarcfd.build_settlement", params, getWalletName().toStdString());
        result.success = true;
        if (r.exists("psbt")) result.psbt = QString::fromStdString(r["psbt"].get_str());
        if (r.exists("fee")) result.fee = QString::fromStdString(r["fee"].getValStr());
        if (r.exists("payout_owner")) result.payout_owner = QString::fromStdString(r["payout_owner"].getValStr());
        if (r.exists("payout_cp")) result.payout_cp = QString::fromStdString(r["payout_cp"].getValStr());
        if (r.exists("is_fallback")) result.is_fallback = r["is_fallback"].get_bool();
        if (r.exists("vault_input_index")) result.vault_input_index = r["vault_input_index"].getInt<int>();
    } catch (const UniValue& e) { result.error = UniErr(e); }
    catch (const std::exception& e) { result.error = QString::fromStdString(e.what()); }
    catch (...) { result.error = tr("Unknown error occurred"); }
    return result;
}

WalletModel::ScalarCfdFinalizeResult WalletModel::scalarCfdFinalizeSettlement(const QString& psbt)
{
    ScalarCfdFinalizeResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }
    try {
        UniValue params(UniValue::VARR); params.push_back(psbt.toStdString());
        UniValue r = m_client_model->node().executeRpc("scalarcfd.finalize_settlement", params, getWalletName().toStdString());
        result.success = true;
        if (r.exists("hex")) result.hex = QString::fromStdString(r["hex"].get_str());
    } catch (const UniValue& e) { result.error = UniErr(e); }
    catch (const std::exception& e) { result.error = QString::fromStdString(e.what()); }
    catch (...) { result.error = tr("Unknown error occurred"); }
    return result;
}

WalletModel::ScalarCfdCoopCloseResult WalletModel::scalarCfdBuildCoopClose(const QString& contract_id, bool isShort,
                                                                          const QList<QPair<QString, qint64>>& outputs)
{
    ScalarCfdCoopCloseResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }
    try {
        UniValue outs(UniValue::VARR);
        for (const auto& o : outputs) {
            UniValue obj(UniValue::VOBJ);
            obj.pushKV("address", o.first.toStdString());
            obj.pushKV("amount", SatsToAmountStr(o.second));
            outs.push_back(obj);
        }
        UniValue params(UniValue::VARR);
        params.push_back(contract_id.toStdString());
        params.push_back(std::string(isShort ? "short" : "long"));
        params.push_back(outs);
        UniValue r = m_client_model->node().executeRpc("scalarcfd.build_coop_close", params, getWalletName().toStdString());
        result.success = true;
        if (r.exists("psbt")) result.psbt = QString::fromStdString(r["psbt"].get_str());
        if (r.exists("fee")) result.fee = QString::fromStdString(r["fee"].getValStr());
    } catch (const UniValue& e) { result.error = UniErr(e); }
    catch (const std::exception& e) { result.error = QString::fromStdString(e.what()); }
    catch (...) { result.error = tr("Unknown error occurred"); }
    return result;
}

WalletModel::ScalarCfdSignCoopResult WalletModel::scalarCfdSignCoop(const QString& contract_id, bool isShort, const QString& psbt)
{
    ScalarCfdSignCoopResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }
    try {
        UniValue params(UniValue::VARR);
        params.push_back(contract_id.toStdString());
        params.push_back(std::string(isShort ? "short" : "long"));
        params.push_back(psbt.toStdString());
        UniValue r = m_client_model->node().executeRpc("scalarcfd.sign_coop", params, getWalletName().toStdString());
        result.success = true;
        if (r.exists("complete")) result.complete = r["complete"].get_bool();
        if (r.exists("psbt")) result.psbt = QString::fromStdString(r["psbt"].get_str());
        if (r.exists("hex")) result.hex = QString::fromStdString(r["hex"].get_str());
    } catch (const UniValue& e) { result.error = UniErr(e); }
    catch (const std::exception& e) { result.error = QString::fromStdString(e.what()); }
    catch (...) { result.error = tr("Unknown error occurred"); }
    return result;
}

WalletModel::ScalarCfdPriceResult WalletModel::scalarCfdPrice(const QString& contract_id, double sigma,
                                                             double forward_cross_rate, double discount_factor)
{
    ScalarCfdPriceResult result;
    if (!m_client_model) { result.error = tr("Client model not available"); return result; }
    try {
        UniValue params(UniValue::VARR);
        params.push_back(contract_id.toStdString());
        UniValue opts(UniValue::VOBJ);
        if (sigma >= 0.0) opts.pushKV("sigma", UniValue(sigma));
        if (forward_cross_rate >= 0.0) opts.pushKV("forward_cross_rate", UniValue(forward_cross_rate));
        if (discount_factor >= 0.0) opts.pushKV("discount_factor", UniValue(discount_factor));
        if (!opts.getKeys().empty()) params.push_back(opts);
        UniValue r = m_client_model->node().executeRpc("scalarcfd.price", params, getWalletName().toStdString());
        result.success = true;
        auto num = [&](const char* k) { return r.exists(k) ? r[k].get_real() : 0.0; };
        result.current_ratio = num("current_ratio");
        result.forecast_ratio = num("forecast_ratio");
        result.intrinsic_long_mtm = num("intrinsic_long_mtm");
        result.intrinsic_short_mtm = num("intrinsic_short_mtm");
        result.expected_long_mtm = num("expected_long_mtm");
        result.expected_short_mtm = num("expected_short_mtm");
        result.sigma = num("sigma");
        result.tau_years = num("tau_years");
        result.discount_factor = num("discount_factor");
        result.long_delta_to_cross_rate = num("long_delta_to_cross_rate");
        result.long_vega = num("long_vega");
        result.long_theta = num("long_theta");
        result.short_delta_to_cross_rate = num("short_delta_to_cross_rate");
        result.short_vega = num("short_vega");
        result.short_theta = num("short_theta");
        if (r.exists("contract_id")) result.contract_id = QString::fromStdString(r["contract_id"].get_str());
        if (r.exists("collateral_is_native")) result.collateral_is_native = r["collateral_is_native"].get_bool();
        if (r.exists("forward_provenance")) result.forward_provenance = QString::fromStdString(r["forward_provenance"].get_str());
        if (r.exists("fixing_reached")) result.fixing_reached = r["fixing_reached"].get_bool();
        if (r.exists("is_fallback")) result.is_fallback = r["is_fallback"].get_bool();
        if (r.exists("model_unreliable")) result.model_unreliable = r["model_unreliable"].get_bool();
        if (r.exists("warnings") && r["warnings"].isArray()) {
            for (size_t i = 0; i < r["warnings"].size(); ++i) result.warnings << QString::fromStdString(r["warnings"][i].get_str());
        }
    } catch (const UniValue& e) { result.error = UniErr(e); }
    catch (const std::exception& e) { result.error = QString::fromStdString(e.what()); }
    catch (...) { result.error = tr("Unknown error occurred"); }
    return result;
}

// ============================================================================
// Forward Settlement RPC Wrappers
// ============================================================================

WalletModel::ForwardBuildSelfDeliveryResult WalletModel::forwardBuildSelfDelivery(const QString& contract_id, const QVariantMap& options)
{
    ForwardBuildSelfDeliveryResult result;

    if (!m_client_model) {
        result.error = tr("Client model not available");
        return result;
    }

    // Ensure wallet is unlocked before building the self-delivery transaction
    WalletModel::UnlockContext ctx(requestUnlock());
    if (!ctx.isValid()) {
        result.error = tr("Wallet locked. Please unlock the wallet to build the self-delivery transaction.");
        return result;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(contract_id.toStdString());

        // Build options object if provided
        if (!options.isEmpty()) {
            UniValue optionsObj(UniValue::VOBJ);

            if (options.contains("fee_rate")) {
                optionsObj.pushKV("fee_rate", options["fee_rate"].toDouble());
            }
            if (options.contains("short_vault_txid")) {
                optionsObj.pushKV("short_vault_txid", options["short_vault_txid"].toString().toStdString());
            }
            if (options.contains("short_vault_vout")) {
                optionsObj.pushKV("short_vault_vout", options["short_vault_vout"].toInt());
            }
            if (options.contains("long_vault_txid")) {
                optionsObj.pushKV("long_vault_txid", options["long_vault_txid"].toString().toStdString());
            }
            if (options.contains("long_vault_vout")) {
                optionsObj.pushKV("long_vault_vout", options["long_vault_vout"].toInt());
            }
            if (options.contains("side")) {
                optionsObj.pushKV("side", options["side"].toString().toStdString());
            }

            params.push_back(optionsObj);
        }

        UniValue response = m_client_model->node().executeRpc("forward.build_self_delivery", params, getWalletName().toStdString());

        result.success = true;
        result.side = QString::fromStdString(response["side"].get_str());
        result.psbt = QString::fromStdString(response["psbt"].get_str());
        result.vault_input_index = response["vault_input_index"].getInt<int>();
        result.escrow_output_index = response["escrow_output_index"].getInt<int>();
        result.margin_output_index = response["margin_output_index"].getInt<int>();

        if (response.exists("complete")) {
            result.complete = response["complete"].get_bool();
        }
        if (response.exists("hex")) {
            result.hex = QString::fromStdString(response["hex"].get_str());
        }
        if (response.exists("txid")) {
            result.txid = QString::fromStdString(response["txid"].get_str());
        }
        if (response.exists("locked_inputs") && response["locked_inputs"].isArray()) {
            const UniValue& lockedArr = response["locked_inputs"].get_array();
            for (size_t i = 0; i < lockedArr.size(); ++i) {
                const UniValue& obj = lockedArr[i].get_obj();
                if (!obj.exists("txid") || !obj.exists("vout")) continue;
                QString txid = QString::fromStdString(obj["txid"].get_str());
                int vout = obj["vout"].getInt<int>();
                result.lockedInputs.append(QPair<QString, int>(txid, vout));
            }
        }

        LogPrintf("WalletModel::forwardBuildSelfDelivery - side=%s, escrow_idx=%d, margin_idx=%d, complete=%d\n",
                  result.side.toStdString().c_str(), result.escrow_output_index, result.margin_output_index, result.complete);

    } catch (const UniValue& e) {
        result.success = false;
        result.error = tr("RPC error: %1").arg(QString::fromStdString(e.write()));
    } catch (const std::exception& e) {
        result.success = false;
        result.error = tr("Error: %1").arg(QString::fromStdString(e.what()));
    } catch (...) {
        result.success = false;
        result.error = tr("Unknown error occurred");
    }

    return result;
}

WalletModel::ForwardBuildEscrowClaimResult WalletModel::forwardBuildEscrowClaim(const QString& contract_id, const QString& escrow_txid, int escrow_vout, const QVariantMap& options)
{
    ForwardBuildEscrowClaimResult result;

    if (!m_client_model) {
        result.error = tr("Client model not available");
        return result;
    }

    // Ensure wallet is unlocked before building the escrow claim transaction
    WalletModel::UnlockContext ctx(requestUnlock());
    if (!ctx.isValid()) {
        result.error = tr("Wallet locked. Please unlock the wallet to build the escrow claim transaction.");
        return result;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(contract_id.toStdString());

        // Build escrow_outpoint object
        UniValue escrowOutpoint(UniValue::VOBJ);
        escrowOutpoint.pushKV("txid", escrow_txid.toStdString());
        escrowOutpoint.pushKV("vout", escrow_vout);
        params.push_back(escrowOutpoint);

        // Build options object if provided
        if (!options.isEmpty()) {
            UniValue optionsObj(UniValue::VOBJ);

            if (options.contains("fee_rate")) {
                optionsObj.pushKV("fee_rate", options["fee_rate"].toDouble());
            }
            if (options.contains("long_vault_txid")) {
                optionsObj.pushKV("long_vault_txid", options["long_vault_txid"].toString().toStdString());
            }
            if (options.contains("long_vault_vout")) {
                optionsObj.pushKV("long_vault_vout", options["long_vault_vout"].toInt());
            }
            if (options.contains("short_vault_txid")) {
                optionsObj.pushKV("short_vault_txid", options["short_vault_txid"].toString().toStdString());
            }
            if (options.contains("short_vault_vout")) {
                optionsObj.pushKV("short_vault_vout", options["short_vault_vout"].toInt());
            }

            params.push_back(optionsObj);
        }

        UniValue response = m_client_model->node().executeRpc("forward.build_escrow_claim", params, getWalletName().toStdString());

        result.success = true;
        result.psbt = QString::fromStdString(response["psbt"].get_str());
        result.payment_output_index = response["payment_output_index"].getInt<int>();

        if (response.exists("complete")) {
            result.complete = response["complete"].get_bool();
        }
        if (response.exists("hex")) {
            result.hex = QString::fromStdString(response["hex"].get_str());
        }
        if (response.exists("txid")) {
            result.txid = QString::fromStdString(response["txid"].get_str());
        }

        LogPrintf("WalletModel::forwardBuildEscrowClaim - payment_idx=%d, complete=%d\n",
                  result.payment_output_index, result.complete);

    } catch (const UniValue& e) {
        result.success = false;
        result.error = tr("RPC error: %1").arg(QString::fromStdString(e.write()));
    } catch (const std::exception& e) {
        result.success = false;
        result.error = tr("Error: %1").arg(QString::fromStdString(e.what()));
    } catch (...) {
        result.success = false;
        result.error = tr("Unknown error occurred");
    }

    return result;
}

WalletModel::ForwardBuildEscrowRefundResult WalletModel::forwardBuildEscrowRefund(const QString& contract_id, const QString& escrow_txid, int escrow_vout, const QVariantMap& options)
{
    ForwardBuildEscrowRefundResult result;

    if (!m_client_model) {
        result.error = tr("Client model not available");
        return result;
    }

    // Ensure wallet is unlocked before building the escrow refund transaction
    WalletModel::UnlockContext ctx(requestUnlock());
    if (!ctx.isValid()) {
        result.error = tr("Wallet locked. Please unlock the wallet to build the escrow refund transaction.");
        return result;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(contract_id.toStdString());

        // Build escrow_outpoint object
        UniValue escrowOutpoint(UniValue::VOBJ);
        escrowOutpoint.pushKV("txid", escrow_txid.toStdString());
        escrowOutpoint.pushKV("vout", escrow_vout);
        params.push_back(escrowOutpoint);

        // Build options object if provided
        if (!options.isEmpty()) {
            UniValue optionsObj(UniValue::VOBJ);

            if (options.contains("fee_rate")) {
                optionsObj.pushKV("fee_rate", options["fee_rate"].toDouble());
            }

            params.push_back(optionsObj);
        }

        UniValue response = m_client_model->node().executeRpc("forward.build_escrow_refund", params, getWalletName().toStdString());

        result.success = true;
        result.psbt = QString::fromStdString(response["psbt"].get_str());
        result.refund_output_index = response["refund_output_index"].getInt<int>();

        if (response.exists("complete")) {
            result.complete = response["complete"].get_bool();
        }
        if (response.exists("hex")) {
            result.hex = QString::fromStdString(response["hex"].get_str());
        }
        if (response.exists("txid")) {
            result.txid = QString::fromStdString(response["txid"].get_str());
        }

        LogPrintf("WalletModel::forwardBuildEscrowRefund - refund_idx=%d, complete=%d\n",
                  result.refund_output_index, result.complete);

    } catch (const UniValue& e) {
        result.success = false;
        result.error = tr("RPC error: %1").arg(QString::fromStdString(e.write()));
    } catch (const std::exception& e) {
        result.success = false;
        result.error = tr("Error: %1").arg(QString::fromStdString(e.what()));
    } catch (...) {
        result.success = false;
        result.error = tr("Unknown error occurred");
    }

    return result;
}

WalletModel::ForwardBuildIMTimeoutResult WalletModel::forwardBuildIMTimeout(const QString& contract_id, const QString& vault_type, const QVariantMap& options)
{
    ForwardBuildIMTimeoutResult result;

    if (!m_client_model) {
        result.error = tr("Client model not available");
        return result;
    }

    // Ensure wallet is unlocked before building the IM timeout transaction
    WalletModel::UnlockContext ctx(requestUnlock());
    if (!ctx.isValid()) {
        result.error = tr("Wallet locked. Please unlock the wallet to build the IM timeout transaction.");
        return result;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(contract_id.toStdString());
        params.push_back(vault_type.toStdString());  // "alice" or "bob"

        // Build options object if provided
        if (!options.isEmpty()) {
            UniValue optionsObj(UniValue::VOBJ);

            if (options.contains("fee_rate")) {
                optionsObj.pushKV("fee_rate", options["fee_rate"].toDouble());
            }
            if (options.contains("vault_txid")) {
                optionsObj.pushKV("vault_txid", options["vault_txid"].toString().toStdString());
            }
            if (options.contains("vault_vout")) {
                optionsObj.pushKV("vault_vout", options["vault_vout"].toInt());
            }
            if (options.contains("sweep_address")) {
                optionsObj.pushKV("sweep_address", options["sweep_address"].toString().toStdString());
            }
            if (options.contains("locktime")) {
                optionsObj.pushKV("locktime", options["locktime"].toUInt());
            }

            params.push_back(optionsObj);
        }

        UniValue response = m_client_model->node().executeRpc("forward.build_im_timeout", params, getWalletName().toStdString());

        result.success = true;
        result.psbt = QString::fromStdString(response["psbt"].get_str());
        result.penalty_output_index = response["sweep_output_index"].getInt<int>();

        if (response.exists("complete")) {
            result.complete = response["complete"].get_bool();
        }
        if (response.exists("hex")) {
            result.hex = QString::fromStdString(response["hex"].get_str());
        }
        if (response.exists("txid")) {
            result.txid = QString::fromStdString(response["txid"].get_str());
        }

        LogPrintf("WalletModel::forwardBuildIMTimeout - vault_type=%s, penalty_idx=%d, complete=%d\n",
                  vault_type.toStdString().c_str(), result.penalty_output_index, result.complete);

    } catch (const UniValue& e) {
        result.success = false;
        result.error = tr("RPC error: %1").arg(QString::fromStdString(e.write()));
    } catch (const std::exception& e) {
        result.success = false;
        result.error = tr("Error: %1").arg(QString::fromStdString(e.what()));
    } catch (...) {
        result.success = false;
        result.error = tr("Unknown error occurred");
    }

    return result;
}

// ============================================================================
// Spot Contract RPC Wrappers
// ============================================================================

WalletModel::SpotProposeResult WalletModel::spotPropose(const QVariantMap& terms)
{
    SpotProposeResult result;

    if (!m_client_model) {
        result.error = tr("Client model not available");
        return result;
    }

    try {
        UniValue params(UniValue::VARR);

        // Build top-level RPC params object
        UniValue rpcParams(UniValue::VOBJ);

        auto variantToBool = [](const QVariant& value, bool fallback) {
            if (!value.isValid()) {
                return fallback;
            }
            switch (static_cast<QMetaType::Type>(value.typeId())) {
            case QMetaType::Bool:
                return value.toBool();
            case QMetaType::Int:
            case QMetaType::LongLong:
                return value.toInt() != 0;
            case QMetaType::QString: {
                const QString str = value.toString().trimmed().toLower();
                if (str == QLatin1String("true") || str == QLatin1String("1") || str == QLatin1String("yes")) {
                    return true;
                }
                if (str == QLatin1String("false") || str == QLatin1String("0") || str == QLatin1String("no")) {
                    return false;
                }
                return fallback;
            }
            default:
                break;
            }
            return value.toBool();
        };

        // Build nested terms object
        UniValue termsObj(UniValue::VOBJ);

        // Alice leg (proposer/maker)
        // NOTE: SpotContractBuilder already stores base units (int64), so we read them directly
        if (terms.contains("alice_leg")) {
            QVariantMap aliceLeg = terms["alice_leg"].toMap();
            UniValue aliceLegObj(UniValue::VOBJ);

            bool alice_is_native = variantToBool(aliceLeg.value("is_native"), true);
            QString alice_asset_id = aliceLeg.value("asset_id").toString();
            int64_t alice_units = aliceLeg.value("units").toLongLong();  // Already in base units

            aliceLegObj.pushKV("is_native", alice_is_native);
            if (!alice_is_native && !alice_asset_id.isEmpty()) {
                aliceLegObj.pushKV("asset_id", alice_asset_id.toStdString());
            }
            aliceLegObj.pushKV("units", alice_units);
            termsObj.pushKV("alice_leg", aliceLegObj);
        }

        // Bob leg (acceptor/taker)
        // NOTE: SpotContractBuilder already stores base units (int64), so we read them directly
        if (terms.contains("bob_leg")) {
            QVariantMap bobLeg = terms["bob_leg"].toMap();
            UniValue bobLegObj(UniValue::VOBJ);

            bool bob_is_native = variantToBool(bobLeg.value("is_native"), true);
            QString bob_asset_id = bobLeg.value("asset_id").toString();
            int64_t bob_units = bobLeg.value("units").toLongLong();  // Already in base units

            bobLegObj.pushKV("is_native", bob_is_native);
            if (!bob_is_native && !bob_asset_id.isEmpty()) {
                bobLegObj.pushKV("asset_id", bob_asset_id.toStdString());
            }
            bobLegObj.pushKV("units", bob_units);
            termsObj.pushKV("bob_leg", bobLegObj);
        }

        // Commitment proof requirement (inside terms)
        if (terms.contains("require_commitment_proof")) {
            termsObj.pushKV("require_commitment_proof", variantToBool(terms["require_commitment_proof"], false));
        }

        // Add terms to top-level params
        rpcParams.pushKV("terms", termsObj);

        // Addresses at top level (not inside terms)
        if (terms.contains("alice_dest") && !terms["alice_dest"].toString().isEmpty()) {
            rpcParams.pushKV("alice_address", terms["alice_dest"].toString().toStdString());
        }
        if (terms.contains("bob_dest") && !terms["bob_dest"].toString().isEmpty()) {
            rpcParams.pushKV("bob_address_hint", terms["bob_dest"].toString().toStdString());
        }

        params.push_back(rpcParams);

        UniValue response = m_client_model->node().executeRpc("spot.propose", params, getWalletName().toStdString());

        result.success = true;
        if (response.exists("offer_id")) {
            result.offer_id = QString::fromStdString(response["offer_id"].get_str());
        }
        // CRITICAL: Extract offer object and serialize it (same as repo/forward pattern)
        if (response.exists("offer")) {
            result.offer_json = QString::fromStdString(response["offer"].write());
        }

    } catch (const UniValue& e) {
        result.success = false;
        result.error = "RPC error: " + QString::fromStdString(e.write());
    } catch (const std::exception& e) {
        result.success = false;
        result.error = QString::fromStdString(e.what());
    } catch (...) {
        result.success = false;
        result.error = "Unknown exception occurred";
    }

    return result;
}

WalletModel::SpotImportOfferResult WalletModel::spotImportOffer(const QString& offer_json)
{
    SpotImportOfferResult result;

    if (!m_client_model) {
        result.error = tr("Client model not available");
        return result;
    }

    try {
        UniValue params(UniValue::VARR);

        // Parse JSON string to UniValue object
        UniValue offerVal;
        if (!offerVal.read(offer_json.toStdString())) {
            result.error = "Invalid JSON format";
            return result;
        }

        params.push_back(offerVal);

        UniValue response = m_client_model->node().executeRpc("spot.import_offer", params, getWalletName().toStdString());

        result.success = true;
        if (response.exists("offer_id")) {
            result.offer_id = QString::fromStdString(response["offer_id"].get_str());
        }

    } catch (const UniValue& e) {
        result.success = false;
        result.error = "RPC error: " + QString::fromStdString(e.write());
    } catch (const std::exception& e) {
        result.success = false;
        result.error = QString::fromStdString(e.what());
    } catch (...) {
        result.success = false;
        result.error = "Unknown exception occurred";
    }

    return result;
}

WalletModel::SpotAcceptResult WalletModel::spotAccept(const QString& offer_id, bool confirmed, const QString& bobAddress)
{
    SpotAcceptResult result;

    if (!m_client_model) {
        result.error = tr("Client model not available");
        return result;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(offer_id.toStdString());

        UniValue options(UniValue::VOBJ);
        options.pushKV("confirmed", confirmed);
        if (!bobAddress.isEmpty()) {
            options.pushKV("bob_address", bobAddress.toStdString());
        }
        params.push_back(options);

        UniValue response = m_client_model->node().executeRpc("spot.accept", params, getWalletName().toStdString());

        result.success = true;
        if (response.exists("accept_id")) {
            result.accept_id = QString::fromStdString(response["accept_id"].get_str());
        }
        if (response.exists("acceptance")) {
            result.acceptance_json = QString::fromStdString(response["acceptance"].write());
        }

    } catch (const UniValue& e) {
        result.success = false;
        result.error = "RPC error: " + QString::fromStdString(e.write());
    } catch (const std::exception& e) {
        result.success = false;
        result.error = QString::fromStdString(e.what());
    } catch (...) {
        result.success = false;
        result.error = "Unknown exception occurred";
    }

    return result;
}

WalletModel::SpotImportAcceptanceResult WalletModel::spotImportAcceptance(const QString& offer_id, const QString& acceptance_json)
{
    SpotImportAcceptanceResult result;

    if (!m_client_model) {
        result.error = tr("Client model not available");
        return result;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(offer_id.toStdString());

        // Parse JSON string to UniValue object
        UniValue acceptanceVal;
        if (!acceptanceVal.read(acceptance_json.toStdString())) {
            result.error = "Invalid JSON format";
            return result;
        }

        params.push_back(acceptanceVal);

        UniValue response = m_client_model->node().executeRpc("spot.import_acceptance", params, getWalletName().toStdString());

        result.success = true;
        if (response.exists("accept_id")) {
            result.accept_id = QString::fromStdString(response["accept_id"].get_str());
        }

    } catch (const UniValue& e) {
        result.success = false;
        result.error = "RPC error: " + QString::fromStdString(e.write());
    } catch (const std::exception& e) {
        result.success = false;
        result.error = QString::fromStdString(e.what());
    } catch (...) {
        result.success = false;
        result.error = "Unknown exception occurred";
    }

    return result;
}

WalletModel::SpotBuildAtomicResult WalletModel::spotBuildAtomic(const QString& offer_id, const QVariantMap& options)
{
    SpotBuildAtomicResult result;

    if (!m_client_model) {
        result.error = tr("Client model not available");
        return result;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(offer_id.toStdString());

        // Add options if provided (for augmentation pattern)
        if (!options.isEmpty()) {
            UniValue opts(UniValue::VOBJ);

            // Handle psbt option for augmentation (taker path)
            if (options.contains("psbt")) {
                opts.pushKV("psbt", options["psbt"].toString().toStdString());
            }

            // Handle fee strategy if provided
            if (options.contains("strategy")) {
                opts.pushKV("strategy", options["strategy"].toString().toStdString());
            }

            // Handle fee_rate if provided (sat/vB)
            if (options.contains("fee_rate")) {
                opts.pushKV("fee_rate", options["fee_rate"].toDouble());
            }

            params.push_back(opts);
        }

        UniValue response = m_client_model->node().executeRpc("spot.build_atomic", params, getWalletName().toStdString());

        result.success = true;
        if (response.exists("psbt")) {
            result.psbt = QString::fromStdString(response["psbt"].get_str());
        }
        if (response.exists("asset_change_index")) {
            result.asset_change_index = response["asset_change_index"].getInt<int>();
        }
        if (response.exists("my_role")) {
            result.my_role = QString::fromStdString(response["my_role"].get_str());
        }
        if (response.exists("complete")) {
            result.complete = response["complete"].get_bool();
        }

    } catch (const UniValue& e) {
        result.success = false;
        result.error = "RPC error: " + QString::fromStdString(e.write());
    } catch (const std::exception& e) {
        result.success = false;
        result.error = QString::fromStdString(e.what());
    } catch (...) {
        result.success = false;
        result.error = "Unknown exception occurred";
    }

    return result;
}

WalletModel::SpotMarkExecutedResult WalletModel::spotMarkExecuted(const QString& offer_id, const QString& txid)
{
    SpotMarkExecutedResult result;

    if (!m_client_model) {
        result.error = tr("Client model not available");
        return result;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(offer_id.toStdString());
        params.push_back(txid.toStdString());

        // Wallet name is required so the correct wallet registry is updated
        (void)m_client_model->node().executeRpc("spot.mark_executed", params, getWalletName().toStdString());
        result.success = true;
    } catch (const UniValue& e) {
        result.success = false;
        result.error = "RPC error: " + QString::fromStdString(e.write());
    } catch (const std::exception& e) {
        result.success = false;
        result.error = QString::fromStdString(e.what());
    } catch (...) {
        result.success = false;
        result.error = tr("Unknown exception occurred");
    }

    return result;
}

// ============================================================================
// Contract State Query
// ============================================================================

WalletModel::ContractStatusResult WalletModel::getContractStatus(const QString& contract_id)
{
    ContractStatusResult result;

    if (!m_client_model) {
        result.error = tr("Client model not available");
        return result;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(contract_id.toStdString());

        UniValue response = m_client_model->node().executeRpc("contract.status", params, getWalletName().toStdString());

        result.success = true;
        result.id = QString::fromStdString(response["id"].get_str());
        // Family discriminator: the difficulty payload uses "type"=difficulty with "kind"=cfd/option
        // (product); repo/spot/forward use "kind" as the family. Prefer "type" for difficulty so the UI
        // does not misclassify a difficulty contract as its product kind.
        if (response.exists("type") && response["type"].isStr() && response["type"].get_str() == "difficulty") {
            result.kind = QStringLiteral("difficulty");
            if (response.exists("kind") && response["kind"].isStr()) {
                result.product = QString::fromStdString(response["kind"].get_str());
            }
        } else if (response.exists("kind") && response["kind"].isStr()) {
            result.kind = QString::fromStdString(response["kind"].get_str());
        }
        result.state = QString::fromStdString(response["state"].get_str());

        if (response.exists("offer") && response["offer"].isObject()) {
            result.offer = uniValueToVariantMap(response["offer"]);
        }

        if (response.exists("deadlines") && response["deadlines"].isObject()) {
            result.deadlines = uniValueToVariantMap(response["deadlines"]);
        }

        if (response.exists("utxos") && response["utxos"].isArray()) {
            const UniValue& utxos = response["utxos"];
            for (size_t i = 0; i < utxos.size(); ++i) {
                result.utxos.append(uniValueToVariantMap(utxos[i]));
            }
        }

        if (response.exists("closure") && response["closure"].isObject()) {
            result.closure = uniValueToVariantMap(response["closure"]);
        }

        if (response.exists("confs")) {
            result.confs = response["confs"].getInt<int>();
        }

        LogPrintf("WalletModel::getContractStatus - id=%s, kind=%s, state=%s, utxos=%zu\n",
                  result.id.toStdString().c_str(), result.kind.toStdString().c_str(),
                  result.state.toStdString().c_str(), result.utxos.size());

    } catch (const UniValue& e) {
        result.success = false;
        result.error = tr("RPC error: %1").arg(QString::fromStdString(e.write()));
    } catch (const std::exception& e) {
        result.success = false;
        result.error = tr("Error: %1").arg(QString::fromStdString(e.what()));
    } catch (...) {
        result.success = false;
        result.error = tr("Unknown error occurred");
    }

    return result;
}

int WalletModel::getNumBlocks() const
{
    if (!m_client_model) {
        return 0;
    }
    return m_client_model->getNumBlocks();
}

// ============================================================================
// Pricing RPC Wrappers
// ============================================================================

WalletModel::PricingRepoQuoteResult WalletModel::pricingRepoQuote(
    const QString& source_type,
    const QString& registry_id,
    const QVariantMap& inline_terms,
    const QString& report_asset,
    bool report_is_native,
    bool compute_greeks,
    const QString& price_source,
    bool include_inception_cashflows)
{
    PricingRepoQuoteResult result;

    if (!m_client_model) {
        result.error = tr("Client model not available");
        return result;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(source_type.toStdString());

        if (source_type == "registry") {
            params.push_back(registry_id.toStdString());
            params.push_back(UniValue(UniValue::VOBJ)); // empty inline_terms
        } else if (source_type == "inline") {
            params.push_back(""); // empty registry_id

            // Build inline_terms object
            UniValue termsObj(UniValue::VOBJ);
            termsObj.pushKV("principal_asset", inline_terms.value("principal_asset", "").toString().toStdString());
            termsObj.pushKV("principal_is_native", inline_terms.value("principal_is_native", false).toBool());
            const qulonglong principal_units = inline_terms.value("principal_units", 0).toULongLong();
            termsObj.pushKV("principal_units", static_cast<int64_t>(principal_units));
            termsObj.pushKV("interest_asset", inline_terms.value("interest_asset", "").toString().toStdString());
            termsObj.pushKV("interest_is_native", inline_terms.value("interest_is_native", false).toBool());
            const qulonglong interest_units = inline_terms.value("interest_units", 0).toULongLong();
            termsObj.pushKV("interest_units", static_cast<int64_t>(interest_units));
            termsObj.pushKV("collateral_asset", inline_terms.value("collateral_asset", "").toString().toStdString());
            termsObj.pushKV("collateral_is_native", inline_terms.value("collateral_is_native", false).toBool());
            const qulonglong collateral_units = inline_terms.value("collateral_units", 0).toULongLong();
            termsObj.pushKV("collateral_units", static_cast<int64_t>(collateral_units));
            termsObj.pushKV("maturity_height", inline_terms.value("maturity_height", 0).toInt());
            termsObj.pushKV("safety_k", inline_terms.value("safety_k", 144).toInt());

            params.push_back(termsObj);
        }

        // Default to native TSC when no explicit report asset is provided
        const bool report_is_native_effective = report_asset.isEmpty() ? true : report_is_native;
        params.push_back(report_asset.toStdString());
        params.push_back(report_is_native_effective);
        params.push_back(compute_greeks);
        params.push_back(price_source.toStdString());
        params.push_back(include_inception_cashflows);

        UniValue response = m_client_model->node().executeRpc("pricing.repo.quote", params, getWalletName().toStdString());

        result.success = true;

        // Extract numeric fields
        if (response.exists("principal_pv") && response["principal_pv"].isNum()) {
            result.principal_pv = response["principal_pv"].get_real();
        }
        if (response.exists("interest_pv") && response["interest_pv"].isNum()) {
            result.interest_pv = response["interest_pv"].get_real();
        }
        if (response.exists("collateral_pv") && response["collateral_pv"].isNum()) {
            result.collateral_pv = response["collateral_pv"].get_real();
        }
        if (response.exists("collateral_option") && response["collateral_option"].isNum()) {
            result.collateral_option = response["collateral_option"].get_real();
        }
        if (response.exists("lender_mtm") && response["lender_mtm"].isNum()) {
            result.lender_mtm = response["lender_mtm"].get_real();
        }
        if (response.exists("borrower_mtm") && response["borrower_mtm"].isNum()) {
            result.borrower_mtm = response["borrower_mtm"].get_real();
        }
        if (response.exists("coverage_ratio") && response["coverage_ratio"].isNum()) {
            result.coverage_ratio = response["coverage_ratio"].get_real();
        }
        if (response.exists("ltv_pct") && response["ltv_pct"].isNum()) {
            result.ltv_pct = response["ltv_pct"].get_real();
        }
        if (response.exists("over_collat_pct") && response["over_collat_pct"].isNum()) {
            result.over_collat_pct = response["over_collat_pct"].get_real();
        }

        // Extract collateral_greeks
        if (response.exists("collateral_greeks") && response["collateral_greeks"].isObject()) {
            result.collateral_greeks = uniValueToVariantMap(response["collateral_greeks"]);
        }

        // Extract warnings
        if (response.exists("warnings") && response["warnings"].isArray()) {
            const UniValue& warnings = response["warnings"];
            for (size_t i = 0; i < warnings.size(); ++i) {
                result.warnings.append(uniValueToVariantMap(warnings[i]));
            }
        }

    } catch (const UniValue& e) {
        result.success = false;
        result.error = tr("RPC error: %1").arg(QString::fromStdString(e.write()));
    } catch (const std::exception& e) {
        result.success = false;
        result.error = tr("Error: %1").arg(QString::fromStdString(e.what()));
    } catch (...) {
        result.success = false;
        result.error = tr("Unknown error occurred");
    }

    return result;
}

WalletModel::PricingForwardQuoteResult WalletModel::pricingForwardQuote(
    const QString& source_type,
    const QString& registry_id,
    const QVariantMap& inline_terms,
    const QString& report_asset,
    bool report_is_native,
    bool compute_greeks,
    const QString& price_source)
{
    LogPrintf( "WalletModel::pricingForwardQuote called: source_type=%s price_source=%s\n", source_type.toStdString(), price_source.toStdString());
    PricingForwardQuoteResult result;

    if (!m_client_model) {
        result.error = tr("Client model not available");
        LogPrintf( "WalletModel::pricingForwardQuote: client model not available\n");
        return result;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(source_type.toStdString());

        if (source_type == "registry") {
            params.push_back(registry_id.toStdString());
            params.push_back(UniValue(UniValue::VOBJ)); // empty inline_terms
        } else if (source_type == "inline") {
            params.push_back(""); // empty registry_id

            // Build inline_terms object with forward contract structure
            // Map from UI field names (long_party_*, short_party_*) to RPC API names (alice_*, bob_*)
            UniValue termsObj(UniValue::VOBJ);

            // Alice (Long party) delivery leg
            termsObj.pushKV("alice_deliver_asset", inline_terms.value("long_party_deliver_asset", "").toString().toStdString());
            termsObj.pushKV("alice_deliver_is_native", inline_terms.value("long_party_deliver_is_native", false).toBool());
            termsObj.pushKV("alice_deliver_units", static_cast<int64_t>(inline_terms.value("long_party_deliver_units", 0).toLongLong()));

            // Bob (Short party) delivery leg
            termsObj.pushKV("bob_deliver_asset", inline_terms.value("short_party_deliver_asset", "").toString().toStdString());
            termsObj.pushKV("bob_deliver_is_native", inline_terms.value("short_party_deliver_is_native", false).toBool());
            termsObj.pushKV("bob_deliver_units", static_cast<int64_t>(inline_terms.value("short_party_deliver_units", 0).toLongLong()));

            // Alice (Long party) initial margin
            termsObj.pushKV("alice_im_asset", inline_terms.value("long_party_margin_asset", "").toString().toStdString());
            termsObj.pushKV("alice_im_is_native", inline_terms.value("long_party_margin_is_native", false).toBool());
            termsObj.pushKV("alice_im_units", static_cast<int64_t>(inline_terms.value("long_party_margin_units", 0).toLongLong()));

            // Bob (Short party) initial margin
            termsObj.pushKV("bob_im_asset", inline_terms.value("short_party_margin_asset", "").toString().toStdString());
            termsObj.pushKV("bob_im_is_native", inline_terms.value("short_party_margin_is_native", false).toBool());
            termsObj.pushKV("bob_im_units", static_cast<int64_t>(inline_terms.value("short_party_margin_units", 0).toLongLong()));

            // Premium (optional)
            termsObj.pushKV("premium_asset", inline_terms.value("premium_asset", "").toString().toStdString());
            termsObj.pushKV("premium_is_native", inline_terms.value("premium_is_native", false).toBool());
            termsObj.pushKV("premium_units", static_cast<int64_t>(inline_terms.value("premium_units", 0).toLongLong()));

            // Deadlines (RPC only uses deadline_short, not deadline_long)
            termsObj.pushKV("deadline_short", inline_terms.value("deadline_short", 0).toInt());
            termsObj.pushKV("safety_k", inline_terms.value("safety_k", 5).toInt());

            params.push_back(termsObj);
        }

        // Default to native TSC when no explicit report asset is provided
        const bool report_is_native_effective = report_asset.isEmpty() ? true : report_is_native;
        params.push_back(report_asset.toStdString());
        params.push_back(report_is_native_effective);
        params.push_back(compute_greeks);
        params.push_back(price_source.toStdString());

        UniValue response = m_client_model->node().executeRpc("pricing.forward.quote", params, getWalletName().toStdString());

        LogPrintf( "WalletModel::pricingForwardQuote: RPC succeeded, extracting results\n");
        result.success = true;

        // Extract numeric fields
        if (response.exists("pv_receive") && response["pv_receive"].isNum()) {
            result.pv_receive = response["pv_receive"].get_real();
        }
        if (response.exists("pv_pay") && response["pv_pay"].isNum()) {
            result.pv_pay = response["pv_pay"].get_real();
        }
        if (response.exists("net_spread_value") && response["net_spread_value"].isNum()) {
            result.net_spread_value = response["net_spread_value"].get_real();
        }
        if (response.exists("premium_pv") && response["premium_pv"].isNum()) {
            result.premium_pv = response["premium_pv"].get_real();
        }
        if (response.exists("alice_short_call_value") && response["alice_short_call_value"].isNum()) {
            result.alice_short_call_value = response["alice_short_call_value"].get_real();
        }
        if (response.exists("alice_long_put_value") && response["alice_long_put_value"].isNum()) {
            result.alice_long_put_value = response["alice_long_put_value"].get_real();
        }
        if (response.exists("alice_mtm") && response["alice_mtm"].isNum()) {
            result.alice_mtm = response["alice_mtm"].get_real();
        }
        if (response.exists("bob_mtm") && response["bob_mtm"].isNum()) {
            result.bob_mtm = response["bob_mtm"].get_real();
        }
        if (response.exists("im_coverage_alice") && response["im_coverage_alice"].isNum()) {
            result.im_coverage_alice = response["im_coverage_alice"].get_real();
        }
        if (response.exists("im_coverage_bob") && response["im_coverage_bob"].isNum()) {
            result.im_coverage_bob = response["im_coverage_bob"].get_real();
        }

        // Extract greeks
        if (response.exists("spread_greeks_call") && response["spread_greeks_call"].isObject()) {
            result.spread_greeks_call = uniValueToVariantMap(response["spread_greeks_call"]);
        }
        if (response.exists("spread_greeks_put") && response["spread_greeks_put"].isObject()) {
            result.spread_greeks_put = uniValueToVariantMap(response["spread_greeks_put"]);
        }

        // Extract warnings
        if (response.exists("warnings") && response["warnings"].isArray()) {
            const UniValue& warnings = response["warnings"];
            for (size_t i = 0; i < warnings.size(); ++i) {
                result.warnings.append(uniValueToVariantMap(warnings[i]));
            }
        }

        LogPrintf( "WalletModel::pricingForwardQuote: Returning success with alice_mtm=%f bob_mtm=%f\n", result.alice_mtm, result.bob_mtm);

    } catch (const UniValue& e) {
        result.success = false;
        result.error = tr("RPC error: %1").arg(QString::fromStdString(e.write()));
        LogPrintf( "WalletModel::pricingForwardQuote: RPC error - %s\n", e.write());
    } catch (const std::exception& e) {
        result.success = false;
        result.error = tr("Error: %1").arg(QString::fromStdString(e.what()));
        LogPrintf( "WalletModel::pricingForwardQuote: Exception - %s\n", e.what());
    } catch (...) {
        result.success = false;
        result.error = tr("Unknown error occurred");
        LogPrintf( "WalletModel::pricingForwardQuote: Unknown error\n");
    }

    return result;
}

WalletModel::PricingDifficultyQuoteResult WalletModel::pricingDifficultyQuote(
    const QString& source_type,
    const QString& registry_id,
    const QVariantMap& inline_terms,
    bool compute_greeks,
    quint32 forecast_nbits,
    const QString& price_source)
{
    PricingDifficultyQuoteResult result;

    if (!m_client_model) {
        result.error = tr("Client model not available");
        return result;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(source_type.toStdString());

        if (source_type == "registry") {
            params.push_back(registry_id.toStdString());
            params.push_back(UniValue(UniValue::VNULL));
        } else if (source_type == "inline") {
            params.push_back("");

            UniValue termsObj(UniValue::VOBJ);
            const QString kind = inline_terms.value("kind", "cfd").toString();
            termsObj.pushKV("kind", kind.toStdString());
            termsObj.pushKV("strike_nbits", inline_terms.value("strike_nbits", 0).toUInt());
            termsObj.pushKV("fixing_height", inline_terms.value("fixing_height", 0).toUInt());
            termsObj.pushKV("settle_lock_height", inline_terms.value("settle_lock_height", 0).toUInt());

            if (kind == "option") {
                termsObj.pushKV("writer_side", inline_terms.value("writer_side", "short").toString().toStdString());
                termsObj.pushKV("im", inline_terms.value("im", "0").toString().toStdString());
                termsObj.pushKV("lambda_q", inline_terms.value("lambda_q", 0).toUInt());
                termsObj.pushKV("premium", inline_terms.value("premium", "0").toString().toStdString());
            } else {
                UniValue longObj(UniValue::VOBJ);
                longObj.pushKV("im", inline_terms.value("long_im", "0").toString().toStdString());
                longObj.pushKV("lambda_q", inline_terms.value("long_lambda_q", 0).toUInt());
                UniValue shortObj(UniValue::VOBJ);
                shortObj.pushKV("im", inline_terms.value("short_im", "0").toString().toStdString());
                shortObj.pushKV("lambda_q", inline_terms.value("short_lambda_q", 0).toUInt());
                termsObj.pushKV("long", longObj);
                termsObj.pushKV("short", shortObj);
            }

            params.push_back(termsObj);
        }

        if (forecast_nbits != 0) {
            params.push_back(static_cast<uint64_t>(forecast_nbits));
        } else {
            params.push_back(UniValue(UniValue::VNULL));
        }
        params.push_back(compute_greeks);
        params.push_back(price_source.toStdString());

        UniValue response = m_client_model->node().executeRpc(
            "pricing.difficulty.quote", params, getWalletName().toStdString());

        result.success = true;
        if (response.exists("kind") && response["kind"].isStr()) {
            result.kind = QString::fromStdString(response["kind"].get_str());
        }
        if (response.exists("writer_side") && response["writer_side"].isStr()) {
            result.writer_side = QString::fromStdString(response["writer_side"].get_str());
        }
        if (response.exists("expected_long_mtm") && response["expected_long_mtm"].isNum()) {
            result.expected_long_mtm = response["expected_long_mtm"].get_real();
        }
        if (response.exists("expected_short_mtm") && response["expected_short_mtm"].isNum()) {
            result.expected_short_mtm = response["expected_short_mtm"].get_real();
        }
        if (response.exists("expected_writer_mtm") && response["expected_writer_mtm"].isNum()) {
            result.expected_writer_mtm = response["expected_writer_mtm"].get_real();
        }
        if (response.exists("expected_buyer_mtm") && response["expected_buyer_mtm"].isNum()) {
            result.expected_buyer_mtm = response["expected_buyer_mtm"].get_real();
        }
        if (response.exists("long_delta_to_difficulty") && response["long_delta_to_difficulty"].isNum()) {
            result.long_delta_to_difficulty = response["long_delta_to_difficulty"].get_real();
        }
        if (response.exists("short_delta_to_difficulty") && response["short_delta_to_difficulty"].isNum()) {
            result.short_delta_to_difficulty = response["short_delta_to_difficulty"].get_real();
        }
        if (response.exists("writer_delta_to_difficulty") && response["writer_delta_to_difficulty"].isNum()) {
            result.writer_delta_to_difficulty = response["writer_delta_to_difficulty"].get_real();
        }
        if (response.exists("buyer_delta_to_difficulty") && response["buyer_delta_to_difficulty"].isNum()) {
            result.buyer_delta_to_difficulty = response["buyer_delta_to_difficulty"].get_real();
        }
        auto read_diff_num = [&](const char* key, double& dst) {
            if (response.exists(key) && response[key].isNum()) dst = response[key].get_real();
        };
        read_diff_num("long_vega", result.long_vega);
        read_diff_num("short_vega", result.short_vega);
        read_diff_num("writer_vega", result.writer_vega);
        read_diff_num("buyer_vega", result.buyer_vega);
        read_diff_num("long_theta", result.long_theta);
        read_diff_num("short_theta", result.short_theta);
        read_diff_num("writer_theta", result.writer_theta);
        read_diff_num("buyer_theta", result.buyer_theta);
        read_diff_num("sigma", result.sigma);
        read_diff_num("tau_years", result.tau_years);
        read_diff_num("discount_factor", result.discount_factor);
        read_diff_num("current_difficulty_ratio", result.current_difficulty_ratio);
        read_diff_num("forecast_difficulty_ratio", result.forecast_difficulty_ratio);
        if (response.exists("forward_provenance") && response["forward_provenance"].isStr()) {
            result.forward_provenance = QString::fromStdString(response["forward_provenance"].get_str());
        }
        if (response.exists("fixing_reached") && response["fixing_reached"].isBool()) {
            result.fixing_reached = response["fixing_reached"].get_bool();
        }
        if (response.exists("current_nbits") && response["current_nbits"].isNum()) {
            result.current_nbits = response["current_nbits"].getInt<int64_t>();
        }
        if (response.exists("forecast_nbits") && response["forecast_nbits"].isNum()) {
            result.forecast_nbits = response["forecast_nbits"].getInt<int64_t>();
        }
        if (response.exists("model_unreliable") && response["model_unreliable"].isBool()) {
            result.model_unreliable = response["model_unreliable"].get_bool();
        }
        if (response.exists("warnings") && response["warnings"].isArray()) {
            const UniValue& warnings = response["warnings"];
            for (size_t i = 0; i < warnings.size(); ++i) {
                result.warnings.append(uniValueToVariantMap(warnings[i]));
            }
        }
    } catch (const UniValue& e) {
        result.success = false;
        result.error = tr("RPC error: %1").arg(QString::fromStdString(e.write()));
    } catch (const std::exception& e) {
        result.success = false;
        result.error = tr("Error: %1").arg(QString::fromStdString(e.what()));
    } catch (...) {
        result.success = false;
        result.error = tr("Unknown error occurred");
    }

    return result;
}

WalletModel::PricingMarketStatusResult WalletModel::pricingMarketStatus()
{
    PricingMarketStatusResult result;

    if (!m_client_model) {
        result.error = tr("Client model not available");
        return result;
    }

    try {
        UniValue params(UniValue::VARR);
        UniValue response = m_client_model->node().executeRpc("pricing.market.status", params, getWalletName().toStdString());

        result.success = true;

        // Extract market data
        if (response.exists("curves") && response["curves"].isObject()) {
            result.curves = uniValueToVariantMap(response["curves"]);
        }
        if (response.exists("fx_quotes") && response["fx_quotes"].isObject()) {
            result.fx_quotes = uniValueToVariantMap(response["fx_quotes"]);
        }
        if (response.exists("vol_surfaces") && response["vol_surfaces"].isObject()) {
            result.vol_surfaces = uniValueToVariantMap(response["vol_surfaces"]);
        }
        if (response.exists("correlation") && response["correlation"].isObject()) {
            result.correlation = uniValueToVariantMap(response["correlation"]);
        }

        // Extract counts
        if (response.exists("total_curves")) {
            result.total_curves = response["total_curves"].getInt<int>();
        }
        if (response.exists("total_fx")) {
            result.total_fx = response["total_fx"].getInt<int>();
        }
        if (response.exists("total_vol_surfaces")) {
            result.total_vol_surfaces = response["total_vol_surfaces"].getInt<int>();
        }
        if (response.exists("has_correlation")) {
            result.has_correlation = response["has_correlation"].get_bool();
        }

    } catch (const UniValue& e) {
        result.success = false;
        result.error = tr("RPC error: %1").arg(QString::fromStdString(e.write()));
    } catch (const std::exception& e) {
        result.success = false;
        result.error = tr("Error: %1").arg(QString::fromStdString(e.what()));
    } catch (...) {
        result.success = false;
        result.error = tr("Unknown error occurred");
    }

    return result;
}

WalletModel::PricingMarketCalibrateResult WalletModel::pricingMarketCalibrate(
    const QString& source,
    double max_age_hours,
    double decay_tau,
    uint64_t min_volume)
{
    PricingMarketCalibrateResult result;

    if (!m_client_model) {
        result.error = tr("Client model not available");
        return result;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(source.toStdString());
        params.push_back(max_age_hours);
        params.push_back(decay_tau);
        params.push_back(min_volume);

        UniValue response = m_client_model->node().executeRpc("pricing.market.calibrate", params, getWalletName().toStdString());

        result.success = true;

        // Extract update counts
        if (response.exists("curves_updated")) {
            result.curves_updated = response["curves_updated"].getInt<int>();
        }
        if (response.exists("fx_updated")) {
            result.fx_updated = response["fx_updated"].getInt<int>();
        }
        if (response.exists("vol_surfaces_updated")) {
            result.vol_surfaces_updated = response["vol_surfaces_updated"].getInt<int>();
        }
        if (response.exists("correlation_updated")) {
            result.correlation_updated = response["correlation_updated"].get_bool();
        }

        // Extract warnings
        if (response.exists("warnings") && response["warnings"].isArray()) {
            const UniValue& warnings = response["warnings"];
            for (size_t i = 0; i < warnings.size(); ++i) {
                result.warnings.append(uniValueToVariantMap(warnings[i]));
            }
        }

    } catch (const UniValue& e) {
        result.success = false;
        result.error = tr("RPC error: %1").arg(QString::fromStdString(e.write()));
    } catch (const std::exception& e) {
        result.success = false;
        result.error = tr("Error: %1").arg(QString::fromStdString(e.what()));
    } catch (...) {
        result.success = false;
        result.error = tr("Unknown error occurred");
    }

    return result;
}

bool WalletModel::pricingMarketPushFX(const QString& base_asset,
                                     const QString& quote_asset,
                                     double spot_rate,
                                     double bid_ask_bps,
                                     const QString& source,
                                     bool base_is_native,
                                     bool quote_is_native)
{
    UniValue params(UniValue::VARR);
    params.push_back(base_asset.toStdString());
    params.push_back(quote_asset.toStdString());
    params.push_back(spot_rate);
    params.push_back(bid_ask_bps);
    params.push_back(source.toStdString());
    params.push_back(base_is_native);
    params.push_back(quote_is_native);

    try {
        UniValue response = m_client_model->node().executeRpc("pricing.market.push_fx", params, getWalletName().toStdString());
        bool success = response["success"].get_bool();
        if (!success && response.exists("error")) {
            LogPrintf("pricing.market.push_fx failed for %s/%s: %s\n",
                     base_asset.toStdString().c_str(),
                     quote_asset.toStdString().c_str(),
                     response["error"].get_str().c_str());
        }
        return success;
    } catch (const std::exception& e) {
        LogPrintf("Error calling pricing.market.push_fx for %s/%s: %s\n",
                 base_asset.toStdString().c_str(),
                 quote_asset.toStdString().c_str(),
                 e.what());
        return false;
    }
}

bool WalletModel::pricingMarketPushVolSurface(const QString& asset_id,
                                             double volatility,
                                             const QString& source)
{
    // Create a simple 3x3 grid for flat vol surface
    // Strikes: [0.8, 1.0, 1.2] (80% to 120% moneyness)
    // Maturities: [30, 90, 180] days
    UniValue params(UniValue::VARR);
    params.push_back(asset_id.toStdString());

    UniValue strikes(UniValue::VARR);
    strikes.push_back(0.8);
    strikes.push_back(1.0);
    strikes.push_back(1.2);
    params.push_back(strikes);

    UniValue maturities(UniValue::VARR);
    maturities.push_back(30);
    maturities.push_back(90);
    maturities.push_back(180);
    params.push_back(maturities);

    // Flat vol surface (same vol for all strikes/maturities)
    UniValue vols(UniValue::VARR);
    for (int i = 0; i < 3; ++i) {
        UniValue row(UniValue::VARR);
        for (int j = 0; j < 3; ++j) {
            row.push_back(volatility / 100.0);  // Convert from % to decimal
        }
        vols.push_back(row);
    }
    params.push_back(vols);
    params.push_back(source.toStdString());

    try {
        UniValue response = m_client_model->node().executeRpc("pricing.market.push_vol_surface", params, getWalletName().toStdString());
        bool success = response["success"].get_bool();
        if (!success && response.exists("error")) {
            LogPrintf("pricing.market.push_vol_surface failed for %s: %s\n",
                     asset_id.toStdString().c_str(),
                     response["error"].get_str().c_str());
        }
        return success;
    } catch (const std::exception& e) {
        LogPrintf("Error calling pricing.market.push_vol_surface for %s: %s\n",
                 asset_id.toStdString().c_str(), e.what());
        return false;
    }
}

bool WalletModel::pricingMarketPushCurve(const QString& asset_id,
                                        bool is_native,
                                        double interest_rate,
                                        const QString& source)
{
    // Create a simple flat curve
    // Tenors: [7, 30, 90, 180, 365] days
    UniValue params(UniValue::VARR);
    params.push_back(asset_id.toStdString());
    params.push_back(is_native);

    UniValue tenors(UniValue::VARR);
    tenors.push_back(7);
    tenors.push_back(30);
    tenors.push_back(90);
    tenors.push_back(180);
    tenors.push_back(365);
    params.push_back(tenors);

    // Flat curve (same rate for all tenors)
    UniValue rates(UniValue::VARR);
    double rate_decimal = interest_rate / 100.0;  // Convert from % to decimal
    for (int i = 0; i < 5; ++i) {
        rates.push_back(rate_decimal);
    }
    params.push_back(rates);
    params.push_back(source.toStdString());

    try {
        UniValue response = m_client_model->node().executeRpc("pricing.market.push_curve", params, getWalletName().toStdString());
        bool success = response["success"].get_bool();
        if (!success && response.exists("error")) {
            LogPrintf("pricing.market.push_curve failed for asset %s: %s\n",
                     asset_id.toStdString().c_str(),
                     response["error"].get_str().c_str());
        }
        return success;
    } catch (const std::exception& e) {
        LogPrintf("Error calling pricing.market.push_curve for asset %s: %s\n",
                 asset_id.toStdString().c_str(),
                 e.what());
        return false;
    }
}

bool WalletModel::pricingMarketPushCurve(const QString& asset_id,
                                        bool is_native,
                                        const QVector<int>& tenors_days,
                                        const QVector<double>& rates,
                                        const QString& source)
{
    if (tenors_days.size() != rates.size()) {
        LogPrintf("Error: tenors and rates size mismatch in pricingMarketPushCurve\n");
        return false;
    }

    UniValue params(UniValue::VARR);
    params.push_back(asset_id.toStdString());
    params.push_back(is_native);

    UniValue tenors(UniValue::VARR);
    for (int tenor : tenors_days) {
        tenors.push_back(tenor);
    }
    params.push_back(tenors);

    UniValue rates_arr(UniValue::VARR);
    for (double rate : rates) {
        rates_arr.push_back(rate / 100.0);  // Convert from % to decimal
    }
    params.push_back(rates_arr);
    params.push_back(source.toStdString());

    try {
        UniValue response = m_client_model->node().executeRpc("pricing.market.push_curve", params, getWalletName().toStdString());
        bool success = response["success"].get_bool();
        if (!success && response.exists("error")) {
            LogPrintf("pricing.market.push_curve failed for asset %s: %s\n",
                     asset_id.toStdString().c_str(),
                     response["error"].get_str().c_str());
        }
        return success;
    } catch (const std::exception& e) {
        LogPrintf("Error calling pricing.market.push_curve for asset %s: %s\n",
                 asset_id.toStdString().c_str(),
                 e.what());
        return false;
    }
}

bool WalletModel::pricingMarketPushCorrelation(const QStringList& asset_ids,
                                              const QVector<QVector<double>>& correlation_matrix)
{
    UniValue params(UniValue::VARR);

    // Build asset_ids array
    UniValue ids_arr(UniValue::VARR);
    for (const QString& id : asset_ids) {
        ids_arr.push_back(id.toStdString());
    }
    params.push_back(ids_arr);

    // Build correlation matrix array
    UniValue corr_arr(UniValue::VARR);
    for (const QVector<double>& row : correlation_matrix) {
        UniValue row_arr(UniValue::VARR);
        for (double val : row) {
            row_arr.push_back(val);
        }
        corr_arr.push_back(row_arr);
    }
    params.push_back(corr_arr);

    try {
        UniValue response = m_client_model->node().executeRpc("pricing.market.push_correlation", params, getWalletName().toStdString());
        bool success = response["success"].get_bool();
        if (!success && response.exists("error")) {
            LogPrintf("pricing.market.push_correlation failed: %s\n",
                     response["error"].get_str().c_str());
        }
        return success;
    } catch (const std::exception& e) {
        LogPrintf("Error calling pricing.market.push_correlation: %s\n", e.what());
        return false;
    }
}

QString WalletModel::resolveAssetId(const QString& symbol_or_id)
{
    // First check if it's already a valid 64-char hex string
    QRegularExpression hexPattern("^[0-9a-fA-F]{64}$");
    if (symbol_or_id.length() == 64 && hexPattern.match(symbol_or_id).hasMatch()) {
        return symbol_or_id;
    }

    // Try to resolve as a ticker using the getassetbyticker RPC
    UniValue params(UniValue::VARR);
    params.push_back(symbol_or_id.toUpper().toStdString());

    try {
        UniValue response = m_client_model->node().executeRpc("getassetbyticker", params, "");
        if (response.isObject() && response.exists("asset_id")) {
            return QString::fromStdString(response["asset_id"].get_str());
        }
    } catch (const std::exception& e) {
        LogPrintf("WalletModel::resolveAssetId: Failed to resolve ticker '%s': %s\n",
                 symbol_or_id.toStdString().c_str(), e.what());
    }

    return QString();  // Not found
}
