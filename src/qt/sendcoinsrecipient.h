// Copyright (c) 2024-2025 The TensorCash Core developers
// Copyright (c) 2011-2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_SENDCOINSRECIPIENT_H
#define BITCOIN_QT_SENDCOINSRECIPIENT_H

#include <consensus/amount.h>
#include <serialize.h>
#include <uint256.h>

#include <optional>
#include <string>

#include <QString>

class SendCoinsRecipient
{
public:
    explicit SendCoinsRecipient() : amount(0), fSubtractFeeFromAmount(false), nVersion(SendCoinsRecipient::CURRENT_VERSION) { }
    explicit SendCoinsRecipient(const QString &addr, const QString &_label, const CAmount& _amount, const QString &_message):
        address(addr), label(_label), amount(_amount), message(_message), fSubtractFeeFromAmount(false), nVersion(SendCoinsRecipient::CURRENT_VERSION) {}

    // If from an unauthenticated payment request, this is used for storing
    // the addresses, e.g. address-A<br />address-B<br />address-C.
    // Info: As we don't need to process addresses in here when using
    // payment requests, we can abuse it for displaying an address list.
    // Todo: This is a hack, should be replaced with a cleaner solution!
    QString address;
    QString label;
    CAmount amount;
    // If from a payment request, this is used for storing the memo
    QString message;
    // Keep the payment request around as a serialized string to ensure
    // load/store is lossless.
    std::string sPaymentRequest;
    // Empty if no authentication or invalid signature/cert/etc.
    QString authenticatedMerchant;

    bool fSubtractFeeFromAmount; // memory only

    // Asset-specific fields
    std::optional<uint256> asset_id;  // nullopt for BTC
    QString asset_ticker;              // Display ticker if available
    uint8_t asset_decimals{8};        // Decimals for the asset (8 for BTC)
    uint64_t asset_units{0};          // Amount in smallest asset units
    QString asset_amount_string;      // Decimal amount string from URI (for deferred conversion)

    static const int CURRENT_VERSION = 1;
    int nVersion;

    SERIALIZE_METHODS(SendCoinsRecipient, obj)
    {
        std::string address_str, label_str, message_str, auth_merchant_str, asset_ticker_str;
        bool has_asset_id = false;
        uint256 asset_id_value;

        SER_WRITE(obj, address_str = obj.address.toStdString());
        SER_WRITE(obj, label_str = obj.label.toStdString());
        SER_WRITE(obj, message_str = obj.message.toStdString());
        SER_WRITE(obj, auth_merchant_str = obj.authenticatedMerchant.toStdString());
        SER_WRITE(obj, asset_ticker_str = obj.asset_ticker.toStdString());
        SER_WRITE(obj, has_asset_id = obj.asset_id.has_value());
        SER_WRITE(obj, if (has_asset_id) asset_id_value = obj.asset_id.value());

        READWRITE(obj.nVersion, address_str, label_str, obj.amount, message_str, obj.sPaymentRequest, auth_merchant_str);
        READWRITE(has_asset_id);
        if (has_asset_id) {
            READWRITE(asset_id_value);
        }
        READWRITE(obj.asset_units, obj.asset_decimals, asset_ticker_str);

        SER_READ(obj, obj.address = QString::fromStdString(address_str));
        SER_READ(obj, obj.label = QString::fromStdString(label_str));
        SER_READ(obj, obj.message = QString::fromStdString(message_str));
        SER_READ(obj, obj.authenticatedMerchant = QString::fromStdString(auth_merchant_str));
        SER_READ(obj, obj.asset_ticker = QString::fromStdString(asset_ticker_str));
        SER_READ(obj, if (has_asset_id) obj.asset_id = asset_id_value);
    }
};

#endif // BITCOIN_QT_SENDCOINSRECIPIENT_H
