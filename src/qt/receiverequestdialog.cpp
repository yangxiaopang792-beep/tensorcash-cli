// Copyright (c) 2024-2025 The TensorCash Core developers
// Copyright (c) 2011-2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/receiverequestdialog.h>
#include <qt/forms/ui_receiverequestdialog.h>

#include <qt/bitcoinunits.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>
#include <qt/qrimagewidget.h>
#include <qt/walletmodel.h>

#include <QDialog>
#include <QString>

#include <bitcoin-build-config.h> // IWYU pragma: keep

ReceiveRequestDialog::ReceiveRequestDialog(QWidget* parent)
    : QDialog(parent, GUIUtil::dialog_flags),
      ui(new Ui::ReceiveRequestDialog)
{
    ui->setupUi(this);
    GUIUtil::handleCloseWindowShortcut(this);
}

ReceiveRequestDialog::~ReceiveRequestDialog()
{
    delete ui;
}

void ReceiveRequestDialog::setModel(WalletModel *_model)
{
    this->model = _model;

    if (_model)
        connect(_model->getOptionsModel(), &OptionsModel::displayUnitChanged, this, &ReceiveRequestDialog::updateDisplayUnit);

    // update the display unit if necessary
    update();
}

void ReceiveRequestDialog::setInfo(const SendCoinsRecipient &_info)
{
    this->info = _info;
    setWindowTitle(tr("Request payment to %1").arg(info.label.isEmpty() ? info.address : info.label));
    QString uri = GUIUtil::formatBitcoinURI(info);

#ifdef USE_QRCODE
    if (ui->qr_code->setQR(uri, info.address)) {
        connect(ui->btnSaveAs, &QPushButton::clicked, ui->qr_code, &QRImageWidget::saveImage);
    } else {
        ui->btnSaveAs->setEnabled(false);
    }
#else
    ui->btnSaveAs->hide();
    ui->qr_code->hide();
#endif

    ui->uri_content->setText("<a href=\"" + uri + "\">" + GUIUtil::HtmlEscape(uri) + "</a>");
    ui->address_content->setText(info.address);

    if (!info.amount) {
        ui->amount_tag->hide();
        ui->amount_content->hide();
    } // Amount is set in updateDisplayUnit() slot.
    updateDisplayUnit();

    if (!info.label.isEmpty()) {
        ui->label_content->setText(info.label);
    } else {
        ui->label_tag->hide();
        ui->label_content->hide();
    }

    if (!info.message.isEmpty()) {
        ui->message_content->setText(info.message);
    } else {
        ui->message_tag->hide();
        ui->message_content->hide();
    }

    // Set asset information
    if (info.asset_id.has_value()) {
        if (!info.asset_ticker.isEmpty()) {
            ui->asset_content->setText(info.asset_ticker);
        } else {
            // Use first 8 chars of asset ID as fallback
            QString shortId = QString::fromStdString(info.asset_id->ToString()).left(8);
            ui->asset_content->setText(shortId + "...");
        }
    } else {
        ui->asset_content->setText("TSC");
    }

    if (!model->getWalletName().isEmpty()) {
        ui->wallet_content->setText(model->getWalletName());
    } else {
        ui->wallet_tag->hide();
        ui->wallet_content->hide();
    }

    ui->btnVerify->setVisible(model->wallet().hasExternalSigner());

    connect(ui->btnVerify, &QPushButton::clicked, [this] {
        model->displayAddress(info.address.toStdString());
    });
}

void ReceiveRequestDialog::updateDisplayUnit()
{
    if (!model) return;

    if (info.asset_id.has_value()) {
        // For assets, display using asset-specific formatting
        QString amountText;
        QString amountBase = GUIUtil::formatAssetAmount(info.asset_units, info.asset_decimals);
        if (amountBase.isEmpty()) {
            amountBase = QStringLiteral("0");
        }

        if (!info.asset_ticker.isEmpty()) {
            amountText = amountBase + QLatin1Char(' ') + info.asset_ticker;
        } else if (info.asset_id.has_value()) {
            QString shortId = QString::fromStdString(info.asset_id->ToString()).left(8) + "...";
            amountText = amountBase + QLatin1Char(' ') + shortId;
        } else {
            amountText = amountBase;
        }

        ui->amount_content->setText(amountText);
    } else {
        // For BTC, use standard formatting
        ui->amount_content->setText(BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), info.amount));
    }
}

void ReceiveRequestDialog::on_btnCopyURI_clicked()
{
    GUIUtil::setClipboard(GUIUtil::formatBitcoinURI(info));
}

void ReceiveRequestDialog::on_btnCopyAddress_clicked()
{
    GUIUtil::setClipboard(info.address);
}
