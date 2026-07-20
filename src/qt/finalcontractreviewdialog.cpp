// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <qt/finalcontractreviewdialog.h>
#include <qt/pricingbreakdowndialog.h>
#include <qt/themehelpers.h>
#include <qt/walletmodel.h>

#include <logging.h>
#include <QApplication>
#include <QClipboard>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QFont>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QTextBrowser>
#include <QTextEdit>
#include <QVBoxLayout>
#include <QMessageBox>

namespace {

QString defaultOr(const QString& value, const QString& fallback)
{
    return value.isEmpty() ? fallback : value;
}

QString formatJsonForDisplay(const QString& json)
{
    return json.isEmpty() ? QStringLiteral("{}") : json;
}

} // namespace

FinalContractReviewDialog::FinalContractReviewDialog(const Options& options, QWidget* parent)
    : QDialog(parent),
      m_options(options)
{
    LogPrintf("FinalContractReviewDialog: Constructor called, showFeeSelector=%d\n", m_options.showFeeSelector);
    setWindowTitle(defaultOr(m_options.title, tr("Review Final Contract")));
    setModal(true);
    setMinimumSize(620, 480);
    try {
        buildUi();
        LogPrintf("FinalContractReviewDialog: buildUi() completed successfully\n");
    } catch (const std::exception& e) {
        LogPrintf("FinalContractReviewDialog: buildUi() threw exception: %s\n", e.what());
        throw;
    } catch (...) {
        LogPrintf("FinalContractReviewDialog: buildUi() threw unknown exception\n");
        throw;
    }
}

void FinalContractReviewDialog::buildUi()
{
    QVBoxLayout* mainLayout = new QVBoxLayout(this);

    if (!m_options.headingHtml.isEmpty()) {
        QLabel* heading = new QLabel(m_options.headingHtml, this);
        heading->setWordWrap(true);
        heading->setTextFormat(Qt::RichText);
        mainLayout->addWidget(heading);
    }

    if (!m_options.userRole.isEmpty()) {
        const QString role = m_options.userRole.left(1).toUpper() + m_options.userRole.mid(1).toLower();
        QLabel* roleLabel = new QLabel(tr("<i>Perspective:</i> <b>%1</b>").arg(role), this);
        roleLabel->setTextFormat(Qt::RichText);
        roleLabel->setStyleSheet(ThemeHelpers::mutedLabelStyleSheet());
        mainLayout->addWidget(roleLabel);
    }

    if (!m_options.offerId.isEmpty()) {
        QLabel* offerLabel = new QLabel(
            tr("<b>Offer ID:</b> %1").arg(m_options.offerId.left(16) + "..."),
            this);
        offerLabel->setTextFormat(Qt::RichText);
        mainLayout->addWidget(offerLabel);
    }

    if (!m_options.sessionId.isEmpty()) {
        QLabel* sessionLabel = new QLabel(
            tr("<b>Session:</b> %1").arg(m_options.sessionId.left(16) + "..."),
            this);
        sessionLabel->setTextFormat(Qt::RichText);
        mainLayout->addWidget(sessionLabel);
    }

    m_summaryWidget = new QTextBrowser(this);
    m_summaryWidget->setOpenExternalLinks(false);
    m_summaryWidget->setHtml(defaultOr(m_options.summaryHtml, tr("<i>No summary available.</i>")));
    m_summaryWidget->setMinimumHeight(220);
    mainLayout->addWidget(m_summaryWidget);

    if (!m_options.criticalChecks.isEmpty()) {
        QString checksHtml;
        checksHtml += tr("<ul style='margin-top: 0; margin-bottom: 0; padding-left: 20px;'>");
        for (const QString& item : m_options.criticalChecks) {
            checksHtml += tr("<li>%1</li>").arg(item.toHtmlEscaped());
        }
        checksHtml += tr("</ul>");

        QLabel* checksTitle = new QLabel(tr("<b>Critical Checks</b>"), this);
        checksTitle->setTextFormat(Qt::RichText);
        mainLayout->addWidget(checksTitle);

        QLabel* checksLabel = new QLabel(checksHtml, this);
        checksLabel->setWordWrap(true);
        checksLabel->setTextFormat(Qt::RichText);
        checksLabel->setStyleSheet(QStringLiteral("QLabel { %1 border-left: 4px solid #fbc02d; }").arg(ThemeHelpers::warningPanelStyleSheet()));
        mainLayout->addWidget(checksLabel);
    }

    if (!m_options.footnoteHtml.isEmpty()) {
        QLabel* footnote = new QLabel(m_options.footnoteHtml, this);
        footnote->setWordWrap(true);
        footnote->setTextFormat(Qt::RichText);
        footnote->setStyleSheet(ThemeHelpers::mutedLabelStyleSheet());
        mainLayout->addWidget(footnote);
    }

    // Fee strategy selector (taker only)
    if (m_options.showFeeSelector) {
        LogPrintf("FinalContractReviewDialog: Creating fee strategy selector\n");
        QHBoxLayout* feeLayout = new QHBoxLayout();
        QLabel* feeLabel = new QLabel(tr("<b>Fee Strategy for Your Funding:</b>"), this);
        feeLabel->setTextFormat(Qt::RichText);
        feeLayout->addWidget(feeLabel);

        m_feeStrategyCombo = new QComboBox(this);
        m_feeStrategyCombo->addItem(tr("Low (2 sat/vB)"), QString("low"));
        m_feeStrategyCombo->addItem(tr("Medium (10 sat/vB)"), QString("medium"));
        m_feeStrategyCombo->addItem(tr("High (50 sat/vB)"), QString("high"));
        m_feeStrategyCombo->setCurrentIndex(1); // Default to medium
        m_feeStrategyCombo->setToolTip(tr("Choose the fee rate for funding your side of the contract"));
        feeLayout->addWidget(m_feeStrategyCombo);
        feeLayout->addStretch();
        mainLayout->addLayout(feeLayout);
        LogPrintf("FinalContractReviewDialog: Fee strategy selector created successfully\n");
    } else {
        LogPrintf("FinalContractReviewDialog: Skipping fee strategy selector (showFeeSelector=false)\n");
    }

    QHBoxLayout* auxiliaryButtons = new QHBoxLayout();
    auxiliaryButtons->addStretch();

    if (!m_options.rawJson.isEmpty()) {
        m_rawJsonButton = new QPushButton(
            defaultOr(m_options.rawJsonTitle, tr("View Contract JSON")), this);
        connect(m_rawJsonButton, &QPushButton::clicked,
                this, &FinalContractReviewDialog::onShowRawJson);
        auxiliaryButtons->addWidget(m_rawJsonButton);
    }

    if (!m_options.extraJson.isEmpty()) {
        m_extraJsonButton = new QPushButton(
            defaultOr(m_options.extraJsonButtonLabel, tr("View Details JSON")), this);
        connect(m_extraJsonButton, &QPushButton::clicked,
                this, &FinalContractReviewDialog::onShowExtraJson);
        auxiliaryButtons->addWidget(m_extraJsonButton);
    }

    if (m_options.showPricingButton) {
        m_pricingButton = new QPushButton(tr("View Pricing"), this);
        m_pricingButton->setStyleSheet(
            "QPushButton { "
            "background-color: #2196f3; "
            "color: white; "
            "font-weight: bold; "
            "padding: 6px 12px; "
            "border-radius: 4px; "
            "}"
            "QPushButton:hover { background-color: #1976d2; }"
        );
        connect(m_pricingButton, &QPushButton::clicked,
                this, &FinalContractReviewDialog::onShowPricing);
        auxiliaryButtons->addWidget(m_pricingButton);
    }

    if (auxiliaryButtons->count() > 1) { // stretch + at least one button
        mainLayout->addLayout(auxiliaryButtons);
    } else {
        delete auxiliaryButtons;
    }

    QDialogButtonBox* buttonBox = new QDialogButtonBox(this);
    QPushButton* rejectButton = buttonBox->addButton(
        defaultOr(m_options.rejectLabel, tr("Cancel")), QDialogButtonBox::RejectRole);
    QPushButton* acceptButton = buttonBox->addButton(
        defaultOr(m_options.acceptLabel, tr("Accept && Continue")), QDialogButtonBox::AcceptRole);

    // Style accept button as green
    acceptButton->setStyleSheet(
        "QPushButton { "
        "background-color: #4caf50; "
        "color: white; "
        "font-weight: bold; "
        "padding: 8px 16px; "
        "border-radius: 4px; "
        "}"
        "QPushButton:hover { background-color: #45a049; }"
    );

    // Style reject button as red
    rejectButton->setStyleSheet(
        "QPushButton { "
        "background-color: #f44336; "
        "color: white; "
        "font-weight: bold; "
        "padding: 8px 16px; "
        "border-radius: 4px; "
        "}"
        "QPushButton:hover { background-color: #da190b; }"
    );

    connect(rejectButton, &QPushButton::clicked, this, &QDialog::reject);
    connect(acceptButton, &QPushButton::clicked, this, &QDialog::accept);

    mainLayout->addWidget(buttonBox);
}

void FinalContractReviewDialog::onShowRawJson()
{
    openJsonDialog(defaultOr(m_options.rawJsonTitle, tr("Contract JSON")),
                   formatJsonForDisplay(m_options.rawJson));
}

void FinalContractReviewDialog::onShowExtraJson()
{
    openJsonDialog(defaultOr(m_options.extraJsonTitle, tr("Details JSON")),
                   formatJsonForDisplay(m_options.extraJson));
}

void FinalContractReviewDialog::openJsonDialog(const QString& title, const QString& json) const
{
    QDialog dialog(const_cast<FinalContractReviewDialog*>(this));
    dialog.setWindowTitle(title);
    dialog.setMinimumSize(700, 520);

    QVBoxLayout* layout = new QVBoxLayout(&dialog);

    QTextEdit* editor = new QTextEdit(&dialog);
    editor->setReadOnly(true);
    editor->setFont(QFont(QStringLiteral("Courier"), 10));
    editor->setPlainText(json);
    layout->addWidget(editor);

    QHBoxLayout* buttonsLayout = new QHBoxLayout();
    buttonsLayout->addStretch();

    QPushButton* copyButton = new QPushButton(tr("Copy JSON"), &dialog);
    connect(copyButton, &QPushButton::clicked, [&]() {
        QApplication::clipboard()->setText(editor->toPlainText());
    });
    buttonsLayout->addWidget(copyButton);

    QPushButton* closeButton = new QPushButton(tr("Close"), &dialog);
    connect(closeButton, &QPushButton::clicked, &dialog, &QDialog::accept);
    buttonsLayout->addWidget(closeButton);

    layout->addLayout(buttonsLayout);

    dialog.exec();
}

QString FinalContractReviewDialog::getSelectedFeeStrategy() const
{
    if (!m_feeStrategyCombo) {
        return QString("medium"); // fallback
    }
    QVariant data = m_feeStrategyCombo->currentData();
    if (!data.isValid() || !data.canConvert<QString>()) {
        return QString("medium"); // fallback if data is invalid
    }
    QString strategy = data.toString();
    if (strategy.isEmpty()) {
        return QString("medium"); // fallback if empty
    }
    return strategy;
}

void FinalContractReviewDialog::onShowPricing()
{
    // Note: This requires access to WalletModel which is not currently passed to this dialog
    // The calling code should set up the pricing data in m_options
    if (m_options.contractTerms.isEmpty()) {
        QMessageBox::information(this, tr("Pricing"),
            tr("Pricing data not available for this contract."));
        return;
    }

    // This is a placeholder - the actual implementation needs WalletModel
    // which should be added to the constructor or Options struct
    QMessageBox::information(this, tr("Pricing"),
        tr("Pricing dialog would open here with contract type: %1\n\n"
           "To complete this feature, WalletModel needs to be passed to FinalContractReviewDialog.")
        .arg(m_options.contractType));
}
