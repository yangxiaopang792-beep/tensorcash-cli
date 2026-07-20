// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <qt/pricingbreakdowndialog.h>
#include <qt/walletmodel.h>

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTableWidget>
#include <QPushButton>
#include <QLabel>
#include <QHeaderView>
#include <QMessageBox>

PricingBreakdownDialog::PricingBreakdownDialog(WalletModel* model, const PricingData& data, QWidget* parent)
    : QDialog(parent)
    , m_walletModel(model)
    , m_data(data)
{
    setWindowTitle(tr("Pricing Breakdown"));
    setMinimumSize(700, 500);

    buildUI();
    updatePricing();
}

void PricingBreakdownDialog::buildUI()
{
    QVBoxLayout* mainLayout = new QVBoxLayout(this);

    // Title
    QLabel* titleLabel = new QLabel(tr("<h3>Contract Pricing Analysis</h3>"));
    titleLabel->setTextFormat(Qt::RichText);
    mainLayout->addWidget(titleLabel);

    // Status label
    m_statusLabel = new QLabel(tr("Price Source: <b>%1</b>").arg(m_data.priceSource.toUpper()));
    m_statusLabel->setTextFormat(Qt::RichText);
    mainLayout->addWidget(m_statusLabel);

    // Pricing table
    m_pricingTable = new QTableWidget(this);
    m_pricingTable->setColumnCount(3);
    m_pricingTable->setHorizontalHeaderLabels({tr("Metric"), tr("Mark Prices"), tr("Market Prices")});
    m_pricingTable->horizontalHeader()->setStretchLastSection(true);
    m_pricingTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_pricingTable->setAlternatingRowColors(true);
    m_pricingTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_pricingTable->setSelectionMode(QAbstractItemView::SingleSelection);
    mainLayout->addWidget(m_pricingTable);

    // Buttons
    QHBoxLayout* buttonLayout = new QHBoxLayout();

    m_refreshButton = new QPushButton(tr("Refresh"));
    connect(m_refreshButton, &QPushButton::clicked, this, &PricingBreakdownDialog::onRefreshPricing);
    buttonLayout->addWidget(m_refreshButton);

    m_toggleSourceButton = new QPushButton(tr("Toggle Mark/Market"));
    connect(m_toggleSourceButton, &QPushButton::clicked, this, &PricingBreakdownDialog::onTogglePriceSource);
    buttonLayout->addWidget(m_toggleSourceButton);

    buttonLayout->addStretch();

    QPushButton* closeButton = new QPushButton(tr("Close"));
    connect(closeButton, &QPushButton::clicked, this, &QDialog::accept);
    buttonLayout->addWidget(closeButton);

    mainLayout->addLayout(buttonLayout);
}

void PricingBreakdownDialog::onRefreshPricing()
{
    updatePricing();
}

void PricingBreakdownDialog::onTogglePriceSource()
{
    m_data.priceSource = (m_data.priceSource == "mark") ? "market" : "mark";
    m_statusLabel->setText(tr("Price Source: <b>%1</b>").arg(m_data.priceSource.toUpper()));
    updatePricing();
}

void PricingBreakdownDialog::updatePricing()
{
    if (!m_walletModel) {
        QMessageBox::warning(this, tr("Error"), tr("Wallet model not available"));
        return;
    }

    try {
        switch (m_data.type) {
            case Repo:
                displayRepoPricing();
                break;
            case Forward:
            case Option:
                displayForwardPricing();
                break;
            case Spot:
                displaySpotPricing();
                break;
            case Difficulty:
                displayDifficultyPricing();
                break;
        }
    } catch (const std::exception& e) {
        QMessageBox::critical(this, tr("Pricing Error"),
            tr("Failed to calculate pricing:\n\n%1").arg(QString::fromStdString(e.what())));
    }
}

void PricingBreakdownDialog::displayRepoPricing()
{
    QString quoteType = m_data.contractId.isEmpty() ? "inline" : "contract";

    auto result = m_walletModel->pricingRepoQuote(
        quoteType,
        m_data.contractId,
        m_data.inlineTerms,
        m_data.reportAsset,
        m_data.reportIsNative,
        true,  // compute_greeks
        m_data.priceSource,
        true   // include_inception
    );

    // Clear and populate table
    m_pricingTable->setRowCount(0);
    m_pricingTable->setColumnCount(2);
    m_pricingTable->setHorizontalHeaderLabels({tr("Metric"), tr("Value")});

    auto addRow = [this](const QString& metric, const QString& value, bool bold = false) {
        int row = m_pricingTable->rowCount();
        m_pricingTable->insertRow(row);

        QTableWidgetItem* metricItem = new QTableWidgetItem(metric);
        QTableWidgetItem* valueItem = new QTableWidgetItem(value);

        if (bold) {
            QFont font = metricItem->font();
            font.setBold(true);
            metricItem->setFont(font);
            valueItem->setFont(font);
        }

        m_pricingTable->setItem(row, 0, metricItem);
        m_pricingTable->setItem(row, 1, valueItem);
    };

    QString currency = m_data.reportAsset.isEmpty() ? "TSC" : m_data.reportAsset;

    addRow(tr("Principal + Interest PV"), QString("%1 %2").arg(result.principal_pv + result.interest_pv, 0, 'f', 8).arg(currency));
    addRow(tr("Collateral PV"), QString("%1 %2").arg(result.collateral_pv, 0, 'f', 8).arg(currency));
    addRow(tr("Collateral Option Value"), QString("%1 %2").arg(result.collateral_option, 0, 'f', 8).arg(currency));
    addRow(tr("Coverage Ratio"), QString("%1%").arg(result.coverage_ratio * 100.0, 0, 'f', 2));
    addRow(tr("LTV"), QString("%1%").arg(result.ltv_pct, 0, 'f', 2));
    addRow(tr("Over-Collateralization"), QString("%1%").arg(result.over_collat_pct, 0, 'f', 2));
    addRow(tr(""), tr(""));  // Separator
    addRow(tr("Lender MTM"), QString("%1 %2").arg(result.lender_mtm, 0, 'f', 8).arg(currency), true);
    addRow(tr("Borrower MTM"), QString("%1 %2").arg(result.borrower_mtm, 0, 'f', 8).arg(currency), true);

    if (!result.warnings.isEmpty()) {
        QString warningsStr;
        for (const auto& warning : result.warnings) {
            warningsStr += warning.toString() + "; ";
        }
        addRow(tr("⚠ Warnings"), warningsStr);
    }
}

void PricingBreakdownDialog::displayForwardPricing()
{
    QString quoteType = m_data.contractId.isEmpty() ? "inline" : "contract";

    auto result = m_walletModel->pricingForwardQuote(
        quoteType,
        m_data.contractId,
        m_data.inlineTerms,
        m_data.reportAsset,
        m_data.reportIsNative,
        true   // compute_greeks
    );

    // Clear and populate table
    m_pricingTable->setRowCount(0);
    m_pricingTable->setColumnCount(2);
    m_pricingTable->setHorizontalHeaderLabels({tr("Metric"), tr("Value")});

    auto addRow = [this](const QString& metric, const QString& value, bool bold = false) {
        int row = m_pricingTable->rowCount();
        m_pricingTable->insertRow(row);

        QTableWidgetItem* metricItem = new QTableWidgetItem(metric);
        QTableWidgetItem* valueItem = new QTableWidgetItem(value);

        if (bold) {
            QFont font = metricItem->font();
            font.setBold(true);
            metricItem->setFont(font);
            valueItem->setFont(font);
        }

        m_pricingTable->setItem(row, 0, metricItem);
        m_pricingTable->setItem(row, 1, valueItem);
    };

    QString currency = m_data.reportAsset.isEmpty() ? "TSC" : m_data.reportAsset;

    addRow(tr("PV Receive (Long Delivers)"), QString("%1 %2").arg(result.pv_receive, 0, 'f', 8).arg(currency));
    addRow(tr("PV Pay (Short Delivers)"), QString("%1 %2").arg(result.pv_pay, 0, 'f', 8).arg(currency));
    addRow(tr("Net Spread Value"), QString("%1 %2").arg(result.net_spread_value, 0, 'f', 8).arg(currency));
    addRow(tr("Premium PV"), QString("%1 %2").arg(result.premium_pv, 0, 'f', 8).arg(currency));
    addRow(tr("Alice Short Call Value"), QString("%1 %2").arg(result.alice_short_call_value, 0, 'f', 8).arg(currency));
    addRow(tr("Alice Long Put Value"), QString("%1 %2").arg(result.alice_long_put_value, 0, 'f', 8).arg(currency));
    addRow(tr(""), tr(""));  // Separator
    addRow(tr("Alice (Long) MTM"), QString("%1 %2").arg(result.alice_mtm, 0, 'f', 8).arg(currency), true);
    addRow(tr("Bob (Short) MTM"), QString("%1 %2").arg(result.bob_mtm, 0, 'f', 8).arg(currency), true);
    addRow(tr("IM Coverage Alice"), QString("%1%").arg(result.im_coverage_alice * 100.0, 0, 'f', 2));
    addRow(tr("IM Coverage Bob"), QString("%1%").arg(result.im_coverage_bob * 100.0, 0, 'f', 2));

    if (!result.warnings.isEmpty()) {
        QString warningsStr;
        for (const auto& warning : result.warnings) {
            warningsStr += warning.toString() + "; ";
        }
        addRow(tr("⚠ Warnings"), warningsStr);
    }
}

void PricingBreakdownDialog::displayDifficultyPricing()
{
    QString quoteType = m_data.contractId.isEmpty() ? "inline" : "registry";

    auto result = m_walletModel->pricingDifficultyQuote(
        quoteType,
        m_data.contractId,
        m_data.inlineTerms,
        /*compute_greeks=*/true,
        /*forecast_nbits=*/0,
        m_data.priceSource);

    m_pricingTable->setRowCount(0);
    m_pricingTable->setColumnCount(2);
    m_pricingTable->setHorizontalHeaderLabels({tr("Metric"), tr("Value")});

    auto addRow = [this](const QString& metric, const QString& value, bool bold = false) {
        int row = m_pricingTable->rowCount();
        m_pricingTable->insertRow(row);
        QTableWidgetItem* metricItem = new QTableWidgetItem(metric);
        QTableWidgetItem* valueItem = new QTableWidgetItem(value);
        if (bold) {
            QFont font = metricItem->font();
            font.setBold(true);
            metricItem->setFont(font);
            valueItem->setFont(font);
        }
        m_pricingTable->setItem(row, 0, metricItem);
        m_pricingTable->setItem(row, 1, valueItem);
    };

    if (!result.success) {
        addRow(tr("Error"), result.error);
        return;
    }

    // MTM/greeks come from the pricer in atomic TSC; show in display units.
    const double a2d = 1.0 / 1e8;
    const QString currency = m_data.reportAsset.isEmpty() ? "TSC" : m_data.reportAsset;
    const bool isOption = (result.kind == "option");

    addRow(tr("Kind"), isOption ? tr("Option (writer %1)").arg(result.writer_side) : tr("CFD"));
    addRow(tr("Forward source"), result.forward_provenance);
    addRow(tr("Fixing status"), result.fixing_reached ? tr("fixed (settlement value known)") : tr("forecasting"));
    addRow(tr("Difficulty vol (sigma)"), QString::number(result.sigma, 'f', 4));
    addRow(tr("Forecast / strike ratio"), QString::number(result.forecast_difficulty_ratio, 'f', 4));
    addRow(tr("Discount factor"), QString::number(result.discount_factor, 'f', 6));
    addRow(QString(), QString());  // separator

    if (isOption) {
        addRow(tr("Writer MTM"), QString("%1 %2").arg(result.expected_writer_mtm * a2d, 0, 'f', 8).arg(currency), true);
        addRow(tr("Buyer MTM"), QString("%1 %2").arg(result.expected_buyer_mtm * a2d, 0, 'f', 8).arg(currency), true);
        addRow(tr("Writer Delta"), QString("%1 %2").arg(result.writer_delta_to_difficulty * a2d, 0, 'f', 8).arg(currency));
        addRow(tr("Buyer Delta"), QString("%1 %2").arg(result.buyer_delta_to_difficulty * a2d, 0, 'f', 8).arg(currency));
        addRow(tr("Writer Vega"), QString("%1 %2").arg(result.writer_vega * a2d, 0, 'f', 8).arg(currency));
        addRow(tr("Buyer Vega"), QString("%1 %2").arg(result.buyer_vega * a2d, 0, 'f', 8).arg(currency));
        addRow(tr("Writer Theta"), QString("%1 %2").arg(result.writer_theta * a2d, 0, 'f', 8).arg(currency));
        addRow(tr("Buyer Theta"), QString("%1 %2").arg(result.buyer_theta * a2d, 0, 'f', 8).arg(currency));
    } else {
        addRow(tr("Long MTM"), QString("%1 %2").arg(result.expected_long_mtm * a2d, 0, 'f', 8).arg(currency), true);
        addRow(tr("Short MTM"), QString("%1 %2").arg(result.expected_short_mtm * a2d, 0, 'f', 8).arg(currency), true);
        addRow(tr("Long Delta"), QString("%1 %2").arg(result.long_delta_to_difficulty * a2d, 0, 'f', 8).arg(currency));
        addRow(tr("Short Delta"), QString("%1 %2").arg(result.short_delta_to_difficulty * a2d, 0, 'f', 8).arg(currency));
        addRow(tr("Long Vega"), QString("%1 %2").arg(result.long_vega * a2d, 0, 'f', 8).arg(currency));
        addRow(tr("Short Vega"), QString("%1 %2").arg(result.short_vega * a2d, 0, 'f', 8).arg(currency));
        addRow(tr("Long Theta"), QString("%1 %2").arg(result.long_theta * a2d, 0, 'f', 8).arg(currency));
        addRow(tr("Short Theta"), QString("%1 %2").arg(result.short_theta * a2d, 0, 'f', 8).arg(currency));
    }

    if (result.model_unreliable) {
        addRow(tr("⚠ Model"), tr("unreliable (see warnings)"));
    }
    if (!result.warnings.isEmpty()) {
        QString warningsStr;
        for (const auto& warning : result.warnings) {
            warningsStr += warning.toString() + "; ";
        }
        addRow(tr("⚠ Warnings"), warningsStr);
    }
}

void PricingBreakdownDialog::displaySpotPricing()
{
    // For spot contracts, we don't have a pricing RPC, so just display the exchange rate
    m_pricingTable->setRowCount(0);
    m_pricingTable->setColumnCount(2);
    m_pricingTable->setHorizontalHeaderLabels({tr("Metric"), tr("Value")});

    auto addRow = [this](const QString& metric, const QString& value) {
        int row = m_pricingTable->rowCount();
        m_pricingTable->insertRow(row);
        m_pricingTable->setItem(row, 0, new QTableWidgetItem(metric));
        m_pricingTable->setItem(row, 1, new QTableWidgetItem(value));
    };

    // Extract spot terms from inline_terms
    double aliceSendQty = m_data.inlineTerms.value("alice_send_qty").toDouble();
    double bobSendQty = m_data.inlineTerms.value("bob_send_qty").toDouble();
    QString aliceSendAsset = m_data.inlineTerms.value("alice_send_asset").toString();
    QString bobSendAsset = m_data.inlineTerms.value("bob_send_asset").toString();

    if (aliceSendQty > 0 && bobSendQty > 0) {
        double exchangeRate = bobSendQty / aliceSendQty;
        addRow(tr("Exchange Rate"), QString("%1 %2 per %3").arg(exchangeRate, 0, 'f', 8).arg(bobSendAsset).arg(aliceSendAsset));
        addRow(tr("Alice Sends"), QString("%1 %2").arg(aliceSendQty, 0, 'f', 8).arg(aliceSendAsset));
        addRow(tr("Alice Receives"), QString("%1 %2").arg(bobSendQty, 0, 'f', 8).arg(bobSendAsset));
        addRow(tr(""), tr(""));
        addRow(tr("Bob Sends"), QString("%1 %2").arg(bobSendQty, 0, 'f', 8).arg(bobSendAsset));
        addRow(tr("Bob Receives"), QString("%1 %2").arg(aliceSendQty, 0, 'f', 8).arg(aliceSendAsset));
    } else {
        addRow(tr("Note"), tr("Spot contracts have simple exchange rate pricing only"));
    }
}
