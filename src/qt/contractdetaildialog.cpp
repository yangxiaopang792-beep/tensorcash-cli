// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/contractdetaildialog.h>
#include <qt/walletmodel.h>
#include <qt/clientmodel.h>
#include <qt/themehelpers.h>
#include <interfaces/node.h>
#include <univalue.h>

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QScrollArea>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QMessageBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QApplication>
#include <QClipboard>
#include <QFont>
#include <QTableWidget>
#include <QHeaderView>
#include <QTableWidgetItem>
#include <cmath>

ContractDetailDialog::ContractDetailDialog(const QVariantMap& contractData, WalletModel* model, QWidget* parent)
    : QDialog(parent),
      contractData(contractData),
      walletModel(model)
{
    setWindowTitle(tr("Contract Details"));
    setMinimumWidth(800);
    setMinimumHeight(700);
    setupUI();
    populateContractDetails();
}

void ContractDetailDialog::setupUI()
{
    QVBoxLayout* mainLayout = new QVBoxLayout(this);

    // Header section
    QGroupBox* headerGroup = new QGroupBox(tr("Contract Overview"));
    QVBoxLayout* headerLayout = new QVBoxLayout(headerGroup);

    contractIdLabel = new QLabel();
    contractIdLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    contractIdLabel->setWordWrap(true);
    headerLayout->addWidget(contractIdLabel);

    statusLabel = new QLabel();
    statusLabel->setStyleSheet("QLabel { font-weight: bold; }");
    headerLayout->addWidget(statusLabel);

    mainLayout->addWidget(headerGroup);

    // Details section
    QGroupBox* detailsGroup = new QGroupBox(tr("Contract Details"));
    QVBoxLayout* detailsLayout = new QVBoxLayout(detailsGroup);

    detailsText = new QTextEdit();
    detailsText->setReadOnly(true);
    detailsText->setMinimumHeight(300);
    detailsLayout->addWidget(detailsText);

    mainLayout->addWidget(detailsGroup);

    // Pricing breakdown section (only shown for repo contracts)
    pricingGroup = new QGroupBox(tr("Pricing Breakdown"));
    pricingGroup->setStyleSheet(ThemeHelpers::panelStyleSheet());
    QVBoxLayout* pricingLayout = new QVBoxLayout(pricingGroup);

    pricingTable = new QTableWidget();
    pricingTable->setColumnCount(3);
    pricingTable->setHorizontalHeaderLabels({tr("Metric"), tr("Marks"), tr("Market")});
    pricingTable->horizontalHeader()->setStretchLastSection(true);
    pricingTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    pricingTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    pricingTable->setSelectionMode(QAbstractItemView::NoSelection);
    pricingTable->setAlternatingRowColors(true);
    pricingTable->setMinimumHeight(200);  // Ensure table can show all 6 rows comfortably
    pricingLayout->addWidget(pricingTable);

    mainLayout->addWidget(pricingGroup);
    pricingGroup->hide(); // Hidden by default, shown only for repo contracts

    // Action buttons
    QHBoxLayout* buttonLayout = new QHBoxLayout();

    showAdvancedButton = new QPushButton(tr("Show Raw JSON"));
    showAdvancedButton->setToolTip(tr("View the raw JSON representation of this contract"));
    connect(showAdvancedButton, &QPushButton::clicked, this, &ContractDetailDialog::onShowAdvancedView);
    buttonLayout->addWidget(showAdvancedButton);

    showScriptButton = new QPushButton(tr("Show Script Preview"));
    showScriptButton->setToolTip(tr("Preview the Bitcoin script for this contract (if available)"));
    connect(showScriptButton, &QPushButton::clicked, this, &ContractDetailDialog::onShowScriptPreview);
    buttonLayout->addWidget(showScriptButton);

    buttonLayout->addStretch();

    closeButton = new QPushButton(tr("Close"));
    connect(closeButton, &QPushButton::clicked, this, &QDialog::accept);
    buttonLayout->addWidget(closeButton);

    mainLayout->addLayout(buttonLayout);
}

void ContractDetailDialog::populateContractDetails()
{
    QString contractId = contractData.value("id").toString();

    // Fetch full contract data via contract.status RPC if available
    if (!contractId.isEmpty() && walletModel) {
        try {
            UniValue params(UniValue::VARR);
            params.push_back(contractId.toStdString());
            UniValue resp = walletModel->node().executeRpc("contract.status", params, walletModel->getWalletName().toStdString());

            // Merge offer data into contractData
            if (resp.isObject() && resp.exists("offer")) {
                const UniValue& offer = resp["offer"];
                if (offer.exists("borrower_address")) {
                    contractData.insert("borrower_address", QString::fromStdString(offer["borrower_address"].get_str()));
                }
                if (offer.exists("lender_address")) {
                    contractData.insert("lender_address", QString::fromStdString(offer["lender_address"].get_str()));
                }
                // Store state from RPC
                if (resp.exists("state")) {
                    contractData.insert("status", QString::fromStdString(resp["state"].get_str()));
                }
            }
        } catch (...) {
            // Fall back to cached data if RPC fails
        }
    }

    QString type = contractData.value("type").toString();
    QString status = contractData.value("status").toString();

    // Header
    contractIdLabel->setText(tr("<b>Contract ID:</b> %1<br><b>Type:</b> %2")
                                 .arg(contractId)
                                 .arg(type.toUpper()));

    // Status with color
    QString statusText = tr("<b>Status:</b> %1").arg(status.toUpper());
    if (status == "active") {
        statusLabel->setStyleSheet("QLabel { color: #4caf50; font-weight: bold; }");
    } else if (status == "pending") {
        statusLabel->setStyleSheet("QLabel { color: #ff9800; font-weight: bold; }");
    } else if (status == "closed") {
        statusLabel->setStyleSheet("QLabel { color: #9e9e9e; font-weight: bold; }");
    }
    statusLabel->setText(statusText);

    // Formatted details
    QString detailsHtml = formatContractInfo();
    detailsText->setHtml(detailsHtml);

    // Populate pricing breakdown for repo contracts
    if (type == "repo" && walletModel) {
        populatePricingBreakdown();
    }
}

QString ContractDetailDialog::formatContractInfo() const
{
    QString type = contractData.value("type").toString();
    QString html;

    html += tr("<h3>Contract Terms</h3>");
    html += "<table border='0' cellpadding='4' cellspacing='0'>";

    if (type == "repo") {
        QString role = contractData.value("role").toString();
        double collateralAmount = contractData.value("collateral_amount", 0.0).toDouble();
        double principalAmount = contractData.value("principal_amount", 0.0).toDouble();
        double interestAmount = contractData.value("interest_amount", 0.0).toDouble();
        int maturityHeight = contractData.value("maturity_height", 0).toInt();

        // Use resolved asset labels if available, otherwise fallback to raw values
        QString collateralAsset = contractData.value("collateral_asset_label",
            contractData.value("collateral_asset", "TSC")).toString();
        QString principalAsset = contractData.value("principal_asset_label",
            contractData.value("principal_asset", "TSC")).toString();
        QString interestAsset = contractData.value("interest_asset_label",
            contractData.value("interest_asset", "TSC")).toString();

        html += tr("<tr><td><b>Role:</b></td><td>%1</td></tr>").arg(role);
        html += tr("<tr><td><b>Collateral:</b></td><td>%1 %2</td></tr>")
                    .arg(QString::number(collateralAmount, 'f', 8))
                    .arg(collateralAsset);
        html += tr("<tr><td><b>Principal:</b></td><td>%1 %2</td></tr>")
                    .arg(QString::number(principalAmount, 'f', 8))
                    .arg(principalAsset);
        html += tr("<tr><td><b>Interest:</b></td><td>%1 %2</td></tr>")
                    .arg(QString::number(interestAmount, 'f', 8))
                    .arg(interestAsset);

        // Repayment display
        if (interestAsset == principalAsset) {
            // Same asset - show combined total
            double totalRepayment = principalAmount + interestAmount;
            html += tr("<tr><td><b>Total Repayment:</b></td><td>%1 %2</td></tr>")
                .arg(QString::number(totalRepayment, 'f', 8))
                .arg(principalAsset);
        } else {
            // Different assets - show warning and separate amounts
            const QString warnBg = ThemeHelpers::isDarkPalette() ? QStringLiteral("#4a3a1a") : QStringLiteral("#fff3cd");
            const QString warnFg = ThemeHelpers::isDarkPalette() ? QStringLiteral("#ffe082") : QStringLiteral("#6d4c00");
            html += tr("<tr><td colspan='2' style='background-color:%1; color:%2; padding:8px; border-radius:4px;'>"
                       "<b>⚠ Multi-Asset Repayment:</b> This contract requires repayment in two different assets.</td></tr>")
                       .arg(warnBg, warnFg);
            html += tr("<tr><td><b>Principal Repayment:</b></td><td>%1 %2</td></tr>")
                .arg(QString::number(principalAmount, 'f', 8))
                .arg(principalAsset);
            html += tr("<tr><td><b>Interest Payment:</b></td><td>%1 %2</td></tr>")
                .arg(QString::number(interestAmount, 'f', 8))
                .arg(interestAsset);
        }
        html += tr("<tr><td><b>Maturity Height:</b></td><td>%1</td></tr>").arg(maturityHeight);

    } else {
        // Generic display for other contract types
        for (auto it = contractData.begin(); it != contractData.end(); ++it) {
            if (it.key() != "id" && it.key() != "type" && it.key() != "status") {
                html += tr("<tr><td><b>%1:</b></td><td>%2</td></tr>")
                            .arg(it.key())
                            .arg(it.value().toString());
            }
        }
    }

    html += "</table>";

    // Transaction history
    if (contractData.contains("opening_txid")) {
        html += tr("<h3>Transaction History</h3>");
        html += "<table border='0' cellpadding='4' cellspacing='0'>";
        html += tr("<tr><td><b>Opening Transaction:</b></td><td>%1</td></tr>")
                    .arg(contractData.value("opening_txid").toString());

        if (contractData.contains("closing_txid")) {
            html += tr("<tr><td><b>Closing Transaction:</b></td><td>%1</td></tr>")
                        .arg(contractData.value("closing_txid").toString());
        }

        html += "</table>";
    }

    // Addresses
    if (contractData.contains("borrower_address") || contractData.contains("lender_address")) {
        html += tr("<h3>Addresses</h3>");
        html += "<table border='0' cellpadding='4' cellspacing='0'>";

        if (contractData.contains("borrower_address")) {
            html += tr("<tr><td><b>Borrower:</b></td><td>%1</td></tr>")
                        .arg(contractData.value("borrower_address").toString());
        }
        if (contractData.contains("lender_address")) {
            html += tr("<tr><td><b>Lender:</b></td><td>%1</td></tr>")
                        .arg(contractData.value("lender_address").toString());
        }

        html += "</table>";
    }

    return html;
}

void ContractDetailDialog::populatePricingBreakdown()
{
    QString contractId = contractData.value("id").toString();
    QString contractType = contractData.value("type").toString();

    if (contractId.isEmpty() || !walletModel) {
        return;
    }

    try {
        // Handle repo pricing
        if (contractType == "repo") {
            populateRepoPricing(contractId);
        }
        // Handle forward/option pricing
        else if (contractType == "forward" || contractType == "option") {
            populateForwardPricing(contractId);
        }
        // Handle difficulty CFD/option pricing
        else if (contractType == "difficulty") {
            populateDifficultyPricing(contractId);
        }
        else {
            // Unknown contract type - hide pricing
            pricingGroup->hide();
        }
    } catch (...) {
        // Hide pricing group on error
        pricingGroup->hide();
    }
}

void ContractDetailDialog::populateRepoPricing(const QString& contractId)
{
    try {
        // Call pricing.repo.quote for both "mark" and "market" sources
        auto resultMark = walletModel->pricingRepoQuote(
            "registry",
            contractId,
            QVariantMap(),  // empty inline_terms
            "",             // report_asset (empty for TSC)
            true,           // report_is_native (default to TSC)
            false,          // compute_greeks (skip for performance)
            QStringLiteral("mark"),
            false           // DO NOT include inception cashflows for opened contracts
        );

        auto resultMarket = walletModel->pricingRepoQuote(
            "registry",
            contractId,
            QVariantMap(),  // empty inline_terms
            "",             // report_asset (empty for TSC)
            true,           // report_is_native (default to TSC)
            false,          // compute_greeks (skip for performance)
            QStringLiteral("market"),
            false           // DO NOT include inception cashflows for opened contracts
        );

        if (!resultMark.success || !resultMarket.success) {
            // Pricing failed - hide the group
            pricingGroup->hide();
            return;
        }

        // Get report decimals (TSC = 8 decimals by default)
        int reportDecimals = 8;
        WalletModel::AssetInfo tscInfo = walletModel->getAssetInfo(""); // Empty = native TSC
        if (tscInfo.has_decimals) {
            reportDecimals = tscInfo.decimals;
        }
        const double toDisplayUnits = 1.0 / std::pow(10.0, reportDecimals);

        // Determine user's role
        QString role = contractData.value("role").toString();
        bool isLender = (role == "lender");

        // Helper to format values with color coding
        auto formatValue = [](double value, const QString& unit, bool isMtm = false) -> QTableWidgetItem* {
            QTableWidgetItem* item = new QTableWidgetItem();
            item->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);

            if (isMtm) {
                if (value > 0.0) {
                    item->setText(QString("+%1 %2").arg(value, 0, 'f', 8).arg(unit));
                    item->setForeground(QColor("#4caf50")); // Green
                } else if (value < 0.0) {
                    item->setText(QString("%1 %2").arg(value, 0, 'f', 8).arg(unit));
                    item->setForeground(QColor("#f44336")); // Red
                } else {
                    item->setText(QString("0.00000000 %1").arg(unit));
                    item->setForeground(QColor("#9e9e9e")); // Gray
                }
                QFont font = item->font();
                font.setBold(true);
                item->setFont(font);
            } else {
                item->setText(QString("%1 %2").arg(value, 0, 'f', 8).arg(unit));
            }
            return item;
        };

        auto formatRatio = [](double value) -> QTableWidgetItem* {
            QTableWidgetItem* item = new QTableWidgetItem();
            item->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
            item->setText(QString::number(value, 'f', 4));

            // Color code coverage ratio
            if (value < 1.2) {
                item->setForeground(QColor("#f44336")); // Red for low coverage
                QFont font = item->font();
                font.setBold(true);
                item->setFont(font);
            }
            return item;
        };

        // Populate table
        pricingTable->setRowCount(6);
        int row = 0;

        // Principal + Interest PV
        pricingTable->setItem(row, 0, new QTableWidgetItem(tr("Principal + Interest PV")));
        pricingTable->setItem(row, 1, formatValue((resultMark.principal_pv + resultMark.interest_pv) * toDisplayUnits, "TSC"));
        pricingTable->setItem(row, 2, formatValue((resultMarket.principal_pv + resultMarket.interest_pv) * toDisplayUnits, "TSC"));
        row++;

        // Collateral PV
        pricingTable->setItem(row, 0, new QTableWidgetItem(tr("Collateral PV")));
        pricingTable->setItem(row, 1, formatValue(resultMark.collateral_pv * toDisplayUnits, "TSC"));
        pricingTable->setItem(row, 2, formatValue(resultMarket.collateral_pv * toDisplayUnits, "TSC"));
        row++;

        // Collateral Option Value
        pricingTable->setItem(row, 0, new QTableWidgetItem(tr("Collateral Option Value")));
        pricingTable->setItem(row, 1, formatValue(resultMark.collateral_option * toDisplayUnits, "TSC"));
        pricingTable->setItem(row, 2, formatValue(resultMarket.collateral_option * toDisplayUnits, "TSC"));
        row++;

        // Coverage Ratio
        pricingTable->setItem(row, 0, new QTableWidgetItem(tr("Coverage Ratio")));
        pricingTable->setItem(row, 1, formatRatio(resultMark.coverage_ratio));
        pricingTable->setItem(row, 2, formatRatio(resultMarket.coverage_ratio));
        row++;

        // User's MTM (based on role)
        double userMtmMark = isLender ? resultMark.lender_mtm : resultMark.borrower_mtm;
        double userMtmMarket = isLender ? resultMarket.lender_mtm : resultMarket.borrower_mtm;
        QString mtmLabel = isLender ? tr("Your MTM (Lender)") : tr("Your MTM (Borrower)");

        pricingTable->setItem(row, 0, new QTableWidgetItem(mtmLabel));
        pricingTable->setItem(row, 1, formatValue(userMtmMark * toDisplayUnits, "TSC", true));
        pricingTable->setItem(row, 2, formatValue(userMtmMarket * toDisplayUnits, "TSC", true));
        row++;

        // Counterparty MTM (opposite role)
        double counterpartyMtmMark = isLender ? resultMark.borrower_mtm : resultMark.lender_mtm;
        double counterpartyMtmMarket = isLender ? resultMarket.borrower_mtm : resultMarket.lender_mtm;
        QString counterpartyLabel = isLender ? tr("Counterparty MTM (Borrower)") : tr("Counterparty MTM (Lender)");

        pricingTable->setItem(row, 0, new QTableWidgetItem(counterpartyLabel));
        pricingTable->setItem(row, 1, formatValue(counterpartyMtmMark * toDisplayUnits, "TSC", true));
        pricingTable->setItem(row, 2, formatValue(counterpartyMtmMarket * toDisplayUnits, "TSC", true));

        // Resize columns to content
        pricingTable->resizeColumnsToContents();

        // Show the pricing group
        pricingGroup->show();

    } catch (...) {
        // Hide pricing group on error
        pricingGroup->hide();
    }
}

void ContractDetailDialog::populateForwardPricing(const QString& contractId)
{
    try {
        // Call pricing.forward.quote for both "mark" and "market" sources
        // Note: forward pricing doesn't have separate mark/market sources like repo
        auto resultMark = walletModel->pricingForwardQuote(
            "registry",
            contractId,
            QVariantMap(),  // empty inline_terms
            "",             // report_asset (empty for TSC)
            true,           // report_is_native (default to TSC)
            false          // compute_greeks (skip for performance)
        );

        // Use same result for both columns since forward pricing has no price_source parameter
        auto resultMarket = resultMark;

        if (!resultMark.success) {
            // Pricing failed - hide the group
            pricingGroup->hide();
            return;
        }

        // Get report decimals (TSC = 8 decimals by default)
        int reportDecimals = 8;
        WalletModel::AssetInfo tscInfo = walletModel->getAssetInfo(""); // Empty = native TSC
        if (tscInfo.has_decimals) {
            reportDecimals = tscInfo.decimals;
        }
        const double toDisplayUnits = 1.0 / std::pow(10.0, reportDecimals);

        // Determine user's role (long or short)
        QString role = contractData.value("role").toString().toLower();
        bool isLong = (role == "long");

        // Helper to format values with color coding
        auto formatValue = [](double value, const QString& unit, bool isMtm = false) -> QTableWidgetItem* {
            QTableWidgetItem* item = new QTableWidgetItem();
            item->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);

            if (isMtm) {
                if (value > 0.0) {
                    item->setText(QString("+%1 %2").arg(value, 0, 'f', 8).arg(unit));
                    item->setForeground(QColor("#4caf50")); // Green
                } else if (value < 0.0) {
                    item->setText(QString("%1 %2").arg(value, 0, 'f', 8).arg(unit));
                    item->setForeground(QColor("#f44336")); // Red
                } else {
                    item->setText(QString("0.00000000 %1").arg(unit));
                    item->setForeground(QColor("#9e9e9e")); // Gray
                }
                QFont font = item->font();
                font.setBold(true);
                item->setFont(font);
            } else {
                item->setText(QString("%1 %2").arg(value, 0, 'f', 8).arg(unit));
            }
            return item;
        };

        auto formatRatio = [](double value) -> QTableWidgetItem* {
            QTableWidgetItem* item = new QTableWidgetItem();
            item->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
            item->setText(QString::number(value * 100.0, 'f', 2) + "%");

            // Color code IM coverage
            if (value < 0.10) { // Less than 10%
                item->setForeground(QColor("#f44336")); // Red for low coverage
                QFont font = item->font();
                font.setBold(true);
                item->setFont(font);
            }
            return item;
        };

        // Populate table with forward-specific metrics
        pricingTable->setRowCount(10);
        int row = 0;

        // Your Delivery PV (what you pay)
        QString yourDeliveryLabel = isLong ? tr("Your Delivery PV (Long)") : tr("Your Delivery PV (Short)");
        double yourDeliveryMark = isLong ? resultMark.pv_pay : resultMark.pv_receive;
        double yourDeliveryMarket = isLong ? resultMarket.pv_pay : resultMarket.pv_receive;
        pricingTable->setItem(row, 0, new QTableWidgetItem(yourDeliveryLabel));
        pricingTable->setItem(row, 1, formatValue(yourDeliveryMark * toDisplayUnits, "TSC"));
        pricingTable->setItem(row, 2, formatValue(yourDeliveryMarket * toDisplayUnits, "TSC"));
        row++;

        // Counterparty Delivery PV (what you receive)
        QString cpDeliveryLabel = isLong ? tr("Counterparty Delivery PV (Short)") : tr("Counterparty Delivery PV (Long)");
        double cpDeliveryMark = isLong ? resultMark.pv_receive : resultMark.pv_pay;
        double cpDeliveryMarket = isLong ? resultMarket.pv_receive : resultMarket.pv_pay;
        pricingTable->setItem(row, 0, new QTableWidgetItem(cpDeliveryLabel));
        pricingTable->setItem(row, 1, formatValue(cpDeliveryMark * toDisplayUnits, "TSC"));
        pricingTable->setItem(row, 2, formatValue(cpDeliveryMarket * toDisplayUnits, "TSC"));
        row++;

        // Net Spread Value
        pricingTable->setItem(row, 0, new QTableWidgetItem(tr("Net Spread Value")));
        pricingTable->setItem(row, 1, formatValue(resultMark.net_spread_value * toDisplayUnits, "TSC"));
        pricingTable->setItem(row, 2, formatValue(resultMarket.net_spread_value * toDisplayUnits, "TSC"));
        row++;

        // Premium PV (if any)
        pricingTable->setItem(row, 0, new QTableWidgetItem(tr("Premium PV")));
        pricingTable->setItem(row, 1, formatValue(resultMark.premium_pv * toDisplayUnits, "TSC"));
        pricingTable->setItem(row, 2, formatValue(resultMarket.premium_pv * toDisplayUnits, "TSC"));
        row++;

        // Short Call Value (Long's short call on Short's IM)
        pricingTable->setItem(row, 0, new QTableWidgetItem(tr("Long Short Call Value")));
        pricingTable->setItem(row, 1, formatValue(resultMark.alice_short_call_value * toDisplayUnits, "TSC"));
        pricingTable->setItem(row, 2, formatValue(resultMarket.alice_short_call_value * toDisplayUnits, "TSC"));
        row++;

        // Long Put Value (Long's long put on Long's IM)
        pricingTable->setItem(row, 0, new QTableWidgetItem(tr("Long Long Put Value")));
        pricingTable->setItem(row, 1, formatValue(resultMark.alice_long_put_value * toDisplayUnits, "TSC"));
        pricingTable->setItem(row, 2, formatValue(resultMarket.alice_long_put_value * toDisplayUnits, "TSC"));
        row++;

        // Your MTM
        double yourMtmMark = isLong ? resultMark.alice_mtm : resultMark.bob_mtm;
        double yourMtmMarket = isLong ? resultMarket.alice_mtm : resultMarket.bob_mtm;
        QString yourMtmLabel = isLong ? tr("Your MTM (Long)") : tr("Your MTM (Short)");
        pricingTable->setItem(row, 0, new QTableWidgetItem(yourMtmLabel));
        pricingTable->setItem(row, 1, formatValue(yourMtmMark * toDisplayUnits, "TSC", true));
        pricingTable->setItem(row, 2, formatValue(yourMtmMarket * toDisplayUnits, "TSC", true));
        row++;

        // Counterparty MTM
        double cpMtmMark = isLong ? resultMark.bob_mtm : resultMark.alice_mtm;
        double cpMtmMarket = isLong ? resultMarket.bob_mtm : resultMarket.alice_mtm;
        QString cpMtmLabel = isLong ? tr("Counterparty MTM (Short)") : tr("Counterparty MTM (Long)");
        pricingTable->setItem(row, 0, new QTableWidgetItem(cpMtmLabel));
        pricingTable->setItem(row, 1, formatValue(cpMtmMark * toDisplayUnits, "TSC", true));
        pricingTable->setItem(row, 2, formatValue(cpMtmMarket * toDisplayUnits, "TSC", true));
        row++;

        // Your IM Coverage
        double yourImCoverageMark = isLong ? resultMark.im_coverage_alice : resultMark.im_coverage_bob;
        double yourImCoverageMarket = isLong ? resultMarket.im_coverage_alice : resultMarket.im_coverage_bob;
        QString yourImLabel = isLong ? tr("Your IM Coverage (Long)") : tr("Your IM Coverage (Short)");
        pricingTable->setItem(row, 0, new QTableWidgetItem(yourImLabel));
        pricingTable->setItem(row, 1, formatRatio(yourImCoverageMark));
        pricingTable->setItem(row, 2, formatRatio(yourImCoverageMarket));
        row++;

        // Counterparty IM Coverage
        double cpImCoverageMark = isLong ? resultMark.im_coverage_bob : resultMark.im_coverage_alice;
        double cpImCoverageMarket = isLong ? resultMarket.im_coverage_bob : resultMarket.im_coverage_alice;
        QString cpImLabel = isLong ? tr("Counterparty IM Coverage (Short)") : tr("Counterparty IM Coverage (Long)");
        pricingTable->setItem(row, 0, new QTableWidgetItem(cpImLabel));
        pricingTable->setItem(row, 1, formatRatio(cpImCoverageMark));
        pricingTable->setItem(row, 2, formatRatio(cpImCoverageMarket));

        // Resize columns to content
        pricingTable->resizeColumnsToContents();

        // Show the pricing group
        pricingGroup->show();

    } catch (...) {
        // Hide pricing group on error
        pricingGroup->hide();
    }
}

void ContractDetailDialog::populateDifficultyPricing(const QString& contractId)
{
    try {
        // Difficulty marks: mark tier (manual) vs market tier (model/calibrated).
        auto resultMark = walletModel->pricingDifficultyQuote(
            "registry", contractId, QVariantMap(), /*compute_greeks=*/true, /*forecast_nbits=*/0,
            QStringLiteral("mark"));
        auto resultMarket = walletModel->pricingDifficultyQuote(
            "registry", contractId, QVariantMap(), /*compute_greeks=*/true, /*forecast_nbits=*/0,
            QStringLiteral("market"));
        if (!resultMark.success || !resultMarket.success) {
            pricingGroup->hide();
            return;
        }

        int reportDecimals = 8;
        WalletModel::AssetInfo tscInfo = walletModel->getAssetInfo("");
        if (tscInfo.has_decimals) reportDecimals = tscInfo.decimals;
        const double toDisplayUnits = 1.0 / std::pow(10.0, reportDecimals);

        const QString role = contractData.value("role").toString();  // long/short (CFD) or writer/buyer (option)
        const bool isOption = (resultMarket.kind == "option");
        const bool isWriter = (role == "writer");
        const bool isShort = (role == "short");

        using DQ = WalletModel::PricingDifficultyQuoteResult;
        auto pickMtm = [&](const DQ& r) {
            if (isOption) return isWriter ? r.expected_writer_mtm : r.expected_buyer_mtm;
            return isShort ? r.expected_short_mtm : r.expected_long_mtm;
        };
        auto pickDelta = [&](const DQ& r) {
            if (isOption) return isWriter ? r.writer_delta_to_difficulty : r.buyer_delta_to_difficulty;
            return isShort ? r.short_delta_to_difficulty : r.long_delta_to_difficulty;
        };
        auto pickVega = [&](const DQ& r) {
            if (isOption) return isWriter ? r.writer_vega : r.buyer_vega;
            return isShort ? r.short_vega : r.long_vega;
        };
        auto pickTheta = [&](const DQ& r) {
            if (isOption) return isWriter ? r.writer_theta : r.buyer_theta;
            return isShort ? r.short_theta : r.long_theta;
        };

        auto mtmItem = [](double v) -> QTableWidgetItem* {
            QTableWidgetItem* item = new QTableWidgetItem();
            item->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
            if (v > 0.0) { item->setText(QString("+%1 TSC").arg(v, 0, 'f', 8)); item->setForeground(QColor("#4caf50")); }
            else if (v < 0.0) { item->setText(QString("%1 TSC").arg(v, 0, 'f', 8)); item->setForeground(QColor("#f44336")); }
            else { item->setText(QStringLiteral("0.00000000 TSC")); item->setForeground(QColor("#9e9e9e")); }
            QFont font = item->font(); font.setBold(true); item->setFont(font);
            return item;
        };
        auto numItem = [](double v, const QString& unit, int prec) -> QTableWidgetItem* {
            QTableWidgetItem* item = new QTableWidgetItem(QString("%1 %2").arg(v, 0, 'f', prec).arg(unit).trimmed());
            item->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
            return item;
        };
        auto txtItem = [](const QString& s) -> QTableWidgetItem* {
            QTableWidgetItem* item = new QTableWidgetItem(s);
            item->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
            return item;
        };

        pricingTable->setRowCount(8);
        int row = 0;

        const QString roleLabel = isOption ? (isWriter ? tr("Writer") : tr("Buyer"))
                                           : (isShort ? tr("Short") : tr("Long"));
        pricingTable->setItem(row, 0, new QTableWidgetItem(tr("Your MTM (%1)").arg(roleLabel)));
        pricingTable->setItem(row, 1, mtmItem(pickMtm(resultMark) * toDisplayUnits));
        pricingTable->setItem(row, 2, mtmItem(pickMtm(resultMarket) * toDisplayUnits));
        row++;

        pricingTable->setItem(row, 0, new QTableWidgetItem(tr("Forward source")));
        pricingTable->setItem(row, 1, txtItem(resultMark.forward_provenance));
        pricingTable->setItem(row, 2, txtItem(resultMarket.forward_provenance));
        row++;

        pricingTable->setItem(row, 0, new QTableWidgetItem(tr("Difficulty vol (sigma)")));
        pricingTable->setItem(row, 1, numItem(resultMark.sigma, "", 4));
        pricingTable->setItem(row, 2, numItem(resultMarket.sigma, "", 4));
        row++;

        pricingTable->setItem(row, 0, new QTableWidgetItem(tr("Forecast / strike ratio")));
        pricingTable->setItem(row, 1, numItem(resultMark.forecast_difficulty_ratio, "", 4));
        pricingTable->setItem(row, 2, numItem(resultMarket.forecast_difficulty_ratio, "", 4));
        row++;

        pricingTable->setItem(row, 0, new QTableWidgetItem(tr("Delta to difficulty")));
        pricingTable->setItem(row, 1, numItem(pickDelta(resultMark) * toDisplayUnits, "TSC", 8));
        pricingTable->setItem(row, 2, numItem(pickDelta(resultMarket) * toDisplayUnits, "TSC", 8));
        row++;

        pricingTable->setItem(row, 0, new QTableWidgetItem(tr("Vega (per +0.01 vol)")));
        pricingTable->setItem(row, 1, numItem(pickVega(resultMark) * toDisplayUnits, "TSC", 8));
        pricingTable->setItem(row, 2, numItem(pickVega(resultMarket) * toDisplayUnits, "TSC", 8));
        row++;

        pricingTable->setItem(row, 0, new QTableWidgetItem(tr("Theta (per -1 day)")));
        pricingTable->setItem(row, 1, numItem(pickTheta(resultMark) * toDisplayUnits, "TSC", 8));
        pricingTable->setItem(row, 2, numItem(pickTheta(resultMarket) * toDisplayUnits, "TSC", 8));
        row++;

        const QString statusTxt = resultMarket.model_unreliable ? tr("model unreliable")
                                 : (resultMarket.fixing_reached ? tr("fixed (settlement value known)")
                                                                : tr("forecasting"));
        pricingTable->setItem(row, 0, new QTableWidgetItem(tr("Status / discount")));
        pricingTable->setItem(row, 1, txtItem(statusTxt));
        pricingTable->setItem(row, 2, txtItem(QString("DF %1").arg(resultMarket.discount_factor, 0, 'f', 6)));
        row++;

        pricingTable->resizeColumnsToContents();
        pricingGroup->show();

    } catch (...) {
        pricingGroup->hide();
    }
}

QString ContractDetailDialog::getContractRawJson() const
{
    // Prefer contract.status RPC for authoritative full payload
    QString id = contractData.value("id").toString();
    if (!id.isEmpty() && walletModel) {
        try {
            UniValue params(UniValue::VARR);
            params.push_back(id.toStdString());
            UniValue resp = walletModel->node().executeRpc("contract.status", params, walletModel->getWalletName().toStdString());
            return QString::fromStdString(resp.write(2, 0));
        } catch (...) {
            // Fall back to local map if RPC not available
        }
    }
    QJsonObject jsonObj = QJsonObject::fromVariantMap(contractData);
    QJsonDocument doc(jsonObj);
    return QString::fromUtf8(doc.toJson(QJsonDocument::Indented));
}

void ContractDetailDialog::onShowAdvancedView()
{
    // Create a new dialog to show the raw JSON
    QDialog* jsonDialog = new QDialog(this);
    jsonDialog->setWindowTitle(tr("Contract Raw JSON"));
    jsonDialog->setMinimumWidth(700);
    jsonDialog->setMinimumHeight(500);

    QVBoxLayout* layout = new QVBoxLayout(jsonDialog);

    QLabel* titleLabel = new QLabel(tr("<b>Raw JSON Representation:</b>"));
    layout->addWidget(titleLabel);

    QTextEdit* jsonText = new QTextEdit();
    jsonText->setReadOnly(true);
    jsonText->setFont(QFont("Courier", 10));
    jsonText->setPlainText(getContractRawJson());
    layout->addWidget(jsonText);

    QHBoxLayout* buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch();

    QPushButton* copyButton = new QPushButton(tr("Copy to Clipboard"));
    connect(copyButton, &QPushButton::clicked, [jsonText]() {
        QApplication::clipboard()->setText(jsonText->toPlainText());
    });
    buttonLayout->addWidget(copyButton);

    QPushButton* closeBtn = new QPushButton(tr("Close"));
    connect(closeBtn, &QPushButton::clicked, jsonDialog, &QDialog::accept);
    buttonLayout->addWidget(closeBtn);

    layout->addLayout(buttonLayout);

    jsonDialog->exec();
    delete jsonDialog;
}

void ContractDetailDialog::onShowScriptPreview()
{
    // Check if script information is available in the contract data
    QString scriptInfo;

    if (contractData.contains("script_hex")) {
        scriptInfo = contractData.value("script_hex").toString();
    } else if (contractData.contains("witness_script")) {
        scriptInfo = contractData.value("witness_script").toString();
    } else if (contractData.contains("taproot_script")) {
        scriptInfo = contractData.value("taproot_script").toString();
    } else if (contractData.contains("vault_script_hex")) {
        scriptInfo = contractData.value("vault_script_hex").toString();
    }

    // If not present, try fetching from contract.status RPC
    if (scriptInfo.isEmpty() && walletModel) {
        const QString contractId = contractData.value("id").toString();
        if (!contractId.isEmpty()) {
            try {
                UniValue params(UniValue::VARR);
                params.push_back(contractId.toStdString());
                UniValue status_resp = walletModel->node().executeRpc("contract.status", params, walletModel->getWalletName().toStdString());
                if (status_resp.isObject() && status_resp.exists("vault_script_hex")) {
                    scriptInfo = QString::fromStdString(status_resp["vault_script_hex"].get_str());
                }
            } catch (const std::exception& e) {
                // Fall through to info box below
                (void)e;
            }
        }
    }

    if (scriptInfo.isEmpty()) {
        // Script not available - show informational message
        QMessageBox infoBox(this);
        infoBox.setWindowTitle(tr("Script Preview"));
        infoBox.setIcon(QMessageBox::Information);
        infoBox.setText(tr("Bitcoin Script Preview"));

        QString type = contractData.value("type").toString();
        QString detailText;

        if (type == "repo") {
            detailText = tr("<b>Script Type:</b> Taproot v1 (P2TR)<br><br>"
                           "<b>Structure:</b> 2-leaf Taproot script<br>"
                           "• <b>Key Path:</b> Disabled (NUMS point)<br>"
                           "• <b>Leaf A (Repayment):</b> OP_OUTPUTMATCH_ASSET + Borrower signature<br>"
                           "• <b>Leaf B (Default):</b> OP_CHECKLOCKTIMEVERIFY + Lender signature<br><br>"
                           "<b>Note:</b> The actual script will be created when the contract is opened on-chain. "
                           "Use RPC commands to inspect the full script after contract creation.");
        } else if (type == "forward" || type == "option") {
            detailText = tr("<b>Script Type:</b> Taproot v1 (P2TR)<br><br>"
                           "<b>Structure:</b> Multi-leaf Taproot script<br>"
                           "• <b>Key Path:</b> Disabled (NUMS point)<br>"
                           "• <b>Leaf A (Cooperative Close):</b> Both party signatures<br>"
                           "• <b>Leaf B (Long Self-Delivery):</b> Long party delivers + claims escrow<br>"
                           "• <b>Leaf C (Short Self-Delivery):</b> Short party delivers + claims escrow<br>"
                           "• <b>Leaf D (Long Timeout):</b> CLTV + Short party claims Long's escrow<br>"
                           "• <b>Leaf E (Short Timeout):</b> CLTV + Long party claims Short's escrow<br><br>"
                           "<b>Note:</b> The actual script will be created when the contract is opened on-chain. "
                           "Use RPC commands to inspect the full script after contract creation.");
        } else {
            detailText = tr("Script preview not available for this contract type.<br><br>"
                           "The contract uses Bitcoin's advanced scripting features with Taproot. "
                           "Use RPC commands to inspect the full script after contract creation.");
        }

        // If we attempted a build and failed, surface a helpful hint
        if (walletModel && contractData.value("status").toString().toLower() == QLatin1String("opened") && contractData.value("type").toString().toLower() == QLatin1String("repo")) {
            detailText += tr("<br><br><b>Tip:</b> Use the Repay/Claim action to generate a spend preview; the script will be shown here once available.");
        }
        infoBox.setInformativeText(detailText);
        infoBox.setStandardButtons(QMessageBox::Ok);
        infoBox.exec();
        return;
    }

    // Decode the script hex if possible to show human-readable form
    QString decodedScript;
    if (walletModel && scriptInfo.length() > 10 && !scriptInfo.contains("{")) {
        try {
            UniValue params(UniValue::VARR);
            params.push_back(scriptInfo.toStdString());
            UniValue decoded_resp = walletModel->node().executeRpc("decodescript", params, "");
            if (decoded_resp.isObject()) {
                QJsonDocument doc = QJsonDocument::fromJson(QString::fromStdString(decoded_resp.write()).toUtf8());
                decodedScript = QString::fromUtf8(doc.toJson(QJsonDocument::Indented));
            }
        } catch (...) {
            // Decode failed, just show hex
        }
    }

    // Script is available - show it in a dialog
    QDialog* scriptDialog = new QDialog(this);
    scriptDialog->setWindowTitle(tr("Bitcoin Script Preview"));
    scriptDialog->setMinimumWidth(700);
    scriptDialog->setMinimumHeight(500);

    QVBoxLayout* layout = new QVBoxLayout(scriptDialog);

    if (!decodedScript.isEmpty()) {
        QLabel* titleLabel = new QLabel(tr("<b>Decoded Script:</b>"));
        layout->addWidget(titleLabel);

        QTextEdit* decodedText = new QTextEdit();
        decodedText->setReadOnly(true);
        decodedText->setFont(QFont("Courier", 10));
        decodedText->setPlainText(decodedScript);
        layout->addWidget(decodedText);

        QLabel* hexLabel = new QLabel(tr("<b>Script Hex:</b>"));
        layout->addWidget(hexLabel);
    } else {
        QLabel* titleLabel = new QLabel(tr("<b>Bitcoin Script (Hex):</b>"));
        layout->addWidget(titleLabel);
    }

    QTextEdit* scriptText = new QTextEdit();
    scriptText->setReadOnly(true);
    scriptText->setFont(QFont("Courier", 10));
    scriptText->setPlainText(scriptInfo);
    layout->addWidget(scriptText);

    QHBoxLayout* buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch();

    QPushButton* copyButton = new QPushButton(tr("Copy to Clipboard"));
    connect(copyButton, &QPushButton::clicked, [scriptText]() {
        QApplication::clipboard()->setText(scriptText->toPlainText());
    });
    buttonLayout->addWidget(copyButton);

    QPushButton* closeBtn = new QPushButton(tr("Close"));
    connect(closeBtn, &QPushButton::clicked, scriptDialog, &QDialog::accept);
    buttonLayout->addWidget(closeBtn);

    layout->addLayout(buttonLayout);

    scriptDialog->exec();
    delete scriptDialog;
}
