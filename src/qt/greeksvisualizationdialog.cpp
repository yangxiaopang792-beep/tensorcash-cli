// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <qt/greeksvisualizationdialog.h>
#include <qt/walletmodel.h>

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTableWidget>
#include <QPushButton>
#include <QLabel>
#include <QHeaderView>
#include <QMessageBox>
#include <QProgressBar>
#include <QClipboard>
#include <QApplication>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTimer>
#include <QBrush>

GreeksVisualizationDialog::GreeksVisualizationDialog(WalletModel* model, const GreeksData& data, QWidget* parent)
    : QDialog(parent)
    , m_walletModel(model)
    , m_data(data)
{
    setWindowTitle(tr("Greeks Visualization"));
    setMinimumSize(800, 600);

    buildUI();
    updateGreeks();
}

void GreeksVisualizationDialog::buildUI()
{
    QVBoxLayout* mainLayout = new QVBoxLayout(this);

    // Title
    QLabel* titleLabel = new QLabel(tr("<h3>Option Greeks Analysis</h3>"));
    titleLabel->setTextFormat(Qt::RichText);
    mainLayout->addWidget(titleLabel);

    // Description
    QLabel* descLabel = new QLabel(
        tr("Greeks measure the sensitivity of the contract's value to various factors:<br>"
           "<b>Delta:</b> Sensitivity to underlying price changes<br>"
           "<b>Gamma:</b> Rate of change of delta<br>"
           "<b>Vega:</b> Sensitivity to volatility changes<br>"
           "<b>Theta:</b> Time decay (value lost per day)<br>"
           "<b>Rho:</b> Sensitivity to interest rate changes"));
    descLabel->setWordWrap(true);
    descLabel->setTextFormat(Qt::RichText);
    descLabel->setStyleSheet("QLabel { color: #666; font-size: 10pt; padding: 8px; background: #f5f5f5; border-radius: 4px; }");
    mainLayout->addWidget(descLabel);

    // Status label
    m_statusLabel = new QLabel(tr("Computing Greeks..."));
    mainLayout->addWidget(m_statusLabel);

    // Greeks table
    m_greeksTable = new QTableWidget(this);
    m_greeksTable->setColumnCount(3);
    m_greeksTable->setHorizontalHeaderLabels({tr("Greek"), tr("Value"), tr("Visual")});
    m_greeksTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_greeksTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    m_greeksTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    m_greeksTable->setAlternatingRowColors(true);
    m_greeksTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_greeksTable->setSelectionMode(QAbstractItemView::SingleSelection);
    mainLayout->addWidget(m_greeksTable);

    // Buttons
    QHBoxLayout* buttonLayout = new QHBoxLayout();

    m_refreshButton = new QPushButton(tr("Refresh"));
    connect(m_refreshButton, &QPushButton::clicked, this, &GreeksVisualizationDialog::onRefreshGreeks);
    buttonLayout->addWidget(m_refreshButton);

    m_exportButton = new QPushButton(tr("Copy to Clipboard"));
    connect(m_exportButton, &QPushButton::clicked, this, &GreeksVisualizationDialog::onExportGreeks);
    buttonLayout->addWidget(m_exportButton);

    buttonLayout->addStretch();

    QPushButton* closeButton = new QPushButton(tr("Close"));
    connect(closeButton, &QPushButton::clicked, this, &QDialog::accept);
    buttonLayout->addWidget(closeButton);

    mainLayout->addLayout(buttonLayout);
}

void GreeksVisualizationDialog::onRefreshGreeks()
{
    updateGreeks();
}

void GreeksVisualizationDialog::onExportGreeks()
{
    // Build JSON with all Greeks data
    QJsonObject json;

    for (int row = 0; row < m_greeksTable->rowCount(); ++row) {
        QString greek = m_greeksTable->item(row, 0) ? m_greeksTable->item(row, 0)->text() : "";
        QString value = m_greeksTable->item(row, 1) ? m_greeksTable->item(row, 1)->text() : "";
        if (!greek.isEmpty() && !value.isEmpty()) {
            json[greek] = value;
        }
    }

    QString jsonStr = QString::fromUtf8(QJsonDocument(json).toJson(QJsonDocument::Indented));
    QApplication::clipboard()->setText(jsonStr);

    m_statusLabel->setText(tr("✓ Greeks copied to clipboard"));
    QTimer::singleShot(3000, this, [this]() {
        m_statusLabel->setText(tr("Greeks computed successfully"));
    });
}

void GreeksVisualizationDialog::updateGreeks()
{
    if (!m_walletModel) {
        QMessageBox::warning(this, tr("Error"), tr("Wallet model not available"));
        return;
    }

    m_greeksTable->setRowCount(0);
    m_statusLabel->setText(tr("Computing Greeks..."));

    try {
        QString quoteType = m_data.contractId.isEmpty() ? "inline" : "contract";

        if (m_data.type == Repo) {
            auto result = m_walletModel->pricingRepoQuote(
                quoteType,
                m_data.contractId,
                m_data.inlineTerms,
                m_data.reportAsset,
                m_data.reportIsNative,
                true,    // compute_greeks
                "mark",
                true
            );

            displayRepoGreeks(result.collateral_greeks);

        } else if (m_data.type == Difficulty) {
            QString diffQuoteType = m_data.contractId.isEmpty() ? "inline" : "registry";
            auto r = m_walletModel->pricingDifficultyQuote(
                diffQuoteType, m_data.contractId, m_data.inlineTerms,
                /*compute_greeks=*/true, /*forecast_nbits=*/0, QStringLiteral("market"));

            // Difficulty greeks are in atomic TSC; the underlying is the chain difficulty itself.
            const double a2d = 1.0 / 1e8;
            if (r.kind == "option") {
                addGreekRow(tr("Writer Delta"), r.writer_delta_to_difficulty * a2d, tr("d(writer MTM) / d(difficulty move)"));
                addGreekRow(tr("Buyer Delta"), r.buyer_delta_to_difficulty * a2d, tr("d(buyer MTM) / d(difficulty move)"));
                addGreekRow(tr("Writer Vega"), r.writer_vega * a2d, tr("per +0.01 difficulty vol"));
                addGreekRow(tr("Buyer Vega"), r.buyer_vega * a2d, tr("per +0.01 difficulty vol"));
                addGreekRow(tr("Writer Theta"), r.writer_theta * a2d, tr("per -1 day to fixing"));
                addGreekRow(tr("Buyer Theta"), r.buyer_theta * a2d, tr("per -1 day to fixing"));
            } else {
                addGreekRow(tr("Long Delta"), r.long_delta_to_difficulty * a2d, tr("d(long MTM) / d(difficulty move)"));
                addGreekRow(tr("Short Delta"), r.short_delta_to_difficulty * a2d, tr("d(short MTM) / d(difficulty move)"));
                addGreekRow(tr("Long Vega"), r.long_vega * a2d, tr("per +0.01 difficulty vol"));
                addGreekRow(tr("Short Vega"), r.short_vega * a2d, tr("per +0.01 difficulty vol"));
                addGreekRow(tr("Long Theta"), r.long_theta * a2d, tr("per -1 day to fixing"));
                addGreekRow(tr("Short Theta"), r.short_theta * a2d, tr("per -1 day to fixing"));
            }

        } else {
            // Forward or Option
            auto result = m_walletModel->pricingForwardQuote(
                quoteType,
                m_data.contractId,
                m_data.inlineTerms,
                m_data.reportAsset,
                m_data.reportIsNative,
                true     // compute_greeks
            );

            displayForwardGreeks(result.spread_greeks_call, result.spread_greeks_put);
        }

        m_statusLabel->setText(tr("Greeks computed successfully"));

    } catch (const std::exception& e) {
        m_statusLabel->setText(tr("⚠ Error: %1").arg(QString::fromStdString(e.what())));
        QMessageBox::critical(this, tr("Greeks Error"),
            tr("Failed to compute Greeks:\n\n%1").arg(QString::fromStdString(e.what())));
    }
}

void GreeksVisualizationDialog::displayRepoGreeks(const QVariantMap& greeks)
{
    if (greeks.isEmpty()) {
        addGreekRow(tr("No Greeks"), 0.0, tr("Greeks not available for this contract"));
        return;
    }

    // Greeks are in atomic TSC units (satoshis), convert to display units
    const double atomic_to_display = 1.0 / 1e8;

    // Display collateral option greeks
    addGreekRow(tr("Delta"), greeks.value("delta").toDouble() * atomic_to_display, tr("Collateral option delta"));
    addGreekRow(tr("Gamma"), greeks.value("gamma").toDouble() * atomic_to_display, tr("Collateral option gamma"));
    addGreekRow(tr("Vega"), greeks.value("vega").toDouble() * atomic_to_display, tr("Collateral option vega"));
    addGreekRow(tr("Theta"), greeks.value("theta").toDouble() * atomic_to_display, tr("Collateral option theta (per day)"));
    addGreekRow(tr("Rho"), greeks.value("rho").toDouble() * atomic_to_display, tr("Collateral option rho"));
}

void GreeksVisualizationDialog::displayForwardGreeks(const QVariantMap& spreadGreeksCall, const QVariantMap& spreadGreeksPut)
{
    // Greeks are in atomic TSC units (satoshis), convert to display units
    const double atomic_to_display = 1.0 / 1e8;

    if (!spreadGreeksCall.isEmpty()) {
        // Add section header
        int row = m_greeksTable->rowCount();
        m_greeksTable->insertRow(row);
        QTableWidgetItem* headerItem = new QTableWidgetItem(tr("CALL SPREAD GREEKS"));
        QFont headerFont = headerItem->font();
        headerFont.setBold(true);
        headerItem->setFont(headerFont);
        headerItem->setBackground(QBrush(QColor(220, 220, 220)));
        m_greeksTable->setItem(row, 0, headerItem);
        m_greeksTable->setSpan(row, 0, 1, 3);

        // Spread Greeks have separate values for asset A (pay leg) and B (receive leg)
        addGreekRow(tr("Delta A (Call)"), spreadGreeksCall.value("delta_A").toDouble() * atomic_to_display, tr("Call delta w.r.t. pay leg asset"));
        addGreekRow(tr("Delta B (Call)"), spreadGreeksCall.value("delta_B").toDouble() * atomic_to_display, tr("Call delta w.r.t. receive leg asset"));
        addGreekRow(tr("Gamma A (Call)"), spreadGreeksCall.value("gamma_A").toDouble() * atomic_to_display, tr("Call gamma w.r.t. pay leg asset"));
        addGreekRow(tr("Gamma B (Call)"), spreadGreeksCall.value("gamma_B").toDouble() * atomic_to_display, tr("Call gamma w.r.t. receive leg asset"));
        addGreekRow(tr("Vega A (Call)"), spreadGreeksCall.value("vega_A").toDouble() * atomic_to_display, tr("Call vega w.r.t. pay leg volatility"));
        addGreekRow(tr("Vega B (Call)"), spreadGreeksCall.value("vega_B").toDouble() * atomic_to_display, tr("Call vega w.r.t. receive leg volatility"));
        addGreekRow(tr("Theta (Call)"), spreadGreeksCall.value("theta").toDouble() * atomic_to_display, tr("Call time decay (per day)"));
        addGreekRow(tr("Rho (Call)"), spreadGreeksCall.value("rho_rate").toDouble() * atomic_to_display, tr("Call interest rate sensitivity"));
    }

    if (!spreadGreeksPut.isEmpty()) {
        // Add section header
        int row = m_greeksTable->rowCount();
        m_greeksTable->insertRow(row);
        QTableWidgetItem* headerItem = new QTableWidgetItem(tr("PUT SPREAD GREEKS"));
        QFont headerFont = headerItem->font();
        headerFont.setBold(true);
        headerItem->setFont(headerFont);
        headerItem->setBackground(QBrush(QColor(220, 220, 220)));
        m_greeksTable->setItem(row, 0, headerItem);
        m_greeksTable->setSpan(row, 0, 1, 3);

        // Spread Greeks have separate values for asset A (pay leg) and B (receive leg)
        addGreekRow(tr("Delta A (Put)"), spreadGreeksPut.value("delta_A").toDouble() * atomic_to_display, tr("Put delta w.r.t. pay leg asset"));
        addGreekRow(tr("Delta B (Put)"), spreadGreeksPut.value("delta_B").toDouble() * atomic_to_display, tr("Put delta w.r.t. receive leg asset"));
        addGreekRow(tr("Gamma A (Put)"), spreadGreeksPut.value("gamma_A").toDouble() * atomic_to_display, tr("Put gamma w.r.t. pay leg asset"));
        addGreekRow(tr("Gamma B (Put)"), spreadGreeksPut.value("gamma_B").toDouble() * atomic_to_display, tr("Put gamma w.r.t. receive leg asset"));
        addGreekRow(tr("Vega A (Put)"), spreadGreeksPut.value("vega_A").toDouble() * atomic_to_display, tr("Put vega w.r.t. pay leg volatility"));
        addGreekRow(tr("Vega B (Put)"), spreadGreeksPut.value("vega_B").toDouble() * atomic_to_display, tr("Put vega w.r.t. receive leg volatility"));
        addGreekRow(tr("Theta (Put)"), spreadGreeksPut.value("theta").toDouble() * atomic_to_display, tr("Put time decay (per day)"));
        addGreekRow(tr("Rho (Put)"), spreadGreeksPut.value("rho_rate").toDouble() * atomic_to_display, tr("Put interest rate sensitivity"));
    }

    if (spreadGreeksCall.isEmpty() && spreadGreeksPut.isEmpty()) {
        addGreekRow(tr("No Greeks"), 0.0, tr("Greeks not available for this contract"));
    }
}

void GreeksVisualizationDialog::addGreekRow(const QString& greekName, double value, const QString& description)
{
    int row = m_greeksTable->rowCount();
    m_greeksTable->insertRow(row);

    QTableWidgetItem* nameItem = new QTableWidgetItem(greekName);
    nameItem->setToolTip(description);
    m_greeksTable->setItem(row, 0, nameItem);

    QTableWidgetItem* valueItem = new QTableWidgetItem(QString::number(value, 'f', 6));
    valueItem->setToolTip(description);
    m_greeksTable->setItem(row, 1, valueItem);

    // Create visual bar
    QWidget* visualWidget = createGreekVisualBar(value, -1.0, 1.0);
    m_greeksTable->setCellWidget(row, 2, visualWidget);
}

QWidget* GreeksVisualizationDialog::createGreekVisualBar(double value, double minVal, double maxVal)
{
    QWidget* container = new QWidget();
    QHBoxLayout* layout = new QHBoxLayout(container);
    layout->setContentsMargins(4, 2, 4, 2);

    QProgressBar* bar = new QProgressBar();
    bar->setMinimum(0);
    bar->setMaximum(100);
    bar->setTextVisible(false);

    // Normalize value to 0-100 range
    double normalized = 0.0;
    if (maxVal != minVal) {
        normalized = ((value - minVal) / (maxVal - minVal)) * 100.0;
        normalized = std::max(0.0, std::min(100.0, normalized));
    } else {
        normalized = 50.0;
    }

    bar->setValue(static_cast<int>(normalized));

    // Color based on value
    QString color;
    if (value > 0.5) {
        color = "#4caf50";  // Green for positive
    } else if (value < -0.5) {
        color = "#f44336";  // Red for negative
    } else if (value > 0) {
        color = "#8bc34a";  // Light green
    } else if (value < 0) {
        color = "#ff7043";  // Light red
    } else {
        color = "#9e9e9e";  // Gray for zero
    }

    bar->setStyleSheet(QString(
        "QProgressBar { border: 1px solid #ccc; border-radius: 3px; background: #f0f0f0; height: 20px; }"
        "QProgressBar::chunk { background: %1; }").arg(color));

    layout->addWidget(bar);
    return container;
}
