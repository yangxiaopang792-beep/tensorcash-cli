// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_QT_GREEKSVISUALIZATIONDIALOG_H
#define BITCOIN_QT_GREEKSVISUALIZATIONDIALOG_H

#include <QDialog>
#include <QString>
#include <QVariantMap>

QT_BEGIN_NAMESPACE
class QTableWidget;
class QPushButton;
class QLabel;
class QProgressBar;
QT_END_NAMESPACE

class WalletModel;

/**
 * Dialog to display and visualize option Greeks
 * Shows delta, gamma, vega, theta, rho with visual indicators
 */
class GreeksVisualizationDialog : public QDialog
{
    Q_OBJECT

public:
    enum ContractType {
        Repo,
        Forward,
        Option,
        Difficulty
    };

    struct GreeksData {
        ContractType type;
        QString contractId;          // For opened contracts
        QVariantMap inlineTerms;     // For offers/new contracts
        QString reportAsset;
        bool reportIsNative{true};
    };

    explicit GreeksVisualizationDialog(WalletModel* model, const GreeksData& data, QWidget* parent = nullptr);
    ~GreeksVisualizationDialog() override = default;

private Q_SLOTS:
    void onRefreshGreeks();
    void onExportGreeks();

private:
    void buildUI();
    void updateGreeks();
    void displayRepoGreeks(const QVariantMap& greeks);
    void displayForwardGreeks(const QVariantMap& spreadGreeksCall, const QVariantMap& spreadGreeksPut);
    void addGreekRow(const QString& greekName, double value, const QString& description);
    QWidget* createGreekVisualBar(double value, double minVal, double maxVal);

    WalletModel* m_walletModel{nullptr};
    GreeksData m_data;

    QTableWidget* m_greeksTable{nullptr};
    QPushButton* m_refreshButton{nullptr};
    QPushButton* m_exportButton{nullptr};
    QLabel* m_statusLabel{nullptr};
};

#endif // BITCOIN_QT_GREEKSVISUALIZATIONDIALOG_H
