// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_QT_NEWCONTRACTTAB_H
#define BITCOIN_QT_NEWCONTRACTTAB_H

#include <QWidget>

class PlatformStyle;
class WalletModel;
class BridgeSessionManager;

QT_BEGIN_NAMESPACE
class QGroupBox;
class QLabel;
class QPushButton;
class QRadioButton;
class QVBoxLayout;
QT_END_NAMESPACE

/**
 * @brief New Contract tab - Contract type selection and wizard launcher
 *
 * Displays three contract types (Repo, Forward, Spot) with descriptions
 * and launches the appropriate wizard when user selects a type.
 */
class NewContractTab : public QWidget
{
    Q_OBJECT

public:
    explicit NewContractTab(const PlatformStyle* platformStyle, QWidget* parent = nullptr);
    ~NewContractTab();

    void setWalletModel(WalletModel* model);
    void setSessionManager(BridgeSessionManager* manager);

Q_SIGNALS:
    void contractCreated(const QString& contract_type, const QString& offer_id);

private Q_SLOTS:
    void onContractTypeChanged();
    void onCreateContract();
    void onImportOffer();
    void onImportScalarCfdAcceptance();

private:
    void setupUI();
    void launchRepoWizard();
    void launchForwardWizard();
    void launchOptionsWizard();
    void launchSpotWizard();
    void launchDifficultyWizard();
    void launchScalarCfdWizard();
    void showImportOfferDialog();
    // Proposer-side step: import the counterparty's acceptance JSON for a scalar-feed CFD offer this wallet
    // proposed, which registers the contract locally so it appears in the Book. Reachable both right after
    // propose and later via the persistent "Import Scalar Acceptance" button.
    void showScalarCfdImportAcceptanceDialog(const QString& prefillOfferJson = QString());

    WalletModel* walletModel{nullptr};
    BridgeSessionManager* sessionManager{nullptr};
    const PlatformStyle* platformStyle{nullptr};

    // UI components
    QRadioButton* repoRadio{nullptr};
    QRadioButton* forwardRadio{nullptr};
    QRadioButton* optionsRadio{nullptr};
    QRadioButton* spotRadio{nullptr};
    QRadioButton* difficultyRadio{nullptr};
    QRadioButton* scalarCfdRadio{nullptr};
    QLabel* descriptionLabel{nullptr};
    QPushButton* createButton{nullptr};
    QPushButton* importButton{nullptr};
    QPushButton* importScalarAcceptanceButton{nullptr};
};

#endif // BITCOIN_QT_NEWCONTRACTTAB_H
