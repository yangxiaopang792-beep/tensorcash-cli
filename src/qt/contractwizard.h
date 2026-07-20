// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_QT_CONTRACTWIZARD_H
#define BITCOIN_QT_CONTRACTWIZARD_H

#include <qt/tormanager.h>

#include <QWizard>
#include <QVariantMap>

class WalletModel;

/**
 * @brief Base class for contract creation wizards
 *
 * Provides common functionality for Repo, Forward, and Spot contract wizards.
 * Subclasses implement specific term sheet pages and validation logic.
 */
class ContractWizard : public QWizard
{
    Q_OBJECT

public:
    explicit ContractWizard(WalletModel* model, QWidget* parent = nullptr);
    virtual ~ContractWizard();

    /** Get the created offer ID (valid after wizard completes successfully) */
    QString getOfferId() const { return offerId; }

    /** Get the offer JSON (valid after wizard completes successfully) */
    QString getOfferJson() const { return offerFinalized ? offerJson : QString(); }

    /** Get the term sheet JSON (always populated after wizard completes) */
    QString getTermSheetJson() const { return termSheetJson; }

    /** Whether the wizard produced a fully finalized offer (repo.propose) */
    bool hasFinalOffer() const { return offerFinalized; }

    /** Get the offer data map (valid after wizard completes successfully) */
    QVariantMap getOfferData() const { return offerData; }

    /** Get contract type ("repo", "forward", "spot") */
    virtual QString getContractType() const = 0;

    /** Access the wallet model (read-only) for UI helpers */
    WalletModel* getWalletModel() const { return walletModel; }

    /** Get selected transport for cosign sessions (relay/tor) */
    QString getTransport() const { return transport; }

    /** Set transport for cosign sessions */
    void setTransport(const QString& value) { transport = value; }

protected:
    WalletModel* walletModel{nullptr};

    // Wizard state
    QString offerId;
    QString offerJson;
    QVariantMap offerData;
    QString termSheetJson;
    bool offerFinalized{false};
    QString transport{"auto"};  // Transport for cosign sessions: "auto", "ws", "tor"

    /** Subclasses override to create offer via RPC */
    virtual bool createOffer() = 0;

    /** Subclasses override to validate term sheet before proceeding to review */
    virtual bool validateTerms() = 0;

    // Allow review page and term sheet pages to access protected methods
    friend class ContractReviewPage;
    friend class RepoTermSheetPage;
    friend class RepoReviewPage;
};

/**
 * @brief Transport selection page (common to all contract types)
 *
 * Allows user to choose transport for cosign sessions (Relay/Tor).
 * Shows Tor readiness status when Tor is selected.
 */
class TransportSelectionPage : public QWizardPage
{
    Q_OBJECT

public:
    explicit TransportSelectionPage(ContractWizard* wizard, QWidget* parent = nullptr);

    bool validatePage() override;
    void initializePage() override;
    bool isComplete() const override;

private Q_SLOTS:
    void onTransportChanged(int index);
    void onTorStatusChanged(TorManager::Status status);

private:
    void setupUI();
    void updateTorStatus();

    ContractWizard* contractWizard{nullptr};
    class QComboBox* transportCombo{nullptr};
    class QLabel* torStatusLabel{nullptr};
    class QLabel* transportDescLabel{nullptr};
};

/**
 * @brief Review page (common to all contract types)
 *
 * Displays offer summary and creates the offer via RPC.
 */
class ContractReviewPage : public QWizardPage
{
    Q_OBJECT

public:
    explicit ContractReviewPage(ContractWizard* wizard, QWidget* parent = nullptr);

    bool validatePage() override;
    void initializePage() override;

protected:
    ContractWizard* contractWizard{nullptr};

    /** Subclasses override to format offer summary */
    virtual QString formatOfferSummary() const;

private:
    class QTextEdit* summaryEdit{nullptr};
    class QLabel* statusLabel{nullptr};
};

#endif // BITCOIN_QT_CONTRACTWIZARD_H
