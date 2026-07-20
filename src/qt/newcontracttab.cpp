// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <qt/newcontracttab.h>
#include <qt/platformstyle.h>
#include <qt/walletmodel.h>
#include <qt/clientmodel.h>
#include <qt/repocontractbuilder.h>
#include <qt/forwardcontractbuilder.h>
#include <qt/spotcontractbuilder.h>
#include <qt/difficultycontractbuilder.h>
#include <qt/scalarcfdcontractbuilder.h>
#include <qt/guiutil.h>
#include <qt/importofferdialog.h>
#include <qt/opencontractdialog.h>
#include <qt/proofbuilder.h>
#include <interfaces/node.h>
#include <logging.h>

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QRadioButton>
#include <QLabel>
#include <QPushButton>
#include <QButtonGroup>
#include <QMessageBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QPlainTextEdit>

namespace {
QWidget* TopLevelDialogParent(QWidget* widget)
{
    return widget && widget->window() ? widget->window() : widget;
}
} // namespace

NewContractTab::NewContractTab(const PlatformStyle* _platformStyle, QWidget* parent)
    : QWidget(parent),
      platformStyle(_platformStyle)
{
    setupUI();
}

NewContractTab::~NewContractTab()
{
}

void NewContractTab::setWalletModel(WalletModel* model)
{
    this->walletModel = model;
}

void NewContractTab::setSessionManager(BridgeSessionManager* manager)
{
    this->sessionManager = manager;
}

void NewContractTab::setupUI()
{
    QVBoxLayout* mainLayout = new QVBoxLayout(this);

    // Contract Type Selection Group
    QGroupBox* typeGroup = new QGroupBox(tr("Contract Type"), this);
    QVBoxLayout* typeLayout = new QVBoxLayout(typeGroup);

    // Create button group for mutual exclusivity
    QButtonGroup* buttonGroup = new QButtonGroup(this);

    // Spot option
    spotRadio = new QRadioButton(tr("Spot"), this);
    spotRadio->setChecked(true); // Default selection
    spotRadio->setEnabled(true);
    buttonGroup->addButton(spotRadio);
    typeLayout->addWidget(spotRadio);

    QLabel* spotDesc = new QLabel(
        tr("Atomic swap for instant asset-for-asset exchange in a single settlement transaction."), this);
    spotDesc->setWordWrap(true);
    spotDesc->setStyleSheet("QLabel { margin-left: 25px; color: #666; font-size: 11px; }");
    typeLayout->addWidget(spotDesc);

    typeLayout->addSpacing(15);

    // Repo option
    repoRadio = new QRadioButton(tr("Repo"), this);
    buttonGroup->addButton(repoRadio);
    typeLayout->addWidget(repoRadio);

    QLabel* repoDesc = new QLabel(
        tr("Non-Recourse Collateralised Loan, borrow/lend an asset against another for a fixed maturity. "
           "Collateral is put in escrow, borrowed asset can be used at will. At maturity borrower can "
           "return collateral plus interest or default and forfeit it."), this);
    repoDesc->setWordWrap(true);
    repoDesc->setStyleSheet("QLabel { margin-left: 25px; color: #666; font-size: 11px; }");
    typeLayout->addWidget(repoDesc);

    typeLayout->addSpacing(15);

    // Forward option
    forwardRadio = new QRadioButton(tr("Forward"), this);
    buttonGroup->addButton(forwardRadio);
    typeLayout->addWidget(forwardRadio);

    QLabel* forwardDesc = new QLabel(
        tr("Both parties agree to physical delivery of two assets (quantities and price defined at inception) "
           "at a given time in the future (with sequentially spaced delivery requirements). Initial margin is "
           "put in escrow by both parties and will be lost by the party forfeiting delivery, that represent "
           "the maximum gain for the non defaulting party."), this);
    forwardDesc->setWordWrap(true);
    forwardDesc->setStyleSheet("QLabel { margin-left: 25px; color: #666; font-size: 11px; }");
    typeLayout->addWidget(forwardDesc);

    typeLayout->addSpacing(15);

    // Options
    optionsRadio = new QRadioButton(tr("Option"), this);
    buttonGroup->addButton(optionsRadio);
    typeLayout->addWidget(optionsRadio);

    QLabel* optionsDesc = new QLabel(
        tr("Both parties agree physical delivery of two assets (quantities and price defined at inception) "
           "at a given time in the future. Option buyer pays a premium upfront to the seller, seller pledges "
           "in escrow an Initial Margin amount, which represent the maximum payout to the option holder if "
           "seller does not deliver."), this);
    optionsDesc->setWordWrap(true);
    optionsDesc->setStyleSheet("QLabel { margin-left: 25px; color: #666; font-size: 11px; }");
    typeLayout->addWidget(optionsDesc);

    typeLayout->addSpacing(15);

    // Difficulty derivative option
    difficultyRadio = new QRadioButton(tr("Difficulty"), this);
    buttonGroup->addButton(difficultyRadio);
    typeLayout->addWidget(difficultyRadio);

    QLabel* difficultyDesc = new QLabel(
        tr("A bilateral derivative on the network's mining difficulty (nBits) at a future buried block height. "
           "Each party posts native TSC initial margin and settles unilaterally as a clamped-linear function of "
           "the realized difficulty vs the agreed strike. Build a CFD (both legs margined) or an Option "
           "(single margined writer leg + an upfront premium)."), this);
    difficultyDesc->setWordWrap(true);
    difficultyDesc->setStyleSheet("QLabel { margin-left: 25px; color: #666; font-size: 11px; }");
    typeLayout->addWidget(difficultyDesc);

    typeLayout->addSpacing(15);

    // Scalar-feed bilateral CFD (the difficulty sibling, keyed by a published scalar feed)
    scalarCfdRadio = new QRadioButton(tr("Scalar CFD"), this);
    buttonGroup->addButton(scalarCfdRadio);
    typeLayout->addWidget(scalarCfdRadio);

    QLabel* scalarCfdDesc = new QLabel(
        tr("A bilateral CFD on a published scalar feed (e.g. an oracle value) at a chosen fixing epoch. "
           "Each party posts initial margin in the collateral's units (native TSC for now) and settles "
           "unilaterally as a clamped-linear function of the realized scalar vs the agreed strike (leverage "
           "= lambda). The difficulty CFD's sibling — same escrow/settle/coop machinery, different reference."), this);
    scalarCfdDesc->setWordWrap(true);
    scalarCfdDesc->setStyleSheet("QLabel { margin-left: 25px; color: #666; font-size: 11px; }");
    typeLayout->addWidget(scalarCfdDesc);

    typeGroup->setLayout(typeLayout);
    mainLayout->addWidget(typeGroup);

    // Connect radio button changes
    connect(repoRadio, &QRadioButton::toggled, this, &NewContractTab::onContractTypeChanged);
    connect(forwardRadio, &QRadioButton::toggled, this, &NewContractTab::onContractTypeChanged);
    connect(optionsRadio, &QRadioButton::toggled, this, &NewContractTab::onContractTypeChanged);
    connect(spotRadio, &QRadioButton::toggled, this, &NewContractTab::onContractTypeChanged);
    connect(difficultyRadio, &QRadioButton::toggled, this, &NewContractTab::onContractTypeChanged);
    connect(scalarCfdRadio, &QRadioButton::toggled, this, &NewContractTab::onContractTypeChanged);

    mainLayout->addSpacing(20);

    // Description area (dynamic based on selection)
    QGroupBox* infoGroup = new QGroupBox(tr("Selected Contract Details"), this);
    QVBoxLayout* infoLayout = new QVBoxLayout(infoGroup);

    descriptionLabel = new QLabel(this);
    descriptionLabel->setWordWrap(true);
    descriptionLabel->setText(
        tr("<b>Spot Swap Features:</b><br>"
           "• <b>Type:</b> Atomic asset-for-asset exchange<br>"
           "• <b>Mechanism:</b> CoinJoin PSBT (deterministic merge)<br>"
           "• <b>Settlement:</b> Instant (single transaction)<br>"
           "• <b>Covenant:</b> None (standard UTXOs)<br>"
           "• <b>Security:</b> Adaptor signatures prevent partial execution<br>"
           "• <b>Best For:</b> Quick swaps without complex terms"));
    infoLayout->addWidget(descriptionLabel);

    infoGroup->setLayout(infoLayout);
    mainLayout->addWidget(infoGroup);

    mainLayout->addSpacing(20);

    // Action buttons
    QHBoxLayout* buttonLayout = new QHBoxLayout();

    createButton = new QPushButton(tr("Create New Offer"), this);
    createButton->setToolTip(tr("Launch wizard to create a new contract offer"));
    createButton->setStyleSheet("QPushButton { padding: 10px 20px; font-weight: bold; }");
    connect(createButton, &QPushButton::clicked, this, &NewContractTab::onCreateContract);
    buttonLayout->addWidget(createButton);

    importButton = new QPushButton(tr("Import Offer"), this);
    importButton->setToolTip(tr("Import an existing offer from JSON or cosign session"));
    connect(importButton, &QPushButton::clicked, this, &NewContractTab::onImportOffer);
    buttonLayout->addWidget(importButton);

    // Proposer's step for a scalar-feed CFD they offered: paste the counterparty's acceptance to register
    // the contract locally (it then shows up in the Book). Kept persistent so a proposer who closed the app
    // between offer and acceptance can still complete it.
    importScalarAcceptanceButton = new QPushButton(tr("Import Scalar Acceptance"), this);
    importScalarAcceptanceButton->setToolTip(
        tr("Import a counterparty's acceptance JSON for a scalar-feed CFD you proposed, registering the "
           "contract so it appears in the Book"));
    connect(importScalarAcceptanceButton, &QPushButton::clicked, this, &NewContractTab::onImportScalarCfdAcceptance);
    buttonLayout->addWidget(importScalarAcceptanceButton);

    buttonLayout->addStretch();

    mainLayout->addLayout(buttonLayout);

    mainLayout->addStretch();

    setLayout(mainLayout);
}

void NewContractTab::onContractTypeChanged()
{
    if (repoRadio->isChecked()) {
        descriptionLabel->setText(
            tr("<b>Repo Contract Features:</b><br>"
               "• <b>Parties:</b> Lender and Borrower<br>"
               "• <b>Collateral:</b> Any Registered Assets or Native Coin, collateral is escrowed, can be redeemed before maturity by delivering exactly the agreed Principal + Interest (in their respective denomination) to the lender address. Can be taken by the lender after maturity.<br>"
               "• <b>Principal:</b> Any Registered Assets or Native Coin, this is transferred by the lender to the borrower and disposable by the borrower. Same quantity needs to be delivered before maturity to redeem collateral.<br>"
               "• <b>Interest:</b> Any Registered Assets or Native Coin, this is a fixed amount that is agreed upfront and included in the condition for Collateral return. Borrower needs to pay it in order to release held collateral.<br>"
               "• <b>Maturity:</b> Fixed Block Heights<br>"
               "• <b>Fees:</b> each party is responsible for arranging delivery and pay appropriate fees<br>"
               "• <b>Notes:</b> for simplicity the building wizard allow to specify maturity in calendar terms, they will solve for an interest rate in annualised percentage and a Loan to Value, requesting the user to specify a fair price for the Collateral/Principal. These are provided for convenience but please note that the actual contract will specify fixed quantities and block heights.<br>"
               "• <b>Technical implementation:</b> Taproot v1 script, key paths disabled with NUMS addresses, multileaf using opcodes."));
    } else if (forwardRadio->isChecked()) {
        descriptionLabel->setText(
            tr("<b>Forward Contract Features:</b><br>"
               "• <b>Parties:</b> Long and Short party<br>"
               "• <b>Long Asset:</b> Any Registered Assets or Native Coin, Long Party receives the specified quantity at or before Long Maturity<br>"
               "• <b>Short Asset:</b> Any Registered Assets or Native Coin, Short Party receives the specified quantity at or before Short Maturity<br>"
               "• <b>Long Initial Margin:</b> Any Registered Assets or Native Coin, Long Party escrows the specified quantity until Long Maturity. If Long Party forfeit delivery of Long Asset (and the trade is not cash settled before), Short Party can claim from Escrow. Otherwise returned to Long party at delivery or early closeout.<br>"
               "• <b>Short Initial Margin:</b> Any Registered Assets or Native Coin, Short Party escrows the specified quantity until Short Maturity. If Short Party forfeit delivery of Short Asset (and the trade is not cash settled before), Long Party can claim from Escrow. Otherwise returned to Short party at delivery or early closeout.<br>"
               "• <b>Long Maturity:</b> Fixed Block height<br>"
               "• <b>Short Maturity:</b> Long Maturity + Offset for sequential delivery<br>"
               "• <b>Premium:</b> a premium can be added to immunise each party for extra fees, defaulted to 0<br>"
               "• <b>Cooperative Close:</b> either parties can chose to terminate the transaction and release respective initial margins for a payment.<br>"
               "• <b>Fees:</b> each party is responsible for arranging delivery and pay appropriate fees<br>"
               "• <b>Technical implementation:</b> Taproot v1 script, key paths disabled with NUMS addresses, multileaf using opcodes."));
    } else if (optionsRadio->isChecked()) {
        descriptionLabel->setText(
            tr("<b>Option Contract Features:</b><br>"
               "• <b>Parties:</b> Long and Short party<br>"
               "• <b>Long Asset:</b> Any Registered Assets or Native Coin, Long Party receives the specified quantity at or before Long Maturity<br>"
               "• <b>Short Asset:</b> Any Registered Assets or Native Coin, Short Party receives the specified quantity at or before Short Maturity<br>"
               "• <b>Long Initial Margin:</b> Any Registered Assets or Native Coin, Long Party escrows the specified quantity until Long Maturity. If Long Party forfeit delivery of Long Asset (and the trade is not cash settled before), Short Party can claim from Escrow. Otherwise returned to Long party at delivery or early closeout.<br>"
               "• <b>Short Initial Margin:</b> Any Registered Assets or Native Coin, Short Party escrows the specified quantity until Short Maturity. If Short Party forfeit delivery of Short Asset (and the trade is not cash settled before), Long Party can claim from Escrow. Otherwise returned to Short party at delivery or early closeout.<br>"
               "• <b>Long Maturity:</b> Fixed Block height<br>"
               "• <b>Short Maturity:</b> Long Maturity + Offset for sequential delivery<br>"
               "• <b>Premium:</b> a premium can be added to immunise each party for extra fees, or for option pricing<br>"
               "• <b>Cooperative Close:</b> either parties can chose to terminate the transaction and release respective initial margins for a payment.<br>"
               "• <b>Fees:</b> each party is responsible for arranging delivery and pay appropriate fees<br>"
               "• <b>Technical implementation:</b> Taproot v1 script, key paths disabled with NUMS addresses, multileaf using opcodes."));
    } else if (spotRadio->isChecked()) {
        descriptionLabel->setText(
            tr("<b>Spot Swap Features:</b><br>"
               "• <b>Type:</b> Atomic asset-for-asset exchange<br>"
               "• <b>Mechanism:</b> CoinJoin PSBT (deterministic merge)<br>"
               "• <b>Settlement:</b> Instant (single transaction)<br>"
               "• <b>Covenant:</b> None (standard UTXOs)<br>"
               "• <b>Security:</b> Adaptor signatures prevent partial execution<br>"
               "• <b>Best For:</b> Quick swaps without complex terms"));
    } else if (difficultyRadio->isChecked()) {
        descriptionLabel->setText(
            tr("<b>Difficulty Derivative Features:</b><br>"
               "• <b>Parties:</b> Long and Short (CFD), or Writer and Buyer (Option)<br>"
               "• <b>Underlying:</b> the network's compact difficulty target (nBits) at a buried fixing height<br>"
               "• <b>Initial Margin:</b> native TSC, escrowed per leg; settled unilaterally as a clamped-linear "
               "function of realized difficulty vs the agreed strike (leverage = lambda)<br>"
               "• <b>Option:</b> a single margined writer leg plus an upfront premium paid buyer → writer<br>"
               "• <b>Settlement:</b> signatureless covenant after the fixing height is buried; either party (or a "
               "keeper) can settle<br>"
               "• <b>Cooperative Close:</b> a 2-of-2 cosign leaf lets both parties close early to an agreed split<br>"
               "• <b>Technical implementation:</b> Taproot v1, NUMS internal key, OP_DIFFCFD_SETTLE covenant leaf"));
    } else if (scalarCfdRadio->isChecked()) {
        descriptionLabel->setText(
            tr("<b>Scalar-feed CFD Features:</b><br>"
               "• <b>Parties:</b> Long and Short<br>"
               "• <b>Underlying:</b> a published scalar feed value (feed id + fixing epoch), with a fallback "
               "scalar if the fixing is not published by the deadline<br>"
               "• <b>Initial Margin:</b> posted per leg in the collateral's units (native TSC for now); settled "
               "unilaterally as a clamped-linear function of the realized scalar vs the agreed strike K "
               "(leverage = lambda)<br>"
               "• <b>Payoff mode:</b> STRIKE (denominated in K) or REALIZED (denominated in the realized X)<br>"
               "• <b>Settlement:</b> signatureless covenant after the settle-lock height; either party (or a "
               "keeper) can settle<br>"
               "• <b>Cooperative Close:</b> a 2-of-2 cosign leaf lets both parties close early to an agreed split<br>"
               "• <b>Technical implementation:</b> Taproot v1, NUMS internal key, per-leg scalar-CFD settle leaf"));
    }
}

void NewContractTab::onCreateContract()
{
    if (!walletModel) {
        QMessageBox::warning(TopLevelDialogParent(this), tr("Error"), tr("Wallet model not available"));
        return;
    }

    if (repoRadio->isChecked()) {
        launchRepoWizard();
    } else if (forwardRadio->isChecked()) {
        launchForwardWizard();
    } else if (optionsRadio->isChecked()) {
        launchOptionsWizard();
    } else if (spotRadio->isChecked()) {
        launchSpotWizard();
    } else if (difficultyRadio->isChecked()) {
        launchDifficultyWizard();
    } else if (scalarCfdRadio->isChecked()) {
        launchScalarCfdWizard();
    }
}

void NewContractTab::onImportScalarCfdAcceptance()
{
    if (!walletModel) {
        QMessageBox::warning(TopLevelDialogParent(this), tr("Error"), tr("Wallet model not available"));
        return;
    }
    showScalarCfdImportAcceptanceDialog();
}

void NewContractTab::onImportOffer()
{
    if (!walletModel) {
        QMessageBox::warning(TopLevelDialogParent(this), tr("Error"), tr("Wallet model not available"));
        return;
    }

    showImportOfferDialog();
}

void NewContractTab::launchRepoWizard()
{
    // Launch Repo Contract Builder wizard
    RepoContractBuilder wizard(walletModel, TopLevelDialogParent(this));

    if (wizard.exec() == QDialog::Accepted) {
        QWidget* dialog_parent = TopLevelDialogParent(this);
        const bool hasFinalOffer = wizard.hasFinalOffer();
        QString offerId = wizard.getOfferId();
        QVariantMap offerData = wizard.getOfferData();
        QString termSheetJson = wizard.getTermSheetJson();

        if (termSheetJson.isEmpty()) {
            QMessageBox::critical(dialog_parent, tr("Error"), tr("Failed to generate repo term sheet."));
            return;
        }

        if (hasFinalOffer && !offerId.isEmpty()) {
            Q_EMIT contractCreated("repo", offerId);
        }

        QString heading = hasFinalOffer
            ? tr("Repo contract offer created!\n\nOffer ID: %1\n\nChoose how to share this offer:").arg(offerId)
            : tr("Repo term sheet prepared!\n\nA counterparty must supply their repayment address to finalize.\n\nChoose how to proceed:");

        // Create custom dialog with multiple sharing options
        QMessageBox shareDialog(dialog_parent);
        shareDialog.setWindowTitle(tr("Repo Contract Ready"));
        shareDialog.setText(heading);
        shareDialog.setIcon(QMessageBox::Information);

        QPushButton* postBBButton = shareDialog.addButton(tr("Publish to Market"), QMessageBox::AcceptRole);
        postBBButton->setStyleSheet("QPushButton { background-color: #4caf50; color: white; font-weight: bold; }");
        QPushButton* exportButton = shareDialog.addButton(tr("Export Manually"), QMessageBox::ActionRole);
        QPushButton* openButton = shareDialog.addButton(tr("Open Now"), QMessageBox::ActionRole);
        shareDialog.addButton(tr("Decide Later"), QMessageBox::RejectRole);

        shareDialog.setDefaultButton(postBBButton);
        shareDialog.exec();

        QAbstractButton* clickedButton = shareDialog.clickedButton();

        LogPrintf("[NewContractTab] Share dialog clicked button: %p vs postBBButton: %p\n", clickedButton, postBBButton);

        if (clickedButton == postBBButton) {
            LogPrintf("[NewContractTab] Publish to Market branch entered\n");

            // Post to bulletin board (term sheet)
            QString role = offerData.value("role").toString();
            double apr = offerData.value("apr_percent").toDouble();
            double ltv = offerData.value("ltv_percent").toDouble();
            int tenor_days = offerData.value("tenor_days").toInt();

            LogPrintf("[NewContractTab] offerId: %s role: %s walletModel: %p\n",
                      offerId.toStdString(), role.toStdString(), walletModel);

            // Optional: Attach proof of funds
            QVariantList proofs;
            LogPrintf("[NewContractTab] About to show proof prompt dialog\n");
            QMessageBox::StandardButton attachProof = QMessageBox::question(dialog_parent,
                tr("Attach Proof of Funds?"),
                tr("Would you like to attach a proof of funds to increase trust?\n\n"
                   "This will allow takers to verify you control the assets before engaging in the contract."),
                QMessageBox::Yes | QMessageBox::No,
                QMessageBox::No);

            LogPrintf("[NewContractTab] Proof prompt returned: %d (Yes=%d)\n",
                      (int)attachProof, (int)QMessageBox::Yes);

            if (attachProof == QMessageBox::Yes) {
                LogPrintf("[NewContractTab] User clicked Yes, launching ProofBuilder\n");

                // Determine which asset to prove based on role
                QString assetToProve;
                QString context;
                if (role == "lender") {
                    // Lender proves principal asset
                    bool principalIsNative = offerData.value("principal_is_native", true).toBool();
                    if (!principalIsNative) {
                        assetToProve = offerData.value("principal_asset_id").toString();
                    }
                    // For native assets, use empty string (wallet will list native UTXOs)
                    context = QString("offer:%1:lender").arg(offerId);
                } else {  // borrower
                    // Borrower proves collateral asset
                    bool collateralIsNative = offerData.value("collateral_is_native", true).toBool();
                    if (!collateralIsNative) {
                        assetToProve = offerData.value("collateral_asset_id").toString();
                    }
                    // For native assets, use empty string
                    context = QString("offer:%1:borrower").arg(offerId);
                }

                ProofBuilder proofDialog(walletModel, assetToProve, context, dialog_parent);
                if (proofDialog.exec() == QDialog::Accepted) {
                    proofs = proofDialog.getProofs();
                    LogPrintf("[NewContractTab] ProofBuilder accepted with %d proofs\n", proofs.size());
                } else {
                    LogPrintf("[NewContractTab] ProofBuilder cancelled/rejected\n");
                }
            }

            // Debug: Log proof count
            LogPrintf("[NewContractTab] Posting offer with %d proofs\n", proofs.size());
            for (int i = 0; i < proofs.size(); ++i) {
                QVariantMap proof = proofs[i].toMap();
                LogPrintf("  Proof %d: %s asset_id=%s units=%lld\n", i,
                          proof["utxo_ref"].toString().toStdString().c_str(),
                          proof["asset_id"].toString().toStdString().c_str(),
                          proof["asset_units"].toLongLong());
            }

            auto result = walletModel->bulletinBoardPostContractOffer("repo", termSheetJson, role, apr, ltv, tenor_days, proofs);

            if (result.success) {
                QMessageBox::information(dialog_parent, tr("Posted to Bulletin Board"),
                    tr("Term sheet posted to Nostr!\n\nOffer ID: %1\n\nCounterparties can now review the terms and provide their addresses.").arg(result.offer_id));
            } else {
                QMessageBox::warning(dialog_parent, tr("Posting Failed"), tr("Failed: %1").arg(result.error));
            }

        } else if (clickedButton == exportButton) {
            if (!hasFinalOffer || offerId.isEmpty()) {
                QMessageBox::warning(dialog_parent, tr("Missing Counterparty Details"),
                    tr("Collect the counterparty's repayment address before exporting a finalized offer."));
                return;
            }

            QMessageBox::information(dialog_parent, tr("Export Offer"),
                tr("Export via JSON or active cosign session.\n\nOffer ID: %1").arg(offerId));

        } else if (clickedButton == openButton) {
            if (!hasFinalOffer || offerId.isEmpty()) {
                QMessageBox::warning(dialog_parent, tr("Missing Counterparty Details"),
                    tr("Cannot open the contract until both parties' addresses are finalized."));
                return;
            }

            OpenContractDialog openDialog(walletModel, offerId, "repo", offerData, dialog_parent);
            if (openDialog.exec() == QDialog::Accepted && openDialog.wasOpened()) {
                QMessageBox::information(dialog_parent, tr("Contract Opened"),
                    tr("Contract opened!\n\nTXID: %1").arg(openDialog.getOpeningTxId()));
            }
        }
    }
}

void NewContractTab::launchForwardWizard()
{
    // Launch Forward Contract Builder wizard
    ForwardContractBuilder wizard(walletModel, false, TopLevelDialogParent(this)); // false = forward, true = option

    if (wizard.exec() == QDialog::Accepted) {
        QWidget* dialog_parent = TopLevelDialogParent(this);
        const bool hasFinalOffer = wizard.hasFinalOffer();
        QString offerId = wizard.getOfferId();
        QVariantMap offerData = wizard.getOfferData();
        QString termSheetJson = wizard.getTermSheetJson();

        if (termSheetJson.isEmpty()) {
            QMessageBox::critical(dialog_parent, tr("Error"), tr("Failed to generate forward term sheet."));
            return;
        }

        if (hasFinalOffer && !offerId.isEmpty()) {
            Q_EMIT contractCreated("forward", offerId);
        }

        QString heading = hasFinalOffer
            ? tr("Forward contract offer created!\n\nOffer ID: %1\n\nChoose how to share this offer:").arg(offerId)
            : tr("Forward term sheet prepared!\n\nA counterparty must supply their settlement addresses to finalize.\n\nChoose how to proceed:");

        // Create custom dialog with multiple sharing options
        QMessageBox shareDialog(dialog_parent);
        shareDialog.setWindowTitle(tr("Forward Contract Ready"));
        shareDialog.setText(heading);
        shareDialog.setIcon(QMessageBox::Information);

        QPushButton* postBBButton = shareDialog.addButton(tr("Publish to Market"), QMessageBox::AcceptRole);
        postBBButton->setStyleSheet("QPushButton { background-color: #4caf50; color: white; font-weight: bold; }");
        QPushButton* exportButton = shareDialog.addButton(tr("Export Manually"), QMessageBox::ActionRole);
        // Forward opening flow not yet implemented - "Open Now" disabled for forward contracts
        // QPushButton* openButton = shareDialog.addButton(tr("Open Now"), QMessageBox::ActionRole);
        shareDialog.addButton(tr("Decide Later"), QMessageBox::RejectRole);

        shareDialog.setDefaultButton(postBBButton);
        shareDialog.exec();

        QAbstractButton* clickedButton = shareDialog.clickedButton();

        if (clickedButton == postBBButton) {
            // Post to bulletin board (term sheet)
            QString role = offerData.value("role").toString();
            double shortTenorDays = offerData.value("tenor_days_short", 0).toDouble();
            double longTenorDays = offerData.value("tenor_days_long", 0).toDouble();
            double longImPct = offerData.value("long_im_percent", 0).toDouble();
            double shortImPct = offerData.value("short_im_percent", 0).toDouble();

            // Use average IM% as metric for bulletin board filtering
            double avgIm = (longImPct + shortImPct) / 2.0;

            auto result = walletModel->bulletinBoardPostContractOffer("forward", termSheetJson, role, avgIm, longTenorDays, shortTenorDays);

            if (result.success) {
                QMessageBox::information(dialog_parent, tr("Posted to Bulletin Board"),
                    tr("Term sheet posted to Nostr!\n\nOffer ID: %1\n\nCounterparties can now review the terms and provide their addresses.").arg(result.offer_id));
            } else {
                QMessageBox::warning(dialog_parent, tr("Posting Failed"), tr("Failed: %1").arg(result.error));
            }

        } else if (clickedButton == exportButton) {
            if (!hasFinalOffer || offerId.isEmpty()) {
                QMessageBox::warning(dialog_parent, tr("Missing Counterparty Details"),
                    tr("Collect the counterparty's settlement addresses before exporting a finalized offer."));
                return;
            }

            QMessageBox::information(dialog_parent, tr("Export Offer"),
                tr("Export via JSON or active cosign session.\n\nOffer ID: %1").arg(offerId));

        /* Forward opening flow not yet implemented - commented out
        } else if (clickedButton == openButton) {
            if (!hasFinalOffer || offerId.isEmpty()) {
                QMessageBox::warning(this, tr("Missing Counterparty Details"),
                    tr("Cannot open the contract until both parties' addresses are finalized."));
                return;
            }

            OpenContractDialog openDialog(walletModel, offerId, "forward", offerData, this);
            if (openDialog.exec() == QDialog::Accepted && openDialog.wasOpened()) {
                QMessageBox::information(this, tr("Contract Opened"),
                    tr("Contract opened!\n\nTXID: %1").arg(openDialog.getOpeningTxId()));
            }
        */
        }
    }
}

void NewContractTab::launchOptionsWizard()
{
    // Launch Option Contract Builder wizard (same as Forward but with isOption=true)
    ForwardContractBuilder wizard(walletModel, true, TopLevelDialogParent(this)); // true = option mode

    if (wizard.exec() == QDialog::Accepted) {
        QWidget* dialog_parent = TopLevelDialogParent(this);
        const bool hasFinalOffer = wizard.hasFinalOffer();
        QString offerId = wizard.getOfferId();
        QVariantMap offerData = wizard.getOfferData();
        QString termSheetJson = wizard.getTermSheetJson();

        if (termSheetJson.isEmpty()) {
            QMessageBox::critical(dialog_parent, tr("Error"), tr("Failed to generate option term sheet."));
            return;
        }

        if (hasFinalOffer && !offerId.isEmpty()) {
            Q_EMIT contractCreated("option", offerId);
        }

        QString heading = hasFinalOffer
            ? tr("Option contract offer created!\n\nOffer ID: %1\n\nChoose how to share this offer:").arg(offerId)
            : tr("Option term sheet prepared!\n\nA counterparty must supply their settlement addresses to finalize.\n\nChoose how to proceed:");

        // Create custom dialog with multiple sharing options
        QMessageBox shareDialog(dialog_parent);
        shareDialog.setWindowTitle(tr("Option Contract Ready"));
        shareDialog.setText(heading);
        shareDialog.setIcon(QMessageBox::Information);

        QPushButton* postBBButton = shareDialog.addButton(tr("Publish to Market"), QMessageBox::AcceptRole);
        postBBButton->setStyleSheet("QPushButton { background-color: #4caf50; color: white; font-weight: bold; }");
        QPushButton* exportButton = shareDialog.addButton(tr("Export Manually"), QMessageBox::ActionRole);
        // Option opening flow not yet implemented - "Open Now" disabled for option contracts
        // QPushButton* openButton = shareDialog.addButton(tr("Open Now"), QMessageBox::ActionRole);
        shareDialog.addButton(tr("Decide Later"), QMessageBox::RejectRole);

        shareDialog.setDefaultButton(postBBButton);
        shareDialog.exec();

        QAbstractButton* clickedButton = shareDialog.clickedButton();

        if (clickedButton == postBBButton) {
            // Post to bulletin board (term sheet)
            QString role = offerData.value("role").toString();
            double shortTenorDays = offerData.value("tenor_days_short", 0).toDouble();
            double longTenorDays = offerData.value("tenor_days_long", 0).toDouble();
            double premiumAmount = offerData.value("premium_units", 0).toDouble();

            // Options are posted as "forward" type (with has_premium flag in the term sheet)
            auto result = walletModel->bulletinBoardPostContractOffer("forward", termSheetJson, role, premiumAmount, longTenorDays, shortTenorDays);

            if (result.success) {
                QMessageBox::information(dialog_parent, tr("Posted to Bulletin Board"),
                    tr("Term sheet posted to Nostr!\n\nOffer ID: %1\n\nCounterparties can now review the terms and provide their addresses.").arg(result.offer_id));
            } else {
                QMessageBox::warning(dialog_parent, tr("Posting Failed"), tr("Failed: %1").arg(result.error));
            }

        } else if (clickedButton == exportButton) {
            if (!hasFinalOffer || offerId.isEmpty()) {
                QMessageBox::warning(dialog_parent, tr("Missing Counterparty Details"),
                    tr("Collect the counterparty's settlement addresses before exporting a finalized offer."));
                return;
            }

            QMessageBox::information(dialog_parent, tr("Export Offer"),
                tr("Export via JSON or active cosign session.\n\nOffer ID: %1").arg(offerId));

        /* Option opening flow not yet implemented - commented out
        } else if (clickedButton == openButton) {
            if (!hasFinalOffer || offerId.isEmpty()) {
                QMessageBox::warning(this, tr("Missing Counterparty Details"),
                    tr("Cannot open the contract until both parties' addresses are finalized."));
                return;
            }

            OpenContractDialog openDialog(walletModel, offerId, "option", offerData, this);
            if (openDialog.exec() == QDialog::Accepted && openDialog.wasOpened()) {
                QMessageBox::information(this, tr("Contract Opened"),
                    tr("Contract opened!\n\nTXID: %1").arg(openDialog.getOpeningTxId()));
            }
        */
        }
    }
}

void NewContractTab::launchSpotWizard()
{
    // Launch Spot Contract Builder wizard
    SpotContractBuilder wizard(walletModel, TopLevelDialogParent(this));

    if (wizard.exec() == QDialog::Accepted) {
        QWidget* dialog_parent = TopLevelDialogParent(this);
        const bool hasFinalOffer = wizard.hasFinalOffer();
        QString offerId = wizard.getOfferId();
        QVariantMap offerData = wizard.getOfferData();
        QString termSheetJson = wizard.getTermSheetJson();

        if (termSheetJson.isEmpty()) {
            QMessageBox::critical(dialog_parent, tr("Error"), tr("Failed to generate spot term sheet."));
            return;
        }

        if (hasFinalOffer && !offerId.isEmpty()) {
            Q_EMIT contractCreated("spot", offerId);
        }

        // Note: require_commitment_proof flag is included in offerData and termSheetJson
        // When counterparty accepts and PSBTs are joined, CommitmentProofDialog will be used
        // if commitment proof is required (for WRAP_REQUIRED assets)

        QString heading = hasFinalOffer
            ? tr("Spot swap offer created!\n\nOffer ID: %1\n\nChoose how to share this offer:").arg(offerId)
            : tr("Spot term sheet prepared!\n\nA counterparty must accept to finalize.\n\nChoose how to proceed:");

        // Create custom dialog with multiple sharing options
        QMessageBox shareDialog(dialog_parent);
        shareDialog.setWindowTitle(tr("Spot Swap Ready"));
        shareDialog.setText(heading);
        shareDialog.setIcon(QMessageBox::Information);

        QPushButton* postWithProofButton = shareDialog.addButton(tr("Publish with Proof"), QMessageBox::AcceptRole);
        postWithProofButton->setStyleSheet("QPushButton { background-color: #2e7d32; color: white; font-weight: bold; }");
        QPushButton* postBBButton = shareDialog.addButton(tr("Publish to Market"), QMessageBox::AcceptRole);
        postBBButton->setStyleSheet("QPushButton { background-color: #4caf50; color: white; font-weight: bold; }");
        QPushButton* exportButton = shareDialog.addButton(tr("Export Manually"), QMessageBox::ActionRole);
        shareDialog.addButton(tr("Decide Later"), QMessageBox::RejectRole);

        shareDialog.setDefaultButton(postWithProofButton);
        shareDialog.exec();

        QAbstractButton* clickedButton = shareDialog.clickedButton();

        if (clickedButton == postWithProofButton || clickedButton == postBBButton) {
            // Post to bulletin board (term sheet)
            double exchangeRate = offerData.value("exchange_rate", 0).toDouble();

            QVariantList proofs;
            if (clickedButton == postWithProofButton) {
                // Determine which asset to prove (alice's delivery asset)
                QString assetToProve;
                bool aliceIsNative = offerData.value("alice_is_native", true).toBool();
                if (!aliceIsNative) {
                    assetToProve = offerData.value("alice_asset_id").toString();
                }
                QString context = QString("offer:%1:alice").arg(offerId);

                ProofBuilder proofDialog(walletModel, assetToProve, context, dialog_parent);
                if (proofDialog.exec() == QDialog::Accepted) {
                    proofs = proofDialog.getProofs();
                }
            }

            auto result = walletModel->bulletinBoardPostContractOffer("spot", termSheetJson, "alice", exchangeRate, 0, 0, proofs);

            if (result.success) {
                QMessageBox::information(dialog_parent, tr("Posted to Bulletin Board"),
                    tr("Term sheet posted to Nostr!\n\nOffer ID: %1\n\nCounterparties can now review and accept the swap.").arg(result.offer_id));
            } else {
                QMessageBox::warning(dialog_parent, tr("Posting Failed"), tr("Failed: %1").arg(result.error));
            }

        } else if (clickedButton == exportButton) {
            if (!hasFinalOffer || offerId.isEmpty()) {
                QMessageBox::warning(dialog_parent, tr("Missing Counterparty Details"),
                    tr("Collect the counterparty's acceptance before exporting."));
                return;
            }

            QMessageBox::information(dialog_parent, tr("Export Offer"),
                tr("Export via JSON or active cosign session.\n\nOffer ID: %1").arg(offerId));
        }
    }
}

void NewContractTab::launchDifficultyWizard()
{
    // Narrow scope: build the proposer's offer JSON (CFD or option) and let the user copy/share it.
    DifficultyContractBuilder wizard(walletModel, TopLevelDialogParent(this));

    if (wizard.exec() == QDialog::Accepted) {
        QWidget* dialog_parent = TopLevelDialogParent(this);
        const QString offerJson = wizard.getOfferJson();
        if (offerJson.isEmpty()) {
            QMessageBox::critical(dialog_parent, tr("Error"), tr("Failed to create the difficulty offer."));
            return;
        }

        Q_EMIT contractCreated("difficulty", QString());

        const QString termSheetJson = wizard.getTermSheetJson();

        QMessageBox shareDialog(dialog_parent);
        shareDialog.setWindowTitle(tr("Difficulty Offer Created"));
        shareDialog.setIcon(QMessageBox::Information);
        shareDialog.setText(tr("Your difficulty offer was created.\n\n"
                               "Share the offer JSON with your counterparty — they accept it with "
                               "difficulty.accept (or difficulty.accept_option), then both parties open and settle.\n\n"
                               "The structured term sheet (difficulty_term_sheet_v1) carries the same terms plus a "
                               "pricing metrics block for display/market posting."));
        shareDialog.setDetailedText(offerJson);
        QPushButton* copyButton = shareDialog.addButton(tr("Copy Offer JSON"), QMessageBox::ActionRole);
        QPushButton* copyTermSheetButton = termSheetJson.isEmpty()
            ? nullptr : shareDialog.addButton(tr("Copy Term Sheet"), QMessageBox::ActionRole);
        shareDialog.addButton(QMessageBox::Close);
        shareDialog.exec();

        if (shareDialog.clickedButton() == copyButton) {
            GUIUtil::setClipboard(offerJson);
        } else if (copyTermSheetButton && shareDialog.clickedButton() == copyTermSheetButton) {
            GUIUtil::setClipboard(termSheetJson);
        }
    }
}

void NewContractTab::launchScalarCfdWizard()
{
    // Narrow scope: build the proposer's scalar-feed CFD offer JSON and let the user copy/share it (and,
    // once the counterparty returns an acceptance, import it to register the contract into the Book).
    ScalarCfdContractBuilder wizard(walletModel, TopLevelDialogParent(this));

    if (wizard.exec() == QDialog::Accepted) {
        QWidget* dialog_parent = TopLevelDialogParent(this);
        const QString offerJson = wizard.getOfferJson();
        if (offerJson.isEmpty()) {
            QMessageBox::critical(dialog_parent, tr("Error"), tr("Failed to create the scalar-feed CFD offer."));
            return;
        }

        Q_EMIT contractCreated("scalarcfd", QString());

        const QString termSheetJson = wizard.getTermSheetJson();

        QMessageBox shareDialog(dialog_parent);
        shareDialog.setWindowTitle(tr("Scalar CFD Offer Created"));
        shareDialog.setIcon(QMessageBox::Information);
        shareDialog.setText(tr("Your scalar-feed CFD offer was created.\n\n"
                               "Send the counterparty the Term Sheet below and have them accept it via "
                               "'Import Offer' — that opens the review + accept dialog and produces an "
                               "acceptance JSON. Then use 'Import Acceptance' here to register the contract into "
                               "the Book, and both parties open and settle.\n\n"
                               "(The raw offer JSON also works with 'Import Offer', but the term sheet is the "
                               "richer artifact for review.)"));
        shareDialog.setDetailedText(termSheetJson.isEmpty() ? offerJson : termSheetJson);
        QPushButton* copyTermSheetButton = termSheetJson.isEmpty()
            ? nullptr : shareDialog.addButton(tr("Copy Term Sheet"), QMessageBox::ActionRole);
        QPushButton* copyButton = shareDialog.addButton(tr("Copy Raw Offer JSON"), QMessageBox::ActionRole);
        QPushButton* importAcceptanceButton = shareDialog.addButton(tr("Import Acceptance…"), QMessageBox::ActionRole);
        shareDialog.addButton(QMessageBox::Close);
        if (copyTermSheetButton) shareDialog.setDefaultButton(copyTermSheetButton);
        shareDialog.exec();

        if (copyTermSheetButton && shareDialog.clickedButton() == copyTermSheetButton) {
            GUIUtil::setClipboard(termSheetJson);
        } else if (shareDialog.clickedButton() == copyButton) {
            GUIUtil::setClipboard(offerJson);
        } else if (shareDialog.clickedButton() == importAcceptanceButton) {
            showScalarCfdImportAcceptanceDialog(offerJson);
        }
    }
}

void NewContractTab::showScalarCfdImportAcceptanceDialog(const QString& prefillOfferJson)
{
    QWidget* dialog_parent = TopLevelDialogParent(this);

    QDialog dialog(dialog_parent);
    dialog.setWindowTitle(tr("Import Scalar CFD Acceptance"));
    dialog.setMinimumWidth(560);

    QVBoxLayout* layout = new QVBoxLayout(&dialog);
    QLabel* intro = new QLabel(
        tr("Paste the offer you proposed and the counterparty's acceptance JSON. This registers the contract "
           "locally so it appears in the Book, ready to open and settle."), &dialog);
    intro->setWordWrap(true);
    layout->addWidget(intro);

    QFormLayout* form = new QFormLayout();
    QPlainTextEdit* offerEdit = new QPlainTextEdit(&dialog);
    offerEdit->setPlaceholderText(tr("your offer JSON"));
    offerEdit->setPlainText(prefillOfferJson);
    offerEdit->setMinimumHeight(90);
    form->addRow(tr("Offer:"), offerEdit);
    QPlainTextEdit* acceptanceEdit = new QPlainTextEdit(&dialog);
    acceptanceEdit->setPlaceholderText(tr("the counterparty's acceptance JSON"));
    acceptanceEdit->setMinimumHeight(90);
    form->addRow(tr("Acceptance:"), acceptanceEdit);
    layout->addLayout(form);

    QDialogButtonBox* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
    buttons->button(QDialogButtonBox::Ok)->setText(tr("Import"));
    layout->addWidget(buttons);
    connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);

    if (dialog.exec() != QDialog::Accepted) return;

    const QString offer = offerEdit->toPlainText().trimmed();
    const QString acceptance = acceptanceEdit->toPlainText().trimmed();
    if (offer.isEmpty() || acceptance.isEmpty()) {
        QMessageBox::warning(dialog_parent, tr("Missing Input"),
            tr("Both the offer and the acceptance JSON are required."));
        return;
    }

    WalletModel::ScalarCfdImportResult r = walletModel->scalarCfdImportAcceptance(offer, acceptance);
    if (!r.success) {
        QMessageBox::critical(dialog_parent, tr("Import Failed"),
            tr("Failed to import the acceptance:\n\n%1").arg(r.error));
        return;
    }

    Q_EMIT contractCreated("scalarcfd", r.contract_id);
    QMessageBox::information(dialog_parent, tr("Acceptance Imported"),
        tr("Contract %1 is now %2 and appears in the Book, ready to open.").arg(r.contract_id, r.state));
}

void NewContractTab::showImportOfferDialog()
{
    ImportOfferDialog dialog(walletModel, sessionManager, TopLevelDialogParent(this));

    if (dialog.exec() == QDialog::Accepted) {
        QString offerId = dialog.getOfferId();
        QString contractType = dialog.getContractType();

        QMessageBox::information(TopLevelDialogParent(this), tr("Offer Imported"),
            tr("Contract offer imported successfully!\n\nOffer ID: %1\nType: %2\n\n"
               "Review the offer details and accept if terms are agreeable.")
            .arg(offerId, contractType));
    }
}
