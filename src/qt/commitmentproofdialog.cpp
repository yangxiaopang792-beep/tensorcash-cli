// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <qt/commitmentproofdialog.h>
#include <qt/walletmodel.h>

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QTextEdit>
#include <QMessageBox>
#include <QDialogButtonBox>

CommitmentProofDialog::CommitmentProofDialog(WalletModel* model, const QString& offerId, const QString& myPsbt, QWidget* parent)
    : QDialog(parent),
      walletModel(model),
      m_offerId(offerId),
      m_myPsbt(myPsbt),
      m_expectedCommitmentCount(0)
{
    setWindowTitle(tr("Add Commitment Proof"));
    setMinimumWidth(600);
    setMinimumHeight(400);

    // Determine how many commitment proofs are expected by checking both legs
    determineExpectedCommitmentCount();

    setupUI();

    // If no commitments are needed (e.g., receiving only native assets), enable signing immediately
    if (m_expectedCommitmentCount == 0) {
        psbtWithCommitment = m_myPsbt; // Use original PSBT
        m_commitmentAdded = true; // Flow completed successfully (no commitment needed)
        updateStatus(tr("✓ No commitments required (no ICU assets received)"), false);
        statusLabel->setStyleSheet("QLabel { font-weight: bold; color: #4caf50; }");
        addCommitmentButton->setVisible(false);
        verifyButton->setVisible(false);
        acceptButton->setEnabled(true);

        QString info = tr("✓ This swap does not require commitment proofs\n\n");
        info += tr("You are not receiving any ICU holder-only assets that require decryption verification.\n");
        info += tr("You can proceed directly to signing.");
        commitmentInfoEdit->setPlainText(info);
    }
}

void CommitmentProofDialog::setupUI()
{
    QVBoxLayout* mainLayout = new QVBoxLayout(this);

    // Title
    QLabel* titleLabel = new QLabel(tr("<h3>Pre-Signing Decryption Commitment</h3>"), this);
    mainLayout->addWidget(titleLabel);

    // Explanation
    QLabel* explanationLabel = new QLabel(
        tr("This atomic swap requires cryptographic proof that you can decrypt the received asset "
           "BEFORE signing the transaction.\n\n"
           "The commitment process:\n"
           "1. Unwrap DEK (Data Encryption Key) from PSBT asset output\n"
           "2. Decrypt counterparty's ICU payload using the DEK\n"
           "3. Compute commitment: hash(canonical_text | your_receive_address)\n"
           "4. Add OP_RETURN output with commitment to transaction\n\n"
           "This provides cryptographic guarantee that you accept the received asset."), this);
    explanationLabel->setWordWrap(true);
    explanationLabel->setStyleSheet("QLabel { color: #666; }");
    mainLayout->addWidget(explanationLabel);

    mainLayout->addSpacing(10);

    // Status label
    statusLabel = new QLabel(tr("Ready to add commitment proof"), this);
    statusLabel->setStyleSheet("QLabel { font-weight: bold; color: #1976d2; }");
    mainLayout->addWidget(statusLabel);

    // Commitment info display
    commitmentInfoEdit = new QTextEdit(this);
    commitmentInfoEdit->setReadOnly(true);
    commitmentInfoEdit->setMaximumHeight(150);
    commitmentInfoEdit->setPlaceholderText(tr("Commitment details will appear here after adding proof..."));
    mainLayout->addWidget(commitmentInfoEdit);

    mainLayout->addSpacing(10);

    // Action buttons
    QHBoxLayout* buttonLayout = new QHBoxLayout();

    addCommitmentButton = new QPushButton(tr("Add My Commitment Proof"), this);
    addCommitmentButton->setToolTip(tr("Decrypt counterparty's asset and add commitment OP_RETURN"));
    connect(addCommitmentButton, &QPushButton::clicked, this, &CommitmentProofDialog::onAddCommitment);
    buttonLayout->addWidget(addCommitmentButton);

    verifyButton = new QPushButton(tr("Verify Counterparty Commitment"), this);
    verifyButton->setToolTip(tr("Verify that counterparty has added their commitment proof"));
    verifyButton->setEnabled(false);
    connect(verifyButton, &QPushButton::clicked, this, &CommitmentProofDialog::onVerifyCommitments);
    buttonLayout->addWidget(verifyButton);

    buttonLayout->addStretch();
    mainLayout->addLayout(buttonLayout);

    // Dialog buttons
    QDialogButtonBox* dialogButtons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    acceptButton = dialogButtons->button(QDialogButtonBox::Ok);
    acceptButton->setText(tr("Continue to Signing"));
    acceptButton->setEnabled(false);
    connect(dialogButtons, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(dialogButtons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    mainLayout->addWidget(dialogButtons);

    setLayout(mainLayout);
}

void CommitmentProofDialog::onAddCommitment()
{
    if (!walletModel) {
        updateStatus(tr("Error: Wallet model not available"), true);
        return;
    }

    try {
        updateStatus(tr("Adding commitment proof..."), false);

        // Call spot.add_commitment_proof RPC
        // This will:
        // 1. Extract counterparty's asset output from PSBT
        // 2. Unwrap DEK from ICU_KEYWRAP
        // 3. Decrypt ICU payload
        // 4. Compute hash(canonical_text | own_receive_addr)
        // 5. Add OP_RETURN output with commitment hash

        QVariantMap result = walletModel->spotAddCommitmentProof(m_myPsbt, m_offerId);

        if (!result.value("success").toBool()) {
            const QString err = result.value("error").toString();

            // SPECIAL CASE: If receiving native asset, no commitment needed from this side
            // The counterparty (sending the asset) should add the commitment instead
            if (err.contains("native", Qt::CaseInsensitive) &&
                err.contains("Commitment proofs only apply to assets", Qt::CaseInsensitive)) {

                psbtWithCommitment = m_myPsbt; // Use original PSBT
                m_commitmentAdded = false; // We didn't add one, but that's correct

                QString info = tr("✓ No commitment required from your side\n\n");
                info += tr("You are receiving a native asset (TSC) which doesn't require decryption verification.\n");
                info += tr("Waiting for counterparty to add their commitment proof...\n");
                commitmentInfoEdit->setPlainText(info);

                updateStatus(tr("Checking for counterparty's commitment..."), false);
                statusLabel->setStyleSheet("QLabel { font-weight: bold; color: #ff9800; }");

                addCommitmentButton->setEnabled(false);
                verifyButton->setEnabled(true); // Allow manual verification check

                // Auto-verify to see if counterparty has already added their commitment
                onVerifyCommitments();
                return;
            }

            // Real error case
            updateStatus(tr("Failed: %1").arg(err), true);

            // Surface full error details in the text area so users
            // can see why the proof failed (e.g. decrypt errors).
            QString info;
            info += tr("✗ Unable to add commitment proof.\n\n");
            info += tr("Wallet error:\n%1\n").arg(err);
            commitmentInfoEdit->setPlainText(info);
            m_commitmentAdded = false;
            return;
        }

        psbtWithCommitment = result.value("psbt").toString();
        commitmentHash = result.value("commitment_hash").toString();
        QString commitmentInfo = result.value("commitment_preimage_info").toString();
        QString canonicalText = result.value("canonical_text").toString();

        m_commitmentAdded = true;

        // Display commitment details
        QString info;
        info += tr("✓ Commitment proof added successfully\n\n");
        info += tr("Commitment hash: %1\n\n").arg(commitmentHash);
        info += tr("Details: %1\n").arg(commitmentInfo);
        if (!canonicalText.isEmpty()) {
            info += "\n";
            info += tr("Decrypted ICU text (preview):\n%1\n").arg(canonicalText.left(512));
        }
        commitmentInfoEdit->setPlainText(info);

        updateStatus(tr("✓ Commitment added. Checking if ready..."), false);
        statusLabel->setStyleSheet("QLabel { font-weight: bold; color: #4caf50; }");

        addCommitmentButton->setEnabled(false);

        // Automatically verify commitments instead of requiring manual click
        onVerifyCommitments();

    } catch (const std::exception& e) {
        updateStatus(tr("Exception: %1").arg(QString::fromStdString(e.what())), true);
    }
}

void CommitmentProofDialog::onVerifyCommitments()
{
    if (!walletModel) {
        updateStatus(tr("Error: Wallet model not available"), true);
        return;
    }

    try {
        updateStatus(tr("Verifying commitments..."), false);

        // Decode PSBT to check for OP_RETURN outputs
        QVariantMap decoded = walletModel->decodePsbt(psbtWithCommitment);

        if (decoded.isEmpty()) {
            updateStatus(tr("Failed to decode PSBT"), true);
            return;
        }

        QVariantMap tx = decoded.value("tx").toMap();
        QVariantList vouts = tx.value("vout").toList();

        int opreturnCount = 0;
        QStringList commitments;

        for (const QVariant& voutVar : vouts) {
            QVariantMap vout = voutVar.toMap();
            QVariantMap scriptPubKey = vout.value("scriptPubKey").toMap();

            if (scriptPubKey.value("type").toString() == "nulldata") {
                opreturnCount++;
                QString asm_str = scriptPubKey.value("asm").toString();
                if (asm_str.startsWith("OP_RETURN ")) {
                    QString commitment = asm_str.mid(10); // Skip "OP_RETURN "
                    commitments.append(commitment);
                }
            }
        }

        QString info = commitmentInfoEdit->toPlainText();
        info += tr("\n--- Verification Results ---\n");
        info += tr("OP_RETURN outputs found: %1\n").arg(opreturnCount);
        info += tr("Expected commitments: %1\n").arg(m_expectedCommitmentCount);

        if (opreturnCount >= m_expectedCommitmentCount && m_expectedCommitmentCount > 0) {
            // Have enough commitments
            info += tr("✓ All required commitment proofs present\n\n");
            info += tr("Commitments:\n");
            for (int i = 0; i < commitments.size(); ++i) {
                info += tr("  %1. %2...\n").arg(i + 1).arg(commitments[i].left(32));
            }
            info += tr("\n✓ Ready to sign transaction");

            updateStatus(tr("✓ All commitments verified. Ready to sign."), false);
            statusLabel->setStyleSheet("QLabel { font-weight: bold; color: #4caf50; }");

            m_commitmentAdded = true; // Flow completed successfully (all required commitments present)
            verifyButton->setEnabled(false);
            acceptButton->setEnabled(true);

        } else if (opreturnCount > 0 && opreturnCount < m_expectedCommitmentCount) {
            info += tr("⚠ Only %1 of %2 required commitments found\n").arg(opreturnCount).arg(m_expectedCommitmentCount);
            info += tr("Waiting for counterparty to add their commitment proof...");

            updateStatus(tr("Waiting for counterparty's commitment"), false);
            statusLabel->setStyleSheet("QLabel { font-weight: bold; color: #ff9800; }");

        } else if (m_expectedCommitmentCount == 0) {
            info += tr("⚠ No commitments required for this swap (no ICU_KEYWRAP assets)\n");
            info += tr("You can proceed to signing.");

            updateStatus(tr("No commitments required"), false);
            statusLabel->setStyleSheet("QLabel { font-weight: bold; color: #4caf50; }");
            m_commitmentAdded = true; // Flow completed successfully (no commitments needed)
            acceptButton->setEnabled(true);

        } else {
            info += tr("✗ No commitment proofs found");
            updateStatus(tr("Error: No commitments found in PSBT"), true);
        }

        commitmentInfoEdit->setPlainText(info);

    } catch (const std::exception& e) {
        updateStatus(tr("Exception: %1").arg(QString::fromStdString(e.what())), true);
    }
}

void CommitmentProofDialog::updateStatus(const QString& message, bool isError)
{
    statusLabel->setText(message);
    if (isError) {
        statusLabel->setStyleSheet("QLabel { font-weight: bold; color: #d32f2f; }");
    } else {
        statusLabel->setStyleSheet("QLabel { font-weight: bold; color: #1976d2; }");
    }
}

void CommitmentProofDialog::determineExpectedCommitmentCount()
{
    if (!walletModel) {
        m_expectedCommitmentCount = 0;
        return;
    }

    // Query contract status to check which legs have ICU_KEYWRAP assets
    WalletModel::ContractStatusResult status = walletModel->getContractStatus(m_offerId);
    if (!status.success || !status.offer.contains("terms")) {
        m_expectedCommitmentCount = 0;
        return;
    }

    const QVariant termsVar = status.offer.value("terms");
    if (!termsVar.canConvert<QVariantMap>()) {
        m_expectedCommitmentCount = 0;
        return;
    }

    QVariantMap termsMap = termsVar.toMap();
    int commitmentCount = 0;

    // For atomic swaps, count non-native assets as potentially needing commitments.
    // Only ICU_KEYWRAP assets actually require commitments, but we can't reliably check
    // the policy here (getassetpolicy may not be synced yet).
    // The RPC spot.add_commitment_proof will validate and return error if no commitment needed,
    // which the dialog handles gracefully by skipping to counterparty verification.

    // Check Alice's leg
    if (termsMap.contains("alice_leg")) {
        QVariantMap aliceLeg = termsMap.value("alice_leg").toMap();
        if (!aliceLeg.value("is_native", false).toBool()) {
            QString assetId = aliceLeg.value("asset_id").toString();
            if (!assetId.isEmpty()) {
                commitmentCount++;
            }
        }
    }

    // Check Bob's leg
    if (termsMap.contains("bob_leg")) {
        QVariantMap bobLeg = termsMap.value("bob_leg").toMap();
        if (!bobLeg.value("is_native", false).toBool()) {
            QString assetId = bobLeg.value("asset_id").toString();
            if (!assetId.isEmpty()) {
                commitmentCount++;
            }
        }
    }

    m_expectedCommitmentCount = commitmentCount;
}
