// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_QT_PROOFBUILDER_H
#define BITCOIN_QT_PROOFBUILDER_H

#include <QDialog>
#include <QVariantList>
#include <QVariantMap>
#include <QTableWidget>

class WalletModel;

QT_BEGIN_NAMESPACE
class QLabel;
class QPushButton;
class QLineEdit;
class QTextEdit;
QT_END_NAMESPACE

/**
 * Dialog for building BIP-322 ownership proofs for contract offers.
 *
 * Allows user to:
 * 1. Select UTXOs containing a specific asset
 * 2. Sign a proof message with BIP-322
 * 3. Generate proof objects for bulletin board posts
 *
 * Usage:
 *   ProofBuilder dialog(walletModel, asset_id, message_context, this);
 *   if (dialog.exec() == QDialog::Accepted) {
 *       QVariantList proofs = dialog.getProofs();
 *   }
 */
class ProofBuilder : public QDialog
{
    Q_OBJECT

public:
    /**
     * Constructor
     *
     * @param walletModel Wallet model for UTXO listing and signing
     * @param asset_id Asset ID to filter UTXOs (hex string)
     * @param message_context Context for proof message (e.g., "offer_id:role")
     * @param parent Parent widget
     */
    explicit ProofBuilder(
        WalletModel* walletModel,
        const QString& asset_id,
        const QString& message_context,
        QWidget* parent = nullptr
    );

    ~ProofBuilder();

    /**
     * Get generated proofs after dialog is accepted
     *
     * @return List of proof objects, each containing:
     *   - utxo_ref (QString): "txid:vout"
     *   - address (QString): Bitcoin address
     *   - message (QString): Signed message
     *   - signature (QString): BIP-322 signature
     *   - asset_units (qint64): Asset units in UTXO
     *   - asset_id (QString): Asset ID (hex)
     */
    QVariantList getProofs() const { return m_proofs; }

private Q_SLOTS:
    void onRefreshUtxos();
    void onGenerateProofs();
    void onUtxoSelectionChanged();

private:
    void setupUI();
    void loadUtxos();
    QString constructProofMessage(const QString& address, const QString& asset_id);

    WalletModel* m_walletModel{nullptr};
    QString m_asset_id;
    QString m_message_context;  // e.g., "offer_id:role" or "offer_id:lender:ASSET123"
    QVariantList m_proofs;

    // UI components
    QLabel* m_assetLabel{nullptr};
    QLabel* m_statusLabel{nullptr};
    QTableWidget* m_utxoTable{nullptr};
    QLineEdit* m_messagePreview{nullptr};
    QTextEdit* m_instructionsText{nullptr};
    QPushButton* m_refreshButton{nullptr};
    QPushButton* m_generateButton{nullptr};
    QPushButton* m_cancelButton{nullptr};

    // UTXO data: maps row → utxo details
    QList<QVariantMap> m_utxos;
};

#endif // BITCOIN_QT_PROOFBUILDER_H
