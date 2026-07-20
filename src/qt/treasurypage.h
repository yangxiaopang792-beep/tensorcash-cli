// Copyright (c) 2024 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_TREASURYPAGE_H
#define BITCOIN_QT_TREASURYPAGE_H

#include <QPointer>
#include <QWidget>
#include <QTabWidget>
#include <QSet>
#include <QDateTime>
#include <QVector>
#include <QStringList>
#include <memory>
#include <optional>

#include <qt/walletmodel.h>  // WalletModel + its OptionSeriesTermsInput / result structs (used in slot signatures)

class ClientModel;
class PlatformStyle;
class ZKParamsManager;
class UniValue;

enum class SyncType;
enum class SynchronizationState;

QT_BEGIN_NAMESPACE
class QComboBox;
class QLineEdit;
class QPushButton;
class QTableWidget;
class QLabel;
class QSpinBox;
class QCheckBox;
class QProgressBar;
class QGroupBox;
class QTextEdit;
class QPlainTextEdit;
class QVBoxLayout;
class QTimer;
QT_END_NAMESPACE

/** Treasury page for asset issuer operations */
class TreasuryPage : public QWidget
{
    Q_OBJECT

public:
    explicit TreasuryPage(const PlatformStyle* platformStyle, QWidget* parent = nullptr);
    ~TreasuryPage();

    void setWalletModel(WalletModel* walletModel);
    void setClientModel(ClientModel* clientModel);
    void activateHolderView(const QString& assetId = QString());

public Q_SLOTS:
    void refreshAssetList();
    void refreshICUDashboard();

Q_SIGNALS:
    void message(const QString& title, const QString& message, unsigned int style);

private:
    void queueModeRefresh();

    // ICU clause-designation UX helpers (frontend; node does authoritative validation)
    void addClauseRow(const QString& initialText = QString(), const QString& initialLabel = QString());
    void removeClauseRow(QWidget* rowContainer);
    void updateClausesSummary();
    void addGovClauseRow(const QString& initialText = QString(), const QString& initialLabel = QString());
    void removeGovClauseRow(QWidget* rowContainer);
    void updateGovClausesSummary();
    void openExpandedEditor(QTextEdit* target, const QString& title);
    // Compose canonical = main body + appended "Designated clauses ..." schedule (one numbered
    // entry per clause). Returns "" + *errorOut on a label error.
    QString composeScheduleCanonical(const QString& body, QString* errorOut);
    // Assemble the TSC-ICU-CONTEXT-1 map from the clause rows (client-side; node re-validates).
    // Returns "" with *errorOut set when there are no clauses (whole-document acceptance).
    // hashesOut (optional) receives each clause's body_hash in clause-row order, so the caller can
    // attach per-clause witness attestations covering those exact hashes.
    // NOTE: under Option A (inline context) the node is authoritative for the clause map; this and
    // composeScheduleCanonical() are retained for the (separate) precheck path only and are NOT used
    // to build the authoritative map on the registration path.
    QString buildIcuContextJson(const QString& canonical, QString* errorOut, QStringList* hashesOut = nullptr);

    // Render the ICU viewer text for the dashboard: the canonical body, then the inline
    // TSC-ICU-CONTEXT-1 clauses parsed by the node (geticupayload "context"/"context_source")
    // rendered as a readable list (clause hash + text + acceptance mode). When context_source is
    // "none"/absent, just the body is shown (no witness JSON dump). `payload` is the geticupayload
    // result; `canonicalText` is the already-decoded canonical body.
    QString renderIcuViewerText(const QString& canonicalText, const UniValue& payload);

    // One designated-clause row (label + clause text + optional per-clause signature). Defined here
    // (before buildIcuPayloadFromForm, which takes a QVector<RegClauseRow>) and shared by the
    // Register form and the Governance amend form.
    struct RegClauseRow {
        QWidget* container{nullptr};
        QLineEdit* labelEdit{nullptr};
        QPlainTextEdit* textEdit{nullptr};
        QPlainTextEdit* attestEdit{nullptr};  // optional signature payload over THIS clause's body_hash
        QPushButton* removeButton{nullptr};
    };

    // Build the ICU payload hex from a governance form's fields (canonical body, freeform witness,
    // Designated Clauses -> icu_clauses inline context, whole-doc + per-clause signature attestations).
    // Widget-agnostic: shared by the standalone + sponsored-child registration paths AND the
    // Governance amend path. On failure it calls showError and returns ok=false.
    struct IcuPayloadBuildResult {
        bool ok{false};
        QString payloadPlain;
        QString canonicalHash;
        QString witnessHash;
        int payloadSize{0};
    };
    IcuPayloadBuildResult buildIcuPayloadFromForm(
        const QString& icuText, int visibility,
        QTextEdit* witnessEdit, const QVector<RegClauseRow>& clauseRows,
        QTextEdit* wholeDocAttest, QTextEdit* statusOut);

    // QPointer auto-nulls on WalletModel destruction so timer slots and
    // QFutureWatcher callbacks survive wallet unload / app shutdown.
    QPointer<WalletModel> walletModel;
    ClientModel* clientModel{nullptr};
    const PlatformStyle* m_platform_style;
    ZKParamsManager* m_zkParamsManager{nullptr};
    bool m_mode_refresh_queued{false};
    bool m_asset_list_refresh_in_progress{false};
    bool m_asset_list_refresh_pending{false};
    bool m_icu_dashboard_refresh_in_progress{false};
    bool m_icu_dashboard_refresh_pending{false};

    // Mode switcher
    QWidget* modeSwitcherWidget{nullptr};
    QPushButton* holderModeButton{nullptr};
    QPushButton* issuerModeButton{nullptr};
    bool isIssuerMode{false};

    // Main tab widget
    QTabWidget* tabWidget{nullptr};

    // ===== REGISTRATION TAB =====
    QWidget* registrationTab{nullptr};
    // Sponsored-child registration (ICU_CHILD.md §7): a mode control selects standalone-root vs
    // sponsored-child; in child mode the ticker field becomes a suffix and a parent dropdown of
    // wallet-controlled full-bond roots appears, with a ROOT.SUFFIX preview.
    QComboBox* regModeCombo{nullptr};
    QWidget* regChildControls{nullptr};
    QComboBox* regParentCombo{nullptr};
    QLabel* regChildPreviewLabel{nullptr};
    QLabel* regTickerLabel{nullptr};
    QLineEdit* regTickerEdit{nullptr};
    QSpinBox* regDecimalsSpinBox{nullptr};
    QLineEdit* regAssetIdEdit{nullptr};
    QPushButton* regGenerateIdButton{nullptr};
    QCheckBox* regMintAllowedCheckbox{nullptr};
    QCheckBox* regBurnAllowedCheckbox{nullptr};
    QCheckBox* regBurnRequireICUCheckbox{nullptr};
    QCheckBox* regBurnJointRequiredCheckbox{nullptr};
    QLabel* regPolicyRestrictionsLabel{nullptr};
    QCheckBox* regFamilyP2PKHCheckbox{nullptr};
    QCheckBox* regFamilyP2WPKHCheckbox{nullptr};
    QCheckBox* regFamilyP2WSHCheckbox{nullptr};
    QCheckBox* regFamilyP2TRCheckbox{nullptr};
    QLineEdit* regBondAmountEdit{nullptr};
    QLineEdit* regUnlockFeesEdit{nullptr};
    QLabel* regBondTooltipLabel{nullptr};
    QLabel* regCompressionLabel{nullptr};
    QCheckBox* regUseCompressionCheckbox{nullptr};
    QLabel* regPayloadSizeLabel{nullptr};
    QPushButton* regRegisterButton{nullptr};
    QTextEdit* regStatusText{nullptr};

    // ICU Governance section (new)
    QGroupBox* icuGovernanceGroup{nullptr};
    QTextEdit* regICUTextEdit{nullptr};
    QComboBox* regICUVisibilityCombo{nullptr};
    QSpinBox* regPolicyQuorumSpinBox{nullptr};
    QLabel* regQuorumPctLabel{nullptr};
    QSpinBox* regIssuanceCapSpinBox{nullptr};
    QTextEdit* regWitnessBundleEdit{nullptr};
    QTextEdit* regWholeDocAttestEdit{nullptr};  // optional issuer/QES signature payload over the whole-document canonical_hash
    QPushButton* regPrecheckICUButton{nullptr};
    QLabel* regCanonicalHashCaption{nullptr};  // row caption; clarifies the hash covers body+schedule
    QLabel* regCanonicalHashLabel{nullptr};
    QPushButton* regCopyHashButton{nullptr};

    // ICU context / clause designation (TSC-ICU-CONTEXT-1) — issuer UX.
    // Frontend scaffold only: the node performs authoritative normalization,
    // hashing, and substring/uniqueness validation (ValidateIcuContext).
    QGroupBox* regClausesGroup{nullptr};
    QWidget* regClausesContainer{nullptr};
    QVBoxLayout* regClausesContainerLayout{nullptr};
    QPushButton* regAddClauseButton{nullptr};
    QLabel* regClausesSummaryLabel{nullptr};
    QPushButton* regExpandCanonicalButton{nullptr};
    QPushButton* regExpandWitnessButton{nullptr};
    QVector<RegClauseRow> regClauseRows;

    // Governance "amend ICU" clause designer -- same fidelity as the Register form (inline
    // TSC-ICU-CONTEXT-1 clauses + per-clause/whole-document attestations). Built through the same
    // buildIcuPayloadFromForm helper as registration so an amendment commits identical structure.
    QTextEdit* govWholeDocAttestEdit{nullptr};
    QGroupBox* govClausesGroup{nullptr};
    QWidget* govClausesContainer{nullptr};
    QVBoxLayout* govClausesContainerLayout{nullptr};
    QPushButton* govAddClauseButton{nullptr};
    QLabel* govClausesSummaryLabel{nullptr};
    QVector<RegClauseRow> govClauseRows;

    // ZK Parameters section (new)
    QGroupBox* zkParamsGroup{nullptr};
    QCheckBox* regKYCRequiredCheckbox{nullptr};
    QCheckBox* regTFRRequiredCheckbox{nullptr};
    QComboBox* regCircuitCombo{nullptr};
    QLineEdit* regVKFileEdit{nullptr};
    QPushButton* regVKBrowseButton{nullptr};
    QLabel* regVKCommitLabel{nullptr};
    QSpinBox* regMaxRootAgeSpinBox{nullptr};
    QLineEdit* regInitialComplianceRootEdit{nullptr};

    // ===== OPTION SERIES TAB =====
    // The issuer's create/issue wizard for a tokenized option series: register the sponsored-child shell,
    // then (once confirmed) mint N units + fund N vaults, then record the series. Each step is gated by the
    // prior step's on-chain confirmation, which the RPCs themselves enforce.
    QWidget* optionSeriesTab{nullptr};
    QComboBox* optParentCombo{nullptr};        // wallet-controlled sponsoring root (shares the asset scan)
    QComboBox* optDirectionCombo{nullptr};     // call (writer short) | put (writer long)
    QLineEdit* optSuffixEdit{nullptr};
    QLabel* optTickerPreviewLabel{nullptr};
    QLineEdit* optWriterEdit{nullptr};         // writer key/address (wallet-signable for self-issuance)
    QPushButton* optWriterGenButton{nullptr};
    QLineEdit* optStrikeTpsEdit{nullptr};      // strike as human tokens/sec (network inference throughput)
    QLabel* optStrikeNbitsLabel{nullptr};      // derived canonical nBits (read-only echo)
    // Fixing is entered as a DURATION from now (humans think in time, not block heights); the absolute
    // fixing height = current tip + duration is computed + echoed. The settle-lock is the only thing kept
    // as a block number — it is a consensus SAFETY gap past fixing (>= DIFFCFD_MATURITY_DEPTH).
    QSpinBox* optFixingDurationSpin{nullptr};
    QComboBox* optFixingUnitCombo{nullptr};    // days / weeks / months / years
    QLabel* optFixingHeightLabel{nullptr};     // derived "-> block H (now + N units)"
    QSpinBox* optSettleWindowSpin{nullptr};    // settlement window in blocks PAST fixing (>= 100)
    QLabel* optSettleHeightLabel{nullptr};     // derived "-> block H"
    QLineEdit* optLeverageEdit{nullptr};       // leverage x (= lambda_q / 65536)
    QLineEdit* optLotImEdit{nullptr};          // per-lot collateral (TSC) = max payout / unit
    QSpinBox* optLotCountSpin{nullptr};        // N
    QLineEdit* optRefPremiumEdit{nullptr};     // reference premium (TSC, display only)
    QSpinBox* optExampleMoveSpin{nullptr};     // payoff preview: example difficulty move %
    QLabel* optPayoffLabel{nullptr};           // worked payoff per unit
    int m_optChainHeight{0};                   // cached tip height for the fixing-duration preview
    // Absolute fixing/settle heights FROZEN at registration. The form enters the fixing as a duration
    // from the current tip, so re-reading it after the tip advances (at Issue/Record) would recompute a
    // different schedule -> a different series_id -> the registry lookup would miss. Once registered we
    // reuse these frozen heights so every later step derives the exact id that was registered. 0 = unset
    // (pre-registration; collectOptionSeriesTerms computes from the live tip).
    int m_optFixingHeight{0};
    int m_optSettleLockHeight{0};
    QLineEdit* optSaltEdit{nullptr};
    QPushButton* optSaltGenButton{nullptr};
    QLineEdit* optBondEdit{nullptr};           // child bond (TSC, optional)
    QLineEdit* optFeeRateEdit{nullptr};
    QLabel* optAssetIdLabel{nullptr};          // derived asset_id preview
    QPushButton* optDeriveButton{nullptr};
    QPushButton* optRegisterButton{nullptr};
    QPushButton* optIssueButton{nullptr};
    QPushButton* optRecordButton{nullptr};
    QPushButton* optResetButton{nullptr};
    QPushButton* optResumeButton{nullptr};      // restore a saved in-progress draft (terms/salt/issue txid)
    QTextEdit* optStatusText{nullptr};
    QString m_optIssueTxid;                     // mint txid carried from build_issue -> record_issue
    // Recorded-series list + backing verification (slice 3)
    QTableWidget* optSeriesTable{nullptr};
    QPushButton* optRefreshListButton{nullptr};
    QPushButton* optVerifyBackingButton{nullptr};
    // Lifecycle actions on the selected series (slice 4)
    QSpinBox* optLotIndexSpin{nullptr};
    QPushButton* optSettleButton{nullptr};
    QPushButton* optBuybackButton{nullptr};
    QLineEdit* optRedeemPotEdit{nullptr};
    QPushButton* optRedeemButton{nullptr};

    // ===== CFD ASSET SERIES TAB (scalar note pair — securitised two-sided CFD) =====
    // CFD_GENERALISATION.md §6/§7: the issuer's create/issue/record wizard for a tokenised scalar note pair
    // (long token L + short token S over per-lot OP_SCALAR_CFD_SETTLE vaults), settled on an issuer-published
    // scalar feed (or the committed fallback). Distinct from the difficulty Option Series tab: two-sided, asset
    // or native collateral, and a permissionless complete-set unwind. The lifecycle steps are gated by the
    // prior step's on-chain confirmation, which the scalar.* RPCs enforce.
    QWidget* cfdSeriesTab{nullptr};
    // Scalar feed publisher (top group): publish + read the issuer oracle the notes settle against.
    QComboBox* cfdFeedAssetCombo{nullptr};      // U — a wallet-controlled feed-issuer asset
    QLineEdit* cfdFeedIdEdit{nullptr};          // feed id (full uint32 — a line edit, not a spin, to span the domain)
    QLineEdit* cfdFeedIcuEdit{nullptr};         // current ICU outpoint "txid:vout" (auto-filled by Lookup)
    QLineEdit* cfdFeedNewIcuAddrEdit{nullptr};  // successor ICU destination
    QPushButton* cfdFeedNewIcuAddrButton{nullptr};
    QLineEdit* cfdFeedNewIcuAmtEdit{nullptr};   // successor ICU bond (TSC)
    QLineEdit* cfdFeedEpochEdit{nullptr};       // scalar_epoch to publish (head+1)
    QLineEdit* cfdFeedScalarEdit{nullptr};      // scalar value, 64-hex
    QSpinBox*  cfdFeedFormatSpin{nullptr};      // scalar_format_id
    QLineEdit* cfdFeedRateEdit{nullptr};        // publication fee rate (sat/vB)
    QPushButton* cfdFeedLookupButton{nullptr};
    QPushButton* cfdFeedPublishButton{nullptr};
    QLineEdit* cfdFeedReadEpochEdit{nullptr};   // epoch to read back (blank = latest)
    QPushButton* cfdFeedReadButton{nullptr};
    QLabel* cfdFeedReadLabel{nullptr};
    QTextEdit* cfdFeedStatusText{nullptr};
    // Note-pair terms (middle group).
    QComboBox* cfdParentCombo{nullptr};         // sponsoring root (shares the asset scan with optParentCombo)
    QLineEdit* cfdLongSuffixEdit{nullptr};
    QLineEdit* cfdShortSuffixEdit{nullptr};
    QComboBox* cfdPayoffModeCombo{nullptr};     // STRIKE / REALIZED
    QComboBox* cfdLossDirCombo{nullptr};        // owner long / short
    QLineEdit* cfdUnderlyingEdit{nullptr};      // U asset id (defaults from the feed asset combo)
    QLineEdit* cfdSeriesFeedIdEdit{nullptr};    // feed id (full uint32)
    QLineEdit* cfdFixingRefEdit{nullptr};       // scalar_epoch the contract settles against
    QLineEdit* cfdDeadlineHeightEdit{nullptr};  // publication_deadline_height
    QLineEdit* cfdSettleLockEdit{nullptr};      // settle_lock_height (CLTV)
    QSpinBox*  cfdFormatSpin{nullptr};          // scalar_format_id (must match the published feed)
    QLineEdit* cfdStrikeEdit{nullptr};          // K, 64-hex
    QLineEdit* cfdFallbackEdit{nullptr};        // fallback_scalar, 64-hex
    QLineEdit* cfdLeverageEdit{nullptr};        // leverage x -> lambda_q (Q16)
    QComboBox* cfdCollateralCombo{nullptr};     // C: Native TSC | collateral-safe wallet assets | Custom hex (§5.1 filter)
    QLineEdit* cfdCollateralEdit{nullptr};      // C asset id, 64-hex (only shown for the Custom combo entry)
    QLineEdit* cfdVaultImEdit{nullptr};         // per-lot IM in C units (sats if native)
    QSpinBox*  cfdLotCountSpin{nullptr};        // N
    QLineEdit* cfdSaltEdit{nullptr};
    QPushButton* cfdSaltGenButton{nullptr};
    QLineEdit* cfdBondEdit{nullptr};            // per-child ICU bond (TSC)
    QLineEdit* cfdVaultNativeEdit{nullptr};     // native carrier per asset-collateral vault (TSC)
    QLineEdit* cfdFeeRateEdit{nullptr};
    QLabel* cfdPairIdLabel{nullptr};
    QPushButton* cfdRegisterButton{nullptr};
    QPushButton* cfdIssueButton{nullptr};
    QPushButton* cfdRecordButton{nullptr};
    QPushButton* cfdResetButton{nullptr};
    QPushButton* cfdResumeButton{nullptr};      // restore a saved in-progress pair (terms + register/issue txids)
    QTextEdit* cfdStatusText{nullptr};
    QString m_cfdIssueTxid;                     // mint txid carried from build_issue -> record_issue
    QString m_cfdRegisterTxid;                  // register txid (passed to record_issue for vault re-derivation)
    // Recorded pairs list + lifecycle actions (bottom group).
    QTableWidget* cfdPairTable{nullptr};
    QPushButton* cfdRefreshListButton{nullptr};
    QSpinBox* cfdLotIndexSpin{nullptr};
    QLineEdit* cfdVaultOutpointEdit{nullptr};   // the lot vault "txid:vout" for settle/unwind (auto-filled from lot_vaults)
    QPushButton* cfdSettleButton{nullptr};
    QPushButton* cfdUnwindButton{nullptr};
    QComboBox* cfdRedeemSideCombo{nullptr};     // L (long) / S (short)
    QLineEdit* cfdRedeemPotEdit{nullptr};
    QPushButton* cfdRedeemButton{nullptr};
    // Settlement → redeem hand-off: the pots the last settle produced, so 'Redeem' auto-fills (mirrors option
    // series). Scoped to the exact pair+lot that was settled so a stale outpoint can never linger once the
    // selection moves away.
    QString m_cfdSettledPairId, m_cfdSettledLongPot, m_cfdSettledShortPot;
    int m_cfdSettledLot{-1};

    // ===== BILATERAL CFD TAB (two-party scalar CFD on an FX cross rate; scalarcfd.*) =====
    // CFD_GENERALISATION.md §7. Distinct from the CFD Asset Series tab above (that securitises into tradeable
    // L/S tokens); this is the difficulty-style two-party contract — propose/accept/import handshake, atomic
    // co-signed open, unilateral settlement, 2-of-2 cooperative close, and a mark-to-market price view.
    QWidget* scfdTab{nullptr};
    // Propose term sheet (economics + this party's side + payout addresses).
    QComboBox* scfdPayoffModeCombo{nullptr};   // STRIKE / REALIZED
    QComboBox* scfdRoleCombo{nullptr};         // proposer side: long / short
    QLineEdit* scfdUnderlyingEdit{nullptr};    // U (64-hex)
    QLineEdit* scfdFeedIdEdit{nullptr};
    QLineEdit* scfdFixingRefEdit{nullptr};
    QLineEdit* scfdDeadlineEdit{nullptr};
    QLineEdit* scfdSettleLockEdit{nullptr};
    QSpinBox*  scfdFormatSpin{nullptr};
    QLineEdit* scfdStrikeEdit{nullptr};        // K, 64-hex
    QLineEdit* scfdFallbackEdit{nullptr};      // 64-hex
    QLineEdit* scfdCollateralEdit{nullptr};    // C 64-hex (blank = native)
    QLineEdit* scfdLongImEdit{nullptr};        // collateral units (sats if native)
    QLineEdit* scfdLongLevEdit{nullptr};       // leverage x -> lambda_q (Q16)
    QLineEdit* scfdShortImEdit{nullptr};
    QLineEdit* scfdShortLevEdit{nullptr};
    QLineEdit* scfdProposeOwnerEdit{nullptr};
    QLineEdit* scfdProposeCpEdit{nullptr};
    QPushButton* scfdProposeOwnerBtn{nullptr};
    QPushButton* scfdProposeCpBtn{nullptr};
    QPushButton* scfdProposeButton{nullptr};
    QTextEdit* scfdOfferOut{nullptr};          // generated offer JSON (hand to the counterparty)
    // Accept (paste an offer; supply this party's addresses).
    QTextEdit* scfdAcceptOfferIn{nullptr};
    QLineEdit* scfdAcceptOwnerEdit{nullptr};
    QLineEdit* scfdAcceptCpEdit{nullptr};
    QPushButton* scfdAcceptOwnerBtn{nullptr};
    QPushButton* scfdAcceptCpBtn{nullptr};
    QCheckBox* scfdAcceptConfirm{nullptr};
    QPushButton* scfdAcceptButton{nullptr};
    QTextEdit* scfdAcceptanceOut{nullptr};     // acceptance JSON (hand back to the proposer)
    // Import acceptance (proposer; paste own offer + the acceptance).
    QTextEdit* scfdImportOfferIn{nullptr};
    QTextEdit* scfdImportAcceptanceIn{nullptr};
    QPushButton* scfdImportButton{nullptr};
    // Lifecycle (contract_id-scoped): open / record / settle / coop / price.
    QLineEdit* scfdContractIdEdit{nullptr};
    QComboBox* scfdLegCombo{nullptr};          // long / short
    QLineEdit* scfdFeeRateEdit{nullptr};
    QTextEdit* scfdOpenPsbtIn{nullptr};        // counterparty partial PSBT to augment (2nd party)
    QPushButton* scfdBuildOpenButton{nullptr};
    QTextEdit* scfdOpenPsbtOut{nullptr};
    QLineEdit* scfdRecordTxidEdit{nullptr};
    QPushButton* scfdRecordOpenButton{nullptr};
    QPushButton* scfdBuildSettleButton{nullptr};
    QTextEdit* scfdSettlePsbtOut{nullptr};
    QTextEdit* scfdFinalizeIn{nullptr};
    QPushButton* scfdFinalizeButton{nullptr};
    QLineEdit* scfdCoopAddr1Edit{nullptr};
    QLineEdit* scfdCoopAmt1Edit{nullptr};      // BTC amount
    QLineEdit* scfdCoopAddr2Edit{nullptr};
    QLineEdit* scfdCoopAmt2Edit{nullptr};
    QPushButton* scfdBuildCoopButton{nullptr};
    QTextEdit* scfdCoopPsbtIO{nullptr};        // coop PSBT in/out for sign_coop round-trips
    QPushButton* scfdSignCoopButton{nullptr};
    QLineEdit* scfdPriceSigmaEdit{nullptr};
    QPushButton* scfdPriceButton{nullptr};
    QLabel* scfdPriceLabel{nullptr};
    QTextEdit* scfdStatusText{nullptr};

    // ===== VERIFY OPTION TAB (pre-purchase fraud check; holder + issuer) =====
    QWidget* verifyOptionTab{nullptr};
    QLineEdit* verifyOptIdEdit{nullptr};
    QPushButton* verifyOptButton{nullptr};
    QTextEdit* verifyOptResult{nullptr};
    // Holder redeem (no wallet record): terms recovered from the verified on-chain descriptor.
    QSpinBox* verifyOptLotSpin{nullptr};
    QLineEdit* verifyOptPotEdit{nullptr};
    QPushButton* verifyOptSettleButton{nullptr};   // holder settle a matured lot (keeper-driven) -> fills the pot
    QPushButton* verifyOptRedeemButton{nullptr};
    QString m_verifyOptTermsJson;

    // ===== MINT TAB =====
    QWidget* mintTab{nullptr};
    QComboBox* mintAssetCombo{nullptr};
    QLabel* mintPolicyLabel{nullptr};
    QLabel* mintBondLabel{nullptr};
    QLabel* mintFeesLabel{nullptr};
    QLabel* mintICULabel{nullptr};
    QLineEdit* mintAmountEdit{nullptr};
    QLabel* mintAmountFormattedLabel{nullptr};
    QLineEdit* mintDestAddressEdit{nullptr};
    QLineEdit* mintNewICUAddressEdit{nullptr};
    QLabel* mintWrapStatusLabel{nullptr};
    QCheckBox* mintAutoWrapCheckbox{nullptr};
    QLineEdit* mintWrappedKeyEdit{nullptr};
    QPushButton* mintMintButton{nullptr};
    QPushButton* mintRefreshButton{nullptr};
    QTextEdit* mintStatusText{nullptr};

    // ===== BURN TAB =====
    QWidget* burnTab{nullptr};
    QComboBox* burnAssetCombo{nullptr};
    QTableWidget* burnAssetUTXOTable{nullptr};
    QPushButton* burnRefreshUTXOsButton{nullptr};
    QLineEdit* burnManualTxidEdit{nullptr};
    QLineEdit* burnManualVoutEdit{nullptr};
    QPushButton* burnUseManualButton{nullptr};
    QLabel* burnSelectedUTXOLabel{nullptr};
    QLabel* burnICULabel{nullptr};
    QLineEdit* burnNewICUAddressEdit{nullptr};
    QPushButton* burnBurnButton{nullptr};
    QTextEdit* burnStatusText{nullptr};
    QString burnSelectedTxid;
    int burnSelectedVout{-1};

    // ===== ICU DASHBOARD TAB =====
    QWidget* dashboardTab{nullptr};
    QTableWidget* dashboardICUTable{nullptr};
    QPushButton* dashboardRefreshButton{nullptr};
    QLineEdit* dashboardFilterEdit{nullptr};
    QComboBox* dashboardFilterCombo{nullptr};
    QGroupBox* dashboardFilterGroup{nullptr};
    QTextEdit* dashboardICUTextViewer{nullptr};
    QLabel* dashboardICUVisibilityLabel{nullptr};
    QLabel* dashboardQuorumLabel{nullptr};
    QLabel* dashboardIssuanceCapLabel{nullptr};
    QPushButton* dashboardDecryptButton{nullptr};
    QPushButton* dashboardRotateICUButton{nullptr};
    QPushButton* dashboardAcceptButton{nullptr};   // holder mode: record an on-chain ICU acknowledgment
    QPushButton* dashboardReturnButton{nullptr};   // holder mode: relinquish the asset to the issuer

    // ===== ZK COMPLIANCE TAB =====
    QWidget* zkComplianceTab{nullptr};
    QLabel* zkNoComplianceLabel{nullptr};
    QWidget* zkContentWidget{nullptr};
    QGroupBox* zkIssuerGroup{nullptr};
    QGroupBox* zkHolderGroup{nullptr};
    QComboBox* zkAssetCombo{nullptr};
    QLabel* zkVKCommitLabel{nullptr};
    QLabel* zkMaxRootAgeLabel{nullptr};
    QLabel* zkCurrentRootLabel{nullptr};
    QLabel* zkTFRRequiredLabel{nullptr};

    // Compliance Root Update (Issuer)
    QComboBox* zkCircuitComboIssuer{nullptr};
    QTextEdit* zkComplianceListEdit{nullptr};
    QPushButton* zkBuildMerkleButton{nullptr};
    QLabel* zkNewRootLabel{nullptr};
    QPushButton* zkRotateRootButton{nullptr};
    QPushButton* zkExportProofsButton{nullptr};
    QPushButton* zkCopyToRegistrationButton{nullptr};

    // Proof Generation (Holder)
    QComboBox* zkCircuitComboHolder{nullptr};
    QLineEdit* zkProvingKeyFileEdit{nullptr};
    QPushButton* zkProvingKeyBrowseButton{nullptr};
    QPushButton* zkProvingKeyDownloadButton{nullptr};
    QLabel* zkProvingKeyStatusLabel{nullptr};
    QLineEdit* zkProofTxidEdit{nullptr};
    QSpinBox* zkProofVoutSpinBox{nullptr};
    QTextEdit* zkProofWitnessEdit{nullptr};
    QTextEdit* zkProofMerkleProofEdit{nullptr};
    QLineEdit* zkTFRAnchorEdit{nullptr};
    QPushButton* zkGenerateProofButton{nullptr};
    QTextEdit* zkProofOutputEdit{nullptr};
    QTextEdit* zkStatusText{nullptr};

    // Cached compliance data
    QString lastComplianceRoot;
    QString lastComplianceData;  // JSON string of full result

    // ===== DISTRIBUTION TAB =====
    QWidget* distributionTab{nullptr};
    QComboBox* distTargetAssetCombo{nullptr};
    QLabel* distTargetAssetInfoLabel{nullptr};
    QLabel* distSettledSupplyLabel{nullptr};
    QLineEdit* distAmountEdit{nullptr};
    QLabel* distAmountFormattedLabel{nullptr};
    QComboBox* distAssetCombo{nullptr};
    QLabel* distAssetBalanceLabel{nullptr};
    QSpinBox* distMinDustSpinBox{nullptr};
    QSpinBox* distMaxRecipientsSpinBox{nullptr};
    QCheckBox* distSnapshotEnableCheckBox{nullptr};
    QSpinBox* distSnapshotHeightSpinBox{nullptr};
    QPushButton* distPreviewButton{nullptr};
    QPushButton* distExecuteButton{nullptr};
    QTableWidget* distPreviewTable{nullptr};
    QLabel* distSummaryLabel{nullptr};
    QTextEdit* distStatusText{nullptr};
    QProgressBar* distProgressBar{nullptr};

    // Distribution state
    bool distributionPreviewReady{false};
    QString lastDistributionResult;

    // ===== GOVERNANCE TAB =====
    QWidget* governanceTab{nullptr};
    QLabel* govNoGovernanceLabel{nullptr};
    QWidget* govContentWidget{nullptr};
    QGroupBox* govPrepareGroup{nullptr};
    QGroupBox* govBallotGroup{nullptr};
    QGroupBox* govFinalizeGroup{nullptr};
    QComboBox* govAssetCombo{nullptr};
    QLabel* govQuorumLabel{nullptr};
    QLabel* govSettledSupplyLabel{nullptr};

    // 1. Prepare Rotation (Issuer)
    QSpinBox* govNewIssuanceCapSpinBox{nullptr};
    QSpinBox* govNewQuorumSpinBox{nullptr};
    QTextEdit* govICUTextEdit{nullptr};
    QTextEdit* govWitnessTextEdit{nullptr};
    QComboBox* govICUVisibilityCombo{nullptr};
    QPushButton* govPrecheckButton{nullptr};
    QLabel* govCanonicalHashLabel{nullptr};
    QPushButton* govCopyHashButton{nullptr};
    QPushButton* govPrepareButton{nullptr};
    QTextEdit* govPSBTEdit{nullptr};
    QLabel* govRequiredUnitsLabel{nullptr};

    // 2. Cast Ballot (Holder)
    QTextEdit* govBallotPSBTEdit{nullptr};
    QTableWidget* govUTXOTable{nullptr};
    QPushButton* govCastBallotButton{nullptr};
    QTextEdit* govSignedPSBTEdit{nullptr};

    // 3. Finalize (Issuer)
    QComboBox* govProposalDropdown{nullptr};
    QTextEdit* govBallotListEdit{nullptr};
    QLabel* govBallotsStatusLabel{nullptr};
    QPushButton* govMergeBallotsButton{nullptr};
    QTextEdit* govMergedPSBTEdit{nullptr};
    QPushButton* govFinalizeButton{nullptr};
    QTextEdit* govStatusText{nullptr};
    QTextEdit* govIssuerProposalSummary{nullptr};
    QTextEdit* govHolderProposalSummary{nullptr};

    // Nostr-based proposal discovery (new)
    QGroupBox* govNostrDiscoveryGroup{nullptr};
    QLabel* govBBStatusLabel{nullptr};
    QLabel* govLastRefreshLabel{nullptr};
    QPushButton* govForceRefreshButton{nullptr};
    QComboBox* govNostrAssetFilterCombo{nullptr};
    QTableWidget* govNostrProposalsTable{nullptr};
    QPushButton* govNostrVoteButton{nullptr};
    QPushButton* govNostrDetailsButton{nullptr};
    QPushButton* govNostrRequestPrivateButton{nullptr};  // PR3: Request private proposal access
    QPushButton* govPublishToNostrButton{nullptr};  // In manual flow, not discovery section
    QTimer* govNostrPollTimer{nullptr};
    // PR3: Issuer private access requests UI
    QGroupBox* govIssuerAccessRequestsGroup{nullptr};
    QTableWidget* govIssuerAccessRequestsTable{nullptr};
    QCheckBox* govAutoApproveCheckbox{nullptr};
    bool govBBInitialized{false};
    QSet<QString> seenProposalIds;  // Track proposals we've notified about
    QDateTime lastGovRefreshTime;   // Track last refresh for display

    uint8_t currentGovAssetDecimals{0};

    // Governance workflow state tracking
    std::optional<uint64_t> lastRequiredUnits;
    std::optional<uint64_t> lastMergedBallotUnits;
    std::optional<bool> lastMergedQuorumMet;

    // UI setup methods
    void setupRegistrationTab();
    void setupOptionSeriesTab();
    void setupVerifyOptionTab();
    // Collect + validate the option-series terms from the form; returns false (and reports via optStatusText)
    // on any invalid field. `out` is filled on success.
    bool collectOptionSeriesTerms(WalletModel::OptionSeriesTermsInput& out);
    void setOptionSeriesFormEnabled(bool enabled); // lock the terms once a series is registered
    bool recoverOptionSeriesFrozenSchedule(const QString& identifier); // old drafts: recover heights from on-chain descriptor
    // Resolve a writer field (a wallet Taproot address, or a 64-hex x-only key) to a bech32m address this
    // wallet can SIGN with — required so issuance/settlement/buy-back can rotate the ICU + sign. Returns
    // false (with errOut) if the key is not a wallet-controlled Taproot output.
    bool resolveSpendableWriterAddress(const QString& writerInput, QString& addressOut, QString& errOut);
    void saveOptionSeriesDraft(int stage);   // persist the in-progress series (1=registered, 2=issued) to QSettings
    void clearOptionSeriesDraft();
    void setupMintTab();
    void setupBurnTab();
    void setupDashboardTab();
    void setupZKComplianceTab();
    void setupDistributionTab();
    void setupGovernanceTab();

    // Helper methods
    void updateMintAssetInfo(const QString& assetId);
    void updateBurnAssetUTXOs(const QString& assetId);
    void switchMode(bool issuerMode);
    void updateVisibilityForMode();
    bool isAddressOwnedByWallet(const QString& address);
    // Populate regParentCombo with wallet-controlled root assets eligible to sponsor children.
    void refreshParentRoots();

    // Cached asset data
    uint8_t currentMintAssetDecimals{8};
    QString formatAssetAmount(uint64_t units, uint8_t decimals) const;
    uint64_t parseAssetAmount(const QString& amountStr, uint8_t decimals) const;
    uint32_t getPolicyBitsFromUI() const;
    uint16_t getAllowedFamiliesFromUI() const;
    void showError(const QString& message);
    void showSuccess(const QString& message);
    QString reverseHexBytes(const QString& hex);
    QString extractTickerFromIssuerRegHex(const QString& outext);
    bool mergeBallotsInternal(const QStringList& ballots, QString& mergedPsbt, bool logStatus);
    void updateGovernanceProposalSummary(const QString& psbt);
    QString computeSHA256(const QString& text) const;

private Q_SLOTS:
    // Mode switcher slots
    void onSwitchToHolderMode();
    void onSwitchToIssuerMode();

    // Registration tab slots
    void onGenerateAssetId();
    void onRegisterAsset();
    void onRegModeChanged();          // toggle standalone-root vs sponsored-child UI

    // Option-series wizard slots
    void onOptGenWriter();            // fill the writer field with a fresh wallet bech32m address
    void onOptGenSalt();              // fill the salt field with 32 random bytes
    void onOptPreviewUpdate();        // refresh the ROOT.SUFFIX ticker preview
    void onOptStrikePreview();        // convert the tokens/sec strike to canonical nBits + echo it
    void onOptScheduleAndPayoffPreview(); // echo derived fixing/settle heights + the worked payoff per unit
    void onOptDerive();               // preview the derived asset_id from the current terms
    void onOptRegister();             // step 1: optionseries.build_register
    void onOptIssue();                // step 2: optionseries.build_issue (after registration confirms)
    void onOptRecord();               // step 3: optionseries.record_issue (after issuance confirms)
    void onOptReset();                // unlock the form for a new series
    void onOptResume();               // restore a saved draft (terms/salt/issue txid + step state)
    void onOptRefreshList();          // reload optionseries.list into the recorded-series table
    void onOptVerifyBacking();        // verify the selected series' on-chain backing (verify + check_backing)
    void onOptSeriesSelectionChanged(); // gate the lifecycle panel to the selected series
    void onOptSettle();               // settle the selected lot (keeper flow)
    void onOptBuyback();              // buy back the selected lot (writer unwind)
    void onOptRedeem();               // redeem the entered pot for the selected lot

    // ── CFD asset series (scalar note pair) ─────────────────────────────────────────────────────────────
    void setupCfdSeriesTab();
    bool collectCfdSeriesTerms(WalletModel::ScalarNotePairTermsInput& out); // form -> RPC terms (validated)
    void setCfdSeriesFormEnabled(bool enabled); // lock descriptor fields once the pair is registered
    void saveCfdDraft(int stage);     // persist the in-progress pair (1=registered, 2=issued) to QSettings
    void clearCfdDraft();
    void onCfdGenSalt();              // fill the series salt with random bytes
    void onCfdPairPreview();          // echo ticker previews (ROOT.SUFFIX)
    void onCfdCollateralChanged();    // show the custom-hex field only for the "Custom" collateral entry
    void onCfdRegister();             // step 1: scalar.build_register (mint-less L+S child shells)
    void onCfdIssue();                // step 2: scalar.build_issue (mint N L + N S, fund N vaults)
    void onCfdRecord();               // step 3: scalar.record_issue (persist the pair + lot vaults)
    void onCfdReset();                // clear the form for a new pair
    void onCfdResume();               // restore a saved in-progress pair draft (terms + step state)
    void onCfdRefreshList();          // reload scalar.list into the recorded-pairs table
    void onCfdPairSelectionChanged(); // gate the lifecycle panel to the selected pair + autofill the lot vault
    void onCfdLotIndexChanged();      // autofill the vault outpoint for the chosen lot from lot_vaults
    void onCfdSettle();               // keeper settle the selected lot vault (scalar.build_settlement)
    void onCfdRedeemSideChanged();    // swap the auto-filled redeem pot between the settled long/short pots
    void onCfdRedeem();               // redeem one side's token against a pot (scalar.build_redeem)
    void onCfdUnwind();               // permissionless complete-set unwind (scalar.build_unwind)
    // Feed publisher (issuer oracle the notes settle against).
    void onCfdFeedLookup();           // fill the current ICU outpoint + next epoch for the chosen feed asset
    void onCfdFeedNewAddr();          // fill the successor ICU address with a fresh wallet address
    void onCfdFeedPublish();          // scalarpublish_raw (autofund + broadcast)
    void onCfdFeedRead();             // scalargetfeed for the chosen (asset, feed, epoch)
    // Bilateral scalar CFD (scalarcfd.*) tab.
    void setupBilateralCfdTab();
    void onScfdProposeOwnerAddr();
    void onScfdProposeCpAddr();
    void onScfdAcceptOwnerAddr();
    void onScfdAcceptCpAddr();
    void onScfdPropose();             // scalarcfd.propose -> offer JSON
    void onScfdAccept();              // scalarcfd.accept -> contract_id + acceptance JSON
    void onScfdImport();              // scalarcfd.import_acceptance (proposer)
    void onScfdBuildOpen();           // scalarcfd.build_open (atomic co-signed open)
    void onScfdRecordOpen();          // scalarcfd.record_open
    void onScfdBuildSettlement();     // scalarcfd.build_settlement
    void onScfdFinalize();            // scalarcfd.finalize_settlement -> broadcastable hex
    void onScfdBuildCoop();           // scalarcfd.build_coop_close
    void onScfdSignCoop();            // scalarcfd.sign_coop (2-of-2)
    void onScfdPrice();               // scalarcfd.price -> MTM
    void onVerifyOptionById();        // pre-purchase fraud check by ticker / asset id (holder + issuer)
    void onVerifyOptionSettle();      // holder settle a matured lot (keeper-driven); auto-fills the pot to redeem
    void onVerifyOptionRedeem();      // holder redeem a pot using terms recovered from verify (no record)
    void onRegChildPreviewUpdate();   // refresh the ROOT.SUFFIX preview label
    void onMintAmountChanged();
    void onPrecheckICU();
    void onCopyCanonicalHash();
    void onBrowseVKFile();
    void onQuorumChanged(int bps);
    void onBurnJointRequiredChanged(bool checked);
    void onICUTextChanged();
    void onAddClauseRow();
    void onAddGovClauseRow();
    void onExpandCanonicalText();
    void onExpandWitnessText();

    // Mint tab slots
    void onMintAssetSelected(int index);
    void onMintAsset();
    void onMintRefresh();

    // Burn tab slots
    void onBurnAssetSelected(int index);
    void onBurnRefreshUTXOs();
    void onBurnUTXOSelected(int row, int column);
    void onBurnUseManual();
    void onBurnAsset();

    // Dashboard tab slots
    void onDashboardRefresh();
    void onDashboardFilterChanged();
    void onDashboardRowClicked(int row, int column);
    void onDashboardDecrypt();
    void onDashboardAccept();
    void onDashboardReturn();
    void onDashboardViewAcceptances();   // issuer/anyone: list on-chain ICU acceptances for the selected asset
    void runDashboardAcceptance(const std::string& mode);
    void onViewRotationHistory();
    void onViewPreviousICU();
    void onOpenRotateICUDialog();

    // ZK Compliance tab slots
    void onZKAssetSelected(int index);
    void onBuildMerkleTree();
    void onExportMerkleProofs();
    void onRotateComplianceRoot();
    void onCopyRootToRegistration();
    void onGenerateMasterKey();
    void onCopyMasterKey();
    void onBrowseProvingKey();
    void onDownloadProvingKey();
    void onProvingKeyReady(const QString& path);
    void onProvingKeyFailed(const QString& error);
    void onGenerateZKProof();

    // Distribution tab slots
    void onDistTargetAssetSelected(int index);
    void onDistAssetSelected(int index);
    void onDistAmountChanged();
    void onDistPreview();
    void onDistExecute();

    // Governance tab slots
    void onGovAssetSelected(int index);
    void onGovPrecheckICU();
    void onGovCopyCanonicalHash();
    void onPrepareRotation();
    void onCastBallot();
    void onGovTemplatePSBTChanged();
    void onRefreshProposalsList();
    void onFetchBallots();
    void onMergeBallots();
    void onFinalizeRotation();

    // Nostr governance slots
    void onGovNostrRefresh();
    void onGovNostrForceRefresh();
    void onGovNostrVote();
    void onGovNostrDetails();
    void onGovNostrRequestPrivate();  // PR3: Request private proposal access
    void onGovIssuerProcessAccessRequests();  // PR3: Issuer - process incoming access requests
    void onGovIssuerApproveRequest();  // PR3: Issuer - manually approve request
    void onGovIssuerDenyRequest();  // PR3: Issuer - manually deny request
    void onGovNostrPublish();
    void onGovNostrPollTimer();
    void onTabChanged(int index);
    void updateGovBulletinBoardStatus();

    // Block update slot
    void onNumBlocksChanged(int count, const QDateTime& blockDate, double nVerificationProgress, SyncType header, SynchronizationState sync_state);
};

#endif // BITCOIN_QT_TREASURYPAGE_H
