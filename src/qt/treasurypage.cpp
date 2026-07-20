// Copyright (c) 2024 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/treasurypage.h>
#include <qt/zkparamsmanager.h>

#include <qt/bitcoinunits.h>
#include <qt/clientmodel.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>
#include <qt/platformstyle.h>
#include <qt/rotateicudialog.h>
#include <qt/themehelpers.h>
#include <qt/walletmodel.h>

#include <interfaces/node.h>
#include <node/interface_ui.h>
#include <uint256.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <assets/asset.h>
#include <consensus/scalar_cfd_leaf.h>  // ScalarCfdSourceType / ScalarCfdPayoffMode (CFD asset series tab)
#include <assets/icu_payload.h>
#include <wallet/difficulty_contract.h>  // DifficultyTokensPerSecToNBits / DifficultyNBitsToTokensPerSec / format
#include <rpc/protocol.h>
#include <psbt.h>
#include <serialize.h>
#include <streams.h>
#include <key_io.h>
#include <outputtype.h>

#include <map>

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QGridLayout>
#include <QGroupBox>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QComboBox>
#include <QSpinBox>
#include <QCheckBox>
#include <QTableWidget>
#include <QHeaderView>
#include <QProgressBar>
#include <QTextEdit>
#include <QScrollArea>
#include <QSettings>
#include <QAbstractItemView>
#include <QPlainTextEdit>
#include <QTextCursor>
#include <QMessageBox>
#include <QStringList>
#include <QApplication>
#include <QClipboard>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QCryptographicHash>
#include <QFileDialog>
#include <QFile>
#include <QDateTime>
#include <QTimer>
#include <QDialog>
#include <QDialogButtonBox>
#include <QSignalBlocker>
#include <QRegularExpression>
#include <QRandomGenerator>
#include <QPointer>
#include <QSettings>

#include <cmath>
#include <limits>
#include <memory>
#include <random>
#include <vector>
#include <set>
#include <optional>

namespace {
QWidget* TopLevelDialogParent(QWidget* widget)
{
    return widget && widget->window() ? widget->window() : widget;
}

struct GovernanceProposalDetails {
    uint64_t settled_supply{0};
    uint64_t required_units{0};
    uint16_t quorum_bps{0};
    QString canonical_text;
    QString canonical_hash;
    QString witness_json;
    QString raw_payload_hex;               // exact committed ICU payload bytes (hex) from the PSBT metadata
    bool has_icu_payload{false};           // true when the PSBT commits an ICU text payload (vs policy-only)
    uint8_t committed_icu_visibility{0};   // icu_visibility from the committed IssuerReg (authoritative for flow_type)
    uint16_t committed_quorum_bps{0};      // policy_quorum_bps from the committed IssuerReg
    uint64_t committed_cap_units{0};       // issuance_cap_units from the committed IssuerReg
};

static constexpr std::string_view ROTATION_PSBT_IDENTIFIER{"assetv2/governance"};
static constexpr uint64_t ROTATION_PSBT_SUBTYPE_METADATA{0x01};
static constexpr size_t ROTATION_METADATA_MIN_SIZE =
    sizeof(uint64_t) * 2 + sizeof(uint16_t) + sizeof(uint8_t) + uint256::size() * 2;

std::optional<GovernanceProposalDetails> DecodeGovernanceMetadata(const PartiallySignedTransaction& psbt)
{
    for (const auto& prop : psbt.m_proprietary) {
        if (prop.identifier.size() == ROTATION_PSBT_IDENTIFIER.size() &&
            std::equal(prop.identifier.begin(), prop.identifier.end(), ROTATION_PSBT_IDENTIFIER.begin()) &&
            prop.subtype == ROTATION_PSBT_SUBTYPE_METADATA) {

            if (prop.value.size() < ROTATION_METADATA_MIN_SIZE) {
                return std::nullopt;
            }

            GovernanceProposalDetails details;
            const unsigned char* data = prop.value.data();
            details.settled_supply = ReadLE64(data);
            details.required_units = ReadLE64(data + sizeof(uint64_t));
            details.quorum_bps = ReadLE16(data + sizeof(uint64_t) * 2);

            size_t offset = ROTATION_METADATA_MIN_SIZE;

            try {
                SpanReader reader(std::span<const unsigned char>{
                    prop.value.data() + offset,
                    prop.value.data() + prop.value.size()
                });
                uint64_t payload_size = ReadCompactSize(reader);
                std::vector<unsigned char> payload(payload_size);
                if (payload_size > 0) {
                    reader.read(std::span<std::byte>(reinterpret_cast<std::byte*>(payload.data()), payload_size));
                }

                // A governance-rotation PSBT MUST carry the committed IssuerReg TLV (finalization
                // requires it too -- assets.cpp restores it as vout[0].vExt). Parse it so flow_type/
                // quorum/cap are sourced from the PSBT (source of truth), and FAIL CLOSED if it is
                // missing or unparseable: returning a metadata object with zero-default committed policy/
                // visibility would let a malformed/tampered PSBT masquerade as a valid governance PSBT.
                uint64_t issuer_tlv_size = ReadCompactSize(reader);
                if (issuer_tlv_size == 0) {
                    return std::nullopt;
                }
                std::vector<unsigned char> issuer_tlv(issuer_tlv_size);
                reader.read(std::span<std::byte>(reinterpret_cast<std::byte*>(issuer_tlv.data()), issuer_tlv_size));
                auto reg = assets::ParseIssuerReg(issuer_tlv);
                if (!reg) {
                    return std::nullopt;
                }
                details.committed_icu_visibility = reg->icu_visibility;
                details.committed_quorum_bps = reg->policy_quorum_bps;
                details.committed_cap_units = reg->issuance_cap_units;

                if (!payload.empty()) {
                    details.raw_payload_hex = QString::fromStdString(HexStr(payload));
                    auto canonical = assets::ParseCanonicalIcuPayload(payload);
                    if (canonical) {
                        details.has_icu_payload = true;
                        details.committed_icu_visibility = canonical->visibility;
                        details.canonical_text = QString::fromUtf8(
                            reinterpret_cast<const char*>(canonical->canonical_text.data()),
                            canonical->canonical_text.size());
                        details.witness_json = QString::fromUtf8(
                            reinterpret_cast<const char*>(canonical->witness_bundle.data()),
                            canonical->witness_bundle.size());

                        QJsonParseError parseError{};
                        QJsonDocument doc = QJsonDocument::fromJson(details.witness_json.toUtf8(), &parseError);
                        if (parseError.error == QJsonParseError::NoError && doc.isObject()) {
                            details.canonical_hash = doc.object().value("canonical_hash").toString();
                        }
                    }
                }
            } catch (const std::exception&) {
                return std::nullopt;
            }

            return details;
        }
    }

    return std::nullopt;
}
}  // namespace

TreasuryPage::TreasuryPage(const PlatformStyle* platformStyle, QWidget* parent)
    : QWidget(parent),
      m_platform_style(platformStyle)
{
    QVBoxLayout* mainLayout = new QVBoxLayout(this);

    // Create mode switcher with compact segmented control bar
    const bool isDark = ThemeHelpers::isDarkPalette();
    const QString switcherBg = isDark ? QStringLiteral("#2d2d2d") : QStringLiteral("#f5f5f5");
    const QString checkedBg = isDark ? QStringLiteral("#3a3a3a") : QStringLiteral("white");
    const QString idleColor = ThemeHelpers::mutedTextColor();
    const QString hoverColor = isDark ? QStringLiteral("#e0e0e0") : QStringLiteral("#333");

    modeSwitcherWidget = new QWidget(this);
    modeSwitcherWidget->setStyleSheet(QStringLiteral("background-color: %1; border-radius: 3px; padding: 2px;").arg(switcherBg));
    modeSwitcherWidget->setMaximumWidth(240);
    QHBoxLayout* modeSwitcherLayout = new QHBoxLayout(modeSwitcherWidget);
    modeSwitcherLayout->setContentsMargins(2, 2, 2, 2);
    modeSwitcherLayout->setSpacing(0);

    holderModeButton = new QPushButton(tr("Asset Holder"), modeSwitcherWidget);
    holderModeButton->setCheckable(true);
    holderModeButton->setChecked(true);
    holderModeButton->setStyleSheet(QStringLiteral(
        "QPushButton {"
        "  background-color: transparent;"
        "  color: %1;"
        "  border: none;"
        "  border-radius: 2px;"
        "  font-weight: normal;"
        "  padding: 4px 8px;"
        "  min-width: 90px;"
        "}"
        "QPushButton:checked {"
        "  background-color: %2;"
        "  color: #2196F3;"
        "  font-weight: bold;"
        "  box-shadow: 0 1px 3px rgba(0,0,0,0.1);"
        "}"
        "QPushButton:hover:!checked {"
        "  color: %3;"
        "}").arg(idleColor, checkedBg, hoverColor));
    connect(holderModeButton, &QPushButton::clicked, this, &TreasuryPage::onSwitchToHolderMode);
    modeSwitcherLayout->addWidget(holderModeButton);

    issuerModeButton = new QPushButton(tr("Asset Issuer"), modeSwitcherWidget);
    issuerModeButton->setCheckable(true);
    issuerModeButton->setChecked(false);
    issuerModeButton->setStyleSheet(QStringLiteral(
        "QPushButton {"
        "  background-color: transparent;"
        "  color: %1;"
        "  border: none;"
        "  border-radius: 2px;"
        "  font-weight: normal;"
        "  padding: 4px 8px;"
        "  min-width: 90px;"
        "}"
        "QPushButton:checked {"
        "  background-color: %2;"
        "  color: #FF9800;"
        "  font-weight: bold;"
        "  box-shadow: 0 1px 3px rgba(0,0,0,0.1);"
        "}"
        "QPushButton:hover:!checked {"
        "  color: %3;"
        "}").arg(idleColor, checkedBg, hoverColor));
    connect(issuerModeButton, &QPushButton::clicked, this, &TreasuryPage::onSwitchToIssuerMode);
    modeSwitcherLayout->addWidget(issuerModeButton);

    modeSwitcherWidget->setLayout(modeSwitcherLayout);

    // Create a wrapper layout to align the switcher to the right
    QHBoxLayout* switcherWrapperLayout = new QHBoxLayout();
    switcherWrapperLayout->addStretch();
    switcherWrapperLayout->addWidget(modeSwitcherWidget);
    mainLayout->addLayout(switcherWrapperLayout);

    // Create tab widget
    tabWidget = new QTabWidget(this);
    connect(tabWidget, &QTabWidget::currentChanged, this, &TreasuryPage::onTabChanged);

    // Create individual tabs
    setupRegistrationTab();
    setupOptionSeriesTab();
    setupCfdSeriesTab();
    // setupBilateralCfdTab() intentionally NOT called: the bilateral scalar-feed CFD moved to the Exchange
    // Structuring→Book flow. The method + its onScfd* handlers/members are retained but dormant (unwired),
    // so the feature can be revived or fully removed later without a risky bulk deletion now.
    setupVerifyOptionTab();
    setupMintTab();
    setupBurnTab();
    setupDashboardTab();
    setupZKComplianceTab();
    setupDistributionTab();
    setupGovernanceTab();

    mainLayout->addWidget(tabWidget);
    setLayout(mainLayout);

    // Initialize ZK params manager (dataDir may not be available yet, set later)
    m_zkParamsManager = new ZKParamsManager(QString(), this);
    connect(m_zkParamsManager, &ZKParamsManager::provingKeyReady, this, &TreasuryPage::onProvingKeyReady);
    connect(m_zkParamsManager, &ZKParamsManager::provingKeyFailed, this, &TreasuryPage::onProvingKeyFailed);

    // VK is embedded in the binary — use it directly
    {
        regVKFileEdit->setText(tr("(embedded in binary)"));
        regVKFileEdit->setReadOnly(true);

        QByteArray vkData = ZKParamsManager::embeddedVK();
        QByteArray vkCommit = QCryptographicHash::hash(vkData, QCryptographicHash::Sha256);
        QString vkCommitHex = vkCommit.toHex();
        regVKCommitLabel->setText(vkCommitHex);
        regVKCommitLabel->setStyleSheet("font-family: monospace; color: #4CAF50; font-weight: bold;");
    }

    // Initialize to Asset Holder view (default) - but don't refresh data yet
    // (wallet and client models aren't set until later)
    if (isIssuerMode) {
        // Core issuance lifecycle first (ICU Dashboard is the landing page), then the option/CFD
        // derivative builders grouped together on the right as optional advanced steps.
        tabWidget->addTab(dashboardTab, tr("ICU Dashboard"));
        tabWidget->addTab(registrationTab, tr("Register Asset"));
        tabWidget->addTab(mintTab, tr("Mint"));
        tabWidget->addTab(burnTab, tr("Burn"));
        tabWidget->addTab(zkComplianceTab, tr("Compliance"));
        tabWidget->addTab(distributionTab, tr("Distribution"));
        tabWidget->addTab(governanceTab, tr("Governance"));
        tabWidget->addTab(optionSeriesTab, tr("Option Series"));
        tabWidget->addTab(cfdSeriesTab, tr("CFD Asset Series"));
        // NOTE: the bilateral scalar-feed CFD ("Bilateral CFD") moved to the Exchange Structuring→Book flow
        // (it shares the difficulty CFD's propose/manage/settle surface). Its Treasury tab is unwired here;
        // the setupBilateralCfdTab()/onScfd* code is retained but dormant.
        tabWidget->addTab(verifyOptionTab, tr("Verify Option"));

        // Issuer mode table headers
        dashboardICUTable->setColumnCount(9);
        dashboardICUTable->setHorizontalHeaderLabels({
            tr("Ticker"), tr("Asset ID"), tr("ICU TxID"), tr("Vout"),
            tr("Bond (TSC)"), tr("Fees Accum"), tr("Unlock Target"),
            tr("Progress"), tr("Status")
        });
    } else {
        tabWidget->addTab(dashboardTab, tr("My Assets"));
        tabWidget->addTab(verifyOptionTab, tr("Verify Option"));
        // The bilateral scalar-feed CFD moved to the Exchange Structuring→Book flow (reachable by holders
        // too, as the acceptor/counterparty). Its Treasury tab is unwired here.
        tabWidget->addTab(zkComplianceTab, tr("Compliance"));
        tabWidget->addTab(governanceTab, tr("Governance"));

        // HOLDER MODE: Table shows asset policy characteristics
        dashboardICUTable->setColumnCount(10);
        dashboardICUTable->setHorizontalHeaderLabels({
            tr("Ticker"), tr("Asset ID"), tr("Balance"), tr("Max Issuance"),
            tr("Total Issued"), tr("Gov BPS"), tr("Text Vis"),
            tr("Script Families"), tr("Compliance"), tr("TFR Req")
        });
    }

    // Install wheel event filters on all combo boxes and spin boxes to prevent
    // accidental changes while scrolling
    GUIUtil::InstallWheelEventFilter(regDecimalsSpinBox);
    GUIUtil::InstallWheelEventFilter(regICUVisibilityCombo);
    GUIUtil::InstallWheelEventFilter(regPolicyQuorumSpinBox);
    GUIUtil::InstallWheelEventFilter(regIssuanceCapSpinBox);
    GUIUtil::InstallWheelEventFilter(regCircuitCombo);
    GUIUtil::InstallWheelEventFilter(regMaxRootAgeSpinBox);
    GUIUtil::InstallWheelEventFilter(mintAssetCombo);
    GUIUtil::InstallWheelEventFilter(burnAssetCombo);
    GUIUtil::InstallWheelEventFilter(dashboardFilterCombo);
    GUIUtil::InstallWheelEventFilter(zkAssetCombo);
    GUIUtil::InstallWheelEventFilter(zkCircuitComboIssuer);
    GUIUtil::InstallWheelEventFilter(zkCircuitComboHolder);
    GUIUtil::InstallWheelEventFilter(zkProofVoutSpinBox);
    GUIUtil::InstallWheelEventFilter(distTargetAssetCombo);
    GUIUtil::InstallWheelEventFilter(distAssetCombo);
    GUIUtil::InstallWheelEventFilter(distMinDustSpinBox);
    GUIUtil::InstallWheelEventFilter(distMaxRecipientsSpinBox);
    GUIUtil::InstallWheelEventFilter(distSnapshotHeightSpinBox);
    GUIUtil::InstallWheelEventFilter(govAssetCombo);
    GUIUtil::InstallWheelEventFilter(govNostrAssetFilterCombo);
    GUIUtil::InstallWheelEventFilter(govNewIssuanceCapSpinBox);
    GUIUtil::InstallWheelEventFilter(govNewQuorumSpinBox);
    GUIUtil::InstallWheelEventFilter(govICUVisibilityCombo);
    GUIUtil::InstallWheelEventFilter(govProposalDropdown);
}

TreasuryPage::~TreasuryPage() = default;

void TreasuryPage::setWalletModel(WalletModel* model)
{
    walletModel = model;
    if (walletModel && clientModel) {
        refreshAssetList();
        refreshICUDashboard();
        if (isIssuerMode && optSeriesTable) onOptRefreshList();  // populate the recorded-series list
        if (optStrikeTpsEdit) {
            const WalletModel::DifficultyChainDefaults d = walletModel->difficultyChainDefaults();
            if (d.success && d.height > 0) m_optChainHeight = d.height;  // anchor the fixing-duration preview
            // Seed the option strike with the current chain difficulty (in tok/s) as a sensible default.
            bool ok = false;
            const uint32_t nb = d.success ? d.strike_nbits.toUInt(&ok, 16) : 0;
            if (ok && nb != 0 && optStrikeTpsEdit->text().trimmed().isEmpty()) {
                optStrikeTpsEdit->setText(QString::fromStdString(
                    wallet::DifficultyFormatTokensPerSec(wallet::DifficultyNBitsToTokensPerSec(nb))));
                onOptStrikePreview();
            }
            onOptScheduleAndPayoffPreview();  // fill the derived fixing/settle heights + payoff once height is known
        }
    }
}

QString TreasuryPage::reverseHexBytes(const QString& hex)
{
    // Reverse byte order: "aabbccdd" -> "ddccbbaa"
    QString reversed;
    for (int i = hex.length() - 2; i >= 0; i -= 2) {
        reversed += hex.mid(i, 2);
    }
    return reversed;
}

QString TreasuryPage::computeSHA256(const QString& text) const
{
    // Compute SHA256 hash of UTF-8 text and return as lowercase hex string
    QByteArray data = text.toUtf8();
    QByteArray hash = QCryptographicHash::hash(data, QCryptographicHash::Sha256);
    return QString::fromLatin1(hash.toHex());
}

QString TreasuryPage::extractTickerFromIssuerRegHex(const QString& outext)
{
    // IssuerReg TLV format (after type 0x10 and length):
    // - 32 bytes (64 hex): asset_id
    // - 4 bytes (8 hex): policy_bits
    // - optional fields, then:
    // - 1 byte (2 hex): ticker length
    // - N bytes: ticker string

    // Skip "10" type and length byte(s)
    int pos = 2;  // Skip "10"

    // Skip compact size length (usually 1 byte = 2 hex chars)
    if (pos + 2 > outext.length()) return "";
    pos += 2;

    // Skip asset_id (32 bytes = 64 hex chars)
    pos += 64;

    // Skip policy_bits (4 bytes = 8 hex chars)
    pos += 8;

    // Scan for ticker length byte (3-11) followed by valid ASCII ticker
    for (int searchPos = pos; searchPos < outext.length() - 6; searchPos += 2) {
        if (searchPos + 2 > outext.length()) break;

        bool ok;
        int tickerLen = outext.mid(searchPos, 2).toInt(&ok, 16);

        if (!ok || tickerLen < 3 || tickerLen > 11) continue;

        int tickerStartPos = searchPos + 2;
        int tickerHexLen = tickerLen * 2;

        if (tickerStartPos + tickerHexLen > outext.length()) continue;

        // Extract and validate ticker
        QString ticker;
        bool valid = true;

        for (int i = 0; i < tickerLen; ++i) {
            int charHex = outext.mid(tickerStartPos + i * 2, 2).toInt(&ok, 16);
            if (!ok) { valid = false; break; }

            char c = static_cast<char>(charHex);
            // First char must be A-Z, rest can be A-Z or 0-9
            if (i == 0) {
                if (c < 'A' || c > 'Z') { valid = false; break; }
            } else {
                if (!((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))) { valid = false; break; }
            }

            ticker += c;
        }

        if (valid && ticker.length() >= 3) {
            return ticker;
        }
    }

    return "";
}

bool TreasuryPage::mergeBallotsInternal(const QStringList& ballots, QString& mergedPsbt, bool logStatus)
{
    if (!walletModel || !clientModel) {
        showError(tr("Wallet or client model not available"));
        return false;
    }

    if (!govPSBTEdit) {
        showError(tr("Template PSBT field not initialized"));
        return false;
    }

    QString templatePsbt = govPSBTEdit->toPlainText().trimmed();
    if (templatePsbt.isEmpty()) {
        showError(tr("Template PSBT missing. Run 'Prepare Rotation' first."));
        return false;
    }

    UniValue ballotArray(UniValue::VARR);
    for (const QString& ballot : ballots) {
        ballotArray.push_back(ballot.toStdString());
    }

    UniValue params(UniValue::VARR);
    params.push_back(templatePsbt.toStdString());
    params.push_back(ballotArray);

    try {
        UniValue result = clientModel->node().executeRpc("merge_rotation", params,
                                                         walletModel->getWalletName().toStdString());

        if (!result.isObject() || !result.exists("psbt")) {
            throw std::runtime_error("merge_rotation returned invalid response");
        }

        mergedPsbt = QString::fromStdString(result.find_value("psbt").get_str());

        if (result.exists("total_ballot_units")) {
            lastMergedBallotUnits = result.find_value("total_ballot_units").getInt<uint64_t>();
        } else {
            lastMergedBallotUnits.reset();
        }

        if (result.exists("required_units")) {
            lastRequiredUnits = result.find_value("required_units").getInt<uint64_t>();
        }

        if (result.exists("quorum_met")) {
            lastMergedQuorumMet = result.find_value("quorum_met").get_bool();
        } else {
            lastMergedQuorumMet.reset();
        }

        int64_t assetDelta = 0;
        if (result.exists("asset_delta")) {
            assetDelta = result.find_value("asset_delta").getInt<int64_t>();
        }

        if (logStatus && govStatusText) {
            govStatusText->append(tr("[INFO] merge_rotation succeeded"));
            govStatusText->append(tr("  Ballots merged: %1").arg(ballots.size()));
            if (lastMergedBallotUnits) {
                govStatusText->append(tr("  Total ballot units: %1")
                    .arg(static_cast<qulonglong>(*lastMergedBallotUnits)));
            }
            if (lastRequiredUnits) {
                govStatusText->append(tr("  Required units: %1")
                    .arg(static_cast<qulonglong>(*lastRequiredUnits)));
            }
            if (lastMergedQuorumMet.has_value()) {
                govStatusText->append(*lastMergedQuorumMet
                    ? tr("  ✓ Quorum met")
                    : tr("  ⚠ Quorum NOT met yet"));
            }
            if (assetDelta != 0) {
                govStatusText->append(tr("  ⚠ Asset delta detected: %1 units").arg(assetDelta));
            }
        }

        if (assetDelta != 0) {
            showError(tr("merge_rotation detected asset delta %1 (should be 0).").arg(assetDelta));
            return false;
        }

        return true;
    } catch (UniValue& objError) {
        QString message;
        try {
            int code = objError.find_value("code").getInt<int>();
            std::string detail = objError.find_value("message").get_str();
            message = tr("RPC Error %1: %2").arg(code).arg(QString::fromStdString(detail));
        } catch (...) {
            message = QString::fromStdString(objError.write());
        }
        if (logStatus && govStatusText) {
            govStatusText->append(tr("[ERROR] %1").arg(message));
        }
        showError(tr("Failed to merge ballots: %1").arg(message));
    } catch (const std::exception& e) {
        if (logStatus && govStatusText) {
            govStatusText->append(tr("[ERROR] %1").arg(e.what()));
        }
        showError(tr("Failed to merge ballots: %1").arg(e.what()));
    }
    return false;
}

void TreasuryPage::updateGovernanceProposalSummary(const QString& psbt)
{
    auto applyText = [](QTextEdit* widget, const QString& text) {
        if (!widget) return;
        QSignalBlocker blocker(widget);
        widget->setPlainText(text);
    };

    const QString trimmed = psbt.trimmed();
    if (trimmed.isEmpty()) {
        const QString placeholder = tr("Prepare a rotation PSBT to review the proposal details.");
        applyText(govIssuerProposalSummary, placeholder);
        applyText(govHolderProposalSummary, placeholder);
        return;
    }

    PartiallySignedTransaction psbtx;
    std::string error;
    if (!DecodeBase64PSBT(psbtx, trimmed.toStdString(), error)) {
        const QString message = tr("Failed to decode PSBT: %1").arg(QString::fromStdString(error));
        applyText(govIssuerProposalSummary, message);
        applyText(govHolderProposalSummary, message);
        return;
    }

    auto metadata = DecodeGovernanceMetadata(psbtx);
    if (!metadata) {
        const QString message = tr("This PSBT does not contain governance metadata.");
        applyText(govIssuerProposalSummary, message);
        applyText(govHolderProposalSummary, message);
        return;
    }

    const GovernanceProposalDetails& proposed = *metadata;

    // Get PROPOSED text from UI fields (PSBT only has hashes, not full text!)
    QString proposedText = govICUTextEdit ? govICUTextEdit->toPlainText().trimmed() : QString();
    QString proposedWitnessRaw = govWitnessTextEdit ? govWitnessTextEdit->toPlainText().trimmed() : QString();
    QString proposedTextHash = !proposedText.isEmpty() ? computeSHA256(proposedText) : proposed.canonical_hash;

    // Auto-wrap witness text into JSON bundle (identical to registration flow)
    QString proposedWitness;
    if (proposedWitnessRaw.isEmpty()) {
        // Empty witness - minimal bundle with placeholder
        QJsonObject witnessObj;
        witnessObj["version"] = "1.0";
        witnessObj["timestamp"] = QDateTime::currentSecsSinceEpoch();
        witnessObj["canonical_hash"] = "placeholder";  // Backend will replace with actual hash
        proposedWitness = QString::fromUtf8(QJsonDocument(witnessObj).toJson(QJsonDocument::Compact));
    } else {
        // Check if it's already valid JSON
        QJsonParseError parseError{};
        QJsonDocument doc = QJsonDocument::fromJson(proposedWitnessRaw.toUtf8(), &parseError);

        if (parseError.error == QJsonParseError::NoError && doc.isObject()) {
            // Already valid JSON - use as-is
            proposedWitness = proposedWitnessRaw;
        } else {
            // Plain text - auto-wrap into witness bundle (identical to registration flow)
            QJsonObject witnessObj;
            witnessObj["version"] = "1.0";
            witnessObj["timestamp"] = QDateTime::currentSecsSinceEpoch();
            witnessObj["canonical_hash"] = "placeholder";  // Backend will replace with actual hash
            witnessObj["witness_text"] = proposedWitnessRaw;
            proposedWitness = QString::fromUtf8(QJsonDocument(witnessObj).toJson(QJsonDocument::Compact));
        }
    }

    // Get proposed quorum and cap from UI
    uint16_t proposedQuorum = proposed.quorum_bps;
    int proposedCapCoins = govNewIssuanceCapSpinBox ? govNewIssuanceCapSpinBox->value() : 0;  // In coins

    // Get current asset policy for comparison
    QString assetId = govAssetCombo->currentData().toString();
    QStringList lines;

    lines << tr("===== GOVERNANCE PROPOSAL SUMMARY =====");
    lines << "";

    if (clientModel && !assetId.isEmpty()) {
        try {
            // Fetch current policy
            UniValue policyParams(UniValue::VARR);
            policyParams.push_back(assetId.toStdString());
            UniValue policy = clientModel->node().executeRpc("getassetpolicy", policyParams, "");

            uint16_t currentQuorum = policy["policy_quorum_bps"].getInt<uint16_t>();
            uint64_t currentCap = policy["issuance_cap_units"].getInt<uint64_t>();
            uint8_t decimals = policy.exists("decimals") ? policy["decimals"].getInt<uint8_t>() : 8;

            // Convert proposed coins to units
            uint64_t proposedCapUnits = (proposedCapCoins > 0) ? static_cast<uint64_t>(proposedCapCoins) * static_cast<uint64_t>(std::pow(10, decimals)) : 0;

            // Fetch current ICU text and witness bundle
            QString currentText;
            QString currentHash;
            QString currentWitnessBundle;
            try {
                UniValue icuParams(UniValue::VARR);
                icuParams.push_back(assetId.toStdString());
                UniValue icuInfo = clientModel->node().executeRpc("geticuinfo", icuParams, "");
                if (icuInfo.exists("canonical_text")) {
                    currentText = QString::fromStdString(icuInfo["canonical_text"].get_str());
                }
                if (icuInfo.exists("canonical_hash")) {
                    currentHash = QString::fromStdString(icuInfo["canonical_hash"].get_str());
                }
                if (icuInfo.exists("witness_bundle")) {
                    currentWitnessBundle = QString::fromStdString(icuInfo["witness_bundle"].get_str());
                }
            } catch (...) {
                currentText = tr("(unable to fetch)");
            }

            // Show changes
            lines << tr("QUORUM:");
            double currentPct = currentQuorum / 100.0;
            double proposedPct = proposedQuorum / 100.0;
            if (currentQuorum != proposedQuorum) {
                lines << tr("  CURRENT:  %1 bps (%2%)").arg(currentQuorum).arg(currentPct, 0, 'f', 2);
                lines << tr("  PROPOSED: %1 bps (%2%)").arg(proposedQuorum).arg(proposedPct, 0, 'f', 2);
            } else {
                lines << tr("  No change: %1 bps (%2%)").arg(currentQuorum).arg(currentPct, 0, 'f', 2);
            }
            lines << "";

            lines << tr("ISSUANCE CAP:");
            QString currentCapFmt = formatAssetAmount(currentCap, currentGovAssetDecimals);
            QString proposedCapFmt = formatAssetAmount(proposedCapUnits, currentGovAssetDecimals);
            if (proposedCapUnits > 0 && currentCap != proposedCapUnits) {
                lines << tr("  CURRENT:  %1 (%2 units)").arg(currentCapFmt).arg(currentCap);
                lines << tr("  PROPOSED: %1 (%2 units)").arg(proposedCapFmt).arg(proposedCapUnits);
            } else {
                lines << tr("  No change: %1 (%2 units)").arg(currentCapFmt).arg(currentCap);
            }
            lines << "";

            lines << tr("GOVERNANCE TEXT:");
            if (!proposedTextHash.isEmpty()) {
                lines << tr("  Proposed Hash: %1").arg(proposedTextHash);
            }
            if (!currentHash.isEmpty()) {
                lines << tr("  Current Hash:  %1").arg(currentHash);
            }

            bool textChanged = (proposedTextHash != currentHash);

            if (textChanged || !currentText.isEmpty() || !proposedText.isEmpty()) {
                lines << "";
                lines << tr("  --- CURRENT TEXT ---");
                if (!currentText.isEmpty()) {
                    lines << currentText.trimmed();
                } else {
                    lines << tr("  (empty or encrypted)");
                }

                lines << "";
                lines << tr("  --- PROPOSED TEXT ---");
                if (!proposedText.isEmpty()) {
                    lines << proposedText;
                } else {
                    lines << tr("  (empty or encrypted)");
                }
            }

            // Show witness bundle changes
            if (!currentWitnessBundle.isEmpty() || !proposedWitness.isEmpty()) {
                lines << "";
                lines << tr("WITNESS BUNDLE (Master Key Shares):");

                if (!currentWitnessBundle.isEmpty()) {
                    lines << tr("  --- CURRENT WITNESS ---");
                    QJsonParseError parseError{};
                    QJsonDocument doc = QJsonDocument::fromJson(currentWitnessBundle.toUtf8(), &parseError);
                    QString currentWitnessPretty;
                    if (parseError.error == QJsonParseError::NoError) {
                        currentWitnessPretty = QString::fromUtf8(doc.toJson(QJsonDocument::Indented));
                    } else {
                        currentWitnessPretty = currentWitnessBundle;
                    }
                    lines << currentWitnessPretty.trimmed();
                    lines << "";
                }

                if (!proposedWitness.isEmpty()) {
                    lines << tr("  --- PROPOSED WITNESS ---");
                    QJsonParseError parseError{};
                    QJsonDocument doc = QJsonDocument::fromJson(proposedWitness.toUtf8(), &parseError);
                    QString proposedWitnessPretty;
                    if (parseError.error == QJsonParseError::NoError) {
                        proposedWitnessPretty = QString::fromUtf8(doc.toJson(QJsonDocument::Indented));
                    } else {
                        proposedWitnessPretty = proposedWitness;
                    }
                    lines << proposedWitnessPretty.trimmed();
                }
            }

        } catch (const std::exception& e) {
            lines << tr("⚠ Unable to fetch current policy for comparison: %1")
                     .arg(QString::fromStdString(e.what()));
            lines << "";
            lines << tr("PROPOSED VALUES:");
            lines << tr("  Quorum: %1 bps (%2%)")
                     .arg(proposed.quorum_bps)
                     .arg(proposed.quorum_bps / 100.0, 0, 'f', 2);
        }
    } else {
        lines << tr("PROPOSED VALUES:");
        lines << tr("  Settled Supply: %1 units")
                 .arg(formatAssetAmount(proposed.settled_supply, currentGovAssetDecimals));
        lines << tr("  Quorum: %1 bps (%2%)")
                 .arg(proposed.quorum_bps)
                 .arg(proposed.quorum_bps / 100.0, 0, 'f', 2);
        if (!proposed.canonical_hash.isEmpty()) {
            lines << tr("  Canonical Hash: %1").arg(proposed.canonical_hash);
        }
    }

    QString summary = lines.join('\n');
    applyText(govIssuerProposalSummary, summary);
    applyText(govHolderProposalSummary, summary);
}

void TreasuryPage::setClientModel(ClientModel* model)
{
    clientModel = model;

    if (clientModel) {
        // Connect to block updates to refresh asset info when new blocks arrive
        connect(clientModel, &ClientModel::numBlocksChanged,
                this, &TreasuryPage::onNumBlocksChanged);

        // Re-initialize ZKParamsManager with actual data directory
        m_zkParamsManager->deleteLater();
        m_zkParamsManager = new ZKParamsManager(clientModel->dataDir(), this);
        connect(m_zkParamsManager, &ZKParamsManager::provingKeyReady, this, &TreasuryPage::onProvingKeyReady);
        connect(m_zkParamsManager, &ZKParamsManager::provingKeyFailed, this, &TreasuryPage::onProvingKeyFailed);

        // Check if proving key is already available
        if (m_zkParamsManager->isProvingKeyAvailable()) {
            zkProvingKeyFileEdit->setText(m_zkParamsManager->provingKeyPath());
            if (zkProvingKeyStatusLabel) {
                zkProvingKeyStatusLabel->setText(tr("Available"));
                zkProvingKeyStatusLabel->setStyleSheet("color: #4CAF50; font-weight: bold;");
            }
        }

        refreshAssetList();
        refreshICUDashboard();
    }
}

void TreasuryPage::setupRegistrationTab()
{
    registrationTab = new QWidget();
    QVBoxLayout* layout = new QVBoxLayout(registrationTab);

    // Asset basics group
    QGroupBox* basicsGroup = new QGroupBox(tr("Asset Details"));
    QFormLayout* basicsForm = new QFormLayout();

    // Registration mode: standalone full-bond root vs sponsored low-bond child (ICU_CHILD.md §7).
    regModeCombo = new QComboBox();
    regModeCombo->addItem(tr("Standalone root"), QString("root"));
    regModeCombo->addItem(tr("Sponsored child"), QString("child"));
    regModeCombo->setToolTip(tr("A sponsored child (ROOT.SUFFIX) registers at a low bond by co-spending its parent root's current ICU."));
    basicsForm->addRow(tr("Mode:"), regModeCombo);

    // Sponsored-child controls (parent dropdown + full-ticker preview); shown only in child mode.
    regChildControls = new QWidget();
    QFormLayout* childForm = new QFormLayout(regChildControls);
    childForm->setContentsMargins(0, 0, 0, 0);
    regParentCombo = new QComboBox();
    regParentCombo->setToolTip(tr("Root assets from your wallet's controlled set. The node verifies spendability and the full bond at submit; a root that no longer holds the full bond is rejected there."));
    childForm->addRow(tr("Sponsoring root:"), regParentCombo);
    regChildPreviewLabel = new QLabel();
    regChildPreviewLabel->setStyleSheet("color: #888;");
    childForm->addRow(tr("Full ticker:"), regChildPreviewLabel);
    basicsForm->addRow(QString(), regChildControls);
    regChildControls->setVisible(false);

    regTickerEdit = new QLineEdit();
    regTickerEdit->setPlaceholderText(tr("e.g., GOLD (3-11 uppercase chars)"));
    regTickerEdit->setMaxLength(11);
    regTickerLabel = new QLabel(tr("Ticker:"));
    basicsForm->addRow(regTickerLabel, regTickerEdit);

    connect(regModeCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &TreasuryPage::onRegModeChanged);
    connect(regParentCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &TreasuryPage::onRegChildPreviewUpdate);
    connect(regTickerEdit, &QLineEdit::textChanged, this, &TreasuryPage::onRegChildPreviewUpdate);

    regDecimalsSpinBox = new QSpinBox();
    regDecimalsSpinBox->setRange(0, 18);
    regDecimalsSpinBox->setValue(8);
    basicsForm->addRow(tr("Decimals:"), regDecimalsSpinBox);

    QHBoxLayout* assetIdLayout = new QHBoxLayout();
    regAssetIdEdit = new QLineEdit();
    regAssetIdEdit->setPlaceholderText(tr("64 hex chars or leave blank to generate"));
    regAssetIdEdit->setMaxLength(64);
    regGenerateIdButton = new QPushButton(tr("Generate"));
    connect(regGenerateIdButton, &QPushButton::clicked, this, &TreasuryPage::onGenerateAssetId);
    assetIdLayout->addWidget(regAssetIdEdit);
    assetIdLayout->addWidget(regGenerateIdButton);
    basicsForm->addRow(tr("Asset ID:"), assetIdLayout);

    basicsGroup->setLayout(basicsForm);
    layout->addWidget(basicsGroup);

    // Combined Policy Settings and Script Families group (two-column layout)
    QGroupBox* policyGroup = new QGroupBox(tr("Advanced: Policy Settings and Allowed Script Families"));
    policyGroup->setCheckable(true);
    policyGroup->setChecked(false);  // Collapsed by default
    policyGroup->setToolTip(tr("Advanced policy and script family configuration. Most users can leave these at default values."));
    QGridLayout* policyGrid = new QGridLayout();

    // Column 1: Policy Settings
    QLabel* policyLabel = new QLabel(tr("<b>Policy Settings:</b>"));
    policyGrid->addWidget(policyLabel, 0, 0);

    regMintAllowedCheckbox = new QCheckBox(tr("MINT_ALLOWED"));
    regMintAllowedCheckbox->setChecked(true);
    regMintAllowedCheckbox->setToolTip(tr("Allow the issuer to mint new units of this asset."));
    policyGrid->addWidget(regMintAllowedCheckbox, 1, 0);

    regBurnAllowedCheckbox = new QCheckBox(tr("BURN_ALLOWED"));
    regBurnAllowedCheckbox->setChecked(true);
    regBurnAllowedCheckbox->setToolTip(tr("Allow holders to burn (destroy) their units of this asset."));
    policyGrid->addWidget(regBurnAllowedCheckbox, 2, 0);

    regBurnRequireICUCheckbox = new QCheckBox(tr("BURN_REQUIRE_ICU"));
    regBurnRequireICUCheckbox->setChecked(true);
    regBurnRequireICUCheckbox->setToolTip(tr("Require the issuer's signature (ICU) to burn units. Prevents holders from burning without issuer approval."));
    policyGrid->addWidget(regBurnRequireICUCheckbox, 3, 0);

    regBurnJointRequiredCheckbox = new QCheckBox(tr("BURN_JOINT_REQUIRED"));
    regBurnJointRequiredCheckbox->setToolTip(tr("The issuer cannot burn balances directly. Burns require joint authorization from both the issuer and the holder.\n\nRestriction: When enabled, only P2PKH and P2WPKH script families are allowed."));
    connect(regBurnJointRequiredCheckbox, &QCheckBox::toggled, this, &TreasuryPage::onBurnJointRequiredChanged);
    policyGrid->addWidget(regBurnJointRequiredCheckbox, 4, 0);

    // Policy restrictions label (for warnings)
    regPolicyRestrictionsLabel = new QLabel();
    regPolicyRestrictionsLabel->setWordWrap(true);
    regPolicyRestrictionsLabel->setStyleSheet("color: #FF8C00; font-weight: bold;");
    regPolicyRestrictionsLabel->setVisible(false);
    policyGrid->addWidget(regPolicyRestrictionsLabel, 5, 0);

    // Column 2: Script Families
    QLabel* familiesLabel = new QLabel(tr("<b>Allowed Script Families:</b>"));
    policyGrid->addWidget(familiesLabel, 0, 1);

    regFamilyP2PKHCheckbox = new QCheckBox(tr("P2PKH (Legacy)"));
    regFamilyP2PKHCheckbox->setToolTip(tr("Pay-to-Public-Key-Hash: Legacy Bitcoin address format (1...)."));
    policyGrid->addWidget(regFamilyP2PKHCheckbox, 1, 1);

    regFamilyP2WPKHCheckbox = new QCheckBox(tr("P2WPKH (SegWit)"));
    regFamilyP2WPKHCheckbox->setChecked(true);
    regFamilyP2WPKHCheckbox->setToolTip(tr("Pay-to-Witness-Public-Key-Hash: Native SegWit address format (bc1q...)."));
    policyGrid->addWidget(regFamilyP2WPKHCheckbox, 2, 1);

    regFamilyP2WSHCheckbox = new QCheckBox(tr("P2WSH (SegWit Script)"));
    regFamilyP2WSHCheckbox->setChecked(true);
    regFamilyP2WSHCheckbox->setToolTip(tr("Pay-to-Witness-Script-Hash: SegWit multisig and complex script support (bc1q...)."));
    policyGrid->addWidget(regFamilyP2WSHCheckbox, 3, 1);

    regFamilyP2TRCheckbox = new QCheckBox(tr("P2TR (Taproot)"));
    regFamilyP2TRCheckbox->setChecked(true);
    regFamilyP2TRCheckbox->setToolTip(tr("Pay-to-Taproot: Advanced privacy and script capabilities (bc1p...)."));
    policyGrid->addWidget(regFamilyP2TRCheckbox, 4, 1);

    policyGrid->setColumnStretch(0, 1);
    policyGrid->setColumnStretch(1, 1);
    policyGroup->setLayout(policyGrid);

    // Connect toggle to hide/show group contents
    connect(policyGroup, &QGroupBox::toggled, [policyGrid](bool checked) {
        for (int i = 0; i < policyGrid->count(); ++i) {
            QWidget* widget = policyGrid->itemAt(i)->widget();
            if (widget) {
                widget->setVisible(checked);
            }
        }
    });

    // Initially hide contents since checked=false by default
    for (int i = 0; i < policyGrid->count(); ++i) {
        QWidget* widget = policyGrid->itemAt(i)->widget();
        if (widget) {
            widget->setVisible(false);
        }
    }

    layout->addWidget(policyGroup);

    // Bond and fees group
    QGroupBox* bondGroup = new QGroupBox(tr("Bond and Unlock Settings"));
    bondGroup->setToolTip(tr("Asset registration requires a bond that will be locked until sufficient fees are accumulated."));
    QFormLayout* bondForm = new QFormLayout();

    regBondAmountEdit = new QLineEdit();
    regBondAmountEdit->setPlaceholderText(tr("Minimum 5.0 TSC"));
    regBondAmountEdit->setText("5.1");
    regBondAmountEdit->setToolTip(tr("You commit this amount of TSC to register the asset. This bond will be locked until transaction fees from asset operations accumulate to the Unlock Fees amount, at which point the bond can be spent and the ICU (Issuer Control UTXO) can be rotated to a dust output."));
    bondForm->addRow(tr("Bond Amount (TSC):"), regBondAmountEdit);

    regUnlockFeesEdit = new QLineEdit();
    regUnlockFeesEdit->setPlaceholderText(tr("e.g., 5.1 (must be >= bond amount)"));
    regUnlockFeesEdit->setText("5.1");
    regUnlockFeesEdit->setToolTip(tr("When miner fees accumulated from asset transactions reach this amount (in TSC), the bond can be spent and the ICU can be rotated to a dust output."));
    bondForm->addRow(tr("Unlock Fees (TSC):"), regUnlockFeesEdit);

    bondGroup->setLayout(bondForm);
    layout->addWidget(bondGroup);

    // Register button (green prominent button before optional sections)
    regRegisterButton = new QPushButton(tr("Register Asset"));
    regRegisterButton->setStyleSheet(
        "QPushButton {"
        "  background-color: #4CAF50;"
        "  color: white;"
        "  border: none;"
        "  border-radius: 4px;"
        "  font-weight: bold;"
        "  padding: 8px 16px;"
        "  font-size: 13px;"
        "}"
        "QPushButton:hover {"
        "  background-color: #45a049;"
        "}"
        "QPushButton:pressed {"
        "  background-color: #3d8b40;"
        "}"
    );
    if (m_platform_style->getImagesOnButtons()) {
        regRegisterButton->setIcon(m_platform_style->SingleColorIcon(":/icons/add"));
    }
    connect(regRegisterButton, &QPushButton::clicked, this, &TreasuryPage::onRegisterAsset);
    layout->addWidget(regRegisterButton);

    // Governance Settings group (optional)
    icuGovernanceGroup = new QGroupBox(tr("Governance Settings (Optional)"));
    QFormLayout* icuForm = new QFormLayout();

    regICUTextEdit = new QTextEdit();
    regICUTextEdit->setPlaceholderText(tr("Governance document (e.g., 'Board requires 2/3 majority for all decisions')"));
    regICUTextEdit->setAcceptRichText(false);  // byte-exact plain text — canonical_hash is over these bytes
    regICUTextEdit->setMinimumHeight(220);      // larger editor (was capped at 80px)
    connect(regICUTextEdit, &QTextEdit::textChanged, this, &TreasuryPage::onICUTextChanged);
    {
        QWidget* canonicalCell = new QWidget();
        QVBoxLayout* canonicalCellLayout = new QVBoxLayout(canonicalCell);
        canonicalCellLayout->setContentsMargins(0, 0, 0, 0);
        canonicalCellLayout->addWidget(regICUTextEdit);
        regExpandCanonicalButton = new QPushButton(tr("\xE2\xA4\xA2 Expand editor"));
        regExpandCanonicalButton->setToolTip(tr("Edit the canonical text in a large window"));
        connect(regExpandCanonicalButton, &QPushButton::clicked, this, &TreasuryPage::onExpandCanonicalText);
        QHBoxLayout* canonicalBtnRow = new QHBoxLayout();
        canonicalBtnRow->addStretch();
        canonicalBtnRow->addWidget(regExpandCanonicalButton);
        canonicalCellLayout->addLayout(canonicalBtnRow);
        icuForm->addRow(tr("Canonical Text:"), canonicalCell);
    }

    regICUVisibilityCombo = new QComboBox();
    regICUVisibilityCombo->addItem(tr("Public (all can read)"), 0);
    regICUVisibilityCombo->addItem(tr("Holder-Only (encrypted)"), 1);
    icuForm->addRow(tr("Visibility:"), regICUVisibilityCombo);

    QHBoxLayout* quorumLayout = new QHBoxLayout();
    regPolicyQuorumSpinBox = new QSpinBox();
    regPolicyQuorumSpinBox->setRange(0, 10000);
    regPolicyQuorumSpinBox->setSuffix(tr(" bps"));
    regPolicyQuorumSpinBox->setValue(0);
    regQuorumPctLabel = new QLabel(tr("(0.00%)"));
    connect(regPolicyQuorumSpinBox, QOverload<int>::of(&QSpinBox::valueChanged),
            this, &TreasuryPage::onQuorumChanged);
    quorumLayout->addWidget(regPolicyQuorumSpinBox);
    quorumLayout->addWidget(regQuorumPctLabel);
    icuForm->addRow(tr("Policy Quorum:"), quorumLayout);

    regIssuanceCapSpinBox = new QSpinBox();
    regIssuanceCapSpinBox->setRange(0, 2000000000);
    regIssuanceCapSpinBox->setValue(0);
    regIssuanceCapSpinBox->setSpecialValueText(tr("Unlimited"));
    regIssuanceCapSpinBox->setToolTip(tr("Maximum issuable supply in coins (will be multiplied by 10^decimals)"));
    icuForm->addRow(tr("Issuance Cap (coins):"), regIssuanceCapSpinBox);

    // Compression checkbox
    regUseCompressionCheckbox = new QCheckBox(tr("Use Compression (zstd)"));
    regUseCompressionCheckbox->setToolTip(tr("Enable deterministic zstd compression for governance text to reduce blockchain space usage."));
    connect(regUseCompressionCheckbox, &QCheckBox::toggled, this, &TreasuryPage::onICUTextChanged);
    icuForm->addRow(regUseCompressionCheckbox);

    // Size estimate
    regPayloadSizeLabel = new QLabel(tr("Payload size: 0 bytes"));
    regPayloadSizeLabel->setStyleSheet(QStringLiteral("color: %1;").arg(ThemeHelpers::mutedTextColor()));
    icuForm->addRow(tr("Size Estimate:"), regPayloadSizeLabel);

    // ICU Precheck & Hash
    QHBoxLayout* precheckLayout = new QHBoxLayout();
    regPrecheckICUButton = new QPushButton(tr("Compute Hash"));
    regPrecheckICUButton->setToolTip(tr("Compute the final canonical hash (document body plus any appended schedule of designated clauses) and normalize the body to its committed form (CRLF, NFC, trailing space trimmed)."));
    connect(regPrecheckICUButton, &QPushButton::clicked, this, &TreasuryPage::onPrecheckICU);
    precheckLayout->addWidget(regPrecheckICUButton);

    regCanonicalHashLabel = new QLabel(tr("(no hash computed)"));
    regCanonicalHashLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    regCanonicalHashLabel->setStyleSheet("font-family: monospace; color: #888;");
    precheckLayout->addWidget(regCanonicalHashLabel, 1);

    regCopyHashButton = new QPushButton(tr("Copy"));
    regCopyHashButton->setEnabled(false);
    connect(regCopyHashButton, &QPushButton::clicked, this, &TreasuryPage::onCopyCanonicalHash);
    precheckLayout->addWidget(regCopyHashButton);

    regCanonicalHashCaption = new QLabel(tr("Canonical Hash:"));
    icuForm->addRow(regCanonicalHashCaption, precheckLayout);

    regWitnessBundleEdit = new QTextEdit();
    regWitnessBundleEdit->setPlaceholderText(tr("Optional: Witness text (e.g., DocuSign envelope ID, PGP signature, or attestation details).\nThis will be automatically wrapped in a JSON bundle with version, timestamp, and canonical_hash."));
    regWitnessBundleEdit->setAcceptRichText(false);
    regWitnessBundleEdit->setMinimumHeight(140);  // larger editor (was capped at 80px)
    {
        QWidget* witnessCell = new QWidget();
        QVBoxLayout* witnessCellLayout = new QVBoxLayout(witnessCell);
        witnessCellLayout->setContentsMargins(0, 0, 0, 0);
        witnessCellLayout->addWidget(regWitnessBundleEdit);
        regExpandWitnessButton = new QPushButton(tr("\xE2\xA4\xA2 Expand editor"));
        regExpandWitnessButton->setToolTip(tr("Edit the witness text in a large window"));
        connect(regExpandWitnessButton, &QPushButton::clicked, this, &TreasuryPage::onExpandWitnessText);
        QHBoxLayout* witnessBtnRow = new QHBoxLayout();
        witnessBtnRow->addStretch();
        witnessBtnRow->addWidget(regExpandWitnessButton);
        witnessCellLayout->addLayout(witnessBtnRow);
        icuForm->addRow(tr("Witness Text:"), witnessCell);
    }

    // Optional issuer/QES signature payload over the WHOLE-document canonical_hash. The issuer pastes
    // a signature record obtained out-of-band (e.g. an Evrotrust QES JSON); it is committed into the
    // witness bundle as an attestation covering canonical_hash. Opaque to the node ("anchor, not embed").
    regWholeDocAttestEdit = new QTextEdit();
    regWholeDocAttestEdit->setPlaceholderText(tr("Optional: signature payload (e.g. QES record JSON, or a verifiable pointer) over the whole-document hash. Committed into the witness as an attestation covering canonical_hash."));
    regWholeDocAttestEdit->setAcceptRichText(false);
    regWholeDocAttestEdit->setMinimumHeight(80);
    icuForm->addRow(tr("Whole-document signature:"), regWholeDocAttestEdit);

    icuGovernanceGroup->setLayout(icuForm);
    layout->addWidget(icuGovernanceGroup);

    // ===== Designated Clauses (TSC-ICU-CONTEXT-1) =====
    // Each clause becomes a numbered entry in an appended "Designated clauses requiring holder
    // affirmation" schedule. The heading makes every committed body a unique substring of the
    // canonical, so the node accepts it even when a clause is also quoted in the document above.
    regClausesGroup = new QGroupBox(tr("Designated Clauses (Optional)"));
    {
        QVBoxLayout* clausesOuter = new QVBoxLayout();

        QLabel* clausesHelp = new QLabel(tr(
            "Clauses the holder must affirm. Each is appended to the document as a numbered, "
            "labelled section the holder affirms individually. The main document above stays free "
            "text. Leave empty for whole-document acceptance."));
        clausesHelp->setWordWrap(true);
        clausesHelp->setStyleSheet("color: #888;");
        clausesOuter->addWidget(clausesHelp);

        regClausesContainer = new QWidget();
        regClausesContainerLayout = new QVBoxLayout(regClausesContainer);
        regClausesContainerLayout->setContentsMargins(0, 0, 0, 0);
        clausesOuter->addWidget(regClausesContainer);

        QHBoxLayout* clauseButtonsRow = new QHBoxLayout();
        regAddClauseButton = new QPushButton(tr("+ Add clause"));
        connect(regAddClauseButton, &QPushButton::clicked, this, &TreasuryPage::onAddClauseRow);
        clauseButtonsRow->addWidget(regAddClauseButton);
        clauseButtonsRow->addStretch();
        clausesOuter->addLayout(clauseButtonsRow);

        regClausesSummaryLabel = new QLabel(tr("0 clauses - whole-document acceptance"));
        regClausesSummaryLabel->setStyleSheet("color: #888;");
        clausesOuter->addWidget(regClausesSummaryLabel);

        regClausesGroup->setLayout(clausesOuter);
    }
    layout->addWidget(regClausesGroup);

    // ZK Parameters group (optional)
    zkParamsGroup = new QGroupBox(tr("Compliance (Optional)"));
    QFormLayout* zkForm = new QFormLayout();

    regKYCRequiredCheckbox = new QCheckBox(tr("Require ZK proof for transfers (KYC_REQUIRED)"));
    zkForm->addRow(regKYCRequiredCheckbox);

    regTFRRequiredCheckbox = new QCheckBox(tr("Require TFR anchor for transfers (TFR_ANCHOR_REQUIRED)"));
    regTFRRequiredCheckbox->setToolTip(tr("If enabled, all transfers must include a TFR (Transfer Flags Required) anchor hash that binds the transaction to off-chain regulatory reporting."));
    zkForm->addRow(regTFRRequiredCheckbox);

    regCircuitCombo = new QComboBox();
    regCircuitCombo->addItem(tr("HDV1 (Holder Delegation v1)"), "hdv1");
    regCircuitCombo->setEnabled(false);
    connect(regKYCRequiredCheckbox, &QCheckBox::toggled, regCircuitCombo, &QComboBox::setEnabled);
    zkForm->addRow(tr("Circuit:"), regCircuitCombo);

    QHBoxLayout* vkLayout = new QHBoxLayout();
    regVKFileEdit = new QLineEdit();
    regVKFileEdit->setPlaceholderText(tr("/path/to/verification_key.bin"));
    regVKBrowseButton = new QPushButton(tr("Browse..."));
    connect(regVKBrowseButton, &QPushButton::clicked, this, &TreasuryPage::onBrowseVKFile);
    vkLayout->addWidget(regVKFileEdit);
    vkLayout->addWidget(regVKBrowseButton);
    zkForm->addRow(tr("Verification Key:"), vkLayout);

    regMaxRootAgeSpinBox = new QSpinBox();
    regMaxRootAgeSpinBox->setRange(0, 100000);
    regMaxRootAgeSpinBox->setSuffix(tr(" blocks"));
    regMaxRootAgeSpinBox->setValue(1008);
    regMaxRootAgeSpinBox->setToolTip(tr("Maximum age for compliance roots (blocks). 1008 blocks ≈ 1 week @ 10min/block"));
    zkForm->addRow(tr("Max Root Age:"), regMaxRootAgeSpinBox);

    regVKCommitLabel = new QLabel(tr("(computed after VK load)"));
    regVKCommitLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    regVKCommitLabel->setStyleSheet("font-family: monospace; color: #888;");
    zkForm->addRow(tr("VK Commitment:"), regVKCommitLabel);

    regInitialComplianceRootEdit = new QLineEdit();
    regInitialComplianceRootEdit->setPlaceholderText(tr("Initial compliance root (64 hex chars) - generate using Compliance tab"));
    regInitialComplianceRootEdit->setToolTip(tr("The Merkle root of initial KYC identities.\n"
                                                 "Generate this using the Compliance tab's \"Build Merkle Tree\" feature,\n"
                                                 "or use an external tool to create the compliance tree."));
    zkForm->addRow(tr("Initial Compliance Root:"), regInitialComplianceRootEdit);

    zkParamsGroup->setLayout(zkForm);
    layout->addWidget(zkParamsGroup);

    // Status text
    regStatusText = new QTextEdit();
    regStatusText->setReadOnly(true);
    regStatusText->setMaximumHeight(100);
    layout->addWidget(regStatusText);

    layout->addStretch();
}

void TreasuryPage::setupMintTab()
{
    mintTab = new QWidget();
    QVBoxLayout* layout = new QVBoxLayout(mintTab);

    // Asset selection
    QGroupBox* selectGroup = new QGroupBox(tr("Select Asset"));
    QHBoxLayout* selectLayout = new QHBoxLayout();

    mintAssetCombo = new QComboBox();
    connect(mintAssetCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &TreasuryPage::onMintAssetSelected);
    selectLayout->addWidget(new QLabel(tr("Asset:")));
    selectLayout->addWidget(mintAssetCombo);

    mintRefreshButton = new QPushButton(tr("Refresh"));
    mintRefreshButton->setMaximumWidth(80);
    connect(mintRefreshButton, &QPushButton::clicked, this, &TreasuryPage::onMintRefresh);
    selectLayout->addWidget(mintRefreshButton);

    selectGroup->setLayout(selectLayout);
    layout->addWidget(selectGroup);

    // Asset info display
    QGroupBox* infoGroup = new QGroupBox(tr("Asset Information"));
    QFormLayout* infoForm = new QFormLayout();

    mintPolicyLabel = new QLabel(tr("N/A"));
    infoForm->addRow(tr("Policy:"), mintPolicyLabel);

    mintBondLabel = new QLabel(tr("N/A"));
    infoForm->addRow(tr("Bond:"), mintBondLabel);

    mintFeesLabel = new QLabel(tr("N/A"));
    infoForm->addRow(tr("Fees Accumulated:"), mintFeesLabel);

    mintICULabel = new QLabel(tr("N/A"));
    mintICULabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    infoForm->addRow(tr("Current ICU:"), mintICULabel);

    mintWrapStatusLabel = new QLabel(tr(""));
    mintWrapStatusLabel->setWordWrap(true);
    infoForm->addRow(tr("Key Wrapping:"), mintWrapStatusLabel);

    infoGroup->setLayout(infoForm);
    layout->addWidget(infoGroup);

    // Mint parameters
    QGroupBox* paramsGroup = new QGroupBox(tr("Mint Parameters"));
    QFormLayout* paramsForm = new QFormLayout();

    QHBoxLayout* amountLayout = new QHBoxLayout();
    mintAmountEdit = new QLineEdit();
    mintAmountEdit->setPlaceholderText(tr("Amount in base units"));
    connect(mintAmountEdit, &QLineEdit::textChanged, this, &TreasuryPage::onMintAmountChanged);
    mintAmountFormattedLabel = new QLabel();
    amountLayout->addWidget(mintAmountEdit);
    amountLayout->addWidget(mintAmountFormattedLabel);
    paramsForm->addRow(tr("Amount:"), amountLayout);

    QHBoxLayout* destLayout = new QHBoxLayout();
    mintDestAddressEdit = new QLineEdit();
    mintDestAddressEdit->setPlaceholderText(tr("Destination address for minted assets"));
    destLayout->addWidget(mintDestAddressEdit);
    QPushButton* genDestButton = new QPushButton(tr("Generate"));
    genDestButton->setMaximumWidth(80);
    genDestButton->setToolTip(tr("Generate a new taproot address for mint destination"));
    connect(genDestButton, &QPushButton::clicked, [this]() {
        if (!walletModel) return;
        auto destRes = walletModel->wallet().getNewDestination(OutputType::BECH32M, "");
        if (!destRes) {
            QMessageBox::critical(this, tr("Address Generation Failed"),
                tr("Could not generate a new taproot destination.")); 
            return;
        }
        mintDestAddressEdit->setText(QString::fromStdString(EncodeDestination(*destRes)));
    });
    destLayout->addWidget(genDestButton);
    paramsForm->addRow(tr("Destination:"), destLayout);

    QHBoxLayout* icuLayout = new QHBoxLayout();
    mintNewICUAddressEdit = new QLineEdit();
    mintNewICUAddressEdit->setPlaceholderText(tr("New ICU address (rotation)"));
    icuLayout->addWidget(mintNewICUAddressEdit);
    QPushButton* genICUButton = new QPushButton(tr("Generate"));
    genICUButton->setMaximumWidth(80);
    genICUButton->setToolTip(tr("Generate a new taproot address for ICU rotation"));
    connect(genICUButton, &QPushButton::clicked, [this]() {
        if (!walletModel) return;
        auto destRes = walletModel->wallet().getNewDestination(OutputType::BECH32M, "");
        if (!destRes) {
            QMessageBox::critical(this, tr("Address Generation Failed"),
                tr("Could not generate a new taproot ICU address."));
            return;
        }
        mintNewICUAddressEdit->setText(QString::fromStdString(EncodeDestination(*destRes)));
    });
    icuLayout->addWidget(genICUButton);
    paramsForm->addRow(tr("New ICU Address:"), icuLayout);

    // Auto-wrap DEK for WRAP_REQUIRED assets
    mintAutoWrapCheckbox = new QCheckBox(tr("Auto-wrap DEK (recommended for WRAP_REQUIRED assets)"));
    mintAutoWrapCheckbox->setChecked(true);
    mintAutoWrapCheckbox->setToolTip(tr("Automatically wrap the Data Encryption Key in minted output.\n"
                                        "Required for assets with ICU_KEYWRAP enforcement."));
    paramsForm->addRow(tr("Auto Key Wrapping:"), mintAutoWrapCheckbox);

    // Manual wrapped key input (advanced - for when auto-wrap is disabled)
    mintWrappedKeyEdit = new QLineEdit();
    mintWrappedKeyEdit->setPlaceholderText(tr("Manual wrapped_key (hex) - advanced use only"));
    mintWrappedKeyEdit->setEnabled(false);
    mintWrappedKeyEdit->setToolTip(tr("Manually provide a pre-wrapped DEK.\nOnly used if auto-wrap is disabled."));
    paramsForm->addRow(tr("Manual Wrapped Key:"), mintWrappedKeyEdit);

    // Connect auto-wrap checkbox to enable/disable manual field
    connect(mintAutoWrapCheckbox, &QCheckBox::toggled, [this](bool checked) {
        mintWrappedKeyEdit->setEnabled(!checked);
    });

    paramsGroup->setLayout(paramsForm);
    layout->addWidget(paramsGroup);

    // Mint button (green prominent button)
    mintMintButton = new QPushButton(tr("Mint Asset"));
    mintMintButton->setStyleSheet(
        "QPushButton {"
        "  background-color: #4CAF50;"
        "  color: white;"
        "  border: none;"
        "  border-radius: 4px;"
        "  font-weight: bold;"
        "  padding: 8px 16px;"
        "  font-size: 13px;"
        "}"
        "QPushButton:hover {"
        "  background-color: #45a049;"
        "}"
        "QPushButton:pressed {"
        "  background-color: #3d8b40;"
        "}"
    );
    if (m_platform_style->getImagesOnButtons()) {
        mintMintButton->setIcon(m_platform_style->SingleColorIcon(":/icons/add"));
    }
    connect(mintMintButton, &QPushButton::clicked, this, &TreasuryPage::onMintAsset);
    layout->addWidget(mintMintButton);

    // Status text
    mintStatusText = new QTextEdit();
    mintStatusText->setReadOnly(true);
    mintStatusText->setMaximumHeight(100);
    layout->addWidget(mintStatusText);

    layout->addStretch();
}

void TreasuryPage::setupBurnTab()
{
    burnTab = new QWidget();
    QVBoxLayout* layout = new QVBoxLayout(burnTab);

    // Asset selection
    QGroupBox* selectGroup = new QGroupBox(tr("Select Asset"));
    QHBoxLayout* selectLayout = new QHBoxLayout();

    burnAssetCombo = new QComboBox();
    connect(burnAssetCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &TreasuryPage::onBurnAssetSelected);
    selectLayout->addWidget(new QLabel(tr("Asset:")));
    selectLayout->addWidget(burnAssetCombo);

    burnRefreshUTXOsButton = new QPushButton(tr("Refresh"));
    burnRefreshUTXOsButton->setMaximumWidth(80);
    connect(burnRefreshUTXOsButton, &QPushButton::clicked, this, &TreasuryPage::onBurnRefreshUTXOs);
    selectLayout->addWidget(burnRefreshUTXOsButton);

    selectGroup->setLayout(selectLayout);
    layout->addWidget(selectGroup);

    // Manual UTXO input (for issuer to burn any UTXO)
    QGroupBox* manualGroup = new QGroupBox(tr("Manual UTXO Entry (for burning non-wallet UTXOs)"));
    QFormLayout* manualForm = new QFormLayout();

    burnManualTxidEdit = new QLineEdit();
    burnManualTxidEdit->setPlaceholderText(tr("Transaction ID (64 hex chars)"));
    burnManualTxidEdit->setMaxLength(64);
    manualForm->addRow(tr("UTXO TxID:"), burnManualTxidEdit);

    burnManualVoutEdit = new QLineEdit();
    burnManualVoutEdit->setPlaceholderText(tr("Output index"));
    manualForm->addRow(tr("UTXO Vout:"), burnManualVoutEdit);

    burnUseManualButton = new QPushButton(tr("Use Manual UTXO"));
    connect(burnUseManualButton, &QPushButton::clicked, this, &TreasuryPage::onBurnUseManual);
    manualForm->addRow("", burnUseManualButton);

    manualGroup->setLayout(manualForm);
    layout->addWidget(manualGroup);

    // Asset UTXO table (for selecting which UTXO to burn)
    QGroupBox* utxoGroup = new QGroupBox(tr("Wallet-Owned Asset UTXOs (Select to Burn)"));
    QVBoxLayout* utxoLayout = new QVBoxLayout();

    burnAssetUTXOTable = new QTableWidget();
    burnAssetUTXOTable->setColumnCount(5);
    burnAssetUTXOTable->setHorizontalHeaderLabels({
        tr("TxID"), tr("Vout"), tr("Amount"), tr("Confirmations"), tr("Address")
    });
    burnAssetUTXOTable->horizontalHeader()->setStretchLastSection(true);
    burnAssetUTXOTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    burnAssetUTXOTable->setSelectionMode(QAbstractItemView::SingleSelection);
    burnAssetUTXOTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    connect(burnAssetUTXOTable, &QTableWidget::cellClicked,
            this, &TreasuryPage::onBurnUTXOSelected);
    utxoLayout->addWidget(burnAssetUTXOTable);

    utxoGroup->setLayout(utxoLayout);
    layout->addWidget(utxoGroup);

    // Burn info display
    QGroupBox* infoGroup = new QGroupBox(tr("Burn Information"));
    QFormLayout* infoForm = new QFormLayout();

    burnSelectedUTXOLabel = new QLabel(tr("None selected"));
    infoForm->addRow(tr("Selected UTXO:"), burnSelectedUTXOLabel);

    burnICULabel = new QLabel(tr("N/A"));
    burnICULabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    infoForm->addRow(tr("Current ICU:"), burnICULabel);

    QHBoxLayout* burnICULayout = new QHBoxLayout();
    burnNewICUAddressEdit = new QLineEdit();
    burnNewICUAddressEdit->setPlaceholderText(tr("New ICU address (rotation)"));
    burnICULayout->addWidget(burnNewICUAddressEdit);
    QPushButton* genBurnICUButton = new QPushButton(tr("Generate"));
    genBurnICUButton->setMaximumWidth(80);
    genBurnICUButton->setToolTip(tr("Generate a new taproot address for ICU rotation"));
    connect(genBurnICUButton, &QPushButton::clicked, [this]() {
        if (!walletModel) return;
        auto destRes = walletModel->wallet().getNewDestination(OutputType::BECH32M, "");
        if (!destRes) {
            QMessageBox::critical(this, tr("Address Generation Failed"),
                tr("Could not generate a new taproot ICU address."));
            return;
        }
        burnNewICUAddressEdit->setText(QString::fromStdString(EncodeDestination(*destRes)));
    });
    burnICULayout->addWidget(genBurnICUButton);
    infoForm->addRow(tr("New ICU Address:"), burnICULayout);

    infoGroup->setLayout(infoForm);
    layout->addWidget(infoGroup);

    // Burn button (red destructive button)
    burnBurnButton = new QPushButton(tr("Burn Selected Asset UTXO"));
    burnBurnButton->setStyleSheet(
        "QPushButton {"
        "  background-color: #f44336;"
        "  color: white;"
        "  border: none;"
        "  border-radius: 4px;"
        "  font-weight: bold;"
        "  padding: 8px 16px;"
        "  font-size: 13px;"
        "}"
        "QPushButton:hover:enabled {"
        "  background-color: #da190b;"
        "}"
        "QPushButton:pressed {"
        "  background-color: #c41c0c;"
        "}"
        "QPushButton:disabled {"
        "  background-color: #cccccc;"
        "  color: #666666;"
        "}"
    );
    if (m_platform_style->getImagesOnButtons()) {
        burnBurnButton->setIcon(m_platform_style->SingleColorIcon(":/icons/remove"));
    }
    burnBurnButton->setEnabled(false);
    connect(burnBurnButton, &QPushButton::clicked, this, &TreasuryPage::onBurnAsset);
    layout->addWidget(burnBurnButton);

    // Status text
    burnStatusText = new QTextEdit();
    burnStatusText->setReadOnly(true);
    burnStatusText->setMaximumHeight(100);
    layout->addWidget(burnStatusText);

    layout->addStretch();
}

void TreasuryPage::setupDashboardTab()
{
    dashboardTab = new QWidget();
    QVBoxLayout* layout = new QVBoxLayout(dashboardTab);

    // Filter controls
    dashboardFilterGroup = new QGroupBox(tr("Filter"));
    QHBoxLayout* filterLayout = new QHBoxLayout();

    dashboardFilterEdit = new QLineEdit();
    dashboardFilterEdit->setPlaceholderText(tr("Search by ticker or asset ID"));
    connect(dashboardFilterEdit, &QLineEdit::textChanged,
            this, &TreasuryPage::onDashboardFilterChanged);
    filterLayout->addWidget(dashboardFilterEdit);

    dashboardFilterCombo = new QComboBox();
    dashboardFilterCombo->addItem(tr("All"));
    dashboardFilterCombo->addItem(tr("Locked"));
    dashboardFilterCombo->addItem(tr("Unlocked"));
    connect(dashboardFilterCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &TreasuryPage::onDashboardFilterChanged);
    filterLayout->addWidget(dashboardFilterCombo);

    dashboardRefreshButton = new QPushButton(tr("Refresh"));
    connect(dashboardRefreshButton, &QPushButton::clicked, this, &TreasuryPage::onDashboardRefresh);
    filterLayout->addWidget(dashboardRefreshButton);

    dashboardFilterGroup->setLayout(filterLayout);
    layout->addWidget(dashboardFilterGroup);

    // ICU dashboard table
    dashboardICUTable = new QTableWidget();
    dashboardICUTable->setColumnCount(9);
    dashboardICUTable->setHorizontalHeaderLabels({
        tr("Ticker"), tr("Asset ID"), tr("ICU TxID"), tr("Vout"),
        tr("Bond (TSC)"), tr("Fees Accum"), tr("Unlock Target"),
        tr("Progress"), tr("Status")
    });
    dashboardICUTable->horizontalHeader()->setSectionsClickable(true);
    dashboardICUTable->horizontalHeader()->setStretchLastSection(true);
    dashboardICUTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    dashboardICUTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    dashboardICUTable->setSelectionMode(QAbstractItemView::SingleSelection);
    dashboardICUTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    dashboardICUTable->setSortingEnabled(true);
    dashboardICUTable->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    dashboardICUTable->setMaximumHeight(250);  // Limit table height to save space for text viewer
    connect(dashboardICUTable, &QTableWidget::cellClicked,
            this, &TreasuryPage::onDashboardRowClicked);
    layout->addWidget(dashboardICUTable);

    // Governance text viewer (shows canonical governance text and witness section)
    QGroupBox* icuViewerGroup = new QGroupBox(tr("Governance Text"));
    QVBoxLayout* icuViewerLayout = new QVBoxLayout();

    // Status row with visibility and governance params
    QHBoxLayout* statusRow = new QHBoxLayout();
    dashboardICUVisibilityLabel = new QLabel(tr("Select an asset to view ICU text"));
    dashboardICUVisibilityLabel->setStyleSheet("QLabel { color: gray; font-style: italic; }");
    statusRow->addWidget(dashboardICUVisibilityLabel);

    dashboardQuorumLabel = new QLabel(tr(""));
    statusRow->addWidget(dashboardQuorumLabel);

    dashboardIssuanceCapLabel = new QLabel(tr(""));
    statusRow->addWidget(dashboardIssuanceCapLabel);

    dashboardDecryptButton = new QPushButton(tr("Decrypt ICU"));
    dashboardDecryptButton->setEnabled(false);
    connect(dashboardDecryptButton, &QPushButton::clicked, this, &TreasuryPage::onDashboardDecrypt);
    statusRow->addWidget(dashboardDecryptButton);

    dashboardRotateICUButton = new QPushButton(tr("Rotate ICU"));
    if (m_platform_style->getImagesOnButtons()) {
        dashboardRotateICUButton->setIcon(m_platform_style->SingleColorIcon(":/icons/synced"));
    }
    connect(dashboardRotateICUButton, &QPushButton::clicked, this, &TreasuryPage::onOpenRotateICUDialog);
    dashboardRotateICUButton->setVisible(false);  // Hidden by default (holder mode), shown in issuer mode
    statusRow->addWidget(dashboardRotateICUButton);

    QPushButton* dashboardRotationHistoryButton = new QPushButton(tr("View Rotation History"));
    connect(dashboardRotationHistoryButton, &QPushButton::clicked, this, &TreasuryPage::onViewRotationHistory);
    statusRow->addWidget(dashboardRotationHistoryButton);

    QPushButton* dashboardViewPriorICUButton = new QPushButton(tr("View Previous ICU"));
    connect(dashboardViewPriorICUButton, &QPushButton::clicked, this, &TreasuryPage::onViewPreviousICU);
    statusRow->addWidget(dashboardViewPriorICUButton);

    // Holder-mode acceptance actions on the selected asset (hidden in issuer mode below).
    dashboardAcceptButton = new QPushButton(tr("Accept ICU"));
    dashboardAcceptButton->setToolTip(tr("Record an on-chain acknowledgment of this asset's ICU document with your holder key (icu.acceptance.record.create)."));
    connect(dashboardAcceptButton, &QPushButton::clicked, this, &TreasuryPage::onDashboardAccept);
    statusRow->addWidget(dashboardAcceptButton);

    dashboardReturnButton = new QPushButton(tr("Return Asset"));
    dashboardReturnButton->setToolTip(tr("Relinquish this asset back to the issuer (spends your holder UTXO to the issuer ICU address)."));
    connect(dashboardReturnButton, &QPushButton::clicked, this, &TreasuryPage::onDashboardReturn);
    statusRow->addWidget(dashboardReturnButton);

    // Issuer (and anyone): visualise the on-chain holder acknowledgments/returns for the selected asset.
    QPushButton* dashboardViewAcceptancesButton = new QPushButton(tr("View Acceptances"));
    dashboardViewAcceptancesButton->setToolTip(tr("List on-chain ICU acceptance records (0x40) bound to the selected asset (icu.acceptance.record.list)."));
    connect(dashboardViewAcceptancesButton, &QPushButton::clicked, this, &TreasuryPage::onDashboardViewAcceptances);
    statusRow->addWidget(dashboardViewAcceptancesButton);

    statusRow->addStretch();
    icuViewerLayout->addLayout(statusRow);

    // Text viewer (more space for readability)
    dashboardICUTextViewer = new QTextEdit();
    dashboardICUTextViewer->setReadOnly(true);
    dashboardICUTextViewer->setMinimumHeight(150);  // Increased for better readability
    dashboardICUTextViewer->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    dashboardICUTextViewer->setPlaceholderText(tr("Click on an asset row above to view its ICU text"));
    icuViewerLayout->addWidget(dashboardICUTextViewer);

    icuViewerGroup->setLayout(icuViewerLayout);
    layout->addWidget(icuViewerGroup);

    dashboardTab->setLayout(layout);
}

void TreasuryPage::setupZKComplianceTab()
{
    zkComplianceTab = new QWidget();
    QVBoxLayout* layout = new QVBoxLayout(zkComplianceTab);

    // Asset selection with special mode for pre-registration
    QHBoxLayout* assetLayout = new QHBoxLayout();
    assetLayout->addWidget(new QLabel(tr("Asset:")));
    zkAssetCombo = new QComboBox();
    zkAssetCombo->addItem(tr("(Pre-Registration Mode - Generate Initial Root)"), "");  // Special entry for issuer mode
    connect(zkAssetCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &TreasuryPage::onZKAssetSelected);
    assetLayout->addWidget(zkAssetCombo, 1);
    layout->addLayout(assetLayout);

    // Info label for pre-registration mode
    QLabel* preRegInfoLabel = new QLabel(tr("<b>Tip:</b> Select 'Pre-Registration Mode' to generate an initial compliance root before registering a KYC asset."));
    preRegInfoLabel->setWordWrap(true);
    preRegInfoLabel->setStyleSheet("color: #1976D2; padding: 8px; background-color: #E3F2FD; border-radius: 4px;");
    layout->addWidget(preRegInfoLabel);

    // Placeholder for no compliance
    zkNoComplianceLabel = new QLabel(tr("This asset does not have compliance requirements."));
    zkNoComplianceLabel->setAlignment(Qt::AlignCenter);
    zkNoComplianceLabel->setStyleSheet("color: #888; font-style: italic; padding: 40px;");
    zkNoComplianceLabel->setVisible(false);  // Hidden by default (pre-reg mode shown first)
    layout->addWidget(zkNoComplianceLabel);

    // Content widget (to be shown/hidden)
    zkContentWidget = new QWidget();
    zkContentWidget->setVisible(false);  // Start hidden until asset with compliance is selected
    QVBoxLayout* contentLayout = new QVBoxLayout(zkContentWidget);

    // Current ZK parameters
    QGroupBox* currentGroup = new QGroupBox(tr("Current ZK Parameters"));
    QFormLayout* currentForm = new QFormLayout();
    zkVKCommitLabel = new QLabel(tr("-"));
    zkVKCommitLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    currentForm->addRow(tr("VK Commitment:"), zkVKCommitLabel);
    zkMaxRootAgeLabel = new QLabel(tr("-"));
    currentForm->addRow(tr("Max Root Age:"), zkMaxRootAgeLabel);
    zkCurrentRootLabel = new QLabel(tr("-"));
    zkCurrentRootLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    currentForm->addRow(tr("Current Root:"), zkCurrentRootLabel);
    zkTFRRequiredLabel = new QLabel(tr("-"));
    zkTFRRequiredLabel->setToolTip(tr("Whether TFR (Transfer Flags Required) anchor is required for this asset. TFR anchors bind transactions to off-chain reporting for regulatory compliance."));
    currentForm->addRow(tr("TFR Anchor Required:"), zkTFRRequiredLabel);
    currentGroup->setLayout(currentForm);
    contentLayout->addWidget(currentGroup);

    // Compliance root update (Issuer)
    zkIssuerGroup = new QGroupBox(tr("Update Compliance Root (Issuer)"));
    QVBoxLayout* issuerLayout = new QVBoxLayout();

    QHBoxLayout* circuitLayoutIssuer = new QHBoxLayout();
    circuitLayoutIssuer->addWidget(new QLabel(tr("Circuit:")));
    zkCircuitComboIssuer = new QComboBox();
    zkCircuitComboIssuer->addItem(tr("HD v1 (pubkey-only, output-key binding)"), "hd_v1");
    zkCircuitComboIssuer->setToolTip(tr("ZK circuit to use for compliance proofs. Must match the circuit used during asset registration."));
    circuitLayoutIssuer->addWidget(zkCircuitComboIssuer, 1);
    issuerLayout->addLayout(circuitLayoutIssuer);

    issuerLayout->addWidget(new QLabel(tr("KYC Identities (format: pubkey,country,age,index):")));
    zkComplianceListEdit = new QTextEdit();
    zkComplianceListEdit->setPlaceholderText(tr("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,840,35,0\n02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5,840,42,1"));
    zkComplianceListEdit->setMaximumHeight(100);
    zkComplianceListEdit->setToolTip(tr("One identity per line.\nFormat: master_pubkey_hex,country_code,age,tree_index\nExample: 0279be...,840,35,0"));
    issuerLayout->addWidget(zkComplianceListEdit);

    zkBuildMerkleButton = new QPushButton(tr("Build Merkle Tree"));
    connect(zkBuildMerkleButton, &QPushButton::clicked, this, &TreasuryPage::onBuildMerkleTree);
    issuerLayout->addWidget(zkBuildMerkleButton);

    QHBoxLayout* rootLayout = new QHBoxLayout();
    rootLayout->addWidget(new QLabel(tr("New Root:")));
    zkNewRootLabel = new QLabel(tr("-"));
    zkNewRootLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    rootLayout->addWidget(zkNewRootLabel, 1);
    issuerLayout->addLayout(rootLayout);

    QHBoxLayout* issuerButtonLayout = new QHBoxLayout();
    zkRotateRootButton = new QPushButton(tr("Rotate Compliance Root"));
    zkRotateRootButton->setEnabled(false);
    connect(zkRotateRootButton, &QPushButton::clicked, this, &TreasuryPage::onRotateComplianceRoot);
    issuerButtonLayout->addWidget(zkRotateRootButton);

    zkExportProofsButton = new QPushButton(tr("Export Merkle Proofs"));
    zkExportProofsButton->setEnabled(false);
    connect(zkExportProofsButton, &QPushButton::clicked, this, &TreasuryPage::onExportMerkleProofs);
    issuerButtonLayout->addWidget(zkExportProofsButton);

    zkCopyToRegistrationButton = new QPushButton(tr("Copy to Registration"));
    zkCopyToRegistrationButton->setEnabled(false);
    zkCopyToRegistrationButton->setToolTip(tr("Copy the generated compliance root to the Registration tab's Initial Compliance Root field"));
    connect(zkCopyToRegistrationButton, &QPushButton::clicked, this, &TreasuryPage::onCopyRootToRegistration);
    issuerButtonLayout->addWidget(zkCopyToRegistrationButton);

    issuerLayout->addLayout(issuerButtonLayout);

    zkIssuerGroup->setLayout(issuerLayout);
    contentLayout->addWidget(zkIssuerGroup);

    // Proof generation (Holder)
    zkHolderGroup = new QGroupBox(tr("Generate ZK Proof (Holder)"));
    QVBoxLayout* holderLayout = new QVBoxLayout();

    // KYC Master Key section
    QGroupBox* masterKeyGroup = new QGroupBox(tr("Step 1: Generate KYC Master Key"));
    QVBoxLayout* masterKeyLayout = new QVBoxLayout();

    QLabel* masterKeyInfo = new QLabel(tr("Generate a master public key to share with the asset issuer for KYC compliance registration."));
    masterKeyInfo->setWordWrap(true);
    masterKeyInfo->setStyleSheet(QStringLiteral("color: %1; font-size: 10pt;").arg(ThemeHelpers::mutedTextColor()));
    masterKeyLayout->addWidget(masterKeyInfo);

    QHBoxLayout* masterKeyButtonLayout = new QHBoxLayout();
    QPushButton* generateMasterKeyButton = new QPushButton(tr("Generate Master Key"));
    generateMasterKeyButton->setToolTip(tr("Generate a new address and extract its public key for KYC registration"));
    connect(generateMasterKeyButton, &QPushButton::clicked, this, &TreasuryPage::onGenerateMasterKey);
    masterKeyButtonLayout->addWidget(generateMasterKeyButton);
    masterKeyButtonLayout->addStretch();
    masterKeyLayout->addLayout(masterKeyButtonLayout);

    QHBoxLayout* masterPubkeyLayout = new QHBoxLayout();
    masterPubkeyLayout->addWidget(new QLabel(tr("Master Public Key:")));
    QLineEdit* masterPubkeyEdit = new QLineEdit();
    masterPubkeyEdit->setReadOnly(true);
    masterPubkeyEdit->setPlaceholderText(tr("Click 'Generate Master Key' to create"));
    masterPubkeyEdit->setObjectName("zkMasterPubkeyEdit");
    masterPubkeyLayout->addWidget(masterPubkeyEdit, 1);
    QPushButton* copyMasterKeyButton = new QPushButton(tr("Copy"));
    copyMasterKeyButton->setToolTip(tr("Copy master public key to clipboard to share with issuer"));
    connect(copyMasterKeyButton, &QPushButton::clicked, this, &TreasuryPage::onCopyMasterKey);
    masterPubkeyLayout->addWidget(copyMasterKeyButton);
    masterKeyLayout->addLayout(masterPubkeyLayout);

    QLabel* masterAddressLabel = new QLabel(tr("Address: -"));
    masterAddressLabel->setObjectName("zkMasterAddressLabel");
    masterAddressLabel->setStyleSheet("font-family: monospace; color: #888;");
    masterAddressLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    masterKeyLayout->addWidget(masterAddressLabel);

    masterKeyGroup->setLayout(masterKeyLayout);
    holderLayout->addWidget(masterKeyGroup);

    // Separator
    QFrame* separator1 = new QFrame();
    separator1->setFrameShape(QFrame::HLine);
    separator1->setFrameShadow(QFrame::Sunken);
    holderLayout->addWidget(separator1);

    // Add label for Step 2
    QLabel* step2Label = new QLabel(tr("Step 2: Generate ZK Proof (after receiving merkle proof from issuer)"));
    step2Label->setStyleSheet("font-weight: bold; margin-top: 10px;");
    holderLayout->addWidget(step2Label);

    QHBoxLayout* circuitLayoutHolder = new QHBoxLayout();
    circuitLayoutHolder->addWidget(new QLabel(tr("Circuit:")));
    zkCircuitComboHolder = new QComboBox();
    zkCircuitComboHolder->addItem(tr("HD v1 (pubkey-only, output-key binding)"), "hd_v1");
    zkCircuitComboHolder->setToolTip(tr("ZK circuit to use for proof generation. Must match the circuit used by the asset issuer."));
    circuitLayoutHolder->addWidget(zkCircuitComboHolder, 1);
    holderLayout->addLayout(circuitLayoutHolder);

    QHBoxLayout* provingKeyLayout = new QHBoxLayout();
    provingKeyLayout->addWidget(new QLabel(tr("Proving Key:")));
    zkProvingKeyFileEdit = new QLineEdit();
    zkProvingKeyFileEdit->setPlaceholderText(tr("Path to proving_key.bin (or click Download)"));
    zkProvingKeyFileEdit->setToolTip(tr("Path to the proving key file for the selected circuit. Required for generating ZK proofs."));
    provingKeyLayout->addWidget(zkProvingKeyFileEdit, 1);
    zkProvingKeyBrowseButton = new QPushButton(tr("Browse..."));
    connect(zkProvingKeyBrowseButton, &QPushButton::clicked, this, &TreasuryPage::onBrowseProvingKey);
    provingKeyLayout->addWidget(zkProvingKeyBrowseButton);
    zkProvingKeyDownloadButton = new QPushButton(tr("Download"));
    zkProvingKeyDownloadButton->setToolTip(tr("Download proving key from ghcr.io"));
    connect(zkProvingKeyDownloadButton, &QPushButton::clicked, this, &TreasuryPage::onDownloadProvingKey);
    provingKeyLayout->addWidget(zkProvingKeyDownloadButton);
    holderLayout->addLayout(provingKeyLayout);

    zkProvingKeyStatusLabel = new QLabel();
    zkProvingKeyStatusLabel->setStyleSheet("color: #999;");
    holderLayout->addWidget(zkProvingKeyStatusLabel);

    QHBoxLayout* utxoLayout = new QHBoxLayout();
    utxoLayout->addWidget(new QLabel(tr("UTXO Txid:")));
    zkProofTxidEdit = new QLineEdit();
    zkProofTxidEdit->setPlaceholderText(tr("Transaction ID"));
    zkProofTxidEdit->setToolTip(tr("Transaction ID of the UTXO you want to spend. This identifies which asset UTXO to generate a proof for."));
    utxoLayout->addWidget(zkProofTxidEdit, 1);
    utxoLayout->addWidget(new QLabel(tr("Vout:")));
    zkProofVoutSpinBox = new QSpinBox();
    zkProofVoutSpinBox->setMinimum(0);
    zkProofVoutSpinBox->setMaximum(65535);
    zkProofVoutSpinBox->setToolTip(tr("Output index (vout) of the UTXO within the transaction."));
    utxoLayout->addWidget(zkProofVoutSpinBox);
    holderLayout->addLayout(utxoLayout);

    holderLayout->addWidget(new QLabel(tr("Witness JSON:")));
    zkProofWitnessEdit = new QTextEdit();
    zkProofWitnessEdit->setPlaceholderText(tr("{\"master_pubkey_x\": \"0x...\", \"master_pubkey_y\": \"0x...\", ...}"));
    zkProofWitnessEdit->setMaximumHeight(80);
    holderLayout->addWidget(zkProofWitnessEdit);

    holderLayout->addWidget(new QLabel(tr("Merkle Proof (from issuer):")));
    zkProofMerkleProofEdit = new QTextEdit();
    zkProofMerkleProofEdit->setPlaceholderText(tr("[\"sibling1_hex\", \"sibling2_hex\", ...]"));
    zkProofMerkleProofEdit->setMaximumHeight(60);
    holderLayout->addWidget(zkProofMerkleProofEdit);

    holderLayout->addWidget(new QLabel(tr("TFR Anchor (if required):")));
    zkTFRAnchorEdit = new QLineEdit();
    zkTFRAnchorEdit->setPlaceholderText(tr("SHA256 hash of off-chain reporting packet (64 hex chars)"));
    zkTFRAnchorEdit->setToolTip(tr("If TFR_ANCHOR_REQUIRED flag is set for this asset, you must provide a SHA256 hash that binds the transaction to off-chain regulatory reporting. This anchor becomes part of the ZK proof's public input. See asset policy for TFR requirements."));
    holderLayout->addWidget(zkTFRAnchorEdit);

    zkGenerateProofButton = new QPushButton(tr("Generate Proof"));
    connect(zkGenerateProofButton, &QPushButton::clicked, this, &TreasuryPage::onGenerateZKProof);
    holderLayout->addWidget(zkGenerateProofButton);

    holderLayout->addWidget(new QLabel(tr("Proof Output (hex):")));
    zkProofOutputEdit = new QTextEdit();
    zkProofOutputEdit->setReadOnly(true);
    zkProofOutputEdit->setMaximumHeight(80);
    holderLayout->addWidget(zkProofOutputEdit);

    zkHolderGroup->setLayout(holderLayout);
    contentLayout->addWidget(zkHolderGroup);

    // Status text
    zkStatusText = new QTextEdit();
    zkStatusText->setReadOnly(true);
    zkStatusText->setMaximumHeight(100);
    contentLayout->addWidget(zkStatusText);

    contentLayout->addStretch();
    zkContentWidget->setLayout(contentLayout);
    layout->addWidget(zkContentWidget);

    layout->addStretch();
    zkComplianceTab->setLayout(layout);
}

void TreasuryPage::setupDistributionTab()
{
    distributionTab = new QWidget();
    QVBoxLayout* layout = new QVBoxLayout(distributionTab);

    // Target asset selection (whose holders will receive distribution)
    QGroupBox* targetGroup = new QGroupBox(tr("Distribution Target"));
    QFormLayout* targetForm = new QFormLayout();

    distTargetAssetCombo = new QComboBox();
    connect(distTargetAssetCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &TreasuryPage::onDistTargetAssetSelected);
    targetForm->addRow(tr("Target Asset:"), distTargetAssetCombo);

    distTargetAssetInfoLabel = new QLabel(tr("Select an asset"));
    distTargetAssetInfoLabel->setWordWrap(true);
    targetForm->addRow(tr("Info:"), distTargetAssetInfoLabel);

    distSettledSupplyLabel = new QLabel(tr("N/A"));
    targetForm->addRow(tr("Settled Supply:"), distSettledSupplyLabel);

    targetGroup->setLayout(targetForm);
    layout->addWidget(targetGroup);

    // Distribution parameters
    QGroupBox* paramsGroup = new QGroupBox(tr("Distribution Parameters"));
    QFormLayout* paramsForm = new QFormLayout();

    // Amount to distribute
    QHBoxLayout* amountLayout = new QHBoxLayout();
    distAmountEdit = new QLineEdit();
    distAmountEdit->setPlaceholderText(tr("Amount to distribute"));
    connect(distAmountEdit, &QLineEdit::textChanged, this, &TreasuryPage::onDistAmountChanged);
    distAmountFormattedLabel = new QLabel();
    amountLayout->addWidget(distAmountEdit);
    amountLayout->addWidget(distAmountFormattedLabel);
    paramsForm->addRow(tr("Amount:"), amountLayout);

    // Distribution asset selector (TSC or other asset)
    QHBoxLayout* distAssetLayout = new QHBoxLayout();
    distAssetCombo = new QComboBox();
    distAssetCombo->addItem(tr("TSC (Native)"), "TSC");
    connect(distAssetCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &TreasuryPage::onDistAssetSelected);
    distAssetLayout->addWidget(distAssetCombo);
    distAssetBalanceLabel = new QLabel(tr("Balance: N/A"));
    distAssetLayout->addWidget(distAssetBalanceLabel);
    paramsForm->addRow(tr("Distribute:"), distAssetLayout);

    // Dust threshold
    distMinDustSpinBox = new QSpinBox();
    distMinDustSpinBox->setRange(1, 1000000);
    distMinDustSpinBox->setValue(1000);
    distMinDustSpinBox->setToolTip(tr("Minimum payment per recipient (satoshis for TSC, raw units for assets)"));
    paramsForm->addRow(tr("Min Dust Threshold:"), distMinDustSpinBox);

    // Max recipients
    distMaxRecipientsSpinBox = new QSpinBox();
    distMaxRecipientsSpinBox->setRange(1, 1000);
    distMaxRecipientsSpinBox->setValue(1000);
    distMaxRecipientsSpinBox->setToolTip(tr("Maximum recipients per transaction"));
    paramsForm->addRow(tr("Max Recipients:"), distMaxRecipientsSpinBox);

    // Snapshot height (optional)
    QHBoxLayout* snapshotLayout = new QHBoxLayout();
    distSnapshotEnableCheckBox = new QCheckBox(tr("Use specific height"));
    distSnapshotEnableCheckBox->setToolTip(tr("Enable to use a historical block height for the UTXO snapshot"));
    distSnapshotHeightSpinBox = new QSpinBox();
    distSnapshotHeightSpinBox->setRange(0, 10000000);
    distSnapshotHeightSpinBox->setValue(0);
    distSnapshotHeightSpinBox->setEnabled(false);
    distSnapshotHeightSpinBox->setToolTip(tr("Block height for UTXO snapshot (leave unchecked to use current tip)"));
    connect(distSnapshotEnableCheckBox, &QCheckBox::toggled, distSnapshotHeightSpinBox, &QSpinBox::setEnabled);
    snapshotLayout->addWidget(distSnapshotEnableCheckBox);
    snapshotLayout->addWidget(distSnapshotHeightSpinBox);
    paramsForm->addRow(tr("Snapshot Height:"), snapshotLayout);

    paramsGroup->setLayout(paramsForm);
    layout->addWidget(paramsGroup);

    // Action buttons
    QHBoxLayout* buttonLayout = new QHBoxLayout();
    distPreviewButton = new QPushButton(tr("Preview Distribution"));
    distPreviewButton->setToolTip(tr("Calculate distribution without broadcasting (dry run)"));
    connect(distPreviewButton, &QPushButton::clicked, this, &TreasuryPage::onDistPreview);
    buttonLayout->addWidget(distPreviewButton);

    distExecuteButton = new QPushButton(tr("Execute Distribution"));
    distExecuteButton->setToolTip(tr("Create and broadcast distribution transaction"));
    distExecuteButton->setEnabled(false);
    connect(distExecuteButton, &QPushButton::clicked, this, &TreasuryPage::onDistExecute);
    buttonLayout->addWidget(distExecuteButton);

    layout->addLayout(buttonLayout);

    // Progress bar
    distProgressBar = new QProgressBar();
    distProgressBar->setVisible(false);
    distProgressBar->setTextVisible(true);
    distProgressBar->setFormat(tr("Scanning UTXO set... %p%"));
    layout->addWidget(distProgressBar);

    // Summary
    distSummaryLabel = new QLabel();
    distSummaryLabel->setWordWrap(true);
    distSummaryLabel->setStyleSheet("QLabel { background: #E8F5E9; padding: 10px; border-radius: 5px; }");
    distSummaryLabel->setVisible(false);
    layout->addWidget(distSummaryLabel);

    // Preview table
    distPreviewTable = new QTableWidget();
    distPreviewTable->setColumnCount(3);
    distPreviewTable->setHorizontalHeaderLabels({tr("Address"), tr("Holdings"), tr("Amount")});
    distPreviewTable->horizontalHeader()->setStretchLastSection(false);
    distPreviewTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    distPreviewTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    distPreviewTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    distPreviewTable->setSortingEnabled(true);
    layout->addWidget(distPreviewTable);

    // Status text
    distStatusText = new QTextEdit();
    distStatusText->setReadOnly(true);
    distStatusText->setMaximumHeight(150);
    layout->addWidget(distStatusText);
}

void TreasuryPage::setupGovernanceTab()
{
    governanceTab = new QWidget();
    QVBoxLayout* layout = new QVBoxLayout(governanceTab);

    // Asset selection
    QHBoxLayout* assetLayout = new QHBoxLayout();
    assetLayout->addWidget(new QLabel(tr("Asset:")));
    govAssetCombo = new QComboBox();
    connect(govAssetCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &TreasuryPage::onGovAssetSelected);
    assetLayout->addWidget(govAssetCombo, 1);
    layout->addLayout(assetLayout);

    // ========== NOSTR-BASED PROPOSAL DISCOVERY (NEW) ==========
    govNostrDiscoveryGroup = new QGroupBox(tr("Nostr-Based Proposal Discovery"));
    QVBoxLayout* nostrLayout = new QVBoxLayout();

    // Bulletin Board Status (one-liner)
    QHBoxLayout* bbStatusLayout = new QHBoxLayout();
    bbStatusLayout->addWidget(new QLabel(tr("Bulletin Board:")));
    govBBStatusLabel = new QLabel(tr("● Not Initialized"));
    govBBStatusLabel->setStyleSheet("QLabel { color: #d32f2f; font-weight: bold; }");
    bbStatusLayout->addWidget(govBBStatusLabel);
    bbStatusLayout->addStretch();
    govLastRefreshLabel = new QLabel(tr("Last refresh: Never"));
    govLastRefreshLabel->setStyleSheet("QLabel { color: #888; font-size: 9pt; }");
    bbStatusLayout->addWidget(govLastRefreshLabel);
    nostrLayout->addLayout(bbStatusLayout);

    // Filter and Refresh
    QHBoxLayout* filterLayout = new QHBoxLayout();
    filterLayout->addWidget(new QLabel(tr("Filter:")));
    govNostrAssetFilterCombo = new QComboBox();
    govNostrAssetFilterCombo->addItem(tr("All Assets"), "");
    connect(govNostrAssetFilterCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &TreasuryPage::onGovNostrRefresh);
    filterLayout->addWidget(govNostrAssetFilterCombo, 1);
    govForceRefreshButton = new QPushButton(tr("Force Refresh"));
    connect(govForceRefreshButton, &QPushButton::clicked, this, &TreasuryPage::onGovNostrForceRefresh);
    filterLayout->addWidget(govForceRefreshButton);
    nostrLayout->addLayout(filterLayout);

    // Proposal List
    govNostrProposalsTable = new QTableWidget();
    govNostrProposalsTable->setColumnCount(7);
    govNostrProposalsTable->setHorizontalHeaderLabels({
        tr("Asset"), tr("Title"), tr("Created"), tr("Expires"), tr("Status"), tr("Verified"), tr("Access")
    });
    govNostrProposalsTable->horizontalHeader()->setStretchLastSection(true);
    govNostrProposalsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    govNostrProposalsTable->setSelectionMode(QAbstractItemView::SingleSelection);
    govNostrProposalsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    govNostrProposalsTable->setMinimumHeight(200);
    connect(govNostrProposalsTable, &QTableWidget::itemSelectionChanged, this, [this]() {
        // Update button visibility based on selected proposal
        int row = govNostrProposalsTable->currentRow();
        if (row >= 0 && govNostrProposalsTable->item(row, 0)) {
            QVariantMap proposal = govNostrProposalsTable->item(row, 0)->data(Qt::UserRole).toMap();
            QString flow_type = proposal.value("flow_type").toString();
            bool isPrivate = (flow_type == "private");
            bool hasTemplatePsbt = proposal.contains("template_psbt") && !proposal.value("template_psbt").toString().isEmpty();
            bool isHolder = !isIssuerMode;

            // Request Private Access button: show for private proposals without access
            govNostrRequestPrivateButton->setVisible(isPrivate && isHolder && !hasTemplatePsbt);

            // Vote button: show for public proposals OR private proposals with access granted
            bool canVote = !isPrivate || hasTemplatePsbt;
            govNostrVoteButton->setVisible(isHolder && canVote);
        } else {
            govNostrRequestPrivateButton->setVisible(false);
            govNostrVoteButton->setVisible(false);
        }
    });
    nostrLayout->addWidget(govNostrProposalsTable);

    // Action Buttons (holder only - vote on proposals)
    QHBoxLayout* nostrButtonLayout = new QHBoxLayout();
    govNostrDetailsButton = new QPushButton(tr("View Details"));
    connect(govNostrDetailsButton, &QPushButton::clicked, this, &TreasuryPage::onGovNostrDetails);
    nostrButtonLayout->addWidget(govNostrDetailsButton);

    govNostrRequestPrivateButton = new QPushButton(tr("Request Private Access"));
    govNostrRequestPrivateButton->setStyleSheet("QPushButton { background-color: #FF9800; color: white; font-weight: bold; }");
    connect(govNostrRequestPrivateButton, &QPushButton::clicked, this, &TreasuryPage::onGovNostrRequestPrivate);
    govNostrRequestPrivateButton->setVisible(false);  // Only shown for private/permissioned proposals
    govNostrRequestPrivateButton->setToolTip(tr("Request access to this private governance proposal via encrypted DM"));
    nostrButtonLayout->addWidget(govNostrRequestPrivateButton);

    govNostrVoteButton = new QPushButton(tr("Vote on Selected"));
    govNostrVoteButton->setStyleSheet("QPushButton { background-color: #4CAF50; color: white; font-weight: bold; }");
    connect(govNostrVoteButton, &QPushButton::clicked, this, &TreasuryPage::onGovNostrVote);
    govNostrVoteButton->setVisible(false);  // Holder mode only
    nostrButtonLayout->addWidget(govNostrVoteButton);

    nostrButtonLayout->addStretch();
    nostrLayout->addLayout(nostrButtonLayout);

    govNostrDiscoveryGroup->setLayout(nostrLayout);
    layout->addWidget(govNostrDiscoveryGroup);

    // ========== ISSUER: PRIVATE ACCESS REQUESTS (PR3) ==========
    govIssuerAccessRequestsGroup = new QGroupBox(tr("Private Governance Access Requests"));
    QVBoxLayout* issuerAccessLayout = new QVBoxLayout();

    QPushButton* processAccessRequestsButton = new QPushButton(tr("Check for New Requests"));
    connect(processAccessRequestsButton, &QPushButton::clicked, this, &TreasuryPage::onGovIssuerProcessAccessRequests);
    issuerAccessLayout->addWidget(processAccessRequestsButton);

    // Auto-approval checkbox
    govAutoApproveCheckbox = new QCheckBox(tr("Auto-approve verified requests"));
    govAutoApproveCheckbox->setToolTip(tr(
        "When enabled, verified access requests are automatically approved and responses sent.\n"
        "When disabled, requests are shown in the table for manual review and approval."));
    // Load saved setting
    QSettings settings;
    govAutoApproveCheckbox->setChecked(settings.value("governance/autoApprove", false).toBool());
    // Save setting when changed
    connect(govAutoApproveCheckbox, &QCheckBox::stateChanged, this, [](int state) {
        QSettings settings;
        settings.setValue("governance/autoApprove", state == Qt::Checked);
    });
    issuerAccessLayout->addWidget(govAutoApproveCheckbox);

    govIssuerAccessRequestsTable = new QTableWidget();
    govIssuerAccessRequestsTable->setColumnCount(7);
    govIssuerAccessRequestsTable->setHorizontalHeaderLabels({
        tr("Proposal"), tr("Holder Pubkey"), tr("UTXO"), tr("Asset Units"), tr("Verified"), tr("Actions"), tr("Status")
    });
    govIssuerAccessRequestsTable->horizontalHeader()->setStretchLastSection(true);
    govIssuerAccessRequestsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    govIssuerAccessRequestsTable->setSelectionMode(QAbstractItemView::SingleSelection);
    govIssuerAccessRequestsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    govIssuerAccessRequestsTable->setMinimumHeight(200);
    issuerAccessLayout->addWidget(govIssuerAccessRequestsTable);

    QLabel* issuerAccessHelpLabel = new QLabel(tr(
        "<i>This table shows holders who have requested access to your private governance proposals.<br>"
        "Click 'Check for New Requests' to poll for incoming DMs and auto-send responses to verified holders.</i>"));
    issuerAccessHelpLabel->setWordWrap(true);
    issuerAccessLayout->addWidget(issuerAccessHelpLabel);

    govIssuerAccessRequestsGroup->setLayout(issuerAccessLayout);
    govIssuerAccessRequestsGroup->setVisible(false);  // Issuer mode only - will be shown in updateVisibilityForMode
    layout->addWidget(govIssuerAccessRequestsGroup);

    // Setup polling timer for Nostr proposals
    // Smart auto-refresh: Only polls when Governance tab is visible, 60s interval
    govNostrPollTimer = new QTimer(this);
    connect(govNostrPollTimer, &QTimer::timeout, this, &TreasuryPage::onGovNostrPollTimer);
    govNostrPollTimer->setInterval(60000);  // 60 seconds (reduced from 30s to minimize overhead)
    // Timer will be started/stopped by onTabChanged when Governance tab becomes visible/hidden

    // ========== PSBT PREPARATION ==========
    QLabel* manualFlowLabel = new QLabel(tr("<b>PSBT Preparation</b>"));
    layout->addWidget(manualFlowLabel);

    // Placeholder for no governance
    govNoGovernanceLabel = new QLabel(tr("This asset does not have governance features."));
    govNoGovernanceLabel->setAlignment(Qt::AlignCenter);
    govNoGovernanceLabel->setStyleSheet("color: #888; font-style: italic; padding: 40px;");
    govNoGovernanceLabel->setVisible(true);  // Start visible (no asset selected yet)
    layout->addWidget(govNoGovernanceLabel);

    // Content widget (to be shown/hidden)
    govContentWidget = new QWidget();
    govContentWidget->setVisible(false);  // Start hidden until asset with governance is selected
    QVBoxLayout* contentLayout = new QVBoxLayout(govContentWidget);

    // Current governance parameters
    QGroupBox* currentGroup = new QGroupBox(tr("Current Governance Parameters"));
    QFormLayout* currentForm = new QFormLayout();
    govQuorumLabel = new QLabel(tr("-"));
    currentForm->addRow(tr("Quorum (bps):"), govQuorumLabel);
    govSettledSupplyLabel = new QLabel(tr("-"));
    currentForm->addRow(tr("Settled Supply:"), govSettledSupplyLabel);
    currentGroup->setLayout(currentForm);
    contentLayout->addWidget(currentGroup);

    // 1. Prepare rotation (Issuer)
    govPrepareGroup = new QGroupBox(tr("1. Prepare Rotation (Issuer)"));
    QVBoxLayout* prepareLayout = new QVBoxLayout();

    QFormLayout* newPolicyForm = new QFormLayout();
    govNewIssuanceCapSpinBox = new QSpinBox();
    govNewIssuanceCapSpinBox->setMinimum(0);
    govNewIssuanceCapSpinBox->setMaximum(INT_MAX);
    govNewIssuanceCapSpinBox->setSpecialValueText(tr("Unlimited"));
    govNewIssuanceCapSpinBox->setSuffix(tr(" coins"));
    newPolicyForm->addRow(tr("New Issuance Cap:"), govNewIssuanceCapSpinBox);

    govNewQuorumSpinBox = new QSpinBox();
    govNewQuorumSpinBox->setMinimum(0);
    govNewQuorumSpinBox->setMaximum(10000);
    govNewQuorumSpinBox->setSuffix(tr(" bps"));
    newPolicyForm->addRow(tr("New Quorum:"), govNewQuorumSpinBox);
    prepareLayout->addLayout(newPolicyForm);

    // Governance Text Rotation
    prepareLayout->addWidget(new QLabel(tr("Rotate Governance Text (optional):")));
    govICUTextEdit = new QTextEdit();
    govICUTextEdit->setPlaceholderText(tr("Enter new governance text here (leave empty to keep current)"));
    govICUTextEdit->setMaximumHeight(100);
    prepareLayout->addWidget(govICUTextEdit);

    prepareLayout->addWidget(new QLabel(tr("Witness Text (optional):")));
    govWitnessTextEdit = new QTextEdit();
    govWitnessTextEdit->setPlaceholderText(tr("Optional witness/metadata text"));
    govWitnessTextEdit->setMaximumHeight(60);
    prepareLayout->addWidget(govWitnessTextEdit);

    QHBoxLayout* visibilityLayout = new QHBoxLayout();
    visibilityLayout->addWidget(new QLabel(tr("Text Visibility:")));
    govICUVisibilityCombo = new QComboBox();
    govICUVisibilityCombo->addItem(tr("Public"), 0);
    govICUVisibilityCombo->addItem(tr("Holder Only"), 1);
    visibilityLayout->addWidget(govICUVisibilityCombo);
    visibilityLayout->addStretch();
    prepareLayout->addLayout(visibilityLayout);

    // Whole-document signature (optional) -- same as the Register form: committed into the witness
    // bundle as an attestation covering canonical_hash.
    prepareLayout->addWidget(new QLabel(tr("Whole-document signature (optional):")));
    govWholeDocAttestEdit = new QTextEdit();
    govWholeDocAttestEdit->setPlaceholderText(tr("Optional: signature payload (QES record JSON / verifiable pointer) over the whole-document hash."));
    govWholeDocAttestEdit->setAcceptRichText(false);
    govWholeDocAttestEdit->setMaximumHeight(80);
    prepareLayout->addWidget(govWholeDocAttestEdit);

    // Designated Clauses designer -- same fidelity as the Register form. Each clause is committed as
    // inline TSC-ICU-CONTEXT-1 context (covered by icu_plain_commit) and can carry a per-clause
    // attestation. Empty = whole-document amendment.
    govClausesGroup = new QGroupBox(tr("Designated Clauses (Optional)"));
    {
        QVBoxLayout* clausesOuter = new QVBoxLayout();
        QLabel* clausesHelp = new QLabel(tr(
            "Clauses the holder must affirm. Each is embedded as a numbered TSC-ICU-CONTEXT-1 entry "
            "the holder affirms individually. The main text above stays free text. Leave empty for a "
            "whole-document amendment."));
        clausesHelp->setWordWrap(true);
        clausesHelp->setStyleSheet("color: #888;");
        clausesOuter->addWidget(clausesHelp);

        govClausesContainer = new QWidget();
        govClausesContainerLayout = new QVBoxLayout(govClausesContainer);
        govClausesContainerLayout->setContentsMargins(0, 0, 0, 0);
        clausesOuter->addWidget(govClausesContainer);

        QHBoxLayout* clauseButtonsRow = new QHBoxLayout();
        govAddClauseButton = new QPushButton(tr("+ Add clause"));
        connect(govAddClauseButton, &QPushButton::clicked, this, &TreasuryPage::onAddGovClauseRow);
        clauseButtonsRow->addWidget(govAddClauseButton);
        clauseButtonsRow->addStretch();
        clausesOuter->addLayout(clauseButtonsRow);

        govClausesSummaryLabel = new QLabel(tr("0 clauses - whole-document amendment"));
        govClausesSummaryLabel->setStyleSheet("color: #888;");
        clausesOuter->addWidget(govClausesSummaryLabel);

        govClausesGroup->setLayout(clausesOuter);
    }
    prepareLayout->addWidget(govClausesGroup);

    // Precheck button and canonical hash display
    QHBoxLayout* precheckLayout = new QHBoxLayout();
    govPrecheckButton = new QPushButton(tr("Precheck Text"));
    connect(govPrecheckButton, &QPushButton::clicked, this, &TreasuryPage::onGovPrecheckICU);
    precheckLayout->addWidget(govPrecheckButton);
    precheckLayout->addStretch();
    prepareLayout->addLayout(precheckLayout);

    QHBoxLayout* hashLayout = new QHBoxLayout();
    hashLayout->addWidget(new QLabel(tr("Canonical Hash:")));
    govCanonicalHashLabel = new QLabel(tr("-"));
    govCanonicalHashLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    govCanonicalHashLabel->setStyleSheet("font-family: monospace; color: #888;");
    hashLayout->addWidget(govCanonicalHashLabel, 1);
    govCopyHashButton = new QPushButton(tr("Copy"));
    govCopyHashButton->setMaximumWidth(60);
    connect(govCopyHashButton, &QPushButton::clicked, this, &TreasuryPage::onGovCopyCanonicalHash);
    hashLayout->addWidget(govCopyHashButton);
    prepareLayout->addLayout(hashLayout);

    govPrepareButton = new QPushButton(tr("Prepare Rotation"));
    connect(govPrepareButton, &QPushButton::clicked, this, &TreasuryPage::onPrepareRotation);
    prepareLayout->addWidget(govPrepareButton);

    QHBoxLayout* psbtHeaderLayout = new QHBoxLayout();
    psbtHeaderLayout->addWidget(new QLabel(tr("Template PSBT:")));
    psbtHeaderLayout->addStretch();
    QPushButton* copyPSBTButton = new QPushButton(tr("Copy PSBT"));
    copyPSBTButton->setMaximumWidth(100);
    connect(copyPSBTButton, &QPushButton::clicked, this, [this]() {
        QString psbt = govPSBTEdit->toPlainText();
        if (!psbt.isEmpty()) {
            QApplication::clipboard()->setText(psbt);
            govStatusText->append(tr("✓ PSBT copied to clipboard"));
        }
    });
    psbtHeaderLayout->addWidget(copyPSBTButton);

    govPublishToNostrButton = new QPushButton(tr("Publish to Network"));
    govPublishToNostrButton->setStyleSheet("QPushButton { background-color: #FF9800; color: white; font-weight: bold; }");
    govPublishToNostrButton->setMaximumWidth(150);
    govPublishToNostrButton->setVisible(false);  // Issuer mode only, shown when PSBT exists
    connect(govPublishToNostrButton, &QPushButton::clicked, this, [this]() {
        LogPrintf("LAMBDA: Publish to Nostr button clicked!\n");
        try {
            onGovNostrPublish();
        } catch (const std::exception& e) {
            LogPrintf("LAMBDA: Caught exception: %s\n", e.what());
            QMessageBox::critical(this, tr("Error"), tr("Exception in onGovNostrPublish: %1").arg(e.what()));
        } catch (...) {
            LogPrintf("LAMBDA: Caught unknown exception\n");
            QMessageBox::critical(this, tr("Error"), tr("Unknown exception in onGovNostrPublish"));
        }
    });
    psbtHeaderLayout->addWidget(govPublishToNostrButton);

    prepareLayout->addLayout(psbtHeaderLayout);

    govPSBTEdit = new QTextEdit();
    govPSBTEdit->setReadOnly(true);
    govPSBTEdit->setMaximumHeight(80);
    govPSBTEdit->setPlaceholderText(tr("PSBT will appear here after clicking 'Prepare Rotation'"));
    prepareLayout->addWidget(govPSBTEdit);
    connect(govPSBTEdit, &QTextEdit::textChanged, this, &TreasuryPage::onGovTemplatePSBTChanged);

    prepareLayout->addWidget(new QLabel(tr("Proposal Summary:")));
    govIssuerProposalSummary = new QTextEdit();
    govIssuerProposalSummary->setReadOnly(true);
    govIssuerProposalSummary->setMaximumHeight(140);
    govIssuerProposalSummary->setStyleSheet("font-family: monospace;");
    govIssuerProposalSummary->setPlaceholderText(tr("Proposal details will appear once a template PSBT is generated."));
    prepareLayout->addWidget(govIssuerProposalSummary);

    govRequiredUnitsLabel = new QLabel(tr("Required units: -"));
    prepareLayout->addWidget(govRequiredUnitsLabel);

    govPrepareGroup->setLayout(prepareLayout);
    contentLayout->addWidget(govPrepareGroup);

    // 2. Cast ballot (Holder)
    govBallotGroup = new QGroupBox(tr("2. Cast Ballot (Holder)"));
    QVBoxLayout* ballotLayout = new QVBoxLayout();

    ballotLayout->addWidget(new QLabel(tr("Template PSBT from Issuer:")));
    govBallotPSBTEdit = new QTextEdit();
    govBallotPSBTEdit->setPlaceholderText(tr("Paste PSBT from issuer here"));
    govBallotPSBTEdit->setMaximumHeight(60);
    ballotLayout->addWidget(govBallotPSBTEdit);
    connect(govBallotPSBTEdit, &QTextEdit::textChanged, this, &TreasuryPage::onGovTemplatePSBTChanged);

    ballotLayout->addWidget(new QLabel(tr("Proposal Summary:")));
    govHolderProposalSummary = new QTextEdit();
    govHolderProposalSummary->setReadOnly(true);
    govHolderProposalSummary->setMaximumHeight(140);
    govHolderProposalSummary->setStyleSheet("font-family: monospace;");
    govHolderProposalSummary->setPlaceholderText(tr("Proposal details will appear once the issuer PSBT is pasted."));
    ballotLayout->addWidget(govHolderProposalSummary);

    ballotLayout->addWidget(new QLabel(tr("Select UTXOs to vote with:")));
    govUTXOTable = new QTableWidget();
    govUTXOTable->setColumnCount(4);
    govUTXOTable->setHorizontalHeaderLabels({tr("Txid"), tr("Vout"), tr("Amount"), tr("Select")});
    govUTXOTable->setMaximumHeight(120);
    ballotLayout->addWidget(govUTXOTable);

    govCastBallotButton = new QPushButton(tr("Cast Ballot"));
    connect(govCastBallotButton, &QPushButton::clicked, this, &TreasuryPage::onCastBallot);
    ballotLayout->addWidget(govCastBallotButton);

    ballotLayout->addWidget(new QLabel(tr("Signed PSBT (send to issuer):")));
    govSignedPSBTEdit = new QTextEdit();
    govSignedPSBTEdit->setReadOnly(true);
    govSignedPSBTEdit->setMaximumHeight(60);
    ballotLayout->addWidget(govSignedPSBTEdit);

    govBallotGroup->setLayout(ballotLayout);
    contentLayout->addWidget(govBallotGroup);

    // 3. Finalize (Issuer)
    govFinalizeGroup = new QGroupBox(tr("3. Finalize && Broadcast (Issuer)"));
    QVBoxLayout* finalizeLayout = new QVBoxLayout();

    // Fetch ballots from Nostr
    QHBoxLayout* fetchBallotsLayout = new QHBoxLayout();
    QLabel* fetchLabel = new QLabel(tr("Select Proposal:"));
    govProposalDropdown = new QComboBox();
    govProposalDropdown->setPlaceholderText(tr("Select a proposal to fetch ballots"));
    govProposalDropdown->setMinimumWidth(300);
    QPushButton* refreshProposalsButton = new QPushButton(tr("Refresh List"));
    connect(refreshProposalsButton, &QPushButton::clicked, this, &TreasuryPage::onRefreshProposalsList);
    QPushButton* fetchBallotsButton = new QPushButton(tr("Fetch Ballots"));
    connect(fetchBallotsButton, &QPushButton::clicked, this, &TreasuryPage::onFetchBallots);
    fetchBallotsLayout->addWidget(fetchLabel);
    fetchBallotsLayout->addWidget(govProposalDropdown, 1);
    fetchBallotsLayout->addWidget(refreshProposalsButton);
    fetchBallotsLayout->addWidget(fetchBallotsButton);
    finalizeLayout->addLayout(fetchBallotsLayout);

    finalizeLayout->addWidget(new QLabel(tr("Signed ballot PSBTs (auto-populated or paste manually):")));
    govBallotListEdit = new QTextEdit();
    govBallotListEdit->setPlaceholderText(tr("Will be populated when you fetch ballots, or paste manually"));
    govBallotListEdit->setMaximumHeight(80);
    finalizeLayout->addWidget(govBallotListEdit);

    QHBoxLayout* mergeLayout = new QHBoxLayout();
    govMergeBallotsButton = new QPushButton(tr("Merge Ballots"));
    connect(govMergeBallotsButton, &QPushButton::clicked, this, &TreasuryPage::onMergeBallots);
    mergeLayout->addWidget(govMergeBallotsButton);

    govBallotsStatusLabel = new QLabel(tr("No ballots loaded"));
    mergeLayout->addWidget(govBallotsStatusLabel);
    mergeLayout->addStretch();
    finalizeLayout->addLayout(mergeLayout);

    finalizeLayout->addWidget(new QLabel(tr("Merged PSBT:")));
    govMergedPSBTEdit = new QTextEdit();
    govMergedPSBTEdit->setPlaceholderText(tr("Resulting PSBT after merging ballots"));
    govMergedPSBTEdit->setMaximumHeight(60);
    finalizeLayout->addWidget(govMergedPSBTEdit);

    govFinalizeButton = new QPushButton(tr("Finalize && Broadcast"));
    connect(govFinalizeButton, &QPushButton::clicked, this, &TreasuryPage::onFinalizeRotation);
    finalizeLayout->addWidget(govFinalizeButton);

    govFinalizeGroup->setLayout(finalizeLayout);
    contentLayout->addWidget(govFinalizeGroup);

    // Status text
    govStatusText = new QTextEdit();
    govStatusText->setReadOnly(true);
    govStatusText->setMaximumHeight(100);
    contentLayout->addWidget(govStatusText);

    contentLayout->addStretch();
    govContentWidget->setLayout(contentLayout);
    layout->addWidget(govContentWidget);

    updateGovernanceProposalSummary(QString());

    layout->addStretch();
    governanceTab->setLayout(layout);
}

// ===== HELPER METHODS =====

QString TreasuryPage::formatAssetAmount(uint64_t units, uint8_t decimals) const
{
    if (decimals == 0) {
        return QString::number(units);
    }

    QString amountStr = QString::number(units);
    while (amountStr.length() <= decimals) {
        amountStr.prepend("0");
    }

    int insertPos = amountStr.length() - decimals;
    amountStr.insert(insertPos, ".");

    // Remove trailing zeros
    while (amountStr.endsWith("0") && amountStr.contains(".")) {
        amountStr.chop(1);
    }
    if (amountStr.endsWith(".")) {
        amountStr.chop(1);
    }

    return amountStr;
}

uint64_t TreasuryPage::parseAssetAmount(const QString& amountStr, uint8_t decimals) const
{
    QString cleaned = amountStr.trimmed();
    if (cleaned.isEmpty()) return 0;

    // Handle decimal point
    QStringList parts = cleaned.split(".");
    QString whole = parts.value(0, "0");
    QString fraction = parts.value(1, "");

    // Pad or truncate fraction to match decimals
    while (fraction.length() < decimals) {
        fraction.append("0");
    }
    if (fraction.length() > decimals) {
        fraction = fraction.left(decimals);
    }

    QString combined = whole + fraction;
    return combined.toULongLong();
}

uint32_t TreasuryPage::getPolicyBitsFromUI() const
{
    uint32_t bits = 0;
    if (regMintAllowedCheckbox->isChecked()) bits |= 0x0001;
    if (regBurnAllowedCheckbox->isChecked()) bits |= 0x0002;
    if (regBurnRequireICUCheckbox->isChecked()) bits |= 0x0004;
    if (regBurnJointRequiredCheckbox->isChecked()) bits |= 0x0008;
    return bits;
}

uint16_t TreasuryPage::getAllowedFamiliesFromUI() const
{
    uint16_t families = 0;
    if (regFamilyP2PKHCheckbox->isChecked()) families |= 0x04;   // P2PKH
    if (regFamilyP2WPKHCheckbox->isChecked()) families |= 0x04;  // P2WPKH
    if (regFamilyP2WSHCheckbox->isChecked()) families |= 0x08;   // P2WSH
    if (regFamilyP2TRCheckbox->isChecked()) families |= 0x10;    // P2TR
    return families;
}

void TreasuryPage::showError(const QString& message)
{
    Q_EMIT this->message(tr("Assets Error"), message, CClientUIInterface::MSG_ERROR);
}

void TreasuryPage::showSuccess(const QString& message)
{
    Q_EMIT this->message(tr("Assets Success"), message, CClientUIInterface::MSG_INFORMATION);
}

bool TreasuryPage::isAddressOwnedByWallet(const QString& address)
{
    if (!walletModel || !clientModel || address.isEmpty()) {
        return false;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(address.toStdString());
        UniValue result = clientModel->node().executeRpc("getaddressinfo", params, walletModel->getWalletName().toStdString());

        if (result.exists("ismine")) {
            return result.find_value("ismine").get_bool();
        }
        return false;
    } catch (...) {
        // If we can't determine, assume not owned for safety
        return false;
    }
}

// ===== SLOT IMPLEMENTATIONS =====

void TreasuryPage::onGenerateAssetId()
{
    // Generate random 32-byte asset ID
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;

    QString assetId;
    for (int i = 0; i < 4; ++i) {
        assetId += QString("%1").arg(dis(gen), 16, 16, QChar('0'));
    }

    regAssetIdEdit->setText(assetId);
}

void TreasuryPage::refreshParentRoots()
{
    // Wallet-controlled roots are populated by the shared asset scan (the same one that fills the
    // mint/burn combos with the ICUs we control), filtered to root tickers (ICU_CHILD.md §7).
    refreshAssetList();
}

void TreasuryPage::onRegModeChanged()
{
    const bool child = regModeCombo && regModeCombo->currentData().toString() == QStringLiteral("child");
    if (regChildControls) regChildControls->setVisible(child);
    if (regTickerLabel) regTickerLabel->setText(child ? tr("Suffix:") : tr("Ticker:"));
    if (regTickerEdit) regTickerEdit->setPlaceholderText(child ? tr("e.g., C150K (3-11 uppercase chars)")
                                                               : tr("e.g., GOLD (3-11 uppercase chars)"));

    // A sponsored child is low-bond: default the bond + unlock down to the consensus child floor
    // (SponsoredChildMinIcuBond = 10,000 sats = 0.0001 TSC) instead of the full root bond. The
    // RPC re-validates against consensus, so this is just a sane visible default.
    if (regBondAmountEdit) regBondAmountEdit->setText(child ? QStringLiteral("0.0001") : QStringLiteral("5.1"));
    if (regUnlockFeesEdit) regUnlockFeesEdit->setText(child ? QStringLiteral("0.0001") : QStringLiteral("5.1"));

    // A sponsored child is a full asset (ICU_CHILD.md §7.1): all the normal registry fields stay
    // available — governance/ICU text, clauses, compliance — exactly as in the standalone flow.

    if (child) refreshParentRoots();
    onRegChildPreviewUpdate();
}

void TreasuryPage::onRegChildPreviewUpdate()
{
    if (!regChildPreviewLabel) return;
    const bool child = regModeCombo && regModeCombo->currentData().toString() == QStringLiteral("child");
    if (!child) { regChildPreviewLabel->clear(); return; }
    const QString root = regParentCombo ? regParentCombo->currentData().toString() : QString();
    const QString suffix = regTickerEdit ? regTickerEdit->text().trimmed().toUpper() : QString();
    regChildPreviewLabel->setText((root.isEmpty() || suffix.isEmpty())
        ? tr("(choose a sponsoring root and enter a suffix)")
        : root + "." + suffix);
}

TreasuryPage::IcuPayloadBuildResult TreasuryPage::buildIcuPayloadFromForm(
    const QString& icuText, int visibility,
    QTextEdit* witnessEdit, const QVector<RegClauseRow>& clauseRows,
    QTextEdit* wholeDocAttest, QTextEdit* statusOut)
{
    IcuPayloadBuildResult r;

    // Witness bundle: version/timestamp/canonical_hash placeholder + optional witness evidence.
    QString witnessText = witnessEdit ? witnessEdit->toPlainText().trimmed() : QString();
    QJsonObject witnessBundle;
    // If the box already holds a witness-bundle JSON object (this widget gets the generated bundle
    // written back after a build, or the user pasted one), reuse it as the base instead of nesting it
    // under "witness" -- otherwise a second Register/Prepare double-wraps the previous JSON and corrupts
    // the payload. Freeform text is wrapped under "witness" as before.
    QJsonParseError wpe{};
    const QJsonDocument wdoc = witnessText.isEmpty()
        ? QJsonDocument()
        : QJsonDocument::fromJson(witnessText.toUtf8(), &wpe);
    if (!witnessText.isEmpty() && wpe.error == QJsonParseError::NoError && wdoc.isObject()) {
        witnessBundle = wdoc.object();          // already a bundle; reuse, refresh managed fields below
        witnessBundle.remove("attestations");   // rebuilt from the current fields below; never keep stale ones
    } else if (!witnessText.isEmpty()) {
        witnessBundle["witness"] = witnessText;  // freeform evidence
    }
    witnessBundle["version"] = "1.0";
    witnessBundle["timestamp"] = QDateTime::currentSecsSinceEpoch();
    witnessBundle["canonical_hash"] = "placeholder";  // filled by buildcanonicalicupayload

    QString witnessJsonStr = QJsonDocument(witnessBundle).toJson(QJsonDocument::Compact);
    UniValue witnessUniValue;
    if (!witnessUniValue.read(witnessJsonStr.toStdString())) {
        showError(tr("Failed to convert witness bundle to UniValue"));
        return r;
    }

    // Option A inline context: hand the human body + ordered clause texts to buildcanonicalicupayload
    // via icu_clauses/icu_acceptance; the node embeds the authoritative TSC-ICU-CONTEXT-1 block INSIDE
    // canonical_text (covered by icu_plain_commit) and returns the parsed "context" + ordered "body_keys".
    UniValue clausesArr(UniValue::VARR);
    int clauseCount = 0;
    for (const RegClauseRow& row : clauseRows) {
        if (!row.textEdit) continue;
        const QString text = row.textEdit->toPlainText().trimmed();
        if (text.isEmpty()) continue;
        clausesArr.push_back(text.toStdString());
        ++clauseCount;
    }
    const bool hasClauses = clauseCount > 0;
    const std::string acceptanceMode = "required";

    auto buildPayload = [&](const UniValue& witnessArg) -> UniValue {
        UniValue p(UniValue::VARR);
        p.push_back(icuText.toStdString());
        p.push_back(witnessArg);
        p.push_back(visibility);
        if (hasClauses) {
            p.push_back(UniValue(UniValue::VNULL));  // [3] legacy icu_context: unused under Option A
            p.push_back(clausesArr);                 // [4] icu_clauses
            p.push_back(acceptanceMode);             // [5] icu_acceptance
        }
        return clientModel->node().executeRpc("buildcanonicalicupayload", p, walletModel->getWalletName().toStdString());
    };

    UniValue payloadResult;
    try {
        payloadResult = buildPayload(witnessUniValue);
    } catch (const std::exception& e) {
        showError(tr("Failed to build ICU payload: %1").arg(QString::fromStdString(e.what())));
        return r;
    }

    std::string icu_payload_plain = payloadResult["icu_payload_plain"].get_str();
    std::string canonical_hash = payloadResult["canonical_hash"].get_str();
    std::string witness_hash = payloadResult["witness_hash"].get_str();
    int payload_size = payloadResult["payload_size"].getInt<int>();

    // Secondary witness attestations (anchor, not embed): whole-doc (covers = canonical_hash) and/or
    // per-clause (covers = that clause's body_key, clause-row order). Evidence only; NOT the clause store.
    {
        QStringList clauseBodyKeys;
        if (payloadResult.exists("body_keys") && payloadResult["body_keys"].isArray()) {
            const UniValue& bk = payloadResult["body_keys"];
            for (size_t i = 0; i < bk.size(); ++i) {
                if (bk[i].isStr()) clauseBodyKeys << QString::fromStdString(bk[i].get_str());
            }
        }

        QJsonArray attestations;
        auto addAtt = [&](const QString& covers, const QString& rawPayload) {
            const QString payload = rawPayload.trimmed();
            if (payload.isEmpty()) return;
            QJsonObject att;
            att["covers"] = covers;
            QJsonParseError pe;
            const QJsonDocument pd = QJsonDocument::fromJson(payload.toUtf8(), &pe);
            if (pe.error == QJsonParseError::NoError && pd.isObject()) att["signature"] = pd.object();
            else if (pe.error == QJsonParseError::NoError && pd.isArray()) att["signature"] = pd.array();
            else att["signature"] = payload;  // opaque string (locator / base64 / etc.)
            attestations.append(att);
        };
        if (wholeDocAttest) addAtt(QString::fromStdString(canonical_hash), wholeDocAttest->toPlainText());
        int ci = 0;  // index into clauseBodyKeys; mirrors the non-empty clause iteration above
        for (const RegClauseRow& row : clauseRows) {
            if (!row.textEdit || row.textEdit->toPlainText().trimmed().isEmpty()) continue;
            if (ci < clauseBodyKeys.size() && row.attestEdit) addAtt(clauseBodyKeys.at(ci), row.attestEdit->toPlainText());
            ++ci;
        }

        if (!attestations.isEmpty()) {
            // Seal the attestation-bearing witness by rebuilding (canonical_hash depends only on the
            // inline-context text, so it is stable across this rebuild).
            witnessBundle["attestations"] = attestations;
            const QString wjs = QJsonDocument(witnessBundle).toJson(QJsonDocument::Compact);
            if (!witnessUniValue.read(wjs.toStdString())) {
                showError(tr("Internal error: failed to encode witness attestations"));
                return r;
            }
            try {
                payloadResult = buildPayload(witnessUniValue);
            } catch (const std::exception& e) {
                showError(tr("Node rejected the ICU payload (witness): %1").arg(QString::fromStdString(e.what())));
                return r;
            }
            icu_payload_plain = payloadResult["icu_payload_plain"].get_str();
            canonical_hash = payloadResult["canonical_hash"].get_str();
            witness_hash = payloadResult["witness_hash"].get_str();
            payload_size = payloadResult["payload_size"].getInt<int>();
        }

        // Save the completed witness bundle back to the text field so the user can see/save it.
        if (payloadResult.exists("witness_bundle") && payloadResult["witness_bundle"].isObject() && witnessEdit) {
            witnessEdit->setPlainText(QString::fromStdString(payloadResult["witness_bundle"].write(2)));
        }
        if (statusOut && hasClauses) {
            statusOut->append(tr("  Inline context committed: %1 designated clause(s) (acceptance: %2)")
                                      .arg(clauseCount).arg(QString::fromStdString(acceptanceMode)));
        }
        if (statusOut && !attestations.isEmpty()) {
            statusOut->append(tr("  Witness attestations (secondary evidence): %1").arg(attestations.size()));
        }
    }

    r.ok = true;
    r.payloadPlain = QString::fromStdString(icu_payload_plain);
    r.canonicalHash = QString::fromStdString(canonical_hash);
    r.witnessHash = QString::fromStdString(witness_hash);
    r.payloadSize = payload_size;
    return r;
}

// ============================================================================
// Option-series create/issue wizard (Treasury "Option Series" tab)
// ============================================================================

static const qint64 kMaxMoneySats = 2100000000000000LL;  // 21,000,000 TSC * 1e8 (== consensus MAX_MONEY)

// Parse a TSC amount string ("1.5", "30", "0.00010000") to exact sats with NO floating point. Rejects
// non-digits, more than 8 decimals, and amounts above MAX_MONEY. Allows zero (the caller decides if zero is OK).
static bool ParseTscToSats(const QString& in, qint64& out)
{
    const QString s = in.trimmed();
    if (s.isEmpty()) return false;
    const int dot = s.indexOf(QChar('.'));
    const QString ip = (dot < 0) ? s : s.left(dot);
    QString fp = (dot < 0) ? QString() : s.mid(dot + 1);
    if (ip.isEmpty() && fp.isEmpty()) return false;
    if (fp.length() > 8) return false;
    auto allDigits = [](const QString& x) {
        for (const QChar& c : x) if (c < QChar('0') || c > QChar('9')) return false;
        return true;
    };
    if (!allDigits(ip) || !allDigits(fp)) return false;
    bool ok = true;
    const qlonglong whole = ip.isEmpty() ? 0 : ip.toLongLong(&ok);
    if (!ip.isEmpty() && !ok) return false;
    if (whole < 0 || whole > 21000000) return false;        // guards the multiply below from overflow
    fp = fp.leftJustified(8, QChar('0'));
    const qlonglong frac = fp.isEmpty() ? 0 : fp.toLongLong(&ok);
    if (!fp.isEmpty() && !ok) return false;
    const qint64 sats = whole * 100000000LL + frac;
    if (sats > kMaxMoneySats) return false;                 // 21000000.00000001 must NOT slip past the GUI
    out = sats;
    return true;
}

static QString FormatSats(qint64 sats)
{
    return QString("%1.%2").arg(sats / 100000000LL).arg(sats % 100000000LL, 8, 10, QChar('0'));
}

// Parse a human strike in tokens/sec (network inference throughput), accepting an optional SI suffix
// (k/M/G/T/P) and a trailing "tok/s" — e.g. "5G", "5.5 T", "750M tok/s". Mirrors the difficulty builder's
// parser so the option strike speaks the SAME human unit; the consensus nBits is derived via
// wallet::DifficultyTokensPerSecToNBits. Sets *ok on a positive parse.
static double ParseTokensPerSec(QString text, bool* ok)
{
    if (ok) *ok = false;
    QString s = text.trimmed();
    s.remove(QStringLiteral("tok/s"), Qt::CaseInsensitive);
    s.remove(QStringLiteral("/s"), Qt::CaseInsensitive);
    s = s.trimmed();
    if (s.isEmpty()) return 0.0;
    double mult = 1.0;
    switch (s.at(s.size() - 1).toLower().toLatin1()) {
        case 'k': mult = 1e3; s.chop(1); break;
        case 'm': mult = 1e6; s.chop(1); break;
        case 'g': mult = 1e9; s.chop(1); break;
        case 't': mult = 1e12; s.chop(1); break;
        case 'p': mult = 1e15; s.chop(1); break;
        default: break;
    }
    bool parsed = false;
    const double v = s.trimmed().toDouble(&parsed);
    if (!parsed || !(v > 0.0)) return 0.0;
    if (ok) *ok = true;
    return v * mult;
}

// The active chain name ("main"/"test"/"regtest"...), used to scope drafts to the context they were made
// in. Empty on failure (treated as "do not match" so a stale draft can't restore into the wrong chain).
static QString CurrentChainName(ClientModel* cm)
{
    if (!cm) return QString();
    try {
        UniValue r = cm->node().executeRpc("getblockchaininfo", UniValue(UniValue::VARR), /*walletName=*/"");
        return r.exists("chain") ? QString::fromStdString(r["chain"].get_str()) : QString();
    } catch (...) {
        return QString();
    }
}

void TreasuryPage::setupVerifyOptionTab()
{
    verifyOptionTab = new QWidget();
    QVBoxLayout* layout = new QVBoxLayout(verifyOptionTab);

    QLabel* intro = new QLabel(tr(
        "<b>Verify an option series before you buy.</b> Enter a series ticker (ROOT.SUFFIX) or its asset id. "
        "This re-derives the N backing vaults from the descriptor published in the series' ICU and scans the "
        "UTXO set — confirming the series is authentic AND fully collateralized on chain. No wallet record is "
        "needed; this works for ANY series, not just ones you issued.<br/><br/>"
        "<b>Hold units of a matured series?</b> Verify it, then use <b>Settle → Redeem</b> below to exercise a "
        "lot end-to-end (no issuer record required)."));
    intro->setWordWrap(true);
    layout->addWidget(intro);

    QHBoxLayout* row = new QHBoxLayout();
    row->addWidget(new QLabel(tr("Ticker / asset id:")));
    verifyOptIdEdit = new QLineEdit();
    verifyOptIdEdit->setPlaceholderText(tr("e.g. ACME.JUL26  or  a 64-hex asset id"));
    row->addWidget(verifyOptIdEdit, 1);
    verifyOptButton = new QPushButton(tr("Verify backing"));
    row->addWidget(verifyOptButton);
    layout->addLayout(row);

    verifyOptResult = new QTextEdit();
    verifyOptResult->setReadOnly(true);
    layout->addWidget(verifyOptResult, 1);

    // Holder exercise: once a series verifies, its terms are recovered from the on-chain descriptor, so a
    // buyer who holds units (but never recorded the series) can exercise an ITM lot end-to-end here — no
    // issuer record. Two steps, mirroring the issuer Option Series tab: (1) Settle lot builds the keeper
    // settlement (signatureless covenant; permissionless) and, if the lot is ITM, funds its pot; on success
    // the pot outpoint is auto-filled below. (2) Redeem pot retires one of your units and sweeps that pot.
    QGroupBox* redeemGroup = new QGroupBox(tr("Exercise a lot you hold (settle → redeem)"));
    QHBoxLayout* rg = new QHBoxLayout();
    rg->addWidget(new QLabel(tr("Lot:")));
    verifyOptLotSpin = new QSpinBox();
    verifyOptLotSpin->setRange(0, 0);
    rg->addWidget(verifyOptLotSpin);
    verifyOptSettleButton = new QPushButton(tr("1. Settle lot"));
    verifyOptSettleButton->setToolTip(tr("Build and broadcast the keeper settlement for this lot (permissionless). "
                                         "Once the fixing height is buried and the settle-lock is open; if the lot is "
                                         "ITM the funded pot is filled in below for you to redeem."));
    rg->addWidget(verifyOptSettleButton);
    rg->addWidget(new QLabel(tr("Pot:")));
    verifyOptPotEdit = new QLineEdit();
    verifyOptPotEdit->setPlaceholderText(tr("settlement pot outpoint  txid:vout  (auto-filled by Settle, or paste one)"));
    rg->addWidget(verifyOptPotEdit, 1);
    verifyOptRedeemButton = new QPushButton(tr("2. Redeem pot"));
    rg->addWidget(verifyOptRedeemButton);
    redeemGroup->setLayout(rg);
    layout->addWidget(redeemGroup);

    verifyOptLotSpin->setEnabled(false);
    verifyOptSettleButton->setEnabled(false);
    verifyOptPotEdit->setEnabled(false);
    verifyOptRedeemButton->setEnabled(false);

    connect(verifyOptButton, &QPushButton::clicked, this, &TreasuryPage::onVerifyOptionById);
    connect(verifyOptIdEdit, &QLineEdit::returnPressed, this, &TreasuryPage::onVerifyOptionById);
    connect(verifyOptSettleButton, &QPushButton::clicked, this, &TreasuryPage::onVerifyOptionSettle);
    connect(verifyOptRedeemButton, &QPushButton::clicked, this, &TreasuryPage::onVerifyOptionRedeem);
}

void TreasuryPage::onVerifyOptionById()
{
    if (!walletModel) { showError(tr("Wallet not ready")); return; }

    // Any new verify attempt invalidates the previously-recovered series. Clear it up front so a FAILED (or
    // different) verify can never leave the redeem panel armed with the prior series' terms.
    m_verifyOptTermsJson.clear();
    verifyOptPotEdit->clear();
    verifyOptLotSpin->setEnabled(false);
    verifyOptSettleButton->setEnabled(false);
    verifyOptPotEdit->setEnabled(false);
    verifyOptRedeemButton->setEnabled(false);

    const QString ident = verifyOptIdEdit->text().trimmed();
    if (ident.isEmpty()) { showError(tr("Enter a ticker or asset id to verify.")); return; }

    verifyOptResult->append(tr("Verifying %1 …").arg(ident));
    WalletModel::OptionSeriesBackingResult r = walletModel->optionSeriesVerifyById(ident);
    if (!r.success) {
        verifyOptResult->append(tr("✗ Could not verify: %1\n").arg(r.error));
        return;
    }
    const QString headline = r.verified
        ? tr("✓ SAFE — authentic and fully backed on chain")
        : tr("✗ NOT VERIFIED — do not rely on this series");
    QStringList lines;
    lines << headline;
    if (!r.ticker.isEmpty()) lines << tr("  ticker: %1").arg(r.ticker);
    lines << tr("  asset id: %1").arg(r.resolved_asset_id);
    lines << tr("  authentic: %1").arg(r.authentic ? tr("yes") : tr("no — descriptor does not match this id"));
    lines << tr("  registry invariants: %1").arg(r.invariants_ok ? tr("ok") : tr("FAIL"));
    lines << tr("  issued units: %1").arg(r.issued_total);
    lines << tr("  vaults funded: %1 / %2").arg(r.vaults_funded).arg(r.vaults_expected);
    if (!r.reason.isEmpty()) lines << tr("  note: %1").arg(r.reason);
    verifyOptResult->append(lines.join('\n') + "\n");

    // Recovered the on-chain terms -> a holder can now redeem a pot for units they own (no record needed).
    m_verifyOptTermsJson = r.terms_json;
    const bool canRedeem = r.authentic && !r.terms_json.isEmpty();
    if (canRedeem && r.lot_count > 0) verifyOptLotSpin->setRange(0, r.lot_count - 1);
    verifyOptLotSpin->setEnabled(canRedeem);
    verifyOptSettleButton->setEnabled(canRedeem);
    verifyOptPotEdit->setEnabled(canRedeem);
    verifyOptRedeemButton->setEnabled(canRedeem);
}

void TreasuryPage::onVerifyOptionSettle()
{
    if (!walletModel) { showError(tr("Wallet not ready")); return; }
    if (m_verifyOptTermsJson.isEmpty()) { showError(tr("Verify a series first to recover its terms.")); return; }
    const int lot = verifyOptLotSpin->value();

    QMessageBox box(TopLevelDialogParent(this));
    box.setWindowTitle(tr("Confirm Settlement"));
    box.setText(tr("Settle lot %1 of this series?\n\nThis builds the keeper settlement and broadcasts it — anyone "
                   "may do it, no issuer record needed. It only succeeds once the fixing height is buried and the "
                   "settle-lock CLTV is open. If the lot is in-the-money, the funded pot is filled in below so you "
                   "can redeem it with the units you hold.").arg(lot));
    box.setIcon(QMessageBox::Question);
    box.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
    box.setDefaultButton(QMessageBox::No);
    if (box.exec() != QMessageBox::Yes) return;

    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if (!ctx.isValid()) { showError(tr("Wallet locked. Please unlock to settle.")); return; }

    // Same model call the issuer Option Series tab uses: build_settlement -> difficulty.finalize_settlement
    // -> broadcast, returning the funded pot outpoint on an ITM settlement.
    WalletModel::OptionSeriesActionResult r = walletModel->optionSeriesSettle(m_verifyOptTermsJson, lot);
    if (!r.success) { verifyOptResult->append(tr("✗ Settle failed: %1").arg(r.error)); showError(r.error); return; }
    verifyOptResult->append(tr("✓ %1 (txid %2)").arg(r.detail).arg(r.txid));
    if (!r.pot_outpoint.isEmpty()) {
        verifyOptPotEdit->setText(r.pot_outpoint);
        verifyOptResult->append(tr("  → ITM: funded pot %1 filled in; click '2. Redeem pot' to claim it.").arg(r.pot_outpoint));
    } else {
        verifyOptResult->append(tr("  → Lot settled OTM (no pot for the holder — collateral returned to the writer)."));
    }
}

void TreasuryPage::onVerifyOptionRedeem()
{
    if (!walletModel) { showError(tr("Wallet not ready")); return; }
    if (m_verifyOptTermsJson.isEmpty()) { showError(tr("Verify a series first to recover its terms.")); return; }
    const int lot = verifyOptLotSpin->value();
    const QString pot = verifyOptPotEdit->text().trimmed();
    if (pot.isEmpty() || !pot.contains(':')) { showError(tr("Enter the settlement pot outpoint as txid:vout.")); return; }

    QMessageBox box(TopLevelDialogParent(this));
    box.setWindowTitle(tr("Confirm Redemption"));
    box.setText(tr("Redeem pot %1 for lot %2?\n\nThis retires one of your option units to the lot sink and sweeps "
                   "the pot value to you.").arg(pot).arg(lot));
    box.setIcon(QMessageBox::Question);
    box.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
    box.setDefaultButton(QMessageBox::No);
    if (box.exec() != QMessageBox::Yes) return;

    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if (!ctx.isValid()) { showError(tr("Wallet locked. Please unlock to redeem.")); return; }

    WalletModel::OptionSeriesActionResult r = walletModel->optionSeriesRedeem(m_verifyOptTermsJson, lot, pot);
    if (!r.success) { verifyOptResult->append(tr("✗ Redeem failed: %1").arg(r.error)); showError(r.error); return; }
    verifyOptResult->append(tr("✓ %1 (txid %2)").arg(r.detail).arg(r.txid));
    verifyOptPotEdit->clear();
}

void TreasuryPage::setupOptionSeriesTab()
{
    optionSeriesTab = new QWidget();
    QVBoxLayout* tabLayout = new QVBoxLayout(optionSeriesTab);
    QScrollArea* scroll = new QScrollArea();
    scroll->setWidgetResizable(true);
    QWidget* content = new QWidget();
    QVBoxLayout* outer = new QVBoxLayout(content);

    QLabel* intro = new QLabel(tr(
        "<b>Tokenized option series.</b> Register the series shell as a sponsored child under one of your root "
        "namespaces, then — once it confirms — issue it (mint N units to the writer and fund the N lot vaults), "
        "then record it in this wallet. Each step needs the previous one confirmed on chain, so this is a "
        "guided three-step flow, not one atomic action."));
    intro->setWordWrap(true);
    outer->addWidget(intro);

    QGroupBox* termsGroup = new QGroupBox(tr("Series terms"));
    QFormLayout* form = new QFormLayout();

    optParentCombo = new QComboBox();
    optParentCombo->setToolTip(tr("A wallet-controlled root namespace to sponsor the series child under."));
    form->addRow(tr("Sponsoring root:"), optParentCombo);

    optDirectionCombo = new QComboBox();
    optDirectionCombo->addItem(tr("Call — long holder profits as difficulty rises above strike"), 0);
    optDirectionCombo->addItem(tr("Put — long holder profits as difficulty falls below strike"), 1);
    optDirectionCombo->setToolTip(tr("Call: the writer is short (holder long a call). Put: the writer is long "
                                     "(holder long a put). This changes the descriptor, asset id and vault addresses."));
    form->addRow(tr("Option kind:"), optDirectionCombo);

    optSuffixEdit = new QLineEdit();
    optSuffixEdit->setPlaceholderText(tr("e.g. JUL26 (3-11 uppercase chars; the ticker becomes ROOT.SUFFIX)"));
    form->addRow(tr("Suffix:"), optSuffixEdit);

    optTickerPreviewLabel = new QLabel(tr("(choose a root + suffix)"));
    optTickerPreviewLabel->setStyleSheet("color: #888;");
    form->addRow(tr("Ticker:"), optTickerPreviewLabel);

    {
        QWidget* w = new QWidget();
        QHBoxLayout* h = new QHBoxLayout(w); h->setContentsMargins(0, 0, 0, 0);
        optWriterEdit = new QLineEdit();
        optWriterEdit->setPlaceholderText(tr("wallet bech32m address or 64-hex x-only key"));
        optWriterEdit->setToolTip(tr("The writer/issuer. For self-issuance this MUST be an address this wallet "
                                     "controls, so it can sign issuance, settlement and buy-backs."));
        optWriterGenButton = new QPushButton(tr("New address"));
        h->addWidget(optWriterEdit, 1); h->addWidget(optWriterGenButton);
        form->addRow(tr("Writer:"), w);
    }

    optStrikeTpsEdit = new QLineEdit();
    optStrikeTpsEdit->setPlaceholderText(tr("e.g. 5G  or  750M tok/s"));
    optStrikeTpsEdit->setToolTip(tr("Strike difficulty as network inference throughput (tokens/sec). Accepts "
                                    "k / M / G / T / P suffixes; the canonical consensus nBits is derived below."));
    form->addRow(tr("Strike (tok/s):"), optStrikeTpsEdit);

    optStrikeNbitsLabel = new QLabel(tr("(enter a strike)"));
    optStrikeNbitsLabel->setStyleSheet("color:#888;");
    optStrikeNbitsLabel->setToolTip(tr("The canonical compact difficulty target (nBits) committed in the descriptor, derived from the tok/s strike."));
    form->addRow(tr("→ nBits:"), optStrikeNbitsLabel);

    // Fixing as a DURATION from now (the option observes difficulty after this much time has elapsed).
    {
        QWidget* w = new QWidget();
        QHBoxLayout* h = new QHBoxLayout(w); h->setContentsMargins(0, 0, 0, 0);
        optFixingDurationSpin = new QSpinBox();
        optFixingDurationSpin->setRange(1, 100000);
        optFixingDurationSpin->setValue(30);
        optFixingUnitCombo = new QComboBox();
        optFixingUnitCombo->addItem(tr("days"), 1);
        optFixingUnitCombo->addItem(tr("weeks"), 7);
        optFixingUnitCombo->addItem(tr("months"), 30);
        optFixingUnitCombo->addItem(tr("years"), 365);
        h->addWidget(optFixingDurationSpin, 1);
        h->addWidget(optFixingUnitCombo);
        optFixingDurationSpin->setToolTip(tr("When the option's difficulty is observed, measured from now. "
                                             "The absolute fixing block height is computed below (144 blocks/day)."));
        form->addRow(tr("Fix in:"), w);
    }
    optFixingHeightLabel = new QLabel(tr("(connecting…)"));
    optFixingHeightLabel->setStyleSheet("color:#888;");
    form->addRow(tr("→ fixing block:"), optFixingHeightLabel);

    // Settle-lock kept as a block-count SAFETY gap past fixing (>= the consensus maturity depth).
    optSettleWindowSpin = new QSpinBox();
    optSettleWindowSpin->setRange(100, 100000);   // >= DIFFCFD_MATURITY_DEPTH
    optSettleWindowSpin->setValue(110);
    optSettleWindowSpin->setToolTip(tr("Settlement window in BLOCKS after fixing before a lot may settle. Must be "
                                       "at least the consensus maturity depth (100 blocks ≈ 16.7h) so the fixing is buried."));
    form->addRow(tr("Settle window (blocks):"), optSettleWindowSpin);
    optSettleHeightLabel = new QLabel();
    optSettleHeightLabel->setStyleSheet("color:#888;");
    form->addRow(tr("→ settle block:"), optSettleHeightLabel);

    optLeverageEdit = new QLineEdit(QStringLiteral("1.0"));
    optLeverageEdit->setToolTip(tr("Leverage multiplier. A favourable difficulty move of m%% past strike pays "
                                   "leverage × m%% of the lot collateral per unit (capped at the collateral)."));
    form->addRow(tr("Leverage (×):"), optLeverageEdit);

    optLotImEdit = new QLineEdit();
    optLotImEdit->setPlaceholderText(tr("collateral per lot, TSC (e.g. 1.0)"));
    optLotImEdit->setToolTip(tr("Collateral backing each lot. This is ALSO the maximum payout a holder can get per unit."));
    form->addRow(tr("Lot collateral / max payout (TSC):"), optLotImEdit);

    optLotCountSpin = new QSpinBox();
    optLotCountSpin->setRange(1, 120);   // headroom below the per-tx covenant-output cap
    optLotCountSpin->setValue(10);
    optLotCountSpin->setToolTip(tr("N — the number of fungible units and backing vaults."));
    form->addRow(tr("Lot count (N):"), optLotCountSpin);

    // Worked payoff preview: TSC per unit for an example difficulty move.
    {
        QWidget* w = new QWidget();
        QHBoxLayout* h = new QHBoxLayout(w); h->setContentsMargins(0, 0, 0, 0);
        optExampleMoveSpin = new QSpinBox();
        optExampleMoveSpin->setRange(1, 1000);
        optExampleMoveSpin->setValue(10);
        optExampleMoveSpin->setSuffix(tr(" %% move"));
        h->addWidget(optExampleMoveSpin);
        h->addStretch();
        form->addRow(tr("Payoff example:"), w);
    }
    optPayoffLabel = new QLabel(tr("(enter leverage + lot collateral)"));
    optPayoffLabel->setWordWrap(true);
    optPayoffLabel->setStyleSheet("color:#9ad;");
    form->addRow(QString(), optPayoffLabel);

    optRefPremiumEdit = new QLineEdit(QStringLiteral("0.0"));
    optRefPremiumEdit->setToolTip(tr("Display/listing premium only — does NOT move any on-chain address."));
    form->addRow(tr("Reference premium (TSC):"), optRefPremiumEdit);

    {
        QWidget* w = new QWidget();
        QHBoxLayout* h = new QHBoxLayout(w); h->setContentsMargins(0, 0, 0, 0);
        optSaltEdit = new QLineEdit();
        optSaltEdit->setPlaceholderText(tr("64 hex (auto-generated if left blank)"));
        optSaltGenButton = new QPushButton(tr("Generate"));
        h->addWidget(optSaltEdit, 1); h->addWidget(optSaltGenButton);
        form->addRow(tr("Series salt:"), w);
    }

    optBondEdit = new QLineEdit(QStringLiteral("0.0001"));
    optBondEdit->setToolTip(tr("Child ICU bond (TSC). The low default is the consensus child floor."));
    form->addRow(tr("Child bond (TSC):"), optBondEdit);

    optFeeRateEdit = new QLineEdit(QStringLiteral("5"));
    form->addRow(tr("Fee rate (sat/vB):"), optFeeRateEdit);

    optAssetIdLabel = new QLabel(tr("(derive to preview)"));
    optAssetIdLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    optAssetIdLabel->setStyleSheet("font-family: monospace;");
    optAssetIdLabel->setWordWrap(true);
    form->addRow(tr("Asset ID:"), optAssetIdLabel);

    termsGroup->setLayout(form);
    outer->addWidget(termsGroup);

    QHBoxLayout* btns = new QHBoxLayout();
    optDeriveButton = new QPushButton(tr("Preview"));
    optRegisterButton = new QPushButton(tr("1. Register series"));
    optIssueButton = new QPushButton(tr("2. Issue series"));
    optRecordButton = new QPushButton(tr("3. Record issue"));
    optResetButton = new QPushButton(tr("New series"));
    optResumeButton = new QPushButton(tr("Resume draft"));
    optResumeButton->setToolTip(tr("Restore an in-progress series (terms, salt and issuance txid) saved on this machine."));
    btns->addWidget(optDeriveButton);
    btns->addWidget(optRegisterButton);
    btns->addWidget(optIssueButton);
    btns->addWidget(optRecordButton);
    btns->addWidget(optResetButton);
    btns->addWidget(optResumeButton);
    outer->addLayout(btns);

    optStatusText = new QTextEdit();
    optStatusText->setReadOnly(true);
    optStatusText->setMaximumHeight(170);
    outer->addWidget(optStatusText);

    // Recorded series + on-chain backing verification (slice 3).
    QGroupBox* listGroup = new QGroupBox(tr("Recorded series"));
    QVBoxLayout* listLayout = new QVBoxLayout();
    QHBoxLayout* listBtns = new QHBoxLayout();
    optRefreshListButton = new QPushButton(tr("Refresh list"));
    optVerifyBackingButton = new QPushButton(tr("Verify backing"));
    optVerifyBackingButton->setToolTip(tr("Re-derive the N lot vaults from the series' published descriptor and scan "
                                          "the UTXO set: confirms the series is authentic and each vault is funded."));
    optVerifyBackingButton->setEnabled(false);
    listBtns->addWidget(optRefreshListButton);
    listBtns->addWidget(optVerifyBackingButton);
    listBtns->addStretch();
    listLayout->addLayout(listBtns);
    optSeriesTable = new QTableWidget(0, 4);
    optSeriesTable->setHorizontalHeaderLabels({tr("Asset ID"), tr("Lots"), tr("Issue tx"), tr("Backing")});
    optSeriesTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    optSeriesTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    optSeriesTable->setSelectionMode(QAbstractItemView::SingleSelection);
    optSeriesTable->horizontalHeader()->setStretchLastSection(true);
    optSeriesTable->setMinimumHeight(150);
    listLayout->addWidget(optSeriesTable);

    // Lifecycle actions on the selected series (settle / buy back a lot; redeem a settlement pot).
    QHBoxLayout* lotRow = new QHBoxLayout();
    lotRow->addWidget(new QLabel(tr("Lot:")));
    optLotIndexSpin = new QSpinBox();
    optLotIndexSpin->setRange(0, 0);
    optLotIndexSpin->setToolTip(tr("Which lot of the selected series to act on."));
    lotRow->addWidget(optLotIndexSpin);
    optSettleButton = new QPushButton(tr("Settle lot"));
    optSettleButton->setToolTip(tr("Keeper settlement of the lot vault once its fixing is buried and the CLTV is open."));
    optBuybackButton = new QPushButton(tr("Buy back lot"));
    optBuybackButton->setToolTip(tr("Writer early-unwind: spend the lot vault, retire one repurchased unit, reclaim the collateral."));
    lotRow->addWidget(optSettleButton);
    lotRow->addWidget(optBuybackButton);
    lotRow->addStretch();
    listLayout->addLayout(lotRow);

    QHBoxLayout* redeemRow = new QHBoxLayout();
    redeemRow->addWidget(new QLabel(tr("Pot:")));
    optRedeemPotEdit = new QLineEdit();
    optRedeemPotEdit->setPlaceholderText(tr("settlement pot outpoint  txid:vout"));
    optRedeemPotEdit->setToolTip(tr("A funded ITM settlement pot for the selected lot; one option unit is retired to sweep it."));
    redeemRow->addWidget(optRedeemPotEdit, 1);
    optRedeemButton = new QPushButton(tr("Redeem pot"));
    redeemRow->addWidget(optRedeemButton);
    listLayout->addLayout(redeemRow);

    optSettleButton->setEnabled(false);
    optBuybackButton->setEnabled(false);
    optRedeemButton->setEnabled(false);

    listGroup->setLayout(listLayout);
    outer->addWidget(listGroup);
    outer->addStretch();

    scroll->setWidget(content);
    tabLayout->addWidget(scroll);

    // Step gating: only register is available until a series is registered + confirmed.
    optIssueButton->setEnabled(false);
    optRecordButton->setEnabled(false);
    {
        QSettings s;
        optResumeButton->setEnabled(s.value(QStringLiteral("OptionSeriesDraft/active"), false).toBool());
    }

    connect(optResumeButton, &QPushButton::clicked, this, &TreasuryPage::onOptResume);
    connect(optWriterGenButton, &QPushButton::clicked, this, &TreasuryPage::onOptGenWriter);
    connect(optSaltGenButton, &QPushButton::clicked, this, &TreasuryPage::onOptGenSalt);
    connect(optSuffixEdit, &QLineEdit::textChanged, this, &TreasuryPage::onOptPreviewUpdate);
    connect(optParentCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &TreasuryPage::onOptPreviewUpdate);
    connect(optStrikeTpsEdit, &QLineEdit::textChanged, this, &TreasuryPage::onOptStrikePreview);
    connect(optFixingDurationSpin, QOverload<int>::of(&QSpinBox::valueChanged), this, &TreasuryPage::onOptScheduleAndPayoffPreview);
    connect(optFixingUnitCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &TreasuryPage::onOptScheduleAndPayoffPreview);
    connect(optSettleWindowSpin, QOverload<int>::of(&QSpinBox::valueChanged), this, &TreasuryPage::onOptScheduleAndPayoffPreview);
    connect(optLeverageEdit, &QLineEdit::textChanged, this, &TreasuryPage::onOptScheduleAndPayoffPreview);
    connect(optLotImEdit, &QLineEdit::textChanged, this, &TreasuryPage::onOptScheduleAndPayoffPreview);
    connect(optExampleMoveSpin, QOverload<int>::of(&QSpinBox::valueChanged), this, &TreasuryPage::onOptScheduleAndPayoffPreview);
    // Direction changes the descriptor → the previewed asset id is stale until re-derived.
    connect(optDirectionCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this,
            [this](int) { if (optAssetIdLabel) optAssetIdLabel->setText(tr("(derive to preview)")); });
    connect(optDeriveButton, &QPushButton::clicked, this, &TreasuryPage::onOptDerive);
    connect(optRegisterButton, &QPushButton::clicked, this, &TreasuryPage::onOptRegister);
    connect(optIssueButton, &QPushButton::clicked, this, &TreasuryPage::onOptIssue);
    connect(optRecordButton, &QPushButton::clicked, this, &TreasuryPage::onOptRecord);
    connect(optResetButton, &QPushButton::clicked, this, &TreasuryPage::onOptReset);
    connect(optRefreshListButton, &QPushButton::clicked, this, &TreasuryPage::onOptRefreshList);
    connect(optVerifyBackingButton, &QPushButton::clicked, this, &TreasuryPage::onOptVerifyBacking);
    connect(optSeriesTable, &QTableWidget::itemSelectionChanged, this, &TreasuryPage::onOptSeriesSelectionChanged);
    connect(optSettleButton, &QPushButton::clicked, this, &TreasuryPage::onOptSettle);
    connect(optBuybackButton, &QPushButton::clicked, this, &TreasuryPage::onOptBuyback);
    connect(optRedeemButton, &QPushButton::clicked, this, &TreasuryPage::onOptRedeem);
}

bool TreasuryPage::collectOptionSeriesTerms(WalletModel::OptionSeriesTermsInput& out)
{
    out.writer_key = optWriterEdit->text().trimmed();
    if (out.writer_key.isEmpty()) {
        optStatusText->append(tr("✗ Writer address/key is required (click 'New address')."));
        return false;
    }

    // Human strike (tokens/sec) -> canonical consensus nBits (same conversion as the difficulty builder).
    bool tokOk = false;
    const double strikeTps = ParseTokensPerSec(optStrikeTpsEdit->text(), &tokOk);
    if (!tokOk) {
        optStatusText->append(tr("✗ Strike must be a positive tokens/sec value (e.g. 5G or 750M)."));
        return false;
    }
    const quint32 strikeNbits = wallet::DifficultyTokensPerSecToNBits(strikeTps);
    if (strikeNbits == 0) {
        optStatusText->append(tr("✗ Strike is outside the representable difficulty range."));
        return false;
    }
    out.strike_nbits = strikeNbits;

    // Fixing/settle schedule. Once the series is REGISTERED these heights are frozen (m_optFixingHeight)
    // and MUST be reused verbatim: the id is TaggedHash(descriptor) and the descriptor commits the
    // absolute fixing/settle heights, so recomputing "tip + duration" at Issue/Record — after the tip has
    // advanced past registration — would derive a different series_id and the registry lookup would miss.
    if (m_optFixingHeight > 0) {
        out.fixing_height = static_cast<quint32>(m_optFixingHeight);
        out.settle_lock_height = static_cast<quint32>(m_optSettleLockHeight);
    } else {
        // Pre-registration: fixing entered as a duration from the CURRENT tip (re-fetched here so the
        // schedule is anchored to the live height). Settle-lock = fixing + the safety window.
        int tipHeight = m_optChainHeight;
        if (walletModel) {
            const WalletModel::DifficultyChainDefaults d = walletModel->difficultyChainDefaults();
            if (d.success && d.height > 0) { tipHeight = d.height; m_optChainHeight = d.height; }
        }
        if (tipHeight <= 0) {
            optStatusText->append(tr("✗ Could not read the chain height to schedule the fixing."));
            return false;
        }
        const int unitDays = optFixingUnitCombo ? optFixingUnitCombo->currentData().toInt() : 1;
        const qint64 durBlocks = static_cast<qint64>(optFixingDurationSpin->value()) * unitDays * 144;
        const qint64 fixing = static_cast<qint64>(tipHeight) + durBlocks;
        const qint64 settle = fixing + optSettleWindowSpin->value();
        if (settle >= 500000000LL) {   // LOCKTIME_THRESHOLD: settle-lock must stay a block height
            optStatusText->append(tr("✗ The fixing + settlement schedule is too far in the future."));
            return false;
        }
        out.fixing_height = static_cast<quint32>(fixing);
        out.settle_lock_height = static_cast<quint32>(settle);
    }

    // Leverage (×) -> lambda_q (Q16).
    bool levOk = false;
    const double lev = optLeverageEdit->text().trimmed().toDouble(&levOk);
    if (!levOk || lev <= 0.0) {
        optStatusText->append(tr("✗ Leverage must be a positive number (e.g. 1.0 or 3.33)."));
        return false;
    }
    const long long lq = std::llround(lev * 65536.0);
    if (lq < 1 || lq > 0xFFFFFFFFLL) {
        optStatusText->append(tr("✗ Leverage is out of the representable range."));
        return false;
    }
    out.lambda_q = static_cast<quint32>(lq);

    // Exact sat parsing (no float): these amounts become descriptor bytes, so a 0.1-as-double round-trip
    // could change the asset_id. ParseTscToSats rejects >8 decimals / non-numeric text.
    if (!ParseTscToSats(optLotImEdit->text(), out.lot_im_sats) || out.lot_im_sats <= 0) {
        optStatusText->append(tr("✗ Lot collateral must be a positive TSC amount with at most 8 decimals."));
        return false;
    }

    out.lot_count = static_cast<quint32>(optLotCountSpin->value());
    // Total collateral must fit the money cap (lot_count is spin-capped, so this cannot overflow int64).
    if (out.lot_im_sats * static_cast<qint64>(out.lot_count) > kMaxMoneySats) {
        optStatusText->append(tr("✗ Total collateral (lot collateral × N) exceeds the 21,000,000 TSC cap."));
        return false;
    }

    const QString refStr = optRefPremiumEdit->text().trimmed();
    if (refStr.isEmpty()) {
        out.reference_premium_sats = 0;
    } else if (!ParseTscToSats(refStr, out.reference_premium_sats)) {
        optStatusText->append(tr("✗ Reference premium must be a TSC amount with at most 8 decimals."));
        return false;
    }

    QString salt = optSaltEdit->text().trimmed();
    if (salt.isEmpty()) { onOptGenSalt(); salt = optSaltEdit->text().trimmed(); }
    if (salt.length() != 64) {
        optStatusText->append(tr("✗ Series salt must be 64 hex characters."));
        return false;
    }
    for (const QChar& c : salt) {
        const bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (!hex) { optStatusText->append(tr("✗ Series salt must be hexadecimal (0-9, a-f).")); return false; }
    }
    out.series_salt = salt;
    out.direction = optDirectionCombo ? optDirectionCombo->currentData().toInt() : 0;  // 0 call, 1 put
    return true;
}

void TreasuryPage::setOptionSeriesFormEnabled(bool enabled)
{
    QWidget* const widgets[] = {
        optParentCombo, optDirectionCombo, optSuffixEdit, optWriterEdit, optWriterGenButton, optStrikeTpsEdit,
        optFixingDurationSpin, optFixingUnitCombo, optSettleWindowSpin, optLeverageEdit, optLotImEdit, optLotCountSpin,
        optExampleMoveSpin, optRefPremiumEdit, optSaltEdit, optSaltGenButton, optBondEdit};
    for (QWidget* w : widgets) if (w) w->setEnabled(enabled);
}

bool TreasuryPage::recoverOptionSeriesFrozenSchedule(const QString& identifier)
{
    if (!walletModel) return false;
    const QString id = identifier.trimmed();
    if (id.isEmpty() || id.startsWith(QLatin1Char('('))) return false;

    const WalletModel::OptionSeriesBackingResult r = walletModel->optionSeriesVerifyById(id);
    if (!r.success || !r.authentic || r.terms_json.isEmpty()) {
        if (optStatusText) {
            optStatusText->append(tr("⚠ Could not recover the registered schedule from chain: %1")
                                      .arg(!r.error.isEmpty() ? r.error : r.reason));
        }
        return false;
    }

    UniValue terms;
    if (!terms.read(r.terms_json.toStdString()) || !terms.isObject()) {
        if (optStatusText) optStatusText->append(tr("⚠ Recovered descriptor terms were not parseable."));
        return false;
    }

    const UniValue& fixingValue = terms.find_value("fixing_height");
    const UniValue& settleValue = terms.find_value("settle_lock_height");
    if (fixingValue.isNull() || settleValue.isNull()) {
        if (optStatusText) optStatusText->append(tr("⚠ Recovered descriptor did not contain fixing/settle heights."));
        return false;
    }

    const int64_t fixing = fixingValue.getInt<int64_t>();
    const int64_t settle = settleValue.getInt<int64_t>();
    if (fixing <= 0 || settle <= 0 ||
        fixing > std::numeric_limits<int>::max() ||
        settle > std::numeric_limits<int>::max()) {
        if (optStatusText) optStatusText->append(tr("⚠ Recovered fixing/settle heights are out of range."));
        return false;
    }

    m_optFixingHeight = static_cast<int>(fixing);
    m_optSettleLockHeight = static_cast<int>(settle);
    if (optStatusText) {
        optStatusText->append(tr("✓ Recovered registered schedule from chain: fixing %1, settle %2.")
                                  .arg(m_optFixingHeight).arg(m_optSettleLockHeight));
    }
    return true;
}

bool TreasuryPage::resolveSpendableWriterAddress(const QString& writerInput, QString& addressOut, QString& errOut)
{
    if (!clientModel || !walletModel) { errOut = tr("Wallet not ready"); return false; }
    const QString input = writerInput.trimmed();
    if (input.isEmpty()) { errOut = tr("Writer is required (click 'New address')"); return false; }
    const std::string wname = walletModel->getWalletName().toStdString();

    // A bare 64-hex x-only key -> derive its P2TR address via rawtr(...), so we can ask the wallet about it.
    QString address = input;
    bool isHex64 = input.length() == 64;
    if (isHex64) {
        for (const QChar& c : input) {
            const bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!hex) { isHex64 = false; break; }
        }
    }
    if (isHex64) {
        try {
            UniValue dp(UniValue::VARR);
            dp.push_back(QString("rawtr(%1)").arg(input).toStdString());
            UniValue di = clientModel->node().executeRpc("getdescriptorinfo", dp, /*walletName=*/"");
            const std::string desc = di.exists("descriptor") ? di["descriptor"].get_str() : std::string();
            if (desc.empty()) { errOut = tr("Could not parse the writer key"); return false; }
            UniValue da(UniValue::VARR);
            da.push_back(desc);
            UniValue addrs = clientModel->node().executeRpc("deriveaddresses", da, /*walletName=*/"");
            if (!addrs.isArray() || addrs.size() < 1) { errOut = tr("Could not derive an address from the writer key"); return false; }
            address = QString::fromStdString(addrs[0].get_str());
        } catch (...) {
            errOut = tr("Invalid writer key");
            return false;
        }
    }

    // The writer must be a Taproot output this wallet can SIGN with — otherwise registration would succeed
    // but issuance (which rotates + signs the ICU) could never go through.
    try {
        UniValue p(UniValue::VARR);
        p.push_back(address.toStdString());
        UniValue r = clientModel->node().executeRpc("getaddressinfo", p, wname);
        const bool ismine = r.exists("ismine") && r["ismine"].get_bool();
        const bool watchonly = r.exists("iswatchonly") && r["iswatchonly"].get_bool();
        const bool iswitness = r.exists("iswitness") && r["iswitness"].get_bool();
        const int witver = r.exists("witness_version") ? r["witness_version"].getInt<int>() : -1;
        if (!iswitness || witver != 1) { errOut = tr("Writer must be a Taproot (bech32m) address"); return false; }
        if (!ismine || watchonly) {
            errOut = tr("Writer must be an address THIS wallet controls (use 'New address'); issuance and "
                        "settlement have to sign with it.");
            return false;
        }
    } catch (...) {
        errOut = tr("Writer address is invalid or not recognized by the wallet");
        return false;
    }
    addressOut = address;
    return true;
}

void TreasuryPage::saveOptionSeriesDraft(int stage)
{
    QSettings s;
    s.beginGroup(QStringLiteral("OptionSeriesDraft"));
    s.setValue("active", true);
    s.setValue("stage", stage);
    // Scope the draft to its wallet + chain so Resume can refuse to restore into the wrong context.
    s.setValue("wallet", walletModel ? walletModel->getWalletName() : QString());
    s.setValue("chain", CurrentChainName(clientModel));
    s.setValue("root", optParentCombo ? optParentCombo->currentData().toString() : QString());
    s.setValue("direction", optDirectionCombo ? optDirectionCombo->currentIndex() : 0);
    s.setValue("suffix", optSuffixEdit->text());
    s.setValue("writer", optWriterEdit->text());
    s.setValue("strike", optStrikeTpsEdit->text());
    s.setValue("fix_dur", optFixingDurationSpin->value());
    s.setValue("fix_unit", optFixingUnitCombo->currentIndex());
    // Persist the FROZEN absolute schedule so a resumed (already-registered) draft re-derives the same
    // series_id instead of recomputing tip+duration against a now-advanced tip.
    s.setValue("fix_height", m_optFixingHeight);
    s.setValue("settle_height", m_optSettleLockHeight);
    s.setValue("settle_window", optSettleWindowSpin->value());
    s.setValue("leverage", optLeverageEdit->text());
    s.setValue("lot_im", optLotImEdit->text());
    s.setValue("lot_count", optLotCountSpin->value());
    s.setValue("ref_premium", optRefPremiumEdit->text());
    s.setValue("salt", optSaltEdit->text());
    s.setValue("bond", optBondEdit->text());
    s.setValue("fee", optFeeRateEdit->text());
    s.setValue("asset_id", optAssetIdLabel->text());
    s.setValue("issue_txid", m_optIssueTxid);
    s.endGroup();
    if (optResumeButton) optResumeButton->setEnabled(true);
}

void TreasuryPage::clearOptionSeriesDraft()
{
    QSettings s;
    s.remove(QStringLiteral("OptionSeriesDraft"));
    if (optResumeButton) optResumeButton->setEnabled(false);
}

void TreasuryPage::onOptGenWriter()
{
    if (!clientModel || !walletModel) { showError(tr("Wallet not ready")); return; }
    try {
        UniValue p(UniValue::VARR);
        p.push_back("");          // label
        p.push_back("bech32m");   // a taproot address the wallet can sign with
        UniValue a = clientModel->node().executeRpc("getnewaddress", p, walletModel->getWalletName().toStdString());
        optWriterEdit->setText(QString::fromStdString(a.get_str()));
    } catch (...) {
        showError(tr("Could not generate a writer address."));
    }
}

void TreasuryPage::onOptGenSalt()
{
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;
    QString s;
    for (int i = 0; i < 4; ++i) s += QString("%1").arg(dis(gen), 16, 16, QChar('0'));
    optSaltEdit->setText(s);
}

void TreasuryPage::onOptPreviewUpdate()
{
    if (!optTickerPreviewLabel) return;
    const QString root = optParentCombo ? optParentCombo->currentData().toString() : QString();
    const QString suffix = optSuffixEdit ? optSuffixEdit->text().trimmed().toUpper() : QString();
    optTickerPreviewLabel->setText((root.isEmpty() || suffix.isEmpty())
                                       ? tr("(choose a root + suffix)")
                                       : (root + "." + suffix));
}

void TreasuryPage::onOptStrikePreview()
{
    if (!optStrikeNbitsLabel) return;
    bool ok = false;
    const double tps = ParseTokensPerSec(optStrikeTpsEdit->text(), &ok);
    if (!ok) { optStrikeNbitsLabel->setText(tr("(enter a positive tok/s strike)")); return; }
    const uint32_t nbits = wallet::DifficultyTokensPerSecToNBits(tps);
    if (nbits == 0) { optStrikeNbitsLabel->setText(tr("(out of representable range)")); return; }
    // Echo the canonical nBits + the strike it actually rounds to (compact targets are not continuous).
    const double canon = wallet::DifficultyNBitsToTokensPerSec(nbits);
    optStrikeNbitsLabel->setText(tr("0x%1   (≈ %2)")
                                     .arg(nbits, 8, 16, QChar('0'))
                                     .arg(QString::fromStdString(wallet::DifficultyFormatTokensPerSec(canon))));
}

void TreasuryPage::onOptScheduleAndPayoffPreview()
{
    // Fixing as a duration -> absolute block height (144 blocks/day on all TSC chains).
    const int unitDays = optFixingUnitCombo ? optFixingUnitCombo->currentData().toInt() : 1;
    const qint64 durBlocks = static_cast<qint64>(optFixingDurationSpin->value()) * unitDays * 144;
    if (m_optFixingHeight > 0) {
        if (optFixingHeightLabel) {
            optFixingHeightLabel->setText(tr("block %1 (registered)").arg(m_optFixingHeight));
        }
        if (optSettleHeightLabel) {
            optSettleHeightLabel->setText(tr("block %1 (registered)").arg(m_optSettleLockHeight));
        }
    } else {
        if (optFixingHeightLabel) {
            if (m_optChainHeight > 0) {
                const qint64 fixing = m_optChainHeight + durBlocks;
                optFixingHeightLabel->setText(tr("≈ block %1   (tip %2 + %3 blocks)")
                                                  .arg(fixing).arg(m_optChainHeight).arg(durBlocks));
            } else {
                optFixingHeightLabel->setText(tr("now + %1 blocks (chain height pending)").arg(durBlocks));
            }
        }
        if (optSettleHeightLabel && m_optChainHeight > 0) {
            const qint64 fixing = m_optChainHeight + durBlocks;
            optSettleHeightLabel->setText(tr("≈ block %1   (fixing + %2)").arg(fixing + optSettleWindowSpin->value()).arg(optSettleWindowSpin->value()));
        }
    }

    // Worked payoff per unit: a favourable m%% move past strike pays min(leverage*m, 1) * lot_collateral.
    if (!optPayoffLabel) return;
    bool levOk = false;
    const double lev = optLeverageEdit->text().trimmed().toDouble(&levOk);
    qint64 imSats = 0;
    const bool imOk = ParseTscToSats(optLotImEdit->text(), imSats) && imSats > 0;
    if (!levOk || lev <= 0.0 || !imOk) {
        optPayoffLabel->setText(tr("Enter leverage and lot collateral to see the payoff."));
        return;
    }
    const double imTsc = imSats / 100000000.0;
    const double m = optExampleMoveSpin->value() / 100.0;          // example move fraction
    const double frac = std::min(lev * m, 1.0);                    // payout fraction of collateral (capped)
    const double payout = frac * imTsc;
    const double fullMovePct = 100.0 / lev;                        // move at which the cap is hit
    const bool isPut = (optDirectionCombo && optDirectionCombo->currentData().toInt() == 1);
    optPayoffLabel->setText(tr("1 unit = 1 lot, max payout %1 TSC. At %2× leverage, difficulty moving %3%% %4 strike "
                               "pays ≈ %5 TSC/unit%6. Full payout (cap) at a %7%% move.")
                                .arg(imTsc, 0, 'f', 8)
                                .arg(lev, 0, 'g', 4)
                                .arg(optExampleMoveSpin->value())
                                .arg(isPut ? tr("below") : tr("above"))
                                .arg(payout, 0, 'f', 8)
                                .arg(frac >= 1.0 ? tr(" (capped)") : QString())
                                .arg(fullMovePct, 0, 'f', 1));
}

void TreasuryPage::onOptDerive()
{
    if (!walletModel) { showError(tr("Wallet not ready")); return; }
    WalletModel::OptionSeriesTermsInput t;
    if (!collectOptionSeriesTerms(t)) return;
    WalletModel::OptionSeriesDeriveResult r = walletModel->optionSeriesDerive(t);
    if (!r.success) {
        optAssetIdLabel->setText(tr("(invalid terms)"));
        optStatusText->append(tr("✗ Preview failed: %1").arg(r.error));
        return;
    }
    optAssetIdLabel->setText(r.asset_id);
    optStatusText->append(tr("✓ Terms valid. Derived asset_id %1 (N=%2).").arg(r.asset_id).arg(r.lot_count));
}

void TreasuryPage::onOptRegister()
{
    if (!walletModel || !clientModel) { showError(tr("Wallet or client model not initialized")); return; }
    if (!optParentCombo || optParentCombo->count() == 0) {
        showError(tr("No wallet-controlled root is available to sponsor the series."));
        return;
    }
    WalletModel::OptionSeriesTermsInput t;
    if (!collectOptionSeriesTerms(t)) return;

    const QString root = optParentCombo->currentData().toString();
    const QString suffix = optSuffixEdit->text().trimmed().toUpper();
    auto isRootChar = [](QChar c) { return (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'); };
    bool suffixOk = suffix.length() >= 3 && suffix.length() <= 11 && suffix.at(0) >= 'A' && suffix.at(0) <= 'Z';
    for (const QChar& ch : suffix) { if (!isRootChar(ch)) suffixOk = false; }
    if (!suffixOk) {
        showError(tr("Suffix must be 3-11 chars, start with a letter, and use A-Z0-9 only (no dot)."));
        return;
    }

    // HIGH: the writer must be a wallet-signable Taproot output, else issuance can never sign the ICU.
    // Resolve + verify before anything is registered, and normalize the field to the validated address.
    QString resolvedWriter, writerErr;
    if (!resolveSpendableWriterAddress(t.writer_key, resolvedWriter, writerErr)) {
        optStatusText->append(tr("✗ %1").arg(writerErr));
        showError(writerErr);
        return;
    }
    t.writer_key = resolvedWriter;
    optWriterEdit->setText(resolvedWriter);

    // Validate the fee + bond explicitly instead of letting bad text silently become 0.
    bool feeOk = false;
    const double feeRate = optFeeRateEdit->text().trimmed().toDouble(&feeOk);
    if (!feeOk || feeRate <= 0.0) { showError(tr("Fee rate must be a positive number (sat/vB).")); return; }
    qint64 bondSats = 0;
    const QString bondStr = optBondEdit->text().trimmed();
    if (!bondStr.isEmpty() && !ParseTscToSats(bondStr, bondSats)) {
        showError(tr("Child bond must be a non-negative TSC amount with at most 8 decimals."));
        return;
    }
    const QString fullTicker = root + "." + suffix;

    QString confirm = tr("<b>Register option series</b><br/><br/>");
    confirm += tr("<b>Ticker:</b> %1<br/>").arg(fullTicker);
    confirm += tr("<b>Lots (N):</b> %1 &times; %2 TSC = %3 TSC collateral at issuance<br/>")
                   .arg(t.lot_count).arg(FormatSats(t.lot_im_sats))
                   .arg(FormatSats(t.lot_im_sats * static_cast<qint64>(t.lot_count)));
    confirm += tr("<b>Writer:</b> %1<br/><br/>").arg(t.writer_key);
    confirm += tr("This registers the series shell only. After it confirms, use '2. Issue series' to mint the "
                  "units and fund the vaults.<br/><br/>Proceed?");
    QMessageBox box(TopLevelDialogParent(this));
    box.setWindowTitle(tr("Confirm Series Registration"));
    box.setTextFormat(Qt::RichText);
    box.setText(confirm);
    box.setIcon(QMessageBox::Question);
    box.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
    box.setDefaultButton(QMessageBox::No);
    box.setWindowModality(Qt::WindowModal);
    if (box.exec() != QMessageBox::Yes) { optStatusText->append(tr("Registration cancelled.")); return; }

    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if (!ctx.isValid()) { showError(tr("Wallet locked. Please unlock to register the series.")); return; }

    WalletModel::OptionSeriesRegisterResult r = walletModel->optionSeriesBuildRegister(t, root, suffix, bondSats, feeRate, true);
    if (!r.success) {
        optStatusText->append(tr("✗ Register failed: %1").arg(r.error));
        showError(r.error);
        return;
    }
    // Freeze the schedule that produced this registered id, so Issue/Record re-derive the SAME series_id
    // even though the tip has since advanced (t still holds the heights build_register committed to).
    m_optFixingHeight = static_cast<int>(t.fixing_height);
    m_optSettleLockHeight = static_cast<int>(t.settle_lock_height);
    onOptScheduleAndPayoffPreview();
    optAssetIdLabel->setText(r.asset_id);
    optStatusText->append(tr("✓ Registered %1 (asset %2). TxID %3.")
                              .arg(r.ticker).arg(r.asset_id).arg(r.txid));
    optStatusText->append(tr("  → Wait for 1 confirmation, then click '2. Issue series'."));
    setOptionSeriesFormEnabled(false);
    optRegisterButton->setEnabled(false);
    optIssueButton->setEnabled(true);
    saveOptionSeriesDraft(/*stage=*/1);  // terms + salt are now durable across an app restart
    refreshAssetList();
    refreshICUDashboard();
}

void TreasuryPage::onOptIssue()
{
    if (!walletModel) { showError(tr("Wallet not ready")); return; }
    WalletModel::OptionSeriesTermsInput t;
    if (!collectOptionSeriesTerms(t)) return;  // the form is locked but still readable
    bool feeOk = false;
    const double feeRate = optFeeRateEdit->text().trimmed().toDouble(&feeOk);
    if (!feeOk || feeRate <= 0.0) { showError(tr("Fee rate must be a positive number (sat/vB).")); return; }

    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if (!ctx.isValid()) { showError(tr("Wallet locked. Please unlock to issue the series.")); return; }

    WalletModel::OptionSeriesIssueResult r = walletModel->optionSeriesBuildIssue(t, feeRate, true);
    if (!r.success) {
        // The RPC rejects issuance until the registration is confirmed; leave the button enabled to retry.
        optStatusText->append(tr("✗ Issue failed: %1").arg(r.error));
        showError(r.error);
        return;
    }
    m_optIssueTxid = r.txid;
    optStatusText->append(tr("✓ Issued %1 units + funded %1 vaults. Mint TxID %2.").arg(r.lot_count).arg(r.txid));
    optStatusText->append(tr("  → Wait for 1 confirmation, then click '3. Record issue'."));
    optIssueButton->setEnabled(false);
    optRecordButton->setEnabled(true);
    saveOptionSeriesDraft(/*stage=*/2);  // persist the issuance txid so Record survives a restart
    refreshAssetList();
}

void TreasuryPage::onOptRecord()
{
    if (!walletModel) { showError(tr("Wallet not ready")); return; }
    if (m_optIssueTxid.isEmpty()) { showError(tr("No issuance txid — run '2. Issue series' first.")); return; }
    WalletModel::OptionSeriesTermsInput t;
    if (!collectOptionSeriesTerms(t)) return;

    WalletModel::OptionSeriesRecordResult r = walletModel->optionSeriesRecordIssue(t, m_optIssueTxid);
    if (!r.success) {
        // record_issue requires the issuance tx confirmed (issued_total == N); leave the button to retry.
        optStatusText->append(tr("✗ Record failed: %1").arg(r.error));
        showError(r.error);
        return;
    }
    optStatusText->append(tr("✓ Recorded series %1 (%2 lots) — persisted: %3.")
                              .arg(r.asset_id).arg(r.lot_count).arg(r.persisted ? tr("yes") : tr("no")));
    optStatusText->append(tr("  → Done. Click 'New series' to create another."));
    optRecordButton->setEnabled(false);
    clearOptionSeriesDraft();  // the series is recorded in the wallet now; the local draft is no longer needed
    onOptRefreshList();        // show the freshly-recorded series in the list
    refreshAssetList();
    refreshICUDashboard();
}

void TreasuryPage::onOptReset()
{
    setOptionSeriesFormEnabled(true);
    optSuffixEdit->clear();
    optSaltEdit->clear();
    optAssetIdLabel->setText(tr("(derive to preview)"));
    m_optIssueTxid.clear();
    m_optFixingHeight = 0;       // unfreeze: the next series computes its schedule from the live tip again
    m_optSettleLockHeight = 0;
    optRegisterButton->setEnabled(true);
    optIssueButton->setEnabled(false);
    optRecordButton->setEnabled(false);
    clearOptionSeriesDraft();  // discard any saved in-progress draft
    optStatusText->append(tr("— Ready for a new series —"));
    onOptPreviewUpdate();
    onOptScheduleAndPayoffPreview();
}

void TreasuryPage::onOptResume()
{
    QSettings s;
    s.beginGroup(QStringLiteral("OptionSeriesDraft"));
    if (!s.value("active", false).toBool()) {
        s.endGroup();
        optStatusText->append(tr("No saved series draft to resume."));
        return;
    }
    // Refuse to restore a draft made for a different wallet or chain (wrong writer keys / vault context).
    const QString draftWallet = s.value("wallet").toString();
    const QString draftChain = s.value("chain").toString();
    const QString curWallet = walletModel ? walletModel->getWalletName() : QString();
    const QString curChain = CurrentChainName(clientModel);
    if (draftWallet != curWallet || draftChain != curChain) {
        s.endGroup();
        optStatusText->append(tr("✗ The saved draft belongs to wallet '%1' on chain '%2' (current: '%3' / '%4'); "
                                 "not resuming. Switch back to that context, or click 'New series' there to discard it.")
                                  .arg(draftWallet.isEmpty() ? tr("(default)") : draftWallet).arg(draftChain)
                                  .arg(curWallet.isEmpty() ? tr("(default)") : curWallet).arg(curChain));
        return;
    }
    const int stage = s.value("stage", 0).toInt();
    const QString root = s.value("root").toString();
    if (optDirectionCombo) optDirectionCombo->setCurrentIndex(s.value("direction", 0).toInt());
    optSuffixEdit->setText(s.value("suffix").toString());
    optWriterEdit->setText(s.value("writer").toString());
    optStrikeTpsEdit->setText(s.value("strike").toString());
    optFixingDurationSpin->setValue(s.value("fix_dur", 30).toInt());
    optFixingUnitCombo->setCurrentIndex(s.value("fix_unit", 0).toInt());
    optSettleWindowSpin->setValue(s.value("settle_window", 110).toInt());
    optLeverageEdit->setText(s.value("leverage", "1.0").toString());
    optLotImEdit->setText(s.value("lot_im").toString());
    optLotCountSpin->setValue(s.value("lot_count").toInt());
    optRefPremiumEdit->setText(s.value("ref_premium").toString());
    optSaltEdit->setText(s.value("salt").toString());
    optBondEdit->setText(s.value("bond").toString());
    optFeeRateEdit->setText(s.value("fee").toString());
    optAssetIdLabel->setText(s.value("asset_id").toString());
    m_optIssueTxid = s.value("issue_txid").toString();
    // Restore the frozen schedule (a stage>=1 draft is already registered; reuse the exact heights so
    // Issue/Record derive the registered series_id rather than recomputing against the current tip).
    m_optFixingHeight = s.value("fix_height", 0).toInt();
    m_optSettleLockHeight = s.value("settle_height", 0).toInt();
    s.endGroup();

    if (optParentCombo) {
        const int idx = optParentCombo->findData(root);
        if (idx >= 0) optParentCombo->setCurrentIndex(idx);
        else if (!root.isEmpty()) optStatusText->append(tr("⚠ Saved sponsoring root '%1' is not in this wallet's controlled set.").arg(root));
    }

    if (stage >= 1 && (m_optFixingHeight <= 0 || m_optSettleLockHeight <= 0)) {
        const QString savedAssetId = optAssetIdLabel ? optAssetIdLabel->text().trimmed() : QString();
        if (recoverOptionSeriesFrozenSchedule(savedAssetId)) {
            saveOptionSeriesDraft(stage);
        }
    }

    // Restore the step gating for the saved stage (form stays locked once registered).
    if (stage >= 1) { setOptionSeriesFormEnabled(false); optRegisterButton->setEnabled(false); }
    if (stage >= 1 && (m_optFixingHeight <= 0 || m_optSettleLockHeight <= 0)) {
        optIssueButton->setEnabled(false);
        optRecordButton->setEnabled(false);
        optStatusText->append(tr("✗ This registered draft was saved before the schedule-freeze fix, and "
                                 "the exact on-chain heights could not be recovered yet. Wait until the "
                                 "registration is confirmed and Resume again, or click 'New series'."));
        onOptPreviewUpdate();
        onOptScheduleAndPayoffPreview();
        return;
    }
    optIssueButton->setEnabled(stage == 1);
    optRecordButton->setEnabled(stage == 2);
    if (stage == 1) {
        optStatusText->append(tr("↻ Resumed a REGISTERED series (awaiting issuance). Terms + salt restored; click '2. Issue series' once it has confirmed."));
    } else if (stage == 2) {
        optStatusText->append(tr("↻ Resumed an ISSUED series (awaiting record). Mint TxID %1; click '3. Record issue' once it has confirmed.").arg(m_optIssueTxid));
    }
    onOptPreviewUpdate();
    onOptScheduleAndPayoffPreview();
}

void TreasuryPage::onOptRefreshList()
{
    if (!walletModel) { return; }
    WalletModel::OptionSeriesListResult r = walletModel->optionSeriesList();
    if (!r.success) {
        optStatusText->append(tr("✗ Could not list series: %1").arg(r.error));
        return;
    }
    optSeriesTable->setRowCount(0);
    for (const WalletModel::OptionSeriesListEntry& e : r.series) {
        const int row = optSeriesTable->rowCount();
        optSeriesTable->insertRow(row);
        QTableWidgetItem* idItem = new QTableWidgetItem(e.asset_id.left(20) + QStringLiteral("…"));
        idItem->setToolTip(e.asset_id);
        idItem->setData(Qt::UserRole, e.asset_id);              // canonical id -> verify
        idItem->setData(Qt::UserRole + 1, e.registry_asset_id); // registry id -> geticupayload
        idItem->setData(Qt::UserRole + 2, e.terms_json);        // full terms -> settle/redeem/buyback
        idItem->setData(Qt::UserRole + 3, e.lot_count);         // lot range for the lifecycle spin
        optSeriesTable->setItem(row, 0, idItem);
        optSeriesTable->setItem(row, 1, new QTableWidgetItem(QString::number(e.lot_count)));
        optSeriesTable->setItem(row, 2, new QTableWidgetItem(e.issue_txid.left(16) + QStringLiteral("…")));
        optSeriesTable->setItem(row, 3, new QTableWidgetItem(tr("(not checked)")));
    }
    optVerifyBackingButton->setEnabled(optSeriesTable->rowCount() > 0);
    if (optSeriesTable->rowCount() > 0 && optSeriesTable->currentRow() < 0) optSeriesTable->selectRow(0);
    optStatusText->append(tr("Listed %1 recorded series.").arg(r.series.size()));
}

void TreasuryPage::onOptVerifyBacking()
{
    if (!walletModel) { showError(tr("Wallet not ready")); return; }
    const int row = optSeriesTable->currentRow();
    if (row < 0) { showError(tr("Select a series in the list to verify.")); return; }
    QTableWidgetItem* idItem = optSeriesTable->item(row, 0);
    if (!idItem) return;
    const QString asset_id = idItem->data(Qt::UserRole).toString();
    const QString reg_id = idItem->data(Qt::UserRole + 1).toString();

    optSeriesTable->setItem(row, 3, new QTableWidgetItem(tr("checking…")));
    WalletModel::OptionSeriesBackingResult r = walletModel->optionSeriesVerifyBacking(reg_id, asset_id);
    if (!r.success) {
        optSeriesTable->setItem(row, 3, new QTableWidgetItem(tr("error")));
        optStatusText->append(tr("✗ Verify backing failed: %1").arg(r.error));
        return;
    }

    QString verdict;
    if (r.verified) {
        verdict = tr("✓ backed %1/%2").arg(r.vaults_funded).arg(r.vaults_expected);
    } else if (!r.authentic) {
        verdict = tr("✗ not authentic");
    } else if (!r.invariants_ok) {
        verdict = tr("✗ bad invariants");
    } else {
        verdict = tr("✗ %1/%2 funded").arg(r.vaults_funded).arg(r.vaults_expected);
    }
    optSeriesTable->setItem(row, 3, new QTableWidgetItem(verdict));
    optStatusText->append(tr("Backing %1: authentic=%2, invariants_ok=%3, issued=%4, vaults=%5/%6, verified=%7%8")
                              .arg(asset_id.left(16) + QStringLiteral("…"))
                              .arg(r.authentic ? tr("yes") : tr("no"))
                              .arg(r.invariants_ok ? tr("yes") : tr("no"))
                              .arg(r.issued_total).arg(r.vaults_funded).arg(r.vaults_expected)
                              .arg(r.verified ? tr("YES") : tr("NO"))
                              .arg(r.reason.isEmpty() ? QString() : tr(" — %1").arg(r.reason)));
}

void TreasuryPage::onOptSeriesSelectionChanged()
{
    const int row = optSeriesTable->currentRow();
    const bool have = row >= 0;
    QTableWidgetItem* idItem = have ? optSeriesTable->item(row, 0) : nullptr;
    const bool ready = idItem && !idItem->data(Qt::UserRole + 2).toString().isEmpty();
    if (ready) {
        const int lotCount = idItem->data(Qt::UserRole + 3).toInt();
        optLotIndexSpin->setRange(0, std::max(0, lotCount - 1));
    }
    optSettleButton->setEnabled(ready);
    optBuybackButton->setEnabled(ready);
    optRedeemButton->setEnabled(ready);
}

void TreasuryPage::onOptSettle()
{
    if (!walletModel) { showError(tr("Wallet not ready")); return; }
    const int row = optSeriesTable->currentRow();
    QTableWidgetItem* idItem = row >= 0 ? optSeriesTable->item(row, 0) : nullptr;
    if (!idItem) { showError(tr("Select a series first.")); return; }
    const QString terms = idItem->data(Qt::UserRole + 2).toString();
    const int lot = optLotIndexSpin->value();
    if (terms.isEmpty()) { showError(tr("Selected series has no terms to act on.")); return; }

    QMessageBox box(TopLevelDialogParent(this));
    box.setWindowTitle(tr("Confirm Settlement"));
    box.setText(tr("Settle lot %1 of the selected series?\n\nThis builds the keeper settlement and broadcasts it. "
                   "It only succeeds once the fixing height is buried and the settle-lock CLTV is open.").arg(lot));
    box.setIcon(QMessageBox::Question);
    box.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
    box.setDefaultButton(QMessageBox::No);
    if (box.exec() != QMessageBox::Yes) return;

    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if (!ctx.isValid()) { showError(tr("Wallet locked. Please unlock to settle.")); return; }

    WalletModel::OptionSeriesActionResult r = walletModel->optionSeriesSettle(terms, lot);
    if (!r.success) { optStatusText->append(tr("✗ Settle failed: %1").arg(r.error)); showError(r.error); return; }
    optStatusText->append(tr("✓ %1 (txid %2)").arg(r.detail).arg(r.txid));
    // Settle → redeem self-contained: if ITM, auto-fill the funded pot so 'Redeem pot' is one click away.
    if (!r.pot_outpoint.isEmpty()) {
        optRedeemPotEdit->setText(r.pot_outpoint);
        optStatusText->append(tr("  → funded pot %1 filled in below; click 'Redeem pot' to claim it.").arg(r.pot_outpoint));
    }
    if (row >= 0) optSeriesTable->setItem(row, 3, new QTableWidgetItem(tr("(stale — re-verify)")));
}

void TreasuryPage::onOptBuyback()
{
    if (!walletModel) { showError(tr("Wallet not ready")); return; }
    const int row = optSeriesTable->currentRow();
    QTableWidgetItem* idItem = row >= 0 ? optSeriesTable->item(row, 0) : nullptr;
    if (!idItem) { showError(tr("Select a series first.")); return; }
    const QString terms = idItem->data(Qt::UserRole + 2).toString();
    const int lot = optLotIndexSpin->value();
    if (terms.isEmpty()) { showError(tr("Selected series has no terms to act on.")); return; }

    QMessageBox box(TopLevelDialogParent(this));
    box.setWindowTitle(tr("Confirm Buy-back"));
    box.setText(tr("Buy back lot %1 of the selected series?\n\nThis spends the lot vault, retires one repurchased "
                   "unit, and reclaims the collateral to the writer. Requires control of the writer key and at "
                   "least one unit.").arg(lot));
    box.setIcon(QMessageBox::Question);
    box.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
    box.setDefaultButton(QMessageBox::No);
    if (box.exec() != QMessageBox::Yes) return;

    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if (!ctx.isValid()) { showError(tr("Wallet locked. Please unlock to buy back.")); return; }

    WalletModel::OptionSeriesActionResult r = walletModel->optionSeriesBuyback(terms, lot);
    if (!r.success) { optStatusText->append(tr("✗ Buy-back failed: %1").arg(r.error)); showError(r.error); return; }
    optStatusText->append(tr("✓ %1 (txid %2)").arg(r.detail).arg(r.txid));
    if (row >= 0) optSeriesTable->setItem(row, 3, new QTableWidgetItem(tr("(stale — re-verify)")));
}

void TreasuryPage::onOptRedeem()
{
    if (!walletModel) { showError(tr("Wallet not ready")); return; }
    const int row = optSeriesTable->currentRow();
    QTableWidgetItem* idItem = row >= 0 ? optSeriesTable->item(row, 0) : nullptr;
    if (!idItem) { showError(tr("Select a series first.")); return; }
    const QString terms = idItem->data(Qt::UserRole + 2).toString();
    const int lot = optLotIndexSpin->value();
    const QString pot = optRedeemPotEdit->text().trimmed();
    if (terms.isEmpty()) { showError(tr("Selected series has no terms to act on.")); return; }
    if (pot.isEmpty() || !pot.contains(':')) { showError(tr("Enter the settlement pot outpoint as txid:vout.")); return; }

    QMessageBox box(TopLevelDialogParent(this));
    box.setWindowTitle(tr("Confirm Redemption"));
    box.setText(tr("Redeem pot %1 for lot %2?\n\nThis retires one of your option units to the lot sink and sweeps "
                   "the pot value to you.").arg(pot).arg(lot));
    box.setIcon(QMessageBox::Question);
    box.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
    box.setDefaultButton(QMessageBox::No);
    if (box.exec() != QMessageBox::Yes) return;

    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if (!ctx.isValid()) { showError(tr("Wallet locked. Please unlock to redeem.")); return; }

    WalletModel::OptionSeriesActionResult r = walletModel->optionSeriesRedeem(terms, lot, pot);
    if (!r.success) { optStatusText->append(tr("✗ Redeem failed: %1").arg(r.error)); showError(r.error); return; }
    optStatusText->append(tr("✓ %1 (txid %2)").arg(r.detail).arg(r.txid));
    optRedeemPotEdit->clear();
    if (row >= 0) optSeriesTable->setItem(row, 3, new QTableWidgetItem(tr("(stale — re-verify)")));
}

// ============================================================================
// CFD Asset Series (scalar note pair) — issuer create/issue/record + keeper
// lifecycle, plus the scalar feed publisher the notes settle against.
// (CFD_GENERALISATION.md §6/§7. Mirrors the Option Series tab, two-sided.)
// ============================================================================

namespace {
//! A canonical 64-char lowercase-hex check for the uint256 leaf operands (strike / fallback / ids / salt).
bool IsHex64(const QString& s)
{
    if (s.size() != 64) return false;
    for (const QChar& c : s) {
        const char ch = c.toLatin1();
        if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F'))) return false;
    }
    return true;
}

//! Parse a full uint32 from a line edit (the RPC feed_id domain is uint32; a QSpinBox only spans int).
bool ParseU32(const QString& s, quint32& out)
{
    bool ok = false;
    const qulonglong v = s.trimmed().toULongLong(&ok);
    if (!ok || v > 0xFFFFFFFFULL) return false;
    out = static_cast<quint32>(v);
    return true;
}
} // namespace

void TreasuryPage::setupCfdSeriesTab()
{
    cfdSeriesTab = new QWidget();
    QVBoxLayout* tabLayout = new QVBoxLayout(cfdSeriesTab);
    QScrollArea* scroll = new QScrollArea();
    scroll->setWidgetResizable(true);
    QWidget* content = new QWidget();
    QVBoxLayout* outer = new QVBoxLayout(content);

    QLabel* intro = new QLabel(tr(
        "<b>CFD asset series (scalar note pair).</b> A securitised two-sided CFD: register a long token <b>L</b> "
        "and a short token <b>S</b> as sponsored children, then issue N units of each and fund N "
        "<tt>OP_SCALAR_CFD_SETTLE</tt> vaults. Each lot settles on a scalar <i>you publish</i> as the asset issuer "
        "(or the committed fallback if you never publish), and any holder of 1 L + 1 S can unwind a lot for the "
        "full collateral at any time. This differs from a difficulty Option Series: two-sided, native or asset "
        "collateral, and a permissionless complete-set unwind."));
    intro->setWordWrap(true);
    outer->addWidget(intro);

    // ── Scalar feed publisher ───────────────────────────────────────────────────────────────────────────
    QGroupBox* feedGroup = new QGroupBox(tr("Scalar feed publisher (issuer oracle)"));
    QFormLayout* feedForm = new QFormLayout();

    cfdFeedAssetCombo = new QComboBox();
    cfdFeedAssetCombo->setToolTip(tr("A wallet-controlled asset whose ICU you spend to publish the feed value."));
    feedForm->addRow(tr("Feed asset (U):"), cfdFeedAssetCombo);

    cfdFeedIdEdit = new QLineEdit(QStringLiteral("0"));
    cfdFeedIdEdit->setToolTip(tr("Which feed of this asset (uint32). One asset can publish many independent feeds."));
    feedForm->addRow(tr("Feed id:"), cfdFeedIdEdit);

    {
        QWidget* w = new QWidget();
        QHBoxLayout* h = new QHBoxLayout(w); h->setContentsMargins(0, 0, 0, 0);
        cfdFeedIcuEdit = new QLineEdit();
        cfdFeedIcuEdit->setPlaceholderText(tr("current ICU outpoint  txid:vout"));
        cfdFeedIcuEdit->setToolTip(tr("The asset's current ICU. Click 'Lookup' to fill this and the next epoch."));
        cfdFeedLookupButton = new QPushButton(tr("Lookup"));
        h->addWidget(cfdFeedIcuEdit, 1); h->addWidget(cfdFeedLookupButton);
        feedForm->addRow(tr("Current ICU:"), w);
    }

    {
        QWidget* w = new QWidget();
        QHBoxLayout* h = new QHBoxLayout(w); h->setContentsMargins(0, 0, 0, 0);
        cfdFeedNewIcuAddrEdit = new QLineEdit();
        cfdFeedNewIcuAddrEdit->setPlaceholderText(tr("successor ICU address (wallet bech32m)"));
        cfdFeedNewIcuAddrButton = new QPushButton(tr("New address"));
        h->addWidget(cfdFeedNewIcuAddrEdit, 1); h->addWidget(cfdFeedNewIcuAddrButton);
        feedForm->addRow(tr("Successor ICU:"), w);
    }

    cfdFeedNewIcuAmtEdit = new QLineEdit();
    cfdFeedNewIcuAmtEdit->setPlaceholderText(tr("successor bond, TSC (>= rotation floor)"));
    cfdFeedNewIcuAmtEdit->setToolTip(tr("The successor ICU's bond. Must be >= the rotation floor (Lookup pre-fills it)."));
    feedForm->addRow(tr("Successor bond (TSC):"), cfdFeedNewIcuAmtEdit);

    cfdFeedEpochEdit = new QLineEdit();
    cfdFeedEpochEdit->setPlaceholderText(tr("scalar_epoch — must equal head+1 (or 1)"));
    cfdFeedEpochEdit->setToolTip(tr("Monotone, append-only per (asset, feed). Lookup fills head+1."));
    feedForm->addRow(tr("Epoch:"), cfdFeedEpochEdit);

    cfdFeedScalarEdit = new QLineEdit();
    cfdFeedScalarEdit->setPlaceholderText(tr("scalar value — 64 hex (uint256 display hex)"));
    cfdFeedScalarEdit->setToolTip(tr("The published value, interpreted per scalar_format_id. Contracts that committed "
                                     "this (asset, feed, epoch) read it at settlement."));
    feedForm->addRow(tr("Scalar (hex):"), cfdFeedScalarEdit);

    cfdFeedFormatSpin = new QSpinBox();
    cfdFeedFormatSpin->setRange(1, 65535);
    cfdFeedFormatSpin->setValue(assets::SCALAR_FORMAT_RAW_U256_LE);
    cfdFeedFormatSpin->setToolTip(tr("Scalar encoding id (default RAW_U256_LE). Must match the leaf's committed format."));
    feedForm->addRow(tr("Format id:"), cfdFeedFormatSpin);

    cfdFeedRateEdit = new QLineEdit(QStringLiteral("5"));
    feedForm->addRow(tr("Fee rate (sat/vB):"), cfdFeedRateEdit);

    feedGroup->setLayout(feedForm);
    outer->addWidget(feedGroup);

    QHBoxLayout* feedBtns = new QHBoxLayout();
    cfdFeedPublishButton = new QPushButton(tr("Publish scalar"));
    feedBtns->addWidget(cfdFeedPublishButton);
    feedBtns->addStretch();
    feedBtns->addWidget(new QLabel(tr("Read epoch:")));
    cfdFeedReadEpochEdit = new QLineEdit();
    cfdFeedReadEpochEdit->setPlaceholderText(tr("blank = latest"));
    cfdFeedReadEpochEdit->setMaximumWidth(120);
    feedBtns->addWidget(cfdFeedReadEpochEdit);
    cfdFeedReadButton = new QPushButton(tr("Read feed"));
    feedBtns->addWidget(cfdFeedReadButton);
    outer->addLayout(feedBtns);

    cfdFeedReadLabel = new QLabel();
    cfdFeedReadLabel->setWordWrap(true);
    cfdFeedReadLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    cfdFeedReadLabel->setStyleSheet("color:#9ad; font-family: monospace;");
    outer->addWidget(cfdFeedReadLabel);

    cfdFeedStatusText = new QTextEdit();
    cfdFeedStatusText->setReadOnly(true);
    cfdFeedStatusText->setMaximumHeight(90);
    outer->addWidget(cfdFeedStatusText);

    // ── Note-pair terms ─────────────────────────────────────────────────────────────────────────────────
    QGroupBox* termsGroup = new QGroupBox(tr("Note-pair terms"));
    QFormLayout* form = new QFormLayout();

    cfdParentCombo = new QComboBox();
    cfdParentCombo->setToolTip(tr("A wallet-controlled root namespace to sponsor the L and S children under."));
    form->addRow(tr("Sponsoring root:"), cfdParentCombo);

    {
        QWidget* w = new QWidget();
        QHBoxLayout* h = new QHBoxLayout(w); h->setContentsMargins(0, 0, 0, 0);
        cfdLongSuffixEdit = new QLineEdit();
        cfdLongSuffixEdit->setPlaceholderText(tr("L suffix (e.g. U6L)"));
        cfdShortSuffixEdit = new QLineEdit();
        cfdShortSuffixEdit->setPlaceholderText(tr("S suffix (e.g. U6S)"));
        h->addWidget(cfdLongSuffixEdit); h->addWidget(cfdShortSuffixEdit);
        form->addRow(tr("Long / Short suffix:"), w);
    }
    cfdPairIdLabel = new QLabel(tr("(register to preview the pair id)"));
    cfdPairIdLabel->setStyleSheet("color:#888; font-family: monospace;");
    cfdPairIdLabel->setWordWrap(true);
    form->addRow(tr("Tickers:"), cfdPairIdLabel);

    cfdPayoffModeCombo = new QComboBox();
    cfdPayoffModeCombo->addItem(tr("STRIKE — |X-K|/K (percent move from strike)"), static_cast<int>(ScalarCfdPayoffMode::STRIKE));
    cfdPayoffModeCombo->addItem(tr("REALIZED — |X-K|/X (difficulty semantics)"), static_cast<int>(ScalarCfdPayoffMode::REALIZED));
    form->addRow(tr("Payoff mode:"), cfdPayoffModeCombo);

    cfdLossDirCombo = new QComboBox();
    cfdLossDirCombo->addItem(tr("Owner is LONG (token L tracks the owner leg)"), 0);
    cfdLossDirCombo->addItem(tr("Owner is SHORT (token S tracks the owner leg)"), 1);
    form->addRow(tr("Owner direction:"), cfdLossDirCombo);

    cfdUnderlyingEdit = new QLineEdit();
    cfdUnderlyingEdit->setPlaceholderText(tr("U — feed asset id, 64 hex (auto-fills from the feed asset above)"));
    cfdUnderlyingEdit->setToolTip(tr("The asset whose published feed settles these notes. Trust = that asset's issuer."));
    form->addRow(tr("Underlying (U):"), cfdUnderlyingEdit);

    cfdSeriesFeedIdEdit = new QLineEdit(QStringLiteral("0"));
    cfdSeriesFeedIdEdit->setToolTip(tr("Feed of U this note settles against (uint32) — must match the published feed."));
    form->addRow(tr("Feed id:"), cfdSeriesFeedIdEdit);

    cfdFixingRefEdit = new QLineEdit();
    cfdFixingRefEdit->setPlaceholderText(tr("scalar_epoch this note settles against (u64)"));
    cfdFixingRefEdit->setToolTip(tr("The future epoch the notes read at settlement. Publish that epoch before the deadline."));
    form->addRow(tr("Fixing epoch:"), cfdFixingRefEdit);

    cfdDeadlineHeightEdit = new QLineEdit();
    cfdDeadlineHeightEdit->setPlaceholderText(tr("publication_deadline_height (u32)"));
    cfdDeadlineHeightEdit->setToolTip(tr("Last height a real fixing counts. After deadline + grace, the fallback fires."));
    form->addRow(tr("Deadline height:"), cfdDeadlineHeightEdit);

    cfdSettleLockEdit = new QLineEdit();
    cfdSettleLockEdit->setPlaceholderText(tr("settle_lock_height (CLTV, u32)"));
    cfdSettleLockEdit->setToolTip(tr("Belt-and-suspenders CLTV before a lot may settle (>= activation, ideally + maturity)."));
    form->addRow(tr("Settle-lock height:"), cfdSettleLockEdit);

    cfdFormatSpin = new QSpinBox();
    cfdFormatSpin->setRange(1, 65535);
    cfdFormatSpin->setValue(assets::SCALAR_FORMAT_RAW_U256_LE);
    cfdFormatSpin->setToolTip(tr("Scalar encoding id — MUST equal the published feed's scalar_format_id."));
    form->addRow(tr("Scalar format id:"), cfdFormatSpin);

    cfdStrikeEdit = new QLineEdit();
    cfdStrikeEdit->setPlaceholderText(tr("strike K — 64 hex in the chosen format"));
    form->addRow(tr("Strike (K, hex):"), cfdStrikeEdit);

    cfdFallbackEdit = new QLineEdit();
    cfdFallbackEdit->setPlaceholderText(tr("fallback_scalar — 64 hex (fires if no in-time fixing)"));
    cfdFallbackEdit->setToolTip(tr("Used iff no usable real fixing by deadline + grace. A neutral value refunds at fair."));
    form->addRow(tr("Fallback (hex):"), cfdFallbackEdit);

    cfdLeverageEdit = new QLineEdit(QStringLiteral("1.0"));
    cfdLeverageEdit->setToolTip(tr("Leverage ×. A move of m%% past strike pays leverage × m%% of the lot IM (capped at the IM)."));
    form->addRow(tr("Leverage (×):"), cfdLeverageEdit);

    // §5.1: only COLLATERAL_SAFE assets can back a long-dated note (else settlement can be griefed/trapped).
    // The combo is filtered to native + wallet-controlled collateral-safe assets; "Custom…" reveals a raw-hex
    // field for an externally-held safe asset. Populated by refreshAssetList (the policy bit is read for free
    // from each asset's IssuerReg during the controlled-asset scan).
    cfdCollateralCombo = new QComboBox();
    cfdCollateralCombo->setToolTip(tr("Per-lot IM / payout asset. Only COLLATERAL_SAFE assets qualify (§5.1); "
                                      "Native TSC always does. Pick 'Custom…' to enter a safe asset id by hand."));
    cfdCollateralCombo->addItem(tr("Native (TSC)"), QString());            // empty data = native sentinel
    cfdCollateralCombo->addItem(tr("Custom (enter id)…"), QStringLiteral("custom"));
    form->addRow(tr("Collateral (C):"), cfdCollateralCombo);

    cfdCollateralEdit = new QLineEdit();
    cfdCollateralEdit->setPlaceholderText(tr("collateral-safe asset C — 64 hex"));
    cfdCollateralEdit->setToolTip(tr("A non-native C must carry the COLLATERAL_SAFE bit or settlement is rejected (§5.1)."));
    cfdCollateralEdit->setVisible(false);                                  // only for the Custom entry
    form->addRow(QString(), cfdCollateralEdit);

    cfdVaultImEdit = new QLineEdit();
    cfdVaultImEdit->setPlaceholderText(tr("per-lot IM in C's units (sats if native)"));
    cfdVaultImEdit->setToolTip(tr("Collateral backing each lot = the maximum total payout split between the two pots."));
    form->addRow(tr("Lot IM (units):"), cfdVaultImEdit);

    cfdLotCountSpin = new QSpinBox();
    cfdLotCountSpin->setRange(1, 120);
    cfdLotCountSpin->setValue(10);
    cfdLotCountSpin->setToolTip(tr("N — the number of L and S units, and the number of backing vaults."));
    form->addRow(tr("Lot count (N):"), cfdLotCountSpin);

    {
        QWidget* w = new QWidget();
        QHBoxLayout* h = new QHBoxLayout(w); h->setContentsMargins(0, 0, 0, 0);
        cfdSaltEdit = new QLineEdit();
        cfdSaltEdit->setPlaceholderText(tr("64 hex (auto-generated if left blank)"));
        cfdSaltGenButton = new QPushButton(tr("Generate"));
        h->addWidget(cfdSaltEdit, 1); h->addWidget(cfdSaltGenButton);
        form->addRow(tr("Series salt:"), w);
    }

    cfdBondEdit = new QLineEdit(QStringLiteral("0.0001"));
    cfdBondEdit->setToolTip(tr("Per-child ICU bond (TSC). The low default is the consensus child floor."));
    form->addRow(tr("Child bond (TSC):"), cfdBondEdit);

    cfdVaultNativeEdit = new QLineEdit(QStringLiteral("0.00000546"));
    cfdVaultNativeEdit->setToolTip(tr("Native carrier per asset-collateral vault (>= dust). Ignored for native collateral."));
    form->addRow(tr("Vault native carrier (TSC):"), cfdVaultNativeEdit);

    cfdFeeRateEdit = new QLineEdit(QStringLiteral("5"));
    form->addRow(tr("Fee rate (sat/vB):"), cfdFeeRateEdit);

    termsGroup->setLayout(form);
    outer->addWidget(termsGroup);

    QHBoxLayout* btns = new QHBoxLayout();
    cfdRegisterButton = new QPushButton(tr("1. Register pair"));
    cfdIssueButton = new QPushButton(tr("2. Issue pair"));
    cfdRecordButton = new QPushButton(tr("3. Record issue"));
    cfdResetButton = new QPushButton(tr("New pair"));
    cfdResumeButton = new QPushButton(tr("Resume draft"));
    cfdResumeButton->setToolTip(tr("Restore an in-progress pair (terms, salt and register/issue txids) saved on this machine."));
    btns->addWidget(cfdRegisterButton);
    btns->addWidget(cfdIssueButton);
    btns->addWidget(cfdRecordButton);
    btns->addWidget(cfdResetButton);
    btns->addWidget(cfdResumeButton);
    outer->addLayout(btns);

    cfdStatusText = new QTextEdit();
    cfdStatusText->setReadOnly(true);
    cfdStatusText->setMaximumHeight(150);
    outer->addWidget(cfdStatusText);

    // ── Recorded pairs + lifecycle actions ──────────────────────────────────────────────────────────────
    QGroupBox* listGroup = new QGroupBox(tr("Recorded note pairs"));
    QVBoxLayout* listLayout = new QVBoxLayout();
    QHBoxLayout* listBtns = new QHBoxLayout();
    cfdRefreshListButton = new QPushButton(tr("Refresh list"));
    listBtns->addWidget(cfdRefreshListButton);
    listBtns->addStretch();
    listLayout->addLayout(listBtns);

    cfdPairTable = new QTableWidget(0, 4);
    cfdPairTable->setHorizontalHeaderLabels({tr("Pair ID"), tr("Lots"), tr("Issue tx"), tr("Vaults")});
    cfdPairTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    cfdPairTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    cfdPairTable->setSelectionMode(QAbstractItemView::SingleSelection);
    cfdPairTable->horizontalHeader()->setStretchLastSection(true);
    cfdPairTable->setMinimumHeight(140);
    listLayout->addWidget(cfdPairTable);

    QHBoxLayout* lotRow = new QHBoxLayout();
    lotRow->addWidget(new QLabel(tr("Lot:")));
    cfdLotIndexSpin = new QSpinBox();
    cfdLotIndexSpin->setRange(0, 0);
    lotRow->addWidget(cfdLotIndexSpin);
    lotRow->addWidget(new QLabel(tr("Vault:")));
    cfdVaultOutpointEdit = new QLineEdit();
    cfdVaultOutpointEdit->setPlaceholderText(tr("lot vault outpoint  txid:vout"));
    lotRow->addWidget(cfdVaultOutpointEdit, 1);
    cfdSettleButton = new QPushButton(tr("Settle lot"));
    cfdSettleButton->setToolTip(tr("Keeper settlement once the fixing (or fallback) is usable and the CLTV is open."));
    cfdUnwindButton = new QPushButton(tr("Unwind (1L+1S)"));
    cfdUnwindButton->setToolTip(tr("Permissionless complete-set collapse: retire 1 L + 1 S, reclaim the full collateral."));
    lotRow->addWidget(cfdSettleButton);
    lotRow->addWidget(cfdUnwindButton);
    listLayout->addLayout(lotRow);

    QHBoxLayout* redeemRow = new QHBoxLayout();
    redeemRow->addWidget(new QLabel(tr("Redeem:")));
    cfdRedeemSideCombo = new QComboBox();
    cfdRedeemSideCombo->addItem(tr("Long (L)"), true);
    cfdRedeemSideCombo->addItem(tr("Short (S)"), false);
    redeemRow->addWidget(cfdRedeemSideCombo);
    redeemRow->addWidget(new QLabel(tr("Pot:")));
    cfdRedeemPotEdit = new QLineEdit();
    cfdRedeemPotEdit->setPlaceholderText(tr("settlement pot outpoint  txid:vout"));
    redeemRow->addWidget(cfdRedeemPotEdit, 1);
    cfdRedeemButton = new QPushButton(tr("Redeem pot"));
    redeemRow->addWidget(cfdRedeemButton);
    listLayout->addLayout(redeemRow);

    cfdSettleButton->setEnabled(false);
    cfdUnwindButton->setEnabled(false);
    cfdRedeemButton->setEnabled(false);

    listGroup->setLayout(listLayout);
    outer->addWidget(listGroup);
    outer->addStretch();

    scroll->setWidget(content);
    tabLayout->addWidget(scroll);

    // Step gating: only register is available until a pair is registered + confirmed.
    cfdIssueButton->setEnabled(false);
    cfdRecordButton->setEnabled(false);

    connect(cfdSaltGenButton, &QPushButton::clicked, this, &TreasuryPage::onCfdGenSalt);
    connect(cfdLongSuffixEdit, &QLineEdit::textChanged, this, &TreasuryPage::onCfdPairPreview);
    connect(cfdShortSuffixEdit, &QLineEdit::textChanged, this, &TreasuryPage::onCfdPairPreview);
    connect(cfdParentCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &TreasuryPage::onCfdPairPreview);
    connect(cfdRegisterButton, &QPushButton::clicked, this, &TreasuryPage::onCfdRegister);
    connect(cfdIssueButton, &QPushButton::clicked, this, &TreasuryPage::onCfdIssue);
    connect(cfdRecordButton, &QPushButton::clicked, this, &TreasuryPage::onCfdRecord);
    connect(cfdResetButton, &QPushButton::clicked, this, &TreasuryPage::onCfdReset);
    connect(cfdResumeButton, &QPushButton::clicked, this, &TreasuryPage::onCfdResume);
    connect(cfdCollateralCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &TreasuryPage::onCfdCollateralChanged);
    connect(cfdRefreshListButton, &QPushButton::clicked, this, &TreasuryPage::onCfdRefreshList);
    connect(cfdPairTable, &QTableWidget::itemSelectionChanged, this, &TreasuryPage::onCfdPairSelectionChanged);
    connect(cfdLotIndexSpin, QOverload<int>::of(&QSpinBox::valueChanged), this, &TreasuryPage::onCfdLotIndexChanged);
    connect(cfdSettleButton, &QPushButton::clicked, this, &TreasuryPage::onCfdSettle);
    connect(cfdUnwindButton, &QPushButton::clicked, this, &TreasuryPage::onCfdUnwind);
    connect(cfdRedeemSideCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &TreasuryPage::onCfdRedeemSideChanged);
    connect(cfdRedeemButton, &QPushButton::clicked, this, &TreasuryPage::onCfdRedeem);
    connect(cfdFeedLookupButton, &QPushButton::clicked, this, &TreasuryPage::onCfdFeedLookup);
    connect(cfdFeedNewIcuAddrButton, &QPushButton::clicked, this, &TreasuryPage::onCfdFeedNewAddr);
    connect(cfdFeedPublishButton, &QPushButton::clicked, this, &TreasuryPage::onCfdFeedPublish);
    connect(cfdFeedReadButton, &QPushButton::clicked, this, &TreasuryPage::onCfdFeedRead);
    // Default the contract's underlying U from the chosen feed asset (the common single-issuer case).
    connect(cfdFeedAssetCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this](int) {
        if (cfdFeedAssetCombo && cfdUnderlyingEdit && cfdUnderlyingEdit->text().trimmed().isEmpty() && cfdFeedAssetCombo->count() > 0) {
            cfdUnderlyingEdit->setText(cfdFeedAssetCombo->currentData().toString());
        }
    });
    { QSettings s; cfdResumeButton->setEnabled(s.value(QStringLiteral("ScalarNotePairDraft/active"), false).toBool()); }
}

// ============================================================================
// Bilateral CFD tab (two-party scalar CFD on an FX cross rate; scalarcfd.*).
// Propose/accept/import handshake -> atomic co-signed open -> unilateral settle
// (or 2-of-2 cooperative close) -> mark-to-market price. (CFD_GENERALISATION.md §7.)
// ============================================================================

void TreasuryPage::setupBilateralCfdTab()
{
    scfdTab = new QWidget();
    QVBoxLayout* tabLayout = new QVBoxLayout(scfdTab);
    QScrollArea* scroll = new QScrollArea();
    scroll->setWidgetResizable(true);
    QWidget* content = new QWidget();
    QVBoxLayout* outer = new QVBoxLayout(content);

    QLabel* intro = new QLabel(tr(
        "<b>Bilateral scalar CFD.</b> A two-party contract on an issuer-published FX cross rate X = base/quote: "
        "a long and a short leg, each its own <tt>OP_SCALAR_CFD_SETTLE</tt> vault, with an atomic co-signed open "
        "and a 2-of-2 cooperative close. The proposer creates an offer; the counterparty accepts (returning an "
        "acceptance); the proposer imports it; both then co-fund the open, and either party can settle a leg after "
        "the fixing, or both can cooperatively close early. Offers/acceptances/PSBTs are exchanged out-of-band."));
    intro->setWordWrap(true);
    outer->addWidget(intro);

    // ── 1. Propose ──────────────────────────────────────────────────────────────────────────────────────
    QGroupBox* proposeGroup = new QGroupBox(tr("1. Propose (define economics + your side)"));
    QFormLayout* pf = new QFormLayout();
    scfdPayoffModeCombo = new QComboBox(); scfdPayoffModeCombo->addItem(tr("STRIKE (denom K)")); scfdPayoffModeCombo->addItem(tr("REALIZED (denom X)"));
    pf->addRow(tr("Payoff mode:"), scfdPayoffModeCombo);
    scfdRoleCombo = new QComboBox(); scfdRoleCombo->addItem(tr("long")); scfdRoleCombo->addItem(tr("short"));
    pf->addRow(tr("Your side:"), scfdRoleCombo);
    scfdUnderlyingEdit = new QLineEdit(); scfdUnderlyingEdit->setPlaceholderText(tr("underlying U asset id (64-hex)"));
    pf->addRow(tr("Underlying (U):"), scfdUnderlyingEdit);
    scfdFeedIdEdit = new QLineEdit(QStringLiteral("0")); pf->addRow(tr("Feed id:"), scfdFeedIdEdit);
    scfdFixingRefEdit = new QLineEdit(QStringLiteral("1")); pf->addRow(tr("Fixing ref (epoch):"), scfdFixingRefEdit);
    scfdDeadlineEdit = new QLineEdit(); scfdDeadlineEdit->setPlaceholderText(tr("publication_deadline_height")); pf->addRow(tr("Deadline height:"), scfdDeadlineEdit);
    scfdSettleLockEdit = new QLineEdit(); scfdSettleLockEdit->setPlaceholderText(tr("settle_lock_height (CLTV)")); pf->addRow(tr("Settle lock height:"), scfdSettleLockEdit);
    scfdFormatSpin = new QSpinBox(); scfdFormatSpin->setRange(0, 65535); scfdFormatSpin->setValue(1); pf->addRow(tr("Scalar format id:"), scfdFormatSpin);
    scfdStrikeEdit = new QLineEdit(); scfdStrikeEdit->setPlaceholderText(tr("strike K (64-hex)")); pf->addRow(tr("Strike (K):"), scfdStrikeEdit);
    scfdFallbackEdit = new QLineEdit(); scfdFallbackEdit->setPlaceholderText(tr("fallback_scalar (64-hex)")); pf->addRow(tr("Fallback:"), scfdFallbackEdit);
    scfdCollateralEdit = new QLineEdit();
    scfdCollateralEdit->setPlaceholderText(tr("native TSC only — asset-collateral open is not yet supported"));
    scfdCollateralEdit->setEnabled(false); // build_open is native-only; don't let the UI persist an unopenable contract
    pf->addRow(tr("Collateral (C):"), scfdCollateralEdit);
    scfdLongImEdit = new QLineEdit(); scfdLongImEdit->setPlaceholderText(tr("collateral units (sats if native)")); pf->addRow(tr("Long IM:"), scfdLongImEdit);
    scfdLongLevEdit = new QLineEdit(QStringLiteral("1")); pf->addRow(tr("Long leverage (x):"), scfdLongLevEdit);
    scfdShortImEdit = new QLineEdit(); pf->addRow(tr("Short IM:"), scfdShortImEdit);
    scfdShortLevEdit = new QLineEdit(QStringLiteral("1")); pf->addRow(tr("Short leverage (x):"), scfdShortLevEdit);
    {
        QWidget* w = new QWidget(); QHBoxLayout* h = new QHBoxLayout(w); h->setContentsMargins(0,0,0,0);
        scfdProposeOwnerEdit = new QLineEdit(); scfdProposeOwnerEdit->setPlaceholderText(tr("your owner payout (P2TR)"));
        scfdProposeOwnerBtn = new QPushButton(tr("New")); h->addWidget(scfdProposeOwnerEdit, 1); h->addWidget(scfdProposeOwnerBtn);
        pf->addRow(tr("Owner addr:"), w);
    }
    {
        QWidget* w = new QWidget(); QHBoxLayout* h = new QHBoxLayout(w); h->setContentsMargins(0,0,0,0);
        scfdProposeCpEdit = new QLineEdit(); scfdProposeCpEdit->setPlaceholderText(tr("your cp payout (P2TR)"));
        scfdProposeCpBtn = new QPushButton(tr("New")); h->addWidget(scfdProposeCpEdit, 1); h->addWidget(scfdProposeCpBtn);
        pf->addRow(tr("CP addr:"), w);
    }
    scfdProposeButton = new QPushButton(tr("Propose → offer"));
    pf->addRow(QString(), scfdProposeButton);
    scfdOfferOut = new QTextEdit(); scfdOfferOut->setReadOnly(true); scfdOfferOut->setMaximumHeight(90); scfdOfferOut->setPlaceholderText(tr("offer JSON (hand to the counterparty)"));
    pf->addRow(tr("Offer:"), scfdOfferOut);
    proposeGroup->setLayout(pf); outer->addWidget(proposeGroup);

    // ── 2. Accept ───────────────────────────────────────────────────────────────────────────────────────
    QGroupBox* acceptGroup = new QGroupBox(tr("2. Accept (counterparty)"));
    QFormLayout* af = new QFormLayout();
    scfdAcceptOfferIn = new QTextEdit(); scfdAcceptOfferIn->setMaximumHeight(80); scfdAcceptOfferIn->setPlaceholderText(tr("paste the offer JSON")); af->addRow(tr("Offer:"), scfdAcceptOfferIn);
    {
        QWidget* w = new QWidget(); QHBoxLayout* h = new QHBoxLayout(w); h->setContentsMargins(0,0,0,0);
        scfdAcceptOwnerEdit = new QLineEdit(); scfdAcceptOwnerEdit->setPlaceholderText(tr("your owner payout (P2TR)"));
        scfdAcceptOwnerBtn = new QPushButton(tr("New")); h->addWidget(scfdAcceptOwnerEdit, 1); h->addWidget(scfdAcceptOwnerBtn); af->addRow(tr("Owner addr:"), w);
    }
    {
        QWidget* w = new QWidget(); QHBoxLayout* h = new QHBoxLayout(w); h->setContentsMargins(0,0,0,0);
        scfdAcceptCpEdit = new QLineEdit(); scfdAcceptCpEdit->setPlaceholderText(tr("your cp payout (P2TR)"));
        scfdAcceptCpBtn = new QPushButton(tr("New")); h->addWidget(scfdAcceptCpEdit, 1); h->addWidget(scfdAcceptCpBtn); af->addRow(tr("CP addr:"), w);
    }
    scfdAcceptConfirm = new QCheckBox(tr("Confirm (persist + return acceptance)")); af->addRow(QString(), scfdAcceptConfirm);
    scfdAcceptButton = new QPushButton(tr("Accept")); af->addRow(QString(), scfdAcceptButton);
    scfdAcceptanceOut = new QTextEdit(); scfdAcceptanceOut->setReadOnly(true); scfdAcceptanceOut->setMaximumHeight(80); scfdAcceptanceOut->setPlaceholderText(tr("acceptance JSON (hand back to the proposer)")); af->addRow(tr("Acceptance:"), scfdAcceptanceOut);
    acceptGroup->setLayout(af); outer->addWidget(acceptGroup);

    // ── 3. Import acceptance (proposer) ──────────────────────────────────────────────────────────────────
    QGroupBox* importGroup = new QGroupBox(tr("3. Import acceptance (proposer)"));
    QFormLayout* imf = new QFormLayout();
    scfdImportOfferIn = new QTextEdit(); scfdImportOfferIn->setMaximumHeight(70); scfdImportOfferIn->setPlaceholderText(tr("your offer JSON")); imf->addRow(tr("Offer:"), scfdImportOfferIn);
    scfdImportAcceptanceIn = new QTextEdit(); scfdImportAcceptanceIn->setMaximumHeight(70); scfdImportAcceptanceIn->setPlaceholderText(tr("the acceptance JSON")); imf->addRow(tr("Acceptance:"), scfdImportAcceptanceIn);
    scfdImportButton = new QPushButton(tr("Import acceptance")); imf->addRow(QString(), scfdImportButton);
    importGroup->setLayout(imf); outer->addWidget(importGroup);

    // ── 4. Lifecycle (open / record / settle / coop / price) ─────────────────────────────────────────────
    QGroupBox* lifeGroup = new QGroupBox(tr("4. Lifecycle"));
    QFormLayout* lf = new QFormLayout();
    scfdContractIdEdit = new QLineEdit(); scfdContractIdEdit->setPlaceholderText(tr("contract id (64-hex)")); lf->addRow(tr("Contract id:"), scfdContractIdEdit);
    scfdLegCombo = new QComboBox(); scfdLegCombo->addItem(tr("long")); scfdLegCombo->addItem(tr("short")); lf->addRow(tr("Leg:"), scfdLegCombo);
    scfdFeeRateEdit = new QLineEdit(); scfdFeeRateEdit->setPlaceholderText(tr("fee rate sat/vB (optional)")); lf->addRow(tr("Fee rate:"), scfdFeeRateEdit);
    scfdOpenPsbtIn = new QTextEdit(); scfdOpenPsbtIn->setMaximumHeight(60); scfdOpenPsbtIn->setPlaceholderText(tr("counterparty partial open PSBT (2nd party only)")); lf->addRow(tr("Open PSBT in:"), scfdOpenPsbtIn);
    scfdBuildOpenButton = new QPushButton(tr("Build open")); lf->addRow(QString(), scfdBuildOpenButton);
    scfdOpenPsbtOut = new QTextEdit(); scfdOpenPsbtOut->setReadOnly(true); scfdOpenPsbtOut->setMaximumHeight(60); lf->addRow(tr("Open PSBT out:"), scfdOpenPsbtOut);
    {
        QWidget* w = new QWidget(); QHBoxLayout* h = new QHBoxLayout(w); h->setContentsMargins(0,0,0,0);
        scfdRecordTxidEdit = new QLineEdit(); scfdRecordTxidEdit->setPlaceholderText(tr("broadcast open txid"));
        scfdRecordOpenButton = new QPushButton(tr("Record open")); h->addWidget(scfdRecordTxidEdit, 1); h->addWidget(scfdRecordOpenButton); lf->addRow(tr("Record open:"), w);
    }
    scfdBuildSettleButton = new QPushButton(tr("Build settlement")); lf->addRow(QString(), scfdBuildSettleButton);
    scfdSettlePsbtOut = new QTextEdit(); scfdSettlePsbtOut->setReadOnly(true); scfdSettlePsbtOut->setMaximumHeight(60); lf->addRow(tr("Settle PSBT:"), scfdSettlePsbtOut);
    scfdFinalizeIn = new QTextEdit(); scfdFinalizeIn->setMaximumHeight(60); scfdFinalizeIn->setPlaceholderText(tr("settlement PSBT (fee input signed) → finalize")); lf->addRow(tr("Finalize PSBT:"), scfdFinalizeIn);
    scfdFinalizeButton = new QPushButton(tr("Finalize settlement → hex")); lf->addRow(QString(), scfdFinalizeButton);
    {
        QWidget* w = new QWidget(); QHBoxLayout* h = new QHBoxLayout(w); h->setContentsMargins(0,0,0,0);
        scfdCoopAddr1Edit = new QLineEdit(); scfdCoopAddr1Edit->setPlaceholderText(tr("coop out 1 addr"));
        scfdCoopAmt1Edit = new QLineEdit(); scfdCoopAmt1Edit->setPlaceholderText(tr("amt (BTC)")); scfdCoopAmt1Edit->setMaximumWidth(110);
        h->addWidget(scfdCoopAddr1Edit, 1); h->addWidget(scfdCoopAmt1Edit); lf->addRow(tr("Coop out 1:"), w);
    }
    {
        QWidget* w = new QWidget(); QHBoxLayout* h = new QHBoxLayout(w); h->setContentsMargins(0,0,0,0);
        scfdCoopAddr2Edit = new QLineEdit(); scfdCoopAddr2Edit->setPlaceholderText(tr("coop out 2 addr (optional)"));
        scfdCoopAmt2Edit = new QLineEdit(); scfdCoopAmt2Edit->setPlaceholderText(tr("amt (BTC)")); scfdCoopAmt2Edit->setMaximumWidth(110);
        h->addWidget(scfdCoopAddr2Edit, 1); h->addWidget(scfdCoopAmt2Edit); lf->addRow(tr("Coop out 2:"), w);
    }
    scfdBuildCoopButton = new QPushButton(tr("Build coop close")); lf->addRow(QString(), scfdBuildCoopButton);
    scfdCoopPsbtIO = new QTextEdit(); scfdCoopPsbtIO->setMaximumHeight(60); scfdCoopPsbtIO->setPlaceholderText(tr("coop PSBT (sign_coop round-trips here)")); lf->addRow(tr("Coop PSBT:"), scfdCoopPsbtIO);
    scfdSignCoopButton = new QPushButton(tr("Sign coop")); lf->addRow(QString(), scfdSignCoopButton);
    {
        QWidget* w = new QWidget(); QHBoxLayout* h = new QHBoxLayout(w); h->setContentsMargins(0,0,0,0);
        scfdPriceSigmaEdit = new QLineEdit(); scfdPriceSigmaEdit->setPlaceholderText(tr("sigma (optional)"));
        scfdPriceButton = new QPushButton(tr("Price (MTM)")); h->addWidget(scfdPriceSigmaEdit, 1); h->addWidget(scfdPriceButton); lf->addRow(tr("Price:"), w);
    }
    scfdPriceLabel = new QLabel(tr("(not priced)")); scfdPriceLabel->setWordWrap(true); lf->addRow(tr("MTM:"), scfdPriceLabel);
    lifeGroup->setLayout(lf); outer->addWidget(lifeGroup);

    scfdStatusText = new QTextEdit(); scfdStatusText->setReadOnly(true); scfdStatusText->setMaximumHeight(110);
    outer->addWidget(new QLabel(tr("Status:"))); outer->addWidget(scfdStatusText);
    outer->addStretch(1);

    scroll->setWidget(content);
    tabLayout->addWidget(scroll);

    connect(scfdProposeOwnerBtn, &QPushButton::clicked, this, &TreasuryPage::onScfdProposeOwnerAddr);
    connect(scfdProposeCpBtn, &QPushButton::clicked, this, &TreasuryPage::onScfdProposeCpAddr);
    connect(scfdAcceptOwnerBtn, &QPushButton::clicked, this, &TreasuryPage::onScfdAcceptOwnerAddr);
    connect(scfdAcceptCpBtn, &QPushButton::clicked, this, &TreasuryPage::onScfdAcceptCpAddr);
    connect(scfdProposeButton, &QPushButton::clicked, this, &TreasuryPage::onScfdPropose);
    connect(scfdAcceptButton, &QPushButton::clicked, this, &TreasuryPage::onScfdAccept);
    connect(scfdImportButton, &QPushButton::clicked, this, &TreasuryPage::onScfdImport);
    connect(scfdBuildOpenButton, &QPushButton::clicked, this, &TreasuryPage::onScfdBuildOpen);
    connect(scfdRecordOpenButton, &QPushButton::clicked, this, &TreasuryPage::onScfdRecordOpen);
    connect(scfdBuildSettleButton, &QPushButton::clicked, this, &TreasuryPage::onScfdBuildSettlement);
    connect(scfdFinalizeButton, &QPushButton::clicked, this, &TreasuryPage::onScfdFinalize);
    connect(scfdBuildCoopButton, &QPushButton::clicked, this, &TreasuryPage::onScfdBuildCoop);
    connect(scfdSignCoopButton, &QPushButton::clicked, this, &TreasuryPage::onScfdSignCoop);
    connect(scfdPriceButton, &QPushButton::clicked, this, &TreasuryPage::onScfdPrice);
}

void TreasuryPage::onScfdProposeOwnerAddr() { if (clientModel && walletModel) { try { UniValue p(UniValue::VARR); p.push_back(""); p.push_back("bech32m"); scfdProposeOwnerEdit->setText(QString::fromStdString(clientModel->node().executeRpc("getnewaddress", p, walletModel->getWalletName().toStdString()).get_str())); } catch (...) { showError(tr("Address generation failed.")); } } }
void TreasuryPage::onScfdProposeCpAddr() { if (clientModel && walletModel) { try { UniValue p(UniValue::VARR); p.push_back(""); p.push_back("bech32m"); scfdProposeCpEdit->setText(QString::fromStdString(clientModel->node().executeRpc("getnewaddress", p, walletModel->getWalletName().toStdString()).get_str())); } catch (...) { showError(tr("Address generation failed.")); } } }
void TreasuryPage::onScfdAcceptOwnerAddr() { if (clientModel && walletModel) { try { UniValue p(UniValue::VARR); p.push_back(""); p.push_back("bech32m"); scfdAcceptOwnerEdit->setText(QString::fromStdString(clientModel->node().executeRpc("getnewaddress", p, walletModel->getWalletName().toStdString()).get_str())); } catch (...) { showError(tr("Address generation failed.")); } } }
void TreasuryPage::onScfdAcceptCpAddr() { if (clientModel && walletModel) { try { UniValue p(UniValue::VARR); p.push_back(""); p.push_back("bech32m"); scfdAcceptCpEdit->setText(QString::fromStdString(clientModel->node().executeRpc("getnewaddress", p, walletModel->getWalletName().toStdString()).get_str())); } catch (...) { showError(tr("Address generation failed.")); } } }

void TreasuryPage::onScfdPropose()
{
    if (!walletModel) { showError(tr("Wallet not ready")); return; }
    WalletModel::ScalarCfdTermsInput t;
    t.source_type = 0;
    t.payoff_mode = scfdPayoffModeCombo->currentIndex();
    t.underlying_asset_id = scfdUnderlyingEdit->text().trimmed();
    quint32 v = 0;
    if (!ParseU32(scfdFeedIdEdit->text(), v)) { showError(tr("Invalid feed id")); return; } t.feed_id = v;
    bool okfr = false; t.fixing_ref = scfdFixingRefEdit->text().trimmed().toULongLong(&okfr);
    if (!okfr) { showError(tr("Invalid fixing ref (epoch)")); return; }
    if (!ParseU32(scfdDeadlineEdit->text(), v)) { showError(tr("Invalid deadline height")); return; } t.publication_deadline_height = v;
    if (!ParseU32(scfdSettleLockEdit->text(), v)) { showError(tr("Invalid settle lock height")); return; } t.settle_lock_height = v;
    t.scalar_format_id = scfdFormatSpin->value();
    t.strike = scfdStrikeEdit->text().trimmed();
    t.fallback_scalar = scfdFallbackEdit->text().trimmed();
    t.collateral_asset_id = scfdCollateralEdit->text().trimmed();
    if (!t.collateral_asset_id.isEmpty()) { showError(tr("Asset-collateral bilateral CFDs cannot be opened yet — leave Collateral blank (native TSC).")); return; }
    // Validate the per-leg IM (non-negative integer collateral units) + leverage (positive, finite, and a
    // lambda_q that fits uint32) IN THE GUI before the RPC — a negative/garbage entry must not silently
    // become a huge uint64/quint32.
    auto parseLeg = [&](QLineEdit* imE, QLineEdit* levE, WalletModel::ScalarCfdLegInput& leg, const QString& name) -> bool {
        bool ok = false;
        const qlonglong im = imE->text().trimmed().toLongLong(&ok);
        if (!ok || im < 0) { showError(tr("%1 IM must be a non-negative integer (collateral units).").arg(name)); return false; }
        bool okl = false;
        const double lev = levE->text().trimmed().toDouble(&okl);
        if (!okl || !std::isfinite(lev) || lev <= 0.0) { showError(tr("%1 leverage must be a positive number.").arg(name)); return false; }
        const double lq = lev * 65536.0;
        if (lq > 4294967295.0) { showError(tr("%1 leverage is too large.").arg(name)); return false; }
        leg.im_sats = im;
        leg.lambda_q = static_cast<quint32>(qRound64(lq));
        return true;
    };
    if (!parseLeg(scfdLongImEdit, scfdLongLevEdit, t.long_leg, tr("Long"))) return;
    if (!parseLeg(scfdShortImEdit, scfdShortLevEdit, t.short_leg, tr("Short"))) return;
    const bool isShort = scfdRoleCombo->currentIndex() == 1;
    auto r = walletModel->scalarCfdPropose(t, isShort, scfdProposeOwnerEdit->text().trimmed(), scfdProposeCpEdit->text().trimmed());
    if (!r.success) { showError(r.error); return; }
    scfdOfferOut->setPlainText(r.offer_json);
    scfdStatusText->append(tr("Proposed as %1 — hand the offer to the counterparty.").arg(isShort ? tr("short") : tr("long")));
}

void TreasuryPage::onScfdAccept()
{
    if (!walletModel) { showError(tr("Wallet not ready")); return; }
    auto r = walletModel->scalarCfdAccept(scfdAcceptOfferIn->toPlainText().trimmed(), scfdAcceptOwnerEdit->text().trimmed(),
                                          scfdAcceptCpEdit->text().trimmed(), scfdAcceptConfirm->isChecked());
    if (!r.success) { showError(r.error); return; }
    if (!r.contract_id.isEmpty()) { scfdContractIdEdit->setText(r.contract_id); scfdStatusText->append(tr("Contract id: %1").arg(r.contract_id)); }
    if (!r.acceptance_json.isEmpty()) { scfdAcceptanceOut->setPlainText(r.acceptance_json); scfdStatusText->append(tr("Accepted — hand the acceptance back to the proposer.")); }
    else if (!r.action_required.isEmpty()) scfdStatusText->append(tr("Review: %1").arg(r.action_required));
}

void TreasuryPage::onScfdImport()
{
    if (!walletModel) { showError(tr("Wallet not ready")); return; }
    auto r = walletModel->scalarCfdImportAcceptance(scfdImportOfferIn->toPlainText().trimmed(), scfdImportAcceptanceIn->toPlainText().trimmed());
    if (!r.success) { showError(r.error); return; }
    scfdContractIdEdit->setText(r.contract_id);
    scfdStatusText->append(tr("Imported acceptance — contract %1 is %2.").arg(r.contract_id, r.state));
}

void TreasuryPage::onScfdBuildOpen()
{
    if (!walletModel || !clientModel) { showError(tr("Wallet not ready")); return; }
    const bool isShort = scfdLegCombo->currentIndex() == 1;
    double fr = 0.0;
    if (!scfdFeeRateEdit->text().trimmed().isEmpty()) {
        bool okfr = false; fr = scfdFeeRateEdit->text().trimmed().toDouble(&okfr);
        if (!okfr || !std::isfinite(fr) || fr <= 0.0) { showError(tr("Invalid fee rate")); return; }
    }
    auto r = walletModel->scalarCfdBuildOpen(scfdContractIdEdit->text().trimmed(), isShort, scfdOpenPsbtIn->toPlainText().trimmed(), fr);
    if (!r.success) { showError(r.error); return; }
    // Sign THIS wallet's inputs in-GUI (walletprocesspsbt). When both legs are signed (the 2nd party,
    // augmenting the 1st party's already-signed PSBT) the open is a normal funding tx -> finalize + broadcast
    // directly and pre-fill the record txid; otherwise the partial-signed PSBT is handed to the counterparty.
    const std::string wname = walletModel->getWalletName().toStdString();
    try {
        UniValue pp(UniValue::VARR); pp.push_back(r.psbt.toStdString()); pp.push_back(true);
        UniValue pr = clientModel->node().executeRpc("walletprocesspsbt", pp, wname);
        const QString signedPsbt = QString::fromStdString(pr["psbt"].get_str());
        const bool complete = pr.exists("complete") && pr["complete"].get_bool();
        scfdOpenPsbtOut->setPlainText(signedPsbt);
        if (complete) {
            UniValue fp(UniValue::VARR); fp.push_back(signedPsbt.toStdString());
            UniValue fres = clientModel->node().executeRpc("finalizepsbt", fp, wname);
            if (fres.exists("complete") && fres["complete"].get_bool() && fres.exists("hex")) {
                UniValue sp(UniValue::VARR); sp.push_back(fres["hex"].get_str());
                const QString txid = QString::fromStdString(clientModel->node().executeRpc("sendrawtransaction", sp, wname).get_str());
                scfdRecordTxidEdit->setText(txid);
                scfdStatusText->append(tr("Open broadcast: %1 — now Record open in BOTH wallets.").arg(txid));
            } else {
                scfdStatusText->append(tr("Open PSBT fully signed — finalize + broadcast it (finalizepsbt)."));
            }
        } else {
            scfdStatusText->append(tr("Built + signed your inputs (%1 leg, vout %2, fee %3). Hand the PSBT to the counterparty to augment + co-sign.").arg(r.leg).arg(r.vault_index).arg(r.fee));
        }
    } catch (...) {
        scfdOpenPsbtOut->setPlainText(r.psbt);
        scfdStatusText->append(tr("Built open (%1 leg) — could not auto-sign; run walletprocesspsbt on it.").arg(r.leg));
    }
}

void TreasuryPage::onScfdRecordOpen()
{
    if (!walletModel) { showError(tr("Wallet not ready")); return; }
    auto r = walletModel->scalarCfdRecordOpen(scfdContractIdEdit->text().trimmed(), scfdRecordTxidEdit->text().trimmed());
    if (!r.success) { showError(r.error); return; }
    scfdStatusText->append(tr("Recorded open — long %1 / short %2.").arg(r.long_vault, r.short_vault));
}

void TreasuryPage::onScfdBuildSettlement()
{
    if (!walletModel || !clientModel) { showError(tr("Wallet not ready")); return; }
    const bool isShort = scfdLegCombo->currentIndex() == 1;
    double fr = 0.0;
    if (!scfdFeeRateEdit->text().trimmed().isEmpty()) {
        bool okfr = false; fr = scfdFeeRateEdit->text().trimmed().toDouble(&okfr);
        if (!okfr || !std::isfinite(fr) || fr <= 0.0) { showError(tr("Invalid fee rate")); return; }
    }
    auto r = walletModel->scalarCfdBuildSettlement(scfdContractIdEdit->text().trimmed(), isShort, fr);
    if (!r.success) { showError(r.error); return; }
    scfdSettlePsbtOut->setPlainText(r.psbt);
    // Sign the keeper fee input in-GUI (walletprocesspsbt) so the Finalize step has a complete fee input;
    // the vault covenant input is already finalized by build_settlement. Pre-fill the (signed) Finalize box.
    const std::string wname = walletModel->getWalletName().toStdString();
    try {
        UniValue pp(UniValue::VARR); pp.push_back(r.psbt.toStdString()); pp.push_back(true);
        UniValue pr = clientModel->node().executeRpc("walletprocesspsbt", pp, wname);
        scfdFinalizeIn->setPlainText(QString::fromStdString(pr["psbt"].get_str()));
        scfdStatusText->append(tr("Built settlement (%1 leg, owner %2 / cp %3%4) + signed the fee input — click Finalize, then broadcast/mine the hex.")
                                   .arg(isShort ? tr("short") : tr("long")).arg(r.payout_owner).arg(r.payout_cp)
                                   .arg(r.is_fallback ? tr(" — fallback") : QString()));
    } catch (...) {
        scfdFinalizeIn->setPlainText(r.psbt);
        scfdStatusText->append(tr("Built settlement (%1 leg) — sign the fee input (walletprocesspsbt) then Finalize.").arg(isShort ? tr("short") : tr("long")));
    }
}

void TreasuryPage::onScfdFinalize()
{
    if (!walletModel) { showError(tr("Wallet not ready")); return; }
    auto r = walletModel->scalarCfdFinalizeSettlement(scfdFinalizeIn->toPlainText().trimmed());
    if (!r.success) { showError(r.error); return; }
    scfdStatusText->append(tr("Finalized settlement — broadcast hex:\n%1").arg(r.hex));
}

void TreasuryPage::onScfdBuildCoop()
{
    if (!walletModel) { showError(tr("Wallet not ready")); return; }
    const bool isShort = scfdLegCombo->currentIndex() == 1;
    QList<QPair<QString, qint64>> outs;
    bool amtOk = true;
    auto add = [&](QLineEdit* a, QLineEdit* m) {
        const QString addr = a->text().trimmed();
        if (addr.isEmpty()) return;
        bool ok = false;
        const double amt = m->text().trimmed().toDouble(&ok);
        // Bound to MAX_MONEY (21,000,000 TSC) BEFORE the sats conversion so absurd input can't overflow/round badly.
        if (!ok || !std::isfinite(amt) || amt <= 0.0 || amt > 21000000.0) { showError(tr("Invalid coop output amount for %1 (0 < amount ≤ 21,000,000)").arg(addr)); amtOk = false; return; }
        outs.append({addr, static_cast<qint64>(qRound64(amt * 100000000.0))});
    };
    add(scfdCoopAddr1Edit, scfdCoopAmt1Edit);
    if (!amtOk) return;
    add(scfdCoopAddr2Edit, scfdCoopAmt2Edit);
    if (!amtOk) return;
    if (outs.isEmpty()) { showError(tr("Add at least one coop output")); return; }
    auto r = walletModel->scalarCfdBuildCoopClose(scfdContractIdEdit->text().trimmed(), isShort, outs);
    if (!r.success) { showError(r.error); return; }
    scfdCoopPsbtIO->setPlainText(r.psbt);
    scfdStatusText->append(tr("Built coop close (%1 leg, fee %2). Each party Signs coop in turn.").arg(isShort ? tr("short") : tr("long")).arg(r.fee));
}

void TreasuryPage::onScfdSignCoop()
{
    if (!walletModel) { showError(tr("Wallet not ready")); return; }
    const bool isShort = scfdLegCombo->currentIndex() == 1;
    auto r = walletModel->scalarCfdSignCoop(scfdContractIdEdit->text().trimmed(), isShort, scfdCoopPsbtIO->toPlainText().trimmed());
    if (!r.success) { showError(r.error); return; }
    scfdCoopPsbtIO->setPlainText(r.complete ? r.hex : r.psbt);
    scfdStatusText->append(r.complete ? tr("Coop close complete — broadcast the hex above.") : tr("Signed your half — pass the PSBT to the counterparty."));
}

void TreasuryPage::onScfdPrice()
{
    if (!walletModel) { showError(tr("Wallet not ready")); return; }
    double sigma = -1.0; // < 0 -> omit (resolved from curves/chain)
    if (!scfdPriceSigmaEdit->text().trimmed().isEmpty()) {
        bool ok = false; sigma = scfdPriceSigmaEdit->text().trimmed().toDouble(&ok);
        if (!ok || !std::isfinite(sigma) || sigma < 0.0) { showError(tr("Invalid sigma (must be a non-negative number)")); return; }
    }
    auto r = walletModel->scalarCfdPrice(scfdContractIdEdit->text().trimmed(), sigma);
    if (!r.success) { showError(r.error); return; }
    // Show BOTH sides (the MTM/greeks are exact negatives) so neither a long nor a short user misreads it;
    // amounts are in the collateral numeraire (native TSC sats unless asset-collateralised).
    QString s = tr("R=%1  F/K=%2  | σ=%3 τ=%4 DF=%5 prov=%6  numéraire=%7%8%9\n"
                   "LONG : MTM exp %10 / intr %11   Δ=%12 vega=%13 θ=%14\n"
                   "SHORT: MTM exp %15 / intr %16   Δ=%17 vega=%18 θ=%19")
        .arg(r.current_ratio, 0, 'f', 4).arg(r.forecast_ratio, 0, 'f', 4)
        .arg(r.sigma, 0, 'f', 3).arg(r.tau_years, 0, 'f', 3).arg(r.discount_factor, 0, 'f', 4)
        .arg(r.forward_provenance).arg(r.collateral_is_native ? tr("native") : tr("asset C"))
        .arg(r.fixing_reached ? tr(" [fixed]") : QString()).arg(r.is_fallback ? tr(" [fallback]") : QString())
        .arg(r.expected_long_mtm, 0, 'f', 0).arg(r.intrinsic_long_mtm, 0, 'f', 0)
        .arg(r.long_delta_to_cross_rate, 0, 'f', 0).arg(r.long_vega, 0, 'f', 0).arg(r.long_theta, 0, 'f', 0)
        .arg(r.expected_short_mtm, 0, 'f', 0).arg(r.intrinsic_short_mtm, 0, 'f', 0)
        .arg(r.short_delta_to_cross_rate, 0, 'f', 0).arg(r.short_vega, 0, 'f', 0).arg(r.short_theta, 0, 'f', 0);
    if (r.model_unreliable) s += tr("\n⚠ MODEL UNRELIABLE");
    scfdPriceLabel->setText(s);
    if (!r.warnings.isEmpty()) scfdStatusText->append(tr("Pricing warnings: %1").arg(r.warnings.join(QStringLiteral("; "))));
    if (r.model_unreliable) scfdStatusText->append(tr("⚠ Pricing model is unreliable — do not act on this MTM."));
}

void TreasuryPage::onCfdGenSalt()
{
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;
    QString s;
    for (int i = 0; i < 4; ++i) s += QString("%1").arg(dis(gen), 16, 16, QChar('0'));
    cfdSaltEdit->setText(s);
}

void TreasuryPage::onCfdPairPreview()
{
    if (!cfdPairIdLabel) return;
    const QString root = cfdParentCombo ? cfdParentCombo->currentData().toString() : QString();
    const QString ls = cfdLongSuffixEdit ? cfdLongSuffixEdit->text().trimmed().toUpper() : QString();
    const QString ss = cfdShortSuffixEdit ? cfdShortSuffixEdit->text().trimmed().toUpper() : QString();
    if (root.isEmpty() || ls.isEmpty() || ss.isEmpty()) {
        cfdPairIdLabel->setText(tr("(choose a root + long/short suffix)"));
        return;
    }
    cfdPairIdLabel->setText(tr("L = %1.%2   S = %1.%3").arg(root, ls, ss));
}

bool TreasuryPage::collectCfdSeriesTerms(WalletModel::ScalarNotePairTermsInput& out)
{
    out.source_type = static_cast<int>(ScalarCfdSourceType::ISSUER_PUBLISHED); // CHAIN_INTRINSIC fails closed (no resolver yet)
    out.payoff_mode = cfdPayoffModeCombo->currentData().toInt();
    out.loss_direction = cfdLossDirCombo->currentData().toInt();

    const QString u = cfdUnderlyingEdit->text().trimmed().toLower();
    if (!IsHex64(u)) { cfdStatusText->append(tr("✗ Underlying (U) must be a 64-hex asset id.")); return false; }
    out.underlying_asset_id = u;

    if (!ParseU32(cfdSeriesFeedIdEdit->text(), out.feed_id)) { cfdStatusText->append(tr("✗ Feed id must be a uint32.")); return false; }

    bool ok = false;
    const qulonglong fixing = cfdFixingRefEdit->text().trimmed().toULongLong(&ok);
    if (!ok) { cfdStatusText->append(tr("✗ Fixing epoch must be a non-negative integer (u64).")); return false; }
    out.fixing_ref = fixing;

    const qulonglong deadline = cfdDeadlineHeightEdit->text().trimmed().toULongLong(&ok);
    if (!ok || deadline > 0xFFFFFFFFULL) { cfdStatusText->append(tr("✗ Deadline height must be a u32 block height.")); return false; }
    out.publication_deadline_height = static_cast<quint32>(deadline);

    const qulonglong settle = cfdSettleLockEdit->text().trimmed().toULongLong(&ok);
    if (!ok || settle > 0xFFFFFFFFULL) { cfdStatusText->append(tr("✗ Settle-lock height must be a u32 block height.")); return false; }
    out.settle_lock_height = static_cast<quint32>(settle);

    out.scalar_format_id = cfdFormatSpin->value();

    const QString strike = cfdStrikeEdit->text().trimmed().toLower();
    if (!IsHex64(strike)) { cfdStatusText->append(tr("✗ Strike must be 64 hex chars in the chosen format.")); return false; }
    out.strike = strike;

    const QString fallback = cfdFallbackEdit->text().trimmed().toLower();
    if (!IsHex64(fallback)) { cfdStatusText->append(tr("✗ Fallback scalar must be 64 hex chars.")); return false; }
    out.fallback_scalar = fallback;

    const double lev = cfdLeverageEdit->text().trimmed().toDouble(&ok);
    if (!ok || lev <= 0.0) { cfdStatusText->append(tr("✗ Leverage must be a positive number.")); return false; }
    const long long lq = std::llround(lev * 65536.0);
    if (lq < 1 || lq > 0xFFFFFFFFLL) { cfdStatusText->append(tr("✗ Leverage is out of the representable range.")); return false; }
    out.lambda_q = static_cast<quint32>(lq);

    // Collateral C: combo data is "" (native), "custom" (read the hex field), or a collateral-safe asset id.
    const QString cdata = cfdCollateralCombo->currentData().toString();
    QString c;
    if (cdata == QStringLiteral("custom")) {
        c = cfdCollateralEdit->text().trimmed().toLower();
        if (!IsHex64(c)) { cfdStatusText->append(tr("✗ Custom collateral (C) must be a 64-hex asset id.")); return false; }
    } else {
        c = cdata.toLower();  // "" = native; otherwise a chosen collateral-safe asset id
    }
    out.collateral_asset_id = c;  // blank -> native sentinel (the RPC defaults to zero/native)

    const qulonglong im = cfdVaultImEdit->text().trimmed().toULongLong(&ok);
    if (!ok || im == 0) { cfdStatusText->append(tr("✗ Lot IM must be a positive integer (C units; sats if native).")); return false; }
    out.vault_im = im;

    out.lot_count = static_cast<quint32>(cfdLotCountSpin->value());

    QString salt = cfdSaltEdit->text().trimmed().toLower();
    if (salt.isEmpty()) { onCfdGenSalt(); salt = cfdSaltEdit->text().trimmed().toLower(); }
    if (!IsHex64(salt)) { cfdStatusText->append(tr("✗ Series salt must be 64 hex chars.")); return false; }
    out.series_salt = salt;
    return true;
}

void TreasuryPage::setCfdSeriesFormEnabled(bool enabled)
{
    QWidget* const widgets[] = {
        cfdParentCombo, cfdLongSuffixEdit, cfdShortSuffixEdit, cfdPayoffModeCombo, cfdLossDirCombo,
        cfdUnderlyingEdit, cfdSeriesFeedIdEdit, cfdFixingRefEdit, cfdDeadlineHeightEdit, cfdSettleLockEdit,
        cfdFormatSpin, cfdStrikeEdit, cfdFallbackEdit, cfdLeverageEdit, cfdCollateralCombo,
        cfdCollateralEdit, cfdVaultImEdit, cfdLotCountSpin, cfdSaltEdit, cfdSaltGenButton, cfdBondEdit};
    for (QWidget* w : widgets) if (w) w->setEnabled(enabled);
    if (enabled) onCfdCollateralChanged();
}

void TreasuryPage::onCfdRegister()
{
    if (!walletModel || !clientModel) { showError(tr("Wallet or client model not initialized")); return; }
    if (!cfdParentCombo || cfdParentCombo->count() == 0) {
        showError(tr("No wallet-controlled root is available to sponsor the pair."));
        return;
    }
    WalletModel::ScalarNotePairTermsInput t;
    if (!collectCfdSeriesTerms(t)) return;

    const QString root = cfdParentCombo->currentData().toString();
    const QString ls = cfdLongSuffixEdit->text().trimmed().toUpper();
    const QString ss = cfdShortSuffixEdit->text().trimmed().toUpper();
    if (ls.isEmpty() || ss.isEmpty() || ls == ss) {
        showError(tr("Enter distinct long and short suffixes (the L and S child tickers).")); return;
    }

    bool feeOk = false;
    const double feeRate = cfdFeeRateEdit->text().trimmed().toDouble(&feeOk);
    if (!feeOk || feeRate <= 0.0) { showError(tr("Fee rate must be a positive number (sat/vB).")); return; }
    qint64 bondSats = 0;
    const QString bondStr = cfdBondEdit->text().trimmed();
    if (!bondStr.isEmpty() && !ParseTscToSats(bondStr, bondSats)) {
        showError(tr("Child bond must be a non-negative TSC amount with at most 8 decimals.")); return;
    }

    QString confirm = tr("<b>Register CFD asset series</b><br/><br/>");
    confirm += tr("<b>Long token:</b> %1.%2<br/><b>Short token:</b> %1.%3<br/>").arg(root, ls, ss);
    confirm += tr("<b>Lots (N):</b> %1, each IM %2 (in C's units)<br/>").arg(t.lot_count).arg(t.vault_im);
    confirm += tr("<b>Collateral:</b> %1<br/><br/>").arg(t.collateral_asset_id.isEmpty() ? tr("native TSC") : t.collateral_asset_id);
    confirm += tr("This registers the L and S child shells only (no minting). After it confirms, click "
                  "'2. Issue pair'.<br/><br/>Proceed?");
    QMessageBox box(TopLevelDialogParent(this));
    box.setWindowTitle(tr("Confirm Pair Registration"));
    box.setTextFormat(Qt::RichText);
    box.setText(confirm);
    box.setIcon(QMessageBox::Question);
    box.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
    box.setDefaultButton(QMessageBox::No);
    box.setWindowModality(Qt::WindowModal);
    if (box.exec() != QMessageBox::Yes) { cfdStatusText->append(tr("Registration cancelled.")); return; }

    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if (!ctx.isValid()) { showError(tr("Wallet locked. Please unlock to register the pair.")); return; }

    WalletModel::ScalarNotePairRegisterResult r = walletModel->scalarNotePairBuildRegister(t, root, ls, ss, bondSats, feeRate, true);
    if (!r.success) { cfdStatusText->append(tr("✗ Register failed: %1").arg(r.error)); showError(r.error); return; }
    m_cfdRegisterTxid = r.txid;
    cfdPairIdLabel->setText(tr("pair %1  |  L=%2  S=%3").arg(r.pair_id.left(16) + QStringLiteral("…"), r.long_ticker, r.short_ticker));
    cfdStatusText->append(tr("✓ Registered pair %1 (L %2 / S %3). TxID %4.")
                              .arg(r.pair_id.left(16) + QStringLiteral("…")).arg(r.long_ticker).arg(r.short_ticker).arg(r.txid));
    cfdStatusText->append(tr("  → Wait for 1 confirmation, then click '2. Issue pair'."));
    setCfdSeriesFormEnabled(false);
    cfdRegisterButton->setEnabled(false);
    cfdIssueButton->setEnabled(true);
    saveCfdDraft(/*stage=*/1);  // terms + salt + register txid now durable across an app restart
    refreshAssetList();
    refreshICUDashboard();
}

void TreasuryPage::onCfdIssue()
{
    if (!walletModel) { showError(tr("Wallet not ready")); return; }
    WalletModel::ScalarNotePairTermsInput t;
    if (!collectCfdSeriesTerms(t)) return;
    bool feeOk = false;
    const double feeRate = cfdFeeRateEdit->text().trimmed().toDouble(&feeOk);
    if (!feeOk || feeRate <= 0.0) { showError(tr("Fee rate must be a positive number (sat/vB).")); return; }
    qint64 vaultNative = 546;
    const QString vnStr = cfdVaultNativeEdit->text().trimmed();
    if (!vnStr.isEmpty() && !ParseTscToSats(vnStr, vaultNative)) {
        showError(tr("Vault native carrier must be a TSC amount with at most 8 decimals.")); return;
    }

    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if (!ctx.isValid()) { showError(tr("Wallet locked. Please unlock to issue the pair.")); return; }

    WalletModel::ScalarNotePairIssueResult r = walletModel->scalarNotePairBuildIssue(t, vaultNative, feeRate, true);
    if (!r.success) { cfdStatusText->append(tr("✗ Issue failed: %1").arg(r.error)); showError(r.error); return; }
    m_cfdIssueTxid = r.txid;
    cfdStatusText->append(tr("✓ Issued %1 L + %1 S units and funded %1 vaults. Mint TxID %2.").arg(r.lot_count).arg(r.txid));
    cfdStatusText->append(tr("  → Wait for 1 confirmation, then click '3. Record issue'."));
    cfdIssueButton->setEnabled(false);
    cfdRecordButton->setEnabled(true);
    saveCfdDraft(/*stage=*/2);  // persist the issuance txid so Record survives a restart
    refreshAssetList();
}

void TreasuryPage::onCfdRecord()
{
    if (!walletModel) { showError(tr("Wallet not ready")); return; }
    if (m_cfdIssueTxid.isEmpty()) { showError(tr("No issuance txid — run '2. Issue pair' first.")); return; }
    WalletModel::ScalarNotePairTermsInput t;
    if (!collectCfdSeriesTerms(t)) return;

    WalletModel::ScalarNotePairRecordResult r = walletModel->scalarNotePairRecordIssue(t, m_cfdIssueTxid, m_cfdRegisterTxid);
    if (!r.success) { cfdStatusText->append(tr("✗ Record failed: %1").arg(r.error)); showError(r.error); return; }
    cfdStatusText->append(tr("✓ Recorded pair %1 (%2 lots) — persisted: %3.")
                              .arg(r.pair_id.left(16) + QStringLiteral("…")).arg(r.lot_count).arg(r.persisted ? tr("yes") : tr("no")));
    cfdStatusText->append(tr("  → Done. Click 'New pair' to create another."));
    cfdRecordButton->setEnabled(false);
    clearCfdDraft();   // the pair is recorded in the wallet now; the local draft is no longer needed
    onCfdRefreshList();
    refreshAssetList();
    refreshICUDashboard();
}

void TreasuryPage::onCfdReset()
{
    setCfdSeriesFormEnabled(true);
    cfdLongSuffixEdit->clear();
    cfdShortSuffixEdit->clear();
    cfdSaltEdit->clear();
    cfdStrikeEdit->clear();
    cfdFallbackEdit->clear();
    cfdPairIdLabel->setText(tr("(register to preview the pair id)"));
    m_cfdIssueTxid.clear();
    m_cfdRegisterTxid.clear();
    cfdRegisterButton->setEnabled(true);
    cfdIssueButton->setEnabled(false);
    cfdRecordButton->setEnabled(false);
    clearCfdDraft();   // discard any saved in-progress draft
    cfdStatusText->append(tr("— Ready for a new pair —"));
}

void TreasuryPage::saveCfdDraft(int stage)
{
    QSettings s;
    s.beginGroup(QStringLiteral("ScalarNotePairDraft"));
    s.setValue("active", true);
    s.setValue("stage", stage);
    // Scope the draft to its wallet + chain so Resume can refuse to restore into the wrong context.
    s.setValue("wallet", walletModel ? walletModel->getWalletName() : QString());
    s.setValue("chain", CurrentChainName(clientModel));
    s.setValue("root", cfdParentCombo ? cfdParentCombo->currentData().toString() : QString());
    s.setValue("long_suffix", cfdLongSuffixEdit->text());
    s.setValue("short_suffix", cfdShortSuffixEdit->text());
    s.setValue("payoff_mode", cfdPayoffModeCombo->currentIndex());
    s.setValue("loss_dir", cfdLossDirCombo->currentIndex());
    s.setValue("underlying", cfdUnderlyingEdit->text());
    s.setValue("feed_id", cfdSeriesFeedIdEdit->text());
    s.setValue("fixing_ref", cfdFixingRefEdit->text());
    s.setValue("deadline", cfdDeadlineHeightEdit->text());
    s.setValue("settle_lock", cfdSettleLockEdit->text());
    s.setValue("format", cfdFormatSpin->value());
    s.setValue("strike", cfdStrikeEdit->text());
    s.setValue("fallback", cfdFallbackEdit->text());
    s.setValue("leverage", cfdLeverageEdit->text());
    s.setValue("collateral_idx", cfdCollateralCombo->currentIndex());
    s.setValue("collateral_data", cfdCollateralCombo->currentData().toString());
    s.setValue("collateral_hex", cfdCollateralEdit->text());
    s.setValue("vault_im", cfdVaultImEdit->text());
    s.setValue("lot_count", cfdLotCountSpin->value());
    s.setValue("salt", cfdSaltEdit->text());
    s.setValue("bond", cfdBondEdit->text());
    s.setValue("vault_native", cfdVaultNativeEdit->text());
    s.setValue("fee", cfdFeeRateEdit->text());
    s.setValue("register_txid", m_cfdRegisterTxid);
    s.setValue("issue_txid", m_cfdIssueTxid);
    s.endGroup();
    if (cfdResumeButton) cfdResumeButton->setEnabled(true);
}

void TreasuryPage::clearCfdDraft()
{
    QSettings s;
    s.remove(QStringLiteral("ScalarNotePairDraft"));
    if (cfdResumeButton) cfdResumeButton->setEnabled(false);
}

void TreasuryPage::onCfdResume()
{
    QSettings s;
    s.beginGroup(QStringLiteral("ScalarNotePairDraft"));
    if (!s.value("active", false).toBool()) { s.endGroup(); cfdStatusText->append(tr("No saved pair draft to resume.")); return; }
    // Refuse to restore a draft made for a different wallet or chain (wrong vault context / txids).
    const QString draftWallet = s.value("wallet").toString();
    const QString draftChain = s.value("chain").toString();
    const QString curWallet = walletModel ? walletModel->getWalletName() : QString();
    const QString curChain = CurrentChainName(clientModel);
    if (draftWallet != curWallet || draftChain != curChain) {
        s.endGroup();
        cfdStatusText->append(tr("✗ The saved draft belongs to wallet '%1' on chain '%2' (current: '%3' / '%4'); not resuming.")
                                  .arg(draftWallet.isEmpty() ? tr("(default)") : draftWallet).arg(draftChain)
                                  .arg(curWallet.isEmpty() ? tr("(default)") : curWallet).arg(curChain));
        return;
    }
    const int stage = s.value("stage", 0).toInt();
    const QString root = s.value("root").toString();
    cfdLongSuffixEdit->setText(s.value("long_suffix").toString());
    cfdShortSuffixEdit->setText(s.value("short_suffix").toString());
    cfdPayoffModeCombo->setCurrentIndex(s.value("payoff_mode", 0).toInt());
    cfdLossDirCombo->setCurrentIndex(s.value("loss_dir", 0).toInt());
    cfdUnderlyingEdit->setText(s.value("underlying").toString());
    cfdSeriesFeedIdEdit->setText(s.value("feed_id", "0").toString());
    cfdFixingRefEdit->setText(s.value("fixing_ref").toString());
    cfdDeadlineHeightEdit->setText(s.value("deadline").toString());
    cfdSettleLockEdit->setText(s.value("settle_lock").toString());
    cfdFormatSpin->setValue(s.value("format", assets::SCALAR_FORMAT_RAW_U256_LE).toInt());
    cfdStrikeEdit->setText(s.value("strike").toString());
    cfdFallbackEdit->setText(s.value("fallback").toString());
    cfdLeverageEdit->setText(s.value("leverage", "1.0").toString());
    cfdVaultImEdit->setText(s.value("vault_im").toString());
    cfdLotCountSpin->setValue(s.value("lot_count", 10).toInt());
    cfdSaltEdit->setText(s.value("salt").toString());
    cfdBondEdit->setText(s.value("bond").toString());
    cfdVaultNativeEdit->setText(s.value("vault_native").toString());
    cfdFeeRateEdit->setText(s.value("fee").toString());
    m_cfdRegisterTxid = s.value("register_txid").toString();
    m_cfdIssueTxid = s.value("issue_txid").toString();
    // Restore the collateral choice by its saved id (the combo is repopulated by the asset scan).
    const QString collData = s.value("collateral_data").toString();
    const QString collHex = s.value("collateral_hex").toString();
    s.endGroup();

    if (cfdParentCombo) {
        const int idx = cfdParentCombo->findData(root);
        if (idx >= 0) cfdParentCombo->setCurrentIndex(idx);
        else if (!root.isEmpty()) cfdStatusText->append(tr("⚠ Saved sponsoring root '%1' is not in this wallet's controlled set.").arg(root));
    }
    if (cfdCollateralCombo) {
        int cidx = cfdCollateralCombo->findData(collData);
        if (cidx < 0) cidx = cfdCollateralCombo->findData(QStringLiteral("custom"));
        if (cidx >= 0) cfdCollateralCombo->setCurrentIndex(cidx);
        if (collData == QStringLiteral("custom")) cfdCollateralEdit->setText(collHex);
        onCfdCollateralChanged();
    }

    // Restore the step gating for the saved stage.
    if (stage >= 1) { setCfdSeriesFormEnabled(false); cfdRegisterButton->setEnabled(false); }
    cfdIssueButton->setEnabled(stage == 1);
    cfdRecordButton->setEnabled(stage == 2);
    if (stage == 1) cfdStatusText->append(tr("↻ Resumed a REGISTERED pair (awaiting issuance). Click '2. Issue pair' once it has confirmed."));
    else if (stage == 2) cfdStatusText->append(tr("↻ Resumed an ISSUED pair (awaiting record). Mint TxID %1; click '3. Record issue' once it has confirmed.").arg(m_cfdIssueTxid));
    onCfdPairPreview();
}

void TreasuryPage::onCfdRefreshList()
{
    if (!walletModel) return;
    WalletModel::ScalarNotePairListResult r = walletModel->scalarNotePairList();
    if (!r.success) { cfdStatusText->append(tr("✗ Could not list pairs: %1").arg(r.error)); return; }
    cfdPairTable->setRowCount(0);
    for (const WalletModel::ScalarNotePairListEntry& e : r.pairs) {
        const int row = cfdPairTable->rowCount();
        cfdPairTable->insertRow(row);
        QTableWidgetItem* idItem = new QTableWidgetItem(e.pair_id.left(20) + QStringLiteral("…"));
        idItem->setToolTip(e.pair_id);
        idItem->setData(Qt::UserRole, e.pair_id);
        idItem->setData(Qt::UserRole + 1, e.terms_json);     // full terms -> settle/redeem/unwind
        idItem->setData(Qt::UserRole + 2, e.lot_count);
        idItem->setData(Qt::UserRole + 3, e.lot_vaults);     // per-lot vault outpoints -> autofill (no manual entry)
        cfdPairTable->setItem(row, 0, idItem);
        cfdPairTable->setItem(row, 1, new QTableWidgetItem(QString::number(e.lot_count)));
        cfdPairTable->setItem(row, 2, new QTableWidgetItem(e.issue_txid.left(16) + QStringLiteral("…")));
        cfdPairTable->setItem(row, 3, new QTableWidgetItem(QString::number(e.lot_vaults.size())));
    }
    if (cfdPairTable->rowCount() > 0 && cfdPairTable->currentRow() < 0) cfdPairTable->selectRow(0);
    cfdStatusText->append(tr("Listed %1 recorded note pairs.").arg(r.pairs.size()));
}

void TreasuryPage::onCfdPairSelectionChanged()
{
    const int row = cfdPairTable->currentRow();
    QTableWidgetItem* idItem = row >= 0 ? cfdPairTable->item(row, 0) : nullptr;
    const bool ready = idItem && !idItem->data(Qt::UserRole + 1).toString().isEmpty();
    if (ready) {
        const int lotCount = idItem->data(Qt::UserRole + 2).toInt();
        cfdLotIndexSpin->setRange(0, std::max(0, lotCount - 1));
    }
    cfdSettleButton->setEnabled(ready);
    cfdUnwindButton->setEnabled(ready);
    cfdRedeemButton->setEnabled(ready);
    onCfdLotIndexChanged();  // autofill the vault outpoint for the now-selected pair + lot
}

void TreasuryPage::onCfdLotIndexChanged()
{
    // Carry the recorded per-lot vault outpoint into the settle/unwind field — no manual entry needed.
    // The field stays editable for the rare case of a respent/rotated vault.
    const int row = cfdPairTable->currentRow();
    QTableWidgetItem* idItem = row >= 0 ? cfdPairTable->item(row, 0) : nullptr;
    const int lot = cfdLotIndexSpin->value();
    if (idItem) {
        const QStringList vaults = idItem->data(Qt::UserRole + 3).toStringList();
        if (lot >= 0 && lot < vaults.size()) cfdVaultOutpointEdit->setText(vaults.at(lot));
    }
    // Invalidate the settlement→redeem context once the selection moves off the settled pair/lot, so a stale
    // auto-filled pot can never linger in the live redeem control.
    const QString curPair = idItem ? idItem->data(Qt::UserRole).toString() : QString();
    if (m_cfdSettledLot >= 0 && (curPair != m_cfdSettledPairId || lot != m_cfdSettledLot)) {
        m_cfdSettledPairId.clear();
        m_cfdSettledLongPot.clear();
        m_cfdSettledShortPot.clear();
        m_cfdSettledLot = -1;
    }
    onCfdRedeemSideChanged();  // re-fill for the settled context, or clear when there is none
}

void TreasuryPage::onCfdSettle()
{
    if (!walletModel) { showError(tr("Wallet not ready")); return; }
    const int row = cfdPairTable->currentRow();
    QTableWidgetItem* idItem = row >= 0 ? cfdPairTable->item(row, 0) : nullptr;
    if (!idItem) { showError(tr("Select a pair first.")); return; }
    const QString terms = idItem->data(Qt::UserRole + 1).toString();
    const int lot = cfdLotIndexSpin->value();
    const QString vault = cfdVaultOutpointEdit->text().trimmed();
    if (terms.isEmpty()) { showError(tr("Selected pair has no terms to act on.")); return; }
    if (vault.isEmpty() || !vault.contains(':')) { showError(tr("Enter the lot vault outpoint as txid:vout.")); return; }

    QMessageBox box(TopLevelDialogParent(this));
    box.setWindowTitle(tr("Confirm Settlement"));
    box.setText(tr("Settle lot %1 of the selected pair?\n\nThis folds the buried fixing (or the committed fallback) "
                   "and pays both pots. It only succeeds once the fixing is usable and the settle-lock CLTV is open.").arg(lot));
    box.setIcon(QMessageBox::Question);
    box.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
    box.setDefaultButton(QMessageBox::No);
    if (box.exec() != QMessageBox::Yes) return;

    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if (!ctx.isValid()) { showError(tr("Wallet locked. Please unlock to settle.")); return; }

    WalletModel::ScalarNotePairActionResult r = walletModel->scalarNotePairSettle(terms, lot, vault);
    if (!r.success) { cfdStatusText->append(tr("✗ Settle failed: %1").arg(r.error)); showError(r.error); return; }
    cfdStatusText->append(tr("✓ %1 (txid %2)").arg(r.detail).arg(r.txid));
    // Settle → redeem hand-off: remember the two pots this settlement produced (scoped to this exact pair+lot)
    // and auto-fill the redeem pot for the currently-selected side (mirrors the option-series one-click flow).
    m_cfdSettledPairId = idItem->data(Qt::UserRole).toString();
    m_cfdSettledLongPot = r.long_pot;
    m_cfdSettledShortPot = r.short_pot;
    m_cfdSettledLot = lot;
    onCfdRedeemSideChanged();
    if (!r.long_pot.isEmpty() || !r.short_pot.isEmpty()) {
        cfdStatusText->append(tr("  → pots: long %1 / short %2 — 'Redeem pot' is pre-filled for the chosen side.")
                                  .arg(r.long_pot.isEmpty() ? tr("(none)") : r.long_pot)
                                  .arg(r.short_pot.isEmpty() ? tr("(none)") : r.short_pot));
    }
}

void TreasuryPage::onCfdRedeemSideChanged()
{
    // The redeem pot is auto-managed ONLY for the exact pair+lot that was just settled. For any other
    // context — different pair/lot, no settlement, or the selected side paid zero (empty pot) — the field
    // is cleared so a stale outpoint can never reach a live redeem. (Manual entry remains possible: type a
    // pot as the last action before clicking Redeem.)
    const int row = cfdPairTable->currentRow();
    QTableWidgetItem* idItem = row >= 0 ? cfdPairTable->item(row, 0) : nullptr;
    const QString curPair = idItem ? idItem->data(Qt::UserRole).toString() : QString();
    const bool atSettled = (m_cfdSettledLot >= 0 && !m_cfdSettledPairId.isEmpty()
                            && curPair == m_cfdSettledPairId && cfdLotIndexSpin->value() == m_cfdSettledLot);
    if (!atSettled) { cfdRedeemPotEdit->clear(); return; }
    const bool redeemLong = cfdRedeemSideCombo->currentData().toBool();
    cfdRedeemPotEdit->setText(redeemLong ? m_cfdSettledLongPot : m_cfdSettledShortPot);  // empty side -> clears
}

void TreasuryPage::onCfdCollateralChanged()
{
    // The raw-hex field is only meaningful for the "Custom…" collateral entry.
    if (!cfdCollateralCombo || !cfdCollateralEdit) return;
    cfdCollateralEdit->setVisible(cfdCollateralCombo->currentData().toString() == QStringLiteral("custom"));
}

void TreasuryPage::onCfdUnwind()
{
    if (!walletModel) { showError(tr("Wallet not ready")); return; }
    const int row = cfdPairTable->currentRow();
    QTableWidgetItem* idItem = row >= 0 ? cfdPairTable->item(row, 0) : nullptr;
    if (!idItem) { showError(tr("Select a pair first.")); return; }
    const QString terms = idItem->data(Qt::UserRole + 1).toString();
    const int lot = cfdLotIndexSpin->value();
    const QString vault = cfdVaultOutpointEdit->text().trimmed();
    if (terms.isEmpty()) { showError(tr("Selected pair has no terms to act on.")); return; }
    if (vault.isEmpty() || !vault.contains(':')) { showError(tr("Enter the lot vault outpoint as txid:vout.")); return; }

    QMessageBox box(TopLevelDialogParent(this));
    box.setWindowTitle(tr("Confirm Complete-Set Unwind"));
    box.setText(tr("Unwind lot %1?\n\nThis retires one L unit AND one S unit to their burn sinks and reclaims the full "
                   "lot collateral. Permissionless — requires you hold 1 L + 1 S; no fixing is needed.").arg(lot));
    box.setIcon(QMessageBox::Question);
    box.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
    box.setDefaultButton(QMessageBox::No);
    if (box.exec() != QMessageBox::Yes) return;

    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if (!ctx.isValid()) { showError(tr("Wallet locked. Please unlock to unwind.")); return; }

    WalletModel::ScalarNotePairActionResult r = walletModel->scalarNotePairUnwind(terms, lot, vault, QString());
    if (!r.success) { cfdStatusText->append(tr("✗ Unwind failed: %1").arg(r.error)); showError(r.error); return; }
    cfdStatusText->append(tr("✓ %1 (txid %2)").arg(r.detail).arg(r.txid));
}

void TreasuryPage::onCfdRedeem()
{
    if (!walletModel) { showError(tr("Wallet not ready")); return; }
    const int row = cfdPairTable->currentRow();
    QTableWidgetItem* idItem = row >= 0 ? cfdPairTable->item(row, 0) : nullptr;
    if (!idItem) { showError(tr("Select a pair first.")); return; }
    const QString terms = idItem->data(Qt::UserRole + 1).toString();
    const int lot = cfdLotIndexSpin->value();
    const bool redeemLong = cfdRedeemSideCombo->currentData().toBool();
    const QString pot = cfdRedeemPotEdit->text().trimmed();
    if (terms.isEmpty()) { showError(tr("Selected pair has no terms to act on.")); return; }
    if (pot.isEmpty() || !pot.contains(':')) { showError(tr("Enter the settlement pot outpoint as txid:vout.")); return; }

    QMessageBox box(TopLevelDialogParent(this));
    box.setWindowTitle(tr("Confirm Redemption"));
    box.setText(tr("Redeem the %1 pot %2 for lot %3?\n\nThis retires one of your %1 tokens to the side sink and sweeps "
                   "the pot value to you.").arg(redeemLong ? tr("long (L)") : tr("short (S)")).arg(pot).arg(lot));
    box.setIcon(QMessageBox::Question);
    box.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
    box.setDefaultButton(QMessageBox::No);
    if (box.exec() != QMessageBox::Yes) return;

    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if (!ctx.isValid()) { showError(tr("Wallet locked. Please unlock to redeem.")); return; }

    WalletModel::ScalarNotePairActionResult r = walletModel->scalarNotePairRedeem(terms, redeemLong, lot, pot, QString());
    if (!r.success) { cfdStatusText->append(tr("✗ Redeem failed: %1").arg(r.error)); showError(r.error); return; }
    cfdStatusText->append(tr("✓ %1 (txid %2)").arg(r.detail).arg(r.txid));
    cfdRedeemPotEdit->clear();
}

void TreasuryPage::onCfdFeedLookup()
{
    if (!walletModel || !clientModel) { showError(tr("Wallet not ready")); return; }
    if (!cfdFeedAssetCombo || cfdFeedAssetCombo->count() == 0) { showError(tr("No wallet-controlled feed asset.")); return; }
    const QString assetId = cfdFeedAssetCombo->currentData().toString();
    quint32 feedId = 0;
    if (!ParseU32(cfdFeedIdEdit->text(), feedId)) { showError(tr("Feed id must be a uint32.")); return; }
    try {
        UniValue p(UniValue::VARR);
        p.push_back(assetId.toStdString());
        UniValue info = clientModel->node().executeRpc("getassetinfo", p, walletModel->getWalletName().toStdString());
        if (info.exists("icu_txid") && info.exists("icu_vout")) {
            cfdFeedIcuEdit->setText(QString::fromStdString(info["icu_txid"].get_str()) + ":" +
                                    QString::number(info["icu_vout"].getInt<int64_t>()));
        }
        if (cfdFeedNewIcuAmtEdit->text().trimmed().isEmpty() && info.exists("rotation_min_sats")) {
            const qint64 floor = info["rotation_min_sats"].getInt<int64_t>();
            if (floor > 0) cfdFeedNewIcuAmtEdit->setText(FormatSats(floor));
        }
    } catch (const std::exception& e) {
        cfdFeedStatusText->append(tr("✗ getassetinfo failed: %1").arg(QString::fromStdString(e.what())));
    } catch (...) {
        cfdFeedStatusText->append(tr("✗ Could not read the asset's current ICU."));
    }
    // Next epoch = this feed's head + 1 (or 1 if none).
    WalletModel::ScalarFeedListResult fl = walletModel->scalarListFeeds(assetId);
    quint64 next = 1;
    if (fl.success) {
        for (const WalletModel::ScalarFeedEntry& fe : fl.feeds) {
            if (fe.feed_id == feedId) { next = fe.last_epoch + 1; break; }
        }
    }
    cfdFeedEpochEdit->setText(QString::number(next));
    cfdFeedStatusText->append(tr("Looked up %1: next epoch for feed %2 is %3.")
                                  .arg(assetId.left(12) + QStringLiteral("…")).arg(feedId).arg(next));
}

void TreasuryPage::onCfdFeedNewAddr()
{
    if (!clientModel || !walletModel) { showError(tr("Wallet not ready")); return; }
    try {
        UniValue p(UniValue::VARR);
        p.push_back("");
        p.push_back("bech32m");
        UniValue a = clientModel->node().executeRpc("getnewaddress", p, walletModel->getWalletName().toStdString());
        cfdFeedNewIcuAddrEdit->setText(QString::fromStdString(a.get_str()));
    } catch (...) {
        showError(tr("Could not generate a successor ICU address."));
    }
}

void TreasuryPage::onCfdFeedPublish()
{
    if (!walletModel || !clientModel) { showError(tr("Wallet not ready")); return; }
    if (!cfdFeedAssetCombo || cfdFeedAssetCombo->count() == 0) { showError(tr("No wallet-controlled feed asset.")); return; }
    const QString assetId = cfdFeedAssetCombo->currentData().toString();
    quint32 feedId = 0;
    if (!ParseU32(cfdFeedIdEdit->text(), feedId)) { showError(tr("Feed id must be a uint32.")); return; }

    const QString icu = cfdFeedIcuEdit->text().trimmed();
    const int colon = icu.indexOf(':');
    if (colon <= 0) { showError(tr("Current ICU must be txid:vout (click 'Lookup').")); return; }
    const QString icuTxid = icu.left(colon);
    bool voutOk = false;
    const int icuVout = icu.mid(colon + 1).toInt(&voutOk);
    if (!IsHex64(icuTxid) || !voutOk || icuVout < 0) { showError(tr("Current ICU outpoint is malformed.")); return; }

    const QString newAddr = cfdFeedNewIcuAddrEdit->text().trimmed();
    if (newAddr.isEmpty()) { showError(tr("Enter a successor ICU address (click 'New address').")); return; }
    qint64 newAmt = 0;
    if (!ParseTscToSats(cfdFeedNewIcuAmtEdit->text().trimmed(), newAmt) || newAmt <= 0) {
        showError(tr("Successor bond must be a positive TSC amount.")); return;
    }
    bool epochOk = false;
    const qulonglong epoch = cfdFeedEpochEdit->text().trimmed().toULongLong(&epochOk);
    if (!epochOk || epoch == 0) { showError(tr("Epoch must be a positive integer (head+1).")); return; }
    const QString scalar = cfdFeedScalarEdit->text().trimmed().toLower();
    if (!IsHex64(scalar)) { showError(tr("Scalar must be 64 hex chars.")); return; }
    bool feeOk = false;
    const double feeRate = cfdFeedRateEdit->text().trimmed().toDouble(&feeOk);
    if (!feeOk || feeRate <= 0.0) { showError(tr("Fee rate must be a positive number (sat/vB).")); return; }

    QMessageBox box(TopLevelDialogParent(this));
    box.setWindowTitle(tr("Confirm Feed Publication"));
    box.setText(tr("Publish scalar epoch %1 for feed %2 of asset %3?\n\nThis spends the asset's current ICU and emits "
                   "the scalar carrier. Epochs are append-only and immutable once published.")
                    .arg(epoch).arg(feedId).arg(assetId.left(12) + QStringLiteral("…")));
    box.setIcon(QMessageBox::Question);
    box.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
    box.setDefaultButton(QMessageBox::No);
    if (box.exec() != QMessageBox::Yes) return;

    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if (!ctx.isValid()) { showError(tr("Wallet locked. Please unlock to publish.")); return; }

    WalletModel::ScalarFeedPublishResult r = walletModel->scalarPublish(
        assetId, icuTxid, icuVout, newAddr, newAmt,
        feedId, epoch, scalar, cfdFeedFormatSpin->value(), feeRate);
    if (!r.success) { cfdFeedStatusText->append(tr("✗ Publish failed: %1").arg(r.error)); showError(r.error); return; }
    cfdFeedStatusText->append(tr("✓ Published epoch %1 (txid %2).").arg(epoch).arg(r.txid));
    cfdFeedStatusText->append(tr("  → It becomes settlement-usable once buried >= maturity."));
    refreshICUDashboard();
}

void TreasuryPage::onCfdFeedRead()
{
    if (!walletModel) { showError(tr("Wallet not ready")); return; }
    if (!cfdFeedAssetCombo || cfdFeedAssetCombo->count() == 0) { showError(tr("No wallet-controlled feed asset.")); return; }
    const QString assetId = cfdFeedAssetCombo->currentData().toString();
    quint32 feedId = 0;
    if (!ParseU32(cfdFeedIdEdit->text(), feedId)) { showError(tr("Feed id must be a uint32.")); return; }
    qint64 epoch = -1;
    const QString epochStr = cfdFeedReadEpochEdit->text().trimmed();
    if (!epochStr.isEmpty()) {
        bool ok = false; epoch = static_cast<qint64>(epochStr.toLongLong(&ok));
        if (!ok || epoch < 0) { showError(tr("Read epoch must be a non-negative integer (or blank for latest).")); return; }
    }
    WalletModel::ScalarFeedGetResult r = walletModel->scalarGetFeed(assetId, feedId, epoch);
    if (!r.success) { cfdFeedReadLabel->setText(tr("✗ %1").arg(r.error)); return; }
    cfdFeedReadLabel->setText(tr("epoch %1 (head %2) — scalar %3 — fmt %4 — height %5 — %6")
                                  .arg(r.epoch).arg(r.last_epoch).arg(r.scalar.left(20) + QStringLiteral("…"))
                                  .arg(r.scalar_format_id).arg(r.publication_height)
                                  .arg(r.buried ? tr("BURIED (usable)") : tr("not yet buried")));
}

void TreasuryPage::onRegisterAsset()
{
    if (!walletModel || !clientModel) {
        showError(tr("Wallet or client model not initialized"));
        return;
    }

    // --- Sponsored child registration path (ICU_CHILD.md §6.1/§7): co-spend the parent root's
    // current ICU and register ROOT.SUFFIX at the low child bond via the sponsorchildasset RPC. ---
    if (regModeCombo && regModeCombo->currentData().toString() == QStringLiteral("child")) {
        if (!regParentCombo || regParentCombo->count() == 0) {
            showError(tr("No wallet-controlled root is available to sponsor a child"));
            return;
        }
        const QString root = regParentCombo->currentData().toString();
        QString suffix = regTickerEdit->text().trimmed().toUpper();
        // Enforce the actual root grammar ([A-Z][A-Z0-9]{2,10}) so the UI catches bad suffixes
        // instead of relying on the RPC/consensus parser to reject them later.
        auto isRootChar = [](QChar c) { return (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'); };
        bool suffixOk = suffix.length() >= 3 && suffix.length() <= 11 && suffix.at(0) >= 'A' && suffix.at(0) <= 'Z';
        for (const QChar& ch : suffix) { if (!isRootChar(ch)) suffixOk = false; }
        if (!suffixOk) {
            showError(tr("Suffix must be 3-11 chars, start with a letter, and use A-Z0-9 only (no dot)"));
            return;
        }
        QString childId = regAssetIdEdit->text().trimmed();
        if (childId.isEmpty()) { onGenerateAssetId(); childId = regAssetIdEdit->text().trimmed(); }
        if (childId.length() != 64) { showError(tr("Asset ID must be 64 hex characters")); return; }

        const uint8_t decimals = regDecimalsSpinBox->value();
        uint32_t policyBits = getPolicyBitsFromUI();  // mutable: KYC/TFR checkboxes may add bits below
        const uint16_t allowedFamilies = getAllowedFamiliesFromUI();
        // Don't hard-code the floor: only pass child_bond_sats when the user entered an explicit
        // bond; otherwise omit it and let sponsorchildasset apply the consensus default
        // (SponsoredChildMinIcuBond), so the UI never duplicates the consensus constant.
        const double bondTSC = regBondAmountEdit->text().trimmed().toDouble();
        const int64_t enteredBondSats = static_cast<int64_t>(std::llround(bondTSC * 100000000.0));
        const bool explicitBond = enteredBondSats > 0;
        const QString fullTicker = root + "." + suffix;

        QString confirm = tr("<b>Sponsored Child Registration</b><br/><br/>");
        confirm += tr("<b>Full ticker:</b> %1<br/>").arg(fullTicker);
        confirm += tr("<b>Child asset ID:</b> %1…<br/>").arg(childId.left(16));
        confirm += tr("<b>Child bond:</b> %1<br/>").arg(explicitBond ? (QString::number(enteredBondSats) + tr(" sats")) : tr("consensus default (SponsoredChildMinIcuBond)"));
        confirm += tr("<b>Sponsoring root:</b> %1<br/><br/>").arg(root);
        confirm += tr("The root's current ICU is spent and recreated as a byte-identical successor in the same transaction.<br/><br/>");
        confirm += tr("Proceed?");
        QMessageBox box(TopLevelDialogParent(this));
        box.setWindowTitle(tr("Confirm Sponsored Child Registration"));
        box.setTextFormat(Qt::RichText);
        box.setText(confirm);
        box.setIcon(QMessageBox::Question);
        box.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
        box.setDefaultButton(QMessageBox::No);
        box.setWindowModality(Qt::WindowModal);
        if (box.exec() != QMessageBox::Yes) { regStatusText->append(tr("Child registration cancelled.")); return; }

        WalletModel::UnlockContext ctx(walletModel->requestUnlock());
        if (!ctx.isValid()) { showError(tr("Wallet locked. Please unlock to register a child.")); return; }

        try {
            UniValue addrParams(UniValue::VARR);
            UniValue childAddr = clientModel->node().executeRpc("getnewaddress", addrParams, walletModel->getWalletName().toStdString());
            UniValue opts(UniValue::VOBJ);
            if (explicitBond) opts.pushKV("child_bond_sats", enteredBondSats);
            const int64_t unlockSats = static_cast<int64_t>(std::llround(regUnlockFeesEdit->text().trimmed().toDouble() * 100000000.0));
            if (unlockSats > 0) opts.pushKV("unlock_fees_sats", unlockSats);

            // Full registry parity (ICU_CHILD.md §7.1): carry the same ICU governance + KYC fields
            // the standalone flow does, so a sponsored child is a complete asset, not a stub.
            const QString icuText = regICUTextEdit ? regICUTextEdit->toPlainText().trimmed() : QString();
            if (!icuText.isEmpty()) {
                // Use the SAME builder as the standalone path so a sponsored child commits its
                // Designated Clauses (inline context) and whole-doc/per-clause attestations too --
                // previously this path dropped them, keeping only the freeform witness text.
                const int visibility = regICUVisibilityCombo ? regICUVisibilityCombo->currentData().toInt() : 0;
                const IcuPayloadBuildResult built = buildIcuPayloadFromForm(icuText, visibility, regWitnessBundleEdit, regClauseRows, regWholeDocAttestEdit, regStatusText);
                if (!built.ok) return;  // helper already reported the error
                opts.pushKV("icu_payload_plain", built.payloadPlain.toStdString());
                opts.pushKV("icu_visibility", visibility);
                if (regUseCompressionCheckbox && regUseCompressionCheckbox->isChecked()) opts.pushKV("use_compression", true);
            }
            if (regPolicyQuorumSpinBox && regPolicyQuorumSpinBox->value() > 0) opts.pushKV("policy_quorum_bps", regPolicyQuorumSpinBox->value());
            if (regIssuanceCapSpinBox && regIssuanceCapSpinBox->value() > 0) {
                const uint64_t capUnits = static_cast<uint64_t>(regIssuanceCapSpinBox->value()) * static_cast<uint64_t>(std::pow(10, decimals));
                opts.pushKV("issuance_cap_units", static_cast<int64_t>(capUnits));
            }
            if (regTFRRequiredCheckbox && regTFRRequiredCheckbox->isChecked()) policyBits |= 0x0020; // TFR_ANCHOR_REQUIRED
            if (regKYCRequiredCheckbox && regKYCRequiredCheckbox->isChecked()) {
                policyBits |= 0x0010; // KYC_REQUIRED
                const QByteArray vk = ZKParamsManager::embeddedVK();
                opts.pushKV("kyc_flags", 1);
                opts.pushKV("vk_data", vk.toHex().toStdString());
                if (regMaxRootAgeSpinBox) opts.pushKV("max_root_age", regMaxRootAgeSpinBox->value());
            }

            opts.pushKV("policy_bits", static_cast<int>(policyBits));
            opts.pushKV("allowed_spk_families", static_cast<int>(allowedFamilies));
            opts.pushKV("decimals", static_cast<int>(decimals));
            opts.pushKV("fee_rate", 5.0);  // 5 sat/vB headroom for the IssuerReg/chunk TLV overhead
            opts.pushKV("broadcast", true);
            UniValue params(UniValue::VARR);
            params.push_back(root.toStdString());
            params.push_back(suffix.toStdString());
            params.push_back(childId.toStdString());
            params.push_back(childAddr.get_str());
            params.push_back(opts);
            UniValue res = clientModel->node().executeRpc("sponsorchildasset", params, walletModel->getWalletName().toStdString());
            QString txid = (res.isObject() && res.exists("txid")) ? QString::fromStdString(res.find_value("txid").get_str()) : tr("(pending)");
            regStatusText->append(tr("\n✓ Sponsored child %1 registered (TxID: %2)").arg(fullTicker).arg(txid));
            showSuccess(tr("Child %1 registered! TxID: %2").arg(fullTicker).arg(txid.left(16) + "..."));
            regTickerEdit->clear();
            regAssetIdEdit->clear();
            refreshAssetList();
            refreshICUDashboard();
        } catch (UniValue& objError) {
            try {
                std::string message = objError.find_value("message").get_str();
                regStatusText->append(tr("\n✗ Sponsor child failed: %1").arg(QString::fromStdString(message)));
                showError(QString::fromStdString(message));
            } catch (const std::runtime_error&) {
                showError(tr("Sponsor child failed: %1").arg(QString::fromStdString(objError.write())));
            }
        } catch (const std::exception& e) {
            showError(tr("Sponsor child failed: %1").arg(e.what()));
        }
        return;
    }

    // Validate inputs
    QString ticker = regTickerEdit->text().trimmed().toUpper();
    if (ticker.length() < 3 || ticker.length() > 11) {
        showError(tr("Ticker must be 3-11 characters"));
        return;
    }

    // Check for reserved tickers
    if (ticker == "TSC" || ticker == "XTC" || ticker == "TAK") {
        showError(tr("Ticker '%1' is reserved and cannot be used for assets").arg(ticker));
        return;
    }

    QString assetId = regAssetIdEdit->text().trimmed();
    if (assetId.isEmpty()) {
        onGenerateAssetId();
        assetId = regAssetIdEdit->text();
    }
    if (assetId.length() != 64) {
        showError(tr("Asset ID must be 64 hex characters"));
        return;
    }

    uint8_t decimals = regDecimalsSpinBox->value();
    uint32_t policyBits = getPolicyBitsFromUI();
    uint16_t allowedFamilies = getAllowedFamiliesFromUI();

    QString bondAmountStr = regBondAmountEdit->text().trimmed();
    double bondAmount = bondAmountStr.toDouble();
    if (bondAmount < 5.0) {
        showError(tr("Bond amount must be at least 5.0 TSC"));
        return;
    }

    QString unlockFeesStr = regUnlockFeesEdit->text().trimmed();
    double unlockFeesTSC = unlockFeesStr.toDouble();
    uint64_t unlockFees = static_cast<uint64_t>(std::round(unlockFeesTSC * 100000000.0));  // Convert TSC to satoshis with rounding

    // Show confirmation dialog with asset details and bond warning
    QString confirmMsg = tr("<b>Asset Registration Summary</b><br/><br/>");
    confirmMsg += tr("<b>Ticker:</b> %1<br/>").arg(ticker);
    confirmMsg += tr("<b>Asset ID:</b> %1<br/>").arg(assetId.left(16) + "...");
    confirmMsg += tr("<b>Decimals:</b> %1<br/>").arg(decimals);
    confirmMsg += tr("<b>Policy Bits:</b> 0x%1<br/>").arg(policyBits, 0, 16);
    confirmMsg += tr("<b>Script Families:</b> 0x%1<br/>").arg(allowedFamilies, 0, 16);
    confirmMsg += tr("<b>Bond Amount:</b> %1 TSC<br/>").arg(bondAmount, 0, 'f', 8);
    confirmMsg += tr("<b>Unlock Fees:</b> %1 TSC<br/><br/>").arg(unlockFeesTSC, 0, 'f', 8);
    confirmMsg += tr("<b style='color: #FF6600;'>⚠️ WARNING:</b><br/>");
    confirmMsg += tr("By submitting this transaction, you are locking <b>%1 TSC</b> as a bond until miners have accumulated <b>%2 TSC</b> in fees from asset transactions.<br/><br/>").arg(bondAmount, 0, 'f', 8).arg(unlockFeesTSC, 0, 'f', 8);
    confirmMsg += tr("Do you want to proceed with asset registration?");

    QMessageBox confirmBox(TopLevelDialogParent(this));
    confirmBox.setWindowTitle(tr("Confirm Asset Registration"));
    confirmBox.setTextFormat(Qt::RichText);
    confirmBox.setText(confirmMsg);
    confirmBox.setIcon(QMessageBox::Warning);
    confirmBox.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
    confirmBox.setDefaultButton(QMessageBox::No);
    confirmBox.setWindowModality(Qt::WindowModal);

    int result = confirmBox.exec();
    if (result != QMessageBox::Yes) {
        regStatusText->append(tr("Asset registration cancelled by user."));
        return;
    }

    regStatusText->append(tr("Registering asset %1...").arg(ticker));
    regStatusText->append(tr("Asset ID: %1").arg(assetId));
    regStatusText->append(tr("Policy: 0x%1, Families: 0x%2").arg(policyBits, 0, 16).arg(allowedFamilies, 0, 16));

    // Ensure wallet is unlocked before building and broadcasting the registration transaction
    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if (!ctx.isValid()) {
        regStatusText->append(tr("✗ Wallet unlock required to register asset"));
        showError(tr("Wallet locked. Please unlock the wallet to register a new asset."));
        return;
    }

    try {
        // Get new address for ICU
        UniValue getAddressParams(UniValue::VARR);
        UniValue icuAddrResult = clientModel->node().executeRpc("getnewaddress", getAddressParams, walletModel->getWalletName().toStdString());
        QString icuAddress = QString::fromStdString(icuAddrResult.get_str());

        // Build registerasset params
        UniValue params(UniValue::VARR);
        params.push_back(icuAddress.toStdString());
        params.push_back(bondAmount);
        params.push_back(assetId.toStdString());
        params.push_back((int)policyBits);
        params.push_back((int)allowedFamilies);
        params.push_back((int64_t)unlockFees);
        params.push_back(ticker.toStdString());
        params.push_back((int)decimals);

        UniValue options(UniValue::VOBJ);
        options.pushKV("autofund", true);
        options.pushKV("broadcast", true);
        options.pushKV("fee_rate", 5.0);  // 5 sat/vB to account for TLV extensions

        // Add ICU Governance parameters if provided
        QString icuText = regICUTextEdit->toPlainText().trimmed();
        if (!icuText.isEmpty()) {
            regStatusText->append(tr("Adding ICU governance parameters..."));

            // Build the ICU payload (canonical body + inline Designated Clauses + whole-doc/per-clause
            // attestations) via the shared helper, so this path and the sponsored-child path commit
            // identical structure.
            const int visibility = regICUVisibilityCombo->currentData().toInt();
            const IcuPayloadBuildResult built = buildIcuPayloadFromForm(icuText, visibility, regWitnessBundleEdit, regClauseRows, regWholeDocAttestEdit, regStatusText);
            if (!built.ok) return;  // helper already reported the error
            const std::string icu_payload_plain = built.payloadPlain.toStdString();
            const std::string canonical_hash = built.canonicalHash.toStdString();
            const std::string witness_hash = built.witnessHash.toStdString();
            const int payload_size = built.payloadSize;

            // Add to registerasset options
            options.pushKV("icu_payload_plain", icu_payload_plain);
            options.pushKV("icu_visibility", visibility);

            // Enable compression if checkbox is checked
            if (regUseCompressionCheckbox && regUseCompressionCheckbox->isChecked()) {
                options.pushKV("use_compression", true);
                regStatusText->append(tr("  Compression: enabled (zstd)"));
            }

            // Display results
            regStatusText->append(tr("  ICU payload size: %1 bytes").arg(payload_size));
            regStatusText->append(tr("  Canonical hash: %1").arg(QString::fromStdString(canonical_hash)));
            regStatusText->append(tr("  Witness hash: %1").arg(QString::fromStdString(witness_hash)));
            regStatusText->append(tr("  Payload hex (first 32 bytes): %1...").arg(QString::fromStdString(icu_payload_plain).left(64)));
            regStatusText->append(tr("  Visibility: %1").arg(visibility == 0 ? "Public" : "Holder-Only"));

            // WRAP_REQUIRED is automatically enabled for holder-only visibility
            if (visibility == 1) {
                options.pushKV("icu_flags", 1); // WRAP_REQUIRED
                regStatusText->append(tr("  WRAP_REQUIRED enabled (automatic for holder-only)"));
            }

            int quorum = regPolicyQuorumSpinBox->value();
            if (quorum > 0) {
                options.pushKV("policy_quorum_bps", quorum);
                regStatusText->append(tr("  Policy quorum: %1 bps (%2%)").arg(quorum).arg(quorum / 100.0));
            }

            int issuanceCapCoins = regIssuanceCapSpinBox->value();
            if (issuanceCapCoins > 0) {
                // Convert coins to units using decimals
                uint64_t issuanceCapUnits = static_cast<uint64_t>(issuanceCapCoins) * static_cast<uint64_t>(std::pow(10, decimals));
                options.pushKV("issuance_cap_units", issuanceCapUnits);
                regStatusText->append(tr("  Issuance cap: %1 coins (%2 units)").arg(issuanceCapCoins).arg(issuanceCapUnits));
            }
        }

        // Update policy bits for compliance flags
        if (regTFRRequiredCheckbox->isChecked()) {
            policyBits |= 0x0020; // Set TFR_ANCHOR_REQUIRED bit
            regStatusText->append(tr("TFR_ANCHOR_REQUIRED flag set"));
        }

        // Add ZK parameters if KYC is required
        if (regKYCRequiredCheckbox->isChecked()) {
            regStatusText->append(tr("Adding ZK compliance parameters..."));

            // Update policy bits to include KYC_REQUIRED
            policyBits |= 0x0010; // Set KYC_REQUIRED bit

            // Rebuild params with updated policy bits
            params.clear();
            params.push_back(icuAddress.toStdString());
            params.push_back(bondAmount);
            params.push_back(assetId.toStdString());
            params.push_back((int)policyBits);
            params.push_back((int)allowedFamilies);
            params.push_back((int64_t)unlockFees);
            params.push_back(ticker.toStdString());
            params.push_back((int)decimals);

            // Use embedded VK data
            QByteArray vkData = ZKParamsManager::embeddedVK();

            options.pushKV("kyc_flags", 1);
            options.pushKV("vk_data", vkData.toHex().toStdString());
            options.pushKV("max_root_age", regMaxRootAgeSpinBox->value());

            // Add initial compliance root if provided
            QString complianceRoot = regInitialComplianceRootEdit->text().trimmed();
            if (!complianceRoot.isEmpty()) {
                // Validate hex format (64 chars = 32 bytes)
                if (complianceRoot.length() != 64 || !QRegularExpression("^[0-9a-fA-F]{64}$").match(complianceRoot).hasMatch()) {
                    showError(tr("Initial compliance root must be 64 hex characters"));
                    return;
                }
                options.pushKV("compliance_root", complianceRoot.toStdString());
                regStatusText->append(tr("  Initial compliance root: %1...").arg(complianceRoot.left(16)));
            } else {
                regStatusText->append(tr("  [WARN] No initial compliance root provided - asset will start with no KYC identities"));
            }

            regStatusText->append(tr("  VK data size: %1 bytes").arg(vkData.size()));
            regStatusText->append(tr("  Max root age: %1 blocks").arg(regMaxRootAgeSpinBox->value()));
            regStatusText->append(tr("  Circuit: %1").arg(regCircuitCombo->currentText()));
        }

        params.push_back(options);

        UniValue result = clientModel->node().executeRpc("registerasset", params, walletModel->getWalletName().toStdString());

        QString txid;
        if (result.isStr()) {
            txid = QString::fromStdString(result.get_str());
        } else if (result.isObject() && result.exists("txid")) {
            txid = QString::fromStdString(result.find_value("txid").get_str());
        }

        regStatusText->append(tr("\n✓ Registration submitted successfully!"));
        regStatusText->append(tr("TxID: %1").arg(txid));
        regStatusText->append(tr("ICU Address: %1").arg(icuAddress));
        showSuccess(tr("Asset %1 registered! TxID: %2").arg(ticker).arg(txid.left(16) + "..."));

        // Refresh asset lists to show the newly registered asset
        refreshAssetList();
        refreshICUDashboard();

        // Clear form
        regTickerEdit->clear();
        regAssetIdEdit->clear();
        regBondAmountEdit->setText("5.1");
        regUnlockFeesEdit->setText("5.1");

        // Clear ICU fields
        regICUTextEdit->clear();
        regICUVisibilityCombo->setCurrentIndex(0);
        regPolicyQuorumSpinBox->setValue(0);
        regIssuanceCapSpinBox->setValue(0);
        regWitnessBundleEdit->clear();
        // regWrapRequiredCheckbox removed - WRAP_REQUIRED is now automatic for holder-only
        regCanonicalHashLabel->setText(tr("(no hash computed)"));
        regCanonicalHashLabel->setStyleSheet("font-family: monospace; color: #888;");
        regCopyHashButton->setEnabled(false);
        // regWitnessPreviewEdit removed - no longer needed

        // Clear ZK/TFR fields
        regKYCRequiredCheckbox->setChecked(false);
        regTFRRequiredCheckbox->setChecked(false);
        // VK is embedded — restore default display
        regVKFileEdit->setText(tr("(embedded in binary)"));
        {
            QByteArray vkData = ZKParamsManager::embeddedVK();
            QByteArray vkCommit = QCryptographicHash::hash(vkData, QCryptographicHash::Sha256);
            regVKCommitLabel->setText(vkCommit.toHex());
            regVKCommitLabel->setStyleSheet("font-family: monospace; color: #4CAF50; font-weight: bold;");
        }
        regMaxRootAgeSpinBox->setValue(1008);
        regInitialComplianceRootEdit->clear();

    } catch (UniValue& objError) {
        try {
            int code = objError.find_value("code").getInt<int>();
            std::string message = objError.find_value("message").get_str();
            regStatusText->append(tr("\n✗ RPC Error (%1): %2").arg(code).arg(QString::fromStdString(message)));
            showError(QString::fromStdString(message));
        } catch (const std::runtime_error&) {
            regStatusText->append(tr("\n✗ Error: %1").arg(QString::fromStdString(objError.write())));
            showError(tr("RPC Error: %1").arg(QString::fromStdString(objError.write())));
        }
    } catch (const std::exception& e) {
        regStatusText->append(tr("\n✗ Error: %1").arg(e.what()));
        showError(tr("Failed to register asset: %1").arg(e.what()));
    }
}

void TreasuryPage::onMintAssetSelected(int index)
{
    if (index < 0 || !walletModel) return;

    QString assetId = mintAssetCombo->currentData().toString();
    updateMintAssetInfo(assetId);
}

void TreasuryPage::onMintRefresh()
{
    int index = mintAssetCombo->currentIndex();
    if (index >= 0) {
        QString assetId = mintAssetCombo->currentData().toString();
        if (!assetId.isEmpty()) {
            refreshAssetList();
            updateMintAssetInfo(assetId);
            mintStatusText->append(tr("Asset info refreshed"));
        }
    }
}

void TreasuryPage::onMintAmountChanged()
{
    // Update formatted amount display using actual asset decimals
    QString amountStr = mintAmountEdit->text();
    if (!amountStr.isEmpty()) {
        uint64_t units = amountStr.toULongLong();
        mintAmountFormattedLabel->setText(tr("= %1").arg(formatAssetAmount(units, currentMintAssetDecimals)));
    } else {
        mintAmountFormattedLabel->clear();
    }
}

void TreasuryPage::onMintAsset()
{
    if (!walletModel || !clientModel) {
        showError(tr("Wallet or client model not initialized"));
        return;
    }

    QString assetId = mintAssetCombo->currentData().toString();
    QString amountStr = mintAmountEdit->text().trimmed();
    QString destAddress = mintDestAddressEdit->text().trimmed();
    QString newICUAddress = mintNewICUAddressEdit->text().trimmed();

    if (assetId.isEmpty() || amountStr.isEmpty() || destAddress.isEmpty() || newICUAddress.isEmpty()) {
        showError(tr("All fields are required for minting"));
        return;
    }

    uint64_t mintUnits = amountStr.toULongLong();
    if (mintUnits == 0) {
        showError(tr("Mint amount must be greater than zero"));
        return;
    }

    // Check if addresses are controlled by wallet
    bool destOwned = isAddressOwnedByWallet(destAddress);
    bool icuOwned = isAddressOwnedByWallet(newICUAddress);

    if (!destOwned || !icuOwned) {
        QString warningMsg;
        if (!destOwned && !icuOwned) {
            warningMsg = tr("WARNING: Neither the destination address (%1) nor the new ICU address (%2) "
                          "are controlled by this wallet.\n\n"
                          "Destination address: You will NOT have access to the minted assets.\n"
                          "ICU address: You will NOT be able to perform future operations (minting, burning, or rotation) "
                          "for this asset.\n\n"
                          "Are you sure you want to continue?")
                .arg(destAddress)
                .arg(newICUAddress);
        } else if (!destOwned) {
            warningMsg = tr("WARNING: The destination address (%1) is not controlled by this wallet.\n\n"
                          "This means you will NOT have access to the minted assets.\n\n"
                          "Are you sure you want to continue?")
                .arg(destAddress);
        } else {
            warningMsg = tr("WARNING: The new ICU address (%1) is not controlled by this wallet.\n\n"
                          "This means you will NOT be able to perform future operations (minting, burning, or rotation) "
                          "for this asset unless you have access to the private key for this address.\n\n"
                          "Are you sure you want to continue?")
                .arg(newICUAddress);
        }

        QMessageBox::StandardButton warningReply = QMessageBox::warning(
            this,
            tr("Address Not Controlled by Wallet"),
            warningMsg,
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No
        );

        if (warningReply != QMessageBox::Yes) {
            mintStatusText->append(tr("Mint operation cancelled by user"));
            return;
        }
    }

    // Confirmation dialogue showing terms
    QString confirmationMsg = tr("Please confirm the minting operation:\n\n"
                                 "Asset ID: %1\n"
                                 "Amount: %2 units (%3)\n"
                                 "Destination: %4\n"
                                 "New ICU Address: %5\n\n"
                                 "Do you want to proceed?")
        .arg(assetId.left(16) + "...")
        .arg(mintUnits)
        .arg(mintAmountFormattedLabel->text())
        .arg(destAddress.left(20) + "...")
        .arg(newICUAddress.left(20) + "...");

    QMessageBox::StandardButton reply = QMessageBox::question(
        this,
        tr("Confirm Mint Asset"),
        confirmationMsg,
        QMessageBox::Yes | QMessageBox::No
    );

    if (reply != QMessageBox::Yes) {
        mintStatusText->append(tr("Mint operation cancelled by user."));
        return;
    }

    mintStatusText->append(tr("Minting %1 units of asset...").arg(amountStr));

    try {
        // Ensure wallet is unlocked before minting
        WalletModel::UnlockContext ctx(walletModel->requestUnlock());
        if (!ctx.isValid()) {
            mintStatusText->append(tr("[ERROR] Wallet unlock required to mint asset"));
            showError(tr("Wallet locked. Please unlock the wallet to mint this asset."));
            return;
        }

        // Get current policy to find ICU location
        UniValue policyParams(UniValue::VARR);
        policyParams.push_back(assetId.toStdString());
        UniValue policy = clientModel->node().executeRpc("getassetpolicy", policyParams, "");

        QString icuTxid = QString::fromStdString(policy.find_value("icu_txid").get_str());
        int icuVout = policy.find_value("icu_vout").getInt<int>();
        int policyBits = policy.find_value("policy_bits").getInt<int>();
        int allowedFamilies = policy.find_value("allowed_spk_families").getInt<int>();
        uint64_t unlockFees = policy.find_value("unlock_fees_sats").getInt<uint64_t>();

        // Get ICU value from wallet transaction
        UniValue getTxParams(UniValue::VARR);
        getTxParams.push_back(icuTxid.toStdString());
        getTxParams.push_back(true);  // include_watchonly
        UniValue walletTx = clientModel->node().executeRpc("gettransaction", getTxParams, walletModel->getWalletName().toStdString());

        // Decode the hex to get vout info
        QString hexStr = QString::fromStdString(walletTx.find_value("hex").get_str());
        UniValue decodeParams(UniValue::VARR);
        decodeParams.push_back(hexStr.toStdString());
        UniValue tx = clientModel->node().executeRpc("decoderawtransaction", decodeParams, "");

        const UniValue& vouts = tx.find_value("vout");
        if (!vouts.isArray() || static_cast<size_t>(icuVout) >= vouts.size()) {
            throw std::runtime_error("ICU vout not found in transaction");
        }
        double icuValue = vouts[icuVout].find_value("value").get_real();

        // Build mintasset params
        UniValue params(UniValue::VARR);
        params.push_back(icuTxid.toStdString());
        params.push_back(icuVout);
        params.push_back(newICUAddress.toStdString());
        params.push_back(icuValue);
        params.push_back(destAddress.toStdString());
        params.push_back(0.00001);  // Asset output BTC dust (1k sats)
        params.push_back(assetId.toStdString());
        params.push_back((int64_t)mintUnits);
        params.push_back(policyBits);
        params.push_back(allowedFamilies);
        params.push_back((int64_t)unlockFees);

        UniValue options(UniValue::VOBJ);
        options.pushKV("autofund", true);
        options.pushKV("broadcast", true);
        options.pushKV("fee_rate", 5.0);  // 5 sat/vB to account for TLV extensions

        // Handle ICU_KEYWRAP (auto-wrap or manual)
        if (mintAutoWrapCheckbox->isChecked()) {
            options.pushKV("auto_keywrap", true);
            mintStatusText->append(tr("[INFO] Auto-wrapping DEK enabled"));
        } else {
            // Manual wrapped key
            QString manualKey = mintWrappedKeyEdit->text().trimmed();
            if (!manualKey.isEmpty()) {
                options.pushKV("wrapped_key", manualKey.toStdString());
                mintStatusText->append(tr("[INFO] Using manual wrapped key"));
            } else {
                mintStatusText->append(tr("[WARN] Auto-wrap disabled and no manual key provided - may fail for WRAP_REQUIRED assets"));
            }
        }

        params.push_back(options);

        UniValue result = clientModel->node().executeRpc("mintasset", params, walletModel->getWalletName().toStdString());

        QString txid = QString::fromStdString(result.isStr() ? result.get_str() : result.find_value("txid").get_str());

        mintStatusText->append(tr("\n✓ Mint submitted successfully!"));
        mintStatusText->append(tr("TxID: %1").arg(txid));
        showSuccess(tr("Minted %1 units! TxID: %2").arg(mintUnits).arg(txid.left(16) + "..."));

        // Clear form
        mintAmountEdit->clear();
        mintDestAddressEdit->clear();
        mintNewICUAddressEdit->clear();
        mintAmountFormattedLabel->clear();

        // Refresh asset info
        updateMintAssetInfo(assetId);

    } catch (UniValue& objError) {
        try {
            int code = objError.find_value("code").getInt<int>();
            std::string message = objError.find_value("message").get_str();
            mintStatusText->append(tr("\n✗ RPC Error (%1): %2").arg(code).arg(QString::fromStdString(message)));
            showError(QString::fromStdString(message));
        } catch (const std::runtime_error&) {
            mintStatusText->append(tr("\n✗ Error: %1").arg(QString::fromStdString(objError.write())));
            showError(tr("RPC Error: %1").arg(QString::fromStdString(objError.write())));
        }
    } catch (const std::exception& e) {
        mintStatusText->append(tr("\n✗ Error: %1").arg(e.what()));
        showError(tr("Failed to mint asset: %1").arg(e.what()));
    }
}

void TreasuryPage::onBurnAssetSelected(int index)
{
    if (index < 0 || !walletModel) return;

    QString assetId = burnAssetCombo->currentData().toString();
    updateBurnAssetUTXOs(assetId);
}

void TreasuryPage::onBurnRefreshUTXOs()
{
    int index = burnAssetCombo->currentIndex();
    if (index >= 0) {
        onBurnAssetSelected(index);
    }
}

void TreasuryPage::onBurnUTXOSelected(int row, int column)
{
    Q_UNUSED(column);

    if (row < 0 || row >= burnAssetUTXOTable->rowCount()) return;

    burnSelectedTxid = burnAssetUTXOTable->item(row, 0)->text();
    burnSelectedVout = burnAssetUTXOTable->item(row, 1)->text().toInt();
    QString amount = burnAssetUTXOTable->item(row, 2)->text();

    burnSelectedUTXOLabel->setText(QString("%1:%2 (%3)").arg(burnSelectedTxid.left(16)).arg(burnSelectedVout).arg(amount));
    burnBurnButton->setEnabled(true);
}

void TreasuryPage::onBurnUseManual()
{
    QString txid = burnManualTxidEdit->text().trimmed();
    QString voutStr = burnManualVoutEdit->text().trimmed();

    if (txid.length() != 64) {
        showError(tr("TxID must be 64 hex characters"));
        return;
    }

    bool ok;
    int vout = voutStr.toInt(&ok);
    if (!ok || vout < 0) {
        showError(tr("Vout must be a non-negative integer"));
        return;
    }

    // Verify the UTXO exists and has the correct asset tag
    if (!walletModel || !clientModel) {
        showError(tr("Wallet or client model not initialized"));
        return;
    }

    QString assetId = burnAssetCombo->currentData().toString();
    if (assetId.isEmpty()) {
        showError(tr("No asset selected"));
        return;
    }

    try {
        // Use gettxout to verify the UTXO exists
        UniValue params(UniValue::VARR);
        params.push_back(txid.toStdString());
        params.push_back(vout);
        params.push_back(false);  // include_mempool

        UniValue result = clientModel->node().executeRpc("gettxout", params, "");

        if (result.isNull()) {
            showError(tr("UTXO %1:%2 not found or already spent").arg(txid.left(16)).arg(vout));
            return;
        }

        // Check if it has an asset tag
        if (!result.exists("outext") || result.find_value("outext").get_str().empty()) {
            showError(tr("UTXO %1:%2 does not contain asset data").arg(txid.left(16)).arg(vout));
            return;
        }

        // Verify the asset ID matches by decoding asset tag TLV
        std::string outext = result.find_value("outext").get_str();
        if (!outext.empty() && outext.size() >= 68) {  // Type (2) + CompactSize (2+) + AssetID (64)
            // AssetTag TLV has type 0x01
            if (outext.substr(0, 2) == "01") {
                // Parse CompactSize to find asset_id offset
                int offset = 2;  // After type byte
                std::string lenByte = outext.substr(offset, 2);
                if (lenByte == "fd") {
                    offset += 6;  // fd + 2 bytes
                } else if (lenByte == "fe") {
                    offset += 10;  // fe + 4 bytes
                } else {
                    offset += 2;  // Single byte length
                }

                if (outext.size() >= static_cast<size_t>(offset + 64)) {
                    QString foundAssetIdLE = QString::fromStdString(outext.substr(offset, 64));
                    QString foundAssetId = reverseHexBytes(foundAssetIdLE);

                    if (foundAssetId != assetId) {
                        showError(tr("UTXO contains different asset!\nExpected: %1\nFound: %2")
                                    .arg(assetId.left(16) + "...")
                                    .arg(foundAssetId.left(16) + "..."));
                        return;
                    }
                }
            }
        }

        burnSelectedTxid = txid;
        burnSelectedVout = vout;
        burnSelectedUTXOLabel->setText(QString("%1:%2 (verified)").arg(txid.left(16)).arg(vout));
        burnBurnButton->setEnabled(true);
        burnStatusText->append(tr("✓ Manual UTXO selected and verified: %1:%2").arg(txid.left(16)).arg(vout));

    } catch (UniValue& objError) {
        try {
            int code = objError.find_value("code").getInt<int>();
            std::string message = objError.find_value("message").get_str();
            showError(QString::fromStdString(message));
            burnStatusText->append(tr("RPC Error (%1): %2").arg(code).arg(QString::fromStdString(message)));
        } catch (const std::runtime_error&) {
            showError(tr("RPC Error: %1").arg(QString::fromStdString(objError.write())));
        }
    } catch (const std::exception& e) {
        showError(tr("Error validating UTXO: %1").arg(e.what()));
    }
}

void TreasuryPage::onBurnAsset()
{
    if (!walletModel || !clientModel) {
        showError(tr("Wallet or client model not initialized"));
        return;
    }

    if (burnSelectedTxid.isEmpty() || burnSelectedVout < 0) {
        showError(tr("No asset UTXO selected"));
        return;
    }

    QString assetId = burnAssetCombo->currentData().toString();
    QString assetTxid = burnSelectedTxid;
    int assetVout = burnSelectedVout;
    QString newICUAddress = burnNewICUAddressEdit->text().trimmed();

    if (newICUAddress.isEmpty()) {
        showError(tr("New ICU address required"));
        return;
    }

    // Check if the new ICU address is controlled by wallet
    bool icuOwned = isAddressOwnedByWallet(newICUAddress);
    if (!icuOwned) {
        QMessageBox::StandardButton warningReply = QMessageBox::warning(
            this,
            tr("Address Not Controlled by Wallet"),
            tr("WARNING: The new ICU address (%1) is not controlled by this wallet.\n\n"
               "This means you will NOT be able to perform future operations (minting, burning, or rotation) "
               "for this asset unless you have access to the private key for this address.\n\n"
               "Are you sure you want to continue?").arg(newICUAddress),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No
        );

        if (warningReply != QMessageBox::Yes) {
            burnStatusText->append(tr("Burn operation cancelled by user"));
            return;
        }
    }

    burnStatusText->append(tr("Burning asset UTXO %1:%2...").arg(assetTxid.left(16)).arg(assetVout));

    try {
        // Ensure wallet is unlocked before burning
        WalletModel::UnlockContext ctx(walletModel->requestUnlock());
        if (!ctx.isValid()) {
            burnStatusText->append(tr("[ERROR] Wallet unlock required to burn asset"));
            showError(tr("Wallet locked. Please unlock the wallet to burn this asset."));
            return;
        }

        // Get current policy for ICU
        UniValue policyParams(UniValue::VARR);
        policyParams.push_back(assetId.toStdString());
        UniValue policy = clientModel->node().executeRpc("getassetpolicy", policyParams, "");

        QString icuTxid = QString::fromStdString(policy.find_value("icu_txid").get_str());
        int icuVout = policy.find_value("icu_vout").getInt<int>();
        int policyBits = policy.find_value("policy_bits").getInt<int>();
        int allowedFamilies = policy.find_value("allowed_spk_families").getInt<int>();
        uint64_t unlockFees = policy.find_value("unlock_fees_sats").getInt<uint64_t>();

        // Get ICU value from wallet transaction
        UniValue getTxParams(UniValue::VARR);
        getTxParams.push_back(icuTxid.toStdString());
        getTxParams.push_back(true);  // include_watchonly
        UniValue walletTx = clientModel->node().executeRpc("gettransaction", getTxParams, walletModel->getWalletName().toStdString());

        // Decode the hex to get vout info
        QString hexStr = QString::fromStdString(walletTx.find_value("hex").get_str());
        UniValue decodeParams(UniValue::VARR);
        decodeParams.push_back(hexStr.toStdString());
        UniValue tx = clientModel->node().executeRpc("decoderawtransaction", decodeParams, "");

        const UniValue& vouts = tx.find_value("vout");
        if (!vouts.isArray() || static_cast<size_t>(icuVout) >= vouts.size()) {
            throw std::runtime_error("ICU vout not found in transaction");
        }
        double icuValue = vouts[icuVout].find_value("value").get_real();

        // Build burnasset params
        UniValue params(UniValue::VARR);
        params.push_back(icuTxid.toStdString());
        params.push_back(icuVout);
        params.push_back(assetTxid.toStdString());
        params.push_back(assetVout);
        params.push_back(newICUAddress.toStdString());
        params.push_back(icuValue);
        params.push_back(assetId.toStdString());
        params.push_back(policyBits);
        params.push_back(allowedFamilies);
        params.push_back((int64_t)unlockFees);

        UniValue options(UniValue::VOBJ);
        options.pushKV("autofund", true);
        options.pushKV("broadcast", true);
        options.pushKV("fee_rate", 5.0);  // 5 sat/vB to account for TLV extensions
        params.push_back(options);

        UniValue result = clientModel->node().executeRpc("burnasset", params, walletModel->getWalletName().toStdString());

        QString txid = QString::fromStdString(result.isStr() ? result.get_str() : result.find_value("txid").get_str());

        burnStatusText->append(tr("\n✓ Burn submitted successfully!"));
        burnStatusText->append(tr("TxID: %1").arg(txid));
        showSuccess(tr("Asset burned! TxID: %1").arg(txid.left(16) + "..."));

        // Clear form and refresh
        burnNewICUAddressEdit->clear();
        burnManualTxidEdit->clear();
        burnManualVoutEdit->clear();
        burnSelectedTxid.clear();
        burnSelectedVout = -1;
        burnSelectedUTXOLabel->setText(tr("None selected"));
        burnBurnButton->setEnabled(false);

        // Refresh UTXO list
        updateBurnAssetUTXOs(assetId);

    } catch (UniValue& objError) {
        try {
            int code = objError.find_value("code").getInt<int>();
            std::string message = objError.find_value("message").get_str();
            burnStatusText->append(tr("\n✗ RPC Error (%1): %2").arg(code).arg(QString::fromStdString(message)));
            showError(QString::fromStdString(message));
        } catch (const std::runtime_error&) {
            burnStatusText->append(tr("\n✗ Error: %1").arg(QString::fromStdString(objError.write())));
            showError(tr("RPC Error: %1").arg(QString::fromStdString(objError.write())));
        }
    } catch (const std::exception& e) {
        burnStatusText->append(tr("\n✗ Error: %1").arg(e.what()));
        showError(tr("Failed to burn asset: %1").arg(e.what()));
    }
}


void TreasuryPage::onDashboardRefresh()
{
    refreshICUDashboard();
}

void TreasuryPage::onDashboardFilterChanged()
{
    QString searchText = dashboardFilterEdit ? dashboardFilterEdit->text().trimmed().toLower() : QString();
    int filterType = (dashboardFilterCombo && dashboardFilterCombo->isVisible())
        ? dashboardFilterCombo->currentIndex()
        : 0;  // 0=All, 1=Locked, 2=Unlocked

    for (int row = 0; row < dashboardICUTable->rowCount(); ++row) {
        bool visible = true;

        // Apply text filter (check ticker and asset ID columns)
        if (!searchText.isEmpty()) {
            QString ticker = dashboardICUTable->item(row, 0) ? dashboardICUTable->item(row, 0)->text().toLower() : "";
            QString assetText = dashboardICUTable->item(row, 1) ? dashboardICUTable->item(row, 1)->text().toLower() : "";
            QString assetId = dashboardICUTable->item(row, 1) ? dashboardICUTable->item(row, 1)->data(Qt::UserRole).toString().toLower() : "";

            if (!ticker.contains(searchText) && !assetText.contains(searchText) && !assetId.contains(searchText)) {
                visible = false;
            }
        }

        // Apply lock status filter
        if (visible && isIssuerMode && filterType != 0) {
            QString status = dashboardICUTable->item(row, 8) ? dashboardICUTable->item(row, 8)->text() : "";
            if (filterType == 1 && status != tr("Locked")) {
                visible = false;
            } else if (filterType == 2 && status != tr("Unlocked")) {
                visible = false;
            }
        }

        dashboardICUTable->setRowHidden(row, !visible);
    }
}

// Pretty-print one witness attestation entry: "    - by <signer> [<scheme>]  sig <truncated>".
static QString RenderIcuAttestation(const UniValue& att)
{
    if (!att.isObject()) return QStringLiteral("    - ") + QString::fromStdString(att.write());
    auto pick = [](const UniValue& o, const char* k) -> QString {
        return (o.isObject() && o.exists(k) && o[k].isStr()) ? QString::fromStdString(o[k].get_str()) : QString();
    };
    QString signer = pick(att, "by");
    QString scheme = pick(att, "scheme");
    QString sigText;
    if (att.exists("signature")) {
        const UniValue& sig = att["signature"];
        if (signer.isEmpty()) signer = pick(sig, "address");
        if (signer.isEmpty()) signer = pick(sig, "signer");
        if (scheme.isEmpty()) scheme = pick(sig, "scheme");
        if (sig.isStr()) sigText = QString::fromStdString(sig.get_str());
        else if (sig.isObject() && sig.exists("signature") && sig["signature"].isStr())
            sigText = QString::fromStdString(sig["signature"].get_str());
        else sigText = QString::fromStdString(sig.write());
    }
    QStringList parts;
    if (!signer.isEmpty()) parts << QStringLiteral("by %1").arg(signer);
    if (!scheme.isEmpty()) parts << QStringLiteral("[%1]").arg(scheme);
    if (sigText.size() > 24) sigText = sigText.left(12) + QStringLiteral("…") + sigText.right(8);
    if (!sigText.isEmpty()) parts << QStringLiteral("sig %1").arg(sigText);
    if (parts.isEmpty()) parts << QString::fromStdString(att.write());
    return QStringLiteral("    - ") + parts.join(QStringLiteral("  "));
}

QString TreasuryPage::renderIcuViewerText(const QString& canonicalText, const UniValue& payload)
{
    // Body first (always shown). Under Option A the authoritative clause map is the inline
    // TSC-ICU-CONTEXT-1 block embedded in canonical_text; the node returns it under "context"
    // ("context_source" = "inline" | "metadata" | "none"). We render clauses structurally, attach
    // each clause's attestations from the witness bundle, then pretty-print the witness box
    // (document-level + any unmatched evidence) -- no raw JSON dump.
    QString out = tr("=== CANONICAL TEXT ===\n\n") + canonicalText;

    QString contextSource;
    if (payload.exists("context_source") && payload["context_source"].isStr()) {
        contextSource = QString::fromStdString(payload["context_source"].get_str());
    }
    const bool haveContext = payload.exists("context") && payload["context"].isObject();
    if (contextSource.isEmpty()) contextSource = haveContext ? QStringLiteral("inline") : QStringLiteral("none");

    // --- Source the witness bundle ---------------------------------------------------------------
    // geticuinfo/decrypticupayload expose "witness_bundle" (object or JSON string); geticupayload
    // returns the whole payload as "plaintext" hex -- parse the witness bundle out of it.
    UniValue witness(UniValue::VNULL);
    bool haveWitness = false;
    auto tryReadObj = [&](const std::string& s) {
        UniValue tmp;
        if (tmp.read(s) && tmp.isObject()) { witness = tmp; haveWitness = true; }
    };
    if (payload.exists("witness_bundle")) {
        const UniValue& wb = payload["witness_bundle"];
        if (wb.isObject()) { witness = wb; haveWitness = true; }
        else if (wb.isStr()) tryReadObj(wb.get_str());
    }
    if (!haveWitness && payload.exists("plaintext") && payload["plaintext"].isStr()) {
        const std::vector<unsigned char> pb = ParseHex(payload["plaintext"].get_str());
        if (auto cp = assets::ParseCanonicalIcuPayload(pb); cp && !cp->witness_bundle.empty()) {
            tryReadObj(std::string(cp->witness_bundle.begin(), cp->witness_bundle.end()));
        }
    }

    QString docHash;
    if (haveWitness && witness.exists("canonical_hash") && witness["canonical_hash"].isStr()) {
        docHash = QString::fromStdString(witness["canonical_hash"].get_str());
    }

    // Bucket attestations by their "covers" clause/document hash.
    std::map<QString, QStringList> attByCovers;
    QStringList attNoCover;
    if (haveWitness && witness.exists("attestations") && witness["attestations"].isArray()) {
        const UniValue& arr = witness["attestations"];
        for (size_t i = 0; i < arr.size(); ++i) {
            const UniValue& att = arr[i];
            QString covers;
            if (att.isObject() && att.exists("covers") && att["covers"].isStr())
                covers = QString::fromStdString(att["covers"].get_str());
            if (covers.isEmpty()) attNoCover << RenderIcuAttestation(att);
            else attByCovers[covers] << RenderIcuAttestation(att);
        }
    }

    // --- Designated clauses (with their attestations inline) -------------------------------------
    if (haveContext) {
        const UniValue& ctx = payload["context"];
        QString acceptance;
        if (ctx.exists("acceptance") && ctx["acceptance"].isStr())
            acceptance = QString::fromStdString(ctx["acceptance"].get_str());
        out += tr("\n\n=== DESIGNATED CLAUSES (context source: %1) ===\n").arg(contextSource);
        if (!acceptance.isEmpty()) out += tr("\nAcceptance mode: %1\n").arg(acceptance);

        if (ctx.exists("bodies") && ctx["bodies"].isObject()) {
            const UniValue& bodies = ctx["bodies"];
            const std::vector<std::string> keys = bodies.getKeys();
            if (keys.empty()) {
                out += tr("\n[No designated clauses in the context map]");
            } else {
                int n = 1;
                for (const std::string& key : keys) {
                    const UniValue& v = bodies[key];
                    const QString clauseText = v.isStr() ? QString::fromStdString(v.get_str()) : QString::fromStdString(v.write());
                    const QString qkey = QString::fromStdString(key);
                    out += tr("\nClause %1\n  hash: %2\n  %3\n").arg(n).arg(qkey).arg(clauseText);
                    auto it = attByCovers.find(qkey);
                    if (it != attByCovers.end()) {
                        out += tr("  attestations (%1):\n").arg(it->second.size());
                        out += it->second.join(QStringLiteral("\n")) + QStringLiteral("\n");
                        attByCovers.erase(it);  // consumed by this clause
                    }
                    ++n;
                }
            }
        } else {
            out += tr("\n[Context map present but carries no clause bodies]");
        }
    }

    // --- Witness box (document-level + leftovers) ------------------------------------------------
    out += tr("\n\n=== WITNESS BOX ===\n");
    if (!haveWitness) {
        out += tr("\n[No witness bundle attached]");
        return out;
    }
    if (!docHash.isEmpty()) out += tr("\nDocument hash (canonical): %1\n").arg(docHash);

    if (!docHash.isEmpty()) {
        auto dit = attByCovers.find(docHash);
        if (dit != attByCovers.end()) {
            out += tr("\nDocument-level attestations (%1):\n").arg(dit->second.size());
            out += dit->second.join(QStringLiteral("\n")) + QStringLiteral("\n");
            attByCovers.erase(dit);
        }
    }
    if (!attByCovers.empty()) {
        out += tr("\nOther attestations (covers not matched to a current clause):\n");
        for (const auto& kv : attByCovers) {
            out += tr("  covers %1:\n").arg(kv.first);
            out += kv.second.join(QStringLiteral("\n")) + QStringLiteral("\n");
        }
    }
    if (!attNoCover.isEmpty()) {
        out += tr("\nUnscoped attestations (no 'covers'):\n");
        out += attNoCover.join(QStringLiteral("\n")) + QStringLiteral("\n");
    }
    // Remaining non-attestation witness fields (DocuSign/PGP refs, etc.), read-only.
    {
        QStringList extras;
        for (const std::string& k : witness.getKeys()) {
            if (k == "attestations" || k == "canonical_hash") continue;
            const UniValue& wv = witness[k];
            const QString val = wv.isStr() ? QString::fromStdString(wv.get_str()) : QString::fromStdString(wv.write());
            extras << tr("  %1: %2").arg(QString::fromStdString(k)).arg(val);
        }
        if (!extras.isEmpty()) {
            out += tr("\nOther witness fields:\n") + extras.join(QStringLiteral("\n"));
        }
    }
    return out;
}

void TreasuryPage::onDashboardRowClicked(int row, int column)
{
    Q_UNUSED(column);

    if (row < 0 || row >= dashboardICUTable->rowCount()) return;

    // Get full asset ID from UserRole data (works in both holder and issuer modes)
    QTableWidgetItem* assetIdItem = dashboardICUTable->item(row, 1);
    if (!assetIdItem) return;

    QString assetId = assetIdItem->data(Qt::UserRole).toString();
    if (assetId.isEmpty()) return;

    // Fetch and display ICU text
    dashboardICUTextViewer->clear();
    dashboardICUVisibilityLabel->setText(tr("Loading ICU text..."));
    dashboardICUVisibilityLabel->setStyleSheet("QLabel { color: gray; font-style: italic; }");
    dashboardQuorumLabel->clear();
    dashboardIssuanceCapLabel->clear();
    dashboardDecryptButton->setEnabled(false);

    if (!clientModel) {
        dashboardICUTextViewer->setPlainText(tr("[Error: No client model available]"));
        dashboardICUVisibilityLabel->setText(tr("Error"));
        return;
    }

    try {
        // First, try geticuinfo (works for public ICUs and confirmed holder-only ICUs)
        UniValue icuParams(UniValue::VARR);
        icuParams.push_back(assetId.toStdString());
        UniValue icuInfo = clientModel->node().executeRpc("geticuinfo", icuParams, "");

        if (!icuInfo.isNull()) {
            // Check visibility mode
            int visibility = icuInfo.exists("visibility") ? icuInfo.find_value("visibility").getInt<int>() : 0;

            // Fetch policy info to show quorum/issuance cap
            UniValue policyParams(UniValue::VARR);
            policyParams.push_back(assetId.toStdString());
            try {
                UniValue policy = clientModel->node().executeRpc("getassetpolicy", policyParams, "");
                if (policy.exists("policy_quorum_bps")) {
                    int quorum = policy.find_value("policy_quorum_bps").getInt<int>();
                    dashboardQuorumLabel->setText(tr("Quorum: %1 bps (%2%)").arg(quorum).arg(quorum / 100.0, 0, 'f', 2));
                }
                if (policy.exists("issuance_cap_units")) {
                    uint64_t cap = policy.find_value("issuance_cap_units").getInt<uint64_t>();
                    if (cap == UINT64_MAX) {
                        dashboardIssuanceCapLabel->setText(tr("Cap: Unlimited"));
                    } else {
                        dashboardIssuanceCapLabel->setText(tr("Cap: %1 units").arg(cap));
                    }
                }
            } catch (...) {
                // Policy not found, ignore
            }

            if (visibility == 0) {
                // Public ICU - show plaintext directly
                dashboardICUVisibilityLabel->setText(tr("Visibility: Public"));
                dashboardICUVisibilityLabel->setStyleSheet("QLabel { color: green; font-weight: bold; }");
                dashboardDecryptButton->setEnabled(false);

                QString displayText;

                // For public ICU, fetch the payload and decompress if needed to get witness_bundle
                try {
                    UniValue payloadParams(UniValue::VARR);
                    payloadParams.push_back(assetId.toStdString());
                    UniValue payload = clientModel->node().executeRpc("geticupayload", payloadParams,
                                                                       walletModel ? walletModel->getWalletName().toStdString() : "");

                    // Only use plaintext if the RPC actually produced it (i.e. decrypted/decompressed successfully).
                    // Do NOT fall back to ciphertext — it may be zstd-compressed and ParseCanonicalIcuPayload
                    // will silently return garbage instead of nullopt on compressed data.
                    std::optional<assets::CanonicalIcuPayload> canonical;
                    if (payload.exists("plaintext")) {
                        std::vector<unsigned char> plaintextBytes = ParseHex(payload.find_value("plaintext").get_str());
                        canonical = assets::ParseCanonicalIcuPayload(plaintextBytes);
                    }

                    if (!canonical && payload.exists("ciphertext")) {
                        // plaintext missing or parse failed — try decompressing ciphertext ourselves
                        std::vector<unsigned char> cipherBytes = ParseHex(payload.find_value("ciphertext").get_str());
                        auto decompressed = assets::DecompressZstd(cipherBytes);
                        if (decompressed) {
                            canonical = assets::ParseCanonicalIcuPayload(*decompressed);
                        }
                    }

                    if (canonical) {
                        // Render body + parsed inline TSC-ICU-CONTEXT-1 clauses (from geticupayload
                        // "context"/"context_source"). No raw witness dump.
                        QString icuText = QString::fromUtf8(
                            reinterpret_cast<const char*>(canonical->canonical_text.data()),
                            canonical->canonical_text.size());
                        displayText = renderIcuViewerText(icuText, payload);
                    } else if (icuInfo.exists("canonical_text")) {
                        // Fallback: use geticuinfo canonical_text (already decompressed by that RPC).
                        // The payload still carries the parsed inline context, so render structurally.
                        QString icuText = QString::fromStdString(icuInfo.find_value("canonical_text").get_str());
                        displayText = renderIcuViewerText(icuText, payload);
                    } else {
                        displayText = tr("=== CANONICAL TEXT ===\n\n[No canonical text found in ICU]");
                    }
                } catch (...) {
                    // Fallback to geticuinfo on error (no payload context available here)
                    if (icuInfo.exists("canonical_text")) {
                        QString icuText = QString::fromStdString(icuInfo.find_value("canonical_text").get_str());
                        displayText = tr("=== CANONICAL TEXT ===\n\n") + icuText;
                    } else {
                        displayText = tr("=== CANONICAL TEXT ===\n\n[No canonical text found in ICU]");
                    }
                }

                dashboardICUTextViewer->setPlainText(displayText);
            } else {
                // Holder-only ICU - try to decrypt with wallet
                dashboardICUVisibilityLabel->setText(tr("Visibility: Holder-Only (Encrypted)"));
                dashboardICUVisibilityLabel->setStyleSheet("QLabel { color: orange; font-weight: bold; }");

                // Enable decrypt button for holder-only ICUs
                dashboardDecryptButton->setEnabled(true);

                try {
                    UniValue payloadParams(UniValue::VARR);
                    payloadParams.push_back(assetId.toStdString());
                    UniValue payload = clientModel->node().executeRpc("geticupayload", payloadParams,
                                                                       walletModel ? walletModel->getWalletName().toStdString() : "");

                    if (payload.exists("decrypted") && payload.find_value("decrypted").get_bool()) {
                        // Successfully decrypted - plaintext is hex-encoded CanonicalIcuPayload
                        if (!payload.exists("plaintext")) {
                            dashboardICUTextViewer->setPlainText(tr("[Error: Decrypted but no plaintext field]"));
                            dashboardICUVisibilityLabel->setStyleSheet("QLabel { color: red; font-weight: bold; }");
                        } else {
                            std::string plaintextHex = payload.find_value("plaintext").get_str();
                            std::vector<unsigned char> plaintextBytes = ParseHex(plaintextHex);

                            // Parse CanonicalIcuPayload to extract canonical_text and witness_bundle
                            auto canonical = assets::ParseCanonicalIcuPayload(plaintextBytes);
                            if (canonical && !canonical->canonical_text.empty()) {
                                // Render body + parsed inline TSC-ICU-CONTEXT-1 clauses (from
                                // geticupayload "context"/"context_source"). No raw witness dump.
                                QString icuText = QString::fromUtf8(
                                    reinterpret_cast<const char*>(canonical->canonical_text.data()),
                                    canonical->canonical_text.size());
                                QString displayText = renderIcuViewerText(icuText, payload);

                                dashboardICUTextViewer->setPlainText(displayText);
                                dashboardICUVisibilityLabel->setText(tr("Visibility: Holder-Only (Decrypted ✓)"));
                                dashboardICUVisibilityLabel->setStyleSheet("QLabel { color: green; font-weight: bold; }");
                            } else {
                                dashboardICUTextViewer->setPlainText(tr("[Error: Failed to parse canonical ICU payload]"));
                                dashboardICUVisibilityLabel->setStyleSheet("QLabel { color: red; font-weight: bold; }");
                            }
                        }
                    } else {
                        // Failed to decrypt - not a holder
                        dashboardICUTextViewer->setPlainText(tr("[ENCRYPTED - You are not a holder of this asset]\n\n"
                                                                "This ICU text is encrypted and can only be viewed by asset holders."));
                        dashboardICUVisibilityLabel->setStyleSheet("QLabel { color: red; font-weight: bold; }");
                    }
                } catch (...) {
                    dashboardICUTextViewer->setPlainText(tr("[ENCRYPTED - Decryption failed]\n\n"
                                                            "Unable to decrypt ICU text. You may not be a holder of this asset."));
                    dashboardICUVisibilityLabel->setStyleSheet("QLabel { color: red; font-weight: bold; }");
                }
            }
        } else {
            dashboardICUTextViewer->setPlainText(tr("[No ICU text available]\n\n"
                                                    "This asset may not have ICU text, or it is unconfirmed."));
            dashboardICUVisibilityLabel->setText(tr("No ICU data"));
            dashboardICUVisibilityLabel->setStyleSheet("QLabel { color: gray; font-style: italic; }");
        }
    } catch (const UniValue& objError) {
        try {
            int code = objError.find_value("code").getInt<int>();
            std::string message = objError.find_value("message").get_str();
            QString messageQt = QString::fromStdString(message);
            if (code == RPC_INVALID_ADDRESS_OR_KEY &&
                (message.find("no ICU payload") != std::string::npos ||
                 message.find("not found in registry") != std::string::npos)) {
                dashboardICUTextViewer->setPlainText(tr("[No ICU text available]\n\n%1").arg(messageQt));
                dashboardICUVisibilityLabel->setText(tr("No ICU data"));
                dashboardICUVisibilityLabel->setStyleSheet("QLabel { color: gray; font-style: italic; }");
                dashboardDecryptButton->setEnabled(false);
                return;
            }
            dashboardICUTextViewer->setPlainText(tr("[RPC Error %1: %2]").arg(code).arg(messageQt));
            dashboardICUVisibilityLabel->setText(tr("Error"));
            dashboardICUVisibilityLabel->setStyleSheet("QLabel { color: red; font-weight: bold; }");
        } catch (const std::runtime_error&) {
            dashboardICUTextViewer->setPlainText(tr("[Error: %1]").arg(QString::fromStdString(objError.write())));
            dashboardICUVisibilityLabel->setText(tr("Error"));
            dashboardICUVisibilityLabel->setStyleSheet("QLabel { color: red; font-weight: bold; }");
        }
    } catch (const std::exception& e) {
        QString errorText = QString::fromUtf8(e.what());
        if (errorText.contains("no ICU payload", Qt::CaseInsensitive)) {
            dashboardICUTextViewer->setPlainText(tr("[No ICU text available]\n\n%1").arg(errorText));
            dashboardICUVisibilityLabel->setText(tr("No ICU data"));
            dashboardICUVisibilityLabel->setStyleSheet("QLabel { color: gray; font-style: italic; }");
            dashboardDecryptButton->setEnabled(false);
        } else {
            dashboardICUTextViewer->setPlainText(tr("[Error: %1]").arg(errorText));
            dashboardICUVisibilityLabel->setText(tr("Error"));
            dashboardICUVisibilityLabel->setStyleSheet("QLabel { color: red; font-weight: bold; }");
        }
    }
}

void TreasuryPage::updateMintAssetInfo(const QString& assetId)
{
    if (!clientModel || assetId.isEmpty()) {
        mintPolicyLabel->setText(tr("N/A"));
        mintBondLabel->setText(tr("N/A"));
        mintFeesLabel->setText(tr("N/A"));
        mintICULabel->setText(tr("N/A"));
        mintWrapStatusLabel->setText(tr(""));
        return;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(assetId.toStdString());

        mintStatusText->append(tr("[DEBUG] Querying asset_id: %1").arg(assetId));
        UniValue policy = clientModel->node().executeRpc("getassetpolicy", params, "");

        if (policy.isNull()) {
            mintStatusText->append(tr("[DEBUG] getassetpolicy returned NULL"));
        } else if (!policy.exists("icu_txid")) {
            mintStatusText->append(tr("[DEBUG] Policy missing icu_txid field"));
        } else {
            mintStatusText->append(tr("[DEBUG] Policy found successfully"));
        }

        if (policy.isNull() || !policy.exists("icu_txid")) {
            // Asset not yet in registry - likely unconfirmed
            mintPolicyLabel->setText(tr("Pending confirmation..."));
            mintBondLabel->setText(tr("Pending confirmation..."));
            mintFeesLabel->setText(tr("Pending confirmation..."));
            mintICULabel->setText(tr("Pending confirmation..."));
            mintStatusText->append(tr("Asset not yet confirmed. Please wait for the registration transaction to be mined."));
            return;
        }

        QString icuTxid = QString::fromStdString(policy.find_value("icu_txid").get_str());
        int icuVout = policy.find_value("icu_vout").getInt<int>();
        int policyBits = policy.find_value("policy_bits").getInt<int>();
        uint64_t feesAccum = policy.find_value("fees_accum_sats").getInt<uint64_t>();
        uint64_t unlockFees = policy.find_value("unlock_fees_sats").getInt<uint64_t>();

        // Store decimals for amount formatting
        if (policy.exists("decimals")) {
            currentMintAssetDecimals = policy.find_value("decimals").getInt<uint8_t>();
        } else {
            currentMintAssetDecimals = 8;  // Default
        }

        // Get bond amount from wallet transaction
        UniValue getTxParams(UniValue::VARR);
        getTxParams.push_back(icuTxid.toStdString());
        getTxParams.push_back(true);  // include_watchonly
        UniValue walletTx = clientModel->node().executeRpc("gettransaction", getTxParams, walletModel->getWalletName().toStdString());

        // Decode the hex to get vout info
        QString hexStr = QString::fromStdString(walletTx.find_value("hex").get_str());
        UniValue decodeParams(UniValue::VARR);
        decodeParams.push_back(hexStr.toStdString());
        UniValue tx = clientModel->node().executeRpc("decoderawtransaction", decodeParams, "");

        const UniValue& vouts = tx.find_value("vout");
        if (!vouts.isArray() || static_cast<size_t>(icuVout) >= vouts.size()) {
            throw std::runtime_error("ICU vout not found");
        }
        double bond = vouts[icuVout].find_value("value").get_real();

        mintPolicyLabel->setText(QString("0x%1").arg(policyBits, 0, 16));
        mintBondLabel->setText(QString("%1 TSC").arg(bond, 0, 'f', 8));
        mintFeesLabel->setText(QString("%1 / %2 sats").arg(feesAccum).arg(unlockFees));
        mintICULabel->setText(QString("%1:%2").arg(icuTxid).arg(icuVout));

        // Check for ICU_FLAGS (WRAP_REQUIRED)
        if (policy.exists("icu_flags")) {
            int icuFlags = policy.find_value("icu_flags").getInt<int>();
            if (icuFlags & 0x0001) {  // WRAP_REQUIRED = 0x0001
                mintWrapStatusLabel->setText(tr("⚠ WRAP_REQUIRED - Keywrap enforcement enabled"));
                mintWrapStatusLabel->setStyleSheet("QLabel { color: orange; font-weight: bold; }");
                mintAutoWrapCheckbox->setEnabled(true);
                mintStatusText->append(tr("[INFO] This asset requires ICU_KEYWRAP on all transfers"));
            } else {
                mintWrapStatusLabel->setText(tr("Optional (no enforcement)"));
                mintWrapStatusLabel->setStyleSheet("QLabel { color: gray; }");
                mintAutoWrapCheckbox->setEnabled(true);
            }
        } else {
            mintWrapStatusLabel->setText(tr("Not configured"));
            mintWrapStatusLabel->setStyleSheet("QLabel { color: gray; }");
            mintAutoWrapCheckbox->setEnabled(true);
        }

    } catch (UniValue& objError) {
        try {
            int code = objError.find_value("code").getInt<int>();
            std::string message = objError.find_value("message").get_str();

            // Check if it's a "not found" error - likely unconfirmed
            if (message.find("not found") != std::string::npos || message.find("missing") != std::string::npos) {
                mintPolicyLabel->setText(tr("Pending confirmation..."));
                mintBondLabel->setText(tr("Pending confirmation..."));
                mintFeesLabel->setText(tr("Pending confirmation..."));
                mintICULabel->setText(tr("Pending confirmation..."));
                mintStatusText->append(tr("Asset registration pending confirmation"));
            } else {
                mintStatusText->append(tr("RPC Error (%1): %2").arg(code).arg(QString::fromStdString(message)));
                mintPolicyLabel->setText(tr("Error"));
                mintBondLabel->setText(tr("Error"));
                mintFeesLabel->setText(tr("Error"));
                mintICULabel->setText(tr("Error"));
            }
        } catch (...) {
            mintStatusText->append(tr("Error: %1").arg(QString::fromStdString(objError.write())));
            mintPolicyLabel->setText(tr("Error"));
            mintBondLabel->setText(tr("Error"));
            mintFeesLabel->setText(tr("Error"));
            mintICULabel->setText(tr("Error"));
        }
    } catch (const std::exception& e) {
        mintPolicyLabel->setText(tr("Pending confirmation..."));
        mintBondLabel->setText(tr("Pending confirmation..."));
        mintFeesLabel->setText(tr("Pending confirmation..."));
        mintICULabel->setText(tr("Pending confirmation..."));
        mintStatusText->append(tr("Asset info unavailable - likely pending confirmation"));
    }
}

void TreasuryPage::updateBurnAssetUTXOs(const QString& assetId)
{
    burnAssetUTXOTable->setRowCount(0);

    if (assetId.isEmpty() || !walletModel || !clientModel) return;

    try {
        // Call listassetutxos with asset filter
        UniValue params(UniValue::VARR);
        UniValue assetFilter(UniValue::VARR);
        assetFilter.push_back(assetId.toStdString());
        params.push_back(assetFilter);
        params.push_back(0);  // minconf = 0 (include unconfirmed)
        params.push_back(9999999);  // maxconf

        if (burnStatusText) {
            burnStatusText->append(tr("Calling listassetutxos with:"));
            burnStatusText->append(tr("  assets: [%1]").arg(assetId));
            burnStatusText->append(tr("  minconf: 0, maxconf: 9999999"));
        }

        UniValue result = clientModel->node().executeRpc("listassetutxos", params, walletModel->getWalletName().toStdString());

        if (!result.isArray()) {
            if (burnStatusText) {
                burnStatusText->append(tr("listassetutxos returned non-array result"));
            }
            return;
        }

        if (burnStatusText) {
            burnStatusText->append(tr("Found %1 UTXOs for asset").arg(result.size()));
        }

        for (size_t i = 0; i < result.size(); ++i) {
            const UniValue& utxo = result[i];

            QString txid = QString::fromStdString(utxo.find_value("txid").get_str());
            int vout = utxo.find_value("vout").getInt<int>();
            uint64_t units = utxo.find_value("asset_units").getInt<uint64_t>();
            int confirmations = utxo.find_value("confirmations").getInt<int>();

            // address is optional
            QString address;
            if (utxo.exists("address")) {
                address = QString::fromStdString(utxo.find_value("address").get_str());
            } else {
                address = tr("N/A");
            }

            // decimals is optional - default to 0 if not available
            uint8_t decimals = 0;
            if (utxo.exists("decimals")) {
                decimals = utxo.find_value("decimals").getInt<int>();
            }

            QString formattedAmount = formatAssetAmount(units, decimals);

            int row = burnAssetUTXOTable->rowCount();
            burnAssetUTXOTable->insertRow(row);
            burnAssetUTXOTable->setItem(row, 0, new QTableWidgetItem(txid));
            burnAssetUTXOTable->setItem(row, 1, new QTableWidgetItem(QString::number(vout)));
            burnAssetUTXOTable->setItem(row, 2, new QTableWidgetItem(formattedAmount));
            burnAssetUTXOTable->setItem(row, 3, new QTableWidgetItem(QString::number(confirmations)));
            burnAssetUTXOTable->setItem(row, 4, new QTableWidgetItem(address));
        }

    } catch (UniValue& objError) {
        // Show detailed error
        QString errorMsg;
        try {
            int code = objError.find_value("code").getInt<int>();
            std::string message = objError.find_value("message").get_str();
            errorMsg = tr("RPC Error (%1): %2").arg(code).arg(QString::fromStdString(message));
        } catch (...) {
            errorMsg = tr("Error: %1").arg(QString::fromStdString(objError.write()));
        }

        int row = burnAssetUTXOTable->rowCount();
        burnAssetUTXOTable->insertRow(row);
        burnAssetUTXOTable->setItem(row, 0, new QTableWidgetItem(errorMsg));
        burnAssetUTXOTable->setSpan(row, 0, 1, 5);  // Span across all columns

        if (burnStatusText) {
            burnStatusText->append(errorMsg);
        }
    } catch (const std::exception& e) {
        QString errorMsg = tr("Error: %1").arg(e.what());

        int row = burnAssetUTXOTable->rowCount();
        burnAssetUTXOTable->insertRow(row);
        burnAssetUTXOTable->setItem(row, 0, new QTableWidgetItem(errorMsg));
        burnAssetUTXOTable->setSpan(row, 0, 1, 5);  // Span across all columns

        if (burnStatusText) {
            burnStatusText->append(errorMsg);
        }
    }
}


void TreasuryPage::refreshAssetList()
{
    if (m_asset_list_refresh_in_progress) {
        m_asset_list_refresh_pending = true;
        return;
    }
    m_asset_list_refresh_in_progress = true;

    [&] {
        if (!walletModel || !clientModel) return;

        const std::string wallet_name = walletModel->getWalletName().toStdString();

        const QString mintSelected = mintAssetCombo ? mintAssetCombo->currentData().toString() : QString();
        const QString burnSelected = burnAssetCombo ? burnAssetCombo->currentData().toString() : QString();
        const QString zkSelected = zkAssetCombo ? zkAssetCombo->currentData().toString() : QString();
        const QString govSelected = govAssetCombo ? govAssetCombo->currentData().toString() : QString();
        const QString distTargetSelected = distTargetAssetCombo ? distTargetAssetCombo->currentData().toString() : QString();
        const QString distAssetSelected = distAssetCombo ? distAssetCombo->currentData().toString() : QString();
        const QString regParentSelected = regParentCombo ? regParentCombo->currentData().toString() : QString();
        const QString optParentSelected = optParentCombo ? optParentCombo->currentData().toString() : QString();
        const QString cfdParentSelected = cfdParentCombo ? cfdParentCombo->currentData().toString() : QString();
        const QString cfdCollateralSelected = cfdCollateralCombo ? cfdCollateralCombo->currentData().toString() : QString();

        auto appendStatus = [&](const QString& text) {
            if (isIssuerMode && regStatusText) {
                regStatusText->append(text);
            }
        };

        auto restoreSelection = [](QComboBox* combo, const QString& value) {
            if (combo && !value.isEmpty()) {
                int idx = combo->findData(value);
                if (idx >= 0) combo->setCurrentIndex(idx);
            }
        };

        auto activateCombo = [&](QComboBox* combo, const QString& previous, void (TreasuryPage::*slot)(int)) {
            if (!combo) {
                (this->*slot)(-1);
                return;
            }

            if (combo->count() == 0) {
                (this->*slot)(-1);
                return;
            }

            int targetIndex = -1;
            if (!previous.isEmpty()) {
                targetIndex = combo->findData(previous);
            }
            if (targetIndex < 0) {
                targetIndex = combo->currentIndex();
            }
            if (targetIndex < 0) {
                targetIndex = 0;
            }
            if (targetIndex >= combo->count()) {
                targetIndex = combo->count() - 1;
            }

            if (combo->currentIndex() != targetIndex) {
                QSignalBlocker blocker(combo);
                combo->setCurrentIndex(targetIndex);
            }

            (this->*slot)(targetIndex);
        };

        if (isIssuerMode) {
            {
                QSignalBlocker blockMint(mintAssetCombo);
                QSignalBlocker blockBurn(burnAssetCombo);
                QSignalBlocker blockZk(zkAssetCombo);
                QSignalBlocker blockGov(govAssetCombo);
                QSignalBlocker blockDistTarget(distTargetAssetCombo);
                QSignalBlocker blockDistAsset(distAssetCombo);
                QSignalBlocker blockRegParent(regParentCombo);
                QSignalBlocker blockOptParent(optParentCombo);
                QSignalBlocker blockCfdParent(cfdParentCombo);
                QSignalBlocker blockCfdCollateral(cfdCollateralCombo);

                if (mintAssetCombo) mintAssetCombo->clear();
                if (burnAssetCombo) burnAssetCombo->clear();
                if (regParentCombo) regParentCombo->clear();
                if (optParentCombo) optParentCombo->clear();
                if (cfdParentCombo) cfdParentCombo->clear();
                if (cfdFeedAssetCombo) cfdFeedAssetCombo->clear();
                if (cfdCollateralCombo) {
                    cfdCollateralCombo->clear();
                    cfdCollateralCombo->addItem(tr("Native (TSC)"), QString());          // native sentinel
                    cfdCollateralCombo->addItem(tr("Custom (enter id)…"), QStringLiteral("custom"));
                }
                if (zkAssetCombo) zkAssetCombo->clear();
                if (govAssetCombo) govAssetCombo->clear();
                if (distTargetAssetCombo) distTargetAssetCombo->clear();
                if (distAssetCombo) {
                    distAssetCombo->clear();
                    distAssetCombo->addItem(tr("TSC (Native)"), "TSC");
                }

                // Re-add Pre-Registration Mode entry for ZK Compliance tab
                if (zkAssetCombo) {
                    zkAssetCombo->addItem(tr("(Pre-Registration Mode - Generate Initial Root)"), "");
                }

                try {
                    // Use listtransactions like refreshICUDashboard does
                    UniValue listTxParams(UniValue::VARR);
                    listTxParams.push_back("*");    // label filter
                    listTxParams.push_back(99999);  // count
                    listTxParams.push_back(0);      // skip
                    listTxParams.push_back(false);  // include_watchonly
                    UniValue txs = clientModel->node().executeRpc("listtransactions", listTxParams, wallet_name);

                    if (!txs.isArray()) {
                        appendStatus(tr("listtransactions returned non-array"));
                        return;
                    }

                    appendStatus(tr("Scanning transactions for ICUs..."));

                    std::set<QString> foundAssets;

                    for (size_t i = 0; i < txs.size(); ++i) {
                        try {
                            const UniValue& txEntry = txs[i];
                            if (!txEntry.exists("txid")) continue;

                            QString txid = QString::fromStdString(txEntry.find_value("txid").get_str());

                            // Get full transaction
                            UniValue getTxParams(UniValue::VARR);
                            getTxParams.push_back(txid.toStdString());
                            getTxParams.push_back(true);   // include_watchonly
                            UniValue walletTx = clientModel->node().executeRpc("gettransaction", getTxParams, wallet_name);

                            if (!walletTx.exists("hex")) continue;

                            QString hexStr = QString::fromStdString(walletTx.find_value("hex").get_str());

                            // Decode transaction
                            UniValue decodeParams(UniValue::VARR);
                            decodeParams.push_back(hexStr.toStdString());
                            UniValue decoded = clientModel->node().executeRpc("decoderawtransaction", decodeParams, "");

                            const UniValue& vouts = decoded.find_value("vout");
                            if (!vouts.isArray()) continue;

                            // Check each output for IssuerReg TLV
                            for (size_t vout = 0; vout < vouts.size(); ++vout) {
                                const UniValue& output = vouts[vout];
                                if (!output.exists("outext")) continue;

                                QString outext = QString::fromStdString(output.find_value("outext").get_str());
                                if (!outext.startsWith("10")) continue;  // IssuerReg TLV type 0x10

                                // Parse IssuerReg TLV
                                std::vector<unsigned char> vext = ParseHex(outext.toStdString());
                                auto issuerReg = assets::ParseIssuerReg(vext);
                                if (!issuerReg) continue;

                                QString assetId = QString::fromStdString(issuerReg->asset_id.ToString());
                                if (foundAssets.count(assetId)) continue;
                                foundAssets.insert(assetId);

                                QString ticker = QString::fromStdString(issuerReg->ticker);
                                QString displayName = ticker.isEmpty() ? (assetId.left(16) + "...") : ticker;

                                if (mintAssetCombo) mintAssetCombo->addItem(displayName, assetId);
                                if (burnAssetCombo) burnAssetCombo->addItem(displayName, assetId);
                                if (zkAssetCombo) zkAssetCombo->addItem(displayName, assetId);
                                if (govAssetCombo) govAssetCombo->addItem(displayName, assetId);
                                if (distTargetAssetCombo) distTargetAssetCombo->addItem(displayName, assetId);
                                if (distAssetCombo) distAssetCombo->addItem(displayName, assetId);
                                // Sponsored-child parent dropdown (ICU_CHILD.md §7): wallet-controlled
                                // ROOT tickers only (no dotted children). The sponsorchildasset RPC
                                // enforces the spendable + full-bond requirements at submit time.
                                if (regParentCombo && !ticker.isEmpty() && !ticker.contains('.')) {
                                    regParentCombo->addItem(ticker, ticker);
                                }
                                // Same wallet-controlled roots feed the option-series wizard's parent dropdown.
                                if (optParentCombo && !ticker.isEmpty() && !ticker.contains('.')) {
                                    optParentCombo->addItem(ticker, ticker);
                                }
                                // …and the CFD-asset-series sponsoring root dropdown.
                                if (cfdParentCombo && !ticker.isEmpty() && !ticker.contains('.')) {
                                    cfdParentCombo->addItem(ticker, ticker);
                                }
                                // The scalar feed publisher can issue a feed from ANY wallet-controlled asset
                                // (root or child) — the display label keeps the ticker, the data holds the id.
                                if (cfdFeedAssetCombo) {
                                    cfdFeedAssetCombo->addItem(displayName, assetId);
                                }
                                // §5.1 collateral picker: offer only COLLATERAL_SAFE assets. The policy bit is
                                // already in the parsed IssuerReg, so the filter costs nothing extra here.
                                if (cfdCollateralCombo && (issuerReg->policy_bits & assets::COLLATERAL_SAFE)) {
                                    cfdCollateralCombo->addItem(displayName + tr(" [safe]"), assetId);
                                }
                            }
                        } catch (...) {
                            continue;  // Skip failed transactions
                        }
                    }

                    appendStatus(tr("Found %1 ICUs we control").arg(foundAssets.size()));

                    restoreSelection(mintAssetCombo, mintSelected);
                    restoreSelection(distTargetAssetCombo, distTargetSelected);
                    restoreSelection(distAssetCombo, distAssetSelected);
                    restoreSelection(burnAssetCombo, burnSelected);
                    restoreSelection(zkAssetCombo, zkSelected);
                    restoreSelection(govAssetCombo, govSelected);
                    restoreSelection(regParentCombo, regParentSelected);
                    restoreSelection(optParentCombo, optParentSelected);
                    restoreSelection(cfdParentCombo, cfdParentSelected);
                    restoreSelection(cfdCollateralCombo, cfdCollateralSelected);

                } catch (UniValue& objError) {
                    // Re-add Pre-Registration Mode entry even on error
                    if (zkAssetCombo && zkAssetCombo->count() == 0) {
                        zkAssetCombo->addItem(tr("(Pre-Registration Mode - Generate Initial Root)"), "");
                    }
                    try {
                        int code = objError.find_value("code").getInt<int>();
                        std::string message = objError.find_value("message").get_str();
                        appendStatus(tr("RPC Error (%1): %2").arg(code).arg(QString::fromStdString(message)));
                    } catch (const std::runtime_error&) {
                        appendStatus(tr("Error: %1").arg(QString::fromStdString(objError.write())));
                    }
                } catch (const std::exception& e) {
                    // Re-add Pre-Registration Mode entry even on error
                    if (zkAssetCombo && zkAssetCombo->count() == 0) {
                        zkAssetCombo->addItem(tr("(Pre-Registration Mode - Generate Initial Root)"), "");
                    }
                    appendStatus(tr("refreshAssetList failed: %1").arg(e.what()));
                }
            } // Signal blockers scope ends here

            activateCombo(govAssetCombo, govSelected, &TreasuryPage::onGovAssetSelected);
            activateCombo(zkAssetCombo, zkSelected, &TreasuryPage::onZKAssetSelected);
            activateCombo(distTargetAssetCombo, distTargetSelected, &TreasuryPage::onDistTargetAssetSelected);
            activateCombo(distAssetCombo, distAssetSelected, &TreasuryPage::onDistAssetSelected);
            onRegChildPreviewUpdate();
            onOptPreviewUpdate();
            onCfdPairPreview();
            onCfdCollateralChanged();
            return;
        }

        {
            QSignalBlocker blockMint(mintAssetCombo);
            QSignalBlocker blockBurn(burnAssetCombo);
            QSignalBlocker blockZk(zkAssetCombo);
            QSignalBlocker blockGov(govAssetCombo);

            if (mintAssetCombo) mintAssetCombo->clear();
            if (burnAssetCombo) burnAssetCombo->clear();
            if (zkAssetCombo) zkAssetCombo->clear();
            if (govAssetCombo) govAssetCombo->clear();

            const auto balances = walletModel->getAssetBalances();
            for (const auto& asset_balance : balances) {
                const uint64_t total_units = asset_balance.balance + asset_balance.pending + asset_balance.locked;
                if (total_units == 0) continue;

                const std::string asset_id_std = asset_balance.asset_id.ToString();
                QString assetId = QString::fromStdString(asset_id_std);

                QString displayName = assetId.left(16) + "...";
                if (!asset_balance.ticker.empty()) {
                    displayName = QString::fromStdString(asset_balance.ticker) + " (" + assetId.left(8) + "...)";
                } else {
                    // Try to enrich name with policy ticker if wallet metadata is missing.
                    try {
                        UniValue policyParams(UniValue::VARR);
                        policyParams.push_back(asset_id_std);
                        UniValue policy = clientModel->node().executeRpc("getassetpolicy", policyParams, "");
                        QString ticker = QString::fromStdString(policy.find_value("ticker").get_str());
                        if (!ticker.isEmpty()) {
                            displayName = ticker + " (" + assetId.left(8) + "...)";
                        }
                    } catch (...) {
                        // Ignore policy lookup failures.
                    }
                }

                if (zkAssetCombo) zkAssetCombo->addItem(displayName, assetId);
                if (govAssetCombo) govAssetCombo->addItem(displayName, assetId);
            }

            restoreSelection(zkAssetCombo, zkSelected);
            restoreSelection(govAssetCombo, govSelected);
        } // end holder signal blocker scope

        activateCombo(govAssetCombo, govSelected, &TreasuryPage::onGovAssetSelected);
        activateCombo(zkAssetCombo, zkSelected, &TreasuryPage::onZKAssetSelected);

        // onHeldAssetRefresh() - removed as heldAssetICUGroup feature was removed
    }();

    m_asset_list_refresh_in_progress = false;
    if (m_asset_list_refresh_pending) {
        m_asset_list_refresh_pending = false;
        QTimer::singleShot(0, this, &TreasuryPage::refreshAssetList);
    }
}

void TreasuryPage::refreshICUDashboard()
{
    if (m_icu_dashboard_refresh_in_progress) {
        m_icu_dashboard_refresh_pending = true;
        return;
    }
    m_icu_dashboard_refresh_in_progress = true;

    [&] {
        if (!walletModel || !clientModel) return;

        bool wasSortingEnabled = dashboardICUTable->isSortingEnabled();
        dashboardICUTable->setSortingEnabled(false);
        dashboardICUTable->setRowCount(0);
        struct SortingRestorer {
            QTableWidget* table;
            bool enabled;
            ~SortingRestorer() {
                if (table) {
                    table->setSortingEnabled(enabled);
                }
            }
        } sortingRestorer{dashboardICUTable, wasSortingEnabled};

        // In HOLDER mode: show assets the user HOLDS (balances)
        // In ISSUER mode: show ICUs the user REGISTERED

        if (!isIssuerMode) {
            // HOLDER MODE: Show assets with balances and policy characteristics
            const auto balances = walletModel->getAssetBalances();
            for (const auto& asset_balance : balances) {
                const uint64_t total_units = asset_balance.balance + asset_balance.pending + asset_balance.locked;
                if (total_units == 0) continue;

                const std::string asset_id_std = asset_balance.asset_id.ToString();
                QString assetId = QString::fromStdString(asset_id_std);

                QString ticker;
                if (!asset_balance.ticker.empty()) {
                    ticker = QString::fromStdString(asset_balance.ticker);
                } else {
                    ticker = assetId.left(8) + "...";
                }

                uint8_t decimals = asset_balance.has_decimals ? asset_balance.decimals : 0;
                QString maxIssuance = "-";
                QString totalIssued = "-";
                QString govBps = "-";
                QString textVis = "-";
                QString scriptFamilies = "-";
                QString compliance = "-";
                QString tfrReq = "-";

                try {
                    UniValue policyParams(UniValue::VARR);
                    policyParams.push_back(asset_id_std);
                    UniValue policy = clientModel->node().executeRpc("getassetpolicy", policyParams, "");

                    // Get ticker
                    UniValue tickerValue = policy.find_value("ticker");
                    if (!tickerValue.isNull()) {
                        ticker = QString::fromStdString(tickerValue.get_str());
                    }

                    // Get decimals
                    UniValue decimalsValue = policy.find_value("decimals");
                    if (!decimalsValue.isNull()) {
                        decimals = static_cast<uint8_t>(decimalsValue.getInt<int>());
                    }

                    // Get max issuance
                    UniValue maxIssuanceValue = policy.find_value("issuance_cap_units");
                    if (!maxIssuanceValue.isNull()) {
                        uint64_t capUnits = maxIssuanceValue.getInt<uint64_t>();
                        if (capUnits == 0 || capUnits == std::numeric_limits<uint64_t>::max()) {
                            maxIssuance = tr("Unlimited");
                        } else {
                            maxIssuance = formatAssetAmount(capUnits, decimals);
                        }
                    }

                    // Get total issued
                    UniValue totalIssuedValue = policy.find_value("issued_total");
                    if (!totalIssuedValue.isNull()) {
                        totalIssued = formatAssetAmount(totalIssuedValue.getInt<uint64_t>(), decimals);
                    }

                    // Get governance BPS
                    UniValue govBpsValue = policy.find_value("policy_quorum_bps");
                    if (!govBpsValue.isNull()) {
                        int bps = govBpsValue.getInt<int>();
                        govBps = QString("%1 (%2%)").arg(bps).arg(bps / 100.0, 0, 'f', 2);
                    }

                    // Get text visibility
                    try {
                        UniValue icuParams(UniValue::VARR);
                        icuParams.push_back(asset_id_std);
                        UniValue icuInfo = clientModel->node().executeRpc("geticuinfo", icuParams, "");
                        if (!icuInfo.isNull() && icuInfo.exists("visibility")) {
                            int vis = icuInfo.find_value("visibility").getInt<int>();
                            switch (vis) {
                                case 0: textVis = "Public"; break;
                                case 1: textVis = "Holder-only"; break;
                                case 2: textVis = "Wrapped"; break;
                                default: textVis = QString::number(vis); break;
                            }
                        }
                    } catch (...) {
                        if (policy.exists("icu_visibility")) {
                            int vis = policy.find_value("icu_visibility").getInt<int>();
                            switch (vis) {
                                case 0: textVis = "Public"; break;
                                case 1: textVis = "Holder-only"; break;
                                default: textVis = QString::number(vis); break;
                            }
                        }
                    }

                    // Get allowed script families
                    UniValue allowedFamiliesValue = policy.find_value("allowed_spk_families");
                    if (!allowedFamiliesValue.isNull()) {
                        uint16_t families = static_cast<uint16_t>(allowedFamiliesValue.getInt<int>());
                        QStringList familyList;
                        if (families & assets::SPK_P2PKH) familyList << "P2PKH";
                        if (families & assets::SPK_P2SH) familyList << "P2SH";
                        if (families & assets::SPK_P2WPKH) familyList << "P2WPKH";
                        if (families & assets::SPK_P2WSH) familyList << "P2WSH";
                        if (families & assets::SPK_P2TR) familyList << "P2TR";
                        scriptFamilies = familyList.isEmpty() ? "None" : familyList.join(", ");
                    }

                    // Get compliance asset (KYC required)
                    UniValue kycValue = policy.find_value("has_kyc");
                    if (!kycValue.isNull()) {
                        compliance = kycValue.get_bool() ? "Yes" : "No";
                    } else if (policy.exists("policy_bits")) {
                        int bits = policy.find_value("policy_bits").getInt<int>();
                        compliance = (bits & assets::KYC_REQUIRED) ? "Yes" : "No";
                    }

                    // Get TFR (wrap) required
                    bool wrapRequired = false;
                    UniValue icuFlagsValue = policy.find_value("icu_flags");
                    if (!icuFlagsValue.isNull()) {
                        wrapRequired = (static_cast<uint32_t>(icuFlagsValue.getInt<int>()) & assets::WRAP_REQUIRED) != 0;
                    }
                    if (!wrapRequired) {
                        UniValue tfrFlagsValue = policy.find_value("tfr_flags");
                        if (!tfrFlagsValue.isNull()) {
                            wrapRequired = (static_cast<uint32_t>(tfrFlagsValue.getInt<int>()) & assets::TFR_ANCHOR_REQUIRED) != 0;
                        } else if (policy.exists("policy_bits")) {
                            int bits = policy.find_value("policy_bits").getInt<int>();
                            wrapRequired = (bits & assets::TFR_ANCHOR_REQUIRED) != 0;
                        }
                    }
                    tfrReq = wrapRequired ? "Yes" : "No";
                } catch (...) {
                    // Fallback: show asset by current wallet metadata if policy lookup fails.
                }

                int row = dashboardICUTable->rowCount();
                dashboardICUTable->insertRow(row);
                dashboardICUTable->setItem(row, 0, new QTableWidgetItem(ticker));

                QTableWidgetItem* assetItem = new QTableWidgetItem(assetId.left(16) + "...");
                assetItem->setData(Qt::UserRole, assetId);
                dashboardICUTable->setItem(row, 1, assetItem);

                QString displayBalance = formatAssetAmount(asset_balance.balance, decimals);
                dashboardICUTable->setItem(row, 2, new QTableWidgetItem(displayBalance));
                dashboardICUTable->setItem(row, 3, new QTableWidgetItem(maxIssuance));
                dashboardICUTable->setItem(row, 4, new QTableWidgetItem(totalIssued));
                dashboardICUTable->setItem(row, 5, new QTableWidgetItem(govBps));
                dashboardICUTable->setItem(row, 6, new QTableWidgetItem(textVis));
                dashboardICUTable->setItem(row, 7, new QTableWidgetItem(scriptFamilies));
                dashboardICUTable->setItem(row, 8, new QTableWidgetItem(compliance));
                dashboardICUTable->setItem(row, 9, new QTableWidgetItem(tfrReq));
            }
            dashboardICUTable->resizeColumnsToContents();
            onDashboardFilterChanged();
            return;
        }

        // ISSUER MODE: Show registered ICUs
        try {
            // Get all wallet transactions (including unconfirmed)
            UniValue listTxParams(UniValue::VARR);
            listTxParams.push_back("*");    // label filter
            listTxParams.push_back(99999);  // count
            listTxParams.push_back(0);      // skip
            listTxParams.push_back(false);  // include_watchonly
            UniValue txs = clientModel->node().executeRpc("listtransactions", listTxParams, walletModel->getWalletName().toStdString());

            if (!txs.isArray()) return;

            std::set<QString> foundAssets;  // Track assets we've found to avoid duplicates

            // Scan all transactions for IssuerReg outputs
            for (size_t i = 0; i < txs.size(); ++i) {
                try {
                    const UniValue& txEntry = txs[i];

                    if (!txEntry.exists("txid")) continue;

                    QString txid = QString::fromStdString(txEntry.find_value("txid").get_str());

                    // Get full transaction
                    UniValue getTxParams(UniValue::VARR);
                    getTxParams.push_back(txid.toStdString());
                    getTxParams.push_back(true);   // include_watchonly
                    getTxParams.push_back(true);   // verbose
                    UniValue walletTx = clientModel->node().executeRpc("gettransaction", getTxParams, walletModel->getWalletName().toStdString());

                    if (!walletTx.exists("hex")) continue;

                    QString hexStr = QString::fromStdString(walletTx.find_value("hex").get_str());

                    // Decode transaction
                    UniValue decodeParams(UniValue::VARR);
                    decodeParams.push_back(hexStr.toStdString());
                    UniValue decoded = clientModel->node().executeRpc("decoderawtransaction", decodeParams, "");

                    const UniValue& vouts = decoded.find_value("vout");
                    if (!vouts.isArray()) continue;

                    // Check each output for IssuerReg TLV
                    for (size_t vout = 0; vout < vouts.size(); ++vout) {
                        const UniValue& output = vouts[vout];

                        if (!output.exists("outext")) continue;

                    QString outext = QString::fromStdString(output.find_value("outext").get_str());

                    // IssuerReg TLV has type 0x10
                    if (!outext.startsWith("10")) continue;

                    // Parse IssuerReg TLV using proper parser (fixes duplicate entries bug)
                    std::vector<unsigned char> vext = ParseHex(outext.toStdString());
                    auto issuerReg = assets::ParseIssuerReg(vext);
                    if (!issuerReg) continue;  // Invalid TLV, skip

                    QString assetId = QString::fromStdString(issuerReg->asset_id.ToString());

                    if (foundAssets.count(assetId)) continue;  // Already added this asset
                    foundAssets.insert(assetId);

                    // Extract ticker from parsed IssuerReg (no more homecooked hex parsing!)
                    QString ticker = QString::fromStdString(issuerReg->ticker);
                    QString displayName = ticker.isEmpty() ? (assetId.left(16) + "...") : ticker;

                    // Get asset details from policy using asset_id
                    try {
                        UniValue policyParams(UniValue::VARR);
                        policyParams.push_back(assetId.toStdString());
                        UniValue policy = clientModel->node().executeRpc("getassetpolicy", policyParams, "");

                        if (policy.isNull() || !policy.exists("icu_txid")) {
                            // Asset not yet confirmed - parse raw transaction data instead
                            int row = dashboardICUTable->rowCount();
                            dashboardICUTable->insertRow(row);
                            dashboardICUTable->setItem(row, 0, new QTableWidgetItem(displayName));
                            dashboardICUTable->setItem(row, 1, new QTableWidgetItem(assetId.left(16) + "..."));
                            dashboardICUTable->setItem(row, 2, new QTableWidgetItem(txid.left(16) + "..."));
                            dashboardICUTable->setItem(row, 3, new QTableWidgetItem(QString::number(vout)));

                            // Extract bond amount from raw transaction
                            double bond = output.find_value("value").get_real();
                            dashboardICUTable->setItem(row, 4, new QTableWidgetItem(
                                QString("%1 (unconf)").arg(bond, 0, 'f', 8)));

                            // Extract unlock fees from parsed IssuerReg
                            uint64_t unlockFees = issuerReg->unlock_fees_sats;
                            if (unlockFees != std::numeric_limits<uint64_t>::max()) {
                                dashboardICUTable->setItem(row, 5, new QTableWidgetItem(tr("0")));  // No fees accumulated yet
                                dashboardICUTable->setItem(row, 6, new QTableWidgetItem(QString::number(unlockFees)));
                                dashboardICUTable->setItem(row, 7, new QTableWidgetItem(tr("0%")));
                            } else {
                                dashboardICUTable->setItem(row, 5, new QTableWidgetItem(tr("-")));
                                dashboardICUTable->setItem(row, 6, new QTableWidgetItem(tr("-")));
                                dashboardICUTable->setItem(row, 7, new QTableWidgetItem(tr("-")));
                            }

                            dashboardICUTable->setItem(row, 8, new QTableWidgetItem(tr("Unconfirmed")));
                            dashboardICUTable->item(row, 1)->setData(Qt::UserRole, assetId);
                            continue;
                        }

                        QString icuTxid = QString::fromStdString(policy.find_value("icu_txid").get_str());
                        int icuVout = policy.find_value("icu_vout").getInt<int>();
                        uint64_t feesAccum = policy.find_value("fees_accum_sats").getInt<uint64_t>();
                        uint64_t unlockFees = policy.find_value("unlock_fees_sats").getInt<uint64_t>();

                        // Get bond amount from wallet transaction
                        UniValue getRawTxParams(UniValue::VARR);
                        getRawTxParams.push_back(icuTxid.toStdString());
                        getRawTxParams.push_back(true);  // include_watchonly
                        UniValue walletTx = clientModel->node().executeRpc("gettransaction", getRawTxParams, walletModel->getWalletName().toStdString());

                        // Decode the hex to get vout info
                        QString hexStr = QString::fromStdString(walletTx.find_value("hex").get_str());
                        UniValue decodeParams(UniValue::VARR);
                        decodeParams.push_back(hexStr.toStdString());
                        UniValue rawTx = clientModel->node().executeRpc("decoderawtransaction", decodeParams, "");

                        const UniValue& rawVouts = rawTx.find_value("vout");
                        if (!rawVouts.isArray() || static_cast<size_t>(icuVout) >= rawVouts.size()) continue;
                        double bond = rawVouts[icuVout].find_value("value").get_real();

                        // Calculate progress percentage
                        int progress = unlockFees > 0 ? (feesAccum * 100) / unlockFees : 0;
                        if (progress > 100) progress = 100;

                        QString status = feesAccum >= unlockFees ? tr("Unlocked") : tr("Locked");

                        int row = dashboardICUTable->rowCount();
                        dashboardICUTable->insertRow(row);
                        dashboardICUTable->setItem(row, 0, new QTableWidgetItem(displayName));
                        dashboardICUTable->setItem(row, 1, new QTableWidgetItem(assetId.left(16) + "..."));
                        dashboardICUTable->setItem(row, 2, new QTableWidgetItem(icuTxid.left(16) + "..."));
                        dashboardICUTable->setItem(row, 3, new QTableWidgetItem(QString::number(icuVout)));
                        dashboardICUTable->setItem(row, 4, new QTableWidgetItem(QString::number(bond, 'f', 8)));
                        dashboardICUTable->setItem(row, 5, new QTableWidgetItem(QString::number(feesAccum)));
                        dashboardICUTable->setItem(row, 6, new QTableWidgetItem(QString::number(unlockFees)));
                        dashboardICUTable->setItem(row, 7, new QTableWidgetItem(QString("%1%").arg(progress)));
                        dashboardICUTable->setItem(row, 8, new QTableWidgetItem(status));

                        // Store full asset ID in row 1 userData for clicking
                        dashboardICUTable->item(row, 1)->setData(Qt::UserRole, assetId);

                    } catch (...) {
                        // Error getting policy or bond, skip this asset
                        continue;
                    }
                }

            } catch (UniValue& objError) {
                // Skip this transaction
                continue;
            } catch (const std::exception& e) {
                // Skip this transaction
                continue;
            }
        }

    } catch (UniValue& objError) {
        // Show error in table
        int row = dashboardICUTable->rowCount();
        dashboardICUTable->insertRow(row);
        try {
            int code = objError.find_value("code").getInt<int>();
            std::string message = objError.find_value("message").get_str();
            dashboardICUTable->setItem(row, 0, new QTableWidgetItem(tr("RPC Error (%1): %2").arg(code).arg(QString::fromStdString(message))));
        } catch (const std::runtime_error&) {
            dashboardICUTable->setItem(row, 0, new QTableWidgetItem(tr("Error: %1").arg(QString::fromStdString(objError.write()))));
        }
    } catch (const std::exception& e) {
        // Show error in table
        int row = dashboardICUTable->rowCount();
        dashboardICUTable->insertRow(row);
        dashboardICUTable->setItem(row, 0, new QTableWidgetItem(tr("Error: %1").arg(e.what())));
    }

    dashboardICUTable->resizeColumnsToContents();
    onDashboardFilterChanged();
    }();

    m_icu_dashboard_refresh_in_progress = false;
    if (m_icu_dashboard_refresh_pending) {
        m_icu_dashboard_refresh_pending = false;
        QTimer::singleShot(0, this, &TreasuryPage::refreshICUDashboard);
    }
}

void TreasuryPage::onNumBlocksChanged(int count, const QDateTime& blockDate, double nVerificationProgress, SyncType header, SynchronizationState sync_state)
{
    Q_UNUSED(count);
    Q_UNUSED(blockDate);
    Q_UNUSED(nVerificationProgress);
    Q_UNUSED(header);
    Q_UNUSED(sync_state);

    if (!walletModel || !clientModel) return;

    try {
        // Refresh asset list to pick up newly confirmed assets
        refreshAssetList();

        // Refresh currently selected asset info in each tab
        int mintIdx = mintAssetCombo->currentIndex();
        if (mintIdx >= 0) {
            QString assetId = mintAssetCombo->currentData().toString();
            if (!assetId.isEmpty()) {
                updateMintAssetInfo(assetId);
            }
        }

        int burnIdx = burnAssetCombo->currentIndex();
        if (burnIdx >= 0) {
            QString assetId = burnAssetCombo->currentData().toString();
            if (!assetId.isEmpty()) {
                updateBurnAssetUTXOs(assetId);
            }
        }

        // Refresh dashboard
        refreshICUDashboard();
    } catch (const std::exception& e) {
        // Silently ignore exceptions during block update refresh
        // User can manually refresh if needed
    } catch (...) {
        // Catch any other exceptions (like UniValue)
    }
}

// ===== NEW SLOT IMPLEMENTATIONS =====

void TreasuryPage::onQuorumChanged(int bps)
{
    double percentage = bps / 100.0;
    regQuorumPctLabel->setText(tr("(%1%)").arg(percentage, 0, 'f', 2));
}

void TreasuryPage::onBurnJointRequiredChanged(bool checked)
{
    if (checked) {
        // BURN_JOINT_REQUIRED restricts to P2PKH and P2WPKH only
        regFamilyP2WSHCheckbox->setChecked(false);
        regFamilyP2WSHCheckbox->setEnabled(false);
        regFamilyP2TRCheckbox->setChecked(false);
        regFamilyP2TRCheckbox->setEnabled(false);
        regPolicyRestrictionsLabel->setText(tr("⚠ BURN_JOINT_REQUIRED enabled: Only P2PKH and P2WPKH families allowed"));
        regPolicyRestrictionsLabel->setVisible(true);
    } else {
        // Re-enable all script families
        regFamilyP2WSHCheckbox->setEnabled(true);
        regFamilyP2TRCheckbox->setEnabled(true);
        regPolicyRestrictionsLabel->setVisible(false);
    }
}

void TreasuryPage::onICUTextChanged()
{
    QString text = regICUTextEdit->toPlainText();
    int size = text.toUtf8().size();

    // Estimate compressed size if compression is enabled
    if (regUseCompressionCheckbox && regUseCompressionCheckbox->isChecked()) {
        // Rough estimate: zstd typically achieves 40-60% compression for text
        size = static_cast<int>(size * 0.5);
        regPayloadSizeLabel->setText(tr("Payload size: ~%1 bytes (compressed)").arg(size));
    } else {
        regPayloadSizeLabel->setText(tr("Payload size: %1 bytes").arg(size));
    }
    // Refresh the designated-clause count/summary.
    updateClausesSummary();
}

void TreasuryPage::onPrecheckICU()
{
    // Run the SAME RPC the registration path runs (buildcanonicalicupayload) so the hash shown
    // here is exactly what registerasset will commit. With designated clauses the committed
    // canonical is the document body + an inline TSC-ICU-CONTEXT-1 block embedded by the node
    // (icu_clauses), so we pass the clause texts and hash THAT (not the body alone) — otherwise the
    // displayed "sign this value" would be wrong.
    QString body = regICUTextEdit->toPlainText().trimmed();

    if (body.isEmpty()) {
        showError(tr("Canonical text is empty"));
        return;
    }

    if (!clientModel || !walletModel) {
        showError(tr("Wallet not ready"));
        return;
    }

    // Option A: registration embeds the authoritative TSC-ICU-CONTEXT-1 block INSIDE canonical_text
    // via the node's icu_clauses builder, so the preview hash must be computed the same way (NOT via
    // a client-side appended schedule). Collect the ordered clause texts here.
    UniValue clausesArr(UniValue::VARR);
    int clauseCount = 0;
    for (const RegClauseRow& row : regClauseRows) {
        if (!row.textEdit) continue;
        const QString t = row.textEdit->toPlainText().trimmed();
        if (t.isEmpty()) continue;
        clausesArr.push_back(t.toStdString());
        ++clauseCount;
    }
    const bool hasSchedule = clauseCount > 0;
    const std::string acceptanceMode = "required";

    // Minimal witness placeholder — buildcanonicalicupayload requires a JSON
    // object and auto-fills canonical_hash. The witness_hash it returns is
    // discarded here; the real witness is built later in onRegisterAsset.
    UniValue witnessUniValue;
    if (!witnessUniValue.read(std::string("{\"version\":\"1.0\",\"canonical_hash\":\"placeholder\"}"))) {
        showError(tr("Internal error: failed to build witness placeholder"));
        return;
    }

    const int visibility = regICUVisibilityCombo ? regICUVisibilityCombo->currentData().toInt() : 0;

    // Run buildcanonicalicupayload on the body; when withClauses is true, pass icu_clauses so the
    // node embeds the inline context (matching registration). On error paints the hash label red.
    auto buildPayload = [&](bool withClauses, UniValue& out) -> bool {
        UniValue params(UniValue::VARR);
        params.push_back(body.toStdString());
        params.push_back(witnessUniValue);
        params.push_back(visibility);
        if (withClauses) {
            params.push_back(UniValue(UniValue::VNULL));  // [3] legacy icu_context: unused under Option A
            params.push_back(clausesArr);                 // [4] icu_clauses
            params.push_back(acceptanceMode);             // [5] icu_acceptance
        }
        try {
            out = clientModel->node().executeRpc("buildcanonicalicupayload", params,
                                                 walletModel->getWalletName().toStdString());
            return true;
        } catch (const std::exception& e) {
            regCanonicalHashLabel->setText(tr("(error)"));
            regCanonicalHashLabel->setStyleSheet("font-family: monospace; color: red; font-weight: bold;");
            regCopyHashButton->setEnabled(false);
            showError(tr("Failed to build ICU payload: %1").arg(QString::fromStdString(e.what())));
            return false;
        }
    };

    // Build the body first (no clauses): gives us the normalized body to show in the editor, and
    // (when there are no clauses) it is also the final canonical.
    UniValue bodyResult;
    if (!buildPayload(false, bodyResult)) return;

    // Normalize the document body in place so the issuer sees the exact committed bytes (CRLF, NFC,
    // trailing-space trim). The appended schedule is generated at register time and not shown here.
    if (bodyResult.exists("normalized_canonical_text")) {
        const QString normalized = QString::fromStdString(bodyResult["normalized_canonical_text"].get_str());
        if (!normalized.isEmpty() && normalized != regICUTextEdit->toPlainText()) {
            regICUTextEdit->setPlainText(normalized);
            regStatusText->append(tr("  Canonical text normalized for commitment (CRLF, NFC, trailing space trimmed)"));
        }
    }

    // The final asset canonical_hash is over body + the embedded inline TSC-ICU-CONTEXT-1 block.
    // Rebuild with icu_clauses to get the exact committed hash when clauses are designated.
    QString finalHash = QString::fromStdString(bodyResult["canonical_hash"].get_str());
    if (hasSchedule) {
        UniValue composedResult;
        if (!buildPayload(true, composedResult)) return;
        finalHash = QString::fromStdString(composedResult["canonical_hash"].get_str());
    }

    regCanonicalHashLabel->setText(finalHash);
    regCanonicalHashLabel->setStyleSheet("font-family: monospace; color: green; font-weight: bold;");
    regCopyHashButton->setEnabled(true);
    // One unambiguous hash in the UI: when clauses exist this value covers body + the embedded
    // inline context block, so label it as such (the editor only shows the body).
    if (regCanonicalHashCaption) {
        regCanonicalHashCaption->setText(hasSchedule ? tr("Final Hash (body + inline context):") : tr("Canonical Hash:"));
    }

    // The body was already normalized in place above (via bodyResult); just refresh the per-clause
    // summary against the normalized text.
    updateClausesSummary();

    regStatusText->append(tr("✓ Canonical text precheck passed"));
    regStatusText->append(tr("  Canonical hash: %1").arg(finalHash));
    if (hasSchedule) {
        regStatusText->append(tr("  Final on-chain canonical_hash (document body + embedded inline TSC-ICU-CONTEXT-1 block) — sign this exact value; witness goes in its own field"));
    } else {
        regStatusText->append(tr("  This is the on-chain canonical_hash — sign this exact value; witness goes in its own field"));
    }
}

void TreasuryPage::onCopyCanonicalHash()
{
    QString hash = regCanonicalHashLabel->text();
    if (hash == "(no hash computed)") {
        return;
    }

    QApplication::clipboard()->setText(hash);

    // Visual feedback
    QString originalStyle = regCanonicalHashLabel->styleSheet();
    regCanonicalHashLabel->setStyleSheet("font-family: monospace; color: blue; font-weight: bold;");
    QTimer::singleShot(500, this, [this, originalStyle]() {
        regCanonicalHashLabel->setStyleSheet(originalStyle);
    });

    regStatusText->append(tr("✓ Canonical hash copied to clipboard"));
}

void TreasuryPage::onExpandCanonicalText()
{
    openExpandedEditor(regICUTextEdit, tr("Canonical Text"));
}

void TreasuryPage::onExpandWitnessText()
{
    openExpandedEditor(regWitnessBundleEdit, tr("Witness Text"));
}

void TreasuryPage::openExpandedEditor(QTextEdit* target, const QString& title)
{
    if (!target) return;
    QDialog dlg(this);
    dlg.setWindowTitle(title);
    dlg.resize(900, 640);
    QVBoxLayout* dlgLayout = new QVBoxLayout(&dlg);
    QPlainTextEdit* bigEdit = new QPlainTextEdit(&dlg);
    bigEdit->setPlainText(target->toPlainText());
    bigEdit->setLineWrapMode(QPlainTextEdit::WidgetWidth);
    dlgLayout->addWidget(bigEdit);
    QDialogButtonBox* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dlg);
    connect(buttons, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    dlgLayout->addWidget(buttons);
    if (dlg.exec() == QDialog::Accepted) {
        target->setPlainText(bigEdit->toPlainText());
    }
}

void TreasuryPage::onAddClauseRow()
{
    addClauseRow();
}

QString TreasuryPage::composeScheduleCanonical(const QString& body, QString* errorOut)
{
    // Build the final canonical = main document + an appended "Schedule of designated clauses".
    // Each clause is a numbered, labelled section "=== Clause N - <label> ===\n<text>". The heading
    // makes each committed body a UNIQUE substring of the canonical, so the node accepts it even
    // when the clause text is also quoted in the body. Numbering is regenerated here, so
    // reordering/deleting rows renumbers cleanly. The main document stays free text.
    //
    // Normalization boundary: trimming the clause text and simplify()-ing the label are UI
    // normalization applied ONLY to the generated schedule entries. The free-text main body is
    // governed solely by the node's canonical normalization (CRLF/NFC/trailing-trim).
    //
    // Two rules keep extraction unambiguous: the clause text is trimmed and may not contain the
    // reserved heading token "=== Clause ", and labels may not contain "===". With those, the only
    // "=== Clause N - " occurrences inside the schedule are the generated headings, so
    // buildIcuContextJson() locates each entry exactly and the committed body is byte-identical to
    // the generated entry. The marker stays actor-neutral (a clause may be holder-affirmed or, in
    // v2, attested by a guarantor/auditor) — who acts on each clause lives in its label.
    if (errorOut) errorOut->clear();
    QStringList entries;
    for (const RegClauseRow& row : regClauseRows) {
        if (!row.textEdit) continue;
        const QString text = row.textEdit->toPlainText().trimmed();  // committed body == generated entry
        if (text.isEmpty()) continue;
        if (text.contains(QStringLiteral("=== Clause "))) {
            if (errorOut) *errorOut = tr("clause text may not contain the reserved heading marker \"=== Clause \"");
            return QString();
        }
        QString label = row.labelEdit ? row.labelEdit->text().simplified() : QString();  // one line, trimmed
        if (label.contains(QStringLiteral("==="))) {
            if (errorOut) *errorOut = tr("a clause label may not contain \"===\": %1").arg(label);
            return QString();
        }
        const int n = entries.size() + 1;
        entries << QStringLiteral("=== Clause %1 - %2 ===\n%3").arg(n).arg(label, text);
    }
    if (entries.isEmpty()) return body;  // no clauses -> whole-document
    QString composed = body;
    composed += QStringLiteral("\n\nSchedule of designated clauses\n");
    for (const QString& e : entries) composed += QStringLiteral("\n") + e + QStringLiteral("\n");
    return composed;
}

void TreasuryPage::addClauseRow(const QString& initialText, const QString& initialLabel)
{
    if (!regClausesContainer || !regClausesContainerLayout) return;

    RegClauseRow row;
    row.container = new QWidget(regClausesContainer);
    row.container->setObjectName("clauseRow");
    row.container->setStyleSheet("#clauseRow { border: 1px solid #444; border-radius: 4px; }");
    QVBoxLayout* rowLayout = new QVBoxLayout(row.container);
    rowLayout->setContentsMargins(6, 6, 6, 6);

    // No clause label: the committed inline TSC-ICU-CONTEXT-1 schema is {hash: text} only, so a label
    // cannot be saved or shown -- it was silently lost. Clauses are numbered (Clause 1, 2, ...) on
    // display. row.labelEdit stays null; initialLabel is kept for signature compat but intentionally unused.
    Q_UNUSED(initialLabel);
    QHBoxLayout* topRow = new QHBoxLayout();
    topRow->addStretch();
    row.removeButton = new QPushButton(tr("Remove"), row.container);
    topRow->addWidget(row.removeButton);
    rowLayout->addLayout(topRow);

    row.textEdit = new QPlainTextEdit(row.container);
    row.textEdit->setPlaceholderText(tr("Clause text the holder must affirm"));
    row.textEdit->setPlainText(initialText);
    row.textEdit->setMinimumHeight(70);
    rowLayout->addWidget(row.textEdit);

    // Optional signature payload (e.g. a guarantor's QES) attesting THIS clause. Committed into the
    // witness as an attestation covering this clause's body_hash. Opaque to the node.
    row.attestEdit = new QPlainTextEdit(row.container);
    row.attestEdit->setPlaceholderText(tr("Optional: signature payload (QES record / verifiable pointer) attesting this clause - committed into the witness covering this clause's hash"));
    row.attestEdit->setMinimumHeight(44);
    rowLayout->addWidget(row.attestEdit);

    QWidget* containerPtr = row.container;
    connect(row.removeButton, &QPushButton::clicked, this, [this, containerPtr]() {
        removeClauseRow(containerPtr);
    });
    connect(row.textEdit, &QPlainTextEdit::textChanged, this, &TreasuryPage::updateClausesSummary);

    regClausesContainerLayout->addWidget(row.container);
    regClauseRows.append(row);
    updateClausesSummary();
}

void TreasuryPage::removeClauseRow(QWidget* rowContainer)
{
    for (int i = 0; i < regClauseRows.size(); ++i) {
        if (regClauseRows[i].container == rowContainer) {
            regClauseRows[i].container->deleteLater();
            regClauseRows.removeAt(i);
            break;
        }
    }
    updateClausesSummary();
}

void TreasuryPage::updateClausesSummary()
{
    if (!regClausesSummaryLabel) return;
    int count = 0;
    qint64 bytes = 0;
    for (const RegClauseRow& row : regClauseRows) {
        if (!row.textEdit) continue;
        const QString t = row.textEdit->toPlainText().trimmed();
        if (t.isEmpty()) continue;
        ++count;
        bytes += t.toUtf8().size();
    }
    if (count == 0) {
        regClausesSummaryLabel->setText(tr("0 clauses - whole-document acceptance"));
    } else {
        regClausesSummaryLabel->setText(
            tr("%1 designated clause(s) - appended as a numbered schedule (~%2 bytes)").arg(count).arg(bytes));
    }
    regClausesSummaryLabel->setStyleSheet("color: #888;");
}

void TreasuryPage::onAddGovClauseRow()
{
    addGovClauseRow();
}

void TreasuryPage::addGovClauseRow(const QString& initialText, const QString& initialLabel)
{
    if (!govClausesContainer || !govClausesContainerLayout) return;

    RegClauseRow row;
    row.container = new QWidget(govClausesContainer);
    row.container->setObjectName("clauseRow");
    row.container->setStyleSheet("#clauseRow { border: 1px solid #444; border-radius: 4px; }");
    QVBoxLayout* rowLayout = new QVBoxLayout(row.container);
    rowLayout->setContentsMargins(6, 6, 6, 6);

    // No clause label: the committed inline TSC-ICU-CONTEXT-1 schema is {hash: text} only, so a label
    // cannot be saved or shown -- it was silently lost. Clauses are numbered (Clause 1, 2, ...) on
    // display. row.labelEdit stays null; initialLabel is kept for signature compat but intentionally unused.
    Q_UNUSED(initialLabel);
    QHBoxLayout* topRow = new QHBoxLayout();
    topRow->addStretch();
    row.removeButton = new QPushButton(tr("Remove"), row.container);
    topRow->addWidget(row.removeButton);
    rowLayout->addLayout(topRow);

    row.textEdit = new QPlainTextEdit(row.container);
    row.textEdit->setPlaceholderText(tr("Clause text the holder must affirm"));
    row.textEdit->setPlainText(initialText);
    row.textEdit->setMinimumHeight(70);
    rowLayout->addWidget(row.textEdit);

    row.attestEdit = new QPlainTextEdit(row.container);
    row.attestEdit->setPlaceholderText(tr("Optional: signature payload (QES record / verifiable pointer) attesting this clause - committed into the witness covering this clause's hash"));
    row.attestEdit->setMinimumHeight(44);
    rowLayout->addWidget(row.attestEdit);

    QWidget* containerPtr = row.container;
    connect(row.removeButton, &QPushButton::clicked, this, [this, containerPtr]() {
        removeGovClauseRow(containerPtr);
    });
    connect(row.textEdit, &QPlainTextEdit::textChanged, this, &TreasuryPage::updateGovClausesSummary);

    govClausesContainerLayout->addWidget(row.container);
    govClauseRows.append(row);
    updateGovClausesSummary();
}

void TreasuryPage::removeGovClauseRow(QWidget* rowContainer)
{
    for (int i = 0; i < govClauseRows.size(); ++i) {
        if (govClauseRows[i].container == rowContainer) {
            govClauseRows[i].container->deleteLater();
            govClauseRows.removeAt(i);
            break;
        }
    }
    updateGovClausesSummary();
}

void TreasuryPage::updateGovClausesSummary()
{
    if (!govClausesSummaryLabel) return;
    int count = 0;
    qint64 bytes = 0;
    for (const RegClauseRow& row : govClauseRows) {
        if (!row.textEdit) continue;
        const QString t = row.textEdit->toPlainText().trimmed();
        if (t.isEmpty()) continue;
        ++count;
        bytes += t.toUtf8().size();
    }
    if (count == 0) {
        govClausesSummaryLabel->setText(tr("0 clauses - whole-document amendment"));
    } else {
        govClausesSummaryLabel->setText(
            tr("%1 designated clause(s) - embedded as inline context (~%2 bytes)").arg(count).arg(bytes));
    }
    govClausesSummaryLabel->setStyleSheet("color: #888;");
}

QString TreasuryPage::buildIcuContextJson(const QString& canonical, QString* errorOut, QStringList* hashesOut)
{
    if (hashesOut) hashesOut->clear();
    // Assemble TSC-ICU-CONTEXT-1 from the appended schedule. `canonical` is the node-normalized
    // text returned by buildcanonicalicupayload. composeScheduleCanonical() guarantees clause text
    // contains no "=== Clause " token and the schedule is appended last, so the schedule's headings
    // are the LAST "=== Clause N - " occurrences in the text. We anchor on the last occurrence of
    // clause 1's heading (skipping any look-alikes the issuer typed in the free-text body) and walk
    // forward entry by entry. The committed body is the full entry (heading + trimmed text): a
    // unique substring of `canonical` that reproduces exactly what ValidateIcuContext recomputes
    // and finds. Returns "" + *errorOut empty for the no-clause (whole-document) case; "" +
    // *errorOut set on a real error.
    if (errorOut) errorOut->clear();
    int count = 0;
    for (const RegClauseRow& row : regClauseRows) {
        if (row.textEdit && !row.textEdit->toPlainText().trimmed().isEmpty()) ++count;
    }
    if (count == 0) return QString();  // whole-document acceptance

    // Anchor on the appended schedule, not a body look-alike: lastIndexOf() lands on clause 1 of the
    // real schedule because the generated headings are the last "=== Clause N - " occurrences.
    int start = canonical.lastIndexOf(QStringLiteral("=== Clause 1 - "));
    if (start < 0) {
        if (errorOut) *errorOut = tr("internal: designated-clauses schedule not found in the normalized text");
        return QString();
    }
    QJsonObject bodies;
    for (int n = 1; n <= count; ++n) {
        // Boundary to the next entry: the SPECIFIC next number, searched forward from this heading.
        // Clause text cannot contain "=== Clause ", so this only ever matches a generated heading.
        int next = -1;
        if (n < count) {
            next = canonical.indexOf(QStringLiteral("=== Clause %1 - ").arg(n + 1), start + 1);
            if (next < 0) {
                if (errorOut) *errorOut = tr("internal: clause %1 heading not found in the normalized text").arg(n + 1);
                return QString();
            }
        }
        QString entry = (next < 0) ? canonical.mid(start) : canonical.mid(start, next - start);
        entry = entry.trimmed();  // drop the inter-entry separator; text is pre-trimmed so this is exact
        const QByteArray digest = QCryptographicHash::hash(entry.toUtf8(), QCryptographicHash::Sha256);
        const QString keyHex = QString::fromLatin1(digest.toHex());  // lowercase hex of the 32-byte digest
        bodies.insert(keyHex, entry);
        if (hashesOut) hashesOut->append(keyHex);  // ordered per clause, for per-clause witness attestations
        start = next;  // clause n+1's heading (or -1 on the last iteration)
    }
    QJsonObject ctx;
    ctx.insert("spec", QStringLiteral("TSC-ICU-CONTEXT-1"));
    ctx.insert("parse_version", 1);
    ctx.insert("acceptance", QStringLiteral("required"));  // operator mandatory-only policy
    ctx.insert("bodies", bodies);
    return QString::fromUtf8(QJsonDocument(ctx).toJson(QJsonDocument::Indented));
}

void TreasuryPage::onBrowseVKFile()
{
    QString filename = QFileDialog::getOpenFileName(
        this,
        tr("Select Verification Key File"),
        QString(),
        tr("Binary Files (*.bin);;All Files (*)")
    );

    if (!filename.isEmpty()) {
        regVKFileEdit->setText(filename);

        // Try to load and compute commitment
        QFile vkFile(filename);
        if (vkFile.open(QIODevice::ReadOnly)) {
            QByteArray vkData = vkFile.readAll();
            vkFile.close();

            // Compute SHA256(vk_data)
            QByteArray vkCommit = QCryptographicHash::hash(vkData, QCryptographicHash::Sha256);
            QString vkCommitHex = vkCommit.toHex();

            regVKCommitLabel->setText(vkCommitHex.left(16) + "...");
            regVKCommitLabel->setStyleSheet("font-family: monospace; color: green;");
            regVKCommitLabel->setToolTip(vkCommitHex);

            regStatusText->append(tr("✓ VK file loaded: %1 bytes").arg(vkData.size()));
            regStatusText->append(tr("  VK commitment: %1...").arg(vkCommitHex.left(16)));
        } else {
            showError(tr("Failed to read VK file: %1").arg(filename));
        }
    }
}

void TreasuryPage::onDownloadProvingKey()
{
    m_zkParamsManager->ensureProvingKey(this);
}

void TreasuryPage::onProvingKeyReady(const QString& path)
{
    zkProvingKeyFileEdit->setText(path);
    if (zkProvingKeyStatusLabel) {
        zkProvingKeyStatusLabel->setText(tr("Downloaded and verified"));
        zkProvingKeyStatusLabel->setStyleSheet("color: #4CAF50; font-weight: bold;");
    }
    zkStatusText->append(tr("[OK] Proving key available: %1").arg(path));
}

void TreasuryPage::onProvingKeyFailed(const QString& error)
{
    if (zkProvingKeyStatusLabel) {
        zkProvingKeyStatusLabel->setText(tr("Not available: %1").arg(error));
        zkProvingKeyStatusLabel->setStyleSheet("color: #f44336;");
    }
    zkStatusText->append(tr("[ERROR] Proving key: %1").arg(error));
}

// ===== ZK COMPLIANCE TAB SLOT IMPLEMENTATIONS =====

void TreasuryPage::onZKAssetSelected(int index)
{
    if (index < 0 || !clientModel) {
        // No asset selected - show placeholder
        if (zkContentWidget) zkContentWidget->setVisible(false);
        if (zkNoComplianceLabel) zkNoComplianceLabel->setVisible(true);
        return;
    }

    QString assetId = zkAssetCombo->currentData().toString();
    if (assetId.isEmpty()) {
        // Pre-Registration Mode - show issuer tools only (no asset policy to load)
        if (zkContentWidget) zkContentWidget->setVisible(true);
        if (zkNoComplianceLabel) zkNoComplianceLabel->setVisible(false);

        zkStatusText->clear();
        zkStatusText->append(tr("[INFO] Pre-Registration Mode"));
        zkStatusText->append(tr("  Use 'Build Merkle Tree' to generate an initial compliance root"));
        zkStatusText->append(tr("  Then copy the root to the Registration tab"));

        // Hide "Current ZK Parameters" section in pre-reg mode (no asset yet)
        // The issuer group will still be visible for building the tree
        return;
    }

    zkStatusText->clear();
    zkStatusText->append(tr("[INFO] Loading ZK parameters for asset %1").arg(assetId));

    // Reset labels to default
    zkVKCommitLabel->setText(tr("-"));
    zkVKCommitLabel->setToolTip("");
    zkMaxRootAgeLabel->setText(tr("-"));
    zkCurrentRootLabel->setText(tr("-"));
    zkCurrentRootLabel->setToolTip("");
    zkTFRRequiredLabel->setText(tr("-"));

    try {
        UniValue params(UniValue::VARR);
        params.push_back(assetId.toStdString());
        UniValue policy = clientModel->node().executeRpc("getassetpolicy", params, "");

        bool hasCompliance = false;

        if (policy.exists("zk_vk_commitment")) {
            QString vkCommit = QString::fromStdString(policy.find_value("zk_vk_commitment").get_str());
            // Check if commitment is non-zero (not all zeros)
            bool isNonZero = false;
            for (QChar c : vkCommit) {
                if (c != '0') {
                    isNonZero = true;
                    break;
                }
            }
            if (isNonZero) {
                zkVKCommitLabel->setText(vkCommit.left(16) + "...");
                zkVKCommitLabel->setToolTip(vkCommit);
                hasCompliance = true;
            }
        }

        if (policy.exists("max_root_age")) {
            int maxRootAge = policy.find_value("max_root_age").getInt<int>();
            zkMaxRootAgeLabel->setText(tr("%1 seconds").arg(maxRootAge));
            hasCompliance = true;
        }

        if (policy.exists("compliance_root_commit")) {
            QString rootCommit = QString::fromStdString(policy.find_value("compliance_root_commit").get_str());
            zkCurrentRootLabel->setText(rootCommit.left(16) + "...");
            zkCurrentRootLabel->setToolTip(rootCommit);
            hasCompliance = true;
        }

        // Check TFR_ANCHOR_REQUIRED flag (0x0020)
        if (policy.exists("tfr_flags")) {
            uint32_t tfrFlags = policy.find_value("tfr_flags").getInt<uint32_t>();
            bool tfrRequired = (tfrFlags & 0x0020u) != 0;
            zkTFRRequiredLabel->setText(tfrRequired ? tr("Yes") : tr("No"));
            if (zkTFRAnchorEdit) {
                if (tfrRequired) {
                    zkTFRAnchorEdit->setEnabled(true);
                    zkStatusText->append(tr("[INFO] TFR anchor is REQUIRED for this asset"));
                } else {
                    zkTFRAnchorEdit->setEnabled(false);
                }
            }
        }

        // Show/hide content based on compliance presence
        if (!hasCompliance) {
            zkContentWidget->setVisible(false);
            zkNoComplianceLabel->setVisible(true);
            zkStatusText->append(tr("[INFO] This asset does not have compliance/KYC requirements configured"));
            zkStatusText->append(tr("[INFO] ZK proof generation is not required for this asset"));
        } else {
            zkContentWidget->setVisible(true);
            zkNoComplianceLabel->setVisible(false);
            zkStatusText->append(tr("[OK] ZK parameters loaded successfully"));
        }
    } catch (UniValue& objError) {
        QString message;
        try {
            int code = objError.find_value("code").getInt<int>();
            std::string detail = objError.find_value("message").get_str();
            message = tr("RPC %1: %2").arg(code).arg(QString::fromStdString(detail));
        } catch (...) {
            message = QString::fromStdString(objError.write());
        }
        zkStatusText->append(tr("[ERROR] Could not load asset policy: %1").arg(message));
        if (zkTFRAnchorEdit) {
            zkTFRAnchorEdit->setEnabled(false);
        }
        zkStatusText->append(tr("[INFO] This asset may not be registered or may not have compliance requirements"));
    } catch (const std::exception& e) {
        zkStatusText->append(tr("[WARNING] Could not load asset policy: %1").arg(e.what()));
        zkStatusText->append(tr("[INFO] This asset may not be registered or may not have compliance requirements"));
    }
}

void TreasuryPage::onBuildMerkleTree()
{
    if (!walletModel || !clientModel) {
        showError(tr("Wallet or client model not available"));
        return;
    }

    zkStatusText->clear();
    zkStatusText->append(tr("[INFO] Building Merkle tree from identity list..."));

    QString identitiesText = zkComplianceListEdit->toPlainText().trimmed();
    if (identitiesText.isEmpty()) {
        zkStatusText->append(tr("[ERROR] Identity list is empty"));
        showError(tr("Please enter at least one identity in format:\npubkey,country,age,index"));
        return;
    }

    try {
        // Parse identities from text (format: pubkey,country,age,index per line)
        QStringList lines = identitiesText.split('\n', Qt::SkipEmptyParts);
        UniValue identities(UniValue::VARR);

        for (int i = 0; i < lines.size(); ++i) {
            QString line = lines[i].trimmed();
            if (line.isEmpty()) continue;

            QStringList parts = line.split(',');
            if (parts.size() < 4) {
                zkStatusText->append(tr("[WARN] Line %1: Invalid format (need: pubkey,country,age,index)").arg(i+1));
                continue;
            }

            UniValue identity(UniValue::VOBJ);
            identity.pushKV("master_pubkey", parts[0].trimmed().toStdString());
            identity.pushKV("country", parts[1].trimmed().toInt());
            identity.pushKV("age", parts[2].trimmed().toInt());
            identity.pushKV("index", parts[3].trimmed().toInt());

            identities.push_back(identity);
        }

        if (identities.size() == 0) {
            showError(tr("No valid identities found. Format:\npubkey,country,age,index"));
            return;
        }

        zkStatusText->append(tr("[INFO] Parsed %1 identities, calling generatecomplianceroot...").arg(identities.size()));

        // Get selected circuit
        QString selectedCircuit = zkCircuitComboIssuer->currentData().toString();
        zkStatusText->append(tr("[INFO] Using circuit: %1").arg(selectedCircuit));

        // Call generatecomplianceroot RPC
        UniValue params(UniValue::VARR);
        params.push_back(identities);
        params.push_back(selectedCircuit.toStdString());

        UniValue result = clientModel->node().executeRpc("generatecomplianceroot", params,
                                                         walletModel->getWalletName().toStdString());

        // Extract compliance root
        QString complianceRoot = QString::fromStdString(result["compliance_root"].get_str());
        lastComplianceRoot = complianceRoot;
        lastComplianceData = QString::fromStdString(result.write(2));  // Pretty JSON

        // Display root
        zkNewRootLabel->setText(complianceRoot.left(16) + "...");
        zkNewRootLabel->setStyleSheet("font-family: monospace; color: green; font-weight: bold;");
        zkNewRootLabel->setToolTip(complianceRoot);

        // Enable buttons
        zkRotateRootButton->setEnabled(true);
        zkExportProofsButton->setEnabled(true);
        zkCopyToRegistrationButton->setEnabled(true);

        zkStatusText->append(tr("✓ Merkle tree built successfully"));
        zkStatusText->append(tr("  Root: %1...").arg(complianceRoot.left(32)));
        zkStatusText->append(tr("  Identities: %1").arg(result["total_identities"].getInt<int>()));
        zkStatusText->append(tr("  Tree depth: %1").arg(result["tree_depth"].getInt<int>()));

        showSuccess(tr("Compliance root generated successfully"));

    } catch (const std::exception& e) {
        zkStatusText->append(tr("[ERROR] %1").arg(e.what()));
        showError(tr("Failed to build Merkle tree: %1").arg(e.what()));
    }
}

void TreasuryPage::onExportMerkleProofs()
{
    if (lastComplianceData.isEmpty()) {
        showError(tr("No Merkle tree data available. Build a tree first."));
        return;
    }

    // Ask user for save location
    QString fileName = QFileDialog::getSaveFileName(
        this,
        tr("Export Merkle Proofs"),
        "merkle_proofs.json",
        tr("JSON Files (*.json);;All Files (*)")
    );

    if (fileName.isEmpty()) {
        return;  // User canceled
    }

    try {
        // Write JSON to file
        QFile file(fileName);
        if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            showError(tr("Failed to open file for writing"));
            return;
        }

        QTextStream out(&file);
        out << lastComplianceData;
        file.close();

        zkStatusText->append(tr("[OK] Merkle proofs exported to: %1").arg(fileName));
        showSuccess(tr("Merkle proofs exported successfully!"));

    } catch (const std::exception& e) {
        showError(tr("Failed to export proofs: %1").arg(e.what()));
    }
}

void TreasuryPage::onRotateComplianceRoot()
{
    if (!walletModel || !clientModel) {
        showError(tr("Wallet or client model not available"));
        return;
    }

    QString assetId = zkAssetCombo->currentData().toString();
    if (assetId.isEmpty()) {
        showError(tr("No asset selected"));
        return;
    }

    if (lastComplianceRoot.isEmpty()) {
        showError(tr("No compliance root available. Build a Merkle tree first."));
        return;
    }

    zkStatusText->clear();
    zkStatusText->append(tr("[INFO] Rotating compliance root for asset %1...").arg(assetId.left(16)));

    try {
        // Ensure wallet is unlocked before rotating compliance root
        WalletModel::UnlockContext ctx(walletModel->requestUnlock());
        if (!ctx.isValid()) {
            zkStatusText->append(tr("[ERROR] Wallet unlock required to rotate compliance root"));
            showError(tr("Wallet locked. Please unlock the wallet to rotate the compliance root."));
            return;
        }

        // Call updatecomplianceroot RPC
        UniValue params(UniValue::VARR);
        params.push_back(assetId.toStdString());
        params.push_back(lastComplianceRoot.toStdString());

        UniValue options(UniValue::VOBJ);
        options.pushKV("broadcast", true);
        params.push_back(options);

        UniValue result = clientModel->node().executeRpc("updatecomplianceroot", params,
                                                         walletModel->getWalletName().toStdString());

        QString txid = QString::fromStdString(result["txid"].get_str());
        zkStatusText->append(tr("✓ Compliance root rotation transaction created"));
        zkStatusText->append(tr("  Txid: %1").arg(txid));
        zkStatusText->append(tr("  New Root: %1...").arg(lastComplianceRoot.left(32)));

        showSuccess(tr("Compliance root updated successfully!"));

        // Clear the cached data after successful rotation
        lastComplianceRoot.clear();
        lastComplianceData.clear();
        zkNewRootLabel->setText(tr("-"));
        zkRotateRootButton->setEnabled(false);
        zkExportProofsButton->setEnabled(false);
        zkCopyToRegistrationButton->setEnabled(false);

    } catch (const std::exception& e) {
        zkStatusText->append(tr("[ERROR] %1").arg(e.what()));
        showError(tr("Failed to rotate compliance root: %1").arg(e.what()));
    }
}

void TreasuryPage::onCopyRootToRegistration()
{
    if (lastComplianceRoot.isEmpty()) {
        showError(tr("No compliance root available. Build a Merkle tree first."));
        return;
    }

    // Copy the compliance root to the Registration tab's field
    regInitialComplianceRootEdit->setText(lastComplianceRoot);

    // Switch to the Registration tab to show the user
    if (tabWidget) {
        tabWidget->setCurrentWidget(registrationTab);
    }

    zkStatusText->append(tr("[OK] Compliance root copied to Registration tab"));
    showSuccess(tr("Compliance root copied!\nSwitch to Registration tab to register your KYC asset."));
}

void TreasuryPage::onGenerateMasterKey()
{
    if (!walletModel || !clientModel) {
        showError(tr("Wallet or client model not available"));
        return;
    }

    zkStatusText->clear();
    zkStatusText->append(tr("[INFO] Generating new master key for KYC..."));

    try {
        // Generate a new address
        UniValue params(UniValue::VARR);
        UniValue result = clientModel->node().executeRpc("getnewaddress", params,
                                                         walletModel->getWalletName().toStdString());
        QString address = QString::fromStdString(result.get_str());

        // Get address info to extract public key
        UniValue infoParams(UniValue::VARR);
        infoParams.push_back(address.toStdString());
        UniValue addressInfo = clientModel->node().executeRpc("getaddressinfo", infoParams,
                                                              walletModel->getWalletName().toStdString());

        if (!addressInfo.exists("pubkey")) {
            showError(tr("Could not extract public key from address. Try using a legacy address type."));
            return;
        }

        QString pubkey = QString::fromStdString(addressInfo.find_value("pubkey").get_str());

        // Find the master pubkey edit widget and update it
        QLineEdit* masterPubkeyEdit = zkHolderGroup->findChild<QLineEdit*>("zkMasterPubkeyEdit");
        if (masterPubkeyEdit) {
            masterPubkeyEdit->setText(pubkey);
        }

        // Update address label
        QLabel* masterAddressLabel = zkHolderGroup->findChild<QLabel*>("zkMasterAddressLabel");
        if (masterAddressLabel) {
            masterAddressLabel->setText(tr("Address: %1").arg(address));
            masterAddressLabel->setToolTip(tr("Use dumpprivkey %1 to get private key for ZK proof generation").arg(address));
        }

        zkStatusText->append(tr("[OK] Master key generated"));
        zkStatusText->append(tr("  Address: %1").arg(address));
        zkStatusText->append(tr("  Public Key: %1...").arg(pubkey.left(32)));
        zkStatusText->append(tr(""));
        zkStatusText->append(tr("IMPORTANT: Share this public key with the asset issuer."));
        zkStatusText->append(tr("Keep your private key safe - you'll need it to generate ZK proofs."));
        zkStatusText->append(tr("To get private key later: dumpprivkey %1").arg(address));

        showSuccess(tr("Master key generated! Copy the public key to share with issuer."));

    } catch (const std::exception& e) {
        zkStatusText->append(tr("[ERROR] %1").arg(e.what()));
        showError(tr("Failed to generate master key: %1").arg(e.what()));
    }
}

void TreasuryPage::onCopyMasterKey()
{
    QLineEdit* masterPubkeyEdit = zkHolderGroup->findChild<QLineEdit*>("zkMasterPubkeyEdit");
    if (!masterPubkeyEdit || masterPubkeyEdit->text().isEmpty()) {
        showError(tr("No master key to copy. Generate one first."));
        return;
    }

    QString pubkey = masterPubkeyEdit->text();
    QClipboard* clipboard = QApplication::clipboard();
    clipboard->setText(pubkey);

    zkStatusText->append(tr("[OK] Master public key copied to clipboard"));
    showSuccess(tr("Public key copied! Share this with the asset issuer for KYC registration."));
}

void TreasuryPage::onBrowseProvingKey()
{
    QString filename = QFileDialog::getOpenFileName(
        this,
        tr("Select Proving Key File"),
        QString(),
        tr("Binary Files (*.bin);;All Files (*)")
    );

    if (!filename.isEmpty()) {
        zkProvingKeyFileEdit->setText(filename);
        m_zkParamsManager->setManualProvingKeyPath(filename);
        if (zkProvingKeyStatusLabel) {
            zkProvingKeyStatusLabel->setText(tr("Manual override"));
            zkProvingKeyStatusLabel->setStyleSheet("color: #FF9800; font-weight: bold;");
        }
        zkStatusText->append(tr("[INFO] Proving key file selected: %1").arg(filename));
    }
}

void TreasuryPage::onGenerateZKProof()
{
    if (!walletModel || !clientModel) {
        showError(tr("Wallet or client model not available"));
        return;
    }

    QString assetId = zkAssetCombo->currentData().toString();
    if (assetId.isEmpty()) {
        showError(tr("No asset selected"));
        return;
    }

    // Auto-trigger download if proving key not available
    if (!m_zkParamsManager->isProvingKeyAvailable() && zkProvingKeyFileEdit->text().trimmed().isEmpty()) {
        m_zkParamsManager->ensureProvingKey(this);
        return;
    }

    QString txid = zkProofTxidEdit->text().trimmed();
    if (txid.isEmpty()) {
        showError(tr("UTXO txid required"));
        return;
    }

    QString witnessJson = zkProofWitnessEdit->toPlainText().trimmed();
    if (witnessJson.isEmpty()) {
        showError(tr("Witness JSON required"));
        return;
    }

    zkStatusText->clear();
    zkStatusText->append(tr("[INFO] Generating ZK proof for asset %1").arg(assetId));

    try {
        // Build public inputs
        UniValue publicInputs(UniValue::VOBJ);
        publicInputs.pushKV("chain_separator", "regtest");  // TODO: Detect network
        publicInputs.pushKV("asset_id", assetId.toStdString());

        // Get current compliance root from policy
        UniValue policyParams(UniValue::VARR);
        policyParams.push_back(assetId.toStdString());
        UniValue policy = clientModel->node().executeRpc("getassetpolicy", policyParams, "");

        if (policy.exists("compliance_root_commit")) {
            publicInputs.pushKV("compliance_root", policy.find_value("compliance_root_commit").get_str());
        }

        // tfr_anchor from UTXO
        QString tfrAnchor = txid + ":" + QString::number(zkProofVoutSpinBox->value());
        publicInputs.pushKV("tfr_anchor", tfrAnchor.toStdString());

        // Call generatezkproof RPC
        UniValue proofParams(UniValue::VARR);
        proofParams.push_back(assetId.toStdString());
        proofParams.push_back(publicInputs);
        proofParams.push_back(witnessJson.toStdString());

        UniValue result = clientModel->node().executeRpc("generatezkproof", proofParams,
                                                         walletModel->getWalletName().toStdString());

        QString proofHex = QString::fromStdString(result.find_value("proof").get_str());
        zkProofOutputEdit->setPlainText(proofHex);

        zkStatusText->append(tr("[OK] ZK proof generated successfully"));
        zkStatusText->append(tr("  Proof size: %1 bytes").arg(proofHex.length() / 2));

        showSuccess(tr("ZK proof generated!"));
    } catch (const std::exception& e) {
        zkStatusText->append(tr("[ERROR] %1").arg(e.what()));
        showError(tr("Failed to generate ZK proof: %1").arg(e.what()));
    }
}

// ===== GOVERNANCE TAB SLOT IMPLEMENTATIONS =====

void TreasuryPage::onGovAssetSelected(int index)
{
    if (index < 0 || !clientModel) {
        // No asset selected - show placeholder
        if (govContentWidget) govContentWidget->setVisible(false);
        if (govNoGovernanceLabel) govNoGovernanceLabel->setVisible(true);
        return;
    }

    QString assetId = govAssetCombo->currentData().toString();
    if (assetId.isEmpty()) {
        // Empty asset - show placeholder
        if (govContentWidget) govContentWidget->setVisible(false);
        if (govNoGovernanceLabel) govNoGovernanceLabel->setVisible(true);
        return;
    }

    // Reset labels
    govQuorumLabel->setText(tr("-"));
    govSettledSupplyLabel->setText(tr("-"));
    govUTXOTable->setRowCount(0);

    govStatusText->clear();
    govStatusText->append(tr("[INFO] Loading governance parameters for asset %1").arg(assetId));

    try {
        UniValue params(UniValue::VARR);
        params.push_back(assetId.toStdString());
        UniValue policy = clientModel->node().executeRpc("getassetpolicy", params, "");

        bool hasGovernance = false;

        if (policy.exists("policy_quorum_bps")) {
            int quorum = policy.find_value("policy_quorum_bps").getInt<int>();
            if (quorum > 0) {
                govQuorumLabel->setText(tr("%1 bps (%2%)").arg(quorum).arg(quorum / 100.0, 0, 'f', 2));
                hasGovernance = true;
            }
        }

        // Show/hide content based on governance presence
        if (!hasGovernance) {
            govContentWidget->setVisible(false);
            govNoGovernanceLabel->setVisible(true);
            govStatusText->append(tr("[INFO] This asset does not have governance features configured (quorum = 0)"));
            updateGovernanceProposalSummary(QString());
            return;
        } else {
            govContentWidget->setVisible(true);
            govNoGovernanceLabel->setVisible(false);
        }

        // Calculate settled supply from issued_total - burned_total
        currentGovAssetDecimals = policy.exists("decimals") ? policy.find_value("decimals").getInt<uint8_t>() : 0;

        if (policy.exists("issued_total") && policy.exists("burned_total")) {
            uint64_t issued = policy.find_value("issued_total").getInt<uint64_t>();
            uint64_t burned = policy.find_value("burned_total").getInt<uint64_t>();
            uint64_t supply = issued - burned;
            govSettledSupplyLabel->setText(formatAssetAmount(supply, currentGovAssetDecimals));
        } else {
            govSettledSupplyLabel->setText(tr("0"));
        }

        govStatusText->append(tr("[OK] Governance parameters loaded"));

        // Populate UTXO table with asset holdings
        if (walletModel) {
            // Build asset filter array
            UniValue assetFilter(UniValue::VARR);
            assetFilter.push_back(assetId.toStdString());

            UniValue listParams(UniValue::VARR);
            listParams.push_back(assetFilter);  // First param: asset filter array

            UniValue unspent = clientModel->node().executeRpc("listassetutxos", listParams,
                                                               walletModel->getWalletName().toStdString());

            if (unspent.isArray()) {
                for (size_t i = 0; i < unspent.size(); ++i) {
                    const UniValue& utxo = unspent[i];
                    QString txid = QString::fromStdString(utxo.find_value("txid").get_str());
                    int vout = utxo.find_value("vout").getInt<int>();
                    uint64_t amount = utxo.find_value("asset_units").getInt<uint64_t>();
                    bool spendable = !utxo.exists("spendable") || utxo.find_value("spendable").get_bool();
                    bool solvable = !utxo.exists("solvable") || utxo.find_value("solvable").get_bool();

                    if (!spendable || !solvable) {
                        govStatusText->append(
                            tr("[WARN] Skipping UTXO %1:%2 (wallet cannot sign this output)")
                                .arg(txid.left(16) + "...", QString::number(vout)));
                        continue;
                    }
                    // Get decimals from UTXO response if available, otherwise from policy
                    uint8_t decimals = utxo.exists("decimals") ? utxo.find_value("decimals").getInt<uint8_t>() :
                                      (policy.exists("decimals") ? policy.find_value("decimals").getInt<uint8_t>() : 0);

                    int row = govUTXOTable->rowCount();
                    govUTXOTable->insertRow(row);
                    govUTXOTable->setItem(row, 0, new QTableWidgetItem(txid.left(16) + "..."));
                    govUTXOTable->setItem(row, 1, new QTableWidgetItem(QString::number(vout)));
                    govUTXOTable->setItem(row, 2, new QTableWidgetItem(formatAssetAmount(amount, decimals)));

                    // Add checkbox in the Select column
                    QTableWidgetItem* checkItem = new QTableWidgetItem();
                    checkItem->setFlags(Qt::ItemIsUserCheckable | Qt::ItemIsEnabled);
                    checkItem->setCheckState(Qt::Unchecked);
                    checkItem->setData(Qt::UserRole, txid);  // Store full txid
                    checkItem->setData(Qt::UserRole + 1, vout);  // Store vout
                    checkItem->setData(Qt::UserRole + 2, QVariant::fromValue(amount));  // Store amount
                    govUTXOTable->setItem(row, 3, checkItem);
                }
                govStatusText->append(tr("[INFO] Found %1 spendable UTXO(s) for voting").arg(govUTXOTable->rowCount()));
            }
        }
        onGovTemplatePSBTChanged();
    } catch (UniValue& objError) {
        QString message;
        try {
            int code = objError.find_value("code").getInt<int>();
            std::string detail = objError.find_value("message").get_str();
            message = tr("RPC %1: %2").arg(code).arg(QString::fromStdString(detail));
        } catch (...) {
            message = QString::fromStdString(objError.write());
        }
        govStatusText->append(tr("[ERROR] Failed to load governance parameters: %1").arg(message));
    } catch (const std::exception& e) {
        govStatusText->append(tr("[ERROR] Failed to load governance parameters: %1").arg(e.what()));
    }
}

void TreasuryPage::onPrepareRotation()
{
    if (!walletModel || !clientModel) {
        showError(tr("Wallet or client model not available"));
        return;
    }

    QString assetId = govAssetCombo->currentData().toString();
    if (assetId.isEmpty()) {
        showError(tr("No asset selected"));
        return;
    }

    govStatusText->clear();
    govStatusText->append(tr("[INFO] Preparing rotation for asset %1").arg(assetId));

    try {
        UniValue params(UniValue::VARR);
        params.push_back(assetId.toStdString());

        UniValue options(UniValue::VOBJ);

        // Get current asset decimals for conversion
        UniValue policyParams(UniValue::VARR);
        policyParams.push_back(assetId.toStdString());
        UniValue currentPolicy = clientModel->node().executeRpc("getassetpolicy", policyParams, "");
        uint8_t decimals = currentPolicy.exists("decimals") ? currentPolicy.find_value("decimals").getInt<uint8_t>() : 8;

        // Add new policy parameters if specified (0 means no change for these fields)
        if (govNewIssuanceCapSpinBox->value() > 0) {
            // Convert coins to base units using decimals
            uint64_t issuanceCapUnits = static_cast<uint64_t>(govNewIssuanceCapSpinBox->value()) * static_cast<uint64_t>(std::pow(10, decimals));
            options.pushKV("issuance_cap_units", issuanceCapUnits);
        }
        if (govNewQuorumSpinBox->value() > 0) {
            options.pushKV("policy_quorum_bps", govNewQuorumSpinBox->value());
        }

        // Add ICU governance text rotation if provided
        QString icuText = govICUTextEdit->toPlainText().trimmed();
        if (!icuText.isEmpty()) {
            govStatusText->append(tr("[INFO] Building new governance text payload..."));

            // Same fidelity as the Register form: inline TSC-ICU-CONTEXT-1 clauses + whole-doc/
            // per-clause attestations, built through the shared helper so an amendment commits
            // identical structure and never silently drops clauses/attestations.
            const int visibility = govICUVisibilityCombo->currentData().toInt();
            const IcuPayloadBuildResult built = buildIcuPayloadFromForm(
                icuText, visibility, govWitnessTextEdit, govClauseRows, govWholeDocAttestEdit, govStatusText);
            if (!built.ok) return;  // helper already reported the error

            options.pushKV("icu_payload_plain", built.payloadPlain.toStdString());
            options.pushKV("icu_visibility", visibility);

            govStatusText->append(tr("  ICU payload size: %1 bytes").arg(built.payloadSize));
            govStatusText->append(tr("  Canonical hash: %1").arg(built.canonicalHash.left(16) + "..."));
            govStatusText->append(tr("  Visibility: %1").arg(visibility == 0 ? "Public" : "Holder-Only"));
        }

        // Ensure adequate fee rate so the rotation clears mempool policy
        options.pushKV("fee_rate", 5.0);  // 5 sat/vB default

        params.push_back(options);

        UniValue result = clientModel->node().executeRpc("prepare_rotation", params,
                                                         walletModel->getWalletName().toStdString());

        if (!result.isObject()) {
            throw std::runtime_error("prepare_rotation returned invalid response");
        }

        if (!result.exists("psbt") || !result.exists("required_units")) {
            throw std::runtime_error("prepare_rotation response missing required fields");
        }

        QString psbt = QString::fromStdString(result.find_value("psbt").get_str());
        uint64_t requiredUnits = result.find_value("required_units").getInt<uint64_t>();

        if (psbt.isEmpty()) {
            throw std::runtime_error("prepare_rotation returned empty PSBT");
        }

        govPSBTEdit->setPlainText(psbt);
        govRequiredUnitsLabel->setText(tr("Required units: %1").arg(requiredUnits));

        if (govBallotPSBTEdit) {
            govBallotPSBTEdit->setPlainText(psbt);
        }
        if (govBallotListEdit) {
            govBallotListEdit->clear();
        }
        if (govMergedPSBTEdit) {
            govMergedPSBTEdit->clear();
        }

        lastRequiredUnits = requiredUnits;
        lastMergedBallotUnits.reset();
        lastMergedQuorumMet.reset();

        if (result.exists("summary") && result["summary"].isObject()) {
            const UniValue& summary = result["summary"];
            QStringList summaryLines;
            for (const std::string& key : summary.getKeys()) {
                summaryLines.append(
                    tr("  %1: %2").arg(QString::fromStdString(key))
                                   .arg(QString::fromStdString(summary[key].get_str())));
            }
            if (!summaryLines.isEmpty()) {
                govStatusText->append(tr("Rotation summary:"));
                for (const QString& line : summaryLines) {
                    govStatusText->append(line);
                }
            }
        }

        // Automatically copy PSBT to clipboard
        QApplication::clipboard()->setText(psbt);

        govStatusText->append(tr("[OK] Rotation prepared successfully"));
        govStatusText->append(tr("  Required voting units: %1").arg(requiredUnits));
        govStatusText->append(tr("  PSBT size: %1 characters").arg(psbt.length()));
        govStatusText->append(tr("  ✓ PSBT automatically copied to clipboard"));
        govStatusText->append(tr("  Share the PSBT with token holders for voting"));

        showSuccess(tr("Rotation template created and copied to clipboard!"));
    } catch (const UniValue& objError) {
        QString message;
        try {
            int code = objError.find_value("code").getInt<int>();
            std::string detail = objError.find_value("message").get_str();
            message = tr("RPC Error %1: %2").arg(code).arg(QString::fromStdString(detail));
        } catch (...) {
            message = QString::fromStdString(objError.write());
        }
        govStatusText->append(tr("[ERROR] %1").arg(message));
        showError(tr("Failed to prepare rotation: %1").arg(message));
    } catch (const std::exception& e) {
        govStatusText->append(tr("[ERROR] %1").arg(e.what()));
        showError(tr("Failed to prepare rotation: %1").arg(e.what()));
    } catch (...) {
        govStatusText->append(tr("[ERROR] Unknown exception"));
        showError(tr("Failed to prepare rotation: Unknown error"));
    }
}

void TreasuryPage::onCastBallot()
{
    if (!walletModel || !clientModel) {
        showError(tr("Wallet or client model not available"));
        return;
    }

    QString psbt = govBallotPSBTEdit->toPlainText().trimmed();
    if (psbt.isEmpty()) {
        showError(tr("Template PSBT required"));
        return;
    }

    govStatusText->clear();
    govStatusText->append(tr("[INFO] Casting ballot..."));

    if (!govUTXOTable) {
        showError(tr("UTXO table not available"));
        return;
    }

    try {
        // Collect selected UTXOs from govUTXOTable
        UniValue selectedUTXOs(UniValue::VARR);

        for (int row = 0; row < govUTXOTable->rowCount(); ++row) {
            QTableWidgetItem* checkItem = govUTXOTable->item(row, 3);
            if (checkItem && checkItem->checkState() == Qt::Checked) {
                UniValue utxo(UniValue::VOBJ);
                QString txid = checkItem->data(Qt::UserRole).toString();
                int vout = checkItem->data(Qt::UserRole + 1).toInt();
                utxo.pushKV("txid", txid.toStdString());
                utxo.pushKV("vout", vout);
                selectedUTXOs.push_back(utxo);
            }
        }

        if (selectedUTXOs.size() == 0) {
            showError(tr("No UTXOs selected. Please check at least one UTXO to vote with."));
            return;
        }

        govStatusText->append(tr("[INFO] Using %1 UTXO(s) for voting").arg(selectedUTXOs.size()));

        WalletModel::UnlockContext ctx(walletModel->requestUnlock());
        if (!ctx.isValid()) {
            govStatusText->append(tr("[ERROR] Wallet unlock required to sign ballot"));
            showError(tr("Wallet locked. Please unlock the wallet to sign the governance ballot."));
            return;
        }

        UniValue params(UniValue::VARR);
        params.push_back(psbt.toStdString());
        params.push_back(selectedUTXOs);

        UniValue result = clientModel->node().executeRpc("ballot", params,
                                                         walletModel->getWalletName().toStdString());

        QString signedPSBT = QString::fromStdString(result.find_value("psbt").get_str());
        uint64_t ballotUnits = result.find_value("ballot_units").getInt<uint64_t>();

        govSignedPSBTEdit->setPlainText(signedPSBT);

        if (govBallotListEdit) {
            QString existing = govBallotListEdit->toPlainText().trimmed();
            QString mergedList = existing;
            if (!mergedList.isEmpty()) {
                mergedList.append('\n');
            }
            mergedList.append(signedPSBT);
            govBallotListEdit->setPlainText(mergedList);
        }
        if (govMergedPSBTEdit) {
            govMergedPSBTEdit->clear();
        }
        lastMergedBallotUnits.reset();
        lastMergedQuorumMet.reset();

        govStatusText->append(tr("[OK] Ballot cast successfully"));
        govStatusText->append(tr("  Your voting power: %1 units").arg(ballotUnits));
        govStatusText->append(tr("  Send the signed PSBT back to the issuer"));

        showSuccess(tr("Ballot cast with %1 units!").arg(ballotUnits));
    } catch (const UniValue& objError) {
        QString errorMsg = QString::fromStdString(objError["message"].get_str());
        govStatusText->append(tr("[ERROR] %1").arg(errorMsg));
        showError(tr("Failed to cast ballot: %1").arg(errorMsg));
    } catch (const std::exception& e) {
        govStatusText->append(tr("[ERROR] %1").arg(e.what()));
        showError(tr("Failed to cast ballot: %1").arg(e.what()));
    }
}

void TreasuryPage::onGovTemplatePSBTChanged()
{
    QString templatePsbt;
    if (govPSBTEdit) {
        templatePsbt = govPSBTEdit->toPlainText().trimmed();
    }
    if (templatePsbt.isEmpty() && govBallotPSBTEdit) {
        templatePsbt = govBallotPSBTEdit->toPlainText().trimmed();
    }
    updateGovernanceProposalSummary(templatePsbt);

    // Show/hide "Publish to Network" button (issuer mode only, when PSBT exists)
    if (govPublishToNostrButton) {
        bool hasPsbt = govPSBTEdit && !govPSBTEdit->toPlainText().trimmed().isEmpty();
        govPublishToNostrButton->setVisible(isIssuerMode && hasPsbt);
    }
}

void TreasuryPage::onRefreshProposalsList()
{
    if (!walletModel || !clientModel) {
        showError(tr("Wallet or client model not available"));
        return;
    }

    if (!govProposalDropdown) return;

    govProposalDropdown->clear();

    try {
        // Get all governance proposals
        auto result = walletModel->governanceListProposals();

        if (!result.success) {
            govProposalDropdown->addItem(tr("Error: %1").arg(result.error), "");
            if (govStatusText) {
                govStatusText->append(tr("[ERROR] Failed to list proposals: %1").arg(result.error));
            }
            return;
        }

        if (result.proposals.isEmpty()) {
            govProposalDropdown->addItem(tr("No proposals found"), "");
            if (govStatusText) {
                govStatusText->append(tr("[INFO] No proposals found"));
            }
            return;
        }

        // Show all proposals - issuer can fetch ballots for any they control
        for (const QVariant& propVariant : result.proposals) {
            QVariantMap prop = propVariant.toMap();
            QString proposal_id = prop.value("proposal_id").toString();
            QString asset_id = prop.value("asset_id").toString();
            qint64 created_at = prop.value("created_at").toLongLong();

            // Look up ticker from asset list
            QString ticker = asset_id.left(8) + "...";
            if (walletModel) {
                QList<WalletModel::AssetInfo> assets = walletModel->listAssets();
                for (const auto& asset : assets) {
                    if (asset.asset_id == asset_id) {
                        if (!asset.ticker.isEmpty()) {
                            ticker = asset.ticker;
                        }
                        break;
                    }
                }
            }

            // Format created timestamp
            QDateTime dt = QDateTime::fromSecsSinceEpoch(created_at);
            QString dateStr = dt.toString("yyyy-MM-dd HH:mm");

            // Build display string: "Asset: TICKER | Created: DATE | Proposal: ID..."
            QString displayText = QString("Asset: %1 | Created: %2 | Proposal: %3...")
                .arg(ticker)
                .arg(dateStr)
                .arg(proposal_id.left(12));

            // Store full proposal_id in item data
            govProposalDropdown->addItem(displayText, proposal_id);
        }

        if (govStatusText) {
            govStatusText->append(tr("[OK] Loaded %1 proposal(s)").arg(result.proposals.size()));
        }

    } catch (const UniValue& objError) {
        QString message;
        try {
            int code = objError.find_value("code").getInt<int>();
            std::string detail = objError.find_value("message").get_str();
            message = tr("RPC Error %1: %2").arg(code).arg(QString::fromStdString(detail));
        } catch (...) {
            message = QString::fromStdString(objError.write());
        }
        QMessageBox::critical(this, tr("Refresh Failed"),
            tr("Failed to refresh proposals list:\n\n%1").arg(message));
    } catch (const std::exception& e) {
        QMessageBox::critical(this, tr("Refresh Failed"),
            tr("Failed to refresh proposals list:\n\n%1").arg(QString::fromStdString(e.what())));
    }
}

void TreasuryPage::onFetchBallots()
{
    if (!walletModel || !clientModel) {
        showError(tr("Wallet or client model not available"));
        return;
    }

    if (!govProposalDropdown || !govBallotListEdit || !govBallotsStatusLabel) return;

    QString proposalId = govProposalDropdown->currentData().toString();
    if (proposalId.isEmpty()) {
        QMessageBox::warning(this, tr("No Proposal Selected"),
            tr("Please select a proposal from the dropdown to fetch ballots for."));
        return;
    }

    try {
        // PR3: First process incoming DMs to capture private ballots
        // Private ballots arrive via encrypted DM but list_ballots only queries public Nostr
        try {
            UniValue dm_params(UniValue::VARR);
            UniValue dmResult = clientModel->node().executeRpc("cosign.process_governance_dms", dm_params, "");

            // Log ballot DMs received
            if (dmResult.exists("ballot_dms") && dmResult["ballot_dms"].isArray()) {
                int ballot_count = dmResult["ballot_dms"].size();
                if (ballot_count > 0) {
                    LogPrintf("TreasuryPage: Processed %d private ballot(s) from DMs\n", ballot_count);
                }
            }
        } catch (const std::exception& e) {
            LogPrintf("TreasuryPage: Warning - failed to process DMs before fetching ballots: %s\n", e.what());
            // Continue anyway - public ballots may still be available
        }

        // Call cosign.list_ballots RPC
        UniValue params(UniValue::VARR);
        params.push_back(proposalId.toStdString());

        UniValue result;
        try {
            result = clientModel->node().executeRpc("cosign.list_ballots", params, "");
        } catch (const UniValue& objError) {
            QString message;
            try {
                int code = objError.find_value("code").getInt<int>();
                std::string detail = objError.find_value("message").get_str();
                message = tr("RPC Error %1: %2").arg(code).arg(QString::fromStdString(detail));
            } catch (...) {
                message = QString::fromStdString(objError.write());
            }
            QMessageBox::critical(this, tr("Fetch Failed"),
                tr("Failed to fetch ballots:\n\n%1").arg(message));
            return;
        }

        // Response is {"ballots": [array]}, extract the array
        if (!result.isObject() || !result.exists("ballots")) {
            QMessageBox::critical(this, tr("Fetch Failed"),
                tr("cosign.list_ballots returned invalid response format"));
            return;
        }

        const UniValue& ballotsArray = result["ballots"];
        if (!ballotsArray.isArray()) {
            QMessageBox::critical(this, tr("Fetch Failed"),
                tr("ballots field is not an array"));
            return;
        }

        // Get template PSBT for validation
        QString templatePsbt = govPSBTEdit ? govPSBTEdit->toPlainText().trimmed() : QString();
        if (templatePsbt.isEmpty()) {
            QMessageBox::warning(this, tr("Template PSBT Missing"),
                tr("Cannot validate ballots without template PSBT.\n\n"
                   "Run 'Prepare Rotation' first to generate the template."));
            return;
        }

        // Extract and validate each ballot
        QStringList validBallotPSBTs;
        QStringList invalidBallotPSBTs;
        uint64_t totalValidUnits = 0;
        uint64_t totalInvalidUnits = 0;
        QStringList validationReport;

        validationReport.append(tr("=== BALLOT VALIDATION REPORT ===\n"));

        for (size_t i = 0; i < ballotsArray.size(); ++i) {
            const UniValue& ballot = ballotsArray[i];
            if (!ballot.isObject() || !ballot.exists("signed_psbt")) {
                continue;
            }

            QString psbt = QString::fromStdString(ballot["signed_psbt"].get_str());
            uint64_t claimed_units = 0;
            if (ballot.exists("ballot_units")) {
                claimed_units = ballot["ballot_units"].getInt<uint64_t>();
            }

            // Validate this ballot using the RPC
            UniValue validateParams(UniValue::VARR);
            validateParams.push_back(templatePsbt.toStdString());
            validateParams.push_back(psbt.toStdString());

            try {
                UniValue validateResult = clientModel->node().executeRpc("validate_ballot", validateParams,
                                                                          walletModel->getWalletName().toStdString());

                bool valid = validateResult["valid"].get_bool();

                if (valid) {
                    validBallotPSBTs.append(psbt);
                    uint64_t actual_units = validateResult["ballot_units"].getInt<uint64_t>();
                    totalValidUnits += actual_units;

                    validationReport.append(tr("Ballot %1: ✓ VALID (%2 units)")
                        .arg(i + 1).arg(actual_units));
                } else {
                    invalidBallotPSBTs.append(psbt);
                    totalInvalidUnits += claimed_units;

                    QString errorMsg;
                    if (validateResult.exists("error")) {
                        errorMsg = QString::fromStdString(validateResult["error"].get_str());
                    } else if (validateResult.exists("issues") && validateResult["issues"].isArray()) {
                        QStringList issues;
                        const UniValue& issuesArr = validateResult["issues"];
                        for (size_t j = 0; j < issuesArr.size(); ++j) {
                            issues.append(QString::fromStdString(issuesArr[j].get_str()));
                        }
                        errorMsg = issues.join("; ");
                    }

                    validationReport.append(tr("Ballot %1: ✗ INVALID (%2)")
                        .arg(i + 1).arg(errorMsg));
                }
            } catch (const UniValue& objError) {
                // RPC error during validation
                invalidBallotPSBTs.append(psbt);
                totalInvalidUnits += claimed_units;

                QString message;
                try {
                    message = QString::fromStdString(objError.find_value("message").get_str());
                } catch (...) {
                    message = QString::fromStdString(objError.write());
                }

                validationReport.append(tr("Ballot %1: ✗ VALIDATION ERROR (%2)")
                    .arg(i + 1).arg(message));
            } catch (const std::exception& e) {
                invalidBallotPSBTs.append(psbt);
                totalInvalidUnits += claimed_units;
                validationReport.append(tr("Ballot %1: ✗ EXCEPTION (%2)")
                    .arg(i + 1).arg(QString::fromStdString(e.what())));
            }
        }

        validationReport.append(tr("\n=== SUMMARY ==="));
        validationReport.append(tr("Valid ballots: %1 (%2 units)")
            .arg(validBallotPSBTs.size()).arg(totalValidUnits));
        validationReport.append(tr("Invalid ballots: %1 (%2 claimed units)")
            .arg(invalidBallotPSBTs.size()).arg(totalInvalidUnits));

        // Only populate with VALID ballots
        govBallotListEdit->setPlainText(validBallotPSBTs.join("\n"));

        // Update status
        govBallotsStatusLabel->setText(tr("%1 valid ballots (%2 units) | %3 invalid")
            .arg(validBallotPSBTs.size())
            .arg(totalValidUnits)
            .arg(invalidBallotPSBTs.size()));

        // Show validation report
        if (govStatusText) {
            for (const QString& line : validationReport) {
                govStatusText->append(line);
            }
        }

        QString summaryMsg = tr("Ballot Validation Complete:\n\n"
                                "✓ Valid: %1 ballots (%2 units)\n"
                                "✗ Invalid: %3 ballots\n\n"
                                "Only valid ballots have been loaded.\n"
                                "Check the status log for details.\n\n"
                                "Click 'Merge Ballots' to proceed.")
            .arg(validBallotPSBTs.size())
            .arg(totalValidUnits)
            .arg(invalidBallotPSBTs.size());

        if (invalidBallotPSBTs.isEmpty()) {
            QMessageBox::information(this, tr("Ballots Validated"), summaryMsg);
        } else {
            QMessageBox::warning(this, tr("Some Ballots Invalid"), summaryMsg);
        }

    } catch (const std::exception& e) {
        QMessageBox::critical(this, tr("Fetch Failed"),
            tr("Failed to fetch ballots:\n\n%1").arg(QString::fromStdString(e.what())));
    }
}

void TreasuryPage::onMergeBallots()
{
    if (!walletModel || !clientModel) {
        showError(tr("Wallet or client model not available"));
        return;
    }

    if (!govBallotListEdit) return;

    QString ballotsText = govBallotListEdit->toPlainText().trimmed();
    if (ballotsText.isEmpty()) {
        showError(tr("Signed ballot PSBTs required"));
        return;
    }

    QStringList ballots = ballotsText.split(QRegularExpression("\\s+"), Qt::SkipEmptyParts);
    if (ballots.isEmpty()) {
        showError(tr("No valid ballot PSBTs found"));
        return;
    }

    if (govStatusText) {
        govStatusText->append(tr("[INFO] Merging %1 ballot(s)...").arg(ballots.size()));
    }

    QString merged;
    if (!mergeBallotsInternal(ballots, merged, true)) {
        return;
    }

    if (govMergedPSBTEdit) {
        govMergedPSBTEdit->setPlainText(merged);
    }

    if (govStatusText) {
        govStatusText->append(tr("[OK] Ballots merged. Ready for finalization."));
    }
}

void TreasuryPage::onGovPrecheckICU()
{
    // Run the SAME RPC the rotation path runs (buildcanonicalicupayload) and
    // read canonical_hash straight off the response. Any other path — including
    // a direct C++ call to NormalizeCanonicalText — risks drift from what
    // prepare_rotation will actually commit.
    QString canonicalText = govICUTextEdit->toPlainText().trimmed();

    if (canonicalText.isEmpty()) {
        showError(tr("Canonical text is empty"));
        return;
    }

    if (!clientModel || !walletModel) {
        showError(tr("Wallet not ready"));
        return;
    }

    UniValue witnessUniValue;
    if (!witnessUniValue.read(std::string("{\"version\":\"1.0\",\"canonical_hash\":\"placeholder\"}"))) {
        showError(tr("Internal error: failed to build witness placeholder"));
        return;
    }

    int visibility = govICUVisibilityCombo ? govICUVisibilityCombo->currentData().toInt() : 0;

    UniValue buildParams(UniValue::VARR);
    buildParams.push_back(canonicalText.toStdString());
    buildParams.push_back(witnessUniValue);
    buildParams.push_back(visibility);
    // Include the Designated Clauses as inline context so the previewed canonical_hash matches what
    // onPrepareRotation actually commits (otherwise the preview is body-only and misleads the issuer).
    {
        UniValue clausesArr(UniValue::VARR);
        for (const RegClauseRow& row : govClauseRows) {
            if (!row.textEdit) continue;
            const QString t = row.textEdit->toPlainText().trimmed();
            if (!t.isEmpty()) clausesArr.push_back(t.toStdString());
        }
        if (!clausesArr.empty()) {
            buildParams.push_back(UniValue(UniValue::VNULL));   // [3] legacy icu_context (unused)
            buildParams.push_back(clausesArr);                  // [4] icu_clauses
            buildParams.push_back(std::string("required"));     // [5] icu_acceptance
        }
    }

    UniValue payloadResult;
    try {
        payloadResult = clientModel->node().executeRpc(
            "buildcanonicalicupayload",
            buildParams,
            walletModel->getWalletName().toStdString());
    } catch (const std::exception& e) {
        govCanonicalHashLabel->setText(tr("(error)"));
        govCanonicalHashLabel->setStyleSheet("font-family: monospace; color: #c00; font-weight: bold;");
        showError(tr("Failed to build ICU payload: %1").arg(QString::fromStdString(e.what())));
        return;
    }

    QString canonicalHash = QString::fromStdString(payloadResult["canonical_hash"].get_str());
    int payloadSize = payloadResult["payload_size"].getInt<int>();

    govCanonicalHashLabel->setText(canonicalHash);
    govCanonicalHashLabel->setStyleSheet("font-family: monospace; color: #4CAF50; font-weight: bold;");

    govStatusText->append(tr("✓ Governance text precheck passed"));
    govStatusText->append(tr("  Canonical hash: %1").arg(canonicalHash));
    govStatusText->append(tr("  Payload size: %1 bytes").arg(payloadSize));
}

void TreasuryPage::onGovCopyCanonicalHash()
{
    QString hash = govCanonicalHashLabel->text();
    if (hash == "-" || hash.isEmpty()) {
        showError(tr("No hash to copy. Click 'Precheck Text' first."));
        return;
    }

    QApplication::clipboard()->setText(hash);

    // Visual feedback
    QString originalStyle = govCanonicalHashLabel->styleSheet();
    govCanonicalHashLabel->setStyleSheet("font-family: monospace; color: #2196F3; font-weight: bold;");
    QTimer::singleShot(500, this, [this, originalStyle]() {
        if (govCanonicalHashLabel) {
            govCanonicalHashLabel->setStyleSheet(originalStyle);
        }
    });

    govStatusText->append(tr("✓ Canonical hash copied to clipboard"));
}

void TreasuryPage::onFinalizeRotation()
{
    if (!walletModel || !clientModel) {
        showError(tr("Wallet or client model not available"));
        return;
    }

    QString mergedPSBT = govMergedPSBTEdit ? govMergedPSBTEdit->toPlainText().trimmed() : QString();
    QString ballotsText = govBallotListEdit ? govBallotListEdit->toPlainText().trimmed() : QString();

    if (govStatusText) {
        govStatusText->clear();
    }

    if (!ballotsText.isEmpty()) {
        QStringList ballots = ballotsText.split(QRegularExpression("\\s+"), Qt::SkipEmptyParts);
        if (!ballots.isEmpty()) {
            if (govStatusText) {
                govStatusText->append(tr("[INFO] Re-merging %1 ballot(s) before finalization...")
                                      .arg(ballots.size()));
            }
            QString mergedFromBallots;
            if (!mergeBallotsInternal(ballots, mergedFromBallots, false)) {
                return;
            }
            mergedPSBT = mergedFromBallots;
            if (govMergedPSBTEdit) {
                govMergedPSBTEdit->setPlainText(mergedFromBallots);
            }
            if (govStatusText) {
                if (lastMergedBallotUnits) {
                    govStatusText->append(tr("  Total ballot units: %1")
                        .arg(static_cast<qulonglong>(*lastMergedBallotUnits)));
                }
                if (lastRequiredUnits) {
                    govStatusText->append(tr("  Required units: %1")
                        .arg(static_cast<qulonglong>(*lastRequiredUnits)));
                }
                if (lastMergedQuorumMet.has_value()) {
                    govStatusText->append(*lastMergedQuorumMet
                        ? tr("  ✓ Quorum met")
                        : tr("  ⚠ Quorum NOT met yet"));
                }
            }
        }
    } else {
        lastMergedBallotUnits.reset();
        lastMergedQuorumMet.reset();
    }

    if (mergedPSBT.isEmpty()) {
        showError(tr("Merged PSBT required"));
        return;
    }

    if (govStatusText) {
        govStatusText->append(tr("[INFO] Finalizing rotation..."));
    }

    try {
        // Finalize rotation using finalize_rotation RPC
        UniValue finalizeParams(UniValue::VARR);
        finalizeParams.push_back(mergedPSBT.toStdString());

        UniValue options(UniValue::VOBJ);
        options.pushKV("broadcast", true);
        options.pushKV("fee_rate", 5.0);  // 5 sat/vB - same as test
        finalizeParams.push_back(options);

        UniValue finalizeResult = clientModel->node().executeRpc(
            "finalize_rotation", finalizeParams, walletModel->getWalletName().toStdString());

        QString txid = QString::fromStdString(finalizeResult.find_value("txid").get_str());
        QString txHex;
        if (finalizeResult.exists("hex") && finalizeResult.find_value("hex").isStr()) {
            txHex = QString::fromStdString(finalizeResult.find_value("hex").get_str());
        }
        bool broadcasted = true;
        if (finalizeResult.exists("broadcast")) {
            broadcasted = finalizeResult.find_value("broadcast").get_bool();
        }

        bool inMempool = false;
        bool confirmed = false;
        QString rejectionReason;
        QString rejectionDetails;

        if (broadcasted) {
            UniValue mempoolParams(UniValue::VARR);
            mempoolParams.push_back(txid.toStdString());
            try {
                clientModel->node().executeRpc("getmempoolentry", mempoolParams, "");
                inMempool = true;
            } catch (const UniValue&) {
                // Not in mempool
            } catch (const std::exception&) {
                // Ignore and fall through to deeper diagnostics
            }
        }

        if (!inMempool) {
            UniValue txParams(UniValue::VARR);
            txParams.push_back(txid.toStdString());
            try {
                UniValue txInfo = clientModel->node().executeRpc(
                    "gettransaction", txParams, walletModel->getWalletName().toStdString());
                if (txInfo.exists("confirmations")) {
                    int confirmations = txInfo.find_value("confirmations").getInt<int>();
                    confirmed = confirmations > 0;
                }
            } catch (const UniValue&) {
                // Transaction unknown to wallet or node
            } catch (const std::exception&) {
                // Ignore
            }
        }

        if (!inMempool && !confirmed && broadcasted && !txHex.isEmpty()) {
            try {
                UniValue tmaParams(UniValue::VARR);
                UniValue rawTxs(UniValue::VARR);
                rawTxs.push_back(txHex.toStdString());
                tmaParams.push_back(rawTxs);
                UniValue tmaResult = clientModel->node().executeRpc("testmempoolaccept", tmaParams, "");
                if (tmaResult.isArray() && tmaResult.size() > 0) {
                    const UniValue& entry = tmaResult[0];
                    bool allowed = entry.exists("allowed") ? entry.find_value("allowed").get_bool() : false;
                    if (!allowed) {
                        if (entry.exists("reject-reason") && entry.find_value("reject-reason").isStr()) {
                            rejectionReason = QString::fromStdString(entry.find_value("reject-reason").get_str());
                        }
                        if (entry.exists("error") && entry.find_value("error").isStr()) {
                            rejectionDetails = QString::fromStdString(entry.find_value("error").get_str());
                        }
                    }
                }
            } catch (const UniValue& objError) {
                rejectionDetails = QString::fromStdString(objError.write());
            } catch (const std::exception& ex) {
                rejectionDetails = QString::fromUtf8(ex.what());
            }
        }

        if (govStatusText) {
            govStatusText->append(tr("[OK] Rotation finalized and broadcast"));
            govStatusText->append(tr("  Txid: %1").arg(txid));

            if (confirmed) {
                govStatusText->append(tr("  ✓ Transaction already confirmed"));
            } else if (inMempool) {
                govStatusText->append(tr("  ✓ Transaction accepted to mempool"));
            } else if (!broadcasted) {
                govStatusText->append(tr("  ⚠ Broadcast disabled (dry run)"));
            } else {
                govStatusText->append(tr("  ⚠ Transaction not found in mempool"));
                if (!rejectionReason.isEmpty()) {
                    govStatusText->append(tr("    Reject reason: %1").arg(rejectionReason));
                }
                if (!rejectionDetails.isEmpty()) {
                    govStatusText->append(tr("    Details: %1").arg(rejectionDetails));
                }
                if (rejectionReason.isEmpty() && rejectionDetails.isEmpty()) {
                    govStatusText->append(tr("    (Check node logs for additional context.)"));
                }
            }
        }

        showSuccess(tr("Governance rotation complete! Txid: %1").arg(txid));

        // Clear inputs
        if (govMergedPSBTEdit) govMergedPSBTEdit->clear();
        if (govPSBTEdit) govPSBTEdit->clear();
        if (govSignedPSBTEdit) govSignedPSBTEdit->clear();
        if (govBallotListEdit) {
            govBallotListEdit->clear();
        }
        lastMergedBallotUnits.reset();
        lastMergedQuorumMet.reset();
        lastRequiredUnits.reset();
        onGovTemplatePSBTChanged();
    } catch (const UniValue& objError) {
        QString message;
        try {
            int code = objError.find_value("code").getInt<int>();
            std::string detail = objError.find_value("message").get_str();
            message = tr("RPC Error %1: %2").arg(code).arg(QString::fromStdString(detail));
        } catch (...) {
            message = QString::fromStdString(objError.write());
        }
        if (govStatusText) {
            govStatusText->append(tr("[ERROR] %1").arg(message));
        }
        showError(tr("Failed to finalize rotation: %1").arg(message));
    } catch (const std::exception& e) {
        if (govStatusText) {
            govStatusText->append(tr("[ERROR] %1").arg(e.what()));
        }
        showError(tr("Failed to finalize rotation: %1").arg(e.what()));
    }
}

// ===== DASHBOARD DECRYPT SLOT =====

void TreasuryPage::onDashboardDecrypt()
{
    // Similar to held asset decrypt but for the dashboard viewer
    if (!walletModel || !clientModel) return;

    // Get currently selected asset from dashboard table
    int row = dashboardICUTable->currentRow();
    if (row < 0) return;

    QString assetId = dashboardICUTable->item(row, 1)->data(Qt::UserRole).toString();
    if (assetId.isEmpty()) return;

    try {
        UniValue params(UniValue::VARR);
        params.push_back(assetId.toStdString());
        UniValue payload = clientModel->node().executeRpc("geticupayload", params,
                                                         walletModel->getWalletName().toStdString());

        if (payload.find_value("decrypted").get_bool()) {
            std::string plaintextHex = payload.find_value("plaintext").get_str();
            std::vector<unsigned char> plaintextBytes = ParseHex(plaintextHex);

            auto canonical = assets::ParseCanonicalIcuPayload(plaintextBytes);
            if (canonical && !canonical->canonical_text.empty()) {
                QString icuText = QString::fromUtf8(
                    reinterpret_cast<const char*>(canonical->canonical_text.data()),
                    canonical->canonical_text.size());
                dashboardICUTextViewer->setPlainText(renderIcuViewerText(icuText, payload));
                dashboardICUVisibilityLabel->setText(tr("Visibility: Holder-Only (Decrypted ✓)"));
                dashboardICUVisibilityLabel->setStyleSheet("color: green; font-weight: bold;");
            }
        } else {
            dashboardICUTextViewer->setPlainText(tr("[DECRYPTION FAILED - Wallet does not have DEK]"));
            dashboardICUVisibilityLabel->setStyleSheet("color: red; font-weight: bold;");
        }
    } catch (UniValue& objError) {
        dashboardICUTextViewer->setPlainText(tr("[ERROR: %1]").arg(QString::fromStdString(objError.write())));
    } catch (const std::exception& e) {
        dashboardICUTextViewer->setPlainText(tr("[ERROR: %1]").arg(e.what()));
    } catch (...) {
        dashboardICUTextViewer->setPlainText(tr("[ERROR: Unexpected failure]"));
    }
}

void TreasuryPage::runDashboardAcceptance(const std::string& mode)
{
    if (!walletModel || !clientModel) return;
    int row = dashboardICUTable ? dashboardICUTable->currentRow() : -1;
    if (row < 0 || !dashboardICUTable->item(row, 1)) {
        QMessageBox::warning(this, tr("ICU Acceptance"), tr("Select an asset row in the dashboard first."));
        return;
    }
    const QString assetId = dashboardICUTable->item(row, 1)->data(Qt::UserRole).toString();
    if (assetId.isEmpty()) {
        QMessageBox::warning(this, tr("ICU Acceptance"), tr("The selected row has no asset id."));
        return;
    }
    const bool is_return = (mode == "return");
    const QString verb = is_return ? tr("return") : tr("acknowledge");

    // Confirm before broadcasting -- RETURN is irreversible (it spends the holder UTXO to the issuer).
    const QString confirmText = is_return
        ? tr("Return (relinquish) this asset to the issuer?\n\nAsset: %1\n\nThis broadcasts a transaction that "
             "SPENDS your holder UTXO and sends the units back to the issuer's ICU address. This cannot be undone.").arg(assetId)
        : tr("Record an on-chain acknowledgment of this asset's ICU document?\n\nAsset: %1\n\nThis broadcasts a "
             "fee-only transaction signed with your holder key; your asset UTXO is not spent.").arg(assetId);
    if (QMessageBox::question(this, is_return ? tr("Confirm Return") : tr("Confirm Acknowledge"), confirmText,
                              QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes) {
        return;
    }

    // Clause picker: for an ACKNOWLEDGE on an asset whose committed context is OPTIONAL, let the holder
    // choose which clauses to affirm. (A 'required' context auto-affirms all; a no-context asset has none.)
    UniValue create_opts(UniValue::VOBJ);
    if (!is_return) {
        try {
            UniValue gp_params(UniValue::VARR);
            gp_params.push_back(assetId.toStdString());
            const UniValue gp = clientModel->node().executeRpc("geticupayload", gp_params,
                                                               walletModel->getWalletName().toStdString());
            if (gp.exists("context") && gp["context"].isObject() &&
                gp["context"].exists("bodies") && gp["context"]["bodies"].isObject() &&
                gp["context"].exists("acceptance") && gp["context"]["acceptance"].isStr() &&
                gp["context"]["acceptance"].get_str() == "optional") {
                const UniValue& bodies = gp["context"]["bodies"];
                QDialog dlg(this);
                dlg.setWindowTitle(tr("Select clauses to affirm"));
                QVBoxLayout* lay = new QVBoxLayout(&dlg);
                lay->addWidget(new QLabel(tr("This asset's ICU context is optional. Choose the clauses you affirm:"), &dlg));
                std::vector<std::pair<std::string, QCheckBox*>> rows;
                for (const std::string& k : bodies.getKeys()) {
                    QCheckBox* cb = new QCheckBox(QString::fromStdString(bodies[k].get_str()).left(160), &dlg);
                    cb->setChecked(true);
                    lay->addWidget(cb);
                    rows.emplace_back(k, cb);
                }
                QDialogButtonBox* bb = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dlg);
                connect(bb, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
                connect(bb, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
                lay->addWidget(bb);
                if (dlg.exec() != QDialog::Accepted) return;  // holder cancelled
                UniValue refs(UniValue::VARR);
                for (const auto& [k, cb] : rows) if (cb->isChecked()) refs.push_back(k);
                create_opts.pushKV("body_refs", refs);
            }
        } catch (...) {
            // No readable context / not applicable -> proceed without a picker (create enforces the rules).
        }
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(assetId.toStdString());
        params.push_back(mode);
        if (!create_opts.empty()) params.push_back(create_opts);
        UniValue res = clientModel->node().executeRpc("icu.acceptance.record.create", params,
                                                      walletModel->getWalletName().toStdString());
        const QString txid = res.exists("txid") ? QString::fromStdString(res["txid"].get_str()) : QString();
        const QString family = res.exists("holder_family") ? QString::fromStdString(res["holder_family"].get_str()) : QString();
        const QString vout = res.exists("acceptance_vout") ? QString::number(res["acceptance_vout"].getInt<int64_t>()) : QString();
        QString body = tr("On-chain ICU %1 recorded.\n\nAsset: %2\nTransaction: %3\nRecord output (vout): %4\nHolder type: %5")
                           .arg(verb, assetId, txid, vout, family);
        // A copy/save-friendly block of the exact arguments needed to verify this record later.
        QString verifyBlock = tr("txid=%1\nvout=%2\nasset_id=%3").arg(txid, vout, assetId);
        if (res.exists("revealed_bip322_proof")) {
            verifyBlock += tr("\nrevealed_bip322_proof=%1").arg(QString::fromStdString(res["revealed_bip322_proof"].get_str()));
            body += tr("\n\nIMPORTANT: this acceptance commits only H(proof) on chain; the proof itself is your "
                       "secret and is NOT recoverable from the chain. Save it to verify later.");
        }
        body += tr("\n\nVerification details (txid / vout / asset_id%1):\n%2")
                    .arg(res.exists("revealed_bip322_proof") ? tr(" / proof") : QString(), verifyBlock);
        // Explicit, on-demand copy (don't auto-place a long-lived secret on the clipboard). The text is
        // also selectable so the holder can copy manually.
        QMessageBox box(QMessageBox::Information, tr("ICU Acceptance"), body, QMessageBox::Ok, this);
        box.setTextInteractionFlags(Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard);
        QPushButton* copyBtn = box.addButton(tr("Copy verification details"), QMessageBox::ActionRole);
        connect(copyBtn, &QAbstractButton::clicked, this, [verifyBlock]() {
            if (QApplication::clipboard()) QApplication::clipboard()->setText(verifyBlock);
        });
        box.exec();
        refreshICUDashboard();
    } catch (const UniValue& e) {
        const QString err = (e.exists("message") && e["message"].isStr())
                                ? QString::fromStdString(e["message"].get_str()) : tr("RPC error");
        QMessageBox::critical(this, tr("ICU Acceptance failed"), err);
    } catch (const std::exception& e) {
        QMessageBox::critical(this, tr("ICU Acceptance failed"), QString::fromStdString(e.what()));
    }
}

void TreasuryPage::onDashboardAccept() { runDashboardAcceptance("acknowledge"); }
void TreasuryPage::onDashboardReturn() { runDashboardAcceptance("return"); }

void TreasuryPage::onDashboardViewAcceptances()
{
    if (!walletModel || !clientModel) return;
    int row = dashboardICUTable ? dashboardICUTable->currentRow() : -1;
    if (row < 0 || !dashboardICUTable->item(row, 1)) {
        QMessageBox::warning(this, tr("ICU Acceptances"), tr("Select an asset row in the dashboard first."));
        return;
    }
    const QString assetId = dashboardICUTable->item(row, 1)->data(Qt::UserRole).toString();
    if (assetId.isEmpty()) {
        QMessageBox::warning(this, tr("ICU Acceptances"), tr("The selected row has no asset id."));
        return;
    }

    QDialog dlg(this);
    dlg.setWindowTitle(tr("ICU Acceptances \xE2\x80\x94 %1\xE2\x80\xA6").arg(assetId.left(20)));
    dlg.resize(940, 440);
    QVBoxLayout* lay = new QVBoxLayout(&dlg);

    QLabel* summary = new QLabel(tr("On-chain holder acknowledgments / returns for this asset (icu.acceptance.record.list)."), &dlg);
    summary->setWordWrap(true);
    lay->addWidget(summary);

    QCheckBox* showInvalid = new QCheckBox(tr("Show unverified / invalid candidates (with reason)"), &dlg);
    lay->addWidget(showInvalid);
    QCheckBox* mineOnly = new QCheckBox(tr("Only my acknowledgments (this wallet's holder UTXOs)"), &dlg);
    lay->addWidget(mineOnly);

    QTableWidget* table = new QTableWidget(&dlg);
    const QStringList headers = {tr("Height"), tr("Mine"), tr("Mode"), tr("Holder address"), tr("Units"),
                                 tr("Scheme"), tr("Doc current"), tr("Verified"), tr("Reason"), tr("Acceptance txid")};
    table->setColumnCount(headers.size());
    table->setHorizontalHeaderLabels(headers);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->verticalHeader()->setVisible(false);
    table->horizontalHeader()->setStretchLastSection(true);
    lay->addWidget(table);

    // (Re)query icu.acceptance.record.list and repopulate the table. Captured by value into the button
    // lambdas (the closure keeps references to these dialog-scoped locals, which outlive the modal exec()).
    const auto populate = [this, table, summary, showInvalid, mineOnly, assetId]() {
        table->setRowCount(0);
        const std::string wname = walletModel->getWalletName().toStdString();
        UniValue res;
        try {
            UniValue p(UniValue::VARR);
            p.push_back(assetId.toStdString());
            UniValue opt(UniValue::VOBJ);
            opt.pushKV("include_invalid", showInvalid->isChecked());
            p.push_back(opt);
            res = clientModel->node().executeRpc("icu.acceptance.record.list", p, wname);
        } catch (const UniValue& e) {
            summary->setText(tr("Error: %1").arg(QString::fromStdString(e.exists("message") && e["message"].isStr() ? e["message"].get_str() : "list failed")));
            return;
        } catch (const std::exception& e) {
            summary->setText(tr("Error: %1").arg(QString::fromStdString(e.what())));
            return;
        }
        if (!res.isArray()) return;
        int verified_count = 0, mine_count = 0;
        for (size_t i = 0; i < res.size(); ++i) {
            const UniValue& r = res[i];
            const auto str = [&](const char* k) -> QString { return r.exists(k) && r[k].isStr() ? QString::fromStdString(r[k].get_str()) : QString(); };
            const auto boolv = [&](const char* k) -> bool { return r.exists(k) && r[k].isBool() && r[k].get_bool(); };
            const auto numv = [&](const char* k) -> QString { return r.exists(k) && r[k].isNum() ? QString::number(r[k].getInt<int64_t>()) : QString(); };

            // Resolve the holder prevout -> address, then ismine (best-effort): unspent ACK prevouts via
            // gettxout; spent/old via getrawtransaction (needs -txindex). Failures leave address/mine unknown.
            QString holderAddr;
            bool isMine = false, mineKnown = false;
            const std::string htxid = str("holder_txid").toStdString();
            const int hvout = (r.exists("holder_vout") && r["holder_vout"].isNum()) ? r["holder_vout"].getInt<int>() : 0;
            UniValue spk;
            try {
                UniValue gp(UniValue::VARR); gp.push_back(htxid); gp.push_back(hvout);
                const UniValue gto = clientModel->node().executeRpc("gettxout", gp, "");
                if (gto.isObject() && gto.exists("scriptPubKey")) spk = gto["scriptPubKey"];
            } catch (...) {}
            if (!spk.isObject()) {
                try {
                    UniValue gp(UniValue::VARR); gp.push_back(htxid); gp.push_back(true);
                    const UniValue grt = clientModel->node().executeRpc("getrawtransaction", gp, "");
                    if (grt.exists("vout") && grt["vout"].isArray() && static_cast<size_t>(hvout) < grt["vout"].size())
                        spk = grt["vout"][hvout]["scriptPubKey"];
                } catch (...) {}
            }
            if (spk.isObject() && spk.exists("address") && spk["address"].isStr()) {
                holderAddr = QString::fromStdString(spk["address"].get_str());
                try {
                    UniValue ap(UniValue::VARR); ap.push_back(holderAddr.toStdString());
                    const UniValue ai = clientModel->node().executeRpc("getaddressinfo", ap, wname);
                    isMine = ai.exists("ismine") && ai["ismine"].isBool() && ai["ismine"].get_bool();
                    mineKnown = true;
                } catch (...) {}
            }

            const bool verified = boolv("verified");
            if (verified) ++verified_count;
            if (isMine) ++mine_count;
            if (mineOnly->isChecked() && !isMine) continue;

            const int rr = table->rowCount();
            table->insertRow(rr);
            table->setItem(rr, 0, new QTableWidgetItem(numv("height")));
            table->setItem(rr, 1, new QTableWidgetItem(mineKnown ? (isMine ? tr("yes") : tr("no")) : tr("?")));
            table->setItem(rr, 2, new QTableWidgetItem(str("mode")));
            QTableWidgetItem* addrItem = new QTableWidgetItem(
                holderAddr.isEmpty() ? (str("holder_txid").left(12) + QStringLiteral("\xE2\x80\xA6:") + numv("holder_vout")) : holderAddr);
            addrItem->setToolTip(str("holder_txid") + QStringLiteral(":") + numv("holder_vout"));
            table->setItem(rr, 3, addrItem);
            table->setItem(rr, 4, new QTableWidgetItem(numv("accepted_units")));
            table->setItem(rr, 5, new QTableWidgetItem(str("scheme")));
            table->setItem(rr, 6, new QTableWidgetItem(boolv("doc_current") ? tr("yes") : tr("no")));
            table->setItem(rr, 7, new QTableWidgetItem(verified ? tr("yes") : tr("no")));
            table->setItem(rr, 8, new QTableWidgetItem(verified ? QString() : str("reason")));
            table->setItem(rr, 9, new QTableWidgetItem(str("acceptance_txid")));
        }
        summary->setText(tr("%1 record(s) \xE2\x80\x94 %2 verified, %3 mine. Asset: %4")
                             .arg(static_cast<int>(res.size())).arg(verified_count).arg(mine_count).arg(assetId));
        table->resizeColumnsToContents();
    };

    connect(showInvalid, &QCheckBox::toggled, &dlg, [populate](bool) { populate(); });
    connect(mineOnly, &QCheckBox::toggled, &dlg, [populate](bool) { populate(); });

    QHBoxLayout* btnRow = new QHBoxLayout();
    QPushButton* refreshBtn = new QPushButton(tr("Refresh"), &dlg);
    connect(refreshBtn, &QPushButton::clicked, &dlg, [populate]() { populate(); });
    QPushButton* closeBtn = new QPushButton(tr("Close"), &dlg);
    connect(closeBtn, &QPushButton::clicked, &dlg, &QDialog::accept);
    btnRow->addWidget(refreshBtn);
    btnRow->addStretch();
    btnRow->addWidget(closeBtn);
    lay->addLayout(btnRow);

    populate();
    dlg.exec();
}

void TreasuryPage::onViewRotationHistory()
{
    if (!clientModel) return;

    // Get currently selected asset from dashboard table
    int row = dashboardICUTable->currentRow();
    if (row < 0) {
        QMessageBox::information(this, tr("No Asset Selected"),
                                tr("Please select an asset from the table to view its rotation history."));
        return;
    }

    QString assetId = dashboardICUTable->item(row, 1)->data(Qt::UserRole).toString();
    if (assetId.isEmpty()) return;

    try {
        // Get asset policy with rotation history
        UniValue policyParams(UniValue::VARR);
        policyParams.push_back(assetId.toStdString());
        policyParams.push_back(UniValue(true));  // include_history=true (wrap in UniValue)

        LogPrintf("GUI: Calling getassetpolicy for asset %s with include_history=true\n", assetId.toStdString());
        UniValue policy = clientModel->node().executeRpc("getassetpolicy", policyParams, "");

        if (policy.isNull()) {
            LogPrintf("GUI: getassetpolicy returned null for asset %s\n", assetId.toStdString());
            QMessageBox::warning(this, tr("Policy Not Found"),
                                tr("Could not retrieve policy information for this asset."));
            return;
        }

        LogPrintf("GUI: getassetpolicy returned policy, has rotation_history: %d\n", policy.exists("rotation_history"));

        // Build rotation history display
        QString historyText = tr("=== POLICY ROTATION HISTORY ===\n\n");
        historyText += tr("Asset ID: %1\n\n").arg(assetId);

        // Get current ICU information
        QString currentICU = QString::fromStdString(policy.find_value("icu_txid").get_str());
        int currentVout = policy.find_value("icu_vout").getInt<int>();
        historyText += tr("Current ICU:\n");
        historyText += tr("  TxID: %1\n").arg(currentICU);
        historyText += tr("  Vout: %1\n\n").arg(currentVout);

        // Get governance parameters history
        if (policy.exists("policy_quorum_bps")) {
            int quorum = policy.find_value("policy_quorum_bps").getInt<int>();
            historyText += tr("Current Governance Quorum: %1 bps (%2%)\n").arg(quorum).arg(quorum / 100.0, 0, 'f', 2);
        }

        if (policy.exists("issuance_cap_units")) {
            uint64_t cap = policy.find_value("issuance_cap_units").getInt<uint64_t>();
            if (cap == UINT64_MAX) {
                historyText += tr("Current Issuance Cap: Unlimited\n");
            } else {
                historyText += tr("Current Issuance Cap: %1 units\n").arg(cap);
            }
        }

        historyText += tr("\n--- Rotation History ---\n\n");

        // Display rotation history if available
        if (policy.exists("rotation_history")) {
            UniValue history = policy.find_value("rotation_history");
            LogPrintf("GUI: rotation_history exists, isArray=%d, size=%d\n", history.isArray(), history.size());
            if (history.isArray() && history.size() > 0) {
                historyText += tr("Total rotations: %1\n\n").arg(history.size());

                for (size_t i = 0; i < history.size(); i++) {
                    const UniValue& snapshot = history[i];

                    int epoch = snapshot.find_value("policy_epoch").getInt<int>();
                    int block_height = snapshot.find_value("block_height").getInt<int>();
                    QString txid = QString::fromStdString(snapshot.find_value("rotation_txid").get_str());
                    uint64_t timestamp = snapshot.find_value("timestamp").getInt<uint64_t>();
                    int quorum = snapshot.find_value("policy_quorum_bps").getInt<int>();
                    uint64_t cap = snapshot.find_value("issuance_cap_units").getInt<uint64_t>();
                    QString icu_commit = QString::fromStdString(snapshot.find_value("icu_ctxt_commit").get_str());

                    historyText += tr("━━━ Epoch %1 ━━━\n").arg(epoch);
                    historyText += tr("  Block Height: %1\n").arg(block_height);
                    historyText += tr("  Rotation TxID: %1\n").arg(txid.left(16) + "...");

                    // Format timestamp
                    QDateTime dt = QDateTime::fromSecsSinceEpoch(timestamp);
                    historyText += tr("  Date: %1\n").arg(dt.toString("yyyy-MM-dd HH:mm:ss"));

                    historyText += tr("  Quorum: %1 bps (%2%)\n").arg(quorum).arg(quorum / 100.0, 0, 'f', 2);

                    if (cap == 0) {
                        historyText += tr("  Issuance Cap: Unlimited\n");
                    } else {
                        historyText += tr("  Issuance Cap: %1 units\n").arg(cap);
                    }

                    historyText += tr("  ICU Commit: %1...\n").arg(icu_commit.left(16));
                    historyText += "\n";
                }
            } else {
                historyText += tr("[No prior rotations found]\n");
                historyText += tr("\nThis asset has not been rotated yet (policy_epoch = 0).\n");
            }
        } else {
            historyText += tr("[No rotation history available]\n");
            historyText += tr("\nNote: Rotation history tracking may not be enabled for this asset.\n");
            historyText += tr("This could indicate an older asset created before history tracking was implemented.\n");
        }

        // Display in message box
        QMessageBox msgBox(TopLevelDialogParent(this));
        msgBox.setWindowTitle(tr("Policy Rotation History"));
        msgBox.setText(historyText);
        msgBox.setIcon(QMessageBox::Information);
        msgBox.setStandardButtons(QMessageBox::Ok);
        msgBox.setTextInteractionFlags(Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard);
        msgBox.exec();

    } catch (const UniValue& objError) {
        try {
            int code = objError.find_value("code").getInt<int>();
            std::string message = objError.find_value("message").get_str();
            QMessageBox::warning(this, tr("RPC Error"),
                                tr("RPC Error %1: %2").arg(code).arg(QString::fromStdString(message)));
        } catch (...) {
            QMessageBox::warning(this, tr("Error"),
                                tr("Failed to retrieve rotation history: %1").arg(QString::fromStdString(objError.write())));
        }
    } catch (const std::exception& e) {
        QMessageBox::warning(this, tr("Error"),
                            tr("Failed to retrieve rotation history: %1").arg(e.what()));
    }
}

void TreasuryPage::onViewPreviousICU()
{
    if (!clientModel) return;

    // Get currently selected asset from dashboard table
    int row = dashboardICUTable->currentRow();
    if (row < 0) {
        QMessageBox::information(this, tr("No Asset Selected"),
                                tr("Please select an asset from the table to view its previous ICU."));
        return;
    }

    QString assetId = dashboardICUTable->item(row, 1)->data(Qt::UserRole).toString();
    if (assetId.isEmpty()) return;

    try {
        // Call geticupayload_prior RPC
        UniValue params(UniValue::VARR);
        params.push_back(assetId.toStdString());

        LogPrintf("GUI: Calling geticupayload_prior for asset %s\n", assetId.toStdString());
        UniValue result = clientModel->node().executeRpc("geticupayload_prior", params, "");

        if (result.isNull()) {
            QMessageBox::warning(this, tr("No Prior ICU"),
                                tr("Could not retrieve prior ICU for this asset."));
            return;
        }

        // Extract result fields
        QString icu_cipher = QString::fromStdString(result.find_value("icu_cipher").get_str());
        QString canonical_hash = QString::fromStdString(result.find_value("canonical_hash").get_str());
        int visibility = result.find_value("visibility").getInt<int>();
        int policy_epoch = result.find_value("policy_epoch").getInt<int>();
        QString icu_commit = QString::fromStdString(result.find_value("icu_ctxt_commit").get_str());

        QString displayText;
        displayText += tr("=== PREVIOUS ICU (Epoch %1) ===\n\n").arg(policy_epoch);
        displayText += tr("ICU Commit: %1...\n\n").arg(icu_commit.left(16));

        // Attempt decryption if encrypted
        if (visibility == 1) {  // holder_only
            displayText += tr("Visibility: Holder-Only (Encrypted)\n");
            displayText += tr("Attempting decryption...\n\n");

            try {
                UniValue decryptParams(UniValue::VARR);
                decryptParams.push_back(assetId.toStdString());
                decryptParams.push_back(icu_cipher.toStdString());

                UniValue decrypted = clientModel->node().executeRpc("decrypticupayload", decryptParams, "");

                if (decrypted.exists("plaintext")) {
                    QString plaintext = QString::fromStdString(decrypted.find_value("plaintext").get_str());
                    displayText += tr("━━━ Decrypted ICU Text ━━━\n\n");
                    displayText += plaintext;
                } else {
                    displayText += tr("✗ Decryption failed (DEK not available in this wallet)\n\n");
                    displayText += tr("Encrypted payload: %1...\n").arg(icu_cipher.left(64));
                }
            } catch (const std::exception& e) {
                displayText += tr("✗ Decryption failed: %1\n\n").arg(e.what());
                displayText += tr("Encrypted payload: %1...\n").arg(icu_cipher.left(64));
            }
        } else {
            // Public ICU - icu_cipher may be zstd-compressed or raw plaintext
            displayText += tr("Visibility: Public\n\n");
            displayText += tr("━━━ ICU Text ━━━\n\n");

            std::vector<unsigned char> decoded = ParseHex(icu_cipher.toStdString());

            // Try decompressing in case it's zstd-compressed
            auto decompressed = assets::DecompressZstd(decoded);
            const std::vector<unsigned char>& payload_bytes = decompressed ? *decompressed : decoded;

            auto canonical = assets::ParseCanonicalIcuPayload(payload_bytes);
            if (canonical && !canonical->canonical_text.empty()) {
                QString plaintext = QString::fromUtf8(
                    reinterpret_cast<const char*>(canonical->canonical_text.data()),
                    canonical->canonical_text.size());
                displayText += plaintext;
            } else {
                // Fallback: treat as raw text
                QString plaintext = QString::fromUtf8(reinterpret_cast<const char*>(payload_bytes.data()), payload_bytes.size());
                displayText += plaintext;
            }
        }

        // Display in dialog
        QDialog dialog(this);
        dialog.setWindowTitle(tr("Previous ICU Text (Epoch %1)").arg(policy_epoch));
        dialog.setMinimumSize(600, 400);

        QVBoxLayout* layout = new QVBoxLayout(&dialog);
        QTextEdit* textEdit = new QTextEdit();
        textEdit->setReadOnly(true);
        textEdit->setPlainText(displayText);
        layout->addWidget(textEdit);

        QPushButton* closeButton = new QPushButton(tr("Close"));
        connect(closeButton, &QPushButton::clicked, &dialog, &QDialog::accept);
        layout->addWidget(closeButton);

        dialog.exec();

    } catch (const UniValue& objError) {
        try {
            int code = objError.find_value("code").getInt<int>();
            std::string message = objError.find_value("message").get_str();

            // Handle specific error cases
            if (message.find("has not been rotated yet") != std::string::npos) {
                QMessageBox::information(this, tr("No Prior ICU"),
                                        tr("This asset has not been rotated yet (policy_epoch=0).\n\n"
                                           "There is no previous ICU to display."));
            } else {
                QMessageBox::warning(this, tr("RPC Error"),
                                    tr("RPC Error %1: %2").arg(code).arg(QString::fromStdString(message)));
            }
        } catch (...) {
            QMessageBox::warning(this, tr("Error"),
                                tr("Failed to retrieve previous ICU: %1").arg(QString::fromStdString(objError.write())));
        }
    } catch (const std::exception& e) {
        QMessageBox::warning(this, tr("Error"),
                            tr("Failed to retrieve previous ICU: %1").arg(e.what()));
    }
}

void TreasuryPage::onOpenRotateICUDialog()
{
    if (!walletModel || !clientModel) {
        QMessageBox::warning(this, tr("Not Initialized"),
                           tr("Wallet or client model not initialized."));
        return;
    }

    // Create and show the Rotate ICU dialog
    RotateICUDialog dialog(m_platform_style, this);
    dialog.setWalletModel(walletModel);
    dialog.setClientModel(clientModel);

    // Build asset list from dashboard table (fast - no RPC calls)
    QMap<QString, QString> assets;
    if (isIssuerMode && dashboardICUTable) {
        for (int row = 0; row < dashboardICUTable->rowCount(); ++row) {
            QTableWidgetItem* tickerItem = dashboardICUTable->item(row, 0);
            QTableWidgetItem* assetIdItem = dashboardICUTable->item(row, 1);
            if (tickerItem && assetIdItem) {
                QString assetId = assetIdItem->data(Qt::UserRole).toString();
                QString ticker = tickerItem->text();
                if (!assetId.isEmpty()) {
                    assets[assetId] = ticker;
                }
            }
        }
    }
    dialog.setAssetList(assets);

    // If there's a selected asset in the dashboard, pass it to the dialog
    int row = dashboardICUTable->currentRow();
    if (row >= 0) {
        QTableWidgetItem* item = dashboardICUTable->item(row, 1);
        if (item) {
            QString assetId = item->data(Qt::UserRole).toString();
            if (!assetId.isEmpty()) {
                dialog.setAsset(assetId);
            }
        }
    }

    // Show dialog modally
    dialog.exec();

    // Refresh the dashboard after dialog closes
    refreshICUDashboard();
}

// ===== MODE SWITCHING IMPLEMENTATIONS =====

void TreasuryPage::onSwitchToHolderMode()
{
    if (!isIssuerMode) return; // Already in holder mode

    holderModeButton->setChecked(true);
    issuerModeButton->setChecked(false);
    switchMode(false);
}

void TreasuryPage::onSwitchToIssuerMode()
{
    if (isIssuerMode) return; // Already in issuer mode

    holderModeButton->setChecked(false);
    issuerModeButton->setChecked(true);
    switchMode(true);
}

void TreasuryPage::switchMode(bool issuerMode)
{
    if (isIssuerMode == issuerMode) {
        return;
    }
    isIssuerMode = issuerMode;
    updateVisibilityForMode();

    // Defer data refresh so the tab rebuild paints immediately.
    // Without this, synchronous RPC calls in the refreshers block
    // the UI thread and the mode switch appears stuck on Windows.
    queueModeRefresh();
}

void TreasuryPage::queueModeRefresh()
{
    if (m_mode_refresh_queued) {
        return;
    }
    m_mode_refresh_queued = true;
    QTimer::singleShot(0, this, [this] {
        m_mode_refresh_queued = false;
        refreshAssetList();
        refreshICUDashboard();
    });
}

void TreasuryPage::activateHolderView(const QString& assetId)
{
    // Switch to holder mode
    holderModeButton->setChecked(true);
    issuerModeButton->setChecked(false);
    switchMode(false);

    // If an asset ID is provided, filter the dashboard to show only that asset
    if (!assetId.isEmpty() && dashboardFilterEdit) {
        dashboardFilterEdit->setText(assetId);
        onDashboardFilterChanged();
    }

    // Switch to the "My Assets" tab (first tab in holder mode)
    if (tabWidget) {
        tabWidget->setCurrentIndex(0);
    }
}

void TreasuryPage::updateVisibilityForMode()
{
    if (isIssuerMode) {
        // Asset Issuer view: Show issuer-specific tabs
        // Remove all tabs first
        while (tabWidget->count() > 0) {
            tabWidget->removeTab(0);
        }

        // Add issuer tabs. Core issuance lifecycle first (ICU Dashboard is the landing page), then the
        // option/CFD derivative builders grouped together on the right as optional advanced steps.
        tabWidget->addTab(dashboardTab, tr("ICU Dashboard"));
        tabWidget->addTab(registrationTab, tr("Register Asset"));
        tabWidget->addTab(mintTab, tr("Mint"));
        tabWidget->addTab(burnTab, tr("Burn"));
        tabWidget->addTab(zkComplianceTab, tr("Compliance"));
        tabWidget->addTab(distributionTab, tr("Distribution"));
        tabWidget->addTab(governanceTab, tr("Governance"));
        tabWidget->addTab(optionSeriesTab, tr("Option Series"));
        tabWidget->addTab(cfdSeriesTab, tr("CFD Asset Series"));
        // Bilateral scalar-feed CFD moved to Exchange (Structuring→Book); Treasury tab unwired.
        tabWidget->addTab(verifyOptionTab, tr("Verify Option"));

        // Update dashboard table headers for issuer view
        dashboardICUTable->setColumnCount(9);
        dashboardICUTable->setHorizontalHeaderLabels({
            tr("Ticker"), tr("Asset ID"), tr("ICU TxID"), tr("Vout"),
            tr("Bond (TSC)"), tr("Fees Accum"), tr("Unlock Target"),
            tr("Progress"), tr("Status")
        });
        dashboardICUTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
        dashboardICUTable->resizeColumnsToContents();
        dashboardICUTable->setMaximumHeight(250);

        if (dashboardFilterGroup) {
            dashboardFilterGroup->setTitle(tr("Filter"));
        }
        if (dashboardFilterCombo) {
            dashboardFilterCombo->setVisible(true);
            dashboardFilterCombo->blockSignals(true);
            dashboardFilterCombo->clear();
            dashboardFilterCombo->addItem(tr("All"));
            dashboardFilterCombo->addItem(tr("Locked"));
            dashboardFilterCombo->addItem(tr("Unlocked"));
            dashboardFilterCombo->setCurrentIndex(0);
            dashboardFilterCombo->blockSignals(false);
        }
        if (dashboardFilterEdit) {
            QSignalBlocker blocker(dashboardFilterEdit);
            dashboardFilterEdit->setPlaceholderText(tr("Search by ticker or asset ID"));
            dashboardFilterEdit->clear();
        }

        // Show Rotate ICU button in issuer mode; hide holder-only acceptance actions.
        if (dashboardRotateICUButton) {
            dashboardRotateICUButton->setVisible(true);
        }
        if (dashboardAcceptButton) dashboardAcceptButton->setVisible(false);
        if (dashboardReturnButton) dashboardReturnButton->setVisible(false);

        if (zkIssuerGroup) {
            zkIssuerGroup->show();
        }
        if (zkHolderGroup) {
            zkHolderGroup->setTitle(tr("Generate ZK Proof (Holder)"));
            zkHolderGroup->show();
        }

        if (govPrepareGroup) {
            govPrepareGroup->show();
        }
        if (govFinalizeGroup) {
            govFinalizeGroup->show();
        }
        if (govBallotGroup) {
            // Hide ballot casting in issuer mode - only holders cast ballots
            govBallotGroup->hide();
        }

        // Nostr governance: Hide entire discovery section in issuer mode
        // Issuers don't browse proposals - they create them
        if (govNostrDiscoveryGroup) {
            govNostrDiscoveryGroup->setVisible(false);
        }
        // PR3: Show issuer access requests section
        if (govIssuerAccessRequestsGroup) {
            govIssuerAccessRequestsGroup->setVisible(true);
        }
        // Publish to Network button visibility controlled by PSBT existence

        // In issuer mode, if Pre-Registration Mode is selected, show zkContentWidget
        if (zkAssetCombo && zkAssetCombo->currentData().toString().isEmpty()) {
            if (zkContentWidget) zkContentWidget->setVisible(true);
            if (zkNoComplianceLabel) zkNoComplianceLabel->setVisible(false);
        }

        onDashboardFilterChanged();
    } else {
        // Asset Holder view: Show holder-specific tabs
        // Remove all tabs first
        while (tabWidget->count() > 0) {
            tabWidget->removeTab(0);
        }

        // Add holder tabs
        tabWidget->addTab(dashboardTab, tr("My Assets"));
        tabWidget->addTab(verifyOptionTab, tr("Verify Option"));
        // Bilateral scalar-feed CFD moved to Exchange (Structuring→Book), reachable by holders too; unwired.
        tabWidget->addTab(zkComplianceTab, tr("Compliance"));
        tabWidget->addTab(governanceTab, tr("Governance"));

        // HOLDER MODE: Table shows asset policy characteristics
        dashboardICUTable->setColumnCount(10);
        dashboardICUTable->setHorizontalHeaderLabels({
            tr("Ticker"), tr("Asset ID"), tr("Balance"), tr("Max Issuance"),
            tr("Total Issued"), tr("Gov BPS"), tr("Text Vis"),
            tr("Script Families"), tr("Compliance"), tr("TFR Req")
        });
        dashboardICUTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
        dashboardICUTable->resizeColumnsToContents();
        dashboardICUTable->setMaximumHeight(std::numeric_limits<int>::max());

        if (dashboardFilterGroup) {
            dashboardFilterGroup->setTitle(tr("Search"));
        }
        if (dashboardFilterCombo) {
            dashboardFilterCombo->setVisible(false);
            dashboardFilterCombo->blockSignals(true);
            dashboardFilterCombo->setCurrentIndex(0);
            dashboardFilterCombo->blockSignals(false);
        }
        if (dashboardFilterEdit) {
            QSignalBlocker blocker(dashboardFilterEdit);
            dashboardFilterEdit->setPlaceholderText(tr("Search my assets"));
            dashboardFilterEdit->clear();
        }

        // Hide Rotate ICU button in holder mode; show the holder-only acceptance actions.
        if (dashboardRotateICUButton) {
            dashboardRotateICUButton->setVisible(false);
        }
        if (dashboardAcceptButton) dashboardAcceptButton->setVisible(true);
        if (dashboardReturnButton) dashboardReturnButton->setVisible(true);

        if (zkIssuerGroup) {
            zkIssuerGroup->hide();
        }
        if (zkHolderGroup) {
            zkHolderGroup->setTitle(tr("Compliance Proof"));
            zkHolderGroup->show();
        }

        if (govPrepareGroup) {
            govPrepareGroup->hide();
        }
        if (govFinalizeGroup) {
            govFinalizeGroup->hide();
        }
        if (govBallotGroup) {
            govBallotGroup->setTitle(tr("Cast Governance Ballot"));
            govBallotGroup->show();
        }

        // Nostr governance: Show discovery section in holder mode
        // Holders browse and vote on proposals
        if (govNostrDiscoveryGroup) {
            govNostrDiscoveryGroup->setVisible(true);
        }
        // PR3: Hide issuer access requests section
        if (govIssuerAccessRequestsGroup) {
            govIssuerAccessRequestsGroup->setVisible(false);
        }
        // Note: Vote button visibility is controlled by proposal selection handler
        // Don't force it visible here - let the handler decide based on proposal type/access

        // Publish to Network button not visible in holder mode

        onDashboardFilterChanged();
    }
}

// ===== NOSTR GOVERNANCE SLOTS =====

void TreasuryPage::onGovNostrRefresh()
{
    updateGovBulletinBoardStatus();

    if (!walletModel || !govBBInitialized) {
        govNostrProposalsTable->setRowCount(0);
        return;
    }

    QString assetFilter = govNostrAssetFilterCombo->currentData().toString();

    // Call RPC to list governance proposals
    auto result = walletModel->governanceListProposals(assetFilter, false);

    if (!result.success) {
        govStatusText->append(tr("Failed to refresh proposals: %1").arg(result.error));
        return;
    }

    // Track new proposals for notifications
    QSet<QString> newProposalIds;

    // Update proposals table
    govNostrProposalsTable->setRowCount(0);
    govNostrProposalsTable->setRowCount(result.proposals.size());

    for (int i = 0; i < result.proposals.size(); i++) {
        QVariantMap prop = result.proposals[i].toMap();

        QString assetId = prop.value("asset_id").toString();
        QString title = prop.value("title").toString();
        qint64 createdAt = prop.value("created_at").toLongLong();
        qint64 expiresAt = prop.value("expires_at").toLongLong();
        bool isExpired = prop.value("is_expired").toBool();

        // Verify BIP-322 attestation for each proposal
        bool verified = false;
        QVariantMap attestation = prop.value("icu_attestation").toMap();
        if (!attestation.isEmpty() && walletModel) {
            QString address = attestation["address"].toString();
            QString message = attestation["message"].toString();
            QString signature = attestation["signature"].toString();
            QString proposal_id = prop.value("proposal_id").toString();
            QString expected_msg = QString("TENSORCASH_GOVERNANCE:%1").arg(proposal_id);

            if (message == expected_msg) {
                verified = walletModel->verifyMessageBip322(address, signature, message);
            }
        }

        // Look up ticker from asset registry for friendly display
        QString assetDisplay = assetId.left(8) + "...";
        if (walletModel) {
            QList<WalletModel::AssetInfo> assets = walletModel->listAssets();
            for (const auto& asset : assets) {
                if (asset.asset_id == assetId) {
                    if (!asset.ticker.isEmpty()) {
                        assetDisplay = asset.ticker;
                    }
                    break;
                }
            }
        }

        govNostrProposalsTable->setItem(i, 0, new QTableWidgetItem(assetDisplay));
        govNostrProposalsTable->setItem(i, 1, new QTableWidgetItem(title.isEmpty() ? tr("(No title)") : title));
        govNostrProposalsTable->setItem(i, 2, new QTableWidgetItem(QDateTime::fromSecsSinceEpoch(createdAt).toString("yyyy-MM-dd")));
        govNostrProposalsTable->setItem(i, 3, new QTableWidgetItem(QDateTime::fromSecsSinceEpoch(expiresAt).toString("yyyy-MM-dd")));
        govNostrProposalsTable->setItem(i, 4, new QTableWidgetItem(isExpired ? tr("Expired") : tr("Active")));
        govNostrProposalsTable->setItem(i, 5, new QTableWidgetItem(verified ? tr("✓") : tr("Pending")));

        // PR3: Show private access status in column 6
        QString flow_type = prop.value("flow_type").toString();
        bool isPrivate = (flow_type == "private");
        bool hasTemplatePsbt = prop.contains("template_psbt") && !prop.value("template_psbt").toString().isEmpty();

        QString accessStatus;
        QColor accessColor;
        if (isPrivate) {
            if (hasTemplatePsbt && verified) {
                accessStatus = tr("GRANTED");
                accessColor = QColor("#388e3c");
            } else if (hasTemplatePsbt) {
                accessStatus = tr("VERIFY FAILED");
                accessColor = QColor("#d32f2f");
            } else {
                accessStatus = tr("PRIVATE - USE BUTTON BELOW");
                accessColor = QColor("#ff6f00");
            }
        } else {
            accessStatus = tr("Public");
            accessColor = QColor("#666");
        }

        QTableWidgetItem* accessItem = new QTableWidgetItem(accessStatus);
        accessItem->setForeground(QBrush(accessColor));
        if (isPrivate && !hasTemplatePsbt) {
            QFont boldFont = accessItem->font();
            boldFont.setBold(true);
            accessItem->setFont(boldFont);
        }
        govNostrProposalsTable->setItem(i, 6, accessItem);

        // Store full proposal data with computed verification status
        prop["bip322_verified"] = verified;
        govNostrProposalsTable->item(i, 0)->setData(Qt::UserRole, prop);

        // Track this proposal ID
        QString proposal_id = prop.value("proposal_id").toString();
        if (!proposal_id.isEmpty()) {
            newProposalIds.insert(proposal_id);

            // Check if this is a new proposal (not seen before)
            if (!seenProposalIds.contains(proposal_id) && !isExpired && verified) {
                // CRITICAL: Only notify for assets the wallet owns
                bool walletOwnsAsset = false;
                if (walletModel) {
                    auto assetBalances = walletModel->getAssetBalances();
                    for (const auto& balance : assetBalances) {
                        QString balanceAssetId = QString::fromStdString(balance.asset_id.ToString());
                        if (balanceAssetId == assetId && balance.balance > 0) {
                            walletOwnsAsset = true;
                            break;
                        }
                    }
                }

                if (walletOwnsAsset) {
                    // Show notification for new verified, active proposal for owned assets
                    QString notificationTitle = tr("New Governance Proposal");
                    QString notificationMsg = tr("%1: %2").arg(assetDisplay).arg(title.isEmpty() ? tr("Untitled proposal") : title);

                    Q_EMIT this->message(notificationTitle, notificationMsg, CClientUIInterface::MSG_INFORMATION);
                    LogPrintf("TreasuryPage: New governance proposal notification: %s - %s\n",
                             assetDisplay.toStdString(), title.toStdString());
                }
            }
        }
    }

    // Update seen proposals set (union with new)
    seenProposalIds.unite(newProposalIds);

    // PR3: Poll for private proposal responses
    if (clientModel) {
        try {
            UniValue params(UniValue::VARR);
            UniValue dmResult = clientModel->node().executeRpc("cosign.process_governance_dms", params, "");

            // DEBUG: Log the full DM result
            LogPrintf("TreasuryPage: DM polling result: %s\n", dmResult.write(2));

            if (dmResult.exists("proposal_responses") && dmResult["proposal_responses"].isArray()) {
                const UniValue& responses = dmResult["proposal_responses"];
                [[maybe_unused]] bool needsRefresh = false;

                for (size_t i = 0; i < responses.size(); i++) {
                    const UniValue& resp = responses[i];

                    // CRITICAL: Check all fields exist before accessing
                    if (!resp.exists("proposal_id") || !resp["proposal_id"].isStr()) {
                        LogPrintf("TreasuryPage: WARNING - proposal_response missing proposal_id\n");
                        continue;
                    }

                    std::string proposal_id = resp["proposal_id"].get_str();
                    LogPrintf("TreasuryPage: Processing response for proposal %s\n", proposal_id);

                    // Find matching proposal in table and update it
                    for (int row = 0; row < govNostrProposalsTable->rowCount(); row++) {
                        QTableWidgetItem* item = govNostrProposalsTable->item(row, 0);
                        if (!item) continue;

                        QVariantMap prop = item->data(Qt::UserRole).toMap();
                        if (prop.value("proposal_id").toString() == QString::fromStdString(proposal_id)) {
                            // Merge all proposal response fields into cached data
                            if (resp.exists("icu_text") && resp["icu_text"].isStr()) {
                                prop["icu_text"] = QString::fromStdString(resp["icu_text"].get_str());
                            }
                            if (resp.exists("template_psbt") && resp["template_psbt"].isStr()) {
                                prop["template_psbt"] = QString::fromStdString(resp["template_psbt"].get_str());
                            }
                            if (resp.exists("template_psbt_hash") && resp["template_psbt_hash"].isStr()) {
                                prop["template_psbt_hash"] = QString::fromStdString(resp["template_psbt_hash"].get_str());
                            }
                            if (resp.exists("witness_bundle") && resp["witness_bundle"].isStr()) {
                                prop["witness_bundle"] = QString::fromStdString(resp["witness_bundle"].get_str());
                            }
                            if (resp.exists("canonical_icu_hash") && resp["canonical_icu_hash"].isStr()) {
                                prop["canonical_icu_hash"] = QString::fromStdString(resp["canonical_icu_hash"].get_str());
                            }

                            govNostrProposalsTable->item(row, 0)->setData(Qt::UserRole, prop);

                            // Update Access column to show "GRANTED"
                            QTableWidgetItem* accessItem = govNostrProposalsTable->item(row, 6);
                            if (accessItem) {
                                accessItem->setText(tr("GRANTED"));
                                accessItem->setForeground(QBrush(QColor("#388e3c")));
                                QFont boldFont = accessItem->font();
                                boldFont.setBold(true);
                                accessItem->setFont(boldFont);
                            }

                            // Update button visibility if this is the currently selected proposal
                            if (row == govNostrProposalsTable->currentRow()) {
                                bool isHolder = !isIssuerMode;
                                // Proposal now has template_psbt, so it's accessible - show Vote button
                                govNostrVoteButton->setVisible(isHolder);
                                // Hide Request Private Access button since access is now granted
                                govNostrRequestPrivateButton->setVisible(false);
                            }

                            needsRefresh = true;
                            LogPrintf("TreasuryPage: Merged proposal response data for %s\n", proposal_id);
                            break;
                        }
                    }
                }
            }
        } catch (const UniValue& uv_error) {
            LogPrintf("TreasuryPage: UniValue exception in DM polling: %s\n", uv_error.write());
        } catch (const std::exception& e) {
            LogPrintf("TreasuryPage: Exception in DM polling: %s\n", e.what());
        } catch (...) {
            LogPrintf("TreasuryPage: Unknown exception in DM polling\n");
        }
    }

    // Update last refresh timestamp
    lastGovRefreshTime = QDateTime::currentDateTime();
    if (govLastRefreshLabel) {
        govLastRefreshLabel->setText(tr("Last refresh: %1").arg(lastGovRefreshTime.toString("hh:mm:ss")));
    }
}

void TreasuryPage::onGovNostrForceRefresh()
{
    if (!walletModel) return;

    govForceRefreshButton->setEnabled(false);
    govForceRefreshButton->setText(tr("Refreshing..."));

    bool success = walletModel->governanceForceRefresh();

    if (success) {
        govStatusText->append(tr("✓ Force refreshed governance proposals from Nostr relays"));
        QTimer::singleShot(1000, this, &TreasuryPage::onGovNostrRefresh);
    } else {
        govStatusText->append(tr("Failed to force refresh governance proposals"));
    }

    govForceRefreshButton->setEnabled(true);
    govForceRefreshButton->setText(tr("Force Refresh"));
}

void TreasuryPage::onGovIssuerProcessAccessRequests()
{
    if (!clientModel || !govIssuerAccessRequestsTable || !govAutoApproveCheckbox) {
        return;
    }

    try {
        // Pass auto-approve flag from checkbox to RPC
        UniValue params(UniValue::VARR);
        params.push_back(UniValue());  // since parameter (default)
        params.push_back(govAutoApproveCheckbox->isChecked());  // auto_approve parameter
        UniValue dmResult = clientModel->node().executeRpc("cosign.process_governance_dms", params, "");

        LogPrintf("TreasuryPage: Issuer DM processing result: %s\n", dmResult.write(2));

        // Clear existing table
        govIssuerAccessRequestsTable->setRowCount(0);

        int rowIndex = 0;

        // Process access requests
        if (dmResult.exists("access_requests") && dmResult["access_requests"].isArray()) {
            const UniValue& requests = dmResult["access_requests"];
            for (size_t i = 0; i < requests.size(); i++) {
                const UniValue& req = requests[i];

                if (!req.exists("proposal_id") || !req["proposal_id"].isStr()) continue;

                QString proposal_id = QString::fromStdString(req["proposal_id"].get_str());
                QString holder_pubkey = req.exists("holder_nostr_pubkey") && req["holder_nostr_pubkey"].isStr() ?
                    QString::fromStdString(req["holder_nostr_pubkey"].get_str()) : tr("Unknown");
                QString utxo_ref = req.exists("utxo_ref") && req["utxo_ref"].isStr() ?
                    QString::fromStdString(req["utxo_ref"].get_str()) : tr("N/A");
                uint64_t asset_units = req.exists("asset_units") && req["asset_units"].isNum() ?
                    req["asset_units"].getInt<uint64_t>() : 0;
                bool verified = req.exists("ownership_verified") && req["ownership_verified"].isBool() ?
                    req["ownership_verified"].get_bool() : false;

                govIssuerAccessRequestsTable->insertRow(rowIndex);
                govIssuerAccessRequestsTable->setItem(rowIndex, 0, new QTableWidgetItem(proposal_id.left(16) + "..."));
                govIssuerAccessRequestsTable->setItem(rowIndex, 1, new QTableWidgetItem(holder_pubkey.left(16) + "..."));
                govIssuerAccessRequestsTable->setItem(rowIndex, 2, new QTableWidgetItem(utxo_ref.left(20) + "..."));
                govIssuerAccessRequestsTable->setItem(rowIndex, 3, new QTableWidgetItem(QString::number(asset_units)));

                QTableWidgetItem* verifiedItem = new QTableWidgetItem(verified ? tr("✓ Yes") : tr("✗ No"));
                verifiedItem->setForeground(QBrush(verified ? QColor("#388e3c") : QColor("#d32f2f")));
                govIssuerAccessRequestsTable->setItem(rowIndex, 4, verifiedItem);

                // Add Approve/Deny buttons (only for verified requests)
                if (verified) {
                    QWidget* buttonWidget = new QWidget();
                    QHBoxLayout* buttonLayout = new QHBoxLayout(buttonWidget);
                    buttonLayout->setContentsMargins(2, 2, 2, 2);
                    buttonLayout->setSpacing(4);

                    QPushButton* approveBtn = new QPushButton(tr("✓ Approve"));
                    approveBtn->setStyleSheet("QPushButton { background-color: #4caf50; color: white; padding: 4px 8px; } QPushButton:hover { background-color: #45a049; }");
                    QPushButton* denyBtn = new QPushButton(tr("✗ Deny"));
                    denyBtn->setStyleSheet("QPushButton { background-color: #f44336; color: white; padding: 4px 8px; } QPushButton:hover { background-color: #da190b; }");

                    // Store proposal_id and holder_pubkey in button properties for callback
                    approveBtn->setProperty("proposal_id", proposal_id);
                    approveBtn->setProperty("holder_pubkey", holder_pubkey);
                    approveBtn->setProperty("row", rowIndex);
                    denyBtn->setProperty("proposal_id", proposal_id);
                    denyBtn->setProperty("holder_pubkey", holder_pubkey);
                    denyBtn->setProperty("row", rowIndex);

                    connect(approveBtn, &QPushButton::clicked, this, &TreasuryPage::onGovIssuerApproveRequest);
                    connect(denyBtn, &QPushButton::clicked, this, &TreasuryPage::onGovIssuerDenyRequest);

                    buttonLayout->addWidget(approveBtn);
                    buttonLayout->addWidget(denyBtn);
                    buttonWidget->setLayout(buttonLayout);

                    govIssuerAccessRequestsTable->setCellWidget(rowIndex, 5, buttonWidget);
                    govIssuerAccessRequestsTable->setItem(rowIndex, 6, new QTableWidgetItem(tr("Pending")));
                } else {
                    govIssuerAccessRequestsTable->setItem(rowIndex, 5, new QTableWidgetItem(tr("N/A")));
                    govIssuerAccessRequestsTable->setItem(rowIndex, 6, new QTableWidgetItem(tr("Unverified")));
                }

                rowIndex++;
            }
        }

        // Process auto-sent responses
        if (dmResult.exists("auto_sent_responses") && dmResult["auto_sent_responses"].isArray()) {
            const UniValue& responses = dmResult["auto_sent_responses"];
            for (size_t i = 0; i < responses.size(); i++) {
                const UniValue& resp = responses[i];

                if (!resp.exists("proposal_id") || !resp["proposal_id"].isStr()) continue;

                QString proposal_id = QString::fromStdString(resp["proposal_id"].get_str());
                QString holder_pubkey = resp.exists("holder_pubkey") && resp["holder_pubkey"].isStr() ?
                    QString::fromStdString(resp["holder_pubkey"].get_str()) : tr("Unknown");
                QString event_id = resp.exists("event_id") && resp["event_id"].isStr() ?
                    QString::fromStdString(resp["event_id"].get_str()) : tr("N/A");
                int64_t sent_at = resp.exists("sent_at") && resp["sent_at"].isNum() ?
                    resp["sent_at"].getInt<int64_t>() : 0;

                // Update existing row or add new one
                bool foundExisting = false;
                for (int row = 0; row < govIssuerAccessRequestsTable->rowCount(); row++) {
                    QTableWidgetItem* pidItem = govIssuerAccessRequestsTable->item(row, 0);
                    QTableWidgetItem* hpkItem = govIssuerAccessRequestsTable->item(row, 1);
                    if (pidItem && hpkItem &&
                        pidItem->text().startsWith(proposal_id.left(16)) &&
                        hpkItem->text().startsWith(holder_pubkey.left(16))) {
                        // Remove action buttons (response already sent)
                        govIssuerAccessRequestsTable->removeCellWidget(row, 5);
                        govIssuerAccessRequestsTable->setItem(row, 5, new QTableWidgetItem(tr("Sent")));
                        // Update status column
                        QString sentText = tr("✓ Approved at %1").arg(QDateTime::fromSecsSinceEpoch(sent_at).toString("hh:mm:ss"));
                        QTableWidgetItem* sentItem = new QTableWidgetItem(sentText);
                        sentItem->setForeground(QBrush(QColor("#388e3c")));
                        govIssuerAccessRequestsTable->setItem(row, 6, sentItem);
                        foundExisting = true;
                        break;
                    }
                }

                if (!foundExisting) {
                    // Add as new row (response sent but no pending request shown)
                    govIssuerAccessRequestsTable->insertRow(rowIndex);
                    govIssuerAccessRequestsTable->setItem(rowIndex, 0, new QTableWidgetItem(proposal_id.left(16) + "..."));
                    govIssuerAccessRequestsTable->setItem(rowIndex, 1, new QTableWidgetItem(holder_pubkey.left(16) + "..."));
                    govIssuerAccessRequestsTable->setItem(rowIndex, 2, new QTableWidgetItem(tr("N/A")));
                    govIssuerAccessRequestsTable->setItem(rowIndex, 3, new QTableWidgetItem(tr("N/A")));
                    govIssuerAccessRequestsTable->setItem(rowIndex, 4, new QTableWidgetItem(tr("Auto")));
                    govIssuerAccessRequestsTable->setItem(rowIndex, 5, new QTableWidgetItem(tr("Sent")));

                    QString sentText = tr("✓ Auto-approved at %1").arg(QDateTime::fromSecsSinceEpoch(sent_at).toString("hh:mm:ss"));
                    QTableWidgetItem* sentItem = new QTableWidgetItem(sentText);
                    sentItem->setForeground(QBrush(QColor("#388e3c")));
                    govIssuerAccessRequestsTable->setItem(rowIndex, 6, sentItem);
                    rowIndex++;
                }
            }
        }

        QMessageBox::information(this, tr("Access Requests Processed"),
            tr("Processed %1 requests.\nAuto-sent responses to verified holders.").arg(rowIndex));

    } catch (const UniValue& uv_error) {
        LogPrintf("TreasuryPage: UniValue exception processing access requests: %s\n", uv_error.write());
        QMessageBox::critical(this, tr("Error"), tr("Failed to process access requests (UniValue error)"));
    } catch (const std::exception& e) {
        LogPrintf("TreasuryPage: Exception processing access requests: %s\n", e.what());
        QMessageBox::critical(this, tr("Error"), tr("Failed to process access requests:\n%1").arg(e.what()));
    }
}

void TreasuryPage::onGovIssuerApproveRequest()
{
    if (!clientModel) {
        return;
    }

    QPushButton* button = qobject_cast<QPushButton*>(sender());
    if (!button) {
        return;
    }

    QString proposal_id = button->property("proposal_id").toString();
    QString holder_pubkey = button->property("holder_pubkey").toString();
    int row = button->property("row").toInt();

    try {
        // Call manual approval RPC
        UniValue params(UniValue::VARR);
        params.push_back(proposal_id.toStdString());
        params.push_back(holder_pubkey.toStdString());
        params.push_back(true);  // approve=true

        UniValue result = clientModel->node().executeRpc("cosign.send_proposal_response_manual", params, "");

        if (result.exists("success") && result["success"].get_bool()) {
            // Remove action buttons from this row
            govIssuerAccessRequestsTable->removeCellWidget(row, 5);
            govIssuerAccessRequestsTable->setItem(row, 5, new QTableWidgetItem(tr("Sent")));

            // Update status column
            QTableWidgetItem* statusItem = new QTableWidgetItem(tr("✓ Manually Approved"));
            statusItem->setForeground(QBrush(QColor("#388e3c")));
            govIssuerAccessRequestsTable->setItem(row, 6, statusItem);

            LogPrintf("TreasuryPage: Manually approved proposal %s for holder %s\n",
                      proposal_id.toStdString(), holder_pubkey.toStdString().substr(0, 16));
        }

    } catch (const std::exception& e) {
        LogPrintf("TreasuryPage: Exception approving request: %s\n", e.what());
        QMessageBox::critical(this, tr("Error"), tr("Failed to approve request:\n%1").arg(e.what()));
    }
}

void TreasuryPage::onGovIssuerDenyRequest()
{
    if (!clientModel) {
        return;
    }

    QPushButton* button = qobject_cast<QPushButton*>(sender());
    if (!button) {
        return;
    }

    QString proposal_id = button->property("proposal_id").toString();
    QString holder_pubkey = button->property("holder_pubkey").toString();
    int row = button->property("row").toInt();

    // Confirm denial
    QMessageBox::StandardButton reply = QMessageBox::question(this, tr("Deny Access Request"),
        tr("Are you sure you want to deny access to this holder?\n\nProposal: %1\nHolder: %2\n\nNo response will be sent (denial by silence).")
            .arg(proposal_id.left(16) + "...").arg(holder_pubkey.left(16) + "..."),
        QMessageBox::Yes | QMessageBox::No);

    if (reply != QMessageBox::Yes) {
        return;
    }

    try {
        // Call manual denial RPC (approve=false means no DM sent)
        UniValue params(UniValue::VARR);
        params.push_back(proposal_id.toStdString());
        params.push_back(holder_pubkey.toStdString());
        params.push_back(false);  // approve=false

        UniValue result = clientModel->node().executeRpc("cosign.send_proposal_response_manual", params, "");

        if (result.exists("success") && result["success"].get_bool()) {
            // Remove action buttons from this row
            govIssuerAccessRequestsTable->removeCellWidget(row, 5);
            govIssuerAccessRequestsTable->setItem(row, 5, new QTableWidgetItem(tr("Denied")));

            // Update status column
            QTableWidgetItem* statusItem = new QTableWidgetItem(tr("✗ Denied"));
            statusItem->setForeground(QBrush(QColor("#d32f2f")));
            govIssuerAccessRequestsTable->setItem(row, 6, statusItem);

            LogPrintf("TreasuryPage: Manually denied proposal %s for holder %s\n",
                      proposal_id.toStdString(), holder_pubkey.toStdString().substr(0, 16));
        }

    } catch (const std::exception& e) {
        LogPrintf("TreasuryPage: Exception denying request: %s\n", e.what());
        QMessageBox::critical(this, tr("Error"), tr("Failed to deny request:\n%1").arg(e.what()));
    }
}

void TreasuryPage::onGovNostrVote()
{
    if (!walletModel || !clientModel) {
        return;
    }

    int row = govNostrProposalsTable->currentRow();
    if (row < 0) {
        QMessageBox::warning(this, tr("No Selection"), tr("Please select a proposal to vote on."));
        return;
    }

    QTableWidgetItem* item = govNostrProposalsTable->item(row, 0);
    if (!item) {
        QMessageBox::warning(this, tr("Invalid Selection"), tr("Selected row has no data."));
        return;
    }

    QVariantMap proposal = item->data(Qt::UserRole).toMap();

    // Extract PSBT from proposal if it exists
    QString template_psbt = proposal.value("template_psbt").toString();

    if (template_psbt.isEmpty()) {
        QMessageBox::warning(this, tr("No PSBT"), tr("This proposal does not have a template PSBT attached."));
        return;
    }

    // Get asset ID for UTXO lookup
    QString asset_id = proposal.value("asset_id").toString();
    QString proposal_id = proposal.value("proposal_id").toString();

    if (asset_id.isEmpty() || proposal_id.isEmpty()) {
        QMessageBox::warning(this, tr("Invalid Proposal"), tr("Proposal is missing asset_id or proposal_id."));
        return;
    }

    // GATE (anti-malleability): refuse to sign/cast a ballot for a proposal that does not faithfully
    // describe the transaction it carries (its template PSBT). This runs BEFORE any ballot RPC, so a
    // tampered or mismatched proposal is rejected up-front rather than signed-and-then-warned. Handles
    // both ICU-text proposals (bind text/witness/visibility/hash to the PSBT payload) and policy-only
    // proposals (PSBT must commit no ICU text, and the proposed quorum/cap must match the PSBT).
    {
        const QString g_icu_text = proposal.value("icu_text").toString();
        const QString g_witness = proposal.value("witness_bundle").toString();
        const QString g_canon_claimed = proposal.value("canonical_icu_hash").toString();
        const QString g_witness_hash_claimed = proposal.value("witness_bundle_hash").toString();
        const int g_visibility = (proposal.value("flow_type").toString() == "public") ? 0 : 1;
        QString g_reason;
        bool g_ok = false;
        PartiallySignedTransaction g_psbt;
        std::string g_perr;
        if (!DecodeBase64PSBT(g_psbt, template_psbt.toStdString(), g_perr)) {
            g_reason = tr("the template PSBT could not be decoded");
        } else if (auto g_meta = DecodeGovernanceMetadata(g_psbt)) {
            // Policy binding (ALL proposal shapes, incl. ICU-text): the proposal's EFFECTIVE policy --
            // proposed_policy field when present, else the CURRENT on-chain value ("no change") -- must
            // equal what the PSBT actually commits. This catches a proposal that omits proposed_policy
            // while the PSBT changes quorum/cap, and one that misrepresents the committed values.
            bool g_policy_bound = false;
            QString g_policy_reason;
            try {
                UniValue cpParams(UniValue::VARR);
                cpParams.push_back(asset_id.toStdString());
                const UniValue cur = clientModel->node().executeRpc("getassetpolicy", cpParams, "");
                const uint64_t cur_quorum = cur["policy_quorum_bps"].getInt<uint64_t>();
                const uint64_t cur_cap = cur["issuance_cap_units"].getInt<uint64_t>();
                const QVariantMap g_pp = proposal.value("proposed_policy").toMap();
                const uint64_t eff_quorum = g_pp.contains("policy_quorum_bps")
                    ? g_pp.value("policy_quorum_bps").toULongLong() : cur_quorum;
                const uint64_t eff_cap = g_pp.contains("issuance_cap_units")
                    ? g_pp.value("issuance_cap_units").toULongLong() : cur_cap;
                if (eff_quorum != g_meta->committed_quorum_bps) g_policy_reason = tr("the proposed quorum does not match the PSBT");
                else if (eff_cap != g_meta->committed_cap_units) g_policy_reason = tr("the proposed issuance cap does not match the PSBT");
                else g_policy_bound = true;
            } catch (const std::exception& e) {
                g_policy_reason = tr("could not fetch current policy: %1").arg(QString::fromStdString(e.what()));
            }

            if (!g_policy_bound) {
                g_reason = g_policy_reason;
            } else if (g_icu_text.isEmpty()) {
                // Policy-only proposal: the PSBT must also commit no ICU text (policy already bound above).
                if (g_meta->has_icu_payload && !g_meta->canonical_text.isEmpty()) {
                    g_reason = tr("the proposal claims no ICU text but the PSBT commits one");
                } else {
                    g_ok = true;
                }
            } else if (g_witness.isEmpty()) {
                g_reason = tr("the proposal is missing its witness bundle");
            } else {
                // ICU-text proposal: stated hashes self-consistent + parsed PSBT fields bind the display.
                try {
                    UniValue wuv;
                    if (!wuv.read(g_witness.toStdString())) throw std::runtime_error("invalid witness JSON");
                    UniValue bp(UniValue::VARR);
                    bp.push_back(g_icu_text.toStdString());
                    bp.push_back(wuv);
                    bp.push_back(g_visibility);
                    const UniValue pr = clientModel->node().executeRpc("buildcanonicalicupayload", bp,
                                            walletModel->getWalletName().toStdString());
                    const QString g_computed = QString::fromStdString(pr["canonical_hash"].get_str());
                    if (g_computed != g_canon_claimed) g_reason = tr("the text hash does not match the proposal");
                    else if (computeSHA256(g_witness) != g_witness_hash_claimed) g_reason = tr("the witness hash does not match the proposal");
                    else if (!g_meta->has_icu_payload || g_meta->canonical_text.isEmpty()) g_reason = tr("the PSBT commits no ICU text but the proposal claims one");
                    else if (g_meta->canonical_text != g_icu_text) g_reason = tr("the text differs from the PSBT");
                    else if (g_meta->witness_json != g_witness) g_reason = tr("the witness differs from the PSBT");
                    else if (g_meta->committed_icu_visibility != g_visibility) g_reason = tr("the visibility differs from the PSBT");
                    else if (!g_meta->canonical_hash.isEmpty() && g_meta->canonical_hash != g_canon_claimed) g_reason = tr("the canonical hash differs from the PSBT");
                    else g_ok = true;
                } catch (const std::exception& e) {
                    g_reason = tr("verification error: %1").arg(QString::fromStdString(e.what()));
                }
            }
        } else {
            g_reason = tr("the PSBT is not a governance-rotation PSBT");
        }
        if (!g_ok) {
            QMessageBox::critical(this, tr("Refusing to Vote"),
                tr("This proposal does not faithfully describe the transaction it carries and may be "
                   "tampered with -- NOT signing.\n\nReason: %1").arg(g_reason));
            return;
        }
    }

    // Get holder's asset UTXOs for voting
    try {
        UniValue listParams(UniValue::VARR);
        UniValue assetArray(UniValue::VARR);
        assetArray.push_back(asset_id.toStdString());
        listParams.push_back(assetArray);

        UniValue utxosResult;
        try {
            utxosResult = clientModel->node().executeRpc("listassetutxos", listParams,
                                                          walletModel->getWalletName().toStdString());
        } catch (const UniValue& objError) {
            QString message;
            try {
                int code = objError.find_value("code").getInt<int>();
                std::string detail = objError.find_value("message").get_str();
                message = tr("RPC Error %1: %2").arg(code).arg(QString::fromStdString(detail));
            } catch (...) {
                message = QString::fromStdString(objError.write());
            }
            QMessageBox::critical(this, tr("Vote Failed"),
                tr("Failed to list asset UTXOs:\n\n%1").arg(message));
            return;
        }

        if (!utxosResult.isArray() || utxosResult.size() == 0) {
            QMessageBox::warning(this, tr("Vote Failed"),
                tr("You don't own any UTXOs for this asset.\n\n"
                   "You must hold asset units to vote on governance proposals."));
            return;
        }

        // Show UTXO selection dialog
        QDialog utxoDialog(this);
        utxoDialog.setWindowTitle(tr("Select Voting UTXOs"));
        utxoDialog.resize(600, 400);
        QVBoxLayout* dialogLayout = new QVBoxLayout(&utxoDialog);

        QLabel* instructionLabel = new QLabel(
            tr("Select which UTXOs to use for voting:\n\n"
               "Your voting power is proportional to the asset units in each UTXO.\n"
               "You can select multiple UTXOs to increase your voting weight."),
            &utxoDialog);
        instructionLabel->setWordWrap(true);
        dialogLayout->addWidget(instructionLabel);

        QTableWidget* utxoTable = new QTableWidget(&utxoDialog);
        utxoTable->setColumnCount(5);
        utxoTable->setHorizontalHeaderLabels({tr("Select"), tr("Txid"), tr("Vout"), tr("Asset Units"), tr("Confirmations")});
        utxoTable->setSelectionBehavior(QAbstractItemView::SelectRows);
        utxoTable->horizontalHeader()->setStretchLastSection(false);
        utxoTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
        utxoTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
        utxoTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
        utxoTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
        utxoTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);

        // Populate UTXO table
        for (size_t i = 0; i < utxosResult.size(); ++i) {
            const UniValue& utxo = utxosResult[i];
            int row = utxoTable->rowCount();
            utxoTable->insertRow(row);

            QString txid = QString::fromStdString(utxo["txid"].get_str());
            int vout = utxo["vout"].getInt<int>();
            uint64_t amount = utxo["asset_units"].getInt<uint64_t>();
            int confirmations = utxo.exists("confirmations") ? utxo["confirmations"].getInt<int>() : 0;

            // Checkbox in first column
            QTableWidgetItem* checkItem = new QTableWidgetItem();
            checkItem->setFlags(Qt::ItemIsUserCheckable | Qt::ItemIsEnabled);
            checkItem->setCheckState(i == 0 ? Qt::Checked : Qt::Unchecked);  // Pre-select first UTXO
            checkItem->setData(Qt::UserRole, txid);
            checkItem->setData(Qt::UserRole + 1, vout);
            utxoTable->setItem(row, 0, checkItem);

            utxoTable->setItem(row, 1, new QTableWidgetItem(txid.left(16) + "..."));
            utxoTable->setItem(row, 2, new QTableWidgetItem(QString::number(vout)));
            utxoTable->setItem(row, 3, new QTableWidgetItem(QString::number(amount)));
            utxoTable->setItem(row, 4, new QTableWidgetItem(QString::number(confirmations)));
        }

        dialogLayout->addWidget(utxoTable);

        QLabel* totalLabel = new QLabel(&utxoDialog);
        dialogLayout->addWidget(totalLabel);

        // Update total when selection changes
        // Use QPointer to safely handle widget deletion during dialog cleanup
        QPointer<QTableWidget> safeTablePtr(utxoTable);
        QPointer<QLabel> safeLabelPtr(totalLabel);
        auto updateTotal = [safeTablePtr, safeLabelPtr]() {
            LogPrintf("TreasuryPage::onGovNostrVote updateTotal called, safeTablePtr=%d safeLabelPtr=%d\n",
                      !safeTablePtr.isNull(), !safeLabelPtr.isNull());
            if (!safeTablePtr || !safeLabelPtr) {
                LogPrintf("TreasuryPage::onGovNostrVote updateTotal: widgets destroyed, returning\n");
                return;  // Widget already destroyed
            }
            uint64_t total = 0;
            int count = 0;
            LogPrintf("TreasuryPage::onGovNostrVote updateTotal: rowCount=%d\n", safeTablePtr->rowCount());
            for (int row = 0; row < safeTablePtr->rowCount(); ++row) {
                QTableWidgetItem* checkItem = safeTablePtr->item(row, 0);
                if (checkItem && checkItem->checkState() == Qt::Checked) {
                    QTableWidgetItem* amountItem = safeTablePtr->item(row, 3);
                    if (amountItem) {
                        total += amountItem->text().toULongLong();
                        count++;
                    }
                }
            }
            safeLabelPtr->setText(QObject::tr("<b>Total voting power:</b> %1 units (%2 UTXOs selected)")
                .arg(total).arg(count));
            LogPrintf("TreasuryPage::onGovNostrVote updateTotal completed: total=%llu count=%d\n", total, count);
        };

        LogPrintf("TreasuryPage::onGovNostrVote: calling initial updateTotal\n");
        updateTotal();  // Initial update
        LogPrintf("TreasuryPage::onGovNostrVote: connecting itemChanged signal\n");
        QMetaObject::Connection totalConn = QObject::connect(
            utxoTable, &QTableWidget::itemChanged, &utxoDialog,
            [updateTotal](QTableWidgetItem*) { updateTotal(); });

        // Collect selected UTXOs BEFORE closing dialog (table will be destroyed after exec())
        UniValue utxoArray(UniValue::VARR);
        auto collectSelectedUTXOs = [&utxoArray, utxoTable]() {
            LogPrintf("TreasuryPage::onGovNostrVote collectSelectedUTXOs called\n");
            utxoArray = UniValue(UniValue::VARR);  // Reset in case called multiple times
            for (int row = 0; row < utxoTable->rowCount(); ++row) {
                QTableWidgetItem* checkItem = utxoTable->item(row, 0);
                if (checkItem && checkItem->checkState() == Qt::Checked) {
                    UniValue utxoObj(UniValue::VOBJ);
                    utxoObj.pushKV("txid", checkItem->data(Qt::UserRole).toString().toStdString());
                    utxoObj.pushKV("vout", checkItem->data(Qt::UserRole + 1).toInt());
                    utxoArray.push_back(utxoObj);
                }
            }
            LogPrintf("TreasuryPage::onGovNostrVote collectSelectedUTXOs: collected %d UTXOs\n", utxoArray.size());
        };

        LogPrintf("TreasuryPage::onGovNostrVote: creating button box\n");
        QDialogButtonBox* buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &utxoDialog);
        connect(buttonBox, &QDialogButtonBox::accepted, &utxoDialog, [&utxoDialog, collectSelectedUTXOs]() {
            LogPrintf("TreasuryPage::onGovNostrVote: OK button clicked\n");
            collectSelectedUTXOs();  // Capture selection before dialog closes
            LogPrintf("TreasuryPage::onGovNostrVote: calling utxoDialog.accept()\n");
            utxoDialog.accept();
            LogPrintf("TreasuryPage::onGovNostrVote: utxoDialog.accept() returned\n");
        });
        connect(buttonBox, &QDialogButtonBox::rejected, &utxoDialog, &QDialog::reject);
        dialogLayout->addWidget(buttonBox);

        LogPrintf("TreasuryPage::onGovNostrVote: calling utxoDialog.exec()\n");
        int dialogResult = utxoDialog.exec();
        LogPrintf("TreasuryPage::onGovNostrVote: utxoDialog.exec() returned %d\n", dialogResult);

        LogPrintf("TreasuryPage::onGovNostrVote: disconnecting totalConn\n");
        QObject::disconnect(totalConn);
        LogPrintf("TreasuryPage::onGovNostrVote: totalConn disconnected\n");

        if (dialogResult != QDialog::Accepted) {
            LogPrintf("TreasuryPage::onGovNostrVote: dialog cancelled\n");
            return;  // User cancelled
        }

        // utxoArray is now populated from the lambda above, before dialog was destroyed
        LogPrintf("TreasuryPage::onGovNostrVote: dialog accepted, utxoArray.size=%d\n", utxoArray.size());

        if (utxoArray.size() == 0) {
            QMessageBox::warning(this, tr("No Selection"),
                tr("Please select at least one UTXO to vote with."));
            return;
        }

        // Call ballot RPC to sign
        LogPrintf("TreasuryPage::onGovNostrVote: preparing ballot RPC call\n");
        UniValue ballotParams(UniValue::VARR);
        LogPrintf("TreasuryPage::onGovNostrVote: ballotParams array created\n");
        ballotParams.push_back(template_psbt.toStdString());
        LogPrintf("TreasuryPage::onGovNostrVote: template PSBT pushed to params\n");
        ballotParams.push_back(utxoArray);
        LogPrintf("TreasuryPage::onGovNostrVote: UTXO array pushed to params size=%d\n", static_cast<int>(utxoArray.size()));

        if (walletModel->getEncryptionStatus() == WalletModel::Locked) {
            LogPrintf("TreasuryPage::onGovNostrVote: wallet locked, aborting vote\n");
            QMessageBox::warning(this, tr("Wallet Locked"),
                tr("Please unlock the wallet to sign the governance ballot."));
            return;
        }
        LogPrintf("TreasuryPage::onGovNostrVote: wallet unlocked, executing ballot RPC\n");

        UniValue ballotResult;
        try {
            ballotResult = clientModel->node().executeRpc("ballot", ballotParams,
                                                         walletModel->getWalletName().toStdString());
            LogPrintf("TreasuryPage::onGovNostrVote: ballot RPC returned successfully\n");
        } catch (const UniValue& objError) {
            QString message;
            try {
                int code = objError.find_value("code").getInt<int>();
                std::string detail = objError.find_value("message").get_str();
                message = tr("RPC Error %1: %2").arg(code).arg(QString::fromStdString(detail));
            } catch (...) {
                message = QString::fromStdString(objError.write());
            }
            QMessageBox::critical(this, tr("Vote Failed"),
                tr("Failed to call ballot RPC:\n\n%1").arg(message));
            return;
        }

        if (!ballotResult.isObject() || !ballotResult.exists("psbt")) {
            QMessageBox::critical(this, tr("Vote Failed"),
                tr("ballot RPC returned invalid response (missing psbt field)"));
            return;
        }

        QString signed_psbt = QString::fromStdString(ballotResult["psbt"].get_str());
        uint64_t ballot_units = ballotResult["ballot_units"].getInt<uint64_t>();

        // PR3: Route ballot based on proposal flow type (private vs public)
        QString flow_type = proposal.value("flow_type").toString();
        bool isPrivate = (flow_type == "private");

        QString ballot_id;
        UniValue publishResult;

        if (isPrivate) {
            // Private flow: Send ballot via encrypted DM to issuer
            QString issuer_nostr_pubkey = proposal.value("issuer_nostr_pubkey").toString();
            if (issuer_nostr_pubkey.isEmpty()) {
                QMessageBox::critical(this, tr("Vote Failed"),
                    tr("Cannot submit private ballot: issuer nostr pubkey missing from proposal data"));
                return;
            }

            UniValue dmParams(UniValue::VARR);
            dmParams.push_back(proposal_id.toStdString());
            dmParams.push_back(asset_id.toStdString());
            dmParams.push_back(issuer_nostr_pubkey.toStdString());
            dmParams.push_back(signed_psbt.toStdString());
            dmParams.push_back((int64_t)ballot_units);

            try {
                publishResult = clientModel->node().executeRpc("cosign.send_governance_ballot_dm", dmParams, "");
            } catch (const UniValue& objError) {
                QString message;
                try {
                    int code = objError.find_value("code").getInt<int>();
                    std::string detail = objError.find_value("message").get_str();
                    message = tr("RPC Error %1: %2").arg(code).arg(QString::fromStdString(detail));
                } catch (...) {
                    message = QString::fromStdString(objError.write());
                }
                QMessageBox::critical(this, tr("Vote Failed"),
                    tr("Failed to send private ballot via DM:\n\n%1").arg(message));
                return;
            }

            if (!publishResult.isObject() || !publishResult.exists("ballot_id")) {
                QMessageBox::critical(this, tr("Vote Failed"),
                    tr("Failed to send private ballot: Invalid response from bridge"));
                return;
            }

            ballot_id = QString::fromStdString(publishResult["ballot_id"].get_str());

            LogPrintf("TreasuryPage::onGovNostrVote() Sent private ballot via DM for proposal %s\n",
                      proposal_id.toStdString().c_str());

        } else {
            // Public flow: Publish ballot to bulletin board
            UniValue ballotPayload(UniValue::VOBJ);
            ballotPayload.pushKV("version", 1);
            ballotPayload.pushKV("proposal_id", proposal_id.toStdString());
            ballotPayload.pushKV("asset_id", asset_id.toStdString());
            ballotPayload.pushKV("signed_psbt", signed_psbt.toStdString());
            ballotPayload.pushKV("ballot_units", (int64_t)ballot_units);
            ballotPayload.pushKV("voter_timestamp", (int64_t)QDateTime::currentSecsSinceEpoch());

            UniValue publishParams(UniValue::VARR);
            publishParams.push_back(ballotPayload);

            try {
                publishResult = clientModel->node().executeRpc("cosign.publish_ballot", publishParams, "");
            } catch (const UniValue& objError) {
                QString message;
                try {
                    int code = objError.find_value("code").getInt<int>();
                    std::string detail = objError.find_value("message").get_str();
                    message = tr("RPC Error %1: %2").arg(code).arg(QString::fromStdString(detail));
                } catch (...) {
                    message = QString::fromStdString(objError.write());
                }
                QMessageBox::critical(this, tr("Vote Failed"),
                    tr("Failed to publish ballot to Nostr:\n\n%1").arg(message));
                return;
            }

            if (!publishResult.isObject() || !publishResult.exists("ballot_id")) {
                QMessageBox::critical(this, tr("Vote Failed"),
                    tr("cosign.publish_ballot returned invalid response (missing ballot_id)"));
                return;
            }

            ballot_id = QString::fromStdString(publishResult["ballot_id"].get_str());

            LogPrintf("TreasuryPage::onGovNostrVote() Published public ballot for proposal %s\n",
                      proposal_id.toStdString().c_str());
        }

        // Build UTXO summary for success message
        QString utxoSummary;
        if (utxoArray.size() == 1) {
            QString txid = QString::fromStdString(utxoArray[0]["txid"].get_str());
            int vout = utxoArray[0]["vout"].getInt<int>();
            utxoSummary = QString("%1:%2").arg(txid.left(16) + "...").arg(vout);
        } else {
            utxoSummary = tr("%1 UTXOs selected").arg(utxoArray.size());
        }

        QMessageBox::information(this, tr("Vote Submitted"),
            tr("Your ballot has been signed and published to the bulletin board!\n\n"
               "Proposal ID: %1\n"
               "Ballot ID: %2\n"
               "Voting Units: %3\n"
               "UTXOs: %4\n\n"
               "The issuer can now collect your vote and finalize the rotation if quorum is reached.")
                .arg(proposal_id.left(16) + "...")
                .arg(ballot_id.left(16) + "...")
                .arg(ballot_units)
                .arg(utxoSummary));

    } catch (const UniValue& objError) {
        QString message;
        try {
            int code = objError.find_value("code").getInt<int>();
            std::string detail = objError.find_value("message").get_str();
            message = tr("RPC Error %1: %2").arg(code).arg(QString::fromStdString(detail));
        } catch (...) {
            message = QString::fromStdString(objError.write());
        }
        QMessageBox::critical(this, tr("Vote Failed"),
            tr("Failed to sign ballot:\n\n%1").arg(message));
        return;
    } catch (const std::exception& e) {
        QMessageBox::critical(this, tr("Vote Failed"),
            tr("Failed to sign ballot:\n\n%1").arg(QString::fromStdString(e.what())));
        return;
    }

    // ALSO populate the manual ballot section for reference
    govBallotPSBTEdit->setPlainText(template_psbt);

    if (govHolderProposalSummary) {
        QStringList summary;
        summary << tr("===== PROPOSAL FROM NETWORK =====");
        summary << "";
        summary << tr("Proposal ID: %1").arg(proposal_id);
        summary << tr("Asset: %1").arg(asset_id.left(16) + "...");

        QVariantMap policy = proposal.value("proposed_policy").toMap();
        if (policy.contains("policy_quorum_bps")) {
            int quorum = policy.value("policy_quorum_bps").toInt();
            summary << tr("Quorum: %1 bps (%2%)").arg(quorum).arg(quorum / 100.0, 0, 'f', 2);
        }
        if (policy.contains("issuance_cap_units")) {
            summary << tr("Issuance Cap: %1 units").arg(policy.value("issuance_cap_units").toULongLong());
        }

        // CRITICAL: Automatic verification of ICU payload hash (anti-malleability)
        summary << "";
        summary << tr("===== AUTOMATIC VERIFICATION (ANTI-MALLEABILITY) =====");

        QString icu_text = proposal.value("icu_text").toString();
        QString witness = proposal.value("witness_bundle").toString();
        QString asset_id_str = proposal.value("asset_id").toString();
        QString canonical_hash_claimed = proposal.value("canonical_icu_hash").toString();
        QString witness_hash_claimed = proposal.value("witness_bundle_hash").toString();

        bool verification_passed = false;

        if (!icu_text.isEmpty() && !witness.isEmpty() && clientModel) {
            try {
                // Step 1: Get compression flag from current asset registry
                UniValue icuParams(UniValue::VARR);
                icuParams.push_back(asset_id_str.toStdString());
                UniValue icuInfo = clientModel->node().executeRpc("geticuinfo", icuParams, "");

                int compression = icuInfo.exists("compression") ? icuInfo["compression"].getInt<int>() : 0;
                int visibility = (proposal.value("flow_type").toString() == "public") ? 0 : 1;

                summary << tr("Current Asset Registry:");
                summary << tr("  Compression: %1").arg(compression);
                summary << tr("  Visibility: %1 (%2)").arg(visibility).arg(proposal.value("flow_type").toString());
                summary << "";

                // Step 2: Verify text and witness hashes
                // icu_text is the full normalized canonical text (incl. any inline TSC-ICU-CONTEXT-1
                // block), so the node reproduces the committed canonical_hash by hashing it. A raw SHA256
                // would skip NFC/CRLF (and, for context-bearing docs, the clauses) and never match.
                QString computed_canonical;
                {
                    UniValue wuv;
                    if (!wuv.read(witness.toStdString())) {
                        throw std::runtime_error("Invalid witness bundle JSON in proposal");
                    }
                    UniValue bp(UniValue::VARR);
                    bp.push_back(icu_text.toStdString());
                    bp.push_back(wuv);
                    bp.push_back(visibility);
                    UniValue pr = clientModel->node().executeRpc("buildcanonicalicupayload", bp,
                                                                 walletModel ? walletModel->getWalletName().toStdString() : std::string());
                    computed_canonical = QString::fromStdString(pr["canonical_hash"].get_str());
                }
                QString computed_witness = computeSHA256(witness);

                bool text_hash_ok = (computed_canonical == canonical_hash_claimed);
                bool witness_hash_ok = (computed_witness == witness_hash_claimed);

                summary << tr("Text Hash: %1").arg(text_hash_ok ? tr("✓ VERIFIED") : tr("✗ MISMATCH"));
                summary << tr("Witness Hash: %1").arg(witness_hash_ok ? tr("✓ VERIFIED") : tr("✗ MISMATCH"));

                // Step 2b: Bind the proposal to its template PSBT -- the authoritative transaction voters
                // sign. The proposal's displayed text/witness/visibility/hash MUST equal what the PSBT's
                // committed ICU payload PARSES to. We compare the parsed committed fields, NOT a byte-
                // rebuilt payload: rebuilding via buildcanonicalicupayload without icu_clauses omits the
                // inline-context metadata marker and would spuriously reject honest inline-clause proposals.
                bool psbt_bind_ok = false;
                {
                    const QString tmpl_psbt = proposal.value("template_psbt").toString();
                    PartiallySignedTransaction vpsbt;
                    std::string vperr;
                    if (!tmpl_psbt.isEmpty() && DecodeBase64PSBT(vpsbt, tmpl_psbt.toStdString(), vperr)) {
                        if (auto vmeta = DecodeGovernanceMetadata(vpsbt)) {
                            if (vmeta->has_icu_payload && !vmeta->canonical_text.isEmpty()) {
                                psbt_bind_ok = (vmeta->canonical_text == icu_text) &&
                                               (vmeta->witness_json == witness) &&
                                               (vmeta->committed_icu_visibility == visibility) &&
                                               (vmeta->canonical_hash.isEmpty() || vmeta->canonical_hash == canonical_hash_claimed);
                            } else {
                                psbt_bind_ok = icu_text.isEmpty();  // policy-only PSBT => proposal must claim no ICU text
                            }
                        }
                    }
                }
                summary << tr("PSBT Binding: %1").arg(psbt_bind_ok
                    ? tr("✓ proposal text/witness/visibility match the prepared transaction")
                    : tr("✗ MISMATCH - the proposal differs from what the PSBT commits"));

                // Step 3: the proposal is honest iff its stated hashes are self-consistent AND it is bound
                // to the PSBT (text + witness + visibility).
                if (text_hash_ok && witness_hash_ok && psbt_bind_ok) {
                    summary << "";
                    summary << tr("✓ The proposal faithfully describes the transaction being signed.");
                    verification_passed = true;
                } else {
                    summary << "";
                    summary << tr("✗ VERIFICATION FAILED - Hash mismatch detected!");
                    summary << tr("⚠ DO NOT SIGN THIS BALLOT - Possible tampering!");
                }

            } catch (const std::exception& e) {
                summary << "";
                summary << tr("⚠ Automatic verification failed: %1").arg(QString::fromStdString(e.what()));
                summary << tr("You may need to verify manually via RPC.");
            }
        } else if (icu_text.isEmpty()) {
            // Policy-only rotation: there is no ICU text to hash. The pre-sign gate already bound the
            // proposed quorum/cap to the PSBT, so reaching this summary means it verified.
            verification_passed = true;
            summary << tr("✓ Policy-only rotation - proposed policy verified against the PSBT before signing.");
        } else {
            summary << tr("⚠ Missing data for automatic verification");
        }

        summary << "";
        if (verification_passed) {
            summary << tr("✓✓✓ SAFE TO SIGN - All verifications passed ✓✓✓");
        } else {
            summary << tr("⚠⚠⚠ REVIEW CAREFULLY - Verification incomplete ⚠⚠⚠");
        }

        if (!icu_text.isEmpty()) {
            summary << "";
            summary << tr("Governance Text Preview:");
            QString preview = icu_text.left(200);
            if (icu_text.length() > 200) preview += "...";
            summary << preview;
        }

        summary << "";
        summary << tr("Review full details with 'View Details' button before voting.");

        if (govHolderProposalSummary) {
            QSignalBlocker blocker(govHolderProposalSummary);
            govHolderProposalSummary->setPlainText(summary.join('\n'));
        }
    }

    // Switch to manual flow and focus on ballot section
    QMessageBox::information(this, tr("Vote Ready"),
        tr("The proposal PSBT has been loaded into the ballot section below.\n\n"
           "Select your UTXOs and click 'Cast Ballot' to vote."));
}

void TreasuryPage::onGovNostrDetails()
{
    int row = govNostrProposalsTable->currentRow();
    if (row < 0) {
        QMessageBox::warning(this, tr("No Selection"), tr("Please select a proposal to view details."));
        return;
    }

    QVariantMap proposal = govNostrProposalsTable->item(row, 0)->data(Qt::UserRole).toMap();

    // Create custom dialog with scrollable text areas
    QDialog detailsDialog(this);
    detailsDialog.setWindowTitle(tr("Proposal Details - Full Review"));
    detailsDialog.resize(900, 700);

    QVBoxLayout* layout = new QVBoxLayout(&detailsDialog);

    // Summary section (non-scrollable)
    QString summary;
    summary += tr("<b>Proposal ID:</b> %1<br>").arg(proposal.value("proposal_id").toString());

    QString asset_id = proposal.value("asset_id").toString();
    summary += tr("<b>Asset ID:</b> %1<br>").arg(asset_id);
    summary += tr("<b>Issuer Pubkey:</b> %1<br>").arg(proposal.value("issuer_nostr_pubkey").toString());
    summary += tr("<b>Created:</b> %1<br>").arg(QDateTime::fromSecsSinceEpoch(proposal.value("created_at").toULongLong()).toString());
    summary += tr("<b>Expires:</b> %1<br>").arg(QDateTime::fromSecsSinceEpoch(proposal.value("expires_at").toULongLong()).toString());
    summary += tr("<b>Flow Type:</b> %1<br>").arg(proposal.value("flow_type").toString());

    bool bip322_verified = proposal.value("bip322_verified", false).toBool();
    summary += tr("<b>ICU Ownership Verified:</b> %1<br>")
        .arg(bip322_verified ? tr("✓ Yes (BIP-322)") : tr("⚠ Pending"));

    // Show policy changes with visual diff (current → proposed)
    QVariantMap currentPolicy = proposal.value("current_policy").toMap();
    QVariantMap proposedPolicy = proposal.value("proposed_policy").toMap();

    summary += tr("<br><b>Policy Changes:</b><br>");
    summary += tr("<table style='margin-left: 20px; border-spacing: 10px 5px;'>");

    // Quorum change
    if (proposedPolicy.contains("policy_quorum_bps")) {
        int currentQuorum = currentPolicy.value("policy_quorum_bps").toInt();
        int proposedQuorum = proposedPolicy.value("policy_quorum_bps").toInt();
        QString arrow = (proposedQuorum > currentQuorum) ? "↗" : (proposedQuorum < currentQuorum) ? "↘" : "→";
        QString color = (proposedQuorum > currentQuorum) ? "#d32f2f" : (proposedQuorum < currentQuorum) ? "#388e3c" : "#888";

        summary += tr("<tr><td><b>Quorum:</b></td><td style='color: %4;'>%1 bps (%2%) %5 <b>%3 bps (%6%)</b></td></tr>")
            .arg(currentQuorum)
            .arg(currentQuorum / 100.0, 0, 'f', 2)
            .arg(proposedQuorum)
            .arg(color)
            .arg(arrow)
            .arg(proposedQuorum / 100.0, 0, 'f', 2);
    }

    // Issuance cap change
    if (proposedPolicy.contains("issuance_cap_units")) {
        uint64_t currentCap = currentPolicy.value("issuance_cap_units").toULongLong();
        uint64_t proposedCap = proposedPolicy.value("issuance_cap_units").toULongLong();
        QString arrow = (proposedCap > currentCap) ? "↗" : (proposedCap < currentCap) ? "↘" : "→";
        QString color = (proposedCap > currentCap) ? "#388e3c" : (proposedCap < currentCap) ? "#d32f2f" : "#888";

        summary += tr("<tr><td><b>Issuance Cap:</b></td><td style='color: %4;'>%1 units %5 <b>%2 units</b> (%3% change)</td></tr>")
            .arg(currentCap)
            .arg(proposedCap)
            .arg(currentCap > 0 ? ((double)(proposedCap - currentCap) / currentCap * 100.0) : 0.0, 0, 'f', 1)
            .arg(color)
            .arg(arrow);
    }

    summary += tr("</table>");

    // Show quorum threshold requirement
    if (currentPolicy.contains("policy_quorum_bps")) {
        int quorumBps = currentPolicy.value("policy_quorum_bps").toInt();
        summary += tr("<br><i>Note: This proposal requires %1% of asset holders to vote for it to pass.</i><br>")
            .arg(quorumBps / 100.0, 0, 'f', 2);
    }

    QLabel* summaryLabel = new QLabel(summary);
    summaryLabel->setTextFormat(Qt::RichText);
    summaryLabel->setWordWrap(true);
    layout->addWidget(summaryLabel);

    // Check if this is a private proposal without access
    QString flow_type = proposal.value("flow_type").toString();
    bool isPrivate = (flow_type == "private");
    bool hasTemplatePsbt = proposal.contains("template_psbt") && !proposal.value("template_psbt").toString().isEmpty();

    if (isPrivate && !hasTemplatePsbt) {
        // Private proposal - access not granted yet
        layout->addWidget(new QLabel(tr("<b>⚠ Private Proposal - Access Required</b>")));
        QTextEdit* infoEdit = new QTextEdit();
        infoEdit->setReadOnly(true);
        infoEdit->setPlainText(tr("This is a private governance proposal.\n\n"
                                   "The ICU text and template PSBT are encrypted and only accessible to verified asset holders.\n\n"
                                   "To view the proposal details and vote:\n"
                                   "1. Select this proposal in the table\n"
                                   "2. Click the 'Request Private Access' button below the table\n"
                                   "3. Prove ownership of the asset by signing with a UTXO containing the asset\n"
                                   "4. Once verified, the issuer will send you the encrypted proposal details\n\n"
                                   "After access is granted, refresh this view to see the full proposal."));
        infoEdit->setMinimumHeight(200);
        layout->addWidget(infoEdit);
    } else {
        // Public proposal OR private proposal with access granted
        QString proposed_text = proposal.value("icu_text").toString();
        QString witness_bundle = proposal.value("witness_bundle").toString();
        QString canonical_hash = proposal.value("canonical_icu_hash").toString();

        QString hashVerification;
        if (!canonical_hash.isEmpty() && !proposed_text.isEmpty()) {
            QString computed_hash = computeSHA256(proposed_text);
            bool hash_matches = (computed_hash == canonical_hash);

            hashVerification = tr("Canonical Hash: %1\nComputed Hash: %2\nVerification: %3\n\n")
                .arg(canonical_hash)
                .arg(computed_hash)
                .arg(hash_matches ? tr("✓ VERIFIED") : tr("✗ FAILED - DO NOT VOTE"));
        }

        layout->addWidget(new QLabel(tr("<b>Governance Text (may be 140KB compressed):</b>")));
        QTextEdit* textEdit = new QTextEdit();
        textEdit->setReadOnly(true);
        textEdit->setPlainText(hashVerification + proposed_text);
        textEdit->setMinimumHeight(200);
        textEdit->setFont(QFont("Monospace", 9));
        layout->addWidget(textEdit);

        // Witness bundle section with scrollbar
        if (!witness_bundle.isEmpty()) {
            layout->addWidget(new QLabel(tr("<b>Witness Bundle (JSON):</b>")));
            QTextEdit* witnessEdit = new QTextEdit();
            witnessEdit->setReadOnly(true);
            witnessEdit->setPlainText(witness_bundle);
            witnessEdit->setMinimumHeight(150);
            witnessEdit->setFont(QFont("Monospace", 9));
            layout->addWidget(witnessEdit);
        }
    }

    // Buttons: Save, Copy, Close
    QHBoxLayout* buttonLayout = new QHBoxLayout();

    QPushButton* saveButton = new QPushButton(tr("Save to File"));
    connect(saveButton, &QPushButton::clicked, [&, isPrivate, hasTemplatePsbt, summaryLabel]() {
        QString fileName = QFileDialog::getSaveFileName(&detailsDialog, tr("Save Proposal Details"),
            QString("proposal_%1.txt").arg(proposal.value("proposal_id").toString().left(12)),
            tr("Text Files (*.txt);;All Files (*)"));

        if (!fileName.isEmpty()) {
            QFile file(fileName);
            if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
                QTextStream out(&file);
                out << "===== PROPOSAL DETAILS =====\n\n";
                out << summaryLabel->text().replace("<br>", "\n").replace(QRegularExpression("<[^>]*>"), "") << "\n\n";

                if (isPrivate && !hasTemplatePsbt) {
                    out << "===== PRIVATE PROPOSAL - ACCESS REQUIRED =====\n\n";
                    out << "This is a private governance proposal. Request access to view full details.\n";
                } else {
                    QString proposed_text = proposal.value("icu_text").toString();
                    QString witness_bundle = proposal.value("witness_bundle").toString();
                    out << "===== GOVERNANCE TEXT =====\n\n";
                    out << proposed_text << "\n\n";
                    if (!witness_bundle.isEmpty()) {
                        out << "===== WITNESS BUNDLE =====\n\n";
                        out << witness_bundle << "\n";
                    }
                }
                file.close();
                QMessageBox::information(&detailsDialog, tr("Saved"), tr("Proposal details saved to:\n%1").arg(fileName));
            } else {
                QMessageBox::critical(&detailsDialog, tr("Error"), tr("Could not write to file:\n%1").arg(fileName));
            }
        }
    });
    buttonLayout->addWidget(saveButton);

    QPushButton* copyButton = new QPushButton(tr("Copy All to Clipboard"));
    connect(copyButton, &QPushButton::clicked, [&, isPrivate, hasTemplatePsbt, summaryLabel]() {
        QString fullText;
        fullText += "===== PROPOSAL DETAILS =====\n\n";
        fullText += summaryLabel->text().replace("<br>", "\n").replace(QRegularExpression("<[^>]*>"), "") + "\n\n";

        if (isPrivate && !hasTemplatePsbt) {
            fullText += "===== PRIVATE PROPOSAL - ACCESS REQUIRED =====\n\n";
            fullText += "This is a private governance proposal. Request access to view full details.\n";
        } else {
            QString proposed_text = proposal.value("icu_text").toString();
            QString witness_bundle = proposal.value("witness_bundle").toString();
            fullText += "===== GOVERNANCE TEXT =====\n\n";
            fullText += proposed_text + "\n\n";
            if (!witness_bundle.isEmpty()) {
                fullText += "===== WITNESS BUNDLE =====\n\n";
                fullText += witness_bundle + "\n";
            }
        }

        QClipboard* clipboard = QApplication::clipboard();
        clipboard->setText(fullText);
        QMessageBox::information(&detailsDialog, tr("Copied"), tr("Full proposal details copied to clipboard!"));
    });
    buttonLayout->addWidget(copyButton);

    buttonLayout->addStretch();

    QPushButton* closeButton = new QPushButton(tr("Close"));
    connect(closeButton, &QPushButton::clicked, &detailsDialog, &QDialog::accept);
    buttonLayout->addWidget(closeButton);

    layout->addLayout(buttonLayout);

    detailsDialog.exec();
}

// PR3: Request private proposal access (Holder → Issuer DM)
void TreasuryPage::onGovNostrRequestPrivate()
{
    int row = govNostrProposalsTable->currentRow();
    if (row < 0) {
        QMessageBox::warning(this, tr("No Selection"), tr("Please select a private proposal to request access."));
        return;
    }

    QVariantMap proposal = govNostrProposalsTable->item(row, 0)->data(Qt::UserRole).toMap();
    QString proposal_id = proposal.value("proposal_id").toString();
    QString asset_id = proposal.value("asset_id").toString();
    QString issuer_nostr_pubkey = proposal.value("issuer_nostr_pubkey").toString();
    QString flow_type = proposal.value("flow_type").toString();

    // Verify this is actually a private proposal
    if (flow_type != "private") {
        QMessageBox::warning(this, tr("Not Private"),
            tr("This proposal is not private. Use the regular Vote button instead."));
        return;
    }

    // NOTE: No need to force_refresh - if the proposal is visible in the UI,
    // it's already in the bridge cache (list_governance and request_private_proposal
    // use the same cache). force_refresh is async and doesn't wait for completion.

    // Create dialog for UTXO selection and ownership proof
    QDialog dialog(this);
    dialog.setWindowTitle(tr("Request Private Proposal Access"));
    dialog.resize(800, 500);

    QVBoxLayout* layout = new QVBoxLayout(&dialog);

    layout->addWidget(new QLabel(tr("<b>Request Access to Private Governance Proposal</b>")));
    layout->addWidget(new QLabel(tr("Asset: %1\nProposal ID: %2")
        .arg(asset_id.left(16) + "...")
        .arg(proposal_id.left(16) + "...")));
    layout->addSpacing(10);

    layout->addWidget(new QLabel(tr("You must prove ownership of the asset to request access.\n"
        "Select a UTXO containing the asset units:")));

    // UTXO selection table
    QTableWidget* utxoTable = new QTableWidget();
    utxoTable->setColumnCount(4);
    utxoTable->setHorizontalHeaderLabels({tr("UTXO"), tr("Amount"), tr("Address"), tr("Confirmations")});
    utxoTable->horizontalHeader()->setStretchLastSection(true);
    utxoTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    utxoTable->setSelectionMode(QAbstractItemView::SingleSelection);
    utxoTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    utxoTable->setMinimumHeight(200);

    // Fetch asset UTXOs
    if (walletModel) {
        auto utxos = walletModel->listAssetUTXOs(asset_id);

        // Check if wallet has any UTXOs containing this asset
        if (utxos.isEmpty()) {
            QMessageBox::warning(this, tr("No Asset UTXOs"),
                tr("Your wallet does not contain any UTXOs with this asset.\n\n"
                   "You must hold the asset to request access to private governance proposals.\n\n"
                   "Asset ID: %1").arg(asset_id));
            return;
        }

        utxoTable->setRowCount(utxos.size());

        for (int i = 0; i < utxos.size(); i++) {
            QVariantMap utxo = utxos[i].toMap();
            QString txid = utxo.value("txid").toString();
            int vout = utxo.value("vout").toInt();
            QString address = utxo.value("address").toString();
            uint64_t asset_units = utxo.value("asset_units").toLongLong();
            int confirmations = utxo.value("confirmations").toInt();

            utxoTable->setItem(i, 0, new QTableWidgetItem(QString("%1:%2").arg(txid.left(12) + "...").arg(vout)));
            utxoTable->setItem(i, 1, new QTableWidgetItem(formatAssetAmount(asset_units, 8)));
            utxoTable->setItem(i, 2, new QTableWidgetItem(address));
            utxoTable->setItem(i, 3, new QTableWidgetItem(QString::number(confirmations)));

            // Store full UTXO data
            utxoTable->item(i, 0)->setData(Qt::UserRole, utxo);
        }
    }

    layout->addWidget(utxoTable);

    QTextEdit* statusText = new QTextEdit();
    statusText->setReadOnly(true);
    statusText->setMaximumHeight(100);
    layout->addWidget(statusText);

    // Buttons
    QHBoxLayout* buttonLayout = new QHBoxLayout();
    QPushButton* requestButton = new QPushButton(tr("Request Access"));
    requestButton->setStyleSheet("QPushButton { background-color: #FF9800; color: white; font-weight: bold; }");
    QPushButton* cancelButton = new QPushButton(tr("Cancel"));

    connect(requestButton, &QPushButton::clicked, [&]() {
        int selectedRow = utxoTable->currentRow();
        if (selectedRow < 0) {
            QMessageBox::warning(&dialog, tr("No UTXO Selected"),
                tr("Please select a UTXO to prove ownership."));
            return;
        }

        QVariantMap utxo = utxoTable->item(selectedRow, 0)->data(Qt::UserRole).toMap();
        QString txid = utxo.value("txid").toString();
        int vout = utxo.value("vout").toInt();
        QString address = utxo.value("address").toString();
        uint64_t asset_units = utxo.value("asset_units").toLongLong();

        // Get holder's nostr pubkey from bridge
        QString holder_pubkey = walletModel->getBridgeNostrPubkey();
        if (holder_pubkey.isEmpty()) {
            statusText->append(tr("✗ Failed to get holder nostr pubkey from bridge"));
            QMessageBox::critical(&dialog, tr("Bridge Not Ready"),
                tr("Could not get nostr pubkey from bridge. Make sure the bridge is initialized."));
            return;
        }

        statusText->append(tr("Holder nostr pubkey: %1").arg(holder_pubkey));

        // Generate BIP-322 ownership proof message
        QString message = QString("TENSORCASH_HOLDER:%1:%2")
            .arg(proposal_id)
            .arg(holder_pubkey);

        statusText->append(tr("Generating BIP-322 signature for message:\n%1").arg(message));

        // Sign message with BIP-322
        QString signature = walletModel->signMessageBip322(address, message);
        if (signature.isEmpty()) {
            statusText->append(tr("✗ Failed to generate BIP-322 signature"));
            QMessageBox::critical(&dialog, tr("Signature Failed"),
                tr("Failed to sign the ownership proof message."));
            return;
        }

        statusText->append(tr("✓ Generated signature: %1...").arg(signature.left(32)));

        // Prepare ownership proof
        UniValue ownership_proof(UniValue::VOBJ);
        ownership_proof.pushKV("utxo_ref", QString("%1:%2").arg(txid).arg(vout).toStdString());
        ownership_proof.pushKV("address", address.toStdString());
        ownership_proof.pushKV("message", message.toStdString());
        ownership_proof.pushKV("signature", signature.toStdString());
        ownership_proof.pushKV("asset_units", (int64_t)asset_units);

        // Call RPC: cosign.request_private_proposal
        statusText->append(tr("Sending access request via encrypted DM..."));

        try {
            std::string cmd = "cosign.request_private_proposal";
            UniValue params(UniValue::VARR);
            params.push_back(proposal_id.toStdString());
            params.push_back(asset_id.toStdString());
            params.push_back(issuer_nostr_pubkey.toStdString());
            params.push_back(holder_pubkey.toStdString());
            params.push_back(ownership_proof);

            UniValue result = clientModel->node().executeRpc(cmd, params, "");

            // CRITICAL: Check result fields exist before accessing
            QString session_id;
            QString status;
            QString result_msg;

            if (result.isObject()) {
                if (result.exists("session_id") && result["session_id"].isStr()) {
                    session_id = QString::fromStdString(result["session_id"].get_str());
                }
                if (result.exists("status") && result["status"].isStr()) {
                    status = QString::fromStdString(result["status"].get_str());
                }
                if (result.exists("message") && result["message"].isStr()) {
                    result_msg = QString::fromStdString(result["message"].get_str());
                }
            }

            statusText->append(tr("✓ Request sent successfully!"));
            if (!session_id.isEmpty()) {
                statusText->append(tr("Session ID: %1").arg(session_id));
            }
            if (!status.isEmpty()) {
                statusText->append(tr("Status: %1").arg(status));
            }
            if (!result_msg.isEmpty()) {
                statusText->append(tr("Message: %1").arg(result_msg));
            }

            QMessageBox::information(&dialog, tr("Access Request Sent"),
                tr("Your access request has been sent to the issuer via encrypted DM.\n\n"
                   "The issuer will review your ownership proof and respond with the full proposal details.\n\n"
                   "Session ID: %1").arg(session_id));

            dialog.accept();
        } catch (const UniValue& e) {
            QString error = QString::fromStdString(e.write());
            statusText->append(tr("✗ RPC error: %1").arg(error));
            QMessageBox::critical(&dialog, tr("Request Failed"),
                tr("Failed to send access request:\n%1").arg(error));
        } catch (const std::exception& e) {
            statusText->append(tr("✗ Error: %1").arg(e.what()));
            QMessageBox::critical(&dialog, tr("Request Failed"),
                tr("Failed to send access request:\n%1").arg(e.what()));
        }
    });

    connect(cancelButton, &QPushButton::clicked, &dialog, &QDialog::reject);

    buttonLayout->addWidget(requestButton);
    buttonLayout->addWidget(cancelButton);
    buttonLayout->addStretch();
    layout->addLayout(buttonLayout);

    dialog.exec();
}

void TreasuryPage::onGovNostrPublish()
{
    LogPrintf("TreasuryPage::onGovNostrPublish: FUNCTION CALLED\n");

    if (!walletModel || !clientModel) {
        LogPrintf("TreasuryPage::onGovNostrPublish: walletModel or clientModel is null\n");
        QMessageBox::warning(this, tr("Not Ready"), tr("Wallet or client model not available."));
        return;
    }
    LogPrintf("TreasuryPage::onGovNostrPublish: Models OK\n");

    if (!govPSBTEdit) {
        LogPrintf("TreasuryPage::onGovNostrPublish: govPSBTEdit is null!\n");
        QMessageBox::critical(this, tr("Error"), tr("Internal error: govPSBTEdit is null"));
        return;
    }

    // Get the prepared PSBT from issuer section
    QString psbt = govPSBTEdit->toPlainText().trimmed();
    LogPrintf("TreasuryPage::onGovNostrPublish: Got PSBT, length=%d\n", psbt.length());

    if (psbt.isEmpty()) {
        QMessageBox::warning(this, tr("No PSBT"),
            tr("Please prepare a rotation PSBT first using the 'Prepare Rotation' section below."));
        return;
    }

    if (!govAssetCombo) {
        LogPrintf("TreasuryPage::onGovNostrPublish: govAssetCombo is null!\n");
        QMessageBox::critical(this, tr("Error"), tr("Internal error: govAssetCombo is null"));
        return;
    }

    // Get selected asset
    QString assetId = govAssetCombo->currentData().toString();
    LogPrintf("TreasuryPage::onGovNostrPublish: Asset ID=%s\n", assetId.toStdString().c_str());
    if (assetId.isEmpty()) {
        QMessageBox::warning(this, tr("No Asset"), tr("Please select an asset first."));
        return;
    }

    if (!govICUTextEdit || !govWitnessTextEdit || !govICUVisibilityCombo) {
        LogPrintf("TreasuryPage::onGovNostrPublish: One of the text widgets is null!\n");
        QMessageBox::critical(this, tr("Error"), tr("Internal error: UI widgets not initialized"));
        return;
    }

    // Get optional governance text fields
    QString icu_text = govICUTextEdit->toPlainText().trimmed();
    QString witness_bundle = govWitnessTextEdit->toPlainText().trimmed();
    QString visibility = govICUVisibilityCombo->currentData().toString();
    LogPrintf("TreasuryPage::onGovNostrPublish: ICU text length=%d, witness length=%d, visibility=%s\n",
              icu_text.length(), witness_bundle.length(), visibility.toStdString().c_str());

    // Note: ICU text is optional for rotations - if unchanged, no need to republish

    // Auto-wrap witness text into JSON bundle if needed (identical to registration flow)
    QString witness_bundle_json;
    try {
        LogPrintf("TreasuryPage::onGovNostrPublish: Building witness bundle JSON...\n");
        if (witness_bundle.isEmpty()) {
            LogPrintf("TreasuryPage::onGovNostrPublish: Witness bundle is empty, creating minimal bundle\n");
            // Empty witness - minimal bundle with placeholder (identical to registration)
            QJsonObject witnessObj;
            witnessObj["version"] = "1.0";
            witnessObj["timestamp"] = QDateTime::currentSecsSinceEpoch();
            witnessObj["canonical_hash"] = "placeholder";  // Backend will replace with actual hash
            witness_bundle_json = QString::fromUtf8(QJsonDocument(witnessObj).toJson(QJsonDocument::Compact));
            LogPrintf("TreasuryPage::onGovNostrPublish: Created empty witness bundle: %s\n", witness_bundle_json.toStdString());
        } else {
            LogPrintf("TreasuryPage::onGovNostrPublish: Witness bundle has content, checking if JSON...\n");
            // Check if it's already valid JSON
            QJsonParseError parseError{};
            QJsonDocument doc = QJsonDocument::fromJson(witness_bundle.toUtf8(), &parseError);

            if (parseError.error == QJsonParseError::NoError && doc.isObject()) {
                // Already valid JSON - use as-is
                witness_bundle_json = witness_bundle;
                LogPrintf("TreasuryPage::onGovNostrPublish: Witness bundle is valid JSON\n");
            } else {
                LogPrintf("TreasuryPage::onGovNostrPublish: Witness bundle is plain text, wrapping...\n");
                // Plain text - auto-wrap into witness bundle (identical to registration flow)
                QJsonObject witnessObj;
                witnessObj["version"] = "1.0";
                witnessObj["timestamp"] = QDateTime::currentSecsSinceEpoch();
                witnessObj["canonical_hash"] = "placeholder";  // Backend will replace with actual hash
                witnessObj["witness_text"] = witness_bundle;
                witness_bundle_json = QString::fromUtf8(QJsonDocument(witnessObj).toJson(QJsonDocument::Compact));
                LogPrintf("TreasuryPage::onGovNostrPublish: Wrapped witness bundle\n");

                govStatusText->append(tr("Auto-wrapped witness text into JSON bundle"));
            }
        }
    } catch (const std::exception& e) {
        LogPrintf("TreasuryPage::onGovNostrPublish: EXCEPTION in witness bundle creation: %s\n", e.what());
        QMessageBox::critical(this, tr("Publish Failed"), tr("Failed to create witness bundle: %1").arg(e.what()));
        return;
    } catch (...) {
        LogPrintf("TreasuryPage::onGovNostrPublish: UNKNOWN EXCEPTION in witness bundle creation\n");
        QMessageBox::critical(this, tr("Publish Failed"), tr("Failed to create witness bundle: Unknown exception"));
        return;
    }

    try {
        LogPrintf("TreasuryPage::onGovNostrPublish: Starting publish...\n");
        govStatusText->append(tr("[DEBUG] Starting publish..."));

        // Ensure wallet is unlocked before signing attestation
        WalletModel::UnlockContext ctx(walletModel->requestUnlock());
        if (!ctx.isValid()) {
            govStatusText->append(tr("[ERROR] Wallet unlock required to sign attestation"));
            QMessageBox::warning(this, tr("Wallet Locked"),
                                 tr("Please unlock the wallet to sign the governance attestation."));
            return;
        }

        // Fetch current asset policy to extract ICU info
        LogPrintf("TreasuryPage::onGovNostrPublish: Fetching asset policy...\n");
        govStatusText->append(tr("[DEBUG] Fetching asset policy..."));
        UniValue policyParams(UniValue::VARR);
        policyParams.push_back(assetId.toStdString());
        UniValue policyResult = clientModel->node().executeRpc("getassetpolicy", policyParams, "");
        LogPrintf("TreasuryPage::onGovNostrPublish: Got asset policy, parsing...\n");
        govStatusText->append(tr("[DEBUG] Got asset policy"));

        if (!policyResult.isObject()) {
            throw std::runtime_error("Failed to fetch asset policy");
        }

        // Validate all required fields exist
        if (!policyResult.exists("icu_txid")) {
            throw std::runtime_error("Asset policy missing icu_txid");
        }
        if (!policyResult.exists("icu_vout")) {
            throw std::runtime_error("Asset policy missing icu_vout");
        }
        if (!policyResult.exists("policy_quorum_bps")) {
            throw std::runtime_error("Asset policy missing policy_quorum_bps");
        }
        if (!policyResult.exists("issuance_cap_units")) {
            throw std::runtime_error("Asset policy missing issuance_cap_units");
        }
        if (!policyResult.exists("policy_epoch")) {
            throw std::runtime_error("Asset policy missing policy_epoch");
        }

        QString icuTxid = QString::fromStdString(policyResult["icu_txid"].get_str());
        int icuVout = policyResult["icu_vout"].getInt<int>();
        uint64_t currentQuorum = policyResult["policy_quorum_bps"].getInt<uint64_t>();
        uint64_t currentCap = policyResult["issuance_cap_units"].getInt<uint64_t>();
        uint32_t currentEpoch = policyResult["policy_epoch"].getInt<uint32_t>();
        LogPrintf("TreasuryPage::onGovNostrPublish: Policy fields extracted: txid=%s, vout=%d\n",
                  icuTxid.toStdString().c_str(), icuVout);

        // Get ICU address for BIP-322 attestation
        LogPrintf("TreasuryPage::onGovNostrPublish: Fetching ICU UTXO via gettxout...\n");
        QString icuAddress;
        try {
            UniValue txoutParams(UniValue::VARR);
            txoutParams.push_back(icuTxid.toStdString());
            txoutParams.push_back(icuVout);
            UniValue txoutResult = clientModel->node().executeRpc("gettxout", txoutParams, "");
            LogPrintf("TreasuryPage::onGovNostrPublish: gettxout returned\n");

            if (txoutResult.isObject() && txoutResult.exists("scriptPubKey") && txoutResult["scriptPubKey"].isObject()) {
                const UniValue& scriptPubKey = txoutResult["scriptPubKey"];
                if (scriptPubKey.exists("address")) {
                    icuAddress = QString::fromStdString(scriptPubKey["address"].get_str());
                } else if (scriptPubKey.exists("addresses") && scriptPubKey["addresses"].isArray() && scriptPubKey["addresses"].size() > 0) {
                    icuAddress = QString::fromStdString(scriptPubKey["addresses"][0].get_str());
                }
            }
        } catch (const UniValue& e) {
            LogPrintf("TreasuryPage::onGovNostrPublish: gettxout RPC threw error: %s\n", e.write());
            govStatusText->append(tr("[DEBUG] gettxout failed: %1").arg(QString::fromStdString(e.write())));
        } catch (const std::exception& e) {
            LogPrintf("TreasuryPage::onGovNostrPublish: gettxout threw std::exception: %s\n", e.what());
            govStatusText->append(tr("[DEBUG] gettxout exception: %1").arg(e.what()));
        }

        if (icuAddress.isEmpty()) {
            LogPrintf("TreasuryPage::onGovNostrPublish: Falling back to gettransaction for ICU address\n");
            govStatusText->append(tr("[DEBUG] Falling back to gettransaction for ICU address"));

            UniValue gettxParams(UniValue::VARR);
            gettxParams.push_back(icuTxid.toStdString());
            UniValue txResult = clientModel->node().executeRpc("gettransaction", gettxParams,
                                                               walletModel->getWalletName().toStdString());

            if (!txResult.isObject() || !txResult.exists("details") || !txResult["details"].isArray()) {
                throw std::runtime_error("Failed to fetch ICU transaction (gettransaction)");
            }

            const UniValue& details = txResult["details"];
            for (size_t i = 0; i < details.size(); ++i) {
                const UniValue& detail = details[i];
                if (detail.exists("vout") && detail["vout"].getInt<int>() == icuVout && detail.exists("address")) {
                    icuAddress = QString::fromStdString(detail["address"].get_str());
                    break;
                }
            }

            if (icuAddress.isEmpty()) {
                throw std::runtime_error("ICU address not found in gettransaction details");
            }
        }

        govStatusText->append(tr("[DEBUG] ICU address: %1").arg(icuAddress.left(16) + "..."));

        // Generate proposal ID: SHA256(asset_id || created_at || nonce)
        // Hash raw UTF-8 bytes, not hex-decoded (avoids fromHex quirks with non-hex chars)
        uint64_t created_at = QDateTime::currentSecsSinceEpoch();
        uint32_t nonce = QRandomGenerator::global()->generate();

        QByteArray preimage_bytes;
        preimage_bytes.append(assetId.toUtf8());
        preimage_bytes.append(reinterpret_cast<const char*>(&created_at), sizeof(created_at));
        preimage_bytes.append(reinterpret_cast<const char*>(&nonce), sizeof(nonce));

        QByteArray proposal_id_hash = QCryptographicHash::hash(preimage_bytes, QCryptographicHash::Sha256);
        QString proposal_id = QString::fromLatin1(proposal_id_hash.toHex());

        // Sign BIP-322 attestation message
        QString attestation_message = QString("TENSORCASH_GOVERNANCE:%1").arg(proposal_id);

        UniValue signParams(UniValue::VARR);
        signParams.push_back(icuAddress.toStdString());
        signParams.push_back(attestation_message.toStdString());
        UniValue signResult = clientModel->node().executeRpc("signmessagebip322", signParams,
                                                             walletModel->getWalletName().toStdString());

        if (!signResult.isStr()) {
            throw std::runtime_error("Failed to sign BIP-322 attestation");
        }

        QString bip322_signature = QString::fromStdString(signResult.get_str());
        govStatusText->append(tr("[DEBUG] BIP-322 signature created"));

        // Get issuer Nostr pubkey from bulletin board.
        // Route through WalletModel::bulletinBoardInit (NOT a raw cosign.init_bb
        // with empty params): that path resolves an app-scoped, per-wallet nostr
        // key path under AppDataLocation. A raw init_bb with no nostr_key_path
        // makes the Rust bridge fall back to the SHARED ~/.tensorcash/nostr_keys,
        // and since init_bb is idempotent per network the first (unsafe) init
        // would stick. Keep this on the safe path.
        govStatusText->append(tr("[DEBUG] Getting Nostr pubkey..."));
        if (!walletModel) {
            throw std::runtime_error("No wallet loaded for bulletin board init");
        }
        // Pass the SAME default relay set the trade-board / models pages use
        // (tradeboardtab.cpp / modelspage.cpp). init_bb is idempotent per
        // network — the first caller's relays stick — so every entry point must
        // use the same list or the bulletin board's relays become call-order
        // dependent. (An empty list here would make bulletinBoardInit omit the
        // key and fall back to the bridge's own slightly different defaults.)
        QStringList defaultRelays = {
            "wss://relay.damus.io",
            "wss://nos.lol",
            "wss://relay.snort.social"
        };
        WalletModel::BulletinBoardInitResult bbInit = walletModel->bulletinBoardInit(defaultRelays);
        if (!bbInit.success || bbInit.pubkey.isEmpty()) {
            throw std::runtime_error(QString("Failed to get Nostr pubkey from bulletin board: %1")
                .arg(bbInit.error.isEmpty() ? QStringLiteral("no pubkey returned") : bbInit.error)
                .toStdString());
        }
        QString issuerNostrPubkey = bbInit.pubkey;
        govStatusText->append(tr("[DEBUG] Got pubkey: %1").arg(issuerNostrPubkey.left(16) + "..."));

        // Build proposal JSON
        govStatusText->append(tr("[DEBUG] Building proposal object..."));
        UniValue proposal(UniValue::VOBJ);
        proposal.pushKV("version", 1);
        proposal.pushKV("proposal_id", proposal_id.toStdString());
        proposal.pushKV("asset_id", assetId.toStdString());
        proposal.pushKV("issuer_nostr_pubkey", issuerNostrPubkey.toStdString());
        proposal.pushKV("icu_txid", icuTxid.toStdString());
        proposal.pushKV("icu_vout", icuVout);
        proposal.pushKV("created_at", created_at);

        // ICU attestation
        UniValue attestation(UniValue::VOBJ);
        attestation.pushKV("address", icuAddress.toStdString());
        attestation.pushKV("message", attestation_message.toStdString());
        attestation.pushKV("signature", bip322_signature.toStdString());
        proposal.pushKV("icu_attestation", attestation);

        // Current policy
        // Decode the prepared PSBT ONCE -- it is the authoritative source of truth for the ICU text,
        // witness, visibility, quorum and cap. Everything published below is derived from it, NOT from the
        // editable UI fields, so a post-Prepare edit can't make the proposal describe something the PSBT
        // (the transaction voters sign) does not commit. To change anything, the issuer re-runs Prepare.
        GovernanceProposalDetails psbtMeta;
        {
            PartiallySignedTransaction psbtx_meta;
            std::string psbt_decode_err;
            if (!DecodeBase64PSBT(psbtx_meta, psbt.toStdString(), psbt_decode_err)) {
                throw std::runtime_error("Failed to decode the prepared PSBT: " + psbt_decode_err);
            }
            auto m = DecodeGovernanceMetadata(psbtx_meta);
            if (!m) {
                throw std::runtime_error("The prepared PSBT is not a governance-rotation PSBT. Re-run Prepare Rotation.");
            }
            psbtMeta = *m;
        }

        UniValue current_policy(UniValue::VOBJ);
        current_policy.pushKV("policy_quorum_bps", currentQuorum);
        current_policy.pushKV("issuance_cap_units", currentCap);
        current_policy.pushKV("policy_epoch", currentEpoch);
        proposal.pushKV("current_policy", current_policy);

        // Proposed policy changes -- taken from the PSBT's committed IssuerReg, NOT the live spinboxes,
        // so they describe exactly what the prepared transaction commits (a post-Prepare spinbox change
        // can't diverge from the PSBT).
        UniValue proposed_policy(UniValue::VOBJ);
        if (psbtMeta.committed_quorum_bps != currentQuorum) {
            proposed_policy.pushKV("policy_quorum_bps", (int)psbtMeta.committed_quorum_bps);
        }
        if (psbtMeta.committed_cap_units != currentCap) {
            proposed_policy.pushKV("issuance_cap_units", psbtMeta.committed_cap_units);
        }
        proposal.pushKV("proposed_policy", proposed_policy);

        // Template PSBT and hash
        QByteArray psbt_bytes = psbt.toUtf8();
        QByteArray psbt_hash = QCryptographicHash::hash(psbt_bytes, QCryptographicHash::Sha256);
        proposal.pushKV("template_psbt_hash", QString::fromLatin1(psbt_hash.toHex()).toStdString());

        // Expiry (default: 30 days from now)
        uint64_t expires_at = created_at + (30 * 24 * 3600);
        proposal.pushKV("expires_at", expires_at);

        // Flow type from the PSBT's COMMITTED visibility, not the live UI combo. The bridge's
        // privacy/sanitization depends on this, so an issuer must not be able to prepare holder-only
        // text and then flip the UI to "public" before publishing.
        if (psbtMeta.committed_icu_visibility == 0) {
            proposal.pushKV("flow_type", "public");  // lowercase to match Rust serde
        } else {
            proposal.pushKV("flow_type", "private");  // lowercase to match Rust serde
        }

        // Bind the published ICU fields to the PSBT (decoded once above as psbtMeta). For an ICU-text
        // rotation we take the exact committed canonical text + witness + hash, so a post-Prepare edit to
        // the text/clauses/witness can never make the proposal describe a different document than the PSBT
        // commits. For a policy-only rotation the PSBT carries no ICU payload -- there is simply no text to
        // publish (the witness from the UI is kept only as optional evidence).
        QString icu_hash;
        if (psbtMeta.has_icu_payload && !psbtMeta.canonical_text.isEmpty()) {
            icu_text = psbtMeta.canonical_text;          // full normalized text incl. the inline clause block
            witness_bundle_json = psbtMeta.witness_json; // the committed witness bundle (exact bytes)
            icu_hash = psbtMeta.canonical_hash;          // canonical_hash committed in the PSBT
            if (icu_hash.isEmpty()) {
                // Defensive fallback: recompute from the committed text via the node (NFC/CRLF-correct).
                UniValue wuv; wuv.read(witness_bundle_json.toStdString());
                UniValue bp(UniValue::VARR);
                bp.push_back(icu_text.toStdString());
                bp.push_back(wuv);
                bp.push_back((int)psbtMeta.committed_icu_visibility);
                UniValue pr = clientModel->node().executeRpc("buildcanonicalicupayload", bp,
                                                             walletModel->getWalletName().toStdString());
                icu_hash = QString::fromStdString(pr["canonical_hash"].get_str());
            }
            govStatusText->append(tr("[INFO] Publishing the ICU payload committed in the prepared PSBT "
                                     "(edits made after Prepare are NOT published -- re-Prepare to change them)."));
        } else {
            icu_text.clear();   // policy-only rotation: no ICU text change
            icu_hash.clear();
            govStatusText->append(tr("[INFO] Policy-only rotation (no ICU text change in the PSBT)."));
        }

        // witness_bundle_json is the EXACT witness bytes committed in the PSBT payload (from
        // DecodeGovernanceMetadata) -- do NOT parse/reserialize it. Reserializing via UniValue reorders
        // keys and would emit bytes different from what the PSBT commits (and from icu_ctxt_commit). The
        // committed witness already carries the real canonical_hash, so there is no placeholder to fix.
        QString witness_hash = computeSHA256(witness_bundle_json);

        // Always provide full payload to the bridge. The Rust side caches and sanitizes
        // private proposals before broadcasting to Nostr, so we can safely include the
        // sensitive fields here even for private flows.
        proposal.pushKV("icu_text", icu_text.toStdString());
        proposal.pushKV("canonical_icu_hash", icu_hash.toStdString());
        proposal.pushKV("witness_bundle", witness_bundle_json.toStdString());
        proposal.pushKV("witness_bundle_hash", witness_hash.toStdString());
        proposal.pushKV("template_psbt", psbt.toStdString());

        // CRITICAL: Include compression flag so holder can rebuild ICU payload
        // NOTE: Currently governance doesn't use compression (always 0)
        // but this field is needed for holder to call buildcanonicalicupayload correctly
        proposal.pushKV("icu_compression", 0);

        // Metadata (optional)
        UniValue metadata(UniValue::VOBJ);
        metadata.pushKV("title", tr("Governance Rotation for %1").arg(assetId.left(8) + "...").toStdString());
        proposal.pushKV("metadata", metadata);

        // Call cosign.publish_governance RPC
        govStatusText->append(tr("[DEBUG] Preparing to call RPC..."));
        UniValue publishParams(UniValue::VARR);
        publishParams.push_back(proposal);

        govStatusText->append(tr("\n=== Publishing to Network ==="));
        govStatusText->append(tr("Proposal ID: %1").arg(proposal_id));
        govStatusText->append(tr("[DEBUG] Calling cosign.publish_governance..."));

        UniValue publishResult = clientModel->node().executeRpc("cosign.publish_governance",
                                                                publishParams, "");
        govStatusText->append(tr("[DEBUG] RPC returned"));

        if (!publishResult.isObject() || !publishResult.exists("proposal_id")) {
            throw std::runtime_error("Publish failed or returned invalid response");
        }

        QString published_id = QString::fromStdString(publishResult["proposal_id"].get_str());

        govStatusText->append(tr("✓ Successfully published to network"));
        govStatusText->append(tr("Published Proposal ID: %1").arg(published_id));

        QMessageBox::information(this, tr("Published"),
            tr("Governance proposal has been published to the network!\n\nProposal ID: %1\n\n"
               "Holders can now discover and vote on this proposal from the Treasury page.")
               .arg(published_id));

        // Refresh the proposals list to show the newly published proposal
        onGovNostrRefresh();

    } catch (const UniValue& objError) {
        QString message;
        try {
            int code = objError.find_value("code").getInt<int>();
            std::string detail = objError.find_value("message").get_str();
            message = tr("RPC Error %1: %2").arg(code).arg(QString::fromStdString(detail));
        } catch (...) {
            message = QString::fromStdString(objError.write());
        }
        if (govStatusText) {
            govStatusText->append(tr("✗ Failed to publish: %1").arg(message));
        }
        QMessageBox::critical(this, tr("Publish Failed"), tr("Failed to publish proposal:\n\n%1").arg(message));
    } catch (const std::exception& e) {
        QString error = QString::fromStdString(e.what());
        if (govStatusText) {
            govStatusText->append(tr("✗ Failed to publish: %1").arg(error));
        }
        QMessageBox::critical(this, tr("Publish Failed"), tr("Failed to publish proposal:\n\n%1").arg(error));
    } catch (...) {
        if (govStatusText) {
            govStatusText->append(tr("✗ Failed to publish: Unknown exception"));
        }
        QMessageBox::critical(this, tr("Publish Failed"), tr("Failed to publish proposal: Unknown exception"));
    }
}

void TreasuryPage::onGovNostrPollTimer()
{
    // Smart auto-refresh: Called every 60s when Governance tab is visible
    if (!walletModel || !govBBInitialized) {
        updateGovBulletinBoardStatus();
        return;
    }

    // Perform full refresh to check for new proposals
    onGovNostrRefresh();
}

void TreasuryPage::onTabChanged(int index)
{
    if (!tabWidget) return;

    // Get the governance tab index by checking tab text
    int governanceTabIndex = -1;
    for (int i = 0; i < tabWidget->count(); ++i) {
        if (tabWidget->tabText(i) == tr("Governance")) {
            governanceTabIndex = i;
            break;
        }
    }

    if (governanceTabIndex < 0) return;

    // Start/stop polling based on whether Governance tab is visible
    if (index == governanceTabIndex) {
        // Governance tab became visible
        LogPrintf("TreasuryPage: Governance tab became visible - starting auto-refresh timer\n");
        if (govNostrPollTimer && !govNostrPollTimer->isActive()) {
            govNostrPollTimer->start();
            // Do an immediate refresh when tab becomes visible
            QTimer::singleShot(100, this, &TreasuryPage::onGovNostrRefresh);
        }
    } else {
        // Governance tab became hidden
        if (govNostrPollTimer && govNostrPollTimer->isActive()) {
            LogPrintf("TreasuryPage: Governance tab became hidden - stopping auto-refresh timer\n");
            govNostrPollTimer->stop();
        }
    }
}

void TreasuryPage::updateGovBulletinBoardStatus()
{
    if (!walletModel) return;

    // Check if bulletin board is initialized by attempting to list governance proposals
    auto result = walletModel->governanceListProposals("", false);

    if (result.success) {
        if (!govBBInitialized) {
            LogPrintf("TreasuryPage: Bulletin board now INITIALIZED\n");
        }
        govBBInitialized = true;
        govBBStatusLabel->setText(tr("● Connected"));
        govBBStatusLabel->setStyleSheet("QLabel { color: #388e3c; font-weight: bold; }");
    } else {
        if (govBBInitialized) {
            LogPrintf("TreasuryPage: Bulletin board became UNINITIALIZED! Error: %s\n",
                      result.error.toStdString().c_str());
        }
        govBBInitialized = false;
        govBBStatusLabel->setText(tr("● Not Initialized (init in Exchange P2P tab)"));
        govBBStatusLabel->setStyleSheet("QLabel { color: #d32f2f; font-weight: bold; }");
    }
}

// ===== DISTRIBUTION TAB SLOT IMPLEMENTATIONS =====

void TreasuryPage::onDistTargetAssetSelected(int index)
{
    if (!walletModel || !clientModel || index < 0) return;

    QString assetId = distTargetAssetCombo->itemData(index).toString();
    if (assetId.isEmpty()) return;

    // Get asset registry info via RPC
    try {
        UniValue params(UniValue::VARR);
        params.push_back(assetId.toStdString());
        UniValue policy = clientModel->node().executeRpc("getassetpolicy", params, "");

        if (!policy.isNull()) {
            QString ticker = QString::fromStdString(policy["ticker"].get_str());
            int decimals = policy["decimals"].getInt<int>();
            uint64_t issued_total = policy["issued_total"].getInt<uint64_t>();
            uint64_t burned_total = policy["burned_total"].getInt<uint64_t>();

            distTargetAssetInfoLabel->setText(QString("Ticker: %1 | Decimals: %2")
                .arg(ticker)
                .arg(decimals));

            uint64_t settled_supply = issued_total > burned_total ?
                issued_total - burned_total : 0;
            distSettledSupplyLabel->setText(formatAssetAmount(settled_supply, decimals));
        }
    } catch (const std::exception& e) {
        distTargetAssetInfoLabel->setText(tr("Could not load asset info"));
        distSettledSupplyLabel->setText(tr("N/A"));
    }

    distributionPreviewReady = false;
    distExecuteButton->setEnabled(false);
    distPreviewTable->setRowCount(0);
    distSummaryLabel->setVisible(false);
}

void TreasuryPage::onDistAssetSelected(int index)
{
    if (!walletModel || index < 0) return;

    QString assetData = distAssetCombo->itemData(index).toString();

    if (assetData == "TSC") {
        // TSC balance
        CAmount balance = walletModel->wallet().getBalance();
        distAssetBalanceLabel->setText(QString("Balance: %1 TSC").arg(BitcoinUnits::format(
            walletModel->getOptionsModel()->getDisplayUnit(), balance)));
    } else {
        // Asset balance
        auto balances = walletModel->getAssetBalances();
        for (const auto& bal : balances) {
            if (QString::fromStdString(bal.asset_id.ToString()) == assetData) {
                distAssetBalanceLabel->setText(QString("Balance: %1 units").arg(bal.balance));
                return;
            }
        }
        distAssetBalanceLabel->setText(tr("Balance: 0"));
    }
}

void TreasuryPage::onDistAmountChanged()
{
    // Clear preview when amount changes
    distributionPreviewReady = false;
    distExecuteButton->setEnabled(false);
}

void TreasuryPage::onDistPreview()
{
    if (!walletModel || !clientModel) return;

    QString targetAssetId = distTargetAssetCombo->currentData().toString();
    QString distAssetData = distAssetCombo->currentData().toString();
    QString amountStr = distAmountEdit->text();

    if (targetAssetId.isEmpty() || amountStr.isEmpty()) {
        QMessageBox::warning(this, tr("Invalid Input"),
            tr("Please select a target asset and enter an amount."));
        return;
    }

    distStatusText->clear();
    distProgressBar->setVisible(true);
    distProgressBar->setValue(0);
    distPreviewButton->setEnabled(false);
    distPreviewTable->setRowCount(0);

    // Build RPC parameters
    UniValue options(UniValue::VOBJ);
    options.pushKV("distribution_asset", distAssetData.toStdString());
    options.pushKV("dry_run", true);
    options.pushKV("min_dust_threshold", distMinDustSpinBox->value());
    options.pushKV("max_recipients", distMaxRecipientsSpinBox->value());
    if (distSnapshotEnableCheckBox->isChecked()) {
        options.pushKV("snapshot_height", distSnapshotHeightSpinBox->value());
    }

    UniValue params(UniValue::VARR);
    params.push_back(targetAssetId.toStdString());
    params.push_back(amountStr.toStdString());
    params.push_back(options);

    // Call distributeasset RPC
    UniValue result;
    try {
        result = clientModel->node().executeRpc("distributeasset", params,
            walletModel->getWalletName().toStdString());
    } catch (UniValue& objError) {
        distProgressBar->setVisible(false);
        distPreviewButton->setEnabled(true);

        QString message;
        try {
            int code = objError.find_value("code").getInt<int>();
            std::string detail = objError.find_value("message").get_str();
            message = tr("RPC Error %1: %2").arg(code).arg(QString::fromStdString(detail));
        } catch (...) {
            message = QString::fromStdString(objError.write());
        }

        distStatusText->setPlainText(message);
        QMessageBox::critical(this, tr("Distribution Error"), message);
        return;
    } catch (const std::exception& e) {
        distProgressBar->setVisible(false);
        distPreviewButton->setEnabled(true);
        distStatusText->setPlainText(QString("Error: %1").arg(e.what()));
        QMessageBox::critical(this, tr("Distribution Error"), QString::fromStdString(e.what()));
        return;
    }

    distProgressBar->setVisible(false);
    distPreviewButton->setEnabled(true);

    // Parse result
    uint64_t total_distributed = result["total_distributed"].getInt<uint64_t>();
    uint64_t remainder = result["remainder"].getInt<uint64_t>();
    int recipient_count = result["recipient_count"].getInt<int>();
    int filtered_count = result["filtered_count"].getInt<int>();
    int utxos_scanned = result["utxos_scanned"].getInt<int>();

    // Update summary
    QString summary = QString(
        "✓ Preview Complete\n"
        "• UTXOs Scanned: %1\n"
        "• Recipients: %2 (%3 filtered by dust)\n"
        "• Total Distributed: %4\n"
        "• Remainder: %5")
        .arg(utxos_scanned)
        .arg(recipient_count)
        .arg(filtered_count)
        .arg(total_distributed)
        .arg(remainder);

    distSummaryLabel->setText(summary);
    distSummaryLabel->setVisible(true);

    // Populate table
    const UniValue& recipients = result["recipients"];
    distPreviewTable->setRowCount(recipients.size());
    distPreviewTable->setSortingEnabled(false);

    for (size_t i = 0; i < recipients.size(); ++i) {
        const UniValue& rec = recipients[i];
        QString address = QString::fromStdString(rec["address"].get_str());
        uint64_t holdings = rec["holdings"].getInt<uint64_t>();
        uint64_t amount = rec["amount"].getInt<uint64_t>();

        distPreviewTable->setItem(i, 0, new QTableWidgetItem(address));
        distPreviewTable->setItem(i, 1, new QTableWidgetItem(QString::number(holdings)));
        distPreviewTable->setItem(i, 2, new QTableWidgetItem(QString::number(amount)));
    }

    distPreviewTable->setSortingEnabled(true);
    distPreviewTable->sortByColumn(2, Qt::DescendingOrder);

    // Store result for execution
    lastDistributionResult = QString::fromStdString(result.write(2));
    distributionPreviewReady = true;
    distExecuteButton->setEnabled(true);

    distStatusText->setPlainText(tr("Preview ready. Click 'Execute Distribution' to broadcast."));
}

void TreasuryPage::onDistExecute()
{
    if (!walletModel || !clientModel || !distributionPreviewReady) return;

    // Confirmation dialog
    QMessageBox::StandardButton reply = QMessageBox::question(this,
        tr("Confirm Distribution"),
        tr("This will create and broadcast a distribution transaction.\n\n"
           "Do you want to proceed?"),
        QMessageBox::Yes | QMessageBox::No);

    if (reply != QMessageBox::Yes) return;

    QString targetAssetId = distTargetAssetCombo->currentData().toString();
    QString distAssetData = distAssetCombo->currentData().toString();
    QString amountStr = distAmountEdit->text();

    distStatusText->clear();
    distExecuteButton->setEnabled(false);
    distPreviewButton->setEnabled(false);

    // Build RPC parameters
    UniValue options(UniValue::VOBJ);
    options.pushKV("distribution_asset", distAssetData.toStdString());
    options.pushKV("dry_run", false);  // Actually broadcast
    options.pushKV("min_dust_threshold", distMinDustSpinBox->value());
    options.pushKV("max_recipients", distMaxRecipientsSpinBox->value());
    if (distSnapshotEnableCheckBox->isChecked()) {
        options.pushKV("snapshot_height", distSnapshotHeightSpinBox->value());
    }

    UniValue params(UniValue::VARR);
    params.push_back(targetAssetId.toStdString());
    params.push_back(amountStr.toStdString());
    params.push_back(options);

    // Ensure wallet is unlocked before executing distribution (creates and signs transactions)
    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if (!ctx.isValid()) {
        distStatusText->setPlainText(tr("Wallet unlock required to execute distribution."));
        QMessageBox::warning(this, tr("Wallet Locked"),
                             tr("Please unlock the wallet to execute the distribution transaction."));
        distExecuteButton->setEnabled(true);
        distPreviewButton->setEnabled(true);
        return;
    }

    // Call distributeasset RPC
    UniValue result;
    try {
        result = clientModel->node().executeRpc("distributeasset", params,
            walletModel->getWalletName().toStdString());
    } catch (UniValue& objError) {
        distExecuteButton->setEnabled(true);
        distPreviewButton->setEnabled(true);

        QString message;
        try {
            int code = objError.find_value("code").getInt<int>();
            std::string detail = objError.find_value("message").get_str();
            message = tr("RPC Error %1: %2").arg(code).arg(QString::fromStdString(detail));
        } catch (...) {
            message = QString::fromStdString(objError.write());
        }

        distStatusText->setPlainText(message);
        QMessageBox::critical(this, tr("Distribution Error"), message);
        return;
    } catch (const std::exception& e) {
        distExecuteButton->setEnabled(true);
        distPreviewButton->setEnabled(true);
        distStatusText->setPlainText(QString("Error: %1").arg(e.what()));
        QMessageBox::critical(this, tr("Distribution Error"), QString::fromStdString(e.what()));
        return;
    }

    distPreviewButton->setEnabled(true);

    // Parse result
    QString txid = QString::fromStdString(result["txid"].get_str());

    distStatusText->setPlainText(QString(
        "✓ Distribution Successful!\n\n"
        "Transaction ID: %1\n\n"
        "The distribution has been broadcast to the network.")
        .arg(txid));

    QMessageBox::information(this, tr("Distribution Successful"),
        QString("Transaction broadcast successfully!\n\nTxID: %1").arg(txid));

    // Reset state
    distributionPreviewReady = false;
    distPreviewTable->setRowCount(0);
    distSummaryLabel->setVisible(false);
    distAmountEdit->clear();
}

// ===== HELPER METHOD IMPLEMENTATIONS =====
// (buildCanonicalPayload and encodeCompactSize removed - now using assets::CanonicalIcuPayload from core)
