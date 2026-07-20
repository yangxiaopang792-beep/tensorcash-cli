// Copyright (c) 2024-2025 The TensorCash Core developers
// Copyright (c) 2016-2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <qt/modaloverlay.h>
#include <qt/forms/ui_modaloverlay.h>

#include <chainparams.h>
#include <qt/guiutil.h>

#include <QEasingCurve>
#include <QPropertyAnimation>
#include <QResizeEvent>

ModalOverlay::ModalOverlay(bool enable_wallet, QWidget* parent)
    : QWidget(parent),
      ui(new Ui::ModalOverlay),
      bestHeaderDate(QDateTime())
{
    ui->setupUi(this);
    connect(ui->closeButton, &QPushButton::clicked, this, &ModalOverlay::closeClicked);
    if (parent) {
        parent->installEventFilter(this);
        raise();
    }
    ui->closeButton->installEventFilter(this);

    blockProcessTime.clear();
    setVisible(false);
    if (!enable_wallet) {
        ui->infoText->setVisible(false);
        ui->infoTextStrong->setText(tr("%1 is currently syncing.  It will download headers and blocks from peers and validate them until reaching the tip of the block chain.").arg(CLIENT_NAME));
    }

    m_animation.setTargetObject(this);
    m_animation.setPropertyName("pos");
    m_animation.setDuration(300 /* ms */);
    m_animation.setEasingCurve(QEasingCurve::OutQuad);
}

ModalOverlay::~ModalOverlay()
{
    delete ui;
}

bool ModalOverlay::eventFilter(QObject * obj, QEvent * ev) {
    if (obj == parent()) {
        if (ev->type() == QEvent::Resize) {
            QResizeEvent * rev = static_cast<QResizeEvent*>(ev);
            resize(rev->size());
            if (!layerIsVisible)
                setGeometry(0, height(), width(), height());

            if (m_animation.endValue().toPoint().y() > 0) {
                m_animation.setEndValue(QPoint(0, height()));
            }
        }
        else if (ev->type() == QEvent::ChildAdded) {
            raise();
        }
    }

    if (obj == ui->closeButton && ev->type() == QEvent::FocusOut && layerIsVisible) {
        ui->closeButton->setFocus(Qt::OtherFocusReason);
    }

    return QWidget::eventFilter(obj, ev);
}

//! Tracks parent widget changes
bool ModalOverlay::event(QEvent* ev) {
    if (ev->type() == QEvent::ParentAboutToChange) {
        if (parent()) parent()->removeEventFilter(this);
    }
    else if (ev->type() == QEvent::ParentChange) {
        if (parent()) {
            parent()->installEventFilter(this);
            raise();
        }
    }
    return QWidget::event(ev);
}

void ModalOverlay::setKnownBestHeight(int count, const QDateTime& blockDate, bool presync)
{
    if (!presync && count > bestHeaderHeight) {
        bestHeaderHeight = count;
        bestHeaderDate = blockDate;
        UpdateHeaderSyncLabel();
    }
    if (presync) {
        UpdateHeaderPresyncLabel(count, blockDate);
    }
}

void ModalOverlay::tipUpdate(int count, const QDateTime& blockDate, double nVerificationProgress)
{
    QDateTime currentDate = QDateTime::currentDateTime();

    // keep a vector of samples of block height at time
    blockProcessTime.push_front(qMakePair(currentDate.toMSecsSinceEpoch(), nVerificationProgress));

    // When bestHeaderHeight is known, use height-based ETA which is reliable
    // regardless of nMinimumChainWork (which is 0 on testnet, making the
    // chain-work-based progress meaningless).
    bool usedHeightEta = false;
    if (bestHeaderHeight > 0 && count > 0 && blockProcessTime.size() >= 2) {
        // Use height ratio for progress instead of nVerificationProgress
        double heightProgress = (double)count / (double)bestHeaderHeight;
        if (heightProgress > 1.0) heightProgress = 1.0;

        // Compute blocks/sec from recent samples to estimate remaining time.
        // blockProcessTime stores (timestamp_ms, nVerificationProgress) but we
        // track height via 'count'.  Use the earliest sample with enough time
        // delta and compute height rate from the count difference.
        // We store count in a static map keyed by timestamp for rate calc.
        static QVector<QPair<qint64, int>> heightSamples;
        heightSamples.push_front(qMakePair(currentDate.toMSecsSinceEpoch(), count));

        if (heightSamples.size() >= 2) {
            int blocksRemaining = bestHeaderHeight - count;
            qint64 remainingMSecs = -1;
            double blocksPerHour = 0;

            for (int i = 1; i < heightSamples.size(); i++) {
                auto& sample = heightSamples[i];
                // Use a sample at least 10 seconds old for stability
                if (sample.first < (currentDate.toMSecsSinceEpoch() - 10 * 1000) || i == heightSamples.size() - 1) {
                    int heightDelta = count - sample.second;
                    qint64 msecDelta = currentDate.toMSecsSinceEpoch() - sample.first;
                    if (heightDelta > 0 && msecDelta > 0) {
                        double blocksPerMSec = (double)heightDelta / (double)msecDelta;
                        blocksPerHour = blocksPerMSec * 1000.0 * 3600.0;
                        remainingMSecs = (qint64)((double)blocksRemaining / blocksPerMSec);
                    }
                    break;
                }
            }

            static const int MAX_HEIGHT_SAMPLES = 5000;
            if (heightSamples.size() > MAX_HEIGHT_SAMPLES) {
                heightSamples.remove(MAX_HEIGHT_SAMPLES, heightSamples.size() - MAX_HEIGHT_SAMPLES);
            }

            ui->progressIncreasePerH->setText(QString::number(blocksPerHour, 'f', 0) + " blk/h");

            if (remainingMSecs >= 0) {
                ui->expectedTimeLeft->setText(GUIUtil::formatNiceTimeOffset(remainingMSecs / 1000.0));
            } else {
                ui->expectedTimeLeft->setText(QObject::tr("calculating..."));
            }

            ui->percentageProgress->setText(QString::number(heightProgress * 100, 'f', 2) + "%");
            usedHeightEta = true;
        }
    }

    // Fall back to the original chain-work-based estimate when height is unknown
    if (!usedHeightEta && blockProcessTime.size() >= 2) {
        double progressDelta = 0;
        double progressPerHour = 0;
        qint64 timeDelta = 0;
        qint64 remainingMSecs = 0;
        double remainingProgress = 1.0 - nVerificationProgress;
        for (int i = 1; i < blockProcessTime.size(); i++) {
            QPair<qint64, double> sample = blockProcessTime[i];

            // take first sample after 500 seconds or last available one
            if (sample.first < (currentDate.toMSecsSinceEpoch() - 500 * 1000) || i == blockProcessTime.size() - 1) {
                progressDelta = blockProcessTime[0].second - sample.second;
                timeDelta = blockProcessTime[0].first - sample.first;
                progressPerHour = (progressDelta > 0) ? progressDelta / (double)timeDelta * 1000 * 3600 : 0;
                remainingMSecs = (progressDelta > 0) ? remainingProgress / progressDelta * timeDelta : -1;
                break;
            }
        }
        // show progress increase per hour
        ui->progressIncreasePerH->setText(QString::number(progressPerHour * 100, 'f', 2)+"%");

        // show expected remaining time
        if(remainingMSecs >= 0) {
            ui->expectedTimeLeft->setText(GUIUtil::formatNiceTimeOffset(remainingMSecs / 1000.0));
        } else {
            ui->expectedTimeLeft->setText(QObject::tr("unknown"));
        }

        // show the percentage done according to nVerificationProgress
        ui->percentageProgress->setText(QString::number(nVerificationProgress*100, 'f', 2)+"%");
    }

    static const int MAX_SAMPLES = 5000;
    if (blockProcessTime.count() > MAX_SAMPLES) {
        blockProcessTime.remove(MAX_SAMPLES, blockProcessTime.count() - MAX_SAMPLES);
    }

    // show the last block date
    ui->newestBlockDate->setText(blockDate.toString());

    if (!bestHeaderDate.isValid())
        // not syncing
        return;

    // estimate the number of headers left based on nPowTargetSpacing
    // and check if the gui is not aware of the best header (happens rarely)
    int estimateNumHeadersLeft = bestHeaderDate.secsTo(currentDate) / Params().GetConsensus().nPowTargetSpacing;
    bool hasBestHeader = bestHeaderHeight >= count;

    // show remaining number of blocks
    if (estimateNumHeadersLeft < HEADER_HEIGHT_DELTA_SYNC && hasBestHeader) {
        ui->numberOfBlocksLeft->setText(QString::number(bestHeaderHeight - count));
    } else {
        UpdateHeaderSyncLabel();
        ui->expectedTimeLeft->setText(tr("Unknown…"));
    }
}

void ModalOverlay::UpdateHeaderSyncLabel() {
    int est_headers_left = bestHeaderDate.secsTo(QDateTime::currentDateTime()) / Params().GetConsensus().nPowTargetSpacing;
    ui->numberOfBlocksLeft->setText(tr("Unknown. Syncing Headers (%1, %2%)…").arg(bestHeaderHeight).arg(QString::number(100.0 / (bestHeaderHeight + est_headers_left) * bestHeaderHeight, 'f', 1)));
}

void ModalOverlay::UpdateHeaderPresyncLabel(int height, const QDateTime& blockDate) {
    int est_headers_left = blockDate.secsTo(QDateTime::currentDateTime()) / Params().GetConsensus().nPowTargetSpacing;
    ui->numberOfBlocksLeft->setText(tr("Unknown. Pre-syncing Headers (%1, %2%)…").arg(height).arg(QString::number(100.0 / (height + est_headers_left) * height, 'f', 1)));
}

void ModalOverlay::toggleVisibility()
{
    showHide(layerIsVisible, true);
    if (!layerIsVisible)
        userClosed = true;
}

void ModalOverlay::showHide(bool hide, bool userRequested)
{
    if ( (layerIsVisible && !hide) || (!layerIsVisible && hide) || (!hide && userClosed && !userRequested))
        return;

    Q_EMIT triggered(hide);

    if (!isVisible() && !hide)
        setVisible(true);

    m_animation.setStartValue(QPoint(0, hide ? 0 : height()));
    // The eventFilter() updates the endValue if it is required for QEvent::Resize.
    m_animation.setEndValue(QPoint(0, hide ? height() : 0));
    m_animation.start(QAbstractAnimation::KeepWhenStopped);
    layerIsVisible = !hide;

    if (layerIsVisible) {
        ui->closeButton->setFocus(Qt::OtherFocusReason);
    }
}

void ModalOverlay::closeClicked()
{
    showHide(true);
    userClosed = true;
}
