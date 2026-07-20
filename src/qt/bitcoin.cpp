// Copyright (c) 2024-2025 The TensorCash Core developers
// Copyright (c) 2011-2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <qt/bitcoin.h>

#include <chainparams.h>
#include <common/args.h>
#include <common/init.h>
#include <common/system.h>
#include <init.h>
#include <interfaces/handler.h>
#include <interfaces/init.h>
#include <interfaces/node.h>
#include <logging.h>
#include <node/context.h>
#include <node/interface_ui.h>
#include <noui.h>
#include <qt/bitcoingui.h>
#include <qt/clientmodel.h>
#include <qt/guiconstants.h>
#include <qt/guiutil.h>
#include <qt/initexecutor.h>
#include <qt/intro.h>
#include <qt/networkstyle.h>
#include <qt/optionsmodel.h>
#include <qt/platformstyle.h>
#include <qt/splashscreen.h>
#include <qt/utilitydialog.h>
#include <qt/winshutdownmonitor.h>
#include <uint256.h>
#include <util/exception.h>
#include <util/string.h>
#include <util/threadnames.h>
#include <util/translation.h>
#include <validation.h>

#ifdef ENABLE_WALLET
#include <qt/paymentserver.h>
#include <qt/walletcontroller.h>
#include <qt/walletframe.h>
#include <qt/walletview.h>
#include <qt/walletmodel.h>
#include <qt/tormanager.h>
#include <wallet/types.h>
#endif // ENABLE_WALLET

#include <boost/signals2/connection.hpp>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <memory>

#ifdef __APPLE__
#include <unistd.h>
#endif

#include <QApplication>
#include <QDebug>
#include <QEvent>
#include <QLatin1String>
#include <QLibraryInfo>
#include <QLocale>
#include <QMessageBox>
#include <QSettings>
#include <QThread>
#include <QTimer>
#include <QTranslator>
#include <QWindow>
#include <QWidget>

// Declare meta types used for QMetaObject::invokeMethod
Q_DECLARE_METATYPE(bool*)
Q_DECLARE_METATYPE(CAmount)
Q_DECLARE_METATYPE(SynchronizationState)
Q_DECLARE_METATYPE(SyncType)
Q_DECLARE_METATYPE(uint256)
#ifdef ENABLE_WALLET
Q_DECLARE_METATYPE(wallet::AddressPurpose)
#endif // ENABLE_WALLET

using util::MakeUnorderedList;

static void RegisterMetaTypes()
{
    // Register meta types used for QMetaObject::invokeMethod and Qt::QueuedConnection
    qRegisterMetaType<bool*>();
    qRegisterMetaType<SynchronizationState>();
    qRegisterMetaType<SyncType>();
  #ifdef ENABLE_WALLET
    qRegisterMetaType<WalletModel*>();
    qRegisterMetaType<wallet::AddressPurpose>();
  #endif // ENABLE_WALLET
    // Register typedefs (see https://doc.qt.io/qt-5/qmetatype.html#qRegisterMetaType)
    // IMPORTANT: if CAmount is no longer a typedef use the normal variant above (see https://doc.qt.io/qt-5/qmetatype.html#qRegisterMetaType-1)
    qRegisterMetaType<CAmount>("CAmount");
    qRegisterMetaType<size_t>("size_t");

    qRegisterMetaType<std::function<void()>>("std::function<void()>");
    qRegisterMetaType<QMessageBox::Icon>("QMessageBox::Icon");
    qRegisterMetaType<interfaces::BlockAndHeaderTipInfo>("interfaces::BlockAndHeaderTipInfo");
    qRegisterMetaType<BitcoinUnit>("BitcoinUnit");
}

static std::string DescribeWidgetForWatchdog(QWidget* widget)
{
    if (!widget) {
        return {};
    }

    std::string desc = widget->metaObject()->className();
    if (!widget->objectName().isEmpty()) {
        desc += "[object=" + widget->objectName().toStdString() + "]";
    }
    if (!widget->windowTitle().isEmpty()) {
        desc += "[title=" + widget->windowTitle().toStdString() + "]";
    }
    return desc;
}

static std::string DescribeObjectForWatchdog(QObject* object)
{
    if (!object) {
        return {};
    }

    std::string desc = object->metaObject()->className();
    if (!object->objectName().isEmpty()) {
        desc += "[object=" + object->objectName().toStdString() + "]";
    }
    if (QWidget* widget = qobject_cast<QWidget*>(object)) {
        if (!widget->windowTitle().isEmpty()) {
            desc += "[title=" + widget->windowTitle().toStdString() + "]";
        }
    }
    return desc;
}

static std::string EventTypeNameForWatchdog(QEvent::Type type)
{
    switch (type) {
    case QEvent::Paint: return "Paint";
    case QEvent::UpdateRequest: return "UpdateRequest";
    case QEvent::Resize: return "Resize";
    case QEvent::Move: return "Move";
    case QEvent::Show: return "Show";
    case QEvent::Hide: return "Hide";
    case QEvent::FocusIn: return "FocusIn";
    case QEvent::FocusOut: return "FocusOut";
    case QEvent::MouseButtonPress: return "MouseButtonPress";
    case QEvent::MouseButtonRelease: return "MouseButtonRelease";
    case QEvent::MouseMove: return "MouseMove";
    case QEvent::Wheel: return "Wheel";
    case QEvent::KeyPress: return "KeyPress";
    case QEvent::KeyRelease: return "KeyRelease";
    case QEvent::Timer: return "Timer";
    case QEvent::LayoutRequest: return "LayoutRequest";
    case QEvent::PolishRequest: return "PolishRequest";
    case QEvent::MetaCall: return "MetaCall";
    default: return std::to_string(static_cast<int>(type));
    }
}

static QString GetLangTerritory()
{
    QSettings settings;
    // Get desired locale (e.g. "de_DE")
    // 1) System default language
    QString lang_territory = QLocale::system().name();
    // 2) Language from QSettings
    QString lang_territory_qsettings = settings.value("language", "").toString();
    if(!lang_territory_qsettings.isEmpty())
        lang_territory = lang_territory_qsettings;
    // 3) -lang command line argument
    lang_territory = QString::fromStdString(gArgs.GetArg("-lang", lang_territory.toStdString()));
    return lang_territory;
}

/** Set up translations */
static void initTranslations(QTranslator &qtTranslatorBase, QTranslator &qtTranslator, QTranslator &translatorBase, QTranslator &translator,
                              QTranslator &tscTranslatorBase, QTranslator &tscTranslator)
{
    // Remove old translators
    QApplication::removeTranslator(&qtTranslatorBase);
    QApplication::removeTranslator(&qtTranslator);
    QApplication::removeTranslator(&translatorBase);
    QApplication::removeTranslator(&translator);
    QApplication::removeTranslator(&tscTranslatorBase);
    QApplication::removeTranslator(&tscTranslator);

    // Get desired locale (e.g. "de_DE")
    // 1) System default language
    QString lang_territory = GetLangTerritory();

    // Convert to "de" only by truncating "_DE"
    QString lang = lang_territory;
    lang.truncate(lang_territory.lastIndexOf('_'));

    // Load language files for configured locale:
    // - First load the translator for the base language, without territory
    // - Then load the more specific locale translator

    const QString translation_path{QLibraryInfo::path(QLibraryInfo::TranslationsPath)};
    // Load e.g. qt_de.qm
    if (qtTranslatorBase.load("qt_" + lang, translation_path)) {
        QApplication::installTranslator(&qtTranslatorBase);
    }

    // Load e.g. qt_de_DE.qm
    if (qtTranslator.load("qt_" + lang_territory, translation_path)) {
        QApplication::installTranslator(&qtTranslator);
    }

    // Load e.g. bitcoin_de.qm (shortcut "de" needs to be defined in bitcoin.qrc)
    if (translatorBase.load(lang, ":/translations/")) {
        QApplication::installTranslator(&translatorBase);
    }

    // Load e.g. bitcoin_de_DE.qm (shortcut "de_DE" needs to be defined in bitcoin.qrc)
    if (translator.load(lang_territory, ":/translations/")) {
        QApplication::installTranslator(&translator);
    }

    // Load TensorCash-specific translations (e.g. tsc_de.qm)
    if (tscTranslatorBase.load(lang, ":/tsc_translations/")) {
        QApplication::installTranslator(&tscTranslatorBase);
    }

    // Load territory-specific TSC translations (e.g. tsc_de_DE.qm)
    if (tscTranslator.load(lang_territory, ":/tsc_translations/")) {
        QApplication::installTranslator(&tscTranslator);
    }
}

static bool ErrorSettingsRead(const bilingual_str& error, const std::vector<std::string>& details)
{
    QMessageBox messagebox(QMessageBox::Critical, CLIENT_NAME, QString::fromStdString(strprintf("%s.", error.translated)), QMessageBox::Reset | QMessageBox::Abort);
    /*: Explanatory text shown on startup when the settings file cannot be read.
      Prompts user to make a choice between resetting or aborting. */
    messagebox.setInformativeText(QObject::tr("Do you want to reset settings to default values, or to abort without making changes?"));
    messagebox.setDetailedText(QString::fromStdString(MakeUnorderedList(details)));
    messagebox.setTextFormat(Qt::PlainText);
    messagebox.setDefaultButton(QMessageBox::Reset);
    switch (messagebox.exec()) {
    case QMessageBox::Reset:
        return false;
    case QMessageBox::Abort:
        return true;
    default:
        assert(false);
    }
}

static void ErrorSettingsWrite(const bilingual_str& error, const std::vector<std::string>& details)
{
    QMessageBox messagebox(QMessageBox::Critical, CLIENT_NAME, QString::fromStdString(strprintf("%s.", error.translated)), QMessageBox::Ok);
    /*: Explanatory text shown on startup when the settings file could not be written.
        Prompts user to check that we have the ability to write to the file.
        Explains that the user has the option of running without a settings file.*/
    messagebox.setInformativeText(QObject::tr("A fatal error occurred. Check that settings file is writable, or try running with -nosettings."));
    messagebox.setDetailedText(QString::fromStdString(MakeUnorderedList(details)));
    messagebox.setTextFormat(Qt::PlainText);
    messagebox.setDefaultButton(QMessageBox::Ok);
    messagebox.exec();
}

/* qDebug() message handler --> debug.log */
void DebugMessageHandler(QtMsgType type, const QMessageLogContext& context, const QString &msg)
{
    Q_UNUSED(context);
    if (type == QtDebugMsg) {
        LogDebug(BCLog::QT, "GUI: %s\n", msg.toStdString());
    } else {
        LogPrintf("GUI: %s\n", msg.toStdString());
    }
}

static int qt_argc = 1;
static const char* qt_argv = "bitcoin-qt";

// std::set_terminate handler. Strictly diagnostic — does NOT recover.
//
// Background: destructors in C++11+ are implicitly noexcept(true). A throw
// from inside a noexcept function calls std::terminate() at the throw site,
// BEFORE any stack unwinding. So a try/catch wrapping the call that owns
// the destructor (e.g. `try { delete window; }` below) cannot catch a
// throw from QObject::~QObject's body — terminate has already fired.
//
// Crash 7BB19689 (2026-05-23) and the 2026-05-27 18:15 SIGABRT
// (incident 412A4FC5) both show this exact pattern: QObject::~QObject
// at offset +1936 throws during widget-tree teardown, std::terminate
// fires, abort() kills the process with no log line from the
// surrounding try/catch.
//
// This handler runs IN PLACE OF abort(). It writes a marker line and the
// exception's what() to stderr using raw write(2) (async-signal-safe;
// LogPrintf and Qt-side logging are explicitly NOT called because their
// internal mutexes may be held by another thread that's now being torn
// down — calling them here can deadlock the process and prevent the
// _Exit). The marker line surfaces in macOS Console.app / the parent
// shell's stderr capture, which is enough to identify "the process
// terminated for reason X" without a symbolized binary.
//
// It does NOT fix the throwing destructor. Finding and removing the
// throw still needs a symbolized build (the unsymbolized frame at
// TensorCash+0x247f0 in the .ips reports). This handler converts
// SIGABRT into a logged _Exit(1) so the failure mode is at least
// visible in stderr and the next-launch checks the marker file.
static void BitcoinTerminateHandler() noexcept
{
    // Use stdio fputs to stderr. Portable across POSIX and the MinGW/Windows
    // cross-build — POSIX write(2) is not declared there ('::write has not
    // been declared'), which broke the Windows desktop build in 44cf4788a6.
    // Do NOT use LogPrintf or any Qt call: their internal mutexes may be held
    // by a thread being torn down, which would deadlock and prevent the
    // _Exit. stderr's own FILE lock is independent of those and is the
    // conventional channel for a terminate handler.
    std::fputs("FATAL: std::terminate called (probable noexcept-dtor throw); see BitcoinTerminateHandler in bitcoin.cpp\n", stderr);

    // Best-effort: extract and log the exception's what(). std::current_exception
    // / rethrow_exception can themselves throw; the outer try/catch absorbs that.
    try {
        if (std::exception_ptr eptr = std::current_exception()) {
            try {
                std::rethrow_exception(eptr);
            } catch (const std::exception& e) {
                std::fputs("  what(): ", stderr);
                std::fputs(e.what() ? e.what() : "(null)", stderr);
                std::fputs("\n", stderr);
            } catch (...) {
                std::fputs("  (non-std::exception type, what() unavailable)\n", stderr);
            }
        } else {
            std::fputs("  (no current_exception — terminate via foreign throw or explicit call)\n", stderr);
        }
    } catch (...) {
        // Even handler logging failed. Bail without recursion.
    }
    std::fflush(stderr);
    std::_Exit(EXIT_FAILURE);
}

BitcoinApplication::BitcoinApplication()
    : QApplication(qt_argc, const_cast<char**>(&qt_argv))
{
    // Install the terminate handler as the FIRST thing in BitcoinApplication
    // construction — before any Qt object is created, so even a throw from a
    // Qt constructor goes through our handler. The handler does not contain
    // the throw; it just converts SIGABRT into a logged _Exit so the failure
    // mode is visible without a symbolized binary. See handler comment.
    std::set_terminate(&BitcoinTerminateHandler);

    // Qt runs setlocale(LC_ALL, "") on initialization.
    RegisterMetaTypes();
    setQuitOnLastWindowClosed(false);

    m_ui_heartbeat_ms.store(QDateTime::currentMSecsSinceEpoch(), std::memory_order_relaxed);
    m_ui_heartbeat_timer = new QTimer(this);
    m_ui_heartbeat_timer->setInterval(1000);
    connect(m_ui_heartbeat_timer, &QTimer::timeout, this, [this] {
        TouchUIHeartbeat();

        std::string context;
        if (window) {
            context += "main_window=" + DescribeWidgetForWatchdog(window);
        }
        if (QWidget* active = QApplication::activeWindow()) {
            if (!context.empty()) context += ' ';
            context += "active_window=" + DescribeWidgetForWatchdog(active);
        }
        if (QWidget* modal = QApplication::activeModalWidget()) {
            if (!context.empty()) context += ' ';
            context += "active_modal=" + DescribeWidgetForWatchdog(modal);
        }
        if (QWidget* focus = QApplication::focusWidget()) {
            if (!context.empty()) context += ' ';
            context += "focus=" + DescribeWidgetForWatchdog(focus);
        }
#ifdef ENABLE_WALLET
        if (window && window->centralWidget()) {
            if (WalletFrame* wallet_frame = qobject_cast<WalletFrame*>(window->centralWidget())) {
                if (WalletView* wallet_view = wallet_frame->currentWalletView()) {
                    QWidget* current_page = wallet_view->currentWidget();
                    if (current_page) {
                        if (!context.empty()) context += ' ';
                        context += "wallet_page=" + DescribeWidgetForWatchdog(current_page);
                    }
                }
            }
        }
#endif

        {
            std::lock_guard<std::mutex> lock(m_ui_watchdog_mutex);
            m_ui_last_context = std::move(context);
        }

        if (m_ui_hang_reported.exchange(false, std::memory_order_acq_rel)) {
            std::string recovered_context;
            {
                std::lock_guard<std::mutex> lock(m_ui_watchdog_mutex);
                recovered_context = m_ui_last_context;
            }
            LogPrintf("GUI watchdog: main thread heartbeat recovered%s%s\n",
                      recovered_context.empty() ? "" : " ",
                      recovered_context.c_str());
        }
    });
    m_ui_heartbeat_timer->start();

    m_ui_watchdog_thread = std::thread([this] {
        util::ThreadRename("qt-ui-watchdog");
        // Two thresholds, gated by independent atomic flags:
        //   STALL_LOG_MS: log a soft stall (m_ui_hang_reported, can recover).
        //   STALL_FATAL_MS: best-effort sample on macOS, then _Exit
        //                   (m_ui_fatal_escalated, latched, never recovers).
        constexpr qint64 STALL_LOG_MS = 5000;
        constexpr qint64 STALL_FATAL_MS = 60000;
        while (!m_ui_watchdog_stop.load(std::memory_order_acquire)) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            const qint64 now_ms = QDateTime::currentMSecsSinceEpoch();
            const qint64 last_ms = m_ui_heartbeat_ms.load(std::memory_order_relaxed);
            const qint64 delta_ms = now_ms - last_ms;

            if (delta_ms > STALL_FATAL_MS &&
                !m_ui_watchdog_stop.load(std::memory_order_acquire) &&
                !m_ui_fatal_escalated.exchange(true, std::memory_order_acq_rel)) {
                std::string context;
                {
                    std::lock_guard<std::mutex> lock(m_ui_watchdog_mutex);
                    context = m_ui_last_context;
                }
                LogPrintf("GUI watchdog: FATAL main thread stall stall_ms=%lld%s%s; escalating to _Exit\n",
                          static_cast<long long>(delta_ms),
                          context.empty() ? "" : " ",
                          context.c_str());
#ifdef __APPLE__
                // Best-effort: kick off macOS `sample` detached, give it a few
                // seconds to write, then _Exit regardless. If sample blocks /
                // missing / disk full, the bounded sleep below still elapses
                // and we still _Exit. The shell trailing `&` ensures system()
                // returns immediately rather than waiting on the child.
                {
                    char cmd[512];
                    std::snprintf(cmd, sizeof(cmd),
                                  "/usr/bin/sample %d 3 -file /tmp/tensorcash-stall-%d.txt "
                                  ">/dev/null 2>&1 &",
                                  static_cast<int>(::getpid()),
                                  static_cast<int>(::getpid()));
                    (void)std::system(cmd);
                }
                std::this_thread::sleep_for(std::chrono::seconds(4));
#endif
                std::_Exit(EXIT_FAILURE);
            }

            if (delta_ms <= STALL_LOG_MS) {
                continue;
            }
            if (m_ui_hang_reported.exchange(true, std::memory_order_acq_rel)) {
                continue;
            }

            std::string context;
            {
                std::lock_guard<std::mutex> lock(m_ui_watchdog_mutex);
                context = m_ui_last_context;
            }
            LogPrintf("GUI watchdog: main thread heartbeat stalled stall_ms=%d%s%s\n",
                      static_cast<int>(delta_ms),
                      context.empty() ? "" : " ",
                      context.c_str());
        }
    });
}

void BitcoinApplication::TouchUIHeartbeat()
{
    const qint64 now_ms = QDateTime::currentMSecsSinceEpoch();
    m_ui_heartbeat_ms.store(now_ms, std::memory_order_relaxed);
}

void BitcoinApplication::setupPlatformStyle()
{
    // UI per-platform customization
    // This must be done inside the BitcoinApplication constructor, or after it, because
    // PlatformStyle::instantiate requires a QApplication
    std::string platformName;
    platformName = gArgs.GetArg("-uiplatform", BitcoinGUI::DEFAULT_UIPLATFORM);
    platformStyle = PlatformStyle::instantiate(QString::fromStdString(platformName));
    if (!platformStyle) // Fall back to "other" if specified name not found
        platformStyle = PlatformStyle::instantiate("other");
    assert(platformStyle);
}

BitcoinApplication::~BitcoinApplication()
{
#ifdef ENABLE_WALLET
    // Stop tor first, before any widget destruction. A throwing dtor in the
    // qApp child chain (we've seen this in QObject::~QObject) skips the
    // implicit TorManager teardown that would otherwise run via qApp's
    // child cleanup, orphaning the bundled tor process.
    if (TorManager* tm = TorManager::peek()) {
        tm->stop();
    }
#endif
    if (m_ui_heartbeat_timer) {
        m_ui_heartbeat_timer->stop();
    }
    m_ui_watchdog_stop.store(true, std::memory_order_release);
    if (m_ui_watchdog_thread.joinable()) {
        m_ui_watchdog_thread.join();
    }

    m_executor.reset();

    // This try/catch ONLY covers exceptions that propagate through normal
    // unwinding — e.g., a non-destructor throw from operator delete. It
    // CANNOT catch a throw from a destructor body (QObject::~QObject,
    // QLayout::~QLayout, etc.), because destructors are implicitly
    // noexcept(true) in C++11+ and a throw inside a noexcept function
    // calls std::terminate AT THE THROW SITE, before any unwinding could
    // reach this frame. The shutdown SIGABRT class we've observed
    // (crash 7BB19689 on 2026-05-23, incident 412A4FC5 on 2026-05-27)
    // is the noexcept-dtor variant — it produces no log line here, and
    // this try/catch is structurally unable to contain it.
    //
    // The actual containment for that case is BitcoinTerminateHandler
    // installed at the top of BitcoinApplication's constructor — it
    // intercepts std::terminate and writes a marker to stderr before
    // _Exit. See the handler's comment for why we cannot use LogPrintf
    // there. Finding and removing the throwing destructor itself
    // requires a symbolized build (unsymbolized frame at
    // TensorCash+0x247f0 in both .ips reports above).
    try {
        delete window;
    } catch (const std::exception& e) {
        LogPrintf("BitcoinApplication: exception during window teardown (non-dtor): %s\n", e.what());
    } catch (...) {
        LogPrintf("BitcoinApplication: unknown exception during window teardown (non-dtor)\n");
    }
    window = nullptr;
    delete platformStyle;
    platformStyle = nullptr;
}

#ifdef ENABLE_WALLET
void BitcoinApplication::createPaymentServer()
{
    paymentServer = new PaymentServer(this);
}
#endif

bool BitcoinApplication::createOptionsModel(bool resetSettings)
{
    optionsModel = new OptionsModel(node(), this);
    if (resetSettings) {
        optionsModel->Reset();
    }
    bilingual_str error;
    if (!optionsModel->Init(error)) {
        fs::path settings_path;
        if (gArgs.GetSettingsPath(&settings_path)) {
            error += Untranslated("\n");
            std::string quoted_path = strprintf("%s", fs::quoted(fs::PathToString(settings_path)));
            error.original += strprintf("Settings file %s might be corrupt or invalid.", quoted_path);
            error.translated += tr("Settings file %1 might be corrupt or invalid.").arg(QString::fromStdString(quoted_path)).toStdString();
        }
        InitError(error);
        QMessageBox::critical(nullptr, CLIENT_NAME, QString::fromStdString(error.translated));
        return false;
    }
    return true;
}

void BitcoinApplication::createWindow(const NetworkStyle *networkStyle)
{
    window = new BitcoinGUI(node(), platformStyle, networkStyle, nullptr);
    connect(window, &BitcoinGUI::quitRequested, this, &BitcoinApplication::requestShutdown);

    pollShutdownTimer = new QTimer(window);
    connect(pollShutdownTimer, &QTimer::timeout, [this]{
        if (!QApplication::activeModalWidget()) {
            window->detectShutdown();
        }
    });
}

void BitcoinApplication::createSplashScreen(const NetworkStyle *networkStyle)
{
    assert(!m_splash);
    m_splash = new SplashScreen(networkStyle);
    m_splash->show();
}

void BitcoinApplication::createNode(interfaces::Init& init)
{
    assert(!m_node);
    m_node = init.makeNode();
    if (m_splash) m_splash->setNode(*m_node);
}

bool BitcoinApplication::baseInitialize()
{
    return node().baseInitialize();
}

void BitcoinApplication::startThread()
{
    assert(!m_executor);
    m_executor.emplace(node());

    /*  communication to and from thread */
    connect(&m_executor.value(), &InitExecutor::initializeResult, this, &BitcoinApplication::initializeResult);
    connect(&m_executor.value(), &InitExecutor::shutdownResult, this, [] {
        QCoreApplication::exit(0);
    });
    connect(&m_executor.value(), &InitExecutor::runawayException, this, &BitcoinApplication::handleRunawayException);
    connect(this, &BitcoinApplication::requestedInitialize, &m_executor.value(), &InitExecutor::initialize);
    connect(this, &BitcoinApplication::requestedShutdown, &m_executor.value(), &InitExecutor::shutdown);
}

void BitcoinApplication::parameterSetup()
{
    // Default printtoconsole to false for the GUI. GUI programs should not
    // print to the console unnecessarily.
    gArgs.SoftSetBoolArg("-printtoconsole", false);

    InitLogging(gArgs);
    InitParameterInteraction(gArgs);
}

void BitcoinApplication::InitPruneSetting(int64_t prune_MiB)
{
    optionsModel->SetPruneTargetGB(PruneMiBtoGB(prune_MiB));
}

void BitcoinApplication::requestInitialize()
{
    qDebug() << __func__ << ": Requesting initialize";
    startThread();
    Q_EMIT requestedInitialize();
}

void BitcoinApplication::requestShutdown()
{
    for (const auto w : QGuiApplication::topLevelWindows()) {
        w->hide();
    }

    delete m_splash;
    m_splash = nullptr;

    // Show a simple window indicating shutdown status
    // Do this first as some of the steps may take some time below,
    // for example the RPC console may still be executing a command.
    shutdownWindow.reset(ShutdownWindow::showShutdownWindow(window));

    qDebug() << __func__ << ": Requesting shutdown";

    // Must disconnect node signals otherwise current thread can deadlock since
    // no event loop is running.
    window->unsubscribeFromCoreSignals();
    // Request node shutdown, which can interrupt long operations, like
    // rescanning a wallet.
    node().startShutdown();
    // Prior to unsetting the client model, stop listening backend signals
    if (clientModel) {
        clientModel->stop();
    }

    // Unsetting the client model can cause the current thread to wait for node
    // to complete an operation, like wait for a RPC execution to complete.
    window->setClientModel(nullptr);
    pollShutdownTimer->stop();

#ifdef ENABLE_WALLET
    // Stop Tor daemon cleanly before wallet cleanup
    TorManager::instance()->stop();

    // Delete wallet controller here manually, instead of relying on Qt object
    // tracking (https://doc.qt.io/qt-5/objecttrees.html). This makes sure
    // walletmodel m_handle_* notification handlers are deleted before wallets
    // are unloaded, which can simplify wallet implementations. It also avoids
    // these notifications having to be handled while GUI objects are being
    // destroyed, making GUI code less fragile as well.
    delete m_wallet_controller;
    m_wallet_controller = nullptr;
#endif // ENABLE_WALLET

    delete clientModel;
    clientModel = nullptr;

    // Request shutdown from core thread
    Q_EMIT requestedShutdown();
}

void BitcoinApplication::initializeResult(bool success, interfaces::BlockAndHeaderTipInfo tip_info)
{
    qDebug() << __func__ << ": Initialization result: " << success;

    if (success) {
        delete m_splash;
        m_splash = nullptr;

        // Log this only after AppInitMain finishes, as then logging setup is guaranteed complete
        qInfo() << "Platform customization:" << platformStyle->getName();
        clientModel = new ClientModel(node(), optionsModel);
        window->setClientModel(clientModel, &tip_info);

        // If '-min' option passed, start window minimized (iconified) or minimized to tray
        bool start_minimized = gArgs.GetBoolArg("-min", false);
#ifdef ENABLE_WALLET
        if (WalletModel::isWalletEnabled()) {
            m_wallet_controller = new WalletController(*clientModel, platformStyle, this);
            window->setWalletController(m_wallet_controller, /*show_loading_minimized=*/start_minimized);
            if (paymentServer) {
                paymentServer->setOptionsModel(optionsModel);
            }

            // Initialize Tor daemon for cosign bridge sessions.
            // Default the instance ID from the chain so the separately-shipped
            // mainnet and testnet apps don't BOTH default to instance 0 and
            // fight over the same Tor SOCKS/control/service ports (TorManager
            // derives 9150/9151/9735 + instanceId offsets). -guiinstance still
            // overrides for explicit multi-instance deployments.
            int default_instance = 0;
            switch (Params().GetChainType()) {
            case ChainType::TENSOR_MAIN: default_instance = 0; break;
            case ChainType::TENSOR_TEST: default_instance = 1; break;
            case ChainType::TENSOR_REG:  default_instance = 2; break;
            default:                     default_instance = 3; break;
            }
            int instanceId = gArgs.GetIntArg("-guiinstance", default_instance);
            QString dataDir = GUIUtil::PathToQString(gArgs.GetDataDirNet());

            TorManager* torManager = TorManager::instance();
            if (torManager->start(dataDir, instanceId)) {
                LogPrintf("TorManager: Started Tor daemon for instance %d\n", instanceId);

                // Set environment variables when Tor becomes ready
                QObject::connect(torManager, &TorManager::ready, [torManager]() {
                    torManager->setEnvironmentForBridge();
                    LogPrintf("TorManager: Environment variables set for cosign-bridge (Tor is ready)\n");
                });

                // If Tor is already ready, set env vars now
                if (torManager->isReady()) {
                    torManager->setEnvironmentForBridge();
                    LogPrintf("TorManager: Environment variables set for cosign-bridge (Tor already ready)\n");
                }
            } else {
                LogPrintf("TorManager: Failed to start (status: %s, error: %s)\n",
                         torManager->statusString().toStdString(),
                         torManager->lastError().toStdString());
                // Non-fatal: user can still use relay transport
            }
        }
#endif // ENABLE_WALLET

        // Show or minimize window
        if (!start_minimized) {
            window->show();
        } else if (clientModel->getOptionsModel()->getMinimizeToTray() && window->hasTrayIcon()) {
            // do nothing as the window is managed by the tray icon
        } else {
            window->showMinimized();
        }
        Q_EMIT windowShown(window);

#ifdef ENABLE_WALLET
        // Now that initialization/startup is done, process any command-line
        // bitcoin: URIs or payment requests:
        if (paymentServer) {
            connect(paymentServer, &PaymentServer::receivedPaymentRequest, window, &BitcoinGUI::handlePaymentRequest);
            connect(window, &BitcoinGUI::receivedURI, paymentServer, &PaymentServer::handleURIOrFile);
            connect(paymentServer, &PaymentServer::message, [this](const QString& title, const QString& message, unsigned int style) {
                window->message(title, message, style);
            });
            QTimer::singleShot(100ms, paymentServer, &PaymentServer::uiReady);
        }
#endif
        pollShutdownTimer->start(SHUTDOWN_POLLING_DELAY);
    } else {
        requestShutdown();
    }
}

void BitcoinApplication::handleRunawayException(const QString &message)
{
    // The QMessageBox below pumps the event loop, which can deliver queued
    // meta-invocations of this same slot. Without this guard a second call
    // would stack another modal (or fall through to ::exit during the first
    // dialog's lifetime, taking the static-dtor finalizer crash path).
    static std::atomic<bool> in_flight{false};
    if (in_flight.exchange(true)) {
        std::_Exit(EXIT_FAILURE);
    }
    QMessageBox::critical(
        nullptr, tr("Runaway exception"),
        tr("A fatal error occurred. %1 can no longer continue safely and will quit.").arg(CLIENT_NAME) +
        QLatin1String("<br><br>") + GUIUtil::MakeHtmlLink(message, CLIENT_BUGREPORT));
    // _Exit (not ::exit): skip atexit + C++ static destructors. A throwing
    // static dtor during __cxa_finalize_ranges turns the fatal-error quit
    // into SIGABRT, which is what we observed on macOS. Trade-off: macOS
    // Crash Reporter does NOT log this as a crash (we exit with status 1
    // cleanly), and Qt's own cleanup hooks don't run. Diagnose runaway
    // exceptions via the QMessageBox above and the corresponding
    // "Runaway exception" / "RPC EXCEPTION" entries in debug.log, NOT via
    // crash dumps. Tor child cleanup is handled by reapStaleTor() at the
    // top of TorManager::start() on next launch — see TorManager.
    std::_Exit(EXIT_FAILURE);
}

void BitcoinApplication::handleNonFatalException(const QString& message)
{
    assert(QThread::currentThread() == thread());
    QMessageBox::warning(
        nullptr, tr("Internal error"),
        tr("An internal error occurred. %1 will attempt to continue safely. This is "
           "an unexpected bug which can be reported as described below.").arg(CLIENT_NAME) +
        QLatin1String("<br><br>") + GUIUtil::MakeHtmlLink(message, CLIENT_BUGREPORT));
}

WId BitcoinApplication::getMainWinId() const
{
    if (!window)
        return 0;

    return window->winId();
}

bool BitcoinApplication::event(QEvent* e)
{
    TouchUIHeartbeat();
    if (e->type() == QEvent::Quit) {
        requestShutdown();
        return true;
    }

    return QApplication::event(e);
}

bool BitcoinApplication::notify(QObject* receiver, QEvent* event)
{
    TouchUIHeartbeat();
    if (receiver && event) {
        std::string event_context = "last_event=" + EventTypeNameForWatchdog(event->type()) +
                                    " receiver=" + DescribeObjectForWatchdog(receiver);
        if (QObject* parent = receiver->parent()) {
            event_context += " parent=" + DescribeObjectForWatchdog(parent);
        }
        {
            std::lock_guard<std::mutex> lock(m_ui_watchdog_mutex);
            m_ui_last_context = std::move(event_context);
        }
    }
    const bool notified = QApplication::notify(receiver, event);
    TouchUIHeartbeat();
    return notified;
}

static void SetupUIArgs(ArgsManager& argsman)
{
    argsman.AddArg("-choosedatadir", strprintf("Choose data directory on startup (default: %u)", DEFAULT_CHOOSE_DATADIR), ArgsManager::ALLOW_ANY, OptionsCategory::GUI);
    argsman.AddArg("-lang=<lang>", "Set language, for example \"de_DE\" (default: system locale)", ArgsManager::ALLOW_ANY, OptionsCategory::GUI);
    argsman.AddArg("-min", "Start minimized", ArgsManager::ALLOW_ANY, OptionsCategory::GUI);
    argsman.AddArg("-resetguisettings", "Reset all settings changed in the GUI", ArgsManager::ALLOW_ANY, OptionsCategory::GUI);
    argsman.AddArg("-splash", strprintf("Show splash screen on startup (default: %u)", DEFAULT_SPLASHSCREEN), ArgsManager::ALLOW_ANY, OptionsCategory::GUI);
    argsman.AddArg("-uiplatform", strprintf("Select platform to customize UI for (one of windows, macosx, other; default: %s)", BitcoinGUI::DEFAULT_UIPLATFORM), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::GUI);
    argsman.AddArg("-guiinstance=<n>", "GUI instance ID for multi-instance deployments (default: 0). Used to assign unique Tor ports.", ArgsManager::ALLOW_ANY, OptionsCategory::GUI);
}

int GuiMain(int argc, char* argv[])
{
#ifdef WIN32
    common::WinCmdLineArgs winArgs;
    std::tie(argc, argv) = winArgs.get();
#endif

    std::unique_ptr<interfaces::Init> init = interfaces::MakeGuiInit(argc, argv);

    SetupEnvironment();
    util::ThreadSetInternalName("main");

    // Subscribe to global signals from core
    boost::signals2::scoped_connection handler_message_box = ::uiInterface.ThreadSafeMessageBox_connect(noui_ThreadSafeMessageBox);
    boost::signals2::scoped_connection handler_question = ::uiInterface.ThreadSafeQuestion_connect(noui_ThreadSafeQuestion);
    boost::signals2::scoped_connection handler_init_message = ::uiInterface.InitMessage_connect(noui_InitMessage);

    // Do not refer to data directory yet, this can be overridden by Intro::pickDataDirectory

    /// 1. Basic Qt initialization (not dependent on parameters or configuration)
    Q_INIT_RESOURCE(bitcoin);
    Q_INIT_RESOURCE(bitcoin_locale);

#if defined(QT_QPA_PLATFORM_ANDROID)
    QApplication::setAttribute(Qt::AA_DontUseNativeMenuBar);
    QApplication::setAttribute(Qt::AA_DontCreateNativeWidgetSiblings);
    QApplication::setAttribute(Qt::AA_DontUseNativeDialogs);
#endif

    BitcoinApplication app;
    GUIUtil::LoadFont(QStringLiteral(":/fonts/monospace"));

    /// 2. Parse command-line options. We do this after qt in order to show an error if there are problems parsing these
    // Command-line options take precedence:
    SetupServerArgs(gArgs, init->canListenIpc());
    SetupUIArgs(gArgs);
    std::string error;
    if (!gArgs.ParseParameters(argc, argv, error)) {
        InitError(Untranslated(strprintf("Error parsing command line arguments: %s", error)));
        // Create a message box, because the gui has neither been created nor has subscribed to core signals
        QMessageBox::critical(nullptr, CLIENT_NAME,
            // message cannot be translated because translations have not been initialized
            QString::fromStdString("Error parsing command line arguments: %1.").arg(QString::fromStdString(error)));
        return EXIT_FAILURE;
    }

    // Error out when loose non-argument tokens are encountered on command line
    // However, allow BIP-21 URIs only if no options follow
    bool payment_server_token_seen = false;
    for (int i = 1; i < argc; i++) {
        QString arg(argv[i]);
        bool invalid_token = !arg.startsWith("-");
#ifdef ENABLE_WALLET
        if (arg.startsWith(TENSORCASH_IPC_PREFIX, Qt::CaseInsensitive)) {
            invalid_token &= false;
            payment_server_token_seen = true;
        }
#endif
        if (payment_server_token_seen && arg.startsWith("-")) {
            InitError(Untranslated(strprintf("Options ('%s') cannot follow a BIP-21 payment URI", argv[i])));
            QMessageBox::critical(nullptr, CLIENT_NAME,
                                  // message cannot be translated because translations have not been initialized
                                  QString::fromStdString("Options ('%1') cannot follow a BIP-21 payment URI").arg(QString::fromStdString(argv[i])));
            return EXIT_FAILURE;
        }
        if (invalid_token) {
            InitError(Untranslated(strprintf("Command line contains unexpected token '%s', see bitcoin-qt -h for a list of options.", argv[i])));
            QMessageBox::critical(nullptr, CLIENT_NAME,
                                  // message cannot be translated because translations have not been initialized
                                  QString::fromStdString("Command line contains unexpected token '%1', see bitcoin-qt -h for a list of options.").arg(QString::fromStdString(argv[i])));
            return EXIT_FAILURE;
        }
    }

    // Now that the QApplication is setup and we have parsed our parameters, we can set the platform style
    app.setupPlatformStyle();

    // Desktop chain lock: a shipped per-network app (compile-time
    // DEFAULT_CHAIN_TYPE) must boot ITS chain on double-click, regardless of a
    // stale datadir config. An old TensorCash/bitcoin.conf or settings.json with
    // chain=tensor-test must NOT flip the mainnet app to testnet; only an
    // explicit COMMAND-LINE chain flag may override. The datadir config is not
    // parsed until InitConfig (step 6 below), so IsArgSet() here reflects only
    // the command line. This is GUI-main ONLY — bitcoind still honors config
    // chain= (the cluster nodes select their network that way).
    {
        constexpr const char* default_chain = DEFAULT_CHAIN_TYPE;
        const bool cli_chain =
            gArgs.IsArgSet("-chain") || gArgs.IsArgSet("-testnet") ||
            gArgs.IsArgSet("-testnet4") || gArgs.IsArgSet("-regtest") ||
            gArgs.IsArgSet("-signet") || gArgs.IsArgSet("-tensor") ||
            gArgs.IsArgSet("-tensortest") || gArgs.IsArgSet("-tensorreg");
        if (default_chain[0] != '\0' && !cli_chain) {
            gArgs.ForceSetArg("-chain", default_chain);
            // Neutralize any config-level boolean chain flags so they cannot
            // combine with the forced -chain into a "multiple chain selection"
            // error inside ArgsManager::GetChainArg().
            for (const char* net : {"-testnet", "-testnet4", "-regtest", "-signet",
                                    "-tensor", "-tensortest", "-tensorreg"}) {
                gArgs.ForceSetArg(net, "0");
            }
        }
    }

    // Tor port sync: TorManager runs Tor on (9150 + instance*10) /
    // (9151 + instance*10), but the bundled bitcoin.conf hardcodes
    // proxy=127.0.0.1:9150 / torcontrol=127.0.0.1:9151 (instance 0). A non-zero
    // GUI instance — the testnet app defaults to instance 1 so it can run
    // alongside mainnet, or an explicit -guiinstance=N — therefore runs Tor on a
    // different port than the node dials, giving ZERO onion peers. Force the
    // node's -proxy/-torcontrol to the instance's real Tor ports BEFORE node
    // init reads them (ForceSetArg beats the config file). The instance
    // derivation MUST match the TorManager::start() call later in this file.
    {
        int default_instance = 0;
        try {
            switch (gArgs.GetChainType()) {
            case ChainType::TENSOR_MAIN: default_instance = 0; break;
            case ChainType::TENSOR_TEST: default_instance = 1; break;
            case ChainType::TENSOR_REG:  default_instance = 2; break;
            default:                     default_instance = 3; break;
            }
        } catch (const std::exception&) {}
        const int gui_instance = gArgs.GetIntArg("-guiinstance", default_instance);
        if (gui_instance != 0) {
            gArgs.ForceSetArg("-proxy", strprintf("127.0.0.1:%d", 9150 + gui_instance * 10));
            gArgs.ForceSetArg("-torcontrol", strprintf("127.0.0.1:%d", 9151 + gui_instance * 10));
        }
    }

    /// 3. Application identification
    // must be set before OptionsModel is initialized or translations are loaded,
    // as it is used to locate QSettings
    QApplication::setOrganizationName(QAPP_ORG_NAME);
    QApplication::setOrganizationDomain(QAPP_ORG_DOMAIN);
    // Pick the network-specific QSettings application name UP FRONT — before
    // Intro::showIfNeeded() (step 5 below) reads the persisted "strDataDir"
    // override. Otherwise the separately-shipped mainnet and testnet apps both
    // read/write strDataDir under the shared QAPP_APP_NAME_DEFAULT namespace, so
    // the mainnet app inherits whatever datadir the testnet app last stored and
    // the two cannot run independently. gArgs.GetChainType() here reflects the
    // compile-time DEFAULT_CHAIN_TYPE plus any -chain/-testnet CLI flag; the
    // datadir's own bitcoin.conf isn't parsed until InitConfig (step 6), and the
    // app name is re-applied from Params() at the network-style step regardless,
    // so an in-config chain override still ends up correct. Keep this mapping in
    // sync with intro.cpp:NetworkSettingsAppName().
    const char* early_app_name = QAPP_APP_NAME_DEFAULT;
    try {
        switch (gArgs.GetChainType()) {
        case ChainType::TENSOR_MAIN: early_app_name = QAPP_APP_NAME_TENSOR; break;
        case ChainType::TENSOR_TEST: early_app_name = QAPP_APP_NAME_TENSOR_TEST; break;
        case ChainType::TENSOR_REG:  early_app_name = QAPP_APP_NAME_TENSOR_REG; break;
        case ChainType::TESTNET:     early_app_name = QAPP_APP_NAME_TESTNET; break;
        case ChainType::TESTNET4:    early_app_name = QAPP_APP_NAME_TESTNET4; break;
        case ChainType::SIGNET:      early_app_name = QAPP_APP_NAME_SIGNET; break;
        case ChainType::REGTEST:     early_app_name = QAPP_APP_NAME_REGTEST; break;
        case ChainType::MAIN:        early_app_name = QAPP_APP_NAME_DEFAULT; break;
        }
    } catch (const std::exception&) {
        // Unknown -chain string — keep the default; InitConfig (step 6) surfaces the error.
    }
    QApplication::setApplicationName(early_app_name);

    /// 4. Initialization of translations, so that intro dialog is in user's language
    // Now that QSettings are accessible, initialize translations
    QTranslator qtTranslatorBase, qtTranslator, translatorBase, translator;
    QTranslator tscTranslatorBase, tscTranslator;
    initTranslations(qtTranslatorBase, qtTranslator, translatorBase, translator, tscTranslatorBase, tscTranslator);

    // Show help message immediately after parsing command-line options (for "-lang") and setting locale,
    // but before showing splash screen.
    if (HelpRequested(gArgs) || gArgs.GetBoolArg("-version", false)) {
        HelpMessageDialog help(nullptr, gArgs.GetBoolArg("-version", false));
        help.showOrPrint();
        return EXIT_SUCCESS;
    }

    // Install global event filter that makes sure that long tooltips can be word-wrapped
    app.installEventFilter(new GUIUtil::ToolTipToRichTextFilter(TOOLTIP_WRAP_THRESHOLD, &app));

    /// 5. Now that settings and translations are available, ask user for data directory
    // User language is set up: pick a data directory
    bool did_show_intro = false;
    int64_t prune_MiB = 0;  // Intro dialog prune configuration
    // Gracefully exit if the user cancels
    if (!Intro::showIfNeeded(did_show_intro, prune_MiB)) return EXIT_SUCCESS;

    /// 6-7. Parse bitcoin.conf, determine network, switch to network specific
    /// options, and create datadir and settings.json.
    // - Do not call gArgs.GetDataDirNet() before this step finishes
    // - Do not call Params() before this step
    // - QSettings() will use the new application name after this, resulting in network-specific settings
    // - Needs to be done before createOptionsModel
    if (auto error = common::InitConfig(gArgs, ErrorSettingsRead)) {
        InitError(error->message, error->details);
        if (error->status == common::ConfigStatus::FAILED_WRITE) {
            // Show a custom error message to provide more information in the
            // case of a datadir write error.
            ErrorSettingsWrite(error->message, error->details);
        } else if (error->status != common::ConfigStatus::ABORTED) {
            // Show a generic message in other cases, and no additional error
            // message in the case of a read error if the user decided to abort.
            QMessageBox::critical(nullptr, CLIENT_NAME, QObject::tr("Error: %1").arg(QString::fromStdString(error->message.translated)));
        }
        return EXIT_FAILURE;
    }
#ifdef ENABLE_WALLET
    // Parse URIs on command line
    PaymentServer::ipcParseCommandLine(argc, argv);
#endif

    QScopedPointer<const NetworkStyle> networkStyle(NetworkStyle::instantiate(Params().GetChainType()));
    assert(!networkStyle.isNull());
    // Allow for separate UI settings for testnets
    QApplication::setApplicationName(networkStyle->getAppName());
    // Re-initialize translations after changing application name (language in network-specific settings can be different)
    initTranslations(qtTranslatorBase, qtTranslator, translatorBase, translator, tscTranslatorBase, tscTranslator);

#ifdef ENABLE_WALLET
    /// 8. URI IPC sending
    // - Do this early as we don't want to bother initializing if we are just calling IPC
    // - Do this *after* setting up the data directory, as the data directory hash is used in the name
    // of the server.
    // - Do this after creating app and setting up translations, so errors are
    // translated properly.
    if (PaymentServer::ipcSendCommandLine())
        exit(EXIT_SUCCESS);

    // Start up the payment server early, too, so impatient users that click on
    // bitcoin: links repeatedly have their payment requests routed to this process:
    if (WalletModel::isWalletEnabled()) {
        app.createPaymentServer();
    }
#endif // ENABLE_WALLET

    /// 9. Main GUI initialization
    // Install global event filter that makes sure that out-of-focus labels do not contain text cursor.
    app.installEventFilter(new GUIUtil::LabelOutOfFocusEventFilter(&app));
#if defined(Q_OS_WIN)
    // Install global event filter for processing Windows session related Windows messages (WM_QUERYENDSESSION and WM_ENDSESSION)
    // Note: it is safe to call app.node() in the lambda below despite the fact
    // that app.createNode() hasn't been called yet, because native events will
    // not be processed until the Qt event loop is executed.
    qApp->installNativeEventFilter(new WinShutdownMonitor([&app] { app.node().startShutdown(); }));
#endif
    // Install qDebug() message handler to route to debug.log
    qInstallMessageHandler(DebugMessageHandler);
    // Allow parameter interaction before we create the options model
    app.parameterSetup();
    GUIUtil::LogQtInfo();

#ifdef ENABLE_WALLET
    // Reap any tor process left behind by a prior launch BEFORE the node init
    // thread starts binding P2P / SOCKS / control ports. This must run:
    //   - after PaymentServer::ipcSendCommandLine() (above): a second invocation
    //     should hand off URIs to the running primary, NOT kill its tor.
    //   - after app.parameterSetup() / LogQtInfo(): bcore logging is wired up
    //     so reap traces land in debug.log.
    //   - before app.requestInitialize() (below): AppInitMain → CConnman::Init
    //     → BindListenPort runs on the InitExecutor thread, and a stuck tor
    //     from the previous _Exit holds the listener ports until reaped.
    {
        QString reap_datadir = GUIUtil::PathToQString(gArgs.GetDataDirNet());
        TorManager::ReapStaleTorEarly(reap_datadir);
    }
#endif

    if (gArgs.GetBoolArg("-splash", DEFAULT_SPLASHSCREEN) && !gArgs.GetBoolArg("-min", false))
        app.createSplashScreen(networkStyle.data());

    app.createNode(*init);

    // Load GUI settings from QSettings
    if (!app.createOptionsModel(gArgs.GetBoolArg("-resetguisettings", false))) {
        return EXIT_FAILURE;
    }

    if (did_show_intro) {
        // Store intro dialog settings other than datadir (network specific)
        app.InitPruneSetting(prune_MiB);
    }

    try
    {
        app.createWindow(networkStyle.data());
        // Perform base initialization before spinning up initialization/shutdown thread
        // This is acceptable because this function only contains steps that are quick to execute,
        // so the GUI thread won't be held up.
        if (app.baseInitialize()) {
            app.requestInitialize();
#if defined(Q_OS_WIN)
            WinShutdownMonitor::registerShutdownBlockReason(QObject::tr("%1 didn't yet exit safely…").arg(CLIENT_NAME), (HWND)app.getMainWinId());
#endif
            app.exec();
        } else {
            // A dialog with detailed error will have been shown by InitError()
            return EXIT_FAILURE;
        }
    } catch (const std::exception& e) {
        PrintExceptionContinue(&e, "Runaway exception");
        app.handleRunawayException(QString::fromStdString(app.node().getWarnings().translated));
    } catch (...) {
        PrintExceptionContinue(nullptr, "Runaway exception");
        app.handleRunawayException(QString::fromStdString(app.node().getWarnings().translated));
    }
    return app.node().getExitStatus();
}
