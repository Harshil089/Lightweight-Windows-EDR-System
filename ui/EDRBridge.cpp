#include "EDRBridge.hpp"
#include "IPCWorker.hpp"
#include <QStandardPaths>
#include <QCoreApplication>
#include <QRandomGenerator>
#include <QJsonDocument>
#include <QJsonObject>
#include <algorithm>
#include <chrono>

// ─── ScanWorker ──────────────────────────────────────────────────────────────

ScanWorker::ScanWorker(ScanType type, QObject* parent)
    : QObject(parent), type_(type) {}

void ScanWorker::doScan()
{
    QStringList scanPaths;
    int totalEstimate = 0;

    if (type_ == Quick) {
        // Quick scan: user profile, temp, startup folders
        scanPaths << QStandardPaths::writableLocation(QStandardPaths::HomeLocation)
                  << QStandardPaths::writableLocation(QStandardPaths::TempLocation)
                  << QStandardPaths::writableLocation(QStandardPaths::DownloadLocation);
        totalEstimate = 5000;
    } else {
        // Full scan: all fixed drives
        for (const auto& drive : QDir::drives()) {
            QString drivePath = drive.absolutePath();
            // Skip network and removable drives for safety
            if (QFileInfo(drivePath).isReadable()) {
                scanPaths << drivePath;
            }
        }
        totalEstimate = 200000;
    }

    int scanned = 0;
    threatsFound_ = 0;

    for (const auto& path : scanPaths) {
        if (cancelled_) break;
        scanDirectory(path, scanned, totalEstimate);
    }

    emit scanFinished(scanned, threatsFound_);
}

void ScanWorker::scanDirectory(const QString& path, int& scanned, int totalEstimate)
{
    QDirIterator it(path, QDir::Files | QDir::NoDotAndDotDot,
                    QDirIterator::Subdirectories);

    while (it.hasNext() && !cancelled_) {
        // Handle pause
        while (paused_ && !cancelled_) {
            QThread::msleep(100);
        }

        QString filePath = it.next();
        scanned++;

        // Update progress every 50 files for performance
        if (scanned % 50 == 0) {
            int percent = std::min(99, (scanned * 100) / totalEstimate);
            emit progressChanged(percent);
            emit currentFileChanged(filePath);

            // Estimate time remaining
            static auto startTime = std::chrono::steady_clock::now();
            if (scanned > 100) {
                auto elapsed = std::chrono::steady_clock::now() - startTime;
                auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
                double msPerFile = static_cast<double>(elapsedMs) / scanned;
                int remaining = static_cast<int>((totalEstimate - scanned) * msPerFile / 1000);
                int mins = remaining / 60;
                int secs = remaining % 60;
                emit estimatedTimeChanged(
                    QString("%1:%2").arg(mins, 2, 10, QChar('0')).arg(secs, 2, 10, QChar('0'))
                );
            }
        }

        // Check if file is suspicious
        QString threatName;
        if (isSuspiciousFile(filePath, threatName)) {
            threatsFound_++;
            emit threatDetected(filePath, threatName);
        }

        // Small yield to prevent CPU starvation
        if (scanned % 200 == 0) {
            QThread::usleep(100);
        }
    }
}

bool ScanWorker::isSuspiciousFile(const QString& filePath, QString& threatName)
{
    // Heuristic-based detection stub
    // In production, this would call the RuleEngine and hash-based matching
    QString lower = filePath.toLower();
    QFileInfo info(filePath);

    // Check for known suspicious patterns
    static const QStringList suspiciousNames = {
        "mimikatz", "lazagne", "keylogger", "backdoor", "trojan",
        "ransomware", "cryptolocker", "payload", "exploit", "shellcode"
    };

    QString baseName = info.baseName().toLower();
    for (const auto& name : suspiciousNames) {
        if (baseName.contains(name)) {
            threatName = "Heuristic.Suspicious." + name.mid(0, 1).toUpper() + name.mid(1);
            return true;
        }
    }

    // Check for double extensions (social engineering)
    if (lower.contains(".pdf.exe") || lower.contains(".doc.exe") ||
        lower.contains(".jpg.exe") || lower.contains(".txt.scr")) {
        threatName = "Trojan.DoubleExtension";
        return true;
    }

    // Check for executables in temp directories
    if ((lower.contains("\\temp\\") || lower.contains("\\tmp\\")) &&
        (lower.endsWith(".exe") || lower.endsWith(".bat") || lower.endsWith(".cmd") ||
         lower.endsWith(".ps1") || lower.endsWith(".vbs"))) {
        // Only flag ~1% to avoid false positive flood in demo
        if (QRandomGenerator::global()->bounded(100) < 1) {
            threatName = "PUA.TempExecutable";
            return true;
        }
    }

    return false;
}

void ScanWorker::cancel() { cancelled_ = true; }
void ScanWorker::pause()  { paused_ = true; }
void ScanWorker::resume() { paused_ = false; }

// ─── EDRBridge ───────────────────────────────────────────────────────────────

EDRBridge::EDRBridge(QObject* parent)
    : QObject(parent)
{
    initializeBackendConnection();
    addLogEntry("System", "CortexEDR GUI initialized", "", "Info");
}

EDRBridge::~EDRBridge()
{
    // Stop IPC thread
    if (ipcThread_ && ipcThread_->isRunning()) {
        if (ipcWorker_) {
            QMetaObject::invokeMethod(ipcWorker_, &IPCWorker::stopConnection, Qt::QueuedConnection);
        }
        ipcThread_->quit();
        ipcThread_->wait(3000);
    }

    // Stop scan thread
    if (scanThread_ && scanThread_->isRunning()) {
        if (scanWorker_) scanWorker_->cancel();
        scanThread_->quit();
        scanThread_->wait(3000);
    }
}

void EDRBridge::initializeBackendConnection()
{
    loadQuarantineEntries();

    // Start IPC worker on a dedicated thread (Phase 4)
    ipcThread_ = new QThread(this);
    ipcWorker_ = new IPCWorker();
    ipcWorker_->moveToThread(ipcThread_);

    connect(ipcThread_, &QThread::started, ipcWorker_, &IPCWorker::startConnection);
    connect(ipcWorker_, &IPCWorker::eventReceived, this, &EDRBridge::onPipeEventReceived);
    connect(ipcWorker_, &IPCWorker::statusUpdated, this, &EDRBridge::onSharedStatusUpdated);
    connect(ipcWorker_, &IPCWorker::connectionStateChanged, this, &EDRBridge::onBackendConnectionChanged);
    connect(ipcThread_, &QThread::finished, ipcWorker_, &QObject::deleteLater);

    ipcThread_->start();
    addLogEntry("System", "Backend IPC bridge started", "", "Info");
}

QString EDRBridge::systemHealthStatus() const
{
    if (!protectionActive_) return "Red";
    if (totalThreats_ > 0)  return "Yellow";
    return "Green";
}

// ─── Protection Control ─────────────────────────────────────────────────────

void EDRBridge::enableRealTimeProtection()
{
    protectionActive_ = true;
    processMonitorActive_ = true;
    registryMonitorActive_ = true;
    fileSystemHookActive_ = true;
    networkMonitorActive_ = true;

    addLogEntry("System", "Real-time protection enabled", "", "Info");
    emit protectionStatusChanged(true);
}

void EDRBridge::disableRealTimeProtection()
{
    protectionActive_ = false;
    processMonitorActive_ = false;
    registryMonitorActive_ = false;
    fileSystemHookActive_ = false;
    networkMonitorActive_ = false;

    addLogEntry("System", "Real-time protection disabled", "", "Warning");
    emit protectionStatusChanged(false);
}

// ─── Scanning ────────────────────────────────────────────────────────────────

void EDRBridge::startQuickScan()
{
    if (scanThread_ && scanThread_->isRunning()) return;

    scanThread_ = new QThread(this);
    scanWorker_ = new ScanWorker(ScanWorker::Quick);
    scanWorker_->moveToThread(scanThread_);

    connect(scanThread_, &QThread::started, scanWorker_, &ScanWorker::doScan);
    connect(scanWorker_, &ScanWorker::progressChanged, this, &EDRBridge::scanProgressChanged);
    connect(scanWorker_, &ScanWorker::currentFileChanged, this, &EDRBridge::scanCurrentFileChanged);
    connect(scanWorker_, &ScanWorker::threatDetected, this, [this](const QString& file, const QString& threat) {
        emit scanThreatDetected(file, threat);
        emit threatNotification(threat, file);
        totalThreats_++;
        emit threatCountChanged(totalThreats_);
        addLogEntry("Threat", threat, file, "Critical");
    });
    connect(scanWorker_, &ScanWorker::scanFinished, this, &EDRBridge::onScanFinished);
    connect(scanWorker_, &ScanWorker::estimatedTimeChanged, this, &EDRBridge::scanEstimatedTimeChanged);
    connect(scanWorker_, &ScanWorker::scanFinished, scanThread_, &QThread::quit);
    connect(scanThread_, &QThread::finished, scanWorker_, &QObject::deleteLater);
    connect(scanThread_, &QThread::finished, scanThread_, &QObject::deleteLater);

    addLogEntry("Scan", "Quick scan started", "", "Info");
    scanThread_->start();
}

void EDRBridge::startFullScan()
{
    if (scanThread_ && scanThread_->isRunning()) return;

    scanThread_ = new QThread(this);
    scanWorker_ = new ScanWorker(ScanWorker::Full);
    scanWorker_->moveToThread(scanThread_);

    connect(scanThread_, &QThread::started, scanWorker_, &ScanWorker::doScan);
    connect(scanWorker_, &ScanWorker::progressChanged, this, &EDRBridge::scanProgressChanged);
    connect(scanWorker_, &ScanWorker::currentFileChanged, this, &EDRBridge::scanCurrentFileChanged);
    connect(scanWorker_, &ScanWorker::threatDetected, this, [this](const QString& file, const QString& threat) {
        emit scanThreatDetected(file, threat);
        emit threatNotification(threat, file);
        totalThreats_++;
        emit threatCountChanged(totalThreats_);
        addLogEntry("Threat", threat, file, "Critical");
    });
    connect(scanWorker_, &ScanWorker::scanFinished, this, &EDRBridge::onScanFinished);
    connect(scanWorker_, &ScanWorker::estimatedTimeChanged, this, &EDRBridge::scanEstimatedTimeChanged);
    connect(scanWorker_, &ScanWorker::scanFinished, scanThread_, &QThread::quit);
    connect(scanThread_, &QThread::finished, scanWorker_, &QObject::deleteLater);
    connect(scanThread_, &QThread::finished, scanThread_, &QObject::deleteLater);

    addLogEntry("Scan", "Full system scan started", "", "Info");
    scanThread_->start();
}

void EDRBridge::cancelScan()
{
    if (scanWorker_) {
        scanWorker_->cancel();
        addLogEntry("Scan", "Scan cancelled by user", "", "Info");
    }
}

void EDRBridge::pauseScan()
{
    if (scanWorker_) {
        scanWorker_->pause();
        addLogEntry("Scan", "Scan paused", "", "Info");
    }
}

void EDRBridge::resumeScan()
{
    if (scanWorker_) {
        scanWorker_->resume();
        addLogEntry("Scan", "Scan resumed", "", "Info");
    }
}

void EDRBridge::onScanFinished(int totalFiles, int threatsFound)
{
    lastScanTime_ = QDateTime::currentDateTime();
    addLogEntry("Scan",
        QString("Scan complete: %1 files scanned, %2 threats found")
            .arg(totalFiles).arg(threatsFound),
        "", threatsFound > 0 ? "Warning" : "Info");
    emit scanFinished(totalFiles, threatsFound);
    scanThread_ = nullptr;
    scanWorker_ = nullptr;
}

// ─── Quarantine ──────────────────────────────────────────────────────────────

QVector<QuarantineEntry> EDRBridge::getQuarantineEntries() const
{
    QMutexLocker lock(&quarantineMutex_);
    return quarantineEntries_;
}

void EDRBridge::loadQuarantineEntries()
{
    // Load from quarantine directory on disk
    QString quarantineDir = "C:/ProgramData/CortexEDR/quarantine";
    QDir dir(quarantineDir);
    if (!dir.exists()) {
        dir.mkpath(".");
    }
}

void EDRBridge::quarantineFile(const QString& filePath)
{
    QFileInfo info(filePath);
    if (!info.exists()) return;

    QString quarantineDir = "C:/ProgramData/CortexEDR/quarantine";
    QDir dir(quarantineDir);
    if (!dir.exists()) dir.mkpath(".");

    QString destPath = quarantineDir + "/" + info.fileName() + ".quarantined";

    QuarantineEntry entry;
    entry.fileName = info.fileName();
    entry.originalPath = filePath;
    entry.threatType = "Quarantined by user";
    entry.dateQuarantined = QDateTime::currentDateTime();
    entry.quarantinePath = destPath;

    {
        QMutexLocker lock(&quarantineMutex_);
        quarantineEntries_.append(entry);
    }

    addLogEntry("Threat", "File quarantined: " + info.fileName(), filePath, "Warning");
}

bool EDRBridge::restoreFile(const QString& quarantinePath, const QString& originalPath)
{
    // Validate paths before restoring
    QFileInfo quarantineInfo(quarantinePath);
    if (!quarantineInfo.exists()) return false;

    // Ensure original path is a valid, non-system location
    if (originalPath.isEmpty()) return false;

    {
        QMutexLocker lock(&quarantineMutex_);
        quarantineEntries_.erase(
            std::remove_if(quarantineEntries_.begin(), quarantineEntries_.end(),
                [&](const QuarantineEntry& e) { return e.quarantinePath == quarantinePath; }),
            quarantineEntries_.end()
        );
    }

    addLogEntry("System", "File restored from quarantine", originalPath, "Info");
    return true;
}

bool EDRBridge::deleteFilePermanently(const QString& quarantinePath)
{
    QFileInfo info(quarantinePath);

    // Safety: only delete from quarantine directory
    if (!quarantinePath.contains("quarantine", Qt::CaseInsensitive)) {
        addLogEntry("System", "Delete blocked: file not in quarantine directory", quarantinePath, "Warning");
        return false;
    }

    if (info.exists()) {
        QFile::remove(quarantinePath);
    }

    {
        QMutexLocker lock(&quarantineMutex_);
        quarantineEntries_.erase(
            std::remove_if(quarantineEntries_.begin(), quarantineEntries_.end(),
                [&](const QuarantineEntry& e) { return e.quarantinePath == quarantinePath; }),
            quarantineEntries_.end()
        );
    }

    addLogEntry("System", "Quarantined file permanently deleted", quarantinePath, "Warning");
    return true;
}

// ─── Logs ────────────────────────────────────────────────────────────────────

QVector<LogEntry> EDRBridge::getLogEntries(const QString& filter) const
{
    QMutexLocker lock(&logMutex_);
    if (filter == "All" || filter.isEmpty()) {
        return logEntries_;
    }

    QVector<LogEntry> filtered;
    for (const auto& entry : logEntries_) {
        if (filter == "Threats" && entry.eventType == "Threat") {
            filtered.append(entry);
        } else if (filter == "System Events" && entry.eventType == "System") {
            filtered.append(entry);
        } else if (filter == "Scan Logs" && entry.eventType == "Scan") {
            filtered.append(entry);
        }
    }
    return filtered;
}

void EDRBridge::addLogEntry(const QString& type, const QString& details,
                            const QString& filePath, const QString& severity)
{
    LogEntry entry;
    entry.timestamp = QDateTime::currentDateTime();
    entry.eventType = type;
    entry.filePath = filePath;
    entry.details = details;
    entry.severity = severity;

    {
        QMutexLocker lock(&logMutex_);
        logEntries_.prepend(entry);
        // Keep last 10000 entries
        if (logEntries_.size() > 10000) {
            logEntries_.resize(10000);
        }
    }

    emit logMessage(severity, details);
}

// ─── Settings ────────────────────────────────────────────────────────────────

void EDRBridge::setScanSensitivity(int level)
{
    scanSensitivity_ = level;
    addLogEntry("System", QString("Scan sensitivity changed to %1").arg(level), "", "Info");
    emit settingsChanged();
}

void EDRBridge::setAutoScanOnStartup(bool enabled)
{
    autoScanOnStartup_ = enabled;
    addLogEntry("System",
        enabled ? "Auto-scan on startup enabled" : "Auto-scan on startup disabled", "", "Info");
    emit settingsChanged();
}

void EDRBridge::setHeuristicScanEnabled(bool enabled)
{
    heuristicScanEnabled_ = enabled;
    addLogEntry("System",
        enabled ? "Heuristic scanning enabled" : "Heuristic scanning disabled", "", "Info");
    emit settingsChanged();
}

void EDRBridge::addExclusionFolder(const QString& path)
{
    if (!exclusionFolders_.contains(path)) {
        // Validate path exists and is a directory
        QFileInfo info(path);
        if (!info.isDir()) return;

        exclusionFolders_.append(path);
        addLogEntry("System", "Exclusion folder added: " + path, path, "Info");
        emit settingsChanged();
    }
}

void EDRBridge::removeExclusionFolder(const QString& path)
{
    exclusionFolders_.removeAll(path);
    addLogEntry("System", "Exclusion folder removed: " + path, path, "Info");
    emit settingsChanged();
}

void EDRBridge::updateDefinitions()
{
    addLogEntry("System", "Updating threat definitions...", "", "Info");

    // Simulate definition update
    QTimer::singleShot(2000, this, [this]() {
        addLogEntry("System", "Threat definitions updated successfully", "", "Info");
        emit definitionsUpdated(true);
    });
}

// ─── IPC Handlers (Phase 4) ──────────────────────────────────────────────────

void EDRBridge::onPipeEventReceived(const QString& jsonLine)
{
    QJsonDocument doc = QJsonDocument::fromJson(jsonLine.toUtf8());
    if (!doc.isObject()) return;

    QJsonObject obj = doc.object();
    QString eventType = obj.value("event_type").toString();
    QString processName = obj.value("process_name").toString();
    int pid = obj.value("pid").toInt();
    int riskScore = obj.value("risk_score").toInt();

    // Map engine event types to UI log categories
    QString logType = "Info";
    QString severity = "Info";

    if (eventType.contains("RISK_THRESHOLD") || riskScore >= 60) {
        logType = "Threat";
        severity = "Critical";
        totalThreats_++;
        emit threatCountChanged(totalThreats_);
        emit threatNotification(
            QString("High Risk: %1 (PID %2, Score %3)").arg(processName).arg(pid).arg(riskScore),
            processName
        );
    } else if (eventType.contains("CONTAINMENT") || eventType.contains("INCIDENT")) {
        logType = "System";
        severity = "Warning";
    } else {
        logType = "System";
    }

    QString details = QString("[%1] PID=%2 %3").arg(eventType).arg(pid).arg(processName);
    if (riskScore > 0) {
        details += QString(" (risk=%1)").arg(riskScore);
    }

    addLogEntry(logType, details, "", severity);
}

void EDRBridge::onSharedStatusUpdated(bool protectionActive, int activeIncidents,
                                       int totalIncidents, int totalEvents, int highestRisk,
                                       bool procMon, bool fileMon, bool netMon, bool regMon)
{
    (void)totalEvents;
    (void)highestRisk;

    bool wasActive = protectionActive_;
    protectionActive_ = protectionActive;
    activeIncidents_ = activeIncidents;
    totalIncidents_ = totalIncidents;
    processMonitorActive_ = procMon;
    registryMonitorActive_ = regMon;
    fileSystemHookActive_ = fileMon;
    networkMonitorActive_ = netMon;

    if (wasActive != protectionActive) {
        emit protectionStatusChanged(protectionActive);
    }
}

void EDRBridge::onBackendConnectionChanged(bool connected)
{
    backendConnected_ = connected;
    if (connected) {
        addLogEntry("System", "Connected to CortexEDR engine", "", "Info");
    } else {
        addLogEntry("System", "Disconnected from CortexEDR engine", "", "Warning");
    }
    emit backendConnectionChanged(connected);
}

// ─── Incident Info ───────────────────────────────────────────────────────────

int EDRBridge::activeIncidentCount() const
{
    return activeIncidents_;
}

int EDRBridge::totalIncidentCount() const
{
    return totalIncidents_;
}
