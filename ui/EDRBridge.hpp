#pragma once

#include <QObject>
#include <QString>
#include <QThread>
#include <QTimer>
#include <QMutex>
#include <QDateTime>
#include <QDir>
#include <QFileInfo>
#include <QDirIterator>
#include <QFile>
#include <atomic>

// Log entry for the UI log viewer
struct LogEntry {
    QDateTime timestamp;
    QString eventType;   // "Threat", "System", "Scan", "Info"
    QString filePath;
    QString details;
    QString severity;    // "Info", "Warning", "Critical"
};

// Quarantine entry for the quarantine table
struct QuarantineEntry {
    QString fileName;
    QString originalPath;
    QString threatType;
    QDateTime dateQuarantined;
    QString quarantinePath;
};

// Scan result for UI display
struct ScanResult {
    QString filePath;
    QString threatName;
    QString action;      // "Quarantined", "Deleted", "Ignored"
    QDateTime detected;
};

// Thread-safe scan worker that runs in a background QThread
class ScanWorker : public QObject {
    Q_OBJECT
public:
    enum ScanType { Quick, Full };

    explicit ScanWorker(ScanType type, QObject* parent = nullptr);

public slots:
    void doScan();
    void cancel();
    void pause();
    void resume();

signals:
    void progressChanged(int percent);
    void currentFileChanged(const QString& filePath);
    void threatDetected(const QString& filePath, const QString& threatName);
    void scanFinished(int totalFiles, int threatsFound);
    void estimatedTimeChanged(const QString& timeRemaining);

private:
    void scanDirectory(const QString& path, int& scanned, int totalEstimate);
    bool isSuspiciousFile(const QString& filePath, QString& threatName);

    ScanType type_;
    std::atomic<bool> cancelled_{false};
    std::atomic<bool> paused_{false};
    int threatsFound_{0};
};

// Main bridge connecting Qt UI signals/slots to the C++ backend
class EDRBridge : public QObject {
    Q_OBJECT
    Q_PROPERTY(bool protectionActive READ isProtectionActive NOTIFY protectionStatusChanged)
    Q_PROPERTY(int totalThreats READ totalThreats NOTIFY threatCountChanged)

public:
    explicit EDRBridge(QObject* parent = nullptr);
    ~EDRBridge();

    // Protection status
    bool isProtectionActive() const { return protectionActive_; }
    int totalThreats() const { return totalThreats_; }
    QDateTime lastScanTime() const { return lastScanTime_; }
    QString systemHealthStatus() const;

    // Monitoring status queries
    bool isProcessMonitorActive() const { return processMonitorActive_; }
    bool isRegistryMonitorActive() const { return registryMonitorActive_; }
    bool isFileSystemHookActive() const { return fileSystemHookActive_; }
    bool isNetworkMonitorActive() const { return networkMonitorActive_; }

    // Quarantine
    QVector<QuarantineEntry> getQuarantineEntries() const;
    bool restoreFile(const QString& quarantinePath, const QString& originalPath);
    bool deleteFilePermanently(const QString& quarantinePath);

    // Logs
    QVector<LogEntry> getLogEntries(const QString& filter = "All") const;

    // Settings
    int scanSensitivity() const { return scanSensitivity_; }
    bool autoScanOnStartup() const { return autoScanOnStartup_; }
    bool heuristicScanEnabled() const { return heuristicScanEnabled_; }
    QStringList exclusionFolders() const { return exclusionFolders_; }

    // Incident info
    int activeIncidentCount() const;
    int totalIncidentCount() const;

public slots:
    // Protection control
    void enableRealTimeProtection();
    void disableRealTimeProtection();

    // Scanning
    void startQuickScan();
    void startFullScan();
    void cancelScan();
    void pauseScan();
    void resumeScan();

    // Settings
    void setScanSensitivity(int level);
    void setAutoScanOnStartup(bool enabled);
    void setHeuristicScanEnabled(bool enabled);
    void addExclusionFolder(const QString& path);
    void removeExclusionFolder(const QString& path);
    void updateDefinitions();

    // Quarantine actions
    void quarantineFile(const QString& filePath);

signals:
    void protectionStatusChanged(bool active);
    void threatCountChanged(int count);
    void scanProgressChanged(int percent);
    void scanCurrentFileChanged(const QString& filePath);
    void scanThreatDetected(const QString& filePath, const QString& threatName);
    void scanFinished(int totalFiles, int threatsFound);
    void scanEstimatedTimeChanged(const QString& timeRemaining);
    void logMessage(const QString& level, const QString& message);
    void threatNotification(const QString& threatName, const QString& filePath);
    void definitionsUpdated(bool success);
    void settingsChanged();

private slots:
    void onScanFinished(int totalFiles, int threatsFound);

private:
    void addLogEntry(const QString& type, const QString& details,
                     const QString& filePath = "", const QString& severity = "Info");
    void initializeBackendConnection();
    void loadQuarantineEntries();

    // State
    bool protectionActive_{false};
    int totalThreats_{0};
    QDateTime lastScanTime_;
    int scanSensitivity_{50};
    bool autoScanOnStartup_{false};
    bool heuristicScanEnabled_{true};
    QStringList exclusionFolders_;

    // Monitoring states
    bool processMonitorActive_{false};
    bool registryMonitorActive_{false};
    bool fileSystemHookActive_{false};
    bool networkMonitorActive_{false};

    // Scan thread
    QThread* scanThread_{nullptr};
    ScanWorker* scanWorker_{nullptr};

    // Data
    mutable QMutex logMutex_;
    QVector<LogEntry> logEntries_;
    mutable QMutex quarantineMutex_;
    QVector<QuarantineEntry> quarantineEntries_;

    // Status polling
    QTimer* statusTimer_{nullptr};
};
