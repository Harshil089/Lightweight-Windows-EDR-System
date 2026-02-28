#pragma once

#include <QObject>
#include <QTimer>
#include <QString>
#include <memory>
#include <atomic>

// Forward declarations — avoid pulling Windows/backend headers into Qt UI layer
namespace cortex {
    class PipeClient;
    class SharedMemoryClient;
}

class IPCWorker : public QObject {
    Q_OBJECT
public:
    explicit IPCWorker(QObject* parent = nullptr);
    ~IPCWorker();

public slots:
    void startConnection();
    void stopConnection();

signals:
    void eventReceived(const QString& jsonLine);
    void statusUpdated(bool protectionActive, int activeIncidents,
                       int totalIncidents, int totalEvents, int highestRisk,
                       bool procMon, bool fileMon, bool netMon, bool regMon);
    void connectionStateChanged(bool connected);

private slots:
    void pollSharedMemory();

private:
    std::unique_ptr<cortex::PipeClient> pipe_client_;
    std::unique_ptr<cortex::SharedMemoryClient> shm_client_;
    QTimer* shm_poll_timer_{nullptr};
    std::atomic<bool> was_connected_{false};
};
