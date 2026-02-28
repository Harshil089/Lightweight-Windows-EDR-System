#include "ui/IPCWorker.hpp"
#include "ipc/PipeClient.hpp"
#include "ipc/SharedMemoryClient.hpp"

IPCWorker::IPCWorker(QObject* parent)
    : QObject(parent)
    , pipe_client_(std::make_unique<cortex::PipeClient>())
    , shm_client_(std::make_unique<cortex::SharedMemoryClient>())
{
}

IPCWorker::~IPCWorker() {
    stopConnection();
}

void IPCWorker::startConnection() {
    // Start pipe client — reads NDJSON events from the engine
    pipe_client_->Start("\\\\.\\pipe\\CortexEDR",
        [this](const std::string& json_line) {
            // Marshal callback from pipe reader thread to Qt thread via signal
            QString qline = QString::fromStdString(json_line);
            QMetaObject::invokeMethod(this, [this, qline]() {
                emit eventReceived(qline);
            }, Qt::QueuedConnection);
        }
    );

    // Start shared memory polling timer
    shm_poll_timer_ = new QTimer(this);
    connect(shm_poll_timer_, &QTimer::timeout, this, &IPCWorker::pollSharedMemory);
    shm_poll_timer_->start(2000);  // Poll every 2 seconds

    // Try initial shared memory connection
    pollSharedMemory();
}

void IPCWorker::stopConnection() {
    if (shm_poll_timer_) {
        shm_poll_timer_->stop();
        delete shm_poll_timer_;
        shm_poll_timer_ = nullptr;
    }

    if (pipe_client_) {
        pipe_client_->Stop();
    }

    if (shm_client_) {
        shm_client_->Disconnect();
    }
}

void IPCWorker::pollSharedMemory() {
    // Try to connect if not already connected
    if (!shm_client_->IsConnected()) {
        shm_client_->Connect("Local\\CortexEDR_SharedStatus");
    }

    bool now_connected = pipe_client_->IsConnected() || shm_client_->IsConnected();
    if (now_connected != was_connected_.load()) {
        was_connected_ = now_connected;
        emit connectionStateChanged(now_connected);
    }

    // Read shared memory status
    auto status = shm_client_->Read();
    if (status.has_value()) {
        emit statusUpdated(
            status->protection_active != 0,
            static_cast<int>(status->active_incident_count),
            static_cast<int>(status->total_incident_count),
            static_cast<int>(status->total_event_count),
            static_cast<int>(status->highest_risk_score),
            status->process_monitor_active != 0,
            status->file_monitor_active != 0,
            status->network_monitor_active != 0,
            status->registry_monitor_active != 0
        );
    }
}
