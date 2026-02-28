// Include Windows headers first with all necessary macro fixes
#include "core/WindowsHeaders.hpp"

#include "core/EventBus.hpp"
#include "core/Logger.hpp"
#include "core/ThreadPool.hpp"
#include "collectors/ProcessMonitor.hpp"
#include "collectors/FileMonitor.hpp"
#include "collectors/NetworkMonitor.hpp"
#include "collectors/RegistryMonitor.hpp"
#include "engine/RiskScorer.hpp"
#include "engine/RuleEngine.hpp"
#include "engine/BehaviorCorrelator.hpp"
#include "response/ContainmentManager.hpp"
#include "response/IncidentManager.hpp"
#include "telemetry/TelemetryExporter.hpp"

#include <yaml-cpp/yaml.h>
#include <iostream>
#include <csignal>
#include <atomic>
#include <chrono>
#include <thread>

namespace cortex {

std::atomic<bool> g_running{true};

void SignalHandler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        LOG_INFO("Received shutdown signal");
        g_running = false;
    }
}

class CortexEDR {
public:
    CortexEDR() : risk_scorer_(std::make_unique<RiskScorer>()) {}

    bool Initialize() {
        LOG_INFO("Initializing CortexEDR...");

        // Initialize the async thread pool for EventBus (2 worker threads)
        EventBus::Instance().InitAsyncPool(2);

        event_subscriber_id_ = EventBus::Instance().Subscribe(
            EventType::PROCESS_CREATE,
            [this](const Event& event) { OnEvent(event); }
        );

        EventBus::Instance().Subscribe(
            EventType::PROCESS_TERMINATE,
            [this](const Event& event) { OnEvent(event); }
        );

        EventBus::Instance().Subscribe(
            EventType::FILE_CREATE,
            [this](const Event& event) { OnEvent(event); }
        );

        EventBus::Instance().Subscribe(
            EventType::FILE_MODIFY,
            [this](const Event& event) { OnEvent(event); }
        );

        EventBus::Instance().Subscribe(
            EventType::FILE_DELETE,
            [this](const Event& event) { OnEvent(event); }
        );

        EventBus::Instance().Subscribe(
            EventType::NETWORK_CONNECT,
            [this](const Event& event) { OnEvent(event); }
        );

        EventBus::Instance().Subscribe(
            EventType::REGISTRY_WRITE,
            [this](const Event& event) { OnEvent(event); }
        );

        LOG_INFO("Event subscriptions configured");

        // Initialize Phase 2 components
        LOG_INFO("Initializing Phase 2 components...");

        // RuleEngine
        rule_engine_ = std::make_unique<RuleEngine>();
        if (!rule_engine_->Initialize("config/rules.yaml", risk_scorer_.get())) {
            LOG_WARN("Failed to initialize RuleEngine, continuing without rules");
        }

        // BehaviorCorrelator
        behavior_correlator_ = std::make_unique<BehaviorCorrelator>();
        behavior_correlator_->Initialize(risk_scorer_.get());

        // ContainmentManager
        containment_manager_ = std::make_unique<ContainmentManager>();
        containment_manager_->Initialize(
            false,  // auto_contain = false (manual mode for safety)
            true,   // require_confirmation = true
            "C:\\ProgramData\\CortexEDR\\quarantine"
        );

        LOG_INFO("Phase 2 components initialized");

        // Initialize Phase 3 components
        LOG_INFO("Initializing Phase 3 components...");

        // IncidentManager
        incident_manager_ = std::make_unique<IncidentManager>();
        incident_manager_->Initialize(risk_scorer_.get(), "incidents");

        // TelemetryExporter - load config from config.yaml
        bool telemetry_enabled = true;
        std::string telemetry_export_path = "telemetry/events.ndjson";
        bool telemetry_named_pipe = false;
        std::string telemetry_pipe_name = "\\\\.\\pipe\\CortexEDR";

        try {
            YAML::Node config = YAML::LoadFile("config/config.yaml");
            if (config["telemetry"]) {
                auto telem = config["telemetry"];
                if (telem["enabled"])           telemetry_enabled = telem["enabled"].as<bool>();
                if (telem["export_path"])        telemetry_export_path = telem["export_path"].as<std::string>();
                if (telem["enable_named_pipe"])   telemetry_named_pipe = telem["enable_named_pipe"].as<bool>();
                if (telem["named_pipe_name"])     telemetry_pipe_name = telem["named_pipe_name"].as<std::string>();
            }
        } catch (const std::exception& ex) {
            LOG_WARN("Failed to load telemetry config, using defaults: {}", ex.what());
        }

        telemetry_exporter_ = std::make_unique<TelemetryExporter>();
        telemetry_exporter_->Initialize(risk_scorer_.get(), telemetry_enabled,
                                         telemetry_export_path, telemetry_named_pipe,
                                         telemetry_pipe_name);

        LOG_INFO("Phase 3 components initialized");
        return true;
    }

    bool Start() {
        LOG_INFO("Starting CortexEDR collectors...");

        process_monitor_ = std::make_unique<ProcessMonitor>();
        if (!process_monitor_->Start()) {
            LOG_ERROR("Failed to start ProcessMonitor - process events will not be collected");
            process_monitor_.reset();
        }

        std::vector<std::wstring> watch_paths = {
            L"C:\\Windows\\System32",
            L"C:\\Windows\\Temp"
        };
        file_monitor_ = std::make_unique<FileMonitor>(watch_paths);
        if (!file_monitor_->Start()) {
            LOG_ERROR("Failed to start FileMonitor");
            return false;
        }

        network_monitor_ = std::make_unique<NetworkMonitor>(std::chrono::seconds(2));
        if (!network_monitor_->Start()) {
            LOG_ERROR("Failed to start NetworkMonitor");
            return false;
        }

        registry_monitor_ = std::make_unique<RegistryMonitor>();
        if (!registry_monitor_->Start()) {
            LOG_ERROR("Failed to start RegistryMonitor");
            return false;
        }

        LOG_INFO("All collectors started successfully");

        // Start Phase 2 components
        LOG_INFO("Starting Phase 2 components...");

        if (rule_engine_) {
            rule_engine_->Start();
        }

        if (behavior_correlator_) {
            behavior_correlator_->Start();
        }

        if (containment_manager_) {
            containment_manager_->Start();
        }

        LOG_INFO("Phase 2 components started");

        // Start Phase 3 components
        LOG_INFO("Starting Phase 3 components...");

        if (incident_manager_) {
            incident_manager_->Start();
        }

        if (telemetry_exporter_) {
            telemetry_exporter_->Start();
        }

        LOG_INFO("Phase 3 components started");
        return true;
    }

    void Run() {
        LOG_INFO("CortexEDR is now running. Press Ctrl+C to stop.");

        size_t event_count = 0;
        auto start_time = std::chrono::steady_clock::now();

        while (g_running) {
            std::this_thread::sleep_for(std::chrono::seconds(10));

            auto current_time = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                current_time - start_time
            ).count();

            LOG_INFO("Status: Uptime={}s, Events processed={}", elapsed, event_count);
        }
    }

    void Stop() {
        LOG_INFO("Stopping CortexEDR...");

        // Stop Phase 3 components first
        if (telemetry_exporter_) {
            telemetry_exporter_->Stop();
        }

        if (incident_manager_) {
            incident_manager_->Stop();
        }

        // Stop Phase 2 components
        if (containment_manager_) {
            containment_manager_->Stop();
        }

        if (behavior_correlator_) {
            behavior_correlator_->Stop();
        }

        if (rule_engine_) {
            rule_engine_->Stop();
        }

        // Stop collectors
        if (registry_monitor_) {
            registry_monitor_->Stop();
        }

        if (network_monitor_) {
            network_monitor_->Stop();
        }

        if (file_monitor_) {
            file_monitor_->Stop();
        }

        if (process_monitor_) {
            process_monitor_->Stop();
        }

        // Shutdown the async publish pool last — after all components stop publishing
        EventBus::Instance().ShutdownAsyncPool();

        LOG_INFO("All components stopped");
    }

private:
    void OnEvent(const Event& event) {
        event_count_++;

        risk_scorer_->ProcessEvent(event);

        if (event.pid > 0) {
            auto risk = risk_scorer_->GetProcessRiskScore(event.pid);
            if (risk.score >= 60) {
                LOG_WARN("HIGH RISK DETECTED: PID={} Score={} Process={}",
                        event.pid, risk.score, event.process_name);
            }
        }
    }

    std::unique_ptr<ProcessMonitor> process_monitor_;
    std::unique_ptr<FileMonitor> file_monitor_;
    std::unique_ptr<NetworkMonitor> network_monitor_;
    std::unique_ptr<RegistryMonitor> registry_monitor_;
    std::unique_ptr<RiskScorer> risk_scorer_;
    std::unique_ptr<RuleEngine> rule_engine_;
    std::unique_ptr<BehaviorCorrelator> behavior_correlator_;
    std::unique_ptr<ContainmentManager> containment_manager_;
    std::unique_ptr<IncidentManager> incident_manager_;
    std::unique_ptr<TelemetryExporter> telemetry_exporter_;

    SubscriptionId event_subscriber_id_;
    std::atomic<size_t> event_count_{0};
};

} // namespace cortex

int main() {
    cortex::Logger::Initialize("logs/cortex.log");
    cortex::Logger::SetLevel(cortex::LogLevel::INFO);

    LOG_INFO("==========================================================");
    LOG_INFO("  CortexEDR - Windows Endpoint Detection & Response");
    LOG_INFO("  Phase 3: Incident Management & Telemetry");
    LOG_INFO("==========================================================");

    std::signal(SIGINT, cortex::SignalHandler);
    std::signal(SIGTERM, cortex::SignalHandler);

    try {
        cortex::CortexEDR edr;

        if (!edr.Initialize()) {
            LOG_CRITICAL("Failed to initialize CortexEDR");
            return 1;
        }

        if (!edr.Start()) {
            LOG_CRITICAL("Failed to start CortexEDR");
            return 1;
        }

        edr.Run();

        edr.Stop();

        LOG_INFO("CortexEDR shutdown complete");
        cortex::Logger::Shutdown();

        return 0;
    } catch (const std::exception& ex) {
        LOG_CRITICAL("Fatal error: {}", ex.what());
        cortex::Logger::Shutdown();
        return 1;
    }
}
