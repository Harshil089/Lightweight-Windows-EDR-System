#include "engine/RiskScorer.hpp"
#include "core/Logger.hpp"
#include <algorithm>

namespace cortex {

RiskScorer::RiskScorer() {
}

void RiskScorer::ProcessEvent(const Event& event) {
    uint32_t pid = event.pid;

    switch (event.type) {
        case EventType::PROCESS_CREATE: {
            auto it = event.metadata.find("image_path");
            if (it != event.metadata.end()) {
                std::string path = it->second;
                std::transform(path.begin(), path.end(), path.begin(), ::tolower);

                if (path.find("\\temp\\") != std::string::npos ||
                    path.find("\\appdata\\") != std::string::npos) {
                    AddRisk(pid, "process_from_temp_or_appdata", 15);
                }
            }
            break;
        }

        case EventType::FILE_CREATE:
        case EventType::FILE_MODIFY: {
            auto it = event.metadata.find("file_path");
            if (it != event.metadata.end()) {
                std::string path = it->second;
                std::transform(path.begin(), path.end(), path.begin(), ::tolower);

                if (path.find("\\system32\\") != std::string::npos ||
                    path.find("\\syswow64\\") != std::string::npos) {
                    AddRisk(pid, "write_to_system_directory", 15);
                }
            }
            break;
        }

        case EventType::NETWORK_CONNECT: {
            auto remote_it = event.metadata.find("remote_address");
            auto port_it = event.metadata.find("remote_port");

            if (remote_it != event.metadata.end()) {
                std::string remote_addr = remote_it->second;

                bool is_private = (remote_addr.rfind("10.", 0) == 0 ||
                                  remote_addr.rfind("192.168.", 0) == 0 ||
                                  remote_addr.rfind("172.16.", 0) == 0 ||
                                  remote_addr == "0.0.0.0" ||
                                  remote_addr == "127.0.0.1");

                if (!is_private) {
                    AddRisk(pid, "connection_to_external_ip", 10);
                }
            }

            if (port_it != event.metadata.end()) {
                int port = std::stoi(port_it->second);
                if (port == 4444 || port == 1337 || port == 6667 || port == 31337) {
                    AddRisk(pid, "connection_to_suspicious_port", 15);
                }
            }
            break;
        }

        case EventType::REGISTRY_WRITE: {
            auto it = event.metadata.find("key_path");
            if (it != event.metadata.end()) {
                std::string key = it->second;
                std::transform(key.begin(), key.end(), key.begin(), ::tolower);

                if (key.find("\\run") != std::string::npos ||
                    key.find("\\services") != std::string::npos) {
                    AddRisk(pid, "registry_persistence_modification", 20);
                }
            }
            break;
        }

        default:
            break;
    }
}

RiskScore RiskScorer::GetProcessRiskScore(uint32_t pid) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = process_scores_.find(pid);
    if (it != process_scores_.end()) {
        return it->second;
    }
    return RiskScore();
}

void RiskScorer::ClearProcessScore(uint32_t pid) {
    std::lock_guard<std::mutex> lock(mutex_);
    process_scores_.erase(pid);
}

void RiskScorer::SetThresholds(uint32_t low, uint32_t medium, uint32_t high, uint32_t critical) {
    threshold_low_ = low;
    threshold_medium_ = medium;
    threshold_high_ = high;
    threshold_critical_ = critical;
}

RiskLevel RiskScorer::CalculateLevel(uint32_t score) const {
    if (score >= threshold_critical_) return RiskLevel::CRITICAL;
    if (score >= threshold_high_) return RiskLevel::HIGH;
    if (score >= threshold_medium_) return RiskLevel::MEDIUM;
    if (score >= threshold_low_) return RiskLevel::MEDIUM;
    return RiskLevel::LOW;
}

void RiskScorer::AddRisk(uint32_t pid, const std::string& reason, uint32_t points) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto& risk = process_scores_[pid];
    risk.contributing_factors[reason] += points;

    risk.score = 0;
    for (const auto& [factor, score] : risk.contributing_factors) {
        risk.score += score;
    }

    risk.score = std::min(risk.score, 100u);
    risk.level = CalculateLevel(risk.score);

    LOG_DEBUG("PID {} risk updated: {} ({})", pid, risk.score, reason);
}

} // namespace cortex
