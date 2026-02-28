#include "engine/BehaviorCorrelator.hpp"
#include "core/Logger.hpp"
#include <chrono>
#include <algorithm>
#include <set>

namespace cortex {

BehaviorCorrelator::BehaviorCorrelator() = default;

BehaviorCorrelator::~BehaviorCorrelator() {
    Stop();
}

void BehaviorCorrelator::Initialize(RiskScorer* risk_scorer) {
    if (!risk_scorer) {
        LOG_ERROR("BehaviorCorrelator::Initialize called with null RiskScorer");
        return;
    }

    risk_scorer_ = risk_scorer;

    // Initialize predefined patterns (for reference, actual detection uses custom logic)
    patterns_.emplace_back("Dropper",
        std::vector<EventType>{EventType::FILE_CREATE, EventType::PROCESS_CREATE, EventType::NETWORK_CONNECT},
        DROPPER_WINDOW_SECONDS, 20);

    patterns_.emplace_back("Persistence",
        std::vector<EventType>{EventType::REGISTRY_WRITE, EventType::PROCESS_CREATE},
        PERSISTENCE_WINDOW_SECONDS, 20);

    patterns_.emplace_back("Lateral_Movement",
        std::vector<EventType>{EventType::NETWORK_CONNECT, EventType::NETWORK_CONNECT},
        LATERAL_WINDOW_SECONDS, 25);

    LOG_INFO("BehaviorCorrelator initialized with {} patterns", patterns_.size());
}

void BehaviorCorrelator::Start() {
    if (running_) {
        LOG_WARN("BehaviorCorrelator already running");
        return;
    }

    // Subscribe to relevant event types
    subscription_ids_.push_back(EventBus::Instance().Subscribe(
        EventType::PROCESS_CREATE,
        [this](const Event& event) { OnEvent(event); }
    ));

    subscription_ids_.push_back(EventBus::Instance().Subscribe(
        EventType::PROCESS_TERMINATE,
        [this](const Event& event) { OnEvent(event); }
    ));

    subscription_ids_.push_back(EventBus::Instance().Subscribe(
        EventType::FILE_CREATE,
        [this](const Event& event) { OnEvent(event); }
    ));

    subscription_ids_.push_back(EventBus::Instance().Subscribe(
        EventType::FILE_MODIFY,
        [this](const Event& event) { OnEvent(event); }
    ));

    subscription_ids_.push_back(EventBus::Instance().Subscribe(
        EventType::NETWORK_CONNECT,
        [this](const Event& event) { OnEvent(event); }
    ));

    subscription_ids_.push_back(EventBus::Instance().Subscribe(
        EventType::REGISTRY_WRITE,
        [this](const Event& event) { OnEvent(event); }
    ));

    running_ = true;
    LOG_INFO("BehaviorCorrelator started");
}

void BehaviorCorrelator::Stop() {
    if (!running_) {
        return;
    }

    for (auto sub_id : subscription_ids_) {
        EventBus::Instance().Unsubscribe(sub_id);
    }
    subscription_ids_.clear();

    running_ = false;
    LOG_INFO("BehaviorCorrelator stopped");
}

size_t BehaviorCorrelator::GetTimelineCount() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return process_timelines_.size();
}

size_t BehaviorCorrelator::GetPatternCount() const {
    return patterns_.size();
}

void BehaviorCorrelator::OnEvent(const Event& event) {
    ProcessTimeline timeline_copy;
    bool has_timeline = false;

    {
        std::unique_lock<std::shared_mutex> lock(mutex_);

        uint64_t current_time = GetCurrentTimestamp();

        // Handle process termination
        if (event.type == EventType::PROCESS_TERMINATE) {
            auto it = process_timelines_.find(event.pid);
            if (it != process_timelines_.end()) {
                LOG_DEBUG("Removing timeline for terminated process {}", event.pid);
                process_timelines_.erase(it);
            }
            return;
        }

        // Add event to process timeline
        if (event.pid != 0) {
            AddEventToTimeline(event.pid, event);

            auto it = process_timelines_.find(event.pid);
            if (it != process_timelines_.end()) {
                // Cleanup old events while holding the lock
                CleanupOldEvents(it->second, current_time);

                // Take a snapshot for pattern detection outside the lock
                timeline_copy = it->second;
                has_timeline = true;
            }
        }
    }
    // Lock released — run O(n²) pattern detection on the copy
    if (has_timeline) {
        DetectDropperPattern(timeline_copy);
        DetectPersistencePattern(timeline_copy);
        DetectLateralMovementPattern(timeline_copy);
    }
}

void BehaviorCorrelator::AddEventToTimeline(uint32_t pid, const Event& event) {
    auto it = process_timelines_.find(pid);

    if (it == process_timelines_.end()) {
        // Create new timeline
        ProcessTimeline timeline(pid);
        timeline.events.push_back(event);
        timeline.last_cleanup_time = GetCurrentTimestamp();
        process_timelines_[pid] = std::move(timeline);
        LOG_DEBUG("Created new timeline for PID {}", pid);
    } else {
        // Add to existing timeline
        it->second.events.push_back(event);
    }
}

void BehaviorCorrelator::CleanupOldEvents(ProcessTimeline& timeline, uint64_t current_time) {
    // Remove events older than the window
    uint64_t cutoff_time = current_time - (TIMELINE_WINDOW_SECONDS * 1000);

    while (!timeline.events.empty() && timeline.events.front().timestamp < cutoff_time) {
        timeline.events.pop_front();
    }

    timeline.last_cleanup_time = current_time;
}

uint64_t BehaviorCorrelator::GetCurrentTimestamp() const {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
}

bool BehaviorCorrelator::DetectDropperPattern(const ProcessTimeline& timeline) {
    // Dropper Pattern: FILE_CREATE (in temp/appdata) → PROCESS_CREATE → NETWORK_CONNECT
    // All within 30 seconds

    if (timeline.events.size() < 3) {
        return false;
    }

    uint64_t window_ms = DROPPER_WINDOW_SECONDS * 1000;

    // Look for the pattern in the timeline
    for (size_t i = 0; i < timeline.events.size(); ++i) {
        const Event& event1 = timeline.events[i];

        // Step 1: Look for FILE_CREATE in suspicious location
        if (event1.type == EventType::FILE_CREATE) {
            auto path_it = event1.metadata.find("file_path");
            if (path_it == event1.metadata.end()) {
                continue;
            }

            std::string path = path_it->second;
            std::transform(path.begin(), path.end(), path.begin(), ::tolower);

            // Check if file created in temp or appdata
            bool suspicious_path = (path.find("\\temp\\") != std::string::npos ||
                                   path.find("\\appdata\\") != std::string::npos);

            if (!suspicious_path) {
                continue;
            }

            // Step 2: Look for PROCESS_CREATE within window
            for (size_t j = i + 1; j < timeline.events.size(); ++j) {
                const Event& event2 = timeline.events[j];

                if (event2.timestamp > event1.timestamp + window_ms) {
                    break; // Outside time window
                }

                if (event2.type == EventType::PROCESS_CREATE) {
                    // Step 3: Look for NETWORK_CONNECT within window
                    for (size_t k = j + 1; k < timeline.events.size(); ++k) {
                        const Event& event3 = timeline.events[k];

                        if (event3.timestamp > event1.timestamp + window_ms) {
                            break; // Outside time window
                        }

                        if (event3.type == EventType::NETWORK_CONNECT) {
                            // Pattern detected!
                            EmitPatternDetection(timeline.pid, "Dropper",
                                "File creation in suspicious location followed by process spawn and network connection",
                                20);
                            LOG_WARN("Dropper pattern detected for PID {}", timeline.pid);
                            return true;
                        }
                    }
                }
            }
        }
    }

    return false;
}

bool BehaviorCorrelator::DetectPersistencePattern(const ProcessTimeline& timeline) {
    // Persistence Pattern: REGISTRY_WRITE (to Run key) → PROCESS_CREATE
    // Within 60 seconds

    if (timeline.events.size() < 2) {
        return false;
    }

    uint64_t window_ms = PERSISTENCE_WINDOW_SECONDS * 1000;

    // Look for the pattern
    for (size_t i = 0; i < timeline.events.size(); ++i) {
        const Event& event1 = timeline.events[i];

        // Step 1: Look for REGISTRY_WRITE to persistence key
        if (event1.type == EventType::REGISTRY_WRITE) {
            auto key_it = event1.metadata.find("key_path");
            if (key_it == event1.metadata.end()) {
                continue;
            }

            std::string key_path = key_it->second;
            std::transform(key_path.begin(), key_path.end(), key_path.begin(), ::tolower);

            // Check if registry key is a persistence location
            bool persistence_key = (key_path.find("\\run") != std::string::npos ||
                                   key_path.find("\\runonce") != std::string::npos ||
                                   key_path.find("\\services") != std::string::npos);

            if (!persistence_key) {
                continue;
            }

            // Step 2: Look for PROCESS_CREATE within window
            for (size_t j = i + 1; j < timeline.events.size(); ++j) {
                const Event& event2 = timeline.events[j];

                if (event2.timestamp > event1.timestamp + window_ms) {
                    break; // Outside time window
                }

                if (event2.type == EventType::PROCESS_CREATE) {
                    // Pattern detected!
                    EmitPatternDetection(timeline.pid, "Persistence",
                        "Registry persistence key modification followed by process creation",
                        20);
                    LOG_WARN("Persistence pattern detected for PID {}", timeline.pid);
                    return true;
                }
            }
        }
    }

    return false;
}

bool BehaviorCorrelator::DetectLateralMovementPattern(const ProcessTimeline& timeline) {
    // Lateral Movement Pattern: Multiple NETWORK_CONNECT to different IPs on port 445/135/139 (SMB/RPC)
    // 3 or more connections within 10 seconds

    if (timeline.events.size() < 3) {
        return false;
    }

    uint64_t window_ms = LATERAL_WINDOW_SECONDS * 1000;

    // Track network connections
    std::vector<std::pair<uint64_t, std::string>> smb_connections;

    for (const auto& event : timeline.events) {
        if (event.type == EventType::NETWORK_CONNECT) {
            auto port_it = event.metadata.find("remote_port");
            auto addr_it = event.metadata.find("remote_address");

            if (port_it == event.metadata.end() || addr_it == event.metadata.end()) {
                continue;
            }

            uint32_t port = std::stoul(port_it->second);

            // Check for SMB/RPC ports
            if (port == 445 || port == 135 || port == 139) {
                smb_connections.emplace_back(event.timestamp, addr_it->second);
            }
        }
    }

    // Check for multiple connections to different IPs within window
    if (smb_connections.size() >= 3) {
        // Check if they're within the time window
        for (size_t i = 0; i < smb_connections.size() - 2; ++i) {
            uint64_t start_time = smb_connections[i].first;

            std::set<std::string> unique_ips;
            for (size_t j = i; j < smb_connections.size(); ++j) {
                if (smb_connections[j].first > start_time + window_ms) {
                    break;
                }

                unique_ips.insert(smb_connections[j].second);

                if (unique_ips.size() >= 3) {
                    // Pattern detected!
                    EmitPatternDetection(timeline.pid, "Lateral_Movement",
                        "Multiple SMB/RPC connections to different hosts in short time window",
                        25);
                    LOG_WARN("Lateral Movement pattern detected for PID {}", timeline.pid);
                    return true;
                }
            }
        }
    }

    return false;
}

void BehaviorCorrelator::EmitPatternDetection(uint32_t pid, const std::string& pattern_name,
                                              const std::string& description, uint32_t bonus_score) {
    // Emit INCIDENT_STATE_CHANGE event
    Event incident_event(EventType::INCIDENT_STATE_CHANGE, pid, "BehaviorCorrelator");
    incident_event.metadata["pattern_name"] = pattern_name;
    incident_event.metadata["description"] = description;
    incident_event.metadata["bonus_score"] = std::to_string(bonus_score);
    incident_event.metadata["state"] = "ACTIVE";

    EventBus::Instance().PublishAsync(incident_event);

    LOG_INFO("Pattern '{}' detected for PID {}: {}", pattern_name, pid, description);
}

} // namespace cortex
