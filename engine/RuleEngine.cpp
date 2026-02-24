#include "engine/RuleEngine.hpp"
#include "core/Logger.hpp"
#include <yaml-cpp/yaml.h>
#include <algorithm>
#include <cctype>

namespace cortex {

RuleEngine::RuleEngine() = default;

RuleEngine::~RuleEngine() {
    Stop();
}

bool RuleEngine::Initialize(const std::string& rules_file_path, RiskScorer* risk_scorer) {
    if (!risk_scorer) {
        LOG_ERROR("RuleEngine::Initialize called with null RiskScorer");
        return false;
    }

    risk_scorer_ = risk_scorer;

    if (!LoadRules(rules_file_path)) {
        LOG_WARN("Failed to load rules from {}, continuing with empty rule set", rules_file_path);
        return false;
    }

    LOG_INFO("RuleEngine initialized with {} rules", rules_.size());
    return true;
}

bool RuleEngine::LoadRules(const std::string& rules_file_path) {
    std::lock_guard<std::mutex> lock(mutex_);

    try {
        YAML::Node config = YAML::LoadFile(rules_file_path);

        if (!config["rules"]) {
            LOG_ERROR("Invalid rules file: missing 'rules' section");
            return false;
        }

        rules_.clear();

        for (const auto& rule_node : config["rules"]) {
            Rule rule;

            if (rule_node["name"]) {
                rule.name = rule_node["name"].as<std::string>();
            } else {
                LOG_WARN("Skipping rule without name");
                continue;
            }

            if (rule_node["enabled"]) {
                rule.enabled = rule_node["enabled"].as<bool>();
            }

            if (rule_node["type"]) {
                rule.type = rule_node["type"].as<std::string>();
            } else {
                LOG_WARN("Skipping rule '{}' without type", rule.name);
                continue;
            }

            if (rule_node["patterns"]) {
                for (const auto& pattern : rule_node["patterns"]) {
                    rule.patterns.push_back(pattern.as<std::string>());
                }
            } else {
                LOG_WARN("Skipping rule '{}' without patterns", rule.name);
                continue;
            }

            if (rule_node["risk_points"]) {
                rule.risk_points = rule_node["risk_points"].as<uint32_t>();
            }

            if (rule_node["action"]) {
                rule.action = rule_node["action"].as<std::string>();
            }

            rules_.push_back(rule);
            LOG_DEBUG("Loaded rule: {} (type={}, patterns={}, points={})",
                     rule.name, rule.type, rule.patterns.size(), rule.risk_points);
        }

        LOG_INFO("Successfully loaded {} rules from {}", rules_.size(), rules_file_path);
        return true;

    } catch (const YAML::Exception& ex) {
        LOG_ERROR("Failed to parse YAML rules file {}: {}", rules_file_path, ex.what());
        return false;
    } catch (const std::exception& ex) {
        LOG_ERROR("Failed to load rules from {}: {}", rules_file_path, ex.what());
        return false;
    }
}

void RuleEngine::Start() {
    if (running_) {
        LOG_WARN("RuleEngine already running");
        return;
    }

    // Subscribe to all event types to check against rules
    subscription_id_ = EventBus::Instance().Subscribe(
        EventType::PROCESS_CREATE,
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
        EventType::NETWORK_CONNECT,
        [this](const Event& event) { OnEvent(event); }
    );

    EventBus::Instance().Subscribe(
        EventType::REGISTRY_WRITE,
        [this](const Event& event) { OnEvent(event); }
    );

    running_ = true;
    LOG_INFO("RuleEngine started");
}

void RuleEngine::Stop() {
    if (!running_) {
        return;
    }

    if (subscription_id_ != 0) {
        EventBus::Instance().Unsubscribe(subscription_id_);
        subscription_id_ = 0;
    }

    running_ = false;
    LOG_INFO("RuleEngine stopped");
}

size_t RuleEngine::GetRuleCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return rules_.size();
}

void RuleEngine::OnEvent(const Event& event) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!risk_scorer_) {
        return;
    }

    for (const auto& rule : rules_) {
        if (!rule.enabled) {
            continue;
        }

        if (MatchRule(rule, event)) {
            LOG_INFO("Rule matched: '{}' for PID {} ({} points)",
                    rule.name, event.pid, rule.risk_points);

            // Add risk points via RiskScorer
            // Note: We need to update RiskScorer to have a public AddRisk method
            // For now, we'll emit an event that RiskScorer can handle
            Event risk_event(EventType::RISK_THRESHOLD_EXCEEDED, event.pid, event.process_name);
            risk_event.metadata["rule_name"] = rule.name;
            risk_event.metadata["rule_type"] = rule.type;
            risk_event.metadata["risk_points"] = std::to_string(rule.risk_points);
            risk_event.metadata["action"] = rule.action;

            // Copy relevant metadata from original event
            for (const auto& [key, value] : event.metadata) {
                risk_event.metadata["original_" + key] = value;
            }

            EventBus::Instance().PublishAsync(risk_event);
        }
    }
}

bool RuleEngine::MatchRule(const Rule& rule, const Event& event) {
    if (rule.type == "hash") {
        return MatchHashRule(rule, event);
    } else if (rule.type == "path") {
        return MatchPathRule(rule, event);
    } else if (rule.type == "network") {
        return MatchNetworkRule(rule, event);
    } else if (rule.type == "registry") {
        return MatchRegistryRule(rule, event);
    }

    return false;
}

bool RuleEngine::MatchHashRule(const Rule& rule, const Event& event) {
    // Hash rules only apply to process creation events
    if (event.type != EventType::PROCESS_CREATE) {
        return false;
    }

    auto hash_it = event.metadata.find("file_hash");
    if (hash_it == event.metadata.end()) {
        return false;
    }

    const std::string& file_hash = hash_it->second;

    // Check if hash matches any pattern (exact match, case-insensitive)
    for (const auto& pattern : rule.patterns) {
        std::string pattern_lower = pattern;
        std::string hash_lower = file_hash;

        std::transform(pattern_lower.begin(), pattern_lower.end(), pattern_lower.begin(),
                      [](unsigned char c) { return std::tolower(c); });
        std::transform(hash_lower.begin(), hash_lower.end(), hash_lower.begin(),
                      [](unsigned char c) { return std::tolower(c); });

        if (pattern_lower == hash_lower) {
            return true;
        }
    }

    return false;
}

bool RuleEngine::MatchPathRule(const Rule& rule, const Event& event) {
    std::string path;

    // Get path from event metadata based on event type
    if (event.type == EventType::PROCESS_CREATE) {
        auto it = event.metadata.find("image_path");
        if (it != event.metadata.end()) {
            path = it->second;
        }
    } else if (event.type == EventType::FILE_CREATE || event.type == EventType::FILE_MODIFY) {
        auto it = event.metadata.find("file_path");
        if (it != event.metadata.end()) {
            path = it->second;
        }
    }

    if (path.empty()) {
        return false;
    }

    // Convert to lowercase for case-insensitive matching
    std::transform(path.begin(), path.end(), path.begin(),
                  [](unsigned char c) { return std::tolower(c); });

    // Check against all patterns
    for (const auto& pattern : rule.patterns) {
        std::string pattern_lower = pattern;
        std::transform(pattern_lower.begin(), pattern_lower.end(), pattern_lower.begin(),
                      [](unsigned char c) { return std::tolower(c); });

        if (WildcardMatch(pattern_lower, path)) {
            return true;
        }
    }

    return false;
}

bool RuleEngine::MatchNetworkRule(const Rule& rule, const Event& event) {
    // Network rules only apply to network connection events
    if (event.type != EventType::NETWORK_CONNECT) {
        return false;
    }

    auto remote_addr_it = event.metadata.find("remote_address");
    if (remote_addr_it == event.metadata.end()) {
        return false;
    }

    const std::string& remote_address = remote_addr_it->second;

    // Check against all patterns
    for (const auto& pattern : rule.patterns) {
        if (WildcardMatch(pattern, remote_address)) {
            return true;
        }
    }

    return false;
}

bool RuleEngine::MatchRegistryRule(const Rule& rule, const Event& event) {
    // Registry rules only apply to registry write events
    if (event.type != EventType::REGISTRY_WRITE) {
        return false;
    }

    auto key_path_it = event.metadata.find("key_path");
    if (key_path_it == event.metadata.end()) {
        return false;
    }

    std::string key_path = key_path_it->second;

    // Convert to lowercase for case-insensitive matching
    std::transform(key_path.begin(), key_path.end(), key_path.begin(),
                  [](unsigned char c) { return std::tolower(c); });

    // Check against all patterns
    for (const auto& pattern : rule.patterns) {
        std::string pattern_lower = pattern;
        std::transform(pattern_lower.begin(), pattern_lower.end(), pattern_lower.begin(),
                      [](unsigned char c) { return std::tolower(c); });

        if (WildcardMatch(pattern_lower, key_path)) {
            return true;
        }
    }

    return false;
}

bool RuleEngine::WildcardMatch(const std::string& pattern, const std::string& text) {
    size_t p = 0; // pattern index
    size_t t = 0; // text index
    size_t star_idx = std::string::npos;
    size_t match_idx = 0;

    while (t < text.length()) {
        if (p < pattern.length() && (pattern[p] == '?' || pattern[p] == text[t])) {
            // Exact match or '?' wildcard
            ++p;
            ++t;
        } else if (p < pattern.length() && pattern[p] == '*') {
            // '*' wildcard - remember position
            star_idx = p;
            match_idx = t;
            ++p;
        } else if (star_idx != std::string::npos) {
            // No match, but we have a previous '*' - backtrack
            p = star_idx + 1;
            ++match_idx;
            t = match_idx;
        } else {
            // No match and no '*' to backtrack to
            return false;
        }
    }

    // Consume remaining '*' in pattern
    while (p < pattern.length() && pattern[p] == '*') {
        ++p;
    }

    return p == pattern.length();
}

} // namespace cortex
