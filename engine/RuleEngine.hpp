#pragma once

#include "core/EventBus.hpp"
#include "engine/RiskScorer.hpp"
#include <string>
#include <vector>
#include <shared_mutex>
#include <atomic>

namespace cortex {

struct Rule {
    std::string name;
    bool enabled;
    std::string type; // "hash", "path", "network", "registry"
    std::vector<std::string> patterns;
    uint32_t risk_points;
    std::string action; // "log", "alert", "escalate"

    Rule() : enabled(true), risk_points(0) {}
};

class RuleEngine {
public:
    RuleEngine();
    ~RuleEngine();

    bool Initialize(const std::string& rules_file_path, RiskScorer* risk_scorer);
    void Start();
    void Stop();

    // Load rules from YAML
    bool LoadRules(const std::string& rules_file_path);
    size_t GetRuleCount() const;

private:
    void OnEvent(const Event& event);
    bool MatchRule(const Rule& rule, const Event& event);
    bool MatchHashRule(const Rule& rule, const Event& event);
    bool MatchPathRule(const Rule& rule, const Event& event);
    bool MatchNetworkRule(const Rule& rule, const Event& event);
    bool MatchRegistryRule(const Rule& rule, const Event& event);

    // Wildcard pattern matching
    bool WildcardMatch(const std::string& pattern, const std::string& text);

    std::vector<Rule> rules_;
    RiskScorer* risk_scorer_{nullptr};
    mutable std::shared_mutex mutex_;
    std::atomic<bool> running_{false};
    SubscriptionId subscription_id_{0};
};

} // namespace cortex
