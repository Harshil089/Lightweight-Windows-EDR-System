#pragma once

#include "core/EventBus.hpp"
#include <string>
#include <unordered_map>

namespace cortex {

enum class RiskLevel {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

struct RiskScore {
    uint32_t score;
    RiskLevel level;
    std::unordered_map<std::string, uint32_t> contributing_factors;

    RiskScore() : score(0), level(RiskLevel::LOW) {}
};

class RiskScorer {
public:
    RiskScorer();

    void ProcessEvent(const Event& event);
    RiskScore GetProcessRiskScore(uint32_t pid) const;
    void ClearProcessScore(uint32_t pid);

    void SetThresholds(uint32_t low, uint32_t medium, uint32_t high, uint32_t critical);

private:
    RiskLevel CalculateLevel(uint32_t score) const;
    void AddRisk(uint32_t pid, const std::string& reason, uint32_t points);

    mutable std::mutex mutex_;
    std::unordered_map<uint32_t, RiskScore> process_scores_;

    uint32_t threshold_low_{30};
    uint32_t threshold_medium_{60};
    uint32_t threshold_high_{80};
    uint32_t threshold_critical_{100};
};

} // namespace cortex
