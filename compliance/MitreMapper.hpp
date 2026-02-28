#pragma once

#include "core/EventBus.hpp"
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>

namespace cortex {

struct MitreTechnique {
    std::string technique_id;
    std::string technique_name;
    std::string tactic;
    std::string description;

    MitreTechnique() = default;
    MitreTechnique(const std::string& id, const std::string& name,
                   const std::string& t, const std::string& desc)
        : technique_id(id), technique_name(name), tactic(t), description(desc) {}
};

struct MitreMapping {
    std::string rule_name;
    std::vector<MitreTechnique> techniques;
};

struct MitreCoverageStats {
    size_t total_techniques;
    size_t total_tactics;
    std::unordered_map<std::string, size_t> techniques_per_tactic;
};

class MitreMapper {
public:
    MitreMapper();
    ~MitreMapper() = default;

    void Initialize();

    // Map a rule name to MITRE techniques
    std::vector<MitreTechnique> MapRule(const std::string& rule_name) const;

    // Map an event to MITRE techniques based on event type and metadata
    std::vector<MitreTechnique> MapEvent(const Event& event) const;

    // Get all mappings
    std::vector<MitreMapping> GetAllMappings() const;

    // Lookup by technique ID
    std::optional<MitreTechnique> GetTechniqueById(const std::string& technique_id) const;

    // Coverage statistics
    MitreCoverageStats GetCoverageStats() const;

    size_t GetMappingCount() const;

private:
    void BuildMappingTable();

    // Rule name → list of techniques
    std::unordered_map<std::string, std::vector<MitreTechnique>> rule_mappings_;

    // Event type → list of techniques
    std::unordered_map<EventType, std::vector<MitreTechnique>> event_mappings_;

    // Technique ID → technique details
    std::unordered_map<std::string, MitreTechnique> technique_catalog_;
};

} // namespace cortex
