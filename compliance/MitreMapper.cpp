#include "compliance/MitreMapper.hpp"
#include "core/Logger.hpp"

namespace cortex {

MitreMapper::MitreMapper() = default;

void MitreMapper::Initialize() {
    BuildMappingTable();
    LOG_INFO("MitreMapper initialized ({} rule mappings, {} techniques cataloged)",
             rule_mappings_.size(), technique_catalog_.size());
}

void MitreMapper::BuildMappingTable() {
    // Build the technique catalog
    auto addTechnique = [this](const std::string& id, const std::string& name,
                               const std::string& tactic, const std::string& desc) {
        MitreTechnique t(id, name, tactic, desc);
        technique_catalog_[id] = t;
        return t;
    };

    // Execution techniques
    auto t1059 = addTechnique("T1059", "Command and Scripting Interpreter",
        "Execution", "Adversaries may abuse command and script interpreters to execute commands");
    auto t1059_001 = addTechnique("T1059.001", "PowerShell",
        "Execution", "Adversaries may abuse PowerShell commands and scripts for execution");
    auto t1204_002 = addTechnique("T1204.002", "User Execution: Malicious File",
        "Execution", "An adversary may rely upon a user opening a malicious file");

    // Persistence techniques
    auto t1547 = addTechnique("T1547", "Boot or Logon Autostart Execution",
        "Persistence", "Adversaries may configure system settings to automatically execute a program during boot or logon");
    auto t1547_001 = addTechnique("T1547.001", "Registry Run Keys / Startup Folder",
        "Persistence", "Adversaries may achieve persistence by adding a program to a startup folder or Registry run key");
    auto t1547_004 = addTechnique("T1547.004", "Winlogon Helper DLL",
        "Persistence", "Adversaries may abuse Winlogon helper features for persistence");
    auto t1543_003 = addTechnique("T1543.003", "Windows Service",
        "Persistence", "Adversaries may create or modify Windows services to repeatedly execute malicious payloads");

    // Defense Evasion techniques
    auto t1036_005 = addTechnique("T1036.005", "Match Legitimate Name or Location",
        "Defense Evasion", "Adversaries may match or approximate names/locations of legitimate files");
    auto t1574_001 = addTechnique("T1574.001", "DLL Search Order Hijacking",
        "Defense Evasion", "Adversaries may execute their own malicious payloads by hijacking the search order for DLLs");

    // Command and Control techniques
    auto t1071_001 = addTechnique("T1071.001", "Web Protocols",
        "Command and Control", "Adversaries may communicate using application layer protocols associated with web traffic");
    auto t1571 = addTechnique("T1571", "Non-Standard Port",
        "Command and Control", "Adversaries may communicate using a protocol and port pairing not typically associated");
    auto t1105 = addTechnique("T1105", "Ingress Tool Transfer",
        "Command and Control", "Adversaries may transfer tools from an external system into a compromised environment");

    // Lateral Movement techniques
    auto t1021 = addTechnique("T1021", "Remote Services",
        "Lateral Movement", "Adversaries may use valid accounts to log into a service for remote access");

    // Resource Development techniques
    auto t1588_001 = addTechnique("T1588.001", "Obtain Capabilities: Malware",
        "Resource Development", "Adversaries may obtain malware for use during targeting");

    // Collection techniques
    auto t1005 = addTechnique("T1005", "Data from Local System",
        "Collection", "Adversaries may search local system sources for data of interest");

    // Impact techniques
    auto t1486 = addTechnique("T1486", "Data Encrypted for Impact",
        "Impact", "Adversaries may encrypt data on target systems to interrupt availability");

    // --- Rule-to-Technique Mappings ---

    // Path-based rules
    rule_mappings_["Suspicious Temp Execution"] = {t1204_002};
    rule_mappings_["Suspicious AppData Execution"] = {t1204_002};
    rule_mappings_["System Directory Write"] = {t1574_001};
    rule_mappings_["Suspicious Script Execution"] = {t1059, t1059_001};
    rule_mappings_["Suspicious Downloads Folder Execution"] = {t1204_002};
    rule_mappings_["Recycler/Recycle Bin Execution"] = {t1036_005};

    // Network-based rules
    rule_mappings_["C2 Network Indicator - Tor Exit Nodes"] = {t1071_001};
    rule_mappings_["Known Malicious Domain Pattern"] = {t1071_001};
    rule_mappings_["Suspicious High-Risk Ports"] = {t1571};

    // Registry-based rules
    rule_mappings_["Persistence Registry Key Modification"] = {t1547_001};
    rule_mappings_["Service Installation"] = {t1543_003};
    rule_mappings_["Winlogon Persistence"] = {t1547_004};

    // Hash-based rules
    rule_mappings_["Known Malware Hash - Example Mimikatz"] = {t1588_001};

    // Behavior patterns (from BehaviorCorrelator)
    rule_mappings_["Dropper Pattern"] = {t1105, t1204_002};
    rule_mappings_["Persistence Pattern"] = {t1547, t1547_001};
    rule_mappings_["Lateral Movement Pattern"] = {t1021};

    // --- Event Type Mappings ---
    event_mappings_[EventType::PROCESS_CREATE] = {t1204_002};
    event_mappings_[EventType::FILE_CREATE] = {t1005};
    event_mappings_[EventType::FILE_MODIFY] = {t1005};
    event_mappings_[EventType::NETWORK_CONNECT] = {t1071_001};
    event_mappings_[EventType::REGISTRY_WRITE] = {t1547_001};
}

std::vector<MitreTechnique> MitreMapper::MapRule(const std::string& rule_name) const {
    auto it = rule_mappings_.find(rule_name);
    if (it != rule_mappings_.end()) {
        return it->second;
    }

    // Try partial matching (rule name contains a known key)
    for (const auto& [key, techniques] : rule_mappings_) {
        if (rule_name.find(key) != std::string::npos ||
            key.find(rule_name) != std::string::npos) {
            return techniques;
        }
    }

    return {};
}

std::vector<MitreTechnique> MitreMapper::MapEvent(const Event& event) const {
    std::vector<MitreTechnique> result;

    // Map by event type
    auto it = event_mappings_.find(event.type);
    if (it != event_mappings_.end()) {
        result = it->second;
    }

    // Check if metadata contains a matched rule name
    auto rule_it = event.metadata.find("matched_rule");
    if (rule_it != event.metadata.end()) {
        auto rule_techniques = MapRule(rule_it->second);
        for (const auto& t : rule_techniques) {
            bool already_present = false;
            for (const auto& existing : result) {
                if (existing.technique_id == t.technique_id) {
                    already_present = true;
                    break;
                }
            }
            if (!already_present) {
                result.push_back(t);
            }
        }
    }

    return result;
}

std::vector<MitreMapping> MitreMapper::GetAllMappings() const {
    std::vector<MitreMapping> result;
    for (const auto& [rule_name, techniques] : rule_mappings_) {
        MitreMapping mapping;
        mapping.rule_name = rule_name;
        mapping.techniques = techniques;
        result.push_back(mapping);
    }
    return result;
}

std::optional<MitreTechnique> MitreMapper::GetTechniqueById(const std::string& technique_id) const {
    auto it = technique_catalog_.find(technique_id);
    if (it != technique_catalog_.end()) {
        return it->second;
    }
    return std::nullopt;
}

MitreCoverageStats MitreMapper::GetCoverageStats() const {
    MitreCoverageStats stats;
    stats.total_techniques = technique_catalog_.size();

    std::unordered_map<std::string, size_t> tactic_counts;
    for (const auto& [id, technique] : technique_catalog_) {
        tactic_counts[technique.tactic]++;
    }

    stats.total_tactics = tactic_counts.size();
    stats.techniques_per_tactic = tactic_counts;
    return stats;
}

size_t MitreMapper::GetMappingCount() const {
    return rule_mappings_.size();
}

} // namespace cortex
