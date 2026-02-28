feat: Phase 5 Implementation - Compliance & Reporting with Audit Trail, MITRE Mapping, and Forensics

Complete implementation of the Compliance & Reporting phase for CortexEDR, adding:

## New Components (compliance/ module - 8 new files):

1. **AuditLogger** (AuditLogger.hpp/cpp)
   - Tamper-proof append-only audit log with HMAC-SHA256 integrity chain
   - Each entry cryptographically linked to previous entry (prev_hash field)
   - VerifyIntegrity() detects tampering by walking and validating chain
   - Subscribes to EventBus events (RISK_THRESHOLD_EXCEEDED, INCIDENT_STATE_CHANGE, CONTAINMENT_ACTION)
   - Auto-exports audit trail to JSON with signatures
   - Integration: DatabaseManager extended with audit_log table

2. **MitreMapper** (MitreMapper.hpp/cpp)
   - Maps 16 detection rules and behavior patterns to MITRE ATT&CK techniques
   - Built-in mappings cover 7 tactics: Execution, Persistence, Defense Evasion, C2, Lateral Movement, Collection, Resource Development
   - MapRule(name) returns techniques for detection rule
   - MapEvent(event) infers MITRE techniques from event metadata
   - GetCoverageStats() provides framework coverage summary

3. **ComplianceReporter** (ComplianceReporter.hpp/cpp)
   - Generates automated compliance reports for 3 frameworks:
     * PCI-DSS v4.0: 8 controls (audit trails, anti-malware, incident response, etc.)
     * HIPAA Security Rule: 5 controls (audit controls, integrity mechanisms, incident procedures)
     * SOC 2 Type II: 5 controls (logical access, software prevention, monitoring)
   - Reports include control status (COMPLIANT/NON_COMPLIANT/PARTIAL/NOT_APPLICABLE)
   - Exports as JSON and human-readable HTML
   - Evidence gathering from database

4. **ForensicsExporter** (ForensicsExporter.hpp/cpp)
   - Exports forensic investigation packages with:
     * timeline.json: Ordered events with MITRE technique IDs
     * incidents.json: All incidents in time range
     * audit_trail.json: Signed audit log entries
     * artifacts/: Collected quarantined files
     * manifest.json: SHA-256 integrity checksums of all files
   - BuildTimeline() creates chronological event sequence
   - CollectQuarantineArtifacts() copies quarantined samples
   - GenerateManifest() creates integrity verification metadata

## Database Integration (persistence/DatabaseManager):
   - New audit_log table with fields:
     * sequence_id (AUTOINCREMENT)
     * timestamp (ISO8601 string)
     * action, actor, target, details (audit metadata)
     * prev_hash, entry_hash (integrity chain)
   - New methods: InsertAuditEntry(), QueryAuditEntriesRaw(), GetAuditEntryCount()

## Build System (CMakeLists.txt):
   - New cortex_compliance static library (lines 109-129)
   - Links to: cortex_core, cortex_engine, cortex_persistence, cortex_response, OpenSSL, nlohmann_json
   - Linked to CortexEDR executable, CortexEDR_GUI, and cortex_tests
   - test_compliance.cpp integrated (30 new tests)

## Integration (main.cpp):
   - Phase 5 initialization (lines 178-213):
     * AuditLogger initialization with HMAC key from config
     * MitreMapper initialization with built-in mappings
     * ComplianceReporter initialization with DB + AuditLogger
     * ForensicsExporter initialization with DB + MitreMapper + AuditLogger
   - Phase 5 startup (lines 282-286): Start AuditLogger + subscribe to events
   - Phase 5 shutdown (lines 346-349): Stop AuditLogger before shutdown
   - Updated banner to "Phase 5: Compliance & Reporting"

## Configuration (config/config.yaml):
   - New compliance section (lines 125-135):
     * audit_log: enabled flag + HMAC key
     * reporting: output_dir for compliance reports
     * forensics: output_dir + include_quarantine_files flag

## Documentation Updates:
   - README.md: Added compliance/ architecture section, Phase 5 status, compliance config examples
   - QUICKSTART.md: Added Part 4 with Phase 5 testing scenarios, compliance testing guide, MITRE mapping table

## Tests (tests/test_compliance.cpp - 30 new tests):
   - AuditLogger: 6 tests (insertion, integrity verification, export, empty chain)
   - MitreMapper: 14 tests (rule mapping, technique lookup, coverage stats, event mapping)
   - ComplianceReporter: 7 tests (PCI-DSS, HIPAA, SOC 2 report generation, JSON/HTML export, field validation)
   - ForensicsExporter: 3 tests (timeline export, package creation, manifest validation)
   - All 80 unit tests passing (50 existing + 30 new)

## Key Technical Details:
   - HMAC computation excludes sequence_id to ensure consistency between insertion and verification
   - Uses ISO8601 timestamp strings (matching DB storage) for HMAC verification
   - OpenSSL 3.0 EVP API used for SHA-256 file hashing (replaces deprecated SHA256_Init/Update/Final)
   - Thread-safe operations with std::lock_guard on all shared state
   - EventBus integration for automatic audit logging of security events
   - Cryptographically sound integrity chain using HMAC-SHA256

## Security Notes:
   - Default HMAC key provided for demo; MUST be changed in production (config.yaml)
   - Audit chain integrity verified before reporting
   - Quarantine artifacts SHA-256 hashed for forensics chain-of-custody
   - Manifest generation includes all files with cryptographic verification

All components follow existing CortexEDR patterns: header+cpp pairs, SQLite persistence, thread-safe operations, and EventBus integration.

Co-Authored-By: Claude Haiku 4.5 <noreply@anthropic.com>
