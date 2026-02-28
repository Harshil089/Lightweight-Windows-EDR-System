# CortexEDR - Windows Endpoint Detection & Response

A production-grade Windows EDR (Endpoint Detection & Response) prototype built in C++ for cybersecurity portfolio demonstration. CortexEDR monitors process, file, network, and registry activity in real-time using native Windows APIs, scores behavior dynamically, provides automated threat response capabilities, and ships with a full Qt6 graphical user interface.

## Architecture

```
CortexEDR/
├── core/                      # Core infrastructure
│   ├── EventBus              # Thread-safe publish/subscribe event dispatcher
│   ├── ThreadPool            # Fixed-size worker thread pool
│   └── Logger                # Structured rotating file logger (spdlog)
│
├── collectors/               # Event ingestion layer
│   ├── ProcessMonitor        # ETW-based process creation/termination tracking
│   ├── FileMonitor           # ReadDirectoryChangesW file system watcher
│   ├── NetworkMonitor        # IP Helper API connection enumeration
│   └── RegistryMonitor       # RegNotifyChangeKeyValue registry watcher
│
├── engine/                   # Analysis and correlation
│   ├── RiskScorer            # Weighted multi-signal scoring engine
│   ├── RuleEngine            # YAML-loaded IOC and behavioral rules
│   └── BehaviorCorrelator    # Time-window event correlation
│
├── response/                 # Automated response
│   ├── ContainmentManager    # Process kill, network block, file quarantine
│   └── IncidentManager       # State machine: NEW → ACTIVE → CONTAINED → CLOSED
│
├── telemetry/                # Data export
│   └── TelemetryExporter     # JSON event export to file/named pipe
│
├── compliance/               # Compliance & reporting (Phase 5)
│   ├── AuditLogger           # Tamper-proof HMAC-SHA256 integrity chain
│   ├── MitreMapper           # MITRE ATT&CK technique mapping (16 techniques)
│   ├── ComplianceReporter    # PCI-DSS / HIPAA / SOC 2 reports
│   └── ForensicsExporter     # Timeline + artifact collection + SHA-256 manifests
│
├── ui/                       # Qt6 graphical user interface
│   ├── EDRBridge             # MVC adapter connecting Qt signals/slots to the backend
│   ├── MainWindow            # Sidebar navigation + QStackedWidget layout
│   ├── DashboardPanel        # Real-time status cards, threat counters
│   ├── QuickScanPanel        # Targeted scan with progress bar and results log
│   ├── FullScanPanel         # Full system scan with ETA, pause/resume
│   ├── RealTimeProtectionPanel # Toggle real-time protection + monitor status rows
│   ├── QuarantinePanel       # Quarantine table with restore and permanent-delete
│   ├── LogsPanel             # Filterable event log viewer
│   ├── SettingsPanel         # Sensitivity, heuristics, exclusion folders
│   └── AboutPanel            # Version and engine component info
│
├── tests/                    # Unit tests (GTest)
│   ├── test_eventbus.cpp
│   ├── test_threadpool.cpp
│   ├── test_riskscorer.cpp
│   └── test_incidentmanager.cpp
│
├── config/
│   ├── config.yaml           # Operator-configurable settings
│   └── rules.yaml            # Detection rules for the RuleEngine
│
├── main.cpp                  # Console EDR engine entry point
└── main_gui.cpp              # Qt6 GUI entry point
```

## Current Status: Phase 5 Complete (Compliance & Reporting)

**Latest Additions (Phase 5):**
- Tamper-proof audit logging with HMAC-SHA256 integrity chain verification
- MITRE ATT&CK mapping for all detection rules and behavior patterns
- Automated compliance report generation for PCI-DSS, HIPAA, and SOC 2 frameworks
- Forensics data export with SHA-256 integrity manifests
- 80/80 unit tests passing (30 new compliance tests)

## Previous Status: All Core Phases Complete

**Core Infrastructure:**
- ✅ Core event bus with pub/sub architecture
- ✅ Thread pool for async task execution
- ✅ Structured logging with rotation (spdlog)

**Collectors:**
- ✅ Process monitoring via ETW (Event Tracing for Windows)
- ✅ File monitoring via ReadDirectoryChangesW
- ✅ Network monitoring via IP Helper API
- ✅ Registry monitoring via RegNotifyChangeKeyValue

**Detection Engine:**
- ✅ Weighted risk scoring engine (multi-signal, 0–100 scale)
- ✅ YAML-based rule engine for IOC and behavioral rule matching
- ✅ Behavioral correlator for time-window event correlation

**Response & Containment:**
- ✅ ContainmentManager: process kill, network block, file quarantine
- ✅ IncidentManager: state machine (NEW → ACTIVE → CONTAINED → CLOSED) with JSON persistence

**Telemetry:**
- ✅ JSON event export to file and named pipe

**Compliance & Reporting (Phase 5):**
- ✅ AuditLogger: Tamper-proof audit trail with HMAC-SHA256 integrity chain
- ✅ MitreMapper: Maps 16 detection rules/patterns to MITRE ATT&CK techniques
- ✅ ComplianceReporter: Generates PCI-DSS v4.0, HIPAA, and SOC 2 Type II reports (JSON + HTML)
- ✅ ForensicsExporter: Event timelines, incident data, artifact collection, SHA-256 integrity manifests

**Qt6 GUI:**
- ✅ Dark-mode sidebar application (Windows Defender / Malwarebytes aesthetic)
- ✅ Dashboard with live status cards
- ✅ Quick Scan and Full System Scan with progress, ETA, and results
- ✅ Real-Time Protection toggle with per-monitor status rows
- ✅ Quarantine management (restore / permanent delete with confirmation)
- ✅ Filterable event log viewer
- ✅ Settings panel (sensitivity slider, heuristics, exclusion folders, definition updates)
- ✅ System tray icon with threat notifications and minimize-to-tray
- ✅ Full MVC separation — GUI has no backend header dependencies

**Tests:**
- ✅ Unit tests for EventBus, ThreadPool, RiskScorer, IncidentManager

## Technical Requirements

### Platform
- Windows 10 1903+ or Windows 11 (x64)
- Visual Studio 2022 or MSVC compiler with C++20 support
- Administrator privileges (required for ETW and system monitoring)

### Build Tools
- CMake 3.20+
- vcpkg package manager

### Dependencies (via vcpkg)
- `yaml-cpp` — Configuration file parsing
- `nlohmann-json` — JSON serialization
- `spdlog` — Structured logging
- `gtest` — Unit testing framework
- `openssl` — Hash verification

### Optional (GUI)
- `Qt6` (Widgets module) — Qt 6.2 or later; install separately from [qt.io](https://www.qt.io/download)

## Build Instructions

### 1. Install vcpkg (if not already installed)

```powershell
git clone https://github.com/Microsoft/vcpkg.git C:\vcpkg
cd C:\vcpkg
.\bootstrap-vcpkg.bat
.\vcpkg integrate install
setx VCPKG_ROOT "C:\vcpkg" /M
```

### 2. Install backend dependencies

```powershell
cd C:\vcpkg
.\vcpkg install yaml-cpp:x64-windows nlohmann-json:x64-windows spdlog:x64-windows gtest:x64-windows openssl:x64-windows
```

### 3. Configure and build the console engine only

```powershell
# From the project root directory
cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=C:\vcpkg\scripts\buildsystems\vcpkg.cmake -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

Output: `.\build\Release\CortexEDR.exe`

### 4. Configure and build with Qt6 GUI (optional)

First, install Qt6 from [qt.io](https://www.qt.io/download) — download the **MSVC 2022 64-bit** kit to `C:\Qt\6.x.x` (replace `6.x.x` with your installed version).

Then configure with GUI enabled:

```powershell
# From the project root directory
cmake -B build -S . `
  -DCMAKE_TOOLCHAIN_FILE=C:\vcpkg\scripts\buildsystems\vcpkg.cmake `
  -DCMAKE_PREFIX_PATH="C:\Qt\6.x.x\msvc2022_64" `
  -DBUILD_GUI=ON `
  -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

Outputs:
- `.\build\Release\CortexEDR.exe` (console engine)
- `.\build\Release\CortexEDR_GUI.exe` (Qt6 GUI application)

**Note:** If Qt6 is not found, CMake will silently skip the GUI target and build only the console engine.

### 5. Run unit tests

```powershell
# Run all tests
cd build
ctest -C Release --verbose

# Or run the test executable directly
.\Release\cortex_tests.exe

# Run specific test suites
.\Release\cortex_tests.exe --gtest_filter=EventBusTest.*
.\Release\cortex_tests.exe --gtest_filter=RiskScorerTest.*
.\Release\cortex_tests.exe --gtest_filter=IncidentManagerTest.*
```

## Running CortexEDR

### Console Engine (requires Administrator)

```powershell
# Right-click PowerShell → "Run as Administrator"
cd C:\Lightweight-Windows-EDR-System
.\build\Release\CortexEDR.exe
```

The console engine will:
- Initialize all system monitors (Process, File, Registry, Network)
- Load detection rules from `config/rules.yaml`
- Begin logging events to `logs/cortex.log`
- Monitor system activity in real-time
- Score and respond to threats according to configured thresholds

Press `Ctrl+C` to gracefully shut down the engine.

### GUI Application (recommended for monitoring and management)

The Qt6 GUI provides a full graphical interface for monitoring and controlling the engine. It does not require Administrator privileges itself, but full monitoring features require the console engine running separately with elevated privileges.

#### Run the GUI from the build directory

```powershell
# No Administrator required for the GUI itself
.\build\Release\CortexEDR_GUI.exe
```

#### Deploy for standalone distribution

If you want to run the GUI outside the build directory, bundle the Qt6 runtime libraries:

```powershell
# From Qt installation directory
C:\Qt\6.x.x\msvc2022_64\bin\windeployqt.exe .\build\Release\CortexEDR_GUI.exe
```

This creates a deployment directory with all necessary Qt DLLs. Copy the entire folder to your target machine.

#### Deployment checklist

```
CortexEDR_Distribution/
├── CortexEDR.exe                 (console engine, copy from build\Release)
├── CortexEDR_GUI.exe             (GUI application, copy from build\Release)
├── config/
│   ├── config.yaml              (settings)
│   └── rules.yaml               (detection rules)
├── logs/                         (auto-created at runtime)
├── Qt libraries/                 (generated by windeployqt)
│   ├── Qt6Core.dll
│   ├── Qt6Gui.dll
│   ├── Qt6Widgets.dll
│   └── [other Qt DLLs]
└── [other dependencies]
```

## Privilege Requirements

CortexEDR (console engine) requires the following Windows privileges:

- **SeDebugPrivilege** — Required for ETW process monitoring and process inspection
- **SeSecurityPrivilege** — Required for accessing security descriptors
- **SeTcbPrivilege** — Required for advanced system monitoring

The application will attempt to escalate privileges at startup. If privileges are unavailable, certain features degrade gracefully with appropriate logging.

## Configuration

Edit `config/config.yaml` to customize behavior:

```yaml
# Risk scoring thresholds (0-100 scale)
risk_scoring:
  thresholds:
    low: 30      # Alert only
    medium: 60   # Escalate
    high: 80     # Auto-contain
    critical: 100

# File monitoring paths
file_monitoring:
  watch_paths:
    - C:\Users
    - C:\Windows\System32

# Network monitoring
network_monitoring:
  poll_interval_seconds: 2
  suspicious_ports:
    - 4444  # Metasploit
    - 1337  # Elite
    - 6667  # IRC

# Compliance & Reporting (Phase 5)
compliance:
  audit_log:
    enabled: true
    hmac_key: "cortex-edr-default-hmac-key-change-in-production"
  reporting:
    output_dir: reports/
  forensics:
    output_dir: forensics/
    include_quarantine_files: true
```

## Risk Scoring Model

CortexEDR uses a weighted additive scoring model (0–100 scale):

| Signal | Weight | Trigger Condition |
|--------|--------|-------------------|
| Process spawned from temp/appdata | 15 | Image path in suspicious dirs |
| Process has no parent (orphan) | 10 | PPID not in active process list |
| Unsigned or invalid PE signature | 20 | WinVerifyTrust returns failure |
| Rapid child process spawning | 15 | >5 children in 10s window |
| Network connection to external IP | 10 | Remote IP outside RFC1918 ranges |
| Connection to high-risk port | 15 | Port in configurable blocklist |
| Registry run key modification | 20 | Write to persistence hive |
| Write to system directory | 15 | File write under System32 etc. |
| Known bad hash (MD5/SHA256) | 30 | Match against local IOC list |

## GUI Overview

The Qt6 GUI (`CortexEDR_GUI.exe`) provides a full dark-mode interface built with strict MVC separation:

| Panel | Description |
|-------|-------------|
| Dashboard | Live status cards: protection state, last scan time, threat count, system health |
| Quick Scan | Targeted scan with real-time progress bar, current file display, and results log |
| Full System Scan | Full drive scan with ETA, pause/resume, and directory traversal log |
| Real-Time Protection | Master toggle + individual monitor status (Process, Registry, FileSystem, Network) |
| Quarantine | Table of quarantined files with restore and permanent-delete (double-confirmation) |
| Logs | Filterable event log (All / Threats / System Events / Scan Logs), color-coded by severity |
| Settings | Scan sensitivity slider, heuristic toggle, exclusion folder manager, definition updater |
| About | Version info and engine component details |

The GUI's `EDRBridge` adapter layer isolates all Qt code from backend headers, preventing Windows CRT / Qt template conflicts and ensuring clean compilation.

## Testing

```powershell
# Run all unit tests
cd build
ctest -C Release --verbose

# Run a specific test suite
.\Release\cortex_tests.exe --gtest_filter=EventBusTest.*
.\Release\cortex_tests.exe --gtest_filter=IncidentManagerTest.*
```

## Known Limitations

- **Userspace Only**: No kernel driver; relies on ETW and Win32 APIs
- **ETW Restrictions**: Requires Administrator privileges for process monitoring
- **Polling Overhead**: Network monitoring uses polling (2s default interval)
- **Limited Evasion Detection**: Does not detect kernel-level rootkits or bootkits
- **No Machine Learning**: Uses rule-based detection only (by design)
- **GUI Simulation**: The GUI's scan engine uses heuristic file inspection independent of the console EDR engine; full integration is the planned next step

## License

MIT License — see LICENSE file for details

## Author

Built as a cybersecurity portfolio project demonstrating:
- Windows internals expertise (ETW, Win32 APIs, COM)
- System-level C++ programming (C++20, RAII, smart pointers, thread safety)
- Security architecture and threat modeling
- Qt6 GUI development with strict MVC separation
- Professional software engineering practices (event-driven architecture, clean layering)

## Disclaimer

This is an educational prototype for portfolio demonstration purposes. It is NOT intended for production deployment without significant hardening, testing, and security review. Use at your own risk.
