# CortexEDR - Windows Endpoint Detection & Response

A production-grade Windows EDR (Endpoint Detection & Response) prototype built in C++ for cybersecurity portfolio demonstration. CortexEDR monitors process, file, network, and registry activity in real-time using native Windows APIs, scores behavior dynamically, and provides automated threat response capabilities.

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
├── engine/                   # Analysis and correlation (Phase 2)
│   ├── RiskScorer            # Weighted multi-signal scoring engine
│   ├── RuleEngine            # YAML-loaded IOC and behavioral rules
│   └── BehaviorCorrelator    # Time-window event correlation
│
├── response/                 # Automated response (Phase 2)
│   ├── ContainmentManager    # Process kill, network block, file quarantine
│   └── IncidentManager       # State machine: NEW → ACTIVE → CONTAINED → CLOSED
│
├── telemetry/                # Data export (Phase 2)
│   └── TelemetryExporter     # JSON event export to file/named pipe
│
├── ui/                       # User interface (Phase 2)
│   └── Dashboard             # Real-time CLI dashboard
│
├── config/
│   └── config.yaml           # Operator-configurable settings
│
└── main.cpp                  # Application entry point
```

## Current Status: Phase 1 Complete

**Implemented:**
- ✅ Core event bus with pub/sub architecture
- ✅ Thread pool for async task execution
- ✅ Structured logging with rotation (spdlog)
- ✅ Process monitoring via ETW (Event Tracing for Windows)
- ✅ File monitoring via ReadDirectoryChangesW
- ✅ Network monitoring via IP Helper API
- ✅ Registry monitoring via RegNotifyChangeKeyValue
- ✅ Basic risk scoring engine
- ✅ Unit tests for core components
- ✅ Configuration system (YAML)

**Next Phases:**
- 🔄 Phase 2: Rule engine, behavioral correlator, containment manager
- 🔄 Phase 3: Incident lifecycle manager, telemetry exporter
- 🔄 Phase 4: CLI dashboard, advanced detection patterns

## Technical Requirements

### Platform
- Windows 10 1903+ or Windows 11 (x64)
- Visual Studio 2022 or MSVC compiler with C++20 support
- Administrator privileges (required for ETW and system monitoring)

### Build Tools
- CMake 3.20+
- vcpkg package manager

### Dependencies (via vcpkg)
- `yaml-cpp` - Configuration file parsing
- `nlohmann-json` - JSON serialization
- `spdlog` - Structured logging
- `gtest` - Unit testing framework
- `openssl` - Hash verification

## Build Instructions

### 1. Install vcpkg (if not already installed)

```powershell
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg
.\bootstrap-vcpkg.bat
.\vcpkg integrate install
```

### 2. Clone the repository

```powershell
git clone https://github.com/yourusername/CortexEDR.git
cd CortexEDR
```

### 3. Build with CMake

```powershell
# Configure
cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=[path to vcpkg]/scripts/buildsystems/vcpkg.cmake

# Build
cmake --build build --config Release

# Run tests
cd build
ctest -C Release
```

### 4. Run CortexEDR

```powershell
# Must run as Administrator
.\build\Release\CortexEDR.exe
```

## Privilege Requirements

CortexEDR requires the following Windows privileges to function fully:

- **SeDebugPrivilege** - Required for ETW process monitoring and process inspection
- **SeSecurityPrivilege** - Required for accessing security descriptors
- **SeTcbPrivilege** - Required for advanced system monitoring

The application will attempt to escalate privileges at startup. If privileges are unavailable, certain features will be degraded gracefully with appropriate logging.

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
```

## Risk Scoring Model

CortexEDR uses a weighted additive scoring model (0-100 scale):

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

## Testing

```powershell
# Run all unit tests
cd build
ctest -C Release --verbose

# Run specific test
.\Release\cortex_tests.exe --gtest_filter=EventBusTest.*
```

## Known Limitations

- **Userspace Only**: No kernel driver; relies on ETW and Win32 APIs
- **ETW Restrictions**: Requires administrator privileges for process monitoring
- **Polling Overhead**: Network monitoring uses polling (2s default interval)
- **Limited Evasion Detection**: Does not detect kernel-level rootkits or bootkits
- **No Machine Learning**: Uses rule-based detection only (by design)

## Future Roadmap

### Phase 2: Detection Engine
- YAML-based rule engine for IOC matching
- Behavioral correlation across event timelines
- Pattern detection (dropper, persistence, lateral movement)

### Phase 3: Response & Containment
- Automated process termination
- Windows Firewall integration for network blocking
- File quarantine with DACL lockdown
- Incident lifecycle state machine

### Phase 4: Visibility & Telemetry
- Real-time CLI dashboard with ANSI/ncurses
- NDJSON event export for SIEM integration
- Named pipe interface for external tools
- Incident timeline visualization

## License

MIT License - see LICENSE file for details

## Author

Built as a cybersecurity internship portfolio project demonstrating:
- Windows internals expertise (ETW, Win32 APIs, COM)
- System-level C++ programming
- Security architecture and threat modeling
- Professional software engineering practices

## Disclaimer

This is an educational prototype for portfolio demonstration purposes. It is NOT intended for production deployment without significant hardening, testing, and security review. Use at your own risk.
