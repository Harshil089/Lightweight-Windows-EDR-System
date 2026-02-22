# Windows EDR System Prototype — Master Build Prompt  
  
## Role & Context  
You are a **senior C++ systems engineer and cybersecurity architect** with deep expertise in Windows internals, threat detection engineering, and endpoint security product development. You are building a **production-grade Windows EDR (Endpoint Detection & Response) prototype** for a cybersecurity student's internship portfolio. The code must be professional, well-structured, and demonstrate real engineering competence — not toy-level implementations.  
  
## Project Identity  
**Project Name:** CortexEDR **Language:** C++17 or C++20 **Platform:** Windows 10/11 (x64) **Build System:** CMake + vcpkg **Architecture:** Multi-threaded, event-driven, modular monolith  
  
## Objective  
Build a fully functional Windows EDR prototype that monitors process, file, network, and registry activity in real time using native Win32 APIs and Windows kernel event interfaces, scores behavior dynamically using a risk engine, automatically contains threats, and manages the full incident lifecycle through a state machine — all exposed through a structured CLI dashboard.  
  
## System Architecture  
Design the system using the following layered module structure:  
```
CortexEDR/
├── core/
│   ├── EventBus.hpp/.cpp          # Thread-safe publish/subscribe event dispatcher
│   ├── ThreadPool.hpp/.cpp        # Fixed-size worker thread pool
│   └── Logger.hpp/.cpp            # Structured rotating file logger
├── collectors/
│   ├── ProcessMonitor.hpp/.cpp    # ETW/WMI process creation & termination
│   ├── FileMonitor.hpp/.cpp       # ReadDirectoryChangesW recursive watcher
│   ├── NetworkMonitor.hpp/.cpp    # IP Helper API connection enumeration
│   └── RegistryMonitor.hpp/.cpp   # RegNotifyChangeKeyValue watcher
├── engine/
│   ├── RiskScorer.hpp/.cpp        # Weighted multi-signal scoring engine
│   ├── RuleEngine.hpp/.cpp        # YAML-loaded IOC and behavioral rules
│   └── BehaviorCorrelator.hpp/.cpp# Time-window event correlation
├── response/
│   ├── ContainmentManager.hpp/.cpp# Process kill, network block, file quarantine
│   └── IncidentManager.hpp/.cpp   # State machine: NEW → ACTIVE → CONTAINED → CLOSED
├── telemetry/
│   └── TelemetryExporter.hpp/.cpp # JSON event export to local file / named pipe
├── ui/
│   └── Dashboard.hpp/.cpp         # Real-time CLI dashboard (pdcurses or raw ANSI)
├── config/
│   └── config.yaml                # Operator-configurable thresholds and rules
└── main.cpp

```
  
## Module Requirements  
## 1. Collectors (Event Ingestion Layer)  
**ProcessMonitor**  
* Use **ETW (Event Tracing for Windows)** via StartTrace, EnableTraceEx2, ProcessTrace on the Microsoft-Windows-Kernel-Process provider to capture real-time process create/terminate events  
* Capture: PID, PPID, image path, command line, user SID, integrity level, session ID, timestamp  
* Fallback: WMI Win32_ProcessStartTrace via COM if ETW elevation is unavailable  
**FileMonitor**  
* Use ReadDirectoryChangesW with FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SECURITY on configurable watch paths  
* Track: file path, change type, process responsible (correlate via handle enumeration), timestamp  
* Flag writes to: %TEMP%, %APPDATA%, %STARTUP%, C:\Windows\System32  
**NetworkMonitor**  
* Poll GetExtendedTcpTable / GetExtendedUdpTable from iphlpapi.h on a configurable interval (default 2s)  
* Detect new connections by diffing against previous snapshot  
* Capture: local/remote IP, port, protocol, owning PID, connection state  
* Flag: connections to non-RFC1918 IPs, high-risk ports (4444, 1337, 6667), rapid new connection bursts  
**RegistryMonitor**  
* Use RegNotifyChangeKeyValue with REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_NAME on persistence-relevant hives:  
    * HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run  
    * HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run  
    * HKLM\SYSTEM\CurrentControlSet\Services  
* Capture: key path, value name, new data, modifying PID  
  
## 2. Risk Scoring Engine  
Implement a **weighted additive scoring model** with a normalized output of 0–100:  

| Signal | Weight | Trigger Condition |
| --------------------------------- | ------ | -------------------------------- |
| Process spawned from temp/appdata | 15 | Image path in suspicious dirs |
| Process has no parent (orphan) | 10 | PPID not in active process list |
| Unsigned or invalid PE signature | 20 | WinVerifyTrust returns failure |
| Rapid child process spawning | 15 | >5 children in 10s window |
| Network connection to non-RFC1918 | 10 | Remote IP outside private ranges |
| Connection to high-risk port | 15 | Port in configurable blocklist |
| Registry run key modification | 20 | Write to persistence hive |
| Write to system directory | 15 | File write under System32 etc. |
| Known bad hash (MD5/SHA256) | 30 | Match against local IOC list |
  
Scoring thresholds (configurable via config.yaml):  
* 0–29 → **LOW** (log only)  
* 30–59 → **MEDIUM** (alert + escalate)  
* 60–79 → **HIGH** (alert + auto-contain)  
* 80–100 → **CRITICAL** (immediate kill + quarantine)  
  
## 3. Behavioral Correlator  
Implement a **sliding time-window correlation engine**:  
* Maintain a per-PID event timeline (ring buffer, last 60 seconds)  
* Define composite behavioral patterns:  
    * **Dropper Pattern:** Process write to temp → spawn child → child makes external network connection (within 30s)  
    * **Persistence Pattern:** Process write to run key → new process entry with same image path  
    * **Lateral Movement Pattern:** Process opens multiple remote SMB connections in short window  
* When a pattern matches, add a **pattern bonus score** (+20) to the process risk score and emit a correlated alert event  
  
## 4. Containment Manager  
Implement automated response actions triggered by score threshold:  
* **Process Kill:** TerminateProcess(OpenProcess(PROCESS_TERMINATE, ...)) with privilege escalation via AdjustTokenPrivileges for SeDebugPrivilege  
* **Network Block:** Add Windows Firewall rule via INetFwRules COM interface to block the offending PID's remote IP  
* **File Quarantine:** Move suspicious file to a locked quarantine\ directory, rename with .quarantine extension, set DACL to deny all access except SYSTEM  
* **Process Suspension:** NtSuspendProcess via ntdll dynamic load as a less-destructive pre-kill option  
* All containment actions must be **logged, reversible (undo registry), and require confirmation in interactive mode**  
  
## 5. Incident Lifecycle State Machine  
Each detected threat becomes an **Incident** object with UUID, managed through states:  
```
NEW → INVESTIGATING → ACTIVE → CONTAINED → CLOSED
                          ↓
                       ESCALATED

```
* State transitions triggered by: score threshold crossings, manual operator commands, containment completion  
* Each incident stores: UUID, PID, process name, all associated events, risk score timeline, containment actions taken, timestamps per state transition  
* Incidents serialized to incidents/YYYY-MM-DD_UUID.json on state change  
* CLI commands: list, inspect <uuid>, contain <uuid>, close <uuid>, revert <uuid>  
  
## 6. Telemetry Exporter  
* Export all events as **structured JSON** (one event per line, NDJSON format) to telemetry/events.ndjson  
* Event schema:  
```
{
  "timestamp": "ISO8601",
  "event_type": "PROCESS_CREATE | FILE_WRITE | NET_CONNECT | REG_WRITE",
  "pid": 1234,
  "process_name": "powershell.exe",
  "risk_score": 75,
  "details": { ... }
}

```
* Optionally write to a **named pipe** (\\.\pipe\CortexEDR) so external tools can consume the stream  
  
## 7. CLI Dashboard  
Build a real-time terminal dashboard (refresh every 2 seconds) displaying:  
```
╔══════════════════════════════════════════════════════╗
║              CortexEDR — Live Threat Monitor         ║
╠══════════════════════════════════════════════════════╣
║ Active Processes Monitored: 187  │ Incidents: 3      ║
║ Events/sec: 42   │ Uptime: 00:14:32                  ║
╠══════════════════════════════════════════════════════╣
║ PID    │ Process         │ Score │ Status             ║
║ 4821   │ powershell.exe  │  78   │ ⚠ HIGH - ACTIVE   ║
║ 2204   │ cmd.exe         │  92   │ 🔴 CRITICAL        ║
╠══════════════════════════════════════════════════════╣
║ Recent Alerts                                        ║
║ [14:32:01] PID 4821 wrote to HKCU\Run              ║
║ [14:32:04] PID 2204 connected to 185.220.101.5     ║
╚══════════════════════════════════════════════════════╝

```
  
## Technical Standards  
**Code Quality**  
* All modules implement a clean interface with a pure virtual ICollector / IResponder base  
* No raw owning pointers — use std::unique_ptr / std::shared_ptr throughout  
* All shared state protected by std::mutex or std::shared_mutex; prefer lock-free where feasible  
* RAII wrappers around all Win32 handles (HANDLE, HKEY, SC_HANDLE)  
* Error handling via std::expected<T, EDRError> (C++23) or a custom Result<T> type — no naked GetLastError() leaks  
**Logging**  
* Structured log entries: [LEVEL][MODULE][TIMESTAMP] message {key=value}  
* Log rotation at 10MB, keep last 5 files  
* Log levels: TRACE, DEBUG, INFO, WARN, ERROR, CRITICAL  
**Configuration**  
* All thresholds, watch paths, rule sets, and response modes loaded from config.yaml at startup  
* Support live reload of config on SIGHUP equivalent (named event or console signal)  
**Privilege Model**  
* Document required privileges: SeDebugPrivilege, SeSecurityPrivilege, SeTcbPrivilege  
* Attempt privilege escalation at startup and log failures gracefully; degrade non-critical features if unavailable  
**Testing**  
* Unit tests for: RiskScorer (score calculation correctness), RuleEngine (rule matching), IncidentManager (state transitions), BehaviorCorrelator (pattern detection)  
* Integration test: simulate a dropper sequence (file write → process create → network connect) and verify detection + containment fires correctly  
* Use **Google Test** via vcpkg  
  
## Build & Delivery Requirements  
**CMakeLists.txt** must:  
* Support Debug / Release / RelWithDebInfo configurations  
* Link: iphlpapi, ws2_32, advapi32, ole32, oleaut32, ntdll, wbemuuid  
* vcpkg dependencies: yaml-cpp, nlohmann-json, spdlog, gtest, openssl (for hash verification)  
**README.md** must include:  
* Architecture diagram (ASCII)  
* Build instructions (CMake + vcpkg)  
* Privilege requirements  
* Module descriptions  
* Example CLI usage  
* Known limitations and future roadmap  
  
## Constraints  
* No paid libraries, no commercial SDKs  
* No kernel driver (stay in userspace — use ETW, Win32 APIs, COM, IP Helper)  
* Must compile cleanly on MSVC 2022 with /W4 /WX (warnings as errors)  
* Must run on Windows 10 1903+ without additional software installs beyond the binary  
* No dependency on third-party AV or EDR products  
  
## Deliverables  
1. Complete C++ source tree matching the module structure above  
2. CMakeLists.txt with full dependency and link configuration  
3. config.yaml with documented default values  
4. README.md with architecture overview and build guide  
5. Google Test suite covering core engine logic  
6. Sample telemetry output (sample_events.ndjson)  
  
*Build this as if it will be reviewed by a security engineering team at a top-tier cybersecurity firm. Every design decision should be defensible. Every line of code should reflect production discipline.*  
