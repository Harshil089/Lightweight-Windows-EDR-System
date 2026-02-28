# CortexEDR Quick Start Guide

This guide will get CortexEDR running on your Windows system in under 15 minutes.
You can run the **console engine** (no dependencies beyond vcpkg), the **Qt6 GUI**, or both.

## Prerequisites Checklist

- [ ] Windows 10 1903+ or Windows 11 (x64)
- [ ] Visual Studio 2022 with "Desktop development with C++" workload
- [ ] Administrator access to your system
- [ ] At least 3 GB free disk space (more if installing Qt6)
- [ ] CMake 3.20+ (included with Visual Studio 2022 or install separately)

---

## Part 1 — Console Engine Setup

### 1. Install vcpkg Package Manager

Open PowerShell as Administrator:

```powershell
# Clone vcpkg to C:\vcpkg
git clone https://github.com/Microsoft/vcpkg.git C:\vcpkg
cd C:\vcpkg

# Bootstrap and integrate with Visual Studio
.\bootstrap-vcpkg.bat
.\vcpkg integrate install

# Persist the root path for all future terminals
setx VCPKG_ROOT "C:\vcpkg" /M
```

> Close and reopen PowerShell after setting the environment variable.

### 2. Install Backend Dependencies

```powershell
cd C:\vcpkg

# Install all required packages (10–15 minutes)
.\vcpkg install yaml-cpp:x64-windows `
               nlohmann-json:x64-windows `
               spdlog:x64-windows `
               gtest:x64-windows `
               openssl:x64-windows
```

### 3. Clone CortexEDR

```powershell
git clone https://github.com/yourusername/CortexEDR.git C:\Lightweight-Windows-EDR-System
cd C:\Lightweight-Windows-EDR-System
```

### 4. Build the Console Engine

```powershell
# Configure (disable GUI to skip the Qt6 requirement for now)
cmake -B build -S . `
  -DCMAKE_TOOLCHAIN_FILE=C:\vcpkg\scripts\buildsystems\vcpkg.cmake `
  -DBUILD_GUI=OFF

# Build
cmake --build build --config Release
```

### 5. Run the Console Engine

> **IMPORTANT**: The console engine must run as Administrator for ETW process monitoring.

```powershell
# Right-click PowerShell → "Run as Administrator"
cd C:\Lightweight-Windows-EDR-System
.\build\Release\CortexEDR.exe
```

Expected startup output:

```
[2026-02-28 09:00:00] [info] [CortexEDR] ==========================================================
[2026-02-28 09:00:00] [info] [CortexEDR]   CortexEDR - Windows Endpoint Detection & Response
[2026-02-28 09:00:00] [info] [CortexEDR] ==========================================================
[2026-02-28 09:00:00] [info] [CortexEDR] Initializing CortexEDR...
[2026-02-28 09:00:00] [info] [CortexEDR] Event subscriptions configured
[2026-02-28 09:00:00] [info] [CortexEDR] Starting CortexEDR collectors...
[2026-02-28 09:00:00] [info] [CortexEDR] Starting ProcessMonitor with ETW
[2026-02-28 09:00:00] [info] [CortexEDR] Starting FileMonitor for 2 paths
[2026-02-28 09:00:00] [info] [CortexEDR] Starting NetworkMonitor with 2s poll interval
[2026-02-28 09:00:00] [info] [CortexEDR] Starting RegistryMonitor
[2026-02-28 09:00:00] [info] [CortexEDR] CortexEDR is now running. Press Ctrl+C to stop.
```

### 6. Verify Monitoring Is Active

Open a **second** PowerShell window (no elevation needed):

```powershell
# Trigger process monitoring
notepad.exe

# Trigger file monitoring (watches C:\Users and C:\Windows\System32 by default)
New-Item -Path "$env:USERPROFILE\Documents\test_edr.txt" -ItemType File -Force

# Trigger network monitoring
Test-NetConnection -ComputerName 8.8.8.8 -Port 443

# Trigger registry persistence monitoring
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v EDRTest /d "C:\test.exe" /f
# Clean up after testing
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v EDRTest /f
```

Watch the first window — events should appear in real time.

### 7. View Logs

CortexEDR writes structured logs to `logs\cortex.log`:

```powershell
# Stream live output
Get-Content C:\Lightweight-Windows-EDR-System\logs\cortex.log -Wait -Tail 30

# Show only warnings and above
Get-Content C:\Lightweight-Windows-EDR-System\logs\cortex.log |
    Where-Object { $_ -match '\[(warn|error|critical)\]' }

# Search for high-risk detections
Select-String -Path C:\Lightweight-Windows-EDR-System\logs\cortex.log -Pattern "HIGH RISK"
```

### 8. Inspect the Active ETW Session

```powershell
# List all active ETW trace sessions (look for "NT Kernel Logger")
logman query -ets

# Show NT Kernel Logger details
logman query "NT Kernel Logger" -ets
```

### 9. Stop the Console Engine

Press `Ctrl+C`. Expected shutdown output:

```
[info] Received shutdown signal
[info] Stopping CortexEDR...
[info] Stopping RegistryMonitor
[info] Stopping NetworkMonitor
[info] Stopping FileMonitor
[info] Stopping ProcessMonitor
[info] All collectors stopped
[info] CortexEDR shutdown complete
```

If the process is killed without a clean shutdown, release the ETW session manually:

```powershell
logman stop "NT Kernel Logger" -ets
```

---

## Part 2 — Qt6 GUI Setup

### 1. Install Qt6

Download the Qt Online Installer from [qt.io/download](https://www.qt.io/download).

During installation select:
- **Qt 6.x** → **MSVC 2022 64-bit**

Note the install path (default: `C:\Qt`).

### 2. Build with GUI Enabled

```powershell
cd C:\Lightweight-Windows-EDR-System

cmake -B build -S . `
  -DCMAKE_TOOLCHAIN_FILE=C:\vcpkg\scripts\buildsystems\vcpkg.cmake `
  -DCMAKE_PREFIX_PATH="C:\Qt\6.x.x\msvc2022_64" `
  -DBUILD_GUI=ON

cmake --build build --config Release
```

> Replace `6.x.x` with your installed Qt version (e.g. `6.7.2`).
> If Qt6 is not found, the build continues without the GUI target and prints:
> `Qt6 not found - GUI target disabled`

### 3. Deploy Qt Runtime DLLs

The first time you run the GUI outside of Qt Creator, run `windeployqt` to copy the required Qt DLLs next to the executable:

```powershell
# Replace with your Qt bin path
C:\Qt\6.x.x\msvc2022_64\bin\windeployqt.exe .\build\Release\CortexEDR_GUI.exe
```

### 4. Run the GUI

```powershell
.\build\Release\CortexEDR_GUI.exe
```

The GUI does **not** require Administrator privileges to launch. Real-time protection and ETW monitoring features require running the console engine (`CortexEDR.exe`) separately with elevation.

### GUI Navigation

| Panel | What it does |
|-------|-------------|
| Dashboard | Live protection status, threat counter, system health, quick scan shortcut |
| Quick Scan | Targeted scan of common locations with progress and results log |
| Full System Scan | Full drive scan with estimated time remaining, pause/resume |
| Real-Time Protection | Master on/off toggle + status of each monitor (Process, Registry, FileSystem, Network) |
| Quarantine | View, restore, or permanently delete quarantined files |
| Logs | Filterable event log (All / Threats / System Events / Scan Logs) |
| Settings | Scan sensitivity, heuristic analysis, exclusion folders, definition updates |
| About | Version and engine component details |

The application minimizes to the system tray when the window is closed. A tray notification appears when a threat is detected.

---

## Part 3 — Run Tests

```powershell
cd build
ctest -C Release --verbose

# Or run specific test suites directly
.\Release\cortex_tests.exe --gtest_filter=EventBusTest.*
.\Release\cortex_tests.exe --gtest_filter=RiskScorerTest.*
.\Release\cortex_tests.exe --gtest_filter=IncidentManagerTest.*
```

---

## Configuration

Edit `config/config.yaml` to tune CortexEDR behavior:

```yaml
# Risk scoring thresholds
risk_scoring:
  thresholds:
    low: 30
    medium: 60
    high: 80
    critical: 100

# Paths to monitor for file activity
file_monitoring:
  watch_paths:
    - C:\Users
    - C:\Windows\System32
    - C:\ProgramData        # Add custom paths here

# Network monitoring
network_monitoring:
  poll_interval_seconds: 2
  suspicious_ports:
    - 4444   # Metasploit
    - 1337   # Elite
    - 6667   # IRC
```

Restart the console engine after any config changes.

---

## Detection Testing Scenarios

### Test 1: Suspicious Process from Temp

```powershell
copy C:\Windows\System32\notepad.exe C:\Users\Public\temp_payload.exe
C:\Users\Public\temp_payload.exe
# Expect: "process_from_temp" risk signal in logs
```

### Test 2: Registry Persistence

```powershell
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v TestEntry /d "C:\test.exe" /f
# Expect: "registry_persistence" signal in logs
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v TestEntry /f
```

### Test 3: External Network Connection

```powershell
Test-NetConnection -ComputerName 8.8.8.8 -Port 80
# Expect: "external_connection" signal in logs
```

### Test 4: Multi-Signal Risk Accumulation

```powershell
copy C:\Windows\System32\curl.exe C:\Temp\suspicious.exe
C:\Temp\suspicious.exe https://example.com
# Expect: accumulated HIGH RISK score in logs
```

---

## Troubleshooting

### "Access Denied" or privilege errors

Ensure you are running the console engine as Administrator:

```powershell
whoami /priv | Select-String "SeDebugPrivilege"
```

### "Failed to start ProcessMonitor" (error 87)

The NT Kernel Logger session may be held by another tool (PerfMon, xperf, WPR):

```powershell
logman stop "NT Kernel Logger" -ets
.\build\Release\CortexEDR.exe
```

### Qt6 GUI won't start — missing DLLs

Run `windeployqt` as shown in Part 2, Step 3.

### "Qt6 not found" during CMake configure

Verify your `CMAKE_PREFIX_PATH` points to the MSVC 64-bit Qt kit:

```powershell
cmake -B build -S . `
  -DCMAKE_TOOLCHAIN_FILE=C:\vcpkg\scripts\buildsystems\vcpkg.cmake `
  -DCMAKE_PREFIX_PATH="C:\Qt\6.7.2\msvc2022_64"
```

### "Cannot find yaml-cpp" during build

Re-run vcpkg integration:

```powershell
cd C:\vcpkg
.\vcpkg integrate install
.\vcpkg list
```

### High CPU usage

Reduce the number of watched file paths in `config/config.yaml`:

```yaml
file_monitoring:
  watch_paths:
    - C:\Windows\System32   # Keep only the most critical paths
```

### No events appearing in the GUI

The GUI's scan panels operate independently of the console engine. To see live backend events, also run `CortexEDR.exe` (as Administrator) and watch `logs\cortex.log`.

---

## Next Steps

- **Explore the code**: Start with `main.cpp` (console) or `main_gui.cpp` (GUI) and follow the architecture
- **Read the docs**: See `ARCHITECTURE.md` for detailed system design
- **Customize detection**: Edit `config/rules.yaml` to add custom IOC rules
- **Tune thresholds**: Adjust `config/config.yaml` for your environment
- **Review tests**: See `tests/` for usage examples of each component

## Getting Help

- `README.md` — Architecture overview and feature list
- `ARCHITECTURE.md` — Deep-dive technical design
- `tests/` — Usage examples for each subsystem
- GitHub Issues — Bug reports and questions

---

> **Security Warning**: CortexEDR is an educational prototype. Do NOT deploy in production
> without a thorough security review. It is designed for portfolio demonstration and learning.

---

**You're all set.** Run the console engine to monitor threats in real time, or launch the GUI for a full dashboard experience.
