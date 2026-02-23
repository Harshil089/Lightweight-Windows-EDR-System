# CortexEDR Quick Start Guide

This guide will get CortexEDR running on your Windows system in under 10 minutes.

## Prerequisites Checklist

- [ ] Windows 10 1903+ or Windows 11 (x64)
- [ ] Visual Studio 2022 with C++ Desktop Development workload
- [ ] Administrator access to your system
- [ ] At least 2 GB free disk space

## Step-by-Step Installation

### 1. Install vcpkg Package Manager

Open PowerShell as Administrator:

```powershell
# Clone vcpkg
cd C:\
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg

# Bootstrap vcpkg
.\bootstrap-vcpkg.bat

# Integrate with Visual Studio
.\vcpkg integrate install

# Set environment variable for easier access
setx VCPKG_ROOT "C:\vcpkg" /M
```

**Note**: You'll need to close and reopen PowerShell after setting the environment variable.

### 2. Install Dependencies

Still in PowerShell as Administrator:

```powershell
cd C:\vcpkg

# Install required packages (this may take 10-15 minutes)
.\vcpkg install yaml-cpp:x64-windows
.\vcpkg install nlohmann-json:x64-windows
.\vcpkg install spdlog:x64-windows
.\vcpkg install gtest:x64-windows
.\vcpkg install openssl:x64-windows
```

### 3. Clone CortexEDR

```powershell
cd C:\
git clone https://github.com/yourusername/CortexEDR.git
cd CortexEDR
```

### 4. Build CortexEDR

Option A - Using the build script:

```powershell
.\build.bat
```

Option B - Manual CMake build:

```powershell
# Configure
cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=C:\vcpkg\scripts\buildsystems\vcpkg.cmake

# Build
cmake --build build --config Release

# Run tests
cd build
ctest -C Release
cd ..
```

### 5. Run CortexEDR

**IMPORTANT**: CortexEDR must be run as Administrator for full functionality.
ETW process monitoring uses the Windows NT Kernel Logger session, which requires elevated privileges.

```powershell
# Open PowerShell as Administrator (right-click → "Run as Administrator")
cd C:\Lightweight-Windows-EDR-System

# Run CortexEDR
.\build\Release\CortexEDR.exe
```

You should see output like:

```
[2026-02-23 09:19:31] [info] [CortexEDR] ==========================================================
[2026-02-23 09:19:31] [info] [CortexEDR]   CortexEDR - Windows Endpoint Detection & Response
[2026-02-23 09:19:31] [info] [CortexEDR]   Phase 1: Core Infrastructure & Collectors
[2026-02-23 09:19:31] [info] [CortexEDR] ==========================================================
[2026-02-23 09:19:31] [info] [CortexEDR] Initializing CortexEDR...
[2026-02-23 09:19:31] [info] [CortexEDR] Event subscriptions configured
[2026-02-23 09:19:31] [info] [CortexEDR] Starting CortexEDR collectors...
[2026-02-23 09:19:31] [info] [CortexEDR] Starting ProcessMonitor with ETW
[2026-02-23 09:19:31] [info] [CortexEDR] Starting FileMonitor for 2 paths
[2026-02-23 09:19:31] [info] [CortexEDR] Starting NetworkMonitor with 2s poll interval
[2026-02-23 09:19:31] [info] [CortexEDR] Starting RegistryMonitor
[2026-02-23 09:19:31] [info] [CortexEDR] CortexEDR is now running. Press Ctrl+C to stop.
```

### 6. Verify It's Working

Open a **second** PowerShell window (does not need to be elevated) and run:

```powershell
# Trigger process monitoring — launch any process
notepad.exe

# Trigger file monitoring (watches C:\Windows\System32 and C:\Users by default)
New-Item -Path "$env:USERPROFILE\Documents\test_edr.txt" -ItemType File -Force

# Trigger network monitoring — connect to an external host
Test-NetConnection -ComputerName 8.8.8.8 -Port 443

# Trigger registry persistence monitoring
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v EDRTest /d "C:\test.exe" /f
# Clean up after testing:
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v EDRTest /f
```

Watch the CortexEDR console in the Administrator window — you should see event log lines appear in real time.

### 7. View Logs

CortexEDR writes structured logs to `logs\cortex.log` relative to the working directory:

```powershell
# Stream live log output (tail -f equivalent)
Get-Content C:\Lightweight-Windows-EDR-System\logs\cortex.log -Wait -Tail 30

# Show only warnings and above (error, critical)
Get-Content C:\Lightweight-Windows-EDR-System\logs\cortex.log |
    Where-Object { $_ -match '\[(warn|error|critical)\]' }

# Search for high-risk process detections
Select-String -Path C:\Lightweight-Windows-EDR-System\logs\cortex.log -Pattern "HIGH RISK"

# Show all events for a specific PID
Select-String -Path C:\Lightweight-Windows-EDR-System\logs\cortex.log -Pattern "PID=1234"
```

### 8. Inspect the Active ETW Kernel Session

While CortexEDR is running, you can verify the NT Kernel Logger session is active:

```powershell
# List all active ETW trace sessions — look for "NT Kernel Logger"
logman query -ets

# Show details of the NT Kernel Logger session specifically
logman query "NT Kernel Logger" -ets
```

## Configuration

Edit `config/config.yaml` to customize CortexEDR behavior:

```yaml
# Example: Change risk thresholds
risk_scoring:
  thresholds:
    low: 30
    medium: 60
    high: 80
    critical: 100

# Example: Add more file monitoring paths
file_monitoring:
  watch_paths:
    - C:\Users
    - C:\Windows\System32
    - C:\ProgramData
    - D:\ImportantData  # Add your custom path here
```

After editing, restart CortexEDR to apply changes.

## Stopping CortexEDR

Press `Ctrl+C` in the CortexEDR console window. You should see:

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

If the process is killed without a clean shutdown (e.g. Task Manager), the NT Kernel Logger
session may remain open. Release it manually before restarting:

```powershell
logman stop "NT Kernel Logger" -ets
```

## Troubleshooting

### "Access Denied" or "Privilege Error"

**Solution**: Make sure you're running as Administrator. Right-click PowerShell → "Run as Administrator"

### "Failed to start ProcessMonitor" (error 87)

**Cause**: ETW process monitoring uses the Windows NT Kernel Logger, which requires Administrator
privileges. Error 87 (`ERROR_INVALID_PARAMETER`) means the session could not be opened.

**Solution**:

```powershell
# 1. Confirm you are running as Administrator
whoami /priv | Select-String "SeDebugPrivilege"

# 2. Stop any existing NT Kernel Logger session that may be held by another tool
logman stop "NT Kernel Logger" -ets

# 3. Restart CortexEDR
.\build\Release\CortexEDR.exe
```

**Note**: Only one process can hold the NT Kernel Logger session at a time. Tools like
PerfMon, xperf, or WPR may also hold it. Stop those tools before starting CortexEDR.

### "vcpkg: command not found"

**Solution**: Make sure you set the VCPKG_ROOT environment variable and reopened PowerShell:

```powershell
setx VCPKG_ROOT "C:\vcpkg" /M
# Close and reopen PowerShell
```

### Build Fails with "Cannot find yaml-cpp"

**Solution**: Verify vcpkg integration:

```powershell
cd C:\vcpkg
.\vcpkg integrate install
.\vcpkg list  # Should show installed packages
```

### High CPU Usage

**Cause**: File monitoring on high-activity directories can generate many events.

**Solution**: Edit `config/config.yaml` and reduce monitored paths:

```yaml
 file_monitoring:
  watch_paths:
    - C:\Windows\System32  # Keep only critical paths
```

### No Events Appearing

**Checks**:

1. Verify CortexEDR has administrator privileges
2. Check `logs/cortex.log` for errors
3. Ensure you're generating actual system activity (create processes, files, etc.)
4. Verify risk thresholds aren't filtering everything out

## Testing CortexEDR Detection

### Test 1: Suspicious Process from Temp

```powershell
# Copy a legitimate executable to temp
copy C:\Windows\System32\notepad.exe C:\Users\Public\temp.exe

# Run it (should trigger "process_from_temp" risk signal)
C:\Users\Public\temp.exe
```

### Test 2: Registry Persistence

```powershell
# Modify Run key (should trigger "registry_persistence" signal)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v TestEntry /d "C:\test.exe" /f

# Clean up
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v TestEntry /f
```

### Test 3: External Network Connection

```powershell
# Connect to external IP (should trigger "external_connection" signal)
Test-NetConnection -ComputerName 8.8.8.8 -Port 80
```

### Test 4: Combine Multiple Signals

```powershell
# This should accumulate risk score across multiple signals
copy C:\Windows\System32\curl.exe C:\Temp\suspicious.exe
C:\Temp\suspicious.exe https://example.com
```

Check CortexEDR logs for "HIGH RISK DETECTED" messages.

## Next Steps

- **Explore the code**: Start with `main.cpp` and follow the architecture
- **Read the docs**: See `ARCHITECTURE.md` for detailed system design
- **Customize detection**: Edit `config/config.yaml` to tune for your environment
- **Add new rules**: Implement custom risk signals in `engine/RiskScorer.cpp`
- **Wait for Phase 2**: Next release will add rule engine and automated containment

## Getting Help

- Check `README.md` for architecture overview
- Read `ARCHITECTURE.md` for technical details
- Review unit tests in `tests/` for usage examples
- Open an issue on GitHub for bugs or questions

## Security Warning

⚠️ **CortexEDR is a prototype for educational purposes**

- Do NOT deploy in production without security review
- Do NOT rely on it for real threat protection
- It is designed for portfolio demonstration and learning

---

**Congratulations!** You now have CortexEDR running on your system. Happy threat hunting! 🛡️
