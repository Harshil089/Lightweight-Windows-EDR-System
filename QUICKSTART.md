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

```powershell
# Open new PowerShell as Administrator
cd C:\CortexEDR

# Run CortexEDR
.\build\Release\CortexEDR.exe
```

You should see output like:

```
[2024-02-21 10:30:45] [INFO] [CortexEDR] ==========================================================
[2024-02-21 10:30:45] [INFO] [CortexEDR]   CortexEDR - Windows Endpoint Detection & Response
[2024-02-21 10:30:45] [INFO] [CortexEDR]   Phase 1: Core Infrastructure & Collectors
[2024-02-21 10:30:45] [INFO] [CortexEDR] ==========================================================
[2024-02-21 10:30:45] [INFO] [CortexEDR] Initializing CortexEDR...
[2024-02-21 10:30:45] [INFO] [CortexEDR] Starting ProcessMonitor with ETW
[2024-02-21 10:30:45] [INFO] [CortexEDR] Starting FileMonitor for 2 paths
[2024-02-21 10:30:45] [INFO] [CortexEDR] Starting NetworkMonitor with 2s poll interval
[2024-02-21 10:30:45] [INFO] [CortexEDR] Starting RegistryMonitor
[2024-02-21 10:30:45] [INFO] [CortexEDR] CortexEDR is now running. Press Ctrl+C to stop.
```

### 6. Verify It's Working

Open a new PowerShell window and run some test commands:

```powershell
# This will trigger process monitoring
notepad.exe

# This will trigger file monitoring (if C:\Windows\Temp is monitored)
echo "test" > C:\Windows\Temp\test.txt

# This will trigger network monitoring
curl https://example.com
```

Check the CortexEDR console - you should see log messages about detected events.

### 7. View Logs

CortexEDR logs are stored in `logs/cortex.log`:

```powershell
# View real-time logs
Get-Content logs\cortex.log -Wait -Tail 20

# Search for high-risk detections
Select-String -Path logs\cortex.log -Pattern "HIGH RISK"
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
[INFO] Received shutdown signal
[INFO] Stopping CortexEDR...
[INFO] Stopping RegistryMonitor
[INFO] Stopping NetworkMonitor
[INFO] Stopping FileMonitor
[INFO] Stopping ProcessMonitor
[INFO] All collectors stopped
[INFO] CortexEDR shutdown complete
```

## Troubleshooting

### "Access Denied" or "Privilege Error"

**Solution**: Make sure you're running as Administrator. Right-click PowerShell → "Run as Administrator"

### "Failed to start ProcessMonitor"

**Cause**: ETW requires administrator privileges and may conflict with existing trace sessions.

**Solution**:

```powershell
# Stop any existing CortexEDR trace sessions
logman stop CortexEDR_ProcessTrace -ets

# Then restart CortexEDR
```

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
