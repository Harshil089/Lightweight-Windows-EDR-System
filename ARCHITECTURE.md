# CortexEDR Architecture Documentation

## System Overview

CortexEDR is a userspace Windows EDR implementation built on a modular, event-driven architecture. The system follows a layered design pattern with clear separation of concerns between data collection, analysis, and response.

## Core Architectural Principles

1. **Event-Driven Architecture**: All system components communicate through a centralized event bus
2. **Thread Safety**: All shared state is protected by mutexes; lock-free patterns used where feasible
3. **RAII Resource Management**: All Windows handles wrapped in smart pointers with proper cleanup
4. **Fail-Safe Degradation**: Missing privileges gracefully disable features rather than crash
5. **Zero Raw Pointers**: Modern C++ using `std::unique_ptr` and `std::shared_ptr` throughout

## Layer Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     User Interface Layer                     │
│                    (Dashboard, CLI)                          │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                   Response & Containment                      │
│        (Process Kill, Network Block, Quarantine)             │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                    Analysis Engine Layer                      │
│     (Risk Scorer, Rule Engine, Behavior Correlator)          │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                       Event Bus (Core)                        │
│              (Publish/Subscribe Event Dispatcher)             │
└─────────────────────────────────────────────────────────────┘
                              ↑
        ┌─────────────────────┼─────────────────────┐
        ↓                     ↓                     ↓
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│   Process    │    │     File     │    │   Network    │
│   Monitor    │    │   Monitor    │    │   Monitor    │
│    (ETW)     │    │(ReadDirChg)  │    │ (IP Helper)  │
└──────────────┘    └──────────────┘    └──────────────┘
        ↓                     ↓                     ↓
┌─────────────────────────────────────────────────────────────┐
│                      Windows Kernel                          │
│     (ETW, File System, TCP/IP Stack, Registry)              │
└─────────────────────────────────────────────────────────────┘
```

## Component Details

### 1. Core Infrastructure

#### EventBus (core/EventBus.hpp)
**Purpose**: Centralized event distribution using publish/subscribe pattern

**Design Decisions**:
- Singleton pattern for global accessibility
- Thread-safe using `std::mutex` for subscriber management
- Copy handlers before invocation to prevent deadlocks
- Supports both synchronous and asynchronous publishing

**Event Flow**:
```
Collector → Publish(Event) → EventBus → Notify All Subscribers → Handlers Execute
```

**Thread Safety**:
- All subscriber modifications protected by mutex
- Handler invocation happens outside lock to prevent deadlock
- Async publish uses detached thread for fire-and-forget

#### ThreadPool (core/ThreadPool.hpp)
**Purpose**: Fixed-size worker pool for asynchronous task execution

**Implementation**:
- Uses `std::packaged_task` for future-based result retrieval
- Worker threads block on condition variable when idle
- Graceful shutdown waits for all queued tasks to complete
- Lock-free queue access via mutex + condition variable

**Usage Pattern**:
```cpp
ThreadPool pool(4);
auto future = pool.Enqueue([](int x) { return x * 2; }, 21);
int result = future.get(); // Returns 42
```

#### Logger (core/Logger.hpp)
**Purpose**: Structured logging with rotation and multiple sinks

**Features**:
- Dual sinks: console (colored) + rotating file
- Automatic log rotation at 10MB, keeps last 5 files
- Structured format: `[TIMESTAMP] [LEVEL] [MODULE] message {key=value}`
- Thread-safe via spdlog internals

### 2. Collectors (Event Ingestion)

#### ProcessMonitor (collectors/ProcessMonitor.hpp)
**Technology**: ETW (Event Tracing for Windows)

**Implementation Details**:
- Uses `StartTraceW` to create real-time ETW session
- Subscribes to `Microsoft-Windows-Kernel-Process` provider
- Captures process create/terminate via opcodes 1/2
- Runs `ProcessTrace` in dedicated background thread

**Privilege Requirements**:
- SeDebugPrivilege (attempted at startup via `AdjustTokenPrivileges`)
- Administrator elevation (required for kernel ETW providers)

**Data Captured**:
```cpp
struct ProcessEvent {
    uint32_t pid, parent_pid;
    std::wstring image_path;
    std::wstring command_line;
    uint32_t session_id;
    uint64_t timestamp;
};
```

**Fallback Strategy**:
- If ETW fails, can fall back to WMI `Win32_ProcessStartTrace` (future phase)

#### FileMonitor (collectors/FileMonitor.hpp)
**Technology**: `ReadDirectoryChangesW` with overlapped I/O

**Implementation**:
- Creates one monitor thread per watched directory
- Uses `FILE_FLAG_OVERLAPPED` for async notification
- Recursive monitoring via `bWatchSubtree = TRUE`
- 64KB buffer for change notifications

**Monitored Actions**:
- `FILE_ACTION_ADDED` → FILE_CREATE
- `FILE_ACTION_MODIFIED` → FILE_MODIFY
- `FILE_ACTION_REMOVED` → FILE_DELETE
- `FILE_ACTION_RENAMED_*` → FILE_MODIFY

**Performance Considerations**:
- Buffer overflow possible on high-volume directories (logged as warning)
- Change notifications are batched by OS
- No PID attribution (requires handle enumeration, future phase)

#### NetworkMonitor (collectors/NetworkMonitor.hpp)
**Technology**: IP Helper API (`GetExtendedTcpTable`, `GetExtendedUdpTable`)

**Polling Design**:
- Snapshot-based: polls every N seconds (configurable, default 2s)
- Diffs against previous snapshot to detect new connections
- Maintains `unordered_set` of known connection keys

**Connection Key Format**:
```
TCP:1234:192.168.1.5:443:185.220.101.5:443
```

**Limitations**:
- Cannot detect short-lived connections between polls
- No real-time notification (Windows limitation for userspace)
- High CPU on systems with thousands of connections

**Alternative Considered**:
- Windows Filtering Platform (WFP) - requires driver, rejected for userspace constraint

#### RegistryMonitor (collectors/RegistryMonitor.hpp)
**Technology**: `RegNotifyChangeKeyValue`

**Monitored Hives**:
```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKLM\SYSTEM\CurrentControlSet\Services
```

**Implementation**:
- One thread per registry key (8 threads total)
- Blocks on `WaitForSingleObject` until change notification
- Re-registers watch after each notification (single-shot API)
- Recursive monitoring via `bWatchSubtree = TRUE`

**Limitation**:
- Cannot determine specific value changed (Windows API limitation)
- Must snapshot before/after to identify delta (future enhancement)

### 3. Analysis Engine

#### RiskScorer (engine/RiskScorer.hpp)
**Algorithm**: Weighted additive scoring with threshold-based levels

**Scoring Model**:
```cpp
risk_score = Σ (signal_weight × signal_count)
risk_level = Threshold_Map[risk_score]
```

**Threshold Ranges** (configurable):
- 0-29: LOW
- 30-59: MEDIUM
- 60-79: HIGH
- 80-100: CRITICAL

**Signal Weights**:
| Signal | Weight | Rationale |
|--------|--------|-----------|
| process_from_temp | 15 | Malware staging directory |
| unsigned_executable | 20 | No code signing validation |
| registry_persistence | 20 | Persistence mechanism |
| external_connection | 10 | C2 communication |
| suspicious_port | 15 | Known malware ports |

**Future Enhancements** (Phase 2):
- Time-decay for old signals
- Per-process timeline ring buffer
- Pattern bonus scores from correlator

## Threading Model

```
Main Thread
  ├── EventBus (singleton, thread-safe)
  ├── Logger (thread-safe via spdlog)
  └── Monitor Threads:
       ├── ProcessMonitor ETW Thread (1)
       ├── FileMonitor Threads (N = watch paths)
       ├── NetworkMonitor Poll Thread (1)
       └── RegistryMonitor Threads (8 = monitored keys)

ThreadPool Workers (4-16 threads, configurable)
  └── Async event handlers (future phase)
```

**Lock Hierarchy** (to prevent deadlock):
1. EventBus::mutex_
2. RiskScorer::mutex_
3. Component-specific mutexes

## Windows API Surface

### Required DLLs
- `advapi32.dll` - Registry, privileges, ETW control
- `iphlpapi.dll` - IP Helper API for network monitoring
- `ws2_32.dll` - Winsock for IP address conversion
- `tdh.dll` - Trace Data Helper for ETW parsing
- `ntdll.dll` - NtSuspendProcess (future phase)
- `ole32.dll` - COM for WMI fallback (future phase)

### Privilege Escalation
```cpp
AdjustTokenPrivileges(
    token,
    FALSE,
    {SE_DEBUG_NAME, SE_SECURITY_NAME, SE_TCB_NAME},
    ...
);
```

### Handle Management (RAII)
All Windows handles wrapped in custom RAII types (future enhancement):
```cpp
template<typename T>
class WinHandle {
    T handle_;
    ~WinHandle() { if (handle_) CloseHandle(handle_); }
};
```

## Configuration Management

**Format**: YAML via yaml-cpp library

**Loading Strategy**:
- Parse at startup via `YAML::LoadFile`
- Validate schema and ranges
- Live reload on SIGHUP equivalent (named event, future phase)

**Validation Rules**:
- Thresholds must be strictly increasing
- Paths must be absolute and exist
- Port numbers in range 1-65535

## Error Handling Strategy

**No Exceptions in Hot Paths**:
- Collectors log errors but continue running
- Missing privileges degrade features gracefully
- Invalid events logged and dropped

**Result Type** (future phase):
```cpp
template<typename T>
class Result {
    std::variant<T, EDRError> value_;
};
```

## Performance Characteristics

**Expected Load** (typical workstation):
- Process events: 10-50/sec
- File events: 100-1000/sec (depends on user activity)
- Network events: 5-20/sec
- Registry events: 1-5/sec

**CPU Usage**:
- Idle: <1% (background polling)
- Active: 5-15% (during event bursts)

**Memory**:
- Base: ~50 MB
- Per-process tracking: ~2 KB
- Event queue: Unbounded (potential OOM, needs circuit breaker)

## Security Considerations

**Attack Surface**:
- Config file injection: YAML parser trusted input
- Log injection: All user input sanitized before logging
- Symbolic link attacks: File paths canonicalized

**Evasion Resistance**:
- ETW can be disabled by admin (known limitation)
- No kernel component = cannot detect rootkits
- Polling delay = misses short-lived connections

**Privilege Separation** (future):
- Split into low-privilege collector + high-privilege responder
- Use named pipe for IPC with ACL restrictions

## Testing Strategy

**Unit Tests** (Google Test):
- EventBus: Subscription, unsubscription, multi-subscriber
- ThreadPool: Task execution, shutdown, return values
- RiskScorer: Score accumulation, threshold mapping

**Integration Tests** (future):
- Simulate dropper sequence: write → spawn → connect
- Verify detection + containment fires correctly
- Test privilege degradation scenarios

**Stress Tests** (future):
- 1000 processes spawning simultaneously
- 10,000 file writes/sec
- Network connection flood

## Future Architecture Enhancements

### Phase 2: Behavioral Correlation
- Sliding time-window event buffer (60s)
- Pattern matching engine for composite behaviors
- Graph-based process tree tracking

### Phase 3: Machine Learning (Optional)
- Gradient-boosted tree for score prediction
- Train on labeled malware dataset
- Export features to ONNX for inference

### Phase 4: Distributed Deployment
- Central management server
- Agent-based architecture
- Encrypted C2 channel using TLS 1.3

## Build System Details

**CMake Structure**:
```
CortexEDR (executable)
  ├─ cortex_core (static lib)
  ├─ cortex_collectors (static lib)
  ├─ cortex_engine (static lib)
  └─ vcpkg dependencies
```

**Compiler Flags**:
- `/W4` - High warning level
- `/WX` - Warnings as errors
- `/std:c++20` - C++20 standard
- `_WIN32_WINNT=0x0A00` - Target Windows 10

## References

- [ETW Documentation](https://docs.microsoft.com/en-us/windows/win32/etw/about-event-tracing)
- [IP Helper API](https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/)
- [ReadDirectoryChangesW](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-readdirectorychangesw)
- [Registry Notifications](https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regnotifychangekeyvalue)
