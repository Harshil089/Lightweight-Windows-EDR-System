cmake_minimum_required(VERSION 3.20)
project(CortexEDR VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# MSVC specific flags
if(MSVC)
    add_compile_options(/W4 /WX)
    add_compile_definitions(_WIN32_WINNT=0x0A00)  # Windows 10
endif()

# Find vcpkg packages
find_package(yaml-cpp CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(spdlog CONFIG REQUIRED)
find_package(GTest CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(unofficial-sqlite3 CONFIG REQUIRED)

# Core library
add_library(cortex_core STATIC
    core/EventBus.cpp
    core/EventBus.hpp
    core/ThreadPool.cpp
    core/ThreadPool.hpp
    core/Logger.cpp
    core/Logger.hpp
)

target_include_directories(cortex_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(cortex_core PUBLIC spdlog::spdlog)

# Collectors library
add_library(cortex_collectors STATIC
    collectors/ProcessMonitor.cpp
    collectors/ProcessMonitor.hpp
    collectors/FileMonitor.cpp
    collectors/FileMonitor.hpp
    collectors/NetworkMonitor.cpp
    collectors/NetworkMonitor.hpp
    collectors/RegistryMonitor.cpp
    collectors/RegistryMonitor.hpp
)

target_include_directories(cortex_collectors PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(cortex_collectors PUBLIC
    cortex_core
    iphlpapi
    ws2_32
    advapi32
    tdh
    ole32
    oleaut32
    uuid
)

# Engine library
add_library(cortex_engine STATIC
    engine/RiskScorer.cpp
    engine/RiskScorer.hpp
    engine/RuleEngine.cpp
    engine/RuleEngine.hpp
    engine/BehaviorCorrelator.cpp
    engine/BehaviorCorrelator.hpp
)

target_include_directories(cortex_engine PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(cortex_engine PUBLIC
    cortex_core
    nlohmann_json::nlohmann_json
    yaml-cpp::yaml-cpp
)

# Persistence library (Phase 4: SQLite)
add_library(cortex_persistence STATIC
    persistence/DatabaseManager.cpp
    persistence/DatabaseManager.hpp
)

target_include_directories(cortex_persistence PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(cortex_persistence PUBLIC
    cortex_core
    cortex_engine
    nlohmann_json::nlohmann_json
    unofficial::sqlite3::sqlite3
)

# Response library
add_library(cortex_response STATIC
    response/ContainmentManager.cpp
    response/ContainmentManager.hpp
    response/IncidentManager.cpp
    response/IncidentManager.hpp
)

target_include_directories(cortex_response PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(cortex_response PUBLIC
    cortex_core
    cortex_engine
    cortex_persistence
    nlohmann_json::nlohmann_json
    OpenSSL::Crypto
    ole32
    oleaut32
)

# Compliance library (Phase 5: Audit, MITRE, Compliance Reports, Forensics)
add_library(cortex_compliance STATIC
    compliance/AuditLogger.cpp
    compliance/AuditLogger.hpp
    compliance/MitreMapper.cpp
    compliance/MitreMapper.hpp
    compliance/ComplianceReporter.cpp
    compliance/ComplianceReporter.hpp
    compliance/ForensicsExporter.cpp
    compliance/ForensicsExporter.hpp
)

target_include_directories(cortex_compliance PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(cortex_compliance PUBLIC
    cortex_core
    cortex_engine
    cortex_persistence
    cortex_response
    nlohmann_json::nlohmann_json
    OpenSSL::Crypto
)

# Telemetry library
add_library(cortex_telemetry STATIC
    telemetry/TelemetryExporter.cpp
    telemetry/TelemetryExporter.hpp
)

target_include_directories(cortex_telemetry PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(cortex_telemetry PUBLIC
    cortex_core
    cortex_engine
    cortex_persistence
    nlohmann_json::nlohmann_json
)

# IPC library (Phase 4: Named Pipe + Shared Memory, pure Windows API)
add_library(cortex_ipc STATIC
    ipc/SharedMemoryServer.cpp
    ipc/SharedMemoryServer.hpp
    ipc/SharedMemoryClient.cpp
    ipc/SharedMemoryClient.hpp
    ipc/PipeClient.cpp
    ipc/PipeClient.hpp
)

target_include_directories(cortex_ipc PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(cortex_ipc PUBLIC cortex_core)

# Main executable (console-based EDR engine)
add_executable(CortexEDR
    main.cpp
)

target_link_libraries(CortexEDR PRIVATE
    cortex_core
    cortex_collectors
    cortex_engine
    cortex_persistence
    cortex_response
    cortex_compliance
    cortex_telemetry
    cortex_ipc
    yaml-cpp::yaml-cpp
    nlohmann_json::nlohmann_json
    ntdll
)

# ═══════════════════════════════════════════════════════════════
# Qt6 GUI Application (CortexEDR Dashboard)
# ═══════════════════════════════════════════════════════════════
option(BUILD_GUI "Build the Qt6 GUI application" ON)

if(BUILD_GUI)
    # Tell CMake where Qt6 is installed
    list(APPEND CMAKE_PREFIX_PATH "C:/Qt/6.10.2/msvc2022_64")

    find_package(Qt6 COMPONENTS Core Gui Widgets QUIET)
    if(Qt6_FOUND)
        message(STATUS "Qt6 found at: ${Qt6_DIR}")

        # Enable Qt auto-generation tools (required for Q_OBJECT, signals/slots, .qrc)
        set(CMAKE_AUTOMOC ON)
        set(CMAKE_AUTORCC ON)
        set(CMAKE_AUTOUIC ON)

        # GUI library (UI panels + bridge to EDR backend)
        add_library(cortex_gui STATIC
            ui/EDRBridge.cpp
            ui/EDRBridge.hpp
            ui/IPCWorker.cpp
            ui/IPCWorker.hpp
            ui/MainWindow.cpp
            ui/MainWindow.hpp
            ui/DashboardPanel.cpp
            ui/DashboardPanel.hpp
            ui/QuickScanPanel.cpp
            ui/QuickScanPanel.hpp
            ui/FullScanPanel.cpp
            ui/FullScanPanel.hpp
            ui/RealTimeProtectionPanel.cpp
            ui/RealTimeProtectionPanel.hpp
            ui/QuarantinePanel.cpp
            ui/QuarantinePanel.hpp
            ui/LogsPanel.cpp
            ui/LogsPanel.hpp
            ui/SettingsPanel.cpp
            ui/SettingsPanel.hpp
            ui/AboutPanel.cpp
            ui/AboutPanel.hpp
        )

        target_include_directories(cortex_gui PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
        target_link_libraries(cortex_gui PUBLIC
            cortex_core
            cortex_collectors
            cortex_engine
            cortex_response
            cortex_telemetry
            cortex_ipc
            Qt6::Core
            Qt6::Gui
            Qt6::Widgets
        )

        # GUI executable (WIN32 = no black console window behind the GUI)
        add_executable(CortexEDR_GUI WIN32
            main_gui.cpp
        )

        target_link_libraries(CortexEDR_GUI PRIVATE
            cortex_gui
            cortex_core
            cortex_collectors
            cortex_engine
            cortex_persistence
            cortex_response
            cortex_compliance
            cortex_telemetry
            cortex_ipc
            yaml-cpp::yaml-cpp
            nlohmann_json::nlohmann_json
            ntdll
            iphlpapi
            ws2_32
            advapi32
            Qt6::Core
            Qt6::Gui
            Qt6::Widgets
        )

        # Auto-deploy all required Qt6 DLLs next to the exe after each build
        add_custom_command(TARGET CortexEDR_GUI POST_BUILD
            COMMAND "C:/Qt/6.10.2/msvc2022_64/bin/windeployqt6.exe"
                    --no-translations
                    --no-system-d3d-compiler
                    $<TARGET_FILE:CortexEDR_GUI>
            COMMENT "Deploying Qt6 runtime DLLs..."
        )

        install(TARGETS CortexEDR_GUI RUNTIME DESTINATION bin)

        message(STATUS "Qt6 GUI target: CortexEDR_GUI enabled")
    else()
        message(WARNING "Qt6 not found. GUI target disabled. Verify Qt6 is installed at C:/Qt/6.10.2/msvc2022_64")
    endif()
endif()

# Tests
enable_testing()
add_executable(cortex_tests
    tests/test_eventbus.cpp
    tests/test_threadpool.cpp
    tests/test_riskscorer.cpp
    tests/test_incidentmanager.cpp
    tests/test_database.cpp
    tests/test_ipc_sharedmem.cpp
    tests/test_ipc_pipe.cpp
    tests/test_e2e_bridge.cpp
    tests/test_compliance.cpp
)

target_link_libraries(cortex_tests PRIVATE
    cortex_core
    cortex_engine
    cortex_persistence
    cortex_response
    cortex_compliance
    cortex_telemetry
    cortex_ipc
    GTest::gtest
    GTest::gtest_main
)

add_test(NAME cortex_tests COMMAND cortex_tests)

# Installation
install(TARGETS CortexEDR RUNTIME DESTINATION bin)
install(FILES config/config.yaml config/rules.yaml DESTINATION bin/config)
