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
)

# Engine library (for future phases)
add_library(cortex_engine STATIC
    engine/RiskScorer.cpp
    engine/RiskScorer.hpp
)

target_include_directories(cortex_engine PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(cortex_engine PUBLIC
    cortex_core
    nlohmann_json::nlohmann_json
    yaml-cpp
)

# Main executable
add_executable(CortexEDR
    main.cpp
)

target_link_libraries(CortexEDR PRIVATE
    cortex_core
    cortex_collectors
    cortex_engine
    yaml-cpp
    nlohmann_json::nlohmann_json
    ntdll
)

# Tests
enable_testing()
add_executable(cortex_tests
    tests/test_eventbus.cpp
    tests/test_threadpool.cpp
    tests/test_riskscorer.cpp
)

target_link_libraries(cortex_tests PRIVATE
    cortex_core
    cortex_engine
    GTest::gtest
    GTest::gtest_main
)

add_test(NAME cortex_tests COMMAND cortex_tests)

# Installation
install(TARGETS CortexEDR RUNTIME DESTINATION bin)
install(FILES config/config.yaml DESTINATION bin/config)
