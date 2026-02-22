#pragma once

#include <spdlog/spdlog.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <fmt/format.h>
#include <memory>
#include <string>

namespace cortex {

enum class LogLevel {
    TRACE,
    DEBUG,
    INFO,
    WARN,
    ERROR,
    CRITICAL
};

class Logger {
public:
    static void Initialize(const std::string& log_file_path = "logs/cortex.log",
                          size_t max_file_size = 10 * 1024 * 1024,
                          size_t max_files = 5);

    static void SetLevel(LogLevel level);
    static void Shutdown();

    static std::shared_ptr<spdlog::logger> Get();

    template<typename... Args>
    static void Trace(fmt::format_string<Args...> fmt, Args&&... args) {
        Get()->trace(fmt, std::forward<Args>(args)...);
    }

    template<typename... Args>
    static void Debug(fmt::format_string<Args...> fmt, Args&&... args) {
        Get()->debug(fmt, std::forward<Args>(args)...);
    }

    template<typename... Args>
    static void Info(fmt::format_string<Args...> fmt, Args&&... args) {
        Get()->info(fmt, std::forward<Args>(args)...);
    }

    template<typename... Args>
    static void Warn(fmt::format_string<Args...> fmt, Args&&... args) {
        Get()->warn(fmt, std::forward<Args>(args)...);
    }

    template<typename... Args>
    static void Error(fmt::format_string<Args...> fmt, Args&&... args) {
        Get()->error(fmt, std::forward<Args>(args)...);
    }

    template<typename... Args>
    static void Critical(fmt::format_string<Args...> fmt, Args&&... args) {
        Get()->critical(fmt, std::forward<Args>(args)...);
    }

private:
    static std::shared_ptr<spdlog::logger> logger_;
};

// Convenience macros
#define LOG_TRACE(...) cortex::Logger::Trace(__VA_ARGS__)
#define LOG_DEBUG(...) cortex::Logger::Debug(__VA_ARGS__)
#define LOG_INFO(...) cortex::Logger::Info(__VA_ARGS__)
#define LOG_WARN(...) cortex::Logger::Warn(__VA_ARGS__)
#define LOG_ERROR(...) cortex::Logger::Error(__VA_ARGS__)
#define LOG_CRITICAL(...) cortex::Logger::Critical(__VA_ARGS__)

} // namespace cortex
