#include "core/Logger.hpp"
#include <filesystem>

namespace cortex {

std::shared_ptr<spdlog::logger> Logger::logger_ = nullptr;

void Logger::Initialize(const std::string& log_file_path, size_t max_file_size, size_t max_files) {
    try {
        std::filesystem::path log_path(log_file_path);
        std::filesystem::create_directories(log_path.parent_path());

        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        console_sink->set_level(spdlog::level::info);
        console_sink->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] [%n] %v");

        auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
            log_file_path, max_file_size, max_files);
        file_sink->set_level(spdlog::level::trace);
        file_sink->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] [%n] [%t] %v");

        std::vector<spdlog::sink_ptr> sinks{console_sink, file_sink};
        logger_ = std::make_shared<spdlog::logger>("CortexEDR", sinks.begin(), sinks.end());
        logger_->set_level(spdlog::level::trace);
        logger_->flush_on(spdlog::level::err);

        spdlog::register_logger(logger_);

        logger_->info("Logger initialized: {}", log_file_path);
    } catch (const std::exception& ex) {
        fprintf(stderr, "Failed to initialize logger: %s\n", ex.what());
        throw;
    }
}

void Logger::SetLevel(LogLevel level) {
    if (!logger_) return;

    switch (level) {
        case LogLevel::TRACE:    logger_->set_level(spdlog::level::trace); break;
        case LogLevel::DEBUG:    logger_->set_level(spdlog::level::debug); break;
        case LogLevel::INFO:     logger_->set_level(spdlog::level::info); break;
        case LogLevel::WARN:     logger_->set_level(spdlog::level::warn); break;
        case LogLevel::ERROR:    logger_->set_level(spdlog::level::err); break;
        case LogLevel::CRITICAL: logger_->set_level(spdlog::level::critical); break;
    }
}

void Logger::Shutdown() {
    if (logger_) {
        logger_->flush();
        spdlog::shutdown();
        logger_ = nullptr;
    }
}

std::shared_ptr<spdlog::logger> Logger::Get() {
    if (!logger_) {
        Initialize();
    }
    return logger_;
}

} // namespace cortex
