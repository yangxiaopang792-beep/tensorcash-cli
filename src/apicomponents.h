#ifndef BITCOIN_ENVCONFIG_H
#define BITCOIN_ENVCONFIG_H

#include <chrono>
#include <logging.h>
#include <mutex>
#include <string>
#include <queue>


struct EnvConfig {
    std::string pushHost = "localhost";
    uint16_t pushPort = 6000;
    std::string pullBindAddress = "*";
    uint16_t pullPort = 7000;
    
    // Validation constants
    static constexpr uint16_t MIN_PORT = 1024;
    static constexpr uint16_t MAX_PORT = 65535;

    std::string getPushAddress() const {
        return "tcp://" + pushHost + ":" + std::to_string(pushPort);
    }
    
    std::string getPullAddress() const {
        return "tcp://" + pullBindAddress + ":" + std::to_string(pullPort);
    }

    static EnvConfig fromEnvironment(const std::string& prefix, const uint16_t& defaultPushPort, const uint16_t& defaultPullPort) {
        EnvConfig cfg;
        
        if (auto host = std::getenv((prefix + "_HOST").c_str())) {
            cfg.pushHost = validateHost(host);
        }
        
        if (auto port = std::getenv((prefix + "_PUSH_PORT").c_str())) {
            cfg.pushPort = validatePort(port, prefix + "_PUSH_PORT");
        } else {
            cfg.pushPort = validatePort(defaultPushPort, prefix + "_DEFAULT_PUSH_PORT");
        }
        
        if (auto bind = std::getenv((prefix + "_PULL_BIND").c_str())) {
            cfg.pullBindAddress = validateBindAddress(bind);
        }
        
        if (auto port = std::getenv((prefix + "_PULL_PORT").c_str())) {
            cfg.pullPort = validatePort(port, prefix + "_PULL_PORT");
        } else {
            cfg.pullPort = validatePort(defaultPullPort, prefix + "_DEFAULT_PULL_PORT");
        }
        
        return cfg;
    }

private:
    static std::string validateHost(const std::string& host) {
        if (host.empty() || host.find_first_of(" \t\n\r") != std::string::npos) {
            throw std::runtime_error("Invalid hostname: contains whitespace or is empty");
        }
        return host;
    }

    static std::string validateBindAddress(const std::string& addr) {
        if (addr.empty()) {
            throw std::runtime_error("Invalid bind address: empty");
        }
        // In K8s context, we might want to restrict to specific interfaces
        if (addr != "*" && addr != "localhost" && addr != "0.0.0.0") {
            // Could add more validation here
            LogPrintf("Warning: Using custom bind address: %s\n", addr);
        }
        return addr;
    }

    static uint16_t validatePort(const int& port, const std::string& varName) {
        try {
            if (port < MIN_PORT || port > MAX_PORT) {
                throw std::runtime_error(varName + ": Port must be between " + 
                                        std::to_string(MIN_PORT) + " and " + 
                                        std::to_string(MAX_PORT));
            }
            return static_cast<uint16_t>(port);
        } catch (const std::exception& e) {
            throw std::runtime_error(varName + ": Invalid port number - " + e.what());
        }
    }

    static uint16_t validatePort(const std::string& portStr, const std::string& varName) {
        try {
            int port = std::stoi(portStr);
            return validatePort(port, varName);
        } catch (const std::exception& e) {
            throw std::runtime_error(varName + ": Invalid port number - " + e.what());
        }
    }
};

// Rate limiter class
class RateLimiter {
private:
    mutable std::mutex mutex_;
    std::queue<std::chrono::steady_clock::time_point> timestamps_;
    const size_t window_size_;
    const std::chrono::seconds window_duration_;

public:
    RateLimiter(size_t max_per_minute = 60) 
        : window_size_(max_per_minute), window_duration_(60) {}

    bool allowRequest() {
        std::lock_guard<std::mutex> lock(mutex_);
        auto now = std::chrono::steady_clock::now();
        
        // Remove old timestamps
        while (!timestamps_.empty() && 
               now - timestamps_.front() > window_duration_) {
            timestamps_.pop();
        }
        
        if (timestamps_.size() >= window_size_) {
            return false;
        }
        
        timestamps_.push(now);
        return true;
    }
};

#endif // BITCOIN_ENVCONFIG_H