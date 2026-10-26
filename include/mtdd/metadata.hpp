#pragma once

#include "mtdd/config.hpp"

#include <atomic>
#include <cstdint>
#include <memory>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace mtdd {
struct MeEndpoint {
    std::int16_t dc{};
    std::string host;
    std::uint16_t port{};
    bool operator==(const MeEndpoint&) const = default;
};

struct MeMetadata {
    std::vector<MeEndpoint> endpoints;
    std::vector<std::uint8_t> secret;
    std::uint64_t generation{};
};

std::vector<MeEndpoint> parse_me_config(std::string_view text);
MeMetadata load_me_metadata(const Config& config, std::stop_token stop = {});

// Refresh never runs on the reactor. Failed refresh preserves the last valid snapshot.
class MetadataProvider {
public:
    explicit MetadataProvider(Config config);
    ~MetadataProvider();
    MetadataProvider(const MetadataProvider&) = delete;
    MetadataProvider& operator=(const MetadataProvider&) = delete;
    std::shared_ptr<const MeMetadata> snapshot() const noexcept;
    std::uint64_t failures() const noexcept;

private:
    void run(std::stop_token stop);
    Config config_;
    std::atomic<std::shared_ptr<const MeMetadata>> current_;
    std::atomic<std::uint64_t> failures_{};
    std::jthread thread_;
};
} // namespace mtdd
