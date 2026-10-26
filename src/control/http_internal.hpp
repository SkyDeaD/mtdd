// Internal helpers for the control HTTP server (not part of the public API).
#pragma once

#include <mtdd/control.hpp>

#include <chrono>
#include <cstddef>
#include <initializer_list>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

struct evhttp_request;

namespace mtdd::control::detail {

using SteadyClock = std::chrono::steady_clock;
using json = nlohmann::json;

struct HttpError {
  int status{500};
  std::string type{"io_error"};
  std::string message{"internal error"};
};

struct RouteInfo {
  ApiRoute route{ApiRoute::unknown};
  std::string name;
};

struct BodyRead {
  json value;
  std::optional<HttpError> error;
};

class TokenBucket {
 public:
  TokenBucket() = default;
  TokenBucket(double rate, double burst) { configure(rate, burst); }

  void configure(double rate, double burst);
  bool allow(SteadyClock::time_point now);

 private:
  void refill(SteadyClock::time_point now);

  double rate_{0.0};
  double burst_{0.0};
  double tokens_{0.0};
  SteadyClock::time_point last_{};
  bool initialized_{false};
};

// Fixed-capacity, least-recently-used-evicted per-source limiter. The table is
// bounded, so a flood of distinct source addresses cannot grow memory.
class SourceRateLimiter {
 public:
  SourceRateLimiter(size_t capacity, double rate, double burst);

  bool allow(uint64_t key, SteadyClock::time_point now);

 private:
  struct Entry {
    uint64_t key{0};
    double tokens{0.0};
    SteadyClock::time_point last{};
    bool used{false};
  };

  std::vector<Entry> entries_;
  size_t capacity_;
  double rate_;
  double burst_;
};

// Stable hash of the source address only (never the port), used as the bounded
// limiter key. Falls back to the textual peer if no sockaddr is available.
uint64_t peer_key(evhttp_request* request);

std::string trim_copy(std::string_view value);
bool ascii_iequals(std::string_view a, std::string_view b);
bool constant_time_equal(std::string_view a, std::string_view b) noexcept;

ApiMethod parse_method(evhttp_request* request);
RouteInfo classify_route(evhttp_request* request);
bool method_allowed(ApiRoute route, ApiMethod method);

std::optional<HttpError> check_allowed_fields(
    const json& object, std::initializer_list<std::string_view> allowed);
std::optional<HttpError> parse_max_connections(const json& value,
                                               std::optional<uint32_t>& out);
std::optional<HttpError> parse_if_match(evhttp_request* request,
                                        std::optional<uint64_t>& out);
HttpError map_store_error(const Error& error);

json user_json(const UserRecord& user, const StatisticsSnapshot& stats);

// Reads and strictly validates an optional JSON object body with a bounded size.
BodyRead read_body(evhttp_request* request, size_t max_body_bytes,
                   bool allow_empty);

void send_json(evhttp_request* request, int status, const json& body,
               std::optional<uint64_t> revision = std::nullopt);
void send_text(evhttp_request* request, int status, const std::string& body,
               std::string_view content_type,
               std::optional<uint64_t> revision = std::nullopt);
void send_error(evhttp_request* request, int status, std::string type,
                std::string message,
                std::optional<uint64_t> revision = std::nullopt);
void send_store_error(evhttp_request* request, const Error& error,
                      std::optional<uint64_t> revision = std::nullopt);

}  // namespace mtdd::control::detail
