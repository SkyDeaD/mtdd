#include "http_internal.hpp"

#include <event2/http.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <algorithm>
#include <cmath>
#include <cstring>
#include <string_view>

namespace mtdd::control::detail {
namespace {

uint64_t mix64(uint64_t value) {
  value ^= value >> 30;
  value *= 0xbf58476d1ce4e5b9ull;
  value ^= value >> 27;
  value *= 0x94d049bb133111ebull;
  value ^= value >> 31;
  return value;
}

}  // namespace

void TokenBucket::configure(double rate, double burst) {
  rate_ = rate > 0.0 ? rate : 0.0;
  burst_ = burst > 0.0 ? burst : 0.0;
  tokens_ = burst_;
  last_ = SteadyClock::time_point{};
  initialized_ = false;
}

void TokenBucket::refill(SteadyClock::time_point now) {
  if (!initialized_) {
    initialized_ = true;
    last_ = now;
    return;
  }
  const double elapsed =
      std::chrono::duration<double>(now - last_).count();
  if (elapsed > 0.0) {
    tokens_ = std::min(burst_, tokens_ + elapsed * rate_);
    last_ = now;
  }
}

bool TokenBucket::allow(SteadyClock::time_point now) {
  refill(now);
  if (tokens_ < 1.0) return false;
  tokens_ -= 1.0;
  return true;
}

SourceRateLimiter::SourceRateLimiter(size_t capacity, double rate, double burst)
    : entries_(std::max<size_t>(capacity, 1)),
      capacity_(std::max<size_t>(capacity, 1)),
      rate_(rate > 0.0 ? rate : 0.0),
      burst_(burst > 0.0 ? burst : 0.0) {}

bool SourceRateLimiter::allow(uint64_t key, SteadyClock::time_point now) {
  const size_t start = static_cast<size_t>(mix64(key) % capacity_);
  size_t free_slot = capacity_;
  for (size_t probe = 0; probe < capacity_; ++probe) {
    Entry& entry = entries_[(start + probe) % capacity_];
    if (!entry.used) {
      free_slot = (start + probe) % capacity_;
      break;
    }
    if (entry.key != key) continue;

    const double elapsed =
        std::chrono::duration<double>(now - entry.last).count();
    if (elapsed > 0.0) {
      entry.tokens = std::min(burst_, entry.tokens + elapsed * rate_);
      entry.last = now;
    }
    if (entry.tokens < 1.0) return false;
    entry.tokens -= 1.0;
    return true;
  }

  Entry* target = nullptr;
  if (free_slot != capacity_) {
    target = &entries_[free_slot];
  } else {
    // Bounded eviction: replace the least recently used entry.
    target = &entries_[0];
    for (auto& entry : entries_) {
      if (entry.last < target->last) target = &entry;
    }
  }
  target->key = key;
  target->tokens = burst_ - 1.0;  // first request consumes one token
  target->last = now;
  target->used = true;
  return burst_ >= 1.0;
}

uint64_t peer_key(evhttp_request* request) {
  if (request != nullptr) {
    evhttp_connection* connection = evhttp_request_get_connection(request);
    if (connection != nullptr) {
      const struct sockaddr* address = evhttp_connection_get_addr(connection);
      if (address != nullptr) {
        if (address->sa_family == AF_INET) {
          const auto* v4 = reinterpret_cast<const sockaddr_in*>(address);
          return mix64(static_cast<uint64_t>(ntohl(v4->sin_addr.s_addr)) |
                       0x100000000ull);
        }
        if (address->sa_family == AF_INET6) {
          const auto* v6 = reinterpret_cast<const sockaddr_in6*>(address);
          uint64_t hash = 1469598103934665603ull;
          for (unsigned char byte : v6->sin6_addr.s6_addr) {
            hash ^= byte;
            hash *= 1099511628211ull;
          }
          return mix64(hash | 0x200000000ull);
        }
      }
      char* host = nullptr;
      ev_uint16_t port = 0;
      evhttp_connection_get_peer(connection, &host, &port);
      if (host != nullptr) {
        // The peer string is bounded by libevent's address formatting.
        std::string_view value(host);
        uint64_t hash = 1469598103934665603ull;
        for (char c : value) {
          hash ^= static_cast<unsigned char>(c);
          hash *= 1099511628211ull;
        }
        return mix64(hash | 0x300000000ull);
      }
    }
  }
  return mix64(0x400000000ull);
}

}  // namespace mtdd::control::detail
