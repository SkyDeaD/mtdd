// Bounded policy for remote-close feedback on a shared Middle-End connection.
//
// When ME delivers RPC_PROXY_ANS / RPC_SIMPLE_ACK for a logical connection this
// proxy no longer owns, the mapping must be released remotely (RPC_CLOSE_CONN).
// Under a
// flood of late/orphan responses that feedback must not become amplification:
//
//   * the queue is bounded (frames are dropped, never grown without limit),
//   * duplicate conn ids inside a short window are collapsed,
//   * a fixed per-window send budget caps the control-frame rate.
//
// The policy is pure bookkeeping: it never touches a session, socket or decoder,
// so callers can invoke it from inside a decoder callback and flush later.
#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <utility>
#include <vector>

namespace mtdd::detail {

// Same value type as protocol::MiddleEndSession::ConnId (8 opaque bytes), kept
// dependency-free so this policy stays unit-testable in isolation.
using RemoteConnId = std::array<std::uint8_t, 8>;

class RemoteCloseControl {
public:
    using Time = std::chrono::steady_clock::time_point;

    struct Limits {
        // Maximum queued RPC_CLOSE_CONN frames per ME connection.
        std::size_t pending{32};
        // Recent ids retained for duplicate suppression.
        std::size_t dedup_entries{64};
        // Duplicate suppression horizon for one conn id.
        std::chrono::milliseconds dedup_window{2000};
        // Maximum frames admitted per rate window.
        std::uint64_t per_window{32};
        std::chrono::milliseconds window{1000};
    };

    RemoteCloseControl() = default;
    explicit RemoteCloseControl(Limits limits) : limits_(limits) {}

    // Records an orphan response for `id`. Returns true when the caller should
    // queue one RPC_CLOSE_CONN; false when suppressed (duplicate, rate limited
    // or queue full). Suppressions are counted, never retried in a loop.
    bool request(const RemoteConnId& id, Time now) {
        if (limits_.pending == 0 || limits_.dedup_entries == 0 ||
            limits_.per_window == 0 || limits_.window.count() <= 0) {
            ++suppressed_;
            return false;
        }
        while (!recent_.empty() &&
               now - recent_.front().second > limits_.dedup_window) {
            recent_.pop_front();
        }
        for (const auto& entry : recent_) {
            if (entry.first == id) {
                ++suppressed_;
                return false;
            }
        }
        // A distinct flag (not Time{}) marks the window: steady_clock::time_point{}
        // is a legitimate input value in tests and in any epoch-relative clock.
        if (!window_active_ || now - window_start_ >= limits_.window) {
            window_active_ = true;
            window_start_ = now;
            window_count_ = 0;
        }
        if (window_count_ >= limits_.per_window) {
            ++suppressed_;
            return false;
        }
        if (pending_.size() >= limits_.pending) {
            ++suppressed_;
            return false;
        }
        pending_.push_back(id);
        recent_.emplace_back(id, now);
        while (recent_.size() > limits_.dedup_entries) recent_.pop_front();
        ++window_count_;
        return true;
    }

    // Moves the queued ids to `out` (replacing its contents) and clears the
    // queue. The caller owns delivery and must count what it actually sends.
    void consume(std::vector<RemoteConnId>& out) {
        out.clear();
        out.swap(pending_);
    }

    void clear() noexcept {
        pending_.clear();
        recent_.clear();
        window_start_ = Time{};
        window_count_ = 0;
        window_active_ = false;
    }

    std::size_t pending_size() const noexcept { return pending_.size(); }
    std::size_t recent_size() const noexcept { return recent_.size(); }
    std::uint64_t suppressed() const noexcept { return suppressed_; }
    const Limits& limits() const noexcept { return limits_; }

private:
    Limits limits_{};
    std::deque<std::pair<RemoteConnId, Time>> recent_;
    std::vector<RemoteConnId> pending_;
    Time window_start_{};
    std::uint64_t window_count_{0};
    bool window_active_{false};
    std::uint64_t suppressed_{0};
};

} // namespace mtdd::detail
