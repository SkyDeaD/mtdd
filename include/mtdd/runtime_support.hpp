#pragma once

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <vector>

namespace mtdd {

// Acknowledgment is sent only after every reactor has invalidated obsolete
// sessions. With N reactors the acknowledged revision is the minimum over all
// registered reactors, so a mutation waits for the slowest one.
class RevisionBarrier {
public:
    // Called once at startup, before run(): resets every worker's observed
    // revision to zero and clears a stop latched by a previous runtime that
    // shared this barrier. Must not race with acknowledge()/wait().
    void configure_workers(std::size_t workers) {
        const std::lock_guard lock{mutex_};
        observed_.assign(std::max<std::size_t>(workers, 1), 0);
        stopped_ = false;
    }

    // Acknowledgment without a worker id means "every worker observed this
    // revision". Kept for single-worker embedders and tests.
    void acknowledge(std::uint64_t revision) {
        {
            const std::lock_guard lock{mutex_};
            for (auto& observed : observed_) {
                if (revision > observed) observed = revision;
            }
        }
        changed_.notify_all();
    }

    void acknowledge(std::size_t worker, std::uint64_t revision) {
        {
            const std::lock_guard lock{mutex_};
            if (observed_.empty()) observed_.assign(1, 0);
            auto& observed = observed_[worker % observed_.size()];
            if (revision > observed) observed = revision;
        }
        changed_.notify_all();
    }

    bool wait(std::uint64_t revision, std::chrono::milliseconds timeout) {
        std::unique_lock lock{mutex_};
        changed_.wait_for(lock, timeout,
                          [&] { return stopped_ || minimum_observed_locked() >= revision; });
        return !stopped_ && minimum_observed_locked() >= revision;
    }

    void stop() {
        {
            const std::lock_guard lock{mutex_};
            stopped_ = true;
        }
        changed_.notify_all();
    }

private:
    std::uint64_t minimum_observed_locked() const noexcept {
        if (observed_.empty()) return 0;
        std::uint64_t minimum = observed_.front();
        for (const auto value : observed_) minimum = std::min(minimum, value);
        return minimum;
    }

    std::mutex mutex_;
    std::condition_variable changed_;
    std::vector<std::uint64_t> observed_{0};
    bool stopped_{};
};

// Exactly one deadline per live token, including after repeated reschedules.
// Tokens identify connection lifetimes, not reusable numeric file descriptors.
class Deadlines {
public:
    using Clock = std::chrono::steady_clock;
    using Time = Clock::time_point;

    Deadlines() = default;
    Deadlines(const Deadlines&) = delete;
    Deadlines& operator=(const Deadlines&) = delete;
    Deadlines(Deadlines&&) = delete;
    Deadlines& operator=(Deadlines&&) = delete;

    void set(std::uint64_t token, Time at) {
        const auto old = by_token_.find(token);
        const auto next = ordered_.emplace(at, token);
        try {
            if (old == by_token_.end()) by_token_.emplace(token, next);
            else {
                ordered_.erase(old->second);
                old->second = next;
            }
        } catch (...) {
            ordered_.erase(next);
            throw;
        }
    }

    void erase(std::uint64_t token) noexcept {
        const auto found = by_token_.find(token);
        if (found == by_token_.end()) return;
        ordered_.erase(found->second);
        by_token_.erase(found);
    }

    std::optional<Time> next() const noexcept {
        if (ordered_.empty()) return std::nullopt;
        return ordered_.begin()->first;
    }

    std::vector<std::uint64_t> due(Time now, std::size_t limit = 256) {
        // Hot path after every epoll batch: the earliest timer is usually still
        // in the future, so return before touching the allocator.
        if (limit == 0 || ordered_.empty() || ordered_.begin()->first > now) return {};
        std::vector<std::uint64_t> result;
        result.reserve(std::min(limit, ordered_.size()));
        while (!ordered_.empty() && ordered_.begin()->first <= now && result.size() < limit) {
            const auto token = ordered_.begin()->second;
            result.push_back(token);
            erase(token);
        }
        return result;
    }

    std::size_t size() const noexcept { return by_token_.size(); }

private:
    std::multimap<Time, std::uint64_t> ordered_;
    std::unordered_map<std::uint64_t, decltype(ordered_)::iterator> by_token_;
};
} // namespace mtdd
