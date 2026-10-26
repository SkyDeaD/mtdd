// Exact online unique-IP accounting. The maps are process-wide (shared by every
// reactor) and touched only on authenticated admission and client close, never
// per packet. Published values are atomics in Statistics/UserMetrics.
#include "internal.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

namespace mtdd {
namespace {

detail::IpKey make_ip_key(const protocol::Endpoint& peer) {
    const auto wire = peer.wire20();
    detail::IpKey key{};
    std::copy_n(wire.begin(), key.size(), key.begin());
    return key;
}

} // namespace

bool Runtime::Impl::count_client_unique_ip(Client& client) {
    if (client.ip_counted) return true;
    if (client.metrics == nullptr) return false;
    if (client.user_name.empty()) return false;

    const detail::IpKey key = make_ip_key(client.peer);
    {
        // Publish the gauges while the maps are still locked: a store after
        // unlock could be overwritten by another reactor's older value, leaving
        // a non-zero gauge after the last client closed.
        const std::lock_guard lock{shared_->ip_mutex};
        bool global_incremented = false;
        bool user_incremented = false;
        try {
            const auto [global, inserted] =
                shared_->unique_ip_counts.try_emplace(key, 0);
            (void)inserted;
            ++global->second;
            global_incremented = true;

            auto& per_user = shared_->user_unique_ip_counts[client.user_name];
            const auto [entry, user_inserted] = per_user.try_emplace(key, 0);
            (void)user_inserted;
            ++entry->second;
            user_incremented = true;
            stats_.set_active_unique_ips(
                static_cast<std::uint64_t>(shared_->unique_ip_counts.size()));
            client.metrics->set_active_unique_ips(
                static_cast<std::uint64_t>(per_user.size()));
        } catch (...) {
            // Roll back without allocating. Leave no empty user map behind.
            if (user_incremented) {
                const auto user =
                    shared_->user_unique_ip_counts.find(client.user_name);
                if (user != shared_->user_unique_ip_counts.end()) {
                    const auto entry = user->second.find(key);
                    if (entry != user->second.end()) {
                        if (entry->second > 1) {
                            --entry->second;
                        } else {
                            user->second.erase(entry);
                        }
                    }
                    if (user->second.empty()) {
                        shared_->user_unique_ip_counts.erase(user);
                    }
                }
            }
            if (global_incremented) {
                const auto global = shared_->unique_ip_counts.find(key);
                if (global != shared_->unique_ip_counts.end()) {
                    if (global->second > 1) {
                        --global->second;
                    } else {
                        shared_->unique_ip_counts.erase(global);
                    }
                }
            }
            return false;
        }
    }

    client.ip_key = key;
    client.ip_counted = true;
    return true;
}

void Runtime::Impl::decrement_client_unique_ip(Client& client) noexcept {
    if (!client.ip_counted) return;
    client.ip_counted = false;

    // Same ordering rule as count_client_unique_ip(): publish under the lock.
    const std::lock_guard lock{shared_->ip_mutex};
    const auto global = shared_->unique_ip_counts.find(client.ip_key);
    if (global != shared_->unique_ip_counts.end()) {
        if (global->second > 1) {
            --global->second;
        } else {
            shared_->unique_ip_counts.erase(global);
        }
    }
    stats_.set_active_unique_ips(
        static_cast<std::uint64_t>(shared_->unique_ip_counts.size()));

    const auto user =
        shared_->user_unique_ip_counts.find(client.user_name);
    if (user != shared_->user_unique_ip_counts.end()) {
        const auto entry = user->second.find(client.ip_key);
        if (entry != user->second.end()) {
            if (entry->second > 1) {
                --entry->second;
            } else {
                user->second.erase(entry);
            }
        }
        if (user->second.empty()) {
            shared_->user_unique_ip_counts.erase(user);
            if (client.metrics) client.metrics->set_active_unique_ips(0);
        } else if (client.metrics) {
            client.metrics->set_active_unique_ips(
                static_cast<std::uint64_t>(user->second.size()));
        }
    } else if (client.metrics) {
        client.metrics->set_active_unique_ips(0);
    }
}

void Runtime::Impl::refresh_ip_history() {
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    if (!stats_.rotate_ip_history(now)) return;
    // A calendar period changed. Exactly one reactor observes rotate() == true
    // and seeds every currently active exact IP once, so long-lived sessions are
    // represented in the new period without N-fold duplicate observations.
    std::vector<detail::IpKey> active;
    {
        const std::lock_guard lock{shared_->ip_mutex};
        active.reserve(shared_->unique_ip_counts.size());
        for (const auto& [key, count] : shared_->unique_ip_counts) {
            if (count != 0) active.push_back(key);
        }
    }
    for (const auto& key : active) stats_.observe_ip_history(key);
}

} // namespace mtdd
