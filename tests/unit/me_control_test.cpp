// Tests for the bounded orphan-answer remote-close policy.
//
// RED evidence for the runtime defect: before this policy existed, an
// RPC_PROXY_ANS/RPC_SIMPLE_ACK whose conn id no longer mapped to a client was
// counted and dropped with no RPC_CLOSE_CONN feedback to ME
// (src/runtime/me_relay.cpp deliver_payload/deliver_quick_ack). The policy is tested
// in isolation with a deterministic clock so the bounds are exact.

#include "../../src/runtime/me_control.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <vector>

namespace {

using namespace std::chrono_literals;
using mtdd::detail::RemoteCloseControl;
using mtdd::detail::RemoteConnId;

RemoteConnId id(std::uint8_t seed) {
    return RemoteConnId{seed, 0, 0, 0, 0, 0, 0, static_cast<std::uint8_t>(seed ^ 0x5a)};
}

std::vector<RemoteConnId> drain(RemoteCloseControl& control) {
    std::vector<RemoteConnId> out;
    control.consume(out);
    return out;
}

TEST(RemoteCloseControl, FirstOrphanIsQueuedOnceAndFlushedInOrder) {
    RemoteCloseControl control;
    const auto t0 = RemoteCloseControl::Time{};
    ASSERT_TRUE(control.request(id(1), t0));
    ASSERT_TRUE(control.request(id(2), t0));
    EXPECT_EQ(control.pending_size(), 2u);

    const auto pending = drain(control);
    ASSERT_EQ(pending.size(), 2u);
    EXPECT_EQ(pending[0], id(1));
    EXPECT_EQ(pending[1], id(2));
    EXPECT_EQ(control.pending_size(), 0u);
    // A second consume yields nothing: delivery is not replayed implicitly.
    EXPECT_TRUE(drain(control).empty());
}

TEST(RemoteCloseControl, DuplicateInsideWindowIsSuppressed) {
    RemoteCloseControl control;
    const auto t0 = RemoteCloseControl::Time{};
    ASSERT_TRUE(control.request(id(3), t0));
    EXPECT_FALSE(control.request(id(3), t0 + 500ms));
    EXPECT_FALSE(control.request(id(3), t0 + 1999ms));
    EXPECT_EQ(control.suppressed(), 2u);
    EXPECT_EQ(control.pending_size(), 1u);
    // After the dedup horizon the same id may be reported again.
    EXPECT_TRUE(control.request(id(3), t0 + 2s + 1ms));
    EXPECT_EQ(control.pending_size(), 2u);
}

TEST(RemoteCloseControl, DedupStateStaysBounded) {
    RemoteCloseControl::Limits limits;
    limits.dedup_entries = 8;
    limits.pending = 100;
    limits.per_window = 1000;
    RemoteCloseControl control(limits);
    const auto t0 = RemoteCloseControl::Time{};
    for (std::uint8_t i = 0; i < 40; ++i) {
        ASSERT_TRUE(control.request(id(i), t0 + std::chrono::milliseconds(i)));
    }
    EXPECT_LE(control.recent_size(), limits.dedup_entries);
    EXPECT_EQ(control.suppressed(), 0u);
}

TEST(RemoteCloseControl, RateWindowCapsFramesAndRecovers) {
    RemoteCloseControl::Limits limits;
    limits.per_window = 4;
    limits.window = 1000ms;
    RemoteCloseControl control(limits);
    const auto t0 = RemoteCloseControl::Time{};
    for (std::uint8_t i = 0; i < 4; ++i) {
        ASSERT_TRUE(control.request(id(i), t0)) << "i=" << static_cast<int>(i);
    }
    EXPECT_FALSE(control.request(id(4), t0 + 10ms));
    EXPECT_FALSE(control.request(id(5), t0 + 999ms));
    EXPECT_EQ(control.suppressed(), 2u);
    // The next window admits new ids again.
    EXPECT_TRUE(control.request(id(6), t0 + 1s));
}

TEST(RemoteCloseControl, PendingQueueIsBounded) {
    RemoteCloseControl::Limits limits;
    limits.pending = 4;
    limits.per_window = 100;
    RemoteCloseControl control(limits);
    const auto t0 = RemoteCloseControl::Time{};
    for (std::uint8_t i = 0; i < 4; ++i) {
        ASSERT_TRUE(control.request(id(i), t0));
    }
    EXPECT_FALSE(control.request(id(9), t0));
    EXPECT_EQ(control.pending_size(), 4u);
    EXPECT_EQ(control.suppressed(), 1u);
    // Flushing frees the queue without touching the dedup history.
    EXPECT_EQ(drain(control).size(), 4u);
    EXPECT_TRUE(control.request(id(10), t0));
}

TEST(RemoteCloseControl, ZeroLimitsDisableFeedbackInsteadOfGrowing) {
    RemoteCloseControl::Limits limits;
    limits.pending = 0;
    RemoteCloseControl control(limits);
    EXPECT_FALSE(control.request(id(1), RemoteCloseControl::Time{}));
    EXPECT_EQ(control.pending_size(), 0u);
    EXPECT_EQ(control.suppressed(), 1u);
}

TEST(RemoteCloseControl, ClearResetsQueueAndWindow) {
    RemoteCloseControl control;
    const auto t0 = RemoteCloseControl::Time{};
    ASSERT_TRUE(control.request(id(1), t0));
    control.clear();
    EXPECT_EQ(control.pending_size(), 0u);
    EXPECT_EQ(control.recent_size(), 0u);
    // After clear() the same id and a fresh window are accepted again.
    EXPECT_TRUE(control.request(id(1), t0 + 1ms));
}

}  // namespace
