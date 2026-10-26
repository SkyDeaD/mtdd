#include "mtdd/runtime_support.hpp"

#include <future>
#include <gtest/gtest.h>

namespace {
using namespace std::chrono_literals;

TEST(RevisionBarrier, MonotonicAcknowledgmentsAndPendingTimeout) {
    mtdd::RevisionBarrier barrier;
    EXPECT_FALSE(barrier.wait(1, 0ms));
    barrier.acknowledge(2);
    EXPECT_TRUE(barrier.wait(2, 0ms));
    barrier.acknowledge(1);
    EXPECT_TRUE(barrier.wait(2, 0ms));
    EXPECT_FALSE(barrier.wait(3, 0ms));
}

TEST(RevisionBarrier, ShutdownReleasesWaitingMutationWithoutClaimingApplication) {
    mtdd::RevisionBarrier barrier;
    std::promise<void> started;
    auto waiter = std::async(std::launch::async, [&] {
        started.set_value();
        return barrier.wait(42, 5s);
    });
    started.get_future().wait();
    barrier.stop();
    ASSERT_EQ(waiter.wait_for(1s), std::future_status::ready);
    EXPECT_FALSE(waiter.get());
}

// With N reactors the revision is acknowledged only when the slowest reactor
// has applied it: the barrier exposes the minimum over per-worker observations.
TEST(RevisionBarrier, MultiWorkerRevisionNeedsEveryReactor) {
    mtdd::RevisionBarrier barrier;
    barrier.configure_workers(4);
    EXPECT_FALSE(barrier.wait(7, 0ms));
    barrier.acknowledge(0, 7);
    barrier.acknowledge(1, 8); // ahead of the others must not unblock revision 7
    barrier.acknowledge(2, 7);
    EXPECT_FALSE(barrier.wait(7, 0ms));
    barrier.acknowledge(3, 7);
    EXPECT_TRUE(barrier.wait(7, 0ms));
    // A worker that falls behind holds back the higher revision as well.
    barrier.acknowledge(0, 9);
    barrier.acknowledge(3, 9);
    EXPECT_FALSE(barrier.wait(9, 0ms));
    barrier.acknowledge(1, 9);
    barrier.acknowledge(2, 9);
    EXPECT_TRUE(barrier.wait(9, 0ms));
}

TEST(RevisionBarrier, ReconfigureForANewRuntimeClearsAPreviousStop) {
    mtdd::RevisionBarrier barrier;
    barrier.configure_workers(2);
    barrier.stop();
    EXPECT_FALSE(barrier.wait(1, 0ms));
    barrier.configure_workers(2);
    EXPECT_FALSE(barrier.wait(1, 0ms));
    barrier.acknowledge(0, 1);
    barrier.acknowledge(1, 1);
    EXPECT_TRUE(barrier.wait(1, 0ms));
}

TEST(Deadlines, ReschedulingDoesNotAccumulateStaleTimerEntries) {
    mtdd::Deadlines timers;
    const mtdd::Deadlines::Time epoch{};
    for (int i{}; i < 10000; ++i) timers.set(7, epoch + std::chrono::seconds(i));
    EXPECT_EQ(timers.size(), 1U);
    EXPECT_TRUE(timers.due(epoch + 10s).empty());
    EXPECT_EQ(timers.due(epoch + 10000s), std::vector<std::uint64_t>{7});
    EXPECT_FALSE(timers.next().has_value());
}

TEST(Deadlines, ErasedConnectionLifetimesCannotExpireReusedDescriptors) {
    mtdd::Deadlines timers;
    const mtdd::Deadlines::Time epoch{};
    timers.set(1, epoch);
    timers.erase(1);
    timers.set(2, epoch + 10s);
    EXPECT_TRUE(timers.due(epoch + 1s).empty());
    EXPECT_EQ(timers.due(epoch + 10s), std::vector<std::uint64_t>{2});
}

TEST(Deadlines, ProcessingHasFairnessLimit) {
    mtdd::Deadlines timers;
    const mtdd::Deadlines::Time epoch{};
    for (std::uint64_t i{}; i < 10; ++i) timers.set(i, epoch);
    EXPECT_EQ(timers.due(epoch, 3).size(), 3U);
    EXPECT_EQ(timers.size(), 7U);
}
} // namespace
