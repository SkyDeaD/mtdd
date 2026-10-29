#include "mtdd/runtime_support.hpp"

#include <atomic>
#include <cstdlib>
#include <future>
#include <new>
#include <gtest/gtest.h>

namespace {
std::atomic<bool> track_allocations{false};
std::atomic<std::size_t> allocations{0};
}

// Test-executable-only interposition: count C++ payload allocations made by the
// header under test. Never linked into mtdd or another test executable.
void* operator new(std::size_t size) {
    if (void* value = std::malloc(size == 0 ? 1 : size)) {
        if (track_allocations.load(std::memory_order_relaxed)) {
            allocations.fetch_add(1, std::memory_order_relaxed);
        }
        return value;
    }
    throw std::bad_alloc();
}
void operator delete(void* value) noexcept { std::free(value); }
void operator delete(void* value, std::size_t) noexcept { std::free(value); }
void* operator new[](std::size_t size) { return ::operator new(size); }
void operator delete[](void* value) noexcept { ::operator delete(value); }
void operator delete[](void* value, std::size_t) noexcept { ::operator delete(value); }
void* operator new(std::size_t size, const std::nothrow_t&) noexcept {
    try { return ::operator new(size); } catch (...) { return nullptr; }
}
void* operator new[](std::size_t size, const std::nothrow_t&) noexcept {
    try { return ::operator new[](size); } catch (...) { return nullptr; }
}
void operator delete(void* value, const std::nothrow_t&) noexcept { ::operator delete(value); }
void operator delete[](void* value, const std::nothrow_t&) noexcept { ::operator delete[](value); }

namespace {
using namespace std::chrono_literals;

std::size_t count_due_allocations(mtdd::Deadlines& timers, mtdd::Deadlines::Time now,
                                  std::vector<std::uint64_t>& batch,
                                  std::size_t limit = 256) {
    allocations.store(0);
    track_allocations.store(true);
    try {
        batch = timers.due(now, limit);
    } catch (...) {
        track_allocations.store(false);
        throw;
    }
    track_allocations.store(false);
    return allocations.load();
}

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

// CPU-01: the post-epoll deadline sweep must not touch the allocator when the
// earliest timer is still in the future, even though the heap is non-empty.
TEST(Deadlines, FutureOnlyCheckOnNonEmptyHeapAllocatesNothing) {
    mtdd::Deadlines timers;
    const mtdd::Deadlines::Time epoch{};
    for (int i{}; i < 1024; ++i) {
        timers.set(static_cast<std::uint64_t>(i), epoch + 1h + std::chrono::seconds(i));
    }
    std::vector<std::uint64_t> batch;
    EXPECT_EQ(count_due_allocations(timers, epoch + 30min, batch), std::size_t{0});
    EXPECT_TRUE(batch.empty());
    EXPECT_EQ(timers.size(), 1024U);

    // Adjacent no-work paths stay allocation-free as well.
    mtdd::Deadlines empty;
    EXPECT_EQ(count_due_allocations(empty, epoch, batch), std::size_t{0});
    EXPECT_TRUE(batch.empty());
    EXPECT_EQ(count_due_allocations(timers, epoch + 30min, batch, 0), std::size_t{0});
    EXPECT_TRUE(batch.empty());
    EXPECT_EQ(timers.size(), 1024U);
}

// Positive control for the executable-local interposition: if this ever stops
// observing a real payload allocation, the CPU-01 regression above is vacuous.
TEST(Deadlines, AllocationProbeCountsOneExplicitAllocation) {
    allocations.store(0);
    track_allocations.store(true);
    std::size_t observed = 0;
    try {
        const std::vector<int> probe(64, 1);
        track_allocations.store(false);
        observed = allocations.load();
        EXPECT_EQ(probe.size(), 64U);
    } catch (...) {
        track_allocations.store(false);
        throw;
    }
    EXPECT_EQ(observed, std::size_t{1});
}

TEST(Deadlines, DuePreservesTimeThenInsertionOrder) {
    mtdd::Deadlines timers;
    const mtdd::Deadlines::Time epoch{};
    timers.set(5, epoch + 3s);
    timers.set(3, epoch + 1s);
    timers.set(4, epoch + 1s);
    timers.set(6, epoch + 2s);
    const std::vector<std::uint64_t> expected{3, 4, 6};
    EXPECT_EQ(timers.due(epoch + 2s), expected);
    EXPECT_EQ(timers.size(), 1U);
    ASSERT_TRUE(timers.next().has_value());
    EXPECT_EQ(*timers.next(), epoch + 3s);
}

TEST(Deadlines, RearmAndEraseKeepOneLiveDeadlinePerToken) {
    mtdd::Deadlines timers;
    const mtdd::Deadlines::Time epoch{};
    timers.set(7, epoch + 10s);
    timers.set(7, epoch + 5s);
    EXPECT_EQ(timers.size(), 1U);
    ASSERT_TRUE(timers.next().has_value());
    EXPECT_EQ(*timers.next(), epoch + 5s);
    EXPECT_TRUE(timers.due(epoch + 4s).empty());
    timers.set(7, epoch + 1s);
    EXPECT_EQ(timers.size(), 1U);
    ASSERT_TRUE(timers.next().has_value());
    EXPECT_EQ(*timers.next(), epoch + 1s);
    const std::vector<std::uint64_t> expected{7};
    EXPECT_EQ(timers.due(epoch + 1s), expected);
    EXPECT_EQ(timers.size(), 0U);
    EXPECT_FALSE(timers.next().has_value());
    timers.erase(7);
    timers.erase(999);
    EXPECT_EQ(timers.size(), 0U);
}

// A handler receives a stable snapshot: the batch is removed from the heap
// before iteration, and re-arming the same tokens schedules fresh deadlines.
TEST(Deadlines, DueBatchCanBeRearmedByTheHandler) {
    mtdd::Deadlines timers;
    const mtdd::Deadlines::Time epoch{};
    timers.set(1, epoch);
    timers.set(2, epoch);
    const std::vector<std::uint64_t> first_expected{1, 2};
    EXPECT_EQ(timers.due(epoch), first_expected);
    EXPECT_EQ(timers.size(), 0U);
    timers.set(1, epoch + 1s);
    timers.set(2, epoch + 1s);
    const std::vector<std::uint64_t> second_expected{1, 2};
    EXPECT_EQ(timers.due(epoch + 1s), second_expected);
}

TEST(Deadlines, DefaultFairnessCapLeavesRemainingWork) {
    mtdd::Deadlines timers;
    const mtdd::Deadlines::Time epoch{};
    for (int i{}; i < 300; ++i) timers.set(static_cast<std::uint64_t>(i), epoch);
    EXPECT_TRUE(timers.due(epoch, 0).empty());
    EXPECT_EQ(timers.size(), 300U);
    const auto first = timers.due(epoch);
    EXPECT_EQ(first.size(), 256U);
    EXPECT_EQ(timers.size(), 44U);
    ASSERT_FALSE(first.empty());
    EXPECT_EQ(first.front(), 0U);
    EXPECT_EQ(first.back(), 255U);
}
} // namespace
