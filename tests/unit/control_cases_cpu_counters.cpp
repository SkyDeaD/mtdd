// CPU-02: per-worker ME request/answer counters.
//
// These cases pin the behavioural contract before the implementation:
// worker overloads must accumulate in a stable slot independent of the active
// worker count, legacy calls must keep landing in slot 0, the snapshot must
// sum every slot up to the monotonic high-water bound (so reconfiguration
// never loses history), and concurrent updates must add up exactly even when
// worker ids collide modulo the slot count or race to extend the bound.
#include "../support/control_fixture.hpp"

#include <array>
#include <barrier>
#include <cstdint>
#include <limits>
#include <string>
#include <thread>
#include <vector>

namespace {

constexpr std::array<const char*, 13> kExpectedDcLabels = {
    "-203", "-5", "-4", "-3", "-2", "-1", "1",
    "2",    "3",  "4",  "5",  "203", "other"};

void expect_one_each(const mtdd::control::MeDcSnapshot& dc) {
  EXPECT_EQ(dc.requests_success, 1u);
  EXPECT_EQ(dc.requests_failure, 1u);
  EXPECT_EQ(dc.requests_timeout, 1u);
  EXPECT_EQ(dc.proxy_ans_received_total, 1u);
  EXPECT_EQ(dc.proxy_ans_delivered_total, 1u);
  EXPECT_EQ(dc.proxy_ans_dropped_unknown_total, 1u);
  EXPECT_EQ(dc.proxy_ans_dropped_other_total, 1u);
}

TEST(MeCounterWorkersTest, OverloadsCoverEveryOutcomeAndBoundedSign) {
  Statistics stats;
  stats.configure_workers(4);

  // -203, -5..-1, 1..5, 203 plus one unbounded id that must map to "other".
  const std::array<int, 13> dcs = {-203, -5, -4, -3, -2, -1, 1, 2,
                                   3,    4,  5,  203, 999};
  for (std::size_t i = 0; i < dcs.size(); ++i) {
    const std::size_t worker = i;  // exercise different slots
    stats.me_request(worker, dcs[i], MeResult::success);
    stats.me_request(worker, dcs[i], MeResult::failure);
    stats.me_request(worker, dcs[i], MeResult::timeout);
    stats.me_answer(worker, dcs[i], MeAnswerResult::received);
    stats.me_answer(worker, dcs[i], MeAnswerResult::delivered);
    stats.me_answer(worker, dcs[i], MeAnswerResult::dropped_unknown);
    stats.me_answer(worker, dcs[i], MeAnswerResult::dropped_other);
  }

  const auto snapshot = stats.snapshot();
  ASSERT_EQ(snapshot.me_dcs.size(), kExpectedDcLabels.size());
  for (const char* label : kExpectedDcLabels) {
    ASSERT_EQ(snapshot.me_dcs.count(label), 1u) << label;
    SCOPED_TRACE(label);
    expect_one_each(snapshot.me_dcs.at(label));
  }

  // Prometheus output keeps one series per signed DC, not per worker.
  const std::string text = stats.prometheus_text();
  EXPECT_NE(text.find("mtdd_me_requests_total{dc=\"2\",result=\"success\"} 1\n"),
            std::string::npos);
  EXPECT_NE(text.find("mtdd_me_proxy_ans_total{dc=\"other\",result=\"received\"} 1\n"),
            std::string::npos);
}

TEST(MeCounterWorkersTest, LegacyCallsKeepLandingInWorkerZero) {
  Statistics stats;
  stats.configure_workers(4);

  stats.me_request(2, MeResult::success);
  stats.me_request(1, 2, MeResult::success);
  stats.me_request(2, MeResult::success);

  stats.me_answer(2, MeAnswerResult::received);
  stats.me_answer(3, 2, MeAnswerResult::received);
  stats.me_answer(2, MeAnswerResult::dropped_other);

  const auto snapshot = stats.snapshot();
  const auto& dc = snapshot.me_dcs.at("2");
  EXPECT_EQ(dc.requests_success, 3u);
  EXPECT_EQ(dc.proxy_ans_received_total, 2u);
  EXPECT_EQ(dc.proxy_ans_dropped_other_total, 1u);
  EXPECT_EQ(dc.proxy_ans_delivered_total, 0u);
}

TEST(MeCounterWorkersTest, ReconfigurationKeepsEveryHistoricalSlot) {
  Statistics stats;
  stats.configure_workers(8);
  for (std::size_t worker = 0; worker < 8; ++worker) {
    stats.me_request(worker, 2, MeResult::success);
    stats.me_answer(worker, 2, MeAnswerResult::received);
  }
  EXPECT_EQ(stats.snapshot().me_dcs.at("2").requests_success, 8u);

  // Shrinking must not hide the slots written while 8 workers were active.
  stats.configure_workers(2);
  stats.me_request(2, MeResult::failure);  // legacy -> slot 0
  stats.me_request(7, 2, MeResult::failure);  // inactive worker 7
  auto snapshot = stats.snapshot();
  EXPECT_EQ(snapshot.me_dcs.at("2").requests_success, 8u);
  EXPECT_EQ(snapshot.me_dcs.at("2").requests_failure, 2u);
  EXPECT_EQ(snapshot.me_dcs.at("2").proxy_ans_received_total, 8u);

  stats.configure_workers(1);
  snapshot = stats.snapshot();
  EXPECT_EQ(snapshot.me_dcs.at("2").requests_success, 8u);
  EXPECT_EQ(snapshot.me_dcs.at("2").requests_failure, 2u);

  // 256 maps to the same slot as worker 0 (worker % 256), and both increments
  // must still be counted exactly once by the fixed 256-slot sweep.
  stats.configure_workers(256);
  stats.me_request(255, 2, MeResult::timeout);
  stats.me_request(256, 2, MeResult::timeout);
  EXPECT_EQ(stats.snapshot().me_dcs.at("2").requests_timeout, 2u);
}

TEST(MeCounterWorkersTest, HighWaterBoundCoversTouchedSlotsBeforeAnyConfigure) {
  Statistics stats;  // bound starts at slot 0 for the legacy API
  stats.me_request(2, MeResult::success);       // legacy -> slot 0
  stats.me_request(99, 2, MeResult::success);   // lazily raises bound to 100
  stats.me_answer(std::numeric_limits<std::size_t>::max(), 2,
                  MeAnswerResult::received);    // slot 255

  const auto snapshot = stats.snapshot();
  EXPECT_EQ(snapshot.me_dcs.at("2").requests_success, 2u);
  EXPECT_EQ(snapshot.me_dcs.at("2").proxy_ans_received_total, 1u);
}

TEST(MeCounterWorkersTest, ShrinkingWorkersNeverLowersHighWaterBound) {
  Statistics stats;
  stats.configure_workers(8);
  stats.me_request(255, 2, MeResult::timeout);
  EXPECT_EQ(stats.snapshot().me_dcs.at("2").requests_timeout, 1u);

  // A retired high slot is still inside the monotonic bound; writes from ids
  // above the active count keep accumulating there.
  stats.configure_workers(1);
  stats.me_request(255, 2, MeResult::timeout);
  EXPECT_EQ(stats.snapshot().me_dcs.at("2").requests_timeout, 2u);

  stats.configure_workers(2);
  stats.me_request(2, 2, MeResult::failure);
  const auto snapshot = stats.snapshot();
  EXPECT_EQ(snapshot.me_dcs.at("2").requests_timeout, 2u);
  EXPECT_EQ(snapshot.me_dcs.at("2").requests_failure, 1u);
}

TEST(MeCounterWorkersTest, ShrinkRetiresReactorGaugesButKeepsCumulativeHistory) {
  Statistics stats;
  stats.configure_workers(4);
  stats.me_queue(3, 2, 7, 1, 1024, 2048);
  stats.me_direct(3, 2, 1, 2, 0, 4096, 8192);
  stats.me_request(3, 2, MeResult::failure);
  stats.me_answer(3, 2, MeAnswerResult::dropped_unknown);

  auto snapshot = stats.snapshot();
  EXPECT_EQ(snapshot.me_dcs.at("2").ready_queue_depth, 7u);
  EXPECT_EQ(snapshot.me_dcs.at("2").direct_rx_bytes_total, 4096u);

  stats.configure_workers(2);  // slot 3 is no longer an active reactor
  snapshot = stats.snapshot();
  // Reactor-owned gauges follow the active set (unchanged semantics)...
  EXPECT_EQ(snapshot.me_dcs.at("2").ready_queue_depth, 0u);
  EXPECT_EQ(snapshot.me_dcs.at("2").direct_active, 0u);
  // ...while cumulative outcomes from the retired slot are never dropped.
  EXPECT_EQ(snapshot.me_dcs.at("2").requests_failure, 1u);
  EXPECT_EQ(snapshot.me_dcs.at("2").proxy_ans_dropped_unknown_total, 1u);
}

TEST(MeCounterWorkersTest, ParallelFirstUseGrowthKeepsExactTotals) {
  Statistics stats;
  stats.configure_workers(1);  // threads race to extend the bound from slot 0

  constexpr std::size_t kThreads = 8;
  constexpr std::size_t kIterations = 10'000;
  const std::array<std::size_t, kThreads> workers = {
      std::numeric_limits<std::size_t>::max(), 255, 256, 200,
      128, 127, 1, 0};

  std::barrier start(static_cast<std::ptrdiff_t>(kThreads));
  std::vector<std::thread> threads;
  threads.reserve(kThreads);
  for (const std::size_t worker : workers) {
    threads.emplace_back([&stats, &start, worker] {
      start.arrive_and_wait();
      for (std::size_t i = 0; i < kIterations; ++i) {
        stats.me_request(worker, 2, MeResult::success);
        stats.me_answer(worker, 2, MeAnswerResult::delivered);
      }
    });
  }
  for (auto& thread : threads) thread.join();

  const uint64_t expected = kThreads * kIterations;
  const auto snapshot = stats.snapshot();
  EXPECT_EQ(snapshot.me_dcs.at("2").requests_success, expected);
  EXPECT_EQ(snapshot.me_dcs.at("2").proxy_ans_delivered_total, expected);
}

TEST(MeCounterWorkersTest, ParallelUpdatesTotalExactlyIncludingSlotCollisions) {
  Statistics stats;
  stats.configure_workers(4);

  constexpr std::size_t kThreads = 8;
  constexpr std::size_t kIterations = 20'000;
  // 0 and 256 collide in slot 0; 255 and SIZE_MAX collide in slot 255; the
  // remaining ids fall into distinct slots regardless of the active count.
  const std::array<std::size_t, kThreads> workers = {
      0, 256, std::numeric_limits<std::size_t>::max(), 255,
      1, 300, 257, 5};

  std::barrier start(static_cast<std::ptrdiff_t>(kThreads));
  std::vector<std::thread> threads;
  threads.reserve(kThreads);
  for (const std::size_t worker : workers) {
    threads.emplace_back([&stats, &start, worker] {
      start.arrive_and_wait();
      for (std::size_t i = 0; i < kIterations; ++i) {
        stats.me_request(worker, 2, MeResult::success);
        stats.me_request(worker, 2, MeResult::failure);
        stats.me_request(worker, 2, MeResult::timeout);
        stats.me_answer(worker, 2, MeAnswerResult::received);
        stats.me_answer(worker, 2, MeAnswerResult::delivered);
        stats.me_answer(worker, 2, MeAnswerResult::dropped_unknown);
        stats.me_answer(worker, 2, MeAnswerResult::dropped_other);
      }
    });
  }
  for (auto& thread : threads) thread.join();

  const uint64_t expected = kThreads * kIterations;
  const auto snapshot = stats.snapshot();
  const auto& dc = snapshot.me_dcs.at("2");
  EXPECT_EQ(dc.requests_success, expected);
  EXPECT_EQ(dc.requests_failure, expected);
  EXPECT_EQ(dc.requests_timeout, expected);
  EXPECT_EQ(dc.proxy_ans_received_total, expected);
  EXPECT_EQ(dc.proxy_ans_delivered_total, expected);
  EXPECT_EQ(dc.proxy_ans_dropped_unknown_total, expected);
  EXPECT_EQ(dc.proxy_ans_dropped_other_total, expected);
}

TEST(MeCounterWorkersTest, DisconnectDoesNotClearCumulativeCounters) {
  Statistics stats;
  stats.configure_workers(4);
  stats.me_request(3, 2, MeResult::success);
  stats.me_request(3, 2, MeResult::failure);
  stats.me_answer(3, 2, MeAnswerResult::received);
  stats.me_answer(3, 2, MeAnswerResult::dropped_other);

  stats.me_connected(2, false);
  stats.me_connected(3, 2, true);
  stats.me_connected(3, 2, false);

  const auto snapshot = stats.snapshot();
  const auto& dc = snapshot.me_dcs.at("2");
  EXPECT_FALSE(dc.connected);
  EXPECT_EQ(dc.requests_success, 1u);
  EXPECT_EQ(dc.requests_failure, 1u);
  EXPECT_EQ(dc.proxy_ans_received_total, 1u);
  EXPECT_EQ(dc.proxy_ans_dropped_other_total, 1u);
}

}  // namespace
