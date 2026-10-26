#include "../../src/runtime/retry.hpp"

#include <gtest/gtest.h>
#include <limits>

namespace {
using namespace std::chrono_literals;

TEST(MeRetry, FirstFailureJitterStaysWithinTwentyFivePercent) {
    for (std::uint32_t sample = 0; sample <= 10000; ++sample) {
        const auto delay = mtdd::detail::me_retry_delay(1, sample);
        ASSERT_GE(delay, 375ms);
        ASSERT_LE(delay, 625ms) << "random sample=" << sample;
    }
    EXPECT_EQ(mtdd::detail::me_retry_delay(1, 0), 375ms);
    EXPECT_EQ(mtdd::detail::me_retry_delay(1, 250), 500ms);
    EXPECT_EQ(mtdd::detail::me_retry_delay(1, 500), 625ms);
}

TEST(MeRetry, ExponentialGrowthCapsWithoutOverflow) {
    EXPECT_EQ(mtdd::detail::me_retry_delay(0, 250), 500ms);
    EXPECT_EQ(mtdd::detail::me_retry_delay(1, 250), 500ms);
    EXPECT_EQ(mtdd::detail::me_retry_delay(2, 250), 1000ms);
    EXPECT_EQ(mtdd::detail::me_retry_delay(3, 250), 2000ms);
    EXPECT_EQ(mtdd::detail::me_retry_delay(7, 0), 22500ms);
    EXPECT_EQ(mtdd::detail::me_retry_delay(7, 500), 30000ms);
    EXPECT_EQ(mtdd::detail::next_me_retry_attempt(0), 1U);
    EXPECT_EQ(mtdd::detail::next_me_retry_attempt(7), 7U);
    const auto largest = std::numeric_limits<std::size_t>::max();
    EXPECT_EQ(mtdd::detail::next_me_retry_attempt(largest), 7U);
    const auto delay = mtdd::detail::me_retry_delay(largest, std::numeric_limits<std::uint32_t>::max());
    EXPECT_GE(delay, 22500ms);
    EXPECT_LE(delay, 30000ms);
}
} // namespace
