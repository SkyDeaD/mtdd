#include <gtest/gtest.h>

#include "../support/fake_tls_fixture.hpp"

#include <atomic>
#include <cstdlib>
#include <new>

namespace {
std::atomic<bool> track_allocations{false};
std::atomic<std::size_t> allocations{0};
}

// Test-executable-only interposition: measure C++ payload allocations, not the
// OpenSSL allocator. Never linked into mtdd or the other test executables.
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

namespace mtdd::test {
namespace {

using Bytes = std::vector<std::uint8_t>;

TEST(FakeTlsSend, PreallocatedOutputNeedsNoPerRecordCppAllocation) {
    auto connection = ready_fake_tls();
    const Bytes plaintext(65537, 0x5a);
    Bytes output;
    output.reserve(plaintext.size() + 5 * 5);
    allocations.store(0);
    track_allocations.store(true);
    protocol::Status result{};
    try {
        result = connection.send(plaintext, output);
    } catch (...) {
        track_allocations.store(false);
        throw;
    }
    track_allocations.store(false);
    EXPECT_EQ(result, protocol::Status::Ok);
    EXPECT_EQ(allocations.load(), 0u);
}

TEST(FakeTlsSend, MultiRecordAppendPreservesPrefixAndCipherContinuity) {
    auto connection = ready_fake_tls();
    auto decryptor = fake_tls_client_decryptor();
    for (const std::size_t size : {0u, 1u, 16383u, 16384u, 16385u, 131073u}) {
        Bytes plaintext(size);
        for (std::size_t i = 0; i < size; ++i) plaintext[i] = static_cast<std::uint8_t>(i * 17);
        const auto original = plaintext;
        Bytes output{0xa5, 0x5a};
        ASSERT_EQ(connection.send(plaintext, output), protocol::Status::Ok);
        EXPECT_EQ(plaintext, original);
        ASSERT_EQ(output[0], 0xa5);
        ASSERT_EQ(output[1], 0x5a);
        Bytes decoded;
        std::size_t offset = 2;
        while (offset < output.size()) {
            ASSERT_GE(output.size() - offset, 5u);
            EXPECT_EQ(output[offset], 0x17);
            EXPECT_EQ(output[offset + 1], 0x03);
            EXPECT_EQ(output[offset + 2], 0x03);
            const std::size_t length = (static_cast<std::size_t>(output[offset + 3]) << 8) |
                                       output[offset + 4];
            ASSERT_GT(length, 0u);
            ASSERT_LE(length, 16384u);
            ASSERT_LE(length, output.size() - offset - 5);
            auto body = std::span<std::uint8_t>(output).subspan(offset + 5, length);
            decryptor.apply(body);
            decoded.insert(decoded.end(), body.begin(), body.end());
            offset += 5 + length;
        }
        EXPECT_EQ(decoded, plaintext);
    }
}

TEST(FakeTlsSend, AliasedInputSurvivesOutputReallocation) {
    auto connection = ready_fake_tls();
    auto decryptor = fake_tls_client_decryptor();
    Bytes output(32769, 0x69);
    output.shrink_to_fit();
    const Bytes expected(output.begin() + 1, output.end());
    const std::size_t prefix = output.size();
    ASSERT_EQ(connection.send(std::span<const std::uint8_t>(output).subspan(1), output),
              protocol::Status::Ok);
    EXPECT_EQ(Bytes(output.begin(), output.begin() + static_cast<std::ptrdiff_t>(prefix)),
              Bytes(prefix, 0x69));
    Bytes decoded;
    for (std::size_t offset = prefix; offset < output.size();) {
        ASSERT_GE(output.size() - offset, 5u);
        const std::size_t length = (static_cast<std::size_t>(output[offset + 3]) << 8) |
                                   output[offset + 4];
        ASSERT_GT(length, 0u);
        ASSERT_LE(length, output.size() - offset - 5);
        auto body = std::span<std::uint8_t>(output).subspan(offset + 5, length);
        decryptor.apply(body);
        decoded.insert(decoded.end(), body.begin(), body.end());
        offset += 5 + length;
    }
    EXPECT_EQ(decoded, expected);
}

} // namespace
} // namespace mtdd::test
