// Local microbenchmark: compile this with libmtdd_protocol.a and -lcrypto.
// Preallocated output isolates record construction; it is not a network test.
#include "../tests/support/fake_tls_fixture.hpp"

#include <algorithm>
#include <chrono>
#include <iostream>
#include <string_view>
#include <vector>

namespace {
// Previous record builder, using the SAME current AES wrapper to isolate the
// per-record allocation/copy rather than attributing crypto gains twice.
mtdd::protocol::Status reference_send(std::span<const std::uint8_t> input,
                                     std::vector<std::uint8_t>& output,
                                     mtdd::protocol::crypto::AesCtr& encryptor) {
    for (std::size_t offset = 0; offset < input.size();) {
        const std::size_t size = std::min<std::size_t>(16384, input.size() - offset);
        const auto part = input.subspan(offset, size);
        std::vector<std::uint8_t> chunk(part.begin(), part.end());
        encryptor.apply(chunk);
        output.push_back(0x17);
        output.push_back(0x03);
        output.push_back(0x03);
        output.push_back(static_cast<std::uint8_t>(size >> 8));
        output.push_back(static_cast<std::uint8_t>(size));
        output.insert(output.end(), chunk.begin(), chunk.end());
        offset += size;
    }
    return mtdd::protocol::Status::Ok;
}
} // namespace

int main(int argc, char** argv) {
    const bool reference = argc == 2 && std::string_view(argv[1]) == "--reference";
    if (argc > 1 && !reference) return 2;
    using Clock = std::chrono::steady_clock;
    std::uint64_t checksum = 0;
    std::cout << "bytes,median_ns_per_send,MiB_per_second\n";
    for (const std::size_t size : {64u, 1024u, 16384u, 65536u, 131072u}) {
        const std::vector<std::uint8_t> input(size, 0x5a);
        std::vector<double> trials;
        for (int trial = 0; trial < 5; ++trial) {
            auto connection = mtdd::test::ready_fake_tls();
            auto encryptor = mtdd::test::fake_tls_client_decryptor();
            std::vector<std::uint8_t> output;
            output.reserve(size + 5 * (size / 16384 + 1));
            constexpr std::size_t iterations = 10000;
            const auto start = Clock::now();
            for (std::size_t i = 0; i < iterations; ++i) {
                output.clear();
                const auto status = reference ? reference_send(input, output, encryptor)
                                              : connection.send(input, output);
                if (status != mtdd::protocol::Status::Ok) return 1;
                checksum += output.back();
            }
            const double ns = std::chrono::duration<double, std::nano>(Clock::now() - start).count();
            trials.push_back(ns / static_cast<double>(iterations));
        }
        std::sort(trials.begin(), trials.end());
        const double median = trials[trials.size() / 2];
        std::cout << size << ',' << median << ','
                  << static_cast<double>(size) * 1e9 / median / (1024 * 1024) << '\n';
    }
    std::cout << "checksum=" << checksum << '\n';
}
