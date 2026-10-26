// Manual A/B benchmark for the S2C framing path (task 5):
//   old: encode_transport_message() into a scratch frame, then send() into wire
//   new: send_transport_message() directly into wire
// Both paths are byte-identical for the same random stream (asserted below).
//
// Build (Release -O2, no -march=native):
//   c++ -std=c++20 -O2 -DNDEBUG -Iinclude -Itests tools/bench_fused_send.cpp
//       build/libmtdd_protocol.a -lcrypto -pthread -o build/bench_fused_send
#include "../tests/support/fake_tls_fixture.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <span>
#include <vector>

namespace {
using Bytes = std::vector<std::uint8_t>;
namespace protocol = mtdd::protocol;
volatile std::uint64_t sink{};

void deterministic_random(std::span<std::uint8_t> out) {
  for (std::size_t i = 0; i < out.size(); ++i) out[i] = static_cast<std::uint8_t>(0x30 + i);
}

template <typename F>
double measure(std::size_t iterations, F&& run) {
  std::uint64_t checksum{};
  const auto start = std::chrono::steady_clock::now();
  for (std::size_t i = 0; i < iterations; ++i) checksum += run(i);
  const auto elapsed = std::chrono::steady_clock::now() - start;
  sink = checksum;
  return std::chrono::duration<double, std::nano>(elapsed).count() /
         static_cast<double>(iterations);
}

template <typename Old, typename New>
void report(const char* name, std::size_t size, std::size_t iterations, Old&& old_run,
            New&& new_run) {
  constexpr std::size_t rounds{7};
  std::array<double, rounds> old_times{}, new_times{};
  (void)old_run(64);
  (void)new_run(64);
  for (std::size_t r = 0; r < rounds; ++r) {
    if (r % 2 == 0) {
      old_times[r] = old_run(iterations);
      new_times[r] = new_run(iterations);
    } else {
      new_times[r] = new_run(iterations);
      old_times[r] = old_run(iterations);
    }
  }
  std::sort(old_times.begin(), old_times.end());
  std::sort(new_times.begin(), new_times.end());
  std::cout << name << ',' << size << ',' << iterations << ',' << old_times[rounds / 2] << ','
            << new_times[rounds / 2] << ',' << old_times[rounds / 2] / new_times[rounds / 2]
            << '\n';
}
}  // namespace

int main() {
  try {
    const protocol::RandomFn random = deterministic_random;
    // Byte-identity check with fresh connections (same deterministic state).
    {
      auto old_connection = mtdd::test::ready_fake_tls();
      auto new_connection = mtdd::test::ready_fake_tls();
      const Bytes payload(4096, 0x5a);
      Bytes tmp, old_wire, new_wire;
      protocol::encode_transport_message(old_connection.proto_tag(), payload, tmp, &random);
      if (old_connection.send(tmp, old_wire) != protocol::Status::Ok) return 1;
      if (new_connection.send_transport_message(new_connection.proto_tag(), payload, new_wire,
                                                random) != protocol::Status::Ok) {
        return 1;
      }
      if (old_wire != new_wire) {
        std::cerr << "fused send is not byte-identical\n";
        return 1;
      }
    }

    std::cout << "compiler=" << __VERSION__ << " rounds=7 median ns/op, speedup=old/new\n"
              << "operation,bytes,iterations,old_ns,new_ns,speedup\n"
              << std::fixed << std::setprecision(2);

    for (const std::size_t size : {64u, 1024u, 16384u, 65536u}) {
      const std::size_t iterations = std::max<std::size_t>(2000, (8u << 20) / size);
      const Bytes payload(size, 0x5a);
      report("send_transport_message", size, iterations,
             [&](std::size_t n) {
               auto connection = mtdd::test::ready_fake_tls();
               Bytes tmp, out;
               return measure(n, [&](std::size_t) {
                 tmp.clear();
                 out.clear();
                 protocol::encode_transport_message(connection.proto_tag(), payload, tmp, &random);
                 if (connection.send(tmp, out) != protocol::Status::Ok) return std::size_t{0};
                 return out.size();
               });
             },
             [&](std::size_t n) {
               auto connection = mtdd::test::ready_fake_tls();
               Bytes out;
               return measure(n, [&](std::size_t) {
                 out.clear();
                 if (connection.send_transport_message(connection.proto_tag(), payload, out,
                                                       random) != protocol::Status::Ok) {
                   return std::size_t{0};
                 }
                 return out.size();
               });
             });
    }
    std::cout << "observable_checksum=" << sink << '\n';
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
