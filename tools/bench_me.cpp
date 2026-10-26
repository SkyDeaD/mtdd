// Manual A/B benchmark for the ME (middle-end) hot path. Links the current
// mtdd_protocol library; the "old" side is the pre-optimization code copied
// verbatim from baseline commit ecc6dce, using the same current crypto
// wrappers, so the measured delta is copies/allocations, not AES or CRC gains.
//
// Build (Release -O2, no -march=native):
//   c++ -std=c++20 -O2 -DNDEBUG -Iinclude tools/bench_me.cpp
//       build/libmtdd_protocol.a -lcrypto -pthread -o build/bench_me
#include "mtdd/protocol.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <memory>
#include <span>
#include <vector>

namespace {
using Bytes = std::vector<std::uint8_t>;
namespace crypto = mtdd::protocol::crypto;
namespace protocol = mtdd::protocol;

volatile std::uint64_t sink{};

void put32(Bytes& out, std::uint32_t v) {
  out.push_back(static_cast<std::uint8_t>(v));
  out.push_back(static_cast<std::uint8_t>(v >> 8));
  out.push_back(static_cast<std::uint8_t>(v >> 16));
  out.push_back(static_cast<std::uint8_t>(v >> 24));
}
void append(Bytes& out, std::span<const std::uint8_t> b) {
  out.insert(out.end(), b.begin(), b.end());
}
std::int32_t next_seq(std::int32_t seq) {
  return static_cast<std::int32_t>(static_cast<std::uint32_t>(seq) + 1u);
}

// ---- Fixture for the Middle-End protocol tests ------------------------------
const std::array<std::uint8_t, 32> kSecret = [] {
  std::array<std::uint8_t, 32> s{};
  for (int i = 0; i < 32; ++i) s[i] = static_cast<std::uint8_t>(i);
  return s;
}();
const protocol::Endpoint kServer = protocol::Endpoint::v4({149, 154, 175, 50}, 8888);
const protocol::Endpoint kLocal = protocol::Endpoint::v4({203, 0, 113, 9}, 54321);
const protocol::Endpoint kAdvertised = protocol::Endpoint::v4({203, 0, 113, 9}, 443);
const protocol::Endpoint kPeer = protocol::Endpoint::v4({198, 51, 100, 7}, 40000);
constexpr std::uint16_t kProcessId = 0x1f3a;
constexpr std::uint32_t kProcessTime = 1600000000u;
const std::array<std::uint8_t, 8> kConnId{1, 2, 3, 4, 5, 6, 7, 8};
const std::array<std::uint8_t, 16> kAdTag{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
                                          0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};

Bytes me_plain_frame(std::int32_t seq, std::span<const std::uint8_t> payload) {
  Bytes f;
  put32(f, static_cast<std::uint32_t>(payload.size() + 12));
  put32(f, static_cast<std::uint32_t>(seq));
  append(f, payload);
  put32(f, crypto::crc32(f));
  return f;
}

Bytes nonce_answer() {
  Bytes n(16);
  for (int i = 0; i < 16; ++i) n[i] = static_cast<std::uint8_t>(0xa0 + i);
  Bytes payload;
  put32(payload, 0x7acb87aau);  // RPC_NONCE
  payload.insert(payload.end(), kSecret.begin(), kSecret.begin() + 4);
  put32(payload, 1);  // RPC_CRYPTO_AES
  put32(payload, 1600000000u);
  append(payload, n);
  return me_plain_frame(-2, payload);
}

// Golden handshake answer (flags = 0 => IEEE CRC-32 data frames afterwards).
constexpr std::string_view kHandshakeAnswerEnc =
    "ca56a51dead27a7ec16e658762b13591dfd6e87a9bcae4d3896b8f8fae573601"
    "f339b98bfa546aff74a6a4ad662d08d6";

Bytes from_hex(std::string_view hex) {
  Bytes out;
  out.reserve(hex.size() / 2);
  for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
    const auto nibble = [](char c) -> int {
      if (c >= '0' && c <= '9') return c - '0';
      if (c >= 'a' && c <= 'f') return c - 'a' + 10;
      return c - 'A' + 10;
    };
    out.push_back(static_cast<std::uint8_t>((nibble(hex[i]) << 4) | nibble(hex[i + 1])));
  }
  return out;
}

protocol::MiddleEndConfig me_config() {
  protocol::MiddleEndConfig cfg;
  cfg.secret.assign(kSecret.begin(), kSecret.end());
  cfg.server = kServer;
  cfg.local = kLocal;
  cfg.advertised = kAdvertised;
  cfg.ad_tag.bytes = kAdTag;
  cfg.max_frame = std::size_t{1} << 20;
  cfg.process_id = kProcessId;
  cfg.process_time = kProcessTime;
  cfg.random = [](std::span<std::uint8_t> out) {
    for (std::size_t i = 0; i < out.size(); ++i) out[i] = static_cast<std::uint8_t>(i);
  };
  cfg.clock = [] { return std::int64_t{1600000000}; };
  return cfg;
}

struct NullSink : protocol::MiddleEndSession::Sink {
  void on_proxy_payload(const protocol::MiddleEndSession::ConnId&, std::span<const std::uint8_t>) override {}
  void on_quick_ack(const protocol::MiddleEndSession::ConnId&, std::array<std::uint8_t, 4>) override {}
  void on_remote_close(const protocol::MiddleEndSession::ConnId&) override {}
};

std::unique_ptr<protocol::MiddleEndSession> make_ready() {
  auto session = std::make_unique<protocol::MiddleEndSession>(me_config(), std::make_unique<NullSink>());
  (void)session->start();
  std::vector<std::uint8_t> to_me;
  if (session->feed(nonce_answer(), to_me) != protocol::Status::Ok) {
    std::cerr << "nonce feed: " << session->error() << '\n';
    return nullptr;
  }
  to_me.clear();
  if (session->feed(from_hex(kHandshakeAnswerEnc), to_me) != protocol::Status::Ok) {
    std::cerr << "handshake feed: " << session->error() << '\n';
    return nullptr;
  }
  if (!session->ready()) {
    std::cerr << "not ready: " << session->error() << '\n';
    return nullptr;
  }
  return session;
}

// ---- Old encode_client_message (baseline ecc6dce, verbatim logic) -----------
struct OldEncoder {
  std::int32_t write_seq{-1};
  crypto::AesCbc encryptor;
  protocol::MiddleEndConfig cfg;

  OldEncoder() : encryptor(kSecret, std::array<std::uint8_t, 16>{}) {
    cfg = me_config();
  }

  void append_encrypted(std::span<const std::uint8_t> payload, Bytes& to_me) {
    Bytes frame;
    frame.reserve(payload.size() + 28);
    put32(frame, static_cast<std::uint32_t>(payload.size() + 12));
    put32(frame, static_cast<std::uint32_t>(write_seq));
    write_seq = next_seq(write_seq);
    append(frame, payload);
    put32(frame, crypto::crc32(frame));
    while (frame.size() % 16 != 0) put32(frame, 4);
    encryptor.encrypt(frame);
    append(to_me, frame);
  }

  void run(std::span<const std::uint8_t> payload, const protocol::Endpoint& peer,
           protocol::ProtoTag tag, bool quick_ack, Bytes& to_me) {
    constexpr std::uint32_t kRpcProxyReq = 0x36cef1ee;
    constexpr std::uint32_t kTlProxyTag = 0xdb1e26ae;
    constexpr std::uint32_t kFlagNotEncrypted = 0x00000002;
    constexpr std::uint32_t kFlagHasAdTag = 0x00000008;
    constexpr std::uint32_t kFlagMagic = 0x00001000;
    constexpr std::uint32_t kFlagExtMode2 = 0x00020000;
    constexpr std::uint32_t kFlagPad = 0x08000000;
    constexpr std::uint32_t kFlagIntermediate = 0x20000000;
    constexpr std::uint32_t kFlagQuickAck = 0x80000000;

    std::uint32_t flags = kFlagMagic | kFlagExtMode2 | kFlagHasAdTag;
    flags |= (tag == protocol::ProtoTag::Secure) ? (kFlagIntermediate | kFlagPad) : kFlagIntermediate;
    if (quick_ack) flags |= kFlagQuickAck;
    if (payload.size() >= 8 &&
        std::all_of(payload.begin(), payload.begin() + 8, [](std::uint8_t b) { return b == 0; })) {
      flags |= kFlagNotEncrypted;
    }

    const std::size_t rpc_len = 84 + payload.size();
    Bytes rpc;
    rpc.reserve(rpc_len);
    put32(rpc, kRpcProxyReq);
    put32(rpc, flags);
    rpc.insert(rpc.end(), kConnId.begin(), kConnId.end());
    append(rpc, peer.wire20());
    append(rpc, cfg.advertised.wire20());
    put32(rpc, 24);
    put32(rpc, kTlProxyTag);
    rpc.push_back(16);
    rpc.insert(rpc.end(), cfg.ad_tag.bytes.begin(), cfg.ad_tag.bytes.end());
    rpc.insert(rpc.end(), {0, 0, 0});
    append(rpc, payload);

    Bytes frame;
    frame.reserve(rpc.size() + 28);
    put32(frame, static_cast<std::uint32_t>(rpc.size() + 12));
    put32(frame, static_cast<std::uint32_t>(write_seq));
    write_seq = next_seq(write_seq);
    append(frame, rpc);
    put32(frame, crypto::crc32(frame));
    while (frame.size() % 16 != 0) put32(frame, 4);
    encryptor.encrypt(frame);
    append(to_me, frame);
  }
};

// ---- Old feed decrypt stage (baseline ecc6dce) ------------------------------
void old_feed_step(crypto::AesCbc& decryptor, std::span<const std::uint8_t> wire,
                   Bytes& cipher_wire, Bytes& plaintext) {
  append(cipher_wire, wire);
  const std::size_t decrypt_len = cipher_wire.size() - (cipher_wire.size() % 16);
  if (decrypt_len > 0) {
    Bytes blocks(cipher_wire.begin(), cipher_wire.begin() + static_cast<std::ptrdiff_t>(decrypt_len));
    decryptor.decrypt(blocks);
    append(plaintext, blocks);
    cipher_wire.erase(cipher_wire.begin(),
                      cipher_wire.begin() + static_cast<std::ptrdiff_t>(decrypt_len));
    if (cipher_wire.capacity() > 64u * 1024u && cipher_wire.empty()) Bytes().swap(cipher_wire);
  }
}

// ---- New feed decrypt stage (current middle_end.cpp) -----------------------
void new_feed_step(crypto::AesCbc& decryptor, std::span<const std::uint8_t> wire,
                   Bytes& cipher_wire, Bytes& plaintext) {
  const std::size_t buffered = cipher_wire.size() - (cipher_wire.size() % 16);
  if (buffered != 0) {
    const std::size_t old = plaintext.size();
    plaintext.resize(old + buffered);
    decryptor.decrypt(std::span<const std::uint8_t>(cipher_wire).first(buffered),
                      std::span<std::uint8_t>(plaintext).subspan(old));
    cipher_wire.erase(cipher_wire.begin(),
                      cipher_wire.begin() + static_cast<std::ptrdiff_t>(buffered));
  }
  std::size_t off = 0;
  if (!cipher_wire.empty() && !wire.empty()) {
    const std::size_t need = 16 - cipher_wire.size();
    const std::size_t take = std::min(need, wire.size());
    append(cipher_wire, wire.first(take));
    off = take;
    if (cipher_wire.size() == 16) {
      const std::size_t old = plaintext.size();
      plaintext.resize(old + 16);
      decryptor.decrypt(cipher_wire, std::span<std::uint8_t>(plaintext).subspan(old));
      cipher_wire.clear();
    }
  }
  const std::size_t direct = (wire.size() - off) / 16 * 16;
  if (direct != 0) {
    const std::size_t old = plaintext.size();
    plaintext.resize(old + direct);
    decryptor.decrypt(wire.subspan(off, direct), std::span<std::uint8_t>(plaintext).subspan(old));
    off += direct;
  }
  if (off < wire.size()) append(cipher_wire, wire.subspan(off));
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

std::size_t iterations_for(std::size_t size) {
  return std::max<std::size_t>(2000, (8u << 20) / size);
}
}  // namespace

bool feed_replicas_agree() {
  Bytes cipher_a, cipher_b, plain_a, plain_b;
  crypto::AesCbc da(kSecret, std::array<std::uint8_t, 16>{});
  crypto::AesCbc db(kSecret, std::array<std::uint8_t, 16>{});
  Bytes wire(4096, 0x42);
  old_feed_step(da, wire, cipher_a, plain_a);
  new_feed_step(db, wire, cipher_b, plain_b);
  return plain_a == plain_b && cipher_a == cipher_b;
}

int main() {
  try {
    if (!feed_replicas_agree()) {
      std::cerr << "feed replicas disagree\n";
      return 1;
    }
    auto session = make_ready();
    if (!session) {
      std::cerr << "failed to reach ME Ready state\n";
      return 1;
    }
    std::cout << "compiler=" << __VERSION__ << " rounds=7 median ns/op, speedup=old/new\n"
              << "operation,bytes,iterations,old_ns,new_ns,speedup\n"
              << std::fixed << std::setprecision(2);

    for (const std::size_t size : {64u, 1024u, 16384u, 65536u}) {
      const std::size_t iterations = iterations_for(size);
      Bytes payload(size, 0x11);

      report("encode_client_message", size, iterations,
             [&](std::size_t n) {
               OldEncoder encoder;
               Bytes out;
               return measure(n, [&](std::size_t i) {
                 out.clear();
                 payload[0] = static_cast<std::uint8_t>(i);
                 encoder.run(payload, kPeer, protocol::ProtoTag::Secure, false, out);
                 return out.size();
               });
             },
             [&](std::size_t n) {
               Bytes out;
               return measure(n, [&](std::size_t i) {
                 out.clear();
                 payload[0] = static_cast<std::uint8_t>(i);
                 if (session->encode_client_message(payload, kPeer, protocol::ProtoTag::Secure,
                                                    false, out) != protocol::Status::Ok) {
                   return std::size_t{0};
                 }
                 return out.size();
               });
             });

      Bytes wire(size, 0x42);
      report("feed_decrypt", size, iterations,
             [&](std::size_t n) {
               crypto::AesCbc decryptor(kSecret, std::array<std::uint8_t, 16>{});
               Bytes cipher_wire, plaintext;
               plaintext.reserve(size + 16);
               return measure(n, [&](std::size_t i) {
                 wire[0] = static_cast<std::uint8_t>(i);
                 old_feed_step(decryptor, wire, cipher_wire, plaintext);
                 const std::size_t out = plaintext.capacity();
                 plaintext.clear();  // demultiplexed frames are consumed
                 return out;
               });
             },
             [&](std::size_t n) {
               crypto::AesCbc decryptor(kSecret, std::array<std::uint8_t, 16>{});
               Bytes cipher_wire, plaintext;
               plaintext.reserve(size + 16);
               return measure(n, [&](std::size_t i) {
                 wire[0] = static_cast<std::uint8_t>(i);
                 new_feed_step(decryptor, wire, cipher_wire, plaintext);
                 const std::size_t out = plaintext.capacity();
                 plaintext.clear();  // demultiplexed frames are consumed
                 return out;
               });
             });
    }

    for (const std::size_t size : {64u, 1024u, 16384u, 65536u}) {
      const std::size_t iterations = iterations_for(size);
      Bytes data(size, 0x5a);
      report("crc_ieee_vs_crc32c", size, iterations,
             [&](std::size_t n) {
               return measure(n, [&](std::size_t i) {
                 data[0] = static_cast<std::uint8_t>(i);
                 return crypto::crc32(data);
               });
             },
             [&](std::size_t n) {
               return measure(n, [&](std::size_t i) {
                 data[0] = static_cast<std::uint8_t>(i);
                 return crypto::crc32c(data);
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
