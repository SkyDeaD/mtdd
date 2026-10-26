#pragma once

#include "mtdd/protocol.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace mtdd::test {

// Test-only identity/time. The hello is independently sealed with Python hmac.
inline constexpr std::int64_t kFakeTlsNow = 1600000000;

inline protocol::FakeTlsConnection ready_fake_tls() {
    using Bytes = std::vector<std::uint8_t>;
    std::array<std::uint8_t, 16> secret{};
    for (std::size_t i = 0; i < secret.size(); ++i) secret[i] = static_cast<std::uint8_t>(i);
    constexpr std::string_view hello_hex =
        "16030100810100007d0303e9554afbd8c6fccd0dd851be7043e8cac9904b7d18f4ef8b6b0dd0f274c3f4f2"
        "20404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f00041301130301000030"
        "002b00020304003300260024001d0020808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
    Bytes hello;
    for (std::size_t i = 0; i < hello_hex.size(); i += 2) {
        const auto nibble = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
        hello.push_back(static_cast<std::uint8_t>((nibble(hello_hex[i]) << 4) |
                                                nibble(hello_hex[i + 1])));
    }
    protocol::FakeTlsConnection::Config config;
    config.secret = secret;
    config.clock = [] { return kFakeTlsNow; };
    config.random = [](std::span<std::uint8_t> out) { std::fill(out.begin(), out.end(), 0x42); };
    protocol::FakeTlsConnection connection(config);
    Bytes response, plaintext;
    if (connection.feed(hello, response, plaintext) != protocol::Status::Ok) {
        throw std::runtime_error("test FakeTLS hello failed");
    }

    Bytes nonce(64);
    for (std::size_t i = 0; i < nonce.size(); ++i) nonce[i] = static_cast<std::uint8_t>(i);
    std::fill(nonce.begin() + 56, nonce.begin() + 60, 0xdd);
    nonce[60] = 2;
    nonce[61] = 0;
    Bytes key_material(48);
    std::copy_n(nonce.begin() + 8, 32, key_material.begin());
    std::copy(secret.begin(), secret.end(), key_material.begin() + 32);
    const auto key = protocol::crypto::sha256(key_material);
    std::array<std::uint8_t, 16> iv{};
    std::copy_n(nonce.begin() + 40, iv.size(), iv.begin());
    protocol::crypto::AesCtr encryptor(key, iv);
    auto encrypted = nonce;
    encryptor.apply(encrypted);
    std::copy(encrypted.begin() + 56, encrypted.end(), nonce.begin() + 56);
    Bytes record{0x17, 0x03, 0x03, 0x00, 0x40};
    record.insert(record.end(), nonce.begin(), nonce.end());
    if (connection.feed(record, response, plaintext) != protocol::Status::Ok ||
        connection.state() != protocol::FakeTlsConnection::State::Ready) {
        throw std::runtime_error("test FakeTLS obfuscation failed");
    }
    return connection;
}

inline protocol::crypto::AesCtr fake_tls_client_decryptor() {
    // The independent client reverses nonce[8..56] for the server-to-client key.
    std::array<std::uint8_t, 48> reversed{};
    for (std::size_t i = 0; i < reversed.size(); ++i) reversed[i] = static_cast<std::uint8_t>(55 - i);
    std::vector<std::uint8_t> material(48);
    std::copy_n(reversed.begin(), 32, material.begin());
    for (std::uint8_t i = 0; i < 16; ++i) material[32 + i] = i;
    std::array<std::uint8_t, 16> iv{};
    std::copy_n(reversed.begin() + 32, iv.size(), iv.begin());
    return protocol::crypto::AesCtr(protocol::crypto::sha256(material), iv);
}

} // namespace mtdd::test
