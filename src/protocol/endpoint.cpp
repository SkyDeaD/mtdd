#include "mtdd/protocol.hpp"

#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace mtdd::protocol {
namespace {

void put(Bytes& out, std::span<const std::uint8_t> data) {
  out.insert(out.end(), data.begin(), data.end());
}

void put16(Bytes& out, std::uint16_t v) {
  out.push_back(static_cast<std::uint8_t>(v));
  out.push_back(static_cast<std::uint8_t>(v >> 8));
}

void put32(Bytes& out, std::uint32_t v) {
  out.push_back(static_cast<std::uint8_t>(v));
  out.push_back(static_cast<std::uint8_t>(v >> 8));
  out.push_back(static_cast<std::uint8_t>(v >> 16));
  out.push_back(static_cast<std::uint8_t>(v >> 24));
}

// KDF uses the IPv4 address in reversed (little-endian) octet order.
std::array<std::uint8_t, 4> kdf_ipv4(const Endpoint& e) {
  return {e.address[3], e.address[2], e.address[1], e.address[0]};
}

}  // namespace

std::optional<ProtoTag> proto_tag_from_u32(std::uint32_t value) {
  switch (value) {
    case static_cast<std::uint32_t>(ProtoTag::Abridged):
      return ProtoTag::Abridged;
    case static_cast<std::uint32_t>(ProtoTag::Intermediate):
      return ProtoTag::Intermediate;
    case static_cast<std::uint32_t>(ProtoTag::Secure):
      return ProtoTag::Secure;
    default:
      return std::nullopt;
  }
}

std::string_view to_string(ProtoTag tag) {
  switch (tag) {
    case ProtoTag::Abridged:
      return "abridged";
    case ProtoTag::Intermediate:
      return "intermediate";
    case ProtoTag::Secure:
      return "secure";
  }
  return "unknown";
}

Endpoint Endpoint::v4(std::array<std::uint8_t, 4> address, std::uint16_t port) {
  Endpoint e;
  std::copy(address.begin(), address.end(), e.address.begin());
  e.port = port;
  e.ipv6 = false;
  return e;
}

Endpoint Endpoint::v6(std::array<std::uint8_t, 16> address, std::uint16_t port) {
  Endpoint e;
  e.address = address;
  e.port = port;
  e.ipv6 = true;
  return e;
}

std::array<std::uint8_t, 20> Endpoint::wire20() const {
  std::array<std::uint8_t, 20> out{};
  if (!ipv6) {
    out[10] = 0xff;
    out[11] = 0xff;
    std::copy_n(address.begin(), 4, out.begin() + 12);
  } else {
    std::copy(address.begin(), address.end(), out.begin());
  }
  out[16] = static_cast<std::uint8_t>(port);
  out[17] = static_cast<std::uint8_t>(port >> 8);
  out[18] = 0;
  out[19] = 0;
  return out;
}

void MiddleProxyKeys::wipe() {
  crypto::secure_zero(write_key);
  crypto::secure_zero(write_iv);
  crypto::secure_zero(read_key);
  crypto::secure_zero(read_iv);
}

MiddleProxyKeys derive_middle_proxy_keys(const MiddleProxyKdfInput& input) {
  if (input.secret.empty() || input.secret.size() > 392) {
    throw std::invalid_argument("middle-proxy secret must be 1..392 bytes");
  }
  if (input.server.port == 0 || input.local.port == 0) {
    throw std::invalid_argument("middle-proxy endpoints require non-zero ports");
  }
  if (input.server.ipv6 != input.local.ipv6) {
    throw std::invalid_argument("middle-proxy endpoints must use the same address family");
  }

  // str := nonce_server.nonce_client.client_timestamp.server_ip.client_port.
  //        ("SERVER"/"CLIENT").client_ip.server_port.secret.nonce_server.
  //        [client_ipv6.server_ipv6].nonce_client
  // key := MD5(str+1)[0..12] || SHA1(str)
  // iv  := MD5(str+2)
  Bytes s;
  s.reserve(16 + 16 + 4 + 4 + 2 + 6 + 4 + 2 + input.secret.size() + 16 + 32 + 16);
  put(s, input.nonce_server);
  put(s, input.nonce_client);
  put32(s, input.client_timestamp);
  if (input.server.ipv6) {
    put(s, std::array<std::uint8_t, 4>{});
  } else {
    auto ip = kdf_ipv4(input.server);
    put(s, ip);
  }
  put16(s, input.local.port);
  const std::uint8_t purpose[6] = {'C', 'L', 'I', 'E', 'N', 'T'};
  put(s, purpose);
  if (input.local.ipv6) {
    put(s, std::array<std::uint8_t, 4>{});
  } else {
    auto ip = kdf_ipv4(input.local);
    put(s, ip);
  }
  put16(s, input.server.port);
  put(s, input.secret);
  put(s, input.nonce_server);
  if (input.server.ipv6) {
    put(s, input.local.address);
    put(s, input.server.address);
  }
  put(s, input.nonce_client);

  auto md5_all = crypto::md5(std::span<const std::uint8_t>(s).subspan(1));
  auto sha1_all = crypto::sha1(s);

  MiddleProxyKeys keys;
  std::copy_n(md5_all.begin(), 12, keys.write_key.begin());
  std::copy(sha1_all.begin(), sha1_all.end(), keys.write_key.begin() + 12);
  keys.write_iv = crypto::md5(std::span<const std::uint8_t>(s).subspan(2));
  crypto::secure_zero(md5_all);
  crypto::secure_zero(sha1_all);

  // Recompute the read direction with the purpose flipped to SERVER. MTProxy
  // flips the six purpose bytes in place and re-hashes the same buffer.
  Bytes s_server = s;
  std::copy_n(purpose, 6, s_server.begin() + 42);
  const std::uint8_t server_purpose[6] = {'S', 'E', 'R', 'V', 'E', 'R'};
  std::copy_n(server_purpose, 6, s_server.begin() + 42);
  auto md5_srv = crypto::md5(std::span<const std::uint8_t>(s_server).subspan(1));
  auto sha1_srv = crypto::sha1(s_server);
  std::copy_n(md5_srv.begin(), 12, keys.read_key.begin());
  std::copy(sha1_srv.begin(), sha1_srv.end(), keys.read_key.begin() + 12);
  keys.read_iv = crypto::md5(std::span<const std::uint8_t>(s_server).subspan(2));
  crypto::secure_zero(md5_srv);
  crypto::secure_zero(sha1_srv);

  crypto::secure_zero(s);
  crypto::secure_zero(s_server);
  return keys;
}

}  // namespace mtdd::protocol
