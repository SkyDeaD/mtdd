#include "mtdd/protocol.hpp"

#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace mtdd::protocol {
namespace {

std::uint32_t rd32(std::span<const std::uint8_t> b, std::size_t off = 0) {
  return static_cast<std::uint32_t>(b[off]) |
         (static_cast<std::uint32_t>(b[off + 1]) << 8) |
         (static_cast<std::uint32_t>(b[off + 2]) << 16) |
         (static_cast<std::uint32_t>(b[off + 3]) << 24);
}
void put32(Bytes& out, std::uint32_t v) {
  out.push_back(static_cast<std::uint8_t>(v));
  out.push_back(static_cast<std::uint8_t>(v >> 8));
  out.push_back(static_cast<std::uint8_t>(v >> 16));
  out.push_back(static_cast<std::uint8_t>(v >> 24));
}

}  // namespace

TransportDecoder::TransportDecoder(Config config)
    : tag_(config.tag), max_message_(config.max_message) {
  if (tag_ == ProtoTag::Abridged) {
    throw std::invalid_argument("abridged transport is not supported");
  }
  if (max_message_ == 0) throw std::invalid_argument("max_message must be non-zero");
}

Status TransportDecoder::feed(std::span<const std::uint8_t> wire, std::vector<Message>& out) {
  buffer_.insert(buffer_.end(), wire.begin(), wire.end());
  std::size_t pos = 0;
  while (buffer_.size() - pos >= 4) {
    const std::uint32_t word = rd32(buffer_, pos);
    const bool quick_ack = (word & 0x80000000u) != 0;
    const std::size_t len = word & 0x7fffffffu;
    if (len == 0 || len > max_message_) return Status::ProtocolError;
    if (buffer_.size() - pos < 4 + len) break;

    const auto data = std::span<const std::uint8_t>(buffer_).subspan(pos + 4, len);
    std::size_t keep = len;
    if (tag_ == ProtoTag::Secure) {
      keep -= len % 4;  // padded intermediate: receiver truncates padding
      if (keep == 0) return Status::ProtocolError;
    } else if (len % 4 != 0) {
      return Status::ProtocolError;
    }

    Message msg;
    msg.data.assign(data.begin(), data.begin() + static_cast<std::ptrdiff_t>(keep));
    msg.quick_ack = quick_ack;
    out.push_back(std::move(msg));
    pos += 4 + len;
  }
  if (pos) buffer_.erase(buffer_.begin(), buffer_.begin() + static_cast<std::ptrdiff_t>(pos));
  if (buffer_.empty() && buffer_.capacity() > 64u * 1024u) Bytes().swap(buffer_);
  return out.empty() ? Status::NeedMoreData : Status::Ok;
}

std::size_t TransportDecoder::buffered() const { return buffer_.size(); }
std::size_t TransportDecoder::retained_bytes() const { return buffer_.capacity(); }

void TransportDecoder::release_idle() {
    if (buffer_.empty()) {
        buffer_.clear();
        if (buffer_.capacity() != 0) Bytes().swap(buffer_);
    }
}

void encode_transport_message(ProtoTag tag, std::span<const std::uint8_t> data,
                              std::vector<std::uint8_t>& out, const RandomFn* random) {
  if (tag == ProtoTag::Abridged) throw std::invalid_argument("abridged transport is not supported");
  if (data.empty() || data.size() % 4 != 0) {
    throw std::invalid_argument("transport payload must be non-empty and 4-byte aligned");
  }
  std::size_t padding = 0;
  std::array<std::uint8_t, 3> pad{};
  if (tag == ProtoTag::Secure) {
    if (random && *random) {
      std::uint8_t r = 0;
      (*random)(std::span<std::uint8_t>(&r, 1));
      padding = r % 4;
      if (padding) (*random)(std::span<std::uint8_t>(pad).first(padding));
    }
  }
  put32(out, static_cast<std::uint32_t>(data.size() + padding));
  out.insert(out.end(), data.begin(), data.end());
  out.insert(out.end(), pad.begin(), pad.begin() + static_cast<std::ptrdiff_t>(padding));
}

void encode_quick_ack(ProtoTag tag, std::array<std::uint8_t, 4> confirm,
                      std::vector<std::uint8_t>& out) {
  if (tag == ProtoTag::Abridged) {
    out.insert(out.end(), {confirm[3], confirm[2], confirm[1], confirm[0]});
  } else {
    out.insert(out.end(), confirm.begin(), confirm.end());
  }
}

}  // namespace mtdd::protocol
