// Local fake Telegram DC for the Direct fallback integration tests/benchmark.
//
// The Direct route speaks raw obfuscated2 (tag 0xdddddddd) and relays the
// client's padded-intermediate bytes verbatim. This helper terminates that
// transport on loopback so tests can observe the exact bytes, count frames and
// drive EOF without contacting Telegram.
#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <algorithm>
#include <array>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

#include "mtdd/protocol.hpp"

namespace mtdd::test {

namespace direct_detail {

inline std::uint32_t rd32(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0]) |
           (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) |
           (static_cast<std::uint32_t>(p[3]) << 24);
}

inline void put32(std::vector<std::uint8_t>& out, std::uint32_t value) {
    for (int i = 0; i < 4; ++i) {
        out.push_back(static_cast<std::uint8_t>(value >> (8 * i)));
    }
}

inline bool send_all(int fd, const std::uint8_t* data, std::size_t size) {
    while (size != 0) {
        const ssize_t sent = ::send(fd, data, size, MSG_NOSIGNAL);
        if (sent < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        data += sent;
        size -= static_cast<std::size_t>(sent);
    }
    return true;
}

inline bool recv_exact(int fd, std::uint8_t* data, std::size_t size) {
    while (size != 0) {
        const ssize_t got = ::recv(fd, data, size, 0);
        if (got < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return false;
            return false;
        }
        if (got == 0) return false;
        data += got;
        size -= static_cast<std::size_t>(got);
    }
    return true;
}

} // namespace direct_detail

class FakeDirectDc {
public:
    explicit FakeDirectDc(std::int16_t expected_dc, bool respond = true,
                          int recv_buffer_bytes = 0)
        : expected_dc_(expected_dc), respond_(respond) {
        listener_ = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (listener_ < 0) throw std::runtime_error("fake direct DC: socket failed");
        int one = 1;
        ::setsockopt(listener_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        if (recv_buffer_bytes > 0) {
            ::setsockopt(listener_, SOL_SOCKET, SO_RCVBUF, &recv_buffer_bytes,
                         sizeof(recv_buffer_bytes));
        }
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = 0;
        if (::bind(listener_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 ||
            ::listen(listener_, 8) != 0) {
            ::close(listener_);
            throw std::runtime_error("fake direct DC: bind/listen failed");
        }
        socklen_t length = sizeof(address);
        ::getsockname(listener_, reinterpret_cast<sockaddr*>(&address), &length);
        port_ = ntohs(address.sin_port);
        thread_ = std::thread([this] { run(); });
    }

    ~FakeDirectDc() {
        stop_.store(true);
        if (thread_.joinable()) thread_.join();
        if (listener_ >= 0) ::close(listener_);
    }

    FakeDirectDc(const FakeDirectDc&) = delete;
    FakeDirectDc& operator=(const FakeDirectDc&) = delete;

    std::uint16_t port() const { return port_; }

    // 0 = keep the connection open. N > 0 = close after the Nth response.
    void close_after_responses(std::size_t count) {
        close_after_.store(count, std::memory_order_relaxed);
    }

    // Stop/resume consuming client bytes. While paused the kernel receive
    // buffer carries the backlog, which lets a test force the proxy's
    // direct_out to would-block without touching production code.
    void pause_reading() { read_enabled_.store(false, std::memory_order_relaxed); }
    void resume_reading() { read_enabled_.store(true, std::memory_order_relaxed); }

    // Send server->client padded-intermediate frames immediately after the
    // header (independent of client requests) and optionally half-close.
    void send_unsolicited(std::vector<std::vector<std::uint8_t>> payloads,
                          bool shutdown_write = false) {
        std::lock_guard<std::mutex> lock(unsolicited_mutex_);
        unsolicited_ = std::move(payloads);
        unsolicited_write_shutdown_ = shutdown_write;
    }

    std::uint64_t connections() const { return connections_.load(std::memory_order_relaxed); }
    std::uint64_t frames() const { return frames_.load(std::memory_order_relaxed); }
    std::uint64_t c2s_bytes() const { return c2s_bytes_.load(std::memory_order_relaxed); }
    std::uint64_t s2c_bytes() const { return s2c_bytes_.load(std::memory_order_relaxed); }
    std::uint64_t recv_calls() const { return recv_calls_.load(std::memory_order_relaxed); }
    std::uint64_t send_calls() const { return send_calls_.load(std::memory_order_relaxed); }
    std::uint64_t unsolicited_sent() const {
        return unsolicited_sent_.load(std::memory_order_relaxed);
    }
    std::uint32_t header_tag() const { return header_tag_.load(std::memory_order_relaxed); }
    std::int16_t header_dc() const { return header_dc_.load(std::memory_order_relaxed); }
    bool header_ok() const { return header_ok_.load(std::memory_order_relaxed); }
    const std::vector<std::vector<std::uint8_t>>& payloads() const { return payloads_; }

private:
    void run() {
        while (!stop_.load(std::memory_order_relaxed)) {
            pollfd entry{listener_, POLLIN, 0};
            const int ready = ::poll(&entry, 1, 50);
            if (ready <= 0) continue;
            const int fd = ::accept4(listener_, nullptr, nullptr, SOCK_CLOEXEC);
            if (fd < 0) continue;
            connections_.fetch_add(1, std::memory_order_relaxed);
            handle(fd);
            ::close(fd);
            if (close_after_.load(std::memory_order_relaxed) != 0) break;
        }
    }

    void handle(int fd) {
        timeval timeout{};
        timeout.tv_usec = 100 * 1000;
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

        std::array<std::uint8_t, 64> header{};
        if (!direct_detail::recv_exact(fd, header.data(), header.size())) return;
        std::array<std::uint8_t, 32> key{};
        std::array<std::uint8_t, 16> iv{};
        std::copy_n(header.begin() + 8, 32, key.begin());
        std::copy_n(header.begin() + 40, 16, iv.begin());
        protocol::crypto::AesCtr c2s(key, iv);
        // Bytes 0..55 travel in the clear; only the trailing 8 header bytes are
        // encrypted, with the AES-CTR stream already advanced to offset 56.
        std::array<std::uint8_t, 8> tail{};
        std::copy_n(header.begin() + 56, 8, tail.begin());
        c2s.skip(56);
        c2s.apply(tail);

        const std::uint32_t tag = direct_detail::rd32(tail.data());
        const std::int16_t dc = static_cast<std::int16_t>(
            static_cast<std::uint16_t>(tail[4]) |
            (static_cast<std::uint16_t>(tail[5]) << 8));
        header_tag_.store(tag, std::memory_order_relaxed);
        header_dc_.store(dc, std::memory_order_relaxed);
        const bool ok = tag == 0xddddddddU && dc == expected_dc_;
        header_ok_.store(ok, std::memory_order_relaxed);
        if (!ok) return;

        std::array<std::uint8_t, 32> read_key{};
        std::array<std::uint8_t, 16> read_iv{};
        for (std::size_t i = 0; i < 32; ++i) read_key[i] = header[63 - 8 - i];
        for (std::size_t i = 0; i < 16; ++i) read_iv[i] = header[63 - 40 - i];
        protocol::crypto::AesCtr s2c(read_key, read_iv);

        std::vector<std::vector<std::uint8_t>> unsolicited;
        bool unsolicited_fin = false;
        {
            std::lock_guard<std::mutex> lock(unsolicited_mutex_);
            unsolicited.swap(unsolicited_);
            unsolicited_fin = unsolicited_write_shutdown_;
        }
        for (const auto& payload : unsolicited) {
            std::vector<std::uint8_t> frame;
            direct_detail::put32(frame, static_cast<std::uint32_t>(payload.size()));
            frame.insert(frame.end(), payload.begin(), payload.end());
            s2c.apply(frame);
            if (!direct_detail::send_all(fd, frame.data(), frame.size())) break;
            send_calls_.fetch_add(1, std::memory_order_relaxed);
            s2c_bytes_.fetch_add(frame.size(), std::memory_order_relaxed);
            unsolicited_sent_.fetch_add(1, std::memory_order_relaxed);
        }
        if (unsolicited_fin) ::shutdown(fd, SHUT_WR);

        std::vector<std::uint8_t> wire;
        std::vector<std::uint8_t> buffer;
        while (!stop_.load(std::memory_order_relaxed)) {
            if (!read_enabled_.load(std::memory_order_relaxed)) {
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
                continue;
            }
            std::array<std::uint8_t, 16384> chunk{};
            const ssize_t got = ::recv(fd, chunk.data(), chunk.size(), 0);
            recv_calls_.fetch_add(1, std::memory_order_relaxed);
            if (got < 0) {
                if (errno == EINTR) continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
                break;
            }
            if (got == 0) break;
            std::vector<std::uint8_t> encrypted(chunk.begin(), chunk.begin() + got);
            c2s.apply(encrypted);
            buffer.insert(buffer.end(), encrypted.begin(), encrypted.end());

            bool fatal = false;
            std::size_t offset = 0;
            while (buffer.size() - offset >= 4) {
                const std::uint32_t length = direct_detail::rd32(buffer.data() + offset);
                if (length == 0 || length > (4U << 20)) {
                    fatal = true;
                    break;
                }
                if (buffer.size() - offset < 4 + length) break;
                std::vector<std::uint8_t> payload(
                    buffer.begin() + static_cast<std::ptrdiff_t>(offset + 4),
                    buffer.begin() + static_cast<std::ptrdiff_t>(offset + 4 + length));
                frames_.fetch_add(1, std::memory_order_relaxed);
                c2s_bytes_.fetch_add(length, std::memory_order_relaxed);
                {
                    std::lock_guard<std::mutex> lock(payloads_mutex_);
                    payloads_.push_back(payload);
                }
                offset += 4 + length;
                if (respond_) {
                    std::vector<std::uint8_t> frame;
                    direct_detail::put32(frame, length);
                    frame.insert(frame.end(), payload.begin(), payload.end());
                    s2c.apply(frame);
                    if (!direct_detail::send_all(fd, frame.data(), frame.size())) {
                        fatal = true;
                        break;
                    }
                    send_calls_.fetch_add(1, std::memory_order_relaxed);
                    s2c_bytes_.fetch_add(frame.size(), std::memory_order_relaxed);
                }
                const std::size_t limit = close_after_.load(std::memory_order_relaxed);
                if (limit != 0 && frames_.load(std::memory_order_relaxed) >= limit) {
                    ::shutdown(fd, SHUT_RDWR);
                    return;
                }
            }
            buffer.erase(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(offset));
            if (fatal) break;
        }
    }

    std::int16_t expected_dc_{0};
    bool respond_{true};
    std::uint16_t port_{0};
    int listener_{-1};
    std::thread thread_;
    std::atomic<bool> stop_{false};
    std::atomic<std::size_t> close_after_{0};
    std::atomic<std::uint64_t> connections_{0};
    std::atomic<std::uint64_t> frames_{0};
    std::atomic<std::uint64_t> c2s_bytes_{0};
    std::atomic<std::uint64_t> s2c_bytes_{0};
    std::atomic<std::uint64_t> recv_calls_{0};
    std::atomic<std::uint64_t> send_calls_{0};
    std::atomic<std::uint64_t> unsolicited_sent_{0};
    std::atomic<bool> read_enabled_{true};
    std::mutex unsolicited_mutex_;
    std::vector<std::vector<std::uint8_t>> unsolicited_;
    bool unsolicited_write_shutdown_{false};
    std::atomic<std::uint32_t> header_tag_{0};
    std::atomic<std::int16_t> header_dc_{0};
    std::atomic<bool> header_ok_{false};
    mutable std::mutex payloads_mutex_;
    std::vector<std::vector<std::uint8_t>> payloads_;
};

} // namespace mtdd::test
