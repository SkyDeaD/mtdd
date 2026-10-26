#include "mtdd/config.hpp"
#include "mtdd/io.hpp"
#include "mtdd/metadata.hpp"
#include "mtdd/protocol.hpp"

#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <iostream>
#include <stdexcept>

namespace {
namespace protocol = mtdd::protocol;

protocol::Endpoint endpoint(const mtdd::io::Endpoint& source) {
    protocol::Endpoint result;
    result.port = source.port;
    if (::inet_pton(AF_INET, source.address.c_str(), result.address.data()) == 1) return result;
    result.ipv6 = true;
    if (::inet_pton(AF_INET6, source.address.c_str(), result.address.data()) != 1)
        throw std::runtime_error("invalid socket endpoint");
    return result;
}

void put32(protocol::Bytes& out, std::uint32_t value) {
    for (unsigned shift{}; shift < 32; shift += 8) out.push_back(static_cast<std::uint8_t>(value >> shift));
}
void put64(protocol::Bytes& out, std::uint64_t value) {
    put32(out, static_cast<std::uint32_t>(value));
    put32(out, static_cast<std::uint32_t>(value >> 32));
}

struct ProbeSink final : protocol::MiddleEndSession::Sink {
    std::array<std::uint8_t, 16> nonce{};
    bool reply{};
    bool closed{};
    void on_proxy_payload(const protocol::MiddleEndSession::ConnId&, std::span<const std::uint8_t> payload) override {
        constexpr std::array<std::uint8_t, 4> res_pq{0x63, 0x24, 0x16, 0x05};
        reply = payload.size() >= 40 &&
                std::all_of(payload.begin(), payload.begin() + 8, [](auto byte) { return byte == 0; }) &&
                std::equal(res_pq.begin(), res_pq.end(), payload.begin() + 20) &&
                std::equal(nonce.begin(), nonce.end(), payload.begin() + 24);
    }
    void on_remote_close(const protocol::MiddleEndSession::ConnId&) override { closed = true; }
};

void queue(mtdd::io::ByteQueue& output, const protocol::Bytes& data) {
    if (output.append(data) != mtdd::io::AppendStatus::ok) throw std::runtime_error("probe queue limit exceeded");
}

void probe(const mtdd::Config& config, const mtdd::MeMetadata& metadata, const mtdd::MeEndpoint& route) {
    auto connection = mtdd::io::connect_tcp(route.host, route.port);
    if (!connection) throw std::runtime_error("ME TCP connection failed");
    pollfd wait{connection.fd.get(), POLLOUT, 0};
    if (::poll(&wait, 1, 5000) <= 0) throw std::runtime_error("ME TCP connect timeout");
    int error{};
    socklen_t length = sizeof(error);
    if (::getsockopt(connection.fd.get(), SOL_SOCKET, SO_ERROR, &error, &length) != 0 || error != 0)
        throw std::runtime_error("ME TCP connect error");
    const auto local = mtdd::io::local_endpoint(connection.fd.get());
    const auto peer = mtdd::io::peer_endpoint(connection.fd.get());
    if (!local || !peer) throw std::runtime_error("cannot obtain ME socket tuple");

    protocol::MiddleEndConfig me;
    me.secret = metadata.secret;
    me.local = endpoint(*local);
    me.server = endpoint(*peer);
    // The probe opens an outbound ME socket without binding a public listener,
    // so the only honest advertised endpoint is its own source tuple.
    me.advertised = me.local;
    me.ad_tag.bytes = config.ad_tag;
    me.random = protocol::system_random();
    me.max_frame = config.max_frame_bytes;
    auto sink = std::make_unique<ProbeSink>();
    auto* observed = sink.get();
    me.random(observed->nonce);
    protocol::MiddleEndSession session(std::move(me), std::move(sink));
    mtdd::io::ByteQueue output(65536);
    queue(output, session.start());
    bool request_sent{};
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
    while (std::chrono::steady_clock::now() < deadline && !observed->reply) {
        wait.events = static_cast<short>(POLLIN | (output.empty() ? 0 : POLLOUT));
        wait.revents = 0;
        const auto ready = ::poll(&wait, 1, 200);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) throw std::runtime_error("probe poll error");
        if ((wait.revents & POLLOUT) != 0 && !output.flush_to(connection.fd.get()).ok())
            throw std::runtime_error("probe send error");
        if ((wait.revents & (POLLIN | POLLHUP | POLLERR)) != 0) {
            std::array<std::uint8_t, 8192> buffer{};
            const auto size = ::recv(connection.fd.get(), buffer.data(), buffer.size(), MSG_DONTWAIT);
            if (size == 0) throw std::runtime_error("ME closed connection during probe");
            if (size < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
                throw std::runtime_error("probe receive error");
            if (size > 0) {
                protocol::Bytes next;
                const auto status = session.feed(std::span(buffer).first(static_cast<std::size_t>(size)), next);
                if (status == protocol::Status::ProtocolError)
                    throw std::runtime_error("ME protocol failure: " + std::string(session.error()));
                queue(output, next);
            }
        }
        if (session.ready() && !request_sent) {
            protocol::Bytes request;
            put64(request, 0); // unencrypted MTProto service message
            const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                                 std::chrono::system_clock::now().time_since_epoch()).count();
            put64(request, static_cast<std::uint64_t>(now) << 32);
            put32(request, 20);
            put32(request, 0xbe7e8ef1); // req_pq_multi
            request.insert(request.end(), observed->nonce.begin(), observed->nonce.end());
            protocol::Bytes encoded;
            if (session.encode_client_message(request, endpoint(*local), protocol::ProtoTag::Secure, false, encoded) ==
                protocol::Status::ProtocolError) throw std::runtime_error("cannot encode MTProto probe");
            queue(output, encoded);
            request_sent = true;
            std::cout << "ME handshake ready; req_pq_multi queued with ad-tag\n";
        }
        if (observed->closed) throw std::runtime_error("ME closed the logical probe connection");
    }
    if (!observed->reply) throw std::runtime_error("no valid matching res_pq within 15 seconds");
    std::cout << "DC " << route.dc << ": verified matching res_pq through ME\n";
}
} // namespace

int main(int argc, char** argv) {
    try {
        if (argc < 2 || argc > 3) throw std::invalid_argument("usage: mtdd_me_probe CONFIG.json [signed-dc]");
        int dc{2};
        if (argc == 3) {
            const std::string_view text{argv[2]};
            const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), dc);
            if (error != std::errc{} || end != text.data() + text.size() || dc == 0)
                throw std::invalid_argument("invalid datacenter");
        }
        const auto config = mtdd::Config::load(argv[1]);
        const auto metadata = mtdd::load_me_metadata(config);
        for (const auto& route : metadata.endpoints) {
            if (route.dc == dc) {
                probe(config, metadata, route);
                return 0;
            }
        }
        throw std::runtime_error("requested DC is absent from Telegram ME configuration");
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
