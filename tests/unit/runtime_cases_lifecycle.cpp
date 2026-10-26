#include "../support/runtime_fixture.hpp"

// ---------------------------------------------------------------------------
// ME lifecycle: keepalive, per-DC pool, metadata replacement
// ---------------------------------------------------------------------------

namespace {

struct PingTuningScope {
    PingTuningScope(std::chrono::milliseconds interval,
                    std::chrono::milliseconds jitter = std::chrono::milliseconds{0},
                    std::size_t max_unanswered = 3) {
        mtdd::detail::set_me_ping_tuning_for_test(
            mtdd::detail::MePingTuning{interval, jitter, max_unanswered});
    }
    ~PingTuningScope() {
        mtdd::detail::set_me_ping_tuning_for_test(std::nullopt);
    }
    PingTuningScope(const PingTuningScope&) = delete;
    PingTuningScope& operator=(const PingTuningScope&) = delete;
};

struct DrainDeadlineScope {
    explicit DrainDeadlineScope(std::chrono::seconds deadline) {
        mtdd::detail::set_me_drain_deadline_for_test(deadline);
    }
    ~DrainDeadlineScope() {
        mtdd::detail::set_me_drain_deadline_for_test(std::nullopt);
    }
    DrainDeadlineScope(const DrainDeadlineScope&) = delete;
    DrainDeadlineScope& operator=(const DrainDeadlineScope&) = delete;
};

void write_me_config(const Services& services, std::uint16_t port) {
    std::ofstream file{services.config.me_config_path, std::ios::binary | std::ios::trunc};
    file << "proxy_for 2 127.0.0.1:" << port << ";\n";
}

void write_me_secret(const Services& services,
                     const std::array<std::uint8_t, 128>& secret) {
    std::ofstream file{services.config.me_secret_path, std::ios::binary | std::ios::trunc};
    file.write(reinterpret_cast<const char*>(secret.data()),
               static_cast<std::streamsize>(secret.size()));
}

bool exchange(TestClient& client, std::uint8_t marker) {
    const Bytes payload{marker, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    if (!client.send_message(payload)) return false;
    Bytes response;
    return client.read_message(response, 5000) && !response.empty();
}

} // namespace

TEST(Runtime, MePingKaMeasuresRttAndKeepsConnectionReady) {
    PingTuningScope tuning(std::chrono::milliseconds{40});
    PoolMe me(me_secret());
    Daemon daemon(me.port(), true, [](mtdd::Config& config) {
        config.me_connections_per_dc = 1;
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 3s));
    ASSERT_TRUE(wait_for([&] { return me.ready() >= 1; }, 3s));

    ASSERT_TRUE(wait_for([&] {
        const auto dc = me_dc(daemon.services.stats, "2");
        return dc.pings_sent_total >= 2 && dc.pongs_received_total >= 1;
    }, 3s)) << "keepalive did not publish PING/PONG counters";
    const auto dc = me_dc(daemon.services.stats, "2");
    EXPECT_GT(dc.ping_rtt_us, 0U) << "PONG did not produce an RTT sample";
    EXPECT_EQ(dc.ping_timeouts_total, 0U);
    EXPECT_EQ(dc.connections, 1U);
    EXPECT_EQ(dc.ready_connections, 1U);
    EXPECT_TRUE(daemon.services.stats.ready());
}


// Intersection of the proto CRC32C negotiation and the melife active keepalive:
// the handshake answer echoes flags=0x800, so the PING and the matching PONG
// must both use Castagnoli. The fake rejects any other checksum, records the
// real wire size of the ping, and the proxy must publish a non-zero RTT.
TEST(Runtime, MePingUsesNegotiatedCrc32cAndPongUpdatesRtt) {
    PingTuningScope tuning(std::chrono::milliseconds{40});
    PoolMe::Options options;
    options.use_crc32c = true;
    PoolMe me(me_secret(), options);
    Daemon daemon(me.port(), true, [](mtdd::Config& config) {
        config.me_connections_per_dc = 1;
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 3s));
    ASSERT_TRUE(wait_for([&] { return me.ready() >= 1; }, 3s))
        << "the CRC32C handshake answer was not accepted";

    ASSERT_TRUE(wait_for([&] {
        const auto dc = me_dc(daemon.services.stats, "2");
        return dc.pings_sent_total >= 2 && dc.pongs_received_total >= 1;
    }, 5s)) << "keepalive did not complete a CRC32C PING/PONG round trip";

    const auto dc = me_dc(daemon.services.stats, "2");
    EXPECT_GT(dc.ping_rtt_us, 0U) << "a CRC32C PONG did not produce an RTT sample";
    EXPECT_EQ(dc.ping_timeouts_total, 0U);
    EXPECT_EQ(dc.ready_connections, 1U);
    EXPECT_GE(me.pings(0), 2U);
    // 12-byte payload + 12-byte header/CRC = 24, padded to the CBC block size.
    EXPECT_EQ(mtdd::detail::kEncodedPingFrameBytes, 32U);
    EXPECT_EQ(me.ping_frame_bytes(0), mtdd::detail::kEncodedPingFrameBytes)
        << "the ping frame must stay exactly 32 wire bytes in CRC32C mode";
    EXPECT_EQ(me.crc_mismatches(0), 0U)
        << "the peer rejected a frame checksum: the proxy did not use the "
           "negotiated CRC32C mode";
}

TEST(Runtime, MePingTimeoutReplacesOnlyTheDeadConnection) {
    PingTuningScope tuning(std::chrono::milliseconds{4000}, std::chrono::milliseconds{0}, 3);
    PoolMe::Options options;
    options.ignore_pings_on_first = true;
    PoolMe me(me_secret(), options);
    Daemon daemon(me.port(), true, [](mtdd::Config& config) {
        config.me_connections_per_dc = 2;
        config.me_clients_per_writer = 1;
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    TestClient first(daemon.port(), secret_bytes());
    TestClient second(daemon.port(), secret_bytes());
    ASSERT_TRUE(first.valid());
    ASSERT_TRUE(second.valid());
    ASSERT_TRUE(first.send_hello());
    ASSERT_TRUE(first.start_obfuscation(2));
    ASSERT_TRUE(second.send_hello(0, 1));
    ASSERT_TRUE(second.start_obfuscation(2));
    ASSERT_TRUE(exchange(first, 0x11));
    ASSERT_TRUE(exchange(second, 0x22));
    ASSERT_TRUE(wait_for([&] {
        return me_dc(daemon.services.stats, "2").ready_connections == 2;
    }, 12s)) << "the pool did not scale to two ready connections";
    TestClient third(daemon.port(), secret_bytes());
    ASSERT_TRUE(third.valid());
    ASSERT_TRUE(third.send_hello(0, 2));
    ASSERT_TRUE(third.start_obfuscation(2));
    ASSERT_TRUE(exchange(third, 0x33));
    ASSERT_TRUE(wait_for([&] { return me.messages(0) >= 1 && me.messages(1) >= 1; }, 3s))
        << "clients were not distributed over both pool connections";

    // The first connection never answers RPC_PING. K=3 unanswered pings must
    // fail it, close only its clients, and leave the second connection alone.
    ASSERT_TRUE(wait_for([&] {
        return me_dc(daemon.services.stats, "2").ping_timeouts_total >= 1;
    }, 22s)) << "the keepalive did not declare the silent connection dead";
    EXPECT_TRUE(wait_closed(first.fd(), 4000))
        << "clients on the failed connection must be closed";
    EXPECT_TRUE(exchange(third, 0x44))
        << "a client on a healthy connection must survive the replacement";
    EXPECT_FALSE(wait_closed(third.fd(), 300));
    ASSERT_TRUE(wait_for([&] {
        const auto dc = me_dc(daemon.services.stats, "2");
        return dc.ready_connections == 2 && dc.connections >= 2;
    }, 5s)) << "the failed slot did not reconnect via backoff";
}

TEST(Runtime, MePoolDistributesClientsAndFailureClosesOnlyItsClients) {
    PoolMe me(me_secret());
    Daemon daemon(me.port(), true, [](mtdd::Config& config) {
        config.me_connections_per_dc = 2;
        config.me_clients_per_writer = 1;
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    TestClient first(daemon.port(), secret_bytes());
    TestClient second(daemon.port(), secret_bytes());
    ASSERT_TRUE(first.valid());
    ASSERT_TRUE(second.valid());
    ASSERT_TRUE(first.send_hello());
    ASSERT_TRUE(first.start_obfuscation(2));
    ASSERT_TRUE(second.send_hello(0, 1));
    ASSERT_TRUE(second.start_obfuscation(2));
    ASSERT_TRUE(exchange(first, 0x41));
    ASSERT_TRUE(exchange(second, 0x42));
    ASSERT_TRUE(wait_for([&] {
        const auto dc = me_dc(daemon.services.stats, "2");
        return dc.connections == 2 && dc.ready_connections == 2;
    }, 12s));
    TestClient third(daemon.port(), secret_bytes());
    ASSERT_TRUE(third.valid());
    ASSERT_TRUE(third.send_hello(0, 2));
    ASSERT_TRUE(third.start_obfuscation(2));
    ASSERT_TRUE(exchange(third, 0x43));
    ASSERT_TRUE(wait_for([&] { return me.messages(0) >= 1 && me.messages(1) >= 1; }, 3s))
        << "least-loaded binding did not spread clients over the pool";

    me.close_connection(0);
    EXPECT_TRUE(wait_closed(first.fd(), 4000))
        << "the failed ME connection must close its own clients";
    EXPECT_TRUE(exchange(third, 0x44))
        << "the other connection's clients must not be disturbed";
    EXPECT_FALSE(wait_closed(third.fd(), 300));
    ASSERT_TRUE(wait_for([&] {
        const auto dc = me_dc(daemon.services.stats, "2");
        return dc.ready_connections == 2;
    }, 5s)) << "the pool did not restore readiness after one slot failed";
}

TEST(Runtime, MeMetadataAddressChangeDrainsOldConnectionsSmoothly) {
    PoolMe old_me(me_secret());
    PoolMe new_me(me_secret());
    Daemon daemon(old_me.port(), true, [](mtdd::Config& config) {
        config.me_connections_per_dc = 1;
        config.metadata_refresh = 1s;
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return old_me.ready() >= 1; }, 5s));

    TestClient old_client(daemon.port(), secret_bytes());
    ASSERT_TRUE(old_client.valid());
    ASSERT_TRUE(old_client.send_hello());
    ASSERT_TRUE(old_client.start_obfuscation(2));
    ASSERT_TRUE(exchange(old_client, 0x51));

    write_me_config(daemon.services, new_me.port());
    ASSERT_TRUE(wait_for([&] { return new_me.ready() >= 1; }, 6s))
        << "metadata address change did not create a connection to the new endpoint";
    ASSERT_TRUE(wait_for([&] {
        const auto dc = me_dc(daemon.services.stats, "2");
        return dc.connections >= 2 && dc.ready_connections >= 1;
    }, 4s));

    // The old connection is draining: it no longer accepts new clients, but the
    // client already bound to it keeps working.
    EXPECT_TRUE(exchange(old_client, 0x52))
        << "a draining connection must keep serving its existing client";

    TestClient new_client(daemon.port(), secret_bytes());
    ASSERT_TRUE(new_client.valid());
    ASSERT_TRUE(new_client.send_hello(0, 1));
    ASSERT_TRUE(new_client.start_obfuscation(2));
    ASSERT_TRUE(exchange(new_client, 0x53));
    ASSERT_TRUE(wait_for([&] { return new_me.messages(0) >= 1; }, 3s))
        << "new clients must attach to the replacement connection";

    old_client.close();
    ASSERT_TRUE(wait_for([&] { return old_me.active() == 0; }, 4s))
        << "the draining connection must retire once its last client is gone";
    EXPECT_TRUE(exchange(new_client, 0x54));
}

TEST(Runtime, MeMetadataSecretChangeUsesNewSecretAndDrainsOld) {
    const auto old_secret = me_secret();
    auto new_secret = old_secret;
    new_secret[0] = static_cast<std::uint8_t>(new_secret[0] ^ 0x5aU);
    new_secret[1] = static_cast<std::uint8_t>(new_secret[1] ^ 0x3cU);
    PoolMe::Options options;
    options.switch_secret_after = 1;
    PoolMe me(std::vector<PoolMe::Secret>{old_secret, new_secret}, options);
    Daemon daemon(me.port(), true, [](mtdd::Config& config) {
        config.me_connections_per_dc = 1;
        config.metadata_refresh = 1s;
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return me.ready() >= 1; }, 5s));
    EXPECT_EQ(me.secret_index(0), 0);

    TestClient old_client(daemon.port(), secret_bytes());
    ASSERT_TRUE(old_client.valid());
    ASSERT_TRUE(old_client.send_hello());
    ASSERT_TRUE(old_client.start_obfuscation(2));
    ASSERT_TRUE(exchange(old_client, 0x61));

    write_me_secret(daemon.services, new_secret);
    ASSERT_TRUE(wait_for([&] { return me.ready() >= 2; }, 6s))
        << "secret change did not create a connection using the new secret";
    ASSERT_TRUE(wait_for([&] { return me.secret_index(1) == 1; }, 2s));
    ASSERT_TRUE(wait_for([&] {
        const auto dc = me_dc(daemon.services.stats, "2");
        return dc.connections >= 2 && dc.ready_connections >= 1;
    }, 4s));

    EXPECT_TRUE(exchange(old_client, 0x62))
        << "the old-secret connection must keep serving its existing client";
    TestClient new_client(daemon.port(), secret_bytes());
    ASSERT_TRUE(new_client.valid());
    ASSERT_TRUE(new_client.send_hello(0, 1));
    ASSERT_TRUE(new_client.start_obfuscation(2));
    ASSERT_TRUE(exchange(new_client, 0x63));
    ASSERT_TRUE(wait_for([&] { return me.messages(1) >= 1; }, 3s))
        << "new clients must attach to the new-secret connection";

    old_client.close();
    ASSERT_TRUE(wait_for([&] {
        return me.active() == 1; // only the new-secret connection remains
    }, 4s));
    EXPECT_TRUE(exchange(new_client, 0x64));
}

TEST(Runtime, MeDrainingConnectionIsClosedAtHardDeadline) {
    DrainDeadlineScope deadline(std::chrono::seconds{1});
    PoolMe old_me(me_secret());
    PoolMe new_me(me_secret());
    Daemon daemon(old_me.port(), true, [](mtdd::Config& config) {
        config.me_connections_per_dc = 1;
        config.metadata_refresh = 1s;
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return old_me.ready() >= 1; }, 5s));

    TestClient old_client(daemon.port(), secret_bytes());
    ASSERT_TRUE(old_client.valid());
    ASSERT_TRUE(old_client.send_hello());
    ASSERT_TRUE(old_client.start_obfuscation(2));
    ASSERT_TRUE(exchange(old_client, 0x71));

    write_me_config(daemon.services, new_me.port());
    ASSERT_TRUE(wait_for([&] { return new_me.ready() >= 1; }, 6s));
    // The old client is never closed by us: the hard deadline must close it.
    EXPECT_TRUE(wait_closed(old_client.fd(), 5000))
        << "draining did not enforce its hard deadline";
    EXPECT_TRUE(wait_for([&] { return old_me.active() == 0; }, 4s));
    TestClient new_client(daemon.port(), secret_bytes());
    ASSERT_TRUE(new_client.valid());
    ASSERT_TRUE(new_client.send_hello(0, 1));
    ASSERT_TRUE(new_client.start_obfuscation(2));
    EXPECT_TRUE(exchange(new_client, 0x72));
}

// Ping liveness is traffic-based: a peer that ignores every PING but keeps
// sending inbound frames is alive and must keep its clients.
TEST(Runtime, MeKeepaliveRescuesConnectionThatOnlySendsTraffic) {
    PingTuningScope tuning(std::chrono::milliseconds{80}, std::chrono::milliseconds{0}, 3);
    PoolMe::Options options;
    options.answer_pings = false;
    options.inbound_chatter = true;
    PoolMe me(me_secret(), options);
    Daemon daemon(me.port(), true, [](mtdd::Config& config) {
        config.me_connections_per_dc = 1;
        config.metadata_refresh = 1s;
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 5s));

    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    ASSERT_TRUE(exchange(client, 0x81));

    ASSERT_TRUE(wait_for([&] {
        const auto dc = me_dc(daemon.services.stats, "2");
        return dc.pings_sent_total >= 6 && dc.ping_stalls_total >= 2;
    }, 6s)) << "inbound progress did not rescue the keepalive window";
    const auto dc = me_dc(daemon.services.stats, "2");
    EXPECT_EQ(dc.ping_timeouts_total, 0U)
        << "a connection proved alive by traffic was declared dead";
    EXPECT_EQ(dc.connections, 1U) << "a live connection was replaced";
    EXPECT_EQ(dc.ready_connections, 1U);
    EXPECT_EQ(me.ready(), 1U);
    EXPECT_TRUE(exchange(client, 0x82))
        << "the client of a live connection was disturbed";
}

// The whole point of successor-first replacement: /v1/ready must never turn
// false while the metadata (address) changes.
TEST(Runtime, MeMetadataReplacementNeverDropsReadiness) {
    PoolMe old_me(me_secret());
    PoolMe new_me(me_secret());
    Daemon daemon(old_me.port(), true, [](mtdd::Config& config) {
        config.me_connections_per_dc = 1;
        config.metadata_refresh = 1s;
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return old_me.ready() >= 1; }, 5s));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 5s));

    TestClient old_client(daemon.port(), secret_bytes());
    ASSERT_TRUE(old_client.valid());
    ASSERT_TRUE(old_client.send_hello());
    ASSERT_TRUE(old_client.start_obfuscation(2));
    ASSERT_TRUE(exchange(old_client, 0x91));

    std::atomic<bool> stop{false};
    std::atomic<std::uint64_t> samples{0};
    std::atomic<std::uint64_t> drops{0};
    std::thread sampler([&] {
        while (!stop.load(std::memory_order_relaxed)) {
            samples.fetch_add(1, std::memory_order_relaxed);
            if (!daemon.services.stats.ready()) drops.fetch_add(1, std::memory_order_relaxed);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    });

    write_me_config(daemon.services, new_me.port());
    ASSERT_TRUE(wait_for([&] { return new_me.ready() >= 1; }, 6s))
        << "the successor was not established";
    ASSERT_TRUE(wait_for([&] {
        const auto dc = me_dc(daemon.services.stats, "2");
        return dc.connections >= 2 && dc.ready_connections >= 1;
    }, 4s));
    EXPECT_TRUE(daemon.services.stats.ready());
    EXPECT_TRUE(exchange(old_client, 0x92))
        << "the old client must keep being served by the draining connection";

    TestClient new_client(daemon.port(), secret_bytes());
    ASSERT_TRUE(new_client.valid());
    ASSERT_TRUE(new_client.send_hello(0, 1));
    ASSERT_TRUE(new_client.start_obfuscation(2));
    ASSERT_TRUE(exchange(new_client, 0x93));
    ASSERT_TRUE(wait_for([&] { return new_me.messages(0) >= 1; }, 3s))
        << "new clients must attach to the successor";

    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    stop.store(true);
    sampler.join();
    EXPECT_GT(samples.load(), 20U);
    EXPECT_EQ(drops.load(), 0U)
        << "readiness dropped at least once during the metadata replacement";

    old_client.close();
    ASSERT_TRUE(wait_for([&] { return old_me.active() == 0; }, 4s))
        << "the drained connection must retire once its client is gone";
    EXPECT_TRUE(exchange(new_client, 0x94));
}

// A successor that never becomes ready must not start a drain timer: the old
// connections keep serving without any deadline.
TEST(Runtime, MeUnreachableSuccessorNeverDrainsTheWorkingGeneration) {
    DrainDeadlineScope deadline(std::chrono::seconds{1});
    PingTuningScope tuning(std::chrono::milliseconds{5000});
    PoolMe old_me(me_secret());
    Daemon daemon(old_me.port(), true, [](mtdd::Config& config) {
        config.me_connections_per_dc = 1;
        config.metadata_refresh = 1s;
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return old_me.ready() >= 1; }, 5s));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 5s));

    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    ASSERT_TRUE(exchange(client, 0xa1));

    // Nothing listens on port 1: the successor can only fail and retry.
    {
        std::ofstream file{daemon.services.config.me_config_path,
                           std::ios::binary | std::ios::trunc};
        file << "proxy_for 2 127.0.0.1:1;\n";
    }
    ASSERT_TRUE(wait_for([&] {
        const auto dc = me_dc(daemon.services.stats, "2");
        return dc.connections >= 2;
    }, 6s)) << "the failed successor attempt was not created";

    // Longer than the shortened drain deadline: without a ready successor no
    // drain may start, so the old connection and its client must still work.
    std::this_thread::sleep_for(std::chrono::milliseconds(2500));
    EXPECT_TRUE(daemon.services.stats.ready())
        << "readiness dropped while the working generation still serves clients";
    EXPECT_EQ(old_me.active(), 1U)
        << "the old connection was replaced without a ready successor";
    EXPECT_TRUE(exchange(client, 0xa2))
        << "the client of the working generation lost service";
    const auto dc = me_dc(daemon.services.stats, "2");
    EXPECT_EQ(dc.ready_connections, 1U);
    EXPECT_FALSE(wait_closed(client.fd(), 250));
}

// Two metadata changes in quick succession (the first successor never becomes
// ready) must not accumulate connections: at most the working generation plus
// one new generation.
TEST(Runtime, MeRapidMetadataChangesBoundTheConnectionCount) {
    PoolMe first(me_secret());
    PoolMe last(me_secret());
    Daemon daemon(first.port(), true, [](mtdd::Config& config) {
        config.me_connections_per_dc = 1;
        config.metadata_refresh = 1s;
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return first.ready() >= 1; }, 5s));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 5s));

    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    ASSERT_TRUE(exchange(client, 0xb1));

    {
        std::ofstream file{daemon.services.config.me_config_path,
                           std::ios::binary | std::ios::trunc};
        file << "proxy_for 2 127.0.0.1:1;\n";
    }
    ASSERT_TRUE(wait_for([&] { return me_dc(daemon.services.stats, "2").connections >= 2; }, 6s));

    write_me_config(daemon.services, last.port());
    ASSERT_TRUE(wait_for([&] { return last.ready() >= 1; }, 6s))
        << "the second successor was not established";
    ASSERT_TRUE(wait_for([&] {
        return me_dc(daemon.services.stats, "2").ready_connections >= 1;
    }, 4s));

    const auto dc = me_dc(daemon.services.stats, "2");
    EXPECT_LE(dc.connections, 2U)
        << "quick metadata changes accumulated ME connections";
    EXPECT_TRUE(exchange(client, 0xb2))
        << "the client of the drained generation lost service";

    TestClient new_client(daemon.port(), secret_bytes());
    ASSERT_TRUE(new_client.valid());
    ASSERT_TRUE(new_client.send_hello(0, 1));
    ASSERT_TRUE(new_client.start_obfuscation(2));
    ASSERT_TRUE(exchange(new_client, 0xb3));
    ASSERT_TRUE(wait_for([&] { return last.messages(0) >= 1; }, 3s))
        << "new clients must attach to the newest generation";

    client.close();
    ASSERT_TRUE(wait_for([&] { return first.active() == 0; }, 4s));
    EXPECT_TRUE(exchange(new_client, 0xb4));
}

// A successor that dies right after taking over must not take the node out of
// rotation: the previous generation is still draining and serving its clients,
// so it is promoted back while the successor retries.
TEST(Runtime, MeFailedSuccessorFallsBackToTheDrainingGeneration) {
    PingTuningScope tuning(std::chrono::milliseconds{5000});
    PoolMe old_me(me_secret());
    PoolMe new_me(me_secret());
    Daemon daemon(old_me.port(), true, [](mtdd::Config& config) {
        config.me_connections_per_dc = 1;
        config.metadata_refresh = 1s;
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return old_me.ready() >= 1; }, 5s));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 5s));

    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    ASSERT_TRUE(exchange(client, 0xd1));

    write_me_config(daemon.services, new_me.port());
    ASSERT_TRUE(wait_for([&] { return new_me.ready() >= 1; }, 6s));
    ASSERT_TRUE(wait_for([&] {
        const auto dc = me_dc(daemon.services.stats, "2");
        return dc.connections >= 2 && dc.ready_connections >= 1;
    }, 4s));
    // The old generation is now draining but still serving this client.
    ASSERT_TRUE(exchange(client, 0xd2));

    std::atomic<bool> stop{false};
    std::atomic<std::uint64_t> drops{0};
    std::thread sampler([&] {
        while (!stop.load(std::memory_order_relaxed)) {
            if (!daemon.services.stats.ready()) drops.fetch_add(1, std::memory_order_relaxed);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    });

    // Kill the successor: it took over and then died, leaving only the draining
    // generation as a working route.
    new_me.close_connection(0);
    ASSERT_TRUE(wait_for([&] { return new_me.active() == 0; }, 4s));
    std::this_thread::sleep_for(std::chrono::milliseconds(700));
    EXPECT_TRUE(exchange(client, 0xd3))
        << "the client of the rolled-back generation lost service";
    stop.store(true);
    sampler.join();
    EXPECT_EQ(drops.load(), 0U)
        << "readiness dropped when the successor died after taking over";
    EXPECT_TRUE(daemon.services.stats.ready());
    EXPECT_FALSE(wait_closed(client.fd(), 250));

    // The successor keeps retrying and takes over again.
    ASSERT_TRUE(wait_for([&] { return new_me.active() >= 1; }, 6s));
    ASSERT_TRUE(wait_for([&] {
        return me_dc(daemon.services.stats, "2").ready_connections >= 1;
    }, 4s));
    EXPECT_TRUE(exchange(client, 0xd4));
}

// proxy_for line order carries no meaning: a pure reorder must not create a
// new generation, a new socket, or a drain.
TEST(Runtime, MeProxyForReorderDoesNotReplaceConnections) {
    PoolMe first(me_secret());
    PoolMe second(me_secret());
    Daemon daemon(first.port(), true, [&](mtdd::Config& config) {
        config.me_connections_per_dc = 1;
        config.metadata_refresh = 1s;
        // Two endpoints of the same DC: the pool dials the first one, the
        // second stays unconnected until a failure rotation picks it.
        std::ofstream file{config.me_config_path, std::ios::binary | std::ios::trunc};
        file << "proxy_for 2 127.0.0.1:" << first.port() << ";\n"
             << "proxy_for 2 127.0.0.1:" << second.port() << ";\n";
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return first.ready() >= 1; }, 5s));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 5s));

    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    ASSERT_TRUE(exchange(client, 0xc1));

    // Same set, reversed order.
    {
        std::ofstream file{daemon.services.config.me_config_path,
                           std::ios::binary | std::ios::trunc};
        file << "proxy_for 2 127.0.0.1:" << second.port() << ";\n"
             << "proxy_for 2 127.0.0.1:" << first.port() << ";\n";
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(2500));

    const auto dc = me_dc(daemon.services.stats, "2");
    EXPECT_EQ(dc.connections, 1U) << "a proxy_for reorder created a new connection";
    EXPECT_EQ(dc.ready_connections, 1U);
    EXPECT_EQ(first.active(), 1U) << "the serving connection was replaced";
    EXPECT_EQ(second.accepted(), 0U) << "the reorder dialled the other endpoint";
    EXPECT_TRUE(daemon.services.stats.ready());
    EXPECT_TRUE(exchange(client, 0xc2));
}
