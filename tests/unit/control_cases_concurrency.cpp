#include "../support/control_fixture.hpp"

namespace {

namespace {

// Deterministic persistence gate: persist_atomic() calls this while the
// mutation mutex is held. The test observes entry and then releases explicitly;
// there are no timing-based sleeps.
class PersistGate {
 public:
  static void enter(void* context) {
    static_cast<PersistGate*>(context)->block();
  }

  void block() {
    std::unique_lock<std::mutex> lock(mutex_);
    entered_ = true;
    cv_.notify_all();
    cv_.wait(lock, [this] { return released_; });
  }

  bool wait_until_entered(std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(mutex_);
    return cv_.wait_for(lock, timeout, [this] { return entered_; });
  }

  void release() {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      released_ = true;
    }
    cv_.notify_all();
  }

 private:
  std::mutex mutex_;
  std::condition_variable cv_;
  bool entered_{false};
  bool released_{false};
};

class PersistGateInstall {
 public:
  explicit PersistGateInstall(PersistGate& gate) {
    mtdd::control::detail::set_persist_gate_hook(&PersistGate::enter, &gate);
  }
  ~PersistGateInstall() {
    mtdd::control::detail::set_persist_gate_hook(nullptr, nullptr);
  }
  PersistGateInstall(const PersistGateInstall&) = delete;
  PersistGateInstall& operator=(const PersistGateInstall&) = delete;
};

// Always unblocks the writer and joins it, including on assertion failure.
struct ReleaseGateAndJoin {
  PersistGate& gate;
  std::thread& writer;
  ~ReleaseGateAndJoin() {
    gate.release();
    if (writer.joinable()) writer.join();
  }
};

}  // namespace

TEST(UserStoreConcurrencyTest, SnapshotDoesNotWaitForBlockedPersistence) {
  TempDir dir;
  auto store = open_store_or_throw(dir.file("users.json"));
  CreateUserRequest seed;
  seed.name = "alice";
  ASSERT_TRUE(store.create_user(seed).ok());

  PersistGate gate;
  PersistGateInstall install(gate);

  std::optional<mtdd::control::Result<MutationOutcome>> writer_result;
  std::thread writer([&store, &writer_result] {
    CreateUserRequest request;
    request.name = "bob";
    writer_result.emplace(store.create_user(request));
  });

  // Declared before the guard so the guard (release + join) is destroyed first;
  // a std::async future destructor would otherwise wait on the still-held gate.
  std::optional<std::future<std::shared_ptr<const mtdd::control::UserSnapshot>>>
      snapshot_future;
  ReleaseGateAndJoin cleanup{gate, writer};

  ASSERT_TRUE(gate.wait_until_entered(5000ms))
      << "persistence gate was never entered";

  // Run snapshot() on another thread so a blocked reader is observable instead
  // of hanging the test process.
  snapshot_future.emplace(std::async(std::launch::async, [&store] {
    return store.snapshot();
  }));
  const bool ready =
      snapshot_future->wait_for(2000ms) == std::future_status::ready;
  EXPECT_TRUE(ready)
      << "snapshot() waited for an in-flight durable write (mutation mutex)";

  // Release unconditionally before evaluating the captured snapshot so a RED
  // run still tears down cleanly.
  gate.release();
  auto captured = snapshot_future->get();
  if (ready) {
    ASSERT_NE(captured, nullptr);
    EXPECT_EQ(captured->revision, 1u);
    EXPECT_EQ(captured->users.size(), 1u);
    EXPECT_EQ(captured->find("bob"), nullptr);
  }

  if (writer.joinable()) writer.join();
  ASSERT_TRUE(writer_result.has_value());
  ASSERT_TRUE(writer_result->ok()) << writer_result->error().message;
  EXPECT_EQ(writer_result->value().revision, 2u);

  // Publication happens only after the durable write completed.
  auto published = store.snapshot();
  EXPECT_EQ(published->revision, 2u);
  ASSERT_NE(published->find("bob"), nullptr);
  EXPECT_TRUE(published->find("bob")->enabled);
}

TEST(UserStoreConcurrencyTest, HeldSnapshotStaysImmutableAcrossCommit) {
  TempDir dir;
  auto store = open_store_or_throw(dir.file("users.json"));
  CreateUserRequest seed;
  seed.name = "alice";
  ASSERT_TRUE(store.create_user(seed).ok());

  auto held = store.snapshot();
  ASSERT_EQ(held->revision, 1u);

  CreateUserRequest next;
  next.name = "bob";
  auto result = store.create_user(next);
  ASSERT_TRUE(result.ok()) << result.error().message;

  // The old owner keeps its own immutable revision and records.
  EXPECT_EQ(held->revision, 1u);
  ASSERT_EQ(held->users.size(), 1u);
  EXPECT_EQ(held->users[0].name, "alice");
  EXPECT_EQ(held->find("bob"), nullptr);

  auto current = store.snapshot();
  EXPECT_EQ(current->revision, 2u);
  ASSERT_NE(current->find("bob"), nullptr);
}

TEST(UserStoreConcurrencyTest, ConcurrentWritersKeepRevisionsMonotonicAndUnique) {
  TempDir dir;
  auto store = open_store_or_throw(dir.file("users.json"));
  constexpr int kWriterCount = 8;
  std::vector<uint64_t> revisions(static_cast<size_t>(kWriterCount), 0);
  std::atomic<int> failures{0};

  std::vector<std::thread> writers;
  writers.reserve(static_cast<size_t>(kWriterCount));
  for (int i = 0; i < kWriterCount; ++i) {
    writers.emplace_back([&store, &revisions, &failures, i] {
      CreateUserRequest request;
      request.name = "user" + std::to_string(i);
      auto result = store.create_user(request);
      if (!result.ok()) {
        failures.fetch_add(1);
        return;
      }
      revisions[static_cast<size_t>(i)] = result.value().revision;
    });
  }
  for (auto& writer : writers) writer.join();

  ASSERT_EQ(failures.load(), 0);
  std::vector<uint64_t> sorted = revisions;
  std::sort(sorted.begin(), sorted.end());
  for (int i = 0; i < kWriterCount; ++i) {
    EXPECT_EQ(sorted[static_cast<size_t>(i)], static_cast<uint64_t>(i + 1));
  }

  auto snapshot = store.snapshot();
  EXPECT_EQ(snapshot->revision, static_cast<uint64_t>(kWriterCount));
  EXPECT_EQ(snapshot->users.size(), static_cast<size_t>(kWriterCount));
  for (int i = 0; i < kWriterCount; ++i) {
    EXPECT_NE(snapshot->find("user" + std::to_string(i)), nullptr);
  }
}

// ---------------------------------------------------------------------------
// UserStore: runtime acknowledgement hook
// ---------------------------------------------------------------------------

TEST(RuntimeAckTest, MissingHookIsImmediatelyApplied) {
  TempDir dir;
  auto store = open_store_or_throw(dir.file("users.json"));
  CreateUserRequest request;
  request.name = "alice";
  auto result = store.create_user(request);
  ASSERT_TRUE(result.ok());
  EXPECT_TRUE(result.value().applied);
  EXPECT_FALSE(result.value().pending);
}

TEST(RuntimeAckTest, HookAcknowledgingRevisionIsApplied) {
  TempDir dir;
  std::atomic<uint64_t> observed{0};
  StoreOptions options;
  options.ack_timeout = 500ms;
  options.ack_hook = [&observed](uint64_t revision, std::chrono::milliseconds) {
    observed.store(revision);
    return true;
  };
  auto store = open_store_or_throw(dir.file("users.json"), options);
  CreateUserRequest request;
  request.name = "alice";
  auto result = store.create_user(request);
  ASSERT_TRUE(result.ok());
  EXPECT_EQ(observed.load(), 1u);
  EXPECT_TRUE(result.value().applied);
  EXPECT_FALSE(result.value().pending);
}

TEST(RuntimeAckTest, HookTimeoutReportsPendingButKeepsDurablePublishedState) {
  TempDir dir;
  std::atomic<uint64_t> observed{0};
  std::atomic<uint64_t> timeout_ms{0};
  StoreOptions options;
  options.ack_timeout = 25ms;
  options.ack_hook = [&](uint64_t revision, std::chrono::milliseconds timeout) {
    observed.store(revision);
    timeout_ms.store(static_cast<uint64_t>(timeout.count()));
    return false;
  };
  auto store = open_store_or_throw(dir.file("users.json"), options);
  CreateUserRequest request;
  request.name = "alice";
  auto result = store.create_user(request);
  ASSERT_TRUE(result.ok()) << result.error().message;
  EXPECT_EQ(observed.load(), 1u);
  EXPECT_EQ(timeout_ms.load(), 25u);
  EXPECT_FALSE(result.value().applied);
  EXPECT_TRUE(result.value().pending);
  EXPECT_EQ(result.value().revision, 1u);
  ASSERT_NE(store.snapshot()->find("alice"), nullptr);

  auto reopened = open_store_or_throw(dir.file("users.json"));
  ASSERT_NE(reopened.snapshot()->find("alice"), nullptr);
  EXPECT_EQ(reopened.snapshot()->revision, 1u);
}

TEST(RuntimeAckTest, ThrowingHookDoesNotEscapeOrCorruptState) {
  TempDir dir;
  StoreOptions options;
  options.ack_hook = [](uint64_t, std::chrono::milliseconds) -> bool {
    throw std::runtime_error("reactor unavailable");
  };
  auto store = open_store_or_throw(dir.file("users.json"), options);
  CreateUserRequest request;
  request.name = "alice";
  auto result = store.create_user(request);
  ASSERT_TRUE(result.ok());
  EXPECT_TRUE(result.value().pending);
  EXPECT_FALSE(result.value().applied);
  EXPECT_EQ(store.snapshot()->revision, 1u);
}

// ---------------------------------------------------------------------------
// Statistics and Prometheus
// ---------------------------------------------------------------------------


}  // namespace
