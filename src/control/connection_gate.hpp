// Absolute-deadline connection admission gate for the control HTTP server.
#pragma once

#include <event2/util.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <unordered_map>

struct bufferevent;
struct evhttp_connection;
struct event_base;
struct evconnlistener;
struct evhttp_request;

namespace mtdd::control::detail {

// Owns one Admission per accepted socket. Holds a bufferevent reference for the
// admission lifetime, enforces an absolute pre-request deadline, and releases
// capacity only when evhttp reports the connection closed (or after evhttp has
// cleared its callback argument). Not thread-safe; used only on the event loop
// thread except set_running/stop after the loop is joined.
class ConnectionGate {
 public:
  ConnectionGate(event_base* base, size_t max_connections,
                 std::chrono::milliseconds request_deadline);
  ~ConnectionGate();
  ConnectionGate(const ConnectionGate&) = delete;
  ConnectionGate& operator=(const ConnectionGate&) = delete;

  // Called from evhttp's bufferevent callback after accept().
  bufferevent* create();

  // Returns false when the connection is untracked or over the cap.
  bool note_request(evhttp_request* request);

  void set_listener(evconnlistener* listener, bool enabled);
  void set_running(bool running) noexcept;

  // Releases residual admissions; call after evhttp_free() and before
  // event_base_free(). Idempotent.
  void stop() noexcept;

  size_t tracked() const noexcept;

 private:
  struct Admission;

  void admit(bufferevent* bev);
  void release(Admission* admission) noexcept;
  void shutdown(Admission* admission) noexcept;
  void maybe_pause_listener();
  void maybe_resume_listener();

  static void on_closed(evhttp_connection* connection, void* arg);
  static void on_deadline(evutil_socket_t fd, short events, void* arg);
  static void on_reclaim(evutil_socket_t fd, short events, void* arg);
  static void on_install(evutil_socket_t fd, short events, void* arg);

  event_base* base_;
  size_t max_connections_;
  std::chrono::milliseconds request_deadline_;
  evconnlistener* listener_{nullptr};
  bool listener_enabled_{false};
  std::atomic<bool> running_{false};
  std::unordered_map<bufferevent*, std::unique_ptr<Admission>> admissions_;
};

}  // namespace mtdd::control::detail
