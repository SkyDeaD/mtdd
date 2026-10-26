#include "connection_gate.hpp"

#include <event2/bufferevent.h>
#include <event2/event.h>
#include <event2/http.h>
#include <event2/listener.h>

#include <sys/socket.h>

#include <chrono>
#include <memory>
#include <unordered_map>
#include <utility>
#include <vector>

namespace mtdd::control::detail {
namespace {

timeval to_timeval(std::chrono::milliseconds value) {
  if (value.count() < 0) value = std::chrono::milliseconds(0);
  timeval tv{};
  tv.tv_sec = static_cast<time_t>(value.count() / 1000);
  tv.tv_usec = static_cast<suseconds_t>((value.count() % 1000) * 1000);
  return tv;
}

}  // namespace

struct ConnectionGate::Admission {
  ConnectionGate* owner{nullptr};
  bufferevent* bev{nullptr};
  event* deadline{nullptr};
  event* install{nullptr};
  event* reclaim{nullptr};
  bool first_request{false};
  bool over_cap{false};
  bool released{false};
  // Set when the absolute deadline could not be armed. on_install then shuts
  // the connection down immediately instead of admitting it under a weaker
  // inactivity timeout.
  bool deadline_missing{false};
};

ConnectionGate::ConnectionGate(event_base* base, size_t max_connections,
                               std::chrono::milliseconds request_deadline)
    : base_(base),
      max_connections_(max_connections),
      request_deadline_(request_deadline) {}

ConnectionGate::~ConnectionGate() { stop(); }

size_t ConnectionGate::tracked() const noexcept { return admissions_.size(); }

void ConnectionGate::set_listener(evconnlistener* listener, bool enabled) {
  listener_ = listener;
  listener_enabled_ = enabled;
}

void ConnectionGate::set_running(bool running) noexcept {
  running_.store(running, std::memory_order_release);
}

bufferevent* ConnectionGate::create() {
  bufferevent* bev =
      bufferevent_socket_new(base_, -1, BEV_OPT_CLOSE_ON_FREE);
  if (bev == nullptr) return nullptr;
  admit(bev);
  return bev;
}

void ConnectionGate::admit(bufferevent* bev) {
  // Our reference outlives evhttp's; the fd is closed only after both drop it.
  bufferevent_incref(bev);
  auto admission = std::make_unique<Admission>();
  admission->owner = this;
  admission->bev = bev;
  admission->over_cap = admissions_.size() >= max_connections_;
  Admission* raw = admission.get();
  admissions_.emplace(bev, std::move(admission));

  raw->deadline = evtimer_new(base_, &ConnectionGate::on_deadline, raw);
  if (raw->deadline != nullptr) {
    const auto delay = raw->over_cap ? std::chrono::milliseconds(0)
                                     : request_deadline_;
    const timeval timer = to_timeval(delay);
    if (evtimer_add(raw->deadline, &timer) != 0) {
      event_free(raw->deadline);
      raw->deadline = nullptr;
    }
  }
  if (raw->deadline == nullptr) raw->deadline_missing = true;

  // Owned zero-time install event (not event_base_once), so release() can
  // always cancel it before deleting the Admission that its argument points to.
  raw->install = evtimer_new(base_, &ConnectionGate::on_install, raw);
  if (raw->install != nullptr) {
    const timeval immediate{0, 0};
    if (evtimer_add(raw->install, &immediate) != 0) {
      event_free(raw->install);
      raw->install = nullptr;
    }
  }
  maybe_pause_listener();
}

void ConnectionGate::maybe_pause_listener() {
  if (listener_ != nullptr && listener_enabled_ &&
      admissions_.size() >= max_connections_) {
    evconnlistener_disable(listener_);
    listener_enabled_ = false;
  }
}

void ConnectionGate::maybe_resume_listener() {
  if (!running_.load(std::memory_order_acquire)) return;
  if (listener_ != nullptr && !listener_enabled_ &&
      admissions_.size() < max_connections_) {
    evconnlistener_enable(listener_);
    listener_enabled_ = true;
  }
}

bool ConnectionGate::note_request(evhttp_request* request) {
  evhttp_connection* connection = evhttp_request_get_connection(request);
  if (connection == nullptr) return false;
  bufferevent* bev = evhttp_connection_get_bufferevent(connection);
  const auto found = admissions_.find(bev);
  if (found == admissions_.end() || found->second->released) return false;
  Admission* admission = found->second.get();
  if (admission->over_cap) return false;
  admission->first_request = true;
  if (admission->deadline != nullptr) evtimer_del(admission->deadline);
  evhttp_connection_set_closecb(connection, &ConnectionGate::on_closed,
                                admission);
  return true;
}

void ConnectionGate::release(Admission* admission) noexcept {
  if (admission == nullptr || admission->released) return;
  admission->released = true;
  bufferevent* bev = admission->bev;
  if (admission->install != nullptr) {
    evtimer_del(admission->install);
    event_free(admission->install);
    admission->install = nullptr;
  }
  if (admission->deadline != nullptr) {
    evtimer_del(admission->deadline);
    event_free(admission->deadline);
    admission->deadline = nullptr;
  }
  if (admission->reclaim != nullptr) {
    evtimer_del(admission->reclaim);
    event_free(admission->reclaim);
    admission->reclaim = nullptr;
  }
  admissions_.erase(bev);   // deletes admission
  bufferevent_decref(bev);  // final ref closes the fd
  maybe_resume_listener();
}

void ConnectionGate::shutdown(Admission* admission) noexcept {
  if (admission == nullptr || admission->released) return;
  const evutil_socket_t fd = bufferevent_getfd(admission->bev);
  if (fd >= 0) ::shutdown(fd, SHUT_RDWR);
  if (admission->reclaim == nullptr) {
    admission->reclaim = evtimer_new(base_, &ConnectionGate::on_reclaim,
                                     admission);
    if (admission->reclaim != nullptr) {
      const timeval retry = to_timeval(std::chrono::milliseconds(250));
      evtimer_add(admission->reclaim, &retry);
    }
  }
}

void ConnectionGate::on_closed(evhttp_connection*, void* arg) {
  auto* admission = static_cast<Admission*>(arg);
  admission->owner->release(admission);
}

void ConnectionGate::on_deadline(evutil_socket_t, short, void* arg) {
  auto* admission = static_cast<Admission*>(arg);
  if (admission->released) return;
  // Absolute pre-request deadline: dribbling cannot extend it. Over-cap
  // admissions are terminated even if a request raced in.
  if (admission->first_request && !admission->over_cap) return;
  admission->owner->shutdown(admission);
}

void ConnectionGate::on_reclaim(evutil_socket_t, short, void* arg) {
  auto* admission = static_cast<Admission*>(arg);
  if (admission->released) return;
  void* cbarg = nullptr;
  bufferevent_getcb(admission->bev, nullptr, nullptr, nullptr, &cbarg);
  if (cbarg == nullptr) {
    // evhttp released the connection; drop our reference so the fd closes.
    admission->owner->release(admission);
    return;
  }
  const evutil_socket_t fd = bufferevent_getfd(admission->bev);
  if (fd >= 0) ::shutdown(fd, SHUT_RDWR);
  const timeval retry = to_timeval(std::chrono::milliseconds(250));
  evtimer_add(admission->reclaim, &retry);
}

void ConnectionGate::on_install(evutil_socket_t, short, void* arg) {
  auto* admission = static_cast<Admission*>(arg);
  if (admission->released) return;
  void* cbarg = nullptr;
  bufferevent_getcb(admission->bev, nullptr, nullptr, nullptr, &cbarg);
  if (cbarg == nullptr) {
    const evutil_socket_t fd = bufferevent_getfd(admission->bev);
    if (fd >= 0) ::shutdown(fd, SHUT_RDWR);
    admission->owner->release(admission);
    return;
  }
  // evhttp's connection is the callback argument. Close notifications cover
  // pre-request evhttp timeouts and request-bearing connections alike.
  auto* connection = static_cast<evhttp_connection*>(cbarg);
  evhttp_connection_set_closecb(connection, &ConnectionGate::on_closed,
                                admission);
  // Allocation/add failure of the absolute deadline must fail closed: install
  // succeeded, so close immediately rather than fall back to the dribbleable
  // inactivity timeout. Over-cap admissions are always terminated.
  if (admission->over_cap || admission->deadline_missing) {
    admission->owner->shutdown(admission);
  }
}

void ConnectionGate::stop() noexcept {
  std::vector<bufferevent*> leftover;
  leftover.reserve(admissions_.size());
  for (const auto& entry : admissions_) leftover.push_back(entry.first);
  for (bufferevent* bev : leftover) {
    const auto found = admissions_.find(bev);
    if (found != admissions_.end()) release(found->second.get());
  }
}

}  // namespace mtdd::control::detail
