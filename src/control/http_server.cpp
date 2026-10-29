// Authenticated libevent/evhttp control API and Prometheus exporter.
//
// One event-loop thread, no detached threads or dangling callbacks. The server
// never owns the token: it is copied from HttpOptions and never logged.
#include <mtdd/control.hpp>

#include "connection_gate.hpp"
#include "http_internal.hpp"

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/event.h>
#include <event2/http.h>
#include <event2/keyvalq_struct.h>
#include <event2/listener.h>
#include <event2/thread.h>
#include <event2/util.h>

#include <sys/socket.h>
#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstring>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <utility>

#include <nlohmann/json.hpp>

namespace mtdd::control {
namespace {

using json = nlohmann::json;
using Clock = std::chrono::steady_clock;

using namespace detail;

std::once_flag g_evthread_once;
bool enable_evthread_once() {
  std::call_once(g_evthread_once, [] { evthread_use_pthreads(); });
  return true;
}

std::string percent_encode(std::string_view value) {
  constexpr char hex[] = "0123456789ABCDEF";
  std::string out;
  for (unsigned char c : value) {
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~') {
      out += static_cast<char>(c);
    } else {
      out += '%'; out += hex[c >> 4]; out += hex[c & 15];
    }
  }
  return out;
}

std::string hex_encode(std::string_view value) {
  constexpr char hex[] = "0123456789abcdef";
  std::string out;
  for (unsigned char c : value) { out += hex[c >> 4]; out += hex[c & 15]; }
  return out;
}

}  // namespace

struct ControlServer::Impl {
  Impl(UserStore& store_ref, Statistics& stats_ref, HttpOptions opts)
      : store(store_ref),
        stats(stats_ref),
        options(std::move(opts)),
        global_bucket(options.global_rate_limit_per_second,
                      options.global_rate_limit_burst),
        source_limits(options.rate_limit_sources,
                      options.rate_limit_per_second,
                      options.rate_limit_burst) {}

  UserStore& store;
  Statistics& stats;
  HttpOptions options;

  event_base* base{nullptr};
  evhttp* http{nullptr};
  evhttp_bound_socket* bound{nullptr};
  std::thread thread;
  std::atomic<bool> running{false};
  std::atomic<bool> loop_ready{false};
  uint16_t bound_port{0};
  evconnlistener* listener{nullptr};
  std::unique_ptr<detail::ConnectionGate> gate;
  detail::TokenBucket global_bucket;
  detail::SourceRateLimiter source_limits;
  std::vector<detail::IpNetwork> allow;

  struct ApiRecord {
    Impl* self;
    ApiRoute route;
    ApiMethod method;
    int* status;
    ~ApiRecord() { self->stats.api_request(route, method, *status); }
  };

  static void on_request_cb(evhttp_request* request, void* arg) {
    auto* self = static_cast<Impl*>(arg);
    try {
      self->handle_request(request);
    } catch (...) {
      if (evhttp_request_get_response_code(request) == 0) {
        detail::send_error(request, 500, "io_error", "internal error");
      }
    }
  }

  static bufferevent* on_bev_created(event_base* base_ref, void* arg) {
    auto* self = static_cast<Impl*>(arg);
    if (self->gate != nullptr) return self->gate->create();
    return bufferevent_socket_new(base_ref, -1, BEV_OPT_CLOSE_ON_FREE);
  }

  enum class Scope { none, admin, read, metrics };

  static bool bearer_matches(evhttp_request* request, std::string_view token) {
    if (token.empty()) return false;
    const char* header = evhttp_find_header(
        evhttp_request_get_input_headers(request), "Authorization");
    if (header == nullptr) return false;
    const std::string_view value(header);
    if (value.size() <= 7) return false;
    if (!ascii_iequals(value.substr(0, 6), "bearer")) return false;
    if (value[6] != ' ') return false;
    return constant_time_equal(value.substr(7), token);
  }

  Scope authorize(evhttp_request* request) const {
    if (options.role == HttpRole::metrics) {
      if (options.metrics_token.empty()) return Scope::metrics;
      return bearer_matches(request, options.metrics_token) ? Scope::metrics
                                                            : Scope::none;
    }
    if (bearer_matches(request, options.bearer_token)) return Scope::admin;
    if (bearer_matches(request, options.read_token)) return Scope::read;
    return Scope::none;
  }

  // Read tokens observe; anything that mutates or reveals a secret (links)
  // or the legacy exporter alias stays admin-only.
  static bool read_scope_allows(ApiRoute route, ApiMethod method) {
    return method == ApiMethod::get && route != ApiRoute::user_links &&
           route != ApiRoute::metrics;
  }

  void send_mutation(evhttp_request* request, const MutationOutcome& outcome,
                     int success_status, bool include_secret) {
    const StatisticsSnapshot snapshot = stats.snapshot();
    json data;
    data["revision"] = outcome.revision;
    data["applied"] = outcome.applied;
    if (outcome.pending) data["pending"] = true;
    if (outcome.deleted) {
      data["deleted"] = true;
      data["name"] = outcome.user.name;
    } else {
      data["user"] = user_json(outcome.user, snapshot);
    }
    if (include_secret && outcome.secret_once) {
      data["secret"] = *outcome.secret_once;
    }
    const int status = outcome.pending ? 202 : success_status;
    send_json(request, status, json{{"data", std::move(data)}},
              outcome.revision);
  }

  bool validate_name(evhttp_request* request, const std::string& name) {
    if (UserStore::is_valid_name(name)) return true;
    send_error(request, 400, "invalid_name",
               "name must match [A-Za-z0-9_.-]{1,64}");
    return false;
  }

  void handle_request(evhttp_request* request) {
    const RouteInfo route = classify_route(request);
    const ApiMethod method = parse_method(request);
    int status = 500;
    ApiRecord record{this, route.route, method, &status};
    const bool admitted = gate != nullptr && gate->note_request(request);

    const auto now = Clock::now();
    const bool global_ok = global_bucket.allow(now);
    const bool source_ok =
        source_limits.allow(detail::peer_key(request), now);
    if (!global_ok || !source_ok) {
      status = 429;
      evhttp_add_header(evhttp_request_get_output_headers(request),
                        "Retry-After", "1");
      send_error(request, 429, "rate_limited",
                 "request rate limit exceeded");
      return;
    }

    if (!source_allowed(allow, request)) {
      status = 403;
      send_error(request, 403, "forbidden",
                 "source address is not in the allowlist");
      return;
    }

    const Scope scope = authorize(request);
    if (scope == Scope::none) {
      status = 401;
      evhttp_add_header(evhttp_request_get_output_headers(request),
                        "WWW-Authenticate", "Bearer realm=\"mtdd\"");
      send_error(request, 401, "unauthorized",
                 "missing or invalid bearer token");
      return;
    }

    if (!admitted) {
      status = 503;
      send_error(request, 503, "overloaded",
                 "connection is over the control-plane admission cap");
      return;
    }

    if (route.route == ApiRoute::unknown ||
        (scope == Scope::metrics && route.route != ApiRoute::metrics)) {
      status = 404;
      send_error(request, 404, "not_found", "route not found");
      return;
    }
    if (!method_allowed(route.route, method)) {
      status = 405;
      send_error(request, 405, "method_not_allowed",
                 "method not allowed for this route");
      return;
    }

    if (scope == Scope::read && !read_scope_allows(route.route, method)) {
      status = 403;
      send_error(request, 403, "forbidden_scope",
                 "read-only token cannot use this route or method");
      return;
    }
    if (route.route == ApiRoute::metrics && scope == Scope::admin) {
      // Served on the API port for one more release; scrape metrics_port.
      evhttp_add_header(evhttp_request_get_output_headers(request),
                        "Deprecation", "true");
    }

    switch (route.route) {
      case ApiRoute::health: handle_health(request, status); break;
      case ApiRoute::ready: handle_ready(request, status); break;
      case ApiRoute::status: handle_status(request, status); break;
      case ApiRoute::users: handle_users(request, method, status); break;
      case ApiRoute::user: handle_user(request, method, route.name, status); break;
      case ApiRoute::user_links: handle_links(request, route.name, status); break;
      case ApiRoute::rotate_secret:
        handle_rotate(request, route.name, status);
        break;
      case ApiRoute::metrics: handle_metrics(request, status); break;
      case ApiRoute::unknown: break;
    }
  }

  void sync_user_metrics() {
    const auto users = store.snapshot();
    for (const auto& user : users->users) {
      stats.user(user.name);
    }
  }

  void handle_health(evhttp_request* request, int& status) {
    const auto snapshot = store.snapshot();
    status = 200;
    send_json(request, status,
              json{{"data", {{"status", "ok"},
                             {"revision", snapshot->revision}}}},
              snapshot->revision);
  }

  void handle_ready(evhttp_request* request, int& status) {
    const auto snapshot = store.snapshot();
    const bool ready = stats.ready();
    status = ready ? 200 : 503;
    send_json(request, status,
              json{{"data", {{"ready", ready},
                             {"revision", snapshot->revision}}}},
              snapshot->revision);
  }

  void handle_status(evhttp_request* request, int& status) {
    const auto users = store.snapshot();
    const StatisticsSnapshot snapshot = stats.snapshot();
    size_t enabled = 0;
    for (const auto& user : users->users) {
      if (user.enabled) ++enabled;
    }
    uint64_t handshakes_total = 0;
    for (const auto& [result, value] : snapshot.handshakes_by_result) {
      (void)result;
      handshakes_total += value;
    }
    uint64_t me_requests = 0;
    uint64_t me_reconnects = 0;
    size_t me_connected = 0;
    for (const auto& [label, dc] : snapshot.me_dcs) {
      (void)label;
      if (dc.connected) ++me_connected;
      me_requests += dc.requests_success + dc.requests_failure +
                     dc.requests_timeout;
      me_reconnects += dc.reconnects_total;
    }
    json me_dcs = json::array();
    for (const auto& [label, dc] : snapshot.me_dcs) {
      me_dcs.push_back(
          {{"dc", label},
           {"connected", dc.connected},
           {"reactors_connected", dc.reactors_connected},
           {"ready_reactors", dc.reactors_connected},           {"reconnects_total", dc.reconnects_total},
           {"connections", dc.connections},
           {"ready_connections", dc.ready_connections},
           {"pool_target", dc.pool_target},
           {"bound_clients", dc.bound_clients},
           {"scale_up_total", dc.scale_up_total},
           {"scale_down_total", dc.scale_down_total},
           {"creation_failures_total", dc.creation_failures_total},
           {"ping_rtt_us", dc.ping_rtt_us},
           {"pings_sent_total", dc.pings_sent_total},
           {"pongs_received_total", dc.pongs_received_total},
           {"ping_timeouts_total", dc.ping_timeouts_total},
           {"ping_stalls_total", dc.ping_stalls_total},
           {"control_close_conn_total", dc.control_close_conn},
           {"control_close_ext_total", dc.control_close_ext},
           {"control_unknown_total", dc.control_unknown},
           {"control_malformed_total", dc.control_malformed},
           {"ready_queue_depth", dc.ready_queue_depth},
           {"ready_queue_clients", dc.ready_queue_clients},
           {"frames_queued_bytes", dc.frames_queued_bytes},
           {"out_queued_bytes", dc.out_queued_bytes},
           {"proxy_ans_received_total", dc.proxy_ans_received_total},
           {"proxy_ans_delivered_total", dc.proxy_ans_delivered_total},
           {"proxy_ans_dropped_unknown_total",
            dc.proxy_ans_dropped_unknown_total},
           {"proxy_ans_dropped_other_total",
            dc.proxy_ans_dropped_other_total},
           {"last_proxy_ans_age_seconds", dc.last_proxy_ans_age_seconds},
           {"direct_active", dc.direct_active},
           {"direct_accepted_total", dc.direct_accepted_total},
           {"direct_connect_fail_total", dc.direct_connect_fail_total},
           {"direct_rx_bytes_total", dc.direct_rx_bytes_total},
           {"direct_tx_bytes_total", dc.direct_tx_bytes_total},
           {"direct_budget_pauses_total", dc.direct_budget_pauses_total},
           {"rx_bytes_total", dc.rx_bytes_total},
           {"tx_bytes_total", dc.tx_bytes_total}});
    }
    json data;
    data["revision"] = users->revision;
    data["ready"] = snapshot.ready;
    data["uptime_seconds"] = snapshot.uptime_seconds;
    data["users_total"] = users->users.size();
    data["users_enabled"] = enabled;
    data["connections_active"] = snapshot.connections_active;
    data["unique_ips_active"] = snapshot.active_unique_ips;
    const auto& history = snapshot.unique_ip_history;
    data["unique_ip_history"] = {
        {"hour", {{"estimate", history.hour},
                  {"started_at", history.hour_started_at}}},
        {"day", {{"estimate", history.day},
                 {"started_at", history.day_started_at}}},
        {"week", {{"estimate", history.week},
                  {"started_at", history.week_started_at}}},
        {"collection_started_at", history.collection_started_at},
        {"approximate", true},
        {"relative_standard_error", 0.0325},
        {"timezone", "UTC"},
        {"week_starts", "Monday"},
        {"persistence_enabled", history.persistence_enabled},
        {"persistence_failures", history.persistence_failures},
        {"observation_failures", snapshot.ip_history_observation_failures}};
    data["connections_accepted_total"] = snapshot.connections_accepted_total;
    data["connections_rejected_total"] = snapshot.connections_rejected_total;
    data["handshakes_total"] = handshakes_total;
    data["api_requests_total"] = snapshot.api_requests_total;
    data["buffer_bytes"] = {{"queued", snapshot.buffer_bytes[0]},
                            {"pending_write", snapshot.buffer_bytes[1]},
                            {"relay", snapshot.buffer_bytes[2]}};
    data["backpressure_events_total"] = {
        {"c2s", snapshot.backpressure_c2s_total},
        {"s2c", snapshot.backpressure_s2c_total}};
    data["replay_cache_entries"] = snapshot.replay_cache_entries;
    data["build"] = {{"version", snapshot.build_version}};
    data["me"] = {{"connected_dcs", me_connected},
                  {"pending_buffer_bytes", snapshot.me_pending_buffer_bytes},
                  {"requests_total", me_requests},
                  {"reconnects_total", me_reconnects},
                  {"dcs", std::move(me_dcs)}};
    status = 200;
    send_json(request, status, json{{"data", std::move(data)}},
              users->revision);
  }

  void handle_metrics(evhttp_request* request, int& status) {
    status = 200;
    send_text(request, status, stats.prometheus_text(),
              "text/plain; version=0.0.4; charset=utf-8",
              store.snapshot()->revision);
  }

  void handle_users(evhttp_request* request, ApiMethod method, int& status) {
    if (method == ApiMethod::get) {
      const auto users = store.snapshot();
      const StatisticsSnapshot snapshot = stats.snapshot();
      json array = json::array();
      for (const auto& user : users->users) {
        array.push_back(user_json(user, snapshot));
      }
      status = 200;
      send_json(request, status,
                json{{"data", {{"revision", users->revision},
                               {"ready", snapshot.ready},
                               {"uptime_seconds", snapshot.uptime_seconds},
                               {"users", std::move(array)}}}},
                users->revision);
      return;
    }

    // POST /v1/users
    BodyRead body = read_body(request, options.max_body_bytes, false);
    if (body.error) {
      status = body.error->status;
      send_error(request, status, body.error->type, body.error->message);
      return;
    }
    if (auto error =
            check_allowed_fields(body.value,
                                 {"name", "secret", "enabled", "max_connections"})) {
      status = error->status;
      send_error(request, status, error->type, error->message);
      return;
    }
    CreateUserRequest create;
    if (!body.value.contains("name")) {
      status = 400;
      send_error(request, status, "invalid_name", "name is required");
      return;
    }
    if (!body.value["name"].is_string()) {
      status = 400;
      send_error(request, status, "invalid_field", "name must be a string");
      return;
    }
    create.name = body.value["name"].get<std::string>();
    if (body.value.contains("secret")) {
      if (!body.value["secret"].is_string()) {
        status = 400;
        send_error(request, status, "invalid_field", "secret must be a string");
        return;
      }
      create.secret = body.value["secret"].get<std::string>();
    }
    if (body.value.contains("enabled")) {
      if (!body.value["enabled"].is_boolean()) {
        status = 400;
        send_error(request, status, "invalid_field",
                   "enabled must be a boolean");
        return;
      }
      create.enabled = body.value["enabled"].get<bool>();
    }
    if (body.value.contains("max_connections")) {
      if (auto error =
              parse_max_connections(body.value["max_connections"],
                                    create.max_connections)) {
        status = error->status;
        send_error(request, status, error->type, error->message);
        return;
      }
    }
    if (auto error = parse_if_match(request, create.if_match)) {
      status = error->status;
      send_error(request, status, error->type, error->message);
      return;
    }

    auto outcome = store.create_user(create);
    if (!outcome.ok()) {
      send_store_error(request, outcome.error());
      status = map_store_error(outcome.error()).status;
      return;
    }
    stats.user(outcome.value().user.name);
    send_mutation(request, outcome.value(), 201, true);
    status = outcome.value().pending ? 202 : 201;
  }

  void handle_user(evhttp_request* request, ApiMethod method,
                   const std::string& name, int& status) {
    if (!validate_name(request, name)) {
      status = 400;
      return;
    }
    if (method == ApiMethod::get) {
      const auto users = store.snapshot();
      const UserRecord* user = users->find(name);
      if (user == nullptr) {
        status = 404;
        send_error(request, status, "not_found", "user '" + name + "' not found",
                   users->revision);
        return;
      }
      const StatisticsSnapshot snapshot = stats.snapshot();
      status = 200;
      send_json(request, status,
                json{{"data", {{"revision", users->revision},
                               {"ready", snapshot.ready},
                               {"uptime_seconds", snapshot.uptime_seconds},
                               {"user", user_json(*user, snapshot)}}}},
                users->revision);
      return;
    }
    if (method == ApiMethod::patch) {
      BodyRead body = read_body(request, options.max_body_bytes, false);
      if (body.error) {
        status = body.error->status;
        send_error(request, status, body.error->type, body.error->message);
        return;
      }
      if (auto error = check_allowed_fields(body.value,
                                            {"enabled", "max_connections"})) {
        status = error->status;
        send_error(request, status, error->type, error->message);
        return;
      }
      UpdateUserRequest update;
      update.name = name;
      bool any = false;
      if (body.value.contains("enabled")) {
        if (!body.value["enabled"].is_boolean()) {
          status = 400;
          send_error(request, status, "invalid_field",
                     "enabled must be a boolean");
          return;
        }
        update.enabled = body.value["enabled"].get<bool>();
        any = true;
      }
      if (body.value.contains("max_connections")) {
        if (auto error =
                parse_max_connections(body.value["max_connections"],
                                      update.max_connections)) {
          status = error->status;
          send_error(request, status, error->type, error->message);
          return;
        }
        update.set_max_connections = true;
        any = true;
      }
      if (!any) {
        status = 400;
        send_error(request, status, "invalid_request",
                   "patch requires enabled or max_connections");
        return;
      }
      if (auto error = parse_if_match(request, update.if_match)) {
        status = error->status;
        send_error(request, status, error->type, error->message);
        return;
      }
      auto outcome = store.update_user(update);
      if (!outcome.ok()) {
        send_store_error(request, outcome.error());
        status = map_store_error(outcome.error()).status;
        return;
      }
      stats.user(outcome.value().user.name);
      send_mutation(request, outcome.value(), 200, false);
      status = outcome.value().pending ? 202 : 200;
      return;
    }

    // DELETE
    DeleteUserRequest remove;
    remove.name = name;
    if (auto error = parse_if_match(request, remove.if_match)) {
      status = error->status;
      send_error(request, status, error->type, error->message);
      return;
    }
    auto outcome = store.delete_user(remove);
    if (!outcome.ok()) {
      send_store_error(request, outcome.error());
      status = map_store_error(outcome.error()).status;
      return;
    }
    stats.forget_user(outcome.value().user.name);
    send_mutation(request, outcome.value(), 200, false);
    status = outcome.value().pending ? 202 : 200;
  }

  void handle_links(evhttp_request* request, const std::string& name, int& status) {
    if (!validate_name(request, name)) { status = 400; return; }
    const auto users = store.snapshot();
    const auto* user = users->find(name);
    if (!user) {
      status = 404;
      send_error(request, status, "not_found", "user not found", users->revision);
      return;
    }
    if (options.public_host.empty() || options.public_port == 0 || options.tls_domain.empty()) {
      status = 503;
      send_error(request, status, "public_address_unconfigured", "configure public_host to generate links");
      return;
    }
    const std::string query = "server=" + percent_encode(options.public_host) +
        "&port=" + std::to_string(options.public_port) + "&secret=ee" +
        user->secret_hex + hex_encode(options.tls_domain);
    status = 200;
    send_json(request, status, json{{"data", {{"name", user->name}, {"enabled", user->enabled},
        {"links", {{"telegram", "https://t.me/proxy?" + query}, {"native", "tg://proxy?" + query}}}}}}, users->revision);
  }

  void handle_rotate(evhttp_request* request, const std::string& name,
                     int& status) {
    if (!validate_name(request, name)) {
      status = 400;
      return;
    }
    BodyRead body = read_body(request, options.max_body_bytes, true);
    if (body.error) {
      status = body.error->status;
      send_error(request, status, body.error->type, body.error->message);
      return;
    }
    if (auto error = check_allowed_fields(body.value, {"secret"})) {
      status = error->status;
      send_error(request, status, error->type, error->message);
      return;
    }
    RotateSecretRequest rotate;
    rotate.name = name;
    if (body.value.contains("secret")) {
      if (!body.value["secret"].is_string()) {
        status = 400;
        send_error(request, status, "invalid_field", "secret must be a string");
        return;
      }
      rotate.secret = body.value["secret"].get<std::string>();
    }
    if (auto error = parse_if_match(request, rotate.if_match)) {
      status = error->status;
      send_error(request, status, error->type, error->message);
      return;
    }
    auto outcome = store.rotate_secret(rotate);
    if (!outcome.ok()) {
      send_store_error(request, outcome.error());
      status = map_store_error(outcome.error()).status;
      return;
    }
    stats.user(outcome.value().user.name);
    send_mutation(request, outcome.value(), 200, true);
    status = outcome.value().pending ? 202 : 200;
  }

  static std::optional<Error> validate_token(std::string_view name,
                                            std::string_view token) {
    if (token.size() > 512) {
      return Error{ErrorCode::invalid_config, std::string(name) + " is too long"};
    }
    for (char c : token) {
      if (std::isspace(static_cast<unsigned char>(c)) || c == '\0') {
        return Error{ErrorCode::invalid_config,
                     std::string(name) + " must not contain whitespace or NUL"};
      }
    }
    return std::nullopt;
  }

  std::optional<Error> validate_tokens() const {
    if (options.role == HttpRole::metrics) {
      return validate_token("metrics_token", options.metrics_token);
    }
    if (options.bearer_token.empty()) {
      return Error{ErrorCode::invalid_config,
                   "bearer_token is required; never run unauthenticated"};
    }
    if (auto invalid = validate_token("bearer_token", options.bearer_token)) {
      return invalid;
    }
    if (auto invalid = validate_token("read_token", options.read_token)) {
      return invalid;
    }
    if (!options.read_token.empty() &&
        constant_time_equal(options.read_token, options.bearer_token)) {
      return Error{ErrorCode::invalid_config,
                   "read_token must differ from bearer_token"};
    }
    return std::nullopt;
  }

  Result<uint16_t> start() {
    if (running.load(std::memory_order_acquire)) {
      return Error{ErrorCode::invalid_config, "server is already running"};
    }
    if (auto invalid = validate_tokens()) return *invalid;
    allow.clear();
    for (const auto& entry : options.allow_networks) {
      auto network = parse_ip_network(entry);
      if (!network) {
        return Error{ErrorCode::invalid_config,
                     "invalid allow_networks entry: " + entry};
      }
      allow.push_back(*network);
    }
    if (options.role == HttpRole::metrics && options.metrics_token.empty() &&
        allow.empty()) {
      return Error{ErrorCode::invalid_config,
                   "metrics listener needs metrics_token or allow_networks"};
    }
    if (options.bind_address.empty() || options.bind_address.size() > 128) {
      return Error{ErrorCode::invalid_config, "invalid bind_address"};
    }
    if (options.max_connections == 0 || options.max_connections > 4096) {
      return Error{ErrorCode::invalid_config,
                   "max_connections must be within 1..4096"};
    }
    if (options.max_body_bytes == 0 || options.max_body_bytes > 4 * 1024 * 1024) {
      return Error{ErrorCode::invalid_config,
                   "max_body_bytes must be within 1..4194304"};
    }
    if (options.max_header_bytes == 0 ||
        options.max_header_bytes > 256 * 1024) {
      return Error{ErrorCode::invalid_config,
                   "max_header_bytes must be within 1..262144"};
    }
    if (options.request_deadline.count() <= 0 ||
        options.request_deadline.count() > 3600000) {
      return Error{ErrorCode::invalid_config,
                   "request_deadline must be within 1ms..1h"};
    }
    if (!(options.rate_limit_per_second > 0.0) ||
        !std::isfinite(options.rate_limit_per_second) ||
        !(options.rate_limit_burst >= 1.0) ||
        !std::isfinite(options.rate_limit_burst) ||
        !(options.global_rate_limit_per_second > 0.0) ||
        !std::isfinite(options.global_rate_limit_per_second) ||
        !(options.global_rate_limit_burst >= 1.0) ||
        !std::isfinite(options.global_rate_limit_burst) ||
        options.rate_limit_sources == 0 || options.rate_limit_sources > 4096) {
      return Error{ErrorCode::invalid_config, "invalid rate limit options"};
    }

    enable_evthread_once();
    base = event_base_new();
    if (base == nullptr) {
      return Error{ErrorCode::io_error, "event_base_new failed"};
    }
    http = evhttp_new(base);
    if (http == nullptr) {
      event_base_free(base);
      base = nullptr;
      return Error{ErrorCode::io_error, "evhttp_new failed"};
    }
    evhttp_set_allowed_methods(
        http, EVHTTP_REQ_GET | EVHTTP_REQ_POST | EVHTTP_REQ_PATCH |
                  EVHTTP_REQ_DELETE | EVHTTP_REQ_PUT);
    evhttp_set_gencb(http, &Impl::on_request_cb, this);
    evhttp_set_bevcb(http, &Impl::on_bev_created, this);
    evhttp_set_max_headers_size(http,
                                static_cast<ev_ssize_t>(options.max_header_bytes));
    // Keep a small slack above the logical JSON limit so read_body() can return
    // a structured 413 for ordinary oversized requests; libevent still enforces
    // a hard bound (and may answer grossly oversized bodies itself with HTML).
    const size_t libevent_body_cap =
        std::min<size_t>(options.max_body_bytes + 4096, 4u * 1024 * 1024);
    evhttp_set_max_body_size(http,
                             static_cast<ev_ssize_t>(libevent_body_cap));
    const timeval timeout {
        static_cast<time_t>(options.request_deadline.count() / 1000),
        static_cast<suseconds_t>((options.request_deadline.count() % 1000) * 1000)};
    evhttp_set_timeout_tv(http, &timeout);

    bound = evhttp_bind_socket_with_handle(
        http, options.bind_address.c_str(), options.port);
    if (bound == nullptr) {
      evhttp_free(http);
      http = nullptr;
      event_base_free(base);
      base = nullptr;
      return Error{ErrorCode::bind_failed,
                   "could not bind " + options.bind_address + ":" +
                       std::to_string(options.port)};
    }
    bound_port = options.port;
    listener = evhttp_bound_socket_get_listener(bound);
    gate = std::make_unique<detail::ConnectionGate>(
        base, options.max_connections, options.request_deadline);
    gate->set_listener(listener, true);
    gate->set_running(true);
    const evutil_socket_t fd = evhttp_bound_socket_get_fd(bound);
    if (fd >= 0) {
      // Limit the kernel accept queue to the connection cap so a burst cannot
      // queue far more completed handshakes than we admit.
      (void)::listen(fd, static_cast<int>(options.max_connections));
      sockaddr_storage storage {};
      socklen_t length = sizeof(storage);
      if (getsockname(fd, reinterpret_cast<sockaddr*>(&storage), &length) == 0) {
        if (storage.ss_family == AF_INET) {
          bound_port = ntohs(reinterpret_cast<sockaddr_in*>(&storage)->sin_port);
        } else if (storage.ss_family == AF_INET6) {
          bound_port =
              ntohs(reinterpret_cast<sockaddr_in6*>(&storage)->sin6_port);
        }
      }
    }

    loop_ready.store(false, std::memory_order_release);
    const timeval immediate {0, 0};
    event_base_once(
        base, -1, EV_TIMEOUT,
        [](evutil_socket_t, short, void* arg) {
          static_cast<Impl*>(arg)->loop_ready.store(true,
                                                    std::memory_order_release);
        },
        this, &immediate);
    running.store(true, std::memory_order_release);
    try {
      thread = std::thread([this] {
        event_base_dispatch(base);
        running.store(false, std::memory_order_release);
      });
    } catch (...) {
      stop();
      return Error{ErrorCode::io_error, "could not start control event thread"};
    }
    // Ensure loopbreak() from another thread is never lost before dispatch.
    for (int attempt = 0; attempt < 2000; ++attempt) {
      if (loop_ready.load(std::memory_order_acquire)) break;
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    if (!loop_ready.load(std::memory_order_acquire)) {
      stop();
      return Error{ErrorCode::io_error, "event loop failed to start"};
    }
    sync_user_metrics();
    return bound_port;
  }

  void stop() noexcept {
    const bool was_running = running.exchange(false, std::memory_order_acq_rel);
    if (gate != nullptr) gate->set_running(false);
    if (base != nullptr) {
      event_base_loopbreak(base);
    }
    if (thread.joinable()) thread.join();
    if (gate != nullptr) gate->set_listener(nullptr, false);
    listener = nullptr;
    if (http != nullptr) {
      evhttp_free(http);
      http = nullptr;
    }
    // Destructor releases residual admissions (and their fd refs) before the
    // event base is freed. evhttp-free close callbacks may already have done so.
    gate.reset();
    if (base != nullptr) {
      event_base_free(base);
      base = nullptr;
    }
    bound = nullptr;
    (void)was_running;
  }

  ~Impl() { stop(); }
};

ControlServer::ControlServer(UserStore& store, Statistics& stats,
                             HttpOptions options)
    : impl_(std::make_unique<Impl>(store, stats, std::move(options))) {}

ControlServer::~ControlServer() = default;

Result<uint16_t> ControlServer::start() { return impl_->start(); }
void ControlServer::stop() noexcept { impl_->stop(); }
bool ControlServer::running() const noexcept {
  return impl_->running.load(std::memory_order_acquire);
}
uint16_t ControlServer::port() const noexcept { return impl_->bound_port; }

}  // namespace mtdd::control
