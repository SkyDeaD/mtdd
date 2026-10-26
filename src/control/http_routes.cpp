#include "http_internal.hpp"

#include <event2/buffer.h>
#include <event2/http.h>
#include <event2/keyvalq_struct.h>
#include <openssl/crypto.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <string>
#include <utility>

namespace mtdd::control::detail {

std::string trim_copy(std::string_view value) {
  size_t begin = 0;
  size_t end = value.size();
  while (begin < end &&
         (value[begin] == ' ' || value[begin] == '\t' || value[begin] == '\r' ||
          value[begin] == '\n')) {
    ++begin;
  }
  while (end > begin &&
         (value[end - 1] == ' ' || value[end - 1] == '\t' ||
          value[end - 1] == '\r' || value[end - 1] == '\n')) {
    --end;
  }
  return std::string(value.substr(begin, end - begin));
}

bool ascii_iequals(std::string_view a, std::string_view b) {
  if (a.size() != b.size()) return false;
  for (size_t i = 0; i < a.size(); ++i) {
    if (std::tolower(static_cast<unsigned char>(a[i])) !=
        std::tolower(static_cast<unsigned char>(b[i]))) {
      return false;
    }
  }
  return true;
}

bool constant_time_equal(std::string_view a, std::string_view b) noexcept {
  if (a.size() != b.size()) return false;
  return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

ApiMethod parse_method(evhttp_request* request) {
  switch (evhttp_request_get_command(request)) {
    case EVHTTP_REQ_GET: return ApiMethod::get;
    case EVHTTP_REQ_POST: return ApiMethod::post;
    case EVHTTP_REQ_PATCH: return ApiMethod::patch;
    case EVHTTP_REQ_DELETE: return ApiMethod::delete_;
    default: return ApiMethod::other;
  }
}

RouteInfo classify_route(evhttp_request* request) {
  RouteInfo info;
  const char* uri = evhttp_request_get_uri(request);
  if (uri == nullptr || std::strlen(uri) > 2048) return info;
  evhttp_uri* parsed = evhttp_uri_parse(uri);
  if (parsed == nullptr) return info;
  const char* raw_path = evhttp_uri_get_path(parsed);
  const std::string path = raw_path != nullptr ? raw_path : "";
  evhttp_uri_free(parsed);
  if (path.empty()) return info;

  if (path == "/v1/health") {
    info.route = ApiRoute::health;
    return info;
  }
  if (path == "/v1/ready") {
    info.route = ApiRoute::ready;
    return info;
  }
  if (path == "/v1/status") {
    info.route = ApiRoute::status;
    return info;
  }
  if (path == "/v1/users") {
    info.route = ApiRoute::users;
    return info;
  }
  if (path == "/metrics") {
    info.route = ApiRoute::metrics;
    return info;
  }

  constexpr std::string_view kUsersPrefix = "/v1/users/";
  constexpr std::string_view kRotateSuffix = "/rotate-secret";
  constexpr std::string_view kLinksSuffix = "/links";
  if (path.rfind(kUsersPrefix, 0) == 0) {
    std::string rest = path.substr(kUsersPrefix.size());
    if (rest.size() > kLinksSuffix.size() &&
        rest.compare(rest.size() - kLinksSuffix.size(), kLinksSuffix.size(), kLinksSuffix) == 0) {
      rest.resize(rest.size() - kLinksSuffix.size());
      if (!rest.empty() && rest.find('/') == std::string::npos) {
        info.route = ApiRoute::user_links;
        info.name = std::move(rest);
      }
      return info;
    }
    if (rest.size() > kRotateSuffix.size() &&
        rest.compare(rest.size() - kRotateSuffix.size(), kRotateSuffix.size(),
                     kRotateSuffix) == 0) {
      rest.resize(rest.size() - kRotateSuffix.size());
      if (!rest.empty() && rest.find('/') == std::string::npos) {
        info.route = ApiRoute::rotate_secret;
        info.name = std::move(rest);
      }
      return info;
    }
    if (!rest.empty() && rest.find('/') == std::string::npos) {
      info.route = ApiRoute::user;
      info.name = std::move(rest);
    }
  }
  return info;
}

bool method_allowed(ApiRoute route, ApiMethod method) {
  switch (route) {
    case ApiRoute::health:
    case ApiRoute::ready:
    case ApiRoute::status:
    case ApiRoute::metrics:
    case ApiRoute::user_links:
      return method == ApiMethod::get;
    case ApiRoute::users:
      return method == ApiMethod::get || method == ApiMethod::post;
    case ApiRoute::user:
      return method == ApiMethod::get || method == ApiMethod::patch ||
             method == ApiMethod::delete_;
    case ApiRoute::rotate_secret:
      return method == ApiMethod::post;
    case ApiRoute::unknown:
      return false;
  }
  return false;
}

std::optional<HttpError> check_allowed_fields(
    const json& object, std::initializer_list<std::string_view> allowed) {
  for (auto it = object.begin(); it != object.end(); ++it) {
    bool known = false;
    for (auto field : allowed) {
      if (it.key() == field) {
        known = true;
        break;
      }
    }
    if (!known) {
      return HttpError{400, "unknown_field", "unknown field '" + it.key() + "'"};
    }
  }
  return std::nullopt;
}

std::optional<HttpError> parse_max_connections(const json& value,
                                               std::optional<uint32_t>& out) {
  if (value.is_null()) {
    out = std::nullopt;
    return std::nullopt;
  }
  if (!value.is_number_unsigned()) {
    return HttpError{400, "invalid_field",
                     "max_connections must be null or an integer within 1.." +
                         std::to_string(kMaxConnectionsLimit)};
  }
  const uint64_t number = value.get<uint64_t>();
  if (number == 0 || number > kMaxConnectionsLimit) {
    return HttpError{400, "invalid_field",
                     "max_connections must be null or an integer within 1.." +
                         std::to_string(kMaxConnectionsLimit)};
  }
  out = static_cast<uint32_t>(number);
  return std::nullopt;
}

std::optional<HttpError> parse_if_match(evhttp_request* request,
                                        std::optional<uint64_t>& out) {
  const char* raw = evhttp_find_header(evhttp_request_get_input_headers(request),
                                       "If-Match");
  if (raw == nullptr) return std::nullopt;
  std::string value = trim_copy(raw);
  if (value.find(',') != std::string::npos) {
    return HttpError{400, "invalid_field",
                     "If-Match accepts exactly one ETag"};
  }
  if (value == "*") {
    out = std::nullopt;  // matches any existing revision
    return std::nullopt;
  }
  bool quoted = false;
  if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
    value = value.substr(1, value.size() - 2);
    quoted = true;
  } else if (value.find('"') != std::string::npos) {
    return HttpError{400, "invalid_field",
                     "If-Match must be a strong ETag such as \"7\""};
  }
  if (value.empty() ||
      value.find_first_not_of("0123456789") != std::string::npos) {
    if (quoted) {
      // A quoted tag that is not a numeric revision is a stale/unknown ETag:
      // report the documented concurrency conflict rather than a syntax error.
      return HttpError{412, "revision_conflict",
                       "If-Match ETag does not match the current revision"};
    }
    return HttpError{400, "invalid_field",
                     "If-Match must be a strong ETag such as \"7\""};
  }
  try {
    out = std::stoull(value);
  } catch (...) {
    return HttpError{400, "invalid_field", "If-Match revision is out of range"};
  }
  return std::nullopt;
}

HttpError map_store_error(const Error& error) {
  int status = 500;
  switch (error.code) {
    case ErrorCode::invalid_name:
    case ErrorCode::invalid_secret:
    case ErrorCode::invalid_field:
    case ErrorCode::unknown_field:
    case ErrorCode::invalid_json:
    case ErrorCode::invalid_request:
    case ErrorCode::limit_exceeded:
    case ErrorCode::file_too_large:
      status = 400;
      break;
    case ErrorCode::duplicate_name:
    case ErrorCode::duplicate_secret:
      status = 409;
      break;
    case ErrorCode::not_found:
      status = 404;
      break;
    case ErrorCode::revision_conflict:
      status = 412;
      break;
    case ErrorCode::invalid_file:
    case ErrorCode::unsupported_version:
    case ErrorCode::permission_denied:
    case ErrorCode::symlink_rejected:
    case ErrorCode::io_error:
    case ErrorCode::bind_failed:
    case ErrorCode::invalid_config:
      status = 500;
      break;
  }
  return HttpError{status, to_string(error.code), error.message};
}

json user_json(const UserRecord& user, const StatisticsSnapshot& stats) {
  json entry;
  entry["name"] = user.name;
  entry["enabled"] = user.enabled;
  if (user.max_connections) {
    entry["max_connections"] = *user.max_connections;
  } else {
    entry["max_connections"] = nullptr;
  }
  entry["generation"] = user.generation;
  UserMetricsSnapshot metrics;
  const auto found = stats.users.find(user.name);
  if (found != stats.users.end()) metrics = found->second;
  entry["stats"] = {{"active_connections", metrics.active_connections},
                    {"unique_ips_active", metrics.unique_ips_active},
                    {"payload_bytes_c2s", metrics.payload_c2s_bytes},
                    {"payload_bytes_s2c", metrics.payload_s2c_bytes}};
  return entry;
}

BodyRead read_body(evhttp_request* request, size_t max_body_bytes,
                   bool allow_empty) {
  BodyRead result;
  const char* content_length =
      evhttp_find_header(evhttp_request_get_input_headers(request),
                         "Content-Length");
  if (content_length != nullptr) {
    try {
      const unsigned long long declared = std::stoull(content_length);
      if (declared > max_body_bytes) {
        result.error = HttpError{413, "body_too_large",
                                 "request body exceeds max_body_bytes"};
        return result;
      }
    } catch (...) {
      result.error =
          HttpError{400, "invalid_field", "invalid Content-Length header"};
      return result;
    }
  }
  evbuffer* input = evhttp_request_get_input_buffer(request);
  const size_t length = evbuffer_get_length(input);
  if (length == 0) {
    if (allow_empty) {
      result.value = json::object();
      return result;
    }
    result.error = HttpError{400, "invalid_request", "request body required"};
    return result;
  }
  if (length > max_body_bytes) {
    result.error = HttpError{413, "body_too_large",
                             "request body exceeds max_body_bytes"};
    return result;
  }
  const unsigned char* data = evbuffer_pullup(input, -1);
  if (data == nullptr) {
    result.error = HttpError{400, "invalid_request", "could not read body"};
    return result;
  }
  const std::string text(reinterpret_cast<const char*>(data), length);
  json parsed = json::parse(text, nullptr, false);
  if (parsed.is_discarded()) {
    result.error = HttpError{400, "invalid_json", "body is not valid JSON"};
    return result;
  }
  if (!parsed.is_object()) {
    result.error = HttpError{400, "invalid_request", "body must be a JSON object"};
    return result;
  }
  result.value = std::move(parsed);
  return result;
}

void send_json(evhttp_request* request, int status, const json& body,
               std::optional<uint64_t> revision) {
  const std::string text = body.dump();
  evbuffer* buffer = evbuffer_new();
  if (buffer == nullptr) {
    evhttp_send_reply(request, 500, nullptr, nullptr);
    return;
  }
  evbuffer_add(buffer, text.data(), text.size());
  evkeyvalq* headers = evhttp_request_get_output_headers(request);
  evhttp_add_header(headers, "Content-Type", "application/json");
  evhttp_add_header(headers, "Cache-Control", "no-store");
  evhttp_add_header(headers, "X-Content-Type-Options", "nosniff");
  if (revision) {
    const std::string etag = "\"" + std::to_string(*revision) + "\"";
    evhttp_add_header(headers, "ETag", etag.c_str());
  }
  evhttp_send_reply(request, status, nullptr, buffer);
  evbuffer_free(buffer);
}

void send_text(evhttp_request* request, int status, const std::string& body,
               std::string_view content_type,
               std::optional<uint64_t> revision) {
  evbuffer* buffer = evbuffer_new();
  if (buffer == nullptr) {
    evhttp_send_reply(request, 500, nullptr, nullptr);
    return;
  }
  evbuffer_add(buffer, body.data(), body.size());
  evkeyvalq* headers = evhttp_request_get_output_headers(request);
  const std::string type(content_type);
  evhttp_add_header(headers, "Content-Type", type.c_str());
  evhttp_add_header(headers, "Cache-Control", "no-store");
  if (revision) {
    const std::string etag = "\"" + std::to_string(*revision) + "\"";
    evhttp_add_header(headers, "ETag", etag.c_str());
  }
  evhttp_send_reply(request, status, nullptr, buffer);
  evbuffer_free(buffer);
}

void send_error(evhttp_request* request, int status, std::string type,
                std::string message, std::optional<uint64_t> revision) {
  json body;
  body["error"] = {{"code", status},
                   {"type", std::move(type)},
                   {"message", std::move(message)}};
  send_json(request, status, body, revision);
}

void send_store_error(evhttp_request* request, const Error& error,
                      std::optional<uint64_t> revision) {
  const HttpError mapped = map_store_error(error);
  const std::string message =
      error.uncertain
          ? "durability outcome uncertain after rename; in-memory state was not "
            "published: " + mapped.message
          : mapped.message;
  send_error(request, mapped.status, mapped.type, message, revision);
}

}  // namespace mtdd::control::detail
