// Durable user store: strict users-file schema, atomic owner-only writes,
// symlink rejection, revisioned immutable snapshots, bounded runtime ack wait.
#include <mtdd/control.hpp>

#include "store_internal.hpp"

#include <openssl/rand.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <fcntl.h>
#include <mutex>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <string>
#include <unordered_set>

#include <nlohmann/json.hpp>

namespace mtdd::control {
namespace {

using json = nlohmann::json;
using namespace mtdd::control::detail;

bool has_duplicate_secret(const std::vector<UserRecord>& users,
                          std::string_view secret, std::string_view except_name) {
  for (const auto& user : users) {
    if (user.name != except_name && user.secret_hex == secret) return true;
  }
  return false;
}

const UserRecord* find_user(const std::vector<UserRecord>& users,
                            std::string_view name) {
  for (const auto& user : users) {
    if (user.name == name) return &user;
  }
  return nullptr;
}

std::optional<Error> check_if_match(const std::optional<uint64_t>& if_match,
                                    uint64_t revision) {
  if (if_match && *if_match != revision) {
    return Error{ErrorCode::revision_conflict,
                 "If-Match revision " + std::to_string(*if_match) +
                     " does not match current revision " +
                     std::to_string(revision)};
  }
  return std::nullopt;
}

}  // namespace

const char* to_string(ErrorCode code) noexcept {
  switch (code) {
    case ErrorCode::invalid_name: return "invalid_name";
    case ErrorCode::invalid_secret: return "invalid_secret";
    case ErrorCode::invalid_field: return "invalid_field";
    case ErrorCode::unknown_field: return "unknown_field";
    case ErrorCode::invalid_json: return "invalid_json";
    case ErrorCode::invalid_request: return "invalid_request";
    case ErrorCode::duplicate_name: return "duplicate_name";
    case ErrorCode::duplicate_secret: return "duplicate_secret";
    case ErrorCode::not_found: return "not_found";
    case ErrorCode::revision_conflict: return "revision_conflict";
    case ErrorCode::limit_exceeded: return "limit_exceeded";
    case ErrorCode::invalid_file: return "invalid_file";
    case ErrorCode::unsupported_version: return "unsupported_version";
    case ErrorCode::file_too_large: return "file_too_large";
    case ErrorCode::permission_denied: return "permission_denied";
    case ErrorCode::symlink_rejected: return "symlink_rejected";
    case ErrorCode::io_error: return "io_error";
    case ErrorCode::bind_failed: return "bind_failed";
    case ErrorCode::invalid_config: return "invalid_config";
  }
  return "io_error";
}

struct UserStore::Impl {
  std::string path;
  StoreOptions options;
  mutable std::mutex mutex;
  std::mutex ack_mutex;
  // Published snapshot pointer. Guarded by snapshot_mutex, which is held only
  // for a pointer copy/assignment, never across I/O. mutex serializes mutations
  // and guards `uncertain`; lock order is always mutex -> snapshot_mutex.
  mutable std::mutex snapshot_mutex;
  std::shared_ptr<const UserSnapshot> snapshot;
  // Latched after a post-rename failure: disk may hold a revision newer than
  // memory. Further mutations would reuse that revision, so require a restart.
  bool uncertain{false};

  std::shared_ptr<const UserSnapshot> published() const {
    std::lock_guard<std::mutex> lock(snapshot_mutex);
    return snapshot;
  }

  Result<MutationOutcome> commit(std::unique_lock<std::mutex>& lock,
                                 std::vector<UserRecord> users,
                                 MutationOutcome outcome,
                                 const std::optional<std::string>& bump_generation_for) {
    const uint64_t new_revision = published()->revision + 1;
    if (new_revision == 0) {
      return Error{ErrorCode::invalid_request, "revision counter overflow"};
    }
    if (bump_generation_for) {
      auto it = std::find_if(
          users.begin(), users.end(), [&](const UserRecord& user) {
            return user.name == *bump_generation_for;
          });
      if (it == users.end()) {
        return Error{ErrorCode::invalid_request,
                     "internal error: generation target missing"};
      }
      // Auth generations are revision values: globally monotonic and durable.
      // A deleted name can be recreated, but its old generation can never be
      // minted again, so stale live sessions cannot be resurrected.
      it->generation = new_revision;
      outcome.user.generation = new_revision;
    }
    const std::string text = serialize_snapshot(new_revision, users);
    if (text.size() > options.max_file_bytes) {
      return Error{ErrorCode::file_too_large,
                   "serialized users file exceeds max_file_bytes (" +
                       std::to_string(options.max_file_bytes) + ")"};
    }
    auto next = std::make_shared<const UserSnapshot>(
        UserSnapshot{new_revision, std::move(users)});

    if (auto error = persist_atomic(path, text, options)) {
      if (error->uncertain) uncertain = true;
      return *error;
    }
    // Durable success only: publish the complete immutable snapshot. Existing
    // readers keep their old shared_ptr; new readers see either old or new.
    {
      std::lock_guard<std::mutex> publish_lock(snapshot_mutex);
      snapshot = std::move(next);
    }
    outcome.revision = new_revision;

    if (!options.ack_hook) {
      outcome.applied = true;
      outcome.pending = false;
      return outcome;
    }

    lock.unlock();
    std::lock_guard<std::mutex> ack_lock(ack_mutex);
    bool observed = false;
    try {
      observed = options.ack_hook(new_revision, options.ack_timeout);
    } catch (...) {
      observed = false;
    }
    outcome.applied = observed;
    outcome.pending = !observed;
    return outcome;
  }
};

Result<std::string> UserStore::generate_secret() {
  unsigned char bytes[kSecretBytes];
  if (RAND_bytes(bytes, static_cast<int>(sizeof(bytes))) != 1) {
    return Error{ErrorCode::io_error, "RAND_bytes failed"};
  }
  return hex_encode(bytes, sizeof(bytes));
}

bool UserStore::is_valid_name(std::string_view name) noexcept {
  if (name.empty() || name.size() > kMaxNameLength) return false;
  for (char c : name) {
    const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                    (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-';
    if (!ok) return false;
  }
  return true;
}

bool UserStore::is_valid_secret_hex(std::string_view secret) noexcept {
  if (secret.size() != kSecretHexChars) return false;
  for (char c : secret) {
    if (!is_hex_digit(c)) return false;
  }
  return true;
}

Result<UserStore> UserStore::open(std::string path, StoreOptions options) {
  if (path.empty()) {
    return Error{ErrorCode::invalid_config, "users path must not be empty"};
  }
  if (base_name(path).empty()) {
    return Error{ErrorCode::invalid_config, "users path must name a file"};
  }
  if (options.max_users == 0 || options.max_users > kMaxUsersLimit) {
    return Error{ErrorCode::invalid_config,
                 "max_users must be within 1.." + std::to_string(kMaxUsersLimit)};
  }
  if (options.max_file_bytes == 0 ||
      options.max_file_bytes > kMaxUsersFileBytesLimit) {
    return Error{ErrorCode::invalid_config,
                 "max_file_bytes must be within 1.." +
                     std::to_string(kMaxUsersFileBytesLimit)};
  }
  if ((options.file_mode & 0077u) != 0 || (options.file_mode & 0200u) == 0) {
    return Error{ErrorCode::invalid_config,
                 "file_mode must be owner-writable and deny group/other access"};
  }
  if ((options.dir_mode & 0077u) != 0 || (options.dir_mode & 0300u) != 0300u) {
    return Error{ErrorCode::invalid_config,
                 "dir_mode must be owner-rwx and deny group/other access"};
  }
  if (options.ack_timeout.count() < 0) {
    return Error{ErrorCode::invalid_config, "ack_timeout must not be negative"};
  }

  const std::string dir = parent_dir(path);
  if (auto error = ensure_directory(dir, options.dir_mode,
                                    options.create_directories)) {
    return *error;
  }

  auto impl = std::make_unique<Impl>();
  impl->path = std::move(path);
  impl->options = std::move(options);

  uint64_t revision = 0;
  std::vector<UserRecord> users;
  const int fd = ::open(impl->path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) {
    if (errno == ENOENT) {
      // Not yet shared with any reader: no publication lock needed.
      impl->snapshot = std::make_shared<const UserSnapshot>(
          UserSnapshot{0, {}});
      return UserStore(std::move(impl));
    }
    return errno_error(errno, "open users file");
  }

  struct stat st {};
  if (::fstat(fd, &st) != 0) {
    const int saved = errno;
    ::close(fd);
    return errno_error(saved, "stat users file");
  }
  if (!S_ISREG(st.st_mode)) {
    ::close(fd);
    return Error{ErrorCode::invalid_file,
                 "users file is not a regular file: " + impl->path};
  }
  // Fail closed before reading any secret: the file must be owned by this
  // process and unreadable/unwritable by group and others.
  if (st.st_uid != ::geteuid()) {
    ::close(fd);
    return Error{ErrorCode::permission_denied,
                 "users file is not owned by the service user: " + impl->path};
  }
  if ((st.st_mode & 0077) != 0) {
    ::close(fd);
    return Error{ErrorCode::permission_denied,
                 "users file is accessible by group/others (require 0600): " +
                     impl->path};
  }
  if (st.st_size < 0 ||
      static_cast<uint64_t>(st.st_size) > impl->options.max_file_bytes) {
    ::close(fd);
    return Error{ErrorCode::file_too_large,
                 "users file exceeds max_file_bytes (" +
                     std::to_string(impl->options.max_file_bytes) + ")"};
  }

  std::string content(static_cast<size_t>(st.st_size), '\0');
  size_t offset = 0;
  while (offset < content.size()) {
    const ssize_t got = ::read(fd, content.data() + offset, content.size() - offset);
    if (got < 0) {
      if (errno == EINTR) continue;
      const int saved = errno;
      ::close(fd);
      return errno_error(saved, "read users file");
    }
    if (got == 0) break;
    offset += static_cast<size_t>(got);
  }
  content.resize(offset);
  ::close(fd);

  if (auto error = parse_store_file(content, impl->options.max_users, revision,
                                    users)) {
    return *error;
  }
  // Not yet shared with any reader: no publication lock needed.
  impl->snapshot =
      std::make_shared<const UserSnapshot>(UserSnapshot{revision, std::move(users)});
  return UserStore(std::move(impl));
}

UserStore::UserStore(std::unique_ptr<Impl> impl) noexcept : impl_(std::move(impl)) {}
UserStore::UserStore(UserStore&&) noexcept = default;
UserStore& UserStore::operator=(UserStore&&) noexcept = default;
UserStore::~UserStore() = default;

std::shared_ptr<const UserSnapshot> UserStore::snapshot() const noexcept {
  if (!impl_) return nullptr;
  // Only the publication pointer is touched: never the mutation mutex that
  // commit() holds across persist_atomic() (fsync/rename).
  return impl_->published();
}

const std::string& UserStore::path() const noexcept {
  static const std::string kEmpty;
  return impl_ ? impl_->path : kEmpty;
}

Result<MutationOutcome> UserStore::create_user(const CreateUserRequest& request) {
  if (!is_valid_name(request.name)) {
    return Error{ErrorCode::invalid_name,
                 "name must match [A-Za-z0-9_.-]{1,64}"};
  }
  if (request.max_connections &&
      (*request.max_connections == 0 ||
       *request.max_connections > kMaxConnectionsLimit)) {
    return Error{ErrorCode::invalid_field,
                 "max_connections must be within 1.." +
                     std::to_string(kMaxConnectionsLimit)};
  }

  std::unique_lock<std::mutex> lock(impl_->mutex);
  if (impl_->uncertain) {
    return Error{ErrorCode::io_error,
                 "users store requires restart after an uncertain write"};
  }
  const auto current = impl_->published();
  if (auto error = check_if_match(request.if_match, current->revision)) {
    return *error;
  }
  if (current->users.size() >= impl_->options.max_users) {
    return Error{ErrorCode::limit_exceeded,
                 "user limit reached (" +
                     std::to_string(impl_->options.max_users) + ")"};
  }
  if (find_user(current->users, request.name) != nullptr) {
    return Error{ErrorCode::duplicate_name,
                 "user '" + request.name + "' already exists"};
  }

  std::string secret;
  if (request.secret) {
    if (!is_valid_secret_hex(*request.secret)) {
      return Error{ErrorCode::invalid_secret,
                   "secret must be exactly 32 hexadecimal characters"};
    }
    secret = lower_ascii(*request.secret);
  } else {
    auto generated = generate_secret();
    if (!generated.ok()) return generated.error();
    secret = std::move(generated).value();
  }
  if (has_duplicate_secret(current->users, secret, {})) {
    return Error{ErrorCode::duplicate_secret,
                 "secret is already assigned to another user"};
  }

  UserRecord record;
  record.name = request.name;
  record.secret_hex = secret;
  record.enabled = request.enabled;
  record.max_connections = request.max_connections;
  record.generation = 1;

  std::vector<UserRecord> users = current->users;
  auto position = std::lower_bound(
      users.begin(), users.end(), record.name,
      [](const UserRecord& user, const std::string& name) { return user.name < name; });
  users.insert(position, record);

  MutationOutcome outcome;
  outcome.user = record;
  outcome.secret_once = secret;
  return impl_->commit(lock, std::move(users), std::move(outcome),
                       request.name);
}

Result<MutationOutcome> UserStore::update_user(const UpdateUserRequest& request) {
  if (!is_valid_name(request.name)) {
    return Error{ErrorCode::invalid_name,
                 "name must match [A-Za-z0-9_.-]{1,64}"};
  }
  if (!request.enabled && !request.set_max_connections) {
    return Error{ErrorCode::invalid_request,
                 "update requires enabled or max_connections"};
  }
  if (request.set_max_connections && request.max_connections &&
      (*request.max_connections == 0 ||
       *request.max_connections > kMaxConnectionsLimit)) {
    return Error{ErrorCode::invalid_field,
                 "max_connections must be within 1.." +
                     std::to_string(kMaxConnectionsLimit)};
  }

  std::unique_lock<std::mutex> lock(impl_->mutex);
  if (impl_->uncertain) {
    return Error{ErrorCode::io_error,
                 "users store requires restart after an uncertain write"};
  }
  const auto current = impl_->published();
  if (auto error = check_if_match(request.if_match, current->revision)) {
    return *error;
  }

  const UserRecord* existing = find_user(current->users, request.name);
  if (existing == nullptr) {
    return Error{ErrorCode::not_found, "user '" + request.name + "' not found"};
  }
  UserRecord updated = *existing;
  bool auth_change = false;
  if (request.enabled) {
    if (*request.enabled != updated.enabled) {
      if (!*request.enabled) auth_change = true;
      updated.enabled = *request.enabled;
    }
  }
  if (request.set_max_connections) {
    updated.max_connections = request.max_connections;
  }

  MutationOutcome outcome;
  outcome.user = updated;
  if (!auth_change &&
      updated.enabled == existing->enabled &&
      updated.max_connections == existing->max_connections) {
    // No-op update: do not advance the revision or rewrite the file.
    outcome.revision = current->revision;
    outcome.applied = true;
    outcome.pending = false;
    return outcome;
  }
  outcome.user = updated;

  std::vector<UserRecord> users = current->users;
  auto position = std::find_if(
      users.begin(), users.end(),
      [&](const UserRecord& user) { return user.name == request.name; });
  *position = updated;
  const std::optional<std::string> bump_generation =
      auth_change ? std::optional<std::string>(request.name) : std::nullopt;
  return impl_->commit(lock, std::move(users), std::move(outcome),
                       bump_generation);
}

Result<MutationOutcome> UserStore::delete_user(const DeleteUserRequest& request) {
  if (!is_valid_name(request.name)) {
    return Error{ErrorCode::invalid_name,
                 "name must match [A-Za-z0-9_.-]{1,64}"};
  }
  std::unique_lock<std::mutex> lock(impl_->mutex);
  if (impl_->uncertain) {
    return Error{ErrorCode::io_error,
                 "users store requires restart after an uncertain write"};
  }
  const auto current = impl_->published();
  if (auto error = check_if_match(request.if_match, current->revision)) {
    return *error;
  }
  auto position = std::find_if(
      current->users.begin(), current->users.end(),
      [&](const UserRecord& user) { return user.name == request.name; });
  if (position == current->users.end()) {
    return Error{ErrorCode::not_found, "user '" + request.name + "' not found"};
  }
  MutationOutcome outcome;
  outcome.user = *position;
  outcome.deleted = true;

  std::vector<UserRecord> users;
  users.reserve(current->users.size() - 1);
  for (const auto& user : current->users) {
    if (user.name != request.name) users.push_back(user);
  }
  return impl_->commit(lock, std::move(users), std::move(outcome), std::nullopt);
}

Result<MutationOutcome> UserStore::rotate_secret(const RotateSecretRequest& request) {
  if (!is_valid_name(request.name)) {
    return Error{ErrorCode::invalid_name,
                 "name must match [A-Za-z0-9_.-]{1,64}"};
  }
  std::unique_lock<std::mutex> lock(impl_->mutex);
  if (impl_->uncertain) {
    return Error{ErrorCode::io_error,
                 "users store requires restart after an uncertain write"};
  }
  const auto current = impl_->published();
  if (auto error = check_if_match(request.if_match, current->revision)) {
    return *error;
  }
  auto position = std::find_if(
      current->users.begin(), current->users.end(),
      [&](const UserRecord& user) { return user.name == request.name; });
  if (position == current->users.end()) {
    return Error{ErrorCode::not_found, "user '" + request.name + "' not found"};
  }

  std::string secret;
  if (request.secret) {
    if (!is_valid_secret_hex(*request.secret)) {
      return Error{ErrorCode::invalid_secret,
                   "secret must be exactly 32 hexadecimal characters"};
    }
    secret = lower_ascii(*request.secret);
  } else {
    auto generated = generate_secret();
    if (!generated.ok()) return generated.error();
    secret = std::move(generated).value();
  }
  if (has_duplicate_secret(current->users, secret, request.name)) {
    return Error{ErrorCode::duplicate_secret,
                 "secret is already assigned to another user"};
  }

  UserRecord updated = *position;
  updated.secret_hex = secret;

  MutationOutcome outcome;
  outcome.user = updated;
  outcome.secret_once = secret;

  std::vector<UserRecord> users = current->users;
  auto updated_position = std::find_if(
      users.begin(), users.end(),
      [&](const UserRecord& user) { return user.name == request.name; });
  *updated_position = updated;
  return impl_->commit(lock, std::move(users), std::move(outcome), request.name);
}

}  // namespace mtdd::control
