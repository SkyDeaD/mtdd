#include "mtdd/io.hpp"

#include <sys/socket.h>
#include <sys/uio.h>

#include <algorithm>
#include <cerrno>
#include <new>

namespace mtdd::io {

namespace {

constexpr std::size_t kMaxIovecs = ByteQueue::kMaxIovecs;
/// Bounds signal-storm spinning inside one flush; data is never dropped.
constexpr int kMaxEintrRetries = 8;
static_assert(ByteQueue::kRetainedIdleChunks == 1,
              "spare_ implements exactly one retained idle block");

}  // namespace

ByteQueue::ByteQueue(ByteQueue&& other) noexcept
    : chunks_(std::move(other.chunks_)),
      spare_(std::move(other.spare_)),
      bytes_(other.bytes_),
      max_bytes_(other.max_bytes_) {
    other.bytes_ = 0;
    other.max_bytes_ = 0;
}

ByteQueue& ByteQueue::operator=(ByteQueue&& other) noexcept {
    if (this != &other) {
        chunks_ = std::move(other.chunks_);
        spare_ = std::move(other.spare_);
        bytes_ = other.bytes_;
        max_bytes_ = other.max_bytes_;
        other.bytes_ = 0;
        other.max_bytes_ = 0;
    }
    return *this;
}

std::size_t ByteQueue::capacity_bytes() const noexcept {
    std::size_t total = spare_.capacity();
    for (const Chunk& chunk : chunks_) {
        total += chunk.data.capacity();
    }
    return total;
}

ByteQueue::Chunk& ByteQueue::tail_chunk() {
    if (chunks_.empty() || chunks_.back().data.size() >= kChunkBytes) {
        Chunk chunk;
        if (chunks_.empty() && spare_.capacity() >= kChunkBytes) {
            chunk.data = std::move(spare_);
        } else {
            // Reserve the fixed block once so appends never reallocate it.
            chunk.data.reserve(kChunkBytes);
        }
        chunks_.push_back(std::move(chunk));
    }
    return chunks_.back();
}

AppendStatus ByteQueue::append(std::span<const std::uint8_t> data) {
    if (data.empty()) {
        return AppendStatus::ok;
    }
    // Invariant: bytes_ <= max_bytes_, so the subtraction cannot underflow.
    if (data.size() > max_bytes_ - bytes_) {
        return AppendStatus::exceeds_capacity;
    }

    const std::size_t previous_bytes = bytes_;
    try {
        std::size_t offset = 0;
        while (offset < data.size()) {
            Chunk& tail = tail_chunk();
            const std::size_t room = kChunkBytes - tail.data.size();
            const std::size_t take = std::min(room, data.size() - offset);
            const std::uint8_t* begin = data.data() + offset;
            tail.data.insert(tail.data.end(), begin, begin + take);
            offset += take;
        }
    } catch (...) {
        // Strong guarantee: undo partial chunk growth and capacity changes.
        trim_to(previous_bytes);
        return AppendStatus::allocation_failure;
    }

    bytes_ += data.size();
    return AppendStatus::ok;
}

void ByteQueue::consume(std::size_t count) noexcept {
    const std::size_t requested = count;
    while (count > 0 && !chunks_.empty()) {
        Chunk& front = chunks_.front();
        const std::size_t available = front.data.size() - front.offset;
        const std::size_t take = std::min(available, count);
        front.offset += take;
        count -= take;

        if (front.offset == front.data.size()) {
            front.data.clear();
            front.offset = 0;
            // Keep at most one drained block; the rest must not accumulate.
            if (spare_.capacity() < kChunkBytes && front.data.capacity() >= kChunkBytes) {
                spare_ = std::move(front.data);
            }
            chunks_.pop_front();
        }
    }
    bytes_ = bytes_ >= requested ? bytes_ - requested : 0;
}

void ByteQueue::trim_to(std::size_t target) noexcept {
    std::size_t total = 0;
    for (const Chunk& chunk : chunks_) {
        total += chunk.data.size() - chunk.offset;
    }

    while (total > target && !chunks_.empty()) {
        Chunk& tail = chunks_.back();
        const std::size_t excess = total - target;
        const std::size_t removable = tail.data.size() - tail.offset;
        const std::size_t take = std::min(excess, removable);
        if (take == 0) {
            break;
        }
        tail.data.resize(tail.data.size() - take);
        total -= take;

        if (tail.data.size() == tail.offset) {
            tail.data.clear();
            tail.offset = 0;
            if (spare_.capacity() < kChunkBytes && tail.data.capacity() >= kChunkBytes) {
                spare_ = std::move(tail.data);
            }
            chunks_.pop_back();
        }
    }
    bytes_ = target;
}

FlushResult ByteQueue::flush_to(int fd, std::size_t byte_budget) {
    FlushResult result;
    if (bytes_ == 0) {
        return result;  // drained
    }
    if (byte_budget == 0) {
        result.status = FlushStatus::budget_exhausted;
        return result;
    }
    if (fd < 0) {
        result.status = FlushStatus::error;
        result.error = EBADF;
        return result;
    }

    int eintr_retries = 0;
    while (result.bytes_written < byte_budget && bytes_ > 0) {
        const std::size_t budget_left = byte_budget - result.bytes_written;

        iovec iov[kMaxIovecs];
        std::size_t iov_count = 0;
        std::size_t wanted = 0;
        for (Chunk& chunk : chunks_) {
            if (iov_count == kMaxIovecs || wanted == budget_left) {
                break;
            }
            const std::size_t available = chunk.data.size() - chunk.offset;
            if (available == 0) {
                continue;
            }
            const std::size_t take = std::min(available, budget_left - wanted);
            iov[iov_count].iov_base = chunk.data.data() + chunk.offset;
            iov[iov_count].iov_len = take;
            ++iov_count;
            wanted += take;
        }
        if (iov_count == 0) {
            // Unreachable while bytes_ > 0; fail loudly instead of reporting a
            // retryable state that could spin the caller's event loop.
            result.status = FlushStatus::error;
            result.error = EIO;
            return result;
        }

        msghdr msg{};
        msg.msg_iov = iov;
        msg.msg_iovlen = static_cast<decltype(msg.msg_iovlen)>(iov_count);

        // MSG_NOSIGNAL turns a closed peer into EPIPE instead of SIGPIPE.
        const ssize_t written = ::sendmsg(fd, &msg, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (written < 0) {
            const int error = errno;
            if (error == EINTR) {
                // No bytes were accepted. Retry a bounded number of times so a
                // signal storm cannot monopolize the worker; the unaccepted
                // bytes stay queued and the caller retries on writability.
                if (++eintr_retries > kMaxEintrRetries) {
                    result.status = FlushStatus::would_block;
                    return result;
                }
                continue;
            }
            if (error == EAGAIN || error == EWOULDBLOCK) {
                result.status = FlushStatus::would_block;
                return result;
            }
            result.status = FlushStatus::error;
            result.error = error;
            return result;
        }
        if (written == 0) {
            // Defensive: never loop forever on a zero-length send.
            result.status = FlushStatus::would_block;
            return result;
        }

        const auto accepted = static_cast<std::size_t>(written);
        consume(accepted);
        result.bytes_written += accepted;

        if (accepted < wanted) {
            // Short write: the socket buffer is saturated. The unaccepted
            // remainder stays queued for the next writability event.
            result.status = FlushStatus::would_block;
            return result;
        }
    }

    result.status = bytes_ == 0 ? FlushStatus::drained : FlushStatus::budget_exhausted;
    return result;
}

void ByteQueue::release_idle() noexcept {
    if (bytes_ != 0) return;
    // Only the retained idle block can exist for an empty queue: consume()
    // pops every fully drained chunk.
    spare_.clear();
    if (spare_.capacity() == 0) return;
    std::vector<std::uint8_t>().swap(spare_);
}

void ByteQueue::clear() noexcept {
    chunks_.clear();
    bytes_ = 0;
    // clear() is non-allocating: keep the single retained block as-is. The
    // spare never exceeds kChunkBytes (only reserved blocks are recycled).
    spare_.clear();
}

}  // namespace mtdd::io
