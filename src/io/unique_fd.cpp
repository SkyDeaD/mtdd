#include "mtdd/io.hpp"

#include <unistd.h>

namespace mtdd::io {

UniqueFd::~UniqueFd() { close(); }

UniqueFd& UniqueFd::operator=(UniqueFd&& other) noexcept {
    if (this != &other) {
        reset(other.release());
    }
    return *this;
}

int UniqueFd::release() noexcept {
    const int fd = fd_;
    fd_ = -1;
    return fd;
}

void UniqueFd::reset(int fd) noexcept {
    if (fd_ == fd) {
        return;
    }
    close();
    fd_ = fd;
}

void UniqueFd::close() noexcept {
    if (fd_ < 0) {
        return;
    }
    const int fd = fd_;
    fd_ = -1;
    // On Linux the descriptor is released even when close() reports EINTR.
    // Retrying could close an unrelated descriptor reused by another thread,
    // so the interruption is deliberately ignored.
    (void)::close(fd);
}

}  // namespace mtdd::io
