// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include <knetsentry/core/enrollment.hpp>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

namespace knetsentry::enrollment {
namespace {
constexpr char registry[] = "endpoints.v1";
constexpr char pending[] = "endpoints.v1.pending";
constexpr char staging[] = "endpoints.v1.new";
constexpr std::array<unsigned char, 8> magic{'K', 'S', 'E', 'N', 'R', 1, 0, 0};
constexpr std::size_t record_size = EndpointId{}.size() + identity::Fingerprint{}.size();
constexpr std::array<unsigned char, 8> lifecycle_magic{'K', 'S', 'E', 'N', 'R', 2, 0, 0};
constexpr std::size_t lifecycle_record_size = record_size + 1;
constexpr std::size_t max_bytes = magic.size() + max_endpoints * lifecycle_record_size;
struct Fd {
    int value{-1};
    explicit Fd(int fd) noexcept : value(fd) {}
    ~Fd() { if (value >= 0) { (void)close(value); } }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
};
struct Record { EndpointId id{}; identity::Fingerprint pin{}; bool retired{}; };
struct Data { std::array<Record, max_endpoints> records{}; std::size_t size{}; bool lifecycle{}; };
template<typename T> bool nonzero(const T& data) noexcept {
    return std::any_of(data.begin(), data.end(), [](unsigned char byte) { return byte != 0; });
}
bool safe_dir(int fd) noexcept {
    struct stat st{};
    return fstat(fd, &st) == 0 && S_ISDIR(st.st_mode) && st.st_uid == geteuid() &&
        (st.st_mode & 07777) == 0700;
}
bool safe_file(const struct stat& st) noexcept {
    return S_ISREG(st.st_mode) && st.st_uid == geteuid() && st.st_nlink == 1 &&
        (st.st_mode & 07777) == 0600;
}
// Reopen the directory to obtain an independent flock description even when
// callers share their original descriptor. All cooperating readers/writers lock.
Status lock(int fd) noexcept {
    if (!safe_dir(fd)) { return Status::UnsafeStorage; }
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        return errno == EWOULDBLOCK ? Status::Busy : Status::Io;
    }
    for (const auto* name : {pending, staging}) {
        struct stat st{};
        if (fstatat(fd, name, &st, AT_SYMLINK_NOFOLLOW) == 0) { return Status::Corrupt; }
        if (errno != ENOENT) { return Status::Io; }
    }
    return Status::Ok;
}
Status load(int dir, Data& data) noexcept {
    Fd file(openat(dir, registry, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC));
    if (file.value < 0) { return errno == ENOENT ? Status::Unavailable : Status::UnsafeStorage; }
    struct stat st{};
    if (fstat(file.value, &st) != 0 || !safe_file(st)) { return Status::UnsafeStorage; }
    if (st.st_size < static_cast<off_t>(magic.size()) || st.st_size > static_cast<off_t>(max_bytes)) {
        return Status::Corrupt;
    }
    const auto size = static_cast<std::size_t>(st.st_size);
    std::array<unsigned char, max_bytes> bytes{};
    std::size_t offset = 0;
    while (offset < size) {
        const auto count = read(file.value, bytes.data() + offset, size - offset);
        if (count < 0 && errno == EINTR) { continue; }
        if (count <= 0) { return Status::Corrupt; }
        offset += static_cast<std::size_t>(count);
    }
    unsigned char extra{};
    if (read(file.value, &extra, 1) != 0) {
        return Status::Corrupt;
    }
    data.lifecycle = std::equal(lifecycle_magic.begin(), lifecycle_magic.end(), bytes.begin());
    if (!data.lifecycle && !std::equal(magic.begin(), magic.end(), bytes.begin())) { return Status::Corrupt; }
    const auto stride = data.lifecycle ? lifecycle_record_size : record_size;
    if ((size - magic.size()) % stride != 0 || (size - magic.size()) / stride > max_endpoints) {
        return Status::Corrupt;
    }
    for (offset = magic.size(); offset < size; offset += stride) {
        Record item{};
        std::copy_n(bytes.data() + offset, item.id.size(), item.id.begin());
        std::copy_n(bytes.data() + offset + item.id.size(), item.pin.size(), item.pin.begin());
        if (data.lifecycle) {
            const auto flag = bytes.at(offset + record_size);
            if (flag > 1) { return Status::Corrupt; }
            item.retired = flag == 1;
        }
        if (!nonzero(item.id) || !nonzero(item.pin)) { return Status::Corrupt; }
        for (std::size_t i = 0; i < data.size; ++i) {
            const auto& prior = data.records.at(i);
            if (prior.pin == item.pin || (prior.id == item.id && !prior.retired)) {
                return Status::Corrupt;
            }
        }
        data.records.at(data.size++) = item;
    }
    return Status::Ok;
}
Status publish(int dir, const Data& data) noexcept {
    // Persist a transaction marker before publication. Any incomplete
    // transaction blocks all cooperating readers until manual recovery.
    Fd marker(openat(dir, pending, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
    if (marker.value < 0 || fchmod(marker.value, 0600) != 0 ||
        fsync(marker.value) != 0 || fsync(dir) != 0) { return Status::Io; }
    Fd file(openat(dir, staging, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
    if (file.value < 0) { return Status::Io; }
    struct stat st{};
    if (fchmod(file.value, 0600) != 0 || fstat(file.value, &st) != 0 || !safe_file(st)) { return Status::Io; }
    std::array<unsigned char, max_bytes> bytes{};
    const auto& header = data.lifecycle ? lifecycle_magic : magic;
    std::copy(header.begin(), header.end(), bytes.begin());
    std::size_t size = magic.size();
    for (std::size_t i = 0; i < data.size; ++i) {
        const auto& record = data.records.at(i);
        std::copy(record.id.begin(), record.id.end(), bytes.data() + size);
        size += record.id.size();
        std::copy(record.pin.begin(), record.pin.end(), bytes.data() + size);
        size += record.pin.size();
        if (data.lifecycle) { bytes.at(size++) = record.retired ? 1 : 0; }
    }
    std::size_t offset = 0;
    while (offset < size) {
        const auto count = write(file.value, bytes.data() + offset, size - offset);
        if (count < 0 && errno == EINTR) { continue; }
        if (count <= 0) { return Status::Io; }
        offset += static_cast<std::size_t>(count);
    }
    if (fsync(file.value) != 0 || renameat(dir, staging, dir, registry) != 0 ||
        fsync(dir) != 0 || unlinkat(dir, pending, 0) != 0) { return Status::Io; }
    // The registry is durable before marker removal. A crash may restore the
    // marker (deny until recovery), but cannot publish a partial record.
    return fsync(dir) == 0 ? Status::Ok : Status::Io;
}
} // namespace

Status initialize(int directory) noexcept {
    if (directory < 0) { return Status::UnsafeStorage; }
    Fd dir(openat(directory, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    const auto status = lock(dir.value);
    if (status != Status::Ok) { return status; }
    struct stat st{};
    if (fstatat(dir.value, registry, &st, AT_SYMLINK_NOFOLLOW) == 0) { return Status::Conflict; }
    if (errno != ENOENT) { return Status::Io; }
    return publish(dir.value, Data{});
}
Status approve(int directory, const EndpointId& id, const identity::Fingerprint& pin) noexcept {
    if (!nonzero(id) || !nonzero(pin)) { return Status::InvalidInput; }
    if (directory < 0) { return Status::UnsafeStorage; }
    Fd dir(openat(directory, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    const auto status = lock(dir.value);
    if (status != Status::Ok) { return status; }
    Data data{};
    const auto loaded = load(dir.value, data);
    if (loaded != Status::Ok) { return loaded; }
    for (std::size_t i = 0; i < data.size; ++i) {
        if (data.records.at(i).id == id || data.records.at(i).pin == pin) { return Status::Conflict; }
    }
    if (data.size == max_endpoints) { return Status::Full; }
    data.records.at(data.size++) = Record{id, pin, false};
    return publish(dir.value, data);
}
namespace {
Status change(int directory, const EndpointId& id, const identity::Fingerprint& expected,
    const identity::Fingerprint* replacement) noexcept {
    if (!nonzero(id) || !nonzero(expected) || (replacement != nullptr && !nonzero(*replacement))) {
        return Status::InvalidInput;
    }
    if (directory < 0) { return Status::UnsafeStorage; }
    Fd dir(openat(directory, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    const auto status = lock(dir.value);
    if (status != Status::Ok) { return status; }
    Data data{};
    const auto loaded = load(dir.value, data);
    if (loaded != Status::Ok) { return loaded; }
    Record* active = nullptr;
    bool known = false;
    for (std::size_t i = 0; i < data.size; ++i) {
        auto& record = data.records.at(i);
        if (record.id == id) {
            known = true;
            if (!record.retired) { active = &record; }
        }
    }
    if (active == nullptr) { return known ? Status::Revoked : Status::Unknown; }
    if (active->pin != expected) { return Status::Conflict; }
    if (replacement != nullptr) {
        for (std::size_t i = 0; i < data.size; ++i) {
            if (data.records.at(i).pin == *replacement) { return Status::Conflict; }
        }
        if (data.size == max_endpoints) { return Status::Full; }
        data.records.at(data.size++) = Record{id, *replacement, false};
    }
    active->retired = true;
    data.lifecycle = true;
    return publish(dir.value, data);
}
} // namespace
Status rotate(int directory, const EndpointId& id, const identity::Fingerprint& expected,
    const identity::Fingerprint& replacement) noexcept {
    return change(directory, id, expected, &replacement);
}
Status revoke(int directory, const EndpointId& id, const identity::Fingerprint& expected) noexcept {
    return change(directory, id, expected, nullptr);
}
Lookup lookup(int directory, const EndpointId& id) noexcept {
    if (!nonzero(id)) { return {Status::InvalidInput}; }
    if (directory < 0) { return {Status::UnsafeStorage}; }
    Fd dir(openat(directory, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    const auto status = lock(dir.value);
    if (status != Status::Ok) { return {status}; }
    Data data{};
    const auto loaded = load(dir.value, data);
    if (loaded != Status::Ok) { return {loaded}; }
    for (std::size_t i = data.size; i > 0; --i) {
        const auto& record = data.records.at(i - 1);
        if (record.id == id) {
            return record.retired ? Lookup{Status::Revoked} : Lookup{Status::Ok, record.pin};
        }
    }
    return {Status::Unknown};
}
Roster inspect(int directory) noexcept {
    Roster result{};
    if (directory < 0) { result.status = Status::UnsafeStorage; return result; }
    Fd dir(openat(directory, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    result.status = lock(dir.value);
    if (result.status != Status::Ok) { return result; }
    Data data{};
    result.status = load(dir.value, data);
    if (result.status != Status::Ok) { return result; }
    // Collapse retired keys into one endpoint row. A current key wins over
    // any historical retired key, regardless of record order.
    for (std::size_t i = 0; i < data.size; ++i) {
        const auto& record = data.records.at(i);
        auto end = result.entries.begin() + static_cast<std::ptrdiff_t>(result.size);
        const auto found = std::find_if(result.entries.begin(), end,
            [&](const RosterEntry& item) { return item.id == record.id; });
        if (found == end) {
            result.entries.at(result.size++) = {record.id, !record.retired};
        } else if (!record.retired) { found->approved = true; }
    }
    return result;
}
} // namespace knetsentry::enrollment
