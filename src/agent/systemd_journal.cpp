// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/agent/journal.hpp"
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <systemd/sd-journal.h>
#include <utility>

namespace knetsentry::agent {
namespace {
class SystemJournal final : public JournalSource {
public:
    SystemJournal(std::string directory, JournalMode mode) : directory_(std::move(directory)), mode_(mode) {}
    ~SystemJournal() override { close(); }
    bool open(std::string_view unit) override {
        if (journal_ != nullptr || !valid_journal_unit(unit) ||
            (mode_ == JournalMode::Authentication && !valid_auth_unit(unit))) { return false; }
        const int result = directory_.empty() ? sd_journal_open(&journal_, SD_JOURNAL_LOCAL_ONLY) :
            sd_journal_open_directory(&journal_, directory_.c_str(), 0);
        if (result < 0) { return false; }
        if (directory_.empty()) {
            sd_id128_t machine{};
            char text[SD_ID128_STRING_MAX]{};
            if (sd_id128_get_machine(&machine) < 0) { return false; }
            local_machine_ = sd_id128_to_string(machine, text);
        }
        const auto match = std::string("_SYSTEMD_UNIT=") + std::string(unit);
        return sd_journal_set_data_threshold(journal_, 2048) >= 0 &&
            sd_journal_add_match(journal_, match.data(), match.size()) >= 0;
    }
    bool resume(std::string_view cursor) override {
        if (journal_ == nullptr || sd_journal_process(journal_) < 0) { return false; }
        if (cursor.empty()) { return sd_journal_seek_head(journal_) >= 0; }
        const std::string value(cursor);
        return sd_journal_seek_cursor(journal_, value.c_str()) >= 0 &&
            sd_journal_next(journal_) > 0 && sd_journal_test_cursor(journal_, value.c_str()) > 0;
    }
    JournalResult next(JournalRecord& record) override {
        if (journal_ == nullptr) { return JournalResult::Error; }
        const int result = sd_journal_next(journal_);
        if (result == 0) { return JournalResult::End; }
        if (result < 0) { return JournalResult::Error; }
        char* raw = nullptr;
        const int cursor_result = sd_journal_get_cursor(journal_, &raw);
        const std::unique_ptr<char, decltype(&std::free)> cursor(raw, &std::free);
        sd_id128_t boot{};
        if (cursor_result < 0 || !cursor ||
            sd_journal_get_realtime_usec(journal_, &record.realtime_usec) < 0 ||
            sd_journal_get_monotonic_usec(journal_, &record.monotonic_usec, &boot) < 0 ||
            !field("_SYSTEMD_UNIT", record.unit, 128) || !field("_MACHINE_ID", record.machine, 32)) {
            return JournalResult::Error;
        }
        const auto length = ::strnlen(cursor.get(), 1025);
        if (length == 0 || length > 1024) { return JournalResult::Error; }
        record.cursor.assign(cursor.get(), length);
        if (!local_machine_.empty() && record.machine != local_machine_) { return JournalResult::Error; }
        char boot_text[SD_ID128_STRING_MAX]{};
        record.boot = sd_id128_to_string(boot, boot_text);
        record.auth = AuthEvent::None;
        if (mode_ == JournalMode::Authentication) {
            // Inspect a bounded message view only in opt-in authentication mode.
            // Never copy the message into a JournalRecord or persistent state.
            const void* data = nullptr;
            std::size_t size{};
            const int status = sd_journal_get_data(journal_, "MESSAGE", &data, &size);
            record.auth = AuthEvent::Unclassified;
            if (status >= 0 && data != nullptr && size > 8 && size <= 1032) {
                const std::string_view field_data(static_cast<const char*>(data), size);
                if (field_data.starts_with("MESSAGE=")) { record.auth = classify_auth(record.unit, field_data.substr(8)); }
            } else if (status < 0 && status != -ENOENT && status != -E2BIG && status != -ENOBUFS) {
                return JournalResult::Error;
            }
        }
        return JournalResult::Record;
    }
    void close() noexcept override {
        if (journal_ != nullptr) { sd_journal_close(journal_); journal_ = nullptr; }
    }
private:
    bool field(std::string_view name, std::string& output, std::size_t max) {
        const std::string key(name);
        const void* raw = nullptr;
        std::size_t size{};
        if (sd_journal_get_data(journal_, key.c_str(), &raw, &size) < 0 || raw == nullptr ||
            size <= name.size() + 1 || size > name.size() + 1 + max) { return false; }
        const std::string_view data(static_cast<const char*>(raw), size);
        if (!data.starts_with(name) || data[name.size()] != '=') { return false; }
        output = data.substr(name.size() + 1);
        return true;
    }
    std::string directory_, local_machine_;
    JournalMode mode_;
    sd_journal* journal_{};
};
} // namespace
std::unique_ptr<JournalSource> make_journal_source(std::string directory, JournalMode mode) {
    return std::make_unique<SystemJournal>(std::move(directory), mode);
}
} // namespace knetsentry::agent
