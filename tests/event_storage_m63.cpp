// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include <knetsentry/storage/event_store.hpp>
#include <knetsentry/agent/delivery.hpp>
#include <iostream>
#include <stdexcept>
#include <type_traits>
#include <utility>

namespace {
using namespace knetsentry::storage;
using namespace knetsentry::agent;
static_assert(!std::is_base_of_v<ReceiptSink, MemoryEventStore>);
void require(bool condition, const char* message) {
    if (!condition) { throw std::runtime_error(message); }
}
template<class T> T read(ReadResult<T> result) {
    require(result.status == StoreStatus::Ok && result.value.has_value(), "expected record unavailable");
    return std::move(*result.value);
}
std::string row(std::string_view cursor, std::string_view suffix = "ssh-accepted") {
    return std::string(cursor) + "\t1795000000123456\t42\t" + std::string(32, 'c') + '\t' +
        std::string(32, 'd') + "\tssh.service\t" + std::string(suffix) + '\n';
}
void verify() {
    MemoryEventStore backend;
    EventStore& store = backend;
    require(store.durability() == Durability::Volatile, "reference store must not acknowledge durability");
    const auto binding = std::string(32, 'a') + std::string(64, 'b');
    const auto other = std::string(32, 'e') + std::string(64, 'b');
    auto original = row("cursor-1");
    auto input = RawInput{binding, "ssh.service", original, JournalMode::Authentication, 100};
    const auto first = store.append(input);
    require(first.status == StoreStatus::Ok && first.id != 0 && first.durability == Durability::Volatile, "append");
    require(read(store.raw(first.id)).canonical_row == original && store.normalized(first.id).status == StoreStatus::IndexPending && store.search({}).events.empty(), "raw precedes index visibility");
    input.received_ms = 999;
    const auto retry = store.append(input);
    require(retry.status == StoreStatus::ExactRetry && retry.id == first.id && read(store.raw(first.id)).received_ms == 100, "retry preserves receipt time");
    auto changed = row("cursor-1", "ssh-failed");
    input.canonical_row = changed;
    require(store.append(input).status == StoreStatus::Conflict, "conflicting evidence");
    input.canonical_row = original;
    const auto changed_manager = std::string(32, 'a') + std::string(64, 'f');
    input.binding = changed_manager;
    require(store.append(input).status == StoreStatus::Conflict, "binding substitution");
    input.binding = other;
    const auto second = store.append(input);
    require(second.status == StoreStatus::Ok && second.id > first.id, "endpoint scoped cursor");
    const auto pending_page = store.pending(0, std::nullopt, 1);
    require(pending_page.status == StoreStatus::Ok && pending_page.ids == std::vector<EventId>{first.id} && pending_page.more, "first pending page");
    const auto pending_next = store.pending(first.id, pending_page.revision, 1);
    require(pending_next.status == StoreStatus::Ok && pending_next.ids == std::vector<EventId>{second.id} && !pending_next.more, "pending continuation");
    require(store.pending(first.id, std::nullopt, 1).status == StoreStatus::Invalid &&
        store.pending(0, std::nullopt, 33).status == StoreStatus::Invalid, "invalid pending query");
    input.binding = binding;
    input.canonical_row = "malformed";
    require(store.append(input).status == StoreStatus::Invalid, "invalid row");
    input.canonical_row = original;
    input.unit = "other.service";
    require(store.append(input).status == StoreStatus::Invalid, "wrong source");
    input.unit = "ssh.service";
    input.received_ms = 0;
    require(store.append(input).status == StoreStatus::Invalid, "invalid receipt time");
    input.received_ms = 100;
    input.mode = JournalMode::Metadata;
    require(store.append(input).status == StoreStatus::Invalid, "wrong mode");
    require(store.index(999).status == StoreStatus::NotFound && store.raw(999).status == StoreStatus::NotFound && store.normalized(999).status == StoreStatus::NotFound, "missing record");
    const auto indexed = store.index(first.id);
    require(indexed.status == StoreStatus::Ok && indexed.durability == Durability::Volatile &&
        store.index(first.id).status == StoreStatus::ExactRetry, "index retry and volatile visibility");
    require(store.pending(first.id, pending_page.revision, 1).status == StoreStatus::Stale, "pending revision invalidated");
    require(read(store.normalized(first.id)).canonical_row == original && read(store.normalized(first.id)).status_id == OcsfStatus::Success, "typed projection");
    auto copy = read(store.raw(first.id));
    copy.canonical_row.clear();
    require(read(store.raw(first.id)).canonical_row == original, "owned retrieval");
    original.clear(); // Backend owns the original bytes.
    require(read(store.normalized(first.id)).source.cursor == "cursor-1", "independent evidence ownership");
    const auto redacted = row("cursor-3", "redacted");
    const auto third = store.append({binding, "ssh.service", redacted, JournalMode::Authentication, 101});
    require(third.status == StoreStatus::Ok && store.index(third.id).status == StoreStatus::Ok &&
        read(store.normalized(third.id)).mapping == MappingResult::Redacted, "redacted evidence");
    SearchQuery q;
    q.limit = 1;
    const auto page = store.search(q);
    require(page.status == StoreStatus::Ok && page.events.size() == 1 && page.events.front().id == first.id && page.more, "first page");
    q.after = first.id;
    q.revision = page.revision;
    const auto next = store.search(q);
    require(next.status == StoreStatus::Ok && next.events.size() == 1 && next.events.front().id == third.id && !next.more, "next page excludes pending");
    require(store.index(second.id).status == StoreStatus::Ok && store.search(q).status == StoreStatus::Stale, "index invalidates page revision");
    q = {};
    q.binding = binding;
    q.class_uid = OcsfClass::Authentication;
    q.status_id = OcsfStatus::Success;
    q.from_ms = 1795000000123ULL;
    q.through_ms = q.from_ms;
    const auto filtered = store.search(q);
    require(filtered.status == StoreStatus::Ok && filtered.events.size() == 1 && filtered.events.front().id == first.id, "combined filters");
    q.from_ms += 1;
    require(store.search(q).status == StoreStatus::Invalid, "reversed time range");
    q.through_ms = q.from_ms;
    require(store.search(q).events.empty(), "nonmatching time range");
    q.limit = 33;
    require(store.search(q).status == StoreStatus::Invalid, "page bound");
    q = {};
    q.after = first.id;
    require(store.search(q).status == StoreStatus::Invalid, "unversioned continuation");
    q = {};
    q.class_uid = static_cast<OcsfClass>(999);
    require(store.search(q).status == StoreStatus::Invalid, "invalid class");
    const auto pending_row = row("pending");
    q = {};
    q.binding = "invalid";
    require(store.search(q).status == StoreStatus::Invalid, "invalid query binding");
    const auto pending = store.append({binding, "ssh.service", pending_row, JournalMode::Authentication, 99});
    require(pending.status == StoreStatus::Ok && store.normalized(pending.id).status == StoreStatus::IndexPending, "pending record admitted");
    const auto initial_plan = store.preview_retention(102, 32).plan;
    require(initial_plan && initial_plan->ids.size() == 2, "retention uses receiver time, excludes pending");
    require(store.set_hold(first.id, true) == StoreStatus::Ok && store.apply_retention(*initial_plan).status == StoreStatus::Stale, "hold invalidates plan");
    const auto plan = store.preview_retention(102, 32).plan;
    require(plan && plan->ids.size() == 1 && plan->ids.front() == third.id, "hold exclusion");
    auto forged = *plan;
    forged.ids.front() = first.id;
    require(store.apply_retention(forged).status == StoreStatus::Invalid && store.raw(first.id).status == StoreStatus::Ok, "modified plan rejected");
    require(store.apply_retention(*plan).removed == 1 && store.raw(third.id).status == StoreStatus::NotFound && store.normalized(third.id).status == StoreStatus::NotFound &&
        store.raw(pending.id).status == StoreStatus::Ok, "explicit removal of both representations");
    require(store.apply_retention(*plan).status == StoreStatus::Stale, "repeated removal rejected");
    require(store.preview_retention(0, 1).status == StoreStatus::Invalid && store.preview_retention(102, 33).status == StoreStatus::Invalid, "retention limits");
    require(store.set_hold(first.id, false) == StoreStatus::Ok, "explicit hold release");
    const auto reinsert = store.append({binding, "ssh.service", redacted, JournalMode::Authentication, 103});
    require(reinsert.status == StoreStatus::Ok && reinsert.id > pending.id, "retired ID never reused");
    // Saturation must not evict existing evidence or prevent exact retries.
    for (std::size_t i = 4; i < MemoryEventStore::max_records; ++i) {
        const auto wire = row("fill-" + std::to_string(i));
        require(store.append({binding, "ssh.service", wire, JournalMode::Authentication, 200}).status == StoreStatus::Ok, "fill store");
    }
    const auto extra = row("extra");
    require(store.append({binding, "ssh.service", extra, JournalMode::Authentication, 200}).status == StoreStatus::Capacity, "capacity rejection");
    require(store.append({binding, "ssh.service", redacted, JournalMode::Authentication, 300}).status == StoreStatus::ExactRetry, "retry at capacity");
    require(store.raw(first.id).status == StoreStatus::Ok, "capacity does not evict");
    MemoryEventStore fresh;
    require(fresh.search({}).events.empty() && fresh.raw(first.id).status == StoreStatus::NotFound, "no claim of restart durability");
    // Metadata and audit are also admitted and indexed through the same parser.
    const auto base = "metadata-1\t1795000000123456\t42\t" + std::string(32, 'c') + '\t' + std::string(32, 'd') + '\t';
    const auto metadata = base + "fixture.service\n";
    const auto audit = base + "audit\t1100\t9\n";
    const auto m = fresh.append({binding, "fixture.service", metadata, JournalMode::Metadata, 1});
    const auto a = fresh.append({other, "audit", audit, JournalMode::Audit, 2});
    require(m.status == StoreStatus::Ok && a.status == StoreStatus::Ok && fresh.index(m.id).status == StoreStatus::Ok &&
        fresh.index(a.id).status == StoreStatus::Ok, "metadata and audit indexing");
    require(read(fresh.normalized(m.id)).mapping == MappingResult::MetadataOnly &&
        read(fresh.normalized(a.id)).source.audit_type == 1100 && read(fresh.normalized(a.id)).source.audit_id == 9, "native audit provenance");
    const auto boundary_plan = fresh.preview_retention(2, 1).plan;
    require(boundary_plan && boundary_plan->ids == std::vector<EventId>{m.id}, "strict retention cutoff");
    const auto removed = fresh.apply_retention(*boundary_plan);
    require(removed.status == StoreStatus::Ok && removed.removed == 1 && fresh.raw(a.id).status == StoreStatus::Ok, "bounded retention leaves newer evidence");
}
} // namespace
int main() {
    try {
        verify();
        std::cout << "M6.3 volatile raw-first storage, indexed search, retention holds, stale plans and bounded admission: PASS\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "M6.3 failure: " << error.what() << '\n';
        return 1;
    }
}
