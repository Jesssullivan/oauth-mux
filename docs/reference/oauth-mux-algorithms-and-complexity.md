<!-- AUDIT-GENERATED DRAFT (2026-06-03 architecture audit workflow wf_a60ca68c).
     Grounded in repo evidence but NOT line-by-line human-verified — treat as a
     strong draft; verify specifics against source before citing as canonical. -->

# oauth-mux Algorithmic Complexity Analysis

## System Architecture Overview

The oauth-mux system implements a multi-account OAuth token broker with load balancing, health tracking, and automatic failover. Key components:

- **HealthStore** (`src/health.zig`): StringHashMap-based health tracking per account and capability
- **AccountPool** (`src/broker/account_pool.zig`): In-memory account list with liveness and availability filtering
- **Wire Proxy** (`src/adapters/codex/wire_proxy.zig`): Request-level account election and quota/retry logic
- **Repair State** (`src/repair_state.zig`): Handoff coordination and lock-based refresh serialization
- **Identity** (`src/main.zig`): SHA256-12hex account ID dedup for inventory

## Core Algorithmic Patterns

### 1. Route Election (Health-Weighted Strategy)

**Location**: `src/broker/account_pool.zig:187-204`

Selects next available account via linear scan:
```
elect(profile, capability, exclude[]):
  for each account in pool.accounts:
    if not selectable: skip
    if not available: skip
    if in exclude[]: skip  
    return this account
  throw NoAccountSelectable
```

**Time Complexity**: **O(n)** where n = pool size
- Single linear pass; no sorting or priority queue
- Subsequent attempts add linear rescans to skip tried accounts

**Space Complexity**: **O(1)** per election
- Stateless scan; no auxiliary data structure

**Concern**: When r retries occur, worst case is O(r·n) if election is called per attempt without amortized skip tracking.

---

### 2. Account Pool State Refresh (Time-Window Expiration)

**Location**: `src/broker/account_pool.zig:155-167`

Recovery of expired transient states:
```
refreshTimeBased(now_unix):
  for each account in pool.accounts:
    if account.next_eligible_at <= now:
      restore availability.available
      restore liveness.live (if not dead)
      restore selectability (unless dead)
```

**Time Complexity**: **O(n)** per refresh call
- Full scan on every serve loop iteration
- No early-exit or incremental approach

**Space Complexity**: **O(1)**

**Risk**: If called per request in a high-throughput scenario with large pools (e.g., 100+ accounts), this O(n) scan adds overhead. Consider: indexed next_eligible_at min-heap or lazy evaluation on first access.

---

### 3. HealthStore: StringHashMap Account:Capability Keying

**Location**: `src/health.zig:245-265`

Dual-level health keying:
- Account-level: `provider:account` → AccountHealth
- Capability-level: `provider:account#capability` → AccountHealth (per route)

```
HealthStore {
  accounts: StringHashMap(AccountHealth)  // O(1) amortized lookup
}

accountKey(provider, account) → "codex:max-1"
capabilityKey(provider, account, capability) → "codex:max-1#codex-max"
```

**Time Complexity**: 
- getOrCreate: **O(1)** amortized
- Iteration (passiveRecovery, persist): **O(n)** where n = |entries| (both account and capability keys)

**Space Complexity**: **O(n)** for n entries
- Each entry: key string + AccountHealth struct (~300 bytes)
- Unbounded growth unless pruned

**Concern**: No automatic eviction. If thousands of capability-level entries accumulate (e.g., per provider × account × capability combinations), the hashmap becomes a memory liability. Current design relies on application lifecycle to bound this.

---

### 4. Circuit Breaker State Machine

**Location**: `src/health.zig:284-401, 991-997`

Per-account state: Closed → Open → Half-Open → Closed

Transitions:
- **Closed → Open**: 3 failures within 60s window
- **Open → Half-Open**: After 30s timeout
- **Half-Open → Closed**: After configured success threshold

**Time Complexity**: **O(1)** per failure/success record
- State check and transition are constant-time

**Space Complexity**: **O(1)** per circuit
- Fixed struct: opened_at, failure_count, successes_so_far

**Design Note**: Window is sliding based on `health.score.window_start`; resets on 60s boundary. Per-account isolation ensures one bad route doesn't block others.

---

### 5. Token Bucket Rate Limiter

**Location**: `src/health.zig:436` + `types.zig` (TokenBucket)

Per-account request throttling:
```
bucket.tryConsume(now_ns):
  refill(now_ns)  // clock-based, no queue
  if tokens > 0:
    tokens -= 1
    return true
  return false
```

**Time Complexity**: **O(1)** per tryConsume
- No queue traversal; clock-based token math

**Space Complexity**: **O(1)** per bucket
- Last refill timestamp + current tokens

**Note**: No queuing; requests either succeed or fail immediately. Appropriate for strict rate enforcement (refuse-fast on limit) rather than fair queueing.

---

### 6. Per-Account Refresh Serialization (TIN-1851)

**Location**: `src/repair_state.zig:378-414`

Mutual exclusion via OS file locks:
```
acquireRepairLock(provider, account, nonblocking):
  path = ~/.cache/oauth-mux/repair-locks/provider-account.lock
  file = createFileAbsolute(path, {
    .lock = .exclusive,
    .lock_nonblocking = nonblocking
  })
  write metadata (started_at) to file
  return RepairLock { file, path }
```

**Time Complexity**: 
- Lock acquire: **O(1)** (kernel op)
- Lock contention: **blocking or error.WouldBlock** (immediate, no retry loop in the tool itself)

**Space Complexity**: **O(1)** per lock
- Single file handle + path string

**Safety**: Ensures only one refresh runs per (provider, account) pair. No deadlock risk (single lock per account). Scope is well-defined: prevents concurrent token refresh that would lose state.

---

### 7. Repair Event JSONL Scan + Handoff Queue Replay

**Location**: `src/repair_state.zig:98-124, 186-241`

Pending handoff state rebuilt via full file scan:
```
hasPendingHandoff(key: HandoffKey):
  bytes = file.readToEndAlloc(events_path, 1MB)
  pending = false
  for each line in bytes.split('\n'):
    trimmed = trim(line)
    if eventLineMatchesKind(trimmed, "daemon_handoff"):
      if isQueuedHandoffEvent(trimmed):
        pending = true if route matches key
      else if eventResolvesHandoff(trimmed):
        pending = false if route matches key
  return pending
```

**Time Complexity**: **O(m)** where m = |events file lines|
- Single-pass scan; no index
- File readToEndAlloc: O(m) I/O + O(m) memory
- **Pathological risk**: Events file grows unbounded; each check re-reads entire file

**Space Complexity**: **O(m)** 
- Full file into memory: up to 1 MB cap
- Pending queue: O(p) where p ≤ m (filtered list)

**Concern**: **SUPERLINEAR RISK** — Repeated calls to hasPendingHandoff() scale linearly with total events ever recorded. If repair.log logs every daemon handoff ever attempted, file grows indefinitely and every poll stalls. Mitigation: rotate log, index pending state, or move to transactional event store.

---

### 8. Handoff Route Key Matching (JSON Field Parsing)

**Location**: `src/repair_state.zig:288-300, 317-360`

Compare pending handoff against incoming key:
```
eventRouteKeyMatches(a, b):
  return eventOptionalFieldEquals(a, b, "profile") &&
         eventOptionalFieldEquals(a, b, "provider") &&
         eventOptionalFieldEquals(a, b, "account") &&
         eventOptionalFieldEquals(a, b, "capability")

eventFieldString(line, field):
  search for "field": in JSON
  extract quoted value
  return substring
```

**Time Complexity**: **O(1)** per field if line length is bounded
- String search + regex extraction: O(line_len)
- **Issue**: No JSON parser; ad-hoc string scanning
- Repeated scans across all lines: O(m·line_len)

**Space Complexity**: **O(1)** per comparison
- No auxiliary allocation beyond substrings

**Risk**: Hand-written JSON parsing is fragile and O(n) without tokenization. Recommend JSON streaming parser or structured event store.

---

### 9. SHA256-12hex Account ID Dedup

**Location**: `src/main.zig:773-779`

Identity compression:
```
shortSha256HexAlloc(account_id):
  digest = Sha256.hash(account_id)
  hex_out = bufPrint(digest[0..6], "{x}")  // first 6 bytes → 12 hex chars
  return hex_out  // "660d25a9d7ee"
```

**Time Complexity**: **O(1)**
- SHA256: constant time (~ns per call on modern CPU)
- hex encode: O(6) = O(1)

**Space Complexity**: **O(1)**
- Output: 12-byte string
- Temporary: 32-byte digest + 12-byte buf = O(1)

**Design**: Non-reversible identifier for account dedup in inventory telemetry. 12 hex = 48-bit collision space; acceptable for dedup (birthday bound ~16M before 50% collision).

---

### 10. Wire Proxy Serve Loop: Request Routing + Retry

**Location**: `src/adapters/codex/wire_proxy.zig:432-722`

Single-request routing with same-turn retry:
```
serveOne():
  req = parseRequest(reader)
  attempted = []
  while True:
    elected = electProxyRouteAfterTimeRefresh(pool, profile, attempted, now)
    tokens = materialize(elected.id)
    out_headers = buildOutboundHeaders(req, tokens)
    status_class = forwardAndStream(req, out_headers)
    
    if should_retry(status_class.classification):
      attempted.append(elected.id)
      continue
    else:
      break
  return response
```

**Time Complexity**: 
- Per attempt: **O(n)** elect + **O(k)** header build + **O(r)** response classify
  - n = pool size
  - k = header count (constant, ~50)
  - r = response size (can be large for streaming 200/streaming OK; small for buffered 4xx)
- Worst case r retries: **O(r·(n + k + r))** = **O(r·n + r²)**
  - Example: 10 retries × 100 accounts = 1000 elections; network I/O dominates in practice

**Space Complexity**:
- Arena allocator per request: O(r·(headers + attempted_list))
  - Buffered response (4xx/5xx only): O(64 KiB cap)
  - Attempted list: O(r) entries

**Design Note**: Same-turn retry is *inline* (no queue), so reattempt is synchronous. Helps account swap within a single Codex turn without blocking. Risk: If upstream is slow, all retries serialize (no pipelining).

---

### 11. Account Exclusion on Retry

**Location**: `src/adapters/codex/wire_proxy.zig:472-576`

Attempted account tracking:
```
attempted = ArrayListUnmanaged([]const u8){}

loop:
  elected = pool.elect(profile, null, attempted.items)  // O(n)
  attempted.append(elected.id)
  // if retry:
  //   continue; next elect skips all in attempted[]
```

**Time Complexity**:
- Per election: **O(n)** scan of pool + **O(r)** scan of attempted list
  - Worst case r retries: **O(r·(n + r))**

**Space Complexity**: **O(r)** for attempted list

**Optimization opportunity**: Pre-sort pool by availability or use a bitmask for tried accounts if n is bounded and small (< 64).

---

### 12. Health Store Passive Recovery (Score Decay)

**Location**: `src/health.zig:439-451`

Opportunistic health score recovery:
```
passiveRecovery():
  for each health in accounts.values():
    elapsed_hours = floor((now - last_updated) / 3600)
    if elapsed_hours > 0:
      score += decay_per_hour * min(elapsed_hours, 100)
      score.clamp()
```

**Time Complexity**: **O(n)**
- Iterate all entries; no sorting or priority structure
- Called once per poll iteration or explicit recovery trigger

**Space Complexity**: **O(1)**

**Note**: Cap at 100 hours prevents integer overflow and limits max recovery. Not called in hot path; safe for correctness.

---

### 13. Health Store Serialization (Persist to JSON)

**Location**: `src/health.zig:484-535`

Atomic write of HealthStore state:
```
persist():
  path = ~/.cache/oauth-mux/health.json
  file = createFileAbsolute(path, {.truncate = true})
  writeJson(file.writer(), self)
  // manual JSON generation, not std.json

fn writeJson(writer, store):
  for each entry in accounts.iterator():
    write JSON object: key, score, circuit_state, liveness, etc.
```

**Time Complexity**: **O(n·s)** where s = avg size per entry
- Iterate all accounts + serialize each as JSON string
- Manual JSON generation (no buffer overhead if streaming)

**Space Complexity**: **O(n·s)** 
- JSON file size; no in-memory buffer (streaming write if file-backed)

**Frequency**: On-demand (not per-request); typically called during shutdown or periodic checkpoints.

---

## Complexity Summary Table

| Pattern | Location | Time Big-O | Space Big-O | Risk Level |
|---------|----------|-----------|------------|-----------|
| Route Election | account_pool.zig:187 | O(n) | O(1) | Medium |
| Time-Based Refresh | account_pool.zig:155 | O(n) per call | O(1) | Medium |
| HealthStore Lookup | health.zig:245 | O(1) amortized | O(n) entries | Low |
| Circuit Breaker | health.zig:284 | O(1) | O(1) | Low |
| Token Bucket | health.zig:436 | O(1) | O(1) | Low |
| Repair Lock | repair_state.zig:378 | O(1) blocking | O(1) | Low |
| Handoff Queue Scan | repair_state.zig:98 | O(m) file size | O(m) buffer | **HIGH** |
| Route Key Match | repair_state.zig:288 | O(line_len) | O(1) | Medium |
| SHA256-12hex | main.zig:773 | O(1) | O(1) | Low |
| Proxy Serve Loop | wire_proxy.zig:432 | O(r·n) retries | O(r) + 64KiB | Medium |
| Account Exclusion | wire_proxy.zig:472 | O(r·n + r²) | O(r) list | Medium |
| Passive Recovery | health.zig:439 | O(n) | O(1) | Low |
| Health Persist | health.zig:484 | O(n·s) | O(n·s) | Low |

---

## Scaling Concerns & Recommendations

### 1. **Events File Growth (CRITICAL)**
- **Issue**: `repair_state.zig` appends JSONL indefinitely; `hasPendingHandoff()` re-reads entire file per check
- **Current State**: 1 MB file cap; no rotation or index
- **Recommendation**: 
  - Implement log rotation (e.g., split at 100MB, keep last 10 files)
  - Add in-memory pending queue index (update on append, not on read)
  - Or move to transactional event store (e.g., SQLite) with indexed pending state

### 2. **Account Pool Scan**
- **Issue**: `refreshTimeBased()` O(n) on every serve; `elect()` O(n) per attempt
- **Current State**: No optimization for large pools (e.g., 1000 accounts)
- **Recommendation**:
  - Lazy recovery: only check expiration on election candidates, not all
  - Heap of next_eligible_at timestamps for fast min recovery
  - Pre-filter pool by tier (tier 1 live accounts checked first)

### 3. **HealthStore Unbounded Growth**
- **Issue**: Capability-level entries (provider:account#cap) accumulate without eviction
- **Current State**: No TTL or cleanup
- **Recommendation**:
  - Add LRU or time-based expiration for cold entries
  - Prune in background (post-persist) if entry untouched for 7 days
  - Or switch to limited-size ring buffer per account

### 4. **Wire Proxy Retry Serialization**
- **Issue**: Same-turn retries are synchronous; 3 retries × 30s upstream timeout = 90s stall
- **Current State**: Backoff is 150ms, 500ms (short); no long-term queueing
- **Recommendation**:
  - Add configurable max retries per turn (currently unbounded by pool size)
  - Consider request pipelining for Phase 3+ to avoid serial retry latency

### 5. **Hash Collision on 12-Bit Identity**
- **Issue**: 12 hex chars = 48 bits; ~16M accounts before 50% birthday collision risk
- **Current State**: Acceptable for inventory dedup; not cryptographic
- **Recommendation**: Monitor collision rate in telemetry; extend to 16 chars if needed

---

## Performance Profile (Estimated)

- **Per-request overhead**: ~5–10ms (1 election O(n) scan + header build + classify)
  - Dominated by network I/O, not algorithmic complexity
  - Scanning 100 accounts (linear search) ≈ negligible vs. network latency
- **Per-refresh polling**: ~1ms (O(n) scan, all local)
- **Handoff check on retry**: Up to 50–100ms if events file is 1 MB (worst case O(m))
- **Persist to disk**: ~10–50ms depending on HealthStore size

No pathological O(n²) or O(n³) patterns observed in core request path. Primary risk is **events file unbounded growth** causing O(m) blocking on handoff checks.

---

## Conclusion

The oauth-mux system exhibits **linear complexity** in account pool size and entry counts, with **acceptable amortized performance** for typical deployments (< 100 accounts, < 100K health entries). The **critical risk** is in repair event log accumulation, which should be addressed with log rotation or indexing. All core algorithmic patterns (circuit breaker, token bucket, route election) are **O(1) or O(n) with small constants**, making the system scalable to mid-sized deployments. For 10K+ accounts or 1M+ events, consider the recommendations above.
