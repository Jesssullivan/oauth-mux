# ADR-005 — Encrypted custody and native runtime

Status: ratified direction, 2026-10-02; experimental and unshipped.

**Existing user decision.** SQLite holds metadata and ciphertext grants; encrypt before insertion, including journal/backup writes. macOS Keychain or Linux Secret Service holds the wrapping key. A missing/locked key never replaces an existing database's key; no plaintext fallback exists. Controls receive redacted metadata and opaque handles; narrowly scoped materialization is restricted to trusted adapter channels.

**Implementation choice.** Fresh official Zig 0.17.0 is the reset's verified pin. Bounded `std.Io.Threaded` work, a libcurl multi owner and SQLite writer queue implement custody/transport ownership. SQLite, libcurl and required native libraries are intentional locked dependencies; predecessor zero-C constraints are superseded. Private sockets, peer-user checks and bounded revisioned messages protect local interfaces.

**Acceptance / unresolved proof.** Fixture ciphertext, lost-key and ABI checks remain separate from real OS-vault IO. The [subsequent safety receipts](../implementation/native-safety-evidence-2026-10-03.md) record genuine isolated Linux Secret Service, private macOS Keychain driver IO and installed Linux daemon/Qt predicates, plus independent SQLite-only rollback fencing. Personal-session access control, production Darwin custody, OS-service lifecycle, provider rotation and complete platform diagnostic/journal/backup acceptance still require their stated gates. Full-user rollback is outside the implemented fence. Future compiler upgrades require verified official inputs, not an unpinned “latest” dependency.

Authority: [reset, custody and toolchain](../plans/omux-native-account-lifecycle-reset-2026-10-02.md); [locked flake](../../flake.lock); [evidence](../implementation/native-reset-evidence-2026-10-02.md). Related: [ADR-007](007-local-declared-execution.md).
