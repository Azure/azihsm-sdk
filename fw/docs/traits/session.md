# HsmSessionManager — Session Allocation and State

**Crate:** `azihsm_fw_hsm_pal_traits`
**File:** `fw/pal/traits/src/session.rs`

## Overview

The session manager trait handles allocation, deletion, and state tracking of authenticated user sessions within a partition. Each partition supports up to 8 concurrent sessions.

## Types

```rust
pub enum HsmSessionState {
    Free,       // Slot is available
    Active,     // Session is in use
}
```

### SessionGuard

An RAII guard returned by `session_create` that auto-deletes the session if dropped without calling `dismiss()`:

```rust
pub struct SessionGuard<'a, P: HsmVault + HsmSessionManager + ?Sized> {
    pal: &'a P,
    pid: HsmPartId,
    sess_id: Option<HsmSessId>,
}
```

| Method | Description |
|--------|-------------|
| `sess_id()` | Returns the session ID |
| `dismiss()` | Commits the session — it persists after the guard is dropped |

## Trait Definition

```rust
pub trait HsmSessionManager {
    fn session_limit_reached(&self, pid: HsmPartId) -> bool;

    fn session_create(
        &self, pid: HsmPartId,
    ) -> HsmResult<SessionGuard<'_, Self>>;

    fn session_delete(&self, pid: HsmPartId, id: HsmSessId) -> HsmResult<()>;

    fn session_state(&self, pid: HsmPartId, id: HsmSessId) -> HsmSessionState;
}
```

| Method | Description |
|--------|-------------|
| `session_limit_reached` | Returns `true` if all 8 session slots are occupied |
| `session_create` | Allocates a new session slot, returns a guard |
| `session_delete` | Frees a session slot and deletes all session-scoped vault keys |
| `session_state` | Queries whether a session slot is `Free` or `Active` |

## Session-Scoped Keys

Keys created with `session_id = Some(id)` in `vault_key_create` are automatically deleted when the session is closed (via `vault_key_delete_by_session`).
