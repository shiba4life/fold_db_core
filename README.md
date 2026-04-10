# fold_db_core

An experimental minimal reimplementation of the FoldDB core database engine, built from the formal model in [Fold DB: Compute Without Exposure](https://folddb.com/papers/fold_db_paper.pdf).

This is a ground-up rewrite exploring whether the core database can be implemented more minimally. The original [fold_db](https://github.com/shiba4life/fold_db) monolith was split into:
- **fold_db_core** (this repo) — experimental minimal core database engine
- [**fold_db_node**](https://github.com/shiba4life/fold_db_node) — the application/node layer (server, HTTP, agents, UI)

Fold DB is a database in which data is never accessed directly. Users interact with **folds** — named interfaces that sit in front of stored values and enforce access policies on every operation. Each fold defines which fields are visible, what transformations are applied, and who may read or write, using four conjunctive mechanisms:

1. **Trust tiers** — per-domain trust levels (Public, Outer, Trusted, Inner, Owner)
2. **Cryptographic capabilities** — bounded quotas tied to public keys
3. **Security labels** — lattice-based information flow control (for transform validation)
4. **Payment gates** — fixed-cost economic safeguards

## Architecture

```
┌─────────────────────────────────────────────┐
│                 FoldDbApi                    │
│  Unified entry point for all operations     │
├─────────────────────────────────────────────┤
│                 FoldEngine                   │
│  Monadic evaluation: Fold[a] = C → Maybe a  │
├──────────┬──────────┬───────────┬───────────┤
│ Registry │  Store   │   Audit   │   Trust   │
│  (folds, │ (append- │   (every  │  (per-    │
│ transforms)│  only)  │  access)  │  domain)  │
└──────────┴──────────┴───────────┴───────────┘
```

| Module | Paper Section | What it does |
|--------|:---:|---|
| `api/` | — | Public API: serializable request/response types, history, rollback |
| `types/` | §3.1 | Fold, Field, FieldValue, AccessContext, TrustTier, FieldAccessPolicy, SecurityLabel |
| `access/trust.rs` | §4.1 | Per-domain trust tiers, graph resolution, overrides, revocation |
| `access/capability.rs` | §4.2 | WX_k / RX_k capabilities with bounded quotas |
| `access/payment.rs` | §4.4 | Payment gates (fixed cost) |
| `engine/` | §3.2, §3.4 | Monadic execution with all-or-nothing failure, fold composition via DAG |
| `transform/` | §3.3, §8 | Reversible/irreversible transforms, content-addressed registry |
| `store/` | §6 | Append-only store with full version history |
| `audit/` | §6 | Immutable audit log of all access events |
| `registry/` | §6, §8 | Fold registry + Universal Transform Registry with cycle detection |

## Usage

`FoldDbApi` is the primary interface. All request/response types are serializable.

```rust
use fold_db_core::api::*;
use fold_db_core::types::{AccessContext, FieldAccessPolicy, FieldValue, SecurityLabel, TrustTier};

let mut api = FoldDbApi::new();

// Create a fold
api.create_fold(CreateFoldRequest {
    fold_id: "my_fold".to_string(),
    owner_id: "alice".to_string(),
    fields: vec![FieldDef {
        name: "email".to_string(),
        value: FieldValue::String("alice@example.com".to_string()),
        label: SecurityLabel::new(2, "PII"),
        policy: FieldAccessPolicy::new(TrustTier::Owner, TrustTier::Outer), // write: Owner, read: Outer
        capabilities: vec![],
        transform_id: None,
        source_fold_id: None,
        source_field_name: None,
    }],
    payment_gate: None,
}).unwrap();

// Assign trust — bob gets Inner tier in the default domain
api.assign_trust("alice", "bob", TrustTier::Inner);

// Bob queries — Inner(3) >= Outer(1) → gets the projection
let resp = api.query_fold(QueryRequest {
    fold_id: "my_fold".to_string(),
    context: AccessContext::remote_single("bob", "default", TrustTier::Inner),
});
assert!(resp.fields.is_some());

// Stranger queries — Public(0) < Outer(1) → gets Nothing
let resp = api.query_fold(QueryRequest {
    fold_id: "my_fold".to_string(),
    context: AccessContext::remote_single("stranger", "default", TrustTier::Public),
});
assert!(resp.fields.is_none());
```

### Trust tier resolution

When a trust graph entry exists for the caller, the engine resolves their trust tier from the graph, overriding the value in `AccessContext.tiers`. The graph is the source of truth — the context tiers map is only used as a fallback when no graph path exists.

## Build & Test

```bash
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
```

## License

MIT
