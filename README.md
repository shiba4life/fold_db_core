# fold_db_core

Core Rust library implementing the formal model from [Fold DB: Compute Without Exposure](https://folddb.com/papers/fold_db_paper.pdf).

Fold DB is a database in which data is never accessed directly. Users interact with **folds** — named interfaces that sit in front of stored values and enforce access policies on every operation. Each fold defines which fields are visible, what transformations are applied, and who may read or write, using four conjunctive mechanisms:

1. **Trust distance** — owner-assigned distances with transitive propagation
2. **Cryptographic capabilities** — bounded quotas tied to public keys
3. **Security labels** — lattice-based information flow control
4. **Payment gates** — economic safeguards with configurable cost functions

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
│  (folds, │ (append- │   (every  │  (graph   │
│ transforms)│  only)  │  access)  │ distance) │
└──────────┴──────────┴───────────┴───────────┘
```

| Module | Paper Section | What it does |
|--------|:---:|---|
| `api/` | — | Public API: serializable request/response types, history, rollback |
| `types/` | §3.1 | Fold, Field, FieldValue, AccessContext, SecurityLabel, TrustDistancePolicy |
| `access/trust.rs` | §4.1 | Additive trust distances, shortest-path resolution, overrides, revocation |
| `access/capability.rs` | §4.2 | WX_k / RX_k capabilities with bounded quotas |
| `access/payment.rs` | §4.4 | Payment gates (linear, exponential, fixed) |
| `engine/` | §3.2, §3.4 | Monadic execution with all-or-nothing failure, fold composition via DAG |
| `transform/` | §3.3, §8 | Reversible/irreversible transforms, content-addressed registry |
| `store/` | §6 | Append-only store with full version history |
| `audit/` | §6 | Immutable audit log of all access events |
| `registry/` | §6, §8 | Fold registry + Universal Transform Registry with cycle detection |

## Usage

`FoldDbApi` is the primary interface. All request/response types are serializable.

```rust
use fold_db_core::api::*;
use fold_db_core::types::{AccessContext, FieldValue, SecurityLabel, TrustDistancePolicy};

let mut api = FoldDbApi::new();

// Create a fold
api.create_fold(CreateFoldRequest {
    fold_id: "my_fold".to_string(),
    owner_id: "alice".to_string(),
    fields: vec![FieldDef {
        name: "email".to_string(),
        value: FieldValue::String("alice@example.com".to_string()),
        label: SecurityLabel::new(2, "PII"),
        policy: TrustDistancePolicy::new(0, 1), // W0 R1
        capabilities: vec![],
        transform_id: None,
        source_fold_id: None,
        source_field_name: None,
    }],
    payment_gate: None,
}).unwrap();

// Assign trust
api.assign_trust("alice", "bob", 1);

// Bob queries — gets the projection
let resp = api.query_fold(QueryRequest {
    fold_id: "my_fold".to_string(),
    context: AccessContext::new("bob", 1),
});
assert!(resp.fields.is_some());

// Stranger queries — gets Nothing
let resp = api.query_fold(QueryRequest {
    fold_id: "my_fold".to_string(),
    context: AccessContext::new("stranger", 5),
});
assert!(resp.fields.is_none());
```

### Trust distance resolution

When a trust graph entry exists for the caller, the engine automatically resolves their trust distance from the graph, overriding the value in `AccessContext.trust_distance`. This means the graph is the source of truth — the context field is only used as a fallback when no graph path exists.

## Build & Test

```bash
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
```

## License

MIT
