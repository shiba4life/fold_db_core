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

```rust
use fold_db_core::{FoldEngine, AccessContext, Fold, Field, FieldValue, SecurityLabel, TrustDistancePolicy};

let mut engine = FoldEngine::new();

// Create a fold with a field
let fold = Fold::new("my_fold", "owner_alice", vec![
    Field::new(
        "email",
        FieldValue::String("alice@example.com".to_string()),
        SecurityLabel::new(2, "PII"),
        TrustDistancePolicy::new(0, 1), // W0 R1: only owner writes, trust ≤ 1 reads
    ),
]);
engine.registry.register_fold(fold).unwrap();

// Owner assigns trust
engine.trust_graph.assign_trust("owner_alice", "bob", 1);

// Bob queries — gets the projection
let ctx = AccessContext::new("bob", 1);
let result = engine.query("my_fold", &ctx);
assert!(result.is_some());

// Stranger queries — gets Nothing
let ctx = AccessContext::new("stranger", 5);
let result = engine.query("my_fold", &ctx);
assert!(result.is_none());
```

## Build & Test

```bash
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
```

## License

MIT
