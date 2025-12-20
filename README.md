# incognito-program

Minimal, purpose-limited Solana program for a Tornado-style privacy pool:

`deposit(commitment)` → prove membership + nullifier → `action_withdraw(proof, nullifierHash, destination)`.

## Design

### Multi-pool model (mint + denomination)

Each pool is uniquely identified by `(mint, denomination)`:

- `state` PDA seeds: `["state", mint, denomination_le_u64]`
- `vault` PDA seeds: `["vault", state]` (TokenAccount owned by `state`)
- `nullifier` PDA seeds: `["nullifier", state, nullifierHash]` (prevents double-spend per pool)

### ZK statement (v0 circuit)

Groth16 over BN254, verified on-chain using Solana `alt_bn128` syscalls.

The proof verifies:

- Merkle membership (commitment is in the tree for this pool root)
- Knowledge of `secret` + `nullifier`
- Correct `nullifierHash = Poseidon(nullifier)` derivation

Public inputs:

- `root` (on-chain stored)
- `nullifierHash`

### Merkle tree strategy

- Append-only tree
- Witness generation off-chain
- On-chain stores only the current `merkle_root`
- A relayer/indexer updates the root using `set_root`

## Instructions

- `initialize_pool(denomination, initial_root, root_updater)`
- `deposit(commitment)` (1 note)
- `deposit_many(commitments)` (max 20 notes; single token transfer of `denomination * N`)
- `set_root(new_root)` (only `root_updater`)
- `action_withdraw(proof, nullifier_hash)` (creates nullifier PDA + transfers `denomination` from vault)

## Build & Deploy

Prereqs:

- Solana CLI
- Anchor CLI

Build:

```bash
cd incognito-program
anchor build
```

Deploy to devnet:

```bash
cd incognito-program
anchor deploy --provider.cluster devnet
```

## Generating a new program id (recommended for your own deployment)

Do **not** commit keypairs.

1. Generate a new keypair:

```bash
solana-keygen new --no-bip39-passphrase -o target/deploy/incognito_program-keypair.json
```

2. Update:

- `programs/incognito_program/src/lib.rs` (`declare_id!`)
- `Anchor.toml` (`[programs.*].incognito_program`)

3. Rebuild + deploy:

```bash
anchor build
anchor deploy --provider.cluster devnet
```

## Security notes

- Amounts are **not** hidden; privacy goal is unlinkability between depositor and destination.
- Privacy depends on pool usage volume and relayer behavior (timing/correlation still possible).
- This code is not audited **yet**.

