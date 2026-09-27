# doppel

**Find the vulnerable twins of a hacked smart contract — across chains, before attackers do.**

When one contract gets exploited, its **forks and clones** usually share the exact
same flaw. Attackers already know this: they grep the chains for copies and hit
them one by one. Defenders have no easy way to do the same in reverse.

`doppel` closes that gap. Point it at a contract that just got hit, hand it a list
of candidates, and it ranks them by how much of the *vulnerable code* they share —
so responders can warn the owners of the twins.

```
  known-vulnerable: ethereum:0xVICTIM
  ————————————————————————————————————————————————————————————
  ██████████████████ 96.4%  TWIN           base:0x1f2e...
  █████████████░░░░░ 74.6%  RELATED        bsc:0x88ab...
  ████░░░░░░░░░░░░░░ 21.5%  UNRELATED      arbitrum:0xdead...
```

> `doppel` **reads code and reports structural kinship. It never executes
> bytecode and never generates exploits.** It is a defensive triage tool for
> whitehats and protocol teams.

---

## Why it works

A fork keeps the logic but changes the cosmetics: the compiler metadata hash,
constructor args, embedded addresses, a few constants. So `doppel` fingerprints
the **shape** of the code, not the bytes:

| Signal | What it captures | How compared |
|---|---|---|
| **Opcode histogram** | overall instruction mix | cosine similarity |
| **Opcode 4-grams** | control-flow shape | Jaccard |
| **Function selectors** | ABI surface (recovered from `PUSH4 … EQ`) | Jaccard |

The three are blended (weighted toward 4-grams, the hardest thing to match by
accident). A superficial re-deploy scores near `1.0`; an unrelated contract near `0`.

## Install

```bash
git clone https://github.com/<you>/doppel && cd doppel
npm install
```

## Usage

A `<source>` is raw bytecode hex, a file of hex, or `chain:address` (fetched live):

```bash
# Compare two contracts you already have
npx tsx src/cli.ts compare ./examples/vault_a.hex ./examples/vault_b.hex

# Fetch live bytecode and scan candidates against a victim
npx tsx src/cli.ts scan ethereum:0xVICTIM base:0xTWIN1 bsc:0xTWIN2

# Inspect a single contract's fingerprint
npx tsx src/cli.ts fingerprint ethereum:0xCONTRACT
```

Supported chain shortcuts: `ethereum`, `base`, `arbitrum`, `optimism`,
`polygon`, `bsc`, `avalanche` — or pass any RPC URL.

### Scripting & CI

`scan` speaks JSON and sets its exit code, so it drops straight into a pipeline:

```bash
npx tsx src/cli.ts scan ethereum:0xVICTIM base:0xTWIN --json --threshold 0.85
# exit code 2 => at least one candidate is at/above the threshold
```

Flags: `--json` (machine output), `--threshold <0..1>` (match cutoff for scan),
`--raw` (skip metadata stripping).

## Try the demo

```bash
npx tsx src/cli.ts scan examples/vault_a.hex examples/vault_b.hex examples/unrelated.hex
```

`vault_b` is a fork of `vault_a` (same logic, different constants + metadata);
`unrelated` is a different contract. `doppel` tells them apart.

## Roadmap

- [x] Strip Solidity CBOR metadata trailer before fingerprinting
- [x] `--json` output, `--threshold`, and CI-friendly exit codes
- [ ] Basic-block CFG hashing for order-independent matching
- [ ] Bulk discovery: given one address, auto-crawl candidates via 4byte + explorer APIs
- [ ] Optional local-fork confirmation harness (Foundry `anvil`) that a shared code path is reachable — **read-only, no exploitation**

## How this compares to existing tools

Real-time exploit monitors (Forta, Hypernative) tell you *you* were hit.
On-chain logic search (Hexens Glider) finds similar code but doesn't rank against
a specific victim for triage. `doppel` is the small, open, scriptable piece in
between: *"this one is bleeding — who else has the same wound?"*

## License

MIT
