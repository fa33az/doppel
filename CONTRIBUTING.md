# Contributing to doppel

Thanks for taking a look. doppel is small on purpose, so it's a good codebase
to get into: about a thousand lines of TypeScript, one runtime dependency, and a
test suite that runs against real mainnet bytecode in a few seconds.

## Getting set up

```bash
git clone https://github.com/fa33az/doppel && cd doppel
npm install        # installs deps and builds dist/
npm test           # unit tests + CLI tests + benchmark separability check
npm run benchmark  # full precision/recall report
```

Node 20 or newer for development (the published CLI runs on Node 18+).

Run the CLI straight from source while you work:

```bash
npx tsx src/cli.ts compare examples/mainnet/uniswap-v2-pair.hex examples/mainnet/sushiswap-pair.hex
```

## How the code is laid out

| file | what it does |
|---|---|
| `src/bytecode.ts` | disassembler, metadata stripping, minimal-proxy detection |
| `src/cfg.ts` | basic blocks, dispatcher parsing, per-function reachability |
| `src/fingerprint.ts` | turns bytecode into the features that get compared |
| `src/similarity.ts` | scoring, weights, per-function comparison |
| `src/fetch.ts` | RPC access and proxy resolution |
| `src/signatures.ts` | offline selector → signature table |
| `src/cli.ts` | argument parsing and output |
| `scripts/benchmark.ts` | scores every labeled pair in `examples/mainnet` |

## What helps the most

### 1. New labeled data

This is the single most useful thing you can contribute. The benchmark has 18
contracts in 3 fork families, which is enough to catch regressions but not
enough to trust the thresholds blindly.

A good addition is a **family**: one known contract, a few of its forks
(ideally on different chains, built with different compilers), and one or two
lookalikes that *aren't* forks. Compound v2 and Aave forks, ERC-4626 vaults,
staking contracts and bridges are all underrepresented.

1. Fetch each contract: `npx tsx src/cli.ts dump bsc:0x… > examples/mainnet/name.chain.hex`
2. Add an entry to `examples/mainnet/manifest.json` with `name`, `family`,
   `chain`, `address`, and `implementation` if it was behind a proxy.
3. Run `npm test` and `npm run benchmark`, and paste the benchmark output in the PR.

If a new family breaks the separability test, that's not a reason to hold the
PR back. It's a finding. Open it anyway and say so; it tells us where the model
is wrong.

### 2. Better matching

Changes to `fingerprint.ts` or `similarity.ts` are welcome, with one rule:
**show the numbers.** Include `npm run benchmark` output before and after your
change. A change that makes the demo look nicer but narrows the gap between the
weakest fork and the strongest unrelated pair will be turned down.

### 3. Features from the roadmap

`doppel hunt` (automatic candidate discovery), a Vyper dispatcher reader, and a
GitHub Action or watch mode are all open. For anything bigger than a small fix,
please open an issue first so we can agree on the shape before you spend a
weekend on it.

## Ground rules

- **doppel stays read-only.** It reads bytecode and reports similarity. PRs
  that execute contract code against live chains, build transactions, or
  generate anything resembling an exploit won't be merged, however they're
  framed.
- **No new runtime dependencies** without a discussion first. The install
  should stay small and easy to audit.
- **Keep it offline by default.** The fingerprint and compare path must never
  touch the network. Only `chain:address` sources do.
- **Comments explain why**, not what. Match the style of the file you're in.
- **Tests for behavior changes.** If it changes a score or an output, a test
  should notice.

## Commits and pull requests

- Keep commits focused, with short lowercase messages that say what changed,
  e.g. `read vyper dispatchers` or `fix proxy loop on self-referencing beacon`.
- One topic per PR. Small PRs get reviewed fast; big ones wait.
- Fill in the PR template, especially the benchmark section if scoring changed.
- CI must be green.

## Licensing of contributions

doppel is MIT licensed. By opening a pull request you agree that your
contribution is licensed under the same MIT License as the rest of the project
(see [LICENSE](LICENSE)), and that you have the right to submit it.

Material that isn't yours (bytecode fixtures, data sets, code adapted from
elsewhere) must be clearly identified in the PR and compatible with that. For
bytecode, it must be read from a public chain; list its source in
`manifest.json` so it can be verified and re-fetched. Third-party material is
tracked in [NOTICE](NOTICE).

## Conduct

Everyone taking part is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
For anything security-related, see [SECURITY.md](SECURITY.md) instead of opening
a public issue.
