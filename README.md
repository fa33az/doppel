<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-dark.svg">
    <img src="assets/logo-light.svg" alt="doppel" width="300">
  </picture>
</p>

<p align="center"><em>Find the vulnerable twins of a hacked smart contract, across chains, before attackers do.</em></p>

<p align="center">
  <a href="https://github.com/fa33az/doppel/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/fa33az/doppel/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://www.npmjs.com/package/doppel-scan"><img alt="npm" src="https://img.shields.io/npm/v/doppel-scan"></a>
  <a href="LICENSE"><img alt="MIT License" src="https://img.shields.io/badge/license-MIT-blue"></a>
  <img alt="Node 18+" src="https://img.shields.io/badge/node-%E2%89%A518-339933">
  <a href="CONTRIBUTING.md"><img alt="Contributions welcome" src="https://img.shields.io/badge/contributions-welcome-orange"></a>
</p>

When a contract gets drained, the bug rarely lives in just one place. DeFi code
gets forked constantly, and a fork inherits its parent's bugs along with
everything else. Compound v2 forks got hit one after another through the same
empty-market rounding trick (Hundred Finance, Onyx, Sonne...). Attackers know
this and work down the list.

doppel lets defenders run that list first. Give it the contract that just got
hit and a pile of candidates, and it tells you which ones are running the same
code, down to the individual function.

```
$ doppel scan ethereum:0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc \
    ethereum:0x397F…ACa0 bsc:0x58F8…Dc16 polygon:0xd899…6268 avalanche:0xE4B9…fB46 \
    bsc:0xDA8c…04cF ethereum:0x88e6…5640 ethereum:0xA0b8…eB48 ethereum:0x6B17…1d0F

  known  ethereum:0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc

  overall              verdict      candidate
  ────────────────────────────────────────────────────────────────────────
  ████████████ 100.0%  TWIN         polygon:0xd899e25F21222ABE4E6212a7aDb26190B5976268
  ███████████░  91.3%  TWIN         bsc:0xDA8ceb724A06819c0A5cDb4304ea0cB27F8304cF
  █████████░░░  75.8%  LIKELY FORK  ethereum:0x397FF1542f962076d0BFE58eA045FfA2d347ACa0
  █████████░░░  73.8%  LIKELY FORK  avalanche:0xE4B9865C0866346BA3613eC122040A365637fB46
  ███████░░░░░  57.9%  LIKELY FORK  bsc:0x58F876857a02D6762E0101bb5C46A8c1ED44Dc16
  ██░░░░░░░░░░  12.9%  UNRELATED    ethereum:0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48
                                    via zeppelinos → 0x43506849D7C04F9138D1A2050bbF3A0c054402dd
  █░░░░░░░░░░░  11.2%  UNRELATED    ethereum:0x6B175474E89094C44Da98b954EedeAC495271d0F
  █░░░░░░░░░░░   6.1%  UNRELATED    ethereum:0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640

  5 of 8 candidates look like forks of it (≥ 30%).
```

That's the Uniswap V2 USDC/WETH pair scanned against QuickSwap (Polygon), Biswap
(BSC), SushiSwap (Ethereum), Trader Joe (Avalanche) and PancakeSwap (BSC) pairs,
plus USDC, DAI and a Uniswap V3 pool as controls. Every fork lands on top, the
controls fall off a cliff, and USDC's proxy is looked through automatically.

doppel only reads code. It never executes bytecode and never builds exploits.
It's a triage tool for whitehats, auditors and protocol teams.

## Install

```bash
npm install -g doppel-scan
```

or from source:

```bash
git clone https://github.com/fa33az/doppel && cd doppel
npm install          # also builds dist/
node dist/cli.js --help
```

Node 18 or newer.

## Usage

### "The bug is in this function. Who else has it?"

Most of the time you know where the bug is. `--fn` ranks candidates by how
closely *that function* matches, not the contract as a whole:

```
$ doppel scan uniswap-v2-pair.hex sushiswap-pair.hex pancakeswap-v2-pair.bsc.hex \
    biswap-pair.bsc.hex traderjoe-v1-pair.avalanche.hex weth9.hex dai.hex \
    --fn "swap(uint256,uint256,address,bytes)"

  function             overall              verdict      candidate
  ────────────────────────────────────────────────────────────────────────
  ████████████  97.1%  ███████████░  91.3%  TWIN         biswap-pair.bsc.hex
  ██████████░░  84.5%  █████████░░░  75.8%  LIKELY FORK  sushiswap-pair.hex
  ██████████░░  80.3%  █████████░░░  73.8%  LIKELY FORK  traderjoe-v1-pair.avalanche.hex
  ████████░░░░  66.5%  ███████░░░░░  57.9%  LIKELY FORK  pancakeswap-v2-pair.bsc.hex
  missing              █░░░░░░░░░░░  11.2%  UNRELATED    dai.hex
  missing              █░░░░░░░░░░░   9.0%  UNRELATED    weth9.hex
```

PancakeSwap scores lower on `swap()` because it changed the fee math there.
That's exactly the kind of difference you want to see before deciding who to
warn.

### Side by side

`compare` breaks the score down per function, so you can see what a fork kept
and what it changed:

```
$ doppel compare uniswap-v2-pair.hex sushiswap-pair.hex

  overall    ███████████████░░░░░  75.8%   LIKELY FORK — same core logic, some changes
  functions  ████████████████░░░░  78.4%   each function vs. its namesake
  code       ██████████████░░░░░░  69.9%   whole-contract logic
  selectors  ████████████████████ 100.0%   same ABI surface

  functions  27 shared · 0 only in a · 0 only in b
    ████████████ 100.0%  MINIMUM_LIQUIDITY()
    ████████████ 100.0%  kLast()
    …
```

### Reference

```
doppel scan <known> <candidate...>   rank candidates against a known-bad contract
doppel compare <a> <b>               side-by-side, down to individual functions
doppel fingerprint <source>          what doppel sees in one contract
doppel dump <source>                 print resolved bytecode (handy for fixtures)
```

A source can be:

| form | example |
|---|---|
| live, on any supported chain | `ethereum:0x…` `base:0x…` `arbitrum:0x…` `optimism:0x…` `polygon:0x…` `bsc:0x…` `avalanche:0x…` |
| live, your own RPC | `https://my-node.example:0x…` |
| a file of hex | `./victim.hex` |
| raw hex | `0x6080…` |
| a list (scan only) | `@candidates.txt`, one source per line, `#` for comments |

| option | |
|---|---|
| `--fn <sig\|selector>` | rank by one function: `--fn "withdraw(uint256)"` or `--fn 0x2e1a7d4d` |
| `--threshold <0..1>` | what counts as a match (default `0.3`) |
| `--json` | machine-readable output |
| `--all` | list every function in `compare` |
| `--no-proxy` | don't look through proxies |
| `--raw` | keep the Solidity metadata trailer |

Exit codes: `0` nothing matched, `1` error, `2` at least one match. So this
works as a CI gate or in a cron job as is:

```bash
doppel scan ethereum:0xVICTIM @watchlist.txt --json > report.json || notify-team
```

RPCs default to publicnode.com. Set `DOPPEL_RPC_ETHEREUM=https://…` (or
`_BASE`, `_BSC`, …) to use your own.

## How it works

**Proxies first.** Thousands of unrelated contracts share the exact same
EIP-1167 or ERC-1967 proxy stub, so comparing stubs is useless. doppel follows
minimal proxies, the ERC-1967 implementation and beacon slots, EIP-1822, the old
zeppelinos slot (USDC), and anything that delegatecalls and answers
`implementation()` (Compound's `CErc20Delegator`), up to four hops deep.

**Then it throws away the noise.** Forks change addresses, immutables, fee
constants and the metadata hash, and they're often built with a different
compiler, which reshuffles how values move around the stack. So doppel strips
the metadata trailer and drops pure stack plumbing (`PUSH`, `DUP`, `SWAP`,
`POP`, `JUMPDEST`), keeping only instructions that do real work plus the 4-byte
selectors. It's the same trick binary clone detectors use to ignore register
allocation.

**Then it lines functions up.** doppel reads the dispatcher to find every
external function, walks the control flow from each entry point to collect the
code that function can reach (internal helpers included), and compares each
function with its namesake on the other side. Functions only one side has count
against the score. That's blended 70/30 with a whole-contract comparison, which
also covers contracts whose dispatcher it can't read.

## Benchmark

`examples/mainnet` has real bytecode for 18 contracts from 6 chains, labeled by
family (9 Uniswap V2 style pairs, 2 V2 routers, 2 Compound v2 markets, and 5
unrelated controls). `npm run benchmark` scores all 153 pairs:

```
threshold  precision  recall   f1
   0.25      100.0%   100.0%  1.000
   0.30      100.0%   100.0%  1.000
   0.45      100.0%    97.4%  0.987
   0.75      100.0%    55.3%  0.712

weakest fork             38.8%  Compound cDAI (ethereum) ~ Venus vUSDC (bsc)
strongest unrelated      24.6%  WETH9 ~ DAI
```

To be upfront about it: that's a small set, and the thresholds were picked on
it, so treat it as a sanity check rather than a promise. More labeled families
are the single most useful contribution you could make (see below).

## Limitations

- **Static only.** doppel tells you the code is the same, not that the bug is
  reachable with this deployment's config. A human still has to look.
- **Heavy rewrites slip through.** A fork that refactored the vulnerable
  function will score low on it, even if the bug survived.
- **Solidity-shaped.** Function-level matching expects Solidity's dispatcher.
  Vyper and hand-written contracts fall back to whole-contract scoring.
- **Proxies are resolved as they are today.** If an implementation gets
  upgraded, so does the answer.
- **Public RPCs rate-limit.** For big lists, bring your own node.

## Contributing

Contributions are welcome, and you don't need to be a bytecode expert to make a
useful one. The thing doppel needs most is **more labeled data**: a known
contract, a few of its forks on any chain, and a couple of lookalikes that
*aren't* forks. You can even just [list them in an issue](https://github.com/fa33az/doppel/issues/new?template=new_family.yml)
and someone will add them.

Open areas:

- `doppel hunt <address>`: find candidates automatically (same deployer, same
  selector set, factory children)
- a Vyper dispatcher reader
- a GitHub Action / watch mode for protocols that want to know when a new twin
  of their code shows up

Start with [CONTRIBUTING.md](CONTRIBUTING.md) for setup, project layout and the
ground rules. Everyone taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md).

## Security

Found a bug in doppel itself, or a way to evade it? Please report it privately,
see [SECURITY.md](SECURITY.md). The same file explains what to do when doppel
points you at a live contract that looks vulnerable: verify, tell the owners
privately, and don't touch the funds.

## License

doppel is released under the [MIT License](LICENSE). You can use it, modify
it, and ship it in commercial or closed-source work, as long as the copyright
and license notice stay with it.

Contributions are accepted under the same license (inbound = outbound, see
[CONTRIBUTING.md](CONTRIBUTING.md#licensing-of-contributions)).

Some material in this repository belongs to third parties and keeps its own
terms: the logo is drawn from the Hack typeface (MIT and Bitstream Vera
License), and `examples/mainnet` holds bytecode of publicly deployed contracts
owned by their respective projects, included only as test data. Details in
[NOTICE](NOTICE). doppel is not affiliated with any of the projects named in
this repository.
