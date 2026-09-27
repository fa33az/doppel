# Security Policy

doppel is a security tool, so this file covers two different things: bugs *in
doppel*, and what to do when doppel points you at a vulnerable contract.

## Reporting a vulnerability in doppel

Please **don't open a public issue.** Use GitHub's private reporting instead:
go to the [Security tab](https://github.com/fa33az/doppel/security) and click
**Report a vulnerability**.

Examples of what counts:

- crafted bytecode or RPC responses that crash doppel, hang it, or make it
  read or write files it shouldn't
- a way to make doppel report two contracts as unrelated when they share
  code (or the reverse) on purpose, e.g. an evasion technique
- anything in the published npm package that doesn't match this repository

Please include the doppel version (`doppel --version`), the command you ran,
and the input, or the smallest input that reproduces it.

What to expect: an acknowledgement within a few days, and a fix or a clear
answer on whether it's in scope. We'll agree on a disclosure date together,
and credit you in the release notes unless you'd rather stay anonymous.

### Supported versions

| version | supported |
|---|---|
| 0.2.x | yes |
| < 0.2 | no |

## If doppel finds a vulnerable twin

doppel will sometimes tell you that a live contract, holding real money, shares
code with something that was just exploited. When that happens:

1. **Verify before you raise the alarm.** A high score means shared code, not a
   confirmed bug. Check whether the vulnerable path is actually reachable with
   that deployment's configuration.
2. **Tell the owners privately and quickly.** Use the project's security
   contact or `security.txt`, its bug bounty program if it has one, or
   [SEAL 911](https://github.com/security-alliance/seal-911) if you can't reach
   anyone and funds are at immediate risk.
3. **Don't disclose publicly** until the owners have had a chance to act.
4. **Don't touch the funds.** Testing an exploit against a live contract you
   don't own can be illegal even if you mean well, and it can trigger the very
   loss you're trying to prevent.

doppel is meant for defenders: incident responders, auditors, whitehats and
protocol teams. Using it to find targets to attack is not a supported use, and
contributions that push it in that direction won't be accepted.
