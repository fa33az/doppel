#!/usr/bin/env node
/**
 * doppel — find the vulnerable twins of a hacked contract.
 *
 * Commands:
 *   doppel fingerprint <source>              Print a contract's fingerprint.
 *   doppel compare <sourceA> <sourceB>       Score similarity of two contracts.
 *   doppel scan <known> <candidate...>       Rank candidates against a known-bad contract.
 *
 * A <source> is one of:
 *   0x60806040...          raw runtime bytecode hex
 *   ./path/to/code.hex     a file containing hex
 *   chain:address          fetch on-chain, e.g. ethereum:0xABC...  base:0xDEF...
 *
 * Flags:
 *   --json                 machine-readable output
 *   --threshold <0..1>     scan: exit non-zero if any candidate scores >= this
 *   --raw                  do not strip the Solidity metadata trailer
 *
 * doppel never executes bytecode and never produces exploits. It reads code
 * and reports structural kinship, so responders can warn the owners of the
 * twins. That is the entire job.
 */

import { readFileSync } from "node:fs";
import { fingerprint, type FingerprintOptions } from "./fingerprint.js";
import { compare } from "./similarity.js";
import { fetchBytecode } from "./fetch.js";

const HEX_RE = /^(0x)?[0-9a-fA-F]+$/;

interface Flags {
  json: boolean;
  raw: boolean;
  threshold: number;
}

/** Pull flags out of argv, returning the leftover positional args. */
function parseFlags(argv: string[]): { positional: string[]; flags: Flags } {
  const positional: string[] = [];
  const flags: Flags = { json: false, raw: false, threshold: 0.75 };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--json") flags.json = true;
    else if (a === "--raw") flags.raw = true;
    else if (a === "--threshold") flags.threshold = parseFloat(argv[++i]);
    else positional.push(a);
  }
  return { positional, flags };
}

/** Resolve a <source> argument to bytecode hex. */
async function resolveSource(src: string): Promise<string> {
  // chain:address
  if (src.includes(":") && !src.startsWith("0x")) {
    const idx = src.indexOf(":");
    const chain = src.slice(0, idx);
    const address = src.slice(idx + 1);
    if (/^0x[0-9a-fA-F]{40}$/.test(address)) {
      return fetchBytecode(chain, address);
    }
  }
  // raw hex
  if (HEX_RE.test(src) && src.length > 8) return src;
  // file
  try {
    return readFileSync(src, "utf8").trim();
  } catch {
    throw new Error(
      `Could not read source "${src}". Use raw hex, a file path, or chain:address.`
    );
  }
}

function bar(x: number, width = 24): string {
  const filled = Math.round(x * width);
  return "█".repeat(filled) + "░".repeat(width - filled);
}

function pct(x: number): string {
  return `${(x * 100).toFixed(1)}%`;
}

function verdict(total: number): string {
  if (total >= 0.9) return "TWIN — almost certainly the same code";
  if (total >= 0.75) return "LIKELY FORK — shares core logic";
  if (total >= 0.5) return "RELATED — notable shared structure";
  return "UNRELATED";
}

async function cmdFingerprint(src: string, flags: Flags) {
  const fpOpts: FingerprintOptions = { stripMeta: !flags.raw };
  const fp = fingerprint(await resolveSource(src), fpOpts);
  if (flags.json) {
    console.log(
      JSON.stringify(
        {
          instructionCount: fp.instructionCount,
          selectors: [...fp.selectors].map((s) => "0x" + s),
          ngramCount: fp.ngrams.size,
          topOpcodes: Object.fromEntries(
            Object.entries(fp.opcodeHistogram).sort((a, b) => b[1] - a[1])
          ),
        },
        null,
        2
      )
    );
    return;
  }
  console.log(`instructions : ${fp.instructionCount}`);
  console.log(`selectors    : ${fp.selectors.size}`);
  console.log(`4-grams      : ${fp.ngrams.size}`);
  const top = Object.entries(fp.opcodeHistogram)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([k, v]) => `${k}=${pct(v)}`)
    .join("  ");
  console.log(`top opcodes  : ${top}`);
  if (fp.selectors.size) {
    console.log(
      `selector list: ${[...fp.selectors].map((s) => "0x" + s).join(" ")}`
    );
  }
}

async function cmdCompare(a: string, b: string, flags: Flags) {
  const fpOpts: FingerprintOptions = { stripMeta: !flags.raw };
  const [fa, fb] = await Promise.all([
    resolveSource(a).then((h) => fingerprint(h, fpOpts)),
    resolveSource(b).then((h) => fingerprint(h, fpOpts)),
  ]);
  const s = compare(fa, fb);
  if (flags.json) {
    console.log(
      JSON.stringify(
        {
          a,
          b,
          verdict: verdict(s.total).split(" — ")[0],
          score: s.total,
          breakdown: {
            opcodes: s.histogram,
            ngrams: s.ngram,
            selectors: s.selector,
          },
          sharedSelectors: s.sharedSelectors.map((x) => "0x" + x),
        },
        null,
        2
      )
    );
    return;
  }
  console.log("");
  console.log(`  overall   ${bar(s.total)}  ${pct(s.total)}`);
  console.log(`  opcodes   ${bar(s.histogram)}  ${pct(s.histogram)}`);
  console.log(`  4-grams   ${bar(s.ngram)}  ${pct(s.ngram)}`);
  console.log(`  selectors ${bar(s.selector)}  ${pct(s.selector)}`);
  console.log("");
  console.log(`  ${verdict(s.total)}`);
  if (s.sharedSelectors.length) {
    console.log(
      `  shared selectors: ${s.sharedSelectors
        .map((x) => "0x" + x)
        .join(" ")}`
    );
  }
  console.log("");
}

async function cmdScan(known: string, candidates: string[], flags: Flags) {
  const fpOpts: FingerprintOptions = { stripMeta: !flags.raw };
  const base = fingerprint(await resolveSource(known), fpOpts);
  const rows: { src: string; total: number; ngram: number; error?: string }[] =
    [];
  for (const c of candidates) {
    try {
      const fp = fingerprint(await resolveSource(c), fpOpts);
      const s = compare(base, fp);
      rows.push({ src: c, total: s.total, ngram: s.ngram });
    } catch (e) {
      rows.push({ src: c, total: -1, ngram: -1, error: (e as Error).message });
    }
  }
  rows.sort((a, b) => b.total - a.total);

  const hits = rows.filter((r) => r.total >= flags.threshold);

  if (flags.json) {
    console.log(
      JSON.stringify(
        {
          known,
          threshold: flags.threshold,
          matches: hits.length,
          results: rows.map((r) => ({
            source: r.src,
            score: r.total < 0 ? null : r.total,
            verdict: r.total < 0 ? "ERROR" : verdict(r.total).split(" — ")[0],
            error: r.error,
          })),
        },
        null,
        2
      )
    );
  } else {
    console.log("");
    console.log(`  known-vulnerable: ${known}`);
    console.log(`  ${"—".repeat(60)}`);
    for (const r of rows) {
      if (r.total < 0) {
        console.log(`  ${"·".repeat(18)}  ERROR   ${r.src}  (${r.error})`);
        continue;
      }
      console.log(
        `  ${bar(r.total, 18)} ${pct(r.total).padStart(6)}  ${verdict(r.total)
          .split(" — ")[0]
          .padEnd(13)}  ${r.src}`
      );
    }
    console.log("");
    if (hits.length) {
      console.log(
        `  ⚠ ${hits.length} candidate(s) at or above ${pct(
          flags.threshold
        )} — warn their owners.`
      );
      console.log("");
    }
  }

  // CI-friendly: non-zero exit when a likely twin is found.
  if (hits.length) process.exitCode = 2;
}

function usage() {
  console.log(`doppel — find the vulnerable twins of a hacked contract

USAGE
  doppel fingerprint <source>            [--json] [--raw]
  doppel compare <sourceA> <sourceB>     [--json] [--raw]
  doppel scan <known> <candidate...>     [--json] [--raw] [--threshold 0.75]

<source>
  0x60806040...        raw runtime bytecode hex
  ./code.hex           file containing hex
  chain:address        fetch on-chain (ethereum:0x..  base:0x..  bsc:0x..)

EXAMPLES
  doppel compare ./examples/vault_a.hex ./examples/vault_b.hex
  doppel scan ethereum:0xVICTIM base:0xTWIN1 bsc:0xTWIN2 --threshold 0.85

scan exits with code 2 when any candidate scores >= threshold, so it drops
straight into CI. doppel reads code and reports structural kinship — it never
executes bytecode and never generates exploits.`);
}

async function main() {
  const { positional, flags } = parseFlags(process.argv.slice(2));
  const [cmd, ...rest] = positional;
  try {
    switch (cmd) {
      case "fingerprint":
        if (!rest[0]) return usage();
        return await cmdFingerprint(rest[0], flags);
      case "compare":
        if (rest.length < 2) return usage();
        return await cmdCompare(rest[0], rest[1], flags);
      case "scan":
        if (rest.length < 2) return usage();
        return await cmdScan(rest[0], rest.slice(1), flags);
      default:
        return usage();
    }
  } catch (e) {
    console.error(`error: ${(e as Error).message}`);
    process.exit(1);
  }
}

main();
