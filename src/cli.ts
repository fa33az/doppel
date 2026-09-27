#!/usr/bin/env node
// SPDX-License-Identifier: MIT
/**
 * doppel — find the vulnerable twins of a hacked contract.
 *
 * doppel never executes bytecode and never produces exploits. It reads code
 * and reports structural kinship, so responders can warn the owners of the
 * twins. That is the entire job.
 */

import { readFileSync } from "node:fs";
import { minimalProxyTarget } from "./bytecode.js";
import { fetchResolved, type ProxyHop } from "./fetch.js";
import { fingerprint, type Fingerprint } from "./fingerprint.js";
import { labelFor, parseFunction } from "./signatures.js";
import { compare, compareFunction } from "./similarity.js";

const VERSION = "0.2.0";

// Calibrated on examples/mainnet (npm run benchmark): every labeled fork pair
// scored >= 0.38, every unrelated pair <= 0.25.
const DEFAULT_THRESHOLD = 0.3;

interface Flags {
  json: boolean;
  raw: boolean;
  proxies: boolean;
  all: boolean;
  threshold: number;
  fn?: string;
}

function parseArgs(argv: string[]): { positional: string[]; flags: Flags } {
  const positional: string[] = [];
  const flags: Flags = { json: false, raw: false, proxies: true, all: false, threshold: DEFAULT_THRESHOLD };
  const value = (i: number, name: string) => {
    const v = argv[i];
    if (v === undefined) throw new Error(`${name} needs a value`);
    return v;
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--json") flags.json = true;
    else if (a === "--raw") flags.raw = true;
    else if (a === "--no-proxy") flags.proxies = false;
    else if (a === "--all") flags.all = true;
    else if (a === "--fn") flags.fn = parseFunction(value(++i, "--fn"));
    else if (a === "--threshold") {
      flags.threshold = Number(value(++i, "--threshold"));
      if (!(flags.threshold >= 0 && flags.threshold <= 1)) {
        throw new Error("--threshold must be between 0 and 1");
      }
    } else if (a === "-v" || a === "--version") positional.unshift("version");
    else if (a === "-h" || a === "--help") positional.unshift("help");
    else if (a.startsWith("--")) throw new Error(`unknown flag ${a}`);
    else positional.push(a);
  }
  return { positional, flags };
}

// ─── sources ────────────────────────────────────────────────────────────────

interface Source {
  label: string;
  hex: string;
  hops: ProxyHop[];
}

const CHAIN_ADDR = /^([a-z0-9-]+|https?:\/\/[^\s]+):(0x[0-9a-fA-F]{40})$/;

/** Resolve a <source> argument to bytecode. */
async function loadSource(src: string, flags: Flags): Promise<Source> {
  const m = src.match(CHAIN_ADDR);
  if (m) {
    const r = await fetchResolved(m[1], m[2], { followProxies: flags.proxies });
    return { label: src, hex: r.bytecode, hops: r.hops };
  }
  let hex: string;
  if (/^(0x)?[0-9a-fA-F]+$/.test(src) && src.length > 8) hex = src;
  else {
    try {
      hex = readFileSync(src, "utf8").trim();
    } catch {
      throw new Error(`can't read "${src}" — use raw hex, a file path, or chain:address`);
    }
  }
  const stub = minimalProxyTarget(hex);
  if (stub && flags.proxies) {
    warn(
      `${src} is an ${stub.kind} proxy stub for ${stub.target}. ` +
        `Every clone looks identical — fingerprint the implementation instead ` +
        `(chain:${stub.target}).`
    );
  }
  return { label: src, hex, hops: [] };
}

/** Expand `@file` arguments into one source per non-empty, non-# line. */
function expandLists(args: string[]): string[] {
  return args.flatMap((a) => {
    if (!a.startsWith("@")) return [a];
    return readFileSync(a.slice(1), "utf8")
      .split("\n")
      .map((l) => l.replace(/#.*/, "").trim())
      .filter(Boolean);
  });
}

/** Run `fn` over `items` with at most `limit` in flight, preserving order. */
async function mapLimit<T, R>(items: T[], limit: number, fn: (x: T) => Promise<R>): Promise<R[]> {
  const out = new Array<R>(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}

// ─── output helpers ─────────────────────────────────────────────────────────

const color = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code: number) => (s: string) => (color ? `\x1b[${code}m${s}\x1b[0m` : s);
const dim = paint(2);
const bold = paint(1);
const red = paint(31);
const yellow = paint(33);
const green = paint(32);

function warn(msg: string) {
  console.error(yellow(`warning: ${msg}`));
}

function bar(x: number, width = 20): string {
  const filled = Math.round(Math.max(0, Math.min(1, x)) * width);
  return "█".repeat(filled) + dim("░".repeat(width - filled));
}

const pct = (x: number) => `${(x * 100).toFixed(1)}%`.padStart(6);

type Verdict = "TWIN" | "LIKELY FORK" | "RELATED" | "UNRELATED";

function verdictOf(total: number): Verdict {
  if (total >= 0.85) return "TWIN";
  if (total >= 0.45) return "LIKELY FORK";
  if (total >= DEFAULT_THRESHOLD) return "RELATED";
  return "UNRELATED";
}

const VERDICT_TEXT: Record<Verdict, string> = {
  TWIN: "same code, redeployed or recompiled",
  "LIKELY FORK": "same core logic, some changes",
  RELATED: "heavily modified fork, or a close cousin — worth a look",
  UNRELATED: "different code",
};

function paintVerdict(v: Verdict, pad = 0): string {
  const s = v.padEnd(pad);
  if (v === "TWIN") return red(bold(s));
  if (v === "LIKELY FORK") return red(s);
  if (v === "RELATED") return yellow(s);
  return dim(s);
}

function describeHops(hops: ProxyHop[]): string {
  return hops.map((h) => `${h.kind} → ${h.implementation}`).join(" → ");
}

// ─── commands ───────────────────────────────────────────────────────────────

async function cmdFingerprint(src: string, flags: Flags) {
  const s = await loadSource(src, flags);
  const fp = fingerprint(s.hex, { stripMeta: !flags.raw });
  const functions = [...fp.selectors].map((sel) => ({
    selector: "0x" + sel,
    name: labelFor(sel),
    size: fp.functions.get(sel)?.size ?? 0,
  }));
  if (flags.json) {
    print({ source: s.label, proxy: s.hops, instructions: fp.instructionCount,
      semanticInstructions: fp.semanticCount, basicBlocks: fp.blockCount,
      grams: fp.grams.size, functions });
    return;
  }
  console.log("");
  console.log(`  ${bold(s.label)}`);
  if (s.hops.length) console.log(dim(`  via ${describeHops(s.hops)}`));
  console.log("");
  console.log(`  instructions  ${fp.instructionCount} ${dim(`(${fp.semanticCount} doing real work)`)}`);
  console.log(`  basic blocks  ${fp.blockCount}`);
  console.log(`  3-grams       ${fp.grams.size}`);
  console.log("");
  console.log(`  functions (${functions.length})`);
  for (const f of functions.sort((a, b) => a.name.localeCompare(b.name))) {
    console.log(`    ${dim(f.selector)}  ${f.name.padEnd(44)} ${dim(`${f.size} ops`)}`);
  }
  console.log("");
}

async function cmdCompare(a: string, b: string, flags: Flags) {
  const [sa, sb] = await Promise.all([loadSource(a, flags), loadSource(b, flags)]);
  const opts = { stripMeta: !flags.raw };
  const s = compare(fingerprint(sa.hex, opts), fingerprint(sb.hex, opts));
  const verdict = verdictOf(s.total);

  if (flags.json) {
    print({
      a: { source: sa.label, proxy: sa.hops },
      b: { source: sb.label, proxy: sb.hops },
      verdict,
      score: round(s.total),
      breakdown: {
        functions: s.functionsScore === null ? null : round(s.functionsScore),
        code: round(s.code),
        selectors: round(s.selector),
      },
      functions: s.functions.map((f) => ({ selector: "0x" + f.selector, name: labelFor(f.selector), score: round(f.score) })),
      onlyInA: s.onlyInA.map((x) => ({ selector: "0x" + x, name: labelFor(x) })),
      onlyInB: s.onlyInB.map((x) => ({ selector: "0x" + x, name: labelFor(x) })),
    });
    return;
  }

  console.log("");
  console.log(`  ${dim("a")}  ${sa.label}`);
  if (sa.hops.length) console.log(dim(`     via ${describeHops(sa.hops)}`));
  console.log(`  ${dim("b")}  ${sb.label}`);
  if (sb.hops.length) console.log(dim(`     via ${describeHops(sb.hops)}`));
  console.log("");
  console.log(`  overall    ${bar(s.total)} ${pct(s.total)}   ${paintVerdict(verdict)} ${dim("— " + VERDICT_TEXT[verdict])}`);
  if (s.functionsScore !== null) {
    console.log(`  functions  ${bar(s.functionsScore)} ${pct(s.functionsScore)}   ${dim("each function vs. its namesake")}`);
  }
  console.log(`  code       ${bar(s.code)} ${pct(s.code)}   ${dim("whole-contract logic")}`);
  console.log(`  selectors  ${bar(s.selector)} ${pct(s.selector)}   ${dim("same ABI surface")}`);
  console.log("");

  if (s.functions.length || s.onlyInA.length || s.onlyInB.length) {
    console.log(
      `  functions  ${s.functions.length} shared ${dim("·")} ${s.onlyInA.length} only in a ${dim("·")} ${s.onlyInB.length} only in b`
    );
    const shown = flags.all ? s.functions : s.functions.slice(0, 15);
    for (const f of shown) {
      console.log(`    ${bar(f.score, 12)} ${pct(f.score)}  ${labelFor(f.selector)}`);
    }
    if (shown.length < s.functions.length) {
      console.log(dim(`    … ${s.functions.length - shown.length} more (--all)`));
    }
    const extra = (tag: string, list: string[]) => {
      if (!list.length) return;
      const names = list.map(labelFor);
      const head = flags.all ? names : names.slice(0, 6);
      console.log(dim(`    ${tag}: ${head.join(", ")}${head.length < names.length ? ", …" : ""}`));
    };
    extra("only in a", s.onlyInA);
    extra("only in b", s.onlyInB);
    console.log("");
  }
}

interface ScanRow {
  source: string;
  proxy: ProxyHop[];
  score: number | null;
  fnScore?: number | null;
  verdict?: Verdict;
  error?: string;
}

async function cmdScan(known: string, rawCandidates: string[], flags: Flags) {
  const candidates = expandLists(rawCandidates);
  if (!candidates.length) throw new Error("no candidates to scan");
  const opts = { stripMeta: !flags.raw };

  const victim = await loadSource(known, flags);
  const base = fingerprint(victim.hex, opts);
  if (flags.fn && !base.functions.has(flags.fn) && !base.selectors.has(flags.fn)) {
    throw new Error(`${labelFor(flags.fn)} isn't a function of ${known}`);
  }

  const rows = await mapLimit(candidates, 4, async (c): Promise<ScanRow> => {
    try {
      const src = await loadSource(c, flags);
      const fp: Fingerprint = fingerprint(src.hex, opts);
      const s = compare(base, fp);
      const row: ScanRow = { source: c, proxy: src.hops, score: s.total, verdict: verdictOf(s.total) };
      if (flags.fn) row.fnScore = compareFunction(base, fp, flags.fn);
      return row;
    } catch (e) {
      return { source: c, proxy: [], score: null, error: (e as Error).message };
    }
  });

  // Rank by the function under suspicion when one is given, else overall.
  const key = (r: ScanRow) => (flags.fn ? r.fnScore ?? -1 : r.score ?? -1);
  rows.sort((x, y) => key(y) - key(x) || (y.score ?? -1) - (x.score ?? -1));
  const hits = rows.filter((r) => r.score !== null && key(r) >= flags.threshold);

  if (flags.json) {
    print({
      known: { source: known, proxy: victim.hops },
      function: flags.fn ? { selector: "0x" + flags.fn, name: labelFor(flags.fn) } : undefined,
      threshold: flags.threshold,
      matches: hits.length,
      results: rows.map((r) => ({
        source: r.source,
        proxy: r.proxy.length ? r.proxy : undefined,
        score: r.score === null ? null : round(r.score),
        functionScore: r.fnScore === undefined ? undefined : r.fnScore === null ? null : round(r.fnScore),
        verdict: r.verdict ?? "ERROR",
        error: r.error,
      })),
    });
  } else {
    console.log("");
    console.log(`  known  ${bold(known)}`);
    if (victim.hops.length) console.log(dim(`         via ${describeHops(victim.hops)}`));
    if (flags.fn) console.log(`  ranking by ${bold(labelFor(flags.fn))}`);
    console.log("");
    console.log(dim(`  ${flags.fn ? "function".padEnd(21) : ""}${"overall".padEnd(21)}verdict      candidate`));
    console.log(dim(`  ${"─".repeat(72)}`));
    for (const r of rows) {
      if (r.score === null) {
        console.log(`  ${red("error".padEnd(flags.fn ? 53 : 32))}  ${r.source}  ${dim(r.error ?? "")}`);
        continue;
      }
      const fnCol = flags.fn
        ? r.fnScore === null
          ? `${dim("missing".padEnd(12))} ${"".padStart(6)}  `
          : `${bar(r.fnScore!, 12)} ${pct(r.fnScore!)}  `
        : "";
      console.log(`  ${fnCol}${bar(r.score, 12)} ${pct(r.score)}  ${paintVerdict(r.verdict!, 11)}  ${r.source}`);
      if (r.proxy.length) console.log(dim(`  ${" ".repeat(flags.fn ? 55 : 34)}via ${describeHops(r.proxy)}`));
    }
    console.log("");
    if (hits.length) {
      const what = flags.fn ? `the same ${labelFor(flags.fn)}` : "forks of it";
      console.log(red(`  ${hits.length} of ${rows.length} candidates ${flags.fn ? "have" : "look like"} ${what} (≥ ${(flags.threshold * 100).toFixed(0)}%).`));
    } else {
      console.log(green(`  nothing above ${(flags.threshold * 100).toFixed(0)}%.`));
    }
    console.log("");
  }

  // CI-friendly: exit 2 when something matched, 1 on errors only.
  if (hits.length) process.exitCode = 2;
}

async function cmdDump(src: string, flags: Flags) {
  const s = await loadSource(src, flags);
  if (s.hops.length) console.error(dim(`via ${describeHops(s.hops)}`));
  console.log(s.hex);
}

// ─── entry ──────────────────────────────────────────────────────────────────

const round = (x: number) => Math.round(x * 10000) / 10000;
const print = (x: unknown) => console.log(JSON.stringify(x, null, 2));

function usage() {
  console.log(`doppel ${VERSION} — find the vulnerable twins of a hacked contract

USAGE
  doppel scan <known> <candidate...>   rank candidates against a known-bad contract
  doppel compare <a> <b>               side-by-side, down to individual functions
  doppel fingerprint <source>          what doppel sees in one contract
  doppel dump <source>                 print resolved bytecode (for fixtures)

SOURCES
  ethereum:0x…         fetch live (ethereum, base, arbitrum, optimism,
  bsc:0x…              polygon, bsc, avalanche, or https://rpc:0x…)
  ./code.hex           a file with hex bytecode
  0x6080…              raw hex
  @list.txt            (scan) one source per line, # for comments

OPTIONS
  --fn <sig|selector>  rank by one function, e.g. --fn "withdraw(uint256)"
  --threshold <0..1>   what counts as a match (default ${DEFAULT_THRESHOLD})
  --json               machine-readable output
  --all                list every function in compare
  --no-proxy           don't look through proxies
  --raw                keep the solidity metadata trailer

EXIT CODES
  0 nothing matched · 1 error · 2 at least one candidate matched

RPCs default to publicnode.com; override with DOPPEL_RPC_<CHAIN>=https://…

doppel only reads code. It never executes bytecode or builds exploits.`);
}

async function main() {
  try {
    const { positional, flags } = parseArgs(process.argv.slice(2));
    const [cmd, ...rest] = positional;
    switch (cmd) {
      case "fingerprint":
        if (rest.length !== 1) return usage();
        return await cmdFingerprint(rest[0], flags);
      case "compare":
        if (rest.length !== 2) return usage();
        return await cmdCompare(rest[0], rest[1], flags);
      case "scan":
        if (rest.length < 2) return usage();
        return await cmdScan(rest[0], rest.slice(1), flags);
      case "dump":
        if (rest.length !== 1) return usage();
        return await cmdDump(rest[0], flags);
      case "version":
        return console.log(VERSION);
      default:
        return usage();
    }
  } catch (e) {
    console.error(red(`error: ${(e as Error).message}`));
    process.exit(1);
  }
}

main();
