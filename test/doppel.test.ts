import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { disassemble, minimalProxyTarget, stripMetadata } from "../src/bytecode.js";
import { functionEntries } from "../src/cfg.js";
import { fingerprint } from "../src/fingerprint.js";
import { labelFor, parseFunction } from "../src/signatures.js";
import { compare, compareFunction } from "../src/similarity.js";

const dir = new URL("../examples/mainnet/", import.meta.url);
const hex = (f: string) => readFileSync(new URL(f, dir), "utf8").trim();
const fp = (f: string) => fingerprint(hex(f));
const manifest: { contracts: { file: string; family: string }[] } = JSON.parse(
  readFileSync(new URL("manifest.json", dir), "utf8")
);

const SWAP = "022c0d9f"; // swap(uint256,uint256,address,bytes)

// ── bytecode ────────────────────────────────────────────────────────────────

test("disassemble consumes PUSH immediates instead of reading them as opcodes", () => {
  const instrs = disassemble("0x61dead00"); // PUSH2 0xdead, STOP
  assert.deepEqual(instrs.map((i) => i.name), ["PUSH2", "STOP"]);
  assert.equal(instrs[0].push, "dead");
});

test("stripMetadata removes bzzr0, bzzr1 and ipfs-style trailers and nothing else", () => {
  for (const f of ["weth9.hex", "uniswap-v2-pair.hex", "aave-v3-pool.hex"]) {
    const full = hex(f).replace(/^0x/, "");
    const stripped = stripMetadata(full);
    const trailer = full.slice(stripped.length);
    assert.ok(stripped.length < full.length, `${f}: should shrink`);
    assert.match(trailer, /^a[0-9a-f]/, `${f}: trailer should start with a CBOR map`);
    assert.ok(trailer.length / 2 < 100, `${f}: trailer should be short`);
  }
  assert.equal(stripMetadata("6080604052"), "6080604052");
});

test("minimalProxyTarget sees through EIP-1167 and ERC-7511 stubs", () => {
  const target = "bebebebebebebebebebebebebebebebebebebebe";
  assert.deepEqual(
    minimalProxyTarget(`0x363d3d373d3d3d363d73${target}5af43d82803e903d91602b57fd5bf3`),
    { kind: "eip-1167", target: `0x${target}` }
  );
  assert.deepEqual(
    minimalProxyTarget(`365f5f375f5f365f73${target}5af43d5f5f3e5f3d91602a57fd5bf3`),
    { kind: "erc-7511", target: `0x${target}` }
  );
  assert.equal(minimalProxyTarget(hex("weth9.hex")), null);
});

// ── dispatcher & signatures ─────────────────────────────────────────────────

test("finds every external function of the Uniswap V2 pair", () => {
  const entries = functionEntries(disassemble(stripMetadata(hex("uniswap-v2-pair.hex"))));
  assert.equal(entries.size, 27);
  assert.ok(entries.has(SWAP));
  assert.ok(entries.has("0902f1ac")); // getReserves()
});

test("selectors resolve to names and --fn accepts both forms", () => {
  assert.equal(labelFor(SWAP), "swap(uint256,uint256,address,bytes)");
  assert.equal(labelFor("deadbeef"), "0xdeadbeef");
  assert.equal(parseFunction("swap(uint256,uint256,address,bytes)"), SWAP);
  assert.equal(parseFunction("0x022C0D9F"), SWAP);
  assert.throws(() => parseFunction("swap"));
});

// ── scoring ─────────────────────────────────────────────────────────────────

test("a contract compared with itself scores 1.0", () => {
  assert.equal(compare(fp("dai.hex"), fp("dai.hex")).total, 1);
});

test("the same code redeployed on another chain is a TWIN", () => {
  const s = compare(fp("uniswap-v2-pair.hex"), fp("uniswap-v2-pair.base.hex"));
  assert.ok(s.total > 0.99, `got ${s.total}`);
});

test("a fork built with a different compiler still ranks far above unrelated code", () => {
  const uni = fp("uniswap-v2-pair.hex");
  const sushi = compare(uni, fp("sushiswap-pair.hex")).total; // solc 0.6.12 vs 0.5.16
  const usdc = compare(uni, fp("usdc-implementation.hex")).total;
  assert.ok(sushi > 0.6, `sushi ${sushi}`);
  assert.ok(usdc < 0.2, `usdc ${usdc}`);
});

test("per-function scores: swap() is shared by forks and absent elsewhere", () => {
  const uni = fp("uniswap-v2-pair.hex");
  assert.ok(compareFunction(uni, fp("biswap-pair.bsc.hex"), SWAP)! > 0.9);
  assert.equal(compareFunction(uni, fp("weth9.hex"), SWAP), null);
});

test("benchmark: every labeled fork pair clears 0.3, every unrelated pair stays under", () => {
  const prints = new Map(manifest.contracts.map((c) => [c.file, fp(c.file)]));
  const cs = manifest.contracts;
  const misses: string[] = [];
  for (let i = 0; i < cs.length; i++) {
    for (let j = i + 1; j < cs.length; j++) {
      const score = compare(prints.get(cs[i].file)!, prints.get(cs[j].file)!).total;
      const fork = cs[i].family === cs[j].family;
      if (fork !== score >= 0.3) misses.push(`${cs[i].file} ~ ${cs[j].file}: ${score.toFixed(3)}`);
    }
  }
  assert.deepEqual(misses, []);
});

// ── cli ─────────────────────────────────────────────────────────────────────

const root = fileURLToPath(new URL("..", import.meta.url));
function cli(args: string[]): { code: number; out: string } {
  try {
    const out = execFileSync(process.execPath, ["--import", "tsx", "src/cli.ts", ...args], {
      cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"],
    });
    return { code: 0, out };
  } catch (e) {
    const err = e as { status: number; stdout: string };
    return { code: err.status, out: err.stdout };
  }
}

test("cli scan exits 2 with JSON when a fork is found, 0 when nothing matches", () => {
  const m = "examples/mainnet/";
  const hit = cli(["scan", m + "uniswap-v2-pair.hex", m + "sushiswap-pair.hex", m + "dai.hex", "--json"]);
  assert.equal(hit.code, 2);
  const report = JSON.parse(hit.out);
  assert.equal(report.matches, 1);
  assert.equal(report.results[0].source, m + "sushiswap-pair.hex");

  const miss = cli(["scan", m + "uniswap-v2-pair.hex", m + "dai.hex", m + "weth9.hex", "--json"]);
  assert.equal(miss.code, 0);
  assert.equal(JSON.parse(miss.out).matches, 0);
});

test("cli rejects bad input with exit 1", () => {
  assert.equal(cli(["scan", "nope.hex", "also-nope.hex"]).code, 1);
  assert.equal(cli(["scan", "examples/mainnet/dai.hex", "examples/mainnet/weth9.hex", "--threshold", "7"]).code, 1);
});
