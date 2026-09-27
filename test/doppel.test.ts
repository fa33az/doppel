import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { disassemble, stripMetadata } from "../src/bytecode.js";
import { fingerprint } from "../src/fingerprint.js";
import { compare } from "../src/similarity.js";

const read = (p: string) => readFileSync(new URL(p, import.meta.url), "utf8").trim();
const vaultA = read("../examples/vault_a.hex");
const vaultB = read("../examples/vault_b.hex");
const unrelated = read("../examples/unrelated.hex");

test("disassemble consumes PUSH immediates, not mistaking them for opcodes", () => {
  // PUSH2 0xdead then STOP  -> two instructions, not four
  const instrs = disassemble("0x61dead00");
  assert.equal(instrs.length, 2);
  assert.equal(instrs[0].name, "PUSH2");
  assert.equal(instrs[0].push, "dead");
  assert.equal(instrs[1].name, "STOP");
});

test("stripMetadata removes a valid CBOR trailer and leaves code untouched otherwise", () => {
  const stripped = stripMetadata(vaultA);
  assert.ok(stripped.length < vaultA.replace(/^0x/, "").length, "should shrink");
  // No trailer present -> unchanged
  const plain = "60806040";
  assert.equal(stripMetadata(plain), plain);
});

test("a fork scores as a TWIN (>= 0.9)", () => {
  const s = compare(fingerprint(vaultA), fingerprint(vaultB));
  assert.ok(s.total >= 0.9, `expected >=0.9, got ${s.total}`);
  assert.deepEqual(s.sharedSelectors.sort(), ["2e1a7d4d", "70a08231", "b6b55f25"]);
});

test("an unrelated contract scores low (< 0.5)", () => {
  const s = compare(fingerprint(vaultA), fingerprint(unrelated));
  assert.ok(s.total < 0.5, `expected <0.5, got ${s.total}`);
  assert.equal(s.selector, 0, "shares no selectors");
});

test("comparing a contract to itself is 1.0", () => {
  const s = compare(fingerprint(vaultA), fingerprint(vaultA));
  assert.equal(s.total, 1);
});
