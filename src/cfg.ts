// SPDX-License-Identifier: MIT
/**
 * Basic blocks and per-function footprints.
 *
 * Whole-contract similarity answers "is this a fork?". Responders usually need
 * a sharper question answered: "the bug is in withdraw() — does this other
 * contract have the *same* withdraw()?". To get there we:
 *
 *   1. split the code into basic blocks (straight-line runs of instructions)
 *   2. find each external function's entry point from the dispatcher
 *   3. collect every block reachable from that entry — the function's footprint
 *
 * Reachability is static and deliberately over-approximate: besides direct
 * `PUSH label; JUMP(I)` edges we treat any pushed value that lands on a
 * JUMPDEST as a possible edge. That's how Solidity passes return addresses
 * into internal functions, so it pulls in the helpers a function calls.
 */

import type { Instruction } from "./bytecode.js";

const ENDS_BLOCK = new Set([
  "JUMP", "JUMPI", "STOP", "RETURN", "REVERT", "INVALID", "SELFDESTRUCT",
]);
const NO_FALLTHROUGH = new Set([
  "JUMP", "STOP", "RETURN", "REVERT", "INVALID", "SELFDESTRUCT",
]);

export interface Block {
  /** Byte offset of the block's first instruction. */
  start: number;
  instrs: Instruction[];
}

export function basicBlocks(instrs: Instruction[]): Block[] {
  const blocks: Block[] = [];
  let cur: Instruction[] = [];
  const flush = () => {
    if (!cur.length) return;
    blocks.push({ start: cur[0].offset, instrs: cur });
    cur = [];
  };
  for (const ins of instrs) {
    if (ins.name === "JUMPDEST") flush();
    cur.push(ins);
    if (ENDS_BLOCK.has(ins.name)) flush();
  }
  flush();
  return blocks;
}

/**
 * Map each function selector to its entry offset, by matching the dispatcher
 * shape Solidity emits: `PUSH4 <selector> … EQ … PUSH <dest> JUMPI`.
 * Range checks in large binary-search dispatchers use GT/LT instead of EQ, so
 * they're skipped naturally.
 */
export function functionEntries(instrs: Instruction[]): Map<string, number> {
  const entries = new Map<string, number>();
  for (let i = 0; i < instrs.length; i++) {
    const ins = instrs[i];
    if (ins.name !== "PUSH4" || !ins.push) continue;
    let sawEq = false;
    for (let j = i + 1; j < Math.min(i + 6, instrs.length - 1); j++) {
      const a = instrs[j];
      if (a.name === "EQ") sawEq = true;
      if (sawEq && a.push !== undefined && instrs[j + 1].name === "JUMPI") {
        if (!entries.has(ins.push)) entries.set(ins.push, parseInt(a.push, 16));
        break;
      }
    }
  }
  return entries;
}

/** Everything the per-function walk needs, computed once per contract. */
export interface Cfg {
  blocks: Block[];
  indexByStart: Map<number, number>;
  jumpdests: Set<number>;
  /** Push sizes we trust as jump labels. */
  labelBytes: number;
}

export function buildCfg(instrs: Instruction[]): Cfg {
  const blocks = basicBlocks(instrs);
  const indexByStart = new Map<number, number>();
  blocks.forEach((b, i) => indexByStart.set(b.start, i));
  const jumpdests = new Set(
    instrs.filter((i) => i.name === "JUMPDEST").map((i) => i.offset)
  );
  const last = instrs[instrs.length - 1];
  const codeSize = last ? last.offset + 1 : 0;
  // Solidity sizes its labels to the code: PUSH1 for tiny contracts, PUSH2
  // otherwise. Only trusting that size keeps small constants like 0x40 from
  // being mistaken for jump targets.
  return { blocks, indexByStart, jumpdests, labelBytes: codeSize <= 0xff ? 1 : 2 };
}

/** Block indices statically reachable from `entry`. */
export function reachable(cfg: Cfg, entry: number): Set<number> {
  const seen = new Set<number>();
  const todo = [entry];
  while (todo.length) {
    const off = todo.pop()!;
    const idx = cfg.indexByStart.get(off);
    if (idx === undefined || seen.has(idx)) continue;
    seen.add(idx);
    const block = cfg.blocks[idx];

    for (const ins of block.instrs) {
      if (ins.push && ins.push.length === cfg.labelBytes * 2) {
        const target = parseInt(ins.push, 16);
        if (cfg.jumpdests.has(target)) todo.push(target);
      }
    }
    const tail = block.instrs[block.instrs.length - 1];
    if (!NO_FALLTHROUGH.has(tail.name) && idx + 1 < cfg.blocks.length) {
      todo.push(cfg.blocks[idx + 1].start);
    }
  }
  return seen;
}
