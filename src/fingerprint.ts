// SPDX-License-Identifier: MIT
/**
 * Turn disassembled bytecode into a fingerprint that survives the differences
 * between a contract and its forks.
 *
 * Forks rarely match byte for byte. Besides the obvious (metadata hash,
 * addresses, immutables, fee constants) they're often built with a different
 * compiler version or optimizer setting, which reshuffles how values move
 * around the stack. Same logic, very different DUP/SWAP/POP soup.
 *
 * So doppel looks at the *semantic* instruction stream: everything that does
 * work (arithmetic, comparisons, memory, storage, calls, logs, jumps) with the
 * pure stack plumbing (PUSH, DUP, SWAP, POP, JUMPDEST) removed. PUSH4 values
 * stay in, since those are selectors and are part of what the code means.
 * This is the same trick binary clone detectors use to ignore register
 * allocation.
 *
 * From that stream we keep:
 *   - grams      whole-contract set of semantic 3-grams
 *   - selectors  functions the dispatcher routes to
 *   - functions  per selector: the semantic bigrams of everything that
 *                function can reach, plus its size
 */

import {
  disassemble,
  normalizeHex,
  stripMetadata,
  type Instruction,
} from "./bytecode.js";
import { buildCfg, functionEntries, reachable } from "./cfg.js";

export interface FunctionPrint {
  grams: Set<string>;
  /** Semantic instructions in the footprint; used to weight functions. */
  size: number;
}

export interface Fingerprint {
  grams: Set<string>;
  selectors: Set<string>;
  functions: Map<string, FunctionPrint>;
  instructionCount: number;
  semanticCount: number;
  blockCount: number;
}

export interface FingerprintOptions {
  /** Strip the Solidity CBOR metadata trailer first. Default: true. */
  stripMeta?: boolean;
}

const PLUMBING = /^(PUSH\d*|DUP\d+|SWAP\d+|POP|JUMPDEST)$/;

/** The semantic token for an instruction, or null for stack plumbing. */
export function semantic(ins: Instruction): string | null {
  if (ins.name === "PUSH4" && ins.push) return `S:${ins.push}`;
  return PLUMBING.test(ins.name) ? null : ins.name;
}

function semanticOps(instrs: Instruction[]): string[] {
  const out: string[] = [];
  for (const ins of instrs) {
    const s = semantic(ins);
    if (s) out.push(s);
  }
  return out;
}

function ngrams(ops: string[], n: number, into = new Set<string>()): Set<string> {
  if (ops.length && ops.length < n) into.add(ops.join("|"));
  for (let i = 0; i + n <= ops.length; i++) into.add(ops.slice(i, i + n).join("|"));
  return into;
}

/**
 * Fallback for code whose dispatcher we don't recognise (e.g. Vyper): every
 * PUSH4 is a candidate selector. Noisier, but better than nothing.
 */
function push4Selectors(instrs: Instruction[]): Set<string> {
  const out = new Set<string>();
  for (const ins of instrs) {
    if (ins.name === "PUSH4" && ins.push && ins.push !== "00000000" && ins.push !== "ffffffff") {
      out.add(ins.push);
    }
  }
  return out;
}

export function fingerprint(
  bytecodeHex: string,
  opts: FingerprintOptions = {}
): Fingerprint {
  const stripMeta = opts.stripMeta ?? true;
  const clean = stripMeta ? stripMetadata(bytecodeHex) : normalizeHex(bytecodeHex);
  const instrs = disassemble(clean);
  const ops = semanticOps(instrs);
  const cfg = buildCfg(instrs);

  const functions = new Map<string, FunctionPrint>();
  const entries = functionEntries(instrs);
  for (const [selector, entry] of entries) {
    const grams = new Set<string>();
    let size = 0;
    // Bigrams per block, so we never stitch together two blocks that only
    // happen to sit next to each other in the byte layout.
    for (const idx of [...reachable(cfg, entry)].sort((a, b) => a - b)) {
      const blockOps = semanticOps(cfg.blocks[idx].instrs);
      size += blockOps.length;
      ngrams(blockOps, 2, grams);
    }
    functions.set(selector, { grams, size });
  }

  return {
    grams: ngrams(ops, 3),
    selectors: entries.size ? new Set(entries.keys()) : push4Selectors(instrs),
    functions,
    instructionCount: instrs.length,
    semanticCount: ops.length,
    blockCount: cfg.blocks.length,
  };
}
