// Browser-side verifier for the server's Merkle delivery proofs.
// Mirrors backend/app/merkle.py exactly: same domain separators, same
// level-by-level tree with the fixed odd-level last-node duplication.

import { sha256Bytes } from "./sha256";

export const MERKLE_ALGORITHM = "merkle-sha256-v1";
export const LEAF_DOMAIN = "cryo-seal-desk/merkle/v1/leaf:";
export const NODE_DOMAIN = "cryo-seal-desk/merkle/v1/node:";

const encoder = new TextEncoder();

export function hexToBytes(hex: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error(`bad hex digest: ${hex}`);
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function u64be(value: number): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(value));
  return out;
}

function hashParts(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const joined = new Uint8Array(total);
  let at = 0;
  for (const p of parts) {
    joined.set(p, at);
    at += p.length;
  }
  return sha256Bytes(joined.buffer);
}

export function leafHash(
  index: number,
  length: number,
  chunkDigestHex: string
): Uint8Array {
  return hashParts([
    encoder.encode(LEAF_DOMAIN),
    u64be(index),
    u64be(length),
    hexToBytes(chunkDigestHex),
  ]);
}

export function nodeHash(left: Uint8Array, right: Uint8Array): Uint8Array {
  return hashParts([encoder.encode(NODE_DOMAIN), left, right]);
}

function levelWidth(leafCount: number, level: number): number {
  return Math.ceil(leafCount / 2 ** level);
}

function treeHeight(leafCount: number): number {
  // level of the root: smallest k with 2^k >= leafCount
  let k = 0;
  while (2 ** k < leafCount) k++;
  return k;
}

export interface RebuildResult {
  rootHex: string;
  consumed: number;
}

/**
 * Rebuild the Merkle root for `leafCount` leaves from the owned range
 * [start, end] (digests/lengths aligned to `start`) plus the sibling proof,
 * consumed in the server's deterministic pre-order.
 */
export function rebuildRoot(
  leafCount: number,
  start: number,
  end: number,
  chunkDigestsHex: string[],
  chunkLengths: number[],
  proofHex: string[]
): RebuildResult {
  const leaves = new Map<number, Uint8Array>();
  for (let i = 0; i < chunkDigestsHex.length; i++) {
    leaves.set(start + i, leafHash(start + i, chunkLengths[i], chunkDigestsHex[i]));
  }
  const proof = proofHex.map(hexToBytes);
  let pos = 0;

  const fromOwned = (level: number, index: number): Uint8Array => {
    if (level === 0) {
      const h = leaves.get(index);
      if (!h) throw new Error(`missing owned leaf ${index}`);
      return h;
    }
    const left = fromOwned(level - 1, 2 * index);
    const right =
      2 * index + 1 < levelWidth(leafCount, level - 1)
        ? fromOwned(level - 1, 2 * index + 1)
        : left; // fixed odd-level duplication
    return nodeHash(left, right);
  };

  const rebuild = (level: number, index: number): Uint8Array => {
    const lo = index * 2 ** level;
    const hi = Math.min((index + 1) * 2 ** level, leafCount) - 1;
    if (hi < start || lo > end) {
      if (pos >= proof.length) throw new Error("sibling proof is too short");
      return proof[pos++];
    }
    if (start <= lo && hi <= end) return fromOwned(level, index);
    const left = rebuild(level - 1, 2 * index);
    const right =
      2 * index + 1 < levelWidth(leafCount, level - 1)
        ? rebuild(level - 1, 2 * index + 1)
        : left;
    return nodeHash(left, right);
  };

  const root = rebuild(treeHeight(leafCount), 0);
  return { rootHex: bytesToHex(root), consumed: pos };
}
