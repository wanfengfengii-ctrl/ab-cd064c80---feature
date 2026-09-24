// Local verification of Merkle export proofs.
//
// Mirrors backend/app/merkle.py byte-for-byte:
//   leaf = SHA-256("merkle-leaf:v1:" + canonical JSON {d,i,l})
//   node = SHA-256("merkle-node:v1:" + left(32B) || right(32B))
//   odd level: the lone node is promoted unchanged (no padding hash).
// A receiver rebuilds the root from a block's (index, length, sha256) plus
// its minimal sibling path and compares it with the committed root.

import { sha256Bytes } from "./sha256";
import type { ProofBlock, RangeProof } from "./api";

const LEAF_DOMAIN = "merkle-leaf:v1:";
const NODE_DOMAIN = "merkle-node:v1:";
const HEX_RE = /^[0-9a-f]{64}$/;

function toHex(view: Uint8Array): string {
  return Array.from(view, (b) => b.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex: string): Uint8Array {
  if (!HEX_RE.test(hex)) throw new Error("摘要必须是 64 位小写十六进制");
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

async function sha256HexOf(bytes: Uint8Array): Promise<string> {
  if (typeof crypto !== "undefined" && crypto.subtle) {
    try {
      const digest = await crypto.subtle.digest(
        "SHA-256",
        bytes.slice().buffer as ArrayBuffer
      );
      return toHex(new Uint8Array(digest));
    } catch {
      // fall through to the pure-TS implementation
    }
  }
  return toHex(sha256Bytes(bytes.slice().buffer as ArrayBuffer));
}

function utf8(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

export async function leafDigestHex(
  index: number,
  length: number,
  chunkSha256: string
): Promise<string> {
  // Canonical JSON: keys sorted (d, i, l), no whitespace — identical to the
  // server's json.dumps(..., sort_keys=True, separators=(",", ":")).
  const payload = `{"d":"${chunkSha256}","i":${index},"l":${length}}`;
  const bytes = new Uint8Array(LEAF_DOMAIN.length + payload.length);
  bytes.set(utf8(LEAF_DOMAIN), 0);
  bytes.set(utf8(payload), LEAF_DOMAIN.length);
  return sha256HexOf(bytes);
}

export async function nodeDigestHex(
  leftHex: string,
  rightHex: string
): Promise<string> {
  const left = hexToBytes(leftHex);
  const right = hexToBytes(rightHex);
  const bytes = new Uint8Array(NODE_DOMAIN.length + 64);
  bytes.set(utf8(NODE_DOMAIN), 0);
  bytes.set(left, NODE_DOMAIN.length);
  bytes.set(right, NODE_DOMAIN.length + 32);
  return sha256HexOf(bytes);
}

/** Rebuild the Merkle root for one block from its sibling path. */
export async function evaluateProofHex(
  block: ProofBlock,
  leafCount: number
): Promise<string> {
  if (!Number.isInteger(leafCount) || leafCount <= 0) {
    throw new Error("叶子总数必须是正整数");
  }
  if (block.index < 0 || block.index >= leafCount) {
    throw new Error(`块序号 ${block.index} 超出叶子总数 ${leafCount}`);
  }
  let current = await leafDigestHex(block.index, block.length, block.sha256);
  let pos = block.index;
  let count = leafCount;
  let step = 0;
  while (count > 1) {
    if (pos % 2 === 0 && pos + 1 < count) {
      if (step >= block.proof.length) {
        throw new Error(`证明在第 ${step} 层缺少右同胞`);
      }
      const item = block.proof[step];
      if (item.side !== "right") {
        throw new Error(`证明第 ${step} 步方向错误（应为右同胞）`);
      }
      current = await nodeDigestHex(current, item.digest);
      step += 1;
    } else if (pos % 2 === 1) {
      if (step >= block.proof.length) {
        throw new Error(`证明在第 ${step} 层缺少左同胞`);
      }
      const item = block.proof[step];
      if (item.side !== "left") {
        throw new Error(`证明第 ${step} 步方向错误（应为左同胞）`);
      }
      current = await nodeDigestHex(item.digest, current);
      step += 1;
    }
    // unpaired last node: promoted unchanged, consumes no proof step
    pos = Math.floor(pos / 2);
    count = Math.ceil(count / 2);
  }
  if (step !== block.proof.length) {
    throw new Error("证明包含多余的同胞步骤");
  }
  return current;
}

export interface VerifyOutcome {
  ok: boolean;
  /** Human-readable verdict; on failure it names the first mismatch. */
  message: string;
  firstMismatchIndex?: number;
}

/**
 * Rebuild the root for every block in the downloaded proof and compare it
 * with the committed root.  Returns the first mismatching block if any.
 */
export async function verifyRangeProof(proof: RangeProof): Promise<VerifyOutcome> {
  if (proof.algorithm !== "merkle-sha256-v1") {
    return { ok: false, message: `不支持的算法版本：${proof.algorithm}` };
  }
  if (!HEX_RE.test(proof.merkle_root)) {
    return { ok: false, message: "承诺根不是合法的 SHA-256 十六进制" };
  }
  const { start, end } = proof.range;
  if (
    !Number.isInteger(start) ||
    !Number.isInteger(end) ||
    start < 0 ||
    start > end ||
    end >= proof.chunk_count
  ) {
    return { ok: false, message: "证明中的块号区间无效" };
  }
  if (proof.blocks.length !== end - start + 1) {
    return { ok: false, message: "证明块数与区间长度不一致" };
  }
  for (let k = 0; k < proof.blocks.length; k++) {
    const block = proof.blocks[k];
    if (block.index !== start + k) {
      return {
        ok: false,
        message: `第 ${k} 个证明块的序号 ${block.index} 与区间不连续`,
        firstMismatchIndex: block.index,
      };
    }
    let rebuilt: string;
    try {
      rebuilt = await evaluateProofHex(block, proof.chunk_count);
    } catch (e) {
      return {
        ok: false,
        message: `块 #${block.index} 的证明结构无效：${(e as Error).message}`,
        firstMismatchIndex: block.index,
      };
    }
    if (rebuilt !== proof.merkle_root) {
      return {
        ok: false,
        message:
          `首个失配位置：块 #${block.index}（偏移 ${block.offset}）——` +
          `由该块重建的根 ${rebuilt.slice(0, 16)}… 与承诺根 ` +
          `${proof.merkle_root.slice(0, 16)}… 不一致`,
        firstMismatchIndex: block.index,
      };
    }
  }
  return {
    ok: true,
    message:
      `校验通过：${proof.blocks.length} 个块（#${start}–#${end}）全部重建出` +
      `承诺根 ${proof.merkle_root.slice(0, 16)}…，与回执 ${proof.receipt_id} 关联一致`,
  };
}

/**
 * Bind the proof to actual bytes: re-hash each claimed block of the local
 * file and compare with the proof's digests and whole-file digest.
 */
export async function verifyProofAgainstFile(
  proof: RangeProof,
  file: File
): Promise<VerifyOutcome> {
  const totalLength = proof.blocks.reduce((acc, b) => acc + b.length, 0);
  const firstOffset = proof.blocks[0]?.offset ?? 0;
  if (firstOffset + totalLength > file.size) {
    return {
      ok: false,
      message: `本地文件只有 ${file.size} 字节，覆盖不到证明区间`,
    };
  }
  for (const block of proof.blocks) {
    const slice = file.slice(block.offset, block.offset + block.length);
    const actual = await sha256HexOf(new Uint8Array(await slice.arrayBuffer()));
    if (actual !== block.sha256) {
      return {
        ok: false,
        message:
          `首个失配位置：块 #${block.index}（偏移 ${block.offset}，长度 ` +
          `${block.length}）——本地字节摘要 ${actual.slice(0, 16)}… 与证明中的 ` +
          `${block.sha256.slice(0, 16)}… 不一致`,
        firstMismatchIndex: block.index,
      };
    }
  }
  if (proof.range.start === 0 && proof.range.end === proof.chunk_count - 1) {
    const whole = await sha256HexOf(new Uint8Array(await file.arrayBuffer()));
    if (whole !== proof.file_sha256) {
      return {
        ok: false,
        message: `整文件摘要 ${whole.slice(0, 16)}… 与回执登记的 ${proof.file_sha256.slice(0, 16)}… 不一致`,
      };
    }
  }
  return {
    ok: true,
    message: `本地文件与证明逐块一致（${proof.blocks.length} 个块）`,
  };
}
