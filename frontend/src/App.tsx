import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ApiError,
  CHUNK_SIZE,
  MAX_FILE_SIZE,
  MIN_FILE_SIZE,
  SESSION_RE,
  ChunkAck,
  Commitment,
  RangeProof,
  Receipt,
  SessionStatus,
  fetchCommitment,
  fetchProof,
  fetchStatus,
  putChunk,
  seal,
  sha256Hex,
} from "./api";
import { MERKLE_ALGORITHM, rebuildRoot } from "./merkle";
import "./styles.css";

interface ChunkError {
  index: number;
  offset: number;
  status: number;
  message: string;
}

function formatRanges(ranges: [number, number][]): string {
  if (ranges.length === 0) return "无";
  return ranges
    .map(([a, b]) => {
      if (a === b) return `#${a}（偏移 ${a * CHUNK_SIZE}）`;
      return `#${a}–#${b}（偏移 ${a * CHUNK_SIZE}–${(b + 1) * CHUNK_SIZE - 1}）`;
    })
    .join("，");
}

interface VerifyOutcome {
  ok: boolean;
  text: string;
}

function verifyFail(text: string): VerifyOutcome {
  return { ok: false, text: `首个失配位置 → ${text}` };
}

/**
 * Local verification of a downloaded range proof against a local copy of the
 * original file: recompute every chunk digest in the proved range, rebuild
 * the Merkle root with the sibling proof, and report either success or the
 * FIRST mismatching position.
 */
async function verifyProofLocally(
  proof: RangeProof,
  localFile: File,
  onPageReceipt: Receipt | null
): Promise<VerifyOutcome> {
  if (proof.algorithm !== MERKLE_ALGORITHM) {
    return verifyFail(`算法版本不符：${String(proof.algorithm)}`);
  }
  const { start, end } = proof.range ?? { start: -1, end: -1 };
  const count = end - start + 1;
  if (
    !Number.isInteger(start) ||
    !Number.isInteger(end) ||
    start < 0 ||
    start > end ||
    end >= proof.chunk_count ||
    !Array.isArray(proof.boundaries) ||
    !Array.isArray(proof.chunk_digests) ||
    !Array.isArray(proof.proof) ||
    proof.boundaries.length !== count ||
    proof.chunk_digests.length !== count
  ) {
    return verifyFail("证明文件结构无效（区间/边界/摘要数量不符）");
  }
  if (localFile.size !== proof.total_size) {
    return verifyFail(
      `文件总长度：本地 ${localFile.size} 字节 ≠ 证明 ${proof.total_size} 字节`
    );
  }
  const localChunks = Math.floor((localFile.size + proof.chunk_size - 1) / proof.chunk_size);
  if (localChunks !== proof.chunk_count) {
    return verifyFail(
      `分块数：本地文件应为 ${localChunks} 块 ≠ 证明 ${proof.chunk_count} 块`
    );
  }
  if (
    onPageReceipt &&
    onPageReceipt.commitment &&
    onPageReceipt.commitment.root !== proof.root
  ) {
    return verifyFail(
      `承诺根：证明根 ${proof.root.slice(0, 16)}… ≠ 当前会话回执承诺根 ${onPageReceipt.commitment.root.slice(0, 16)}…`
    );
  }
  if (onPageReceipt && onPageReceipt.receipt_id !== proof.receipt_id) {
    return verifyFail(
      `回执标识：证明 ${proof.receipt_id} ≠ 当前会话回执 ${onPageReceipt.receipt_id}`
    );
  }
  for (let i = start; i <= end; i++) {
    const boundary = proof.boundaries[i - start];
    const offset = i * proof.chunk_size;
    if (boundary.index !== i || boundary.offset !== offset) {
      return verifyFail(
        `分块 #${i}：证明边界（index ${boundary.index}, offset ${boundary.offset}）与固定分块规则不符`
      );
    }
    const buf = await localFile
      .slice(offset, Math.min(offset + proof.chunk_size, localFile.size))
      .arrayBuffer();
    if (buf.byteLength !== boundary.length) {
      return verifyFail(
        `分块 #${i}（偏移 ${offset}）长度：本地 ${buf.byteLength} ≠ 证明 ${boundary.length}`
      );
    }
    const digest = await sha256Hex(buf);
    if (digest !== proof.chunk_digests[i - start]) {
      return verifyFail(
        `分块 #${i}（偏移 ${offset}）摘要：本地 ${digest.slice(0, 16)}… ≠ 证明 ${proof.chunk_digests[i - start].slice(0, 16)}…`
      );
    }
  }
  let rebuilt;
  try {
    rebuilt = rebuildRoot(
      proof.chunk_count,
      start,
      end,
      proof.chunk_digests,
      proof.boundaries.map((b) => b.length),
      proof.proof
    );
  } catch (e) {
    return verifyFail(`同胞证明无法重建根：${(e as Error).message}`);
  }
  if (rebuilt.consumed !== proof.proof.length) {
    return verifyFail(
      `同胞证明数量：重建消费 ${rebuilt.consumed} 个 ≠ 证明提供 ${proof.proof.length} 个`
    );
  }
  if (rebuilt.rootHex !== proof.root) {
    return verifyFail(
      `Merkle 根：重建 ${rebuilt.rootHex.slice(0, 16)}… ≠ 承诺 ${proof.root.slice(0, 16)}…`
    );
  }
  return {
    ok: true,
    text:
      `校验通过：区间 #${start}–#${end}（${count} 块）的 ${proof.proof.length} 个同胞哈希` +
      `重建根 ${proof.root.slice(0, 16)}… 与承诺一致，回执 ${proof.receipt_id}`,
  };
}

export default function App() {
  const [session, setSession] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [digest, setDigest] = useState<string | null>(null);
  const [confirmed, setConfirmed] = useState<Set<number>>(new Set());
  const [chunkCount, setChunkCount] = useState<number>(0);
  const [totalSize, setTotalSize] = useState<number>(0);
  const [busy, setBusy] = useState(false);
  const [phase, setPhase] = useState<string>("");
  const [errors, setErrors] = useState<ChunkError[]>([]);
  const [receipt, setReceipt] = useState<Receipt | null>(null);
  const [sealed, setSealed] = useState(false);
  const [notice, setNotice] = useState<string>("");
  const [commitment, setCommitment] = useState<Commitment | null>(null);
  const [commitmentMsg, setCommitmentMsg] = useState<string>("");
  const [proofStart, setProofStart] = useState<string>("");
  const [proofEnd, setProofEnd] = useState<string>("");
  const [proofJson, setProofJson] = useState<RangeProof | null>(null);
  const [proofJsonName, setProofJsonName] = useState<string>("");
  const [verifyFile, setVerifyFile] = useState<File | null>(null);
  const [verifyResult, setVerifyResult] = useState<VerifyOutcome | null>(null);

  const sessionValid = SESSION_RE.test(session);
  const fileError = useMemo(() => {
    if (!file) return "";
    if (file.size < MIN_FILE_SIZE) return "文件不得小于 1 字节";
    if (file.size > MAX_FILE_SIZE) return "文件不得超过 8 MiB";
    return "";
  }, [file]);

  const expectedChunks = file
    ? Math.floor((file.size + CHUNK_SIZE - 1) / CHUNK_SIZE)
    : 0;

  const resetProgress = useCallback(() => {
    setConfirmed(new Set());
    setErrors([]);
    setReceipt(null);
    setSealed(false);
    setNotice("");
    setChunkCount(0);
    setTotalSize(0);
  }, []);

  const onPickFile = useCallback(
    async (picked: File | null) => {
      setFile(picked);
      setDigest(null);
      resetProgress();
      if (!picked) return;
      if (picked.size < MIN_FILE_SIZE || picked.size > MAX_FILE_SIZE) return;
      setPhase("正在计算整文件 SHA-256…");
      const buffer = await picked.arrayBuffer();
      setDigest(await sha256Hex(buffer));
      setChunkCount(Math.floor((picked.size + CHUNK_SIZE - 1) / CHUNK_SIZE));
      setTotalSize(picked.size);
      setPhase("");
    },
    [resetProgress]
  );

  // Merge a server ack. The server's confirmed list is authoritative.
  const applyAck = useCallback((ack: ChunkAck) => {
    setConfirmed(new Set(ack.confirmed_chunks));
    setChunkCount(ack.chunk_count);
    setSealed(ack.sealed);
  }, []);

  const sendAllChunks = useCallback(async (): Promise<boolean> => {
    if (!file || !digest) return false;
    const buffer = await file.arrayBuffer();
    const total = buffer.byteLength;
    const count = Math.floor((total + CHUNK_SIZE - 1) / CHUNK_SIZE);

    // Resend EVERY chunk (the server deduplicates identical retransmissions).
    // This is how an interrupted transfer is recovered with the same session.
    for (let i = 0; i < count; i++) {
      const offset = i * CHUNK_SIZE;
      const part = buffer.slice(offset, Math.min(offset + CHUNK_SIZE, total));
      setPhase(`正在发送分块 ${i + 1} / ${count}`);
      try {
        const ack = await putChunk(session, offset, part, total, digest);
        applyAck(ack);
        setErrors((prev) => prev.filter((e) => e.index !== i));
      } catch (e) {
        const err = e as ApiError;
        setErrors((prev) => [
          ...prev.filter((x) => x.index !== i),
          {
            index: i,
            offset,
            status: err.status ?? 0,
            message:
              err.status === 409
                ? `409 冲突：该会话已确认不同内容，服务器拒绝覆盖（${err.message}）`
                : err.status === 0
                  ? `网络错误（可能断线），已确认分块保留在服务器，可重发恢复：${err.message}`
                  : err.message,
          },
        ]);
        if (err.status === 409) {
          // A conflict means a different file is bound to this session:
          // stop immediately, never overwrite, do not attempt to seal.
          setPhase("传输因 409 冲突中止，已确认数据未被修改。");
          return false;
        }
        // Network/5xx error: keep everything confirmed so far; stop.
        setPhase("传输中断，已确认分块未丢失；重选同一文件并重发即可恢复。");
        return false;
      }
    }
    return true;
  }, [applyAck, digest, file, session]);

  const handleUploadAndSeal = useCallback(async () => {
    setBusy(true);
    setErrors([]);
    setNotice("");
    try {
      const complete = await sendAllChunks();
      if (!complete) return;
      setPhase("所有分块已确认，正在请求封存…");
      const result = await seal(session);
      if (result.receipt) {
        setReceipt(result.receipt);
        setSealed(true);
        setNotice("封存成功，回执已生成并持久化。");
        setPhase("");
      } else if (result.missingRanges) {
        setNotice(`仍有缺块，未生成回执：${formatRanges(result.missingRanges)}`);
        setPhase("");
      } else {
        setNotice(`封存被拒绝，未生成回执：${result.error ?? "摘要不一致"}`);
        setPhase("");
      }
    } finally {
      setBusy(false);
    }
  }, [sendAllChunks, session]);

  const handleSealOnly = useCallback(async () => {
    setBusy(true);
    try {
      const result = await seal(session);
      if (result.receipt) {
        setReceipt(result.receipt);
        setSealed(true);
        setNotice("封存成功。");
      } else if (result.missingRanges) {
        setNotice(`仍有缺块：${formatRanges(result.missingRanges)}`);
      } else {
        setNotice(`封存失败：${result.error}`);
      }
    } finally {
      setBusy(false);
    }
  }, [session]);

  const handleRefresh = useCallback(async () => {
    if (!sessionValid) return;
    setBusy(true);
    try {
      const status: SessionStatus | null = await fetchStatus(session);
      if (!status) {
        resetProgress();
        setNotice("服务器上没有该会话（可能从未成功写入分块）。");
        return;
      }
      setChunkCount(status.chunk_count);
      setTotalSize(status.total_size);
      setConfirmed(new Set(status.confirmed_chunks));
      setSealed(status.sealed);
      setReceipt(status.receipt);
      setNotice(
        status.sealed
          ? "该会话已封存，回执如下（服务重启后仍然保留）。"
          : `已从服务器恢复进度：${status.confirmed_chunks.length}/${status.chunk_count} 块。`,
      );
    } catch (e) {
      setNotice(`查询失败：${(e as Error).message}`);
    } finally {
      setBusy(false);
    }
  }, [resetProgress, session, sessionValid]);

  const pct = chunkCount ? Math.round((confirmed.size / chunkCount) * 100) : 0;
  const ready = sessionValid && !!file && !fileError && !!digest && !busy;

  const loadCommitment = useCallback(async () => {
    if (!sessionValid) return;
    try {
      const record = await fetchCommitment(session);
      setCommitment(record);
      setCommitmentMsg("");
    } catch (e) {
      setCommitment(null);
      setCommitmentMsg(`承诺记录不可用：${(e as Error).message}`);
    }
  }, [session, sessionValid]);

  // Once sealed, the commitment record is anchored to the receipt: pull it.
  useEffect(() => {
    if (sealed && sessionValid) void loadCommitment();
  }, [sealed, sessionValid, loadCommitment]);

  // Switching sessions invalidates any downloaded/loaded proof material.
  useEffect(() => {
    setCommitment(null);
    setCommitmentMsg("");
    setProofJson(null);
    setProofJsonName("");
    setVerifyResult(null);
    setProofStart("");
    setProofEnd("");
  }, [session]);

  const handleDownloadProof = useCallback(async () => {
    const parse = (raw: string): number | undefined | null => {
      if (raw.trim() === "") return undefined;
      const n = Number(raw);
      return Number.isInteger(n) && n >= 0 ? n : null;
    };
    const lo = parse(proofStart);
    const hi = parse(proofEnd);
    if (lo === null || hi === null) {
      setVerifyResult({ ok: false, text: "区间起止必须是非负整数（留空表示整份文件）" });
      return;
    }
    setBusy(true);
    setVerifyResult(null);
    try {
      const proof = await fetchProof(session, lo, hi);
      const name = `proof-${session}-${proof.range.start}-${proof.range.end}.json`;
      const blob = new Blob([JSON.stringify(proof, null, 2)], {
        type: "application/json",
      });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = name;
      anchor.click();
      URL.revokeObjectURL(url);
      // Keep the just-downloaded proof available for instant local checks.
      setProofJson(proof);
      setProofJsonName(name);
    } catch (e) {
      const err = e as ApiError;
      setVerifyResult({ ok: false, text: `证明生成被拒绝：${err.message}` });
    } finally {
      setBusy(false);
    }
  }, [proofStart, proofEnd, session]);

  const onPickProofJson = useCallback(async (picked: File | null) => {
    if (!picked) return;
    try {
      const parsed = JSON.parse(await picked.text()) as RangeProof;
      setProofJson(parsed);
      setProofJsonName(picked.name);
      setVerifyResult(null);
    } catch {
      setProofJson(null);
      setProofJsonName("");
      setVerifyResult({ ok: false, text: `证明文件 ${picked.name} 不是有效 JSON` });
    }
  }, []);

  const handleVerifyProof = useCallback(async () => {
    const local = verifyFile ?? file;
    if (!proofJson || !local) return;
    setBusy(true);
    try {
      setVerifyResult(await verifyProofLocally(proofJson, local, receipt));
    } finally {
      setBusy(false);
    }
  }, [verifyFile, file, proofJson, receipt]);

  const localFileForVerify = verifyFile ?? file;
  const proofReady = sealed || commitment !== null;

  return (
    <main className="page">
      <h1>冷冻电镜采集包 · 断点续传封存台</h1>
      <p className="sub">
        固定分块 65536 字节 · 文件 1 B – 8 MiB · 会话号 1–32 位字母或数字 ·
        已确认分块与封存回执跨重启保留
      </p>

      <section className="card">
        <label className="field">
          <span>会话号</span>
          <input
            value={session}
            placeholder="例如 CRYO2026A1（1–32 位字母或数字）"
            onChange={(e) => setSession(e.target.value.trim())}
            disabled={busy}
          />
          {session && !sessionValid && (
            <em className="bad">会话号只能包含英文字母与数字，长度 1–32</em>
          )}
        </label>

        <div className="row">
          <button onClick={handleRefresh} disabled={!sessionValid || busy}>
            查询/恢复服务器进度
          </button>
          <button onClick={handleSealOnly} disabled={!sessionValid || busy}>
            仅请求封存
          </button>
        </div>

        <label className="field">
          <span>选择采集包文件（重选原文件即可用原会话号重发所有块）</span>
          <input
            type="file"
            // Reset so picking the SAME file again still fires onChange
            // (that is exactly the "reselect the original file" recovery path).
            onClick={(e) => {
              e.currentTarget.value = "";
            }}
            onChange={(e) => void onPickFile(e.target.files?.[0] ?? null)}
            disabled={busy}
          />
          {fileError && <em className="bad">{fileError}</em>}
        </label>

        {file && !fileError && (
          <div className="meta">
            <div>文件名：{file.name}</div>
            <div>
              大小：{file.size} 字节（{expectedChunks} 块）
            </div>
            <div className="digest">
              整文件 SHA-256：{digest ?? "计算中…"}
            </div>
          </div>
        )}

        <div className="row">
          <button
            className="primary"
            onClick={() => void handleUploadAndSeal()}
            disabled={!ready}
          >
            {confirmed.size > 0 ? "重发所有分块并封存" : "传输并封存"}
          </button>
        </div>
      </section>

      <section className="card">
        <h2>进度</h2>
        <div className="bar">
          <div className="bar-fill" style={{ width: `${pct}%` }} />
        </div>
        <div className="status">
          {phase && <div>{phase}</div>}
          已确认分块：{confirmed.size} / {chunkCount || "—"}（{pct}%）
          {totalSize > 0 && ` · 总长度 ${totalSize} 字节`}
          {sealed && <strong className="good"> · 已封存</strong>}
        </div>
        {chunkCount > 0 && (
          <ChunkGrid count={chunkCount} confirmed={confirmed} />
        )}
        {notice && <div className="notice">{notice}</div>}
      </section>

      {errors.length > 0 && (
        <section className="card">
          <h2>错误（{errors.length}）</h2>
          <ul className="errors">
            {errors.map((e) => (
              <li key={e.index}>
                分块 #{e.index}，偏移 {e.offset}：{e.message}
              </li>
            ))}
          </ul>
        </section>
      )}

      {receipt && (
        <section className="card receipt">
          <h2>封存回执（唯一，重复封存返回同一份）</h2>
          <dl>
            <dt>回执标识</dt>
            <dd>{receipt.receipt_id}</dd>
            <dt>会话号</dt>
            <dd>{receipt.session}</dd>
            <dt>总长度</dt>
            <dd>{receipt.total_size} 字节</dd>
            <dt>分块数</dt>
            <dd>{receipt.chunks}</dd>
            <dt>SHA-256</dt>
            <dd>{receipt.sha256}</dd>
            <dt>封存时间 (UTC)</dt>
            <dd>{receipt.sealed_at}</dd>
            {receipt.commitment && (
              <>
                <dt>Merkle 承诺根</dt>
                <dd>{receipt.commitment.root}</dd>
              </>
            )}
          </dl>
        </section>
      )}

      {proofReady && (
        <section className="card">
          <h2>出库证明（Merkle 承诺 · 连续块区间）</h2>

          {commitment && (
            <div className="receipt">
              <dl>
                <dt>算法版本</dt>
                <dd>{commitment.algorithm}</dd>
                <dt>承诺根</dt>
                <dd>{commitment.root}</dd>
                <dt>叶子数</dt>
                <dd>{commitment.leaf_count}</dd>
                <dt>关联回执</dt>
                <dd>{commitment.receipt_id}</dd>
              </dl>
            </div>
          )}
          {commitmentMsg && <div className="notice">{commitmentMsg}</div>}

          <div className="row range-row">
            <label>
              起始块号
              <input
                type="number"
                min={0}
                value={proofStart}
                placeholder="0"
                onChange={(e) => setProofStart(e.target.value)}
                disabled={busy}
              />
            </label>
            <label>
              结束块号
              <input
                type="number"
                min={0}
                value={proofEnd}
                placeholder={chunkCount > 0 ? String(chunkCount - 1) : ""}
                onChange={(e) => setProofEnd(e.target.value)}
                disabled={busy}
              />
            </label>
            <button onClick={() => void handleDownloadProof()} disabled={busy || !sessionValid}>
              下载区间证明（边界 · 块摘要 · 同胞证明 · 回执标识）
            </button>
            <button onClick={() => void loadCommitment()} disabled={busy || !sessionValid}>
              刷新承诺记录
            </button>
          </div>

          <h3>本地校验（不上传文件，浏览器内重建根）</h3>
          <div className="row range-row">
            <label>
              证明 JSON（{proofJsonName || "未选择"}）
              <input
                type="file"
                accept="application/json"
                onClick={(e) => {
                  e.currentTarget.value = "";
                }}
                onChange={(e) => void onPickProofJson(e.target.files?.[0] ?? null)}
                disabled={busy}
              />
            </label>
            <label>
              本地原件{file && !verifyFile ? "（默认用上方已选文件）" : ""}
              <input
                type="file"
                onClick={(e) => {
                  e.currentTarget.value = "";
                }}
                onChange={(e) => setVerifyFile(e.target.files?.[0] ?? null)}
                disabled={busy}
              />
            </label>
            <button
              className="primary"
              onClick={() => void handleVerifyProof()}
              disabled={busy || !proofJson || !localFileForVerify}
            >
              本地校验证明
            </button>
          </div>
          {verifyResult && (
            <div className={verifyResult.ok ? "verify-ok" : "verify-bad"}>
              {verifyResult.text}
            </div>
          )}
        </section>
      )}
    </main>
  );
}

function ChunkGrid({
  count,
  confirmed,
}: {
  count: number;
  confirmed: Set<number>;
}) {
  const cells = Array.from({ length: count }, (_, i) => i);
  return (
    <div className="grid" title={`共 ${count} 块，绿色为服务器已确认`}>
      {cells.map((i) => (
        <span key={i} className={`cell ${confirmed.has(i) ? "on" : ""}`}>
          {i}
        </span>
      ))}
    </div>
  );
}
