import { useCallback, useMemo, useState } from "react";
import {
  ApiError,
  CHUNK_SIZE,
  MAX_FILE_SIZE,
  MIN_FILE_SIZE,
  SESSION_RE,
  ChunkAck,
  RangeProof,
  Receipt,
  SessionStatus,
  buildLegacyCommitment,
  fetchRangeProof,
  fetchStatus,
  putChunk,
  seal,
  sha256Hex,
} from "./api";
import { verifyProofAgainstFile, verifyRangeProof, type VerifyOutcome } from "./merkle";
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
  // 出库证明（Merkle 承诺）状态
  const [proofStart, setProofStart] = useState("0");
  const [proofEnd, setProofEnd] = useState("");
  const [proofBusy, setProofBusy] = useState(false);
  const [proof, setProof] = useState<RangeProof | null>(null);
  const [verifyOutcome, setVerifyOutcome] = useState<VerifyOutcome | null>(null);
  const [legacyRoot, setLegacyRoot] = useState<string | null>(null);

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
    setProof(null);
    setVerifyOutcome(null);
    setLegacyRoot(null);
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
      setLegacyRoot(status.commitment?.merkle_root ?? null);
      setProof(null);
      setVerifyOutcome(null);
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

  // ---- 出库证明：下载 + 本地校验 -------------------------------------------

  // 承诺根优先取回执内嵌字段；旧回执经完整扫描后取独立承诺记录。
  const commitmentRoot = receipt?.merkle_root ?? legacyRoot;
  const effectiveProofEnd =
    proofEnd === "" ? String(Math.max(0, chunkCount - 1)) : proofEnd;

  const parseRange = useCallback((): { start: number; end: number } | null => {
    if (!/^\d+$/.test(proofStart) || !/^\d+$/.test(effectiveProofEnd)) return null;
    const start = Number(proofStart);
    const end = Number(effectiveProofEnd);
    if (start > end || end >= chunkCount) return null;
    return { start, end };
  }, [proofStart, effectiveProofEnd, chunkCount]);

  const handleFetchProof = useCallback(
    async (download: boolean) => {
      const range = parseRange();
      if (!range) {
        setVerifyOutcome({ ok: false, message: "块号区间无效：需为 0 起的连续闭区间且不越界" });
        return;
      }
      setProofBusy(true);
      try {
        const p = await fetchRangeProof(session, range.start, range.end);
        setProof(p);
        setVerifyOutcome(null);
        if (download) {
          const blob = new Blob([JSON.stringify(p, null, 2)], {
            type: "application/json",
          });
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a");
          a.href = url;
          a.download = `proof-${session}-${range.start}-${range.end}.json`;
          a.click();
          URL.revokeObjectURL(url);
        }
      } catch (e) {
        setProof(null);
        setVerifyOutcome({
          ok: false,
          message: `获取证明被拒绝：${(e as ApiError).message}`,
        });
      } finally {
        setProofBusy(false);
      }
    },
    [parseRange, session]
  );

  const handleVerify = useCallback(async () => {
    setProofBusy(true);
    setVerifyOutcome(null);
    try {
      let p = proof;
      if (!p) {
        const range = parseRange();
        if (!range) {
          setVerifyOutcome({ ok: false, message: "块号区间无效：需为 0 起的连续闭区间且不越界" });
          return;
        }
        p = await fetchRangeProof(session, range.start, range.end);
        setProof(p);
      }
      // 先与页面上受信的承诺根（回执/独立承诺记录）比对，再逐块重建根。
      if (commitmentRoot && p.merkle_root !== commitmentRoot) {
        setVerifyOutcome({
          ok: false,
          message:
            `证明携带的根 ${p.merkle_root.slice(0, 16)}… 与回执承诺根 ` +
            `${commitmentRoot.slice(0, 16)}… 不一致`,
        });
        return;
      }
      const structural = await verifyRangeProof(p);
      if (!structural.ok || !file) {
        setVerifyOutcome(structural);
        return;
      }
      const bytes = await verifyProofAgainstFile(p, file);
      setVerifyOutcome(
        bytes.ok
          ? { ok: true, message: `${structural.message}；${bytes.message}` }
          : bytes
      );
    } catch (e) {
      setVerifyOutcome({ ok: false, message: `校验失败：${(e as Error).message}` });
    } finally {
      setProofBusy(false);
    }
  }, [proof, parseRange, session, file, commitmentRoot]);

  const handleLegacyRescan = useCallback(async () => {
    setProofBusy(true);
    try {
      const record = await buildLegacyCommitment(session);
      setLegacyRoot(record.merkle_root);
      setNotice("已为旧回执生成独立承诺记录（完整扫描通过，旧回执未被改写）。");
    } catch (e) {
      setNotice(`生成承诺记录被拒绝：${(e as ApiError).message}`);
    } finally {
      setProofBusy(false);
    }
  }, [session]);

  const pct = chunkCount ? Math.round((confirmed.size / chunkCount) * 100) : 0;
  const ready = sessionValid && !!file && !fileError && !!digest && !busy;

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
            <dt>Merkle 算法</dt>
            <dd>{receipt.merkle_algorithm ?? "（旧回执：未内嵌承诺根）"}</dd>
            <dt>承诺根</dt>
            <dd>{receipt.merkle_root ?? (legacyRoot ?? "—（旧回执，需完整扫描生成独立承诺）")}</dd>
          </dl>
        </section>
      )}

      {sealed && (
        <section className="card proof-card">
          <h2>连续分块出库证明</h2>
          <p className="hint">
            为已封存会话选择连续闭区间块号，导出边界、块摘要与最小同胞证明；
            接收方无需整份采集包即可本地重建二叉 Merkle 根并与回执标识比对。
            奇数层采用「末节点直接提升」的固定补位规则，叶子绑定块序号、实际长度与块摘要。
          </p>

          {!commitmentRoot && (
            <div className="row">
              <button
                onClick={() => void handleLegacyRescan()}
                disabled={!sessionValid || proofBusy}
              >
                为旧回执完整扫描并生成独立承诺记录
              </button>
            </div>
          )}

          <div className="range-row">
            <label>
              起始块号
              <input
                type="text"
                inputMode="numeric"
                value={proofStart}
                placeholder="0"
                disabled={proofBusy}
                onChange={(e) => setProofStart(e.target.value.trim())}
              />
            </label>
            <label>
              结束块号（留空 = {Math.max(0, chunkCount - 1)}）
              <input
                type="text"
                inputMode="numeric"
                value={proofEnd}
                placeholder={String(Math.max(0, chunkCount - 1))}
                disabled={proofBusy}
                onChange={(e) => setProofEnd(e.target.value.trim())}
              />
            </label>
            <span className="range-hint">共 {chunkCount > 0 ? chunkCount : "—"} 块</span>
          </div>

          <div className="row">
            <button
              className="primary"
              onClick={() => void handleFetchProof(true)}
              disabled={!sessionValid || proofBusy || chunkCount === 0}
            >
              下载区间证明
            </button>
            <button
              onClick={() => void handleFetchProof(false)}
              disabled={!sessionValid || proofBusy || chunkCount === 0}
            >
              仅查看证明
            </button>
            <button
              onClick={() => void handleVerify()}
              disabled={!sessionValid || proofBusy || chunkCount === 0}
            >
              本地重建根并校验{file ? "（对照所选文件）" : "（仅证明结构）"}
            </button>
          </div>

          {verifyOutcome && (
            <div className={`notice ${verifyOutcome.ok ? "verify-ok" : "verify-bad"}`}>
              {verifyOutcome.ok ? "✓ " : "✗ "}
              {verifyOutcome.message}
            </div>
          )}

          {proof && (
            <div className="proof-detail">
              <div>算法：{proof.algorithm}</div>
              <div className="digest">承诺根：{proof.merkle_root}</div>
              <div>回执标识：{proof.receipt_id}</div>
              <div>
                区间：#{proof.range.start}–#{proof.range.end}（{proof.blocks.length} 块）·
                总块数 {proof.chunk_count}
              </div>
              <ul className="proof-blocks">
                {proof.blocks.map((b) => (
                  <li key={b.index}>
                    #{b.index} · 偏移 {b.offset} · 长度 {b.length} · 同胞 {b.proof.length} 个
                    <span className="digest">{b.sha256}</span>
                  </li>
                ))}
              </ul>
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
