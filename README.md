# 冷冻电镜采集包 · 断点续传封存台

TypeScript/React 前端 + FastAPI 后端的全栈封存台。上传中断（断线、重发、服务重启、误选文件）
**绝不覆盖**已经确认的数据，封存回执全库**唯一**，进度与回执跨服务重启保留。

## 核心规则

- 会话号：`^[A-Za-z0-9]{1,32}$`；文件大小：1 B – 8 MiB。
- 固定块长 `65536` 字节，块从零起算的偏移必须对齐 65536，末块可缩短。
- 每个 `PUT` 携带：块字节、`X-Chunk-Offset`、`X-Total-Size`、`X-Content-SHA256`
  （整文件小写 SHA-256；元数据首次成功写入后，重传可省略后两个头）。
- 分块允许**乱序**到达。
- 元数据（总长度、摘要、块数）在第一个合法分块成功后**永久固定**。
- 相同重传：**幂等 200**；块内容不同或元数据不同：**409 且状态不变**。
- 未对齐、越界、块长错误：**400**，错误信息带具体偏移/长度，且不留任何状态。
- `POST /seal`：无缺块且服务端重算整文件摘要一致时，原子写入唯一回执；
  此后不可新增/更改分块（相同重传仍 200，不同内容 409）。
- 重复封存返回**同一份回执**；缺块返回 409 并列出 `missing_ranges`（闭区间块号）；
  摘要不符返回 409 且不产生回执文件。
- 封存时按固定顺序构建二叉 Merkle 承诺，`merkle_root` 与算法版本
  `merkle-sha256-v1` **与新回执原子关联**（另落独立 `commitment.json`）。
  叶子以域分隔编码绑定**块序号、实际长度、块 SHA-256**；奇数层固定
  「末节点直接提升」补位，不伪造兄弟哈希。
- 已封存会话可下载任意**连续闭区间块号**的出库证明（边界、块摘要、最小同胞
  证明、回执标识）；接收方不持有整份采集包也能逐块重建根并比对承诺根，
  失配时给出首个失配块号。
- 旧回执没有承诺根：只有**完整有序扫描**、每块长度正确且重算整文件摘要与
  回执一致，才生成**独立**承诺记录；旧回执永不改写。缺块、摘要不符或回执
  损坏一律拒绝证明，且会话维持不可写。

## API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/health` | 健康检查 |
| `GET` | `/api/uploads/{session}` | 会话状态：已确认块、缺失范围、回执、承诺记录 |
| `PUT` | `/api/uploads/{session}/chunks` | 上传/重传一个分块（头见上） |
| `POST` | `/api/uploads/{session}/seal` | 原子封存；已封存则返回原回执 |
| `GET` | `/api/uploads/{session}/proof?start=a&end=b` | 下载连续块号区间的 Merkle 出库证明 |
| `POST` | `/api/uploads/{session}/commitment` | 旧回执完整扫描，生成独立承诺记录（不改旧回执） |

`proof` 参数为 0 起算的闭区间整数块号，须连续、不越界、十进制规范写法
（`01` 拒绝）；区间非法返回 400，会话不存在 404，未封存/旧回执尚无承诺/
封存字节损坏返回 409，回执文件损坏返回 500 且拒绝一切写入与证明。

证明 JSON 顶层含 `algorithm`、`merkle_root`、`receipt_id`、`file_sha256`、
`chunk_size`、`chunk_count`、`range`，`blocks[]` 每项含 `index`、`offset`、
`length`、`sha256` 与最小同胞路径 `proof[]`（`{side, digest}`，方向为相对
重建子树的 `left`/`right`）。单叶文件的同胞路径为空，根即叶摘要。

### 本地校验（与实现语言无关）

```
leaf_i = SHA256("merkle-leaf:v1:" + JSON({d:<块摘要>,i:<序号>,l:<长度>}, 键序 d,i,l 无空白))
node   = SHA256("merkle-node:v1:" + left(32B) || right(32B))
```

从叶开始按 `side` 逐层合并；奇数层的末节点直接提升（不消耗同胞步），
比较重建根与 `merkle_root`。

## 持久化与崩溃安全

`./data/<会话>/`：

```
meta.json       # 元数据，首次合法分块时原子写入后不可变
chunks/00000000 …  # 每块一个文件，写临时文件 + fsync + rename 原子落盘
commitment.json # Merkle 承诺记录（叶表+根+回执标识），封存时随回执原子出现；
                # 旧回执经完整扫描后也可独立生成
receipt.json    # 仅封存成功后原子出现；存在即代表已封存。新回执内嵌 merkle_root
                # 与 merkle_algorithm；旧回执无这两个字段且永不改写
```

所有写操作经进程内锁串行化，落盘均为「临时文件 → fsync → 原子 rename → fsync 目录」，
服务重启/容器重建后直接从该目录重建状态。

## 前端

页面输入会话号、选择文件后浏览器本地计算整文件 SHA-256（优先 WebCrypto，
HTTP 局域网等非安全上下文自动回退到内置纯 TS 实现），逐块 `PUT` 并显示：

- 已确认分块网格与百分比、缺失范围；
- 每块错误（含定位偏移；409 明确提示数据被拒绝覆盖）；
- **重选原文件**即用原会话号**重发所有块**（服务端去重），断线后如此恢复；
- 「查询/恢复服务器进度」可在页面刷新/重启后拉回服务端权威状态；
- 封存后展示唯一回执；
- 已封存会话可输入连续块号区间下载出库证明，并在浏览器内**本地重建 Merkle
  根**校验（若同时选取原文件，还逐块重算摘要对照），显示通过或首个失配位置；
  旧回执可一键完整扫描生成独立承诺记录。

## 运行（Docker Compose）

```bash
docker compose up -d web          # 打开 http://localhost:8000
HOST_PORT=9000 docker compose up -d web
```

- 宿主机端口：`${HOST_PORT:-8000}:8000`；
- 持久数据：宿主机 `./data` 挂载到容器 `/data`；
- 内置健康检查，`depends_on: service_healthy` 可供编排使用。

## 一次性 verify 服务

在完成代码测试、前端生产构建与对运行中服务的 HTTP 冒烟后**自行退出，以退出码汇报成败**：

```bash
docker compose build verify
docker compose up --exit-code-from verify verify
# 或一行：
docker compose run --rm verify
```

阶段（任一失败立即非零退出）：

1. `pytest`：后端测试（乱序、幂等、409 不改状态、定位拒绝、缺块范围、
   摘要不符无回执、封存后不可变、跨"重启"持久化、边界尺寸，以及 Merkle
   承诺/连续区间证明/旧回执迁移/损坏拒绝）；
2. `npm run build`：`tsc` 类型检查 + Vite 构建；
3. `verify/smoke.py`：对 `http://web:8000` 的纯 stdlib HTTP 全链路冒烟，
   含用独立实现重建 Merkle 根的出库证明校验。

## 本地开发

```bash
# 后端
cd backend && python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
DATA_DIR=../data uvicorn app.main:app --reload

# 前端（dev server 代理 /api 与 /health 到 :8000）
cd frontend && npm install && npm run dev
```
