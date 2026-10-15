# llm-proxy — DSHP 增量同步 LLM 代理

**llm-proxy（代号 DSHP）** 放在**客户端与上游 LLM API 之间**，让"多轮对话里反复出现的那部分输入"在链路上**只传一次**：客户端缓存内容寻址的块，后续请求只发差异；响应方向则把流式事件归纳成模板并批量成帧。

- **请求方向**：请求体切成内容寻址的块（指纹 + `REF`），跨请求复用不变的部分；服务端缺块时只补缺的那几块。
- **响应方向**：从 SSE 流里归纳**字节模板**并把重复事件批量成帧；命中不了时退到流式 zstd 慢路径。
- **传输**：降级链 `KCP(UDP) → WS → SSE → 直连上游`，掉线自动重连；客户端可配直连兜底。
- **正确性红线**：**没发完绝不当作发完了** —— 任何截断都让调用方拿到明确错误，而不是半截 200。
- **上游无关**：path 与 query **原样透传**，SDK 只改 `base_url` 即可接入。

省下来的字节是实测的（含帧头）：

| 方向 | 场景 | 链路占用 | 省 |
|---|---|---|---|
| 请求 | 2.75 MB 会话只多两条消息 | **0.545%** | 99.5% |
| 请求 | 347 KB 会话只多两条消息 | **3.999%** | 96.0% |
| 响应 | 141 个 SSE 事件的流式响应（首响应） | **9.48%** | 90.5% |
| 响应 | 同一连接上的第 3 个响应（稳态） | **7.26%** | 92.7% |
| 请求 | 冷启动整段（zstd + 字典，718 KB 高熵合成体） | **61.7%** | 38.3% |

> 冷启动那行偏低是**负载性质**决定的：合成体主体是伪随机 CJK，存在熵下限（脱敏语料上字典对完整 body 的增益也只有 1.02×）；真实文本可达 25–35%，但需要真实流量才能验证，这里不把设计估算当实测。

## 目录结构

```
crates/
├─ llm-proxy-core/        帧编解码、指纹、CDC 分块、字典、加密、资源硬约束
├─ llm-proxy-json/        JSON 语法级 span 扫描、SSE 事件切分、字节模板归纳
├─ llm-proxy-cache/       块存储 LRU + 6h TTL + 预算控制
├─ llm-proxy-transport/   帧多路复用、KCP/WS/SSE 三档链路、FEC、channel body
├─ llmproxyc/             客户端 ingress（本地反向代理，目标 ARM 软路由）
├─ llmproxyd/             服务端 egress（隧道入口 + 上游转发 + 统计 WebUI）
├─ e2e-tests/             端到端验收测试（不发布）
└─ dev-tools/             基准门禁、字典训练、语料脱敏、opkg 打包、CI 日志分析
bench/                    回归门禁的基线与说明（见 bench/README.md）
dicts/                    内嵌字典产物（dict_patch / dict_ctrl / dict_sse）
openwrt/                  OpenWrt 部署文件与安装说明（见 openwrt/README.md）
corpus/ corpus-next/      脱敏语料（生成物，已 gitignore，不入库）
dev-notes/                本地开发归档（设计文档、发布检查清单、逐轮实测记录；已 gitignore）
```

## 构建

```bash
cargo build                    # 调试构建（e2e 测试用 target/debug 下的二进制）
cargo build --release          # 发布构建：opt-level=z + fat LTO + strip + panic=abort
```

工作区要求 Rust 1.82 及以上。ARM 交叉构建见「部署」。

## 快速开始

两个进程，一实例一上游。**客户端默认只绑回环**，绑非回环地址需要显式 `--allow-lan`（否则启动自检直接拒绝）。

```bash
# 服务端（egress）：隧道入口 → 上游
llmproxyd --listen 127.0.0.1:9000 --upstream http://127.0.0.1:9100

# 客户端（ingress）：本地入口 → 链路 → 服务端
llmproxyc --listen 127.0.0.1:8787 --server ws://127.0.0.1:9000
```

两端 `psk` 必须一致（默认 `change-me`，务必改掉）：

```bash
export DSHP_PSK='<你的预共享密钥>'   # 或写进 TOML 的 psk 字段
```

SDK 侧只需改 `base_url`：

```python
# OpenAI SDK（base_url 带 /v1）
client = OpenAI(base_url="http://127.0.0.1:8787/v1")

# Anthropic SDK（base_url 不带 /v1）
client = Anthropic(base_url="http://127.0.0.1:8787")
```

两种写法都不需要代理特殊处理 —— path 与 query 是原样透传的，这是「上游无关」的直接收益。

## 配置

三处来源，优先级：**命令行 > 环境变量 > TOML > 内置默认值**。

### 命令行

`llmproxyc`（客户端）：

| 参数 | 含义 | 默认 |
|---|---|---|
| `-c, --config <PATH>` | TOML 配置文件 | 无（全用内置默认值） |
| `--listen <ADDR>` | 本地入口监听地址 | `127.0.0.1:8787` |
| `--allow-lan` | 显式允许绑局域网地址（会暴露 prompt 与 API key，请配防火墙） | 关闭 |
| `--server <URL>` | 服务端地址，支持 `ws://` 与 `wss://` | `ws://127.0.0.1:9000` |
| `--upstream-host <HOST>` | 上游主机名（参与缓存命名空间派生，**两端必须一致**） | `localhost` |
| `--tenant <ID>` | 租户标识（**两端必须一致**，不一致时握手被拒） | 空（单租户） |
| `--no-delta` | 关闭增量路径，一律原样转发（对照与排查用） | 关闭 |
| `--max-decompose-bytes <N>` | 增量路径允许缓冲的请求体上限 | 8 MiB |
| `--upload-entries <N>` | 上传记账条目上限（只存指纹） | 200000 |
| `--upstream-fallback <URL>` | 直连兜底的上游 base URL（纯前缀，**不带 `/v1`**），`http://` 或 `https://` | 无 |
| `--upstream-ca <PEM>` | 追加到内嵌根集之上的 CA 证书（自签/私有 CA 的 https 上游用） | 无 |
| `--kcp-server <ADDR>` | KCP(UDP) 服务端地址；不设则完全不试 KCP | 无 |
| `--force-mode <ws\|sse>` | 强制传输模式；不设则按降级链逐档尝试 | 无 |
| `--reconnect-min-ms <MS>` / `--reconnect-max-ms <MS>` | 重连退避上下限（退避翻倍至上限，带 ±25% 抖动） | 200 / 5000 |
| `--keepalive-sec <S>` | 空闲保活间隔，`0` 关闭 | 30 |

`llmproxyd`（服务端）：

| 参数 | 含义 | 默认 |
|---|---|---|
| `-c, --config <PATH>` | TOML 配置文件 | 无 |
| `--listen <ADDR>` | 隧道监听地址 | `127.0.0.1:9000` |
| `--kcp-bind <ADDR>` | KCP(UDP) 监听地址；不设则不起 UDP 监听 | 无 |
| `--upstream <URL>` | 上游 base URL（**不含 path**，收到的 path/query 原样拼在其后），`http://` 或 `https://` | `http://127.0.0.1:9100` |
| `--upstream-ca <PEM>` | 追加到内嵌根集之上的 CA 证书（自签/私有 CA 的 https 上游用） | 无 |
| `--upstream-host <HOST>` | 上游主机名（**两端必须一致**） | `localhost` |
| `--tenant <ID>` | 租户标识（**两端必须一致**） | 空 |
| `--block-cache-bytes <N>` | 服务端块存储预算（测试用它逼出淘汰与降级路径） | 256 MiB |
| `--cache-ttl-secs <S>` | 缓存有效期 | 21600（6h） |
| `--stream-wait-ms <MS>` | 并发流超限时的等待时限（等待而非立即拒绝） | 20000 |
| `--max-concurrent-streams <N>` | 同时访问上游的活跃流上限（所有 session 共享）；不设置则无界 | 无界 |
| `--max-pending-streams <N>` | 等待活跃流额度的全局逻辑流上限；不设置则无界 | 无界 |
| `--slow-flush-ms <MS>` / `--slow-flush-bytes <N>` | 慢路径 flush 窗口 / 字节阈值（先到者触发） | 100 / 1024 |
| `--disable-slow-path` | 关闭慢路径（对照实验用） | 关闭 |
| `--sse-batch-ms <MS>` | SSE 批量帧刷新窗口（越大越省带宽、事件滞留越久） | 150 |
| `--sse-batch-max <N>` | 单帧最多合并多少个事件 | 32 |

### https 上游（可选）

上游可以是 `https://`（服务端 `--upstream`、客户端 `--upstream-fallback` 都一样）。证书策略刻意保守：

| 事项 | 说明 |
|---|---|
| 根证书 | **内嵌 Mozilla 根集**（不读系统证书目录）——OpenWrt 上常常没有 `/etc/ssl/certs`，读系统存储会变成"开发机连得上、装到设备上不行" ✗ |
| 私有/自签 CA | `--upstream-ca <PEM>` **追加**（不是替换 ✓，公网上游照旧可用）。文件读不到、解析不出证书、证书不被接受都会**响亮失败**（不会"静默什么都没加"✗） |
| **没有**"跳过校验"的开关 | 那等于把 TLS 做成装饰品 ✗。校验失败 ⇒ 请求失败，**绝不静默降级成明文**（守门用例断言"上游一个请求都收不到" ✓） |
| scheme 校验 | `--upstream` / `--upstream-fallback` 的 scheme 在**启动时**检查：漏了或写错当场退出，而不是等第一个请求变成一个含义模糊的 502 ✗ |
| 代价 | 客户端 +3.1%（2.90→2.99 MB，rustls 本来已为 `wss://` 链着）；服务端 +30.2%（2.98→3.87 MB，此前完全没有 TLS 栈） |

### 配置文件（TOML）

字段名与上表同名同义（`snake_case`），两个二进制各读自己的文件：

```toml
listen = "127.0.0.1:9000"
upstream_base = "http://127.0.0.1:9100"   # 服务端字段名
upstream_host = "localhost"
tenant = ""
psk = "change-me"
worker_threads = 2
block_cache_bytes = 8388608
cache_ttl_secs = 21600
# max_concurrent_streams = 16              # 可选：显式限制活跃上游请求数
# max_pending_streams = 64                  # 可选：显式限制等待中的逻辑请求数
stats_file = "/overlay/dshp/stats.toml"   # 空字符串 = 只存内存
webui_token = ""                          # 空 = 关闭 WebUI
allow_passthrough = false
```

[openwrt/etc/dshp/llmproxyd.toml](openwrt/etc/dshp/llmproxyd.toml) 是一份可直接照抄的极小配置。

### 并发请求的准入与背压

一个客户端可以同时创建 10～20 个逻辑请求。生产默认不按请求数量限制服务端；如果
显式设置 `max_concurrent_streams`，它只限制**正在访问上游**的请求数，所有 session
共享这一额度。`max_pending_streams` 只在显式设置时限制等待队列。请求数量和缓存
生命周期因此不再绑定，服务端不会因为客户端 session 或 subagent 数量增加而拒绝请求。

新版客户端在发送 `ReqOpen` 后会等待服务端的 `StreamReady` 准入帧，拿到活跃额度
后才发送 `BodyChunk` 和 `ReqCommit`。显式配置限额时，排队请求不会把大请求体提前
堆进服务端的 stream channel；无界模式下则直接获得准入。只有配置了限额且额度耗尽
时，请求才会收到 `TOO_MANY_STREAMS`。

服务端会在握手能力中宣告 `stream-ready`。未声明该能力的旧客户端仍走兼容时序，
以便滚动升级；升级完成后应优先使用新版客户端，以获得请求体准入屏障和更稳定的
内存上界。活跃额度目前由所有 session 共享，单个 session 可能暂时占满额度；需要
严格跨客户端公平性时，应进一步配置或实现 per-session 活跃额度。

### 缓存与 session 的边界

session 只负责传输、取消、模板表和请求生命周期。请求体增量缓存使用内容寻址块：
服务端的 `BlockStore` 挂在进程级 `App`，客户端的远端块知识挂在 `Proxy`，因此重连、
并行 stream 和多个 subagent 可以共享同一 `Namespace` 下已经确认的块。不同租户或
上游主机通过 `Namespace` 隔离，不能互相引用块。

缓存提交采用请求级事务：一个请求只有在服务端返回响应头、越过提交点后，才把本次
发送的 literal 指纹加入共享账本。并行请求不会共用待提交列表，因此某个 subagent
失败或重试时不会清掉另一个 subagent 已经成功发送的数据。两个请求同时首次发送
同一块时，允许短暂重复传输；等任一请求提交后，后续请求即可使用 `REF`，优先保证
正确性和故障恢复。

### 环境变量

| 变量 | 作用 |
|---|---|
| `DSHP_PSK` | 预共享密钥（覆盖 TOML 的 `psk`） |
| `DSHP_ALLOW_LAN` | `1`/`true`/`yes` 等价于客户端 `--allow-lan` |
| `DSHP_WEBUI_TOKEN` | 服务端统计页面与统计接口的鉴权令牌；**空 = 关闭**。不要复用 `DSHP_PSK` |
| `DSHP_STATS_FILE` | 统计快照落盘路径；**空 = 只存内存** |
| `DSHP_ALLOW_PASSTHROUGH` | `1`/`true`/`yes` 时打开服务端直连透传（见下节），默认关闭 |
| `RUST_LOG` | 日志过滤（`tracing` 的 `EnvFilter`） |

## 管理端点与统计

| 端点 | 位置 | 鉴权 |
|---|---|---|
| `/__dshp/status` | 客户端与服务端都有 | 未配置 `DSHP_WEBUI_TOKEN` 时**保持开放**（诊断通道）；配了 token 后同样需要凭据 |
| `/__dshp/ui` | 服务端 | 需要 `DSHP_WEBUI_TOKEN`，未配置或凭据不符返回 `401` |
| `/__dshp/api/stats` | 服务端 | 同上（返回**原始整数**，单位换算只在页面里做） |
| `/__dshp/drain` | 服务端 | **仅 `POST`**，需要 `DSHP_WEBUI_TOKEN`，未配置或凭据不符返回 `401`；成功返回 `202` 后服务端**排空并退出** |
| `/__dshp/tunnel` | 服务端 | DSHP 隧道入口（WS 握手）；未知的 `/__dshp/*` 一律 404，不会漏给上游 |

```bash
# 客户端：增量路径的实时记账
curl http://127.0.0.1:8787/__dshp/status
# 关心这些字段：delta_requests / delta_fallbacks / req_raw_bytes / req_wire_bytes /
#              req_saved_ratio / ref_blocks / forgotten_blocks / known_blocks

# 服务端：统计页面（浏览器 Basic Auth，用户名 admin、密码即 token；脚本可用 Bearer）
curl -H "Authorization: Bearer $DSHP_WEBUI_TOKEN" http://127.0.0.1:9000/__dshp/api/stats
```

统计以「客户端发请求」为主视角，把字节分成上行/下行 × 前/后四组：

| 方向 | 前（应用层内容） | 后（链路上实际占用，含帧头） |
|---|---|---|
| 上行（客户端 → 上游） | `request_body_bytes` | `request_transport_bytes` |
| 下行（上游 → 客户端） | `response_body_bytes` | `response_transport_bytes` |

两个节省比例统一是 `1 - 后/前`：下行一般为正，**上行可能为负**（小请求加帧头比原始更大），所以别拿"上行省了多少"当判据。`protocols` 把 `chat_completions`/`responses`/`messages` 三条协议分开统计；token 与输入缓存命中率（`cache_hit_ratio`，同时给出 `cache_reports`/`usage_reports` 样本量）都从上游响应的 usage 里读——`null` 不算一次上报，`0` 算。

设置 `DSHP_STATS_FILE` 后服务端会持久化累计计数（启动时恢复，每个响应在阻塞线程里原子替换快照）；快照损坏或启动时无法写入会阻止启动，强制终止时未落盘的计数可能丢失。

页面默认深色，可切浅色/自动（`…/__dshp/ui?theme=light` 也可直接指定），主题只换 CSS 变量、不动任何数字。

## 优雅排空（计划内停机）

**为什么要它**：换二进制 / 改配置 / `systemctl restart` 都会给服务端发 `SIGTERM`。没有排空时进程**直接消失** ⇒ 在途响应被切断，SDK 看到传输错误、整轮对话白跑、还白付一次上游调用。这与「没发完绝不许当成发完了」是同一条红线的另一面：**能等的时候，不该主动制造"没发完"**。

触发方式两条，**行为完全一样**：

| 触发 | 说明 |
|---|---|
| `SIGTERM` / Ctrl-C | 生产路径：`systemctl stop` / `restart` / 换二进制都走这条 ⇒ **排空后退出**；`Restart=on-failure` 的 unit 里，`restart` 是显式的，所以照常拉起 ✓ |
| `POST /__dshp/drain` | 运维/脚本路径，需要凭据（排空会终止服务，所以**不能**像只读的诊断端点那样"没配 token 就开放"）；先回 `202`，再排空，最后退出 |

> ⚠️ 用端点触发时，进程是 **`exit(0)`（干净退出）** ⇒ 若 unit 写的是 `Restart=on-failure` **不会**自动拉起（要的就是"排空后停住"这个语义 ✓）。想"排空后重启"请用 `systemctl restart`（它发 SIGTERM，同样走排空 ✓）。

排空做的事，按顺序只有三件：

1. 向**每个活着的会话**发 `GOAWAY`（客户端收到后**立刻降级为直连上游 + 后台重连**，因此不会在一条即将关闭的会话上开新流）；
2. 等**在途流跑完**（轮询 `streams_inflight` 归零，上限 30s，可用 `DSHP_DRAIN_TIMEOUT_MS` 调整；到点如实记录并退出，不无限等）；
3. 退出进程。

排空期间：**新隧道与新透传请求都返回 `503`**（明牌失败优于"接了又被切"✗），管理端点照旧可用——`/__dshp/status` 会如实带 `"draining":true`，运维据此判断该不该重试。

```bash
# 排空后停住（systemd 的 Restart=on-failure 不会自动拉起 ⇒ 这是"排空后停机"的语义）
curl -X POST -H "Authorization: Bearer $DSHP_WEBUI_TOKEN" http://127.0.0.1:9000/__dshp/drain
# 排空后重启：用 systemctl restart（发 SIGTERM，同样走排空）
```

对应守门用例：`crates/e2e-tests/tests/goaway_drain.rs`（4 条）——

| 判据 | 内容 |
|---|---|
| 主判据 | 排空**不切断**在途响应：逐字节完整 + `truncated_responses == 0` + 服务端随后真的退出 |
| 客户端那一半 | 排空**当场**读客户端：`link_alive=false`、`mode=bypass`（此刻服务端还在等那条在途流 ⇒ 连接没断 ⇒ 只可能是处理了 `GOAWAY`） |
| 排空期间 | 新隧道与新透传 `503`，诊断端点仍可读且 `draining=true` |
| 负向对照 | 硬杀同一场景 ⇒ 客户端只拿到 0 字节、`truncated_responses == 1` |

> 写这组用例踩了三次**假判据**，都记在用例注释里：① 用"在途流已打开"当"响应正在流"（可能还停在请求上传）；② 用客户端的 `resp_bytes`（那是**按响应结束累加**的口径，读到非 0 时响应已经完了）；③ 用 mock 的 `sse_bytes`（它把整个 body **一次算好**，不是"已发出多少"）。真正的活信号只有**逐帧累加**的 `resp_frames.*` ✓。

## 直连透传（可选，默认关闭）

打开后服务端不再只是隧道出入口：凡不是 `/__dshp/tunnel` 与 `/__dshp/*` 的 HTTP 请求都会**原样转发给上游**（方法与 path/query 不改写，只有逐跳头例外），响应（含 SSE）原样回给调用方。

```bash
DSHP_ALLOW_PASSTHROUGH=1 llmproxyd --listen 127.0.0.1:9000 --upstream http://127.0.0.1:9100
```

| 事项 | 说明 |
|---|---|
| 默认关闭 | 关闭时非隧道请求返回 **403**，响应体写清"本端口服务什么 / 替代方案 / 怎么打开" |
| 为什么是显式开关 | 打开等于服务端对上游做普通反代：**谁能访问这个端口谁就能用上游**（凭据仍是上游自己的 key） |
| 体积上限 | 请求体 32 MiB，超过返回 413；这条通路不做分块转发 |
| 记账 | 单独一组 `passthrough`，**不并进隧道四组**（透传没有编码/复用这一步，并进去只会把节省率摊薄） |

## 测试与门禁

```bash
cargo test --workspace -- --test-threads=1   # 必须单线程：e2e 各自绑端口并启动子进程
```

端到端测试**启动真实二进制**，所以要先 `cargo build`；每个测试有超时保护，超时会连同子进程一起清理。真实语料相关的用例（`replay_real` / `replay_stats`）默认跳过，需要语料与 `DSHP_REAL_CORPUS=1` 才运行，语料缺失时不判红。

`dev-tools` 承载全部可重复的工程工作（不需要 Python 解释器）：

| 子命令 | 作用 |
|---|---|
| `gates [--selftest]` | 静态门禁：死常量、协议帧、协议字段、生产代码磁盘写入、文档入口、线程配置 |
| `baseline` | 合成基准（zstd / 批次 AEAD / SSE 模板 / base64）并执行合成门禁 |
| `verify-dicts` | 校验已提交的 `dicts/` 产物：sha256 + 字节数 + 清单一致性 |
| `train --corpus corpus --out dicts` | 从脱敏语料训练 zstd 字典 + 时间留出评估 + 语料门禁 |
| `smoke-corpus --out target/smoke-corpus` | 生成确定性合成语料，供无语料环境的门禁机制验证 |
| `desensitize --archive <归档> --out corpus` | 从真实流量归档转出脱敏语料；`--verify` 校验产物哈希 |
| `soak --duration 60 --ceiling-only` | 启动真实二进制的有界长稳压测（RSS 预算 32 MiB，趋势项可关） |
| `package --bin-dir <dir> --out dist` | 生成或校验（`--verify-only`）OpenWrt `.ipk` |
| `ci-failures <log>` | 从 cargo/CI 日志里点名失败的测试与门禁步骤 |

合成门禁 7 项硬指标（阈值以 `cargo run -p dev-tools -- baseline` 的输出为准，一律"越小越好"）：

| 指标 | 阈值 | 守护的决策 |
|---|---|---|
| `compression.sizes.patch_4turn` | ≤ 0.30 | 增量 patch 压缩率 |
| `compression.sizes.small_32_dict` | ≤ 0.80 | 字典是必需项（32 B 也要压得动） |
| `compression.dict_2k_vs_16k_ratio` | ≤ 1.10 | 2 KB 字典即饱和，不需更大字典 |
| `aead.batching.tag_reduction_ratio` | ≤ 0.20 | AEAD 作用域是批次不是单帧 |
| `aead.batching.frame_density` | ≤ 0.20 | 帧粒度是批次不是 chunk |
| `template.template_ratio` | ≤ 0.06 | 响应侧模板化收益 |
| `template.batched_total_ratio` | ≤ 0.08 | 模板化 + 批量帧 + 批次 AEAD 的总占比 |

语料重训门禁另有一套上界/下界判据（`chosen.gain_vs_nodict ≥ 1.0`、`structure_only.gain_vs_nodict ≥ 1.30`、`chosen.holdout_ratio ≤ 0.70`、`chosen.dict_bytes ≤ 131072` 等），只在有 `corpus/` 的机器上运行。

**为什么压缩类门禁必须进 CI**：这类退化**不会让任何测试变红**，只会让省下来的流量悄悄变少。同理还有一道「死常量门禁」——一条没人引用的硬约束也不会让测试变红，它只会让人**以为**那条约束被守住了。

### 持续集成

```bash
pwsh -File scripts/ci.ps1      # Windows
bash scripts/ci.sh             # Linux / macOS
```

本地脚本与 [.github/workflows/ci.yml](.github/workflows/ci.yml) 的步骤一致：格式 → Clippy（`-D warnings`）→ 构建 → 测试 → `gates` + `package --selftest` → `baseline` + `verify-dicts` →（有语料时）重训门禁 → 合成夹具 → soak。测试失败时脚本会自动调 `ci-failures` **点名失败的测试或门禁**。

GitHub Actions 三个 job：`rust`（fmt / clippy / 测试，测试失败会整轮重跑一次以区分抖动与真回归）、`gates`（打包自检 + 静态门禁 + 合成门禁 + 字典产物门禁 + 语料门禁机制 + 有界 soak）、`arm`（zig 交叉构建 `aarch64-unknown-linux-musl` + opkg 打包与自校验 + 上传产物）。

## 部署（OpenWrt / ARM）

目标平台 `aarch64-unknown-linux-musl`，产物是静态单二进制（`readelf -d` 的 `NEEDED` 必须为 0）：

```bash
bash scripts/build-arm.sh --package     # 构建 + 校验 + 打出 dist/dshp-aarch64-unknown-linux-musl.tar.gz
cargo run -p dev-tools -- package --bin-dir target/aarch64-unknown-linux-musl/release --out dist
cargo run -p dev-tools -- package --verify-only dist/dshp_0.1.0_aarch64.ipk
```

打包器对每个载荷做 ELF 自检（ELF32/ELF64 小端、`e_machine` 与 `--arch` 一致、不得有 `PT_INTERP`/`PT_DYNAMIC`），`--selftest` 另含反例（非 ELF + **两个架构互斥反例** ✓）。安装步骤与 UCI 配置见 [openwrt/README.md](openwrt/README.md)。

> 目标架构上的实测资源：RSS 约 14 MiB、二进制约 **2.99 MB**（aarch64 客户端，含 https 上游的 TLS 栈；服务端 3.87 MB）、纯内存无运行时磁盘写入（`gates` 扫生产代码的写入类 API，命中即失败）。
>
> **armv7 已构建并校验**（第 182 轮，缺口 #7）：客户端 2,874 KiB / 服务端 2,985 KiB，
> `file` 判定 `ELF 32-bit LSB executable, ARM, EABI5 … statically linked, stripped` ✓，
> 并过 `dev-tools package --arch armv7` 的 ELF 自检（无 `PT_INTERP`、无 `PT_DYNAMIC` ✓）。
> **mipsle 仍未构建**：`rustup` 没有它的预编译 std（tier-3）⇒ 要走 nightly 的 `-Z build-std` ✗。

## 当前状态

| 里程碑 | 状态 |
|---|---|
| M0 原样透传（四协议逐字节一致） | ✅ 含压缩相关内存 < 1 MiB 的实测 |
| M1a 请求侧块级增量 | ✅ 上行实测 0.545% / 3.999% |
| M1b 字典标定 | ⚠️ 真实流量标定完成（`dict_patch` 16 KB、holdout 0.6226），CPU 开销报告待补 |
| M2 响应侧模板归纳 | ✅ 首响应 9.48%、稳态 7.26% |
| M3 慢路径 + SSE 降级 | ✅ 被中间设备拦掉 Upgrade 时 16 ms 落到 SSE |
| M4 KCP + 运行时质量降级 | ⚠️ 核心完成，换档灵敏度需真实弱网复核 |
| M5 块级补缺 | ✅ 中段插入图片后仍复用块，补缺额外 RTT ≤ 1 |
| M6 静态构建 / opkg / 内存预算 | ⚠️ 均已达标，72h 真机长稳未做 |
| M7 故障演练 | ⚠️ 16 项进程内演练通过，真实网络/设备演练未做 |
| 传输安全（X25519 + PSK 握手 + ChaCha20-Poly1305） | ✅ 含抗重放水位与"认证失败不推进水位" |

## 已知缺口与限制

| # | 缺口 | 后果 |
|---|---|---|
| 1 | 换档灵敏度（`escalate_factor`）未经真实弱网复核 | 可能偏迟钝或偏灵敏；两端档位不一致只影响恢复能力，不影响正确性 |
| 2 | SSE 续传（`STREAM_GAP`）：**服务端半边已就绪，客户端半边未交付** ⇒ **功能还不可用** | 隧道断在响应中途**仍然**报错重来（多花一次上游调用）。服务端已具备：按流的环形缓冲（256 KB × 在途流，**有界** ✓）、`RESUME{req_id, ack_seq}` 重放、断点不在则 `ERR(STREAM_GAP)`、hold 窗口 60s、以及**能力门控**（见下方说明）。客户端半边**试过两次都不合格** ✗：改完之后 `link_timing` 与 `recovery` 两套时序用例会**挂死**（A/B：干净树 7.65s/20.6s 绿 ✓ vs 改动后 90s 超时 ✗）⇒ **不交付**（宁可缺口明摆着，也不留一棵半接的树 ✓）。**当前诊断（已排除法推进到上游侧）**：变体"出口只登记、泵照旧直接读"**照样挂** ✗ ⇒ 读路径已排除 ✓；卡住时查服务端状态得 `phases="2=buffered:await-upstream"`、`streams_opened=2`、`received_frames=7`、`streams_inflight=0` ⇒ 请求**到了服务端** ✓、服务端**正等上游回话** ✓ ⇒ 客户端"等不到响应头"是**下游现象** ✓；下一步该把仪器装到**夹具的上游 mock**（它的连接处理是串行的 ✗）✓。设计结论已固化：a) 续传只服务于**已开始产出**的流 ✓；b) ack **只能**在字节确实交给 SDK 之后推进 ✓；c) 客户端能力位与服务端 hold 必须**同时**开 ✓ |
| 3 | 多上游故障转移（`alt_bases` / `RETRY_ALT_BASE`）**未实现** | 上游挂了只能整条链路降级；要先定义 POST 的"提交点"语义 |
| 4 | 字典对**完整 body** 增益接近中性（1.02×） | 冷启动整段压缩吃不到字典红利，需真实流量复核 |
| 5 | M6 的 72h 长稳压测未做 | 有界 soak（240 s / 2.3 万请求）服务端上包络只动 0.01 MiB，但长稳未在真机验证 |
| 6 | 字典的「客户端运行时训练 + 上送」**未实现** | 字典是构建期内嵌，运行时不会按设备真实流量自适应 |
| 7 | **armv7 已构建并校验** ✓；**mipsle** 未构建 | mipsle 装不上：`rustup` 没有该 target 的预编译 std（tier-3）⇒ 需 nightly 的 `-Z build-std`。armv7 的交叉 C 工具链由 **zig** 提供 —— 原先记的"缺 `arm-linux-musleabihf-gcc`"在 zig 路径下**不成立** ✓（与 aarch64 同一套 ✓） |
| 8 | `req_id` 幂等表只做"重复即拒" | 尚未做到"直接返回已缓存结果" |

> 已完成的条目（各留一行说明，便于与旧记录对照）：
>
> * **`GOAWAY` 优雅排空**（原第 7 行）在第 181 轮实现 —— 见「优雅排空（计划内停机）」；
> * **https 上游**（原第 4 行"上游只支持明文 HTTP"）在第 181 轮实现 —— 见「https 上游（可选）」。
>   当时的限制是真的（`enforce_http(true)` 写死），而它的代价是**必须靠外部做 TLS 终止** ✗。
>
> **半完成的条目要特别说明**：SSE 续传（上面第 2 行）的服务端已在位，但客户端**故意还没有**
> 声明 `"resume"` 能力 ✓ —— 不是漏了：服务端一见该能力位就会在客户端断线期间**继续消费上游**
> （设计 §11.2 的"hold + 缓冲" ✓），客户端若还不能真的续传，那笔钱就是**白烧**的 ✗✗。
> ⇒ 能力位必须与客户端实现**一起**上 ✓。代价侧的护栏已就位：hold 窗口 60s（超窗主动结束该流）、
> 环有界（256 KB × 在途流 ⇒ 最坏 1 MiB），两者都能在 `/__dshp/status` 的
> `resp_rings_count` / `resp_rings_bytes` 上看到 ✓。
>
> 客户端半边为什么没交出来（第 184/185 轮）：两次实现都在**时序用例**上挂死（见第 2 行说明），
> 而这两套用例守的正是"降级/重连的时延与语义" —— 那是本项目最不愿悄悄改坏的东西 ✗。
> 结论是**宁可功能不可用，也不让已有的时序保证退化** ✓；下一次要先造"可切断链路的夹具"把机制观测出来，
> 再动实现 ✓（草案与全部证据留在 `dev-notes/resume-client-草案.*` 与设计文档 §11.2 ✓）。

其它有意为之的行为：HTTP header 名的大小写无法逐字节保留（hyper 入口已规范化，语义上大小写不敏感）；逐跳头按规范允许中间节点增删，不在逐字节比对范围内。

## 许可证

**MIT**，见 [LICENSE](LICENSE)；工作区所有 crate 通过 `[workspace.package] license = "MIT"` 统一继承。

更细的口径与复现命令：回归门禁与语料脱敏见 [bench/README.md](bench/README.md)，设备部署见 [openwrt/README.md](openwrt/README.md)。
