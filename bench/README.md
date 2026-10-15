# bench — DSHP 压缩/加密层回归门禁

## 目的

把设计文档里所有「因为实测如此，所以这样设计」的结论变成**可执行的门禁**，防止实现过程中无声地退化回被否决的方案。

最关键的两条防回归：

- **禁止逐帧 AEAD** — 16B tag 在 203 个小帧上会产生 261.9% 的膨胀，把模板化收益吃掉 72%
- **禁止逐 chunk 成帧** — 24B 固定帧头 × 203 帧远超 6B 的模板增量载荷

这两条都是「实现起来很自然、但会毁掉核心收益」的陷阱，所以必须有机器判定。

## 三道门禁，两种运行环境

阈值与求值逻辑的**唯一权威定义**在 [`dev-tools gates`](dev-tools gates)——`dev-tools train` 与
`dev-tools verify-dicts` 共用它。阈值一旦复制成两份，就会出现「CI 通过而本地失败」的分叉。

| 门禁 | 脚本 | 环境要求 | 跑在哪 |
|---|---|---|---|
| **合成门禁**（8 项） | `dev-tools baseline` | 无 | CI + 本地 |
| **字典产物门禁** | `dev-tools verify-dicts` | 无 | CI + 本地 |
| **语料驱动的重训门禁** | `dev-tools train` | 需要 `corpus/` | 有语料的机器 |

### 为什么「字典产物门禁」必须与「重训门禁」拆开

`dev-tools train` 依赖 `corpus/`，而 `corpus/` 源自**真实用户流量**、已 gitignore。
CI 里没有它，`dev-tools train` 会直接退出——于是「把真实语料门禁纳入 CI」这个要求
无法靠直接调用满足。

拆开之后：

* **CI 每次 push 都跑** `dev-tools verify-dicts`，它校验已提交的 `dicts/` 与记录是否自洽：
  * 重新计算每个字典的 `sha256` 与字节数，与 `manifest.json` 的记录比对
    → 想换字典就必须重跑训练（因为要拿到新字节让 sha256 自洽）；
  * 对 `metrics.json` 的已记录值求出全部回归门禁
    → 阈值下降或指标退化都会失败；
  * `bench/real_baseline.json` 必须与 `dicts/metrics.json` 逐字段一致
    → 改动记录后必须重跑 `--update-baseline`；
  * `chosen.size` 必须等于 `dict_patch` 的实际字节数。
* **有语料的机器上**才跑 `dev-tools train`（重训 + 全量门禁 + 落盘）。

这不能防住蓄意造假（任何人都能手工编辑 JSON），但能防住**事故性**的产物/记录不一致
——那才是这类门禁真正要拦的东西。已实测三种篡改场景都会失败（见
`cargo run -p dev-tools -- verify-dicts` 的设计说明）。

### 训练是确定性的

实测：对同一份语料重跑 `dev-tools train`，`dict_patch` / `dict_ctrl` 的 sha256
**逐字节一致**。这一点很重要——否则 CI 的 sha256 绑定会产生偶发失败，门禁很快
就会被人绕过。

## 快速开始

```bash
cargo build -p dev-tools   # 可选；缺失时自动跳过对应组

cargo run -p dev-tools -- baseline                    # 合成门禁，全绿退出 0
cargo run -p dev-tools -- baseline --check-timings    # 额外输出算法相对计时（不作跨机器门禁）
cargo run -p dev-tools -- baseline --json out.json    # 导出原始结果
cargo run -p dev-tools -- baseline --update-baseline  # 重新生成 baseline.json

cargo run -p dev-tools -- verify-dicts                # 字典产物门禁（CI 用，不需要语料）
cargo run -p dev-tools -- train                  # 语料驱动的重训门禁（需要 corpus/）
```

或者一条命令跑完与 CI 完全相同的全部检查：

```bash
pwsh -File scripts/ci.ps1     # Windows
bash scripts/ci.sh            # Linux / macOS
```

## 门禁清单

| 指标 | 阈值 | 守护的设计决策 |
|---|---|---|
| `compression.sizes.patch_4turn` | ≤ 0.30 | 增量 patch 压缩率 |
| `compression.sizes.small_32_dict` | ≤ 0.80 | **字典是必需项**：32B 小载荷也必须压得动 |
| `compression.dict_2k_vs_16k_ratio` | ≤ 1.10 | **2KB 字典即饱和**，不需更大字典（低内存友好） |
| `aead.batching.tag_reduction_ratio` | ≤ 0.20 | **AEAD 作用域是批次不是单帧** |
| `aead.batching.frame_density` | ≤ 0.20 | **帧粒度是批次不是 chunk** |
| `template.template_ratio` | ≤ 0.06 | 响应侧模板化收益 |
| `template.batched_total_ratio` | ≤ 0.08 | 模板化 + 批量帧 + 批次 AEAD 的总占比 |
| `base64.decode_ratio` | ≤ 0.80 | base64 图像解码为二进制传输 |

## 为什么门禁只断言比值

**体积比值是数据属性，与 CPU 架构无关**；绝对耗时随机器、编译器、后台负载变化极大，作为门禁只会制造假失败。

具体来说：

- `template.template_ratio` = 0.0251 在任何机器上都成立（SSE chunk 的 JSON 模板冗余是协议属性）
- `aead_8192_us` 在 x86 上是 4.55µs，在 Cortex-A53 上约 55µs —— 同一个断言不可能同时适用于两者

因此耗时指标默认仅**记录**，`--check-timings` 只额外打印算法间比值；Rust 原生计时受平台和压缩快路影响较大，不作为跨机器失败门禁。

## baseline.json 的角色

`baseline.json` 保存上一次被人工确认的测量结果。它是**契约**，不是缓存：

- 门禁失败时，先判断是「实现退化」还是「环境变化」
- 只有确认是有意变更时，才用 `--update-baseline` 覆盖，并**在 code review 中评审 diff**
- 禁止在 CI 里自动更新基线 —— 那等于删掉门禁

## 在 ARM 目标上运行

体积类门禁在 ARM 上应当给出**完全相同的值**，可以直接跑在软路由上验证：

```bash
# 软路由（OpenWrt，需 cargo run -p dev-tools -- + zstandard）
cargo run -p dev-tools -- baseline
```

绝对值差异对照（x86_64 → Cortex-A53 单核，约 8–15×）：

| 指标 | x86_64 | Cortex-A53（推算） |
|---|---|---|
| ChaCha20-Poly1305 @1KiB | 2.9µs | ~35µs |
| ChaCha20-Poly1305 @64KiB | 29.9µs | ~360µs |
| zstd-1 @8KiB | 8.7µs | ~105µs |
| 200KB SSE 响应加密总耗时 | — | ~0.9ms |

结论：**AEAD 在 ARM 上不是瓶颈**，一个持续数秒的 SSE 响应只花约 1ms 做加密。

## 与 Rust 层 benchmark 的分工

本脚本测的是**底层 C 库（zstd / ChaCha20-Poly1305）的性能地板**与**数据属性**，与具体实现语言无关。它不能替代：

| 层次 | 工具 | 测什么 |
|---|---|---|
| 参考地板（本脚本） | Rust + C 库 | 压缩率、tag 开销、算法间比值 |
| 实现层 | Rust `criterion`（M0 建立） | 我们的编码/扫描/重组实现的真实开销 |
| 端到端 | 故障注入套件（M7） | 正确性与降级行为 |

Rust 层实现应当**不显著劣于**本脚本给出的地板；若显著劣于，说明实现有问题（如未复用压缩上下文、未预编译字典）。

## 语料脱敏（`dev-tools desensitize`）

真实流量日志含完整系统提示词、全部对话正文和半脱敏凭据，**不能直接入库**。
`dev-tools desensitize` 把它转成可入库的语料。

```bash
cargo run -p dev-tools -- desensitize --archive "<日志转储.tar.gz>" --out corpus/
cargo run -p dev-tools -- desensitize ... --dry-run --sample 2 --max-files 3   # 只看前后对照
cargo run -p dev-tools -- desensitize ... --sections request,headers,response,api
```

### 策略

| 处理 | 对象 |
|---|---|
| **保留** | JSON 键名、结构骨架、低基数枚举值（`role` / `type` / `model` / `cache_control`…）、schema 元数据（`required` / `enum`） |
| **替换为等字节长填充物** | 所有其他字符串值（`content` / `text` / `thinking` / `signature` / `description` / `id` / `file_path` / `command` …） |
| **整键删除** | 无歧义凭据（`x-api-key` / `authorization` / `access_token` / `password` …） |
| **只替换值，保留键** | 含义含糊的键（`signature` / `token` / `key` / `session`）——删除会破坏 JSON 结构 |
| **header** | 键名保留；凭据类值 `[REDACTED]`；低熵值保留；其余替换 |

三条关键实现细节，都是被实测抓出来的：

1. **填充物必须是种子驱动的独立伪随机流，不能用「固定池 + 偏移切片」。**
   池切片会让不同填充物共享长公共子串，压缩器据此找到**虚假的跨样本匹配**。
   实测该缺陷把语料压到 **12.2%**，而修正后是 **62.5%**——前者偏乐观，后者偏保守。
2. **长度按 JSON 转义后的字节数保持，不是按字符数。**
   按字符会让中文内容缩水 3 倍；忽略转义会让含大量换行的正文再缩水约 5.6%。
3. **必须区分「JSON 往返损失」与「脱敏额外损失」。**
   脚本内置保真度自审计，逐文件报告两者。当前实测：往返损失 0.91%（原日志混用
   `","/":"` 与 `", "/": "` 两种分隔符风格），**脱敏额外损失 0.00%**。

### 保真度与偏差（重要）

| 项 | 结论 |
|---|---|
| 字节精确性 | **额外损失 0.00%**，脱敏不改变任何字段长度 |
| 结构性 | 键名、枚举、SSE 字段、header 名全部保留 → **字典结构覆盖率不受影响** |
| 内容可压缩性 | 填充物近乎不可压缩，真实自然语言约 25–35% → **压缩率是保守下界（低估收益）** |
| 已知残留 | JSON Schema 的**属性名**属于键名，因此工具接口字段名仍可见 |

### 验收要求

脱敏后**必须**跑泄露检查才能入库：

- 从原文内容字段抽 ≥200 个特征子串作探针，在脱敏语料中全文搜索，**要求零命中**
- 定点检查高危项：凭据前缀与后缀、系统提示词片段、trace id、工具调用命令、原文文件名

当前实测：**200 探针零命中，12 项高危全部 clean，45 个成员 SHA256 全部一致**。

## 字典训练（`dev-tools train`）

从脱敏语料训练 `dict_patch` / `dict_ctrl` / `dict_sse`，在**时间留出集**上评估。

```bash
cargo run -p dev-tools -- train                  # 训练 + 评估 + 门禁
cargo run -p dev-tools -- train --update-baseline   # 落盘字典到 dicts/ 并更新基线
```

### 方法论

| 要点 | 做法 |
|---|---|
| **时间切分，不随机切分** | 字典是静态产物：生产上训练一次用于此后所有流量。故所有 patch 按时间排序，前段训练、后段留出。随机切分会把几乎相同的相邻样本分到两侧 |
| **训练目标是 patch，不是完整 body** | 热路径发送的是新追加的 message JSON；`tools` 等不变尾部由 CDC 块引用覆盖，不进字典目标 |
| **过滤畸形 patch** | 非追加式会话会产生「整个 messages 数组」级别的 patch，那不是热路径载荷（实测丢弃 21/53 对） |
| **选型按结构骨架指标** | 见下方「为什么不能用整条 patch 选型」 |

### 实测结果

| 指标 | 无字典 | 有字典 | 增益 |
|---|---|---|---|
| `dict_ctrl` 控制帧 | 80.74% | **21.49%** | **3.76x** |
| 结构骨架（留出集） | 44.61% | **20.76%** | **2.15x** |
| 整条 patch（留出集） | 65.16% | 63.77% | 1.02x |
| `dict_sse` 响应流 | 9.33% | 8.46% | 1.10x |
| 完整 body（冷路径） | 61.48% | 61.54% | 1.00x |

### 三条必须知道的限制

**1. 整条 patch 上的字典增益测不出来——这是语料构造的必然结果。**

脱敏把正文换成了 36 符号伪随机串，其熵约 5.17 bit/char ≈ **65%**，正好等于实测的整条 patch 压缩率 65.16%。也就是说**这个 65% 反映的是填充物字母表大小，与真实流量无关**。伪随机串不含重复子串，而重复子串正是字典唯一能利用的东西——所以字典在整条 patch 上必然只有 ~1.02x。

只有剥离正文后的**结构骨架**（占原文 4.3%）才承载跨样本重复结构，也只有它上面的增益是真实的。

**2. 「2KB 字典即饱和」的旧结论被推翻。**

早期用窄合成控制消息得出「2–4KB 即饱和」，在真实 patch 结构上不成立：

| 字典 | 骨架留出指标 | 骨架增益 |
|---|---|---|
| 512B | 37.36% | 1.19x |
| 4KB | 26.02% | 1.71x |
| 16KB | 21.92% | 2.03x |
| 32KB | **20.76%** | **2.15x** — **仍未饱和** |

骨架指标在 32KB 处依然在改善，因此**这个方法无法确定最优字典尺寸**。脚本会显式报告 `saturation.saturated=false`，不要据此断言「字典已足够大」。

**3. 为什么不能用整条 patch 选型。**

36 符号伪随机串的熵把所有尺寸的整条指标压成同一个数（512B..32KB 全部在 63.77–64.67%），完全没有区分度。实测用它选型会选出 512B，把骨架增益从 2.03x 打到 1.19x。选型必须用骨架指标。

### 由这些限制导出的设计结论

内容侧收益无法用脱敏语料验证（脱敏与保留内容可压缩性在定义上互斥）。因此生产上应改为：

> **字典在客户端本地训练**——数据从不离开设备，无需脱敏，且天然匹配使用者的领域词汇。训练好的字典（几十 KB）在握手时随 `CAPS` 一次性上传给服务端，按 `dict_id`（sha256 前缀）缓存复用。

内嵌的固定字典退化为**首启动的引导默认值**。

## 尚未覆盖的门禁

以下设计决策**无法**在本脚本中测出，需要 Rust 层单元测试或配置断言（M0 建立）：

| 决策 | 断言方式 |
|---|---|
| manifest 必须禁用字典 | 配置/分支单元测试：高熵路径不得走字典压缩 |
| `windowLog` 必须为 17 | 启动时自检，超限拒绝启动 |
| 压缩上下文必须对象池复用 | 分配计数器测试：并发 4 流不得新建超过 2 个 CCtx |
| 帧上限 1MB / stream 上限 4 | 协议层边界测试 |
| 模板由 server 主导归纳 | 集成测试：client 不得单方面建模板 |
