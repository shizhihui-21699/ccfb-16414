# SecurePrint — 企业安全打印刷卡释放服务

员工在任意电脑提交打印任务后，文件**不会**立刻从打印机出来。任务先加密暂存在服务器，
员工走到**任意一台**受管的打印机前刷工卡或扫二维码，通过身份验证后，任务才在**那台**打印机上输出。

这解决了工资单、并购合同、解除劳动关系通知书这类文件"打印后被路过的人顺手拿走"的问题。

```
   ┌──────────┐   ①提交(PDF/文本)    ┌────────────┐   ④一次性释放授权   ┌──────────┐
   │ 员工电脑 │ ───────────────────▶ │  中央服务器 │ ◀────────────────── │ 分公司   │
   └──────────┘   (落地即加密)        │  加密暂存   │   (Ed25519 签名)     │ 释放终端 │
                                     │  过期即销毁 │                      │ (Agent)  │
                                     └────────────┘                      └────┬─────┘
                                                                  ②刷工卡/扫码 │
                                                                  ③按品牌驱动  ▼
                                                                        ┌──────────┐
                                                                        │ 各类打印机│
                                                                        └──────────┘
```

---

## 1. 为什么要"暂存 + 刷卡释放"，而不是打印驱动自带的"安全打印"

HP/Canon/Kyocera 都自带"保密打印(PIN 打印)"。它们不适用于本场景，因为：

| 自带方案 | 本项目 |
|---|---|
| PIN 存在**本机**打印机内存里 | 文档在**服务器**，打印机只接收已授权的字节流 |
| 只能在同一台打印机取件 | 任意一台受管打印机取件（出差场景的核心） |
| 换品牌就换一套操作 | 员工无感知，一套流程 |
| 打印机的加密能力不可审计 | 服务器侧 AES-256-GCM，密钥分层，可审计 |
| 打印机断电/重启任务丢失 | 服务器暂存，取件窗口内不会丢 |
| 无法集中策略（谁能打彩色、谁能打 A3） | 服务器统一策略 + 能力路由 |

代价是必须自己做：**多品牌驱动适配**、**离线可用**、**加密暂存**、**过期销毁**。下面逐条说明。

---

## 2. 五个难点的解法

### 2.1 十几个品牌型号，接口各不相同

**问题**：HP 用 PCL + PJL、Ricoh 常走 RPCS、Kyocera 有自己的 KPDL、Canon imageRUNNER
默认 UFR II、部分老机型只有 LPD、新机型都支持 IPP/AirPrint。传输层还有 9100 / IPP / LPD / 厂商 REST 之别。

**方案：把品牌差异收敛到一个 30 行的适配器后面。** 见 `drivers` 模块。

```
core  ──  PrinterDriver 接口（唯一缝）
                │
   ┌────────────┼──────────────┬───────────────┐
PclRawSocketDriver        PostScriptDriver   IppDriver
   │                            │               │
 HP / Kyocera / Ricoh     Canon / Konica    任何支持 IPP 的
 （PCL5 光栅 + raw 9100）  （PS3 + raw 9100）   机型（含 AirPrint）
```

关键设计决策：

- **一律先转成 1-bit 光栅再交给打印机**，而不是把 PDF 直传给打印机解释器。
  理由有两条：① 排版在不同品牌上完全一致（工资单在苏州和慕尼黑打出来必须一样）；
  ② **安全**——PostScript 是一个编程语言，把提交者上传的内容当 PS 直接交给打印机等于让
  提交者在打印机上执行代码。
- `DriverRegistry` 支持**按型号字符串自动匹配**（`"KYOCERA TASKalfa 3554ci"` → Kyocera 驱动），
  匹配不到时回落到 IPP 通用驱动。**只有"通用路径跑不通"的畸形型号才需要单独写驱动**——
  这就是十几个品牌能维护得动的原因。
- 品牌插件可通过 `ServiceLoader` 从独立 jar 加载，集成商无需 fork 本项目（见 `DriverRegistry.withBuiltinsAndPlugins`）。
- **驱动永远拿不到 spool 密钥**，只拿到已解密的 `RenderRequest`，且其 `documentBytes` 只在
  `deliver()` 调用期间有效。品牌插件在密码学信任边界之外。

已实现并测试的驱动：`hp.laserjet.pcl5.raw9100`、`kyocera.ecosys.pcl5.raw9100`、
`ricoh.aficio.pcl5.raw9100`、`canon.imagerunner.postscript.raw9100`、
`konica.bizhub.postscript.raw9100`、`generic.ipp`。

### 2.2 出差在分公司打印

**问题**：员工在上海总部提交，人在苏州分公司。

**方案**：`Employee.travelSiteIds` + `PrintJob.collectSites`（见 `core/domain`）。
提交时把员工当前可取的站点集合**快照**进任务记录，manifest 构建按站点索引查询。
`Employee.ANY_SITE` (`"*"`) 留给审计/高管等确实需要任意取件的角色，**不是默认值**。

释放时双重校验：`ReleaseService.release` 检查 `job.collectableAt(agent.siteId())`，
同时 `agent.siteId()` 必须等于 `printer.siteId()`——**一个被攻陷的分公司 Agent 不能把文档
打到另一个国家的打印机上**。

### 2.3 打印机与服务器之间网络可能中断

这是整个系统里最需要诚实对待的部分。完整设计见第 4 节。

**一句话**：Agent 定期同步"清单 + 已用该 Agent 公钥包裹的数据密钥 + 密文"，断网时用本地清单授权打印；
恢复后对账。**断网期间 Agent 的授权完全来自上一次同步的签名清单，服务器不参与**——因此清单必须是短时效、严格递增序号、且 Agent 在过期后**失败关闭（fail-closed）**。

### 2.4 暂存期间文件本身要加密

**方案：信封加密（envelope encryption）+ 密钥分层。** 见 `core/store/SpoolEnvelope`。

```
            每个任务一把全新随机 data key (256-bit)
                        │
     ┌──────────────────┴───────────────────┐
     │                                      │
  AES-256-GCM 加密                     AES-256-GCM 加密
  (文档 + PrintSpec)                  data key（用 KEK 包裹）
     │                                      │
     ▼                                      ▼
  密文(spool blob)                     包裹后的 key
     └──────────────┬───────────────────────┘
                    ▼
             同一个 spool 文件
                    │
        KEK = HKDF-SHA256(安装主密钥, "spool-kek/v2")
        （生产环境主密钥在 KMS/HSM 中）
```

- **GCM 带 AAD**，AAD 绑定 `(jobId, ownerEmployeeId)`，所以拿到数据库写权限的人**无法把一个密文
  挪到另一个任务记录上**。
- **AAD 还区分密钥包裹和内容加密**（`keyAad` / `contentAad`），密钥包裹不能被当作内容密文重放。
- **销毁 = 删除密钥包裹**（crypto-shredding）。即使备份里还留着密文，没有 KEK 包裹的 data key，
  它就是不可解的随机字节。这把"过期销毁"从"尽力删除文件"变成"密码学上不可恢复"。
- **轮换 KEK 只需重新包裹 data key**，不需要重新加密所有文档。
- 传输中的文档不落盘：`SubmissionService` 在密封后立刻 `Arrays.fill(userBytes, 0)`，
  避免线程堆转储泄露工资单。

### 2.5 超时未取的任务自动销毁

**方案**：`ExpirySweeper`（见 `server/service`）。

1. 每个任务有 `holdUntil`（默认 8 小时，可配置，上限 30 天）。
2. 定时扫描到期任务，**原子地**从 `HELD` 迁移到 `EXPIRED`（`JobStore.claimExpired`）——
   只有赢得这次迁移的扫描线程才有权删除，两个并发扫描不会重复删除或漏删（有并发测试覆盖）。
3. 赢得迁移后：**物理删除** spool blob，任务记录改写为墓碑（tombstone），`spoolObjectId` 清空，
   只保留"谁、什么类别、何时、为何"给审计用。
4. 因为 blob 里同时装着 data key 的包裹副本，删掉 blob 等价于 crypto-shred。
5. 启动时 `purgeOrphans` 清理"盘上有 blob 但没有任何存活任务引用"的孤儿对象。

---

## 3. 在线释放：并发下"只能打一次"

核心在 `InMemoryJobStore.claimForRelease`：`HELD → RELEASING` 的原子迁移。

```java
// ReleaseFlowTest.concurrentReleasesAtTwoPrintersYieldExactlyOneWinner
// 16 个线程同时用同一 job 在 2 台打印机之间抢释放
assertEquals(1, wins.get());          // 恰好一个赢家
assertEquals(15, denials.get());
```

JDBC 实现必须用 `UPDATE jobs SET state='RELEASING' WHERE job_id=? AND state='HELD'`
并检查受影响行数——**不能**写成先读后写（接口上的 Javadoc 明确写了这一点）。

释放授权 `ReleaseGrant` 是服务器 Ed25519 签名的对象，绑定
`(jobId, employeeId, agentId, printerId, nonce, 有效期)`，并携带
用该 Agent X25519 公钥包裹的数据密钥：

```java
Ecies.seal(agentPub, dataKey, aad = agentKeyAad(agentId, jobId, employeeId))
```

- 授权被截获也没用：**只有目标 Agent 的私钥能解出 data key**，且 AAD 把它绑死到
  (agent, job, owner)。
- 授权只能用一次：Agent 侧维护已消费 nonce 集合，**在投递前**消费。投递失败后必须重新申请授权，
  而不是重放旧授权。

员工身份来自**工卡 UID 的加盐摘要**（`Hmac.badgeDigest(pepper, canonicalUid)`），
原始 UID 从不落库、从不日志。工卡 UID 熵很低，无 key 的哈希可被彩虹表反查，
所以 pepper 是必需的。

---

## 4. 离线释放：设计、保证与取舍

### 4.1 机制

每次成功同步，服务器给 Agent 推送：

1. **签名清单**（`ReleaseManifest`）：本站点可释放的任务列表（jobId、owner、holdUntil、spoolObjectId、
   以及**每个任务用该 Agent 公钥包裹的 data key**）。
2. **密封的 spool 密文**。

Agent 把两者落本地。断网时，刷卡走：

```
清单签名验证 → agentId 匹配 → 有效期/最大龄 → sequence 严格递增
   → 任务在清单中 → owner 匹配刷卡员工 → 未过 holdUntil
   → ECIES 解出 data key → 解密 → 品牌驱动渲染 → 投递
```

Agent 侧 `ManifestVerifier` 的防重放控制：
- `sequence` 每 Agent 严格递增，**持久化在加密 vault 里**（`AgentKeyVault`），重启不丢。
- `expiresAt` 与 `maxAge` 双重时效，一周前截获的清单不能长期复用。
- 同一清单内 jobId 重复直接拒绝。

### 4.2 离线期间的诚实性：journal + 对账

这是最容易被做"假"的地方，所以单独设计。

- **打印前**先写本地 `OfflineJournal`（append-only NDJSON），再投递。崩溃中断会留下
  `IN_PROGRESS` 记录，对账时如实报告为 `outcome unknown` 而不是猜成功或失败。
- 恢复联网后 `OfflineReconciler` 逐条上报，服务器 `reconcileOffline` 给出明确裁定：

| 服务器状态 | 离线已投递 | 裁定 | 后续 |
|---|---|---|---|
| HELD | 是 | `CONFIRMED` | → RELEASED |
| RELEASED（别处已打） | 是 | `ALREADY_RELEASED_DOUBLE_PRINT` | 保留 RELEASED，**记为双重打印事件** |
| CANCELLED | 是 | `PRINTED_AFTER_CANCEL` | → FAILED + "printed offline after cancellation" |
| EXPIRED | 是 | `PRINTED_AFTER_EXPIRY` | → FAILED + 对应原因 |
| 任意 | 否 | `REVERTED_TO_HELD` | 员工可重新取件 |

**绝不静默改写历史。** 发生过什么，审计链里就记什么。

### 4.3 已知限制（不藏着）

> **分区容忍打印无法做到跨站点 exactly-once。**

如果网络分区把苏州和慕尼黑同时切断，两地可以在同一次分区窗口里各打印同一份文档
（各自清单里都有它，各自都以为自己是唯一授权方）。要彻底消除，需要跨站点共识协议，
其代价（延迟、可用性、运维复杂度）对一个打印系统不值得。

本设计的缓解措施：
1. 清单短时效（小时级，默认 24h，可配）+ 严格递增序号，把"双方都能打"的窗口压到最小。
2. 每个 job 的离线授权 `expiresAt` 不超过它自己的 `holdUntil`。
3. 对账检测并**显式上报**双重打印，交给 DLP/合规流程，而不是假装没发生。
4. 长时间断网的站点**主动停止**只能打印（`offlineAuthorityExpired()` → fail-closed），
   宁可让员工走去联网的打印机，也不让陈旧授权长期有效。

`OfflineGrantTest` / `OfflineReleaseEndToEndTest` / `OfflineJournalTest` 覆盖了上述所有路径。

---

## 5. 安全属性一览

| 属性 | 实现 | 测试 |
|---|---|---|
| 暂存文档机密性 | AES-256-GCM 信封加密，per-job data key | `SpoolEnvelopeTest`, `submittedBytesAreEncryptedOnDisk` |
| 密文不可跨任务挪用 | AAD 绑定 (jobId, owner) | `envelopeIsBoundToJobIdAndOwner` |
| 篡改检测 | GCM tag + 截断拒绝 | `tamperedCiphertextIsRejected` |
| 过期不可恢复 | crypto-shred（删密钥包裹）+ 删 blob | `cryptoShredMakesBytesInert`, `expiredJobIsDestroyedAndTombstoned` |
| 并发只打一次 | 原子 `claimForRelease` | `concurrentReleasesAtTwoPrintersYieldExactlyOneWinner` |
| 授权不可伪造 | 服务器 Ed25519 签名 | `releaseProducesVerifiableGrantBoundToAgentAndPrinter` |
| 授权不可挪用 | ECIES 包裹到指定 Agent + AAD | `recipientCanOpenAndStrangerCannot` |
| 授权不可重放 | nonce 单次消费 | `offlineGrantReplayIsRefusedAfterNonceConsumption` |
| 清单不可篡改 | Ed25519 签名覆盖 canonical 形式 | `tamperedManifestIsRejectedByAgent` |
| 清单不可回滚 | 持久化递增 sequence | `rejectsReplayOfOlderSequence` |
| 身份不可伪造 | 工卡加盐 HMAC 摘要 | `badgeLookupFailsForUnknownBadge` |
| 跨站点越权打印 | 双重站点校验 + collectSites | `agentCannotDrivePrinterAtAnotherSite` |
| 审计防篡改 | SHA-256 哈希链 | `tamperingBreaksVerification` |
| PDL 注入防护 | 光栅化 + 控制字符剥离 | `rasterizerStripsControlCharactersThatCouldInjectPdl` |
| 打印保真 | 逐字节 PCL 编解码往返 | `everyRowIsByteIdenticalToSource` |

---

## 6. 代码结构

```
core/      领域模型、密码学、协议、审计链       ← 无外部依赖（除 Jackson）
  domain/    Employee, Printer, PrintJob, PrintSpec, Capability…
  crypto/    AesGcm, Hkdf, Hmac, Ed25519, Ecies
  store/     SpoolEnvelope（信封加密）, SpoolStore / FileSpoolStore
  protocol/  ReleaseGrant, ReleaseManifest, GrantSigning, ManifestVerifier
  audit/     AuditEvent, AuditLog（哈希链）, AuditSink

drivers/   多品牌打印机适配                     ← 依赖 core + PDFBox
  spi/       PrinterDriver（唯一接口）, DeviceSession, RenderRequest…
  format/    DocumentRasterizer, PclEncoder, PostScriptEncoder, Rle
  transport/ RawTcpTransport, IppTransport
  brand/     Hp / Kyocera / Ricoh / PostScript / Ipp
  registry/  DriverRegistry（型号→驱动）, CapabilityMapper

server/    中央服务                             ← 依赖 core
  service/   SubmissionService, ReleaseService, ManifestService,
             ExpirySweeper, AgentRegistry, AuditingService
  store/     JobStore / InMemoryJobStore
  security/  ReleaseTokenService
  config/    ServerConfig

agent/     分公司释放终端                       ← 依赖 core + drivers（不依赖 server）
  sync/      ManifestSyncService, OfflineJournal, OfflineReconciler
  store/     OfflineSpool, AgentKeyVault
  release/   ReleaseEngine, LocalPrinter
  terminal/  TapReader, UidNormalizer, ScriptedTapReader

app/       组装 + HTTP API + 可运行 Demo
```

**依赖方向**：`agent` 与 `server` 互不依赖，只通过 `core/protocol` 里的签名对象通信。
这不是洁癖——离线打印要求 Agent 在服务器不可达时独立工作，代码上任何反向依赖都会
在编译期破坏这个性质。

---

## 7. 运行

```bash
# 全部测试（130 个）
./gradlew test

# 端到端演示：提交 → 同步 → 断网 → 刷卡打印 → 重放被拒 → 恢复对账 → 过期销毁
./gradlew :app:run
```

Demo 走的是**真实代码路径**：真 AES-GCM、真 Ed25519 验签、真 PCL 生成、真 socket 投递；
只有打印机是一个本地记录字节的 socket。

---

## 8. 上线前还需要做的事

这是可运行的参考实现，不是成品。生产化清单：

1. **持久化**：`InMemoryJobStore` 换 JDBC/Redis，`claimForRelease` 必须用
   `UPDATE ... WHERE state='HELD'` 并检查行数。
2. **密钥管理**：`ServerConfig.ephemeralDefaults()` 里的主密钥/pepper 必须来自 KMS/HSM。
   Agent 私钥应存 TPM/OS keystore，而不是口令派生的 vault。
3. **传输层**：提交与 Agent 端点走 mTLS；员工身份走 SSO/SAML，应用层仍保留全部授权判断。
4. **证书轮换**：给 `ReleaseGrant`/`ReleaseManifest` 加 `keyId` 与双密钥并行期。
5. **可观测性**：审计链接入 SIEM；双重打印事件走告警。
6. **驱动验收**：每个品牌型号在真实设备上跑一遍 `PclRoundTripFidelityTest` 的对应版本
   （用真实打印机抓包比对光栅）。
7. **速率限制与配额**：提交端点限流，防止有人用打印系统当存储滥用。
8. **合规**：审计日志保留期、DSAR 删除流程、工卡摘要的可删除性设计。
