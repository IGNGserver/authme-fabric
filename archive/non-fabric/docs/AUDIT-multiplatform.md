# AuthMe 全代码库安全与架构审计

审计日期：2026-08-27
审计对象：当前工作树（不是只审计 `HEAD`）
Git 基线：`f9eb7d0` (`main`, `origin/main`)
审计性质：只读审计；除本文件外未修改业务代码

## 1. 结论摘要

当前工作树可以完整构建，核心自测也能通过，但这不足以支持“可安全发布到所有已声明平台”的结论。本轮确认了 **6 个 P1、10 个 P2、1 个 P3** 问题；没有确认一个在默认 SQLite 单服配置下可直接远程利用的 P0。

最需要先处理的不是常规 SQL 注入，而是几处更深的信任边界错误：

1. PostgreSQL 后端完全没有消费配置中的 TLS/证书校验开关；解析当前捆绑驱动可确认未传参数时是 `prefer`，并不强制加密或校验证书。
2. GroupOptions 为实现“临时隔离组”会清空 LuckPerms 用户的全部节点并持久化，恢复快照却只存在内存中；崩溃、并发修改或异步保存乱序会把临时状态永久写入权限系统。
3. 旧哈希自动迁移不是比较并交换；共享数据库中，一个已经验证旧口令的延迟请求可以覆盖另一实例刚完成的新口令。
4. Paper/Folia 的异步任务仍直接读取 `Player`/Bukkit 状态；purge 甚至在异步线程查询在线玩家与 `authme.bypasspurge`，错误结果可以让本应跳过的账号被删除。
5. 后端配置和逻辑备份都依赖进程 `umask`。本轮实际生成的 `config.yml` 和 `backup.sql` 均为 `0664`；前者会承载数据库/SMTP 密码，后者包含口令哈希、TOTP、邮箱、IP 等完整账号列。
6. Velocity 与 Bungee 的 Premium 全局名单在玩家断开时被删除；下一次 PreLogin 因此不再强制正版验证。这是一条代码组件都还存在、但产品保障在首次断开后失效的完整遗留功能链。

对受影响配置而言，P1 应视为发布阻断项。尤其不要在修复前把 PostgreSQL TLS、GroupOptions、Folia purge、代理 Premium 或共享数据库旧哈希迁移标为“已验收”。

## 2. 审计快照与边界

当前 `settings.gradle:12-27` 声明 15 个子项目：共享 core、平台 core、Paper common、6 条 Fabric 版本线、Paper、Folia、旧 Spigot、Velocity、Bungee。代码规模约为 168 个 Java 文件，生产 Java 约 32,896 行。

工作树并不干净：审计开始时有 72 个已跟踪文件修改、34 个未跟踪路径；Paper/Folia/Spigot、代理模块、三个更旧 Fabric 模块、`.github/workflows/security.yml`、`SECURITY.md` 和功能矩阵都还未被 Git 跟踪。因此：

- 本报告审计的是用户当前可见的整个工作树，包含这些未跟踪实现；
- 本地构建通过不能证明 `origin/main` 已包含这些模块或安全门禁；
- 文档中对 CI、平台或功能的声明，在对应文件提交并由真实环境执行前仍只是工作树状态。

本轮没有使用外部聊天、历史记忆或网络资料。证据来自当前源码、已解析的 Gradle 依赖、Git 历史与本地执行结果。

### 2.1 实际信任边界

| 边界 | 当前实际权威 | 主要问题 |
|---|---|---|
| 客户端 → Fabric/Bukkit 事件与命令 | 各平台运行时的本地 `Session`/`PlayerSession` | 多份状态机漂移；部分 Bukkit/Folia API 在异步线程读取 |
| 平台运行时 → 共享数据库 | `DataSource` 及进程内锁/缓存 | 本地锁被误当成跨实例串行化；若干检查和写入不原子 |
| 代理 → 后端自动登录 | `authme:main`；仅 `perform.login`/握手带 HMAC | 后端状态通知未签名；Premium 全局状态和连接状态混用 |
| AuthMe → LuckPerms | 反射调用并持久化整个用户节点集 | 临时权限状态越过了持久权限边界，恢复快照不耐崩溃 |
| AuthMe → 文件系统 | 配置目录、逻辑备份、purge 文件 | 路径约束较好，但凭据文件权限没有安全默认值 |
| AuthMe → 外部数据库 | 运行时账号同时执行 DML 与 DDL | 无法落实最小权限；启动时隐式迁移且缺少版本化事务 |

## 3. 发现总表

优先级定义：P1 = 高风险或条件性发布阻断；P2 = 应在下一发布周期修复的安全/可靠性缺陷；P3 = 低风险纵深防御或清理项。

| ID | 优先级 | 结论 | 影响范围 |
|---|---:|---|---|
| A-01 | P1 | PostgreSQL TLS/证书配置是无效开关 | PostgreSQL；MySQL 还有主机名校验弱化 |
| A-02 | P1 | GroupOptions 把临时隔离状态持久化并可覆盖全部 LuckPerms 节点 | 启用 GroupOptions + LuckPerms |
| A-03 | P1 | 旧哈希自动迁移存在跨实例口令回滚竞态 | 共享数据库 + `legacyHashes` |
| A-04 | P1 | Paper/Folia 异步任务读取实时 Bukkit 状态，purge 可误删 bypass 账号 | Paper/Folia，尤其 Folia 与 purge |
| A-05 | P1 | 配置与备份未设置私有权限；实测为 `0664` | 多用户主机、备份和外部 DB/SMTP |
| A-06 | P1 | 代理 Premium 名单在断开时丢失，下一次连接不再强制在线验证 | Velocity/Bungee Premium |
| A-07 | P2 | 单会话、失败限制和 IP 登录上限并非跨实例安全策略 | 多服共享账号库 |
| A-08 | P2 | 连接池在全局锁内建连，且 `maxLifetime` 实际被重置成空闲计时 | 所有 SQL 后端 |
| A-09 | P2 | 非法数据库/哈希配置静默降级而不是拒绝启动 | 配置拼写错误、部署漂移 |
| A-10 | P2 | 新安装仍默认快速 SHA256，弱算法可直接作为主算法 | 离线口令数据库泄露 |
| A-11 | P2 | Fabric TOTP 接受会话中的旧密钥且没有 TOTP 失败节流 | 三条主 Fabric 状态机 |
| A-12 | P2 | 多条“配置/类仍在但产品行为不存在或语义已断裂”的遗留链 | 全平台配置兼容层 |
| A-13 | P2 | 代理信任任一配置的 auth server 发出的未签名状态；分片快照不绑定来源 | 多认证后端、`allServersAreAuthServers` |
| A-14 | P2 | 运行时数据库账号承担隐式 DDL，迁移非版本化、非原子 | MySQL/MariaDB/PostgreSQL/SQLite |
| A-15 | P2 | CI 目前未被 Git 跟踪，构建依赖也不可复现验证 | 发布与供应链 |
| A-16 | P2 | 安全状态机大规模复制，已经产生可观察的安全语义漂移 | Fabric/Paper/Spigot 多平台 |
| A-17 | P3 | Bukkit 保护事件在 `LOWEST` 执行，后续插件可重新放行 | Paper/Folia/Spigot 纵深防御 |

## 4. 详细发现

### A-01 [P1] PostgreSQL TLS/证书配置是无效开关

**证据链**

- 默认配置明确设置 `mySQLUseSSL: true` 和 `mySQLCheckServerCertificate: true`：`authme-core/src/main/resources/assets/authme/config.yml:21-30`。
- `AuthMeConfig.toDbSettings()` 对所有后端构造同一组 `useSsl`、`checkServerCertificate` 参数：`authme-core/src/main/java/io/github/authme/fabric/config/AuthMeConfig.java:221-244`。
- PostgreSQL URL 只包含 `binaryTransfer=true`，没有 `sslmode`、根证书或主机校验参数：`authme-core/src/main/java/io/github/authme/fabric/datasource/PostgreSqlDataSource.java:43-49`。
- 通用 JDBC properties 只放入用户名和密码：`authme-core/src/main/java/io/github/authme/fabric/datasource/AbstractSqlDataSource.java:78-91`。
- 本轮对 `gradle.properties:23` 解析出的 PostgreSQL JDBC 42.7.11 执行 `javap`，`SslMode.of(Properties)` 在未提供属性时返回 `PREFER`；`verifyCertificate()` 只对 `VERIFY_CA`/`VERIFY_FULL` 为真。因此当前代码既不强制 TLS，也不校验证书。
- MySQL 分支在“检查证书”时选择 `VERIFY_CA` 而不是验证主机名的 `VERIFY_IDENTITY`：`authme-core/src/main/java/io/github/authme/fabric/datasource/MySQLDataSource.java:35-45`；MariaDB 却使用 `verify-full`，三种后端语义不一致。

**影响**

运维人员看到配置为 `true` 会合理地认为数据库凭据和账号数据受 TLS 与服务端身份校验保护，PostgreSQL 实际上可能回退到明文连接；即使建立 TLS，也没有由本项目保证证书/主机身份。中间人可窃取数据库密码、账号哈希、TOTP 和会话数据。

**修复**

为每个数据库后端建立明确的 TLS 枚举（`DISABLED`、`REQUIRED`、`VERIFY_CA`、`VERIFY_IDENTITY/FULL`），PostgreSQL 映射到 `sslmode=disable/require/verify-ca/verify-full`；生产默认应为完整主机校验。启动日志应输出不含秘密的最终 TLS 模式，并增加 URL/properties 单测与真实数据库证书正反例测试。

### A-02 [P1] GroupOptions 把临时权限状态持久化

**证据链**

- 配置承诺“未认证时切组，登录或断开恢复原始节点”：`authme-core/src/main/resources/assets/authme/config.yml:324-330`。
- `applyGroup()` 读取 `getNodes()` 后调用 `data.clear()`，只加入一个继承节点，然后调用 `saveUser()`：`authme-core/src/main/java/io/github/authme/fabric/util/PermissionBridge.java:120-140`。
- `restoreGroup()` 再次清空当前全部节点，然后重放旧快照并保存：同文件 `146-164`。
- 快照只是 `Session` 内的 Java 对象；`GroupSnapshot` 本身没有持久化：同文件 `24-29`，Paper 调用见 `authme-paper-common/src/main/java/io/github/authme/platform/paper/PaperAuthRuntime.java:1206-1227`。
- `saveUser()` 只反射调用并忽略返回的异步完成对象，无法确认保存成功或顺序：`PermissionBridge.java:194-203`。
- `FEATURE_MATRIX.md:63` 反而声称该实现“防止跨服务器污染权限”，与实际持久化行为相反。

**影响**

开启该选项后，临时认证状态被写入 LuckPerms 的持久/网络权限域。服务器在 apply 后崩溃、权限插件重载、玩家从另一服务器修改权限、两次异步 save 乱序，都会造成永久隔离组、丢失权限节点或把并发新权限覆盖回旧快照。它也不是“只切 primary group”，而是清空用户全部显式节点。

**修复**

不要修改并保存持久用户节点。使用 LuckPerms context/transient node、临时权限附件或 AuthMe 自己的认证 context；如果必须落库，至少持久化带版本的恢复日志，并用节点级差异而不是 `clear()`/全量回放。等待并检查保存 future，加入崩溃恢复、跨服并发修改和插件重载测试。在修复前默认保持关闭，并修正文档声明。

### A-03 [P1] 旧哈希迁移可覆盖另一实例刚设置的新口令

**证据链**

- 平台服务先查询、验证旧哈希，再无条件调用 `updatePassword(name, newHash)`：`authme-platform-core/src/main/java/io/github/authme/platform/PlatformAuthService.java:407-435`。
- Fabric 的窗口更大：验证后另起一个 `CompletableFuture` 执行更新，登录流程不等待迁移结果：`authme-fabric/src/main/java/io/github/authme/fabric/auth/AuthManager.java:445-482`；mid/legacy 有同构代码。
- SQL 更新条件只有用户名，没有旧哈希/盐：`authme-core/src/main/java/io/github/authme/fabric/datasource/AbstractSqlDataSource.java:406-425`。
- `PlatformAuthService` 的 `lockFor(name)` 是单 JVM 锁：`PlatformAuthService.java:52-56,1188-1195`，不能串行化 README 所宣称的共享数据库实例。

**可复现时序**

1. A 实例读取旧哈希并验证旧口令；
2. B 实例/网站重置为新口令；
3. A 执行仅按用户名更新，把“旧口令的新算法哈希”覆盖回数据库；
4. 用户的新口令失效，旧口令重新成为有效凭据。

**修复**

新增 CAS API，例如 `UPDATE ... SET password=?, salt=? WHERE username=? AND password=? AND salt IS NOT DISTINCT FROM ?`。受影响行数为 0 时必须重新读取并停止当前迁移，不能继续宣称迁移成功。跨实例测试应覆盖改密、邮箱恢复、管理员重置和旧哈希登录并发。

### A-04 [P1] Paper/Folia 越过平台线程边界，purge 可误删 bypass 账号

**证据链**

- `scheduler.runAsync` 中直接调用 `player.getName()`、`address(player)`：`authme-paper-common/src/main/java/io/github/authme/platform/paper/PaperAuthRuntime.java:224-260,354-387`。
- 注册异步块还直接调用 `player.hasPermission(...)`：同文件 `390-434`。
- Folia 明确把 `runAsync` 映射到 async scheduler，把玩家操作映射到 entity scheduler：`authme-folia/src/main/java/io/github/authme/platform/folia/AuthMeFoliaPlugin.java:58-86`；但调用者把实时 `Player` 对象捕获进了 async lambda。
- 管理 purge 整体在异步任务执行：`PaperAuthRuntime.java:672-679`。候选过滤随后调用 `plugin.getServer().getPlayerExact()` 和 `player.hasPermission("authme.bypasspurge")`：同文件 `1739-1775`。

**影响**

普通 Paper 上会表现为竞态或偶发不一致；Folia 上这是明确的区域线程契约破坏，可能抛异常、读到过期状态或导致认证流程卡住。purge 的后果更严重：如果异步在线查询返回 null/失败，本应由 `authme.bypasspurge` 保护的在线账号会进入删除集合，并可能走批量删除分支。

**修复**

在玩家/entity 线程一次性快照不可变 DTO（name、UUID、IP、所需权限结果），异步层只接收值对象。purge 前先在正确线程收集在线 bypass 名单，再执行数据库删除；删除前再次校验候选版本。为 Folia 增加真实服务器线程违规检测和在线 bypass purge 集成测试。

### A-05 [P1] 配置与逻辑备份没有私有文件权限

**证据链与实测**

- 默认配置通过普通 `Files.newOutputStream(file)` 创建，没有 POSIX 权限或 ACL：`authme-core/src/main/java/io/github/authme/fabric/config/AuthMeConfig.java:40-56`。
- 该文件包含 `DataSource.mySQLPassword` 与 `Email.password`：`authme-core/src/main/resources/assets/authme/config.yml:32-35,245-257`。
- 逻辑备份执行 `SELECT *` 并把每一列写成 SQL，目标通过普通 `Files.newBufferedWriter` 创建：`authme-core/src/main/java/io/github/authme/fabric/datasource/AbstractSqlDataSource.java:939-968`。
- Paper、Fabric、Spigot 只是把目标约束在各自 `backups` 目录，没有收紧权限：例如 `authme-paper-common/src/main/java/io/github/authme/platform/paper/PaperAuthRuntime.java:1696-1718`。
- 在本轮环境 `umask 0002` 下运行正式 `configSelfTest`/`dataSourceSelfTest` 后，实际 `config.yml`、SQLite DB 和 `backup.sql` 均为 `0664`。这不是推测。
- 代理配置已经有 `restrictOwnerOnly()`：`authme-proxy-core/src/main/java/io/github/authme/proxy/core/ProxyConfig.java:80-91,244-265`，说明后端配置与代理秘密保护标准也不一致。

**影响**

同机其他用户/容器可能读取数据库和 SMTP 凭据。备份包含口令哈希、盐、TOTP secret、邮箱、注册/最后 IP、Session 状态和位置；这会显著扩大一次本地低权限突破或错误制品打包的后果。

**修复**

以 `CREATE_NEW` + `0600` 创建配置、秘密和备份临时文件，再原子移动；目录使用 `0700`。启动时检查现有权限并对过宽权限报警/自动收紧。Windows 使用 ACL。为配置秘密提供环境变量或独立 secret file 引用，并给备份增加加密、保留期和安全删除策略。文件打开还应采用 no-follow/安全目录句柄以消除 symlink 检查后的 TOCTOU。

### A-06 [P1] Premium 全局目录被当成连接状态清理

**完整失效链**

1. 后端 Premium 快照/`premium.set` 调用 `rememberPremium()`，加入 `premiumNames`：`authme-velocity/src/main/java/io/github/authme/proxy/velocity/VelocityProxyBridge.java:317-327`；Bungee 同构于 `BungeeProxyBridge.java:289-299`。
2. PreLogin 只依据 `premiumNames` 决定是否强制 online mode：Velocity `177-193,245-247`；Bungee `161-176,215-217`。
3. 玩家断开时，代码正确清理连接态 `store.clear(name)`，但又错误删除全局 Premium 目录项：Velocity `238-243`；Bungee `207-213`。
4. 下一次 PreLogin 时该用户名不在目录中，因此不会强制正版验证。只有之后另一次快照/变更消息才能恢复。

**影响**

Premium 保护在玩家第一次断开后降级。攻击者能以 offline-mode 身份再次尝试该用户名；后端密码仍是后续防线，所以这里没有直接证明“无密码接管”，但产品承诺的 Mojang 身份强制边界已经失效，并扩大了冒名与口令攻击面。

**修复**

明确拆分“全局 Premium 账号目录”和“当前连接的认证/UUID proof”。断开只能清理后者；全局目录只允许完整快照、`PREMIUM_SET/PREMIUM_UNSET` 修改。为 Velocity/Bungee 各增加测试：收到快照 → Premium 登录 → 断开 → 同名下一次 PreLogin 仍必须 force online。

### A-07 [P2] 共享数据库场景下，多项安全策略仍只是单进程状态

- `ForceSingleSession` 默认开启：`config.yml:163-165`，但 Paper 只扫描本进程 `sessions.values()`：`PaperAuthRuntime.java:1329-1357`；Fabric 也只扫描本地 map：`AuthManager.java:2348-2359`。另一个服务器上的旧会话不会被踢出。
- 登录/TOTP 失败、CAPTCHA 和连接代次存在本地 `ConcurrentHashMap`：`PlatformAuthService.java:42-64`。攻击者可在多个认证实例间分摊尝试次数。
- `maxLoginPerIp` 先单独 `COUNT`：`PlatformAuthService.java:1316-1325`，再在另一个语句更新登录态：`440-443`；两个实例可同时通过检查。
- README 明确宣传多个 Bukkit/Fabric 实例共享同一个账号库：`README.md:7-10,95-100`，所以“进程本地”不是可以忽略的部署模型差异。

建议为账号会话建立带 instance/connection/expiry/version 的租约表；用事务、唯一约束或数据库 advisory lock 完成单会话与 IP 配额；失败限速至少使用代理级或共享存储。若产品只支持单认证入口，应在配置、文档和启动检查中明确限制，而不是继续宣称共享库下策略等价。

### A-08 [P2] 自制连接池会放大数据库故障

- `borrow()` 整个方法是 `synchronized`，在持有池全局监视器时执行可能长期阻塞的 `DriverManager.getConnection(...)`：`authme-core/src/main/java/io/github/authme/fabric/datasource/SimpleConnectionPool.java:52-95`。此时 `release()` 也需要同一锁，已有健康连接无法归还，单次慢建连可阻塞全池。
- 空闲条目中的 `createdAt` 用于判断 `maxLifetime`：同文件 `55-63`；但每次归还都以当前时间重新构造条目：`97-125`。频繁使用的连接永远不会达到 max lifetime，配置语义实际变成“最近一次归还时间”。

建议换用维护成熟的池（如 HikariCP），或至少在锁内预留槽位、锁外建连；连接创建时间必须随连接生命周期保持不变。增加阻塞 fake driver、并发 borrow/release、连接年龄与关闭竞态测试。

### A-09 [P2] 安全相关配置静默降级

- 未知 `DataSource.backend` 只记录 warning 并退回 SQLite：`AuthMeConfig.java:184-191`。共享数据库拼写错误会把服务器悄悄切到一个新的本地账号域。
- 未知/空 `passwordHash` 静默退回 SHA256：`authme-core/src/main/java/io/github/authme/fabric/security/HashAlgorithm.java:44-53`。例如 `ARGON2DI` 拼错后，服务仍启动并以较弱算法保存新口令。
- 启动只显式拒绝 `CUSTOM` 无实现，无法发现上述降级：`authme-platform-core/src/main/java/io/github/authme/platform/PlatformAuthService.java:81-100`。

修复原则是安全配置 fail closed：未知枚举、空关键字段和不支持的组合必须阻止启动，并给出精确路径与允许值。兼容别名可显式映射，但不能用默认值吞掉拼写错误。

### A-10 [P2] 新账号的默认口令哈希仍是快速 SHA256

- 新配置默认 `passwordHash: SHA256`，PBKDF2 只有 10,000 轮：`config.yml:75-88`。
- 实现是两次快速 SHA-256 加盐，没有工作因子或内存成本：`authme-core/src/main/java/io/github/authme/fabric/security/crypts/Sha256.java:7-27`。
- `PLAINTEXT`、MD5、SHA1 等兼容算法可直接成为 primary：`authme-core/src/main/java/io/github/authme/fabric/security/PasswordSecurity.java:107-124`；启动不警告或要求危险确认。

兼容旧 AuthMe 数据库是合理需求，但不应决定新安装默认值。新安装应默认 Argon2id（参数需按服务器预算基准化），现有 SHA256 放入显式 legacy 列表并用 A-03 的 CAS 安全迁移。弱算法作为 primary 至少必须拒绝或要求醒目的危险开关。

### A-11 [P2] Fabric TOTP 使用旧会话密钥且没有失败节流

- 密码验证后把当时数据库行的 TOTP key 放进 `session.totpKey`：`authme-fabric/src/main/java/io/github/authme/fabric/auth/AuthManager.java:458-480`。
- `/2fa` 验证先使用该旧 key 校验；成功后虽重新查询账号，却没有比较/重新验证当前数据库 key，直接完成登录：同文件 `932-957`。
- 错误 TOTP 只返回消息，没有计数、最小延时或临时封禁：`939-942`。
- 共享 `PlatformAuthService` 的实现会重新读取当前 key，并复用失败限速：`authme-platform-core/src/main/java/io/github/authme/platform/PlatformAuthService.java:627-648`。这证明平台间已经发生安全语义漂移。

密钥在另一实例被轮换/禁用后，等待中的 Fabric 会话仍可用旧 key 完成登录。应在同一个串行化决策中读取并验证当前 key，并把 TOTP 失败纳入按账号+来源的有界限速；最好让 Fabric 也复用共享认证服务。

### A-12 [P2] 已确认的遗留/无效产品链

| 链 | 代码证据 | 实际结果 |
|---|---|---|
| Paper/Folia/Spigot 的 `Hooks.bungeecord` | 共享配置 accessor 在 `AuthMeConfig.java:466`；Paper 只在 `preJoinShouldSkip()` 读取：`PaperAuthRuntime.java:97-103`；三个入口类仅注册事件/命令/Placeholder，见 `AuthMePaperPlugin.java:14-41`、`AuthMeFoliaPlugin.java:22-48`、`AuthMeSpigotLegacyPlugin.java:12-36`。对这些模块搜索 `ProxyProtocol`、`authme:main`、plugin channel 注册均无结果。 | 打开该开关不会建立代理认证链，只会跳过 Pre-Join Dialog。配置看似启用功能，实际传输端不存在。 |
| `otherAccountsCmdThreshold` | 模板同时有展示阈值 0 和命令阈值 5：`config.yml:167-172`；独立 getter 存在但全仓只有声明：`AuthMeConfig.java:534-535`；实际 Paper/Fabric 都用 `otherAccountsThreshold()` 同时控制展示和命令：`PaperAuthRuntime.java:1297-1325`、`AuthManager.java:2362-2378`。一般阈值键又排在 fallback 前：`AuthMeConfig.java:519-521`。 | 命令专用阈值从不生效；默认 0 会遮蔽 5。该键自 Git 提交 `2f1cd65` 已存在，属于长期遗留。 |
| `Hooks.displayname` | 配置键位于 `config.yml:216-223`，全仓搜索只有这一处；Git 历史显示从初始提交 `8ee3610` 起存在。 | 没有 accessor、hook 或运行时消费者，纯粹是产品表面占位。 |
| 配置兼容 API | 系统化统计 `AuthMeConfig` getter 调用数后，`databaseCacheEnabled()`、`eventCommandsFile()`、`otherAccountsCommandThreshold()`、`registerTimeout()` 都只有声明（`AuthMeConfig.java:741,759,534,740`）。 | 对应核心功能有的通过别的 API 存活，但这些兼容入口本身是死代码，会误导维护者和测试。 |
| 已失效的 Premium 保护链 | 见 A-06。 | 代码、消息与状态容器都在，第一次断开后关键产品保障消失。 |

反例也做了验证：`limbo.recreateEnderPearls` **不应**被报告为全局死配置。当前 modern/mid/legacy Fabric 分别在 `AuthManager.java:2663/2552/2550` 消费它，且 `ConfigSelfTest.java:274-297` 验证解析。它只是在 Bukkit-family 没有等价末影珍珠实现，属于平台覆盖差异而不是整条死链。

修复应先确定产品契约：实现真实功能或删除配置/兼容入口，并在迁移日志明确告知；不要继续用“解析测试通过”代替运行时消费者测试。建议增加一项自动门禁：每个公开配置键必须映射到被调用的 typed accessor，功能矩阵再映射到至少一个行为测试。

### A-13 [P2] 代理后端状态通知信任范围过宽

- `ProxyMessageCodec.parseBackend()` 以 `ProxyProtocol.parse(payload, null)` 解析，LOGIN/LOGOUT/PREMIUM 状态不带 HMAC：`authme-proxy-core/src/main/java/io/github/authme/proxy/core/ProxyMessageCodec.java:26-35`。
- 平台桥只依据消息来源是否为一个已配置的 backend server：Velocity `VelocityProxyBridge.java:85-160`，Bungee `BungeeProxyBridge.java:75-143`。
- 配置允许 `allServersAreAuthServers=true`，也允许 128 个 auth server：`authme-proxy-core/src/main/java/io/github/authme/proxy/core/ProxyConfig.java:35-47,95-130`。在该模式下任一被攻陷的游戏后端都能为任意用户名发送登录/Premium 状态。
- Premium 分片的 buffer/sequence 是代理全局字段而不是按源服务器隔离：Velocity `VelocityProxyBridge.java:330-363`；多个 auth server 的合法分片可以互相清空、混合或使快照失效。

默认 auth server 白名单降低了风险，但没有密码学绑定。建议所有影响认证/ Premium 的后端消息都使用带方向、实例 ID、时间戳和 nonce 的 HMAC envelope；快照状态按来源与 snapshot ID 隔离，最终以明确的单权威或版本合并。安全模式下移除 `allServersAreAuthServers`。

### A-14 [P2] 运行时数据库账号承担隐式 DDL

每个 SQL datasource 在构造时立即 `createSchemaAndColumns()`：`authme-core/src/main/java/io/github/authme/fabric/datasource/AbstractSqlDataSource.java:37-63`。PostgreSQL 会直接 `CREATE TABLE`/逐列 `ALTER TABLE`：`PostgreSqlDataSource.java:69-95`，MySQL 同类逻辑从 `MySQLDataSource.java:48` 开始。

这要求长期运行账号拥有 DDL 权限，并让启动路径承担非版本化、跨多条 autocommit 语句的迁移。中途失败会留下部分 schema；插件进程被利用后，数据库破坏半径也超过账号 DML 所需。

应引入显式、版本化、可回滚/可重入的 migration；部署阶段使用 migration principal，运行时账号仅授予目标表的最小 DML 权限。启动只验证 schema 版本，不自动扩权修改。

### A-15 [P2] 当前 CI 与依赖供应链不能提供可复现保证

- `.github/workflows/security.yml` 在当前工作树是 `??`，`git ls-files` 没有输出；所以 `security.yml:14-39` 中的 build/self-test 门禁尚不属于 Git 历史，也不会保护 `origin/main`。
- 工作流 action 使用可移动 tag（`actions/checkout@v4`、`setup-java@v4`、`gitleaks@v2`），没有 pin commit SHA：`security.yml:18-21,49-65`。
- `loom_version=1.17-SNAPSHOT`：`gradle.properties:9`；Paper/Folia/Spigot API 也使用 SNAPSHOT。仓库没有 dependency lock 或 `gradle/verification-metadata.xml`。
- 本轮 build 中 6 个 Fabric `processIncludeJars` 均警告 SnakeYAML `2.6`、SQLite JDBC `3.53.1.0` “not valid semver”。构建仍成功，但发布元数据质量没有门禁。
- dependency review 只在 PR 触发：`security.yml:41-54`；定时任务没有持续扫描已存在依赖，也没有 SBOM、制品签名或 provenance。

先把工作流和全部新模块纳入 Git，再 pin actions SHA、锁定/校验依赖和 Gradle plugin，消除 SNAPSHOT，生成 SBOM，并对最终发布 JAR 做签名与 provenance。依赖漏洞扫描需在联网、可更新的环境单独运行；本轮没有把“版本看起来新”当成无漏洞证据。

### A-16 [P2] 状态机复制已经造成安全漂移

- 三个主要 Fabric `AuthManager` 分别约 2,954 / 2,833 / 2,830 行；modern 对 mid 的差异仍有 203 行新增、324 行删除，mid 对 legacy 也有 26/29 行差异。
- Paper runtime 约 1,975 行，旧 Spigot runtime 约 1,683 行。五个文件合计约 12,275 行认证/保护编排逻辑。
- 较旧的 1.19.3/1.19.2/1.18.2 模块通过 Gradle source set 复用 legacy 源码，这是正确方向：例如 `authme-fabric-old/build.gradle:27-33`。但 modern/mid/legacy 与 Paper/Spigot 仍手工复制。
- A-11 已给出实际漂移结果：Platform TOTP 每次读当前 secret 并限速，Fabric 用旧 session secret 且不限速。A-04 的线程错误也来自共享 Paper runtime 对平台对象和值对象没有分层。

这不是纯风格问题，而是修复无法同时覆盖所有认证入口。应把“输入规范化 → 查库 → 密码/TOTP/Session 决策 → CAS 写入 → 结果”收敛成一个无平台类型的状态机；平台 adapter 只负责捕获不可变输入和在正确线程应用结果。用同一组 contract tests 跑所有 adapter。

### A-17 [P3] Bukkit 保护监听优先级不足以作为最终拦截

Paper 的命令、移动、交互、伤害、库存等保护大多注册在 `EventPriority.LOWEST` 且 `ignoreCancelled=true`：`authme-paper-common/src/main/java/io/github/authme/platform/paper/PaperAuthListener.java:75-213`；旧 Spigot 同样如此：`LegacyAuthListener.java:67-200`。

后续插件可以有意或无意重新 `setCancelled(false)`。同 JVM 恶意插件本来就有任意代码能力，因此这不是一个可对抗恶意插件的安全沙箱；但对插件兼容和纵深防御，应把最终保护放到适合的高优先级，并增加“后续插件尝试解禁”的集成测试，同时记录与上游 Bukkit 事件语义的差异。

## 5. 已确认的正向控制

以下控制有实际代码证据，不应在修复时回退：

- SQL 值普遍使用 `PreparedStatement`；动态表/列名在 datasource 构造时用 `[A-Za-z_][A-Za-z0-9_]*` 校验：`AbstractSqlDataSource.java:1281-1304`。本轮未发现玩家输入直接拼入 SQL 值的注入链。
- `perform.login` 与签名握手有 HMAC、时间窗、常量时间比较、重放缓存、长度与用户名限制：`authme-core/src/main/java/io/github/authme/fabric/util/ProxyProtocol.java:68-149,152-193,217-271`。
- YAML 使用 `SafeConstructor`，并限制代码点、别名和嵌套深度：`AuthMeConfig.java:56-64`、`ProxyConfig.java:153-165`。
- Platform 认证失败默认 fail closed，连接代次用于拒绝旧异步回调；缓存的 `lookupAuth()` 在安全决策上直读源数据库：`authme-core/src/main/java/io/github/authme/fabric/datasource/CachingDataSource.java:35-60`。
- purge 文件清理使用规范化路径、`NOFOLLOW_LINKS` 和根目录边界：`authme-core/src/main/java/io/github/authme/fabric/util/PurgeFileCleaner.java:78-108`。A-05 是创建权限/TOCTOU 问题，不否定已有路径约束。
- Proxy secret 用 `SecureRandom` 生成并尝试收紧为 owner-only：`ProxyConfig.java:244-265`。

## 6. 验证结果

| 验证项 | 结果 | 说明 |
|---|---|---|
| 仓库/模块/入口与真实调用链追踪 | PASS | 覆盖 15 子项目、配置、命令、事件、代理、权限、数据源、构建与文档 |
| 核心 release self-tests | PASS | `configSelfTest`、`coreSelfTest`、`dataSourceSelfTest`、`mailSelfTest`、`externalDbSelfTest`、`proxyCoreSelfTest`、`platformCoreSelfTest` 全通过 |
| 全量 Gradle build | PASS | `BUILD SUCCESSFUL in 1m 3s`，86 tasks，15 子项目 |
| 非 sources JAR 完整性 | PASS | 15 个 JAR 全部 `unzip -t` 无压缩错误 |
| `git diff --check` | PASS | 无 whitespace error |
| 配置/备份权限安全默认 | **FAIL** | 在 `umask 0002` 下实测 `config.yml`、DB、`backup.sql` 均为 `0664` |
| 无效配置/死 getter 引用扫描 | **FAIL** | `displayname` 仅配置；4 个 typed getter 仅声明；命令阈值 getter无调用 |
| PostgreSQL 驱动默认 TLS 模式静态验证 | **FAIL** | 解析已锁定依赖 42.7.11，未传属性时为 `PREFER` 且不校验证书 |
| 真实 MySQL/MariaDB/PostgreSQL TLS 与并发 | NOT RUN | `externalDbSelfTest` 只验证连接失败路径，不是外部数据库集成测试 |
| 真实 LuckPerms GroupOptions/崩溃恢复 | NOT RUN | 工作区没有运行中的 LuckPerms 测试服 |
| 真实 Paper/Folia/Spigot 与客户端 | NOT RUN | build/API 证据不能替代线程、事件和玩家验收 |
| Velocity/Bungee 双端与 forwarding/Premium 重连 | NOT RUN | 未启动真实代理与后端 |
| SMTP/TLS/邮件恢复 | NOT RUN | mail self-test 不连接真实 SMTP |
| 在线依赖漏洞扫描、远端 CI、制品签名 | NOT RUN | 工作流未跟踪，且本轮未使用网络漏洞情报 |

最初在 `/tmp` 运行自测时因该 tmpfs 已被其他任务占用数 GB而出现 `Disk quota exceeded`；切换到有 5.6 GB 可用空间的 `/dev/shm` 后，同一组任务和全量 build 均通过。因此那次失败是环境问题，不计作代码测试失败，也没有清理其他任务文件。

## 7. 修复顺序与临时缓解

### 第一批：发布前阻断项

1. 修 A-01：为 PostgreSQL/MySQL/MariaDB 建立可验证的强 TLS 语义；完成真实证书正反例。
2. 修 A-03：所有口令迁移改为 CAS；先补共享数据库并发回归测试。
3. 修 A-02：GroupOptions 改为 transient/context 模型。在此之前保持 `enablePermissionCheck: false`；已使用过的部署应审查 LuckPerms 用户节点与备份。
4. 修 A-04：平台线程值对象化，并暂停 Paper/Folia 自动/手动 purge，直到在线 bypass 测试通过。
5. 修 A-05：配置、secret、DB 备份统一 `0600/0700`。部署层可临时用专用系统用户和 `umask 0077`，并立即检查既有备份权限。
6. 修 A-06：代理 Premium 全局目录与连接 proof 分离；完成“断开后下一次连接仍强制 online”的黑盒测试。

### 第二批：安全架构收敛

1. 用数据库租约/事务解决 A-07；不要再用本地 map 宣称跨服单会话或全局限速。
2. 替换连接池并拆分 versioned migration/runtime DML 权限（A-08、A-14）。
3. 配置 fail closed，升级新安装哈希默认值，并修复 Fabric TOTP（A-09、A-10、A-11）。
4. 收紧代理所有认证状态消息并按来源隔离快照（A-13）。
5. 收敛共享状态机和 contract tests（A-16），避免每次安全修复复制五遍。

### 第三批：产品与发布真实性

1. 按 A-12 删除或真正实现无效配置链，给每个公开键建立行为测试。
2. 把当前未跟踪模块、文档和 CI 纳入可审查提交；锁定供应链并签名制品（A-15）。
3. 调整 Bukkit 最终拦截优先级并做插件兼容测试（A-17）。
4. 完成真实数据库、LuckPerms、Folia、代理、SMTP 和客户端验收矩阵；继续明确区分 build PASS 与产品验收 PASS。

## 8. 最终判断

当前代码的输入边界、SQL 参数化、YAML 解析限制、代理 `perform.login` 防重放等基础控制比一般移植项目完整；问题主要出现在“一个进程内看起来正确，跨平台/跨实例/跨持久权限域后不再成立”的地方。

在 P1 修复且相应真实环境测试完成前，本工作树可以称为“可构建、核心自测通过的开发快照”，不能称为 PostgreSQL TLS、LuckPerms GroupOptions、Folia、原生代理 Premium 或共享数据库并发场景下的安全发布候选。
