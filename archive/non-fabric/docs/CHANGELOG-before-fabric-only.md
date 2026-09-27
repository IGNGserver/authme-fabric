# Changelog

## 6.0.1-fabric.2-SNAPSHOT

- Added schema v3 with restart-safe version history, explicit MIGRATE/VALIDATE modes, remote
  migration locks, shared failure buckets and renewable fenced login leases for cross-instance
  single-session/IP-quota enforcement and crash recovery.
- Made native proxy Premium decisions query a read-only authoritative account database during
  PreLogin, and bound every physical authentication backend to its own backendId and HMAC key.
- Replaced persistent LuckPerms GroupOptions mutation with fail-closed transient inheritance nodes
  that are rolled back on partial application and removed only by their owning AuthMe session.
- Pinned Fabric Loom, Gradle distribution integrity and every GitHub Action to immutable versions;
  added dependency verification metadata for resolved build artifacts.
- Made legacy-hash migration a blocking compare-and-set step for Fabric login: a concurrent password
  change now rejects the stale login instead of merely preventing the delayed hash overwrite.
- Moved Paper/Folia and legacy Spigot purge permission snapshots onto the appropriate player/main
  threads before asynchronous database deletion, and made sensitive-file creation owner-only at
  creation time on POSIX file systems.
- Bound old-account purge deletes to the queried account snapshot and recheck activity, identity/security fields,
  current runtime sessions, and live database leases before deleting each candidate.
- Moved Bungee Premium online-mode selection to `PreLoginEvent`, where the player name is available.
- New installations now default to Argon2id. Existing weak primary hashes require an explicit
  migration-only opt-in or should be listed under `legacyHashes` while both database-sharing ends
  use the same strong primary algorithm.
- Added the dedicated `authme-fabric-old` 1.19.3 artifact with legacy-compatible disconnect and
  teleport/command adapters.
- Added independently pinned `authme-fabric-pre` (1.19.2) and `authme-fabric-older` (1.18.2)
  artifacts, including old text/command/event compatibility and packet-level chat/damage guards.
- Bound platform adapter authentication mutations to connection generations so delayed Paper,
  Folia, and Spigot tasks cannot change state for a rapid reconnect.
- Enforced TOTP on platform Session/Premium paths and require a solved CAPTCHA before configured
  registration; platform registration now honors the configured post-registration kick policy.
- Fixed Paper public AuthMe help/version reachability and tightened legacy Spigot `getip` permission
  routing.
- Added platform email/recovery, CAPTCHA, Premium, GeoIP, event-hook, AntiBot, chat-policy and
  multiple-account permission handling through the shared Paper/Folia/Spigot service.
- Added Paper/Folia/Spigot automatic lifecycle backup and purge scheduling, delayed authenticated
  join announcements, authentication reminders, single-session displacement, GroupOptions restore,
  and safe optional-file cleanup for single, banned, and bulk purges.
- Fixed Bukkit registration semantics: `forceLoginAfterRegister` now really requires `/login`,
  password registration alone may auto-login, and email registration never treats the email address
  as the generated password.
- Fixed Bukkit-family quick-command protection permission semantics: the official
  `authme.player.protection.quickcommandsprotection` node now enables the guard, matching the
  Fabric adapters and AuthMeReloaded permission documentation.
- Hardened optional purge-file cleanup against parent and final-component symlinks, so a server
  directory link cannot redirect deletion outside the configured server root.
- Added the modern `EntityPickupItemEvent` protection path to Paper/Folia/Spigot adapters so
  unauthenticated players cannot collect dropped items when the newer Bukkit event is emitted.
- Made Fabric backup filenames collision-resistant and rejected backup-directory/final-file
  symlinks before writing sensitive account snapshots.
- Added Paper/Folia 1.21 post-join login, registration, and TOTP dialogs using the native Paper
  Dialog API; dialog actions still execute the normal AuthMe commands and are re-opened after a
  failed authentication attempt. Added an opt-in Paper/Folia configuration-phase Pre-Join Dialog
  for login, registration and recovery, with bounded waits, cancellation policy, disconnect cleanup
  and a safe handoff into the same AuthMe service. It remains unverified with a real client/proxy.
- Capped configuration, message, spawn, proxy and import YAML parsing, and fixed the old source-set
  mixin packaging issues found by Loader startup smoke tests.
- Made password recovery invalidate the previous login/session state in the same SQL transaction;
  the Fabric and Bukkit-family recovery paths now share this fail-closed transition.
- Bounded Paper/Folia pre-join dialog waits and one-connection handoffs, including their short-lived
  submitted-value storage, and bounded per-address join tracking in Paper/Folia and Spigot legacy.
- Exposed the existing whitelist-only `debug mysqldef` data-source operation through all three main
  Fabric command lines, with asynchronous execution and no arbitrary identifier input.
- Marked `gradlew` executable so the repository security workflow can run its declared Linux gates.

## 6.0.1-fabric.2-SNAPSHOT — security hardening

### 安全修复

- Session 恢复现在始终要求相同 IP、有效时间和有效时间方向；首次升级启动会一次性清除旧的登录/Session 标记。
- 同 IP 账户展示默认关闭，并要求 `authme.admin.seeotheraccounts`。
- `/authme debug` 增加总权限和子权限校验；LuckPerms 异常时玩家权限检查 fail-closed。
- 运行时数据库故障会停止认证服务，按配置停止服务器或断开在线玩家并拒绝后续加入。
- 邮箱恢复增加冷却时间、最大失败次数和验证码长度配置。
- 接入 `authme.bypassantibot` 与 `authme.allowmultipleaccounts` 权限。
- 补齐 `authme.admin.*` / `authme.player.*` 通配权限匹配，并接入官方快速命令保护配置。
- 实现 `hideChat` 的普通聊天广播接收者过滤，以及 Limbo 期间末影珍珠的追踪与认证后重建。
- 实现 `authme.vip` 满员替换（保留原版封禁/白名单检查）和 `authme.admin.antibotmessages` 的 AntiBot 生命周期通知。
- 认证、Session、密码和 TOTP 查询绕过普通缓存，避免共享数据库下跨实例注销或改密继续使用旧状态；同时修复 1.21.x Limbo 使用 `NameAndId` 适配 OP 撤销/恢复。
- 更新内置安全依赖：Bouncy Castle 1.85.2、SQLite JDBC 3.53.1.0、SnakeYAML 2.6，并完成六条 Fabric 版本线的回归构建与启动期冒烟；三个旧版本线受保留的 EULA 状态限制，未宣称完整服务启动。
- 补齐 `DenyTabCompleteBeforeLogin` 的支持版本线建议包拦截，并实现 `UnrestrictedInventories` 的标题匹配、容器 ID 绑定和关闭/断开清理。
- 代理时间戳校验改为溢出安全的有界比较；Argon2、PBKDF2、TOTP 和代理 Payload 增加输入/资源上限，避免异常数据库记录或网络包触发不受控计算和内存分配；新配置模板不再预填 MySQL 示例密码。
- 修正 `allowedMovementRadius: 0`、斜杠形式 `allowCommands` 和临时封禁优先级，使其与上游配置语义一致；密码长度、登录失败表、危险 IP 表和账户缓存均增加上限。
- 修正 `UnrestrictedName` 的执行顺序，并阻止该受信任身份在断开时修改同名真实账户；配置热重载会立即同步 Limbo、盲视和 Tab 列表保护状态。
- 调试树拒绝未知子命令，盲视只移除 AuthMe 自己添加的效果；代理 `perform.login` 还必须匹配签名目标玩家与承载连接玩家。
- 修复旧连接异步数据库异常影响新连接的会话竞态；邮件地址、SMTP envelope、存储哈希、验证码/生成密码、恢复冷却表和代理重放表均增加边界校验或容量上限；AntiBot 配置命令异常不再直接冲击加入流程，延迟事件命令队列也有上限。
- 登录请求在进入数据库查询前拒绝超长密码并纳入失败计数，避免无效输入触发不必要的哈希验证。
- `/authme help` 与 `/authme version` 不再被管理根节点错误拦截；账户数量条件事件命令和延迟事件命令绑定当前玩家会话，避免旧连接异步回调跨连接执行。
- 登录、代理自动登录、注册、TOTP 和邮箱找回密码请求现在按玩家会话串行化；重复提交不会并发推进数据库认证状态。
- 新增无 Fabric 依赖的 `authme-proxy-core`，以及可独立打包的原生 Velocity/Bungee 代理桥：签名 `proxy.started`、HMAC 自动登录、重放拒绝、切服/命令/聊天保护、重试、热重载和分片 Premium 快照。
- 新增 `authme-platform-core` 与 Paper/Folia/Spigot legacy 基础适配：异步数据库认证、哈希兼容、注册/登录/注销/改密/TOTP 和基础未登录保护；完整上游 Bukkit 集成及真实服务器验收仍未完成。
- 收紧原生代理 Premium 边界：用户名-only Premium 快照不再触发离线自动登录，避免同名账号绕过密码；Premium UUID 转发协议仍需独立实现后才能开启该旁路。

### 兼容性说明

- 首次启动可能清除数据库中的 `isLogged`/`hasSession` 标记，所有玩家需要重新登录；这是修复旧 Session 绕过风险所必需的迁移。
- 完整功能差异见 [`FEATURE_MATRIX.md`](FEATURE_MATRIX.md)。
- 现代、mid、legacy 三条 Fabric 支持线均到达 AuthMe ready/protecting；1.19.3、1.19.2 和 1.18.2 线已通过 Loader/Mixin/专用入口检查，但因保留的 EULA 状态未进入完整服务初始化。真实客户端、LuckPerms、SMTP、外部数据库和代理双端联调仍需部署验收。

## 6.0.1-fabric.1 — 2026-08-14

首个基于 AuthMeReloaded 6.0.1 的 Fabric 正式发行版。

### 功能

- 完成登录、注册、注销、改密、注销账号、验证码、TOTP、邮箱恢复、Premium/Freemium、会话和欢迎/离开消息等玩家流程。
- 完成 `/authme` 管理指令、权限节点、帮助/补全、账号查询、密码/邮箱管理、强制登录、反认证、备份、清理、迁移和调试入口。
- 兼容 AuthMe 风格配置与消息文件，并支持嵌套 YAML、语言覆盖、注册模式、二次参数、GeoIP/MaxMind、反机器人和代理协议配置。
- 支持 SQLite、MySQL/MariaDB、PostgreSQL 数据源，AuthMe 数据导入、密码哈希兼容、邮箱发送和数据清理。
- 增加 LuckPerms 可选权限桥接、代理 HMAC 校验/重放保护、输入校验和并发认证状态保护。
- 提供三个 Minecraft 覆盖模块：1.21.11、1.20.5–1.21.10、1.19.4–1.20.4；三个模块共用版本号。

### 验证

- Gradle 核心测试及三个 Fabric 模块的 `check`/`build` 通过。
- 在 Fabric Loader 0.19.3、Minecraft 1.21.11 的一次性测试服中完成启动、配置加载、SQLite 初始化、管理帮助和 MCC 玩家命令冒烟测试。

### 范围说明

- 1.16.5–1.18.1、1.19.1 移植不包含在本发行版中；1.18.2、1.19.2、1.19.3 使用独立兼容制品。
- MySQL/MariaDB/PostgreSQL、SMTP、LuckPerms 和代理双端联调仍需在使用方的实际基础设施中进行部署级验证。
