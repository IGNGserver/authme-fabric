# AuthMe Fabric

[AuthMeReloaded](https://github.com/AuthMe/AuthMeReloaded) 的 **服务端 Fabric 移植版**—— 为离线模式（offline-mode）的 Minecraft 服务器提供账号认证。

上游 AuthMe Reloaded 采用 GPL-3.0 协议，本移植作为衍生作品同样采用 GPL-3.0。

> **为什么需要这个移植？** 原版 AuthMe 是 Bukkit/Spigot/Paper/Folia 插件，无法在 Fabric 上运行。
> 本项目把同样的账户数据库、口令哈希和认证流程带到 Fabric 服务器，让你可以：
> - 在纯 Fabric 离线模式服务器上获得完整的密码登录认证；
> - 让 Bukkit/Spigot 上的 AuthMe 与 Fabric 服务器共用**同一个 MySQL / MariaDB / PostgreSQL 账户数据库**，玩家账户在两端保持同步。

---

## 与上游 AuthMe 的功能对齐

### 认证
- `/login`、`/register`、`/changepassword`、`/logout`、`/unregister`
- 注册模式兼容 AuthMeReloaded：`settings.registration.type` 支持 `PASSWORD` / `EMAIL`，`secondArg` 支持 `NONE`、`CONFIRMATION`、`EMAIL_OPTIONAL`、`EMAIL_MANDATORY`；邮箱模式会生成随机密码并通过 SMTP 发送。
- **会话登录**（在配置时长内免重复登录）
- 登录失败次数过多后的**验证码**（`/captcha`）
- **2FA / TOTP**（RFC 6238，兼容 Google Authenticator）—— `/2fa add`、`/2fa remove <code>`、`/2fa <code>`
- **邮箱**的添加、验证、查看与 SMTP 密码恢复（`/email add|change|show|recover|code|setpassword`）
- 玩家帮助与上游命令权限节点兼容：`/login help`、`/register help`、`/2fa help`、`/email help` 等；可选 LuckPerms 节点使用 `authme.player.*`。
- **AntiBot** 连接速率限制
- **Premium 旁路**（仅在服务器启用 Mojang 身份验证时让已验证正版账号跳过密码登录）—— `/premium` / `/freemium`
- **原生对话框 UI**：1.21.11 模块可选显示登录、注册和 TOTP 对话框；旧支持线和关闭该选项时自动使用聊天流程。消息加载同时兼容上游嵌套 YAML、扁平键和 `messages_<locale>.yml` 覆盖。

### 未认证玩家保护
未登录玩家会被沙箱化，直到完成登录：
- **移动冻结**：可配置半径，通过每 tick 传送回原位置取消移动
- **聊天屏蔽**：未认证玩家发出的聊天消息会被丢弃
- **交互屏蔽**：对方块 / 物品 / 实体的左键、右键交互被取消
- **伤害屏蔽**：未认证玩家不会受到伤害
- **命令白名单**：只能使用配置允许的命令（默认：`login`、`register`、`l`、`reg`、`authme`、`email`、`2fa`、`totp`、`captcha`），其余命令通过 Brigadier `CommandDispatcher` Mixin 直接拦截
- **物品栏点击屏蔽**：通过 `ServerGamePacketListenerImpl#handleContainerClick` Mixin 实现（等效于上游基于 PacketEvents 的物品栏保护，但不需要 PacketEvents 依赖）

### 管理命令（`/authme ...`，OP 或 `authme.admin.*` 权限）
- `register <玩家> <密码>`
- `unregister <玩家>`
- `setpassword <玩家> <密码>`
- `auth <玩家>` / `unauth <玩家>` —— 在数据库中切换玩家的已登录状态
- `accountdata <玩家>`
- `accounts <玩家>`、`getip <玩家>`、`recent [数量]` —— 查询 IP 关联账号和最近账号
- `email get|set <玩家> [邮箱]`，以及旧版别名 `getemail` / `setemail`
- `totp status|disable <玩家>`、`premium|freemium <玩家>`（含 `setpremium` / `setfreemium` 别名）
- `spawn`、`setspawn`、`firstspawn`、`setfirstspawn`、`resetpos <玩家|*>`
- `purge [天数]`、`purgeplayer <玩家> [force]`、`purgebannedplayers`、`switchantibot [on|off|toggle]`
- `help [查询]`、`debug [子命令] [参数]`、`messages`（向现有 messages.yml 补齐缺失键）
- `reload` —— 重载配置 + 消息 + 数据库连接
- `converter list` / `converter <id> [参数]` —— 执行账户导入 / 迁移（AuthMe SQLite、AuthPlus YAML 及常见登录插件 SQLite 布局均为真实导入器）
- `backup`、`version`

管理命令同时兼容原版 `authme.admin.*` 权限节点；玩家命令也支持 `authme.player.*` 节点。安装 LuckPerms 时会通过可选反射桥读取节点，未安装权限插件时玩家命令保持可用、管理命令仍使用 Fabric/原版 OP 等级。

### 口令哈希——与上游字节级一致
本端口生成的哈希可与原版插件互用。默认 `SHA256`：

| 算法 | 状态 | 格式 |
|---|---|---|
| **SHA256** *(默认)* | ✅ 已实现 | `$SHA$<16位hex盐>$<sha256(sha256(pw)+盐)>` |
| SHA512 / SHA1 / MD5 / DOUBLE_SHA512 / PLAINTEXT | ✅ 已实现 | 单哈希（hex） |
| SALTEDSHA256 / SALTEDSHA512 / SALTED2MD5 | ✅ 已实现 | `hash(pw + 盐)`，盐存独立列 |
| BCRYPT (`2a`) / BCRYPT2Y (`2y`) | ✅ 已实现 | BouncyCastle `OpenBSDBCrypt` |
| PBKDF2 / PBKDF2BASE64 | ✅ 已实现 | BouncyCastle `PKCS5S2ParametersGenerator`（HmacSHA256） |
| ARGON2 / ARGON2ID | ✅ 已实现 | BouncyCastle `Argon2BytesGenerator`，PHC `$argon2i$`/`$argon2id$` 格式 |
| CMW, CRAZYCRYPT1, DOUBLEMD5, IPB3/4, JOOMLA, MD5VB, MYBB, PBKDF2DJANGO, PHPBB, PHPFUSION, ROYALAUTH, SMF, TWO_FACTOR, WBB3/4, WORDPRESS, XFBCRYPT | ✅ 已实现 | 含上游兼容验证与错误哈希拒绝 |

另外支持**旧哈希回退并自动重哈希**：当密码能用配置的 `settings.security.legacyHashes` 算法验证通过时，会透明地用主算法重新哈希，实现零停机哈希算法迁移。

---

## 覆盖矩阵——按 MC 版本选一个 jar

各版本间 Fabric / Minecraft API 漂移较大，单个 jar 无法通吃。项目拆成**共用一个纯 Java `authme-core`** 的多模块：

| 模块 | Minecraft | Java | fabric.mod.json `minecraft` 约束 |
|---|---|---|---|
| `authme-fabric` | **1.21.11** | 21 | `~1.21.11` |
| `authme-fabric-mid` | **1.20.5 – 1.21.10** | 21 | `>=1.20.5 <1.21.11` |
| `authme-fabric-legacy` | **1.19.4 – 1.20.4** | 17 | `>=1.19.4 <1.20.5` |

> **1.16.5 – 1.19.3 不支持** —— 它们使用的 pre-1.19 聊天 / `TextComponent` API 与 packet 处理差异较大，需要再拆一个独立的 `authme-fabric-legacy-old` 模块才能覆盖。

三个 jar 共用：
- 同一个 `authme-core`（`io.github.authme.fabric.*` 包），以 Fabric **jar-in-jar** 内联，
- 同一套运行库捆绑（MySQL / MariaDB / PostgreSQL / SQLite JDBC、BouncyCastle、SnakeYAML），
- 同一个配置文件格式与配置目录（`<服务器>/config/authme/`）。

因此**账户数据库与配置跨版本完全兼容**——升级服务器时只需换 jar，数据无需迁移。

### 为什么要拆分？
通过 `javap` 直接核对每个目标 MC 版本的 merged Mojmap jar：
- `CommandSourceStack.hasPermission(int)` → `PermissionSet` 仅在 **1.21.11** 出现
- `ResourceLocation.location()` → `Identifier.identifier()` 仅在 **1.21.11** 改名
- `ServerPlayer.level()` 的协变返回 `ServerLevel` 从 1.21.10 才有；1.20.4 需用 `serverLevel()`
- 1.20.4 的 `teleportTo(ServerLevel, …)` 参数为 `Set<RelativeMovement>` 且无末尾 boolean；1.21.x 改为 `Set<Relative>` + boolean
- 1.20.4 的 `UseItemCallback.interact` 返回 `InteractionResultHolder<ItemStack>`；1.21.x 改为 `InteractionResult`

---

## 数据库——以及"与 Spigot AuthMe 共用账户"

支持的后端（`config.yml` 中的 `DataSource.backend`）：

| 后端 | 状态 | 说明 |
|---|---|---|
| **MySQL** | ✅ | 建出**与 AuthMe 完全一致**的表结构（可配置列名、`MEDIUMINT(8) UNSIGNED AUTO_INCREMENT` 主键、`password ascii_bin`、`isLogged`/`hasSession`/`regdate`/`totp`/`premiumUUID` 等列） |
| **MariaDB** | ✅ | 同表结构，走 MariaDB JDBC 驱动 |
| **PostgreSQL** | ✅ | 同结构 + PG 类型适配（`SERIAL`、`DOUBLE PRECISION`、`REAL`，用 `COLLATE "C"` 代替 MySQL `ascii_bin` 实现字节级区分） |
| **SQLite** | ✅ | 本地文件位于 `config/authme/` 下；已捆绑 `sqlite-jdbc` 驱动 |

**让 Bukkit/Spigot AuthMe 与本端口共用一个账户数据库：**
1. 两份 `config.yml` 配**同一** MySQL/MariaDB/PostgreSQL 连接（主机、端口、库、表名、用户名、密码）。
2. 使用**一致**的列名——默认值已经与 AuthMe 对齐（`username`、`realname`、`password`、`ip`、`lastlogin`、`regdate`、`isLogged`、`hasSession`、`totp`、`premiumUUID` 等）。
3. 使用**同一个** `settings.security.passwordHash`（默认 `SHA256`）。
4. 两端服务器即可读写同一账户行；哈希字节级一致，在 Spigot 端注册的玩家可以直接在 Fabric 端登录，反之亦然。

> ✅ 默认配置（`mySQLColumnSalt: ''`）与上游 SHA256 对齐（盐嵌入哈希）。
> 如果使用带独立盐列的算法（`SALTEDSHA256/512`、`SALTED2MD5`），把 `mySQLColumnSalt` 设成与你 AuthMe 一致的列名即可。

`MySQLDataSource` 启动时还会对缺失的 AuthMe 列做 `ALTER TABLE … ADD COLUMN`，所以把本端口指向原版插件已建好的数据库不会破坏它。

### 账户转换器
`/authme converter list` 与 `/authme converter <id> [参数]`：
- `sqliteToSql <路径>` —— 把一个 AuthMe SQLite 文件中的全部账户复制到你当前配置的 SQL 后端（**已实现**）
- `authplus` —— 读取默认 `plugins/Auth/players.yml`（也可传入 YAML 路径）
- `librelogin`、`limboauth`、`nlogin`、`openlogin`、`tiauth`、`nexauth` —— 读取对应默认 SQLite 文件；参数格式为 `路径` 或 `路径|表名`
- `mysqlToSqlite` —— 将 AuthMe 结构的 SQLite 快照导入当前配置的数据源；目标为 SQLite 时会拒绝无意义的迁移

---

## 运行要求

| 组件 | 版本要求 |
|---|---|
| Minecraft | 1.19.4 – 1.21.11 |
| Fabric Loader | ≥ 0.16.0（构建基于 0.19.3） |
| Fabric API | 任意版本（构建基于各模块的 pin 版本） |
| Java | `authme-fabric` / `-mid` 需 21，`-legacy` 需 17 |
| 可选代理 | 代理应把验证后的玩家以在线模式身份转发；本移植不会在离线模式下信任客户端自报 UUID |

**运行时无任何外部依赖**——JDBC 驱动、BouncyCastle、SnakeYAML 全部以 Fabric jar-in-jar 形式打进每个模块的 jar 内。

---

## 构建

需要 JDK 21，以及首次运行时联网（Loom 会下载 Minecraft + Mojmap 映射）：

```bash
./gradlew clean build
```

### 发布版本

本项目使用“上游版本 + Fabric 移植发行线 + 本项目发布序号”的格式：
`<上游版本>-fabric.<序号>`。当前开发版本为 `6.0.1-fabric.2-SNAPSHOT`，最近的正式版本为
`6.0.1-fabric.1`；后续继续基于上游 AuthMeReloaded 6.0.1 修正时依次使用
`6.0.1-fabric.2`、`6.0.1-fabric.3` 等。完整规则见 [`RELEASE.md`](RELEASE.md)。

会得到三个 jar：
- `authme-fabric/build/libs/authme-fabric-6.0.1-fabric.2-SNAPSHOT.jar`
- `authme-fabric-mid/build/libs/authme-fabric-mid-6.0.1-fabric.2-SNAPSHOT.jar`
- `authme-fabric-legacy/build/libs/authme-fabric-legacy-6.0.1-fabric.2-SNAPSHOT.jar`

（每个还有对应的 `-sources.jar`。）

只构建某个模块：`./gradlew :authme-fabric-mid:build` 等。

---

## 安装与配置

1. 按你的 MC 版本选择对应 jar（见覆盖矩阵）。
2. 把它和 Fabric API 一起放进 `mods/` 目录。
3. 启动一次服务器——会自动生成 `config/authme/config.yml` 与 `config/authme/messages.yml`。
4. 停服，编辑 `config.yml`：
   - `DataSource.backend` —— `SQLITE`（默认）或 `MYSQL` / `MARIADB` / `POSTGRESQL`
   - SQL 后端：`mySQLHost`、`mySQLPort`、`mySQLDatabase`、`mySQLTablename`、凭据等。**与原 AuthMe 配置保持一致即可共享账户。**
   - `settings.security.passwordHash`（默认 `SHA256`）—— 与现有 AuthMe 使用同一个值
   - `Settings.restrictUnauthenticated.allowCommands` —— 登录前可用的命令
   - `settings.session.enabled` / `timeout` —— 会话登录
   - `settings.registration.type` / `secondArg` —— 兼容密码注册、邮箱注册、密码确认和注册邮箱模式
   - `settings.registration.dialog.postJoin.enable` —— 1.21.11 原生登录/注册/TOTP 对话框（支持线默认开启；其他支持线安全使用聊天）
   - `Security.captcha.*`、`Security.tempban.*` —— 暴力破解防护
5. 重启服务器，完成。

### 关键配置项（与 AuthMe 的 config.yml 兼容）

```yaml
DataSource:
  backend: MYSQL
  mySQLHost: 127.0.0.1
  mySQLPort: 3306
  mySQLDatabase: authme
  mySQLTablename: authme
  mySQLUsername: authme
  mySQLPassword: '...'
  # 与你现有 AuthMe 配置保持列名一致：
  mySQLColumnName: username
  mySQLColumnPassword: password
  mySQLColumnSalt: ''          # '' 代表 SHA256（盐嵌入）；带独立盐列的算法需设该列名
  mySQLColumnIp: ip
  mySQLColumnLastLogin: lastlogin
  mySQLColumnRegisterDate: regdate
  mySQLColumnLogged: isLogged
  mySQLColumnHasSession: hasSession
  mySQLtotpKey: totp
  mySQLColumnPremiumUUID: premiumUUID

settings:
  messagesLanguage: en
  registration:
    type: PASSWORD             # PASSWORD 或 EMAIL
    secondArg: CONFIRMATION    # NONE / CONFIRMATION / EMAIL_OPTIONAL / EMAIL_MANDATORY
    forceKickAfterRegister: false
    forceLoginAfterRegister: false
    messageInterval: 5
    useWelcomeMessage: true
    broadcastWelcomeMessage: false
    serverName: 'Minecraft Server'
  security:
    passwordHash: SHA256       # 与你的 Spigot AuthMe 同值
    minPasswordLength: 5
    passwordMaxLength: 30
    # legacyHashes: [SHA1]    # 可选旧哈希回退 / 自动重哈希迁移
  session:
    enabled: false
    timeout: 60

  restrictions:
    AllowRestrictedUser: false
    AllowedRestrictedUser: []       # player;127.0.0.* 或 player;regex:...
    banUnsafedIP: false
    enablePasswordVerifier: true    # false 时 /register 允许单参数
    noTeleport: false
    removeSpeed: false
    ForceSpawnLocOnJoin:
      enabled: false
      worlds: [world, world_nether, world_the_end]

  unrestrictions:
    UnrestrictedName: []             # 受信任 NPC/Mod 账号，绕过认证

BackupSystem:
  ActivateBackup: false
  OnServerStart: false
  OnServerStop: false
Purge:
  useAutoPurge: false
  daysBeforeRemovePlayer: 60
  removePlayerDat: false
  removeEssentialsFile: false
  removeLimitedCreativesInventories: false
  removeAntiXRayFile: false
  removePermissions: false

Hooks:
  bungeecord: false
  proxySharedSecret: ''       # 与 AuthMe Bungee/Velocity 端一致
  sendPlayerTo: ''            # 登录/注册成功后发送 BungeeCord Connect

Protection:
  enableProtection: false
  geoIpDatabase:
    enabled: true
    failClosed: false
    file: geoip-countries.csv  # 也可填写 GeoLite2-Country.mmdb
  countries: ['US', 'GB', 'LOCALHOST']
  countriesBlacklist: ['A1']

Email:
  enabled: false
  host: 127.0.0.1
  port: 25
  username: ''
  password: ''
  from: 'authme@example.invalid'
  maxRegPerEmail: 1
  RecoveryPasswordLength: 8
  # requireVerification: true 时，/email add 会先发送验证代码
```

---

## 命令（玩家侧）

| 命令 | 别名 | 用途 |
|---|---|---|
| `/login <密码>` | `/l` | 登录 |
| `/register <密码> <密码>` | `/reg` | 注册（由 `secondArg` 决定第二参数，也可为邮箱） |
| `/changepassword <旧密码> <新密码>` | `/changepass` | 修改密码（需已登录） |
| `/logout` | — | 登出 |
| `/unregister <密码>` | — | 注销自己的账号 |
| `/captcha <验证码>` | — | 输入验证码 |
| `/2fa <code>` | `/totp` | 验证 2FA 码 |
| `/2fa add` | — | 启用 2FA（会打印密钥 + otpauth URI） |
| `/2fa remove <code>` | — | 关闭 2FA |
| `/email add <邮箱> <邮箱>` | `/email change` | 添加或修改邮箱 |
| `/email show` | — | 查看邮箱 |
| `/email recover <邮箱>` | — | 发送一次性 SMTP 恢复码（需启用 Email） |
| `/email code <验证码>` | `/email confirm` | 验证邮箱或恢复码 |
| `/email setpassword <密码>` | — | 完成恢复后的密码重置并登录 |
| `/premium` | — | 为本账号启用 premium（正版）旁路 |
| `/freemium` | — | 为本账号关闭 premium 旁路 |

---

## 权限

- 玩家命令：全部开放（AuthMe 自己通过登录状态约束）
- 管理命令（`/authme ...`）：由服务器的 OP 级权限把关
  - `authme-fabric`（1.21.11）—— `Permission.HasCommandLevel(ADMINS)`
  - `-mid` / `-legacy` —— `CommandSourceStack.hasPermission(3)`（OP 等级 ≥ 3）

---

## 它如何对未登录玩家实施保护

| 玩家行为 | 防护机制 |
|---|---|
| 走出 / 掉出生点 | 每 tick 传送回冻结的加入点（取消 delta movement） |
| 发送聊天消息 | `ServerMessageEvents.ALLOW_CHAT_MESSAGE` 返回 false |
| 左/右键点击方块或实体、使用物品 | `AttackBlockCallback` / `UseBlockCallback` / `UseEntityCallback` / `AttackEntityCallback` / `UseItemCallback` 返回 `FAIL` |
| 受到伤害 | `ServerLivingEntityEvents.ALLOW_DAMAGE` 返回 false |
| 在物品栏内点击 | `ContainerClickMixin` 在 HEAD 处取消 `ServerGamePacketListenerImpl#handleContainerClick` |
| 执行不在白名单的命令 | `CommandDispatcherMixin` 在 HEAD 处取消 `CommandDispatcher#execute(...)`，除非命令根在 `allowCommands` 中 |
| 用已注册到 premium 账号的名字加入 | （当 `enablePremium: true` 且服务器在线验证开启）按 `premiumUUID` 匹配已验证的 Mojang UUID |
| 机器人式连接刷屏 | `AntiBotManager` 在达到配置阈值后拦截新加入请求 |

### 仍需外部环境才能证明的边界

- 1.16.5–1.19.3 按项目要求不提供模块。
- 代理消息、GeoIP 和 purge 文件清理已经实现，但真实 BungeeCord/Velocity 双端跨服链路、非本机公网 IP 转发和代理压力仍需对应部署环境验证；Fabric 端不会信任客户端自报 UUID，未携带共享密钥的 premium 列表同步会被拒绝。
- GeoIP 支持本地 MaxMind `.mmdb`（或 CIDR CSV）读取，不会自动下载数据库；数据库文件、国家数据更新和授权条款由服务器运营者负责。
- MySQL/MariaDB/PostgreSQL 的真实成功连接、故障转移和长时间压力结果需要对应数据库实例；当前已完成 JDBC 配置、连接池、失败关闭和 SQLite 运行验证。

### 当前仍有边界的上游功能
- **pre-join dialog UI**（Paper/Folia 专有的配置阶段连接与响应 API；Fabric 仍使用加入后的认证流程；1.21.11 的 post-join 原生对话框已实现）
- 1.16.5 – 1.19.3 支持

邮箱恢复使用内置 JDK SMTP 客户端；验证码只保存在内存中、过期后失效，并限制错误尝试次数。`/authme backup` 会生成 UTF-8 SQL 数据快照；它不是数据库厂商的物理热备，生产环境仍应配置正式备份策略。真实 SMTP、MySQL/MariaDB/PostgreSQL 和代理双端部署仍需在目标环境做最终验收。

---

## 架构

```
authme-core/                   # 纯 Java 17 —— 不依赖 Minecraft
  src/main/java/io/github/authme/fabric/
    security/                   # 哈希（SHA256/BCrypt/PBKDF2/Argon2/…）
    datasource/                 # MySQL/MariaDB/PostgreSQL/SQLite + 连接池
    converter/                  # SQLite/YAML 账户导入与 sqliteToSql 迁移
    mail/                       # JDK SMTP（SSL/STARTTLS）
    totp/                       # RFC 6238 TOTP 客户端
    config/                     # YAML 配置 + 消息（SnakeYAML）
    antibot/                    # 速率限制
    auth/                       # PlayerSession（纯数据，不引用 ServerPlayer）
    util/Log.java               # 可插拔 Log.Sink（log4j 留在平台模块）
authme-fabric/                 # 1.21.11，Java 21，Identifier + PermissionSet
authme-fabric-mid/             # 1.20.5–1.21.10，Java 21，ResourceLocation + hasPermission
authme-fabric-legacy/          # 1.19.4–1.20.4，Java 17，RelativeMovement
                               # 每个平台模块都包含：AuthMe、AuthManager、
                               # AuthMeFabric、AuthMeCommands、AuthMeEvents、
                               # MinecraftText、ContainerClickMixin、CommandDispatcherMixin
```

每个平台模块都会把 `authme-core` 与捆绑库（MySQL/MariaDB/PostgreSQL/SQLite JDBC、BouncyCastle、SnakeYAML）作为 Fabric **jar-in-jar** 内嵌——用户侧无需任何运行时依赖。

---

## 许可证

```
AuthMe Fabric
Copyright (C) 自 2026 起 AuthMe Fabric 移植贡献者
Copyright (C) 自 2013 起 AuthMe-Team（上游 AuthMeReloaded）

本程序为自由软件：你可依据自由软件基金会发布的 GPLv3（或更高版本）重新分发与修改它。

本程序以期有用而发布，但不提供任何担保；亦不对其适销性或特定用途适用性作任何默示担保。
详见 GNU 通用公共许可证以获取更多信息。
```

完整 GPLv3 文本见 [`LICENSE`](LICENSE)。

上游：[`AuthMe/AuthMeReloaded`](https://github.com/AuthMe/AuthMeReloaded)—— 请给原项目点个 star，没有它就没有本移植。

---

## 致谢

- **AuthMe-Team** —— 上游 AuthMeReloaded 的作者与持续维护者。
- **FabricMC** —— Loom、Fabric Loader 与 Fabric API。
- **BouncyCastle** —— BCrypt / PBKDF2 / Argon2 实现。
- **xerial** —— `sqlite-jdbc` 驱动。
- 上游 AuthMe 的所有翻译者与贡献者。

## 问题 / 贡献

本仓库是衍生移植版本；移植本身引入的 bug 请提到[本仓库的 issue 跟踪器](issues)。关于上游 AuthMe 行为 / 哈希算法的问题，仍以[上游 issue 跟踪器](https://github.com/AuthMe/AuthMeReloaded/issues)为准。
