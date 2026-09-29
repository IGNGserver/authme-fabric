# AuthMe Fabric 安全边界

本文件定义本项目可以验证的安全范围。它不构成“没有漏洞”的保证，也不把 AuthMeReloaded 的 Bukkit/Paper/Folia 或原生代理实现自动视为本项目已覆盖。

## 范围

当前代码范围包括六个 Fabric 服务端模块、原生代理桥和基础 Bukkit-family 适配模块：

- `authme-fabric`：Minecraft 1.21.11；
- `authme-fabric-mid`：Minecraft 1.20.5–1.21.10 兼容线；
- `authme-fabric-legacy`：Minecraft 1.19.4–1.20.4 兼容线；
- `authme-fabric-old`：Minecraft 1.19.3 专用兼容线；当前已验证 Loader/Mixin/入口，完整服务启动仍受本地 `eula=false` 运行目录限制。
- `authme-fabric-pre`：Minecraft 1.19.2 专用兼容线；当前已验证旧 API 编译、重映射、Loader/Mixin/入口，完整服务启动仍需 EULA 与真实客户端验收。
- `authme-fabric-older`：Minecraft 1.18.2 专用兼容线；当前已验证旧 API 编译、重映射、Loader/Mixin/入口，完整服务启动仍需 EULA 与真实客户端验收。
- `authme-velocity` / `authme-bungee`：Java 21 原生代理桥，尚未完成真实代理黑盒验收；
- `authme-paper` / `authme-folia` / `authme-spigot-legacy`：基础 Bukkit-family 认证适配，尚未达到 AuthMeReloaded 完整功能齐平。

未列出的 Minecraft（包括 Fabric 1.16.5–1.18.1、1.19.1）、以及未列出的 Bukkit/Paper/Folia/BungeeCord/Velocity 版本不属于本地构建可以证明的范围。

## 信任边界

| 输入或边界 | 处理原则 |
|---|---|
| Minecraft 客户端命令、聊天和网络包 | 一律视为不可信；认证前限制命令、交互、容器、建议包和聊天路径 |
| Fabric/代理 Payload | 长度、类型、玩家名和字段先校验；每个物理认证服绑定独立 backendId/密钥，只有带时效 HMAC 且未重放的 `perform.login` 才能触发自动登录 |
| 数据库中的密码、盐、TOTP、邮箱和 Session 字段 | 视为可能损坏或被外部实例修改；解析前有长度/格式边界，认证查询不依赖普通展示缓存 |
| 配置文件和事件命令 | 视为服务器管理员输入；`commands.yml` 中的命令本来就具有服务器命令执行权限，不能把不可信用户写入该文件 |
| LuckPerms、SMTP、GeoIP 和外部数据库 | 可选外部系统；连接失败不能被当作授权成功，部署级行为必须单独验收 |

## 已落地的控制

- Session 恢复绑定最近认证 IP 和有效时间；安全迁移会清除旧的登录/Session 标记。
- 认证数据库错误进入 fail-closed 路径，不继续接受新的认证决策。
- HMAC 代理登录使用有界时间窗口、固定目标玩家校验和一次性重放缓存。
- 原生代理收到的用户名-only Premium 快照只用于有界状态同步，不会单独授予离线自动登录；缺少可验证 Premium UUID 时默认拒绝该旁路。
- 代理 Premium `PreLogin` 使用只读权威账户库；冷启动不依赖后端快照，查询不可用时拒绝连接。多认证服必须配置逐后端凭据，物理来源、签名 backendId 和对应密钥三者必须一致。
- 密码/TOTP 失败在共享库中同时累计账号+来源桶与纯来源桶；成功认证只重置自己的账号桶，不能替同一 NAT 下的其他账号清除跨账号爆破记录。
- Gradle 校验所有下载的上游构建制品。唯一可信豁免是 Loom 在本机从已校验输入生成、且缓存重建后字节不稳定的精确 synthetic mappings 坐标，以及限定命名空间下的 remapped Fabric API / merged Minecraft JAR；不得扩大到普通远程依赖。
- 登录/IP 配额使用 schema v3 的可过期数据库租约、事务内 fencing version 和定期续租；退出只撤销自己持有的版本，崩溃租约会在 30 秒后失效。密码/TOTP 失败与临时封禁使用共享数据库状态。
- 远程数据库默认只验证 schema；DDL 仅在显式 `schemaManagement: MIGRATE` 下由迁移账号执行，并由版本历史 dirty/success 标记和全局迁移锁保护。
- 密码验证、Argon2/PBKDF2 参数、TOTP、邮箱地址、SMTP envelope、验证码、恢复冷却表、延迟命令队列和代理缓存都有资源上限；配置、消息、出生点和导入 YAML 解析器也设置了代码点/别名上限；Paper/Folia/旧 Spigot 的未登录伤害拦截同时检查投射物所有者。
- 邮箱恢复改密会把新哈希与 `isLogged=0`、`hasSession=0` 放在同一个 SQL 事务中；Paper/Folia Pre-Join Dialog 的等待数量、连接交接数量、交接 TTL 和按来源地址的连接键数量均有上限，满载时回退到普通认证流程而不是驱逐其他连接的凭据。
- 旧连接的异步回调必须匹配当前 `PlayerSession` 或平台连接代次；账户数量条件事件命令和延迟命令不会再跨连接执行。
- 同一会话的登录、代理自动登录、注册、TOTP 和邮箱找回密码请求串行化；数据库未返回前的重复提交只收到等待提示，不会并发推进认证状态。
- 管理命令使用独立权限节点；LuckPerms 存在但无法返回结果时不把故障当作授权。
- 关联账户展示默认关闭，调试树的总权限和具体子权限分开检查。
- 注册后的自动登录仅适用于密码注册；`forceLoginAfterRegister` 会保留未认证状态，邮箱注册必须使用邮件生成的密码，避免把用户输入的邮箱误当作认证凭据。
- 快速命令保护的 `authme.player.protection.quickcommandsprotection` 权限按官方语义作为启用节点处理；权限桥不可用时不因故障静默关闭保护。
- Bukkit-family 未登录物品拾取同时拦截旧版 `PlayerPickupItemEvent` 和现代 `EntityPickupItemEvent`，避免事件 API 迁移留下保护旁路。
- Fabric 与 Bukkit-family 备份文件名避免同秒覆盖，并拒绝备份目录/目标文件 symlink 后再写入账户快照；自动/手动 purge 先读取待删记录，逐候选条件删除时重新核对活动时间、身份/安全快照与有效登录租约，数据库删除成功后才按安全路径规则清理可选玩家文件，并拒绝父目录/目标文件 symlink 越出服务器根目录；批量 purge 尊重在线 `authme.bypasspurge` 和当前运行时会话。
- Paper/Folia 加入后 Dialog 只提交到现有 AuthMe 命令入口；失败重试会重新绑定当前玩家会话，认证成功或断开时关闭 AuthMe 自己的 Dialog。Pre-Join 配置期 Dialog 默认关闭，启用时使用有上限的等待、连接关闭清理、一次性 UUID 交接，并在登录/注册/恢复阶段继续使用同一认证服务；真实客户端、ViaVersion、代理竞态仍未纳入本地发布门槛。

## 本地发布门槛

在发布候选版本前至少执行：

```bash
env -u CODEX_HOME GRADLE_OPTS='-Xmx4g -XX:MaxMetaspaceSize=768m' \
  bash ./gradlew --no-daemon --max-workers=1 \
  :authme-core:configSelfTest \
  :authme-core:coreSelfTest \
  :authme-core:dataSourceSelfTest \
  :authme-core:mailSelfTest \
  :authme-core:externalDbSelfTest \
  :authme-proxy-core:proxyCoreSelfTest \
  :authme-platform-core:platformCoreSelfTest \
  build
git diff --check
```

六个 Fabric 模块还必须分别启动一次测试服：现代、mid、legacy 三条线应确认出现 `Done`、AuthMe ready/protecting，且日志没有 `ERROR`、Mixin apply failure 或异常堆栈；1.19.3、1.19.2、1.18.2 线当前确认 Loader、Mixin 和专用入口加载成功，但保留的运行目录未同意 EULA，未进入完整服务初始化。构建成功、JAR 哈希和启动冒烟不能替代真实客户端测试。

## 仍必须在部署环境完成的门槛

以下项目在当前工作区没有可复现的真实外部环境，因此不能宣称已完成：

1. 至少一台真实客户端完成注册、登录、TOTP、邮箱、未登录保护、Tab 补全和容器例外验收；
2. LuckPerms 的通配符、继承、用户未加载、GroupOptions 恢复和 VIP 满员并发场景；
3. MySQL/MariaDB/PostgreSQL 的 TLS、迁移/运行时权限分离、断线重连、并发租约/失败桶和跨 AuthMe 实例一致性；
4. SMTP TLS/证书、恢复邮件、邮箱验证和失败/冷却场景；
5. Velocity/BungeeCord 双端原生插件、跨服切换、离线代理 HMAC 和真实 forwarding 配置；
   其中 Premium 还必须覆盖代理冷启动后的首个同名连接，不得把玩家连入后才到达的快照当作 PreLogin 阶段已有保障；
6. 独立安全审计、依赖漏洞扫描和发布制品签名。

发现疑似安全问题时，不要把凭据或生产数据库导出到 issue；先保留最小复现、版本、配置类别和日志中已脱敏的错误信息。
