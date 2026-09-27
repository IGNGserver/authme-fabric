# AuthMeReloaded 功能差异矩阵

本文件是当前 Fabric 移植版的发布边界，不把“代码中存在配置项”当作“功能已经实现”。对照基准为 AuthMeReloaded 官方的 [README](https://github.com/AuthMe/AuthMeReloaded/blob/master/README.md)、[配置文档](https://github.com/AuthMe/AuthMeReloaded/blob/master/docs/config.md)、[命令文档](https://github.com/AuthMe/AuthMeReloaded/blob/master/docs/commands.md) 和 [权限节点文档](https://github.com/AuthMe/AuthMeReloaded/blob/master/docs/permission_nodes.md)。

状态含义：

- **已实现**：当前 Fabric 代码中有对应行为，并有核心测试或静态验证。
- **部分实现**：有可用子集，但与上游语义、平台或集成方式不完全相同。
- **未实现**：目前只有配置兼容项、占位项或没有对应代码。
- **未验证**：代码路径存在，但需要真实 Minecraft、代理、数据库或第三方服务验收。

## 当前版本

| 功能 | 状态 | 说明 |
|---|---|---|
| 注册、登录、注销、改密 | 已实现 | 六个 Fabric 覆盖模块共用认证流程；1.18.2/1.19.2 仍需完整服务启动与客户端验收 |
| 密码哈希与旧哈希兼容 | 已实现 | 核心自测覆盖已实现算法和旧向量 |
| TOTP | 已实现 | 登录后第二因素，不应在密码前直接触发 |
| Session | 已实现（安全修复后） | 必须在超时内且来源 IP 相同；升级首次启动清除旧 Session；平台适配的异步操作绑定连接代次；旧兼容线仍需完整运行时验收 |
| 邮箱注册、验证、找回 | 部分实现（运行时未验证） | Fabric 与 Bukkit-family 共享服务均覆盖邮箱注册/验证/找回、恢复冷却、失败次数、验证码长度、密码修改窗口和可选邮箱脱敏；真实 SMTP/TLS 仍需部署验证 |
| AntiBot | 部分实现 | 有连接速率阻断、`authme.bypassantibot` 和 `authme.admin.antibotmessages` 生命周期通知，不是上游全部挑战器实现 |
| 多账户限制 | 部分实现（跨实例代码已覆盖） | IP 登录配额在数据库租约事务内执行，崩溃租约 30 秒过期；`authme.allowmultipleaccounts` 与真实代理 IP/NAT 场景仍需部署验证 |
| 未登录保护 | 部分实现 | 移动、聊天、交互、容器、命令和伤害有 Fabric 拦截；`allowedMovementRadius: 0` 按上游语义表示不限制半径；1.19.3+ 使用聊天广播接收者过滤，1.18.2 使用专用聊天包拦截；平台事件语义不等同 Bukkit |
| 快速命令保护 | 部分实现（未验证） | 支持官方 `Protection.quickCommands.denyCommandsBeforeMilliseconds`，默认 1000ms；命令过早时踢出未登录玩家，权限/真实客户端场景仍需验收 |
| 登录前 Tab 补全屏蔽 | 部分实现（未验证） | 支持的 Fabric 线均通过对应的命令建议包拦截；真实客户端建议包行为仍需验收 |
| UnrestrictedName | 部分实现（未验证） | 配置名称会绕过 AuthMe 注册、登录、命令和动作限制；仍保留连接健康、临时封禁和 AntiBot 入口保护，真实 NPC/模组场景需验收 |
| UnrestrictedInventories | 部分实现（未验证） | 支持配置标题、方块/实体菜单初始交互和成功菜单的容器点击放行；物品触发的自定义菜单与真实客户端场景仍需验收 |
| GeoIP 国家限制 | 部分实现（未验证） | Fabric 与 Bukkit-family 适配均支持本地 MaxMind MMDB/CIDR 数据、`authme.bypasscountrycheck` 和 fail-closed 配置；数据文件与真实公网地址仍需部署验收 |
| `commands.yml` 事件钩子 | 部分实现（未验证） | Fabric 与 Bukkit-family 运行时支持登录、注册、注销、Session、首次登录、Join、Logout、延迟和账户数量条件；第三方命令执行效果仍需真实服务器验收 |
| `/authme` 管理命令 | 部分实现 | Fabric 与 Bukkit-family 均有官方主要管理树、别名、玩家子命令 help、`debug mysqldef` 白名单 DDL 和逐项鉴权；原生 Bukkit 补全、Paper/Folia Dialog 的真实客户端验收和真实权限继承仍未完成 |
| 权限节点 | 部分实现 | 已有 LuckPerms 桥接，支持 `authme.admin.*`、`authme.player.*`、`authme.vip` 满员替换和 AntiBot 通知节点；仍需补齐全部上游节点和权限继承语义 |
| VIP 满员替换 | 部分实现（未验证） | `authme.vip` 只绕过原版容量分支，加入后优先踢出非 VIP；LuckPerms 用户预加载、并发登录和真实客户端场景仍需验收 |
| 账户隐私信息 | 已实现（安全默认） | 同 IP 账户信息默认关闭；管理员需 `authme.admin.seeotheraccounts`，玩家查看自己的关联账号需 `authme.player.seeownaccounts` |
| 数据库故障安全失败 | 已实现（运行时边界） | 默认停止服务器；显式关闭时踢出在线玩家并拒绝后续加入 |
| SQLite、MySQL、MariaDB、PostgreSQL | 部分实现 | 核心 JDBC/SQLite 自测通过，外部实例仍未在本工作区联调 |
| 数据备份、清理、导入 | 部分实现（代码已补齐主要路径） | Fabric 与 Bukkit-family 支持启动/停止/周期 SQL 备份、旧账号清理、单账号/封禁账号清理和受配置控制的关联文件清理；批量清理尊重在线 `authme.bypasspurge`，外部数据库、文件兼容性和真实服务器仍需验收 |
| BungeeCord / Velocity 认证桥 | 部分实现（未验证） | 独立原生桥按物理服务器绑定 backendId/独立 HMAC 密钥；Premium PreLogin 直接查询只读权威库并在故障时拒绝。真实跨服、冷启动与 forwarding 仍需黑盒联调 |
| 原生 Fabric 登录对话框 | 部分实现 | 支持加入后流程；不是 Paper/Folia Pre-Join API |
| 每玩家语言 | 部分实现（未做真实客户端验收） | `messages_<locale>.yml` 精确匹配后按基础语言和服务器语言回退；最终输出点统一解析，代码覆盖聊天、踢出和命令回复，但各 Minecraft 映射线的客户端 locale 反射仍需真实客户端验证 |
| GroupOptions | 已实现（默认关闭） | 安装 LuckPerms 时使用 transient 继承节点屏蔽原组并加入隔离组；不清空、不保存持久节点，恢复时只删除 AuthMe 自己加入的节点 |
| Limbo 状态恢复 | 部分实现（未做真实客户端验收） | 暂时保存并恢复 OP、飞行、速度、无敌状态；已接入未登录期间末影珍珠追踪、认证后重建、单会话失效、注册后自动登录/强制登录、延迟加入消息和认证提醒；分桶大小变更迁移、Folia 区域线程和真实 Minecraft 状态仍需验收 |
| Citizens、CombatTag、PlaceholderAPI 等集成 | 部分实现 | Bukkit-family 已提供 PlaceholderAPI 状态扩展、NPC metadata 兼容和软依赖声明；Fabric 没有 Bukkit 第三方插件生态的等价模块，Citizens/CombatTag 的真实插件验收仍未完成 |
| 原生 BungeeCord / Velocity 插件 | 部分实现（已编译，未黑盒验证） | 独立插件 JAR 不依赖 Fabric Loader；当前只把已在认证服登录的会话跨服重放，用户名-only Premium 快照不会触发离线自动登录；仍缺真实代理部署验收和官方 Premium/ConfigMe/PacketEvents 完整兼容 |
| Pre-Join Dialog | 部分实现（未做真实客户端/代理验收） | Paper/Folia 1.21 可选配置阶段登录、注册和恢复邮件 Dialog；默认关闭，超时/取消/断开清理和会话集成有边界保护；Fabric 仍走加入后的认证流程 |
| Minecraft 1.19.3 | 部分实现（Fabric，独立制品） | `authme-fabric-old` 使用 1.19.3 专用 Mixin/兼容反射；已通过 Loader/Mixin/专用入口冒烟，完整服务启动和真实客户端仍需验收 |
| Minecraft 1.19.2 | 部分实现（Fabric，独立制品） | `authme-fabric-pre` 已完成旧命令/断开/网络兼容编译与 Loader 冒烟；完整服务启动和真实客户端仍需验收 |
| Minecraft 1.18.2 | 部分实现（Fabric，独立制品） | `authme-fabric-older` 已完成旧文本/命令/事件/聊天/伤害兼容编译与 Loader 冒烟；完整服务启动和真实客户端仍需验收 |
| Minecraft 1.16.5–1.18.1、1.19.1 | 未实现（Fabric） | 仍缺对应独立 API/网络适配；另有独立 Spigot legacy 1.16.5+ JAR，不能互相替代 |
| Bukkit/Paper/Folia API 与事件兼容 | 部分实现 | 已有独立 Paper 1.21、Folia 1.21、Spigot legacy 模块，共享数据库/哈希/注册/登录/注销/改密/TOTP、邮箱/恢复、CAPTCHA、Premium、加入后/配置期原生 Dialog、命令钩子、自动维护和基础未登录保护；完整 AuthMe 命令树语义、LuckPerms/PlaceholderAPI/Citizens/CombatTag 仍未齐平，真实服务器未验收 |

## 本次安全修复

- Session 恢复统一使用共享的 `SessionSecurityPolicy`，强制校验 IP、过期时间和时间方向；邮箱恢复改密会在同一数据库事务中清除旧登录/Session 标记。
- 首次启动通过 `.session-ip-binding-v2` 一次性清除旧的登录/Session 标记。
- 同 IP 账户列表默认关闭，并限制到 `authme.admin.seeotheraccounts`。
- `/authme debug` 要求 `authme.debug.command`，动态子命令还要求对应的 `authme.debug.*`。
- 管理/玩家权限检查支持官方通配节点 `authme.admin.*` 与 `authme.player.*`；新增快速命令保护默认等待窗口，减少刚连接时的命令竞态。
- LuckPerms 存在但无法返回结果时，玩家权限检查拒绝而不是放行。
- 运行时数据库故障会令 AuthMe 进入不可用状态，禁止继续认证。
- 邮箱恢复增加按玩家/IP 冷却、失败次数和验证码长度配置。
- `authme.bypassantibot` 与 `authme.allowmultipleaccounts` 已接入对应限制。
- 玩家语言文件在最终输出点解析，避免异步数据库回调丢失玩家语言上下文。
- GroupOptions 仅修改 LuckPerms transient 节点，崩溃时不会将隔离组写入权限存储；Limbo 状态继续使用服务器本地持久化。
- 共享数据库登录使用可续期 fencing lease，IP 配额与账户状态在同一协调事务中提交；失败计数、CAPTCHA 阈值和临时封禁使用共享数据库状态。
- 远程数据库默认 `VALIDATE` 且运行时不执行 DDL；显式 `MIGRATE` 使用版本历史与迁移锁。代理 Premium 使用 SELECT-only 权威目录并按后端隔离凭据。
- Bukkit-family 的注册分支区分密码注册自动登录、`forceLoginAfterRegister` 强制 `/login` 和邮箱生成密码注册，避免把邮箱地址误当作密码；延迟加入消息只在认证完成后广播一次。
- 备份目标固定在 AuthMe 数据目录下并避免同秒文件覆盖；批量/封禁/单账号清理在删除数据库记录后才清理受配置允许的关联文件，并尊重在线 `authme.bypasspurge`。旧账号批量清理逐候选复核活动时间、身份/安全快照、在线会话和有效登录租约，不再在无 bypass 时回退到未绑定候选快照的批量删除。
- 登录、Session、密码和 TOTP 决策绕过普通认证缓存，每次从数据源读取，避免共享数据库另一实例注销或改密后继续接受旧状态；普通账户展示仍可使用有界缓存。
- 账户数量条件事件命令和延迟事件命令绑定创建它们的 `PlayerSession`，旧连接的异步查询不能跨连接执行配置命令。
- 登录、代理自动登录、注册、TOTP 和邮箱找回密码在单个会话内串行化，避免重复命令并发写入认证状态。
- 1.21.x 的 Limbo OP 隔离适配 `NameAndId`，恢复/撤销 OP 时不再把旧版 `GameProfile` 直接传给新版本 API。
- `hideChat` 的普通服务器聊天广播已过滤未认证接收者；私有消息、第三方聊天管线和原生客户端验收仍不在该覆盖范围内。
- 代理 `perform.login` 仅接受带时效、HMAC 和一次性重放缓存的消息；未认证的代理消息不会返回 Premium 列表。
- 代理时间戳使用溢出安全的有界窗口；代理 Payload、Argon2/PBKDF2 参数和 TOTP 密钥长度均有限制，异常网络/数据库输入会被拒绝。
- 邮件地址和 SMTP envelope 使用有界 ASCII 地址策略；存储密码哈希、验证码/生成密码、恢复冷却和代理重放缓存有容量上限；旧异步会话回调不能再触发新连接的全服数据库故障处理。
- 邮箱恢复密码与清除旧登录/Session 标志在 SQL 数据源中使用同一事务；Paper/Folia 配置期 Dialog 和按地址连接跟踪增加容量、TTL 和满载回退边界。
- 配置、消息、出生点和导入 YAML 设置了代码点与别名上限，欢迎消息也限制行数和总大小，避免恶意配置制造无界解析消耗。
- Paper/Folia/Spigot 的 GeoIP、`allowChat`、`UnrestrictedName`、`allowmultipleaccounts`、AntiBot 和连接代次保护已接入共享适配；其第三方集成与真实调度线程仍需部署验收。
- 新安装配置模板不再包含 `mySQLPassword: '12345'` 示例凭据；切换到 MySQL/MariaDB 前必须由部署者设置唯一强密码。
- 内置 Bouncy Castle、SQLite JDBC 和 SnakeYAML 已升级到当前验证过的安全基线；项目仍需在发布流水线接入持续的依赖漏洞扫描。

## 仍不能宣称的内容

即使本矩阵中的已实现项全部通过，也只能宣称“在声明的 Fabric 版本和测试范围内没有已知阻断问题”。不能宣称“包含 AuthMeReloaded 全部功能”或“绝对没有漏洞”，除非补齐平台级模块、真实基础设施测试和独立安全审计。
