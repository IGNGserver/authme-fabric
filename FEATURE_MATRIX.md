# AuthMe Fabric 功能矩阵

本文件只描述 Fabric 服务端模组及其外部互操作边界。归档目录中的 Paper、Bukkit、Spigot、Folia、Velocity、BungeeCord 原生适配不属于当前发布物。

状态含义：

- **已实现**：活动 Fabric 代码中存在对应行为，并有核心测试或静态检查支撑；
- **部分实现**：只覆盖上游功能的 Fabric 子集，或不同兼容线行为有差异；
- **未验证**：代码路径存在，但需要真实 Minecraft、数据库、邮件、权限或外部代理环境验收。

## 功能矩阵

| 功能 | 状态 | Fabric 范围与说明 |
|---|---|---|
| 注册、登录、注销、改密 | 已实现 | 六条 Fabric 兼容线共用 `authme-core` 认证流程 |
| 口令哈希与旧哈希兼容 | 已实现 | 保持 AuthMe 账户表和哈希格式兼容；旧哈希可按配置自动迁移 |
| Session 登录 | 已实现 | 绑定安全约束和租约状态，仍需多实例真实环境验收 |
| TOTP / 2FA | 已实现 | RFC 6238，使用 `/2fa` 命令族 |
| 邮箱注册与恢复 | 部分实现 | 内置 JDK SMTP 客户端；真实 SMTP、证书和投递结果未在本地证明 |
| 验证码、临时封禁、AntiBot | 已实现 | 核心策略和 Fabric 连接生命周期已接入 |
| 未登录玩家沙箱 | 已实现 | 移动、聊天、交互、伤害、命令和物品栏保护按兼容线实现 |
| VIP 满员替换 | 部分实现 | 依赖 Fabric 连接/玩家事件；需要真实满员和并发连接验收 |
| Premium / Mojang 身份验证 | 部分实现 | 仅在在线模式与账户数据条件满足时生效 |
| LuckPerms GroupOptions | 部分实现 | 通过可选 Fabric 侧桥接使用 transient 权限；需真实 LuckPerms 验收 |
| 数据库 | 已实现 | SQLite、MySQL、MariaDB、PostgreSQL；可与外部 AuthMe 实例共享账户表 |
| 账户转换器与备份 | 部分实现 | 支持多个 AuthMe/登录插件数据布局；备份不是数据库物理热备 |
| 原生对话框 | 部分实现 | 1.21.11 提供 post-join 对话框，其他兼容线使用聊天回退；需真实客户端验收 |
| 外部代理互操作 | 部分实现 | Fabric 侧 Payload/raw channel、HMAC 和 Connect 请求；原生代理插件已归档 |

## Minecraft 兼容线

| 活动模块 | Minecraft | Java |
|---|---|---|
| `authme-fabric` | 1.21.11 | 21 |
| `authme-fabric-mid` | 1.20.5–1.21.10 | 21 |
| `authme-fabric-legacy` | 1.19.4–1.20.4 | 17 |
| `authme-fabric-old` | 1.19.3 | 17 |
| `authme-fabric-pre` | 1.19.2 | 17 |
| `authme-fabric-older` | 1.18.2 | 17 |

1.16.5–1.18.1 和 1.19.1 不在当前 Fabric 覆盖范围内。任何未列出的 Minecraft、Fabric Loader/API 或第三方集成，都必须单独标记为未验证，不能由相邻版本构建结果推断。
