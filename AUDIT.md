# AuthMe Fabric 范围审计

审计日期：2026-08-30  
审计对象：当前工作树及本次归档后的构建图  
审计性质：范围与边界审计；不把本地构建结果扩大解释为真实服务器验收

## 1. 结论

本仓库的活动开发范围已经收敛为 Fabric 服务端模组：一个纯 Java `authme-core` 和六条 Fabric/Minecraft 兼容线。Paper、Bukkit、Spigot、Folia、Velocity、BungeeCord 原生适配代码已移至 [`archive/non-fabric/`](archive/non-fabric/)，不再由根目录 Gradle 构建图管理。

Fabric 侧仍保留与外部代理互操作所需的 `ProxyBridge`、`ProxyProtocol`、`ProxyMessageSink`、`BungeeConnectPayload` 等代码。这些是 Fabric 模组中的协议客户端/桥接能力，不代表仓库继续维护原生代理插件。

## 2. 活动代码范围

根目录 `settings.gradle` 当前只包含：

- `authme-core`：纯 Java 核心，负责配置、认证策略、哈希、数据源、转换器、邮件、TOTP 和安全策略；
- `authme-fabric`：1.21.11；
- `authme-fabric-mid`：1.20.5–1.21.10；
- `authme-fabric-legacy`：1.19.4–1.20.4；
- `authme-fabric-old`：1.19.3；
- `authme-fabric-pre`：1.19.2；
- `authme-fabric-older`：1.18.2。

活动源代码不应出现 Bukkit/Paper/Folia/Velocity/BungeeCord 原生 API、原生插件描述符或这些平台的专属包名。范围检查由 [`scripts/check-fabric-scope.sh`](scripts/check-fabric-scope.sh) 固化。

## 3. 归档内容

以下模块的源码和构建描述已保存在 `archive/non-fabric/modules/`：

`authme-paper-common`、`authme-paper`、`authme-folia`、`authme-spigot-legacy`、`authme-platform-core`、`authme-proxy-core`、`authme-velocity`、`authme-bungee`。

只被上述原生模块使用的 `ReadOnlyDataSources` 已保存到 `archive/non-fabric/shared/`。混合文档和本次调整前的配置/核心源码快照也保存在 `archive/non-fabric/docs/` 与 `archive/non-fabric/shared/`，用于追溯，不参与活动构建。

## 4. 仍需验证的事实

- `check-fabric-scope.sh` 只能证明活动树没有越界引用，不能证明游戏内行为完整；
- Gradle 构建和核心自测只能证明编译、静态检查及可自动化的核心路径；
- 真实客户端、各 Minecraft 版本完整启动、LuckPerms、SMTP、MySQL/MariaDB/PostgreSQL、外部代理跨服和长时间压力仍需目标环境验收；
- 归档代码不再接受本仓库的常规修复。若未来恢复某段代码，必须先确认它是 Fabric 活动代码还是外部项目职责，并重新通过范围检查。

## 5. 后续审计规则

后续审计先从 `settings.gradle`、实际入口、数据源调用链和生命周期调用者开始追踪；不能因为配置键、历史文档或协议名称中出现某个平台，就把该平台判定为本仓库的活动实现。
