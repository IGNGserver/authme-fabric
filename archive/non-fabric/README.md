# 非 Fabric 代码归档

本目录保存 2026-08-30 前工作树中已经实现、但不属于 AuthMe Fabric 活动开发范围的代码和多平台资料。

## 归档模块

- `modules/authme-platform-core`：Bukkit-family 共用认证服务。
- `modules/authme-paper-common`：Paper/Folia 事件、命令、Dialog 和调度适配。
- `modules/authme-paper`：Paper 插件入口。
- `modules/authme-folia`：Folia 插件入口。
- `modules/authme-spigot-legacy`：旧版 Spigot 插件入口和运行时。
- `modules/authme-proxy-core`：原生代理共用核心。
- `modules/authme-velocity`：原生 Velocity 插件。
- `modules/authme-bungee`：原生 BungeeCord/Waterfall 插件。

归档保留源码、测试、资源和 Gradle 构建描述；各模块已经生成的 `build/` 输出和 Paper 测试服务器运行目录没有纳入归档，可按需重新生成。

## 共享代码快照

`shared/authme-core/` 保存归档前的多平台专用核心文件和配置快照。活动 `authme-core` 仍保留 Fabric 认证、数据库、哈希、TOTP、文件安全以及 Fabric 侧代理 Payload 所需的代码。

## 恢复说明

本目录不属于根 Gradle 工程，不能直接参与活动构建。若未来重新启用某个平台，需要将对应模块恢复到仓库根目录，在 `settings.gradle` 重新加入项目，并按模块构建脚本恢复 `authme-core`、平台核心和代理核心的项目依赖；恢复前应重新审计线程模型、认证状态、代理信任边界和依赖校验。

Fabric 模块中的 BungeeCord/Velocity 兼容只表示 Fabric 端的代理消息互操作，仍属于活动 Fabric 功能，不应从本归档目录恢复或删除。
