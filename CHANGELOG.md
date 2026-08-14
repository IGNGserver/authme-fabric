# Changelog

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

- 1.16.5–1.19.3 移植不包含在本发行版中。
- MySQL/MariaDB/PostgreSQL、SMTP、LuckPerms 和代理双端联调仍需在使用方的实际基础设施中进行部署级验证。
