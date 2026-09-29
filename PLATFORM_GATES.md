# Fabric 兼容线开发与发布门槛

本仓库只发布 Fabric 服务端模组。六条 Fabric 兼容线共用 `authme-core`，每条线必须按自己的 Minecraft/Fabric API 依赖单独编译和检查；归档的原生平台模块不再作为发布门槛。

## 活动兼容线

`authme-fabric`（1.21.11）、`authme-fabric-mid`（1.20.5–1.21.10）、`authme-fabric-legacy`（1.19.4–1.20.4）、`authme-fabric-old`（1.19.3）、`authme-fabric-pre`（1.19.2）、`authme-fabric-older`（1.18.2）。

## 本地门槛

1. `bash ./scripts/check-fabric-scope.sh` 通过，确认活动构建图和源代码没有原生非-Fabric平台引用；
2. `./gradlew build` 通过，包含六条 Fabric 线和 `authme-core`；
3. 核心配置、认证、数据源、邮件和外部数据库兼容性自测通过；
4. `git diff --check` 通过；
5. 产物只从六个 Fabric 模组的 `build/libs/` 目录发布。

## 部署门槛

本地门槛通过后，仍需在目标环境完成：

- 每条声明版本线的真实服务端启动、登录/注册、未登录保护和断线恢复；
- 真实客户端对 1.21.11 对话框、旧线聊天回退、locale 和命令补全的验收；
- SQLite 之外的 MySQL/MariaDB/PostgreSQL 连接、TLS、迁移、故障和并发验收；
- LuckPerms transient 权限、SMTP 投递、Premium 在线模式和外部代理跨服链路验收；
- 多实例、恶意输入、重放、断线、重启及长时间运行压力验收。

构建通过只能记为 `PASS（本地构建）`；未运行的客户端、数据库、代理或第三方服务验收必须记为 `NOT RUN`，不能写成“平台支持已完成”。
