# AuthMe Fabric 开发规范

## 项目范围

本仓库只负责 AuthMe 的 Fabric 服务端开发和发布，不负责 Paper、Bukkit、Spigot、Folia、Velocity 或 BungeeCord 原生插件。

活动工程由以下模块组成：

- `authme-core`：被 Fabric 制品内嵌的纯 Java 认证、数据库、哈希、TOTP、邮件、文件安全和协议核心。
- `authme-fabric`：Minecraft 1.21.11。
- `authme-fabric-mid`：Minecraft 1.20.5–1.21.10。
- `authme-fabric-legacy`：Minecraft 1.19.4–1.20.4。
- `authme-fabric-old`：Minecraft 1.19.3。
- `authme-fabric-pre`：Minecraft 1.19.2。
- `authme-fabric-older`：Minecraft 1.18.2。

Fabric 端可以继续通过 BungeeCord/Velocity 兼容协议与外部代理互操作，也可以与外部 AuthMe 实例共享账户数据库；这表示 Fabric 端的兼容能力，不表示本仓库维护对应的原生代理或 Bukkit-family 插件。

## 活动代码边界

活动源码不得引入或新增以下平台 API、入口描述或原生插件模块：

- Bukkit/Paper/Folia/Spigot：`org.bukkit`、`io.papermc`、`dev.folia`、`plugin.yml`；
- Velocity/BungeeCord：`com.velocitypowered`、`net.md-5`、`bungee.yml`；
- `io.github.authme.platform.*` 和 `io.github.authme.proxy.*` 原生平台实现。

Fabric 侧的 `ProxyBridge`、`ProxyProtocol`、`ProxyMessageSink`、`BungeeConnectPayload` 属于活动 Fabric 功能，不能因为协议名称包含 Bungee/Velocity 就移入归档。

## 非 Fabric 代码

非 Fabric 实验、移植或修复必须放在 `archive/non-fabric/` 或独立仓库，不得加入根 `settings.gradle`，也不得进入 Fabric 发布制品。归档目录不是活动 Gradle 子项目；重新启用前必须重新审计线程模型、权限边界、代理信任和依赖校验。

新增共享核心代码前，必须确认至少有一个活动 Fabric 模块的真实调用者。仅被归档平台使用的工厂、配置键、测试和适配器应留在归档范围，不应为了保留旧代码而污染活动核心。

## 提交前门槛

在本地修改后执行：

```bash
bash ./scripts/check-fabric-scope.sh
env -u CODEX_HOME GRADLE_OPTS='-Xmx4g -XX:MaxMetaspaceSize=768m' \
  bash ./gradlew --no-daemon --max-workers=1 \
  :authme-core:configSelfTest \
  :authme-core:coreSelfTest \
  :authme-core:dataSourceSelfTest \
  :authme-core:mailSelfTest \
  :authme-core:externalDbSelfTest \
  build
git diff --check
```

六条 Fabric 线都必须参与构建。构建、JAR 完整性或静态扫描不能替代真实客户端、外部数据库、SMTP、LuckPerms、代理和长时间运行验收；报告结果时必须分别标记 `PASS`、`FAIL` 或 `NOT RUN`。

## 工作树纪律

修改前先检查 `git status`。不得使用 `git reset --hard`、`git clean` 或覆盖他人未提交的文件；不得使用 `git add .`，只应暂存本次任务涉及的路径。生成的 `build/`、服务器运行目录和本地测试临时文件不属于源码归档。
