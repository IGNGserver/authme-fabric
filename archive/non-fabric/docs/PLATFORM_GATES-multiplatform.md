# AuthMeReloaded 平台开发门槛

本项目的“全量完成”不是把同一份 Fabric JAR 复制到其他平台，而是每个平台分别通过认证、限制、事件和网络身份验收。下面是剩余工作的工程化拆分。

## 阶段 A：Fabric 当前支持线

状态：代码与本地门槛已完成；仍需要部署级验收。1.21.11、mid、legacy 三条较新 Fabric 线已到 `AuthMe ready/protecting`；1.19.3、1.19.2、1.18.2 线已通过 Loader/Mixin/专用入口检查，但保留的 EULA 状态未允许服务继续初始化。

- 1.21.11、1.20.5–1.21.10、1.19.4–1.20.4、1.19.3、1.19.2 和 1.18.2 六个 Loom 模块；
- 共用 `authme-core` 的哈希、数据库、邮箱、代理协议和安全策略；
- 玩家/管理命令、未登录沙箱、Session、TOTP、Premium、转换器和备份；
- 输入长度、HMAC 重放、异步会话、权限 fail-closed 和数据库故障边界；
- 构建、核心自测和六条线启动期冒烟；旧两条线额外使用独立 API/文本/网络兼容边界。

完成判据：本地门槛通过，并在真实客户端、LuckPerms、SMTP、外部 SQL 和代理环境中完成 `SECURITY.md` 的部署门槛；当前本地代码门槛通过，部署级判据仍未完成。

## 阶段 B：原生 Velocity/BungeeCord

状态：代码实现完成，真实代理黑盒验收未完成。

实施顺序：

1. `authme-proxy-core` 已提供共享配置模型、HMAC/重放策略、玩家认证状态机和无平台代理编解码；
2. `authme-velocity` 已使用 Velocity 事件、命令、连接和 plugin-message API；
3. `authme-bungee` 已使用 BungeeCord/Waterfall 事件、命令、连接和 plugin-message API；
4. 实现认证服务器列表、未认证服务器切换、登录后目标服务器、登出回退、配置热重载和安全随机共享密钥；
5. 用离线代理 + 两台后端、在线代理、跨服切换、伪造 Payload、重放包和代理重启做黑盒验收。

完成判据：两个原生插件可独立打包，不能依赖 Fabric Loader；本地协议自测已通过，但代理配置、跨服身份和后端 `perform.login` 的真实双向测试仍未通过。

## 阶段 C：Bukkit/Paper/Folia

状态：基础适配已实现，主要认证与维护路径已补齐；完整 AuthMeReloaded 功能齐平和真实服务器验收未完成。

实施顺序：

1. `authme-platform-core` 已抽取数据库/哈希/注册/登录/注销/改密/TOTP、邮箱/恢复、CAPTCHA 和 Premium 服务，明确异步数据库和结果边界；
2. `authme-paper` 已覆盖 Pre-Login/Join、基础保护、官方主要命令树与 help、TOTP、邮箱/恢复、CAPTCHA、Premium、GroupOptions、Limbo、单会话、延迟加入消息、自动备份/清理和 purge 文件安全边界；Paper/Folia 原生 Pre-Join Dialog 已做成默认关闭的可选路径，但仍需真实客户端/代理验收；PacketEvents 可选能力、LuckPerms、PlaceholderAPI、Citizens 和 CombatTag 尚未齐平；
3. `authme-folia` 已使用实体/异步/全局调度器，未把 Paper 主线程调度器直接用于玩家回调；仍需真实 Folia 区域线程验收；
4. `authme-spigot-legacy` 已按 1.16.5 API 独立编译基础认证/保护；旧版本完整 AuthMe 命令树和扩展集成尚未完成；
5. 用 AuthMeReloaded 官方命令、权限、配置和事件测试集做兼容验收。

完成判据：每个平台独立 JAR、独立依赖锁定、独立运行测试，且不把基础适配误报为完整 Bukkit drop-in 兼容；当前完成独立编译和平台核心自测，真实 Paper/Folia/Spigot 服务器仍未验收。

## 阶段 D：完整集成和发布

状态：未完成。

- GeoIP/MaxMind 自动下载、OAuth2 邮件、真实 SMTP 和数据库矩阵；
- 外部插件集成及其缺失时的安全降级；
- 依赖漏洞扫描、SBOM、制品签名、升级回归和独立安全审计；
- 更新 `FEATURE_MATRIX.md`，只有黑盒验收通过的条目才能从“部分/未验证”改成“已实现”。
