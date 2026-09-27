# NEEDS_SOL_REVIEW

本文件记录最终复核后仍需真实运行环境或产品决策确认的边界。已在本轮落地的代码控制列在前半部分；“本地已修复”不等于第三方组件和生产部署已经验收。

## 已完成但仍需部署验收的整改

### A-02：LuckPerms GroupOptions

`PermissionBridge` 已改为只操作 LuckPerms `transientData`：临时加入目标组、用 transient false inheritance 节点屏蔽当前继承组，恢复时只删除本会话成功添加的节点。API 返回不完整、任一屏蔽节点无法确认生效或发生部分失败时会回滚，不再清空或保存持久用户节点。

仍需在真实 LuckPerms 上验证直接组、继承组、context、用户卸载/重载、崩溃恢复和并发权限修改。验收失败时应保持 `GroupOptions.enablePermissionCheck: false`，不能回退到持久节点快照方案。

### A-04：Paper/Folia 线程边界与 purge

受影响的加入、注册和 purge 路径先在玩家/实体线程捕获玩家名、UUID、地址与权限，异步数据库阶段只使用这些值对象。旧账号 purge 不再在“本页没有 bypass”时回退到脱离候选快照的批量删除；每个候选会再次检查当前运行时会话，并在数据库条件删除中复核活动时间、密码/盐/邮箱/TOTP/Premium/UUID 身份快照、`isLogged` 与有效登录租约，只有实际删除成功的账号才清理关联文件。

仍需真实 Paper/Folia/Spigot 验证区域线程检测、玩家在 purge 查询与删除之间加入/认证、在线 bypass 和多实例同时登录的竞态。外部实例若不实现 AuthMe 登录租约，`isLogged` 是最后一道兼容保护，因此生产清理前仍应备份。

### A-06：代理 Premium 冷启动

Velocity/Bungee 在 `PreLogin` 阶段直接查询共享 AuthMe 账户表的只读 Premium 目录；代理冷启动不依赖 plugin message 快照。查询或数据库不可用时 fail closed，Premium 用户强制 online mode。远程代理数据库账号应只有账户表所需列的 `SELECT` 权限。

仍需覆盖“代理重启后首个 Premium 同名连接”、数据库中断/恢复、正版与非正版同名、Velocity/Bungee forwarding 的黑盒测试。

### A-07：跨实例登录与失败状态

数据库 schema v3 新增共享登录租约与失败状态表。登录在数据库全局协调锁和事务内完成 IP 配额、单调 fencing version、账户状态与 30 秒可续期租约写入；运行时每 5 秒续租，旧实例检测到 fence 被替换后断开，正常退出只清理自己持有的版本，崩溃遗留租约会过期。密码/TOTP 失败使用“账号+来源”和“来源”双共享桶：前者驱动该账号的尝试/CAPTCHA，后者阻断跨账号爆破；成功认证只清前者，不能由同 NAT 的另一个有效账号清空全地址记录。

仍需用至少两个真实实例验证并发登录、崩溃、网络分区、数据库主从切换、时钟偏差与 NAT 多账号压力。生产节点应保持时间同步；测试必须确认 30 秒过期恢复不会造成长期 IP 配额占用。

### A-13：代理信任域

代理现在把物理 server name 映射到固定 `backendId` 和独立 HMAC 密钥，解析前按实际来源选择密钥，解析后再核对签名中的身份。多认证服缺少任一显式凭据会拒绝启动，`allServersAreAuthServers` 被拒绝；单认证服仅保留可安全映射的旧配置兼容。

仍需真实 Velocity/Bungee 双端验证错误密钥、错误 backendId、重放、分片乱序和后端被攻陷后的隔离范围。每个认证服必须使用不同随机密钥。

### A-14：数据库迁移权限边界

schema v3 使用 `<table>_schema_history` dirty/success 标记、幂等迁移和远程数据库 advisory migration lock。远程数据库 `schemaManagement: AUTO` 等价于 `VALIDATE`，不会在普通启动/重载执行 DDL；升级时必须由单独 DDL principal 显式运行一次 `MIGRATE`，随后切回最小 DML principal。SQLite 保持首次启动自动迁移。

仍需在 MySQL/MariaDB/PostgreSQL 上验证从旧表升级、DDL 中途故障后重入、并发启动和回滚备份。迁移前必须做数据库原生备份；不能把 SQL 文本备份当作厂商级热备。

### A-15：供应链

本地工作流已把 GitHub Actions 固定到完整提交 SHA，Fabric Loom 固定到 `1.17.20`，Gradle wrapper 配置官方分发 SHA-256。依赖校验元数据覆盖构建实际解析的上游制品；只豁免 Loom 在本机由已校验输入生成、且缓存重建后字节不稳定的 synthetic mappings/remapped/merged JAR 坐标。版本、上游制品或豁免范围发生变化时必须通过审查后显式更新。

远端 CI 结果、漏洞库结果、SBOM 发布、制品签名和发布平台权限仍只能在正式流水线确认。工作树中的新模块、文档和 `.github/workflows/security.yml` 也必须在发布提交中被 Git 跟踪；本轮不会擅自替用户暂存或提交整个脏工作树。

## 仍需产品/架构决策

### A-12：兼容配置与平台行为契约

`Hooks.bungeecord` 在 Paper/Folia/Spigot 入口仍没有与 Fabric 完全相同的代理传输语义；`Hooks.displayname`、`databaseCacheEnabled`、`eventCommandsFile`、`registerTimeout` 等公开 accessor 也可能属于外部配置兼容面。删除、弃用或补齐行为需要发布兼容策略和逐键 contract tests，不能凭“当前消费者少”直接移除。

`limbo.recreateEnderPearls` 不是全局死配置：modern、mid、legacy Fabric 均消费它；Bukkit-family 没有等价实现属于平台覆盖差异。

### A-16：重复状态机收敛

Fabric 多版本、Paper/Folia/Spigot 与代理仍存在重复认证适配。当前关键安全路径已有共享数据源协议和 self-test，但大规模合并仍会触及映射版本、线程模型与网络协议。下一步应先建立跨平台登录/Session/TOTP/失败限制/代理 contract tests，再逐步把纯状态转换下沉到共享核心；不应在安全整改尾声进行无验证的大重构。

## 未运行的真实环境验收

以下结果不能由本地编译或 self-test 替代：

1. MySQL/MariaDB/PostgreSQL TLS 证书正反例、迁移 principal、双实例事务/租约/失败桶与断线恢复；
2. LuckPerms transient 继承、context、重载、崩溃恢复和并发权限修改；
3. Paper/Folia/Spigot 事件线程、purge 在线 bypass 与真实插件兼容；
4. Velocity/Bungee 冷启动 Premium、forwarding、切服、错误凭据与重放；
5. 真实 SMTP、玩家客户端、远端 CI、漏洞扫描、SBOM 与制品签名。
