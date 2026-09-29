# AuthMe Fabric 发布规范

本项目是 AuthMeReloaded 的 Fabric 衍生移植版。版本号需要同时表达两件事：

1. 本项目所对齐的上游 AuthMeReloaded 版本；
2. 本项目在该上游版本基础上的独立发布序号。

## 版本格式

正式发布使用：

```text
<上游版本>-fabric.<本项目发布序号>
```

开发快照在正式版本后追加 `-SNAPSHOT`：

```text
<上游版本>-fabric.<本项目发布序号>-SNAPSHOT
```

当前版本线：

```text
6.0.1-fabric.2-SNAPSHOT
```

其中：

- `6.0.1` 是本次移植对齐的上游 AuthMeReloaded 基线版本；
- `fabric` 表示本项目的 Fabric 移植发行线；
- `.1` 是本项目基于该上游基线的第一个可发布版本；
- `-SNAPSHOT` 表示开发中，不能作为正式发布版本。

## 版本递进规则

同一个上游版本继续修正时，只递增本项目发布序号：

| 场景 | 版本示例 |
| --- | --- |
| 当前开发版本 | `6.0.1-fabric.1-SNAPSHOT` |
| 首个正式发布 | `6.0.1-fabric.1` |
| 基于同一上游版本的下一次修正 | `6.0.1-fabric.2` |
| 下一次修正的开发版本 | `6.0.1-fabric.3-SNAPSHOT` |
| 改为对齐上游 `6.0.2` | `6.0.2-fabric.1-SNAPSHOT` |

规则如下：

- 不能发布不带后缀的 `6.0.1`；该形式只保留给“上游基线版本”这一语义。
- 同一 `<上游版本>` 下，每次面向用户的新发布都递增 `fabric.N`，从 `1` 开始，不能复用已发布的序号。
- 当项目改为对齐新的上游版本时，替换前三段上游版本号，并将 `N` 重置为 `1`。
- `SNAPSHOT` 只能用于开发态。正式 tag、Release、jar 文件名和 `fabric.mod.json` 中都不能包含 `SNAPSHOT`。
- 六个 Minecraft 覆盖模块共用同一个版本号；模块差异由 jar 名称和兼容的 Minecraft 范围表达，不再追加 `-mid` 或 `-legacy` 到版本号。

## 为什么采用 `-fabric.N`

`6.0.1-fabric.1` 是合法的 SemVer 预发布标识形式，也能被 Fabric Loader 的扩展 SemVer 解析。相比 `6.0.1+fabric.1`，它保留了下游修订号的排序意义：`fabric.2` 明确高于 `fabric.1`。

`+` 后的内容属于 build metadata。按照 SemVer 和 Fabric Loader 的规则，build metadata 不参与版本优先级比较，因此不适合作为本项目连续正式发布的唯一递进依据。`+` 可以留给 CI 构建信息，但不用于发布序号。

需要注意：按 SemVer，`6.0.1-fabric.1` 的优先级低于不带后缀的 `6.0.1`，因为它具有预发布标识。本项目是独立的 Fabric mod，发布和更新应始终在 `authme-fabric` 这条版本线上比较，不能把上游插件的 `6.0.1` 当作本项目的可替代发布物。

## 发布时的唯一版本源

版本唯一写在根目录的 [`gradle.properties`](gradle.properties) 的 `mod_version` 中：

```properties
mod_version=6.0.1-fabric.2-SNAPSHOT
```

不要手动修改六个模块的 `fabric.mod.json` 版本字段；它们的 `${version}` 占位符会由 Gradle 构建时替换。启动日志和 `/authme version` 也必须从 Fabric Loader 的 mod metadata 读取版本，禁止再次写死版本号。

## 正式发布流程

1. 在 `gradle.properties` 中把 `mod_version` 从 `...-SNAPSHOT` 改为待发布的正式版本，例如 `6.0.1-fabric.1`。
2. 更新 release notes，明确写出上游基线版本、Fabric 移植改动、兼容的 Minecraft 范围和数据库兼容性。
3. 执行 `./gradlew clean build`，确认六个 jar、六个 `fabric.mod.json` 和 `/authme version` 显示完全一致的正式版本。
4. 使用同一个版本创建 Git tag 和 Release：

   ```text
   v6.0.1-fabric.1
   ```

5. 发布完成后，把 `mod_version` 推进到下一开发版本，例如 `6.0.1-fabric.2-SNAPSHOT`。

正式产物示例：

```text
authme-fabric-6.0.1-fabric.1.jar
authme-fabric-mid-6.0.1-fabric.1.jar
authme-fabric-legacy-6.0.1-fabric.1.jar
authme-fabric-old-6.0.1-fabric.1.jar
authme-fabric-pre-6.0.1-fabric.1.jar
authme-fabric-older-6.0.1-fabric.1.jar
```

## 参考规范

- [Semantic Versioning 2.0.0](https://semver.org/)
- [Fabric `fabric.mod.json` version and dependency specification](https://docs.fabricmc.net/develop/loader/fabric-mod-json)
