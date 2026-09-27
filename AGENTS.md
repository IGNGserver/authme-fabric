# 插件移植 authme（authme-fabric）· 项目 Agent 规范
> 只写本仓库与设备级规范的差异。Git 纪律、worktree、冲突处理见 `~/.qoder/coder-rules/global-rules.md`。

Collaboration: solo（**移植仓库**：改动必须可反复 rebase 到上游）
Default branch: main
Integration: direct-after-validation
Release: 按仓库根 `RELEASE.md`（100 行，权威）
Worktree: `~/项目/.wt/authme/<slug>`

## 这是什么
AuthMe Fabric 的上游移植分支。历史里有"Merge AuthMe Fabric 6.0.1-fabric.1 release branch"这类**上游合入**提交。

## 移植纪律（本仓库的核心约束）
- 每个本地改动都要能被反复 rebase 到上游新版本：优先最小补丁式改动，**不得**大面积重排上游代码，否则下次同步上游不可维护。
- 上游合入按设备级规范做语义合并，禁止 `--ours` / `--theirs` 选边；判断不了上游与本地改动的意图时停下来问。
- 提交信息必须区分"本地改动"与"上游合入"，两类不得混在同一个提交里。

## 验证命令
- `./gradlew test`、`./gradlew build`，以 `ci.yml` 复核。未实测跑通时如实报告缺口。

## 现状（必须先处理再开发）
- 工作区有 **174 个未提交文件**。Agent 进入本仓库先报告，不得 stash / reset / clean；新任务从 `origin/main` 另建 worktree，让这 174 个文件留在原地等你处置。
