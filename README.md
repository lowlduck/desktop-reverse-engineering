# Desktop Reverse Engineering Skill

中文为主、保留英文技术术语的团队技能包。目标是把桌面应用的一个功能研究成**稳定、高复用、可编程的功能接口**——不限 HTTP，也覆盖 WebSocket、TCP、UDP、IPC 与客户端内部函数调用。

这是按需加载的**工作方法与验证模板**，不是现成 SDK，也不自动授予工具或系统权限。

## 核心原则

- **先观测，后推理**：别猜参数、别猜通道；一次只改一个变量，保留空对照。
- **受理 ≠ 完成**：HTTP 200、函数返回 true、界面上屏都只是受理，必须有第二份业务证据。
- **先日志，后网络**：日志函数通常没有反调试保护，入参是明文（只有落盘文件才加密）。
- **壳先分类再决定**：压缩壳/加密壳可脱；虚拟化壳不破，改边界观察或「调而不破」。
- **T1 优先但不强求**；T2（客户端运行时直接调业务函数）通过工程验收即合格交付。
- **维护成本必须实测**：算法稳定 ≠ T1 低维护（认证/风控常变）；内部函数布局也未必稳定。两者都按版本回归工时比较。
- **时间盒**：单路线 45 分钟 / 3 次失败即换路线，失败连同错误码写入「已排除」。
- 最终交付禁止 UI 自动化（含通过 CDP 派发点击或 UI 事件）。分析阶段可用 UI 建立基准。

## 内容结构

```text
skills/desktop-reverse-engineering/
├── SKILL.md                 入口：交付定义、开工顺序、症状路由、硬规则
├── references/
│   ├── 01-goals-evidence.md      交付等级、路线优先级、壳四分类、时间盒、证据标签
│   ├── 02-observation-routing.md 30 分钟侦察、三层两通道、观测点性价比、通道判定
│   ├── 03-protocol-contract.md   接口契约、各传输要点、WS 落地五步、T1 独立性试验
│   ├── 04-internal-call-adapters.md T2：调而不破、ABI/对象/线程/版本适配
│   ├── 05-reliability-acceptance.md 验收矩阵、重试与副作用、交付形态、清理回滚
│   ├── 06-credentials-session.md 凭据三级判定、内存取票、生命周期、掉线归因、限速
│   ├── 07-param-recovery.md      前端三路径、信封与枚举、错误码分层、签名策略
│   ├── 08-context-budget.md      上下文预算、研究记录纪律、压缩后恢复
│   └── 09-pitfalls.md            方向性/操作级陷阱、结构性排除、Windows 工具链坑
└── templates/
    ├── research-record.md     研究记录（含时间盒、已排除、归因表）
    ├── interface-contract.md  接口契约
    └── validation-matrix.md   验证矩阵
```

入口见 [SKILL.md](skills/desktop-reverse-engineering/SKILL.md)。详细文档按需读取，不必每次全量加载 —— 这也是这套结构存在的原因：完整方法论文档很长，而 AI 的上下文预算要留给真实证据。

## 获取与更新

```sh
git clone https://github.com/lowlduck/desktop-reverse-engineering.git
cd desktop-reverse-engineering
# 更新前先保存本地修改
git pull --ff-only
```

若仓库为私有，团队成员需先由所有者邀请并获得访问授权。也可在 GitHub 下载 ZIP。Git 更新的是仓库副本；若采用复制安装，还需重新同步技能目录。

## 安装到支持文件型 Skill 的宿主

完整复制 `skills/desktop-reverse-engineering` 文件夹到宿主实际扫描的技能根目录，保留 `SKILL.md`、`references`、`templates` 的相对结构。

常见位置包括 `$DSH_HOME/skills`、项目 `.agents/skills` 或宿主自定义技能根，**这些位置不保证对所有平台自动生效**。先查宿主配置；例如 DSH 的 `skill-filesystem.customSkillDirs` 与 `includeDefaultRoots` 会影响发现范围。不要猜测 DSH_HOME，也不要把资料放进应用安装目录或插件的 node_modules。

```powershell
if (-not $env:DSH_HOME) { throw '请先确认实际 DSH_HOME' }
$skillRoot = Join-Path $env:DSH_HOME 'skills'
$destination = Join-Path $skillRoot 'desktop-reverse-engineering'
if (Test-Path $destination) { throw '目标已存在，请先备份并检查差异再更新' }
New-Item -ItemType Directory -Force $skillRoot | Out-Null
Copy-Item './skills/desktop-reverse-engineering' $destination -Recurse
```

完成后按宿主要求刷新技能目录或开启新会话，在目录中确认名称 `desktop-reverse-engineering` 并实际加载。不要假定复制文件或 `git pull` 会让当前会话热更新。

## 使用

向支持 skill 工具的助手提出：

> 加载 desktop-reverse-engineering，研究 APP 的 FEATURE，最终交付稳定、可复用的功能接口。允许客户端运行，禁止最终使用 UI 自动化。先建立研究记录与可验证的成功标准。

更有效的问法（给出起点，省一轮侦察）：

> 加载 desktop-reverse-engineering。目标 APP 装在 `INSTALL_DIR`，平台 Windows，进程名 `PROC`。要复现 FEATURE，我已有自己的测试账号和一个测试目标对象。先做 30 分钟侦察：判通道、判壳、找日志与前端资源，再决定 T1 还是 T2。

研究记录放到各自项目工作区，勿把真实证据、凭据和客户数据提交回技能仓库。模板初始状态全部为未测试。

## 团队协作与检查

通过分支和 PR 修改方法论。提交时写明**结论适用版本、证据范围及未验证部分**——新建议不因写入本仓库就成为已实测事实。

发布前检查 Markdown 相对链接、frontmatter、占位数据、个人绝对路径、Token/私钥、日志及真实业务资料。`.gitignore` 只是减少误提交，不代替审查。工具与目标兼容性需团队在各自环境验证。

## 变更记录

| 日期 | 变更 |
|---|---|
| 2026-10-16 | 初版：T0–T2 分级、证据标签、观测路由、协议契约、T2 适配、验收模板 |
| 2026-10-20 | 同步实战：新增 06 凭据与会话（三级判定 / 内存取票 / 掉线归因）、07 参数还原（前端三路径 / 信封 / 错误码分层）、08 上下文预算、09 陷阱与工具链；01 补路线优先级与壳四分类、时间盒熔断；02 补观测点性价比与通道判定；03 补 WS 落地五步；05 补交付形态与回滚 manifest；研究记录模板补时间盒、已排除、归因表 |

本仓库未指定开源许可证；当前用于获准成员的内部协作。如需公开分发，应由所有者先确定许可证与公开内容范围。
