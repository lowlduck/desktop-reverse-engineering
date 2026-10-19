# Desktop Reverse Engineering Skill

中文为主、保留英文技术术语的团队技能包。目标是把桌面应用功能研究为**稳定、高复用、可编程的功能调用接口**，不限 HTTP，也覆盖 WebSocket、TCP、UDP、IPC 和内部函数调用。

这是按需加载的工作方法与验证模板，不是现成客户端 SDK，也不自动授予工具、MCP 或系统权限。

## 核心原则

- T1：脱离客户端独立调用，优先考虑但不强求。
- T2：客户端运行时直接调用业务函数/内部服务，满足工程验收也可正式交付。
- 分析阶段可以使用 UI；最终交付禁止 UI 自动化，包括通过 CDP 执行点击或 UI 事件。
- 内部函数地址、签名、ABI、对象布局可能比底层算法更频繁变化；没有“几乎零维护”的通用路线，按版本实测。
- 不局限无状态、全自动认证或所有内容类型；明确支持范围、登录前置条件和状态生命周期。

## 内容结构

```text
skills/desktop-reverse-engineering/
├── SKILL.md                     精简入口、执行顺序与参考索引
├── references/                 目标证据、观测定位、协议、T2、可靠性
└── templates/                  研究记录、接口契约、验证矩阵
```

入口见 [SKILL.md](skills/desktop-reverse-engineering/SKILL.md)。详细文档按需读取，不需每次全量加载。

## 获取与更新

当前仓库为私有，团队成员须先由仓库所有者邀请并接受访问授权。

```sh
git clone https://github.com/lowlduck/desktop-reverse-engineering.git
cd desktop-reverse-engineering
# 更新前先保存本地修改
git pull --ff-only
```

也可在 GitHub 下载 ZIP。Git 更新的是仓库副本；如果采用复制安装，还需重新同步技能目录。

## 安装到支持文件型 Skill 的宿主

完整复制 `skills/desktop-reverse-engineering` 文件夹到宿主实际扫描的技能根目录，保留 SKILL.md、references 和 templates 的相对结构。

常见位置包括 `$DSH_HOME/skills`、项目 `.agents/skills` 或宿主自定义技能根，**这些位置不保证对所有平台自动生效**。先查宿主配置；例如 DSH 的 `skill-filesystem.customSkillDirs` 与 `includeDefaultRoots` 会影响发现范围。不要猜测 DSH_HOME，也不要把资料放进应用安装目录或任意插件的 node_modules。

PowerShell 复制示例（仅在已确认环境变量指向正确技能根时执行）：

```powershell
if (-not $env:DSH_HOME) { throw '请先确认实际 DSH_HOME' }
$skillRoot = Join-Path $env:DSH_HOME 'skills'
$destination = Join-Path $skillRoot 'desktop-reverse-engineering'
if (Test-Path $destination) { throw '目标已存在，请先备份并检查差异再更新' }
New-Item -ItemType Directory -Force $skillRoot | Out-Null
Copy-Item './skills/desktop-reverse-engineering' $destination -Recurse
```

完成后按宿主要求刷新技能目录或开启新会话，在目录中确认名称 `desktop-reverse-engineering` 并实际加载。不要假定复制文件或 `git pull` 会让当前会话热更新。未发现时先核对扫描路径和配置，而不是重复安装。

可使用宿主支持的自定义扫描根指向本仓库的 `skills`，减少重复复制；是否支持链接目录及热加载需另行验证。本包不修改宿主配置、不安装 MCP、不附带插件注册代码。

## 使用

向支持 skill 工具的助手提出：

> 加载 desktop-reverse-engineering，研究 APP 的 FEATURE，最终交付稳定、可复用的功能接口。允许客户端运行，禁止最终使用 UI 自动化。先建立研究记录与可验证的成功标准。

研究记录放到各自项目工作区，勿把真实研究证据、凭据和客户数据提交回技能仓库。模板初始状态全部为未测试。

## 团队协作与检查

通过分支和 PR 修改方法论。提交时写明结论适用版本、证据范围及未验证部分。新建议不因写入本仓库就成为已实测事实。

发布前检查 Markdown 相对链接、frontmatter、占位数据、个人绝对路径、Token/私钥、日志及真实业务资料。`.gitignore` 只是减少误提交，不代替审查。工具和真实目标兼容性需团队在各自环境验证。

本仓库未指定开源许可证；当前用于获准成员的内部协作。如需公开分发，应由所有者先确定许可证与公开内容范围。
