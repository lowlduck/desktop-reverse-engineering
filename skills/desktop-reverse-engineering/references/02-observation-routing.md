# 02 · 侦察、观测点选择与通道判定

## 前 30 分钟做什么（不做任何 hook）

| # | 动作 | 要拿到的东西 |
|---|---|---|
| 1 | 列进程 + **完整命令行** | `--user-data-dir`（profile 位置）、`--*-local-root-path`（前端资源，常常是明文）、IPC 通道名、设备标识、`--extra-cmd=<hex>`（说明有参数过滤） |
| 2 | 模块导入表，**递归看依赖链** | 自研 HTTP DLL、libcurl、OpenSSL、winhttp；不要只看一层 |
| 3 | 找日志目录与格式 | 明文？加密？文件名规律？ |
| 4 | 找前端资源目录 | JS 是否打包/加密 |
| 5 | 找本地数据库 | SQLite / SQLCipher |
| 6 | 探测壳与完整性校验 | `.vmp0` 段、`VMProtect/Themida` 字符串、`digital_sign/md5checker/sentinel` |
| 7 | 判架构 | CEF / Electron / 原生 / Flutter / RN |

```powershell
# 命令行（PowerShell 7 用 CIM，Get-WmiObject 已移除）
Get-CimInstance Win32_Process | Where-Object { $_.Name -match 'KEYWORD' } |
    Select-Object ProcessId, CommandLine | Format-List
```

```python
# 递归看导入：先拿一层，再顺着自研 DLL 继续
import pefile, glob, os
KEYS = ('curl', 'winhttp', 'wininet', 'ws2_32', 'ssl', 'crypt', 'request', 'network')
def imports(p):
    pe = pefile.PE(p, fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
    out = [e.dll.decode(errors='ignore').lower() for e in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', [])]
    pe.close(); return out
for f in glob.glob(r'<INSTALL_DIR>\*.dll'):
    hit = [d for d in imports(f) if any(k in d for k in KEYS)]
    if hit: print(os.path.basename(f), '->', hit)
```

判据：只看到 `WS2_32.WSAStartup` 不代表不用网络——真正的 HTTP 可能由 `XXXRequest.dll` 转发，而它又 import 了 `libcurl.dll`。**必须递归。**

## 三层两通道

```
UI / 前端（CEF 页面、原生 Qt/DuiLib）
        │ 原生桥（pinbridge / cefQuery / window.chrome / IPC）
业务 SDK（构造业务 JSON、算签名）
        │ 内部 API
网络层（libcurl / winhttp / 自研库）
        │
   ─────┴───── 网络
旁路 A：日志函数 → 明文入参          ★★★★★
旁路 B：本地数据库 / 内存字符串 / 缓存  ★★★
```

钩子点选择：前端看 CDP 与 bundle；业务层看导出/虚函数；网络层看 setopt / SSL_write / vtable。

## 观测点性价比（按顺序试，别倒过来）

| 观测点 | 能拿到 | 相对成本 |
|---|---|---|
| 日志函数 | URL + Body + 响应 + 错误码 | 低（一次全拿） |
| 前端 bundle 静态读 | 参数、枚举、签名实现 | 低 |
| CDP（Network / Runtime） | 请求、WS 帧、页面内部函数 | 中（先要能开 DevTools） |
| 自研 HTTP 层 vtable | URL + Body | 中（覆盖可能不全） |
| libcurl / SSL_write hook | 明文请求 | 中（只覆盖走该库的流量） |
| 内存扫描 | 凭据、构造好的请求体 | 中高（时序敏感） |
| 系统代理 / mitmproxy | — | 对 CEF 系基本为零（硬编码忽略系统代理） |

「装根证书 + 抓包」在 Chromium 定制客户端上常常整套失效；遇到一次就整条路线排除，不要在证书上反复折腾。

## 按证据辨通道

| 候选通道 | 可观察信息 | 仍需验证 |
|---|---|---|
| HTTP/HTTPS | 方法、路由模板、状态码、请求/响应关联 | 认证依赖、异步完成、分页与错误语义 |
| WebSocket | 握手、子协议、帧方向与事件 | 帧与业务消息的关系、心跳、断线续订 |
| TCP | 连接生命周期、读写数据、时序 | framing、字节序、拆包粘包、关联 ID |
| UDP | 数据报边界、源/目的、序号 | 丢包/乱序/重复、应用层确认、重组 |
| IPC/RPC | 管道、Unix socket、COM/RPC、共享内存 | 权限、锁、句柄生命周期、进程重启 |
| 文件/数据库 | 副本 schema、变更、事务 | 变化是否等于业务完成，缓存/锁一致性 |

**通道判定法（最快的一条）：**

```
日志里有 `request parameter, <url>, <body>`  → 该功能走 HTTP
HTTP 的 send 端点怎么调都停在「参数错误 / 业务拒绝」
且二进制字符串表里没有「按目标 ID 发该类型」的端点
                                              → 换长连接（WS / 自定义 socket）
长连接建起来但类型不匹配                    → 该类型可能并不走这条连接
```

同一个应用里，**文本、卡片、文件、实时事件可能走不同通道**。不要因为文本走通了就假定附件也走同一条。

## 观测约束

- 优先用现有诊断、开发接口或测试构建；观测点覆盖范围要记录（「漏掉了哪些路径」本身是结论）。
- 观测可能改变行为：日志函数即使返回 void，也可能涉及锁、状态、审计与时序。量化开销与丢事件情况，别让观测变成被测对象的一部分。
- 修改要可恢复，原始样本与派生产物分开目录。
- 未开放的调试能力，记录条件并停止该候选路径，换观测点，而不是在同一个点上换工具重试。
