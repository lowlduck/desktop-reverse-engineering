# 06 · 凭据与会话生命周期

> 先确认目标操作的认证来源及生命周期，再决定是否采集。只获取用户授权实例与功能需要的材料；静态定位和离线解析可在没有登录态时推进。

## 会话代次与冻结材料

把业务请求密钥、业务响应密钥、传输 secret/ticket、包头 cookie、分页 cookie、设备状态分开记录；相似长度或相同账号不证明可互换。绑定采集时间、登录代次、进程创建时间、模块构建和真实请求/响应证据。

同一已验证会话的材料可以在限定范围内复用，包括用户明确要求继续使用当前材料的续页任务。不要每次调用都附加进程或强制重登；也不要在观察到退出/重登/撤销后自动沿用旧材料。

必要的冻结材料保存在权限收紧的私有研究目录，秘密值不进入报告、控制台、测试公共 fixture 或 Git。公开记录只保留来源标签、长度、材料是否变化和验证结果；低熵秘密不要用裸哈希作公开指纹。保留旧失败样本与原审计，用新增审计修正理解，不覆写历史。

确认失效后，按用户授权和已知刷新机制处理。刷新前不得盲试排列组合的旧/新密钥；刷新后验证材料与当前请求、成功响应的绑定。业务会话失效不等于所有传输材料失效；有效期不能从一次成功或一次失败外推。分层方法见 [11](11-encrypted-protocol-independence.md)。

## 来源判定（按目标证据选路，不必逐级穷举）

已知宿主会话接口、调试状态或业务认证函数可直接定位时，优先使用窄范围的明确来源。磁盘和内存扫描是候选手段，不是默认全进程搜索。缓存命中或出现形似票据的字符串，不足以证明当前有效。

```
① 磁盘上有没有？
   定位 profile：命令行里的 --user-data-dir / %LOCALAPPDATA%\<App> / %APPDATA%\<App>
   Chromium 系：<profile>\Network\Cookies（SQLite）
   ├─ 行存在且 value 非空       → 落盘了，直接读（最省事）
   ├─ 行存在但只有密文          → 先识别当前构建的加密/密钥保护方案
   └─ 没有这一行                → 检查实例/profile/分区/持久化状态，再换观测来源
   自定义格式：搜 *.db / *.bin / prefs / token 文件

② 调试接口能不能给？
   已授权且可用的调试接口 → 按当前工具版本读取对应实例、域和分区的状态

③ 进程内存（最后但常常唯一可用）
```

```sql
-- 先判「有没有落盘」，别急着写解密代码
SELECT host_key, name, length(value), hex(substr(encrypted_value,1,3)), is_persistent
FROM cookies WHERE name LIKE '%SESSION%' OR name LIKE '%TOKEN%' OR host_key LIKE '%DOMAIN%';
```

会话 Cookie 的持久化行为受应用、恢复策略、profile 与存储实现影响；`is_persistent=0` 不是“绝不落盘”的通用证明。表中缺值也可能是实例/分区错误或尚未落盘。先确认实际来源，避免把源数据缺失误诊为解密失败；同用户也不保证所有构建都只用 DPAPI。

## 内存取票据五步

```
① 定位扫哪些进程
   按进程树、模块、已知调用链选取授权目标，优先扫描有证据指向的区域。
   命中通常集中在「宿主进程 + 浏览器主进程」；network / renderer / storage / gpu 常常 0 命中，
   别把 2 GB 内存烧在它们身上。
② 只扫「已提交 + 可读 + 非 PAGE_GUARD」区域（VirtualQueryEx 逐段枚举）
   8 MB 分块 + 4 KB 重叠（特征串会跨块）
③ 用形态正则过滤，不要「取第一个」
   真值有稳定结构：前缀 + 随机串 + 分隔 + 后缀
   碎片通常是长度不对、后缀缺失的截断
④ 用来源与当前请求绑定筛选；命中次数仅作候选排序
   真值被复制多份（实测 x36~x60），碎片只有 x1~x2。
   重新登录后新旧两份可并存，复制次数不能证明新旧或有效性。
⑤ 用只读、幂等的业务接口当探针验证
   返回 200 且业务成功码才算拿到；不要靠「字符串看着像」。
   默认只发 1 次探针。
```

```python
import ctypes, re
from ctypes import wintypes as w

k32 = ctypes.WinDLL('kernel32', use_last_error=True)
PROCESS_QUERY_INFORMATION, PROCESS_VM_READ = 0x0400, 0x0010
MEM_COMMIT, PAGE_GUARD, PAGE_NOACCESS = 0x1000, 0x100, 0x01
CHUNK, OVERLAP = 8 << 20, 4096

class MBI(ctypes.Structure):
    _fields_ = [('BaseAddress', ctypes.c_void_p), ('AllocationBase', ctypes.c_void_p),
                ('AllocationProtect', w.DWORD), ('PartitionId', w.WORD),
                ('RegionSize', ctypes.c_size_t), ('State', w.DWORD),
                ('Protect', w.DWORD), ('Type', w.DWORD)]

def scan(pid, pattern):
    h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h: return {}
    hits, addr, mbi = {}, 0, MBI()
    while k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
        base, size = mbi.BaseAddress, mbi.RegionSize
        if mbi.State == MEM_COMMIT and not (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)):
            off = 0
            while off < size:
                n = min(CHUNK, size - off)
                buf = ctypes.create_string_buffer(n)
                got = ctypes.c_size_t(0)
                if k32.ReadProcessMemory(h, ctypes.c_void_p(base + off), buf, n, ctypes.byref(got)):
                    for m in pattern.finditer(buf.raw[:got.value]):
                        hits[m.group(0)] = hits.get(m.group(0), 0) + 1
                off += n - OVERLAP if n > OVERLAP else n
        addr = base + size
    k32.CloseHandle(h)
    return dict(sorted(hits.items(), key=lambda kv: -kv[1]))

PAT = re.compile(rb'PASS_ID["\']?\s*[:=]\s*["\']?([A-Za-z0-9_\-./+~=]{12,400})')
# 用形态完整的那条正则收口，探针次数从 N 降到 1
```

只读 API 不直接修改认证状态，但这不足以排除访问监控、工具附加、并发请求或其他同时发生的因素。记录实际 API、权限、附加行为和时间线；不能由“只读”推出目标绝不可感知或掉线因果已排除。

## 生命周期（换目标也成立）

| 现象 | 结论 |
|---|---|
| 重新登录后票据换值 | 进入新会话代次，重新关联材料并验证；不自动复用旧代次 |
| 旧值仍留在内存里 | 用来源与真实调用绑定分辨，不能只靠复制次数 |
| 票据带 `Max-Age=10天` 却几小时失效 | 服务端可提前失效，`Max-Age` 不代表可用时长 |
| 全局扫描 vs 局部扫描 | 连续全量扫描同一登录态内未见异常（实测 11 分钟内 6 次同值），但没必要刷 |

## 掉线归因四步（先排除，再怀疑）

```
第 1 步：区分工具自身行为与同时发生的请求、退出、重登、过期等因素
        直接证据能排除到哪一层就写到哪一层，不用“只读”替代因果实验
第 2 步：排时间线。「我做了什么」 vs 「什么时候失效」——时间吻合才有嫌疑
第 3 步：对每个嫌疑做变量控制
        头部三件套是否与客户端一致？是否建立了第二条同账号连接造成互踢？
第 4 步：写「归因表」，允许结论是「未定」，但每项都要带排除理由
```

HTTP 客户端的默认 UA、cookie 选择和重定向行为可能与原客户端不同，可作为差异实验的候选。没有目标响应或策略证据时，不能将其直接归因为风控、复制会话或掉线原因。

复现实际入口的请求元数据；原客户端未携带的浏览器头不要凭经验补入私有传输。探针优先只读，次数与副作用预算按授权范围设定。

## 长连接与单点互踢

- 同账号第二条长连接很可能与客户端互踢（IM 类应用常见单点登录语义）。
- 纪律：用完立刻 `close()`，不常驻、不轮询；需要常驻时先确认该应用允许多端。
- 出现掉线时，「是否建立了第二条同账号连接」优先于「是否被扫内存」怀疑。

## 限速纪律

| 项 | 建议 |
|---|---|
| 探针 | 只读、幂等、默认 1 次 |
| 写操作 | 先预览，确认后执行；单账号有日预算 |
| 退避 | 指数退避 + jitter，遵循服务端限流提示 |
| 并发 | 先测服务限额，不假定无限并发 |
| 会话失效 | 进入 `AUTH_REQUIRED`，不无限刷新 |
