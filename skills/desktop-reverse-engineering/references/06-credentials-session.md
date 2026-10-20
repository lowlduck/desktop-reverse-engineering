# 06 · 凭据与会话生命周期

> 任何需要登录态的功能，**第一件事不是找接口，是把凭据拿到手且可自动复现**。
> 凭据拿不到，后面全是空转。

## 三级来源判定（每步几分钟，按顺序）

```
① 磁盘上有没有？
   定位 profile：命令行里的 --user-data-dir / %LOCALAPPDATA%\<App> / %APPDATA%\<App>
   Chromium 系：<profile>\Network\Cookies（SQLite）
   ├─ 行存在且 value 非空       → 落盘了，直接读（最省事）
   ├─ 行存在但只有 v10/v11 密文  → 同用户下可 DPAPI 解密
   └─ 压根没有这一行            → 会话 Cookie，只在内存 → 走 ③
   自定义格式：搜 *.db / *.bin / prefs / token 文件

② 调试接口能不能给？
   能开 CDP → Network.getAllCookies（最可靠，前置是解决「怎么开」）

③ 进程内存（最后但常常唯一可用）
```

```sql
-- 先判「有没有落盘」，别急着写解密代码
SELECT host_key, name, length(value), hex(substr(encrypted_value,1,3)), is_persistent
FROM cookies WHERE name LIKE '%SESSION%' OR name LIKE '%TOKEN%' OR host_key LIKE '%DOMAIN%';
```

**通用判据**：`is_persistent=0` / `has_expires=0` 的 Cookie **不会落盘**。
所以在会话型票据上「从磁盘读」必然失败——这不是方法不对，是数据不在那。
看到目标票据压根不在表里，立刻判定「内存唯一路径」，省掉一整轮 DPAPI 折腾。

## 内存取票据五步

```
① 定位扫哪些进程
   先全扫一遍看命中分布，再固定只扫命中的那几个。
   命中通常集中在「宿主进程 + 浏览器主进程」；network / renderer / storage / gpu 常常 0 命中，
   别把 2 GB 内存烧在它们身上。
② 只扫「已提交 + 可读 + 非 PAGE_GUARD」区域（VirtualQueryEx 逐段枚举）
   8 MB 分块 + 4 KB 重叠（特征串会跨块）
③ 用形态正则过滤，不要「取第一个」
   真值有稳定结构：前缀 + 随机串 + 分隔 + 后缀
   碎片通常是长度不对、后缀缺失的截断
④ 按命中次数排序
   真值被复制多份（实测 x36~x60），碎片只有 x1~x2。
   重新登录后新旧两份并存（新 x36 / 旧 x10）→ 不排序就会先试到过期值。
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

要点：**只读，不写、不注入、不改内存**。纯读不产生回调，目标进程无法感知，因此不可能反过来导致服务端会话失效——这类因果关系可以直接结构性排除。

## 生命周期（换目标也成立）

| 现象 | 结论 |
|---|---|
| 重新登录后票据换值 | 正常。工具必须每次现取，**不能缓存** |
| 旧值仍留在内存里 | 正常。靠命中次数分辨新旧，别取到旧的 |
| 票据带 `Max-Age=10天` 却几小时失效 | 服务端可提前失效，`Max-Age` 不代表可用时长 |
| 全局扫描 vs 局部扫描 | 连续全量扫描同一登录态内未见异常（实测 11 分钟内 6 次同值），但没必要刷 |

## 掉线归因四步（先排除，再怀疑）

```
第 1 步：能不能「结构性排除」某个嫌疑？
        例：ReadProcessMemory 无回调 → 不可能让服务端会话失效
第 2 步：排时间线。「我做了什么」 vs 「什么时候失效」——时间吻合才有嫌疑
第 3 步：对每个嫌疑做变量控制
        头部三件套是否与客户端一致？是否建立了第二条同账号连接造成互踢？
第 4 步：写「归因表」，允许结论是「未定」，但每项都要带排除理由
```

**最容易踩的坑：用默认 HTTP 客户端的 UA 打业务接口。**
`Python-urllib/3.x`、`requests` 默认 UA 会直接暴露「不是客户端」。同一票据出现「客户端 UA ↔ 脚本 UA」交替，是「会话被复制/多端使用」的典型特征，风控优先处理这种。

判断式建议：同一票据的**所有**请求（HTTP 与 WS）统一 UA / Referer / Origin；探针只读且只发一次。

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
