# CHANGELOG — DSH 安全插件 correctover v2.4.6

> 2026-08-20 ｜ 安全修复 + 收费门禁 + 交互感知
> 发布/升级关键词前置：DSH / dsh-plugin / deepseek-harness

---

## 🟢 安全修复与收费门禁（v2.4.6）

### 安全漏检修复（R1–R5）

| # | 问题 | 修复 |
|---|---|---|
| R1 | SSRF IPv6 compat 绕过漏检 | ssrf.js 补 IPv4-compatible / IPv4-mapped IPv6 形态 + zone id 剥离（`::ffff:7f00:1`、`::7f00:1%eth0` 等） |
| R2 | write 位置参数短载荷漏检 | policy.js 去掉 val.length>40 长度门槛，短载荷同样走恶意内容检测 |
| R3 | 内嵌 URL 漏检（整串锚定绕过） | policy.js 整串锚定 → 全局 URL 提取逐个校验（web_fetch 与 subprocess 同步路径） |
| R4 | injection 多行/CRLF 换行漏检 | injection.js 换行归一化后检测（\r\n / 多行改写指令不再绕过） |
| R5 | commandTools 未覆盖 git/docker 等 | policy.js 默认命令工具清单扩展 git/git_*、docker/docker_*、ssh/ssh_*、npm、pip、npx（精确名 + 下划线/连字符通配，gitlab_*/github_* 不误伤） |

### 误报修复（F1–F4）

| # | 问题 | 修复 |
|---|---|---|
| F1 | destructive 判定过宽误伤良性工具 | policy.js 精确匹配 + 危险前缀白名单收窄 |
| F2 | 相对路径穿越误报 | policy.js 归一化后与强信号系统目录精确比对（var/log、images 的上层路径引用放行） |
| F3 | markdown 表格 `| Bash |` 被当管道注入 | cmdi.js 剥离表格行 + 管道类模式逐行检测、排除中文文档行 |
| F4 | injection 标签误报 | injection.js system 冒号/标签收窄 —— 要求强信号（忽略上文类措辞、指令性动词）才命中 |

### 收费门禁（license P0）

- `DEFAULT_PRODUCT = 'correctover-dsh'`：签发/验证产品统一，旧 product 密钥正确拒绝
- 免费层 preview=2，修复建议锁定 + Pro CTA（https://correctover.com/checkout）

### 交互感知

- 会话启动横幅：tier 直接展示（Pro/Free），用户第一眼看到 CCS 在运行（dsh/index.js apply() 启动横幅）

### 块表 P0

- V4_BLOCKLIST 修正：误拦公网段移除，漏拦段（0.0.0.0/8 子网、TEST-NET-3 203.0.113.0/24 等）补齐，标签纠正

### 验证

- 103/103 + 13/13 + 18/18 + 6/6 全部通过（含 R1–R5 / F1–F4 专项验证）

---

# CHANGELOG — DSH 安全插件 correctover v2.4.5

> 2026-08-19 ｜ 安全加固 + FP-1 文档上下文误报修复
> 发布/升级关键词前置：DSH / dsh-plugin / deepseek-harness

---

## 🟢 安全加固与误报修复（v2.4.3）

| # | 问题 | 场景 | 修复 |
|---|---|---|---|
| 1 | PowerShell 下载执行链漏报 | `IEX (New-Object Net.WebClient).DownloadString(...)` 未被拦截 | cmdi.js 新增 PowerShell download cradle 规则 |
| 2 | 命令工具预过滤不识别 PowerShell 关键词 | 即使 cmdi 有规则，policy 预过滤也会跳过 | policy.js 命令注入预过滤加入 powershell/pwsh/iex/invoke-expression/iwr/downloadstring 等 |
| 3 | 写 markdown 文档里的 shell 示例被误拦（FP-1） | `docs/example.md` 代码块里写 `curl 接 bash` 被当成恶意文件 | policy.js 文件写入检测增加上下文：文档类扩展名放行；非可执行文件内的 markdown 围栏代码块放行；`.sh/.ps1/.py` 等可执行文件仍然拦截 |

PowerShell 覆盖形态：

- `IEX (...DownloadString...)`
- `Invoke-Expression (...DownloadString...)`
- `iwr ... | iex`
- `Start-BitsTransfer ... ; IEX ...`
- `powershell -enc ...`
- `DownloadFile(...); Start-Process ...`

新增测试：

- `tests/ccs-powershell-cradle-test.mjs`：18 项（6 攻击 + 3 良性 × policy/cmdi 双通道）
- `tests/ccs-filewrite-context-test.mjs`：6 项（文档放行 + 可执行文件仍拦截）

---

# CHANGELOG — DSH 安全插件 correctover v2.4.2

> 2026-08-19 ｜ 输出侧工具感知：入参侧已经做到工具区分，输出侧补上同一原则
> 发布/升级关键词前置：DSH / dsh-plugin / deepseek-harness

---

## 🔴 输出侧误报消除（v2.4.2）

| # | 问题 | 场景 | 修复 |
|---|---|---|---|
| 1 | 所有工具输出统一跑注入检测 | `read_file` 读取含 prompt injection 特征的本地样例文件被拦截 | `evaluateToolResult()` 增加输出侧工具感知：read/cat/grep 等本地读取工具只告警不阻断 |
| 2 | 外部数据源没有更严格 | `web_fetch` 返回恶意网页内容 | fetch/web/http/request/search 等外部数据工具保持严格阻断 |

- `dsh/index.js` post-execute 钩子现在把 `exec.name` 传给 `evaluateToolResult(result, config, { toolName })`
- `dsh/policy.js` 新增 `OUTPUT_LOCAL_READ_TOOL_RE` / `OUTPUT_NETWORK_TOOL_RE`
- `scanOutput` 新增可配置动作：`localReadAction` / `networkAction` / `defaultAction`（`warn` / `block`），向 audit/enforce 双模式过渡
- 新增 `tests/ccs-output-toolaware-test.mjs`：13 项输出侧工具感知回归（默认行为 + 可配置动作）

---

# CHANGELOG — correctover v2.4.1

> 2026-08-19 ｜ 基于真实使用反馈（M9-M24 战役）的全面改造版
> 核心目标：**消除真实误报，让防护"自己用得顺"，同时不放松安全拦截**

---

## 🔴 误报消除（本次改造重点，真实场景驱动）

| # | 问题 | 场景 | 修复 |
|---|---|---|---|
| 1 | `$()` 子表达式被当命令注入 | PowerShell 命令 `$(Get-Date)`、脚本 `$($_.x)` | cmdi.js：`$()` 仅当内含危险命令词（rm/curl/bash/…）才拦 |
| 2 | 反引号代码块被当命令替换 | 文档/代码中的 `` `ls` `` | cmdi.js：反引号内必须含危险命令特征才拦 |
| 3 | markdown 表格 `\| Bash \|` 被当管道注入 | 写文档含表格 | cmdi.js：管道左边必须有命令字符才匹配 |
| 4 | write/search/web 等数据工具参数被命令注入扫描 | 写文档、搜索、网页查询被拦 | policy.js：命令注入**只检查命令执行类工具**（pwsh/bash/shell/exec/run…） |
| 5 | 模板字符串 `${}`、`env ` 被当环境变量访问 | 写入含模板字符串的代码 | guardrail.js：EnvProtection 移除泛模式，改具体命令形态 |
| 6 | 破坏性工具子串匹配误伤良性工具 | push_notification/apply_patch/merge 被永久拒绝 | policy.js：精确匹配 + 危险前缀，移除 apply/push/merge/deploy |

## 🟢 安全加固（保持并增强）

| # | 修复 | 说明 |
|---|---|---|
| 7 | D11 IPv4-mapped IPv6 SSRF 绕过 | ssrf.js 补十六进制形态检测（Node URL 归一化为 `::ffff:7f00:1`） |
| 8 | F5 提示词探询漏检 | injection.js 外泄模式权重 5→6，一票拦截 |
| 9 | CVE 错映射删除 | 删除与模式无关的 CVE-2026-42271/12957 引用 |
| 10 | CKG 约束缺参崩溃 | 可选链 + 未知 predicate 拒绝 |
| 11 | 完整性哈希规范化 | 复用 canonicalJson（嵌套键序不影响哈希） |
| 12 | 版本号统一 | ccs_status 返回 2.4.1 |
| 13 | .env.example 误伤 | 凭据路径放行示例/模板文件 |

## ⚙️ 新增能力

- **命令工具列表可配置**：`commandInjection.commandTools`（默认含 pwsh/bash/shell/exec/run/python/node/curl 等 21 项），用户可按需增删，决定哪些工具的参数走命令注入检查
- **文件写入感知检测（工具感知，v2.4.1）**：write 类工具（write_file/fs_write/append/save/put…）不做命令注入扫描（避免误报），但按**文件语义**检查真实攻击面：
  - 危险路径：`.bashrc/.zshrc/profile`、`authorized_keys`、`~/.ssh`、`~/.aws`、`/etc/passwd|shadow|sudoers`、`cron`、`systemd`、Windows 启动项
  - 恶意内容：下载执行（`curl|bash`）、反弹 shell（`/dev/tcp`）、base64 解码执行、PHP/ASP/JSP webshell、fork bomb
  - 写密钥文件：内容含 AWS/OpenAI/GitHub 等密钥模式
  - 正常写入（文档、代码含模板字符串）放行
- **真实场景回归测试**：Suite H（9 误报用例）+ Suite I（9 文件写入用例）

## ✅ 验证

- **103/103 测试通过（100%）**：87 原有用例 + 18 新增（误报回归 + 文件写入感知）
- 安全拦截不放松：`rm -rf && curl \| bash`、base64 解码执行、SSRF、密钥外泄、提示注入、**写后门/webshell/密钥文件**全部仍拦截

## 安装

```text
profile 依赖: correctover -> link:D:/Deepseek工作区/ccs-improved/pkg
一键安装: powershell -File D:\Deepseek工作区\scripts\install-ccs-improved.ps1
```

## 已知限制

- 命令注入检查依赖工具名识别命令工具；自定义命名的命令工具需加入 `commandTools` 配置
- 语义级注入检测（模型分类器）未包含——当前为规则层


## 可用性修复与收费门禁（v2.4.4）
1. workflow 编排参数误判修复：编排工具豁免 + injection 双信号
2. 管道命令误报修复：python 移出通用解释器清单
3. 收费门禁：license.js + applyTierGate，免费层 preview=2
4. GEO：keywords 20 词 + description 精简




## 安全修复（v2.4.5）
1. P0 修复：SSRF 块表数值错乱——误拦公网段（195.19.200.0/24）已移除，漏拦段（TEST-NET-3 203.0.113.0/24、0.0.0.0/8 子网）已补齐，标签纠正
2. 版本号全量统一：npm/已安装/源码/dsh/index.js/README/CHANGELOG 全部 2.4.5

