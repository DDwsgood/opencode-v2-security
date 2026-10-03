# v1.4.0 研究与验证摘要

> 以下 9,095 条固定回放记录属于原有静态证明研究阶段。发布前独立复核另外发现并修复了参数别名/展开状态、NumPy 可写映射与 pickle、SQL 引号/注释和 quoted 函数名、curl write-out、tmux 命令串联、gh 紧凑写参数及 SQLite 可变 PRAGMA 的证明缺口。不能把原回放中的“0 误放”解释为这些新反例不存在。发布阶段补充的正反测试、JEV 授权与 TUI 刷新研究见 `RESEARCH-JEV-PAYLOAD-20261003.md`；最终回归 Bun 2,562 / Python 196 全部通过。

## 做了什么

本轮（v1.3.0 之后）目标是把更多判定放到静态层、减少动态审查调用，同时不引入漏判。三条线：

1. **LOOSE 读写会话语义放行**：新增 `src/security/semantic-allow.ts` 与 Python AST 只读证明器 `src/security/python-readonly.py`（fail-closed：模块白名单、只读 open/SQL、拒绝 URL/敏感文件名/环境变量读取；`python3 -I -S -B` 运行、5 秒超时、sha256 缓存）。覆盖 python `-c`/stdin heredoc/本地脚本、sqlite3 只读 SQL、gh 读、tmux 只读、版本/帮助查询、仅 loopback 的 curl GET/HEAD、字面量赋值与循环变量绑定、凭据安全 glob 读、新配置 `trustedCommands`。
2. **只读（RO）会话共享词法/词汇放宽**：`looseRelaxationScope`（AsyncLocalStorage）三态 rw/ro/off；RO 也启用 `sed … 2>/dev/null`、`~` 路径、`for`/`if` 复合体、`:`、`git worktree list`、glob 读等放宽；timeout 剥离与赋值绑定保持 RW-only；语义放行仍不进 RO。
3. **RO 逃逸面修复**（见下）。

验证不执行任何命令，全部作为文本送审；复现工具在 `/tmp/sec-probe/`（replay/replay4 = RO+内核直通、cmp、segprobe、危险语料 corpus/corpus2/c3–c6）。

## 结果（固定回放 9,095 条带 reviewer 标签的历史命令）

| 模式 | 1.3.0 静态 ALLOW | 本版 | 备注 |
|---|---:|---:|---|
| LOOSE 读写 | 740 (8.1%) | **4041 (44.4%)** | 0 条 reviewer-DENY 被静态放行；无新静态 DENY |
| HARD | 722 | 722 | 判定逐行一致（0 变化） |
| RO（无内核） | 1066 | **2252** | 1 条收紧（本地模块 import 检查） |
| RO + 内核直通 | 7246 | **7397** | 49 条转 ASK（多为凭据文件触碰）；9 条收紧 |

危险语料（corpus×3 模式×2 工作树）：LOOSE/HARD **0 LEAK/WEAK**；RO 的 30 条"LEAK"全部为预期只读放宽 + 1 条既有 home 秘密搜索缺口（1.3.0 同样存在，未获决策不处理）。

## RO 逃逸面修复（三者均 1.3.0 已存在，本轮发现并修复）

1. **复合关键字遮蔽 interop 写**：`if true; then pwsh.exe -Command 'Remove-Item …'; fi` 在内核强制 RO 下被放行——分段遗留的 `then`/`do` 等关键字让可执行名不被识别，走了"未识别叶子 → 内核直通"，而 Linux 内核沙箱管不住 Windows 侧进程。修复：RO 门先剥掉关键字前缀再分类，包裹形式与裸命令判定一致（DENY）。`exec cmd.exe`、`case …) cmd.exe`、`xargs cmd.exe`、函数体包裹等残余形态已记录为已知缺口（1.3.0 同样存在）。
2. **temp 豁免绕过执行器扫描**：`sed -n '1e id' x > /tmp/o`（sed `e` 命令执行任意代码）与 `awk 'BEGIN{system(…)}' > /tmp/o` 曾在**所有模式**下被"/tmp 目标全受限"早放行。修复：temp 豁免前先过 `executorCapabilityHazard`；awk 加入该检查（system/getline/print 管道；引号内容先屏蔽，`print $1" || "$3` 不误判；`print > file` 仍按写处理）。未解析 argv 的 awk 不进"未识别叶子即执行器"分支——现实语料里 awk 常与被切断的 `$(…)` 相邻，逐段硬拒会大面积误拦（先实现过一版，回放出现 12+6 条假 DENY 后回退为仅解析成功时判定）。
3. **内联代码点名凭据文件**：`python3 -c "print(open('/home/u/.ssh/id_rsa').read())"`、`node -e "…readFileSync('/home/u/.ssh/id_rsa')…"` 里的路径不构成可分类路径 token，RO 曾以"纯读"静态 ALLOW（HARD-RO 也放行）。修复：`paths.ts` 新增 `embeddedCredentialFinding`（凭据词表与注册表同源），作用于 python/node 内联分类与 `roNonWriteGate`（覆盖内核直通）。效果：无内核 RO → DENY；内核 RO → ASK credentials.sensitive-access；RW 不变（本就走 wrapper 审查）。

回放核对：RO+内核下"静态 ALLOW 但 reviewer DENY"的命令 **29 → 25**（少的 4 条即上述第 3 类修复）；RO 无内核 3 → 3；无新增。

## 修复过程中的两个假阳性与一次环境干扰（记录方法论）

- 初版 awk 检查把 `print $1" || "$3` 里的字符串 `" || "` 误判为管道命令（12 条假 DENY）——用保长度的引号屏蔽修复。
- 初版把"未解析 argv 的 awk"当执行器（6 条假 DENY，`awk -v font="$FONT"` 一类）——回退。
- 回放对比出现 5 条 LOOSE ASK→ALLOW "翻转"，追查后确认是探测期间我创建/删除 `/tmp/opencode/secwork` 改变了文件系统状态（目录存在性检查参与判定），非代码变化；用同代基线（同日重跑 1.3.0 基线）重新对比后消失。

## 验证与局限

- 最终回归：**Bun 2463 通过 / 0 失败**（新增 20 条 RO 逃逸/精确性用例）；**Python 116 通过**。
- 固定回放四模式（LOOSE/HARD/RO/RO+内核）与 1.3.0 基线逐行对比（同文件系统状态）。
- 危险语料 6 套 × 3 模式 × 2 工作树：LOOSE/HARD 零 LEAK/WEAK。
- RO+内核收紧的 9 条均为 Windows 互操作、未验证 cwd 循环删除或 sed 动态脚本一类（逐条人工复核）。
- 已知未决（沿袭 1.3.0，需用户决策，未擅自处理）：home 根目录内容搜索静态放行（`grep -rn 'sk-' ~`）；`curl -o` 远程下载静态放行；`exec`/`case`/`xargs`/函数体包裹 interop 的内核直通缺口（本轮仅修复最常见的关键字包裹形态）。
- 测试载荷全部仅作为文本送审，未执行；真实凭据未进入任何研究产物。
