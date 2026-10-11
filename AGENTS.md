# 项目指南

## 入口与执行链

- 本包是 **OpenCode V2 effect 插件**，不是 V1 的函数插件。入口为 `{ id, effect(ctx) }`；hook 回调返回 `Effect`。阻断通过带 `_tag: "Tool.Error"` 的失败返回当前工具调用，不能改成普通异步异常或人工确认。
- npm 入口为 `src/index.ts`、TUI 子入口为 `src/tui.tsx`；目录安装依赖根目录 `index.ts`、`tui.ts` 两个转发文件，不能因 package exports 已存在就删除它们。
- 宿主直接加载 TypeScript，没有 `dist` 构建步骤。`package.json` 没有 scripts，仓库没有根 tsconfig、lint 配置或 CI workflow；不要猜 `npm test`、`npm run build` 或通用 typecheck 命令。
- `src/index.ts` 串联工具前审查、权限上限、沙箱路由和运行时边界监督；静态语义在 `src/security/classifier.ts`，规则到豁免类别的映射在 `src/security/bypass.ts`。不要为一个局部任务反复通读整个入口。
- 常规动态审查：`reviewer.ts` → `jev-reviewer.py`（仅 JEV，旧导出接口；新 Linux 边界链路由 `effects-reviewer.ts` 直接请求 JEV，只读会话使用其 readonly 变体）。JEV 的共享效果题在 `risk_heads.py`。核对实际发送题目应看 `build_questions` 与 state 构造函数，不能把保留但已停发的旧题目常量算进去。
- JEV 官方 `noul` 是命题为真的概率，不是任意严重度数轴；`score` 才是等级量表，要求顶层 `criteria` 为 2～10 项有序数组。题目 ID 不进入模型，类别与判断必须完整写在本题 instructions；不要靠改名解释返回值，也不要把畸形请求的 400 当作题型不支持。接口依据：`https://docs.typesafe.ai/primitives`、`https://docs.typesafe.ai/api`。
- `reviewer` 的 `"openai"`/`"auto"` 旧拼写仅作兼容输入并解析为 `"jev"`，没有 OpenAI-compatible 审查器回退；JEV 基础设施失败直接按 `failPolicy` 处理。Python stdout 是结构化结果通道，诊断写 stderr。

## 容易破坏的契约

- 七个风险类别是 `filesystem/host/privilege/secret/network/remote/indirection`；`dynamic/sandbox/slow` 是额外层级开关。输入别名在边界展开，状态与协议保存 canonical 名称。
- 凭据同对象的读写、删除和保护弱化归 secret，不能机械重复为 filesystem/privilege；独立普通数据损失仍保留。远端动作的附随传输不自动加 network。真实独立复合不能强制单类。
- 分类、许可决定、实际权限和沙箱能力分开。category 豁免不扩大 r/w 上限；x 仅兼容显示，始终可用且不能单独授予或撤销。不可绕过底线由 `isFloorRule` 判断；不能把“没有类别映射”的普通规则都当底线。
- 一次批准绑定会话、命令和受审事实；弱 secondary 不进入下一次申请的硬覆盖要求。修改审查逻辑须检查 **Python 结果 → TS 解析 → 宿主拒绝** 整条链，不能只测 Python `decide()`。
- `/perm`、`/bypass` 状态变更只更新 `session-notifications.ts` 快照，不入队；在 `session.hook("prompt")`（宿主准备下一条真实用户消息、尚未入队）里才用 `session.synthetic`（`resume:false`、`steer`）追加。状态变更时直接 synthetic 会在 inbox 留下待处理 steer 项，正在收尾的 runner 会因此多发一次模型请求；排队（`queue`）消息不携带通知。运行中的变更另由 `tool.execute.after` 前置到下一个已完成工具结果（`takeForToolResult`，计为已送达），本次运行的下一步本来就会读取它，不另起请求。
- 自动采到正文不等于已证明安全；原始模型选择、程序底线、权限拒绝、协议/网络错误应分源，不能用未选项概率伪造模型拒绝。

## 定位与验证

- 单个 TS 测试：`bun test tests/session-notifications.test.ts`；按改动选对应 `tests/*.test.ts`，无需全仓库扫描。
- 单个 Python 测试：`python3 -m unittest discover -s tests -p 'test_risk_heads.py'`；JEV 接口由 `test_jev_reviewer.py` 覆盖，单（LOOSE）策略契约由 `test_single_policy_reviewer.py` 覆盖。
- 全量回归（仅需要时）：`bun test tests`；`python3 -m unittest discover -s tests -p 'test_*.py'`。文档或小配置修改只重读及 `git diff --check`，不跑全套。
- `OPENCODE_SECURITY_KEEP_TEST_ARTIFACTS=1` 禁用 `tests/artifacts.ts` 的清理。部分测试直接在 HOME 创建 `.classifier-regression-*`、`.payload-routing-*` 等目录；保留 fixture 前先确认根目录，不把实验产物留在 HOME。新临时研究放 `/tmp/opencode`，不要执行被审危险样例。
- Linux helper 修改后运行 `make -C native/linux-sandbox`，输出 `bin/opencode-sandbox`。Windows supervisor 构建为 `cargo build --release --manifest-path native/windows-bash-supervisor/Cargo.toml`；其运行依赖 Windows Job Object 和注入的 `OPENCODE_REAL_BASH`，Linux 编译或 mock 不能冒充 Windows 集成验证。

## 配置与发布陷阱

- 配置加载是根 `config.json` → `options.configFile` → 显式 options 的**浅层覆盖**，不是嵌套深合并。根文件解析失败会警告并回退；显式 configFile 失败会抛错。
- `config.json` 是 gitignore 的本机文件，可能含个人端点和凭据；不要回显其值、放进实验日志或打包。修改源码不代表当前 OpenCode 服务已重新加载；未验证就不能宣称热更新生效。
- `package.json.files` 同时打包 TS、Python、共享 `risk_heads.py` 与 native 文件；打包需排除 pycache/pyc。Python 的隔离加载与包内 sibling import 也要验证，不能只测源码目录。
- 发布前核对 remote 与 `package.json.repository`：这个 checkout 的 `origin` 指旧 `opencode-bash-classifier` 仓库，`pub` 指 `opencode-v2-security`。两仓库历史不同，不盲推 origin，也不用 force/reset 对齐历史。
- `RESEARCH-v1.5.0.md` 区分研究题组与正式题组；分类足迹成绩不等于联合裁决准确率，模拟宿主测试也不等于真实隔离/执行验证。
