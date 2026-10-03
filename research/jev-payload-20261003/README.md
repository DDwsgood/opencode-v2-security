# JEV 小批次研究材料

完整说明见仓库根目录 `RESEARCH-JEV-PAYLOAD-20261003.md`。

| 文件 | 内容 |
|---|---|
| `optimized-prompt.json` | 交付源码的提示词组件与无绕过时编译出的 23 个问题 |
| `optimized-prompt-authorized.json` | 批准本次 indirection/network/secret 后的完整编译问题及授权模板 |
| `training.json` | 36 条训练请求：14 条数据库请求 + 22 条对照 |
| `validation.json` | 34 条验证请求：6 条数据库请求 + 28 条对照 |
| `second-holdout.json` | 28 条新增执行/数据边界对照 |
| `secret-regression.json` | 14 对真实读取/只保存读取描述的敏感来源检查 |
| `interface-smoke.json` | 12 条 shell 包装、参数与受保护目标检查 |
| `protected-followup.json` | 补充已确认存在的授权文件后，检查实际覆盖风险 |
| `metrics.json` | 所有批次规模、误拦/误放、错误数及来源说明 |
| `results.jsonl` | 每条判定及内部触发规则，包含弃用候选和失败结果 |
| `grant-followup.json` | 18 条授权、未知执行、载荷数据与真实底线对照 |
| `hard-followup.json` | 11 条 HARD 完整检查、授权解除与真实底线对照 |
| `release-results.jsonl` | 发布复核与授权重放的独立结果；包含重复波动和失败 |
| `release-metrics.json` | 发布阶段批次、源码指纹及与原研究阶段合计的次数 |
| `replay.py` | 只调用 JEV，不执行语料；每批限制 1–49 条 |

用户名路径已脱敏，完整数据库、全量历史记录和凭据未导出。预期标签依赖请求场景和重建条件，不代表当前机器的真实文件状态。API 凭据只从环境变量读取。
