# openai-pool-refill-workflow

一个面向 `openai_pool_orchestrator` 仓库的**补号专项可执行 skill**。

## 现在这个 skill 做什么

它不只是说明文档，而是分成两层：

1. `SKILL.md`
   - 负责触发条件、使用流程、代码入口
2. `scripts/refill_diagnose.py`
   - 负责本地静态诊断补号配置与 gap 估算

## 目录结构

```text
openai-pool-refill-workflow/
├── SKILL.md
├── README.md
├── scripts/
│   └── refill_diagnose.py
└── references/
    ├── refill-flow.md
    └── refill-checklist.md
```

## 脚本能力

`refill_diagnose.py` 会读取当前项目中的：

- `openai_pool_orchestrator/server.py`
- `openai_pool_orchestrator/register.py`
- `data/sync_config.json` 或 `config/sync_config.json`
- 可选的 `data/refill_snapshot.json`

输出一个 JSON 诊断结果，帮助快速判断：

- 自动补号是否开启
- 代理或代理池是否满足前置条件
- `upload_mode` 是什么
- CPA / Sub2Api 阈值是多少
- 如果提供了池快照，本地估算 gap 是多少
- 当前最明显的阻塞项是什么
- 是否存在 Web / CLI 配置路径不一致问题

## 运行方式

```bash
python3 ${CLAUDE_SKILL_DIR}/scripts/refill_diagnose.py /absolute/path/to/project
```

如果当前目录就是项目根目录：

```bash
python3 ${CLAUDE_SKILL_DIR}/scripts/refill_diagnose.py
```

## 池快照文件

如果你知道当前平台里的候选账号数，可以创建：

`data/refill_snapshot.json`

示例：

```json
{
  "cpa_candidates": 780,
  "sub2api_candidates": 160
}
```

脚本会据此计算更准确的本地 gap。

## 为什么现在没有写更多脚本

当前这个 skill 的核心目的是：

- 先快速做配置和 gap 诊断
- 再引导 Claude 沿真实代码链路分析和修改仓库

它还没有加入“主动访问外部平台 API 并拉实时池状态”的脚本，是因为这会引入凭证、安全和环境耦合问题。等你要做真正的“在线补号巡检脚本”时，可以继续在 `scripts/` 下扩展。