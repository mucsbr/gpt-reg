---
name: openai-pool-refill-workflow
description: 处理 OpenAI Pool Orchestrator 的补号问题。用户提到补号、池不足自动注册、gap 计算、CPA/Sub2Api 池补充、snapshot/decoupled、min_candidates、auto_register、自动维护后没触发注册时，优先使用此 skill。
---

# OpenAI Pool Refill Workflow

这是一个**可执行的补号专项 skill**。它不是只给说明，而是先用脚本快速做本地补号诊断，再引导 Claude 沿真实代码链路继续分析或修改。

## When to Use This Skill

在下面场景优先使用：

- 用户说“补号”“自动补号”“池不足自动注册”
- 用户提到 `auto_register`、`min_candidates`、`sub2api_min_candidates`
- 用户提到 `snapshot` / `decoupled`
- 用户说 CPA / Sub2Api 池数量不对
- 用户说自动维护后没有继续补号
- 用户要修改补号相关逻辑、配置、接口或前端状态展示

## What This Skill Does

1. 运行本地诊断脚本，快速输出补号配置和 gap 估算
2. 判断问题更像是：
   - 没触发自动补号
   - 补号数量不对
   - 注册成功但平台数量没涨
   - 前端显示异常
3. 再沿真实代码入口继续读代码、分析或改动

## Usage

### Step 1: 先运行本地诊断脚本

优先运行：

```bash
python3 ${CLAUDE_SKILL_DIR}/scripts/refill_diagnose.py /absolute/path/to/project
```

如果当前工作目录就是项目根目录，也可以运行：

```bash
python3 ${CLAUDE_SKILL_DIR}/scripts/refill_diagnose.py
```

脚本会输出 JSON，内容包括：

- `auto_register`
- `auto_sync`
- 代理 / 代理池状态
- `upload_mode`
- CPA / Sub2Api 阈值
- 本地估算的 CPA / Sub2Api gap
- 总 gap
- 已识别的 blockers
- Web/CLI 配置路径是否不一致

### Step 2: 读脚本结果并分类问题

按下面方式解释脚本结果：

- `blockers` 非空：优先解释为什么当前不会自动补号
- `total_gap = 0`：优先解释为什么系统认为无需补号
- 注册成功但用户说平台没涨：继续查上传和统计链路
- 用户反馈页面异常：继续查前端和状态刷新链路

### Step 3: 再读真实代码入口

根据问题类型，至少继续读这些位置：

- `openai_pool_orchestrator/server.py` 中 `_try_auto_register()`
- `openai_pool_orchestrator/pool_maintainer.py` 中对应平台的 `calculate_gap()`
- 注册后上传点：
  - `openai_pool_orchestrator/server.py:1197`
  - `openai_pool_orchestrator/server.py:1413`
  - `openai_pool_orchestrator/register.py:2096`
  - `openai_pool_orchestrator/pool_maintainer.py:322`

详细链路说明见：

- `${CLAUDE_SKILL_DIR}/references/refill-flow.md`
- `${CLAUDE_SKILL_DIR}/references/refill-checklist.md`

### Step 4: 如需更准确估算 gap，可先提供池快照

脚本默认不会请求外部平台 API，只做本地静态诊断。

如果你已经知道当前池数量，可在项目里写入：

`data/refill_snapshot.json`

内容示例：

```json
{
  "cpa_candidates": 780,
  "sub2api_candidates": 160
}
```

然后重新运行脚本，得到更接近真实情况的 gap 估算。

### Step 5: 输出时必须说明四件事

- gap 从哪里得出
- 自动补号为何触发或没触发
- 注册是否真的启动/成功
- 卡在配置、算法、上传、统计还是前端展示

## Important Notes

- 这个 skill 自带的是**静态诊断脚本**，不会直接调用外部平台 API，也不会主动发起补号。
- 真正的补号触发点在 `server.py` 的 `_try_auto_register()`。
- `snapshot` 和 `decoupled` 会直接影响总补号目标数。
- Web 与 CLI 当前配置读取路径不完全一致，这是已知坑。

## Error Handling

- 如果脚本输出 `缺少池快照，无法本地估算 gap`，说明它只能检查配置和代码默认值；这不是脚本失败。
- 如果用户明确提供当前池数量，建议先写入 `data/refill_snapshot.json` 再重跑。
- 如果需要真实线上状态，不要伪造数据，应继续读维护器和 API 代码，或由用户提供实时状态。

## Examples

**Example 1**

用户：`为什么自动维护后还是没有补号？`

处理：
1. 运行 `refill_diagnose.py`
2. 看 `blockers`、`upload_mode`、gap 估算
3. 继续读 `_try_auto_register()` 和维护后触发链路

**Example 2**

用户：`snapshot 模式应该补 10 个，为什么系统没补够？`

处理：
1. 运行脚本确认 `upload_mode`、阈值、gap 估算
2. 继续读两个 `calculate_gap()`
3. 区分是 gap 算错，还是任务目标数与 worker 数混淆

**Example 3**

用户：`日志显示注册成功，但 Sub2Api 数量不涨。`

处理：
1. 运行脚本确认不是配置阻塞
2. 再追上传链路和池状态统计
3. 最后看前端刷新是否滞后
