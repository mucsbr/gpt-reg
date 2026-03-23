# Refill Flow Reference

这个文档给出补号专项的真实代码链路，供主 `SKILL.md` 按需引用。

## 1. gap 计算入口

### CPA

- `openai_pool_orchestrator/pool_maintainer.py:113` `PoolMaintainer.get_pool_status()`
- `openai_pool_orchestrator/pool_maintainer.py:313` `PoolMaintainer.calculate_gap()`

逻辑：
- 先读取 CPA 平台 auth files
- 筛出目标类型账号
- 用 `min_candidates - current_candidates` 计算缺口

### Sub2Api

- `openai_pool_orchestrator/pool_maintainer.py:901` `Sub2ApiMaintainer.get_pool_status()`
- `openai_pool_orchestrator/pool_maintainer.py:1055` `Sub2ApiMaintainer.calculate_gap()`

逻辑：
- 拉取全部账号
- 把异常状态账号排除出 candidates
- 用 `sub2api_min_candidates - current_candidates` 计算缺口

## 2. 自动补号决策中心

- `openai_pool_orchestrator/server.py:3056` `_try_auto_register()`

这里会依次判断：

1. `auto_register` 是否开启
2. 是否配置了固定代理或启用了代理池
3. 当前 `_state.status` 是否允许启动新任务
4. CPA gap 与 Sub2Api gap 各是多少
5. `upload_mode` 是 `snapshot` 还是 `decoupled`
6. 最终调用 `_state.start_task(...)` 时的 `target_count`、`cpa_target_count`、`sub2api_target_count`

### gap 合成规则

- `snapshot`：`gap = cpa_gap + sub2api_gap`
- `decoupled`：`gap = max(cpa_gap, sub2api_gap)`

这是补号数量分析时最容易出错的地方。

## 3. 自动维护如何接到自动补号

### CPA 自动维护

- `openai_pool_orchestrator/server.py:3154` `_start_auto_maintain()`

链路：
1. 维护线程定期执行 `pm.probe_and_clean_sync()`
2. 维护完成后调用 `_try_auto_register()`

### Sub2Api 自动维护

代码里还有独立的 Sub2Api 自动维护链路；维护完成后同样会触发 `_try_auto_register()`。

因此，“维护成功但没补号”优先看维护后的自动注册决策，而不是维护函数本身。

## 4. 注册任务与上传链路

### Web 模式上传点

- `openai_pool_orchestrator/server.py:1197`
- `openai_pool_orchestrator/server.py:1413`

### CLI 模式上传点

- `openai_pool_orchestrator/register.py:2096`

### CPA 上传实现

- `openai_pool_orchestrator/pool_maintainer.py:322` `upload_token()`

如果补号任务确实启动并成功生成 token，但平台数量没有增加，要继续顺着这些点追：

1. token 是否落盘到 `data/tokens/`
2. 上传函数是否成功返回
3. 目标平台统计接口是否把新账号计入 candidates

## 5. 前端相关入口

### Sub2Api 维护按钮

- `openai_pool_orchestrator/static/app.js:2408` `triggerSub2ApiMaintenance()`

维护完成后会：
- 刷新池状态
- 刷新账号列表
- 显示维护结果文案

如果用户说“补号或维护已经完成，但页面没变”，不要只看后端，也要看这里。

## 6. 配置路径陷阱

### Web

- `server.py` 通过 `CONFIG_FILE` 读写 `data/sync_config.json`

### CLI

- `register.py:2046` 仍读取 `config/sync_config.json`

所以“Web 上设置了自动补号，但 CLI 侧补号行为不一致”是一个真实风险点。
