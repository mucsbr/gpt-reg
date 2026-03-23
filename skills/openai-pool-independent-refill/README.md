# OpenAI Pool Independent Refill

这是独立补号 skill 的第一版代码骨架。

最终目标只有一个：**去掉全部桥接依赖，变成真正可迁移的独立补号 skill。**

## 当前能力

- 读取 skill 自己的配置文件
- 查询 CPA / Sub2Api 池状态
- 计算 gap 并输出补号计划
- 提供统一的 refill 命令入口
- 已经把 Sub2Api 查询、查重、创建/更新上传逻辑迁入 skill 内部
- `scripts/register_http.py` 已具备非 relay 版基础网络层：session 复用、固定代理、cookie / `oai-did`、trace headers、统一 get/post 封装

## 当前桥接依赖

当前版本还依赖以下仓库内实现：

- 注册桥接：已移除，入口已改为 skill 内部 `scripts/register_engine.py`
- CPA client 桥接：`openai_pool_orchestrator.pool_maintainer.PoolMaintainer`

已经移除的桥接：

- Sub2Api 上传桥接：已改为 skill 内部 `scripts/sub2api_api.py`
- Sub2Api client 桥接：已改为 skill 内部 `scripts/sub2api_client.py`
- 注册入口桥接：已不再调用 `openai_pool_orchestrator.register.run`

这意味着它现在已经完成了 **Sub2Api Phase 1 去桥接**，但仍不是最终完全独立可移植版。

## 去桥接顺序

建议严格按下面顺序继续推进：

1. 保持已完成的 Sub2Api 去桥接状态并补齐边界测试
2. 补全 `register_engine.py` 主流程实现与 skill 内邮箱 provider 细节
3. 最后迁出 CPA maintainer 包装依赖

原因：
- Sub2Api 上传链路已经独立，先稳住
- 注册层耦合最重，必须整体迁
- CPA maintainer 仍可暂时复用，降低重写风险

## 当前限制

- 还没有把 `register.py` 与 `mail_providers.py` 的完整业务细节迁完
- 注册入口已迁入 skill 内部，但 `register_engine.py` 目前仍是待补全主流程骨架
- 当前 `scripts/register_http.py` 仅实现非 relay 版基础网络层，尚未迁入 `_request_via_pool_relay` 与 OpenAI relay 预检语义
- CPA 查询/上传层目前仍桥接 `openai_pool_orchestrator.pool_maintainer.PoolMaintainer`
- `probe_and_clean` 目前是独立最小实现，尚未迁入 refresh abnormal 全量并发语义

## 目录结构

```text
skills/openai-pool-independent-refill/
├── SKILL.md
├── README.md
├── requirements.txt
├── assets/
│   └── config.example.json
└── scripts/
    ├── __init__.py
    ├── main.py
    ├── config_loader.py
    ├── cpa_client.py
    ├── sub2api_api.py
    ├── sub2api_client.py
    ├── refill_planner.py
    ├── uploader.py
    ├── register_runner.py
    └── token_store.py
```

## 用法

先准备配置文件：

```bash
cp skills/openai-pool-independent-refill/assets/config.example.json /tmp/refill-config.json
```

查看状态：

```bash
python skills/openai-pool-independent-refill/scripts/main.py status --config /tmp/refill-config.json
```

查看补号计划：

```bash
python skills/openai-pool-independent-refill/scripts/main.py plan --config /tmp/refill-config.json
```

尝试执行补号骨架：

```bash
python skills/openai-pool-independent-refill/scripts/main.py refill --config /tmp/refill-config.json
```
