---
name: openai-pool-independent-refill
description: 独立补号 skill 骨架。用于查询 CPA/Sub2Api 池状态、计算 gap、生成补号计划，并逐步去桥接，最终收敛为真正无桥接的独立补号执行器。
---

# OpenAI Pool Independent Refill

这是独立补号 skill 的第一版代码骨架。

当前能力：
- 读取 skill 自己的配置文件
- 查询 CPA / Sub2Api 池状态
- 标准化输出 gap 与补号计划
- 提供统一的 refill 入口骨架
- Sub2Api 查询、查重、创建/更新上传逻辑已迁入 skill 内部
- `scripts/register_http.py` 已具备非 relay 版基础网络层，可提供 session / cookie / `oai-did` / trace headers / 固定代理能力

当前限制：
- 注册主流程入口已迁入 skill 内部，但 `scripts/register_engine.py` 目前仍是待补全骨架
- `scripts/register_http.py` 当前只覆盖非 relay 版基础网络层，尚未迁入完整 relay / 预检逻辑
- CPA 状态查询/上传层当前仍包装 `openai_pool_orchestrator.pool_maintainer.PoolMaintainer`
- skill 内邮箱 provider 文件已建立，但具体 provider 业务实现仍待继续迁入
- `probe_and_clean` 目前还是最小独立实现，尚未迁入 refresh abnormal 全量并发语义
- 还不是最终的完全独立迁移版

最终目标：
- 删除全部桥接依赖
- skill 自带注册执行层
- skill 自带 Sub2Api 上传去重逻辑
- skill 自带独立平台 client
