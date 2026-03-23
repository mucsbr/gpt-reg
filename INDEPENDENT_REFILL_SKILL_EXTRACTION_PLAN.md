# 独立补号 Skill 抽取设计说明

本文档只做一件事：

**基于当前仓库已有实现，说明为什么现有 `skills/openai-pool-refill-workflow/` 不满足需求，以及如果要做成“可安装到另一个 agent 的独立补号 skill”，应该从当前项目里抽哪些逻辑、如何拆边界。**

---

## 1. 目标需求复述

目标 skill 不是“分析当前仓库的补号代码”，而是一个**独立、可迁移、可执行**的 skill。装到另一个 agent 后，应具备：

1. 不依赖本项目源码目录结构
2. skill 自带脚本、依赖、配置模板
3. 如果配置了 CPA / Sub2Api：
   - 查询账号情况
   - 判断 `401 / 额度用完 / 可用 / 其他异常`
   - 统计可用数量
4. 如果低于阈值（如 200）：
   - 执行补齐闭环
   - 调用注册流程
   - 将产物上传到 CPA / Sub2Api

这意味着要从当前仓库中抽出的不是“文档知识”，而是**实际执行逻辑**。

---

## 2. 为什么现有 skill 不合格

现有 skill 在这里：

- `skills/openai-pool-refill-workflow/SKILL.md`
- `skills/openai-pool-refill-workflow/scripts/refill_diagnose.py`

它的问题不是写得不够多，而是**方向错误**。

### 2.1 它依赖当前项目源码，不是独立 skill

`refill_diagnose.py` 直接读取：

- `openai_pool_orchestrator/server.py`
- `openai_pool_orchestrator/register.py`
- `data/sync_config.json`

见：
- `skills/openai-pool-refill-workflow/scripts/refill_diagnose.py:106`
- `skills/openai-pool-refill-workflow/scripts/refill_diagnose.py:107`
- `skills/openai-pool-refill-workflow/scripts/refill_diagnose.py:108`
- `skills/openai-pool-refill-workflow/scripts/refill_diagnose.py:113`

这说明它本质是“repo 内诊断器”，不是“独立可安装 skill”。

### 2.2 它没有抽取补号逻辑，只是在读配置和源码

它做的是：

- 正则提取默认值
- 读取本地配置
- 输出 blockers / findings

见：
- `skills/openai-pool-refill-workflow/scripts/refill_diagnose.py:25`
- `skills/openai-pool-refill-workflow/scripts/refill_diagnose.py:106`
- `skills/openai-pool-refill-workflow/scripts/refill_diagnose.py:163`

这不是“把补号逻辑抠出来”，只是“围着当前源码做静态诊断”。

### 2.3 它不会查询平台实时状态

当前脚本明确说明：

- 不调用外部平台 API
- gap 依赖手动快照 `data/refill_snapshot.json`

见：
- `skills/openai-pool-refill-workflow/scripts/refill_diagnose.py:90`
- `skills/openai-pool-refill-workflow/scripts/refill_diagnose.py:184`
- `skills/openai-pool-refill-workflow/README.md:27`
- `skills/openai-pool-refill-workflow/README.md:75`

这直接违背了“skill 自己去 CPA / Sub2Api 查询账号情况”的需求。

### 2.4 它没有补号执行能力

当前 skill 没有：

- 注册执行器
- 补齐规划器
- 上传执行器
- 统一入口脚本

所以它不是“补号 skill”，只是“补号静态分析器”。

---

## 3. 当前仓库里，真正需要抽取的逻辑分层

如果要做成独立 skill，当前项目里至少要抽出这五层：

1. **配置层**
2. **平台查询与状态分类层**
3. **gap 计算与补齐规划层**
4. **注册执行层**
5. **上传与回写层**

下面逐层说明当前对应代码入口。

---

## 4. 平台查询与状态分类：应从哪里抽

## 4.1 CPA 平台查询与状态分类

关键类：
- `openai_pool_orchestrator/pool_maintainer.py:84` `class PoolMaintainer`

关键方法：
- `fetch_auth_files()`：拉取 auth files
- `get_pool_status()`：统计 candidates 与阈值对比
- `probe_accounts_async()`：探测账号是否 `401` 或额度异常
- `clean_invalid_async()` / `probe_and_clean_sync()`：清理无效账号
- `calculate_gap()`：计算缺口
- `upload_token()`：上传 token 到 CPA

最关键的状态分类逻辑在：
- `openai_pool_orchestrator/pool_maintainer.py:154`
- `openai_pool_orchestrator/pool_maintainer.py:214`
- `openai_pool_orchestrator/pool_maintainer.py:215`
- `openai_pool_orchestrator/pool_maintainer.py:222`

这里已经有：
- `invalid_401`
- `invalid_used_percent`
- `used_percent`

也就是说，**CPA 侧“401 / 额度用完 / 可用”分类能力已经基本存在**，适合抽成独立 client。

### 抽取建议

独立 skill 中应拆为：

- `scripts/cpa_client.py`
  - `fetch_auth_files()`
  - `probe_accounts()`
  - `classify_accounts()`
  - `calculate_gap()`
  - `upload_token()`

其中分类输出建议标准化为：

```json
{
  "available": [],
  "invalid_401": [],
  "invalid_used_percent": [],
  "errors": []
}
```

---

## 4.2 Sub2Api 平台查询与状态分类

关键类：
- `openai_pool_orchestrator/pool_maintainer.py:345` `class Sub2ApiMaintainer`

关键方法：
- `get_dashboard_stats()`
- `list_accounts()` / `_list_all_accounts()`
- `get_pool_status()`
- `probe_and_clean_sync()`
- `calculate_gap()`

最关键的状态判断逻辑：
- `openai_pool_orchestrator/pool_maintainer.py:483` `_is_abnormal_status()`
- `openai_pool_orchestrator/pool_maintainer.py:901` `get_pool_status()`
- `openai_pool_orchestrator/pool_maintainer.py:968` `probe_and_clean_sync()`

与 CPA 不同，Sub2Api 当前主要是按账号状态字段判断异常，不是按 `used_percent` 做分类。

### 抽取建议

独立 skill 中应拆为：

- `scripts/sub2api_client.py`
  - `login_if_needed()`
  - `list_accounts()`
  - `classify_accounts()`
  - `calculate_gap()`
  - `upload_account()` 或等价 push 能力
  - `cleanup_or_recover_accounts()`

建议输出标准化结构，例如：

```json
{
  "available": [],
  "abnormal": [],
  "duplicates": [],
  "errors": []
}
```

如果目标是统一 skill 输出层，需做一层抽象：

- CPA 使用 `401 / used_percent`
- Sub2Api 使用 `status abnormal / duplicate / normal`

不能直接共用一套原始字段。

---

## 5. gap 计算与补齐决策：应从哪里抽

关键入口：
- `openai_pool_orchestrator/server.py:3056` `_try_auto_register()`

这是当前仓库的“补号总控函数”。

它负责：

1. 判断 `auto_register` 是否开启
2. 判断是否配置固定代理或代理池
3. 判断当前 `_state.status` 是否允许启动任务
4. 分别计算：
   - `cpa_gap`
   - `sub2api_gap`
5. 根据 `upload_mode` 合成总 gap：
   - `snapshot`：`cpa_gap + sub2api_gap`
   - `decoupled`：`max(cpa_gap, sub2api_gap)`
6. 调用 `_state.start_task(...)`

对应位置：
- `openai_pool_orchestrator/server.py:3083`
- `openai_pool_orchestrator/server.py:3093`
- `openai_pool_orchestrator/server.py:3104`
- `openai_pool_orchestrator/server.py:3118`
- `openai_pool_orchestrator/server.py:3131`

### 抽取建议

独立 skill 中不要照搬 `_try_auto_register()`，而要拆成：

- `scripts/refill_planner.py`
  - `compute_platform_gaps(config, cpa_status, sub2api_status)`
  - `compute_total_gap(upload_mode, cpa_gap, sub2api_gap, auto_sync)`
  - `should_refill(config, runtime_state, gaps)`
  - `build_refill_plan(...)`

这里要特别注意：

当前仓库依赖 `_state.status` 来避免重复启动，但独立 skill 未必有这个全局任务状态对象，因此需要重新设计“运行锁 / 单实例保护”机制。

---

## 6. 注册执行层：应从哪里抽

关键入口：
- `openai_pool_orchestrator/register.py:877` `run(...)`

这是当前项目真正的注册主流程，内部包含：

- 代理选择
- 代理池 fallback
- 邮箱提供商选择
- OAuth / OTP / token 获取
- token 结果构造

### 关联依赖

它不是一个孤立函数，至少依赖：

- `mail_providers.py`
  - `MailProvider`
  - `MultiMailRouter`
- 代理池配置与取号逻辑
- token 文件写入
- 若干内部 helper

### 抽取难点

这是当前仓库中**最难抽的一层**。原因：

1. `register.py` 逻辑很长，helper 高耦合
2. 它依赖当前包内路径和运行态常量
3. 邮箱路由与 provider 配置都绑在当前项目配置结构上

### 抽取建议

如果做独立 skill，最现实的拆法不是“复制一个 `run(...)`”，而是：

- `scripts/register_runner.py`
- `scripts/mail_router.py`
- `scripts/mail_providers/*.py`
- `scripts/proxy_pool.py`
- `scripts/token_store.py`

也就是说：

**注册层必须整体迁移，不适合只抽单个函数。**

---

## 7. 上传与回写层：应从哪里抽

### 7.1 CPA 上传

现成入口：
- `openai_pool_orchestrator/pool_maintainer.py:322` `upload_token()`

这部分相对独立，好抽。

### 7.2 Sub2Api 上传

当前仓库的 Sub2Api 同步逻辑不在单独的 maintainer 方法里，而是散落在 `server.py` 启动任务后的处理链里，尤其是：

- `openai_pool_orchestrator/server.py:1129` `_auto_sync(...)`
- 其内部调用 `_push_account_api_with_dedupe(...)`
- 以及围绕 token 文件、本地去重标记、已有账号更新的处理

### 抽取建议

独立 skill 中应把它收敛为：

- `scripts/uploader.py`
  - `upload_to_cpa(token_data, file_name, config)`
  - `upload_to_sub2api(token_data, config)`
  - `mark_local_state(...)`（如果 skill 需要本地持久化）

特别注意：

Sub2Api 上传链路在当前项目里比 CPA 更复杂，因为它带：
- 去重
- 账号已存在时更新凭据
- 重试与状态判断

所以抽取时不能只抄一个 HTTP POST，要把 dedupe/update 语义一起梳理出来。

---

## 8. 当前 skill 与目标 skill 的本质差异

### 当前 skill 是什么

- 针对当前 repo 的静态诊断器
- 帮 Claude 看懂补号链路
- 不执行平台查询
- 不执行补齐
- 不执行上传

### 目标 skill 应是什么

- 一个独立可安装的补号执行器
- 带自己的配置
- 带自己的平台 client
- 带自己的注册运行器
- 带自己的上传器
- 能独立完成：查询 → 分类 → 算 gap → 补齐 → 上传

所以差异不是“少几个脚本”，而是：

**当前 skill 站在“分析 repo”的视角；目标 skill 站在“执行补号闭环”的视角。**

---

## 9. 独立 skill 推荐目录结构

如果真的按目标需求抽，建议目录结构至少是：

```text
independent-refill-skill/
├── SKILL.md
├── README.md
├── requirements.txt
├── assets/
│   └── config.example.json
├── scripts/
│   ├── main.py
│   ├── config_loader.py
│   ├── cpa_client.py
│   ├── sub2api_client.py
│   ├── refill_planner.py
│   ├── register_runner.py
│   ├── uploader.py
│   ├── token_store.py
│   ├── proxy_pool.py
│   ├── mail_router.py
│   └── mail_providers/
│       ├── __init__.py
│       ├── base.py
│       ├── mailtm.py
│       ├── moemail.py
│       ├── duckmail.py
│       └── cloudflare_temp.py
└── references/
    ├── workflow.md
    └── troubleshooting.md
```

这是“真正独立”所需的最小合理形态。

---

## 10. 抽取优先级建议

如果按落地复杂度排序，建议这样拆：

### Phase 1：先抽平台查询与 gap 计算

先实现：
- CPA client
- Sub2Api client
- 状态分类
- gap 计算
- 独立配置读取

这样先能完成“查当前池够不够”。

### Phase 2：再抽上传层

再实现：
- CPA 上传
- Sub2Api 上传
- 去重与更新逻辑

这样能完成“注册结果如何落平台”。

### Phase 3：最后抽注册层

最后迁移：
- `register.py`
- `mail_providers.py`
- 代理池逻辑

这是最重的一层。

结论：

**最难抽的是注册层，不是平台状态查询层。**

---

## 11. 结论

### 已证实的事实

1. 现有 `skills/openai-pool-refill-workflow/` 不满足目标需求。
2. 它没有把补号能力抽出来，只是围绕当前 repo 做静态诊断。
3. 如果要做成独立 skill，至少要抽出：
   - 平台查询 client
   - 状态分类逻辑
   - gap 规划器
   - 注册执行层
   - 上传层
4. 其中：
   - CPA 状态分类与上传相对好抽
   - Sub2Api 查询/维护中等复杂
   - 注册层最难抽，必须整体迁移

### 最核心判断

如果只是想验证“我的方案是否可行”，答案是：

**可行，但不是把当前 skill 补两三个脚本就能成，而是要按模块迁移，尤其要把 `register.py + mail_providers.py + 上传链路` 整体内嵌到 skill。**

也就是说，这不是“优化现有 skill”，而是：

**基于当前项目已有实现，重新封装一个独立执行型 skill。**