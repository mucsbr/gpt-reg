# Claude Code Skill 创建指南

基于创建 vuln-checker skill 的实践经验总结。

## 核心概念

Claude Code Skills 是可重用的工作流程，通过 `SKILL.md` 文件定义，可以包含可执行脚本。当用户的查询匹配 skill 的描述时，Claude 会自动加载并使用该 skill。

## 标准文件结构

```
skill-name/
├── SKILL.md                    # 必需：Skill 定义文件（大写）
├── requirements.txt            # 可选：Python 依赖
├── scripts/                    # 可选：可执行脚本目录
│   ├── main_script.py
│   └── data_file.json
├── references/                 # 可选：详细文档
│   ├── api_reference.md
│   └── troubleshooting.md
└── README.md                   # 可选：使用说明
```

## SKILL.md 格式规范

### 1. YAML Frontmatter（必需）

```yaml
---
name: skill-name                    # 必需：kebab-case，最多 64 字符
description: 详细描述何时使用此 skill。包含触发关键词和使用场景。  # 必需：最多 200 字符
argument-hint: [optional-arg]       # 可选：参数提示
dependencies:                       # 可选：依赖说明
  - python3
  - pip
user-invocable: true                # 可选：是否显示在 / 菜单
disable-model-invocation: false     # 可选：是否禁止自动触发
---
```

### 2. Description 编写技巧

**关键原则：要"pushy"一点，避免 undertrigger**

❌ 不好的描述：
```yaml
description: Check vulnerabilities for packages
```

✅ 好的描述：
```yaml
description: Check known security vulnerabilities for OpenClaw, Clawdbot, or Moltbot packages by version number. Use when the user asks to check vulnerabilities, security issues, CVEs, or GHSA advisories for these packages, or when they mention version numbers like "2026.3.2" in the context of security or updates. Also use when analyzing scan results that include version information for these packages.
```

**要点：**
- 明确说明"何时使用"（when to use）
- 包含具体的触发关键词
- 列举相关的使用场景
- 包含同义词和相关术语

### 3. Markdown 内容结构

```markdown
# Skill 标题

简短的一句话说明 skill 的目的。

## When to Use This Skill

- 用户询问 X 时
- 用户提到 Y 时
- 用户需要 Z 时

## How It Works

简要说明工作原理。

## Usage

### Step 1: 第一步

详细说明和命令示例。

### Step 2: 第二步

...

## Important Notes

重要提示和注意事项。

## Error Handling

常见错误和解决方案。

## Examples

实际使用示例。
```

## Python 脚本最佳实践

### 1. 文件组织

**推荐：脚本和数据放在同一目录**

```
scripts/
├── main_script.py
└── data_file.json          # 脚本可以直接访问同目录文件
```

**原因：**
- 避免路径问题
- 脚本执行时可以直接找到数据文件
- 减少 Claude 出错的可能性

### 2. 路径引用

在 SKILL.md 中使用完整路径：

```bash
# ✅ 推荐：使用完整路径
python3 ${CLAUDE_SKILL_DIR}/scripts/main_script.py arg1 arg2

# ❌ 避免：需要 cd 的命令
cd ${CLAUDE_SKILL_DIR}/scripts
python3 main_script.py arg1 arg2
```

### 3. 依赖管理

**Claude Code 自动依赖管理：**
- 自动检测 `ModuleNotFoundError`
- 自动运行 `pip install`
- 无需手动安装

**requirements.txt 位置：**
- 放在 skill 根目录
- 格式标准：`package>=version`

```txt
packaging>=21.0
requests>=2.28.0
```

**在 SKILL.md 中说明：**
```markdown
## Dependencies

Claude Code will automatically install missing dependencies. If automatic installation fails:

```bash
pip3 install -r ${CLAUDE_SKILL_DIR}/requirements.txt
```
```

### 4. 脚本可执行权限

```bash
chmod +x scripts/main_script.py
```

添加 shebang：
```python
#!/usr/bin/env python3
```

## 常见陷阱和解决方案

### 陷阱 1：路径问题

**问题：** 脚本和数据分在不同目录，执行时找不到数据文件。

**解决：** 将脚本和数据放在同一目录（如 `scripts/`）。

### 陷阱 2：Description 太简单

**问题：** Claude 不知道何时触发 skill（undertrigger）。

**解决：** 写详细的 description，包含所有可能的触发场景和关键词。

### 陷阱 3：手动依赖管理

**问题：** 要求用户手动安装依赖。

**解决：** 依赖 Claude Code 的自动安装功能，只在失败时提供手动方案。

### 陷阱 4：使用相对路径

**问题：** `cd` 到某个目录再执行命令，容易出错。

**解决：** 始终使用 `${CLAUDE_SKILL_DIR}` 的完整路径。

### 陷阱 5：文件名错误

**问题：** 使用 `skill.json` 或 `Skill.md`（小写）。

**解决：** 必须使用 `SKILL.md`（全大写）。

## 参考优秀 Skill

### 1. NotebookLM Skill
- **特点：** 复杂的浏览器自动化
- **亮点：** `run.py` 包装器自动管理虚拟环境
- **链接：** https://github.com/PleasePrompto/notebooklm-skill

### 2. Anthropic 官方 Skills
- **特点：** 官方标准实现
- **亮点：** 完整的 references 目录，详细文档
- **链接：** https://github.com/anthropics/skills

### 3. XLSX Skill
- **特点：** 处理 Excel 文件
- **亮点：** 假设依赖已安装，首次运行自动配置
- **链接：** https://github.com/anthropics/skills/tree/main/skills/xlsx

## 测试和调试

### 1. 本地测试脚本

在创建 skill 之前，先单独测试脚本：

```bash
cd scripts/
python3 main_script.py test_arg
```

### 2. 安装 Skill

```bash
# 使用符号链接（推荐，便于开发）
ln -s /path/to/your/skill ~/.claude/skills/skill-name

# 或复制
cp -r /path/to/your/skill ~/.claude/skills/
```

### 3. 测试触发

在 Claude Code 中尝试：
- 直接调用：`/skill-name arg1 arg2`
- 自然语言：使用 description 中的关键词

### 4. 检查日志

如果 skill 没有触发，检查：
- description 是否包含用户使用的关键词
- SKILL.md 文件名是否正确（大写）
- 文件是否在正确的位置

## 发布和分享

### 1. 必需文件

- `SKILL.md` - 核心定义
- `README.md` - 使用说明
- `LICENSE` - 许可证

### 2. 可选但推荐

- `CHANGELOG.md` - 版本历史
- `.gitignore` - 忽略敏感文件
- `examples/` - 使用示例

### 3. README.md 内容

```markdown
# Skill Name

简短描述

## 安装

安装命令

## 使用

使用示例

## 依赖

依赖说明

## 故障排除

常见问题
```

## 进阶技巧

### 1. 使用 Subagents

对于复杂任务，可以在 SKILL.md 中指定使用 subagent：

```yaml
---
name: complex-skill
context: fork                       # 在隔离的 subagent 中运行
agent: Explore                      # 使用 Explore agent
---
```

### 2. 限制工具使用

```yaml
---
allowed-tools: Read, Grep, Bash     # 只允许使用这些工具
---
```

### 3. 多脚本协作

使用 `run.py` 包装器统一管理多个脚本：

```python
#!/usr/bin/env python3
import sys
import subprocess
from pathlib import Path

def main():
    if len(sys.argv) < 2:
        print("Usage: python run.py <script_name> [args...]")
        sys.exit(1)

    script_name = sys.argv[1]
    script_args = sys.argv[2:]

    skill_dir = Path(__file__).parent.parent
    script_path = skill_dir / "scripts" / f"{script_name}.py"

    subprocess.run([sys.executable, str(script_path)] + script_args)

if __name__ == "__main__":
    main()
```

### 4. 配置文件

对于需要配置的 skill，使用 JSON 或 YAML 配置文件：

```
scripts/
├── config.json
└── main_script.py
```

在脚本中读取：
```python
import json
from pathlib import Path

config_path = Path(__file__).parent / "config.json"
with open(config_path) as f:
    config = json.load(f)
```

## 总结

### 核心原则

1. **简单优先**：不要过度设计，单脚本 skill 不需要复杂的包装器
2. **路径清晰**：使用完整路径，避免 cd 命令
3. **描述详细**：description 要包含所有触发场景
4. **依赖自动**：依赖 Claude Code 的自动依赖管理
5. **测试充分**：先测试脚本，再测试 skill 触发

### 检查清单

创建 skill 前的检查：

- [ ] SKILL.md 文件名正确（大写）
- [ ] YAML frontmatter 包含 name 和 description
- [ ] description 详细说明触发条件
- [ ] 脚本和数据在同一目录
- [ ] 使用 ${CLAUDE_SKILL_DIR} 完整路径
- [ ] requirements.txt 在根目录
- [ ] 脚本有执行权限
- [ ] 本地测试脚本可运行
- [ ] README.md 包含安装和使用说明

### 参考资源

- **官方文档：** https://code.claude.com/docs/en/skills
- **官方 Skills 仓库：** https://github.com/anthropics/skills
- **Skill 规范：** https://agentskills.io
- **社区 Skills：** https://playbooks.com/skills

---

**最后更新：** 2026-03-12
**基于项目：** vuln-checker skill for OpenClaw/Clawdbot/Moltbot