<div align="center">

# 🐱 civet

**只要能跑 Python 的地方，就能跑的工作流安全审计器。**

36 条确定性规则 · 零依赖 · 证据式输出 · SARIF 直传 CI · 自带 MCP Server

[![CI](https://github.com/xuange-hu/civet/actions/workflows/ci.yml/badge.svg)](https://github.com/xuange-hu/civet/actions/workflows/ci.yml)
[![tests](https://img.shields.io/badge/tests-163%20passing-brightgreen.svg)](tests/)
[![rules](https://img.shields.io/badge/rules-36-red.svg)](#规则表)
[![Dependencies](https://img.shields.io/badge/dependencies-0-blue.svg)](pyproject.toml)
[![MCP](https://img.shields.io/badge/MCP-4%20tools-green.svg)](https://modelcontextprotocol.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[English](README.md) · [简体中文](README_CN.md)

</div>

---

## 为什么还要再做一个

`zizmor`（6.7k★，Rust）和 `actionlint`（4.3k★，Go）都很强。但它们都是**编译好的二进制**，
你得先下载；而且 `actionlint` 不做安全审计，`zizmor` 不做通用 lint。

`civet` 是第三种形态：

| | zizmor | actionlint | **civet** |
|---|---|---|---|
| 实现 | Rust 二进制 | Go 二进制 | **纯 Python，0 依赖** |
| 安装 | 下载 release | 下载 release | **`pip install civet-audit`** |
| 离线 / 隔离网可用 | 需要二进制 | 需要二进制 | **能，只用标准库** |
| YAML 解析 | serde_yaml | 自研 | **自研，因此能保住行号** |
| 证据（file:line + 原文） | 有 | 有 | **有，每条结论下面都附原始行** |
| 讲清攻击链 | 有 | 部分 | **`civet explain CIV201`，逐条叙事** |
| SARIF 2.1.0 | 有 | 有 | 有 |
| MCP Server | 无 | 无 | **4 个工具** |

零依赖不是为了省事，是重点本身：**在你的 CI 那个瘦身容器里跑不起来的扫描器，
你最终就不会去跑它。**

## 安装

```bash
pip install civet-audit
# 或者什么都不装：
uvx --from civet-audit civet .
```

## 三步跑通

```bash
# 1. 先看效果——扫一个故意写坏的工作流
civet demo

# 2. 扫自己的仓库
civet scan .

# 3. 读懂最严重的那条
civet explain CIV201
```

只要 Python ≥ 3.10，别的都不需要。无 API Key、不联网、不调模型 ——
扫描结果是磁盘字节的纯函数，同一份代码两次跑必然同一份报告。

## 输出长什么样

以下是 `civet demo` 的真实输出（只保留 high 及以上）：

```
  scanning ./civet-demo  ·  2 workflow file(s)  ·  36 rules

  .github/workflows/civet-demo.yml
    line 13   HIGH     CIV205  Self-hosted runner reachable from a fork-triggered event
                    job: build
                    Job 'build' runs on a self-hosted runner under ['issue_comment', 'pull_request_target'].
                    › runs-on: self-hosted
    line 15   CRITICAL CIV201  pwn request: pull_request_target + checkout of PR head
                    job: build / step: actions/checkout@v4
                    pull_request_target checks out PR head code while holding a privileged token.
                    › - uses: actions/checkout@v4
    line 20   CRITICAL CIV101  Untrusted event data interpolated into run:
                    job: build / step: Greet the contributor
                    run: interpolates attacker-controlled `${{ github.event.pull_request.title }}`.
                    › - name: Greet the contributor

  52 findings  ·  critical 3  high 10  medium 22  low 13
  Risk score: 100/100 → CRITICAL RISK
```

每条都带：**行号**、所属 **job 与 step**、具体**原因**，以及**原始源码行**（`›`）——
你可以自己复核，而不是选择相信。

## `explain`：真正教人的那部分

```console
$ civet explain CIV201

CIV201  CRITICAL  [trigger]
  pwn request: pull_request_target + checkout of PR head

  WHY
    pull_request_target runs with the base repo's token, and checking out
    github.event.pull_request.head.sha executes the fork's code in that context.
    Any attacker PR gets a write-scoped token and access to secrets.

  FIX
    Use pull_request, or split into two workflows: an unprivileged build that
    uploads an artifact and a privileged workflow_run that consumes it.

  CWE-269
```

## 规则表

| 分组 | 数量 | 覆盖内容 |
|---|---|---|
| `injection` | 5 | `${{ github.event.* }}` 进 `run:`、github-script、action 入参、不可信 `if:` |
| `trigger` | 6 | **pwn request**、`pull_request_target`、`workflow_run`、评论触发、self-hosted + fork |
| `supply-chain` | 6 | SHA 固定、分支固定、`persist-credentials`、可变镜像、可复用工作流固定 |
| `secrets` | 5 | `run:` 里的 `GITHUB_TOKEN`、`secrets: inherit`、第三方交接、job 级密钥 |
| `execution` | 5 | `curl \| bash`、`eval`、未固定 `npx`/`uvx`、`set-output`、`GITHUB_ENV` 写入 |
| `artifact` | 3 | 缓存投毒、特权运行上传制品、留存期 |
| `hygiene` | 6 | `permissions:`、`timeout-minutes`、环境保护、并发组 |

```bash
civet rules                    # 全部 36 条及严重级
civet rules | grep injection   # 只看一组
```

## 当 CI 门禁

```yaml
- name: Audit workflows
  run: |
    pip install civet-audit
    civet scan . --fail-on high --min-severity medium
```

退出码：`0` 干净，`1` 存在 `--fail-on` 及以上的发现，`2` 用法错误。默认 `--fail-on high`。

接入 code scanning：

```yaml
- run: civet scan . --format sarif -o civet.sarif --fail-on none
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: civet.sarif
```

对已接受的风险做例外：

```bash
civet scan . --ignore-rule CIV301 --ignore-group hygiene
```

## MCP Server

```bash
pip install "civet-audit[mcp]"
civet-mcp
```

Claude Code / Cursor 配置：

```json
{
  "mcpServers": {
    "civet": {
      "command": "uvx",
      "args": ["--from", "civet-audit[mcp]", "civet-mcp"]
    }
  }
}
```

| 工具 | 作用 |
|---|---|
| `civet_scan` | 扫描路径，返回计数、风险分、带证据的发现 |
| `civet_explain` | 某条规则的攻击叙事与修复 |
| `civet_rules` | 列出规则，可按分组过滤 |
| `civet_demo` | 生成并扫描一个坏工作流，一次调用证明价值 |

## 设计原则

1. **确定性。** 无模型、无网络、不取时钟。同样字节 → 同样报告。
2. **证据优先。** `file:line`、job、step，加原始源码行。
3. **核心零依赖。** `mcp` 放进 extra，CLI 永不 import 它。
4. **不静默失败。** 解析不了的 YAML 进 `errors`，不吞掉。
5. **讲清原因。** 每条规则都带攻击叙事与最小修复。

## 自查（dogfood）

`civet` 会审计作者自己其它仓库的工作流：首次运行就在 `vehsec`（2 个工作流）发现 19 条、
`pcaplens` 19 条、`skillvet` 22 条、`agent-scan` 13 条 —— 其中包括一条真实的
`curl … | sh` 发布管线。这些正在被改掉，而不是被 `--ignore-rule` 压掉。

## 路线图

- [ ] `--fix`：机械性修复（SHA 固定、`persist-credentials`）
- [ ] `actions/*` 版本→SHA 解析（带本地缓存）
- [ ] GitLab CI 与 Jenkinsfile 读取器，复用同一套规则引擎
- [ ] 基线文件（`.civet-baseline.json`），支持渐进接入
- [ ] 结合仓库 API 校验 `environment` 保护规则

## 参与开发

```bash
git clone https://github.com/xuange-hu/civet && cd civet
pip install -e ".[mcp]"
PYTHONPATH=src pytest -q     # 163 个测试
```

新增一条规则要动三处：`rules.py`（id、严重级、why、fix）、`analyze.py`（检测逻辑）、
`demo.py`（一行能把它点亮的样本）。`tests/test_rules.py` 钉住规则 id，
`test_demo.py` 钉住 demo 对规则表的 100% 覆盖。

## 许可

MIT
