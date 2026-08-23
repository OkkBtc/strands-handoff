# strands-handoff

[English](README.md) | **简体中文**

[![CI](https://github.com/OkkBtc/strands-handoff/actions/workflows/ci.yml/badge.svg)](https://github.com/OkkBtc/strands-handoff/actions/workflows/ci.yml)
[![许可证](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

面向 [Strands Agents](https://github.com/strands-agents/harness-sdk) 的离线会话移交、脱敏与完整性检查工具。

`strands-handoff` 将 Python `FileSessionManager` 会话打包为便携的 `.strandpack`，用于审查、传递和比较。全部操作在本地完成，不调用 LLM，也不上传会话数据。

脱敏仅是尽力而为，当前实现也没有经过独立安全审计。它不能替代完整的秘密或个人信息扫描；传递每个 pack 前都应人工检查。

## 功能

- **尽力脱敏导出：** 优先应用已经持久化的 Strands `redact_message`，再处理敏感键以及若干常见凭据、Token、邮箱和用户目录模式。
- **完整性检查：** 在版本化清单中记录文件大小和 SHA-256，并在查看或提取前验证。
- **批量校验：** 一条命令检查多个 pack，可同时生成每个完整归档的指纹，输出全部结果后再返回统一退出状态。
- **只读检查：** 汇总 Agent、消息、角色、工具调用、脱敏计数和 Artifact，不修改源会话。
- **已验证文件清单：** 完整性检查通过后，可列出每个打包路径、字节数和清单 SHA-256。
- **传输指纹：** 可计算完整 `.strandpack` 文件的哈希，用于传输前后核对。
- **会话分支：** 使用新会话 ID 创建完整副本，或者创建不可恢复运行的消息边界审查分支。
- **结构化差异：** 显示新增、删除、变化的文件以及各 Agent 的消息数量变化，并可用退出状态直接接入 CI。
- **交接摘要：** 根据已验证的 pack 生成 Markdown 报告。
- **Artifact 命名空间：** 按显式命名空间打包工具输出，并记录文件数和字节用量。
- **适合自动化的输出：** 为导出、验证、检查、差异比较和提取提供 JSON 摘要。
- **提取预演：** 写入前先验证 pack，并报告准确的目标会话目录。
- **防御性提取：** 拒绝目录穿越、重复条目、符号链接、不支持的顶层路径、清单外文件，以及大小或摘要不匹配。

## 安装

需要 Python 3.10+，运行时没有第三方依赖。

```bash
git clone https://github.com/OkkBtc/strands-handoff.git
cd strands-handoff
python -m venv .venv
source .venv/bin/activate
python -m pip install .
strands-handoff --version
```

## 快速开始

导出由 Strands `FileSessionManager` 创建的会话：

```bash
strands-handoff export \
  --storage-dir ~/.strands/sessions \
  --session-id support-123 \
  --output support-123.strandpack
```

源目录只读。导出器拒绝符号链接和不支持的非 JSON 会话文件。

如需获得包含 pack 绝对路径、文件数、脱敏计数和 Artifact 元数据的机器可读结果：

```bash
strands-handoff export \
  --storage-dir ~/.strands/sessions \
  --session-id support-123 \
  --output support-123.strandpack \
  --json > export-result.json
```

如果源会话 ID 包含账号或客户身份，可以只替换 pack 内的 ID，无需重命名源目录：

```bash
strands-handoff export \
  --storage-dir ~/.strands/sessions \
  --session-id account-123 \
  --handoff-session-id case-001 \
  --output case-001.strandpack
```

不解包就完成验证和只读查看：

```bash
strands-handoff verify support-123.strandpack
strands-handoff verify support-123.strandpack --json
strands-handoff inspect support-123.strandpack
strands-handoff inspect support-123.strandpack --json
```

审计准确的打包路径，并为传输记录生成指纹：

```bash
strands-handoff inspect support-123.strandpack --files
strands-handoff inspect support-123.strandpack \
  --files \
  --sha256 \
  --json > inventory.json
```

`--files` 会输出每个载荷文件在已验证清单中的路径、大小和 SHA-256；`--sha256`
会计算 `.strandpack` 归档准确字节的哈希，可在复制或上传前后进行比较。这两类摘要都
不能认证创建者，也不能替代数字签名。

在传递或归档前批量校验：

```bash
strands-handoff verify support-123.strandpack support-124.strandpack
strands-handoff verify support-123.strandpack support-124.strandpack \
  --sha256 \
  --json > verification.json
```

即使前面的 pack 失败，命令仍会检查所有输入；只要任意 pack 校验失败，最终退出状态
就是 `1`。`--sha256` 会为每个通过校验的归档增加 `pack_sha256` 指纹，使同一份批量
结果既能记录完整性，也能用于传输前后核对。归档指纹可以发现字节变化，但不能认证
创建者身份。

生成 Markdown 交接报告：

```bash
strands-handoff summary support-123.strandpack --output HANDOFF.md
```

使用新会话 ID 创建完整副本分支：

```bash
strands-handoff branch support-123.strandpack \
  --new-session-id support-123-qa \
  --output support-123-qa.strandpack
```

创建截止到某个 Agent 消息边界的只读审查分支：

```bash
strands-handoff branch support-123.strandpack \
  --new-session-id support-123-review \
  --agent-id triage-agent \
  --through-message 12 \
  --output support-123-review.strandpack
```

不调用模型，直接比较两个 pack：

```bash
strands-handoff diff support-123.strandpack support-123-review.strandpack
strands-handoff diff support-123.strandpack support-123-review.strandpack --json
strands-handoff diff support-123.strandpack support-123-review.strandpack \
  --exit-code
```

默认情况下，只要比较成功，`diff` 即使发现变化也返回状态 `0`。使用 `--exit-code`
后，相同载荷仍返回 `0`，只要有文件新增、删除或变化就返回 `1`，因此可以直接作为
CI 门禁；pack 无效时仍返回状态 `2`。

验证完整副本 pack，并在不写入任何内容的前提下预览准确目标：

```bash
strands-handoff extract support-123-qa.strandpack \
  --destination ./received-sessions \
  --dry-run \
  --json
```

计划会显示解析后的目标根目录、`session_<id>` 目录和将写入的文件数，并验证 pack
完整性、可恢复标记、会话 ID 和目标目录冲突。预演不会创建目标目录或临时目录，但
不能证明最终写入时一定有足够磁盘空间或写权限。

确认计划后再执行提取：

```bash
strands-handoff extract support-123-qa.strandpack --destination ./received-sessions
strands-handoff extract support-123-qa.strandpack \
  --destination ./received-sessions \
  --json
```

结果包含 `received-sessions/session_support-123-qa/`。提取只负责验证并写出存储目录；无论预演还是实际提取，CLI 都不会启动 Strands，也不会验证运行时恢复。恢复仍需要兼容的 Strands 版本、相同的 Agent 身份以及兼容的 Agent 配置。已有目标目录不会被覆盖；消息边界审查分支不能提取为运行时会话。

## Artifact 打包

每个 Artifact 目录都必须指定独立命名空间：

```bash
strands-handoff export \
  --storage-dir ~/.strands/sessions \
  --session-id support-123 \
  --artifact research=./artifacts/research \
  --artifact screenshots=./artifacts/screenshots \
  --output support-123.strandpack
```

UTF-8 文本和 JSON Artifact 会经过脱敏；文件路径一旦命中已知敏感模式就会被拒绝。其他类型按二进制处理，由于无法可靠扫描内容，默认阻止；只有人工检查后才应使用 `--allow-binary-artifacts`，且清单会记录未扫描的二进制文件数量。单文件默认上限为 25 MiB，可用 `--max-artifact-mib` 调整。

## Pack 格式

`.strandpack` 是如下结构的 ZIP 容器：

```text
manifest.json
session/session.json
session/agents/agent_<id>/agent.json
session/agents/agent_<id>/messages/message_<n>.json
artifacts/<namespace>/...
```

清单记录兼容性参考、脱敏分类计数、Artifact 用量、文件大小和 SHA-256。校验能够发现与清单不一致的文件，但不能认证 pack 创建者，也不能替代数字签名。

## 兼容性与限制

- 当前实现支持 [UPSTREAM.md](UPSTREAM.md) 中说明的 Python `FileSessionManager` 消息日志结构，不支持 Strands snapshot 存储。
- 完整副本分支使用新的会话 ID 保留已导出的元数据和消息；能否成功恢复仍取决于兼容的 Strands、Agent ID、工具和状态结构。
- 消息边界分支只删除之后的消息文件，用于离线审查和比较。由于 `agent.json` 保存的是最新状态，它不是运行时回退，并被标记为 `restorable: false`。
- 模式脱敏不是完整的秘密或个人信息扫描器。分享前仍需人工检查，尤其是允许二进制 Artifact 时。
- CLI 不执行工具、不重放模型调用、不上传 pack，也不实现 Strands 运行时编排器的 Agent handoff。

## 开发与验证

```bash
python -m pip install -e '.[dev]'
ruff check .
ruff format --check .
pyright
pytest
python -m build
```

全部测试使用合成会话运行，不需要 Provider 凭据。

## 安全

不要在公开 Issue 中附带真实 session pack、Token 或客户数据。私密报告方式和安全边界见 [SECURITY.md](SECURITY.md)。

## 许可证与上游

`strands-handoff` 使用 Apache-2.0 许可证。本项目是独立社区项目，与 Strands Agents 维护者不存在关联，也未获得其背书。兼容性参考与归属说明见 [UPSTREAM.md](UPSTREAM.md) 和 [NOTICE](NOTICE)。
