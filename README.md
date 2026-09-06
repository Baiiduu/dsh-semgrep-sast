# DeepSeek Harness Semgrep SAST

[English](#english) | [简体中文](#简体中文)

## English

`@aaub-software/dsh-semgrep-sast` is a Cordis bundle that exposes the model-facing
`semgrep_scan` tool in [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness).
It runs read-only Semgrep SAST scans against files and directories inside the current
workspace and returns bounded, structured findings for the agent to review in source
context.

The default managed runtime currently supports **Windows x64**. It includes CPython
3.14.7 and Semgrep 1.175.0, so users do not need to install Python or Semgrep separately.

### Install

DeepSeek Harness requires Node.js 24 or newer. Install the prebuilt bundle into the
profile you use, for example `web`:

```powershell
dsh plugin --profile web add @aaub-software/dsh-semgrep-sast
```

Restart that profile after installation. The agent will then see a tool named
`semgrep_scan`.

The bundle uses the managed Windows runtime by default. Installing the npm package also
installs `@aaub-software/semgrep-runtime-win32-x64` on compatible systems.

### Tool behavior

`semgrep_scan` accepts:

| Parameter | Required | Description |
| --- | --- | --- |
| `paths` | No | Workspace-relative files or directories. Defaults to the workspace root. |
| `ruleset` | No | Rule configuration. Version 0.1 supports only `p/default`. |
| `sandbox_permissions` | Only for an approved retry | `workspace-write` or `danger-full-access`. |
| `justification` | With `sandbox_permissions` | One sentence shown with the permission request. |

Absolute paths, paths that escape the workspace, and symlinks resolving outside the
workspace are rejected. Autofix is not exposed. Semgrep metrics are disabled.

Results contain the Semgrep version, scanned paths, exact finding locations,
diagnostics, duration, total and returned finding counts, and an explicit truncation
flag. Findings are capped at 200 by the default bundle configuration. A `partial`
status means Semgrep reported scan diagnostics; it does not mean that every returned
finding is a confirmed vulnerability.

### Windows permission approval

Semgrep Core cannot open the Windows system certificate store inside the current
DeepSeek Harness ACL sandbox. To keep the wider permission explicit, the first
restricted call does not start Semgrep. It returns the standard Harness sandbox-denial
marker and asks the model to retry the same scan with:

```json
{
  "sandbox_permissions": "danger-full-access",
  "justification": "Run the requested Semgrep scan because Semgrep Core cannot access the Windows certificate store inside the Harness ACL sandbox."
}
```

Harness then asks the user for approval. The scan runs only after approval. Wider
access is never requested silently or treated as a standing permission by this tool.

### Security and resource controls

- Scan targets must remain inside the active workspace.
- Scans are read-only and do not offer autofix.
- Metrics are disabled with `--metrics=off` and `SEMGREP_SEND_METRICS=off`.
- Cache, configuration, settings, version-cache, and log locations are redirected to
  the scan's temporary environment.
- Harness process services enforce cancellation, a five-minute default timeout, a
  two-second termination grace period, and process-tree termination.
- Captured stdout is limited to 32 MiB and stderr to 1 MiB. Oversized JSON output fails
  closed instead of returning incomplete JSON.
- Model-facing findings are deterministically ordered and capped; truncation is
  reported separately from partial scan coverage.

The default `p/default` ruleset is fetched from the Semgrep Registry at scan time, so a
scan requires network access when the rules are not already available in the temporary
environment. Registry rules are not redistributed by this project.

### Configuration

The shipped bundle layer uses:

```yaml
- insert:
    - id: semgrep-sast
      name: '@aaub-software/dsh-semgrep-sast'
      config:
        runtimeMode: bundled
        defaultRuleset: p/default
        timeoutMs: 300000
        maxFindings: 200
```

Advanced deployments may select `runtimeMode: system`, but must also provide an
explicit `executable`. The managed runtime is the supported zero-install path for
Windows x64.

### Development

```powershell
pnpm install
pnpm typecheck
pnpm build
```

The repository is a pnpm workspace. The DSH bundle is under `packages/bundle`, and the
managed runtime package is under `packages/runtimes/win32-x64`.

### Licenses

The bundle code is released under the MIT License. The managed runtime is an aggregate
distribution whose components retain their upstream licenses. See
`packages/runtimes/win32-x64/THIRD_PARTY_NOTICES.md` and the packaged license files for
details. Semgrep Registry rules are covered by their own rules license.

## 简体中文

`@aaub-software/dsh-semgrep-sast` 是一个面向
[DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) 的 Cordis 组合包，
向模型注册 `semgrep_scan` 工具。它只扫描当前工作区内的文件或目录，并返回有大小
限制的结构化结果，供 Agent 结合源码上下文继续复核。

当前默认托管运行时支持 **Windows x64**，内置 CPython 3.14.7 和 Semgrep 1.175.0，
用户不需要另外安装 Python 或 Semgrep。

### 安装

DeepSeek Harness 需要 Node.js 24 或更高版本。将已经构建好的 npm 组合包安装到实际
使用的 profile，例如 `web`：

```powershell
dsh plugin --profile web add @aaub-software/dsh-semgrep-sast
```

安装后重启该 profile，模型即可看到 `semgrep_scan` 工具。在兼容平台上，npm 会同时
安装 `@aaub-software/semgrep-runtime-win32-x64` 托管运行时。

### 工具行为

`semgrep_scan` 接受以下参数：

| 参数 | 是否必需 | 说明 |
| --- | --- | --- |
| `paths` | 否 | 工作区相对文件或目录；默认扫描工作区根目录。 |
| `ruleset` | 否 | 规则配置；0.1 版本只支持 `p/default`。 |
| `sandbox_permissions` | 仅批准重试时 | 可选值为 `workspace-write` 或 `danger-full-access`。 |
| `justification` | 与权限参数一起使用 | 展示给用户的一句话权限申请理由。 |

插件会拒绝绝对路径、逃逸工作区的路径，以及最终解析到工作区外的符号链接。它不提供
autofix，并关闭 Semgrep 指标上报。

结果包含 Semgrep 版本、实际扫描路径、发现的精确位置、诊断信息、耗时、发现总数、
返回数量以及明确的截断标志。默认最多向模型返回 200 条发现。`partial` 表示 Semgrep
报告了影响覆盖范围的诊断，并不表示返回的每一项都已经被确认是漏洞。

### Windows 权限批准流程

Semgrep Core 在当前 DeepSeek Harness Windows ACL 沙箱内无法打开系统证书库。为了让
扩大权限始终经过明确批准，第一次受限调用不会启动 Semgrep，而是返回 Harness 标准的
沙箱拒绝标记，并提示模型使用完全相同的扫描参数，加上以下字段重试：

```json
{
  "sandbox_permissions": "danger-full-access",
  "justification": "运行用户要求的 Semgrep 扫描，因为 Semgrep Core 无法在 Harness Windows ACL 沙箱内访问系统证书库。"
}
```

随后由 Harness 向用户请求批准，只有批准后才会运行扫描。插件不会静默扩大权限，也不
会把这次批准当作工具自身的永久权限。

### 安全与资源控制

- 扫描目标必须位于当前工作区。
- 扫描只读，不提供 autofix。
- 通过 `--metrics=off` 和 `SEMGREP_SEND_METRICS=off` 关闭指标上报。
- 缓存、配置、设置、版本缓存和日志位置被重定向到本次扫描的临时环境。
- 使用 Harness 进程服务实现取消、默认五分钟超时、两秒终止宽限期和进程树终止。
- stdout 最大 32 MiB，stderr 最大 1 MiB；JSON 输出超限时直接失败，不返回残缺 JSON。
- 发现按确定顺序排列并限制数量；结果截断与扫描覆盖不完整分别报告。

默认 `p/default` 规则集在扫描时从 Semgrep Registry 获取。因此，当规则尚未存在于临时
环境中时，扫描需要网络访问。本项目不重新分发 Registry 规则。

### 配置

组合包默认配置为：

```yaml
- insert:
    - id: semgrep-sast
      name: '@aaub-software/dsh-semgrep-sast'
      config:
        runtimeMode: bundled
        defaultRuleset: p/default
        timeoutMs: 300000
        maxFindings: 200
```

高级部署可以选择 `runtimeMode: system`，但必须同时提供明确的 `executable`。Windows
x64 用户的免安装支持路径是默认托管运行时。

### 开发

```powershell
pnpm install
pnpm typecheck
pnpm build
```

仓库使用 pnpm workspace。DSH 组合包位于 `packages/bundle`，托管运行时包位于
`packages/runtimes/win32-x64`。

### 许可证

组合包代码使用 MIT 许可证。托管运行时是聚合二进制发行包，其中各组件继续适用各自的
上游许可证。详细信息见 `packages/runtimes/win32-x64/THIRD_PARTY_NOTICES.md` 及包内许可证
文件；Semgrep Registry 规则另行适用其规则许可证。
