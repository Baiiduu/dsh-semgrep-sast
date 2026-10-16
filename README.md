# DSH Semgrep SAST for Claude Code

将 `dsh-semgrep-sast` 0.3.0 的扫描能力接入 Claude Code Mod。模型工具名：

```text
mcp__dsh-semgrep-sast-cc__semgrep_scan
```

保留 `ssc-sast/v1` 结果、CWE 优先级、跨文件分散、源码上下文及离线 `cwe-audit` 规则。扫描由模型显式调用。入口仅注册工具并执行扫描，不包含自动扫描、UI 或 MCP server。

## 安装与使用

需要 **Node.js 24+** 和支持 Mod 的 **Claude Code CLI 2.1.287+**。本版在 Windows x64、Node 24.13.0、Claude Code 2.1.291 上验证。

本版本发布在 fork 仓库的 [`claude-code-mod` 分支](https://github.com/LunTr/dsh-semgrep-sast-cc/tree/claude-code-mod)，插件位于分支根目录。上游项目为 [Baiiduu/dsh-semgrep-sast](https://github.com/Baiiduu/dsh-semgrep-sast)。

```powershell
git clone --branch claude-code-mod --single-branch https://github.com/LunTr/dsh-semgrep-sast-cc.git dsh-semgrep-sast-cc
```

下载后按下述步骤准备 Semgrep 运行时，再从待扫描项目启动 Claude Code。

### Windows x64

复用 `@aaub-software/semgrep-runtime-win32-x64` **0.1.1**，包含 CPython 3.14.7 和 Semgrep 1.163.0。该版本截至 2026-10-07 尚未发布到 npm；从现有 DSH 源码打包安装：

```powershell
# 从同时包含两个项目的目录执行
npm pack ./dsh-semgrep-sast/packages/runtimes/win32-x64 --pack-destination .
cd dsh-semgrep-sast-cc
npm install --no-save --package-lock=false --ignore-scripts ../aaub-software-semgrep-runtime-win32-x64-0.1.1.tgz
```

打包要求原运行时已完成组装；原项目的运行时构建脚本与第三方许可说明位于 `packages/runtimes/win32-x64`。也可以使用已生成的同版本 `.tgz` 文件。运行时安装在本插件自己的 `node_modules` 中，扫描时无需访问原 DSH 目录。

在待扫描项目目录启动 Claude Code，插件参数使用绝对路径：

```powershell
claude --plugin-dir E:/DL/AGENTSFT/dsh-semgrep-sast-cc
```

然后输入：

```text
使用 semgrep_scan，以 cwe-audit 扫描当前项目；优先 CWE-22，返回最多 30 条结果并附带前后 3 行源码。检查输入可达性及已有防护。
```

### 系统 Semgrep / Linux / macOS

Linux/macOS 默认调用 PATH 中的 `semgrep`。Windows 可以通过环境变量指定已安装的 Semgrep 可执行文件：

```powershell
$env:DSH_SEMGREP_EXECUTABLE = 'C:/tools/semgrep/Scripts/semgrep.exe'
claude --plugin-dir E:/DL/AGENTSFT/dsh-semgrep-sast-cc
```

该变量是单个可执行文件路径，不接受 shell 命令或附加参数。Linux/macOS 的代码路径尚未实机验证。

插件加载后 `/plugin` 显示活动 Mod，修改后可执行 `/reload-plugins`。本版的入口遵循 Claude Mod API；DeepSeek Harness 对这些 API 的兼容性需要在其 Mod 宿主上单独验证。

## 参数与返回值

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `paths` | `["."]` | 工作区相对文件或目录，至少一项 |
| `ruleset` | `p/default` | Registry 规则；`cwe-audit` 使用随包离线规则 |
| `focus_cwes` | `[]` | 如 `["CWE-22"]`，在截断前优先排序 |
| `diversify` | `false` | 在同一相关性级别内按文件轮转 |
| `context_lines` | `0` | 匹配起始行前后各 0–20 行 |
| `max_findings` | `200` | 返回 1–200 条 finding |

返回 `schemaVersion: "ssc-sast/v1"`，包含 `status`、`scanner`、`scannedPaths`、`findings`、`diagnostics`、`summary`。解析警告/错误对应 `partial`；finding 数量截断单独由 `summary.truncated` 表示。扫描失败以明确错误返回，调用方应据此报告扫描未完成。

`cwe-audit` 的匹配用于定位候选代码，需检查输入来源、可达性和防护。源码片段作为待分析数据处理。

## 最小适配范围

```text
.claude-plugin/plugin.json   Claude 插件清单
hooks/hooks.json             hooks module 入口
hooks/register.js            session.start 注册工具；tool.call 处理扫描
scripts/scan.mjs             JSON stdin → 独立 Node runner → JSON stdout
lib/runner.js                参数/路径校验、运行时解析、进程控制
lib/parser.js                复用原 Semgrep JSON 解析
lib/agent-result.js          复用原排序与 ssc-sast/v1 转换
lib/source-context.js        复用原源码片段提取
rules/cwe-audit.json         原离线审计规则
```

Mod hook 通过 `$.process.run` 启动 Node runner。Node API 留在外部进程中，符合 [Mod API 运行环境](https://code.claude.com/docs/en/plugins/mods/api#reach-files-processes-and-the-network)。三个复用模块从原 TypeScript 去除类型生成，协议版本常量固定为 `ssc-sast/v1`，因此运行时无需 Cordis、DSH 服务或编译步骤。

更新共享逻辑时，在本目录执行：

```powershell
node scripts/sync-core.mjs ../dsh-semgrep-sast
```

权限采用 [Claude Mod 的宿主权限模型](https://code.claude.com/docs/en/plugins/mods/overview#what-a-mod-can-reach)。进程使用当前用户权限，原 Harness 的 `sandbox_permissions` / `justification` 参数由此移除。相对路径、realpath 越界检查约束扫描目标；这层检查不提供 OS 沙箱隔离。工具未注册权限自动批准逻辑。

扫描使用只读 Semgrep 参数、关闭 metrics 与版本检查。`p/default` 需要联网获取 Registry 规则；`cwe-audit` 从本地加载。每次扫描使用独立临时目录，结束后清理。扫描超时 300 秒，Mod 进程调用超时 310 秒；runner 处理取消和进程树终止。Semgrep stdout 上限 32 MiB、stderr 上限 1 MiB，返回 JSON 上限 512 KiB；超限提示缩小扫描范围。源码上下文沿用单文件 512 KiB、总片段 24,000 字符上限。

## 验证

```powershell
npm test
claude plugin validate --strict .
claude plugin test .

# 加上真实 Windows 离线扫描
$env:SEMGREP_TEST_MANIFEST = "$PWD/node_modules/@aaub-software/semgrep-runtime-win32-x64/runtime-manifest.json"
npm test
```

测试覆盖协议转换、CWE 排序、partial/truncation、路径与符号链接越界、超时、取消、输出上限、真实离线扫描，以及官方 Mod 宿主中的工具注册、stdin/cwd 传递、错误和其他工具放行。官方 Mod 测试使用进程桩；真实 Semgrep 扫描由 Node 集成测试验证。

2026-10-07 验证结果：严格验证通过，9 项 Node 测试与 4 项官方 Mod 测试通过；额外通过实际 CLI 扫描含中文和空格的文件名。尚未进行真实模型会话中的自动工具选择测试。

## 发布渠道（2026-10-07 核对）

Mod 随 Claude Plugin 分发，可使用以下渠道：

1. **Anthropic Directory**：在 [开发者门户](https://claude.ai/directory/manage) 提交 Plugin bundle；填写 GitHub 仓库与插件子目录。需要有资格的付费计划、连接的 GitHub 账号及仓库写权限；公开上架前仓库须公开。提交、验证与审核流程见[官方提交文档](https://claude.com/docs/plugins/submit)。Mod 功能运行于 Claude Code，跨产品支持以[组件支持表](https://claude.com/docs/plugins/platform-support)为准。
2. **自建 Plugin Marketplace**：在托管仓库放置 `.claude-plugin/marketplace.json`，用户通过 `/plugin marketplace add OWNER/REPO` 添加，再 `/plugin install dsh-semgrep-sast-cc@MARKETPLACE` 安装。见[创建 marketplace](https://code.claude.com/docs/en/plugin-marketplaces)。
3. **目录或 ZIP 分享**：用户下载后通过 `claude --plugin-dir <目录或zip>` 加载。见[分发文档](https://code.claude.com/docs/en/plugins/publish)。

Anthropic Directory 与 `claude-plugins-official` 是不同的发布入口；官方文档说明，后者通过 Anthropic 合作联系人咨询上架。Directory 的本地验证通过后，门户还会运行额外规则检查。

公开目录上架前需落实 Windows 运行时的分发：上传 0.1.1 npm 包或提供带第三方许可的运行时包。Claude 安装插件后仍需上述运行时安装步骤；本插件不会自动下载依赖。源码通过 fork 仓库的 `claude-code-mod` 分支分发，尚未提交外部插件目录。

## English

A minimal Claude Code Mod port of DSH Semgrep SAST 0.3.0. It registers
`mcp__dsh-semgrep-sast-cc__semgrep_scan` using `$.tool.register` and handles calls
through `$.process.run`. The standalone Node runner retains `ssc-sast/v1`, CWE
prioritization, finding diversification, bounded source context, and offline audit
rules. Requires Node 24+ and Claude Code CLI 2.1.287+.

Install the existing Windows runtime 0.1.1 tarball in this directory with
`npm install --no-save --package-lock=false --ignore-scripts <tarball>`, or set
`DSH_SEMGREP_EXECUTABLE` to a system Semgrep executable. That runtime version is
not on npm as of 2026-10-07. Linux/macOS use `semgrep` from PATH by default.
Start Claude in the target project with `claude --plugin-dir <absolute-plugin-path>`.
The runtime is installed separately; marketplace installation does not install it.

This port uses Claude Mod host permissions. Harness-specific approval parameters
are removed. Run `npm test`, `claude plugin test .`, and
`claude plugin validate --strict .` for verification. The original project remains
the upstream source of the three reused core modules and the rules (MIT).
