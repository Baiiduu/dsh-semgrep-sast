# DeepSeek Harness Semgrep SAST

`@aaub-software/dsh-semgrep-sast` is a Cordis bundle that registers the
model-facing `semgrep_scan` tool in
[DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness).

The default managed runtime supports Windows x64 and includes CPython 3.14.7
and Semgrep 1.175.0. Users do not need to install Python or Semgrep separately.

## Install

DeepSeek Harness and Node.js 24 or newer are required. Install the bundle into
the profile you use, for example:

```powershell
dsh plugin --profile web add @aaub-software/dsh-semgrep-sast
```

Restart the profile after installation. The agent will then see the
`semgrep_scan` tool.

## Behavior and safety

- Scans only workspace-relative files and directories.
- Rejects paths and resolved symlinks that escape the active workspace.
- Uses the Semgrep Registry `p/default` ruleset in version 0.1.
- Does not expose autofix and disables Semgrep metrics.
- Redirects Semgrep cache, settings, configuration, and logs to the temporary
  scan environment.
- Supports Harness cancellation, timeout, process-tree termination, bounded
  subprocess output, and bounded model-facing findings.
- Returns structured findings for contextual review; a rule match is not by
  itself a confirmed vulnerability.

On Windows, Semgrep Core cannot open the system certificate store inside the
current Harness ACL sandbox. A restricted first call does not start the scan.
Instead, it returns the standard permission-escalation hint. The model may retry
the same scan with `sandbox_permissions: "danger-full-access"` and a concise
`justification`; Harness asks the user for approval before execution.

The default ruleset is obtained from the Semgrep Registry at scan time and may
require network access. Registry rules are not redistributed by this package.

## Documentation and source

See the
[repository documentation](https://github.com/Baiiduu/dsh-semgrep-sast#readme)
for the complete English and Chinese guide, configuration reference, security
controls, development instructions, and third-party license information.

Source: [Baiiduu/dsh-semgrep-sast](https://github.com/Baiiduu/dsh-semgrep-sast)

