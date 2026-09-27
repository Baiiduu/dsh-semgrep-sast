# Windows directory scan timeout: compatibility pin

Bundle 0.2.2 uses managed Windows runtime 0.1.1, pinned to **Semgrep 1.163.0**.
This is a compatibility rollback, not an upstream engine patch. The system-runtime
option still uses the executable configured by its owner.

## Cause and decision

The previous runtime bundled Semgrep 1.175.0. Its ignore-cache construction walks
the entire project before target filtering. On Windows, pnpm Junction cycles can
make that walk recurse through unrelated `node_modules` directories even when the
requested target is a small source directory. Downloading Registry rules succeeds
before this happens; increasing the timeout does not address the traversal.

Upstream source comparison locates the eager-cache change between
[1.163.0](https://github.com/semgrep/semgrep/blob/v1.163.0/libs/gitignore/Gitignore_cache.ml)
and [1.164.0](https://github.com/semgrep/semgrep/blob/v1.164.0/libs/gitignore/Gitignore_cache.ml).
The behavior remains in
[1.175.0](https://github.com/semgrep/semgrep/blob/v1.175.0/libs/gitignore/Gitignore_cache.ml).

We select the last version before that change, using the official Windows wheel
and its complete, hash-locked dependency set. The Semgrep constraint also requires
compatible versions of Click, MCP and PyJWT; other dependency pins are retained.
CPython remains at 3.14.7. No source tree, Junction or ignore file is modified by
the scan. There is no subdirectory `--project-root` override, custom file expansion,
or replacement ignore-rule implementation.

The tradeoff is that features and fixes added after Semgrep 1.163.0 are unavailable
in the managed runtime. Registry rules may change independently of this pin.
Remove the pin only after a newer official runtime passes the Junction/ignore
regression below and the Registry smoke test. This does not claim to fix every
possible directory-link topology in upstream Semgrep.

## Diagnostics

The bundle requests verbose stderr instead of quiet mode. JSON stdout remains the
only result input. Harness still bounds stderr capture to 1 MiB; error messages
retain at most 4,000 characters of stderr plus a truncation marker, including both
its beginning and end. Timeouts now include that diagnostic, or explicitly state
that no stderr was captured. An empty diagnostic is not classified as a network
failure. Caller cancellation continues to preserve its original reason.

## Reproducing validation

First assemble the runtime into an empty `runtime/` output directory:

```powershell
powershell -NoProfile -File packages/runtimes/win32-x64/scripts/assemble-runtime.ps1 -ScratchDirectory E:/CodexData/semgrep-build
```

Run the offline regression with the packaged Python and Git available on PATH:

```powershell
packages/runtimes/win32-x64/runtime/python/python.exe packages/runtimes/win32-x64/scripts/test-runtime.py --scratch-directory E:/CodexData/semgrep-tests
```

`--runtime-package PATH` selects another assembled runtime for a control run.
The test uses local rules, a temporary Git repository, and a real Windows Junction
cycle in ignored `node_modules`. It verifies findings as well as scanned paths:

- Root and nested `.gitignore`, `.semgrepignore`, and `:include` exclusions.
- A Git-tracked file whose name is also ignored remains included.
- Untracked source files are scanned.
- Subdirectory, workspace, multiple-target and explicit-file scans have the expected scope.
- Adding the Junction does not change coverage or cause the scan to exceed 45 seconds.

No network rules or credentials are required. Logs are retained under the supplied
scratch directory; the test removes only the Junction itself, without following it.
The ordinary bundle test command covers timeout diagnostics and cancellation.

Local validation on 2026-09-27: all five offline scans completed in approximately
9–14 seconds with Semgrep 1.163.0. The original failing Harness directory also
completed with `p/default`: 210 applicable rules, one scanned TypeScript file,
zero findings (16 seconds with the final, fully locked runtime). Zero findings is a scanner result, not a statement that the code
has no vulnerabilities.

## Packaging

The bundle references the runtime with `workspace:0.1.1`. `pnpm pack` rewrites that
dependency to the runtime package's exact version (0.1.1), so development uses the
local runtime and a release cannot silently retain 0.1.0. Publish the runtime
before publishing the bundle. The runtime's prepack check rejects an absent or
stale payload whose Semgrep version disagrees with the manifest.
A Git push does not update an installed DSH profile;
install the new package pair and restart the profile to activate it.
