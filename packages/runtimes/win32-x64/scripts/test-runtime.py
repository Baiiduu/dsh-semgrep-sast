"""Offline Windows regression test; requires the assembled runtime and Git.

Run with the packaged Python, passing --scratch-directory for test artifacts.
No Registry downloads or account credentials are used. Fixtures/logs are retained
for diagnosis; the Junction is removed before returning.
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-package", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--scratch-directory", type=Path, required=True)
    args = parser.parse_args()
    package = args.runtime_package.resolve()
    manifest = json.loads((package / "runtime-manifest.json").read_text(encoding="utf-8-sig"))
    args.scratch_directory.mkdir(parents=True, exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix="semgrep-regression-", dir=args.scratch_directory)).resolve()
    project = scratch / "project"
    project.mkdir()
    files = {
        ".gitignore": "node_modules/\n/src/root-hidden.py\n/src/tracked-ignored.py\n",
        ".semgrepignore": "/src/semgrep-hidden.py\n:include extra.ignore\n",
        "extra.ignore": "/src/included-hidden.py\n",
        "src/.gitignore": "nested-hidden.py\n",
        "src/keep.py": "eval(user_input)\n",
        "src/untracked.py": "eval(user_input)\n",
        "src/root-hidden.py": "eval(user_input)\n",
        "src/nested-hidden.py": "eval(user_input)\n",
        "src/semgrep-hidden.py": "eval(user_input)\n",
        "src/included-hidden.py": "eval(user_input)\n",
        "src/tracked-ignored.py": "eval(user_input)\n",
        "other/outside-target.py": "eval(user_input)\n",
    }
    for name, contents in files.items():
        target = project / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(contents, encoding="utf-8")
    subprocess.run(["git", "init", "--quiet", str(project)], check=True)
    subprocess.run(["git", "add", "-f", "src/keep.py", "src/tracked-ignored.py"], cwd=project, check=True)
    rules = scratch / "rules.yml"
    rules.write_text("""rules:
  - id: regression-eval
    languages: [python]
    severity: WARNING
    message: Regression fixture
    pattern: eval($X)
""", encoding="utf-8")
    env = os.environ.copy()
    for key in list(env):
        if key.startswith("SEMGREP_") or key in {"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"}:
            del env[key]
    env.update(manifest["environment"])
    env.update(TEMP=str(scratch), TMP=str(scratch), SEMGREP_ENABLE_VERSION_CHECK="0")
    command = [str(package / manifest["launcher"]["executable"]), *manifest["launcher"]["arguments"],
               "scan", "--json", "--verbose", "--metrics=off", "--config", str(rules)]

    def scan(name, targets):
        started = time.monotonic()
        with (scratch / f"{name}.json").open("wb") as out, (scratch / f"{name}.log").open("wb") as err:
            child = subprocess.Popen(command + targets, cwd=project, env=env, stdout=out, stderr=err)
            try:
                code = child.wait(timeout=45)
            except subprocess.TimeoutExpired:
                subprocess.run(["taskkill", "/PID", str(child.pid), "/T", "/F"], capture_output=True)
                child.wait(timeout=10)
                raise AssertionError(f"{name} exceeded 45s; logs: {scratch}")
        assert code == 0, f"{name} exited {code}; logs: {scratch}"
        report = json.loads((scratch / f"{name}.json").read_text(encoding="utf-8"))
        assert report["version"] == manifest["semgrepVersion"], report["version"]
        assert report["errors"] == [], report["errors"]
        paths = {path.replace("\\", "/") for path in report["paths"]["scanned"]}
        findings = {finding["path"].replace("\\", "/") for finding in report["results"]}
        assert findings == paths, (findings, paths)
        print(f"{name}: {time.monotonic() - started:.2f}s, {sorted(paths)}", flush=True)
        return paths

    # Establish the native ignore behavior before introducing the unrelated loop.
    baseline = scan("baseline", ["src"])
    assert baseline == {"src/keep.py", "src/untracked.py", "src/tracked-ignored.py"}, baseline
    (project / "node_modules").mkdir()
    junction = project / "node_modules" / "cycle"
    import _winapi
    _winapi.CreateJunction(str(project), str(junction))
    try:
        assert scan("junction-subdirectory", ["src"]) == baseline
        assert scan("junction-workspace", ["."]) == baseline | {"other/outside-target.py"}
        assert scan("junction-multiple-targets", ["src", "other"]) == baseline | {"other/outside-target.py"}
        assert scan("explicit-file", ["src/keep.py"]) == {"src/keep.py"}
    finally:
        # Remove only the Junction itself, never recurse into its target.
        os.rmdir(junction)
    print(f"PASS: offline ignore/scope/Junction regression; artifacts: {scratch}")


if __name__ == "__main__":
    main()
