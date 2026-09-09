"""在隔离容器里采集一个仓库状态的可执行证据（proposal.md §3.5）。

仓库以**只读**挂到容器 /src，容器内复制到 /work 再跑，所以验证过程不可能
改动被评分的快照（output/audit F-005）。工具版本固定在镜像里，base 和
treated 用的是同一把尺子。
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

IMAGE = os.environ.get("PROM_EVIDENCE_IMAGE", "prom/evidence:0.2")
INTEREST = ("readme", "contributing", "license", "security", "pyproject.toml",
            "setup.py", "setup.cfg", "makefile", "tox.ini", "dockerfile")


def probe_in_container(repo: Path, cpus: str, memory: str, timeout: int) -> dict:
    # 探针必须能联网：D5 问的是"干净环境能不能通过单一入口装起来"，
    # 断网会让 pip 无条件失败，把环境问题误记成仓库问题（第一版就栽在这）。
    # pip 缓存挂成共享卷，torch 这类大依赖只下一次。
    cache = Path(os.environ.get("PROM_PIP_CACHE",
                            "/data/SWE-Prometheus/cache/prom-pip"))
    cache.mkdir(parents=True, exist_ok=True)
    cmd = ["docker", "run", "--rm",
           "-v", f"{repo.resolve()}:/src:ro",          # 只读，F-005
           "-v", f"{cache}:/root/.cache/pip",
           "-e", f"PIP_INDEX_URL={os.environ.get('PIP_INDEX_URL', 'https://pypi.tuna.tsinghua.edu.cn/simple')}",
           "-e", f"PROBE_INSTALL_TIMEOUT={os.environ.get('PROBE_INSTALL_TIMEOUT', '900')}",
           f"--cpus={cpus}", f"--memory={memory}",
           "--name", f"prom-probe-{repo.name[:20]}-{abs(hash(str(repo))) % 10**6}",
           IMAGE]
    p = subprocess.run(cmd, capture_output=True, text=True,
                       errors="replace", timeout=timeout)
    if p.returncode != 0 and not p.stdout.strip():
        return {"container_error": p.stderr[-2000:], "benchmark_probes": {},
                "declared_commands": {}}
    try:
        return json.loads(p.stdout)
    except json.JSONDecodeError:
        return {"container_error": f"探针输出不是 JSON: {p.stdout[-800:]}",
                "benchmark_probes": {}, "declared_commands": {}}


def static_shape(repo: Path) -> dict:
    files = sorted(p.relative_to(repo).as_posix()
                   for p in repo.rglob("*")
                   if p.is_file() and ".git/" not in p.as_posix())
    docs = {}
    for f in files:
        if f.split("/")[-1].lower().startswith(INTEREST) and f.count("/") <= 1:
            try:
                docs[f] = (repo / f).read_text(encoding="utf-8", errors="ignore")[:4000]
            except Exception:
                pass
    ci = {}
    for f in [x for x in files if x.startswith(".github/workflows/")][:5]:
        try:
            ci[f] = (repo / f).read_text(encoding="utf-8", errors="ignore")[:2500]
        except Exception:
            pass
    return {
        "file_count": len(files),
        "py_file_count": sum(1 for f in files if f.endswith(".py")),
        "test_file_count": sum(1 for f in files
                               if f.startswith(("tests/", "test/"))
                               or f.split("/")[-1].startswith("test_")),
        "tree_sample": files[:400], "docs": docs, "ci_workflows": ci,
    }


def render(ev: dict, label: str) -> str:
    L = [f"# Repository state: {label}", ""]
    if ev.get("container_error"):
        L += ["## PROBE ENVIRONMENT FAILURE", "```", ev["container_error"], "```",
              "", "Treat this as missing evidence, not as a governance failure.", ""]

    dg = ev.get("declared_governance") or {}
    if dg:
        L += ["## Declared governance",
              "What the repository **itself** declares. This answers Q1 of the scoring",
              "table: does the mechanism exist? It is independent of whether it works.", ""]
        for k, v in dg.items():
            L.append(f"- `{k}`: {json.dumps(v, ensure_ascii=False)}")
        L.append("")

    L += ["## Benchmark probes",
          "Fixed commands, identical for BASE and TREATED, run in an isolated container",
          "with pinned tool versions. `exit_code` 0 = succeeded, non-zero = failed,",
          "null = could not run. **These are the comparable measurements.**",
          "",
          "Note: `lint` and `typecheck` run on every repository regardless of whether it",
          "declares such a gate. If `declares_lint_config` / `declares_typecheck_config`",
          "is false, treat their output as a neutral code-health reading, **not** as a",
          "failing gate belonging to this repository."]
    for k, r in (ev.get("benchmark_probes") or {}).items():
        L.append(f"\n### {k}\n- command: `{r.get('cmd')}`\n- exit_code: {r.get('exit_code')}")
        if r.get("error"):
            L.append(f"- error: {r['error']}")
        for s in ("stdout_tail", "stderr_tail"):
            if (r.get(s) or "").strip():
                L.append(f"- {s}:\n```\n{r[s][-1400:]}\n```")

    L += ["", "## Commands the repository declares for itself",
          "Makefile targets and CI `run:` steps. **The agent can rewrite these,**",
          "so they are context, not a comparable measurement."]
    dc = ev.get("declared_commands") or {}
    if not dc:
        L.append("\n(none found)")
    for k, r in dc.items():
        L.append(f"\n### {k}\n- command: `{r.get('cmd')}`\n- exit_code: {r.get('exit_code')}")
        for s in ("stdout_tail", "stderr_tail"):
            if (r.get(s) or "").strip():
                L.append(f"- {s}:\n```\n{r[s][-900:]}\n```")

    sh = ev.get("shape") or {}
    L += ["", "## Repository shape",
          f"- files: {sh.get('file_count')}, python files: {sh.get('py_file_count')}, "
          f"test files: {sh.get('test_file_count')}"]
    L += ["", "## CI workflows"]
    L += [f"\n### {f}\n```yaml\n{c}\n```" for f, c in (sh.get("ci_workflows") or {}).items()] or ["(none)"]
    L += ["", "## Key documents"]
    L += [f"\n### {f}\n```\n{c[:2500]}\n```" for f, c in (sh.get("docs") or {}).items()] or ["(none)"]
    L += ["", "## File listing (first 400)", "```", *(sh.get("tree_sample") or []), "```"]
    return "\n".join(L)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", type=Path, required=True)
    ap.add_argument("--label", required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--json-output", type=Path, default=None)
    ap.add_argument("--cpus", default="2")
    ap.add_argument("--memory", default="4g")
    ap.add_argument("--timeout", type=int, default=2400)
    a = ap.parse_args()

    ev = probe_in_container(a.repo, a.cpus, a.memory, a.timeout)
    ev["shape"] = static_shape(a.repo)
    a.output.write_text(render(ev, a.label), encoding="utf-8")
    if a.json_output:
        a.json_output.write_text(json.dumps(ev, ensure_ascii=False, indent=1))

    if ev.get("container_error"):
        print(f"{a.label}: 容器失败 — {ev['container_error'][:120]}", file=sys.stderr)
    else:
        codes = {k: r.get("exit_code") for k, r in ev["benchmark_probes"].items()}
        print(f"{a.label}: {codes}")


if __name__ == "__main__":
    main()
