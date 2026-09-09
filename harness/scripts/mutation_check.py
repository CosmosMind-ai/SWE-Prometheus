#!/usr/bin/env python3
"""验证补丁的判别力检验（变异测试）。

补丁在 BASE 全绿、在 TREATED 也全绿，只能说明“没检测到变化”，不能说明
“有能力检测变化”。如果它对任何代码树都全绿，这道行为闸门就是摆设，
“60/60 preserved” 这个结论也就没有意义。

做法：给 BASE 注入一个人工的行为变异（把数值常量 +1、布尔取反），再跑同一
套 tests_verify。测试**应该变红**。仍然全绿 = 该补丁无判别力。
"""
from __future__ import annotations

import argparse, ast, json, os, shutil, subprocess, sys, tempfile, threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

DS = Path(__file__).resolve().parent.parent
IMAGE = os.environ.get("PROM_EVIDENCE_IMAGE", "prom/evidence:0.2")
SKIP = {"tests_verify", "test", "tests", ".git", "node_modules", "venv", ".venv"}
_lock = threading.Lock()


def log(m: str) -> None:
    with _lock:
        print(f"[{datetime.now():%H:%M:%S}] {m}", flush=True)


class Mutator(ast.NodeTransformer):
    """把数值常量 +1、布尔取反。足够改变行为，又不会破坏语法。"""
    def __init__(self) -> None:
        self.n = 0

    def visit_Constant(self, node: ast.Constant) -> ast.Constant:
        if isinstance(node.value, bool):
            self.n += 1
            return ast.copy_location(ast.Constant(value=not node.value), node)
        if isinstance(node.value, (int, float)) and not isinstance(node.value, bool):
            self.n += 1
            return ast.copy_location(ast.Constant(value=node.value + 1), node)
        return node


def mutate_tree(root: Path, limit: int | None = None) -> int:
    """变异**整棵树**，不设上限。

    第一版设了 limit=40 并 break，结果只变异了按字母序排在最前面的一两个
    文件——测试根本不 import 那些文件，于是 60 个实例全判 BLIND。那是我的
    抽样问题，不是补丁没有判别力。要证明补丁瞎，必须把它够得着的地方全改掉。
    """
    total = 0
    for f in sorted(root.rglob("*.py")):
        if any(p in SKIP for p in f.parts) or f.name.startswith("test_"):
            continue
        try:
            src = f.read_text(errors="replace")
            tree = ast.parse(src)
        except Exception:
            continue
        m = Mutator()
        new = m.fix_missing_locations(m.visit(tree)) if hasattr(m, "fix_missing_locations") \
              else ast.fix_missing_locations(m.visit(tree))
        if not m.n:
            continue
        try:
            f.write_text(ast.unparse(new))
        except Exception:
            continue
        total += m.n
        if limit is not None and total >= limit:
            break
    return total


def parse_pytest(out: str) -> dict:
    """从 pytest 摘要里抽 passed/skipped/failed。

    `N skipped` 的退出码是 0，也就是“绿”。一套全 skip 的测试能让闸门空跑
    通过——必须和真正的 passed 分开统计，否则“行为保持”是个假结论。
    """
    import re as _re
    r = {}
    for kind in ("passed", "failed", "skipped", "error", "errors"):
        m = _re.search(r"(\d+) " + kind + r"\b", out)
        if m:
            r["error" if kind == "errors" else kind] = int(m.group(1))
    m = _re.search(r"in ([\d.]+)s", out)
    if m:
        r["seconds"] = float(m.group(1))
    return r


def run_tests(work: Path, cpus: str, mem: str, timeout: int = 1500) -> tuple[int, str]:
    # set -o pipefail 是必须的：管道的退出码取自最后一个命令，也就是 tail，
    # 而 tail 永远成功。没有它，run_tests 恒返回 0，测试红了也看不出来——
    # 第一版就是这样把 4 个实例全判成 BLIND 的。
    script = (
        "set -o pipefail; "
        "for f in requirements.txt requirements-dev.txt requirements/base.txt; do "
        "  [ -f \"$f\" ] && pip install -q -r \"$f\" 2>/dev/null; done; "
        "{ [ -f setup.py ] || [ -f pyproject.toml ]; } && pip install -q -e . 2>/dev/null; "
        "pip install -q pytest 2>/dev/null; "
        "python -m pytest tests_verify -q --no-header -p no:cacheprovider 2>&1 | tail -25"
    )
    p = subprocess.run(
        ["docker", "run", "--rm", "--entrypoint", "bash",
         f"--cpus={cpus}", f"--memory={mem}",
         "--name", f"prom-mut-{abs(hash(str(work)))%10**6}",
         "-v", f"{work.resolve()}:/workspace",
         "-v", os.environ.get("PROM_PIP_CACHE",
                 "/data/SWE-Prometheus/cache/prom-pip") + ":/root/.cache/pip",
         "-e", "PIP_INDEX_URL=" + os.environ.get(
             "PIP_INDEX_URL", "https://pypi.tuna.tsinghua.edu.cn/simple"),
         "-w", "/workspace", IMAGE, "-lc", script],
        capture_output=True, text=True, errors="replace", timeout=timeout)
    return p.returncode, (p.stdout or "")[-800:]


def one(inst: dict, cpus: str, mem: str) -> dict:
    rid, repo = inst["instance_id"], inst["repo"]
    src = DS / "runs" / rid / "base_snapshot"
    patch = DS / "instances" / f"{rid}.verify.patch"
    if not src.is_dir() or not patch.exists():
        return {"instance_id": rid, "verdict": "missing"}
    tmp = Path(tempfile.mkdtemp(prefix="mut-", dir=str(DS / "work")))
    work = tmp / "repo"
    try:
        shutil.copytree(src, work, symlinks=True)
        subprocess.run(["git", "apply", "--3way", "--whitespace=nowarn", str(patch)],
                       cwd=work, capture_output=True, text=True)
        if not (work / "tests_verify").is_dir():
            return {"instance_id": rid, "verdict": "patch_apply_failed"}
        rc0, out0 = run_tests(work, cpus, mem)
        base = parse_pytest(out0)
        if rc0 != 0:
            return {"instance_id": rid, "repo": repo, "verdict": "base_not_green",
                    "base": base, "tail": out0[-200:]}
        # 全 skip 的补丁根本没有闸门作用，单独归类，不要混进 BLIND
        if base.get("passed", 0) == 0 and base.get("skipped", 0) > 0:
            log(f"■ {repo:45s} VACUOUS（{base['skipped']} 条全 skip）")
            return {"instance_id": rid, "repo": repo, "verdict": "VACUOUS",
                    "base": base, "tail": out0[-300:]}
        n = mutate_tree(work)
        if n == 0:
            return {"instance_id": rid, "repo": repo, "verdict": "no_mutation_site"}
        rc1, out1 = run_tests(work, cpus, mem)
        mut = parse_pytest(out1)
        v = "DETECTED" if rc1 != 0 else "BLIND"
        log(f"■ {repo:45s} {v}  变异点 {n}  base={base}  变异后={mut}")
        return {"instance_id": rid, "repo": repo, "verdict": v, "mutations": n,
                "base": base, "mutated": mut, "tail": out1[-300:]}
    except subprocess.TimeoutExpired:
        return {"instance_id": rid, "verdict": "timeout"}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--instances", type=Path, default=DS / "data" / "final60.json")
    ap.add_argument("--output", type=Path, default=DS / "data" / "mutation_check.json")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--cpus", default="1")
    ap.add_argument("--memory", default="3g")
    a = ap.parse_args()

    insts = json.load(open(a.instances))
    if a.limit:
        # 按测试数分层抽样，强/中/弱都要覆盖
        import collections
        vp = {json.loads(l)["repo"]: json.loads(l).get("n_tests", 0)
              for l in open(DS / "data" / "verify_patches.jsonl")}
        insts.sort(key=lambda i: vp.get(i["repo"], 0))
        step = max(1, len(insts) // a.limit)
        insts = insts[::step][:a.limit]
    (DS / "work").mkdir(exist_ok=True)
    log(f"变异测试 {len(insts)} 个实例，并发 {a.workers}")

    res = []
    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        for f in as_completed([ex.submit(one, i, a.cpus, a.memory) for i in insts]):
            res.append(f.result())
            a.output.write_text(json.dumps(res, ensure_ascii=False, indent=1))

    import collections
    c = collections.Counter(r["verdict"] for r in res)
    log("")
    log(f"完成 {len(res)}  {dict(c)}")
    eff = c["DETECTED"] + c["BLIND"]
    if eff:
        log(f"判别力: {c['DETECTED']}/{eff} = {100*c['DETECTED']/eff:.0f}% 的补丁能抓到人工变异")
    if c["VACUOUS"]:
        log(f"空跑闸门（全 skip，形同虚设）: {c['VACUOUS']}")


if __name__ == "__main__":
    main()
