"""第三阶段：为每个实例构造「验证补丁」——数据集的核心资产。

要解决的问题：我们挑的是没有测试、没有 CI 的烂仓库（这正是纳入标准），
所以仓库自身提供不了任何行为保持的凭据。reference_pipeline 的
retrofit/verification.py 跑的是仓库自己声明的命令，对这类目标是空转。

于是验证补丁必须由我们构造——一组针对 base_commit 公开行为的
characterization tests：

    补丁 → base    必须 100% 通过   （不通过说明测试本身写错了，实例作废）
    补丁 → treated 必须 100% 通过   （通过才证明 agent 没有靠删代码/改行为骗分）

关键约束（写进 prompt，也在校验层强制）：
  1. 只测公开行为——导入路径、CLI、函数返回值、异常类型。绝不测私有属性、
     文件布局、行号，否则 agent 一做 D4 的结构重构就误判为回归，而结构重构
     恰恰是我们要求它做的。
  2. 不许联网、不许读凭据、不许依赖本机路径，否则评测环境一换就红。
  3. 必须确定性——不用随机数、当前时间、字典序假设。
  4. 放在 tests_verify/ 下，与仓库自己的测试目录隔离，agent 改不到也删不掉
     （评测时是在 agent 交付后才把补丁打上去的）。
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
HARNESS = ROOT.parent / "pi_harness" / "scripts"
sys.path.insert(0, str(HARNESS))
import judge as J                                     # noqa: E402  复用它的 proxy 调用

IMAGE = "prom/evidence:0.1"
TEST_DIR = "tests_verify"
MAX_ROUNDS = int(os.environ.get("PROM_VERIFY_ROUNDS", "3"))

SYSTEM = """\
You write characterization tests that pin down a Python repository's CURRENT
observable behavior, so that a later large-scale refactor can be checked for
behavioral regressions.

You are NOT writing tests that judge whether the behavior is good. You are
recording what it does today, exactly as it is, bugs included.

HARD RULES — a test that breaks any of these makes the whole suite worthless:

1. Test only PUBLIC, STABLE surface: importable module paths and their public
   functions/classes, CLI entry points, documented return values and raised
   exception types.
   NEVER assert on: private names (_foo), internal file layout, line numbers,
   import order, module __file__ paths, or the exact text of log messages.
   The repository WILL be restructured — module files may be moved, split, or
   renamed. Your tests must survive that. Import from the package's top level
   or its documented public submodules only.
2. NO network. NO credentials. NO reading paths outside the repo. NO writing
   outside tmp_path. If a function needs the network, do not test it.
3. DETERMINISTIC. No randomness without a fixed seed, no reliance on the
   current time, no assumptions about dict/set iteration order.
4. Tests must be FAST — the whole file should run in well under a minute.
   Do not load large models, download data, or train anything.
5. If you cannot find enough safely testable public surface, write fewer
   tests. A small suite that passes reliably is worth far more than a large
   one that is flaky. Never pad with vacuous asserts like `assert True`.

Output ONLY the content of a single pytest file. No markdown fences, no prose.
Start with the imports.
"""


def sh(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def repo_overview(repo_dir: Path, max_chars: int = 24000) -> str:
    """给模型一份仓库速览：结构 + README + 顶层包的公开接口。"""
    parts = []
    files = sh(["git", "-C", str(repo_dir), "ls-files"]).stdout.splitlines()
    py = [f for f in files if f.endswith(".py")]
    parts.append("## Files (python)\n" + "\n".join(py[:250]))

    for name in ("README.md", "README.rst", "README.txt", "pyproject.toml", "setup.py"):
        p = repo_dir / name
        if p.exists():
            parts.append(f"## {name}\n" + p.read_text(errors="replace")[:6000])

    # 顶层包的 __init__ 与最大的几个模块，模型据此判断公开接口在哪
    inits = [f for f in py if f.endswith("__init__.py") and f.count("/") <= 1]
    for f in inits[:3]:
        parts.append(f"## {f}\n" + (repo_dir / f).read_text(errors="replace")[:4000])
    biggest = sorted(py, key=lambda f: (repo_dir / f).stat().st_size if (repo_dir / f).exists() else 0,
                     reverse=True)[:4]
    for f in biggest:
        parts.append(f"## {f} (head)\n" + (repo_dir / f).read_text(errors="replace")[:3500])

    blob = "\n\n".join(parts)
    return blob[:max_chars]


def ask_model(repo: str, overview: str, feedback: str | None) -> str | None:
    user = [f"Repository: {repo}", "", overview, "",
            "Write the pytest file now. Put it at "
            f"`{TEST_DIR}/test_characterization.py`."]
    if feedback:
        user += ["", "## Your previous attempt FAILED against the unmodified repo",
                 "These failures mean your tests asserted something untrue about "
                 "current behavior, or depended on something unavailable. Fix them. "
                 "A ModuleNotFoundError or a collection error means that import is "
                 "not available in the test environment — do NOT try to install it, "
                 "just drop every test that needs it and test only what imports "
                 "cleanly, even if that leaves very few tests. "
                 "Delete any test you cannot make pass — a smaller passing suite is "
                 "correct, a failing one is useless.", "```", feedback[-6000:], "```"]
    raw = J.call_teacher("gpt-5.6-sol", SYSTEM, "\n".join(user), timeout=600)
    if not raw:
        return None
    body = raw.strip()
    if body.startswith("```"):                        # 兜底剥 fence
        body = body.split("\n", 1)[1] if "\n" in body else body
        if body.rstrip().endswith("```"):
            body = body.rstrip()[:-3]
    return body.strip() + "\n"


def run_tests(repo_dir: Path, cpus: str, memory: str, timeout: int = 900) -> tuple[bool, str]:
    """在证据镜像里装依赖并跑验证测试。返回 (全绿, 输出尾巴)。"""
    # 依赖装不全是 never_green 的头号原因（首轮 7 个失败里 5 个是
    # ModuleNotFoundError）。原来写成 `-e . || -r requirements.txt`，用 || 短路，
    # `-e .` 一旦成功就再也不装 requirements.txt——而这些烂仓库的运行期依赖
    # 恰恰只写在 requirements.txt 里。改成逐个都试，每个都容错。
    script = (
        "set -o pipefail; "
        "for f in requirements.txt requirements-dev.txt requirements/base.txt; do "
        "  [ -f \"$f\" ] && pip install -q -r \"$f\" 2>/dev/null; done; "
        "[ -f setup.py ] || [ -f pyproject.toml ] && pip install -q -e . 2>/dev/null; "
        "pip install -q pytest 2>/dev/null; "
        f"python -m pytest {TEST_DIR} -q --no-header -p no:cacheprovider 2>&1 | tail -60"
    )
    # 镜像的 ENTRYPOINT 是 python3 /probe.py，必须显式覆盖成 bash，
    # 否则脚本参数会被 probe.py 吞掉（它还只认 /src 这个挂载点）。
    cache = Path(os.environ.get("PROM_PIP_CACHE",
                            "/data/SWE-Prometheus/cache/prom-pip"))
    cache.mkdir(parents=True, exist_ok=True)
    p = sh(["docker", "run", "--rm", "--entrypoint", "bash",
            f"--cpus={cpus}", f"--memory={memory}",
            "--name", f"prom-verify-{abs(hash(str(repo_dir))) % 10**6}",
            "-v", f"{repo_dir.resolve()}:/workspace",
            "-v", f"{cache}:/root/.cache/pip",
            "-e", "PIP_INDEX_URL=" + os.environ.get(
                "PIP_INDEX_URL", "https://pypi.tuna.tsinghua.edu.cn/simple"),
            "-w", "/workspace",
            IMAGE, "-lc", script], timeout=timeout)
    out = (p.stdout or "") + (p.stderr or "")
    return p.returncode == 0, out[-4000:]


def pytest_counts(out: str) -> dict:
    """从 pytest 摘要抽 passed/skipped/failed。

    `N skipped` 的退出码是 0，也就是“绿”。变异测试量过：60 个补丁里 13 个
    在 BASE 上全部 skip（多半是 pytest.importorskip 撞上装不上的重依赖），
    这种闸门对任何代码树都放行，等于没有验证环节。所以“绿”不够，必须
    至少有一条真正 passed。
    """
    r = {}
    for kind in ("passed", "failed", "skipped", "error"):
        m = re.search(r"(\d+) " + kind + r"\b", out)
        if m:
            r[kind] = int(m.group(1))
    return r


def build_one(repo: str, base_commit: str, workdir: Path,
              cpus: str, memory: str) -> dict:
    rec: dict = {"repo": repo, "base_commit": base_commit}
    with tempfile.TemporaryDirectory(dir=workdir) as tmp:
        d = Path(tmp) / "repo"
        if sh(["git", "clone", "--quiet", f"https://github.com/{repo}.git",
               str(d)], timeout=900).returncode != 0:
            rec["status"] = "clone_failed"; return rec
        if sh(["git", "-C", str(d), "checkout", "--quiet", base_commit]).returncode != 0:
            rec["status"] = "checkout_failed"; return rec

        overview = repo_overview(d)
        feedback = None
        for rnd in range(1, MAX_ROUNDS + 1):
            body = ask_model(repo, overview, feedback)
            if not body:
                rec["status"] = "model_unavailable"; return rec
            tdir = d / TEST_DIR
            tdir.mkdir(exist_ok=True)
            (tdir / "test_characterization.py").write_text(body, encoding="utf-8")
            ok, out = run_tests(d, cpus, memory)
            rec[f"round{rnd}_tail"] = out[-1200:]
            counts = pytest_counts(out)
            rec[f"round{rnd}_counts"] = counts
            if ok and counts.get("passed", 0) == 0:
                # 全 skip：退出码是绿的，但闸门是空的。当成失败继续下一轮，
                # 并明确告诉模型别再用 importorskip 挡整个文件。
                ok = False
                out = (out + "\n\n[验收未通过] 测试全部被 skip（" +
                       str(counts.get("skipped", 0)) +
                       " 条），退出码虽为 0 但这道闸门对任何代码都放行。"
                       "请改成只测不需要重依赖（torch/cuda/网络/GPU）的纯逻辑，"
                       "不要用 pytest.importorskip 或 skipif 挡住整个文件，"
                       "必须至少有一条真正执行并通过的测试。")
                feedback = out
                continue
            if ok:
                # 只把 tests_verify/ 打成补丁，绝不夹带仓库本身的改动
                # 必须排除 __pycache__：pytest 跑完会在 tests_verify/ 下留
                # assertion-rewrite 的 .pyc，`add -f` 会把它一起收进补丁，
                # 于是 54 个补丁全都夹带一段二进制 diff、体积翻倍。
                sh(["git", "-C", str(d), "add", "-f", TEST_DIR,
                    "--", f":!{TEST_DIR}/__pycache__"])
                patch = sh(["git", "-C", str(d), "diff", "--cached", "--binary"]).stdout
                n = body.count("def test_")
                rec.update({"status": "ok", "rounds": rnd, "n_tests": n,
                            "n_passed": counts.get("passed", 0),
                            "n_skipped": counts.get("skipped", 0), "patch": patch})
                return rec
            feedback = out
        last = rec.get(f"round{MAX_ROUNDS}_counts", {})
        rec["status"] = ("all_skipped" if last.get("passed", 0) == 0
                         and last.get("skipped", 0) > 0 else "never_green")
    return rec


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--selected", type=Path, default=ROOT / "data" / "selected60.json")
    ap.add_argument("--output", type=Path, default=ROOT / "data" / "verify_patches.jsonl")
    ap.add_argument("--workdir", type=Path, default=ROOT / "work")
    ap.add_argument("--patch-dir", type=Path, default=ROOT / "instances")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--cpus", default="1")
    ap.add_argument("--memory", default="3g")
    a = ap.parse_args()

    sel = json.load(open(a.selected))
    done = set()
    if a.output.exists():
        for line in a.output.read_text().splitlines():
            if line.strip():
                done.add(json.loads(line)["repo"])
    todo = [r for r in sel if r["repo"] not in done]
    if a.limit:
        todo = todo[:a.limit]
    print(f"选中 {len(sel)}，已构造 {len(done)}，本轮 {len(todo)}", file=sys.stderr)

    a.workdir.mkdir(parents=True, exist_ok=True)
    a.patch_dir.mkdir(parents=True, exist_ok=True)
    lock = threading.Lock()
    counter = {"n": 0, "ok": 0}

    def one(r: dict) -> None:
        t0 = time.time()
        rec = build_one(r["repo"], r["base_commit"], a.workdir, a.cpus, a.memory)
        rec["elapsed_s"] = round(time.time() - t0)
        with lock:
            counter["n"] += 1
            i = counter["n"]
            if rec.get("status") == "ok":
                counter["ok"] += 1
                iid = r["repo"].replace("/", "__")
                (a.patch_dir / f"{iid}.verify.patch").write_text(rec.pop("patch"))
            with open(a.output, "a") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            print(f"[{i}/{len(todo)}] 合格 {counter['ok']:>2}  {r['repo']:<42} "
                  f"{rec['status']:<16} tests={rec.get('n_tests','-')} "
                  f"轮={rec.get('rounds','-')} {rec['elapsed_s']}s",
                  file=sys.stderr, flush=True)

    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        list(as_completed([ex.submit(one, r) for r in todo]))


if __name__ == "__main__":
    main()
