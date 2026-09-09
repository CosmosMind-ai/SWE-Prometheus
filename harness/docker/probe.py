"""容器内的证据探针。输出 JSON 到 stdout。

三条硬规则，都对应 output/audit 的发现：

F-002：命令成败**只看退出码**。绝不在 stdout 里搜标记字符串——那种做法
       可以被被测程序的输出直接伪造（审计的探针就是塞了一个假的
       ===RETROFIT_STEP_i_OK=== 再返回 exit 1，解析器认成了通过）。

F-005：仓库自己声明的命令（Makefile / CI）是 agent 可以改写的，不能当作
       base 和 treated 之间的可比测量。所以分两组报告：benchmark 自带的
       固定探针（两个状态用同一把尺子）和仓库声明的命令（仅供参考）。

F-004：D3-D6 需要确定性证据，不能只让 judge 看 diff。所以复杂度、依赖
       审计、凭据扫描每次都实际跑。
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

SRC, WORK = Path("/src"), Path("/work")
TIMEOUT = int(os.environ.get("PROBE_TIMEOUT", "600"))
# 装依赖比其他探针慢得多（torch 这类），给独立超时。超时记 exit_code=None，
# judge 会当作"证据缺失"而不是"门禁失败"。
INSTALL_TIMEOUT = int(os.environ.get("PROBE_INSTALL_TIMEOUT", "900"))


def run(cmd: list[str] | str, cwd: Path = WORK, timeout: int = TIMEOUT) -> dict:
    shell = isinstance(cmd, str)
    try:
        p = subprocess.run(cmd, cwd=cwd, shell=shell, capture_output=True,
                           text=True, errors="replace", timeout=timeout)
        return {"cmd": cmd if shell else " ".join(cmd),
                "exit_code": p.returncode,              # 唯一的成败依据
                "stdout_tail": p.stdout[-3000:], "stderr_tail": p.stderr[-3000:]}
    except subprocess.TimeoutExpired:
        return {"cmd": cmd if shell else " ".join(cmd), "exit_code": None,
                "error": f"timeout>{timeout}s"}
    except Exception as e:
        return {"cmd": cmd if shell else " ".join(cmd), "exit_code": None,
                "error": f"{type(e).__name__}: {e}"}


def install() -> dict:
    """按优先级找安装入口。装依赖是后续探针的前提，单独报告。"""
    attempts = []
    if (WORK / "pyproject.toml").exists() or (WORK / "setup.py").exists():
        attempts.append([sys.executable, "-m", "pip", "install", "-e", ".", "-q"])
    for req in ("requirements.txt", "requirements-dev.txt", "requirements/dev.txt"):
        if (WORK / req).exists():
            attempts.append([sys.executable, "-m", "pip", "install", "-r", req, "-q"])
    if not attempts:
        return {"cmd": "(no install entry point found)", "exit_code": None,
                "error": "仓库没有 pyproject.toml / setup.py / requirements.txt"}
    last = None
    for cmd in attempts:
        last = run(cmd, timeout=INSTALL_TIMEOUT)
        if last.get("exit_code") == 0:
            return last
    return last


def dep_audit() -> dict:
    """审计**仓库声明的**依赖，不是探针镜像自己的环境。

    原来这里是裸 `pip_audit -f json`，它审的是容器里已安装的包——也就是
    ruff/radon/mypy/build 这套探针工具链。后果：60 个仓库拿到的是同一份
    报告，镜像自带的 setuptools 恒定带一个 CVE，于是 rubric 里“无漏洞包→4分”
    那一档永远进不去，D6 全体封顶在 3，agent 做什么都改不动。

    改成按仓库声明的清单审计。清单不存在时明确报告“未声明依赖”，让 judge
    据此打 1-2 分，而不是拿镜像的健康度冒充仓库的。
    """
    manifests = []
    for pat in ("requirements.txt", "requirements-dev.txt", "requirements/*.txt",
                "constraints.txt"):
        manifests += sorted(str(f.relative_to(WORK)) for f in WORK.glob(pat) if f.is_file())
    locks = [f for f in ("poetry.lock", "Pipfile.lock", "uv.lock", "pdm.lock")
             if (WORK / f).exists()]
    has_pyproject = (WORK / "pyproject.toml").exists()

    if not manifests and not locks and not has_pyproject:
        return {"cmd": "(no declared dependency manifest)", "exit_code": None,
                "error": "仓库没有 requirements/lockfile/pyproject，依赖未声明",
                "declared_manifests": [], "declared_locks": []}

    cmd = [sys.executable, "-m", "pip_audit", "-f", "json",
           "--progress-spinner", "off"]
    if manifests:
        for m in manifests:
            cmd += ["-r", m]
    else:
        # 只有 pyproject/lockfile：审计本地项目本身，仍然是仓库而非镜像
        cmd += ["--no-deps", "."] if has_pyproject else []

    res = run(cmd, timeout=INSTALL_TIMEOUT)

    # 退出码不能作为判据：pip_audit 发现漏洞时退 1，解析依赖失败时**也**退 1。
    # 唯一可靠的区分是 stdout 里有没有可解析的 JSON 报告。没有就退回
    # --no-deps —— 只按清单里写死的 name==version 查漏洞库，不做依赖解析，
    # 这样清单里钉了个不存在的版本（agent 干过）也不会让整个探针失效。
    def parsed(r: dict) -> bool:
        try:
            json.loads((r.get("stdout_tail") or "").strip())
            return True
        except Exception:
            return False

    if not parsed(res) and manifests:
        alt = run(cmd + ["--no-deps"], timeout=TIMEOUT)
        if parsed(alt):
            alt["note"] = "回退到 --no-deps（跳过依赖解析）"
            res = alt

    # 解析不出报告时，必须区分两种完全不同的情况，否则会把仓库的缺陷
    # 误记成我们的证据缺失：
    #   (a) 清单本身坏了——钉了不存在的版本、依赖互相冲突。这是**关于仓库的
    #       正面证据**：环境不可复现。agent 干过这事（把 Django 钉到 6.0.2）。
    #   (b) 网络/超时等基础设施原因。这才是证据缺失，按 rubric 封顶 3。
    if not parsed(res):
        err = (res.get("stderr_tail") or "") + (res.get("error") or "")
        unresolved = ("No matching distribution found" in err
                      or "Could not find a version" in err
                      or "ResolutionImpossible" in err
                      or "conflict is caused by" in err)
        if not unresolved:
            res["manifest_resolvable"] = True
            res["audit_status"] = "evidence_missing"
        else:
            # 解析失败有两种原因，长得几乎一样但性质完全相反：
            #   (a) 钉了一个**从来不存在**的版本（agent 幻觉出来的），仓库真坏了；
            #   (b) 版本存在，只是没有本探针 Python 版本的 wheel——比如仓库
            #       写明用 Python 3.8 + torch 1.13，而镜像是 3.11。这是**我们的
            #       环境和仓库目标不匹配**，不是仓库的缺陷。
            # 字符串分不开，直接问 PyPI：该 name/version 是否存在。
            pins = re.findall(r"No matching distribution found for ([A-Za-z0-9._-]+)==([\w.]+)", err)
            verdicts = []
            for name, ver in pins[:5]:
                try:
                    import urllib.request
                    with urllib.request.urlopen(
                            f"https://pypi.org/pypi/{name}/{ver}/json", timeout=20) as r:
                        verdicts.append((name, ver, r.status == 200))
                except Exception as e:
                    code = getattr(e, "code", None)
                    verdicts.append((name, ver, False if code == 404 else None))
            res["pin_existence"] = [
                {"name": n, "version": v,
                 "exists_on_pypi": ok} for n, v, ok in verdicts]
            ghost = [f"{n}=={v}" for n, v, ok in verdicts if ok is False]
            res["manifest_resolvable"] = False
            if ghost:
                res["audit_status"] = "manifest_broken"
                res["finding"] = ("清单钉了 PyPI 上不存在的版本：" + ", ".join(ghost) +
                                  "。任何环境都装不上，这是仓库的缺陷。")
            else:
                res["audit_status"] = "env_mismatch"
                res["finding"] = ("清单里的版本在 PyPI 上存在，只是没有本探针 Python "
                                  "版本的发行版。这是探针环境与仓库目标不匹配，"
                                  "**不是仓库的缺陷**，按证据缺失处理。")
    else:
        res["manifest_resolvable"] = True
        res["audit_status"] = "ok"
    res["declared_manifests"] = manifests
    res["declared_locks"] = locks
    return res


def benchmark_probes() -> dict:
    """benchmark 自带的固定探针。base 和 treated 跑完全一样的命令。"""
    return {
        "install":     install(),
        "tests":       run([sys.executable, "-m", "pytest", "-q",
                            "--timeout=120", "-p", "no:cacheprovider"]),
        "test_collect": run([sys.executable, "-m", "pytest", "--co", "-q",
                             "-p", "no:cacheprovider"]),
        "lint":        run([sys.executable, "-m", "ruff", "check", "."]),
        "typecheck":   run([sys.executable, "-m", "mypy", ".",
                            "--ignore-missing-imports", "--no-error-summary"]),
        "build":       run([sys.executable, "-m", "build", "--no-isolation"]),
        "dep_audit":   dep_audit(),
        # secret_scan 已移除。detect-secrets 是全部探针里最重的一个（实测单次
        # 6 分多钟、7 个并发就能把 8 核占满），而它产出的 potential_secrets
        # 计数是 ~100% 误报（中位 412、最小 1、从无 0），rubric 早已明令
        # 忽略。花最多算力产出一个规定要无视的数字，没有意义。
        "complexity":  run([sys.executable, "-m", "radon", "cc", ".", "-a", "-s"]),
        "maintainability": run([sys.executable, "-m", "radon", "mi", ".", "-s"]),
    }


def declared_commands() -> dict:
    """仓库自己声明的命令。**agent 可以改写这些，所以不可比。**"""
    out: dict = {}
    mk = WORK / "Makefile"
    if mk.exists():
        targets = re.findall(r"^([a-zA-Z][\w-]*):", mk.read_text(errors="ignore"), re.M)
        for t in [x for x in ("test", "lint", "check", "typecheck", "ci") if x in targets]:
            out[f"make {t}"] = run(["make", t])

    wf_dir = WORK / ".github" / "workflows"
    if wf_dir.is_dir():
        cmds = []
        for f in sorted(wf_dir.glob("*.y*ml"))[:3]:
            cmds += _extract_run_steps(f.read_text(errors="ignore"))
        seen = set()
        for c in cmds[:8]:
            if c not in seen:
                seen.add(c)
                out[f"ci: {c[:60]}"] = run(c)
    return out


_KEYWORDS = ("test", "lint", "mypy", "ruff", "flake8", "pytest", "tox", "check")


def _extract_run_steps(text: str) -> list[str]:
    """抓 workflow 里的 run: 命令。必须处理 `run: |` 多行块——GitHub Actions
    里绝大多数命令是这么写的，只匹配单行会把它们全漏掉。"""
    out, lines = [], text.splitlines()
    i = 0
    while i < len(lines):
        m = re.match(r"^(\s*)run:\s*(.*)$", lines[i])
        if not m:
            i += 1
            continue
        indent, inline = len(m.group(1)), m.group(2).strip()
        if inline and inline not in ("|", ">", "|-", ">-"):
            if any(k in inline for k in _KEYWORDS):
                out.append(inline)
            i += 1
            continue
        # 块标量：收下面缩进更深的行
        i += 1
        block = []
        while i < len(lines):
            ln = lines[i]
            if ln.strip() and (len(ln) - len(ln.lstrip())) <= indent:
                break
            if ln.strip():
                block.append(ln.strip())
            i += 1
        for c in block:
            if any(k in c for k in _KEYWORDS):
                out.append(c)
    return out


LINT_FILES = {".flake8", ".pylintrc", "ruff.toml", ".ruff.toml", "tox.ini",
              ".pre-commit-config.yaml", "setup.cfg"}
LINT_SECTIONS = ("[tool.ruff]", "[tool.flake8]", "[tool.black]", "[tool.pylint]",
                 "[tool.isort]", "[flake8]")
TYPE_SECTIONS = ("[tool.mypy]", "[mypy]", "[tool.pyright]")
TEST_SECTIONS = ("[tool.pytest", "[pytest]", "[tool.tox]")


def declared_governance() -> dict:
    """仓库**自己声明**了哪些治理机制。

    这一段是 D1/D2 的关键：必须把"仓库声明了 lint 门禁"和"benchmark 拿
    ruff 默认配置去扫了一遍"分开。第一版没分开，judge 把后者当成前者，
    于是有没有 lint 配置的仓库 D2 一律给 3——量表卡死。
    """
    names = {p.name.lower() for p in WORK.iterdir() if p.is_file()}
    pyproj = ""
    if (WORK / "pyproject.toml").exists():
        pyproj = (WORK / "pyproject.toml").read_text(errors="ignore")
    setupcfg = ""
    if (WORK / "setup.cfg").exists():
        setupcfg = (WORK / "setup.cfg").read_text(errors="ignore")
    blob = pyproj + setupcfg

    lint_files = sorted(names & LINT_FILES)
    lint_secs = [s for s in LINT_SECTIONS if s in blob]
    type_secs = [s for s in TYPE_SECTIONS if s in blob]
    test_secs = [s for s in TEST_SECTIONS if s in blob]

    wf_dir = WORK / ".github" / "workflows"
    wf_text = ""
    wf_files = []
    if wf_dir.is_dir():
        for f in sorted(wf_dir.glob("*.y*ml")):
            wf_files.append(f.name)
            wf_text += f.read_text(errors="ignore")

    test_files = [str(p.relative_to(WORK)) for p in WORK.rglob("test_*.py")][:40]
    test_files += [str(p.relative_to(WORK)) for p in WORK.rglob("*_test.py")][:20]

    return {
        "declares_lint_config": bool(lint_files or lint_secs),
        "lint_config_evidence": lint_files + lint_secs,
        "declares_typecheck_config": bool(type_secs),
        "typecheck_config_evidence": type_secs,
        "declares_test_config": bool(test_secs),
        "test_config_evidence": test_secs,
        "test_file_count": len(test_files),
        "test_files_sample": test_files[:15],
        "ci_workflow_files": wf_files,
        "ci_mentions_tests": any(k in wf_text for k in ("pytest", "test", "tox")),
        "ci_mentions_lint": any(k in wf_text for k in ("ruff", "flake8", "lint", "black")),
        "ci_mentions_typecheck": any(k in wf_text for k in ("mypy", "pyright")),
        "has_contributing": any(n.startswith("contributing") for n in names),
        "has_security_policy": any(n.startswith("security.") for n in names),
        "has_license": any(n.startswith("license") or n.startswith("copying") for n in names),
        "has_lockfile": bool(names & {"poetry.lock", "uv.lock", "pdm.lock",
                                      "pipfile.lock", "requirements.txt"}),
    }


def main() -> None:
    # F-005：/src 只读挂载，复制到 /work 再跑，宿主上的快照绝不被改
    # 排除虚拟环境和构建产物：它们不是仓库的治理状态，而且 agent 建的 .venv
    # 里的 python 符号链接在容器内是断的，会让 copytree 直接抛错。
    # symlinks=True + ignore_dangling_symlinks 兜住剩下的断链。
    shutil.copytree(
        SRC, WORK, dirs_exist_ok=True, symlinks=True,
        ignore_dangling_symlinks=True,
        ignore=shutil.ignore_patterns(
            ".git", ".venv", "venv", "env", ".env", "node_modules",
            "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
            "*.egg-info", "build", "dist", ".tox"),
    )
    result = {
        "declared_governance": declared_governance(),
        "benchmark_probes": benchmark_probes(),
        "declared_commands": declared_commands(),
        "note": ("benchmark_probes 是固定探针，base/treated 可比；"
                 "declared_commands 由仓库自己声明，agent 可改写，不可比"),
    }
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
