"""SWE-Prometheus judge：多教师六维评分 + base/treated 配对 + NGI。

对应 proposal.md §3.5 / §3.6 / §3.7。

设计要点（直接对应 output/audit 的 F-003）：教师返回的分数一律经过 schema 和
范围校验，任何不是 1-5 整数、缺维度、非法 JSON 的响应整条作废，不做截断也不做
兜底。校验后存活的教师数低于法定人数时，本次评分记为 judge_failed 并保留在
分母里，绝不用剩下的教师硬凑一个中位数。
"""
from __future__ import annotations

import argparse
import json
import os
import re
import statistics
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any

DIMENSIONS = ("D1", "D2", "D3", "D4", "D5", "D6")
TEACHERS = ("gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna")
MIN_QUORUM = 2                      # 存活教师少于这个数 → judge_failed
RUBRIC = Path(__file__).resolve().parent.parent / "prompts" / "judge_rubric.md"


class JudgeFailure(Exception):
    """教师法定人数不足。调用方必须把它当成评分缺失，不是能力失败。"""


# --------------------------------------------------------------------------- API

def call_teacher(model: str, system: str, user: str, timeout: int = 300) -> str | None:
    base = os.environ["PROXY_BASE_URL"].rstrip("/")
    req = urllib.request.Request(
        f"{base}/chat/completions",
        data=json.dumps({
            "model": model,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}],
        }).encode(),
        # gpt-5.6 系列不接受 temperature；UA 必须显式设，proxy 前面的
        # Cloudflare 会用 1010 拦掉 urllib 的默认 UA
        headers={"Authorization": f"Bearer {os.environ['PROXY_API_KEY']}",
                 "Content-Type": "application/json",
                 "User-Agent": "swe-prometheus-judge/0.1"},
    )
    # 瞬时 429/5xx 不能让一个教师直接作废——三个教师同时撞上就会被误判成
    # judge_failed，而那本该是"评分缺失"里最不该出现的原因。
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.load(r)["choices"][0]["message"]["content"]
        except urllib.error.HTTPError as e:
            # 404 也归瞬时：实测 proxy 会对存在的模型偶发返回 404
            # （r2 批次里 gpt-5.6-luna 报了 6 次 404，同一模型其余 143 次正常），
            # 之前把它当永久错误直接放弃，一次抖动就让法定人数不足。
            # 5xx 一律当瞬时错误重试。Cloudflare 的 520-527（尤其 524
            # 源站超时）在教师侧很常见：一次 524 打在 terra 上，加上
            # luna 被中转拦，就只剩 sol 一个通过、够不上法定人数 2，
            # 整个实例评分作废。
            transient = (e.code in (404, 408, 409, 425, 429)
                         or 500 <= e.code <= 599)
            print(f"    [{model}] HTTP {e.code}"
                  f"{'，退避重试' if transient and attempt < 3 else ''}", file=sys.stderr)
            if not transient or attempt == 3:
                return None
        except Exception as e:
            print(f"    [{model}] {type(e).__name__}: {e}"
                  f"{'，退避重试' if attempt < 3 else ''}", file=sys.stderr)
            if attempt == 3:
                return None
        time.sleep(5 * (2 ** attempt))
    return None


# -------------------------------------------------------------------- 校验（F-003）

def parse_and_validate(raw: str | None, model: str) -> dict[str, Any] | None:
    """严格解析。任何一处不合规就整条作废，返回 None。"""
    if not raw:
        return None

    m = re.search(r"\{.*\}", raw, re.DOTALL)
    if not m:
        print(f"    [{model}] 作废：响应里没有 JSON 对象", file=sys.stderr)
        return None
    try:
        obj = json.loads(m.group(0))
    except json.JSONDecodeError as e:
        print(f"    [{model}] 作废：JSON 不合法 ({e})", file=sys.stderr)
        return None
    if not isinstance(obj, dict):
        print(f"    [{model}] 作废：顶层不是对象", file=sys.stderr)
        return None

    out: dict[str, Any] = {}
    for d in DIMENSIONS:
        cell = obj.get(d)
        if not isinstance(cell, dict):
            print(f"    [{model}] 作废：缺维度 {d}", file=sys.stderr)
            return None
        s = cell.get("score")
        # bool 是 int 的子类，必须显式排除
        if isinstance(s, bool) or not isinstance(s, int):
            print(f"    [{model}] 作废：{d}.score 不是整数（{s!r}）", file=sys.stderr)
            return None
        if not 1 <= s <= 5:
            # 这条就是探针塞 999 时该走的分支——不截断，整条丢弃
            print(f"    [{model}] 作废：{d}.score={s} 越界，合法范围 1-5", file=sys.stderr)
            return None
        just = cell.get("justification")
        if not isinstance(just, str) or not just.strip():
            print(f"    [{model}] 作废：{d} 缺 justification", file=sys.stderr)
            return None
        ev = cell.get("evidence")
        if not isinstance(ev, list):
            print(f"    [{model}] 作废：{d}.evidence 不是数组", file=sys.stderr)
            return None
        out[d] = {"score": s, "justification": just.strip(),
                  "evidence": [str(x) for x in ev]}
    return out


# ------------------------------------------------------------------------ 评一个态

def score_state(state_name: str, evidence_blob: str,
                teachers: tuple[str, ...] = TEACHERS,
                diff: str | None = None) -> dict[str, Any]:
    system = RUBRIC.read_text(encoding="utf-8")
    parts = [f"Score the following repository state: **{state_name}**.", "", evidence_blob]
    if diff:
        # §3.5 第 5 步：diff 是 D4（结构与可维护性）的主要依据，不给就等于让
        # 教师盲评结构改动。第一版漏了这个，D4 的判词全在抱怨"no diff shown"。
        parts += ["", "## Unified diff from BASE to this state",
                  "This is what changed. Judge structural improvement against it;",
                  "cosmetic reformatting is not structural improvement.",
                  "```diff", diff, "```"]
    parts += ["", "Return only the JSON object."]
    user = "\n".join(parts)

    valid, rejected = {}, []
    for t in teachers:
        print(f"  教师 {t} …", file=sys.stderr)
        parsed = parse_and_validate(call_teacher(t, system, user), t)
        if parsed is None:
            rejected.append(t)
        else:
            valid[t] = parsed

    if len(valid) < MIN_QUORUM:
        raise JudgeFailure(
            f"{state_name}: 仅 {len(valid)}/{len(teachers)} 位教师通过校验，"
            f"低于法定人数 {MIN_QUORUM}（作废：{', '.join(rejected) or '无'}）")

    agg = {}
    for d in DIMENSIONS:
        scores = sorted(v[d]["score"] for v in valid.values())
        agg[d] = {
            "median": statistics.median(scores),
            "scores": scores,
            "spread": max(scores) - min(scores),      # 显式保留教师分歧
        }
    return {"state": state_name, "aggregate": agg, "per_teacher": valid,
            "valid_teachers": list(valid), "rejected_teachers": rejected}


# --------------------------------------------------------------------- NGI（§3.6）

def normalized_governance_improvement(base: dict, treated: dict) -> dict[str, Any]:
    """NGI = mean_d (treated_d - base_d) / (5 - base_d)，base=5 的维度记为保持项。"""
    per_dim, ratios, held, regressed = {}, [], [], []
    for d in DIMENSIONS:
        b = base["aggregate"][d]["median"]
        t = treated["aggregate"][d]["median"]
        delta = t - b
        if b >= 5:
            held.append(d)                      # 无改善空间，不奖励也不惩罚
            ratio = None
        else:
            ratio = delta / (5 - b)
            ratios.append(ratio)
        if delta < 0:
            regressed.append(d)
        per_dim[d] = {"base": b, "treated": t, "delta": delta, "ratio": ratio}

    return {
        "NGI": (sum(ratios) / len(ratios)) if ratios else None,
        "per_dimension": per_dim,
        "held_at_ceiling": held,
        "regressed": regressed,
        "no_regression": not regressed,
        "strict_success": all(per_dim[d]["treated"] >= 4 for d in DIMENSIONS),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="SWE-Prometheus 多教师配对评分")
    ap.add_argument("--base-evidence", type=Path, required=True)
    ap.add_argument("--treated-evidence", type=Path, required=True)
    ap.add_argument("--diff", type=Path, default=None,
                    help="treatment.patch；只喂给 treated 态（§3.5 第 5 步）")
    ap.add_argument("--max-diff-chars", type=int, default=60000)
    ap.add_argument("--instance-id", required=True)
    ap.add_argument("--output", type=Path, required=True)
    a = ap.parse_args()

    result: dict[str, Any] = {"instance_id": a.instance_id}
    try:
        print("评 base 态：", file=sys.stderr)
        base = score_state("BASE", a.base_evidence.read_text(encoding="utf-8"))
        print("评 treated 态：", file=sys.stderr)
        diff_text = None
        if a.diff and a.diff.exists():
            diff_text = a.diff.read_text(encoding="utf-8", errors="ignore")
            if len(diff_text) > a.max_diff_chars:
                diff_text = (diff_text[:a.max_diff_chars] +
                             f"\n[... diff truncated at {a.max_diff_chars} chars ...]")
        treated = score_state("TREATED", a.treated_evidence.read_text(encoding="utf-8"),
                              diff=diff_text)
    except JudgeFailure as e:
        result.update({"status": "judge_failed", "reason": str(e)})
        a.output.write_text(json.dumps(result, ensure_ascii=False, indent=1))
        print(f"\njudge_failed: {e}", file=sys.stderr)
        sys.exit(2)

    result.update({
        "status": "scored",
        "base": base,
        "treated": treated,
        "outcome": normalized_governance_improvement(base, treated),
    })
    a.output.write_text(json.dumps(result, ensure_ascii=False, indent=1))

    o = result["outcome"]
    ngi = o["NGI"]
    print(f"\nNGI = {ngi:.3f}" if ngi is not None else "\nNGI = n/a（所有维度已达上限）",
          file=sys.stderr)
    print("逐维 base→treated：" + "  ".join(
        f"{d} {o['per_dimension'][d]['base']:.0f}→{o['per_dimension'][d]['treated']:.0f}"
        for d in DIMENSIONS), file=sys.stderr)
    print(f"无回退={o['no_regression']}  严格达标={o['strict_success']}", file=sys.stderr)


if __name__ == "__main__":
    main()
