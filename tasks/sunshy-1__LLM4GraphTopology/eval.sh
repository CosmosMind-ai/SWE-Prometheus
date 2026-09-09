#!/usr/bin/env bash
# SWE-Prometheus 单实例评测 —— sunshy-1__LLM4GraphTopology
#
# 用法：
#   ./eval.sh base                    只采 base 证据并打分（不跑 agent）
#   ./eval.sh agent <patch.diff>      评测一个 agent 产出的补丁
#
# 六个阶段：
#   [1/6] clone 到钉死的 commit
#   [2/6] base 证据（容器内跑固定探针）
#   [3/6] 应用待评补丁（agent 模式）
#   [4/6] 行为闸门：把 verify_patch.diff 打回去跑 pytest，不全绿即 broken
#   [5/6] treated 证据（**必须先删掉 tests_verify/**，否则 agent 白蹭 D1 分）
#   [6/6] 配对打分，算 NGI
set -euo pipefail

MODE="${1:-base}"
PATCH="${2:-}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="sunshy-1/LLM4GraphTopology"
COMMIT="366d6774622906d46b61e529ccd4e3b71641ed8b"
IMAGE="${PROM_EVIDENCE_IMAGE:-prom/evidence:0.3}"
RUN="${PROM_RUN_DIR:-$HERE/run}"

rm -rf "$RUN"; mkdir -p "$RUN"

echo "=== [1/6] clone $REPO @ ${COMMIT:0:8} ==="
git clone --quiet "https://github.com/$REPO.git" "$RUN/work"
git -C "$RUN/work" checkout --quiet "$COMMIT"
cp -R "$RUN/work" "$RUN/base_snapshot"

echo "=== [2/6] base 证据 ==="
python3 "$PROM_HARNESS/scripts/collect_evidence.py" \
  --repo "$RUN/base_snapshot" --label BASE \
  --output "$RUN/base_evidence.md" --json-output "$RUN/base_evidence.json"

if [ "$MODE" = "agent" ]; then
  echo "=== [3/6] 应用待评补丁 ==="
  [ -n "$PATCH" ] || { echo "agent 模式需要传补丁路径"; exit 2; }
  git -C "$RUN/work" apply --3way --whitespace=nowarn "$PATCH"
else
  echo "=== [3/6] base 模式，跳过补丁 ==="
fi

echo "=== [4/6] 行为闸门 ==="
if [ -f "$HERE/verify_patch.diff" ]; then
  set +e
  git -C "$RUN/work" apply --3way --whitespace=nowarn "$HERE/verify_patch.diff"
  APPLIED=$?
  if [ "$APPLIED" = 0 ]; then
    # set -o pipefail 不可省：管道退出码取自 tail，而 tail 永远成功
    docker run --rm --entrypoint bash --cpus=1 --memory=4g \
      -v "$RUN/work:/workspace" -w /workspace "$IMAGE" -lc '
        set -o pipefail
        for f in requirements.txt requirements-dev.txt requirements/base.txt; do
          [ -f "$f" ] && pip install -q -r "$f" 2>/dev/null; done
        { [ -f setup.py ] || [ -f pyproject.toml ]; } && pip install -q -e . 2>/dev/null
        pip install -q pytest 2>/dev/null
        python -m pytest tests_verify -q --no-header -p no:cacheprovider 2>&1 | tail -40
      ' > "$RUN/verify_result.log" 2>&1
    VRC=$?
  else
    VRC=99
  fi
  set -e
  BEHAVIOR=$([ "$VRC" = 0 ] && echo preserved || echo broken)
else
  BEHAVIOR=no_gate; VRC=99
  echo "  本实例无验证补丁（gate_strength=none），行为无法验证"
fi
echo "{\"behavior\":\"$BEHAVIOR\",\"verify_exit\":$VRC}" > "$RUN/verify.json"
echo "  行为：$BEHAVIOR"

echo "=== [5/6] treated 证据 ==="
rm -rf "$RUN/work/tests_verify"
python3 "$PROM_HARNESS/scripts/collect_evidence.py" \
  --repo "$RUN/work" --label TREATED \
  --output "$RUN/treated_evidence.md" --json-output "$RUN/treated_evidence.json"

echo "=== [6/6] 配对打分 ==="
git -C "$RUN/work" add -A
git -C "$RUN/work" -c user.email=e@p -c user.name=eval commit --quiet -m eval || true
git -C "$RUN/work" diff "$COMMIT" HEAD > "$RUN/treatment.patch"
python3 "$PROM_HARNESS/scripts/judge.py" --instance-id "$REPO" \
  --diff "$RUN/treatment.patch" \
  --base-evidence "$RUN/base_evidence.md" \
  --treated-evidence "$RUN/treated_evidence.md" \
  --output "$RUN/scores.json"
echo "产物在 $RUN"
