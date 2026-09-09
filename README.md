---
license: cc-by-4.0
task_categories:
- text-generation
language:
- en
tags:
- software-engineering
- swe-bench
- repository-governance
- agent
pretty_name: SWE-Prometheus
size_categories:
- n<1K
configs:
- config_name: default
  data_files:
  - split: train
    path: dataset.jsonl
---

# SWE-Prometheus Public Tasks

Public question package for SWE-Prometheus from CosmosMind AI Lab.

This release contains the 22 public tasks used in the benchmark. Each task
includes the task statement, the fixed repository revision, the environment
definition, the evaluation entry point, and the characterization tests used as
the behavior gate. Reference scores, model results, traces, and treated evidence
are intentionally excluded. A further 38 tasks are held out and not published.

SWE-Prometheus evaluates repository-level engineering governance. A task supplies
a repository pinned at a fixed commit with no issue, no failing test, and no
reference patch; the agent decides what to improve and must do so without
changing observable behavior. Scoring covers six governance dimensions on a 1-5
scale.

## Layout

```
dataset.jsonl              one JSON object per line
tasks/<instance_id>/
  problem_statement.txt    task given to the agent
  Dockerfile               environment definition
  eval.sh                  evaluation entry point
  meta.json                task metadata
  developer_patch.diff     empty; no reference patch exists
  test_patch.diff          characterization tests (behavior gate)
  status.json              construction and validation status
instance_ids.json          the 22 instance ids
harness/                   prompts, evidence probe, scoring scripts
```

## `dataset.jsonl` schema

```json
{
  "repo": "SkyworkAI/Skywork-Skills",
  "instance_id": "SkyworkAI__Skywork-Skills",
  "base_commit": "c8c6aeb742c3d6a2b728992142796702464b6fce",
  "patch": "",
  "test_patch": "diff --git ...",
  "problem_statement": "task statement, including the six governance dimensions",
  "hints_text": "",
  "created_at": "2026-04-02T13:44:43+02:00",
  "version": "dataset60-v1",
  "FAIL_TO_PASS": "[]",
  "PASS_TO_PASS": "[\"tests_verify/test_characterization.py::test_...\"]",
  "environment_setup_commit": "c8c6aeb742c3d6a2b728992142796702464b6fce",
  "image_assets": "{}",
  "base_scores": {"D1": 1, "D2": 1, "D3": 3, "D4": 3, "D5": 1, "D6": 1},
  "base_mean": 1.667
}
```

`patch` is empty and `FAIL_TO_PASS` is `"[]"`: the benchmark is oracle-free, so
there is no reference solution and no test that must newly pass.

`test_patch` adds `tests_verify/` containing characterization tests that pin the
repository's current observable behavior. They are verified green on
`base_commit` before a task enters the dataset. After the agent finishes, the
patch is reapplied and the tests are rerun; if they do not all stay green the
instance is marked `behavior: broken` and its score is not counted. Their names
are listed in `PASS_TO_PASS`. This is the mirror image of SWE-bench, where tests
are the target rather than a constraint.

`image_assets` is `"{}"` for all tasks; SWE-Prometheus is not multimodal. The
field is retained for schema compatibility.

`base_scores` records the pre-retrofit score of each governance dimension
(D1 Tests & CI, D2 Code Quality Gates, D3 Documentation & Collaboration,
D4 Structure & Maintainability, D5 Reproducible Environment,
D6 Dependency & Security Health), and `base_mean` their mean. The reported
metric is

```
NGI = mean_d (treated_d - base_d) / (5 - base_d)
```

alongside `no_regression` and `strict_success` (all six dimensions >= 4).

## Usage

```bash
export PROM_HARNESS=$PWD/harness
docker build -t prom/evidence:0.3 -f harness/docker/Dockerfile.evidence harness/docker

cd tasks/SkyworkAI__Skywork-Skills
./eval.sh base                        # score the base state
./eval.sh agent /path/to/patch.diff   # score an agent patch
```

Repository contents are not redistributed. Each task records `repo` and
`base_commit`; `eval.sh` clones from GitHub at that revision. All repositories
carry an explicit open-source license, recorded per task in `meta.json`.

## Citation

To be announced.
