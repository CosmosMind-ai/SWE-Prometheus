# SWE-Prometheus 评测环境 —— sirnfs__OptionSuite
#
# 两个设计约束：
#   仓库以只读挂到 /src，容器内复制到 /work 再跑，宿主快照永不被写。
#   工具版本全部钉死，保证 base 与 treated 用的是同一把尺子。
FROM docker.1ms.run/library/python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        git curl ca-certificates build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
        pytest==8.3.4 pytest-timeout==2.3.1 ruff==0.8.4 mypy==1.14.0 \
        build==1.2.2 pip-audit==2.7.3 radon==6.0.1

# 任务钉死的仓库与提交
ENV PROM_REPO=sirnfs/OptionSuite
ENV PROM_BASE_COMMIT=388b130b7267199bc7caee246df61a4835d11f91

WORKDIR /work
COPY probe.py /probe.py
ENTRYPOINT ["python3", "/probe.py"]
