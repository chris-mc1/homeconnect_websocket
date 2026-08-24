FROM mcr.microsoft.com/vscode/devcontainers/base:debian

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN \
    apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        python3 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

USER vscode

ENV VIRTUAL_ENV="/home/vscode/.local/ha-venv" \
    UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1
ENV UV_PROJECT_ENVIRONMENT=$VIRTUAL_ENV
RUN --mount=type=bind,source=.python-version,target=.python-version \
    uv python install \
    && uv venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

WORKDIR /workspaces

ENV SHELL=/bin/bash