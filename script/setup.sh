#!/usr/bin/env bash

set -e

cd "$(dirname "$0")/.."
python3 -m pip install uv
uv sync
uv run pre-commit install
