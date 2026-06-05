#!/usr/bin/env bash
# Refresh internal/data/popular-pypi.json from the public top-PyPI-packages dataset.
set -euo pipefail
curl -fsS "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json" \
  | python3 -c 'import sys,json; d=json.load(sys.stdin); print(json.dumps([r["project"].lower().replace("_","-").replace(".","-") for r in d["rows"][:2000]]))' \
  > internal/data/popular-pypi.json
echo "wrote $(python3 -c 'import json;print(len(json.load(open("internal/data/popular-pypi.json"))))') pypi names"
