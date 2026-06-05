#!/usr/bin/env bash
# Refresh internal/data/popular-crates.json from crates.io most-downloaded.
set -euo pipefail
out=internal/data/popular-crates.json
python3 - <<'PY'
import json,urllib.request
names=[]
for page in range(1,21):  # 20 pages x 100 = top 2000
    url=f"https://crates.io/api/v1/crates?sort=downloads&per_page=100&page={page}"
    req=urllib.request.Request(url, headers={"User-Agent":"invoke-guard refresh"})
    data=json.load(urllib.request.urlopen(req))
    names+=[c["id"] for c in data["crates"]]
json.dump(sorted(set(names)), open("internal/data/popular-crates.json","w"))
print("wrote",len(set(names)),"crate names")
PY
