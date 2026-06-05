#!/usr/bin/env bash
# Refresh data/popular-npm.json with the most-depended-upon npm packages.
# Uses the public npm search API (read-only). Commit the result.
set -euo pipefail
out=internal/data/popular-npm.json
tmp=$(mktemp)
echo "[" > "$tmp"
first=1
for offset in $(seq 0 250 1750); do
  curl -fsS "https://registry.npmjs.org/-/v1/search?text=boost-exact:false&popularity=1.0&size=250&from=${offset}" \
    | python3 -c 'import sys,json;[print(o["package"]["name"]) for o in json.load(sys.stdin)["objects"]]'
done | sort -u | while read -r name; do
  [ $first -eq 1 ] && first=0 || echo "," >> "$tmp"
  printf '%s' "$(python3 -c "import json,sys;print(json.dumps(sys.argv[1]))" "$name")" >> "$tmp"
done
echo "]" >> "$tmp"
mv "$tmp" "$out"
echo "wrote $(python3 -c 'import json;print(len(json.load(open("internal/data/popular-npm.json"))))') names to $out"
