# Zyrax Guard — JSON output schema

`zyrax-guard check --json` (and `zyrax-guard scan --json`) emits a versioned JSON
document. This document defines every field and the stability promise for downstream
consumers.

---

## Top-level envelope

```json
{
  "schemaVersion": "1.0",
  "results": [ ... ]
}
```

| Field | Type | Description |
|---|---|---|
| `schemaVersion` | string | Schema version (see stability promise below). Currently `"1.0"`. |
| `results` | array of Result | One entry per package vetted. |

---

## Result object

Each element of `results` corresponds to one package verdict.

| Field | Type | Description |
|---|---|---|
| `ecosystem` | string | Package ecosystem. Currently `"npm"`. |
| `name` | string | Package name as queried (e.g. `"express"`, `"reqeust"`). |
| `version` | string | Version queried, or `""` if none was specified (bare name). |
| `verdict` | string | `"SAFE"`, `"WARN"`, or `"BLOCK"`. |
| `score` | integer | Weighted risk score (block signal = 100, warn = 10, info = 1). Useful for sorting by risk; not a probability. |
| `signals` | array of Signal | The individual check results that produced the verdict. |
| `suggestion` | string | *(optional)* Corrected package name when a typosquat is detected (e.g. `"request"`). Absent when no suggestion applies. |

---

## Signal object

Each element of `signals` is one check's contribution to the verdict.

| Field | Type | Description |
|---|---|---|
| `check` | string | Check identifier (the Rule ID). One of: `nonexistent`, `typosquat`, `known-malware`, `new-and-unused`, `lockfile-integrity`, `maintainer-change`. Also `policy-allow` or `policy-deny` when a local policy short-circuits the checks. |
| `level` | integer | Severity: `0` = info (does not escalate verdict), `1` = warn, `2` = block. |
| `message` | string | Plain-language reason, suitable for display. Empty string when the check produced no finding. |
| `suggest` | string | *(optional)* Corrected package name (typosquat only). |

---

## Example

```bash
zyrax-guard check reqeust --json
```

```json
{
  "schemaVersion": "1.0",
  "results": [
    {
      "ecosystem": "npm",
      "name": "reqeust",
      "version": "",
      "verdict": "BLOCK",
      "score": 101,
      "signals": [
        {
          "check": "nonexistent",
          "level": 0,
          "message": ""
        },
        {
          "check": "typosquat",
          "level": 2,
          "message": "looks like a typo of \"request\" (far more popular); this name has only 3 weekly downloads",
          "suggest": "request"
        },
        {
          "check": "new-and-unused",
          "level": 1,
          "message": "published 2 days ago with only 3 weekly downloads"
        },
        {
          "check": "known-malware",
          "level": 0,
          "message": ""
        }
      ],
      "suggestion": "request"
    }
  ]
}
```

---

## Stability promise

**Within a major `schemaVersion` (e.g. `"1.0"`, `"1.x"`):**

- Existing fields are never removed or renamed.
- Existing `check` identifier strings are never changed.
- New fields may be added to Result or Signal objects (additive-only).
- The `level` integer encoding (0/1/2) is stable.

**On a major version bump (e.g. `"1.0"` → `"2.0"`):**

- Any breaking change is preceded by a deprecation notice in the changelog.
- The old schema remains supported for at least one minor release cycle.

Consumers should read `schemaVersion` and handle unknown fields gracefully (ignore extras).
They should **not** hardcode the integer value of `level` beyond 0/1/2 — future
ecosystems may introduce intermediate values.

---

## SARIF output

`--sarif` emits **SARIF 2.1.0** — a separate stable contract. Each finding maps to a
`results[]` entry with `ruleId` (the check name), `level` (`error`/`warning`/`note` for
BLOCK/WARN/info), and a `message.text`. It uploads directly to GitHub Code Scanning or any
SARIF-aware tool.
