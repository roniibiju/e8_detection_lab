#!/usr/bin/env python3
"""
CI check: verify every rule has required E8 metadata fields.
Exits non-zero if any rule is missing required fields.
"""

import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: pyyaml required", file=sys.stderr)
    sys.exit(1)

RULES_DIR = Path(__file__).parent.parent / "rules"
REQUIRED_TAGS_PREFIX = ("e8.control.", "e8.maturity.", "attack.")
REQUIRED_CUSTOM_FIELDS = ("e8_control", "e8_maturity", "e8_bypass_technique", "false_positive_rate")

errors = []

for rule_file in sorted(RULES_DIR.rglob("*.yml")):
    with open(rule_file, encoding="utf-8") as f:
        try:
            rule = yaml.safe_load(f)
        except yaml.YAMLError as e:
            errors.append(f"{rule_file}: YAML parse error — {e}")
            continue

    if not rule or not isinstance(rule, dict):
        continue

    name = rule_file.relative_to(RULES_DIR.parent)

    tags = rule.get("tags", [])
    for prefix in REQUIRED_TAGS_PREFIX:
        if not any(t.startswith(prefix) for t in tags):
            errors.append(f"{name}: missing tag with prefix '{prefix}'")

    custom = rule.get("custom", {}) or {}
    for field in REQUIRED_CUSTOM_FIELDS:
        if field not in custom:
            errors.append(f"{name}: missing custom.{field}")

    if not rule.get("id"):
        errors.append(f"{name}: missing id (UUID)")

    if not rule.get("description"):
        errors.append(f"{name}: missing description")

if errors:
    print(f"\n{len(errors)} metadata error(s) found:\n")
    for e in errors:
        print(f"  ✗ {e}")
    sys.exit(1)
else:
    rule_count = sum(1 for _ in RULES_DIR.rglob("*.yml"))
    print(f"All {rule_count} rules passed metadata checks.")
