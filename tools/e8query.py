#!/usr/bin/env python3
"""
e8query.py — Query and filter Essential Eight Sigma rules.

Usage:
    python e8query.py --list
    python e8query.py --control e8-05
    python e8query.py --maturity ML2
    python e8query.py --logsource windows
    python e8query.py --control e8-03 --logsource windows
    python e8query.py --level high
    python e8query.py --stats
"""

import argparse
import sys
from pathlib import Path
from typing import Optional

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML not installed. Run: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

RULES_DIR = Path(__file__).parent.parent / "rules"

CONTROL_NAMES = {
    "e8-01": "Application Control",
    "e8-02": "Patch Applications",
    "e8-03": "Configure Microsoft Office Macro Settings",
    "e8-04": "User Application Hardening",
    "e8-05": "Restrict Administrative Privileges",
    "e8-06": "Patch Operating Systems",
    "e8-07": "Multi-Factor Authentication",
    "e8-08": "Regular Backups",
}


def load_rules() -> list[dict]:
    rules = []
    for rule_file in sorted(RULES_DIR.rglob("*.yml")):
        try:
            with open(rule_file, encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if data and isinstance(data, dict) and "title" in data:
                data["_file"] = rule_file.relative_to(RULES_DIR.parent)
                rules.append(data)
        except yaml.YAMLError as e:
            print(f"WARN: Could not parse {rule_file}: {e}", file=sys.stderr)
    return rules


def get_e8_control(rule: dict) -> Optional[str]:
    custom = rule.get("custom", {})
    if custom and "e8_control" in custom:
        return custom["e8_control"].lower().replace("_", "-")
    tags = rule.get("tags", [])
    for tag in tags:
        if tag.startswith("e8.control."):
            num = tag.split(".")[-1].zfill(2)
            return f"e8-{num}"
    return None


def get_e8_maturity(rule: dict) -> Optional[str]:
    custom = rule.get("custom", {})
    if custom and "e8_maturity" in custom:
        return custom["e8_maturity"].upper()
    tags = rule.get("tags", [])
    for tag in tags:
        if tag.startswith("e8.maturity."):
            return tag.split(".")[-1].upper()
    return None


def get_logsource(rule: dict) -> str:
    ls = rule.get("logsource", {})
    parts = [ls.get("product", ""), ls.get("service", ""), ls.get("category", "")]
    return " / ".join(p for p in parts if p)


def filter_rules(
    rules: list[dict],
    control: Optional[str] = None,
    maturity: Optional[str] = None,
    logsource: Optional[str] = None,
    level: Optional[str] = None,
) -> list[dict]:
    results = rules
    if control:
        c = control.lower()
        results = [r for r in results if (get_e8_control(r) or "").startswith(c)]
    if maturity:
        m = maturity.upper()
        results = [r for r in results if get_e8_maturity(r) == m]
    if logsource:
        ls = logsource.lower()
        results = [r for r in results if ls in get_logsource(r).lower()]
    if level:
        lv = level.lower()
        results = [r for r in results if (r.get("level") or "").lower() == lv]
    return results


def print_rule_row(rule: dict, verbose: bool = False) -> None:
    control = get_e8_control(rule) or "unknown"
    maturity = get_e8_maturity(rule) or "?"
    level = rule.get("level", "?")
    title = rule.get("title", "Untitled")
    file_path = rule.get("_file", "")

    level_colors = {"critical": "\033[91m", "high": "\033[93m", "medium": "\033[94m", "low": "\033[92m"}
    reset = "\033[0m"
    color = level_colors.get(level.lower(), "")

    print(f"  {control.upper():<8} {maturity:<5} {color}{level:<8}{reset}  {title}")
    if verbose:
        print(f"           File:      {file_path}")
        ls = get_logsource(rule)
        if ls:
            print(f"           LogSource: {ls}")
        custom = rule.get("custom", {})
        if custom.get("e8_bypass_technique"):
            print(f"           Bypass:    {custom['e8_bypass_technique']}")
        if custom.get("false_positive_rate"):
            print(f"           FP Rate:   {custom['false_positive_rate']}")
        print()


def cmd_list(rules: list[dict], verbose: bool) -> None:
    print(f"\n{'CONTROL':<8} {'ML':<5} {'LEVEL':<8}  TITLE")
    print("─" * 80)
    for rule in rules:
        print_rule_row(rule, verbose)
    print(f"\n{len(rules)} rule(s) found.")


def cmd_stats(rules: list[dict]) -> None:
    from collections import Counter

    controls = Counter(get_e8_control(r) or "unknown" for r in rules)
    levels = Counter((r.get("level") or "unknown").lower() for r in rules)
    maturities = Counter(get_e8_maturity(r) or "unknown" for r in rules)

    print("\n=== Essential Eight Detection Lab — Stats ===\n")

    print("Rules per control:")
    for ctrl in sorted(controls):
        name = CONTROL_NAMES.get(ctrl, "")
        print(f"  {ctrl.upper():<8} {controls[ctrl]:>3}  {name}")

    print("\nRules per severity level:")
    for lv in ["critical", "high", "medium", "low", "unknown"]:
        if lv in levels:
            print(f"  {lv:<10} {levels[lv]:>3}")

    print("\nRules per minimum maturity level:")
    for ml in ["ML1", "ML2", "ML3", "unknown"]:
        if ml in maturities:
            print(f"  {ml:<6} {maturities[ml]:>3}")

    print(f"\nTotal rules: {len(rules)}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Query Essential Eight Sigma rules",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--control", help="Filter by E8 control (e.g. e8-05, e8-03)")
    parser.add_argument("--maturity", help="Filter by min maturity level (ML1, ML2, ML3)")
    parser.add_argument("--logsource", help="Filter by log source product/service (e.g. windows, azure)")
    parser.add_argument("--level", help="Filter by severity level (critical, high, medium, low)")
    parser.add_argument("--list", action="store_true", help="List all rules (default if no filter)")
    parser.add_argument("--stats", action="store_true", help="Show summary statistics")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show full rule details")

    args = parser.parse_args()

    if not RULES_DIR.exists():
        print(f"ERROR: rules/ directory not found at {RULES_DIR}", file=sys.stderr)
        sys.exit(1)

    all_rules = load_rules()

    if not all_rules:
        print("No rules found. Check that rules/ contains .yml files.")
        sys.exit(0)

    if args.stats:
        cmd_stats(all_rules)
        return

    filtered = filter_rules(
        all_rules,
        control=args.control,
        maturity=args.maturity,
        logsource=args.logsource,
        level=args.level,
    )

    cmd_list(filtered, verbose=args.verbose)


if __name__ == "__main__":
    main()
