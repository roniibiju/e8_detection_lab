#!/usr/bin/env python3
"""
Essential Eight Detection Lab — Web Dashboard
Run: python tools/webapp/app.py
Then open: http://localhost:5000
"""

from pathlib import Path
from flask import Flask, render_template, request, abort
import yaml

BASE_DIR = Path(__file__).parent.parent.parent
WEBAPP_DIR = Path(__file__).parent
RULES_DIR = BASE_DIR / "rules"
MAPPING_FILE = BASE_DIR / "docs" / "mapping.yaml"
EMULATION_DIR = BASE_DIR / "emulation"

app = Flask(__name__,
            template_folder=str(WEBAPP_DIR / "templates"),
            static_folder=str(WEBAPP_DIR / "static"))

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

CONTROL_ICONS = {
    "e8-01": "shield-lock",
    "e8-02": "patch-check",
    "e8-03": "file-earmark-code",
    "e8-04": "person-lock",
    "e8-05": "key",
    "e8-06": "cpu",
    "e8-07": "phone-vibrate",
    "e8-08": "archive",
}

LEVEL_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}


def _get_control(rule: dict) -> str:
    custom = rule.get("custom") or {}
    if "e8_control" in custom:
        return custom["e8_control"].lower().replace("_", "-")
    for tag in rule.get("tags") or []:
        if tag.startswith("e8.control."):
            return "e8-" + tag.split(".")[-1].zfill(2)
    return "unknown"


def _get_maturity(rule: dict) -> str:
    custom = rule.get("custom") or {}
    if "e8_maturity" in custom:
        return custom["e8_maturity"].upper()
    for tag in rule.get("tags") or []:
        if tag.startswith("e8.maturity."):
            return tag.split(".")[-1].upper()
    return "?"


def _get_logsource(rule: dict) -> str:
    ls = rule.get("logsource") or {}
    parts = [ls.get("product", ""), ls.get("service", ""), ls.get("category", "")]
    return " / ".join(p for p in parts if p)


def _get_attack_tags(rule: dict) -> list[str]:
    return [t for t in (rule.get("tags") or []) if t.startswith("attack.t")]


def load_rules() -> list[dict]:
    rules = []
    for path in sorted(RULES_DIR.rglob("*.yml")):
        try:
            raw = path.read_text(encoding="utf-8")
            data = yaml.safe_load(raw)
            if not data or not isinstance(data, dict) or "title" not in data:
                continue
            data["_file"] = str(path.relative_to(BASE_DIR))
            data["_raw"] = raw
            data["_control"] = _get_control(data)
            data["_maturity"] = _get_maturity(data)
            data["_logsource"] = _get_logsource(data)
            data["_attack_tags"] = _get_attack_tags(data)
            data["_level"] = (data.get("level") or "unknown").lower()
            data["_control_name"] = CONTROL_NAMES.get(data["_control"], data["_control"])
            data["_id"] = data.get("id", path.stem)

            # check for a matching emulation script
            ctrl_num = data["_control"].split("-")[1] if "-" in data["_control"] else ""
            emulation_dir = EMULATION_DIR / f"e8-{ctrl_num}"
            scripts = list(emulation_dir.glob("*.ps1")) if emulation_dir.exists() else []
            data["_emulation_scripts"] = [str(s.relative_to(BASE_DIR)) for s in scripts]

            rules.append(data)
        except Exception:
            continue
    rules.sort(key=lambda r: (r["_control"], LEVEL_ORDER.get(r["_level"], 4)))
    return rules


def load_mapping() -> dict:
    if not MAPPING_FILE.exists():
        return {}
    with open(MAPPING_FILE, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


@app.context_processor
def inject_globals():
    return {
        "control_names": CONTROL_NAMES,
        "control_icons": CONTROL_ICONS,
        "all_controls": sorted(CONTROL_NAMES.keys()),
    }


@app.route("/health")
def health():
    return {"status": "ok", "rules_dir": str(RULES_DIR), "exists": RULES_DIR.exists()}


@app.errorhandler(Exception)
def handle_error(e):
    import traceback
    return f"""
    <h1>Error</h1>
    <pre>{traceback.format_exc()}</pre>
    """, 500


@app.route("/")
def index():
    rules = load_rules()

    # per-control stats
    control_stats = {}
    for ctrl, name in CONTROL_NAMES.items():
        ctrl_rules = [r for r in rules if r["_control"] == ctrl]
        maturities = sorted({r["_maturity"] for r in ctrl_rules if r["_maturity"] != "?"})
        levels = sorted({r["_level"] for r in ctrl_rules}, key=lambda l: LEVEL_ORDER.get(l, 4))
        control_stats[ctrl] = {
            "name": name,
            "count": len(ctrl_rules),
            "maturities": maturities,
            "top_level": levels[0] if levels else "none",
            "icon": CONTROL_ICONS.get(ctrl, "shield"),
        }

    high_critical = [r for r in rules if r["_level"] in ("high", "critical")]
    controls_covered = sum(1 for c in CONTROL_NAMES if any(r["_control"] == c for r in rules))

    return render_template(
        "index.html",
        rules=rules,
        control_stats=control_stats,
        total_rules=len(rules),
        controls_covered=controls_covered,
        high_critical_count=len(high_critical),
        recent_rules=rules[:5],
    )


@app.route("/rules/")
def rules_list():
    all_rules = load_rules()

    control_filter = request.args.get("control", "").lower()
    maturity_filter = request.args.get("maturity", "").upper()
    level_filter = request.args.get("level", "").lower()
    search = request.args.get("q", "").lower()

    filtered = all_rules
    if control_filter:
        filtered = [r for r in filtered if r["_control"] == control_filter]
    if maturity_filter:
        filtered = [r for r in filtered if r["_maturity"] == maturity_filter]
    if level_filter:
        filtered = [r for r in filtered if r["_level"] == level_filter]
    if search:
        filtered = [
            r for r in filtered
            if search in r.get("title", "").lower()
            or search in (r.get("description") or "").lower()
            or search in r.get("_control", "").lower()
        ]

    return render_template(
        "rules.html",
        rules=filtered,
        total=len(filtered),
        control_filter=control_filter,
        maturity_filter=maturity_filter,
        level_filter=level_filter,
        search=search,
    )


@app.route("/rules/<rule_id>/")
def rule_detail(rule_id):
    rules = load_rules()
    rule = next((r for r in rules if r.get("_id") == rule_id), None)
    if not rule:
        abort(404)
    return render_template("rule_detail.html", rule=rule)


@app.route("/mapping/")
def mapping():
    data = load_mapping()
    return render_template("mapping.html", mapping=data)


@app.route("/about/")
def about():
    return render_template("about.html")


@app.route("/emulation/<path:script_path>")
def emulation_view(script_path):
    full_path = BASE_DIR / "emulation" / script_path
    if not full_path.exists() or full_path.suffix != ".ps1":
        abort(404)
    content = full_path.read_text(encoding="utf-8")
    return render_template("emulation_view.html", script_path=script_path, content=content)


if __name__ == "__main__":
    import argparse, os
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", 8080)))
    args = parser.parse_args()
    app.run(debug=True, port=args.port)
