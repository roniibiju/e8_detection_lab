#!/usr/bin/env python3
"""
Generate a fully static version of the E8 Detection Lab dashboard.

Usage:
    python tools/webapp/freeze.py

Output: dist/  — upload the contents of this folder to Hostinger public_html.
"""

import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

DEST = Path(__file__).parent.parent.parent / "dist"

# Clean before each build to avoid file/directory conflicts
if DEST.exists():
    shutil.rmtree(DEST)

from app import app, load_rules, CONTROL_NAMES, BASE_DIR
from flask_frozen import Freezer

app.config["FREEZER_DESTINATION"] = str(DEST)
app.config["FREEZER_RELATIVE_URLS"] = True
app.config["FREEZER_IGNORE_MIMETYPE_WARNINGS"] = True
# Ensures /rules → dist/rules/index.html (dir), not dist/rules (file)
app.config["FREEZER_REDIRECT_POLICY"] = "ignore"

# Force trailing slashes on all routes so Frozen-Flask uses index.html files
app.url_map.strict_slashes = False


freezer = Freezer(app)


@freezer.register_generator
def rules_list():
    yield {}
    for ctrl in CONTROL_NAMES:
        yield {"control": ctrl}


@freezer.register_generator
def rule_detail():
    for rule in load_rules():
        yield {"rule_id": rule["_id"]}


@freezer.register_generator
def emulation_view():
    for ps1 in (BASE_DIR / "emulation").rglob("*.ps1"):
        yield {"script_path": str(ps1.relative_to(BASE_DIR / "emulation"))}


if __name__ == "__main__":
    print("Building static site…")
    freezer.freeze()
    html_files = list(DEST.rglob("*.html"))
    print(f"\nDone — {len(html_files)} HTML pages written to {DEST}/")
    print("\nTo deploy:")
    print("  1. Open Hostinger hPanel → File Manager")
    print("  2. Navigate into the folder for e8lab.ronibiju.com")
    print("  3. Upload everything inside dist/")
