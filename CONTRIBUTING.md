# Contributing to Essential Eight Detection Lab

Thanks for contributing. The goal is high-quality, interview-defensible Sigma rules — not volume. One well-tuned rule beats five noisy ones.

---

## What we're looking for

- **Sigma rules** mapped to an E8 control with accurate metadata
- **Emulation scripts** that safely trigger the detection in a lab environment
- **Mapping updates** when a rule covers a technique not yet in `docs/mapping.yaml`
- **Tuning feedback** — if a rule fires with high FP rate, open an issue with environment details

## What we're not looking for

- Rules with no E8 control mapping
- Rules that duplicate existing SigmaHQ content without E8-specific value
- Emulation scripts that require real malware or live C2 infrastructure

---

## Rule Requirements

Every rule must have:

```yaml
title:        # Clear, descriptive — usable as a blog post title
id:           # UUID v4 — generate with: python -c "import uuid; print(uuid.uuid4())"
status:       # experimental / test / stable
description:  # What the rule detects and WHY it maps to the E8 control
tags:
    - e8.control.XX      # e.g. e8.control.05
    - e8.maturity.mlX    # e.g. e8.maturity.ml2
    - attack.tXXXX       # ATT&CK technique
custom:
    e8_control: E8-XX
    e8_maturity: MLX
    e8_bypass_technique: <one-line description of bypass>
    false_positive_rate: low | medium | high
    tuning_notes: |
        <what to suppress and why>
```

---

## Submitting upstream to SigmaHQ

Rules in this repo that are stable and generic enough should be submitted to [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma). When they merge, update the table in `README.md`.

**Before submitting upstream:**
1. Remove `custom:` block (not part of Sigma spec)
2. Move E8 tags to `tags:` using `attack.*` tags only
3. Ensure the rule validates: `sigma check <rule.yml>`
4. Follow [SigmaHQ contribution guidelines](https://github.com/SigmaHQ/sigma/blob/master/CONTRIBUTING.md)

---

## Local setup

```bash
pip install sigma-cli pyyaml

# Validate all rules
sigma check rules/

# Convert to Splunk
sigma convert -t splunk rules/

# Query rules
python tools/e8query.py --stats
python tools/e8query.py --control e8-05 -v
```

---

## Branch and PR conventions

- Branch: `rule/e8-XX-short-description` or `fix/rule-title`
- PR title: `[E8-XX] Rule: <title>` or `[E8-XX] Fix: <description>`
- PR body must include:
  - Which E8 control and maturity level
  - What technique it detects
  - How you tested it (log snippet, emulation script, or lab description)
  - Known false positives and how to suppress them

---

## Filing issues

Use the issue templates:
- **New rule request** — describe the bypass technique and E8 control
- **False positive report** — rule name, environment context, suppression suggestion
- **SigmaHQ PR tracking** — link to upstream PR

---

## Licence

By contributing you agree your rules are released under the [Detection Rule License (DRL) 1.1](https://github.com/SigmaHQ/Detection-Rule-License) and emulation scripts under MIT.
