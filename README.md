# Essential Eight Detection Lab

Sigma detection rules and adversary emulation scripts mapped to the [ASD Essential Eight](https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight) mitigation strategies.

> **Status:** Active development. Rules are being submitted upstream to [SigmaHQ](https://github.com/SigmaHQ/sigma).

---

## Why Essential Eight?

MITRE ATT&CK is the universal language of detections, but Australian government and critical infrastructure environments are assessed against the Essential Eight maturity model. This project maps detections directly to E8 controls so SOC teams can answer: *"Are we detecting bypass of our own mitigations?"*

---

## Structure

```
rules/                    # Sigma rules, one folder per E8 control
  e8-01-application-control/
  e8-02-patch-applications/
  e8-03-office-macros/
  e8-04-user-app-hardening/
  e8-05-restrict-admin/
  e8-06-patch-os/
  e8-07-mfa/
  e8-08-backups/

emulation/                # PowerShell emulation scripts per control
  e8-01/ … e8-08/

tools/
  e8query.py              # CLI: filter rules by control, ML, log source

docs/
  mapping.yaml            # E8 control → ATT&CK technique cross-reference
```

---

## Essential Eight Controls

| # | Control | Maturity Levels |
|---|---------|----------------|
| E8-01 | Application Control | ML1–ML3 |
| E8-02 | Patch Applications | ML1–ML3 |
| E8-03 | Configure Microsoft Office Macro Settings | ML1–ML3 |
| E8-04 | User Application Hardening | ML1–ML3 |
| E8-05 | Restrict Administrative Privileges | ML1–ML3 |
| E8-06 | Patch Operating Systems | ML1–ML3 |
| E8-07 | Multi-Factor Authentication | ML1–ML3 |
| E8-08 | Regular Backups | ML1–ML3 |

---

## Quick Start

### Web Dashboard

```bash
pip install flask pyyaml
python tools/webapp/app.py
# Open http://localhost:5000
```

Features: coverage overview by control, filterable rule browser, rule detail with YAML viewer and tuning notes, E8↔ATT&CK mapping.

### Query rules by control (CLI)

```bash
python tools/e8query.py --control e8-05
python tools/e8query.py --maturity ML2
python tools/e8query.py --logsource windows --control e8-03
python tools/e8query.py --list
```

### Validate all rules

```bash
pip install sigma-cli
sigma check rules/
```

### Convert rules to a SIEM backend

```bash
# Splunk
sigma convert -t splunk rules/e8-05-restrict-admin/

# Microsoft Sentinel (KQL)
sigma convert -t microsoft365defender rules/e8-01-application-control/

# Elastic
sigma convert -t elasticsearch rules/
```

### Run emulation (lab environment only)

```powershell
# Run as non-admin in a Windows VM
.\emulation\e8-03\Invoke-MacroEmulation.ps1
```

---

## Rule Metadata Convention

Every rule carries these custom fields under `tags` and `custom`:

```yaml
tags:
  - e8.control.01          # E8 control number
  - e8.maturity.ml2        # minimum maturity level where this should fire
  - attack.t1059.001       # ATT&CK technique
custom:
  e8_control: "E8-01"
  e8_maturity: "ML2"
  e8_bypass_technique: "LOLBAS via mshta.exe"
  false_positive_rate: low  # low / medium / high
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Rule submissions that get merged into SigmaHQ upstream are credited in the table below.

---

## Upstream SigmaHQ PRs

| Rule | PR | Status |
|------|----|--------|
| *(first submission pending)* | — | — |

---

## References

- [ASD Essential Eight Explained](https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight/essential-eight-explained)
- [Essential Eight Maturity Model](https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight/essential-eight-maturity-model)
- [SigmaHQ Rule Specification](https://github.com/SigmaHQ/sigma-specification)
- [MITRE ATT&CK](https://attack.mitre.org/)

---

## License

Rules: [Detection Rule License (DRL) 1.1](https://github.com/SigmaHQ/Detection-Rule-License)  
Emulation scripts: MIT
