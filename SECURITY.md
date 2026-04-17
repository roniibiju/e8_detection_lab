# Security Policy

## Scope

This repository contains **detection rules and emulation scripts** — it is a defensive security project.
Emulation scripts are intentionally benign: they generate telemetry without executing real payloads.

## Reporting a False Positive or Logic Error

If you find a rule that will not fire as described, or fires on clearly benign activity:

1. Open an issue using the **False Positive Report** template
2. Include: rule filename, environment context, log snippet (sanitised), and suggested fix

## Reporting a Vulnerability in the Web Dashboard

The web dashboard (`tools/webapp/`) is a local-only read-only tool.
It serves static files generated from YAML on your own machine — there is no authentication surface.

If you find a path traversal or injection issue in the Flask app, open an issue.

## Out of Scope

- The emulation scripts are designed to run in isolated lab VMs. Running them outside a lab
  environment is the user's responsibility.
- Rules are provided as-is with no guarantee of detection coverage in any specific SIEM or EDR.
