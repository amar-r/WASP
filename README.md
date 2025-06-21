# 🛡️ WISP - Windows Infrastructure Security Profiler

**WISP** is a lightweight PowerShell-based auditing tool that scans Windows systems for outdated software and configuration drift against the CIS (Center for Internet Security) benchmarks. Designed for security engineers, platform teams, and auditors, WISP outputs human-readable and machine-parsable compliance reports in YAML, JSON, or CSV formats.

---

## 🔧 Features

- 📦 Scans for outdated or unapproved installed software
- 🗂️ Compares system configuration to CIS baselines (customizable via YAML)
- ⚙️ Checks Windows registry, services, and local policies
- 🧾 Outputs results in YAML, JSON, and optional CSV formats
- ✅ Lightweight and agentless—no dependencies beyond PowerShell

---

## 📚 Use Cases

- Validate Windows Server configuration against CIS benchmarks
- Detect insecure services, misconfigurations, or unnecessary software
- Generate compliance reports for internal security reviews
- Use as part of a CI/CD pipeline or with remote PowerShell execution

---

## 🚀 Getting Started

```powershell
# Run scan on local system using default baseline
.\scan.ps1 -Baseline .\baselines\cis-ws2019.yaml -Output .\output\report.json
