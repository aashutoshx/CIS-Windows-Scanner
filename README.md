# CIS Benchmark Configuration Review Tool

A modular Python-based security assessment tool that evaluates Windows Endpoints and Windows
Servers against CIS Benchmark controls and generates professional Excel reports.

---

## Architecture Overview

```
cis_scanner/
├── main.py                          # Entry point — CLI prompts & argument parser
├── requirements.txt
│
├── engine/
│   └── scanner.py                   # Orchestrates checklist loading & check dispatch
│
├── checkers/
│   ├── base_checker.py              # Abstract base class + CheckResult dataclass
│   ├── registry_checker.py          # Windows registry reads (winreg)
│   ├── service_checker.py           # Service startup/state (sc.exe)
│   ├── policy_checker.py            # Security policy (secedit) + audit policy (auditpol)
│   └── network_checker.py          # Firewall (netsh) + network settings
│
├── checklists/
│   ├── windows_endpoint_essential.json
│   ├── windows_endpoint_intermediate.json
│   ├── windows_endpoint_deep.json   # Extend with your own controls
│   └── windows_server_essential.json
│
└── reporting/
    └── excel_reporter.py            # 3-sheet Excel report (openpyxl)
```

---

## Quick Start

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Interactive mode (recommended)
```bash
python main.py
```
You will be prompted to select:
- System type (Endpoint or Server)
- Scan depth (Essential / Intermediate / Deep)
- Output file path

### 3. CLI / automated mode
```bash
# Windows Endpoint — Intermediate scan
python main.py --system windows_endpoint --depth intermediate --output report.xlsx

# Windows Server — Essential scan
python main.py --system windows_server --depth essential --output server_report.xlsx

# All options
python main.py --system [windows_endpoint|windows_server] \
               --depth  [essential|intermediate|deep] \
               --output [path/to/output.xlsx]
```

---

## Scan Depths

| Depth        | Controls Included         | Use Case                              |
|-------------|--------------------------|---------------------------------------|
| Essential    | Critical controls only    | Quick spot-check, first scan          |
| Intermediate | Essential + moderate      | Regular compliance assessment         |
| Deep         | All CIS benchmark checks  | Full audit, pre-certification review  |

Depths are **cumulative** — Intermediate includes all Essential controls.

---

## Check Types & Implementation

### registry
Reads a specific Windows registry key/value using the built-in `winreg` module.

```json
{
  "check_type": "registry",
  "check_params": {
    "hive": "HKLM",
    "key": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
    "value_name": "EnableLUA",
    "expected": 1,
    "operator": "eq"
  }
}
```

### service
Checks a Windows service startup type and/or running state via `sc.exe`.

```json
{
  "check_type": "service",
  "check_params": {
    "service_name": "RemoteRegistry",
    "expected_startup": "disabled",
    "operator": "eq"
  }
}
```

### security_policy
Exports local security policy via `secedit /export` and reads values from the .cfg output.
Covers: password policy, account lockout, user rights assignments.

```json
{
  "check_type": "security_policy",
  "check_params": {
    "section": "System Access",
    "policy_key": "MinimumPasswordLength",
    "expected": 14,
    "operator": "gte"
  }
}
```

### audit_policy
Runs `auditpol /get /category:*` and checks audit settings per subcategory.

```json
{
  "check_type": "audit_policy",
  "check_params": {
    "subcategory": "Logon",
    "expected": "Success and Failure",
    "operator": "eq"
  }
}
```

### firewall
Queries Windows Defender Firewall per-profile state and settings via `netsh advfirewall`.

```json
{
  "check_type": "firewall",
  "check_params": {
    "profile": "domain",
    "setting": "state",
    "expected": "on",
    "operator": "eq"
  }
}
```

---

## Supported Operators

| Operator      | Meaning                          |
|--------------|----------------------------------|
| `eq`          | Equal (case-insensitive)         |
| `neq`         | Not equal                        |
| `gte`         | Greater than or equal (numeric)  |
| `lte`         | Less than or equal (numeric)     |
| `gt`          | Greater than                     |
| `lt`          | Less than                        |
| `contains`    | Substring match                  |
| `not_contains`| Substring not present            |
| `exists`      | Key/value exists                 |
| `not_exists`  | Key/value must not exist         |

---

## Adding Your Own Controls

### Extend an existing checklist
Add your control object to the relevant JSON file:

```json
{
  "id": "CUSTOM.1.1",
  "name": "My Custom Control",
  "description": "Describe what is being checked and why.",
  "category": "Custom",
  "severity": "High",
  "check_type": "registry",
  "check_params": {
    "hive": "HKLM",
    "key": "SOFTWARE\\MyApp",
    "value_name": "SecureSetting",
    "expected": 1,
    "operator": "eq"
  },
  "remediation": "How to fix if non-compliant.",
  "references": "Internal Policy / NIST SP 800-53 CM-7"
}
```

### Add a new checker type
1. Create `checkers/my_checker.py` inheriting from `BaseChecker`
2. Implement `_check(self, control: dict) -> CheckResult`
3. Register it in `engine/scanner.py`:
   ```python
   from checkers.my_checker import MyChecker
   CHECKER_REGISTRY["my_type"] = MyChecker()
   ```

---

## Excel Report Structure

The generated `.xlsx` report contains three sheets:

| Sheet          | Contents                                                             |
|---------------|----------------------------------------------------------------------|
| **Summary**    | Compliance score, stat boxes, severity breakdown, category table     |
| **Findings**   | Full detail for every control — filterable, colour-coded by status   |
| **By Category**| Per-category pass rates with colour-coded scores                     |

### Status colour coding
- 🟢 **Compliant** — Green
- 🔴 **Non-Compliant** — Red
- 🟡 **Error / Skipped** — Amber

---

## Running Without Windows (Dev/Testing)

The tool includes a **simulation layer** in every checker. When run on Linux/macOS,
realistic default values are returned so the full report pipeline can be tested
and the Excel output can be verified.

To customise simulated values, edit the `_simulate()` method in each checker file.

---

## Extending to Linux

To add Linux support:
1. Create `checkers/linux_sysctl_checker.py`, `linux_service_checker.py`, etc.
2. Add checklists under `checklists/linux_server_essential.json`
3. Extend the `SYSTEM_TYPES` dict in `main.py` and `CHECKER_REGISTRY` in `scanner.py`

The architecture is fully modular — no changes to the core engine or reporter are needed.

---

## Required Permissions

Run the tool as a **local Administrator** (or Domain Admin for GPO-level checks).
Some checks (`secedit`, `auditpol`) require elevated privileges.

```powershell
# Run as Administrator in PowerShell
Start-Process python -ArgumentList "main.py" -Verb RunAs
```

---

## Recommended Libraries (advanced use)

| Library     | Purpose                                     | Install              |
|------------|---------------------------------------------|----------------------|
| `pywin32`   | Advanced registry, services, Event Log APIs | `pip install pywin32`|
| `wmi`       | WMI queries (hardware, OS, processes)       | `pip install wmi`    |
| `python-gflags`| GPO/Group Policy via LGPO.exe wrapper   | manual               |
| `openpyxl`  | Excel report generation (**required**)      | `pip install openpyxl`|

---

## Roadmap / Future Enhancements

- [ ] Remote scanning via WinRM (`pywinrm`)
- [ ] Linux CIS Benchmark support (Ubuntu, RHEL)
- [ ] HTML report output
- [ ] Baseline delta comparison (compare two scans)
- [ ] Scheduled scan + email reporting
- [ ] GPO-level verification via LGPO.exe
- [ ] CVSS-scored risk ratings per finding
