# CIS Benchmark Configuration Review Tool
### Version 1.1

A modular Python-based security assessment tool that evaluates **Windows Endpoints**,
**Windows Servers**, and **any modern Linux distribution** against CIS Benchmark controls
and generates professional Excel reports with full audit logging.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Quick Start](#quick-start)
- [Scan Depths](#scan-depths)
- [Check Types — Windows](#check-types--windows)
- [Check Types — Linux](#check-types--linux)
- [Supported Operators](#supported-operators)
- [Excel Report Structure](#excel-report-structure)
- [Audit Logging](#audit-logging)
- [Adding Your Own Controls](#adding-your-own-controls)
- [Linux Support](#linux-support)
- [Platform Safety](#platform-safety)
- [Required Permissions](#required-permissions)
- [Understanding Audit Policy Results](#understanding-audit-policy-results)
- [Recommended Libraries](#recommended-libraries)
- [Roadmap / Future Enhancements](#roadmap--future-enhancements)

---

## Architecture Overview

```
cis_scanner/
├── main.py                          # Entry point — CLI prompts & argument parser
├── requirements.txt
│
├── engine/
│   ├── scanner.py                   # Orchestrates checklist loading & check dispatch
│   └── audit_logger.py              # Structured rotating audit log (per-scan .log file)
│
├── checkers/
│   ├── base_checker.py              # Abstract base class + CheckResult dataclass
│   ├── registry_checker.py          # Windows registry reads (winreg)
│   ├── service_checker.py           # Service startup/state (sc.exe)
│   ├── policy_checker.py            # Security policy (secedit) + audit policy (auditpol)
│   ├── network_checker.py           # Firewall (netsh) + network settings
│   ├── account_checker.py           # Local account policy checks
│   └── linux_checker.py             # All Linux check types (10 checker classes)
│
├── checklists/
│   ├── windows_endpoint/
│   │   ├── essential.json           # Critical controls — fast scan
│   │   ├── intermediate.json        # Moderate coverage
│   │   └── deep.json                # Full CIS benchmark
│   ├── windows_server/
│   │   └── essential.json
│   └── linux/
│       ├── essential.json           # 28 high-impact baseline controls
│       ├── intermediate.json        # Kernel modules, mounts, service hygiene
│       └── deep.json                # PAM, boot hardening, file integrity, sysctl
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
- System type (Windows Endpoint / Windows Server / Linux)
- Scan depth (Essential / Intermediate / Deep)
- Output file path

### 3. CLI / automated mode
```bash
# Windows Endpoint — deep scan
python main.py --system windows_endpoint --depth deep --output report.xlsx

# Windows Server — essential scan
python main.py --system windows_server --depth essential --output server_report.xlsx

# Linux host — run directly on the target Linux machine
python main.py --system linux --depth deep --output linux_report.xlsx

# Synthetic Linux report for pipeline/format testing (NOT a real audit)
python main.py --system linux --depth deep --simulate --output test_report.xlsx

# All flags
python main.py --system [windows_endpoint|windows_server|linux] \
               --depth  [essential|intermediate|deep] \
               --output [path/to/output.xlsx] \
               --verbose \
               --simulate
```

---

## Scan Depths

| Depth        | Controls Included         | Use Case                              |
|-------------|--------------------------|---------------------------------------|
| Essential    | Critical controls only    | Quick spot-check, first scan          |
| Intermediate | Essential + moderate      | Regular compliance assessment         |
| Deep         | All CIS benchmark checks  | Full audit, pre-certification review  |

Depths are **cumulative** — Intermediate includes all Essential controls, Deep includes all
Intermediate controls. When tiers define the same check with different IDs, the deeper tier's
definition wins (it carries the official CIS benchmark ID and richer metadata).

---

## Check Types — Windows

### `registry`
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

> **Note:** Keys in `HKLM\SAM` require **SYSTEM-level** privilege (not just local Administrator).
> The tool returns a structured `Error` result with a clear remediation note rather than crashing.

### `service`
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

### `security_policy`
Exports local security policy via `secedit /export` and reads values from the `.cfg` output.
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

### `audit_policy`
Runs `auditpol /get /category:*` and checks the **effective** audit setting per subcategory.

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

> **Important — "Not Configured" vs actual values:** `auditpol` reads the *effective* audit
> policy, which combines GPO-configured settings, Local Security Policy, and Windows OS
> built-in defaults. A subcategory showing **"Not Configured"** in `gpedit.msc` Advanced
> Audit Policy does **not** mean "No Auditing" — Windows OS defaults still apply underneath.
> See [Understanding Audit Policy Results](#understanding-audit-policy-results) for full details.

### `firewall`
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

## Check Types — Linux

| Check type             | What it verifies                                        |
|------------------------|---------------------------------------------------------|
| `linux_file`           | File existence, mode, owner, group, content regex       |
| `linux_sshd`           | `/etc/ssh/sshd_config` directive (via `sshd -T`)        |
| `linux_sysctl`         | Kernel parameter (`net`, `kernel`, `fs` namespaces)     |
| `linux_service`        | systemd unit `is-enabled` / `is-active`                 |
| `linux_package`        | Package installed (dpkg / rpm / pacman — auto-detected) |
| `linux_kernel_module`  | Module loaded / blacklisted via `modprobe`              |
| `linux_mount`          | fstab option present on a mount point (`nodev`, `noexec`, …) |
| `linux_login_defs`     | `/etc/login.defs` key/value                             |
| `linux_firewall`       | `ufw` / `firewalld` / `nftables` / `iptables` is active |
| `linux_command`        | Generic shell command with stdout pattern match         |

---

## Supported Operators

| Operator       | Meaning                          |
|---------------|----------------------------------|
| `eq`           | Equal (case-insensitive)         |
| `neq`          | Not equal                        |
| `gte`          | Greater than or equal (numeric)  |
| `lte`          | Less than or equal (numeric)     |
| `gt`           | Greater than                     |
| `lt`           | Less than                        |
| `contains`     | Substring match                  |
| `not_contains` | Substring not present            |
| `exists`       | Key/value exists                 |
| `not_exists`   | Key/value must not exist         |

---

## Excel Report Structure

The generated `.xlsx` report contains three sheets:

| Sheet           | Contents                                                             |
|----------------|----------------------------------------------------------------------|
| **Summary**     | Compliance score, stat boxes, severity breakdown, category table     |
| **Findings**    | Full detail for every control — filterable, colour-coded by status   |
| **By Category** | Per-category pass rates with colour-coded scores                     |

### Status colour coding
- 🟢 **Compliant** — Green
- 🔴 **Non-Compliant** — Red
- 🟡 **Error / Skipped** — Amber

> **Excel formula safety:** All cell values are sanitised before writing. Strings that begin
> with `=`, `+`, `-`, or `@` are prefixed with a zero-width no-break space so Excel does not
> misinterpret them as formulas (preventing `#NAME?` errors in the Expected Value column).

---

## Audit Logging

Every scan produces a `.log` file alongside the Excel report (same name, `.log` extension).
The log captures:

| Entry type      | What is recorded                                              |
|----------------|---------------------------------------------------------------|
| Session header  | Platform, machine name, Python version, scan start time       |
| Checklist load  | Path and control count per tier                               |
| Dedup decisions | Which controls were superseded and by which deeper-tier ID    |
| RAW READ        | Exact value read from the system before any comparison        |
| COMPARE         | Observed vs expected, operator, PASS/FAIL outcome             |
| Check result    | Structured per-control status line (INFO / WARNING / ERROR)   |
| Session footer  | Total / Compliant / Non-Compliant / Error counts, scan time   |

Log verbosity:
```bash
python main.py --system windows_endpoint --depth deep --verbose  # DEBUG to console
```
Without `--verbose`, only WARNING/ERROR level entries appear on the console; everything
(including DEBUG) is always written to the log file.

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

### Companion controls (dual-operator checks)
When a single key needs two constraints (e.g., `1 ≤ LockoutThreshold ≤ 5`), define a
**primary** control and a **companion** (ID ending in `b`):

```json
{ "id": "X.Y.Z",  "check_params": { "operator": "gte", "expected": 1 } },
{ "id": "X.Y.Zb", "check_params": { "operator": "lte", "expected": 5 } }
```

Companion controls are never de-duplicated across tiers — both always run.

---

## Linux Support

Full support for any modern Linux distribution
(Debian/Ubuntu, RHEL/CentOS/Rocky/AlmaLinux, SUSE, Arch, Fedora) ships out of the box.

```bash
# Run a Linux scan — must be executed directly on the Linux host
python main.py --system linux --depth essential
python main.py --system linux --depth deep --output report.xlsx
```

### Linux checklists included

| Checklist                         | Controls | Coverage                                       |
|----------------------------------|----------|------------------------------------------------|
| `checklists/linux/essential.json` | 28       | SSH hardening, sysctl, firewall, account policy |
| `checklists/linux/intermediate.json` | 23    | Kernel modules, mount options, service hygiene  |
| `checklists/linux/deep.json`      | 30       | PAM, boot hardening, AIDE, world-writable audit |

All three tiers are **distro-independent** — they use standard interfaces
(`/proc/sys`, `systemctl`, `findmnt`, `sshd -T`, `dpkg`/`rpm`/`pacman`) present on every
mainstream distribution. No extra Python dependencies are required for Linux scans.

### Platform safety
The tool enforces a hard stop if you attempt to run a Linux scan on a non-Linux host:

```
[ERROR] Cannot run a Linux scan on a Windows host.
        Linux checks read /proc/sys, sysctl, systemctl, /etc/ssh/sshd_config, etc.
        Running the scan here would produce fabricated results.

        To scan a Linux target:
          1. Copy the tool to the Linux host and run it there, OR
          2. Use --simulate to generate a synthetic report for pipeline/format testing.
```

Use `--simulate` only for Excel format testing — it produces hardcoded secure-baseline
values and is clearly labelled as synthetic in both the console output and the log.

---

## Required Permissions

Run the tool as a **local Administrator** (or Domain Admin for GPO-level checks).
Some checks (`secedit`, `auditpol`) require elevated privileges.

```powershell
# Run as Administrator in PowerShell
Start-Process python -ArgumentList "main.py" -Verb RunAs
```

> **Note on HKLM\SAM:** Checks that read the SAM hive (e.g., built-in Administrator
> account status) require **SYSTEM-level** privilege, not just local Administrator.
> These return an `Error` result with remediation guidance rather than crashing.
> To run as SYSTEM: `PsExec -s python main.py --system windows_endpoint --depth deep`

---

## Understanding Audit Policy Results

Windows has **two separate audit policy layers** that are often confused:

```
secpol.msc
└── Security Settings
    ├── Local Policies
    │   └── Audit Policy                    ← LEGACY (9 broad categories)
    └── Advanced Audit Policy Configuration
        └── System Audit Policies           ← MODERN (58 granular subcategories)
```

`auditpol /get /category:*` reads the **effective** policy — the combined result of:
1. Windows OS built-in defaults (baked into Windows 10/11, always active)
2. Legacy Audit Policy settings (Local Policies → Audit Policy in secpol.msc)
3. Advanced Audit Policy Configuration (what gpedit.msc shows)

**"Not Configured" in gpedit does NOT mean "No Auditing."** It means that layer has no
override — the OS default is still active. This is why the tool reports observed values
(e.g., `Success`) for subcategories that appear unconfigured in the GUI.

To verify the effective value yourself:
```
auditpol /get /subcategory:"User Account Management"
```

To remediate a Non-Compliant audit finding:
```
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
```
Or configure via: **gpedit.msc → Advanced Audit Policy Configuration → Account Management
→ Audit User Account Management → Success and Failure**

---

## Recommended Libraries

| Library        | Purpose                                      | Install               |
|---------------|----------------------------------------------|-----------------------|
| `openpyxl`    | Excel report generation (**required**)        | `pip install openpyxl`|
| `pywin32`     | Advanced registry, services, Event Log APIs  | `pip install pywin32` |
| `wmi`         | WMI queries (hardware, OS, processes)        | `pip install wmi`     |
| `pywinrm`     | Remote WinRM-based scanning (future)         | `pip install pywinrm` |

---

## Roadmap / Future Enhancements

### ✅ Completed (v1.1)
- [x] Windows Endpoint & Server CIS Benchmark scanning
- [x] Linux CIS Benchmark support (Debian, RHEL, SUSE, Arch — distro-independent)
- [x] Three scan depths (Essential / Intermediate / Deep) with cumulative tier loading
- [x] Structured per-scan audit log with RAW READ and COMPARE entries
- [x] Platform safety guard — hard block on Linux scans running on non-Linux hosts
- [x] Subprocess timeout protection on all Windows checkers
- [x] Thread-safe parallel execution (8-worker ThreadPoolExecutor)
- [x] Excel formula injection prevention (`#NAME?` fix)

---

### 🔄 Near-term (v1.2)

- [x] **HTML report output** — self-contained single-file HTML alternative to Excel,
      suitable for email delivery and browser-based viewing without Office installed

- [ ] **Baseline delta comparison** — diff two scan reports to highlight regressions
      and improvements between scans (e.g., before/after a patch cycle)

- [ ] **Scheduled scan + email reporting** — run scans on a cron/Task Scheduler cadence
      and deliver the Excel + log automatically via SMTP

- [ ] **GPO-level verification via LGPO.exe** — import and compare Group Policy Object
      backups directly against CIS benchmark baselines

- [ ] **CVSS-scored risk ratings** — attach CVSS v3.1 base scores to findings for
      risk-prioritised remediation ordering

---

### 🚀 Strategic (v2.0) — Distributed Agent Architecture

The tool is being evolved into a **distributed agent platform** capable of managing
security assessments across an entire enterprise fleet from a central controller.

#### Agent Mode
Each target machine runs a lightweight **CIS Scanner Agent** — a persistent background
service that:
- Registers itself with a central controller on startup
- Executes scans on demand or on schedule
- Streams results back to the controller in real time
- Operates fully offline if the controller is unreachable, queuing results for upload

#### Webhook-based Remote Control
Agents are controlled via **webhooks** — HTTP callbacks that the central controller
sends to trigger actions on individual agents or groups:

```
Controller  ──── POST /agent/{id}/scan ────►  Agent (Windows endpoint)
            ◄─── POST /controller/results ──  Agent (streams findings back)

Trigger payload example:
{
  "action": "scan",
  "system_type": "windows_endpoint",
  "depth": "deep",
  "callback_url": "https://controller.internal/results",
  "auth_token": "..."
}
```

Planned capabilities:
- **Broadcast scans** — trigger a scan across all registered agents simultaneously
- **Group targeting** — scope scans to tagged agent groups (e.g., `env:production`, `os:linux`)
- **Live progress streaming** — per-check results pushed to the controller as they complete,
  not just at scan completion
- **Signed payloads** — HMAC-signed webhook bodies to authenticate controller instructions
- **Agent self-update** — controller pushes new checklist versions to agents automatically

#### Central Dashboard
A web-based dashboard aggregating results from all agents:
- Fleet-wide compliance score and trend over time
- Per-machine drill-down with finding history
- Alerting on new Non-Compliant findings or regressions
- Export to Excel, PDF, or JSON for audit evidence packages

---

### 🌐 Strategic (v2.0) — Internal Network Scanner

A Nessus-style **active network scanning** capability for internal infrastructure,
integrated directly into the existing reporting pipeline.

#### What it will scan
| Target | Checks |
|--------|--------|
| **Open ports & services** | TCP/UDP port enumeration across CIDR ranges |
| **Service fingerprinting** | Banner grabbing, version detection (HTTP, SSH, FTP, SMB, RDP, etc.) |
| **TLS/SSL posture** | Certificate expiry, weak cipher suites, protocol version (SSLv3, TLS 1.0/1.1) |
| **SMB / NetBIOS** | Null sessions, SMBv1 enabled, anonymous share enumeration |
| **Default credentials** | Common username/password pairs against discovered services |
| **Known CVEs** | Match discovered service versions against a local CVE database |
| **SNMP community strings** | Default `public`/`private` community string detection |
| **Web application basics** | Missing security headers, directory listing, default pages |

#### How it integrates
Network scan findings are merged into the same Excel report format as CIS compliance
findings — a fourth sheet **"Network Findings"** with consistent severity, evidence,
and remediation columns. This gives a single unified report covering both host
configuration compliance and network exposure.

```bash
# Future CLI — network scan a /24 subnet
python main.py --network-scan 192.168.1.0/24 --output network_report.xlsx

# Combined host compliance + network scan
python main.py --system windows_endpoint --depth deep \
               --network-scan 192.168.1.0/24 \
               --output full_assessment.xlsx
```

#### Architecture
- **Scanner core** built on raw sockets + optional `nmap` subprocess integration
- **Plugin system** — each check type (port scan, TLS check, CVE match) is a standalone
  plugin following the same `BaseChecker` pattern as host compliance checks
- **Rate limiting & stealth controls** — configurable scan rate, randomised port ordering,
  and TCP half-open (SYN) scan support to avoid triggering IDS alerts during authorised assessments
- **Credential vaulting** — encrypted local store for credentials used in authenticated scans,
  never written to disk in plaintext

> ⚠️ **Legal notice:** Network scanning should only be performed against infrastructure
> you own or have explicit written authorisation to test. Unauthorised network scanning
> is illegal in most jurisdictions.

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-check`
3. Add your checklist controls or checker class following the patterns above
4. Verify your control runs cleanly: `python main.py --system windows_endpoint --depth essential`
5. Submit a pull request with a description of what the control checks and its CIS reference

---

*Built for security engineers who need reliable, auditable, repeatable CIS compliance assessments.*
