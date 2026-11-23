# 🛡️ WinAudit

A read-only **Windows security baseline checker** in a single Python file. It audits the
local machine against a set of common hardening checks and prints a report with a security
score and concrete recommendations.

**WinAudit never changes anything** — every check only *reads* state. No dependencies beyond
the Python standard library.

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=flat-square&logo=windows&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

## Checks

| Check | What it looks for |
|-------|-------------------|
| Windows Firewall | Enabled for all profiles (Domain/Private/Public) |
| Microsoft Defender | Antivirus + real-time protection on, signatures fresh |
| User Account Control | UAC enabled (`EnableLUA`) |
| Remote Desktop (RDP) | Disabled unless needed |
| SMBv1 | Legacy protocol disabled (WannaCry vector) |
| Windows Update | How long since the last patch |
| Guest account | Disabled or absent |
| Administrator accounts | How many local admins exist *(needs admin)* |
| BitLocker | System drive encrypted *(needs admin)* |
| Listening ports | TCP ports exposed on non-loopback addresses |

Checks that need elevation are reported as **SKIPPED** when you run without it, so a normal
run is always safe and never fails loudly.

## Usage

```bash
python winaudit.py            # full report
python winaudit.py --json     # machine-readable output (for pipelines)
python winaudit.py --no-color # plain text, no ANSI colours
```

Run it from an **Administrator** terminal to include the BitLocker and admin-group checks.

## Example

```
======================================================================
 WinAudit - security baseline for DESKTOP-XXXX (Windows 11)
======================================================================
[OK]    Windows Firewall
        Enabled for all profiles.
[OK]    Microsoft Defender
        Antivirus and real-time protection on.
[OK]    SMBv1 protocol
        SMBv1 is disabled.
[WARN]  Remote Desktop (RDP)
        RDP is enabled.
        -> Disable RDP if you don't use it; if you do, restrict it and require NLA.
...
 Score: 7/8 (88%) across graded checks, 2 skipped
======================================================================
```

## How it works

WinAudit shells out to built-in Windows tooling (PowerShell cmdlets like
`Get-NetFirewallProfile`, `Get-MpComputerStatus`, `Get-SmbServerConfiguration`, and a few
registry reads) and interprets the results. Each check is isolated, so a single failing
check can never crash the whole audit.

## Disclaimer

WinAudit is a quick baseline check for your own machine, not a replacement for a full
security assessment or a compliance tool. Scores are indicative.

## License

MIT - see [LICENSE](LICENSE). Author: **Yassin Kamal** ·
[Portfolio](https://portfolio-sand-eight-20.vercel.app) ·
[LinkedIn](https://www.linkedin.com/in/yassin-kamal-simo/)
