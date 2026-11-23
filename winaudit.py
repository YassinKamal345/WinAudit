#!/usr/bin/env python3
"""
WinAudit - a read-only Windows security baseline checker.

Runs a set of checks against the local machine (firewall, Microsoft Defender,
Windows Update, UAC, RDP, SMBv1, listening ports, local accounts, BitLocker...)
and prints a report with a security score and concrete recommendations.

WinAudit never changes anything: every check only reads state. Some checks need an
elevated (Administrator) prompt to read their data and are reported as SKIPPED
otherwise.

  python winaudit.py            # full report
  python winaudit.py --json     # machine-readable output

Author: Yassin Kamal - https://github.com/YassinKamal345
License: MIT
"""

from __future__ import annotations

import argparse
import ctypes
import json
import platform
import subprocess
import sys
from dataclasses import dataclass, field

# Status levels, ordered from best to worst for scoring.
OK, INFO, WARN, FAIL, SKIP = "OK", "INFO", "WARN", "FAIL", "SKIP"

# ANSI colours; disabled automatically when output is not a terminal.
COLORS = {OK: "\033[92m", INFO: "\033[96m", WARN: "\033[93m", FAIL: "\033[91m", SKIP: "\033[90m"}
RESET = "\033[0m"


@dataclass
class Result:
    name: str
    status: str
    detail: str = ""
    recommendation: str = ""


@dataclass
class Report:
    results: list[Result] = field(default_factory=list)

    def add(self, name, status, detail="", recommendation=""):
        self.results.append(Result(name, status, detail, recommendation))

    def score(self) -> tuple[int, int]:
        """Return (points, maximum) counting only checks that could run."""
        graded = [r for r in self.results if r.status in (OK, WARN, FAIL)]
        points = sum(1 for r in graded if r.status == OK)
        points += sum(0.5 for r in graded if r.status == WARN)
        return round(points), len(graded)


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def run_ps(script: str, timeout: float = 20.0) -> str:
    """Run a PowerShell snippet and return stdout (empty string on failure)."""
    try:
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=timeout,
        )
        return completed.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def run_cmd(args: list[str], timeout: float = 20.0) -> str:
    try:
        completed = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return completed.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


# --------------------------------------------------------------------------- #
# Individual checks. Each takes the Report and an is_admin flag.               #
# --------------------------------------------------------------------------- #

def check_firewall(report: Report, admin: bool) -> None:
    out = run_ps(
        "Get-NetFirewallProfile | Select-Object Name,Enabled | "
        "ForEach-Object { \"$($_.Name)=$($_.Enabled)\" }"
    )
    if not out:
        report.add("Windows Firewall", SKIP, "Could not query firewall profiles.")
        return
    states = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    disabled = [name for name, enabled in states.items() if enabled.strip().lower() != "true"]
    if disabled:
        report.add("Windows Firewall", FAIL,
                   f"Disabled for profile(s): {', '.join(disabled)}.",
                   "Enable the firewall for every profile (Domain, Private, Public).")
    else:
        report.add("Windows Firewall", OK, "Enabled for all profiles.")


def check_defender(report: Report, admin: bool) -> None:
    out = run_ps(
        "$s = Get-MpComputerStatus; "
        "\"$($s.AntivirusEnabled)|$($s.RealTimeProtectionEnabled)|$($s.AntivirusSignatureAge)\""
    )
    if not out or "|" not in out:
        report.add("Microsoft Defender", SKIP,
                   "Get-MpComputerStatus unavailable (another AV may be installed).")
        return
    av, rtp, age = (out.split("|") + ["", "", ""])[:3]
    if av.strip().lower() != "true":
        report.add("Microsoft Defender", FAIL, "Antivirus is disabled.",
                   "Enable Microsoft Defender or confirm another antivirus is active.")
    elif rtp.strip().lower() != "true":
        report.add("Microsoft Defender", WARN, "Real-time protection is off.",
                   "Turn real-time protection back on.")
    else:
        detail = "Antivirus and real-time protection on."
        try:
            if int(age) > 7:
                report.add("Microsoft Defender", WARN,
                           f"{detail} Signatures are {age} days old.",
                           "Update Defender signatures.")
                return
        except ValueError:
            pass
        report.add("Microsoft Defender", OK, detail)


def check_uac(report: Report, admin: bool) -> None:
    out = run_ps(
        "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\"
        "Policies\\System').EnableLUA"
    )
    if out == "":
        report.add("User Account Control (UAC)", SKIP, "Could not read UAC policy.")
    elif out.strip() == "1":
        report.add("User Account Control (UAC)", OK, "UAC is enabled.")
    else:
        report.add("User Account Control (UAC)", FAIL, "UAC is disabled.",
                   "Re-enable UAC (EnableLUA = 1) to require consent for admin actions.")


def check_rdp(report: Report, admin: bool) -> None:
    out = run_ps(
        "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server')"
        ".fDenyTSConnections"
    )
    if out == "":
        report.add("Remote Desktop (RDP)", SKIP, "Could not read RDP setting.")
    elif out.strip() == "1":
        report.add("Remote Desktop (RDP)", OK, "RDP is disabled.")
    else:
        report.add("Remote Desktop (RDP)", WARN, "RDP is enabled.",
                   "Disable RDP if you don't use it; if you do, restrict it and require NLA.")


def check_smb1(report: Report, admin: bool) -> None:
    out = run_ps(
        "(Get-SmbServerConfiguration -ErrorAction SilentlyContinue).EnableSMB1Protocol"
    )
    if out == "":
        report.add("SMBv1 protocol", SKIP, "Could not query SMB configuration (needs admin).")
    elif out.strip().lower() == "true":
        report.add("SMBv1 protocol", FAIL, "The legacy SMBv1 protocol is enabled.",
                   "Disable SMBv1; it is obsolete and exploited by malware like WannaCry.")
    else:
        report.add("SMBv1 protocol", OK, "SMBv1 is disabled.")


def check_updates(report: Report, admin: bool) -> None:
    # Format the date in PowerShell to an invariant ISO form so parsing is reliable
    # regardless of the machine's locale.
    out = run_ps(
        "$h = Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | "
        "Select-Object -First 1; if ($h) { $h.InstalledOn.ToString('yyyy-MM-dd') }"
    )
    if not out:
        report.add("Windows Update", SKIP, "Could not read the update history.")
        return
    from datetime import datetime
    try:
        last = datetime.strptime(out.split("\n")[0].strip(), "%Y-%m-%d")
    except ValueError:
        report.add("Windows Update", INFO, f"Last hotfix date: {out}")
        return
    days = (datetime.now() - last).days
    if days > 45:
        report.add("Windows Update", WARN, f"Last update was {days} days ago.",
                   "Check Windows Update; patches may be pending.")
    else:
        report.add("Windows Update", OK, f"Last update {days} days ago.")


def check_guest(report: Report, admin: bool) -> None:
    out = run_ps(
        "$g = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue; "
        "if ($g) { $g.Enabled } else { 'none' }"
    )
    if out == "" :
        report.add("Guest account", SKIP, "Could not query local users.")
    elif out.strip().lower() == "none":
        report.add("Guest account", OK, "No Guest account present.")
    elif out.strip().lower() == "false":
        report.add("Guest account", OK, "Guest account is disabled.")
    else:
        report.add("Guest account", FAIL, "The Guest account is enabled.",
                   "Disable the Guest account.")


def check_admin_accounts(report: Report, admin: bool) -> None:
    if not admin:
        report.add("Administrator accounts", SKIP,
                   "Run as Administrator to enumerate the Administrators group.")
        return
    out = run_ps(
        "(Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | "
        "Measure-Object).Count"
    )
    if not out.strip().isdigit() or out.strip() == "0":
        report.add("Administrator accounts", SKIP, "Could not enumerate administrators.")
        return
    count = int(out.strip())
    if count > 2:
        report.add("Administrator accounts", WARN, f"{count} accounts are local administrators.",
                   "Keep the number of admin accounts to a minimum.")
    else:
        report.add("Administrator accounts", OK, f"{count} local administrator account(s).")


def check_bitlocker(report: Report, admin: bool) -> None:
    if not admin:
        report.add("BitLocker (system drive)", SKIP, "Run as Administrator to read BitLocker state.")
        return
    out = run_ps(
        "(Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue)"
        ".ProtectionStatus"
    )
    if out == "":
        report.add("BitLocker (system drive)", SKIP, "BitLocker not available on this edition.")
    elif out.strip() in ("On", "1"):
        report.add("BitLocker (system drive)", OK, "System drive is encrypted.")
    else:
        report.add("BitLocker (system drive)", WARN, "System drive is not encrypted.",
                   "Enable BitLocker (or another full-disk encryption) on the system drive.")


def check_listening_ports(report: Report, admin: bool) -> None:
    out = run_ps(
        "Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | "
        "Where-Object { $_.LocalAddress -notin '127.0.0.1','::1' } | "
        "Select-Object -ExpandProperty LocalPort | Sort-Object -Unique"
    )
    if not out:
        report.add("Externally-listening ports", OK,
                   "No TCP ports listening on non-loopback addresses.")
        return
    ports = sorted({int(p) for p in out.split() if p.strip().isdigit()})
    report.add("Externally-listening ports", INFO,
               f"{len(ports)} port(s) listening on all/non-loopback addresses: "
               f"{', '.join(map(str, ports[:20]))}" + (" ..." if len(ports) > 20 else ""),
               "Review these; close any service you do not need exposed.")


CHECKS = [
    check_firewall, check_defender, check_uac, check_rdp, check_smb1,
    check_updates, check_guest, check_admin_accounts, check_bitlocker,
    check_listening_ports,
]


def build_report() -> Report:
    report = Report()
    admin = is_admin()
    for check in CHECKS:
        try:
            check(report, admin)
        except Exception as exc:  # a broken check must never crash the whole audit
            report.add(check.__name__, SKIP, f"check error: {exc}")
    return report


def print_report(report: Report, use_color: bool) -> None:
    def tag(status: str) -> str:
        label = f"[{status}]".ljust(7)
        if use_color:
            return f"{COLORS.get(status, '')}{label}{RESET}"
        return label

    print("=" * 70)
    print(f" WinAudit - security baseline for {platform.node()} ({platform.system()} "
          f"{platform.release()})")
    if not is_admin():
        print(" Note: not elevated - some checks are skipped. Re-run as Administrator for all.")
    print("=" * 70)

    for result in report.results:
        print(f"{tag(result.status)} {result.name}")
        if result.detail:
            print(f"        {result.detail}")
        if result.recommendation and result.status in (WARN, FAIL):
            print(f"        -> {result.recommendation}")

    points, maximum = report.score()
    skipped = sum(1 for r in report.results if r.status == SKIP)
    print("=" * 70)
    if maximum:
        pct = round(100 * points / maximum)
        print(f" Score: {points}/{maximum} ({pct}%) across graded checks"
              + (f", {skipped} skipped" if skipped else ""))
    else:
        print(" No checks could be graded (try running as Administrator).")
    print("=" * 70)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only Windows security baseline checker.")
    parser.add_argument("--json", action="store_true", help="Output JSON instead of a report.")
    parser.add_argument("--no-color", action="store_true", help="Disable coloured output.")
    args = parser.parse_args(argv)

    if platform.system() != "Windows":
        print("WinAudit only runs on Windows.", file=sys.stderr)
        return 2

    report = build_report()

    if args.json:
        points, maximum = report.score()
        print(json.dumps({
            "host": platform.node(),
            "elevated": is_admin(),
            "score": {"points": points, "max": maximum},
            "checks": [vars(r) for r in report.results],
        }, indent=2))
        return 0

    print_report(report, use_color=sys.stdout.isatty() and not args.no_color)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
