"""Read-only Windows security audit: firewall, Defender, UAC, and drive encryption."""
import json
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path

PS = r"""
$ErrorActionPreference = 'Stop'
$r = [ordered]@{}
try {
 $r.firewall = @{ status='ok'; profiles=@(Get-NetFirewallProfile | Select-Object Name, Enabled) }
} catch { $r.firewall = @{ status='unknown' } }
try {
 $d = Get-MpComputerStatus
 $r.defender = @{status='ok'; realtime=$d.RealTimeProtectionEnabled; antivirus=$d.AntivirusEnabled; signature_age_days=$d.AntivirusSignatureAge}
} catch { $r.defender = @{status='unknown'; note='Defender may be inactive when a third-party antivirus is installed'} }
try {
 $u = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA
 $r.uac = @{status='ok'; enabled=($u.EnableLUA -eq 1)}
} catch { $r.uac = @{status='unknown'} }
try {
 $b = Get-BitLockerVolume -MountPoint $env:SystemDrive
 $r.encryption = @{status='ok'; protection=([string]$b.ProtectionStatus); volume_status=([string]$b.VolumeStatus); encrypted_percent=$b.EncryptionPercentage}
} catch { $r.encryption = @{status='unknown'} }
try {
 $products = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Select-Object -ExpandProperty displayName)
 $r.antivirus_products = @{status='ok'; names=$products}
} catch { $r.antivirus_products = @{status='unknown'} }
$r | ConvertTo-Json -Depth 6 -Compress
"""

def main():
    if platform.system() != "Windows":
        raise SystemExit("This audit runs on Windows only.")
    try:
        p = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", PS],
            capture_output=True, text=True, timeout=45, check=False,
        )
        if p.returncode:
            raise ValueError("PowerShell checks failed")
        results = json.loads(p.stdout)
    except (ValueError, json.JSONDecodeError, subprocess.TimeoutExpired) as err:
        raise SystemExit(f"Audit could not complete: {err}")
    print("WINDOWS SECURITY AUDIT (read-only)")
    print("=" * 40)
    firewall = results.get("firewall", {})
    if firewall.get("status") == "ok":
        profiles = firewall.get("profiles", [])
        if isinstance(profiles, dict):
            profiles = [profiles]
        for profile in profiles:
            print(f"Firewall {profile['Name']}: {'ON' if profile['Enabled'] else 'OFF'}")
    else:
        print("Firewall: UNKNOWN")
    defender = results.get("defender", {})
    if defender.get("status") == "ok":
        print("Defender real-time protection:", "ON" if defender.get("realtime") else "OFF / INACTIVE")
    else:
        print("Defender: UNKNOWN (check third-party antivirus)")
    uac = results.get("uac", {})
    print("User Account Control:", ("ON" if uac.get("enabled") else "OFF") if uac.get("status") == "ok" else "UNKNOWN")
    encryption = results.get("encryption", {})
    if encryption.get("status") == "ok":
        print("System drive encryption:", encryption.get("volume_status", "UNKNOWN"), "-", encryption.get("encrypted_percent", "?"), "%")
        print("BitLocker key protection:", encryption.get("protection", "UNKNOWN"))
        if str(encryption.get("protection", "")).lower() == "off":
            print("REVIEW: Encryption is present but protection is OFF. Verify recovery key before making changes.")
    else:
        print("System drive encryption: UNKNOWN")
    products = results.get("antivirus_products", {})
    if products.get("status") == "ok":
        names = products.get("names", [])
        if isinstance(names, str):
            names = [names]
        print("Registered antivirus products:", ", ".join(names) if names else "None reported")
        if len(names) > 1:
            print("REVIEW: Multiple antivirus products are registered; check their active roles.")
    else:
        print("Registered antivirus products: UNKNOWN")
    print("UNKNOWN does not mean the system is insecure.")
    report = {"timestamp_utc": datetime.now(timezone.utc).isoformat(), "checks": results}
    Path("security-audit-report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print("Local report saved as security-audit-report.json")
    print("Do not publish your personal audit report.")

if __name__ == "__main__":
    main()
