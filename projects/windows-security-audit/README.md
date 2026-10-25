# Windows Security Audit Tool

A beginner-friendly, **read-only** Python tool for inspecting several Windows security settings. Built as a hands-on cybersecurity portfolio project.

## Checks
| Check | What it reports | Important limitation |
| --- | --- | --- |
| Windows Firewall | Whether each firewall profile is enabled | Does not inspect individual firewall rules |
| Microsoft Defender | Real-time protection status, when available | Defender may be inactive when Norton or another antivirus is installed |
| User Account Control (UAC) | Whether UAC is enabled | Does not evaluate the prompt level |
| System drive encryption | Encryption percentage, volume status, and BitLocker protection | A fully encrypted drive can still have BitLocker protection switched off |
| Antivirus products | Names registered in Windows Security Center | Registration does not by itself prove conflicting active scanners |

**Encryption and protection are different.** If the drive is fully encrypted but protection is off, verify that a recovery key is safely backed up before changing protection settings. Do not post recovery keys online.

**Unknown is not a failure.** This tool does not determine whether a computer is safe or detect malware.

## Requirements
- Windows 10 or 11
- Python 3
- Windows PowerShell
- No extra Python packages required

## Run
Download `audit.py`, open PowerShell in the file's directory, and run:

```powershell
python audit.py
```

You can also try `py audit.py` on Windows.

The tool prints a short summary and creates `security-audit-report.json` locally. Some checks may need elevated privileges, but start without administrator privileges. **The script does not change Windows settings.**

## Privacy
The report contains security configuration details about your device. **Do not commit or upload your actual generated report.** The root repository `.gitignore` excludes it.

## What I learned
- Distinguishing encrypted volumes from active BitLocker key protection
- Checking antivirus registration without assuming products conflict
- Running read-only PowerShell commands from Python
- Understanding firewall profiles, Defender status, UAC, and drive encryption
- Handling missing permissions and unavailable checks safely
- Saving structured JSON results and writing reproducible documentation

## Next improvements
- Mocked tests to validate output without running on a Windows host
- Clearer status labels and actionable remediation references
- Support for alternate Windows security products

## Author
James Gamache — BSIT student interested in IT support, network security, and defensive security.

[Portfolio](https://jimmyg1983.github.io/) · [GitHub](https://github.com/Jimmyg1983)
