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

## Automated tests

The project includes mocked Python regression tests for normal and malformed PowerShell responses. Run them from the repository root:

```sh
python -m unittest discover -s projects/windows-security-audit/tests -v
```

These tests do not inspect or change your computer. A passing test run is not evidence that an actual Windows machine is secure.

## Demonstrate the project safely

1. On your own Windows computer, run `python audit.py` from the project folder.
2. Record the terminal output, **after removing device names and other identifying information**.
3. Explain what each result means, including why `UNKNOWN` is not automatically a failure.
4. Keep `security-audit-report.json` private. Do not upload reports, recovery keys, or security configuration details.
5. Note the Windows version and whether antivirus software is managed by a third party, without publishing sensitive settings.

## Next improvements
- Clearer status labels and remediation references
- Support for alternate Windows security products
- Additional Windows-specific integration testing

## Author
James Gamache — BSIT student interested in IT support, network security, and defensive security.

[Portfolio](https://jimmyg1983.github.io/) · [GitHub](https://github.com/Jimmyg1983)
