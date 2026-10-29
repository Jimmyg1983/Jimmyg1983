# Windows Security Audit: Read-only Case Study

**Environment:** Personal Windows workstation (identifying details omitted)  
**Method:** Read-only PowerShell checks conducted through an authorized remote session  
**Date:** October 28, 2026 (session date; timezone may differ)

## Goal
Check a small set of Windows defensive settings and practice interpreting results without changing security configuration.

## Sanitized observations

| Check | Observation | Interpretation |
| --- | --- | --- |
| Domain firewall | Enabled | Domain profile firewall was on at the time checked |
| Private firewall | Enabled | Private profile firewall was on |
| Public firewall | Enabled | Public profile firewall was on |
| Defender real-time protection | Enabled | Defender reported active real-time protection |
| Defender antivirus signature age | 0 days | Signatures were reported as recent |
| User Account Control | Enabled | EnableLUA was set to 1 |
| System drive BitLocker | **Unknown** | Query returned access-denied / unavailable-volume errors; encryption state could not be established |
| Registered antivirus products | 2 | Two registrations were reported; this alone does not show two active engines or a conflict |

## Troubleshooting notes
The BitLocker query produced a permission error and a message that the system drive did not have an associated BitLocker volume. The result was treated as **unknown**, not as proof that encryption is off. A future authorized, elevated check may clarify the configuration, but recovery-key readiness should be verified before making encryption changes.

Two antivirus registrations can occur when security products coexist or leave registrations behind. Do not uninstall or disable anything based only on the count.

## Limits and privacy
This is a snapshot, **not** a vulnerability scan, malware scan, compliance certification, or proof of system security. No configuration changes were made. Device identifiers, antivirus product names, and full system reports are intentionally excluded. No BitLocker recovery keys were accessed.

## Skills demonstrated
- Read-only Windows PowerShell checks
- Firewall profile, UAC, Defender, and BitLocker interpretation
- Differentiating unknown results from negative results
- Privacy-aware security documentation
- Evidence-based troubleshooting
