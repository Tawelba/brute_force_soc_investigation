# Incident Report: Brute Force Login Attempt
## 1. Summary
On 17-07-2026 at 14:02, host 'target' recorded five SSH login
attempts against the 'analyst' account from 172.22.85.65
within 3 seconds. Four failed; the fifth succeeded. The
account is considered compromised. Recommend immediate
password reset and a block on the source IP.

## 2. Affected assets
- Host: [target]
- Account: [analyst]

## 3. Indicators of compromise
- Source IP: 172.22.85.65
- Targeted user: [analyst]

## 4. Timeline
- [15:18] First failed login from 172.22.85.65
- [15:20] Further failed attempts 4 (total)
- [15:21] Successful login from same IP <-- compromise

## 5. Analysis
[What the pattern tells you and how you concluded compromise]

## 6. MITRE ATT&CK mapping
- T1110 Brute Force
- T1078 Valid Accounts
## 7. Impact
[What the attacker could do with this account]

## 8. Remediation
1. Force a password reset on 'analyst' and review its activity.
2. Disable SSH password login; require SSH keys instead.
3. Install fail2ban to auto-block IPs after repeated failures.
4. Alert on repeated 'Failed password' events in real time.
## 9. Lessons learned
[What you would detect or change to catch this sooner]