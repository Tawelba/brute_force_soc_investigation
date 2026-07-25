# Incident Report: Brute Force Login Attempt

## 1. Summary

On 17-07-2026 at 14:02, host `target` recorded five SSH login attempts against the `analyst` account from 172.22.85.65 within 8 seconds. Four failed; the fifth succeeded. The account is considered compromised. Recommend immediate password reset and a block on the source IP.

## 2. Affected assets

- **Host:** `target` (Ubuntu lab VM)
- **Account:** `analyst`
- **Service:** SSH (`sshd`) on port 22

## 3. Indicators of compromise

- **Source IP:** 172.22.85.65
- **Targeted user:** `analyst`
- **Log source:** `/var/log/auth.log`

## 4. Timeline

| Time | Event |
|---|---|
| 14:02:00 | First failed SSH login for `analyst` from 172.22.85.65 |
| 14:02:03 | Second failed SSH login from same source |
| 14:02:05 | Third failed SSH login from same source |
| 14:02:07 | Fourth failed SSH login from same source |
| 14:02:08 | Successful SSH login for `analyst` from same source |

The transition from repeated failures to a successful login from the same IP is the key indicator that the brute-force attempt succeeded.

## 5. Analysis

The raw log sequence shows a classic brute-force pattern:

```text
Failed password for analyst from 172.22.85.65 port 49172 ssh2
Failed password for analyst from 172.22.85.65 port 49172 ssh2
Failed password for analyst from 172.22.85.65 port 49172 ssh2
Failed password for analyst from 172.22.85.65 port 49172 ssh2
Accepted password for analyst from 172.22.85.65 port 49172 ssh2
```

Four failed attempts in rapid succession followed by an accepted password means the attacker guessed the password. At that point the account is no longer trusted; any subsequent activity from that session must be treated as potentially malicious until reviewed.

The investigation was performed manually on `/var/log/auth.log`. In a production environment, a SIEM would raise an alert on the failed-login burst, and the analyst would then correlate it with the accepted-login event to confirm or rule out compromise.

## 6. MITRE ATT&CK mapping

| ID | Technique | Where it appears |
|---|---|---|
| T1110 | Brute Force | The repeated failed SSH password attempts from one source |
| T1078 | Valid Accounts | The successful login means the attacker now uses a legitimate account |

## 7. Impact

With interactive access to the `analyst` account, an attacker could:

- Read files the account can access
- Move laterally to other systems if credentials or SSH keys are reused
- Install persistence mechanisms such as cron jobs or authorised keys
- Escalate privileges if the account has sudo rights or if the system has unpatched vulnerabilities
- Exfiltrate data or deploy malware

Because the account was intentionally created with a weak password for the lab, the impact in this controlled environment is limited. In production, the same pattern could lead to significant breach impact.

## 8. Remediation

1. **Force a password reset** on the `analyst` account and review its activity since the successful login.
2. **Block the source IP** 172.22.85.65 at the firewall or network edge.
3. **Disable SSH password authentication** and require SSH key-based authentication instead.
4. **Install and configure fail2ban** to auto-block source IPs after repeated failed SSH attempts.
5. **Create a SIEM alert** for multiple `Failed password` events from the same source IP within 60 seconds.
6. **Review session logs** (`/var/log/wtmp`, `~/.bash_history`, `~/.ssh/authorized_keys`) for post-compromise activity.
7. **Apply least privilege**: ensure the `analyst` account has only the permissions required for its role.

## 9. Lessons learned

- The value of the investigation is not running the attack tool; it is being able to say whether the attacker actually got in and what to do next.
- Failed logins alone are suspicious but not confirmation of compromise. The accepted login from the same source is the critical event.
- Manual log analysis is a good learning exercise, but a production SOC needs automated alerting and correlation to respond within minutes rather than hours.
- Strong password policy and key-based authentication would have prevented this compromise.
- Detection rules should cover both the brute-force burst and the successful-login event for the same account or source.

## 10. Detection rule

A Sigma rule describing the failed-login pattern is included in this repo at `detection/sigma.yml`:

```yaml
title: Multiple Failed SSH Logins From One Source
logsource:
  product: linux
  service: sshd
detection:
  failed:
    message|contains: 'Failed password'
  timeframe: 60s
  condition: failed | count() > 5 by src_ip
level: high
tags:
  - attack.credential_access
  - attack.t1110
```

This rule would raise a high-severity alert in a SIEM when more than five failed SSH logins occur from the same source IP within 60 seconds.
