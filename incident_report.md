# Incident Report: Simulated SSH Brute-Force Investigation

**Environment:** authorized training lab. **Investigation:** manual log correlation. **Review date:** 11 October 2026. The original recorded timeline is retained; this review does not independently reverify the original VM logs.

## 1. Summary

On 17-07-2026 at 14:02, host `target` recorded five SSH login attempts against the `analyst` account from 172.22.85.65 within 8 seconds. Four failed; the fifth succeeded. In the known authorized attack simulation, the account was treated as compromised. Password reset, session review and narrowly scoped source blocking were recommended; completion of those actions is not evidenced here.

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

The transition warrants investigation. In this controlled exercise, known attack context supports the simulated compromise conclusion; the log pattern alone would not establish malicious compromise in production.

## 5. Analysis

The existing report includes this shortened message excerpt. It omits timestamps and is not a fresh export of the original log:

```text
Failed password for analyst from 172.22.85.65 port 49172 ssh2
Failed password for analyst from 172.22.85.65 port 49172 ssh2
Failed password for analyst from 172.22.85.65 port 49172 ssh2
Failed password for analyst from 172.22.85.65 port 49172 ssh2
Accepted password for analyst from 172.22.85.65 port 49172 ssh2
```

Four failures followed by success establish failed and successful authentication, not the intent of the person logging in. The known simulation provides additional context. In production, validate the login with the account owner and examine session activity before concluding that password guessing succeeded.

The investigation was performed manually on `/var/log/auth.log`. A SIEM could alert on the burst only after suitable telemetry parsing, field mappings and a tested rule are deployed. The analyst would then review the successful login and subsequent activity. This project does not claim a live SIEM alert.

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

## 8. Recommended remediation (not recorded as executed)

1. **Force a password reset** on the `analyst` account and review its activity since the successful login.
2. **Block the source IP** 172.22.85.65 at the firewall or network edge.
3. **Disable SSH password authentication** and require SSH key-based authentication instead.
4. **Install and configure fail2ban** to auto-block source IPs after repeated failed SSH attempts.
5. **Create a SIEM alert** for multiple `Failed password` events from the same source IP within 60 seconds.
6. **Review session logs** (`/var/log/wtmp`, `~/.bash_history`, `~/.ssh/authorized_keys`) for post-compromise activity.
7. **Apply least privilege**: ensure the `analyst` account has only the permissions required for its role.

## 9. Lessons learned

- The value of the investigation is not running the attack tool; it is being able to say whether the attacker actually got in and what to do next.
- Failed logins alone are suspicious but not confirmation of compromise. The accepted login from the same source is a critical investigation pivot; authorization and post-login behavior still matter.
- Manual log analysis is a good learning exercise, but a production SOC needs automated alerting and correlation to respond within minutes rather than hours.
- A stronger password would reduce guessing risk; disabling SSH password authentication and requiring correctly managed keys would remove this password-guessing route. Neither replaces monitoring or prevents every form of account compromise.
- Detection rules should cover both the brute-force burst and the successful-login event for the same account or source.

## 10. Corrected detection design

See [sigma.yml](sigma.yml) for the canonical base event rule and event-count correlation. The lab threshold is **at least four failed passwords within 60 seconds**, grouped by `host`, `src_ip` and `username`. The earlier `> 5` example would not match the report's four failures; the earlier uploaded `> 4` / `3s` rule also would not match that sequence.

The ingestion pipeline must extract those fields from SSH logs. The rule detects failures only; successful authentication remains an investigation pivot rather than an automatic compromise verdict.

See [validation.md](validation.md) for the exact scope of the local parser and synthetic logic checks. No deployed SIEM conversion, live alert or executed containment is claimed by those checks.

## 11. Evidence limitations and follow-up

- Original screenshots and the previously recorded timeline are retained. Complete original logs, timezone and session-level identifiers were not reverified during this documentation correction.
- Potential impact is listed separately from observed behavior; lateral movement, persistence and exfiltration were not demonstrated.
- Validate post-login activity using reliable host telemetry and session records. Shell history alone can be incomplete or altered.
- Reproduce rule conversion and telemetry ingestion in the chosen SIEM; test below-threshold activity, separate accounts/hosts/sources, legitimate activity and a positive burst.
- Record containment, credential remediation and monitoring recovery only when performed and verified.
