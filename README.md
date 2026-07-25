# Brute Force Login Detection - SOC Investigation

This project solves a real SOC problem: **how do you tell the difference between a routine brute-force scan and a real account compromise, using only the logs the system already writes?**

Every SSH server on the internet receives failed login attempts. The noise is normal. The danger is the moment a failure turns into a success. This project shows how to spot that moment, prove it happened, and respond like a SOC analyst.

A home-lab SOC investigation: detected and investigated an SSH brute force attack that compromised an account, using the system's own authentication logs. Mapped to MITRE ATT&CK and wrote an incident report with remediation.

## What I did

- Built an isolated lab (Ubuntu target + attacker via Multipass)
- Simulated a brute force attack with hydra
- Investigated `/var/log/auth.log`: found the failure burst and the successful login from the same IP = account compromised
- Mapped to MITRE ATT&CK (T1110, T1078)
- Wrote a Sigma detection rule for the failed-login pattern
- Wrote a SOC-style incident report with remediation

## Evidence

![failures](screenshots/failed-logins.png)
![breach](screenshots/accepted-login.png)

## Detection

See [detection/sigma.yml](detection/sigma.yml) for a portable Sigma rule that detects multiple failed SSH logins from one source IP.

## Full write-up

See [incident-report.md](incident-report.md) for the full incident report: summary, affected assets, indicators of compromise, timeline, analysis, MITRE ATT&CK mapping, impact, remediation, and lessons learned.

## Honest framing

This is a home-lab project. The attack was simulated against virtual machines I own and control. The breach is not real; the investigation skills are.
