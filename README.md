# Brute Force Login Detection - SOC Investigation
A home-lab SOC investigation: detected and investigated an SSH
brute force attack that compromised an account, using the
system's own authentication logs. Mapped to MITRE ATT&CK and
wrote an incident report with remediation.

## What I did
- Built an isolated lab (Ubuntu target + attacker via Multipass)
- Simulated a brute force attack with hydra
- Investigated /var/log/auth.log: found the failure burst and
 the successful login from the same IP = account compromised
- Mapped to MITRE ATT&CK (T1110, T1078)
- Wrote a SOC-style incident report with remediation

## Evidence
![failures](screenshots/failed-logins.png)
![breach](screenshots/accepted-login.png)
## Full write-up
See [incident-report.md](incident-report.md)