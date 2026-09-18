# RedTeamCTFs

Written walkthroughs of two Active Directory attack-path exercises, captured from hosted red team CTF ranges. They are technique references for anyone studying AD lateral movement and privilege escalation, not turnkey scripts: every command is tied to specific hostnames, IP ranges and credentials from a lab environment that no longer exists.

## Contents

- `DC719-CTF.md`: a nine-flag chain across three Active Directory domains. It goes from a Jenkins credential passback attack, through password spraying and LAPS abuse, ASREPRoasting, abuse of a linked MSSQL server via `xp_cmdshell`, DPAPI credential extraction from a scheduled task, a vulnerable AD CS certificate template, outbound domain trust abuse with Kerberoasting, and finishes with constrained delegation and resource-based constrained delegation (RBCD) against a file server and domain controller.
- `Graylog CTF Walkthrough.md`: a three-flag chain starting from a web application reverse shell (built on a public `flask-image-bgremover` demo payload), through SMB share credential harvesting, to MSSQL impersonation and `xp_cmdshell` on a domain controller.

Both files record command sequences, expected output, and the resulting flag for each stage, in the order the exercise was solved.

## Requirements

Reproducing these techniques against your own lab requires the standard AD attack tooling referenced in the text: `nmap`, `crackmapexec`, `evil-winrm`, a Cobalt Strike (or equivalent C2) beacon, PowerView, Rubeus, Mimikatz, Certify, ADSearch, StandIn, and `impacket`. None of that tooling is bundled here; the files are notes, not a lab or a toolkit.

## How to read these files

`DC719-CTF.md` opens with setup instructions for viewing it in Obsidian (outline navigation, one-click command copying). That is a leftover from how the notes were originally taken, not a requirement: any Markdown viewer works, you just lose the clickable outline.

## Limitations

- Every IP, hostname, domain, and credential in these files belonged to a temporary CTF range and is not reachable or valid outside it. They are included for technique reference, not as working examples to run as-is.
- Commands invoke tooling from `/opt/tools`; adjust those paths to wherever the tooling lives in your environment.
- These are solve-order narratives, not general-purpose runbooks: some steps (for example, AV bypass staging in Flag 5/6 of `DC719-CTF.md`) assume tooling and payload choices specific to that engagement and will need adaptation elsewhere.

---
https://www.assumed-breach.com
