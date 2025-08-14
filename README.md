# 🧨 RansomDeploymentPackage
This repository contains a collection of red team utilities, scripts, and payloads for adversary emulation and advanced threat simulation.

> ⚠️ **For educational and authorized use only.** Do not use on systems you do not own or have explicit permission to operate on.

## Tools Included

| Tool | Description | MITRE ATT&CK Technique | References |
|-------------|-------------|-------------|-------------|
| [`encryptor`](encryptor/) | Linux-based ransomware deployment package to demonstrate hybrid encryption (AES + RSA) techniques | [Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/) | [1](www.trendmicro.com/en_sg/research/23/h/monti-ransomware-unleashes-a-new-encryptor-for-linux.html) |
| [`exfiltrator`](exfiltrator/) | Linux-based exfiltration agent that scans, filters, and transmits files to a remote collector using IPC and resumable TCP transfers | [Automated Exfiltration](https://attack.mitre.org/techniques/T1020/) | [1](https://www.cybereason.com/blog/research/threat-analysis-report-inside-the-lockbit-arsenal-the-stealbit-exfiltration-tool) |
| [`loader`](loader/) | A Linux fileless in-memory ELF loader. Downloads a remote payload, runs it from memory, and deletes itself from disk. Simulates a Cobalt Strike stager. | [Reflective Code Loading](https://attack.mitre.org/techniques/T1620/) | [1](https://medium.com/confluera-engineering/reflective-code-loading-in-linux-a-new-defense-evasion-technique-in-mitre-att-ck-v10-da7da34ed301) |
| [`wiper`](wiper/) | Bash script designed to wipe trace evidence from Linux systems. | [Indicator Removal on Host](https://attack.mitre.org/techniques/T1620/) | |

