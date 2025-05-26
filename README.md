# 🧨 RansomDeploymentPackage
This repository contains a collection of red team utilities, scripts, and payloads for adversary emulation and advanced threat simulation.

> ⚠️ **For educational and authorized use only.** Do not use on systems you do not own or have explicit permission to operate on.

## 📂 Tools Included

| Tool | Description | MITRE ATT&CK Technique | References |
|-------------|-------------|-------------|-------------|
| [`loader`](loader/) | A Linux fileless in-memory ELF loader using `memfd_create()`. Downloads a remote payload, runs it from memory, and deletes itself from disk. Simulates a Cobalt Strike stager. | [Reflective Code Loading](https://attack.mitre.org/techniques/T1620/) | [1](https://medium.com/confluera-engineering/reflective-code-loading-in-linux-a-new-defense-evasion-technique-in-mitre-att-ck-v10-da7da34ed301) |
