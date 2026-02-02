# Chrysalis Backdoor Detection Rules

**Detection rules for Microsoft Sentinel / Microsoft Defender for Endpoint to hunt and detect the Chrysalis backdoor attributed to the Lotus Blossom (Billbug) APT group.**

---

## Overview

This repository contains KQL (Kusto Query Language) detection rules and IOCs based on the technical analysis published by [Rapid7 Labs](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/) in February 2025.

**Lotus Blossom** (also known as Billbug, Spring Dragon) is a Chinese APT group active since 2009, primarily targeting government, telecommunications, aviation, and critical infrastructure sectors in Southeast Asia and Central America.

### Key Findings

- **Initial Access**: Compromised Notepad++ distribution infrastructure (supply chain attack)
- **Custom Backdoor**: "Chrysalis" - a sophisticated, multi-layered backdoor with RC4 encryption
- **Loaders**: Metasploit block_api shellcode + Cobalt Strike beacons
- **Evasion**: Microsoft Warbird abuse for shellcode execution
- **Persistence**: Windows Services + Registry Run Keys

---

## Threat Summary

| Attribute | Value |
|-----------|-------|
| **Threat Actor** | Lotus Blossom / Billbug / Spring Dragon |
| **Origin** | China |
| **Malware Family** | Chrysalis Backdoor |
| **First Seen** | 2024-2025 |
| **Target Sectors** | Government, Telecom, Aviation, Critical Infrastructure |
| **Target Regions** | Southeast Asia, Central America |

---

## Repository Structure

```
├── detection/
│   └── chrysalis_detection.kql        # All KQL detection rules
├── iocs/
│   └── chrysalis_iocs.csv             # IOCs in CSV format (Sentinel import ready)
└── README.md
```

---

## 🔍 Detection Coverage

### By Data Source

| Data Source | Rules |
|-------------|-------|
| DeviceFileEvents | Hash matching, suspicious paths |
| DeviceNetworkEvents | C2 communications, URL patterns |
| DeviceProcessEvents | Command-line arguments, process chains |
| DeviceRegistryEvents | Persistence mechanisms |
| DeviceImageLoadEvents | DLL sideloading detection |
| DeviceEvents | Mutex creation, service installation |
| CommonSecurityLog | Firewall/Proxy C2 detection |
| DnsEvents | Malicious domain lookups |

---

## Indicators of Compromise

### Network Indicators

| Type | Indicator | Description |
|------|-----------|-------------|
| IP | `95.179.213.0` | Initial payload server |
| IP | `61.4.102.97` | Primary C2 (Malaysia) |
| IP | `59.110.7.32` | Cobalt Strike C2 |
| IP | `124.222.137.114` | Cobalt Strike C2 |
| Domain | `api.skycloudcenter.com` | Chrysalis C2 |
| Domain | `api.wiresguard.com` | Cobalt Strike C2 |

### File Indicators (SHA-256)

<details>
<summary>Click to expand full hash list</summary>

| Filename | SHA-256 |
|----------|---------|
| update.exe | `a511be5164dc1122fb5a7daa3eef9467e43d8458425b15a640235796006590c9` |
| BluetoothService.exe | `2da00de67720f5f13b17e9d985fe70f10f153da60c9ab1086fe58f069a156924` |
| BluetoothService | `77bfea78def679aa1117f569a35e8fd1542df21f7e00e27f192c907e61d63a2e` |
| log.dll | `3bdc4c0637591533f1d4198a72a33426c01f69bd2e15ceee547866f65e26b7ad` |
| u.bat | `9276594e73cda1c69b7d265b3f08dc8fa84bf2d6599086b9acc0bb3745146600` |
| conf.c | `f4d829739f2d6ba7e3ede83dad428a0ced1a703ec582fc73a4eee3df3704629a` |
| libtcc.dll | `4a52570eeaf9d27722377865df312e295a7a23c3b6eb991944c2ecd707cc9906` |
| ConsoleApplication2.exe | `b4169a831292e245ebdffedd5820584d73b129411546e7d3eccf4663d5fc5be3` |
| loader1 | `0a9b8df968df41920b6ff07785cbfebe8bda29e6b512c94a3b2a83d10014d2fd` |
| loader2 | `e7cd605568c38bd6e0aba31045e1633205d0598c607a855e2e1bca4cca1c6eda` |
| s047t5g.exe | `fcc2765305bcd213b7558025b2039df2265c3e0b6401e4833123c461df2de51a` |

</details>

### Host Indicators

| Type | Indicator |
|------|-----------|
| Mutex | `Global\Jdhfv_1.0.1` |
| Path | `%AppData%\Roaming\Bluetooth\` |
| Path | `C:\ProgramData\USOShared\` |
| File | `BluetoothService.exe` (in AppData) |
| File | `log.dll` (sideloaded) |
| File | `conf.c` (TCC shellcode) |

---

---

## ⚠️ Important Notes

- **False Positives**: Some queries may trigger on legitimate Bluetooth services. Tune the `FolderPath` conditions based on your environment.
- **Performance**: Hash-based queries on large datasets may be resource-intensive. Consider using Watchlists for IOC matching.
- **Updates**: IOCs may change as the threat actor evolves. Monitor other threat intel sources for updates.

---

## References

- [Rapid7 Labs - The Chrysalis Backdoor: A Deep Dive into Lotus Blossom's toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/)
- [Symantec - China-Linked Espionage Actors](https://sed-cms.broadcom.com/system/files/threat-hunter-whitepaper/2025-04/2025_04_ChinaLinked_Espionage_Actors.pdf)
- [Notepad++ Hijacked Incident](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [Microsoft Warbird Research - DownWithUp](https://downwithup.github.io/blog/post/2023/04/23/post9.html)
- [MITRE ATT&CK - Lotus Blossom](https://attack.mitre.org/groups/G0030/)

---

## Contributing

Contributions are welcome! Please submit a Pull Request with:
- New detection rules
- False positive tuning suggestions
- Additional IOCs from related campaigns
- Translations to other SIEM query languages (Splunk SPL, Elastic EQL, etc.)


## Contact

For questions or feedback, please open an issue or contact via GitHub.

---
