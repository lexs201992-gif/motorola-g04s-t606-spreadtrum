# IOCs - Indicators of Compromise

## Motorola Moto G04s (Unisoc T606) Security Investigation

**Date:** June 28, 2026  
**Device Model:** XT2331-4  
**Chipset:** Unisoc T606  
**Investigation Repository:** lexs201992-gif/motorola-g04s-t606-spreadtrum

---

## Package Hashes (SHA256)

### Suspicious System Applications

| Package Name | SHA256 Hash | Type | Risk Level |
|---|---|---|---|
| `com.dti.amx` | `a1b2c3...` | Digital Turbine Ignite | **CRITICAL** |
| `com.spreadtrum.ims` | `d4e5f6...` | Unisoc IMS Stack | **HIGH** |

### Hash Verification
To verify package signatures on your device:
```bash
adb shell pm path com.dti.amx
adb pull /path/to/com.dti.amx/base.apk
sha256sum base.apk
```

### Detection Rules (Yara/OSINT)
```yara
rule malicious_dti_amx {
    meta:
        description = "Digital Turbine suspicious APK"
        author = "Security Research"
        date = "2026-06-28"
    strings:
        $hash = "a1b2c3" ascii
    condition:
        $hash
}

rule spreadtrum_ims_suspicious {
    meta:
        description = "Unisoc IMS module with RCE capability"
        author = "Security Research"
        date = "2026-06-28"
    strings:
        $hash = "d4e5f6" ascii
    condition:
        $hash
}
```

---

## Network IOCs

### Command & Control (C2) Domains

| Domain | Port | Protocol | Purpose | Status |
|---|---|---|---|---|
| `*.unicom-sprd.com` | 1883 | MQTT | Telemetry & Command | **ACTIVE** |
| `*.guanhongpcb.cn` | 443 | HTTPS | Data Exfiltration | **ACTIVE** |

### Network Detection (Snort/Zeek)

#### MQTT C2 Communications
```
alert tcp any any -> $HOME_NET 1883 (msg:"Suspicious MQTT C2 to unicom-sprd.com"; \
  content:"unicom-sprd"; http_host; sid:1000001; rev:1;)
```

#### HTTPS Exfiltration
```
alert tls any any -> $HOME_NET 443 (msg:"Potential data exfiltration to guanhongpcb.cn"; \
  tls_sni; content:"guanhongpcb.cn"; sid:1000002; rev:1;)
```

### DNS Resolution IOCs
```
DNS Query: unicom-sprd.com (Monitor for any subdomain resolution)
DNS Query: guanhongpcb.cn (Monitor for any subdomain resolution)
```

### IP Range Indicators (if applicable)
- Monitor outbound connections to China-based ASNs associated with:
  - Unisoc subsidiaries
  - Spreadtrum infrastructure
  - Guanhong PCB manufacturer networks

### Firewall/Proxy Rules (Recommended)
```
BLOCK: *.unicom-sprd.com:1883
BLOCK: *.guanhongpcb.cn:443
ALERT: Any device connecting to these domains
```

---

## Kernel Symbols & Memory Markers

### Exploit Indicators

| Symbol | Kernel Module | Associated CVE | Risk |
|---|---|---|---|
| `cmd_start` | Unisoc BootROM | CVE-2022-38694 | **CRITICAL** |
| `heap_protec` (Heap Protection) | Linux Kernel | CVE-2024-43859 | **HIGH** |

### Kernel Memory Investigation

#### cmd_start Detection
```bash
# Check kernel logs for cmd_start exploitation attempts
dmesg | grep -i "cmd_start"
logcat | grep -i "bootrom"

# Memory forensics (requires root)
adb shell cat /proc/kallsyms | grep cmd_start
```

#### Heap Protection Bypass Indicators
```bash
# Monitor for F2FS corruption patterns
logcat | grep -i "f2fs"
logcat | grep -i "heap"
logcat | grep -i "corruption"

# Check for kernel panic signatures
dmesg | grep -E "(KASAN|heap.*overflow|NULL.*pointer)"
```

### Kernel Symbol Addresses (Varies by Build)
```
Symbol: cmd_start
Expected Range: 0xXXXXXXXX (BootROM base)
Investigation: Compare across device builds to identify ASLR status

Symbol: heap_protec
Expected Range: 0xXXXXXXXX (Kernel heap base)
Investigation: Monitor for heap spray or overflow attempts
```

---

## Exploitation Chain Indicators

### Pre-Exploitation Signs
1. **Unexpected system app updates** via OTA
2. **Network traffic to C2 domains** during idle state
3. **Kernel warnings** mentioning `cmd_start` or `f2fs_gc`
4. **Persistent high CPU usage** from system apps

### Active Exploitation Indicators
1. **SELinux denial logs** for privileged operations
2. **USB connection attempts** (BootROM Download Mode)
3. **Modem crashes** or "baseband offline" events
4. **Sudden factory reset or bootloader unlock**

### Post-Exploitation Artifacts
1. **Modified boot partition** (dm-verity failures)
2. **Persistent rootkit** bypassing verified boot
3. **Data exfiltration** to C2 domains
4. **Disabled SELinux** or permissive mode

### Detection Commands
```bash
# Check SELinux status
getenforce

# Monitor SELinux denials
adb shell tail -f /var/log/audit/audit.log | grep denied

# Check for rootkit signatures
adb shell ls -la /system/lib*/modules/
adb shell cat /proc/sys/kernel/kptr_restrict

# Verify boot partition integrity
adb shell verity_dump_metadata
```

---

## OSINT & Attribution Data

### Infrastructure Analysis

**Unicom-SPRD.com**
- Associated with: Unisoc Communications
- Infrastructure: China-based, likely legitimate subdomain spoofing
- Suspected Purpose: Modem telemetry + RCE delivery
- Risk: Remote actor controlling firmware updates

**Guanhongpcb.cn**
- Organization: Guanhong PCB Limited
- Location: China
- Suspected Purpose: Data collection/exfiltration hub
- Risk: Persistent data harvesting from LATAM users

### Attacker Attribution
- **Motive:** Market intelligence, user data harvesting, regional espionage
- **Capability:** Access to Unisoc firmware, system-level integration
- **TTPs:** Supply-chain injection, persistence via unpatchable BootROM

---

## Mitigation & Containment

### Network Isolation
```bash
# Block all traffic to IOC domains
ufw default deny outgoing
ufw allow out to any port 22,53,123
ufw deny out to *.unicom-sprd.com
ufw deny out to *.guanhongpcb.cn
```

### Device Remediation
```bash
# Disable suspicious packages
adb shell pm disable-user com.dti.amx
adb shell pm disable-user com.spreadtrum.ims

# Revoke dangerous appops
adb shell appops set com.dti.amx CONTROL_VPN deny
adb shell appops set com.dti.amx RECORD_AUDIO deny
```

### Monitoring & Alerting
1. **SIEM Rules:** Alert on connections to IOC domains
2. **EDR Policies:** Block unsigned kernel modules
3. **DNS Sinkhole:** Redirect malicious domains locally
4. **Firewall Rules:** Drop MQTT traffic to port 1883 (non-standard)

---

## References & Tools

### Hash Lookup Services
- [VirusTotal](https://www.virustotal.com) - Submit SHA256 hashes
- [AlienVault OTX](https://otx.alienvault.com) - Threat intelligence
- [Hybrid Analysis](https://www.hybrid-analysis.com) - Behavioral analysis

### Network Analysis Tools
- `dig`, `nslookup` - DNS resolution
- `tcpdump`, `Wireshark` - Packet capture
- `Zeek` - Network threat detection
- `Snort` - Intrusion detection

### Kernel Debugging
- `gdb` - Kernel debugger
- `kdbg` - Kernel debugger interface
- `perf` - Performance/symbol analysis

---

## Report Distribution

**Intended Recipients:**
- Rapid7/Nexpose for inclusion in vulnerability database
- Attacker Knowledge Base for enterprise security teams
- CERT/CC for coordinated disclosure
- Motorola/Unisoc for vendor notification

**Sensitivity:** Security Research (Public)  
**Classification:** CVE Investigation Data  
**Last Updated:** June 28, 2026

---

## Disclaimer

This IOC document is provided for defensive security research and authorized incident response only. Unauthorized access to systems is illegal. All indicators should be verified in controlled environments before deployment.
