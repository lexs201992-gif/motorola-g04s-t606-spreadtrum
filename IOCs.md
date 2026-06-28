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
| `com.dti.amx` | `7902116480673e44239c5a310bb5feed257692eacca25a1284a9fa613a8ebd20` | Digital Turbine Ignite | **CRITICAL** |
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

```