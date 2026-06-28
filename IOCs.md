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
| `com.spreadtrum.ims` | `1b938cb3920d601a38e4d80e88c87aaacc56abfa6464f3054de2430172c6f519` | Unisoc IMS Stack | **HIGH** |
| `com.spreadtrum.sgps` | `4cfe803b578fd6958d236e494248585eccbc5c33a5113bda7ff1a47351e4118d` | SPRD SGPS/GNSS component | **HIGH** |

### Hash Verification
To verify package signatures on your device:
```bash
adb shell pm path <package.name>
adb pull /path/to/<package>/base.apk
sha256sum base.apk
```

### Detection Rules (Yara/OSINT)
- malicious_dti_amx.yar
- malicious_sprd_ims.yar
- malicious_sprd_sgps.yar

---

## Network IOCs

### Command & Control (C2) Domains

| Domain | Port | Protocol | Purpose | Status |
|---|---|---|---|---|
| `*.unicom-sprd.com` | 1883 | MQTT | Telemetry & Command | **ACTIVE** |
| `*.guanhongpcb.cn` | 443 | HTTPS | Data Exfiltration | **ACTIVE** |

---

## Notes
- These entries were added to this branch for focused disclosure and analysis of the listed APKs. Keep the branch as Draft PR while coordinating with vendors.
