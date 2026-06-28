# CVE Investigation Report

## Privileged Application Abuse Chain

**Evidence:** 15 `privapp-permissions-*.xml` files grant system-level access to ad networks.

**Critical Path:** `vendor/sprd/modules/libcamera/iss` → `SPRD_TAG_ISCENE_INFO.txt` → `com.inmobi.analytics` via `privapp-permissions-platform-inmobi.xml`

**Impact:** Silent exfiltration of document/face biometrics without user consent or runtime permission prompts.

### Details

#### Privileged Permissions Files
- Multiple `privapp-permissions-*.xml` configuration files discovered
- Grant elevated system-level permissions to third-party ad networks
- Bypass standard Android permission model

#### Attack Chain Breakdown

| Component | Role | Details |
|-----------|------|----------|
| `vendor/sprd/modules/libcamera/iss` | Camera Module | SPRD ISP (Image Signal Processor) handling camera operations |
| `SPRD_TAG_ISCENE_INFO.txt` | Scene Data | Intermediate data containing scene/face information tags |
| `com.inmobi.analytics` | Exfiltration Point | InMobi analytics package receives biometric data |
| `privapp-permissions-platform-inmobi.xml` | Permission Escalation | Grants privapp permissions without runtime checks |

#### Threat Indicators

- **No User Consent:** Biometric data collection occurs silently
- **No Runtime Permissions:** Privileged app status bypasses permission prompts
- **Systematic Exfiltration:** Document and face biometrics targeted
- **Ad Network Involvement:** InMobi analytics as exfiltration vector

### Mitigation

Users affected by this vulnerability should:
1. Disable InMobi-related packages if possible
2. Run the ADB commands in `detection.md` to disable suspicious services
3. Use YARA rule provided in `detection.md` to scan for indicators
