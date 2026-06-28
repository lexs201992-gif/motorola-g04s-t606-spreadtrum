# Consolidated Disclosure Report — Rapid7 & AttackerKB

This consolidated report collects findings, IOCs, YARA rules, verification steps, and suggested disclosure actions for three privileged/system APKs discovered in Motorola G04s (Unisoc T606) firmware. It is intended for submission to Rapid7, AttackerKB, and vendor security teams for coordinated disclosure.

Report author: lexs201992 (lexs201992@gmail.com)
Date: 2026-06-28

---

## Title
Suspected factory-installed telemetry / biometric-exfiltration components in Motorola G04s (Unisoc T606) firmware — com.dti.amx, com.spreadtrum.ims, com.spreadtrum.sgps

## Short summary
Security research by lexs201992 identifies three privileged/system APKs embedded in Motorola G04s / Unisoc T606 firmware associated with telemetry, potential exfiltration behaviors, and ISP/camera chains enabling covert biometric collection. The report contains hashes, YARA detection rules, detection steps, and recommended mitigations for ingestion and vendor coordination.

## Affected artifacts (packages + SHA256)
- com.dti.amx (Digital Turbine Ignite) — SHA256: `7902116480673e44239c5a310bb5feed257692eacca25a1284a9fa613a8ebd20` — Risk: CRITICAL
- com.spreadtrum.ims (Unisoc IMS stack) — SHA256: `1b938cb3920d601a38e4d80e88c87aaacc56abfa6464f3054de2430172c6f519` — Risk: HIGH
- com.spreadtrum.sgps (SPRD SGPS/GNSS component) — SHA256: `4cfe803b578fd6958d236e494248585eccbc5c33a5113bda7ff1a47351e4118d` — Risk: HIGH

## Repository artifacts (branches & files)
- Branches created (contains YARA rules and disclosure drafts):
  - dti-apk-report: https://github.com/lexs201992-gif/motorola-g04s-t606-spreadtrum/tree/dti-apk-report
  - sprd-ims-apk-report: https://github.com/lexs201992-gif/motorola-g04s-t606-spreadtrum/tree/sprd-ims-apk-report
  - sprd-sgps-apk-report: https://github.com/lexs201992-gif/motorola-g04s-t606-spreadtrum/tree/sprd-sgps-apk-report
- Files added:
  - malicious_dti_amx.yar
  - malicious_sprd_ims.yar
  - malicious_sprd_sgps.yar
  - REPORTS/DTI_DISCLOSURE.md
  - REPORTS/SPRD_IMS_DISCLOSURE.md
  - REPORTS/SPRD_SGPS_DISCLOSURE.md
  - IOCs.md (updated with the three SHAs)
  - PR_DESCRIPTION.md

## Key technical findings (evidence summary)
- Privileged permissions and configs:
  - Multiple `privapp-permissions-*.xml` grant elevated permissions to ad/analytics components (see CVE_INVESTIGATION.md).
  - Attack chain: `vendor/sprd/modules/libcamera/iss` → `SPRD_TAG_ISCENE_INFO` → privileged analytics app (e.g., `com.inmobi.analytics`) via `privapp-permissions-*.xml` — allows silent collection of camera frames/biometrics without runtime prompts.

- ISP/camera vectors:
  - ISP structures (AE/AWB, LSC, PDAF, scene detection, XDR/HDR) can be manipulated to covertly capture and optimize images for biometric extraction (see SPRD_VECTOR_ATTACK.md and SPRD_ADVANCED_ATTACK_VECTORS.md).

- Manifest evidence (com.spreadtrum.sgps):
  - package: `com.spreadtrum.sgps`
  - Exported MAIN activity: `.SgpsActivity` (`android:exported="true"`)
  - Receiver for secret code: `android_secret_code` host="2266" (Telephony.SECRET_CODE) — hidden trigger pattern
  - Permissions include `ACCESS_FINE_LOCATION`, `ACCESS_BACKGROUND_LOCATION`, `ACCESS_LOCATION_EXTRA_COMMANDS`, `REBOOT`, `WAKE_LOCK`.

## Network and other IOCs
- C2 domains:
  - `*.unicom-sprd.com` — port 1883 (MQTT) — telemetry & command
  - `*.guanhongpcb.cn` — port 443 (HTTPS) — data exfiltration
- Kernel/build metadata:
  - Build path indicator: `/data/jenkins/workspace/Build-LXF_M173_U_MP_SMR`
  - Kernel noted in investigation: `5.15.178-android13-...` (see README/CVE_INVESTIGATION.md)

## YARA rules (located in repo branches)
- malicious_dti_amx.yar — matches DTI APK SHA + fallback strings
- malicious_sprd_ims.yar — matches SPRD IMS APK SHA + package strings
- malicious_sprd_sgps.yar — matches SPRD SGPS APK SHA + package strings

## Detection & verification steps
1) Pull APK and confirm SHA:
```bash
adb shell pm path <package.name>
adb pull /path/to/<package>/base.apk ./<package>.apk
sha256sum <package>.apk
```

2) Run YARA rules:
```bash
# from repo or downloaded rules
yara malicious_dti_amx.yar com.dti.amx.apk
yara malicious_sprd_ims.yar com.spreadtrum.ims.apk
yara malicious_sprd_sgps.yar com.spreadtrum.sgps.apk
```

3) Network detection:
- Use Snort/Zeek rules provided in IOCs.md to detect MQTT/TLS SNI connections to IOC domains.

4) Kernel/build forensic checks (requires root & controlled lab):
```bash
dmesg | grep -i "cmd_start"
adb shell cat /proc/kallsyms | grep cmd_start
logcat | grep -i "f2fs\|heap\|bootrom"
```

## Containment & mitigation (immediate actions)
- Non-root package disable (works for many devices):
```bash
adb shell pm disable-user com.dti.amx
adb shell pm disable-user com.spreadtrum.ims
adb shell pm disable-user com.spreadtrum.sgps
```
- Revoke dangerous appops (example):
```bash
adb shell appops set com.dti.amx CONTROL_VPN deny
adb shell appops set com.dti.amx RECORD_AUDIO deny
```
- Network containment:
  - Block `*.unicom-sprd.com` and `*.guanhongpcb.cn` at network edge
  - Block MQTT/1883 egress for affected devices
- Monitoring:
  - SIEM alerts on IOC domains
  - EDR policy to detect camera/ISP access and unsigned kernel modules

## Impact assessment / suggested severity
- `com.dti.amx` — CRITICAL: privileged/system app plus telemetry/exfiltration patterns; CVSS ~9.0+ if exfiltration from privileged context confirmed.
- `com.spreadtrum.ims` — HIGH: IMS stack influences telephony; potential RCE/privilege misuse; CVSS 7.x–9.x depending on repro.
- `com.spreadtrum.sgps` — HIGH: exported activity, secret-code receiver, and location permissions allow covert triggering and persistent location leakage.

## Suggested disclosure plan (coordinated)
1) Verify reproducibility across firmware images (collect sample firmware/APKs, confirm SHAs).
2) Dynamic lab testing of secret-code receiver, exported activities, and IMS interfaces.
3) Notify vendor(s) privately (Motorola & Unisoc) with secure artifact transfer.
4) Submit to Rapid7 / AttackerKB with full report + artifacts (secure transfer).
5) Public disclosure after vendor coordination and mitigation timeline.

## Suggested vendor notification template (short)
Subject: Sensitive: Suspected factory-installed telemetry/exfiltration components (Motorola G04s / Unisoc T606)

Body (high level):
- We identified privileged APKs (SHA256 listed) in Motorola G04s firmware that correlate with telemetry and camera/ISP behaviors enabling covert biometric exfiltration. Full evidence, YARA rules, and verification steps are in the repository branch; we are prepared to transfer artifacts securely and coordinate disclosure.
- Contact: lexs201992 (lexs201992@gmail.com)

---

## Repository/PR links (for reviewers)
- Repo root: https://github.com/lexs201992-gif/motorola-g04s-t606-spreadtrum
- DTI branch: https://github.com/lexs201992-gif/motorola-g04s-t606-spreadtrum/tree/dti-apk-report
- SPRD IMS branch: https://github.com/lexs201992-gif/motorola-g04s-t606-spreadtrum/tree/sprd-ims-apk-report
- SPRD SGPS branch: https://github.com/lexs201992-gif/motorola-g04s-t606-spreadtrum/tree/sprd-sgps-apk-report

---

Contact & handling
- Reporter: lexs201992 (lexs201992@gmail.com)
- Suggested sensitivity: Coordinated disclosure with vendor advised; public after vendor notification

