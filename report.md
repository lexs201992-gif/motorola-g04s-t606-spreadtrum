# Suspected factory-installed telemetry & installer components in Motorola G04s (Unisoc T606)

Researcher: lexs201992 (lexs201992@gmail.com)
Date: 2026-06-28

Tags: android, firmware, telemetry, backdoor, installer, privilege-escalation, privacy, supply-chain

---

## Title
Suspected factory-installed telemetry & installer components in Motorola G04s (Unisoc T606) — com.dti.amx, com.spreadtrum.ims, com.spreadtrum.sgps, com.inmobi.installer

## Overview
Researcher lexs201992 identified multiple privileged/system APKs present in Motorola G04s / Unisoc T606 firmware that show telemetry/exfiltration patterns, installer/update capabilities, and exported/secret-code interfaces enabling covert triggering and persistent telemetry. This submission provides hashes, YARA detection rules, network IOCs, reproduction steps, and suggested mitigations for AttackerKB ingestion and cross-reference.

## Affected components / products
- com.dti.amx (Digital Turbine Ignite) — SHA256: `7902116480673e44239c5a310bb5feed257692eacca25a1284a9fa613a8ebd20` — Risk: CRITICAL
- com.spreadtrum.ims (Unisoc IMS stack) — SHA256: `1b938cb3920d601a38e4d80e88c87aaacc56abfa6464f3054de2430172c6f519` — Risk: HIGH
- com.spreadtrum.sgps (SPRD SGPS/GNSS) — SHA256: `4cfe803b578fd6958d236e494248585eccbc5c33a5113bda7ff1a47351e4118d` — Risk: HIGH
- com.inmobi.installer (InMobi installer/updater) — SHA256: `1fe9c2c2e4b390f01d2bb7d90b5d219dbe85fdd42321f247a295d532c9b387d2` — Risk: HIGH

## Technical details
- com.dti.amx: identified as Digital Turbine Ignite; privileged/system context observed in firmware. Telemetry/exfiltration patterns and telemetry endpoints correlate with observed network IOCs.
- com.spreadtrum.ims: IMS stack component with system privileges — potential to influence telephony/IMS surfaces; may increase attack surface for remote/privileged misuse.
- com.spreadtrum.sgps: Manifest includes exported MAIN activity (`.SgpsActivity` android:exported="true") and a `Telephony.SECRET_CODE` receiver (`android_secret_code` host="2266`) — hidden trigger capability plus fine/background location permissions.
- com.inmobi.installer: installer/updater with `INSTALL_PACKAGES` and `QUERY_ALL_PACKAGES` permissions, exported provider(s) and `InstallationService` (exported=true) — enables silent installs or update flows if misused.
- Attack surface correlation: vendor ISP/camera chains (`vendor/sprd/modules/libcamera/iss` → `SPRD_TAG_ISCENE_INFO`) plus `privapp-permissions-*.xml` allow privileged analytics components to receive ISP/camera artifacts, enabling covert biometric collection without runtime prompts.

## Indicators of Compromise (IOCs)
- SHA256 hashes:
  - `7902116480673e44239c5a310bb5feed257692eacca25a1284a9fa613a8ebd20` (com.dti.amx)
  - `1b938cb3920d601a38e4d80e88c87aaacc56abfa6464f3054de2430172c6f519` (com.spreadtrum.ims)
  - `4cfe803b578fd6958d236e494248585eccbc5c33a5113bda7ff1a47351e4118d` (com.spreadtrum.sgps)
  - `1fe9c2c2e4b390f01d2bb7d90b5d219dbe85fdd42321f247a295d532c9b387d2` (com.inmobi.installer)
- Network IOCs:
  - `*.unicom-sprd.com` (MQTT, port 1883) — telemetry/command channels
  - `*.guanhongpcb.cn` (HTTPS, TLS SNI) — exfiltration endpoints
- Manifest notable strings:
  - com.spreadtrum.sgps: `Telephony.SECRET_CODE` host=2266, exported `.SgpsActivity`
  - com.inmobi.installer: `INSTALL_PACKAGES`, `QUERY_ALL_PACKAGES`, exported providers (authorities `com.inmobi.installer.provider` and attribution provider), `InstallationService` action `com.inmobi.installer.IPackageInstaller`
- Certificate for com.inmobi.installer:
  - Issuer/Subject CN=Swish (InMobi pvt. ltd.), Serial: 1760801217 — use cert fingerprint to confirm binary signing

## Detection signatures (YARA)
Provided YARA rules (in repo branches):
- `malicious_dti_amx.yar` — matches DTI SHA or package name + strings
- `malicious_sprd_ims.yar` — matches SPRD IMS SHA or package name
- `malicious_sprd_sgps.yar` — matches SPRD SGPS SHA or package + sgps
- `malicious_inmobi_installer.yar` — matches InMobi SHA, package name, certificate CN "Swish", and inmobi strings

Repo location for rules: https://github.com/lexs201992-gif/motorola-g04s-t606-spreadtrum (branches: `dti-apk-report`, `sprd-ims-apk-report`, `sprd-sgps-apk-report`, `inmobi-installer-apk-report`)

## Reproduction steps (verification)
1) Pull APK from device/firmware and validate hash:
```bash
adb shell pm path <package.name>
adb pull /path/to/<package>/base.apk ./<package>.apk
sha256sum <package>.apk
```
2) Run YARA:
```bash
yara malicious_<rule>.yar <package>.apk
```
3) Dynamic tests (lab, controlled):
- For `com.spreadtrum.sgps`: send `Telephony.SECRET_CODE` broadcast with host=2266 or dial the secret code equivalent to exercise the hidden receiver; monitor `logcat` and network traffic.
- For `com.inmobi.installer`: exercise installer service via intent `com.inmobi.installer.IPackageInstaller` in a confined lab environment; observe for silent install behavior.
- Instrument network connections; capture pcap to detect MQTT to `unicom-sprd.com` or TLS SNI to `guanhongpcb.cn`.

## Impact
- Silent telemetry and potential exfiltration of sensitive data (including images/ISP data usable for biometric extraction) originating from privileged/system apps.
- Installer/updater component (`com.inmobi.installer`) with `INSTALL_PACKAGES` may enable silent installs or update chains leading to persistence or supply-chain abuse.
- Exported activities and secret-code receivers permit covert local triggers.
- Combined with ISP/camera hooks, an attacker can capture and exfiltrate biometric data without user consent.

## Suggested severity
- `com.dti.amx` — CRITICAL (privileged telemetry/exfiltration)
- `com.spreadtrum.ims` — HIGH (IMS privileged surface)
- `com.spreadtrum.sgps` — HIGH (exported secret-code receiver + location leak)
- `com.inmobi.installer` — HIGH (installer privileges + exported interfaces)

## Mitigations / recommendations
- Short-term (ops):
  - Block IOC domains (`*.unicom-sprd.com`, `*.guanhongpcb.cn`) at network perimeter and EDR/IDS.
  - Disable problematic packages on affected devices:
    `adb shell pm disable-user <package>`
  - Revoke dangerous appops where possible (`appops set ...`).
- Medium-term:
  - Include certificate fingerprint checks (signing cert SHA256) in detection rules.
  - Vendor coordination: request firmware audit, confirm presence and purpose of these APKs, remove or restrict exported interfaces, and restrict privileged permissions to only vetted components.
- Long-term:
  - Add YARA scanning to firmware intake pipelines and CI for vendor/OTA builds.

## Disclosure & coordination
- Recommended: coordinated disclosure with vendor(s) and maintain embargo until vendor response.
- Repo branches and draft reports (for reviewer reference):
  - dti-apk-report: https://github.com/lexs201992-gif/motorola-g04s-t606-spreadtrum/tree/dti-apk-report
  - sprd-ims-apk-report: https://github.com/lexs201992-gif/motorola-g04s-t606-spreadtrum/tree/sprd-ims-apk-report
  - sprd-sgps-apk-report: https://github.com/lexs201992-gif/motorola-g04s-t606-spreadtrum/tree/sprd-sgps-apk-report
  - inmobi-installer-apk-report: https://github.com/lexs201992-gif/motorola-g04s-t606-spreadtrum/tree/inmobi-installer-apk-report

Attachments & artifacts
- YARA rules and disclosure drafts are in the repo branches above. Do NOT include full APK binaries in public AttackerKB posts if an embargo is desired; transfer samples via secure channel (PGP/SFTP) to vendor or trusted parties.

## Contact (reporter)
- lexs201992 — lexs201992@gmail.com

## References
- Repository root: https://github.com/lexs201992-gif/motorola-g04s-t606-spreadtrum
- See branches listed above for YARA and disclosure drafts
- Additional internal analysis: README, CVE_INVESTIGATION.md, SPRD_VECTOR_ATTACK.md in repo
