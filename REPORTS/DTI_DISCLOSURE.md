Title: com.dti.amx (Digital Turbine Ignite) — Suspected factory-installed telemetry/exfiltration component
Reporter: lexs201992 (lexs201992@gmail.com)
Branch: dti-apk-report
SHA256 (artifact reported): 7902116480673e44239c5a310bb5feed257692eacca25a1284a9fa613a8ebd20

Summary:
- com.dti.amx (Digital Turbine Ignite) appears in investigated firmware for Motorola G04s / Unisoc T606 devices.
- The APK with the above SHA is flagged as CRITICAL in our assessment because it is a privileged/system app and correlates with telemetry/exfiltration patterns observed during investigation.

Evidence included:
- SHA256 (above)
- ADB commands and YARA rules to identify the artifact (see detection.md and malicious_dti_amx.yar)
- Network IOCs observed in investigation (IOCs.md): *.unicom-sprd.com (MQTT), *.guanhongpcb.cn (HTTPS)
- Kernel/build metadata references: Build path /data/jenkins/workspace/Build-LXF_M173_U_MP_SMR (see SPRD docs)

Impact:
- Silent telemetry / possible exfiltration from privileged app context
- Potential privacy and biometric data exposure when combined with other ISP/backdoor chains described in this repository

Suggested actions for Rapid7 / AttackerKB (and general disclosure steps):
1. Verify the SHA on available firmware/APK samples and in vendor images.
2. Correlate with dynamic network telemetry (MQTT to unicom-sprd, TLS SNI guanhongpcb.cn).
3. If reproducible and confirmed, assign a severity/score consistent with privilege level and telemetry patterns (recommend CVSS near 9.x if exfiltration from privileged context is confirmed).
4. Coordinate vendor notification (Motorola / Unisoc) and consider coordinated disclosure; provide repro artifacts in a secure channel.
5. Publish an advisory entry (AttackerKB) summarizing indicators, mitigation steps (ADB disable commands), and YARA rules — link to this repository branch for details.

Attachments to include with disclosure:
- The APK (or a hash + retrieval instructions)
- Relevant log extracts (logcat, network captures)
- YARA rule file(s) and the IOCs.md references

Contact & handling:
- Reporter: lexs201992 (lexs201992@gmail.com)
- Suggested sensitivity: Public (once vendor notified) / Coordinated disclosure recommended
