Title: com.spreadtrum.ims (Unisoc IMS Stack) — Suspected privileged IMS component with RCE potential
Reporter: lexs201992 (lexs201992@gmail.com)
Branch: sprd-ims-apk-report
SHA256 (artifact reported): 1b938cb3920d601a38e4d80e88c87aaacc56abfa6464f3054de2430172c6f519

Summary:
- com.spreadtrum.ims (Unisoc IMS stack) appears in investigated firmware for Motorola G04s / Unisoc T606 devices.
- The APK with the above SHA is flagged as HIGH in our assessment due to system privileges and its role in IMS (which can influence telephony/remote-execution surface when vulnerable).

Evidence included:
- SHA256 (above)
- ADB commands and YARA rules to identify the artifact (see IOCs.md and malicious_sprd_ims.yar)
- Network IOCs observed in investigation (IOCs.md): *.unicom-sprd.com (MQTT), *.guanhongpcb.cn (HTTPS)
- Kernel/build metadata references: Build path /data/jenkins/workspace/Build-LXF_M173_U_MP_SMR (see SPRD docs)

Impact:
- Potential remote code execution or privileged misuse via IMS interfaces
- Telephony disruption or data exfiltration when exploited, especially combined with other system-level components

Suggested actions for Rapid7 / AttackerKB (and general disclosure steps):
1. Verify the SHA on available firmware/APK samples and in vendor images.
2. Perform dynamic testing of IMS interfaces in a controlled lab to determine RCE or privilege escalation potential.
3. Correlate with network telemetry (MQTT to unicom-sprd, TLS SNI guanhongpcb.cn) and with observed device symptoms (battery drain, high temp, persistent connections).
4. Coordinate vendor notification (Motorola / Unisoc) and consider coordinated disclosure; provide repro artifacts in a secure channel.
5. Publish an advisory entry (AttackerKB) summarizing indicators, mitigation steps (ADB disable commands), and YARA rules — link to this repository branch for details.

Attachments to include with disclosure:
- The APK (or a hash + retrieval instructions)
- Relevant log extracts (logcat, network captures)
- YARA rule file(s) and the IOCs.md references

Contact & handling:
- Reporter: lexs201992 (lexs201992@gmail.com)
- Suggested sensitivity: Coordinated disclosure with vendor advised; public after vendor notification
