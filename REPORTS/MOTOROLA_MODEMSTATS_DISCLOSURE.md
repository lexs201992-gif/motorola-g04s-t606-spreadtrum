Title: com.motorola.bach.modemstats — Motorola modemstats privileged component
Reporter: lexs201992 (lexs201992@gmail.com)
Branch: motorola-modemstats-apk-report
SHA256 (artifact reported): 4cfe803b578fd6958d236e494248585eccbc5c33a5113bda7ff1a47351e4118d

Summary:
- com.motorola.bach.modemstats appears in investigated firmware for Motorola G04s / Unisoc T606 devices. The APK is associated with modem/telemetry reporting and is built to run persistently in the modemservice process with elevated telephony and device-management permissions.

Manifest highlights (from provided manifest snippet):
- package: com.motorola.bach.modemstats
- application: persistent=true, process="com.motorola.modemservice", singleUser=true
- Permissions observed: READ_PRIVILEGED_PHONE_STATE, MODIFY_PHONE_STATE, MANAGE_NETWORK_POLICY, MANAGE_USERS, PACKAGE_USAGE_STATS, INTERACT_ACROSS_USERS_FULL, RECEIVE_BOOT_COMPLETED, ACCESS_NETWORK_STATE, ACCESS_WIFI_STATE, INTERNET, READ_LOGS
- Services: ModemStatsService, DataStallDetectService, NRCheckinService, NRCheckinJobService, MPhoneInCallService (BIND_INCALL_SERVICE, exported=true)
- Receiver: ModemStatsReceiver (exported=true) listening for SIM_STATE_CHANGED and BOOT_COMPLETED

Certificate summary (from provided cert):
- Issuer/Subject: C=CN, ST=ShangHai, L=ShangHai, O=Longcheer, OU=Longcheer, CN=Longcheer
- Serial: 0x228526b0d1ef90c3b8ed568a49c3714f6a39506b
- Signature algorithm: sha256WithRSAEncryption
- Subject Key Identifier: 97:B6:E1:F1:B2:AC:DB:DA:80:5C:56:B0:4E:82:D0:52:83:3C:8F:7B

Impact / Risk:
- The component holds multiple high-privilege telephony and device-management permissions and is persistent in a modem-related process. Potential risks include telemetry exfiltration, privileged access to telephony state, control over network policy, and in-call service interfaces that could be abused for surveillance or persistent data collection.

Suggested verification steps (local):
```bash
# confirm APK hash
adb shell pm path com.motorola.bach.modemstats
adb pull /path/to/com.motorola.bach.modemstats/base.apk ./com.motorola.bach.modemstats.apk
sha256sum com.motorola.bach.modemstats.apk

# run yara
yara malicious_motorola_modemstats.yar com.motorola.bach.modemstats.apk
```

Suggested mitigations:
- For immediate containment:
  - adb shell pm disable-user com.motorola.bach.modemstats
  - Block device egress to IOC domains at network edge
  - Monitor for unexpected modem/telemetry traffic and in-call service registrations
- For medium-term:
  - Coordinate with vendor (Motorola/Longcheer) for code/audit review and removal or hardening of exported interfaces
  - Add certificate fingerprint checks and YARA rules to firmware intake and CI

Suggested disclosure steps:
1. Verify SHA across firmware images and collect full APKs and log captures (logcat, pcap).
2. Perform dynamic lab testing of receiver/service behaviors (SIM_STATE_CHANGED handling, BOOT_COMPLETED, in-call service registration) in a controlled environment.
3. Notify vendor(s) privately with secure transfer of artifacts and coordinate remediation.
4. Publish coordinated advisory after vendor acknowledges and provides timeline.

Verification notes:
- The same SHA (4cfe803b...) has appeared for other components in this investigation (e.g., com.spreadtrum.sgps) — confirm sample provenance and build mapping when correlating across packages.

Contact & handling:
- Reporter: lexs201992 (lexs201992@gmail.com)
- Suggested sensitivity: Coordinated disclosure with vendor advised; keep PRs and artifacts Draft/embargoed until vendor coordination
