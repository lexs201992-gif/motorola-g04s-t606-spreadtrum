Title: com.spreadtrum.sgps (SPRD SGPS/GNSS component) — Suspected privileged/location component
Reporter: lexs201992 (lexs201992@gmail.com)
Branch: sprd-sgps-apk-report
SHA256 (artifact reported): 4cfe803b578fd6958d236e494248585eccbc5c33a5113bda7ff1a47351e4118d

Summary:
- com.spreadtrum.sgps appears in investigated firmware for Motorola G04s / Unisoc T606 devices.
- The APK with the above SHA is flagged as HIGH in our assessment due to location permissions, an exported MAIN activity, and a SECRET_CODE receiver which can be used as a hidden trigger.

Manifest highlights (from provided manifest snippet):
- package: com.spreadtrum.sgps
- exported MAIN Activity: .SgpsActivity (exported="true")
- SECRET_CODE receiver: android_secret_code host="2266" (intent-filter with Telephony.SECRET_CODE)
- Service: .SgpsService (exported="false")
- Permissions observed: ACCESS_FINE_LOCATION, ACCESS_LOCATION_EXTRA_COMMANDS, ACCESS_BACKGROUND_LOCATION, REBOOT, WAKE_LOCK

Impact:
- High risk to user location privacy and potential for covert triggering via secret-code receiver.
- If combined with other privileged components, could enable persistent location exfiltration or unexpected device behavior (reboot via REBOOT permission).

Suggested actions for Rapid7 / AttackerKB (and general disclosure steps):
1. Verify the SHA on available firmware/APK samples and in vendor images.
2. Perform dynamic testing in a controlled lab to exercise the SECRET_CODE receiver (dial secret code or send Telephony.SECRET_CODE intents) and the exported MAIN activity.
3. Correlate with network telemetry and device symptoms (battery drain, persistent network connections).
4. Coordinate vendor notification (Motorola / Unisoc) and consider coordinated disclosure; provide repro artifacts in a secure channel.
5. Publish an advisory entry (AttackerKB) summarizing indicators, mitigation steps (ADB disable commands), and YARA rules — link to this repository branch for details.

Verification steps (local):
```bash
# confirm APK hash
adb shell pm path com.spreadtrum.sgps
adb pull /path/to/com.spreadtrum.sgps/base.apk ./com.spreadtrum.sgps.apk
sha256sum com.spreadtrum.sgps.apk

# run yara
yara malicious_sprd_sgps.yar com.spreadtrum.sgps.apk
```

Contact & handling:
- Reporter: lexs201992 (lexs201992@gmail.com)
- Suggested sensitivity: Coordinated disclosure with vendor advised; public after vendor notification
