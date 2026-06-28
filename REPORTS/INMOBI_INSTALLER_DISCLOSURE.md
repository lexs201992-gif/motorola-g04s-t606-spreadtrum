Title: com.inmobi.installer — InMobi installer/updater — privileged installer component
Reporter: lexs201992 (lexs201992@gmail.com)
Branch: inmobi-installer-apk-report
SHA256: 1fe9c2c2e4b390f01d2bb7d90b5d219dbe85fdd42321f247a295d532c9b387d2

Summary:
- com.inmobi.installer is present in investigated firmware and provides installer-level capabilities. The manifest and certificate indicate it is an installer/updater component with INSTALL_PACKAGES and QUERY_ALL_PACKAGES permissions and exported providers/services which can be invoked by system or other apps.

Manifest highlights (from provided manifest snippet):
- package: com.inmobi.installer
- Permissions: INSTALL_PACKAGES, QUERY_ALL_PACKAGES, RECEIVE_BOOT_COMPLETED, INTERNET, WAKE_LOCK, POST_NOTIFICATIONS, FOREGROUND_SERVICE, ACCESS_NETWORK_STATE, ACCESS_WIFI_STATE
- Providers: com.inmobi.installer.provider (exported = true), attribution provider (exported = true)
- Services: InstallationService exported=true, handles com.inmobi.installer.IPackageInstaller intent
- Receivers: BootReceiver exported=true (BOOT_COMPLETED)
- Activities: webview/consent activities, some exported=false, app supports installer flows and a foreground installer service

Certificate summary (from provided cert):
- Issuer/Subject: C=91, ST=Karnataka, L=Bangalore, O=InMobi pvt. ltd., OU=ITC, CN=Swish
- Serial: 1760801217
- Signature algorithm: sha256WithRSAEncryption
- Subject Key Identifier: FC:BF:0E:5B:C4:0B:C9:D7:5C:B2:D5:63:59:B7:E1:76:B9:F5:26:65

Impact / Risk:
- INSTALL_PACKAGES + exported installer interfaces and exported providers may allow silent installs, broad package queries, or privilege escalation flows if misused. High risk for unwanted app installs, supply-chain update abuse, or privileged persistence.

Suggested verification steps:
- Pull APK and confirm SHA:
  adb shell pm path com.inmobi.installer
  adb pull /path/to/com.inmobi.installer/base.apk ./com.inmobi.installer.apk
  sha256sum com.inmobi.installer.apk
- Run YARA:
  yara malicious_inmobi_installer.yar com.inmobi.installer.apk

Suggested mitigations:
- Disable installer interfaces until vendor response:
  adb shell pm disable-user com.inmobi.installer
- Block network telemetry to IOC domains and monitor for unexpected package installations.
- Include cert fingerprint checks in detection for more reliable binary identification.

Suggested disclosure steps:
- Verify across firmware images, collect logs (logcat, pcap), perform controlled dynamic testing of the installer service and exported providers, then coordinate vendor disclosure.
