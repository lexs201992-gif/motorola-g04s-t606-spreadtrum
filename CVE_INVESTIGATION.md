# CVE Investigation - Motorola Moto G04s (T606)

## Device Information

### System Details
- **OS Version:** 14, Build: ULAS34.89-209-4
- **Bootloader:** lion-2026-03-18-15:42:53_LOCAL
- **VM:** ART
- **Kernel:** 5.15.178-android13-8-00006-g0c6055fd2d8b-ab13363910
- **Brand:** motorola
- **Model:** moto g04s
- **Board:** lion
- **Manufacturer:** motorola

### SDK Configuration
- **Target SDK:** 34
- **Minimum SDK:** 28

### Security Posture

#### Security Patch & Boot
- **Security Patch Level:** April 5, 2026
- **Root Access:** Disabled
- **Debuggable:** No
- **SELinux:** Enforcing
- **Encryption:** Enabled (FBE)
- **Verified Boot:** Green (verified)
- **AVB Version:** 1.2
- **dm-verity:** Enforcing
- **Bootloader:** Locked

#### Security Providers
- AndroidNSSP (v1.0)
- AndroidOpenSSL (v1.0)
- CertPathProvider (v1.0)
- AndroidKeyStoreBCWorkaround (v1.0)
- BC (v1.77)
- HarmonyJSSE (v1.0)
- AndroidKeyStore (v1.0)
- JKS (v1.0)

#### Android KeyStore Features
- **Software:** Supported
- **Hardware:** Supported
  - AES, HMAC, ECDSA, RSA, ECDH, Curve 25519

### Hardware Specifications

#### Processor
- **CPU Hardware:** Spreadtrum T606
- **Supported Architectures:** arm64-v8a, armeabi-v7a, armeabi
- **Cores:** 8

#### Graphics
- **GPU:** ARM Mali-G57
- **OpenGL ES Version:** 3.2
- **Vulkan Version:** 1.3

#### Memory
- **RAM:** 4.00 GB

#### Battery
- **Technology:** Li-ion
- **Capacity:** 5000.0 mAh (est. 4873.1 mAh)
- **Health:** Good (1569 cycles)

#### Display
- **Density:** hdpi (238 DPI)
- **Scaling Factor:** 1.4875001
- **Resolution:** 720px × 1612px
- **Window Size:** 720px × 1462px
- **Refresh Rate:** 90.0 Hz

### System Configuration

#### Users & Apps
- **Users:** 1 (This device)
- **Total Apps:** 292
  - User Apps: 17
  - System Apps: 275

#### Languages
- English (United States)

## Hardware Features

### Communication
- Bluetooth & Bluetooth LE
- Broadcast Radio
- WiFi & WiFi Direct
- WiFi Passpoint
- GPS & Network Location
- Telephony (GSM, CDMA, IMS)
- USB Accessory & USB Host

### Sensors
- Accelerometer
- Light Sensor
- Proximity Sensor
- Step Counter & Step Detector

### Biometrics & Security
- Face Biometrics
- Fingerprint Recognition
- Hardware Keystore (v200)
- App Attestation Key Support

### Camera & Media
- Rear Camera with Auto-focus & Flash
- Front Camera
- Manual Sensor Capability
- Audio Output & Microphone

### Additional Features
- Touch Screen (Multi-touch)
- Home Screen
- App Widgets
- Autofill
- Device Admin
- Print Support
- Picture-in-Picture

## Software Features & Capabilities

### Android Features
- Verified Boot
- File-Based Encryption (FBE)
- Incremental Delivery (v2)
- Managed Users
- App Enumeration
- Securely Removes Users
- Device Lock
- EROFS Support

### Graphics & Rendering
- OpenGL ES Support
- Vulkan Compute Support
- Vulkan Level (v1)
- Vulkan Version (v4206592)

### OEM-Specific Features
- **Motorola:**
  - com.motorola.enterprise
  - com.motorola.help
  - com.motorola.launcher3 (with grid customization)
  - com.motorola.motolivewallpaper
  - com.motorola.software.game_mode
  - com.motorola.software.guideme

- **Google:**
  - Google Dialer with call recording
  - Google Contacts
  - Advanced Satellite Imagery (ASI)
  - Device-to-Device Cable Migration
  - Personal Safety
  - Turbo Preload
  - Wellbeing
  - Google Lens Camera Integration

---

# Security Investigation Report: Motorola Moto G04s (Unisoc T606)

**Date:** June 26, 2026  
**Target Device:** Motorola Moto G04s, Model XT2331-4  
**Chipset:** Unisoc T606, Octa-core  
**ODM:** Longcheer  
**Region Focus:** Latin America, Mexico  
**Investigator:** Independent Security Research

## 1. Executive Summary

The Motorola Moto G04s contains a critical chain of vulnerabilities stemming from the Unisoc T606 chipset firmware and aggressive pre-installed system applications from Digital Turbine and InMobi. The combination of an unpatchable BootROM exploit **CVE-2022-38694**, active modem RCE vulnerabilities **CVE-2025-31718**, and privileged system apps with invasive appops (VPN, Bluetooth, Audio) creates a high-risk environment for remote code execution, covert surveillance, and data exfiltration. Current security patches from Motorola are insufficient or delayed, leaving millions of LATAM users exposed.

This report highlights a systemic issue in budget Android devices sold in LATAM. The combination of hardware-level vulnerabilities (unpatchable) and software-level abuse (system apps) creates a "perfect storm" for privacy violations.

## 2. Critical Hardware & Firmware Vulnerabilities (Unisoc T606)

### 2.1 BootROM Exploit (Permanent)

- **CVE:** CVE-2022-38694, CVSS 7.8
- **Component:** Unisoc BootROM, Download Mode / `cmd_start`
- **Mechanism:** Unchecked write address allows arbitrary memory overwrite during FDL1 payload loading
- **Impact:** Permanent bypass of Secure Boot, allowing unsigned firmware flashing, bootloader unlocking, and persistent rootkits. Cannot be patched via OTA
- **Status:** Public PoC available, NCC Group, GitHub
- **Relevance:** Enables physical attackers or malicious apps with USB/reboot privileges to take full control of the device

### 2.2 Modem Remote Code Execution (RCE)

- **CVE:** CVE-2025-31718, CVSS 7.5 | CVE-2025-31717 DoS
- **Component:** LTE Modem Firmware, Baseband
- **Mechanism:** Improper input validation in modem stack allows malformed LTE signals to trigger system crash or arbitrary code execution in the kernel

### 2.3 Kernel & Driver Flaws

- **CVE:** CVE-2024-43859 F2FS, CVE-2022-20210 Modem
- **Component:** Linux Kernel, F2FS, Camera, GPU drivers
- **Mechanism:** NULL pointer dereference in `f2fs_truncate`, IOCTL bugs in camera/SPI drivers
- **Impact:** Local Privilege Escalation (LPE) from system app to Kernel Root

## 3. System App Abuse & Privacy Violations

### 3.1 Aggressive System Apps

- **Packages:** `com.digitalturbine._` (DT Ignite, Mobile Services Manager), `com.inmobi._` (Analytics, Weather/News widgets)
- **Location:** `/system/priv-app/`. Non-removable without root

### 3.2 Invasive AppOps & Permissions

#### CONTROL_VPN
- System app can programmatically enable, disable, or switch VPN profile without user interaction
- **Risk:** Man-in-the-Middle, intercepting all unencrypted HTTP and potentially decrypting HTTPS if they also install root cert
- Can disable user-installed security VPN

#### BLUETOOTH_CONNECT
- Combined with location, allows tracking via beacons even if GPS is off

#### SOUND / RECORD_AUDIO
- Potential for covert microphone activation

#### GNSS & Location Privacy (Major Concern)
- Unisoc location stack lacks transparent user controls
- System apps with `ACCESS_FINE_LOCATION` granted by default can track precise location continuously
- Data is sent to third-party analytics SDKs InMobi embedded in system apps

## 4. Attack Chain Scenario: From System App to Kernel Root

1. **Initial Access:** Malicious system app `com.dti.amx` uses `INSTALL_PACKAGES` or `CONTROL_VPN` to drop payload or establish C2
2. **Privilege Escalation:** Payload exploits `CVE-2024-43859` F2FS or `sprd_camera` IOCTL to achieve Kernel Root
3. **Persistence:** Rootkit leverages `CVE-2022-38694` BootROM flaw to modify `boot` partition or install persistent rootkit that survives factory resets
4. **Surveillance & Exfiltration:** With root, attacker can access microphone `SOUND`, camera, location `BLUETOOTH_CONNECT`, and all user data, bypassing Android `fscrypt` and SELinux. Exfiltrates data via controlled VPN or modem backchannel

## 5. Recommendations for Rapid7 & Attacker KB

### 5.1 Detection Signatures (Nessus/Nexpose)

- **Check:** Android Security Patch Level < June 2026
- **Check:** Presence of `com.digitalturbine._` or `com.inmobi._` in `/system/priv-app/`
- **Check:** Unisoc T606 chipset detected via `ro.product.board` or `getprop ro.hardware`
- **Vulnerability ID:** Create new plugin for CVE-2025-31718 Unisoc Modem RCE and CVE-2022-38694 BootROM

### 5.2 Mitigation for Users (LATAM Focus)

#### 1. Disable Bloatware (ADB)
```bash
adb shell pm uninstall --user 0 com.digitalturbine.appcloud
adb shell pm uninstall --user 0 com.inmobi.analytics
adb shell pm uninstall --user 0 com.motorola.frameworks.core.addon
```
**Note:** Verify package names via `pm list packages -s`

#### 2. Revoke Appops (Root/ADB)
```bash
appops set com.digitalturbine.* CONTROL_VPN ignore
appops set com.digitalturbine.* BLUETOOTH_CONNECT ignore
```

#### 3. Network Segmentation
- Use a trusted, user-installed VPN with "Always-On" and "Block connections without VPN" enabled to counter `CONTROL_VPN` abuse

#### 4. Hardware Replacement
- For high-security needs, avoid Unisoc T606/T616 devices until a hardware revision is released

### 5.3 Call to Action for Motorola/Unisoc

- **Immediate Patch:** Release a security update addressing CVE-2025-31718 and F2FS flaws for Moto G04s
- **Transparency:** Publish a clear list of pre-installed system apps and their data collection practices
- **Bootloader Unlock:** Provide an official, secure method to unlock bootloaders for security researchers, currently blocked by BootROM exploit risk

## 6. References & IOCs

### CVE References
- **CVE-2022-38694:** Unisoc BootROM Arbitrary Write, NCC Group
- **CVE-2025-31718:** Unisoc Modem Improper Input Validation, Unisoc Bulletin
- **CVE-2024-43859:** Linux Kernel F2FS Privilege Escalation

### Affected Packages
- `com.digitalturbine.appcloud`
- `com.inmobi.analytics`
- `com.motorola.frameworks.core.addon`

### Log Indicators
- Look for `f2fs_gc`, `cmd_start`, `sprd_camera`, `tcpm` errors in `dmesg` / `logcat`

---

## Investigation Summary

This report highlights a systemic issue in budget Android devices sold in LATAM. The combination of hardware-level vulnerabilities (unpatchable) and software-level abuse (system apps) creates a "perfect storm" for privacy violations. Submitting this to Rapid7 and Attacker KB will help flag these devices as high-risk for enterprise and personal use.

**Investigation Date:** 2026-06-28  
**Device:** lexs201992-gif/motorola-g04s-t606-spreadtrum
