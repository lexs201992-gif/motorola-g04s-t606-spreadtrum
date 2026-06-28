# Detection Commands

The following ADB commands can be used to disable suspicious packages that may be related to backdoors or malware:

```bash
pm disable-user com.spreadtrum.ims
pm disable-user com.guanhong.guanhongpcb
pm disable-user com.dti.amx
pm disable-user --user 0 com.android.ims
```

## Package Details

| Package | Type | Notes |
|---------|------|-------|
| `com.spreadtrum.ims` | Spreadtrum IMS | Suspicious Spreadtrum-related service |
| `com.guanhong.guanhongpcb` | Guanhong PCB | Potentially malicious application |
| `com.dti.amx` | DTI AMX | Unknown/suspicious package |
| `com.android.ims` | Android IMS | System IMS package (user 0) |

## Usage

To run these commands on your device:

1. Enable USB Debugging on your Android device
2. Connect to ADB (Android Debug Bridge)
3. Run each command:

```bash
adb shell pm disable-user com.spreadtrum.ims
adb shell pm disable-user com.guanhong.guanhongpcb
adb shell pm disable-user com.dti.amx
adb shell pm disable-user --user 0 com.android.ims
```

## Notes

- These commands disable packages for the current user without uninstalling them
- Some packages may be system apps and require device admin privileges
- Use with caution as disabling system packages may affect device functionality

---

## YARA Detection Rule

### Unisoc Camera Exfiltration Detection

```yara
rule Unisoc_Camera_Exfiltration_SPv1 {
  meta:
    description = "Detects SPRD ISP tags + privileged InMobi access"
  strings:
    $s1 = "ISSFrame.h"
    $s2 = "ai_scene_enabled"
    $s3 = "privapp-permissions-platform-inmobi.xml"
    $p1 = "/data/jenkins/workspace/Build-LXF_M173_U_MP_SMR"
  condition:
    2 of ($s*) and $p1
}
```

### Detection Details

| Indicator | Type | Description |
|-----------|------|-------------|
| `ISSFrame.h` | String | SPRD ISP (Image Signal Processor) header file |
| `ai_scene_enabled` | String | AI scene detection feature indicator |
| `privapp-permissions-platform-inmobi.xml` | String | Privileged InMobi permissions configuration |
| `/data/jenkins/workspace/Build-LXF_M173_U_MP_SMR` | Path | Jenkins build path - build artifact indicator |

### How to Use

Use this YARA rule to scan APK files or firmware for indicators of camera exfiltration capabilities:

```bash
yara Unisoc_Camera_Exfiltration_SPv1.yar <target_file>
```

### Rule Logic

- Requires at least 2 of the 3 string indicators ($s1, $s2, $s3)
- AND must contain the Jenkins build path ($p1)
- This combination indicates potential Unisoc/Spreadtrum camera exfiltration backdoor
