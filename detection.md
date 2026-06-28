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
