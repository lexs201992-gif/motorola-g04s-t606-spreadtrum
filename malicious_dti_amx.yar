rule malicious_dti_amx {
    meta:
        description = "Digital Turbine suspicious APK (com.dti.amx) - SHA256 match"
        author = "lexs201992"
        date = "2026-06-28"
    strings:
        $sha256 = "7902116480673e44239c5a310bb5feed257692eacca25a1284a9fa613a8ebd20" ascii
        // Secondary checks (package name and likely strings) to reduce false negatives:
        $pkg_name = "com.dti.amx" ascii
        $inmobi = "inmobi" ascii
    condition:
        // Match either the exact SHA when present in metadata or the package name + a suspect string
        any of ($sha256) or (all of ($pkg_name, $inmobi))
}
