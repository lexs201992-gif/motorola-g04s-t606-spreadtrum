rule malicious_inmobi_installer {
    meta:
        description = "InMobi installer APK (com.inmobi.installer) - SHA256 match + manifest/cert fallback"
        author = "lexs201992"
        date = "2026-06-28"
    strings:
        $sha256 = "1fe9c2c2e4b390f01d2bb7d90b5d219dbe85fdd42321f247a295d532c9b387d2" ascii
        $pkg    = "com.inmobi.installer" ascii
        $issuer_cn = "CN=Swish" ascii
        $inmobi = "inmobi" nocase
    condition:
        any of ($sha256) or (all of ($pkg, $inmobi)) or any of ($issuer_cn)
}
