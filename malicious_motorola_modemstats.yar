rule malicious_motorola_modemstats {
    meta:
        description = "Motorola modemstats APK (com.motorola.bach.modemstats) - SHA256 + manifest/cert fallback"
        author = "lexs201992"
        date = "2026-06-28"
    strings:
        $sha256 = "4cfe803b578fd6958d236e494248585eccbc5c33a5113bda7ff1a47351e4118d" ascii
        $pkg    = "com.motorola.bach.modemstats" ascii
        $issuer = "CN=Longcheer" ascii
        $longcheer = "longcheer" nocase
    condition:
        any of ($sha256) or (all of ($pkg, $longcheer)) or any of ($issuer)
}
