rule spreadtrum_sgps_suspicious {
    meta:
        description = "Spreadtrum SGPS component (com.spreadtrum.sgps) - SHA256 match"
        author = "lexs201992"
        date = "2026-06-28"
    strings:
        $sha256 = "4cfe803b578fd6958d236e494248585eccbc5c33a5113bda7ff1a47351e4118d" ascii
        $pkg    = "com.spreadtrum.sgps" ascii
        $gpsstr = "sgps" ascii
    condition:
        any of ($sha256) or (all of ($pkg, $gpsstr))
}
