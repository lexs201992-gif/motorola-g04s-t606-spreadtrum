import "hash"

rule spreadtrum_sgps_suspicious {
    meta:
        description = "Spreadtrum SGPS component (com.spreadtrum.sgps) - SHA256 match OR String match"
        author = "lexs201992"
        date = "2026-06-28"
        hash_sha256 = "4cfe803b578fd6958d236e494248585eccbc5c33a5113bda7ff1a47351e4118d"
    
    strings:
        $pkg    = "com.spreadtrum.sgps" ascii wide
        $gpsstr = "sgps" ascii wide
    
    condition:
        // Coincidencia exacta por Hash
        hash.sha256(0, filesize) == "4cfe803b578fd6958d236e494248585eccbc5c33a5113bda7ff1a47351e4118d"
        or
        // Coincidencia heurística por cadenas (ambas deben estar presentes)
        all of ($pkg, $gpsstr)
}   
