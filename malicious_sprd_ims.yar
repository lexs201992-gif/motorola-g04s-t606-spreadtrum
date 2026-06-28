rule spreadtrum_ims_suspicious {
    meta:
        description = "Unisoc IMS module (com.spreadtrum.ims) - SHA256 match"
        author = "lexs201992"
        date = "2026-06-28"
    strings:
        $sha256 = "1b938cb3920d601a38e4d80e88c87aaacc56abfa6464f3054de2430172c6f519" ascii
        $pkg = "com.spreadtrum.ims" ascii
        $sprd = "sprd" ascii
    condition:
        any of ($sha256) or (all of ($pkg, $sprd))
}
