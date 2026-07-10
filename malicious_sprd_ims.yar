rule Unisoc_IMS_Internal_Components {
    meta:
        description = "Detects internal components of compromised com.spreadtrum.ims APK"
        author = "lexs201992-gif"
        date = "2026-07-10"
        severity = "CRITICAL"
        reference = "Addendum 82-F / VirusTotal Analysis"
    
    strings:
        // Hash del código ejecutable (Dex)
        $dex_hash = "0b84aa8467bf89ef07bb46f4b4fb4cbbe77414ce9a829e26b75a63e04b05b3d5" ascii
        
        // Hash del Manifiesto (Permisos y configuración)
        $manifest_hash = "0ff6999e93126d20b5f60ec590bcb710b2363443be77f237041a93563e18912d" ascii
        
        // Hash del archivo RIL específico de Spreadtrum
        $ril_request_hash = "774ff07970c3c889fead83f6d9c28a52ced1089c2535cd19553378f207f963ff" ascii
        
        // Hash del Certificado RSA (Para correlación con Longcheer)
        $cert_rsa_hash = "d3eab3dffd411055d0a8c289f986e0580f8dd51ae1f6bef1c4c50e2e8109a65c" ascii
        
        // Ruta del archivo propietario
        $ril_path = "com/spreadtrum/ims/RILRequest.uau" ascii

    condition:
        // Detecta si cualquiera de los componentes internos coincide
        any of ($dex_hash, $manifest_hash, $ril_request_hash, $cert_rsa_hash, $ril_path)
}   
