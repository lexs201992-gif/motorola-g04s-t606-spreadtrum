rule Unisoc_IMS_Attack_Vector_Smali {
    meta:
        description = "Detects the IMS/RIL attack vector in Smali code regardless of APK obfuscation"
        author = "lexs201992-gif"
        date = "2026-07-16"
        severity = "CRITICAL"
        reference = "Addendum 82-F / VirusTotal Analysis"
        technique = "Smali Pattern Matching - Logic Based Detection"
        note = "Diseñada para detectar la lógica del ataque en código Smali dentro de APKs ofuscados. No depende de hashes ni nombres de archivos."
    
    strings:
        // 1. Identificadores de Paquete y Clase (Cadenas fijas, más fiables que regex)
        $pkg_spreadtrum = "com/spreadtrum/ims" ascii wide
        $pkg_unisoc = "com/unisoc/ims" ascii wide
        
        // 2. Instrucciones Smali Críticas (Cadenas fijas para evitar bugs de regex+wide)
        // Buscamos las partes por separado para mayor flexibilidad
        $smali_invoke = "invoke-virtual" ascii wide
        $smali_new = "new-instance" ascii wide
        $ril_request = "RILRequest" ascii wide
        
        // 3. Cadenas de Método y Lógica de Negocio (Las que NO se pueden ofuscar)
        $ril_method = "sendRILRequest" ascii wide
        $ims_stack_err = "ims.stack" ascii wide
        $ril_exception = "RILCommandException" ascii wide
        
        // 4. Patrones Hexadecimales de OpCodes Dalvik (Corregido con saltos variables)
        // invoke-virtual (0x6E) seguido de cualquier cosa [0-20 bytes] y luego otro invoke (0x71 o 0x6E)
        $dalvik_invoke_seq = { 6E ?? ?? ?? ?? ?? [0-20] (71 | 6E) }
        
        // 5. Ruta interna específica (Alta confianza)
        $smali_path = "Lcom/spreadtrum/ims/RILRequest;" ascii wide

    condition:
        // Lógica de Detección del Vector:
        
        // Opción A: Detecta la ruta de la clase específica (Alta confianza, casi cero falsos positivos)
        $smali_path
        
        // Opción B: Detecta contexto de paquete + invocación de método RIL (Resistente a ofuscación)
        or 
        ( ($pkg_spreadtrum or $pkg_unisoc) and ($smali_invoke or $smali_new) and $ril_request )
        
        // Opción C: Detecta la lógica pura (método + error) si el paquete está ofuscado
        or
        ( $ril_method and $ims_stack_err )
        
        // Opción D: Secuencia de opcodes sospechosa (Nivel binario)
        or
        ( $dalvik_invoke_seq and ($ril_request or $ril_method) )
}   
