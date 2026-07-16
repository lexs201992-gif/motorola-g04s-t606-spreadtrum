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
        // 1. Identificadores de Paquete y Clase (Aunque el paquete esté ofuscado, las referencias internas suelen mantener estructura o strings críticas)
        // Buscamos referencias a la lógica IMS/Spreadtrum incluso si la clase se llama 'a.b.c'
        $pkg_spreadtrum = "com/spreadtrum/ims" ascii wide
        $pkg_unisoc = "com/unisoc/ims" ascii wide
        
        // 2. Instrucciones Smali Críticas para el Vector RIL (Radio Interface Layer)
        // El vector de ataque suele involucrar invocaciones específicas a métodos RIL
        $smali_invoke_ril = "invoke-virtual.*RILRequest" ascii wide
        $smali_new_ril = "new-instance.*RILRequest" ascii wide
        
        // 3. Cadenas de Método y Lógica de Negocio (Lo que NO se puede ofuscar fácilmente sin romper la app)
        // Los nombres de métodos nativos o strings de error suelen permanecer
        $ril_method = "sendRILRequest" ascii wide
        $ims_stack_err = "ims.stack" ascii wide
        $ril_exception = "RILCommandException" ascii wide
        
        // 4. Patrones Hexadecimales de OpCodes Dalvik (Nivel más bajo, difícil de ofuscar)
        // invoke-virtual (0x6E) o invoke-static (0x71) seguidos de patrones típicos de llamada a método
        $dalvik_invoke = { 6E ?? ?? ?? ?? ?? 71 } // Patrón genérico de invocación
        
        // 5. Ruta interna específica (Si el atacante no ofusca la estructura de directorios del Smali)
        $smali_path = "Lcom/spreadtrum/ims/RILRequest;" ascii

    condition:
        // Lógica de Detección del Vector:
        // Opción A: Detecta la ruta de la clase específica (Alta confianza)
        $smali_path
        
        // Opción B: Detecta la combinación de contexto de paquete + invocación de método RIL (Resistente a ofuscación de nombres de clase)
        or 
        ( ($pkg_spreadtrum or $pkg_unisoc) and ($smali_invoke_ril or $smali_new_ril or $ril_method) )
        
        // Opción C: Detecta la lógica pura si el paquete está totalmente ofuscado pero las llamadas al sistema RIL permanecen
        or
        ( $ril_method and $ims_stack_err )
}   
