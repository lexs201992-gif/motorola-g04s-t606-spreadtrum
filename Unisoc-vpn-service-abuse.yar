rule Unisoc_Longcheer_VPN_Service_Abuse {
    meta:
        description = "Detects Privileged Apps abusing BIND_VPN_SERVICE to establish covert WireGuard/System tunnels"
        author = "lexs201992-gif"
        date = "2026-07-16"
        severity = "CRITICAL"
        reference = "Addendum 82-F / VPN Service Hijack Vector"
        technique = "Detection of VpnService.Builder and WireGuard initialization in Privileged Context"
    
    strings:
        // 1. Llamadas críticas a la API de VPN de Android (No ofuscables funcionalmente)
        $vpn_service_builder = "Landroid/net/VpnService$Builder;" ascii wide
        $vpn_add_route = "addRoute" ascii wide
        $vpn_add_dns = "addDnsServer" ascii wide
        $vpn_establish = "establish" ascii wide
        
        // 2. Cadenas específicas de WireGuard o Túneles (Incluso si la librería es nativa, la carga se referencia)
        $wg_interface = "wg0" ascii wide
        $wg_config = "[Interface]" ascii wide
        $wg_private_key = "PrivateKey" ascii wide
        $tunnel_svc = "TunnelService" ascii wide
        
        // 3. Invocaciones de permisos privilegiados (El "gatillo" del abuso)
        $bind_vpn_perm = "android.permission.BIND_VPN_SERVICE" ascii wide
        $network_stack = "Landroid/net/ConnectivityManager;" ascii wide
        $set_global_proxy = "setGlobalProxy" ascii wide
        
        // 4. Patrones Hex de invocación (OpCodes Dalvik para llamadas a métodos VPN)
        // invoke-virtual {v0}, Landroid/net/VpnService$Builder;->establish()
        $dalvik_vpn_establish = { 6E ?? ?? ?? ?? ?? } "establish" ascii wide

    condition:
        // Lógica de Detección:
        // Debe construir una VPN (Builder) Y establecerla (establish) O configurar rutas DNS
        ( $vpn_service_builder and $vpn_establish )
        
        // O debe tener el permiso Y configurar servidores DNS/Rutas (Típico de túneles C2)
        or ( $bind_vpn_perm and ( $vpn_add_dns or $vpn_add_route ) )
        
        // O referencia directa a configuración WireGuard en una App de Sistema
        or ( $wg_config and $wg_private_key )
}
