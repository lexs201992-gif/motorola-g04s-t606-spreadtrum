rule Unisoc_Motorola_AWS_C2_Traffic {
    meta:
        description = "Detects suspicious HTTPS traffic to Motorola sandclowd.com associated with OMA CP exploits"
        author = "lexs201992-gif"
        date = "2026-07-10"
        severity = "CRITICAL"
        network_indicator = "notification.sandclowd.com"
        reference = "Addendum 82-B"
    
    strings:
        $domain_sandclowd = "notification.sandclowd.com" ascii
        $domain_metrics = "metrics-server.sandclowd.com" ascii
        $aws_cert_issuer = "Amazon RSA 2048" ascii
        $moto_package = "com.motorola.enterprise.adapter.service" ascii
        $http_post = "POST /notification" ascii
        $http_post_metrics = "POST /metrics" ascii
        $wap_push_trigger = "WAP Push" ascii
        
    condition:
        (any of ($domain_sandclowd, $domain_metrics)) and 
        ($aws_cert_issuer in file) and
        (any of ($http_post, $http_post_metrics)) and
        ($moto_package in file)
}

rule Unisoc_Omacp_To_Motorola_Bridge {
    meta:
        description = "Detects interaction between Unisoc OMA CP and Motorola Enterprise Service"
        author = "lexs201992-gif"
        date = "2026-07-10"
        severity = "HIGH"
        type = "Behavioral"
    
    strings:
        $unisoc_receiver = "com.sprd.omacp.transaction.OtaOmaReceiver" ascii
        $moto_adapter = "com.motorola.enterprise.adapter.service" ascii
        $intent_ota = "com.motorola.ccc.ota.UPGRADE_ASC_UPDATE_REQUEST" ascii
        $permission_asc = "com.motorola.enterprise.asc.permission.INTERACT_ASC_SERVICE" ascii
        $fcm_event = "com.google.firebase.MESSAGING_EVENT" ascii
        
    condition:
        ($unisoc_receiver in file) and 
        ($moto_adapter in file) and
        (any of ($intent_ota, $permission_asc, $fcm_event))
}
