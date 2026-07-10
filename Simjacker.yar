rule Unisoc_Longcheer_STK_SHA256 {
    meta:
        description = "Identifies the compromised Longcheer SIM Toolkit binary by exact SHA256"
        author = "lexs201992-gif"
        date = "2026-07-10"
        severity = "CRITICAL"
        sha256 = "4cfe803b578fd6958d236e494248585eccbc5c33a5113bda7ff1a47351e4118d"
        package = "com.android.stk"
        reference = "Addendum 82-C"
    
    strings:
        $sha256_hex = "4cfe803b578fd6958d236e494248585eccbc5c33a5113bda7ff1a47351e4118d" ascii
        $pkg_name = "com.android.stk" ascii
        $stk_class = "Lcom/android/stk/StkAppService;" ascii
        $longcheer_cert = "CN=Longcheer" ascii
        
    condition:
        $sha256_hex in file or 
        (all of ($pkg_name, $stk_class, $longcheer_cert))
}

rule Unisoc_STK_Intent_Injection_Vulnerability {
    meta:
        description = "Detects vulnerable StkCmdReceiver implementation allowing intent injection"
        author = "lexs201992-gif"
        date = "2026-07-10"
        severity = "HIGH"
        cve = "CVE-2015-3843-Variant"
    
    strings:
        $receiver_class = "Lcom/android/stk/StkCmdReceiver;" ascii
        $intent_action = "com.android.internal.stk.command" ascii
        $handle_action = "handleAction" ascii
        $on_receive = "onReceive" ascii
        $exported_true = "exported=\"true\"" ascii wide
        $permission_none = "android:permission=\"\"" ascii wide
        
    condition:
        (all of ($receiver_class, $intent_action, $handle_action)) and
        ($exported_true in file or $permission_none in file)
}

rule Unisoc_STK_UI_Spoofing_Capability {
    meta:
        description = "Identifies STK components capable of UI spoofing and overlay attacks"
        author = "lexs201992-gif"
        date = "2026-07-10"
        severity = "MEDIUM"
        attack_type = "Social Engineering"
    
    strings:
        $dialog_activity = "Lcom/android/stk/StkDialogActivity;" ascii
        $translucent_theme = "Theme.Translucent.NoTitleBar" ascii
        $exclude_recents = "excludeFromRecents=\"true\"" ascii wide
        $text_message = "Lcom/android/internal/telephony/cat/TextMessage;" ascii
        $send_response = "sendResponse" ascii
        
    condition:
        (all of ($dialog_activity, $translucent_theme, $exclude_recents)) and
        (any of ($text_message, $send_response))
}

rule Unisoc_STK_Persistence_Mechanism {
    meta:
        description = "Detects boot persistence receivers in compromised STK"
        author = "lexs201992-gif"
        date = "2026-07-10"
        severity = "HIGH"
        persistence = "Boot Completed"
    
    strings:
        $boot_receiver = "Lcom/android/stk/BootCompletedReceiver;" ascii
        $boot_action = "android.intent.action.BOOT_COMPLETED" ascii
        $sim_change = "android.telephony.action.SIM_CARD_STATE_CHANGED" ascii
        $start_service = "startServiceByBootCompleted" ascii
        
    condition:
        (all of ($boot_receiver, $boot_action, $sim_change)) and
        ($start_service in file)
}
