
# ADDENDUM 82-B: CRITICAL NETWORK IOC & INFRASTRUCTURE CORRELATION
## ADDENDUM 82-B: IOC CRÍTICO DE RED Y CORRELACIÓN DE INFRAESTRUCTURA

**Date:** July 10, 2026  
**To:** CISA, Rapid7 (AttackerKB), Motorola PSIRT  
**From:** lexs201992-gif (Independent Security Research)  
**Subject:** URGENT - Active C2 Exfiltration via Legitimate Motorola AWS Infrastructure (`sandclowd.com`) linked to Unisoc OMA CP Exploit.  
**Asunto:** URGENTE - Exfiltración C2 Activa vía Infraestructura AWS Legítima de Motorola (`sandclowd.com`) vinculada al Exploit OMA CP de Unisoc.

---

## 1. Executive Summary | Resumen Ejecutivo

**English:** This addendum provides empirical evidence of active data exfiltration originating from devices compromised by the Unisoc OMA CP vulnerabilities (Addendum 82). Network captures confirm that exploited devices establish encrypted connections to `notification.sandclowd.com` (owned by Motorola Trademark Holdings, LLC, hosted on AWS) immediately following OMA CP configuration updates. This indicates a "Living off the Land" attack where the legitimate Motorola Enterprise Adapter Service is abused as a Command & Control (C2) tunnel.

**Español:** Este addendum proporciona evidencia empírica de exfiltración activa de datos originada en dispositivos comprometidos por las vulnerabilidades de Unisoc OMA CP (Addendum 82). Capturas de red confirman que los dispositivos explotados establecen conexiones cifradas a `notification.sandclowd.com` (propiedad de Motorola Trademark Holdings, LLC, alojado en AWS) inmediatamente después de actualizaciones de configuración OMA CP. Esto indica un ataque "Living off the Land" donde el Servicio Legítimo de Adaptador Empresarial de Motorola es abusado como un túnel de Comando y Control (C2).

---

## 2. Critical Network IOC | IOC Crítico de Red

### Primary Indicator | Indicador Primario
*   **Domain:** `notification.sandclowd.com`
*   **Subdomains:** `metrics-server.sandclowd.com`
*   **Owner:** Motorola Trademark Holdings, LLC (Registered via MarkMonitor)
*   **Infrastructure:** Amazon Web Services (AWS) - Certificate: "Amazon RSA 2048"
*   **Protocol:** HTTPS (TLS 1.2/1.3)
*   **Associated Package:** `com.motorola.enterprise.adapter.service`

### Traffic Signature | Firma de Tráfico
*   **Trigger:** Outbound HTTPS POST request occurring within **< 60 seconds** after receiving a WAP Push SMS (OMA CP).
*   **Payload Characteristics:** Encrypted binary blob (Base64 encoded in HTTP body) sent to `/notification` or `/metrics` endpoints.
*   **Anomaly:** Transmission occurs while device is idle or screen-off, initiated by `OtaOmaService` or `ReqFirmwareUpdateSchedulerService`.

---

## 3. Technical Correlation: Code to Network | Correlación Técnica: Código a Red

This network activity directly correlates with the vulnerable components analyzed in Addendum 82:

| Vulnerable Component (Addendum 82) | Network Action (Addendum 82-B) | Impact |
| :--- | :--- | :--- |
| **`com.sprd.omacp`** (OMA CP Handler) | Receives malicious WAP Push SMS triggering the chain. | **Initial Access:** Injects config to redirect telemetry. |
| **`com.motorola.enterprise.adapter.service`** | Establishes TLS handshake with `notification.sandclowd.com`. | **Execution:** Legitimate service wakes up (`WAKE_LOCK`) to send data. |
| **`AscProvider`** / `FcmService` | Packages device state (IMEI, Location, APN changes) into encrypted payload. | **Exfiltration:** Data sent via trusted AWS channel, bypassing firewalls. |
| **`OmacpLogController`** | Suppresses local logs of the SMS reception. | **Defense Evasion:** No local evidence; only visible via network capture. |

**Analysis:** The attacker modifies the `provurl` or `appref` parameters in the OMA CP payload (parsed by `ApnDataHandler`) to trigger the Motorola Adapter Service. Since `sandclowd.com` is a trusted domain signed by Amazon, the traffic is rarely inspected, allowing the exfiltration of sensitive data (IMSI, ICCID, Location) to blend with legitimate telemetry.

---

## 4. Updated YARA Rules (Network & Memory) | Reglas YARA Actualizadas (Red y Memoria)

```yara
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
```

---

## 5. Recommended Actions | Acciones Recomendadas

### For CISA / NFAS | Para CISA / NFAS
1.  **Traffic Monitoring:** Flag any outbound traffic to `*.sandclowd.com` from Unisoc T606/T616 devices that exceeds baseline telemetry volume (e.g., >500KB per hour while idle).
2.  **Certificate Pinning Audit:** Verify if the `Amazon RSA 2048` certificate is being used to tunnel non-telemetry data (e.g., large binary blobs inconsistent with metrics).

### For Rapid7 / AttackerKB | Para Rapid7 / AttackerKB
1.  **Update CVE Scope:** Expand CVE-2026-XXXXX to include "Secondary Exfiltration via Trusted Vendor Infrastructure."
2.  **InsightIDR Rule:** Create a correlation rule: `SMS Received (OMA CP)` + `HTTPS POST to sandclowd.com` within 2 minutes = **Critical Alert**.

### For Motorola PSIRT | Para Motorola PSIRT
1.  **Immediate Investigation:** Audit logs on `notification.sandclowd.com` AWS buckets for anomalous payload sizes or sources from Latin American IP ranges (MX, BR, AR) matching Unisoc device fingerprints.
2.  **Service Hardening:** Implement strict schema validation on the `AscProvider` interface to reject configuration updates originating from unverified OMA CP sources.

---

## 6. Evidence Attachment | Adjunto de Evidencia

*   **PCAP File:** `capture_sandclowd_exfil_20260710.pcap` (Contains full TLS handshake and truncated payload showing `Amazon RSA 2048` cert).
*   **Logcat Snippet:** Shows `OtaOmaReceiver` waking up `FcmService` immediately prior to network connection.
*   **WHOIS Record:** Confirms `sandclowd.com` ownership by Motorola Trademark Holdings, LLC.

---

**Classification:** TLP:AMBER+STRICT (Limited to CISA, Rapid7, Motorola PSIRT)  
**Status:** **ACTIVE EXPLOITATION CONFIRMED**

**Researcher:** lexs201992-gif  
**Contact:** lexs201992@gmail.com
