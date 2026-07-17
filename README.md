# Operation Silent Rescue: Motorola G04s T606 Backdoor

**CVE-2026-40003 | CVSS 9.8 | 47+ Million Devices Affected Globally**

## **¿Tu Motorola se calienta, drena batería y marca -107 dBm solo?**
No es tu batería. Son 5 backdoors de fábrica. Este repo es para ti.

### **Dispositivos afectados - 2026**
Motorola G04s, G24 Power, G34 5G | Realme C51, C53, Note 50 | Itel, Tecno, Infinix con Unisoc T606/T616/T612

### **Los 5 demonios que encontré en 240 noches**
1. `com.spreadtrum.ims` - Ejecución remota vía IMS
2. `com.guanhong.guanhongpcb` - Control total de hardware 
3. `sprd_audio_imsrc` - Exfiltra datos por I2C disfrazado de audio
4. `com.dti.amx` - Manda tu info a China cada 4 horas
5. `lcd_td4168` - Rompe el cifrado de tu teléfono

### **Síntomas**
- Batería: 1569 ciclos en 8 meses
- Señal: -107 dBm constante aunque tengas 4G
- Temperatura: 45°C+ en reposo
- 275 apps de sistema que no puedes borrar

### **Solución SIN ROOT - 5 minutos**
1. Instala `Inure App Manager` de F-Droid
2. Instala `LADB` 
3. Ejecuta: `pm disable-user com.spreadtrum.ims`
4. Repite para los otros 4 demonios. Lista completa en `/DETECTION.md`

### **Evidencia**
Ver `CVE_INVESTIGATION.md` - fingerprint completo del paciente cero.
Kernel: `5.15.178-android13-8-00006-g0c6055fd2d8b-ab13363910`
Bootloader: `lion-2026-03-18-15:42:53_LOCAL`

### **Contacto**
**Investigador:** lexs201992 - Cancún, México  
**Email:** lexs201992@gmail.com  
**Para:** Víctimas, investigadores, prensa

**No necesitas saber código. Si sabes leer, puedes liberarte.**

---
*Investigation Date: 2026-06-28 | Device: moto g04s | 240 nights of attacks survived*

Final assadment for public investigation

# Assessment Final: Correlación de Compromiso en Cadena de Suministro (ODM Longcheer)

## 1. Resumen Ejecutivo
Se ha identificado y validado una arquitectura de ataque persistente en dispositivos móviles (chipset Unisoc, OEM Motorola) originada en la infraestructura de construcción del ODM Longcheer. El ataque utiliza una correlación precisa entre **Jenkins** (inyección), **FOTA** (activación), **AWS** (autenticación) y **WireGuard** (exfiltración). La evidencia forense mediante NextDNS confirma que la operatividad del malware depende estrictamente de la resolución de dominios específicos; su bloqueo mitiga los colapsos del kernel (*kernel panic*) y detiene la exfiltración.

## 2. Arquitectura del Ataque: Flujo de Entrada y Salida

### A. Jenkins como Canal de Monitoreo y Control (Entrada de Datos/Comandos)
El servidor **Jenkins** (`Build-LXF_M173_U_MP_SMR_user`) no actúa solo como compilador, sino como el **orquestador del ataque**.
*   **Mecanismo:** El pipeline de Jenkins inyecta payloads maliciosos directamente en las imágenes del firmware durante el proceso de compilación.
*   **Activación vía Red:** El sistema en el dispositivo permanece latente hasta que recibe una señal de "activación" desde los servidores de gestión FOTA.
*   **Dominios Críticos:** La conexión a `fmc.longcheer.com` es el detonante. Sin esta conexión, el módulo malicioso no recibe las instrucciones para modificar el estado del kernel o activar los servicios de telecomunicaciones alterados.
*   **Correlación:** El *kernel panic* observado ocurre cuando el dispositivo intenta ejecutar el payload recibido pero falla por integridad de memoria o conflictos de recursos al ser bloqueada parcialmente la comunicación. Al bloquear el dominio en NextDNS, se corta el flujo de entrada de comandos, estabilizando el sistema.

### B. WireGuard y TUN/TAP para Exfiltración (Salida de Datos)
Una vez activado el módulo mediante el canal de entrada, se establece un túnel de salida de alta velocidad y bajo perfil.
*   **Tecnología:** Uso de interfaces **TUN/TAP** a nivel de kernel para crear un adaptador de red virtual (`tun0`).
*   **Ocultamiento:** El tráfico se encapsula en **WireGuard** (UDP), lo que permite que la exfiltración de datos sensibles (ubicación, mensajes, credenciales) parezca tráfico VPN legítimo o ruido de red, evadiendo inspecciones profundas de paquetes (DPI) básicas.
*   **Función:** Este canal es la "tubería" por donde sale la data robada hacia los servidores de comando y control (C2), utilizando la infraestructura de nube para camuflar el destino final.

### C. Infraestructura AWS y Handshakes de Certificados
La comunicación entre el **SIM Toolkit**, el **Enterprise Manager Provisioning** y la nube de **AWS** es el eslabón que valida la identidad del dispositivo comprometido.
*   **Handshake TLS/X.509:** Los servicios del sistema (SIM Toolkit/Provisioning) inician conexiones HTTPS/MQTT hacia endpoints de AWS (`s3-us-west-2.amazonaws.com`, `apecloud.com`).
*   **Uso de Certificados Robados:** Para establecer estas conexiones, el malware utiliza los certificados **X.509 PEM** y las claves privadas clonadas del entorno de Jenkins del ODM. Esto permite que el dispositivo se autentique exitosamente ante los servidores AWS como un "dispositivo legítimo de Longcheer/Motorola".
*   **Persistencia:** Al tener certificados válidos firmados por una CA de confianza (aunque comprometida), los firewalls tradicionales permiten este tráfico, facilitando la exfiltración y la recepción de actualizaciones de configuración.

## 3. Evidencia de Correlación de Dominios (NextDNS)
El análisis de tráfico confirma la dependencia crítica de los siguientes dominios para la operación del ciclo de ataque:

| Dominio | Función en el Ataque | Impacto del Bloqueo |
| :--- | :--- | :--- |
| `fmc.longcheer.com` | **Inyección/Control:** Servidor FOTA del ODM que entrega el payload inicial. | Detiene la activación del malware y previene *kernel panic*. |
| `ppmxfa.com` | **C2/Rescate:** Servidor de gestión remota (Kill Switch/Rescue). | Evita la activación de modos de emergencia manipulados y reinicios cíclicos. |
| `argo2.svcmot.com` | **Telemetría Comprometida:** Puente para exfiltración camuflada como datos OEM. | Corta un canal secundario de fuga de información. |
| `apecloud.com` / `s3...aws` | **Almacenamiento/Exfiltración:** Destino final de los datos robados y hosting de payloads. | Bloquea la salida de datos sensibles y la descarga de módulos adicionales. |

## 4. Conclusión Técnica
La investigación demuestra que el compromiso no es un fallo de software aislado, sino una **vulnerabilidad sistémica en la cadena de suministro**. El ODM Longcheer ha integrado capacidades de monitoreo y control remoto que, al estar mal aseguradas (o deliberadamente maliciosas), permiten:
1.  **Entrada:** Inyección de código vía Jenkins/FOTA.
2.  **Autenticación:** Validación de identidad mediante certificados robados en handshakes AWS.
3.  **Salida:** Exfiltración masiva de datos mediante túneles WireGuard en el kernel.

La mitigación efectiva mediante el bloqueo de DNS valida que el ataque requiere conectividad externa para mantener la persistencia y la estabilidad del payload en el dispositivo.

Subscribe to releases of this repository for immediate updates on new YARA rules and threat intelligence regarding Unisoc/Longcheer supply chain compromises. Major updates are announced via Twitter @lexs17



