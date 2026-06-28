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
