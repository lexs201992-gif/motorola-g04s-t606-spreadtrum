# Asesoría de política — APKs preinstaladas con privilegios en firmware de consumo

Propósito
- Proveer a reguladores, CSIRTs nacionales y equipos técnicos de política una guía concisa y lista de acciones operativas para el triage, coordinación y remediación de APKs preinstaladas con privilegios detectadas en firmware Android de consumo (caso: Motorola G04s / Unisoc T606).
- Ofrecer pasos de contención a corto plazo, orientación para coordinación con proveedores a mediano plazo y recomendaciones políticas a largo plazo.

Audiencia
- Equipos técnicos y regulatorios en IFT, PROFECO, CERT‑MX y agencias relacionadas; también útil para equipos de seguridad de proveedores y CSIRTs asociados.

Resumen ejecutivo
- Investigación independiente identificó múltiples paquetes Android preinstalados con permisos privilegiados en imágenes de firmware que podrían recopilar telemetría, acceder a capacidades sensibles (telefónica/ubicación/cámara) o ejecutar operaciones de instalación/actualización sin consentimiento claro del usuario. Estas conductas suponen riesgos de privacidad y protección al consumidor que requieren atención regulatoria inmediata y coordinación con los proveedores.

Antecedentes y evidencia
- Paquetes identificados (ejemplos, SHA256 en el repo): com.dti.amx, com.spreadtrum.ims, com.spreadtrum.sgps, com.inmobi.installer, com.motorola.bach.modemstats.
- Artefactos disponibles: extractos de manifiesto que muestran permisos privilegiados (INSTALL_PACKAGES, READ_PRIVILEGED_PHONE_STATE, ACCESS_FINE_LOCATION, MODIFY_PHONE_STATE), componentes exportados/receivers (incluyendo Telephony.SECRET_CODE), atributos de persistencia/proceso y metadatos de certificados.
- Recursos de detección (reglas YARA, pasos de verificación, IOCs de red) están publicados en el repositorio enlazado para que equipos técnicos y reguladores los revisen y validen.
- Indicadores de red observados incluyen endpoints MQTT y HTTPS correlacionados con telemetría/exfiltración (detalles en el repo).

Relevancia legal y política en México
- Privacidad: la posible recolección o exfiltración de datos personales (ubicación, identificadores de dispositivo, datos derivados de cámara/biométricos) puede implicar obligaciones bajo la Ley Federal de Protección de Datos Personales en Posesión de los Particulares (LFPDPPP).
- Telecomunicaciones y protección al consumidor: componentes que afectan funcionalidad telefónica o servicios pueden entrar en la competencia del IFT y en las obligaciones de protección al consumidor administradas por PROFECO, especialmente si reducen el control del usuario o implican recopilación no divulgada.
- Coordinación incidentes: CERT‑MX puede facilitar la recepción segura de artefactos, realizar triage técnico y coordinar la interacción con proveedores.

Riesgos inmediatos para usuarios en México
- Telemetría silenciosa o exfiltración de ubicación / datos sensibles.
- Instaladores privilegiados que permitan instalaciones silenciosas (riesgo de cadena de suministro).
- Mecanismos de activación ocultos (secret‑code receivers) que permitan activación encubierta.
- Alcance potencial amplio dada la distribución del dispositivo.

Acciones regulatorias recomendadas

Inmediatas (0–7 días)
1. Solicitar acuse y respuesta inicial de proveedores:
   - Pedir a OEMs y proveedores implicados (Motorola, Unisoc, InMobi, Longcheer u otros) que acusen recibo del informe técnico y entreguen medidas de mitigación iniciales.
2. Triage y contención:
   - Indicar a CERT‑MX que reciba artefactos por canal seguro (PGP/SFTP) y realice triage técnico inicial.
   - Valorar emitir un aviso de contención a ISPs/operadores críticos para bloquear opcionalmente dominios IOC mientras se investiga.
3. Aviso preventivo al consumidor (si procede):
   - Si el riesgo se confirma, emitir orientación breve para consumidores con pasos seguros (respaldo, cómo solicitar soporte del fabricante).

Corto plazo (7–30 días)
4. Plan de remediación del proveedor:
   - Exigir a proveedores un plan documentado de remediación y un BOM (bill‑of‑materials) de firmware para las versiones afectadas.
5. Verificación forense independiente:
   - Coordinar análisis técnico independiente (CERT‑MX o tercero acreditado) para confirmar flujos de telemetría y datos involucrados.
6. Coordinación de divulgación:
   - Establecer cronograma de divulgación coordinada; valorar asignación de CVE/MITRE/CERT‑CC si procede.

Largo plazo (política)
7. Transparencia de firmware y BOM:
   - Exigir publicación del BOM de firmware (apps preinstaladas, certificados de firma, lista de permisos) por cada build distribuido.
8. Certificación de componentes preinstalados:
   - Requerir auditoría de seguridad para componentes privilegiados preinstalados.
9. Escaneo obligatorio de la cadena de suministro:
   - Mandatar escaneo estático y de firmas (YARA, comprobaciones de firma) como parte de la aceptación de firmware para dispositivos vendidos en México.
10. Controles al consumidor y avisos:
    - Garantizar medios prácticos para que usuarios desactiven o desinstalen apps no esenciales y que reciban avisos de privacidad claros en el primer encendido.
11. SLAs de reporte de incidentes:
    - Definir plazos regulatorios para acuse y remediación por parte de proveedores.
12. Medidas de cumplimiento:
    - Establecer sanciones por envío de firmware con telemetría no divulgada o componentes privilegiados injustificados.

Manejo seguro de artefactos e ingreso (intake)
- Aceptar artefactos solo vía archivo PGP‑encriptado o SFTP gestionado por el CSIRT.
- Requerir del remitente:
  - SHA256 de cada artefacto.
  - Contexto mínimo y redactado (modelo, versión de firmware).
  - Reglas YARA y pasos de reproducción.
- Verificar integridad al recibir (checksums y firma PGP).
- Limitar distribución de binarios completos; usar manifiestos redactados y logs no sensibles para avisos públicos.
- Mantener cadena de custodia documentada.

Lista de verificación de triage técnico (para CSIRT)
- Confirmar SHA256 contra IOCs reportados.
- Ejecutar reglas YARA provistas contra firmware / APK.
- Inspeccionar manifiesto por permisos privilegiados, componentes exportados y secret‑code receivers.
- Capturar tráfico de red (pcap) en laboratorio aislado si se sospecha comportamiento dinámico.
- Extraer metadatos de certificados y calcular huellas (SHA256) para detección.
- Producir memo técnico conciso para reguladores y contactos del proveedor.

Plantilla breve de aviso al consumidor (ejemplo)
- Título: Aviso de seguridad — Revise apps preinstaladas en Moto G04s
- Cuerpo corto: Investigación independiente sugiere que ciertas versiones del Moto G04s pueden incluir apps preinstaladas con permisos privilegiados que podrían recopilar telemetría o actuar como instaladores. Recomendamos:
  1) Hacer copia de seguridad de datos importantes.
  2) Verificar con el fabricante o PROFECO si su dispositivo está afectado.
  3) Evitar instalar apps fuera de la tienda oficial hasta que el fabricante confirme.
- Nota: proporcionar instrucciones seguras no técnicas; evitar indicar procedimientos que requieran root.

Consideraciones legales y regulatorias
- Protección de datos: evaluar obligaciones bajo LFPDPPP respecto a tratamiento/exfiltración de datos personales.
- Protección al consumidor: valorar incumplimientos en obligaciones de información y consentimiento.
- Riesgo penal y privacidad: asegurar que la investigación se limite a dispositivos/artefactos legalmente obtenidos; solicitar asesoría legal antes de liberar datos sensibles.
- Revisar contratos o acuerdos de suministro que limiten divulgación.

Cronograma recomendado
- Día 0–7: Recepción y validación de artefactos; acuse del proveedor.
- Día 7–30: Análisis independiente y plan de remediación; emitir guía al consumidor si procede.
- Día 30–90: Implementación de remediación y aviso coordinado; auditoría independiente.
- >90 días: Acciones regulatorias o políticas adicionales si se detecta un patrón sistémico.

Contacto y vías seguras de transferencia
- Investigador: Alex de la cruz (lexs201992@gmail.com) — disponible para coordinación técnica y entrega segura de artefactos.
- Repo técnico y reglas YARA: https://github.com/lexs201992-gif/motorola-g04s-t606-spreadtrum
- Métodos de entrega sugeridos: archivo PGP‑encriptado a dirección gestionada por CERT‑MX o SFTP provisto por CERT‑MX.

Recomendaciones iniciales para reguladores
1. Aceptar la asesoría y establecer un canal seguro para recibir artefactos técnicos.  
2. Realizar triage con CERT‑MX usando reglas YARA y hashes provistos.  
3. Contactar proveedores relevantes para acuse y plan de remediación.  
4. Considerar la emisión de un aviso para consumidores si la evidencia confirma riesgo de privacidad.

Apéndice
- Enlaces a reglas YARA y al informe técnico consolidado en el repositorio.
- Contacto del investigador y propuestas de evaluadores técnicos.
