% Policy Advisory: APKs preinstaladas con privilegios en firmware de consumo
% Alex de la cruz — lexs201992@gmail.com
% 2026-06-28

# Asesoría de política para autoridades mexicanas

**Para:** IFT, PROFECO, CERT‑MX (equipos técnicos y de política)  
**De:** Alex de la cruz (investigador) — lexs201992@gmail.com  
**Repositorio técnico:** https://github.com/lexs201992-gif/motorola-g04s-t606-spreadtrum

---

## Resumen ejecutivo

Investigación independiente detectó múltiples APKs preinstaladas con permisos privilegiados en firmware de Motorola Moto G04s (Unisoc T606). Estas aplicaciones pueden recopilar telemetría, acceder a capacidades sensibles o habilitar instalaciones silenciosas sin consentimiento claro del usuario. Se recomienda acción regulatoria coordinada y mitigación inmediata.

---

## Evidencia y alcance (resumen)

- Paquetes de interés (ejemplos, hashes en el repo): com.dti.amx, com.spreadtrum.ims, com.spreadtrum.sgps, com.inmobi.installer, com.motorola.bach.modemstats.  
- Artefactos disponibles: extractos de manifiesto, metadatos de certificados, reglas YARA y IOCs de red.  
- Riesgo: recolección/exfiltración de datos personales, control privilegiado sobre funciones de red/llamadas, mecanismos de activación ocultos.

---

## Riesgos para consumidores

1. Telemetría y exfiltración silenciosa de ubicación y otros datos.  
2. Persistencia / actualizaciones silenciosas via instaladores privilegiados.  
3. Activaciones encubiertas mediante secret codes o componentes exportados.  
4. Potencial afectación a gran escala según la distribución del dispositivo.

---

## Acciones recomendadas (resumidas)

### Inmediatas (0–7 días)
- Solicitar acuse de proveedores y aceptar artefactos por canal seguro (PGP/SFTP).  
- Cert‑MX realiza triage técnico con YARA/hashes.  
- Evaluar bloqueo temporal de dominios IOC y preparar aviso breve al consumidor si procede.

### Corto plazo (7–30 días)
- Exigir plan de remediación y BOM de firmware a proveedores.  
- Coordinar verificación independiente.  
- Acordar cronograma de divulgación coordinada.

### Largo plazo (política)
- Requerir BOMs públicos por firmware.  
- Auditoría/certificación de componentes preinstalados privilegiados.  
- Mandatar escaneo de firmware en la cadena de suministro.  
- Facilitar controles al consumidor y SLAs de reporte de incidentes.

---

## Manejo seguro de artefactos

- Aceptar solo PGP‑encriptado o SFTP gestionado por CSIRT.  
- Requerir SHA256, contexto redactado y reglas YARA con pasos reproducibles.  
- Documentar y mantener cadena de custodia.

---

## Plantilla breve de aviso al consumidor (ejemplo)

**Título:** Aviso: revise apps preinstaladas en Moto G04s  
**Cuerpo:** Se recomienda respaldar datos, evitar instalar apps fuera de tiendas oficiales y contactar soporte del fabricante o PROFECO para orientación. Evite compartir APKs públicamente.

---

## Consideraciones legales

- Revisar obligaciones bajo LFPDPPP y posibles obligaciones de notificación.  
- Consultar asesoría legal antes de publicar artefactos que puedan implicar datos personales.  
- Mantener investigaciones en dispositivos obtenidos legalmente.

---

## Cronograma sugerido

- 0–7 días: validación y acuse.  
- 7–30 días: análisis y plan de remediación.  
- 30–90 días: implementación y aviso coordinado.  
- >90 días: evaluación de acciones regulatorias adicionales.

---

## Contacto y siguientes pasos

- Alex de la cruz — lexs201992@gmail.com (disponible para transferencia segura de artefactos y coordinación técnica).  
- Repositorio técnico: https://github.com/lexs201992-gif/motorola-g04s-t606-spreadtrum

---

If you want to produce a PDF from this file use pandoc:

pandoc REPORTS/POLICY_ADVISORY_MX_PDF.md -o Policy_Advisory_MX.pdf --pdf-engine=xelatex -V geometry:margin=1in
