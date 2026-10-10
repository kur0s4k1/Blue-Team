# Blue Team — Arsenal Defensivo & CTI

Portafolio defensivo con **herramientas de DFIR/Blue Team**. Cada entrada incluye telemetría real, indicadores de compromiso (IOCs), tradecraft del actor y **detecciones accionables** (Sigma, YARA, reglas de red/endpoint y mapeo MITRE ATT&CK).

El objetivo es cerrar la brecha entre la observación de un incidente y la defensa: lo que un analista puede instrumentar hoy mismo en su SOC, EDR o NDR.

---

## Estructura del repositorio

```text
Blue-Team/
├── tools/          # Herramientas operativas de defensa, respuesta y forense
└── campaigns/      # Campañas de phishing desarticuladas: análisis, IOCs y detecciones
```

| Ruta | Tipo | Contenido |
|---|---|---|
| [`tools/wazuh-indexer-forensic-exporter`](tools/wazuh-indexer-forensic-exporter) | Herramienta | Exportador forense en Python para Wazuh Indexer / OpenSearch |
| [`campaigns/`](campaigns) | Campañas | Carpeta reservada para análisis de campañas de phishing desarticuladas |

---

## 🧰 Herramientas

### Wazuh Indexer Forensic Exporter

Exportador forense en Python para **Wazuh Indexer / OpenSearch**. Extrae eventos históricos por mes en formato `NDJSON.GZ` y genera evidencias de integridad (`manifest.json`, `sha256.txt`, `backup.log`). Pensado para auditoría, análisis forense, continuidad operacional y respaldos temporales antes de eliminar índices antiguos.

- Exporta `wazuh-alerts`, `wazuh-archives`, ambos o un patrón manual.
- Exportación paralela por slices, barra de progreso, velocidad y ETA.
- Validación previa de espacio en disco y cálculo de eventos esperados (`_count`).
- Genera hashes SHA-256 y manifiesto para verificación de integridad.
- **No** borra eventos del Indexer, **no** modifica configuración y **no** elimina respaldos locales.

→ Detalle completo en [`tools/wazuh-indexer-forensic-exporter/README.md`](tools/wazuh-indexer-forensic-exporter/README.md).

---

## 🎣 Campañas de phishing desarticuladas

La carpeta [`campaigns/`](campaigns) queda reservada para el análisis de campañas de phishing desarticuladas (análisis, IOCs y detecciones).

> Actualmente sin análisis publicados.

---

## 🎯 Enfoque de detección

- **Sigma** — reglas de detección comportamental.
- **YARA** — huellas de loaders, DLLs y artefactos.
- **Endpoint / EDR** y **Red / Proxy / NDR** — reglas y comportamientos a instrumentar.
- **Mapeo MITRE ATT&CK** por análisis.
- **IOCs defangados** (dominios, IPs, URLs, hashes, fingerprints) listos para alimentar un TIP/SIEM.

---

## ⚠️ Aviso y uso responsable

Este repositorio es material **defensivo y de investigación**. Los IOCs y muestras se publican **defangados** y con fines de detección, threat hunting y respuesta a incidentes. No se realizó acceso no autorizado a infraestructura de terceros; las credenciales o artefactos sensibles observados durante el análisis se omiten deliberadamente.

---

## Licencia

Distribuido bajo licencia **MIT** — ver [`tools/wazuh-indexer-forensic-exporter/LICENSE`](tools/wazuh-indexer-forensic-exporter/LICENSE).

<p align="center"><sub>Blue Team · DFIR · CTI · Detection Engineering</sub></p>
