# Campañas de phishing desarticuladas

Esta carpeta reúne el análisis de campañas de phishing desarticuladas: cadena de ataque, telemetría real, IOCs **defangados** y detecciones accionables (Sigma, YARA, reglas de red/endpoint y mapeo MITRE ATT&CK).

Los indicadores de red se publican **defangados** (el punto como `[.]`, los esquemas como `hxxps[:]//`). Deben re-armarse antes de usarlos en herramientas de bloqueo o detección.

## Campañas publicadas

| Campaña | Tipo | Objetivo | Fecha | Contenido |
|---|---|---|---|---|
| [2026-10 · Smishing «Pasaste sin TAG»](2026-10-smishing-pasaste-sin-tag/) | Smishing / PhaaS con C2 | Usuarios de peajes y TAG (Chile) | 2026-10-12 | Informe técnico, cadena de redirección, protocolo C2 por WebSocket, IOCs v5.1 (JSON y lista plana) y firmas de detección |

<p align="center"><sub>Blue Team · DFIR · CTI · Detection Engineering</sub></p>
