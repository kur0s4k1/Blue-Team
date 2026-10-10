# CrediGestion "Factura Vencida" — Cadena de Phishing

## Resumen

Una campaña de phishing con señuelo de **documento urgente ("CrediGestion / Factura Vencida")** abusa de **MailinBlack SecureLink** (gateway de correo legítimo) y de un **informe público de Power BI "publish-to-web"** con un logo falso de **Docusign** para ocultar un hyperlink malicioso dentro del modelo del informe.

La cadena termina en una **plataforma PhaaS autoalojada** con huella atribuible al ecosistema **Kali365** (documentado por Unit 42, Crimson7, Todyl y Huntress, abr–jun 2026): landing anti-bot con **Cloudflare Turnstile**, panel de operador estilo terminal y redirector Caddy con catch-all anti-fingerprinting.

**Hallazgo clave:** el hyperlink malicioso no está en el HTML del informe, sino **enterrado en el modelo de datos del visual de Power BI**. Solo se extrae renderizando el informe y leyendo el payload XHR del modelo (`modelsAndExploration`) — técnica que burla crawlers, sandboxes y la mayoría de los gateways de correo.

---

## Cadena de ataque (paso a paso)

```
[1] MailinBlack SecureLink (legítimo, abusado)
        │  https://mibc-fr-04.mailinblack.com/securelink/?url=https://app.powerbi.com&key=...
        ▼
[2] Power BI publish-to-web (legítimo, abusado)
        │  https://app.powerbi.com/view?r=<JWT base64>
        │  Señuelo: logo Docusign falso + "Ver documento aquí | Descargar archivo"
        │  ⚠️ hyperlink malicioso oculto en el MODELO del visual (no en el HTML)
        ▼
[3] Redirector Caddy (infrastructure del actor)
        │  https://mcole830ej.alyamunadensons-ae.com/<token-aleatorio>
        │  CNAME → edge.vericlick.cc → 82.221.101.187 (FlokiNET, Islandia)
        │  302 → ...
        ▼
[4] Landing anti-bot (Turnstile)
        │  https://k5k33e9k7r.asianrnarine.com/l/1zBcPYLEww0
        │  Cloudflare Turnstile (sitekey 0x4AAAAAAEaMG8dpijvxbfNI)
        │  "Secure browsing scan underway." + auto-submit on onVerified
        ▼
[5] *** Credential harvesting (PÁGINA DE RECOLECCIÓN — NO ACCEDIDA) ***
        │  Tras resolver Turnstile, tsForm hace POST same-origin
        │  Pide correo + contraseña (posible MFA en paso posterior)
        │  ⚠️ NO capturamos esta página deliberadamente (ver §"Brecha de evidencia")
        ▼
[6] Panel C2 del operador (Kali365)
        https://k5k33e9k7r.asianrnarine.com/login
        Donde el atacante consulta las credenciales robadas
```

---

## Lo que ve la víctima (flujo completo, paso a paso)

Esta es la secuencia completa desde la perspectiva de la víctima — la evidencia de por qué este kit funciona tan bien:

1. **La víctima abre el enlace del correo** (MailinBlack SecureLink, dominio legítimo → cero sospecha)
<img width="1179" height="668" alt="Captura de pantalla 2026-08-28 195648" src="https://github.com/user-attachments/assets/9a759a0c-f447-4e2a-a0e1-9797d654020c" />


2. **El enlace abre un informe público de Power BI** con un documento que dice **"Ver documento aquí"**.
<img width="1177" height="639" alt="Captura de pantalla 2026-08-28 195705" src="https://github.com/user-attachments/assets/9a9426e3-f22d-4897-8e74-abb209e0623d" />


3. **Al hacer clic**, aparece el **anti-bot de Cloudflare** (Turnstile — "Verify you are human") y, tras resolverse, se abre automáticamente el documento, que **muestra un código** y un botón **"Open"**.
<img width="1177" height="668" alt="Captura de pantalla 2026-08-28 195727" src="https://github.com/user-attachments/assets/fbc974c2-c3e9-488d-8cf9-df654ce0be5a" />
<img width="1184" height="667" alt="Captura de pantalla 2026-08-28 195734" src="https://github.com/user-attachments/assets/9552734e-374b-468a-88c0-c148b6b63bae" />


4. **Al presionar "Open"**, se abre una **ventana legítima de Microsoft** (`microsoft.com/devicelogin` — no es un clon, es el sitio real) donde se debe **pegar el código**.
<img width="1179" height="671" alt="Captura de pantalla 2026-08-28 195747" src="https://github.com/user-attachments/assets/8c854e86-1db1-4cc9-a354-4f620ab0b6b3" />


5. **Tras ingresar el código, la víctima ingresa sus credenciales** — en el portal real de Microsoft.
<img width="1189" height="674" alt="Captura de pantalla 2026-08-28 195755" src="https://github.com/user-attachments/assets/bd85638a-c2d4-47c4-8901-ec96a9563f33" />


---

## Análisis técnico por eslabón

### [1] MailinBlack SecureLink (gateway legítimo, abusado)

- Host: `mibc-fr-04.mailinblack.com` — IP `20.199.104.10`, cert CN `*.mailinblack.com` (Gandi CA).
- Función legítima: gateway de Secure Mail que reenvía a la URL destino pasada como parámetro.
- **Abuso:** el atacante lo usa como **primer salto de confianza**. Como el dominio es legítimo y tiene reputación limpia, burla anti-spam, DMARC-lookalike y sandboxes que confían en la primera URL.

### [2] Informe público de Power BI "publish-to-web" (señuelo Docusign)

- URL: `https://app.powerbi.com/view?r=eyJrIjoiNzA1OWY0MjAtNTNkNi00Mjk2LWFhZjItNDk3MGRlNTk3M2VjIiwidCI6ImU5ZDMxMGU3LTc1Y2QtNDgyNC1iYTg5LTc4YTExZTBiMjUzNiJ9`
- Payload decodificado del parámetro `r` (base64 → JSON):
  ```json
  {
    "k": "7059f420-53d6-4296-aaf2-4970de5973ec",   // reportId
    "t": "e9d310e7-75cd-4824-ba89-78a11e0b2536"    // workspace/tenant
  }
  ```
- Región del backend: `wabi-switzerland-north`.
- **Técnica de ocultación:** el hyperlink malicioso **NO aparece en el HTML** de la página. Está incrustado en el **modelo de datos del visual**, entregado por un XHR a `modelsAndExploration` protegido por sesión y bloqueado por CORS. Solo se extrae renderizando el informe y leyendo el body del XHR vía Chrome DevTools Protocol (`Network.getResponseBody`).
<img width="1920" height="1080" alt="01_sepuelo_powerbi_docusign" src="https://github.com/user-attachments/assets/80016e72-3f91-40da-9dfd-507711747221" />


> **Texto de ingeniería social:** *"Nota importante: Accede con tu dirección de correo electrónico de recepción y sigue las instrucciones que aparecen en la URL para ver la propuesta."* — botón: **"Ver documento aquí | Descargar archivo"**.

### [3] Redirector Caddy con catch-all anti-fingerprinting

- Subdominio de campaña: `mcole830ej.alyamunadensons-ae.com` → **CNAME** → `edge.vericlick.cc` → **A** `82.221.101.187`.
- Hosting: **FlokiNET ehf** (Islandia), ASN **AS50613 ThorDC/Advania**, mnt `MNT-ADVANIA`.
- Servidor: **Caddy**.
  - Puerto 80: `301` → HTTPS.
  - Puerto 443: sirve el cert solo con **SNI `edge.vericlick.cc`**. Si se conecta por IP directa (sin SNI correcto) → `tlsv1 alert internal error`.
  - **Catch-all anti-fingerprinting:** **todas** las rutas devuelven `200 "Nothing to see here."` — los crawlers de VirusTotal, urlscan o hydra no distinguen el patrón real.

### [4] Landing anti-bot (Cloudflare Turnstile)

- URL: `https://k5k33e9k7r.asianrnarine.com/l/1zBcPYLEww0`
- Fronting: **Cloudflare** (`104.21.92.137`, `172.67.194.135`).
- Contenido: página minimalista con título **rotativo** (`"Marsh"`, `"Grain"`) y widget **Cloudflare Turnstile** con sitekey `0x4AAAAAAEaMG8dpijvxbfNI`.
- Texto social-engineering: *"Secure browsing scan underway."* / *"Scanning for browsing security"* — finge un análisis de seguridad mientras resuelve el challenge.
- Formulario `<form method="POST" id="tsForm">` con **auto-submit en `onVerified`**.
- **Función:** filtra bots y sandboxes. Los crawlers (urlscan, VT, any.run sin interacción) **nunca alcanzan** la página de recolección.

<img width="1920" height="1080" alt="02_landing_turnstile_gate" src="https://github.com/user-attachments/assets/31107984-fdd2-4ce6-b2fd-fddefd8db4e4" />


### [5] Recolección de credenciales (no accedida deliberadamente — brecha de evidencia)

**Esta es la pieza que NO está documentada con screenshot.** Tras resolver Turnstile, `tsForm` hace POST al mismo origen (`asianrnarine.com`), que sirve la página de recolección. Todo lo que sabemos de este paso es **inferencia técnica** a partir del comportamiento del chain, no captura directa:

- **Formulario de entrada esperado:** usuario (correo) + contraseña; probablemente un segundo paso de OTP/MFA (patrón estándar de los kits PhaaS modernos, incluido Kali365).
- **Endpoint de envío:** POST same-origin a `asianrnarine.com` (los creds viajan a la BD del atacante, no a un tercero).
- **Destino de esos creds:** la BD detrás del panel `/login`, donde el operador los consulta.

### [6] Panel C2 del operador (Kali365 PhaaS)

- URL: `https://k5k33e9k7r.asianrnarine.com/login`
- Formulario `<form method="POST">` con campos `username` / `password`, **sin CSRF** ni cookie de sesión en el login fallido (`vary: Cookie` sugiere sesión post-login).
- Estética terminal: fondo negro, texto rojo, botón **`[ ACCESS ]`**, footer **"AUTHORIZED PERSONNEL ONLY"**, enlace **"[ FORGOT PASSWORD? ]"** (señuelo, 404), fuentes **Share Tech Mono / JetBrains Mono / VT323 / IBM Plex Mono**, efecto **CRT scanline**.
- Respuesta a POST inválido: `200` con `<p class="err">Invalid credentials</p>` — **panel funcional**, sin enum de usuarios, sin credenciales por defecto, **sin rate-limiting**.

<img width="1920" height="1080" alt="03_panel_c2_login (1)" src="https://github.com/user-attachments/assets/ee520eee-9867-43fd-b285-870cc21a9aa5" />


---

## Atribución: Kali365 PhaaS

El panel coincide casi exacto con el panel de operador **Kali365**, PhaaS documentado de forma independiente por:

- **Unit 42** (abr 2026)
- **Crimson7** — *"Hunting a PhaaS Operator: Kali365"* (abr 2026)
- **Todyl** — *"Kali365: Inside the Attack Infrastructure"* (may 2026)
- **Huntress** (jun 2026)

Coincidencias técnicas observadas:

| Característica | Kali365 documentado | Nuestra instancia |
|---|---|---|
| Botón `[ ACCESS ]` | Sí | Sí |
| Footer "AUTHORIZED PERSONNEL ONLY" | Sí | Sí |
| "[ FORGOT PASSWORD? ]" | Sí | Sí (señuelo 404) |
| Rutas `/login`, `/register`, `/forgot-password` | Sí | `/login` y `/forgot-password` (404) |
| Fuentes mono + CRT scanline | Sí | Sí |
| Turnstile anti-bot | Sí | Sí |
| Distribución vía Telegram, ~$250/mes BTC | Sí | (no verificado) |

**Caveat:** nuestra instancia **NO expone** `/register` ni `/health` (404) y el panel es HTML estático, no el React/Vite descrito por Huntress. 
Interpretación: **Kali365 en "modo campaña"** (rutas recortadas) o un **clon/derivado** del mismo ecosistema.

**Contexto Kali365 (Crimson7 / FBI abr 2026):**
- PhaaS distribuido por **Telegram**, suscripción ~**$250/mes** en Bitcoin.
- AiTM reverse-proxy + device-code phishing para **Microsoft 365**.
- Clúster del operador atribuido a **Lagos, Nigeria (Starlink)** — merchant OxaPay `11153123`, NetHandle `NET-135-129-124-0-1`.

**Confianza:** ALTA en estética/TTPs · MODERADA en binario exacto.

---

## Infraestructura y OPSEC

### WHOIS / registro (3 registradores distintos = dispersión OPSEC)

| Dominio | Registrador | Creado | NS |
|---|---|---|---|
| `asianrnarine.com` | Dynadot | 2026-03-08 | Cloudflare |
| `alyamunadensons-ae.com` | Hosting Concepts B.V. / Registrar.eu | 2026-03-18 | Cloudflare |
| `vericlick.cc` | Tucows | 2026-08-19 | FlokiNET |

Los dos primeros dominios (marzo 2026) son **"sleeper"** preparados con ~3 meses de antelación.

### Certificados Let's Encrypt (timeline de despliegue)

| Cert | notBefore | SHA-256 (primeros bytes) |
|---|---|---|
| `asianrnarine.com` | 2026-07-04 | `DC:5B:2A:B1:30:59:...` |
| `edge.vericlick.cc` | 2026-08-20 | `70:2B:1E:D4:6B:...` |
| `mcole830ej.alyamunadensons-ae.com` | 2026-08-27 | `B4:FA:13:D9:B7:08:...` |

### Rotación de subdominios de campaña

| Subdominio (`alyamunadensons-ae.com`) | Estado | Cert CT |
|---|---|---|
| `mcole830ej` | **ACTIVO** → `edge.vericlick.cc` | 2026-08-27 |
| `83hslinka7` | **ACTIVO** → `82.221.101.187` | 2026-08-27 |
| `gomfar32a` | **ACTIVO** → `82.221.101.187` | 2026-08-26 |
| `gosergio` | retirado (sin DNS) | 2026-08-24 |
| `r7a73ejhs` | retirado (sin DNS) | 2026-08-25 |
| `go823ska` | retirado (sin DNS) | 2026-08-27 |

**Ciclo de vida OPSEC corto:** rotación diaria y retiro rápido (3 de 6 ya sin DNS).

### Reputación previa (a 2026-08-28)

- **OTX AlienVault:** 0 pulses para los 3 dominios y la IP.
- **urlscan.io:** 0 escaneos de landing/panel (Turnstile bloquea crawlers); solo 2 del propio redirector (21 y 22 ago), ninguno de la campaña.
- **Interpretación:** infraestructura deliberadamente **fresca y no bloqueada** — patrón documentado en PhaaS ("cero detecciones en todos los vendors de VT al descubrirse").

### Tecnologías confirmadas (stack del actor)

- **Cloudflare** (proxy + Turnstile invisible + challenge skip)
- **Caddy** (redirector 80→443, catch-all "Nothing to see here")
- **Let's Encrypt** (certs frescos, sin OCSP must-staple)
- **CNAME → FlokiNET** (AS50613 ThorDC/Advania)
- **NS Cloudflare** (asianrnarine, alyamunadensons) y **NS FlokiNET** (vericlick.cc)
- Panel **HTML+CSS estático** (sin React/Vite) con fuentes mono + CRT scanline
- Landing **SPA** "Grain"/"Marsh" con Turnstile

---

## IOCs (defanged)

### Dominios del actor

```
asianrnarine[.]com
k5k33e9k7r[.]asianrnarine[.]com
alyamunadensons-ae[.]com
mcole830ej[.]alyamunadensons-ae[.]com
83hslinka7[.]alyamunadensons-ae[.]com
gomfar32a[.]alyamunadensons-ae[.]com
vericlick[.]cc
edge[.]vericlick[.]cc
```

### Subdominios retirados (referencia histórica)

```
gosergio[.]alyamunadensons-ae[.]com
r7a73ejhs[.]alyamunadensons-ae[.]com
go823ska[.]alyamunadensons-ae[.]com
```

### IPs

```
82[.]221[.]101[.]187          # FlokiNET ehf (IS) — redirector Caddy, infrastructure del actor
104[.]21[.]92[.]137           # Cloudflare (anycast, fronting del dominio del actor)
172[.]67[.]194[.]135          # Cloudflare (anycast, fronting del dominio del actor)
```

### URLs / patrones

```
https://app.powerbi.com/view?r=eyJrIjoiNzA1OWY0MjAtNTNkNi00Mjk2LWFhZjItNDk3MGRlNTk3M2VjIiwidCI6ImU5ZDMxMGU3LTc1Y2QtNDgyNC1iYTg5LTc4YTExZTBiMjUzNiJ9
https://mcole830ej[.]alyamunadensons-ae[.]com/<token-aleatorio>
https://k5k33e9k7r[.]asianrnarine[.]com/l/<token>
https://k5k33e9k7r[.]asianrnarine[.]com/login
```

### Servicios legítimos abusados (referencia, NO son IOCs del actor)

```
mibc-fr-04[.]mailinblack[.]com      # MailinBlack SecureLink (gateway legítimo)
20[.]199[.]104[.]10                 # MailinBlack
app[.]powerbi[.]com                 # Microsoft Power BI publish-to-web
```

### Identificadores de campaña

| Tipo | Valor |
|---|---|
| Power BI reportId | `7059f420-53d6-4296-aaf2-4970de5973ec` |
| Power BI workspace/tenant | `e9d310e7-75cd-4824-ba89-78a11e0b2536` |
| Región Power BI | `wabi-switzerland-north` |
| Cloudflare Turnstile sitekey | `0x4AAAAAAEaMG8dpijvxbfNI` |
| ASN del redirector | `AS50613` (ThorDC/Advania — FlokiNET ehf) |
| Patrón de campaña | `/l/<token>` en el landing · `/login` en el panel C2 |
| Merchant OxaPay (at. Kali365) | `11153123` |
| NetHandle | `NET-135-129-124-0-1` |

### Fingerprint del panel (para hunting)

```
título: "Panel"
botón: "[ ACCESS ]"
footer: "AUTHORIZED PERSONNEL ONLY"
enlace: "[ FORGOT PASSWORD? ]"
fuentes: Share Tech Mono, JetBrains Mono, VT323, IBM Plex Mono
efecto: CRT scanline (conic-gradient animado)
campos: username, password (sin CSRF)
respuesta login inválido: <p class="err">Invalid credentials</p>
```

### Diagrama de OPSEC del atacante
<img width="1491" height="1055" alt="WhatsApp Image 2026-08-28 at 18 51 07" src="https://github.com/user-attachments/assets/51347631-ab06-4e7a-ab29-58573ea0e3d6" />



### Fingerprint del landing

```
title rotativo: "Grain" / "Marsh"
widget: Cloudflare Turnstile (sitekey 0x4AAAAAAEaMG8dpijvxbfNI)
texto: "Secure browsing scan underway." / "Scanning for browsing security"
form: <form method="POST" id="tsForm"> con auto-submit en onVerified
```

---

## TTPs (MITRE ATT&CK)

| Táctica | Técnica | ID |
|---|---|---|
| Resource Development | Adquisición de dominios (sleeper, registradores dispersos) | T1583.001 |
| Resource Development | Capacidades de phishing (PhaaS Kali365) | T1587.002 |
| Resource Development | Abuso de CDN/infra legítima (Cloudflare, FlokiNET) | T1584.006 |
| Initial Access | Phishing con enlace (Power BI + MailinBlack abusados) | T1566.002 |
| Initial Access | Phishing con servicio de terceros (publish-to-web) | T1660 |
| Execution | Usuario víctima resuelve Turnstile (interacción) | T1204.001 |
| Credential Access | Credential harvesting (página de recolección) | T1056.004 |
| Credential Access | **Device-code phishing (login real de Microsoft + código del atacante)** | **T1621** |
| Credential Access | Robo de token OAuth post-MFA (device code flow) | T1528 |
| Defense Evasion | Anti-bot Turnstile (evasión de sandboxes/crawlers) | T1027 |
| Defense Evasion | Catch-all Caddy "Nothing to see here" (anti-fingerprinting) | T1027 |
| Defense Evasion | Hyperlink oculto en el modelo de Power BI | T1027.010 |

---

### Mitigación para organizaciones

- Bloquear / alertar sobre **`app.powerbi.com/view?r=...`** cuando provenga de correo externo no solicitado (publish-to-web no es uso legítimo corporativo interno).
- Capacitar: **ningún documento urgente pide tu correo "de recepción" para ver la propuesta**.
- Inspección de URL en el correo: ampliar el análisis al **modelo de datos de los visuales**, no solo al HTML del primer hop.
- Cazar en logs de proxy/dns visitas a los dominios/IPs del IOC.

---

## Referencias

Referencias sobre Kali365:

- Unit 42 — *The New Face of Phishing-as-a-Service* (abr 2026)
- Crimson7 — *Hunting a PhaaS Operator: Kali365* (abr 2026)
- Todyl — *Kali365: Inside the Attack Infrastructure* (may 2026)
- Huntress — *Kali365 PhaaS Analysis* (jun 2026)
- Arctic Wolf — *Kali365 Overview* (abr 2026)

---

*Análisis realizado el 2026-08-28. Todos los IOCs son del actor; no se incluye información de la víctima. Los screenshots se capturaron sobre infraestructura del atacante en un entorno aislado, sin resolver el Turnstile challenge ni interactuar con el panel más allá de observación pasiva.*
