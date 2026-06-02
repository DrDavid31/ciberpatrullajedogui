# INE CTI Monitor v2.9
## Inteligencia de Amenazas Cibernéticas

Sistema de monitoreo OSINT defensivo para detectar información del INE
expuesta públicamente en internet, repositorios en la nube y dark web indexada.
La pantalla principal muestra los hallazgos en vivo durante el escaneo.

---

## Instalación rápida

### Windows
1. Instala Python 3.9+ desde https://python.org
2. Haz doble clic en `iniciar.bat`
3. El navegador abre automáticamente en http://localhost:5000

### Mac / Linux
```bash
chmod +x iniciar.sh
./iniciar.sh
```

### Manual
```bash
pip install -r requirements.txt
python app.py
```
Abre http://localhost:5000 en tu navegador.

---

## Estructura del proyecto

```
ine-cti/
├── app.py                  # Backend Flask (API REST)
├── modules/
│   └── scanner.py          # Módulos de escaneo por fuente
├── static/
│   └── index.html          # Interfaz web completa
├── results/
│   └── findings.json       # Resultados guardados automáticamente
├── requirements.txt
├── iniciar.sh              # Lanzador Linux/Mac
└── iniciar.bat             # Lanzador Windows
```

---

## Módulos de monitoreo incluidos

| Módulo         | Fuente                    | Tipo               | API Key |
|----------------|---------------------------|--------------------|---------|
| github         | GitHub / GitLab           | Código expuesto    | Opcional|
| pastebin       | Pastebin                  | Paste/Leak         | No      |
| googledrive    | Google Drive / Docs       | Repositorio        | No      |
| filerepos      | Dropbox / OneDrive / MEGA | Repositorio        | No      |
| aws            | AWS S3 Buckets            | Cloud Storage      | No      |
| azure          | Azure Blob Storage        | Cloud Storage      | No      |
| gcloud         | Google Cloud Storage      | Cloud Storage      | No      |
| ahmia          | Ahmia.fi (Dark Web)       | Dark Web indexada  | No      |
| darksearch     | DarkSearch.io             | Dark Web indexada  | No      |
| onionsearch    | OnionSearch               | Motores .onion     | No      |
| trufflehog     | TruffleHog                | Secret scanning    | Opcional|
| gitleaks       | Gitleaks                  | Secret scanning    | Opcional|
| socialanalyzer | Social Analyzer           | Perfiles sociales  | Opcional|
| apprise        | Apprise                   | Notificaciones     | Opcional|
| changedetection| changedetection.io        | Monitoreo de cambios| Requerida|
| huginn         | Huginn                    | Automatizacion/eventos| Webhook|
| ail            | AIL Framework             | Correlacion/API    | Requerida|
| misp           | MISP                      | Threat Intel       | Requerida|
| aleph          | Aleph/OpenAleph           | Investigacion documental| Opcional|
| followthemoney | FollowTheMoney            | Normalizacion de entidades| No|
| thehive        | TheHive                   | Alertas/casos SOC  | Requerida|
| shuffle        | Shuffle SOAR              | Workflows/webhooks | Webhook |
| subfinder      | ProjectDiscovery Subfinder| Subdominios        | Binario |
| httpx          | ProjectDiscovery httpx    | Servicios HTTP     | Binario |
| naabu          | ProjectDiscovery Naabu    | Puertos expuestos  | Binario |
| nuclei         | ProjectDiscovery Nuclei   | Templates vuln     | Binario |
| urlscan        | urlscan.io                | Analisis de URLs   | API Key |
| sigma          | SigmaHQ Sigma             | Reglas deteccion   | Ruta local|
| yara           | VirusTotal YARA           | Analisis documentos| Ruta local|
| leakix         | LeakIX                    | Servicios expuestos| Opcional|
| hibp           | HaveIBeenPwned            | Credenciales       | Opcional|
| intelx         | Intelligence X            | Dark Web / Leaks   | Opcional|

---

## API Keys opcionales

Agrégalas en la pestaña **Configuración** del monitor:

| Servicio         | Costo    | URL de registro                        |
|------------------|----------|----------------------------------------|
| GitHub Token     | Gratis   | https://github.com/settings/tokens    |
| IntelX           | Gratis*  | https://intelx.io/account             |
| HaveIBeenPwned   | $3.50/mes| https://haveibeenpwned.com/API/Key     |
| LeakIX           | Gratis*  | https://leakix.net                     |
| AIL Framework    | Self-hosted| https://github.com/ail-project/ail-framework |
| MISP             | Self-hosted| https://github.com/MISP/MISP          |
| TruffleHog       | Binario local| https://github.com/trufflesecurity/trufflehog |
| Gitleaks         | Binario local| https://github.com/gitleaks/gitleaks |
| Social Analyzer  | Python package| https://github.com/qeeqbox/social-analyzer |
| Apprise          | Python package| https://github.com/caronc/apprise |
| changedetection.io| Self-hosted| https://github.com/dgtlmoon/changedetection.io |
| Huginn           | Self-hosted| https://github.com/huginn/huginn |
| Aleph            | Self-hosted/API| https://github.com/alephdata/aleph |
| FollowTheMoney   | Python package| https://github.com/alephdata/followthemoney |
| TheHive          | Self-hosted| https://github.com/TheHive-Project/TheHive |
| Shuffle          | Self-hosted/Cloud| https://github.com/shuffle/shuffle |
| ProjectDiscovery | Binarios locales| https://github.com/projectdiscovery |
| urlscan.io       | Gratis*  | https://urlscan.io/user/signup |
| Sigma            | Reglas locales| https://github.com/SigmaHQ/sigma |
| YARA             | Binario/Python| https://github.com/VirusTotal/yara |

*Plan gratuito con límite de consultas diarias.

---

## API REST del backend

| Endpoint              | Método | Descripción                        |
|-----------------------|--------|------------------------------------|
| `/api/scan/start`     | POST   | Iniciar escaneo                    |
| `/api/scan/status`    | GET    | Estado actual del escaneo          |
| `/api/scan/findings`  | GET    | Obtener hallazgos (filtrable)      |
| `/api/scan/stop`      | POST   | Detener escaneo en curso           |
| `/api/export/json`    | GET    | Exportar hallazgos en JSON         |
| `/api/export/csv`     | GET    | Exportar hallazgos en CSV          |
| `/api/ail/test`       | POST   | Probar conexion con AIL Framework  |
| `/api/ail/export`     | POST   | Enviar hallazgos a AIL             |
| `/api/ail/tracker`    | POST   | Crear tracker en AIL               |
| `/api/misp/test`      | POST   | Probar conexion con MISP           |
| `/api/misp/export`    | POST   | Crear evento MISP desde hallazgos  |
| `/api/apprise/test`   | POST   | Enviar notificacion de prueba      |
| `/api/apprise/notify` | POST   | Enviar resumen por Apprise         |
| `/api/changedetection/test` | POST | Probar changedetection.io        |
| `/api/changedetection/export` | POST | Crear watches desde hallazgos  |
| `/api/huginn/test`    | POST   | Enviar evento de prueba a Huginn   |
| `/api/huginn/export`  | POST   | Enviar hallazgos como eventos      |
| `/api/aleph/test`     | POST   | Probar conexion/busqueda Aleph     |
| `/api/aleph/search`   | POST   | Buscar entidades/documentos Aleph  |
| `/api/followthemoney/test` | POST | Probar normalizador FtM        |
| `/api/followthemoney/export` | POST | Exportar hallazgos como FtM   |
| `/api/thehive/test` | POST | Probar conexion TheHive             |
| `/api/thehive/export` | POST | Crear alertas TheHive            |
| `/api/shuffle/test` | POST | Probar webhook Shuffle              |
| `/api/shuffle/export` | POST | Enviar hallazgos a Shuffle       |
| `/api/urlscan/test` | POST | Probar cuotas urlscan.io            |
| `/api/urlscan/submit` | POST | Enviar URLs a urlscan.io          |
| `/api/sigma/test` | POST | Probar carga de reglas Sigma         |
| `/api/sigma/rules` | POST | Listar reglas Sigma                 |
| `/api/yara/test` | POST | Probar motor YARA                    |
| `/api/yara/scan` | POST | Escanear documentos con YARA         |
| `/api/health`         | GET    | Estado del sistema                 |

### Ejemplo de llamada a /api/scan/start
```json
POST /api/scan/start
{
  "term": "INE",
  "domain": "ine.mx",
  "modules": ["github", "pastebin", "aws", "ahmia", "darksearch", "onionsearch", "trufflehog", "gitleaks", "socialanalyzer", "changedetection", "aleph", "subfinder", "httpx", "naabu", "nuclei"],
  "api_keys": {
    "github": "ghp_xxxx",
    "intelx": "xxxx-xxxx",
    "hibp": "xxxx",
    "leakix": "xxxx",
    "onion_proxy": "127.0.0.1:9050",
    "onion_engines": "ahmia darksearchio phobos",
    "onion_limit": 1,
    "trufflehog_target": "https://github.com/DrDavid31/ciberpatrullajedogui",
    "trufflehog_mode": "git",
    "trufflehog_results": "verified,unknown",
    "trufflehog_limit": 20,
    "trufflehog_comments": false,
    "gitleaks_target": ".",
    "gitleaks_mode": "dir",
    "gitleaks_config": "",
    "gitleaks_baseline": "",
    "gitleaks_limit": 20,
    "gitleaks_max_mb": "",
    "gitleaks_log_opts": "",
    "social_username": "INE",
    "social_websites": "github youtube tiktok",
    "social_countries": "mx us",
    "social_mode": "fast",
    "social_method": "find",
    "social_filter": "good",
    "social_profiles": "detected",
    "social_type": "",
    "social_top": 100,
    "social_limit": 30,
    "social_timeout": 10,
    "social_metadata": false,
    "social_extract": false,
    "apprise_urls": "discord://webhook_id/webhook_token",
    "apprise_on_complete": false,
    "apprise_on_high": true,
    "changedetection_url": "http://localhost:5000",
    "changedetection_key": "CHANGEDETECTION_API_KEY",
    "changedetection_tag": "ine-cti",
    "changedetection_limit": 20,
    "changedetection_recheck": false,
    "changedetection_verify_tls": true,
    "huginn_webhook_url": "https://huginn.local/users/1/web_requests/1/secret",
    "huginn_limit": 20,
    "huginn_verify_tls": true,
    "aleph_url": "https://aleph.occrp.org",
    "aleph_key": "",
    "aleph_schemata": "Person,Company,Document",
    "aleph_limit": 10,
    "aleph_verify_tls": true,
    "ftm_dataset": "ine-cti-monitor",
    "ftm_limit": 100,
    "thehive_url": "https://thehive.local",
    "thehive_key": "THEHIVE_API_KEY",
    "thehive_org": "",
    "thehive_limit": 20,
    "thehive_verify_tls": true,
    "shuffle_webhook_url": "https://shuffler.io/api/v1/webhooks/webhook_xxx",
    "shuffle_token": "",
    "shuffle_limit": 20,
    "shuffle_verify_tls": true,
    "pd_target": "ine.mx",
    "pd_limit": 50,
    "pd_timeout": 240,
    "pd_ports": "80,443",
    "nuclei_templates": "",
    "nuclei_severity": "critical,high,medium",
    "nuclei_tags": "cve,exposure,misconfig",
    "urlscan_key": "URLSCAN_API_KEY",
    "urlscan_visibility": "unlisted",
    "urlscan_tags": "ine-cti",
    "urlscan_limit": 10,
    "sigma_rules_path": "C:\\ruta\\sigma\\rules",
    "sigma_limit": 50,
    "yara_rules_path": "C:\\ruta\\rules.yar",
    "yara_target_path": "C:\\ruta\\documentos",
    "yara_max_files": 200,
    "yara_recursive": true,
    "ail_url": "https://localhost:7000",
    "ail_key": "AIL_API_KEY",
    "ail_tags": "ine-cti, osint",
    "ail_tracker_type": "word",
    "ail_verify_tls": false,
    "misp_url": "https://misp.local",
    "misp_key": "MISP_API_KEY",
    "misp_tags": "tlp:amber, osint, ine-cti",
    "misp_distribution": 0,
    "misp_threat_level": "",
    "misp_analysis": 0,
    "misp_verify_tls": false,
    "misp_publish": false
  }
}
```

---

## Flujo de trabajo recomendado

```
1. ESCANEO
   Configurar términos → Seleccionar módulos → Iniciar escaneo

2. REVISIÓN
   Pestaña Hallazgos → Filtrar por riesgo CRÍTICO/ALTO → Revisar URLs

3. VALIDACIÓN
   Pestaña Validación → Confirmar amenaza / Falso positivo / Investigar

4. REPORTE
   Exportar CSV o JSON → Generar informe para el cliente
```

---

## Notas de uso

- El sistema funciona en **modo demo** si el backend no está corriendo,
  mostrando hallazgos de ejemplo para familiarizarse con la interfaz.
- Los resultados se guardan automáticamente en `results/findings.json`
  al terminar cada escaneo.
- Para monitoreo continuo, configura el **intervalo de auto-scan**
  en la interfaz (cada 1h, 6h, 12h o 24h).
- Los módulos de dark web (Ahmia, DarkSearch) buscan en índices públicos
  de contenido .onion sin necesidad de Tor.
- OnionSearch amplía la cobertura consultando múltiples motores .onion.
  Se instala con `pip install -r requirements.txt`; el proxy Tor local
  `127.0.0.1:9050` es opcional y se configura desde la pestaña Configuración.
- TruffleHog se integra como escaner externo de secretos. Instala el binario
  `trufflehog` desde sus releases y configura un repositorio, organizacion o
  ruta local autorizada desde la pestaña Configuracion.
- Gitleaks se integra como escaner externo de secretos para rutas locales o
  repositorios git locales. Instala el binario `gitleaks` y usa modo `dir` o
  `git`; los reportes se generan en JSON temporal y se importan como hallazgos.
- Social Analyzer se integra como paquete Python externo. Busca perfiles
  asociados a usernames en sitios sociales usando salida JSON y normaliza
  resultados como hallazgos de "Perfil Social".
- Apprise se integra como canal de notificaciones. Configura una o varias URLs
  Apprise para probar envio, mandar resúmenes manuales y notificar
  automáticamente al finalizar escaneos o al detectar hallazgos alto/critico.
- changedetection.io se integra como monitor de cambios. Puedes listar watches
  durante el escaneo y crear nuevos watches desde URLs detectadas en hallazgos.
- Huginn se integra mediante Webhook Agent. El monitor envia eventos JSON de
  prueba o un evento por hallazgo para que Huginn dispare workflows.
- Aleph/OpenAleph se integra como busqueda documental y de entidades usando
  `/api/2/entities`; puedes usar una instancia publica o self-hosted con ApiKey.
- FollowTheMoney normaliza hallazgos a entidades FtM para exportarlas como JSON
  compatible con pipelines Aleph/OpenAleph y herramientas del ecosistema FtM.
- TheHive crea alertas SOC desde hallazgos usando API key. Soporta rutas API
  comunes de TheHive 4/5 y observables tipo URL u otros valores.
- Shuffle envia eventos JSON a un Webhook Trigger para disparar workflows SOAR.
- ProjectDiscovery integra `subfinder`, `httpx`, `naabu` y `nuclei` como
  binarios locales. Ejecutalos solo sobre dominios/sistemas autorizados.
- urlscan.io envia URLs detectadas para analisis externo; usa visibilidad
  `unlisted` o `private` si el hallazgo puede contener informacion sensible.
- Sigma carga reglas YAML locales del repositorio SigmaHQ/sigma para validarlas
  y preparar conversion/uso posterior en SIEM.
- YARA escanea documentos locales autorizados usando `yara-python` o el binario
  `yara`; los matches se agregan como hallazgos de documento sospechoso.
- AIL Framework se integra como plataforma externa. Desde Configuracion puedes
  probar la conexion, enviar hallazgos del monitor como items de texto y crear
  trackers para el termino activo.
- MISP se integra como plataforma externa. Desde Configuracion puedes probar
  la conexion y crear un evento MISP con atributos derivados de los hallazgos
  actuales; por defecto los atributos se envian con `to_ids=false`.

---

## Uso autorizado

Este sistema es para uso exclusivo de seguridad informática defensiva
bajo contrato con el cliente. Prohibida su distribución o uso no autorizado.
