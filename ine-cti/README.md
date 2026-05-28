# INE CTI Monitor v2.4
## Inteligencia de Amenazas Cibernéticas

Sistema de monitoreo OSINT defensivo para detectar información del INE
expuesta públicamente en internet, repositorios en la nube y dark web indexada.

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
| ail            | AIL Framework             | Correlacion/API    | Requerida|
| misp           | MISP                      | Threat Intel       | Requerida|
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
| `/api/health`         | GET    | Estado del sistema                 |

### Ejemplo de llamada a /api/scan/start
```json
POST /api/scan/start
{
  "term": "INE",
  "domain": "ine.mx",
  "modules": ["github", "pastebin", "aws", "ahmia", "darksearch", "onionsearch", "trufflehog", "gitleaks"],
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
