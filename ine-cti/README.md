# INE CTI Monitor v2.0
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
| `/api/health`         | GET    | Estado del sistema                 |

### Ejemplo de llamada a /api/scan/start
```json
POST /api/scan/start
{
  "term": "INE",
  "domain": "ine.mx",
  "modules": ["github", "pastebin", "aws", "ahmia", "darksearch", "onionsearch"],
  "api_keys": {
    "github": "ghp_xxxx",
    "intelx": "xxxx-xxxx",
    "hibp": "xxxx",
    "leakix": "xxxx",
    "onion_proxy": "127.0.0.1:9050",
    "onion_engines": "ahmia darksearchio phobos",
    "onion_limit": 1
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

---

## Uso autorizado

Este sistema es para uso exclusivo de seguridad informática defensiva
bajo contrato con el cliente. Prohibida su distribución o uso no autorizado.
