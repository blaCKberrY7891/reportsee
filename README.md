# ReportSee

Motor de análisis de reconocimiento para pentesting. Lee la salida cruda (`.txt`) de herramientas de Kali Linux y la normaliza en hallazgos clasificados por severidad, listos para un reporte profesional.

Construido mientras avanzo por TryHackMe (Jr Penetration Tester path) y estudio para eJPT / KLCP — pensado como una herramienta real de flujo de trabajo, no un ejercicio académico.

## Por qué existe

Después de correr `nmap`, `feroxbuster`, `nikto`, `hydra`, `sqlmap`, etc. contra un objetivo, terminas con varios `.txt` de salida cruda y la tarea manual de releerlos todos para no perder nada relevante. ReportSee automatiza esa primera pasada: separa lo que importa (credenciales encontradas, servicios vulnerables conocidos, rutas web interesantes) de lo que es ruido, y lo presenta con severidad estandarizada.

No reemplaza el análisis humano — es la herramienta que te ahorra el primer barrido y te dice por dónde empezar a mirar.

## Herramientas soportadas

**Motor nativo:**
- `nmap` (puertos, servicios, OS fingerprint, traceroute, scripts NSE comunes)
- `gobuster`, `feroxbuster`, `dirb`, `ffuf`, `wfuzz` (fuzzing web)
- `nikto`
- `hydra`
- `sqlmap`
- `John the Ripper`

**Vía reglas externas (`reportsee_signatures.json`):**
- `enum4linux` / `enum4linux-ng`
- `smbmap` / `smbclient`
- `crackmapexec` / `netexec`
- `hashcat`
- `whatweb`
- `wpscan`
- `dnsrecon` / `dnsenum`
- `searchsploit`

Un mismo archivo `.txt` puede mezclar salidas de varias herramientas — el motor detecta automáticamente cuáles están presentes y aplica solo las reglas correspondientes.

## Instalación

Requiere Python 3.8+ (sin dependencias externas — solo librería estándar).

```bash
git clone https://github.com/blaCKberrY7891/reportsee.git
cd reportsee
chmod +x reportsee.py
sudo ln -s "$(pwd)/reportsee.py" /usr/local/bin/reportsee
```

Confirma que quedó disponible:

```bash
reportsee --help
```

**Importante:** `reportsee_signatures.json` debe vivir en el mismo directorio que `reportsee.py`. Sin él, la correlación de CVEs y las herramientas Tier 1/2 quedan desactivadas (nmap, fuzzing web, nikto, hydra, sqlmap y John siguen funcionando normal).

## Uso

```bash
# Analizar un archivo
reportsee nmap_scan.txt

# Varios archivos de un mismo engagement
reportsee nmap.txt feroxbuster.txt nikto.txt hydra.txt

# Exportar reporte consolidado en Markdown (estilo OSCP)
reportsee nmap.txt feroxbuster.txt --export-md reporte.md

# Sin colores ANSI (para redirigir a archivo)
reportsee nmap.txt --no-color > salida.txt

# Set de reglas alterno
reportsee nmap.txt --signatures otras_reglas.json
```

## Ejemplo de salida

```
+----------------------------------------------------------------------------+
| REPORTSEE v3 - MOTOR DE ANALISIS DE RECONOCIMIENTO                         |
+----------------------------------------------------------------------------+
| Archivo: nmap_scan.txt                                                     |
| Lineas analizadas: 53                                                      |
| Herramientas detectadas: nmap                                              |
+----------------------------------------------------------------------------+

--[ RESUMEN EJECUTIVO ]
  MEDIO    : 2
  INFO     : 1
------------------------------------------------------------------------

--[ HALLAZGOS (3) ]
  [MEDIO   ] Web                L15
      80/tcp - Apache HTTP
      Apache detectado (Apache httpd 2.4.41 ((Ubuntu))). Iniciar fuzzing de
      directorios y revisar vhosts / archivos de configuracion expuestos.
```

## Severidad

| Nivel | Criterio |
|---|---|
| `CRITICO` | RCE confirmado / credenciales válidas / exploit público activo |
| `ALTO` | Vulnerabilidad conocida sin RCE directo confirmado, o exposición que facilita movimiento lateral |
| `MEDIO` | Debilidad de configuración que requiere otra vulnerabilidad para ser explotada |
| `BAJO` | Exposición de información, fingerprinting |
| `INFO` | Contexto, sin impacto de seguridad directo |

La correlación de CVEs (`version_cve_db` en el JSON) es una señal de "revisa esto primero", no una confirmación de explotabilidad — siempre verifica versión exacta y contexto antes de reportarlo como hallazgo confirmado.

## Arquitectura

Cada archivo se procesa en **un solo recorrido de sus líneas**. Antes de ese recorrido, una detección barata (una pasada de regex sobre el texto completo) decide qué "familias" de herramientas activar línea por línea, evitando aplicar reglas de una herramienta a la salida de otra.

Las reglas de las herramientas Tier 1/2 viven en `reportsee_signatures.json`, no en el código — agregar soporte a una herramienta nueva es agregar un bloque JSON, no tocar Python. Ver la estructura de reglas existentes como referencia.

## Extender con una herramienta nueva

Agrega un bloque a `reportsee_signatures.json`:

```json
{
  "name": "nombre_herramienta",
  "detect_regex": "patron que identifica la salida de esta herramienta",
  "rules": [
    {
      "regex": "patron con grupos de captura",
      "severity": "ALTO",
      "category": "Categoria",
      "title": "Título usando {1} para el grupo 1",
      "detail": "Detalle usando {1}, {2}, etc."
    }
  ]
}
```

## Roadmap

- [ ] Soporte a `nuclei` (salida JSON lines)
- [ ] Soporte a `masscan` / `rustscan`
- [ ] Modo `--dir` para procesar carpetas completas de loot
- [ ] Export a formato SysReptor

## Licencia

MIT — ver [LICENSE](LICENSE).
