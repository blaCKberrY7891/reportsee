#!/usr/bin/env python3
"""
ReportSee v3 - Motor profesional de analisis de reconocimiento
=================================================================
Lee salidas RAW de herramientas de Kali Linux y las normaliza en
hallazgos con severidad estandarizada.

Herramientas soportadas:
  - nmap, gobuster, feroxbuster, dirb, ffuf, wfuzz (motor propio)
  - nikto, hydra, sqlmap, John the Ripper (motor propio)
  - enum4linux, smbmap/smbclient, crackmapexec/netexec, hashcat,
    whatweb, wpscan, dnsrecon/dnsenum, searchsploit (via reglas
    externas en reportsee_signatures.json)

Uso:
    python3 reportsee.py escaneo1.txt [escaneo2.txt ...]
    python3 reportsee.py escaneo.txt --export-md reporte.md
    python3 reportsee.py escaneo.txt --no-color
    python3 reportsee.py escaneo.txt --signatures ruta/personalizada.json

Arquitectura: cada archivo se procesa en UN SOLO recorrido de sus
lineas. Antes de ese recorrido se hace una deteccion barata (una
pasada de regex sobre el texto completo) para saber que "familias"
de herramientas activar linea por linea, evitando aplicar reglas de
una herramienta a la salida de otra. Las reglas de las herramientas
Tier 1/2 viven en reportsee_signatures.json, no en este archivo, asi
que agregar soporte a una herramienta nueva no requiere tocar codigo.
"""

import sys
import re
import os
import json
import argparse
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict


# =====================================================================
# ESTILOS ANSI (sin emojis, salida orientada a entorno profesional)
# =====================================================================
class C:
    HEADER = '\033[95m\033[1m'
    BLUE = '\033[94m\033[1m'
    GREEN = '\033[92m\033[1m'
    YELLOW = '\033[93m\033[1m'
    RED = '\033[91m\033[1m'
    MAGENTA = '\033[35m\033[1m'
    CYAN = '\033[96m\033[1m'
    WHITE = '\033[97m\033[1m'
    GRAY = '\033[90m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


def disable_colors():
    for attr in list(vars(C).keys()):
        if not attr.startswith('_'):
            setattr(C, attr, '')


# =====================================================================
# SEVERIDAD ESTANDARIZADA
# =====================================================================
#   CRITICO -> RCE confirmado / credenciales validas / exploit publico activo
#   ALTO    -> vulnerabilidad conocida sin RCE directo confirmado, o
#              exposicion que facilita movimiento lateral
#   MEDIO   -> debilidad de configuracion que requiere otra vulnerabilidad
#              para ser explotada (ej. cookie sin HttpOnly)
#   BAJO    -> exposicion de informacion, fingerprinting
#   INFO    -> contexto, sin impacto de seguridad directo
SEVERITY_ORDER = ["CRITICO", "ALTO", "MEDIO", "BAJO", "INFO"]
SEVERITY_COLOR = {
    "CRITICO": C.MAGENTA,
    "ALTO": C.RED,
    "MEDIO": C.YELLOW,
    "BAJO": C.CYAN,
    "INFO": C.BLUE,
}
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    detail: str
    source: str = ""
    line: int = 0
    ref: str = ""


@dataclass
class ScanData:
    filename: str
    target_ips: set = field(default_factory=set)
    detected_os: set = field(default_factory=set)
    uptime_info: str = ""
    nmap_services: list = field(default_factory=list)
    web_titles: set = field(default_factory=set)
    http_methods: set = field(default_factory=set)
    server_headers: set = field(default_factory=set)
    cpes: set = field(default_factory=set)
    ssh_keys: list = field(default_factory=list)
    web_endpoints: list = field(default_factory=list)
    found_creds: list = field(default_factory=list)
    traceroute_hops: list = field(default_factory=list)
    found_cves: set = field(default_factory=set)
    findings: list = field(default_factory=list)
    tools_detected: set = field(default_factory=set)

    def add(self, severity, category, title, detail, source="", line=0, ref=""):
        self.findings.append(Finding(severity, category, title, detail, source, line, ref))


# =====================================================================
# CARGA DE REGLAS EXTERNAS (reportsee_signatures.json)
# =====================================================================

def load_signatures(custom_path=None):
    sig_path = Path(custom_path) if custom_path else \
        Path(__file__).resolve().parent / "reportsee_signatures.json"
    empty = {"version_cve_db": [], "tools": []}

    if not sig_path.exists():
        print(f"{C.YELLOW}[!] Aviso: no se encontro '{sig_path}'. La correlacion de CVEs "
              f"y los parsers de enum4linux/smbmap/crackmapexec/hashcat/whatweb/wpscan/"
              f"dnsrecon/searchsploit quedan desactivados; nmap, fuzzing web, nikto, "
              f"hydra, sqlmap y John siguen funcionando normal.{C.ENDC}\n", file=sys.stderr)
        return empty

    try:
        with open(sig_path, 'r', encoding='utf-8') as f:
            raw = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"{C.RED}[!] Error leyendo '{sig_path}': {e}. Se ignoran esas reglas.{C.ENDC}\n",
              file=sys.stderr)
        return empty

    for entry in raw.get('version_cve_db', []):
        try:
            entry['_compiled'] = re.compile(entry['pattern'], re.I)
        except re.error as e:
            print(f"{C.YELLOW}[!] Regla de correlacion CVE invalida ('{entry.get('title')}'): "
                  f"{e}. Se omite.{C.ENDC}", file=sys.stderr)
            entry['_compiled'] = None

    for tool_cfg in raw.get('tools', []):
        try:
            tool_cfg['_detect_re'] = re.compile(tool_cfg['detect_regex'], re.I)
        except re.error as e:
            print(f"{C.YELLOW}[!] Regex de deteccion invalido para '{tool_cfg.get('name')}': "
                  f"{e}. Se omite esta herramienta.{C.ENDC}", file=sys.stderr)
            tool_cfg['_detect_re'] = None
        for rule in tool_cfg.get('rules', []):
            try:
                rule['_compiled'] = re.compile(rule['regex'], re.I)
            except re.error as e:
                print(f"{C.YELLOW}[!] Regla invalida en '{tool_cfg.get('name')}': {e}. "
                      f"Se omite esa regla.{C.ENDC}", file=sys.stderr)
                rule['_compiled'] = None

    return raw


SIGNATURES = load_signatures()

HTTP_DANGEROUS_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT"}

# Se evito a proposito incluir terminos genericos como "success" (aparece en
# outputs de exito normales, ej. "connection success") porque generan
# demasiado ruido.
CRITICAL_KEYWORDS = [
    'vulnerable', 'vulnerability', 'rce', 'remote code execution',
    'sql injection', 'sqli', 'lfi', 'rfi', 'xxe', 'ssrf',
    'backdoor', 'exploit found', 'privilege escalation', 'buffer overflow',
    'authentication bypass', 'directory traversal', 'command injection',
]


# =====================================================================
# REGEX MODULARES (compilados UNA sola vez al importar el modulo)
# =====================================================================

RE_IP = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
RE_CVE = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.I)
RE_CPE = re.compile(r'cpe:/[a-z0-9:\._\-]+', re.I)

# --- Deteccion de herramienta a nivel de archivo completo (una sola pasada
# de regex.search sobre raw_text, no un loop linea por linea) ---
NMAP_DETECT_RE = re.compile(r'Nmap scan report for|Starting Nmap|PORT\s+STATE\s+SERVICE', re.I)
NIKTO_DETECT_RE = re.compile(r'Nikto\s*v?[\d.]+', re.I)
HYDRA_DETECT_RE = re.compile(r'Hydra v|\[\d+\]\[\w+\]\s+host:', re.I)
SQLMAP_DETECT_RE = re.compile(r'sqlmap resumed|Parameter:\s*\S+\s*\([A-Za-z]+\)', re.I)
JOHN_DETECT_RE = re.compile(r'Loaded\s+\d+\s+password hash', re.I)

# --- nmap ---
NMAP_TARGET_RE = re.compile(r'Nmap scan report for (?:[a-zA-Z0-9.\-]+ \()?((?:\d{1,3}\.){3}\d{1,3})\)?')
TTL_RE = re.compile(r'ttl\s+(\d+)', re.I)
PORT_RE = re.compile(r'^(\d{1,5}/(?:tcp|udp))\s+(open|closed|filtered)\s+(\S+)\s*(.*)$')
TRACEROUTE_HOP_RE = re.compile(r'^\s*(\d+)\s+([\d.]+\s*ms|\.\.\.)\s*((?:\d{1,3}\.){3}\d{1,3})?')
OS_INFO_RE = re.compile(r'Service Info:\s*OS:\s*([^;]+)', re.I)
TITLE_RE = re.compile(r'\|_?\s*http-title:\s*(.+)', re.I)
METHODS_RE = re.compile(r'Supported Methods:\s*(.+)', re.I)
SERVER_HDR_RE = re.compile(r'\|_?http-server-header:\s*(.+)', re.I)
SSH_KEY_RE = re.compile(r'\|_(ssh-[a-z0-9\-]+|ecdsa-[a-z0-9\-]+)\s+([A-Za-z0-9+/=]+)')
UPTIME_RE = re.compile(r'Uptime guess:\s*(.+)', re.I)
ANON_FTP_RE = re.compile(r'Anonymous FTP login allowed', re.I)
SMB_SIG_RE = re.compile(r'message_signing:\s*disabled', re.I)
# nmap con -v/-vv agrega una columna REASON (ej. "syn-ack ttl 62") entre
# SERVICE y VERSION que no existe en un scan sin -v; se recorta si aparece.
REASON_PREFIX_RE = re.compile(
    r'^(?:syn-ack|reset|no-response|conn-refused|echo-reply)(?:\s+ttl\s+\d+)?\s+', re.I)

# --- fuzzing web: gobuster / feroxbuster / dirb / ffuf / wfuzz ---
FUZZ_PATTERNS = [
    ("feroxbuster",
     re.compile(r'^(\d{3})\s+(GET|POST|HEAD|PUT|DELETE)\s+\d+l\s+\d+w\s+(\d+)c\s+(\S+)\s*$'),
     lambda m: (m.group(4), m.group(1), m.group(3))),
    ("gobuster",
     re.compile(r'^(/\S*)\s+\(Status:\s*(\d{3})\)\s*\[Size:\s*(\d+)\]'),
     lambda m: (m.group(1), m.group(2), m.group(3))),
    ("dirb",
     re.compile(r'^\+\s+(\S+)\s+\(CODE:(\d{3})\|SIZE:(\d+)\)'),
     lambda m: (m.group(1), m.group(2), m.group(3))),
    ("ffuf",
     re.compile(r'^(\S+)\s+\[Status:\s*(\d{3}),\s*Size:\s*(\d+)'),
     lambda m: (m.group(1), m.group(2), m.group(3))),
    ("wfuzz",
     re.compile(r'^\d+:\s+(\d{3})\s+\d+\s+L\s+\d+\s+W\s+(\d+)\s+Ch\s+"(.+)"\s*$'),
     lambda m: (m.group(3), m.group(1), m.group(2))),
]

# --- nikto ---
NIKTO_ELEVATE_RE = re.compile(r'rce|inject|traversal|shell|execute|upload|backdoor', re.I)
NIKTO_SKIP_PREFIXES = ('+ Target', '+ Start', '+ Server:', '+ End')

# --- hydra ---
HYDRA_HIT_RE = re.compile(
    r'\[(\d+)]\[(\w+)]\s+host:\s*(\S+)\s+login:\s*(\S+)\s+password:\s*(\S+)', re.I)

# --- John the Ripper ---
JOHN_CRACKED_RE = re.compile(r'^(\S+)\s+\(([^)]+)\)\s*$')
JOHN_SKIP_VALUES = {'password', 'hashes', 'guesses'}

# --- credenciales genericas / cookies (multi-linea) ---
CRED_GENERIC_RE = re.compile(
    r'(?:login|user|username|account):\s*(\S+)\s+(?:password|pass):\s*(\S+)', re.I)
COOKIE_HTTPONLY_RE = re.compile(
    r'([A-Za-z0-9_\-]+):\s*\n\s*\|_\s*httponly flag not set', re.I)

# --- sqlmap (multi-linea, bloques Parameter:/Type:) ---
SQLMAP_PARAM_RE = re.compile(r'^Parameter:\s*(\S+)\s*\(([A-Za-z]+)\)', re.M)
SQLMAP_TYPE_RE = re.compile(r'Type:\s*(.+)')
SQLMAP_DBMS_RE = re.compile(r'back-end DBMS:\s*(.+)', re.I)


def clean_hex_title(text):
    def replace_hex(match):
        hex_bytes = bytes.fromhex(match.group(0).replace(r'\x', ''))
        try:
            return hex_bytes.decode('utf-8')
        except UnicodeDecodeError:
            return match.group(0)
    return re.sub(r'(\\x[0-9a-fA-F]{2})+', replace_hex, text)


def get_status_color(code):
    if code.startswith('2'): return f"{C.GREEN}{code}{C.ENDC}"
    elif code.startswith('3'): return f"{C.CYAN}{code}{C.ENDC}"
    elif code.startswith('4'): return f"{C.YELLOW}{code}{C.ENDC}"
    elif code.startswith('5'): return f"{C.RED}{code}{C.ENDC}"
    return f"{C.WHITE}{code}{C.ENDC}"


def _format_template(template, m):
    """Sustituye {1}, {2}, ... por los grupos capturados de un match."""
    if not template:
        return ""

    def repl(mm):
        idx = int(mm.group(1))
        try:
            return m.group(idx) or ""
        except (IndexError, re.error):
            return ""

    return re.sub(r'\{(\d+)\}', repl, template)


def _correlate_version(text_blob, data: ScanData, source="", line=0):
    for entry in SIGNATURES.get('version_cve_db', []):
        compiled = entry.get('_compiled')
        if compiled and compiled.search(text_blob):
            data.add(entry['severity'], "Correlacion CVE", entry['title'], entry['detail'],
                      source=source, line=line, ref=entry.get('cve', ''))
            if entry.get('cve'):
                data.found_cves.add(entry['cve'])


def emit_json_finding(data: ScanData, tool_name, rule, m, lnum):
    title = _format_template(rule.get('title', ''), m) or tool_name
    detail = _format_template(rule.get('detail', ''), m)
    data.add(rule['severity'], rule.get('category', tool_name), title, detail,
              source=tool_name, line=lnum, ref=rule.get('cve', ''))
    if rule.get('cve'):
        data.found_cves.add(rule['cve'])


# =====================================================================
# HANDLERS POR LINEA (cada uno procesa UNA linea; se llaman dentro del
# unico recorrido principal en analyze_file)
# =====================================================================

def handle_nmap_line(line, lnum, data: ScanData, state):
    if not line.startswith('#'):
        m = NMAP_TARGET_RE.search(line)
        if m:
            data.target_ips.add(m.group(1))

    m = TTL_RE.search(line)
    if m:
        ttl_val = int(m.group(1))
        # Heuristica estandar: Linux/Unix arrancan TTL en 64, Windows en 128,
        # equipos de red en 255. Como el TTL baja 1 por salto, es una
        # estimacion, no una certeza.
        if ttl_val <= 64:
            data.detected_os.add(f"Linux/Unix (estimado por TTL={ttl_val})")
        elif ttl_val <= 128:
            data.detected_os.add(f"Windows (estimado por TTL={ttl_val})")
        else:
            data.detected_os.add(f"Red/Embebido - Cisco u otro (estimado por TTL={ttl_val})")

    m = UPTIME_RE.search(line)
    if m:
        data.uptime_info = m.group(1).strip()

    if "TRACEROUTE" in line:
        state['in_traceroute'] = True
        return
    if state.get('in_traceroute'):
        m = TRACEROUTE_HOP_RE.search(line)
        if m:
            hop_num, rtt, hop_ip = m.groups()
            data.traceroute_hops.append((hop_num, rtt, hop_ip or "---"))
        elif "OS and Service detection" in line or line.startswith('#'):
            state['in_traceroute'] = False

    m = PORT_RE.match(line)
    if m:
        port_proto, port_state, service, version_info = m.groups()
        ver_clean = REASON_PREFIX_RE.sub('', version_info.strip()).strip()
        if not ver_clean:
            ver_clean = "Sin version detectada"
        data.nmap_services.append((port_proto, port_state.upper(), service, ver_clean))

        ver_lower = ver_clean.lower()
        if "apache" in ver_lower and "http" in service.lower():
            data.add("MEDIO", "Web", f"{port_proto} - Apache HTTP",
                      f"Apache detectado ({ver_clean}). Iniciar fuzzing de directorios y "
                      f"revisar vhosts / archivos de configuracion expuestos.",
                      source="nmap", line=lnum)
        elif "ssh" in service.lower():
            data.add("INFO", "SSH", f"{port_proto} - SSH",
                      f"OpenSSH detectado ({ver_clean}). Considerar enumeracion de usuarios "
                      f"si la version es < 7.7, y fuerza bruta como ultimo recurso.",
                      source="nmap", line=lnum)

        _correlate_version(f"{service} {ver_clean} {port_proto}", data, source="nmap", line=lnum)

    m = OS_INFO_RE.search(line)
    if m:
        data.detected_os.add(m.group(1).strip())

    m = TITLE_RE.search(line)
    if m:
        raw_title = m.group(1).strip()
        if "doesn't have a title" not in raw_title.lower():
            data.web_titles.add(clean_hex_title(raw_title))

    m = METHODS_RE.search(line)
    if m:
        methods_str = m.group(1).strip()
        data.http_methods.add(methods_str)
        found_dangerous = {mth.strip().upper() for mth in re.split(r'[,\s]+', methods_str)
                            if mth.strip().upper() in HTTP_DANGEROUS_METHODS}
        if found_dangerous:
            data.add("ALTO", "Web", "Metodos HTTP peligrosos habilitados",
                      f"El servidor acepta: {', '.join(sorted(found_dangerous))}. "
                      f"PUT/DELETE pueden permitir subir o borrar archivos (webshell); "
                      f"TRACE puede facilitar XST. Confirmar con curl -X OPTIONS.",
                      source="nmap", line=lnum)

    m = SERVER_HDR_RE.search(line)
    if m:
        data.server_headers.add(m.group(1).strip())

    for cpe in RE_CPE.findall(line):
        data.cpes.add(cpe)

    m = SSH_KEY_RE.search(line)
    if m:
        ktype, kdata = m.groups()
        data.ssh_keys.append((ktype, kdata[:35] + "..."))

    if ANON_FTP_RE.search(line):
        data.add("ALTO", "FTP", "FTP anonimo habilitado",
                  "El servidor FTP permite login anonimo. Revisar archivos accesibles y "
                  "permisos de escritura (posible pivote a webshell si hay docroot compartido).",
                  source="nmap", line=lnum)

    if SMB_SIG_RE.search(line):
        data.add("MEDIO", "SMB", "SMB signing deshabilitado",
                  "Sin firma SMB, el trafico es susceptible a ataques de relay "
                  "(ej. NTLM relay con Responder/ntlmrelayx).",
                  source="nmap", line=lnum)


def handle_fuzzing_line(line, lnum, data: ScanData):
    stripped = line.strip()
    if not stripped or stripped.startswith('='):
        return
    for tool_name, pattern, extract in FUZZ_PATTERNS:
        m = pattern.match(stripped)
        if m:
            path, status, size = extract(m)
            data.web_endpoints.append((tool_name, path, status, size, lnum))
            data.tools_detected.add(tool_name)
            if status.startswith('5'):
                data.add("BAJO", "Web", f"Error de servidor en {path}",
                          f"Status {status} devuelto por {tool_name}. Puede indicar un "
                          f"input mal manejado (posible punto de fuzzing mas profundo).",
                          source=tool_name, line=lnum)
            return


def handle_nikto_line(line, lnum, data: ScanData):
    if not line.startswith('+') or line.startswith(NIKTO_SKIP_PREFIXES):
        return
    detail = line.lstrip('+ ').strip()
    if not detail:
        return
    sev = "ALTO" if NIKTO_ELEVATE_RE.search(detail) else "MEDIO"
    data.add(sev, "Nikto", detail[:70], detail, source="nikto", line=lnum)
    for cve in RE_CVE.findall(detail):
        data.found_cves.add(cve.upper())


def handle_hydra_line(line, lnum, data: ScanData):
    m = HYDRA_HIT_RE.search(line)
    if m:
        port, service, host, user, pwd = m.groups()
        data.found_creds.append((f"hydra/{service}", user, pwd, lnum))
        data.add("CRITICO", "Credenciales", f"Credencial valida por fuerza bruta ({service})",
                  f"Host {host}:{port} - usuario '{user}' / password '{pwd}'. "
                  f"Confirmar acceso real antes de reportar como explotado.",
                  source="hydra", line=lnum)


def handle_john_line(line, lnum, data: ScanData):
    m = JOHN_CRACKED_RE.match(line)
    if m:
        pwd, user = m.groups()
        if pwd.lower() in JOHN_SKIP_VALUES:
            return
        data.found_creds.append(("john", user, pwd, lnum))
        data.add("CRITICO", "Credenciales", f"Hash crackeado: {user}",
                  f"John the Ripper recupero la contrasena en texto plano: '{pwd}'.",
                  source="john", line=lnum)


def handle_generic_line(line, lnum, data: ScanData):
    if line.startswith('#'):
        return
    m = CRED_GENERIC_RE.search(line)
    if m:
        data.found_creds.append(("generico", m.group(1), m.group(2), lnum))

    for cve in RE_CVE.findall(line):
        data.found_cves.add(cve.upper())

    line_lower = line.lower()
    if any(kw in line_lower for kw in CRITICAL_KEYWORDS):
        data.add("ALTO", "Hallazgo textual", line[:70], line, source="generico", line=lnum)


def parse_sqlmap_blocks(raw_text, data: ScanData):
    for pm in SQLMAP_PARAM_RE.finditer(raw_text):
        pname, ptype = pm.groups()
        window = raw_text[pm.end():pm.end() + 400]
        type_m = SQLMAP_TYPE_RE.search(window)
        inj_type = type_m.group(1).strip() if type_m else "no especificado"
        data.add("CRITICO", "SQLi", f"Parametro inyectable: {pname} ({ptype})",
                  f"Tecnica de inyeccion: {inj_type}. sqlmap confirmo explotabilidad.",
                  source="sqlmap")
    dbms_m = SQLMAP_DBMS_RE.search(raw_text)
    if dbms_m:
        data.add("INFO", "SQLi", "DBMS identificado", dbms_m.group(1).strip(), source="sqlmap")


def handle_cookie_blocks(raw_text, data: ScanData):
    for cookie_m in COOKIE_HTTPONLY_RE.finditer(raw_text):
        c_name = cookie_m.group(1)
        # MEDIO, no ALTO: sin un XSS que la explote, la falta de HttpOnly no
        # compromete nada por si sola.
        data.add("MEDIO", "Web", f"Cookie sin HttpOnly ({c_name})",
                  f"La cookie '{c_name}' no tiene el atributo HttpOnly. Aumenta el impacto "
                  f"de un XSS existente (permitiria robo de sesion via document.cookie), "
                  f"pero no es explotable por si sola.", source="nmap/nikto")


# =====================================================================
# MOTOR PRINCIPAL: un solo recorrido de lineas por archivo
# =====================================================================

def analyze_file(path, signatures=None) -> ScanData:
    sigs = signatures if signatures is not None else SIGNATURES
    full_path = os.path.abspath(os.path.expanduser(path))
    data = ScanData(filename=full_path)

    if not os.path.exists(full_path):
        print(f"\n{C.RED}[!] Error: No se encuentra el archivo en:{C.ENDC} {C.YELLOW}{full_path}{C.ENDC}")
        return None
    if not os.path.isfile(full_path):
        print(f"\n{C.RED}[!] Error: '{full_path}' es un directorio, no un archivo.{C.ENDC}")
        return None

    try:
        with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"{C.RED}[!] Error al leer el archivo: {e}{C.ENDC}")
        return None

    raw_text = "".join(lines)

    # --- Deteccion barata de "familias" de herramientas (una pasada de
    # regex.search por herramienta sobre el texto completo, no un loop) ---
    tool_active = {
        'nmap': bool(NMAP_DETECT_RE.search(raw_text)),
        'nikto': bool(NIKTO_DETECT_RE.search(raw_text)),
        'hydra': bool(HYDRA_DETECT_RE.search(raw_text)),
        'sqlmap': bool(SQLMAP_DETECT_RE.search(raw_text)),
        'john': bool(JOHN_DETECT_RE.search(raw_text)),
    }
    for name, active in tool_active.items():
        if active:
            data.tools_detected.add(name)

    # --- Deteccion de herramientas Tier 1/2 definidas en el JSON externo ---
    active_json_rules = []
    for tool_cfg in sigs.get('tools', []):
        detect_re = tool_cfg.get('_detect_re')
        if detect_re and detect_re.search(raw_text):
            data.tools_detected.add(tool_cfg['name'])
            for rule in tool_cfg.get('rules', []):
                if rule.get('_compiled'):
                    active_json_rules.append((rule['_compiled'], tool_cfg['name'], rule))

    # --- Un solo recorrido de lineas ---
    state = {'in_traceroute': False}
    for lnum, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line:
            continue

        if tool_active['nmap']:
            handle_nmap_line(line, lnum, data, state)

        handle_fuzzing_line(line, lnum, data)

        if tool_active['nikto']:
            handle_nikto_line(line, lnum, data)

        if tool_active['hydra']:
            handle_hydra_line(line, lnum, data)

        if tool_active['john']:
            handle_john_line(line, lnum, data)

        for compiled_re, tool_name, rule in active_json_rules:
            m = compiled_re.search(line)
            if m:
                emit_json_finding(data, tool_name, rule, m, lnum)

        handle_generic_line(line, lnum, data)

    # --- Pasadas adicionales, ligeras, sobre el texto completo (patrones
    # inherentemente multi-linea que no caben en un handler por linea) ---
    if tool_active['sqlmap']:
        parse_sqlmap_blocks(raw_text, data)
    handle_cookie_blocks(raw_text, data)

    if not data.target_ips:
        for ip in RE_IP.findall('\n'.join(lines[:10])):
            if not ip.startswith('127.0.0.'):
                data.target_ips.add(ip)

    # --- Dedup de findings identicos ---
    seen = set()
    unique_findings = []
    for f_ in data.findings:
        key = (f_.severity, f_.category, f_.title, f_.detail)
        if key not in seen:
            seen.add(key)
            unique_findings.append(f_)
    data.findings = sorted(unique_findings, key=lambda f_: SEVERITY_RANK.get(f_.severity, 99))

    # --- Dedup de credenciales identicas, priorizando la fuente especifica
    # (hydra/john) sobre el parser generico ---
    seen_creds = {}
    for source, u, p, lnum in data.found_creds:
        key = (u, p)
        if key not in seen_creds or seen_creds[key][0] == "generico":
            seen_creds[key] = (source, u, p, lnum)
    data.found_creds = list(seen_creds.values())

    return data


# =====================================================================
# PRESENTACION EN TERMINAL (sin emojis; cajas con padding calculado
# dinamicamente para que no se rompan con nombres de archivo largos)
# =====================================================================

BOX_WIDTH = 76


def _box_top():
    return f"{C.CYAN}+{'-' * BOX_WIDTH}+{C.ENDC}"


def _box_bottom():
    return f"{C.CYAN}+{'-' * BOX_WIDTH}+{C.ENDC}"


def _box_sep():
    return f"{C.CYAN}+{'-' * BOX_WIDTH}+{C.ENDC}"


def _box_line(text_plain):
    if len(text_plain) > BOX_WIDTH:
        text_plain = text_plain[:BOX_WIDTH - 3] + "..."
    pad = BOX_WIDTH - len(text_plain)
    return f"{C.CYAN}|{C.ENDC}{C.BOLD}{text_plain}{C.ENDC}{' ' * pad}{C.CYAN}|{C.ENDC}"


def banner(filename, total_lines, tools):
    tools_str = ", ".join(sorted(tools)) if tools else "no identificadas"
    print()
    print(_box_top())
    print(_box_line(" REPORTSEE v3 - MOTOR DE ANALISIS DE RECONOCIMIENTO"))
    print(_box_sep())
    print(_box_line(f" Archivo: {os.path.basename(filename)}"))
    print(_box_line(f" Lineas analizadas: {total_lines}"))
    print(_box_line(f" Herramientas detectadas: {tools_str}"))
    print(_box_bottom())
    print()


def _section(title):
    print(f"{C.HEADER}--[ {title} ]{C.ENDC}")


def _section_end():
    print(f"{C.HEADER}{'-' * 72}{C.ENDC}\n")


def print_report(data: ScanData, total_lines):
    banner(data.filename, total_lines, data.tools_detected)

    # Resumen ejecutivo
    counts = defaultdict(int)
    for f_ in data.findings:
        counts[f_.severity] += 1
    _section("RESUMEN EJECUTIVO")
    for sev in SEVERITY_ORDER:
        if counts[sev]:
            col = SEVERITY_COLOR[sev]
            print(f"  {col}{sev:<8}{C.ENDC} : {counts[sev]}")
    if not data.findings:
        print(f"  {C.GRAY}Sin hallazgos clasificados en este archivo.{C.ENDC}")
    _section_end()

    # Target y entorno base
    _section("TARGET OBJETIVO Y ENTORNO BASE")
    for ip in sorted(data.target_ips):
        print(f"  - {C.BOLD}IP Objetivo:{C.ENDC} {C.YELLOW}{ip}{C.ENDC}")
    for os_info in data.detected_os:
        print(f"  - {C.BOLD}Sistema Operativo:{C.ENDC} {C.GREEN}{os_info}{C.ENDC}")
    if data.uptime_info:
        print(f"  - {C.BOLD}Uptime:{C.ENDC} {C.WHITE}{data.uptime_info}{C.ENDC}")
    _section_end()

    # Hallazgos
    if data.findings:
        _section(f"HALLAZGOS ({len(data.findings)})")
        for f_ in data.findings:
            col = SEVERITY_COLOR.get(f_.severity, C.WHITE)
            ref = f" {C.GRAY}[{f_.ref}]{C.ENDC}" if f_.ref else ""
            loc = f" L{f_.line}" if f_.line else ""
            print(f"  [{col}{f_.severity:<8}{C.ENDC}] {C.BOLD}{f_.category:<18}{C.ENDC}{loc}{ref}")
            print(f"      {C.BOLD}{f_.title}{C.ENDC}")
            print(f"      {C.GRAY}{f_.detail}{C.ENDC}")
        _section_end()

    # Puertos y servicios
    if data.nmap_services:
        _section(f"PUERTOS Y SERVICIOS ({len(data.nmap_services)})")
        print(f"  {C.BOLD}{'PUERTO':<12} {'ESTADO':<10} {'SERVICIO':<12} VERSION{C.ENDC}")
        print("  " + "-" * 69)
        for port, port_state, srv, ver in data.nmap_services:
            st_color = C.GREEN if port_state == "OPEN" else C.RED
            print(f"  {C.BOLD}{port:<12}{C.ENDC} {st_color}{port_state:<10}{C.ENDC} "
                  f"{C.CYAN}{srv:<12}{C.ENDC} {C.WHITE}{ver}{C.ENDC}")
        _section_end()

    # Aplicacion web
    if data.web_titles or data.http_methods or data.server_headers:
        _section("APLICACION WEB")
        for title in data.web_titles:
            print(f"  - {C.BOLD}Titulo:{C.ENDC} {C.CYAN}{title}{C.ENDC}")
        for hdr in data.server_headers:
            print(f"  - {C.BOLD}Server header:{C.ENDC} {C.WHITE}{hdr}{C.ENDC}")
        for mth in data.http_methods:
            print(f"  - {C.BOLD}Metodos aceptados:{C.ENDC} {C.YELLOW}{mth}{C.ENDC}")
        _section_end()

    # Rutas de fuzzing
    if data.web_endpoints:
        _section(f"RUTAS ENCONTRADAS ({len(data.web_endpoints)})")
        for tool_name, path, status, size, lnum in data.web_endpoints:
            print(f"  L{lnum:<5} [{get_status_color(status)}] {C.GRAY}{size:<8}{C.ENDC} "
                  f"{C.MAGENTA}{tool_name:<12}{C.ENDC} {C.WHITE}{path}{C.ENDC}")
        _section_end()

    # Credenciales
    if data.found_creds:
        _section("CREDENCIALES DETECTADAS")
        for source, u, p, lnum in data.found_creds:
            loc = f"L{lnum}" if lnum else "  -  "
            print(f"  {loc:<6} [{C.MAGENTA}{source}{C.ENDC}] {C.BOLD}user:{C.ENDC} "
                  f"{C.GREEN}{u}{C.ENDC} {C.BOLD}pass:{C.ENDC} {C.RED}{p}{C.ENDC}")
        _section_end()

    # CPEs / llaves
    if data.cpes or data.ssh_keys:
        _section("IDENTIFICADORES Y LLAVES")
        for cpe in sorted(data.cpes):
            print(f"  - {C.BOLD}CPE:{C.ENDC} {C.GRAY}{cpe}{C.ENDC}")
        for ktype, kdata in data.ssh_keys:
            print(f"  - {C.BOLD}SSH ({ktype}):{C.ENDC} {C.GRAY}{kdata}{C.ENDC}")
        _section_end()

    # Traceroute
    if data.traceroute_hops:
        _section("TRACEROUTE")
        for hop, rtt, ip in data.traceroute_hops:
            print(f"  Hop {hop:<2} | RTT: {C.GRAY}{rtt:<10}{C.ENDC} | IP: {C.BLUE}{ip}{C.ENDC}")
        _section_end()

    # CVEs referenciados
    if data.found_cves:
        _section("CVES REFERENCIADOS")
        for cve in sorted(data.found_cves):
            print(f"  - {C.RED}{cve}{C.ENDC}")
        _section_end()


# =====================================================================
# EXPORT MARKDOWN (estilo OSCP)
# =====================================================================

def export_markdown(all_data, out_path):
    lines_out = []
    lines_out.append("# Reporte de Reconocimiento\n")
    lines_out.append(f"_Generado: {datetime.now().strftime('%Y-%m-%d %H:%M')}_\n")

    lines_out.append("## Resumen ejecutivo\n")
    total_counts = defaultdict(int)
    for data in all_data:
        for f_ in data.findings:
            total_counts[f_.severity] += 1
    for sev in SEVERITY_ORDER:
        if total_counts[sev]:
            lines_out.append(f"- **{sev}**: {total_counts[sev]}")
    lines_out.append("")

    for data in all_data:
        lines_out.append(f"## Archivo: `{os.path.basename(data.filename)}`\n")
        if data.target_ips:
            lines_out.append("**Objetivos:** " + ", ".join(sorted(data.target_ips)) + "\n")
        if data.detected_os:
            lines_out.append("**SO estimado:** " + "; ".join(sorted(data.detected_os)) + "\n")
        if data.tools_detected:
            lines_out.append("**Herramientas detectadas:** " +
                              ", ".join(sorted(data.tools_detected)) + "\n")

        if data.findings:
            lines_out.append("### Hallazgos\n")
            lines_out.append("| Severidad | Categoria | Titulo | Referencia |")
            lines_out.append("|---|---|---|---|")
            for f_ in data.findings:
                ref = f_.ref if f_.ref else "-"
                lines_out.append(f"| {f_.severity} | {f_.category} | {f_.title} | {ref} |")
            lines_out.append("")
            lines_out.append("#### Detalle\n")
            for f_ in data.findings:
                lines_out.append(f"**[{f_.severity}] {f_.title}** (fuente: {f_.source or 'n/a'})")
                lines_out.append(f"> {f_.detail}\n")

        if data.nmap_services:
            lines_out.append("### Puertos y servicios\n")
            lines_out.append("| Puerto | Estado | Servicio | Version |")
            lines_out.append("|---|---|---|---|")
            for port, port_state, srv, ver in data.nmap_services:
                lines_out.append(f"| {port} | {port_state} | {srv} | {ver} |")
            lines_out.append("")

        if data.web_endpoints:
            lines_out.append("### Rutas encontradas (fuzzing)\n")
            lines_out.append("| Herramienta | Ruta | Status | Tamano |")
            lines_out.append("|---|---|---|---|")
            for tool_name, path, status, size, lnum in data.web_endpoints:
                lines_out.append(f"| {tool_name} | {path} | {status} | {size} |")
            lines_out.append("")

        if data.found_creds:
            lines_out.append("### Credenciales detectadas\n")
            lines_out.append("| Fuente | Usuario | Password |")
            lines_out.append("|---|---|---|")
            for source, u, p, _lnum in data.found_creds:
                lines_out.append(f"| {source} | {u} | {p} |")
            lines_out.append("")

    with open(out_path, 'w', encoding='utf-8') as f:
        f.write("\n".join(lines_out))


def main():
    parser = argparse.ArgumentParser(
        description="ReportSee v3 - Analiza salidas de herramientas de Kali Linux")
    parser.add_argument("files", nargs='+', help="Archivo(s) .txt de salida de herramientas")
    parser.add_argument("--export-md", metavar="ARCHIVO.md",
                         help="Exportar reporte consolidado en Markdown")
    parser.add_argument("--no-color", action="store_true", help="Desactivar colores ANSI")
    parser.add_argument("--signatures", metavar="ARCHIVO.json",
                         help="Ruta alterna a reportsee_signatures.json")
    args = parser.parse_args()

    if args.no_color:
        disable_colors()

    sigs = SIGNATURES
    if args.signatures:
        sigs = load_signatures(args.signatures)

    all_data = []
    for path in args.files:
        try:
            with open(os.path.abspath(os.path.expanduser(path)), 'r',
                      encoding='utf-8', errors='ignore') as f:
                total_lines = len(f.readlines())
        except OSError:
            total_lines = 0
        data = analyze_file(path, signatures=sigs)
        if data is None:
            continue
        print_report(data, total_lines)
        all_data.append(data)

    if args.export_md and all_data:
        export_markdown(all_data, args.export_md)
        print(f"{C.GREEN}[+] Reporte Markdown exportado a: {args.export_md}{C.ENDC}\n")


if __name__ == '__main__':
    main()
