# modules/scan_network.py
# Scanner réseau "complet" pour pentest-cli
# - TCP connect scan (par défaut)
# - UDP basique (DNS, SNMP, NTP, etc.)
# - Concurrence via ThreadPoolExecutor
# - Progress bar (tqdm si dispo)
# - Banner grabbing basique
# - Détection de service
# - Export JSON/CSV
# - Couleurs + PentestLogger

import socket
import ssl
import json
import csv
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from .service_analyzer import interpret_scan_results, print_detailed_analysis, generate_executive_summary
import argparse
from core import colors, logger
from core.colors import green, yellow, red, cyan, blue
from core.logger import PentestLogger

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

DEFAULT_TIMEOUT = 1.0
DEFAULT_WORKERS = 200
BANNER_TIMEOUT = 1.0

log = PentestLogger()


def _resolve_target(target: str) -> str:
    """Résout un hostname → IP"""
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        return socket.gethostbyname(target)


def _service_guess(port: int, proto: str, banner: str | None) -> str:
    """Devine le service probable"""
    try:
        name = socket.getservbyport(port, proto)
        if name:
            return name
    except Exception:
        pass

    if not banner:
        return "unknown"

    b = banner.lower()
    if "ssh" in b:
        return "ssh"
    if "ftp" in b:
        return "ftp"
    if "http" in b and "ssl" not in b and "tls" not in b:
        return "http"
    if "tls" in b or "ssl" in b:
        return "https"
    if "smtp" in b:
        return "smtp"
    if "imap" in b:
        return "imap"
    if "pop" in b:
        return "pop3"
    if "domain" in b or "dns" in b:
        return "dns"
    if "snmp" in b:
        return "snmp"
    return "unknown"


def _banner_grab(host: str, port: int) -> str | None:
    """Tentative de bannière sur TCP"""
    try:
        if port in (80, 8080, 8000, 8888):
            with socket.create_connection((host, port), timeout=BANNER_TIMEOUT) as s:
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: test\r\n\r\n")
                return s.recv(256).decode(errors="ignore")
        if port == 443:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=BANNER_TIMEOUT) as s:
                with ctx.wrap_socket(s, server_hostname=host) as ssock:
                    return f"TLS {ssock.version()}"
        with socket.create_connection((host, port), timeout=BANNER_TIMEOUT) as s:
            try:
                return s.recv(256).decode(errors="ignore")
            except Exception:
                return None
    except Exception:
        return None


def _scan_one_tcp(host: str, port: int, timeout: float) -> dict:
    """Scan TCP"""
    result = {
        "host": host, "port": port, "proto": "tcp",
        "state": "closed", "service": "unknown", "banner": None
    }
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((host, port)) == 0:
                result["state"] = "open"
                result["banner"] = _banner_grab(host, port)
                result["service"] = _service_guess(port, "tcp", result["banner"])
    except Exception:
        pass
    return result


def _scan_one_udp(host: str, port: int, timeout: float) -> dict:
    """Scan UDP basique"""
    result = {
        "host": host, "port": port, "proto": "udp",
        "state": "closed", "service": "unknown", "banner": None
    }
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(b"\x00" * 4, (host, port))
            try:
                data, _ = s.recvfrom(512)
                result["state"] = "open"
                banner = data.decode(errors="ignore")
                result["banner"] = banner
                result["service"] = _service_guess(port, "udp", banner)
            except socket.timeout:
                result["state"] = "open|filtered"
                result["service"] = _service_guess(port, "udp", None)
    except Exception:
        pass
    return result


def _print_result_line(r: dict):
    """Affichage couleur"""
    if r["state"].startswith("open"):
        print(green(f"{r['proto'].upper()} {r['port']} {r['state']} [{r['service']}]"))
        if r["banner"]:
            print(blue(f"  └─ {r['banner'][:150]}"))
    elif r["state"] == "filtered":
        print(yellow(f"{r['proto'].upper()} {r['port']} filtré"))


def _export_results(results: list[dict], json_path: str | None, csv_path: str | None):
    if json_path:
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        log.info(f"Résultats JSON → {json_path}")
    if csv_path:
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=results[0].keys())
            w.writeheader()
            w.writerows(results)
        log.info(f"Résultats CSV → {csv_path}")


def scan_network(target: str,
                 ports: list[int],
                 udp: bool = False,
                 timeout: float = DEFAULT_TIMEOUT,
                 workers: int = DEFAULT_WORKERS,
                 export_json: str | None = None,
                 export_csv: str | None = None,
                 analyze: bool = True) -> list[dict]:  # ← Nouveau paramètre
    """Scan principal avec analyse automatique"""
    ip = _resolve_target(target)
    results = []
    tasks = []

    log.info(f"Scan sur {ip} | ports={len(ports)} | UDP={udp}")

    with ThreadPoolExecutor(max_workers=workers) as ex:
        for p in ports:
            if udp:
                tasks.append(ex.submit(_scan_one_udp, ip, p, timeout))
            else:
                tasks.append(ex.submit(_scan_one_tcp, ip, p, timeout))

        it = tqdm(as_completed(tasks), total=len(tasks), unit="port") if HAS_TQDM else as_completed(tasks)
        for fut in it:
            r = fut.result()
            results.append(r)
            _print_result_line(r)

    open_ports = [f"{r['proto']}/{r['port']}" for r in results if r["state"].startswith("open")]
    print(cyan(f"Scan terminé. Ports ouverts: {open_ports}"))

    # === NOUVELLE SECTION D'ANALYSE ===
    if analyze and any(r["state"].startswith("open") for r in results):
        # Analyser les résultats
        interpretation = interpret_scan_results(results)
        
        # Afficher le résumé exécutif
        print(generate_executive_summary(interpretation, target))
        
        # Afficher l'analyse détaillée
        print_detailed_analysis(interpretation, target)
        
        # Exporter l'analyse si demandé
        if export_json:
            analysis_data = {
                "scan_results": results,
                "interpretation": interpretation,
                "target": target,
                "scan_params": {
                    "ports": ports,
                    "udp": udp,
                    "timeout": timeout
                }
            }
            analysis_path = export_json.replace('.json', '_analysis.json')
            with open(analysis_path, "w", encoding="utf-8") as f:
                json.dump(analysis_data, f, indent=2, ensure_ascii=False, default=str)
            log.info(f"Analyse JSON → {analysis_path}")

    _export_results(results, export_json, export_csv)
    return results
