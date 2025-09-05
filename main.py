#!/usr/bin/env python3
import argparse
import sys
from core import colors, logger, config, utils
from modules.api_tests import APIPentestScanner

# Import des modules
from modules import (
    scan_network, brute, web, reconnaissance, api_tests, mobile,
    social, load_testing, database_testing, cloud_security, iot_testing,
    compliance, automation, exploitation, post_exploitation, network_tests,
    report
)

print(colors.cyan("\n=== Pentest CLI Suite ==="))


def banner():
    """Affichage d'une bannière en couleurs"""
    print(colors.cyan("\n=== Pentest CLI Suite ==="))
    print(colors.green("🔎 Outil d'audit et de tests de sécurité tout-en-un\n"))

def main():
    banner()

    parser = argparse.ArgumentParser(
        prog="pentest-cli",
        description="Suite d'outils de pentest en CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # === SCAN RÉSEAU === (mise à jour)
    scan_parser = subparsers.add_parser("scan", help="Scan réseau")
    scan_parser.add_argument("--target", required=True, help="IP ou domaine à scanner")
    scan_parser.add_argument("--ports", required=True, help="Liste des ports ex: 22,80,443")
    scan_parser.add_argument('--protocol', choices=['tcp', 'udp'], 
                        default='tcp', help='Protocole à utiliser (tcp/udp)')
    # Nouveaux arguments pour l'analyse
    scan_parser.add_argument('--no-analysis', action='store_true', 
                        help='Désactiver l\'analyse automatique des résultats')
    scan_parser.add_argument('--export-json', type=str, 
                        help='Exporter les résultats en JSON')
    scan_parser.add_argument('--export-csv', type=str,
                        help='Exporter les résultats en CSV')
    scan_parser.add_argument('--timeout', type=float, default=1.0,
                        help='Timeout de connexion en secondes (défaut: 1.0)')
    scan_parser.add_argument('--workers', type=int, default=200,
                        help='Nombre de threads concurrents (défaut: 200)')

    # === BRUTE FORCE ===
    brute_parser = subparsers.add_parser("brute", help="Brute force logins")
    brute_parser.add_argument("--service", required=True, choices=["ssh", "ftp", "http"])
    brute_parser.add_argument("--target", required=True)
    brute_parser.add_argument("--username", required=True)
    brute_parser.add_argument("--wordlist", required=True)

    # === WEB TESTING ===
    web_parser = subparsers.add_parser("web", help="Scan web & vulnérabilités")
    web_parser.add_argument("--url", required=True)
    web_parser.add_argument("--scan", choices=["xss", "sql", "all"], default="all")

    # === OSINT ===
    osint_parser = subparsers.add_parser("osint", help="OSINT & reconnaissance")
    osint_parser.add_argument("--domaine", required=True)

   # === API TESTING ===
    api_parser = subparsers.add_parser("api", help="Tests d'API")
    api_parser.add_argument("--url", required=True, help="URL de l'API")
    api_parser.add_argument("--http-method", type=str, default="GET", help="Méthode HTTP (GET, POST, PUT, DELETE, ...)")
    api_parser.add_argument("--api-headers", type=str, help='Headers JSON (ex: \'{"Authorization":"Bearer ..."}\')')
    api_parser.add_argument("--api-data", type=str, help='Form data JSON (ex: \'{"key":"value"}\')')
    api_parser.add_argument("--api-json", type=str, help='JSON body (ex: \'{"name":"John"}\')')
    api_parser.add_argument("--token", type=str, help="Token d'authentification Bearer si nécessaire")
        
    # === MOBILE TESTING ===
    mobile_parser = subparsers.add_parser("mobile", help="Tests mobiles")
    mobile_parser.add_argument("--apk", required=True, help="Fichier APK cible")

    # === SOCIAL ENGINEERING ===
    social_parser = subparsers.add_parser("social", help="Attaques sociales")
    social_parser.add_argument("--target", required=True)

    # === LOAD TESTING ===
    load_parser = subparsers.add_parser("load", help="Test de charge")
    load_parser.add_argument("--target", required=True)
    load_parser.add_argument("--users", type=int, default=100)

    # === DATABASE TESTING ===
    db_parser = subparsers.add_parser("db", help="Tests sur bases de données")
    db_parser.add_argument("--dbtype", required=True, choices=["mysql", "postgres", "mongo"])
    db_parser.add_argument("--target", required=True)

    # === CLOUD SECURITY ===
    cloud_parser = subparsers.add_parser("cloud", help="Tests cloud (AWS, GCP, Azure)")
    cloud_parser.add_argument("--provider", required=True, choices=["aws", "gcp", "azure"])

    # === IOT TESTING ===
    iot_parser = subparsers.add_parser("iot", help="Tests IoT & hardware")
    iot_parser.add_argument("--target", required=True)

    # === COMPLIANCE ===
    compliance_parser = subparsers.add_parser("compliance", help="Tests conformité (GDPR, PCI-DSS, ISO)")
    compliance_parser.add_argument("--standard", required=True, choices=["owasp", "gdpr", "pci", "iso"])

    # === AUTOMATION ===
    auto_parser = subparsers.add_parser("auto", help="Automatisation & CI/CD")
    auto_parser.add_argument("--pipeline", choices=["jenkins", "gitlab"], required=True)

    # === EXPLOITATION ===
    exploit_parser = subparsers.add_parser("exploit", help="Exploitation d'une vulnérabilité")
    exploit_parser.add_argument("--target", required=True)
    exploit_parser.add_argument("--exploit", required=True)

    # === POST-EXPLOITATION ===
    post_parser = subparsers.add_parser("post", help="Post-exploitation (persistence, privesc, etc.)")
    post_parser.add_argument("--session", required=True)

    # === NETWORK TESTS ===
    net_parser = subparsers.add_parser("net", help="Tests réseaux avancés")
    net_parser.add_argument("--target", required=True)

    # === REPORTING ===
    report_parser = subparsers.add_parser("report", help="Génération de rapports")
    report_parser.add_argument("--format", choices=["txt", "json", "html"], default="txt")

    args = parser.parse_args()

    try:
        # === ROUTAGE SELON LE MODULE ===
        if args.command == "scan":
            ports = [int(p.strip()) for p in args.ports.split(",")]
            is_udp = (args.protocol == 'udp')
            analyze = not args.no_analysis  # Par défaut True, False si --no-analysis
            
            scan_network.scan_network(
                target=args.target, 
                ports=ports, 
                udp=is_udp,
                timeout=args.timeout,
                export_json=args.export_json,
                export_csv=args.export_csv,
                analyze=analyze
            )


        elif args.command == "brute":
            brute.run_bruteforce(args.service, args.target, args.username, args.wordlist)

        elif args.command == "web":
            web.run_web_scan(args.url, args.scan)

        elif args.command == "osint":
            reconnaissance.run_osint(args.domaine)

        elif args.command == "api":
            try:
                headers = json.loads(args.api_headers) if args.api_headers else None
                data = json.loads(args.api_data) if args.api_data else None
                json_data = json.loads(args.api_json) if args.api_json else None
            except json.JSONDecodeError:
                logger.log_error("Headers/Data/JSON doivent être valides en JSON.")
                sys.exit(1)

            scanner = APIPentestScanner(base_url=args.url, token=args.token)

            if args.http_method != "GET" or data or json_data or headers:
                # Requête personnalisée
                r = scanner._request(endpoint="", method=args.http_method, data=data, headers=headers, params=None)
                try:
                    body = r.json()
                except:
                    body = r.text
                print(json.dumps({
                    "status_code": r.status_code,
                    "headers": dict(r.headers),
                    "body": body
                }, indent=2))
            else:
                # Scan complet pentest
                scanner.run()

        elif args.command == "mobile":
            mobile.run_mobile_analysis(args.apk)

        elif args.command == "social":
            social.run_social_attack(args.target)

        elif args.command == "load":
            load_testing.run_load_test(args.target, args.users)

        elif args.command == "db":
            database_testing.run_db_tests(args.dbtype, args.target)

        elif args.command == "cloud":
            cloud_security.run_cloud_audit(args.provider)

        elif args.command == "iot":
            iot_testing.run_iot_tests(args.target)

        elif args.command == "compliance":
            compliance.run_compliance_check(args.standard)

        elif args.command == "auto":
            automation.run_pipeline_integration(args.pipeline)

        elif args.command == "exploit":
            exploitation.run_exploit(args.target, args.exploit)

        elif args.command == "post":
            post_exploitation.run_post_exploit(args.session)

        elif args.command == "net":
            network_tests.run_network_tests(args.target)

        elif args.command == "report":
            report.generate_report(args.format)

        else:
            logger.log_error("Commande inconnue. Utilisez --help pour voir les options.")
            sys.exit(1)

    except Exception as e:
        logger.log_error(f"Erreur d'exécution : {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
