#!/usr/bin/env python3
import argparse
import sys
from core import colors, logger, config, utils

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

    # === SCAN RÉSEAU ===
    scan_parser = subparsers.add_parser("scan", help="Scan réseau")
    scan_parser.add_argument("--target", required=True, help="IP ou domaine à scanner")
    scan_parser.add_argument("--ports", required=True, help="Liste des ports ex: 22,80,443")

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
    api_parser.add_argument("--url", required=True)

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
            scan_network.scan_network(args.target, ports)

        elif args.command == "brute":
            brute.run_bruteforce(args.service, args.target, args.username, args.wordlist)

        elif args.command == "web":
            web.run_web_scan(args.url, args.scan)

        elif args.command == "osint":
            reconnaissance.run_osint(args.domaine)

        elif args.command == "api":
            api_tests.run_api_tests(args.url)

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
