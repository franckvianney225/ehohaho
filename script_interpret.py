import json

# Charger le fichier JSON
with open("api_scan_report.json", "r") as f:
    data = json.load(f)

base_url = data.get("base_url", "API")
vulnerabilities = data.get("vulnerabilities", [])

# Créer un dictionnaire pour regrouper par type de vulnérabilité
summary = {}

for vuln in vulnerabilities:
    vuln_type = vuln["type"]
    endpoint = vuln.get("endpoint", "unknown")
    if vuln_type not in summary:
        summary[vuln_type] = set()
    summary[vuln_type].add(endpoint)

# Afficher un résumé clair
print(f"\n=== Résumé des vulnérabilités détectées pour {base_url} ===\n")

for vuln_type, endpoints in summary.items():
    endpoints_list = ", ".join(sorted(endpoints))
    print(f"- {vuln_type} → Endpoints concernés : {endpoints_list}")

print("\n💡 Conseils :")
print("- Auth bypass → sécuriser l'authentification et vérifier les tokens.")
print("- Rate limiting → ajouter des limites de requêtes par utilisateur/IP.")
print("- HTTP insecure → forcer HTTPS partout.")
print("- SQL Injection → valider et échapper toutes les entrées.")
print("- IDOR → vérifier les droits d'accès avant chaque ressource.")
