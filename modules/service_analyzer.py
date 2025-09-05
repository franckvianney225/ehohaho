# modules/service_analyzer.py
# Analyse et interprétation des résultats de scan

from core.colors import green, yellow, red, cyan, blue, magenta
from core.logger import PentestLogger

log = PentestLogger()

# Base de données des services et risques
SERVICE_DB = {
    # Services UDP critiques
    "dns": {
        "port": 53,
        "protocol": "udp",
        "risk_level": "medium",
        "description": "Service DNS - Résolution de noms de domaine",
        "risks": [
            "Énumération de zones DNS (zone transfer)",
            "Cache poisoning possible",
            "Révélation d'informations internes",
            "Amplification DDoS possible"
        ],
        "recommendations": [
            "Vérifier la configuration des zone transfers",
            "Implémenter DNSSEC si possible",
            "Limiter les requêtes récursives",
            "Surveiller les requêtes anormales"
        ],
        "tests": [
            "nslookup -type=any {target}",
            "dig axfr @{target} domain.com",
            "dnsrecon -t axfr -d domain.com -n {target}"
        ]
    },
    
    "snmp": {
        "port": 161,
        "protocol": "udp",
        "risk_level": "high",
        "description": "SNMP - Protocole de gestion réseau",
        "risks": [
            "Community strings faibles (public/private)",
            "Révélation d'informations système sensibles",
            "Possibilité de modification de configuration",
            "Énumération complète du réseau"
        ],
        "recommendations": [
            "Changer les community strings par défaut",
            "Utiliser SNMPv3 avec authentification",
            "Filtrer l'accès SNMP par IP",
            "Désactiver SNMP si non nécessaire"
        ],
        "tests": [
            "snmpwalk -v2c -c public {target}",
            "snmpwalk -v2c -c private {target}",
            "onesixtyone -c community.txt {target}"
        ]
    },
    
    "ntp": {
        "port": 123,
        "protocol": "udp",
        "risk_level": "low",
        "description": "NTP - Synchronisation d'horloge réseau",
        "risks": [
            "Amplification DDoS (réflexion)",
            "Révélation d'informations système",
            "Manipulation possible de l'heure système"
        ],
        "recommendations": [
            "Configurer des restrictions d'accès",
            "Utiliser NTP authentifié si possible",
            "Monitorer les requêtes anormales",
            "Limiter les commandes de monitoring"
        ],
        "tests": [
            "ntpq -p {target}",
            "ntpdate -q {target}",
            "nmap -sU -p123 --script ntp-monlist {target}"
        ]
    },
    
    # Services TCP critiques
    "ssh": {
        "port": 22,
        "protocol": "tcp",
        "risk_level": "medium",
        "description": "SSH - Accès à distance sécurisé",
        "risks": [
            "Brute force sur mots de passe faibles",
            "Vulnérabilités dans les versions anciennes",
            "Clés SSH mal configurées",
            "Accès privilégié si compromis"
        ],
        "recommendations": [
            "Utiliser l'authentification par clés",
            "Désactiver l'accès root direct",
            "Changer le port par défaut",
            "Implémenter fail2ban"
        ],
        "tests": [
            "ssh {target} -o PreferredAuthentications=none",
            "hydra -l admin -P passwords.txt ssh://{target}",
            "nmap --script ssh-auth-methods {target}"
        ]
    },
    
    "http": {
        "port": 80,
        "protocol": "tcp", 
        "risk_level": "medium",
        "description": "HTTP - Serveur web non chiffré",
        "risks": [
            "Trafic non chiffré (interception)",
            "Vulnérabilités web (XSS, SQLi, etc.)",
            "Révélation d'informations sensibles",
            "Attaques sur applications web"
        ],
        "recommendations": [
            "Migrer vers HTTPS",
            "Implémenter des headers de sécurité",
            "Scanner les vulnérabilités web",
            "Auditer les applications hébergées"
        ],
        "tests": [
            "curl -I http://{target}",
            "nikto -h {target}",
            "gobuster dir -u http://{target} -w wordlist.txt"
        ]
    }
}

def get_risk_color(risk_level: str) -> callable:
    """Retourne la couleur selon le niveau de risque"""
    colors = {
        "critical": red,
        "high": red,
        "medium": yellow,
        "low": green,
        "info": cyan
    }
    return colors.get(risk_level, cyan)

def analyze_service(service_name: str, port: int, protocol: str, banner: str = None) -> dict:
    """Analyse un service détecté"""
    service_info = SERVICE_DB.get(service_name, {
        "risk_level": "info",
        "description": f"Service inconnu sur port {port}/{protocol}",
        "risks": ["Service non identifié - analyse manuelle requise"],
        "recommendations": ["Identifier le service manuellement", "Vérifier les vulnérabilités connues"],
        "tests": [f"nmap -sV -p {port} {{target}}"]
    })
    
    # Ajouter des infos contextuelles
    service_info["detected_port"] = port
    service_info["detected_protocol"] = protocol
    service_info["banner"] = banner
    
    return service_info


def normalize_service_name(service_name: str, port: int, protocol: str) -> str:
    """Normalise les noms de services pour la base de données"""
    # Mapping des services alternatifs
    service_mapping = {
        "domain": "dns",  # ← Fix pour votre problème
        "nameserver": "dns",
        "http-alt": "http",
        "http-proxy": "http", 
        "https-alt": "https",
        "ssh-alt": "ssh",
        "telnet-alt": "telnet"
    }
    
    # Vérification par port si le service n'est pas reconnu
    port_mapping = {
        53: "dns",
        80: "http", 
        443: "https",
        22: "ssh",
        161: "snmp",
        123: "ntp",
        21: "ftp",
        25: "smtp",
        110: "pop3",
        143: "imap",
        993: "imaps",
        995: "pop3s"
    }
    
    # Essayer le mapping par nom d'abord
    normalized = service_mapping.get(service_name.lower(), service_name.lower())
    
    # Si toujours pas trouvé, essayer par port
    if normalized == service_name.lower() and normalized not in SERVICE_DB:
        normalized = port_mapping.get(port, service_name.lower())
    
    return normalized

# Modifiez la fonction analyze_service
def analyze_service(service_name: str, port: int, protocol: str, banner: str = None) -> dict:
    """Analyse un service détecté"""
    # Normaliser le nom du service
    normalized_service = normalize_service_name(service_name, port, protocol)
    
    service_info = SERVICE_DB.get(normalized_service, {
        "risk_level": "info",
        "description": f"Service {service_name} sur port {port}/{protocol}",
        "risks": ["Service nécessite une analyse manuelle approfondie"],
        "recommendations": [
            "Identifier précisément le service et sa version", 
            "Rechercher les vulnérabilités CVE associées",
            "Vérifier la configuration de sécurité"
        ],
        "tests": [f"nmap -sV -sC -p {port} {{target}}"]
    })
    
    # Ajouter des infos contextuelles
    service_info["detected_port"] = port
    service_info["detected_protocol"] = protocol
    service_info["detected_service_name"] = service_name  # Service original
    service_info["normalized_service_name"] = normalized_service  # Service normalisé
    service_info["banner"] = banner
    
    return service_info


def interpret_scan_results(scan_results: list[dict]) -> dict:
    """Interprète les résultats d'un scan complet"""
    interpretation = {
        "summary": {
            "total_ports": len(scan_results),
            "open_ports": 0,
            "services_identified": 0,
            "risk_distribution": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        },
        "services": [],
        "recommendations": set(),
        "immediate_actions": [],
        "further_testing": []
    }
    
    for result in scan_results:
        if result["state"].startswith("open"):
            interpretation["summary"]["open_ports"] += 1
            
            # Analyser le service
            service_analysis = analyze_service(
                result["service"], 
                result["port"], 
                result["proto"],
                result.get("banner")
            )
            
            interpretation["services"].append({
                "port": result["port"],
                "protocol": result["proto"],
                "service": result["service"],
                "analysis": service_analysis
            })
            
            # Compter les risques
            risk_level = service_analysis.get("risk_level", "info")
            interpretation["summary"]["risk_distribution"][risk_level] += 1
            
            # Ajouter recommandations
            for rec in service_analysis.get("recommendations", []):
                interpretation["recommendations"].add(rec)
            
            # Actions immédiates pour services critiques/high
            if risk_level in ["critical", "high"]:
                interpretation["immediate_actions"].append(f"Port {result['port']}/{result['proto']} ({result['service']}) - Risque {risk_level}")
            
            # Tests supplémentaires
            interpretation["further_testing"].extend(service_analysis.get("tests", []))
    
    interpretation["recommendations"] = list(interpretation["recommendations"])
    return interpretation

def print_detailed_analysis(interpretation: dict, target: str):
    """Affiche une analyse détaillée"""
    print(f"\n{cyan('='*60)}")
    print(f"{cyan('ANALYSE DES RÉSULTATS DE SCAN')}")
    print(f"{cyan('='*60)}")
    
    summary = interpretation["summary"]
    print(f"\n{blue('📊 RÉSUMÉ')}")
    print(f"• Cible analysée: {target}")
    print(f"• Ports ouverts: {summary['open_ports']}/{summary['total_ports']}")
    print(f"• Services identifiés: {len(interpretation['services'])}")
    
    # Distribution des risques
    print(f"\n{blue('⚠️  RÉPARTITION DES RISQUES')}")
    risk_dist = summary["risk_distribution"]
    for risk, count in risk_dist.items():
        if count > 0:
            color = get_risk_color(risk)
            print(f"• {color(risk.upper())}: {count} service(s)")
    
    # Actions immédiates
    if interpretation["immediate_actions"]:
        print(f"\n{red('🚨 ACTIONS IMMÉDIATES RECOMMANDÉES')}")
        for action in interpretation["immediate_actions"]:
            print(f"• {red(action)}")
    
    # Analyse détaillée par service
    print(f"\n{blue('🔍 ANALYSE DÉTAILLÉE PAR SERVICE')}")
    for service in interpretation["services"]:
        analysis = service["analysis"]
        color = get_risk_color(analysis["risk_level"])
        
        print(f"\n{color(f'📡 {service["service"].upper()}')} - Port {service['port']}/{service['protocol']}")
        print(f"   Description: {analysis['description']}")
        print(f"   Niveau de risque: {color(analysis['risk_level'].upper())}")
        
        if "risks" in analysis:
            print(f"   {yellow('Risques identifiés:')}")
            for risk in analysis["risks"]:
                print(f"   • {risk}")
    
    # Recommandations générales
    if interpretation["recommendations"]:
        print(f"\n{blue('💡 RECOMMANDATIONS DE SÉCURITÉ')}")
        for i, rec in enumerate(interpretation["recommendations"], 1):
            print(f"{i}. {rec}")
    
    # Tests supplémentaires
    if interpretation["further_testing"]:
        print(f"\n{blue('🧪 TESTS SUPPLÉMENTAIRES SUGGÉRÉS')}")
        unique_tests = list(set(interpretation["further_testing"]))
        for i, test in enumerate(unique_tests[:10], 1):  # Limite à 10 tests
            formatted_test = test.replace("{target}", target)
            print(f"{i}. {formatted_test}")
    
    print(f"\n{cyan('='*60)}")

def generate_executive_summary(interpretation: dict, target: str) -> str:
    """Génère un résumé exécutif"""
    summary = interpretation["summary"]
    risk_dist = summary["risk_distribution"]
    
    total_risk_services = risk_dist["critical"] + risk_dist["high"] + risk_dist["medium"]
    
    if risk_dist["critical"] > 0:
        risk_level = "CRITIQUE"
        color = "🔴"
    elif risk_dist["high"] > 0:
        risk_level = "ÉLEVÉ"
        color = "🟠"
    elif risk_dist["medium"] > 0:
        risk_level = "MODÉRÉ"
        color = "🟡"
    else:
        risk_level = "FAIBLE"
        color = "🟢"
    
    return f"""
{color} RÉSUMÉ EXÉCUTIF - SCAN DE {target}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Niveau de risque global: {risk_level}
Services exposés: {summary['open_ports']} port(s) ouvert(s)
Services à risque: {total_risk_services} service(s) nécessitent une attention

Actions prioritaires: {len(interpretation['immediate_actions'])} action(s) immédiate(s)
Tests recommandés: {len(set(interpretation['further_testing']))} test(s) supplémentaire(s)
"""