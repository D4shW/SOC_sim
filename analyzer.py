"""
========================================
analyzer.py — Moteur d'analyse et de détection
========================================

📚 CONCEPT : QU'EST-CE QU'UN ANALYSEUR SOC ?
Dans un vrai SOC, des règles de détection analysent en permanence
les logs pour identifier des comportements suspects.
C'est le cerveau du SOC.

Outils réels similaires :
- Sigma Rules (règles de détection standardisées)
- YARA (détection de malware par patterns)
- Suricata IDS (détection d'intrusion réseau)

Notre analyseur utilise :
1. Regex (expressions régulières) pour chercher des patterns dans les logs
2. Corrélation temporelle pour détecter le brute force
3. Score de menace pour prioriser les alertes
"""

import re           # Module des expressions régulières
import time         # Pour la gestion du temps (fenêtres temporelles)
import json         # Pour la configuration
import os           # Pour les chemins
from datetime import datetime
from collections import defaultdict  # Dictionnaire avec valeur par défaut


def load_config():
    """Charge la configuration depuis config.json"""
    config_path = os.path.join(os.path.dirname(__file__), "config.json")
    with open(config_path, "r") as f:
        return json.load(f)


# ============================================================
# RÈGLES DE DÉTECTION (SIGNATURES)
# ============================================================
# Ces patterns sont des "signatures" comme dans un antivirus.
# Chaque règle cherche un pattern spécifique dans les logs.
#
# 📚 REGEX EXPLIQUÉ :
# r"..." = raw string (les \ ne sont pas interprétés)
# \d+ = un ou plusieurs chiffres
# \b = limite de mot
# (?i) = insensible à la casse

DETECTION_RULES = [
    {
        "id": "RULE-001",
        "name": "SSH Brute Force",
        "pattern": r"Failed password for .+ from ([\d.]+)",
        "level": "CRITICAL",
        "description": "Multiples échecs de mot de passe SSH détectés",
        "mitre": "T1110.001",  # MITRE ATT&CK technique (brute force)
    },
    {
        "id": "RULE-002",
        "name": "SQL Injection Attempt",
        "pattern": r"(UNION SELECT|DROP TABLE|OR '1'='1|--|\bexec\b|\bxp_cmdshell\b)",
        "level": "CRITICAL",
        "description": "Pattern d'injection SQL détecté dans les logs web",
        "mitre": "T1190",  # Exploit Public-Facing Application
    },
    {
        "id": "RULE-003",
        "name": "Port Scan Detection",
        "pattern": r"IPTABLES DROP.+SRC=([\d.]+).+FLAGS=S",
        "level": "WARNING",
        "description": "Scan de ports détecté via les logs iptables",
        "mitre": "T1046",  # Network Service Discovery
    },
    {
        "id": "RULE-004",
        "name": "Malware Detection",
        "pattern": r"(Trojan|Ransomware|Backdoor|Rootkit|Worm|Spyware)\.\w+",
        "level": "CRITICAL",
        "description": "Signature de malware identifiée par l'antivirus",
        "mitre": "T1204",  # User Execution
    },
    {
        "id": "RULE-005",
        "name": "Suspicious Command Execution",
        "pattern": r"(cat /etc/passwd|wget http|chmod \+x|nc -lvp|find / -suid|sudo -l)",
        "level": "CRITICAL",
        "description": "Commande suspecte de post-exploitation détectée",
        "mitre": "T1059",  # Command and Scripting Interpreter
    },
    {
        "id": "RULE-006",
        "name": "Large Data Transfer",
        "pattern": r"BYTES=(\d{8,})",  # 8+ chiffres = 10+ MB
        "level": "WARNING",
        "description": "Transfert de données volumineux suspect",
        "mitre": "T1048",  # Exfiltration Over Alternative Protocol
    },
    {
        "id": "RULE-007",
        "name": "Known Attack Tool",
        "pattern": r"(sqlmap|nikto|masscan|nmap scripting|metasploit|msfvenom)",
        "level": "WARNING",
        "description": "Outil d'attaque connu détecté dans les logs",
        "mitre": "T1595",  # Active Scanning
    },
    {
        "id": "RULE-008",
        "name": "Privilege Escalation",
        "pattern": r"(sudo|FAILED.*root|su - root|SUID)",
        "level": "WARNING",
        "description": "Tentative d'élévation de privilèges",
        "mitre": "T1548",  # Abuse Elevation Control Mechanism
    },
    {
        "id": "RULE-009",
        "name": "DDoS Traffic Spike",
        "pattern": r"(\d+) req/s",  # Taux de requêtes
        "level": "CRITICAL",
        "description": "Pic de trafic suspect pouvant indiquer un DDoS",
        "mitre": "T1498",  # Network Denial of Service
    },
    {
        "id": "RULE-010",
        "name": "Telnet Connection (Unencrypted)",
        "pattern": r"(telnet|DPT=23\b)",
        "level": "WARNING",
        "description": "Connexion Telnet détectée (protocole non chiffré, obsolète et dangereux)",
        "mitre": "T1021",  # Remote Services
    },
]


class ThreatAnalyzer:
    """
    Moteur d'analyse qui examine chaque log et détecte les menaces.
    
    📚 COMMENT ÇA MARCHE ?
    1. Un log arrive (texte brut)
    2. On applique chaque règle de détection (regex)
    3. Si une règle correspond, on génère une alerte
    4. On calcule aussi des corrélations (ex: même IP, plusieurs fois)
    """

    def __init__(self):
        """Initialise l'analyseur."""
        config = load_config()
        self.thresholds = config["thresholds"]

        # Dictionnaire pour compter les événements par IP
        # defaultdict(list) crée automatiquement une liste vide si la clé n'existe pas
        self.ip_event_history = defaultdict(list)

        # Ensemble des IPs connues comme malveillantes (liste noire simulée)
        self.blacklisted_ips = set()

        # Compteurs pour les statistiques
        self.total_analyzed = 0
        self.alerts_generated = 0

        print("[ANALYZER] 🔍 Moteur d'analyse initialisé avec", len(DETECTION_RULES), "règles")

    def extract_ip_from_log(self, log_text: str) -> str:
        """
        Extrait l'adresse IP source d'un log.
        
        REGEX POUR UNE ADRESSE IP :
        d{1,3} = 1 a 3 chiffres
        . = un point litteral (le backslash "echappe" le point)
        On repete ca 4 fois pour avoir x.x.x.x
        """
        # Pattern pour matcher une adresse IPv4
        ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
        matches = re.findall(ip_pattern, log_text)

        # On retourne la première IP trouvée qui n'est pas locale
        for ip in matches:
            if not ip.startswith("127.") and not ip.startswith("0."):
                return ip

        return "unknown"

    def apply_detection_rules(self, log_text: str) -> list:
        """
        Applique toutes les règles de détection sur un log.
        
        Retourne une liste des règles qui ont "matché" (trouvé quelque chose).
        
        📚 re.search() vs re.findall() :
        - re.search() : cherche si le pattern existe quelque part dans le texte
        - re.findall() : retourne TOUS les matches trouvés
        - re.flags=re.IGNORECASE : ignore la casse (majuscules/minuscules)
        """
        triggered_rules = []

        for rule in DETECTION_RULES:
            # On cherche le pattern du la règle dans le log
            match = re.search(rule["pattern"], log_text, re.IGNORECASE)

            if match:
                # La règle a trouvé quelque chose !
                triggered_rules.append({
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "level": rule["level"],
                    "description": rule["description"],
                    "mitre": rule["mitre"],
                    "matched_text": match.group(0)[:100]  # On tronque à 100 chars
                })

        return triggered_rules

    def check_brute_force(self, ip: str, event_type: str) -> bool:
        """
        Détecte une attaque brute force par corrélation temporelle.
        
        📚 LOGIQUE DE CORRÉLATION :
        - On garde l'historique des tentatives par IP
        - Si une IP a fait plus de X tentatives dans Y secondes → BRUTE FORCE !
        - C'est une règle "stateful" : elle garde un état entre les événements.
        
        Retourne True si brute force détecté.
        """
        # On ignore les événements qui ne sont pas des échecs de connexion
        if event_type not in ["failed_login", "brute_force_ssh"]:
            return False

        now = time.time()
        window = self.thresholds["brute_force_window_seconds"]
        max_attempts = self.thresholds["brute_force_attempts"]

        # On ajoute le timestamp actuel à l'historique de cette IP
        self.ip_event_history[ip].append(now)

        # On filtre : on garde seulement les événements dans la fenêtre temporelle
        # Ex: "les événements des 60 dernières secondes"
        recent_events = [
            t for t in self.ip_event_history[ip]
            if now - t <= window
        ]

        # On met à jour l'historique (on enlève les vieux événements)
        self.ip_event_history[ip] = recent_events

        # Si le nombre de tentatives récentes dépasse le seuil → brute force !
        if len(recent_events) >= max_attempts:
            self.blacklisted_ips.add(ip)  # On ajoute à la liste noire
            return True

        return False

    def calculate_threat_score(self, event: dict, triggered_rules: list) -> int:
        """
        Calcule un score de menace de 0 à 100.
        
        📚 THREAT SCORING :
        Dans les SIEM professionnels (comme Splunk), chaque événement
        a un score de risque basé sur plusieurs facteurs :
        - La sévérité des règles déclenchées
        - La réputation de l'IP
        - Le contexte (heure, fréquence...)
        
        Ici on fait une version simplifiée mais réaliste.
        """
        score = 0

        # Score de base selon le niveau
        level = event.get("level", "INFO")
        if level == "INFO":
            score += 5
        elif level == "WARNING":
            score += 30
        elif level == "CRITICAL":
            score += 60

        # Bonus pour chaque règle déclenchée
        for rule in triggered_rules:
            if rule["level"] == "CRITICAL":
                score += 15
            elif rule["level"] == "WARNING":
                score += 8

        # Bonus si l'IP est dans la liste noire
        if event.get("source_ip") in self.blacklisted_ips:
            score += 20

        # On plafonne à 100
        return min(100, score)

    def analyze_event(self, event: dict) -> dict:
        """
        Analyse complète d'un événement de sécurité.
        
        C'est la méthode principale : elle combine toutes les analyses
        et retourne un événement enrichi avec des informations de détection.
        
        Paramètre event : le dictionnaire d'un événement (depuis simulator.py)
        Retourne : le même événement enrichi avec les résultats d'analyse
        """
        self.total_analyzed += 1

        raw_log = event.get("raw_log", event.get("message", ""))
        source_ip = event.get("source_ip", "unknown")
        event_type = event.get("event_type", "unknown")

        # 1. Appliquer les règles de détection
        triggered_rules = self.apply_detection_rules(raw_log)

        # 2. Vérifier le brute force
        is_brute_force = self.check_brute_force(source_ip, event_type)
        if is_brute_force and event["level"] != "CRITICAL":
            event["level"] = "CRITICAL"
            triggered_rules.append({
                "rule_id": "RULE-CORR-001",
                "rule_name": "Brute Force Correlation",
                "level": "CRITICAL",
                "description": f"IP {source_ip}: dépassement du seuil de tentatives ({self.thresholds['brute_force_attempts']} en {self.thresholds['brute_force_window_seconds']}s)",
                "mitre": "T1110",
                "matched_text": f"{self.thresholds['brute_force_attempts']} tentatives"
            })

        # 3. Calculer le score de menace
        threat_score = self.calculate_threat_score(event, triggered_rules)

        # 4. Enrichir l'événement avec les résultats d'analyse
        event["threat_score"] = threat_score
        event["triggered_rules"] = triggered_rules
        event["is_blacklisted"] = source_ip in self.blacklisted_ips

        # 5. Ajouter les informations MITRE ATT&CK si des règles ont matché
        if triggered_rules:
            mitre_ids = [r["mitre"] for r in triggered_rules if r.get("mitre")]
            if mitre_ids:
                event["mitre_techniques"] = mitre_ids
                self.alerts_generated += 1

        # 6. Ajouter une explication pédagogique si absente
        if not event.get("explained") and triggered_rules:
            best_rule = triggered_rules[0]  # La première règle déclenchée
            event["explained"] = (
                f"🔍 RÈGLE DÉCLENCHÉE: {best_rule['rule_name']} ({best_rule['rule_id']})\n"
                f"📋 Description: {best_rule['description']}\n"
                f"🎯 Technique MITRE ATT&CK: {best_rule['mitre']}\n"
                f"📊 Score de menace: {threat_score}/100\n"
                f"🔎 Pattern détecté: {best_rule['matched_text']}"
            )

        return event

    def get_ip_risk_level(self, ip: str) -> str:
        """
        Retourne le niveau de risque d'une IP.
        Utile pour l'affichage dans la GUI.
        """
        if ip in self.blacklisted_ips:
            return "BLACKLISTED"

        history = self.ip_event_history.get(ip, [])
        recent_count = len(history)

        if recent_count >= 10:
            return "CRITICAL"
        elif recent_count >= 5:
            return "HIGH"
        elif recent_count >= 2:
            return "MEDIUM"
        else:
            return "LOW"

    def get_statistics(self) -> dict:
        """Retourne les statistiques du moteur d'analyse."""
        return {
            "total_analyzed": self.total_analyzed,
            "alerts_generated": self.alerts_generated,
            "blacklisted_ips": len(self.blacklisted_ips),
            "tracked_ips": len(self.ip_event_history),
            "detection_rules": len(DETECTION_RULES)
        }

    def reset(self):
        """Remet à zéro l'état de l'analyseur (pour nouvelle simulation)."""
        self.ip_event_history.clear()
        self.blacklisted_ips.clear()
        self.total_analyzed = 0
        self.alerts_generated = 0
        print("[ANALYZER] 🔄 Analyseur remis à zéro")
