"""
========================================
database.py — Gestion de la base de données SQLite
========================================

📚 CONCEPT : QU'EST-CE QUE SQLITE ?
SQLite est une base de données légère qui stocke tout dans un seul fichier.
C'est comme un tableur Excel, mais accessible par du code Python.
Dans un vrai SOC, on utilise des bases comme Elasticsearch ou PostgreSQL.
Ici, SQLite nous permet d'apprendre sans installation complexe.

📦 CE QUE CE FICHIER FAIT :
- Crée les tables (les "feuilles" de notre base de données)
- Sauvegarde chaque événement de sécurité
- Permet de chercher dans l'historique des événements
- Génère des statistiques pour le dashboard
"""

import sqlite3      # Module Python intégré pour SQLite (pas besoin d'installer)
import json         # Pour lire le fichier de configuration
import os           # Pour manipuler les chemins de fichiers
from datetime import datetime  # Pour horodater les événements


def load_config():
    """Charge la configuration depuis config.json"""
    config_path = os.path.join(os.path.dirname(__file__), "config.json")
    with open(config_path, "r") as f:
        return json.load(f)


class SOCDatabase:
    """
    📚 QU'EST-CE QU'UNE CLASSE ?
    Une classe est comme un "plan de construction".
    SOCDatabase décrit comment gérer notre base de données.
    Chaque fois qu'on crée un objet SOCDatabase(), on obtient
    un gestionnaire de base de données prêt à l'emploi.
    """

    def __init__(self):
        """
        __init__ est appelé automatiquement quand on crée SOCDatabase().
        C'est comme le "démarrage" de notre gestionnaire.
        """
        config = load_config()
        # On récupère le chemin du fichier de base de données depuis config.json
        self.db_path = config["database"]["path"]
        # On initialise la connexion à None (pas encore connecté)
        self.connection = None
        # On crée les tables si elles n'existent pas encore
        self.initialize_database()

    def get_connection(self):
        """
        Crée ou retourne une connexion à la base de données.
        
        📚 POURQUOI check_same_thread=False ?
        Notre programme utilise plusieurs "threads" (fils d'exécution en parallèle).
        Par défaut, SQLite n'aime pas ça. Ce paramètre lui dit que c'est OK.
        """
        if self.connection is None:
            # On se connecte au fichier de base de données
            # Si le fichier n'existe pas, SQLite le crée automatiquement
            self.connection = sqlite3.connect(
                self.db_path,
                check_same_thread=False  # Permet l'accès depuis plusieurs threads
            )
            # row_factory permet de récupérer les données comme des dictionnaires
            # Au lieu de ("192.168.1.1", "CRITICAL"), on aura {"ip": "192.168.1.1", "level": "CRITICAL"}
            self.connection.row_factory = sqlite3.Row
        return self.connection

    def initialize_database(self):
        """
        Crée les tables de la base de données si elles n'existent pas.
        
        📚 C'EST QUOI UNE TABLE SQL ?
        Une table, c'est comme un tableau Excel :
        - Les colonnes = les types d'informations (IP, date, message...)
        - Les lignes = les données réelles (un événement par ligne)
        """
        conn = self.get_connection()
        cursor = conn.cursor()  # Le "curseur" exécute les commandes SQL

        # ---- TABLE 1 : EVENTS ----
        # Stocke TOUS les événements de sécurité
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                level TEXT NOT NULL,
                source_ip TEXT,
                event_type TEXT,
                message TEXT,
                raw_log TEXT,
                explained TEXT
            )
        """)
        # Explication des colonnes :
        # id              → numéro unique auto-incrémenté (1, 2, 3, ...)
        # timestamp       → date et heure de l'événement
        # level           → INFO, WARNING, ou CRITICAL
        # source_ip       → l'adresse IP d'où vient l'attaque
        # event_type      → type : brute_force, port_scan, etc.
        # message         → description lisible par un humain
        # raw_log         → le log brut tel qu'il a été généré
        # explained       → explication pédagogique de l'alerte

        # ---- TABLE 2 : STATISTICS ----
        # Stocke les statistiques agrégées pour le dashboard
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS statistics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                total_events INTEGER DEFAULT 0,
                info_count INTEGER DEFAULT 0,
                warning_count INTEGER DEFAULT 0,
                critical_count INTEGER DEFAULT 0,
                unique_ips INTEGER DEFAULT 0,
                top_attacker_ip TEXT
            )
        """)

        # ---- TABLE 3 : SUSPICIOUS_IPS ----
        # Garde une liste des IPs suspectes avec leur score de menace
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS suspicious_ips (
                ip TEXT PRIMARY KEY,
                first_seen TEXT,
                last_seen TEXT,
                event_count INTEGER DEFAULT 1,
                threat_score INTEGER DEFAULT 0,
                is_blocked INTEGER DEFAULT 0
            )
        """)
        # ip           → l'adresse IP (clé unique, pas de doublons)
        # threat_score → score de 0 à 100 (plus c'est haut, plus c'est dangereux)
        # is_blocked   → 0 = pas bloqué, 1 = bloqué (simulé)

        # On "valide" les changements (comme "Enregistrer" dans Excel)
        conn.commit()
        print("[DATABASE] ✅ Base de données initialisée avec succès")

    def save_event(self, event: dict):
        """
        Sauvegarde un événement de sécurité dans la base de données.
        
        📚 PARAMÈTRE 'event' :
        C'est un dictionnaire Python, comme une fiche d'information.
        Exemple : {"level": "CRITICAL", "source_ip": "192.168.1.5", ...}
        """
        conn = self.get_connection()
        cursor = conn.cursor()

        # INSERT INTO = "ajouter une nouvelle ligne dans la table"
        # Les ? sont des "placeholders" pour éviter les injections SQL
        # (une faille de sécurité classique !)
        cursor.execute("""
            INSERT INTO events 
            (timestamp, level, source_ip, event_type, message, raw_log, explained)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            event.get("timestamp", datetime.now().isoformat()),
            event.get("level", "INFO"),
            event.get("source_ip", "unknown"),
            event.get("event_type", "unknown"),
            event.get("message", ""),
            event.get("raw_log", ""),
            event.get("explained", "")
        ))

        conn.commit()

        # On met aussi à jour la table des IPs suspectes
        if event.get("level") in ["WARNING", "CRITICAL"]:
            self._update_suspicious_ip(event.get("source_ip"), event.get("level"))

    def _update_suspicious_ip(self, ip: str, level: str):
        """
        Met à jour ou crée une entrée pour une IP suspecte.
        Le _ au début du nom signifie "méthode privée" (usage interne seulement).
        """
        if not ip or ip == "unknown":
            return

        conn = self.get_connection()
        cursor = conn.cursor()
        now = datetime.now().isoformat()

        # On calcule le score de menace selon la gravité
        score_increment = 5 if level == "WARNING" else 15  # CRITICAL = +15 points

        # INSERT OR REPLACE : si l'IP existe déjà, on la met à jour
        # Sinon, on en crée une nouvelle
        cursor.execute("""
            INSERT INTO suspicious_ips (ip, first_seen, last_seen, event_count, threat_score)
            VALUES (?, ?, ?, 1, ?)
            ON CONFLICT(ip) DO UPDATE SET
                last_seen = ?,
                event_count = event_count + 1,
                threat_score = MIN(100, threat_score + ?)
        """, (ip, now, now, score_increment, now, score_increment))

        conn.commit()

    def get_recent_events(self, limit: int = 50) -> list:
        """
        Récupère les événements les plus récents.
        
        📚 PARAMÈTRE limit :
        Combien d'événements retourner. Par défaut : les 50 derniers.
        """
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT * FROM events 
            ORDER BY id DESC 
            LIMIT ?
        """, (limit,))

        # fetchall() retourne toutes les lignes trouvées
        return [dict(row) for row in cursor.fetchall()]

    def get_statistics(self) -> dict:
        """
        Calcule et retourne les statistiques globales du SOC.
        Utilisé pour le dashboard (compteurs, graphiques...).
        """
        conn = self.get_connection()
        cursor = conn.cursor()

        # COUNT(*) compte toutes les lignes
        cursor.execute("SELECT COUNT(*) as total FROM events")
        total = cursor.fetchone()["total"]

        # On compte par niveau de gravité
        cursor.execute("SELECT level, COUNT(*) as count FROM events GROUP BY level")
        level_counts = {row["level"]: row["count"] for row in cursor.fetchall()}

        # On récupère les IPs suspectes (menace > 20)
        cursor.execute("""
            SELECT ip, event_count, threat_score 
            FROM suspicious_ips 
            WHERE threat_score > 20
            ORDER BY threat_score DESC 
            LIMIT 10
        """)
        top_threats = [dict(row) for row in cursor.fetchall()]

        # On compte les IPs uniques
        cursor.execute("SELECT COUNT(DISTINCT source_ip) as unique_ips FROM events WHERE source_ip != 'unknown'")
        unique_ips = cursor.fetchone()["unique_ips"]

        return {
            "total_events": total,
            "info_count": level_counts.get("INFO", 0),
            "warning_count": level_counts.get("WARNING", 0),
            "critical_count": level_counts.get("CRITICAL", 0),
            "unique_ips": unique_ips,
            "top_threats": top_threats
        }

    def get_suspicious_ips(self) -> list:
        """Retourne toutes les IPs suspectes triées par score de menace."""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT * FROM suspicious_ips 
            ORDER BY threat_score DESC
        """)
        return [dict(row) for row in cursor.fetchall()]

    def block_ip(self, ip: str):
        """
        Marque une IP comme bloquée dans la base de données.
        (Simulé : dans un vrai SOC, ça enverrait une commande au firewall)
        """
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE suspicious_ips SET is_blocked = 1 WHERE ip = ?
        """, (ip,))

        conn.commit()

    def clear_all_data(self):
        """Efface toutes les données (pour recommencer une simulation)."""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute("DELETE FROM events")
        cursor.execute("DELETE FROM statistics")
        cursor.execute("DELETE FROM suspicious_ips")
        conn.commit()
        print("[DATABASE] 🗑️ Toutes les données ont été effacées")

    def close(self):
        """Ferme proprement la connexion à la base de données."""
        if self.connection:
            self.connection.close()
            self.connection = None
            print("[DATABASE] 🔒 Connexion fermée")
