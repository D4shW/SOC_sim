"""
========================================
monitor.py — Moteur de surveillance en temps réel
========================================

📚 CONCEPT : QU'EST-CE QUE LE THREADING ?
Imaginez un restaurant :
- Le cuisinier prépare les plats (simulateur génère des events)
- Le serveur les apporte aux tables (monitor envoie à la GUI)
- Le caissier encaisse (database sauvegarde)

Ils travaillent EN MÊME TEMPS = parallèlement = en "threads".

Sans threading, notre programme ferait une chose à la fois :
1. Générer un event → 2. L'analyser → 3. Afficher → 4. Sauvegarder
Et pendant ce temps, l'interface serait GELÉE (frozen).

Avec threading, tout se passe en parallèle et l'interface reste fluide.

📦 RÔLE DE CE FICHIER :
Ce fichier orchestre tout :
1. Lance le thread de simulation
2. Lance le thread de surveillance de fichier
3. Appelle l'analyseur pour chaque event
4. Sauvegarde dans la DB
5. Envoie les alertes à la GUI (via une queue)
"""

import threading      # Pour créer des threads (exécutions parallèles)
import time           # Pour les délais (sleep)
import queue          # Pour la communication thread-safe entre threads
import json           # Pour la config
import os             # Pour les chemins
import random         # Pour les intervalles aléatoires
from datetime import datetime

# On importe nos modules personnalisés
from simulator import AttackSimulator
from analyzer import ThreatAnalyzer
from database import SOCDatabase


def load_config():
    """Charge la configuration depuis config.json"""
    config_path = os.path.join(os.path.dirname(__file__), "config.json")
    with open(config_path, "r") as f:
        return json.load(f)


class SOCMonitor:
    """
    Le chef d'orchestre du SOC.
    Il coordonne simulation, analyse, stockage et affichage.
    
    📚 QUEUE (FILE D'ATTENTE) :
    La queue est comme une file d'attente au supermarché.
    - Le simulateur "dépose" des events dans la queue
    - La GUI "récupère" les events de la queue pour les afficher
    - Thread-safe : plusieurs threads peuvent l'utiliser sans conflit
    """

    def __init__(self, event_callback=None):
        """
        Initialise le monitor.
        
        Paramètre event_callback :
        C'est une FONCTION qui sera appelée à chaque nouvel événement.
        La GUI passera sa propre fonction ici pour recevoir les events.
        
        📚 CALLBACK = RAPPEL :
        Un callback est comme laisser son numéro de téléphone.
        "Quand tu as quelque chose pour moi, appelle ce numéro."
        Ici : "Quand tu as un event, appelle cette fonction."
        """
        config = load_config()
        self.sim_config = config["simulator"]

        # Notre queue thread-safe (capacity max = 1000 events en attente)
        self.event_queue = queue.Queue(maxsize=1000)

        # Nos composants principaux
        self.simulator = AttackSimulator()
        self.analyzer = ThreatAnalyzer()
        self.database = SOCDatabase()

        # La fonction callback pour notifier la GUI
        self.event_callback = event_callback

        # Flags de contrôle (True = en marche, False = arrêté)
        self._running = False       # Le monitor tourne-t-il ?
        self._paused = False        # Est-il en pause ?

        # Statistiques en mémoire (mise à jour rapide)
        self.stats = {
            "total_events": 0,
            "info_count": 0,
            "warning_count": 0,
            "critical_count": 0,
            "events_per_minute": 0,
            "uptime_seconds": 0,
        }

        # Références aux threads (pour les gérer)
        self._simulation_thread = None
        self._processing_thread = None
        self._stats_thread = None

        # Heure de démarrage
        self.start_time = None

        print("[MONITOR] 🎛️ SOC Monitor initialisé")

    def start(self):
        """
        Démarre tous les threads du monitor.
        
        📚 daemon=True :
        Un thread "daemon" s'arrête automatiquement quand
        le programme principal se ferme. Sans ça, le programme
        ne se fermerait jamais !
        """
        if self._running:
            print("[MONITOR] ⚠️ Monitor déjà en cours d'exécution")
            return

        self._running = True
        self._paused = False
        self.start_time = time.time()

        print("[MONITOR] 🚀 Démarrage du monitor SOC...")

        # Thread 1 : Génération d'événements
        # Ce thread simule des attaques en continu
        self._simulation_thread = threading.Thread(
            target=self._simulation_loop,
            name="SOC-Simulator",
            daemon=True     # S'arrête avec le programme principal
        )

        # Thread 2 : Traitement des événements
        # Ce thread prend les events de la queue et les traite
        self._processing_thread = threading.Thread(
            target=self._processing_loop,
            name="SOC-Processor",
            daemon=True
        )

        # Thread 3 : Mise à jour des statistiques
        self._stats_thread = threading.Thread(
            target=self._stats_loop,
            name="SOC-Stats",
            daemon=True
        )

        # On démarre les 3 threads
        self._simulation_thread.start()
        self._processing_thread.start()
        self._stats_thread.start()

        print("[MONITOR] ✅ Tous les threads démarrés")
        print(f"[MONITOR] Thread simulation : {self._simulation_thread.name}")
        print(f"[MONITOR] Thread traitement : {self._processing_thread.name}")
        print(f"[MONITOR] Thread statistiques : {self._stats_thread.name}")

    def stop(self):
        """Arrête proprement tous les threads."""
        print("[MONITOR] 🛑 Arrêt du monitor SOC...")
        self._running = False

        # On attend que les threads se terminent (max 2 secondes chacun)
        if self._simulation_thread and self._simulation_thread.is_alive():
            self._simulation_thread.join(timeout=2)

        if self._processing_thread and self._processing_thread.is_alive():
            self._processing_thread.join(timeout=2)

        if self._stats_thread and self._stats_thread.is_alive():
            self._stats_thread.join(timeout=2)

        self.database.close()
        print("[MONITOR] ✅ Monitor arrêté proprement")

    def pause(self):
        """Met le simulateur en pause (l'analyse continue)."""
        self._paused = True
        print("[MONITOR] ⏸️ Simulation en pause")

    def resume(self):
        """Reprend la simulation."""
        self._paused = False
        print("[MONITOR] ▶️ Simulation reprise")

    def _simulation_loop(self):
        """
        Thread 1 : Boucle de simulation.
        Génère des events et les place dans la queue.
        
        📚 BOUCLE INFINIE :
        while self._running continue tant que _running = True.
        Dès qu'on appelle stop(), _running devient False et la boucle s'arrête.
        """
        print(f"[SIMULATOR THREAD] Démarré - ID: {threading.current_thread().ident}")

        while self._running:
            # Si en pause, on attend et on recommence
            if self._paused:
                time.sleep(0.1)
                continue

            try:
                # Générer un événement aléatoire
                event = self.simulator.generate_event()

                # Tenter de placer l'event dans la queue
                # block=False = si la queue est pleine, lever une exception (pas bloquer)
                # On évite ainsi de bloquer le thread si la GUI est lente
                try:
                    self.event_queue.put_nowait(event)
                except queue.Full:
                    # Queue pleine : on perd cet event (acceptable en prod)
                    pass

                # Délai aléatoire entre les events (simule le trafic réel)
                delay = random.uniform(
                    self.sim_config["event_interval_min"],
                    self.sim_config["event_interval_max"]
                )
                time.sleep(delay)

            except Exception as e:
                print(f"[SIMULATOR THREAD] Erreur: {e}")
                time.sleep(1)

    def _processing_loop(self):
        """
        Thread 2 : Boucle de traitement.
        Récupère les events de la queue, les analyse et les sauvegarde.
        
        📚 POURQUOI UN THREAD SÉPARÉ POUR LE TRAITEMENT ?
        L'analyse et la sauvegarde en DB peuvent être lentes.
        En les faisant dans un thread séparé, le simulateur peut
        continuer à générer des events sans attendre.
        """
        print(f"[PROCESSOR THREAD] Démarré - ID: {threading.current_thread().ident}")

        while self._running:
            try:
                # On essaie de récupérer un event de la queue
                # timeout=0.5 : si pas d'event en 0.5s, on recommence la boucle
                # Ça permet de vérifier régulièrement si _running est encore True
                try:
                    event = self.event_queue.get(timeout=0.5)
                except queue.Empty:
                    # Pas d'event en attente, on continue la boucle
                    continue

                # 1. Analyser l'événement
                analyzed_event = self.analyzer.analyze_event(event)

                # 2. Mettre à jour les statistiques en mémoire
                self._update_stats(analyzed_event)

                # 3. Sauvegarder en base de données
                try:
                    self.database.save_event(analyzed_event)
                except Exception as db_error:
                    print(f"[PROCESSOR THREAD] Erreur DB: {db_error}")

                # 4. Notifier la GUI via le callback
                if self.event_callback:
                    try:
                        # On appelle la fonction de la GUI avec l'event traité
                        self.event_callback(analyzed_event)
                    except Exception as cb_error:
                        print(f"[PROCESSOR THREAD] Erreur callback: {cb_error}")

                # 5. Marquer l'event comme traité dans la queue
                self.event_queue.task_done()

            except Exception as e:
                print(f"[PROCESSOR THREAD] Erreur inattendue: {e}")
                time.sleep(0.1)

    def _stats_loop(self):
        """
        Thread 3 : Mise à jour des statistiques globales.
        S'exécute toutes les 5 secondes.
        """
        print(f"[STATS THREAD] Démarré - ID: {threading.current_thread().ident}")

        while self._running:
            time.sleep(5)  # Mise à jour toutes les 5 secondes

            if self.start_time:
                self.stats["uptime_seconds"] = int(time.time() - self.start_time)

    def _update_stats(self, event: dict):
        """
        Met à jour les compteurs de statistiques.
        Appelé après chaque event traité.
        """
        self.stats["total_events"] += 1

        level = event.get("level", "INFO")
        if level == "INFO":
            self.stats["info_count"] += 1
        elif level == "WARNING":
            self.stats["warning_count"] += 1
        elif level == "CRITICAL":
            self.stats["critical_count"] += 1

    def inject_scenario(self, scenario_type: str):
        """
        Injecte un scénario d'attaque complet dans la queue.
        Utilisé par la GUI quand l'utilisateur clique "Simuler une attaque".
        
        Paramètre scenario_type : "apt", "ransomware", ou "insider"
        """
        print(f"[MONITOR] 🎭 Injection du scénario : {scenario_type}")
        events = self.simulator.generate_attack_scenario(scenario_type)

        for event in events:
            try:
                self.event_queue.put_nowait(event)
            except queue.Full:
                pass

        return len(events)

    def get_live_stats(self) -> dict:
        """Retourne les statistiques en temps réel (depuis la mémoire, pas la DB)."""
        return dict(self.stats)

    def get_db_stats(self) -> dict:
        """Retourne les statistiques depuis la base de données (plus complètes)."""
        return self.database.get_statistics()

    def get_suspicious_ips(self) -> list:
        """Retourne la liste des IPs suspectes depuis la DB."""
        return self.database.get_suspicious_ips()

    def clear_data(self):
        """Remet à zéro toutes les données (simulation + DB)."""
        self.analyzer.reset()
        self.database.clear_all_data()

        # Réinitialiser les stats en mémoire
        self.stats = {k: 0 for k in self.stats}

        # Vider la queue
        while not self.event_queue.empty():
            try:
                self.event_queue.get_nowait()
            except queue.Empty:
                break

        print("[MONITOR] 🔄 Toutes les données remises à zéro")

    @property
    def is_running(self) -> bool:
        """Propriété pour vérifier si le monitor tourne."""
        return self._running

    @property
    def is_paused(self) -> bool:
        """Propriété pour vérifier si le monitor est en pause."""
        return self._paused
