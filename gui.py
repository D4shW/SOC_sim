"""
========================================
gui.py — Interface graphique (GUI) du SOC
========================================

📚 CONCEPT : QU'EST-CE QUE TKINTER ?
Tkinter est la bibliothèque graphique INTÉGRÉE à Python.
Elle permet de créer des fenêtres, boutons, tableaux...
Pas besoin de l'installer : elle vient avec Python !

Dans un vrai SOC, l'interface ressemble à des outils comme :
- Splunk (SIEM commercial)
- Kibana (dashboard Elasticsearch)
- Wazuh (SIEM open-source)

Notre GUI simule un dashboard SOC professionnel avec :
- Un panneau de logs en temps réel (avec couleurs)
- Des compteurs de statistiques
- Une liste des IPs suspectes
- Des boutons pour contrôler la simulation
- Un panneau pédagogique d'explication

📚 ARCHITECTURE GUI :
┌─────────────────────────────────────────┐
│ 🔴 HEADER : Titre + statut              │
├──────────────┬──────────────────────────┤
│ STATS PANEL  │  LOG VIEWER (temps réel) │
│  INFO: 45    │  [INFO]  Login alice...  │
│  WARN: 23    │  [WARN]  Port scan...   │
│  CRIT: 12    │  [CRIT]  Brute force... │
├──────────────┼──────────────────────────┤
│ IP SUSPICTES │  EXPLANATION PANEL      │
│ 192.168.1.5  │  ⚠️ RÈGLE: SSH BruteForce│
│ 203.0.113.7  │  Pattern: Failed passwd  │
└──────────────┴──────────────────────────┘
│ BOUTONS DE CONTRÔLE                     │
└─────────────────────────────────────────┘
"""

import tkinter as tk                    # Bibliothèque GUI principale
from tkinter import ttk, scrolledtext  # Widgets avancés de tkinter
import threading                         # Pour les mises à jour thread-safe
import time                              # Pour les délais
import json                              # Pour la config
import os                                # Pour les chemins
from datetime import datetime            # Pour les horodatages
from collections import deque           # Deque = liste avec taille maximale

# On importe notre monitor (qui orchestre tout)
from monitor import SOCMonitor


def load_config():
    """Charge la configuration depuis config.json"""
    config_path = os.path.join(os.path.dirname(__file__), "config.json")
    with open(config_path, "r") as f:
        return json.load(f)


class SOCGUI:
    """
    L'interface graphique complète du SOC Simulator.
    
    📚 ORGANISATION DU CODE GUI :
    1. __init__ : Configuration et création de la fenêtre
    2. create_* : Méthodes qui créent chaque partie de l'interface
    3. update_* : Méthodes qui mettent à jour l'affichage
    4. on_* : Gestionnaires d'événements (clics, etc.)
    5. _safe_* : Méthodes thread-safe pour les mises à jour
    """

    def __init__(self):
        """
        Initialise la GUI.
        Cette méthode est la première appelée.
        """
        # Charger la configuration
        self.config = load_config()
        self.colors = self.config["colors"]
        self.gui_config = self.config["gui"]

        # ---- CRÉATION DE LA FENÊTRE PRINCIPALE ----
        # tk.Tk() crée la fenêtre principale
        self.root = tk.Tk()
        self.root.title("🛡️ SOC Simulator — Security Operations Center")

        # Définir la taille de la fenêtre
        width = self.gui_config["window_width"]
        height = self.gui_config["window_height"]
        self.root.geometry(f"{width}x{height}")

        # Couleur de fond (noir cyber)
        self.root.configure(bg=self.colors["BACKGROUND"])

        # Empêcher la fenêtre d'être trop petite
        self.root.minsize(1000, 600)

        # ---- VARIABLES D'ÉTAT ----
        # Variables Tkinter (mises à jour automatiquement dans la GUI)
        # StringVar = texte, IntVar = nombre entier
        self.var_total = tk.StringVar(value="0")
        self.var_info = tk.StringVar(value="0")
        self.var_warning = tk.StringVar(value="0")
        self.var_critical = tk.StringVar(value="0")
        self.var_status = tk.StringVar(value="⏹ ARRÊTÉ")
        self.var_uptime = tk.StringVar(value="00:00:00")
        self.var_ips = tk.StringVar(value="0")

        # File d'attente thread-safe pour les events à afficher
        # La GUI ne peut être mise à jour QUE depuis le thread principal
        # On utilise une queue + after() pour passer les données en sécurité
        self.pending_events = deque(maxlen=500)

        # Compteur pour les statistiques locales
        self.local_stats = {"total": 0, "info": 0, "warning": 0, "critical": 0}

        # Référence au dernier event sélectionné (pour le panneau d'explication)
        self.selected_event = None

        # ---- CRÉER L'INTERFACE ----
        self._create_interface()

        # ---- INITIALISER LE MONITOR ----
        # On crée le monitor APRÈS la GUI
        # On passe notre méthode _on_new_event comme callback
        self.monitor = SOCMonitor(event_callback=self._on_new_event)

        # ---- DÉMARRER LA BOUCLE DE MISE À JOUR ----
        # after() planifie un appel futur depuis le thread principal
        # C'est la façon SÉCURISÉE de mettre à jour la GUI
        self._schedule_gui_update()

        print("[GUI] 🖥️ Interface graphique initialisée")

    def _create_interface(self):
        """Crée tous les éléments de l'interface."""
        self._create_header()
        self._create_main_area()
        self._create_control_bar()

    # ============================================================
    # SECTION 1 : HEADER
    # ============================================================

    def _create_header(self):
        """
        Crée la barre de titre en haut.
        Contient : logo, titre, statut, uptime.
        """
        # Frame = conteneur invisible pour organiser les widgets
        header_frame = tk.Frame(
            self.root,
            bg="#0D1117",      # Noir profond
            height=70,
            relief="flat"
        )
        header_frame.pack(fill="x", padx=0, pady=0)
        header_frame.pack_propagate(False)  # Empêche le redimensionnement automatique

        # ---- LOGO ET TITRE ----
        # Frame gauche pour le logo et titre
        left_frame = tk.Frame(header_frame, bg="#0D1117")
        left_frame.pack(side="left", padx=20, pady=10)

        # Logo ASCII
        tk.Label(
            left_frame,
            text="🛡️",
            font=("Courier", 28),
            bg="#0D1117",
            fg=self.colors["ACCENT"]
        ).pack(side="left", padx=(0, 10))

        # Titre principal
        title_frame = tk.Frame(left_frame, bg="#0D1117")
        title_frame.pack(side="left")

        tk.Label(
            title_frame,
            text="SOC SIMULATOR",
            font=("Courier", 18, "bold"),
            bg="#0D1117",
            fg=self.colors["ACCENT"]
        ).pack(anchor="w")

        tk.Label(
            title_frame,
            text="Security Operations Center v1.0",
            font=("Courier", 9),
            bg="#0D1117",
            fg="#4A5568"
        ).pack(anchor="w")

        # ---- INDICATEURS À DROITE ----
        right_frame = tk.Frame(header_frame, bg="#0D1117")
        right_frame.pack(side="right", padx=20)

        # Statut (RUNNING / PAUSED / STOPPED)
        status_container = tk.Frame(right_frame, bg="#1A202C", padx=10, pady=5)
        status_container.pack(side="right", padx=10)

        tk.Label(
            status_container,
            text="STATUT",
            font=("Courier", 8),
            bg="#1A202C",
            fg="#4A5568"
        ).pack()

        self.status_label = tk.Label(
            status_container,
            textvariable=self.var_status,
            font=("Courier", 11, "bold"),
            bg="#1A202C",
            fg="#FF2255"
        )
        self.status_label.pack()

        # Uptime
        uptime_container = tk.Frame(right_frame, bg="#1A202C", padx=10, pady=5)
        uptime_container.pack(side="right", padx=10)

        tk.Label(
            uptime_container,
            text="UPTIME",
            font=("Courier", 8),
            bg="#1A202C",
            fg="#4A5568"
        ).pack()

        tk.Label(
            uptime_container,
            textvariable=self.var_uptime,
            font=("Courier", 11, "bold"),
            bg="#1A202C",
            fg=self.colors["ACCENT"]
        ).pack()

    # ============================================================
    # SECTION 2 : ZONE PRINCIPALE
    # ============================================================

    def _create_main_area(self):
        """Crée la zone principale divisée en colonnes."""
        # Conteneur principal
        main_frame = tk.Frame(self.root, bg=self.colors["BACKGROUND"])
        main_frame.pack(fill="both", expand=True, padx=8, pady=8)

        # ---- COLONNE GAUCHE (stats + IPs suspectes) ----
        left_column = tk.Frame(main_frame, bg=self.colors["BACKGROUND"], width=280)
        left_column.pack(side="left", fill="y", padx=(0, 8))
        left_column.pack_propagate(False)

        self._create_stats_panel(left_column)
        self._create_ip_panel(left_column)

        # ---- COLONNE DROITE (logs + explication) ----
        right_column = tk.Frame(main_frame, bg=self.colors["BACKGROUND"])
        right_column.pack(side="left", fill="both", expand=True)

        self._create_log_viewer(right_column)
        self._create_explanation_panel(right_column)

    def _create_stats_panel(self, parent):
        """
        Panneau de statistiques : compteurs INFO / WARNING / CRITICAL / TOTAL.
        
        📚 grid() vs pack() :
        - pack() = placement simple (gauche, droite, haut, bas)
        - grid() = placement en tableau (ligne/colonne)
        On utilise grid() pour les stats car on veut une grille 2x2.
        """
        # ---- Titre du panneau ----
        panel = tk.LabelFrame(
            parent,
            text=" 📊 STATISTIQUES ",
            font=("Courier", 10, "bold"),
            bg=self.colors["PANEL"],
            fg=self.colors["ACCENT"],
            bd=1,
            relief="solid"
        )
        panel.pack(fill="x", pady=(0, 8))

        # ---- Grille de statistiques ----
        stats_data = [
            ("TOTAL EVENTS", self.var_total, self.colors["TEXT"], "🔵"),
            ("INFO", self.var_info, self.colors["INFO"], "✅"),
            ("WARNING", self.var_warning, self.colors["WARNING"], "⚠️"),
            ("CRITICAL", self.var_critical, self.colors["CRITICAL"], "🚨"),
        ]

        for i, (label, var, color, icon) in enumerate(stats_data):
            # Conteneur pour chaque stat
            stat_frame = tk.Frame(panel, bg="#1A202C", padx=8, pady=6)
            # grid() place en ligne i, colonne i%2 (0 ou 1 = 2 colonnes)
            stat_frame.grid(
                row=i // 2,    # Division entière : 0//2=0, 1//2=0, 2//2=1, 3//2=1
                column=i % 2,  # Modulo : 0%2=0, 1%2=1, 2%2=0, 3%2=1
                padx=4, pady=4,
                sticky="nsew"  # Étire le widget dans toutes les directions
            )

            # Icône et nom
            tk.Label(
                stat_frame,
                text=f"{icon} {label}",
                font=("Courier", 8),
                bg="#1A202C",
                fg="#718096"
            ).pack()

            # Nombre (grand et coloré)
            tk.Label(
                stat_frame,
                textvariable=var,
                font=("Courier", 22, "bold"),
                bg="#1A202C",
                fg=color
            ).pack()

        # Configurer les colonnes pour qu'elles aient le même poids (même largeur)
        panel.columnconfigure(0, weight=1)
        panel.columnconfigure(1, weight=1)

        # ---- IPs uniques ----
        ip_frame = tk.Frame(panel, bg="#0D1117", padx=8, pady=5)
        ip_frame.grid(row=2, column=0, columnspan=2, padx=4, pady=4, sticky="ew")

        tk.Label(
            ip_frame,
            text="🌐 IPs UNIQUES TRACKÉES",
            font=("Courier", 8),
            bg="#0D1117",
            fg="#718096"
        ).pack(side="left")

        tk.Label(
            ip_frame,
            textvariable=self.var_ips,
            font=("Courier", 12, "bold"),
            bg="#0D1117",
            fg=self.colors["ACCENT"]
        ).pack(side="right")

    def _create_ip_panel(self, parent):
        """
        Panneau des IPs suspectes avec score de menace.
        Utilise un ttk.Treeview (tableau).
        """
        panel = tk.LabelFrame(
            parent,
            text=" 🚩 IPs SUSPECTES ",
            font=("Courier", 10, "bold"),
            bg=self.colors["PANEL"],
            fg=self.colors["CRITICAL"],
            bd=1,
            relief="solid"
        )
        panel.pack(fill="both", expand=True)

        # ---- TREEVIEW = TABLEAU ----
        # columns = les colonnes du tableau (sauf la première "tree" column)
        columns = ("ip", "events", "score", "status")

        # Style pour le treeview (thème sombre)
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "SOC.Treeview",
            background="#111827",
            foreground="#E2E8F0",
            fieldbackground="#111827",
            borderwidth=0,
            font=("Courier", 9)
        )
        style.configure(
            "SOC.Treeview.Heading",
            background="#1A202C",
            foreground=self.colors["ACCENT"],
            font=("Courier", 9, "bold")
        )

        self.ip_tree = ttk.Treeview(
            panel,
            columns=columns,
            show="headings",   # "headings" = on affiche seulement les colonnes (pas la colonne tree)
            style="SOC.Treeview",
            height=8
        )

        # Définir les en-têtes de colonnes
        self.ip_tree.heading("ip", text="IP ADDRESS")
        self.ip_tree.heading("events", text="EVENTS")
        self.ip_tree.heading("score", text="SCORE")
        self.ip_tree.heading("status", text="STATUS")

        # Largeurs des colonnes
        self.ip_tree.column("ip", width=120)
        self.ip_tree.column("events", width=55)
        self.ip_tree.column("score", width=50)
        self.ip_tree.column("status", width=65)

        # Tags de couleur pour les lignes
        self.ip_tree.tag_configure("critical", foreground=self.colors["CRITICAL"])
        self.ip_tree.tag_configure("warning", foreground=self.colors["WARNING"])
        self.ip_tree.tag_configure("blocked", foreground="#666666", background="#1A0A0A")

        # Scrollbar vertical
        scrollbar_ip = ttk.Scrollbar(panel, orient="vertical", command=self.ip_tree.yview)
        self.ip_tree.configure(yscrollcommand=scrollbar_ip.set)

        self.ip_tree.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        scrollbar_ip.pack(side="right", fill="y", pady=5)

        # Double-clic pour bloquer une IP
        self.ip_tree.bind("<Double-Button-1>", self._on_ip_double_click)

    def _create_log_viewer(self, parent):
        """
        Panneau principal : affichage des logs en temps réel.
        
        📚 ScrolledText :
        C'est un widget Text avec une scrollbar intégrée.
        Parfait pour afficher des logs qui défilent.
        
        📚 TAGS DE COULEUR :
        Dans tkinter Text, on peut "tagger" des portions de texte
        et leur appliquer des styles (couleur, gras...).
        """
        panel = tk.LabelFrame(
            parent,
            text=" 📋 FLUX DE LOGS EN TEMPS RÉEL ",
            font=("Courier", 10, "bold"),
            bg=self.colors["PANEL"],
            fg=self.colors["TEXT"],
            bd=1,
            relief="solid"
        )
        panel.pack(fill="both", expand=True, pady=(0, 8))

        # ---- BARRE D'OUTILS DU LOG ----
        toolbar = tk.Frame(panel, bg=self.colors["PANEL"])
        toolbar.pack(fill="x", padx=5, pady=(5, 0))

        # Filtres
        tk.Label(toolbar, text="FILTRE:", font=("Courier", 9), bg=self.colors["PANEL"],
                 fg="#718096").pack(side="left")

        self.filter_var = tk.StringVar(value="ALL")
        for level in ["ALL", "INFO", "WARNING", "CRITICAL"]:
            color = {
                "ALL": self.colors["ACCENT"],
                "INFO": self.colors["INFO"],
                "WARNING": self.colors["WARNING"],
                "CRITICAL": self.colors["CRITICAL"]
            }.get(level, self.colors["TEXT"])

            tk.Radiobutton(
                toolbar,
                text=level,
                value=level,
                variable=self.filter_var,
                font=("Courier", 9, "bold"),
                bg=self.colors["PANEL"],
                fg=color,
                selectcolor=self.colors["BACKGROUND"],
                activebackground=self.colors["PANEL"]
            ).pack(side="left", padx=8)

        # Bouton "Clear Logs"
        tk.Button(
            toolbar,
            text="🗑 CLEAR",
            font=("Courier", 9, "bold"),
            bg="#2D1B1B",
            fg=self.colors["CRITICAL"],
            relief="flat",
            cursor="hand2",
            command=self._clear_logs
        ).pack(side="right", padx=5)

        # ---- ZONE DE TEXTE SCROLLABLE ----
        self.log_text = scrolledtext.ScrolledText(
            panel,
            wrap=tk.WORD,           # Retour à la ligne sur les mots entiers
            font=("Courier", 10),
            bg="#0A0E1A",           # Fond très sombre
            fg=self.colors["TEXT"],
            insertbackground=self.colors["ACCENT"],
            relief="flat",
            padx=8,
            pady=8,
            state="disabled",       # "disabled" = lecture seule (on ne peut pas écrire dedans)
            height=15
        )
        self.log_text.pack(fill="both", expand=True, padx=5, pady=5)

        # ---- CONFIGURATION DES TAGS DE COULEUR ----
        # Chaque tag définit un style pour une portion de texte
        self.log_text.tag_configure(
            "INFO",
            foreground=self.colors["INFO"],      # Vert
            font=("Courier", 10)
        )
        self.log_text.tag_configure(
            "WARNING",
            foreground=self.colors["WARNING"],   # Orange
            font=("Courier", 10, "bold")
        )
        self.log_text.tag_configure(
            "CRITICAL",
            foreground=self.colors["CRITICAL"],  # Rouge
            font=("Courier", 10, "bold")
        )
        self.log_text.tag_configure(
            "TIMESTAMP",
            foreground="#4A5568",                # Gris discret pour l'heure
            font=("Courier", 9)
        )
        self.log_text.tag_configure(
            "SELECTED",
            background="#1A2E1A"                 # Fond vert sombre pour la sélection
        )

        # Clic sur un log pour voir l'explication
        self.log_text.bind("<Button-1>", self._on_log_click)

    def _create_explanation_panel(self, parent):
        """
        Panneau pédagogique : explique l'alerte sélectionnée.
        C'est le MODE PÉDAGOGIQUE du SOC Simulator.
        """
        panel = tk.LabelFrame(
            parent,
            text=" 📚 MODE PÉDAGOGIQUE — EXPLICATION DE L'ALERTE ",
            font=("Courier", 10, "bold"),
            bg=self.colors["PANEL"],
            fg="#A78BFA",   # Violet pour le panneau éducatif
            bd=1,
            relief="solid"
        )
        panel.pack(fill="x", pady=(0, 0))

        self.explanation_text = scrolledtext.ScrolledText(
            panel,
            wrap=tk.WORD,
            font=("Courier", 10),
            bg="#0F0A1A",
            fg="#C4B5FD",
            relief="flat",
            padx=10,
            pady=8,
            state="disabled",
            height=6
        )
        self.explanation_text.pack(fill="x", padx=5, pady=5)

        # Message par défaut
        self._update_explanation(
            "👋 Bienvenue dans le SOC Simulator !\n\n"
            "🖱️ Cliquez sur un log dans le panneau ci-dessus pour voir\n"
            "l'explication détaillée de l'alerte.\n\n"
            "▶️ Appuyez sur DÉMARRER pour lancer la simulation."
        )

    # ============================================================
    # SECTION 3 : BARRE DE CONTRÔLE
    # ============================================================

    def _create_control_bar(self):
        """
        Barre de boutons de contrôle en bas de la fenêtre.
        """
        control_frame = tk.Frame(self.root, bg="#0D1117", height=60)
        control_frame.pack(fill="x", padx=0, pady=0)
        control_frame.pack_propagate(False)

        # Style commun pour les boutons
        btn_style = {
            "font": ("Courier", 10, "bold"),
            "relief": "flat",
            "cursor": "hand2",
            "padx": 15,
            "pady": 8,
            "bd": 0
        }

        # ---- BOUTON DÉMARRER ----
        self.btn_start = tk.Button(
            control_frame,
            text="▶  DÉMARRER",
            bg="#0D4A0D",
            fg=self.colors["INFO"],
            command=self._start_simulation,
            **btn_style
        )
        self.btn_start.pack(side="left", padx=(15, 5), pady=12)

        # ---- BOUTON PAUSE ----
        self.btn_pause = tk.Button(
            control_frame,
            text="⏸  PAUSE",
            bg="#2D2D00",
            fg=self.colors["WARNING"],
            command=self._pause_simulation,
            state="disabled",  # Désactivé au départ
            **btn_style
        )
        self.btn_pause.pack(side="left", padx=5, pady=12)

        # ---- BOUTON STOP ----
        self.btn_stop = tk.Button(
            control_frame,
            text="⏹  ARRÊTER",
            bg="#2D0D0D",
            fg=self.colors["CRITICAL"],
            command=self._stop_simulation,
            state="disabled",
            **btn_style
        )
        self.btn_stop.pack(side="left", padx=5, pady=12)

        # ---- SÉPARATEUR ----
        tk.Frame(control_frame, bg="#1A202C", width=2).pack(
            side="left", fill="y", padx=10, pady=8
        )

        # ---- LABEL SCÉNARIOS ----
        tk.Label(
            control_frame,
            text="SCÉNARIOS:",
            font=("Courier", 9),
            bg="#0D1117",
            fg="#4A5568"
        ).pack(side="left", padx=(5, 5))

        # ---- BOUTONS DE SCÉNARIOS ----
        scenarios = [
            ("🎯 APT ATTACK", "apt", "#1A0A2E", "#A78BFA"),
            ("💀 RANSOMWARE", "ransomware", "#2D0D0D", self.colors["CRITICAL"]),
            ("🕵️ INSIDER", "insider", "#2D1A00", self.colors["WARNING"]),
        ]

        for text, scenario, bg, fg in scenarios:
            btn = tk.Button(
                control_frame,
                text=text,
                bg=bg,
                fg=fg,
                command=lambda s=scenario: self._inject_scenario(s),
                **btn_style
            )
            btn.pack(side="left", padx=5, pady=12)

        # ---- BOUTON RESET ----
        tk.Frame(control_frame, bg="#1A202C", width=2).pack(
            side="right", fill="y", padx=10, pady=8
        )

        tk.Button(
            control_frame,
            text="🔄 RESET",
            bg="#1A1A2E",
            fg="#718096",
            command=self._reset_simulation,
            **btn_style
        ).pack(side="right", padx=(5, 15), pady=12)

    # ============================================================
    # SECTION 4 : LOGIQUE DE MISE À JOUR
    # ============================================================

    def _on_new_event(self, event: dict):
        """
        Callback appelé par le monitor à chaque nouvel événement.
        
        📚 IMPORTANT : THREAD SAFETY
        Cette méthode est appelée depuis le thread de traitement (PAS le thread GUI).
        On ne peut PAS modifier les widgets Tkinter directement depuis un autre thread.
        Solution : on ajoute l'event à une deque, et le thread GUI les traite via after().
        """
        # Vérifier le filtre
        current_filter = self.filter_var.get()
        if current_filter != "ALL" and event.get("level") != current_filter:
            pass  # On le met quand même dans pending pour les stats
        
        # On ajoute l'event à la file d'attente thread-safe
        self.pending_events.append(event)

    def _schedule_gui_update(self):
        """
        Planifie la prochaine mise à jour de la GUI.
        
        📚 after() = LA CLÉ DE TKINTER MULTI-THREAD
        self.root.after(ms, function) dit à Tkinter :
        "Dans {ms} millisecondes, appelle {function} depuis le thread principal."
        
        C'est comme un minuteur qui se relance en boucle.
        C'est LE moyen sécurisé de mettre à jour la GUI depuis d'autres threads.
        """
        # Traiter les events en attente
        self._process_pending_events()

        # Mettre à jour les statistiques
        self._update_stats_display()

        # Mettre à jour l'uptime
        self._update_uptime()

        # Relancer dans {refresh_rate} millisecondes (boucle infinie)
        refresh_rate = self.gui_config["refresh_rate_ms"]
        self.root.after(refresh_rate, self._schedule_gui_update)

    def _process_pending_events(self):
        """
        Traite tous les événements en attente (dans la deque).
        Appelé depuis le thread principal = safe pour Tkinter.
        """
        # On traite max 10 events par tick pour ne pas bloquer la GUI
        max_per_tick = 10
        processed = 0

        while self.pending_events and processed < max_per_tick:
            event = self.pending_events.popleft()  # Récupère le premier event
            self._add_log_entry(event)
            processed += 1

    def _add_log_entry(self, event: dict):
        """
        Ajoute une entrée dans le viewer de logs.
        
        📚 ÉTAT DES WIDGETS TKINTER :
        - state="disabled" = lecture seule (l'utilisateur ne peut pas modifier)
        - state="normal" = modifiable
        On doit temporairement passer en "normal" pour ajouter du texte.
        """
        # Vérifier le filtre actif
        level = event.get("level", "INFO")
        current_filter = self.filter_var.get()
        if current_filter != "ALL" and level != current_filter:
            # Mise à jour des stats quand même
            self._increment_local_stat(level)
            return

        # Formater l'entrée de log
        timestamp = event.get("timestamp", datetime.now().strftime("%H:%M:%S"))
        # On garde seulement HH:MM:SS si le timestamp contient la date
        if "T" in timestamp or len(timestamp) > 8:
            timestamp = timestamp.split(" ")[-1][:8] if " " in timestamp else timestamp[-8:]

        source_ip = event.get("source_ip", "?")
        message = event.get("message", "")

        # Formater le niveau avec padding (pour aligner)
        level_padded = f"[{level:<8}]"  # <8 = aligner à gauche sur 8 chars

        # Construire la ligne de log
        log_line = f"{timestamp} {level_padded} {source_ip:<15} {message}\n"

        # ---- AJOUTER LE TEXTE AU WIDGET ----
        self.log_text.config(state="normal")  # Activer l'écriture

        # Insérer à la fin ("end")
        start_idx = self.log_text.index("end-1c")  # Position avant l'insertion

        # On insère les différentes parties avec des tags différents
        self.log_text.insert("end", f"{timestamp} ", "TIMESTAMP")
        self.log_text.insert("end", f"{level_padded} ", level)
        self.log_text.insert("end", f"{source_ip:<15} ", level)
        self.log_text.insert("end", f"{message}\n", level)

        # Stocker l'event associé à cette ligne (pour l'explication au clic)
        # On utilise le tag de ligne pour stocker la référence
        line_num = int(self.log_text.index("end").split(".")[0]) - 1
        self.log_text.tag_add(f"line_{line_num}", f"{line_num}.0", f"{line_num}.end")

        # Limiter le nombre de lignes (éviter la surcharge mémoire)
        max_lines = self.gui_config["max_log_lines"]
        current_lines = int(self.log_text.index("end").split(".")[0])
        if current_lines > max_lines:
            # Supprimer les premières lignes
            self.log_text.delete("1.0", f"{current_lines - max_lines}.0")

        # Faire défiler automatiquement vers le bas
        self.log_text.see("end")

        self.log_text.config(state="disabled")  # Remettre en lecture seule

        # Mettre à jour les stats locales
        self._increment_local_stat(level)

        # Stocker le dernier event pour l'affichage de l'explication
        # On le lie au numéro de ligne actuel
        if not hasattr(self, '_event_by_line'):
            self._event_by_line = {}

        actual_line = int(self.log_text.index("end").split(".")[0]) - 1
        self._event_by_line[actual_line] = event

        # Nettoyer l'historique si trop grand
        if len(self._event_by_line) > 300:
            old_keys = sorted(self._event_by_line.keys())[:100]
            for k in old_keys:
                del self._event_by_line[k]

    def _increment_local_stat(self, level: str):
        """Incrémente les compteurs locaux."""
        self.local_stats["total"] += 1
        if level == "INFO":
            self.local_stats["info"] += 1
        elif level == "WARNING":
            self.local_stats["warning"] += 1
        elif level == "CRITICAL":
            self.local_stats["critical"] += 1

    def _update_stats_display(self):
        """Met à jour les compteurs affichés dans le panneau stats."""
        self.var_total.set(str(self.local_stats["total"]))
        self.var_info.set(str(self.local_stats["info"]))
        self.var_warning.set(str(self.local_stats["warning"]))
        self.var_critical.set(str(self.local_stats["critical"]))

        # Mettre à jour les IPs toutes les 10 secondes environ (DB query coûteuse)
        if self.local_stats["total"] % 20 == 0 and self.local_stats["total"] > 0:
            self._update_ip_list()

    def _update_ip_list(self):
        """Met à jour le tableau des IPs suspectes."""
        if not hasattr(self, 'monitor') or not self.monitor.is_running:
            return

        try:
            suspicious_ips = self.monitor.get_suspicious_ips()

            # Vider le tableau
            for item in self.ip_tree.get_children():
                self.ip_tree.delete(item)

            # Mettre à jour le compteur
            self.var_ips.set(str(len(suspicious_ips)))

            # Remplir avec les nouvelles données
            for ip_data in suspicious_ips[:20]:  # Max 20 IPs
                score = ip_data.get("threat_score", 0)
                is_blocked = ip_data.get("is_blocked", 0)

                # Déterminer le tag de couleur
                if is_blocked:
                    tag = "blocked"
                    status = "🚫 BLOCKED"
                elif score >= 60:
                    tag = "critical"
                    status = "🔴 CRITICAL"
                else:
                    tag = "warning"
                    status = "🟠 SUSPECT"

                # Insérer la ligne dans le tableau
                self.ip_tree.insert(
                    "",         # Parent (vide = racine)
                    "end",      # Position (à la fin)
                    values=(
                        ip_data.get("ip", "?"),
                        ip_data.get("event_count", 0),
                        f"{score}/100",
                        status
                    ),
                    tags=(tag,)
                )
        except Exception as e:
            pass  # Ignorer les erreurs de DB pendant la mise à jour

    def _update_uptime(self):
        """Met à jour l'affichage du temps de fonctionnement."""
        if hasattr(self, 'monitor') and self.monitor.is_running:
            stats = self.monitor.get_live_stats()
            seconds = stats.get("uptime_seconds", 0)
            hours = seconds // 3600
            minutes = (seconds % 3600) // 60
            secs = seconds % 60
            self.var_uptime.set(f"{hours:02d}:{minutes:02d}:{secs:02d}")

    def _update_explanation(self, text: str):
        """Met à jour le panneau d'explication pédagogique."""
        self.explanation_text.config(state="normal")
        self.explanation_text.delete("1.0", "end")
        self.explanation_text.insert("1.0", text)
        self.explanation_text.config(state="disabled")

    # ============================================================
    # SECTION 5 : GESTIONNAIRES D'ÉVÉNEMENTS (CALLBACKS)
    # ============================================================

    def _on_log_click(self, event):
        """
        Appelé quand l'utilisateur clique sur un log.
        Affiche l'explication dans le panneau pédagogique.
        """
        # Récupérer le numéro de ligne cliquée
        index = self.log_text.index(f"@{event.x},{event.y}")
        line_num = int(index.split(".")[0])

        # Chercher l'event associé à cette ligne
        if hasattr(self, '_event_by_line'):
            # Chercher la ligne la plus proche avec un event
            for offset in range(3):
                event_data = self._event_by_line.get(line_num - offset)
                if event_data:
                    self._display_event_explanation(event_data)
                    break

    def _display_event_explanation(self, event: dict):
        """Affiche l'explication détaillée d'un événement."""
        level = event.get("level", "INFO")
        event_type = event.get("event_type", "unknown")
        source_ip = event.get("source_ip", "unknown")
        timestamp = event.get("timestamp", "")
        message = event.get("message", "")
        explained = event.get("explained", "Aucune explication disponible.")
        threat_score = event.get("threat_score", 0)

        # Construire le texte d'explication
        mitre_info = ""
        if event.get("mitre_techniques"):
            mitre_info = f"\n🎯 MITRE ATT&CK: {', '.join(event['mitre_techniques'])}"

        rules_info = ""
        if event.get("triggered_rules"):
            rules = event["triggered_rules"]
            rules_info = f"\n📏 RÈGLES: {', '.join(r['rule_id'] for r in rules[:3])}"

        explanation = (
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"📅 {timestamp}  |  📊 SCORE: {threat_score}/100  |  🔖 {level}\n"
            f"🌐 SOURCE IP: {source_ip}  |  📌 TYPE: {event_type}\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            f"{explained}"
            f"{mitre_info}"
            f"{rules_info}\n\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"💡 LOG BRUT:\n{event.get('raw_log', 'N/A')}"
        )

        self._update_explanation(explanation)

    def _on_ip_double_click(self, event):
        """Double-clic sur une IP pour la 'bloquer' (simulé)."""
        selection = self.ip_tree.selection()
        if not selection:
            return

        item = self.ip_tree.item(selection[0])
        ip = item["values"][0]

        # Bloquer l'IP en DB
        if hasattr(self, 'monitor'):
            self.monitor.database.block_ip(ip)
            self._update_ip_list()

            self._update_explanation(
                f"🚫 IP BLOQUÉE : {ip}\n\n"
                f"Dans un vrai SOC, cette action enverrait une règle au firewall :\n"
                f"  iptables -A INPUT -s {ip} -j DROP\n\n"
                f"Ou sur un pare-feu Cisco :\n"
                f"  access-list 100 deny ip host {ip} any\n\n"
                f"L'IP est maintenant marquée comme bloquée dans la base de données.\n"
                f"Les événements provenant de cette IP seront toujours loggés\n"
                f"mais l'alerte indiquera qu'elle est bloquée."
            )

    # ============================================================
    # SECTION 6 : CONTRÔLES DE SIMULATION
    # ============================================================

    def _start_simulation(self):
        """Démarre la simulation."""
        if not self.monitor.is_running:
            self.monitor.start()

            # Mettre à jour l'interface
            self.var_status.set("▶ EN COURS")
            self.status_label.config(fg=self.colors["INFO"])
            self.btn_start.config(state="disabled")
            self.btn_pause.config(state="normal")
            self.btn_stop.config(state="normal")

            self._update_explanation(
                "🚀 SIMULATION DÉMARRÉE !\n\n"
                "Le simulateur génère maintenant des événements de sécurité aléatoires.\n"
                "Observez les logs défiler en temps réel dans le panneau principal.\n\n"
                "🟢 VERT = Événements normaux (INFO)\n"
                "🟠 ORANGE = Événements suspects (WARNING)\n"
                "🔴 ROUGE = Attaques détectées (CRITICAL)\n\n"
                "💡 Cliquez sur n'importe quel log pour voir son explication détaillée.\n"
                "💡 Utilisez les boutons de scénarios pour simuler des attaques spécifiques."
            )

    def _pause_simulation(self):
        """Met la simulation en pause/reprend."""
        if self.monitor.is_paused:
            self.monitor.resume()
            self.btn_pause.config(text="⏸  PAUSE")
            self.var_status.set("▶ EN COURS")
            self.status_label.config(fg=self.colors["INFO"])
        else:
            self.monitor.pause()
            self.btn_pause.config(text="▶  REPRENDRE")
            self.var_status.set("⏸ EN PAUSE")
            self.status_label.config(fg=self.colors["WARNING"])

    def _stop_simulation(self):
        """Arrête la simulation."""
        self.monitor.stop()

        self.var_status.set("⏹ ARRÊTÉ")
        self.status_label.config(fg=self.colors["CRITICAL"])
        self.btn_start.config(state="normal")
        self.btn_pause.config(state="disabled", text="⏸  PAUSE")
        self.btn_stop.config(state="disabled")

    def _inject_scenario(self, scenario_type: str):
        """Injecte un scénario d'attaque complet."""
        if not self.monitor.is_running:
            self._start_simulation()
            time.sleep(0.5)

        count = self.monitor.inject_scenario(scenario_type)

        scenario_names = {
            "apt": "APT (Advanced Persistent Threat)",
            "ransomware": "RANSOMWARE",
            "insider": "INSIDER THREAT"
        }

        scenario_explanations = {
            "apt": (
                "🎯 SCÉNARIO APT INJECTÉ\n\n"
                "APT = Advanced Persistent Threat (Menace Persistante Avancée)\n\n"
                "Un groupe APT est souvent sponsorisé par un État (ex: APT28 = Russie,\n"
                "APT41 = Chine). Ils s'infiltrent discrètement et restent des mois\n"
                "dans le réseau avant d'agir.\n\n"
                "📋 PHASES DE L'ATTAQUE :\n"
                "1️⃣ Reconnaissance (port scan)\n"
                "2️⃣ Tentatives d'intrusion (brute force)\n"
                "3️⃣ Exploitation web (SQL injection)\n"
                "4️⃣ Installation backdoor (malware)\n"
                "5️⃣ Élévation de privilèges\n"
                "6️⃣ Exfiltration de données\n\n"
                f"→ {count} événements injectés dans la simulation"
            ),
            "ransomware": (
                "💀 SCÉNARIO RANSOMWARE INJECTÉ\n\n"
                "Un ransomware chiffre toutes les données d'une organisation\n"
                "et demande une rançon pour les déchiffrer.\n\n"
                "Exemples célèbres :\n"
                "  • WannaCry (2017) - 150 pays touchés\n"
                "  • NotPetya (2017) - 10 milliards $ de dégâts\n"
                "  • Colonial Pipeline (2021) - pénurie de carburant aux USA\n\n"
                "📋 PHASES :\n"
                "1️⃣ Intrusion initiale\n"
                "2️⃣ Élévation de privilèges\n"
                "3️⃣ Exfiltration (double extorsion)\n"
                "4️⃣ Chiffrement des fichiers\n\n"
                f"→ {count} événements injectés dans la simulation"
            ),
            "insider": (
                "🕵️ SCÉNARIO INSIDER THREAT INJECTÉ\n\n"
                "Une menace interne vient de quelqu'un DANS l'organisation.\n"
                "Employé mécontent, espion, ou compte compromis.\n\n"
                "C'est l'une des menaces les plus difficiles à détecter car :\n"
                "  • L'accès est légitime\n"
                "  • L'activité paraît normale\n"
                "  • Connaissance des défenses internes\n\n"
                "📋 INDICATEURS :\n"
                "  • Accès à des données inhabituelles\n"
                "  • Copies massives de fichiers\n"
                "  • Connexions à des heures anormales\n"
                "  • Tentatives d'élévation de privilèges\n\n"
                f"→ {count} événements injectés depuis des IPs INTERNES"
            )
        }

        self._update_explanation(
            scenario_explanations.get(scenario_type, f"Scénario {scenario_type} injecté : {count} événements")
        )

    def _reset_simulation(self):
        """Remet tout à zéro."""
        was_running = self.monitor.is_running

        if was_running:
            self._stop_simulation()

        # Reset des données
        self.monitor.clear_data()

        # Reset de l'affichage
        self.local_stats = {"total": 0, "info": 0, "warning": 0, "critical": 0}
        self._clear_logs()
        self._update_ip_list()

        if hasattr(self, '_event_by_line'):
            self._event_by_line.clear()

        self._update_explanation(
            "🔄 SIMULATION REMISE À ZÉRO\n\n"
            "Toutes les données ont été effacées :\n"
            "  • Logs vidés\n"
            "  • Base de données nettoyée\n"
            "  • Compteurs remis à 0\n"
            "  • IPs suspectes effacées\n\n"
            "Appuyez sur DÉMARRER pour lancer une nouvelle simulation."
        )

        if was_running:
            self._start_simulation()

    def _clear_logs(self):
        """Vide le panneau de logs."""
        self.log_text.config(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.config(state="disabled")

    # ============================================================
    # SECTION 7 : DÉMARRAGE
    # ============================================================

    def run(self):
        """
        Lance la boucle principale de Tkinter.
        
        📚 mainloop() :
        C'est LA méthode qui "lance" l'interface.
        Elle tourne en boucle infinie et gère :
        - Les événements utilisateur (clics, frappes)
        - Les mises à jour de l'affichage
        - Les callbacks after()
        
        Le programme reste ici jusqu'à ce que la fenêtre soit fermée.
        """
        print("[GUI] 🚀 Lancement de la boucle principale Tkinter...")

        # Gestion de la fermeture propre
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        # Lancer la boucle
        self.root.mainloop()

    def _on_close(self):
        """Appelé quand l'utilisateur ferme la fenêtre."""
        print("[GUI] 👋 Fermeture de l'application...")

        # Arrêter proprement le monitor
        if self.monitor.is_running:
            self.monitor.stop()

        # Fermer la fenêtre
        self.root.destroy()
