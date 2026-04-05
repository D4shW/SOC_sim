"""
========================================
main.py — Point d'entrée du SOC Simulator
========================================

📚 CONCEPT : LE POINT D'ENTRÉE
C'est le premier fichier exécuté quand on lance le programme.
C'est lui qui "orchestre" le lancement de tout le reste.

Pour lancer le projet :
    python main.py

📦 STRUCTURE DU PROJET RAPPEL :
    soc_simulator/
    ├── main.py         ← Vous êtes ici (point d'entrée)
    ├── gui.py          ← Interface graphique
    ├── monitor.py      ← Orchestrateur (threading)
    ├── simulator.py    ← Générateur d'événements
    ├── analyzer.py     ← Moteur de détection
    ├── database.py     ← Stockage SQLite
    └── config.json     ← Configuration
"""

# ---- IMPORTS SYSTÈME ----
import sys          # Pour accéder aux arguments de ligne de commande
import os           # Pour les opérations sur les fichiers/dossiers
import json         # Pour lire la configuration
import platform     # Pour détecter l'OS (Windows, Mac, Linux)


def check_python_version():
    """
    Vérifie que Python 3.7+ est utilisé.
    
    📚 sys.version_info :
    Contient la version de Python.
    sys.version_info.major = 3 (pour Python 3.x)
    sys.version_info.minor = 9 (pour Python 3.9.x)
    """
    if sys.version_info < (3, 7):
        print("❌ ERREUR : Python 3.7 ou supérieur est requis !")
        print(f"   Version actuelle : Python {sys.version}")
        print("   Téléchargez Python sur : https://www.python.org/downloads/")
        sys.exit(1)  # Quitter avec code d'erreur

    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor} détecté")


def check_dependencies():
    """
    Vérifie que toutes les dépendances sont disponibles.
    Toutes ces bibliothèques sont INTÉGRÉES à Python (pas besoin de pip install).
    """
    required_modules = {
        "tkinter": "Interface graphique (GUI)",
        "sqlite3": "Base de données SQLite",
        "threading": "Exécution parallèle",
        "re": "Expressions régulières",
        "json": "Lecture de la configuration",
        "random": "Génération aléatoire",
        "time": "Gestion du temps",
    }

    all_ok = True

    for module, description in required_modules.items():
        try:
            # __import__ permet d'importer dynamiquement (par nom)
            __import__(module)
            print(f"  ✅ {module:<12} — {description}")
        except ImportError:
            print(f"  ❌ {module:<12} — MANQUANT ! ({description})")
            all_ok = False

    return all_ok


def check_config():
    """
    Vérifie que le fichier de configuration existe et est valide.
    """
    config_path = os.path.join(os.path.dirname(__file__), "config.json")

    if not os.path.exists(config_path):
        print(f"❌ ERREUR : config.json introuvable à : {config_path}")
        return False

    try:
        with open(config_path, "r") as f:
            config = json.load(f)
        print(f"✅ config.json chargé avec succès")
        return True
    except json.JSONDecodeError as e:
        print(f"❌ ERREUR : config.json est invalide : {e}")
        return False


def display_banner():
    """
    Affiche la bannière de démarrage dans le terminal.
    
    📚 ASCII ART :
    L'art ASCII utilise des caractères texte pour former des dessins.
    C'est traditionnel dans les outils de sécurité (Metasploit, Nmap...).
    """
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║    ███████╗ ██████╗  ██████╗     ███████╗██╗███╗   ███╗    ║
    ║    ██╔════╝██╔═══██╗██╔════╝     ██╔════╝██║████╗ ████║    ║
    ║    ███████╗██║   ██║██║         ███████╗██║██╔████╔██║    ║
    ║    ╚════██║██║   ██║██║         ╚════██║██║██║╚██╔╝██║    ║
    ║    ███████║╚██████╔╝╚██████╗    ███████║██║██║ ╚═╝ ██║    ║
    ║    ╚══════╝ ╚═════╝  ╚═════╝    ╚══════╝╚═╝╚═╝     ╚═╝    ║
    ║                                                              ║
    ║         SECURITY OPERATIONS CENTER SIMULATOR v1.0           ║
    ║              Un projet pédagogique Python                    ║
    ║                                                              ║
    ╠══════════════════════════════════════════════════════════════╣
    ║  Simule : Brute Force • Port Scan • SQL Injection • DDoS    ║
    ║           Malware • Privilege Escalation • Data Exfiltration ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def display_system_info():
    """Affiche les informations système."""
    print("📋 INFORMATIONS SYSTÈME")
    print("=" * 45)
    print(f"  OS        : {platform.system()} {platform.release()}")
    print(f"  Python    : {sys.version.split()[0]}")
    print(f"  Répertoire: {os.getcwd()}")
    print("=" * 45)


def run_demo_mode():
    """
    Mode démonstration sans GUI (pour tester dans un terminal).
    Lancé avec : python main.py --demo
    """
    print("\n🎮 MODE DÉMO — Test des composants sans GUI")
    print("=" * 45)

    # Importer et tester le simulateur
    from simulator import AttackSimulator
    from analyzer import ThreatAnalyzer
    from database import SOCDatabase

    sim = AttackSimulator()
    analyzer = ThreatAnalyzer()
    db = SOCDatabase()

    print("\n📡 Génération de 5 événements test...")
    for i in range(5):
        event = sim.generate_event()
        analyzed = analyzer.analyze_event(event)
        db.save_event(analyzed)

        level_icons = {"INFO": "✅", "WARNING": "⚠️", "CRITICAL": "🚨"}
        icon = level_icons.get(analyzed["level"], "📝")
        print(f"  {icon} [{analyzed['level']:<8}] {analyzed['message'][:60]}...")

    print("\n📊 Statistiques de la simulation :")
    stats = db.get_statistics()
    print(f"  Total events : {stats['total_events']}")
    print(f"  INFO         : {stats['info_count']}")
    print(f"  WARNING      : {stats['warning_count']}")
    print(f"  CRITICAL     : {stats['critical_count']}")
    print(f"  IPs uniques  : {stats['unique_ips']}")

    db.close()
    print("\n✅ Démo terminée ! Lancez sans --demo pour l'interface graphique.")


def main():
    """
    Fonction principale — Point d'entrée du programme.
    
    📚 if __name__ == "__main__" :
    Cette condition est VRAIE seulement quand on exécute ce fichier directement.
    Si quelqu'un importe main.py, cette partie ne s'exécute PAS.
    C'est une convention Python très importante !
    """

    # Afficher la bannière
    display_banner()
    display_system_info()

    print("\n🔍 VÉRIFICATIONS DE DÉMARRAGE")
    print("=" * 45)

    # 1. Vérifier la version Python
    check_python_version()

    # 2. Vérifier les dépendances
    print("\n📦 Vérification des modules...")
    if not check_dependencies():
        print("\n❌ Des modules manquants ont été détectés. Impossible de démarrer.")
        sys.exit(1)

    # 3. Vérifier la configuration
    print("\n⚙️ Vérification de la configuration...")
    if not check_config():
        sys.exit(1)

    # 4. Changer le répertoire de travail vers le dossier du script
    # Important pour que les chemins relatifs fonctionnent
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)

    print("\n✅ Toutes les vérifications passées !")

    # 5. Mode démo ou mode GUI ?
    if "--demo" in sys.argv:
        run_demo_mode()
        return

    # 6. Lancer l'interface graphique
    print("\n🖥️ Lancement de l'interface graphique...")
    print("=" * 45)
    print("  💡 Conseil : Appuyez sur DÉMARRER pour lancer la simulation")
    print("  💡 Cliquez sur un log pour voir son explication détaillée")
    print("  💡 Double-cliquez sur une IP suspecte pour la 'bloquer'")
    print("  💡 Utilisez les boutons de scénarios pour des attaques spécifiques")
    print("=" * 45)

    try:
        # Importer et créer la GUI
        # On importe ici pour que les vérifications se fassent d'abord
        from gui import SOCGUI

        # Créer l'application
        app = SOCGUI()

        # Lancer la boucle principale (bloque ici jusqu'à fermeture)
        app.run()

    except ImportError as e:
        print(f"\n❌ Erreur d'importation : {e}")
        print("Vérifiez que tous les fichiers .py sont dans le même dossier.")
        sys.exit(1)

    except Exception as e:
        print(f"\n❌ Erreur inattendue : {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    print("\n👋 SOC Simulator fermé. À bientôt !")


# ============================================================
# POINT D'ENTRÉE
# ============================================================
# Cette ligne est LA PLUS IMPORTANTE du fichier.
# Elle dit : "Si ce fichier est exécuté directement, appelle main()"
# Si quelqu'un fait 'import main', cette partie ne s'exécute PAS.

if __name__ == "__main__":
    main()
