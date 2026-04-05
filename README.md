# 🛡️ SOC Simulator — Tutoriel Complet

## Security Operations Center Simulator en Python

---

## 🎯 Qu'est-ce que ce projet ?

Ce projet est un **simulateur pédagogique d'un SOC** (Security Operations Center).

Un SOC est le "centre de commandement" de la cybersécurité d'une entreprise. Des analystes y surveillent en permanence les systèmes informatiques pour détecter et répondre aux attaques.

Ce simulateur vous permet de :
- Voir des attaques informatiques en temps réel (simulées)
- Comprendre comment un SOC analyse les logs
- Apprendre les concepts de cybersécurité de façon interactive
- S'entraîner à reconnaître les patterns d'attaque

---

## 📦 Structure du projet

```
soc_simulator/
├── main.py         → Point d'entrée (lancez ce fichier !)
├── gui.py          → Interface graphique Tkinter
├── monitor.py      → Orchestrateur (threading)
├── simulator.py    → Générateur d'événements
├── analyzer.py     → Moteur de détection
├── database.py     → Stockage SQLite
└── config.json     → Configuration
```

---

## 🚀 Installation et lancement

### Prérequis
- Python 3.7 ou supérieur
- Aucune bibliothèque externe à installer !

### Lancement

```bash
# Dans le dossier du projet :
python main.py

# Mode démonstration (sans GUI, pour tester) :
python main.py --demo
```

---

## 📚 Tutoriel étape par étape

### ÉTAPE 1 : La GUI principale (gui.py)

**Concept :** Tkinter crée des fenêtres avec des widgets (boutons, zones de texte...).

```python
import tkinter as tk

# Créer une fenêtre
root = tk.Tk()
root.title("Mon SOC")
root.geometry("800x600")

# Lancer la boucle principale
root.mainloop()
```

**Ce que vous voyez :** Une fenêtre vide. C'est votre canevas vierge !

---

### ÉTAPE 2 : Afficher des logs simples

**Concept :** `ScrolledText` permet d'afficher du texte scrollable.

```python
from tkinter import scrolledtext

# Zone de texte scrollable
log_area = scrolledtext.ScrolledText(root, height=20)
log_area.pack(fill="both", expand=True)

# Ajouter du texte
log_area.insert("end", "2024-01-15 10:30:00 [INFO] Connexion réussie\n")
log_area.insert("end", "2024-01-15 10:30:05 [WARNING] Tentative échouée\n")
```

---

### ÉTAPE 3 : Le simulateur d'attaques

**Concept :** On génère des logs fictifs réalistes avec `random`.

```python
import random
from datetime import datetime

def generate_failed_login():
    ips = ["203.0.113.1", "198.51.100.5"]
    users = ["admin", "root", "test"]
    ip = random.choice(ips)
    user = random.choice(users)
    return f"{datetime.now()} sshd: Failed password for {user} from {ip}"

# Tester :
print(generate_failed_login())
# → 2024-01-15 10:30:00 sshd: Failed password for admin from 203.0.113.1
```

---

### ÉTAPE 4 : Connecter les logs à la GUI

**Concept :** Une fonction callback reçoit les logs et les affiche.

```python
def add_log(message, level="INFO"):
    colors = {"INFO": "green", "WARNING": "orange", "CRITICAL": "red"}
    
    log_area.config(state="normal")
    log_area.insert("end", message + "\n", level)
    log_area.tag_configure(level, foreground=colors[level])
    log_area.see("end")
    log_area.config(state="disabled")
```

---

### ÉTAPE 5 : Analyser les logs avec regex

**Concept :** `re` (regular expressions) cherche des patterns dans le texte.

```python
import re

def detect_brute_force(log_text):
    # Chercher "Failed password" dans le log
    pattern = r"Failed password for (.+) from ([\d.]+)"
    match = re.search(pattern, log_text)
    
    if match:
        username = match.group(1)  # 1er groupe capturé
        ip = match.group(2)        # 2ème groupe capturé
        return f"ALERTE: Brute force par {ip} sur compte {username}"
    return None
```

**Regex expliqués :**
- `(.+)` = capture tout caractère, une fois ou plus
- `([\d.]+)` = capture chiffres et points (adresse IP)
- `\b` = limite de mot

---

### ÉTAPE 6 : Ajouter le threading

**Problème :** Si la simulation tourne dans le thread principal, la GUI se "gèle".

**Solution :** Un thread séparé pour la simulation !

```python
import threading
import time

def simulation_loop():
    while running:
        event = generate_event()
        # ⚠️ On ne peut PAS modifier la GUI directement depuis ici !
        # On utilise une queue thread-safe
        event_queue.put(event)
        time.sleep(random.uniform(0.5, 2.0))

# Démarrer le thread
thread = threading.Thread(target=simulation_loop, daemon=True)
thread.start()
```

**Important :** `daemon=True` = le thread s'arrête avec le programme principal.

---

### ÉTAPE 7 : Couleurs et alertes

**Concept :** Les tags Tkinter permettent de colorer des portions de texte.

```python
# Définir les styles
log_text.tag_configure("INFO",     foreground="#00FF88")  # Vert
log_text.tag_configure("WARNING",  foreground="#FF9900")  # Orange  
log_text.tag_configure("CRITICAL", foreground="#FF2255")  # Rouge

# Utiliser le tag lors de l'insertion
log_text.insert("end", "[CRITICAL] Attaque détectée!\n", "CRITICAL")
```

---

### ÉTAPE 8 : Statistiques avec StringVar

**Concept :** `StringVar` est une variable tkinter qui met à jour l'affichage automatiquement.

```python
# Créer la variable
count = tk.StringVar(value="0")

# L'attacher à un label
label = tk.Label(root, textvariable=count, font=("Courier", 20))
label.pack()

# La mettre à jour (le label s'actualise automatiquement !)
count.set("42")
```

---

### ÉTAPE 9 : SQLite pour la persistance

**Concept :** SQLite stocke les données dans un fichier local.

```python
import sqlite3

# Connexion (crée le fichier si inexistant)
conn = sqlite3.connect("soc.db")
cursor = conn.cursor()

# Créer une table
cursor.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        level TEXT,
        message TEXT
    )
""")

# Insérer des données
cursor.execute(
    "INSERT INTO events (timestamp, level, message) VALUES (?, ?, ?)",
    ("2024-01-15 10:30:00", "CRITICAL", "Brute force détecté")
)
conn.commit()

# Lire les données
cursor.execute("SELECT * FROM events ORDER BY id DESC LIMIT 10")
for row in cursor.fetchall():
    print(row)
```

---

### ÉTAPE 10 : Améliorer le simulateur

Ajoutez de nouveaux types d'attaques et des scénarios complets :

```python
def generate_apt_scenario():
    """Scénario APT complet : 6 phases d'attaque"""
    return [
        generate_port_scan(),           # Phase 1: Reconnaissance
        generate_ssh_brute_force(),     # Phase 2: Intrusion
        generate_sql_injection(),       # Phase 3: Exploitation
        generate_malware_detection(),   # Phase 4: Installation
        generate_privilege_escalation(),# Phase 5: Escalade
        generate_data_exfiltration(),   # Phase 6: Vol de données
    ]
```

---

## 🔥 Types d'attaques simulées

| Attaque | Description | Indicateurs |
|---------|-------------|-------------|
| **Brute Force SSH** | Essai massif de mots de passe | Nombreux "Failed password" |
| **Port Scan** | Reconnaissance des services ouverts | Logs iptables en rafale |
| **SQL Injection** | Injection de code dans les formulaires | Payloads SQL dans les logs web |
| **DDoS** | Saturation par millions de requêtes | Pic de trafic soudain |
| **Malware** | Logiciel malveillant détecté | Alerte antivirus |
| **Privilege Escalation** | Élévation vers root | Commandes sudo suspectes |
| **Data Exfiltration** | Vol de données | Gros transferts sortants |

---

## 🎯 Framework MITRE ATT&CK

Chaque attaque est liée à une technique MITRE ATT&CK :

| ID | Technique | Notre simulation |
|----|-----------|-----------------|
| T1110.001 | Brute Force: Password Guessing | SSH Brute Force |
| T1046 | Network Service Discovery | Port Scan |
| T1190 | Exploit Public-Facing Application | SQL Injection |
| T1498 | Network Denial of Service | DDoS |
| T1204 | User Execution | Malware Detection |
| T1548 | Abuse Elevation Control Mechanism | Privilege Escalation |
| T1048 | Exfiltration Over Alt Protocol | Data Exfiltration |

MITRE ATT&CK est **le référentiel mondial** des techniques d'attaque.
URL : https://attack.mitre.org/

---

## 💡 Idées d'améliorations avancées

### Niveau Intermédiaire
- **Graphiques en temps réel** avec `matplotlib` ou `plotly`
- **Export des logs** en CSV ou JSON
- **Notifications système** (toast notifications)
- **Mode replay** : rejouer une simulation enregistrée

### Niveau Avancé
- **Détection d'anomalies ML** avec `scikit-learn`
  ```python
  from sklearn.ensemble import IsolationForest
  # Détecter les comportements anormaux statistiquement
  ```
- **API IP Reputation** (AbuseIPDB, VirusTotal)
  ```python
  import requests
  # Vérifier si une IP est connue comme malveillante
  response = requests.get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}")
  ```
- **Règles Sigma** : implémenter le standard de détection Sigma
- **Intégration MISP** : partage d'indicators of compromise (IoC)

### Niveau Expert
- **Machine Learning UEBA** : User and Entity Behavior Analytics
- **Threat Hunting** automatisé
- **SOAR** : Orchestration et réponse automatisée
- **Integration Elasticsearch** pour les vraies recherches de logs

---

## 🏆 Valoriser ce projet (CV / Portfolio)

### Sur votre CV
```
Projet : SOC Simulator (Python)
- Développé un simulateur de Security Operations Center avec GUI Tkinter
- Implémenté 7 types d'attaques (Brute Force, SQLi, DDoS, Ransomware...)
- Créé un moteur de détection basé sur des règles regex (MITRE ATT&CK)
- Architecture multi-threads (simulation, analyse, GUI en parallèle)
- Base de données SQLite pour la persistance et l'historique
Technologies : Python, Tkinter, SQLite, Threading, Regex
```

### Sur GitHub
- Créez un README avec des screenshots
- Ajoutez des "badges" (Python version, license)
- Documentez chaque module

### Compétences démontrées
- Python intermédiaire/avancé
- Concepts SOC/SIEM
- Architecture multi-threads
- Base de données SQL
- Analyse de logs
- Framework MITRE ATT&CK
- Développement d'outils de sécurité

---

## 📖 Lexique cybersécurité

| Terme | Définition |
|-------|------------|
| **SOC** | Security Operations Center — équipe de surveillance 24/7 |
| **SIEM** | Security Information and Event Management — agrège et analyse les logs |
| **IOC** | Indicator of Compromise — preuve d'une attaque (IP, hash, domaine) |
| **TTPs** | Tactics, Techniques and Procedures — méthodes des attaquants |
| **APT** | Advanced Persistent Threat — attaque ciblée longue durée |
| **Brute Force** | Essai systématique de toutes les combinaisons possibles |
| **Privilege Escalation** | Obtenir des droits supérieurs à ceux accordés |
| **Lateral Movement** | Se déplacer d'une machine à l'autre dans un réseau |
| **Exfiltration** | Vol et transfert de données vers l'extérieur |
| **C2/C&C** | Command & Control — serveur qui contrôle les malwares |
| **EDR** | Endpoint Detection and Response — antivirus avancé |
| **WAF** | Web Application Firewall — protège les applications web |

---

## 🙏 Ressources pour aller plus loin

- **TryHackMe** : https://tryhackme.com (lab cybersécurité interactif)
- **MITRE ATT&CK** : https://attack.mitre.org
- **Wazuh** : https://wazuh.com (SIEM open-source)
- **Elastic SIEM** : https://www.elastic.co/siem
- **Splunk Free** : https://www.splunk.com/en_us/download.html

---

*Projet créé à des fins pédagogiques. Ne pas utiliser pour des activités malveillantes.*
