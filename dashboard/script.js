const API_URL = "http://localhost:8080/api";
let lastLogCount = 0;

// Fonction pour récupérer les logs toutes les secondes
async function fetchLogs() {
    try {
        const response = await fetch(`${API_URL}/logs`);
        const logs = await response.json();

        if (logs.length > lastLogCount) {
            renderLogs(logs);
            lastLogCount = logs.length;
        }
    } catch (error) {
        console.error("Erreur de connexion au backend", error);
    }
}

// Fonction pour afficher les logs dans l'HTML
function renderLogs(logs) {
    const logsDiv = document.getElementById('logs');
    logsDiv.innerHTML = ''; // On vide pour réécrire (simplification)

    // On inverse pour avoir le plus récent en haut
    [...logs].reverse().forEach(log => {
        const logItem = document.createElement('div');
        logItem.className = `log log-${log.type}`;

        let html = `<span>[${log.type}] IP: ${log.source_ip} - ${log.message}</span>`;

        // Si c'est critique, on propose des actions à l'analyste
        if (log.type === "CRITICAL" && log.source_ip !== "SOC") {
            html += `<span class="actions">
                <button onclick="takeAction('block', '${log.source_ip}')">Bloquer IP</button>
                <button onclick="takeAction('ignore', '${log.source_ip}')">Ignorer</button>
            </span>`;
        }

        logItem.innerHTML = html;
        logsDiv.appendChild(logItem);
    });
}

// Lancer une attaque via l'API
async function launchAttack(type) {
    await fetch(`${API_URL}/attack?type=${type}`);
    alert("Attaque lancée ! Observez les logs.");
}

// Prendre une décision (Bloquer ou Ignorer)
async function takeAction(action, ip) {
    const res = await fetch(`${API_URL}/action?type=${action}&ip=${ip}`);
    const message = await res.text();
    alert(message);
    fetchScore(); // Met à jour le score après l'action
}

// Mettre à jour le score
async function fetchScore() {
    const res = await fetch(`${API_URL}/score`);
    const data = await res.json();
    document.getElementById('score').innerText = data.score;
}

// Générer et afficher le rapport
async function generateReport() {
    const res = await fetch(`${API_URL}/report`);
    const text = await res.text();
    document.getElementById('report-content').innerText = text;
    document.getElementById('report-modal').classList.remove('hidden');
}

function closeReport() {
    document.getElementById('report-modal').classList.add('hidden');
}

// Boucle d'actualisation (répète toutes les 1000 millisecondes)
setInterval(fetchLogs, 1000);
setInterval(fetchScore, 3000);
fetchLogs(); // Appel initial