// --- VARIABLES GLOBALES ---
let stats = { total: 0, warnings: 0, criticals: 0, blocked: 0, score: 0 };
let allLogs = [];
let logIdCounter = 1;
let lineChart, doughnutChart;
let eventsTimeline = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
let currentSecondEvents = 0;

// Base de connaissances pédagogique
const explanations = {
    'brute': "<strong>Brute Force :</strong> L'attaquant essaie de deviner un mot de passe en testant des milliers de combinaisons à la seconde. <em>Indicateur :</em> Multiples échecs de connexion rapprochés.",
    'scan': "<strong>Scan de Ports :</strong> L'attaquant 'toque' à toutes les portes (ports) du serveur pour voir lesquelles sont ouvertes et potentiellement vulnérables.",
    'sqli': "<strong>Injection SQL :</strong> L'attaquant insère du code de base de données (ex: ' OR '1'='1) dans un formulaire web pour tromper le système et se connecter sans mot de passe.",
    'ddos': "<strong>DDoS :</strong> Des milliers d'ordinateurs zombies envoient des requêtes en même temps pour saturer votre serveur et le faire planter.",
    'fp': "<strong>Faux Positif :</strong> Une activité qui semble suspecte mais qui est légitime. Par exemple, un employé qui oublie son mot de passe 3 fois de suite."
};

// --- INITIALISATION ---
document.addEventListener("DOMContentLoaded", () => {
    initCharts();
    setInterval(() => {
        eventsTimeline.shift(); eventsTimeline.push(currentSecondEvents);
        lineChart.update(); currentSecondEvents = 0;
    }, 1000);
});

function switchView(viewName, element) {
    document.querySelectorAll('#nav-menu li').forEach(li => li.classList.remove('active'));
    element.classList.add('active');
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active-view'));
    document.getElementById('view-' + viewName).classList.add('active-view');
    const titles = { 'overview': 'Global Threat Dashboard', 'alerts': 'Incident Response & Alerts', 'history': 'Event Database', 'missions': 'Centre de Formation SOC' };
    document.getElementById('page-title').innerText = titles[viewName];
}

// --- GRAPHIQUES ---
function initCharts() {
    const ctxLine = document.getElementById('lineChart').getContext('2d');
    lineChart = new Chart(ctxLine, {
        type: 'line', data: { labels: ['-9s', '-8s', '-7s', '-6s', '-5s', '-4s', '-3s', '-2s', '-1s', 'Live'], datasets: [{ label: 'Events', data: eventsTimeline, borderColor: '#3b82f6', backgroundColor: 'rgba(59, 130, 246, 0.1)', borderWidth: 2, fill: true, tension: 0.4 }] },
        options: { responsive: true, maintainAspectRatio: false, animation: false, scales: { y: { beginAtZero: true, suggestedMax: 5 } }, plugins: { legend: { display: false } } }
    });
    const ctxDoughnut = document.getElementById('doughnutChart').getContext('2d');
    doughnutChart = new Chart(ctxDoughnut, {
        type: 'doughnut', data: { labels: ['INFO', 'WARNING', 'CRITICAL'], datasets: [{ data: [0, 0, 0], backgroundColor: ['#10b981', '#f59e0b', '#ef4444'], borderWidth: 0 }] },
        options: { responsive: true, maintainAspectRatio: false, cutout: '75%', plugins: { legend: { position: 'right', labels: { color: '#94a3b8' } } } }
    });
}

// --- LOGGING ENGINE ---
function createLog(level, message, ip, type = 'general', isFalsePositive = false) {
    stats.total++; currentSecondEvents++;
    if (level === "WARNING") stats.warnings++;
    if (level === "CRITICAL") stats.criticals++;

    const now = new Date().toLocaleTimeString();
    const logEntry = { id: logIdCounter++, time: now, level: level, ip: ip, message: message, type: type, isFP: isFalsePositive };
    allLogs.push(logEntry);

    updateOverviewDashboard();
    addLogToTerminal(logEntry);
    if (level === "CRITICAL") addLogToAlertsTable(logEntry);
    addLogToHistoryTable(logEntry);
}

function updateOverviewDashboard() {
    document.getElementById('total-logs').innerText = stats.total;
    document.getElementById('total-warnings').innerText = stats.warnings;
    document.getElementById('total-criticals').innerText = stats.criticals;
    document.getElementById('total-blocked').innerText = stats.blocked;
    document.getElementById('score').innerText = stats.score;
    doughnutChart.data.datasets[0].data = [stats.total - stats.warnings - stats.criticals, stats.warnings, stats.criticals];
    doughnutChart.update();
}

function addLogToTerminal(log) {
    const terminal = document.getElementById('terminal');
    const div = document.createElement('div');
    div.className = `log log-${log.level.toLowerCase()}`;

    // Ajout du lien cliquable sur l'IP
    let logHTML = `<span class="log-time">[${log.time}]</span> <strong>[${log.level}]</strong> IP: <span class="ip-link" onclick="analyzeIP('${log.ip}')">${log.ip}</span> - ${log.message}`;

    if (log.level === "CRITICAL" && log.ip !== "SOC_ADMIN") {
        logHTML += `<br><button class="btn-block" style="margin-top:5px;" onclick="handleAlert('${log.ip}', ${log.isFP}, 'block', this)">Bloquer IP</button>
                    <button class="btn-ignore" style="margin-top:5px; margin-left:5px;" onclick="handleAlert('${log.ip}', ${log.isFP}, 'ignore', this)">Ignorer (FP)</button>`;
    }
    div.innerHTML = logHTML;
    terminal.appendChild(div);
    terminal.scrollTop = terminal.scrollHeight;
}

function addLogToAlertsTable(log) {
    const tbody = document.getElementById('alerts-table-body');
    const tr = document.createElement('tr');
    tr.innerHTML = `
        <td>${log.time}</td>
        <td><span class="badge badge-critical">${log.level}</span></td>
        <td><span class="ip-link" onclick="analyzeIP('${log.ip}')">${log.ip}</span></td>
        <td>${log.message}</td>
        <td><button class="btn-edu" onclick="openExplanation('${log.type}')">🎓 Comprendre</button></td>
        <td>
            <button class="btn-block" onclick="handleAlert('${log.ip}', ${log.isFP}, 'block', this)">Bloquer</button>
            <button class="btn-ignore" onclick="handleAlert('${log.ip}', ${log.isFP}, 'ignore', this)">Ignorer</button>
        </td>
    `;
    tbody.insertBefore(tr, tbody.firstChild);
}

function addLogToHistoryTable(log) {
    const tbody = document.getElementById('history-table-body');
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>#${log.id}</td><td>${log.time}</td><td><span class="badge badge-${log.level.toLowerCase()}">${log.level}</span></td><td>${log.ip}</td><td>${log.message}</td>`;
    tbody.insertBefore(tr, tbody.firstChild);
}

// --- GESTION DES DÉCISIONS (Vrai vs Faux Positifs) ---
function handleAlert(ip, isFP, action, btnElement) {
    let parentCell = btnElement.parentElement;

    if (action === 'block') {
        if (isFP) {
            stats.score -= 50; // AIE ! Bloqué un employé !
            createLog("CRITICAL", `ERREUR SOC : Vous avez bloqué un employé légitime (${ip}). -50 Pts.`, "SOC_ADMIN");
            document.getElementById('score').style.color = "var(--critical)";
        } else {
            stats.score += 50;
            stats.blocked++;
            createLog("INFO", `Succès SOC : Attaquant ${ip} neutralisé. +50 Pts.`, "SOC_ADMIN");
            document.getElementById('score').style.color = "var(--info)";
        }
        parentCell.innerHTML = `<span style="color:var(--critical); font-weight:bold;">Action : BLOQUÉ</span>`;
    }
    else if (action === 'ignore') {
        if (isFP) {
            stats.score += 50; // Bien vu !
            createLog("INFO", `Succès SOC : Faux positif bien identifié pour ${ip}. +50 Pts.`, "SOC_ADMIN");
            document.getElementById('score').style.color = "var(--info)";
        } else {
            stats.score -= 100; // AIE ! Attaque ignorée !
            createLog("CRITICAL", `ERREUR FATALE : Vous avez ignoré une attaque réelle (${ip}) ! -100 Pts.`, "SOC_ADMIN");
            document.getElementById('score').style.color = "var(--critical)";
        }
        parentCell.innerHTML = `<span style="color:var(--warning); font-weight:bold;">Action : IGNORÉ</span>`;
    }
    setTimeout(() => document.getElementById('score').style.color = "var(--info)", 1000);
}

// --- FONCTIONNALITÉS MODALES (Timeline & Pédagogie) ---
function analyzeIP(ip) {
    const ipLogs = allLogs.filter(l => l.ip === ip);
    let html = `
        <div class="threat-intel">
            <p><strong>Rapport Threat Intelligence pour ${ip}</strong></p>
            <p>🌍 Géolocalisation : ${Math.random() > 0.5 ? 'Russie (Moscou)' : 'USA (AWS Datacenter)'}</p>
            <p>🚨 Réputation AbuseIPDB : ${ipLogs[ipLogs.length - 1]?.isFP ? 'Saine (IP Corporate)' : 'Malveillante (Score: 89/100)'}</p>
        </div>
        <h3>🕵️ Timeline de l'incident :</h3>
        <div class="timeline">
    `;
    ipLogs.forEach(l => {
        html += `<div class="timeline-item"><strong>[${l.time}]</strong> <span class="badge badge-${l.level.toLowerCase()}">${l.level}</span> : ${l.message}</div>`;
    });
    html += `</div>`;

    document.getElementById('modal-title').innerText = `Analyse : ${ip}`;
    document.getElementById('modal-body').innerHTML = html;
    document.getElementById('modal-overlay').classList.remove('hidden');
}

function openExplanation(type) {
    document.getElementById('modal-title').innerText = `🎓 Comprendre l'Alerte`;
    document.getElementById('modal-body').innerHTML = `<p style="line-height:1.6; font-size:1.1rem;">${explanations[type] || explanations['fp']}</p>`;
    document.getElementById('modal-overlay').classList.remove('hidden');
}

function closeModal() {
    document.getElementById('modal-overlay').classList.add('hidden');
}

// --- GÉNÉRATEUR D'ATTAQUES ---
function triggerAttack(type) {
    const ip = `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.1`;

    if (type === 'brute') {
        createLog("INFO", "Nouvelle connexion SSH entrante", ip, 'brute');
        let count = 0;
        const bInt = setInterval(() => {
            createLog("WARNING", "sshd: Failed password for root", ip, 'brute');
            if (++count >= 4) { clearInterval(bInt); setTimeout(() => createLog("CRITICAL", "BRUTE FORCE SSH DÉTECTÉ", ip, 'brute', false), 200); }
        }, 300);
    }
    else if (type === 'false_positive') {
        const fp_ip = "192.168.1.55"; // IP Interne
        createLog("INFO", "Connexion VPN initiée par 'Directeur_Finance'", fp_ip, 'fp');
        let count = 0;
        const fpInt = setInterval(() => {
            createLog("WARNING", "Erreur d'authentification (Bad Password)", fp_ip, 'fp', true);
            if (++count >= 3) { clearInterval(fpInt); setTimeout(() => createLog("CRITICAL", "ALERTE : Multiples échecs de connexion (Compte Directeur)", fp_ip, 'fp', true), 500); }
        }, 1500); // Plus lent qu'un robot
    }
    else if (type === 'scan') {
        createLog("INFO", "TCP SYN Packet received port 80", ip, 'scan');
        setTimeout(() => createLog("WARNING", "Connexion suspecte port 22", ip, 'scan'), 250);
        setTimeout(() => createLog("CRITICAL", "SCAN DE PORTS HORIZONTAL DÉTECTÉ", ip, 'scan', false), 600);
    }
    else if (type === 'sqli') {
        createLog("INFO", "GET /store.php?id=1 HTTP/1.1", ip, 'sqli');
        setTimeout(() => createLog("WARNING", "GET /store.php?id=1' HTTP/1.1 500 ERROR", ip, 'sqli'), 800);
        setTimeout(() => createLog("CRITICAL", "INJECTION SQL RÉUSSIE", ip, 'sqli', false), 1600);
    }
    else if (type === 'ddos') {
        createLog("WARNING", "Détection pic de requêtes", "Multiple IPs", 'ddos');
        for (let i = 0; i < 15; i++) setTimeout(() => createLog("INFO", "GET / HTTP/1.1", `Botnet_${i}`, 'ddos'), i * 50);
        setTimeout(() => createLog("CRITICAL", "ATTAQUE DDoS VOLUMÉTRIQUE", "Multiple IPs", 'ddos', false), 800);
    }
}

// --- MISSIONS ---
function startMission(id) {
    switchView('overview', document.querySelector('#nav-menu li:first-child')); // Retourne sur l'écran principal
    createLog("INFO", `--- DÉBUT DE LA MISSION ${id} ---`, "SYSTEM");

    if (id === 1) {
        setTimeout(() => triggerAttack('scan'), 1000); // Vraie attaque
        setTimeout(() => triggerAttack('false_positive'), 3000); // Le faux positif pour piéger
    }
    else if (id === 2) {
        setTimeout(() => triggerAttack('ddos'), 1000); // Diversion (le DDoS est dur à bloquer IP par IP)
        setTimeout(() => triggerAttack('brute'), 2000); // La vraie intrusion silencieuse
    }
}