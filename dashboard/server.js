const express = require('express');
const path = require('path');

const app = express();
const PORT = 3000;

// Sert les fichiers statiques (HTML, CSS, JS) du dossier courant
app.use(express.static(__dirname));

app.listen(PORT, () => {
    console.log(`🖥️ Frontend SOC disponible sur http://localhost:${PORT}`);
});