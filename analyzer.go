package main

// AnalyzeLogs vérifie si une IP a fait des choses suspectes
func AnalyzeLogs(ip string, typeAttaque string) {
	compteur := 0

	// On parcourt tous les logs
	for _, log := range Logs {
		if log.SourceIP == ip && (log.Type == "WARNING" || log.Type == "CRITICAL") {
			compteur++
		}
	}

	// Si plus de 5 avertissements, on déclenche une alerte rouge !
	if compteur >= 5 {
		AddLog("CRITICAL", "ALERTE SÉCURITÉ : "+typeAttaque+" détectée !", ip)
	}
}
