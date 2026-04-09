package main

import "fmt"

// HandleAction traite le choix du joueur face à une IP suspecte
func HandleAction(action string, ip string) string {
	Mutex.Lock()
	defer Mutex.Unlock()

	if action == "block" {
		BlockedIP = append(BlockedIP, ip)
		Score += 10 // Bonne décision !
		AddLog("INFO", fmt.Sprintf("L'analyste a bloqué l'IP %s", ip), "SOC")
		return "IP bloquée avec succès. +10 points."
	} else if action == "ignore" {
		Score -= 5 // Mauvaise décision !
		AddLog("CRITICAL", fmt.Sprintf("L'analyste a ignoré l'IP %s. L'attaque continue !", ip), "SOC")
		return "Alerte ignorée. -5 points de pénalité."
	}
	return "Action inconnue"
}

// GenerateReport crée un résumé de l'incident
func GenerateReport() string {
	rapport := fmt.Sprintf("=== RAPPORT D'INCIDENT ===\n")
	rapport += fmt.Sprintf("Score de l'analyste : %d points\n", Score)
	rapport += fmt.Sprintf("Nombre total de logs : %d\n", len(Logs))
	rapport += fmt.Sprintf("IP Bloquées : %v\n", BlockedIP)
	rapport += "----------------------------\n"
	rapport += "Conclusion : "
	if Score > 0 {
		rapport += "L'analyste a bien réagi face aux menaces."
	} else {
		rapport += "L'analyste doit être formé. Des menaces sont passées."
	}
	return rapport
}
