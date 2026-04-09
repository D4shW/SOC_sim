package main

import (
	"fmt"
	"net/http"
)

func main() {
	fmt.Println("🚀 Démarrage du Simulateur SOC Backend sur le port 8080...")

	// Un log de bienvenue
	AddLog("INFO", "Démarrage du système SIEM", "127.0.0.1")

	SetupRoutes()

	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		fmt.Println("Erreur du serveur :", err)
	}
}
