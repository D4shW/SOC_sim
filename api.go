package main

import (
	"encoding/json"
	"net/http"
)

// SetupRoutes configure notre API REST
func SetupRoutes() {
	// Route pour récupérer les logs
	http.HandleFunc("/api/logs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*") // Permet au frontend de nous parler
		json.NewEncoder(w).Encode(Logs)
	})

	// Route pour récupérer le score
	http.HandleFunc("/api/score", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		json.NewEncoder(w).Encode(map[string]int{"score": Score})
	})

	// Route pour lancer une attaque
	http.HandleFunc("/api/attack", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		typeAttaque := r.URL.Query().Get("type")
		if typeAttaque == "brute" {
			go SimulateBruteForce() // "go" permet de lancer ça en arrière-plan !
		} else if typeAttaque == "scan" {
			go SimulatePortScan()
		}
		w.Write([]byte("Attaque lancée"))
	})

	// Route pour prendre une décision
	http.HandleFunc("/api/action", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		action := r.URL.Query().Get("type")
		ip := r.URL.Query().Get("ip")
		resultat := HandleAction(action, ip)
		w.Write([]byte(resultat))
	})

	// Route pour le rapport
	http.HandleFunc("/api/report", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Write([]byte(GenerateReport()))
	})
}
