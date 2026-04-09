package main

import (
	"time"
)

// SimulateBruteForce crée une attaque de type Brute Force
func SimulateBruteForce() {
	ipAttaquante := "192.168.1.50"
	for i := 0; i < 6; i++ {
		AddLog("WARNING", "Échec de connexion SSH", ipAttaquante)
		time.Sleep(500 * time.Millisecond) // Pause d'une demi-seconde
	}
	AnalyzeLogs(ipAttaquante, "Brute Force")
}

// SimulatePortScan crée une attaque de type Scan de Ports
func SimulatePortScan() {
	ipAttaquante := "10.0.0.99"
	AddLog("INFO", "Connexion au port 80", ipAttaquante)
	AddLog("INFO", "Connexion au port 443", ipAttaquante)
	AddLog("WARNING", "Tentative d'accès au port 22", ipAttaquante)
	AddLog("WARNING", "Tentative d'accès au port 3306 (Base de données)", ipAttaquante)

	AnalyzeLogs(ipAttaquante, "Scan de Ports")
}
