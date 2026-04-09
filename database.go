package main

import "sync"

// Log représente un événement système
type Log struct {
	ID       int    `json:"id"`
	Type     string `json:"type"` // INFO, WARNING, CRITICAL
	Message  string `json:"message"`
	SourceIP string `json:"source_ip"`
}

var (
	Logs      []Log
	Score     int        = 0
	LogID     int        = 1
	Mutex     sync.Mutex // Pour éviter les conflits si on écrit en même temps
	BlockedIP []string
)

// AddLog ajoute un log à notre base de données virtuelle
func AddLog(logType, message, ip string) {
	Mutex.Lock()         // On verrouille la base
	defer Mutex.Unlock() // On déverrouillera à la fin

	Logs = append(Logs, Log{
		ID:       LogID,
		Type:     logType,
		Message:  message,
		SourceIP: ip,
	})
	LogID++
}
