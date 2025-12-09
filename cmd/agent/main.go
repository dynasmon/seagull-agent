package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
)

type NetEvent struct {
	AgentID   string                 `json:"agent_id"`
	EventType string                 `json:"event_type"`
	Timestamp time.Time              `json:"timestamp"`
	SrcIP     string                 `json:"src_ip,omitempty"`
	DstIP     string                 `json:"dst_ip,omitempty"`
	SrcPort   int                    `json:"src_port,omitempty"`
	DstPort   int                    `json:"dst_port,omitempty"`
	Proto     string                 `json:"proto,omitempty"`
	Bytes     int                    `json:"bytes,omitempty"`
	Extra     map[string]interface{} `json:"extra"`
}

func main() {
	agentID := getEnv("NETWATCH_AGENT_ID", "agent-unknown")
	apiURL := getEnv("NETWATCH_API_URL", "http://localhost:8000")

	log.Printf("[AGENT] Iniciando com ID=%s, backend=%s", agentID, apiURL)

	for {
		// Evento fake
		event := NetEvent{
			AgentID:   agentID,
			EventType: "flow",
			Timestamp: time.Now().UTC(),
			SrcIP:     "10.0.0.10",
			DstIP:     "10.0.0.20",
			SrcPort:   54321,
			DstPort:   22,
			Proto:     "tcp",
			Bytes:     1024,
			Extra: map[string]interface{}{
				"flow_id": uuid.New().String(),
				"note":    "evento de teste gerado pelo agente",
			},
		}

		events := []NetEvent{event}

		payload, err := json.Marshal(events)
		if err != nil {
			log.Printf("erro ao serializar evento: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}

		resp, err := http.Post(apiURL+"/ingest/events", "application/json", bytes.NewReader(payload))
		if err != nil {
			log.Printf("erro ao enviar evento: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}

		_ = resp.Body.Close()

		log.Printf("[AGENT] Evento enviado, status code=%d", resp.StatusCode)

		// Espera 10s
		time.Sleep(10 * time.Second)
	}
}

func getEnv(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}
