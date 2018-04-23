package main

import (
	"encoding/json"
	"net/http"

	"github.com/siddontang/go/log"
)

type responseMessage struct {
	status  string
	message string
}

func renderJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Errorf("JSON encoding failed: %v", err)
	}
}
