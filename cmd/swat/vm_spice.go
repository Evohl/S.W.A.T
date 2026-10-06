package main

import (
	"net"
	"net/http"
	"strconv"

	"github.com/gorilla/websocket"

	"swat/internal/collect"
)

var vmSpiceUpgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	// spice-html5 requests the "binary" subprotocol; without echoing it back
	// the browser fails the WebSocket handshake before any SPICE data flows.
	Subprotocols: []string{"binary"},
	CheckOrigin: func(r *http.Request) bool {
		return r.Header.Get("Origin") == "" || r.Header.Get("Origin") == "https://"+r.Host || r.Header.Get("Origin") == "http://"+r.Host
	},
}

// handleVMSpice bridges a browser WebSocket connection to the VM's local SPICE
// TCP port, since QEMU's spice server has no native WebSocket support.
func handleVMSpice(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Methode nicht erlaubt", http.StatusMethodNotAllowed)
		return
	}
	if _, _, ok := currentSession(r); !ok {
		http.Error(w, "Anmeldung erforderlich", http.StatusUnauthorized)
		return
	}
	name := r.URL.Query().Get("name")
	if !vmNamePattern.MatchString(name) {
		http.Error(w, "Ungültiger VM-Name", http.StatusBadRequest)
		return
	}
	detail, err := collect.VMByName(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if detail.State != "running" || !detail.SpiceAvailable || detail.SpicePort <= 0 {
		http.Error(w, "Kein aktiver SPICE-Port verfügbar", http.StatusConflict)
		return
	}

	target, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(detail.SpicePort))
	if err != nil {
		http.Error(w, "SPICE-Port konnte nicht erreicht werden: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer target.Close()

	connection, err := vmSpiceUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer connection.Close()

	done := make(chan struct{})
	go func() {
		buffer := make([]byte, 4096)
		for {
			count, readErr := target.Read(buffer)
			if count > 0 {
				if writeErr := connection.WriteMessage(websocket.BinaryMessage, buffer[:count]); writeErr != nil {
					break
				}
			}
			if readErr != nil {
				break
			}
		}
		close(done)
	}()

	for {
		messageType, message, readErr := connection.ReadMessage()
		if readErr != nil {
			break
		}
		if messageType != websocket.BinaryMessage && messageType != websocket.TextMessage {
			continue
		}
		if _, writeErr := target.Write(message); writeErr != nil {
			break
		}
	}
	_ = target.(*net.TCPConn).CloseWrite()
	<-done
}
