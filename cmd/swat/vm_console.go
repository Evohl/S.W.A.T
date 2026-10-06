package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"

	"swat/internal/collect"
)

var vmConsoleUpgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin: func(r *http.Request) bool {
		return r.Header.Get("Origin") == "" || r.Header.Get("Origin") == "https://"+r.Host || r.Header.Get("Origin") == "http://"+r.Host
	},
}

func handleVMConsole(w http.ResponseWriter, r *http.Request) {
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
	if detail.State != "running" {
		http.Error(w, "Die VM ist nicht gestartet", http.StatusConflict)
		return
	}
	connection, err := vmConsoleUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer connection.Close()

	// virsh console refuses to run without a controlling TTY, so allocate a real pty.
	command := exec.Command("virsh", "--connect", "qemu:///system", "console", "--force", name)
	command.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	tty, err := pty.Start(command)
	if err != nil {
		writeVMConsoleError(connection, err)
		return
	}
	defer tty.Close()

	var writeLock sync.Mutex
	outputDone := make(chan struct{})
	go func() {
		buffer := make([]byte, 4096)
		for {
			count, readErr := tty.Read(buffer)
			if count > 0 {
				writeLock.Lock()
				// Binary frames carry raw terminal bytes without UTF-8 validation.
				_ = connection.WriteMessage(websocket.BinaryMessage, buffer[:count])
				writeLock.Unlock()
			}
			if readErr != nil {
				break
			}
		}
		writeLock.Lock()
		_ = connection.WriteMessage(websocket.BinaryMessage, []byte("\r\n[Konsole beendet]\r\n"))
		_ = connection.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "Konsole beendet"), time.Now().Add(time.Second))
		writeLock.Unlock()
		close(outputDone)
	}()

	for {
		messageType, message, readErr := connection.ReadMessage()
		if readErr != nil {
			break
		}
		if messageType != websocket.TextMessage && messageType != websocket.BinaryMessage {
			continue
		}
		if len(message) > 0 && message[0] == 0 {
			var resize struct{ Cols, Rows int }
			if json.Unmarshal(message[1:], &resize) == nil && resize.Cols > 0 && resize.Rows > 0 {
				_ = pty.Setsize(tty, &pty.Winsize{Cols: uint16(resize.Cols), Rows: uint16(resize.Rows)})
			}
			continue
		}
		if _, writeErr := tty.Write(message); writeErr != nil {
			break
		}
	}
	_ = command.Process.Kill()
	_ = command.Wait()
	<-outputDone
}

func writeVMConsoleError(connection *websocket.Conn, err error) {
	_ = connection.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("\r\n[Konsole beendet: %v]\r\n", err)))
}
