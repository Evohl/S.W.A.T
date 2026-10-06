package main

import "sync"

// flashMessage carries a one-time action result across a redirect so a
// browser refresh after a POST never re-submits the form (Post/Redirect/Get).
type flashMessage struct {
	Error   string
	Success string
}

var flashStore = struct {
	sync.Mutex
	items map[string]flashMessage
}{items: make(map[string]flashMessage)}

func setFlash(errorMsg, successMsg string) string {
	if errorMsg == "" && successMsg == "" {
		return ""
	}
	token, err := randomToken()
	if err != nil {
		return ""
	}
	flashStore.Lock()
	flashStore.items[token] = flashMessage{Error: errorMsg, Success: successMsg}
	flashStore.Unlock()
	return token
}

func popFlash(token string) (flashMessage, bool) {
	if token == "" {
		return flashMessage{}, false
	}
	flashStore.Lock()
	msg, ok := flashStore.items[token]
	if ok {
		delete(flashStore.items, token)
	}
	flashStore.Unlock()
	return msg, ok
}
