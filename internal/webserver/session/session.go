package session

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
)

var (
	sessions map[string]interface{} = make(map[string]interface{})
	mu       sync.RWMutex
)

// GetUser returns a *User by the user's username
func GetSession(sessionID string) (interface{}, error) {

	mu.Lock()
	defer mu.Unlock()

	session, ok := sessions[sessionID]
	if !ok {
		return nil, fmt.Errorf("error getting session '%s': does not exist", sessionID)
	}

	return session, nil
}

func DeleteSession(sessionID string) {
	mu.Lock()
	defer mu.Unlock()

	delete(sessions, sessionID)
}

// PutUser stores a new user by the user's username
func StartSession(data interface{}) string {

	mu.Lock()
	defer mu.Unlock()

	sessionId, _ := random(32)
	sessions[sessionId] = data

	return sessionId
}

func random(length int) (string, error) {
	randomData := make([]byte, length)
	_, err := rand.Read(randomData)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(randomData), nil
}
