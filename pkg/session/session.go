package session

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
)

type SessionManager struct {
	sessions map[string]interface{}
	mu       sync.RWMutex
}

func NewSessionManager() *SessionManager {
	var sm SessionManager
	sm.sessions = make(map[string]interface{})
	return &sm
}

// GetUser returns a *User by the user's username
func (sm *SessionManager) GetSession(sessionID string) (interface{}, error) {

	sm.mu.Lock()
	defer sm.mu.Unlock()

	session, ok := sm.sessions[sessionID]
	if !ok {
		return nil, fmt.Errorf("error getting session '%s': does not exist", sessionID)
	}

	return session, nil
}

func (sm *SessionManager) DeleteSession(sessionID string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	delete(sm.sessions, sessionID)
}

// PutUser stores a new user by the user's username
func (sm *SessionManager) StartSession(data interface{}) string {

	sm.mu.Lock()
	defer sm.mu.Unlock()

	sessionId, _ := random(32)
	sm.sessions[sessionId] = data

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
