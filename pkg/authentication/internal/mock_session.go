// Package internal provides internal test utilities for the authentication package.
package internal

import (
	"errors"

	"github.com/zitadel/zitadel-go/v3/pkg/authentication"
)

// MockSessionStore is a mock implementation of a session store for testing purposes.
// It stores sessions in memory and tracks whether Set and Get methods were called.
type MockSessionStore[T authentication.Ctx] struct {
	SetCalled bool
	GetCalled bool
	Store     map[string]T
}

// NewMockSessionStore creates a new MockSessionStore with an initialized storage map.
func NewMockSessionStore[T authentication.Ctx]() *MockSessionStore[T] {
	return &MockSessionStore[T]{
		Store: make(map[string]T),
	}
}

// Set stores a session with the given ID and marks SetCalled as true.
func (m *MockSessionStore[T]) Set(id string, session T) error {
	m.SetCalled = true
	m.Store[id] = session
	return nil
}

// Get retrieves a session by ID and marks GetCalled as true.
// Returns an error if the session ID is not found.
func (m *MockSessionStore[T]) Get(id string) (T, error) {
	m.GetCalled = true
	s, ok := m.Store[id]
	if !ok {
		var zero T
		return zero, errors.New("session not found")
	}
	return s, nil
}
