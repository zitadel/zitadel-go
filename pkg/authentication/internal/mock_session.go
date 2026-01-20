package internal

import (
	"errors"

	"github.com/zitadel/zitadel-go/v3/pkg/authentication"
)

type MockSessionStore[T authentication.Ctx] struct {
	SetCalled bool
	GetCalled bool
	Store     map[string]T
}

func NewMockSessionStore[T authentication.Ctx]() *MockSessionStore[T] {
	return &MockSessionStore[T]{
		Store: make(map[string]T),
	}
}

func (m *MockSessionStore[T]) Set(id string, session T) error {
	m.SetCalled = true
	m.Store[id] = session
	return nil
}

func (m *MockSessionStore[T]) Get(id string) (T, error) {
	m.GetCalled = true
	s, ok := m.Store[id]
	if !ok {
		var zero T
		return zero, errors.New("session not found")
	}
	return s, nil
}
