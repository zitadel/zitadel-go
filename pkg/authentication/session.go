package authentication

import "errors"

// Sessions is an abstraction of the session storage
type Sessions[T Ctx] interface {
	Set(id string, session T) error
	Get(id string) (T, error)
}

// InMemorySessions implements the [Sessions] interface by storing the sessions
// in-memory. This is obviously not suitable for production and only meant for testing purposes.
type InMemorySessions[T Ctx] struct {
	sessions map[string]T
}

func (s *InMemorySessions[T]) Get(id string) (T, error) {
	t, ok := s.sessions[id]
	if !ok {
		return t, errors.New("not found")
	}
	return t, nil
}
func (s *InMemorySessions[T]) Set(id string, session T) error {
	s.sessions[id] = session
	return nil
}
