package authentication

import "errors"

// Sessions is an abstraction of the session storage
type Sessions[T Ctx] interface {
	Set(id string, session T) error
	Get(id string) (T, error)
}

// InMemorySessions implements the [Sessions] interface by storing sessions
// in application memory.
//
// ⚠️  Warning: Not suitable for production use
//
// This implementation is fundamentally broken for production use and will
// cause serious issues in real applications:
//
// Reliability problems:
//   - All user sessions vanish instantly when your app restarts, crashes,
//     or is redeployed - forcing every user to log in again
//   - Zero fault tolerance - any server issue kills all active sessions
//
// Scalability problems:
//   - Impossible to run multiple server instances - sessions exist only
//     on one server, so load balancers will randomly break user logins
//   - Cannot handle traffic spikes or distribute load
//
// Security & resource problems:
//   - Memory grows indefinitely - old sessions never expire or clean up
//   - Will eventually crash your server by consuming all available RAM
//   - No way to revoke sessions or handle security incidents
//
// Production alternatives:
//   - Use WithCookieSession(true) for stateless encrypted cookie sessions
//   - Use Redis/Memcached for fast server-side sessions
//   - Use database storage for persistent sessions
//   - Implement your own Sessions interface with custom storage
//
// Intended use: Local development, unit tests, and proof-of-concept demos only.
type InMemorySessions[T Ctx] struct {
	sessions map[string]T
}

// NewInMemorySessions creates a new in-memory session store.
//
// ⚠️  Warning: Do not use in production - this will break your application!
// See [InMemorySessions] documentation for why this is dangerous.
//
// For production use, consider [WithCookieSession](true) for stateless sessions
// or implement a proper session store.
//
// Only use for local development, testing, or learning purposes.
func NewInMemorySessions[T Ctx]() Sessions[T] {
	return &InMemorySessions[T]{
		sessions: make(map[string]T),
	}
}

func (s *InMemorySessions[T]) Get(id string) (T, error) {
	t, ok := s.sessions[id]
	if !ok {
		return t, errors.New("session not found")
	}
	return t, nil
}

func (s *InMemorySessions[T]) Set(id string, session T) error {
	s.sessions[id] = session
	return nil
}
