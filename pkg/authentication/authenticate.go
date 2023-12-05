package authentication

import (
	"context"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"golang.org/x/exp/slog"
)

type Authenticator[T Ctx] struct {
	authN             Handler[T]
	logger            *slog.Logger
	router            *http.ServeMux
	sessions          Sessions[T]
	encryptionKey     string
	sessionCookieName string
	tls               bool
}

type Sessions[T Ctx] interface {
	Set(id string, session T) error
	Get(id string) (T, error)
}

// Handler defines the handling of authentication and logout
type Handler[T Ctx] interface {
	Authenticate(w http.ResponseWriter, r *http.Request, state string)
	Callback(w http.ResponseWriter, r *http.Request) (t T, state string)
	Logout(w http.ResponseWriter, r *http.Request, authCtx T, state string)
}

// HandlerInitializer abstracts the initialization of a [Handler] by providing the ZITADEL domain
type HandlerInitializer[T Ctx] func(ctx context.Context, domain string) (Handler[T], error)

func New[T Ctx](ctx context.Context, domain, encryptionKey string, initAuthentication HandlerInitializer[T]) (*Authenticator[T], error) {
	authN, err := initAuthentication(ctx, domain)
	if err != nil {
		return nil, err
	}
	authenticator := &Authenticator[T]{
		authN:             authN,
		sessions:          &InMemorySessions[T]{sessions: make(map[string]T)},
		encryptionKey:     encryptionKey,
		sessionCookieName: "zitadel.session",
		tls:               false, // TODO: change after development!
		logger:            slog.Default(),
	}
	authenticator.createRouter()
	return authenticator, nil
}

func (a *Authenticator[T]) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	http.StripPrefix("/auth", a.router).ServeHTTP(w, r)
}

func (a *Authenticator[T]) createRouter() {
	a.router = http.NewServeMux()
	a.router.Handle("/login", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		a.Authenticate(w, req, "")
	}))
	a.router.Handle("/callback", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		a.Callback(w, req)
	}))

	a.router.Handle("/logout", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		a.Logout(w, req)
	}))
}

func (a *Authenticator[T]) Authenticate(w http.ResponseWriter, r *http.Request, requestedURI string) {
	s := &State{RequestedURI: requestedURI}
	stateParam, err := s.Encrypt(a.encryptionKey)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	a.authN.Authenticate(w, r, stateParam)
}

func (a *Authenticator[T]) Callback(w http.ResponseWriter, req *http.Request) {
	ctx, stateParam := a.authN.Callback(w, req)
	if !ctx.IsAuthenticated() {
		http.Error(w, "not authenticated", http.StatusForbidden)
		return
	}
	state, err := DecryptState(stateParam, a.encryptionKey)
	if err != nil {

	}

	id := uuid.NewString()
	http.SetCookie(w, &http.Cookie{
		Name:     a.sessionCookieName,
		Value:    id,
		Path:     "/",
		Domain:   "",
		MaxAge:   0, // TODO: ?
		Secure:   a.tls,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	a.sessions.Set(id, ctx)

	http.Redirect(w, req, state.RequestedURI, http.StatusFound)
}

func (a *Authenticator[T]) cookieName() string {
	if a.tls {
		return "__Host-" + a.sessionCookieName
	}
	return a.sessionCookieName
}

func (a *Authenticator[T]) Logout(w http.ResponseWriter, req *http.Request) {
	ctx, err := a.IsAuthenticated(w, req)
	if err != nil {
		// TODO: ?
	}
	s := &State{RequestedURI: ""}
	stateParam, err := s.Encrypt(a.encryptionKey)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	a.authN.Logout(w, req, ctx, stateParam)
}

var (
	ErrNoCookie  = errors.New("no cookie")
	ErrNoSession = errors.New("no session")
)

func (a *Authenticator[T]) IsAuthenticated(w http.ResponseWriter, req *http.Request) (T, error) {
	var t T
	cookie, err := req.Cookie(a.sessionCookieName)
	if err != nil {
		return t, ErrNoCookie
	}
	session, err := a.sessions.Get(cookie.Value)
	if err != nil {
		a.logger.Log(req.Context(), slog.LevelWarn, "no session found for cookie", "sessionID", cookie.Value)
		return t, ErrNoSession
	}
	return session, nil
}

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
