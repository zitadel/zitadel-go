package authentication

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"golang.org/x/exp/slog"
)

var (
	ErrNoCookie  = errors.New("no cookie")
	ErrNoSession = errors.New("no session")
)

// Authenticator provides the functionality to handle authentication including check for existing session,
// starting a new authentication by redirecting the user to the Login UI and more.
type Authenticator[T Ctx] struct {
	authN             Handler[T]
	logger            *slog.Logger
	router            *http.ServeMux
	sessions          Sessions[T]
	encryptionKey     string
	sessionCookieName string
}

// Option allows customization of the [Authenticator] such as logging and more.
type Option[T Ctx] func(authorizer *Authenticator[T])

// WithLogger allows a logger other than slog.Default().
//
// EXPERIMENTAL: Will change to log/slog import after we drop support for Go 1.20
func WithLogger[T Ctx](logger *slog.Logger) Option[T] {
	return func(a *Authenticator[T]) {
		a.logger = logger
	}
}

func New[T Ctx](ctx context.Context, domain, encryptionKey string, initAuthentication HandlerInitializer[T], options ...Option[T]) (*Authenticator[T], error) {
	authN, err := initAuthentication(ctx, domain)
	if err != nil {
		return nil, err
	}
	authenticator := &Authenticator[T]{
		authN:             authN,
		sessions:          &InMemorySessions[T]{sessions: make(map[string]T)},
		encryptionKey:     encryptionKey,
		sessionCookieName: "zitadel.session",
		logger:            slog.Default(),
	}
	for _, option := range options {
		option(authenticator)
	}
	authenticator.createRouter()
	return authenticator, nil
}

// ServeHTTP serves the authentication handler and its three subroutes.
func (a *Authenticator[T]) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	http.StripPrefix("/auth", a.router).ServeHTTP(w, r)
}

// Authenticate starts a new authentication (by redirecting the user to the Login UI)
// The initially requested URI (in the application) is passed as encrypted state.
func (a *Authenticator[T]) Authenticate(w http.ResponseWriter, r *http.Request, requestedURI string) {
	s := &State{RequestedURI: requestedURI}
	stateParam, err := s.Encrypt(a.encryptionKey)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	a.authN.Authenticate(w, r, stateParam)
}

// Callback handles the redirect back from the Login UI. On successful authentication a new session
// will be created and its id will be stored in a cookie.
// The user will be redirected to the initially requested UI (passed as encrypted state)
func (a *Authenticator[T]) Callback(w http.ResponseWriter, req *http.Request) {
	ctx, stateParam := a.authN.Callback(w, req)
	if !ctx.IsAuthenticated() {
		http.Error(w, "not authenticated", http.StatusForbidden)
		return
	}
	state, err := DecryptState(stateParam, a.encryptionKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	id := uuid.NewString()
	http.SetCookie(w, &http.Cookie{
		Name:     a.sessionCookieName,
		Value:    id,
		Path:     "/",
		Domain:   "",
		MaxAge:   0,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	a.sessions.Set(id, ctx)

	http.Redirect(w, req, state.RequestedURI, http.StatusFound)
}

// Logout will terminate the exising session.
func (a *Authenticator[T]) Logout(w http.ResponseWriter, req *http.Request) {
	ctx, err := a.IsAuthenticated(w, req)
	if err != nil {
		http.Redirect(w, req, "/", http.StatusFound)
		return
	}
	s := &State{RequestedURI: ""}
	stateParam, err := s.Encrypt(a.encryptionKey)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     a.sessionCookieName,
		Path:     "/",
		Domain:   "",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	proto := "http"
	if req.TLS != nil {
		proto = "https"
	}
	postLogout := fmt.Sprintf("%s://%s/", proto, req.Host)
	a.authN.Logout(w, req, ctx, stateParam, postLogout)
}

// IsAuthenticated checks whether there is an existing session of not.
// In case there is one, it will be returned.
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

// Handler defines the handling of authentication and logout
type Handler[T Ctx] interface {
	Authenticate(w http.ResponseWriter, r *http.Request, state string)
	Callback(w http.ResponseWriter, r *http.Request) (t T, state string)
	Logout(w http.ResponseWriter, r *http.Request, authCtx T, state, optionalRedirectURI string)
}

// HandlerInitializer abstracts the initialization of a [Handler] by providing the ZITADEL domain
type HandlerInitializer[T Ctx] func(ctx context.Context, domain string) (Handler[T], error)
