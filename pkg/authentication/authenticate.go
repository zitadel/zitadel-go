package authentication

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
)

type Authenticator[T Ctx] struct {
	authN    AuthenticationProvider[T]
	sessions map[string]T
	key      string
}

// AuthenticationProvider defines the possible verification checks such as validation of the authorizationToken.
type AuthenticationProvider[T Ctx] interface {
	Authenticate(state string) http.HandlerFunc
	Callback(w http.ResponseWriter, r *http.Request) (t T, state string)
	Logout(ctx context.Context, idToken, state string) http.HandlerFunc
}

// VerifierInitializer abstracts the initialization of a [Verifier] by providing the ZITADEL domain
type AuthenticationProviderInitializer[T Ctx] func(ctx context.Context, domain string) (AuthenticationProvider[T], error)

func New[T Ctx](ctx context.Context, domain string, initAuthentication AuthenticationProviderInitializer[T]) (*Authenticator[T], error) {
	authN, err := initAuthentication(ctx, domain)
	if err != nil {
		return nil, err
	}
	authenticator := &Authenticator[T]{
		authN:    authN,
		sessions: make(map[string]T),
		key:      "arajcoejmdijijf3joirio3sdf3gsfdg",
	}
	return authenticator, nil
}

func (a *Authenticator[T]) Authenticate(requestedURI string) http.HandlerFunc {
	s := &State{RequestedURI: requestedURI}
	stateParam, err := s.Encrypt(a.key)

	if err != nil {
		return func(w http.ResponseWriter, req *http.Request) {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
	return a.authN.Authenticate(stateParam)
}

func (a *Authenticator[T]) Callback(w http.ResponseWriter, req *http.Request) {
	ctx, stateParam := a.authN.Callback(w, req)
	if !ctx.IsAuthenticated() {
		http.Error(w, "not authenticated", http.StatusForbidden)
		return
	}
	state, err := DecryptState(stateParam, a.key)
	if err != nil {

	}

	id := uuid.NewString()
	http.SetCookie(w, &http.Cookie{
		Name:       "test",
		Value:      id,
		Path:       "/",
		Domain:     "",
		Expires:    time.Time{},
		RawExpires: "",
		MaxAge:     0,
		Secure:     false,
		HttpOnly:   true,
		SameSite:   http.SameSiteLaxMode,
		Raw:        "",
		Unparsed:   nil,
	})
	a.sessions[id] = ctx

	http.Redirect(w, req, state.RequestedURI, http.StatusFound)
}

func (a *Authenticator[T]) Logout(w http.ResponseWriter, req *http.Request) {
	s := &State{RequestedURI: ""}
	stateParam, err := s.Encrypt(a.key)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	a.authN.Logout(req.Context(), "", stateParam)(w, req)
}

var (
	ErrNoCookie  = errors.New("no cookie")
	ErrNoSession = errors.New("no session")
)

func (a *Authenticator[T]) IsAuthenticated(w http.ResponseWriter, req *http.Request) (Ctx, error) {
	var t T
	cookie, err := req.Cookie("test")
	if err != nil {
		return t, ErrNoCookie
	}
	session, ok := a.sessions[cookie.Value]
	if !ok {
		return t, ErrNoSession
	}
	return session, nil
}
