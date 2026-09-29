package authentication

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
)

var ErrRefreshNotSupported = errors.New("handler does not support refresh")

// Refresh renews the session referenced by the request's cookie using the handler's
// Refresh method (such as the OIDC code flow with refresh enabled), persists it,
// and returns it. The session cookie is rewritten on w, which also extends its
// Max-Age. If renewal fails the session is left untouched.
func (a *Authenticator[T]) Refresh(w http.ResponseWriter, req *http.Request) (T, error) {
	var t T
	refresher, ok := a.authN.(interface {
		Refresh(ctx context.Context, authCtx T) (T, error)
	})
	if !ok {
		return t, ErrRefreshNotSupported
	}
	session, sessionID, err := a.loadSession(req)
	if err != nil {
		return t, err
	}
	renewed, err := refresher.Refresh(req.Context(), session)
	if err != nil {
		a.logger.Log(req.Context(), slog.LevelWarn, "unable to refresh session", "error", err)
		return t, fmt.Errorf("%w: %w", ErrNoSession, err)
	}
	if !renewed.IsAuthenticated() {
		a.logger.Log(req.Context(), slog.LevelWarn, "refreshed session is not authenticated")
		return t, ErrNoSession
	}
	maxAge := int(a.maxAge.Seconds())
	if a.useCookieSession {
		data, err := json.Marshal(renewed)
		if err != nil {
			return t, err
		}
		if err := a.setSessionCookie(w, string(data), maxAge); err != nil {
			return t, err
		}
		return renewed, nil
	}
	if err := a.sessions.Set(sessionID, renewed); err != nil {
		return t, err
	}
	if err := a.setSessionCookie(w, sessionID, maxAge); err != nil {
		return t, err
	}
	return renewed, nil
}
