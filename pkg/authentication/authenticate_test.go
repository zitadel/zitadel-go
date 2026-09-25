package authentication

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type withGetExpiration struct {
	exp time.Time
}

func (w withGetExpiration) GetExpiration() time.Time {
	return w.exp
}

type withExpiresAt struct {
	exp time.Time
}

func (w withExpiresAt) ExpiresAt() time.Time {
	return w.exp
}

type withExpiration struct {
	exp time.Time
}

func (w withExpiration) Expiration() time.Time {
	return w.exp
}

func TestGetSessionExpiration(t *testing.T) {
	future := time.Now().Add(10 * time.Minute)
	past := time.Now().Add(-10 * time.Minute)

	tests := []struct {
		name       string
		authCtx    any
		wantMaxAge int
		wantPast   bool
		wantZero   bool
	}{
		{
			name:     "nil authCtx",
			authCtx:  nil,
			wantZero: true,
		},
		{
			name:     "non-expiring context",
			authCtx:  "some-context",
			wantZero: true,
		},
		{
			name:     "zero GetExpiration",
			authCtx:  withGetExpiration{exp: time.Time{}},
			wantZero: true,
		},
		{
			name:       "future GetExpiration",
			authCtx:    withGetExpiration{exp: future},
			wantMaxAge: 600,
		},
		{
			name:       "past GetExpiration",
			authCtx:    withGetExpiration{exp: past},
			wantMaxAge: -1,
			wantPast:   true,
		},
		{
			name:       "future ExpiresAt",
			authCtx:    withExpiresAt{exp: future},
			wantMaxAge: 600,
		},
		{
			name:       "past ExpiresAt",
			authCtx:    withExpiresAt{exp: past},
			wantMaxAge: -1,
			wantPast:   true,
		},
		{
			name:       "future Expiration",
			authCtx:    withExpiration{exp: future},
			wantMaxAge: 600,
		},
		{
			name:       "past Expiration",
			authCtx:    withExpiration{exp: past},
			wantMaxAge: -1,
			wantPast:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			maxAge, expires := getSessionExpiration(tc.authCtx)
			if tc.wantZero {
				assert.Equal(t, 0, maxAge)
				assert.True(t, expires.IsZero())
				return
			}
			if tc.wantPast {
				assert.Equal(t, -1, maxAge)
				assert.WithinDuration(t, past, expires, time.Second)
				return
			}
			assert.InDelta(t, tc.wantMaxAge, maxAge, 5)
			assert.WithinDuration(t, future, expires, time.Second)
		})
	}
}

func TestSetSessionCookie(t *testing.T) {
	encKey := "01234567890123456789012345678901"
	a := &Authenticator[Ctx]{
		sessionCookieName: "test.session",
		encryptionKey:     encKey,
	}

	t.Run("future expiration", func(t *testing.T) {
		rec := httptest.NewRecorder()
		future := time.Now().Add(time.Hour)
		err := a.setSessionCookie(rec, "session-1", 3600, future)
		assert.NoError(t, err)

		cookies := rec.Result().Cookies()
		assert.Len(t, cookies, 1)
		assert.Equal(t, 3600, cookies[0].MaxAge)
		assert.WithinDuration(t, future, cookies[0].Expires, time.Second)
	})

	t.Run("elapsed expiration", func(t *testing.T) {
		rec := httptest.NewRecorder()
		past := time.Now().Add(-time.Hour)
		err := a.setSessionCookie(rec, "session-2", -1, past)
		assert.NoError(t, err)

		cookies := rec.Result().Cookies()
		assert.Len(t, cookies, 1)
		assert.Equal(t, -1, cookies[0].MaxAge)
		assert.WithinDuration(t, past, cookies[0].Expires, time.Second)
	})

	t.Run("zero expiration (session cookie)", func(t *testing.T) {
		rec := httptest.NewRecorder()
		err := a.setSessionCookie(rec, "session-3", 0, time.Time{})
		assert.NoError(t, err)

		cookies := rec.Result().Cookies()
		assert.Len(t, cookies, 1)
		assert.Equal(t, 0, cookies[0].MaxAge)
		assert.True(t, cookies[0].Expires.IsZero())
	})
}

