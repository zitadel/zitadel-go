package actions

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func Test_validatePayload(t *testing.T) {
	tnow := time.Now()
	payload := []byte("test")
	signingKey := "testSigningKey"
	header := ComputeSignatureHeader(tnow, payload, signingKey)

	tests := []struct {
		name             string
		payload          []byte
		sigHeader        string
		signingKey       string
		tolerance        time.Duration
		enforceTolerance bool
		wantErr          error
	}{
		{
			name:             "valid header with enforced tolerance",
			payload:          payload,
			sigHeader:        header,
			signingKey:       signingKey,
			wantErr:          nil,
			tolerance:        DefaultTolerance,
			enforceTolerance: true,
		},
		{
			name:             "valid header without enforced tolerance",
			payload:          payload,
			sigHeader:        header,
			signingKey:       signingKey,
			wantErr:          nil,
			enforceTolerance: false,
		},
		{
			name:             "invalid header",
			payload:          payload,
			sigHeader:        "invalidHeader",
			signingKey:       signingKey,
			enforceTolerance: true,
			wantErr:          ErrInvalidHeader,
		},
		{
			name:       "no header",
			payload:    payload,
			sigHeader:  "",
			signingKey: signingKey,
			wantErr:    ErrNotSigned,
		},
		{
			name:             "expired header",
			payload:          payload,
			sigHeader:        header,
			signingKey:       signingKey,
			tolerance:        -1 * time.Second,
			enforceTolerance: true,
			wantErr:          ErrTooOld,
		},
		{
			name:       "invalid signing key",
			payload:    payload,
			sigHeader:  header,
			signingKey: "invalidSigningKey",
			wantErr:    ErrNoValidSignature,
		},
		{
			name:       "invalid signing timestamp",
			payload:    payload,
			sigHeader:  "t=abc,v1=456",
			signingKey: signingKey,
			wantErr:    ErrInvalidHeader,
		},
		{
			name:       "invalid signing version",
			payload:    payload,
			sigHeader:  "t=12345,v1=",
			signingKey: signingKey,
			wantErr:    ErrNoValidSignature,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePayload(tt.payload, tt.sigHeader, tt.signingKey, tt.tolerance, tt.enforceTolerance)
			require.Equal(t, tt.wantErr, err)
		})
	}
}
