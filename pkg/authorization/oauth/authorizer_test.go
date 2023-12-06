package oauth

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIntrospectionVerification_CheckAuthorization(t *testing.T) {
	type args struct {
		ctx                context.Context
		authorizationToken string
	}
	type testCase[T any] struct {
		name     string
		i        IntrospectionVerification[T]
		args     args
		wantResp T
		wantErr  error
	}
	tests := []testCase[*introspection]{
		{
			name: "invalid authorizationToken format",
			i: IntrospectionVerification[*introspection]{
				ResourceServer: &resourceServer{},
			},
			args: args{
				ctx:                context.Background(),
				authorizationToken: "token",
			},
			wantErr: ErrInvalidAuthorizationHeader,
		},
		{
			name: "invalid authorizationToken format",
			i: IntrospectionVerification[*introspection]{
				ResourceServer: &resourceServer{},
			},
			args: args{
				ctx:                context.Background(),
				authorizationToken: "token",
			},
			wantErr: ErrInvalidAuthorizationHeader,
		},
		{
			name: "introspection failed",
			i: IntrospectionVerification[*introspection]{
				ResourceServer: &resourceServer{
					client: mockClient([]byte(`invalid client authorization`), 401),
				},
			},
			args: args{
				ctx:                context.Background(),
				authorizationToken: "Bearer valid",
			},
			wantErr: ErrIntrospectionFailed,
		},
		{
			name: "introspection succeeded",
			i: IntrospectionVerification[*introspection]{
				ResourceServer: &resourceServer{
					client: mockClient([]byte(`{"active": true, "sub": "sub"}`), 200),
				},
			},
			args: args{
				ctx:                context.Background(),
				authorizationToken: "Bearer invalid",
			},
			wantResp: &introspection{
				Active:  true,
				Subject: "sub",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.i.CheckAuthorization(tt.args.ctx, tt.args.authorizationToken)
			assert.ErrorIs(t, err, tt.wantErr)
			assert.Equal(t, tt.wantResp, got)
		})
	}
}

type introspection struct {
	Active  bool   `json:"active,omitempty"`
	Subject string `json:"sub,omitempty"`
}

type resourceServer struct {
	client *http.Client
}

func (r *resourceServer) IntrospectionURL() string {
	return "introspect"
}

func (r *resourceServer) TokenEndpoint() string {
	return ""
}

func (r *resourceServer) HttpClient() *http.Client {
	return r.client
}

func (r *resourceServer) AuthFn() (any, error) {
	return nil, nil
}

func mockClient(resp []byte, status int) *http.Client {
	return &http.Client{
		Transport: &mockTransport{
			resp:   resp,
			status: status,
		},
	}
}

type mockTransport struct {
	resp   []byte
	status int
}

func (m *mockTransport) RoundTrip(_ *http.Request) (*http.Response, error) {
	responseBody := io.NopCloser(bytes.NewReader(m.resp))
	return &http.Response{
		StatusCode: m.status,
		Body:       responseBody,
	}, nil
}
