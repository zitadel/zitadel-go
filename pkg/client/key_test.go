package client

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfigFromKeyFileData(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		args    args
		want    *KeyFile
		wantErr bool
	}{
		{
			name: "valid service account key",
			args: args{
				data: []byte(`{
					"type": "serviceaccount",
					"keyId": "key1",
					"key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY",
					"userId": "user1"
				}`),
			},
			want: &KeyFile{
				Type:   ServiceAccountKey,
				KeyID:  "key1",
				Key:    []byte("-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY"),
				UserID: "user1",
			},
		},
		{
			name: "valid application key",
			args: args{
				data: []byte(`{
					"type": "application",
					"keyId": "key2",
					"key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY",
					"clientId": "client1",
					"appId": "app1"
				}`),
			},
			want: &KeyFile{
				Type:     ApplicationKey,
				KeyID:    "key2",
				Key:      []byte("-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY"),
				ClientID: "client1",
				AppID:    "app1",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ConfigFromKeyFileData(tt.args.data)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)

			// Test JSON marshalling as well
			data, err := got.MarshalJSON()
			require.NoError(t, err)
			require.JSONEq(t, string(tt.args.data), string(data))
		})
	}
}
