package authentication

import (
	"encoding/json"

	"github.com/zitadel/oidc/v3/pkg/crypto"
)

type State struct {
	RequestedURI string
}

func (s *State) Encrypt(key string) (string, error) {
	data, err := json.Marshal(s)
	if err != nil {
		return "", nil
	}
	return crypto.EncryptAES(string(data), key)
}

func DecryptState(data, key string) (*State, error) {
	decrypted, err := crypto.DecryptAES(data, key)
	if err != nil {
		return nil, err
	}
	state := new(State)
	err = json.Unmarshal([]byte(decrypted), state)
	return state, err
}
