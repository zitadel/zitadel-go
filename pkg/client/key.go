package client

import (
	"encoding/json"
	"os"
)

type KeyType int32

//go:generate enumer -type KeyType -linecomment -json
const (
	ServiceAccountKey KeyType = iota // serviceaccount
	ApplicationKey                   // application
)

type KeyFile struct {
	Type  KeyType `json:"type"`
	KeyID string  `json:"keyId"`
	Key   []byte  `json:"key"`

	// serviceaccount
	UserID string `json:"userId,omitempty"`

	// application
	ClientID string `json:"clientId,omitempty"`
	AppID    string `json:"appId,omitempty"`
}

// MarshalJSON implements the json.Marshaler interface for KeyType
func (i *KeyFile) MarshalJSON() ([]byte, error) {
	type Alias KeyFile
	aux := &struct {
		*Alias
		Key string `json:"key"`
	}{
		Alias: (*Alias)(i),
		Key:   string(i.Key),
	}
	return json.Marshal(aux)
}

// UnmarshalJSON implements the json.Unmarshaler interface for KeyType
func (i *KeyFile) UnmarshalJSON(data []byte) error {
	type Alias KeyFile
	aux := &struct {
		Key string `json:"key"`
		*Alias
	}{
		Alias: (*Alias)(i),
	}

	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}

	i.Key = []byte(aux.Key)
	return nil
}

func ConfigFromKeyFile(path string) (*KeyFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ConfigFromKeyFileData(data)
}

func ConfigFromKeyFileData(data []byte) (*KeyFile, error) {
	var f KeyFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	return &f, nil
}
