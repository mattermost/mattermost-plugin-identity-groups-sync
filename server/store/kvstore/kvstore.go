package kvstore

import (
	"encoding/json"

	"github.com/mattermost/mattermost/server/public/pluginapi"
	"github.com/pkg/errors"

	"github.com/mattermost/mattermost-plugin-groups/server/model"
)

type Client struct {
	client *pluginapi.Client
}

func NewKVStore(client *pluginapi.Client) KVStore {
	return Client{
		client: client,
	}
}

// GetJWT retrieves the JWT token from the KV store
func (kv Client) GetJWT() (*model.JWT, error) {
	tokenBytes := []byte{}
	err := kv.client.KV.Get("keycloak_access_token", &tokenBytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get keycloak_access_token")
	}

	// check if tokenBytes is empty
	if len(tokenBytes) == 0 {
		return nil, errors.New("keycloak_access_token_empty")
	}
	token := &model.JWT{}
	err = json.Unmarshal(tokenBytes, token)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal token")
	}

	return token, nil
}

// StoreJWT stores the JWT token in the KV store
func (kv Client) StoreJWT(token *model.JWT) error {
	tokenBytes, err := json.Marshal(token)
	if err != nil {
		return errors.Wrap(err, "failed to marshal token")
	}

	ok, err := kv.client.KV.Set("keycloak_access_token", tokenBytes)
	if err != nil {
		return errors.Wrap(err, "dataebase error occurred when trying to save keycloak_access_token")
	} else if !ok {
		return errors.New("Failed to save keycloak_access_token")
	}
	return nil
}
