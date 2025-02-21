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

// GetKeycloakJWT retrieves the JWT token from the KV store
func (kv Client) GetKeycloakJWT() (*model.JWT, error) {
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

// StoreKeycloakJWT stores the JWT token in the KV store
func (kv Client) StoreKeycloakJWT(token *model.JWT) error {
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

// StoreKeycloakGroupID stores a single group name to ID mapping in the KV store
func (kv Client) StoreKeycloakGroupID(groupName string, groupID string) error {
	key := "keycloak_group_" + groupName
	ok, err := kv.client.KV.Set(key, []byte(groupID))
	if err != nil {
		return errors.Wrap(err, "database error occurred when trying to save group ID")
	} else if !ok {
		return errors.New("Failed to save group ID")
	}
	return nil
}

// GetKeycloakGroupID retrieves a single group ID by name from the KV store
func (kv Client) GetKeycloakGroupID(groupName string) (string, error) {
	key := "keycloak_group_" + groupName
	var groupID []byte
	err := kv.client.KV.Get(key, &groupID)
	if err != nil {
		return "", errors.Wrap(err, "failed to get group ID")
	}
	if len(groupID) == 0 {
		return "", errors.New("group not found")
	}
	return string(groupID), nil
}

// DeleteKeycloakGroupID removes a group mapping from the KV store
func (kv Client) DeleteKeycloakGroupID(groupName string) error {
	key := "keycloak_group_" + groupName
	err := kv.client.KV.Delete(key)
	if err != nil {
		return errors.Wrap(err, "failed to delete group ID")
	}
	return nil
}

// ListKeycloakGroupIDs retrieves all group mappings from the KV store
func (kv Client) ListKeycloakGroupIDs() (map[string]string, error) {
	prefix := "keycloak_group_"
	mapping := make(map[string]string)
	page := 0
	perPage := 100

	for {
		keys, err := kv.client.KV.ListKeys(page*perPage, perPage, pluginapi.WithPrefix(prefix))
		if err != nil {
			return nil, errors.Wrap(err, "failed to list group keys")
		}

		if len(keys) == 0 {
			break // No more keys to process
		}

		for _, key := range keys {
			var groupID []byte
			err := kv.client.KV.Get(key, &groupID)
			if err != nil {
				return nil, errors.Wrap(err, "failed to get group ID")
			}
			if len(groupID) > 0 {
				groupName := key[len(prefix):]
				mapping[groupName] = string(groupID)
			}
		}

		if len(keys) < perPage {
			break // Last page
		}

		page++
	}

	return mapping, nil
}
