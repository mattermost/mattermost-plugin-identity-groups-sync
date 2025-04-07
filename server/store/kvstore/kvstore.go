package kvstore

import (
	"encoding/json"

	"github.com/mattermost/mattermost/server/public/pluginapi"
	"github.com/pkg/errors"

	"github.com/mattermost/mattermost-plugin-groups/server/model"
	"github.com/mattermost/mattermost-plugin-groups/server/utils"
)

const (
	keycloakGroupPrefix = "keycloak_group_"
)

type Client struct {
	client        *pluginapi.Client
	encryptionKey string
}

func NewKVStore(client *pluginapi.Client, encryptionKey string) KVStore {
	return Client{
		client:        client,
		encryptionKey: encryptionKey,
	}
}

// GetKeycloakJWT retrieves the JWT token from the KV store
func (kv Client) GetKeycloakJWT() (*model.JWT, error) {
	// Ensure encryption key is set
	if kv.encryptionKey == "" {
		return nil, errors.New("encryption key is not configured")
	}

	tokenBytes := []byte{}
	err := kv.client.KV.Get("keycloak_access_token", &tokenBytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get keycloak_access_token")
	}

	// check if tokenBytes is empty
	if len(tokenBytes) == 0 {
		return nil, errors.New("keycloak_access_token_empty")
	}

	// Decrypt the token
	decryptedBytes, err := utils.Decrypt([]byte(kv.encryptionKey), tokenBytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decrypt token")
	}

	token := &model.JWT{}
	err = json.Unmarshal(decryptedBytes, token)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal token")
	}

	return token, nil
}

// StoreKeycloakJWT stores the JWT token in the KV store
func (kv Client) StoreKeycloakJWT(token *model.JWT) error {
	// Ensure encryption key is set
	if kv.encryptionKey == "" {
		return errors.New("encryption key is not configured")
	}

	tokenBytes, err := json.Marshal(token)
	if err != nil {
		return errors.Wrap(err, "failed to marshal token")
	}

	// Encrypt the token
	bytesToStore, err := utils.Encrypt([]byte(kv.encryptionKey), tokenBytes)
	if err != nil {
		return errors.Wrap(err, "failed to encrypt token")
	}

	ok, err := kv.client.KV.Set("keycloak_access_token", bytesToStore)
	if err != nil {
		return errors.Wrap(err, "database error occurred when trying to save keycloak_access_token")
	} else if !ok {
		return errors.New("Failed to save keycloak_access_token")
	}
	return nil
}

// DeleteKeycloakJWT removes the JWT token from the KV store
func (kv Client) DeleteKeycloakJWT() error {
	err := kv.client.KV.Delete("keycloak_access_token")
	if err != nil {
		return errors.Wrap(err, "failed to delete keycloak_access_token")
	}
	return nil
}

// StoreKeycloakGroupID stores a single group name to ID mapping in the KV store
func (kv Client) StoreKeycloakGroupID(groupName string, groupID string) error {
	key := keycloakGroupPrefix + groupName
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
	key := keycloakGroupPrefix + groupName
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
	key := keycloakGroupPrefix + groupName
	err := kv.client.KV.Delete(key)
	if err != nil {
		return errors.Wrap(err, "failed to delete group ID")
	}
	return nil
}

// ListKeycloakGroupIDs retrieves all group mappings from the KV store
func (kv Client) ListKeycloakGroupIDs() (map[string]string, error) {
	prefix := keycloakGroupPrefix
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
				groupName := key[len(keycloakGroupPrefix):]
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
