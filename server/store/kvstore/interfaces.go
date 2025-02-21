package kvstore

import "github.com/mattermost/mattermost-plugin-groups/server/model"

type KVStore interface {
	StoreKeycloakJWT(token *model.JWT) error
	GetKeycloakJWT() (*model.JWT, error)
	StoreKeycloakGroupID(groupName string, groupID string) error
	GetKeycloakGroupID(groupName string) (string, error)
	DeleteKeycloakGroupID(groupName string) error
	ListKeycloakGroupIDs() (map[string]string, error)
}
