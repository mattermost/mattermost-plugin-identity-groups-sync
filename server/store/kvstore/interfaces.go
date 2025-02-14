package kvstore

import "github.com/mattermost/mattermost-plugin-groups/server/model"

type KVStore interface {
	StoreJWT(token *model.JWT) error
	GetJWT() (*model.JWT, error)
	StoreGroupID(groupName string, groupID string) error
	GetGroupID(groupName string) (string, error)
	DeleteGroupID(groupName string) error
	ListGroupIDs() (map[string]string, error)
}
