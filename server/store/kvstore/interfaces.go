package kvstore

import "github.com/mattermost/mattermost-plugin-groups/server/model"

type KVStore interface {
	StoreJWT(token *model.JWT) error
	GetJWT() (*model.JWT, error)
}
