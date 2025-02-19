package groups

import (
	"context"
	"errors"

	"github.com/Nerzal/gocloak/v13"
	mmModel "github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"
	"github.com/mattermost/mattermost/server/public/pluginapi"

	"github.com/mattermost/mattermost-plugin-groups/server/model"
	"github.com/mattermost/mattermost-plugin-groups/server/store/kvstore"
)

var (
	ErrUnsupportedProvider = errors.New("unsupported groups provider")
)

type Query struct {
	Page    int
	PerPage int
	Search  string
	Q       string // Additional query parameter for filtering
}

// Client interface defines the SAML operations
type Client interface {
	Authenticate(ctx context.Context) (string, error)
	GetGroups(ctx context.Context, groupsQuery Query) ([]*mmModel.Group, error)
	GetGroup(ctx context.Context, groupID string) (*mmModel.Group, error)
	GetGroupsCount(ctx context.Context) (int, error)
	GetGroupMembers(ctx context.Context, groupID string) ([]*gocloak.User, error)
	SyncGroupMap(ctx context.Context) error
	HandleSAMLLogin(c *plugin.Context, user *mmModel.User, encodedXML string, groupsAttribute string) error
	GetGroupSource() mmModel.GroupSource
}

// NewClient creates a new SAML client with the given configuration
func NewClient(provider string, cfg *model.KeycloakConfigs, kvstore kvstore.KVStore, client *pluginapi.Client) (Client, error) {
	switch provider {
	case "keycloak", "":
		// Always return a KeycloakClient, even if config is empty
		// Empty config will result in authentication failures until configured
		if cfg == nil {
			cfg = &model.KeycloakConfigs{}
		}
		return NewKeycloakClient(cfg.Host, cfg.Realm, cfg.ClientID, cfg.ClientSecret, kvstore, client), nil
	default:
		return nil, ErrUnsupportedProvider
	}
}
