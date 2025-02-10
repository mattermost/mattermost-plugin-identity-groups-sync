package groups

import (
	"context"

	"github.com/Nerzal/gocloak/v13"
)

// GoCloak is an interface that wraps the gocloak methods we use
type GoCloak interface {
	LoginClient(ctx context.Context, clientID, clientSecret, realm string, scopes ...string) (*gocloak.JWT, error)
	RefreshToken(ctx context.Context, refreshToken, clientID, clientSecret, realm string) (*gocloak.JWT, error)
	GetGroups(ctx context.Context, token string, realm string, params gocloak.GetGroupsParams) ([]*gocloak.Group, error)
	GetGroupsCount(ctx context.Context, token string, realm string, params gocloak.GetGroupsParams) (int, error)
	GetGroup(ctx context.Context, token string, realm string, groupID string) (*gocloak.Group, error)
	GetGroupMembers(ctx context.Context, token string, realm string, groupID string, params gocloak.GetGroupsParams) ([]*gocloak.User, error)
}

// Ensure gocloak.GoCloak implements our interface
var _ GoCloak = (*gocloak.GoCloak)(nil)
