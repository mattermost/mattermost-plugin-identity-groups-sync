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
	GetGroupByPath(ctx context.Context, token, realm, groupPath string) (*gocloak.Group, error)
	GetRealmRole(ctx context.Context, token string, realm string, roleName string) (*gocloak.Role, error)
	GetRealmRoles(ctx context.Context, token string, realm string, params gocloak.GetRoleParams) ([]*gocloak.Role, error)
	GetRealmRoleByID(ctx context.Context, token string, realm string, roleID string) (*gocloak.Role, error)
}

// This is a compile-time check to ensure gocloak.GoCloak implements our GoCloak interface.
// It will cause a compilation error if gocloak.GoCloak is missing any methods defined in the interface.
var _ GoCloak = (*gocloak.GoCloak)(nil)
