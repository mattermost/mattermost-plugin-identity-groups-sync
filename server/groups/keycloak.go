package groups

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Nerzal/gocloak/v13"
	mmModel "github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/pluginapi"

	"github.com/mattermost/mattermost-plugin-groups/server/model"
	"github.com/mattermost/mattermost-plugin-groups/server/store/kvstore"
)

// KeycloakClient wraps the gocloak client and provides SAML-specific functionality
type KeycloakClient struct {
	Client       GoCloak
	Realm        string
	ClientID     string
	ClientSecret string
	Kvstore      kvstore.KVStore
	PluginAPI    *pluginapi.Client
}

// executeWithRetry gets a valid token and executes the given function, retrying once with a new token if it gets a 401
func (k *KeycloakClient) executeWithRetry(ctx context.Context, fn func(string) (interface{}, error)) (interface{}, error) {
	if k.Client == nil || k.Realm == "" {
		return nil, &AuthError{
			Message: "keycloak not configured",
			Err:     fmt.Errorf("missing required configuration: client and realm"),
		}
	}

	token, err := k.getAuthToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get auth token: %w", err)
	}

	result, err := fn(token)
	if err != nil && strings.Contains(err.Error(), "401 Unauthorized") {
		// Try to authenticate once
		newToken, authErr := k.Authenticate(ctx)
		if authErr != nil {
			return nil, fmt.Errorf("failed to reauthenticate after 401: %w", authErr)
		}
		// Retry the request with new token
		result, err = fn(newToken)
		if err != nil {
			return nil, fmt.Errorf("operation failed after reauthentication: %w", err)
		}
	}
	return result, err
}

// AuthError represents authentication related errors
type AuthError struct {
	Message string
	Err     error
}

func (e *AuthError) Error() string {
	return fmt.Sprintf("authentication error: %s: %v", e.Message, e.Err)
}

// NewKeycloakClient creates a new instance of KeycloakClient
func NewKeycloakClient(hostURL, realm, clientID, clientSecret string, kvstore kvstore.KVStore, client *pluginapi.Client) *KeycloakClient {
	return &KeycloakClient{
		Client:       gocloak.NewClient(hostURL),
		Realm:        realm,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Kvstore:      kvstore,
		PluginAPI:    client,
	}
}

// Authenticate performs authentication against Keycloak server
// Returns a JWT token string if successful
func (k *KeycloakClient) Authenticate(ctx context.Context) (string, error) {
	gocloakJWT, err := k.Client.LoginClient(ctx,
		k.ClientID,
		k.ClientSecret,
		k.Realm,
	)
	if err != nil {
		return "", &AuthError{
			Message: "failed to authenticate client",
			Err:     err,
		}
	}

	now := time.Now()
	jwt := &model.JWT{
		AccessToken:                gocloakJWT.AccessToken,
		ExpiresIn:                  gocloakJWT.ExpiresIn,
		RefreshToken:               gocloakJWT.RefreshToken,
		RefreshExpiresIn:           gocloakJWT.RefreshExpiresIn,
		TokenType:                  gocloakJWT.TokenType,
		NotBeforePolicy:            gocloakJWT.NotBeforePolicy,
		SessionState:               gocloakJWT.SessionState,
		Scope:                      gocloakJWT.Scope,
		AccessTokenExpirationTime:  now.Add(time.Duration(gocloakJWT.ExpiresIn) * time.Second).UnixMilli(),
		RefreshTokenExpirationTime: now.Add(time.Duration(gocloakJWT.RefreshExpiresIn) * time.Second).UnixMilli(),
	}

	if err := k.Kvstore.StoreJWT(jwt); err != nil {
		return "", &AuthError{
			Message: "failed to store jwt",
			Err:     err,
		}
	}

	return jwt.AccessToken, nil
}

// GetGroups retrieves all groups from Keycloak and converts them to Mattermost groups
func (k *KeycloakClient) GetGroups(ctx context.Context, query Query) ([]*mmModel.Group, error) {
	first := query.Page
	if first != 0 {
		first = (query.Page * query.PerPage)
	}
	params := gocloak.GetGroupsParams{
		First:  &first,
		Max:    &query.PerPage,
		Search: &query.Q,
	}
	result, err := k.executeWithRetry(ctx, func(t string) (interface{}, error) {
		return k.Client.GetGroups(ctx, t, k.Realm, params)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get groups: %w", err)
	}

	keycloakGroups := result.([]*gocloak.Group)
	mmGroups := make([]*mmModel.Group, len(keycloakGroups))
	for i, group := range keycloakGroups {
		mmGroups[i] = k.translateGroup(group)
	}

	return mmGroups, nil
}

// GetGroupsCount retrieves the total number of groups in Keycloak
func (k *KeycloakClient) GetGroupsCount(ctx context.Context) (int, error) {
	result, err := k.executeWithRetry(ctx, func(t string) (interface{}, error) {
		return k.Client.GetGroupsCount(ctx, t, k.Realm, gocloak.GetGroupsParams{})
	})
	if err != nil {
		return 0, fmt.Errorf("failed to get groups count: %w", err)
	}
	count := result.(int)

	return count, nil
}

// getAuthToken retrieves and validates the authentication token
func (k *KeycloakClient) getAuthToken(ctx context.Context) (string, error) {
	jwt, err := k.Kvstore.GetJWT()
	now := time.Now().UnixMilli()
	expirationBuffer := int64(60 * 1000) // 60 seconds in milliseconds

	// If no token exists or there was an error getting it, authenticate
	if err != nil {
		return k.Authenticate(ctx)
	}

	// Check if access token is still valid (with buffer)
	if now+expirationBuffer < jwt.AccessTokenExpirationTime {
		return jwt.AccessToken, nil
	}

	// Check if refresh token is still valid
	if now+expirationBuffer < jwt.RefreshTokenExpirationTime {
		// Refresh the token
		var gocloakJWT *gocloak.JWT
		gocloakJWT, err = k.Client.RefreshToken(ctx, jwt.RefreshToken, k.ClientID, k.ClientSecret, k.Realm)
		if err != nil {
			// If refresh fails, try to authenticate again
			return k.Authenticate(ctx)
		}

		// Create new token with updated expiration times
		newToken := &model.JWT{
			AccessToken:                gocloakJWT.AccessToken,
			ExpiresIn:                  gocloakJWT.ExpiresIn,
			RefreshToken:               gocloakJWT.RefreshToken,
			RefreshExpiresIn:           gocloakJWT.RefreshExpiresIn,
			TokenType:                  gocloakJWT.TokenType,
			NotBeforePolicy:            gocloakJWT.NotBeforePolicy,
			SessionState:               gocloakJWT.SessionState,
			Scope:                      gocloakJWT.Scope,
			AccessTokenExpirationTime:  now + (int64(gocloakJWT.ExpiresIn) * 1000),
			RefreshTokenExpirationTime: now + (int64(gocloakJWT.RefreshExpiresIn) * 1000),
		}

		if err = k.Kvstore.StoreJWT(newToken); err != nil {
			return "", fmt.Errorf("failed to store refreshed token: %w", err)
		}

		return newToken.AccessToken, nil
	}

	// Both tokens are expired, need to authenticate again
	var accessToken string
	accessToken, err = k.Authenticate(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to re-authenticate: %w", err)
	}

	return accessToken, nil
}

// translateGroup converts a Keycloak group to a Mattermost group
func (k *KeycloakClient) translateGroup(group *gocloak.Group) *mmModel.Group {
	return &mmModel.Group{
		DisplayName:    *group.Name,
		Source:         k.GetGroupSource(),
		RemoteId:       group.ID,
		AllowReference: false,
	}
}

// GetGroupMembers retrieves all members of a specific group from Keycloak
func (k *KeycloakClient) GetGroupMembers(ctx context.Context, groupID string) ([]*gocloak.User, error) {
	result, err := k.executeWithRetry(ctx, func(t string) (interface{}, error) {
		return k.Client.GetGroupMembers(ctx, t, k.Realm, groupID, gocloak.GetGroupsParams{})
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get group members: %w", err)
	}
	users := result.([]*gocloak.User)

	return users, nil
}

// GetGroup retrieves a specific group from Keycloak by ID
func (k *KeycloakClient) GetGroup(ctx context.Context, groupID string) (*mmModel.Group, error) {
	result, err := k.executeWithRetry(ctx, func(t string) (interface{}, error) {
		return k.Client.GetGroup(ctx, t, k.Realm, groupID)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get group: %w", err)
	}
	group := result.(*gocloak.Group)

	return k.translateGroup(group), nil
}

func (k *KeycloakClient) GetGroupSource() mmModel.GroupSource {
	return mmModel.GroupSourcePluginPrefix + "keycloak"
}
