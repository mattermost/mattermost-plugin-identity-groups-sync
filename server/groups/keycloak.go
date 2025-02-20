package groups

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Nerzal/gocloak/v13"
	mmModel "github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"
	"github.com/mattermost/mattermost/server/public/pluginapi"
	"github.com/pkg/errors"

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
	params := gocloak.GetGroupsParams{
		First:  &query.Page,
		Max:    &query.PerPage,
		Search: &query.Search,
		Q:      &query.Q,
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

// processTeamSyncables handles adding or removing a user from teams for a group
func (k *KeycloakClient) processTeamSyncables(groupID string, user *mmModel.User, isRemoval bool) {
	teamSyncables, err := k.PluginAPI.Group.GetSyncables(groupID, mmModel.GroupSyncableTypeTeam)
	if err != nil {
		k.PluginAPI.Log.Error("Failed to get group teams",
			"group_id", groupID,
			"error", err)
		return
	}

	for _, teamSyncable := range teamSyncables {
		if teamSyncable.AutoAdd {
			if isRemoval {
				if err = k.PluginAPI.Team.DeleteMember(teamSyncable.SyncableId, user.Id, ""); err != nil {
					k.PluginAPI.Log.Error("Failed to remove user from team",
						"user_id", user.Id,
						"team_id", teamSyncable.SyncableId,
						"error", err)
				}
			} else {
				if _, err = k.PluginAPI.Team.CreateMember(teamSyncable.SyncableId, user.Id); err != nil {
					k.PluginAPI.Log.Error("Failed to add user to team",
						"user_id", user.Id,
						"team_id", teamSyncable.SyncableId,
						"error", err)
				}
			}
		}
	}
}

// processChannelSyncables handles adding or removing a user from channels for a group
func (k *KeycloakClient) processChannelSyncables(groupID string, user *mmModel.User, isRemoval bool) {
	channelSyncables, err := k.PluginAPI.Group.GetSyncables(groupID, mmModel.GroupSyncableTypeChannel)
	if err != nil {
		k.PluginAPI.Log.Error("Failed to get group channels",
			"group_id", groupID,
			"error", err)
		return
	}

	for _, channelSyncable := range channelSyncables {
		if channelSyncable.AutoAdd {
			if isRemoval {
				if err = k.PluginAPI.Channel.DeleteMember(channelSyncable.SyncableId, user.Id); err != nil {
					k.PluginAPI.Log.Error("Failed to remove user from channel",
						"user_id", user.Id,
						"channel_id", channelSyncable.SyncableId,
						"error", err)
				}
			} else {
				if _, err = k.PluginAPI.Channel.AddMember(channelSyncable.SyncableId, user.Id); err != nil {
					k.PluginAPI.Log.Error("Failed to add user to channel",
						"user_id", user.Id,
						"channel_id", channelSyncable.SyncableId,
						"error", err)
				}
			}
		}
	}
}

// getExistingGroups retrieves all groups the user is currently a member of
func (k *KeycloakClient) GetExistingGroups(userID string) ([]*mmModel.Group, error) {
	var existingGroups []*mmModel.Group
	page := 0
	perPage := 100

	for {
		groups, err := k.PluginAPI.Group.GetGroups(page, perPage, mmModel.GroupSearchOpts{
			Source:          mmModel.GroupSourcePluginPrefix + "keycloak",
			FilterHasMember: userID,
		}, nil)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get user's existing groups")
		}

		existingGroups = append(existingGroups, groups...)

		if len(groups) < perPage {
			break
		}

		page++
	}

	return existingGroups, nil
}

// ProcessMembershipChanges handles the addition and removal of group memberships
func (k *KeycloakClient) ProcessMembershipChanges(user *mmModel.User, existingGroups []*mmModel.Group, newGroupIDs map[string]bool) ([]string, []string, []*mmModel.Group) {
	var removedFromGroups []string
	var addedToGroups []string
	remainingGroups := make([]*mmModel.Group, 0)

	// Process removals
	for _, existingGroup := range existingGroups {
		if !newGroupIDs[existingGroup.Id] {
			if _, err := k.PluginAPI.Group.DeleteMember(existingGroup.Id, user.Id); err != nil {
				k.PluginAPI.Log.Error("Failed to remove user from group",
					"user_id", user.Id,
					"group_id", existingGroup.Id,
					"error", err)
			} else {
				removedFromGroups = append(removedFromGroups, existingGroup.Id)
			}
		} else {
			remainingGroups = append(remainingGroups, existingGroup)
		}
	}

	// Process additions
	existingGroupIDs := make(map[string]bool)
	for _, group := range existingGroups {
		existingGroupIDs[group.Id] = true
	}

	for groupID := range newGroupIDs {
		if !existingGroupIDs[groupID] {
			group, err := k.PluginAPI.Group.Get(groupID)
			if err != nil {
				k.PluginAPI.Log.Error("Failed to get group info",
					"group_id", groupID,
					"error", err)
				continue
			}

			if _, err := k.PluginAPI.Group.UpsertMember(groupID, user.Id); err != nil {
				k.PluginAPI.Log.Error("Failed to add user to group",
					"user_id", user.Id,
					"group_id", groupID,
					"error", err)
			} else {
				addedToGroups = append(addedToGroups, group.Id)
			}
		}
	}

	return removedFromGroups, addedToGroups, remainingGroups
}

// HandleSAMLLogin processes SAML login events and syncs group memberships
func (k *KeycloakClient) HandleSAMLLogin(c *plugin.Context, user *mmModel.User, encodedXML string, groupsAttribute string) error {
	if groupsAttribute == "" {
		k.PluginAPI.Log.Debug("Groups attribute not configured, skipping group sync")
		return nil
	}

	assertionInfo, err := k.PluginAPI.User.ValidateSAMLResponse(encodedXML)
	if err != nil {
		return errors.Wrap(err, "failed to validate SAML response")
	}

	// Get all group values from the SAML assertion
	var groupNames []string
	for _, attr := range assertionInfo.Assertions[0].AttributeStatement.Attributes {
		if attr.Name == groupsAttribute {
			for _, val := range attr.Values {
				if val.Value != "" {
					groupNames = append(groupNames, val.Value)
				}
			}
			break
		}
	}

	if len(groupNames) == 0 {
		k.PluginAPI.Log.Debug("No groups found in SAML assertion")
		var existingGroups []*mmModel.Group
		// Even with no new groups, we need to clean up existing memberships
		existingGroups, err = k.GetExistingGroups(user.Id)
		if err != nil {
			return err
		}

		if len(existingGroups) > 0 {
			for _, group := range existingGroups {
				if _, err = k.PluginAPI.Group.DeleteMember(group.Id, user.Id); err != nil {
					k.PluginAPI.Log.Error("Failed to remove user from group",
						"user_id", user.Id,
						"group_id", group.Id,
						"error", err)
					continue
				}
				k.processTeamSyncables(group.Id, user, true)
				k.processChannelSyncables(group.Id, user, true)
			}
		}
		return nil
	}

	// Create a map of new group IDs
	newGroupIDs := make(map[string]bool)

	// Process all groups from SAML assertion
	for _, groupName := range groupNames {
		var keycloakGroupID string
		keycloakGroupID, err = k.Kvstore.GetGroupID(groupName)
		if err != nil {
			// If not in KVStore, fetch from Keycloak
			validToken, err := k.Authenticate(context.Background())
			if err != nil {
				k.PluginAPI.Log.Error("Failed to authenticate", "error", err)
				continue
			}

			group, err := k.Client.GetGroupByPath(context.Background(), validToken, k.Realm, "/"+groupName)
			if err != nil {
				k.PluginAPI.Log.Error("Failed to get group by path", "group", groupName, "error", err)
				continue
			}

			if group == nil || group.ID == nil {
				k.PluginAPI.Log.Error("Group not found in Keycloak", "group", groupName)
				continue
			}

			keycloakGroupID = *group.ID
			if err = k.Kvstore.StoreGroupID(groupName, keycloakGroupID); err != nil {
				k.PluginAPI.Log.Error("Failed to store group mapping", "group", groupName, "error", err)
				continue
			}
		}

		var mmGroup *mmModel.Group
		mmGroup, err = k.PluginAPI.Group.GetByRemoteID(keycloakGroupID, k.GetGroupSource())
		if err != nil {
			k.PluginAPI.Log.Error("Failed to get Mattermost group", "remote_id", keycloakGroupID, "error", err)
			continue
		}

		newGroupIDs[mmGroup.Id] = true
	}

	existingGroups, err := k.GetExistingGroups(user.Id)
	if err != nil {
		return err
	}

	removedFromGroups, addedToGroups, remainingGroups := k.ProcessMembershipChanges(user, existingGroups, newGroupIDs)

	if len(removedFromGroups) > 0 {
		k.PluginAPI.Log.Debug("Removed user from groups",
			"user_id", user.Id,
			"groups", strings.Join(removedFromGroups, ", "))

		for _, groupID := range removedFromGroups {
			k.processTeamSyncables(groupID, user, true)
			k.processChannelSyncables(groupID, user, true)
		}
	}

	if len(addedToGroups) > 0 {
		k.PluginAPI.Log.Debug("Added user to groups",
			"user_id", user.Id,
			"groups", strings.Join(addedToGroups, ", "))

		for _, groupID := range addedToGroups {
			k.processTeamSyncables(groupID, user, false)
			k.processChannelSyncables(groupID, user, false)
		}
	}

	if len(remainingGroups) > 0 {

		for _, group := range remainingGroups {
			if newGroupIDs[group.Id] {
				k.processTeamSyncables(group.Id, user, false)
				k.processChannelSyncables(group.Id, user, false)
			}
		}
	}

	return nil
}

func (k *KeycloakClient) SyncGroupMap(ctx context.Context) error {
	// Get existing group mappings from KV store
	existingGroups, err := k.Kvstore.ListGroupIDs()
	if err != nil {
		return fmt.Errorf("failed to list existing groups: %w", err)
	}

	// Create a map to track which groups we find in Keycloak
	foundGroups := make(map[string]bool)

	page := 0
	perPage := 100

	for {
		// Get groups page by page
		params := gocloak.GetGroupsParams{
			First: &page,
			Max:   &perPage,
		}
		result, err := k.executeWithRetry(ctx, func(t string) (interface{}, error) {
			return k.Client.GetGroups(ctx, t, k.Realm, params)
		})
		if err != nil {
			return fmt.Errorf("failed to sync groups: %w", err)
		}

		groups := result.([]*gocloak.Group)
		if len(groups) == 0 {
			break // No more groups to process
		}

		// Store each group mapping individually
		for _, group := range groups {
			if group.Name != nil && group.ID != nil {
				foundGroups[*group.Name] = true

				// Check if mapping already exists with same ID
				if existingID, exists := existingGroups[*group.Name]; !exists || existingID != *group.ID {
					if err := k.Kvstore.StoreGroupID(*group.Name, *group.ID); err != nil {
						k.PluginAPI.Log.Error("Failed to store group mapping", "group", *group.Name, "error", err)
					}
				}
			}
		}

		// If we got less than perPage results, we've reached the end
		if len(groups) < perPage {
			break
		}

		page++ // Move to next page
	}

	// Remove any groups that exist in KV store but weren't found in Keycloak
	for groupName := range existingGroups {
		if !foundGroups[groupName] {
			if err := k.Kvstore.DeleteGroupID(groupName); err != nil {
				k.PluginAPI.Log.Error("Failed to delete stale group mapping", "group", groupName, "error", err)
			} else {
				k.PluginAPI.Log.Debug("Deleted stale group mapping", "group", groupName)
			}
		}
	}

	return nil
}

func (k *KeycloakClient) GetGroupSource() mmModel.GroupSource {
	return mmModel.GroupSourcePluginPrefix + "keycloak"
}
