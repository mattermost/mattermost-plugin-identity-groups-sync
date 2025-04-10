package groups

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Nerzal/gocloak/v13"
	saml2 "github.com/mattermost/gosaml2"
	mmModel "github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"
	"github.com/mattermost/mattermost/server/public/pluginapi"
	"github.com/pkg/errors"

	"github.com/mattermost/mattermost-plugin-identity-groups-sync/server/model"
	"github.com/mattermost/mattermost-plugin-identity-groups-sync/server/store/kvstore"
)

// KeycloakClient wraps the gocloak client and provides SAML-specific functionality
type KeycloakClient struct {
	Client        GoCloak
	Realm         string
	ClientID      string
	ClientSecret  string
	EncryptionKey string
	Kvstore       kvstore.KVStore
	PluginAPI     *pluginapi.Client
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
func NewKeycloakClient(hostURL, realm, clientID, clientSecret, encryptionKey string, kvstore kvstore.KVStore, client *pluginapi.Client) *KeycloakClient {
	return &KeycloakClient{
		Client:        gocloak.NewClient(hostURL),
		Realm:         realm,
		ClientID:      clientID,
		ClientSecret:  clientSecret,
		EncryptionKey: encryptionKey,
		Kvstore:       kvstore,
		PluginAPI:     client,
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

	if err := k.Kvstore.StoreKeycloakJWT(jwt); err != nil {
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
		Search: &query.Search,
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
// If q is provided, it will filter the count based on the search term
func (k *KeycloakClient) GetGroupsCount(ctx context.Context, q string) (int, error) {
	params := gocloak.GetGroupsParams{}
	if q != "" {
		params.Search = &q
	}

	result, err := k.executeWithRetry(ctx, func(t string) (interface{}, error) {
		return k.Client.GetGroupsCount(ctx, t, k.Realm, params)
	})
	if err != nil {
		return 0, fmt.Errorf("failed to get groups count: %w", err)
	}
	count := result.(int)

	return count, nil
}

// getAuthToken retrieves and validates the authentication token
func (k *KeycloakClient) getAuthToken(ctx context.Context) (string, error) {
	jwt, err := k.Kvstore.GetKeycloakJWT()
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

		if err = k.Kvstore.StoreKeycloakJWT(newToken); err != nil {
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

// addUserToTeams adds a user to all teams associated with a group
func (k *KeycloakClient) addUserToTeams(groupID string, user *mmModel.User) {
	teamSyncables, err := k.PluginAPI.Group.GetSyncables(groupID, mmModel.GroupSyncableTypeTeam)
	if err != nil {
		k.PluginAPI.Log.Error("Failed to get group teams",
			"group_id", groupID,
			"error", err)
		return
	}

	for _, teamSyncable := range teamSyncables {
		if teamSyncable.AutoAdd {
			if _, err = k.PluginAPI.Team.CreateMember(teamSyncable.SyncableId, user.Id); err != nil {
				k.PluginAPI.Log.Error("Failed to add user to team",
					"user_id", user.Id,
					"team_id", teamSyncable.SyncableId,
					"error", err)
			}
		}
	}
}

// removeUserFromTeams removes a user from all teams associated with a group
func (k *KeycloakClient) removeUserFromTeams(groupID string, user *mmModel.User) {
	teamSyncables, err := k.PluginAPI.Group.GetSyncables(groupID, mmModel.GroupSyncableTypeTeam)
	if err != nil {
		k.PluginAPI.Log.Error("Failed to get group teams",
			"group_id", groupID,
			"error", err)
		return
	}

	for _, teamSyncable := range teamSyncables {
		if teamSyncable.AutoAdd {
			if err = k.PluginAPI.Team.DeleteMember(teamSyncable.SyncableId, user.Id, ""); err != nil {
				k.PluginAPI.Log.Error("Failed to remove user from team",
					"user_id", user.Id,
					"team_id", teamSyncable.SyncableId,
					"error", err)
			}
		}
	}
}

// addUserToChannels adds a user to all channels associated with a group
func (k *KeycloakClient) addUserToChannels(groupID string, user *mmModel.User) {
	channelSyncables, err := k.PluginAPI.Group.GetSyncables(groupID, mmModel.GroupSyncableTypeChannel)
	if err != nil {
		k.PluginAPI.Log.Error("Failed to get group channels",
			"group_id", groupID,
			"error", err)
		return
	}

	for _, channelSyncable := range channelSyncables {
		if channelSyncable.AutoAdd {
			if _, err = k.PluginAPI.Channel.AddMember(channelSyncable.SyncableId, user.Id); err != nil {
				k.PluginAPI.Log.Error("Failed to add user to channel",
					"user_id", user.Id,
					"channel_id", channelSyncable.SyncableId,
					"error", err)
			}
		}
	}
}

// removeUserFromChannels removes a user from all channels associated with a group
func (k *KeycloakClient) removeUserFromChannels(groupID string, user *mmModel.User) {
	channelSyncables, err := k.PluginAPI.Group.GetSyncables(groupID, mmModel.GroupSyncableTypeChannel)
	if err != nil {
		k.PluginAPI.Log.Error("Failed to get group channels",
			"group_id", groupID,
			"error", err)
		return
	}

	for _, channelSyncable := range channelSyncables {
		if channelSyncable.AutoAdd {
			if err = k.PluginAPI.Channel.DeleteMember(channelSyncable.SyncableId, user.Id); err != nil {
				k.PluginAPI.Log.Error("Failed to remove user from channel",
					"user_id", user.Id,
					"channel_id", channelSyncable.SyncableId,
					"error", err)
			}
		}
	}
}

// getExistingGroups retrieves all groups the user is currently a member of
func (k *KeycloakClient) GetExistingGroupMemberships(userID string) ([]*mmModel.Group, error) {
	var existingGroups []*mmModel.Group
	page := 0
	perPage := 100

	for {
		groups, err := k.PluginAPI.Group.GetGroups(page, perPage, mmModel.GroupSearchOpts{
			Source:          mmModel.GroupSourcePluginPrefix + "keycloak",
			FilterHasMember: userID,
			// When a group is unlinked the group memberships and syncables remain but the user should be removed from those syncables
			// so we need to include archived groups to remove the user from them.
			// If they decide to re-link the group, the user will be added back to the syncables because those relationships remain.
			IncludeArchived: true,
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
func (k *KeycloakClient) ProcessMembershipChanges(user *mmModel.User, existingGroupMemberships []*mmModel.Group, activeSamlAssertionGroups map[string]*mmModel.Group) ([]string, []string) {
	var removedFromGroups []string
	activeGroups := make([]string, 0)

	// Create map of existing group IDs and process removals in one pass
	existingGroupIDs := make(map[string]bool)
	for _, group := range existingGroupMemberships {
		existingGroupIDs[group.Id] = true
		if _, exists := activeSamlAssertionGroups[group.Id]; !exists {
			if _, err := k.PluginAPI.Group.DeleteMember(group.Id, user.Id); err != nil {
				k.PluginAPI.Log.Error("Failed to remove user from group",
					"user_id", user.Id,
					"group_id", group.Id,
					"error", err)
			} else {
				removedFromGroups = append(removedFromGroups, group.Id)
			}
		} else {
			activeGroups = append(activeGroups, group.Id)
		}
	}

	// Process additions
	for groupID := range activeSamlAssertionGroups {
		if !existingGroupIDs[groupID] {
			if _, err := k.PluginAPI.Group.UpsertMember(groupID, user.Id); err != nil {
				k.PluginAPI.Log.Error("Failed to add user to group",
					"user_id", user.Id,
					"group_id", groupID,
					"error", err)
			} else {
				// Add the newly added group to activeGroups
				activeGroups = append(activeGroups, groupID)
			}
		}
	}

	return removedFromGroups, activeGroups
}

// HandleSAMLLogin processes SAML login events and syncs group memberships
func (k *KeycloakClient) HandleSAMLLogin(c *plugin.Context, user *mmModel.User, assertionInfo *saml2.AssertionInfo, groupsAttribute string) error {
	if groupsAttribute == "" {
		k.PluginAPI.Log.Debug("Groups attribute not configured, skipping group sync")
		return nil
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
		var existingGroupMemberships []*mmModel.Group
		// Even with no new groups, we need to clean up existing memberships
		existingGroupMemberships, err := k.GetExistingGroupMemberships(user.Id)
		if err != nil {
			return err
		}

		if len(existingGroupMemberships) > 0 {
			for _, group := range existingGroupMemberships {
				if _, err = k.PluginAPI.Group.DeleteMember(group.Id, user.Id); err != nil {
					k.PluginAPI.Log.Error("Failed to remove user from group",
						"user_id", user.Id,
						"group_id", group.Id,
						"error", err)
					continue
				}
				k.removeUserFromTeams(group.Id, user)
				k.removeUserFromChannels(group.Id, user)
			}
		}
		return nil
	}

	// Create a map of groups from the SAML assertion that should be active in Mattermost
	activeSamlAssertionGroups := make(map[string]*mmModel.Group)

	// Process all groups from SAML assertion
	for _, groupName := range groupNames {
		var keycloakGroupID string
		keycloakGroupID, err := k.Kvstore.GetKeycloakGroupID(groupName)
		if err != nil {
			// If not in KVStore, fetch from Keycloak
			var result interface{}
			result, err = k.executeWithRetry(context.Background(), func(token string) (interface{}, error) {
				return k.Client.GetGroupByPath(context.Background(), token, k.Realm, "/"+groupName)
			})
			if err != nil {
				k.PluginAPI.Log.Error("Failed to get group by path", "group", groupName, "error", err)
				continue
			}

			group := result.(*gocloak.Group)
			if group == nil || group.ID == nil {
				k.PluginAPI.Log.Error("Group not found in Keycloak", "group", groupName)
				continue
			}

			keycloakGroupID = *group.ID
			if err = k.Kvstore.StoreKeycloakGroupID(groupName, keycloakGroupID); err != nil {
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

		// If the group is deleted in Mattermost, skip it because activeSamlAssertionGroups should only contain active groups that you want the user to be a member of.
		if mmGroup.DeleteAt != 0 {
			continue
		}

		activeSamlAssertionGroups[mmGroup.Id] = mmGroup
	}

	existingGroupMemberships, err := k.GetExistingGroupMemberships(user.Id)
	if err != nil {
		return err
	}

	removedFromGroups, activeGroups := k.ProcessMembershipChanges(user, existingGroupMemberships, activeSamlAssertionGroups)

	if len(removedFromGroups) > 0 {
		for _, groupID := range removedFromGroups {
			k.removeUserFromTeams(groupID, user)
			k.removeUserFromChannels(groupID, user)
		}
	}

	// Process all active groups (both remaining and newly added)
	if len(activeGroups) > 0 {
		for _, groupID := range activeGroups {
			k.addUserToTeams(groupID, user)
			k.addUserToChannels(groupID, user)
		}
	}

	return nil
}

func (k *KeycloakClient) SyncGroupMap(ctx context.Context) error {
	// Get existing group mappings from KV store
	existingGroups, err := k.Kvstore.ListKeycloakGroupIDs()
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
					if err := k.Kvstore.StoreKeycloakGroupID(*group.Name, *group.ID); err != nil {
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
			if err := k.Kvstore.DeleteKeycloakGroupID(groupName); err != nil {
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
