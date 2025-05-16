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
	Client                    GoCloak
	Realm                     string
	ClientID                  string
	ClientSecret              string
	EncryptionKey             string
	FailLoginOnGroupSyncError bool
	Kvstore                   kvstore.KVStore
	PluginAPI                 *pluginapi.Client
}

// executeWithRetry gets a valid token and executes the given function, retrying once with a new token if it gets a 401
// A timeout is applied to the context to ensure API calls don't hang indefinitely
func (k *KeycloakClient) executeWithRetry(ctx context.Context, fn func(context.Context, string) (interface{}, error)) (interface{}, error) {
	if k.Client == nil || k.Realm == "" {
		return nil, &AuthError{
			Message: "keycloak not configured",
			Err:     fmt.Errorf("missing required configuration: client and realm"),
		}
	}

	// Create a timeout context that will be used for all API calls
	// Default timeout of 30 seconds if the parent context doesn't have a deadline
	ctxWithTimeout, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	token, err := k.getAuthToken(ctxWithTimeout)
	if err != nil {
		return nil, fmt.Errorf("failed to get auth token: %w", err)
	}

	result, err := fn(ctxWithTimeout, token)
	if err != nil && strings.Contains(err.Error(), "401 Unauthorized") {
		// Try to authenticate once
		newToken, authErr := k.Authenticate(ctxWithTimeout)
		if authErr != nil {
			return nil, fmt.Errorf("failed to reauthenticate after 401: %w", authErr)
		}
		// Retry the request with new token
		result, err = fn(ctxWithTimeout, newToken)
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
func NewKeycloakClient(hostURL, realm, clientID, clientSecret, encryptionKey string, failLoginOnGroupSyncError bool, kvstore kvstore.KVStore, client *pluginapi.Client) *KeycloakClient {
	return &KeycloakClient{
		Client:                    gocloak.NewClient(hostURL),
		Realm:                     realm,
		ClientID:                  clientID,
		ClientSecret:              clientSecret,
		EncryptionKey:             encryptionKey,
		FailLoginOnGroupSyncError: failLoginOnGroupSyncError,
		Kvstore:                   kvstore,
		PluginAPI:                 client,
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
	result, err := k.executeWithRetry(ctx, func(reqCtx context.Context, t string) (interface{}, error) {
		return k.Client.GetGroups(reqCtx, t, k.Realm, params)
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

	result, err := k.executeWithRetry(ctx, func(reqCtx context.Context, t string) (interface{}, error) {
		return k.Client.GetGroupsCount(reqCtx, t, k.Realm, params)
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
	result, err := k.executeWithRetry(ctx, func(reqCtx context.Context, t string) (interface{}, error) {
		return k.Client.GetGroupMembers(reqCtx, t, k.Realm, groupID, gocloak.GetGroupsParams{})
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get group members: %w", err)
	}
	users := result.([]*gocloak.User)

	return users, nil
}

// GetGroup retrieves a specific group from Keycloak by ID
func (k *KeycloakClient) GetGroup(ctx context.Context, groupID string) (*mmModel.Group, error) {
	result, err := k.executeWithRetry(ctx, func(reqCtx context.Context, t string) (interface{}, error) {
		return k.Client.GetGroup(reqCtx, t, k.Realm, groupID)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get group: %w", err)
	}
	group := result.(*gocloak.Group)

	return k.translateGroup(group), nil
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

// GetGroupsForRemovalAndActiveGroups returns the groups the user should be removed from, groups user should be added to, and groups the user will remain in.
func (k *KeycloakClient) GetGroupsForRemovalAndActiveGroups(user *mmModel.User, existingGroupMemberships []*mmModel.Group, activeSamlAssertionGroups map[string]*mmModel.Group) ([]string, []string, []string) {
	groupsForRemoval := make([]string, 0)
	groupsForAddition := make([]string, 0)
	groupsForRetention := make([]string, 0)

	// Create map of existing group IDs so we can check for removals and retentions
	existingGroupIDs := make(map[string]bool)
	for _, group := range existingGroupMemberships {
		existingGroupIDs[group.Id] = true
		if _, exists := activeSamlAssertionGroups[group.Id]; !exists {
			// User is not in the group anymore, mark for removal
			groupsForRemoval = append(groupsForRemoval, group.Id)
		} else {
			// User is still in the group, mark for retention
			groupsForRetention = append(groupsForRetention, group.Id)
		}
	}

	// Process additions
	for groupID := range activeSamlAssertionGroups {
		if !existingGroupIDs[groupID] {
			// User is not in the group, mark for addition
			groupsForAddition = append(groupsForAddition, groupID)
		}
	}

	return groupsForRemoval, groupsForAddition, groupsForRetention
}

func (k *KeycloakClient) RemoveUserFromGroups(groupIDs []string, user *mmModel.User) error {
	for _, groupID := range groupIDs {
		if _, err := k.PluginAPI.Group.DeleteMember(groupID, user.Id); err != nil {
			k.PluginAPI.Log.Error("Failed to remove user from group",
				"user_id", user.Id,
				"group_id", groupID,
				"error", err)
			if k.FailLoginOnGroupSyncError {
				return err
			}
		}
	}
	return nil
}
func (k *KeycloakClient) AddUserToGroups(groupIDs []string, user *mmModel.User) []string {
	newGroupMemberships := make([]string, 0)
	for _, groupID := range groupIDs {
		if _, err := k.PluginAPI.Group.UpsertMember(groupID, user.Id); err != nil {
			k.PluginAPI.Log.Error("Failed to add user to group",
				"user_id", user.Id,
				"group_id", groupID,
				"error", err)
		} else {
			newGroupMemberships = append(newGroupMemberships, groupID)
		}
	}

	return newGroupMemberships
}

// addSyncableTeamsForAddition adds team IDs that the user should be added to into the provided map
func (k *KeycloakClient) addSyncableTeamsForAddition(groupID string, teamsToAdd map[string]mmModel.GroupSyncable) {
	teamSyncables, err := k.PluginAPI.Group.GetSyncables(groupID, mmModel.GroupSyncableTypeTeam)
	if err != nil {
		k.PluginAPI.Log.Error("Failed to get group teams for addition",
			"group_id", groupID,
			"error", err)
		return
	}

	for _, teamSyncable := range teamSyncables {
		if teamSyncable.AutoAdd {
			teamsToAdd[teamSyncable.SyncableId] = *teamSyncable
		}
	}
}

// addSyncableTeamsForRemoval adds team IDs that the user should be removed from into the provided map
func (k *KeycloakClient) addSyncableTeamsForRemoval(groupID string, teamsToRemove map[string]mmModel.GroupSyncable) error {
	teamSyncables, err := k.PluginAPI.Group.GetSyncables(groupID, mmModel.GroupSyncableTypeTeam)
	if err != nil {
		k.PluginAPI.Log.Error("Failed to get group teams for removal",
			"group_id", groupID,
			"error", err)
		return errors.Wrap(err, "failed to get group teams")
	}

	for _, teamSyncable := range teamSyncables {
		teamsToRemove[teamSyncable.SyncableId] = *teamSyncable
	}

	return nil
}

// addSyncableChannelsForAddition adds channel IDs that the user should be added to into the provided map
func (k *KeycloakClient) addSyncableChannelsForAddition(groupID string, channelsToAdd map[string]mmModel.GroupSyncable) {
	channelSyncables, err := k.PluginAPI.Group.GetSyncables(groupID, mmModel.GroupSyncableTypeChannel)
	if err != nil {
		k.PluginAPI.Log.Error("Failed to get group channels for addition",
			"group_id", groupID,
			"error", err)
		return
	}

	for _, channelSyncable := range channelSyncables {
		if channelSyncable.AutoAdd {
			channelsToAdd[channelSyncable.SyncableId] = *channelSyncable
		}
	}
}

// addSyncableChannelsForRemoval adds channel IDs that the user should be removed from into the provided map
func (k *KeycloakClient) addSyncableChannelsForRemoval(groupID string, channelsToRemove map[string]mmModel.GroupSyncable) error {
	channelSyncables, err := k.PluginAPI.Group.GetSyncables(groupID, mmModel.GroupSyncableTypeChannel)
	if err != nil {
		k.PluginAPI.Log.Error("Failed to get group channels for removal",
			"group_id", groupID,
			"error", err)
		return errors.Wrap(err, "failed to get group channels")
	}

	for _, channelSyncable := range channelSyncables {
		channelsToRemove[channelSyncable.SyncableId] = *channelSyncable
	}

	return nil
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
			k.PluginAPI.Log.Error("Failed to get existing group memberships",
				"user_id", user.Id,
				"error", err)
			if k.FailLoginOnGroupSyncError {
				return err
			}
			existingGroupMemberships = []*mmModel.Group{}
		}

		if len(existingGroupMemberships) > 0 {
			teamsToLeave := make(map[string]mmModel.GroupSyncable)
			channelsToLeave := make(map[string]mmModel.GroupSyncable)
			for _, group := range existingGroupMemberships {
				if err = k.addSyncableTeamsForRemoval(group.Id, teamsToLeave); err != nil {
					if k.FailLoginOnGroupSyncError {
						return err
					}
				}
				if err = k.addSyncableChannelsForRemoval(group.Id, channelsToLeave); err != nil {
					if k.FailLoginOnGroupSyncError {
						return err
					}
				}
			}
			err = k.removeUserFromChannels(channelsToLeave, user)
			if err != nil {
				return err
			}
			err = k.removeUserFromTeams(teamsToLeave, user)
			if err != nil {
				return err
			}
			for _, group := range existingGroupMemberships {
				if _, err = k.PluginAPI.Group.DeleteMember(group.Id, user.Id); err != nil {
					k.PluginAPI.Log.Error("Failed to remove user from group",
						"user_id", user.Id,
						"group_id", group.Id,
						"error", err)
					if k.FailLoginOnGroupSyncError {
						return errors.New("failed to remove user from group")
					}
				}
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
			result, err = k.executeWithRetry(context.Background(), func(reqCtx context.Context, token string) (interface{}, error) {
				return k.Client.GetGroupByPath(reqCtx, token, k.Realm, "/"+groupName)
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
		k.PluginAPI.Log.Error("Failed to get existing group memberships",
			"user_id", user.Id,
			"error", err)
		if k.FailLoginOnGroupSyncError {
			return err
		}
		existingGroupMemberships = []*mmModel.Group{}
	}

	groupsForRemoval, groupsForAddition, groupsForRetention := k.GetGroupsForRemovalAndActiveGroups(user, existingGroupMemberships, activeSamlAssertionGroups)

	proposedChannelsToLeave := make(map[string]mmModel.GroupSyncable)
	finalChannelsToJoin := make(map[string]mmModel.GroupSyncable)

	proposedTeamsToLeave := make(map[string]mmModel.GroupSyncable)
	finalTeamsToJoin := make(map[string]mmModel.GroupSyncable)
	if len(groupsForRemoval) > 0 {
		for _, groupID := range groupsForRemoval {
			if err = k.addSyncableTeamsForRemoval(groupID, proposedTeamsToLeave); err != nil {
				if k.FailLoginOnGroupSyncError {
					return err
				}
			}
			if err = k.addSyncableChannelsForRemoval(groupID, proposedChannelsToLeave); err != nil {
				if k.FailLoginOnGroupSyncError {
					return err
				}
			}
		}
	}

	// Get the syncables for groups that the user will remain in
	if len(groupsForRetention) > 0 {
		for _, groupID := range groupsForRetention {
			k.addSyncableTeamsForAddition(groupID, finalTeamsToJoin)
			k.addSyncableChannelsForAddition(groupID, finalChannelsToJoin)
		}
	}

	finalTeamsToLeave := make(map[string]mmModel.GroupSyncable)
	// Loop over teams to leave and check if it's in the list of teams to join.
	// If it's in the teams to join, we don't need to remove the team membership.
	for teamID, groupSyncable := range proposedTeamsToLeave {
		if _, exists := finalTeamsToJoin[teamID]; !exists {
			finalTeamsToLeave[teamID] = groupSyncable
		}
	}

	finalChannelsToLeave := make(map[string]mmModel.GroupSyncable)
	// Loop over channels to leave and check if it's in the list of channels to join.
	// If it's in the channels to join, we don't need to remove the channel membership.
	for channelID, groupSyncable := range proposedChannelsToLeave {
		if _, exists := finalChannelsToJoin[channelID]; !exists {
			finalChannelsToLeave[channelID] = groupSyncable
		}
	}
	err = k.removeUserFromChannels(finalChannelsToLeave, user)
	if err != nil {
		return err
	}
	err = k.removeUserFromTeams(finalTeamsToLeave, user)
	if err != nil {
		return err
	}
	err = k.RemoveUserFromGroups(groupsForRemoval, user)
	if err != nil {
		return err
	}
	newGroupMemberships := k.AddUserToGroups(groupsForAddition, user)

	// Get the syncables for new group memberships.
	// There could be cases where the user was removed from a team or channel but is being added back to the same team or channel.
	// We could have used groupsForAddition instead of newGroupMemberships to get the syncables but then you can end up in a situation where the user fails to be added to a group but is successfully added to the team/channel.
	// This is because the group membership can fail to be added but the syncable membership can still be added.
	if len(newGroupMemberships) > 0 {
		for _, groupID := range newGroupMemberships {
			k.addSyncableTeamsForAddition(groupID, finalTeamsToJoin)
			k.addSyncableChannelsForAddition(groupID, finalChannelsToJoin)
		}
	}
	k.addUserToTeams(finalTeamsToJoin, user)
	k.addUserToChannels(finalChannelsToJoin, user)

	return nil
}

func (k *KeycloakClient) removeUserFromTeams(teamsToLeave map[string]mmModel.GroupSyncable, user *mmModel.User) error {
	for teamID := range teamsToLeave {
		team, err := k.PluginAPI.Team.Get(teamID)
		if err != nil {
			k.PluginAPI.Log.Error("Failed to remove user from team, unable to get team",
				"user_id", user.Id,
				"team_id", teamID,
				"error", err)
			if k.FailLoginOnGroupSyncError {
				return err
			}
			continue
		}

		// Don't remove user from the team if it's not group constrained.
		// Groups get associated with teams when a group is associated to a channel within the team. So we cannot tell if the user was added to the team directly or through the group.
		if team.GroupConstrained == nil || (team.GroupConstrained != nil && !*team.GroupConstrained) {
			continue
		}
		// Check if they are a member of the team
		member, err := k.PluginAPI.Team.GetMember(teamID, user.Id)
		if err != nil {
			if strings.ToLower(err.Error()) == "not found" {
				k.PluginAPI.Log.Debug("User has already left the team", "team_id", teamID, "user_id", user.Id)
			} else {
				k.PluginAPI.Log.Error("Failed to remove user from team, unable to get team member",
					"user_id", user.Id,
					"team_id", teamID,
					"error", err)
				if k.FailLoginOnGroupSyncError {
					return err
				}
			}
			continue
		}
		if member != nil && member.DeleteAt == 0 {
			k.PluginAPI.Log.Debug("Removing user from team", "team_id", teamID, "user_id", user.Id)
			if err = k.PluginAPI.Team.DeleteMember(teamID, user.Id, ""); err != nil {
				k.PluginAPI.Log.Error("Failed to remove user from team",
					"user_id", user.Id,
					"team_id", teamID,
					"error", err)
				if k.FailLoginOnGroupSyncError {
					return err
				}
			}
		}
	}

	return nil
}

// addUserToTeams adds a user to all teams associated with a group
func (k *KeycloakClient) addUserToTeams(teamsToJoin map[string]mmModel.GroupSyncable, user *mmModel.User) {
	for teamID := range teamsToJoin {
		// Check if they are a member of the team
		member, err := k.PluginAPI.Team.GetMember(teamID, user.Id)
		if err != nil {
			if strings.ToLower(err.Error()) != "not found" {
				k.PluginAPI.Log.Error("Failed to add user to team, unable to get team member",
					"user_id", user.Id,
					"team_id", teamID,
					"error", err)
				continue
			}
		}

		if member == nil || (member.DeleteAt != 0) {
			k.PluginAPI.Log.Debug("Adding user to team", "team_id", teamID, "user_id", user.Id)
			if _, err = k.PluginAPI.Team.CreateMember(teamID, user.Id); err != nil {
				k.PluginAPI.Log.Error("Failed to add user to team",
					"user_id", user.Id,
					"team_id", teamID,
					"error", err)
			}
		}
	}
}

// removeUserFromChannels removes a user from all channels associated with a group
func (k *KeycloakClient) removeUserFromChannels(channelsToLeave map[string]mmModel.GroupSyncable, user *mmModel.User) error {
	for channelID := range channelsToLeave {
		_, err := k.PluginAPI.Channel.GetMember(channelID, user.Id)
		if err != nil {
			// check if the error is because the user was not found
			if strings.ToLower(err.Error()) == "not found" {
				k.PluginAPI.Log.Debug("User has already left the channel", "channel_id", channelID, "user_id", user.Id)
			} else {
				k.PluginAPI.Log.Error("Failed to remove user from channel, unable to get channel member",
					"user_id", user.Id,
					"channel_id", channelID,
					"error", err)
				if k.FailLoginOnGroupSyncError {
					return err
				}
			}
			continue
		}
		k.PluginAPI.Log.Debug("Removing user from channel", "channel_id", channelID, "user_id", user.Id)
		if err = k.PluginAPI.Channel.DeleteMember(channelID, user.Id); err != nil {
			k.PluginAPI.Log.Error("Failed to remove user from channel",
				"user_id", user.Id,
				"channel_id", channelID,
				"error", err)
			if k.FailLoginOnGroupSyncError {
				return err
			}
		}
	}
	return nil
}

// addUserToChannels adds a user to all channels associated with a group
func (k *KeycloakClient) addUserToChannels(channelsToJoin map[string]mmModel.GroupSyncable, user *mmModel.User) {
	for channelID := range channelsToJoin {
		// Check if they are a member of the team
		member, err := k.PluginAPI.Channel.GetMember(channelID, user.Id)
		if err != nil {
			// check if the error is because the user was not found
			if strings.ToLower(err.Error()) != "not found" {
				k.PluginAPI.Log.Error("Failed to add user to channel, unable to get channel member",
					"user_id", user.Id,
					"channel_id", channelID,
					"error", err)
				continue
			}
		}

		if member == nil {
			k.PluginAPI.Log.Debug("Adding user to channel", "channel_id", channelID, "user_id", user.Id)
			if _, err = k.PluginAPI.Channel.AddMember(channelID, user.Id); err != nil {
				k.PluginAPI.Log.Error("Failed to add user to channel",
					"user_id", user.Id,
					"channel_id", channelID,
					"error", err)
			}
		}
	}
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
		first := page
		if first != 0 {
			first = (page * perPage)
		}
		// Get groups page by page
		params := gocloak.GetGroupsParams{
			First: &first,
			Max:   &perPage,
		}
		result, err := k.executeWithRetry(ctx, func(reqCtx context.Context, t string) (interface{}, error) {
			return k.Client.GetGroups(reqCtx, t, k.Realm, params)
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
