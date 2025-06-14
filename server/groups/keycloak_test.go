package groups_test

import (
	"context"
	"testing"
	"time"

	"github.com/mattermost/mattermost-plugin-identity-groups-sync/server/groups"

	"github.com/Nerzal/gocloak/v13"
	"github.com/golang/mock/gomock"
	saml2 "github.com/mattermost/gosaml2"
	saml2Types "github.com/mattermost/gosaml2/types"
	mmModel "github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin/plugintest"
	"github.com/mattermost/mattermost/server/public/plugin/plugintest/mock"
	"github.com/mattermost/mattermost/server/public/pluginapi"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"

	"github.com/mattermost/mattermost-plugin-identity-groups-sync/server/groups/mocks"
	"github.com/mattermost/mattermost-plugin-identity-groups-sync/server/model"
	kvMocks "github.com/mattermost/mattermost-plugin-identity-groups-sync/server/store/kvstore/mocks"
)

func TestKeycloakClient_Authenticate(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockGoCloak := mocks.NewMockGoCloak(ctrl)
	mockKVStore := kvMocks.NewMockKVStore(ctrl)

	client := &groups.KeycloakClient{
		Client:       mockGoCloak,
		Realm:        "test-realm",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Kvstore:      mockKVStore,
		PluginAPI:    &pluginapi.Client{},
	}

	t.Run("successful authentication", func(t *testing.T) {
		mockGoCloak.EXPECT().
			LoginClient(
				gomock.Any(),
				"test-client",
				"test-secret",
				"test-realm",
				gomock.Any(),
			).
			Return(&gocloak.JWT{
				AccessToken:      "test-token",
				ExpiresIn:        300,
				RefreshToken:     "refresh-token",
				RefreshExpiresIn: 1800,
			}, nil)

		mockKVStore.EXPECT().
			StoreKeycloakJWT(gomock.Any()).
			Return(nil)

		token, err := client.Authenticate(context.Background())
		assert.NoError(t, err)
		assert.Equal(t, "test-token", token)
	})

	t.Run("login failure", func(t *testing.T) {
		mockGoCloak.EXPECT().
			LoginClient(
				gomock.Any(),
				"test-client",
				"test-secret",
				"test-realm",
				gomock.Any(),
			).
			Return(nil, errors.New("login failed"))

		token, err := client.Authenticate(context.Background())
		assert.Error(t, err)
		assert.Empty(t, token)
		assert.Contains(t, err.Error(), "failed to authenticate client")
	})

	t.Run("store failure", func(t *testing.T) {
		mockGoCloak.EXPECT().
			LoginClient(
				gomock.Any(),
				"test-client",
				"test-secret",
				"test-realm",
				gomock.Any(),
			).
			Return(&gocloak.JWT{
				AccessToken:      "test-token",
				ExpiresIn:        300,
				RefreshToken:     "refresh-token",
				RefreshExpiresIn: 1800,
			}, nil)

		mockKVStore.EXPECT().
			StoreKeycloakJWT(gomock.Any()).
			Return(errors.New("store failed"))

		token, err := client.Authenticate(context.Background())
		assert.Error(t, err)
		assert.Empty(t, token)
		assert.Contains(t, err.Error(), "failed to store jwt")
	})
}

func TestKeycloakClient_GetGroups(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockGoCloak := mocks.NewMockGoCloak(ctrl)
	mockKVStore := kvMocks.NewMockKVStore(ctrl)

	client := &groups.KeycloakClient{
		Client:       mockGoCloak,
		Realm:        "test-realm",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Kvstore:      mockKVStore,
		PluginAPI:    &pluginapi.Client{},
	}

	t.Run("successful groups retrieval", func(t *testing.T) {
		validToken := &model.JWT{
			AccessToken:               "valid-token",
			AccessTokenExpirationTime: time.Now().Add(1 * time.Hour).UnixMilli(),
		}

		mockKVStore.EXPECT().
			GetKeycloakJWT().
			Return(validToken, nil)

		name := "Test Group"
		id := "test-id"
		mockGoCloak.EXPECT().
			GetGroups(
				gomock.Any(),
				"valid-token",
				"test-realm",
				gomock.Any(),
			).
			Return([]*gocloak.Group{
				{
					Name: &name,
					ID:   &id,
				},
			}, nil)

		groups, err := client.GetGroups(context.Background(), groups.Query{Page: 0, PerPage: 100})
		assert.NoError(t, err)
		assert.Len(t, groups, 1)
		assert.Equal(t, name, groups[0].DisplayName)
		assert.Equal(t, &id, groups[0].RemoteId)
		assert.Equal(t, client.GetGroupSource(), groups[0].Source)
	})

	t.Run("successful roles retrieval", func(t *testing.T) {
		// Test roles mapping type
		client.MappingType = "roles"

		validToken := &model.JWT{
			AccessToken:               "valid-token",
			AccessTokenExpirationTime: time.Now().Add(1 * time.Hour).UnixMilli(),
		}

		mockKVStore.EXPECT().
			GetKeycloakJWT().
			Return(validToken, nil)

		name := "Test Role"
		id := "test-role-id"
		mockGoCloak.EXPECT().
			GetRealmRoles(
				gomock.Any(),
				"valid-token",
				"test-realm",
				gomock.Any(),
			).
			Return([]*gocloak.Role{
				{
					Name: &name,
					ID:   &id,
				},
			}, nil)

		groups, err := client.GetGroups(context.Background(), groups.Query{Page: 0, PerPage: 100})
		assert.NoError(t, err)
		assert.Len(t, groups, 1)
		assert.Equal(t, name, groups[0].DisplayName)
		assert.Equal(t, &id, groups[0].RemoteId)
		assert.Equal(t, client.GetGroupSource(), groups[0].Source)
	})

	t.Run("token refresh needed", func(t *testing.T) {
		// Reset to groups mapping type
		client.MappingType = "groups"
		expiredToken := &model.JWT{
			AccessToken:                "expired-token",
			AccessTokenExpirationTime:  time.Now().Add(-1 * time.Hour).UnixMilli(),
			RefreshToken:               "refresh-token",
			RefreshTokenExpirationTime: time.Now().Add(1 * time.Hour).UnixMilli(),
		}

		mockKVStore.EXPECT().
			GetKeycloakJWT().
			Return(expiredToken, nil)

		mockGoCloak.EXPECT().
			RefreshToken(
				gomock.Any(),
				"refresh-token",
				"test-client",
				"test-secret",
				"test-realm",
			).
			Return(&gocloak.JWT{
				AccessToken:      "new-token",
				ExpiresIn:        300,
				RefreshToken:     "new-refresh-token",
				RefreshExpiresIn: 1800,
			}, nil)

		mockKVStore.EXPECT().
			StoreKeycloakJWT(gomock.Any()).
			Return(nil)

		name := "Test Group"
		id := "test-id"
		mockGoCloak.EXPECT().
			GetGroups(
				gomock.Any(),
				"new-token",
				"test-realm",
				gomock.Any(),
			).
			Return([]*gocloak.Group{
				{
					Name: &name,
					ID:   &id,
				},
			}, nil)

		groups, err := client.GetGroups(context.Background(), groups.Query{Page: 0, PerPage: 100})
		assert.NoError(t, err)
		assert.Len(t, groups, 1)
	})
}

func TestKeycloakClient_GetGroupsCount(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockGoCloak := mocks.NewMockGoCloak(ctrl)
	mockKVStore := kvMocks.NewMockKVStore(ctrl)

	client := &groups.KeycloakClient{
		Client:       mockGoCloak,
		Realm:        "test-realm",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Kvstore:      mockKVStore,
		PluginAPI:    &pluginapi.Client{},
	}

	t.Run("successful count retrieval", func(t *testing.T) {
		validToken := &model.JWT{
			AccessToken:               "valid-token",
			AccessTokenExpirationTime: time.Now().Add(1 * time.Hour).UnixMilli(),
		}

		mockKVStore.EXPECT().
			GetKeycloakJWT().
			Return(validToken, nil)

		mockGoCloak.EXPECT().
			GetGroupsCount(
				gomock.Any(),
				"valid-token",
				"test-realm",
				gomock.Any(),
			).
			Return(42, nil)

		count, err := client.GetGroupsCount(context.Background(), "")
		assert.NoError(t, err)
		assert.Equal(t, 42, count)
	})
}

func TestKeycloakClient_GetGroup(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockGoCloak := mocks.NewMockGoCloak(ctrl)
	mockKVStore := kvMocks.NewMockKVStore(ctrl)

	client := &groups.KeycloakClient{
		Client:       mockGoCloak,
		Realm:        "test-realm",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Kvstore:      mockKVStore,
		PluginAPI:    &pluginapi.Client{},
	}

	t.Run("successful group retrieval", func(t *testing.T) {
		validToken := &model.JWT{
			AccessToken:               "valid-token",
			AccessTokenExpirationTime: time.Now().Add(1 * time.Hour).UnixMilli(),
		}

		mockKVStore.EXPECT().
			GetKeycloakJWT().
			Return(validToken, nil)

		name := "Test Group"
		id := "test-id"
		mockGoCloak.EXPECT().
			GetGroup(
				gomock.Any(),
				"valid-token",
				"test-realm",
				"test-id",
			).
			Return(&gocloak.Group{
				Name: &name,
				ID:   &id,
			}, nil)

		group, err := client.GetGroup(context.Background(), "test-id")
		assert.NoError(t, err)
		assert.Equal(t, name, group.DisplayName)
		assert.Equal(t, &id, group.RemoteId)
		assert.Equal(t, client.GetGroupSource(), group.Source)
	})

	t.Run("successful role retrieval", func(t *testing.T) {
		// Test roles mapping type
		client.MappingType = "roles"

		validToken := &model.JWT{
			AccessToken:               "valid-token",
			AccessTokenExpirationTime: time.Now().Add(1 * time.Hour).UnixMilli(),
		}

		mockKVStore.EXPECT().
			GetKeycloakJWT().
			Return(validToken, nil)

		name := "Test Role"
		id := "test-role-id"
		mockGoCloak.EXPECT().
			GetRealmRoleByID(
				gomock.Any(),
				"valid-token",
				"test-realm",
				"test-role-id",
			).
			Return(&gocloak.Role{
				Name: &name,
				ID:   &id,
			}, nil)

		group, err := client.GetGroup(context.Background(), "test-role-id")
		assert.NoError(t, err)
		assert.Equal(t, name, group.DisplayName)
		assert.Equal(t, &id, group.RemoteId)
		assert.Equal(t, client.GetGroupSource(), group.Source)
	})
}

func TestKeycloakClient_GetGroupMembers(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockGoCloak := mocks.NewMockGoCloak(ctrl)
	mockKVStore := kvMocks.NewMockKVStore(ctrl)

	client := &groups.KeycloakClient{
		Client:       mockGoCloak,
		Realm:        "test-realm",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Kvstore:      mockKVStore,
		PluginAPI:    &pluginapi.Client{},
	}

	t.Run("successful members retrieval", func(t *testing.T) {
		validToken := &model.JWT{
			AccessToken:               "valid-token",
			AccessTokenExpirationTime: time.Now().Add(1 * time.Hour).UnixMilli(),
		}

		mockKVStore.EXPECT().
			GetKeycloakJWT().
			Return(validToken, nil)

		username := "testuser"
		mockGoCloak.EXPECT().
			GetGroupMembers(
				gomock.Any(),
				"valid-token",
				"test-realm",
				"test-group-id",
				gomock.Any(),
			).
			Return([]*gocloak.User{
				{
					Username: &username,
				},
			}, nil)

		members, err := client.GetGroupMembers(context.Background(), "test-group-id")
		assert.NoError(t, err)
		assert.Len(t, members, 1)
		assert.Equal(t, username, *members[0].Username)
	})
}

func TestKeycloakClient_HandleSAMLLogin(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockGoCloak := mocks.NewMockGoCloak(ctrl)
	mockKVStore := kvMocks.NewMockKVStore(ctrl)
	api := &plugintest.API{}

	client := &groups.KeycloakClient{
		Client:                    mockGoCloak,
		Realm:                     "test-realm",
		ClientID:                  "test-client",
		ClientSecret:              "test-secret",
		Kvstore:                   mockKVStore,
		PluginAPI:                 pluginapi.NewClient(api, nil),
		FailLoginOnGroupSyncError: true,
	}

	t.Run("empty groups attribute", func(t *testing.T) {
		// Mock logging
		api.On("LogDebug", "Groups attribute not configured, skipping group sync").Return()

		err := client.HandleSAMLLogin(nil, &mmModel.User{}, nil, "")
		assert.NoError(t, err)

		api.AssertExpectations(t)
	})

	t.Run("cleanup existing groups when SAML has no groups", func(t *testing.T) {
		// Reset the mock
		api = &plugintest.API{}
		client.PluginAPI = pluginapi.NewClient(api, nil)

		api.On("LogDebug", "No groups found in SAML assertion").Return()

		// Mock GetGroups to return existing groups
		api.On("GetGroups", 0, 100, mmModel.GroupSearchOpts{
			Source:          mmModel.GroupSourcePluginPrefix + "keycloak",
			FilterHasMember: "user1",
			IncludeArchived: true,
		}, (*mmModel.ViewUsersRestrictions)(nil)).Return([]*mmModel.Group{
			{Id: "group1", DisplayName: "Group 1"},
			{Id: "group2", DisplayName: "Group 2"},
		}, nil)

		// Mock group deletion
		api.On("DeleteGroupMember", "group1", "user1").Return(nil, nil)
		api.On("DeleteGroupMember", "group2", "user1").Return(nil, nil)

		// Mock team syncables
		api.On("GetGroupSyncables", "group1", mmModel.GroupSyncableTypeTeam).Return([]*mmModel.GroupSyncable{
			{GroupId: "group1", SyncableId: "team1", AutoAdd: true},
		}, nil)
		api.On("GetGroupSyncables", "group2", mmModel.GroupSyncableTypeTeam).Return([]*mmModel.GroupSyncable{}, nil)
		api.On("GetTeam", "team1").Return(&mmModel.Team{Id: "team1", GroupConstrained: mmModel.NewPointer(true)}, nil)
		api.On("GetTeamMember", "team1", "user1").Return(&mmModel.TeamMember{TeamId: "team1", DeleteAt: 0}, nil)
		api.On("DeleteTeamMember", "team1", "user1", "").Return(nil)
		api.On("LogDebug", "Removing user from team", "team_id", "team1", "user_id", "user1").Return()

		// Mock channel syncables
		api.On("GetGroupSyncables", "group1", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{
			{GroupId: "group1", SyncableId: "channel1", AutoAdd: true},
		}, nil)
		api.On("GetGroupSyncables", "group2", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{}, nil)
		api.On("GetChannelMember", "channel1", "user1").Return(&mmModel.ChannelMember{ChannelId: "channel1"}, nil)
		api.On("DeleteChannelMember", "channel1", "user1").Return(nil)
		api.On("LogDebug", "Removing user from channel", "channel_id", "channel1", "user_id", "user1").Return()

		err := client.HandleSAMLLogin(nil, &mmModel.User{Id: "user1"}, &saml2.AssertionInfo{
			Assertions: []saml2Types.Assertion{
				{
					AttributeStatement: &saml2Types.AttributeStatement{
						Attributes: []saml2Types.Attribute{
							{
								Name:   "groups",
								Values: []saml2Types.AttributeValue{},
							},
						},
					},
				},
			},
		}, "groups")
		assert.NoError(t, err)
		api.AssertExpectations(t)
	})

	t.Run("group exists in SAML but not in KVStore", func(t *testing.T) {
		// Reset the mock
		api = &plugintest.API{}
		client.PluginAPI = pluginapi.NewClient(api, nil)

		// Mock GetKeycloakGroupID to return error (not found)
		mockKVStore.EXPECT().
			GetKeycloakGroupID("newgroup").
			Return("", errors.New("not found"))

		// Mock GetJWT to return a valid token
		validToken := &model.JWT{
			AccessToken:               "valid-token",
			AccessTokenExpirationTime: time.Now().Add(1 * time.Hour).UnixMilli(),
		}

		mockKVStore.EXPECT().
			GetKeycloakJWT().
			Return(validToken, nil)

		// Mock GetGroupByPath success
		groupID := "remote-id-1"
		groupName := "newgroup"
		mockGoCloak.EXPECT().
			GetGroupByPath(gomock.Any(), "valid-token", "test-realm", "/newgroup").
			Return(&gocloak.Group{
				ID:   &groupID,
				Name: &groupName,
			}, nil)

		// Mock StoreGroupID success
		mockKVStore.EXPECT().
			StoreKeycloakGroupID("newgroup", "remote-id-1").
			Return(nil)

		// Mock GetGroupByRemoteID
		api.On("GetGroupByRemoteID", "remote-id-1", mmModel.GroupSourcePluginPrefix+"keycloak").Return(&mmModel.Group{
			Id: "mm-group-1",
		}, nil)

		// Mock GetGroups for existing memberships
		api.On("GetGroups", 0, 100, mmModel.GroupSearchOpts{
			Source:          mmModel.GroupSourcePluginPrefix + "keycloak",
			FilterHasMember: "user1",
			IncludeArchived: true,
		}, (*mmModel.ViewUsersRestrictions)(nil)).Return([]*mmModel.Group{}, nil)

		// Mock group membership operations
		api.On("UpsertGroupMember", "mm-group-1", "user1").Return(nil, nil)

		// Mock GetGroupSyncables
		api.On("GetGroupSyncables", "mm-group-1", mmModel.GroupSyncableTypeTeam).Return([]*mmModel.GroupSyncable{}, nil)
		api.On("GetGroupSyncables", "mm-group-1", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{}, nil)

		err := client.HandleSAMLLogin(nil, &mmModel.User{Id: "user1"}, &saml2.AssertionInfo{
			Assertions: []saml2Types.Assertion{
				{
					AttributeStatement: &saml2Types.AttributeStatement{
						Attributes: []saml2Types.Attribute{
							{
								Name: "groups",
								Values: []saml2Types.AttributeValue{
									{Value: "newgroup"},
								},
							},
						},
					},
				},
			},
		}, "groups")
		assert.NoError(t, err)
		api.AssertExpectations(t)
	})

	t.Run("GetGroupByPath fails", func(t *testing.T) {
		// Reset the mock
		api = &plugintest.API{}
		client.PluginAPI = pluginapi.NewClient(api, nil)

		// Mock GetKeycloakGroupID to return error (not found)
		mockKVStore.EXPECT().
			GetKeycloakGroupID("newgroup").
			Return("", errors.New("not found"))

		// Mock GetJWT to return a valid token
		validToken := &model.JWT{
			AccessToken:               "valid-token",
			AccessTokenExpirationTime: time.Now().Add(1 * time.Hour).UnixMilli(),
		}

		mockKVStore.EXPECT().
			GetKeycloakJWT().
			Return(validToken, nil)

		// Mock GetGroupByPath failure
		mockGoCloak.EXPECT().
			GetGroupByPath(gomock.Any(), gomock.Any(), "test-realm", "/newgroup").
			Return(nil, errors.New("failed to get group"))

		// Mock logging
		api.On("LogError", "Failed to get group by path", "group", "newgroup", "error", mock.Anything).Return()

		// Mock GetGroups for existing memberships
		api.On("GetGroups", 0, 100, mmModel.GroupSearchOpts{
			Source:          mmModel.GroupSourcePluginPrefix + "keycloak",
			FilterHasMember: "user1",
			IncludeArchived: true,
		}, (*mmModel.ViewUsersRestrictions)(nil)).Return([]*mmModel.Group{}, nil)

		err := client.HandleSAMLLogin(nil, &mmModel.User{Id: "user1"}, &saml2.AssertionInfo{
			Assertions: []saml2Types.Assertion{
				{
					AttributeStatement: &saml2Types.AttributeStatement{
						Attributes: []saml2Types.Attribute{
							{
								Name: "groups",
								Values: []saml2Types.AttributeValue{
									{Value: "newgroup"},
								},
							},
						},
					},
				},
			},
		}, "groups")
		assert.NoError(t, err)
		api.AssertExpectations(t)
	})

	t.Run("StoreGroupID fails", func(t *testing.T) {
		// Reset the mock
		api = &plugintest.API{}
		client.PluginAPI = pluginapi.NewClient(api, nil)

		// Mock GetKeycloakGroupID to return error (not found)
		mockKVStore.EXPECT().
			GetKeycloakGroupID("newgroup").
			Return("", errors.New("not found"))

		// Mock GetJWT to return a valid token
		validToken := &model.JWT{
			AccessToken:               "valid-token",
			AccessTokenExpirationTime: time.Now().Add(1 * time.Hour).UnixMilli(),
		}

		mockKVStore.EXPECT().
			GetKeycloakJWT().
			Return(validToken, nil)

		// Mock GetGroupByPath success
		groupID := "remote-id-1"
		groupName := "newgroup"
		mockGoCloak.EXPECT().
			GetGroupByPath(gomock.Any(), gomock.Any(), "test-realm", "/newgroup").
			Return(&gocloak.Group{
				ID:   &groupID,
				Name: &groupName,
			}, nil)

		// Mock StoreGroupID failure
		mockKVStore.EXPECT().
			StoreKeycloakGroupID("newgroup", "remote-id-1").
			Return(errors.New("failed to store"))

		// Mock logging
		api.On("LogWarn", "Failed to store group mapping", "group", "newgroup", "error", mock.Anything).Return()

		api.On("GetGroupByRemoteID", "remote-id-1", mmModel.GroupSourcePluginPrefix+"keycloak").Return(&mmModel.Group{}, &mmModel.AppError{Message: "not found"})
		api.On("LogDebug", "Keycloak group hasn't been linked to Mattermost yet", "remote_id", "remote-id-1", "name", "newgroup").Return()

		// Mock GetGroups for existing memberships
		api.On("GetGroups", 0, 100, mmModel.GroupSearchOpts{
			Source:          mmModel.GroupSourcePluginPrefix + "keycloak",
			FilterHasMember: "user1",
			IncludeArchived: true,
		}, (*mmModel.ViewUsersRestrictions)(nil)).Return([]*mmModel.Group{}, nil)

		err := client.HandleSAMLLogin(nil, &mmModel.User{Id: "user1"}, &saml2.AssertionInfo{
			Assertions: []saml2Types.Assertion{
				{
					AttributeStatement: &saml2Types.AttributeStatement{
						Attributes: []saml2Types.Attribute{
							{
								Name: "groups",
								Values: []saml2Types.AttributeValue{
									{Value: "newgroup"},
								},
							},
						},
					},
				},
			},
		}, "groups")
		assert.NoError(t, err)
		api.AssertExpectations(t)
	})

	t.Run("mixed group scenario - add, remove and remain", func(t *testing.T) {
		// Reset the mock
		api = &plugintest.API{}
		client.PluginAPI = pluginapi.NewClient(api, nil)

		// Mock GetKeycloakGroupID calls
		mockKVStore.EXPECT().
			GetKeycloakGroupID("group1").
			Return("remote-id-1", nil)
		mockKVStore.EXPECT().
			GetKeycloakGroupID("group2").
			Return("remote-id-2", nil)

		// Mock GetGroupByRemoteID
		api.On("GetGroupByRemoteID", "remote-id-1", mmModel.GroupSourcePluginPrefix+"keycloak").Return(&mmModel.Group{
			Id: "mm-group-1",
		}, nil)
		api.On("GetGroupByRemoteID", "remote-id-2", mmModel.GroupSourcePluginPrefix+"keycloak").Return(&mmModel.Group{
			Id: "mm-group-2",
		}, nil)

		// Mock GetGroups to return existing memberships (group1 and group3)
		api.On("GetGroups", 0, 100, mmModel.GroupSearchOpts{
			Source:          mmModel.GroupSourcePluginPrefix + "keycloak",
			FilterHasMember: "user1",
			IncludeArchived: true,
		}, (*mmModel.ViewUsersRestrictions)(nil)).Return([]*mmModel.Group{
			{Id: "mm-group-1", DisplayName: "Group 1"}, // Will remain
			{Id: "mm-group-3", DisplayName: "Group 3"}, // Will be removed
		}, nil)

		// Mock group membership operations
		api.On("DeleteGroupMember", "mm-group-3", "user1").Return(nil, nil) // Remove from group3
		api.On("UpsertGroupMember", "mm-group-2", "user1").Return(nil, nil) // Add to group2

		// Mock GetGroupSyncables for all groups
		api.On("GetGroupSyncables", "mm-group-1", mmModel.GroupSyncableTypeTeam).Return([]*mmModel.GroupSyncable{}, nil)
		api.On("GetGroupSyncables", "mm-group-1", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{}, nil)
		api.On("GetGroupSyncables", "mm-group-2", mmModel.GroupSyncableTypeTeam).Return([]*mmModel.GroupSyncable{}, nil)
		api.On("GetGroupSyncables", "mm-group-2", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{}, nil)
		api.On("GetGroupSyncables", "mm-group-3", mmModel.GroupSyncableTypeTeam).Return([]*mmModel.GroupSyncable{
			{
				GroupId:    "mm-group-3",
				SyncableId: "team1",
				AutoAdd:    false,
			},
			{
				GroupId:    "mm-group-3",
				SyncableId: "team2",
				AutoAdd:    true,
			},
		}, nil)
		api.On("GetGroupSyncables", "mm-group-3", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{
			{
				GroupId:    "mm-group-1",
				SyncableId: "channel1",
				AutoAdd:    true,
			},
		}, nil)

		// Mock team/channel member removal
		api.On("GetTeam", "team1").Return(&mmModel.Team{Id: "team1", GroupConstrained: mmModel.NewPointer(true)}, nil)
		api.On("GetTeamMember", "team1", "user1").Return(&mmModel.TeamMember{TeamId: "team1", DeleteAt: 0}, nil)
		// Return non Group contrained team for team2, user should not be removed from it
		api.On("GetTeam", "team2").Return(&mmModel.Team{Id: "team2", GroupConstrained: nil}, nil)
		api.On("DeleteTeamMember", "team1", "user1", "").Return(nil)
		api.On("LogDebug", "Removing user from team", "team_id", "team1", "user_id", "user1").Return()
		api.On("GetChannelMember", "channel1", "user1").Return(&mmModel.ChannelMember{ChannelId: "channel1"}, nil)
		api.On("DeleteChannelMember", "channel1", "user1").Return(nil)
		api.On("LogDebug", "Removing user from channel", "channel_id", "channel1", "user_id", "user1").Return()

		err := client.HandleSAMLLogin(nil, &mmModel.User{Id: "user1"}, &saml2.AssertionInfo{
			Assertions: []saml2Types.Assertion{
				{
					AttributeStatement: &saml2Types.AttributeStatement{
						Attributes: []saml2Types.Attribute{
							{
								Name: "groups",
								Values: []saml2Types.AttributeValue{
									{Value: "group1"}, // Will remain
									{Value: "group2"}, // Will be added
								},
							},
						},
					},
				},
			},
		}, "groups")
		assert.NoError(t, err)
		api.AssertExpectations(t)
	})

	t.Run("role exists in SAML but not in KVStore (roles mapping)", func(t *testing.T) {
		// Reset the mock
		api = &plugintest.API{}
		client.PluginAPI = pluginapi.NewClient(api, nil)
		client.MappingType = "roles"

		// Mock GetKeycloakGroupID to return error (not found)
		mockKVStore.EXPECT().
			GetKeycloakGroupID("admin").
			Return("", errors.New("not found"))

		// Mock GetJWT to return a valid token
		validToken := &model.JWT{
			AccessToken:               "valid-token",
			AccessTokenExpirationTime: time.Now().Add(1 * time.Hour).UnixMilli(),
		}

		mockKVStore.EXPECT().
			GetKeycloakJWT().
			Return(validToken, nil)

		// Mock GetRealmRole success
		roleID := "role-remote-id-1"
		roleName := "admin"
		mockGoCloak.EXPECT().
			GetRealmRole(gomock.Any(), "valid-token", "test-realm", "admin").
			Return(&gocloak.Role{
				ID:   &roleID,
				Name: &roleName,
			}, nil)

		// Mock StoreGroupID success
		mockKVStore.EXPECT().
			StoreKeycloakGroupID("admin", "role-remote-id-1").
			Return(nil)

		// Mock GetGroupByRemoteID
		api.On("GetGroupByRemoteID", "role-remote-id-1", mmModel.GroupSourcePluginPrefix+"keycloak").Return(&mmModel.Group{
			Id: "mm-group-1",
		}, nil)

		// Mock GetGroups for existing memberships
		api.On("GetGroups", 0, 100, mmModel.GroupSearchOpts{
			Source:          mmModel.GroupSourcePluginPrefix + "keycloak",
			FilterHasMember: "user1",
			IncludeArchived: true,
		}, (*mmModel.ViewUsersRestrictions)(nil)).Return([]*mmModel.Group{}, nil)

		// Mock group membership operations
		api.On("UpsertGroupMember", "mm-group-1", "user1").Return(nil, nil)

		// Mock GetGroupSyncables
		api.On("GetGroupSyncables", "mm-group-1", mmModel.GroupSyncableTypeTeam).Return([]*mmModel.GroupSyncable{}, nil)
		api.On("GetGroupSyncables", "mm-group-1", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{}, nil)

		err := client.HandleSAMLLogin(nil, &mmModel.User{Id: "user1"}, &saml2.AssertionInfo{
			Assertions: []saml2Types.Assertion{
				{
					AttributeStatement: &saml2Types.AttributeStatement{
						Attributes: []saml2Types.Attribute{
							{
								Name: "roles",
								Values: []saml2Types.AttributeValue{
									{Value: "admin"},
								},
							},
						},
					},
				},
			},
		}, "roles")
		assert.NoError(t, err)
		api.AssertExpectations(t)
	})

	t.Run("mixed role scenario with additions and removals (roles mapping)", func(t *testing.T) {
		// Reset the mock
		api = &plugintest.API{}
		client.PluginAPI = pluginapi.NewClient(api, nil)
		client.MappingType = "roles"

		// Mock GetKeycloakGroupID calls for roles in SAML assertion
		mockKVStore.EXPECT().
			GetKeycloakGroupID("admin").
			Return("role-admin-id", nil)
		mockKVStore.EXPECT().
			GetKeycloakGroupID("developer").
			Return("role-developer-id", nil)

		// Mock GetGroupByRemoteID for roles in SAML assertion
		api.On("GetGroupByRemoteID", "role-admin-id", mmModel.GroupSourcePluginPrefix+"keycloak").Return(&mmModel.Group{
			Id: "mm-admin-group",
		}, nil)
		api.On("GetGroupByRemoteID", "role-developer-id", mmModel.GroupSourcePluginPrefix+"keycloak").Return(&mmModel.Group{
			Id: "mm-developer-group",
		}, nil)

		// Mock GetGroups for existing memberships (user currently has "manager" and "admin" roles)
		api.On("GetGroups", 0, 100, mmModel.GroupSearchOpts{
			Source:          mmModel.GroupSourcePluginPrefix + "keycloak",
			FilterHasMember: "user1",
			IncludeArchived: true,
		}, (*mmModel.ViewUsersRestrictions)(nil)).Return([]*mmModel.Group{
			{Id: "mm-manager-group", DisplayName: "Manager"},
			{Id: "mm-admin-group", DisplayName: "Admin"},
		}, nil)

		// Mock syncables for group being removed (manager)
		api.On("GetGroupSyncables", "mm-manager-group", mmModel.GroupSyncableTypeTeam).Return([]*mmModel.GroupSyncable{
			{GroupId: "mm-manager-group", SyncableId: "team1", AutoAdd: true},
		}, nil)
		api.On("GetGroupSyncables", "mm-manager-group", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{
			{GroupId: "mm-manager-group", SyncableId: "channel1", AutoAdd: true},
		}, nil)

		// Mock syncables for group being retained (admin)
		api.On("GetGroupSyncables", "mm-admin-group", mmModel.GroupSyncableTypeTeam).Return([]*mmModel.GroupSyncable{
			{GroupId: "mm-admin-group", SyncableId: "team2", AutoAdd: true},
		}, nil)
		api.On("GetGroupSyncables", "mm-admin-group", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{
			{GroupId: "mm-admin-group", SyncableId: "channel2", AutoAdd: true},
		}, nil)

		// Mock team operations for removal
		api.On("GetTeam", "team1").Return(&mmModel.Team{Id: "team1", GroupConstrained: mmModel.NewPointer(true)}, nil)
		api.On("GetTeamMember", "team1", "user1").Return(&mmModel.TeamMember{TeamId: "team1", DeleteAt: 0}, nil)
		api.On("DeleteTeamMember", "team1", "user1", "").Return(nil)
		api.On("LogDebug", "Removing user from team", "team_id", "team1", "user_id", "user1").Return()

		// Mock channel operations for removal
		api.On("GetChannelMember", "channel1", "user1").Return(&mmModel.ChannelMember{ChannelId: "channel1"}, nil)
		api.On("DeleteChannelMember", "channel1", "user1").Return(nil)
		api.On("LogDebug", "Removing user from channel", "channel_id", "channel1", "user_id", "user1").Return()

		// Mock group removal
		api.On("DeleteGroupMember", "mm-manager-group", "user1").Return(nil, nil)

		// Mock group addition for new role (developer)
		api.On("UpsertGroupMember", "mm-developer-group", "user1").Return(nil, nil)

		// Mock syncables for new group (developer)
		api.On("GetGroupSyncables", "mm-developer-group", mmModel.GroupSyncableTypeTeam).Return([]*mmModel.GroupSyncable{
			{GroupId: "mm-developer-group", SyncableId: "team3", AutoAdd: true},
		}, nil)
		api.On("GetGroupSyncables", "mm-developer-group", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{
			{GroupId: "mm-developer-group", SyncableId: "channel3", AutoAdd: true},
		}, nil)

		// Mock team operations for addition
		api.On("GetTeamMember", "team2", "user1").Return(&mmModel.TeamMember{TeamId: "team2", DeleteAt: 0}, nil) // Already member
		api.On("GetTeamMember", "team3", "user1").Return(nil, &mmModel.AppError{Message: "not found"})
		api.On("CreateTeamMember", "team3", "user1").Return(&mmModel.TeamMember{}, nil)
		api.On("LogDebug", "Adding user to team", "team_id", "team3", "user_id", "user1").Return()

		// Mock channel operations for addition
		api.On("GetChannelMember", "channel2", "user1").Return(&mmModel.ChannelMember{ChannelId: "channel2"}, nil) // Already member
		api.On("GetChannelMember", "channel3", "user1").Return(nil, &mmModel.AppError{Message: "not found"})
		api.On("AddChannelMember", "channel3", "user1").Return(&mmModel.ChannelMember{}, nil)
		api.On("LogDebug", "Adding user to channel", "channel_id", "channel3", "user_id", "user1").Return()

		err := client.HandleSAMLLogin(nil, &mmModel.User{Id: "user1"}, &saml2.AssertionInfo{
			Assertions: []saml2Types.Assertion{
				{
					AttributeStatement: &saml2Types.AttributeStatement{
						Attributes: []saml2Types.Attribute{
							{
								Name: "roles",
								Values: []saml2Types.AttributeValue{
									{Value: "admin"},     // Keep this role
									{Value: "developer"}, // Add this role
									// "manager" role removed (was in existing memberships)
								},
							},
						},
					},
				},
			},
		}, "roles")
		assert.NoError(t, err)
		api.AssertExpectations(t)
	})

	t.Run("GetGroupByRemoteID fails with a timeout", func(t *testing.T) {
		// Reset the mock
		api = &plugintest.API{}
		client.PluginAPI = pluginapi.NewClient(api, nil)
		client.MappingType = "groups" // Reset to groups

		// Mock GetKeycloakGroupID
		mockKVStore.EXPECT().
			GetKeycloakGroupID("group1").
			Return("remote-id-1", nil)

		// Mock GetGroupByRemoteID failure
		api.On("GetGroupByRemoteID", "remote-id-1", mmModel.GroupSourcePluginPrefix+"keycloak").Return(nil, &mmModel.AppError{Message: "failed to get groups", StatusCode: 504})

		// Mock logging
		api.On("LogError", "Failed to get Mattermost group by remote ID", "remote_id", "remote-id-1", "name", "group1", "error", mock.Anything).Return()

		err := client.HandleSAMLLogin(nil, &mmModel.User{Id: "user1"}, &saml2.AssertionInfo{
			Assertions: []saml2Types.Assertion{
				{
					AttributeStatement: &saml2Types.AttributeStatement{
						Attributes: []saml2Types.Attribute{
							{
								Name: "groups",
								Values: []saml2Types.AttributeValue{
									{Value: "group1"},
								},
							},
						},
					},
				},
			},
		}, "groups")

		// GetGroupByRemoteID returns an error if it fails with anything other than "not found"
		assert.Error(t, err)
		api.AssertExpectations(t)
	})

	t.Run("groups in assertion", func(t *testing.T) {
		// Reset the mock
		api = &plugintest.API{}
		client.PluginAPI = pluginapi.NewClient(api, nil)

		// Mock GetKeycloakGroupID calls
		mockKVStore.EXPECT().
			GetKeycloakGroupID("group1").
			Return("remote-id-1", nil).
			Times(1)
		mockKVStore.EXPECT().
			GetKeycloakGroupID("group2").
			Return("remote-id-2", nil).
			Times(1)

		// Mock GetGroupByRemoteID
		api.On("GetGroupByRemoteID", "remote-id-1", mmModel.GroupSourcePluginPrefix+"keycloak").Return(&mmModel.Group{
			Id: "mm-group-1",
		}, nil)
		api.On("GetGroupByRemoteID", "remote-id-2", mmModel.GroupSourcePluginPrefix+"keycloak").Return(&mmModel.Group{
			Id: "mm-group-2",
		}, nil)

		// Mock GetGroups for existing memberships
		api.On("GetGroups", 0, 100, mmModel.GroupSearchOpts{
			Source:          mmModel.GroupSourcePluginPrefix + "keycloak",
			FilterHasMember: "user1",
			IncludeArchived: true,
		}, (*mmModel.ViewUsersRestrictions)(nil)).Return([]*mmModel.Group{}, nil)

		// Mock group membership operations
		api.On("UpsertGroupMember", "mm-group-1", "user1").Return(nil, nil)
		api.On("UpsertGroupMember", "mm-group-2", "user1").Return(nil, nil)

		// Mock GetGroupSyncables and member operations
		api.On("GetGroupSyncables", "mm-group-1", mmModel.GroupSyncableTypeTeam).Return([]*mmModel.GroupSyncable{}, nil)
		api.On("GetGroupSyncables", "mm-group-2", mmModel.GroupSyncableTypeTeam).Return([]*mmModel.GroupSyncable{}, nil)
		api.On("GetGroupSyncables", "mm-group-1", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{}, nil)
		api.On("GetGroupSyncables", "mm-group-2", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{}, nil)

		err := client.HandleSAMLLogin(nil, &mmModel.User{Id: "user1"}, &saml2.AssertionInfo{
			Assertions: []saml2Types.Assertion{
				{
					AttributeStatement: &saml2Types.AttributeStatement{
						Attributes: []saml2Types.Attribute{
							{
								Name: "groups",
								Values: []saml2Types.AttributeValue{
									{Value: "group1"},
									{Value: "group2"},
								},
							},
						},
					},
				},
			},
		}, "groups")
		assert.NoError(t, err)
		api.AssertExpectations(t)
	})

	t.Run("multiple teams with different AutoAdd settings", func(t *testing.T) {
		// Reset the mock
		api = &plugintest.API{}
		client.PluginAPI = pluginapi.NewClient(api, nil)

		// Mock GetKeycloakGroupID
		mockKVStore.EXPECT().
			GetKeycloakGroupID("group1").
			Return("remote-id-1", nil)

		// Mock GetGroupByRemoteID
		api.On("GetGroupByRemoteID", "remote-id-1", mmModel.GroupSourcePluginPrefix+"keycloak").Return(&mmModel.Group{
			Id: "mm-group-1",
		}, nil)

		// Mock GetGroups for existing memberships
		api.On("GetGroups", 0, 100, mmModel.GroupSearchOpts{
			Source:          mmModel.GroupSourcePluginPrefix + "keycloak",
			FilterHasMember: "user1",
			IncludeArchived: true,
		}, (*mmModel.ViewUsersRestrictions)(nil)).Return([]*mmModel.Group{}, nil)

		// Mock group membership operations
		api.On("UpsertGroupMember", "mm-group-1", "user1").Return(nil, nil)

		// Mock GetGroupSyncables to return multiple teams with different AutoAdd settings
		api.On("GetGroupSyncables", "mm-group-1", mmModel.GroupSyncableTypeTeam).Return([]*mmModel.GroupSyncable{
			{
				GroupId:    "mm-group-1",
				SyncableId: "team1",
				AutoAdd:    true,
			},
			{
				GroupId:    "mm-group-1",
				SyncableId: "team2",
				AutoAdd:    false,
			},
			{
				GroupId:    "mm-group-1",
				SyncableId: "team3",
				AutoAdd:    true,
			},
		}, nil)

		// Mock team member creation only for AutoAdd=true teams
		api.On("GetTeamMember", "team1", "user1").Return(nil, &mmModel.AppError{Message: "not found"})
		api.On("CreateTeamMember", "team1", "user1").Return(nil, nil)
		api.On("LogDebug", "Adding user to team", "team_id", "team1", "user_id", "user1").Return()
		api.On("GetTeamMember", "team3", "user1").Return(&mmModel.TeamMember{TeamId: "team1", DeleteAt: 1234}, nil)
		api.On("CreateTeamMember", "team3", "user1").Return(nil, nil)
		api.On("LogDebug", "Adding user to team", "team_id", "team3", "user_id", "user1").Return()

		// Mock GetGroupSyncables for channels (empty)
		api.On("GetGroupSyncables", "mm-group-1", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{}, nil)

		err := client.HandleSAMLLogin(nil, &mmModel.User{Id: "user1"}, &saml2.AssertionInfo{
			Assertions: []saml2Types.Assertion{
				{
					AttributeStatement: &saml2Types.AttributeStatement{
						Attributes: []saml2Types.Attribute{
							{
								Name: "groups",
								Values: []saml2Types.AttributeValue{
									{Value: "group1"},
								},
							},
						},
					},
				},
			},
		}, "groups")
		assert.NoError(t, err)
		api.AssertExpectations(t)
	})

	t.Run("multiple channels with different AutoAdd settings", func(t *testing.T) {
		// Reset the mock
		api = &plugintest.API{}
		client.PluginAPI = pluginapi.NewClient(api, nil)

		// Mock GetKeycloakGroupID
		mockKVStore.EXPECT().
			GetKeycloakGroupID("group1").
			Return("remote-id-1", nil)

		// Mock GetGroupByRemoteID
		api.On("GetGroupByRemoteID", "remote-id-1", mmModel.GroupSourcePluginPrefix+"keycloak").Return(&mmModel.Group{
			Id: "mm-group-1",
		}, nil)

		// Mock GetGroups for existing memberships
		api.On("GetGroups", 0, 100, mmModel.GroupSearchOpts{
			Source:          mmModel.GroupSourcePluginPrefix + "keycloak",
			FilterHasMember: "user1",
			IncludeArchived: true,
		}, (*mmModel.ViewUsersRestrictions)(nil)).Return([]*mmModel.Group{}, nil)

		// Mock group membership operations
		api.On("UpsertGroupMember", "mm-group-1", "user1").Return(nil, nil)

		// Mock GetGroupSyncables for teams (empty)
		api.On("GetGroupSyncables", "mm-group-1", mmModel.GroupSyncableTypeTeam).Return([]*mmModel.GroupSyncable{}, nil)

		// Mock GetGroupSyncables to return multiple channels with different AutoAdd settings
		api.On("GetGroupSyncables", "mm-group-1", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{
			{
				GroupId:    "mm-group-1",
				SyncableId: "channel1",
				AutoAdd:    true,
			},
			{
				GroupId:    "mm-group-1",
				SyncableId: "channel2",
				AutoAdd:    false,
			},
			{
				GroupId:    "mm-group-1",
				SyncableId: "channel3",
				AutoAdd:    true,
			},
		}, nil)

		// Mock channel member creation only for AutoAdd=true channels
		api.On("GetChannelMember", "channel1", "user1").Return(nil, &mmModel.AppError{Message: "not found"})
		api.On("AddChannelMember", "channel1", "user1").Return(nil, nil)
		api.On("LogDebug", "Adding user to channel", "channel_id", "channel1", "user_id", "user1").Return()
		api.On("GetChannelMember", "channel3", "user1").Return(nil, &mmModel.AppError{Message: "not found"})
		api.On("AddChannelMember", "channel3", "user1").Return(nil, nil)
		api.On("LogDebug", "Adding user to channel", "channel_id", "channel3", "user_id", "user1").Return()

		err := client.HandleSAMLLogin(nil, &mmModel.User{Id: "user1"}, &saml2.AssertionInfo{
			Assertions: []saml2Types.Assertion{
				{
					AttributeStatement: &saml2Types.AttributeStatement{
						Attributes: []saml2Types.Attribute{
							{
								Name: "groups",
								Values: []saml2Types.AttributeValue{
									{Value: "group1"},
								},
							},
						},
					},
				},
			},
		}, "groups")
		assert.NoError(t, err)
		api.AssertExpectations(t)
	})

	t.Run("deleted group in SAML assertion", func(t *testing.T) {
		// Reset the mock
		api = &plugintest.API{}
		client.PluginAPI = pluginapi.NewClient(api, nil)

		// Mock GetKeycloakGroupID
		mockKVStore.EXPECT().
			GetKeycloakGroupID("deletedgroup").
			Return("remote-id-deleted", nil)

		// Mock GetGroupByRemoteID to return a deleted group (DeleteAt > 0)
		api.On("GetGroupByRemoteID", "remote-id-deleted", mmModel.GroupSourcePluginPrefix+"keycloak").Return(&mmModel.Group{
			Id:          "deleted-group-id",
			RemoteId:    mmModel.NewPointer("remote-id-deleted"),
			DeleteAt:    12345, // Non-zero DeleteAt indicates the group is deleted
			DisplayName: "deletedgroup",
		}, nil)

		api.On("LogDebug", "Keycloak group has been unlinked in Mattermost", "remote_id", "remote-id-deleted", "name", "deletedgroup").Return()

		// Mock GetGroups for existing memberships - user is already a member of the deleted group
		api.On("GetGroups", 0, 100, mmModel.GroupSearchOpts{
			Source:          mmModel.GroupSourcePluginPrefix + "keycloak",
			FilterHasMember: "user1",
			IncludeArchived: true,
		}, (*mmModel.ViewUsersRestrictions)(nil)).Return([]*mmModel.Group{
			{Id: "deleted-group-id", DisplayName: "Deleted Group", DeleteAt: 12345},
		}, nil)

		// Mock DeleteGroupMember - user should be removed from the deleted group
		api.On("DeleteGroupMember", "deleted-group-id", "user1").Return(nil, nil)

		// Mock GetGroupSyncables for the deleted group
		api.On("GetGroupSyncables", "deleted-group-id", mmModel.GroupSyncableTypeTeam).Return([]*mmModel.GroupSyncable{
			{GroupId: "deleted-group-id", SyncableId: "team-deleted", AutoAdd: true},
		}, nil)
		api.On("GetGroupSyncables", "deleted-group-id", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{
			{GroupId: "deleted-group-id", SyncableId: "channel-deleted", AutoAdd: true},
		}, nil)

		// Mock team/channel member removal
		api.On("GetTeam", "team-deleted").Return(&mmModel.Team{Id: "team-deleted", GroupConstrained: mmModel.NewPointer(false)}, nil) // Non-group constrained team, don't remove them
		api.On("GetChannelMember", "channel-deleted", "user1").Return(&mmModel.ChannelMember{ChannelId: "channel-deleted"}, nil)
		api.On("DeleteChannelMember", "channel-deleted", "user1").Return(nil)
		api.On("LogDebug", "Removing user from channel", "channel_id", "channel-deleted", "user_id", "user1").Return()

		err := client.HandleSAMLLogin(nil, &mmModel.User{Id: "user1"}, &saml2.AssertionInfo{
			Assertions: []saml2Types.Assertion{
				{
					AttributeStatement: &saml2Types.AttributeStatement{
						Attributes: []saml2Types.Attribute{
							{
								Name: "groups",
								Values: []saml2Types.AttributeValue{
									{Value: "deletedgroup"}, // Group exists in SAML but is deleted in Mattermost
								},
							},
						},
					},
				},
			},
		}, "groups")
		assert.NoError(t, err)
		api.AssertExpectations(t)
	})

	t.Run("mixed team and channel syncables with different AutoAdd settings", func(t *testing.T) {
		// Reset the mock
		api = &plugintest.API{}
		client.PluginAPI = pluginapi.NewClient(api, nil)

		// Mock GetKeycloakGroupID
		mockKVStore.EXPECT().
			GetKeycloakGroupID("group1").
			Return("remote-id-1", nil)

		// Mock GetGroupByRemoteID
		api.On("GetGroupByRemoteID", "remote-id-1", mmModel.GroupSourcePluginPrefix+"keycloak").Return(&mmModel.Group{
			Id: "mm-group-1",
		}, nil)

		// Mock GetGroups for existing memberships
		api.On("GetGroups", 0, 100, mmModel.GroupSearchOpts{
			Source:          mmModel.GroupSourcePluginPrefix + "keycloak",
			FilterHasMember: "user1",
			IncludeArchived: true,
		}, (*mmModel.ViewUsersRestrictions)(nil)).Return([]*mmModel.Group{}, nil)

		// Mock group membership operations
		api.On("UpsertGroupMember", "mm-group-1", "user1").Return(nil, nil)

		// Mock GetGroupSyncables to return mixed teams and channels with different AutoAdd settings
		api.On("GetGroupSyncables", "mm-group-1", mmModel.GroupSyncableTypeTeam).Return([]*mmModel.GroupSyncable{
			{
				GroupId:    "mm-group-1",
				SyncableId: "team1",
				AutoAdd:    true,
			},
			{
				GroupId:    "mm-group-1",
				SyncableId: "team2",
				AutoAdd:    false,
			},
		}, nil)

		api.On("GetGroupSyncables", "mm-group-1", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{
			{
				GroupId:    "mm-group-1",
				SyncableId: "channel1",
				AutoAdd:    true,
			},
			{
				GroupId:    "mm-group-1",
				SyncableId: "channel2",
				AutoAdd:    false,
			},
		}, nil)

		// Mock team/channel member creation only for AutoAdd=true
		api.On("GetTeamMember", "team1", "user1").Return(nil, &mmModel.AppError{Message: "not found"})
		api.On("CreateTeamMember", "team1", "user1").Return(nil, nil)
		api.On("LogDebug", "Adding user to team", "team_id", "team1", "user_id", "user1").Return()
		api.On("GetChannelMember", "channel1", "user1").Return(nil, &mmModel.AppError{Message: "not found"})
		api.On("AddChannelMember", "channel1", "user1").Return(nil, nil)
		api.On("LogDebug", "Adding user to channel", "channel_id", "channel1", "user_id", "user1").Return()

		err := client.HandleSAMLLogin(nil, &mmModel.User{Id: "user1"}, &saml2.AssertionInfo{
			Assertions: []saml2Types.Assertion{
				{
					AttributeStatement: &saml2Types.AttributeStatement{
						Attributes: []saml2Types.Attribute{
							{
								Name: "groups",
								Values: []saml2Types.AttributeValue{
									{Value: "group1"},
								},
							},
						},
					},
				},
			},
		}, "groups")
		assert.NoError(t, err)
		api.AssertExpectations(t)
	})

	t.Run("removal from multiple teams and channels", func(t *testing.T) {
		// Reset the mock
		api = &plugintest.API{}
		client.PluginAPI = pluginapi.NewClient(api, nil)

		// Mock GetGroups to return existing memberships
		api.On("GetGroups", 0, 100, mmModel.GroupSearchOpts{
			Source:          mmModel.GroupSourcePluginPrefix + "keycloak",
			FilterHasMember: "user1",
			IncludeArchived: true,
		}, (*mmModel.ViewUsersRestrictions)(nil)).Return([]*mmModel.Group{
			{Id: "group1", DisplayName: "Group 1"},
			{Id: "group2", DisplayName: "Group 2"},
		}, nil)

		// Mock group membership removals
		api.On("DeleteGroupMember", "group1", "user1").Return(nil, nil)
		api.On("DeleteGroupMember", "group2", "user1").Return(nil, nil)

		// Mock GetGroupSyncables with multiple teams and channels
		api.On("GetGroupSyncables", "group1", mmModel.GroupSyncableTypeTeam).Return([]*mmModel.GroupSyncable{
			{
				GroupId:    "group1",
				SyncableId: "team1",
				AutoAdd:    true,
			},
			{
				GroupId:    "group1",
				SyncableId: "team2",
				AutoAdd:    true,
			},
		}, nil)

		api.On("GetGroupSyncables", "group2", mmModel.GroupSyncableTypeTeam).Return([]*mmModel.GroupSyncable{
			{
				GroupId:    "group2",
				SyncableId: "team3",
				AutoAdd:    true,
			},
		}, nil)

		api.On("GetGroupSyncables", "group1", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{
			{
				GroupId:    "group1",
				SyncableId: "channel1",
				AutoAdd:    true,
			},
			{
				GroupId:    "group1",
				SyncableId: "channel2",
				AutoAdd:    true,
			},
		}, nil)

		api.On("GetGroupSyncables", "group2", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{
			{
				GroupId:    "group2",
				SyncableId: "channel3",
				AutoAdd:    true,
			},
		}, nil)

		// Mock team/channel member removals
		api.On("GetTeam", "team1").Return(&mmModel.Team{Id: "team1", GroupConstrained: mmModel.NewPointer(false)}, nil)
		api.On("GetTeam", "team2").Return(&mmModel.Team{Id: "team2", GroupConstrained: mmModel.NewPointer(true)}, nil)
		api.On("GetTeam", "team3").Return(&mmModel.Team{Id: "team3", GroupConstrained: mmModel.NewPointer(true)}, nil)

		api.On("GetTeamMember", "team2", "user1").Return(&mmModel.TeamMember{TeamId: "team2", DeleteAt: 0}, nil)
		api.On("GetTeamMember", "team3", "user1").Return(&mmModel.TeamMember{TeamId: "team3", DeleteAt: 0}, nil)
		api.On("DeleteTeamMember", "team2", "user1", "").Return(nil)
		api.On("LogDebug", "Removing user from team", "team_id", "team2", "user_id", "user1").Return()
		api.On("DeleteTeamMember", "team3", "user1", "").Return(nil)
		api.On("LogDebug", "Removing user from team", "team_id", "team3", "user_id", "user1").Return()
		api.On("GetChannelMember", "channel1", "user1").Return(&mmModel.ChannelMember{ChannelId: "channel1"}, nil)
		api.On("GetChannelMember", "channel2", "user1").Return(&mmModel.ChannelMember{ChannelId: "channel2"}, nil)
		api.On("GetChannelMember", "channel3", "user1").Return(nil, &mmModel.AppError{Message: "not found"})
		api.On("LogDebug", "User has already left the channel", "channel_id", "channel3", "user_id", "user1").Return()
		api.On("DeleteChannelMember", "channel1", "user1").Return(nil)
		api.On("LogDebug", "Removing user from channel", "channel_id", "channel1", "user_id", "user1").Return()
		api.On("DeleteChannelMember", "channel2", "user1").Return(nil)
		api.On("LogDebug", "Removing user from channel", "channel_id", "channel2", "user_id", "user1").Return()

		// Mock logging
		api.On("LogDebug", mock.Anything).Return()

		err := client.HandleSAMLLogin(nil, &mmModel.User{Id: "user1"}, &saml2.AssertionInfo{
			Assertions: []saml2Types.Assertion{
				{
					AttributeStatement: &saml2Types.AttributeStatement{
						Attributes: []saml2Types.Attribute{
							{
								Name:   "groups",
								Values: []saml2Types.AttributeValue{},
							},
						},
					},
				},
			},
		}, "groups")
		assert.NoError(t, err)
		api.AssertExpectations(t)
	})

	t.Run("removal and additions to multiple overlapping teams and channels", func(t *testing.T) {
		// Reset the mock
		api = &plugintest.API{}
		client.PluginAPI = pluginapi.NewClient(api, nil)

		// Mock GetKeycloakGroupID
		mockKVStore.EXPECT().
			GetKeycloakGroupID("group3").
			Return("remote-id-3", nil)
		mockKVStore.EXPECT().
			GetKeycloakGroupID("group4").
			Return("remote-id-4", nil)
		mockKVStore.EXPECT().
			GetKeycloakGroupID("group5").
			Return("remote-id-5", nil)
		mockKVStore.EXPECT()

		// Mock GetGroupByRemoteID
		api.On("GetGroupByRemoteID", "remote-id-3", mmModel.GroupSourcePluginPrefix+"keycloak").Return(&mmModel.Group{
			Id: "group3",
		}, nil)
		api.On("GetGroupByRemoteID", "remote-id-4", mmModel.GroupSourcePluginPrefix+"keycloak").Return(&mmModel.Group{
			Id: "group4",
		}, nil)
		api.On("GetGroupByRemoteID", "remote-id-5", mmModel.GroupSourcePluginPrefix+"keycloak").Return(&mmModel.Group{
			Id: "group5",
		}, nil)

		// Mock GetGroups to return existing memberships
		api.On("GetGroups", 0, 100, mmModel.GroupSearchOpts{
			Source:          mmModel.GroupSourcePluginPrefix + "keycloak",
			FilterHasMember: "user1",
			IncludeArchived: true,
		}, (*mmModel.ViewUsersRestrictions)(nil)).Return([]*mmModel.Group{
			{Id: "group1", DisplayName: "Group 1"},
			{Id: "group2", DisplayName: "Group 2"},
			{Id: "group3", DisplayName: "Group 3"},
		}, nil)

		// Mock group membership removals
		api.On("DeleteGroupMember", "group1", "user1").Return(nil, nil)
		api.On("DeleteGroupMember", "group2", "user1").Return(nil, nil)

		api.On("UpsertGroupMember", "group4", "user1").Return(nil, nil)
		api.On("UpsertGroupMember", "group5", "user1").Return(nil, nil)

		// Mock GetGroupSyncables with multiple teams and channels
		api.On("GetGroupSyncables", "group1", mmModel.GroupSyncableTypeTeam).Return([]*mmModel.GroupSyncable{
			{
				GroupId:    "group1",
				SyncableId: "team1",
				AutoAdd:    true,
			},
			{
				GroupId:    "group1",
				SyncableId: "team2",
				AutoAdd:    true,
			},
		}, nil)

		api.On("GetGroupSyncables", "group2", mmModel.GroupSyncableTypeTeam).Return([]*mmModel.GroupSyncable{
			{
				GroupId:    "group2",
				SyncableId: "team1",
				AutoAdd:    true,
			},
			{
				GroupId:    "group2",
				SyncableId: "team2",
				AutoAdd:    true,
			},
		}, nil)

		api.On("GetGroupSyncables", "group3", mmModel.GroupSyncableTypeTeam).Return([]*mmModel.GroupSyncable{
			{
				GroupId:    "group3",
				SyncableId: "team4",
				AutoAdd:    true,
			},
		}, nil)

		api.On("GetGroupSyncables", "group4", mmModel.GroupSyncableTypeTeam).Return([]*mmModel.GroupSyncable{
			{
				GroupId:    "group4",
				SyncableId: "team4",
				AutoAdd:    true,
			},
			{
				GroupId:    "group4",
				SyncableId: "team3",
				AutoAdd:    true,
			},
		}, nil)

		api.On("GetGroupSyncables", "group5", mmModel.GroupSyncableTypeTeam).Return([]*mmModel.GroupSyncable{
			{
				GroupId:    "group5",
				SyncableId: "team1",
				AutoAdd:    true,
			},
			{
				GroupId:    "group5",
				SyncableId: "team5",
				AutoAdd:    true,
			},
		}, nil)

		api.On("GetGroupSyncables", "group1", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{
			{
				GroupId:    "group1",
				SyncableId: "channel1",
				AutoAdd:    true,
			},
			{
				GroupId:    "group1",
				SyncableId: "channel2",
				AutoAdd:    true,
			},
		}, nil)

		api.On("GetGroupSyncables", "group2", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{
			{
				GroupId:    "group2",
				SyncableId: "channel1",
				AutoAdd:    true,
			},
			{
				GroupId:    "group2",
				SyncableId: "channel2",
				AutoAdd:    true,
			},
			{
				GroupId:    "group2",
				SyncableId: "channel3",
				AutoAdd:    true,
			},
		}, nil)

		api.On("GetGroupSyncables", "group3", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{
			{
				GroupId:    "group3",
				SyncableId: "channel3",
				AutoAdd:    true,
			},
		}, nil)

		api.On("GetGroupSyncables", "group4", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{
			{
				GroupId:    "group4",
				SyncableId: "channel4",
				AutoAdd:    true,
			},
		}, nil)

		api.On("GetGroupSyncables", "group5", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{
			{
				GroupId:    "group5",
				SyncableId: "channel4",
				AutoAdd:    true,
			},
			{
				GroupId:    "group15",
				SyncableId: "channel5",
				AutoAdd:    true,
			},
		}, nil)

		// Mock team/channel member removals
		// User is removed from team1 and re-added due to flow of removals/additions
		api.On("GetTeam", "team1").Return(&mmModel.Team{Id: "team1", GroupConstrained: mmModel.NewPointer(true)}, nil) // Only get teams for remoals
		api.On("GetTeam", "team2").Return(&mmModel.Team{Id: "team2", GroupConstrained: mmModel.NewPointer(true)}, nil) // Only get teams for remoals

		api.On("GetTeamMember", "team1", "user1").Return(&mmModel.TeamMember{TeamId: "team1", DeleteAt: 0}, nil)
		api.On("GetTeamMember", "team1", "user1").Return(&mmModel.TeamMember{TeamId: "team1", DeleteAt: 0}, nil)
		api.On("GetTeamMember", "team2", "user1").Return(&mmModel.TeamMember{TeamId: "team2", DeleteAt: 0}, nil)
		api.On("GetTeamMember", "team3", "user1").Return(nil, &mmModel.AppError{Message: "not found"})
		api.On("GetTeamMember", "team4", "user1").Return(&mmModel.TeamMember{TeamId: "team4", DeleteAt: 0}, nil)      // Already a member
		api.On("GetTeamMember", "team5", "user1").Return(&mmModel.TeamMember{TeamId: "team5", DeleteAt: 123241}, nil) // Was previously a member

		api.On("DeleteTeamMember", "team1", "user1", "").Return(nil)
		api.On("LogDebug", "Removing user from team", "team_id", "team1", "user_id", "user1").Return()
		api.On("DeleteTeamMember", "team2", "user1", "").Return(nil)
		api.On("LogDebug", "Removing user from team", "team_id", "team2", "user_id", "user1").Return()
		api.On("CreateTeamMember", "team3", "user1").Return(nil, nil)
		api.On("LogDebug", "Adding user to team", "team_id", "team3", "user_id", "user1").Return()
		api.On("CreateTeamMember", "team5", "user1").Return(nil, nil)
		api.On("LogDebug", "Adding user to team", "team_id", "team5", "user_id", "user1").Return()

		api.On("GetChannelMember", "channel1", "user1").Return(&mmModel.ChannelMember{ChannelId: "channel1"}, nil)
		api.On("GetChannelMember", "channel2", "user1").Return(&mmModel.ChannelMember{ChannelId: "channel2"}, nil)
		api.On("GetChannelMember", "channel3", "user1").Return(nil, &mmModel.AppError{Message: "not found"})
		api.On("GetChannelMember", "channel4", "user1").Return(nil, &mmModel.AppError{Message: "unexpected error"})
		api.On("GetChannelMember", "channel5", "user1").Return(&mmModel.ChannelMember{ChannelId: "channel5"}, nil)

		api.On("DeleteChannelMember", "channel1", "user1").Return(nil)
		api.On("LogDebug", "Removing user from channel", "channel_id", "channel1", "user_id", "user1").Return()
		api.On("DeleteChannelMember", "channel2", "user1").Return(nil)
		api.On("LogDebug", "Removing user from channel", "channel_id", "channel2", "user_id", "user1").Return()
		api.On("AddChannelMember", "channel3", "user1").Return(nil, nil)
		api.On("LogDebug", "Adding user to channel", "channel_id", "channel3", "user_id", "user1").Return()
		api.On("LogError", "Failed to add user to channel, unable to get channel member", "user_id", "user1", "channel_id", "channel4", "error", mock.Anything).Return()

		err := client.HandleSAMLLogin(nil, &mmModel.User{Id: "user1"}, &saml2.AssertionInfo{
			Assertions: []saml2Types.Assertion{
				{
					AttributeStatement: &saml2Types.AttributeStatement{
						Attributes: []saml2Types.Attribute{
							{
								Name: "groups",
								Values: []saml2Types.AttributeValue{
									{Value: "group3"},
									{Value: "group4"},
									{Value: "group5"},
								},
							},
						},
					},
				},
			},
		}, "groups")
		assert.NoError(t, err)
		api.AssertExpectations(t)
	})
}

func TestKeycloakClient_HandleSAMLLogin_FailLoginOnGroupSyncError_true(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockGoCloak := mocks.NewMockGoCloak(ctrl)
	mockKVStore := kvMocks.NewMockKVStore(ctrl)
	api := &plugintest.API{}

	client := &groups.KeycloakClient{
		Client:                    mockGoCloak,
		Realm:                     "test-realm",
		ClientID:                  "test-client",
		ClientSecret:              "test-secret",
		Kvstore:                   mockKVStore,
		PluginAPI:                 pluginapi.NewClient(api, nil),
		FailLoginOnGroupSyncError: true,
	}

	t.Run("error in GetGroups", func(t *testing.T) {
		// Reset the mock
		api = &plugintest.API{}
		client.PluginAPI = pluginapi.NewClient(api, nil)

		api.On("LogDebug", "No groups found in SAML assertion").Return()

		// Mock GetGroups to return existing groups
		api.On("GetGroups", 0, 100, mmModel.GroupSearchOpts{
			Source:          mmModel.GroupSourcePluginPrefix + "keycloak",
			FilterHasMember: "user1",
			IncludeArchived: true,
		}, (*mmModel.ViewUsersRestrictions)(nil)).Return([]*mmModel.Group{}, &mmModel.AppError{Message: "failed to get groups"})

		api.On("LogError", "Failed to get existing group memberships", "user_id", "user1", "error", mock.Anything).Return()

		err := client.HandleSAMLLogin(nil, &mmModel.User{Id: "user1"}, &saml2.AssertionInfo{
			Assertions: []saml2Types.Assertion{
				{
					AttributeStatement: &saml2Types.AttributeStatement{
						Attributes: []saml2Types.Attribute{
							{
								Name:   "groups",
								Values: []saml2Types.AttributeValue{},
							},
						},
					},
				},
			},
		}, "groups")
		assert.Error(t, err)
		api.AssertExpectations(t)
	})

	t.Run("error in addSyncableTeamsForRemoval", func(t *testing.T) {
		// Reset the mock
		api = &plugintest.API{}
		client.PluginAPI = pluginapi.NewClient(api, nil)

		api.On("LogDebug", "No groups found in SAML assertion").Return()

		// Mock GetGroups to return existing groups
		api.On("GetGroups", 0, 100, mmModel.GroupSearchOpts{
			Source:          mmModel.GroupSourcePluginPrefix + "keycloak",
			FilterHasMember: "user1",
			IncludeArchived: true,
		}, (*mmModel.ViewUsersRestrictions)(nil)).Return([]*mmModel.Group{
			{Id: "group1", DisplayName: "Group 1"},
		}, nil)

		api.On("GetGroupSyncables", "group1", mmModel.GroupSyncableTypeTeam).Return([]*mmModel.GroupSyncable{}, &mmModel.AppError{Message: "failed to get group teams"})
		api.On("LogError", "Failed to get group teams for removal", "group_id", "group1", "error", mock.Anything).Return()

		err := client.HandleSAMLLogin(nil, &mmModel.User{Id: "user1"}, &saml2.AssertionInfo{
			Assertions: []saml2Types.Assertion{
				{
					AttributeStatement: &saml2Types.AttributeStatement{
						Attributes: []saml2Types.Attribute{
							{
								Name:   "groups",
								Values: []saml2Types.AttributeValue{},
							},
						},
					},
				},
			},
		}, "groups")
		assert.Error(t, err)
		api.AssertExpectations(t)
	})

	t.Run("error in addSyncableChannelsForRemoval", func(t *testing.T) {
		// Reset the mock
		api = &plugintest.API{}
		client.PluginAPI = pluginapi.NewClient(api, nil)

		api.On("LogDebug", "No groups found in SAML assertion").Return()

		// Mock GetGroups to return existing groups
		api.On("GetGroups", 0, 100, mmModel.GroupSearchOpts{
			Source:          mmModel.GroupSourcePluginPrefix + "keycloak",
			FilterHasMember: "user1",
			IncludeArchived: true,
		}, (*mmModel.ViewUsersRestrictions)(nil)).Return([]*mmModel.Group{
			{Id: "group1", DisplayName: "Group 1"},
		}, nil)

		api.On("GetGroupSyncables", "group1", mmModel.GroupSyncableTypeTeam).Return([]*mmModel.GroupSyncable{
			{
				GroupId:    "group1",
				SyncableId: "channel1",
				AutoAdd:    true,
			},
		}, nil)
		api.On("GetGroupSyncables", "group1", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{}, &mmModel.AppError{Message: "failed to get group channels"})
		api.On("LogError", "Failed to get group channels for removal", "group_id", "group1", "error", mock.Anything).Return()

		err := client.HandleSAMLLogin(nil, &mmModel.User{Id: "user1"}, &saml2.AssertionInfo{
			Assertions: []saml2Types.Assertion{
				{
					AttributeStatement: &saml2Types.AttributeStatement{
						Attributes: []saml2Types.Attribute{
							{
								Name:   "groups",
								Values: []saml2Types.AttributeValue{},
							},
						},
					},
				},
			},
		}, "groups")
		assert.Error(t, err)
		api.AssertExpectations(t)
	})

	t.Run("error skipped in addSyncableTeamsForAddition and addSyncableChannelsForAddition", func(t *testing.T) {
		// Reset the mock
		api = &plugintest.API{}
		client.PluginAPI = pluginapi.NewClient(api, nil)

		// Mock GetGroups to return existing groups
		api.On("GetGroups", 0, 100, mmModel.GroupSearchOpts{
			Source:          mmModel.GroupSourcePluginPrefix + "keycloak",
			FilterHasMember: "user1",
			IncludeArchived: true,
		}, (*mmModel.ViewUsersRestrictions)(nil)).Return([]*mmModel.Group{
			{Id: "group1", DisplayName: "Group 1"},
		}, nil)

		mockKVStore.EXPECT().
			GetKeycloakGroupID("group1").
			Return("group1", nil)

		mockKVStore.EXPECT().
			GetKeycloakGroupID("group2").
			Return("group2", nil)

		api.On("GetGroupByRemoteID", "group1", mmModel.GroupSourcePluginPrefix+"keycloak").Return(&mmModel.Group{
			Id: "group1",
		}, nil)

		api.On("GetGroupByRemoteID", "group2", mmModel.GroupSourcePluginPrefix+"keycloak").Return(&mmModel.Group{
			Id: "group2",
		}, nil)

		api.On("GetGroupSyncables", "group1", mmModel.GroupSyncableTypeTeam).Return([]*mmModel.GroupSyncable{}, &mmModel.AppError{Message: "failed to get group teams"})
		api.On("GetGroupSyncables", "group2", mmModel.GroupSyncableTypeTeam).Return([]*mmModel.GroupSyncable{}, nil)

		api.On("GetGroupSyncables", "group1", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{}, nil)
		api.On("GetGroupSyncables", "group2", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{}, &mmModel.AppError{Message: "failed to get group channels"})

		api.On("LogError", "Failed to get group teams for addition", "group_id", "group1", "error", mock.Anything).Return()
		api.On("LogError", "Failed to get group channels for addition", "group_id", "group2", "error", mock.Anything).Return()

		api.On("UpsertGroupMember", "group2", "user1").Return(nil, nil)

		err := client.HandleSAMLLogin(nil, &mmModel.User{Id: "user1"}, &saml2.AssertionInfo{
			Assertions: []saml2Types.Assertion{
				{
					AttributeStatement: &saml2Types.AttributeStatement{
						Attributes: []saml2Types.Attribute{
							{
								Name: "groups",
								Values: []saml2Types.AttributeValue{
									{Value: "group1"},
									{Value: "group2"},
								},
							},
						},
					},
				},
			},
		}, "groups")
		assert.NoError(t, err)
		api.AssertExpectations(t)
	})

	t.Run("not found error skipped in GetMember when removing user from Channel", func(t *testing.T) {
		// Reset the mock
		api = &plugintest.API{}
		client.PluginAPI = pluginapi.NewClient(api, nil)

		api.On("LogDebug", "No groups found in SAML assertion").Return()

		// Mock GetGroups to return existing groups
		api.On("GetGroups", 0, 100, mmModel.GroupSearchOpts{
			Source:          mmModel.GroupSourcePluginPrefix + "keycloak",
			FilterHasMember: "user1",
			IncludeArchived: true,
		}, (*mmModel.ViewUsersRestrictions)(nil)).Return([]*mmModel.Group{
			{Id: "group1", DisplayName: "Group 1"},
		}, nil)

		api.On("GetGroupSyncables", "group1", mmModel.GroupSyncableTypeTeam).Return([]*mmModel.GroupSyncable{}, nil)
		api.On("GetGroupSyncables", "group1", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{
			{
				GroupId:    "group1",
				SyncableId: "channel1",
				AutoAdd:    true,
			},
		}, nil)

		api.On("GetChannelMember", "channel1", "user1").Return(nil, &mmModel.AppError{Message: "not found"})
		api.On("LogDebug", "User has already left the channel", "channel_id", "channel1", "user_id", "user1").Return()

		api.On("DeleteGroupMember", "group1", "user1").Return(nil, nil)

		err := client.HandleSAMLLogin(nil, &mmModel.User{Id: "user1"}, &saml2.AssertionInfo{
			Assertions: []saml2Types.Assertion{
				{
					AttributeStatement: &saml2Types.AttributeStatement{
						Attributes: []saml2Types.Attribute{
							{
								Name:   "groups",
								Values: []saml2Types.AttributeValue{},
							},
						},
					},
				},
			},
		}, "groups")
		assert.NoError(t, err)
		api.AssertExpectations(t)
	})

	t.Run("error in GetMember when removing user from Channel", func(t *testing.T) {
		// Reset the mock
		api = &plugintest.API{}
		client.PluginAPI = pluginapi.NewClient(api, nil)

		api.On("LogDebug", "No groups found in SAML assertion").Return()

		// Mock GetGroups to return existing groups
		api.On("GetGroups", 0, 100, mmModel.GroupSearchOpts{
			Source:          mmModel.GroupSourcePluginPrefix + "keycloak",
			FilterHasMember: "user1",
			IncludeArchived: true,
		}, (*mmModel.ViewUsersRestrictions)(nil)).Return([]*mmModel.Group{
			{Id: "group1", DisplayName: "Group 1"},
		}, nil)

		api.On("GetGroupSyncables", "group1", mmModel.GroupSyncableTypeTeam).Return([]*mmModel.GroupSyncable{}, nil)
		api.On("GetGroupSyncables", "group1", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{
			{
				GroupId:    "group1",
				SyncableId: "channel1",
				AutoAdd:    true,
			},
		}, nil)

		api.On("GetChannelMember", "channel1", "user1").Return(nil, &mmModel.AppError{Message: "failed to get channel member"})
		api.On("LogError", "Failed to remove user from channel, unable to get channel member", "user_id", "user1", "channel_id", "channel1", "error", mock.Anything).Return()

		err := client.HandleSAMLLogin(nil, &mmModel.User{Id: "user1"}, &saml2.AssertionInfo{
			Assertions: []saml2Types.Assertion{
				{
					AttributeStatement: &saml2Types.AttributeStatement{
						Attributes: []saml2Types.Attribute{
							{
								Name:   "groups",
								Values: []saml2Types.AttributeValue{},
							},
						},
					},
				},
			},
		}, "groups")
		assert.Error(t, err)
		api.AssertExpectations(t)
	})

	t.Run("error in GetTeam when removing user from Team", func(t *testing.T) {
		// Reset the mock
		api = &plugintest.API{}
		client.PluginAPI = pluginapi.NewClient(api, nil)

		api.On("LogDebug", "No groups found in SAML assertion").Return()

		// Mock GetGroups to return existing groups
		api.On("GetGroups", 0, 100, mmModel.GroupSearchOpts{
			Source:          mmModel.GroupSourcePluginPrefix + "keycloak",
			FilterHasMember: "user1",
			IncludeArchived: true,
		}, (*mmModel.ViewUsersRestrictions)(nil)).Return([]*mmModel.Group{
			{Id: "group1", DisplayName: "Group 1"},
		}, nil)

		api.On("GetGroupSyncables", "group1", mmModel.GroupSyncableTypeTeam).Return([]*mmModel.GroupSyncable{
			{
				GroupId:    "group1",
				SyncableId: "team1",
				AutoAdd:    true,
			},
		}, nil)
		api.On("GetGroupSyncables", "group1", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{}, nil)

		api.On("GetTeam", "team1").Return(nil, &mmModel.AppError{Message: "failed to get team"})
		api.On("LogError", "Failed to remove user from team, unable to get team", "user_id", "user1", "team_id", "team1", "error", mock.Anything).Return()

		err := client.HandleSAMLLogin(nil, &mmModel.User{Id: "user1"}, &saml2.AssertionInfo{
			Assertions: []saml2Types.Assertion{
				{
					AttributeStatement: &saml2Types.AttributeStatement{
						Attributes: []saml2Types.Attribute{
							{
								Name:   "groups",
								Values: []saml2Types.AttributeValue{},
							},
						},
					},
				},
			},
		}, "groups")
		assert.Error(t, err)
		api.AssertExpectations(t)
	})

	t.Run("not found error skipped in GetMember when removing user from Team", func(t *testing.T) {
		// Reset the mock
		api = &plugintest.API{}
		client.PluginAPI = pluginapi.NewClient(api, nil)

		api.On("LogDebug", "No groups found in SAML assertion").Return()

		// Mock GetGroups to return existing groups
		api.On("GetGroups", 0, 100, mmModel.GroupSearchOpts{
			Source:          mmModel.GroupSourcePluginPrefix + "keycloak",
			FilterHasMember: "user1",
			IncludeArchived: true,
		}, (*mmModel.ViewUsersRestrictions)(nil)).Return([]*mmModel.Group{
			{Id: "group1", DisplayName: "Group 1"},
		}, nil)

		api.On("GetGroupSyncables", "group1", mmModel.GroupSyncableTypeTeam).Return([]*mmModel.GroupSyncable{
			{
				GroupId:    "group1",
				SyncableId: "team1",
				AutoAdd:    true,
			},
		}, nil)
		api.On("GetGroupSyncables", "group1", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{}, nil)
		api.On("GetTeam", "team1").Return(&mmModel.Team{Id: "team1", GroupConstrained: mmModel.NewPointer(true)}, nil)
		api.On("GetTeamMember", "team1", "user1").Return(nil, &mmModel.AppError{Message: "not found"})
		api.On("LogDebug", "User has already left the team", "team_id", "team1", "user_id", "user1").Return()

		api.On("DeleteGroupMember", "group1", "user1").Return(nil, nil)

		err := client.HandleSAMLLogin(nil, &mmModel.User{Id: "user1"}, &saml2.AssertionInfo{
			Assertions: []saml2Types.Assertion{
				{
					AttributeStatement: &saml2Types.AttributeStatement{
						Attributes: []saml2Types.Attribute{
							{
								Name:   "groups",
								Values: []saml2Types.AttributeValue{},
							},
						},
					},
				},
			},
		}, "groups")
		assert.NoError(t, err)
		api.AssertExpectations(t)
	})

	t.Run("error in GetTeamMember when removing user from Team", func(t *testing.T) {
		// Reset the mock
		api = &plugintest.API{}
		client.PluginAPI = pluginapi.NewClient(api, nil)

		api.On("LogDebug", "No groups found in SAML assertion").Return()

		// Mock GetGroups to return existing groups
		api.On("GetGroups", 0, 100, mmModel.GroupSearchOpts{
			Source:          mmModel.GroupSourcePluginPrefix + "keycloak",
			FilterHasMember: "user1",
			IncludeArchived: true,
		}, (*mmModel.ViewUsersRestrictions)(nil)).Return([]*mmModel.Group{
			{Id: "group1", DisplayName: "Group 1"},
		}, nil)

		api.On("GetGroupSyncables", "group1", mmModel.GroupSyncableTypeTeam).Return([]*mmModel.GroupSyncable{
			{
				GroupId:    "group1",
				SyncableId: "team1",
				AutoAdd:    true,
			},
		}, nil)
		api.On("GetGroupSyncables", "group1", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{}, nil)
		api.On("GetTeam", "team1").Return(&mmModel.Team{Id: "team1", GroupConstrained: mmModel.NewPointer(true)}, nil)
		api.On("GetTeamMember", "team1", "user1").Return(nil, &mmModel.AppError{Message: "failed to get team member"})
		api.On("LogError", "Failed to remove user from team, unable to get team member", "user_id", "user1", "team_id", "team1", "error", mock.Anything).Return()

		err := client.HandleSAMLLogin(nil, &mmModel.User{Id: "user1"}, &saml2.AssertionInfo{
			Assertions: []saml2Types.Assertion{
				{
					AttributeStatement: &saml2Types.AttributeStatement{
						Attributes: []saml2Types.Attribute{
							{
								Name:   "groups",
								Values: []saml2Types.AttributeValue{},
							},
						},
					},
				},
			},
		}, "groups")
		assert.Error(t, err)
		api.AssertExpectations(t)
	})

	t.Run("error in DeleteMember when removing user from Team", func(t *testing.T) {
		// Reset the mock
		api = &plugintest.API{}
		client.PluginAPI = pluginapi.NewClient(api, nil)

		api.On("LogDebug", "No groups found in SAML assertion").Return()

		// Mock GetGroups to return existing groups
		api.On("GetGroups", 0, 100, mmModel.GroupSearchOpts{
			Source:          mmModel.GroupSourcePluginPrefix + "keycloak",
			FilterHasMember: "user1",
			IncludeArchived: true,
		}, (*mmModel.ViewUsersRestrictions)(nil)).Return([]*mmModel.Group{
			{Id: "group1", DisplayName: "Group 1"},
		}, nil)

		api.On("GetGroupSyncables", "group1", mmModel.GroupSyncableTypeTeam).Return([]*mmModel.GroupSyncable{
			{
				GroupId:    "group1",
				SyncableId: "team1",
				AutoAdd:    true,
			},
		}, nil)
		api.On("GetGroupSyncables", "group1", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{}, nil)
		api.On("GetTeam", "team1").Return(&mmModel.Team{Id: "team1", GroupConstrained: mmModel.NewPointer(true)}, nil)
		api.On("GetTeamMember", "team1", "user1").Return(&mmModel.TeamMember{DeleteAt: 0}, nil)
		api.On("LogDebug", "Removing user from team", "team_id", "team1", "user_id", "user1").Return()
		api.On("DeleteTeamMember", "team1", "user1", "").Return(&mmModel.AppError{Message: "failed to delete team member"})
		api.On("LogError", "Failed to remove user from team", "user_id", "user1", "team_id", "team1", "error", mock.Anything).Return()

		err := client.HandleSAMLLogin(nil, &mmModel.User{Id: "user1"}, &saml2.AssertionInfo{
			Assertions: []saml2Types.Assertion{
				{
					AttributeStatement: &saml2Types.AttributeStatement{
						Attributes: []saml2Types.Attribute{
							{
								Name:   "groups",
								Values: []saml2Types.AttributeValue{},
							},
						},
					},
				},
			},
		}, "groups")
		assert.Error(t, err)
		api.AssertExpectations(t)
	})

	t.Run("error in DeleteGroupMember", func(t *testing.T) {
		// Reset the mock
		api = &plugintest.API{}
		client.PluginAPI = pluginapi.NewClient(api, nil)

		api.On("LogDebug", "No groups found in SAML assertion").Return()

		// Mock GetGroups to return existing groups
		api.On("GetGroups", 0, 100, mmModel.GroupSearchOpts{
			Source:          mmModel.GroupSourcePluginPrefix + "keycloak",
			FilterHasMember: "user1",
			IncludeArchived: true,
		}, (*mmModel.ViewUsersRestrictions)(nil)).Return([]*mmModel.Group{
			{Id: "group1", DisplayName: "Group 1"},
		}, nil)

		api.On("GetGroupSyncables", "group1", mmModel.GroupSyncableTypeTeam).Return([]*mmModel.GroupSyncable{
			{
				GroupId:    "group1",
				SyncableId: "team1",
				AutoAdd:    true,
			},
		}, nil)
		api.On("GetGroupSyncables", "group1", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{}, nil)
		api.On("GetTeam", "team1").Return(&mmModel.Team{Id: "team1", GroupConstrained: mmModel.NewPointer(true)}, nil)
		api.On("GetTeamMember", "team1", "user1").Return(nil, &mmModel.AppError{Message: "not found"})
		api.On("LogDebug", "User has already left the team", "team_id", "team1", "user_id", "user1").Return()

		api.On("DeleteGroupMember", "group1", "user1").Return(nil, &mmModel.AppError{Message: "failed to delete group member"})
		api.On("LogError", "Failed to remove user from group", "user_id", "user1", "group_id", "group1", "error", mock.Anything).Return()

		err := client.HandleSAMLLogin(nil, &mmModel.User{Id: "user1"}, &saml2.AssertionInfo{
			Assertions: []saml2Types.Assertion{
				{
					AttributeStatement: &saml2Types.AttributeStatement{
						Attributes: []saml2Types.Attribute{
							{
								Name:   "groups",
								Values: []saml2Types.AttributeValue{},
							},
						},
					},
				},
			},
		}, "groups")
		assert.Error(t, err)
		api.AssertExpectations(t)
	})

	t.Run("skip error in UpsertGroupMember", func(t *testing.T) {
		// Reset the mock
		api = &plugintest.API{}
		client.PluginAPI = pluginapi.NewClient(api, nil)

		// Mock GetGroups to return existing groups
		api.On("GetGroups", 0, 100, mmModel.GroupSearchOpts{
			Source:          mmModel.GroupSourcePluginPrefix + "keycloak",
			FilterHasMember: "user1",
			IncludeArchived: true,
		}, (*mmModel.ViewUsersRestrictions)(nil)).Return([]*mmModel.Group{
			{Id: "group1", DisplayName: "Group 1"},
		}, nil)

		mockKVStore.EXPECT().
			GetKeycloakGroupID("group1").
			Return("group1", nil)

		mockKVStore.EXPECT().
			GetKeycloakGroupID("group2").
			Return("group2", nil)

		api.On("GetGroupByRemoteID", "group1", mmModel.GroupSourcePluginPrefix+"keycloak").Return(&mmModel.Group{
			Id: "group1",
		}, nil)

		api.On("GetGroupByRemoteID", "group2", mmModel.GroupSourcePluginPrefix+"keycloak").Return(&mmModel.Group{
			Id: "group2",
		}, nil)

		api.On("GetGroupSyncables", "group1", mmModel.GroupSyncableTypeTeam).Return([]*mmModel.GroupSyncable{}, nil)

		api.On("GetGroupSyncables", "group1", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{}, nil)

		api.On("UpsertGroupMember", "group2", "user1").Return(nil, &mmModel.AppError{Message: "failed to upsert group member"})
		api.On("LogError", "Failed to add user to group", "user_id", "user1", "group_id", "group2", "error", mock.Anything).Return()

		err := client.HandleSAMLLogin(nil, &mmModel.User{Id: "user1"}, &saml2.AssertionInfo{
			Assertions: []saml2Types.Assertion{
				{
					AttributeStatement: &saml2Types.AttributeStatement{
						Attributes: []saml2Types.Attribute{
							{
								Name: "groups",
								Values: []saml2Types.AttributeValue{
									{Value: "group1"},
									{Value: "group2"},
								},
							},
						},
					},
				},
			},
		}, "groups")
		assert.NoError(t, err)
		api.AssertExpectations(t)
	})

	t.Run("not found error in addUserToTeams still tries to add team member and skips over other errors", func(t *testing.T) {
		// Reset the mock
		api = &plugintest.API{}
		client.PluginAPI = pluginapi.NewClient(api, nil)

		// Mock GetGroups to return existing groups
		api.On("GetGroups", 0, 100, mmModel.GroupSearchOpts{
			Source:          mmModel.GroupSourcePluginPrefix + "keycloak",
			FilterHasMember: "user1",
			IncludeArchived: true,
		}, (*mmModel.ViewUsersRestrictions)(nil)).Return([]*mmModel.Group{
			{Id: "group1", DisplayName: "Group 1"},
		}, nil)

		mockKVStore.EXPECT().
			GetKeycloakGroupID("group1").
			Return("group1", nil)

		mockKVStore.EXPECT().
			GetKeycloakGroupID("group2").
			Return("group2", nil)

		api.On("GetGroupByRemoteID", "group1", mmModel.GroupSourcePluginPrefix+"keycloak").Return(&mmModel.Group{
			Id: "group1",
		}, nil)

		api.On("GetGroupByRemoteID", "group2", mmModel.GroupSourcePluginPrefix+"keycloak").Return(&mmModel.Group{
			Id: "group2",
		}, nil)

		api.On("GetGroupSyncables", "group1", mmModel.GroupSyncableTypeTeam).Return([]*mmModel.GroupSyncable{
			{
				GroupId:    "group1",
				SyncableId: "team1",
				AutoAdd:    true,
			},
		}, nil)
		api.On("GetGroupSyncables", "group2", mmModel.GroupSyncableTypeTeam).Return([]*mmModel.GroupSyncable{
			{
				GroupId:    "group2",
				SyncableId: "team2",
				AutoAdd:    true,
			},
		}, nil)

		api.On("GetGroupSyncables", "group1", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{}, nil)
		api.On("GetGroupSyncables", "group2", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{}, nil)

		api.On("UpsertGroupMember", "group2", "user1").Return(nil, nil)

		api.On("GetTeamMember", "team1", "user1").Return(nil, &mmModel.AppError{Message: "an error occurred"})
		api.On("LogError", "Failed to add user to team, unable to get team member", "user_id", "user1", "team_id", "team1", "error", mock.Anything).Return()
		api.On("GetTeamMember", "team2", "user1").Return(nil, &mmModel.AppError{Message: "not found"})
		api.On("LogDebug", "Adding user to team", "team_id", "team2", "user_id", "user1").Return()
		api.On("CreateTeamMember", "team2", "user1").Return(nil, nil)

		err := client.HandleSAMLLogin(nil, &mmModel.User{Id: "user1"}, &saml2.AssertionInfo{
			Assertions: []saml2Types.Assertion{
				{
					AttributeStatement: &saml2Types.AttributeStatement{
						Attributes: []saml2Types.Attribute{
							{
								Name: "groups",
								Values: []saml2Types.AttributeValue{
									{Value: "group1"},
									{Value: "group2"},
								},
							},
						},
					},
				},
			},
		}, "groups")
		assert.NoError(t, err)
		api.AssertExpectations(t)
	})

	t.Run("not found error in addUserToChannels still tries to add channel member and skips over other errors", func(t *testing.T) {
		// Reset the mock
		api = &plugintest.API{}
		client.PluginAPI = pluginapi.NewClient(api, nil)

		// Mock GetGroups to return existing groups
		api.On("GetGroups", 0, 100, mmModel.GroupSearchOpts{
			Source:          mmModel.GroupSourcePluginPrefix + "keycloak",
			FilterHasMember: "user1",
			IncludeArchived: true,
		}, (*mmModel.ViewUsersRestrictions)(nil)).Return([]*mmModel.Group{
			{Id: "group1", DisplayName: "Group 1"},
		}, nil)

		mockKVStore.EXPECT().
			GetKeycloakGroupID("group1").
			Return("group1", nil)

		mockKVStore.EXPECT().
			GetKeycloakGroupID("group2").
			Return("group2", nil)

		api.On("GetGroupByRemoteID", "group1", mmModel.GroupSourcePluginPrefix+"keycloak").Return(&mmModel.Group{
			Id: "group1",
		}, nil)

		api.On("GetGroupByRemoteID", "group2", mmModel.GroupSourcePluginPrefix+"keycloak").Return(&mmModel.Group{
			Id: "group2",
		}, nil)

		api.On("GetGroupSyncables", "group1", mmModel.GroupSyncableTypeTeam).Return([]*mmModel.GroupSyncable{}, nil)
		api.On("GetGroupSyncables", "group2", mmModel.GroupSyncableTypeTeam).Return([]*mmModel.GroupSyncable{}, nil)

		api.On("GetGroupSyncables", "group1", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{
			{
				GroupId:    "group1",
				SyncableId: "channel1",
				AutoAdd:    true,
			},
		}, nil)
		api.On("GetGroupSyncables", "group2", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{
			{
				GroupId:    "group2",
				SyncableId: "channel2",
				AutoAdd:    true,
			},
		}, nil)

		api.On("UpsertGroupMember", "group2", "user1").Return(nil, nil)

		api.On("GetChannelMember", "channel1", "user1").Return(nil, &mmModel.AppError{Message: "an error occurred"})
		api.On("LogError", "Failed to add user to channel, unable to get channel member", "user_id", "user1", "channel_id", "channel1", "error", mock.Anything).Return()
		api.On("GetChannelMember", "channel2", "user1").Return(nil, &mmModel.AppError{Message: "not found"})
		api.On("LogDebug", "Adding user to channel", "channel_id", "channel2", "user_id", "user1").Return()
		api.On("AddChannelMember", "channel2", "user1").Return(nil, nil)

		err := client.HandleSAMLLogin(nil, &mmModel.User{Id: "user1"}, &saml2.AssertionInfo{
			Assertions: []saml2Types.Assertion{
				{
					AttributeStatement: &saml2Types.AttributeStatement{
						Attributes: []saml2Types.Attribute{
							{
								Name: "groups",
								Values: []saml2Types.AttributeValue{
									{Value: "group1"},
									{Value: "group2"},
								},
							},
						},
					},
				},
			},
		}, "groups")
		assert.NoError(t, err)
		api.AssertExpectations(t)
	})
}

func TestKeycloakClient_HandleSAMLLogin_FailLoginOnGroupSyncError_false(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockGoCloak := mocks.NewMockGoCloak(ctrl)
	mockKVStore := kvMocks.NewMockKVStore(ctrl)
	api := &plugintest.API{}

	client := &groups.KeycloakClient{
		Client:                    mockGoCloak,
		Realm:                     "test-realm",
		ClientID:                  "test-client",
		ClientSecret:              "test-secret",
		Kvstore:                   mockKVStore,
		PluginAPI:                 pluginapi.NewClient(api, nil),
		FailLoginOnGroupSyncError: false,
	}

	t.Run("skip errors in GetGroups", func(t *testing.T) {
		// Reset the mock
		api = &plugintest.API{}
		client.PluginAPI = pluginapi.NewClient(api, nil)

		api.On("LogDebug", "No groups found in SAML assertion").Return()

		// Mock GetGroups to return existing groups
		api.On("GetGroups", 0, 100, mmModel.GroupSearchOpts{
			Source:          mmModel.GroupSourcePluginPrefix + "keycloak",
			FilterHasMember: "user1",
			IncludeArchived: true,
		}, (*mmModel.ViewUsersRestrictions)(nil)).Return([]*mmModel.Group{}, &mmModel.AppError{Message: "failed to get groups"})

		api.On("LogError", "Failed to get existing group memberships", "user_id", "user1", "error", mock.Anything).Return()

		err := client.HandleSAMLLogin(nil, &mmModel.User{Id: "user1"}, &saml2.AssertionInfo{
			Assertions: []saml2Types.Assertion{
				{
					AttributeStatement: &saml2Types.AttributeStatement{
						Attributes: []saml2Types.Attribute{
							{
								Name:   "groups",
								Values: []saml2Types.AttributeValue{},
							},
						},
					},
				},
			},
		}, "groups")
		assert.NoError(t, err)
		api.AssertExpectations(t)
	})

	t.Run("skip errors when fetching syncables", func(t *testing.T) {
		// Reset the mock
		api = &plugintest.API{}
		client.PluginAPI = pluginapi.NewClient(api, nil)

		// Mock GetGroups to return existing groups
		api.On("GetGroups", 0, 100, mmModel.GroupSearchOpts{
			Source:          mmModel.GroupSourcePluginPrefix + "keycloak",
			FilterHasMember: "user1",
			IncludeArchived: true,
		}, (*mmModel.ViewUsersRestrictions)(nil)).Return([]*mmModel.Group{
			{Id: "group1", DisplayName: "Group 1"},
		}, nil)

		mockKVStore.EXPECT().
			GetKeycloakGroupID("group2").
			Return("group2", nil)

		api.On("GetGroupByRemoteID", "group2", mmModel.GroupSourcePluginPrefix+"keycloak").Return(&mmModel.Group{
			Id: "group2",
		}, nil)

		api.On("GetGroupSyncables", "group1", mmModel.GroupSyncableTypeTeam).Return([]*mmModel.GroupSyncable{}, &mmModel.AppError{Message: "failed to get group teams"})
		api.On("LogError", "Failed to get group teams for removal", "group_id", "group1", "error", mock.Anything).Return()

		api.On("GetGroupSyncables", "group1", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{}, &mmModel.AppError{Message: "failed to get group channels"})
		api.On("LogError", "Failed to get group channels for removal", "group_id", "group1", "error", mock.Anything).Return()

		api.On("GetGroupSyncables", "group2", mmModel.GroupSyncableTypeTeam).Return([]*mmModel.GroupSyncable{}, &mmModel.AppError{Message: "failed to get group teams"})
		api.On("LogError", "Failed to get group teams for addition", "group_id", "group2", "error", mock.Anything).Return()

		api.On("GetGroupSyncables", "group2", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{}, &mmModel.AppError{Message: "failed to get group channels"})
		api.On("LogError", "Failed to get group channels for addition", "group_id", "group2", "error", mock.Anything).Return()

		api.On("DeleteGroupMember", "group1", "user1").Return(nil, nil)
		api.On("UpsertGroupMember", "group2", "user1").Return(nil, nil)

		err := client.HandleSAMLLogin(nil, &mmModel.User{Id: "user1"}, &saml2.AssertionInfo{
			Assertions: []saml2Types.Assertion{
				{
					AttributeStatement: &saml2Types.AttributeStatement{
						Attributes: []saml2Types.Attribute{
							{
								Name: "groups",
								Values: []saml2Types.AttributeValue{
									{Value: "group2"},
								},
							},
						},
					},
				},
			},
		}, "groups")
		assert.NoError(t, err)
		api.AssertExpectations(t)
	})

	t.Run("skip errors when syncing channel memberships", func(t *testing.T) {
		// Reset the mock
		api = &plugintest.API{}
		client.PluginAPI = pluginapi.NewClient(api, nil)

		// Mock GetGroups to return existing groups
		api.On("GetGroups", 0, 100, mmModel.GroupSearchOpts{
			Source:          mmModel.GroupSourcePluginPrefix + "keycloak",
			FilterHasMember: "user1",
			IncludeArchived: true,
		}, (*mmModel.ViewUsersRestrictions)(nil)).Return([]*mmModel.Group{
			{Id: "group1", DisplayName: "Group 1"},
		}, nil)

		mockKVStore.EXPECT().
			GetKeycloakGroupID("group2").
			Return("group2", nil)

		api.On("GetGroupByRemoteID", "group2", mmModel.GroupSourcePluginPrefix+"keycloak").Return(&mmModel.Group{
			Id: "group2",
		}, nil)

		api.On("GetGroupSyncables", "group1", mmModel.GroupSyncableTypeTeam).Return([]*mmModel.GroupSyncable{}, nil)
		api.On("GetGroupSyncables", "group1", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{
			{
				GroupId:    "group1",
				SyncableId: "channel1",
				AutoAdd:    true,
			},
			{
				GroupId:    "group1",
				SyncableId: "channel2",
				AutoAdd:    true,
			},
		}, nil)

		api.On("GetGroupSyncables", "group2", mmModel.GroupSyncableTypeTeam).Return([]*mmModel.GroupSyncable{}, nil)
		api.On("GetGroupSyncables", "group2", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{
			{
				GroupId:    "group2",
				SyncableId: "channel3",
				AutoAdd:    true,
			},
		}, nil)

		api.On("GetChannelMember", "channel1", "user1").Return(nil, &mmModel.AppError{Message: "failed to get channel member"})
		api.On("LogError", "Failed to remove user from channel, unable to get channel member", "user_id", "user1", "channel_id", "channel1", "error", mock.Anything).Return()
		api.On("GetChannelMember", "channel2", "user1").Return(nil, &mmModel.AppError{Message: "not found"})
		api.On("LogDebug", "User has already left the channel", "channel_id", "channel2", "user_id", "user1").Return()
		api.On("GetChannelMember", "channel3", "user1").Return(nil, &mmModel.AppError{Message: "not found"})
		api.On("LogDebug", "Adding user to channel", "channel_id", "channel3", "user_id", "user1").Return()
		api.On("AddChannelMember", "channel3", "user1").Return(nil, nil)

		api.On("DeleteGroupMember", "group1", "user1").Return(nil, nil)
		api.On("UpsertGroupMember", "group2", "user1").Return(nil, nil)

		err := client.HandleSAMLLogin(nil, &mmModel.User{Id: "user1"}, &saml2.AssertionInfo{
			Assertions: []saml2Types.Assertion{
				{
					AttributeStatement: &saml2Types.AttributeStatement{
						Attributes: []saml2Types.Attribute{
							{
								Name: "groups",
								Values: []saml2Types.AttributeValue{
									{Value: "group2"},
								},
							},
						},
					},
				},
			},
		}, "groups")
		assert.NoError(t, err)
		api.AssertExpectations(t)
	})

	t.Run("skip errors when syncing group memberships", func(t *testing.T) {
		// Reset the mock
		api = &plugintest.API{}
		client.PluginAPI = pluginapi.NewClient(api, nil)

		// Mock GetGroups to return existing groups
		api.On("GetGroups", 0, 100, mmModel.GroupSearchOpts{
			Source:          mmModel.GroupSourcePluginPrefix + "keycloak",
			FilterHasMember: "user1",
			IncludeArchived: true,
		}, (*mmModel.ViewUsersRestrictions)(nil)).Return([]*mmModel.Group{
			{Id: "group1", DisplayName: "Group 1"},
		}, nil)

		mockKVStore.EXPECT().
			GetKeycloakGroupID("group2").
			Return("group2", nil)

		api.On("GetGroupByRemoteID", "group2", mmModel.GroupSourcePluginPrefix+"keycloak").Return(&mmModel.Group{
			Id: "group2",
		}, nil)

		api.On("GetGroupSyncables", "group1", mmModel.GroupSyncableTypeTeam).Return([]*mmModel.GroupSyncable{}, nil)
		api.On("GetGroupSyncables", "group1", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{}, nil)

		api.On("DeleteGroupMember", "group1", "user1").Return(nil, &mmModel.AppError{Message: "failed to delete group member"})
		api.On("LogError", "Failed to remove user from group", "user_id", "user1", "group_id", "group1", "error", mock.Anything).Return()

		api.On("UpsertGroupMember", "group2", "user1").Return(nil, &mmModel.AppError{Message: "failed to upsert group member"})
		api.On("LogError", "Failed to add user to group", "user_id", "user1", "group_id", "group2", "error", mock.Anything).Return()

		err := client.HandleSAMLLogin(nil, &mmModel.User{Id: "user1"}, &saml2.AssertionInfo{
			Assertions: []saml2Types.Assertion{
				{
					AttributeStatement: &saml2Types.AttributeStatement{
						Attributes: []saml2Types.Attribute{
							{
								Name: "groups",
								Values: []saml2Types.AttributeValue{
									{Value: "group2"},
								},
							},
						},
					},
				},
			},
		}, "groups")
		assert.NoError(t, err)
		api.AssertExpectations(t)
	})

	t.Run("skip errors when syncing team memberships", func(t *testing.T) {
		// Reset the mock
		api = &plugintest.API{}
		client.PluginAPI = pluginapi.NewClient(api, nil)

		// Mock GetGroups to return existing groups
		api.On("GetGroups", 0, 100, mmModel.GroupSearchOpts{
			Source:          mmModel.GroupSourcePluginPrefix + "keycloak",
			FilterHasMember: "user1",
			IncludeArchived: true,
		}, (*mmModel.ViewUsersRestrictions)(nil)).Return([]*mmModel.Group{
			{Id: "group1", DisplayName: "Group 1"},
		}, nil)

		mockKVStore.EXPECT().
			GetKeycloakGroupID("group2").
			Return("group2", nil)

		api.On("GetGroupByRemoteID", "group2", mmModel.GroupSourcePluginPrefix+"keycloak").Return(&mmModel.Group{
			Id: "group2",
		}, nil)

		api.On("GetGroupSyncables", "group1", mmModel.GroupSyncableTypeTeam).Return([]*mmModel.GroupSyncable{
			{
				GroupId:    "group1",
				SyncableId: "team1",
				AutoAdd:    true,
			},
			{
				GroupId:    "group1",
				SyncableId: "team2",
				AutoAdd:    true,
			},
		}, nil)
		api.On("GetGroupSyncables", "group1", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{}, nil)

		api.On("DeleteGroupMember", "group1", "user1").Return(nil, nil)
		api.On("UpsertGroupMember", "group2", "user1").Return(nil, nil)

		api.On("GetGroupSyncables", "group2", mmModel.GroupSyncableTypeTeam).Return([]*mmModel.GroupSyncable{
			{
				GroupId:    "group2",
				SyncableId: "team3",
				AutoAdd:    true,
			},
		}, nil)
		api.On("GetGroupSyncables", "group2", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{}, nil)

		api.On("GetTeam", "team1").Return(nil, &mmModel.AppError{Message: "failed to get team"})
		api.On("LogError", "Failed to remove user from team, unable to get team", "user_id", "user1", "team_id", "team1", "error", mock.Anything).Return()

		api.On("GetTeam", "team2").Return(&mmModel.Team{Id: "team2", GroupConstrained: mmModel.NewPointer(true)}, nil)
		api.On("GetTeamMember", "team2", "user1").Return(nil, &mmModel.AppError{Message: "failed to get team member"})
		api.On("LogError", "Failed to remove user from team, unable to get team member", "user_id", "user1", "team_id", "team2", "error", mock.Anything).Return()

		api.On("GetTeamMember", "team3", "user1").Return(nil, &mmModel.AppError{Message: "not found"})
		api.On("LogDebug", "Adding user to team", "team_id", "team3", "user_id", "user1").Return()
		api.On("CreateTeamMember", "team3", "user1").Return(nil, &mmModel.AppError{Message: "failed to add user to team"})
		api.On("LogError", "Failed to add user to team", "user_id", "user1", "team_id", "team3", "error", mock.Anything).Return()

		err := client.HandleSAMLLogin(nil, &mmModel.User{Id: "user1"}, &saml2.AssertionInfo{
			Assertions: []saml2Types.Assertion{
				{
					AttributeStatement: &saml2Types.AttributeStatement{
						Attributes: []saml2Types.Attribute{
							{
								Name: "groups",
								Values: []saml2Types.AttributeValue{
									{Value: "group2"},
								},
							},
						},
					},
				},
			},
		}, "groups")
		assert.NoError(t, err)
		api.AssertExpectations(t)
	})
}

func TestKeycloakClient_GetExistingGroups(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockGoCloak := mocks.NewMockGoCloak(ctrl)
	mockKVStore := kvMocks.NewMockKVStore(ctrl)
	api := &plugintest.API{}

	client := &groups.KeycloakClient{
		Client:       mockGoCloak,
		Realm:        "test-realm",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Kvstore:      mockKVStore,
		PluginAPI:    pluginapi.NewClient(api, nil),
	}

	t.Run("get existing groups", func(t *testing.T) {
		// Mock GetGroups to return some groups
		api.On("GetGroups", 0, 100, mmModel.GroupSearchOpts{
			Source:          "plugin_keycloak",
			FilterHasMember: "user1",
			IncludeArchived: true,
		}, (*mmModel.ViewUsersRestrictions)(nil)).Return([]*mmModel.Group{
			{Id: "group1", DisplayName: "Group 1"},
			{Id: "group2", DisplayName: "Group 2"},
		}, nil)

		groups, err := client.GetExistingGroupMemberships("user1")
		assert.NoError(t, err)
		assert.Len(t, groups, 2)
		assert.Equal(t, "group1", groups[0].Id)
		assert.Equal(t, "group2", groups[1].Id)

		api.AssertExpectations(t)
	})
}
