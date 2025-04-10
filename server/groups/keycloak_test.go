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

	t.Run("token refresh needed", func(t *testing.T) {
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
		Client:       mockGoCloak,
		Realm:        "test-realm",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Kvstore:      mockKVStore,
		PluginAPI:    pluginapi.NewClient(api, nil),
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
		api.On("DeleteTeamMember", "team1", "user1", "").Return(nil)

		// Mock channel syncables
		api.On("GetGroupSyncables", "group1", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{
			{GroupId: "group1", SyncableId: "channel1", AutoAdd: true},
		}, nil)
		api.On("GetGroupSyncables", "group2", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{}, nil)
		api.On("DeleteChannelMember", "channel1", "user1").Return(nil)

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

	t.Run("handle DeleteMember failure during cleanup", func(t *testing.T) {
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

		// Mock DeleteMember to fail
		api.On("DeleteGroupMember", "group1", "user1").Return(nil, &mmModel.AppError{Message: "failed to delete member"})

		// Mock logging
		api.On("LogDebug", mock.Anything).Return()
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
		assert.NoError(t, err) // Should not return error even if deletion fails
		api.AssertExpectations(t)
	})

	t.Run("handle syncable processing failure during cleanup", func(t *testing.T) {
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

		// Mock successful group member deletion
		api.On("DeleteGroupMember", "group1", "user1").Return(nil, nil)

		// Mock GetGroupSyncables to fail
		api.On("GetGroupSyncables", "group1", mmModel.GroupSyncableTypeTeam).Return(nil, &mmModel.AppError{Message: "failed to get team syncables"})
		api.On("GetGroupSyncables", "group1", mmModel.GroupSyncableTypeChannel).Return(nil, &mmModel.AppError{Message: "failed to get channel syncables"})

		// Mock logging
		api.On("LogDebug", mock.Anything).Return()
		api.On("LogError", "Failed to get group teams", "group_id", "group1", "error", mock.Anything).Return()
		api.On("LogError", "Failed to get group channels", "group_id", "group1", "error", mock.Anything).Return()

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
		assert.NoError(t, err) // Should not return error even if syncable processing fails
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
		api.On("LogError", "Failed to store group mapping", "group", "newgroup", "error", mock.Anything).Return()

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

	t.Run("mixed scenario - add, remove and remain", func(t *testing.T) {
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
				GroupId:    "mm-group-1",
				SyncableId: "team1",
				AutoAdd:    false,
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
		api.On("DeleteTeamMember", "team1", "user1", "").Return(nil)
		api.On("DeleteChannelMember", "channel1", "user1").Return(nil)

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

	t.Run("GetGroupByRemoteID fails", func(t *testing.T) {
		// Reset the mock
		api = &plugintest.API{}
		client.PluginAPI = pluginapi.NewClient(api, nil)

		// Mock GetKeycloakGroupID
		mockKVStore.EXPECT().
			GetKeycloakGroupID("group1").
			Return("remote-id-1", nil)

		// Mock GetGroupByRemoteID failure
		api.On("GetGroupByRemoteID", "remote-id-1", mmModel.GroupSourcePluginPrefix+"keycloak").Return(nil, &mmModel.AppError{Message: "group not found"})

		// Mock logging
		api.On("LogError", "Failed to get Mattermost group", "remote_id", "remote-id-1", "error", mock.Anything).Return()

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
		api.On("CreateTeamMember", "team1", "user1").Return(nil, nil)
		api.On("CreateTeamMember", "team3", "user1").Return(nil, nil)

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
		api.On("AddChannelMember", "channel1", "user1").Return(nil, nil)
		api.On("AddChannelMember", "channel3", "user1").Return(nil, nil)

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
			Id:       "deleted-group-id",
			DeleteAt: 12345, // Non-zero DeleteAt indicates the group is deleted
		}, nil)

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
		api.On("DeleteTeamMember", "team-deleted", "user1", "").Return(nil)
		api.On("DeleteChannelMember", "channel-deleted", "user1").Return(nil)

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
		api.On("CreateTeamMember", "team1", "user1").Return(nil, nil)
		api.On("AddChannelMember", "channel1", "user1").Return(nil, nil)

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
		api.On("DeleteTeamMember", "team1", "user1", "").Return(nil)
		api.On("DeleteTeamMember", "team2", "user1", "").Return(nil)
		api.On("DeleteTeamMember", "team3", "user1", "").Return(nil)
		api.On("DeleteChannelMember", "channel1", "user1").Return(nil)
		api.On("DeleteChannelMember", "channel2", "user1").Return(nil)
		api.On("DeleteChannelMember", "channel3", "user1").Return(nil)

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

	t.Run("partial failures in team and channel operations", func(t *testing.T) {
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

		// Mock GetGroupSyncables with multiple teams and channels
		api.On("GetGroupSyncables", "mm-group-1", mmModel.GroupSyncableTypeTeam).Return([]*mmModel.GroupSyncable{
			{GroupId: "mm-group-1", SyncableId: "team1", AutoAdd: true},
			{GroupId: "mm-group-1", SyncableId: "team2", AutoAdd: true},
			{GroupId: "mm-group-1", SyncableId: "team3", AutoAdd: true},
		}, nil)

		api.On("GetGroupSyncables", "mm-group-1", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{
			{GroupId: "mm-group-1", SyncableId: "channel1", AutoAdd: true},
			{GroupId: "mm-group-1", SyncableId: "channel2", AutoAdd: true},
			{GroupId: "mm-group-1", SyncableId: "channel3", AutoAdd: true},
		}, nil)

		// Mock team member creation with mixed results
		api.On("CreateTeamMember", "team1", "user1").Return(nil, nil)                                                  // Success
		api.On("CreateTeamMember", "team2", "user1").Return(nil, &mmModel.AppError{Message: "failed to add to team2"}) // Failure
		api.On("CreateTeamMember", "team3", "user1").Return(nil, nil)                                                  // Success

		// Mock channel member creation with mixed results
		api.On("AddChannelMember", "channel1", "user1").Return(nil, nil)                                                     // Success
		api.On("AddChannelMember", "channel2", "user1").Return(nil, &mmModel.AppError{Message: "failed to add to channel2"}) // Failure
		api.On("AddChannelMember", "channel3", "user1").Return(nil, nil)                                                     // Success

		// Mock error logging
		api.On("LogError", "Failed to add user to team",
			"user_id", "user1",
			"team_id", "team2",
			"error", mock.Anything).Return()
		api.On("LogError", "Failed to add user to channel",
			"user_id", "user1",
			"channel_id", "channel2",
			"error", mock.Anything).Return()

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
		assert.NoError(t, err) // Overall operation should succeed despite partial failures
		api.AssertExpectations(t)

		// Verify that the mock was called as expected
		api.AssertCalled(t, "CreateTeamMember", "team1", "user1")
		api.AssertCalled(t, "CreateTeamMember", "team2", "user1")
		api.AssertCalled(t, "CreateTeamMember", "team3", "user1")
		api.AssertCalled(t, "AddChannelMember", "channel1", "user1")
		api.AssertCalled(t, "AddChannelMember", "channel2", "user1")
		api.AssertCalled(t, "AddChannelMember", "channel3", "user1")
	})

	t.Run("partial failures in team removals", func(t *testing.T) {
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
		}, nil)

		// Mock group membership removal
		api.On("DeleteGroupMember", "group1", "user1").Return(nil, nil)

		// Mock GetGroupSyncables with teams
		api.On("GetGroupSyncables", "group1", mmModel.GroupSyncableTypeTeam).Return([]*mmModel.GroupSyncable{
			{GroupId: "group1", SyncableId: "team1", AutoAdd: true},
			{GroupId: "group1", SyncableId: "team2", AutoAdd: true},
			{GroupId: "group1", SyncableId: "team3", AutoAdd: true},
		}, nil)

		// Mock GetGroupSyncables with channels
		api.On("GetGroupSyncables", "group1", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{}, nil)

		// Mock team member removal with mixed results
		api.On("DeleteTeamMember", "team1", "user1", "").Return(nil)                                          // Success
		api.On("DeleteTeamMember", "team2", "user1", "").Return(&mmModel.AppError{Message: "removal failed"}) // Failure
		api.On("DeleteTeamMember", "team3", "user1", "").Return(nil)                                          // Success

		// Mock error logging
		api.On("LogError", "Failed to remove user from team",
			"user_id", "user1",
			"team_id", "team2",
			"error", mock.Anything).Return()

		// Mock success logging
		api.On("LogDebug", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return()

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
		assert.NoError(t, err) // Overall operation should succeed despite partial failures
		api.AssertExpectations(t)
	})

	t.Run("team permission scenarios", func(t *testing.T) {
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

		// Mock GetGroupSyncables with teams having different schemes
		api.On("GetGroupSyncables", "mm-group-1", mmModel.GroupSyncableTypeTeam).Return([]*mmModel.GroupSyncable{
			{GroupId: "mm-group-1", SyncableId: "team1", AutoAdd: true}, // Default scheme
			{GroupId: "mm-group-1", SyncableId: "team2", AutoAdd: true}, // Custom scheme
			{GroupId: "mm-group-1", SyncableId: "team3", AutoAdd: true}, // Restricted scheme
		}, nil)

		// Mock team member creation with different permission scenarios
		api.On("CreateTeamMember", "team1", "user1").Return(nil, nil) // Success with default scheme
		api.On("CreateTeamMember", "team2", "user1").Return(nil, &mmModel.AppError{
			Message:       "failed to add to team2",
			DetailedError: "User does not have required permissions in custom scheme",
		}) // Failure due to custom scheme permissions
		api.On("CreateTeamMember", "team3", "user1").Return(nil, &mmModel.AppError{
			Message:       "failed to add to team3",
			DetailedError: "User does not meet restrictions for this team",
		}) // Failure due to team restrictions

		// Mock GetGroupSyncables for channels (empty)
		api.On("GetGroupSyncables", "mm-group-1", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{}, nil)

		// Mock error logging for permission failures
		api.On("LogError", "Failed to add user to team",
			"user_id", "user1",
			"team_id", "team2",
			"error", mock.Anything).Return()
		api.On("LogError", "Failed to add user to team",
			"user_id", "user1",
			"team_id", "team3",
			"error", mock.Anything).Return()

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
		assert.NoError(t, err) // Overall operation should succeed despite permission failures
		api.AssertExpectations(t)
	})

	t.Run("channel permission scenarios", func(t *testing.T) {
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

		// Mock GetGroupSyncables with channels having different schemes
		api.On("GetGroupSyncables", "mm-group-1", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{
			{GroupId: "mm-group-1", SyncableId: "channel1", AutoAdd: true}, // Default scheme
			{GroupId: "mm-group-1", SyncableId: "channel2", AutoAdd: true}, // Custom scheme
			{GroupId: "mm-group-1", SyncableId: "channel3", AutoAdd: true}, // Private channel
			{GroupId: "mm-group-1", SyncableId: "channel4", AutoAdd: true}, // Read-only channel
		}, nil)

		// Mock channel member creation with different permission scenarios
		api.On("AddChannelMember", "channel1", "user1").Return(nil, nil) // Success with default scheme
		api.On("AddChannelMember", "channel2", "user1").Return(nil, &mmModel.AppError{
			Message:       "failed to add to channel2",
			DetailedError: "User does not have required permissions in custom scheme",
		}) // Failure due to custom scheme permissions
		api.On("AddChannelMember", "channel3", "user1").Return(nil, &mmModel.AppError{
			Message:       "failed to add to channel3",
			DetailedError: "User cannot join private channels",
		}) // Failure due to private channel restrictions
		api.On("AddChannelMember", "channel4", "user1").Return(nil, &mmModel.AppError{
			Message:       "failed to add to channel4",
			DetailedError: "Channel is read-only",
		}) // Failure due to read-only restriction

		// Mock error logging for permission failures
		api.On("LogError", "Failed to add user to channel",
			"user_id", "user1",
			"channel_id", "channel2",
			"error", mock.Anything).Return()
		api.On("LogError", "Failed to add user to channel",
			"user_id", "user1",
			"channel_id", "channel3",
			"error", mock.Anything).Return()
		api.On("LogError", "Failed to add user to channel",
			"user_id", "user1",
			"channel_id", "channel4",
			"error", mock.Anything).Return()

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
		assert.NoError(t, err) // Overall operation should succeed despite permission failures
		api.AssertExpectations(t)
	})

	t.Run("partial failures in channel removals", func(t *testing.T) {
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
		}, nil)

		// Mock group membership removal
		api.On("DeleteGroupMember", "group1", "user1").Return(nil, nil)

		// Mock GetGroupSyncables with teams (empty)
		api.On("GetGroupSyncables", "group1", mmModel.GroupSyncableTypeTeam).Return([]*mmModel.GroupSyncable{}, nil)

		// Mock GetGroupSyncables with channels
		api.On("GetGroupSyncables", "group1", mmModel.GroupSyncableTypeChannel).Return([]*mmModel.GroupSyncable{
			{GroupId: "group1", SyncableId: "channel1", AutoAdd: true},
			{GroupId: "group1", SyncableId: "channel2", AutoAdd: true},
			{GroupId: "group1", SyncableId: "channel3", AutoAdd: true},
		}, nil)

		// Mock channel member removal with mixed results
		api.On("DeleteChannelMember", "channel1", "user1").Return(nil)                                          // Success
		api.On("DeleteChannelMember", "channel2", "user1").Return(&mmModel.AppError{Message: "removal failed"}) // Failure
		api.On("DeleteChannelMember", "channel3", "user1").Return(nil)                                          // Success

		// Mock error logging
		api.On("LogError", "Failed to remove user from channel",
			"user_id", "user1",
			"channel_id", "channel2",
			"error", mock.Anything).Return()

		// Mock success logging
		api.On("LogDebug", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return()

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
		assert.NoError(t, err) // Overall operation should succeed despite partial failures
		api.AssertExpectations(t)
	})
}

func TestKeycloakClient_ProcessMembershipChanges(t *testing.T) {
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

	t.Run("process membership changes", func(t *testing.T) {
		existingGroups := []*mmModel.Group{
			{Id: "group1", DisplayName: "Group 1"},
			{Id: "group2", DisplayName: "Group 2"},
		}

		newGroups := map[string]*mmModel.Group{
			"group2": {Id: "group2", DisplayName: "Group 2"},
			"group3": {Id: "group3", DisplayName: "Group 3"},
		}

		// Mock DeleteMember for removed group
		api.On("DeleteGroupMember", "group1", "user1").Return(nil, nil)

		// Mock UpsertMember for new group
		api.On("UpsertGroupMember", "group3", "user1").Return(nil, nil)

		removed, active := client.ProcessMembershipChanges(&mmModel.User{Id: "user1"}, existingGroups, newGroups)

		assert.Contains(t, removed, "group1")
		assert.Len(t, active, 2)

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
