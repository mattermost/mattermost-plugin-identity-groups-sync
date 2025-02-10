package groups_test

import (
	"context"
	"testing"
	"time"

	"github.com/mattermost/mattermost-plugin-groups/server/groups"

	"github.com/Nerzal/gocloak/v13"
	"github.com/golang/mock/gomock"
	mmModel "github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/pluginapi"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"

	"github.com/mattermost/mattermost-plugin-groups/server/groups/mocks"
	"github.com/mattermost/mattermost-plugin-groups/server/model"
	kvMocks "github.com/mattermost/mattermost-plugin-groups/server/store/kvstore/mocks"
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
			StoreJWT(gomock.Any()).
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
			StoreJWT(gomock.Any()).
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
			GetJWT().
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
		assert.Equal(t, mmModel.GroupSourcePluginPrefix+"keycloak", groups[0].Source)
	})

	t.Run("token refresh needed", func(t *testing.T) {
		expiredToken := &model.JWT{
			AccessToken:                "expired-token",
			AccessTokenExpirationTime:  time.Now().Add(-1 * time.Hour).UnixMilli(),
			RefreshToken:               "refresh-token",
			RefreshTokenExpirationTime: time.Now().Add(1 * time.Hour).UnixMilli(),
		}

		mockKVStore.EXPECT().
			GetJWT().
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
			StoreJWT(gomock.Any()).
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
			GetJWT().
			Return(validToken, nil)

		mockGoCloak.EXPECT().
			GetGroupsCount(
				gomock.Any(),
				"valid-token",
				"test-realm",
				gomock.Any(),
			).
			Return(42, nil)

		count, err := client.GetGroupsCount(context.Background())
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
			GetJWT().
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
		assert.Equal(t, mmModel.GroupSourcePluginPrefix+"keycloak", group.Source)
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
			GetJWT().
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
