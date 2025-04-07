package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/mattermost/mattermost-plugin-groups/server/groups"
	"github.com/mattermost/mattermost-plugin-groups/server/groups/mocks"
	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin/plugintest"
	"github.com/mattermost/mattermost/server/public/pluginapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestGetGroups(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockGroupsClient := mocks.NewMockClient(ctrl)
	api := &plugintest.API{}

	api.Mock.On("CreateGroup", &model.Group{}).Return(nil, nil)

	p := &Plugin{
		groupsClient: mockGroupsClient,
		client:       pluginapi.NewClient(api, nil),
	}
	p.SetAPI(api)

	t.Run("unauthorized groups fetch", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/api/v1/groups", nil)
		r.Header.Set("Mattermost-User-ID", "user1")

		api.Mock.On("HasPermissionTo", "user1", model.PermissionSysconsoleReadUserManagementGroups).Return(false).Once()

		p.ServeHTTP(nil, w, r)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("successful groups fetch", func(t *testing.T) {
		remoteID := "remote1"
		api.Mock.On("HasPermissionTo", "user1", model.PermissionSysconsoleReadUserManagementGroups).Return(true).Once()

		mmGroups := []*model.Group{
			{
				Id:          "group1",
				DisplayName: "Group 1",
				RemoteId:    &remoteID,
				Source:      model.GroupSourcePluginPrefix + "keycloak",
			},
		}

		mockGroupsClient.EXPECT().
			GetGroups(gomock.Any(), groups.Query{
				Page:    0,
				PerPage: 100,
			}).
			Return(mmGroups, nil)

		mockGroupsClient.EXPECT().
			GetGroupSource().
			Return(model.GroupSourcePluginPrefix + "keycloak")

		api.Mock.On("GetGroupByRemoteID", "remote1", model.GroupSourcePluginPrefix+"keycloak").Return(mmGroups[0], nil)

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/api/v1/groups", nil)
		r.Header.Set("Mattermost-User-ID", "user1")

		p.ServeHTTP(nil, w, r)

		assert.Equal(t, http.StatusOK, w.Code)

		var response struct {
			Groups []*model.Group `json:"groups"`
			Count  int            `json:"total_count"`
		}
		err := json.NewDecoder(w.Body).Decode(&response)
		assert.NoError(t, err)
		assert.Equal(t, 1, response.Count)
		assert.Equal(t, mmGroups, response.Groups)
	})
}

func TestGetGroupsCount(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockGroupsClient := mocks.NewMockClient(ctrl)
	api := &plugintest.API{}

	// Mock required API methods
	api.Mock.On("CreateGroup", &model.Group{}).Return(&model.Group{}, nil)
	api.Mock.On("UpdateGroup", &model.Group{}).Return(&model.Group{}, nil)

	p := &Plugin{
		groupsClient: mockGroupsClient,
		client:       pluginapi.NewClient(api, nil),
	}
	p.SetAPI(api)

	t.Run("unauthorized count fetch", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/api/v1/groups/count", nil)
		r.Header.Set("Mattermost-User-ID", "user1")

		api.Mock.On("HasPermissionTo", "user1", model.PermissionSysconsoleReadUserManagementGroups).Return(false).Once()

		p.ServeHTTP(nil, w, r)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("successful count fetch", func(t *testing.T) {
		api.Mock.On("HasPermissionTo", "user1", model.PermissionSysconsoleReadUserManagementGroups).Return(true).Once()

		mockGroupsClient.EXPECT().
			GetGroupsCount(gomock.Any(), "").
			Return(5, nil)

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/api/v1/groups/count", nil)
		r.Header.Set("Mattermost-User-ID", "user1")

		p.ServeHTTP(nil, w, r)

		assert.Equal(t, http.StatusOK, w.Code)

		var response struct {
			Count int `json:"count"`
		}
		err := json.NewDecoder(w.Body).Decode(&response)
		assert.NoError(t, err)
		assert.Equal(t, 5, response.Count)
	})
}

func TestLinkGroup(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockGroupsClient := mocks.NewMockClient(ctrl)
	api := &plugintest.API{}

	// Mock required API methods
	api.Mock.On("CreateGroup", &model.Group{}).Return(nil, nil)

	p := &Plugin{
		groupsClient: mockGroupsClient,
		client:       pluginapi.NewClient(api, nil),
	}
	p.SetAPI(api)

	t.Run("unauthorized group link", func(t *testing.T) {
		w := httptest.NewRecorder()
		body := bytes.NewBufferString(`{"remote_id": "remote1"}`)
		r := httptest.NewRequest(http.MethodPost, "/api/v1/groups/link", body)
		r.Header.Set("Mattermost-User-ID", "user1")
		r.Header.Set("Content-Type", "application/json")

		api.Mock.On("HasPermissionTo", "user1", model.PermissionSysconsoleWriteUserManagementGroups).Return(false).Once()

		p.ServeHTTP(nil, w, r)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("successful group link", func(t *testing.T) {
		remoteID := "remote1"
		group := &model.Group{
			DisplayName: "Test Group",
			RemoteId:    &remoteID,
			Source:      model.GroupSourcePluginPrefix + "keycloak",
		}

		api.Mock.On("HasPermissionTo", "user1", model.PermissionSysconsoleWriteUserManagementGroups).Return(true).Once()

		mockGroupsClient.EXPECT().
			GetGroup(gomock.Any(), "remote1").
			Return(group, nil)

		mockGroupsClient.EXPECT().
			GetGroupSource().
			Return(model.GroupSourcePluginPrefix + "keycloak")

		api.Mock.On("GetGroupByRemoteID", "remote1", model.GroupSourcePluginPrefix+"keycloak").Return(group, nil)
		api.Mock.On("UpdateGroup", &model.Group{
			DisplayName: "Test Group",
			RemoteId:    &remoteID,
			Source:      model.GroupSourcePluginPrefix + "keycloak",
		}).Return(group, nil)
		api.Mock.On("CreateGroup", &model.Group{
			DisplayName: "Test Group",
			RemoteId:    &remoteID,
			Source:      model.GroupSourcePluginPrefix + "keycloak",
		}).Return(group, nil)
		api.Mock.On("LogError", mock.Anything, mock.Anything, mock.Anything).Return()

		w := httptest.NewRecorder()
		body := bytes.NewBufferString(`{"remote_id": "remote1"}`)
		r := httptest.NewRequest(http.MethodPost, "/api/v1/groups/link", body)
		r.Header.Set("Mattermost-User-ID", "user1")
		r.Header.Set("Content-Type", "application/json")

		p.ServeHTTP(nil, w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestUnlinkGroup(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockGroupsClient := mocks.NewMockClient(ctrl)
	api := &plugintest.API{}

	// Mock required API methods
	api.Mock.On("CreateGroup", &model.Group{}).Return(nil, nil)

	p := &Plugin{
		groupsClient: mockGroupsClient,
		client:       pluginapi.NewClient(api, nil),
	}
	p.SetAPI(api)

	t.Run("unauthorized group unlink", func(t *testing.T) {
		w := httptest.NewRecorder()
		body := bytes.NewBufferString(`{"remote_id": "remote1"}`)
		r := httptest.NewRequest(http.MethodPost, "/api/v1/groups/unlink", body)
		r.Header.Set("Mattermost-User-ID", "user1")
		r.Header.Set("Content-Type", "application/json")

		api.Mock.On("HasPermissionTo", "user1", model.PermissionSysconsoleWriteUserManagementGroups).Return(false).Once()

		p.ServeHTTP(nil, w, r)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("successful group unlink", func(t *testing.T) {
		remoteID := "remote1"
		group := &model.Group{
			Id:          "group1",
			DisplayName: "Test Group",
			RemoteId:    &remoteID,
			Source:      model.GroupSourcePluginPrefix + "keycloak",
		}

		api.Mock.On("HasPermissionTo", "user1", model.PermissionSysconsoleWriteUserManagementGroups).Return(true).Once()

		mockGroupsClient.EXPECT().
			GetGroupSource().
			Return(model.GroupSourcePluginPrefix + "keycloak")

		// Mock GetByRemoteID
		api.Mock.On("GetGroupByRemoteID", "remote1", model.GroupSourcePluginPrefix+"keycloak").Return(group, nil)

		// Mock Delete call
		deletedGroup := *group
		deletedGroup.DeleteAt = 1234567890
		api.Mock.On("DeleteGroup", "group1").Return(&deletedGroup, nil)

		api.Mock.On("LogError", mock.Anything, mock.Anything, mock.Anything).Return()

		w := httptest.NewRecorder()
		body := bytes.NewBufferString(`{"remote_id": "remote1"}`)
		r := httptest.NewRequest(http.MethodPost, "/api/v1/groups/unlink", body)
		r.Header.Set("Mattermost-User-ID", "user1")
		r.Header.Set("Content-Type", "application/json")

		p.ServeHTTP(nil, w, r)

		assert.Equal(t, http.StatusOK, w.Code)

		var response model.Group
		err := json.NewDecoder(w.Body).Decode(&response)
		assert.NoError(t, err)
		assert.Equal(t, int64(1234567890), response.DeleteAt)
		assert.Equal(t, "group1", response.Id)
	})
}
