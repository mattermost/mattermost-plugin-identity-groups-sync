package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"github.com/mattermost/mattermost-plugin-groups/server/groups"
	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"
)

// ServeHTTP demonstrates a plugin that handles HTTP requests by greeting the world.
// The root URL is currently <siteUrl>/plugins/com.mattermost.plugin-starter-template/api/v1/. Replace com.mattermost.plugin-starter-template with the plugin ID.
func (p *Plugin) ServeHTTP(c *plugin.Context, w http.ResponseWriter, r *http.Request) {
	router := mux.NewRouter()

	userID := r.Header.Get("Mattermost-User-ID")
	if userID == "" {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	apiRouter := router.PathPrefix("/api/v1").Subrouter()

	apiRouter.HandleFunc("/groups", p.GetGroups).Methods(http.MethodGet)
	apiRouter.HandleFunc("/groups/count", p.GetGroupsCount).Methods(http.MethodGet)
	apiRouter.HandleFunc("/groups/link", p.LinkGroup).Methods(http.MethodPost)
	apiRouter.HandleFunc("/groups/unlink", p.UnlinkGroup).Methods(http.MethodPost)

	router.ServeHTTP(w, r)
}

func (p *Plugin) GetGroups(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("Mattermost-User-ID")
	if !p.client.User.HasPermissionTo(userID, model.PermissionSysconsoleReadUserManagementGroups) {
		http.Error(w, "Not authorized", http.StatusForbidden)
		return
	}

	query := r.URL.Query()
	page := 0
	perPage := 100 // default value

	if pageStr := query.Get("page"); pageStr != "" {
		if parsedPage, err := strconv.Atoi(pageStr); err == nil && parsedPage >= 0 {
			page = parsedPage
		}
	}

	if perPageStr := query.Get("perPage"); perPageStr != "" {
		if parsedPerPage, err := strconv.Atoi(perPageStr); err == nil && parsedPerPage > 0 {
			perPage = parsedPerPage
		}
	}

	search := query.Get("search")
	groupsQuery := groups.Query{
		Page:    page,
		PerPage: perPage,
		Search:  search,
	}
	samlGroups, err := p.groupsClient.GetGroups(r.Context(), groupsQuery)
	if err != nil {
		p.API.LogError("Failed to fetch groups", "error", err)
		http.Error(w, "Failed to fetch groups", http.StatusInternalServerError)
		return
	}

	groups := []*model.Group{}
	// Check if each group exists in Mattermost
	for _, group := range samlGroups {
		mmGroup, _ := p.client.Group.GetByRemoteID(*group.RemoteId, model.GroupSourcePluginPrefix+"keycloak")
		if mmGroup != nil {
			group.Id = mmGroup.Id
			group.AllowReference = mmGroup.AllowReference
			group.DeleteAt = mmGroup.DeleteAt
			group.CreateAt = mmGroup.CreateAt
			group.UpdateAt = mmGroup.UpdateAt
		}

		groups = append(groups, group)
	}

	response := struct {
		Groups []*model.Group `json:"groups"`
		Count  int            `json:"total_count"`
	}{
		Groups: groups,
		Count:  len(groups),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		p.API.LogError("Failed to write response", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (p *Plugin) UnlinkGroup(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("Mattermost-User-ID")
	if !p.client.User.HasPermissionTo(userID, model.PermissionSysconsoleWriteUserManagementGroups) {
		http.Error(w, "Not authorized", http.StatusForbidden)
		return
	}

	var req struct {
		RemoteID string `json:"remote_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.RemoteID == "" {
		http.Error(w, "remote_id is required", http.StatusBadRequest)
		return
	}

	// Get the group from Mattermost by remote ID
	existingGroup, err := p.client.Group.GetByRemoteID(req.RemoteID, model.GroupSourcePluginPrefix+"keycloak")
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			http.Error(w, "Group not found", http.StatusNotFound)
			return
		}
		p.API.LogError("Failed to get group", "error", err)
		http.Error(w, "Failed to get group", http.StatusInternalServerError)
		return
	}

	updatedGroup, err := p.client.Group.Delete(existingGroup.Id)
	if err != nil {
		p.API.LogError("Failed to delete group", "error", err, "group_id", existingGroup.Id)
		http.Error(w, "Failed to delete group", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(updatedGroup); err != nil {
		p.API.LogError("Failed to write response", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (p *Plugin) LinkGroup(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("Mattermost-User-ID")
	if !p.client.User.HasPermissionTo(userID, model.PermissionSysconsoleWriteUserManagementGroups) {
		http.Error(w, "Not authorized", http.StatusForbidden)
		return
	}

	var req struct {
		RemoteID string `json:"remote_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.RemoteID == "" {
		http.Error(w, "remote_id is required", http.StatusBadRequest)
		return
	}

	// Get the group from SAML provider
	samlGroup, err := p.groupsClient.GetGroup(r.Context(), req.RemoteID)
	if err != nil {
		p.API.LogError("Failed to fetch group from SAML provider", "error", err)
		http.Error(w, "Failed to fetch group from SAML provider", http.StatusInternalServerError)
		return
	}

	// Try to get existing group from Mattermost
	existingGroup, err := p.client.Group.GetByRemoteID(req.RemoteID, model.GroupSourcePluginPrefix+"keycloak")
	if err != nil && !strings.Contains(err.Error(), "not found") {
		p.API.LogError("Failed to check existing group", "error", err)
		http.Error(w, "Failed to check existing group", http.StatusInternalServerError)
		return
	}

	var resultGroup *model.Group
	if existingGroup != nil {
		// Update existing group
		existingGroup.DisplayName = samlGroup.DisplayName
		existingGroup.DeleteAt = 0 // Undelete the group if it was deleted

		resultGroup, err = p.client.Group.Update(existingGroup)
		if err != nil {
			p.API.LogError("Failed to update group", "error", err)
			http.Error(w, "Failed to update group", http.StatusInternalServerError)
			return
		}
	} else {
		// Create new group
		resultGroup, err = p.client.Group.Create(samlGroup)
		if err != nil {
			p.API.LogError("Failed to create group", "error", err)
			http.Error(w, "Failed to create group", http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resultGroup); err != nil {
		p.API.LogError("Failed to write response", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (p *Plugin) GetGroupsCount(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("Mattermost-User-ID")
	if !p.client.User.HasPermissionTo(userID, model.PermissionSysconsoleReadUserManagementGroups) {
		http.Error(w, "Not authorized", http.StatusForbidden)
		return
	}

	count, err := p.groupsClient.GetGroupsCount(r.Context())
	if err != nil {
		p.API.LogError("Failed to fetch groups count", "error", err)
		http.Error(w, "Failed to fetch groups count", http.StatusInternalServerError)
		return
	}

	response := struct {
		Count int `json:"count"`
	}{
		Count: count,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		p.API.LogError("Failed to write response", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
