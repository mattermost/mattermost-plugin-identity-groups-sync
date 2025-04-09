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

func (p *Plugin) respondWithError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	response := map[string]string{"error": message}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		p.API.LogError("Error encoding error response", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (p *Plugin) ServeHTTP(c *plugin.Context, w http.ResponseWriter, r *http.Request) {
	router := mux.NewRouter()

	// Set content type for all responses
	w.Header().Set("Content-Type", "application/json")

	userID := r.Header.Get("Mattermost-User-ID")
	if userID == "" {
		p.respondWithError(w, http.StatusUnauthorized, "Not authorized")
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
	w.Header().Set("Content-Type", "application/json")

	userID := r.Header.Get("Mattermost-User-ID")
	if !p.client.User.HasPermissionTo(userID, model.PermissionSysconsoleReadUserManagementGroups) {
		p.respondWithError(w, http.StatusForbidden, "Not authorized")
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

	q := query.Get("q")

	// Validate search query
	if len(q) > 255 {
		p.respondWithError(w, http.StatusBadRequest, "Search query too long (max 255 characters)")
		return
	}

	groupsQuery := groups.Query{
		Page:    page,
		PerPage: perPage,
		Q:       q,
	}
	samlGroups, err := p.groupsClient.GetGroups(r.Context(), groupsQuery)
	if err != nil {
		p.API.LogError("Failed to fetch groups", "error", err)
		p.respondWithError(w, http.StatusInternalServerError, "Failed to fetch groups")
		return
	}

	groups := []*model.Group{}
	// Check if each group exists in Mattermost
	for _, group := range samlGroups {
		mmGroup, _ := p.client.Group.GetByRemoteID(*group.RemoteId, p.groupsClient.GetGroupSource())
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

	if err := json.NewEncoder(w).Encode(response); err != nil {
		p.API.LogError("Failed to write response", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (p *Plugin) UnlinkGroup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	userID := r.Header.Get("Mattermost-User-ID")
	if !p.client.User.HasPermissionTo(userID, model.PermissionSysconsoleWriteUserManagementGroups) {
		p.respondWithError(w, http.StatusForbidden, "Not authorized")
		return
	}

	var req struct {
		RemoteID string `json:"remote_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		p.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.RemoteID == "" {
		p.respondWithError(w, http.StatusBadRequest, "remote_id is required")
		return
	}

	// Get the group from Mattermost by remote ID
	existingGroup, err := p.client.Group.GetByRemoteID(req.RemoteID, p.groupsClient.GetGroupSource())
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			p.respondWithError(w, http.StatusNotFound, "Group not found")
			return
		}
		p.API.LogError("Failed to get group", "error", err)
		p.respondWithError(w, http.StatusInternalServerError, "Failed to get group")
		return
	}

	updatedGroup, err := p.client.Group.Delete(existingGroup.Id)
	if err != nil {
		p.API.LogError("Failed to delete group", "error", err, "group_id", existingGroup.Id)
		p.respondWithError(w, http.StatusInternalServerError, "Failed to delete group")
		return
	}

	if err := json.NewEncoder(w).Encode(updatedGroup); err != nil {
		p.API.LogError("Failed to write response", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (p *Plugin) LinkGroup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	userID := r.Header.Get("Mattermost-User-ID")
	if !p.client.User.HasPermissionTo(userID, model.PermissionSysconsoleWriteUserManagementGroups) {
		p.respondWithError(w, http.StatusForbidden, "Not authorized")
		return
	}

	var req struct {
		RemoteID string `json:"remote_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		p.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.RemoteID == "" {
		p.respondWithError(w, http.StatusBadRequest, "remote_id is required")
		return
	}

	// Get the group from SAML provider
	samlGroup, err := p.groupsClient.GetGroup(r.Context(), req.RemoteID)
	if err != nil {
		p.API.LogError("Failed to fetch group from SAML provider", "error", err)
		p.respondWithError(w, http.StatusInternalServerError, "Failed to fetch group from SAML provider")
		return
	}

	// Try to get existing group from Mattermost
	existingGroup, err := p.client.Group.GetByRemoteID(req.RemoteID, p.groupsClient.GetGroupSource())
	if err != nil && !strings.Contains(err.Error(), "not found") {
		p.API.LogError("Failed to check existing group", "error", err)
		p.respondWithError(w, http.StatusInternalServerError, "Failed to check existing group")
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
			p.respondWithError(w, http.StatusInternalServerError, "Failed to update group")
			return
		}
	} else {
		// Create new group
		resultGroup, err = p.client.Group.Create(samlGroup)
		if err != nil {
			p.API.LogError("Failed to create group", "error", err)
			p.respondWithError(w, http.StatusInternalServerError, "Failed to create group")
			return
		}
	}

	if err := json.NewEncoder(w).Encode(resultGroup); err != nil {
		p.API.LogError("Failed to write response", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (p *Plugin) GetGroupsCount(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	userID := r.Header.Get("Mattermost-User-ID")
	if !p.client.User.HasPermissionTo(userID, model.PermissionSysconsoleReadUserManagementGroups) {
		p.respondWithError(w, http.StatusForbidden, "Not authorized")
		return
	}

	query := r.URL.Query()
	q := query.Get("q")

	// Validate search query
	if len(q) > 255 {
		p.respondWithError(w, http.StatusBadRequest, "Search query too long (max 255 characters)")
		return
	}

	count, err := p.groupsClient.GetGroupsCount(r.Context(), q)
	if err != nil {
		p.API.LogError("Failed to fetch groups count", "error", err)
		p.respondWithError(w, http.StatusInternalServerError, "Failed to fetch groups count")
		return
	}

	response := struct {
		Count int `json:"count"`
	}{
		Count: count,
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		p.API.LogError("Failed to write response", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
