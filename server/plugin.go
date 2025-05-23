package main

import (
	"context"
	"sync"
	"time"

	saml2 "github.com/mattermost/gosaml2"
	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"
	"github.com/mattermost/mattermost/server/public/pluginapi"
	"github.com/mattermost/mattermost/server/public/pluginapi/cluster"
	"github.com/pkg/errors"

	"github.com/mattermost/mattermost-plugin-identity-groups-sync/server/config"
	"github.com/mattermost/mattermost-plugin-identity-groups-sync/server/groups"
	"github.com/mattermost/mattermost-plugin-identity-groups-sync/server/store/kvstore"
)

// Plugin implements the interface expected by the Mattermost server to communicate between the server and plugin processes.
type Plugin struct {
	plugin.MattermostPlugin

	// kvstore is the client used to read/write KV records for this plugin.
	kvstore kvstore.KVStore

	// client is the Mattermost server API client.
	client *pluginapi.Client

	// configurationLock synchronizes access to the configuration.
	configurationLock sync.RWMutex

	// configuration is the active plugin configuration. Consult getConfiguration and
	// setConfiguration for usage.
	configuration *config.Configuration

	groupsClient groups.Client

	groupsJob *cluster.Job

	ReSyncMembershipsJob *cluster.JobOnceScheduler
}

// OnActivate is invoked when the plugin is activated. If an error is returned, the plugin will be deactivated.
func (p *Plugin) OnActivate() error {
	// Check for an enterprise license or a development environment
	mmConfig := p.API.GetConfig()
	license := p.API.GetLicense()

	if !pluginapi.IsEnterpriseLicensedOrDevelopment(mmConfig, license) {
		return errors.New("this plugin requires an Enterprise license")
	}

	p.client = pluginapi.NewClient(p.API, p.Driver)

	config := p.getConfiguration()

	// The encryption key should already be set by OnConfigurationChange
	if config.EncryptionKey == "" {
		return errors.New("encryption key is not configured")
	}

	p.kvstore = kvstore.NewKVStore(p.client, config.EncryptionKey)

	groupsClient, err := groups.NewClient(config.GetGroupsProvider(), config, p.kvstore, p.client)
	if err != nil {
		return errors.Wrap(err, "failed to create groups client")
	}
	p.groupsClient = groupsClient

	// Schedule group sync job to run every hour
	job, err := cluster.Schedule(p.API, "SyncGroups", cluster.MakeWaitForInterval(1*time.Hour), func() {
		if err = p.groupsClient.SyncGroupMap(context.Background()); err != nil {
			p.client.Log.Error("Failed to sync groups", "error", err)
		}
	})
	if err != nil {
		return errors.Wrap(err, "failed to schedule group sync job")
	}

	p.groupsJob = job

	p.ReSyncMembershipsJob = cluster.GetJobOnceScheduler(p.API)

	err = p.ReSyncMembershipsJob.SetCallback(p.ReSyncTeamAndChannelMemberships)
	if err != nil {
		return errors.Wrap(err, "failed to set resync memberships job callback")
	}

	err = p.ReSyncMembershipsJob.Start()
	if err != nil {
		return errors.Wrap(err, "failed to start resync memberships job")
	}

	return nil
}

// OnDeactivate is invoked when the plugin is deactivated. This is the plugin's last chance to use
// the API, and the plugin will be terminated seconds after this call.
func (p *Plugin) OnDeactivate() error {
	if p.groupsJob != nil {
		if err := p.groupsJob.Close(); err != nil {
			p.API.LogError("Failed to close background job", "err", err)
		}
	}
	return nil
}

func (p *Plugin) OnSAMLLogin(c *plugin.Context, user *model.User, assertion *saml2.AssertionInfo) error {
	config := p.getConfiguration()

	var groupsAttribute string

	// Use a switch statement to handle different group providers
	switch config.GetGroupsProvider() {
	case "keycloak":
		keycloakConfig := config.GetKeycloakConfig()
		groupsAttribute = keycloakConfig.GroupsAttribute
	default:
		// For other providers or when no provider is configured, do nothing
		p.API.LogDebug("SAML login received but no compatible groups provider configured")
		return nil
	}

	return p.groupsClient.HandleSAMLLogin(c, user, assertion, groupsAttribute)
}

func (p *Plugin) ReSyncTeamAndChannelMemberships(key string, props any) {
	if key == "resync_memberships" {
		p.API.LogDebug("Resyncing team and channel memberships")
		err := p.API.DeleteGroupConstrainedMemberships()
		if err != nil {
			p.API.LogError("Failed to delete group constrained memberships", "error", err)
			return
		}
		params := model.CreateDefaultMembershipParams{
			ReAddRemovedMembers: true,
		}
		err = p.API.CreateDefaultSyncableMemberships(params)
		if err != nil {
			p.API.LogError("Failed to create default syncable memberships", "error", err)
			return
		}
		p.API.LogDebug("Resyncing team and channel memberships completed")
	}
}
