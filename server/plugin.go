package main

import (
	"sync"

	"github.com/mattermost/mattermost-plugin-groups/server/groups"
	"github.com/mattermost/mattermost-plugin-groups/server/store/kvstore"
	"github.com/mattermost/mattermost/server/public/plugin"
	"github.com/mattermost/mattermost/server/public/pluginapi"
	"github.com/pkg/errors"
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
	configuration *Configuration

	groupsClient groups.Client
}

// OnActivate is invoked when the plugin is activated. If an error is returned, the plugin will be deactivated.
func (p *Plugin) OnActivate() error {
	p.client = pluginapi.NewClient(p.API, p.Driver)
	p.kvstore = kvstore.NewKVStore(p.client)

	groupsClient, err := groups.NewClient(p.getConfiguration().GroupsProvider, &p.getConfiguration().KeycloakConfig, p.kvstore, p.client)
	if err != nil {
		return errors.Wrap(err, "failed to create groups client")
	}
	p.groupsClient = groupsClient

	return nil
}
