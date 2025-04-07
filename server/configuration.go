package main

import (
	"reflect"

	"github.com/pkg/errors"

	"github.com/mattermost/mattermost-plugin-groups/server/config"
	"github.com/mattermost/mattermost-plugin-groups/server/groups"
)

// getConfiguration retrieves the active configuration under lock, making it safe to use
// concurrently. The active configuration may change underneath the client of this method, but
// the struct returned by this API call is considered immutable.
func (p *Plugin) getConfiguration() *config.Configuration {
	p.configurationLock.RLock()
	defer p.configurationLock.RUnlock()

	if p.configuration == nil {
		return &config.Configuration{}
	}

	return p.configuration
}

// setConfiguration replaces the active configuration under lock.
//
// Do not call setConfiguration while holding the configurationLock, as sync.Mutex is not
// reentrant. In particular, avoid using the plugin API entirely, as this may in turn trigger a
// hook back into the plugin. If that hook attempts to acquire this lock, a deadlock may occur.
//
// This method panics if setConfiguration is called with the existing configuration. This almost
// certainly means that the configuration was modified without being cloned and may result in
// an unsafe access.
func (p *Plugin) setConfiguration(configuration *config.Configuration) {
	p.configurationLock.Lock()
	defer p.configurationLock.Unlock()

	if configuration != nil && p.configuration == configuration {
		// Ignore assignment if the configuration struct is empty. Go will optimize the
		// allocation for same to point at the same memory address, breaking the check
		// above.
		if reflect.ValueOf(*configuration).NumField() == 0 {
			return
		}

		panic("setConfiguration called with the existing configuration")
	}

	p.configuration = configuration
}

// OnConfigurationChange is invoked when configuration changes may have been made.
func (p *Plugin) OnConfigurationChange() error {
	var configuration = new(config.Configuration)

	// Load the public configuration fields from the Mattermost server configuration.
	if err := p.API.LoadPluginConfiguration(configuration); err != nil {
		return errors.Wrap(err, "failed to load plugin configuration")
	}

	p.setConfiguration(configuration)

	// Delete the stored JWT token when configuration changes
	// This ensures we'll re-authenticate with the new settings
	if p.kvstore != nil {
		if err := p.client.KV.Delete("keycloak_access_token"); err != nil {
			p.API.LogWarn("Failed to delete stored JWT token", "error", err)
		}
	}

	if p.groupsClient != nil {
		config := p.getConfiguration()
		groupsClient, err := groups.NewClient(config.GetGroupsProvider(), config, p.kvstore, p.client)
		if err != nil {
			return errors.Wrap(err, "failed to create SAML client")
		}
		p.groupsClient = groupsClient
	}

	return nil
}
