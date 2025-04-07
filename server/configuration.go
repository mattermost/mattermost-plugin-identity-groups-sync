package main

import (
	"encoding/json"
	"reflect"

	"github.com/pkg/errors"

	"github.com/mattermost/mattermost-plugin-groups/server/groups"
	"github.com/mattermost/mattermost-plugin-groups/server/model"
)

// configuration captures the plugin's external configuration as exposed in the Mattermost server
// configuration, as well as values computed from the configuration. Any public fields will be
// deserialized from the Mattermost server configuration in OnConfigurationChange.
//
// As plugins are inherently concurrent (hooks being called asynchronously), and the plugin
// configuration can change at any time, access to the configuration must be synchronized. The
// strategy used in this plugin is to guard a pointer to the configuration, and clone the entire
// struct whenever it changes. You may replace this with whatever strategy you choose.
//
// If you add non-reference types to your configuration struct, be sure to rewrite Clone as a deep
// copy appropriate for your types.
type Configuration struct {
	GroupsProvider string                `json:"groupsprovider"`
	KeycloakConfig model.KeycloakConfigs `json:"keycloakconfig"`
}

func (c *Configuration) ToMap() (map[string]interface{}, error) {
	var out map[string]interface{}
	data, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(data, &out)
	if err != nil {
		return nil, err
	}

	return out, nil
}

// Clone creates a deep copy of the configuration.
func (c *Configuration) Clone() *Configuration {
	var clone = Configuration{
		GroupsProvider: c.GroupsProvider,
		KeycloakConfig: model.KeycloakConfigs{
			Realm:        c.KeycloakConfig.Realm,
			ClientID:     c.KeycloakConfig.ClientID,
			ClientSecret: c.KeycloakConfig.ClientSecret,
			Host:         c.KeycloakConfig.Host,
		},
	}
	return &clone
}

// getConfiguration retrieves the active configuration under lock, making it safe to use
// concurrently. The active configuration may change underneath the client of this method, but
// the struct returned by this API call is considered immutable.
func (p *Plugin) getConfiguration() *Configuration {
	p.configurationLock.RLock()
	defer p.configurationLock.RUnlock()

	if p.configuration == nil {
		return &Configuration{}
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
func (p *Plugin) setConfiguration(configuration *Configuration) {
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
	var configuration = new(Configuration)

	// Load the public configuration fields from the Mattermost server configuration.
	if err := p.API.LoadPluginConfiguration(configuration); err != nil {
		return errors.Wrap(err, "failed to load plugin configuration")
	}

	p.setConfiguration(configuration)

	// Delete the stored JWT token when configuration changes
	// This ensures we'll re-authenticate with the new settings
	if p.kvstore != nil {
		if err := p.client.KV.Delete("keycloak_access_token"); err != nil {
			return errors.Wrap(err, "failed to delete keycloak_access_token")
		}
	}

	if p.groupsClient != nil {
		groupsClient, err := groups.NewClient(p.getConfiguration().GroupsProvider, &p.getConfiguration().KeycloakConfig, p.kvstore, p.client)
		if err != nil {
			return errors.Wrap(err, "failed to create SAML client")
		}
		p.groupsClient = groupsClient
	}

	return nil
}
