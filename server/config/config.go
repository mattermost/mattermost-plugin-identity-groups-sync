package config

import (
	"encoding/json"
)

// Constants for KeycloakMappingType values
const (
	KeycloakMappingTypeGroups = "groups"
	KeycloakMappingTypeRoles  = "roles"
)

// Configuration captures the plugin's external configuration as exposed in the Mattermost server
// configuration, as well as values computed from the configuration.
type Configuration struct {
	GroupsProvider            string `json:"groupsprovider"`
	KeycloakRealm             string `json:"keycloakrealm"`
	KeycloakClientID          string `json:"keycloakclientid"`
	KeycloakClientSecret      string `json:"keycloakclientsecret"`
	KeycloakHost              string `json:"keycloakhost"`
	KeycloakGroupsAttribute   string `json:"keycloakgroupsattribute"`
	KeycloakMappingType       string `json:"keycloakmappingtype"`
	EncryptionKey             string `json:"encryptionkey"`
	FailLoginOnGroupSyncError bool   `json:"failloginongroupsyncerror"`
}

// KeycloakConfig contains all Keycloak-specific configuration
type KeycloakConfig struct {
	Host                      string
	Realm                     string
	ClientID                  string
	ClientSecret              string
	GroupsAttribute           string
	MappingType               string
	EncryptionKey             string
	FailLoginOnGroupSyncError bool
}

// ToMap converts the configuration to a map
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

// GetKeycloakConfig returns all Keycloak-related configuration as a single struct
func (c *Configuration) GetKeycloakConfig() KeycloakConfig {
	return KeycloakConfig{
		Host:                      c.KeycloakHost,
		Realm:                     c.KeycloakRealm,
		ClientID:                  c.KeycloakClientID,
		ClientSecret:              c.KeycloakClientSecret,
		GroupsAttribute:           c.KeycloakGroupsAttribute,
		MappingType:               c.KeycloakMappingType,
		EncryptionKey:             c.EncryptionKey,
		FailLoginOnGroupSyncError: c.FailLoginOnGroupSyncError,
	}
}

// GetGroupsProvider returns the configured groups provider
func (c *Configuration) GetGroupsProvider() string {
	return c.GroupsProvider
}

// Clone creates a deep copy of the configuration.
func (c *Configuration) Clone() *Configuration {
	var clone = &Configuration{
		GroupsProvider:            c.GroupsProvider,
		KeycloakRealm:             c.KeycloakRealm,
		KeycloakClientID:          c.KeycloakClientID,
		KeycloakClientSecret:      c.KeycloakClientSecret,
		KeycloakHost:              c.KeycloakHost,
		KeycloakGroupsAttribute:   c.KeycloakGroupsAttribute,
		KeycloakMappingType:       c.KeycloakMappingType,
		EncryptionKey:             c.EncryptionKey,
		FailLoginOnGroupSyncError: c.FailLoginOnGroupSyncError,
	}
	return clone
}
