package model

// JWT extends gocloak.JWT with expiration times
type JWT struct {
	AccessToken      string `json:"access_token,omitempty"`
	ExpiresIn        int    `json:"expires_in,omitempty"`
	RefreshToken     string `json:"refresh_token,omitempty"`
	RefreshExpiresIn int    `json:"refresh_expires_in,omitempty"`
	TokenType        string `json:"token_type,omitempty"`
	NotBeforePolicy  int    `json:"not-before-policy,omitempty"`
	SessionState     string `json:"session_state,omitempty"`
	Scope            string `json:"scope,omitempty"`

	AccessTokenExpirationTime  int64 `json:"access_token_expiration_time,omitempty"`
	RefreshTokenExpirationTime int64 `json:"refresh_token_expiration_time,omitempty"`
}

// KeycloakConfigs holds the configuration for Keycloak integration
type KeycloakConfigs struct {
	Realm           string
	ClientID        string
	ClientSecret    string
	Host            string
	GroupsAttribute string
}
