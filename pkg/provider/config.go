package provider

type configuration struct {
	oidc *configurationOIDC
	saml *configurationSAML
}

type configurationOIDC struct {
	issuer       string
	keyPath      string
	clientID     string
	clientSecret string
	port         string
	callbackURL  string
	scopes       []string
}

func (c *configurationOIDC) validRS() bool {
	return c.issuer != "" && c.keyPath != ""
}

func (c *configurationOIDC) validRP() bool {
	return c.issuer != "" && c.clientID != "" && c.port != "" && c.callbackURL != ""
}

type configurationSAML struct{}

func OIDCProviderConfiguration(issuer, keyPath, clientID, clientSecret, port, callbackURL string, scopes []string) *configuration {
	return &configuration{
		oidc: &configurationOIDC{
			issuer:       issuer,
			keyPath:      keyPath,
			clientID:     clientID,
			clientSecret: clientSecret,
			port:         port,
			callbackURL:  callbackURL,
			scopes:       scopes,
		},
	}
}

func SAMLProviderConfiguration() *configuration {
	return &configuration{
		saml: &configurationSAML{},
	}
}
