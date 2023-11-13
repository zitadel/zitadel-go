package provider

type configuration struct {
	oidc *configurationOIDC
}

type configurationOIDC struct {
	keyPath      string
	clientID     string
	clientSecret string
	insecure     bool
	issuer       string
	callbackURL  string
	scopes       []string
	cookieKey    []byte
}

func (c *configurationOIDC) validRS() bool {
	return c.issuer != "" &&
		(c.keyPath != "" || (c.clientID != "" && c.clientSecret != ""))
}

func (c *configurationOIDC) validRP() bool {
	return c.issuer != "" &&
		c.clientID != "" &&
		c.callbackURL != ""
}

func OIDCConfiguration(issuer string, insecure bool, keyPath, clientID, clientSecret, callbackURL string, scopes []string, cookieKey []byte) *configuration {
	return &configuration{
		oidc: &configurationOIDC{
			issuer:       issuer,
			insecure:     insecure,
			keyPath:      keyPath,
			clientID:     clientID,
			clientSecret: clientSecret,
			callbackURL:  callbackURL,
			scopes:       scopes,
			cookieKey:    cookieKey,
		},
	}
}
