package provider

type configuration struct {
	oidc *configurationOIDC
}

type configurationOIDC struct {
	keyPath      string
	clientID     string
	clientSecret string
	insecure     bool
	domain       string
	port         string
	callbackURL  string
	scopes       []string
}

func (c *configurationOIDC) validRS() bool {
	return c.domain != "" &&
		(c.keyPath != "" || (c.clientID != "" && c.clientSecret != ""))
}

func (c *configurationOIDC) validRP() bool {
	return c.domain != "" &&
		c.clientID != "" &&
		c.callbackURL != ""
}

func OIDCConfiguration(domain, port string, insecure bool, keyPath, clientID, clientSecret, callbackURL string, scopes []string) *configuration {
	return &configuration{
		oidc: &configurationOIDC{
			domain:       domain,
			port:         port,
			insecure:     insecure,
			keyPath:      keyPath,
			clientID:     clientID,
			clientSecret: clientSecret,
			callbackURL:  callbackURL,
			scopes:       scopes,
		},
	}
}

func (c *configurationOIDC) getIssuer() string {
	issuerScheme := "https://"
	if c.insecure {
		issuerScheme = "http://"
	}

	issuerPort := c.port
	if c.port == "80" && c.insecure || c.port == "443" && !c.insecure {
		issuerPort = ""
	}

	issuer := issuerScheme + c.domain
	if issuerPort != "" {
		issuer += ":" + issuerPort
	}
	return issuer
}
