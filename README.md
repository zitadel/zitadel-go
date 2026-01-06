# Go SDK for Zitadel

[![semantic-release](https://img.shields.io/badge/%20%20%F0%9F%93%A6%F0%9F%9A%80-semantic--release-e10079.svg)](https://github.com/semantic-release/semantic-release)
[![Release](https://github.com/zitadel/zitadel-go/workflows/Release/badge.svg)](https://github.com/zitadel/zitadel-go/actions)
[![license](https://badgen.net/github/license/zitadel/zitadel-go/)](https://github.com/zitadel/zitadel-go/blob/main/LICENSE)
[![release](https://badgen.net/github/release/zitadel/zitadel-go/stable)](https://github.com/zitadel/zitadel-go/releases)
[![tag](https://badgen.net/github/tag/zitadel/zitadel-go)](https://github.com/zitadel/zitadel-go/tags)
[![Go Report Card](https://goreportcard.com/badge/github.com/zitadel/zitadel-go)](https://goreportcard.com/report/github.com/zitadel/zitadel-go)
[![codecov](https://codecov.io/gh/zitadel/zitadel-go/branch/main/graph/badge.svg)](https://codecov.io/gh/zitadel/zitadel-go)

This is the Zitadel Go SDK, designed to provide a convenient and idiomatic way to interact with the Zitadel APIs in Go. The SDK provides a seamless wrapping of the Zitadel API, making it easy to authenticate service users and perform API operations.

The SDK enables efficient integration with the Zitadel API, allowing you to manage resources and execute actions.

Additionally, zitadel-go includes a powerful set of Authentication Helpers designed to secure your own Go web applications. This part of the SDK provides convenient HTTP middleware and wrappers that abstract away the complexities of OIDC, making it simple to add an "Login with Zitadel" flow, manage user sessions, and handle callbacks.

These helpers are built as a convenient wrapper around our powerful, low-level [zitadel/oidc](https://github.com/zitadel/oidc) library. For most developers looking to add user login to a Go web application, using these helpers is the recommended approach and should be sufficient.

## Features

- Authentication
- Authorization checks
- Client for Zitadel API

## Usage

Add the package to your `go.mod` by

```bash
go get -u github.com/zitadel/zitadel-go/v3
```
...and check out the [examples](./example) in this repo or head over to
our [docs website](https://zitadel.com/docs/guides/start/quickstart#introduction).

### Implementing Authentication

When adding user authentication to your Go web application, we recommend using the helpers provided directly in this SDK. These helpers are a convenient, high-level wrapper around our powerful, low-level `zitadel/oidc` library and are designed to handle most common use cases, like login flows and session management, right out of the box.

Since we are actively expanding our formal documentation for this feature, the best way to get started is by exploring the working examples we've provided in this repository.

**Web Application Example**

[This example](./example/app) demonstrates how to add a complete OIDC login flow to a standard Go web application. It includes:

-   A home page with a login button.
-   User authentication using the OIDC PKCE Flow.
-   A public page accessible without login.
-   A private page showing user info after login.
-   A logout function.

**API Application Example**

[This example](./example/api) shows how to secure a REST API, where different endpoints require a valid ZITADEL token for access. It includes:

-   A public endpoint accessible without a token.
-   A private endpoint accessible with any valid token.
-   An administrator endpoint accessible only by users with a specific role.

---

### Accessing APIs

The SDK offers [three ways to authenticate with Zitadel](https://zitadel.com/docs/apis/openidoauth/authn-methods). Each method has its
own benefits—choose the one that fits your situation best.

#### 1. Private Key JWT Authentication

**What is it?**
You use a JSON Web Token (JWT) that you sign with a private key stored in a
JSON file. This process creates a secure token.

https://zitadel.com/docs/apis/openidoauth/endpoints#jwt-profile-grant

**When should you use it?**

- **Best for production:** It offers strong security.
- **Advanced control:** You can adjust token settings like expiration.

**How do you use it?**

1. Save your private key in a JSON file.
2. Build the client

**Example:**

```go
package main

import (
	"context"
	"log"
	"os"
	"log/slog"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/zitadel/zitadel-go/v3/pkg/client"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/management"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
)

func main() {
	domain := "https://example.us1.zitadel.cloud"
	keyPath := "path/to/jwt-key.json"

	ctx := context.Background()

	authOption := client.DefaultServiceUserAuthentication(
		keyPath,
		oidc.ScopeOpenID,
		client.ScopeZitadelAPI(),
	)

	api, err := client.New(ctx, zitadel.New(domain), client.WithAuth(authOption))
	if err != nil {
		slog.Error("could not create api client", "error", err)
		os.Exit(1)
	}

	resp, err := api.ManagementService().GetMyOrg(ctx, &management.GetMyOrgRequest{})
	if err != nil {
		slog.Error("gRPC call failed", "error", err)
		os.Exit(1)
	}

	log.Printf("Successfully called API: Your organization is %s", resp.GetOrg().GetName())
}
```

#### 2. Client Credentials Grant

**What is it?**
This method uses a client ID and client secret to get a secure access token,
which is then used to authenticate.

https://zitadel.com/docs/apis/openidoauth/endpoints#client-credentials-grant

**When should you use it?**

- **Simple and straightforward:** Good for server-to-server communication.
- **Trusted environments:** Use it when both servers are owned or trusted.

**How do you use it?**

1. Provide your client ID and client secret.
2. Build the client

**Example:**

```go
package main

import (
	"context"
	"log"
	"os"
	"log/slog"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/zitadel/zitadel-go/v3/pkg/client"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/management"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
)

func main() {
	domain := "https://example.us1.zitadel.cloud"
	clientID := "id"
	clientSecret := "secret"

	ctx := context.Background()

	authOption := client.PasswordAuthentication(
		clientID,
		clientSecret,
		oidc.ScopeOpenID,
		client.ScopeZitadelAPI(),
	)

	api, err := client.New(ctx, zitadel.New(domain), client.WithAuth(authOption))
	if err != nil {
		slog.Error("could not create api client", "error", err)
		os.Exit(1)
	}

	resp, err := api.ManagementService().GetMyOrg(ctx, &management.GetMyOrgRequest{})
	if err != nil {
		slog.Error("gRPC call failed", "error", err)
		os.Exit(1)
	}

	log.Printf("Successfully called API: Your organization is %s", resp.GetOrg().GetName())
}
```

#### 3. Personal Access Tokens (PATs)

**What is it?**
A Personal Access Token (PAT) is a pre-generated token that you can use to
authenticate without exchanging credentials every time.

**When should you use it?**

- **Easy to use:** Great for development or testing scenarios.
- **Quick setup:** No need for dynamic token generation.

**How do you use it?**

1. Obtain a valid personal access token from your account.
2. Build the client

**Example:**

```go
package main

import (
	"context"
	"log"
	"os"
	"log/slog"

	"github.com/zitadel/zitadel-go/v3/pkg/client"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/management"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
)

func main() {
	domain := "https://example.us1.zitadel.cloud"
	token := "token"

	ctx := context.Background()

	authOption := client.PAT(token)

	api, err := client.New(ctx, zitadel.New(domain), client.WithAuth(authOption))
	if err != nil {
		slog.Error("could not create api client", "error", err)
		os.Exit(1)
	}

	resp, err := api.ManagementService().GetMyOrg(ctx, &management.GetMyOrgRequest{})
	if err != nil {
		slog.Error("gRPC call failed", "error", err)
		os.Exit(1)
	}

	log.Printf("Successfully called API: Your organization is %s", resp.GetOrg().GetName())
}
```

---

Choose the authentication method that best suits your needs based on your
environment and security requirements. For more details, please refer to the
[Zitadel documentation on authenticating service users](https://zitadel.com/docs/guides/integrate/service-users/authenticate-service-users).

### Versions

If you're looking for older version of this module, please check out the following tags:

- v3.x.x is maintained on the [main](https://github.com/zitadel/zitadel-go/tree/main) branch
- [v2.2.8](https://github.com/zitadel/zitadel-go/releases/tag/v2.2.8) is the last release for the v2 Go module
- [v0.3.5](https://github.com/zitadel/zitadel-go/releases/tag/v0.3.5) is the last release for the v0/v1 Go module

Currently only v3 is supported, due to some security updates that involve breaking changes. Therefore v2 and older will
no longer be supported.

## Supported Go Versions

For security reasons, we only support and recommend the use of one of the latest two Go versions (:white_check_mark:).
Versions that also build are marked with :warning:.

| Version | Supported          |
|---------|--------------------|
| <1.24   | :x:                |
| 1.24    | :white_check_mark: |
| 1.25    | :white_check_mark: |

## License

The full functionality of this library is and stays open source and free to use for everyone. Visit
our [website](https://zitadel.com) and get in touch.

See the exact licensing terms [here](./LICENSE)

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "
AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
language governing permissions and limitations under the License.

## Contributors

<a href="https://github.com/zitadel/zitadel-go/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=zitadel/zitadel-go" />
</a>
