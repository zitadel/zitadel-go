package provider

import "github.com/zitadel/oidc/v3/pkg/oidc"

type Check[R any] func(resp R) error

func CheckTokenActive(resp *oidc.IntrospectionResponse) error {
	if !resp.Active {
		return ErrInvalidToken
	}
	return nil
}

var _ Check[*oidc.IntrospectionResponse] = CheckTokenActive

func CheckClaimValue(requestedClaim string, requestedValue string) func(resp *oidc.IntrospectionResponse) error {
	return func(resp *oidc.IntrospectionResponse) error {
		if err := CheckTokenActive(resp); err != nil {
			return err
		}

		value, ok := resp.Claims[requestedClaim].(string)
		if !ok || value == "" || value != requestedValue {
			return ErrInvalidAuthorization
		}
		return nil
	}
}

var _ Check[*oidc.IntrospectionResponse] = CheckClaimValue("", "")
