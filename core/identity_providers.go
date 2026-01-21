package core

import "SparkProxy/core/identity"

type IdentityProvider = identity.IdentityProvider

func ListIdentityProviders() []identity.IdentityProvider {
	return identity.ListIdentityProviders()
}

func GetIdentityProvider(id string) (identity.IdentityProvider, bool) {
	return identity.GetIdentityProvider(id)
}

func CreateIdentityProvider(name, providerType, clientID, clientSecret, authEndpoint, tokenEndpoint string) (identity.IdentityProvider, error) {
	return identity.CreateIdentityProvider(name, providerType, clientID, clientSecret, authEndpoint, tokenEndpoint)
}

func DeleteIdentityProvider(id string) error {
	return identity.DeleteIdentityProvider(id)
}

func ToggleIdentityProvider(id string, enabled bool) error {
	return identity.ToggleIdentityProvider(id, enabled)
}

func ExchangeOAuthCode(provider identity.IdentityProvider, code, redirectURI string) (*identity.OAuthToken, error) {
	return identity.ExchangeOAuthCode(provider, code, redirectURI)
}

func FetchOAuthUserInfo(provider identity.IdentityProvider, accessToken string) (*identity.OAuthUserInfo, error) {
	return identity.FetchOAuthUserInfo(provider, accessToken)
}
