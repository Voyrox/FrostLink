package identity

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type OAuthToken struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

type OAuthUserInfo struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Username string `json:"username"`
	Avatar   string `json:"avatar"`
}

func getStringFromMap(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func ExchangeOAuthCode(provider IdentityProvider, code, redirectURI string) (*OAuthToken, error) {
	if provider.TokenEndpoint == "" {
		return nil, errors.New("provider does not support token exchange")
	}

	data := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {redirectURI},
	}

	credentials := provider.ClientID + ":" + provider.ClientSecret
	encoded := base64.StdEncoding.EncodeToString([]byte(credentials))

	req, err := http.NewRequest("POST", provider.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Basic "+encoded)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token exchange failed: %s", string(body))
	}

	var token OAuthToken
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	return &token, nil
}

func FetchOAuthUserInfo(provider IdentityProvider, accessToken string) (*OAuthUserInfo, error) {
	var userInfoURL string
	if provider.ProviderType == "google" {
		userInfoURL = "https://www.googleapis.com/oauth2/v2/userinfo"
	} else {
		userInfoURL = "https://discord.com/api/users/@me"
	}

	req, err := http.NewRequest("GET", userInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get user info: %s", string(body))
	}

	body, _ := io.ReadAll(resp.Body)

	var rawData map[string]interface{}
	if err := json.Unmarshal(body, &rawData); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	var userInfo OAuthUserInfo
	if provider.ProviderType == "google" {
		userInfo.ID = getStringFromMap(rawData, "id")
		userInfo.Email = getStringFromMap(rawData, "email")
		userInfo.Username = getStringFromMap(rawData, "name")
		userInfo.Avatar = getStringFromMap(rawData, "picture")
	} else {
		userInfo.ID = getStringFromMap(rawData, "id")
		userInfo.Email = getStringFromMap(rawData, "email")
		userInfo.Username = getStringFromMap(rawData, "username")
		userInfo.Avatar = getStringFromMap(rawData, "avatar")
	}

	return &userInfo, nil
}
