package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/exp/slices"

	"github.com/bitly/go-simplejson"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/util"
)

// AzureProvider represents an Azure based Identity Provider
type AzureProvider struct {
	*ProviderData
	Tenant          string
	GraphGroupField string
	isV2Endpoint    bool
}

// AccessToken represents a client_credentials flow access token for oauth2-proxy to read groups from Microsoft Graph w/ application permissions
type AccessToken struct {
	TokenType   string `json:"token_type"`
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
	Expiry      time.Time
}

// Simple cache for group lookups
type GroupCache struct {
	items map[string]GroupCacheItem
	mu    sync.RWMutex
}

type GroupCacheItem struct {
	Groups []string
	Expiry time.Time
}

var _ Provider = (*AzureProvider)(nil)

const (
	azureProviderName           = "Azure"
	azureDefaultScope           = "openid"
	azureDefaultGraphGroupField = "id"
	groupCacheTTL               = 5 * time.Minute
)

var (
	// Default Login URL for Azure. Pre-parsed URL of https://login.microsoftonline.com/common/oauth2/authorize.
	azureDefaultLoginURL = &url.URL{
		Scheme: "https",
		Host:   "login.microsoftonline.com",
		Path:   "/common/oauth2/authorize",
	}

	// Default Redeem URL for Azure. Pre-parsed URL of https://login.microsoftonline.com/common/oauth2/token.
	azureDefaultRedeemURL = &url.URL{
		Scheme: "https",
		Host:   "login.microsoftonline.com",
		Path:   "/common/oauth2/token",
	}

	// Default Profile URL for Azure. Pre-parsed URL of https://graph.microsoft.com/v1.0/me.
	azureDefaultProfileURL = &url.URL{
		Scheme: "https",
		Host:   "graph.microsoft.com",
		Path:   "/v1.0/me",
	}

	// Simple cache so that we don't request a new access token for every request
	cachedAccessToken *AccessToken
	accessTokenMutex  sync.Mutex

	// Simple cache so that we don't lookup groups on every request
	groupCache = &GroupCache{
		items: make(map[string]GroupCacheItem),
	}
)

// NewAzureProvider initiates a new AzureProvider
func NewAzureProvider(p *ProviderData, opts options.AzureOptions) *AzureProvider {
	p.setProviderDefaults(providerDefaults{
		name:        azureProviderName,
		loginURL:    azureDefaultLoginURL,
		redeemURL:   azureDefaultRedeemURL,
		profileURL:  azureDefaultProfileURL,
		validateURL: nil,
		scope:       azureDefaultScope,
	})

	if p.ValidateURL == nil || p.ValidateURL.String() == "" {
		p.ValidateURL = p.ProfileURL
	}
	p.getAuthorizationHeaderFunc = makeAzureHeader

	tenant := "common"
	if opts.Tenant != "" {
		tenant = opts.Tenant
		overrideTenantURL(p.LoginURL, azureDefaultLoginURL, tenant, "authorize")
		overrideTenantURL(p.RedeemURL, azureDefaultRedeemURL, tenant, "token")
	}

	graphGroupField := azureDefaultGraphGroupField
	if opts.GraphGroupField != "" {
		graphGroupField = opts.GraphGroupField
	}

	isV2Endpoint := false
	if strings.Contains(p.LoginURL.String(), "v2.0") {
		isV2Endpoint = true

		// /start:DELETED - hardcoding `https://graph.microsoft.com/.default` is a bad value that unnecessarily breaks auth flows
		// azureV2GraphScope := fmt.Sprintf("https://%s/.default", p.ProfileURL.Host)

		// if strings.Contains(p.Scope, " groups") {
		// 	logger.Print("WARNING: `groups` scope is not an accepted scope when using Azure OAuth V2 endpoint. Removing it from the scope list")
		// 	p.Scope = strings.ReplaceAll(p.Scope, " groups", "")
		// }

		// if !strings.Contains(p.Scope, " "+azureV2GraphScope) {
		// 	// In order to be able to query MS Graph we must pass the ms graph default endpoint
		// 	p.Scope += " " + azureV2GraphScope
		// }
		// /end:DELETED

		if p.ProtectedResource != nil && p.ProtectedResource.String() != "" {
			logger.Print("WARNING: `--resource` option has no effect when using the Azure OAuth V2 endpoint.")
		}
	}

	return &AzureProvider{
		ProviderData:    p,
		Tenant:          tenant,
		GraphGroupField: graphGroupField,
		isV2Endpoint:    isV2Endpoint,
	}
}

func overrideTenantURL(current, defaultURL *url.URL, tenant, path string) {
	if current == nil || current.String() == "" || current.String() == defaultURL.String() {
		*current = url.URL{
			Scheme: "https",
			Host:   current.Host,
			Path:   "/" + tenant + "/oauth2/" + path}
	}
}

func getMicrosoftGraphGroupsURL(profileURL *url.URL, graphGroupField string) *url.URL {

	selectStatement := "$select=displayName,id"
	if !slices.Contains([]string{"displayName", "id"}, graphGroupField) {
		selectStatement += "," + graphGroupField
	}

	// Select only security groups. Due to the filter option, count param is mandatory even if unused otherwise
	return &url.URL{
		Scheme:   "https",
		Host:     profileURL.Host,
		Path:     "/v1.0/me/transitiveMemberOf",
		RawQuery: "$count=true&$filter=securityEnabled+eq+true&" + selectStatement,
	}
}

func (p *AzureProvider) GetLoginURL(redirectURI, state, _ string, extraParams url.Values) string {
	// In azure oauth v2 there is no resource param so add it only if V1 endpoint
	// https://docs.microsoft.com/en-us/azure/active-directory/azuread-dev/azure-ad-endpoint-comparison#scopes-not-resources
	if p.ProtectedResource != nil && p.ProtectedResource.String() != "" && !p.isV2Endpoint {
		extraParams.Add("resource", p.ProtectedResource.String())
	}
	a := makeLoginURL(p.ProviderData, redirectURI, state, extraParams)
	return a.String()
}

// Redeem exchanges the OAuth2 authentication token for an ID token
func (p *AzureProvider) Redeem(ctx context.Context, redirectURL, code, codeVerifier string) (*sessions.SessionState, error) {
	params, err := p.prepareRedeem(redirectURL, code, codeVerifier)
	if err != nil {
		return nil, err
	}

	// blindly try json and x-www-form-urlencoded
	var jsonResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresOn    int64  `json:"expires_on,string"`
		IDToken      string `json:"id_token"`
	}

	err = requests.New(p.RedeemURL.String()).
		WithContext(ctx).
		WithMethod("POST").
		WithBody(bytes.NewBufferString(params.Encode())).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Do().
		UnmarshalInto(&jsonResponse)
	if err != nil {
		return nil, err
	}

	session := &sessions.SessionState{
		AccessToken:  jsonResponse.AccessToken,
		IDToken:      jsonResponse.IDToken,
		RefreshToken: jsonResponse.RefreshToken,
	}
	session.CreatedAtNow()
	session.SetExpiresOn(time.Unix(jsonResponse.ExpiresOn, 0))

	err = p.extractClaimsIntoSession(ctx, session)

	if err != nil {
		return nil, fmt.Errorf("unable to get email and/or groups claims from token: %v", err)
	}

	return session, nil
}

// EnrichSession enriches the session state with userID, mail and groups
func (p *AzureProvider) EnrichSession(ctx context.Context, session *sessions.SessionState) error {
	err := p.extractClaimsIntoSession(ctx, session)

	if err != nil {
		logger.Printf("unable to get email and/or groups claims from token: %v", err)
	}

	if session.Email == "" {
		email, err := p.getEmailFromProfileAPI(ctx, session.AccessToken)
		if err != nil {
			return fmt.Errorf("unable to get email address from profile URL: %v", err)
		}
		session.Email = email
	}

	// If using the v2.0 oidc endpoint we're also querying Microsoft Graph
	if p.isV2Endpoint {
		groups, err := p.getGroupsFromProfileAPI(ctx, session)
		if err != nil {
			return fmt.Errorf("unable to get groups from Microsoft Graph: %v", err)
		}
		session.Groups = util.RemoveDuplicateStr(append(session.Groups, groups...))
	}
	return nil
}

func (p *AzureProvider) prepareRedeem(redirectURL, code, codeVerifier string) (url.Values, error) {
	params := url.Values{}
	if code == "" {
		return params, ErrMissingCode
	}
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return params, err
	}

	params.Add("redirect_uri", redirectURL)
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", clientSecret)
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")
	if codeVerifier != "" {
		params.Add("code_verifier", codeVerifier)
	}

	// In azure oauth v2 there is no resource param so add it only if V1 endpoint
	// https://docs.microsoft.com/en-us/azure/active-directory/azuread-dev/azure-ad-endpoint-comparison#scopes-not-resources
	if p.ProtectedResource != nil && p.ProtectedResource.String() != "" && !p.isV2Endpoint {
		params.Add("resource", p.ProtectedResource.String())
	}

	return params, nil
}

// extractClaimsIntoSession tries to extract email and groups claims from either id_token or access token
// when oidc verifier is configured
func (p *AzureProvider) extractClaimsIntoSession(ctx context.Context, session *sessions.SessionState) error {

	var s *sessions.SessionState

	// First let's verify session token
	if err := p.verifySessionToken(ctx, session); err != nil {
		return fmt.Errorf("unable to verify token: %v", err)
	}

	// https://github.com/oauth2-proxy/oauth2-proxy/pull/914#issuecomment-782285814
	// https://github.com/AzureAD/azure-activedirectory-library-for-java/issues/117
	// due to above issues, id_token may not be signed by AAD
	// in that case, we will fallback to access token
	var err error
	s, err = p.buildSessionFromClaims(session.IDToken, session.AccessToken)
	if err != nil || s.Email == "" {
		s, err = p.buildSessionFromClaims(session.AccessToken, session.AccessToken)
	}
	if err != nil {
		return fmt.Errorf("unable to get claims from token: %v", err)
	}

	session.Email = s.Email
	if s.Groups != nil {
		session.Groups = s.Groups
	}

	return nil
}

// verifySessionToken tries to validate id_token if present or access token when oidc verifier is configured
func (p *AzureProvider) verifySessionToken(ctx context.Context, session *sessions.SessionState) error {
	// Without a verifier there's no way to verify
	if p.Verifier == nil {
		return nil
	}

	if session.IDToken != "" {
		if _, err := p.Verifier.Verify(ctx, session.IDToken); err != nil {
			logger.Printf("unable to verify ID token, fallback to access token: %v", err)
			if _, err = p.Verifier.Verify(ctx, session.AccessToken); err != nil {
				return fmt.Errorf("unable to verify access token: %v", err)
			}
		}
	} else if _, err := p.Verifier.Verify(ctx, session.AccessToken); err != nil {
		return fmt.Errorf("unable to verify access token: %v", err)
	}
	return nil
}

// RefreshSession uses the RefreshToken to fetch new Access and ID Tokens
func (p *AzureProvider) RefreshSession(ctx context.Context, s *sessions.SessionState) (bool, error) {
	if s == nil || s.RefreshToken == "" {
		return false, nil
	}

	err := p.redeemRefreshToken(ctx, s)
	if err != nil {
		return false, fmt.Errorf("unable to redeem refresh token: %v", err)
	}

	return true, nil
}

func (p *AzureProvider) redeemRefreshToken(ctx context.Context, s *sessions.SessionState) error {
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return err
	}

	params := url.Values{}
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", clientSecret)
	params.Add("refresh_token", s.RefreshToken)
	params.Add("grant_type", "refresh_token")

	var jsonResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresOn    int64  `json:"expires_on,string"`
		IDToken      string `json:"id_token"`
	}

	err = requests.New(p.RedeemURL.String()).
		WithContext(ctx).
		WithMethod("POST").
		WithBody(bytes.NewBufferString(params.Encode())).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Do().
		UnmarshalInto(&jsonResponse)
	if err != nil {
		return err
	}

	s.AccessToken = jsonResponse.AccessToken
	s.IDToken = jsonResponse.IDToken
	s.RefreshToken = jsonResponse.RefreshToken

	s.CreatedAtNow()
	s.SetExpiresOn(time.Unix(jsonResponse.ExpiresOn, 0))

	err = p.extractClaimsIntoSession(ctx, s)

	if err != nil {
		logger.Printf("unable to get email and/or groups claims from token: %v", err)
	}

	return nil
}

func makeAzureHeader(accessToken string) http.Header {
	return makeAuthorizationHeader(tokenTypeBearer, accessToken, nil)
}

func (p *AzureProvider) getGroupsFromProfileAPI(ctx context.Context, s *sessions.SessionState) ([]string, error) {
	if s.AccessToken == "" {
		return nil, fmt.Errorf("missing access token")
	}

	groupsURL := getMicrosoftGraphGroupsURL(p.ProfileURL, p.GraphGroupField).String()

	// Need and extra header while talking with MS Graph. For more context see
	// https://docs.microsoft.com/en-us/graph/api/group-list-transitivememberof?view=graph-rest-1.0&tabs=http#request-headers
	extraHeader := makeAzureHeader(s.AccessToken)
	extraHeader.Add("ConsistencyLevel", "eventual")

	var groups []string

	for groupsURL != "" {
		jsonRequest, err := requests.New(groupsURL).
			WithContext(ctx).
			WithHeaders(extraHeader).
			Do().
			UnmarshalSimpleJSON()
		if err != nil {
			return nil, fmt.Errorf("unable to unmarshal Microsoft Graph response: %v", err)

		}
		groupsURL, err = jsonRequest.Get("@odata.nextLink").String()
		if err != nil {
			groupsURL = ""
		}
		groupsPage := getGroupsFromJSON(jsonRequest, p.GraphGroupField)
		groups = append(groups, groupsPage...)
	}

	return groups, nil
}

func getGroupsFromJSON(json *simplejson.Json, graphGroupField string) []string {
	groups := []string{}

	for i := range json.Get("value").MustArray() {
		value := json.Get("value").GetIndex(i).Get(graphGroupField).MustString()
		groups = append(groups, value)
	}

	return groups
}

func (p *AzureProvider) getEmailFromProfileAPI(ctx context.Context, accessToken string) (string, error) {
	if accessToken == "" {
		return "", fmt.Errorf("missing access token")
	}

	json, err := requests.New(p.ProfileURL.String()).
		WithContext(ctx).
		WithHeaders(makeAzureHeader(accessToken)).
		Do().
		UnmarshalSimpleJSON()
	if err != nil {
		return "", err
	}

	email, err := getEmailFromJSON(json)
	if email == "" {
		return "", fmt.Errorf("empty email address: %v", err)
	}
	return email, nil
}

func getEmailFromJSON(json *simplejson.Json) (string, error) {
	email, err := json.Get("mail").String()

	if err != nil || email == "" {
		otherMails, otherMailsErr := json.Get("otherMails").Array()
		if len(otherMails) > 0 {
			email = otherMails[0].(string)
		}
		err = otherMailsErr
	}

	if err != nil || email == "" {
		email, err = json.Get("userPrincipalName").String()
		if err != nil {
			logger.Errorf("unable to find userPrincipalName: %s", err)
			return "", err
		}
	}

	return email, nil
}

// ValidateSession validates the AccessToken
func (p *AzureProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, makeAzureHeader(s.AccessToken))
}

// Ensure that groups are available for Service Principal tokens
func (p *AzureProvider) CreateSessionFromToken(ctx context.Context, token string) (*sessions.SessionState, error) {
	ss, err := p.Data().CreateSessionFromToken(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("could not create session from token: %v", err)
	}

	oid, err := p.getObjectId(ss)
	if err != nil {
		return nil, fmt.Errorf("could not get oid from token: %v", err)
	}

	// use groups from the token if present
	if len(ss.Groups) > 0 {
		return ss, nil
	}

	// use cached groups if available
	groupCache.mu.RLock()
	item, ok := groupCache.items[oid]
	groupCache.mu.RUnlock()
	if ok && item.Expiry.After(time.Now()) {
		ss.Groups = item.Groups
		return ss, nil
	}

	// read and cache overage groups from Microsoft Graph
	groupCache.mu.Lock()
	defer groupCache.mu.Unlock()
	groups, err := p.getGroupsFromMicrosoftGraph(ctx, oid)
	if err != nil {
		return nil, fmt.Errorf("unable to get groups from Microsoft Graph: %v", err)
	}
	ss.Groups = groups
	groupCache.items[oid] = GroupCacheItem{
		Groups: groups,
		Expiry: time.Now().Add(groupCacheTTL),
	}

	return ss, nil
}

// read the oid claim from the token
// https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference#payload-claims
func (p *AzureProvider) getObjectId(ss *sessions.SessionState) (string, error) {
	claims, err := p.getClaimExtractor(ss.IDToken, ss.AccessToken)
	if err != nil {
		return "", fmt.Errorf("could not get claims from token: %v", err)
	}

	values, exists, err := claims.GetClaim("oid")
	if err != nil {
		return "", fmt.Errorf("could not get oid claim: %v", err)
	}
	if !exists {
		return "", fmt.Errorf("could not find oid claim")
	}

	oid, ok := values.(string)
	if !ok {
		return "", fmt.Errorf("could not convert oid claim to string")
	}

	return oid, nil
}

// Retrieve and cache an application access token
func (p *AzureProvider) getAppAccessToken(ctx context.Context, scope string) (string, error) {
	accessTokenMutex.Lock()
	defer accessTokenMutex.Unlock()

	if cachedAccessToken != nil && cachedAccessToken.Expiry.After(time.Now()) {
		return cachedAccessToken.AccessToken, nil
	}

	logger.Print("Getting new application access token")
	params := url.Values{}
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return "", err
	}

	params.Add("client_id", p.ClientID)
	params.Add("client_secret", clientSecret)
	params.Add("grant_type", "client_credentials")
	params.Add("scope", scope)

	err = requests.New(p.RedeemURL.String()).
		WithContext(ctx).
		WithMethod("POST").
		WithBody(bytes.NewBufferString(params.Encode())).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Do().
		UnmarshalInto(&cachedAccessToken)
	if err != nil {
		return "", err
	}

	// cache tokens for 1min less than the expiry time
	expiresIn := cachedAccessToken.ExpiresIn - 60
	cachedAccessToken.Expiry = time.Now().Add(time.Duration(expiresIn) * time.Second)

	return cachedAccessToken.AccessToken, nil
}

// Retrieve groups from Microsoft Graph
func (p *AzureProvider) getGroupsFromMicrosoftGraph(ctx context.Context, oid string) ([]string, error) {
	logger.Printf("Getting groups for oid: %s", oid)
	accessToken, err := p.getAppAccessToken(ctx, "https://graph.microsoft.com/.default")
	if err != nil {
		return nil, fmt.Errorf("could not get app access token: %v", err)
	}

	// Read groups by objectId, which works for both users and service principals
	// https://learn.microsoft.com/en-us/graph/api/directoryobject-getmemberobjects?view=graph-rest-1.0&tabs=http
	groupsURL := fmt.Sprintf("https://graph.microsoft.com/v1.0/%s/directoryObjects/%s/getMemberObjects", p.Tenant, oid)
	extraHeader := makeAzureHeader(accessToken)
	extraHeader.Add("ConsistencyLevel", "eventual")
	extraHeader.Add("Content-Type", "application/json")
	requestBody := map[string]interface{}{
		"securityEnabledOnly": true,
	}
	requestBodyBytes, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal request body: %v", err)
	}

	jsonResponse, err := requests.New(groupsURL).
		WithContext(ctx).
		WithMethod("POST").
		WithHeaders(extraHeader).
		WithBody(bytes.NewBuffer(requestBodyBytes)).
		Do().
		UnmarshalSimpleJSON()
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal Microsoft Graph response: %v", err)
	}

	var groups []string
	for i := range jsonResponse.Get("value").MustArray() {
		value := jsonResponse.Get("value").GetIndex(i).MustString()
		groups = append(groups, value)
	}

	return groups, nil
}
