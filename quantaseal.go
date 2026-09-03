// Package quantaseal provides a Go client SDK for the QuantaSeal
// quantum-safe security API. It wraps all v2 API endpoints for encryption,
// vault, proxy, compliance, and agent operations.
//
// Quick start:
//
//	client := quantaseal.New("https://api.quantaseal.io", "qs_apikey_xxx")
//	ct, err := client.Encrypt(ctx, quantaseal.EncryptRequest{
//	    Plaintext: "sensitive data",
//	    Algorithm: "ML-KEM-768",
//	})
package quantaseal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	DefaultTimeout = 30 * time.Second
	UserAgent      = "quantaseal-go-sdk/1.0.0"
)

// Client is the QuantaSeal API client.
type Client struct {
	BaseURL    string
	APIKey     string
	HTTPClient *http.Client
}

// New creates a new QuantaSeal client.
func New(baseURL, apiKey string) *Client {
	return &Client{
		BaseURL: baseURL,
		APIKey:  apiKey,
		HTTPClient: &http.Client{
			Timeout: DefaultTimeout,
		},
	}
}

// APIResponse is the standard envelope for all API responses.
type APIResponse[T any] struct {
	Success bool         `json:"success"`
	Data    T            `json:"data"`
	Error   *APIError    `json:"error,omitempty"`
	Meta    *APIMetadata `json:"meta,omitempty"`
}

// APIError represents an error from the API.
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// APIMetadata contains request metadata.
type APIMetadata struct {
	RequestID string `json:"request_id"`
	Timestamp string `json:"timestamp"`
	Version   string `json:"version"`
}

// ── Encryption ────────────────────────────────────────────────────────────

// EncryptRequest is the payload for /api/v2/encryption/encrypt.
type EncryptRequest struct {
	Plaintext string `json:"plaintext"`
	Algorithm string `json:"algorithm,omitempty"`
}

// EncryptResponse is returned from the encrypt endpoint.
type EncryptResponse struct {
	Ciphertext string `json:"ciphertext"`
	Algorithm  string `json:"algorithm"`
	KeyID      string `json:"key_id"`
}

// Encrypt encrypts plaintext using the specified PQC algorithm.
func (c *Client) Encrypt(ctx context.Context, req EncryptRequest) (*EncryptResponse, error) {
	var resp APIResponse[EncryptResponse]
	if err := c.post(ctx, "/api/v2/encryption/encrypt", req, &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("encrypt failed: %s", resp.Error.Message)
	}
	return &resp.Data, nil
}

// DecryptRequest is the payload for /api/v2/encryption/decrypt.
type DecryptRequest struct {
	Ciphertext string `json:"ciphertext"`
}

// DecryptResponse is returned from the decrypt endpoint.
type DecryptResponse struct {
	Plaintext string `json:"plaintext"`
	Algorithm string `json:"algorithm"`
}

// Decrypt decrypts ciphertext.
func (c *Client) Decrypt(ctx context.Context, req DecryptRequest) (*DecryptResponse, error) {
	var resp APIResponse[DecryptResponse]
	if err := c.post(ctx, "/api/v2/encryption/decrypt", req, &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("decrypt failed: %s", resp.Error.Message)
	}
	return &resp.Data, nil
}

// ── Vault ─────────────────────────────────────────────────────────────────

// VaultSealRequest seals a secret in QuantaVault.
type VaultSealRequest struct {
	Name   string `json:"name"`
	Secret string `json:"secret"`
}

// VaultSealResponse is returned from vault seal.
type VaultSealResponse struct {
	EntryID string `json:"entry_id"`
	Name    string `json:"name"`
}

// VaultSeal stores a secret in QuantaVault with 3-layer encryption.
func (c *Client) VaultSeal(ctx context.Context, req VaultSealRequest) (*VaultSealResponse, error) {
	var resp APIResponse[VaultSealResponse]
	if err := c.post(ctx, "/api/v2/vault/seal", req, &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("vault seal failed: %s", resp.Error.Message)
	}
	return &resp.Data, nil
}

// VaultUnsealRequest retrieves a secret from QuantaVault.
type VaultUnsealRequest struct {
	EntryID string `json:"entry_id"`
}

// VaultUnsealResponse is returned from vault unseal.
type VaultUnsealResponse struct {
	Name   string `json:"name"`
	Secret string `json:"secret"`
}

// VaultUnseal retrieves and decrypts a secret from QuantaVault.
func (c *Client) VaultUnseal(ctx context.Context, req VaultUnsealRequest) (*VaultUnsealResponse, error) {
	var resp APIResponse[VaultUnsealResponse]
	if err := c.post(ctx, "/api/v2/vault/unseal", req, &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("vault unseal failed: %s", resp.Error.Message)
	}
	return &resp.Data, nil
}

// ── Health ─────────────────────────────────────────────────────────────────

// HealthResponse represents the /health endpoint response.
type HealthResponse struct {
	Status      string `json:"status"`
	Version     string `json:"version"`
	Region      string `json:"region"`
	Environment string `json:"environment"`
}

// Health checks the API health.
func (c *Client) Health(ctx context.Context) (*HealthResponse, error) {
	var resp HealthResponse
	if err := c.get(ctx, "/health", &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ── HTTP helpers ──────────────────────────────────────────────────────────

func (c *Client) post(ctx context.Context, path string, body any, result any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+path, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", UserAgent)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("API error %d: %s", resp.StatusCode, string(respBody))
	}

	return json.Unmarshal(respBody, result)
}

func (c *Client) get(ctx context.Context, path string, result any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", UserAgent)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("API error %d: %s", resp.StatusCode, string(respBody))
	}

	return json.Unmarshal(respBody, result)
}

func (c *Client) delete(ctx context.Context, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.BaseURL+path, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", UserAgent)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

func (c *Client) patch(ctx context.Context, path string, body any, result any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, c.BaseURL+path, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", UserAgent)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("API error %d: %s", resp.StatusCode, string(respBody))
	}

	return json.Unmarshal(respBody, result)
}

func (c *Client) getWithQuery(ctx context.Context, path string, params map[string]string, result any) error {
	fullURL := c.BaseURL + path
	if len(params) > 0 {
		fullURL += "?"
		first := true
		for k, v := range params {
			if !first {
				fullURL += "&"
			}
			fullURL += k + "=" + v
			first = false
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", UserAgent)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("API error %d: %s", resp.StatusCode, string(respBody))
	}

	return json.Unmarshal(respBody, result)
}

// ── Auth ──────────────────────────────────────────────────────────────────

// LoginRequest is the payload for /api/v2/auth/login.
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginResult is returned from the login endpoint.
type LoginResult struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
	TenantID     string `json:"tenant_id"`
}

// RegisterRequest is the payload for /api/v2/auth/register.
type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	OrgName  string `json:"org_name"`
}

// RegisterResult is returned from the register endpoint.
type RegisterResult struct {
	UserID   string `json:"user_id"`
	TenantID string `json:"tenant_id"`
}

// TokenResult is returned from the token refresh endpoint.
type TokenResult struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
}

// MfaSetupResult is returned from the MFA setup endpoint.
type MfaSetupResult struct {
	Secret string `json:"secret"`
	QRCode string `json:"qr_code"`
}

// MfaVerifyResult is returned from the MFA verify endpoint.
type MfaVerifyResult struct {
	Verified    bool     `json:"verified"`
	BackupCodes []string `json:"backup_codes"`
}

// Login authenticates with email and password.
func (c *Client) Login(ctx context.Context, email, password string) (*LoginResult, error) {
	var resp APIResponse[LoginResult]
	if err := c.post(ctx, "/api/v2/auth/login", LoginRequest{Email: email, Password: password}, &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("login failed: %s", resp.Error.Message)
	}
	return &resp.Data, nil
}

// Register creates a new user and organisation.
func (c *Client) Register(ctx context.Context, email, password, orgName string) (*RegisterResult, error) {
	var resp APIResponse[RegisterResult]
	if err := c.post(ctx, "/api/v2/auth/register", RegisterRequest{Email: email, Password: password, OrgName: orgName}, &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("register failed: %s", resp.Error.Message)
	}
	return &resp.Data, nil
}

// RefreshToken exchanges a refresh token for a new token pair.
func (c *Client) RefreshToken(ctx context.Context, refreshToken string) (*TokenResult, error) {
	var resp APIResponse[TokenResult]
	if err := c.post(ctx, "/api/v2/auth/refresh", map[string]string{"refresh_token": refreshToken}, &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("refresh failed: %s", resp.Error.Message)
	}
	return &resp.Data, nil
}

// Logout invalidates the given refresh token.
func (c *Client) Logout(ctx context.Context, refreshToken string) error {
	var resp APIResponse[map[string]any]
	return c.post(ctx, "/api/v2/auth/logout", map[string]string{"refresh_token": refreshToken}, &resp)
}

// SetupMfa begins MFA setup and returns the TOTP secret and QR code.
func (c *Client) SetupMfa(ctx context.Context) (*MfaSetupResult, error) {
	var resp APIResponse[MfaSetupResult]
	if err := c.post(ctx, "/api/v2/auth/mfa/setup", nil, &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("mfa setup failed: %s", resp.Error.Message)
	}
	return &resp.Data, nil
}

// VerifyMfa completes MFA setup by verifying a TOTP code.
func (c *Client) VerifyMfa(ctx context.Context, totpCode string) (*MfaVerifyResult, error) {
	var resp APIResponse[MfaVerifyResult]
	if err := c.post(ctx, "/api/v2/auth/mfa/verify", map[string]string{"totp_code": totpCode}, &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("mfa verify failed: %s", resp.Error.Message)
	}
	return &resp.Data, nil
}

// ── Proxy ─────────────────────────────────────────────────────────────────

// Integration represents an external system integration.
type Integration struct {
	ID                string         `json:"id"`
	Name              string         `json:"name"`
	SystemType        string         `json:"system_type"`
	Config            map[string]any `json:"config"`
	EndpointURL       string         `json:"endpoint_url,omitempty"`
	AllowedOperations []string       `json:"allowed_operations,omitempty"`
	IsActive          bool           `json:"is_active"`
	CreatedAt         string         `json:"created_at"`
}

// CreateIntegrationRequest is the payload for creating a new integration.
type CreateIntegrationRequest struct {
	Name              string         `json:"name"`
	SystemType        string         `json:"system_type"`
	Config            map[string]any `json:"config"`
	EndpointURL       string         `json:"endpoint_url,omitempty"`
	AllowedOperations []string       `json:"allowed_operations,omitempty"`
}

// ConnectivityResult is returned from the test connectivity endpoint.
type ConnectivityResult struct {
	Connected bool `json:"connected"`
	LatencyMs *int `json:"latency_ms,omitempty"`
}

// ForwardRequest is the payload for the proxy forward endpoint.
type ForwardRequest struct {
	IntegrationID string         `json:"integration_id"`
	Method        string         `json:"method"`
	Endpoint      string         `json:"endpoint"`
	Payload       any            `json:"payload,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
}

// ForwardResponse is returned from the proxy forward endpoint.
type ForwardResponse struct {
	StatusCode int               `json:"status_code"`
	Body       any               `json:"body"`
	Headers    map[string]string `json:"headers,omitempty"`
}

// CreateIntegration creates a new external system integration.
func (c *Client) CreateIntegration(ctx context.Context, req CreateIntegrationRequest) (*Integration, error) {
	var resp APIResponse[Integration]
	if err := c.post(ctx, "/api/v2/proxy/integrations", req, &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("create integration failed: %s", resp.Error.Message)
	}
	return &resp.Data, nil
}

// ListIntegrations returns all active integrations for the current tenant.
func (c *Client) ListIntegrations(ctx context.Context) ([]Integration, error) {
	var resp APIResponse[[]Integration]
	if err := c.get(ctx, "/api/v2/proxy/integrations", &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("list integrations failed: %s", resp.Error.Message)
	}
	return resp.Data, nil
}

// GetIntegration retrieves a single integration by ID.
func (c *Client) GetIntegration(ctx context.Context, integrationID string) (*Integration, error) {
	var resp APIResponse[Integration]
	if err := c.get(ctx, "/api/v2/proxy/integrations/"+integrationID, &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("get integration failed: %s", resp.Error.Message)
	}
	return &resp.Data, nil
}

// DeleteIntegration deletes an integration.
func (c *Client) DeleteIntegration(ctx context.Context, integrationID string) error {
	return c.delete(ctx, "/api/v2/proxy/integrations/"+integrationID)
}

// TestConnectivity tests connectivity to an integration's upstream system.
func (c *Client) TestConnectivity(ctx context.Context, integrationID string) (*ConnectivityResult, error) {
	var resp APIResponse[ConnectivityResult]
	if err := c.post(ctx, "/api/v2/proxy/integrations/"+integrationID+"/test", nil, &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("test connectivity failed: %s", resp.Error.Message)
	}
	return &resp.Data, nil
}

// ForwardRequest forwards a request through the proxy to the upstream system.
func (c *Client) Forward(ctx context.Context, req ForwardRequest) (*ForwardResponse, error) {
	var resp APIResponse[ForwardResponse]
	if err := c.post(ctx, "/api/v2/proxy/forward", req, &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("forward failed: %s", resp.Error.Message)
	}
	return &resp.Data, nil
}

// ── Compliance ────────────────────────────────────────────────────────────

// ComplianceReport represents a compliance report.
type ComplianceReport struct {
	ID        string         `json:"id"`
	Framework string         `json:"framework"`
	Status    string         `json:"status"`
	CreatedAt string         `json:"created_at"`
	ReportURL string         `json:"report_url,omitempty"`
	Summary   map[string]any `json:"summary,omitempty"`
}

// ComplianceScore represents a framework compliance score.
type ComplianceScore struct {
	Framework    string         `json:"framework"`
	Score        float64        `json:"score"`
	Grade        string         `json:"grade,omitempty"`
	CalculatedAt string         `json:"calculated_at,omitempty"`
	Breakdown    map[string]any `json:"breakdown,omitempty"`
}

// GenerateComplianceReport triggers generation of a compliance report.
func (c *Client) GenerateComplianceReport(ctx context.Context, framework string) (*ComplianceReport, error) {
	var resp APIResponse[ComplianceReport]
	if err := c.post(ctx, "/api/v2/compliance/reports", map[string]string{"framework": framework}, &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("generate report failed: %s", resp.Error.Message)
	}
	return &resp.Data, nil
}

// GetComplianceReport retrieves a compliance report by ID.
func (c *Client) GetComplianceReport(ctx context.Context, id string) (*ComplianceReport, error) {
	var resp APIResponse[ComplianceReport]
	if err := c.get(ctx, "/api/v2/compliance/reports/"+id, &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("get report failed: %s", resp.Error.Message)
	}
	return &resp.Data, nil
}

// ListComplianceReports lists all compliance reports for the current tenant.
func (c *Client) ListComplianceReports(ctx context.Context) ([]ComplianceReport, error) {
	var resp APIResponse[[]ComplianceReport]
	if err := c.get(ctx, "/api/v2/compliance/reports", &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("list reports failed: %s", resp.Error.Message)
	}
	return resp.Data, nil
}

// GetComplianceScore retrieves the current compliance score for a framework.
func (c *Client) GetComplianceScore(ctx context.Context, framework string) (*ComplianceScore, error) {
	var resp APIResponse[ComplianceScore]
	if err := c.get(ctx, "/api/v2/compliance/score/"+framework, &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("get score failed: %s", resp.Error.Message)
	}
	return &resp.Data, nil
}

// ── Billing ───────────────────────────────────────────────────────────────

// BillingPlan represents the current subscription plan.
type BillingPlan struct {
	Tier           string         `json:"tier"`
	PricePerPeriod *int           `json:"price_per_period,omitempty"`
	Interval       string         `json:"interval,omitempty"`
	Limits         map[string]any `json:"limits,omitempty"`
	RenewsAt       string         `json:"renews_at,omitempty"`
}

// BillingUsage represents current period usage statistics.
type BillingUsage struct {
	EncryptionOps int    `json:"encryption_ops"`
	VaultEntries  int    `json:"vault_entries"`
	APICalls      int    `json:"api_calls"`
	StorageBytes  *int64 `json:"storage_bytes,omitempty"`
	PeriodStart   string `json:"period_start,omitempty"`
	PeriodEnd     string `json:"period_end,omitempty"`
}

// Invoice represents a billing invoice.
type Invoice struct {
	ID          string `json:"id"`
	AmountCents int    `json:"amount_cents"`
	Currency    string `json:"currency"`
	Status      string `json:"status"`
	InvoiceDate string `json:"invoice_date"`
	PDFURL      string `json:"pdf_url,omitempty"`
}

// CheckoutSession represents a Stripe checkout session.
type CheckoutSession struct {
	SessionID   string `json:"session_id"`
	CheckoutURL string `json:"checkout_url"`
}

// GetBillingPlan retrieves the current subscription plan.
func (c *Client) GetBillingPlan(ctx context.Context) (*BillingPlan, error) {
	var resp APIResponse[BillingPlan]
	if err := c.get(ctx, "/api/v2/billing/plan", &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("get plan failed: %s", resp.Error.Message)
	}
	return &resp.Data, nil
}

// GetBillingUsage retrieves current period usage statistics.
func (c *Client) GetBillingUsage(ctx context.Context) (*BillingUsage, error) {
	var resp APIResponse[BillingUsage]
	if err := c.get(ctx, "/api/v2/billing/usage", &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("get usage failed: %s", resp.Error.Message)
	}
	return &resp.Data, nil
}

// ListInvoices lists all invoices for the current tenant.
func (c *Client) ListInvoices(ctx context.Context) ([]Invoice, error) {
	var resp APIResponse[[]Invoice]
	if err := c.get(ctx, "/api/v2/billing/invoices", &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("list invoices failed: %s", resp.Error.Message)
	}
	return resp.Data, nil
}

// UpgradePlan upgrades the subscription to a new tier.
func (c *Client) UpgradePlan(ctx context.Context, tier string) (*BillingPlan, error) {
	var resp APIResponse[BillingPlan]
	if err := c.post(ctx, "/api/v2/billing/plan/upgrade", map[string]string{"tier": tier}, &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("upgrade plan failed: %s", resp.Error.Message)
	}
	return &resp.Data, nil
}

// GetCheckoutSession creates a Stripe checkout session for a plan upgrade.
func (c *Client) GetCheckoutSession(ctx context.Context, tier string) (*CheckoutSession, error) {
	var resp APIResponse[CheckoutSession]
	if err := c.post(ctx, "/api/v2/billing/checkout", map[string]string{"tier": tier}, &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("get checkout session failed: %s", resp.Error.Message)
	}
	return &resp.Data, nil
}

// CancelSubscription cancels the subscription at the end of the billing period.
func (c *Client) CancelSubscription(ctx context.Context) error {
	var resp APIResponse[map[string]any]
	return c.post(ctx, "/api/v2/billing/cancel", nil, &resp)
}

// ── Security ──────────────────────────────────────────────────────────────

// APIKey represents an API key record (no secret value).
type APIKey struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Scopes     []string `json:"scopes"`
	KeyPrefix  string   `json:"key_prefix,omitempty"`
	IsActive   bool     `json:"is_active"`
	CreatedAt  string   `json:"created_at"`
	LastUsedAt string   `json:"last_used_at,omitempty"`
}

// CreateAPIKeyResult contains the new key metadata and one-time secret.
type CreateAPIKeyResult struct {
	Key    APIKey `json:"key"`
	Secret string `json:"secret"`
}

// RevokeIntegration revokes an integration using its HMAC signature.
func (c *Client) RevokeIntegration(ctx context.Context, id, hmac string) error {
	var resp APIResponse[map[string]any]
	return c.post(ctx, "/api/v2/security/integrations/"+id+"/revoke", map[string]string{"hmac": hmac}, &resp)
}

// ListAPIKeys lists all API keys for the current tenant.
func (c *Client) ListAPIKeys(ctx context.Context) ([]APIKey, error) {
	var resp APIResponse[[]APIKey]
	if err := c.get(ctx, "/api/v2/security/api-keys", &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("list api keys failed: %s", resp.Error.Message)
	}
	return resp.Data, nil
}

// CreateAPIKey creates a new API key with the given name and scopes.
func (c *Client) CreateAPIKey(ctx context.Context, name string, scopes []string) (*CreateAPIKeyResult, error) {
	var resp APIResponse[CreateAPIKeyResult]
	if err := c.post(ctx, "/api/v2/security/api-keys", map[string]any{"name": name, "scopes": scopes}, &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("create api key failed: %s", resp.Error.Message)
	}
	return &resp.Data, nil
}

// RevokeAPIKey permanently revokes an API key.
func (c *Client) RevokeAPIKey(ctx context.Context, id string) error {
	return c.delete(ctx, "/api/v2/security/api-keys/"+id)
}

// EmergencyLockdown triggers an emergency lockdown for the tenant.
func (c *Client) EmergencyLockdown(ctx context.Context, reason string) error {
	var resp APIResponse[map[string]any]
	return c.post(ctx, "/api/v2/security/emergency-lockdown", map[string]string{"reason": reason}, &resp)
}

// ── Agent ─────────────────────────────────────────────────────────────────

// AgentQueryRequest is the payload for /api/v2/agent/query.
type AgentQueryRequest struct {
	Message        string `json:"message"`
	ConversationID string `json:"conversation_id,omitempty"`
}

// AgentQueryResult is returned from the agent query endpoint.
type AgentQueryResult struct {
	Response       string `json:"response"`
	ConversationID string `json:"conversation_id"`
}

// AgentConversation represents a conversation session.
type AgentConversation struct {
	ID             string `json:"id"`
	Title          string `json:"title,omitempty"`
	MessageCount   int    `json:"message_count"`
	CreatedAt      string `json:"created_at"`
	LastMessageAt  string `json:"last_message_at,omitempty"`
}

// AgentQuery sends a message to the AI security agent.
func (c *Client) AgentQuery(ctx context.Context, message, conversationID string) (*AgentQueryResult, error) {
	req := AgentQueryRequest{Message: message, ConversationID: conversationID}
	var resp APIResponse[AgentQueryResult]
	if err := c.post(ctx, "/api/v2/agent/query", req, &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("agent query failed: %s", resp.Error.Message)
	}
	return &resp.Data, nil
}

// ListConversations lists all agent conversations for the current tenant.
func (c *Client) ListConversations(ctx context.Context) ([]AgentConversation, error) {
	var resp APIResponse[[]AgentConversation]
	if err := c.get(ctx, "/api/v2/agent/conversations", &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("list conversations failed: %s", resp.Error.Message)
	}
	return resp.Data, nil
}

// GetConversation retrieves a single conversation by ID.
func (c *Client) GetConversation(ctx context.Context, id string) (*AgentConversation, error) {
	var resp APIResponse[AgentConversation]
	if err := c.get(ctx, "/api/v2/agent/conversations/"+id, &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("get conversation failed: %s", resp.Error.Message)
	}
	return &resp.Data, nil
}

// DeleteConversation deletes a conversation and all its messages.
func (c *Client) DeleteConversation(ctx context.Context, id string) error {
	return c.delete(ctx, "/api/v2/agent/conversations/"+id)
}

// ── Tokenize ──────────────────────────────────────────────────────────────

// TokenizeRequest is the payload for /api/v2/tokenize.
type TokenizeRequest struct {
	Data            string `json:"data"`
	DataType        string `json:"data_type"`
	FormatPreserving bool  `json:"format_preserving"`
}

// TokenizeResult is returned from the tokenize endpoint.
type TokenizeResult struct {
	Token           string `json:"token"`
	DataType        string `json:"data_type"`
	FormatPreserving bool  `json:"format_preserving"`
}

// DetokenizeResult is returned from the detokenize endpoint.
type DetokenizeResult struct {
	Value    string `json:"value"`
	DataType string `json:"data_type"`
}

// BatchTokenizeItem is a single item in a batch tokenize request.
type BatchTokenizeItem struct {
	Data            string `json:"data"`
	DataType        string `json:"data_type"`
	FormatPreserving bool  `json:"format_preserving"`
	Index           int    `json:"index"`
}

// BatchTokenizeResult is a single result in a batch tokenize response.
type BatchTokenizeResult struct {
	Token           string `json:"token"`
	DataType        string `json:"data_type"`
	FormatPreserving bool  `json:"format_preserving"`
	Index           int    `json:"index"`
}

// Tokenize tokenizes a single sensitive value.
func (c *Client) Tokenize(ctx context.Context, data, dataType string, formatPreserving bool) (*TokenizeResult, error) {
	var resp APIResponse[TokenizeResult]
	if err := c.post(ctx, "/api/v2/tokenize", TokenizeRequest{Data: data, DataType: dataType, FormatPreserving: formatPreserving}, &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("tokenize failed: %s", resp.Error.Message)
	}
	return &resp.Data, nil
}

// Detokenize resolves a token back to its original value.
func (c *Client) Detokenize(ctx context.Context, token string) (*DetokenizeResult, error) {
	var resp APIResponse[DetokenizeResult]
	if err := c.post(ctx, "/api/v2/detokenize", map[string]string{"token": token}, &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("detokenize failed: %s", resp.Error.Message)
	}
	return &resp.Data, nil
}

// BatchTokenize tokenizes multiple values in a single request.
func (c *Client) BatchTokenize(ctx context.Context, items []BatchTokenizeItem) ([]BatchTokenizeResult, error) {
	var resp APIResponse[[]BatchTokenizeResult]
	if err := c.post(ctx, "/api/v2/tokenize/batch", map[string]any{"items": items}, &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("batch tokenize failed: %s", resp.Error.Message)
	}
	return resp.Data, nil
}

// BatchDetokenize detokenizes multiple tokens in a single request.
func (c *Client) BatchDetokenize(ctx context.Context, tokens []string) ([]DetokenizeResult, error) {
	var resp APIResponse[[]DetokenizeResult]
	if err := c.post(ctx, "/api/v2/detokenize/batch", map[string]any{"tokens": tokens}, &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("batch detokenize failed: %s", resp.Error.Message)
	}
	return resp.Data, nil
}

// ── MFT ───────────────────────────────────────────────────────────────────

// FileTransfer represents a managed file transfer record.
type FileTransfer struct {
	ID          string `json:"id"`
	Filename    string `json:"filename"`
	Destination string `json:"destination"`
	Status      string `json:"status"`
	SizeBytes   *int64 `json:"size_bytes,omitempty"`
	Encrypted   bool   `json:"encrypted"`
	CreatedAt   string `json:"created_at"`
	CompletedAt string `json:"completed_at,omitempty"`
}

// MFTUploadRequest is the payload for /api/v2/mft/upload.
type MFTUploadRequest struct {
	FileData    string `json:"file_data"`
	Filename    string `json:"filename"`
	Destination string `json:"destination"`
	Encrypt     bool   `json:"encrypt"`
}

// MFTDownloadResult is returned from the MFT download endpoint.
type MFTDownloadResult struct {
	Data     string `json:"data"`
	Filename string `json:"filename"`
}

// MFTUpload uploads a file (base64-encoded) for managed transfer.
func (c *Client) MFTUpload(ctx context.Context, fileDataBase64, filename, destination string, encrypt bool) (*FileTransfer, error) {
	var resp APIResponse[FileTransfer]
	req := MFTUploadRequest{FileData: fileDataBase64, Filename: filename, Destination: destination, Encrypt: encrypt}
	if err := c.post(ctx, "/api/v2/mft/upload", req, &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("mft upload failed: %s", resp.Error.Message)
	}
	return &resp.Data, nil
}

// MFTDownload downloads a file by transfer ID.
func (c *Client) MFTDownload(ctx context.Context, transferID string) (*MFTDownloadResult, error) {
	var resp APIResponse[MFTDownloadResult]
	if err := c.get(ctx, "/api/v2/mft/transfers/"+transferID+"/download", &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("mft download failed: %s", resp.Error.Message)
	}
	return &resp.Data, nil
}

// ListTransfers lists all file transfers for the current tenant.
func (c *Client) ListTransfers(ctx context.Context) ([]FileTransfer, error) {
	var resp APIResponse[[]FileTransfer]
	if err := c.get(ctx, "/api/v2/mft/transfers", &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("list transfers failed: %s", resp.Error.Message)
	}
	return resp.Data, nil
}

// GetTransfer retrieves a single file transfer record.
func (c *Client) GetTransfer(ctx context.Context, id string) (*FileTransfer, error) {
	var resp APIResponse[FileTransfer]
	if err := c.get(ctx, "/api/v2/mft/transfers/"+id, &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("get transfer failed: %s", resp.Error.Message)
	}
	return &resp.Data, nil
}

// DeleteTransfer deletes a transfer and its file data.
func (c *Client) DeleteTransfer(ctx context.Context, id string) error {
	return c.delete(ctx, "/api/v2/mft/transfers/"+id)
}

// ── Sync ──────────────────────────────────────────────────────────────────

// SyncJob represents a data synchronisation job.
type SyncJob struct {
	ID            string `json:"id"`
	IntegrationID string `json:"integration_id"`
	Direction     string `json:"direction"`
	Schedule      string `json:"schedule"`
	Status        string `json:"status"`
	CreatedAt     string `json:"created_at"`
	NextRunAt     string `json:"next_run_at,omitempty"`
}

// SyncJobExecution represents a historical sync job execution.
type SyncJobExecution struct {
	ID               string `json:"id"`
	JobID            string `json:"job_id"`
	Status           string `json:"status"`
	RecordsProcessed *int   `json:"records_processed,omitempty"`
	ErrorMessage     string `json:"error_message,omitempty"`
	StartedAt        string `json:"started_at"`
	CompletedAt      string `json:"completed_at,omitempty"`
}

// CreateSyncJobRequest is the payload for creating a sync job.
type CreateSyncJobRequest struct {
	IntegrationID string `json:"integration_id"`
	Direction     string `json:"direction"`
	Schedule      string `json:"schedule"`
}

// CreateSyncJob creates a new sync job.
func (c *Client) CreateSyncJob(ctx context.Context, integrationID, direction, schedule string) (*SyncJob, error) {
	var resp APIResponse[SyncJob]
	req := CreateSyncJobRequest{IntegrationID: integrationID, Direction: direction, Schedule: schedule}
	if err := c.post(ctx, "/api/v2/sync/jobs", req, &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("create sync job failed: %s", resp.Error.Message)
	}
	return &resp.Data, nil
}

// ListSyncJobs lists all sync jobs for the current tenant.
func (c *Client) ListSyncJobs(ctx context.Context) ([]SyncJob, error) {
	var resp APIResponse[[]SyncJob]
	if err := c.get(ctx, "/api/v2/sync/jobs", &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("list sync jobs failed: %s", resp.Error.Message)
	}
	return resp.Data, nil
}

// GetSyncJob retrieves a single sync job.
func (c *Client) GetSyncJob(ctx context.Context, id string) (*SyncJob, error) {
	var resp APIResponse[SyncJob]
	if err := c.get(ctx, "/api/v2/sync/jobs/"+id, &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("get sync job failed: %s", resp.Error.Message)
	}
	return &resp.Data, nil
}

// TriggerSyncJob manually triggers an immediate execution of a sync job.
func (c *Client) TriggerSyncJob(ctx context.Context, id string) error {
	var resp APIResponse[map[string]any]
	return c.post(ctx, "/api/v2/sync/jobs/"+id+"/trigger", nil, &resp)
}

// DeleteSyncJob deletes a sync job.
func (c *Client) DeleteSyncJob(ctx context.Context, id string) error {
	return c.delete(ctx, "/api/v2/sync/jobs/"+id)
}

// GetSyncJobHistory gets execution history for a sync job.
func (c *Client) GetSyncJobHistory(ctx context.Context, id string) ([]SyncJobExecution, error) {
	var resp APIResponse[[]SyncJobExecution]
	if err := c.get(ctx, "/api/v2/sync/jobs/"+id+"/history", &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("get sync job history failed: %s", resp.Error.Message)
	}
	return resp.Data, nil
}

// ── Workflows ─────────────────────────────────────────────────────────────

// Workflow represents a workflow definition.
type Workflow struct {
	ID        string           `json:"id"`
	Name      string           `json:"name"`
	Trigger   map[string]any   `json:"trigger"`
	Steps     []map[string]any `json:"steps"`
	IsActive  bool             `json:"is_active"`
	CreatedAt string           `json:"created_at"`
	UpdatedAt string           `json:"updated_at,omitempty"`
}

// WorkflowExecution represents a workflow execution record.
type WorkflowExecution struct {
	ID           string         `json:"id"`
	WorkflowID   string         `json:"workflow_id"`
	Status       string         `json:"status"`
	Payload      map[string]any `json:"payload,omitempty"`
	Output       map[string]any `json:"output,omitempty"`
	ErrorMessage string         `json:"error_message,omitempty"`
	StartedAt    string         `json:"started_at"`
	CompletedAt  string         `json:"completed_at,omitempty"`
}

// CreateWorkflowRequest is the payload for creating a workflow.
type CreateWorkflowRequest struct {
	Name    string           `json:"name"`
	Trigger map[string]any   `json:"trigger"`
	Steps   []map[string]any `json:"steps"`
}

// CreateWorkflow creates a new workflow.
func (c *Client) CreateWorkflow(ctx context.Context, req CreateWorkflowRequest) (*Workflow, error) {
	var resp APIResponse[Workflow]
	if err := c.post(ctx, "/api/v2/workflows", req, &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("create workflow failed: %s", resp.Error.Message)
	}
	return &resp.Data, nil
}

// ListWorkflows lists all workflows for the current tenant.
func (c *Client) ListWorkflows(ctx context.Context) ([]Workflow, error) {
	var resp APIResponse[[]Workflow]
	if err := c.get(ctx, "/api/v2/workflows", &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("list workflows failed: %s", resp.Error.Message)
	}
	return resp.Data, nil
}

// GetWorkflow retrieves a single workflow.
func (c *Client) GetWorkflow(ctx context.Context, id string) (*Workflow, error) {
	var resp APIResponse[Workflow]
	if err := c.get(ctx, "/api/v2/workflows/"+id, &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("get workflow failed: %s", resp.Error.Message)
	}
	return &resp.Data, nil
}

// TriggerWorkflow manually triggers a workflow execution.
func (c *Client) TriggerWorkflow(ctx context.Context, id string, payload map[string]any) (*WorkflowExecution, error) {
	var resp APIResponse[WorkflowExecution]
	if payload == nil {
		payload = map[string]any{}
	}
	if err := c.post(ctx, "/api/v2/workflows/"+id+"/trigger", payload, &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("trigger workflow failed: %s", resp.Error.Message)
	}
	return &resp.Data, nil
}

// UpdateWorkflow updates an existing workflow.
func (c *Client) UpdateWorkflow(ctx context.Context, id string, updates map[string]any) (*Workflow, error) {
	var resp APIResponse[Workflow]
	if err := c.patch(ctx, "/api/v2/workflows/"+id, updates, &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("update workflow failed: %s", resp.Error.Message)
	}
	return &resp.Data, nil
}

// DeleteWorkflow deletes a workflow.
func (c *Client) DeleteWorkflow(ctx context.Context, id string) error {
	return c.delete(ctx, "/api/v2/workflows/"+id)
}

// GetWorkflowExecutions gets execution history for a workflow.
func (c *Client) GetWorkflowExecutions(ctx context.Context, id string) ([]WorkflowExecution, error) {
	var resp APIResponse[[]WorkflowExecution]
	if err := c.get(ctx, "/api/v2/workflows/"+id+"/executions", &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("get workflow executions failed: %s", resp.Error.Message)
	}
	return resp.Data, nil
}

// ── Files ─────────────────────────────────────────────────────────────────

// FileMetadata represents stored file metadata (no content).
type FileMetadata struct {
	ID          string `json:"id"`
	Filename    string `json:"filename"`
	ContentType string `json:"content_type,omitempty"`
	SizeBytes   *int64 `json:"size_bytes,omitempty"`
	Encrypted   bool   `json:"encrypted"`
	CreatedAt   string `json:"created_at"`
}

// FileUploadRequest is the payload for file upload.
type FileUploadRequest struct {
	FileData string `json:"file_data"`
	Filename string `json:"filename"`
	Encrypt  bool   `json:"encrypt"`
}

// FileDownloadResult is returned from the file download endpoint.
type FileDownloadResult struct {
	Data     string `json:"data"`
	Filename string `json:"filename"`
}

// UploadFile uploads a file (base64-encoded) with optional PQC encryption.
func (c *Client) UploadFile(ctx context.Context, fileDataBase64, filename string, encrypt bool) (*FileMetadata, error) {
	var resp APIResponse[FileMetadata]
	req := FileUploadRequest{FileData: fileDataBase64, Filename: filename, Encrypt: encrypt}
	if err := c.post(ctx, "/api/v2/files/upload", req, &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("upload file failed: %s", resp.Error.Message)
	}
	return &resp.Data, nil
}

// DownloadFile downloads a file by ID.
func (c *Client) DownloadFile(ctx context.Context, fileID string) (*FileDownloadResult, error) {
	var resp APIResponse[FileDownloadResult]
	if err := c.get(ctx, "/api/v2/files/"+fileID+"/download", &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("download file failed: %s", resp.Error.Message)
	}
	return &resp.Data, nil
}

// ListFiles lists all stored files for the current tenant.
func (c *Client) ListFiles(ctx context.Context) ([]FileMetadata, error) {
	var resp APIResponse[[]FileMetadata]
	if err := c.get(ctx, "/api/v2/files", &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("list files failed: %s", resp.Error.Message)
	}
	return resp.Data, nil
}

// DeleteFile deletes a file and its encrypted data.
func (c *Client) DeleteFile(ctx context.Context, fileID string) error {
	return c.delete(ctx, "/api/v2/files/"+fileID)
}

// GetFileMetadata retrieves metadata for a single file.
func (c *Client) GetFileMetadata(ctx context.Context, fileID string) (*FileMetadata, error) {
	var resp APIResponse[FileMetadata]
	if err := c.get(ctx, "/api/v2/files/"+fileID, &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("get file metadata failed: %s", resp.Error.Message)
	}
	return &resp.Data, nil
}

// ── Audit ─────────────────────────────────────────────────────────────────

// AuditLog represents a single audit log entry.
type AuditLog struct {
	ID         string         `json:"id"`
	Action     string         `json:"action"`
	Outcome    string         `json:"outcome"`
	ActorID    string         `json:"actor_id,omitempty"`
	IPAddress  string         `json:"ip_address,omitempty"`
	ResourceID string         `json:"resource_id,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
	CreatedAt  string         `json:"created_at"`
}

// AuditListOptions controls filtering for the audit log list endpoint.
type AuditListOptions struct {
	Action    string
	ActorID   string
	StartDate string
	EndDate   string
	Limit     int
	Offset    int
}

// ListAuditLogs lists audit log entries with optional filters.
func (c *Client) ListAuditLogs(ctx context.Context, opts AuditListOptions) ([]AuditLog, error) {
	params := map[string]string{}
	if opts.Action != "" {
		params["action"] = opts.Action
	}
	if opts.ActorID != "" {
		params["actor_id"] = opts.ActorID
	}
	if opts.StartDate != "" {
		params["start_date"] = opts.StartDate
	}
	if opts.EndDate != "" {
		params["end_date"] = opts.EndDate
	}
	if opts.Limit > 0 {
		params["limit"] = fmt.Sprintf("%d", opts.Limit)
	}
	if opts.Offset > 0 {
		params["offset"] = fmt.Sprintf("%d", opts.Offset)
	}

	var resp APIResponse[[]AuditLog]
	if err := c.getWithQuery(ctx, "/api/v2/audit/logs", params, &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("list audit logs failed: %s", resp.Error.Message)
	}
	return resp.Data, nil
}

// GetAuditLog retrieves a single audit log entry.
func (c *Client) GetAuditLog(ctx context.Context, logID string) (*AuditLog, error) {
	var resp APIResponse[AuditLog]
	if err := c.get(ctx, "/api/v2/audit/logs/"+logID, &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("get audit log failed: %s", resp.Error.Message)
	}
	return &resp.Data, nil
}

// ExportAuditLogs exports audit logs in the specified format.
func (c *Client) ExportAuditLogs(ctx context.Context, format, startDate, endDate string) (string, error) {
	body := map[string]string{"format": format}
	if startDate != "" {
		body["start_date"] = startDate
	}
	if endDate != "" {
		body["end_date"] = endDate
	}
	var resp APIResponse[map[string]string]
	if err := c.post(ctx, "/api/v2/audit/export", body, &resp); err != nil {
		return "", err
	}
	if !resp.Success {
		return "", fmt.Errorf("export audit logs failed: %s", resp.Error.Message)
	}
	return resp.Data["content"], nil
}

// ── Metrics ───────────────────────────────────────────────────────────────

// UsageMetrics holds general usage statistics for a period.
type UsageMetrics struct {
	APICalls      int    `json:"api_calls"`
	EncryptionOps int    `json:"encryption_ops"`
	DecryptionOps int    `json:"decryption_ops"`
	SignOps        int    `json:"sign_ops"`
	VerifyOps     int    `json:"verify_ops"`
	Period        string `json:"period"`
}

// EncryptionStats holds encryption algorithm usage statistics.
type EncryptionStats struct {
	ByAlgorithm   map[string]int `json:"by_algorithm"`
	KeysGenerated int            `json:"keys_generated"`
	KeysRotated   int            `json:"keys_rotated"`
	AvgLatencyMs  *float64       `json:"avg_latency_ms,omitempty"`
}

// APIStats holds API call statistics.
type APIStats struct {
	TotalRequests      int            `json:"total_requests"`
	SuccessfulRequests int            `json:"successful_requests"`
	FailedRequests     int            `json:"failed_requests"`
	AvgResponseTimeMs  *float64       `json:"avg_response_time_ms,omitempty"`
	ByEndpoint         map[string]int `json:"by_endpoint,omitempty"`
	Period             string         `json:"period"`
}

// VaultStats holds vault storage statistics.
type VaultStats struct {
	TotalEntries      int            `json:"total_entries"`
	ActiveEntries     int            `json:"active_entries"`
	ExpiringEntries   int            `json:"expiring_entries"`
	ByCredentialType  map[string]int `json:"by_credential_type,omitempty"`
}

// GetUsageMetrics retrieves usage metrics for a time period.
func (c *Client) GetUsageMetrics(ctx context.Context, period string) (*UsageMetrics, error) {
	if period == "" {
		period = "30d"
	}
	var resp APIResponse[UsageMetrics]
	if err := c.getWithQuery(ctx, "/api/v2/metrics/usage", map[string]string{"period": period}, &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("get usage metrics failed: %s", resp.Error.Message)
	}
	return &resp.Data, nil
}

// GetEncryptionStats retrieves encryption algorithm and key usage statistics.
func (c *Client) GetEncryptionStats(ctx context.Context) (*EncryptionStats, error) {
	var resp APIResponse[EncryptionStats]
	if err := c.get(ctx, "/api/v2/metrics/encryption", &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("get encryption stats failed: %s", resp.Error.Message)
	}
	return &resp.Data, nil
}

// GetAPIStats retrieves API call statistics for a time period.
func (c *Client) GetAPIStats(ctx context.Context, period string) (*APIStats, error) {
	if period == "" {
		period = "30d"
	}
	var resp APIResponse[APIStats]
	if err := c.getWithQuery(ctx, "/api/v2/metrics/api", map[string]string{"period": period}, &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("get api stats failed: %s", resp.Error.Message)
	}
	return &resp.Data, nil
}

// GetVaultStats retrieves vault storage statistics.
func (c *Client) GetVaultStats(ctx context.Context) (*VaultStats, error) {
	var resp APIResponse[VaultStats]
	if err := c.get(ctx, "/api/v2/metrics/vault", &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("get vault stats failed: %s", resp.Error.Message)
	}
	return &resp.Data, nil
}

// ── Webhooks ──────────────────────────────────────────────────────────────

// WebhookSubscription represents a webhook subscription.
type WebhookSubscription struct {
	ID        string   `json:"id"`
	URL       string   `json:"url"`
	Events    []string `json:"events"`
	IsActive  bool     `json:"is_active"`
	CreatedAt string   `json:"created_at"`
}

// WebhookDelivery represents a webhook delivery attempt.
type WebhookDelivery struct {
	ID             string `json:"id"`
	WebhookID      string `json:"webhook_id"`
	EventType      string `json:"event_type"`
	ResponseStatus *int   `json:"response_status,omitempty"`
	Success        bool   `json:"success"`
	DeliveredAt    string `json:"delivered_at"`
	Attempts       int    `json:"attempts"`
}

// CreateWebhookRequest is the payload for creating a webhook.
type CreateWebhookRequest struct {
	URL    string   `json:"url"`
	Events []string `json:"events"`
	Secret string   `json:"secret"`
}

// CreateWebhook creates a new webhook subscription.
func (c *Client) CreateWebhook(ctx context.Context, url string, events []string, secret string) (*WebhookSubscription, error) {
	var resp APIResponse[WebhookSubscription]
	req := CreateWebhookRequest{URL: url, Events: events, Secret: secret}
	if err := c.post(ctx, "/api/v2/webhooks", req, &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("create webhook failed: %s", resp.Error.Message)
	}
	return &resp.Data, nil
}

// ListWebhooks lists all webhook subscriptions for the current tenant.
func (c *Client) ListWebhooks(ctx context.Context) ([]WebhookSubscription, error) {
	var resp APIResponse[[]WebhookSubscription]
	if err := c.get(ctx, "/api/v2/webhooks", &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("list webhooks failed: %s", resp.Error.Message)
	}
	return resp.Data, nil
}

// GetWebhook retrieves a single webhook subscription.
func (c *Client) GetWebhook(ctx context.Context, id string) (*WebhookSubscription, error) {
	var resp APIResponse[WebhookSubscription]
	if err := c.get(ctx, "/api/v2/webhooks/"+id, &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("get webhook failed: %s", resp.Error.Message)
	}
	return &resp.Data, nil
}

// DeleteWebhook deletes a webhook subscription.
func (c *Client) DeleteWebhook(ctx context.Context, id string) error {
	return c.delete(ctx, "/api/v2/webhooks/"+id)
}

// TestWebhook sends a test event to the webhook target URL.
func (c *Client) TestWebhook(ctx context.Context, id string) (bool, error) {
	var resp APIResponse[map[string]any]
	if err := c.post(ctx, "/api/v2/webhooks/"+id+"/test", nil, &resp); err != nil {
		return false, err
	}
	if !resp.Success {
		return false, fmt.Errorf("test webhook failed: %s", resp.Error.Message)
	}
	success, _ := resp.Data["success"].(bool)
	return success, nil
}

// ListWebhookDeliveries lists delivery attempts for a webhook.
func (c *Client) ListWebhookDeliveries(ctx context.Context, id string) ([]WebhookDelivery, error) {
	var resp APIResponse[[]WebhookDelivery]
	if err := c.get(ctx, "/api/v2/webhooks/"+id+"/deliveries", &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("list webhook deliveries failed: %s", resp.Error.Message)
	}
	return resp.Data, nil
}

// ── Settings ──────────────────────────────────────────────────────────────

// TenantSettings represents tenant-level configuration.
type TenantSettings struct {
	TenantID        string         `json:"tenant_id"`
	OrgName         string         `json:"org_name,omitempty"`
	DefaultAlgorithm string        `json:"default_algorithm,omitempty"`
	MFAEnforced     bool           `json:"mfa_enforced"`
	RetentionDays   *int           `json:"retention_days,omitempty"`
	AllowedIPRanges []string       `json:"allowed_ip_ranges,omitempty"`
	Extra           map[string]any `json:"extra,omitempty"`
}

// GetSettings retrieves the current tenant settings.
func (c *Client) GetSettings(ctx context.Context) (*TenantSettings, error) {
	var resp APIResponse[TenantSettings]
	if err := c.get(ctx, "/api/v2/settings", &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("get settings failed: %s", resp.Error.Message)
	}
	return &resp.Data, nil
}

// UpdateSettings updates tenant settings.
func (c *Client) UpdateSettings(ctx context.Context, updates map[string]any) (*TenantSettings, error) {
	var resp APIResponse[TenantSettings]
	if err := c.patch(ctx, "/api/v2/settings", updates, &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("update settings failed: %s", resp.Error.Message)
	}
	return &resp.Data, nil
}

// GetSettingsAPIKeys lists API keys from the settings endpoint.
func (c *Client) GetSettingsAPIKeys(ctx context.Context) ([]APIKey, error) {
	var resp APIResponse[[]APIKey]
	if err := c.get(ctx, "/api/v2/settings/api-keys", &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("get settings api keys failed: %s", resp.Error.Message)
	}
	return resp.Data, nil
}

// RotateSigningKey rotates the tenant's HMAC signing key.
func (c *Client) RotateSigningKey(ctx context.Context) (string, error) {
	var resp APIResponse[map[string]string]
	if err := c.post(ctx, "/api/v2/settings/rotate-signing-key", nil, &resp); err != nil {
		return "", err
	}
	if !resp.Success {
		return "", fmt.Errorf("rotate signing key failed: %s", resp.Error.Message)
	}
	return resp.Data["signing_key"], nil
}

// ── Discovery ─────────────────────────────────────────────────────────────

// SchemaDiscovery represents the result of a schema discovery operation.
type SchemaDiscovery struct {
	IntegrationID string         `json:"integration_id"`
	Objects       []string       `json:"objects"`
	DiscoveredAt  string         `json:"discovered_at"`
	Schema        map[string]any `json:"schema,omitempty"`
}

// DiscoveredObject represents a discovered object/entity.
type DiscoveredObject struct {
	Name     string         `json:"name"`
	Label    string         `json:"label,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

// ObjectField represents a field definition within a discovered object.
type ObjectField struct {
	Name        string `json:"name"`
	DataType    string `json:"data_type"`
	Required    bool   `json:"required,omitempty"`
	ReadOnly    bool   `json:"read_only,omitempty"`
	Description string `json:"description,omitempty"`
}

// DiscoverSchema triggers schema discovery for an integration.
func (c *Client) DiscoverSchema(ctx context.Context, integrationID string) (*SchemaDiscovery, error) {
	var resp APIResponse[SchemaDiscovery]
	if err := c.post(ctx, "/api/v2/discovery/"+integrationID+"/schema", nil, &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("discover schema failed: %s", resp.Error.Message)
	}
	return &resp.Data, nil
}

// ListDiscoveredObjects lists all discoverable objects for an integration.
func (c *Client) ListDiscoveredObjects(ctx context.Context, integrationID string) ([]DiscoveredObject, error) {
	var resp APIResponse[[]DiscoveredObject]
	if err := c.get(ctx, "/api/v2/discovery/"+integrationID+"/objects", &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("list objects failed: %s", resp.Error.Message)
	}
	return resp.Data, nil
}

// GetObjectFields retrieves field definitions for a specific object.
func (c *Client) GetObjectFields(ctx context.Context, integrationID, objectName string) ([]ObjectField, error) {
	var resp APIResponse[[]ObjectField]
	if err := c.get(ctx, "/api/v2/discovery/"+integrationID+"/objects/"+objectName+"/fields", &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("get object fields failed: %s", resp.Error.Message)
	}
	return resp.Data, nil
}

// ── Mappings ──────────────────────────────────────────────────────────────

// FieldMapping represents a single field-level mapping rule.
type FieldMapping struct {
	SourceField string `json:"source_field"`
	TargetField string `json:"target_field"`
	Transform   string `json:"transform,omitempty"`
}

// ObjectMapping represents a field mapping definition between two objects.
type ObjectMapping struct {
	ID            string         `json:"id"`
	IntegrationID string         `json:"integration_id"`
	SourceObject  string         `json:"source_object"`
	TargetObject  string         `json:"target_object"`
	FieldMappings []FieldMapping `json:"field_mappings"`
	IsActive      bool           `json:"is_active"`
	CreatedAt     string         `json:"created_at"`
	UpdatedAt     string         `json:"updated_at,omitempty"`
}

// CreateMappingRequest is the payload for creating an object mapping.
type CreateMappingRequest struct {
	IntegrationID string         `json:"integration_id"`
	SourceObject  string         `json:"source_object"`
	TargetObject  string         `json:"target_object"`
	FieldMappings []FieldMapping `json:"field_mappings"`
}

// CreateMapping creates a new object mapping for an integration.
func (c *Client) CreateMapping(ctx context.Context, req CreateMappingRequest) (*ObjectMapping, error) {
	var resp APIResponse[ObjectMapping]
	if err := c.post(ctx, "/api/v2/mappings", req, &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("create mapping failed: %s", resp.Error.Message)
	}
	return &resp.Data, nil
}

// ListMappings lists all mappings for a specific integration.
func (c *Client) ListMappings(ctx context.Context, integrationID string) ([]ObjectMapping, error) {
	var resp APIResponse[[]ObjectMapping]
	if err := c.getWithQuery(ctx, "/api/v2/mappings", map[string]string{"integration_id": integrationID}, &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("list mappings failed: %s", resp.Error.Message)
	}
	return resp.Data, nil
}

// GetMapping retrieves a single mapping by ID.
func (c *Client) GetMapping(ctx context.Context, id string) (*ObjectMapping, error) {
	var resp APIResponse[ObjectMapping]
	if err := c.get(ctx, "/api/v2/mappings/"+id, &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("get mapping failed: %s", resp.Error.Message)
	}
	return &resp.Data, nil
}

// UpdateMapping updates an existing mapping.
func (c *Client) UpdateMapping(ctx context.Context, id string, updates map[string]any) (*ObjectMapping, error) {
	var resp APIResponse[ObjectMapping]
	if err := c.patch(ctx, "/api/v2/mappings/"+id, updates, &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("update mapping failed: %s", resp.Error.Message)
	}
	return &resp.Data, nil
}

// DeleteMapping deletes a mapping.
func (c *Client) DeleteMapping(ctx context.Context, id string) error {
	return c.delete(ctx, "/api/v2/mappings/"+id)
}
