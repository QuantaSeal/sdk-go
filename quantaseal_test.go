package quantaseal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEncrypt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/encryption/encrypt" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Error("missing or wrong auth header")
		}
		if r.Header.Get("User-Agent") != UserAgent {
			t.Error("missing user-agent")
		}

		resp := APIResponse[EncryptResponse]{
			Success: true,
			Data: EncryptResponse{
				Ciphertext: "encrypted_data",
				Algorithm:  "ML-KEM-768",
				KeyID:      "key-123",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := New(server.URL, "test-key")
	result, err := client.Encrypt(context.Background(), EncryptRequest{
		Plaintext: "hello world",
		Algorithm: "ML-KEM-768",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Ciphertext != "encrypted_data" {
		t.Errorf("expected encrypted_data, got %s", result.Ciphertext)
	}
	if result.Algorithm != "ML-KEM-768" {
		t.Errorf("expected ML-KEM-768, got %s", result.Algorithm)
	}
}

func TestDecrypt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := APIResponse[DecryptResponse]{
			Success: true,
			Data: DecryptResponse{
				Plaintext: "hello world",
				Algorithm: "ML-KEM-768",
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := New(server.URL, "test-key")
	result, err := client.Decrypt(context.Background(), DecryptRequest{
		Ciphertext: "encrypted_data",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Plaintext != "hello world" {
		t.Errorf("expected hello world, got %s", result.Plaintext)
	}
}

func TestHealth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := HealthResponse{
			Status:      "healthy",
			Version:     "2.1.0",
			Region:      "ap-southeast-2",
			Environment: "production",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := New(server.URL, "test-key")
	result, err := client.Health(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "healthy" {
		t.Errorf("expected healthy, got %s", result.Status)
	}
}

func TestVaultSeal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := APIResponse[VaultSealResponse]{
			Success: true,
			Data: VaultSealResponse{
				EntryID: "entry-456",
				Name:    "my-secret",
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := New(server.URL, "test-key")
	result, err := client.VaultSeal(context.Background(), VaultSealRequest{
		Name:   "my-secret",
		Secret: "super-secret-value",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.EntryID != "entry-456" {
		t.Errorf("expected entry-456, got %s", result.EntryID)
	}
}

func TestAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"success":false,"error":{"code":"unauthorized","message":"Invalid API key"}}`))
	}))
	defer server.Close()

	client := New(server.URL, "bad-key")
	_, err := client.Health(context.Background())
	if err == nil {
		t.Error("expected error for 401 response")
	}
}
