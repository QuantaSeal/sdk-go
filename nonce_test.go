package quantaseal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
)

// The server accepts 16-64 characters of letters, digits and hyphens.
var nonceRule = regexp.MustCompile(`^[A-Za-z0-9-]{16,64}$`)

func TestMutatingCallsCarryAUniqueValidNonce(t *testing.T) {
	var seen []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("X-Nonce"))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(APIResponse[EncryptResponse]{Success: true, Data: EncryptResponse{Ciphertext: "x"}})
	}))
	defer server.Close()

	client := New(server.URL, "test-key")
	for i := 0; i < 2; i++ {
		if _, err := client.Encrypt(context.Background(), EncryptRequest{Plaintext: "a", Algorithm: "ML-KEM-768"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if len(seen) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(seen))
	}
	for _, nonce := range seen {
		if !nonceRule.MatchString(nonce) {
			t.Errorf("nonce %q does not satisfy the server's rule", nonce)
		}
	}
	if seen[0] == seen[1] {
		t.Error("two requests reused the same nonce")
	}
}

func TestReadsCarryNoNonce(t *testing.T) {
	var nonce string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce = r.Header.Get("X-Nonce")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(APIResponse[HealthResponse]{Success: true})
	}))
	defer server.Close()

	if _, err := New(server.URL, "test-key").Health(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if nonce != "" {
		t.Errorf("a read sent a nonce: %q", nonce)
	}
}
