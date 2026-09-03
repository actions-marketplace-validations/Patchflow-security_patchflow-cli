package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewClientSetsTimeout(t *testing.T) {
	c := NewClient("http://example.com", "token")
	if c.httpClient.Timeout != 30*time.Second {
		t.Fatalf("expected timeout 30s, got %v", c.httpClient.Timeout)
	}
}

func TestNewClientWithHTTP_NilClient(t *testing.T) {
	c := NewClientWithHTTP("http://example.com", "token", nil)
	if c.httpClient == nil {
		t.Fatal("expected non-nil httpClient")
	}
	if c.httpClient.Timeout != 30*time.Second {
		t.Fatalf("expected default timeout 30s, got %v", c.httpClient.Timeout)
	}
}

func TestSetAuthHeader(t *testing.T) {
	c := NewClient("http://example.com", "my-secret-token")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	c.SetAuthHeader(req)

	auth := req.Header.Get("Authorization")
	expected := "Bearer my-secret-token"
	if auth != expected {
		t.Fatalf("expected auth header %q, got %q", expected, auth)
	}
}

func TestPostContext_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/cli/context" {
			t.Fatalf("expected path /api/v1/cli/context, got %s", r.URL.Path)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Fatalf("expected Content-Type application/json, got %s", ct)
		}
		if auth := r.Header.Get("Authorization"); !strings.HasPrefix(auth, "Bearer ") {
			t.Fatalf("expected Bearer auth, got %s", auth)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "job-123"})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	id, err := client.PostContext(context.Background(), ContextPayload{RepoRoot: "/repo"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "job-123" {
		t.Fatalf("expected job-123, got %s", id)
	}
}

func TestPostReview_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/cli/review" {
			t.Fatalf("expected path /api/v1/cli/review, got %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "job-456"})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	id, err := client.PostReview(context.Background(), ReviewPayload{RepoRoot: "/repo", Submit: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "job-456" {
		t.Fatalf("expected job-456, got %s", id)
	}
}

func TestGetStatus_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expectedPath := "/api/v1/cli/status/job-789"
		if r.URL.Path != expectedPath {
			t.Fatalf("expected path %s, got %s", expectedPath, r.URL.Path)
		}
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(StatusResponse{ID: "job-789", Status: "completed", ResultURL: "http://result"})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	status, err := client.GetStatus(context.Background(), "job-789")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.ID != "job-789" || status.Status != "completed" || status.ResultURL != "http://result" {
		t.Fatalf("unexpected status response: %+v", status)
	}
}

func TestPostContext_ErrorParsing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "invalid token", "code": "AUTH_001"})
	}))
	defer server.Close()

	client := NewClient(server.URL, "bad-token")
	_, err := client.PostContext(context.Background(), ContextPayload{})
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	apiErr, ok := err.(*Error)
	if !ok {
		t.Fatalf("expected *api.Error, got %T", err)
	}
	if apiErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", apiErr.StatusCode)
	}
	if apiErr.Message != "invalid token" {
		t.Fatalf("expected message 'invalid token', got %q", apiErr.Message)
	}
	if apiErr.Code != "AUTH_001" {
		t.Fatalf("expected code AUTH_001, got %q", apiErr.Code)
	}
}

func TestPostContext_ErrorPlainTextBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("bad request"))
	}))
	defer server.Close()

	client := NewClient(server.URL, "token")
	_, err := client.PostContext(context.Background(), ContextPayload{})
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	apiErr, ok := err.(*Error)
	if !ok {
		t.Fatalf("expected *api.Error, got %T", err)
	}
	if apiErr.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", apiErr.StatusCode)
	}
	if apiErr.Message != "bad request" {
		t.Fatalf("expected message 'bad request', got %q", apiErr.Message)
	}
}

func TestContextPropagation(t *testing.T) {
	var receivedCtx context.Context
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedCtx = r.Context()
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "job-ctx"})
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	client := NewClient(server.URL, "token")
	_, err := client.PostContext(ctx, ContextPayload{})
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
	_ = receivedCtx // server may not have been reached, that's fine for cancelled context
}

func TestPostScanResults_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/cli/scan-results" {
			t.Fatalf("expected path /api/v1/cli/scan-results, got %s", r.URL.Path)
		}
		// Verify query params
		q := r.URL.Query()
		if q.Get("project_id") != "42" {
			t.Fatalf("expected project_id=42, got %s", q.Get("project_id"))
		}
		if q.Get("scan_id") != "cli-scan-001" {
			t.Fatalf("expected scan_id=cli-scan-001, got %s", q.Get("scan_id"))
		}
		// Verify body is valid JSON
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("failed to decode body: %v", err)
		}
		if body["scan_id"] != "cli-scan-001" {
			t.Fatalf("expected scan_id in body, got %v", body["scan_id"])
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(ScanResultResponse{
			ScanID:    100,
			ProjectID: 42,
			Status:    "completed",
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	payload := json.RawMessage(`{"scan_id":"cli-scan-001","findings":[]}`)
	resp, err := client.PostScanResults(context.Background(), payload, 42, "cli-scan-001")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.ScanID != 100 {
		t.Fatalf("expected scan_id 100, got %d", resp.ScanID)
	}
	if resp.ProjectID != 42 {
		t.Fatalf("expected project_id 42, got %d", resp.ProjectID)
	}
	if resp.Status != "completed" {
		t.Fatalf("expected status completed, got %s", resp.Status)
	}
}

func TestPostPRReviewResults_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/cli/pr-review-results" {
			t.Fatalf("expected path /api/v1/cli/pr-review-results, got %s", r.URL.Path)
		}
		q := r.URL.Query()
		if q.Get("project_id") != "10" {
			t.Fatalf("expected project_id=10, got %s", q.Get("project_id"))
		}
		if q.Get("repository") != "owner/repo" {
			t.Fatalf("expected repository=owner/repo, got %s", q.Get("repository"))
		}
		if q.Get("pr_number") != "5" {
			t.Fatalf("expected pr_number=5, got %s", q.Get("pr_number"))
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(PRReviewResultResponse{
			PRReviewID: 200,
			ProjectID:  10,
			Status:     "completed",
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	payload := json.RawMessage(`{"base":"main","head":"feature","findings":[]}`)
	resp, err := client.PostPRReviewResults(context.Background(), payload, PRReviewSubmitOpts{
		ProjectID:  10,
		Repository: "owner/repo",
		PRNumber:   5,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.PRReviewID != 200 {
		t.Fatalf("expected pr_review_id 200, got %d", resp.PRReviewID)
	}
}

func TestPostScanResults_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "access denied", "code": "FORBIDDEN"})
	}))
	defer server.Close()

	client := NewClient(server.URL, "bad-token")
	payload := json.RawMessage(`{}`)
	_, err := client.PostScanResults(context.Background(), payload, 1, "")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	apiErr, ok := err.(*Error)
	if !ok {
		t.Fatalf("expected *api.Error, got %T", err)
	}
	if apiErr.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", apiErr.StatusCode)
	}
}
