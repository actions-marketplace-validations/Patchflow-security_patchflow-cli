package api

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// mockAPIClient implements APIClient for testing.
type mockAPIClient struct {
	calls    int
	statuses []StatusResponse
	err      error
}

func (m *mockAPIClient) PostContext(_ context.Context, _ ContextPayload) (string, error) {
	return "", nil
}

func (m *mockAPIClient) PostReview(_ context.Context, _ ReviewPayload) (string, error) {
	return "", nil
}

func (m *mockAPIClient) PostScanResults(_ context.Context, _ json.RawMessage, _ int, _ string) (*ScanResultResponse, error) {
	return &ScanResultResponse{}, nil
}

func (m *mockAPIClient) PostPRReviewResults(_ context.Context, _ json.RawMessage, _ PRReviewSubmitOpts) (*PRReviewResultResponse, error) {
	return &PRReviewResultResponse{}, nil
}

func (m *mockAPIClient) GetStatus(_ context.Context, _ string) (*StatusResponse, error) {
	if m.err != nil {
		return nil, m.err
	}
	status := m.statuses[m.calls]
	m.calls++
	return &status, nil
}

func TestPoll_CompletesOnSecondCall(t *testing.T) {
	mock := &mockAPIClient{
		statuses: []StatusResponse{
			{ID: "job-1", Status: "pending"},
			{ID: "job-1", Status: "completed", ResultURL: "http://result"},
		},
	}
	poller := &Poller{
		Client:      mock,
		Interval:    10 * time.Millisecond,
		MaxAttempts: 10,
	}

	resp, err := poller.Poll(context.Background(), "job-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != "completed" {
		t.Fatalf("expected completed, got %s", resp.Status)
	}
	if resp.ResultURL != "http://result" {
		t.Fatalf("expected result URL http://result, got %s", resp.ResultURL)
	}
	if mock.calls != 2 {
		t.Fatalf("expected 2 calls, got %d", mock.calls)
	}
}

func TestPoll_RespectsMaxAttempts(t *testing.T) {
	mock := &mockAPIClient{
		statuses: []StatusResponse{
			{ID: "job-2", Status: "pending"},
			{ID: "job-2", Status: "pending"},
			{ID: "job-2", Status: "pending"},
		},
	}
	poller := &Poller{
		Client:      mock,
		Interval:    10 * time.Millisecond,
		MaxAttempts: 2,
	}

	_, err := poller.Poll(context.Background(), "job-2")
	if err == nil {
		t.Fatal("expected error after max attempts, got nil")
	}
	if mock.calls != 2 {
		t.Fatalf("expected 2 calls, got %d", mock.calls)
	}
}

func TestPoll_RespectsContextCancellation(t *testing.T) {
	mock := &mockAPIClient{
		statuses: []StatusResponse{
			{ID: "job-3", Status: "pending"},
			{ID: "job-3", Status: "pending"},
			{ID: "job-3", Status: "pending"},
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	poller := &Poller{
		Client:      mock,
		Interval:    1 * time.Second,
		MaxAttempts: 10,
	}

	// Cancel after a short delay to ensure at least one call is made.
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	_, err := poller.Poll(ctx, "job-3")
	if err != context.Canceled {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}
