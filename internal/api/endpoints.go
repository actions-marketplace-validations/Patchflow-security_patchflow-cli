package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// ContextPayload represents the payload for the context endpoint.
type ContextPayload struct {
	RepoRoot     string   `json:"repo_root"`
	RemoteURL    string   `json:"remote_url"`
	Branch       string   `json:"branch"`
	CommitSHA    string   `json:"commit_sha"`
	BaseBranch   string   `json:"base_branch"`
	ChangedFiles []string `json:"changed_files"`
	AddedLines   int      `json:"added_lines"`
	DeletedLines int      `json:"deleted_lines"`
	Manifests    []string `json:"manifests"`
}

// ReviewPayload represents the payload for the review endpoint.
type ReviewPayload struct {
	RepoRoot     string   `json:"repo_root"`
	RemoteURL    string   `json:"remote_url"`
	Branch       string   `json:"branch"`
	CommitSHA    string   `json:"commit_sha"`
	BaseBranch   string   `json:"base_branch"`
	ChangedFiles []string `json:"changed_files"`
	AddedLines   int      `json:"added_lines"`
	DeletedLines int      `json:"deleted_lines"`
	Manifests    []string `json:"manifests"`
	Submit       bool     `json:"submit"`
}

// StatusResponse represents the status of a job.
type StatusResponse struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	ResultURL string `json:"result_url"`
}

// APIClient defines the interface for interacting with the PatchFlow API.
type APIClient interface {
	PostContext(ctx context.Context, payload ContextPayload) (string, error)
	PostReview(ctx context.Context, payload ReviewPayload) (string, error)
	PostScanResults(ctx context.Context, payload json.RawMessage, projectID int, scanID string) (*ScanResultResponse, error)
	PostPRReviewResults(ctx context.Context, payload json.RawMessage, opts PRReviewSubmitOpts) (*PRReviewResultResponse, error)
	GetStatus(ctx context.Context, id string) (*StatusResponse, error)
}

var _ APIClient = (*Client)(nil)

// ScanResultResponse is the backend's response to POST /api/v1/cli/scan-results.
type ScanResultResponse struct {
	ScanID     int    `json:"scan_id"`
	ProjectID  int    `json:"project_id"`
	Status     string `json:"status"`
}

// PRReviewSubmitOpts contains query parameters for POST /api/v1/cli/pr-review-results.
type PRReviewSubmitOpts struct {
	ProjectID  int    `json:"project_id"`
	Repository string `json:"repository"`
	PRNumber   int    `json:"pr_number"`
	PRTitle    string `json:"pr_title"`
	PRAuthor   string `json:"pr_author"`
	PRURL      string `json:"pr_url"`
}

// PRReviewResultResponse is the backend's response to POST /api/v1/cli/pr-review-results.
type PRReviewResultResponse struct {
	PRReviewID int    `json:"pr_review_id"`
	ProjectID  int    `json:"project_id"`
	Status     string `json:"status"`
}

// PostContext submits a context payload and returns the job ID.
func (c *Client) PostContext(ctx context.Context, payload ContextPayload) (string, error) {
	return c.postJSON(ctx, "/api/v1/cli/context", payload)
}

// PostReview submits a review payload and returns the job ID.
func (c *Client) PostReview(ctx context.Context, payload ReviewPayload) (string, error) {
	return c.postJSON(ctx, "/api/v1/cli/review", payload)
}

// PostScanResults submits the full AnalysisResult JSON to the backend.
// The backend maps findings to Vulnerability/ExternalFinding models.
func (c *Client) PostScanResults(ctx context.Context, payload json.RawMessage, projectID int, scanID string) (*ScanResultResponse, error) {
	path := fmt.Sprintf("/api/v1/cli/scan-results?project_id=%d", projectID)
	if scanID != "" {
		path += fmt.Sprintf("&scan_id=%s", scanID)
	}
	return postJSONRaw[ScanResultResponse](c, ctx, path, payload)
}

// PostPRReviewResults submits the pr-review JSON to the backend.
func (c *Client) PostPRReviewResults(ctx context.Context, payload json.RawMessage, opts PRReviewSubmitOpts) (*PRReviewResultResponse, error) {
	path := fmt.Sprintf("/api/v1/cli/pr-review-results?project_id=%d&repository=%s&pr_number=%d", opts.ProjectID, opts.Repository, opts.PRNumber)
	if opts.PRTitle != "" {
		path += "&pr_title=" + opts.PRTitle
	}
	if opts.PRAuthor != "" {
		path += "&pr_author=" + opts.PRAuthor
	}
	if opts.PRURL != "" {
		path += "&pr_url=" + opts.PRURL
	}
	return postJSONRaw[PRReviewResultResponse](c, ctx, path, payload)
}

// GetStatus retrieves the status of a job by ID.
func (c *Client) GetStatus(ctx context.Context, id string) (*StatusResponse, error) {
	url := c.baseURL + fmt.Sprintf("/api/v1/cli/status/%s", id)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	c.SetAuthHeader(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return nil, c.parseError(resp)
	}

	var status StatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, err
	}
	return &status, nil
}

func (c *Client) postJSON(ctx context.Context, path string, payload any) (string, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	url := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	c.SetAuthHeader(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return "", c.parseError(resp)
	}

	var result struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	return result.ID, nil
}

// postJSONRaw sends a raw JSON payload and decodes the response into T.
// Used for endpoints that accept pre-marshaled JSON (e.g. AnalysisResult)
// and return structured data (not just an ID).
func postJSONRaw[T any](c *Client, ctx context.Context, path string, payload json.RawMessage) (*T, error) {
	url := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	c.SetAuthHeader(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return nil, c.parseError(resp)
	}

	var result T
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) parseError(resp *http.Response) *Error {
	var apiErr Error
	apiErr.StatusCode = resp.StatusCode

	// Attempt to decode structured error body.
	body, _ := io.ReadAll(resp.Body)
	if len(body) > 0 {
		var parsed struct {
			Message string `json:"message"`
			Code    string `json:"code"`
		}
		if err := json.Unmarshal(body, &parsed); err == nil {
			apiErr.Message = parsed.Message
			apiErr.Code = parsed.Code
		} else {
			apiErr.Message = string(body)
		}
	} else {
		apiErr.Message = http.StatusText(resp.StatusCode)
	}

	return &apiErr
}
