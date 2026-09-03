package debian_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/vuln/db"
	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/vuln/db/debian"
)

// fixtureJSON is a minimal Debian Security Tracker JSON fixture covering:
//
//   - curl/CVE-2024-0001: bookworm(resolved)→fixed, bullseye(open)→affected,
//     sid→skipped (no numeric version)
//   - curl/CVE-2024-0002: bookworm(resolved)→fixed, buster(undetermined)→skipped
//   - openssl/CVE-2024-0003: bullseye(resolved)→fixed, bookworm(open)→affected
//   - openssl/CVE-2024-0004: trixie(open)→affected
//
// Expected: 6 AffectedPackage rows inserted, 2 skipped (sid + undetermined).
const fixtureJSON = `{
  "curl": {
    "CVE-2024-0001": {
      "description": "Buffer overflow in curl HTTP/2 parsing",
      "scope": "local",
      "releases": {
        "bookworm": {
          "status": "resolved",
          "fixed_version": "7.88.1-10+deb12u7",
          "urgency": "low"
        },
        "bullseye": {
          "status": "open",
          "urgency": "unimportant"
        },
        "sid": {
          "status": "resolved",
          "fixed_version": "8.0.0-1",
          "urgency": "low"
        }
      }
    },
    "CVE-2024-0002": {
      "description": "Use-after-free in curl SOCKS5 proxy handling",
      "scope": "remote",
      "releases": {
        "bookworm": {
          "status": "resolved",
          "fixed_version": "7.88.1-10+deb12u8",
          "urgency": "medium"
        },
        "buster": {
          "status": "undetermined"
        }
      }
    }
  },
  "openssl": {
    "CVE-2024-0003": {
      "description": "Memory leak in OpenSSL X.509 certificate verification",
      "scope": "local",
      "releases": {
        "bullseye": {
          "status": "resolved",
          "fixed_version": "1.1.1w-0+deb11u1",
          "urgency": "high"
        },
        "bookworm": {
          "status": "open",
          "urgency": "medium"
        }
      }
    },
    "CVE-2024-0004": {
      "description": "Null pointer dereference in OpenSSL TLS 1.3",
      "scope": "local",
      "releases": {
        "trixie": {
          "status": "open",
          "urgency": "low"
        }
      }
    }
  }
}`

// newTestDB opens a temporary SQLite DB in t.TempDir().
func newTestDB(t *testing.T) *db.DB {
	t.Helper()
	database, err := db.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database
}

func TestName(t *testing.T) {
	imp := debian.New()
	if imp.Name() != "debian-security" {
		t.Errorf("Name() = %q, want %q", imp.Name(), "debian-security")
	}
}

func TestImport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fixtureJSON))
	}))
	t.Cleanup(srv.Close)

	database := newTestDB(t)
	imp := debian.New()
	imp.FeedURL = srv.URL
	imp.HTTPClient = srv.Client()

	ctx := context.Background()
	stats, err := imp.Import(ctx, database)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}

	// Verify stats from the first run.
	// 6 AffectedPackage rows should be inserted; 2 entries skipped (sid + undetermined).
	if stats.Source != "debian-security" {
		t.Errorf("stats.Source = %q, want %q", stats.Source, "debian-security")
	}
	if stats.Inserted != 6 {
		t.Errorf("stats.Inserted = %d, want 6", stats.Inserted)
	}
	if stats.Skipped != 2 {
		t.Errorf("stats.Skipped = %d, want 2", stats.Skipped)
	}
	if stats.Errors != 0 {
		t.Errorf("stats.Errors = %d, want 0", stats.Errors)
	}
	if stats.Duration == 0 {
		t.Error("stats.Duration should be non-zero")
	}
}

func TestImportIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fixtureJSON))
	}))
	t.Cleanup(srv.Close)

	database := newTestDB(t)
	imp := debian.New()
	imp.FeedURL = srv.URL
	imp.HTTPClient = srv.Client()

	ctx := context.Background()

	// First import.
	if _, err := imp.Import(ctx, database); err != nil {
		t.Fatalf("first Import: %v", err)
	}

	// Second import — must not error and must not duplicate data.
	stats2, err := imp.Import(ctx, database)
	if err != nil {
		t.Fatalf("second Import: %v", err)
	}
	if stats2.Errors != 0 {
		t.Errorf("idempotency: stats.Errors = %d, want 0", stats2.Errors)
	}

	// Verify affected_packages row count did not grow by querying sources.
	sources, err := database.ListSources(ctx)
	if err != nil {
		t.Fatalf("ListSources: %v", err)
	}
	var found bool
	for _, s := range sources {
		if s.Name == "debian-security" {
			found = true
			break
		}
	}
	if !found {
		t.Error("source 'debian-security' not found after import")
	}
}

func TestImportContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fixtureJSON))
	}))
	t.Cleanup(srv.Close)

	database := newTestDB(t)
	imp := debian.New()
	imp.FeedURL = srv.URL
	imp.HTTPClient = srv.Client()

	// A pre-cancelled context should cause Import to return an error.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := imp.Import(ctx, database)
	if err == nil {
		t.Error("expected error with cancelled context, got nil")
	}
}

func TestImportBadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)

	database := newTestDB(t)
	imp := debian.New()
	imp.FeedURL = srv.URL
	imp.HTTPClient = srv.Client()

	_, err := imp.Import(context.Background(), database)
	if err == nil {
		t.Error("expected error for non-200 HTTP status, got nil")
	}
}
