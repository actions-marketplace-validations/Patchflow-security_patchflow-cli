package db

import "context"

// Importer is the contract every advisory source importer must satisfy.
// Each importer owns one feed (OSV, Alpine SecDB, etc.); the pf-db-builder
// binary runs them in sequence and records the Stats.
type Importer interface {
	// Name returns the importer's source identifier (must match the Source.Name
	// registered in vulnerability_sources).
	Name() string

	// Import fetches the feed and writes into db. It must be idempotent:
	// re-running an importer on the same data should produce no duplicates.
	// Returns Stats summarising what was inserted / skipped / errored.
	Import(ctx context.Context, db *DB) (Stats, error)
}
