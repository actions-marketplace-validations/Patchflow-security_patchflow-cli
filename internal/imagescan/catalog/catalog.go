// Package catalog defines the package cataloger interface and the shared
// cataloging pipeline. A Cataloger inspects a FileSystemView and emits
// discovered packages (OS or language) with layer attribution.
//
// Each cataloger is self-contained: it knows which files indicate its
// ecosystem (e.g. /lib/apk/db/installed for Alpine, /var/lib/dpkg/status
// for Debian) and parses them into model.Package records. The pipeline runs
// all matching catalogers and merges their output.
package catalog

import (
	"context"

	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/model"
)

// Cataloger discovers packages from a filesystem view. Match is called first
// to cheaply decide whether the cataloger applies (e.g. presence of a
// marker file); Catalog does the actual parsing.
type Cataloger interface {
	// Name returns the cataloger identifier (e.g. "apk", "dpkg").
	Name() string
	// Match reports whether this cataloger should run against the view.
	Match(fs model.FileSystemView) bool
	// Catalog parses the view and returns discovered packages.
	Catalog(ctx context.Context, fs model.FileSystemView) ([]model.Package, error)
}

// Pipeline runs a set of catalogers against a filesystem view and returns
// the merged package list. Catalogers whose Match returns false are skipped.
type Pipeline struct {
	Catalogers []Cataloger
}

// NewPipeline builds a pipeline with the given catalogers.
func NewPipeline(catalogers ...Cataloger) *Pipeline {
	return &Pipeline{Catalogers: catalogers}
}

// Run executes all matching catalogers and concatenates their results.
func (p *Pipeline) Run(ctx context.Context, fs model.FileSystemView) ([]model.Package, error) {
	var all []model.Package
	for _, c := range p.Catalogers {
		if !c.Match(fs) {
			continue
		}
		pkgs, err := c.Catalog(ctx, fs)
		if err != nil {
			return nil, err
		}
		all = append(all, pkgs...)
	}
	return all, nil
}
