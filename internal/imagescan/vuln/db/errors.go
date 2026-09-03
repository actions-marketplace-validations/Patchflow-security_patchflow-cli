package db

import "errors"

// ErrDBNotFound is returned by OpenReadOnly when the DB file does not exist
// or cannot be opened. The scanner CLI catches this and suggests running
// `patchflow-image-scanner vulndb sync` first.
var ErrDBNotFound = errors.New("vulnerability database not found — run 'vulndb sync' to build it")
