package extractor

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
)

// sha256Writer wraps crypto/sha256 and exposes the hex digest.
type sha256Writer struct {
	h hash.Hash
}

func newSHA256() *sha256Writer {
	return &sha256Writer{h: sha256.New()}
}

func (s *sha256Writer) Write(p []byte) (int, error) { return s.h.Write(p) }

// BlockSize returns the underlying hash block size.
func (s *sha256Writer) BlockSize() int { return s.h.BlockSize() }

// Size returns the digest size in bytes.
func (s *sha256Writer) Size() int { return s.h.Size() }

// Sum appends the current digest to b.
func (s *sha256Writer) Sum(b []byte) []byte { return s.h.Sum(b) }

// Reset resets the hash.
func (s *sha256Writer) Reset() { s.h.Reset() }

// hex returns the lowercase hex digest of everything written so far.
func (s *sha256Writer) hex() string { return hex.EncodeToString(s.h.Sum(nil)) }

// ensure the interface is satisfied (used via io.MultiWriter).
var _ hash.Hash = (*sha256Writer)(nil)
