package delivery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// signedBytes returns the deterministic JSON covered by the report digest.
// The digest field itself is excluded so a sealed report verifies itself.
func (r Report) signedBytes() ([]byte, error) {
	copyValue := r
	copyValue.SHA256 = ""
	encoded, err := json.Marshal(copyValue)
	if err != nil {
		return nil, fmt.Errorf("encode delivery report for sealing: %w", err)
	}
	return encoded, nil
}

// seal computes and attaches the SHA-256 digest over the report body.
func (r *Report) seal() error {
	encoded, err := r.signedBytes()
	if err != nil {
		return err
	}
	sum := sha256.Sum256(encoded)
	r.SHA256 = hex.EncodeToString(sum[:])
	return nil
}

// VerifyDigest recomputes the digest and reports whether it still matches.
func (r Report) VerifyDigest() (bool, error) {
	if r.SHA256 == "" {
		return false, fmt.Errorf("delivery report for pass %s carries no digest", r.PassID)
	}
	encoded, err := r.signedBytes()
	if err != nil {
		return false, err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]) == r.SHA256, nil
}
