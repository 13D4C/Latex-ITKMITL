package overleaf

import (
	"crypto/sha256"
	"encoding/base64"
	"hash"
)

func sha256New() hash.Hash { return sha256.New() }

func encodeURL(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
