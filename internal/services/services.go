package services

import (
	"os"
	"time"

	"aidanwoods.dev/go-paseto"
)

func newToken(dur time.Duration) paseto.Token {
	n := time.Now()

	// generate a new token
	tkn := paseto.NewToken()
	tkn.SetIssuedAt(n)
	tkn.SetNotBefore(n)
	tkn.SetExpiration(n.Add(dur))

	return tkn
}

func readFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return []byte{}, err
	}

	return data, nil
}
