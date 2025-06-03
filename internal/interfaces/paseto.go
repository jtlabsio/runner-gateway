package interfaces

import "aidanwoods.dev/go-paseto"

type PASETOProvider interface {
	EncryptToken(paseto.Token) (string, error)
	GenerateSymmetricKey() string
	GenerateAsymmetricKeyPair() (string, string, error)
	SignToken(paseto.Token) (string, error)
	ValidateToken(token string) error
}
