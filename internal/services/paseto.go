package services

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"aidanwoods.dev/go-paseto"
	"github.com/rs/zerolog/log"
	"go.jtlabs.io/runner-gateway/internal/models"
	"golang.org/x/crypto/ssh"
)

const (
	v2AsymPrefix = "v2.public."
	v2SymPrefix  = "v2.local."
	v4AsymPrefix = "v4.public."
	v4SymPrefix  = "v4.local."
)

type v4Service struct {
	pubKey *paseto.V4AsymmetricPublicKey
	prvKey *paseto.V4AsymmetricSecretKey
	symKey *paseto.V4SymmetricKey
}

func NewV4Service(s *models.Settings) (*v4Service, error) {
	svc := &v4Service{}

	// attempt to read the public key based on configuration
	var pubKeyErr error
	if b, err := readFile(s.PASETO.PublicPath); err == nil {
		// parse the SSH formatted key
		authKey, _, _, _, err := ssh.ParseAuthorizedKey(b)
		if err != nil {
			pubKeyErr = err
		}

		if err == nil {
			// ensure the public key is an ed25519 key
			if edKey, ok := authKey.(ssh.CryptoPublicKey); ok {
				// parse the ed25519 key
				pubKey, err := paseto.NewV4AsymmetricPublicKeyFromBytes(edKey.CryptoPublicKey().(ed25519.PublicKey))
				if err != nil {
					log.Warn().
						Err(err).
						Msg("Failed to read public key from file. Please check your configuration.")
					pubKeyErr = err
				}

				// assign public key
				if err == nil {
					svc.pubKey = &pubKey
				}
			}
		}
	}

	// attempt to read the symmetric key based on configuration
	sk, err := paseto.V4SymmetricKeyFromHex(s.PASETO.SecretKey)
	if err != nil && pubKeyErr != nil {
		log.Warn().
			Str("asymmetricPublicKeyError", pubKeyErr.Error()).
			Str("symmetricKeyError", err.Error()).
			Msg("Failed to read either a public key or a symmetric key for signing and verification. Please check your configuration.")
		return nil, errors.New("unable to read either a public key or a symmetric key for signing and verification")
	}

	// assign symmetric key
	svc.symKey = &sk

	// attempt to read the private key based on configuration
	b, err := readFile(s.PASETO.KeyPath)
	if err != nil {
		log.Warn().
			Str("error", err.Error()).
			Str("path", s.PASETO.KeyPath).
			Msg("Failed to read private key. Please check your configuration.")

		// returning anyway, we don't need the private key to validate...
		return svc, nil
	}

	blk, _ := pem.Decode(b)
	if blk != nil && len(blk.Bytes) > 0 {
		prvKey, err := paseto.NewV4AsymmetricSecretKeyFromBytes(blk.Bytes)
		if err != nil {
			log.Warn().
				Str("error", err.Error()).
				Str("path", s.PASETO.KeyPath).
				Msg("Failed to load private key as PASETO v4 Asymmetric Private Key.")

			// returning anyway, we don't need the private key to validate...
			return svc, nil
		}

		svc.prvKey = &prvKey
	}

	if blk == nil || len(blk.Bytes) == 0 {
		log.Warn().
			Str("path", s.PASETO.KeyPath).
			Msg("Unable to decode private key, invalid key format.")
	}

	return svc, nil
}

func (svc *v4Service) EncryptToken(tkn paseto.Token) (string, error) {
	if svc.symKey == nil {
		return "", errors.New("symmetric key is not set")
	}

	return tkn.V4Encrypt(*svc.symKey, nil), nil
}

func (svc *v4Service) GenerateSymmetricKey() string {
	sym := paseto.NewV4SymmetricKey()
	return sym.ExportHex()
}

func (svc *v4Service) GenerateAsymmetricKeyPair() (string, string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate ed25519 key pair: %w", err)
	}

	privK := pem.EncodeToMemory(&pem.Block{
		Type:  "ED25519 PRIVATE KEY",
		Bytes: priv,
	})

	// convert the public key to bytes
	pubK, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", "", fmt.Errorf("failed to create public key: %w", err)
	}

	return string(ssh.MarshalAuthorizedKey(pubK)), string(privK), nil
}

func (svc *v4Service) SignToken(tkn paseto.Token) (string, error) {
	if svc.prvKey == nil {
		return "", fmt.Errorf("asymmetric private key is not set")
	}

	sgn := tkn.V4Sign(*svc.prvKey, nil)

	return sgn, nil
}

func (svc *v4Service) ValidateToken(tkn string) error {
	prsr := paseto.NewParser()

	// check for asymmetric public token
	if strings.HasPrefix(tkn, v4AsymPrefix) {
		if _, err := prsr.ParseV4Public(*svc.pubKey, tkn, nil); err != nil {
			return fmt.Errorf("failed to parse v4.public token: %w", err)
		}

		return nil
	}

	// check for symmetric local token
	if strings.HasPrefix(tkn, v4SymPrefix) {
		if _, err := prsr.ParseV4Local(*svc.symKey, tkn, nil); err != nil {
			return fmt.Errorf("failed to parse v4.local token: %w", err)
		}

		return nil
	}

	return errors.New("unsupported token type")
}

type v2Service struct {
	pubKey *paseto.V2AsymmetricPublicKey
	prvKey *paseto.V2AsymmetricSecretKey
	symKey *paseto.V2SymmetricKey
}

func NewV2Service(s *models.Settings) (*v2Service, error) {
	svc := &v2Service{}

	// attempt to read the public key based on configuration
	var pubKeyErr error
	if b, err := readFile(s.PASETO.PublicPath); err == nil {
		// parse the SSH formatted key
		authKey, _, _, _, err := ssh.ParseAuthorizedKey(b)
		if err != nil {
			pubKeyErr = err
		}

		if err == nil {
			// ensure the public key is an ed25519 key
			if edKey, ok := authKey.(ssh.CryptoPublicKey); ok {
				// parse the ed25519 key
				pubKey, err := paseto.NewV2AsymmetricPublicKeyFromBytes(edKey.CryptoPublicKey().(ed25519.PublicKey))
				if err != nil {
					log.Warn().
						Err(err).
						Msg("Failed to read public key from file. Please check your configuration.")
					pubKeyErr = err
				}

				// assign public key
				if err == nil {
					svc.pubKey = &pubKey
				}
			}
		}
	}

	// attempt to read the symmetric key based on configuration
	sk, err := paseto.V2SymmetricKeyFromHex(s.PASETO.SecretKey)
	if err != nil && pubKeyErr != nil {
		log.Warn().
			Str("asymmetricPublicKeyError", pubKeyErr.Error()).
			Str("symmetricKeyError", err.Error()).
			Msg("Failed to read either a public key or a symmetric key for signing and verification. Please check your configuration.")
		return nil, errors.New("unable to read either a public key or a symmetric key for signing and verification")
	}

	// assign symmetric key
	svc.symKey = &sk

	// attempt to read the private key based on configuration
	b, err := readFile(s.PASETO.KeyPath)
	if err != nil {
		log.Warn().
			Str("error", err.Error()).
			Str("path", s.PASETO.KeyPath).
			Msg("Failed to read private key. Please check your configuration.")

		// returning anyway, we don't need the private key to validate...
		return svc, nil
	}

	blk, _ := pem.Decode(b)
	if blk != nil && len(blk.Bytes) > 0 {
		prvKey, err := paseto.NewV2AsymmetricSecretKeyFromBytes(blk.Bytes)
		if err != nil {
			log.Warn().
				Str("error", err.Error()).
				Str("path", s.PASETO.KeyPath).
				Msg("Failed to load private key as PASETO v4 Asymmetric Private Key.")

			// returning anyway, we don't need the private key to validate...
			return svc, nil
		}

		svc.prvKey = &prvKey
	}

	if blk == nil || len(blk.Bytes) == 0 {
		log.Warn().
			Str("path", s.PASETO.KeyPath).
			Msg("Unable to decode private key, invalid key format.")
	}

	return svc, nil
}

func (svc *v2Service) EncryptToken(tkn paseto.Token) (string, error) {
	if svc.prvKey == nil {
		return "", fmt.Errorf("symmetric private key is not set")
	}

	return tkn.V2Encrypt(*svc.symKey), nil
}

func (svc *v2Service) GenerateSymmetricKey() string {
	sym := paseto.NewV4SymmetricKey()
	return sym.ExportHex()
}

func (svc *v2Service) GenerateAsymmetricKeyPair() (string, string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate ed25519 key pair: %w", err)
	}

	privK := pem.EncodeToMemory(&pem.Block{
		Type:  "ED25519 PRIVATE KEY",
		Bytes: priv,
	})

	// convert the public key to bytes
	pubK, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", "", fmt.Errorf("failed to create public key: %w", err)
	}

	return string(ssh.MarshalAuthorizedKey(pubK)), string(privK), nil
}

func (svc *v2Service) SignToken(tkn paseto.Token) (string, error) {
	if svc.prvKey == nil {
		return "", fmt.Errorf("asymmetric private key is not set")
	}

	sgn := tkn.V2Sign(*svc.prvKey)

	return sgn, nil
}

func (svc *v2Service) ValidateToken(tkn string) error {
	prsr := paseto.NewParser()

	// check for asymmetric public token
	if strings.HasPrefix(tkn, v2AsymPrefix) {
		if _, err := prsr.ParseV2Public(*svc.pubKey, tkn); err != nil {
			return fmt.Errorf("failed to parse v2.public token: %w", err)
		}

		return nil
	}

	// check for symmetric local token
	if strings.HasPrefix(tkn, v2SymPrefix) {
		if _, err := prsr.ParseV2Local(*svc.symKey, tkn); err != nil {
			return fmt.Errorf("failed to parse v2.local token: %w", err)
		}

		return nil
	}

	return errors.New("unsupported token type")
}
